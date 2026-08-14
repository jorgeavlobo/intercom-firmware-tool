//! Viewer-activity auto-hold for the on-device camera (issue #120, the #104 follow-up the SIP hold
//! loop flagged as deferred — see the note at `sip.rs`'s hold loop).
//!
//! `sip.rs` holds the on-demand panel session for a FIXED window per `view_camera` press because there
//! was no continuous "someone is watching" signal — so a single press bounds the session to one window
//! and it auto-hangs-up when the window elapses. This task supplies that missing signal for the
//! on-device media path: while a client holds an ESTABLISHED TCP connection to go2rtc's RTSP port
//! (`:8554`, = `Go2RtcConfig.OnDeviceRtspPort`) it pokes `ViewCmd::Start` to renew the window, so Home
//! Assistant "just opens the camera" and the panel session follows the live viewer.
//!
//! ## Why the client TCP session, and NOT go2rtc's `/api/streams` (both hardware-confirmed on a C100X)
//! An earlier revision keyed auto-hold off go2rtc's control API. Real-hardware testing proved BOTH of
//! its arrays unusable as the trigger:
//!   * **producers** is ALWAYS populated — go2rtc lists the configured `exec:` source even with no
//!     ffmpeg running and no viewer — so keying auto-hold on producers held the panel up FOREVER
//!     ("always on"): the window never lapsed.
//!   * **consumers** stays `null` until go2rtc actually SERVES video. But go2rtc's `exec:` is a LAZY
//!     source: it can't answer a viewer's RTSP DESCRIBE (start its ffmpeg, get RTP) unless the panel is
//!     already up — which only this task brings up. So a consumers-based trigger DEADLOCKS the very
//!     first open: no consumer ⇒ no Start ⇒ no RTP ⇒ DESCRIBE never completes ⇒ no consumer.
//!
//! A raw TCP connection to `:8554`, by contrast, is present the instant the client CONNECTS — before any
//! video, before go2rtc answers DESCRIBE — so it BOOTSTRAPS the first open; and it clears the instant the
//! client DISCONNECTS, so the window lapses on its own once the last viewer leaves. (Confirmed on device:
//! a client connected to `rtsp://…:8554` shows `consumers:null` and no producer ffmpeg, yet an
//! ESTABLISHED socket on local port 8554 IS present.) go2rtc's ~30 s `exec:` idle-timeout is irrelevant
//! now — we key off the client's TCP session, not go2rtc's producer.
//!
//! ## How the count is exact (no double-count, never the LISTEN socket)
//! We count ESTABLISHED (TCP state hex `01`) sockets whose LOCAL port is 8554, across BOTH
//! `/proc/net/tcp` and `/proc/net/tcp6`, and sum. go2rtc listens on IPv6, so:
//!   * a LAN viewer's accepted socket (go2rtc side) is the only local-port-8554 socket and lives in
//!     `tcp6`;
//!   * a loopback viewer's accepted socket (local 8554) is in `tcp6` while the client's own socket
//!     (local ephemeral, REMOTE 8554) is in `tcp4` — counting only LOCAL-port-8554 skips it.
//!
//! So summing LOCAL-port-8554 ESTABLISHED across both files = exactly the viewer count, and the LISTEN
//! socket (state `0A`) is never counted.
//!
//! Best-effort: reading `/proc` doesn't fail meaningfully — a read error reads as "no viewer" (logged
//! once). The manual `view_camera`/`stop_camera` MQTT actions are unaffected — every source drives the
//! same `view_rx`, and `ViewCmd::Start` is idempotent (a fresh full window each time).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::config::Config;
use crate::sip::ViewCmd;

/// go2rtc's on-device RTSP port (`Go2RtcConfig.OnDeviceRtspPort` = 8554) as the uppercase hex the
/// `/proc/net/tcp` port field uses: 8554 = 0x216A. A client holding an ESTABLISHED connection to this
/// LOCAL port is a live viewer.
const RTSP_PORT_HEX: &str = "216A";
/// Target poll cadence. Short for RESPONSIVENESS: when Home Assistant opens the camera, the client
/// connects to `:8554` and this task must bring the panel session up within a couple seconds (not a
/// third of the viewing window). The effective period is still capped under the window (see `run`) so a
/// held view never lapses between pokes.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Debounce for the (essentially never taken) `/proc` read-error log, so a broken procfs can't spam the
/// log every poll — the same one-shot-warn role the old API-unreachable `warned` flag served.
static READ_WARNED: AtomicBool = AtomicBool::new(false);

/// Poke `Start` while a viewer holds an ESTABLISHED TCP connection to go2rtc's RTSP port. Returns when
/// `stopping` is set. `main` also aborts this task at shutdown, so the poll-interval sleep is a bounded
/// wait.
pub async fn run(cfg: Arc<Config>, stopping: Arc<AtomicBool>, view_tx: mpsc::Sender<ViewCmd>) {
    // Poll every POLL_INTERVAL for a prompt panel start when a viewer connects, but never longer than
    // half the viewing window so a held view can't lapse between pokes (floored so a pathological tiny
    // window can't spin the loop). On the 30 s default this is a flat 2 s.
    let window = Duration::from_secs(cfg.camera_view_idle_secs.max(1));
    let period = POLL_INTERVAL
        .min(window / 2)
        .max(Duration::from_millis(500));
    while !stopping.load(Ordering::Relaxed) {
        if viewer_connected() {
            // Renew the on-demand window. try_send never blocks the poll loop: a full queue means
            // sip.rs isn't draining (reconnect backoff) and a dropped poke is harmless — the next poll
            // pokes again; Closed means the SIP task is gone, nothing to hold.
            //
            // DELIBERATE: auto-hold is AUTHORITATIVE while a viewer's TCP session is up. If an operator
            // issues `stop_camera` (ViewCmd::Stop) while Home Assistant still has the feed open, this
            // poll re-Starts within one interval — so a Stop only interrupts an active view briefly
            // rather than ending it. This is by design: the session follows the live viewer, which is
            // exactly what makes the feature "transparent" (HA just opens the camera). To end a view,
            // close it (the TCP connection clears → these pokes stop → the window lapses); `stop_camera`
            // remains effective when no viewer is connected (e.g. after a ring). Honoring the Stop over
            // an active viewer was considered and rejected: tearing the session down drops the client,
            // HA auto-reconnects, the connection reappears, and a suppression flag would fight HA's
            // reconnect for no real benefit (product decision on #129; Codex review).
            let _ = view_tx.try_send(ViewCmd::Start);
        }
        // Re-check `stopping` before sleeping so a shutdown observed mid-poll exits promptly.
        if stopping.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(period).await;
    }
}

/// True iff at least one client holds an ESTABLISHED TCP connection to go2rtc's RTSP port (LOCAL port
/// 8554). Sums LOCAL-port-8554 ESTABLISHED sockets across `/proc/net/tcp` and `/proc/net/tcp6` (see the
/// module doc for why that count is exactly the viewer count with no double-count). Reading `/proc`
/// doesn't fail meaningfully: a file that can't be read contributes 0 (treated as "no viewer"), and if
/// NEITHER file could be read that's logged once via [`READ_WARNED`].
fn viewer_connected() -> bool {
    let mut count = 0usize;
    let mut any_read = false;
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            any_read = true;
            count += established_local_port_count(&text, RTSP_PORT_HEX);
        }
    }
    if any_read {
        // Procfs is readable again — re-arm the one-shot warning for a future outage.
        READ_WARNED.store(false, Ordering::Relaxed);
    } else if !READ_WARNED.swap(true, Ordering::Relaxed) {
        eprintln!(
            "btmqttd: camera auto-hold: could not read /proc/net/tcp{{,6}}; assuming no viewer"
        );
    }
    count > 0
}

/// Count ESTABLISHED sockets whose LOCAL port equals `port_hex`, parsing `/proc/net/tcp`-format text.
/// Skips the header line; for each remaining line, whitespace-splits it, takes field[1]
/// (`HEXIP:HEXPORT`, the LOCAL address — port is the substring after the LAST `:`) and field[3] (the
/// connection state), and counts the line when the local port matches `port_hex` (case-insensitive) AND
/// the state is `01` (TCP_ESTABLISHED). Pure and testable — no `/proc` I/O.
fn established_local_port_count(proc_tcp: &str, port_hex: &str) -> usize {
    proc_tcp
        .lines()
        .skip(1) // header row
        .filter(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 4 {
                return false;
            }
            // field[1] is the LOCAL `HEXIP:HEXPORT`; the port is after the LAST ':' (IPv6 addresses in
            // /proc are a single colon-free hex blob, so there's exactly one ':' here, but rsplit is
            // robust regardless). field[3] is the state; "01" is TCP_ESTABLISHED.
            let local_port = match fields[1].rsplit(':').next() {
                Some(p) => p,
                None => return false,
            };
            local_port.eq_ignore_ascii_case(port_hex) && fields[3] == "01"
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A realistic /proc/net/tcp header line (the parser skips it).
    const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";

    #[test]
    fn listen_socket_is_not_a_viewer() {
        // go2rtc's LISTEN socket: local port 8554 (216A) but state 0A (TCP_LISTEN), not 01 — must not
        // count as a viewer, else the panel would be held up forever.
        let proc = format!(
            "{HEADER}\n\
               0: 00000000000000000000000000000000:216A 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 10001 1 0000000000000000 100 0 0 10 0"
        );
        assert_eq!(established_local_port_count(&proc, "216A"), 0);
    }

    #[test]
    fn established_local_8554_is_one_viewer() {
        // A viewer's accepted socket: local port 8554 (216A), state 01 (ESTABLISHED) ⇒ counts.
        let proc = format!(
            "{HEADER}\n\
              44: 0100007F:216A 0100007F:AA70 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 0 0 10 -1"
        );
        assert_eq!(established_local_port_count(&proc, "216A"), 1);
        // The LISTEN socket alongside it still doesn't add to the count.
        let with_listen = format!(
            "{proc}\n\
               0: 00000000000000000000000000000000:216A 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 10001 1 0000000000000000 100 0 0 10 0"
        );
        assert_eq!(established_local_port_count(&with_listen, "216A"), 1);
    }

    #[test]
    fn eight554_as_the_remote_port_is_not_counted() {
        // The loopback CLIENT's own socket: local ephemeral (AA70), REMOTE port 8554 (216A), state 01.
        // We key off the LOCAL port only, so this must NOT count — otherwise a loopback viewer would be
        // double-counted (its client socket in tcp4 + go2rtc's accepted socket in tcp6).
        let proc = format!(
            "{HEADER}\n\
              45: 0100007F:AA70 0100007F:216A 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 20 0 0 10 -1"
        );
        assert_eq!(established_local_port_count(&proc, "216A"), 0);
    }

    #[test]
    fn multiple_viewers_are_summed() {
        // Two ESTABLISHED accepted sockets on local 8554 (two HA clients) ⇒ 2. A third line with 8554 as
        // the REMOTE port (a client socket) is ignored.
        let proc = format!(
            "{HEADER}\n\
              44: 0100007F:216A 0100007F:AA70 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 0 0 10 -1\n\
              46: 0100007F:216A 0200A8C0:C1AB 01 00000000:00000000 00:00000000 00000000  1000        0 12347 1 0000000000000000 20 0 0 10 -1\n\
              45: 0100007F:AA70 0100007F:216A 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 20 0 0 10 -1"
        );
        assert_eq!(established_local_port_count(&proc, "216A"), 2);
    }

    #[test]
    fn port_hex_match_is_case_insensitive() {
        // The /proc port field is uppercase hex, but match case-insensitively so a lowercase port_hex
        // (or a kernel that emitted lowercase) still counts.
        let proc = format!(
            "{HEADER}\n\
              44: 0100007F:216a 0100007F:AA70 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 0 0 10 -1"
        );
        assert_eq!(established_local_port_count(&proc, "216A"), 1);
        assert_eq!(established_local_port_count(&proc, "216a"), 1);
    }

    #[test]
    fn empty_and_header_only_are_zero() {
        assert_eq!(established_local_port_count("", "216A"), 0);
        assert_eq!(established_local_port_count(HEADER, "216A"), 0);
    }
}
