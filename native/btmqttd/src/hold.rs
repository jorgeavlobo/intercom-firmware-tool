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
//! ## Excluding go2rtc's OWN loopback publisher (not a viewer)
//! During a REAL view go2rtc's `exec:` ffmpeg copies the panel's H.264 back into go2rtc's own RTSP
//! server — it publishes `{output}` to `127.0.0.1:8554`. That publisher socket is ESTABLISHED and its
//! LOCAL port is ALSO 8554, so a naive local-port-8554 count would see it as a second "viewer" and keep
//! the panel held for ~go2rtc's idle timeout AFTER the real viewer already left. What distinguishes it:
//! a real external viewer's accepted socket carries the LAN IP as its LOCAL address (e.g.
//! `::ffff:192.168.50.251:8554`), whereas the publisher's LOCAL address is loopback
//! (`::ffff:127.0.0.1:8554` / `127.0.0.1:8554` / `::1`). So we count a local-port-8554 ESTABLISHED
//! socket only when its LOCAL IP is NOT loopback ([`is_loopback_hex`], matched against the exact /proc
//! loopback encodings — never by range, so a parse slip can't drop a real viewer and break auto-hold).
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
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Debounce for the (essentially never taken) `/proc` read-error log, so a broken procfs can't spam the
/// log every poll — the same one-shot-warn role the old API-unreachable `warned` flag served.
static READ_WARNED: AtomicBool = AtomicBool::new(false);

/// Poke `Start` while a viewer holds an ESTABLISHED TCP connection to go2rtc's RTSP port. Returns when
/// `stopping` is set. `main` also aborts this task at shutdown, so the poll-interval sleep is a bounded
/// wait.
pub async fn run(cfg: Arc<Config>, stopping: Arc<AtomicBool>, view_tx: mpsc::Sender<ViewCmd>) {
    // Poll every POLL_INTERVAL for a prompt panel start when a viewer connects, but never longer than
    // half the viewing window so a held view can't lapse between pokes (floored so a pathological tiny
    // window can't spin the loop). On the 30 s default this is a flat 1 s.
    let window = Duration::from_secs(cfg.camera_view_idle_secs.max(1));
    let period = POLL_INTERVAL
        .min(window / 2)
        .max(Duration::from_millis(500));
    while !stopping.load(Ordering::Relaxed) {
        if viewer_connected().await {
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
/// NEITHER file could be read that's logged once via [`READ_WARNED`]. Reads are async
/// (`tokio::fs::read_to_string`, consistent with `sprop.rs`) so a slow procfs read never blocks the
/// single-threaded runtime; the parsing helpers below stay pure/synchronous and unit-testable.
async fn viewer_connected() -> bool {
    let mut count = 0usize;
    let mut any_read = false;
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = tokio::fs::read_to_string(path).await {
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

/// Count ESTABLISHED sockets whose LOCAL port equals `port_hex` AND whose LOCAL IP is not loopback,
/// parsing `/proc/net/tcp`-format text. Skips the header line; for each remaining line it reads only
/// field[1] (`HEXIP:HEXPORT`, the LOCAL address — the port is the substring after the LAST `:`, the IP
/// the part before it) and field[3] (the connection state) straight off the whitespace iterator (no
/// per-line allocation), and counts the line when the local port matches `port_hex` (case-insensitive),
/// the state is `01` (TCP_ESTABLISHED), AND the local IP is NOT loopback (see [`is_loopback_hex`] — this
/// drops go2rtc's own `127.0.0.1:8554` republish so it is not miscounted as a viewer). Pure and
/// testable — no `/proc` I/O.
fn established_local_port_count(proc_tcp: &str, port_hex: &str) -> usize {
    proc_tcp
        .lines()
        .skip(1) // header row
        .filter(|line| {
            // Pull only the two fields we need straight from the iterator — no per-line Vec allocation,
            // since this runs every poll (~1s) on the single-threaded runtime. field[1] is the LOCAL
            // address, field[3] the state: `nth(1)` yields field[1] (skipping field[0]), then a second
            // `nth(1)` yields field[3] (skipping field[2]) from where the iterator now sits.
            let mut cols = line.split_whitespace();
            let (Some(local), Some(state)) = (cols.nth(1), cols.nth(1)) else {
                return false;
            };
            // `local` is the LOCAL `HEXIP:HEXPORT`; split off the port after the LAST ':' (IPv6
            // addresses in /proc are a single colon-free hex blob, so there's exactly one ':' here). The
            // part before it is the LOCAL IP. `state` "01" is TCP_ESTABLISHED.
            let (local_ip, local_port) = match local.rsplit_once(':') {
                Some((ip, port)) => (ip, port),
                None => return false,
            };
            // A local-port-8554 ESTABLISHED socket is a viewer only when its LOCAL IP is a real LAN
            // address: go2rtc's own exec ffmpeg republishes {output} to 127.0.0.1:8554 during a view, so
            // a LOOPBACK local IP here is that publisher, not an external viewer — skip it.
            local_port.eq_ignore_ascii_case(port_hex)
                && state == "01"
                && !is_loopback_hex(local_ip)
        })
        .count()
}

/// True iff `ip_hex` is a `/proc`-format LOOPBACK local address we must EXCLUDE from the viewer count.
/// go2rtc's own `exec:` ffmpeg republishes `{output}` to `127.0.0.1:8554` during a real view, so that
/// publisher's socket ALSO has local port 8554 — but a loopback local IP, unlike a real external viewer's
/// LAN local IP (see the module doc). Matches EXACTLY the loopback /proc encodings (case-insensitive) and
/// NOTHING else: matching by range could false-positive on a real LAN address and wrongly drop a viewer,
/// which would break auto-hold. Pure — no I/O.
fn is_loopback_hex(ip_hex: &str) -> bool {
    // The `/proc/net/tcp{,6}` address field prints each 32-bit word in HOST byte order (little-endian on
    // the armv7 target), words in order — NOT the network-order text form. IPv4 (len 8): 127.0.0.1 =>
    // `0100007F`. IPv6 (len 32): `::1` => `00000000000000000000000001000000` (the low word 0x00000001
    // byte-swapped to `01000000`), and the IPv4-mapped `::ffff:127.0.0.1` => `…FFFF00000100007F`.
    ip_hex.eq_ignore_ascii_case("0100007F")
        || ip_hex.eq_ignore_ascii_case("00000000000000000000000001000000")
        || ip_hex.eq_ignore_ascii_case("0000000000000000FFFF00000100007F")
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
        // A viewer's accepted socket: local port 8554 (216A), state 01 (ESTABLISHED), and a NON-loopback
        // LAN local IP (192.168.50.251 = FB32A8C0) ⇒ counts.
        let proc = format!(
            "{HEADER}\n\
              44: FB32A8C0:216A 0100007F:AA70 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 0 0 10 -1"
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
    fn remote_port_8554_is_not_counted() {
        // A CLIENT's own socket: local ephemeral (AA70) on a NON-loopback LAN IP, REMOTE port 8554
        // (216A), state 01. We key off the LOCAL port only, so this must NOT count — otherwise a viewer
        // would be double-counted (its client socket + go2rtc's accepted socket).
        let proc = format!(
            "{HEADER}\n\
              45: FB32A8C0:AA70 0100007F:216A 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 20 0 0 10 -1"
        );
        assert_eq!(established_local_port_count(&proc, "216A"), 0);
    }

    #[test]
    fn multiple_viewers_are_summed() {
        // Two ESTABLISHED accepted sockets on local 8554, both on NON-loopback LAN local IPs (two HA
        // clients) ⇒ 2. A third line with 8554 as the REMOTE port (a client socket) is ignored.
        let proc = format!(
            "{HEADER}\n\
              44: FB32A8C0:216A 0100007F:AA70 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 0 0 10 -1\n\
              46: FB32A8C0:216A 0200A8C0:C1AB 01 00000000:00000000 00:00000000 00000000  1000        0 12347 1 0000000000000000 20 0 0 10 -1\n\
              45: FB32A8C0:AA70 0100007F:216A 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 20 0 0 10 -1"
        );
        assert_eq!(established_local_port_count(&proc, "216A"), 2);
    }

    #[test]
    fn port_hex_match_is_case_insensitive() {
        // The /proc port field is uppercase hex, but match case-insensitively so a lowercase port_hex
        // (or a kernel that emitted lowercase) still counts. Local IP is a NON-loopback LAN address.
        let proc = format!(
            "{HEADER}\n\
              44: FB32A8C0:216a 0100007F:AA70 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 0 0 10 -1"
        );
        assert_eq!(established_local_port_count(&proc, "216A"), 1);
        assert_eq!(established_local_port_count(&proc, "216a"), 1);
    }

    #[test]
    fn real_lan_viewer_counts() {
        // A REAL external viewer's accepted socket in tcp6 form: local port 8554 (216A), state 01, and a
        // NON-loopback LAN local IP (::ffff:192.168.50.251) ⇒ a genuine viewer, counts.
        let proc = format!(
            "{HEADER}\n\
              44: 0000000000000000FFFF0000FB32A8C0:216A 0000000000000000FFFF0000FB32A8FB:AA70 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 0 0 10 -1"
        );
        assert_eq!(established_local_port_count(&proc, "216A"), 1);
    }

    #[test]
    fn loopback_publisher_is_not_a_viewer() {
        // go2rtc's OWN exec ffmpeg republishes {output} to 127.0.0.1:8554 during a real view: its socket
        // has local port 8554 (216A) and state 01, but a LOOPBACK local IP (::ffff:127.0.0.1). It must
        // NOT count, or the panel would be held ~go2rtc-idle after the real viewer already left.
        let proc = format!(
            "{HEADER}\n\
              47: 0000000000000000FFFF00000100007F:216A 0000000000000000FFFF00000100007F:AA70 01 00000000:00000000 00:00000000 00000000  1000        0 12348 1 0000000000000000 20 0 0 10 -1"
        );
        assert_eq!(established_local_port_count(&proc, "216A"), 0);
    }

    #[test]
    fn ipv6_loopback_local_is_not_a_viewer() {
        // A ::1 accepted socket (local port 8554, state 01) is likewise a loopback publisher, not an
        // external viewer ⇒ excluded. ::1 is rendered in procfs word-endian as the low word 0x00000001
        // byte-swapped to `01000000` (NOT the network-order `…00000001`).
        let proc = format!(
            "{HEADER}\n\
              48: 00000000000000000000000001000000:216A 00000000000000000000000001000000:AA70 01 00000000:00000000 00:00000000 00000000  1000        0 12349 1 0000000000000000 20 0 0 10 -1"
        );
        assert_eq!(established_local_port_count(&proc, "216A"), 0);
    }

    #[test]
    fn is_loopback_hex_matches_exactly_the_loopback_encodings() {
        // The three /proc loopback encodings we exclude (case-insensitive) …
        assert!(is_loopback_hex("0100007F")); // 127.0.0.1
        assert!(is_loopback_hex("0100007f"));
        assert!(is_loopback_hex("00000000000000000000000001000000")); // ::1 (procfs word-endian)
        assert!(is_loopback_hex("0000000000000000FFFF00000100007F")); // ::ffff:127.0.0.1
        assert!(is_loopback_hex("0000000000000000ffff00000100007f"));
        // … and NOTHING else — a real LAN address must never be treated as loopback.
        assert!(!is_loopback_hex("FB32A8C0")); // 192.168.50.251
        assert!(!is_loopback_hex("0000000000000000FFFF0000FB32A8C0")); // ::ffff:192.168.50.251
        assert!(!is_loopback_hex("00000000000000000000000000000000")); // :: (unspecified)
        // The NETWORK-order text of ::1 is NOT a procfs encoding — must not match (regression guard: the
        // constant is the word-endian form the kernel actually prints, not `…00000001`).
        assert!(!is_loopback_hex("00000000000000000000000000000001"));
        assert!(!is_loopback_hex(""));
    }

    #[test]
    fn empty_and_header_only_are_zero() {
        assert_eq!(established_local_port_count("", "216A"), 0);
        assert_eq!(established_local_port_count(HEADER, "216A"), 0);
    }
}
