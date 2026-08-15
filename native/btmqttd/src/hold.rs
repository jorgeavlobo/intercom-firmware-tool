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
//! ## Two signals: the external viewer, and go2rtc's OWN loopback publisher
//! During a REAL view go2rtc's `exec:` ffmpeg copies the panel's H.264 back into go2rtc's own RTSP
//! server — it publishes `{output}` to `127.0.0.1:8554`. That publisher socket is ESTABLISHED and its
//! LOCAL port is ALSO 8554, so a naive local-port-8554 count would see it as a second "viewer". What
//! distinguishes it: a real external viewer's accepted socket carries the LAN IP as its LOCAL address
//! (e.g. `::ffff:192.168.50.251:8554`), whereas the publisher's LOCAL address is loopback
//! (`::ffff:127.0.0.1:8554` / `127.0.0.1:8554` / `::1`). So we split the local-port-8554 ESTABLISHED
//! count by whether the LOCAL IP is loopback ([`is_loopback_hex`], matched against the exact /proc
//! loopback encodings — never by range, so a parse slip can't drop a real viewer and break auto-hold):
//!   * a NON-loopback match is a real EXTERNAL viewer — the "someone connected" BOOTSTRAP signal;
//!   * a loopback match is the publisher — present ONLY while go2rtc is actually SERVING an authenticated
//!     consumer (its `exec:` is lazy and RTSP-auth-gated), so it is the "media actually flowing" signal.
//!
//! ## Why both signals: bootstrap vs sustain (the AUTHENTICATED-ACTIVITY GATE)
//! The external socket alone must BOOTSTRAP the first open — go2rtc's exec can't serve until this task
//! brings the panel up — but it must not PIN the panel indefinitely: an unauthenticated LAN host (a
//! scanner, a health-check, a malicious hold) could otherwise hold the session up without ever knowing
//! the RTSP credentials. So a socket earns exactly ONE bootstrap ALLOWANCE ([`bootstrap_decision`]): while
//! it is live the socket renews on its own; once it lapses, renewal — and arming any FURTHER allowance —
//! requires either the SERVING signal (which only a genuinely authenticated view produces) or that a
//! cooldown gate has elapsed. Merely disconnecting and reconnecting does NOT mint a fresh allowance
//! ([`BOOTSTRAP_COOLDOWN`]), so a raw socket can't pin the panel by cycling faster than the SIP window
//! lapses; an observed serving clears the gate at once, so a working unit stays instantly responsive.
//! The allowance length is sized to whether the RUNTIME SDP already carries the parameter sets (see
//! [`BOOTSTRAP_GRACE`] / [`PROVISIONING_GRACE`] and [`sprop::runtime_sdp_has_sprop`]): a unit whose SDP
//! lacks them needs longer because go2rtc can't open the publisher until the first cold lock-on (~a
//! keyframe interval), and this gate is the only thing holding the panel up through it.
//!
//! Best-effort: reading `/proc` doesn't fail meaningfully — a read error reads as "no viewer" (logged
//! once). The manual `view_camera`/`stop_camera` MQTT actions are unaffected — every source drives the
//! same `view_rx`, and `ViewCmd::Start` is idempotent (a fresh full window each time).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::config::Config;
use crate::sip::ViewCmd;
use crate::sprop;

/// go2rtc's on-device RTSP port (`Go2RtcConfig.OnDeviceRtspPort` = 8554) as the uppercase hex the
/// `/proc/net/tcp` port field uses: 8554 = 0x216A. A client holding an ESTABLISHED connection to this
/// LOCAL port is a live viewer.
const RTSP_PORT_HEX: &str = "216A";
/// Target poll cadence. Short for RESPONSIVENESS: when Home Assistant opens the camera, the client
/// connects to `:8554` and this task must bring the panel session up within a couple seconds (not a
/// third of the viewing window). The effective period is still capped under the window (see `run`) so a
/// held view never lapses between pokes.
const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// How long one bootstrap allowance lets a viewer socket renew the window on the SOCKET ALONE before
/// renewal additionally requires go2rtc to be ACTUALLY serving (see `run`), on a unit whose RUNTIME SDP
/// ALREADY carries `sprop-parameter-sets` (learned, pre-seeded, or spliced at boot — see
/// [`sprop::runtime_sdp_has_sprop`]). With the parameter sets already in the SDP, go2rtc's copy ffmpeg
/// resolves the video and opens its loopback publisher within about a second of the panel coming up, so
/// this only has to outlast the RTSP handshake + panel-up + first republish. Short so an unauthenticated
/// socket's single allowance is brief (Codex). Validated on hardware.
const BOOTSTRAP_GRACE: Duration = Duration::from_secs(15);
/// The bootstrap allowance when the RUNTIME SDP has NO parameter sets yet (a genuinely fresh unit, or a
/// learn that persisted but whose best-effort runtime patch failed — see [`sprop::runtime_sdp_has_sprop`],
/// which is why grace is sized on the runtime SDP, not the persist record). There go2rtc's `-c:v copy`
/// ffmpeg cannot resolve the video — and therefore cannot open the loopback publisher `serving` keys off —
/// until the panel emits its next in-band SPS/PPS, up to a full ~20 s keyframe interval after the panel
/// comes up (see `sprop.rs`). The passive learner is renew-less, so THIS allowance is the only thing
/// holding the panel up through that first cold lock-on; it must outlast one keyframe interval + SIP settle
/// regardless of how short `camera_view_idle_secs` is, or the session BYEs before `serving` can ever go
/// true and the unit never learns (Codex). Generous margin over the ~20 s interval for settle/jitter and a
/// just-missed keyframe. Applies only until the runtime SDP gains its parameter sets (then serving
/// sustains the view and later opens fall back to `BOOTSTRAP_GRACE`).
const PROVISIONING_GRACE: Duration = Duration::from_secs(45);
/// Forced idle gap after a bootstrap allowance is SPENT WITHOUT reaching `serving`, before another
/// socket-alone allowance may arm. A raw socket earns exactly one `grace` allowance, then — crucially —
/// merely disconnecting and reconnecting must NOT mint a fresh one (that would let an unauthenticated
/// client pin the panel indefinitely by cycling the socket faster than the SIP window lapses; Codex). So
/// `run` gates the NEXT allowance behind `camera_view_idle_secs + BOOTSTRAP_COOLDOWN` measured from the
/// last arm: the `+ window` guarantees the panel actually comes down (a poke holds it up for the whole
/// window) and this margin is the true idle gap. An observed `serving` (a real authenticated view) clears
/// the gate immediately, so a working unit is always instantly responsive; the gate only bites an
/// unauthenticated cycler, bounding it to one `grace + window` up-period per `grace + window + cooldown`.
/// A benign socket that lingered through a genuine viewer's first attempt likewise recovers within it.
const BOOTSTRAP_COOLDOWN: Duration = Duration::from_secs(30);

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
    // The next allowance is gated behind window + BOOTSTRAP_COOLDOWN from the last arm, so a spent
    // allowance can't be refreshed by cycling the socket faster than the SIP window lapses (see
    // [`bootstrap_decision`] / [`BOOTSTRAP_COOLDOWN`]).
    let cooldown = window + BOOTSTRAP_COOLDOWN;
    // Bootstrap-allowance state (see [`bootstrap_decision`]): `boot_until` is the end of the current
    // socket-alone allowance (None if none is armed); `next_arm` is the earliest instant a NEW allowance
    // may arm (the cooldown gate). Starting `next_arm` in the past lets the first viewer arm immediately.
    let mut boot_until: Option<Instant> = None;
    let mut next_arm = Instant::now();
    // Sticky: has the RUNTIME SDP gained its `sprop-parameter-sets` (so go2rtc resolves fast and `serving`
    // appears within ~a second)? It only ever goes false→true within a boot (a learn splices it; a reboot
    // re-splices from persist), so once true we stop re-reading. While false we re-check each poll — cheap,
    // and only during the transient unprovisioned window — so the grace tier follows a mid-view first learn.
    let mut resolves_fast = false;
    while !stopping.load(Ordering::Relaxed) {
        let (viewer, serving) = viewer_signals().await;
        if !resolves_fast {
            resolves_fast = sprop::runtime_sdp_has_sprop().await;
        }
        let grace = if resolves_fast {
            BOOTSTRAP_GRACE
        } else {
            PROVISIONING_GRACE
        };
        let now = Instant::now();
        let (new_until, new_next_arm, poke) =
            bootstrap_decision(boot_until, next_arm, viewer, serving, now, grace, cooldown);
        boot_until = new_until;
        next_arm = new_next_arm;
        if poke {
            // Renew the on-demand window. try_send never blocks the poll loop: a full queue means sip.rs
            // isn't draining (reconnect backoff) and a dropped poke is harmless — the next poll pokes
            // again; Closed means the SIP task is gone, nothing to hold.
            //
            // DELIBERATE: auto-hold is AUTHORITATIVE while a viewer is genuinely watching. If an operator
            // issues `stop_camera` (ViewCmd::Stop) while Home Assistant still has the feed open, this poll
            // re-Starts within one interval — so a Stop only interrupts an active view briefly rather than
            // ending it. This is by design: the session follows the live viewer, which is exactly what makes
            // the feature "transparent" (HA just opens the camera). To end a view, close it (the TCP
            // connection clears → these pokes stop → the window lapses); `stop_camera` remains effective
            // when no viewer is connected (e.g. after a ring). Honoring the Stop over an active viewer was
            // considered and rejected: tearing the session down drops the client, HA auto-reconnects, the
            // connection reappears, and a suppression flag would fight HA's reconnect for no real benefit
            // (product decision on #129; Codex).
            let _ = view_tx.try_send(ViewCmd::Start);
        }
        // Re-check `stopping` before sleeping so a shutdown observed mid-poll exits promptly.
        if stopping.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(period).await;
    }
}

/// Decide, for one poll, whether to poke `Start` and how the bootstrap-allowance state advances. Pure (no
/// I/O, no wall clock) so the bootstrap / serving / cooldown state machine is unit-testable; `run` owns the
/// clock and the async `/proc` + SDP reads.
///
/// The AUTHENTICATED-ACTIVITY GATE (Codex): a raw TCP socket to :8554 is enough to BOOTSTRAP the first
/// open — it has to be, because go2rtc's exec is lazy and can't serve (spawn ffmpeg, get RTP) until this
/// task brings the panel up — but a raw socket alone must not PIN the panel indefinitely: an
/// unauthenticated LAN host (a scanner, a health-check, a malicious hold) could otherwise keep the session
/// up without ever knowing the RTSP credentials, and simply reconnecting must not refresh that ability.
/// So a socket earns exactly ONE `grace` allowance; renewing past it — or arming another after it lapses —
/// requires either `serving` (go2rtc's own exec ffmpeg republishing on loopback :8554, present ONLY while
/// it is actually serving an authenticated consumer) or that the cooldown gate (`next_arm`) has elapsed.
///
/// Arguments: `until` = current allowance end (None if unarmed); `next_arm` = earliest instant a new
/// allowance may arm; `viewer` = an external socket is present; `serving` = the authenticated-serving
/// signal; `now`; `grace` = the allowance length for the unit's provisioning tier; `cooldown` = the arm-
/// to-next-arm gate. Returns `(new_until, new_next_arm, poke)`.
fn bootstrap_decision(
    until: Option<Instant>,
    next_arm: Instant,
    viewer: bool,
    serving: bool,
    now: Instant,
    grace: Duration,
    cooldown: Duration,
) -> (Option<Instant>, Instant, bool) {
    if serving {
        // Authenticated media is flowing: renew, and let the NEXT allowance arm immediately — a real view
        // proved the path works, so a later reopen isn't cooldown-gated. Drop the socket-alone allowance;
        // serving is the authority while it holds.
        return (None, now, true);
    }
    if !viewer {
        // No external socket: nothing to hold, and the loopback publisher alone is never a viewer. Crucially
        // we PRESERVE `next_arm` — a mere connection gap must not grant the next raw connection a fresh
        // allowance (Codex), so an unauthenticated cycler stays gated across the gap.
        return (until, next_arm, false);
    }
    match until {
        // Within the active allowance: keep poking.
        Some(d) if now < d => (until, next_arm, true),
        // No live allowance (unarmed, or the last one lapsed without serving) AND the cooldown gate has
        // elapsed: arm a fresh allowance and push the gate out past it. This is the ONLY place a raw socket
        // earns socket-alone renewal, and it's rate-limited — a client that never reaches `serving` gets at
        // most one `grace` per `grace + cooldown`, so it cannot pin the panel indefinitely by cycling; a
        // genuine viewer bootstraps immediately when no recent allowance was spent, and unlocks fully the
        // moment its view authenticates (the `serving` branch above).
        _ if now >= next_arm => (Some(now + grace), now + grace + cooldown, true),
        // Allowance spent and still within the cooldown gate: hold off.
        _ => (until, next_arm, false),
    }
}

/// Read `/proc/net/tcp{,6}` and report `(viewer_connected, serving_consumer)`:
///   * `viewer_connected` — at least one real LAN client holds an ESTABLISHED :8554 socket (the
///     bootstrap signal: "someone connected").
///   * `serving_consumer` — go2rtc's OWN exec ffmpeg is republishing on loopback :8554 (the sustain
///     signal: "authenticated media is actually flowing"; see [`established_local_port_counts`]).
///
/// Reading `/proc` doesn't fail meaningfully: a file that can't be read contributes nothing, and if
/// NEITHER file could be read that's logged once via [`READ_WARNED`]. Reads are async
/// (`tokio::fs::read_to_string`, consistent with `sprop.rs`) so a slow procfs read never blocks the
/// single-threaded runtime; the parsing helper below stays pure/synchronous and unit-testable.
async fn viewer_signals() -> (bool, bool) {
    let mut external = 0usize;
    let mut publisher = 0usize;
    let mut any_read = false;
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = tokio::fs::read_to_string(path).await {
            any_read = true;
            let (e, p) = established_local_port_counts(&text, RTSP_PORT_HEX);
            external += e;
            publisher += p;
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
    (external > 0, publisher > 0)
}

/// Tally ESTABLISHED sockets whose LOCAL port equals `port_hex`, parsing `/proc/net/tcp`-format text,
/// SPLIT by whether the LOCAL IP is loopback. Returns `(external, loopback)`:
///   * `external` — a NON-loopback local IP: a real LAN RTSP client (the "viewer connected" signal).
///   * `loopback` — a LOOPBACK local IP: go2rtc's OWN exec ffmpeg republishing `{output}` to
///     `127.0.0.1:8554`, which is present ONLY while go2rtc is actively serving an authenticated
///     consumer (its exec is lazy and RTSP-auth-gated) — the "actually being watched" signal `run` uses
///     to sustain the hold past the bootstrap grace.
///
/// Skips the header line; for each remaining line it reads only field[1] (`HEXIP:HEXPORT`, the LOCAL
/// address — port after the LAST `:`, IP before it) and field[3] (the connection state) straight off the
/// whitespace iterator (no per-line allocation, since this runs every poll ~1s). Pure and testable — no
/// `/proc` I/O.
fn established_local_port_counts(proc_tcp: &str, port_hex: &str) -> (usize, usize) {
    let mut external = 0usize;
    let mut loopback = 0usize;
    for line in proc_tcp.lines().skip(1) {
        // `nth(1)` yields field[1] (skipping field[0]); a second `nth(1)` yields field[3] (skipping
        // field[2]) from where the iterator now sits.
        let mut cols = line.split_whitespace();
        let (Some(local), Some(state)) = (cols.nth(1), cols.nth(1)) else {
            continue;
        };
        // `local` is the LOCAL `HEXIP:HEXPORT`; split off the port after the LAST ':' (IPv6 addresses in
        // /proc are a single colon-free hex blob, so there's exactly one ':' here). `state` "01" is
        // TCP_ESTABLISHED.
        let Some((local_ip, local_port)) = local.rsplit_once(':') else {
            continue;
        };
        if local_port.eq_ignore_ascii_case(port_hex) && state == "01" {
            if is_loopback_hex(local_ip) {
                loopback += 1; // go2rtc's own republish — an authenticated-serving signal, not a viewer
            } else {
                external += 1; // a real external LAN viewer
            }
        }
    }
    (external, loopback)
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
        assert_eq!(established_local_port_counts(&proc, "216A"), (0, 0));
    }

    #[test]
    fn established_local_8554_is_one_viewer() {
        // A viewer's accepted socket: local port 8554 (216A), state 01 (ESTABLISHED), and a NON-loopback
        // LAN local IP (192.168.50.251 = FB32A8C0) ⇒ counts.
        let proc = format!(
            "{HEADER}\n\
              44: FB32A8C0:216A 0100007F:AA70 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 0 0 10 -1"
        );
        assert_eq!(established_local_port_counts(&proc, "216A"), (1, 0));
        // The LISTEN socket alongside it still doesn't add to the count.
        let with_listen = format!(
            "{proc}\n\
               0: 00000000000000000000000000000000:216A 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 10001 1 0000000000000000 100 0 0 10 0"
        );
        assert_eq!(established_local_port_counts(&with_listen, "216A"), (1, 0));
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
        assert_eq!(established_local_port_counts(&proc, "216A"), (0, 0));
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
        assert_eq!(established_local_port_counts(&proc, "216A"), (2, 0));
    }

    #[test]
    fn port_hex_match_is_case_insensitive() {
        // The /proc port field is uppercase hex, but match case-insensitively so a lowercase port_hex
        // (or a kernel that emitted lowercase) still counts. Local IP is a NON-loopback LAN address.
        let proc = format!(
            "{HEADER}\n\
              44: FB32A8C0:216a 0100007F:AA70 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 0 0 10 -1"
        );
        assert_eq!(established_local_port_counts(&proc, "216A"), (1, 0));
        assert_eq!(established_local_port_counts(&proc, "216a"), (1, 0));
    }

    #[test]
    fn real_lan_viewer_counts() {
        // A REAL external viewer's accepted socket in tcp6 form: local port 8554 (216A), state 01, and a
        // NON-loopback LAN local IP (::ffff:192.168.50.251) ⇒ a genuine viewer, counts.
        let proc = format!(
            "{HEADER}\n\
              44: 0000000000000000FFFF0000FB32A8C0:216A 0000000000000000FFFF0000FB32A8FB:AA70 01 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 20 0 0 10 -1"
        );
        assert_eq!(established_local_port_counts(&proc, "216A"), (1, 0));
    }

    #[test]
    fn loopback_publisher_is_the_serving_signal_not_an_external_viewer() {
        // go2rtc's OWN exec ffmpeg republishes {output} to 127.0.0.1:8554 during a real view: its socket
        // has local port 8554 (216A) and state 01, but a LOOPBACK local IP (::ffff:127.0.0.1). It is NOT
        // an external viewer (external == 0), so it can never PIN the panel on its own; instead it is the
        // `serving` signal (loopback == 1) — present only while go2rtc actively serves an authenticated
        // consumer — that `run` uses to sustain the hold past the bootstrap grace.
        let proc = format!(
            "{HEADER}\n\
              47: 0000000000000000FFFF00000100007F:216A 0000000000000000FFFF00000100007F:AA70 01 00000000:00000000 00:00000000 00000000  1000        0 12348 1 0000000000000000 20 0 0 10 -1"
        );
        assert_eq!(established_local_port_counts(&proc, "216A"), (0, 1));
    }

    #[test]
    fn ipv6_loopback_local_is_the_serving_signal_not_an_external_viewer() {
        // A ::1 accepted socket (local port 8554, state 01) is likewise a loopback publisher: external ==
        // 0 (never a viewer), loopback == 1 (the serving signal). ::1 is rendered in procfs word-endian as
        // the low word 0x00000001 byte-swapped to `01000000` (NOT the network-order `…00000001`).
        let proc = format!(
            "{HEADER}\n\
              48: 00000000000000000000000001000000:216A 00000000000000000000000001000000:AA70 01 00000000:00000000 00:00000000 00000000  1000        0 12349 1 0000000000000000 20 0 0 10 -1"
        );
        assert_eq!(established_local_port_counts(&proc, "216A"), (0, 1));
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
        assert_eq!(established_local_port_counts("", "216A"), (0, 0));
        assert_eq!(established_local_port_counts(HEADER, "216A"), (0, 0));
    }

    // --- bootstrap_decision: the socket-alone allowance + serving gate + cooldown state machine ---

    // Fixture durations for the pure state-machine tests. Their absolute values are irrelevant to the
    // logic — only their ordering against the injected `now` — so GRACE/COOL are simply distinct, round
    // numbers matching the provisioned-tier shape (short grace, a longer arm-to-next-arm gate).
    const GRACE: Duration = Duration::from_secs(15);
    const COOL: Duration = Duration::from_secs(60);

    fn at(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    #[test]
    fn first_viewer_arms_an_allowance_and_pokes() {
        let t = Instant::now();
        // Unarmed, cooldown gate already open (next_arm == now), a viewer appears, not serving yet.
        let (until, next_arm, poke) = bootstrap_decision(None, t, true, false, t, GRACE, COOL);
        assert!(poke);
        assert_eq!(until, Some(t + GRACE)); // allowance = now + grace
        assert_eq!(next_arm, t + GRACE + COOL); // next arm gated by grace + cooldown
    }

    #[test]
    fn within_the_allowance_keeps_poking_without_rearming() {
        let t = Instant::now();
        let until = Some(at(t, 15));
        let next_arm = at(t, 75);
        // 10 s in: still inside the allowance ⇒ poke, state unchanged.
        let (u, n, poke) = bootstrap_decision(until, next_arm, true, false, at(t, 10), GRACE, COOL);
        assert!(poke);
        assert_eq!(u, until);
        assert_eq!(n, next_arm);
    }

    #[test]
    fn expired_allowance_without_serving_is_gated_until_cooldown() {
        let t = Instant::now();
        let until = Some(at(t, 15));
        let next_arm = at(t, 75);
        // 20 s in: the allowance lapsed (now >= until) but the cooldown gate hasn't elapsed (now <
        // next_arm) ⇒ no poke, and no fresh allowance armed.
        let (u, n, poke) = bootstrap_decision(until, next_arm, true, false, at(t, 20), GRACE, COOL);
        assert!(!poke);
        assert_eq!(u, until);
        assert_eq!(n, next_arm);
    }

    #[test]
    fn reconnect_within_cooldown_cannot_refresh_the_allowance() {
        // Codex: an unauthenticated client holds a socket, drops it for a poll, and reconnects. The gap
        // (viewer == false) must NOT reset the cooldown gate, so the reconnect stays gated — otherwise a
        // raw socket could pin the panel indefinitely by cycling faster than the SIP window lapses.
        let t = Instant::now();
        let until = Some(at(t, 15));
        let next_arm = at(t, 75);
        // Gap poll: no viewer ⇒ state preserved verbatim (the key property: next_arm survives the gap).
        let (u_gap, n_gap, poke_gap) =
            bootstrap_decision(until, next_arm, false, false, at(t, 16), GRACE, COOL);
        assert!(!poke_gap);
        assert_eq!(u_gap, until);
        assert_eq!(n_gap, next_arm);
        // Reconnect poll, still within the cooldown gate ⇒ still gated, no fresh grace.
        let (_, _, poke_reconnect) =
            bootstrap_decision(u_gap, n_gap, true, false, at(t, 17), GRACE, COOL);
        assert!(!poke_reconnect);
    }

    #[test]
    fn a_fresh_allowance_arms_once_the_cooldown_gate_elapses() {
        // CodeRabbit: a genuine viewer that arrived after an earlier socket spent the allowance must not be
        // starved forever — once the cooldown gate passes, a new allowance arms.
        let t = Instant::now();
        let now = at(t, 80); // past next_arm (t + 75)
        let (u, n, poke) = bootstrap_decision(Some(at(t, 15)), at(t, 75), true, false, now, GRACE, COOL);
        assert!(poke);
        assert_eq!(u, Some(now + GRACE));
        assert_eq!(n, now + GRACE + COOL);
    }

    #[test]
    fn serving_pokes_and_opens_the_gate_immediately() {
        // An authenticated view: poke regardless of the allowance, drop the allowance, and reset the gate
        // to `now` so the NEXT reopen isn't cooldown-gated (a working unit stays instantly responsive).
        let t = Instant::now();
        let now = at(t, 500);
        // Even with the allowance long expired and the cooldown gate far in the future, serving wins.
        let (u, n, poke) = bootstrap_decision(Some(at(t, 15)), at(t, 999), true, true, now, GRACE, COOL);
        assert!(poke);
        assert_eq!(u, None);
        assert_eq!(n, now); // gate reset to now
    }

    #[test]
    fn serving_sustains_the_view_past_the_allowance() {
        // Past the allowance and the cooldown, a still-serving view keeps poking (the serving branch is
        // checked before the allowance logic).
        let t = Instant::now();
        let (_, _, poke) = bootstrap_decision(None, t, true, true, at(t, 300), GRACE, COOL);
        assert!(poke);
    }

    #[test]
    fn no_viewer_never_pokes_and_preserves_the_gate() {
        // The loopback publisher alone is never a viewer; with no external socket we never poke, and the
        // cooldown gate is preserved across the idle gap (so a later raw reconnect can't jump the gate).
        let t = Instant::now();
        let until = Some(at(t, 15));
        let next_arm = at(t, 75);
        let (u, n, poke) = bootstrap_decision(until, next_arm, false, false, at(t, 50), GRACE, COOL);
        assert!(!poke);
        assert_eq!(u, until);
        assert_eq!(n, next_arm);
    }
}
