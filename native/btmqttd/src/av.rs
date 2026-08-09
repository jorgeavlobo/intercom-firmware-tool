//! Live doorbell camera (Phase 1, issues #103–#105): siphon the panel's own cleartext
//! A/V and fan it out for Home Assistant, with NO SIP and NO extra device tooling.
//!
//! ## Mechanism (firmware-verified on the Classe 100X and 300X)
//! The on-board `bt_av_media` daemon encodes the entrance camera to a GStreamer
//! `multiudpsink` (H.264 for video, speex for audio). Sending a WHO=7
//! `*7*300#<ip>#<port>#<branch>##` frame to its command port (`:30007`) **adds a UDP
//! client** to that sink — a non-disruptive fan-out: the panel keeps rendering to its own
//! client while it *also* sends a cleartext RTP copy to the `ip:port` we name. So we
//! never decode, transcode, or open `/dev/video` here — we just ask for a copy.
//!
//! ## What this task does
//! It runs its **own** OWN monitor session (`:20000`), independent of `sender.rs`, so it
//! can't perturb the reviewed call-state machine there. Whenever the panel brings an A/V
//! session up — a ring, an answered call, or the eye/self-view — the bus carries the
//! panel's own `*7*300#127#0#0#1#<port>#<branch>##` frames; we take that as "media is
//! live now" and **add our own client** on `:30007`, pointing the low-res H.264 (+ speex
//! audio) at `camera_target` (the go2rtc/Home-Assistant host). When the panel tears the
//! session down (`*7*0*##`) we simply drop our `:30007` connection.
//!
//! ## Why we never send `*7*0*##`
//! In this ring/self-view flow the **panel** owns the session lifecycle. `*7*0*##` tears
//! down the WHOLE media session (every `multiudpsink` client, including the panel's own
//! on-screen view). We must not do that — a resident looking at the door would lose the
//! picture. We only ever ADD a client and let the panel's own teardown remove it. (The
//! on-demand path in #104, where *we* originate the session, is the place that will own
//! and tear down a session — not here.)

use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::{Config, OWN_PORT_AV};
use crate::own::Framer;

/// Monitor-session request, identical to `sender.rs` — the gateway streams every bus
/// frame after this.
const MONITOR_REQ: &[u8] = b"*99*1##";

/// The panel's own media-start frames target loopback (`127.0.0.1` = `127#0#0#1`); this
/// prefix marks "the encoder is now streaming" and is our arm signal. Our OWN added
/// client targets `camera_target` (different octets), so it never matches this.
const DEVICE_MEDIA_PREFIX: &str = "*7*300#127#0#0#1#";

/// Whole-session teardown emitted by the panel when the A/V session ends.
const TEARDOWN: &str = "*7*0*##";

/// A/V daemon reply frames (same control frames as the monitor ACK/NACK).
const AV_ACK: &[u8] = b"*#*1##";
const AV_NACK: &[u8] = b"*#*0##";

/// How many times to re-send an "add client" frame on a NACK before giving up on it
/// (mirrors the reference project's `≤3`).
const ADD_CLIENT_RETRIES: u32 = 3;

/// How long to wait for the `:30007` ACK/NACK for one "add client" frame. Loopback, tiny
/// payload — a couple of seconds is generous and keeps a hung daemon from stalling arm.
const ACK_TIMEOUT: Duration = Duration::from_secs(2);

/// Idle cap on a monitor read, so a quiet bus still lets the loop re-check `stopping`
/// and exit promptly at shutdown (the bus is rarely silent this long — dim/keepalive
/// frames arrive — but the bound guarantees responsiveness regardless).
const READ_IDLE: Duration = Duration::from_secs(15);

/// Reconnect backoff bounds for the monitor session (a gateway restart / boot race).
const BACKOFF_INIT: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Run the camera A/V task: keep an OWN monitor session up and drive the `:30007`
/// siphon from it. Owned by `main`, which sets `stopping` at shutdown; there is no
/// half-actuated state to drain (we never send a teardown), so exiting is immediate.
pub async fn run(cfg: Arc<Config>, stopping: Arc<AtomicBool>) {
    let mut backoff = BACKOFF_INIT;
    while !stopping.load(Ordering::Relaxed) {
        match session(&cfg, &stopping).await {
            // A clean return means `stopping` was observed — leave the loop.
            Ok(()) => break,
            Err(e) => eprintln!("btmqttd: camera monitor {}: {e}", cfg.own_port_mon),
        }
        if stopping.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

/// One monitor session: connect, request the stream, and arm/disarm the siphon from the
/// panel's own media frames. Returns `Ok(())` only when `stopping` was seen; any I/O
/// error is returned so `run` backs off and reconnects. The armed `:30007` socket lives
/// in `siphon`; dropping it (on teardown, error, or return) closes it.
async fn session(cfg: &Arc<Config>, stopping: &Arc<AtomicBool>) -> std::io::Result<()> {
    let mut sock = TcpStream::connect((cfg.own_host.as_str(), cfg.own_port_mon)).await?;
    sock.write_all(MONITOR_REQ).await?;
    sock.flush().await?;

    let mut framer = Framer::default();
    let mut buf = [0u8; 4096];
    let mut frames: Vec<String> = Vec::new();
    let mut siphon: Option<TcpStream> = None; // Some(_) while our client is added

    loop {
        if stopping.load(Ordering::Relaxed) {
            return Ok(());
        }
        let n = match tokio::time::timeout(READ_IDLE, sock.read(&mut buf)).await {
            Ok(Ok(0)) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "monitor closed",
                ))
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => continue, // idle: re-check `stopping`, keep reading
        };

        frames.clear();
        framer.push(&buf[..n], &mut frames);
        for f in &frames {
            if f == TEARDOWN {
                // Panel ended the session — our added client is gone with it; drop ours.
                if siphon.take().is_some() {
                    eprintln!("btmqttd: camera siphon released (session ended)");
                }
            } else if siphon.is_none() && f.starts_with(DEVICE_MEDIA_PREFIX) {
                // Media is live now: add our client and hand HA the stream.
                match arm(cfg).await {
                    Ok(s) => {
                        siphon = Some(s);
                        eprintln!(
                            "btmqttd: camera siphon armed -> {}:{}/{} (branch {})",
                            cfg.camera_target,
                            cfg.camera_video_port,
                            cfg.camera_audio_port,
                            cfg.camera_branch
                        );
                    }
                    Err(e) => eprintln!("btmqttd: camera siphon arm failed: {e}"),
                }
            }
        }
    }
}

/// Open a `:30007` session and add our video + audio UDP clients pointing at
/// `camera_target`. Returns the still-open socket (kept for the session lifetime; the
/// daemon drops the clients when the connection closes or the panel tears down). Errors
/// if the target can't be resolved or the daemon NACKs an "add client" past its retries.
async fn arm(cfg: &Arc<Config>) -> std::io::Result<TcpStream> {
    let ip = resolve_ipv4(&cfg.camera_target).await.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("camera_target '{}' did not resolve to an IPv4", cfg.camera_target),
        )
    })?;
    let o = ip.octets();
    let ipf = format!("{}#{}#{}#{}", o[0], o[1], o[2], o[3]);
    let video = format!("*7*300#{ipf}#{}#{}*##", cfg.camera_video_port, cfg.camera_branch);
    let audio = format!("*7*300#{ipf}#{}#2*##", cfg.camera_audio_port);

    let mut sock = TcpStream::connect(("127.0.0.1", OWN_PORT_AV)).await?;
    add_client(&mut sock, &video).await?;
    add_client(&mut sock, &audio).await?;
    Ok(sock)
}

/// Write one "add client" frame and wait for the daemon's ACK, retrying on NACK up to
/// [`ADD_CLIENT_RETRIES`]. A NACK past the retries, an EOF, or a timeout is an error.
async fn add_client(sock: &mut TcpStream, frame: &str) -> std::io::Result<()> {
    for _ in 0..ADD_CLIENT_RETRIES {
        sock.write_all(frame.as_bytes()).await?;
        sock.flush().await?;

        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(ACK_TIMEOUT, sock.read(&mut buf))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "av daemon ack timed out")
            })??;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "av daemon closed",
            ));
        }
        let resp = &buf[..n];
        if contains(resp, AV_ACK) {
            return Ok(());
        }
        if !contains(resp, AV_NACK) {
            // Neither ACK nor NACK: an unexpected reply — don't spin, surface it.
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "av daemon: unexpected reply to add-client",
            ));
        }
        // NACK: loop and retry the same frame.
    }
    Err(std::io::Error::other(
        "av daemon NACKed add-client past retries",
    ))
}

/// Resolve `host` to an IPv4 for the OWN `*7*300#a#b#c#d#…` target: a literal dotted
/// IPv4 is used as-is; otherwise the first IPv4 from a DNS lookup. `None` if neither
/// yields an IPv4 (an IPv6-only or unresolvable target — the fan-out frame is IPv4-only).
async fn resolve_ipv4(host: &str) -> Option<Ipv4Addr> {
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return Some(v4);
    }
    // Port 0: we only want the address; the port in the frame comes from config.
    let addrs = tokio::net::lookup_host((host, 0)).await.ok()?;
    for a in addrs {
        if let IpAddr::V4(v4) = a.ip() {
            return Some(v4);
        }
    }
    None
}

/// True if `needle` occurs in `haystack` (small buffers; a plain scan is ample).
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm_signal_is_only_the_loopback_media_frame() {
        // The panel's own media-start (loopback target) arms us…
        assert!("*7*300#127#0#0#1#5007#0*##".starts_with(DEVICE_MEDIA_PREFIX));
        assert!("*7*300#127#0#0#1#5002#1*##".starts_with(DEVICE_MEDIA_PREFIX));
        // …but our OWN fan-out frame (a non-loopback target) does not, so we never
        // re-arm off our own echo on the monitor.
        assert!(!"*7*300#192#168#1#50#40000#1*##".starts_with(DEVICE_MEDIA_PREFIX));
        // The teardown is matched exactly.
        assert_eq!(TEARDOWN, "*7*0*##");
    }

    #[test]
    fn contains_finds_ack_and_nack() {
        assert!(contains(b"*#*1##", AV_ACK));
        assert!(contains(b"junk*#*1##junk", AV_ACK));
        assert!(contains(b"*#*0##", AV_NACK));
        assert!(!contains(b"*#*1##", AV_NACK));
        assert!(!contains(b"", AV_ACK));
    }

    #[test]
    fn resolve_ipv4_accepts_literal() {
        // A literal dotted IPv4 resolves synchronously (no DNS), so a tiny runtime is fine.
        let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let v4 = rt.block_on(resolve_ipv4("192.168.1.50"));
        assert_eq!(v4, Some(Ipv4Addr::new(192, 168, 1, 50)));
        // An empty target yields nothing rather than a bogus address.
        assert_eq!(rt.block_on(resolve_ipv4("")), None);
    }
}
