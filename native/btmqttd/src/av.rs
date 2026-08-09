//! Live doorbell camera (Phase 1, issues #103–#105): siphon the panel's own cleartext
//! A/V and fan it out for Home Assistant, with NO SIP and NO extra device tooling.
//!
//! ## Mechanism (firmware-verified on the Classe 100X and 300X)
//! The on-board `bt_av_media` daemon encodes the entrance camera to a GStreamer
//! `multiudpsink` (H.264 for video, speex for audio). Sending a WHO=7
//! `*7*300#<ip>#<port>#<branch>*##` frame to its command port (`:30007`) **adds a UDP
//! client** to that sink — a non-disruptive fan-out: the panel keeps rendering to its own
//! client while it *also* sends a cleartext RTP copy to the `ip:port` we name. So we
//! never decode, transcode, or open `/dev/video` here — we just ask for a copy.
//!
//! ## What this task does
//! It runs its **own** OWN monitor session (`:20000`), independent of `sender.rs`, so it
//! can't perturb the reviewed call-state machine there. Whenever the panel brings an A/V
//! session up — a ring, an answered call, or the eye/self-view — the bus carries the
//! panel's own `*7*300#127#0#0#1#<port>#<branch>*##` frames; we take that as "media is
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

/// TOTAL attempts to send an "add client" frame (the loop runs `0..ADD_CLIENT_ATTEMPTS`): one
/// initial send plus NACK retries, 3 in all (≤ the reference project's cap).
const ADD_CLIENT_ATTEMPTS: u32 = 3;

/// How long to wait for the `:30007` ACK/NACK for one "add client" frame. Loopback, tiny
/// payload — a couple of seconds is generous and keeps a hung daemon from stalling arm.
const ACK_TIMEOUT: Duration = Duration::from_secs(2);

/// How long to wait for the monitor-session ACK (`*#*1##`) after `*99*1##` before treating
/// the session as refused and reconnecting. The gateway can accept the TCP connection yet
/// REFUSE the monitor with a NACK (e.g. monitor slots exhausted) and then go idle; a bound
/// here turns that into a backoff-reconnect instead of an infinite idle. Matches `sender.rs`.
const MONITOR_ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// Ceiling on bytes accumulated while waiting for a control ACK/NACK. The reply is a 6-byte
/// `*#*1##` / `*#*0##` (at most preceded by a tiny banner or one batched media frame), so a
/// few KB is ample. The cap keeps a misbehaving peer that streams non-control bytes until the
/// timeout from ballooning the accumulation buffer — overflow is an error (reconnect / fail).
const MAX_CTRL_BYTES: usize = 4096;

/// Idle cap on a monitor read, so a quiet bus still lets the loop re-check `stopping`
/// and exit promptly at shutdown (the bus is rarely silent this long — dim/keepalive
/// frames arrive — but the bound guarantees responsiveness regardless).
const READ_IDLE: Duration = Duration::from_secs(15);

/// Reconnect backoff bounds for the monitor session (a gateway restart / boot race).
const BACKOFF_INIT: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// A session that stayed up at least this long was HEALTHY: its eventual drop resets the
/// backoff, so a long-stable monitor that finally hiccups reconnects promptly instead of
/// inheriting a maxed-out delay (which could otherwise miss a ring). Mirrors `sender.rs`.
const HEALTHY_SESSION: Duration = Duration::from_secs(60);

/// Run the camera A/V task: keep an OWN monitor session up and drive the `:30007`
/// siphon from it. Owned by `main`, which sets `stopping` at shutdown; there is no
/// half-actuated state to drain (we never send a teardown), so exiting is immediate.
///
/// KNOWN LIMITATION (issue #103, deferred to a hardware-tested follow-up): the siphon is
/// SESSION-LOCAL — if the `:20000` monitor socket drops WHILE a call is live, `session`
/// returns, its `:30007` socket closes, and the fan-out stops for the rest of that call;
/// it re-arms only on the NEXT media-start frame. This is accepted for now because (a) on
/// this device the monitor and `bt_av_media` are the same BTicino stack, so a monitor drop
/// almost always means the media session ended too (nothing left to re-arm), and (b) the
/// robust fix — persisting the siphon across a monitor reconnect — must also reconcile a
/// teardown MISSED during the gap (else it stays wrongly "armed" and the NEXT call gets no
/// camera), which needs on-hardware validation to get right. Tracked for Phase 1 follow-up.
pub async fn run(cfg: Arc<Config>, stopping: Arc<AtomicBool>) {
    let mut backoff = BACKOFF_INIT;
    while !stopping.load(Ordering::Relaxed) {
        let start = tokio::time::Instant::now();
        match session(&cfg, &stopping).await {
            // A clean return means `stopping` was observed — leave the loop.
            Ok(()) => break,
            Err(e) => eprintln!("btmqttd: camera monitor {}: {e}", cfg.own_port_mon),
        }
        if stopping.load(Ordering::Relaxed) {
            break;
        }
        // A session that ran healthy for a while shouldn't inherit a maxed-out backoff from
        // earlier startup churn — reset so the reconnect is prompt (a 30 s wait could miss a ring).
        if start.elapsed() >= HEALTHY_SESSION {
            backoff = BACKOFF_INIT;
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

    // Confirm the monitor ACK before trusting the stream. The gateway may accept the TCP
    // connection yet REFUSE the monitor with a NACK (`*#*0##`) and then stay idle — the
    // `Framer` DROPS the control frames, so without a raw-byte scan here the read loop would
    // just time out on `READ_IDLE` forever and never reconnect. `sender.rs` does the same.
    // Bytes trailing the ACK are handed to the framer, so a bus frame batched with the ACK
    // isn't lost. Accumulate across reads: TCP may split the 6-byte ACK.
    {
        let mut pre: Vec<u8> = Vec::new();
        let acked = tokio::time::timeout(
            MONITOR_ACK_TIMEOUT,
            read_until_ack_or_nack(&mut sock, &mut pre),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "monitor ACK timed out"))??;
        if !acked {
            // The gateway REFUSED the monitor session — back off and reconnect (see `run`).
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "monitor session refused (NACK)",
            ));
        }
        // Frame only the bytes AFTER the ACK (any pre-ACK banner is not a frame). The helper
        // returned Ok(true) only on a complete ACK, so the position is always present.
        let pos = find_sub(&pre, AV_ACK).expect("ACK present when read_until_ack_or_nack is true");
        framer.push(&pre[pos + AV_ACK.len()..], &mut frames);
    }

    loop {
        if stopping.load(Ordering::Relaxed) {
            return Ok(());
        }
        // Process frames collected so far — the post-ACK batch on the first pass, then each
        // freshly-read batch. Kept at the top so the initial batch isn't skipped.
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
        frames.clear();

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
        framer.push(&buf[..n], &mut frames);
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

/// Write one "add client" frame and wait for the daemon's ACK, resending on a NACK for up to
/// [`ADD_CLIENT_ATTEMPTS`] total tries. A NACK on the last try, an EOF, or a timeout is an error.
async fn add_client(sock: &mut TcpStream, frame: &str) -> std::io::Result<()> {
    for _ in 0..ADD_CLIENT_ATTEMPTS {
        sock.write_all(frame.as_bytes()).await?;
        sock.flush().await?;

        // Wait for the daemon's control reply (shared accumulate/scan/cap helper: TCP may split
        // the 6-byte `*#*1##` / `*#*0##` across reads). Bounded by ACK_TIMEOUT.
        let mut resp: Vec<u8> = Vec::new();
        let acked = tokio::time::timeout(ACK_TIMEOUT, read_until_ack_or_nack(sock, &mut resp))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "av daemon ack timed out")
            })??;
        if acked {
            return Ok(());
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

/// The start index of the first occurrence of `needle` in `haystack`, if any (small
/// buffers; a plain scan is ample). Used both to detect the ACK/NACK control frames and to
/// slice past the monitor ACK so trailing bus bytes still reach the framer.
fn find_sub(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Read from `sock` into `acc`, accumulating ACROSS reads, until a COMPLETE control frame
/// appears: `Ok(true)` on ACK (`*#*1##`), `Ok(false)` on NACK (`*#*0##`). A single `read`
/// does not preserve OWN frame boundaries, so the 6-byte reply may be split across packets;
/// this keeps reading until one completes. Errors on EOF, on an I/O failure, or when `acc`
/// exceeds [`MAX_CTRL_BYTES`] (a peer streaming non-control bytes — the cap stops unbounded
/// allocation). Callers add their OWN timeout and interpret the bool (the monitor also reads
/// the ACK's position out of `acc` afterwards to frame the bytes trailing it). Shared by the
/// monitor handshake and `add_client` so the accumulate/scan/cap logic lives in one place.
async fn read_until_ack_or_nack(
    sock: &mut TcpStream,
    acc: &mut Vec<u8>,
) -> std::io::Result<bool> {
    let mut buf = [0u8; 4096];
    loop {
        let n = sock.read(&mut buf).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed before ACK/NACK",
            ));
        }
        acc.extend_from_slice(&buf[..n]);
        if find_sub(acc, AV_ACK).is_some() {
            return Ok(true);
        }
        if find_sub(acc, AV_NACK).is_some() {
            return Ok(false);
        }
        if acc.len() > MAX_CTRL_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ACK/NACK not seen within the control-buffer cap",
            ));
        }
    }
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
    fn find_sub_locates_ack_and_nack() {
        assert_eq!(find_sub(b"*#*1##", AV_ACK), Some(0));
        assert_eq!(find_sub(b"junk*#*1##junk", AV_ACK), Some(4));
        assert_eq!(find_sub(b"*#*0##", AV_NACK), Some(0));
        assert_eq!(find_sub(b"*#*1##", AV_NACK), None);
        assert_eq!(find_sub(b"", AV_ACK), None);
    }

    #[test]
    fn add_client_accepts_an_ack_split_across_reads() {
        // TCP can split the 6-byte `*#*1##` across packets; `add_client` must accumulate until
        // the ACK is COMPLETE rather than misread the first fragment as an unexpected reply.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut b = [0u8; 64];
                let _ = s.read(&mut b).await.unwrap(); // consume the add-client frame
                // Reply with the ACK deliberately fragmented into two writes.
                s.write_all(b"*#").await.unwrap();
                s.flush().await.unwrap();
                s.write_all(b"*1##").await.unwrap();
                s.flush().await.unwrap();
            });
            let mut client = TcpStream::connect(addr).await.unwrap();
            add_client(&mut client, "*7*300#1#2#3#4#40000#1*##").await.unwrap();
            server.await.unwrap();
        });
    }

    #[test]
    fn add_client_errors_on_a_nack() {
        // A complete NACK past the retries surfaces as an error (so arm() fails and is logged).
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut b = [0u8; 64];
                // NACK every add-client attempt (ADD_CLIENT_ATTEMPTS of them).
                for _ in 0..ADD_CLIENT_ATTEMPTS {
                    let _ = s.read(&mut b).await.unwrap();
                    s.write_all(AV_NACK).await.unwrap();
                    s.flush().await.unwrap();
                }
            });
            let mut client = TcpStream::connect(addr).await.unwrap();
            assert!(add_client(&mut client, "*7*300#1#2#3#4#40000#1*##").await.is_err());
            let _ = server.await;
        });
    }

    #[test]
    fn read_until_ack_or_nack_reassembles_a_fragmented_ack() {
        // The shared helper (used by BOTH the monitor handshake and add_client) must reassemble an
        // ACK split across reads and report the position via the accumulator — this covers the
        // monitor-ACK fragmentation path that has no socket-level test of its own. Only the server
        // side writes here; the client reads via the helper, so just AsyncWriteExt is needed.
        use tokio::io::AsyncWriteExt;
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                // A pre-ACK banner, then the ACK split across writes, then a trailing bus frame.
                s.write_all(b"junk*").await.unwrap();
                s.flush().await.unwrap();
                s.write_all(b"#*1##*7*300#127#0#0#1#5002#1*##").await.unwrap();
                s.flush().await.unwrap();
            });
            let mut client = TcpStream::connect(addr).await.unwrap();
            let mut acc = Vec::new();
            assert!(read_until_ack_or_nack(&mut client, &mut acc).await.unwrap());
            // The ACK is located within the accumulator, so a caller can frame the bytes past it.
            let pos = find_sub(&acc, AV_ACK).unwrap();
            assert!(acc[pos + AV_ACK.len()..].starts_with(b"*7*300#127#0#0#1#"));
            server.await.unwrap();
        });
    }

    #[test]
    fn read_until_ack_or_nack_caps_a_flood_of_non_control_bytes() {
        // A peer streaming non-control bytes must not grow the buffer unboundedly: past
        // MAX_CTRL_BYTES the helper errors (which makes the monitor reconnect / the arm fail).
        use tokio::io::AsyncWriteExt;
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut s, _) = listener.accept().await.unwrap();
                // Well over the cap, and never a control frame.
                let flood = vec![b'x'; MAX_CTRL_BYTES + 1024];
                let _ = s.write_all(&flood).await;
                let _ = s.flush().await;
            });
            let mut client = TcpStream::connect(addr).await.unwrap();
            let mut acc = Vec::new();
            let err = read_until_ack_or_nack(&mut client, &mut acc).await.unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
            let _ = server.await;
        });
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
