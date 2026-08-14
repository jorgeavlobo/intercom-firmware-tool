//! Viewer-activity auto-hold for the on-device camera (issue #120, the #104 follow-up the SIP hold
//! loop flagged as deferred — see the note at `sip.rs`'s hold loop).
//!
//! `sip.rs` holds the on-demand panel session for a FIXED window per `view_camera` press because there
//! was no continuous "someone is watching" signal — so a single press bounds the session to one window
//! and it auto-hangs-up when the window elapses. This task supplies that missing signal for the
//! on-device media path: it polls the loopback go2rtc control API and, while go2rtc has an active
//! producer for the camera stream, pokes `ViewCmd::Start` to renew the window.
//!
//! go2rtc starts its ffmpeg producer **lazily** — only when a consumer (Home Assistant) subscribes to
//! the RTSP stream — so a producer being present means someone is viewing (or has just connected). The
//! net effect: Home Assistant "just opens the camera", go2rtc starts the producer, this task sees it
//! and brings/holds the panel session up, and the session auto-hangs-up shortly after the last viewer
//! leaves (go2rtc drops the producer → the pokes stop → the window lapses on its own).
//!
//! Loopback-only and best-effort: any API hiccup (go2rtc restarting, not yet up) just skips a poll and
//! is logged once. The manual `view_camera`/`stop_camera` MQTT actions are unaffected — every source
//! drives the same `view_rx`, and `ViewCmd::Start` is idempotent (a fresh full window each time).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::sip::ViewCmd;

/// The on-device go2rtc control API. `Go2RtcConfig.BuildOnDeviceYaml` pins it to loopback `:1984`
/// (never the LAN), so this is fixed — the same way `av.rs`/`receiver.rs` hardcode the on-device
/// `bt_av_media`/gateway loopback ports.
const GO2RTC_API: &str = "127.0.0.1:1984";
/// Cap one API request so a wedged socket can't stall the poll loop (the port is loopback, so this is
/// generous). Covers connect + request + read.
const REQ_TIMEOUT: Duration = Duration::from_secs(4);
/// Target poll cadence. Short for RESPONSIVENESS: when Home Assistant opens the camera, go2rtc starts
/// the producer and this task must bring the panel session up within a couple seconds (not a third of
/// the viewing window). The effective period is still capped under the window (see `run`) so a held
/// view never lapses between pokes.
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Ceiling on the response we will buffer from the loopback API (its /api/streams JSON is tiny; this
/// just bounds a hostile/broken peer).
const MAX_RESP_BYTES: usize = 64 * 1024;

/// Poll go2rtc and renew the on-demand window while a viewer is connected. Returns when `stopping` is
/// set. `main` also aborts this task at shutdown, so the poll-interval sleep is a bounded wait.
pub async fn run(cfg: Arc<Config>, stopping: Arc<AtomicBool>, view_tx: mpsc::Sender<ViewCmd>) {
    // Poll every POLL_INTERVAL for a prompt panel start when a viewer connects, but never longer than
    // half the viewing window so a held view can't lapse between pokes (floored so a pathological tiny
    // window can't spin the loop). On the 30 s default this is a flat 2 s.
    let window = Duration::from_secs(cfg.camera_view_idle_secs.max(1));
    let period = POLL_INTERVAL
        .min(window / 2)
        .max(Duration::from_millis(500));
    // Debounce the "API unreachable" log: a stopped/starting go2rtc must not spam the log every poll.
    let mut warned = false;
    while !stopping.load(Ordering::Relaxed) {
        match stream_has_producer().await {
            Ok(active) => {
                warned = false;
                if active {
                    // Renew the on-demand window. try_send never blocks the poll loop: a full queue
                    // means sip.rs isn't draining (reconnect backoff) and a dropped poke is harmless —
                    // the next poll pokes again; Closed means the SIP task is gone, nothing to hold.
                    let _ = view_tx.try_send(ViewCmd::Start);
                }
            }
            Err(e) => {
                if !warned {
                    eprintln!("btmqttd: camera auto-hold: go2rtc API poll failed: {e}");
                    warned = true;
                }
            }
        }
        // Re-check `stopping` before sleeping so a shutdown observed mid-poll exits promptly.
        if stopping.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(period).await;
    }
}

/// True iff go2rtc reports at least one active producer. The lazy exec starts only on a consumer, so a
/// producer present ⇒ someone is viewing. GET /api/streams over loopback HTTP/1.0.
async fn stream_has_producer() -> std::io::Result<bool> {
    let body = tokio::time::timeout(REQ_TIMEOUT, http_get_streams())
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "go2rtc API timed out"))??;
    let json: Value = serde_json::from_str(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    // Response shape: { "<stream>": { "producers": [...], "consumers": [...] }, ... }. The on-device
    // go2rtc serves exactly the one camera stream, so ANY stream carrying a non-empty producers array
    // means the camera is being consumed — this task needs no knowledge of the sanitized stream name.
    if let Value::Object(streams) = json {
        for (_, s) in &streams {
            if let Some(Value::Array(p)) = s.get("producers") {
                if !p.is_empty() {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Minimal HTTP/1.0 GET of `/api/streams` over loopback; returns the JSON body. `Connection: close`
/// lets us read to EOF without parsing a Content-Length.
async fn http_get_streams() -> std::io::Result<String> {
    let mut sock = TcpStream::connect(GO2RTC_API).await?;
    sock.write_all(b"GET /api/streams HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .await?;
    sock.flush().await?;
    let mut raw = Vec::new();
    // Bounded read: the loopback API's body is tiny; MAX_RESP_BYTES only guards a broken/hostile peer.
    let mut buf = [0u8; 4096];
    loop {
        let n = sock.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        if raw.len() + n > MAX_RESP_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "go2rtc API response too large",
            ));
        }
        raw.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&raw);
    // The JSON body follows the blank line after the HTTP headers.
    match text.split_once("\r\n\r\n") {
        Some((_, body)) => Ok(body.to_string()),
        None => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "malformed HTTP response from go2rtc API",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The producer-detection logic, factored so it can be unit-tested without a go2rtc socket.
    fn any_producer(json: &Value) -> bool {
        if let Value::Object(streams) = json {
            for (_, s) in streams {
                if let Some(Value::Array(p)) = s.get("producers") {
                    if !p.is_empty() {
                        return true;
                    }
                }
            }
        }
        false
    }

    #[test]
    fn detects_a_live_producer() {
        // A consumer connected → go2rtc started the exec → non-empty producers.
        let j: Value = serde_json::from_str(
            r#"{"doorbell":{"producers":[{"url":"exec:ffmpeg ..."}],"consumers":null}}"#,
        )
        .unwrap();
        assert!(any_producer(&j));
    }

    #[test]
    fn idle_stream_has_no_producer() {
        // No viewer → lazy exec not started → empty/absent producers ⇒ don't hold the session.
        assert!(!any_producer(
            &serde_json::from_str(r#"{"doorbell":{"producers":[],"consumers":null}}"#).unwrap()
        ));
        assert!(!any_producer(
            &serde_json::from_str(r#"{"doorbell":{"consumers":null}}"#).unwrap()
        ));
        assert!(!any_producer(&serde_json::from_str(r#"{}"#).unwrap()));
    }
}
