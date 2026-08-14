//! Viewer-activity auto-hold for the on-device camera (issue #120, the #104 follow-up the SIP hold
//! loop flagged as deferred — see the note at `sip.rs`'s hold loop).
//!
//! `sip.rs` holds the on-demand panel session for a FIXED window per `view_camera` press because there
//! was no continuous "someone is watching" signal — so a single press bounds the session to one window
//! and it auto-hangs-up when the window elapses. This task supplies that missing signal for the
//! on-device media path: it polls the loopback go2rtc control API and, while go2rtc has an active
//! CONSUMER on the camera stream, pokes `ViewCmd::Start` to renew the window.
//!
//! A **consumer** is a viewer (Home Assistant) connected to the RTSP stream; go2rtc starts its lazy
//! ffmpeg **producer** only once a consumer connects. We key off consumers, NOT producers: for an
//! `exec:` stream go2rtc leaves the producers array populated (and keeps STOPPED entries) even after
//! the last viewer leaves, so a producer being present does not prove anyone is watching — the window
//! could then never lapse. A non-empty consumers array, by contrast, means a real RTSP client is
//! connected right now. The net effect: Home Assistant "just opens the camera", a consumer appears,
//! this task sees it and brings/holds the panel session up, and the session auto-hangs-up shortly after
//! the last viewer leaves (the consumer drops → the pokes stop → the window lapses on its own).
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
        match stream_has_consumer().await {
            Ok(active) => {
                warned = false;
                if active {
                    // Renew the on-demand window. try_send never blocks the poll loop: a full queue
                    // means sip.rs isn't draining (reconnect backoff) and a dropped poke is harmless —
                    // the next poll pokes again; Closed means the SIP task is gone, nothing to hold.
                    //
                    // DELIBERATE: auto-hold is AUTHORITATIVE while a viewer is connected. If an operator
                    // issues `stop_camera` (ViewCmd::Stop) while Home Assistant still has the feed open,
                    // this poll re-Starts within one interval — so a Stop only interrupts an active view
                    // briefly rather than ending it. This is by design: the session follows the live
                    // viewer, which is exactly what makes the feature "transparent" (HA just opens the
                    // camera). To end a view, close it (the consumer drops → these pokes stop → the
                    // window lapses); `stop_camera` remains effective when no viewer is connected (e.g.
                    // after a ring). Honoring the Stop over an active viewer was considered and rejected:
                    // tearing the session down drops the consumer, HA auto-reconnects, the consumer
                    // reappears, and a suppression flag would fight HA's reconnect for no real benefit
                    // (product decision on #129; Codex review).
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

/// True iff go2rtc reports at least one active CONSUMER (a connected RTSP viewer). GET /api/streams
/// over loopback HTTP/1.0. `pub(crate)` so `sprop.rs` can reuse it to coordinate the shared UDP input
/// port (a viewer's consumer means go2rtc's own ffmpeg owns the port, so the provisioning probe must
/// stand aside). We key off consumers, not producers: an `exec:` stream keeps its producers array
/// populated (with stopped entries) even when idle, so only a non-empty consumers array proves a real
/// viewer is connected right now.
pub(crate) async fn stream_has_consumer() -> std::io::Result<bool> {
    let body = tokio::time::timeout(REQ_TIMEOUT, http_get_streams())
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "go2rtc API timed out"))??;
    let json: Value = serde_json::from_str(&body)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    // Response shape: { "<stream>": { "producers": [...], "consumers": [...] }, ... }. The on-device
    // go2rtc serves exactly the one camera stream, so ANY stream carrying a non-empty consumers array
    // means a viewer is connected — this task needs no knowledge of the sanitized stream name.
    if let Value::Object(streams) = json {
        for (_, s) in &streams {
            if let Some(Value::Array(c)) = s.get("consumers") {
                if !c.is_empty() {
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

    // The consumer-detection logic, factored so it can be unit-tested without a go2rtc socket.
    fn any_consumer(json: &Value) -> bool {
        if let Value::Object(streams) = json {
            for (_, s) in streams {
                if let Some(Value::Array(c)) = s.get("consumers") {
                    if !c.is_empty() {
                        return true;
                    }
                }
            }
        }
        false
    }

    #[test]
    fn detects_a_live_consumer() {
        // A viewer connected → non-empty consumers ⇒ hold the session. The producers array may be
        // populated with a stopped exec entry at the same time, but only the consumer proves a viewer.
        let j: Value = serde_json::from_str(
            r#"{"doorbell":{"producers":[{"url":"exec:ffmpeg ..."}],"consumers":[{"type":"RTSP client"}]}}"#,
        )
        .unwrap();
        assert!(any_consumer(&j));
    }

    #[test]
    fn idle_stream_has_no_consumer() {
        // No viewer → empty/absent consumers ⇒ don't hold the session — even when the exec:'s
        // producers array is still populated (go2rtc leaves stopped producer entries in place).
        assert!(!any_consumer(
            &serde_json::from_str(
                r#"{"doorbell":{"producers":[{"url":"exec:ffmpeg ..."}],"consumers":[]}}"#
            )
            .unwrap()
        ));
        assert!(!any_consumer(
            &serde_json::from_str(r#"{"doorbell":{"producers":[{"url":"exec:ffmpeg ..."}]}}"#)
                .unwrap()
        ));
        assert!(!any_consumer(
            &serde_json::from_str(r#"{"doorbell":{"consumers":null}}"#).unwrap()
        ));
        assert!(!any_consumer(&serde_json::from_str(r#"{}"#).unwrap()));
    }
}
