//! On-device still-image HTTP endpoint (issue #168).
//!
//! ## Why
//! Home Assistant's Generic Camera grabs the entity THUMBNAIL from the configured still-image URL;
//! with NO still URL it instead grabs a frame from the live RTSP stream, so every thumbnail poll
//! (~every 10 s) wakes the on-demand doorbell session — the panel is brought up, streamed, and torn
//! down again and again (issue #168, the "thrash"). Pointing HA's *Still Image URL* at THIS endpoint
//! gives it a cheap JPEG that never touches the stream, so the panel session stays down until
//! someone actually opens the camera.
//!
//! ## What it serves
//! One JPEG on a `GET`: the persisted idle snapshot (`cfg/extra/btmqttd/idle.jpg`) when it is present
//! and a valid JPEG, else a small baked neutral placeholder. It re-reads the file PER REQUEST, so
//! Phase 2 (#169) — which captures the real idle view at first run and on an HA "update idle snapshot"
//! press — is picked up on the next poll with no restart. Phase 1 (#168) only ever serves the baked
//! placeholder (no writer exists yet); the endpoint and HA wiring are what Phase 1 delivers.
//!
//! ## Security posture
//! LAN-only, gated by the go2rtcd `GO2RTC` firewall chain — an `ACCEPT` for tcp/8556 from the LAN /24
//! on `wlan0`, exactly like the tcp/8554 RTSP rule — so the socket carries NO auth of its own (the
//! idle snapshot is the same picture the doorbell already shows on the LAN; it is not a credential).
//! Behind the firewall the server is still defensive against a misbehaving LAN client: it is GET-only,
//! reads the request head under a byte cap AND a per-connection timeout, caps concurrent connections,
//! always sends `Connection: close`, and IGNORES the request path, headers and body entirely (it
//! always serves the one image) — so there is no path to traverse and nothing to inject.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

/// LAN-facing TCP port for the still endpoint. Adjacent to the go2rtc RTSP port (8554) and WebRTC
/// port (8555), and firewalled the same way. Kept in step with the C# installer's on-device setup
/// guide (`Go2RtcConfig.OnDeviceStillPort`) and the go2rtcd firewall (`CAM_STILL_PORT`).
pub const STILL_PORT: u16 = 8556;

/// The baked neutral placeholder, served whenever no valid persisted idle snapshot exists. Compiled
/// into the binary so the endpoint always has SOMETHING to return (it is provenance-covered like the
/// rest of the binary). A ~11 KB 640×480 JPEG — see `native/btmqttd/assets/idle-placeholder.jpg`.
const PLACEHOLDER: &[u8] = include_bytes!("../assets/idle-placeholder.jpg");

/// Whole-request-head read budget: a client has this long to send the request line + headers. A
/// slow-loris that dribbles bytes is cut off here rather than pinning a task/socket.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Response write budget: a client that stops reading mid-response can't pin the task forever.
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long `accept()` waits before the loop wakes to re-check `stopping`, so a quiet endpoint still
/// winds down promptly at shutdown even though the daemon also aborts the task.
const ACCEPT_POLL: Duration = Duration::from_secs(1);

/// Cap on request-head bytes read. We only need the method (first token); the path/headers/body are
/// discarded. 8 KiB is ample for any real request line + headers and bounds a garbage flood.
const MAX_REQUEST_BYTES: usize = 8 * 1024;

/// Cap on concurrently-served connections, so a LAN client opening many sockets can't exhaust file
/// descriptors or spawn unbounded tasks. Excess connections are dropped (the client can retry).
const MAX_CONNS: usize = 8;

/// Run the still endpoint until `stopping` is set (the daemon also aborts the task at shutdown).
/// Binds `0.0.0.0:STILL_PORT` (DHCP-proof; the firewall is the access gate, like go2rtc's RTSP). A
/// bind failure degrades gracefully: the endpoint is simply absent and HA falls back to stream stills
/// (the pre-#168 behaviour) rather than the daemon crashing.
pub async fn run(stopping: Arc<AtomicBool>) {
    let listener = match TcpListener::bind((Ipv4Addr::UNSPECIFIED, STILL_PORT)).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("btmqttd: still: cannot bind :{STILL_PORT}: {e}; still endpoint disabled");
            return;
        }
    };
    eprintln!("btmqttd: still: serving idle snapshot on :{STILL_PORT}");
    let sem = Arc::new(Semaphore::new(MAX_CONNS));
    while !stopping.load(Ordering::Relaxed) {
        // Bounded accept so the loop periodically re-checks `stopping` on a quiet endpoint.
        let (stream, _peer) = match tokio::time::timeout(ACCEPT_POLL, listener.accept()).await {
            Ok(Ok(pair)) => pair,
            Ok(Err(e)) => {
                eprintln!("btmqttd: still: accept error: {e}");
                continue;
            }
            Err(_) => continue, // accept timed out — re-check `stopping`
        };
        // Bound concurrency: if the pool is exhausted, drop this connection rather than queue it.
        let Ok(permit) = sem.clone().try_acquire_owned() else {
            drop(stream); // closes the socket; the client can retry
            continue;
        };
        tokio::spawn(async move {
            // `permit` is held for the connection's lifetime and released on drop. A client hanging
            // up mid-request is normal, so swallow the connection error rather than log per hit.
            let _permit = permit;
            let _ = serve_conn(stream).await;
        });
    }
}

/// Serve ONE connection: read (and discard) the request head, then reply. Generic over the stream so
/// it is unit-testable over an in-memory duplex without binding a real socket.
async fn serve_conn<S>(mut stream: S) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let response = match tokio::time::timeout(REQUEST_TIMEOUT, read_head(&mut stream)).await {
        Ok(Ok(head)) => match request_is_get(&head) {
            Some(true) => jpeg_response(&idle_or_placeholder().await),
            Some(false) => simple_response("405 Method Not Allowed"),
            None => simple_response("400 Bad Request"),
        },
        Ok(Err(e)) => return Err(e), // socket read error — nothing to reply on
        Err(_) => simple_response("408 Request Timeout"), // slow client — bounded reply, then close
    };
    let _ = write_all_timeout(&mut stream, &response).await;
    let _ = stream.shutdown().await;
    Ok(())
}

/// Read the request head — up to the `\r\n\r\n` terminator, or the byte cap, or EOF. We keep only
/// enough to read the method; the rest (path, headers, body) is intentionally ignored.
async fn read_head<S>(stream: &mut S) -> std::io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    while find_head_end(&buf).is_none() && buf.len() < MAX_REQUEST_BYTES {
        // Read no more than the remaining budget so the buffer can NEVER exceed MAX_REQUEST_BYTES —
        // a hard cap, not "cap ± one chunk" (the loop-guard alone would let the last read overshoot).
        let want = (MAX_REQUEST_BYTES - buf.len()).min(chunk.len());
        let n = stream.read(&mut chunk[..want]).await?;
        if n == 0 {
            break; // EOF before a full head — parse what we have (likely None ⇒ 400)
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Ok(buf)
}

/// Index just past the blank line that ends an HTTP head (`\r\n\r\n`), if present.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// The request method decision from the head: `Some(true)` = GET, `Some(false)` = a valid but
/// non-GET method, `None` = malformed (no method token). Only the first token (up to the first
/// space or line end) is examined.
fn request_is_get(head: &[u8]) -> Option<bool> {
    let end = head
        .iter()
        .position(|&b| b == b' ' || b == b'\r' || b == b'\n')?;
    if end == 0 {
        return None; // leading space / blank line — no method
    }
    Some(&head[..end] == b"GET")
}

/// The idle snapshot if a valid persisted JPEG exists, else the baked placeholder. Read per request
/// (so a Phase-2 capture is picked up without a restart); the blocking `std::fs` read is offloaded
/// off the single-threaded runtime.
async fn idle_or_placeholder() -> Vec<u8> {
    match tokio::task::spawn_blocking(crate::persist::read_idle_jpg).await {
        Ok(Some(bytes)) if is_jpeg(&bytes) => bytes,
        _ => PLACEHOLDER.to_vec(),
    }
}

/// A structural JPEG check — enough to trust the bytes are a REAL frame without pulling a full JPEG
/// decoder into a size-constrained embedded binary (the endpoint is not a codec). It requires, in the
/// byte stream: the SOI magic (`FF D8 FF`) at the start, a Start-Of-Frame marker (`FF C0`..`FF CF`,
/// excluding the non-frame `FF C4` DHT / `FF C8` JPG / `FF CC` DAC), a Start-Of-Scan (`FF DA`), and an
/// EOI (`FF D9`). The SOF+SOS requirement rejects a marker-only stub like `FF D8 FF D9` that carries no
/// image data (which HA would render as nothing), on top of rejecting a truncated or non-JPEG file. The
/// markers are SEARCHED, not position-pinned: the EOI need not be the last two bytes (encoders append
/// trailing padding / metadata / an embedded thumbnail after it), and a valid file still matches.
fn is_jpeg(b: &[u8]) -> bool {
    if b.len() < 4 || !b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return false;
    }
    let (mut has_sof, mut has_sos, mut has_eoi) = (false, false, false);
    // A JPEG marker is `FF` followed by its code. We only need PRESENCE of the three structural
    // markers; a byte scan is sufficient (in a valid stream, entropy-coded data byte-stuffs every
    // `FF` as `FF 00` or a restart `FF D0`..`FF D7`, so a bare SOF/SOS/EOI code marks a real segment).
    for w in b[2..].windows(2) {
        if w[0] != 0xFF {
            continue;
        }
        match w[1] {
            0xC0..=0xCF if !matches!(w[1], 0xC4 | 0xC8 | 0xCC) => has_sof = true,
            0xDA => has_sos = true,
            0xD9 => has_eoi = true,
            _ => {}
        }
    }
    has_sof && has_sos && has_eoi
}

/// A `200 OK` JPEG response. `no-store` keeps HA from pinning a stale thumbnail after a Phase-2
/// idle-image update; `Connection: close` matches the one-shot request/response shape.
fn jpeg_response(body: &[u8]) -> Vec<u8> {
    let head = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: image/jpeg\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let mut out = Vec::with_capacity(head.len() + body.len());
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(body);
    out
}

/// A bodyless status response (error paths). Always `Connection: close`.
fn simple_response(status: &str) -> Vec<u8> {
    format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
}

async fn write_all_timeout<S>(stream: &mut S, bytes: &[u8]) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    match tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(bytes)).await {
        Ok(r) => r,
        Err(_) => Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "still: response write timed out",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baked_placeholder_is_a_valid_jpeg() {
        // The compiled-in fallback must itself pass the JPEG structural check, so the endpoint never
        // serves a body HA would reject.
        assert!(is_jpeg(PLACEHOLDER));
        assert!(PLACEHOLDER.len() > 1000); // a real image, not an empty stub
    }

    #[test]
    fn is_jpeg_requires_frame_and_scan_structure_not_just_markers() {
        // A structurally complete JPEG: SOI + SOF0 + SOS + EOI (segment payloads elided).
        let valid: &[u8] = &[0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x0B, 0xFF, 0xDA, 0x00, 0x08, 0xFF, 0xD9];
        assert!(is_jpeg(valid));
        // Trailing padding / metadata after EOI is fine — the EOI need not be the last two bytes
        // (some encoders append bytes after EOI, and the file is still a valid, viewable JPEG).
        let mut with_trailer = valid.to_vec();
        with_trailer.extend_from_slice(b"\x00\x00   trailer");
        assert!(is_jpeg(&with_trailer));
        // A marker-only stub (SOI + EOI, no frame/scan) carries no image data → rejected, so the
        // endpoint serves the baked placeholder instead of an unusable "image".
        assert!(!is_jpeg(&[0xFF, 0xD8, 0xFF, 0xD9]));
        // SOI + an APP0 header but no SOF/SOS (a truncated header) → rejected.
        assert!(!is_jpeg(b"\xff\xd8\xff\xe0\x00\x10JFIF\xff\xd9"));
        // SOF present but no SOS (frame declared, scan missing) → rejected.
        assert!(!is_jpeg(&[0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x0B, 0xFF, 0xD9]));
        assert!(!is_jpeg(b"")); // empty
        assert!(!is_jpeg(b"\xff\xd8\xff")); // too short, no structure
        assert!(!is_jpeg(b"not a jpeg at all")); // wrong magic
        assert!(!is_jpeg(b"\x89PNG\r\n\x1a\n")); // a PNG
    }

    #[test]
    fn request_is_get_parses_only_the_method_token() {
        assert_eq!(request_is_get(b"GET /idle.jpg HTTP/1.1\r\n"), Some(true));
        assert_eq!(request_is_get(b"GET / HTTP/1.1\r\n\r\n"), Some(true));
        assert_eq!(request_is_get(b"POST / HTTP/1.1\r\n"), Some(false));
        assert_eq!(request_is_get(b"HEAD / HTTP/1.1\r\n"), Some(false));
        // A path is never inspected: a would-be traversal in the URL is irrelevant (still GET).
        assert_eq!(request_is_get(b"GET /../../etc/passwd HTTP/1.1\r\n"), Some(true));
        // Malformed: no method token.
        assert_eq!(request_is_get(b""), None);
        assert_eq!(request_is_get(b" \r\n"), None);
        assert_eq!(request_is_get(b"\r\n\r\n"), None);
    }

    #[test]
    fn find_head_end_locates_the_blank_line() {
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n\r\n"), Some(18));
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\nHost: x\r\n\r\nBODY"), Some(27));
        assert_eq!(find_head_end(b"GET / HTTP/1.1\r\n"), None); // head not finished
    }

    #[test]
    fn jpeg_response_has_image_content_type_and_length() {
        let body = b"\xff\xd8\xff\xd9";
        let resp = jpeg_response(body);
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Type: image/jpeg\r\n"));
        assert!(text.contains("Content-Length: 4\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        // Body is appended verbatim after the blank line.
        assert!(resp.ends_with(body));
    }

    // --- End-to-end over an in-memory duplex (no socket bound) --------------------------------

    async fn round_trip(request: &[u8]) -> Vec<u8> {
        use tokio::io::AsyncWriteExt as _;
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn(async move { serve_conn(server).await });
        client.write_all(request).await.unwrap();
        // Read the whole response until the server closes its half.
        let mut resp = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = client.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            resp.extend_from_slice(&chunk[..n]);
        }
        srv.await.unwrap().unwrap();
        resp
    }

    #[tokio::test]
    async fn get_returns_a_valid_jpeg_body() {
        // No persisted idle.jpg in the test env ⇒ the baked placeholder is served. Assert the shape
        // and that the body is a structurally valid JPEG (true whether idle.jpg exists or not).
        let resp = round_trip(b"GET /idle.jpg HTTP/1.1\r\nHost: unit\r\n\r\n").await;
        let sep = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let (head, body) = resp.split_at(sep);
        let head = String::from_utf8_lossy(head);
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "head: {head}");
        assert!(head.contains("Content-Type: image/jpeg\r\n"));
        assert!(head.contains("Connection: close\r\n"));
        assert!(is_jpeg(body), "served body is not a valid JPEG");
        // Content-Length must match the served body exactly.
        assert!(head.contains(&format!("Content-Length: {}\r\n", body.len())));
    }

    #[tokio::test]
    async fn non_get_method_is_405() {
        let resp = round_trip(b"POST /idle.jpg HTTP/1.1\r\n\r\n").await;
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"), "resp: {text}");
        assert!(text.contains("Connection: close\r\n"));
    }

    #[tokio::test]
    async fn read_head_enforces_the_byte_cap_exactly() {
        // A flood with no head terminator must stop at EXACTLY MAX_REQUEST_BYTES — the last read can't
        // overshoot the cap by a chunk (the request-head DoS bound must be hard, not "cap ± a chunk").
        use tokio::io::AsyncWriteExt as _;
        let (mut client, mut server) = tokio::io::duplex(64 * 1024);
        let flood = vec![b'A'; MAX_REQUEST_BYTES + 1000];
        tokio::spawn(async move {
            let _ = client.write_all(&flood).await;
        });
        let head = read_head(&mut server).await.unwrap();
        assert_eq!(head.len(), MAX_REQUEST_BYTES);
    }

    #[tokio::test]
    async fn malformed_request_is_400() {
        let resp = round_trip(b"\r\n\r\n").await;
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 400 Bad Request\r\n"), "resp: {text}");
    }
}
