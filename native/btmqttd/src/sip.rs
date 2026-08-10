//! On-demand viewing (Phase 2, issue #104): a minimal SIP-over-TCP user agent that brings the
//! idle entrance-panel A/V session up on demand, so the Home Assistant camera works at any time —
//! not only while the panel is ringing.
//!
//! ## Why SIP
//! When the panel is idle nothing is streaming; something must ask it to start. Hardware capture
//! (issue #104) showed the phone app's "view camera" is a plain **SIP INVITE to
//! `sip:<aor>@<domain>`** (`aor` = `c100x`/`c300x`) routed by the on-board **flexisip** proxy on
//! loopback `127.0.0.1:5060`. flexisip's factory `trusted-hosts=127.0.0.1` means a loopback UA is
//! auto-trusted, so we can originate that INVITE ourselves with no SIP password.
//!
//! ## What this module does (and does NOT do)
//! It only drives the **signalling** — INVITE → ACK to hold the session up, BYE to tear it down. The
//! SIP-negotiated media is SRTP (`RTP/SAVP`), which we deliberately **blackhole**: the usable
//! cleartext video still comes from Phase 1's `:30007` siphon (`av.rs`), which auto-arms the moment
//! the panel emits its media-start frame on the monitor. So the two modules coordinate implicitly
//! through the panel's own session lifecycle — this file never touches `bt_av_media`.
//!
//! ## Captured dialog (redacted), the ground truth this mirrors
//! ```text
//! INVITE sip:c100x@<domain>            CSeq: 21 INVITE   (SDP offer, RTP/SAVP)
//!   <- 100 Trying / 180 Ringing (To adds ;tag=<panel>) / 200 OK (Contact: c100x@127.0.0.1:<ephem>)
//! ACK  sip:c100x@127.0.0.1:<ephem>     CSeq: 21 ACK
//!   ... session held; av.rs siphons :30007 ...
//! BYE  sip:c100x@127.0.0.1:<ephem>     CSeq: 22 BYE
//!   <- 200 OK
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::config::Config;

/// Where flexisip seeds the device's SIP domain at boot: the first whitespace-delimited token of
/// the first real line is the panel's local domain (e.g. `<uuid>.bs.iotleg.com`).
const DOMAIN_REGISTRATION_CONF: &str = "/etc/flexisip/domain-registration.conf";
/// Model detection, same file the rest of the tool already uses.
const HOSTNAME_PATH: &str = "/etc/hostname";

/// Response wait + overall INVITE timeout, and how long a single read may block.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
const READ_CHUNK_TIMEOUT: Duration = Duration::from_secs(2);
/// Cap on a single SIP message we will buffer (offer/answer are ~2–3 KB; this bounds a hostile peer).
const MAX_SIP_BYTES: usize = 65536;
/// Reconnect backoff for the (rare) case the SIP socket / dialog fails.
const BACKOFF_INIT: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

// ---- runtime discovery (pure helpers take file contents, so they unit-test) ------------------

/// The answer-machine AOR user for a model hostname: `Bticino_Classe_100_X` → `c100x`,
/// `…300_X` → `c300x`. Returns `None` for an unrecognized model (feature then stays idle rather
/// than INVITE-ing a guess).
pub fn aor_user_for_hostname(hostname: &str) -> Option<&'static str> {
    let h = hostname.trim();
    if h.contains("100") {
        Some("c100x")
    } else if h.contains("300") {
        Some("c300x")
    } else {
        None
    }
}

/// The local SIP domain from `domain-registration.conf`: first token of the first line that is not
/// blank and not a `#` comment.
pub fn domain_from_registration(content: &str) -> Option<String> {
    content
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .and_then(|l| l.split_whitespace().next())
        .map(str::to_string)
}

/// Resolve `(aor_user, domain)` from config overrides, falling back to on-device files. `None` if
/// the model or domain can't be determined — the caller then declines to originate.
fn resolve_identity(cfg: &Config) -> Option<(String, String)> {
    let aor = if !cfg.sip_local_aor.is_empty() {
        cfg.sip_local_aor.clone()
    } else {
        let hn = std::fs::read_to_string(HOSTNAME_PATH).ok()?;
        aor_user_for_hostname(&hn)?.to_string()
    };
    let domain = if !cfg.sip_domain.is_empty() {
        cfg.sip_domain.clone()
    } else {
        let text = std::fs::read_to_string(DOMAIN_REGISTRATION_CONF).ok()?;
        domain_from_registration(&text)?
    };
    Some((aor, domain))
}

// ---- SDP + SIP message construction ----------------------------------------------------------

/// A minimal `RTP/SAVP` offer belle-sip will answer. We ask the panel to SEND video (`recvonly`
/// from our side) and keep audio `inactive` — Phase 2 only needs the session UP; the actual media
/// is siphoned cleartext by `av.rs`. The crypto key is a throwaway (the SRTP is blackholed). Ports
/// are placeholders we never read.
pub fn build_sdp_offer(video_port: u16, audio_port: u16, srtp_key_b64: &str) -> String {
    format!(
        "v=0\r\n\
         o=btmqttd 0 0 IN IP4 127.0.0.1\r\n\
         s=btmqttd\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         m=audio {audio_port} RTP/SAVP 98 101\r\n\
         a=rtpmap:98 speex/8000\r\n\
         a=rtpmap:101 telephone-event/8000\r\n\
         a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_b64}\r\n\
         a=inactive\r\n\
         m=video {video_port} RTP/SAVP 97\r\n\
         a=rtpmap:97 H264/90000\r\n\
         a=fmtp:97 profile-level-id=42801F\r\n\
         a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_b64}\r\n\
         a=recvonly\r\n"
    )
}

/// The mutable per-call state we carry from the INVITE through ACK/BYE.
pub struct Dialog {
    pub aor: String,
    pub domain: String,
    pub local_port: u16,
    pub call_id: String,
    pub from_tag: String,
    pub branch: String,
    pub cseq: u32,
    /// Learned from the 200 OK.
    pub to_tag: String,
    pub remote_target: String,
}

/// Build the initial INVITE (with SDP body). Request-URI and `To` are the AOR; `Contact`/`Via`
/// point at our loopback listening port so responses route back on this TCP connection.
pub fn build_invite(d: &Dialog, sdp: &str) -> String {
    format!(
        "INVITE sip:{aor}@{domain} SIP/2.0\r\n\
         Via: SIP/2.0/TCP 127.0.0.1:{lport};rport;branch={branch}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:btmqttd@{domain}>;tag={ftag}\r\n\
         To: <sip:{aor}@{domain}>\r\n\
         Call-ID: {callid}\r\n\
         CSeq: {cseq} INVITE\r\n\
         Contact: <sip:btmqttd@127.0.0.1:{lport};transport=tcp>\r\n\
         Allow: INVITE, ACK, CANCEL, BYE, OPTIONS\r\n\
         User-Agent: btmqttd\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: {len}\r\n\
         \r\n\
         {sdp}",
        aor = d.aor,
        domain = d.domain,
        lport = d.local_port,
        branch = d.branch,
        ftag = d.from_tag,
        callid = d.call_id,
        cseq = d.cseq,
        len = sdp.len(),
    )
}

/// ACK for a 2xx (same CSeq number as the INVITE; request-URI = the panel's learned Contact).
pub fn build_ack(d: &Dialog, ack_branch: &str) -> String {
    format!(
        "ACK {target} SIP/2.0\r\n\
         Via: SIP/2.0/TCP 127.0.0.1:{lport};rport;branch={branch}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:btmqttd@{domain}>;tag={ftag}\r\n\
         To: <sip:{aor}@{domain}>;tag={ttag}\r\n\
         Call-ID: {callid}\r\n\
         CSeq: {cseq} ACK\r\n\
         Content-Length: 0\r\n\
         \r\n",
        target = d.remote_target,
        lport = d.local_port,
        branch = ack_branch,
        domain = d.domain,
        ftag = d.from_tag,
        aor = d.aor,
        ttag = d.to_tag,
        callid = d.call_id,
        cseq = d.cseq,
    )
}

/// BYE to end the dialog (CSeq incremented; request-URI = the panel's learned Contact).
pub fn build_bye(d: &Dialog, bye_branch: &str) -> String {
    format!(
        "BYE {target} SIP/2.0\r\n\
         Via: SIP/2.0/TCP 127.0.0.1:{lport};rport;branch={branch}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:btmqttd@{domain}>;tag={ftag}\r\n\
         To: <sip:{aor}@{domain}>;tag={ttag}\r\n\
         Call-ID: {callid}\r\n\
         CSeq: {cseq} BYE\r\n\
         Content-Length: 0\r\n\
         \r\n",
        target = d.remote_target,
        lport = d.local_port,
        branch = bye_branch,
        domain = d.domain,
        ftag = d.from_tag,
        aor = d.aor,
        ttag = d.to_tag,
        callid = d.call_id,
        cseq = d.cseq + 1,
    )
}

// ---- response parsing ------------------------------------------------------------------------

/// The status code of a SIP response's start line (`SIP/2.0 200 Ok` → `200`). `None` if the buffer
/// does not start with a SIP status line (e.g. it's a request, or incomplete).
pub fn parse_status(msg: &str) -> Option<u16> {
    let first = msg.lines().next()?;
    let rest = first.strip_prefix("SIP/2.0 ")?;
    rest.split_whitespace().next()?.parse().ok()
}

/// First value of a header (case-insensitive name match), trimmed.
pub fn header_value<'a>(msg: &'a str, name: &str) -> Option<&'a str> {
    for line in msg.lines() {
        if line.is_empty() {
            break; // end of headers
        }
        if let Some((h, v)) = line.split_once(':') {
            if h.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim());
            }
        }
    }
    None
}

/// The `;tag=` value of the `To` header, if present.
pub fn to_tag(msg: &str) -> Option<String> {
    let to = header_value(msg, "To")?;
    tag_of(to)
}

fn tag_of(header: &str) -> Option<String> {
    let after = header.split(";tag=").nth(1)?;
    Some(
        after
            .split(|c: char| c == ';' || c.is_whitespace())
            .next()?
            .to_string(),
    )
}

/// The URI inside the angle brackets of the `Contact` header (the panel's in-dialog target for our
/// ACK/BYE). Falls back to a bare (bracket-less) Contact URI.
pub fn contact_uri(msg: &str) -> Option<String> {
    let c = header_value(msg, "Contact")?;
    if let Some(start) = c.find('<') {
        let end = c[start + 1..].find('>')?;
        Some(c[start + 1..start + 1 + end].to_string())
    } else {
        Some(c.split(';').next()?.trim().to_string())
    }
}

// ---- randomness for SIP tokens + the throwaway SRTP key --------------------------------------

/// Fill `buf` with OS entropy (`/dev/urandom`). Falls back to a time-seeded xorshift only if the
/// device has no urandom (it always does) — SIP tags/branches need uniqueness, not secrecy, and the
/// SRTP key is blackholed.
fn fill_random(buf: &mut [u8]) {
    use std::io::Read;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(buf).is_ok() {
            return;
        }
    }
    let mut x = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E3779B97F4A7C15)
        | 1;
    for b in buf.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *b = x as u8;
    }
}

/// A lowercase-hex token of `n_bytes` of entropy, for a branch/tag/Call-ID. RFC 3261 requires the
/// magic-cookie prefix on the branch; callers prepend it where needed.
fn rand_hex(n_bytes: usize) -> String {
    let mut buf = vec![0u8; n_bytes];
    fill_random(&mut buf);
    let mut s = String::with_capacity(n_bytes * 2);
    for b in buf {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Standard base64 (no line wrapping) — small, dependency-free, for the SDES SRTP key.
pub fn base64_encode(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { A[n as usize & 63] as char } else { '=' });
    }
    out
}

/// A fresh throwaway SDES key||salt (16+14 bytes) for `AES_CM_128_HMAC_SHA1_80`, base64-encoded.
fn srtp_key() -> String {
    let mut k = [0u8; 30];
    fill_random(&mut k);
    base64_encode(&k)
}

// ---- the driver ------------------------------------------------------------------------------

/// Run the on-demand SIP UA. Waits for a view request on `view_rx`; each request brings the panel
/// session up (if not already up) and refreshes an idle deadline. After
/// `cfg.camera_view_idle_secs` with no further request the dialog is torn down (BYE) so the panel
/// is never left pinned. Returns when `stopping` is observed (draining the active dialog first).
pub async fn run(cfg: Arc<Config>, stopping: Arc<AtomicBool>, mut view_rx: mpsc::Receiver<()>) {
    let mut backoff = BACKOFF_INIT;
    while !stopping.load(Ordering::Relaxed) {
        // Idle until a view is requested (or the trigger channel closes ⇒ shutting down).
        if view_rx.recv().await.is_none() {
            return;
        }
        if stopping.load(Ordering::Relaxed) {
            return;
        }
        match session(&cfg, &stopping, &mut view_rx).await {
            Ok(()) => backoff = BACKOFF_INIT,
            Err(e) => {
                eprintln!("btmqttd: on-demand SIP session failed: {e}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

/// One on-demand session: INVITE → ACK, hold while views keep arriving, then BYE. The idle timer is
/// refreshed by every extra `view_rx` message received while the session is up.
async fn session(
    cfg: &Arc<Config>,
    stopping: &Arc<AtomicBool>,
    view_rx: &mut mpsc::Receiver<()>,
) -> std::io::Result<()> {
    let (aor, domain) = resolve_identity(cfg).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot resolve SIP AOR/domain (model or domain-registration.conf missing)",
        )
    })?;

    let mut sock = TcpStream::connect(("127.0.0.1", cfg.sip_port)).await?;
    let local_port = sock.local_addr()?.port();

    let mut d = Dialog {
        aor,
        domain,
        local_port,
        call_id: rand_hex(8),
        from_tag: rand_hex(6),
        branch: format!("z9hG4bK{}", rand_hex(8)),
        cseq: 21,
        to_tag: String::new(),
        remote_target: String::new(),
    };

    // INVITE with a throwaway-keyed SAVP offer; media is blackholed (av.rs does the real siphon).
    let sdp = build_sdp_offer(cfg.camera_video_port, cfg.camera_audio_port, &srtp_key());
    let invite = build_invite(&d, &sdp);
    sock.write_all(invite.as_bytes()).await?;
    sock.flush().await?;

    // Await the final response to the INVITE. 1xx are provisional; 2xx confirms; >=300 is failure.
    let final_resp = tokio::time::timeout(RESPONSE_TIMEOUT, wait_final_response(&mut sock))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "INVITE response timed out"))??;

    let status = parse_status(&final_resp)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no SIP status line"))?;
    if status == 407 || status == 401 {
        // flexisip challenged our loopback INVITE — trusted-hosts should prevent this. If it ever
        // happens we need a registered identity + digest; surface it clearly for the hardware pass.
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "SIP auth required (flexisip did not trust the loopback UA) — needs a registered identity",
        ));
    }
    if !(200..300).contains(&status) {
        return Err(std::io::Error::other(format!("INVITE rejected with {status}")));
    }

    d.to_tag = to_tag(&final_resp).unwrap_or_default();
    d.remote_target = contact_uri(&final_resp)
        .unwrap_or_else(|| format!("sip:{}@{}", d.aor, d.domain));

    // Confirm the dialog.
    sock.write_all(build_ack(&d, &format!("z9hG4bK{}", rand_hex(8))).as_bytes()).await?;
    sock.flush().await?;
    eprintln!("btmqttd: on-demand session up (sip:{}@{})", d.aor, d.domain);

    // Hold the session while views keep arriving; drain any responses/requests the panel sends.
    let idle = Duration::from_secs(cfg.camera_view_idle_secs);
    let mut scratch = [0u8; 4096];
    loop {
        if stopping.load(Ordering::Relaxed) {
            break;
        }
        tokio::select! {
            v = view_rx.recv() => match v {
                Some(()) => continue,          // refreshed — keep holding
                None => break,                 // shutting down
            },
            r = sock.read(&mut scratch) => match r {
                Ok(0) => break,                // panel closed the dialog
                Ok(_) => continue,             // ignore mid-dialog traffic (re-INVITE/OPTIONS/media stats)
                Err(e) => return Err(e),
            },
            _ = tokio::time::sleep(idle) => break, // idle expiry ⇒ hang up
        }
    }

    // Teardown: BYE (best-effort — the session may already be gone).
    let bye = build_bye(&d, &format!("z9hG4bK{}", rand_hex(8)));
    let _ = sock.write_all(bye.as_bytes()).await;
    let _ = sock.flush().await;
    // Give the 200-to-BYE a brief moment; we don't strictly need to read it.
    let _ = tokio::time::timeout(Duration::from_secs(1), sock.read(&mut scratch)).await;
    eprintln!("btmqttd: on-demand session torn down (sip:{}@{})", d.aor, d.domain);
    Ok(())
}

/// Read until the INVITE's FINAL response (skips `1xx` provisional). Accumulates bytes until a
/// complete message with a `>= 200` status line is seen, or the cap/timeout trips.
async fn wait_final_response(sock: &mut TcpStream) -> std::io::Result<String> {
    let mut acc: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(READ_CHUNK_TIMEOUT, sock.read(&mut buf))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "SIP read stalled"))??;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "peer closed before final response",
            ));
        }
        acc.extend_from_slice(&buf[..n]);
        if acc.len() > MAX_SIP_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SIP response exceeded cap",
            ));
        }
        // The panel pipelines 100/180/200 as separate TCP segments. Scan for the last complete
        // message and stop once its status is final (>= 200).
        let text = String::from_utf8_lossy(&acc);
        if let Some(status) = last_final_status(&text) {
            if status >= 200 {
                return Ok(extract_final_message(&text));
            }
        }
    }
}

/// The status code of the last complete response present in `text` (messages are separated by the
/// blank line + start of the next `SIP/2.0` line). `None` while only provisional responses so far.
fn last_final_status(text: &str) -> Option<u16> {
    text.split("SIP/2.0 ")
        .filter(|seg| !seg.is_empty())
        .filter_map(|seg| seg.split_whitespace().next()?.parse::<u16>().ok())
        .filter(|s| *s >= 200)
        .last()
}

/// Extract the final (>= 200) response message from a buffer that may hold several pipelined
/// responses, re-prefixing the `SIP/2.0 ` the split consumed.
fn extract_final_message(text: &str) -> String {
    let mut last = String::new();
    for seg in text.split("SIP/2.0 ") {
        if seg.is_empty() {
            continue;
        }
        if let Some(code) = seg.split_whitespace().next().and_then(|c| c.parse::<u16>().ok()) {
            if code >= 200 {
                last = format!("SIP/2.0 {seg}");
            }
        }
    }
    last
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aor_maps_from_model_hostname() {
        assert_eq!(aor_user_for_hostname("Bticino_Classe_100_X\n"), Some("c100x"));
        assert_eq!(aor_user_for_hostname("Bticino_Classe_300_X"), Some("c300x"));
        assert_eq!(aor_user_for_hostname("SomethingElse"), None);
    }

    #[test]
    fn domain_is_first_token_of_first_real_line() {
        let conf = "# comment\n\n\
                    f4055f96-88f5-4523-ad76-3b19bf29a581.bs.iotleg.com sips:vdesip.bs.iotleg.com;transport=tls\n";
        assert_eq!(
            domain_from_registration(conf).as_deref(),
            Some("f4055f96-88f5-4523-ad76-3b19bf29a581.bs.iotleg.com")
        );
        assert_eq!(domain_from_registration("   \n# only comments\n"), None);
    }

    #[test]
    fn status_and_headers_parse() {
        let msg = "SIP/2.0 200 Ok\r\n\
                   To: <sip:c100x@d>;tag=QockcBd\r\n\
                   Contact: <sip:c100x@127.0.0.1:41044;transport=tcp>\r\n\
                   CSeq: 21 INVITE\r\n\
                   \r\n";
        assert_eq!(parse_status(msg), Some(200));
        assert_eq!(to_tag(msg).as_deref(), Some("QockcBd"));
        assert_eq!(
            contact_uri(msg).as_deref(),
            Some("sip:c100x@127.0.0.1:41044;transport=tcp")
        );
        assert_eq!(header_value(msg, "cseq"), Some("21 INVITE")); // case-insensitive
    }

    #[test]
    fn provisional_then_final_is_picked() {
        let pipelined = "SIP/2.0 100 Trying\r\n\r\nSIP/2.0 180 Ringing\r\n\r\nSIP/2.0 200 Ok\r\nTo: <sip:x>;tag=t\r\n\r\n";
        assert_eq!(last_final_status(pipelined), Some(200));
        let only_provisional = "SIP/2.0 100 Trying\r\n\r\nSIP/2.0 180 Ringing\r\n\r\n";
        assert_eq!(last_final_status(only_provisional), None);
        assert!(extract_final_message(pipelined).starts_with("SIP/2.0 200 Ok"));
    }

    #[test]
    fn invite_ack_bye_are_well_formed() {
        let d = Dialog {
            aor: "c100x".into(),
            domain: "dev.example".into(),
            local_port: 5555,
            call_id: "abcd".into(),
            from_tag: "ft".into(),
            branch: "z9hG4bKdeadbeef".into(),
            cseq: 21,
            to_tag: "paneltag".into(),
            remote_target: "sip:c100x@127.0.0.1:41044;transport=tcp".into(),
        };
        let sdp = build_sdp_offer(40000, 40002, "AAAA");
        let invite = build_invite(&d, &sdp);
        assert!(invite.starts_with("INVITE sip:c100x@dev.example SIP/2.0\r\n"));
        assert!(invite.contains("CSeq: 21 INVITE\r\n"));
        assert!(invite.contains(&format!("Content-Length: {}\r\n", sdp.len())));
        assert!(invite.contains("m=video 40000 RTP/SAVP 97"));
        assert!(invite.contains("profile-level-id=42801F"));

        let ack = build_ack(&d, "z9hG4bKack1");
        assert!(ack.starts_with("ACK sip:c100x@127.0.0.1:41044;transport=tcp SIP/2.0\r\n"));
        assert!(ack.contains("To: <sip:c100x@dev.example>;tag=paneltag\r\n"));
        assert!(ack.contains("CSeq: 21 ACK\r\n"));

        let bye = build_bye(&d, "z9hG4bKbye1");
        assert!(bye.starts_with("BYE sip:c100x@127.0.0.1:41044;transport=tcp SIP/2.0\r\n"));
        assert!(bye.contains("CSeq: 22 BYE\r\n")); // incremented
        assert!(bye.contains("tag=paneltag"));
    }

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }
}
