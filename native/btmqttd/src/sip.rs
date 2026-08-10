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
//! ## What makes it SILENT (hardware-proven, issue #104)
//! An INVITE whose SDP is `m=video recvonly` but is otherwise plain RINGS the indoor unit as a
//! normal intercom call. Two session-level SDP attributes flip it to a silent camerasliding pull:
//! `a=DEVADDR:<uuid>` (the entrance camera to switch on — on the C100X the `id` of the
//! `videodoorentry` `EU` module at OWN address 20 in `mymodules`; the numeric `20` form is
//! C300X-only) and `a=nortpproxy:yes`. With both, the panel answers `200 OK` / `m=video sendonly`
//! and the household stays quiet. `180 Ringing` still appears at the SIP layer — it does NOT mean
//! the unit rang; `wait_final_response` skips it and waits for the `200`.
//!
//! ## Captured dialog (redacted), the ground truth this mirrors
//! ```text
//! INVITE sip:c100x@<domain>            CSeq: 21 INVITE   (SDP: RTP/SAVP, a=nortpproxy:yes, a=DEVADDR:<uuid>)
//!   <- 100 Trying / 180 Ringing (SIP-layer only; To adds ;tag=<panel>) / 200 OK (m=video sendonly)
//! ACK  sip:c100x@127.0.0.1:<ephem>     CSeq: 21 ACK      (Contact: c100x@127.0.0.1:<ephem>)
//!   ... session held; av.rs siphons :30007 ...
//! BYE  sip:c100x@127.0.0.1:<ephem>     CSeq: 22 BYE
//!   <- 200 OK
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::config::Config;

/// Where flexisip seeds the device's SIP domain at boot: the first whitespace-delimited token of
/// the first real line is the panel's local domain (e.g. `<uuid>.bs.iotleg.com`).
const DOMAIN_REGISTRATION_CONF: &str = "/etc/flexisip/domain-registration.conf";
/// Model detection, same file the rest of the tool already uses.
const HOSTNAME_PATH: &str = "/etc/hostname";
/// The on-device plant topology (JSON): the `a=DEVADDR` that makes the INVITE a SILENT camerasliding
/// pull is a module `id` in here (see `devaddr_from_mymodules`).
const MYMODULES_PATH: &str = "/home/bticino/cfg/extra/.bt_eliot/mymodules";
/// The OWN address of the main entrance panel — conventionally `20` on these plants (the reference
/// `detectDevAddrOnC100X()` hardcodes it). An installer can override the whole DEVADDR via config.
const MAIN_ENTRANCE_OWN_ADDR: &str = "20";

/// Overall INVITE-response budget. This is the SINGLE timeout on the response wait (it wraps the
/// whole `wait_final_response`), so there is exactly one timeout exit — routed through
/// `cancel_pending_invite` — and no faster per-read timeout that could drop the socket without a
/// CANCEL (Codex/CodeRabbit).
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long we keep draining (framing responses, tearing down a racing 2xx) after sending CANCEL.
const CANCEL_DRAIN: Duration = Duration::from_secs(2);
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

/// The `a=DEVADDR` value — a port of the reference `detectDevAddrOnC100X()`. In the on-device
/// `mymodules` JSON the entrance camera is the `videodoorentry` `EU` module at OWN address
/// `own_addr` (conventionally `20`); its `id` (a UUID) is the DEVADDR that flips the INVITE from a
/// household-ringing intercom call to a SILENT camerasliding pull (hardware-proven, issue #104).
/// Returns the id only when EXACTLY ONE module matches — an ambiguous plant declines rather than
/// guess (never ring the wrong / a household). Pure over the file contents, so it unit-tests.
///
/// The numeric OWN-address form works on the C300X but returns `486 Busy here` on the C100X, so we
/// resolve the UUID here for universality; an installer can still pin either form via `SIP_DEVADDR`.
pub fn devaddr_from_mymodules(content: &str, own_addr: &str) -> Option<String> {
    let root: Value = serde_json::from_str(content).ok()?;
    let modules = root.get("modules")?.as_array()?;
    let mut hit: Option<String> = None;
    for m in modules {
        if m.get("system").and_then(Value::as_str) != Some("videodoorentry") {
            continue;
        }
        if m.get("deviceType").and_then(Value::as_str) != Some("EU") {
            continue;
        }
        let addr_match = m
            .get("privateAddress")
            .and_then(|p| p.get("addressValues"))
            .and_then(Value::as_array)
            .is_some_and(|vals| {
                vals.iter()
                    .any(|a| a.get("value").and_then(Value::as_str) == Some(own_addr))
            });
        if !addr_match {
            continue;
        }
        // A blank or whitespace-only `id` on an otherwise-matching module is corrupt/mid-update
        // data: treat it as NO match (skip) rather than returning `Some("")` / `Some("  ")`, which
        // would pass resolve_identity's mandatory gate and emit an empty/blank `a=DEVADDR:` —
        // defeating the fail-closed guarantee that we never originate a ringing INVITE (Codex/CodeRabbit).
        let Some(id) = m.get("id").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty())
        else {
            continue;
        };
        if hit.is_some() {
            return None; // more than one entrance at this address ⇒ ambiguous, decline
        }
        hit = Some(id.to_string());
    }
    hit
}

/// Resolve `(aor_user, domain, devaddr)` from config overrides, falling back to on-device files.
/// `None` if the model, domain, OR the camerasliding DEVADDR can't be determined — the caller then
/// declines to originate. The DEVADDR is MANDATORY on purpose: without it the INVITE would ring the
/// household as a normal intercom call, so "cannot resolve it" must mean "do not send" (issue #104).
async fn resolve_identity(cfg: &Config) -> Option<(String, String, String)> {
    // tokio::fs (not std::fs): btmqttd runs on a single-threaded runtime, so a blocking read here
    // would stall the MQTT loop, the OWN monitor and the camera siphon for its duration (Copilot).
    let aor = if !cfg.sip_local_aor.is_empty() {
        cfg.sip_local_aor.clone()
    } else {
        let hn = tokio::fs::read_to_string(HOSTNAME_PATH).await.ok()?;
        aor_user_for_hostname(&hn)?.to_string()
    };
    let domain = if !cfg.sip_domain.is_empty() {
        cfg.sip_domain.clone()
    } else {
        let text = tokio::fs::read_to_string(DOMAIN_REGISTRATION_CONF).await.ok()?;
        domain_from_registration(&text)?
    };
    // A whitespace-only SIP_DEVADDR override is treated as unset (fall through to auto-detect), and
    // the auto-detected id is likewise trimmed+non-empty (above) — so the DEVADDR we emit is never
    // blank, keeping the fail-closed gate intact (CodeRabbit).
    let devaddr = {
        let over = cfg.sip_devaddr.trim();
        if !over.is_empty() {
            over.to_string()
        } else {
            let text = tokio::fs::read_to_string(MYMODULES_PATH).await.ok()?;
            devaddr_from_mymodules(&text, MAIN_ENTRANCE_OWN_ADDR)?
        }
    };
    Some((aor, domain, devaddr))
}

// ---- SDP + SIP message construction ----------------------------------------------------------

/// A minimal `RTP/SAVP` offer belle-sip will answer. We ask the panel to SEND video (`recvonly`
/// from our side) and keep audio `inactive` — Phase 2 only needs the session UP; the actual media
/// is siphoned cleartext by `av.rs`. The crypto key is a throwaway (the SRTP is blackholed). Ports
/// are placeholders we never read.
///
/// The two session-level attributes are what make this a SILENT camerasliding pull rather than a
/// household-ringing intercom call (hardware-proven, issue #104): `a=DEVADDR:<uuid>` selects the
/// entrance camera to switch on, and `a=nortpproxy:yes` tells flexisip not to insert its media
/// relay. An INVITE with the identical `m=video recvonly` but WITHOUT these rings the unit; WITH
/// them the panel answers `200 OK`/`m=video sendonly` and the house stays quiet.
pub fn build_sdp_offer(video_port: u16, audio_port: u16, srtp_key_b64: &str, devaddr: &str) -> String {
    format!(
        "v=0\r\n\
         o=btmqttd 0 0 IN IP4 127.0.0.1\r\n\
         s=btmqttd\r\n\
         c=IN IP4 127.0.0.1\r\n\
         t=0 0\r\n\
         a=nortpproxy:yes\r\n\
         a=DEVADDR:{devaddr}\r\n\
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

/// CANCEL a still-pending INVITE (RFC 3261 §9.1). It MUST reuse the INVITE's Request-URI, `Call-ID`,
/// `From`-tag, `To` (no tag yet — the transaction isn't confirmed), CSeq NUMBER (method `CANCEL`) and,
/// critically, the SAME top `Via` branch as the INVITE it cancels, so the proxy matches it to that
/// transaction. Sent best-effort if the INVITE times out, so a late `200` can't bring the panel
/// session up after we've walked away (a dropped TCP connection does not cancel a SIP transaction).
pub fn build_cancel(d: &Dialog) -> String {
    format!(
        "CANCEL sip:{aor}@{domain} SIP/2.0\r\n\
         Via: SIP/2.0/TCP 127.0.0.1:{lport};rport;branch={branch}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:btmqttd@{domain}>;tag={ftag}\r\n\
         To: <sip:{aor}@{domain}>\r\n\
         Call-ID: {callid}\r\n\
         CSeq: {cseq} CANCEL\r\n\
         Content-Length: 0\r\n\
         \r\n",
        aor = d.aor,
        domain = d.domain,
        lport = d.local_port,
        branch = d.branch,
        ftag = d.from_tag,
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

/// True when `msg`'s request-line is a `BYE` — the panel ending the dialog from its side.
pub fn is_bye(msg: &str) -> bool {
    msg.lines().next().is_some_and(|l| l.starts_with("BYE "))
}

/// True when `msg` is a 2xx response to the INVITE transaction itself — i.e. an ESTABLISHED dialog
/// we must ACK then BYE. Distinguished from the `200 OK` to our CANCEL (also 2xx, but `CSeq: N
/// CANCEL`), which establishes nothing and must NOT trigger a teardown (CodeRabbit).
pub fn is_established_invite_2xx(msg: &str) -> bool {
    matches!(parse_status(msg), Some(s) if (200..300).contains(&s))
        && header_value(msg, "CSeq")
            .and_then(|c| c.split_whitespace().nth(1))
            .is_some_and(|m| m.eq_ignore_ascii_case("INVITE"))
}

/// A `200 OK` to an in-dialog request (the panel's BYE), echoing the headers the transaction needs:
/// every `Via` (in order), plus `From`/`To`/`Call-ID`/`CSeq`. `None` if a required header is absent
/// (then we simply let the peer's retransmits lapse). Sent so the panel doesn't retransmit its BYE.
pub fn build_ok_to(request: &str) -> Option<String> {
    let mut out = String::from("SIP/2.0 200 OK\r\n");
    for line in request.lines() {
        if line.is_empty() {
            break; // end of headers
        }
        if line.split_once(':').is_some_and(|(h, _)| h.trim().eq_ignore_ascii_case("Via")) {
            out.push_str(line);
            out.push_str("\r\n");
        }
    }
    for name in ["From", "To", "Call-ID", "CSeq"] {
        out.push_str(name);
        out.push_str(": ");
        out.push_str(header_value(request, name)?);
        out.push_str("\r\n");
    }
    out.push_str("Content-Length: 0\r\n\r\n");
    Some(out)
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
    let (aor, domain, devaddr) = resolve_identity(cfg).await.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot resolve SIP identity (model, domain-registration.conf, or camerasliding DEVADDR \
             from mymodules missing) — declining so we never ring the household",
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
    // The DEVADDR + nortpproxy in the SDP make it a silent camerasliding pull (no household ring).
    let sdp = build_sdp_offer(cfg.camera_video_port, cfg.camera_audio_port, &srtp_key(), &devaddr);
    let invite = build_invite(&d, &sdp);
    sock.write_all(invite.as_bytes()).await?;
    sock.flush().await?;

    // Await the final response to the INVITE. 1xx are provisional; 2xx confirms; >=300 is failure.
    // The ONLY timeout is this outer budget; on expiry we don't just drop the socket (over TCP that
    // does NOT cancel the INVITE, and a late 200 could then pin the panel) — we run the full
    // cancellation routine, which sends CANCEL and, if a 2xx raced in, ACK/BYEs it (Codex/CodeRabbit).
    let final_resp = match tokio::time::timeout(RESPONSE_TIMEOUT, wait_final_response(&mut sock)).await {
        Ok(r) => r?,
        Err(_) => {
            cancel_pending_invite(&mut sock, &mut d).await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "INVITE response timed out (CANCEL sent)",
            ));
        }
    };

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

    // A 2xx to INVITE MUST carry a To-tag — it's what makes the dialog "confirmed" and is echoed in
    // the ACK and BYE. Without it the teardown is unreliable, so fail rather than send an ACK/BYE with
    // an empty tag (Copilot). The Contact is the panel's in-dialog request target for ACK/BYE; a 2xx
    // should include one, but fall back to the AOR (still routable via the proxy) if a peer omits it.
    d.to_tag = to_tag(&final_resp).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "2xx to INVITE has no To-tag — cannot form a confirmed dialog for ACK/BYE",
        )
    })?;
    d.remote_target = contact_uri(&final_resp)
        .unwrap_or_else(|| format!("sip:{}@{}", d.aor, d.domain));

    // Confirm the dialog.
    sock.write_all(build_ack(&d, &format!("z9hG4bK{}", rand_hex(8))).as_bytes()).await?;
    sock.flush().await?;
    eprintln!("btmqttd: on-demand session up (sip:{}@{})", d.aor, d.domain);

    // Hold the session while views keep arriving. The idle-hangup uses a PERSISTENT absolute
    // deadline that only a real viewer poke (`view_rx`) refreshes — NOT socket traffic. Otherwise
    // in-dialog chatter the panel sends (OPTIONS/re-INVITE/media stats) arriving more often than the
    // idle window would keep resetting a per-iteration timer and pin the session open forever (Codex).
    let idle = Duration::from_secs(cfg.camera_view_idle_secs);
    let mut deadline = tokio::time::Instant::now() + idle;
    let mut scratch = [0u8; 4096];
    // FRAME in-dialog requests the same way `wait_final_response` frames responses: TCP can split a
    // panel BYE across reads, or coalesce it after other in-dialog traffic, so inspecting one raw
    // read chunk could miss the `BYE ` prefix (⇒ no 200 OK, the panel retransmits) or see the prefix
    // before its headers are complete (⇒ `build_ok_to` returns None yet we'd mark the dialog ended).
    // Accumulate, then act only on COMPLETE messages (Codex + CodeRabbit).
    let mut inbound: Vec<u8> = Vec::new();
    let mut panel_ended = false; // the panel tore the dialog down first ⇒ don't send our own BYE
    'dialog: loop {
        if stopping.load(Ordering::Relaxed) {
            break;
        }
        tokio::select! {
            v = view_rx.recv() => match v {
                Some(()) => deadline = tokio::time::Instant::now() + idle, // refresh on a real view
                None => break,                                            // shutting down
            },
            r = sock.read(&mut scratch) => match r {
                Ok(0) => { panel_ended = true; break; } // panel closed the connection
                Ok(n) => {
                    inbound.extend_from_slice(&scratch[..n]);
                    if inbound.len() > MAX_SIP_BYTES {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "in-dialog SIP request exceeded cap",
                        ));
                    }
                    // Drain every complete message now buffered. A panel-initiated BYE ends the
                    // dialog: acknowledge it (200 OK, else the panel retransmits) and stop — we must
                    // NOT then send our own BYE to a dead dialog. Other in-dialog traffic
                    // (OPTIONS/re-INVITE/media stats) is ignored and does NOT refresh the deadline.
                    while let Some(len) = complete_message_len(&inbound) {
                        let msg = String::from_utf8_lossy(&inbound[..len]).into_owned();
                        inbound.drain(..len);
                        if !is_bye(&msg) {
                            continue;
                        }
                        if let Some(ok) = build_ok_to(&msg) {
                            let _ = sock.write_all(ok.as_bytes()).await;
                            let _ = sock.flush().await;
                        }
                        panel_ended = true;
                        break 'dialog;
                    }
                }
                Err(e) => return Err(e),
            },
            _ = tokio::time::sleep_until(deadline) => break, // idle expiry ⇒ hang up
        }
    }

    // Teardown: send our BYE unless the panel already ended the dialog (we ACKed its BYE above).
    if !panel_ended {
        let bye = build_bye(&d, &format!("z9hG4bK{}", rand_hex(8)));
        let _ = sock.write_all(bye.as_bytes()).await;
        let _ = sock.flush().await;
        // Give the 200-to-BYE a brief moment; we don't strictly need to read it.
        let _ = tokio::time::timeout(Duration::from_secs(1), sock.read(&mut scratch)).await;
    }
    eprintln!("btmqttd: on-demand session torn down (sip:{}@{})", d.aor, d.domain);
    Ok(())
}

/// Best-effort teardown when the INVITE never gets a timely final response. Over TCP, closing the
/// socket does NOT cancel a pending INVITE transaction, so:
///  1. send `CANCEL` (matched to the INVITE by branch + CSeq), then
///  2. drain framed responses for a bounded window — and if a 2xx to the INVITE *raced in* (the
///     panel answered right as we gave up), CANCEL can't undo it, so we MUST confirm and tear that
///     dialog down (`ACK` then `BYE`) or the panel keeps its camera streaming (Codex/CodeRabbit).
///
/// All writes are best-effort (`let _ =`): we're already on the error path and about to drop the
/// connection; the goal is simply to leave the panel with no established session.
async fn cancel_pending_invite(sock: &mut TcpStream, d: &mut Dialog) {
    let _ = sock.write_all(build_cancel(d).as_bytes()).await;
    let _ = sock.flush().await;

    let mut acc: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + CANCEL_DRAIN;
    loop {
        while let Some(len) = complete_message_len(&acc) {
            let msg = String::from_utf8_lossy(&acc[..len]).into_owned();
            acc.drain(..len);
            // A 2xx to the INVITE (CSeq method INVITE) means the dialog established despite our
            // CANCEL. Confirm it (ACK) and immediately end it (BYE) so nothing stays pinned. Needs
            // the To-tag; if a peer omits it we can't form a valid ACK/BYE, so just stop (the socket
            // close is our last resort). The `200 OK` to the CANCEL is ALSO 2xx but carries
            // `CSeq: N CANCEL` and establishes nothing — it must NOT trigger a teardown, so we keep
            // draining past it for a possible racing INVITE 2xx (CodeRabbit). 487/provisional: ignore.
            if is_established_invite_2xx(&msg) {
                if let Some(tag) = to_tag(&msg) {
                    d.to_tag = tag;
                    d.remote_target =
                        contact_uri(&msg).unwrap_or_else(|| format!("sip:{}@{}", d.aor, d.domain));
                    let _ = sock
                        .write_all(build_ack(d, &format!("z9hG4bK{}", rand_hex(8))).as_bytes())
                        .await;
                    let _ = sock.flush().await;
                    let _ = sock
                        .write_all(build_bye(d, &format!("z9hG4bK{}", rand_hex(8))).as_bytes())
                        .await;
                    let _ = sock.flush().await;
                }
                return;
            }
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return;
        }
        match tokio::time::timeout(remaining, sock.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                acc.extend_from_slice(&buf[..n]);
                if acc.len() > MAX_SIP_BYTES {
                    return;
                }
            }
            // EOF, read error, or the drain window elapsed ⇒ nothing more to do.
            _ => return,
        }
    }
}

/// Read until the INVITE's FINAL response (skips `1xx` provisional). Accumulates bytes until a
/// complete message with a `>= 200` status line is seen, or the cap/timeout trips.
async fn wait_final_response(sock: &mut TcpStream) -> std::io::Result<String> {
    let mut acc: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        // Consume every COMPLETE message already buffered and return the first FINAL (>= 200). A
        // message is complete only once its CRLFCRLF header terminator AND its Content-Length body
        // have all arrived — returning on the status line alone could hand back a 200 whose
        // To-tag/Contact haven't been read yet, so the ACK would carry an empty tag and the dialog
        // would never confirm even though the panel accepted the INVITE (Codex).
        while let Some(len) = complete_message_len(&acc) {
            let msg = String::from_utf8_lossy(&acc[..len]).into_owned();
            acc.drain(..len);
            match parse_status(&msg) {
                Some(s) if s >= 200 => return Ok(msg),
                _ => {} // 1xx provisional (or a stray in-dialog request) — keep reading
            }
        }
        // No per-read timeout here: the caller wraps this whole call in `RESPONSE_TIMEOUT`, so a
        // stalled read is bounded by that single outer budget and its expiry routes through the
        // CANCEL path. A faster per-read timeout would return here without cancelling the INVITE.
        let n = sock.read(&mut buf).await?;
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
    }
}

/// If `buf` begins with a COMPLETE SIP message — headers terminated by CRLFCRLF, followed by a body
/// of `Content-Length` bytes (0 when the header is absent) — return that message's total byte length;
/// else `None` (more bytes needed). Frames one message at a time, so pipelined 100/180/200 responses
/// (and a 200's SDP body) are handled without ever returning a half-read message.
fn complete_message_len(buf: &[u8]) -> Option<usize> {
    let sep = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let header_end = sep + 4;
    let headers = std::str::from_utf8(&buf[..sep]).ok()?;
    let content_length = headers
        .lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(h, _)| h.trim().eq_ignore_ascii_case("Content-Length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let total = header_end + content_length;
    (buf.len() >= total).then_some(total)
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
    fn devaddr_selects_the_eu_module_at_own_address_20() {
        // Mirrors the real C100X mymodules shape (UUIDs are placeholders): an IU at 112 (whose
        // addressValues also carry an EUaddress=20 — must NOT match, it's deviceType IU), the main
        // entrance EU at 20, a lock at 20, and a SECOND entrance EU at 21. Only the EU@20 id wins.
        let conf = r#"{
          "jsonrpc":"2.0",
          "modules":[
            {"system":"videodoorentry","deviceType":"IU","id":"iu-1",
             "privateAddress":{"addressValues":[{"name":"address","value":"112"},
                                                {"name":"EUaddress","value":"20"}]}},
            {"system":"videodoorentry","deviceType":"EU","id":"eu-at-20",
             "privateAddress":{"addressValues":[{"name":"address","value":"20"}]}},
            {"system":"automation","deviceType":"Lock","id":"lock-20",
             "privateAddress":{"addressValues":[{"name":"address","value":"20"}]}},
            {"system":"videodoorentry","deviceType":"EU","id":"eu-at-21",
             "privateAddress":{"addressValues":[{"name":"address","value":"21"}]}}
          ]}"#;
        assert_eq!(devaddr_from_mymodules(conf, "20").as_deref(), Some("eu-at-20"));
        assert_eq!(devaddr_from_mymodules(conf, "21").as_deref(), Some("eu-at-21"));
        // No entrance at this address ⇒ None (decline, don't guess).
        assert_eq!(devaddr_from_mymodules(conf, "99"), None);
        // Two entrances at the same address ⇒ ambiguous ⇒ None (never ring the wrong one).
        let dup = r#"{"modules":[
            {"system":"videodoorentry","deviceType":"EU","id":"a",
             "privateAddress":{"addressValues":[{"name":"address","value":"20"}]}},
            {"system":"videodoorentry","deviceType":"EU","id":"b",
             "privateAddress":{"addressValues":[{"name":"address","value":"20"}]}}]}"#;
        assert_eq!(devaddr_from_mymodules(dup, "20"), None);
        // Garbage / missing modules array ⇒ None, not a panic.
        assert_eq!(devaddr_from_mymodules("not json", "20"), None);
        assert_eq!(devaddr_from_mymodules("{}", "20"), None);
        // A matching EU@20 with a BLANK or whitespace-only id is corrupt/mid-update data ⇒ None, NOT
        // Some("")/Some("  "), so the mandatory gate can't be defeated into emitting an empty/blank
        // `a=DEVADDR:` (Codex/CodeRabbit).
        let blank = r#"{"modules":[
            {"system":"videodoorentry","deviceType":"EU","id":"",
             "privateAddress":{"addressValues":[{"name":"address","value":"20"}]}}]}"#;
        assert_eq!(devaddr_from_mymodules(blank, "20"), None);
        let ws = r#"{"modules":[
            {"system":"videodoorentry","deviceType":"EU","id":"   ",
             "privateAddress":{"addressValues":[{"name":"address","value":"20"}]}}]}"#;
        assert_eq!(devaddr_from_mymodules(ws, "20"), None);
        // A valid id with surrounding whitespace is trimmed, not rejected.
        let padded = r#"{"modules":[
            {"system":"videodoorentry","deviceType":"EU","id":"  uuid-1  ",
             "privateAddress":{"addressValues":[{"name":"address","value":"20"}]}}]}"#;
        assert_eq!(devaddr_from_mymodules(padded, "20").as_deref(), Some("uuid-1"));
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
    fn frames_complete_messages_and_skips_provisional() {
        // Completeness needs BOTH the CRLFCRLF header terminator and the Content-Length body.
        let full = b"SIP/2.0 200 Ok\r\nContent-Length: 4\r\n\r\nabcd";
        assert_eq!(complete_message_len(full), Some(full.len()));
        assert_eq!(complete_message_len(b"SIP/2.0 200 Ok\r\nContent-Length: 4\r\n\r\nab"), None); // body short
        assert_eq!(complete_message_len(b"SIP/2.0 200 Ok\r\nContent-Len"), None); // headers unterminated

        // Pipelined 100 then 200: frame one at a time; the provisional is skipped and the final's
        // To-tag parses (the bug the framing fixes: a half-read 200 would lose the tag).
        let mut acc =
            b"SIP/2.0 100 Trying\r\nContent-Length: 0\r\n\r\nSIP/2.0 200 Ok\r\nTo: <sip:x>;tag=t\r\nContent-Length: 0\r\n\r\n"
                .to_vec();
        let l1 = complete_message_len(&acc).unwrap();
        assert_eq!(parse_status(&String::from_utf8_lossy(&acc[..l1])), Some(100));
        acc.drain(..l1);
        let l2 = complete_message_len(&acc).unwrap();
        let final_msg = String::from_utf8_lossy(&acc[..l2]).into_owned();
        assert_eq!(parse_status(&final_msg), Some(200));
        assert_eq!(to_tag(&final_msg).as_deref(), Some("t"));
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
        let sdp = build_sdp_offer(40000, 40002, "AAAA", "dev-addr-uuid");
        let invite = build_invite(&d, &sdp);
        assert!(invite.starts_with("INVITE sip:c100x@dev.example SIP/2.0\r\n"));
        assert!(invite.contains("CSeq: 21 INVITE\r\n"));
        assert!(invite.contains(&format!("Content-Length: {}\r\n", sdp.len())));
        assert!(invite.contains("m=video 40000 RTP/SAVP 97"));
        assert!(invite.contains("profile-level-id=42801F"));
        // The two attributes that make it a silent camerasliding pull, not a ringing call (#104).
        assert!(invite.contains("a=nortpproxy:yes\r\n"));
        assert!(invite.contains("a=DEVADDR:dev-addr-uuid\r\n"));

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
    fn acknowledges_a_panel_bye_with_a_matching_200_ok() {
        let bye = "BYE sip:btmqttd@127.0.0.1:5060 SIP/2.0\r\n\
                   Via: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bKxyz\r\n\
                   From: <sip:app@d>;tag=ft\r\n\
                   To: <sip:c100x@d>;tag=tt\r\n\
                   Call-ID: cid123\r\n\
                   CSeq: 22 BYE\r\n\
                   Content-Length: 0\r\n\r\n";
        assert!(is_bye(bye));
        assert!(!is_bye("SIP/2.0 200 Ok\r\n\r\n"));
        let ok = build_ok_to(bye).unwrap();
        assert!(ok.starts_with("SIP/2.0 200 OK\r\n"));
        assert!(ok.contains("Via: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bKxyz\r\n")); // echoed verbatim
        assert!(ok.contains("Call-ID: cid123\r\n"));
        assert!(ok.contains("CSeq: 22 BYE\r\n")); // same CSeq so the panel matches the transaction
        assert!(ok.ends_with("Content-Length: 0\r\n\r\n"));
    }

    #[test]
    fn only_a_2xx_to_the_invite_counts_as_established() {
        // A 200 to the INVITE (CSeq method INVITE) is an established dialog we must ACK/BYE.
        let ok_invite = "SIP/2.0 200 OK\r\nCSeq: 21 INVITE\r\nTo: <sip:x>;tag=t\r\nContent-Length: 0\r\n\r\n";
        assert!(is_established_invite_2xx(ok_invite));
        // The 200 to our CANCEL is ALSO 2xx but CSeq method CANCEL — it establishes nothing, so it
        // must NOT select the ACK/BYE path (regression for the racing-drain fix).
        let ok_cancel = "SIP/2.0 200 OK\r\nCSeq: 21 CANCEL\r\nContent-Length: 0\r\n\r\n";
        assert!(!is_established_invite_2xx(ok_cancel));
        // 487 to the INVITE (the expected terminal response after CANCEL) is not 2xx ⇒ no teardown.
        let req_terminated = "SIP/2.0 487 Request Terminated\r\nCSeq: 21 INVITE\r\nContent-Length: 0\r\n\r\n";
        assert!(!is_established_invite_2xx(req_terminated));
        // A provisional (or a missing CSeq) is not an established dialog either.
        assert!(!is_established_invite_2xx("SIP/2.0 100 Trying\r\nCSeq: 21 INVITE\r\n\r\n"));
        assert!(!is_established_invite_2xx("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"));
    }

    #[test]
    fn cancel_reuses_the_invite_branch_and_cseq_number() {
        let d = Dialog {
            aor: "c100x".into(),
            domain: "dev.example".into(),
            local_port: 5555,
            call_id: "abcd".into(),
            from_tag: "ft".into(),
            branch: "z9hG4bKinvitebranch".into(),
            cseq: 21,
            to_tag: String::new(), // not yet confirmed
            remote_target: String::new(),
        };
        let cancel = build_cancel(&d);
        assert!(cancel.starts_with("CANCEL sip:c100x@dev.example SIP/2.0\r\n"));
        // MUST match the INVITE it cancels: same branch, same CSeq number, method CANCEL.
        assert!(cancel.contains("branch=z9hG4bKinvitebranch\r\n"));
        assert!(cancel.contains("CSeq: 21 CANCEL\r\n"));
        // No To-tag (the transaction isn't confirmed) and no body.
        assert!(cancel.contains("To: <sip:c100x@dev.example>\r\n"));
        assert!(cancel.ends_with("Content-Length: 0\r\n\r\n"));
    }

    #[test]
    fn a_panel_bye_split_across_reads_is_framed_before_acting() {
        // Regression for the in-dialog framing fix (Codex/CodeRabbit): a BYE that arrives in two TCP
        // chunks must only be recognized once BOTH halves have accumulated. Mirrors the loop's logic:
        // accumulate, then act only on a message complete_message_len() confirms.
        let bye = "BYE sip:btmqttd@127.0.0.1:5060 SIP/2.0\r\n\
                   Via: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bKsplit\r\n\
                   From: <sip:app@d>;tag=ft\r\n\
                   To: <sip:c100x@d>;tag=tt\r\n\
                   Call-ID: cid\r\n\
                   CSeq: 9 BYE\r\n\
                   Content-Length: 0\r\n\r\n";
        let (head, tail) = bye.split_at(40); // split mid-headers
        let mut inbound = head.as_bytes().to_vec();
        // First chunk: not yet a complete message, so nothing is acted upon.
        assert_eq!(complete_message_len(&inbound), None);
        // Second chunk completes it: now it frames, and the framed message is the BYE.
        inbound.extend_from_slice(tail.as_bytes());
        let len = complete_message_len(&inbound).expect("now complete");
        let msg = String::from_utf8_lossy(&inbound[..len]).into_owned();
        assert!(is_bye(&msg));
        assert!(build_ok_to(&msg).is_some()); // the 200 OK we must send back is well-formed
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
