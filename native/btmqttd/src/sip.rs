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
/// CANCEL.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long we keep draining (framing responses, tearing down a racing 2xx) after sending CANCEL.
const CANCEL_DRAIN: Duration = Duration::from_secs(2);
/// Cap on a single SIP message we will buffer (offer/answer are ~2–3 KB; this bounds a hostile peer).
const MAX_SIP_BYTES: usize = 65536;
/// Reconnect backoff for the (rare) case the SIP socket / dialog fails.
const BACKOFF_INIT: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// Post-disconnect LINGER for the viewer-activity path (issue #120): how long the panel session is
/// held after the LAST viewer socket clears, when the session is driven by `hold.rs`'s auto-hold
/// (`ViewCmd::Hold`) rather than a manual `view_camera` press. `hold.rs` re-pokes `Hold` every poll
/// (~1 s) while a viewer holds an ESTABLISHED `:8554` socket, each poke renewing this short window; so
/// once the viewer disconnects the session hangs up ~`VIEWER_LINGER` later — not after the full
/// `camera_view_idle_secs` max window. A SHORT linger (not instant) is deliberate: it absorbs a brief
/// Home-Assistant reconnect (HA drops/re-opens the RTSP socket) without thrashing the SIP session up
/// and down, while still turning the panel off promptly once nobody is watching. It is DECOUPLED from
/// `camera_view_idle_secs` (which remains the manual-press / no-viewer-tracking max window) so shortening
/// the auto tail does not also shrink the manual window — and, because it is renewed by frequent pokes,
/// it never lapses between them (it only has to exceed `hold.rs`'s poll cadence). Must stay strictly
/// greater than that cadence (`hold::POLL_INTERVAL`).
pub const VIEWER_LINGER: Duration = Duration::from_secs(5);

/// Make-before-break refresh window (issue #174, Finding #3). The panel enforces a HARD ~60 s lifetime
/// on the on-demand camera dialog and then BYEs it — hardware-confirmed, and it is the PLANT's limit, not
/// ours: even BTicino's own app is cut at ~60 s, and the panel sends NO session-refresh re-INVITE/UPDATE
/// to accept (just a plain BYE). Left alone, a continuously-watched view freezes at that cut: the BYE
/// stops the RTP, `av.rs` sees the panel's `*7*0*##` teardown and releases the go2rtc siphon, and by the
/// time a fresh dialog re-establishes the media, go2rtc's producer has already timed out and dropped every
/// consumer. So while a viewer is still holding the session, we proactively stand up the NEXT dialog a few
/// seconds BEFORE the panel's BYE. IF the plant keeps its single shared media session up while the new
/// dialog holds it (multiudpsink is fan-out, and `av.rs` arms/releases the siphon off the BUS media
/// lifecycle, NOT per-dialog), the panel never emits `*7*0*##`, the siphon never lapses, and the view is
/// SEAMLESS. IF the plant refuses a second concurrent dialog (some installs are single-owner — a `486`
/// busy), the refresh is abandoned for this dialog and we fall back to the panel's BYE + `run()`'s
/// re-INVITE recycle: a brief blip, never a permanent freeze. Sized so the WHOLE attempt — start plus its
/// worst-case [`RESPONSE_TIMEOUT`] budget — completes with margin before [`PANEL_SESSION_LIMIT`], so even a
/// slow refresh finishes standing up the successor before the panel drops the old dialog (guarded by the
/// `const _: () = assert!(…)` timing invariant just below [`PANEL_SESSION_LIMIT`]).
const SESSION_REFRESH_AFTER: Duration = Duration::from_secs(45);

/// The panel's observed HARD lifetime on an on-demand camera dialog before it BYEs (issue #174,
/// Finding #3) — ~60 s on the C100X, and it binds every consumer (BTicino's own app included). Not a knob
/// we set; documented here only so the make-before-break timing invariant below is checked against the
/// real cutoff, not a bare constant.
const PANEL_SESSION_LIMIT: Duration = Duration::from_secs(60);

/// Compile-time invariant (issue #174, Finding #3): the make-before-break successor must be fully stood up
/// — its start (`SESSION_REFRESH_AFTER`) plus the WORST-CASE response budget (`RESPONSE_TIMEOUT`) — with a
/// few seconds of handover margin left BELOW the panel's hard cut, or a slow refresh could complete only
/// after the panel has already dropped the old dialog, defeating the whole point. A const assert is
/// stronger than a runtime test (it cannot be bypassed) and keeps `PANEL_SESSION_LIMIT` a live reference.
const _: () = assert!(
    SESSION_REFRESH_AFTER.as_secs() + RESPONSE_TIMEOUT.as_secs() + 3 <= PANEL_SESSION_LIMIT.as_secs(),
    "make-before-break refresh must complete with handover margin before the panel's session cut",
);

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
        // defeating the fail-closed guarantee that we never originate a ringing INVITE.
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
    // would stall the MQTT loop, the OWN monitor and the camera siphon for its duration.
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
    // blank, keeping the fail-closed gate intact.
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

/// The mutable per-call state we carry from the INVITE through ACK/BYE. `Clone` so a teardown over a
/// FRESH connection (when the original signalling socket died mid-dialog) can reuse the dialog
/// identity while swapping in the new local port.
#[derive(Clone)]
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

/// ACK a NON-2xx final response to the INVITE (RFC 3261 §17.1.1.3). Unlike the 2xx ACK (a new
/// transaction to the panel's Contact), this ACK is part of the INVITE CLIENT transaction: same
/// Request-URI as the INVITE (`sip:<aor>@<domain>`), the SAME top `Via` branch and CSeq NUMBER, plus
/// the failure response's `To`-tag. It absorbs the transaction so the proxy/panel don't hold the
/// server transaction until Timer H after a reject (486/401/407/…).
pub fn build_ack_failure(d: &Dialog, to_tag: &str) -> String {
    format!(
        "ACK sip:{aor}@{domain} SIP/2.0\r\n\
         Via: SIP/2.0/TCP 127.0.0.1:{lport};rport;branch={branch}\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:btmqttd@{domain}>;tag={ftag}\r\n\
         To: <sip:{aor}@{domain}>;tag={ttag}\r\n\
         Call-ID: {callid}\r\n\
         CSeq: {cseq} ACK\r\n\
         Content-Length: 0\r\n\
         \r\n",
        aor = d.aor,
        domain = d.domain,
        lport = d.local_port,
        branch = d.branch,
        ftag = d.from_tag,
        ttag = to_tag,
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

/// The SIP method of a REQUEST message — the first token of a request-line like
/// `OPTIONS sip:… SIP/2.0`. `None` if `msg` is a RESPONSE (status-line starting `SIP/2.0`) or has no
/// recognizable request-line. Used in the established-dialog hold loop to answer in-dialog requests
/// (OPTIONS/re-INVITE/…) so the panel's transaction completes instead of timing out.
fn request_method(msg: &str) -> Option<&str> {
    let line = msg.lines().next()?;
    if line.starts_with("SIP/2.0") {
        return None; // a response, not a request
    }
    // request-line = METHOD SP Request-URI SP SIP-Version; require the trailing SIP-Version so a
    // stray/garbled line isn't mistaken for a request.
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    let has_version = line.split_whitespace().next_back().is_some_and(|v| v.starts_with("SIP/2.0"));
    (has_version && !method.is_empty()).then_some(method)
}

/// True when `msg`'s `CSeq` method is `INVITE` (case-insensitive) — i.e. the response belongs to the
/// INVITE transaction, not to a `CANCEL`/`BYE`/`OPTIONS` we may also have in flight.
fn cseq_is_invite(msg: &str) -> bool {
    header_value(msg, "CSeq")
        .and_then(|c| c.split_whitespace().nth(1))
        .is_some_and(|m| m.eq_ignore_ascii_case("INVITE"))
}

/// True when `msg` is a 2xx response to the INVITE transaction itself — i.e. an ESTABLISHED dialog
/// we must ACK then BYE. Distinguished from the `200 OK` to our CANCEL (also 2xx, but `CSeq: N
/// CANCEL`), which establishes nothing and must NOT trigger a teardown.
pub fn is_established_invite_2xx(msg: &str) -> bool {
    matches!(parse_status(msg), Some(s) if (200..300).contains(&s)) && cseq_is_invite(msg)
}

/// A bodyless response to an in-dialog request, echoing the headers the transaction needs: every
/// `Via` (in order), plus `From`/`To`/`Call-ID`/`CSeq`. `status_line` is the full first line, e.g.
/// `"SIP/2.0 200 OK"` or `"SIP/2.0 488 Not Acceptable Here"`. `None` if a required header is absent
/// (then we simply let the peer's retransmits lapse). In-dialog the request's `To` already carries
/// OUR local tag, so echoing it verbatim keeps the dialog identity correct.
pub fn build_response_to(request: &str, status_line: &str) -> Option<String> {
    let mut out = String::with_capacity(status_line.len() + 160);
    out.push_str(status_line);
    out.push_str("\r\n");
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

/// A `200 OK` to an in-dialog request (the panel's BYE / OPTIONS), echoing the transaction headers.
/// `None` if a required header is absent. Sent so the panel doesn't retransmit its request.
pub fn build_ok_to(request: &str) -> Option<String> {
    build_response_to(request, "SIP/2.0 200 OK")
}

/// The final response to answer an in-dialog request the panel sends mid-session, or `None` if `msg`
/// is not a request (a response) or a required transaction header is missing. We never renegotiate
/// media: a re-INVITE or UPDATE (offer/answer refresh methods) is rejected with `488 Not Acceptable
/// Here`, which completes the transaction while leaving the existing session unchanged (RFC 3261
/// §14.2 / RFC 3311) — a bare `200 OK` would be a 2xx to an offer with no SDP answer, worse than a
/// clean refusal. Every other in-dialog request (OPTIONS keepalive, INFO, NOTIFY, …) gets `200 OK`.
fn in_dialog_answer(msg: &str) -> Option<String> {
    let method = request_method(msg)?;
    if method.eq_ignore_ascii_case("INVITE") || method.eq_ignore_ascii_case("UPDATE") {
        build_response_to(msg, "SIP/2.0 488 Not Acceptable Here")
    } else {
        build_ok_to(msg)
    }
}

// ---- randomness for SIP tokens + the throwaway SRTP key --------------------------------------

/// Fill `buf` with OS entropy. Prefers the non-blocking `getrandom(2)` syscall over reading
/// `/dev/urandom`: btmqttd runs on a single-threaded Tokio runtime, so a blocking file open+read on
/// this (synchronous) path would stall the MQTT loop / OWN monitor / AV siphon for its duration. Falls
/// back to `/dev/urandom`, then a time-seeded xorshift — SIP tags/branches need uniqueness, not
/// secrecy, and the SRTP key is blackholed, so a degraded source is acceptable.
fn fill_random(buf: &mut [u8]) {
    // GRND_NONBLOCK: never wait on the entropy pool — return EAGAIN instead and let us fall back.
    // Safe: writes exactly `buf.len()` bytes into `buf`; we only trust a full-length success.
    let n = unsafe {
        libc::getrandom(buf.as_mut_ptr() as *mut libc::c_void, buf.len(), libc::GRND_NONBLOCK)
    };
    if n >= 0 && n as usize == buf.len() {
        return;
    }
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

/// A command on the trigger channel.
///   * `Start` = the HA "View Camera" button (a MANUAL press): bring the session up and renew the FULL
///     `camera_view_idle_secs` window — a single press holds the panel for that whole window.
///   * `Hold(expiry)` = the viewer-activity auto-hold (`hold.rs`): bring the session up and renew only
///     the short [`VIEWER_LINGER`] window. `hold.rs` re-pokes this every poll while a viewer holds an
///     ESTABLISHED `:8554` socket, so the panel follows the live viewer and hangs up ~`VIEWER_LINGER`
///     after the last one disconnects — WITHOUT shortening a concurrent manual `Start` window (the two
///     deadlines are tracked independently and the LATER governs hang-up; see `session`). The payload is
///     the poke's ABSOLUTE expiry (`poke instant + VIEWER_LINGER`): a `Hold` that queues while `run` is
///     in reconnect backoff and is only consumed after the viewer has already disconnected is STALE, so
///     the consumer drops it once `expiry` has passed rather than reviving or extending a viewerless
///     session, and derives `hold_deadline` from `expiry` (poke time) rather than receipt time.
///     `tokio::time::Instant` (not `std`) so it's the same clock the SIP hold loop sleeps on.
///   * `Stop` = the HA "Stop Camera" button (end the on-demand view now instead of waiting for a window
///     to elapse). A `Stop` received while no session is up is a harmless no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewCmd {
    Start,
    Hold(tokio::time::Instant),
    Stop,
}

/// Run the on-demand SIP UA. Waits for a `Start`/`Hold` on `view_rx`; each brings the panel session up
/// (if not already up) and renews the relevant viewing-window deadline (`Start` = the full
/// `camera_view_idle_secs` window, `Hold` = the short [`VIEWER_LINGER`]). After both deadlines elapse
/// with no further request — or on an explicit `Stop` — the dialog is torn down (BYE) so the panel is
/// never left pinned. Returns when `stopping` is observed (draining the active dialog first).
pub async fn run(cfg: Arc<Config>, stopping: Arc<AtomicBool>, mut view_rx: mpsc::Receiver<ViewCmd>) {
    let mut backoff = BACKOFF_INIT;
    while !stopping.load(Ordering::Relaxed) {
        // Idle until a Start or a still-FRESH Hold is requested (channel closed ⇒ shutting down). A Stop
        // while idle has nothing to stop — ignore it. A `Hold` whose absolute `expiry` has already passed
        // is STALE — it queued while a prior session was in reconnect backoff and the viewer has since
        // disconnected — so DISCARD it and keep waiting rather than reopening a viewerless session; a
        // still-present viewer re-pokes a fresh `Hold` within one poll interval. The
        // triggering command is threaded into `session` so it seeds the matching initial deadline (a
        // manual `Start` ⇒ the full window; a fresh auto `Hold` ⇒ its short-linger expiry).
        let trigger = loop {
            match view_rx.recv().await {
                None => return,
                Some(ViewCmd::Stop) => continue,
                Some(ViewCmd::Hold(expiry)) if expiry <= tokio::time::Instant::now() => continue,
                Some(cmd) => break cmd, // Start, or a Hold that has not yet expired
            }
        };
        if stopping.load(Ordering::Relaxed) {
            return;
        }
        match session(&cfg, &stopping, &mut view_rx, trigger).await {
            Ok(()) => backoff = BACKOFF_INIT,
            Err(e) => {
                eprintln!("btmqttd: on-demand SIP session failed: {e}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}

/// Seed the two per-session viewing-window deadlines from what the session-open requested. `want_start`
/// (a manual `view_camera` press) arms the full `window` from `now`. `hold_expiry` is the ABSOLUTE expiry
/// of the auto-hold `Hold` that opened (or arrived while establishing) the session, if any; it arms the
/// short-linger deadline directly at that instant — but is DROPPED if it has already elapsed by `now`
/// (session-up), so a `Hold` that queued during a reconnect backoff and outlived the viewer can't seed a
/// linger on a viewerless session. A regime nobody requested is seeded to `now`
/// (already elapsed) so [`governing_deadline`]'s `max` ignores it. Pure, so the seed rule is unit-testable.
fn seed_deadlines(
    want_start: bool,
    hold_expiry: Option<tokio::time::Instant>,
    now: tokio::time::Instant,
    window: Duration,
) -> (tokio::time::Instant, tokio::time::Instant) {
    (
        if want_start { now + window } else { now },
        hold_expiry.filter(|e| *e > now).unwrap_or(now),
    )
}

/// The deadline that governs hang-up: the LATER of the manual-window and short-linger deadlines. So a
/// manual `Start` window is a FLOOR the auto linger can never cut below (`hold_deadline` being sooner
/// changes nothing) — while a viewer stays connected, auto-hold's `Hold` pokes keep `hold_deadline`
/// ahead and the session deliberately FOLLOWS the live viewer past `camera_view_idle_secs` (issue #120,
/// exactly as the previous `Start`-poke auto-hold did), hanging up ~`VIEWER_LINGER` after the viewer
/// disconnects (or at the manual floor, whichever is later). It is NOT a hard cap on an actively-watched
/// session — capping mid-view would tear the feed down and force HA to reconnect on a fixed cycle. Pure.
fn governing_deadline(
    start_deadline: tokio::time::Instant,
    hold_deadline: tokio::time::Instant,
) -> tokio::time::Instant {
    start_deadline.max(hold_deadline)
}

/// Outcome of a make-before-break refresh attempt ([`establish_refresh_dialog`]).
enum RefreshOutcome {
    /// The panel admitted a concurrent dialog: the confirmed successor `(socket, Dialog)`.
    Established(TcpStream, Dialog),
    /// The panel refused (e.g. `486 Busy` on a single-owner plant) or the attempt errored. The pending
    /// INVITE was CANCELled / the non-2xx ACKed, so nothing dangles; the caller keeps its current dialog
    /// and falls back to the panel's recycle.
    Declined(std::io::Error),
    /// Shutdown (`stopping`) or a `Stop`/closed channel was observed mid-attempt. The pending INVITE was
    /// CANCELled (over TCP a dropped socket does NOT cancel it, so a late 2xx could otherwise pin the
    /// panel), so nothing dangles; the caller tears the CURRENT dialog down (a Stop means the viewer wants
    /// the camera off; a shutdown means we are going away).
    Aborted,
}

/// Make-before-break (issue #174, Finding #3): stand up a FRESH on-demand dialog (INVITE → 2xx → ACK)
/// while an existing one is still up, so the panel's single shared media session stays alive across its
/// hard ~60 s BYE and `av.rs`'s RTP siphon to go2rtc never lapses (see [`SESSION_REFRESH_AFTER`]). It
/// reuses the live dialog's identity (`aor`/`domain`/`devaddr`) but mints a NEW Call-ID/tags/branch and a
/// throwaway SRTP key, so the panel sees a distinct dialog it can admit alongside the current one.
///
/// INTERRUPTIBLE, and that matters: the response wait races `stopping` and `view_rx` — exactly like
/// `session`'s own establish — so a daemon shutdown (main.rs bounds shutdown to a few seconds) or a
/// `Stop`/"Stop Camera" press aborts PROMPTLY instead of blocking up to `RESPONSE_TIMEOUT + CANCEL_DRAIN`.
/// Every exit that is not a clean 2xx — refusal, error, timeout, or abort — first runs the cancellation
/// routine (CANCEL a pending INVITE / ACK a non-2xx), because over TCP a dropped socket does NOT cancel an
/// INVITE and a late 2xx would otherwise pin the panel. `Start`/`Hold` that arrive mid-attempt are ignored
/// (the caller's live dialog still owns the viewing-window deadlines, and it renews the linger on adopt).
async fn establish_refresh_dialog(
    cfg: &Arc<Config>,
    stopping: &Arc<AtomicBool>,
    view_rx: &mut mpsc::Receiver<ViewCmd>,
    aor: &str,
    domain: &str,
    devaddr: &str,
) -> RefreshOutcome {
    let mut sock = match TcpStream::connect(("127.0.0.1", cfg.sip_port)).await {
        Ok(s) => s,
        Err(e) => return RefreshOutcome::Declined(e),
    };
    let local_port = match sock.local_addr() {
        Ok(a) => a.port(),
        Err(e) => return RefreshOutcome::Declined(e),
    };
    let mut d = Dialog {
        aor: aor.to_string(),
        domain: domain.to_string(),
        local_port,
        call_id: rand_hex(8),
        from_tag: rand_hex(6),
        branch: format!("z9hG4bK{}", rand_hex(8)),
        cseq: 21,
        to_tag: String::new(),
        remote_target: String::new(),
    };
    let sdp = build_sdp_offer(cfg.camera_video_port, cfg.camera_audio_port, &srtp_key(), devaddr);
    let invite = build_invite(&d, &sdp);
    if let Err(e) = write_all_flush(&mut sock, invite.as_bytes()).await {
        return RefreshOutcome::Declined(e);
    }

    // Bounded, INTERRUPTIBLE wait for the final response. Every non-2xx / error / abort routes through
    // cancel_pending_invite (CANCEL + drain + ACK/BYE a racing 2xx) so the panel is never left pinned by
    // an uncancelled INVITE. The accumulator is owned here so a timeout mid-2xx carries its partial bytes
    // into that drain. Mirrors `session`'s open select.
    let mut acc: Vec<u8> = Vec::new();
    let resp_deadline = tokio::time::Instant::now() + RESPONSE_TIMEOUT;
    let final_resp = loop {
        tokio::select! {
            biased;
            _ = wait_until_stopping(stopping) => {
                let seed = std::mem::take(&mut acc);
                cancel_pending_invite(&mut sock, cfg, &mut d, seed).await;
                return RefreshOutcome::Aborted; // shutdown: INVITE cancelled, caller BYEs the live dialog
            }
            v = view_rx.recv() => match v {
                // Start/Hold mid-refresh: the caller's live dialog still owns the deadlines (and renews the
                // linger on adopt), so ignore and keep waiting rather than swallow-and-act on them here.
                Some(ViewCmd::Start) | Some(ViewCmd::Hold(_)) => continue,
                Some(ViewCmd::Stop) | None => {
                    let seed = std::mem::take(&mut acc);
                    cancel_pending_invite(&mut sock, cfg, &mut d, seed).await;
                    return RefreshOutcome::Aborted; // Stop/closed: INVITE cancelled, caller hangs up
                }
            },
            res = tokio::time::timeout_at(resp_deadline, wait_final_response(&mut sock, &mut acc)) => {
                match res {
                    Ok(Ok(resp)) => break resp,
                    other => {
                        let seed = std::mem::take(&mut acc);
                        cancel_pending_invite(&mut sock, cfg, &mut d, seed).await;
                        return RefreshOutcome::Declined(match other {
                            Err(_) => std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "refresh INVITE timed out (CANCEL sent)",
                            ),
                            Ok(Err(e)) => e,
                            Ok(Ok(_)) => unreachable!("handled by the break arm above"),
                        });
                    }
                }
            }
        }
    };

    let Some(status) = parse_status(&final_resp) else {
        return RefreshOutcome::Declined(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no SIP status line",
        ));
    };
    if !(200..300).contains(&status) {
        // ACK the non-2xx (486 Busy / other) so flexisip doesn't hold the INVITE server transaction to
        // Timer H, then surface the status so the caller keeps the current dialog and falls back. A refresh
        // rejection is EXPECTED on single-owner plants and is non-fatal — the caller only logs it.
        if let Some(tag) = to_tag(&final_resp) {
            let _ = write_all_flush(&mut sock, build_ack_failure(&d, &tag).as_bytes()).await;
        }
        return RefreshOutcome::Declined(std::io::Error::other(format!(
            "refresh INVITE rejected with {status}"
        )));
    }

    let Some(tag) = to_tag(&final_resp) else {
        return RefreshOutcome::Declined(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "2xx to refresh INVITE has no To-tag — cannot form a confirmed dialog for ACK/BYE",
        ));
    };
    d.to_tag = tag;
    d.remote_target =
        contact_uri(&final_resp).unwrap_or_else(|| format!("sip:{}@{}", d.aor, d.domain));
    let ack = build_ack(&d, &format!("z9hG4bK{}", rand_hex(8)));
    if let Err(e) = write_all_flush(&mut sock, ack.as_bytes()).await {
        // The panel accepted (2xx) but our ACK couldn't be written — the dialog may be live at the panel,
        // so BYE it over a FRESH connection rather than leaving it streaming, and decline so the caller
        // keeps its current dialog. Same last-resort reasoning as `session`'s post-2xx ACK failure.
        bye_reconnect(cfg, &d).await;
        return RefreshOutcome::Declined(e);
    }
    RefreshOutcome::Established(sock, d)
}

/// One on-demand session: INVITE → ACK, hold while views keep arriving, then BYE. `initial` is the
/// command that opened the session (`Start` or `Hold`); it — together with any command that arrives
/// while the INVITE establishes — seeds the matching deadline(s). While the session is up, every extra
/// `Start` renews the full-window deadline and every extra `Hold` renews the short-linger deadline (see
/// the hold loop below).
async fn session(
    cfg: &Arc<Config>,
    stopping: &Arc<AtomicBool>,
    view_rx: &mut mpsc::Receiver<ViewCmd>,
    initial: ViewCmd,
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
    // ONCE THE INVITE IS ON THE WIRE, EVERY exit other than a clean final response must run the
    // cancellation routine — over TCP, dropping the socket does NOT cancel the INVITE, so a late 200
    // could otherwise pin the panel. The wait is a select over four events:
    //   * a clean final response (the only path that continues to ACK the dialog),
    //   * the outer RESPONSE_TIMEOUT deadline, or a reader error from wait_final_response,
    //   * daemon shutdown (run() can't interrupt an in-flight session; main.rs bounds shutdown), and
    //   * a `Stop` on view_rx — pressing "Stop Camera" WHILE the INVITE is still pending must abort the
    //     start PROMPTLY, not sit queued up to RESPONSE_TIMEOUT while the panel establishes.
    //     A `Start`/`Hold` in this window doesn't re-send anything (the INVITE already
    //     serves the "bring it up" intent) but it IS recorded (`want_start` / the latest `hold_expiry`)
    //     so the post-ACK deadlines honor it: a manual `Start` that arrives while a `Hold`-opened session
    //     is still establishing must still seed the FULL window, not just the auto linger.
    // The timeout is an ABSOLUTE deadline (timeout_at) so a `Start` poke doesn't restart the 10 s
    // budget each loop turn. All non-success exits route through cancel_pending_invite (CANCEL + drain
    // + ACK/BYE a racing 2xx); the accumulator is owned HERE so a timeout mid-2xx carries its partial
    // bytes into that drain.
    //
    // Which window(s) to arm once the dialog is up, seeded by the command that OPENED the session and
    // updated by any that arrive while it establishes: `want_start` = a manual `view_camera` full window;
    // `hold_expiry` = the latest auto-hold `Hold` expiry seen (its short linger). We keep the LATEST
    // expiry so a `Hold` that lands during establishment carries the freshest linger to the seed.
    let mut want_start = matches!(initial, ViewCmd::Start);
    let mut hold_expiry: Option<tokio::time::Instant> =
        if let ViewCmd::Hold(e) = initial { Some(e) } else { None };
    let mut acc: Vec<u8> = Vec::new();
    let resp_deadline = tokio::time::Instant::now() + RESPONSE_TIMEOUT;
    let final_resp = loop {
        tokio::select! {
            biased;
            _ = wait_until_stopping(stopping) => {
                let seed = std::mem::take(&mut acc);
                cancel_pending_invite(&mut sock, cfg, &mut d, seed).await;
                return Ok(()); // shutdown: dialog cancelled, nothing left pinned
            }
            v = view_rx.recv() => match v {
                // A Start/Hold while still establishing — the INVITE already serves the "bring it up"
                // intent, so keep waiting, but record it so the post-ACK deadlines honor it. Keep the
                // LATEST Hold expiry seen; `seed_deadlines` drops it if it has elapsed by session-up.
                Some(ViewCmd::Start) => { want_start = true; continue; }
                Some(ViewCmd::Hold(e)) => {
                    hold_expiry = Some(hold_expiry.map_or(e, |cur| cur.max(e)));
                    continue;
                }
                Some(ViewCmd::Stop) | None => {    // user aborted the start (or the channel closed)
                    let seed = std::mem::take(&mut acc);
                    cancel_pending_invite(&mut sock, cfg, &mut d, seed).await;
                    return Ok(());
                }
            },
            res = tokio::time::timeout_at(resp_deadline, wait_final_response(&mut sock, &mut acc)) => {
                match res {
                    Ok(Ok(resp)) => break resp, // a clean final response — continue below
                    other => {
                        let seed = std::mem::take(&mut acc);
                        cancel_pending_invite(&mut sock, cfg, &mut d, seed).await;
                        return match other {
                            Err(_) => Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "INVITE response timed out (CANCEL sent)",
                            )),
                            Ok(Err(e)) => Err(e), // reader error; cancelled best-effort
                            Ok(Ok(_)) => unreachable!("handled by the break arm above"),
                        };
                    }
                }
            }
        }
    };

    let status = parse_status(&final_resp)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "no SIP status line"))?;
    if !(200..300).contains(&status) {
        // ACK any NON-2xx final (486 Busy, 401/407, other rejects) — RFC 3261 §17.1.1.3. The ACK is
        // part of the INVITE client transaction: same Request-URI, top Via branch and CSeq number,
        // plus the response's To-tag. Without it flexisip holds the INVITE server transaction until
        // Timer H, so repeated busy/failed views would pile up stale transactions. Best-effort.
        if let Some(tag) = to_tag(&final_resp) {
            let _ = write_all_flush(&mut sock, build_ack_failure(&d, &tag).as_bytes()).await;
        }
        if status == 401 || status == 407 {
            // flexisip challenged our loopback INVITE — trusted-hosts should prevent this. If it ever
            // happens we need a registered identity + digest; surface it clearly for the hardware pass.
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "SIP auth required (flexisip did not trust the loopback UA) — needs a registered identity",
            ));
        }
        return Err(std::io::Error::other(format!("INVITE rejected with {status}")));
    }

    // A 2xx to INVITE MUST carry a To-tag — it's what makes the dialog "confirmed" and is echoed in
    // the ACK and BYE. Without it the teardown is unreliable, so fail rather than send an ACK/BYE with
    // an empty tag. The Contact is the panel's in-dialog request target for ACK/BYE; a 2xx
    // should include one, but fall back to the AOR (still routable via the proxy) if a peer omits it.
    d.to_tag = to_tag(&final_resp).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "2xx to INVITE has no To-tag — cannot form a confirmed dialog for ACK/BYE",
        )
    })?;
    d.remote_target = contact_uri(&final_resp)
        .unwrap_or_else(|| format!("sip:{}@{}", d.aor, d.domain));

    // Confirm the dialog. If the ACK can't be written/flushed, the signalling socket died AFTER the
    // panel accepted our INVITE (2xx) — the dialog may be active, so tear it down over a FRESH
    // connection rather than leaving the panel streaming. This is the last confirmed-
    // dialog exit; together with the hold-loop's EOF/read-error/cap arms, no post-2xx path can strand
    // the panel.
    let ack = build_ack(&d, &format!("z9hG4bK{}", rand_hex(8)));
    if let Err(e) = write_all_flush(&mut sock, ack.as_bytes()).await {
        bye_reconnect(cfg, &d).await;
        return Err(e);
    }
    eprintln!("btmqttd: on-demand session up (sip:{}@{})", d.aor, d.domain);

    // Hold the session until BOTH viewing-window deadlines elapse; the LATER one governs hang-up. There
    // are two independent renewal regimes, tracked separately so shortening one never shortens the other:
    //   * `start_deadline` — the FULL `camera_view_idle_secs` window, renewed by a manual `view_camera`
    //     press (`ViewCmd::Start`). It is a per-press cap, NOT an inactivity timeout: a single press
    //     bounds the session to one window and it auto-hangs-up when the window elapses.
    //   * `hold_deadline` — the short [`VIEWER_LINGER`], renewed by the viewer-activity auto-hold
    //     (`ViewCmd::Hold`, from hold.rs) every poll while a viewer holds an ESTABLISHED :8554 socket. So
    //     an auto-opened view follows the live viewer and hangs up ~VIEWER_LINGER after the last one
    //     disconnects, rather than lingering for the whole (much longer) manual window.
    // Seed each from what was requested by session-open (`want_start` / `hold_expiry`, above): the
    // deadline for a regime nobody asked for starts already-elapsed at `now0`, so `governing_deadline`'s
    // `max` ignores it. An auto `Hold` open lingers ~VIEWER_LINGER; a manual `Start` open gets the full
    // window; a session that saw BOTH gets both. Neither deadline is renewed by socket traffic or the
    // in-dialog chatter the panel sends (OPTIONS/re-INVITE/media stats) — only by an explicit `view_rx`
    // command — or that chatter would keep resetting the timer and pin the session open forever.
    let window = Duration::from_secs(cfg.camera_view_idle_secs);
    let now0 = tokio::time::Instant::now();
    let (mut start_deadline, mut hold_deadline) =
        seed_deadlines(want_start, hold_expiry, now0, window);
    let mut scratch = [0u8; 4096];
    // FRAME in-dialog requests the same way `wait_final_response` frames responses: TCP can split a
    // panel BYE across reads, or coalesce it after other in-dialog traffic, so inspecting one raw
    // read chunk could miss the `BYE ` prefix (⇒ no 200 OK, the panel retransmits) or see the prefix
    // before its headers are complete (⇒ `build_ok_to` returns None yet we'd mark the dialog ended).
    // Accumulate, then act only on COMPLETE messages.
    let mut inbound: Vec<u8> = Vec::new();
    let mut panel_ended = false; // the panel tore the dialog down first ⇒ don't send our own BYE
    let mut transport_lost = false; // the signalling socket died ⇒ BYE over a fresh connection
    // Make-before-break refresh state (issue #174, Finding #3). `refresh_at` (absolute) is when we try to
    // stand up the successor dialog — SESSION_REFRESH_AFTER into this one, before the panel's hard ~60 s
    // BYE — so its shared media never tears down and av.rs's siphon to go2rtc never lapses. On a successful
    // refresh it is pushed out past the new dialog; `refresh_disabled` latches after a refusal (a
    // single-owner plant `486`) so we stop hammering and simply ride this dialog to the panel's BYE +
    // run()'s recycle.
    let mut refresh_at = now0 + SESSION_REFRESH_AFTER;
    let mut refresh_disabled = false;
    'dialog: loop {
        if stopping.load(Ordering::Relaxed) {
            break;
        }
        // Make-before-break, done as a PRE-select step (not a select arm) so the attempt can watch
        // `view_rx` + `stopping` internally without a second mutable borrow of `view_rx` colliding with the
        // `view_rx.recv()` arm below. It fires only once the dialog is old enough AND an AUTO-HOLD is still
        // live (`hold_deadline` ahead of now — a viewer is genuinely watching). Deliberately gated on
        // `hold_deadline`, NOT the governing deadline: a manual `view_camera` press with a long
        // `camera_view_idle_secs` must NOT trigger a viewerless refresh (it would also let the linger renew
        // on adopt push the session a few seconds past that manual window). A manual-only view keeps its
        // existing behavior — the panel's ~60 s cut bounds it, exactly as before this feature. While a
        // viewer holds, hold.rs re-pokes every ~1 s so this loop iterates well inside SESSION_REFRESH_AFTER
        // and the attempt fires within ~1 s of it.
        let now = tokio::time::Instant::now();
        if !refresh_disabled && now >= refresh_at && hold_deadline > now {
            match establish_refresh_dialog(cfg, stopping, view_rx, &d.aor, &d.domain, &devaddr).await {
                RefreshOutcome::Established(new_sock, new_d) => {
                    // The panel ADMITTED a concurrent dialog. BYE the old one on its own socket
                    // (best-effort) and adopt the new. When the plant shares its single media session
                    // across the two — the seamless case, and the likely one since it just accepted a
                    // second dialog — av.rs never sees the panel's `*7*0*##` teardown, so the RTP siphon to
                    // go2rtc holds and the view never blips. (If a plant instead tore media on this BYE it
                    // would surface as an av.rs siphon released/armed pair around the refresh — a brief
                    // blip, still far better than the ~60 s freeze; the recycle fallback covers it.)
                    eprintln!(
                        "btmqttd: on-demand session refreshed before the panel cut (make-before-break)"
                    );
                    let _ = teardown_bye(&mut sock, &d).await;
                    sock = new_sock;
                    d = new_d;
                    inbound.clear(); // fresh socket ⇒ discard any partial framing from the old leg
                    let now = tokio::time::Instant::now();
                    // Establishing the successor may have parked this loop briefly (bounded, interruptible),
                    // during which auto-hold `Hold` pokes went unread. The refresh only fires with a viewer
                    // actively holding, so renew the linger here (equivalent to a poke at refresh time) so a
                    // stale deadline can't spuriously hang the freshly-adopted dialog up before the next poke
                    // arrives. A longer manual window, if any, still governs via `start_deadline`.
                    hold_deadline = hold_deadline.max(now + VIEWER_LINGER);
                    refresh_at = now + SESSION_REFRESH_AFTER;
                    continue; // re-evaluate with the adopted dialog
                }
                RefreshOutcome::Declined(e) => {
                    // Refused (a single-owner plant's `486 Busy`) or errored: keep THIS dialog untouched,
                    // stop retrying, and let the panel's ~60 s BYE + run()'s re-INVITE recycle take over (a
                    // brief blip, never a permanent freeze). The refusal itself is the hardware probe.
                    eprintln!(
                        "btmqttd: on-demand session refresh declined ({e}) — falling back to the panel recycle"
                    );
                    refresh_disabled = true;
                }
                RefreshOutcome::Aborted => break, // Stop or shutdown mid-refresh (INVITE already cancelled)
            }
        }
        // Hang up once BOTH windows have elapsed: the later deadline governs (see the seeding above).
        let deadline = governing_deadline(start_deadline, hold_deadline);
        tokio::select! {
            v = view_rx.recv() => match v {
                // A manual View press = a fresh FULL window; an auto-hold poke = a fresh short LINGER.
                // Each renews only its own deadline (the other is untouched) so neither can shorten the
                // other; there is no viewer heartbeat beyond these explicit commands. A `Hold` renews
                // hold_deadline from its ABSOLUTE `expiry` (poke time + linger), not receipt time, and a
                // poke that is ALREADY expired on arrival (a straggler buffered during a stall while the
                // viewer left) is ignored — so buffered holds can neither extend nor revive a viewerless
                // session past ~VIEWER_LINGER after the last live poke. `max` keeps
                // the deadline monotonic against any out-of-order or already-surpassed expiry.
                Some(ViewCmd::Start) => start_deadline = tokio::time::Instant::now() + window,
                Some(ViewCmd::Hold(expiry)) => {
                    if expiry > tokio::time::Instant::now() {
                        hold_deadline = hold_deadline.max(expiry);
                    }
                }
                Some(ViewCmd::Stop) => break,  // user pressed "Stop Camera" ⇒ hang up now (our BYE)
                None => break,                 // shutting down
            },
            r = sock.read(&mut scratch) => match r {
                // TCP EOF is NOT a panel BYE — flexisip may have closed/restarted our loopback leg
                // while the SIP dialog is still up. Treat it as transport loss and BYE over a fresh
                // connection below, so the panel isn't left streaming until its own timeout.
                Ok(0) => { transport_lost = true; break; }
                Ok(n) => {
                    inbound.extend_from_slice(&scratch[..n]);
                    if inbound.len() > MAX_SIP_BYTES {
                        // The dialog is CONFIRMED here (we ACKed a 2xx), so CANCEL is invalid — a
                        // best-effort BYE is what releases the panel. Returning without it would skip
                        // the teardown below and leave the camera session up until the panel's own
                        // timeout. If the BYE write fails the socket is dead ⇒ reconnect.
                        if teardown_bye(&mut sock, &d).await.is_err() {
                            bye_reconnect(cfg, &d).await;
                        }
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "in-dialog SIP request exceeded cap",
                        ));
                    }
                    // Drain every complete message now buffered. A panel-initiated BYE ends the
                    // dialog: acknowledge it (200 OK, else the panel retransmits) and stop — we must
                    // NOT then send our own BYE to a dead dialog. Every OTHER in-dialog request gets a
                    // final response so the panel's transaction completes instead of timing out, but
                    // NONE of them renews the viewing-window deadline (only a real viewer poke does).
                    while let Some(len) = complete_message_len(&inbound) {
                        let msg = String::from_utf8_lossy(&inbound[..len]).into_owned();
                        inbound.drain(..len);
                        if is_bye(&msg) {
                            if let Some(ok) = build_ok_to(&msg) {
                                let _ = sock.write_all(ok.as_bytes()).await;
                                let _ = sock.flush().await;
                            }
                            panel_ended = true;
                            break 'dialog;
                        }
                        // A RETRANSMITTED INVITE 2xx (our first ACK was lost between flexisip and the
                        // panel) must be re-ACKed — a UAC ACKs every 2xx or the panel times out the
                        // confirmed dialog and the camera stops. Best-effort; a dead socket surfaces on
                        // the next read as EOF/error and routes through bye_reconnect.
                        if is_established_invite_2xx(&msg) {
                            let ack = build_ack(&d, &format!("z9hG4bK{}", rand_hex(8)));
                            let _ = write_all_flush(&mut sock, ack.as_bytes()).await;
                            continue;
                        }
                        // Answer in-dialog REQUESTS the panel sends mid-session. Leaving them
                        // unanswered lets the peer transaction time out — and a session-refresh
                        // re-INVITE that times out can make the panel tear down the camera dialog
                        // BEFORE our window deadline. `in_dialog_answer` picks the response
                        // (OPTIONS/other → 200 OK; re-INVITE/UPDATE → 488, no media renegotiation).
                        // A write failure here (BrokenPipe/ConnectionReset) proves the confirmed
                        // dialog's signalling socket is dead — do NOT discard it and wait for the next
                        // read / user command / window deadline, which would leave the panel streaming
                        // meanwhile. Tear down over a FRESH connection and surface the error for the
                        // session-backoff path, exactly like the read-error arm below.
                        if let Some(resp) = in_dialog_answer(&msg) {
                            if let Err(e) = write_all_flush(&mut sock, resp.as_bytes()).await {
                                bye_reconnect(cfg, &d).await;
                                return Err(e);
                            }
                        }
                    }
                }
                // A socket error on a CONFIRMED dialog (ConnectionReset / BrokenPipe / …) means the
                // signalling connection is gone — BYEing THIS dead socket would silently fail and leave
                // the panel streaming, so tear the dialog down over a FRESH connection (like the Ok(0)
                // EOF case) before propagating the error for backoff.
                Err(e) => {
                    bye_reconnect(cfg, &d).await;
                    return Err(e);
                }
            },
            _ = tokio::time::sleep_until(deadline) => break, // viewing-window expiry ⇒ hang up
        }
    }

    // Teardown. Three cases:
    //  * panel_ended — the panel already BYE'd (we ACKed it); sending our own BYE would hit a dead
    //    dialog, so do nothing.
    //  * transport_lost — our signalling socket died; the dialog may still be up at flexisip/panel,
    //    so BYE over a FRESH loopback connection (the dialog is keyed by Call-ID/tags, not the TCP
    //    connection) rather than writing into the dead socket.
    //  * otherwise — normal window-expiry/shutdown hang-up on the live socket.
    if panel_ended {
        // nothing to send
    } else if transport_lost {
        bye_reconnect(cfg, &d).await;
    } else if teardown_bye(&mut sock, &d).await.is_err() {
        // The "live" socket turned out dead as we wrote the BYE ⇒ retry over a fresh connection.
        bye_reconnect(cfg, &d).await;
    }
    eprintln!("btmqttd: on-demand session torn down (sip:{}@{})", d.aor, d.domain);
    Ok(())
}

/// BYE a confirmed dialog whose ORIGINAL signalling socket died mid-session (TCP EOF from flexisip).
/// Opens a fresh loopback connection and sends the in-dialog BYE there — a SIP dialog is identified
/// by Call-ID + tags, not by the transport connection, so flexisip still routes it to the panel and
/// the camera session ends instead of running to the panel's own timeout. Best-effort: if we
/// can't even reconnect, there's nothing more we can do from here.
async fn bye_reconnect(cfg: &Config, d: &Dialog) {
    if let Ok(mut sock) = TcpStream::connect(("127.0.0.1", cfg.sip_port)).await {
        // Reuse the dialog identity but advertise the NEW local port in Via/Contact so the 200-to-BYE
        // routes back on this connection.
        let mut d2 = d.clone();
        if let Ok(a) = sock.local_addr() {
            d2.local_port = a.port();
        }
        let _ = teardown_bye(&mut sock, &d2).await;
    }
}

/// Write a whole buffer and flush it, surfacing the first error. A tiny helper so a confirmed-dialog
/// send (e.g. the ACK) can route a `ConnectionReset`/`BrokenPipe` through the fresh-connection
/// teardown instead of a bare `?` that would skip it.
async fn write_all_flush(sock: &mut TcpStream, bytes: &[u8]) -> std::io::Result<()> {
    sock.write_all(bytes).await?;
    sock.flush().await
}

/// ACK a racing INVITE 2xx then BYE it on `sock`, reading the `200`-to-BYE best-effort. Returns Err
/// if EITHER write fails, so the caller can redo the whole ACK+BYE over a fresh connection (a BYE to
/// an un-ACKed 2xx is unreliable — this dialog was never ACKed on a live socket).
async fn ack_then_bye(sock: &mut TcpStream, d: &Dialog) -> std::io::Result<()> {
    write_all_flush(sock, build_ack(d, &format!("z9hG4bK{}", rand_hex(8))).as_bytes()).await?;
    write_all_flush(sock, build_bye(d, &format!("z9hG4bK{}", rand_hex(8))).as_bytes()).await?;
    let mut scratch = [0u8; 256];
    let _ = tokio::time::timeout(Duration::from_secs(1), sock.read(&mut scratch)).await;
    Ok(())
}

/// Redo an ACK+BYE for a racing 2xx over a FRESH loopback connection (with its new local port), when
/// the original socket died before/between the ACK and BYE. Best-effort — if we can't reconnect,
/// there's nothing more we can do.
async fn ack_bye_reconnect(cfg: &Config, d: &Dialog) {
    if let Ok(mut sock) = TcpStream::connect(("127.0.0.1", cfg.sip_port)).await {
        let mut d2 = d.clone();
        if let Ok(a) = sock.local_addr() {
            d2.local_port = a.port();
        }
        let _ = ack_then_bye(&mut sock, &d2).await;
    }
}

/// BYE a CONFIRMED dialog on the given socket, then read the `200`-to-BYE best-effort. Returns the
/// write/flush result so a caller on the LIVE-socket path can tell when the socket turned out dead
/// (`ConnectionReset`/`BrokenPipe`) and fall back to `bye_reconnect` — otherwise a discarded write
/// error would silently leave the panel streaming.
async fn teardown_bye(sock: &mut TcpStream, d: &Dialog) -> std::io::Result<()> {
    let bye = build_bye(d, &format!("z9hG4bK{}", rand_hex(8)));
    write_all_flush(sock, bye.as_bytes()).await?;
    let mut scratch = [0u8; 256];
    let _ = tokio::time::timeout(Duration::from_secs(1), sock.read(&mut scratch)).await;
    Ok(())
}

/// Complete when `stopping` is observed true. Used to make the INVITE-response wait interruptible by
/// daemon shutdown (a short poll — it only runs during the brief window we're awaiting that response,
/// and `stopping` is set before the shutdown path bounds the task's join).
async fn wait_until_stopping(stopping: &AtomicBool) {
    while !stopping.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Best-effort teardown when the INVITE never gets a timely final response. Over TCP, closing the
/// socket does NOT cancel a pending INVITE transaction, so:
///  1. send `CANCEL` (matched to the INVITE by branch + CSeq) — and if that write fails because the
///     signalling socket already died (EOF/reset that ended the response wait), retry it over a FRESH
///     loopback connection so flexisip still cancels the forwarded transaction, then
///  2. drain framed responses for a bounded window — and if a 2xx to the INVITE *raced in* (the panel
///     answered right as we gave up), CANCEL can't undo it, so we MUST confirm and tear that dialog
///     down (`ACK` then `BYE`) or the panel keeps its camera streaming.
async fn cancel_pending_invite(sock: &mut TcpStream, cfg: &Config, d: &mut Dialog, acc: Vec<u8>) {
    if write_all_flush(sock, build_cancel(d).as_bytes()).await.is_ok() {
        // Same socket: `acc` was read from `sock`, so a trailing partial is a valid continuation.
        drain_after_cancel(sock, cfg, d, acc, false).await;
    } else if let Ok(mut fresh) = TcpStream::connect(("127.0.0.1", cfg.sip_port)).await {
        // The original socket was dead. Resend over a fresh connection, but KEEP the INVITE's original
        // `Via` (branch AND sent-by port) unchanged: both the CANCEL and the drained non-2xx (487) ACK
        // are part of the INVITE client transaction and MUST reuse its top `Via`, or flexisip won't
        // match them and the transaction lingers until Timer H (RFC 3261 §9.1 / §17.1.1.3). Over TCP
        // that's also fine for the drain's racing-2xx ACK/BYE: SIP sends responses back
        // on the connection the request arrived on (§18.2.2), so the original sent-by port doesn't
        // misroute the 200-to-BYE. Hence we do NOT overwrite `d.local_port` here.
        let _ = write_all_flush(&mut fresh, build_cancel(d).as_bytes()).await;
        // Carry `acc` (the bytes wait_final_response had already read) into the drain even on the
        // reconnect path: if it holds a COMPLETE INVITE 2xx buffered just before the old socket died,
        // drain_after_cancel frames and tears it down (ACK+BYE) — dropping it would leave the accepted
        // camera session up. `seed_foreign = true`: it frames the seed's COMPLETE messages
        // first, then DISCARDS any trailing partial from the dead stream before reading the fresh socket
        // — otherwise that partial would concatenate with the fresh socket's 200-to-CANCEL into one
        // synthetic message and trigger a bogus ACK/BYE with mismatched dialog data.
        drain_after_cancel(&mut fresh, cfg, d, acc, true).await;
    }
    // else: couldn't even reconnect — nothing more we can do.
}

/// Drain framed responses after a CANCEL for `CANCEL_DRAIN`, ACK+BYE-ing a racing INVITE 2xx.
///
/// `seed_foreign` distinguishes where `acc`'s seed bytes came from relative to `sock`:
/// - `false` (same-socket path): `acc` was read from `sock` itself, so a trailing partial is the
///   valid start of the NEXT message on that stream and must be kept and completed by later reads.
/// - `true` (reconnect path): `acc` was read from a now-dead ORIGINAL socket while `sock` is a
///   fresh connection. After framing the seed's COMPLETE messages, any trailing partial belongs to
///   the dead stream and must be DISCARDED — concatenating it with `sock`'s bytes (e.g. the fresh
///   socket's `200`-to-CANCEL) would frame a synthetic message whose status line and headers come
///   from two different streams, causing a bogus ACK/BYE with mismatched dialog data.
async fn drain_after_cancel(
    sock: &mut TcpStream,
    cfg: &Config,
    d: &mut Dialog,
    mut acc: Vec<u8>,
    seed_foreign: bool,
) {
    // `acc` is seeded with whatever `wait_final_response` had already read when the timeout fired —
    // possibly a partial (or even complete) INVITE 2xx — so we can finish framing it below.
    let mut buf = [0u8; 4096];
    let mut first_pass = true;
    let deadline = tokio::time::Instant::now() + CANCEL_DRAIN;
    loop {
        while let Some(len) = complete_message_len(&acc) {
            let msg = String::from_utf8_lossy(&acc[..len]).into_owned();
            acc.drain(..len);
            // We only act on responses to the INVITE transaction. The `200 OK` to our CANCEL is also
            // 2xx but carries `CSeq: N CANCEL` and needs no ACK — skip it and keep draining for the
            // INVITE's own final response.
            if !cseq_is_invite(&msg) {
                continue;
            }
            match parse_status(&msg) {
                // A 2xx to the INVITE means the dialog established despite our CANCEL. It was never
                // ACKed on a live socket, so ACK-then-BYE; if EITHER write fails (socket reset before
                // the ACK reaches flexisip, or between ACK and BYE), redo BOTH over a fresh connection
                // (a BYE alone to an unacknowledged 2xx is unreliable).
                Some(s) if (200..300).contains(&s) => {
                    if let Some(tag) = to_tag(&msg) {
                        d.to_tag = tag;
                        d.remote_target = contact_uri(&msg)
                            .unwrap_or_else(|| format!("sip:{}@{}", d.aor, d.domain));
                        if ack_then_bye(sock, d).await.is_err() {
                            ack_bye_reconnect(cfg, d).await;
                        }
                    }
                    return;
                }
                // The normal terminal response to a cancelled INVITE is `487 Request Terminated` (or
                // another non-2xx). That is ALSO a non-2xx final and requires an in-transaction ACK
                // (build_ack_failure), or flexisip holds the server transaction until Timer H — the
                // same stale-transaction accumulation the reject-path ACK fixes.
                Some(s) if s >= 300 => {
                    if let Some(tag) = to_tag(&msg) {
                        let _ = write_all_flush(sock, build_ack_failure(d, &tag).as_bytes()).await;
                    }
                    return;
                }
                _ => {} // a 1xx provisional to the INVITE (unlikely post-CANCEL) — keep draining
            }
        }
        // Seed fully framed. If it came from the dead original socket, drop any trailing partial
        // now — before the first read from the fresh `sock` — so the two streams' bytes never merge
        // into one synthetic message. On the same-socket path the residue is a legitimate
        // continuation and is kept.
        if first_pass && seed_foreign {
            acc.clear();
        }
        first_pass = false;
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
async fn wait_final_response(sock: &mut TcpStream, acc: &mut Vec<u8>) -> std::io::Result<String> {
    let mut buf = [0u8; 4096];
    loop {
        // Consume every COMPLETE message already buffered and return the first FINAL (>= 200). A
        // message is complete only once its CRLFCRLF header terminator AND its Content-Length body
        // have all arrived — returning on the status line alone could hand back a 200 whose
        // To-tag/Contact haven't been read yet, so the ACK would carry an empty tag and the dialog
        // would never confirm even though the panel accepted the INVITE.
        while let Some(len) = complete_message_len(acc) {
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
        // `a=DEVADDR:`.
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
    fn request_method_extracts_the_method_and_ignores_responses() {
        assert_eq!(request_method("OPTIONS sip:x@127.0.0.1 SIP/2.0\r\n\r\n"), Some("OPTIONS"));
        assert_eq!(request_method("INVITE sip:x@127.0.0.1 SIP/2.0\r\n\r\n"), Some("INVITE"));
        assert_eq!(request_method("UPDATE sip:x@127.0.0.1 SIP/2.0\r\n\r\n"), Some("UPDATE"));
        // A response is NOT a request — the hold loop must not treat a stray 200/1xx as one.
        assert_eq!(request_method("SIP/2.0 200 OK\r\nCSeq: 1 OPTIONS\r\n\r\n"), None);
        assert_eq!(request_method("SIP/2.0 180 Ringing\r\n\r\n"), None);
        // A garbled first line without a SIP-Version token is not a request.
        assert_eq!(request_method("garbage\r\n\r\n"), None);
    }

    #[test]
    fn in_dialog_options_gets_200_and_reinvite_gets_488() {
        // An in-dialog OPTIONS keepalive: answer 200 OK echoing the transaction headers so the
        // panel's OPTIONS transaction completes (no timeout), session untouched.
        let options = "OPTIONS sip:btmqttd@127.0.0.1:5060 SIP/2.0\r\n\
                       Via: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bKopt\r\n\
                       From: <sip:app@d>;tag=ft\r\n\
                       To: <sip:c100x@d>;tag=tt\r\n\
                       Call-ID: cid\r\n\
                       CSeq: 30 OPTIONS\r\n\
                       Content-Length: 0\r\n\r\n";
        assert_eq!(request_method(options), Some("OPTIONS"));
        let ok = in_dialog_answer(options).unwrap();
        assert!(ok.starts_with("SIP/2.0 200 OK\r\n"));
        assert!(ok.contains("CSeq: 30 OPTIONS\r\n"));
        assert!(ok.contains("Via: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bKopt\r\n"));

        // A session-refresh re-INVITE: reject with 488 so the transaction completes without
        // renegotiating media — the existing camera session continues (RFC 3261 §14.2).
        let reinvite = "INVITE sip:btmqttd@127.0.0.1:5060 SIP/2.0\r\n\
                        Via: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bKrei\r\n\
                        From: <sip:app@d>;tag=ft\r\n\
                        To: <sip:c100x@d>;tag=tt\r\n\
                        Call-ID: cid\r\n\
                        CSeq: 31 INVITE\r\n\
                        Content-Length: 0\r\n\r\n";
        let rej = in_dialog_answer(reinvite).unwrap();
        assert!(rej.starts_with("SIP/2.0 488 Not Acceptable Here\r\n"));
        assert!(rej.contains("CSeq: 31 INVITE\r\n")); // same CSeq ⇒ panel matches its INVITE txn
        assert!(rej.contains("To: <sip:c100x@d>;tag=tt\r\n")); // our local tag preserved
        assert!(rej.ends_with("Content-Length: 0\r\n\r\n"));

        // UPDATE is also an offer/answer refresh method ⇒ 488; INFO carries no media ⇒ 200 OK.
        let update = "UPDATE sip:x SIP/2.0\r\nFrom: <sip:a>;tag=f\r\nTo: <sip:b>;tag=t\r\n\
                      Call-ID: c\r\nCSeq: 32 UPDATE\r\nContent-Length: 0\r\n\r\n";
        assert!(in_dialog_answer(update).unwrap().starts_with("SIP/2.0 488 "));
        let info = "INFO sip:x SIP/2.0\r\nFrom: <sip:a>;tag=f\r\nTo: <sip:b>;tag=t\r\n\
                    Call-ID: c\r\nCSeq: 33 INFO\r\nContent-Length: 0\r\n\r\n";
        assert!(in_dialog_answer(info).unwrap().starts_with("SIP/2.0 200 OK"));
        // A RESPONSE (not a request) is never answered.
        assert!(in_dialog_answer("SIP/2.0 200 OK\r\nCSeq: 1 OPTIONS\r\n\r\n").is_none());
    }

    // A write failure while answering an in-dialog request proves the confirmed dialog's socket is
    // dead. The hold loop routes that error to bye_reconnect + `return Err(e)` (same idiom as the
    // read-error arm) so the panel is never left streaming. This test proves the precondition is
    // reachable: once our write half is shut down, writing the OPTIONS `200 OK` fails deterministically
    // (so the branch takes its teardown path rather than silently swallowing the error).
    #[tokio::test]
    async fn in_dialog_answer_write_failure_is_surfaced_not_swallowed() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (_server, _) = listener.accept().await.unwrap();
        client.shutdown().await.unwrap(); // close our write half ⇒ subsequent writes must error

        let options = "OPTIONS sip:x SIP/2.0\r\nFrom: <sip:a>;tag=f\r\nTo: <sip:b>;tag=t\r\n\
                       Call-ID: c\r\nCSeq: 40 OPTIONS\r\nContent-Length: 0\r\n\r\n";
        let resp = in_dialog_answer(options).unwrap();
        assert!(
            write_all_flush(&mut client, resp.as_bytes()).await.is_err(),
            "a dead socket must surface an error from the in-dialog answer write, not swallow it"
        );
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
    fn failure_ack_is_in_transaction_and_targets_the_aor() {
        let d = Dialog {
            aor: "c100x".into(),
            domain: "dev.example".into(),
            local_port: 5555,
            call_id: "abcd".into(),
            from_tag: "ft".into(),
            branch: "z9hG4bKinvitebranch".into(),
            cseq: 21,
            to_tag: String::new(),
            remote_target: "sip:c100x@127.0.0.1:41044".into(), // NOT used by the failure ACK
        };
        let ack = build_ack_failure(&d, "paneltag");
        // Request-URI is the ORIGINAL INVITE R-URI (the AOR), not the panel's Contact.
        assert!(ack.starts_with("ACK sip:c100x@dev.example SIP/2.0\r\n"));
        // In-transaction: SAME top Via branch and CSeq NUMBER as the INVITE, method ACK.
        assert!(ack.contains("branch=z9hG4bKinvitebranch\r\n"));
        assert!(ack.contains("CSeq: 21 ACK\r\n"));
        // Carries the failure response's To-tag.
        assert!(ack.contains("To: <sip:c100x@dev.example>;tag=paneltag\r\n"));
        // Its top Via matches the INVITE's (branch + sent-by), like the CANCEL.
        let invite = build_invite(&d, &build_sdp_offer(1, 2, "k", "da"));
        let via = |m: &str| m.lines().find(|l| l.starts_with("Via:")).unwrap().to_string();
        assert_eq!(via(&ack), via(&invite));
    }

    // --- make-before-break refresh (issue #174, Finding #3) --------------------------------------

    #[tokio::test]
    async fn establish_refresh_dialog_adopts_a_2xx_and_acks() {
        // A confirmable 200 OK to the refresh INVITE is adopted: the helper parses the To-tag + Contact
        // and ACKs, returning the confirmed successor dialog for the make-before-break handover.
        use std::collections::HashMap;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = s.read(&mut buf).await.unwrap();
            let invite = String::from_utf8_lossy(&buf[..n]).into_owned();
            assert!(
                invite.starts_with("INVITE sip:c100x@dev.example SIP/2.0\r\n"),
                "expected a fresh INVITE, got: {invite}"
            );
            s.write_all(
                b"SIP/2.0 200 OK\r\n\
                  Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bKsrv\r\n\
                  From: <sip:btmqttd@dev.example>;tag=cf\r\n\
                  To: <sip:c100x@dev.example>;tag=srv123\r\n\
                  Call-ID: xyz\r\n\
                  CSeq: 21 INVITE\r\n\
                  Contact: <sip:c100x@127.0.0.1:5599;transport=tcp>\r\n\
                  Content-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
            s.flush().await.unwrap();
            // The UAC MUST ACK the confirmed dialog (else the panel retransmits the 2xx).
            let n = s.read(&mut buf).await.unwrap();
            let ack = String::from_utf8_lossy(&buf[..n]).into_owned();
            assert!(ack.starts_with("ACK "), "expected an ACK, got: {ack}");
        });

        let mut m = HashMap::new();
        m.insert("MQTT_HOST".to_string(), "h".to_string());
        m.insert("SIP_PORT".to_string(), port.to_string());
        let cfg = Arc::new(crate::config::Config::from_map(m));
        let stopping = Arc::new(AtomicBool::new(false));
        let (_view_tx, mut view_rx) = mpsc::channel::<ViewCmd>(4); // kept open: no Stop/None mid-attempt
        let d = match establish_refresh_dialog(&cfg, &stopping, &mut view_rx, "c100x", "dev.example", "da")
            .await
        {
            RefreshOutcome::Established(_sock, d) => d,
            other => panic!(
                "a confirmable 2xx refresh must be adopted, got {}",
                match other {
                    RefreshOutcome::Declined(e) => format!("Declined({e})"),
                    RefreshOutcome::Aborted => "Aborted".to_string(),
                    RefreshOutcome::Established(..) => unreachable!(),
                }
            ),
        };
        assert_eq!(d.to_tag, "srv123");
        assert!(
            d.remote_target.contains("127.0.0.1:5599"),
            "remote target should be the panel's Contact, got: {}",
            d.remote_target
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn establish_refresh_dialog_surfaces_a_486_busy() {
        // A single-owner plant refuses a concurrent dialog with 486 Busy Here. The helper ACKs the
        // failure (so flexisip doesn't hold the transaction) and returns Err, so the caller keeps its
        // current dialog and falls back to the panel's recycle — never a panic, never a stuck view.
        use std::collections::HashMap;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).await.unwrap(); // consume the INVITE
            s.write_all(
                b"SIP/2.0 486 Busy Here\r\n\
                  Via: SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bKsrv\r\n\
                  From: <sip:btmqttd@dev.example>;tag=cf\r\n\
                  To: <sip:c100x@dev.example>;tag=srv486\r\n\
                  Call-ID: xyz\r\n\
                  CSeq: 21 INVITE\r\n\
                  Content-Length: 0\r\n\r\n",
            )
            .await
            .unwrap();
            s.flush().await.unwrap();
            // The UAC MUST ACK the non-2xx final (RFC 3261 §17.1.1.3), carrying the failure To-tag.
            let n = s.read(&mut buf).await.unwrap();
            let ack = String::from_utf8_lossy(&buf[..n]).into_owned();
            assert!(ack.starts_with("ACK "), "expected a failure ACK, got: {ack}");
            assert!(ack.contains("tag=srv486"), "failure ACK must echo the To-tag, got: {ack}");
        });

        let mut m = HashMap::new();
        m.insert("MQTT_HOST".to_string(), "h".to_string());
        m.insert("SIP_PORT".to_string(), port.to_string());
        let cfg = Arc::new(crate::config::Config::from_map(m));
        let stopping = Arc::new(AtomicBool::new(false));
        let (_view_tx, mut view_rx) = mpsc::channel::<ViewCmd>(4);
        let err = match establish_refresh_dialog(&cfg, &stopping, &mut view_rx, "c100x", "dev.example", "da")
            .await
        {
            RefreshOutcome::Declined(e) => e,
            RefreshOutcome::Established(..) => {
                panic!("a 486 must not be adopted — the caller must keep its current dialog")
            }
            RefreshOutcome::Aborted => panic!("a 486 is a decline, not an abort"),
        };
        assert!(err.to_string().contains("486"), "error should name the status, got: {err}");
        server.await.unwrap();
    }

    // NB: the timing invariant `SESSION_REFRESH_AFTER + RESPONSE_TIMEOUT (+margin) < PANEL_SESSION_LIMIT`
    // is enforced at COMPILE TIME by the `const _: () = assert!(…)` next to the constants — stronger than a
    // runtime test (it cannot be bypassed), so there is deliberately no unit test duplicating it here.

    #[tokio::test]
    async fn establish_refresh_dialog_aborts_on_stop_and_cancels() {
        // A `Stop`/"Stop Camera" (or shutdown) observed while the refresh INVITE is in flight must abort
        // PROMPTLY with the INVITE CANCELled — not block up to RESPONSE_TIMEOUT inside the wait. This is the
        // interruptibility that keeps a daemon shutdown within main.rs's budget and never leaves a refresh
        // INVITE dangling (a late 2xx to which would pin the panel). The panel here never sends a final
        // response; the abort must come from the `view_rx` Stop, and a CANCEL must go out afterwards.
        use std::collections::HashMap;
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            // Never answer the INVITE; keep the socket open so the client's CANCEL has somewhere to land.
            // Accumulate ALL received bytes and check at the end — the INVITE and the CANCEL can arrive in
            // one read, so a per-read "first is INVITE, rest is CANCEL" split would miss the coalesced case.
            let mut all = String::new();
            loop {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(m) => all.push_str(&String::from_utf8_lossy(&buf[..m])),
                }
            }
            (all.contains("INVITE "), all.contains("CANCEL "))
        });

        let mut m = HashMap::new();
        m.insert("MQTT_HOST".to_string(), "h".to_string());
        m.insert("SIP_PORT".to_string(), port.to_string());
        let cfg = Arc::new(crate::config::Config::from_map(m));
        let stopping = Arc::new(AtomicBool::new(false));
        let (view_tx, mut view_rx) = mpsc::channel::<ViewCmd>(4);
        view_tx.send(ViewCmd::Stop).await.unwrap(); // a Stop waiting before the panel ever responds
        let outcome =
            establish_refresh_dialog(&cfg, &stopping, &mut view_rx, "c100x", "dev.example", "da").await;
        assert!(
            matches!(outcome, RefreshOutcome::Aborted),
            "a mid-flight Stop must abort the refresh, not block on the response"
        );
        drop(view_tx);
        let (saw_invite, saw_cancel) = server.await.unwrap();
        assert!(saw_invite, "the refresh must have sent an INVITE");
        assert!(saw_cancel, "the aborted refresh must CANCEL its in-flight INVITE");
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
        // RFC 3261 §9.1: the CANCEL's top Via must be byte-identical to the INVITE's (branch AND
        // sent-by port), so flexisip matches it — even when we resend over a fresh connection with a
        // different local port, build_cancel must be given the ORIGINAL dialog.
        let invite = build_invite(&d, &build_sdp_offer(1, 2, "k", "da"));
        let via = |m: &str| m.lines().find(|l| l.starts_with("Via:")).unwrap().to_string();
        assert_eq!(via(&cancel), via(&invite));
    }

    #[test]
    fn a_panel_bye_split_across_reads_is_framed_before_acting() {
        // Regression for the in-dialog framing fix: a BYE that arrives in two TCP
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

    // --- the two-deadline hang-up rule (seed_deadlines / governing_deadline) --------------------

    const WINDOW: Duration = Duration::from_secs(30); // camera_view_idle_secs default (manual window)
    const LINGER: Duration = Duration::from_secs(5); // VIEWER_LINGER (auto short linger)

    #[test]
    fn auto_hold_open_governs_by_the_short_linger() {
        // A `Hold`-opened session (a fresh hold expiry, no manual press): only the short linger is armed,
        // so once the auto pokes stop the session hangs up ~VIEWER_LINGER later — not after the full window.
        let now = tokio::time::Instant::now();
        let (start, hold) = seed_deadlines(false, Some(now + LINGER), now, WINDOW);
        assert_eq!(start, now); // no manual window armed (already elapsed)
        assert_eq!(hold, now + LINGER);
        assert_eq!(governing_deadline(start, hold), now + LINGER);
    }

    #[test]
    fn manual_open_governs_by_the_full_window() {
        // A manual `view_camera` press with no live viewer: only the full window is armed.
        let now = tokio::time::Instant::now();
        let (start, hold) = seed_deadlines(true, None, now, WINDOW);
        assert_eq!(start, now + WINDOW);
        assert_eq!(hold, now); // no auto linger armed
        assert_eq!(governing_deadline(start, hold), now + WINDOW);
    }

    #[test]
    fn a_hold_expiry_already_elapsed_at_session_up_is_dropped() {
        // A `Hold` that queued while sip.rs was in reconnect backoff and is only
        // consumed after the viewer disconnected carries an expiry now in the PAST. `seed_deadlines` must
        // drop it (seed the hold side already-elapsed) so it can't seed a linger on a viewerless session —
        // the session then governs by whatever the manual side says (here nothing ⇒ hangs up at once).
        let now = tokio::time::Instant::now();
        let stale = now - Duration::from_secs(1); // poked >VIEWER_LINGER ago
        let (start, hold) = seed_deadlines(false, Some(stale), now, WINDOW);
        assert_eq!(start, now);
        assert_eq!(hold, now); // stale expiry dropped, not armed
        assert_eq!(governing_deadline(start, hold), now);
    }

    #[test]
    fn manual_window_is_a_floor_the_auto_linger_cannot_cut_below() {
        // A manual window is active AND an auto `Hold` poke lands (a viewer is also connected): the auto
        // linger (now + LINGER) is SOONER than the manual window (now + WINDOW), so the governing
        // deadline stays at the manual window — auto-hold can never shorten a manual view.
        let now = tokio::time::Instant::now();
        let start = now + WINDOW; // manual window
        let hold = now + LINGER; // an auto poke, sooner
        assert_eq!(governing_deadline(start, hold), now + WINDOW);
    }

    #[test]
    fn follow_the_live_viewer_extends_past_the_manual_window_by_design() {
        // Issue #120: while a viewer stays connected, auto-hold keeps poking `Hold`, so `hold_deadline`
        // advances past an already-elapsed manual window and the session FOLLOWS the live viewer rather
        // than capping at camera_view_idle_secs (the same behavior the previous `Start`-poke auto-hold
        // had). The ~VIEWER_LINGER tail only applies once the viewer disconnects and the pokes stop.
        let now = tokio::time::Instant::now();
        let start = now + WINDOW; // manual window
        let late_poke = now + WINDOW + Duration::from_secs(3); // a Hold poke AFTER the window elapsed
        let hold = late_poke + LINGER;
        assert_eq!(governing_deadline(start, hold), late_poke + LINGER); // extends with the viewer
    }

    #[test]
    fn a_manual_start_during_establishment_still_arms_the_full_window() {
        // A `Hold`-opened session that also saw a manual `Start` while the INVITE established
        // arms BOTH deadlines, so a later disconnect honors the full window (not just the short linger).
        let now = tokio::time::Instant::now();
        let (start, hold) = seed_deadlines(true, Some(now + LINGER), now, WINDOW);
        assert_eq!(start, now + WINDOW);
        assert_eq!(hold, now + LINGER);
        assert_eq!(governing_deadline(start, hold), now + WINDOW); // full manual window preserved
    }
}
