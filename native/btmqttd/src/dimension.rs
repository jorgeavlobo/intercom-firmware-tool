//! OWN command session on the openserver gateway for DIMENSION read/write (issue #40).
//!
//! The command-injection port used for ACTIONS (bt_vct, `OWN_PORT_CMD` = 30006) does
//! NOT handle WHO=8 dimension get/set — those must go to the openserver main gateway
//! (`OWN_HOST:own_port_mon`, default `:20000`) via an OWN *command* session (`*99*0##`),
//! distinct from the read-only *monitor* session (`*99*1##`) that `sender.rs` holds.
//!
//! Per-operation (the industry pattern for low-frequency control): connect, send the
//! command-session request, send the frame, read the gateway's reply frame(s), close.
//! No persistent command session is kept — volume STATE is learned for free from the
//! monitor broadcasts, so a short-lived session per set/read is simpler and robust
//! (no keepalive / stale-session handling), and mirrors the per-command `:30006` path.
//!
//! Two independent WHO=8 dimensions are driven here (both reverse-engineered against a
//! live unit and captured with `strace` on `bt_answering_machine`, which owns them):
//!
//! * Ringtone VOLUME — dimension `41`, value = percent (0..=100, step 10 in the UI):
//!   ```text
//!     read  request : *#8**41##       -> reply *#8**41*<N>##
//!     write command : *#8**#41*<N>##  -> reply *#8**41*<N>##
//!   ```
//!   The write persists to `aswm_settings.ini` `[Volumes] Ring=<N>` and sets the real
//!   ringtone loudness (proven audibly at the door station); it does NOT move the unit's
//!   on-screen volume indicator, which the GUI caches in RAM and cannot be synced from
//!   the bus.
//!
//! * Ringtone MUTE — dimension `33`, value = the device's `RingEnable` flag (boolean):
//!   ```text
//!     read  request : *#8**33##       -> reply *#8**33*<0|1>##
//!     write command : *#8**#33*<0|1>##  -> reply *#8**33*<0|1>##
//!   ```
//!   `1` = ringtone ENABLED (audible), `0` = ringtone DISABLED (silenced) — persisted to
//!   `aswm_settings.ini` `RingEnable=<0|1>`. This is the unit's own "do not disturb"
//!   toggle and is INDEPENDENT of the volume: muting leaves the volume level untouched.
//!
//! Verified on a live Classe 300X (`imx6dl-shark-zl380tw`): `*99*0##` -> `*#*1##`, then
//! the frame; the gateway answers `*#*1##` (accepted) / `*#*0##` (rejected) and, for a
//! read/write, the dimension report (which the monitor also broadcasts).

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::own::Framer;

/// The OWN command-session request. The gateway replies `*#*1##` (accepted) — the
/// session type that permits dimension read/write, unlike the monitor `*99*1##`.
const COMMAND_REQ: &[u8] = b"*99*0##";

/// Wall-clock cap for one command-session round trip (connect + handshake + reply).
const SESSION_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait for further reply bytes before treating the gateway as idle and
/// closing the session. The reply (`*#*1##` + optional dimension report) arrives in
/// one burst, so a short idle gap reliably marks the end without hanging.
const REPLY_IDLE: Duration = Duration::from_millis(500);

/// WHO=8 dimension carrying the ringtone volume, 0..=100 (issue #40 RE).
const VOLUME_DIM: &str = "41";

/// WHO=8 dimension carrying the ringtone-enabled (`RingEnable`) flag, `0`/`1` — the
/// device's own "do not disturb"/mute, independent of the volume (issue #40 RE).
const MUTE_DIM: &str = "33";

/// The maximum volume percent the device accepts.
pub const VOLUME_MAX: u8 = 100;

/// The dimension-REQUEST frame that asks the gateway for the current volume.
pub fn volume_read_request() -> String {
    format!("*#8**{VOLUME_DIM}##")
}

/// The dimension-WRITE frame that sets the volume to `pct` (caller clamps to 0..=100).
/// Note the `#` before the dimension — that is what makes it a write, not a report.
pub fn volume_write_frame(pct: u8) -> String {
    format!("*#8**#{VOLUME_DIM}*{pct}##")
}

/// Parse a WHO=8 volume dimension report `*#8**41*<N>##` into `N` (0..=100).
///
/// Returns `None` for any other frame, so the monitor stream can be filtered for
/// volume updates: the WHO=7 companion (`*#7**31#2#0*<N>##`), other WHO=8 dimensions
/// (e.g. `*#8**35*…`), commands, and out-of-range values are all rejected.
pub fn parse_volume_report(frame: &str) -> Option<u8> {
    let body = frame.strip_prefix("*#8**")?.strip_suffix("##")?;
    let (dim, val) = body.split_once('*')?;
    if dim != VOLUME_DIM {
        return None;
    }
    // A single numeric value only: reject multi-field dimensions like "41*1*2".
    val.parse::<u8>().ok().filter(|&n| n <= VOLUME_MAX)
}

/// The dimension-REQUEST frame that asks the gateway for the current mute state.
pub fn mute_read_request() -> String {
    format!("*#8**{MUTE_DIM}##")
}

/// The dimension-WRITE frame that mutes (`muted == true`) or unmutes the ringtone.
///
/// The value is the device's `RingEnable` flag, so it is INVERTED from `muted`:
/// muted → `RingEnable=0` (disabled), unmuted → `RingEnable=1` (enabled).
pub fn mute_write_frame(muted: bool) -> String {
    let ring_enable = u8::from(!muted);
    format!("*#8**#{MUTE_DIM}*{ring_enable}##")
}

/// Parse a WHO=8 mute dimension report `*#8**33*<0|1>##` into `muted` (`RingEnable==0`).
///
/// Returns `None` for any other frame (so the monitor stream can be filtered) and for
/// out-of-range values — only the booleans `0`/`1` are accepted, which is what makes the
/// earlier "dim33 with a percent value did nothing" behaviour make sense: the device
/// silently rejects non-boolean writes to this dimension.
pub fn parse_mute_report(frame: &str) -> Option<bool> {
    let body = frame.strip_prefix("*#8**")?.strip_suffix("##")?;
    let (dim, val) = body.split_once('*')?;
    if dim != MUTE_DIM {
        return None;
    }
    match val {
        "0" => Some(true),  // RingEnable=0 -> muted
        "1" => Some(false), // RingEnable=1 -> not muted
        _ => None,
    }
}

/// WHO=8 entrance-panel CALL ("doorbell") command: `*8*1#1#4#21*<WHERE>##` (RE —
/// captured on a live Classe 100X, matching fquinto's Classe 300X
/// `*8*1#1#4#21*16##`). The WHAT (`1#1#4#21`) is the stable doorbell signature; the
/// WHERE (the entrance-panel address, e.g. `112`/`16`) varies per install, so it is
/// NOT matched — it is returned for information.
const DOORBELL_WHAT: &str = "1#1#4#21";

/// WHO=8 dimension carrying the CALL STATE, broadcast as a call progresses:
/// `*#8**35*<N>*0*0##`. Confirmed against live captures of both an ANSWERED and an
/// unanswered call: `0` idle/ended, `1`/`2`/`4` the pre-answer ringing phases, `6`
/// answered/in-call (it appeared exactly when the call was picked up, and never on the
/// unanswered call which went `1->2->4->0`). See [`call_state_label`]; the raw code also
/// travels as an attribute for finer granularity (door-entry RE).
const CALL_STATE_DIM: &str = "35";

/// Match the entrance-panel call ("doorbell") `*8*1#1#4#21*<WHERE>##` and return the
/// WHERE (the panel address). Returns `None` for any other frame — a different WHO=8
/// WHAT (`*8*9#1#4*20##`), a dimension report (`*#8**…`), a command, etc.
pub fn parse_doorbell(frame: &str) -> Option<&str> {
    let body = frame.strip_prefix("*8*")?.strip_suffix("##")?;
    // `*8*<WHAT>*<WHERE>##`: require the exact doorbell WHAT, then the '*' before WHERE.
    let where_ = body.strip_prefix(DOORBELL_WHAT)?.strip_prefix('*')?;
    // WHERE must be a single non-empty field: reject `*8*1#1#4#21*##` (empty) and an
    // extended frame `*8*1#1#4#21*112*X##` (extra '*'-separated fields) so neither fires
    // a spurious doorbell event.
    if where_.is_empty() || where_.contains('*') {
        return None;
    }
    Some(where_)
}

/// Parse a WHO=8 call-state report `*#8**35*<N>*0*0##` into `N`. Returns `None` for any
/// other frame (other WHO=8 dimensions like volume `41`/mute `33`, commands, malformed).
pub fn parse_call_state(frame: &str) -> Option<u8> {
    let body = frame.strip_prefix("*#8**")?.strip_suffix("##")?;
    let (dim, rest) = body.split_once('*')?;
    if dim != CALL_STATE_DIM {
        return None;
    }
    // The state is the first value field; the trailing `*0*0` sub-fields are ignored.
    let code = rest.split('*').next()?;
    code.parse::<u8>().ok()
}

/// Human-readable label for a call-state code (see [`parse_call_state`]), from live
/// captures: `0` idle, `1`/`2`/`4` the pre-answer ringing phases, `6` answered/in-call.
/// Any other (unobserved) code maps to "active" as a safe fallback; the raw code travels
/// alongside as an attribute for finer granularity.
pub fn call_state_label(code: u8) -> &'static str {
    match code {
        0 => "idle",
        1 | 2 | 4 => "ringing",
        6 => "in_call",
        _ => "active",
    }
}

/// Run ONE command-session operation: connect to `host:port`, open the command
/// session, send `frame`, and collect the gateway's reply frames (dimension reports;
/// the `*#*1##`/`*#*0##` ACK/NACK control frames are dropped by the framer) until the
/// gateway goes idle or closes. Bounded by [`SESSION_TIMEOUT`].
async fn session(host: &str, port: u16, frame: &str) -> std::io::Result<Vec<String>> {
    let fut = async {
        let mut sock = TcpStream::connect((host, port)).await?;
        // Send the session request and the frame back-to-back: openserver is permissive
        // and processes them in order (as the manual `nc` test did), so we don't need to
        // await the intermediate ACK before sending the frame.
        sock.write_all(COMMAND_REQ).await?;
        sock.write_all(frame.as_bytes()).await?;
        sock.flush().await?;

        let mut framer = Framer::default();
        let mut out: Vec<String> = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match tokio::time::timeout(REPLY_IDLE, sock.read(&mut buf)).await {
                Ok(Ok(0)) => break,                        // gateway closed the session
                Ok(Ok(n)) => framer.push(&buf[..n], &mut out),
                Ok(Err(e)) => return Err(e),
                Err(_) => break,                           // idle: reply burst is complete
            }
        }
        Ok(out)
    };
    tokio::time::timeout(SESSION_TIMEOUT, fut).await.map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "own command session timed out")
    })?
}

/// Read the current volume via a dimension request. Returns the reported percent, or
/// `None` if the gateway gave no valid volume report (e.g. session refused).
pub async fn read_volume(host: &str, port: u16) -> std::io::Result<Option<u8>> {
    let replies = session(host, port, &volume_read_request()).await?;
    Ok(replies.iter().find_map(|f| parse_volume_report(f)))
}

/// Write the volume (`pct` clamped to 0..=100) and return the level the device
/// ECHOES back. A successful write replies with the dimension report
/// `*#8**41*<N>##`; a REFUSED write yields only the NACK `*#*0##` (dropped by the
/// framer), so no report comes back — which we surface as an error (logged rather
/// than a silent success).
///
/// Returning the echoed level lets the caller update its state from the device's OWN
/// confirmation immediately, instead of waiting on (and racing) the monitor
/// broadcast: a rapid follow-up step/set then computes from the confirmed value
/// rather than a stale one, so consecutive up/down presses don't skip or repeat a
/// step. The monitor broadcast still reaffirms the same value shortly after.
pub async fn write_volume(host: &str, port: u16, pct: u8) -> std::io::Result<u8> {
    let pct = pct.min(VOLUME_MAX);
    let replies = session(host, port, &volume_write_frame(pct)).await?;
    replies.iter().find_map(|f| parse_volume_report(f)).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "volume write not acknowledged (no dimension report in reply)",
        )
    })
}

/// Read the current mute state via a dimension request. Returns `Some(muted)`, or `None`
/// if the gateway gave no valid mute report (session refused / dimension unsupported).
pub async fn read_mute(host: &str, port: u16) -> std::io::Result<Option<bool>> {
    let replies = session(host, port, &mute_read_request()).await?;
    Ok(replies.iter().find_map(|f| parse_mute_report(f)))
}

/// Mute/unmute the ringtone and return the state the device ECHOES back. Mirrors
/// [`write_volume`]: a successful write replies with the `*#8**33*<0|1>##` report; a
/// REFUSED write yields only the NACK `*#*0##` (dropped by the framer), surfaced as an
/// error rather than a silent success. Returning the echoed state lets the caller update
/// from the device's confirmation immediately instead of racing the monitor broadcast.
pub async fn write_mute(host: &str, port: u16, muted: bool) -> std::io::Result<bool> {
    let replies = session(host, port, &mute_write_frame(muted)).await?;
    replies.iter().find_map(|f| parse_mute_report(f)).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "mute write not acknowledged (no dimension report in reply)",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_request_frame() {
        assert_eq!(volume_read_request(), "*#8**41##");
    }

    #[test]
    fn write_frame_has_the_hash_before_the_dimension() {
        // The leading '#' on the dimension is what marks a WRITE (vs a report).
        assert_eq!(volume_write_frame(0), "*#8**#41*0##");
        assert_eq!(volume_write_frame(30), "*#8**#41*30##");
        assert_eq!(volume_write_frame(100), "*#8**#41*100##");
    }

    #[test]
    fn parses_who8_dim41_reports() {
        assert_eq!(parse_volume_report("*#8**41*0##"), Some(0));
        assert_eq!(parse_volume_report("*#8**41*50##"), Some(50));
        assert_eq!(parse_volume_report("*#8**41*100##"), Some(100));
    }

    #[test]
    fn rejects_non_volume_frames() {
        // WHO=7 companion carried alongside the volume report.
        assert_eq!(parse_volume_report("*#7**31#2#0*50##"), None);
        // A different WHO=8 dimension (seen spontaneously on the bus).
        assert_eq!(parse_volume_report("*#8**35*0*0*0##"), None);
        // A plain command, not a dimension report.
        assert_eq!(parse_volume_report("*8*19*20##"), None);
        // Out of range.
        assert_eq!(parse_volume_report("*#8**41*200##"), None);
        // Non-numeric / malformed.
        assert_eq!(parse_volume_report("*#8**41*x##"), None);
        assert_eq!(parse_volume_report("*#8**41##"), None); // the request, not a report
        assert_eq!(parse_volume_report("garbage"), None);
    }

    #[test]
    fn write_clamps_are_the_callers_job_but_frame_builder_is_literal() {
        // volume_write_frame does not clamp (write_volume does); it renders the value.
        assert_eq!(volume_write_frame(90), "*#8**#41*90##");
    }

    #[test]
    fn mute_request_frame() {
        assert_eq!(mute_read_request(), "*#8**33##");
    }

    #[test]
    fn mute_write_frame_inverts_muted_into_ring_enable() {
        // muted -> RingEnable=0 (silenced); unmuted -> RingEnable=1 (audible).
        assert_eq!(mute_write_frame(true), "*#8**#33*0##");
        assert_eq!(mute_write_frame(false), "*#8**#33*1##");
    }

    #[test]
    fn parses_who8_dim33_reports_as_muted() {
        assert_eq!(parse_mute_report("*#8**33*0##"), Some(true)); // RingEnable=0 -> muted
        assert_eq!(parse_mute_report("*#8**33*1##"), Some(false)); // RingEnable=1 -> audible
    }

    #[test]
    fn rejects_non_mute_frames() {
        // The volume dimension is not the mute dimension.
        assert_eq!(parse_mute_report("*#8**41*50##"), None);
        // Only the booleans 0/1 are valid RingEnable values.
        assert_eq!(parse_mute_report("*#8**33*2##"), None);
        assert_eq!(parse_mute_report("*#8**33*88##"), None);
        // The request, not a report; and malformed input.
        assert_eq!(parse_mute_report("*#8**33##"), None);
        assert_eq!(parse_mute_report("garbage"), None);
        // And the volume parser rejects the mute dimension, keeping the two streams apart.
        assert_eq!(parse_volume_report("*#8**33*1##"), None);
    }

    #[test]
    fn parses_doorbell_call_and_returns_where() {
        // Captured on a live Classe 100X; WHERE varies per install.
        assert_eq!(parse_doorbell("*8*1#1#4#21*112##"), Some("112"));
        // fquinto's Classe 300X used the SAME WHAT, a different WHERE.
        assert_eq!(parse_doorbell("*8*1#1#4#21*16##"), Some("16"));
    }

    #[test]
    fn rejects_non_doorbell_frames() {
        // Other WHO=8 commands seen in the same capture must NOT trigger the doorbell.
        assert_eq!(parse_doorbell("*8*9#1#4*20##"), None);
        assert_eq!(parse_doorbell("*8*3#1#4*420##"), None);
        assert_eq!(parse_doorbell("*8*19*20##"), None);
        // A near-miss WHAT must not match (prefix guard).
        assert_eq!(parse_doorbell("*8*1#1#4#210*112##"), None);
        // An empty WHERE or an extended frame with extra '*' fields must not match.
        assert_eq!(parse_doorbell("*8*1#1#4#21*##"), None);
        assert_eq!(parse_doorbell("*8*1#1#4#21*112*X##"), None);
        // Dimension reports and other WHOs are not doorbell commands.
        assert_eq!(parse_doorbell("*#8**35*1*0*0##"), None);
        assert_eq!(parse_doorbell("*7*55*##"), None);
        assert_eq!(parse_doorbell("garbage"), None);
    }

    #[test]
    fn parses_call_state_reports() {
        // The full ANSWERED-call sequence captured: 1 -> 2 -> 4 -> 6 (answered) -> 0.
        assert_eq!(parse_call_state("*#8**35*1*0*0##"), Some(1));
        assert_eq!(parse_call_state("*#8**35*2*0*0##"), Some(2));
        assert_eq!(parse_call_state("*#8**35*4*0*0##"), Some(4));
        assert_eq!(parse_call_state("*#8**35*6*0*0##"), Some(6));
        assert_eq!(parse_call_state("*#8**35*0*0*0##"), Some(0));
    }

    #[test]
    fn rejects_non_call_state_frames() {
        // Other WHO=8 dimensions (volume 41 / mute 33) are not the call-state dimension.
        assert_eq!(parse_call_state("*#8**41*50##"), None);
        assert_eq!(parse_call_state("*#8**33*1##"), None);
        // The doorbell command is not a dimension report.
        assert_eq!(parse_call_state("*8*1#1#4#21*112##"), None);
        assert_eq!(parse_call_state("garbage"), None);
        // And the volume/mute parsers reject the call-state dimension.
        assert_eq!(parse_volume_report("*#8**35*1*0*0##"), None);
        assert_eq!(parse_mute_report("*#8**35*1*0*0##"), None);
    }

    #[test]
    fn call_state_labels() {
        assert_eq!(call_state_label(0), "idle");
        assert_eq!(call_state_label(1), "ringing");
        assert_eq!(call_state_label(2), "ringing");
        assert_eq!(call_state_label(4), "ringing");
        assert_eq!(call_state_label(6), "in_call"); // answered (confirmed on a live call)
        assert_eq!(call_state_label(3), "active");   // unobserved code -> safe fallback
    }
}
