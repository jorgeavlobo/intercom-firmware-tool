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
//! Volume is WHO=8 dimension `41`, value = percent (0..=100, step 10 in the UI):
//! ```text
//!   read  request : *#8**41##       -> reply *#8**41*<N>##
//!   write command : *#8**#41*<N>##  -> reply *#8**41*<N>##
//! ```
//! Verified on a live Classe 100X: `*99*0##` -> `*#*1##`, then the frame; the gateway
//! answers `*#*1##` (accepted) / `*#*0##` (rejected) and, for a read/write, the
//! `*#8**41*<N>##` dimension report (which the monitor also broadcasts).

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

/// WHO=8 dimension carrying the ringtone/speaker volume (issue #40 RE).
const VOLUME_DIM: &str = "41";

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

/// Write the volume (`pct` clamped to 0..=100). Ok means the frame was sent and the
/// session completed; the authoritative confirmation is the `*#8**41*<N>##` broadcast
/// the monitor delivers, which the volume state machine consumes.
pub async fn write_volume(host: &str, port: u16, pct: u8) -> std::io::Result<()> {
    let pct = pct.min(VOLUME_MAX);
    let _ = session(host, port, &volume_write_frame(pct)).await?;
    Ok(())
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
}
