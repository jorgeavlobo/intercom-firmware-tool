//! OpenWebNet frame handling: split the raw monitor byte stream into frames, drop
//! the session ACK/NACK control frames, and (for PAYLOAD_FORMAT=json) turn each
//! frame into the same structured object the jq `own_frame_to_json` produced.
//!
//! Faithful reimplementation of `frame_own` (busybox awk) and `own_frame_to_json`
//! (jq) from mqtt_common.sh / StartMqttSend.

use serde_json::{json, Value};
use time::OffsetDateTime;

/// The session control frames — a monitor ACK / NACK. They carry no bus event and
/// are dropped by both the framer and the JSON converter (as in the shell).
pub const ACK: &[u8] = b"*#*1##";
pub const NACK: &[u8] = b"*#*0##";

/// True when `s` is a raw OpenWebNet frame: starts with `*` and ends with `##`
/// (the receiver's `grep -qE '^\*.*##$'` test in StartMqttReceive).
pub fn is_own_frame(s: &str) -> bool {
    let b = s.as_bytes();
    b.first() == Some(&b'*') && b.len() >= 3 && s.ends_with("##")
}

/// Incremental framer for the monitor byte stream. OpenWebNet frames ("*...##")
/// arrive back-to-back with NO separators and legitimately contain single '#'
/// bytes (status/dimension frames), so we cannot split on a single '#'. This
/// mirrors the awk framer exactly: treat '#' as a record separator and reassemble
/// — an EMPTY record (two '#' in a row) is the closing "##" that flushes a frame.
#[derive(Default)]
pub struct Framer {
    rec: Vec<u8>, // bytes of the current inter-'#' record
    buf: Vec<u8>, // accumulated frame so far (already includes trailing '#'s)
}

impl Framer {
    /// Feed raw bytes; push each COMPLETE, non-control frame (as a String) to `out`.
    /// Frames are guaranteed valid UTF-8 in practice (ASCII OWN), but a stray
    /// non-UTF-8 byte is dropped rather than panicking.
    pub fn push(&mut self, bytes: &[u8], out: &mut Vec<String>) {
        for &byte in bytes {
            if byte == b'#' {
                if self.rec.is_empty() {
                    // Second '#' of a "##" terminator: the frame is complete.
                    if !self.buf.is_empty() {
                        self.buf.push(b'#');
                        let frame = std::mem::take(&mut self.buf);
                        if frame.first() == Some(&b'*') && frame != ACK && frame != NACK {
                            if let Ok(s) = String::from_utf8(frame) {
                                out.push(s);
                            }
                        }
                    }
                } else {
                    self.buf.extend_from_slice(&self.rec);
                    self.buf.push(b'#');
                    self.rec.clear();
                }
            } else {
                self.rec.push(byte);
            }
        }
    }
}

/// UTC ISO-8601 timestamp with second precision and a `Z` suffix — matching jq's
/// `now | todate` (e.g. `2026-07-21T15:04:24Z`).
pub fn utc_now_iso() -> String {
    let n = OffsetDateTime::now_utc();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        n.year(),
        n.month() as u8,
        n.day(),
        n.hour(),
        n.minute(),
        n.second()
    )
}

/// Structural (not semantic) parse of one frame into the JSON object the jq
/// `own_frame_to_json` produced: `{frame, ts, type, who, what, where, params}`.
/// A leading `*#` marks a status/dimension REQUEST (`*#WHO*WHERE…##`), otherwise a
/// COMMAND (`*WHO*WHAT*WHERE…##`). Missing positions degrade to `null`; extra
/// tokens go to `params`. Sub-parameters inside a token (e.g. `0#0`) are left
/// intact. Returns `None` for the ACK/NACK control frames (dropped).
pub fn frame_to_json(frame: &str) -> Option<Value> {
    if frame.as_bytes() == ACK || frame.as_bytes() == NACK {
        return None;
    }
    // Remove exactly ONE leading `*` and ONE trailing `##`, matching jq's
    // `ltrimstr("*")` / `rtrimstr("##")` (single occurrence). trim_*_matches would
    // strip ALL repetitions, diverging on malformed frames like `**…` or `…####`.
    let body = frame.strip_prefix('*').unwrap_or(frame);
    let body = body.strip_suffix("##").unwrap_or(body);
    let ts = utc_now_iso();

    let obj = if let Some(req) = body.strip_prefix('#') {
        let t: Vec<&str> = req.split('*').collect();
        json!({
            "frame": frame,
            "ts": ts,
            "type": "request",
            "who": t.first().copied(),
            "what": Value::Null,
            "where": t.get(1).copied(),
            "params": t.get(2..).unwrap_or(&[]),
        })
    } else {
        let t: Vec<&str> = body.split('*').collect();
        json!({
            "frame": frame,
            "ts": ts,
            "type": "command",
            "who": t.first().copied(),
            "what": t.get(1).copied(),
            "where": t.get(2).copied(),
            "params": t.get(3..).unwrap_or(&[]),
        })
    };
    Some(obj)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames(input: &[u8]) -> Vec<String> {
        let mut f = Framer::default();
        let mut out = Vec::new();
        f.push(input, &mut out);
        out
    }

    #[test]
    fn splits_backtoback_and_preserves_internal_hash() {
        // command, request, dimension-with-internal-'#', back-to-back, no newlines.
        let out = frames(b"*1*0*12##*#1*12##*#4*3*0#0##");
        assert_eq!(out, vec!["*1*0*12##", "*#1*12##", "*#4*3*0#0##"]);
    }

    #[test]
    fn drops_ack_and_nack() {
        let out = frames(b"*#*1##*8*19*20##*#*0##");
        assert_eq!(out, vec!["*8*19*20##"]);
    }

    #[test]
    fn framer_handles_split_chunks() {
        let mut f = Framer::default();
        let mut out = Vec::new();
        f.push(b"*1*0", &mut out);
        f.push(b"*12##*2", &mut out);
        f.push(b"*1*3##", &mut out);
        assert_eq!(out, vec!["*1*0*12##", "*2*1*3##"]);
    }

    #[test]
    fn command_json_shape() {
        let v = frame_to_json("*1*0*12##").unwrap();
        assert_eq!(v["type"], "command");
        assert_eq!(v["who"], "1");
        assert_eq!(v["what"], "0");
        assert_eq!(v["where"], "12");
        assert_eq!(v["params"], json!([]));
        assert_eq!(v["frame"], "*1*0*12##");
        assert!(v["ts"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn request_json_shape_has_null_what() {
        let v = frame_to_json("*#4*1*0##").unwrap();
        assert_eq!(v["type"], "request");
        // body after '*'/'##' = "#4*1*0"; strip '#' -> "4*1*0"; split -> [4,1,0]
        assert_eq!(v["who"], "4");
        assert_eq!(v["where"], "1");
        assert_eq!(v["what"], Value::Null);
        assert_eq!(v["params"], json!(["0"]));
    }

    #[test]
    fn short_frame_degrades_to_null() {
        let v = frame_to_json("*1##").unwrap();
        assert_eq!(v["who"], "1");
        assert_eq!(v["what"], Value::Null);
        assert_eq!(v["where"], Value::Null);
        assert_eq!(v["params"], json!([]));
    }

    #[test]
    fn json_drops_control_frames() {
        assert!(frame_to_json("*#*1##").is_none());
        assert!(frame_to_json("*#*0##").is_none());
    }

    #[test]
    fn strips_only_one_star_and_one_terminator() {
        // jq ltrimstr/rtrimstr remove a SINGLE prefix/suffix. A malformed frame with a
        // doubled leading `*` keeps the extra one, so `who` is the empty first token
        // rather than being silently collapsed (which trim_start_matches would do).
        let v = frame_to_json("**1*2*3##").unwrap();
        assert_eq!(v["who"], ""); // extra leading `*` -> empty first token
        assert_eq!(v["what"], "1");
        assert_eq!(v["where"], "2");
        assert_eq!(v["params"], json!(["3"]));

        // A doubled trailing `##` strips only one; the other stays attached to the
        // last token (not stripped away as trim_end_matches would).
        let v = frame_to_json("*1*2*3####").unwrap();
        assert_eq!(v["who"], "1");
        assert_eq!(v["what"], "2");
        assert_eq!(v["where"], "3##"); // extra `##` retained on the last token
        assert_eq!(v["params"], json!([]));
    }

    #[test]
    fn own_frame_detection() {
        assert!(is_own_frame("*1*0*12##"));
        assert!(is_own_frame("*#1*12##"));
        assert!(!is_own_frame("{\"command\":\"x\"}"));
        assert!(!is_own_frame("*1*0*12")); // no terminator
        assert!(!is_own_frame(""));
    }
}
