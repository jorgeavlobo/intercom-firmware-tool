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

/// WHO=8 ENTRANCE-PANEL CALL command: `*8*1#1#4#21*<WHERE>##` (RE — captured on a live
/// Classe 100X, matching fquinto's Classe 300X `*8*1#1#4#21*16##`). The WHAT
/// (`1#1#4#21`) is the stable entrance-panel-call signature; the WHERE (the entrance-panel
/// address, e.g. `112`/`16`) varies per install, so it is NOT matched — it is returned for
/// information. This is the outdoor door-station ("betoneira") call.
const ENTRANCE_PANEL_CALL_WHAT: &str = "1#1#4#21";

/// WHO=8 FLOOR-CALL command: `*8*1#13#2*<WHERE>##` (RE — captured live on a Classe unit
/// with a dumb push-button wired to the unit's floor-call terminals; the ring-start frame
/// was `*8*1#13#2*10##` byte-for-byte on 3/3 presses, and the entrance-panel call NEVER
/// emits this WHAT). The WHAT (`1#13#2`) is the stable floor-call signature — BTicino's
/// "chiamata al piano", the local front-door bell, distinct from the entrance panel. The
/// WHERE (`10` observed) is returned for information, not matched.
const FLOOR_CALL_WHAT: &str = "1#13#2";

/// WHO=8 dimension carrying the CALL STATE, broadcast as a call progresses:
/// `*#8**35*<N>*0*0##`. Confirmed against live captures of both an ANSWERED and an
/// unanswered call: `0` idle/ended, `1`/`2`/`4` the pre-answer ringing phases, `6`
/// answered/in-call (it appeared exactly when the call was picked up, and never on the
/// unanswered call which went `1->2->4->0`). See [`call_state_label`]; the raw code also
/// travels as an attribute for finer granularity (door-entry RE).
const CALL_STATE_DIM: &str = "35";

/// Match a WHO=8 CALL command `*8*<WHAT>*<WHERE>##` for the EXACT `what`, returning the
/// WHERE. The WHAT must be followed immediately by the `*` before WHERE (so a longer WHAT
/// with `what` as a prefix can't match), and WHERE must be a single non-empty field —
/// rejecting the empty (`…*##`) and extended (`…*112*X##`) forms so neither fires a
/// spurious event. Returns `None` for a dimension report (`*#8**…`), a different WHAT
/// (e.g. the `9#…` ring-STOP), or any other frame.
fn parse_who8_call<'a>(frame: &'a str, what: &str) -> Option<&'a str> {
    let body = frame.strip_prefix("*8*")?.strip_suffix("##")?;
    let where_ = body.strip_prefix(what)?.strip_prefix('*')?;
    if where_.is_empty() || where_.contains('*') {
        return None;
    }
    Some(where_)
}

/// Match the ENTRANCE-PANEL call `*8*1#1#4#21*<WHERE>##` (the outdoor door station) and
/// return the WHERE (the panel address). `None` for any other frame.
pub fn parse_entrance_panel_call(frame: &str) -> Option<&str> {
    parse_who8_call(frame, ENTRANCE_PANEL_CALL_WHAT)
}

/// Match the FLOOR call `*8*1#13#2*<WHERE>##` (the local front-door button on the unit's
/// floor-call terminals) and return the WHERE. Disjoint from the entrance-panel WHAT, so
/// the two never cross-fire. `None` for any other frame.
pub fn parse_floor_call(frame: &str) -> Option<&str> {
    parse_who8_call(frame, FLOOR_CALL_WHAT)
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

/// The dimension-REQUEST frame that asks the gateway for the current call state.
/// Confirmed on a live Classe 300X: `*#8**35##` -> `*#8**35*<N>*0*0##` (e.g. `*35*0*…`
/// idle, `*35*6*…` in-call), i.e. dim-35 answers a GET authoritatively (not push-only).
pub fn call_state_read_request() -> String {
    format!("*#8**{CALL_STATE_DIM}##")
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

/// What the caller should do with a dim-35 call-state code, per [`CallClassifier`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CallStateAction {
    /// Publish this code to the (entrance-panel) call-state sensor.
    Publish(u8),
    /// Swallow it — it belongs to a FLOOR call (or a not-yet-classified ring being held),
    /// which must never surface on the entrance-panel call-state sensor.
    Suppress,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum CallKind {
    /// No call in progress.
    #[default]
    Idle,
    /// A ring started (`code` 1/2) but the source is not yet known — the classifying WHO=8
    /// frame (`*8*1#1#4#21*…` entrance vs `*8*1#13#2*…` floor) always arrives ONE frame
    /// later, so the first ringing code is HELD until then. `code` is the held ring code.
    Pending(u8),
    /// Classified as an entrance-panel call → publish call-state normally.
    Entrance,
    /// Classified as a floor call → suppress call-state until the ring ends.
    Floor,
}

/// Routes the SHARED dim-35 call-state stream to the entrance-panel sensor ONLY.
///
/// Both an entrance-panel call and a floor call drive dim-35 (`1→2→…→0`), and in BOTH the
/// first `*#8**35*1*…` (ringing) arrives BEFORE the classifying WHO=8 frame. To keep the
/// floor call entirely off the entrance-panel `call_state` sensor without leaking that
/// leading "ringing", the first ring code is HELD (`Pending`) until the classifier is seen:
/// an entrance signature flushes the held code and publishes normally; a floor signature
/// discards it and suppresses the rest. Frame-driven, no timers. The instance is owned by `run()`
/// but RESET to `Idle` at the start of each monitor session ([`Self::on_reconnect`]): a monitor
/// outage can end one call and begin another in the gap, so no classification is trustworthy across
/// it — the authoritative reconcile (see [`Self::reconcile_snapshot`]) and post-reconnect live
/// frames re-establish state from scratch, which is what keeps a floor call off this sensor even
/// across reconnects.
#[derive(Default)]
pub struct CallClassifier {
    state: CallKind,
}

impl CallClassifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// The entrance-panel signature (`*8*1#1#4#21*…`) was seen. Classify as entrance and, if
    /// a ring code was being held, return it so the caller can now publish it.
    pub fn saw_entrance_panel_call(&mut self) -> Option<u8> {
        let held = match self.state {
            CallKind::Pending(code) => Some(code),
            _ => None,
        };
        self.state = CallKind::Entrance;
        held
    }

    /// The floor-call signature (`*8*1#13#2*…`) was seen. Classify as floor; any held ring
    /// code is DISCARDED (never published), so the entrance-panel sensor stays idle.
    pub fn saw_floor_call(&mut self) {
        self.state = CallKind::Floor;
    }

    /// Called at the start of each monitor session. A monitor outage loses EVERY frame in the gap,
    /// so a call in progress before it may have ENDED and a DIFFERENT one begun. No classification
    /// carried across the reconnect can therefore be trusted for the current dim-35 reading — a
    /// stale `Floor`, `Entrance`, OR `Pending` would mis-handle a new call and could publish a floor
    /// call's ring onto the entrance-panel sensor. Reset to `Idle`: the authoritative reconcile then
    /// suppresses ambiguous rings (`1`/`2`) and publishes only definitive entrance-only phases
    /// (`4`/`6`), while live frames after the reconnect reclassify from scratch (Codex). Cost: an
    /// entrance call merely RINGING across a reconnect is not shown until it is answered (`4`/`6`),
    /// a live signature arrives, or it goes idle — the accepted price of never leaking a floor call.
    pub fn on_reconnect(&mut self) {
        self.state = CallKind::Idle;
    }

    /// A dim-35 call-state `code` arrived. Decide whether it reaches the entrance-panel
    /// sensor. `0` (idle/ended) always publishes and resets. A leading ring-start `1` is HELD
    /// (pending classification) — including from a stale `Entrance` (a previous call's terminal
    /// `0` was missed), so the NEXT call's leading ring can't be mis-published before its
    /// signature resolves it. A second unclassified ring, or a `4`/`6` (which only an entrance
    /// call reaches), defaults to entrance rather than risk hiding a real call.
    pub fn on_call_state(&mut self, code: u8) -> CallStateAction {
        match code {
            0 => {
                self.state = CallKind::Idle;
                CallStateAction::Publish(0)
            }
            1 | 2 => match self.state {
                CallKind::Idle => {
                    self.state = CallKind::Pending(code);
                    CallStateAction::Suppress
                }
                // A second ring with no classifier yet: prefer showing a real call over
                // hiding one — treat as entrance and publish.
                CallKind::Pending(_) => {
                    self.state = CallKind::Entrance;
                    CallStateAction::Publish(code)
                }
                // A fresh ring-START (`1`) from a stale TERMINAL state (Entrance OR Floor — the
                // previous call's terminal `0` was missed, leaving us wedged) begins a NEW call of
                // unknown type. RE-HOLD it as Pending so the following signature classifies it
                // (entrance flushes it via `saw_entrance_panel_call`, floor discards it), instead of
                // publishing a floor ring as entrance (from Entrance) or silently dropping an
                // entrance ring (from Floor) (Codex). Safe for a genuine repeated `1` mid-call: the
                // retained sensor keeps its last value during the one-frame hold and the next frame
                // republishes — no idle flicker. (A leading ring is always `1`; a floor call's own
                // sequence is `1 → 2 → 0`, so `Floor + 1` only ever means a new call, never a
                // continuation.)
                CallKind::Entrance | CallKind::Floor if code == 1 => {
                    self.state = CallKind::Pending(1);
                    CallStateAction::Suppress
                }
                // A `2` from Entrance is a mid-call progression of the SAME entrance call → publish;
                // a `2` from Floor is a floor-call continuation → stays suppressed.
                CallKind::Entrance => CallStateAction::Publish(code),
                CallKind::Floor => CallStateAction::Suppress,
            },
            // 4/6 (answered/in-call phases) are reached ONLY by an entrance-panel call — a floor
            // call's sequence is `1 → 2 → 0`. So either is DEFINITIVE evidence of an entrance call:
            // (re)classify to Entrance and publish, even from a stale `Floor` left by a floor call
            // whose terminal `0` was missed across a monitor reconnect. Suppressing here would hide a
            // real entrance call until its terminal idle (Codex).
            4 | 6 => {
                self.state = CallKind::Entrance;
                CallStateAction::Publish(code)
            }
            // Any OTHER code (`3`/`5`/`7` — never observed for door entry, mapped to the "active"
            // label). An unrecognised code is NOT definitive evidence of an entrance call, so it must
            // not reclassify a KNOWN floor call — honour "a floor call never reaches this sensor".
            // From any other state, fall back to showing it as an entrance call (CodeRabbit).
            _ => match self.state {
                CallKind::Floor => CallStateAction::Suppress,
                _ => {
                    self.state = CallKind::Entrance;
                    CallStateAction::Publish(code)
                }
            },
        }
    }

    /// Reconcile an AUTHORITATIVE dim-35 snapshot `code` — read directly from the gateway,
    /// OUT-OF-BAND from the live frame stream (the reconnect/poll/reseed reconcile) — against the
    /// current classification, returning whether it may reach the entrance-panel sensor.
    ///
    /// - `0` (idle) is gateway truth that no call is active: RESET to `Idle` and publish. Repairs a
    ///   missed live terminal `0` (otherwise the classifier would linger and mis-handle the next call).
    /// - `4`/`6` (answered/in-call) are entrance-ONLY phases — a floor call never emits them — so an
    ///   out-of-band read of one is DEFINITIVE entrance evidence: (re)classify to `Entrance` and
    ///   publish, from ANY state. This is exactly the case the poll/reconnect reconcile exists to
    ///   repair — a real entrance call whose live frames were missed, even from a stale `Floor`
    ///   (Codex/Copilot).
    /// - `1`/`2` (ringing) are AMBIGUOUS — floor and entrance share them, and out-of-band there is no
    ///   signature to disambiguate. Publish ONLY when the call is already KNOWN to be entrance
    ///   (`Entrance`); from every other state (`Floor`, `Pending`, or a fresh `Idle` at reconnect)
    ///   SUPPRESS, so a floor call's ringing can never leak onto the entrance-panel sensor — the
    ///   feature's hard rule (Codex). Cost: a genuine entrance call merely RINGING across a reconnect
    ///   is not shown until it is answered (`4`/`6`), a live signature arrives, or it goes idle — an
    ///   acceptable trade for never leaking a floor call.
    ///
    /// `0` and `4`/`6` mutate the classification; a `1`/`2` snapshot does not (it is an out-of-band
    /// read, not a live transition — feeding it into [`Self::on_call_state`] would spuriously hold it
    /// as `Pending`).
    pub fn reconcile_snapshot(&mut self, code: u8) -> CallStateAction {
        match code {
            0 => {
                self.state = CallKind::Idle;
                CallStateAction::Publish(0)
            }
            4 | 6 => {
                self.state = CallKind::Entrance;
                CallStateAction::Publish(code)
            }
            // 1/2 (ambiguous ring) AND any unrecognised code (`3`/`5`/`7`): publish only from a KNOWN
            // Entrance; from every other state suppress — an out-of-band unknown code is not evidence
            // enough to override Floor or to assume entrance from a fresh Idle (CodeRabbit).
            _ => match self.state {
                CallKind::Entrance => CallStateAction::Publish(code),
                _ => CallStateAction::Suppress,
            },
        }
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

/// Like [`session`], but returns AS SOON AS a reply frame satisfies `parse` — it does not
/// wait out the [`REPLY_IDLE`] tail after the report. For a single-report GET this makes the
/// call return at the snapshot instant instead of ~500 ms later, which matters for the
/// call-state reconcile: it shrinks the window in which the monitor read is blocked (so a light
/// echo isn't buffered past its guard, Codex) and removes the gap in which a monitor transition
/// arriving during the tail would be newer than this snapshot yet published before it (Codex).
/// Still bounded by [`SESSION_TIMEOUT`]; returns `None` if the reply burst ends with no match.
async fn session_first<T>(
    host: &str,
    port: u16,
    frame: &str,
    parse: impl Fn(&str) -> Option<T>,
) -> std::io::Result<Option<T>> {
    let fut = async {
        let mut sock = TcpStream::connect((host, port)).await?;
        sock.write_all(COMMAND_REQ).await?;
        sock.write_all(frame.as_bytes()).await?;
        sock.flush().await?;

        let mut framer = Framer::default();
        let mut out: Vec<String> = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            match tokio::time::timeout(REPLY_IDLE, sock.read(&mut buf)).await {
                Ok(Ok(0)) => break, // gateway closed the session
                Ok(Ok(n)) => {
                    framer.push(&buf[..n], &mut out);
                    if let Some(found) = out.iter().find_map(|f| parse(f)) {
                        return Ok(Some(found)); // report in hand — return without the idle wait
                    }
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => break, // idle: reply burst is complete, no match
            }
        }
        Ok(None)
    };
    tokio::time::timeout(SESSION_TIMEOUT, fut).await.map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "own command session timed out")
    })?
}

/// Read the current call state via a dimension request (`*#8**35##`). Returns the
/// reported code, or `None` if the gateway gave no valid call-state report (session
/// refused). This is the AUTHORITATIVE source used to reconcile the retained sensor,
/// so a missed transition frame (or a reconnect mid-call) can't leave HA stuck. Returns
/// PROMPTLY on the report (see [`session_first`]) rather than waiting out the reply idle gap.
pub async fn read_call_state(host: &str, port: u16) -> std::io::Result<Option<u8>> {
    session_first(host, port, &call_state_read_request(), parse_call_state).await
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
    fn parses_entrance_panel_call_and_returns_where() {
        // Captured on a live Classe 100X; WHERE varies per install.
        assert_eq!(parse_entrance_panel_call("*8*1#1#4#21*112##"), Some("112"));
        // fquinto's Classe 300X used the SAME WHAT, a different WHERE.
        assert_eq!(parse_entrance_panel_call("*8*1#1#4#21*16##"), Some("16"));
    }

    #[test]
    fn rejects_non_entrance_panel_call_frames() {
        // Other WHO=8 commands seen in the same capture must NOT trigger the entrance call.
        assert_eq!(parse_entrance_panel_call("*8*9#1#4*20##"), None);
        assert_eq!(parse_entrance_panel_call("*8*3#1#4*420##"), None);
        assert_eq!(parse_entrance_panel_call("*8*19*20##"), None);
        // A near-miss WHAT must not match (prefix guard).
        assert_eq!(parse_entrance_panel_call("*8*1#1#4#210*112##"), None);
        // An empty WHERE or an extended frame with extra '*' fields must not match.
        assert_eq!(parse_entrance_panel_call("*8*1#1#4#21*##"), None);
        assert_eq!(parse_entrance_panel_call("*8*1#1#4#21*112*X##"), None);
        // Dimension reports and other WHOs are not entrance-call commands.
        assert_eq!(parse_entrance_panel_call("*#8**35*1*0*0##"), None);
        assert_eq!(parse_entrance_panel_call("*7*55*##"), None);
        assert_eq!(parse_entrance_panel_call("garbage"), None);
        // The FLOOR-call WHAT must NOT be read as an entrance-panel call.
        assert_eq!(parse_entrance_panel_call("*8*1#13#2*10##"), None);
    }

    #[test]
    fn parses_floor_call_and_returns_where() {
        // Captured live: byte-for-byte on 3/3 presses of the floor-call button.
        assert_eq!(parse_floor_call("*8*1#13#2*10##"), Some("10"));
        // WHERE is informational, not matched — a different WHERE still parses.
        assert_eq!(parse_floor_call("*8*1#13#2*42##"), Some("42"));
    }

    #[test]
    fn rejects_non_floor_call_frames() {
        // The floor-call ring-STOP (`9#13#2`) is not the ring-START.
        assert_eq!(parse_floor_call("*8*9#13#2*410##"), None);
        // The ENTRANCE-panel WHAT must NOT be read as a floor call (the two are disjoint).
        assert_eq!(parse_floor_call("*8*1#1#4#21*112##"), None);
        // Near-miss WHAT (prefix guard), empty/extended WHERE.
        assert_eq!(parse_floor_call("*8*1#13#20*10##"), None);
        assert_eq!(parse_floor_call("*8*1#13#2*##"), None);
        assert_eq!(parse_floor_call("*8*1#13#2*10*X##"), None);
        // Dimension reports and other WHOs.
        assert_eq!(parse_floor_call("*#8**35*1*0*0##"), None);
        assert_eq!(parse_floor_call("*7*58#14#0#0#1*##"), None);
        assert_eq!(parse_floor_call("garbage"), None);
    }

    #[test]
    fn classifier_suppresses_a_floor_call_entirely() {
        // The captured floor-call sequence: the leading ring (1) arrives BEFORE the
        // classifier, so it is HELD; the floor signature then discards it; 2 and (final) 0
        // never surface a "ringing" — only the terminating idle publishes.
        let mut c = CallClassifier::new();
        assert_eq!(c.on_call_state(1), CallStateAction::Suppress); // held (pending)
        c.saw_floor_call(); // classified floor -> held ring discarded
        assert_eq!(c.on_call_state(2), CallStateAction::Suppress);
        assert_eq!(c.on_call_state(0), CallStateAction::Publish(0)); // idle (harmless, already idle)
    }

    #[test]
    fn classifier_preserves_the_entrance_panel_call() {
        // The captured entrance sequence: the held leading ring (1) is FLUSHED when the
        // entrance signature arrives, then 2 -> 4 -> 0 publish normally.
        let mut c = CallClassifier::new();
        assert_eq!(c.on_call_state(1), CallStateAction::Suppress); // held (pending)
        assert_eq!(c.saw_entrance_panel_call(), Some(1)); // flush the held ring
        assert_eq!(c.on_call_state(2), CallStateAction::Publish(2));
        assert_eq!(c.on_call_state(4), CallStateAction::Publish(4));
        assert_eq!(c.on_call_state(6), CallStateAction::Publish(6));
        assert_eq!(c.on_call_state(0), CallStateAction::Publish(0));
    }

    #[test]
    fn classifier_defaults_to_entrance_when_the_classifier_is_missing() {
        // Defensive: a second ring with no classifier seen must NOT hide a real call.
        let mut c = CallClassifier::new();
        assert_eq!(c.on_call_state(1), CallStateAction::Suppress); // held
        assert_eq!(c.on_call_state(2), CallStateAction::Publish(2)); // promote to entrance
        // A 4/6 straight from idle (no preceding ring) also publishes.
        let mut c2 = CallClassifier::new();
        assert_eq!(c2.on_call_state(4), CallStateAction::Publish(4));
    }

    #[test]
    fn reconcile_snapshot_ambiguous_ring_only_publishes_from_entrance() {
        // A fresh classifier (reconnect) SUPPRESSES an ambiguous ringing snapshot (1/2) — it could be
        // a floor call, and a floor call must never leak onto the entrance sensor...
        let mut c = CallClassifier::new();
        assert_eq!(c.reconcile_snapshot(1), CallStateAction::Suppress);
        assert_eq!(c.reconcile_snapshot(2), CallStateAction::Suppress);
        // ...but an entrance-ONLY phase (4/6) is definitive → publish + reclassify from fresh Idle...
        assert_eq!(c.reconcile_snapshot(6), CallStateAction::Publish(6));
        // ...and an idle snapshot always publishes (and resets).
        assert_eq!(c.reconcile_snapshot(0), CallStateAction::Publish(0));
        // A KNOWN entrance call publishes even an ambiguous ring snapshot.
        let mut e = CallClassifier::new();
        e.saw_entrance_panel_call();
        assert_eq!(e.reconcile_snapshot(2), CallStateAction::Publish(2));
    }

    #[test]
    fn reconcile_snapshot_suppresses_during_floor_and_pending() {
        // A classified floor call suppresses a ringing snapshot (the reseed-during-floor leak)...
        let mut c = CallClassifier::new();
        c.saw_floor_call();
        assert_eq!(c.reconcile_snapshot(1), CallStateAction::Suppress);
        assert_eq!(c.reconcile_snapshot(2), CallStateAction::Suppress);
        // A still-Pending (held leading ring, not yet classified) also suppresses — publishing the
        // out-of-band ringing could pre-empt a floor signature still in flight and leak.
        let mut p = CallClassifier::new();
        assert_eq!(p.on_call_state(1), CallStateAction::Suppress); // Pending(1)
        assert_eq!(p.reconcile_snapshot(2), CallStateAction::Suppress);
    }

    #[test]
    fn a_floor_call_after_a_missed_terminal_frame_is_still_held() {
        // Stuck-Entrance repair on the LIVE path: an entrance call's terminal `0` is missed, so the
        // classifier lingers in Entrance. A floor call then starts BEFORE the authoritative poll
        // reconciles. Its leading ring-start `1` must be HELD (not published as an entrance ring),
        // then the floor signature discards it — the floor call never surfaces on the sensor.
        let mut c = CallClassifier::new();
        c.saw_entrance_panel_call(); // classified entrance; its terminal 0 is then missed
        assert_eq!(c.on_call_state(1), CallStateAction::Suppress); // NEW leading ring re-held
        c.saw_floor_call();
        assert_eq!(c.on_call_state(2), CallStateAction::Suppress);
        assert_eq!(c.on_call_state(0), CallStateAction::Publish(0));
        // Contrast: a `2` from Entrance is a same-call continuation and still publishes.
        let mut e = CallClassifier::new();
        e.saw_entrance_panel_call();
        assert_eq!(e.on_call_state(2), CallStateAction::Publish(2));
    }

    #[test]
    fn an_entrance_call_after_a_missed_floor_terminal_frame_is_reclassified() {
        // Mirror of the stuck-Entrance case: a floor call's terminal `0` is missed, so the
        // classifier lingers in Floor. An entrance call then starts before the reseed reconciles.
        // Its leading ring-start `1` must be RE-HELD (not silently dropped) so the entrance
        // signature can flush it — otherwise the entrance ring would never surface.
        let mut c = CallClassifier::new();
        c.saw_floor_call(); // classified floor; its terminal 0 is then missed
        assert_eq!(c.on_call_state(1), CallStateAction::Suppress); // NEW leading ring re-held
        assert_eq!(c.saw_entrance_panel_call(), Some(1)); // flushed as a real entrance ring
        assert_eq!(c.on_call_state(2), CallStateAction::Publish(2));
        assert_eq!(c.on_call_state(0), CallStateAction::Publish(0));
        // A floor continuation `2` from stale Floor still stays suppressed (not a new call).
        let mut f = CallClassifier::new();
        f.saw_floor_call();
        assert_eq!(f.on_call_state(2), CallStateAction::Suppress);
        // But an entrance-ONLY phase (4/6) from a stale Floor is definitive evidence of an entrance
        // call (a floor call never emits these) → publish and reclassify, don't suppress.
        let mut g = CallClassifier::new();
        g.saw_floor_call();
        assert_eq!(g.on_call_state(4), CallStateAction::Publish(4));
        assert_eq!(g.on_call_state(6), CallStateAction::Publish(6));
        assert_eq!(g.on_call_state(0), CallStateAction::Publish(0));
        // An UNRECOGNISED code (never observed) is NOT definitive entrance evidence, so it must not
        // reclassify a known floor call — stays suppressed on both the live and snapshot paths.
        let mut u = CallClassifier::new();
        u.saw_floor_call();
        assert_eq!(u.on_call_state(5), CallStateAction::Suppress);
        assert_eq!(u.reconcile_snapshot(5), CallStateAction::Suppress);
    }

    #[test]
    fn on_reconnect_resets_every_classification_to_idle() {
        // A monitor outage can end one call and start another in the gap, so NO carried-over state
        // is trustworthy — reset all of Pending/Floor/Entrance to Idle. After the reset, an ambiguous
        // ring snapshot is suppressed (proving no stale Entrance can leak a new floor call's ring),
        // and a new leading ring is held afresh.
        for setup in [0u8, 1, 4] {
            let mut c = CallClassifier::new();
            match setup {
                1 => {
                    c.on_call_state(1); // Pending
                }
                4 => {
                    c.on_call_state(4); // Entrance
                }
                _ => c.saw_floor_call(), // Floor
            }
            c.on_reconnect();
            // Reset to Idle → an ambiguous authoritative ring is suppressed (no leak from stale state)...
            assert_eq!(c.reconcile_snapshot(2), CallStateAction::Suppress);
            // ...and a fresh leading ring is HELD (Idle → Pending), not published.
            assert_eq!(c.on_call_state(1), CallStateAction::Suppress);
        }
    }

    #[test]
    fn reconcile_snapshot_idle_resets_the_classifier() {
        // The missed-terminal-frame repair: a stuck Entrance classifier is reset to Idle by an
        // authoritative idle snapshot, so the NEXT floor call's leading ring is HELD (not published
        // as a false entrance ring).
        let mut c = CallClassifier::new();
        c.saw_entrance_panel_call(); // state = Entrance (its terminal 0 was missed)
        assert_eq!(c.reconcile_snapshot(0), CallStateAction::Publish(0)); // discovers idle + resets
        // Proof of reset: a subsequent leading ring is now HELD (Pending), not published.
        assert_eq!(c.on_call_state(1), CallStateAction::Suppress);
        c.saw_floor_call();
        assert_eq!(c.on_call_state(2), CallStateAction::Suppress);
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
        // The entrance-panel / floor call commands are not dimension reports.
        assert_eq!(parse_call_state("*8*1#1#4#21*112##"), None);
        assert_eq!(parse_call_state("*8*1#13#2*10##"), None);
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
