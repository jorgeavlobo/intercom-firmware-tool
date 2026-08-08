//! MQTT -> bus: dispatch a message received on TOPIC_RX. A raw OpenWebNet frame is
//! forwarded to the local gateway (127.0.0.1:30006). A JSON payload is one of two
//! things:
//!   * an UNGATED device-control ACTION (volume / mute / volume_step / lock — issues
//!     #40/#41): these actuate the OWN bus the same way a raw frame on TOPIC_RX
//!     already can (the broker ACL on TOPIC_RX is the trust boundary), so they are
//!     not behind the remote-shell gate; see handle_action for the posture note;
//!   * a GATED shell command (read_file / write_file / execute_command), honoured
//!     ONLY when the remote-command channel is unlocked (ALLOW_REMOTE_SHELL=1 AND the
//!     client is authenticated) — code execution, so it stays locked by default.
//!
//! Extends StartMqttReceive's dispatch/handle_json with the device-control actions.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rumqttc::{AsyncClient, QoS};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use tokio::sync::mpsc::Sender;

use crate::config::{Config, OWN_PORT_CMD};
use crate::light::LightCtl;
use crate::lock::Lock;
use crate::own;
use crate::volume::VolumeCtl;

/// Cap for read_file/write_file/execute_command payloads (256 KB), matching
/// `head -c 262144` in the shell — a huge/special file or runaway command must not
/// balloon memory or blow past the broker's message limit.
const CAP: usize = 262_144;

/// Wall-clock cap for an execute_command child (the shell relied on the reader
/// closing the pipe to SIGPIPE a runaway; we kill explicitly after this).
const EXEC_TIMEOUT: Duration = Duration::from_secs(60);

/// Wall-clock cap for forwarding a frame to the local gateway. The command worker
/// is single and ordered, so a gateway that accepts the connection but stops
/// reading (or hangs on connect) would block write_all/flush with no deadline and
/// stall EVERY subsequent command, not just this frame. Loopback + a tiny payload
/// makes this unlikely, but the bound keeps the worker live regardless.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(5);

/// Monotonic suffix so concurrent write_file tasks never share a temp path.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Fixed cap on command children that are running-or-awaiting-reap at once. A permit
/// is reserved BEFORE spawning the shell (see execute_command), so a flood of
/// CAP-hitting commands whose killed children momentarily block unreaped can't grow the
/// daemon's outstanding-child/task count without limit — the (N+1)-th is rejected.
const REAP_CONCURRENCY: usize = 16;

/// The fixed-capacity permit pool backing REAP_CONCURRENCY. A permit is held from just
/// before spawn until the child is reaped (released inline on a clean finish, or by the
/// reaper task on cap/timeout). `const_new` so it lives in a `static` with no lazy init.
static REAP_SLOTS: Semaphore = Semaphore::const_new(REAP_CONCURRENCY);

/// Dispatch one received payload. The shell receiver looped `while IFS= read -r
/// rxcmd`, so it processed EVERY `\n`-delimited line of a payload IN ORDER — a
/// multi-line message is several records, not one. We split on `\n` and run each
/// record through the same ordered path (`dispatch` is awaited sequentially by the
/// single command worker, so ordering is preserved). `read -r` consumes only the
/// `\n` separator and keeps any other byte, so `\r` is PRESERVED within each record
/// (a CRLF frame `*…##\r` therefore fails the OWN-frame check and is not forwarded,
/// exactly as the shell's `^\*.*##$` did). Never panics; every failure is logged and
/// swallowed so one bad record can't take the receiver down.
pub async fn dispatch(
    cfg: &Arc<Config>,
    client: &AsyncClient,
    vol: &Arc<VolumeCtl>,
    lock: &Sender<Lock>,
    light: Option<&Arc<LightCtl>>,
    payload: &[u8],
) {
    let text = match std::str::from_utf8(payload) {
        Ok(t) => t,
        Err(_) => {
            eprintln!("btmqttd: ignoring non-UTF-8 command payload");
            return;
        }
    };
    for record in text.split('\n') {
        dispatch_record(cfg, client, vol, lock, light, record).await;
    }
}

/// Classify and act on ONE line (the shell's per-`read` record). `record` keeps its
/// `\r` and any interior/leading/trailing spaces — a space-prefixed " *…##" is not an
/// OWN frame (it falls to the ignored JSON path, as in the shell, rather than being
/// forwarded to the gateway and executed).
async fn dispatch_record(
    cfg: &Arc<Config>,
    client: &AsyncClient,
    vol: &Arc<VolumeCtl>,
    lock: &Sender<Lock>,
    light: Option<&Arc<LightCtl>>,
    record: &str,
) {
    // Blank / whitespace-only records are neither a frame nor JSON — ignore them.
    if record.trim().is_empty() {
        return;
    }
    if own::is_own_frame(record) {
        if let Err(e) = forward_to_gateway(record, FORWARD_TIMEOUT).await {
            eprintln!("btmqttd: forwarding frame to gateway failed: {e}");
        }
    } else {
        handle_json(cfg, client, vol, lock, light, record).await;
    }
}

/// Forward a raw OpenWebNet frame to the gateway's command-injection port. Always
/// the LOOPBACK gateway (127.0.0.1:30006), as StartMqttReceive did — OWN_HOST is
/// only the monitor (read) endpoint, not the command (write) endpoint. `pub(crate)`
/// so the lock task (`lock.rs`) can send its press/release frames the same way; it
/// passes a TIGHTER `timeout` so a full press+hold+release pulse fits inside the
/// shutdown drain window (the raw-command path passes [`FORWARD_TIMEOUT`]).
pub(crate) async fn forward_to_gateway(frame: &str, timeout: Duration) -> std::io::Result<()> {
    tokio::time::timeout(timeout, async {
        let mut sock = TcpStream::connect(("127.0.0.1", OWN_PORT_CMD)).await?;
        sock.write_all(frame.as_bytes()).await?;
        sock.write_all(b"\n").await?;
        sock.flush().await?;
        Ok::<_, std::io::Error>(())
    })
    .await
    .map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "gateway forward timed out")
    })?
}

async fn handle_json(
    cfg: &Arc<Config>,
    client: &AsyncClient,
    vol: &Arc<VolumeCtl>,
    lock: &Sender<Lock>,
    light: Option<&Arc<LightCtl>>,
    msg: &str,
) {
    let v: Value = match serde_json::from_str(msg) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("btmqttd: ignored non-JSON command payload");
            return;
        }
    };
    // Device-control ACTIONS (volume / mute / lock) are UNGATED — the broker ACL on
    // TOPIC_RX is the trust boundary. TOPIC_RX is ALREADY a privileged control channel:
    // a raw frame on it is forwarded to the gateway (:30006) with no gate, so a
    // publisher can already actuate WHO=8 commands — including opening a lock
    // (*8*19*20##). The `main_lock`/`secondary_lock` actions here are exactly that same
    // :30006 capability. `volume`/`mute` additionally reach WHO=8 DIMENSION writes on
    // openserver (:20000), a capability a raw :30006 frame does NOT have — but volume is
    // low-stakes and strictly less sensitive than the lock a raw frame can already
    // trigger, so gating only the volume path (while raw frames stay ungated) would add
    // no real security. The arbitrary-shell channel below (read_file/write_file/
    // execute_command) is the one that stays behind ALLOW_REMOTE_SHELL, because it is
    // categorically more dangerous (code execution). These are the payloads the HA
    // volume/lock entities publish (via command_template / payload_press).
    if let Some(action) = v.get("action").and_then(Value::as_str) {
        handle_action(vol, lock, light, action, &v).await;
        return;
    }

    if !cfg.remote_shell_allowed() {
        eprintln!(
            "btmqttd: ignored JSON command: remote channel disabled (needs \
             ALLOW_REMOTE_SHELL=1 and an authenticated broker: user/pass or mutual TLS)."
        );
        return;
    }
    let command = v.get("command").and_then(Value::as_str).unwrap_or("");
    let file_path = v.get("file_path").and_then(Value::as_str).unwrap_or("");
    // `data` as Option: a MISSING (or non-string) key is rejected per-command rather
    // than defaulting to "". Defaulting silently truncates a write_file target to
    // empty and runs execute_command as `sh -c ""` — dangerous on a remote command
    // surface. An EXPLICIT "data":"" is still honoured (an intentional truncate / no-op).
    let data = v.get("data").and_then(Value::as_str);

    match command {
        "read_file" => read_file(cfg, client, file_path).await,
        "write_file" => match data {
            Some(d) => write_file(file_path, d).await,
            None => eprintln!("btmqttd: write_file: missing 'data'"),
        },
        "execute_command" => match data {
            Some(d) => execute_command(cfg, client, d).await,
            None => eprintln!("btmqttd: execute_command: missing 'data'"),
        },
        "" => eprintln!("btmqttd: JSON command missing 'command'"),
        other => eprintln!("btmqttd: unsupported command: {other}"),
    }
}

/// Handle an ungated device-control action (issue #40 volume, #41 lock). `v` is the
/// already-parsed action object; `action` is its `action` field. Unknown actions are
/// logged and ignored. A volume op that fails (gateway refused/unreachable) is logged;
/// the retained state stays whatever the monitor last observed, so HA is never left
/// showing a value the device didn't accept.
/// A parsed device-control action — the PURE classification of a JSON action object,
/// separated from the async dispatch so it can be unit-tested without a live gateway or
/// broker. Values are already validated/normalised (volume clamped/rounded, step
/// reduced to a direction).
#[derive(Debug, PartialEq, Eq)]
enum Action {
    /// Absolute volume set, `0..=100` — the slider `number`.
    Volume(u8),
    /// Mute (`true`) / unmute (`false`) — the mute `switch`.
    Mute(bool),
    /// Relative step: up (`true`) / down (`false`) — the ± `button`s. Only the SIGN of
    /// the JSON value matters (the step size is owned device-side).
    Step(bool),
    /// Momentary door-entry lock pulse (issue #41) — the Main/Secondary Lock `button`s.
    /// The variant carries WHICH actuator so one queue/task serialises both.
    Lock(Lock),
    /// Stair-light SWITCH desired state — `on` (`true`) / `off` (`false`). The daemon
    /// toggles the actuator only when the tracked state differs (see `light.rs`). Bistable only.
    Light(bool),
    /// Stair-light PRESS (momentary install): forward the actuator frame once to turn ON — the
    /// physical staircase timer switches it off. No state (see `light.rs`).
    LightPress,
    /// Stair-light RESYNC button: correct the tracked state (unknown→on→off→on) WITHOUT
    /// actuating the relay — realigns HA to the wall after a cold boot / missed press.
    LightResync,
    /// Stair-light LEARN button: open the capture window so the next physical press teaches
    /// the actuator WHERE (for a unit that shipped without a known WHERE).
    LightLearn,
}

/// Classify a JSON action object (`{"action":<name>,"value":…}`) into an [`Action`], or
/// `None` when the action name is unknown or its value is missing/invalid. Pure — the
/// async dispatch (device write / lock enqueue) lives in [`handle_action`].
fn parse_action(action: &str, v: &Value) -> Option<Action> {
    match action {
        "volume" => v.get("value").and_then(json_percent).map(Action::Volume),
        "mute" => match v.get("value").and_then(Value::as_str) {
            Some("on") => Some(Action::Mute(true)),
            Some("off") => Some(Action::Mute(false)),
            _ => None,
        },
        "volume_step" => match v.get("value").and_then(Value::as_i64) {
            Some(d) if d > 0 => Some(Action::Step(true)),
            Some(d) if d < 0 => Some(Action::Step(false)),
            _ => None,
        },
        "main_lock" => Some(Action::Lock(Lock::Main)),
        "secondary_lock" => Some(Action::Lock(Lock::Secondary)),
        "light" => match v.get("value").and_then(Value::as_str) {
            Some("on") => Some(Action::Light(true)),
            Some("off") => Some(Action::Light(false)),
            _ => None,
        },
        // Stateless BUTTON presses — no "value" field.
        "light_press" => Some(Action::LightPress),
        "light_resync" => Some(Action::LightResync),
        "light_learn" => Some(Action::LightLearn),
        _ => None,
    }
}

async fn handle_action(
    vol: &Arc<VolumeCtl>,
    lock: &Sender<Lock>,
    light: Option<&Arc<LightCtl>>,
    action: &str,
    v: &Value,
) {
    match parse_action(action, v) {
        Some(Action::Volume(n)) => log_action_err("volume", vol.set(n).await),
        Some(Action::Mute(on)) => log_action_err("mute", vol.mute(on).await),
        Some(Action::Step(up)) => log_action_err("volume_step", vol.step(up).await),
        // Enqueue a pulse request (WHICH lock) to the dedicated lock task (lock.rs),
        // which serialises press→hold→release off the command worker and is drained on
        // shutdown so the release always follows. Full => a burst faster than it can
        // pulse (drop, don't block the worker); Closed => the task is gone (shutting down).
        Some(Action::Lock(which)) => match lock.try_send(which) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                eprintln!("btmqttd: lock press dropped — pulse queue full");
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
        },
        // Stair-light SWITCH: set the desired absolute state. The controller toggles the
        // actuator only when the tracked state differs (no-op when already there). Ignored
        // if the feature is off (no WHERE configured) — the action shouldn't arrive then,
        // as the installer omits the entity, but stay defensive.
        Some(Action::Light(on)) => match light {
            Some(l) => l.command(on).await,
            None => eprintln!("btmqttd: ignored 'light' action — light feature not configured"),
        },
        // Momentary press: forward one ON pulse; the installation's timer owns the off.
        Some(Action::LightPress) => match light {
            Some(l) => l.press().await,
            None => eprintln!("btmqttd: ignored 'light_press' — light feature not configured"),
        },
        // Resync: correct the tracked state only (no relay actuation). Learn: open the WHERE
        // capture window. Both no-op when the light feature is off.
        Some(Action::LightResync) => match light {
            Some(l) => l.resync().await,
            None => eprintln!("btmqttd: ignored 'light_resync' — light feature not configured"),
        },
        Some(Action::LightLearn) => match light {
            Some(l) => l.learn().await,
            None => eprintln!("btmqttd: ignored 'light_learn' — light feature not configured"),
        },
        None => eprintln!(
            "btmqttd: ignored action {action:?} (unknown, or missing/invalid value {:?})",
            v.get("value")
        ),
    }
}

/// Parse a volume percent (0..=100) from a JSON number. Accepts an integer OR a
/// float: the installer's slider `command_template` renders `{{ value | int }}` (an
/// integer), but Home Assistant `number` entities carry the value as a float and
/// another publisher (or a hand-crafted payload) could still send `50.0`, so a float
/// is accepted DEFENSIVELY — rounded to the nearest integer. Both forms are clamped
/// to 0..=100. Returns `None` for a non-number or a non-finite float (NaN/∞).
fn json_percent(v: &Value) -> Option<u8> {
    if let Some(n) = v.as_u64() {
        return Some(n.min(100) as u8);
    }
    let f = v.as_f64()?;
    if !f.is_finite() {
        return None;
    }
    Some(f.round().clamp(0.0, 100.0) as u8)
}

/// Log a device-control action's error without aborting the worker (best-effort, like
/// the rest of the receiver): a failed set/step leaves HA on the last observed state.
fn log_action_err(action: &str, r: std::io::Result<()>) {
    if let Err(e) = r {
        eprintln!("btmqttd: action {action} failed: {e}");
    }
}

async fn read_file(cfg: &Arc<Config>, client: &AsyncClient, path: &str) {
    if path.is_empty() {
        eprintln!("btmqttd: read_file: missing file_path");
        return;
    }
    // Read at most CAP bytes — `.take(CAP)` bounds BOTH the MQTT payload and the RAM
    // used, so a huge or /proc-style file can't balloon memory (unlike reading the
    // whole file then truncating). Mirrors `head -c 262144`.
    let content = match tokio::fs::File::open(path).await {
        Ok(f) => {
            let mut buf = Vec::new();
            let mut capped = f.take(CAP as u64);
            if let Err(e) = capped.read_to_end(&mut buf).await {
                eprintln!("btmqttd: read_file {path}: {e}");
            }
            buf
        }
        Err(e) => {
            eprintln!("btmqttd: read_file {path}: {e}");
            Vec::new()
        }
    };
    publish(client, &cfg.topic_file_content, content, false).await;
}

async fn write_file(path: &str, data: &str) {
    if path.is_empty() {
        eprintln!("btmqttd: write_file: missing file_path");
        return;
    }
    let path = path.to_string();
    let bytes = data.as_bytes()[..data.len().min(CAP)].to_vec();
    // Do ALL the filesystem work on the blocking pool: open/chmod/chown/rename are
    // synchronous syscalls that would otherwise stall the single-threaded runtime
    // (delaying MQTT keepalives and other tasks).
    match tokio::task::spawn_blocking(move || write_file_blocking(&path, &bytes)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("btmqttd: write_file: {e}"),
        // JoinError is either a panic or a cancellation/abort; either way the write
        // didn't complete. Report it generically rather than asserting "panicked".
        Err(e) => eprintln!("btmqttd: write_file task did not complete: {e}"),
    }
}

/// Synchronous write-then-rename (runs on the blocking pool). Writes to a UNIQUE
/// 0600 temp in the same directory (O_EXCL, so concurrent write_file tasks for the
/// same path never share/clobber a temp inode), matches the existing file's
/// mode/owner (best-effort), then atomically renames over the target.
fn write_file_blocking(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = create_unique_temp(path, bytes)?;
    preserve_mode_owner(path, &tmp);
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Create a fresh 0600 temp file (O_EXCL) beside `path` and write `bytes`, retrying
/// on the vanishingly unlikely name collision. Returns the temp path. Synchronous —
/// called only from the blocking pool (write_file_blocking, and rediscovery's hosts
/// rewrite).
pub(crate) fn create_unique_temp(path: &str, bytes: &[u8]) -> std::io::Result<String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let pid = std::process::id();
    for _ in 0..8 {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = format!("{path}.tmp.{pid}.{seq}");
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true) // O_EXCL: never reuse another writer's temp
            .mode(0o600)
            .open(&tmp)
        {
            Ok(mut f) => {
                // Write + flush + fsync BEFORE the caller renames over the target, so a crash
                // right after the rename can't leave the new name pointing at unwritten/zeroed
                // data (CodeRabbit). A no-op on tmpfs (the hosts rewrite), a durability
                // guarantee on the persistent cfg partition. On ANY failure, remove the temp
                // before returning so repeated retries can't accumulate .tmp files and fill
                // the partition (CodeRabbit).
                let write = (|| -> std::io::Result<()> {
                    f.write_all(bytes)?;
                    f.flush()?;
                    f.sync_all()
                })();
                if let Err(e) = write {
                    drop(f);
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e);
                }
                return Ok(tmp);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not create a unique temp file",
    ))
}

/// Best-effort: copy the existing target's mode and owner/group onto `tmp` so a
/// replace preserves them (as the shell's stat + chmod/chown did). Silent on error.
pub(crate) fn preserve_mode_owner(target: &str, tmp: &str) {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(target) {
        let _ = std::fs::set_permissions(tmp, std::fs::Permissions::from_mode(meta.mode() & 0o7777));
        // chown via libc (std has no owner setter). Best-effort; ignore failure.
        if let Ok(ctmp) = std::ffi::CString::new(tmp) {
            unsafe {
                libc::chown(ctmp.as_ptr(), meta.uid(), meta.gid());
            }
        }
    }
}

async fn execute_command(cfg: &Arc<Config>, client: &AsyncClient, data: &str) {
    // Run `sh -c "$data"` — the gated remote-command channel's whole purpose is to
    // run operator-supplied shell (identical to StartMqttReceive's `sh -c "$data"`),
    // reachable only when remote_shell_allowed() already held. stdin from /dev/null
    // so a command reading stdin can't swallow later work. Bound BOTH memory (stop at
    // CAP TOTAL bytes) and time (kill after EXEC_TIMEOUT), then reap the child.
    //
    // Reserve a cleanup permit BEFORE spawning, so the number of command children that
    // are running-or-awaiting-reap is HARD-bounded by REAP_CONCURRENCY. If none is free
    // (that many children still outstanding — e.g. earlier kills stuck in D-state), we
    // REJECT this command rather than spawn a shell we couldn't explicitly own and reap.
    // The single ordered worker means at most one child is actually running at a time;
    // the rest of the budget covers killed children still being awaited.
    let permit = match REAP_SLOTS.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            let msg =
                b"btmqttd: execute_command rejected: too many outstanding command children".to_vec();
            publish(client, &cfg.topic_cmd_result, msg, false).await;
            return;
        }
    };
    use std::process::Stdio;
    let mut child = match tokio::process::Command::new("sh")
        .arg("-c")
        .arg(data)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Put the shell in its OWN process group (pgid == its pid). On timeout/CAP we
        // SIGKILL the whole group, not just the shell PID — otherwise a command like
        // `sleep 300; echo done` or a pipeline leaves grandchildren running (reparented
        // to init) after we publish the result, defeating the wall-clock/CAP bound and
        // leaking processes on repeated timeouts.
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("btmqttd: execute_command failed to spawn: {e}");
            publish(client, &cfg.topic_cmd_result, msg.into_bytes(), false).await;
            return;
        }
    };
    // stdout/stderr are Some by construction (Stdio::piped() above), but handle None
    // gracefully rather than panicking — the module's contract is "never panics".
    let (Some(mut out), Some(mut err)) = (child.stdout.take(), child.stderr.take()) else {
        eprintln!("btmqttd: execute_command: child stdout/stderr pipe missing");
        let _ = child.start_kill();
        reap(child, permit); // reaper owns the child + its permit until reaped
        return;
    };

    // Read stdout+stderr CONCURRENTLY and stop the moment we have CAP bytes TOTAL —
    // like the shell's `... 2>&1 | head -c 262144` in the ONE sense that matters here:
    // a single combined diagnostic blob capped at CAP total bytes. We do NOT reproduce
    // the shell's exact merged-stream byte order — reading two separate pipes
    // interleaves by ARRIVAL order (arguably closer to real time than a buffered pipe),
    // and a command that writes to both streams may see them interleaved differently.
    // That's fine: the result is an opaque diagnostic blob, not a stream whose
    // stdout/stderr ordering is contractual. Reading each to its own CAP with
    // join! would instead WAIT for the second stream even after the first is full:
    // a command that writes >CAP to stdout and keeps running blocks on the (now
    // unread) full stdout pipe and never closes stderr, so join! would hang until the
    // timeout and drop the output we already had. Exiting at CAP total (then killing
    // the child below) returns the first 256 KB promptly instead.
    // One future for the WHOLE lifecycle — read up to CAP total, and (only when both
    // streams close before the cap) WAIT for the process to finish its side-effecting
    // work — under a SINGLE EXEC_TIMEOUT deadline. Doing the wait inside this future
    // (rather than a second timeout after it) keeps the total wall-clock at one
    // EXEC_TIMEOUT and the FIFO command worker isn't held for ~2x that. Returns
    // (bytes, hit_cap).
    let run = async {
        let mut buf: Vec<u8> = Vec::new();
        let mut ob = [0u8; 8192];
        let mut eb = [0u8; 8192];
        let mut out_open = true;
        let mut err_open = true;
        while buf.len() < CAP && (out_open || err_open) {
            tokio::select! {
                r = out.read(&mut ob), if out_open => match r {
                    Ok(0) | Err(_) => out_open = false,
                    Ok(n) => {
                        let take = (CAP - buf.len()).min(n);
                        buf.extend_from_slice(&ob[..take]);
                    }
                },
                r = err.read(&mut eb), if err_open => match r {
                    Ok(0) | Err(_) => err_open = false,
                    Ok(n) => {
                        let take = (CAP - buf.len()).min(n);
                        buf.extend_from_slice(&eb[..take]);
                    }
                },
            }
        }
        let capped = buf.len() >= CAP;
        // Clean EOF before the cap: the command may have redirected/closed its output
        // early yet still be doing work (e.g. `exec >/dev/null 2>&1; sleep 5; touch …`)
        // — let it finish rather than killing it (matches the shell). Bounded by the
        // shared timeout wrapping this whole future.
        if !capped {
            let _ = child.wait().await;
        }
        (buf, capped)
    };

    let (mut result, capped_or_timeout) = match tokio::time::timeout(EXEC_TIMEOUT, run).await {
        Ok((buf, capped)) => (buf, capped),
        // Timed out (slow producer, or a quiet command running past the deadline).
        Err(_) => (b"btmqttd: execute_command timed out".to_vec(), true),
    };
    // Kill only when we stopped at the cap or hit the timeout; on a clean finish the
    // child already exited (and was reaped by child.wait) inside `run`.
    if capped_or_timeout {
        // SIGKILL the whole process GROUP (pgid == the shell's pid, set via
        // process_group(0) at spawn), so any children/pipeline the shell spawned die
        // too — not just the shell.
        match child.id() {
            Some(pid) => {
                let rc = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
                if rc != 0 {
                    let err = std::io::Error::last_os_error();
                    // ESRCH just means the group is already gone (the shell and its
                    // children exited on their own) — benign; reap() collects the
                    // zombie. Any OTHER error (e.g. EPERM) means the group may still be
                    // alive, so fall back to killing the direct child, otherwise it (and
                    // its REAP_SLOTS permit) could linger and stall further commands.
                    if err.raw_os_error() != Some(libc::ESRCH) {
                        eprintln!("btmqttd: killpg({pid}) failed: {err}; killing the shell directly");
                        let _ = child.start_kill();
                    }
                }
            }
            None => {
                let _ = child.start_kill();
            }
        }
        // Hand the killed child + its permit to the bounded reaper, which awaits it to
        // completion (explicit, not tokio's best-effort drop-time cleanup) and releases
        // the permit only once collected — so the slot stays reserved while the child
        // is still outstanding.
        reap(child, permit);
    } else {
        // Clean finish: the child already exited and was reaped by child.wait inside
        // `run`. No reaper task needed — just release the permit.
        drop(child);
        drop(permit);
    }
    result.truncate(CAP);
    publish(client, &cfg.topic_cmd_result, result, false).await;
}

/// Reap a killed command child, awaiting it to completion in a short-lived task that
/// carries the caller's cleanup `permit`. The permit was reserved (in execute_command)
/// BEFORE the shell was spawned, so the count of command children that are
/// running-or-awaiting-reap is hard-bounded by REAP_CONCURRENCY: the daemon never
/// spawns a child it can't explicitly own, and never falls back to tokio's
/// non-guaranteed best-effort drop-time cleanup. The permit is released when the wait
/// resolves — a normally-exiting or freshly-SIGKILLed child is collected at once.
///
/// A truly D-stuck process (uninterruptible kernel I/O) holds its process-table slot
/// until the kernel releases it no matter how it's waited; while stuck, its permit
/// stays taken, so further execute_command requests are REJECTED up-front — that is
/// the bound. (This channel is a gated, authenticated `sh -c` surface, so the bound is
/// about the daemon's own resources, not a defense against an operator who can already
/// run any command.)
fn reap(child: tokio::process::Child, permit: tokio::sync::SemaphorePermit<'static>) {
    tokio::spawn(async move {
        let _permit = permit; // released once the wait resolves
        let mut child = child;
        let _ = child.wait().await;
    });
}

async fn publish(client: &AsyncClient, topic: &str, payload: Vec<u8>, retain: bool) {
    // QoS 0 — the shell bridge's `mosquitto_pub` default for these diagnostic
    // replies (command result / file content); the command SUBSCRIPTION is the only
    // QoS-1 path.
    if let Err(e) = client.publish(topic, QoS::AtMostOnce, retain, payload).await {
        eprintln!("btmqttd: publish to {topic} failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The per-record classification dispatch_record() applies: a record is forwarded
    /// to the gateway as an OWN frame only when it is non-blank AND is_own_frame().
    /// Otherwise it goes to the (gated / possibly-ignored) JSON path. Encodes the
    /// shell parity boundary without needing the network.
    fn is_frame(record: &str) -> bool {
        !record.trim().is_empty() && own::is_own_frame(record)
    }

    /// Mirror dispatch()'s payload → records split so tests can assert per-line
    /// behaviour (the shell's `while IFS= read -r` loop).
    fn records(payload: &str) -> Vec<&str> {
        payload.split('\n').collect()
    }

    #[test]
    fn json_percent_accepts_int_and_float_clamped_and_rounded() {
        use serde_json::json;
        // Integer values pass through, clamped to 0..=100.
        assert_eq!(json_percent(&json!(0)), Some(0));
        assert_eq!(json_percent(&json!(50)), Some(50));
        assert_eq!(json_percent(&json!(100)), Some(100));
        assert_eq!(json_percent(&json!(150)), Some(100)); // clamp
        // Floats (what an HA `number` slider renders via `{{ value }}`) are rounded.
        assert_eq!(json_percent(&json!(50.0)), Some(50));
        assert_eq!(json_percent(&json!(49.6)), Some(50)); // round to nearest
        assert_eq!(json_percent(&json!(120.0)), Some(100)); // clamp after round
        assert_eq!(json_percent(&json!(-5.0)), Some(0)); // clamp low
        // Non-numbers / non-finite are rejected (fall to the invalid-value path).
        assert_eq!(json_percent(&json!("50")), None);
        assert_eq!(json_percent(&json!(null)), None);
    }

    #[test]
    fn parse_action_classifies_the_control_surface() {
        use serde_json::json;
        // volume: int or float, clamped/rounded (via json_percent).
        assert_eq!(parse_action("volume", &json!({"value": 50})), Some(Action::Volume(50)));
        assert_eq!(parse_action("volume", &json!({"value": 49.6})), Some(Action::Volume(50)));
        assert_eq!(parse_action("volume", &json!({"value": 150})), Some(Action::Volume(100)));
        // mute: only "on"/"off".
        assert_eq!(parse_action("mute", &json!({"value": "on"})), Some(Action::Mute(true)));
        assert_eq!(parse_action("mute", &json!({"value": "off"})), Some(Action::Mute(false)));
        // volume_step: only the SIGN matters.
        assert_eq!(parse_action("volume_step", &json!({"value": 10})), Some(Action::Step(true)));
        assert_eq!(parse_action("volume_step", &json!({"value": -10})), Some(Action::Step(false)));
        assert_eq!(parse_action("volume_step", &json!({"value": -1})), Some(Action::Step(false)));
        // locks: no value needed; each name maps to its actuator.
        assert_eq!(parse_action("main_lock", &json!({})), Some(Action::Lock(Lock::Main)));
        assert_eq!(
            parse_action("main_lock", &json!({"value": "ignored"})),
            Some(Action::Lock(Lock::Main))
        );
        assert_eq!(
            parse_action("secondary_lock", &json!({})),
            Some(Action::Lock(Lock::Secondary))
        );
        // light: on/off only.
        assert_eq!(parse_action("light", &json!({"value": "on"})), Some(Action::Light(true)));
        assert_eq!(parse_action("light", &json!({"value": "off"})), Some(Action::Light(false)));
        // light stateless buttons: press (momentary), resync, learn — no "value" field.
        assert_eq!(parse_action("light_press", &json!({})), Some(Action::LightPress));
        assert_eq!(parse_action("light_resync", &json!({})), Some(Action::LightResync));
        assert_eq!(parse_action("light_learn", &json!({})), Some(Action::LightLearn));
    }

    #[test]
    fn parse_action_rejects_unknown_and_invalid() {
        use serde_json::json;
        // Unknown action name.
        assert_eq!(parse_action("nope", &json!({"value": 1})), None);
        assert_eq!(parse_action("", &json!({})), None);
        // volume: missing / non-numeric / non-finite value.
        assert_eq!(parse_action("volume", &json!({})), None);
        assert_eq!(parse_action("volume", &json!({"value": "x"})), None);
        // mute: value other than on/off.
        assert_eq!(parse_action("mute", &json!({"value": "maybe"})), None);
        assert_eq!(parse_action("mute", &json!({"value": 1})), None);
        // volume_step: zero (no direction) / missing / non-integer.
        assert_eq!(parse_action("volume_step", &json!({"value": 0})), None);
        assert_eq!(parse_action("volume_step", &json!({})), None);
        assert_eq!(parse_action("volume_step", &json!({"value": "up"})), None);
    }

    #[test]
    fn crlf_frame_is_not_forwarded() {
        // `IFS= read -r` keeps the trailing \r, so `*…##\r` failed `^\*.*##$` and was
        // NOT forwarded. A naive \r/\n trim would have promoted it to a live command.
        assert!(!is_frame("*1*0*12##\r"));
        // A bare-LF (or no) terminator is the record separator the shell consumed —
        // the frame IS recognised.
        assert!(is_frame("*1*0*12##"));
    }

    #[test]
    fn every_line_is_a_record_second_line_forwarded() {
        // The shell looped over EVERY line, so junk on line 1 is ignored and a valid
        // frame on line 2 is still forwarded — btmqttd must not drop the 2nd record.
        let r = records("junk\n*1*0*12##");
        assert_eq!(r.len(), 2);
        assert!(!is_frame(r[0])); // "junk" -> JSON path -> ignored
        assert!(is_frame(r[1])); // frame -> forwarded
    }

    #[test]
    fn crlf_is_preserved_per_record() {
        // A CRLF-separated pair: record 0 keeps its \r (not forwarded), record 1 is a
        // clean LF-terminated frame (forwarded).
        let r = records("*1*0*12##\r\n*2*1*3##");
        assert_eq!(r, vec!["*1*0*12##\r", "*2*1*3##"]);
        assert!(!is_frame(r[0]));
        assert!(is_frame(r[1]));
    }

    #[test]
    fn blank_and_space_prefixed_records_ignored() {
        assert!(!is_frame("")); // empty record
        assert!(!is_frame("   ")); // whitespace-only
        assert!(!is_frame(" *1*0*12##")); // leading space -> JSON path, not a frame
        // A trailing blank record (from a trailing '\n') is ignored, not an error.
        let r = records("*1*0*12##\n");
        assert_eq!(r, vec!["*1*0*12##", ""]);
        assert!(is_frame(r[0]));
        assert!(!is_frame(r[1]));
    }
}
