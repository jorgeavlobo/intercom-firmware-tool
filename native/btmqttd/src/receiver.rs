//! MQTT -> bus: dispatch a message received on TOPIC_RX. A raw OpenWebNet frame is
//! forwarded to the local gateway (127.0.0.1:30006); anything else is a JSON
//! command, honoured ONLY when the gated remote-command channel is unlocked
//! (ALLOW_REMOTE_SHELL=1 AND the client is authenticated). Faithful port of
//! StartMqttReceive's dispatch/handle_json.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rumqttc::{AsyncClient, QoS};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

use crate::config::{Config, OWN_PORT_CMD};
use crate::own;

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
pub async fn dispatch(cfg: &Arc<Config>, client: &AsyncClient, payload: &[u8]) {
    let text = match std::str::from_utf8(payload) {
        Ok(t) => t,
        Err(_) => {
            eprintln!("btmqttd: ignoring non-UTF-8 command payload");
            return;
        }
    };
    for record in text.split('\n') {
        dispatch_record(cfg, client, record).await;
    }
}

/// Classify and act on ONE line (the shell's per-`read` record). `record` keeps its
/// `\r` and any interior/leading/trailing spaces — a space-prefixed " *…##" is not an
/// OWN frame (it falls to the ignored JSON path, as in the shell, rather than being
/// forwarded to the gateway and executed).
async fn dispatch_record(cfg: &Arc<Config>, client: &AsyncClient, record: &str) {
    // Blank / whitespace-only records are neither a frame nor JSON — ignore them.
    if record.trim().is_empty() {
        return;
    }
    if own::is_own_frame(record) {
        if let Err(e) = forward_to_gateway(record).await {
            eprintln!("btmqttd: forwarding frame to gateway failed: {e}");
        }
    } else {
        handle_json(cfg, client, record).await;
    }
}

/// Forward a raw OpenWebNet frame to the gateway's command-injection port. Always
/// the LOOPBACK gateway (127.0.0.1:30006), as StartMqttReceive did — OWN_HOST is
/// only the monitor (read) endpoint, not the command (write) endpoint.
async fn forward_to_gateway(frame: &str) -> std::io::Result<()> {
    tokio::time::timeout(FORWARD_TIMEOUT, async {
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

async fn handle_json(cfg: &Arc<Config>, client: &AsyncClient, msg: &str) {
    if !cfg.remote_shell_allowed() {
        eprintln!(
            "btmqttd: ignored JSON command: remote channel disabled (needs \
             ALLOW_REMOTE_SHELL=1 and an authenticated broker: user/pass or mutual TLS)."
        );
        return;
    }
    let v: Value = match serde_json::from_str(msg) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("btmqttd: ignored non-JSON command payload");
            return;
        }
    };
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
/// called only from the blocking pool (write_file_blocking).
fn create_unique_temp(path: &str, bytes: &[u8]) -> std::io::Result<String> {
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
                f.write_all(bytes)?;
                f.flush()?;
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
fn preserve_mode_owner(target: &str, tmp: &str) {
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
