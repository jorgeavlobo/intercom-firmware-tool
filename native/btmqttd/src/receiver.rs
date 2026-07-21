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

use crate::config::{Config, OWN_PORT_CMD};
use crate::own;

/// Cap for read_file/write_file/execute_command payloads (256 KB), matching
/// `head -c 262144` in the shell — a huge/special file or runaway command must not
/// balloon memory or blow past the broker's message limit.
const CAP: usize = 262_144;

/// Wall-clock cap for an execute_command child (the shell relied on the reader
/// closing the pipe to SIGPIPE a runaway; we kill explicitly after this).
const EXEC_TIMEOUT: Duration = Duration::from_secs(60);

/// Monotonic suffix so concurrent write_file tasks never share a temp path.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Dispatch one received payload. Empty payloads are ignored (neither a frame nor
/// JSON). Never panics; every failure is logged and swallowed so one bad command
/// can't take the receiver down.
pub async fn dispatch(cfg: &Arc<Config>, client: &AsyncClient, payload: &[u8]) {
    let text = match std::str::from_utf8(payload) {
        Ok(t) => t.trim(),
        Err(_) => {
            eprintln!("btmqttd: ignoring non-UTF-8 command payload");
            return;
        }
    };
    if text.is_empty() {
        return;
    }

    if own::is_own_frame(text) {
        if let Err(e) = forward_to_gateway(text).await {
            eprintln!("btmqttd: forwarding frame to gateway failed: {e}");
        }
    } else {
        handle_json(cfg, client, text).await;
    }
}

/// Forward a raw OpenWebNet frame to the gateway's command-injection port. Always
/// the LOOPBACK gateway (127.0.0.1:30006), as StartMqttReceive did — OWN_HOST is
/// only the monitor (read) endpoint, not the command (write) endpoint.
async fn forward_to_gateway(frame: &str) -> std::io::Result<()> {
    let mut sock = TcpStream::connect(("127.0.0.1", OWN_PORT_CMD)).await?;
    sock.write_all(frame.as_bytes()).await?;
    sock.write_all(b"\n").await?;
    sock.flush().await?;
    Ok(())
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
    let data = v.get("data").and_then(Value::as_str).unwrap_or("");

    match command {
        "read_file" => read_file(cfg, client, file_path).await,
        "write_file" => write_file(file_path, data).await,
        "execute_command" => execute_command(cfg, client, data).await,
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
        Err(e) => eprintln!("btmqttd: write_file task panicked: {e}"),
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
    use std::process::Stdio;
    let mut child = match tokio::process::Command::new("sh")
        .arg("-c")
        .arg(data)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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
    let mut out = child.stdout.take().expect("piped stdout");
    let mut err = child.stderr.take().expect("piped stderr");

    // Read stdout+stderr CONCURRENTLY and stop the moment we have CAP bytes TOTAL —
    // like the shell's `... 2>&1 | head -c 262144`. Reading each to its own CAP with
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
    // child already exited inside `run`. Bounded reap backstop regardless (kill_on_drop
    // is a further guard), so nothing lingers.
    if capped_or_timeout {
        let _ = child.start_kill();
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
    result.truncate(CAP);
    publish(client, &cfg.topic_cmd_result, result, false).await;
}

async fn publish(client: &AsyncClient, topic: &str, payload: Vec<u8>, retain: bool) {
    // QoS 0 — the shell bridge's `mosquitto_pub` default for these diagnostic
    // replies (command result / file content); the command SUBSCRIPTION is the only
    // QoS-1 path.
    if let Err(e) = client.publish(topic, QoS::AtMostOnce, retain, payload).await {
        eprintln!("btmqttd: publish to {topic} failed: {e}");
    }
}
