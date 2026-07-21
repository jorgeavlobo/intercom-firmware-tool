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
            if let Err(e) = f.take(CAP as u64).read_to_end(&mut buf).await {
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
    let bytes = &data.as_bytes()[..data.len().min(CAP)];
    // Write to a UNIQUE temp in the same directory then rename, so a crash mid-write
    // can't leave a partial file and concurrent write_file tasks for the same path
    // never share (and clobber) a temp inode. Created 0600 with O_EXCL; then match
    // the existing file's mode/owner (best-effort) so replacing e.g. the 0600 config
    // or a bticino-owned file doesn't change them.
    let tmp = match create_unique_temp(path, bytes).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("btmqttd: write_file temp for {path}: {e}");
            return;
        }
    };
    preserve_mode_owner(path, &tmp);
    if let Err(e) = tokio::fs::rename(&tmp, path).await {
        eprintln!("btmqttd: write_file rename -> {path}: {e}");
        let _ = tokio::fs::remove_file(&tmp).await;
    }
}

/// Create a fresh 0600 temp file (O_EXCL) beside `path` and write `bytes`, retrying
/// on the vanishingly unlikely name collision. Returns the temp path.
async fn create_unique_temp(path: &str, bytes: &[u8]) -> std::io::Result<String> {
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
            Ok(std_file) => {
                let mut f = tokio::fs::File::from_std(std_file);
                f.write_all(bytes).await?;
                f.flush().await?;
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
    // so a command reading stdin can't swallow later work. Bound BOTH memory (cap
    // each stream at CAP, read concurrently to avoid a full-pipe deadlock) and time
    // (kill after EXEC_TIMEOUT), then reap the child.
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
    let out = child.stdout.take().expect("piped stdout");
    let err = child.stderr.take().expect("piped stderr");

    let collect = async {
        let mut ov = Vec::new();
        let mut ev = Vec::new();
        // Bind the capped readers so they outlive the join's awaits; concurrent so
        // neither full pipe blocks the other; each capped at CAP.
        let mut out_take = out.take(CAP as u64);
        let mut err_take = err.take(CAP as u64);
        let _ = tokio::join!(
            out_take.read_to_end(&mut ov),
            err_take.read_to_end(&mut ev),
        );
        ov.extend_from_slice(&ev);
        ov
    };

    let mut result = match tokio::time::timeout(EXEC_TIMEOUT, collect).await {
        Ok(buf) => buf,
        Err(_) => b"btmqttd: execute_command timed out".to_vec(),
    };
    // ALWAYS kill then reap, under their own bounded timeout: the capped readers can
    // hit CAP (or the whole collect can time out) while the child keeps running or is
    // blocked on a now-unread full pipe, so a bare child.wait() could hang forever and
    // the result would never be published. start_kill (SIGKILL) unblocks it; the
    // bounded wait reaps without hanging (kill_on_drop is a further backstop).
    let _ = child.start_kill();
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
