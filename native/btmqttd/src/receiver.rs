//! MQTT -> bus: dispatch a message received on TOPIC_RX. A raw OpenWebNet frame is
//! forwarded to the local gateway (127.0.0.1:30006); anything else is a JSON
//! command, honoured ONLY when the gated remote-command channel is unlocked
//! (ALLOW_REMOTE_SHELL=1 AND the client is authenticated). Faithful port of
//! StartMqttReceive's dispatch/handle_json.

use std::sync::Arc;

use rumqttc::{AsyncClient, QoS};
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::config::{Config, OWN_PORT_CMD};
use crate::own;

/// Cap for read_file/write_file/execute_command payloads (256 KB), matching
/// `head -c 262144` in the shell — a huge/special file or runaway command must not
/// balloon memory or blow past the broker's message limit.
const CAP: usize = 262_144;

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
        if let Err(e) = forward_to_gateway(&cfg.own_host, text).await {
            eprintln!("btmqttd: forwarding frame to gateway failed: {e}");
        }
    } else {
        handle_json(cfg, client, text).await;
    }
}

/// Forward a raw OpenWebNet frame to the gateway's command port (127.0.0.1:30006),
/// terminated with a newline as the shell's `nc` did.
async fn forward_to_gateway(host: &str, frame: &str) -> std::io::Result<()> {
    let mut sock = TcpStream::connect((host, OWN_PORT_CMD)).await?;
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
    // Cap at 256 KB, like `head -c 262144` (guards huge or /proc-style files).
    let content = match tokio::fs::read(path).await {
        Ok(mut b) => {
            b.truncate(CAP);
            b
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
    // Write to a temp in the same directory then rename, so a crash mid-write can't
    // leave a partial file. umask-equivalent: create 0600 so it's never briefly
    // world-readable; then match the existing file's mode/owner (best-effort) so
    // replacing e.g. the 0600 config or a bticino-owned file doesn't change them.
    let tmp = format!("{path}.tmp.{}", std::process::id());
    if let Err(e) = write_private(&tmp, bytes).await {
        eprintln!("btmqttd: write_file temp {tmp}: {e}");
        let _ = tokio::fs::remove_file(&tmp).await;
        return;
    }
    preserve_mode_owner(path, &tmp);
    if let Err(e) = tokio::fs::rename(&tmp, path).await {
        eprintln!("btmqttd: write_file rename -> {path}: {e}");
        let _ = tokio::fs::remove_file(&tmp).await;
    }
}

/// Create a file 0600 and write `bytes`.
async fn write_private(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    use tokio::io::AsyncWriteExt;
    let std_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    let mut f = tokio::fs::File::from_std(std_file);
    f.write_all(bytes).await?;
    f.flush().await?;
    Ok(())
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
    // Run `sh -c "$data"` with stdin from /dev/null (so a command reading stdin
    // can't swallow later MQTT payloads). Capture stdout+stderr, cap at 256 KB.
    use std::process::Stdio;
    let out = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(data)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await;
    let mut result = match out {
        Ok(o) => {
            let mut b = o.stdout;
            b.extend_from_slice(&o.stderr);
            b
        }
        Err(e) => format!("btmqttd: execute_command failed to spawn: {e}").into_bytes(),
    };
    result.truncate(CAP);
    publish(client, &cfg.topic_cmd_result, result, false).await;
}

async fn publish(client: &AsyncClient, topic: &str, payload: Vec<u8>, retain: bool) {
    if let Err(e) = client.publish(topic, QoS::AtLeastOnce, retain, payload).await {
        eprintln!("btmqttd: publish to {topic} failed: {e}");
    }
}
