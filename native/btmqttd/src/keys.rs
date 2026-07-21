//! Physical key presses -> MQTT: read the front-panel keypad via the kernel evdev
//! interface and publish a small JSON object per key to TOPIC_KEY. Native
//! replacement for keypress.sh (evtest + jq), using the pure-Rust `evdev` crate.

use std::sync::Arc;
use std::time::Duration;

use evdev::{Device, EventType, InputEventKind};
use rumqttc::{AsyncClient, QoS};
use serde_json::json;

use crate::config::Config;

/// A capture session that lasted at least this long counts as "healthy": the device
/// was working, so the next reopen is prompt. A session that ended sooner (device
/// absent, immediate read error) backs off. Same duration heuristic as sender::run.
const HEALTHY_SESSION: Duration = Duration::from_secs(60);

/// Locate the keypad event device: the one whose name contains "keypad"
/// (case-insensitive), falling back to /dev/input/event0 — mirroring keypress.sh's
/// auto-detection (the node isn't the same across models; it's event0 on C100X).
fn find_keypad() -> Option<(String, Device)> {
    let mut fallback: Option<(String, Device)> = None;
    for (path, dev) in evdev::enumerate() {
        let p = path.to_string_lossy().to_string();
        let is_keypad = dev
            .name()
            .map(|n| n.to_lowercase().contains("keypad"))
            .unwrap_or(false);
        if is_keypad {
            return Some((p, dev));
        }
        if p == "/dev/input/event0" {
            fallback = Some((p, dev));
        }
    }
    fallback
}

/// Run forever: (re)open the keypad and publish key events, reopening with capped
/// backoff on any failure. The shell relied on TcpDump2Mqtt's pgrep watchdog to
/// respawn keypress.sh; this self-heals instead, so a transient evdev read error or
/// a device that re-enumerates doesn't leave key publishing dead for the daemon's
/// lifetime. A model with no keypad at all just retries quietly (backoff caps at
/// 30s, and the "device absent" reason is logged only once until it changes), so it
/// costs almost nothing while surviving a boot-time race where the node appears late.
pub async fn run(cfg: Arc<Config>, client: AsyncClient) {
    let mut backoff = 0u64;
    let mut last_reason: Option<String> = None;
    loop {
        let start = tokio::time::Instant::now();
        let reason = session(&cfg, &client).await;
        // A long-lived session was healthy: reopen promptly. A quick failure backs off.
        if start.elapsed() >= HEALTHY_SESSION {
            backoff = 0;
        } else {
            backoff = (backoff + 1).min(6);
        }
        // Log the reason only when it changes, so a permanently keypad-less variant
        // doesn't spam the log every backoff interval.
        if last_reason.as_deref() != Some(reason.as_str()) {
            eprintln!("btmqttd: {reason}; retrying key capture");
            last_reason = Some(reason);
        }
        if backoff > 0 {
            tokio::time::sleep(Duration::from_secs(backoff * 5)).await;
        }
    }
}

/// One capture session: open the keypad and publish events until the device can't be
/// opened or a read errors. Returns a short human reason for why it stopped, which
/// run() uses for de-duplicated logging.
async fn session(cfg: &Arc<Config>, client: &AsyncClient) -> String {
    let (path, dev) = match find_keypad() {
        Some(d) => d,
        None => return "no keypad input device found".to_string(),
    };
    let mut events = match dev.into_event_stream() {
        Ok(s) => s,
        Err(e) => return format!("cannot read keypad {path}: {e}"),
    };

    loop {
        let ev = match events.next_event().await {
            Ok(ev) => ev,
            Err(e) => return format!("keypad read error on {path}: {e}"),
        };
        if ev.event_type() != EventType::KEY {
            continue;
        }
        let key = match ev.kind() {
            InputEventKind::Key(k) => k,
            _ => continue,
        };
        // 1 = press, 0 = release; ignore 2 (auto-repeat) and anything unexpected.
        let value = match ev.value() {
            1 => "pressed",
            0 => "released",
            _ => continue,
        };
        // The evdev key name, e.g. "KEY_1" (matches the label evtest printed).
        let name = format!("{:?}", key);
        let payload = json!({ "key": name, "code": key.code(), "value": value }).to_string();
        if let Err(e) = client
            .publish(&cfg.topic_key, QoS::AtMostOnce, false, payload.into_bytes())
            .await
        {
            eprintln!("btmqttd: publish key failed: {e}");
        }
    }
}
