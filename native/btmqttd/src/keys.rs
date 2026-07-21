//! Physical key presses -> MQTT: read the front-panel keypad via the kernel evdev
//! interface and publish a small JSON object per key to TOPIC_KEY. Native
//! replacement for keypress.sh (evtest + jq), using the pure-Rust `evdev` crate.

use std::sync::Arc;

use evdev::{Device, EventType, InputEventKind};
use rumqttc::{AsyncClient, QoS};
use serde_json::json;

use crate::config::Config;

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

/// Run forever: read key events and publish them. If the keypad can't be opened
/// (absent on some variant) this logs once and returns — the rest of the bridge is
/// unaffected.
pub async fn run(cfg: Arc<Config>, client: AsyncClient) {
    let (path, dev) = match find_keypad() {
        Some(d) => d,
        None => {
            eprintln!("btmqttd: no keypad input device found; key publishing disabled");
            return;
        }
    };
    let mut events = match dev.into_event_stream() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("btmqttd: cannot read keypad {path}: {e}");
            return;
        }
    };

    loop {
        let ev = match events.next_event().await {
            Ok(ev) => ev,
            Err(e) => {
                eprintln!("btmqttd: keypad read error on {path}: {e}");
                return;
            }
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
