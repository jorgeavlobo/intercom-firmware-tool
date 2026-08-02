//! Physical key presses -> MQTT: read the front-panel keypad via the kernel evdev
//! interface and publish a small JSON object per key to TOPIC_KEY. Native
//! replacement for keypress.sh (evtest + jq), using the pure-Rust `evdev` crate.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use evdev::{Device, EventType, InputEventKind};
use rumqttc::{AsyncClient, QoS};
use serde_json::json;

use crate::config::Config;
use crate::own;

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
pub async fn run(cfg: Arc<Config>, client: AsyncClient, broker_online: Arc<AtomicBool>) {
    let mut backoff = 0u64;
    let mut last_reason: Option<String> = None;
    loop {
        let start = tokio::time::Instant::now();
        let reason = session(&cfg, &client, &broker_online).await;
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
async fn session(cfg: &Arc<Config>, client: &AsyncClient, broker_online: &AtomicBool) -> String {
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

        // A keypress is a MOMENTARY event, like the door-call events, and rides the SAME shared
        // rumqttc client (issue #71). If the broker is offline, DROP it: a keypress published while
        // disconnected is queued by rumqttc and flushed on the next reconnect, firing a stale HA
        // automation (a code digit, a shortcut) long after the fact. A momentary event has no
        // meaning once stale, so we skip it rather than enqueue for a late replay.
        //
        // Deliberately NO burst-coalescing here, unlike the call events: each keypress is a DISTINCT
        // input — repeated same-key presses ("111") and multi-digit codes must ALL survive — so a
        // debounce would corrupt entry. There is also no repeated-frame artifact to fold: evdev
        // already suppresses held-key auto-repeat (value == 2 is skipped above), so a single
        // physical press yields exactly one `pressed` (and later one `released`).
        if !broker_online.load(Ordering::Relaxed) {
            eprintln!(
                "btmqttd: dropped key {name} ({value}) on {} \
                 (broker offline; not queued for late replay)",
                cfg.topic_key
            );
            continue;
        }

        let payload = key_payload(&name, key.code(), value);

        // Non-blocking (try_publish, not publish().await), mirroring the call events: a press
        // admitted in the pre-detection window (broker just dropped but not yet observed) is either
        // refused here on a full channel or purged from `eventloop.pending` by main's disconnect
        // handler (see is_momentary_publish) — never blocked on the channel and then replayed stale
        // on reconnect. QoS 0, non-retained: fire-once, never re-flushed.
        if let Err(e) =
            client.try_publish(&cfg.topic_key, QoS::AtMostOnce, false, payload.into_bytes())
        {
            eprintln!("btmqttd: publish key failed: {e}");
        }
    }
}

/// Build the key-event payload: the evdev key name, its numeric `code`, the press/release `value`,
/// and a UTC ISO-8601 `ts` (see [`own::utc_now_iso`]) so a consumer can enforce its own freshness
/// TTL — the transport-independent backstop to the offline drop (issue #71).
fn key_payload(name: &str, code: u16, value: &str) -> String {
    json!({ "key": name, "code": code, "value": value, "ts": own::utc_now_iso() }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_payload_carries_key_code_value_and_a_utc_ts() {
        // The published payload must carry the key name, numeric code, press/release value, and a
        // `ts` so a consumer can enforce a freshness TTL (issue #71). Parse it back rather than
        // string-match, so the assertion survives key reordering.
        let v: serde_json::Value =
            serde_json::from_str(&key_payload("KEY_1", 2, "pressed")).unwrap();
        assert_eq!(v["key"], "KEY_1");
        assert_eq!(v["code"], 2);
        assert_eq!(v["value"], "pressed");
        // Validate the COMPLETE UTC ISO-8601 shape `YYYY-MM-DDTHH:MM:SSZ`, not just a trailing Z
        // (which would accept "invalidZ") — this test guards the HA freshness contract (CodeRabbit).
        let ts = v["ts"].as_str().unwrap();
        assert_eq!(ts.len(), 20, "ts must be YYYY-MM-DDTHH:MM:SSZ, got {ts:?}");
        for (i, b) in ts.bytes().enumerate() {
            let ok = match i {
                4 | 7 => b == b'-',
                10 => b == b'T',
                13 | 16 => b == b':',
                19 => b == b'Z',
                _ => b.is_ascii_digit(),
            };
            assert!(ok, "ts malformed at index {i}: {ts:?}");
        }
    }
}
