//! Home Assistant MQTT discovery: reconcile the retained discovery configs from the
//! installer-generated manifest. Native replacement for ha_discovery.sh.
//!
//! The installer writes `/etc/tcpdump2mqtt/ha/manifest` — one
//! `config-topic<TAB>filename` line per entity — plus the JSON payload files. When
//! HA_DISCOVERY=1 we PUBLISH each config retained (HA auto-creates the entities);
//! when 0 we CLEAR them (empty retained payload) so an opt-out removes them.
//!
//! Runs on every (re)connect (in the birth sequence), so a broker that was down at
//! boot is reconciled as soon as it returns — no separate marker/watchdog needed.

use std::path::Path;
use std::sync::Arc;

use rumqttc::{AsyncClient, QoS};

use crate::config::{Config, HA_DIR};

/// Publish or clear the discovery configs. Best-effort: logs and continues on a
/// per-row error, so one bad entry can't block the others or the birth sequence.
pub async fn reconcile(cfg: &Arc<Config>, client: &AsyncClient) {
    let manifest_path = format!("{HA_DIR}/manifest");
    let manifest = match tokio::fs::read_to_string(&manifest_path).await {
        Ok(m) if !m.trim().is_empty() => m,
        Ok(_) => {
            eprintln!("btmqttd: ha manifest {manifest_path} is empty");
            return;
        }
        Err(e) => {
            eprintln!("btmqttd: ha manifest {manifest_path}: {e}");
            return;
        }
    };

    let action = if cfg.ha_discovery { "published" } else { "cleared" };
    let mut applied = 0usize;
    for line in manifest.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Some((topic, file)) = line.split_once('\t') else {
            eprintln!("btmqttd: ha malformed manifest row");
            continue;
        };
        let (topic, file) = (topic.trim(), file.trim());
        if topic.is_empty() || file.is_empty() {
            eprintln!("btmqttd: ha malformed manifest row");
            continue;
        }
        // Defence-in-depth: require a plain basename so a tampered filename can't
        // escape HA_DIR (e.g. "../TcpDump2Mqtt.conf" leaking config).
        if file.contains('/') || file == ".." {
            eprintln!("btmqttd: ha unsafe filename in manifest: {file}");
            continue;
        }

        let ok = if cfg.ha_discovery {
            match tokio::fs::read(Path::new(HA_DIR).join(file)).await {
                Ok(payload) => publish(client, topic, payload).await,
                Err(e) => {
                    eprintln!("btmqttd: ha missing {HA_DIR}/{file}: {e}");
                    false
                }
            }
        } else {
            // Clear: empty retained payload makes the broker drop the config.
            publish(client, topic, Vec::new()).await
        };
        if ok {
            applied += 1;
        }
    }
    eprintln!("btmqttd: ha discovery {action} {applied} config(s)");
}

/// Publish a retained config (or an empty retained payload to clear it).
async fn publish(client: &AsyncClient, topic: &str, payload: Vec<u8>) -> bool {
    match client.publish(topic, QoS::AtLeastOnce, true, payload).await {
        Ok(()) => true,
        Err(e) => {
            eprintln!("btmqttd: ha publish to {topic} failed: {e}");
            false
        }
    }
}
