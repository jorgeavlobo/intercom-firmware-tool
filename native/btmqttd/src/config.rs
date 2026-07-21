//! Configuration: parse the same `/etc/tcpdump2mqtt/TcpDump2Mqtt.conf` the shell
//! bridge used, so the App UI and `MqttInstaller` config generation don't change.
//!
//! The file is a POSIX-sh `KEY=value` fragment (the shell `source`d it). We do NOT
//! run a shell — we parse the small, fixed set of keys the installer writes:
//! `KEY=value`, optionally single- or double-quoted, one per line, `#` comments and
//! blank lines ignored. The installer writes it 0600 root:root on a read-only
//! rootfs, so it is a trusted, machine-written file (see the header in the .conf).

use std::collections::HashMap;
use std::path::Path;

pub const DEFAULT_CFG_PATH: &str = "/etc/tcpdump2mqtt/TcpDump2Mqtt.conf";

/// The OpenWebNet gateway's command-injection port (raw frames received over MQTT
/// are forwarded here). Fixed, as in StartMqttReceive (`OWN_PORT=30006`).
pub const OWN_PORT_CMD: u16 = 30006;

/// Directory holding the Home Assistant discovery manifest + payloads.
pub const HA_DIR: &str = "/etc/tcpdump2mqtt/ha";

#[derive(Debug, Clone)]
pub struct Config {
    // Broker
    pub mqtt_host: String,
    pub mqtt_port: u16,
    pub mqtt_user: Option<String>,
    pub mqtt_pass: Option<String>,
    // TLS
    pub ca_file: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    // Topics
    pub topic_rx: String,
    pub topic_dump: String,
    pub topic_startd: String,
    pub topic_lastwill: String,
    pub topic_key: String,
    pub topic_cmd_result: String,
    pub topic_file_content: String,
    // OpenWebNet monitor endpoint (bus -> MQTT)
    pub own_host: String,
    pub own_port_mon: u16,
    // Behaviour
    pub payload_json: bool,
    pub ha_discovery: bool,
    pub allow_remote_shell: bool,
    pub client_id: Option<String>,
}

impl Config {
    /// Load from the default path, or from `$BTMQTTD_CONF` when set (tests/dev).
    pub fn load() -> Result<Config, String> {
        let path = std::env::var("BTMQTTD_CONF").unwrap_or_else(|_| DEFAULT_CFG_PATH.to_string());
        Config::load_from(&path)
    }

    pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Config, String> {
        let text = std::fs::read_to_string(path.as_ref())
            .map_err(|e| format!("cannot read {}: {e}", path.as_ref().display()))?;
        Ok(Config::from_map(parse_env(&text)))
    }

    /// Build a Config from a parsed key/value map, applying the same defaults as
    /// `mqtt_common.sh` (topic defaults, PAYLOAD_FORMAT=json, CAPTURE socket, etc.).
    pub fn from_map(m: HashMap<String, String>) -> Config {
        // A value that is present but empty means "unset" (the shell treated
        // MQTT_USER= as empty and skipped auth), so collapse "" to None.
        let opt = |k: &str| -> Option<String> {
            m.get(k).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
        };
        let get = |k: &str, d: &str| -> String { opt(k).unwrap_or_else(|| d.to_string()) };
        let flag = |k: &str| -> bool { opt(k).as_deref() == Some("1") };

        Config {
            mqtt_host: get("MQTT_HOST", ""),
            mqtt_port: opt("MQTT_PORT").and_then(|s| s.parse().ok()).unwrap_or(1883),
            mqtt_user: opt("MQTT_USER"),
            mqtt_pass: opt("MQTT_PASS"),
            ca_file: opt("MQTT_CAFILE"),
            cert_file: opt("MQTT_CERTFILE"),
            key_file: opt("MQTT_KEYFILE"),
            topic_rx: get("TOPIC_RX", "Bticino/rx"),
            topic_dump: get("TOPIC_DUMP", "Bticino/tx"),
            topic_startd: get("TOPIC_STARTD", "Bticino/start_date"),
            topic_lastwill: get("TOPIC_LASTWILL", "Bticino/LastWillT"),
            topic_key: get("TOPIC_KEY", "Bticino/key"),
            topic_cmd_result: get("TOPIC_CMD_RESULT", "Bticino/command_result_topic"),
            topic_file_content: get("TOPIC_FILE_CONTENT", "Bticino/file_content_topic"),
            own_host: get("OWN_HOST", "127.0.0.1"),
            own_port_mon: opt("OWN_PORT_MON").and_then(|s| s.parse().ok()).unwrap_or(20000),
            // PAYLOAD_FORMAT defaults to json (mqtt_common.sh); anything but "raw" is json.
            payload_json: opt("PAYLOAD_FORMAT").as_deref() != Some("raw"),
            ha_discovery: flag("HA_DISCOVERY"),
            allow_remote_shell: flag("ALLOW_REMOTE_SHELL"),
            client_id: opt("MQTT_CLIENT_ID"),
        }
    }

    /// The JSON remote-command channel is honoured only when explicitly enabled AND
    /// the CLIENT is authenticated: username+password, or mutual TLS (CA + cert +
    /// key). One-way TLS (CA only) verifies the broker, not the client — it does NOT
    /// unlock the channel. Mirrors `remote_shell_allowed` in mqtt_common.sh exactly.
    pub fn remote_shell_allowed(&self) -> bool {
        if !self.allow_remote_shell {
            return false;
        }
        if self.mqtt_user.is_some() && self.mqtt_pass.is_some() {
            return true;
        }
        self.ca_file.is_some() && self.cert_file.is_some() && self.key_file.is_some()
    }

    /// True when the broker connection uses TLS (a CA file is configured).
    pub fn uses_tls(&self) -> bool {
        self.ca_file.is_some()
    }

    /// Mutual-TLS client credentials, when both a client cert and key are set.
    pub fn client_auth_files(&self) -> Option<(&str, &str)> {
        match (&self.cert_file, &self.key_file) {
            (Some(c), Some(k)) => Some((c.as_str(), k.as_str())),
            _ => None,
        }
    }

    /// The MQTT client id. An operator override (`MQTT_CLIENT_ID`) wins; otherwise a
    /// short, stable, per-unit id derived from the LWT topic. With atomic birth/will
    /// on one connection we use a CLEAN session, so the long injective hex id the
    /// shell needed for durable-session resume (and its 23-byte portability problem)
    /// is gone — a readable, sanitised id suffices (see issue #32).
    pub fn client_id(&self) -> String {
        if let Some(id) = &self.client_id {
            return id.clone();
        }
        let mut s = String::from("btmqttd-");
        for c in self.topic_lastwill.chars() {
            s.push(if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' });
        }
        // Keep well within the MQTT 3.1.1 23-byte guidance where possible.
        if s.len() > 23 {
            s.truncate(23);
        }
        s
    }
}

/// Parse a POSIX-sh `KEY=value` fragment into a map. Supports `#` comments, blank
/// lines, optional surrounding single/double quotes, and a leading `export `. This
/// is deliberately NOT a shell: values with metacharacters are taken literally
/// (the installer never writes such values into this trusted file).
pub fn parse_env(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, val)) = line.split_once('=') else { continue };
        let key = key.trim();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let mut val = val.trim();
        // Strip a trailing inline comment only for UNquoted values (a '#' inside
        // quotes is literal). The installer doesn't emit inline comments, but be
        // lenient about a hand-edited file.
        if !(val.starts_with('"') || val.starts_with('\'')) {
            if let Some(idx) = val.find(" #") {
                val = val[..idx].trim_end();
            }
        }
        let val = unquote(val);
        map.insert(key.to_string(), val);
    }
    map
}

/// Remove one layer of matching single or double quotes.
fn unquote(v: &str) -> String {
    let b = v.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        v[1..v.len() - 1].to_string()
    } else {
        v.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quotes_comments_and_defaults() {
        let text = r#"
# comment
MQTT_HOST=192.168.1.10
MQTT_PORT=8883
MQTT_USER="alice"
MQTT_PASS='s3cret'
TOPIC_RX=Bticino/rx
PAYLOAD_FORMAT=raw
ALLOW_REMOTE_SHELL=1
export HA_DISCOVERY=1
EMPTY=
"#;
        let c = Config::from_map(parse_env(text));
        assert_eq!(c.mqtt_host, "192.168.1.10");
        assert_eq!(c.mqtt_port, 8883);
        assert_eq!(c.mqtt_user.as_deref(), Some("alice"));
        assert_eq!(c.mqtt_pass.as_deref(), Some("s3cret"));
        assert!(!c.payload_json); // raw
        assert!(c.ha_discovery);
        assert!(c.allow_remote_shell);
        // defaults
        assert_eq!(c.topic_dump, "Bticino/tx");
        assert_eq!(c.own_port_mon, 20000);
    }

    #[test]
    fn remote_shell_gate_matches_shell() {
        let base = "MQTT_HOST=h\nALLOW_REMOTE_SHELL=1\n";
        // enabled but unauthenticated -> refused
        assert!(!Config::from_map(parse_env(base)).remote_shell_allowed());
        // password auth -> allowed
        let pw = format!("{base}MQTT_USER=u\nMQTT_PASS=p\n");
        assert!(Config::from_map(parse_env(&pw)).remote_shell_allowed());
        // one-way TLS (CA only) -> refused
        let ca = format!("{base}MQTT_CAFILE=/ca.pem\n");
        assert!(!Config::from_map(parse_env(&ca)).remote_shell_allowed());
        // mutual TLS -> allowed
        let mtls = format!("{base}MQTT_CAFILE=/ca.pem\nMQTT_CERTFILE=/c.pem\nMQTT_KEYFILE=/k.pem\n");
        assert!(Config::from_map(parse_env(&mtls)).remote_shell_allowed());
        // disabled entirely -> refused even with auth
        let off = "MQTT_HOST=h\nMQTT_USER=u\nMQTT_PASS=p\n";
        assert!(!Config::from_map(parse_env(off)).remote_shell_allowed());
    }
}
