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
    // Volume control (issue #40): RETAINED state topics HA reads back. The volume /
    // mute / gate COMMANDS reuse TOPIC_RX (delivered as small JSON actions), so no
    // extra subscription is needed — only these two state topics are new.
    pub topic_volume: String,
    pub topic_mute: String,
    // OpenWebNet monitor endpoint (bus -> MQTT)
    pub own_host: String,
    pub own_port_mon: u16,
    // Behaviour
    pub payload_json: bool,
    pub ha_discovery: bool,
    pub allow_remote_shell: bool,
    pub client_id: Option<String>,
    // Broker rediscovery (issue #43): when the broker moves to a new LAN IP, scan its
    // /24 and repoint the broker's /etc/hosts mapping so the next reconnect finds it.
    // OFF by default and only effective when the broker is configured by NAME (the
    // rewrite has no effect on a bare-IP config). `broker_mac`, when set, is an
    // optional confirmation HINT the scan prefers — never a trust gate.
    pub rediscovery: bool,
    pub broker_mac: Option<[u8; 6]>,
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
        // MQTT_USER= as empty and skipped auth), so collapse "" to None. Do NOT trim:
        // shell_unquote already yields the exact intended value, and a credential or
        // topic may legitimately contain leading/trailing spaces (e.g. the installer
        // wrote MQTT_PASS=' secret '), which the shell-sourced config preserved.
        let opt = |k: &str| -> Option<String> { m.get(k).filter(|s| !s.is_empty()).cloned() };
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
            topic_volume: get("TOPIC_VOLUME", "Bticino/volume"),
            topic_mute: get("TOPIC_MUTE", "Bticino/mute"),
            own_host: get("OWN_HOST", "127.0.0.1"),
            own_port_mon: opt("OWN_PORT_MON").and_then(|s| s.parse().ok()).unwrap_or(20000),
            // PAYLOAD_FORMAT defaults to json (mqtt_common.sh); anything but "raw" is json.
            payload_json: opt("PAYLOAD_FORMAT").as_deref() != Some("raw"),
            ha_discovery: flag("HA_DISCOVERY"),
            allow_remote_shell: flag("ALLOW_REMOTE_SHELL"),
            client_id: opt("MQTT_CLIENT_ID"),
            rediscovery: flag("MQTT_REDISCOVERY"),
            broker_mac: opt("MQTT_BROKER_MAC").and_then(|s| crate::rediscovery::parse_mac(&s)),
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
    /// stable, per-unit id derived from the topics. The session is DURABLE
    /// (clean_session=false, see main.rs) so the broker can queue QoS 1 commands
    /// across a brief disconnect, which requires a STABLE, collision-free id to resume
    /// the right session — exactly what the injective hex below provides.
    ///
    /// The id is `btmqttd-<sanitised LWT>-<hex(LWT)>-<hex(RX)>`. The sanitised prefix
    /// is a lossy readability aid; the appended lowercase HEX of the raw LWT- and
    /// RX-topic bytes is an INJECTIVE encoding, so DISTINCT topic pairs always map to
    /// DISTINCT ids — no collision (a plain truncation, or a 32-bit hash, could
    /// collide and make two units evict each other on the broker). This mirrors the
    /// shell's `mqtt_hex` derivation.
    ///
    /// Both topics feed the id BECAUSE the session is DURABLE (clean_session=false):
    /// TOPIC_LASTWILL makes it per-unit unique; folding in TOPIC_RX means CHANGING the
    /// command topic yields a DIFFERENT id — a FRESH durable session — instead of the
    /// broker keeping the old topic's subscription alongside the new one. mosquitto
    /// (on-box and the usual external choice) accepts ids longer than the MQTT 3.1.1
    /// 23-byte guidance — as the shell bridge already relied on; a strict broker gets
    /// the MQTT_CLIENT_ID escape hatch.
    ///
    /// This id differs from the shell bridge's (`btrx-…`) by design — btmqttd fully
    /// REPLACES the shell scripts (they never run together on a device). If a broker
    /// somehow already holds the shell's durable session, set MQTT_CLIENT_ID to that
    /// old id to resume it (or clear the stale session on the broker) so no orphaned
    /// subscription lingers.
    pub fn client_id(&self) -> String {
        if let Some(id) = &self.client_id {
            return id.clone();
        }
        let mut san = String::new();
        for c in self.topic_lastwill.chars() {
            san.push(if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' });
        }
        // Keep the readable prefix bounded; uniqueness comes from the injective hex.
        san.truncate(24);
        format!(
            "btmqttd-{san}-{}-{}",
            hex_bytes(self.topic_lastwill.as_bytes()),
            hex_bytes(self.topic_rx.as_bytes())
        )
    }
}

/// Injective lowercase-hex encoding: each byte -> two fixed hex chars, so distinct
/// byte strings always produce distinct outputs (the shell's `mqtt_hex`). Writes into
/// the preallocated buffer with no per-byte allocation.
fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
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
        // lenient about a hand-edited file: a '#' begins a comment when preceded by
        // whitespace — space OR tab (POSIX) — so cut at the earliest of either.
        if !(val.starts_with('"') || val.starts_with('\'')) {
            let cut = match (val.find(" #"), val.find("\t#")) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            if let Some(idx) = cut {
                val = val[..idx].trim_end();
            }
        }
        let val = shell_unquote(val);
        map.insert(key.to_string(), val);
    }
    map
}

/// Decode POSIX-shell quoting for a value. The installer writes every value as
/// `KEY='...'` and escapes an embedded apostrophe as `'\''` (close-quote, escaped
/// literal quote, reopen) — e.g. `'a'\''b'` sources as `a'b`. This handles that
/// exactly: single-quoted spans are literal, double-quoted spans are literal, and a
/// backslash outside quotes escapes the next char. Not a full shell (no expansion),
/// which is correct — the installer only ever quotes literal values.
fn shell_unquote(v: &str) -> String {
    let mut out = String::new();
    let mut chars = v.chars();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                for d in chars.by_ref() {
                    if d == '\'' {
                        break;
                    }
                    out.push(d);
                }
            }
            '"' => {
                while let Some(d) = chars.next() {
                    match d {
                        '"' => break,
                        // POSIX: inside DOUBLE quotes a backslash escapes only " \ $ `
                        // (and a newline, for line continuation). Before any other
                        // character it stays literal. Without this a value like
                        // MQTT_PASS="a\"b" would end the quote at the escaped `"` and
                        // silently mis-parse the rest of the line.
                        '\\' => match chars.next() {
                            Some(e @ ('"' | '\\' | '$' | '`')) => out.push(e),
                            Some(e) => {
                                out.push('\\');
                                out.push(e);
                            }
                            None => out.push('\\'),
                        },
                        _ => out.push(d),
                    }
                }
            }
            '\\' => {
                if let Some(d) = chars.next() {
                    out.push(d);
                }
            }
            other => out.push(other),
        }
    }
    out
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
        assert_eq!(c.topic_volume, "Bticino/volume");
        assert_eq!(c.topic_mute, "Bticino/mute");
    }

    #[test]
    fn decodes_installer_single_quote_escaping() {
        // The installer writes KEY='...' and escapes an apostrophe as '\'' —
        // e.g. a password of a'b is written MQTT_PASS='a'\''b'.
        let m = parse_env("MQTT_PASS='a'\\''b'\nMQTT_USER='p@ss word#1'\n");
        assert_eq!(m.get("MQTT_PASS").map(String::as_str), Some("a'b"));
        // Spaces and '#' inside the single quotes are literal.
        assert_eq!(m.get("MQTT_USER").map(String::as_str), Some("p@ss word#1"));
    }

    #[test]
    fn decodes_double_quote_backslash_escapes() {
        // A hand-edited double-quoted value: POSIX sh escapes only " \ $ ` inside "".
        // MQTT_PASS="a\"b" must decode to a"b (the escaped quote must NOT end the span
        // early), and "a\\b" to a\b; a backslash before an ordinary char stays literal.
        let m = parse_env("MQTT_PASS=\"a\\\"b\"\nTOPIC_RX=\"x\\\\y\"\nMQTT_USER=\"c\\d\"\n");
        assert_eq!(m.get("MQTT_PASS").map(String::as_str), Some("a\"b"));
        assert_eq!(m.get("TOPIC_RX").map(String::as_str), Some("x\\y"));
        assert_eq!(m.get("MQTT_USER").map(String::as_str), Some("c\\d"));
    }

    #[test]
    fn preserves_leading_trailing_quoted_whitespace() {
        // A credential with intentional surrounding spaces must survive intact — the
        // shell-sourced config preserved it; a stray trim would reject the broker.
        let c = Config::from_map(parse_env("MQTT_HOST=h\nMQTT_USER=u\nMQTT_PASS=' secret '\n"));
        assert_eq!(c.mqtt_pass.as_deref(), Some(" secret "));
    }

    #[test]
    fn client_id_is_distinct_for_distinct_lastwill() {
        let a = Config::from_map(parse_env("MQTT_HOST=h\nTOPIC_LASTWILL=Bticino/UnitA/LastWillT\n"));
        let b = Config::from_map(parse_env("MQTT_HOST=h\nTOPIC_LASTWILL=Bticino/UnitB/LastWillT\n"));
        assert_ne!(a.client_id(), b.client_id());
        // Even when the sanitised prefixes would truncate to the same bytes.
        let c = Config::from_map(parse_env(
            "MQTT_HOST=h\nTOPIC_LASTWILL=Bticino/very-long-identical-prefix/AAAA\n",
        ));
        let d = Config::from_map(parse_env(
            "MQTT_HOST=h\nTOPIC_LASTWILL=Bticino/very-long-identical-prefix/BBBB\n",
        ));
        assert_ne!(c.client_id(), d.client_id());
        // Changing only TOPIC_RX must also change the id (durable session: a new
        // command topic starts a fresh session instead of resuming the old one).
        let e = Config::from_map(parse_env("MQTT_HOST=h\nTOPIC_LASTWILL=Bticino/lw\nTOPIC_RX=Bticino/rx1\n"));
        let f = Config::from_map(parse_env("MQTT_HOST=h\nTOPIC_LASTWILL=Bticino/lw\nTOPIC_RX=Bticino/rx2\n"));
        assert_ne!(e.client_id(), f.client_id());
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
