//! Configuration: parse the `/etc/btmqttd/btmqttd.conf` the installer writes, so
//! the App UI and `MqttInstaller` config generation stay in lock-step.
//!
//! The file is a POSIX-sh `KEY=value` fragment (the shell `source`d it). We do NOT
//! run a shell — we parse the small, fixed set of keys the installer writes:
//! `KEY=value`, optionally single- or double-quoted, one per line, `#` comments and
//! blank lines ignored. The installer writes it 0600 root:root on a read-only
//! rootfs, so it is a trusted, machine-written file (see the header in the .conf).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;

pub const DEFAULT_CFG_PATH: &str = "/etc/btmqttd/btmqttd.conf";

/// The OpenWebNet gateway's command-injection port (raw frames received over MQTT
/// are forwarded here). Fixed, as in StartMqttReceive (`OWN_PORT=30006`).
pub const OWN_PORT_CMD: u16 = 30006;

/// The on-board `bt_av_media` A/V daemon's command port (issue #103). A WHO=7
/// `*7*300#IP#IP#IP#IP#PORT#BRANCH*##` frame "adds a UDP client" to its GStreamer
/// `multiudpsink`, fanning a cleartext RTP copy of the panel's H.264/speex to that
/// `ip:port` — the mechanism `av.rs` uses to siphon the doorbell camera. Same on
/// the C100X and C300X (firmware-verified). Adjacent to the command port above.
pub const OWN_PORT_AV: u16 = 30007;

/// Directory holding the Home Assistant discovery manifest + payloads.
pub const HA_DIR: &str = "/etc/btmqttd/ha";

/// The loopback address the on-device media server (go2rtc) listens on. In on-device mode
/// (`CAMERA_ONDEVICE=1`, issue #120) the siphon fans the panel's RTP here — to a socket on
/// the SAME device — instead of to an off-device host. It is loopback (routes via `lo`,
/// immutable, DHCP-proof) but deliberately **not** `127.0.0.1`: our add-client frame
/// `*7*300#127#0#0#2#…` does not match the panel's own `*7*300#127#0#0#1#…` media-start
/// signal that `av.rs` watches to arm, so the on-device feed never re-arms us off its own
/// echo. `av.rs`'s loopback guard permits exactly this address in on-device mode.
pub const CAMERA_ONDEVICE_TARGET: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

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
    // mute / lock COMMANDS reuse TOPIC_RX (delivered as small JSON actions), so no
    // extra subscription is needed — only these two state topics are new.
    pub topic_volume: String,
    pub topic_mute: String,
    // Door-entry events: the ENTRANCE-PANEL CALL (outdoor door station) and the FLOOR CALL
    // (local front-door button on the unit's floor-call terminals) are each published as a
    // momentary event (NOT retained); the call STATE (entrance-panel only) as a retained
    // sensor. All are learned for free from the same WHO=8 monitor stream — no extra
    // subscription. The two calls have disjoint WHO=8 signatures and never cross-fire.
    pub topic_entrance_panel_call: String,
    pub topic_floor_call: String,
    pub topic_call_state: String,
    // Stair-light SWITCH (opt-in). `light_enabled` reflects the installer's "has exterior
    // light" choice: when true the light subsystem RUNS even before a WHERE is known, so a
    // build left blank can LEARN the WHERE at runtime (see light.rs). `light_where` is the
    // WHO=8 actuator WHERE (installation-specific, e.g. "112"); None + light_enabled ⇒ learn
    // mode. The button toggles the relay (`*8*21*<where>##`) — no discrete on/off and no
    // status query (firmware-confirmed). In BISTABLE mode `topic_light` carries a TRACKED retained
    // on/off (see `light_momentary`); `topic_light_avail` gates HA's entities until a WHERE is known.
    // The COMMANDs reuse TOPIC_RX (small JSON actions: light / light_press / light_resync /
    // light_learn), so no extra subscription is added.
    pub light_enabled: bool,
    // Light TYPE. `false` (default) = BISTABLE: a toggle actuator that stays on until switched off;
    // btmqttd tracks + publishes the on/off and exposes resync. `true` = MOMENTARY: a
    // staircase-timer install that auto-offs; btmqttd only forwards a PRESS (turn on) and tracks no
    // state (HA gets a press button, no switch/resync). Set from LIGHT_MODE=momentary.
    pub light_momentary: bool,
    pub light_where: Option<String>,
    pub topic_light: String,
    pub topic_light_avail: String,
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
    // rewrite has no effect on a bare-IP config). `broker_mac`'s role depends on TLS:
    // WITH TLS it is a tie-breaker HINT (the reconnect's pinned-cert validation is the
    // trust gate, so it only orders candidates); WITHOUT TLS it is REQUIRED and becomes
    // the trust gate — a candidate is adopted only if its ARP MAC matches it.
    pub rediscovery: bool,
    pub broker_mac: Option<[u8; 6]>,

    // --- Live doorbell camera (Phase 1, issue #103) --------------------------------
    /// "Expose the entrance-panel camera". When enabled, `av.rs` opens its own OWN
    /// monitor and, whenever the panel brings an A/V session up (a ring/answer/self-view),
    /// siphons the cleartext RTP off `bt_av_media` (:30007) by adding our own UDP client,
    /// fanning it out to `camera_target` for go2rtc/Home Assistant. Opt-in; off by default.
    pub camera_enabled: bool,
    /// Where to fan the siphoned RTP. In OFF-device mode this is the go2rtc/HA host and
    /// defaults to `MQTT_HOST` (go2rtc typically runs alongside Home Assistant). In on-device
    /// mode (`camera_ondevice`) it is pinned to [`CAMERA_ONDEVICE_TARGET`] (`127.0.0.2`) and
    /// `CAMERA_TARGET_HOST` is ignored. Resolved to an IPv4 at runtime.
    pub camera_target: String,
    /// UDP ports on `camera_target` for the video and audio RTP fan-out. Must match the
    /// generated go2rtc SDP. Defaults 40000 (video) / 40002 (audio).
    pub camera_video_port: u16,
    pub camera_audio_port: u16,
    /// Which `multiudpsink` branch to siphon for video: `1` = low-res H.264 (the universal
    /// default — the only one siphonable on the C100X, and present on the C300X), `0` =
    /// hi-res (C300X only). Clamped to 0..=1; default 1.
    pub camera_branch: u8,
    /// On-device media server mode (issue #120, Phase 1). When set (`CAMERA_ONDEVICE=1`),
    /// go2rtc + ffmpeg run ON the panel and go2rtc listens on loopback, so the siphon fans
    /// the RTP to the loopback alias [`CAMERA_ONDEVICE_TARGET`] (`127.0.0.2`) rather than an
    /// off-device host — `camera_target` is pinned to that address and `CAMERA_TARGET_HOST`
    /// is ignored. `127.0.0.2` (not `127.0.0.1`) is deliberate: it stays loopback yet does
    /// not collide with the panel's own media-start arm signal `av.rs` watches. Opt-in; off
    /// by default (the fan-out then targets the off-device go2rtc/HA host as before).
    pub camera_ondevice: bool,

    // --- On-demand viewing (Phase 2, issue #104) -----------------------------------
    /// "View the entrance-panel camera on demand" (not only while ringing). When enabled,
    /// `sip.rs` originates a loopback SIP INVITE to the panel's on-board UA (via the local
    /// flexisip on `127.0.0.1:SIP_PORT`) to bring the idle A/V session up, then reuses the
    /// Phase-1 `:30007` siphon for the actual video. Requires `camera_enabled` (the media
    /// path). Opt-in; off by default.
    pub camera_ondemand_enabled: bool,
    /// The local flexisip plain-SIP port (loopback). Factory default 5060 on both models.
    pub sip_port: u16,
    /// The panel's local SIP domain (e.g. a `<uuid>.bs.iotleg.com`). Empty ⇒ discover at
    /// runtime from `/etc/flexisip/domain-registration.conf`. An installer may pin it.
    pub sip_domain: String,
    /// The panel's local answer-machine AOR user (`c100x` / `c300x`). Empty ⇒ derive from
    /// the model (`/etc/hostname`) at runtime. The INVITE targets `sip:<aor>@<domain>`.
    pub sip_local_aor: String,
    /// The `a=DEVADDR` value that turns the INVITE into a SILENT camerasliding pull instead of a
    /// household-ringing intercom call (hardware-proven, issue #104). On the C100X this MUST be the
    /// entrance module's UUID (the `id` of the `videodoorentry` `EU` module at OWN address 20 in
    /// `/home/bticino/cfg/extra/.bt_eliot/mymodules`); the numeric OWN-address form (`20`) works only
    /// on the C300X. Empty ⇒ auto-detect from `mymodules` at runtime. Without a resolved DEVADDR the
    /// feature declines to originate (never rings the house).
    pub sip_devaddr: String,
    /// Maximum length of one on-demand viewing window, in seconds (default 30). A `view_camera`
    /// request brings the session up and starts this countdown; when it elapses `sip.rs` hangs up
    /// (BYE) so an on-demand pull never leaves the panel session pinned open. There is no continuous
    /// "someone is watching" signal, so the timer is NOT extended by the video stream itself — only
    /// by another explicit `view_camera` press (each press restarts the full window), and it is cut
    /// short by a `stop_camera` press. Despite the historical `_idle_` name it is a fixed per-request
    /// cap, not an inactivity timeout.
    pub camera_view_idle_secs: u64,
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

        // On-device media server (issue #120): go2rtc runs on the panel and listens on loopback,
        // so the siphon target is pinned to the loopback alias 127.0.0.2 (CAMERA_ONDEVICE_TARGET)
        // and CAMERA_TARGET_HOST is ignored. Computed once — it drives both the flag and the target.
        let camera_ondevice = flag("CAMERA_ONDEVICE");

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
            topic_entrance_panel_call: get("TOPIC_ENTRANCE_PANEL_CALL", "Bticino/entrance_panel_call"),
            topic_floor_call: get("TOPIC_FLOOR_CALL", "Bticino/floor_call"),
            topic_call_state: get("TOPIC_CALL_STATE", "Bticino/call_state"),
            // Digits only — a WHERE like "112". Empty ⇒ unknown (learn mode when enabled).
            light_where: opt("LIGHT_WHERE").filter(|s| s.bytes().all(|b| b.is_ascii_digit())),
            // "Has exterior light". When the installer wrote LIGHT_ENABLED it is AUTHORITATIVE
            // ("1" enables, anything else disables) — so unticking the option reliably turns the
            // subsystem off even if a stale numeric LIGHT_WHERE lingers in the conf (Copilot,
            // Codex). Only an OLD conf that predates the key (LIGHT_ENABLED absent) falls back to
            // "a numeric LIGHT_WHERE implies the feature", keeping legacy configs working.
            light_enabled: match opt("LIGHT_ENABLED") {
                Some(v) => v == "1",
                None => opt("LIGHT_WHERE").is_some_and(|s| s.bytes().all(|b| b.is_ascii_digit())),
            },
            // Light TYPE: "momentary" = staircase-timer install (press-only, no tracked state);
            // anything else (incl. absent) = the default BISTABLE toggle. Mirrors PAYLOAD_FORMAT.
            light_momentary: opt("LIGHT_MODE").as_deref() == Some("momentary"),
            topic_light: get("TOPIC_LIGHT", "Bticino/light"),
            topic_light_avail: get("TOPIC_LIGHT_AVAIL", "Bticino/light_avail"),
            own_host: get("OWN_HOST", "127.0.0.1"),
            own_port_mon: opt("OWN_PORT_MON").and_then(|s| s.parse().ok()).unwrap_or(20000),
            // PAYLOAD_FORMAT defaults to json (mqtt_common.sh); anything but "raw" is json.
            payload_json: opt("PAYLOAD_FORMAT").as_deref() != Some("raw"),
            ha_discovery: flag("HA_DISCOVERY"),
            allow_remote_shell: flag("ALLOW_REMOTE_SHELL"),
            client_id: opt("MQTT_CLIENT_ID"),
            rediscovery: flag("MQTT_REDISCOVERY"),
            broker_mac: opt("MQTT_BROKER_MAC").and_then(|s| crate::rediscovery::parse_mac(&s)),
            // Live doorbell camera (issue #103). Opt-in; the fan-out target defaults to the
            // broker host (go2rtc usually lives with HA). Branch clamped to lo/hi-res (1/0).
            camera_enabled: flag("CAMERA_ENABLED"),
            camera_ondevice,
            // On-device mode pins the fan-out to the loopback alias 127.0.0.2 (go2rtc listens
            // there); otherwise it's CAMERA_TARGET_HOST, defaulting to the broker host (go2rtc
            // usually lives with HA).
            camera_target: if camera_ondevice {
                CAMERA_ONDEVICE_TARGET.to_string()
            } else {
                get("CAMERA_TARGET_HOST", &get("MQTT_HOST", ""))
            },
            // Reject port 0 (a hand-edited / corrupt conf) as well as an unparseable value: 0 would
            // build an invalid `*7*300#…#0#…*##` frame the siphon can never use. Fall back to the
            // default so a bad value degrades to a working port rather than a dead one (Copilot).
            camera_video_port: opt("CAMERA_VIDEO_PORT")
                .and_then(|s| s.parse().ok())
                .filter(|p| *p != 0)
                .unwrap_or(40000),
            camera_audio_port: opt("CAMERA_AUDIO_PORT")
                .and_then(|s| s.parse().ok())
                .filter(|p| *p != 0)
                .unwrap_or(40002),
            camera_branch: opt("CAMERA_BRANCH")
                .and_then(|s| s.parse().ok())
                .filter(|b| *b <= 1)
                .unwrap_or(1),
            // On-demand viewing (issue #104). Opt-in; domain/AOR default to empty ⇒ discovered
            // on-device at runtime. Port 0 (bad conf) falls back to the flexisip default 5060.
            camera_ondemand_enabled: flag("CAMERA_ONDEMAND_ENABLED"),
            sip_port: opt("SIP_PORT")
                .and_then(|s| s.parse().ok())
                .filter(|p| *p != 0)
                .unwrap_or(5060),
            sip_domain: get("SIP_DOMAIN", ""),
            sip_local_aor: get("SIP_LOCAL_AOR", ""),
            sip_devaddr: get("SIP_DEVADDR", ""),
            // Clamp to 1 s..=86400 s (1 day). >0 keeps a hand-edited 0 from disabling the hang-up; the
            // upper cap keeps a huge hand-edited value from overflowing `Instant + Duration` (which
            // panics) when sip.rs builds the viewing-window deadline (Copilot). 86400 s is far above any real
            // on-demand view.
            camera_view_idle_secs: opt("CAMERA_VIEW_IDLE_SECS")
                .and_then(|s| s.parse::<u64>().ok())
                .filter(|n| *n > 0)
                .map(|n| n.min(86_400))
                .unwrap_or(30),
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
        assert_eq!(c.topic_entrance_panel_call, "Bticino/entrance_panel_call");
        assert_eq!(c.topic_floor_call, "Bticino/floor_call");
        assert_eq!(c.topic_call_state, "Bticino/call_state");
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

    #[test]
    fn light_enabled_flag_is_authoritative_over_a_stale_where() {
        let cfg = |s: &str| Config::from_map(parse_env(s));
        // Explicit LIGHT_ENABLED=0 disables the subsystem even if a numeric LIGHT_WHERE lingers
        // (the installer writes both keys; unticking "has exterior light" must win) — Copilot/Codex.
        assert!(!cfg("MQTT_HOST=h\nLIGHT_ENABLED=0\nLIGHT_WHERE=112\n").light_enabled);
        // Explicit LIGHT_ENABLED=1 enables even with a blank WHERE (learn mode).
        assert!(cfg("MQTT_HOST=h\nLIGHT_ENABLED=1\n").light_enabled);
        // Legacy conf WITHOUT the key: a numeric LIGHT_WHERE still implies the feature.
        assert!(cfg("MQTT_HOST=h\nLIGHT_WHERE=112\n").light_enabled);
        // Nothing set at all -> disabled.
        assert!(!cfg("MQTT_HOST=h\n").light_enabled);
    }

    #[test]
    fn light_mode_selects_momentary_only_for_the_exact_token() {
        let cfg = |s: &str| Config::from_map(parse_env(s));
        // Explicit momentary.
        assert!(cfg("MQTT_HOST=h\nLIGHT_ENABLED=1\nLIGHT_MODE=momentary\n").light_momentary);
        // Explicit bistable, and any other/absent value, default to bistable (not momentary).
        assert!(!cfg("MQTT_HOST=h\nLIGHT_ENABLED=1\nLIGHT_MODE=bistable\n").light_momentary);
        assert!(!cfg("MQTT_HOST=h\nLIGHT_ENABLED=1\n").light_momentary);
        assert!(!cfg("MQTT_HOST=h\nLIGHT_ENABLED=1\nLIGHT_MODE=\n").light_momentary);
    }

    #[test]
    fn camera_ports_reject_zero_and_unparseable_falling_back_to_defaults() {
        let cfg = |s: &str| Config::from_map(parse_env(s));
        // A valid explicit port is kept.
        let c = cfg("MQTT_HOST=h\nCAMERA_VIDEO_PORT=41000\nCAMERA_AUDIO_PORT=41002\n");
        assert_eq!(c.camera_video_port, 41000);
        assert_eq!(c.camera_audio_port, 41002);
        // 0 (a hand-edited / corrupt conf) falls back to the default rather than building a port-0
        // frame the siphon can never use.
        let z = cfg("MQTT_HOST=h\nCAMERA_VIDEO_PORT=0\nCAMERA_AUDIO_PORT=0\n");
        assert_eq!(z.camera_video_port, 40000);
        assert_eq!(z.camera_audio_port, 40002);
        // An unparseable / out-of-range value likewise falls back.
        let bad = cfg("MQTT_HOST=h\nCAMERA_VIDEO_PORT=70000\nCAMERA_AUDIO_PORT=nope\n");
        assert_eq!(bad.camera_video_port, 40000);
        assert_eq!(bad.camera_audio_port, 40002);
    }

    #[test]
    fn camera_ondevice_pins_the_target_to_the_loopback_alias() {
        let cfg = |s: &str| Config::from_map(parse_env(s));
        // Off by default: the flag is false and the target follows CAMERA_TARGET_HOST (falling
        // back to the broker host) — the off-device go2rtc/HA path, unchanged.
        let off = cfg("MQTT_HOST=192.168.1.10\nCAMERA_TARGET_HOST=192.168.1.99\n");
        assert!(!off.camera_ondevice);
        assert_eq!(off.camera_target, "192.168.1.99");
        let broker = cfg("MQTT_HOST=192.168.1.10\n");
        assert!(!broker.camera_ondevice);
        assert_eq!(broker.camera_target, "192.168.1.10");
        // On-device mode pins the siphon to the loopback alias 127.0.0.2 (NOT 127.0.0.1) and
        // ignores CAMERA_TARGET_HOST — go2rtc runs on the panel and listens on loopback.
        let on = cfg("MQTT_HOST=192.168.1.10\nCAMERA_ONDEVICE=1\nCAMERA_TARGET_HOST=192.168.1.99\n");
        assert!(on.camera_ondevice);
        assert_eq!(on.camera_target, "127.0.0.2");
        assert_eq!(on.camera_target, CAMERA_ONDEVICE_TARGET.to_string());
        // Only the exact "1" enables it (mirrors the other flags); anything else stays off-device.
        assert!(!cfg("MQTT_HOST=h\nCAMERA_ONDEVICE=0\n").camera_ondevice);
        assert!(!cfg("MQTT_HOST=h\nCAMERA_ONDEVICE=true\n").camera_ondevice);
    }

    #[test]
    fn camera_view_idle_secs_clamps_zero_and_huge_values() {
        let cfg = |s: &str| Config::from_map(parse_env(s));
        // A sane value is kept.
        assert_eq!(cfg("MQTT_HOST=h\nCAMERA_VIEW_IDLE_SECS=45\n").camera_view_idle_secs, 45);
        // 0 (would disable the hang-up) falls back to the default.
        assert_eq!(cfg("MQTT_HOST=h\nCAMERA_VIEW_IDLE_SECS=0\n").camera_view_idle_secs, 30);
        // A huge hand-edited value is capped at 1 day so `Instant + Duration` can't overflow/panic.
        assert_eq!(
            cfg("MQTT_HOST=h\nCAMERA_VIEW_IDLE_SECS=18446744073709551615\n").camera_view_idle_secs,
            86_400
        );
    }
}
