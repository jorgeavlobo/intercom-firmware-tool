using SharpExt4;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using IntercomFirmwareTool.Core.Localization;

namespace IntercomFirmwareTool.Core
{
    /// <summary>
    /// Options for installing the optional MQTT bridge into a firmware image.
    /// The bridge is <b>off by default</b>; the installer only runs when the user
    /// opts in. Mirrors the variables <c>btmqttd</c> reads from
    /// <c>btmqttd.conf</c>.
    /// </summary>
    /// <param name="MqttHost">Broker IP (preferred) or hostname. Required.</param>
    /// <param name="MqttPort">Broker port (1..65535, default 1883).</param>
    /// <param name="MqttUser">Broker username (with <paramref name="MqttPass"/>), or null.</param>
    /// <param name="MqttPass">Broker password (with <paramref name="MqttUser"/>), or null.</param>
    /// <param name="CaCertPem">CA certificate (PEM) for TLS, or null. Alone = one-way TLS.</param>
    /// <param name="ClientCertPem">Client certificate (PEM) for mutual TLS, or null.</param>
    /// <param name="ClientKeyPem">Client private key (PEM) for mutual TLS, or null.</param>
    /// <param name="HostIpForHosts">
    /// IP to map <paramref name="MqttHost"/> to in <c>bt_daemon-apps.sh</c> when the host is
    /// a name (the device resolves broker names via <c>bt_hosts.sh</c>). If null and the host
    /// is a name, the installer resolves it (best effort). Ignored when the host is an IP.
    /// </param>
    /// <param name="AllowRemoteShell">
    /// Enable the gated JSON command channel. Requires client auth (user/pass or mutual TLS);
    /// enforced by <see cref="Validate"/>.
    /// </param>
    /// <param name="EnableHaDiscovery">
    /// Publish retained Home Assistant MQTT discovery configs at bridge startup, so the
    /// connectivity/bus/keypad entities appear in HA automatically (no manual YAML). Additive and
    /// read-only (no command entity); off by default at the Core layer. Reconciled natively by btmqttd.
    /// </param>
    /// <param name="UseJsonPayload">
    /// Publish the bus (TOPIC_DUMP) as one structured JSON object per OpenWebNet frame
    /// (<c>{frame, ts, type, who, what, where, params}</c>) instead of the raw "*...##" string.
    /// On by default (json — the modern, HA-friendly representation); set false for raw frames
    /// (a low-level, dependency-free option). TOPIC_KEY is already JSON either way. When on, the
    /// HA <c>bus</c> entity exposes the parsed fields as attributes (its value_template also
    /// tolerates a raw payload, so a raw-mode frame still shows). See PAYLOAD_FORMAT /
    /// frame_to_json in btmqttd.
    /// </param>
    /// <param name="MqttRediscovery">
    /// Let the device recover the broker after its LAN IP changes (issues #43/#44): when the
    /// broker's address goes stale, btmqttd scans its /24 and repoints the broker name's
    /// <c>/etc/hosts</c> mapping so the bridge reconnects without a re-flash. On by default.
    /// Self-gates on the device: it only acts when the broker is a NAME (the repoint has no
    /// effect on a bare-IP config) AND there is a trust anchor — either TLS (the reconnect
    /// validates the broker's pinned certificate) OR the broker MAC (see
    /// <paramref name="MqttBrokerMac"/>), which lets the plaintext path adopt a rescanned
    /// broker whose ARP MAC matches. Writes <c>MQTT_REDISCOVERY</c>.
    /// </param>
    /// <param name="MqttBrokerMac">
    /// The broker's Ethernet MAC address (six hex octets, ':' or '-' separated), captured in
    /// the UI at "Test connection" time via ARP. On the plaintext (no-TLS) path it lets
    /// rediscovery re-adopt a rescanned candidate whose ARP MAC matches this value — so a
    /// broker on a fixed NIC recovers a changed DHCP lease without a certificate. This is a
    /// convenience match for a trusted LAN, NOT authentication: a same-subnet attacker can
    /// spoof both IP and MAC, so TLS remains the only cryptographic anchor. Writes
    /// <c>MQTT_BROKER_MAC</c> when set; null omits the key (rediscovery then requires TLS).
    /// Validated by <see cref="Validate"/>.
    /// </param>
    public sealed record MqttOptions(
        string MqttHost,
        int MqttPort = 1883,
        string? MqttUser = null,
        string? MqttPass = null,
        string? CaCertPem = null,
        string? ClientCertPem = null,
        string? ClientKeyPem = null,
        string? HostIpForHosts = null,
        bool AllowRemoteShell = false,
        bool EnableHaDiscovery = false,
        bool UseJsonPayload = true,
        bool MqttRediscovery = true,
        string? MqttBrokerMac = null)
    {
        // A record's synthesized ToString() prints EVERY property — which would
        // leak MqttPass and the TLS private key (ClientKeyPem) into any log line
        // or exception that interpolates the options. Redact: expose only
        // non-sensitive fields (booleans for the presence of secrets).
        public override string ToString() =>
            $"MqttOptions {{ MqttHost = {MqttHost}, MqttPort = {MqttPort}, " +
            $"HasAuth = {HasAuth}, HasTls = {HasTls}, HasMutualTls = {HasMutualTls}, " +
            $"AllowRemoteShell = {AllowRemoteShell}, " +
            $"Payload = {(UseJsonPayload ? "json" : "raw")}, " +
            $"HaDiscovery = {EnableHaDiscovery}, " +
            $"Rediscovery = {MqttRediscovery}, " +
            // The MAC is not a secret (any LAN host can ARP it), so print it — it
            // aids diagnosing a rediscovery-anchor mismatch. "(none)" when unset.
            $"BrokerMac = {MqttBrokerMac ?? "(none)"} }}";

        /// <summary>OpenWebNet gateway host for the socket monitor back-end (loopback alias).</summary>
        public string OwnHost { get; init; } = "127.0.0.1";
        /// <summary>OpenWebNet gateway plaintext OwnPort for the socket monitor session.</summary>
        public int OwnPortMon { get; init; } = 20000;

        // --- Live doorbell camera (Phase 1, #103) --------------------------------------
        /// <summary>"Expose the entrance-panel camera" opt-in (default false). When true, btmqttd's
        /// <c>av.rs</c> siphons the panel's cleartext A/V off the on-board <c>bt_av_media</c> daemon
        /// (:30007) whenever the panel brings an A/V session up (ring / answer / self-view) and fans
        /// the RTP out to <see cref="EffectiveCameraTargetHost"/> — no SIP, no on-device transcode.
        /// A go2rtc stream on the target host turns it into a Home Assistant camera.</summary>
        public bool CameraEnabled { get; init; }

        /// <summary>Host the siphoned RTP is fanned out to (the go2rtc / Home Assistant host). NULL
        /// or blank (default) means "use <see cref="MqttHost"/>" (go2rtc typically runs alongside
        /// Home Assistant) — see <see cref="EffectiveCameraTargetHost"/>. May be a hostname or an
        /// IPv4; btmqttd resolves it to an IPv4 at runtime (the OWN fan-out frame is IPv4-only).</summary>
        public string? CameraTargetHost { get; init; }

        /// <summary>UDP port on the target for the VIDEO (H.264) RTP fan-out. Must match the
        /// generated go2rtc SDP. Default 40000. Must differ from <see cref="CameraAudioPort"/>.</summary>
        public int CameraVideoPort { get; init; } = 40000;

        /// <summary>UDP port on the target for the AUDIO (speex) RTP fan-out. Default 40002. Must
        /// differ from <see cref="CameraVideoPort"/>.</summary>
        public int CameraAudioPort { get; init; } = 40002;

        /// <summary>Siphon the HI-RES video branch instead of low-res (default false = low-res). The
        /// low-res branch (<c>1</c>) is the UNIVERSAL default — it is the only one siphonable on the
        /// C100X and is present on the C300X; hi-res (<c>0</c>) is C300X-only. Maps to
        /// <see cref="CameraBranch"/>.</summary>
        public bool CameraHiRes { get; init; }

        /// <summary>The <c>bt_av_media</c> multiudpsink branch for video: <c>0</c> hi-res (C300X only)
        /// or <c>1</c> low-res (universal). Derived from <see cref="CameraHiRes"/>.</summary>
        public int CameraBranch => CameraHiRes ? 0 : 1;

        /// <summary>On-demand viewing (Phase 2, #104): view the entrance camera at any time — not
        /// only while ringing — by having btmqttd's SIP UA (<c>sip.rs</c>) bring the idle panel A/V
        /// session up via a loopback INVITE, then reuse the Phase-1 siphon. Requires
        /// <see cref="CameraEnabled"/> (the media path). Opt-in; off by default.</summary>
        public bool CameraOnDemand { get; init; }

        /// <summary>Maximum length of one on-demand viewing window, in seconds: a "View Camera" press
        /// brings the SIP dialog up and starts this countdown, after which the daemon hangs it up (BYE)
        /// so a pull never pins the panel session. It is a fixed per-request cap, NOT an inactivity
        /// timeout — there is no continuous "someone is watching" signal, so it is extended only by
        /// another View press (each restarts the full window) and cut short by "Stop Camera". Despite
        /// the legacy <c>_idle_</c> name in the conf key it is not idle-based. The daemon clamps;
        /// default 30.</summary>
        public int CameraViewIdleSecs { get; init; } = 30;

        /// <summary>The camera fan-out target actually used: the explicit
        /// <see cref="CameraTargetHost"/>, or <see cref="MqttHost"/> when it is null/blank (go2rtc
        /// usually lives with Home Assistant). Mirrors btmqttd's <c>CAMERA_TARGET_HOST</c> default.</summary>
        public string EffectiveCameraTargetHost =>
            string.IsNullOrWhiteSpace(CameraTargetHost) ? MqttHost : CameraTargetHost!;

        /// <summary>Home Assistant MQTT discovery topic prefix (HA default is "homeassistant").</summary>
        public string HaDiscoveryPrefix { get; init; } = "homeassistant";
        /// <summary>
        /// Stable id for the HA device + entity unique_ids / discovery object ids. Distinct per
        /// unit gives several bridges distinct HA devices/entities on one broker. NOTE: this
        /// scopes only the discovery topic and unique_ids — the entities' state/availability
        /// still read the MQTT data topics (TopicDump/TopicKey/TopicLastWill), so a multi-unit
        /// deployment must ALSO give each unit distinct topics, or the HA devices will mirror
        /// each other's bus/key/availability. (Auto-scoping topics from the node id is future
        /// work — see #12.)
        /// <para>MIGRATION: changing the node id (e.g. a reflash where the model-derived
        /// default replaces a previous value) leaves the PREVIOUS node's RETAINED discovery
        /// configs on the broker, which HA keeps showing as an orphan device. To remove it,
        /// clear those retained topics ON THE BROKER. The old configs live at
        /// <c>&lt;prefix&gt;/&lt;component&gt;/&lt;old-node&gt;/&lt;object&gt;/config</c> — the
        /// <c>&lt;prefix&gt;/+/&lt;old-node&gt;/+/config</c> form is only a SELECTION pattern for
        /// finding them (<c>+</c> is a subscribe-only wildcard and is invalid in a publish
        /// topic). Publish an empty retained payload to each CONCRETE config topic that was
        /// generated — e.g. <c>mosquitto_pub -r -n -t &lt;prefix&gt;/sensor/&lt;old-node&gt;/bus/config</c>,
        /// once per entity — or delete them in MQTT Explorer. Deleting the device inside Home
        /// Assistant is NOT sufficient: the retained config survives on the broker and HA
        /// re-creates the device on the next MQTT reconnect or restart. The installer does
        /// NOT auto-clear the old node: it can't tell whether the default
        /// <c>bticino_intercom</c> belongs to THIS bridge or to another unit sharing the
        /// broker, and blindly clearing it would wipe that other unit's entities.</para>
        /// </summary>
        public string HaNodeId { get; init; } = "bticino_intercom";

        /// <summary>
        /// Friendly name of the Home Assistant DEVICE the entities group under. The App
        /// sets it from the firmware being customized (<c>BTicino Classe 100X</c> /
        /// <c>BTicino Classe 300X</c>); the record default is a model-neutral fallback for
        /// a firmware with no model mapping. Distinct from <see cref="HaNodeId"/>, which is
        /// the machine id that scopes the discovery topics, unique_ids and (via each
        /// entity's <c>object_id</c>) the <c>entity_id</c> prefix — HA lowercases that, so
        /// the node id must already be lower-case (e.g. <c>bticino_c100x</c>).
        /// </summary>
        public string HaDeviceName { get; init; } = "BTicino intercom bridge";

        public string TopicRx { get; init; } = "Bticino/rx";
        public string TopicDump { get; init; } = "Bticino/tx";
        public string TopicStartDate { get; init; } = "Bticino/start_date";
        public string TopicLastWill { get; init; } = "Bticino/LastWillT";
        public string TopicKey { get; init; } = "Bticino/key";
        public string TopicCmdResult { get; init; } = "Bticino/command_result_topic";
        public string TopicFileContent { get; init; } = "Bticino/file_content_topic";

        /// <summary>
        /// Retained volume-state topic (0..100) HA's slider reads back (#40). NULL (the
        /// default) means "derive from the <see cref="TopicLastWill"/> namespace" via
        /// <see cref="EffectiveTopicVolume"/>, so it AUTO-SCOPES per unit: a unit whose
        /// last-will is <c>Home1/unitA/LastWillT</c> publishes volume to
        /// <c>Home1/unitA/volume</c> (and the default <c>Bticino/LastWillT</c> yields
        /// <c>Bticino/volume</c>, unchanged). Set a non-null value to override. The
        /// volume/mute/gate COMMANDS reuse <see cref="TopicRx"/> as small JSON actions,
        /// so only these two STATE topics are new — no extra subscription.
        /// </summary>
        public string? TopicVolume { get; init; }
        /// <summary>Retained mute-state topic (on/off) HA's mute switch reads back (#40).
        /// NULL (default) derives from the <see cref="TopicLastWill"/> namespace — see
        /// <see cref="TopicVolume"/> and <see cref="EffectiveTopicMute"/>.</summary>
        public string? TopicMute { get; init; }

        /// <summary>Momentary entrance-panel-call event topic HA's event entity reads (the
        /// outdoor door station ring). NULL (default) derives from the <see cref="TopicLastWill"/>
        /// namespace — see <see cref="TopicVolume"/> and <see cref="EffectiveTopicEntrancePanelCall"/>.</summary>
        public string? TopicEntrancePanelCall { get; init; }
        /// <summary>Momentary floor-call event topic HA's event entity reads (the dumb push-button
        /// at the apartment's own front door — independent from the entrance panel). NULL (default)
        /// derives from the <see cref="TopicLastWill"/> namespace — see
        /// <see cref="TopicVolume"/> and <see cref="EffectiveTopicFloorCall"/>.</summary>
        public string? TopicFloorCall { get; init; }
        /// <summary>Retained call-state topic HA's sensor reads. NULL (default)
        /// derives from the <see cref="TopicLastWill"/> namespace — see
        /// <see cref="TopicVolume"/> and <see cref="EffectiveTopicCallState"/>.</summary>
        public string? TopicCallState { get; init; }

        /// <summary>
        /// Stair-light SWITCH (opt-in): the WHO=8 actuator WHERE, digits only (e.g.
        /// <c>112</c>). Installation-specific — the same door-entry "light button" WHAT
        /// (21/22) drives whatever WHERE the building wired. Whether the light subsystem ships
        /// at all is governed by <see cref="HasExteriorLight"/> / <see cref="LightEnabled"/>,
        /// NOT by this alone:
        /// <list type="bullet">
        /// <item>enabled + a digit WHERE here ⇒ the switch + resync ship bound to that WHERE;</item>
        /// <item>enabled + this NULL/empty ⇒ <see cref="LightLearnMode"/>: the switch + resync ship
        /// UNAVAILABLE and a Learn button is emitted so btmqttd learns the WHERE at runtime;</item>
        /// <item>disabled ⇒ no light entities (the <c>light.json</c>/<c>light_resync.json</c>/
        /// <c>light_learn.json</c> discovery configs are tombstoned), <c>LIGHT_WHERE</c> is written
        /// empty, and <c>TOPIC_LIGHT</c> stays configured.</item>
        /// </list>
        /// The actuator is a stateless toggle (firmware-confirmed), so btmqttd tracks + persists the
        /// state; there is no readable state to poll.
        /// </summary>
        public string? LightWhere { get; init; }

        /// <summary>"Has exterior light" opt-in — a TRI-STATE. <c>true</c> ships the light
        /// subsystem (switch + resync [+ learn when the WHERE is blank]) even if
        /// <see cref="LightWhere"/> is blank — a blank WHERE means LEARN it at runtime. <c>false</c>
        /// creates no light entities, authoritatively, even if a stale <see cref="LightWhere"/>
        /// lingers. <c>null</c> (the default, for a Core-API caller that never set it) falls back to
        /// the pre-opt-in behavior: the light is enabled iff <see cref="LightWhere"/> is populated,
        /// so old callers that enabled the light by setting only <see cref="LightWhere"/> keep
        /// working (Codex). The WPF app always sets this explicitly.</summary>
        public bool? HasExteriorLight { get; init; }

        /// <summary>Light type (default false = BISTABLE). <c>false</c>: a bistable/toggle actuator
        /// that stays on until switched off — Home Assistant gets an on/off switch with tracked
        /// state plus a Resync button. <c>true</c>: a MOMENTARY / staircase-timer installation that
        /// switches the light off automatically — Home Assistant gets a single press button (no
        /// on/off state, no Resync), because only "on" can be commanded and the hardware owns the
        /// off. Learning the WHERE works in both modes. Ignored when the light is disabled.</summary>
        public bool LightMomentary { get; init; }

        /// <summary>"Has secondary lock" opt-in (default false). When true the Secondary Lock
        /// button entity is created; when false it is tombstoned (not everyone wires a second
        /// gate, so it shouldn't clutter HA). The Main Lock is always present.</summary>
        public bool HasSecondaryLock { get; init; }

        /// <summary>Retained light-availability topic. NULL (default) derives from the
        /// <see cref="TopicLastWill"/> namespace (see <see cref="EffectiveTopicLightAvail"/>).</summary>
        public string? TopicLightAvail { get; init; }

        /// <summary>Retained light-state topic (on/off) HA's light switch reads back.
        /// NULL (default) derives from the <see cref="TopicLastWill"/> namespace — see
        /// <see cref="TopicVolume"/> and <see cref="EffectiveTopicLight"/>.</summary>
        public string? TopicLight { get; init; }

        /// <summary>The volume state topic actually used: the explicit
        /// <see cref="TopicVolume"/>, or one derived from the <see cref="TopicLastWill"/>
        /// namespace so multi-unit deployments auto-scope without extra UI.</summary>
        public string EffectiveTopicVolume => TopicVolume ?? (TopicNamespace(TopicLastWill) + "volume");
        /// <summary>The mute state topic actually used (see <see cref="EffectiveTopicVolume"/>).</summary>
        public string EffectiveTopicMute => TopicMute ?? (TopicNamespace(TopicLastWill) + "mute");
        /// <summary>The entrance-panel-call event topic actually used (see <see cref="EffectiveTopicVolume"/>).</summary>
        public string EffectiveTopicEntrancePanelCall => TopicEntrancePanelCall ?? (TopicNamespace(TopicLastWill) + "entrance_panel_call");
        /// <summary>The floor-call event topic actually used (see <see cref="EffectiveTopicVolume"/>).</summary>
        public string EffectiveTopicFloorCall => TopicFloorCall ?? (TopicNamespace(TopicLastWill) + "floor_call");
        /// <summary>The call-state topic actually used (see <see cref="EffectiveTopicVolume"/>).</summary>
        public string EffectiveTopicCallState => TopicCallState ?? (TopicNamespace(TopicLastWill) + "call_state");
        /// <summary>The light state topic actually used (see <see cref="EffectiveTopicVolume"/>).</summary>
        public string EffectiveTopicLight => TopicLight ?? (TopicNamespace(TopicLastWill) + "light");
        /// <summary>The light-availability topic actually used (retained online/offline gate that
        /// keeps HA's switch + resync unavailable until a WHERE is known). Defaults from the LWT
        /// namespace like the other topics; btmqttd's default key must match (TOPIC_LIGHT_AVAIL).</summary>
        public string EffectiveTopicLightAvail => TopicLightAvail ?? (TopicNamespace(TopicLastWill) + "light_avail");
        /// <summary>Whether the exterior-light subsystem is present at all — the "has exterior
        /// light" opt-in. When true the switch + resync + learn entities ship; the WHERE may be
        /// known (from the build) or LEARNED at runtime (<see cref="LightLearnMode"/>).</summary>
        public bool LightEnabled => HasExteriorLight ?? !string.IsNullOrEmpty(LightWhere);
        /// <summary>Light enabled but no WHERE yet (blank field): the unit will LEARN the WHERE at
        /// runtime. The switch + resync ship UNAVAILABLE (gated by the light-availability topic)
        /// until the Learn button captures it, and the Learn button is emitted ONLY in this mode.</summary>
        public bool LightLearnMode => LightEnabled && string.IsNullOrEmpty(LightWhere);

        /// <summary>The namespace prefix of <paramref name="topic"/> — everything up to
        /// and INCLUDING the last '/', or "" when the topic has no '/'. Scopes the
        /// derived volume/mute state topics to the same namespace as the per-unit
        /// last-will topic.</summary>
        private static string TopicNamespace(string topic)
        {
            int slash = topic.LastIndexOf('/');
            return slash >= 0 ? topic.Substring(0, slash + 1) : "";
        }

        /// <summary>True when BOTH username and password are set (password auth).</summary>
        public bool HasAuth => !string.IsNullOrEmpty(MqttUser) && !string.IsNullOrEmpty(MqttPass);
        /// <summary>True when a CA is supplied (one-way TLS, at least).</summary>
        public bool HasTls => !string.IsNullOrEmpty(CaCertPem);
        /// <summary>True when a client certificate AND key are supplied.</summary>
        public bool HasClientCertKey =>
            !string.IsNullOrEmpty(ClientCertPem) && !string.IsNullOrEmpty(ClientKeyPem);
        /// <summary>True for mutual TLS: CA + client cert + key (what the scripts actually send).</summary>
        public bool HasMutualTls => HasTls && HasClientCertKey;
        /// <summary>True when <see cref="MqttHost"/> parses as an IP address (no hosts edit needed).</summary>
        public bool HostIsIp => IPAddress.TryParse(MqttHost, out _);
    }

    /// <summary>
    /// Installs the optional MQTT bridge into a bare ext4 firmware image via
    /// SharpExt4 — the same offline, no-mount, verify-by-read-back approach as
    /// <see cref="Ext4Probe.EnableSsh"/>. Writes the payload scripts (from
    /// embedded resources, LF-normalized), the ARM binaries (from
    /// <see cref="PayloadBinaries"/>), a generated <c>btmqttd.conf</c>, the
    /// boot symlinks, and the two idempotent init-script patches. The input image
    /// is never touched; callers operate on a modified copy.
    /// </summary>
    public static class MqttInstaller
    {
        private const string EtcDir = "/etc/btmqttd";
        private const string ResourcePrefix = "IntercomFirmwareTool.Core.Payload.mqtt.";
        private const long MaxEditFileBytes = 4L * 1024 * 1024; // init scripts are tiny

        /// <summary>A payload script: embedded resource, install path, and octal mode.</summary>
        private sealed record ScriptFile(string Resource, string Path, int Mode);

        // Two embedded payload SysV init scripts (installed 0755 root:root — an
        // init script needs no group-write; only the daemon binary is 0775):
        //  - btmqttd: the daemon's OWN init script (start|stop|restart|status) — the
        //    single control point for the native MQTT bridge daemon.
        //  - bt_service_watchdog: keeps THIS TOOL's own daemons alive — dropbear
        //    (SSH, which bt_daemon stops when the app stack starts) — and reconciles
        //    btmqttd via `/etc/init.d/btmqttd respawn` each pass. It deliberately does
        //    NOT supervise the core BTicino services (scsserver/mosquitto/app stack):
        //    the device manages those, and restarting them from here relaunched a
        //    second colliding app stack that took the intercom down (see the script).
        // (The whole shell bridge — StartMqttSend/Receive, keypress.sh, filter.py,
        // ha_discovery.sh, mqtt_common.sh, TcpDump2Mqtt[.sh] — is replaced by
        // btmqttd, installed as an ARM binary via PayloadBinaries. btmqttd.conf is
        // generated, not a resource.)
        private static readonly ScriptFile[] Scripts =
        {
            new(ResourcePrefix + "btmqttd", "/etc/init.d/btmqttd", 755),
            new(ResourcePrefix + "bt_service_watchdog", "/etc/init.d/bt_service_watchdog", 755),
        };

        // Home Assistant discovery configs: one JSON file per entity plus a manifest
        // of "config-topic<TAB>filename". Written ALWAYS (regardless of the enable
        // flag) so btmqttd can either publish them retained (HA_DISCOVERY=1)
        // or clear the retained configs (HA_DISCOVERY=0).
        private const string HaDir = EtcDir + "/ha";

        // Boot symlinks in rc5.d. The 'z' after S99 sorts these AFTER the factory
        // S99<Capital…> services (ASCII 'z' > any capital), so they start once the
        // network, dbus/avahi and the BTicino apps are already up. Two services:
        // btmqttd (its own init script) and the watchdog that supervises + respawns
        // it. Both `start` are idempotent (they no-op if the process is already up),
        // so the boot order between the two symlinks does not matter.
        private static readonly (string Link, string Target)[] Symlinks =
        {
            ("/etc/rc5.d/S99zbtmqttd", "../init.d/btmqttd"),
            ("/etc/rc5.d/S99zBtServiceWatchdog", "../init.d/bt_service_watchdog"),
        };

        /// <summary>
        /// Installs the bridge on an open, writable filesystem, in order:
        /// idempotency guard → payload scripts → ARM binaries → TLS material →
        /// generated config → init-script patches → boot symlinks. Meant to run in
        /// the SAME fs session as <see cref="Ext4Probe.EnableSsh"/>'s edits.
        /// </summary>
        public static void InstallMqtt(ExtFileSystem fs, MqttOptions opts)
        {
            ArgumentNullException.ThrowIfNull(fs);
            ArgumentNullException.ThrowIfNull(opts);
            Validate(opts);

            // Idempotency guard: refuse an image that already carries the bridge,
            // rather than half-overwriting a previous install (the init-script
            // patches are the only idempotent parts; the rest is a fresh layout).
            // Refuse if ANYTHING already occupies the path: a directory (a prior
            // install) or an unexpected regular file/symlink — which would
            // otherwise slip past and fail later with an opaque CreateDirectory
            // error instead of this clear message.
            bool occupied = fs.DirectoryExists(EtcDir) || fs.FileExists(EtcDir);
            if (!occupied)
            {
                try { fs.ReadSymLink(EtcDir); occupied = true; } catch { /* not a symlink */ }
            }
            if (occupied)
                throw new InvalidOperationException(
                    CoreStrings.Format("Mqtt_AlreadyInstalled", EtcDir));

            // --- payload scripts (LF-normalized text) ---------------------------
            EnsureDir(fs, EtcDir);
            fs.SetMode(EtcDir, ToMode(755));
            fs.SetOwner(EtcDir, 0, 0);
            foreach (var s in Scripts)
            {
                string text = LoadScript(s.Resource);
                WriteTextFile(fs, s.Path, text);
                fs.SetMode(s.Path, ToMode(s.Mode));
                fs.SetOwner(s.Path, 0, 0);
            }

            // --- ARM binaries (byte-exact, SHA-256 verified on read) ------------
            foreach (var bin in PayloadBinaries.All)
            {
                byte[] bytes = PayloadBinaries.Read(bin);
                WriteBytesFile(fs, bin.InstallPath, bytes);
                fs.SetMode(bin.InstallPath, ToMode(775));
                fs.SetOwner(bin.InstallPath, 0, 0);
            }

            // --- TLS material (only what the user supplied) ---------------------
            if (opts.HasTls)
            {
                WriteConfigFile(fs, EtcDir + "/ca.crt", opts.CaCertPem!, 644);
                if (opts.HasClientCertKey)
                {
                    WriteConfigFile(fs, EtcDir + "/client.crt", opts.ClientCertPem!, 644);
                    WriteConfigFile(fs, EtcDir + "/client.key", opts.ClientKeyPem!, 600);
                }
            }

            // --- generated config (0600 — holds MQTT_PASS) ----------------------
            WriteConfigFile(fs, EtcDir + "/btmqttd.conf", GenerateConf(opts), 600);

            // --- Home Assistant discovery configs -------------------------------
            // One retained-config JSON per entity + a manifest of
            // "config-topic<TAB>filename". Written ALWAYS (not only when enabled):
            // btmqttd publishes them retained when HA_DISCOVERY=1, and
            // CLEARS the retained configs (empty payload) when HA_DISCOVERY=0 — so a
            // rebuild that unticks discovery actually removes the HA entities from a
            // broker that already saw them, instead of leaving them orphaned.
            {
                EnsureDir(fs, HaDir);
                fs.SetMode(HaDir, ToMode(755));
                fs.SetOwner(HaDir, 0, 0);
                var manifest = new StringBuilder();
                foreach (var e in GenerateHaDiscovery(opts))
                {
                    // Wrap the ext4 write so a SharpExt4 failure names the offending entity — its
                    // native exceptions (e.g. IndexOutOfRangeException from ExtFileStream) carry no
                    // path, which otherwise makes a bad entity impossible to identify from the trace.
                    try
                    {
                        WriteConfigFile(fs, HaDir + "/" + e.FileName, e.Json, 644);
                    }
                    catch (Exception ex)
                    {
                        throw new InvalidOperationException(
                            $"Failed writing HA discovery config '{e.FileName}' (payload {Encoding.UTF8.GetByteCount(e.Json)} bytes): {ex.Message}",
                            ex);
                    }
                    manifest.Append(e.ConfigTopic).Append('\t').Append(e.FileName).Append('\n');
                }
                WriteConfigFile(fs, HaDir + "/manifest", manifest.ToString(), 644);
            }

            // --- idempotent init-script patches ---------------------------------
            PatchFlexisip(fs);
            if (!opts.HostIsIp)
            {
                // If the broker name is already resolvable via the device's hosts
                // file (the built-in "openserver" → 127.0.0.1 alias, or a mapping
                // from a prior run) and the caller gave no explicit IP override,
                // keep that mapping: don't DNS-resolve — which would fail for
                // device-only names — and don't append a duplicate line. An
                // explicit HostIpForHosts override is always honored (ValidateMqtt
                // then asserts that exact mapping).
                bool alreadyMapped = BtDaemonAppsHosts.HasHostMapping(fs, opts.MqttHost);
                if (!(alreadyMapped && string.IsNullOrWhiteSpace(opts.HostIpForHosts)))
                    PatchHosts(fs, opts.MqttHost, ResolveHostIp(opts));
            }

            // --- boot symlinks --------------------------------------------------
            if (!fs.FileExists("/etc/init.d/bt_service_watchdog"))
                throw new InvalidOperationException(
                    CoreStrings.Get("Mqtt_WatchdogMissingAfterInstall"));
            if (!fs.DirectoryExists("/etc/rc5.d"))
                throw new InvalidOperationException(CoreStrings.Get("Mqtt_Rc5dMissing"));
            foreach (var (link, target) in Symlinks)
                CreateSymLinkTolerant(fs, link, target);
        }

        /// <summary>
        /// Defensive validation of the options, independent of the UI: host is a
        /// valid IP/hostname; port in range; user/pass both-or-neither; TLS
        /// cert+key both-or-neither and a CA present for mutual TLS; and the
        /// security invariant — <c>ALLOW_REMOTE_SHELL</c> needs client auth
        /// (user/pass OR mutual TLS).
        /// </summary>
        public static void Validate(MqttOptions opts)
        {
            ArgumentNullException.ThrowIfNull(opts);

            if (string.IsNullOrWhiteSpace(opts.MqttHost) || !IsValidHost(opts.MqttHost))
                throw new ArgumentException(CoreStrings.Get("Mqtt_InvalidHost"), nameof(opts));
            if (opts.MqttPort < 1 || opts.MqttPort > 65535)
                throw new ArgumentException(CoreStrings.Get("Mqtt_InvalidPort"), nameof(opts));

            // The OpenWebNet monitor endpoint feeds btmqttd's bus-monitor config.
            // It is not exposed in the UI (the App always uses the defaults), but
            // it is a public option, so a library caller could set a bad value —
            // a 0/negative/oversized port or an empty host would generate a config
            // whose monitor session can never connect (no fallback exists). Fail fast
            // here instead, mirroring the broker host/port checks above.
            if (string.IsNullOrWhiteSpace(opts.OwnHost) || !IsValidHost(opts.OwnHost) ||
                opts.OwnPortMon < 1 || opts.OwnPortMon > 65535)
                throw new ArgumentException(CoreStrings.Get("Mqtt_InvalidOwnEndpoint"), nameof(opts));

            // The HA discovery prefix and node id become MQTT topic levels
            // ("<prefix>/<component>/<node>/<obj>/config"). The node id is stricter
            // than a generic topic level: Home Assistant's discovery parser only
            // accepts node/object ids of [A-Za-z0-9_-], so anything else (e.g.
            // "front.door", "door:1") is accepted here but silently ignored by HA.
            // The prefix is looser — it may be multi-level — but must have no
            // whitespace, no + / # wildcards, and no leading/trailing/double slash
            // (which would emit an empty topic level). Validated UNCONDITIONALLY (not
            // only when EnableHaDiscovery): the manifest is generated and btmqttd
            // reconciles it on every connect even when disabled (to CLEAR the
            // retained configs), so a bad prefix/node would otherwise pass the build
            // and fail on-device.
            {
                bool BadPrefix(string s) =>
                    string.IsNullOrWhiteSpace(s) || s.IndexOfAny(new[] { '+', '#' }) >= 0 ||
                    s.Any(char.IsWhiteSpace) ||
                    s.StartsWith('/') || s.EndsWith('/') || s.Contains("//");
                bool BadNode(string s) =>
                    string.IsNullOrEmpty(s) ||
                    !s.All(c => char.IsAsciiLetterOrDigit(c) || c == '_' || c == '-');
                if (BadPrefix(opts.HaDiscoveryPrefix) || BadNode(opts.HaNodeId))
                    throw new ArgumentException(CoreStrings.Get("Mqtt_InvalidHaDiscovery"), nameof(opts));
            }

            // A hosts-mapping IP override is only USED when the broker is given by
            // name (when the host is already an IP, PatchHosts is skipped and this
            // field is ignored). So only validate it in the hostname case — a stale
            // override left over from a previous hostname configuration must not
            // fail an otherwise-valid IP-based build. When it IS used, a malformed
            // value fails fast here, before any write session. It must be IPv4:
            // ResolveHostIp() selects an IPv4 address and the bt_hosts.sh mapping
            // in bt_daemon-apps.sh assumes an IPv4 literal, so an IPv6 override
            // would write a value the device path cannot use.
            if (!opts.HostIsIp && !string.IsNullOrWhiteSpace(opts.HostIpForHosts) &&
                !(IPAddress.TryParse(opts.HostIpForHosts, out var hostIp) &&
                  hostIp.AddressFamily == AddressFamily.InterNetwork))
                throw new ArgumentException(CoreStrings.Get("Mqtt_InvalidHostIp"), nameof(opts));

            // Broker MAC anchor (rediscovery, plaintext path): if supplied it must be
            // six hex octets, ':'/'-' separated — the exact shape btmqttd's parse_mac
            // accepts. A malformed value would be silently dropped device-side, quietly
            // disabling the plaintext anchor, so reject it here where the user sees why.
            if (!string.IsNullOrWhiteSpace(opts.MqttBrokerMac) && !IsValidMac(opts.MqttBrokerMac!))
                throw new ArgumentException(CoreStrings.Get("Mqtt_InvalidBrokerMac"), nameof(opts));

            // user/pass are both-or-neither.
            bool hasUser = !string.IsNullOrEmpty(opts.MqttUser);
            bool hasPass = !string.IsNullOrEmpty(opts.MqttPass);
            if (hasUser != hasPass)
                throw new ArgumentException(CoreStrings.Get("Mqtt_UserPassBothOrNeither"), nameof(opts));

            // Credentials are written into the sourced .conf; a CR/LF would make a
            // multi-line shell-quoted value and break mosquitto auth. Require them
            // single-line. (The TLS PEM fields legitimately contain newlines but
            // go into separate files, not the .conf, so they are not checked here.)
            var nl = new[] { '\r', '\n' };
            if ((opts.MqttUser?.IndexOfAny(nl) ?? -1) >= 0 || (opts.MqttPass?.IndexOfAny(nl) ?? -1) >= 0)
                throw new ArgumentException(CoreStrings.Get("Mqtt_CredentialNewline"), nameof(opts));

            // client cert and key are both-or-neither, and need a CA (mutual TLS).
            bool hasCert = !string.IsNullOrEmpty(opts.ClientCertPem);
            bool hasKey = !string.IsNullOrEmpty(opts.ClientKeyPem);
            if (hasCert != hasKey)
                throw new ArgumentException(CoreStrings.Get("Mqtt_CertKeyBothOrNeither"), nameof(opts));
            if (hasCert && !opts.HasTls)
                throw new ArgumentException(CoreStrings.Get("Mqtt_MutualTlsNeedsCa"), nameof(opts));

            // Security invariant: the remote command channel needs a CLIENT-
            // authenticated broker — user/pass or mutual TLS (client cert+key).
            // One-way TLS (CA only) verifies the broker, not the client.
            if (opts.AllowRemoteShell && !(opts.HasAuth || opts.HasMutualTls))
                throw new ArgumentException(CoreStrings.Get("Mqtt_RemoteShellNeedsAuth"), nameof(opts));

            // Stair-light WHERE: digits only, matching btmqttd's LIGHT_WHERE parse. A BLANK WHERE
            // is allowed when the light is enabled — it means LEARN it at runtime — so only a
            // non-empty, non-numeric value is rejected (here, where the user sees why).
            if (opts.LightEnabled && !string.IsNullOrEmpty(opts.LightWhere)
                && !opts.LightWhere.All(char.IsAsciiDigit))
                throw new ArgumentException(CoreStrings.Get("Mqtt_InvalidLightWhere"), nameof(opts));

            // Live doorbell camera (#103): validate only when enabled. The fan-out target must
            // resolve to something (it defaults to MQTT_HOST, so an empty target here means MQTT_HOST
            // itself is blank — reject where the user sees why, rather than shipping a daemon that
            // can't resolve its target). The two UDP ports must be in range and DISTINCT — video and
            // audio are separate RTP streams; aliasing them would interleave two payload types on one
            // port and break go2rtc's demux.
            if (opts.CameraEnabled)
            {
                string camTarget = opts.EffectiveCameraTargetHost;
                if (string.IsNullOrWhiteSpace(camTarget)
                    || camTarget.IndexOfAny(new[] { '\r', '\n' }) >= 0)
                    throw new ArgumentException(CoreStrings.Get("Mqtt_CameraTargetRequired"), nameof(opts));
                // The fan-out target must be a hostname or an IPv4 literal: btmqttd's av.rs sends the
                // WHO=7 `*7*300#a#b#c#d#…` frame, whose address field is IPv4-only, and its resolver
                // takes the first IPv4 a lookup yields. An IPv6 literal (or a URL / host:port string)
                // would install but never arm — reject it here where the user sees why (CodeRabbit/Codex).
                if (!IsHostnameOrIpv4(camTarget))
                    throw new ArgumentException(CoreStrings.Get("Mqtt_InvalidCameraTarget"), nameof(opts));
                // Reject an unroutable target — go2rtc/Home Assistant runs OFF the intercom, so
                // neither loopback (127/8) nor the unspecified 0.0.0.0 wildcard is a real fan-out
                // destination. Loopback would also make our add-client frame collide with the panel's
                // own `*7*300#127#0#0#1#…` media-start signal (Copilot), and 0.0.0.0 would arm the
                // siphon against a bind wildcard no receiver reads (Codex). av.rs rejects both too,
                // but fail here so a broken config never ships.
                if (IPAddress.TryParse(camTarget, out var camIp)
                    && (IPAddress.IsLoopback(camIp) || camIp.Equals(IPAddress.Any)))
                    throw new ArgumentException(CoreStrings.Get("Mqtt_CameraTargetLoopback"), nameof(opts));
                // Also reject the stock "openserver" alias: the device pins it to 127.0.0.1, so a
                // camera target equal to it (e.g. a blank target when MQTT_HOST is "openserver")
                // resolves to loopback on-device and never arms — the IP-literal check above can't
                // see that a HOSTNAME maps to loopback (Codex).
                if (BtDaemonAppsHosts.IsStockLoopbackAlias(camTarget))
                    throw new ArgumentException(CoreStrings.Get("Mqtt_CameraTargetLoopback"), nameof(opts));
                // Device resolvability: the installer pins ONLY MQTT_HOST in /etc/hosts, and the
                // daemon's musl resolver consults /etc/hosts then public DNS — never the LAN/mDNS
                // resolver (see Payload/mqtt/README.md). So a blank target (⇒ MQTT_HOST) or one equal
                // to it resolves via that pin, and an IPv4 literal is trivially resolvable; but any
                // OTHER explicit hostname would never resolve on the device and the camera could never
                // arm. Require such a target to be an IPv4 literal (Codex).
                if (!string.IsNullOrWhiteSpace(opts.CameraTargetHost)
                    && !string.Equals(opts.CameraTargetHost, opts.MqttHost, StringComparison.OrdinalIgnoreCase)
                    && !IPAddress.TryParse(opts.CameraTargetHost, out _))
                    throw new ArgumentException(CoreStrings.Get("Mqtt_CameraTargetUnresolvable"), nameof(opts));
                if (opts.CameraVideoPort is < 1 or > 65535 || opts.CameraAudioPort is < 1 or > 65535)
                    throw new ArgumentException(CoreStrings.Get("Mqtt_CameraPortRange"), nameof(opts));
                if (opts.CameraVideoPort == opts.CameraAudioPort)
                    throw new ArgumentException(CoreStrings.Get("Mqtt_CameraPortsMustDiffer"), nameof(opts));
            }

            // Topics must be non-empty and single-line (they are sourced into the
            // .conf and used as MQTT topic filters).
            foreach (var t in new[] { opts.TopicRx, opts.TopicDump, opts.TopicStartDate,
                                      opts.TopicLastWill, opts.TopicKey, opts.TopicCmdResult,
                                      opts.TopicFileContent, opts.EffectiveTopicVolume, opts.EffectiveTopicMute,
                                      opts.EffectiveTopicEntrancePanelCall, opts.EffectiveTopicFloorCall, opts.EffectiveTopicCallState,
                                      opts.EffectiveTopicLight, opts.EffectiveTopicLightAvail })
                if (string.IsNullOrWhiteSpace(t) || t.IndexOfAny(new[] { '\r', '\n' }) >= 0)
                    throw new ArgumentException(CoreStrings.Get("Mqtt_InvalidTopic"), nameof(opts));

            // The PUBLISH topics (everything except TopicRx, which is only ever
            // subscribed) must not contain the MQTT wildcards '+'/'#': those are
            // subscription filters and are rejected by mosquitto_pub -t /
            // --will-topic, so a wildcard here would build an image that cannot
            // publish at runtime. TopicRx may keep them (a valid subscription).
            foreach (var t in new[] { opts.TopicDump, opts.TopicStartDate, opts.TopicLastWill,
                                      opts.TopicKey, opts.TopicCmdResult, opts.TopicFileContent,
                                      opts.EffectiveTopicVolume, opts.EffectiveTopicMute,
                                      opts.EffectiveTopicEntrancePanelCall, opts.EffectiveTopicFloorCall, opts.EffectiveTopicCallState,
                                      opts.EffectiveTopicLight, opts.EffectiveTopicLightAvail })
                // '+'/'#' are subscription wildcards, and '$share/' is a shared-subscription
                // prefix — both are subscription-only and invalid to PUBLISH to (a broker
                // rejects the publish), so no publish topic (including the derived volume/
                // mute state topics) may use them. TopicRx, the only subscribe filter, may.
                if (t.IndexOfAny(new[] { '+', '#' }) >= 0
                    || t.StartsWith("$share/", StringComparison.Ordinal))
                    throw new ArgumentException(CoreStrings.Get("Mqtt_PublishTopicWildcard"), nameof(opts));

            // No two PUBLISH topics may be equal. Each carries a DISTINCT data stream, so a
            // collision would make two Home Assistant entities consume each other's (incompatible)
            // payloads — e.g. the floor-call event and the volume state on one topic — or corrupt
            // the retained state / last-will availability. In particular the two momentary call
            // events and the retained call-state sensor must stay independent (the whole point of
            // this feature). Defaults are namespace-scoped and always distinct, so this only rejects
            // a caller that explicitly overrode topics to collide. The light STATE topic is included
            // ONLY when the feature is enabled — it is otherwise derived but never published.
            // TopicRx is excluded: it is the sole SUBSCRIBE filter, and its self-loop overlap with
            // the publish topics is checked separately below.
            // The light STATE topic is included ONLY when the feature is enabled — it is otherwise
            // derived but never published. The light AVAILABILITY topic is included UNCONDITIONALLY:
            // the daemon publishes it in every state — online/offline when enabled, and a retained
            // offline even when DISABLED (the announce disabled-path gate) — so an alias onto it must
            // always be rejected (Codex).
            var publishTopics = new List<string>
            {
                opts.TopicDump, opts.TopicStartDate, opts.TopicLastWill, opts.TopicKey,
                opts.TopicCmdResult, opts.TopicFileContent, opts.EffectiveTopicVolume,
                opts.EffectiveTopicMute, opts.EffectiveTopicEntrancePanelCall,
                opts.EffectiveTopicFloorCall, opts.EffectiveTopicCallState,
                opts.EffectiveTopicLightAvail,
            };
            // The light STATE topic is published whenever the light is ENABLED, in BOTH modes: a
            // bistable light publishes the tracked on/off, and a momentary light publishes an empty
            // retained payload on connect to clear any stale bistable value (LightCtl::seed). So it
            // must be in the collision set for either mode — otherwise a momentary seed could delete
            // an aliased retained stream (Codex).
            if (opts.LightEnabled) publishTopics.Add(opts.EffectiveTopicLight);
            if (publishTopics.Distinct(StringComparer.Ordinal).Count() != publishTopics.Count)
                throw new ArgumentException(CoreStrings.Get("Mqtt_PublishTopicsMustDiffer"), nameof(opts));

            // No daemon-PUBLISHED data topic may live under the HA discovery prefix. That namespace
            // is owned by the discovery reconcile for RETAINED entity configs
            // (<prefix>/<component>/<node>/…/config). This is enforced REGARDLESS of the discovery
            // toggle: the manifest is installed either way — btmqttd publishes the configs retained
            // when HA_DISCOVERY=1 and CLEARS them (empty retained) when HA_DISCOVERY=0 — so a data
            // publish into that namespace would corrupt an entity's config, or, against an empty
            // retained clear, DELETE it / delete the data topic's own retained value (Codex). The
            // defaults are namespace-disjoint (data under "Bticino/", discovery under
            // "homeassistant/"), so this only rejects a caller that explicitly overrode a data topic
            // into the discovery namespace.
            {
                string discoRoot = opts.HaDiscoveryPrefix + "/";
                foreach (var pub in publishTopics)
                    if (pub.StartsWith(discoRoot, StringComparison.Ordinal))
                        throw new ArgumentException(
                            CoreStrings.Get("Mqtt_PublishTopicUnderDiscoveryPrefix"), nameof(opts));
            }

            // A shared-subscription TopicRx ("$share/<group>/<filter>") is matched by
            // the broker against the UNDERLYING <filter> that btmqttd
            // subscribes to. So the checks below must run on <filter>, not the raw
            // "$share/..." string —
            // otherwise "$share/g/Bticino/#" would slip past the self-loop guard while
            // the broker still delivers the bridge's own Bticino/tx publishes to
            // btmqttd, replaying them to the gateway. Normalise here (and
            // reject a malformed share: empty group/filter, or wildcards in the group).
            string rxFilter = opts.TopicRx;
            if (rxFilter.StartsWith("$share/", StringComparison.Ordinal))
            {
                string rest = rxFilter.Substring("$share/".Length);
                int slash = rest.IndexOf('/');
                string group = slash >= 0 ? rest.Substring(0, slash) : rest;
                string inner = slash >= 0 ? rest.Substring(slash + 1) : "";
                if (group.Length == 0 || inner.Length == 0 ||
                    group.IndexOfAny(new[] { '+', '#' }) >= 0)
                    throw new ArgumentException(
                        CoreStrings.Get("Mqtt_InvalidSubscriptionFilter"), nameof(opts));
                rxFilter = inner;
            }

            // TopicRx is the only SUBSCRIBE filter (mosquitto_sub -t). It MAY use
            // the wildcards '+'/'#', but they must follow MQTT subscription-filter
            // rules: '+' occupies a whole level and '#' is the final whole level.
            // An invalid filter (e.g. "Bticino/rx#" or "Bticino/+rx") would build
            // but be rejected by the broker at subscribe time.
            if (rxFilter.IndexOfAny(new[] { '+', '#' }) >= 0 &&
                !IsValidSubscriptionFilter(rxFilter))
                throw new ArgumentException(
                    CoreStrings.Get("Mqtt_InvalidSubscriptionFilter"), nameof(opts));

            // TopicRx must not match any PUBLISH topic (equal, or a wildcard that
            // matches one). If it did, the bridge would subscribe to its own
            // output: btmqttd publishes bus frames to TopicDump, the
            // TopicRx subscriber (btmqttd itself) would then receive them and
            // replay them to the gateway — a feedback loop that floods the bus.
            foreach (var pub in new[] { opts.TopicDump, opts.TopicStartDate, opts.TopicLastWill,
                                        opts.TopicKey, opts.TopicCmdResult, opts.TopicFileContent,
                                        opts.EffectiveTopicVolume, opts.EffectiveTopicMute,
                                        opts.EffectiveTopicEntrancePanelCall, opts.EffectiveTopicFloorCall, opts.EffectiveTopicCallState })
                if (TopicFilterMatches(rxFilter, pub))
                    throw new ArgumentException(
                        CoreStrings.Get("Mqtt_RxMatchesPublishTopic"), nameof(opts));
            // The light STATE topic is PUBLISHED whenever the light is ENABLED — a bistable light
            // publishes the tracked on/off, and a momentary light publishes an empty retained clear
            // on connect (LightCtl::seed) — so its self-loop with TopicRx is checked in both modes.
            // A DISABLED build only derives EffectiveTopicLight and never publishes it, so it's
            // excluded there (else a valid opt-out config whose namespace happens to derive a
            // colliding light topic would fail validation) — Codex.
            if (opts.LightEnabled && TopicFilterMatches(rxFilter, opts.EffectiveTopicLight))
                throw new ArgumentException(
                    CoreStrings.Get("Mqtt_RxMatchesPublishTopic"), nameof(opts));
            // The AVAILABILITY topic is published in EVERY state (including the disabled-path
            // retained offline), so its self-loop with TopicRx is checked UNCONDITIONALLY — an
            // alias onto TopicRx would make the daemon consume its own availability publish as a
            // command even with the light disabled (Codex).
            if (TopicFilterMatches(rxFilter, opts.EffectiveTopicLightAvail))
                throw new ArgumentException(
                    CoreStrings.Get("Mqtt_RxMatchesPublishTopic"), nameof(opts));
        }

        /// <summary>
        /// MQTT topic-filter match: does subscription filter <paramref name="filter"/>
        /// match the concrete topic name <paramref name="topic"/>? <c>+</c> matches
        /// exactly one level; <c>#</c> matches the remaining levels (including zero)
        /// and is terminal; other levels must be equal. A filter with no wildcards
        /// matches only its exact equal.
        /// </summary>
        private static bool TopicFilterMatches(string filter, string topic)
        {
            string[] f = filter.Split('/');
            string[] t = topic.Split('/');
            int i = 0;
            for (; i < f.Length; i++)
            {
                if (f[i] == "#") return true;      // matches the rest, incl. zero levels
                if (i >= t.Length) return false;   // filter deeper than topic (and not '#')
                if (f[i] == "+") continue;         // matches this single level
                if (!string.Equals(f[i], t[i], StringComparison.Ordinal)) return false;
            }
            return i == t.Length;                  // all filter levels consumed the topic exactly
        }

        /// <summary>
        /// True if <paramref name="topic"/> is a valid MQTT subscription filter:
        /// a level containing <c>+</c> must be exactly <c>+</c> (a whole level),
        /// and a level containing <c>#</c> must be exactly <c>#</c> and the final
        /// level. (Callers only invoke this when a wildcard is actually present.)
        /// </summary>
        private static bool IsValidSubscriptionFilter(string topic)
        {
            string[] levels = topic.Split('/');
            for (int i = 0; i < levels.Length; i++)
            {
                string lvl = levels[i];
                if (lvl.IndexOf('#') >= 0 && (lvl != "#" || i != levels.Length - 1))
                    return false;
                if (lvl.IndexOf('+') >= 0 && lvl != "+")
                    return false;
            }
            return true;
        }

        /// <summary>
        /// Re-checks every install artifact on an open filesystem (files with
        /// expected mode/owner, config content, patches, symlinks, and the runtime
        /// deps the README lists), returning a pass/fail checklist. Takes an open
        /// <see cref="ExtFileSystem"/> — symmetric with <see cref="InstallMqtt"/>,
        /// so the build pipeline can validate in the same session it wrote in, or
        /// reopen a sliced image and validate that. Check names stay English
        /// (diagnostic, like <c>ValidateSsh</c>).
        /// </summary>
        public static IReadOnlyList<Ext4Check> ValidateMqtt(ExtFileSystem fs, MqttOptions opts)
        {
            ArgumentNullException.ThrowIfNull(fs);
            ArgumentNullException.ThrowIfNull(opts);
            Validate(opts);
            var checks = new List<Ext4Check>();
            {
                // Scripts + binaries: presence, mode, owner. The ARM binaries also
                // get a byte-level read-back (length + SHA-256) so a partial or
                // corrupted write is caught — presence+mode+owner alone would pass
                // a truncated file.
                foreach (var s in Scripts)
                    CheckFile(fs, checks, s.Path, s.Mode);
                foreach (var bin in PayloadBinaries.All)
                {
                    CheckFile(fs, checks, bin.InstallPath, 775);
                    CheckBinaryBytes(fs, checks, bin);
                }

                // Config: 0600, and its CONTENT byte-for-byte equals what these
                // exact options generate — a true read-back. Checking only that
                // keys are present would pass a partial/stale write or a
                // pre-existing config with different values.
                CheckFile(fs, checks, EtcDir + "/btmqttd.conf", 600);
                string conf = fs.FileExists(EtcDir + "/btmqttd.conf")
                    ? ReadAllText(fs, EtcDir + "/btmqttd.conf") : "";
                checks.Add(new(".conf matches the generated config for these options",
                    conf == GenerateConf(opts), ""));

                // HA discovery configs: always present and byte-exact (they are
                // written regardless of the enable flag, so btmqttd can
                // publish OR clear them). Read back the manifest and each JSON,
                // comparing to what these options generate (a true read-back, like
                // the .conf check above).
                {
                    var expected = GenerateHaDiscovery(opts);
                    var expectedManifest = new StringBuilder();
                    foreach (var e in expected) expectedManifest.Append(e.ConfigTopic).Append('\t').Append(e.FileName).Append('\n');
                    CheckFile(fs, checks, HaDir + "/manifest", 644);
                    string gotManifest = fs.FileExists(HaDir + "/manifest") ? ReadAllText(fs, HaDir + "/manifest") : "";
                    checks.Add(new("ha/manifest matches the generated discovery set",
                        gotManifest == expectedManifest.ToString(), ""));
                    foreach (var e in expected)
                    {
                        CheckFile(fs, checks, HaDir + "/" + e.FileName, 644);
                        string got = fs.FileExists(HaDir + "/" + e.FileName) ? ReadAllText(fs, HaDir + "/" + e.FileName) : "";
                        checks.Add(new($"ha/{e.FileName} matches the generated config", got == e.Json, ""));
                    }
                }

                // TLS material present iff supplied.
                if (opts.HasTls) CheckFile(fs, checks, EtcDir + "/ca.crt", 644);
                if (opts.HasClientCertKey)
                {
                    CheckFile(fs, checks, EtcDir + "/client.crt", 644);
                    CheckFile(fs, checks, EtcDir + "/client.key", 600);
                }

                // flexisipsh patch: file present (explicit, so an absent patch
                // target is its own clear check, not a confusing "touch line"
                // failure), touch line exactly once, backup present.
                checks.Add(new("/etc/init.d/flexisipsh exists (patch target)",
                    fs.FileExists("/etc/init.d/flexisipsh"), ""));
                string flexi = fs.FileExists("/etc/init.d/flexisipsh")
                    ? ReadAllText(fs, "/etc/init.d/flexisipsh") : "";
                // Verify the marker sits inside the start) case exactly once and
                // immediately after the start-stop-daemon --start line — not merely
                // present somewhere in the file (a comment or another case).
                const string flexiMarker = "/bin/touch /tmp/flexisip_restarted";
                string[] flexiLines = flexi.Replace("\r\n", "\n").Split('\n');
                var (fxBlock, fxAnchor, fxCount) = ScanFlexisipStartCase(flexiLines, flexiMarker);
                bool fxPlaced = fxAnchor >= 0 && fxAnchor + 1 < flexiLines.Length &&
                    flexiLines[fxAnchor + 1].Contains(flexiMarker);
                checks.Add(new("flexisipsh touch line once, right after start-stop-daemon in start)",
                    fxBlock && fxCount == 1 && fxPlaced, ""));
                bool bakExists = fs.FileExists("/etc/init.d/flexisipsh_bak");
                checks.Add(new("flexisipsh_bak exists", bakExists, ""));
                // The patch must preserve the script's original mode/owner. The
                // backup captured them before the edit, so the patched flexisipsh
                // must still match it — a divergence means RewritePreservingMeta
                // dropped metadata.
                bool metaPreserved = false;
                if (fs.FileExists("/etc/init.d/flexisipsh") && bakExists)
                {
                    uint m1 = fs.GetMode("/etc/init.d/flexisipsh") & 0xFFF;
                    uint m2 = fs.GetMode("/etc/init.d/flexisipsh_bak") & 0xFFF;
                    var o1 = fs.GetOwner("/etc/init.d/flexisipsh");
                    var o2 = fs.GetOwner("/etc/init.d/flexisipsh_bak");
                    metaPreserved = m1 == m2 && o1 != null && o2 != null &&
                        o1.Item1 == o2.Item1 && o1.Item2 == o2.Item2;
                }
                checks.Add(new("flexisipsh mode/owner preserved (matches backup)",
                    metaPreserved, ""));

                // hosts patch: file present (explicit), and the host line present
                // iff the broker is a name.
                checks.Add(new("/etc/init.d/bt_daemon-apps.sh exists (hosts patch target)",
                    fs.FileExists(BtDaemonAppsHosts.ScriptPath), ""));
                // When the broker IP was pinned explicitly (HostIpForHosts, hostname
                // case), assert the exact mapping — otherwise a patch that wrote the
                // wrong IP would still pass. When the IP was DNS-resolved at install
                // time it isn't known here, so fall back to the host-presence check.
                // Both go through the shared whole-line matcher (a commented line
                // does not count).
                bool hostLine = (!opts.HostIsIp && !string.IsNullOrWhiteSpace(opts.HostIpForHosts))
                    ? BtDaemonAppsHosts.HasMapping(fs, opts.MqttHost, opts.HostIpForHosts!)
                    : BtDaemonAppsHosts.HasHostMapping(fs, opts.MqttHost);
                checks.Add(new("bt_daemon-apps.sh host line present iff hostname",
                    opts.HostIsIp ? !hostLine : hostLine, ""));

                // Boot symlinks.
                foreach (var (link, target) in Symlinks)
                {
                    string got = "";
                    bool ok = false;
                    try { got = fs.ReadSymLink(link); ok = got == target; } catch { }
                    checks.Add(new($"{link} -> {target}", ok, got));
                }

                // Runtime-dependency presence checks (issue #10 §F: base tools
                // "confirmed present on a factory C100X"). btmqttd is a STATIC musl
                // binary that speaks MQTT natively (rumqttc) and parses JSON / reads
                // the keypad in-process, so it invokes NONE of the shell bridge's old
                // tools — no tcpdump, python, jq, nc, awk, or mosquitto_pub/sub. What
                // still matters:
                //  - the mosquitto broker init — a baseline/expected-firmware indicator
                //    (the on-box broker the default config targets; MQTT_HOST may point
                //    elsewhere, so this is a firmware-identity check, not a hard need);
                //  - pgrep, which bt_service_watchdog uses to launch/respawn btmqttd;
                //  - route/ping — #10 base tools we do NOT invoke, a plain presence
                //    check that confirms the target is the expected firmware.
                var deps = new (string Name, string[] Paths)[]
                {
                    ("mosquitto (broker init)", new[] { "/etc/init.d/mosquitto" }),
                    ("pgrep", new[] { "/usr/bin/pgrep" }),                        // bt_service_watchdog respawns btmqttd
                    ("route", new[] { "/sbin/route", "/usr/sbin/route", "/bin/route" }), // #10 base tool (not invoked by us)
                    ("ping", new[] { "/bin/ping", "/usr/bin/ping" }),            // #10 base tool (not invoked by us)
                };
                foreach (var (name, paths) in deps)
                    // Present = resolves to a real file, FOLLOWING symlinks: on a
                    // stock image these tools are almost always symlinks (busybox
                    // applets like route/ping, or pgrep -> pgrep.procps), and the ext
                    // reader's FileExists returns false for a symlink. A plain
                    // FileExists therefore false-fails a tool that IS present.
                    checks.Add(new($"runtime dep {name} present",
                        paths.Any(p => DependencyPresent(fs, p)),
                        string.Join(" | ", paths)));
            }
            return checks;
        }

        /// <summary>
        /// True when <paramref name="path"/> resolves to an existing regular file,
        /// following symlinks. The ext reader's <c>FileExists</c> reports false for a
        /// symlink, but on the device runtime tools are commonly symlinks (busybox
        /// applets; version links like <c>python -&gt; python2 -&gt; python2.7</c>), so a
        /// bare <c>FileExists</c> would false-fail a tool that is actually present. A
        /// dangling symlink still fails (its chain never lands on a real file). The
        /// hop budget guards a symlink cycle.
        /// </summary>
        private static bool DependencyPresent(ExtFileSystem fs, string path)
        {
            string current = path;
            for (int hops = 0; hops < 40; hops++)
            {
                if (fs.FileExists(current)) return true;   // real file (executable / init script)
                string target;
                try { target = fs.ReadSymLink(current); } // throws if not a symlink (or absent)
                catch { return false; }
                if (string.IsNullOrEmpty(target)) return false;
                current = ResolveLinkTarget(current, target);
            }
            return false; // exceeded the hop budget (likely a cycle) — treat as absent
        }

        /// <summary>
        /// Resolves a symlink target — absolute, or relative to the link's own
        /// directory — to a normalized absolute path, collapsing <c>.</c> and
        /// <c>..</c> segments. (Parent components are assumed to be real directories,
        /// which holds for the runtime-dep paths we check.)
        /// </summary>
        private static string ResolveLinkTarget(string linkPath, string target)
        {
            string combined;
            if (target.StartsWith("/", StringComparison.Ordinal))
            {
                combined = target;
            }
            else
            {
                int slash = linkPath.LastIndexOf('/');
                string dir = slash > 0 ? linkPath.Substring(0, slash) : "";
                combined = dir + "/" + target;
            }

            var parts = new List<string>();
            foreach (var seg in combined.Split('/'))
            {
                if (seg.Length == 0 || seg == ".") continue;
                if (seg == "..") { if (parts.Count > 0) parts.RemoveAt(parts.Count - 1); }
                else parts.Add(seg);
            }
            return "/" + string.Join("/", parts);
        }

        // ---- config generation --------------------------------------------------

        private static string GenerateConf(MqttOptions opts)
        {
            var sb = new StringBuilder();
            sb.Append("# btmqttd - configuration (generated by IntercomFirmwareTool)\n");
            sb.Append("# Sourced by POSIX sh; installed 0600 root:root. Do not hand-edit on-device.\n\n");

            sb.Append(Conf("MQTT_HOST", opts.MqttHost));
            sb.Append("MQTT_PORT=").Append(opts.MqttPort).Append('\n');

            sb.Append(Conf("MQTT_USER", opts.MqttUser ?? ""));
            sb.Append(Conf("MQTT_PASS", opts.MqttPass ?? ""));

            // TLS file paths (only set when the material was written).
            sb.Append(Conf("MQTT_CAFILE", opts.HasTls ? EtcDir + "/ca.crt" : ""));
            sb.Append(Conf("MQTT_CERTFILE", opts.HasClientCertKey ? EtcDir + "/client.crt" : ""));
            sb.Append(Conf("MQTT_KEYFILE", opts.HasClientCertKey ? EtcDir + "/client.key" : ""));

            sb.Append(Conf("TOPIC_RX", opts.TopicRx));
            sb.Append(Conf("TOPIC_DUMP", opts.TopicDump));
            sb.Append(Conf("TOPIC_STARTD", opts.TopicStartDate));
            sb.Append(Conf("TOPIC_LASTWILL", opts.TopicLastWill));
            sb.Append(Conf("TOPIC_KEY", opts.TopicKey));
            sb.Append(Conf("TOPIC_CMD_RESULT", opts.TopicCmdResult));
            sb.Append(Conf("TOPIC_FILE_CONTENT", opts.TopicFileContent));

            // Volume control (#40): retained state topics btmqttd publishes and the HA
            // slider/mute switch read back. Commands reuse TOPIC_RX (JSON actions).
            // Effective* resolves the auto-scoped default (derived from the last-will
            // namespace) or an explicit override.
            sb.Append(Conf("TOPIC_VOLUME", opts.EffectiveTopicVolume));
            sb.Append(Conf("TOPIC_MUTE", opts.EffectiveTopicMute));

            // Door-entry events: two INDEPENDENT momentary events — the entrance-panel call
            // (outdoor door station) and the floor call (the apartment's own front-door button) —
            // plus the retained call-state sensor btmqttd publishes from the WHO=8 monitor stream.
            sb.Append(Conf("TOPIC_ENTRANCE_PANEL_CALL", opts.EffectiveTopicEntrancePanelCall));
            sb.Append(Conf("TOPIC_FLOOR_CALL", opts.EffectiveTopicFloorCall));
            sb.Append(Conf("TOPIC_CALL_STATE", opts.EffectiveTopicCallState));

            // Stair-light SWITCH (opt-in). LIGHT_ENABLED is the "has exterior light" choice: the
            // subsystem runs when set, even with an EMPTY LIGHT_WHERE (learn mode — btmqttd learns
            // the WHO=8 actuator WHERE from the first physical press). TOPIC_LIGHT is the retained
            // on/off state btmqttd tracks (no readable state); TOPIC_LIGHT_AVAIL gates HA's switch +
            // resync OFFLINE until a WHERE is known. Commands reuse TOPIC_RX (JSON actions).
            sb.Append(Conf("LIGHT_ENABLED", opts.LightEnabled ? "1" : "0"));
            // Write the WHERE only when the light is ON. Emitting a leftover WHERE with
            // LIGHT_ENABLED=0 would re-enable the subsystem device-side, because config.rs
            // treats any valid LIGHT_WHERE as enabling (legacy-conf compatibility) — Codex.
            sb.Append(Conf("LIGHT_WHERE", opts.LightEnabled ? (opts.LightWhere ?? "") : ""));
            // Light TYPE: "momentary" (staircase-timer install → press only, no tracked state) vs the
            // default "bistable" (toggle with tracked on/off + resync). btmqttd branches its light
            // controller and HA discovery on this.
            sb.Append(Conf("LIGHT_MODE", opts.LightMomentary ? "momentary" : "bistable"));
            sb.Append(Conf("TOPIC_LIGHT", opts.EffectiveTopicLight));
            sb.Append(Conf("TOPIC_LIGHT_AVAIL", opts.EffectiveTopicLightAvail));

            // Live doorbell camera (#103): opt-in. When enabled, av.rs adds a UDP client to the
            // on-board bt_av_media daemon on every A/V session and fans the cleartext RTP to
            // CAMERA_TARGET_HOST:CAMERA_{VIDEO,AUDIO}_PORT (where a go2rtc stream turns it into an
            // HA camera). CAMERA_BRANCH selects the video multiudpsink branch: 1 = low-res
            // (universal), 0 = hi-res (C300X only). The target defaults to MQTT_HOST device-side too,
            // but we write the resolved value so a later MQTT_HOST edit can't silently move it.
            sb.Append("CAMERA_ENABLED=").Append(opts.CameraEnabled ? '1' : '0').Append('\n');
            // Only serialize the user's target when the camera is ENABLED. When disabled the value is
            // irrelevant (av.rs never runs), and writing it would let an unvalidated multi-line target
            // (a library caller, or a paste) inject a second KEY=value line — e.g. `x\nMQTT_HOST=bad`
            // — that config.rs's line-based parse_env would honour, hijacking the broker even with the
            // camera off (Codex). Disabled ⇒ empty, which config.rs falls back to MQTT_HOST for.
            sb.Append(Conf("CAMERA_TARGET_HOST", opts.CameraEnabled ? opts.EffectiveCameraTargetHost : ""));
            sb.Append("CAMERA_VIDEO_PORT=").Append(opts.CameraVideoPort).Append('\n');
            sb.Append("CAMERA_AUDIO_PORT=").Append(opts.CameraAudioPort).Append('\n');
            sb.Append("CAMERA_BRANCH=").Append(opts.CameraBranch).Append('\n');
            // On-demand viewing (#104): sip.rs INVITEs the panel to bring the idle session up. Only
            // meaningful with the media path, so gate the ENABLED flag on CameraEnabled too — the
            // daemon does the same, but coercing here keeps a stray on-demand=1 from a camera-off
            // conf from ever reading as active. The daemon clamps the viewing window (>0, default 30).
            sb.Append("CAMERA_ONDEMAND_ENABLED=")
                .Append(opts.CameraEnabled && opts.CameraOnDemand ? '1' : '0')
                .Append('\n');
            // Coerce a non-positive viewing window to the default (30) HERE too, so the emitted conf is
            // always a valid value rather than a 0/negative the daemon would silently override —
            // keeping the written conf and the daemon's effective behaviour in step (Copilot).
            sb.Append("CAMERA_VIEW_IDLE_SECS=")
                .Append(opts.CameraViewIdleSecs > 0 ? opts.CameraViewIdleSecs : 30)
                .Append('\n');

            sb.Append("ALLOW_REMOTE_SHELL=").Append(opts.AllowRemoteShell ? '1' : '0').Append('\n');

            // OpenWebNet gateway endpoint for the bus MONITOR session (btmqttd opens it
            // directly — no tcpdump/python; the retired CAPTURE_MODE toggle is gone).
            sb.Append(Conf("OWN_HOST", opts.OwnHost));
            sb.Append("OWN_PORT_MON=").Append(opts.OwnPortMon).Append('\n');

            // Bus payload format: 'json' (default; one structured object per frame — see
            // btmqttd's own::frame_to_json) or 'raw' (OpenWebNet frames verbatim). Only
            // TOPIC_DUMP is affected; btmqttd parses frames natively (serde_json). TOPIC_KEY
            // is JSON either way.
            sb.Append(Conf("PAYLOAD_FORMAT", opts.UseJsonPayload ? "json" : "raw"));

            // Home Assistant auto-discovery: when 1, btmqttd publishes the retained
            // discovery configs (from the installer-generated manifest under HaDir) on
            // every connect; when 0 it clears them. Reconciled natively (no ha_discovery.sh).
            sb.Append("HA_DISCOVERY=").Append(opts.EnableHaDiscovery ? '1' : '0').Append('\n');

            // Broker rediscovery (#43/#44): when 1, btmqttd recovers the broker after its LAN
            // IP changes by scanning the broker name's /24 and repointing its /etc/hosts
            // mapping. It self-gates device-side (needs a hostname config + a trust anchor —
            // TLS, or the broker MAC written below), so this stays safe even when on by default.
            sb.Append("MQTT_REDISCOVERY=").Append(opts.MqttRediscovery ? '1' : '0').Append('\n');

            // Broker MAC anchor (#43): the plaintext trust anchor for rediscovery.
            // Emit only when set (Validate has already checked its shape) — absent, the
            // device falls back to requiring TLS before adopting a rescanned broker.
            if (!string.IsNullOrWhiteSpace(opts.MqttBrokerMac))
                sb.Append(Conf("MQTT_BROKER_MAC", opts.MqttBrokerMac!));
            return sb.ToString();
        }

        /// <summary>
        /// One <c>KEY='value'</c> config line. Single-quoted with each embedded
        /// single quote escaped as <c>'\''</c>, so a value with shell
        /// metacharacters (or an injected newline — already rejected in
        /// <see cref="Validate"/>) cannot run as shell when the file is sourced.
        /// </summary>
        private static string Conf(string key, string value) =>
            $"{key}='{value.Replace("'", "'\\''")}'\n";

        // ---- Home Assistant MQTT discovery --------------------------------------

        /// <summary>A discovery entity: its retained-config topic, the on-device
        /// JSON filename (under <see cref="HaDir"/>), and the JSON payload.</summary>
        private readonly record struct HaEntity(string FileName, string ConfigTopic, string Json);

        // Default STJ encoder: it does NOT escape the '{'/'}' of value_template
        // (only '<' '>' '&' '+' and non-ASCII, none of which appear in the default
        // payloads), so the discovery JSON stays valid and readable for Home
        // Assistant. Preferred over UnsafeRelaxedJsonEscaping — the relaxed encoder
        // buys nothing here (no chars need it) and gets flagged by security tooling;
        // the default even escapes '&'/'<'/'>' should a user set an exotic topic.
        // WriteIndented for a readable on-device file.
        private static readonly JsonSerializerOptions HaJson = new()
        {
            WriteIndented = true,
            // Force LF: WriteIndented otherwise follows the host newline, so a Windows
            // build would emit CRLF and the on-device JSON would differ byte-for-byte
            // from a Linux build (and from the ValidateMqtt read-back expectation).
            NewLine = "\n",
        };

        /// <summary>
        /// The volume / lock / light / on-demand-camera CONTROL entities' identity — (JSON filename,
        /// discovery component, object id). Used by the TOMBSTONE path in
        /// <see cref="GenerateHaDiscovery"/> (when there is no concrete command topic) to
        /// emit the exact same config topics with an empty payload, so a previous build's
        /// controls are cleared. The real-config path builds each entity inline (their
        /// JSON bodies differ: number vs switch vs button, and the light is opt-in), so this
        /// list MUST be kept in step with those entities' filenames/components/object ids — it is the
        /// single definition of WHICH config topics the controls occupy (constant across
        /// builds; they depend only on the node id, not on TopicRx).
        /// </summary>
        private static readonly (string File, string Component, string ObjectId)[] ControlEntityIds =
        {
            ("volume.json", "number", "volume"),
            ("mute.json", "switch", "mute"),
            ("volume_up.json", "button", "volume_up"),
            ("volume_down.json", "button", "volume_down"),
            ("main_lock.json", "button", "main_lock"),
            ("secondary_lock.json", "button", "secondary_lock"),
            ("light.json", "switch", "light"),
            ("light_press.json", "button", "light_press"),
            ("light_resync.json", "button", "light_resync"),
            ("light_learn.json", "button", "light_learn"),
            ("view_camera.json", "button", "view_camera"),
            ("stop_camera.json", "button", "stop_camera"),
        };

        /// <summary>
        /// Slugify a node id into the object part of an HA <c>entity_id</c>: lower-case, with
        /// any character outside <c>[a-z0-9_]</c> replaced by <c>'_'</c>. HA accepts only
        /// <c>[a-z0-9_]</c> there and <b>rejects</b> (rather than normalises) a
        /// <c>default_entity_id</c> that violates it, so a custom node with uppercase or
        /// <c>'-'</c> (both permitted by <c>BadNode</c>) must be normalised first. The
        /// model-derived nodes (<c>bticino_c100x</c>/<c>c300x</c>) are already valid.
        /// </summary>
        private static string EntityIdSlug(string node)
        {
            var sb = new StringBuilder(node.Length);
            foreach (char c in node)
            {
                if (c is >= 'a' and <= 'z' or >= '0' and <= '9' or '_') sb.Append(c);
                else if (c is >= 'A' and <= 'Z') sb.Append((char)(c + 32));
                else sb.Append('_');
            }
            return sb.ToString();
        }

        /// <summary>
        /// Builds the Home Assistant MQTT discovery configs for the bridge: a
        /// connectivity <c>binary_sensor</c> (online/offline via the last-will
        /// topic), a diagnostic <c>sensor</c> for the last OpenWebNet bus frame, a
        /// <c>sensor</c> for the last key press (with code/value as attributes), and
        /// the volume-control set (#40): a <c>number</c> slider, a <c>switch</c> for
        /// mute (the device's real RingEnable toggle, independent of the volume), and
        /// two <c>button</c>s for ±10%, plus a gate <c>button</c>
        /// (#41). All grouped under one HA device. The volume/mute/gate command entities
        /// publish small JSON ACTIONS to <see cref="MqttOptions.TopicRx"/> (the
        /// existing command channel — no new subscription), so they exercise the same
        /// OWN-bus capability a raw frame on that topic already has; btmqttd owns all
        /// volume/mute state (survives HA restarts). Discovery stays opt-in
        /// (<see cref="MqttOptions.EnableHaDiscovery"/>): when off, btmqttd CLEARS
        /// these retained configs. Topics/prefix/node are baked in here, so the
        /// on-device publisher just sends each payload retained.
        /// </summary>
        private static IReadOnlyList<HaEntity> GenerateHaDiscovery(MqttOptions opts)
        {
            string prefix = opts.HaDiscoveryPrefix;
            string node = opts.HaNodeId;

            // Shared device block so every entity groups under one HA device. The friendly
            // name is model-dependent (BTicino Classe 100X / 300X), set by the App from the
            // firmware being customized.
            var device = new
            {
                identifiers = new[] { node },
                name = opts.HaDeviceName,
                manufacturer = "BTicino",
                model = "OpenWebNet MQTT bridge",
            };

            string Topic(string component, string objectId) =>
                $"{prefix}/{component}/{node}/{objectId}/config";

            // HA's default_entity_id SUGGESTS the entity_id; it must be FULLY QUALIFIED
            // ("<domain>.<object>"). Deriving it as "<component>.<node>_<objectId>" (e.g.
            // sensor.bticino_c100x_bus) forces the entity_id prefix to follow the node,
            // independent of the device's model-dependent friendly name. (The older
            // `object_id` field is deprecated and removed in HA 2026.4, so it is not used.)
            //
            // HA entity_ids allow only [a-z0-9_] in the object part, but a CUSTOM node id may
            // contain uppercase or '-' (BadNode permits [A-Za-z0-9_-]) — HA would REJECT such a
            // default_entity_id rather than normalise it. Slugify the node here (lowercase;
            // any other char -> '_') so e.g. "Front-Door" yields sensor.front_door_bus. The
            // model-derived nodes (bticino_c100x/c300x) are already valid and pass through
            // unchanged. Only the entity_id is slugged; the discovery topic and unique_id keep
            // the raw node.
            string nodeSlug = EntityIdSlug(node);
            string EntId(string component, string objectId) => $"{component}.{nodeSlug}_{objectId}";

            // Availability (TopicLastWill): btmqttd is a single-connection MQTT client,
            // so availability is ATOMIC (issue #32). It registers the retained 'offline'
            // last will at CONNECT — the broker delivers it on an UNCLEAN drop — and
            // publishes retained 'online' only AFTER the command subscription's SubAck is
            // confirmed at QoS>=1, so ONLINE never precedes a working command channel. A
            // clean shutdown (SIGTERM/SIGINT) publishes 'offline' explicitly. No 30 s
            // watchdog refresh and no birth/will race: the connectivity sensor and the
            // per-entity availability blocks below reflect the bridge's real state.
            var entities = new List<HaEntity>();

            // Legacy migration (one release, #41 → Main/Secondary Lock): the single "Gate"
            // button (object id `gate`) that shipped in an earlier release was replaced by
            // main_lock/secondary_lock. ha::reconcile only touches config topics present in
            // the NEW manifest, so a prior install's retained `button/<node>/gate/config`
            // would linger — HA would keep showing a "Gate" button whose {"action":"gate"}
            // btmqttd no longer handles (a dead control). Tombstone it: same config topic,
            // EMPTY retained payload = cleared. Emitted UNCONDITIONALLY (even with a concrete
            // command topic, unlike the control tombstones below) so the migration also runs
            // on a normal working install. SAFE — unlike a whole-node migration, this stays
            // within THIS bridge's OWN current node/object (the multi-unit contract already
            // requires distinct node ids), so it can't reach another bridge's device. On a
            // fresh install the topic holds nothing, so the empty publish is a harmless
            // no-op. Remove this entry a release after the rename has propagated.
            entities.Add(new HaEntity("gate.json", Topic("button", "gate"), ""));

            // Connectivity: reports online/offline itself, so it carries NO
            // availability block (else HA would show it "unavailable" when offline
            // instead of "off").
            entities.Add(new HaEntity(
                "status.json",
                Topic("binary_sensor", "status"),
                JsonSerializer.Serialize(new
                {
                    name = "Bridge",
                    unique_id = $"{node}_status",
                    default_entity_id = EntId("binary_sensor", "status"),
                    device_class = "connectivity",
                    state_topic = opts.TopicLastWill,
                    payload_on = "online",
                    payload_off = "offline",
                    entity_category = "diagnostic",
                    device,
                }, HaJson)));

            // Last OpenWebNet bus frame (diagnostic). In JSON payload mode the state is the
            // frame and the parsed fields (type/who/what/where/params/ts) are exposed as entity
            // attributes; in raw mode the state is the frame string.
            // Both templates TOLERATE a non-JSON payload: in raw mode (PAYLOAD_FORMAT=raw)
            // btmqttd publishes raw "*...##" frames on TopicDump. The value_template
            // then still shows the raw frame instead of going unknown ("value_json is defined else
            // value"), and the json_attributes_template yields "{}" instead of letting Home
            // Assistant try to parse each raw frame as attributes JSON (which logs "Erroneous
            // JSON" noise) — attributes just stay empty until JSON output resumes.
            // Two separate anonymous objects (not a ?: to object) so JsonSerializer keeps each
            // one's compile-time type — serializing through a plain `object` would emit `{}`.
            string busConfigJson = opts.UseJsonPayload
                ? JsonSerializer.Serialize(new
                {
                    name = "OpenWebNet bus",
                    unique_id = $"{node}_bus",
                    default_entity_id = EntId("sensor", "bus"),
                    state_topic = opts.TopicDump,
                    value_template = "{{ value_json.frame if value_json is defined else value }}",
                    json_attributes_topic = opts.TopicDump,
                    json_attributes_template = "{{ value if value_json is defined else '{}' }}",
                    icon = "mdi:bus",
                    entity_category = "diagnostic",
                    availability_topic = opts.TopicLastWill,
                    payload_available = "online",
                    payload_not_available = "offline",
                    device,
                }, HaJson)
                : JsonSerializer.Serialize(new
                {
                    name = "OpenWebNet bus",
                    unique_id = $"{node}_bus",
                    default_entity_id = EntId("sensor", "bus"),
                    state_topic = opts.TopicDump,
                    icon = "mdi:bus",
                    entity_category = "diagnostic",
                    availability_topic = opts.TopicLastWill,
                    payload_available = "online",
                    payload_not_available = "offline",
                    device,
                }, HaJson);
            entities.Add(new HaEntity("bus.json", Topic("sensor", "bus"), busConfigJson));

            // Last key press: state = key name, code/value/ts exposed as attributes. btmqttd publishes
            // {"key":…,"code":…,"value":"pressed|released","ts":…} NON-retained, QoS 0.
            //
            // FRESHNESS (issue #71): a keypress is momentary — only meaningful NOW — so btmqttd DROPS
            // it while the broker is offline (never queued for a late replay that would fire a stale
            // automation), and stamps each event with a UTC ISO-8601 `ts`. Gate any time-sensitive
            // key automation (a door code, a "press N to…" shortcut) on that stamp, e.g.
            //   trigger: { platform: mqtt, topic: <key topic> }
            //   condition: "{{ -1 <= now().timestamp() - as_timestamp(trigger.payload_json.ts) < 5 }}"
            // (bounded both sides — see the call-event entities above — assumes NTP-synced clocks).
            // Unlike the call events there is NO burst-coalescing: each keypress is a distinct input.
            entities.Add(new HaEntity(
                "key.json",
                Topic("sensor", "key"),
                JsonSerializer.Serialize(new
                {
                    name = "Last key",
                    unique_id = $"{node}_key",
                    default_entity_id = EntId("sensor", "key"),
                    state_topic = opts.TopicKey,
                    value_template = "{{ value_json.key }}",
                    json_attributes_topic = opts.TopicKey,
                    icon = "mdi:gesture-tap-button",
                    availability_topic = opts.TopicLastWill,
                    payload_available = "online",
                    payload_not_available = "offline",
                    device,
                }, HaJson)));

            // Legacy migration (one release, #69 → Entrance Panel Call): the "Doorbell" event
            // (object id `doorbell`) that shipped in #40 was renamed to entrance_panel_call.
            // ha::reconcile only touches config topics present in the NEW manifest, so a prior
            // install's retained `event/<node>/doorbell/config` would linger as an orphan
            // "Doorbell" entity. Tombstone it: same config topic, EMPTY retained payload = cleared.
            // Emitted UNCONDITIONALLY (like the gate tombstone above) so it runs on a normal
            // install too; on a fresh install the topic holds nothing, so it is a harmless no-op.
            // SAFE — stays within THIS bridge's OWN node/object. Remove a release after the rename
            // has propagated.
            entities.Add(new HaEntity("doorbell.json", Topic("event", "doorbell"), ""));

            // Entrance-panel call: a momentary EVENT fired when the OUTDOOR door-station call is
            // seen on the bus (WHO=8 `*8*1#1#4#21*<WHERE>##`). `event_types` lists "pressed";
            // btmqttd publishes {"event_type":"pressed","where":…,"ts":…} NON-retained, so it fires
            // once per ring and never re-fires on an HA reconnect. HA reads `event_type` from
            // the JSON and exposes the extra `where` and `ts` keys as attributes.
            //
            // FRESHNESS (issue #71): a momentary "pressed" is only meaningful NOW. btmqttd already
            // drops it at the source while the broker is offline (never queued for a late replay),
            // but the `ts` (UTC ISO-8601) is the END-TO-END backstop: gate any time-sensitive
            // automation on it so a stale event that somehow arrived late is ignored, e.g.
            //   trigger: { platform: mqtt, topic: <entrance_panel_call topic> }
            //   condition: "{{ -1 <= now().timestamp() - as_timestamp(trigger.payload_json.ts) < 5 }}"
            // Bound the age on BOTH sides: a one-sided `age < 5` treats a FUTURE-dated payload as
            // fresh (negative age), so an event delayed while the intercom clock ran ahead of HA
            // (e.g. a bad RTC restore before NTP sync) would slip through for the whole offset. The
            // lower bound rejects that. It is `-1`, not `0`, because `ts` is whole-second precision
            // (own::utc_now_iso) and the intercom may sit a fraction ahead of HA even under NTP, so
            // a genuine press can compute an age just below zero; -1 s absorbs that while still
            // rejecting materially future-dated (stale) events. Assumes the clocks are NTP-synced.
            // Freshness is only truly knowable at the consumer, so enforce the TTL there.
            entities.Add(new HaEntity(
                "entrance_panel_call.json",
                Topic("event", "entrance_panel_call"),
                JsonSerializer.Serialize(new
                {
                    name = "Entrance Panel Call",
                    unique_id = $"{node}_entrance_panel_call",
                    default_entity_id = EntId("event", "entrance_panel_call"),
                    state_topic = opts.EffectiveTopicEntrancePanelCall,
                    event_types = new[] { "pressed" },
                    device_class = "doorbell",
                    icon = "mdi:bell-ring",
                    availability_topic = opts.TopicLastWill,
                    payload_available = "online",
                    payload_not_available = "offline",
                    device,
                }, HaJson)));

            // Floor call: a momentary EVENT fired when the dumb push-button at the apartment's
            // OWN front door is pressed (WHO=8 `*8*1#13#2*<WHERE>##`). Wholly INDEPENDENT from the
            // entrance-panel call above — a separate entity so automations never conflate the two.
            // Same delivery model: {"event_type":"pressed","where":…,"ts":…} NON-retained, fires
            // once per ring, and carries the same `ts` freshness stamp (gate time-sensitive
            // automations on it — see the entrance-panel entity above). btmqttd also SUPPRESSES the
            // concurrent dim-35 ringing so a floor call never surfaces on the entrance-panel
            // call-state sensor.
            entities.Add(new HaEntity(
                "floor_call.json",
                Topic("event", "floor_call"),
                JsonSerializer.Serialize(new
                {
                    name = "Floor Call",
                    unique_id = $"{node}_floor_call",
                    default_entity_id = EntId("event", "floor_call"),
                    state_topic = opts.EffectiveTopicFloorCall,
                    event_types = new[] { "pressed" },
                    device_class = "doorbell",
                    icon = "mdi:doorbell",
                    availability_topic = opts.TopicLastWill,
                    payload_available = "online",
                    payload_not_available = "offline",
                    device,
                }, HaJson)));

            // Call state: a SENSOR reflecting the WHO=8 dim-35 call state. btmqttd publishes
            // it RETAINED as {"state":<idle|ringing|in_call|active>,"code":<N>} (mapping
            // confirmed against live answered + unanswered calls); the template tolerates a
            // non-JSON payload, and the raw `code` is exposed as an attribute for granularity.
            entities.Add(new HaEntity(
                "call_state.json",
                Topic("sensor", "call_state"),
                JsonSerializer.Serialize(new
                {
                    name = "Call state",
                    unique_id = $"{node}_call_state",
                    default_entity_id = EntId("sensor", "call_state"),
                    state_topic = opts.EffectiveTopicCallState,
                    value_template = "{{ value_json.state if value_json is defined else value }}",
                    json_attributes_topic = opts.EffectiveTopicCallState,
                    json_attributes_template = "{{ value if value_json is defined else '{}' }}",
                    icon = "mdi:phone-in-talk",
                    availability_topic = opts.TopicLastWill,
                    payload_available = "online",
                    payload_not_available = "offline",
                    device,
                }, HaJson)));

            // ---- Volume control (#40) + gate (#41) — COMMAND entities ---------------
            // These publish JSON actions to the command channel; btmqttd routes volume/
            // mute/step to the openserver dimension session (:20000) and gate to :30006,
            // and owns all volume state. State is read back from the retained
            // TopicVolume / TopicMute topics btmqttd maintains from the bus.
            //
            // HA's command_topic must be a CONCRETE publish topic. TopicRx MAY be a
            // wildcard or a "$share/<group>/<filter>" subscription filter (valid for the
            // daemon to SUBSCRIBE, per Validate), but HA cannot publish a command to a
            // wildcard, and publishing to "$share/..." is invalid. Derive the concrete
            // publish topic (the plain topic, or a $share subscription's underlying
            // filter when THAT is concrete).
            //
            // The five control config topics are the SAME regardless (they depend on the
            // node id, not TopicRx). When there is NO concrete publish topic, emit them
            // as TOMBSTONES — same config topic, EMPTY payload — instead of omitting
            // them: ha::reconcile only touches config topics present in the manifest, so
            // omitting them would leave any controls a PREVIOUS concrete-TopicRx build
            // published retained on the broker, and HA would keep showing buttons that
            // publish to the stale command topic. An empty retained payload clears them.
            // (With a concrete topic, the real working configs are built below.) The
            // read-only sensors above always ship — graceful degradation, no regression.
            string? controlTopic = ConcretePublishTopic(opts.TopicRx);
            if (controlTopic is null)
            {
                foreach (var (file, component, objectId) in ControlEntityIds)
                    entities.Add(new HaEntity(file, Topic(component, objectId), ""));
                return entities;
            }

            // Volume slider: 0..100 step 10. command_template renders the numeric value
            // into the volume action; state_topic reflects the real level (learned from
            // the bus, so it also follows changes made on the unit's own menu).
            entities.Add(new HaEntity(
                "volume.json",
                Topic("number", "volume"),
                JsonSerializer.Serialize(new
                {
                    name = "Volume",
                    unique_id = $"{node}_volume",
                    default_entity_id = EntId("number", "volume"),
                    command_topic = controlTopic,
                    // QoS 1: an ABSOLUTE, idempotent command (set to N / mute on|off), so a
                    // QoS-1 redelivery is harmless, while the durable QoS-1 command
                    // subscription means a press published during a brief daemon reconnect
                    // is queued rather than dropped (effective delivery is min(pub, sub)).
                    // The non-idempotent step/gate buttons below use QoS 0.
                    qos = 1,
                    // `value | int`: HA number entities carry the value as a float, so a
                    // bare `{{ value }}` can render "50.0"; `| int` sends a clean integer.
                    // (btmqttd also accepts a float defensively — see json_percent.)
                    command_template = "{\"action\":\"volume\",\"value\":{{ value | int }}}",
                    state_topic = opts.EffectiveTopicVolume,
                    min = 0,
                    max = 100,
                    step = 10,
                    mode = "slider",
                    icon = "mdi:volume-high",
                    availability_topic = opts.TopicLastWill,
                    payload_available = "online",
                    payload_not_available = "offline",
                    device,
                }, HaJson)));

            // Mute switch: on = mute, off = ring. btmqttd drives the device's own
            // RingEnable dimension (WHO=8 dim 33), which silences the ringtone WITHOUT
            // touching the volume — so unmute rings again at the same level and the
            // slider is unaffected. state_topic follows the real RingEnable state, so
            // muting via the unit's own menu flips this switch too.
            entities.Add(new HaEntity(
                "mute.json",
                Topic("switch", "mute"),
                JsonSerializer.Serialize(new
                {
                    name = "Mute",
                    unique_id = $"{node}_mute",
                    default_entity_id = EntId("switch", "mute"),
                    command_topic = controlTopic,
                    // QoS 1: an ABSOLUTE, idempotent command (set to N / mute on|off), so a
                    // QoS-1 redelivery is harmless, while the durable QoS-1 command
                    // subscription means a press published during a brief daemon reconnect
                    // is queued rather than dropped (effective delivery is min(pub, sub)).
                    // The non-idempotent step/gate buttons below use QoS 0.
                    qos = 1,
                    payload_on = "{\"action\":\"mute\",\"value\":\"on\"}",
                    payload_off = "{\"action\":\"mute\",\"value\":\"off\"}",
                    state_topic = opts.EffectiveTopicMute,
                    state_on = "on",
                    state_off = "off",
                    icon = "mdi:volume-mute",
                    availability_topic = opts.TopicLastWill,
                    payload_available = "online",
                    payload_not_available = "offline",
                    device,
                }, HaJson)));

            // Volume up / down buttons: ±10% (btmqttd clamps to 0..100). Only the sign
            // of the step value matters — the step size is owned device-side.
            entities.Add(new HaEntity(
                "volume_up.json",
                Topic("button", "volume_up"),
                JsonSerializer.Serialize(new
                {
                    name = "Volume up",
                    unique_id = $"{node}_volume_up",
                    default_entity_id = EntId("button", "volume_up"),
                    command_topic = controlTopic,
                    // QoS 0 (the default): a relative step is NON-idempotent, and QoS 1
                    // may legitimately REDELIVER a publish (DUP on a lost PUBACK), applying
                    // the step twice (e.g. +20 instead of +10). A press lost during a brief
                    // reconnect is self-correcting — the user just presses again — so
                    // avoiding duplication wins here, unlike the absolute volume/mute
                    // commands above (idempotent, QoS 1).
                    qos = 0,
                    payload_press = "{\"action\":\"volume_step\",\"value\":10}",
                    icon = "mdi:volume-plus",
                    availability_topic = opts.TopicLastWill,
                    payload_available = "online",
                    payload_not_available = "offline",
                    device,
                }, HaJson)));

            entities.Add(new HaEntity(
                "volume_down.json",
                Topic("button", "volume_down"),
                JsonSerializer.Serialize(new
                {
                    name = "Volume down",
                    unique_id = $"{node}_volume_down",
                    default_entity_id = EntId("button", "volume_down"),
                    command_topic = controlTopic,
                    // QoS 0 (the default): a relative step is NON-idempotent, and QoS 1
                    // may legitimately REDELIVER a publish (DUP on a lost PUBACK), applying
                    // the step twice (e.g. -20 instead of -10). A press lost during a brief
                    // reconnect is self-correcting — the user just presses again — so
                    // avoiding duplication wins here, unlike the absolute volume/mute
                    // commands above (idempotent, QoS 1).
                    qos = 0,
                    payload_press = "{\"action\":\"volume_step\",\"value\":-10}",
                    icon = "mdi:volume-minus",
                    availability_topic = opts.TopicLastWill,
                    payload_available = "online",
                    payload_not_available = "offline",
                    device,
                }, HaJson)));

            // Lock buttons (#41): each press performs the full momentary press/release
            // pulse on a WHO=8 actuator via the :30006 command port — Main = WHERE 20
            // (*8*19*20## / *8*20*20##), Secondary = WHERE 21 (*8*19*21## / *8*20*21##).
            // btmqttd maps the action name to the WHERE; the two entities are identical in
            // shape, so build them from one template that varies only object id / name /
            // icon / action.
            void AddLock(string objectId, string friendlyName, string action, string icon) =>
                entities.Add(new HaEntity(
                    $"{objectId}.json",
                    Topic("button", objectId),
                    JsonSerializer.Serialize(new
                    {
                        name = friendlyName,
                        unique_id = $"{node}_{objectId}",
                        default_entity_id = EntId("button", objectId),
                        command_topic = controlTopic,
                        // QoS 0 (the default): a lock pulse is a NON-idempotent side effect,
                        // and QoS 1 may legitimately REDELIVER a publish (DUP on a lost
                        // PUBACK), pulsing the actuator twice from one press. A press lost
                        // during a brief reconnect is self-correcting — the user just presses
                        // again — so avoiding an unintended double actuation wins here, unlike
                        // the absolute volume/mute commands above (idempotent, QoS 1).
                        qos = 0,
                        payload_press = $"{{\"action\":\"{action}\"}}",
                        icon,
                        availability_topic = opts.TopicLastWill,
                        payload_available = "online",
                        payload_not_available = "offline",
                        device,
                    }, HaJson)));

            AddLock("main_lock", "Main Lock", "main_lock", "mdi:lock");
            // Secondary Lock is OPT-IN (#not everyone wires a second gate): add it only when the
            // installer enabled it, else TOMBSTONE the config (empty retained) so a previous
            // build's entity is cleared from HA rather than lingering.
            if (opts.HasSecondaryLock)
                AddLock("secondary_lock", "Secondary Lock", "secondary_lock", "mdi:lock-outline");
            else
                entities.Add(new HaEntity("secondary_lock.json", Topic("button", "secondary_lock"), ""));

            // On-demand viewing (#104): a "View Camera" button that pokes btmqttd's SIP UA to bring
            // the idle panel A/V session up (same {"action":...}-to-TopicRx pattern as the locks), so
            // the go2rtc/HA camera has live video on demand — not only while ringing. Opt-in (needs
            // the media path AND on-demand enabled); otherwise TOMBSTONE the config (empty retained)
            // so a previous build's button is cleared from HA rather than lingering as a dead control.
            if (opts.CameraEnabled && opts.CameraOnDemand)
                entities.Add(new HaEntity(
                    "view_camera.json",
                    Topic("button", "view_camera"),
                    JsonSerializer.Serialize(new
                    {
                        name = "View Camera",
                        unique_id = $"{node}_view_camera",
                        default_entity_id = EntId("button", "view_camera"),
                        command_topic = controlTopic,
                        // QoS 0: the poke is idempotent (the UA re-checks and renews its viewing window
                        // on each press), so a redelivered DUP is harmless and a press lost during a
                        // reconnect is self-correcting — the user just presses again.
                        qos = 0,
                        payload_press = "{\"action\":\"view_camera\"}",
                        icon = "mdi:cctv",
                        availability_topic = opts.TopicLastWill,
                        payload_available = "online",
                        payload_not_available = "offline",
                        device,
                    }, HaJson)));
            else
                entities.Add(new HaEntity("view_camera.json", Topic("button", "view_camera"), ""));

            // On-demand viewing (#104): a companion "Stop Camera" button that ends the on-demand view
            // immediately instead of waiting for the viewing window to elapse — btmqttd sends the dialog's BYE, the
            // panel drops its A/V session and the go2rtc/HA stream stops. Same opt-in/TOMBSTONE posture
            // as "View Camera". (A live doorbell ring is a separate panel session and is unaffected.)
            if (opts.CameraEnabled && opts.CameraOnDemand)
                entities.Add(new HaEntity(
                    "stop_camera.json",
                    Topic("button", "stop_camera"),
                    JsonSerializer.Serialize(new
                    {
                        name = "Stop Camera",
                        unique_id = $"{node}_stop_camera",
                        default_entity_id = EntId("button", "stop_camera"),
                        command_topic = controlTopic,
                        // QoS 0: a dropped Stop is self-correcting (the viewing window still expires), and a
                        // redelivered DUP is harmless (ending an already-ended view is a no-op).
                        qos = 0,
                        payload_press = "{\"action\":\"stop_camera\"}",
                        icon = "mdi:cctv-off",
                        availability_topic = opts.TopicLastWill,
                        payload_available = "online",
                        payload_not_available = "offline",
                        device,
                    }, HaJson)));
            else
                entities.Add(new HaEntity("stop_camera.json", Topic("button", "stop_camera"), ""));

            // Stair-light SWITCH (opt-in). The actuator is a stateless TOGGLE with no readable
            // state (firmware-confirmed), so btmqttd tracks the on/off and publishes it retained
            // to EffectiveTopicLight; HA reads that as the switch state. The command is an
            // ABSOLUTE on/off action on TopicRx — btmqttd toggles the actuator only when the
            // tracked state differs, so a QoS-1 redelivery is harmless (idempotent set), unlike
            // the non-idempotent lock pulses above. When the feature is OFF, TOMBSTONE the
            // config (empty retained) so turning it off in a later build drops the stale entity.
            if (opts.LightEnabled)
            {
                // Availability that ALSO gates on "a WHERE is known": both the device (LWT) and
                // the light subsystem (EffectiveTopicLightAvail) must report online. The switch /
                // press button + resync use this so they show UNAVAILABLE in learn mode; the Learn
                // button uses the plain device availability (it is how the user LEAVES learn mode).
                var lightAvail = new[]
                {
                    new { topic = opts.TopicLastWill, payload_available = "online", payload_not_available = "offline" },
                    new { topic = opts.EffectiveTopicLightAvail, payload_available = "online", payload_not_available = "offline" },
                };

                if (opts.LightMomentary)
                {
                    // MOMENTARY (staircase-timer install): a single PRESS button that only turns the
                    // light ON — the installation's own timer switches it off, so there is NO tracked
                    // state, no state_topic, and no Resync. QoS 0 (fire-and-forget): a momentary press
                    // is NOT idempotent (each re-triggers the timer/pulse), so we must NOT let a QoS-1
                    // redelivery double-pulse it. Same WHERE-gated availability as the switch, so it's
                    // unavailable in learn mode. Tombstone the bistable switch + resync a prior build
                    // may have published.
                    entities.Add(new HaEntity(
                        "light_press.json",
                        Topic("button", "light_press"),
                        JsonSerializer.Serialize(new
                        {
                            name = "Light",
                            unique_id = $"{node}_light_press",
                            default_entity_id = EntId("button", "light_press"),
                            command_topic = controlTopic,
                            qos = 0,
                            payload_press = "{\"action\":\"light_press\"}",
                            icon = "mdi:lightbulb",
                            availability = lightAvail,
                            availability_mode = "all",
                            device,
                        }, HaJson)));
                    entities.Add(new HaEntity("light.json", Topic("switch", "light"), ""));
                    entities.Add(new HaEntity("light_resync.json", Topic("button", "light_resync"), ""));
                }
                else
                {
                    // BISTABLE (default): the actuator is a stateless TOGGLE with no readable state
                    // (firmware-confirmed), so btmqttd tracks the on/off and publishes it retained to
                    // EffectiveTopicLight; HA reads that as the switch state. The command is an ABSOLUTE
                    // on/off action on TopicRx — btmqttd toggles only when the tracked state differs, so
                    // a QoS-1 redelivery is harmless (idempotent set), unlike the momentary press above.
                    entities.Add(new HaEntity(
                        "light.json",
                        Topic("switch", "light"),
                        JsonSerializer.Serialize(new
                        {
                            name = "Light",
                            unique_id = $"{node}_light",
                            default_entity_id = EntId("switch", "light"),
                            command_topic = controlTopic,
                            qos = 1,
                            payload_on = "{\"action\":\"light\",\"value\":\"on\"}",
                            payload_off = "{\"action\":\"light\",\"value\":\"off\"}",
                            state_topic = opts.EffectiveTopicLight,
                            state_on = "on",
                            state_off = "off",
                            icon = "mdi:lightbulb",
                            availability = lightAvail,
                            availability_mode = "all",
                            device,
                        }, HaJson)));

                    // "Resync light state" — a CONFIG-section button that corrects the TRACKED state
                    // (unknown→on→off→on) WITHOUT actuating the relay, so the user realigns HA to the
                    // wall after a cold boot / a press missed while the daemon was down. Same WHERE-gated
                    // availability as the switch. Bistable-only (momentary has no tracked state).
                    entities.Add(new HaEntity(
                        "light_resync.json",
                        Topic("button", "light_resync"),
                        JsonSerializer.Serialize(new
                        {
                            name = "Resync light state",
                            unique_id = $"{node}_light_resync",
                            default_entity_id = EntId("button", "light_resync"),
                            command_topic = controlTopic,
                            qos = 0,
                            payload_press = "{\"action\":\"light_resync\"}",
                            icon = "mdi:sync",
                            entity_category = "config",
                            availability = lightAvail,
                            availability_mode = "all",
                            device,
                        }, HaJson)));

                    // A prior MOMENTARY build may have published the press button — tombstone it.
                    entities.Add(new HaEntity("light_press.json", Topic("button", "light_press"), ""));
                }

                // "Learn light" — a CONFIG-section button that opens the capture window; the user
                // then presses the physical stair-light button once to teach the WHERE. Available
                // whenever the device is online (it is the way OUT of learn mode), so it uses the
                // plain device availability, not the WHERE-gated one. Emitted ONLY in LEARN MODE
                // (blank build WHERE): a CONFIGURED build has a fixed, authoritative WHERE that
                // btmqttd's `learn()` guard refuses to override, so the button would be a guaranteed
                // no-op — tombstone it instead (Codex).
                if (opts.LightLearnMode)
                    entities.Add(new HaEntity(
                        "light_learn.json",
                        Topic("button", "light_learn"),
                        JsonSerializer.Serialize(new
                        {
                            name = "Learn light",
                            unique_id = $"{node}_light_learn",
                            default_entity_id = EntId("button", "light_learn"),
                            command_topic = controlTopic,
                            qos = 0,
                            payload_press = "{\"action\":\"light_learn\"}",
                            icon = "mdi:school",
                            entity_category = "config",
                            availability_topic = opts.TopicLastWill,
                            payload_available = "online",
                            payload_not_available = "offline",
                            device,
                        }, HaJson)));
                else
                    // Configured build → tombstone the Learn button (a previous learn-mode build may
                    // have published it) so it doesn't linger as an inert control.
                    entities.Add(new HaEntity("light_learn.json", Topic("button", "light_learn"), ""));
            }
            else
            {
                // Feature OFF → tombstone all four light configs so a prior build's entities clear.
                entities.Add(new HaEntity("light.json", Topic("switch", "light"), ""));
                entities.Add(new HaEntity("light_press.json", Topic("button", "light_press"), ""));
                entities.Add(new HaEntity("light_resync.json", Topic("button", "light_resync"), ""));
                entities.Add(new HaEntity("light_learn.json", Topic("button", "light_learn"), ""));
            }

            return entities;
        }

        /// <summary>
        /// The concrete topic HA can PUBLISH a command to, derived from
        /// <paramref name="topicRx"/> (the daemon's subscription filter). Returns the
        /// topic itself when it is concrete; for a <c>$share/&lt;group&gt;/&lt;filter&gt;</c>
        /// shared subscription, the underlying <c>&lt;filter&gt;</c> when THAT is concrete
        /// (a publish to it reaches the shared group); otherwise <c>null</c> — a
        /// wildcard filter has no single publish topic, so the HA control entities are
        /// omitted. Mirrors the <c>$share</c> normalisation in <see cref="Validate"/>.
        /// </summary>
        private static string? ConcretePublishTopic(string topicRx)
        {
            string t = topicRx;
            if (t.StartsWith("$share/", StringComparison.Ordinal))
            {
                string rest = t.Substring("$share/".Length);
                int slash = rest.IndexOf('/');
                if (slash < 0) return null;              // malformed: no filter
                t = rest.Substring(slash + 1);           // the underlying filter
            }
            return t.IndexOfAny(new[] { '+', '#' }) >= 0 ? null : t;
        }

        // ---- init-script patches (owner/mode preserved, idempotent) -------------

        /// <summary>
        /// Inserts the <c>/bin/touch /tmp/flexisip_restarted</c> marker right after
        /// the <c>start-stop-daemon --start</c> line in flexisipsh's <c>start)</c>
        /// case, backing the file up to <c>flexisipsh_bak</c> first. Preserves the
        /// file's existing owner+mode (on-device it is <c>bticino:bticino</c> 0775 —
        /// NOT root). Idempotent: does nothing if the marker is already present.
        /// </summary>
        private static void PatchFlexisip(ExtFileSystem fs)
        {
            const string path = "/etc/init.d/flexisipsh";
            if (!fs.FileExists(path))
                throw new InvalidOperationException(CoreStrings.Format("Mqtt_FileMissing", path));

            string content = ReadAllText(fs, path);
            const string marker = "/bin/touch /tmp/flexisip_restarted";

            // Back up first (if no backup exists yet), BEFORE the idempotency
            // return — the backup is the revert target, and ValidateMqtt requires
            // it to exist. This also covers an image whose flexisipsh already
            // carries the marker (e.g. a prior fquinto mod): we still record a
            // backup of the current state, then skip the insert below.
            if (!fs.FileExists(path + "_bak"))
            {
                uint bmode = fs.GetMode(path) & 0xFFF;
                var bowner = fs.GetOwner(path);
                WriteTextFile(fs, path + "_bak", content);
                fs.SetMode(path + "_bak", bmode);
                if (bowner != null) fs.SetOwner(path + "_bak", bowner.Item1, bowner.Item2);
            }

            // Idempotency AND the insert point are both scoped to the `start)`
            // case — the marker only "counts" where we put it. A stray occurrence
            // elsewhere (a comment, another case) must neither suppress the patch
            // nor be mistaken for it, and searching the whole file could match a
            // start-stop-daemon line in another case and patch the wrong place.
            string[] lines = content.Replace("\r\n", "\n").Split('\n');
            var (blockFound, anchor, markerCount) = ScanFlexisipStartCase(lines, marker);
            if (!blockFound)
                throw new InvalidOperationException(
                    CoreStrings.Format("Mqtt_AnchorMissing", path, "start) case"));
            if (markerCount > 0) return;   // already patched inside the start) case
            if (anchor < 0)
                throw new InvalidOperationException(CoreStrings.Format("Mqtt_AnchorMissing", path,
                    "start-stop-daemon --start (in the start) case)"));

            var patched = new List<string>(lines);
            patched.Insert(anchor + 1, "\t" + marker);
            RewritePreservingMeta(fs, path, string.Join("\n", patched));
        }

        /// <summary>
        /// Parses flexisipsh's <c>start)</c> case. Returns whether that case
        /// exists, the index of its <c>start-stop-daemon --start</c> line (the
        /// insert anchor, or -1), and how many lines INSIDE the case contain
        /// <paramref name="marker"/>. Bounding to <c>start)</c> (via
        /// <see cref="IsCaseTerminator"/>) mirrors where the marker is inserted,
        /// so a stray occurrence in a comment or another case is ignored by both
        /// the idempotency check and the read-back validation.
        /// </summary>
        private static (bool blockFound, int anchor, int markerCount) ScanFlexisipStartCase(
            string[] lines, string marker)
        {
            int startCase = Array.FindIndex(lines, l =>
            {
                string t = l.Trim();
                return t == "start)" || t.StartsWith("start)", StringComparison.Ordinal);
            });
            if (startCase < 0) return (false, -1, 0);

            int anchor = -1, count = 0;
            for (int i = startCase + 1; i < lines.Length; i++)
            {
                if (IsCaseTerminator(lines[i])) break;   // end of the start) block
                if (anchor < 0 && lines[i].Contains("start-stop-daemon --start")) anchor = i;
                if (lines[i].Contains(marker)) count++;
            }
            return (true, anchor, count);
        }

        /// <summary>
        /// True when <paramref name="line"/> ends a shell <c>case</c> branch
        /// (<c>;;</c>): standalone, following a command on the same line
        /// (<c>foo ;;</c> or <c>foo;;</c>), or with a trailing comment
        /// (<c>;; # done</c>). Used to bound the <c>start)</c> block scan so the
        /// flexisip marker is never inserted into a later case. Not a full shell
        /// parser — a heuristic that strips a trailing <c>#</c> comment (one at
        /// line start or preceded by whitespace) before testing for <c>;;</c>.
        /// </summary>
        private static bool IsCaseTerminator(string line)
        {
            string t = line.Trim();
            for (int i = 0; i < t.Length; i++)
            {
                if (t[i] == '#' && (i == 0 || char.IsWhiteSpace(t[i - 1])))
                {
                    t = t.Substring(0, i).TrimEnd();
                    break;
                }
            }
            return t.EndsWith(";;", StringComparison.Ordinal);
        }

        /// <summary>
        /// Adds a <c>bt_hosts.sh add &lt;host&gt; &lt;ip&gt;</c> mapping so the device
        /// can resolve a broker given by name. Delegates to the shared
        /// <see cref="BtDaemonAppsHosts"/> patcher — the same anchor, whole-line
        /// idempotency and owner/mode preservation the OTA-update block uses, so the
        /// two paths cannot drift.
        /// </summary>
        private static void PatchHosts(ExtFileSystem fs, string host, string ip) =>
            BtDaemonAppsHosts.AddMappings(fs, new[] { (host, ip) });

        /// <summary>Resolves the broker hostname to an IPv4 for the hosts edit.</summary>
        private static string ResolveHostIp(MqttOptions opts)
        {
            // An explicit override wins (its format was already checked in Validate).
            if (!string.IsNullOrWhiteSpace(opts.HostIpForHosts))
                return opts.HostIpForHosts!;
            try
            {
                // This runs inside the open-fs write session — which, on the .fwz
                // build path, holds the input file lock — so a slow/unreachable
                // resolver must not stall it indefinitely. Bound the lookup to 5 s
                // via a CancellationToken. (Core work runs off the UI thread, so
                // blocking on the async call here is safe.)
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                IPAddress[] addrs = Dns.GetHostAddressesAsync(opts.MqttHost, cts.Token)
                    .GetAwaiter().GetResult();
                var v4 = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork);
                if (v4 != null) return v4.ToString();
            }
            catch { /* resolution failed or timed out — fall through to a clear error */ }
            throw new InvalidOperationException(
                CoreStrings.Format("Mqtt_HostUnresolved", opts.MqttHost));
        }

        // ---- fs helpers (mirror Ext4Probe's; kept local so the SSH path stays
        //      untouched — the two classes never share mutable state) -------------

        private static void RewritePreservingMeta(ExtFileSystem fs, string path, string text)
        {
            uint mode = fs.GetMode(path) & 0xFFF;
            var owner = fs.GetOwner(path);
            WriteTextFile(fs, path, text);
            fs.SetMode(path, mode);
            if (owner != null) fs.SetOwner(path, owner.Item1, owner.Item2);
        }

        private static void CreateSymLinkTolerant(ExtFileSystem fs, string linkPath, string linkTarget)
        {
            string? existing = null;
            try { existing = fs.ReadSymLink(linkPath); } catch { /* absent or not a symlink */ }
            if (existing != null)
            {
                if (existing != linkTarget)
                    throw new InvalidOperationException(
                        CoreStrings.Format("Ext4_SymlinkWrongTarget", linkPath, existing, linkTarget));
            }
            else if (fs.FileExists(linkPath) || fs.DirectoryExists(linkPath))
            {
                throw new InvalidOperationException(
                    CoreStrings.Format("Ext4_SymlinkNotSymlink", linkPath));
            }
            else
            {
                fs.CreateSymLink(linkTarget, linkPath);
            }
        }

        /// <summary>Loads an embedded payload script as UTF-8 text, normalized to LF.</summary>
        private static string LoadScript(string resourceName)
        {
            var asm = typeof(MqttInstaller).Assembly;
            using Stream? stream = asm.GetManifestResourceStream(resourceName);
            if (stream is null)
                throw new InvalidOperationException(
                    CoreStrings.Format("Mqtt_ResourceMissing", resourceName));
            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);
            // A stray CR would leave "#!/bin/sh\r" and fail on the rootfs; normalize
            // CRLF and lone CR to LF regardless of how the resource was stored.
            return Encoding.UTF8.GetString(buffer.ToArray())
                .Replace("\r\n", "\n").Replace('\r', '\n');
        }

        private static void WriteConfigFile(ExtFileSystem fs, string path, string text, int mode)
        {
            WriteTextFile(fs, path, text);
            fs.SetMode(path, ToMode(mode));
            fs.SetOwner(path, 0, 0);
        }

        private static void WriteTextFile(ExtFileSystem fs, string path, string text)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            using var f = fs.OpenFile(path, FileMode.Create, FileAccess.Write);
            // A ZERO-length write throws IndexOutOfRangeException inside SharpExt4's
            // ExtFileStream.Write (empty-buffer edge). FileMode.Create has already created/
            // truncated the file to 0 bytes, so writing nothing leaves the correct empty file.
            // Tombstone discovery entities carry an empty payload, so this path is real.
            if (bytes.Length > 0)
                f.Write(bytes, 0, bytes.Length);
        }

        private static void WriteBytesFile(ExtFileSystem fs, string path, byte[] bytes)
        {
            using var f = fs.OpenFile(path, FileMode.Create, FileAccess.Write);
            // See WriteTextFile: a zero-length Write throws in SharpExt4; FileMode.Create already
            // leaves a correct 0-byte file, so skip the empty write.
            if (bytes.Length > 0)
                f.Write(bytes, 0, bytes.Length);
        }

        private static void EnsureDir(ExtFileSystem fs, string path)
        {
            if (fs.DirectoryExists(path)) return;
            fs.CreateDirectory(path);
            fs.SetMode(path, ToMode(755));
            fs.SetOwner(path, 0, 0);
        }

        private static string ReadAllText(ExtFileSystem fs, string path)
        {
            using var file = fs.OpenFile(path, FileMode.Open, FileAccess.Read);
            long length = file.Length;
            if (length > MaxEditFileBytes)
                throw new NotSupportedException(
                    CoreStrings.Format("Mqtt_FileTooLarge", path, length, MaxEditFileBytes));
            int len = (int)length;
            var buf = new byte[len];
            int total = 0;
            while (total < len)
            {
                int n = file.Read(buf, total, len - total);
                if (n <= 0) break;
                total += n;
            }
            // A short read must fail loudly, not silently return a truncated
            // string — patching/validation on partial content could rewrite an
            // init script incorrectly. (Mirrors Ext4Probe's read helper.)
            if (total != len)
                throw new IOException(CoreStrings.Format("Ext4_IncompleteRead", len, total));
            return Encoding.UTF8.GetString(buf, 0, total);
        }

        private static void CheckFile(ExtFileSystem fs, List<Ext4Check> checks, string path, int mode)
        {
            bool exists = fs.FileExists(path);
            checks.Add(new($"{path} exists", exists, ""));
            if (!exists) return;
            uint got = fs.GetMode(path) & 0xFFF;
            checks.Add(new($"{path} mode 0{mode}",
                got == ToMode(mode), $"actual 0{Convert.ToString((long)got, 8)}"));
            var owner = fs.GetOwner(path);
            checks.Add(new($"{path} owner 0:0",
                owner != null && owner.Item1 == 0 && owner.Item2 == 0,
                owner != null ? $"{owner.Item1}:{owner.Item2}" : "null"));
        }

        /// <summary>
        /// Read-back integrity check for an installed ARM binary: its on-image
        /// bytes must match the embedded resource's recorded length and SHA-256.
        /// Catches a partial/truncated/corrupted write that presence+mode+owner
        /// would miss. Skips silently if the file is absent (existence is already
        /// reported by <see cref="CheckFile"/>).
        /// </summary>
        private static void CheckBinaryBytes(ExtFileSystem fs, List<Ext4Check> checks, ArmBinary bin)
        {
            if (!fs.FileExists(bin.InstallPath)) return;
            using var file = fs.OpenFile(bin.InstallPath, FileMode.Open, FileAccess.Read);
            long length = file.Length;
            bool lenOk = length == bin.Length;
            checks.Add(new($"{bin.InstallPath} length {bin.Length} bytes",
                lenOk, $"actual {length}"));
            // A wrong length is already a failure; don't hash a mismatched buffer.
            if (!lenOk) return;
            var buf = new byte[bin.Length];
            int total = 0;
            while (total < buf.Length)
            {
                int n = file.Read(buf, total, buf.Length - total);
                if (n <= 0) break;
                total += n;
            }
            string sha = total == buf.Length
                ? Convert.ToHexStringLower(SHA256.HashData(buf)) : "";
            checks.Add(new($"{bin.InstallPath} SHA-256 matches embedded {bin.Name}",
                string.Equals(sha, bin.Sha256Hex, StringComparison.Ordinal), sha));
        }

        /// <summary>A hostname or an IPv4 literal — but NOT an IPv6 literal. Used for the camera
        /// fan-out target, which btmqttd delivers via the IPv4-only OWN `*7*300#a#b#c#d#…` frame
        /// (its resolver takes the first IPv4 a lookup returns), so an IPv6 target would install but
        /// never arm. A literal that parses as an IP must be IPv4; any other value goes through the
        /// same hostname rules as <see cref="IsValidHost"/> (which rejects URLs and `host:port`).</summary>
        private static bool IsHostnameOrIpv4(string host)
        {
            if (IPAddress.TryParse(host, out var ip))
                return ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
            return IsValidHost(host);
        }

        private static bool IsValidHost(string host)
        {
            if (IPAddress.TryParse(host, out _)) return true;
            // Hostname: 1..253 chars, dot-separated labels of [A-Za-z0-9-], each
            // 1..63, not starting/ending with '-'. Uri.CheckHostName also accepts
            // it, but this is explicit and dependency-free.
            if (host.Length == 0 || host.Length > 253) return false;
            foreach (var label in host.Split('.'))
            {
                if (label.Length == 0 || label.Length > 63) return false;
                if (label[0] == '-' || label[^1] == '-') return false;
                foreach (char c in label)
                    if (!(char.IsAsciiLetterOrDigit(c) || c == '-')) return false;
            }
            return true;
        }

        /// <summary>Six hex octets separated by ':' or '-' (e.g. <c>aa:bb:cc:dd:ee:ff</c>).
        /// Kept in lockstep with btmqttd's <c>parse_mac</c>: exactly six two-digit hex
        /// groups, no more, no fewer — so a value this accepts is one the device also
        /// accepts (and vice versa). Case-insensitive.</summary>
        private static bool IsValidMac(string mac)
        {
            var parts = mac.Split(':', '-');
            if (parts.Length != 6) return false;
            foreach (var part in parts)
            {
                if (part.Length != 2) return false;
                foreach (char c in part)
                    if (!char.IsAsciiHexDigit(c)) return false;
            }
            return true;
        }

        private static uint ToMode(int octalDigits) => Convert.ToUInt32(octalDigits.ToString(), 8);
    }
}
