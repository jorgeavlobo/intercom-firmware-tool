using SharpExt4;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using IntercomFirmwareTool.Core.Localization;

namespace IntercomFirmwareTool.Core
{
    /// <summary>
    /// Options for installing the optional MQTT bridge into a firmware image.
    /// The bridge is <b>off by default</b>; the installer only runs when the user
    /// opts in. Mirrors the variables consumed by <c>TcpDump2Mqtt.conf</c> /
    /// <c>mqtt_common.sh</c>.
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
    /// <param name="UseTcpdumpCapture">
    /// Force the faithful tcpdump + filter.py capture back-end. When false (default) the bridge
    /// opens a MONITOR session directly on the local OpenWebNet gateway (no tcpdump, no resident
    /// python) and only falls back to tcpdump when that gateway is unreachable. See StartMqttSend.
    /// </param>
    /// <param name="EnableHaDiscovery">
    /// Publish retained Home Assistant MQTT discovery configs at bridge startup, so the
    /// connectivity/bus/keypad entities appear in HA automatically (no manual YAML). Additive and
    /// read-only (no command entity); off by default at the Core layer. See ha_discovery.sh.
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
        bool UseTcpdumpCapture = false,
        bool EnableHaDiscovery = false)
    {
        // A record's synthesized ToString() prints EVERY property — which would
        // leak MqttPass and the TLS private key (ClientKeyPem) into any log line
        // or exception that interpolates the options. Redact: expose only
        // non-sensitive fields (booleans for the presence of secrets).
        public override string ToString() =>
            $"MqttOptions {{ MqttHost = {MqttHost}, MqttPort = {MqttPort}, " +
            $"HasAuth = {HasAuth}, HasTls = {HasTls}, HasMutualTls = {HasMutualTls}, " +
            $"AllowRemoteShell = {AllowRemoteShell}, " +
            $"Capture = {(UseTcpdumpCapture ? "tcpdump" : "socket")}, " +
            $"HaDiscovery = {EnableHaDiscovery} }}";

        /// <summary>OpenWebNet gateway host for the socket monitor back-end (loopback alias).</summary>
        public string OwnHost { get; init; } = "127.0.0.1";
        /// <summary>OpenWebNet gateway plaintext OwnPort for the socket monitor session.</summary>
        public int OwnPortMon { get; init; } = 20000;

        /// <summary>Home Assistant MQTT discovery topic prefix (HA default is "homeassistant").</summary>
        public string HaDiscoveryPrefix { get; init; } = "homeassistant";
        /// <summary>
        /// Stable id for the HA device + entity unique_ids / discovery object ids. Distinct per
        /// unit lets several bridges coexist on one broker without colliding.
        /// </summary>
        public string HaNodeId { get; init; } = "bticino_intercom";

        public string TopicRx { get; init; } = "Bticino/rx";
        public string TopicDump { get; init; } = "Bticino/tx";
        public string TopicStartDate { get; init; } = "Bticino/start_date";
        public string TopicLastWill { get; init; } = "Bticino/LastWillT";
        public string TopicKey { get; init; } = "Bticino/key";
        public string TopicCmdResult { get; init; } = "Bticino/command_result_topic";
        public string TopicFileContent { get; init; } = "Bticino/file_content_topic";

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
    /// <see cref="PayloadBinaries"/>), a generated <c>TcpDump2Mqtt.conf</c>, the
    /// boot symlinks, and the two idempotent init-script patches. The input image
    /// is never touched; callers operate on a modified copy.
    /// </summary>
    public static class MqttInstaller
    {
        private const string EtcDir = "/etc/tcpdump2mqtt";
        private const string ResourcePrefix = "IntercomFirmwareTool.Core.Payload.mqtt.";
        private const long MaxEditFileBytes = 4L * 1024 * 1024; // init scripts are tiny

        /// <summary>A payload script: embedded resource, install path, and octal mode.</summary>
        private sealed record ScriptFile(string Resource, string Path, int Mode);

        // The 9 embedded scripts. TcpDump2Mqtt.conf is generated (not a resource);
        // jq/evtest come from PayloadBinaries. Executables 0775; mqtt_common.sh is
        // only sourced, so 0644. ha_discovery.sh runs on every startup and
        // self-selects publish (HA_DISCOVERY=1) vs clear (0).
        private static readonly ScriptFile[] Scripts =
        {
            new(ResourcePrefix + "TcpDump2Mqtt",       EtcDir + "/TcpDump2Mqtt",       775),
            new(ResourcePrefix + "TcpDump2Mqtt.sh",    EtcDir + "/TcpDump2Mqtt.sh",    775),
            new(ResourcePrefix + "StartMqttSend",      EtcDir + "/StartMqttSend",      775),
            new(ResourcePrefix + "StartMqttReceive",   EtcDir + "/StartMqttReceive",   775),
            new(ResourcePrefix + "keypress.sh",        EtcDir + "/keypress.sh",        775),
            new(ResourcePrefix + "filter.py",          EtcDir + "/filter.py",          775),
            new(ResourcePrefix + "mqtt_common.sh",     EtcDir + "/mqtt_common.sh",     644),
            new(ResourcePrefix + "ha_discovery.sh",    EtcDir + "/ha_discovery.sh",    775),
            new(ResourcePrefix + "bt_service_watchdog", "/etc/init.d/bt_service_watchdog", 775),
        };

        // Home Assistant discovery configs: one JSON file per entity plus a manifest
        // of "config-topic<TAB>filename". Written ALWAYS (regardless of the enable
        // flag) so ha_discovery.sh can either publish them retained (HA_DISCOVERY=1)
        // or clear the retained configs (HA_DISCOVERY=0).
        private const string HaDir = EtcDir + "/ha";

        // Boot symlinks in rc5.d. The 'z' after S99 sorts these AFTER the factory
        // S99<Capital…> services (ASCII 'z' > any capital), so the bridge starts
        // once the network, dbus/avahi and the BTicino apps are already up. The
        // watchdog (…zBtServiceWatchdog) still sorts before the bridge
        // (…zTcpDump2Mqtt) — B < T — so it comes up first.
        private static readonly (string Link, string Target)[] Symlinks =
        {
            ("/etc/rc5.d/S99zBtServiceWatchdog", "../init.d/bt_service_watchdog"),
            ("/etc/rc5.d/S99zTcpDump2Mqtt",      "../tcpdump2mqtt/TcpDump2Mqtt.sh"),
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
            WriteConfigFile(fs, EtcDir + "/TcpDump2Mqtt.conf", GenerateConf(opts), 600);

            // --- Home Assistant discovery configs -------------------------------
            // One retained-config JSON per entity + a manifest of
            // "config-topic<TAB>filename". Written ALWAYS (not only when enabled):
            // ha_discovery.sh publishes them retained when HA_DISCOVERY=1, and
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
                    WriteConfigFile(fs, HaDir + "/" + e.FileName, e.Json, 644);
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

            // The OpenWebNet monitor endpoint feeds the socket back-end's config.
            // It is not exposed in the UI (the App always uses the defaults), but
            // it is a public option, so a library caller could set a bad value —
            // a 0/negative/oversized port or an empty host would generate a config
            // that silently fails socket mode and falls back to tcpdump. Fail fast
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
            // only when EnableHaDiscovery): the manifest is generated and
            // ha_discovery.sh runs on every boot even when disabled (to CLEAR the
            // retained configs), so a bad prefix/node would otherwise pass the build
            // and fail every boot on-device.
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

            // Topics must be non-empty and single-line (they are sourced into the
            // .conf and used as MQTT topic filters).
            foreach (var t in new[] { opts.TopicRx, opts.TopicDump, opts.TopicStartDate,
                                      opts.TopicLastWill, opts.TopicKey, opts.TopicCmdResult,
                                      opts.TopicFileContent })
                if (string.IsNullOrWhiteSpace(t) || t.IndexOfAny(new[] { '\r', '\n' }) >= 0)
                    throw new ArgumentException(CoreStrings.Get("Mqtt_InvalidTopic"), nameof(opts));

            // The PUBLISH topics (everything except TopicRx, which is only ever
            // subscribed) must not contain the MQTT wildcards '+'/'#': those are
            // subscription filters and are rejected by mosquitto_pub -t /
            // --will-topic, so a wildcard here would build an image that cannot
            // publish at runtime. TopicRx may keep them (a valid subscription).
            foreach (var t in new[] { opts.TopicDump, opts.TopicStartDate, opts.TopicLastWill,
                                      opts.TopicKey, opts.TopicCmdResult, opts.TopicFileContent })
                if (t.IndexOfAny(new[] { '+', '#' }) >= 0)
                    throw new ArgumentException(CoreStrings.Get("Mqtt_PublishTopicWildcard"), nameof(opts));

            // TopicRx is the only SUBSCRIBE filter (mosquitto_sub -t). It MAY use
            // the wildcards '+'/'#', but they must follow MQTT subscription-filter
            // rules: '+' occupies a whole level and '#' is the final whole level.
            // An invalid filter (e.g. "Bticino/rx#" or "Bticino/+rx") would build
            // but be rejected by the broker at subscribe time.
            if (opts.TopicRx.IndexOfAny(new[] { '+', '#' }) >= 0 &&
                !IsValidSubscriptionFilter(opts.TopicRx))
                throw new ArgumentException(
                    CoreStrings.Get("Mqtt_InvalidSubscriptionFilter"), nameof(opts));

            // TopicRx must not match any PUBLISH topic (equal, or a wildcard that
            // matches one). If it did, the bridge would subscribe to its own
            // output: StartMqttSend publishes bus frames to TopicDump, the
            // TopicRx subscriber (StartMqttReceive) would then receive them and
            // replay them to the gateway — a feedback loop that floods the bus.
            foreach (var pub in new[] { opts.TopicDump, opts.TopicStartDate, opts.TopicLastWill,
                                        opts.TopicKey, opts.TopicCmdResult, opts.TopicFileContent })
                if (TopicFilterMatches(opts.TopicRx, pub))
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
                CheckFile(fs, checks, EtcDir + "/TcpDump2Mqtt.conf", 600);
                string conf = fs.FileExists(EtcDir + "/TcpDump2Mqtt.conf")
                    ? ReadAllText(fs, EtcDir + "/TcpDump2Mqtt.conf") : "";
                checks.Add(new(".conf matches the generated config for these options",
                    conf == GenerateConf(opts), ""));

                // HA discovery configs: always present and byte-exact (they are
                // written regardless of the enable flag, so ha_discovery.sh can
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
                // "confirmed present on a factory C100X"). jq/evtest are installed
                // above, so not here. Two categories:
                //  - Tools our scripts INVOKE: validate the EXACT path the script
                //    uses — not just "a tcpdump/pgrep somewhere" — so an image with
                //    the tool at a different path fails here rather than at boot.
                //    Candidates are used ONLY where the script itself tolerates more
                //    than one path: python (StartMqttSend tries /usr/bin/python then
                //    /usr/bin/python3) and nc (StartMqttReceive calls bare `nc` via
                //    PATH). tcpdump/pgrep/mosquitto_* are hard-coded absolute paths.
                //  - Base tools our scripts do NOT invoke (route, ping): a plain
                //    presence check against common locations. These confirm the
                //    target is the expected firmware (per #10), not that a script
                //    will find them, so multiple candidate paths are correct here.
                var deps = new (string Name, string[] Paths)[]
                {
                    ("mosquitto_pub", new[] { "/usr/bin/mosquitto_pub" }),        // mqtt_common.sh
                    ("mosquitto_sub", new[] { "/usr/bin/mosquitto_sub" }),        // mqtt_common.sh
                    ("mosquitto (broker init)", new[] { "/etc/init.d/mosquitto" }),
                    ("tcpdump", new[] { "/usr/sbin/tcpdump" }),                   // StartMqttSend hard-codes this
                    ("python", new[] { "/usr/bin/python", "/usr/bin/python3" }),  // StartMqttSend tries both
                    ("pgrep", new[] { "/usr/bin/pgrep" }),                        // TcpDump2Mqtt/watchdog hard-code this
                    ("nc", new[] { "/usr/bin/nc", "/bin/nc" }),                   // StartMqttReceive command inject + StartMqttSend socket monitor (bare `nc` via PATH)
                    ("route", new[] { "/sbin/route", "/usr/sbin/route", "/bin/route" }), // #10 base tool (not invoked by us)
                    ("ping", new[] { "/bin/ping", "/usr/bin/ping" }),            // #10 base tool (not invoked by us)
                };
                foreach (var (name, paths) in deps)
                    // Present = resolves to a real file, FOLLOWING symlinks: on a
                    // stock image these tools are almost always symlinks (busybox
                    // applets like nc/route/ping, version links like python ->
                    // python2 -> python2.7, or pgrep -> pgrep.procps), and the ext
                    // reader's FileExists returns false for a symlink. A plain
                    // FileExists therefore false-fails a tool that IS present.
                    checks.Add(new($"runtime dep {name} present",
                        paths.Any(p => DependencyPresent(fs, p)),
                        string.Join(" | ", paths)));

                // awk is used ONLY by the socket capture back-end (its busybox framer).
                // Gate the check on that choice: in tcpdump mode awk is not invoked at
                // all, so requiring it would wrongly reject an otherwise-valid image
                // (every ValidateMqtt failure fails the whole build). When socket mode
                // IS selected we require it, so the build reflects the user's choice
                // rather than silently degrading to the runtime tcpdump fallback.
                if (!opts.UseTcpdumpCapture)
                {
                    var awkPaths = new[] { "/usr/bin/awk", "/bin/awk" };  // busybox applet
                    checks.Add(new("runtime dep awk present (socket capture)",
                        awkPaths.Any(p => DependencyPresent(fs, p)),
                        string.Join(" | ", awkPaths)));
                }
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
            sb.Append("# TcpDump2Mqtt - configuration (generated by IntercomFirmwareTool)\n");
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

            sb.Append("ALLOW_REMOTE_SHELL=").Append(opts.AllowRemoteShell ? '1' : '0').Append('\n');

            // Capture back-end: 'socket' (default; direct OpenWebNet monitor session, no
            // tcpdump/python) or 'tcpdump' (faithful Phase 1 pipeline). OWN_* is the gateway
            // endpoint for the socket back-end. See StartMqttSend for the fallback behaviour.
            sb.Append(Conf("CAPTURE_MODE", opts.UseTcpdumpCapture ? "tcpdump" : "socket"));
            sb.Append(Conf("OWN_HOST", opts.OwnHost));
            sb.Append("OWN_PORT_MON=").Append(opts.OwnPortMon).Append('\n');

            // Home Assistant auto-discovery: when 1, the orchestrator runs
            // ha_discovery.sh once at startup to publish the retained configs under
            // HaDir. The discovery prefix/node/topics are baked into those files.
            sb.Append("HA_DISCOVERY=").Append(opts.EnableHaDiscovery ? '1' : '0').Append('\n');
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

        // Relaxed encoder so template braces / '+' etc. aren't over-escaped; the
        // output is still valid JSON. WriteIndented for a readable on-device file.
        private static readonly JsonSerializerOptions HaJson = new()
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
            WriteIndented = true,
        };

        /// <summary>
        /// Builds the Home Assistant MQTT discovery configs for the bridge: a
        /// connectivity <c>binary_sensor</c> (online/offline via the last-will
        /// topic), a diagnostic <c>sensor</c> for the last OpenWebNet bus frame, and
        /// a <c>sensor</c> for the last key press (with code/value as attributes).
        /// All read-only and grouped under one HA device — no command entity, to
        /// keep the secure-by-default posture. Topics/prefix/node are baked in here,
        /// so the on-device publisher just sends each payload retained.
        /// </summary>
        private static IReadOnlyList<HaEntity> GenerateHaDiscovery(MqttOptions opts)
        {
            string prefix = opts.HaDiscoveryPrefix;
            string node = opts.HaNodeId;

            // Shared device block so every entity groups under one HA device.
            var device = new
            {
                identifiers = new[] { node },
                name = "BTicino intercom bridge",
                manufacturer = "BTicino",
                model = "OpenWebNet MQTT bridge",
            };

            string Topic(string component, string objectId) =>
                $"{prefix}/{component}/{node}/{objectId}/config";

            var entities = new List<HaEntity>();

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
                    device_class = "connectivity",
                    state_topic = opts.TopicLastWill,
                    payload_on = "online",
                    payload_off = "offline",
                    entity_category = "diagnostic",
                    device,
                }, HaJson)));

            // Last OpenWebNet bus frame (diagnostic).
            entities.Add(new HaEntity(
                "bus.json",
                Topic("sensor", "bus"),
                JsonSerializer.Serialize(new
                {
                    name = "OpenWebNet bus",
                    unique_id = $"{node}_bus",
                    state_topic = opts.TopicDump,
                    icon = "mdi:bus",
                    entity_category = "diagnostic",
                    availability_topic = opts.TopicLastWill,
                    payload_available = "online",
                    payload_not_available = "offline",
                    device,
                }, HaJson)));

            // Last key press: state = key name, code/value exposed as attributes.
            entities.Add(new HaEntity(
                "key.json",
                Topic("sensor", "key"),
                JsonSerializer.Serialize(new
                {
                    name = "Last key",
                    unique_id = $"{node}_key",
                    state_topic = opts.TopicKey,
                    value_template = "{{ value_json.key }}",
                    json_attributes_topic = opts.TopicKey,
                    icon = "mdi:gesture-tap-button",
                    availability_topic = opts.TopicLastWill,
                    payload_available = "online",
                    payload_not_available = "offline",
                    device,
                }, HaJson)));

            return entities;
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
            f.Write(bytes, 0, bytes.Length);
        }

        private static void WriteBytesFile(ExtFileSystem fs, string path, byte[] bytes)
        {
            using var f = fs.OpenFile(path, FileMode.Create, FileAccess.Write);
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

        private static uint ToMode(int octalDigits) => Convert.ToUInt32(octalDigits.ToString(), 8);
    }
}
