using SharpExt4;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
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
    public sealed record MqttOptions(
        string MqttHost,
        int MqttPort = 1883,
        string? MqttUser = null,
        string? MqttPass = null,
        string? CaCertPem = null,
        string? ClientCertPem = null,
        string? ClientKeyPem = null,
        string? HostIpForHosts = null,
        bool AllowRemoteShell = false)
    {
        // A record's synthesized ToString() prints EVERY property — which would
        // leak MqttPass and the TLS private key (ClientKeyPem) into any log line
        // or exception that interpolates the options. Redact: expose only
        // non-sensitive fields (booleans for the presence of secrets).
        public override string ToString() =>
            $"MqttOptions {{ MqttHost = {MqttHost}, MqttPort = {MqttPort}, " +
            $"HasAuth = {HasAuth}, HasTls = {HasTls}, HasMutualTls = {HasMutualTls}, " +
            $"AllowRemoteShell = {AllowRemoteShell} }}";

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

        // The 8 embedded scripts. TcpDump2Mqtt.conf is generated (not a resource);
        // jq/evtest come from PayloadBinaries. Executables 0775; mqtt_common.sh is
        // only sourced, so 0644.
        private static readonly ScriptFile[] Scripts =
        {
            new(ResourcePrefix + "TcpDump2Mqtt",       EtcDir + "/TcpDump2Mqtt",       775),
            new(ResourcePrefix + "TcpDump2Mqtt.sh",    EtcDir + "/TcpDump2Mqtt.sh",    775),
            new(ResourcePrefix + "StartMqttSend",      EtcDir + "/StartMqttSend",      775),
            new(ResourcePrefix + "StartMqttReceive",   EtcDir + "/StartMqttReceive",   775),
            new(ResourcePrefix + "keypress.sh",        EtcDir + "/keypress.sh",        775),
            new(ResourcePrefix + "filter.py",          EtcDir + "/filter.py",          775),
            new(ResourcePrefix + "mqtt_common.sh",     EtcDir + "/mqtt_common.sh",     644),
            new(ResourcePrefix + "bt_service_watchdog", "/etc/init.d/bt_service_watchdog", 775),
        };

        // Boot symlinks in rc5.d. The watchdog (S99BtServiceWatchdog) sorts before
        // the bridge (S99TcpDump2Mqtt) — B < T — so it comes up first.
        private static readonly (string Link, string Target)[] Symlinks =
        {
            ("/etc/rc5.d/S99BtServiceWatchdog", "../init.d/bt_service_watchdog"),
            ("/etc/rc5.d/S99TcpDump2Mqtt",      "../tcpdump2mqtt/TcpDump2Mqtt.sh"),
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
                bool alreadyMapped = fs.FileExists("/etc/init.d/bt_daemon-apps.sh") &&
                    ReadAllText(fs, "/etc/init.d/bt_daemon-apps.sh")
                        .Contains("/bin/bt_hosts.sh add " + opts.MqttHost + " ");
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
                checks.Add(new("flexisipsh has the touch line exactly once",
                    CountOccurrences(flexi, "/bin/touch /tmp/flexisip_restarted") == 1, ""));
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
                    fs.FileExists("/etc/init.d/bt_daemon-apps.sh"), ""));
                string hosts = fs.FileExists("/etc/init.d/bt_daemon-apps.sh")
                    ? ReadAllText(fs, "/etc/init.d/bt_daemon-apps.sh") : "";
                // When the broker IP was pinned explicitly (HostIpForHosts, hostname
                // case), assert the exact mapping — otherwise a patch that wrote the
                // wrong IP would still pass. When the IP was DNS-resolved at install
                // time it isn't known here, so fall back to the host-prefix check.
                bool hostLine = (!opts.HostIsIp && !string.IsNullOrWhiteSpace(opts.HostIpForHosts))
                    ? hosts.Contains($"/bin/bt_hosts.sh add {opts.MqttHost} {opts.HostIpForHosts}")
                    : hosts.Contains("/bin/bt_hosts.sh add " + opts.MqttHost + " ");
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
                    ("nc", new[] { "/usr/bin/nc", "/bin/nc" }),                   // StartMqttReceive: bare `nc` via PATH
                    ("route", new[] { "/sbin/route", "/usr/sbin/route", "/bin/route" }), // #10 base tool (not invoked by us)
                    ("ping", new[] { "/bin/ping", "/usr/bin/ping" }),            // #10 base tool (not invoked by us)
                };
                foreach (var (name, paths) in deps)
                    // File only: these are executables / init scripts, so a
                    // directory at the path is not a satisfied dependency.
                    checks.Add(new($"runtime dep {name} present",
                        paths.Any(fs.FileExists),
                        string.Join(" | ", paths)));
            }
            return checks;
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

            if (content.Contains(marker)) return; // already patched (by us or upstream)

            // Insert specifically inside the `start)` case: find that case label,
            // then the first `start-stop-daemon --start` before the block ends
            // (`;;`). Searching the whole file could match a start-stop-daemon line
            // in another case/function and patch the wrong place.
            string[] lines = content.Replace("\r\n", "\n").Split('\n');
            int startCase = Array.FindIndex(lines, l =>
            {
                string t = l.Trim();
                return t == "start)" || t.StartsWith("start)", StringComparison.Ordinal);
            });
            if (startCase < 0)
                throw new InvalidOperationException(
                    CoreStrings.Format("Mqtt_AnchorMissing", path, "start) case"));

            int anchor = -1;
            for (int i = startCase + 1; i < lines.Length; i++)
            {
                if (IsCaseTerminator(lines[i])) break;   // end of the start) block
                if (lines[i].Contains("start-stop-daemon --start")) { anchor = i; break; }
            }
            if (anchor < 0)
                throw new InvalidOperationException(CoreStrings.Format("Mqtt_AnchorMissing", path,
                    "start-stop-daemon --start (in the start) case)"));

            var patched = new List<string>(lines);
            patched.Insert(anchor + 1, "\t" + marker);
            RewritePreservingMeta(fs, path, string.Join("\n", patched));
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
        /// Adds a <c>bt_hosts.sh add &lt;host&gt; &lt;ip&gt;</c> line after the
        /// existing <c>openserver</c> mapping in bt_daemon-apps.sh, so the device
        /// can resolve a broker given by name. Preserves owner+mode (on-device
        /// 0700 root:root). Idempotent.
        /// </summary>
        private static void PatchHosts(ExtFileSystem fs, string host, string ip)
        {
            const string path = "/etc/init.d/bt_daemon-apps.sh";
            if (!fs.FileExists(path))
                throw new InvalidOperationException(CoreStrings.Format("Mqtt_FileMissing", path));

            string content = ReadAllText(fs, path);
            string addLine = $"/bin/bt_hosts.sh add {host} {ip}";
            if (content.Contains(addLine)) return; // already patched

            string[] lines = content.Replace("\r\n", "\n").Split('\n');
            int anchor = Array.FindIndex(lines,
                l => l.Contains("/bin/bt_hosts.sh add openserver 127.0.0.1"));
            if (anchor < 0)
                throw new InvalidOperationException(CoreStrings.Format("Mqtt_AnchorMissing", path,
                    "/bin/bt_hosts.sh add openserver 127.0.0.1"));

            var patched = new List<string>(lines);
            patched.Insert(anchor + 1, "\t" + addLine);
            RewritePreservingMeta(fs, path, string.Join("\n", patched));
        }

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

        private static int CountOccurrences(string haystack, string needle)
        {
            if (needle.Length == 0) return 0;
            int count = 0, i = 0;
            while ((i = haystack.IndexOf(needle, i, StringComparison.Ordinal)) >= 0)
            {
                count++;
                i += needle.Length;
            }
            return count;
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
