using SharpExt4;
using System.Text;
using IntercomFirmwareTool.Core.Localization;

namespace IntercomFirmwareTool.Core
{
    /// <summary>
    /// Single owner of the device's boot-time hosts seeding in
    /// <c>/etc/init.d/bt_daemon-apps.sh</c>: adds
    /// <c>/bin/bt_hosts.sh add &lt;host&gt; &lt;ip&gt;</c> lines after the existing
    /// <c>openserver</c> mapping, so the unit resolves the name (into the tmpfs
    /// <c>/etc/hosts</c>) at every boot.
    ///
    /// <para>Both features that need this — the MQTT broker-name mapping
    /// (<see cref="MqttInstaller"/>) and the OTA-update block
    /// (<see cref="Ext4Probe"/>) — go through here, so the anchor, the
    /// whole-line matching semantics, the idempotency guard and the owner/mode
    /// preservation live in ONE place and cannot drift between the two paths.</para>
    ///
    /// <para>Matching is on WHOLE normalized lines (the scripts indent with a
    /// tab), never a substring: a commented-out or superset line must not count
    /// as the anchor or as an already-present mapping, otherwise a commented
    /// mapping could suppress insertion yet still validate as present.</para>
    /// </summary>
    internal static class BtDaemonAppsHosts
    {
        /// <summary>The init script that seeds the device's hosts file at boot.</summary>
        internal const string Path = "/etc/init.d/bt_daemon-apps.sh";

        // The stock line every image carries; we insert new mappings right after it.
        private const string OpenserverAnchor = "/bin/bt_hosts.sh add openserver 127.0.0.1";

        private const long MaxEditFileBytes = 4L * 1024 * 1024; // the init script is tiny

        /// <summary>The exact <c>bt_hosts.sh add</c> command line for a mapping.</summary>
        internal static string MappingLine(string host, string ip) =>
            $"/bin/bt_hosts.sh add {host} {ip}";

        /// <summary>
        /// True when the file already contains the exact <paramref name="host"/> →
        /// <paramref name="ip"/> mapping as a whole line (ignoring the leading tab /
        /// trailing space). A commented or superset line does not count.
        /// </summary>
        internal static bool HasMapping(ExtFileSystem fs, string host, string ip)
        {
            if (!fs.FileExists(Path)) return false;
            string expected = MappingLine(host, ip);
            return SplitLines(ReadAllText(fs, Path)).Any(l => l.Trim() == expected);
        }

        /// <summary>
        /// Adds each missing <c>host → ip</c> mapping after the <c>openserver</c>
        /// anchor, in order, in a single read-modify-write. Idempotent per mapping
        /// (whole-line match); preserves the file's owner+mode (on-device
        /// <c>0700 root:root</c>). Throws if the file is missing, or if any mapping
        /// needs inserting but the anchor is absent. A no-op (no write) when every
        /// mapping is already present.
        /// </summary>
        internal static void AddMappings(ExtFileSystem fs, IReadOnlyList<(string Host, string Ip)> mappings)
        {
            if (!fs.FileExists(Path))
                throw new InvalidOperationException(CoreStrings.Format("Mqtt_FileMissing", Path));

            var patched = new List<string>(SplitLines(ReadAllText(fs, Path)));
            int anchor = -1, insertAt = -1;
            bool changed = false;
            foreach (var (host, ip) in mappings)
            {
                string addLine = MappingLine(host, ip);
                // Idempotent: skip a mapping already present (whole-line), including
                // one inserted earlier in this same call.
                if (patched.Any(l => l.Trim() == addLine)) continue;

                // Resolve the anchor lazily — only when there is actually something
                // to insert — so an all-present (no-op) call never fails on a missing
                // anchor.
                if (anchor < 0)
                {
                    anchor = patched.FindIndex(l => l.Trim() == OpenserverAnchor);
                    if (anchor < 0)
                        throw new InvalidOperationException(
                            CoreStrings.Format("Mqtt_AnchorMissing", Path, OpenserverAnchor));
                    insertAt = anchor + 1;
                }
                patched.Insert(insertAt, "\t" + addLine);
                insertAt++;
                changed = true;
            }
            if (changed) RewritePreservingMeta(fs, string.Join("\n", patched));
        }

        // ---- fs plumbing (the drift-prone logic is above; this is trivial I/O) ---

        private static string[] SplitLines(string content) =>
            content.Replace("\r\n", "\n").Split('\n');

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
            if (total != len)
                throw new IOException(CoreStrings.Format("Ext4_IncompleteRead", len, total));
            return Encoding.UTF8.GetString(buf, 0, total);
        }

        private static void RewritePreservingMeta(ExtFileSystem fs, string text)
        {
            uint mode = fs.GetMode(Path) & 0xFFF;
            var owner = fs.GetOwner(Path);
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            using (var f = fs.OpenFile(Path, FileMode.Create, FileAccess.Write))
                f.Write(bytes, 0, bytes.Length);
            fs.SetMode(Path, mode);
            if (owner != null) fs.SetOwner(Path, owner.Item1, owner.Item2);
        }
    }
}
