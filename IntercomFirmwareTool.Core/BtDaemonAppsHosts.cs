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
            return SplitLines(ReadAllText(fs)).Any(l => LineIs(l, expected));
        }

        /// <summary>
        /// True when the file maps <paramref name="host"/> to ANY IP — a whole line
        /// beginning with the <c>bt_hosts.sh add &lt;host&gt; </c> command. A commented
        /// line (trimmed, it starts with <c>#</c>) does not match. Used where only the
        /// presence of a mapping for the name matters, not its exact IP.
        /// </summary>
        internal static bool HasHostMapping(ExtFileSystem fs, string host)
        {
            if (!fs.FileExists(Path)) return false;
            string prefix = $"/bin/bt_hosts.sh add {host} ";
            return SplitLines(ReadAllText(fs)).Any(l => LineStarts(l, prefix));
        }

        /// <summary>
        /// Ensures each <c>host → ip</c> mapping is present exactly once, right after
        /// the <c>openserver</c> anchor, in a single read-modify-write. Enforces
        /// <b>one mapping per host</b>: an existing mapping for the same host with a
        /// different IP (or a duplicate) is removed and replaced, rather than leaving
        /// several <c>bt_hosts.sh add &lt;host&gt;</c> commands whose net effect would
        /// depend on runtime order. Whole-line matching (a commented line never
        /// counts); the stock <c>openserver</c> anchor is never removed; the file's
        /// owner+mode are preserved (on-device <c>0700 root:root</c>). Idempotent — a
        /// no-op (no write) when every mapping is already exactly present. Throws if
        /// the file is missing, or if a mapping must be inserted but the anchor is
        /// absent.
        /// </summary>
        internal static void AddMappings(ExtFileSystem fs, IReadOnlyList<(string Host, string Ip)> mappings)
        {
            if (!fs.FileExists(Path))
                throw new InvalidOperationException(CoreStrings.Format("Hosts_FileMissing", Path));

            var lines = new List<string>(SplitLines(ReadAllText(fs)));
            bool changed = false;
            foreach (var (host, ip) in mappings)
            {
                string desired = MappingLine(host, ip);
                // The stock openserver→127.0.0.1 mapping IS the anchor line; it is
                // always present, so a request for it is already satisfied and must
                // never lead to removing or duplicating the anchor.
                if (string.Equals(desired, OpenserverAnchor, StringComparison.OrdinalIgnoreCase))
                    continue;

                // Every existing mapping for this host (any IP), by whole line, but
                // NEVER the openserver anchor. A commented line (trimmed, starts with
                // '#') does not match the command prefix.
                string prefix = $"/bin/bt_hosts.sh add {host} ";
                bool IsHostMapping(string l) => !LineIs(l, OpenserverAnchor) && LineStarts(l, prefix);

                int existing = lines.Count(IsHostMapping);
                // Already exactly right: one mapping for this host and it is the
                // desired one → nothing to do.
                if (existing == 1 && lines.Any(l => LineIs(l, desired))) continue;

                // Otherwise enforce uniqueness: drop every existing mapping for this
                // host (wrong IP and/or duplicates), then insert the desired one.
                if (existing > 0) { lines.RemoveAll(IsHostMapping); changed = true; }

                int anchor = lines.FindIndex(l => LineIs(l, OpenserverAnchor));
                if (anchor < 0)
                    throw new InvalidOperationException(
                        CoreStrings.Format("Hosts_AnchorMissing", Path, OpenserverAnchor));
                lines.Insert(anchor + 1, "\t" + desired);
                changed = true;
            }
            if (changed) RewritePreservingMeta(fs, string.Join("\n", lines));
        }

        // ---- fs plumbing (the drift-prone logic is above; this is trivial I/O) ---

        private static string[] SplitLines(string content) =>
            content.Replace("\r\n", "\n").Split('\n');

        // Line comparisons are case-INSENSITIVE: a bt_hosts.sh line's variable part is
        // the hostname, and hostnames are case-insensitive (RFC 4343), so the same
        // broker entered as "Broker.EXAMPLE.com" and "broker.example.com" must be
        // recognized as the same mapping — otherwise idempotency/dedup would miss it.
        // The fixed command text is always lowercase as we write it, so ignoring case
        // there is harmless.
        private static bool LineIs(string line, string exact) =>
            string.Equals(line.Trim(), exact, StringComparison.OrdinalIgnoreCase);

        private static bool LineStarts(string line, string prefix) =>
            line.Trim().StartsWith(prefix, StringComparison.OrdinalIgnoreCase);

        private static string ReadAllText(ExtFileSystem fs)
        {
            using var file = fs.OpenFile(Path, FileMode.Open, FileAccess.Read);
            long length = file.Length;
            if (length > MaxEditFileBytes)
                throw new NotSupportedException(
                    CoreStrings.Format("Hosts_FileTooLarge", Path, length, MaxEditFileBytes));
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
