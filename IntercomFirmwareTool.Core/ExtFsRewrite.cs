using System;
using System.IO;
using System.Text;
using IntercomFirmwareTool.Core.Localization;

namespace IntercomFirmwareTool.Core
{
    /// <summary>
    /// The shared crash-safe in-place file rewrite for ext-image editing (issue #151 / #154). The in-place script
    /// edits that go through it replace an EXISTING file's contents while preserving its mode/owner — the
    /// factory-firewall hook and flexisip init script (<see cref="MqttInstaller"/>) and the boot-time hosts script
    /// (<see cref="BtDaemonAppsHosts"/>). Keeping the swap protocol in ONE place means the correctness the #151
    /// review rounds established (verified raw-byte write, backup + rollback, recover-on-next-run, fail-closed on
    /// odd sibling shapes) cannot drift between callers, and it is exercised by one shared test suite through the
    /// in-memory <c>IExtFs</c> fake — no native SharpExt4 or ext4 fixture required.
    ///
    /// <para>NOT every in-place rewrite in the codebase routes through here yet: <see cref="Ext4Probe"/>'s
    /// <c>/etc/passwd</c> + <c>/etc/shadow</c> SSH edits still use a truncating write and lack an
    /// <c>IExtFs</c> seam; migrating them is tracked in issue #156.</para>
    /// </summary>
    internal static class ExtFsRewrite
    {
        /// <summary>
        /// Replaces <paramref name="path"/>'s contents with <paramref name="text"/> WITHOUT ever leaving the
        /// original truncated on failure. A bare <c>FileMode.Create</c> write truncates the target to zero BEFORE
        /// the new bytes land, so a mid-write throw or crash would leave a partial — or empty — file on the image;
        /// for a security-critical hook (the factory firewall, #145) that means flashing a firewall that silently
        /// does nothing. Instead we write the new content to a sibling temp file, read it back and require a
        /// byte-for-byte match, stamp the captured mode/owner onto the temp, and only THEN swap it into place. The
        /// good original is never touched until a fully-written, verified replacement exists; on any earlier
        /// failure the original stays intact and the temp is removed.
        ///
        /// <para>SharpExt4's <c>RenameFile</c> refuses to overwrite an existing destination, so the swap goes
        /// through a BACKUP rather than deleting the original outright: <c>original → .ift-bak</c>, then
        /// <c>temp → path</c>, then delete the backup. If the second rename fails the original is rolled back from
        /// <c>.ift-bak</c>, so <paramref name="path"/> always ends up holding either the verified new content or
        /// the intact original — never nothing. The only non-atomic residue is the sub-millisecond window between
        /// the two renames; it matters solely on host power-loss mid-swap, and even then the original survives on
        /// disk under <c>.ift-bak</c>. This is a HOST-side image editor whose output is not flashed until the tool
        /// returns success, so a crash there simply means re-running against a fresh image, never a half-written
        /// device.</para>
        /// </summary>
        internal static void RewritePreservingMeta(IExtFs fs, string path, string text)
        {
            uint mode = fs.GetMode(path) & 0xFFF;
            var owner = fs.GetOwner(path);
            string tmp = path + ".ift-tmp";   // staging for the new content
            string bak = path + ".ift-bak";   // the original, moved aside during the swap
            // Clear any siblings a previously-interrupted swap may have left behind; RenameFile refuses to
            // overwrite, so a leftover here would break the swap.
            ClearSwapSibling(fs, tmp, path);
            ClearSwapSibling(fs, bak, path);
            try
            {
                byte[] expected = Encoding.UTF8.GetBytes(text);
                WriteAllBytes(fs, tmp, expected);
                // Read the just-written temp back and require an exact match before it is allowed to replace the
                // original. A short/partial write that slipped past WriteAllBytes is caught HERE — while the
                // original is still in place and nothing has been destroyed. Compare RAW BYTES (not decoded
                // text): UTF-8 decoding maps malformed sequences to U+FFFD, so a decoded-string compare could let
                // a corrupted temp pass; ReadAllBytes also fails loudly on a short read.
                if (!ReadAllBytes(fs, tmp).AsSpan().SequenceEqual(expected))
                    throw new IOException(CoreStrings.Format("Mqtt_RewriteVerifyFailed", path));
                // Stamp the captured metadata onto the temp; SharpExt4's rename moves the inode, so mode/owner
                // travel with it into the final path.
                fs.SetMode(tmp, mode);
                if (owner != null) fs.SetOwner(tmp, owner.Item1, owner.Item2);
            }
            catch
            {
                // Nothing has moved yet — the original is untouched. Best-effort clean up the partial temp.
                TryDeleteRegular(fs, tmp);
                throw;
            }
            // Commit via a BACKUP so the original is never lost, even if a rename fails mid-swap. RenameFile
            // will not overwrite (see IExtFs.RenameFile), so the destination must be free before each move:
            //   1. original -> bak   (frees `path`; original now safe under `bak`)
            //   2. tmp      -> path  (the verified replacement lands)
            //   3. delete bak        (best-effort cleanup)
            // If step 2 throws (an ext I/O error, say), we roll the original back from `bak`, so `path` always
            // ends up holding either the new verified content or the intact original — never nothing.
            try
            {
                fs.RenameFile(path, bak);
            }
            catch
            {
                TryDeleteRegular(fs, tmp);   // original still at `path`; drop the staged temp
                throw;
            }
            try
            {
                fs.RenameFile(tmp, path);
            }
            catch
            {
                // Restore the original; if even this fails the original still exists on disk under `bak`.
                try { fs.RenameFile(bak, path); } catch { /* original remains recoverable at bak */ }
                TryDeleteRegular(fs, tmp);
                throw;
            }
            TryDeleteRegular(fs, bak);
        }

        /// <summary>
        /// Reconciles a <c>.ift-bak</c> that a previous <see cref="RewritePreservingMeta"/> run left behind when
        /// the host died mid-swap, run BEFORE a caller's target-existence check so an interrupted swap never
        /// looks like a missing (or already-done) file:
        /// <list type="bullet">
        /// <item>crash AFTER <c>original → .ift-bak</c> but BEFORE <c>temp → path</c> — <paramref name="path"/> is
        /// absent while <c>.ift-bak</c> holds the intact original: restore it (<c>bak → path</c>, carrying
        /// mode/owner), else the file would be treated as absent and the edit silently skipped or wrongly
        /// rejected as missing.</item>
        /// <item>crash AFTER <c>temp → path</c> but BEFORE the backup cleanup — the target is present and the
        /// idempotency check may skip the rewrite, so a stale (executable) <c>.ift-bak</c> or leftover
        /// <c>.ift-tmp</c> would linger forever.</item>
        /// </list>
        /// After any restore, it reconciles BOTH swap siblings via <see cref="ClearSwapSibling"/> in every case —
        /// target present, restored, or genuinely absent — which deletes a regular leftover and FAILS CLOSED on a
        /// non-regular node (symlink/dir) at these tool-reserved paths, so an unexpected shape can't slip through
        /// the idempotent-skip path or the absent-target no-op. Only when the TARGET itself is a non-regular node
        /// are the siblings left intact — the caller fails closed on that target shape.
        /// </summary>
        internal static void RecoverInterruptedRewrite(IExtFs fs, string path)
        {
            string tmp = path + ".ift-tmp";
            string bak = path + ".ift-bak";

            // If the TARGET itself is a non-regular node (symlink/dir), leave everything as-is; the caller fails
            // closed on that target shape. (FileExists is symlink-blind, so "absent AND occupied" == non-regular.)
            if (!fs.FileExists(path) && PathOccupied(fs, path))
                return;

            // Swap crashed AFTER original -> .ift-bak but BEFORE the promote: the target is absent while a regular
            // backup holds the original — restore it so the caller doesn't mistake the file for genuinely absent.
            if (!fs.FileExists(path) && fs.FileExists(bak))
                fs.RenameFile(bak, path);

            // Reconcile any remaining swap siblings in EVERY case (target present, restored, or genuinely absent).
            // ClearSwapSibling deletes a regular leftover and FAILS CLOSED on a non-regular node at these
            // tool-reserved paths — so a symlink/dir at .ift-tmp/.ift-bak can't slip through the idempotent-skip
            // path or the absent-target no-op.
            ClearSwapSibling(fs, tmp, path);
            ClearSwapSibling(fs, bak, path);
        }

        /// <summary>
        /// True when <paramref name="path"/> is OCCUPIED by anything — a regular file, a directory, or a symlink.
        /// <see cref="IExtFs.FileExists"/> is symlink-blind, so callers that must not clobber a non-regular node
        /// use this to detect one. (Mirrors the same helper in <see cref="Ext4Probe"/> / <see cref="MqttInstaller"/>.)
        /// </summary>
        internal static bool PathOccupied(IExtFs fs, string path)
        {
            if (fs.FileExists(path) || fs.DirectoryExists(path)) return true;
            try { fs.ReadSymLink(path); return true; } catch { return false; }
        }

        /// <summary>
        /// Clears a swap sibling (<c>.ift-tmp</c> / <c>.ift-bak</c>) left over from an interrupted rewrite so the
        /// no-overwrite <see cref="IExtFs.RenameFile"/> has a free destination. A regular file is deleted; a path
        /// OCCUPIED by a non-regular node (a symlink or directory — which <see cref="IExtFs.FileExists"/> is blind
        /// to) cannot be safely cleared and would make the swap rename over an unexpected shape, so we fail closed
        /// rather than risk it.
        /// </summary>
        private static void ClearSwapSibling(IExtFs fs, string sibling, string target)
        {
            if (fs.FileExists(sibling)) { fs.DeleteFile(sibling); return; }
            if (PathOccupied(fs, sibling))
                throw new InvalidOperationException(
                    CoreStrings.Format("Mqtt_RewriteSiblingOccupied", target, sibling));
        }

        /// <summary>Best-effort removal of a regular file used only for cleanup on the failure/commit paths of
        /// <see cref="RewritePreservingMeta"/> — swallows any error since there is nothing further to do.</summary>
        private static void TryDeleteRegular(IExtFs fs, string path)
        {
            try { if (fs.FileExists(path)) fs.DeleteFile(path); } catch { /* best-effort */ }
        }

        /// <summary>Writes <paramref name="bytes"/> to <paramref name="path"/> via <c>FileMode.Create</c>
        /// (create/truncate). A ZERO-length write throws inside SharpExt4's ExtFileStream (empty-buffer edge), and
        /// Create has already left a correct 0-byte file, so an empty payload skips the write.</summary>
        private static void WriteAllBytes(IExtFs fs, string path, byte[] bytes)
        {
            using var f = fs.OpenFile(path, FileMode.Create, FileAccess.Write);
            if (bytes.Length > 0)
                f.Write(bytes, 0, bytes.Length);
        }

        /// <summary>Reads the whole of <paramref name="path"/> into a buffer, failing loudly on a short read
        /// (a truncated read-back must not silently pass verification). Used only to verify a just-written temp,
        /// whose size is known and small.</summary>
        private static byte[] ReadAllBytes(IExtFs fs, string path)
        {
            using var file = fs.OpenFile(path, FileMode.Open, FileAccess.Read);
            int len = (int)file.Length;
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
            return buf;
        }
    }
}
