using System.IO.Compression;
using ICSharpCode.SharpZipLib.Zip;
// Disambiguate: ZipFile exists in both System.IO.Compression and SharpZipLib.
// Here "ZipFile" always means the SharpZipLib one (which supports ZipCrypto).
using ZipFile = ICSharpCode.SharpZipLib.Zip.ZipFile;

namespace IntercomFirmwareTool.Core
{
    /// <summary>Result of reading the full chain from a .fwz.</summary>
    public sealed record FwzReadResult(
        string PasswordUsed,
        string SelectedEntry,
        string Content);

    /// <summary>Password, selected entry and the temp path of the extracted bare ext4.</summary>
    public sealed record FwzExtractResult(
        string PasswordUsed,
        string SelectedEntry,
        string BareImagePath);

    /// <summary>Result of the .fwz write proof of concept.</summary>
    public sealed record FwzWriteResult(
        string PasswordUsed,
        string SelectedEntry,
        string TargetFile,
        bool CanWrite,
        string Before,
        string After,
        bool Persisted);

    /// <summary>Result of the SSH-enable edit + logical validation from a .fwz.</summary>
    public sealed record SshEnableReport(
        string PasswordUsed,
        string SelectedEntry,
        bool AllPass,
        IReadOnlyList<Ext4Check> Checks);

    /// <summary>Result of building a modified .fwz and round-tripping it.</summary>
    public sealed record FwzBuildResult(
        string OutputPath,
        string PasswordUsed,
        string SelectedEntry,
        bool RoundTripAllPass,
        IReadOnlyList<Ext4Check> RoundTripChecks);

    /// <summary>
    /// Replicates (read-only) the fquinto installer flow up to the ext4 image:
    /// opens the .fwz (a ZipCrypto ZIP), tries the known passwords, picks the
    /// right file (name ending in ".gz" and not containing "recovery"), gunzips
    /// it and reads a file from the resulting ext4 image.
    /// </summary>
    public static class FwzProbe
    {
        // .fwz passwords per model (they are the model names themselves in fquinto).
        private static readonly string[] Passwords = { "C300X", "C100X", "SMARTDES" };

        // Upper bound on the decompressed ext4 image, so a malformed/malicious
        // .gz cannot expand until the temp disk is exhausted.
        private const long MaxImageBytes = 2L * 1024 * 1024 * 1024; // 2 GiB

        /// <summary>
        /// Runs the full chain from a .fwz: finds the password, selects the
        /// payload, gunzips it and reads the requested file from the ext4 image.
        /// </summary>
        /// <param name="fwzPath">Path to the .fwz file.</param>
        /// <param name="fileInsideImage">File inside the ext4, e.g. "/etc/hostname".</param>
        public static FwzReadResult ReadFileFromFwz(string fwzPath, string fileInsideImage)
        {
            FwzExtractResult ex = ExtractBareImage(fwzPath);
            try
            {
                string content = Ext4Probe.ReadFile(ex.BareImagePath, fileInsideImage);
                return new FwzReadResult(ex.PasswordUsed, ex.SelectedEntry, content);
            }
            finally
            {
                TryDelete(ex.BareImagePath);
            }
        }

        /// <summary>
        /// Runs the same chain and then a WRITE proof of concept on the
        /// extracted ext4 (all on temp files): mounts it read-write, reports
        /// <c>CanWrite</c>, and if writable appends a test line to
        /// <paramref name="targetFile"/> and verifies it persists after a raw
        /// round-trip. The caller's .fwz is never modified.
        /// </summary>
        public static FwzWriteResult TestWriteFromFwz(string fwzPath, string targetFile, string testLine)
        {
            FwzExtractResult ex = ExtractBareImage(fwzPath);
            try
            {
                Ext4WriteResult w = Ext4Probe.TestAppendPersists(ex.BareImagePath, targetFile, testLine);
                return new FwzWriteResult(
                    ex.PasswordUsed, ex.SelectedEntry, targetFile,
                    w.CanWrite, w.Before, w.After, w.Persisted);
            }
            finally
            {
                TryDelete(ex.BareImagePath);
            }
        }

        /// <summary>
        /// Extracts the bare ext4 from the .fwz, applies the SSH/root-enable
        /// edits (Phase A–D) on a temporary copy, reopens the modified image and
        /// validates every change. All on temp files — the .fwz is never
        /// modified and no repackaging happens here (that is a later step).
        /// </summary>
        public static SshEnableReport TestSshEnableFromFwz(string fwzPath, EnableSshOptions opts)
        {
            FwzExtractResult ex = ExtractBareImage(fwzPath);
            string? modified = null;
            try
            {
                modified = Ext4Probe.EnableSsh(ex.BareImagePath, opts);
                IReadOnlyList<Ext4Check> checks = Ext4Probe.ValidateSsh(modified, opts);
                bool all = true;
                foreach (var c in checks) all &= c.Pass;
                return new SshEnableReport(ex.PasswordUsed, ex.SelectedEntry, all, checks);
            }
            finally
            {
                if (modified != null) TryDelete(modified);
                TryDelete(ex.BareImagePath);
            }
        }

        /// <summary>
        /// Read-only: opens an already-modified .fwz, extracts its ext4 and runs
        /// the SSH-enable validation checklist against it — WITHOUT modifying
        /// anything. Use it to cross-validate a .fwz produced by another tool
        /// (e.g. fquinto) against the same expected edits, given the password and
        /// public key that .fwz was built with.
        /// </summary>
        public static SshEnableReport ValidateSshInFwz(string fwzPath, EnableSshOptions opts)
        {
            FwzExtractResult ex = ExtractBareImage(fwzPath);
            try
            {
                IReadOnlyList<Ext4Check> checks = Ext4Probe.ValidateSsh(ex.BareImagePath, opts);
                bool all = true;
                foreach (var c in checks) all &= c.Pass;
                return new SshEnableReport(ex.PasswordUsed, ex.SelectedEntry, all, checks);
            }
            finally
            {
                TryDelete(ex.BareImagePath);
            }
        }

        /// <summary>
        /// Full write pipeline (all on temp files except the chosen output):
        /// extract → SSH-enable → re-gzip → repack into a NEW .fwz at
        /// <paramref name="outputPath"/> (all 4 entries DEFLATE level 9 +
        /// ZipCrypto, like fquinto), then round-trip: reopen the output .fwz
        /// with our own read chain and re-validate every SSH change. The input
        /// .fwz is never modified; the output is for validation, not flashing.
        /// </summary>
        public static FwzBuildResult BuildModifiedFwz(string inputFwz, EnableSshOptions opts, string outputPath)
        {
            // Repack opens the output with FileMode.Create while still reading the
            // input; if they are the same file the source is truncated mid-read
            // and the original archive is destroyed. Reject that up front.
            if (PathsEqual(inputFwz, outputPath))
                throw new InvalidOperationException(
                    "The output .fwz must be a different file from the input .fwz.");

            FwzExtractResult ex = ExtractBareImage(inputFwz);
            string? modifiedBare = null;
            string? modifiedGz = null;
            try
            {
                // 1) Apply Phase A–D to a modified raw ext4.
                modifiedBare = Ext4Probe.EnableSsh(ex.BareImagePath, opts);

                // 2) Re-gzip the modified ext4 into a temp .gz.
                modifiedGz = NewTempPath(".gz");
                using (var inFs = new FileStream(modifiedBare, FileMode.Open, FileAccess.Read))
                using (var outGz = new FileStream(modifiedGz, FileMode.CreateNew, FileAccess.Write))
                using (var gz = new GZipStream(outGz, CompressionLevel.SmallestSize))
                    inFs.CopyTo(gz);

                // 3) Repack a new ZipCrypto .fwz with the modified entry replaced.
                Repack(inputFwz, ex.PasswordUsed, ex.SelectedEntry, modifiedGz, outputPath);

                // 4) Round-trip: read the OUTPUT .fwz back through our chain and
                //    re-validate all the SSH edits survived gzip + ZipCrypto zip.
                FwzExtractResult rt = ExtractBareImage(outputPath);
                try
                {
                    IReadOnlyList<Ext4Check> checks = Ext4Probe.ValidateSsh(rt.BareImagePath, opts);
                    bool all = true;
                    foreach (var c in checks) all &= c.Pass;
                    return new FwzBuildResult(outputPath, ex.PasswordUsed, ex.SelectedEntry, all, checks);
                }
                finally
                {
                    TryDelete(rt.BareImagePath);
                }
            }
            finally
            {
                if (modifiedGz != null) TryDelete(modifiedGz);
                if (modifiedBare != null) TryDelete(modifiedBare);
                TryDelete(ex.BareImagePath);
            }
        }

        /// <summary>
        /// Writes a new .fwz: every entry of <paramref name="inputFwz"/> re-added
        /// with DEFLATE level 9 + ZipCrypto (<paramref name="password"/>), in the
        /// original order, with <paramref name="modifiedEntryName"/> replaced by
        /// the bytes of <paramref name="modifiedGzPath"/>. Mirrors fquinto's
        /// pyminizip.compress_multiple(level=9).
        /// </summary>
        private static void Repack(
            string inputFwz, string password, string modifiedEntryName,
            string modifiedGzPath, string outputPath)
        {
            using var srcZip = new ZipFile(inputFwz) { Password = password };
            using var outFs = new FileStream(outputPath, FileMode.Create, FileAccess.Write);
            using var zipOut = new ZipOutputStream(outFs) { Password = password };
            zipOut.SetLevel(9); // DEFLATE level 9, like fquinto

            foreach (ZipEntry src in srcZip)
            {
                if (!src.IsFile) continue;
                var entry = new ZipEntry(src.Name) { CompressionMethod = CompressionMethod.Deflated };
                zipOut.PutNextEntry(entry);
                if (string.Equals(src.Name, modifiedEntryName, StringComparison.Ordinal))
                {
                    using var gzFs = new FileStream(modifiedGzPath, FileMode.Open, FileAccess.Read);
                    gzFs.CopyTo(zipOut);
                }
                else
                {
                    using var s = srcZip.GetInputStream(src);
                    s.CopyTo(zipOut);
                }
                zipOut.CloseEntry();
            }
            zipOut.Finish();
        }

        /// <summary>
        /// Opens the .fwz, finds the password, selects the non-recovery ".gz"
        /// payload and gunzips it into a temporary bare ext4 file. Returns the
        /// password, the entry name and the temp path — the caller must delete
        /// the temp file when done.
        /// </summary>
        public static FwzExtractResult ExtractBareImage(string fwzPath)
        {
            using var zip = new ZipFile(fwzPath);

            // 1) Select the entry: name ends in ".gz" and does not contain
            //    "recovery" (fquinto's rule). Yields btweb_only.ext4.gz.
            ZipEntry? selected = null;
            foreach (ZipEntry entry in zip)
            {
                if (!entry.IsFile) continue;
                string name = entry.Name;
                // fquinto's rule (name with "gz" and without "recovery"), but
                // requiring it to actually end in ".gz" so we don't pick a
                // signature sidecar like "btweb_only.ext4.gz.sig".
                if (name.EndsWith(".gz", StringComparison.OrdinalIgnoreCase) &&
                    !name.Contains("recovery", StringComparison.OrdinalIgnoreCase))
                {
                    selected = entry;
                    break;
                }
            }
            if (selected is null)
                throw new InvalidOperationException(
                    "No '.gz' (non-recovery) file found inside the .fwz.");

            // 2) Find which of the known passwords opens the entry.
            string? goodPassword = null;
            foreach (string pw in Passwords)
            {
                if (PasswordOpensEntry(zip, selected, pw))
                {
                    goodPassword = pw;
                    break;
                }
            }
            if (goodPassword is null)
                throw new InvalidOperationException(
                    "None of the known passwords (C300X, C100X, SMARTDES) opened the .fwz.");

            zip.Password = goodPassword;

            // 3) Decrypt (ZipCrypto) and decompress (gzip) in a single stream,
            //    straight into the .ext4 temp file — without writing the
            //    intermediate .gz to disk (less I/O, less data left in %TEMP%).
            //    The copy is bounded so a bad .gz cannot fill the temp disk.
            string extTemp = NewTempPath(".ext4");
            try
            {
                using (var zin = zip.GetInputStream(selected))
                using (var gunzip = new GZipStream(zin, CompressionMode.Decompress))
                using (var extOut = new FileStream(extTemp, FileMode.CreateNew, FileAccess.Write))
                    CopyBounded(gunzip, extOut, MaxImageBytes);

                return new FwzExtractResult(goodPassword, selected.Name, extTemp);
            }
            catch
            {
                TryDelete(extTemp);
                throw;
            }
        }

        /// <summary>
        /// Copies <paramref name="source"/> to <paramref name="destination"/>,
        /// throwing once more than <paramref name="maxBytes"/> have been written.
        /// </summary>
        private static void CopyBounded(Stream source, Stream destination, long maxBytes)
        {
            var buffer = new byte[81920];
            long written = 0;
            int read;
            while ((read = source.Read(buffer, 0, buffer.Length)) > 0)
            {
                written += read;
                if (written > maxBytes)
                    throw new NotSupportedException(
                        $"Decompressed image exceeds the {maxBytes} byte limit; aborting.");
                destination.Write(buffer, 0, read);
            }
        }

        /// <summary>
        /// Checks whether a password decrypts the entry: since each entry is a
        /// .gz, the decrypted content must start with the gzip header — magic
        /// bytes 0x1F 0x8B followed by the deflate compression method 0x08.
        /// This makes a ZipCrypto false positive extremely unlikely (~1/16M).
        /// </summary>
        private static bool PasswordOpensEntry(ZipFile zip, ZipEntry entry, string password)
        {
            zip.Password = password;
            try
            {
                using var s = zip.GetInputStream(entry);
                int b0 = s.ReadByte();
                int b1 = s.ReadByte();
                int b2 = s.ReadByte();
                return b0 == 0x1F && b1 == 0x8B && b2 == 0x08;
            }
            catch (ZipException)
            {
                return false; // wrong password
            }
        }

        /// <summary>True if two paths resolve to the same file (case-insensitive, Windows).</summary>
        private static bool PathsEqual(string a, string b) =>
            string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase);

        /// <summary>Builds a unique path in the temp folder with the given extension.</summary>
        private static string NewTempPath(string extension) =>
            Path.Combine(Path.GetTempPath(), $"fwzprobe_{Guid.NewGuid():N}{extension}");

        /// <summary>Deletes a file if it exists, ignoring failures (best-effort).</summary>
        private static void TryDelete(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); }
            catch { /* best-effort cleanup */ }
        }
    }
}
