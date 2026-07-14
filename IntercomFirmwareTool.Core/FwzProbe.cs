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

    /// <summary>
    /// Result of inspecting an existing .fwz's SSH-enable state without any
    /// caller-supplied credentials: the ZipCrypto password and inner entry, the
    /// informational findings (password-login mode, installed key fingerprint)
    /// and the objective structural checks.
    /// </summary>
    public sealed record SshInspectionReport(
        string PasswordUsed,
        string SelectedEntry,
        IReadOnlyList<string> Findings,
        IReadOnlyList<Ext4Check> Checks,
        bool AllPass);

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
        /// Read-only: opens an existing .fwz, extracts its ext4 and INSPECTS the
        /// SSH-enable state — reporting what is installed (password-login mode,
        /// key fingerprint) plus the objective structural checks — WITHOUT the
        /// caller declaring the password or key. This backs the UI's
        /// point-and-read "Verify existing .fwz" flow.
        /// </summary>
        public static SshInspectionReport InspectSshInFwz(string fwzPath)
        {
            FwzExtractResult ex = ExtractBareImage(fwzPath);
            try
            {
                SshInspection ins = Ext4Probe.InspectSsh(ex.BareImagePath);
                return new SshInspectionReport(
                    ex.PasswordUsed, ex.SelectedEntry, ins.Findings, ins.Checks, ins.AllPass);
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
            if (PathIdentity.SamePath(inputFwz, outputPath))
                throw new InvalidOperationException(
                    "The output .fwz must be a different file from the input .fwz.");

            // Validate the output folder up front, before the expensive extract/
            // repack, so a nonexistent target fails with a clear message instead of
            // a generic DirectoryNotFoundException from a later FileStream/File.Move.
            string outDir = Path.GetDirectoryName(Path.GetFullPath(outputPath)) ?? ".";
            if (!Directory.Exists(outDir))
                throw new DirectoryNotFoundException(
                    $"The output folder does not exist: {outDir}");

            // Hold the input open for the WHOLE build with a share mode that denies
            // deletion/replacement (FileShare.Read allows our own re-reads and any
            // other reader, but NOT delete). PathIdentity.SamePath above catches the
            // common aliases up front with a clear message; this lock is the backstop
            // no string-based path check can guarantee on Windows: if the output
            // resolves to the input through ANY alias the path comparison cannot see
            // as equal (a SUBST drive, an 8.3 short name, a hard link, …), the final
            // File.Move that would overwrite the input fails with a sharing violation
            // instead of destroying it. A genuinely different output is unaffected.
            // Resolve the input to its concrete final target ONCE, following any
            // symlink/junction. Every subsequent step (lock, verify, extract,
            // repack) uses this resolved path rather than reopening the original
            // name — otherwise a link retargeted mid-build could point the extract
            // at different bytes than the ones the whitelist gate just approved.
            string realInput = PathIdentity.ResolveFinal(inputFwz);

            using var inputLock = new FileStream(
                realInput, FileMode.Open, FileAccess.Read, FileShare.Read);

            // Tie the whitelist guarantee to the exact bytes we are about to
            // modify. A UI may pre-verify the selection, but between that check
            // and here the path could be replaced or a symlink retargeted; by
            // re-verifying the resolved target now — while inputLock holds it open
            // with a share mode that denies deletion/rename — the file that passes
            // this gate is the same one ExtractBareImage reads below. This is the
            // authoritative check: no non-UI caller can build from an unrecognized
            // firmware.
            var verified = FirmwareRegistry.Verify(realInput);
            if (!verified.Ok)
                throw new InvalidOperationException(
                    "Refusing to build: the input is not a recognized original firmware.\n" +
                    verified.Message);

            FwzExtractResult ex = ExtractBareImage(realInput);
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

                // 3) Repack a new ZipCrypto .fwz to a TEMP file in the same
                //    directory as the output (validated above), so the user's
                //    chosen path is only ever replaced by a fully written,
                //    verified artifact.
                string tempOut = Path.Combine(outDir, $".fwzbuild_{Guid.NewGuid():N}.tmp");
                bool committed = false;
                bool preserveTemp = false;
                try
                {
                    Repack(realInput, ex.PasswordUsed, ex.SelectedEntry, modifiedGz, tempOut);

                    // 4) Round-trip: validate the TEMP .fwz (reopen it through our
                    //    chain) before it is allowed to become the output.
                    FwzExtractResult rt = ExtractBareImage(tempOut);
                    var checkList = new List<Ext4Check>();
                    try
                    {
                        checkList.AddRange(Ext4Probe.ValidateSsh(rt.BareImagePath, opts));
                    }
                    finally
                    {
                        TryDelete(rt.BareImagePath);
                    }

                    // Assert the repacked entry is still ZipCrypto-encrypted and
                    // decrypts with the SAME password as the input. The round-trip
                    // above would otherwise "pass" an accidentally unencrypted
                    // archive, since any password reads an unencrypted entry.
                    checkList.Add(new Ext4Check(
                        $"{ex.SelectedEntry} is ZipCrypto-encrypted (input password)",
                        EntryEncryptedWith(tempOut, ex.SelectedEntry, ex.PasswordUsed), ""));

                    IReadOnlyList<Ext4Check> checks = checkList;
                    bool all = true;
                    foreach (var c in checks) all &= c.Pass;

                    // Only move the verified build into place; a failed build
                    // never overwrites/creates the user's output path.
                    if (all)
                    {
                        try
                        {
                            File.Move(tempOut, outputPath, overwrite: true);
                            committed = true;
                        }
                        catch (Exception moveEx)
                        {
                            // The build passed every check but could not be placed at
                            // the chosen output (e.g. the file is locked or the folder
                            // is read-only). Don't discard the verified artifact —
                            // keep the temp file and point the user at it to recover.
                            preserveTemp = true;
                            throw new IOException(
                                "The firmware was built and verified, but could not be written to:\n" +
                                outputPath + "\n(" + moveEx.Message + ")\n\n" +
                                "The verified build was kept here — move/rename it manually:\n" + tempOut,
                                moveEx);
                        }
                    }
                    return new FwzBuildResult(
                        committed ? outputPath : "", ex.PasswordUsed, ex.SelectedEntry, all, checks);
                }
                finally
                {
                    // Drop the temp only when it neither became the output nor is
                    // being deliberately preserved for the user to recover.
                    if (!committed && !preserveTemp) TryDelete(tempOut);
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
        /// True if the named entry of <paramref name="fwz"/> is <b>ZipCrypto</b>
        /// (traditional PKWARE) encrypted AND decrypts with
        /// <paramref name="password"/> to gzip data (magic 1F 8B 08). Guards against a
        /// repack that produced an unencrypted archive (which any password reads),
        /// one under a different password, or one that used AES instead of the
        /// ZipCrypto the device firmware expects.
        /// </summary>
        private static bool EntryEncryptedWith(string fwz, string entryName, string password)
        {
            try
            {
                using var zf = new ZipFile(fwz) { Password = password };
                ZipEntry? entry = zf.GetEntry(entryName);
                // IsCrypted covers ZipCrypto AND AES; AESKeySize == 0 narrows it to
                // traditional ZipCrypto (AES entries report 128/192/256).
                if (entry == null || !entry.IsCrypted || entry.AESKeySize != 0) return false;
                using var s = zf.GetInputStream(entry);
                // gzip header: magic 1F 8B + method 08 (deflate) — the same 3-byte
                // check PasswordOpensEntry uses, so a wrong password / garbage is far
                // less likely to pass by chance than a 2-byte magic-only check.
                return s.ReadByte() == 0x1F && s.ReadByte() == 0x8B && s.ReadByte() == 0x08;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Writes a new .fwz: every entry of <paramref name="inputFwz"/> — except
        /// <c>.sig</c> signature sidecars, which are dropped like fquinto's
        /// default — re-added with DEFLATE level 9 + ZipCrypto
        /// (<paramref name="password"/>), in the original order, with
        /// <paramref name="modifiedEntryName"/> replaced by the bytes of
        /// <paramref name="modifiedGzPath"/>. Mirrors fquinto's
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
                // Drop stale signature sidecars. fquinto removes .sig files by
                // default (main.py: remove_sig defaults to 'y', filtered out of
                // the repack list), and its output works on real devices — so
                // the updater tolerates their absence. Keeping a signature for
                // the now-modified payload could instead get the archive
                // rejected by a signature-checking updater.
                if (src.Name.EndsWith(".sig", StringComparison.OrdinalIgnoreCase)) continue;
                // Mark the entry ZipCrypto-encrypted explicitly (not only via the
                // stream Password): the device firmware requires traditional
                // ZipCrypto, and being explicit keeps the repack correct regardless
                // of SharpZipLib version behaviour. The build's round-trip re-check
                // (EntryEncryptedWith) still fails the build if this ever regresses.
                var entry = new ZipEntry(src.Name)
                {
                    CompressionMethod = CompressionMethod.Deflated,
                    IsCrypted = true,
                };
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

            // The genuine firmware payload is traditional ZipCrypto. Reject an
            // entry that is unencrypted (then any password's gzip-header check
            // would pass, falsely accepting the first candidate) or that is
            // AES-encrypted. This mirrors the IsCrypted/AESKeySize gate that
            // EntryEncryptedWith applies on the output-verification path.
            if (!selected.IsCrypted || selected.AESKeySize != 0)
                throw new InvalidOperationException(
                    "The '.gz' payload inside the .fwz is not ZipCrypto-encrypted " +
                    "(expected traditional PKWARE encryption).");

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
