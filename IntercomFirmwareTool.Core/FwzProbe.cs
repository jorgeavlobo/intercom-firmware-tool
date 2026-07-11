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
