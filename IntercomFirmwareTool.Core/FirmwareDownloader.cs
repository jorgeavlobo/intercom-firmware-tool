using System.ComponentModel; // AsyncCompletedEventArgs
using System.Security.Cryptography;
using Downloader;
using IntercomFirmwareTool.Core.Localization;

namespace IntercomFirmwareTool.Core
{
    /// <summary>Progress of a firmware download. <see cref="Fraction"/> is null until the total is known.</summary>
    public sealed record DownloadProgress(long BytesReceived, long TotalBytes, double BytesPerSecond)
    {
        public double? Fraction => TotalBytes > 0 ? (double)BytesReceived / TotalBytes : null;
    }

    /// <summary>Why a <see cref="FirmwareDownloader.DownloadAsync"/> ended.</summary>
    public enum DownloadOutcome
    {
        /// <summary>Downloaded and verified (size + SHA-256) against the registry entry.</summary>
        Verified,
        /// <summary>A valid copy already existed on disk; no download was needed.</summary>
        Cached,
        /// <summary>The caller cancelled.</summary>
        Cancelled,
        /// <summary>A network/HTTP transport failure (after retries).</summary>
        HttpError,
        /// <summary>Downloaded, but the bytes did not match the expected size/SHA-256.</summary>
        IntegrityMismatch,
        /// <summary>A local filesystem error (create dir / write / rename).</summary>
        IoError,
        /// <summary>The entry is not eligible (not Door Entry, or no URL) — a programming guard.</summary>
        NotDownloadable,
    }

    /// <summary>The result of a download attempt, with a localized <see cref="Message"/>.</summary>
    public sealed class DownloadResult
    {
        public DownloadOutcome Outcome { get; }
        /// <summary>The verified firmware file on <see cref="DownloadOutcome.Verified"/>/<see cref="DownloadOutcome.Cached"/>; else null.</summary>
        public string? Path { get; }
        public string Message { get; }

        public DownloadResult(DownloadOutcome outcome, string? path, string message)
        {
            Outcome = outcome;
            Path = path;
            Message = message;
        }

        public bool Ok => Outcome is DownloadOutcome.Verified or DownloadOutcome.Cached;
    }

    /// <summary>
    /// Fetches an official firmware from its registry <see cref="KnownFirmware.DownloadUrl"/> and
    /// guarantees the result is a byte-for-byte known-good original before it can be used (issue #23).
    ///
    /// Uses the <b>Downloader</b> library for a fast, resumable, multipart transfer, but the integrity
    /// gate is always <b>ours</b>: the downloaded bytes are verified against the <i>specific</i> entry's
    /// <see cref="KnownFirmware.SizeBytes"/> + <see cref="KnownFirmware.Sha256"/> (a clearer error than the
    /// whole-registry <see cref="FirmwareRegistry.Verify"/>), and a file that passes therefore also
    /// satisfies that gate downstream. The write is <b>atomic</b> — download to <c>&lt;name&gt;.part</c>,
    /// verify, then rename into place — so a failed/partial transfer never leaves a file that looks valid;
    /// and an already-present valid copy is a <b>cache hit</b> (no re-download).
    /// </summary>
    public sealed class FirmwareDownloader
    {
        // Modest parallelism: enough to be fast without hammering the CDN. Downloader falls back to a
        // single connection when the server doesn't support range requests. Timeout/retry use the
        // library defaults (its v5 DownloadConfiguration exposes neither as a property).
        private static DownloadConfiguration BuildConfig() => new()
        {
            ChunkCount = 4,
            ParallelDownload = true,
            RequestConfiguration = new RequestConfiguration
            {
                UserAgent = "IntercomFirmwareTool",
                AllowAutoRedirect = true,
                KeepAlive = true,
            },
        };

        /// <summary>
        /// Download <paramref name="fw"/> into <paramref name="destDir"/> (as its original name),
        /// reporting <paramref name="progress"/> and honoring <paramref name="ct"/>. Verifies the
        /// bytes before publishing them.
        /// </summary>
        public async Task<DownloadResult> DownloadAsync(
            KnownFirmware fw, string destDir,
            IProgress<DownloadProgress>? progress, CancellationToken ct)
        {
            ArgumentNullException.ThrowIfNull(fw);
            ArgumentException.ThrowIfNullOrWhiteSpace(destDir);

            // Fail-closed: only a customizable Door Entry entry with a URL may be fetched.
            if (!fw.IsCustomizable || string.IsNullOrWhiteSpace(fw.DownloadUrl))
                return new(DownloadOutcome.NotDownloadable, null, CoreStrings.Get("FD_NotDownloadable"));

            string finalPath = Path.Combine(destDir, fw.OriginalName);
            string partPath = finalPath + ".part";

            // Cache hit: a valid copy is already here → skip the download entirely.
            if (File.Exists(finalPath) && MatchesEntry(finalPath, fw))
                return new(DownloadOutcome.Cached, finalPath, CoreStrings.Format("FD_Cached", fw.OriginalName));

            try
            {
                Directory.CreateDirectory(destDir);
                TryDelete(partPath); // clear any leftover partial from a previous aborted run
            }
            catch (Exception ex)
            {
                return new(DownloadOutcome.IoError, null, CoreStrings.Format("FD_IoError", SafeMsg(ex)));
            }

            AsyncCompletedEventArgs? completed = null;
            try
            {
                using var service = new DownloadService(BuildConfig());
                if (progress is not null)
                {
                    service.DownloadProgressChanged += (_, e) =>
                        progress.Report(new DownloadProgress(
                            e.ReceivedBytesSize, e.TotalBytesToReceive, e.BytesPerSecondSpeed));
                }
                service.DownloadFileCompleted += (_, e) => completed = e;

                // Bridge cancellation to the service (its DownloadFileTaskAsync overloads vary by version;
                // registering CancelAsync is the portable way).
                using (ct.Register(() => service.CancelAsync()))
                {
                    await service.DownloadFileTaskAsync(fw.DownloadUrl!, partPath).ConfigureAwait(false);
                }

                if (ct.IsCancellationRequested || completed?.Cancelled == true)
                {
                    TryDelete(partPath);
                    return new(DownloadOutcome.Cancelled, null, CoreStrings.Get("FD_Cancelled"));
                }
                if (completed?.Error is { } err)
                {
                    TryDelete(partPath);
                    return new(DownloadOutcome.HttpError, null, CoreStrings.Format("FD_DownloadError", SafeMsg(err)));
                }
                if (!File.Exists(partPath))
                {
                    return new(DownloadOutcome.HttpError, null, CoreStrings.Get("FD_DownloadFailed"));
                }
            }
            catch (OperationCanceledException)
            {
                TryDelete(partPath);
                return new(DownloadOutcome.Cancelled, null, CoreStrings.Get("FD_Cancelled"));
            }
            catch (Exception ex)
            {
                TryDelete(partPath);
                return new(DownloadOutcome.HttpError, null, CoreStrings.Format("FD_DownloadError", SafeMsg(ex)));
            }

            // Verify the downloaded bytes against THIS entry (size + SHA-256).
            if (!MatchesEntry(partPath, fw))
            {
                TryDelete(partPath);
                return new(DownloadOutcome.IntegrityMismatch, null,
                    CoreStrings.Format("FD_IntegrityMismatch", fw.OriginalName));
            }

            // Atomic publish: move the verified .part into place.
            try
            {
                if (File.Exists(finalPath)) File.Delete(finalPath);
                File.Move(partPath, finalPath);
            }
            catch (Exception ex)
            {
                TryDelete(partPath);
                return new(DownloadOutcome.IoError, null, CoreStrings.Format("FD_IoError", SafeMsg(ex)));
            }

            return new(DownloadOutcome.Verified, finalPath,
                CoreStrings.Format("FD_Verified", fw.OriginalName, fw.SizeBytes));
        }

        // Size fast-path then SHA-256, checked against a SPECIFIC entry (clearer than the whole-registry
        // Verify, and a match here means the file also passes that gate).
        private static bool MatchesEntry(string path, KnownFirmware fw)
        {
            try
            {
                if (new FileInfo(path).Length != fw.SizeBytes) return false;
                using var sha = SHA256.Create();
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
                string hex = Convert.ToHexString(sha.ComputeHash(fs)); // uppercase hex
                return string.Equals(hex, fw.Sha256, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }

        private static void TryDelete(string path)
        {
            try { if (File.Exists(path)) File.Delete(path); }
            catch { /* best-effort cleanup */ }
        }

        private static string SafeMsg(Exception ex) =>
            string.IsNullOrWhiteSpace(ex.Message) ? ex.GetType().Name : ex.Message;
    }
}
