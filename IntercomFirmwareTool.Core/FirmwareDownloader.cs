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
    /// Uses the <b>Downloader</b> library for a fast multipart transfer (with a single-connection
    /// fallback; each run starts fresh — no resume), but the integrity gate is always <b>ours</b>:
    /// the downloaded bytes are verified against the <i>specific</i> entry's
    /// <see cref="KnownFirmware.SizeBytes"/> + <see cref="KnownFirmware.Sha256"/> (a clearer error than the
    /// whole-registry <see cref="FirmwareRegistry.Verify"/>), and a file that passes therefore also
    /// satisfies that gate downstream. The write is <b>atomic</b> — download to <c>&lt;name&gt;.part</c>,
    /// verify, then rename into place — so a failed/partial transfer never leaves a file that looks valid;
    /// and an already-present valid copy is a <b>cache hit</b> (no re-download).
    /// </summary>
    public sealed class FirmwareDownloader
    {
        // Transfer config. <paramref name="parallel"/> true = fast multipart (4 parallel range
        // chunks); false = a single, sequential connection. We START parallel and only fall back
        // to single if an attempt fails (see DownloadAsync), so links that support multipart keep
        // it, while endpoints that choke on concurrent range requests — the Liferay checkout links
        // intermittently serve an error page for some chunks, corrupting the assembly — are
        // downloaded reliably on a single connection. Timeout/retry use the library defaults (its
        // v5 DownloadConfiguration exposes neither as a property); our retry loop covers the rest.
        private static DownloadConfiguration BuildConfig(bool parallel) => new()
        {
            ChunkCount = parallel ? 4 : 1,
            ParallelDownload = parallel,
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

            // Cache hit: a valid copy is already here → skip the download entirely. The SHA-256
            // hash of a ~100 MB file runs on a thread-pool thread (Task.Run) so it can't freeze the
            // UI. The hash itself isn't interruptible, but cancellation is still honored: the token
            // stops the task from starting if already cancelled (caught below), and once it finishes
            // we re-check the token and return Cancelled rather than Cached.
            try
            {
                if (File.Exists(finalPath)
                    && await Task.Run(() => MatchesEntry(finalPath, fw), ct).ConfigureAwait(false))
                {
                    if (ct.IsCancellationRequested)
                        return new(DownloadOutcome.Cancelled, null, CoreStrings.Get("FD_Cancelled"));
                    return new(DownloadOutcome.Cached, finalPath, CoreStrings.Format("FD_Cached", fw.OriginalName));
                }
            }
            catch (OperationCanceledException)
            {
                return new(DownloadOutcome.Cancelled, null, CoreStrings.Get("FD_Cancelled"));
            }

            try
            {
                Directory.CreateDirectory(destDir);
            }
            catch (Exception ex)
            {
                return new(DownloadOutcome.IoError, null, CoreStrings.Format("FD_IoError", SafeMsg(ex)));
            }

            // Re-try a few times — each from a FRESH .part (never a Range resume, which some
            // endpoints reject) — so the user doesn't have to click Download repeatedly. The FIRST
            // attempt uses fast multipart; if it fails, the rest fall back to a single sequential
            // connection, which the fussy endpoints (the Liferay checkout links) serve reliably.
            // A cancel or a local IO error is final; only transport/integrity failures are retried.
            const int maxAttempts = 4;
            DownloadResult lastFailure =
                new(DownloadOutcome.HttpError, null, CoreStrings.Get("FD_DownloadFailed"));

            for (int attempt = 1; attempt <= maxAttempts; attempt++)
            {
                if (ct.IsCancellationRequested)
                {
                    CleanPartials(partPath);
                    return new(DownloadOutcome.Cancelled, null, CoreStrings.Get("FD_Cancelled"));
                }

                CleanPartials(partPath); // always start clean: a fresh, whole-file GET (no resume)
                // Multipart on the first try (keep it for links that support it); single
                // connection on the fallback tries.
                bool parallel = attempt == 1;
                DownloadResult attemptResult = await TransferOnceAsync(fw, partPath, parallel, progress, ct)
                    .ConfigureAwait(false);

                switch (attemptResult.Outcome)
                {
                    case DownloadOutcome.Verified:
                        // Honor a cancel pressed during the (thread-pool) verify hash: don't
                        // publish a file the user just cancelled.
                        if (ct.IsCancellationRequested)
                        {
                            CleanPartials(partPath);
                            return new(DownloadOutcome.Cancelled, null, CoreStrings.Get("FD_Cancelled"));
                        }
                        // The bytes are present in partPath and already verified; publish it.
                        // Move with overwrite=true is a single operation, so it can't leave the
                        // destination missing (a delete-then-move could, if the move failed) —
                        // a previously verified cached copy is only ever replaced, never lost.
                        try
                        {
                            File.Move(partPath, finalPath, overwrite: true);
                        }
                        catch (Exception ex)
                        {
                            CleanPartials(partPath);
                            return new(DownloadOutcome.IoError, null, CoreStrings.Format("FD_IoError", SafeMsg(ex)));
                        }
                        return new(DownloadOutcome.Verified, finalPath,
                            CoreStrings.Format("FD_Verified", fw.OriginalName, fw.SizeBytes));

                    case DownloadOutcome.Cancelled:
                    case DownloadOutcome.IoError:
                        // Both are final: a local filesystem error won't fix itself on retry.
                        CleanPartials(partPath);
                        return attemptResult;

                    default: // HttpError or IntegrityMismatch → remember and retry
                        lastFailure = attemptResult;
                        CleanPartials(partPath);
                        if (attempt < maxAttempts)
                        {
                            try
                            {
                                await Task.Delay(TimeSpan.FromMilliseconds(600 * attempt), ct)
                                    .ConfigureAwait(false);
                            }
                            catch (OperationCanceledException)
                            {
                                return new(DownloadOutcome.Cancelled, null, CoreStrings.Get("FD_Cancelled"));
                            }
                        }
                        break;
                }
            }

            return lastFailure;
        }

        /// <summary>
        /// One download attempt into <paramref name="partPath"/>. Returns <see cref="DownloadOutcome.Verified"/>
        /// (bytes written and checked against <paramref name="fw"/>), <see cref="DownloadOutcome.Cancelled"/>,
        /// <see cref="DownloadOutcome.HttpError"/> (transport / no file), or <see cref="DownloadOutcome.IntegrityMismatch"/>.
        /// The caller decides whether to publish, retry, or give up. On the Verified result the message is
        /// unused (the caller builds the final one), so it is left empty.
        /// <paramref name="parallel"/> picks fast multipart vs a single sequential connection.
        /// </summary>
        private static async Task<DownloadResult> TransferOnceAsync(
            KnownFirmware fw, string partPath, bool parallel,
            IProgress<DownloadProgress>? progress, CancellationToken ct)
        {
            AsyncCompletedEventArgs? completed = null;
            try
            {
                using var service = new DownloadService(BuildConfig(parallel));
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
                    return new(DownloadOutcome.Cancelled, null, CoreStrings.Get("FD_Cancelled"));
                if (completed?.Error is { } err)
                    return ClassifyTransferError(err);
                if (!File.Exists(partPath))
                    return new(DownloadOutcome.HttpError, null, CoreStrings.Get("FD_DownloadFailed"));
            }
            catch (OperationCanceledException)
            {
                return new(DownloadOutcome.Cancelled, null, CoreStrings.Get("FD_Cancelled"));
            }
            catch (Exception ex)
            {
                return ClassifyTransferError(ex);
            }

            // Verify the downloaded bytes against THIS entry (size + SHA-256).
            if (!MatchesEntry(partPath, fw))
                return new(DownloadOutcome.IntegrityMismatch, null,
                    CoreStrings.Format("FD_IntegrityMismatch", fw.OriginalName));

            return new(DownloadOutcome.Verified, partPath, string.Empty);
        }

        // A local filesystem failure (unwritable dir, disk full, locked .part) is not a transport
        // error and must NOT be retried — classify it as IoError so the loop stops and the user
        // sees a file error, not a network one. Everything else is treated as a transport failure.
        private static DownloadResult ClassifyTransferError(Exception ex) =>
            ex is IOException or UnauthorizedAccessException
                ? new(DownloadOutcome.IoError, null, CoreStrings.Format("FD_IoError", SafeMsg(ex)))
                : new(DownloadOutcome.HttpError, null, CoreStrings.Format("FD_DownloadError", SafeMsg(ex)));

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

        // Remove the partial and the Downloader library's working temp. The library streams into
        // "&lt;partPath&gt;.download" and renames it to partPath only on success, so a cancel or a
        // failure leaves that ".download" sidecar behind — delete both, so nothing lingers and a
        // later Download always starts clean (no resume).
        private static void CleanPartials(string partPath)
        {
            TryDelete(partPath);
            TryDelete(partPath + ".download");
        }

        private static string SafeMsg(Exception ex) =>
            string.IsNullOrWhiteSpace(ex.Message) ? ex.GetType().Name : ex.Message;
    }
}
