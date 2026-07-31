using System.ComponentModel; // AsyncCompletedEventArgs
using System.Diagnostics;    // Stopwatch (transfer-rate for the owned single-stream fallback)
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
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
        private readonly Func<string> _message;

        /// <summary>
        /// The localized outcome message, regenerated in the current UI culture on each access
        /// (like <see cref="FirmwareCheckResult"/>) — so a language switch after a download
        /// re-localizes it. Any non-localizable detail (an exception's text) is captured once by
        /// the factory; the surrounding localized prefix still re-resolves.
        /// </summary>
        public string Message => _message();

        public DownloadResult(DownloadOutcome outcome, string? path, Func<string> message)
        {
            Outcome = outcome;
            Path = path;
            _message = message;
        }

        public bool Ok => Outcome is DownloadOutcome.Verified or DownloadOutcome.Cached;
    }

    /// <summary>
    /// Fetches an official firmware from its registry <see cref="KnownFirmware.DownloadUrl"/> and
    /// guarantees the result is a byte-for-byte known-good original before it can be used (issue #23).
    ///
    /// Uses the <b>Downloader</b> library for a fast multipart transfer on the first attempt, then
    /// falls back to our <b>own single-connection stream</b> that enforces the known size at the
    /// write boundary (a hard cap — see <see cref="TransferSingleCappedAsync"/>); each run starts
    /// fresh — no resume. The integrity gate is always <b>ours</b>:
    /// the downloaded bytes are verified against the <i>specific</i> entry's
    /// <see cref="KnownFirmware.SizeBytes"/> + <see cref="KnownFirmware.Sha256"/> (a clearer error than the
    /// whole-registry <see cref="FirmwareRegistry.Verify"/>), and a file that passes therefore also
    /// satisfies that gate downstream. The write is <b>atomic</b> — download to <c>&lt;name&gt;.part</c>,
    /// verify, then rename into place — so a failed/partial transfer never leaves a file that looks valid;
    /// and an already-present valid copy is a <b>cache hit</b> (no re-download).
    /// </summary>
    public sealed class FirmwareDownloader
    {
        // Fast multipart config for the FIRST attempt (4 parallel range chunks). Endpoints that
        // support ranges send a Content-Length, so the library requests exact byte ranges and can't
        // overrun; the fallback attempts use our own single-connection stream instead (see
        // TransferSingleCappedAsync), which both serves the range-hostile Liferay checkout links
        // reliably AND enforces the size cap at the write boundary. Timeout/retry use the library
        // defaults (its v5 DownloadConfiguration exposes neither as a property); our retry loop
        // covers the rest.
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

        // Shared client for the owned single-connection fallback stream. Static (process-lifetime,
        // never disposed) is the recommended HttpClient pattern; we bound each transfer with the
        // CancellationToken rather than a wall-clock timeout.
        private static readonly HttpClient _http =
            new(new HttpClientHandler { AllowAutoRedirect = true }) { Timeout = Timeout.InfiniteTimeSpan };

        // Inactivity timeout for the owned fallback stream: since _http has no wall-clock timeout (we
        // bound with the token), a server that accepts the request then stalls — no header or body
        // bytes — would otherwise hang until the user cancels. If nothing arrives for this long, abort
        // the attempt as a RETRYABLE transport failure so the retry loop moves on.
        private static readonly TimeSpan InactivityTimeout = TimeSpan.FromSeconds(30);

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
                return new(DownloadOutcome.NotDownloadable, null, () => CoreStrings.Get("FD_NotDownloadable"));

            try
            {
                Directory.CreateDirectory(destDir);
            }
            catch (Exception ex)
            {
                return new(DownloadOutcome.IoError, null, () => CoreStrings.Format("FD_IoError", SafeMsg(ex)));
            }

            // Scan the folder for THIS firmware: reuse an already-verified copy — the canonical name
            // OR a "<name> (n)" sibling — as a cache hit (so repeated downloads don't pile up
            // duplicate copies), otherwise take the first FREE name as the target (never overwriting
            // an unrelated file that holds the name). The SHA-256 hashing runs off the UI thread so
            // it can't freeze the UI, and it observes the token — the scan checks between candidates
            // and reads each file with cancellable async I/O — so a Cancel pressed while a slow or
            // stalled/networked destination with many same-size candidates is being hashed stops
            // promptly instead of sitting at "Cancelling…". A cancel surfaces as
            // OperationCanceledException, caught below.
            string finalPath;
            try
            {
                // WaitAsync(ct) makes the OUTER wait cancellable too: a synchronous filesystem call
                // inside the scan (enumeration MoveNext, FileInfo.Length) can stall on a dead network
                // share where the scan's own inner token checks can't run and Task.Run's token can't
                // stop a delegate already started — so without this, Cancel would hang the UI. The
                // orphaned background scan finishes when the share recovers; its result is dropped.
                var scan = await Task.Run(() => ScanDestinationAsync(destDir, fw, ct), ct)
                    .WaitAsync(ct).ConfigureAwait(false);
                if (scan.CachedPath is string hit)
                {
                    if (ct.IsCancellationRequested)
                        return new(DownloadOutcome.Cancelled, null, () => CoreStrings.Get("FD_Cancelled"));
                    return new(DownloadOutcome.Cached, hit,
                        () => CoreStrings.Format("FD_Cached", Path.GetFileName(hit)));
                }
                finalPath = scan.FreeTarget;
            }
            catch (OperationCanceledException)
            {
                return new(DownloadOutcome.Cancelled, null, () => CoreStrings.Get("FD_Cancelled"));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // The destination folder couldn't be fully enumerated (a network share went away, an
                // ACL denial). Don't proceed on a partial view of what's there — report a file error.
                return new(DownloadOutcome.IoError, null, () => CoreStrings.Format("FD_IoError", SafeMsg(ex)));
            }

            // Re-try a few times — each from a FRESH, exclusively-OWNED .part (a GUID name, never a
            // Range resume some endpoints reject) — so the user doesn't have to click Download
            // repeatedly. A per-attempt path means a cleanup that fails (AV/lock) can never leave the
            // NEXT attempt starting from a dirty file, and the finally removes every temp we created.
            // The FIRST attempt uses fast multipart (the library); the rest fall back to our own
            // single-connection capped stream, which the fussy endpoints (the Liferay checkout links)
            // serve reliably and which can't overrun the disk.
            // A cancel or a local IO error is final; only transport/integrity failures are retried.
            const int maxAttempts = 4;
            DownloadResult lastFailure =
                new(DownloadOutcome.HttpError, null, () => CoreStrings.Get("FD_DownloadFailed"));
            var usedParts = new List<string>();
            try
            {
                for (int attempt = 1; attempt <= maxAttempts; attempt++)
                {
                    if (ct.IsCancellationRequested)
                        return new(DownloadOutcome.Cancelled, null, () => CoreStrings.Get("FD_Cancelled"));

                    string partPath = Path.Combine(destDir, $".ift-{Guid.NewGuid():N}.part");
                    usedParts.Add(partPath);
                    // First attempt: fast multipart via the library (range-supporting CDNs, which
                    // send a Content-Length so it can't overrun). Fallback attempts: our OWN
                    // single-connection stream with a hard write-boundary size cap, which both serves
                    // the range-hostile Liferay links reliably and can't be made to overrun the disk.
                    DownloadResult attemptResult = attempt == 1
                        ? await TransferOnceAsync(fw, partPath, progress, ct).ConfigureAwait(false)
                        : await TransferSingleCappedAsync(fw, partPath, progress, ct).ConfigureAwait(false);

                    switch (attemptResult.Outcome)
                    {
                        case DownloadOutcome.Verified:
                            // Honor a cancel pressed during the (thread-pool) verify hash: don't
                            // publish a file the user just cancelled.
                            if (ct.IsCancellationRequested)
                                return new(DownloadOutcome.Cancelled, null, () => CoreStrings.Get("FD_Cancelled"));
                            // The bytes are present in partPath and already verified; publish them
                            // (handling a concurrent process that grabbed the target name first).
                            return await PublishVerifiedAsync(partPath, finalPath, destDir, fw, ct)
                                .ConfigureAwait(false);

                        case DownloadOutcome.Cancelled:
                        case DownloadOutcome.IoError:
                            // Both are final: a local filesystem error won't fix itself on retry.
                            return attemptResult;

                        default: // HttpError or IntegrityMismatch → remember and retry
                            lastFailure = attemptResult;
                            CleanPartials(partPath); // free this attempt's temp now (finally is a backstop)
                            if (attempt < maxAttempts)
                            {
                                try
                                {
                                    await Task.Delay(TimeSpan.FromMilliseconds(600 * attempt), ct)
                                        .ConfigureAwait(false);
                                }
                                catch (OperationCanceledException)
                                {
                                    return new(DownloadOutcome.Cancelled, null, () => CoreStrings.Get("FD_Cancelled"));
                                }
                            }
                            break;
                    }
                }

                return lastFailure;
            }
            finally
            {
                // Best-effort backstop: remove every temp this operation created, so no orphaned
                // .ift-*.part / .part.download is left behind on any exit path. The Verified one was
                // renamed to finalPath by File.Move, so cleaning its old name is a harmless no-op.
                foreach (string p in usedParts) CleanPartials(p);
            }
        }

        /// <summary>
        /// The fast <b>multipart</b> attempt via the Downloader library, into <paramref name="partPath"/>.
        /// Returns <see cref="DownloadOutcome.Verified"/> (bytes written and checked against
        /// <paramref name="fw"/>), <see cref="DownloadOutcome.Cancelled"/>,
        /// <see cref="DownloadOutcome.HttpError"/> (transport / no file), or <see cref="DownloadOutcome.IntegrityMismatch"/>.
        /// The caller decides whether to publish, retry, or give up. On the Verified result the message is
        /// unused (the caller builds the final one), so it is left empty. The single-connection fallback is
        /// <see cref="TransferSingleCappedAsync"/>.
        /// </summary>
        private static async Task<DownloadResult> TransferOnceAsync(
            KnownFirmware fw, string partPath,
            IProgress<DownloadProgress>? progress, CancellationToken ct)
        {
            AsyncCompletedEventArgs? completed = null;
            bool oversize = false;
            try
            {
                using var service = new DownloadService(BuildConfig());
                service.DownloadProgressChanged += (_, e) =>
                {
                    // Backstop size guard for the multipart path: a range-supporting endpoint sends a
                    // Content-Length so the library requests exact bytes and shouldn't overrun, but if
                    // one lies, abort the instant we exceed the exact expected size rather than write
                    // on. (The strict, write-boundary cap lives in the single-stream fallback.)
                    if (!oversize && fw.SizeBytes > 0 && e.ReceivedBytesSize > fw.SizeBytes)
                    {
                        oversize = true;
                        service.CancelAsync();
                    }
                    // Some endpoints (the Liferay checkout links) don't send a Content-Length,
                    // so the library reports total 0 and the bar can't fill. We already KNOW the
                    // exact size from the registry — fall back to it so the percentage shows.
                    // Safe: the bytes are verified against this same size on completion.
                    progress?.Report(new DownloadProgress(
                        e.ReceivedBytesSize,
                        e.TotalBytesToReceive > 0 ? e.TotalBytesToReceive : fw.SizeBytes,
                        e.BytesPerSecondSpeed));
                };
                service.DownloadFileCompleted += (_, e) => completed = e;

                // Bridge cancellation to the service (its DownloadFileTaskAsync overloads vary by version;
                // registering CancelAsync is the portable way). The callback must be fail-safe — a throw
                // here (e.g. a dispose/race in the library) would propagate out of cancellation.
                using (ct.Register(() => { try { service.CancelAsync(); } catch { /* best-effort cancel */ } }))
                {
                    await service.DownloadFileTaskAsync(fw.DownloadUrl!, partPath).ConfigureAwait(false);
                }

                // An oversize abort is NOT a user cancel (which is final): the endpoint overran the
                // known size, so treat it as an integrity failure the retry loop can re-attempt.
                // Check it before the cancel branch, since aborting sets completed.Cancelled too.
                if (oversize)
                    return new(DownloadOutcome.IntegrityMismatch, null,
                        () => CoreStrings.Format("FD_IntegrityOversize", fw.OriginalName, fw.SizeBytes));
                if (ct.IsCancellationRequested || completed?.Cancelled == true)
                    return new(DownloadOutcome.Cancelled, null, () => CoreStrings.Get("FD_Cancelled"));
                if (completed?.Error is { } err)
                    return ClassifyTransferError(err);
                if (!File.Exists(partPath))
                    return new(DownloadOutcome.HttpError, null, () => CoreStrings.Get("FD_DownloadFailed"));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                // Only a cancel the CALLER requested is a real cancellation; a transport-thrown
                // OperationCanceledException (e.g. an HTTP timeout while ct is still active) is a
                // transport failure that should be retried, so let it fall through below.
                return new(DownloadOutcome.Cancelled, null, () => CoreStrings.Get("FD_Cancelled"));
            }
            catch (Exception ex)
            {
                return ClassifyTransferError(ex);
            }

            // Verify the downloaded bytes against THIS entry (size + SHA-256). Distinguish a
            // genuine content mismatch from an IO error reading the .part (locked / ACL / disk):
            // the latter is a final IoError, not something a re-download would fix.
            try
            {
                var v = await VerifyEntryAsync(partPath, fw, ct).ConfigureAwait(false);
                if (v.Outcome == VerifyOutcome.SizeMismatch)
                {
                    long actual = v.ActualSize; // capture for the re-localizing message factory
                    return new(DownloadOutcome.IntegrityMismatch, null,
                        () => CoreStrings.Format("FD_IntegritySize", fw.OriginalName, actual, fw.SizeBytes));
                }
                if (v.Outcome == VerifyOutcome.HashMismatch)
                {
                    string got = ShortHash(v.ActualHash), want = ShortHash(fw.Sha256);
                    return new(DownloadOutcome.IntegrityMismatch, null,
                        () => CoreStrings.Format("FD_IntegrityHash", fw.OriginalName, got, want));
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                // Cancelled mid-verify (the hash reads in cancellable chunks) — report it as such,
                // not as an integrity/IO failure.
                return new(DownloadOutcome.Cancelled, null, () => CoreStrings.Get("FD_Cancelled"));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                return new(DownloadOutcome.IoError, null, () => CoreStrings.Format("FD_IoError", SafeMsg(ex)));
            }

            return new(DownloadOutcome.Verified, partPath, () => string.Empty);
        }

        /// <summary>
        /// The single-connection fallback: a plain sequential GET (no Range — the Liferay checkout
        /// links reject it) that WE stream ourselves, so the known registry size is enforced at the
        /// <b>write boundary</b> — the industry-standard hard cap for an untrusted download: the
        /// moment more than <see cref="KnownFirmware.SizeBytes"/> bytes arrive we stop, so the file on
        /// disk can never exceed it (no reliance on an async cancel racing the writer). The SHA-256 is
        /// computed inline as we write, so there is no second pass over the file. Same result contract
        /// as <see cref="TransferOnceAsync"/>.
        /// </summary>
        private static async Task<DownloadResult> TransferSingleCappedAsync(
            KnownFirmware fw, string partPath,
            IProgress<DownloadProgress>? progress, CancellationToken ct)
        {
            // tk = the user token PLUS an inactivity deadline (re-armed on every network wait via
            // CancelAfter). It bounds the header wait and each body read; the file ops keep the plain
            // user token (ct), so a slow disk isn't mistaken for a network stall.
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            CancellationToken tk = timeoutCts.Token;
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, fw.DownloadUrl!);
                req.Headers.UserAgent.ParseAdd("IntercomFirmwareTool");
                req.Headers.Accept.ParseAdd("application/octet-stream, */*");
                timeoutCts.CancelAfter(InactivityTimeout); // arm for the header wait
                using var resp = await _http
                    .SendAsync(req, HttpCompletionOption.ResponseHeadersRead, tk).ConfigureAwait(false);
                // Headers have arrived — disarm before the LOCAL work below (get the body stream,
                // open the temp file). A slow disk opening the FileStream must not trip the network
                // clock and cancel tk before the first body read; the loop re-arms per read.
                timeoutCts.CancelAfter(Timeout.InfiniteTimeSpan);
                if (!resp.IsSuccessStatusCode)
                    // Read as a DOWNLOAD failure (not a probe result): wrap the HTTP-status detail in
                    // the download-error prefix so the message is consistent with the other outcomes.
                    return new(DownloadOutcome.HttpError, null,
                        () => CoreStrings.Format("FD_DownloadError",
                            CoreStrings.Format("FD_ProbeHttpStatus", (int)resp.StatusCode)));

                long expected = fw.SizeBytes;
                // For the % bar: prefer a sane Content-Length, else the known registry size.
                long barTotal = resp.Content.Headers.ContentLength is long cl && cl > 0 ? cl : expected;

                using var body = await resp.Content.ReadAsStreamAsync(tk).ConfigureAwait(false);

                // Creating/writing/flushing the destination is a LOCAL op — wrap those so their
                // failures classify as a final IoError, distinct from a transport IOException on the
                // network body read below (which the retry loop can and should re-attempt).
                FileStream file;
                try
                {
                    file = new FileStream(partPath, FileMode.Create, FileAccess.Write, FileShare.None,
                        bufferSize: 1 << 20, options: FileOptions.Asynchronous | FileOptions.SequentialScan);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    throw new LocalIoException(ex);
                }

                using (file)
                using (var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
                {
                    byte[] buffer = new byte[1 << 20]; // 1 MiB
                    long received = 0;
                    long startTs = Stopwatch.GetTimestamp();
                    while (true)
                    {
                        timeoutCts.CancelAfter(InactivityTimeout); // arm only for the network read
                        int read = await body.ReadAsync(buffer.AsMemory(0, buffer.Length), tk).ConfigureAwait(false);
                        // Disarm the instant the read returns, so the LOCAL write/hash below aren't
                        // under the network clock — a slow disk taking >InactivityTimeout on a 1 MiB
                        // write must not cancel tk and get mis-reported as a network stall.
                        timeoutCts.CancelAfter(Timeout.InfiniteTimeSpan);
                        if (read <= 0) break;

                        // HARD write-boundary cap: if this chunk would push the file past the known
                        // size, stop before writing it — the .part can never exceed `expected` on disk.
                        if (expected > 0 && received + read > expected)
                            return new(DownloadOutcome.IntegrityMismatch, null,
                                () => CoreStrings.Format("FD_IntegrityOversize", fw.OriginalName, expected));

                        try
                        {
                            await file.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                        }
                        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                        {
                            throw new LocalIoException(ex);
                        }
                        sha.AppendData(buffer, 0, read);
                        received += read;

                        double secs = (Stopwatch.GetTimestamp() - startTs) / (double)Stopwatch.Frequency;
                        progress?.Report(new DownloadProgress(received, barTotal, secs > 0 ? received / secs : 0));
                    }

                    try
                    {
                        await file.FlushAsync(ct).ConfigureAwait(false);
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        throw new LocalIoException(ex);
                    }

                    // Verify inline (no re-read): a short read means a truncated transfer; then the hash.
                    if (received != expected)
                        return new(DownloadOutcome.IntegrityMismatch, null,
                            () => CoreStrings.Format("FD_IntegritySize", fw.OriginalName, received, expected));
                    string hex = Convert.ToHexString(sha.GetHashAndReset()); // uppercase hex
                    if (!string.Equals(hex, fw.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        string got = ShortHash(hex), want = ShortHash(fw.Sha256);
                        return new(DownloadOutcome.IntegrityMismatch, null,
                            () => CoreStrings.Format("FD_IntegrityHash", fw.OriginalName, got, want));
                    }
                    return new(DownloadOutcome.Verified, partPath, () => string.Empty);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return new(DownloadOutcome.Cancelled, null, () => CoreStrings.Get("FD_Cancelled"));
            }
            catch (OperationCanceledException)
            {
                // Not the user's cancel (ct isn't set) → the inactivity deadline fired: the server
                // stalled. A retryable transport failure, so the loop moves to the next attempt.
                return new(DownloadOutcome.HttpError, null, () => CoreStrings.Get("FD_DownloadFailed"));
            }
            catch (LocalIoException lex)
            {
                // A local file failure (disk full, ACL, lock) — final; a re-download won't fix it.
                return new(DownloadOutcome.IoError, null,
                    () => CoreStrings.Format("FD_IoError", SafeMsg(lex.InnerException ?? lex)));
            }
            catch (Exception ex)
            {
                // Everything else — including a network IOException/HttpIOException on the body read
                // (reset/truncated) — is a TRANSPORT failure the retry loop can re-attempt.
                return new(DownloadOutcome.HttpError, null,
                    () => CoreStrings.Format("FD_DownloadError", SafeMsg(ex)));
            }
        }

        // Marks a LOCAL file-operation failure inside TransferSingleCappedAsync, so the handler can
        // classify it as a final IoError — distinct from a transport IOException on the body read.
        private sealed class LocalIoException(Exception inner) : Exception(inner.Message, inner);

        // Publish the verified .part into finalPath. Normally a plain Move (finalPath was chosen free
        // and Move refuses to overwrite, so nothing is clobbered). If ANOTHER process grabbed the
        // name first — a concurrent download of the same firmware into the same folder — re-scan and
        // either accept their identical, verified copy as a cache hit, or move into a fresh free name
        // instead of throwing away our fully-verified transfer as an IoError.
        private static async Task<DownloadResult> PublishVerifiedAsync(
            string partPath, string finalPath, string destDir, KnownFirmware fw, CancellationToken ct)
        {
            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    File.Move(partPath, finalPath); // refuses to overwrite → atomic publish
                    return new(DownloadOutcome.Verified, finalPath,
                        () => CoreStrings.Format("FD_Verified", Path.GetFileName(finalPath), fw.SizeBytes));
                }
                catch (IOException) when (File.Exists(finalPath) || Directory.Exists(finalPath))
                {
                    // The name was taken between the scan and now. Re-scan: a verified match is a
                    // cache hit (someone published the identical file); else take a fresh free target
                    // and try the move again. Classify a rescan failure here — an exception thrown
                    // inside this catch would otherwise escape past the sibling catches below.
                    try
                    {
                        var scan = await ScanDestinationAsync(destDir, fw, ct).ConfigureAwait(false);
                        if (scan.CachedPath is string hit)
                            return new(DownloadOutcome.Cached, hit,
                                () => CoreStrings.Format("FD_Cached", Path.GetFileName(hit)));
                        finalPath = scan.FreeTarget;
                    }
                    catch (OperationCanceledException) when (ct.IsCancellationRequested)
                    {
                        return new(DownloadOutcome.Cancelled, null, () => CoreStrings.Get("FD_Cancelled"));
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        return new(DownloadOutcome.IoError, null, () => CoreStrings.Format("FD_IoError", SafeMsg(ex)));
                    }
                }
                catch (Exception ex)
                {
                    return new(DownloadOutcome.IoError, null, () => CoreStrings.Format("FD_IoError", SafeMsg(ex)));
                }
            }
            // Kept colliding across re-scans (pathological) → give up rather than loop forever.
            return new(DownloadOutcome.IoError, null, () => CoreStrings.Get("FD_PublishFailed"));
        }

        // A local filesystem failure (unwritable dir, disk full, locked .part) is not a transport
        // error and must NOT be retried — classify it as IoError so the loop stops and the user
        // sees a file error, not a network one. Everything else is treated as a transport failure.
        private static DownloadResult ClassifyTransferError(Exception ex) =>
            ex is IOException or UnauthorizedAccessException
                ? new(DownloadOutcome.IoError, null, () => CoreStrings.Format("FD_IoError", SafeMsg(ex)))
                : new(DownloadOutcome.HttpError, null, () => CoreStrings.Format("FD_DownloadError", SafeMsg(ex)));

        // Size fast-path then SHA-256, checked against a SPECIFIC entry (clearer than the
        // whole-registry Verify, and a match here means the file also passes that gate). Throws on
        // an IO error reading the file — the caller decides whether that means "not a match" or a
        // hard IoError.
        // Which check a file failed against an entry, so callers can report WHY (size vs content)
        // instead of one generic message.
        private enum VerifyOutcome { Match, SizeMismatch, HashMismatch }

        // Size fast-path then SHA-256, against a SPECIFIC entry. Returns which check failed plus the
        // ACTUAL size and (when it got as far as hashing) the actual hash, so the caller can build a
        // diagnosable message — a size mismatch usually means a truncated download or an HTML error
        // page, a hash mismatch means same-size but different content. Throws on an IO error reading
        // the file (the caller decides what that means) and on cancellation.
        private static async Task<(VerifyOutcome Outcome, long ActualSize, string? ActualHash)> VerifyEntryAsync(
            string path, KnownFirmware fw, CancellationToken ct)
        {
            long actualSize = new FileInfo(path).Length;
            if (actualSize != fw.SizeBytes) return (VerifyOutcome.SizeMismatch, actualSize, null);
            using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            // Open async + sequential so ReadAsync observes the token: a Cancel interrupts a read
            // that's blocked on a stalled/slow network share, instead of leaving the UI at
            // "Cancelling…" until the filesystem operation times out.
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read,
                bufferSize: 1 << 20, options: FileOptions.Asynchronous | FileOptions.SequentialScan);
            byte[] buffer = new byte[1 << 20]; // 1 MiB
            int read;
            while ((read = await fs.ReadAsync(buffer.AsMemory(0, buffer.Length), ct).ConfigureAwait(false)) > 0)
                sha.AppendData(buffer, 0, read);
            string hex = Convert.ToHexString(sha.GetHashAndReset()); // uppercase hex
            return string.Equals(hex, fw.Sha256, StringComparison.OrdinalIgnoreCase)
                ? (VerifyOutcome.Match, actualSize, hex)
                : (VerifyOutcome.HashMismatch, actualSize, hex);
        }

        // Bool wrapper for the cache-hit scan: any mismatch — or an unreadable file — is just "no
        // match" (download it). A cancel, however, must NOT be read as "no match" (that would keep
        // scanning) — let it propagate so the scan stops.
        private static async Task<bool> MatchesEntryAsync(string path, KnownFirmware fw, CancellationToken ct)
        {
            try { return (await VerifyEntryAsync(path, fw, ct).ConfigureAwait(false)).Outcome == VerifyOutcome.Match; }
            catch (OperationCanceledException) { throw; }
            catch { return false; }
        }

        // First 12 hex chars of a SHA-256, for a compact, human-diffable message (never the full 64).
        private static string ShortHash(string? hash) =>
            string.IsNullOrEmpty(hash) ? "?" : (hash.Length <= 12 ? hash : hash[..12]);

        // Consider the canonical name and every "<name> (n).fwz" sibling, and decide where THIS
        // firmware goes:
        //   • an existing candidate that VERIFIES as this entry → a cache hit (reuse it, no
        //     re-download), so clicking Download repeatedly never piles up duplicate copies;
        //   • otherwise the first name that does NOT exist → the free target to download into (so an
        //     unrelated file holding one of these names is never overwritten).
        // The existing siblings are found by enumerating the folder ONCE and matching the exact
        // pattern, so every numbered copy is considered no matter how large the gaps in the
        // numbering are (a lone "(16)" left after "(0)"–"(15)" were deleted is still reused).
        // Hashing happens here (call it off the UI thread).
        private static async Task<(string? CachedPath, string FreeTarget)> ScanDestinationAsync(
            string destDir, KnownFirmware fw, CancellationToken ct)
        {
            string baseName = Path.GetFileNameWithoutExtension(fw.OriginalName);
            string ext = Path.GetExtension(fw.OriginalName);

            // Which candidate indices are already taken on disk (0 = the canonical name; n = "(n)").
            // Enumerate file-system ENTRIES, not just files: a *directory* named like a candidate
            // (e.g. a "C100X_010508.fwz" folder) also occupies that name — File.Move onto it would
            // fail, and only after a full 100-300 MB transfer — so it must be skipped as a target
            // too. Such an entry never becomes a cache hit: MatchesEntryAsync can't hash a directory.
            // Enumerate the folder ONCE. Don't swallow a failure here (a network share going away, an
            // ACL denial): continuing with a PARTIAL set could miss a cached copy or pick a name
            // that's actually taken — wasting a full transfer before File.Move fails. Let it
            // propagate so DownloadAsync reports it as an IoError instead of scanning blind.
            // Keep the ACTUAL enumerated path with each parsed index — don't reconstruct a candidate
            // name from baseName/ext later. The reconstructed form can differ from what's on disk
            // (a zero-padded "(01)" the regex normalizes to 1, or a differently-cased canonical name
            // on a case-sensitive filesystem), which would hash a non-existent path and MISS a valid
            // 100-300 MB cache copy.
            var candidates = new List<(int Index, string Path)>();
            var rx = new Regex(
                "^" + Regex.Escape(baseName) + @" \((\d+)\)" + Regex.Escape(ext) + "$",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            foreach (string path in Directory.EnumerateFileSystemEntries(destDir))
            {
                // Check between entries so a Cancel is responsive even on a large or slow network
                // folder (the enumeration is lazy; Task.Run's token can't stop it once started).
                ct.ThrowIfCancellationRequested();
                string name = Path.GetFileName(path);
                if (string.Equals(name, fw.OriginalName, StringComparison.OrdinalIgnoreCase))
                    candidates.Add((0, path));
                else if (rx.Match(name) is { Success: true } m
                         && int.TryParse(m.Groups[1].Value, out int n) && n > 0)
                    candidates.Add((n, path));
            }

            // Reuse a verified copy if one exists — verify the REAL enumerated path, in ascending
            // index order so the reused file is the most canonical available.
            foreach (var (_, path) in candidates.OrderBy(static c => c.Index))
            {
                ct.ThrowIfCancellationRequested(); // stop between candidates so Cancel is responsive
                if (await MatchesEntryAsync(path, fw, ct).ConfigureAwait(false))
                    return (path, path);
            }

            // No verified copy anywhere → download into the first free NAME (smallest unused index),
            // never overwriting an existing (unrelated) file.
            var occupied = new HashSet<int>(candidates.Select(static c => c.Index));
            int free = 0;
            while (occupied.Contains(free)) free++;
            string target = free == 0
                ? Path.Combine(destDir, fw.OriginalName)
                : Path.Combine(destDir, $"{baseName} ({free}){ext}");
            return (null, target);
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
