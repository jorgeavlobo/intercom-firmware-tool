using System.Net;
using System.Net.Http.Headers;
using IntercomFirmwareTool.Core.Localization;
using Polly;
using Polly.Retry;
using Polly.Timeout;

namespace IntercomFirmwareTool.Core
{
    /// <summary>
    /// The outcome of probing a known firmware's official download URL: whether it is reachable
    /// and appears to serve the expected file. <see cref="Reason"/> is a localized explanation
    /// (available, or why not).
    /// </summary>
    public sealed record FirmwareAvailability(KnownFirmware Firmware, bool Available, string Reason)
    {
        /// <summary>
        /// True whenever the server actually answered — even with a 404/403, an HTML error page, or
        /// a size mismatch — and false only when the request never completed (DNS/TLS/connection
        /// failure, exhausted retries). Lets the UI tell "no internet" apart from "reachable but
        /// nothing to offer". An init-only property (not a positional parameter) so the record's
        /// deconstruction/positional shape stays its three core fields; defaults true so the
        /// reachable classifications don't have to set it.
        /// </summary>
        public bool Reachable { get; init; } = true;
    }

    /// <summary>
    /// Probes the official download URLs of the <b>customizable (Door Entry)</b> registry entries so
    /// the app can offer for download <b>only</b> those whose link is currently valid and online
    /// (issue #23). Each probe is a lightweight, headers-only <c>GET</c> (read the response headers,
    /// then dispose without draining the body), following redirects, and — when the server reports a
    /// length — <b>rejecting</b> any that does not match the registry's recorded
    /// <see cref="KnownFirmware.SizeBytes"/>. That catches an HTML error page or a different/rotated
    /// artifact without downloading it. A reachable endpoint that reports <i>no</i> length is still
    /// offered (it can't be size-checked here), because the download re-verifies size + SHA-256 before
    /// the file is ever used — the probe is only an availability hint, not the integrity gate. A Range
    /// request is deliberately NOT used: some official endpoints (the Liferay checkout links) reject
    /// Range even though the file downloads fine, which would wrongly hide them.
    ///
    /// Transport resilience uses <b>Polly v8</b>'s industry-standard pipeline: retry only on transient
    /// failures (network errors, per-attempt timeouts, and HTTP 408/429/5xx), with <b>exponential
    /// backoff + jitter</b>, honoring a <c>Retry-After</c> header when present, plus a per-attempt
    /// timeout. The final integrity guarantee is still the full SHA-256 verification done at
    /// <see cref="FirmwareDownloader"/> time — a probe is only an availability hint.
    /// </summary>
    public sealed class FirmwareAvailabilityChecker : IDisposable
    {
        private readonly HttpClient _http;
        private readonly bool _ownsHttp;
        private readonly ResiliencePipeline<HttpResponseMessage> _pipeline;

        /// <param name="http">
        /// Injectable for testing (stub the transport). When null, a private client is created with
        /// auto-redirect on and an infinite client timeout (Polly owns the per-attempt timeout).
        /// </param>
        public FirmwareAvailabilityChecker(HttpClient? http = null)
        {
            if (http is null)
            {
                _http = new HttpClient(new HttpClientHandler { AllowAutoRedirect = true })
                {
                    Timeout = Timeout.InfiniteTimeSpan,
                };
                _ownsHttp = true;
            }
            else
            {
                _http = http;
                _ownsHttp = false;
            }
            _pipeline = BuildPipeline();
        }

        // Upper bound on any server-supplied Retry-After we'll actually wait. This is a
        // best-effort STARTUP probe and ProbeAsync awaits every entry before exposing ANY
        // result, so a single endpoint answering 429/503 with a long Retry-After (minutes,
        // hours, or a far-future Date) must not hold the whole download list hostage. A few
        // seconds is polite enough yet keeps startup snappy; the overall wait stays bounded
        // (MaxRetryAttempts x this, plus the per-attempt timeouts).
        private static readonly TimeSpan MaxRetryDelay = TimeSpan.FromSeconds(5);

        private static ResiliencePipeline<HttpResponseMessage> BuildPipeline() =>
            new ResiliencePipelineBuilder<HttpResponseMessage>()
                // Retry (outer) wraps the per-attempt timeout (inner), so each attempt is time-bounded
                // and a timeout is itself retried.
                .AddRetry(new RetryStrategyOptions<HttpResponseMessage>
                {
                    ShouldHandle = new PredicateBuilder<HttpResponseMessage>()
                        .Handle<HttpRequestException>()
                        .Handle<TimeoutRejectedException>()
                        .HandleResult(static r => IsTransient(r.StatusCode)),
                    MaxRetryAttempts = 3,
                    BackoffType = DelayBackoffType.Exponential,
                    UseJitter = true,
                    Delay = TimeSpan.FromMilliseconds(500),
                    // Honor Retry-After (429/503) when present; otherwise fall back (null) to the
                    // exponential-with-jitter schedule above.
                    DelayGenerator = static args =>
                    {
                        RetryConditionHeaderValue? ra = args.Outcome.Result?.Headers.RetryAfter;
                        TimeSpan? delay = ra?.Delta
                            ?? (ra?.Date is { } date ? date - DateTimeOffset.UtcNow : null);
                        // Cap the honored delay (see MaxRetryDelay) so one throttled endpoint can't
                        // keep every successful probe hidden for minutes/hours.
                        TimeSpan? capped = delay is { } d && d > TimeSpan.Zero
                            ? (d < MaxRetryDelay ? d : MaxRetryDelay)
                            : null;
                        return ValueTask.FromResult(capped);
                    },
                    // Polly v8 does not dispose a handled result, so dispose the response that
                    // triggered this retry — otherwise a retried 5xx/429 leaks its socket/handler
                    // until finalization. The final (returned) response is disposed by the caller.
                    OnRetry = static args =>
                    {
                        args.Outcome.Result?.Dispose();
                        return default;
                    },
                })
                .AddTimeout(TimeSpan.FromSeconds(10))
                .Build();

        // Transient HTTP status codes worth a retry.
        private static bool IsTransient(HttpStatusCode s) => s is
            HttpStatusCode.RequestTimeout           // 408
            or HttpStatusCode.TooManyRequests       // 429
            or HttpStatusCode.InternalServerError   // 500
            or HttpStatusCode.BadGateway            // 502
            or HttpStatusCode.ServiceUnavailable    // 503
            or HttpStatusCode.GatewayTimeout;       // 504

        /// <summary>
        /// Probe every customizable (Door Entry) entry that has a download URL, in parallel. Returns
        /// one <see cref="FirmwareAvailability"/> per entry. Honors <paramref name="ct"/>.
        /// </summary>
        public async Task<IReadOnlyList<FirmwareAvailability>> ProbeAsync(CancellationToken ct = default)
        {
            var targets = FirmwareRegistry.Known
                .Where(k => k.IsCustomizable && !string.IsNullOrWhiteSpace(k.DownloadUrl))
                .ToList();
            var results = await Task.WhenAll(targets.Select(fw => ProbeOneAsync(fw, ct)))
                .ConfigureAwait(false);
            return results;
        }

        private async Task<FirmwareAvailability> ProbeOneAsync(KnownFirmware fw, CancellationToken ct)
        {
            // ProbeAsync only ever queues entries with a non-empty DownloadUrl; capture it as a
            // non-null local so the contract is explicit at the single use site (and nullability
            // is satisfied without warnings).
            string url = fw.DownloadUrl!;
            // Flipped inside the pipeline callback the instant ANY attempt gets a response — even a
            // retryable 5xx that Polly will retry — so the catch below can tell a pure transport
            // failure (no response ever — genuinely unreachable) from a server that DID answer
            // (reachable, just not usable, or a later retry/Classify fault). Setting it only AFTER
            // the whole pipeline returns would miss the "503 then the retry fails at the transport
            // layer" case, where ExecuteAsync throws and the server would be mis-reported as offline.
            bool responseReceived = false;
            try
            {
                HttpResponseMessage resp = await _pipeline.ExecuteAsync(async token =>
                {
                    using var req = new HttpRequestMessage(HttpMethod.Get, url);
                    // A plain, headers-only GET (deliberately NO Range header): some official
                    // endpoints — notably the Liferay checkout links (bt_mxLiferayCheckout.jsp) —
                    // reject Range requests (403/416) even though the file downloads fine, which
                    // wrongly hid them. ResponseHeadersRead returns as soon as the headers arrive
                    // and we dispose without draining the body, so it stays just as lightweight.
                    // A browser-ish UA/Accept avoids servers that 403 an unidentified client.
                    req.Headers.UserAgent.ParseAdd("IntercomFirmwareTool");
                    req.Headers.Accept.ParseAdd("application/octet-stream, */*");
                    HttpResponseMessage attempt = await _http
                        .SendAsync(req, HttpCompletionOption.ResponseHeadersRead, token)
                        .ConfigureAwait(false);
                    responseReceived = true; // this attempt got a response (even if it's retried)
                    return attempt;
                }, ct).ConfigureAwait(false);

                using (resp)
                {
                    return Classify(fw, resp);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw; // caller cancelled the whole probe — propagate
            }
            catch (Exception ex)
            {
                // Not available. Reachable only if a response had already come back (a fault inside
                // Classify) — a transport/DNS/TLS/timeout failure never answered, so the UI can
                // attribute THAT to connectivity, but not a post-response local error.
                return new FirmwareAvailability(
                    fw, false, CoreStrings.Format("FD_ProbeUnreachable", SafeMsg(ex)))
                { Reachable = responseReceived };
            }
        }

        private static FirmwareAvailability Classify(KnownFirmware fw, HttpResponseMessage r)
        {
            if (r.StatusCode is not (HttpStatusCode.OK or HttpStatusCode.PartialContent))
                return new(fw, false, CoreStrings.Format("FD_ProbeHttpStatus", (int)r.StatusCode));

            // An HTML body served with 200 is a login/error page, not the firmware.
            string? mediaType = r.Content.Headers.ContentType?.MediaType;
            if (mediaType is not null && mediaType.Contains("html", StringComparison.OrdinalIgnoreCase))
                return new(fw, false, CoreStrings.Get("FD_ProbeNotFirmware"));

            // Resolve the full length from Content-Length (a Content-Range total is still
            // honored if some server sends one). Null when the server streams chunked.
            long? total = r.Content.Headers.ContentRange?.Length ?? r.Content.Headers.ContentLength;
            if (total is { } len && len != fw.SizeBytes)
                return new(fw, false, CoreStrings.Format("FD_ProbeSizeMismatch", fw.SizeBytes, len));

            // Reachable, right size (or size unknown but reachable) → offer it; the download re-verifies.
            return new(fw, true, CoreStrings.Get("FD_ProbeAvailable"));
        }

        private static string SafeMsg(Exception ex) =>
            string.IsNullOrWhiteSpace(ex.Message) ? ex.GetType().Name : ex.Message;

        public void Dispose()
        {
            if (_ownsHttp) _http.Dispose();
        }
    }
}
