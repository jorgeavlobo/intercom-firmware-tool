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
    public sealed record FirmwareAvailability(KnownFirmware Firmware, bool Available, string Reason);

    /// <summary>
    /// Probes the official download URLs of the <b>customizable (Door Entry)</b> registry entries so
    /// the app can offer for download <b>only</b> those whose link is currently valid and online
    /// (issue #23). Each probe is a lightweight, headers-only <c>GET</c> (read the response headers,
    /// then dispose without draining the body), following redirects, and — crucially — checking that
    /// the reported length matches the registry's recorded <see cref="KnownFirmware.SizeBytes"/>. That
    /// confirms the URL still serves the <i>expected</i> file (not an HTML error page, and not a
    /// different/rotated artifact) without downloading it. A Range request is deliberately NOT used:
    /// some official endpoints (the Liferay checkout links) reject Range even though the file
    /// downloads fine, which would wrongly hide them.
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
                        return ValueTask.FromResult(delay is { } d && d > TimeSpan.Zero ? d : (TimeSpan?)null);
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
            try
            {
                HttpResponseMessage resp = await _pipeline.ExecuteAsync(async token =>
                {
                    using var req = new HttpRequestMessage(HttpMethod.Get, fw.DownloadUrl);
                    // A plain, headers-only GET (deliberately NO Range header): some official
                    // endpoints — notably the Liferay checkout links (bt_mxLiferayCheckout.jsp) —
                    // reject Range requests (403/416) even though the file downloads fine, which
                    // wrongly hid them. ResponseHeadersRead returns as soon as the headers arrive
                    // and we dispose without draining the body, so it stays just as lightweight.
                    // A browser-ish UA/Accept avoids servers that 403 an unidentified client.
                    req.Headers.UserAgent.ParseAdd("IntercomFirmwareTool");
                    req.Headers.Accept.ParseAdd("application/octet-stream, */*");
                    return await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, token)
                        .ConfigureAwait(false);
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
                // Unreachable / DNS / TLS / exhausted retries → not available.
                return new FirmwareAvailability(fw, false, CoreStrings.Format("FD_ProbeUnreachable", SafeMsg(ex)));
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
