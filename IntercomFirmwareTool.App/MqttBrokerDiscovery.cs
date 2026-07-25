using System;
using System.Collections.Generic;
using System.IO;                                 // Stream (plaintext or TLS-wrapped probe)
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;                       // SslStream (confirm an 8883 TLS broker)
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace IntercomFirmwareTool.App
{
    /// <summary>A broker found on the LAN. <see cref="Hostname"/> is the advertised
    /// name (mDNS) or a reverse-DNS name (scan), or null when only an IP is known.
    /// <see cref="IsTls"/> records the transport EXPLICITLY (set by the discovery method
    /// that confirmed it), rather than inferring it from the port number.</summary>
    public sealed record BrokerCandidate(string? Hostname, string Ip, int Port, bool IsTls = false);

    /// <summary>
    /// Best-effort discovery of MQTT brokers on the local network, with NO external
    /// dependency (issue #43, follow-up 2):
    /// <list type="bullet">
    /// <item><b>mDNS</b> — a hand-rolled <c>_mqtt._tcp.local</c> query (unicast-response
    /// bit set) parsed for PTR/SRV/A records, giving <c>(hostname, IPv4, port)</c> directly.
    /// Cheap and passive; run at startup.</item>
    /// <item><b>/24 scan</b> — a heavier fallback: TCP-probe every host on each active LAN
    /// /24, confirm a broker with a real MQTT CONNECT/CONNACK — over a TLS handshake on 8883
    /// — then reverse-DNS the address. Run on demand only.</item>
    /// </list>
    /// Everything here is best-effort and swallows all errors — discovery failing must never
    /// disrupt the app; it simply yields no candidates.
    /// </summary>
    public sealed class MqttBrokerDiscovery
    {
        private static readonly IPAddress MdnsGroup = IPAddress.Parse("224.0.0.251");
        private const int MdnsPort = 5353;
        private const string ServiceName = "_mqtt._tcp.local";
        // Home Assistant's own DNS-SD service (issue #52). HA's zeroconf integration is on by
        // default and always advertises this, whereas the Mosquitto broker add-on does NOT advertise
        // _mqtt._tcp by default. We learn the HA HOST IP(s) from it and later probe the MQTT port
        // there — the advertised SRV port is HA's frontend (8123), not the broker, so it is ignored.
        private const string HaServiceName = "_home-assistant._tcp.local";

        // mDNS results, accumulated by RunMdnsAsync. Guarded by _lock (RunMdnsAsync runs on
        // a background task; the UI reads Candidates on the dispatcher thread).
        private readonly object _lock = new();
        private readonly List<BrokerCandidate> _mdns = new();
        // Home Assistant host IPs discovered via _home-assistant._tcp (issue #52), same guard.
        private readonly List<string> _haHosts = new();

        /// <summary>The mDNS candidates found so far (snapshot copy; safe to enumerate).</summary>
        public IReadOnlyList<BrokerCandidate> MdnsCandidates
        {
            get { lock (_lock) return _mdns.ToArray(); }
        }

        /// <summary>Home Assistant host IPs found via mDNS so far (snapshot copy). The broker is
        /// commonly co-located with HA, so these are probed on the MQTT port as a fallback source
        /// between direct MQTT mDNS and the /24 scan (issue #52).</summary>
        public IReadOnlyList<string> HaHostIps
        {
            get { lock (_lock) return _haHosts.ToArray(); }
        }

        // ---- mDNS ------------------------------------------------------------

        /// <summary>Send a <c>_mqtt._tcp.local</c> query AND a <c>_home-assistant._tcp.local</c>
        /// query, and collect responses for <paramref name="window"/>. Populates
        /// <see cref="MdnsCandidates"/> (direct brokers) and <see cref="HaHostIps"/> (HA hosts to
        /// probe as a fallback, issue #52). Never throws.</summary>
        public async Task RunMdnsAsync(TimeSpan window, CancellationToken ct)
        {
            // SRV (instance → host:port) and A (host → IPv4), accumulated across every datagram in
            // the window, then correlated once. The PTR record itself isn't needed — correlation is
            // by the SRV instance's service suffix — so we don't collect it (its only former use,
            // MQTT-instance membership, would now also match HA instances; see the correlation).
            var srv = new Dictionary<string, (string target, int port)>(StringComparer.OrdinalIgnoreCase);
            var a = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                using var udp = CreateMdnsSocket();

                // Query the MQTT service AND Home Assistant's service in the same window (issue #52),
                // so one listen collects both direct broker answers and the HA host(s).
                foreach (var svc in new[] { ServiceName, HaServiceName })
                {
                    byte[] query = BuildPtrQuery(svc);
                    await udp.SendAsync(query, query.Length, new IPEndPoint(MdnsGroup, MdnsPort)).ConfigureAwait(false);
                }

                using var winCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                winCts.CancelAfter(window);
                while (!winCts.IsCancellationRequested)
                {
                    UdpReceiveResult res;
                    try { res = await udp.ReceiveAsync(winCts.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }
                    catch { break; }
                    try { ParseDnsResponse(res.Buffer, srv, a); }
                    catch { /* skip a malformed datagram, keep listening */ }
                }
            }
            catch { /* socket setup / send failed — no candidates */ }

            // Correlation + publish is inside the guard too, so this fire-and-forget method
            // honours its "never throws" contract even on an unexpected failure here.
            try
            {
                // Correlate ONLY SRV records that belong to the MQTT service — those whose instance
                // name is of the form "<instance>._mqtt._tcp.local". A chatty responder may include
                // unrelated SRV+A pairs in the same datagram; those must not be mistaken for MQTT
                // brokers. Matching by the service SUFFIX is complete (a genuine DNS-SD instance
                // name always ends with its service) AND necessary: because we query both
                // `_mqtt._tcp` and `_home-assistant._tcp`, keying off PTR-instance membership would
                // let an HA SRV (port 8123) be misclassified as a plaintext MQTT broker — hiding the
                // whole HA-host fallback below and pre-filling HA's frontend port (Codex P1 / Copilot).
                var found = new List<BrokerCandidate>();
                foreach (var kv in srv)
                {
                    if (!kv.Key.EndsWith("." + ServiceName, StringComparison.OrdinalIgnoreCase)) continue;
                    if (a.TryGetValue(kv.Value.target, out string? ip))
                    {
                        string host = kv.Value.target.TrimEnd('.');
                        // _mqtt._tcp is the plaintext service (TLS brokers advertise a distinct
                        // service name we don't query), so treat an mDNS hit as plaintext.
                        // Mirror the scan path's reverse-DNS validation: an mDNS hit is auto-
                        // prefilled (IsTls false), so a self-advertised name outside the charset
                        // Build accepts (underscores are common) must fall back to IP-only — else
                        // it would be silently written and then rejected by MqttStructuralError().
                        string? hostname = IsAcceptableHostname(host) ? host : null;
                        found.Add(new BrokerCandidate(hostname, ip, kv.Value.port, IsTls: false));
                    }
                }

                // Correlate HA hosts the same way (issue #52): an SRV whose name is under
                // _home-assistant._tcp, resolved through its A record, gives the HA host IP. The
                // advertised port is HA's frontend and is discarded — the caller probes the MQTT
                // port on the IP instead. The HA suffix check keeps an MQTT instance (both services'
                // instances share the `srv`/`a` accumulators) from being mis-correlated as an HA host.
                var foundHa = new List<string>();
                foreach (var kv in srv)
                {
                    if (!kv.Key.EndsWith("." + HaServiceName, StringComparison.OrdinalIgnoreCase)) continue;
                    if (a.TryGetValue(kv.Value.target, out string? ip) && !foundHa.Contains(ip))
                        foundHa.Add(ip);
                }

                lock (_lock)
                {
                    foreach (var c in found)
                        if (!_mdns.Any(x => x.Ip == c.Ip && x.Port == c.Port))
                            _mdns.Add(c);
                    foreach (var ip in foundHa)
                        if (!_haHosts.Contains(ip))
                            _haHosts.Add(ip);
                }
            }
            catch { /* correlation failed — no candidates; never fault this fire-and-forget task */ }
        }

        /// <summary>A UDP socket for the mDNS exchange. Preferably bound to port 5353 and
        /// joined to the group, so it receives BOTH multicast responses (224.0.0.251:5353,
        /// the common case) and unicast (QU) replies; SO_REUSEADDR lets it coexist with a
        /// system mDNS responder. Falls back to an ephemeral port (QU-only) when 5353 can't
        /// be bound.</summary>
        private static UdpClient CreateMdnsSocket()
        {
            UdpClient? m = null;
            try
            {
                m = new UdpClient(AddressFamily.InterNetwork);
                // Windows binds exclusively by default; SO_REUSEADDR alone isn't enough to
                // co-bind 5353 with a system mDNS responder — clear ExclusiveAddressUse too,
                // else the bind fails and we drop to the ephemeral (multicast-blind) fallback.
                m.ExclusiveAddressUse = false;
                m.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                m.Client.Bind(new IPEndPoint(IPAddress.Any, MdnsPort));
                m.JoinMulticastGroup(MdnsGroup);
                // RFC 6762 §11: mDNS is link-local; send with IP TTL=255 (compliant responders
                // silently drop queries whose TTL isn't 255, as a same-link-origin check).
                m.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 255);
                return m;
            }
            catch { m?.Dispose(); }

            var e = new UdpClient(AddressFamily.InterNetwork);
            e.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            e.Client.Bind(new IPEndPoint(IPAddress.Any, 0));   // ephemeral; QU unicast replies land here
            e.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 255);  // RFC 6762 §11
            return e;
        }

        /// <summary>Build a standard-query datagram for a single PTR record with the mDNS
        /// unicast-response (QU) bit set, so responders reply to our ephemeral port.</summary>
        private static byte[] BuildPtrQuery(string name)
        {
            var b = new List<byte>
            {
                0x00, 0x00,             // ID (0 for mDNS)
                0x00, 0x00,             // flags: standard query
                0x00, 0x01,             // QDCOUNT = 1
                0x00, 0x00,             // ANCOUNT
                0x00, 0x00,             // NSCOUNT
                0x00, 0x00,             // ARCOUNT
            };
            foreach (var label in name.Split('.'))
            {
                byte[] bytes = Encoding.ASCII.GetBytes(label);
                b.Add((byte)bytes.Length);
                b.AddRange(bytes);
            }
            b.Add(0x00);                // end of QNAME
            b.Add(0x00); b.Add(0x0C);   // QTYPE = PTR (12)
            b.Add(0x80); b.Add(0x01);   // QCLASS = IN with the QU (unicast response) bit
            return b.ToArray();
        }

        /// <summary>Parse a DNS response into the SRV/A accumulators. Bounds-checked throughout; a
        /// truncated/odd record just stops parsing that datagram. PTR records are skipped —
        /// correlation is by the SRV instance's service suffix, so the PTR content isn't needed.</summary>
        private static void ParseDnsResponse(byte[] b,
            Dictionary<string, (string, int)> srv, Dictionary<string, string> a)
        {
            int len = b.Length;
            if (len < 12) return;
            int qd = (b[4] << 8) | b[5];
            int an = (b[6] << 8) | b[7];
            int ns = (b[8] << 8) | b[9];
            int ar = (b[10] << 8) | b[11];
            int pos = 12;

            for (int i = 0; i < qd; i++)
            {
                ReadName(b, ref pos);
                pos += 4;               // QTYPE + QCLASS
                if (pos > len) return;
            }

            int records = an + ns + ar;
            for (int i = 0; i < records; i++)
            {
                string name = ReadName(b, ref pos);
                if (pos + 10 > len) return;
                int type = (b[pos] << 8) | b[pos + 1];
                int rdlen = (b[pos + 8] << 8) | b[pos + 9];
                pos += 10;
                if (pos + rdlen > len) return;
                int rd = pos;

                switch (type)
                {
                    case 33 when rdlen >= 6: // SRV: priority(2) weight(2) port(2) target(name)
                    {
                        int port = (b[rd + 4] << 8) | b[rd + 5];
                        int pp = rd + 6;
                        string target = ReadName(b, ref pp);
                        if (target.Length > 0 && port is > 0 and <= 65535)
                            srv[name] = (target, port);
                        break;
                    }
                    case 1 when rdlen == 4: // A
                        a[name] = $"{b[rd]}.{b[rd + 1]}.{b[rd + 2]}.{b[rd + 3]}";
                        break;
                }
                pos = rd + rdlen;
            }
        }

        /// <summary>Read a DNS name (dotted, no trailing dot) starting at <paramref name="pos"/>,
        /// following 0xC0 compression pointers. Advances <paramref name="pos"/> past the name in
        /// the record stream (not past a pointer's target). Loop- and bounds-guarded.</summary>
        private static string ReadName(byte[] b, ref int pos)
        {
            var sb = new StringBuilder();
            int len = b.Length;
            int p = pos;
            bool jumped = false;
            int guard = 0;

            while (p < len && guard++ < 128)
            {
                int c = b[p];
                if (c == 0) { p++; break; }
                if ((c & 0xC0) == 0xC0) // compression pointer
                {
                    if (p + 1 >= len) break;
                    int ptr = ((c & 0x3F) << 8) | b[p + 1];
                    if (!jumped) { pos = p + 2; jumped = true; }
                    if (ptr >= len) break;
                    p = ptr;
                    continue;
                }
                // ordinary label
                p++;
                if (p + c > len) break;
                if (sb.Length > 0) sb.Append('.');
                sb.Append(Encoding.ASCII.GetString(b, p, c));
                p += c;
            }
            if (!jumped) pos = p;
            return sb.ToString();
        }

        // ---- /24 scan --------------------------------------------------------

        /// <summary>Scan the local /24 for a broker: TCP-probe every host on the two common
        /// MQTT ports, confirm a broker with a real MQTT CONNECT/CONNACK (over TLS on 8883),
        /// then reverse-DNS each hit. Deduplicated by IP, preferring the plaintext port. Scans
        /// every gateway-bearing LAN /24 (not virtual/VPN adapters). Never throws; returns an
        /// empty list on any failure.</summary>
        public async Task<IReadOnlyList<BrokerCandidate>> ScanSubnetAsync(CancellationToken ct)
        {
            IReadOnlyList<string> prefixes = LocalV24Prefixes();
            if (prefixes.Count == 0) return Array.Empty<BrokerCandidate>();

            // Materialise the /24 host list (…1–…254 of each prefix), parsing each base once.
            var hosts = new List<IPAddress>(prefixes.Count * 254);
            foreach (var prefix in prefixes)
            {
                byte[] o = IPAddress.Parse(prefix + ".0").GetAddressBytes();
                for (int h = 1; h <= 254; h++)
                    hosts.Add(new IPAddress(new[] { o[0], o[1], o[2], (byte)h }));
            }
            return await ProbeTargetsAsync(hosts, ct).ConfigureAwait(false);
        }

        /// <summary>Probe the discovered Home Assistant host(s) on the two MQTT ports and return any
        /// that answer a real MQTT CONNECT/CONNACK — the broker is commonly co-hosted with HA yet the
        /// Mosquitto add-on doesn't advertise <c>_mqtt._tcp</c> (issue #52). Same confirm-before-
        /// suggest rule as the scan: an HA host is returned ONLY once a broker actually answers
        /// there. Empty when no HA host was found or none runs a broker.</summary>
        public async Task<IReadOnlyList<BrokerCandidate>> ProbeHomeAssistantHostsAsync(CancellationToken ct)
        {
            var hosts = new List<IPAddress>();
            foreach (var ipStr in HaHostIps)
                if (IPAddress.TryParse(ipStr, out var ip))
                    hosts.Add(ip);
            if (hosts.Count == 0) return Array.Empty<BrokerCandidate>();
            return await ProbeTargetsAsync(hosts, ct).ConfigureAwait(false);
        }

        /// <summary>Shared probe engine for the /24 scan and the HA-host fallback: TCP-probe every
        /// <paramref name="hosts"/> entry on both MQTT ports, confirm a broker with a real MQTT
        /// CONNECT/CONNACK (over TLS on 8883), reverse-DNS each hit, dedup by IP preferring the
        /// plaintext port. Never throws; returns an empty list on any failure. Early-stops the moment
        /// a plaintext (1883) broker is confirmed.</summary>
        private async Task<IReadOnlyList<BrokerCandidate>> ProbeTargetsAsync(
            IReadOnlyList<IPAddress> hosts, CancellationToken ct)
        {
            var hits = new System.Collections.Concurrent.ConcurrentDictionary<string, int>(); // ip → port
            // A confirmed plaintext (1883) broker is all the caller consumes (it takes the first
            // non-TLS candidate), so stop the sweep the moment one lands instead of waiting on the
            // remaining host×port probes (each up to 400ms connect + 1200ms I/O — for a /24 that's
            // tens of seconds of "Searching…" past a broker already found). Linked to ct so a
            // bridge-off / window-close still cancels; cancelling THIS never signals ct, so the
            // caller still treats the sweep as completed (non-cancelled) and uses the results.
            using var earlyStop = CancellationTokenSource.CreateLinkedTokenSource(ct);

            // Probe every host×port with a bounded worker pool. Parallel.ForEachAsync pulls targets
            // LAZILY from the generator below, so we never materialise the whole host×port set as
            // Task + CTS objects up front the way the old List<Task> fan-out did — for a /24 that
            // burst of allocations spiked GC
            // (whose collections pause every managed thread) and did its whole fan-out on the
            // caller's thread. Here at most ScanConcurrency probes are live at once. Every candidate
            // is confirmed to speak MQTT: 1883 with a plaintext CONNECT/CONNACK, 8883 with a TLS
            // handshake THEN the same CONNECT/CONNACK. 1883 wins on a dual-port host.
            //
            // ScanConcurrency is intentionally moderate, not maximal. The probes are I/O-bound, but a
            // batch of dead-host connect timeouts fires its ~N continuations (parse/cleanup/alloc) in
            // near-synchronised bursts; each burst is a CPU + GC spike that competes with WPF's
            // render/dispatcher threads at equal priority (async continuations can't cheaply run at
            // lower priority), which shows as scroll stutter. A smaller pool shrinks each burst — the
            // common case still finishes fast because the sweep early-stops on the first plaintext
            // broker; only a no-broker-present sweep pays the extra wall-clock.
            const int ScanConcurrency = 24;
            var options = new ParallelOptions
            {
                MaxDegreeOfParallelism = ScanConcurrency,
                CancellationToken = earlyStop.Token,
            };
            try
            {
                // Return ProbeHostAsync's Task straight to the loop (wrapped as a ValueTask) instead
                // of an `async … await` lambda, which would add a redundant state machine per probe.
                await Parallel.ForEachAsync(EnumerateProbeTargets(hosts), options,
                    (t, probeCt) => new ValueTask(
                        ProbeHostAsync(t.Ip, t.Port, t.UseTls, hits, earlyStop, probeCt)))
                    .ConfigureAwait(false);
            }
            // Early-stop on a 1883 hit (or the caller cancelling) surfaces here as a cancellation —
            // keep whatever landed in `hits`; the caller tells the two apart via
            // scanCts.IsCancellationRequested (a plaintext-hit stop never signalled its ct).
            catch (OperationCanceledException) { }
            catch { /* individual probes already swallow; be safe */ }

            var results = new List<BrokerCandidate>();
            // Order by the IP numerically (…1.20 before …1.100), not lexicographically —
            // the UI picks the first plaintext hit, so a stable low-to-high order is intuitive.
            foreach (var kv in hits.OrderBy(k => IpSortKey(k.Key)))
            {
                string? host = await TryReverseDnsAsync(kv.Key, ct).ConfigureAwait(false);
                // The winning port reflects which probe confirmed it: 8883 was validated with a
                // TLS handshake, 1883 with a plaintext CONNECT — so the transport is known here.
                results.Add(new BrokerCandidate(host, kv.Key, kv.Value, IsTls: kv.Value == 8883));
            }
            return results;
        }

        /// <summary>Big-endian numeric value of a dotted-quad IPv4, so OrderBy sorts by host
        /// number rather than string (…1.20 before …1.100). All scan hits are valid IPv4.</summary>
        private static uint IpSortKey(string ip)
        {
            byte[] b = IPAddress.Parse(ip).GetAddressBytes();
            return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        }

        /// <summary>Lazily yield every (host, port, TLS) probe target for the given hosts — both MQTT
        /// ports across each host, plaintext (1883) first so a plaintext broker is confirmed (and the
        /// sweep early-stopped) as soon as possible. Enumerated on demand by the bounded worker pool,
        /// so a large host set is never materialised into tasks all at once.</summary>
        private static IEnumerable<(IPAddress Ip, int Port, bool UseTls)> EnumerateProbeTargets(
            IReadOnlyList<IPAddress> hosts)
        {
            foreach (var (port, useTls) in new[] { (1883, false), (8883, true) })
                foreach (var ip in hosts)
                    yield return (ip, port, useTls);
        }

        private static async Task ProbeHostAsync(IPAddress ip, int port, bool useTls,
            System.Collections.Concurrent.ConcurrentDictionary<string, int> hits,
            CancellationTokenSource earlyStop, CancellationToken ct)
        {
            // Concurrency is bounded by Parallel.ForEachAsync's MaxDegreeOfParallelism, so there is
            // no semaphore here. `ct` is the loop's token (linked to earlyStop): it trips when a
            // plaintext broker is found or the caller cancels, ending in-flight probes promptly.
            try
            {
                using var tcp = new TcpClient();
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                connectCts.CancelAfter(TimeSpan.FromMilliseconds(400));
                try { await tcp.ConnectAsync(ip, port, connectCts.Token).ConfigureAwait(false); }
                catch { return; }   // closed / filtered / timed out — not a hit

                using var ioCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                ioCts.CancelAfter(TimeSpan.FromMilliseconds(1200));
                Stream stream = tcp.GetStream();
                SslStream? ssl = null;
                try
                {
                    if (useTls)
                    {
                        // Discovery, not a security check — accept any server certificate; we only
                        // want to know a TLS MQTT broker is listening. The user's Test connection
                        // (and Build) validate the certificate properly.
                        ssl = new SslStream(stream, leaveInnerStreamOpen: false, (_, _, _, _) => true);
                        await ssl.AuthenticateAsClientAsync(
                            new SslClientAuthenticationOptions { TargetHost = ip.ToString() }, ioCts.Token).ConfigureAwait(false);
                        stream = ssl;
                    }
                    if (await IsMqttOverStreamAsync(stream, ioCts.Token).ConfigureAwait(false))
                    {
                        hits.AddOrUpdate(ip.ToString(), port, (_, existing) => Math.Min(existing, port)); // prefer 1883
                        // A plaintext broker is the best-case result the caller wants — end the
                        // sweep. (8883 hits keep scanning: the caller needs a plaintext candidate,
                        // and a TLS-only find is only surfaced as guidance, never auto-prefilled.)
                        if (port == 1883) { try { earlyStop.Cancel(); } catch { /* already disposed/cancelled */ } }
                    }
                }
                finally { ssl?.Dispose(); }
            }
            catch { /* best-effort */ }
        }

        /// <summary>Confirm a stream speaks MQTT by sending a 3.1.1 CONNECT and checking the reply
        /// begins with the full CONNACK fixed header <c>0x20 0x02</c> (type 2, remaining length 2)
        /// — regardless of the return code, since an auth-required broker still answers with a
        /// CONNACK before refusing. Requiring both header bytes avoids a false positive from a
        /// service whose first byte merely happens to be 0x20.</summary>
        // The scan's CONNECT is constant (fixed anonymous client id), so encode it ONCE and reuse
        // the bytes across every probe instead of rebuilding a List<byte> per host. WriteAsync only
        // READS the buffer, so sharing this immutable array across concurrent probes is safe.
        private static readonly byte[] ScanConnectPacket = BuildMqttConnect("intercom-fw-tool-scan");

        private static async Task<bool> IsMqttOverStreamAsync(Stream stream, CancellationToken ct)
        {
            try
            {
                await stream.WriteAsync(ScanConnectPacket, ct).ConfigureAwait(false);
                byte[] hdr = new byte[2];
                int got = 0;
                while (got < hdr.Length)
                {
                    int n = await stream.ReadAsync(hdr.AsMemory(got, hdr.Length - got), ct).ConfigureAwait(false);
                    if (n <= 0) break;   // peer closed
                    got += n;
                }
                return got == 2 && hdr[0] == 0x20 && hdr[1] == 0x02;
            }
            catch { return false; }
        }

        /// <summary>A minimal MQTT 3.1.1 CONNECT packet (clean session, anonymous).</summary>
        private static byte[] BuildMqttConnect(string clientId)
        {
            byte[] id = Encoding.ASCII.GetBytes(clientId);
            var vhAndPayload = new List<byte>
            {
                0x00, 0x04, (byte)'M', (byte)'Q', (byte)'T', (byte)'T', // protocol name
                0x04,                       // protocol level (3.1.1)
                0x02,                       // connect flags: clean session
                0x00, 0x3C,                 // keep-alive 60s
                (byte)(id.Length >> 8), (byte)(id.Length & 0xFF),
            };
            vhAndPayload.AddRange(id);

            var pkt = new List<byte> { 0x10 };  // CONNECT
            int rem = vhAndPayload.Count;       // encode remaining length as a varint
            do
            {
                byte enc = (byte)(rem & 0x7F);
                rem >>= 7;
                if (rem > 0) enc |= 0x80;
                pkt.Add(enc);
            } while (rem > 0);
            pkt.AddRange(vhAndPayload);
            return pkt.ToArray();
        }

        private static async Task<string?> TryReverseDnsAsync(string ip, CancellationToken ct)
        {
            try
            {
                using var dnsCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                dnsCts.CancelAfter(TimeSpan.FromSeconds(2));
                var entry = await Dns.GetHostEntryAsync(IPAddress.Parse(ip)).WaitAsync(dnsCts.Token).ConfigureAwait(false);
                string name = (entry.HostName ?? "").TrimEnd('.');
                // Only return a name the app would actually accept as a broker host. A PTR
                // carrying underscores (or other characters Core's IsValidHost rejects), or an
                // IP-shaped echo, must fall back to the IP-only path — otherwise the prefill
                // writes a host that can never be tested or built.
                return IsAcceptableHostname(name) ? name : null;
            }
            catch { return null; }
        }

        /// <summary>Mirrors MainWindow.IsValidMqttHost / MqttInstaller.IsValidHost for the
        /// reverse-DNS path (minus the IP branch — an IP-shaped PTR echo is not a useful host
        /// here): 1..253 chars, dot-separated labels of 1..63 [A-Za-z0-9-] that don't start or
        /// end with '-'. Keeps discovery from surfacing a structurally invalid host.</summary>
        private static bool IsAcceptableHostname(string name)
        {
            if (name.Length == 0 || name.Length > 253) return false;
            if (IPAddress.TryParse(name, out _)) return false;   // resolver echoed the address back
            foreach (var label in name.Split('.'))
            {
                if (label.Length == 0 || label.Length > 63) return false;
                if (label[0] == '-' || label[^1] == '-') return false;
                foreach (char c in label)
                    if (!(char.IsAsciiLetterOrDigit(c) || c == '-')) return false;
            }
            return true;
        }

        /// <summary>The /24 prefixes (first three octets) to scan: the private-range IPv4
        /// networks on operational, non-loopback, non-tunnel interfaces. Interfaces that have an
        /// IPv4 default gateway (the real LAN) are preferred and scanned together; a gateway-less
        /// private network is used only as a fallback when none has a gateway — so a Docker/VPN
        /// adapter can't hijack the scan, and a broker on any active LAN is still reached.
        /// Distinct and capped so a machine with many adapters can't explode the probe count.</summary>
        private static IReadOnlyList<string> LocalV24Prefixes()
        {
            var gatewayed = new List<string>();
            var others = new List<string>();
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (IsVirtualOrVpn(ni)) continue;   // never probe a VPN/virtual /24
                    var props = ni.GetIPProperties();
                    bool hasV4Gateway = props.GatewayAddresses.Any(g =>
                        g.Address.AddressFamily == AddressFamily.InterNetwork && !g.Address.Equals(IPAddress.Any));
                    foreach (var ua in props.UnicastAddresses)
                    {
                        if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                        byte[] o = ua.Address.GetAddressBytes();
                        bool isPrivate = o[0] == 10
                            || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
                            || (o[0] == 192 && o[1] == 168);
                        if (isPrivate) (hasV4Gateway ? gatewayed : others).Add($"{o[0]}.{o[1]}.{o[2]}");
                    }
                }
            }
            catch { /* fall through with whatever was collected */ }

            return (gatewayed.Count > 0 ? gatewayed : others)
                .Distinct(StringComparer.OrdinalIgnoreCase).Take(4).ToList();
        }

        /// <summary>Whether an interface is a loopback, tunnel, PPP, or a virtual/VPN adapter
        /// that merely presents as Ethernet (TAP, Hyper-V, VMware, Docker, WSL, WireGuard,
        /// Tailscale, …). Such adapters can carry a gateway yet route to a corporate/remote
        /// network — never a LAN we should port-scan. Matched by type and by well-known
        /// adapter-name markers, erring toward EXCLUDING (a missed real LAN just means no
        /// scan there; scanning a VPN would blast probes into a remote network).</summary>
        private static bool IsVirtualOrVpn(NetworkInterface ni)
        {
            var t = ni.NetworkInterfaceType;
            if (t is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel or NetworkInterfaceType.Ppp)
                return true;
            string s = (ni.Description + " " + ni.Name).ToLowerInvariant();
            foreach (var marker in VirtualAdapterMarkers)
                if (s.Contains(marker)) return true;
            return false;
        }

        private static readonly string[] VirtualAdapterMarkers =
        {
            "vpn", "tailscale", "wireguard", "nordlynx", "zerotier", "openvpn", "hamachi",
            "hyper-v", "vethernet", "vmware", "virtualbox", "vbox", "virtual",
            "docker", "wsl", "tap-windows", "pseudo", "loopback", "bluetooth",
        };
    }
}
