using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace IntercomFirmwareTool.App
{
    /// <summary>A broker found on the LAN. <see cref="Hostname"/> is the advertised
    /// name (mDNS) or a reverse-DNS name (scan), or null when only an IP is known.</summary>
    public sealed record BrokerCandidate(string? Hostname, string Ip, int Port);

    /// <summary>
    /// Best-effort discovery of MQTT brokers on the local network, with NO external
    /// dependency (issue #43, follow-up 2):
    /// <list type="bullet">
    /// <item><b>mDNS</b> — a hand-rolled <c>_mqtt._tcp.local</c> query (unicast-response
    /// bit set) parsed for PTR/SRV/A records, giving <c>(hostname, IPv4, port)</c> directly.
    /// Cheap and passive; run at startup.</item>
    /// <item><b>/24 scan</b> — a heavier fallback: TCP-probe every host on the local /24,
    /// confirm a plaintext broker with a raw MQTT CONNECT/CONNACK exchange (port 1883) or a
    /// bare TCP open (TLS port 8883), then reverse-DNS the address. Run on demand only.</item>
    /// </list>
    /// Everything here is best-effort and swallows all errors — discovery failing must never
    /// disrupt the app; it simply yields no candidates.
    /// </summary>
    public sealed class MqttBrokerDiscovery
    {
        private static readonly IPAddress MdnsGroup = IPAddress.Parse("224.0.0.251");
        private const int MdnsPort = 5353;
        private const string ServiceName = "_mqtt._tcp.local";

        // mDNS results, accumulated by RunMdnsAsync. Guarded by _lock (RunMdnsAsync runs on
        // a background task; the UI reads Candidates on the dispatcher thread).
        private readonly object _lock = new();
        private readonly List<BrokerCandidate> _mdns = new();

        /// <summary>The mDNS candidates found so far (snapshot copy; safe to enumerate).</summary>
        public IReadOnlyList<BrokerCandidate> MdnsCandidates
        {
            get { lock (_lock) return _mdns.ToArray(); }
        }

        // ---- mDNS ------------------------------------------------------------

        /// <summary>Send one <c>_mqtt._tcp.local</c> query and collect responses for
        /// <paramref name="window"/>. Populates <see cref="MdnsCandidates"/>. Never throws.</summary>
        public async Task RunMdnsAsync(TimeSpan window, CancellationToken ct)
        {
            // PTR (instances of the service), SRV (instance → host:port), A (host → IPv4).
            // Accumulated across every datagram in the window, then correlated once.
            var ptr = new List<string>();
            var srv = new Dictionary<string, (string target, int port)>(StringComparer.OrdinalIgnoreCase);
            var a = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                using var udp = new UdpClient(AddressFamily.InterNetwork);
                udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));   // ephemeral; unicast replies land here
                udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 4);

                byte[] query = BuildPtrQuery(ServiceName);
                await udp.SendAsync(query, query.Length, new IPEndPoint(MdnsGroup, MdnsPort));

                using var winCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                winCts.CancelAfter(window);
                while (!winCts.IsCancellationRequested)
                {
                    UdpReceiveResult res;
                    try { res = await udp.ReceiveAsync(winCts.Token); }
                    catch (OperationCanceledException) { break; }
                    catch { break; }
                    try { ParseDnsResponse(res.Buffer, ptr, srv, a); }
                    catch { /* skip a malformed datagram, keep listening */ }
                }
            }
            catch { /* socket setup / send failed — no candidates */ }

            // Correlate — but ONLY SRV records that actually belong to our service, i.e.
            // an instance the PTR answer pointed to, or a name of the form
            // "<instance>._mqtt._tcp.local". A chatty responder may include unrelated SRV+A
            // pairs in the same datagram; those must not be mistaken for MQTT brokers.
            var instances = new HashSet<string>(ptr, StringComparer.OrdinalIgnoreCase);
            var found = new List<BrokerCandidate>();
            foreach (var kv in srv)
            {
                // Instance names are "<instance>._mqtt._tcp.local" → suffix "." + ServiceName.
                bool isMqtt = instances.Contains(kv.Key)
                    || kv.Key.EndsWith("." + ServiceName, StringComparison.OrdinalIgnoreCase);
                if (!isMqtt) continue;
                if (a.TryGetValue(kv.Value.target, out string? ip))
                {
                    string host = kv.Value.target.TrimEnd('.');
                    found.Add(new BrokerCandidate(NullIfEmpty(host), ip, kv.Value.port));
                }
            }

            lock (_lock)
            {
                foreach (var c in found)
                    if (!_mdns.Any(x => x.Ip == c.Ip && x.Port == c.Port))
                        _mdns.Add(c);
            }
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

        /// <summary>Parse a DNS response into the PTR/SRV/A accumulators. Bounds-checked
        /// throughout; a truncated/odd record just stops parsing that datagram.</summary>
        private static void ParseDnsResponse(byte[] b, List<string> ptr,
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
                    case 12 when name.Equals(ServiceName, StringComparison.OrdinalIgnoreCase): // PTR
                    {
                        int pp = rd;
                        ptr.Add(ReadName(b, ref pp));
                        break;
                    }
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
        /// MQTT ports, confirm plaintext brokers (1883) with a real CONNECT/CONNACK, accept a
        /// bare TCP open on the TLS port (8883), then reverse-DNS each hit. Deduplicated by IP,
        /// preferring the plaintext port. Never throws; returns an empty list on any failure.</summary>
        public async Task<IReadOnlyList<BrokerCandidate>> ScanSubnetAsync(CancellationToken ct)
        {
            string? prefix = LocalV24Prefix();
            if (prefix == null) return Array.Empty<BrokerCandidate>();

            var hits = new System.Collections.Concurrent.ConcurrentDictionary<string, int>(); // ip → port
            using var sem = new SemaphoreSlim(48);
            var tasks = new List<Task>();
            // 1883 (plaintext, MQTT-confirmed) takes precedence over 8883 (TLS, TCP-open only).
            foreach (var (port, confirmMqtt) in new[] { (1883, true), (8883, false) })
            {
                for (int h = 1; h <= 254; h++)
                {
                    string ip = $"{prefix}.{h}";
                    tasks.Add(ProbeHostAsync(ip, port, confirmMqtt, sem, hits, ct));
                }
            }
            try { await Task.WhenAll(tasks); } catch { /* individual probes already swallow */ }

            var results = new List<BrokerCandidate>();
            foreach (var kv in hits.OrderBy(k => k.Key))
            {
                string? host = await TryReverseDnsAsync(kv.Key, ct);
                results.Add(new BrokerCandidate(host, kv.Key, kv.Value));
            }
            return results;
        }

        private static async Task ProbeHostAsync(string ip, int port, bool confirmMqtt,
            SemaphoreSlim sem, System.Collections.Concurrent.ConcurrentDictionary<string, int> hits,
            CancellationToken ct)
        {
            await sem.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                using var tcp = new TcpClient();
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                connectCts.CancelAfter(TimeSpan.FromMilliseconds(400));
                try { await tcp.ConnectAsync(IPAddress.Parse(ip), port, connectCts.Token); }
                catch { return; }   // closed / filtered / timed out — not a hit

                bool isBroker = !confirmMqtt || await IsPlaintextMqttAsync(tcp, ct);
                if (isBroker)
                    hits.AddOrUpdate(ip, port, (_, existing) => Math.Min(existing, port)); // prefer 1883
            }
            catch { /* best-effort */ }
            finally { try { sem.Release(); } catch { } }
        }

        /// <summary>Confirm an open socket speaks MQTT by sending a 3.1.1 CONNECT and checking
        /// the first response byte is a CONNACK (0x20) — regardless of the return code, since an
        /// auth-required broker still answers with a CONNACK before refusing.</summary>
        private static async Task<bool> IsPlaintextMqttAsync(TcpClient tcp, CancellationToken ct)
        {
            try
            {
                var stream = tcp.GetStream();
                using var ioCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                ioCts.CancelAfter(TimeSpan.FromMilliseconds(800));
                byte[] connect = BuildMqttConnect("intercom-fw-tool-scan");
                await stream.WriteAsync(connect, ioCts.Token);
                byte[] resp = new byte[1];
                int n = await stream.ReadAsync(resp, ioCts.Token);
                // A CONNACK fixed header is exactly 0x20 (type 2, reserved flags all 0);
                // 0x21–0x2F would be a malformed header, so match 0x20 exactly.
                return n == 1 && resp[0] == 0x20;
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
                var entry = await Dns.GetHostEntryAsync(IPAddress.Parse(ip)).WaitAsync(dnsCts.Token);
                string name = (entry.HostName ?? "").TrimEnd('.');
                // Reject an IP-shaped "name" (some resolvers echo the address back).
                return (name.Length > 0 && !IPAddress.TryParse(name, out _)) ? name : null;
            }
            catch { return null; }
        }

        /// <summary>The first three octets of the machine's LAN IPv4 (a private-range address
        /// on an operational, non-loopback interface), or null if none is found.</summary>
        private static string? LocalV24Prefix()
        {
            try
            {
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up) continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                    foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                    {
                        if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                        byte[] o = ua.Address.GetAddressBytes();
                        bool isPrivate = o[0] == 10
                            || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
                            || (o[0] == 192 && o[1] == 168);
                        if (isPrivate) return $"{o[0]}.{o[1]}.{o[2]}";
                    }
                }
            }
            catch { /* fall through */ }
            return null;
        }

        private static string? NullIfEmpty(string s) => string.IsNullOrEmpty(s) ? null : s;
    }
}
