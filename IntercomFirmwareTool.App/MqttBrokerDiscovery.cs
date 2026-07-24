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
    /// name (mDNS) or a reverse-DNS name (scan), or null when only an IP is known.</summary>
    public sealed record BrokerCandidate(string? Hostname, string Ip, int Port);

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
                using var udp = CreateMdnsSocket();

                byte[] query = BuildPtrQuery(ServiceName);
                await udp.SendAsync(query, query.Length, new IPEndPoint(MdnsGroup, MdnsPort)).ConfigureAwait(false);

                using var winCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                winCts.CancelAfter(window);
                while (!winCts.IsCancellationRequested)
                {
                    UdpReceiveResult res;
                    try { res = await udp.ReceiveAsync(winCts.Token).ConfigureAwait(false); }
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
                m.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                m.Client.Bind(new IPEndPoint(IPAddress.Any, MdnsPort));
                m.JoinMulticastGroup(MdnsGroup);
                m.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 4);
                return m;
            }
            catch { m?.Dispose(); }

            var e = new UdpClient(AddressFamily.InterNetwork);
            e.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            e.Client.Bind(new IPEndPoint(IPAddress.Any, 0));   // ephemeral; QU unicast replies land here
            e.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 4);
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
        /// MQTT ports, confirm a broker with a real MQTT CONNECT/CONNACK (over TLS on 8883),
        /// then reverse-DNS each hit. Deduplicated by IP, preferring the plaintext port. Scans
        /// every gateway-bearing LAN /24 (not virtual/VPN adapters). Never throws; returns an
        /// empty list on any failure.</summary>
        public async Task<IReadOnlyList<BrokerCandidate>> ScanSubnetAsync(CancellationToken ct)
        {
            IReadOnlyList<string> prefixes = LocalV24Prefixes();
            if (prefixes.Count == 0) return Array.Empty<BrokerCandidate>();

            var hits = new System.Collections.Concurrent.ConcurrentDictionary<string, int>(); // ip → port
            using var sem = new SemaphoreSlim(48);
            var tasks = new List<Task>();
            // Every candidate is confirmed to speak MQTT: 1883 with a plaintext CONNECT/CONNACK,
            // 8883 with a TLS handshake THEN the same CONNECT/CONNACK. 1883 wins on a dual-port host.
            foreach (var prefix in prefixes)
                foreach (var (port, useTls) in new[] { (1883, false), (8883, true) })
                    for (int h = 1; h <= 254; h++)
                        tasks.Add(ProbeHostAsync($"{prefix}.{h}", port, useTls, sem, hits, ct));

            try { await Task.WhenAll(tasks).ConfigureAwait(false); } catch { /* individual probes already swallow */ }

            var results = new List<BrokerCandidate>();
            foreach (var kv in hits.OrderBy(k => k.Key))
            {
                string? host = await TryReverseDnsAsync(kv.Key, ct).ConfigureAwait(false);
                results.Add(new BrokerCandidate(host, kv.Key, kv.Value));
            }
            return results;
        }

        private static async Task ProbeHostAsync(string ip, int port, bool useTls,
            SemaphoreSlim sem, System.Collections.Concurrent.ConcurrentDictionary<string, int> hits,
            CancellationToken ct)
        {
            // Acquire the throttle outside the main try so a cancellation here can't fault the
            // task — nothing to release if we never got the slot.
            try { await sem.WaitAsync(ct).ConfigureAwait(false); }
            catch { return; }
            try
            {
                using var tcp = new TcpClient();
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                connectCts.CancelAfter(TimeSpan.FromMilliseconds(400));
                try { await tcp.ConnectAsync(IPAddress.Parse(ip), port, connectCts.Token).ConfigureAwait(false); }
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
                            new SslClientAuthenticationOptions { TargetHost = ip }, ioCts.Token).ConfigureAwait(false);
                        stream = ssl;
                    }
                    if (await IsMqttOverStreamAsync(stream, ioCts.Token).ConfigureAwait(false))
                        hits.AddOrUpdate(ip, port, (_, existing) => Math.Min(existing, port)); // prefer 1883
                }
                finally { ssl?.Dispose(); }
            }
            catch { /* best-effort */ }
            finally { try { sem.Release(); } catch { } }
        }

        /// <summary>Confirm a stream speaks MQTT by sending a 3.1.1 CONNECT and checking the reply
        /// begins with the full CONNACK fixed header <c>0x20 0x02</c> (type 2, remaining length 2)
        /// — regardless of the return code, since an auth-required broker still answers with a
        /// CONNACK before refusing. Requiring both header bytes avoids a false positive from a
        /// service whose first byte merely happens to be 0x20.</summary>
        private static async Task<bool> IsMqttOverStreamAsync(Stream stream, CancellationToken ct)
        {
            try
            {
                byte[] connect = BuildMqttConnect("intercom-fw-tool-scan");
                await stream.WriteAsync(connect, ct).ConfigureAwait(false);
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
                // Reject an IP-shaped "name" (some resolvers echo the address back).
                return (name.Length > 0 && !IPAddress.TryParse(name, out _)) ? name : null;
            }
            catch { return null; }
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
            "vpn", "tailscale", "wireguard", "zerotier", "openvpn", "hamachi",
            "hyper-v", "vethernet", "vmware", "virtualbox", "vbox", "virtual",
            "docker", "wsl", "tap-windows", "pseudo", "loopback", "bluetooth",
        };

        private static string? NullIfEmpty(string s) => string.IsNullOrEmpty(s) ? null : s;
    }
}
