//! Hand-rolled mDNS / DNS-SD discovery of `_mqtt._tcp.local` (issue #49 item 2, #43 Layer B).
//!
//! ## Why hand-rolled
//! The statically-linked musl binary's resolver ignores `nsswitch`/system mDNS, so — exactly
//! as the WPF app does at config time (`MqttBrokerDiscovery.cs`) — we speak the mDNS wire
//! protocol directly: send a `_mqtt._tcp.local` PTR query to the link-local multicast group
//! `224.0.0.251:5353` (unicast-response bit set) and parse the PTR/SRV/A records the brokers
//! answer with, yielding the advertised IPv4 address(es) directly — no `/24` port scan.
//!
//! Used by `rediscovery::rediscover` as the FIRST (cheap, name-based, cross-`/24`-on-link)
//! rediscovery layer, before the brute-force subnet scan. The trust boundary is unchanged:
//! mDNS only PROPOSES an address; the caller repoints `/etc/hosts` and the main client's
//! authenticated + pinned-TLS reconnect is the gate (plaintext additionally requires an ARP
//! MAC match, applied by the caller). Never panics: socket/parse failures just yield no
//! candidates.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::net::UdpSocket;

/// The IPv4 link-local mDNS multicast group and port (RFC 6762).
const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

/// The service we look for. Lower-case: parsed names are ASCII-case-folded (via
/// `to_ascii_lowercase`) so correlation against this constant is a plain string match. DNS
/// compares ASCII letters case-insensitively; any non-ASCII bytes in a DNS-SD instance label
/// are left as-is, which is harmless here — only the ASCII `_mqtt._tcp.local` service suffix
/// needs to match.
const SERVICE: &str = "_mqtt._tcp.local";

/// Query `_mqtt._tcp.local` on the LAN for `window` and return the distinct advertised IPv4
/// addresses of MQTT brokers (correlated PTR→SRV→A). Empty on any socket failure or no answer.
/// Only the IP is returned — the caller repoints the CONFIGURED broker name to it, so the
/// mDNS-advertised instance/host name is not needed.
pub async fn discover_ips(window: Duration) -> Vec<Ipv4Addr> {
    let mut ptr: Vec<String> = Vec::new();
    let mut srv: HashMap<String, (String, u16)> = HashMap::new();
    // A host may advertise MORE THAN ONE A record (a multihomed broker): keep every
    // distinct address per name so a target reachable on one interface is not lost when
    // a later, unreachable A record for the same host arrives (Codex P2).
    let mut a: HashMap<String, Vec<Ipv4Addr>> = HashMap::new();

    if let Ok((sock, unicast_response)) = open_socket().await {
        let query = build_ptr_query(SERVICE, unicast_response);
        let _ = sock.send_to(&query, (MDNS_GROUP, MDNS_PORT)).await;

        let deadline = tokio::time::sleep(window);
        tokio::pin!(deadline);
        // RFC 6762 §17 caps an mDNS message (incl. IP+UDP headers) at 9000 bytes; a smaller
        // buffer would let the kernel silently TRUNCATE a large datagram (many additional
        // records on a chatty LAN), and the bounds-checked parser would then bail early and
        // miss an otherwise-valid broker answer (Copilot). Size for the RFC maximum.
        let mut buf = [0u8; 9000];
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                r = sock.recv_from(&mut buf) => match r {
                    Ok((n, _)) => parse_response(&buf[..n], &mut ptr, &mut srv, &mut a),
                    Err(_) => break,
                }
            }
        }
    }
    correlate(&ptr, &srv, &a)
}

/// A UDP socket for the exchange, plus whether to ask for a UNICAST response (the QU bit).
///
/// Preferred: bind 5353 (with `SO_REUSEADDR` + `SO_REUSEPORT`) and join the group, so we co-bind
/// alongside a system mDNS responder (e.g. Avahi) that already holds the port (Copilot). On this
/// SHARED socket we must ask for a MULTICAST answer (`unicast_response = false`): a unicast reply
/// to 5353 is delivered to only ONE of the co-bound sockets, so Avahi could consume the broker's
/// answer and leave us empty-handed (Codex) — a multicast answer, by contrast, is copied to every
/// socket joined to the group. Fallback: an ephemeral port we solely own, where we did NOT join
/// the group and so must ask for a UNICAST reply (`unicast_response = true`) to receive anything.
/// TTL 255 per RFC 6762 §11.
async fn open_socket() -> std::io::Result<(UdpSocket, bool)> {
    match bind_reuse(MDNS_PORT) {
        Ok(sock) => {
            let _ = sock.join_multicast_v4(MDNS_GROUP, Ipv4Addr::UNSPECIFIED);
            let _ = sock.set_multicast_ttl_v4(255);
            Ok((sock, false)) // shared 5353 + joined group → request MULTICAST answers
        }
        Err(_) => {
            let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
            let _ = sock.set_multicast_ttl_v4(255);
            Ok((sock, true)) // sole owner of an ephemeral port → request UNICAST answers
        }
    }
}

/// Bind a non-blocking UDP socket to `0.0.0.0:port` with `SO_REUSEADDR` + `SO_REUSEPORT` set
/// BEFORE the bind (std's `UdpSocket` offers no reuse setter, and the crate already depends on
/// `libc` — used for `chown` in `receiver.rs` — so no new crate is pulled). Returns a tokio
/// socket registered on the current reactor; call from within the runtime.
fn bind_reuse(port: u16) -> std::io::Result<UdpSocket> {
    use std::os::fd::FromRawFd;
    let err = std::io::Error::last_os_error;
    // SAFETY: standard socket syscalls. The raw fd is wrapped in an owning std `UdpSocket`
    // immediately, so every early return closes it via `Drop` — the fd is never leaked.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(err());
        }
        let std_sock = std::net::UdpSocket::from_raw_fd(fd);
        let on: libc::c_int = 1;
        let optlen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        // SO_REUSEADDR is required to co-bind the mDNS group/port; treat its failure as fatal
        // (fall back to the ephemeral port).
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            std::ptr::addr_of!(on).cast(),
            optlen,
        ) != 0
        {
            return Err(err());
        }
        // SO_REUSEPORT is an ADDITIONAL sharing hint that older/embedded kernels may not know;
        // treat `ENOPROTOOPT` as best-effort so the reuse bind still succeeds with just
        // SO_REUSEADDR (Copilot). Any other error is still surfaced.
        if libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            std::ptr::addr_of!(on).cast(),
            optlen,
        ) != 0
        {
            let e = err();
            if e.raw_os_error() != Some(libc::ENOPROTOOPT) {
                return Err(e);
            }
        }
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr { s_addr: 0 }, // INADDR_ANY
            ..std::mem::zeroed()
        };
        if libc::bind(
            fd,
            std::ptr::addr_of!(addr).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) != 0
        {
            return Err(err());
        }
        std_sock.set_nonblocking(true)?;
        UdpSocket::from_std(std_sock)
    }
}

// ---------------------------------------------------------------------------
// Pure wire helpers (unit-tested). No I/O — ported from MqttBrokerDiscovery.cs.
// ---------------------------------------------------------------------------

/// Build a standard-query datagram for a single PTR record. When `unicast_response` is set, the
/// mDNS unicast-response (QU) top bit of QCLASS is set so responders reply to our source port —
/// used ONLY on the solely-owned ephemeral socket. On the shared 5353 socket it is cleared, i.e.
/// a normal multicast-response (QM) question, so the answer reaches every co-bound listener
/// (Codex).
fn build_ptr_query(name: &str, unicast_response: bool) -> Vec<u8> {
    let mut b = vec![
        0x00, 0x00, // ID (0 for mDNS)
        0x00, 0x00, // flags: standard query
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ];
    for label in name.split('.') {
        b.push(label.len() as u8);
        b.extend_from_slice(label.as_bytes());
    }
    b.push(0x00); // end of QNAME
    b.extend_from_slice(&[0x00, 0x0C]); // QTYPE = PTR (12)
    // QCLASS = IN (0x0001); the top bit is the mDNS QU (unicast-response) request.
    let qclass: u16 = if unicast_response { 0x8001 } else { 0x0001 };
    b.extend_from_slice(&qclass.to_be_bytes());
    b
}

/// Parse a DNS response into the PTR/SRV/A accumulators (names lower-cased). Bounds-checked
/// throughout; a truncated/odd record just stops parsing that datagram.
fn parse_response(
    b: &[u8],
    ptr: &mut Vec<String>,
    srv: &mut HashMap<String, (String, u16)>,
    a: &mut HashMap<String, Vec<Ipv4Addr>>,
) {
    let len = b.len();
    if len < 12 {
        return;
    }
    let word = |i: usize| ((b[i] as usize) << 8) | b[i + 1] as usize;
    let qd = word(4);
    let records = word(6) + word(8) + word(10); // AN + NS + AR
    let mut pos = 12usize;

    for _ in 0..qd {
        read_name(b, &mut pos);
        pos += 4; // QTYPE + QCLASS
        if pos > len {
            return;
        }
    }

    for _ in 0..records {
        let name = read_name(b, &mut pos);
        if pos + 10 > len {
            return;
        }
        let typ = ((b[pos] as usize) << 8) | b[pos + 1] as usize;
        let rdlen = ((b[pos + 8] as usize) << 8) | b[pos + 9] as usize;
        pos += 10;
        if pos + rdlen > len {
            return;
        }
        let rd = pos;
        match typ {
            12 if name == SERVICE => {
                // PTR: the RDATA is the instance name.
                let mut pp = rd;
                ptr.push(read_name(b, &mut pp));
            }
            33 if rdlen >= 6 => {
                // SRV: priority(2) weight(2) port(2) target(name).
                let port = ((b[rd + 4] as u16) << 8) | b[rd + 5] as u16;
                let mut pp = rd + 6;
                let target = read_name(b, &mut pp);
                if !target.is_empty() && port > 0 {
                    srv.insert(name, (target, port));
                }
            }
            1 if rdlen == 4 => {
                // A: 4-byte IPv4. Accumulate (deduped) — a host may carry several.
                let ip = Ipv4Addr::new(b[rd], b[rd + 1], b[rd + 2], b[rd + 3]);
                let ips = a.entry(name).or_default();
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
            _ => {}
        }
        pos = rd + rdlen;
    }
}

/// Read a DNS name (dotted, no trailing dot, LOWER-cased) at `pos`, following `0xC0`
/// compression pointers. Advances `pos` past the name in the record stream (not past a
/// pointer's target). Loop- and bounds-guarded.
fn read_name(b: &[u8], pos: &mut usize) -> String {
    let mut out = String::new();
    let len = b.len();
    let mut p = *pos;
    let mut jumped = false;
    let mut guard = 0u32;

    while p < len && guard < 128 {
        guard += 1;
        let c = b[p] as usize;
        if c == 0 {
            p += 1;
            break;
        }
        if (c & 0xC0) == 0xC0 {
            // compression pointer
            if p + 1 >= len {
                break;
            }
            let target = ((c & 0x3F) << 8) | b[p + 1] as usize;
            if !jumped {
                *pos = p + 2;
                jumped = true;
            }
            if target >= len {
                break;
            }
            p = target;
            continue;
        }
        // ordinary label
        p += 1;
        if p + c > len {
            break;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(&b[p..p + c]).to_ascii_lowercase());
        p += c;
    }
    if !jumped {
        *pos = p;
    }
    out
}

/// Correlate the accumulated records into the advertised broker IPv4s: keep only SRV records
/// that actually belong to `_mqtt._tcp` (an instance the PTR pointed to, or a name of the form
/// `<instance>._mqtt._tcp.local`), resolve each SRV target through the A records (every A record
/// the target carries, not just one — a multihomed broker has several), and return the distinct
/// IPs. A chatty responder's unrelated SRV+A pairs are ignored.
fn correlate(
    ptr: &[String],
    srv: &HashMap<String, (String, u16)>,
    a: &HashMap<String, Vec<Ipv4Addr>>,
) -> Vec<Ipv4Addr> {
    let instances: HashSet<&String> = ptr.iter().collect();
    let suffix = format!(".{SERVICE}");
    let mut out: Vec<Ipv4Addr> = Vec::new();
    for (name, (target, _port)) in srv {
        let is_mqtt = instances.contains(name) || name.ends_with(&suffix);
        if !is_mqtt {
            continue;
        }
        if let Some(ips) = a.get(target) {
            for ip in ips {
                if !out.contains(ip) {
                    out.push(*ip);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_ptr_query_has_the_expected_shape() {
        let q = build_ptr_query("_mqtt._tcp.local", true);
        // Header: QDCOUNT = 1, everything else 0.
        assert_eq!(&q[0..12], &[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        // QNAME labels: 5 "_mqtt", 4 "_tcp", 5 "local", 0.
        assert_eq!(q[12], 5);
        assert_eq!(&q[13..18], b"_mqtt");
        assert_eq!(q[18], 4);
        assert_eq!(&q[19..23], b"_tcp");
        assert_eq!(q[23], 5);
        assert_eq!(&q[24..29], b"local");
        assert_eq!(q[29], 0);
        // QTYPE = PTR (12), QCLASS = IN | QU bit (0x8001) when unicast response is requested.
        assert_eq!(&q[30..34], &[0x00, 0x0C, 0x80, 0x01]);
    }

    #[test]
    fn build_ptr_query_uses_multicast_qclass_when_not_unicast() {
        // On the shared 5353 socket we ask for a MULTICAST answer: QCLASS = IN with the QU bit
        // CLEARED (0x0001), so a co-bound Avahi can't consume a unicast reply meant for us.
        let q = build_ptr_query("_mqtt._tcp.local", false);
        assert_eq!(&q[30..34], &[0x00, 0x0C, 0x00, 0x01]);
    }

    /// Encode a DNS name as length-prefixed labels + terminator.
    fn enc_name(name: &str, out: &mut Vec<u8>) {
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }

    /// Build a minimal mDNS response advertising one `_mqtt._tcp` instance with SRV + A.
    fn sample_response(instance: &str, host: &str, port: u16, ip: [u8; 4]) -> Vec<u8> {
        let mut b = vec![0, 0, 0x84, 0x00]; // id 0, flags = response|AA
        b.extend_from_slice(&[0, 0]); // QDCOUNT
        b.extend_from_slice(&[0, 3]); // ANCOUNT = PTR + SRV + A
        b.extend_from_slice(&[0, 0, 0, 0]); // NS, AR
        // PTR: _mqtt._tcp.local -> instance
        enc_name(SERVICE, &mut b);
        b.extend_from_slice(&[0, 12, 0, 1]); // type PTR, class IN
        b.extend_from_slice(&[0, 0, 0, 120]); // TTL
        let mut rd = Vec::new();
        enc_name(instance, &mut rd);
        b.extend_from_slice(&[(rd.len() >> 8) as u8, rd.len() as u8]);
        b.extend_from_slice(&rd);
        // SRV: instance -> host:port
        enc_name(instance, &mut b);
        b.extend_from_slice(&[0, 33, 0, 1]);
        b.extend_from_slice(&[0, 0, 0, 120]);
        let mut sd = vec![0, 0, 0, 0, (port >> 8) as u8, port as u8]; // prio, weight, port
        enc_name(host, &mut sd);
        b.extend_from_slice(&[(sd.len() >> 8) as u8, sd.len() as u8]);
        b.extend_from_slice(&sd);
        // A: host -> ip
        enc_name(host, &mut b);
        b.extend_from_slice(&[0, 1, 0, 1]);
        b.extend_from_slice(&[0, 0, 0, 120]);
        b.extend_from_slice(&[0, 4]);
        b.extend_from_slice(&ip);
        b
    }

    #[test]
    fn parse_and_correlate_extracts_the_broker_ip() {
        let resp = sample_response("Mosquitto._mqtt._tcp.local", "broker.local", 1883, [192, 168, 50, 40]);
        let (mut ptr, mut srv, mut a) = (Vec::new(), HashMap::new(), HashMap::new());
        parse_response(&resp, &mut ptr, &mut srv, &mut a);
        let ips = correlate(&ptr, &srv, &a);
        assert_eq!(ips, vec![Ipv4Addr::new(192, 168, 50, 40)]);
    }

    #[test]
    fn correlate_ignores_unrelated_srv_records() {
        // An SRV/A pair for a DIFFERENT service must not be mistaken for an MQTT broker.
        let mut srv = HashMap::new();
        srv.insert("printer._ipp._tcp.local".to_string(), ("printer.local".to_string(), 631u16));
        let mut a = HashMap::new();
        a.insert("printer.local".to_string(), vec![Ipv4Addr::new(192, 168, 50, 99)]);
        // No PTR for our service, and the SRV name isn't under _mqtt._tcp → dropped.
        assert!(correlate(&[], &srv, &a).is_empty());
    }

    #[test]
    fn correlate_returns_every_a_record_of_a_multihomed_broker() {
        // A broker advertising two A records for its SRV target must yield BOTH addresses,
        // in first-seen order, so the caller can try each (Codex P2).
        let mut srv = HashMap::new();
        srv.insert("Mosquitto._mqtt._tcp.local".to_string(), ("broker.local".to_string(), 1883u16));
        let mut a = HashMap::new();
        a.insert(
            "broker.local".to_string(),
            vec![Ipv4Addr::new(192, 168, 50, 40), Ipv4Addr::new(10, 0, 0, 40)],
        );
        let ips = correlate(&["Mosquitto._mqtt._tcp.local".to_string()], &srv, &a);
        assert_eq!(ips, vec![Ipv4Addr::new(192, 168, 50, 40), Ipv4Addr::new(10, 0, 0, 40)]);
    }

    #[test]
    fn parse_response_accumulates_multiple_a_records_for_one_host() {
        // Two A records for the same host in one datagram must both survive (not overwrite).
        let mut b = vec![0, 0, 0x84, 0x00];
        b.extend_from_slice(&[0, 0]); // QDCOUNT
        b.extend_from_slice(&[0, 2]); // ANCOUNT = two A records
        b.extend_from_slice(&[0, 0, 0, 0]); // NS, AR
        for ip in [[192u8, 168, 50, 40], [10, 0, 0, 40]] {
            enc_name("broker.local", &mut b);
            b.extend_from_slice(&[0, 1, 0, 1]); // type A, class IN
            b.extend_from_slice(&[0, 0, 0, 120]); // TTL
            b.extend_from_slice(&[0, 4]); // RDLENGTH
            b.extend_from_slice(&ip);
        }
        let (mut ptr, mut srv, mut a) = (Vec::new(), HashMap::new(), HashMap::new());
        parse_response(&b, &mut ptr, &mut srv, &mut a);
        assert_eq!(
            a.get("broker.local"),
            Some(&vec![Ipv4Addr::new(192, 168, 50, 40), Ipv4Addr::new(10, 0, 0, 40)])
        );
    }

    #[test]
    fn read_name_follows_compression_pointers() {
        // "local" at offset 12; then "broker" + pointer(12) at offset 18.
        let mut b = vec![0u8; 12];
        b.push(5);
        b.extend_from_slice(b"local");
        b.push(0);
        let start = b.len(); // 18
        b.push(6);
        b.extend_from_slice(b"broker");
        b.push(0xC0);
        b.push(12); // pointer to "local"
        let mut pos = start;
        assert_eq!(read_name(&b, &mut pos), "broker.local");
        // pos advanced past the 2-byte pointer, not into the target.
        assert_eq!(pos, b.len());
    }

    #[tokio::test]
    async fn bind_reuse_produces_a_usable_socket() {
        // Exercise the raw-libc reuse path at runtime (port 0 → kernel-assigned, so it never
        // clashes with a real mDNS responder). Confirms the sockaddr/setsockopt calls are valid.
        let sock = bind_reuse(0).expect("reuse bind should succeed");
        let addr = sock.local_addr().expect("bound socket has a local address");
        assert!(addr.port() != 0); // the kernel assigned a concrete port
    }

    #[test]
    fn parse_response_ignores_truncated_datagram() {
        let (mut ptr, mut srv, mut a) = (Vec::new(), HashMap::new(), HashMap::new());
        parse_response(&[0, 0, 0], &mut ptr, &mut srv, &mut a); // < 12 bytes
        assert!(ptr.is_empty() && srv.is_empty() && a.is_empty());
    }
}
