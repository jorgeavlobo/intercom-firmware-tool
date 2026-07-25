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

/// The service we look for. Lower-case: all parsed names are lower-cased so correlation is a
/// plain string match (DNS names are ASCII, case-insensitive).
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

    if let Ok(sock) = open_socket().await {
        let query = build_ptr_query(SERVICE);
        let _ = sock.send_to(&query, (MDNS_GROUP, MDNS_PORT)).await;

        let deadline = tokio::time::sleep(window);
        tokio::pin!(deadline);
        let mut buf = [0u8; 4096];
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

/// A UDP socket for the exchange: preferably bound to 5353 and joined to the group (so it
/// receives BOTH multicast responses — the common case — and unicast QU replies); falls back
/// to an ephemeral port (QU-only) when 5353 can't be bound (a system mDNS responder holds it).
/// TTL 255 per RFC 6762 §11.
async fn open_socket() -> std::io::Result<UdpSocket> {
    match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, MDNS_PORT)).await {
        Ok(sock) => {
            let _ = sock.join_multicast_v4(MDNS_GROUP, Ipv4Addr::UNSPECIFIED);
            let _ = sock.set_multicast_ttl_v4(255);
            Ok(sock)
        }
        Err(_) => {
            let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
            let _ = sock.set_multicast_ttl_v4(255);
            Ok(sock)
        }
    }
}

// ---------------------------------------------------------------------------
// Pure wire helpers (unit-tested). No I/O — ported from MqttBrokerDiscovery.cs.
// ---------------------------------------------------------------------------

/// Build a standard-query datagram for a single PTR record with the mDNS unicast-response
/// (QU) bit set, so responders may reply to our source port.
fn build_ptr_query(name: &str) -> Vec<u8> {
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
    b.extend_from_slice(&[0x80, 0x01]); // QCLASS = IN with the QU (unicast response) bit
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
        let q = build_ptr_query("_mqtt._tcp.local");
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
        // QTYPE = PTR (12), QCLASS = IN | QU bit (0x8001).
        assert_eq!(&q[30..34], &[0x00, 0x0C, 0x80, 0x01]);
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

    #[test]
    fn parse_response_ignores_truncated_datagram() {
        let (mut ptr, mut srv, mut a) = (Vec::new(), HashMap::new(), HashMap::new());
        parse_response(&[0, 0, 0], &mut ptr, &mut srv, &mut a); // < 12 bytes
        assert!(ptr.is_empty() && srv.is_empty() && a.is_empty());
    }
}
