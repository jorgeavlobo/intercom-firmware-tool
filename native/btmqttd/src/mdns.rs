//! Hand-rolled mDNS / DNS-SD discovery of `_mqtt._tcp.local` (issue #49 item 2, #43 Layer B).
//!
//! ## Why hand-rolled
//! The statically-linked musl binary's resolver ignores `nsswitch`/system mDNS, so — exactly
//! as the WPF app does at config time (`MqttBrokerDiscovery.cs`) — we speak the mDNS wire
//! protocol directly: send PTR queries for the MQTT DNS-SD services (`_mqtt._tcp.local` plus the
//! TLS `_secure-mqtt._tcp.local`) to the link-local multicast group `224.0.0.251:5353` and parse
//! the PTR/SRV/A records the brokers answer with, yielding the advertised IPv4 address(es)
//! directly — no `/24` port scan. The query asks for a MULTICAST
//! answer when we co-bind the shared 5353 port (so a system responder can't consume a unicast
//! reply meant for us) and only sets the unicast-response (QU) bit on the solely-owned
//! ephemeral-port fallback (see `open_socket`).
//!
//! Used by `rediscovery::rediscover` as the FIRST (cheap, name-based, cross-`/24`-on-link)
//! rediscovery layer, before the brute-force subnet scan. The trust boundary is unchanged:
//! mDNS only PROPOSES an address; the caller repoints `/etc/hosts` and the main client's
//! authenticated + pinned-TLS reconnect is the gate (plaintext additionally requires an ARP
//! MAC match, applied by the caller). Never panics: socket/parse failures just yield no
//! candidates.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rumqttc::{AsyncClient, QoS};
use tokio::net::UdpSocket;

/// The IPv4 link-local mDNS multicast group and port (RFC 6762).
const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

/// The DNS-SD services we look for, both IANA-registered: `_mqtt._tcp` is plaintext MQTT
/// (port 1883) and `_secure-mqtt._tcp` is MQTT over TLS (port 8883). A TLS-configured broker
/// commonly advertises ONLY the secure service, so querying just `_mqtt._tcp` would miss it and
/// leave a moved TLS broker undiscoverable across subnets. We query both and merge; the
/// caller's trust gate (pinned-cert reconnect under TLS, ARP-MAC under plaintext) still decides
/// what is adopted, so an advertised service that doesn't match the configured transport is
/// simply filtered out downstream.
///
/// Lower-case: parsed names are ASCII-case-folded (via `to_ascii_lowercase`) so correlation
/// against these constants is a plain string match. DNS compares ASCII letters
/// case-insensitively; any non-ASCII bytes in a DNS-SD instance label are left as-is, which is
/// harmless here — only the ASCII service suffix needs to match.
const SERVICE: &str = "_mqtt._tcp.local";
const SERVICE_TLS: &str = "_secure-mqtt._tcp.local";
const SERVICES: [&str; 2] = [SERVICE, SERVICE_TLS];

/// Home Assistant's own DNS-SD service (issue #52). HA's `zeroconf` integration is on by default
/// and always advertises `_home-assistant._tcp.local`; the Mosquitto broker add-on, by contrast,
/// does NOT advertise `_mqtt._tcp` by default, so on the common "HA OS + Mosquitto add-on" topology
/// the MQTT services above find nothing. We query HA separately to learn the HA HOST IP(s) — the
/// advertised SRV port is HA's frontend (8123), NOT the broker, so it is ignored; the caller
/// port-probes the CONFIGURED MQTT port on each HA host and trust-gates it like any other proposal.
const HA_SERVICE: &str = "_home-assistant._tcp.local";

/// Query the MQTT DNS-SD services (`_mqtt._tcp` + `_secure-mqtt._tcp`) on the LAN for `window`
/// and return the distinct advertised IPv4 addresses of MQTT brokers (correlated PTR→SRV→A).
/// Empty on any socket failure or no answer. Only the IP is returned — the caller repoints the
/// CONFIGURED broker name to it, so the mDNS-advertised instance/host name is not needed.
pub async fn discover_ips(window: Duration) -> Vec<Ipv4Addr> {
    discover_service_ips(&SERVICES, window).await
}

/// Query Home Assistant's DNS-SD service (`_home-assistant._tcp`) on the LAN for `window` and
/// return the distinct HA HOST IPv4 addresses (correlated PTR→SRV→A). The advertised SRV port is
/// HA's frontend, not the broker, so it is discarded here — the caller probes the CONFIGURED MQTT
/// port on each returned host and trust-gates it like any other proposal (issue #52). Empty on any
/// socket failure or no answer.
pub async fn discover_ha_hosts(window: Duration) -> Vec<Ipv4Addr> {
    discover_service_ips(&[HA_SERVICE], window).await
}

/// Shared engine for [`discover_ips`] and [`discover_ha_hosts`]: send one PTR query per service in
/// `services`, follow up with SRV/A queries for still-unresolved instances/targets inside the same
/// window, then return the correlated A-record IPv4s — each service in `services` order, deduped.
async fn discover_service_ips(services: &[&str], window: Duration) -> Vec<Ipv4Addr> {
    let mut ptr: Vec<String> = Vec::new();
    let mut srv: HashMap<String, (String, u16)> = HashMap::new();
    // A host may advertise MORE THAN ONE A record (a multihomed broker): keep every
    // distinct address per name so a target reachable on one interface is not lost when
    // a later, unreachable A record for the same host arrives.
    let mut a: HashMap<String, Vec<Ipv4Addr>> = HashMap::new();

    if let Ok((sock, unicast_response)) = open_socket().await {
        // One PTR query per service (plaintext + TLS), so a broker advertising only the secure
        // service is still discovered.
        let queries: Vec<Vec<u8>> = services
            .iter()
            .filter_map(|svc| build_query(svc, QTYPE_PTR, unicast_response))
            .collect();
        for q in &queries {
            let _ = sock.send_to(q, (MDNS_GROUP, MDNS_PORT)).await;
        }

        let deadline = tokio::time::sleep(window);
        tokio::pin!(deadline);
        // Retransmit the queries ONCE partway through the window: a single UDP probe lost on
        // Wi-Fi would otherwise yield no candidates and push the caller into a full /24 sweep
        // (RFC 6762 §5.2 querier behaviour retransmits). One extra datagram per service, same
        // window.
        let retry = tokio::time::sleep(window / 2);
        tokio::pin!(retry);
        let mut retried = false;
        // RFC 6762 §17 caps an mDNS message (incl. IP+UDP headers) at 9000 bytes; a smaller
        // buffer would let the kernel silently TRUNCATE a large datagram (many additional
        // records on a chatty LAN), and the bounds-checked parser would then bail early and
        // miss an otherwise-valid broker answer. Size for the RFC maximum.
        let mut buf = [0u8; 9000];
        // A minimal responder may answer a PTR query with ONLY the PTR record (SRV/A are
        // recommended additional answers, not guaranteed — RFC 6763 §12), leaving nothing to
        // correlate. So follow up within the same window: query SRV for each PTR instance still
        // missing one, and A for each SRV target still missing one, each sent at most once.
        let mut srv_queried: HashSet<String> = HashSet::new();
        let mut a_queried: HashSet<String> = HashSet::new();
        let svc_suffixes: Vec<String> = services.iter().map(|s| format!(".{s}")).collect();
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                _ = &mut retry, if !retried => {
                    retried = true;
                    for q in &queries {
                        let _ = sock.send_to(q, (MDNS_GROUP, MDNS_PORT)).await;
                    }
                }
                r = sock.recv_from(&mut buf) => match r {
                    Ok((n, _)) => {
                        parse_response(&buf[..n], services, &mut ptr, &mut srv, &mut a);
                        for inst in &ptr {
                            if !srv.contains_key(inst) && srv_queried.insert(inst.clone()) {
                                if let Some(q) = build_query(inst, QTYPE_SRV, unicast_response) {
                                    let _ = sock.send_to(&q, (MDNS_GROUP, MDNS_PORT)).await;
                                }
                            }
                        }
                        for (name, (target, _port)) in &srv {
                            // Only chase A records for SRV entries under OUR MQTT services: `srv`
                            // accumulates every service seen on the shared socket, and A-querying
                            // all of them would be needless multicast amplification on the device.
                            // `correlate` filters the final output regardless.
                            if !svc_suffixes.iter().any(|suf| name.ends_with(suf)) {
                                continue;
                            }
                            if !a.contains_key(target) && a_queried.insert(target.clone()) {
                                if let Some(q) = build_query(target, QTYPE_A, unicast_response) {
                                    let _ = sock.send_to(&q, (MDNS_GROUP, MDNS_PORT)).await;
                                }
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
    // Correlate each service in order (for MQTT: plaintext first, then TLS); merge, deduped.
    let mut out: Vec<Ipv4Addr> = Vec::new();
    for svc in services {
        for ip in correlate(&ptr, &srv, &a, svc) {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

/// A UDP socket for the exchange, plus whether to ask for a UNICAST response (the QU bit).
///
/// Preferred: bind 5353 (with `SO_REUSEADDR` + `SO_REUSEPORT`) and join the group, so we co-bind
/// alongside a system mDNS responder (e.g. Avahi) that already holds the port. On this
/// SHARED socket we must ask for a MULTICAST answer (`unicast_response = false`): a unicast reply
/// to 5353 is delivered to only ONE of the co-bound sockets, so Avahi could consume the broker's
/// answer and leave us empty-handed — a multicast answer, by contrast, is copied to every
/// socket joined to the group. The preferred socket is usable ONLY if the JOIN also succeeds —
/// otherwise we would request a multicast answer on a socket not subscribed to receive it and
/// hear nothing, so a failed join falls through to the fallback like a failed
/// bind. Fallback: an ephemeral port we solely own, where we did NOT join the group and so must
/// ask for a UNICAST reply (`unicast_response = true`) to receive anything. TTL 255 per §11.
async fn open_socket() -> std::io::Result<(UdpSocket, bool)> {
    // Preferred: co-bind 5353 AND join the group — both must succeed to request multicast answers.
    if let Ok(sock) = bind_reuse(MDNS_PORT) {
        if sock.join_multicast_v4(MDNS_GROUP, Ipv4Addr::UNSPECIFIED).is_ok() {
            let _ = sock.set_multicast_ttl_v4(255);
            return Ok((sock, false)); // shared 5353 + joined group → request MULTICAST answers
        }
    }
    // Fallback: an ephemeral port we solely own → request UNICAST answers (QU).
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    let _ = sock.set_multicast_ttl_v4(255);
    Ok((sock, true))
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
        // SOCK_CLOEXEC so this fd is not leaked into the shells btmqttd spawns per command
        // (std/tokio set it on their own sockets; the raw path must too).
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
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
        // SO_REUSEADDR. Any other error is still surfaced.
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

/// DNS record types we query/parse.
const QTYPE_A: u16 = 1;
const QTYPE_PTR: u16 = 12;
const QTYPE_SRV: u16 = 33;
/// The wildcard query type (`*`): a querier asking for ANY record of a name, which our responder must
/// also answer for an A-record host (RFC 6762 §6).
const QTYPE_ANY: u16 = 255;

/// Split a DNS presentation-format name into its wire labels, reversing the `\.`/`\\` escaping
/// that [`read_name`] applies. A `\` escapes the next character (so an escaped `.` stays inside a
/// label); an unescaped `.` separates labels. A trailing empty label (from a trailing dot) is
/// preserved so [`build_query`] can reject it.
fn presentation_labels(name: &str) -> Vec<String> {
    let mut labels = Vec::new();
    let mut cur = String::new();
    let mut chars = name.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                if let Some(next) = chars.next() {
                    cur.push(next);
                }
            }
            '.' => labels.push(std::mem::take(&mut cur)),
            _ => cur.push(ch),
        }
    }
    labels.push(cur);
    labels
}

/// Build a standard-query datagram for a single record of `qtype` (PTR/SRV/A), or `None` if
/// `name` doesn't fit the DNS wire limits (RFC 1035 §2.3.4): each label 1..=63 bytes and the
/// encoded QNAME (labels + length octets + root) <= 255. The follow-up SRV/A queries reuse
/// instance/target names parsed from UNTRUSTED responses, so an out-of-range name yields `None`
/// (the caller skips it) instead of a malformed datagram.
///
/// When `unicast_response` is set, the mDNS unicast-response (QU) top bit of QCLASS is set so
/// responders reply to our source port — used ONLY on the solely-owned ephemeral socket. On the
/// shared 5353 socket it is cleared, i.e. a normal multicast-response (QM) question, so the answer
/// reaches every co-bound listener.
fn build_query(name: &str, qtype: u16, unicast_response: bool) -> Option<Vec<u8>> {
    // Honour `\.`/`\\` escaping so a label that contained a literal dot round-trips as ONE label,
    // rather than splitting on the presentation separator.
    let labels = presentation_labels(name);
    let mut encoded_len = 1usize; // the terminating root label
    for label in &labels {
        let l = label.len();
        if l == 0 || l > 63 {
            return None;
        }
        encoded_len += 1 + l; // length octet + label bytes
    }
    if encoded_len > 255 {
        return None;
    }
    let mut b = vec![
        0x00, 0x00, // ID (0 for mDNS)
        0x00, 0x00, // flags: standard query
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ];
    for label in &labels {
        b.push(label.len() as u8); // <= 63, checked above
        b.extend_from_slice(label.as_bytes());
    }
    b.push(0x00); // end of QNAME
    b.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    // QCLASS = IN (0x0001); the top bit is the mDNS QU (unicast-response) request.
    let qclass: u16 = if unicast_response { 0x8001 } else { 0x0001 };
    b.extend_from_slice(&qclass.to_be_bytes());
    Some(b)
}

/// Parse a DNS response into the PTR/SRV/A accumulators (names lower-cased). Bounds-checked
/// throughout; a truncated/odd record just stops parsing that datagram.
fn parse_response(
    b: &[u8],
    services: &[&str],
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
            12 if services.contains(&name.as_str()) => {
                // PTR: the RDATA is the instance name. Require it to decode WITHIN this record's
                // RDLENGTH; a malformed datagram whose name has no terminator inside RDATA would
                // otherwise let read_name splice in bytes from the following record and forge a
                // false instance name.
                let mut pp = rd;
                let instance = read_name(b, &mut pp);
                if !instance.is_empty() && pp <= rd + rdlen {
                    ptr.push(instance);
                }
            }
            33 if rdlen >= 6 => {
                // SRV: priority(2) weight(2) port(2) target(name). The target must decode WITHIN
                // this record's RDATA; if it overran `rd + rdlen` (a malformed datagram with no
                // terminator inside RDLENGTH), reject it rather than accept a target spliced from
                // the following record's bytes. A compression pointer advances `pp` by
                // only its 2 bytes, so a legitimate target always lands at or before rd + rdlen.
                let port = ((b[rd + 4] as u16) << 8) | b[rd + 5] as u16;
                let mut pp = rd + 6;
                let target = read_name(b, &mut pp);
                if !target.is_empty() && port > 0 && pp <= rd + rdlen {
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
        // Ordinary label: the top two bits must be 00 (0x40/0x80 are RFC 1035 reserved), so a
        // length octet > 63 here is malformed — stop rather than decode a garbage label from
        // untrusted LAN input. Pointers (0xC0) are already handled above.
        if c > 63 {
            break;
        }
        // ordinary label
        p += 1;
        if p + c > len {
            break;
        }
        if !out.is_empty() {
            out.push('.');
        }
        // Escape a `.` (and `\`) that occurs INSIDE a wire label — DNS-SD instance labels may
        // legally contain a literal dot (e.g. "70-35-60-63.1"). Without escaping, a follow-up
        // query rebuilt by splitting on `.` would break one label into two and ask for a
        // different name. `presentation_labels` reverses this.
        for ch in String::from_utf8_lossy(&b[p..p + c]).to_ascii_lowercase().chars() {
            if ch == '.' || ch == '\\' {
                out.push('\\');
            }
            out.push(ch);
        }
        p += c;
    }
    if !jumped {
        *pos = p;
    }
    out
}

/// Correlate the accumulated records into the advertised broker IPv4s: keep only SRV records
/// that actually belong to `service` (an instance the PTR pointed to, or a name of the form
/// `<instance>.<service>`), resolve each SRV target through the A records (every A record the
/// target carries, not just one — a multihomed broker has several), and return the distinct IPs.
/// A chatty responder's unrelated SRV+A pairs are ignored.
///
/// The order is DETERMINISTIC (so `mdns_propose`'s "first open candidate" is reproducible across
/// runs, unlike raw `HashMap` iteration): SRV targets named by a PTR come first, in PTR
/// discovery order; then any remaining `<instance>.<service>` SRV records with no PTR, sorted by
/// name.
fn correlate(
    ptr: &[String],
    srv: &HashMap<String, (String, u16)>,
    a: &HashMap<String, Vec<Ipv4Addr>>,
    service: &str,
) -> Vec<Ipv4Addr> {
    let suffix = format!(".{service}");
    let mut out: Vec<Ipv4Addr> = Vec::new();

    // Resolve one SRV target's A records into `out`, de-duplicating.
    fn add_target(target: &str, a: &HashMap<String, Vec<Ipv4Addr>>, out: &mut Vec<Ipv4Addr>) {
        if let Some(ips) = a.get(target) {
            for ip in ips {
                if !out.contains(ip) {
                    out.push(*ip);
                }
            }
        }
    }

    // 1) SRV targets named by a PTR for THIS service (its instances end with the suffix), in PTR
    //    discovery order (the order the responder advertised). The suffix check keeps a PTR for the
    //    OTHER service — the accumulators hold both — from resolving here.
    let mut resolved: HashSet<&String> = HashSet::new();
    for inst in ptr {
        if inst.ends_with(&suffix) {
            if let Some((target, _port)) = srv.get(inst) {
                resolved.insert(inst);
                add_target(target, a, &mut out);
            }
        }
    }
    // 2) Remaining `<instance>.<service>` SRV records with no PTR, sorted by name so the result
    //    is stable across runs.
    let mut rest: Vec<&String> = srv
        .keys()
        .filter(|name| !resolved.contains(*name) && name.ends_with(&suffix))
        .collect();
    rest.sort_unstable();
    for name in rest {
        if let Some((target, _port)) = srv.get(name) {
            add_target(target, a, &mut out);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Camera mDNS host resolution (issue #171) — the `<name>.local` the panel is
// reachable on, published as a retained diagnostic so Home Assistant can address
// the live RTSP stream and the idle still endpoint by name instead of a DHCP IP.
// ---------------------------------------------------------------------------

/// The factory Avahi responder config (present + running on the C100X, absent on the C300X).
const AVAHI_CONF_PATH: &str = "/etc/avahi/avahi-daemon.conf";
/// The kernel hostname, e.g. `Bticino_Classe_100_X` / `Bticino_Classe_300_X`.
const ETC_HOSTNAME_PATH: &str = "/etc/hostname";

/// Extract the `host-name=` value from an `avahi-daemon.conf`, or `None` if unset/commented.
///
/// Avahi's `[server]` `host-name` key (when set) is the label it advertises as `<value>.local`,
/// overriding `/etc/hostname` — so the C100X advertises `Bticino-Classe100X.local` even though its
/// kernel hostname is `Bticino_Classe_100_X`. A commented (`#host-name=…`) or absent key yields
/// `None` (Avahi would then derive the name from the kernel hostname, handled by the caller). Pure;
/// unit-tested.
pub(crate) fn parse_avahi_host_name(conf: &str) -> Option<String> {
    for line in conf.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("host-name") {
            // Accept `host-name=X` / `host-name = X` — the key must be exactly `host-name`, not a
            // longer key like `host-name-from-machine-id`, so require `=` (after optional spaces)
            // to be the next non-space character.
            let val = rest.trim_start();
            if let Some(val) = val.strip_prefix('=') {
                // A hostname is a single DNS label token (letters/digits/hyphen, optionally
                // dot-qualified) — never whitespace or a comment marker. Take only the first token so
                // an inline comment (`host-name=Foo # factory`) or trailing junk can't leak into the
                // published `<name>.local`.
                let val = val
                    .trim()
                    .split(|c: char| c.is_whitespace() || c == '#' || c == ';')
                    .next()
                    .unwrap_or("");
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/// Derive the panel's `Bticino-Classe<model>X` mDNS label from its kernel hostname (the naming
/// convention the C100X factory uses, applied uniformly). `Bticino_Classe_100_X` → `Bticino-Classe100X`,
/// `Bticino_Classe_300_X` → `Bticino-Classe300X`. Returns `None` if no model digits are present, so
/// the caller can fall back rather than advertise a modelless name. Pure; unit-tested.
pub(crate) fn model_host_from_hostname(etc_hostname: &str) -> Option<String> {
    let digits: String = etc_hostname.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    Some(format!("Bticino-Classe{digits}X"))
}

/// The configured Avahi `host-name` (`<value>`, no `.local`), or `None` if unset/unreadable.
async fn read_avahi_host_name() -> Option<String> {
    tokio::fs::read_to_string(AVAHI_CONF_PATH)
        .await
        .ok()
        .and_then(|c| parse_avahi_host_name(&c))
}

/// The kernel hostname (trimmed), or `None` if empty/unreadable.
async fn read_system_hostname() -> Option<String> {
    tokio::fs::read_to_string(ETC_HOSTNAME_PATH)
        .await
        .ok()
        .map(|h| h.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// C100X path — the name the FACTORY Avahi actually advertises, so the HA sensors match what it
/// resolves: its configured `host-name` if set, else Avahi's own fallback, the RAW system hostname
/// (NOT the model-derived name — Avahi doesn't reshape it). btmqttd only REPORTS this; it never runs
/// its own responder where Avahi is present. `None` only if neither file yields a usable label.
pub async fn resolve_avahi_or_system_host() -> Option<String> {
    let label = match read_avahi_host_name().await {
        Some(l) => l,
        None => read_system_hostname().await?,
    };
    ensure_dot_local(&label)
}

/// C300X path — the base `<name>.local` btmqttd's OWN responder advertises: a configured Avahi
/// `host-name` if somehow present, else the `Bticino-Classe<model>X` name derived from the kernel
/// hostname (the factory C100X convention, applied uniformly; conflict resolution may append `-N`).
/// `None` if no model digits are present. Used only where no system responder owns the name.
pub async fn resolve_responder_base_host() -> Option<String> {
    let label = match read_avahi_host_name().await {
        Some(l) => l,
        None => model_host_from_hostname(read_system_hostname().await?.as_str())?,
    };
    ensure_dot_local(&label)
}

/// Normalize `label` to a bare `<name>.local` mDNS name: append `.local` only when it isn't already
/// there (case-insensitive) and drop any trailing FQDN dot, so an already-qualified Avahi `host-name`
/// (or a future fully-qualified caller) can't become `<name>.local.local`. `None` if nothing usable
/// remains. Pure; unit-tested.
fn ensure_dot_local(label: &str) -> Option<String> {
    let label = label.trim().trim_end_matches('.').trim();
    if label.is_empty() {
        return None;
    }
    if label.to_ascii_lowercase().ends_with(".local") {
        Some(label.to_string())
    } else {
        Some(format!("{label}.local"))
    }
}

// ---------------------------------------------------------------------------
// mDNS responder (issue #171 Part B) — advertise OUR OWN `<name>.local` A record
// on models WITHOUT a factory responder (the C300X). On the C100X the factory Avahi
// already owns `Bticino-Classe100X.local`, so a second responder would trigger mDNS
// name-conflict flapping — the caller must NOT run this there (see
// `system_mdns_responder_present`); it only READS that name for the Part A sensors.
// ---------------------------------------------------------------------------

/// The factory Avahi responder binary. Its PRESENCE marks a model whose system already owns the
/// `.local` name (the C100X), so btmqttd must not advertise — the discriminator the issue asks for
/// ("presence of avahi-daemon", not a hard-coded model).
const AVAHI_DAEMON_PATH: &str = "/usr/sbin/avahi-daemon";

/// A-record TTL for our answers/announcements. RFC 6762 §10 recommends 120 s for hostname records.
const RESPONDER_TTL: u32 = 120;

/// True when a system mDNS responder (Avahi) owns the `.local` name on this model, so btmqttd must
/// NOT run its own responder. Detected by the presence of the Avahi daemon binary (C100X ships it,
/// C300X does not), which is stable and independent of boot timing. Never panics.
pub async fn system_mdns_responder_present() -> bool {
    tokio::fs::metadata(AVAHI_DAEMON_PATH).await.is_ok()
}

/// Encode `name` as a DNS wire QNAME (length-prefixed labels + root), honouring `\.`/`\\` escaping,
/// or `None` if it violates the RFC 1035 limits (each label 1..=63 bytes, encoded QNAME <= 255). Our
/// name is the fixed `Bticino-Classe<model>X.local`, well within the bounds, but the limit is enforced
/// anyway so a future caller can't emit a malformed answer.
fn encode_qname(name: &str, out: &mut Vec<u8>) -> Option<()> {
    let labels = presentation_labels(name);
    let mut encoded_len = 1usize; // terminating root label
    for label in &labels {
        let l = label.len();
        if l == 0 || l > 63 {
            return None;
        }
        encoded_len += 1 + l;
    }
    if encoded_len > 255 {
        return None;
    }
    for label in &labels {
        out.push(label.len() as u8); // <= 63, checked above
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0x00);
    Some(())
}

/// Build an mDNS response advertising `name` → `ip` as a single A record: an authoritative answer
/// (QR=1, AA=1) with the mDNS cache-flush bit set on the record's class (RFC 6762 §10.2 — our host
/// address is unique, so resolvers replace rather than accumulate) and a `RESPONDER_TTL` TTL. `None`
/// only if `name` doesn't fit the DNS wire limits.
fn build_a_response(name: &str, ip: Ipv4Addr) -> Option<Vec<u8>> {
    let mut b = vec![
        0x00, 0x00, // ID 0 (mDNS)
        0x84, 0x00, // flags: QR=1 (response), AA=1 (authoritative)
        0x00, 0x00, // QDCOUNT
        0x00, 0x01, // ANCOUNT = 1
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ];
    encode_qname(name, &mut b)?;
    b.extend_from_slice(&QTYPE_A.to_be_bytes()); // TYPE = A
    // CLASS = IN (0x0001) | cache-flush bit (0x8000).
    b.extend_from_slice(&0x8001u16.to_be_bytes());
    b.extend_from_slice(&RESPONDER_TTL.to_be_bytes());
    b.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4 (one IPv4)
    b.extend_from_slice(&ip.octets());
    Some(b)
}

/// True when datagram `b` is an mDNS QUERY carrying a question for `our_name` (compared
/// case-insensitively) of type A or ANY — i.e. "what is `<name>.local`'s address?". A response
/// (QR=1), an unrelated name/type, or a truncated datagram yields false. Bounds-checked throughout.
fn query_asks_for_a(b: &[u8], our_name: &str) -> bool {
    if b.len() < 12 {
        return false;
    }
    if b[2] & 0x80 != 0 {
        return false; // QR=1 → a response, not a query
    }
    let qd = ((b[4] as usize) << 8) | b[5] as usize;
    let mut pos = 12usize;
    for _ in 0..qd {
        let name = read_name(b, &mut pos);
        if pos + 4 > b.len() {
            return false;
        }
        let qtype = ((b[pos] as u16) << 8) | b[pos + 1] as u16;
        pos += 4;
        if (qtype == QTYPE_A || qtype == QTYPE_ANY) && name.eq_ignore_ascii_case(our_name) {
            return true;
        }
    }
    false
}

/// Co-bind the shared 5353 mDNS port and JOIN the group, so we both receive queries and can multicast
/// answers. `None` if the bind or join fails (without the socket there is no responder; the still
/// endpoint is still reachable by IP, so this is a soft failure, not a panic).
async fn open_responder_socket() -> Option<UdpSocket> {
    let sock = bind_reuse(MDNS_PORT).ok()?;
    sock.join_multicast_v4(MDNS_GROUP, Ipv4Addr::UNSPECIFIED).ok()?;
    let _ = sock.set_multicast_ttl_v4(255);
    Some(sock)
}

/// The next candidate name after an mDNS conflict (RFC 6762 §9): increment a trailing `-N` on the
/// label (before `.local`), starting at `-2`. `Bticino-Classe300X.local` → `Bticino-Classe300X-2.local`
/// → `…-3.local`. The `Bticino-Classe` hyphen is preserved because its tail (`Classe300X`) isn't a
/// bare number. Pure; unit-tested.
fn next_conflict_name(name: &str) -> String {
    let (label, suffix) = match name.strip_suffix(".local") {
        Some(l) => (l, ".local"),
        None => (name, ""),
    };
    match label
        .rsplit_once('-')
        .and_then(|(head, tail)| tail.parse::<u32>().ok().map(|n| (head, n)))
    {
        Some((head, n)) => format!("{head}-{}{suffix}", n + 1),
        None => format!("{label}-2{suffix}"),
    }
}

/// True when datagram `b` means our claim to `our_name_lc` LOSES — i.e. we must pick another name.
/// Reuses [`parse_response`] to pull every A record for our name (in any section, so a probe's
/// authority record counts too):
/// - a RESPONSE (QR=1) carrying our name at a DIFFERENT address = an already-committed owner, so we
///   always yield;
/// - a simultaneous PROBE (QR=0) proposing a NUMERICALLY-GREATER address wins the RFC 6762 §8.2
///   address tiebreak, so we yield to it; a lesser address loses, so we keep our name.
///
/// Our own record echoed back (same address) is ignored. Bounds-checked via `parse_response`.
fn datagram_conflict(b: &[u8], our_name_lc: &str, our_ip: Ipv4Addr) -> bool {
    if b.len() < 12 {
        return false;
    }
    let is_response = b[2] & 0x80 != 0;
    let (mut ptr, mut srv, mut a) = (Vec::new(), HashMap::new(), HashMap::new());
    // Empty `services` → no PTR is collected (we only need A records); A/SRV parse regardless.
    parse_response(b, &[], &mut ptr, &mut srv, &mut a);
    if let Some(ips) = a.get(our_name_lc) {
        for &ip in ips {
            if ip == our_ip {
                continue; // our own record looped back
            }
            if is_response || ip > our_ip {
                return true;
            }
        }
    }
    false
}

/// RFC 6762 §8.1 probing: how many probe queries and how far apart.
const PROBE_COUNT: u32 = 3;
const PROBE_INTERVAL: Duration = Duration::from_millis(250);
/// RFC 6762 §8.3 announcing: how many unsolicited announcements on commit / address change.
const ANNOUNCE_COUNT: u32 = 2;
const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(1);
/// Serve-loop poll slice: also the cadence at which the responder re-checks its own address for a DHCP
/// change (a routing-table probe, so cheap), and bounds how promptly it observes `stopping`. Kept far
/// below the ring cache's 300 s so a DHCP change converges quickly (issue #171 review).
const RESPONDER_TICK: Duration = Duration::from_secs(15);

/// Send `count` unsolicited A-record announcements for `name` → `ip`, `ANNOUNCE_INTERVAL` apart (§8.3).
async fn announce_record(sock: &UdpSocket, name: &str, ip: Ipv4Addr, count: u32) {
    let Some(resp) = build_a_response(name, ip) else {
        return;
    };
    for i in 0..count {
        let _ = sock.send_to(&resp, (MDNS_GROUP, MDNS_PORT)).await;
        if i + 1 < count {
            tokio::time::sleep(ANNOUNCE_INTERVAL).await;
        }
    }
}

/// Probe `name` (§8.1): send `PROBE_COUNT` multicast ANY-queries `PROBE_INTERVAL` apart and listen for
/// a conflict ([`datagram_conflict`] vs `our_ip`). Returns true if the name is TAKEN (or we lose the
/// tiebreak), so the caller renames and re-probes. Bounded by the probe window; returns false early if
/// `stopping` is set.
async fn probe(sock: &UdpSocket, name: &str, name_lc: &str, our_ip: Ipv4Addr, stopping: &AtomicBool) -> bool {
    let query = build_query(name, QTYPE_ANY, false); // QM on the shared 5353 socket
    let mut buf = [0u8; 9000];
    for _ in 0..PROBE_COUNT {
        if stopping.load(Ordering::Relaxed) {
            return false;
        }
        if let Some(q) = &query {
            let _ = sock.send_to(q, (MDNS_GROUP, MDNS_PORT)).await;
        }
        let deadline = tokio::time::sleep(PROBE_INTERVAL);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = &mut deadline => break,
                r = sock.recv_from(&mut buf) => {
                    if let Ok((n, _)) = r {
                        if datagram_conflict(&buf[..n], name_lc, our_ip) {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

/// Advertise the panel's own `<name>.local` A record over mDNS (issue #171 Part B), with full RFC 6762
/// conflict resolution: PROBE the name (§8.1) with the §8.2 address tiebreak, on conflict rename via
/// [`next_conflict_name`] and re-probe, then ANNOUNCE (§8.3), publish the FINAL chosen name retained on
/// `topic` (and expose it in `advertised` for the reconnect re-assert in `announce()`), and answer
/// A/ANY queries — renaming again if a later claim (§9) takes the name. The advertised address is a
/// fresh `still::reachable_ipv4` routing-table probe (a named broker hits `/etc/hosts`, so no network
/// DNS), re-checked every `RESPONDER_TICK`, so a DHCP change converges in seconds — NOT the 300 s ring
/// cache. Exits promptly when `stopping` is set. Never panics.
///
/// MUST be spawned ONLY where no system responder owns the name (see `system_mdns_responder_present`).
pub async fn run_responder(
    base_host: String,
    broker: String,
    client: AsyncClient,
    topic: String,
    advertised: Arc<Mutex<Option<String>>>,
    stopping: Arc<AtomicBool>,
) {
    let Some(sock) = open_responder_socket().await else {
        eprintln!("btmqttd: mdns responder: could not bind :5353 — not advertising {base_host}");
        return;
    };
    let mut buf = [0u8; 9000];
    let mut name = base_host;
    'claim: while !stopping.load(Ordering::Relaxed) {
        // Our own wlan0 source address, resolved fresh (no packet; a named broker hits /etc/hosts).
        // Without it we can neither probe meaningfully nor answer, so wait a tick and retry.
        let Some(mut our_ip) = crate::still::reachable_ipv4(&broker).await else {
            tokio::time::sleep(RESPONDER_TICK).await;
            continue;
        };
        let name_lc = name.to_ascii_lowercase();
        // PROBE (§8.1): if the name is taken, rename and re-probe.
        if probe(&sock, &name, &name_lc, our_ip, &stopping).await {
            name = next_conflict_name(&name);
            continue;
        }
        // COMMIT: announce (§8.3), then publish the chosen name retained + expose it for announce()'s
        // reconnect re-assert. (A prior name's record just times out via its TTL — no goodbye packet.)
        announce_record(&sock, &name, our_ip, ANNOUNCE_COUNT).await;
        if let Ok(mut slot) = advertised.lock() {
            *slot = Some(name.clone());
        }
        if let Err(e) = client
            .publish(&topic, QoS::AtMostOnce, true, name.clone().into_bytes())
            .await
        {
            eprintln!("btmqttd: mdns responder: publish host failed: {e}");
        }
        // SERVE until a conflicting claim forces a rename or we stop.
        while !stopping.load(Ordering::Relaxed) {
            tokio::select! {
                _ = tokio::time::sleep(RESPONDER_TICK) => {
                    // Track a DHCP address change and re-announce so resolvers (and the HA URL) follow.
                    if let Some(ip) = crate::still::reachable_ipv4(&broker).await {
                        if ip != our_ip {
                            our_ip = ip;
                            announce_record(&sock, &name, our_ip, ANNOUNCE_COUNT).await;
                        }
                    }
                }
                r = sock.recv_from(&mut buf) => {
                    if let Ok((n, _)) = r {
                        let pkt = &buf[..n];
                        if query_asks_for_a(pkt, &name_lc) {
                            if let Some(resp) = build_a_response(&name, our_ip) {
                                let _ = sock.send_to(&resp, (MDNS_GROUP, MDNS_PORT)).await;
                            }
                        } else if datagram_conflict(pkt, &name_lc, our_ip) {
                            // Someone else claimed our name (§9): drop it, rename, re-probe.
                            name = next_conflict_name(&name);
                            continue 'claim;
                        }
                    }
                }
            }
        }
        return;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_ptr_query_has_the_expected_shape() {
        let q = build_query("_mqtt._tcp.local", QTYPE_PTR, true).unwrap();
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
    fn build_query_uses_multicast_qclass_when_not_unicast() {
        // On the shared 5353 socket we ask for a MULTICAST answer: QCLASS = IN with the QU bit
        // CLEARED (0x0001), so a co-bound Avahi can't consume a unicast reply meant for us.
        let q = build_query("_mqtt._tcp.local", QTYPE_SRV, false).unwrap();
        assert_eq!(&q[30..34], &[0x00, 0x21, 0x00, 0x01]); // QTYPE=SRV(33), QCLASS=IN, QU cleared
        let q = build_query("_mqtt._tcp.local", QTYPE_PTR, false).unwrap();
        assert_eq!(&q[30..34], &[0x00, 0x0C, 0x00, 0x01]);
    }

    #[test]
    fn build_query_rejects_out_of_range_names() {
        // Follow-up SRV/A queries reuse names parsed from untrusted responses; a label > 63 bytes,
        // an empty label, or a name > 255 bytes must yield None (no datagram) rather than a
        // malformed query.
        let long_label = "a".repeat(64);
        assert!(build_query(&format!("{long_label}._tcp.local"), QTYPE_SRV, true).is_none());
        assert!(build_query("a..local", QTYPE_A, true).is_none()); // empty label
        let long_name = vec!["abcdefghij"; 30].join("."); // 30 valid labels, > 255 bytes total
        assert!(build_query(&long_name, QTYPE_A, true).is_none());
        assert!(build_query("broker.local", QTYPE_A, true).is_some()); // a valid name still builds
    }

    /// Encode a DNS name as length-prefixed labels + terminator.
    fn enc_name(name: &str, out: &mut Vec<u8>) {
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }

    /// Build a minimal mDNS response advertising one `<service>` instance with SRV + A.
    fn sample_response(service: &str, instance: &str, host: &str, port: u16, ip: [u8; 4]) -> Vec<u8> {
        let mut b = vec![0, 0, 0x84, 0x00]; // id 0, flags = response|AA
        b.extend_from_slice(&[0, 0]); // QDCOUNT
        b.extend_from_slice(&[0, 3]); // ANCOUNT = PTR + SRV + A
        b.extend_from_slice(&[0, 0, 0, 0]); // NS, AR
        // PTR: <service> -> instance
        enc_name(service, &mut b);
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
        let resp = sample_response(SERVICE, "Mosquitto._mqtt._tcp.local", "broker.local", 1883, [192, 168, 50, 40]);
        let (mut ptr, mut srv, mut a) = (Vec::new(), HashMap::new(), HashMap::new());
        parse_response(&resp, &SERVICES, &mut ptr, &mut srv, &mut a);
        let ips = correlate(&ptr, &srv, &a, SERVICE);
        assert_eq!(ips, vec![Ipv4Addr::new(192, 168, 50, 40)]);
    }

    #[test]
    fn discovers_home_assistant_host_ip_and_the_mqtt_query_ignores_the_ha_ptr() {
        // Issue #52: an HA instance advertises `_home-assistant._tcp` on its frontend port (8123);
        // we correlate it to the HA HOST IP (the caller discards the SRV port and probes the MQTT
        // port there instead). The SAME datagram parsed while querying only the MQTT services must
        // NOT surface the HA PTR as a broker.
        let resp = sample_response(
            HA_SERVICE,
            "Home._home-assistant._tcp.local",
            "hass.local",
            8123,
            [192, 168, 50, 64],
        );

        // HA query: the PTR is accepted and the host resolves to the HA host IP.
        let (mut ptr, mut srv, mut a) = (Vec::new(), HashMap::new(), HashMap::new());
        parse_response(&resp, &[HA_SERVICE], &mut ptr, &mut srv, &mut a);
        assert_eq!(correlate(&ptr, &srv, &a, HA_SERVICE), vec![Ipv4Addr::new(192, 168, 50, 64)]);

        // MQTT query over the same bytes: the HA PTR is filtered out, so no broker is proposed.
        let (mut ptr2, mut srv2, mut a2) = (Vec::new(), HashMap::new(), HashMap::new());
        parse_response(&resp, &SERVICES, &mut ptr2, &mut srv2, &mut a2);
        assert!(correlate(&ptr2, &srv2, &a2, SERVICE).is_empty());
        assert!(correlate(&ptr2, &srv2, &a2, SERVICE_TLS).is_empty());
    }

    #[test]
    fn correlate_resolves_the_tls_secure_mqtt_service() {
        // A TLS broker advertising only `_secure-mqtt._tcp` must still be found via that service.
        // Its instance/target under the secure suffix resolves through the A records.
        let ptr = vec!["Mosquitto._secure-mqtt._tcp.local".to_string()];
        let mut srv = HashMap::new();
        srv.insert(
            "Mosquitto._secure-mqtt._tcp.local".to_string(),
            ("brokertls.local".to_string(), 8883u16),
        );
        let mut a = HashMap::new();
        a.insert("brokertls.local".to_string(), vec![Ipv4Addr::new(192, 168, 50, 41)]);
        // The plaintext service finds nothing here; the TLS service finds the broker.
        assert!(correlate(&ptr, &srv, &a, SERVICE).is_empty());
        assert_eq!(correlate(&ptr, &srv, &a, SERVICE_TLS), vec![Ipv4Addr::new(192, 168, 50, 41)]);
    }

    #[test]
    fn correlate_order_is_deterministic() {
        // PTR names instance B; A and C are extra `_mqtt._tcp` SRV records with no PTR. The result
        // is B first (PTR order) then A, C by sorted name — stable regardless of HashMap order.
        let ptr = vec!["b._mqtt._tcp.local".to_string()];
        let mut srv = HashMap::new();
        srv.insert("b._mqtt._tcp.local".to_string(), ("hb.local".to_string(), 1883u16));
        srv.insert("a._mqtt._tcp.local".to_string(), ("ha.local".to_string(), 1883u16));
        srv.insert("c._mqtt._tcp.local".to_string(), ("hc.local".to_string(), 1883u16));
        let mut a = HashMap::new();
        a.insert("hb.local".to_string(), vec![Ipv4Addr::new(192, 168, 50, 2)]);
        a.insert("ha.local".to_string(), vec![Ipv4Addr::new(192, 168, 50, 1)]);
        a.insert("hc.local".to_string(), vec![Ipv4Addr::new(192, 168, 50, 3)]);
        assert_eq!(
            correlate(&ptr, &srv, &a, SERVICE),
            vec![
                Ipv4Addr::new(192, 168, 50, 2), // b, via PTR
                Ipv4Addr::new(192, 168, 50, 1), // a, sorted
                Ipv4Addr::new(192, 168, 50, 3), // c, sorted
            ]
        );
    }

    #[test]
    fn correlate_ignores_unrelated_srv_records() {
        // An SRV/A pair for a DIFFERENT service must not be mistaken for an MQTT broker.
        let mut srv = HashMap::new();
        srv.insert("printer._ipp._tcp.local".to_string(), ("printer.local".to_string(), 631u16));
        let mut a = HashMap::new();
        a.insert("printer.local".to_string(), vec![Ipv4Addr::new(192, 168, 50, 99)]);
        // No PTR for our service, and the SRV name isn't under _mqtt._tcp → dropped.
        assert!(correlate(&[], &srv, &a, SERVICE).is_empty());
    }

    #[test]
    fn correlate_returns_every_a_record_of_a_multihomed_broker() {
        // A broker advertising two A records for its SRV target must yield BOTH addresses,
        // in first-seen order, so the caller can try each.
        let mut srv = HashMap::new();
        srv.insert("Mosquitto._mqtt._tcp.local".to_string(), ("broker.local".to_string(), 1883u16));
        let mut a = HashMap::new();
        a.insert(
            "broker.local".to_string(),
            vec![Ipv4Addr::new(192, 168, 50, 40), Ipv4Addr::new(10, 0, 0, 40)],
        );
        let ips = correlate(&["Mosquitto._mqtt._tcp.local".to_string()], &srv, &a, SERVICE);
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
        parse_response(&b, &SERVICES, &mut ptr, &mut srv, &mut a);
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
    fn dotted_instance_label_round_trips_through_read_name_and_build_query() {
        // A DNS-SD instance label may contain a literal '.' (e.g. "70-35-60-63.1"). read_name must
        // escape it so build_query re-encodes it as ONE label, not two — otherwise a follow-up
        // query would ask for a different name and miss the broker.
        // Wire: one label "a.b" (3 bytes) + "local" + root.
        let mut b = Vec::new();
        b.push(3);
        b.extend_from_slice(b"a.b");
        b.push(5);
        b.extend_from_slice(b"local");
        b.push(0);
        let mut pos = 0;
        let name = read_name(&b, &mut pos);
        assert_eq!(name, "a\\.b.local"); // the '.' inside the label is escaped
        assert_eq!(presentation_labels(&name), vec!["a.b".to_string(), "local".to_string()]);
        let q = build_query(&name, QTYPE_SRV, false).unwrap();
        assert_eq!(q[12], 3); // one 3-byte label "a.b", NOT two labels "a"/"b"
        assert_eq!(&q[13..16], b"a.b");
        assert_eq!(q[16], 5);
        assert_eq!(&q[17..22], b"local");
        assert_eq!(q[22], 0);
    }

    #[test]
    fn read_name_stops_on_reserved_length_octet() {
        // A length octet with top bits 10 (0x80) is RFC 1035 reserved — not a valid label length
        // and not a compression pointer (0xC0). read_name must stop, not read a 128-byte label
        // from untrusted input.
        let mut b = vec![3u8];
        b.extend_from_slice(b"abc"); // valid label "abc"
        b.push(0x80); // reserved length octet
        b.extend_from_slice(&[0u8; 4]);
        let mut pos = 0;
        assert_eq!(read_name(&b, &mut pos), "abc");
    }

    #[test]
    fn parse_response_ignores_truncated_datagram() {
        let (mut ptr, mut srv, mut a) = (Vec::new(), HashMap::new(), HashMap::new());
        parse_response(&[0, 0, 0], &SERVICES, &mut ptr, &mut srv, &mut a); // < 12 bytes
        assert!(ptr.is_empty() && srv.is_empty() && a.is_empty());
    }

    #[test]
    fn parse_response_rejects_ptr_name_overrunning_rdlength() {
        // A PTR whose instance name has no terminator inside RDLENGTH would let read_name splice
        // in bytes from following records; the rd+rdlen guard must drop it.
        let mut b = vec![0, 0, 0x84, 0x00];
        b.extend_from_slice(&[0, 0]); // QDCOUNT
        b.extend_from_slice(&[0, 1]); // ANCOUNT = 1
        b.extend_from_slice(&[0, 0, 0, 0]); // NS, AR
        enc_name(SERVICE, &mut b); // record name = _mqtt._tcp.local → PTR branch runs
        b.extend_from_slice(&[0, 12, 0, 1]); // type PTR, class IN
        b.extend_from_slice(&[0, 0, 0, 120]); // TTL
        b.extend_from_slice(&[0, 2]); // RDLENGTH = 2 (too short for the label below)
        b.extend_from_slice(&[0x06, b'b']); // 6-char label start, only 1 char inside RDATA
        b.extend_from_slice(&[b'r', b'o', b'k', b'e', b'r', 0]); // completes "broker" beyond RDATA
        let (mut ptr, mut srv, mut a) = (Vec::new(), HashMap::new(), HashMap::new());
        parse_response(&b, &SERVICES, &mut ptr, &mut srv, &mut a);
        assert!(ptr.is_empty()); // the overrunning PTR name was rejected
    }

    #[test]
    fn parse_response_rejects_srv_target_overrunning_rdlength() {
        // Likewise an SRV target that overruns its RDLENGTH must not be spliced from the next
        // record's bytes.
        let mut b = vec![0, 0, 0x84, 0x00];
        b.extend_from_slice(&[0, 0]); // QDCOUNT
        b.extend_from_slice(&[0, 1]); // ANCOUNT = 1
        b.extend_from_slice(&[0, 0, 0, 0]); // NS, AR
        enc_name("svc._mqtt._tcp.local", &mut b); // record name
        b.extend_from_slice(&[0, 33, 0, 1]); // type SRV, class IN
        b.extend_from_slice(&[0, 0, 0, 120]); // TTL
        b.extend_from_slice(&[0, 8]); // RDLENGTH = 8
        // prio, weight, port=1883, then a truncated target start (0x06, 'b') — 8 bytes total.
        b.extend_from_slice(&[0, 0, 0, 0, 0x07, 0x5B, 0x06, b'b']);
        b.extend_from_slice(&[b'r', b'o', b'k', b'e', b'r', 0]); // completes "broker" beyond RDATA
        let (mut ptr, mut srv, mut a) = (Vec::new(), HashMap::new(), HashMap::new());
        parse_response(&b, &SERVICES, &mut ptr, &mut srv, &mut a);
        assert!(srv.is_empty()); // the overrunning SRV target was rejected
    }

    #[test]
    fn parse_avahi_host_name_reads_the_c100x_factory_name() {
        // The C100X ships this key set; the advertised name is `<value>.local`, overriding the
        // kernel hostname. Tolerate surrounding keys, comments, and `key = value` spacing.
        let conf = "\
            [server]\n\
            #host-name=commented-out\n\
            host-name=Bticino-Classe100X\n\
            use-ipv4=yes\n\
            use-ipv6=no\n";
        assert_eq!(parse_avahi_host_name(conf).as_deref(), Some("Bticino-Classe100X"));
        assert_eq!(parse_avahi_host_name("host-name = spaced \n").as_deref(), Some("spaced"));
        // An INLINE comment or trailing junk after the value must be stripped (a hostname is a single
        // token) — otherwise a `<name> # factory.local` would be published.
        assert_eq!(parse_avahi_host_name("host-name=Foo # factory\n").as_deref(), Some("Foo"));
        assert_eq!(parse_avahi_host_name("host-name=Bar;comment\n").as_deref(), Some("Bar"));
        // Absent / only-commented / empty value ⇒ None (Avahi would derive from the kernel hostname).
        assert_eq!(parse_avahi_host_name("[server]\nuse-ipv4=yes\n"), None);
        assert_eq!(parse_avahi_host_name("#host-name=x\n"), None);
        assert_eq!(parse_avahi_host_name("host-name=\n"), None);
        // A LONGER key that merely starts with `host-name` must not match.
        assert_eq!(parse_avahi_host_name("host-name-from-machine-id=yes\n"), None);
    }

    #[test]
    fn ensure_dot_local_appends_once_and_normalizes() {
        // A bare label gains `.local`; an already-qualified name (any case) is left as one `.local`;
        // a trailing FQDN dot is dropped. Guards against `<name>.local.local`.
        assert_eq!(ensure_dot_local("Bticino-Classe300X").as_deref(), Some("Bticino-Classe300X.local"));
        assert_eq!(ensure_dot_local("Bticino-Classe100X.local").as_deref(), Some("Bticino-Classe100X.local"));
        assert_eq!(ensure_dot_local("host.LOCAL").as_deref(), Some("host.LOCAL"));
        assert_eq!(ensure_dot_local("host.local.").as_deref(), Some("host.local"));
        assert_eq!(ensure_dot_local("  spaced  ").as_deref(), Some("spaced.local"));
        assert_eq!(ensure_dot_local(""), None);
        assert_eq!(ensure_dot_local("."), None);
    }

    #[test]
    fn model_host_from_hostname_derives_the_bticino_classe_name() {
        // The kernel hostname carries the model; the mDNS label follows the C100 factory convention.
        assert_eq!(model_host_from_hostname("Bticino_Classe_100_X").as_deref(), Some("Bticino-Classe100X"));
        assert_eq!(model_host_from_hostname("Bticino_Classe_300_X").as_deref(), Some("Bticino-Classe300X"));
        // No digits ⇒ None (caller falls back rather than advertise a modelless name).
        assert_eq!(model_host_from_hostname("localhost"), None);
        assert_eq!(model_host_from_hostname(""), None);
    }

    #[test]
    fn build_a_response_encodes_our_host_record() {
        let resp = build_a_response("Bticino-Classe300X.local", Ipv4Addr::new(192, 168, 50, 7)).unwrap();
        // Header: QR=1|AA (0x8400), QDCOUNT 0, ANCOUNT 1, NS/AR 0.
        assert_eq!(&resp[0..12], &[0, 0, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0]);
        // QNAME: 18 "Bticino-Classe300X", 5 "local", 0.
        assert_eq!(resp[12], 18);
        assert_eq!(&resp[13..31], b"Bticino-Classe300X");
        assert_eq!(resp[31], 5);
        assert_eq!(&resp[32..37], b"local");
        assert_eq!(resp[37], 0);
        // TYPE A(1), CLASS IN|cache-flush (0x8001), TTL 120, RDLENGTH 4, then the 4 IP bytes.
        assert_eq!(&resp[38..40], &[0x00, 0x01]);
        assert_eq!(&resp[40..42], &[0x80, 0x01]);
        assert_eq!(&resp[42..46], &120u32.to_be_bytes());
        assert_eq!(&resp[46..48], &[0x00, 0x04]);
        assert_eq!(&resp[48..52], &[192, 168, 50, 7]);
    }

    #[test]
    fn query_asks_for_a_matches_our_name_case_insensitively() {
        // A QUERY (QR=0) asking A (or ANY) for our name → true; a different name/type, or a RESPONSE,
        // → false. `build_query` emits QDCOUNT=1 with QR=0, so it doubles as a query fixture here.
        let q = build_query("Bticino-Classe300X.local", QTYPE_A, false).unwrap();
        assert!(query_asks_for_a(&q, "bticino-classe300x.local")); // compared case-insensitively
        let any = build_query("Bticino-Classe300X.local", QTYPE_ANY, false).unwrap();
        assert!(query_asks_for_a(&any, "Bticino-Classe300X.local"));
        // A DIFFERENT name must not match.
        let other = build_query("some-other-host.local", QTYPE_A, false).unwrap();
        assert!(!query_asks_for_a(&other, "Bticino-Classe300X.local"));
        // A different TYPE (SRV) for our name must not match — we only answer A/ANY.
        let srv = build_query("Bticino-Classe300X.local", QTYPE_SRV, false).unwrap();
        assert!(!query_asks_for_a(&srv, "Bticino-Classe300X.local"));
        // A RESPONSE (QR=1) is not a query, even for our name+type.
        let mut resp = build_query("Bticino-Classe300X.local", QTYPE_A, false).unwrap();
        resp[2] |= 0x80;
        assert!(!query_asks_for_a(&resp, "Bticino-Classe300X.local"));
        // Truncated datagram.
        assert!(!query_asks_for_a(&[0, 0, 0, 0], "Bticino-Classe300X.local"));
    }

    #[test]
    fn next_conflict_name_increments_the_suffix() {
        // First conflict → `-2`; then increment; the `Bticino-Classe` hyphen (non-numeric tail) is
        // preserved, and the `.local` suffix is kept.
        assert_eq!(next_conflict_name("Bticino-Classe300X.local"), "Bticino-Classe300X-2.local");
        assert_eq!(next_conflict_name("Bticino-Classe300X-2.local"), "Bticino-Classe300X-3.local");
        assert_eq!(next_conflict_name("Bticino-Classe300X-9.local"), "Bticino-Classe300X-10.local");
        assert_eq!(next_conflict_name("host"), "host-2"); // no .local suffix still works
        assert_eq!(next_conflict_name("a-b"), "a-b-2"); // non-numeric tail isn't a counter
    }

    #[test]
    fn datagram_conflict_applies_the_ownership_and_tiebreak_rules() {
        let ours = Ipv4Addr::new(192, 168, 50, 7);
        let name = "bticino-classe300x.local"; // parse_response lower-cases, so compare lower-cased

        // A RESPONSE (QR=1) advertising our name at a DIFFERENT address = an existing owner → yield.
        let owner = build_a_response("Bticino-Classe300X.local", Ipv4Addr::new(192, 168, 50, 8)).unwrap();
        assert!(datagram_conflict(&owner, name, ours));
        // Our OWN record looped back (same address) → not a conflict.
        let echo = build_a_response("Bticino-Classe300X.local", ours).unwrap();
        assert!(!datagram_conflict(&echo, name, ours));
        // A record for a DIFFERENT name → not a conflict.
        let other = build_a_response("someone-else.local", Ipv4Addr::new(192, 168, 50, 8)).unwrap();
        assert!(!datagram_conflict(&other, name, ours));

        // A simultaneous PROBE (QR=0) proposing a GREATER address wins the §8.2 tiebreak → we yield;
        // a LESSER address loses → we keep our name.
        let mut probe_hi = build_a_response("Bticino-Classe300X.local", Ipv4Addr::new(192, 168, 50, 8)).unwrap();
        probe_hi[2] &= !0x80; // clear QR → a query/probe
        assert!(datagram_conflict(&probe_hi, name, ours));
        let mut probe_lo = build_a_response("Bticino-Classe300X.local", Ipv4Addr::new(192, 168, 50, 6)).unwrap();
        probe_lo[2] &= !0x80;
        assert!(!datagram_conflict(&probe_lo, name, ours));
    }
}
