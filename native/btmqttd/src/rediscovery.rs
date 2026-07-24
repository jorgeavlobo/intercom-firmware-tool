//! Broker rediscovery on the local subnet when its IP changes (issue #43, Layer C).
//!
//! ## The problem
//! The installer configures the bridge with a broker endpoint. If the broker's IP
//! changes — a DHCP lease change, a broker restart/reprovision — the unit keeps
//! dialing the stale address forever and the whole HA integration goes dark until
//! someone re-flashes or edits the on-device config by hand.
//!
//! On this device a hostname does NOT rescue us: the rootfs resolver for our
//! statically-linked **musl** binary consults `/etc/hosts` (where the installer pins
//! the broker name to its build-time IP) and then only the `resolv.conf` nameservers
//! — which on the unit are PUBLIC DNS (8.8.8.8, …), never a LAN resolver. A private
//! broker name therefore never resolves to the broker's new LAN IP. (The device's
//! glibc `nsswitch` mDNS does not help either — musl ignores `nsswitch.conf`.)
//!
//! ## The approach (deliberately minimal — no client rebuild, trust boundary intact)
//! rumqttc fixes the broker host when the event loop is built, so we do NOT rebuild
//! the client. Instead we reuse the indirection the device already has: when the
//! broker is configured by **name**, the installer maps `name -> IP` in `/etc/hosts`
//! (a tmpfs symlink, writable at runtime). Rediscovery:
//!   1. reads the IP currently mapped to the broker name — the **anchor** — and scans
//!      that IP's `/24` (the broker moved WITHIN its subnet: the DHCP case);
//!   2. TCP-probes the broker port across the subnet, and (when a broker MAC was
//!      recorded at config time) prefers a candidate whose `/proc/net/arp` MAC
//!      matches — the MAC is a HINT/tie-breaker, never the trust gate;
//!   3. rewrites ONLY the broker's `/etc/hosts` line to the proposed IP.
//!
//! The **main client** then re-resolves on its next reconnect and applies its normal
//! **authenticated + TLS-pinned** connect. That connect is the trust gate: a wrong
//! host fails auth/TLS, the connection fails again, and the next rediscovery proposes
//! the next candidate (the current anchor is remembered as tried, so proposals are
//! monotonic). So rediscovery only ever *proposes* an address; it can never make the
//! bridge attach to an unauthenticated or mismatched broker.
//!
//! Scope of this module: same-subnet (`/24`) rediscovery, opt-in (`MQTT_REDISCOVERY`,
//! off by default) and only when the broker is a name. Learned addresses are NOT yet
//! persisted across a reboot (the boot-time hosts seed re-pins the original IP); that
//! persistence, mDNS discovery, and config-time MAC capture in the installer are
//! tracked as follow-ups on #43.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::net::TcpStream;

use crate::config::Config;

/// The hosts file (a tmpfs symlink on the device, so writable at runtime). Rewriting
/// only the broker's line here repoints the name for our musl resolver on the next
/// reconnect.
pub const HOSTS_PATH: &str = "/etc/hosts";

/// Consecutive connection failures before a rediscovery scan is attempted. High
/// enough that an ordinary brief broker blip (which rumqttc recovers from on its own)
/// does NOT trigger a subnet scan; low enough that a real IP change is corrected in a
/// couple of minutes at the 5 s reconnect backoff.
pub const REDISCOVER_AFTER_FAILURES: u32 = 5;

/// Per-host TCP connect timeout while probing the subnet. The broker is on the LAN
/// (a live host answers in ~ms); a tight cap keeps a full /24 sweep bounded.
const PROBE_TIMEOUT: Duration = Duration::from_millis(300);

/// How many probe sockets are outstanding at once. A /24 is 254 hosts; batching keeps
/// the file-descriptor and scheduling load bounded on the single-threaded runtime
/// while still sweeping the subnet in a fraction of a second.
const PROBE_CONCURRENCY: usize = 64;

/// Whether a poll error is consistent with a STALE/WRONG broker address (as an IP
/// change produces) rather than the REAL broker rejecting us at the application layer.
/// Only these advance the rediscovery failure streak:
///   * a network timeout, or a socket/transport-level I/O failure (connection refused,
///     host/network unreachable, reset, EOF) — nothing usable answered at this address;
///   * a **TLS** failure — this variant only occurs with TLS configured, and it means
///     the peer did NOT present our pinned certificate, i.e. the address is now served
///     by a DIFFERENT host (the classic DHCP-reuse case). The real broker passes the
///     pinned-cert handshake and refuses (if at all) at the MQTT layer instead (Copilot).
///
/// A `ConnectionRefused` (MQTT CONNACK: bad credentials / not authorized — and, under
/// TLS, only reached AFTER the cert validated, so it is the REAL broker) or another
/// protocol-level variant means the host WAS reached as our broker and rejected US, so
/// we must NOT wander off and retire the anchor (issue #43 / Codex P2).
///
/// For the `Io` variant we exclude only the `ErrorKind`s that signal a LOCAL fault
/// (permission denied, unsupported) rather than an unreachable/foreign host; unexpected
/// bytes from a non-MQTT service at a reused address surface as other kinds and DO
/// count, so a real stale-address failure is never missed.
pub fn is_unreachable(e: &rumqttc::ConnectionError) -> bool {
    use rumqttc::ConnectionError;
    use std::io::ErrorKind;
    match e {
        ConnectionError::NetworkTimeout | ConnectionError::FlushTimeout => true,
        ConnectionError::Tls(_) => true,
        ConnectionError::Io(err) => {
            !matches!(err.kind(), ErrorKind::PermissionDenied | ErrorKind::Unsupported)
        }
        _ => false,
    }
}

/// Attempt one rediscovery pass: propose a new IP for the broker name and repoint its
/// `/etc/hosts` line to it, returning the proposed IP. `None` means nothing was done
/// (broker not name-mapped, no open/trusted candidate this pass, or the rewrite failed).
///
/// `tried` accumulates addresses already proposed during this outage so proposals are
/// monotonic (no oscillation between two open-but-wrong hosts); the caller CLEARS it on
/// a successful connect, and this function clears it once the whole `/24` is exhausted,
/// so a broker that returns to a former address (including the original one) can be
/// found again — the scan is self-healing.
///
/// The trust boundary is unchanged: this only PROPOSES an address. When the config uses
/// TLS, the main client validates the broker's certificate (pinned CA + hostname) on
/// reconnect, so proposing any open candidate is safe — a wrong one fails the handshake.
/// WITHOUT TLS there is no way to authenticate the broker on reconnect (a rogue/other
/// broker would simply accept the connection, and any credentials, in cleartext), so a
/// candidate is adopted ONLY when its `/proc/net/arp` MAC matches the recorded
/// `MQTT_BROKER_MAC` hint (issue #43 / Codex P1 / CodeRabbit). `main` additionally
/// refuses to activate rediscovery at all without one of these anchors.
pub async fn rediscover(cfg: &Config, tried: &mut HashSet<Ipv4Addr>) -> Option<Ipv4Addr> {
    // Read the hosts file and find the IP currently mapped to the broker name.
    let hosts = match tokio::fs::read_to_string(HOSTS_PATH).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("btmqttd: rediscovery: cannot read {HOSTS_PATH}: {e}");
            return None;
        }
    };
    let anchor = match parse_hosts_ip(&hosts, &cfg.mqtt_host) {
        Some(a) => a,
        None => {
            // The name isn't pinned to an IPv4 in the hosts file — a misconfiguration
            // (the installer normally pins it). Say so instead of returning silently,
            // which otherwise looks like rediscovery just never triggering.
            eprintln!(
                "btmqttd: rediscovery: broker name '{}' has no IPv4 mapping in {HOSTS_PATH}; \
                 cannot rediscover (is it pinned there?)",
                cfg.mqtt_host
            );
            return None;
        }
    };
    // Only ever scan a private LAN /24. If the broker name is pinned to a public,
    // loopback or link-local address, probing its whole /24 would be off-scope outbound
    // scanning — refuse (Copilot). A moved LAN broker is, by definition, on a private
    // subnet, so this loses nothing legitimate.
    if !anchor_is_scannable(anchor) {
        eprintln!(
            "btmqttd: rediscovery: broker anchor {anchor} is not a private LAN address; \
             refusing to scan a non-local /24"
        );
        return None;
    }
    // Retire the CURRENT mapping for the rest of this outage: without this, once we
    // repoint A -> B, the next pass (anchor now B) would find A eligible again and could
    // bounce back to an address already shown unusable this outage (CodeRabbit). Proposals
    // stay monotonic; the memory is cleared only on a successful ConnAck (caller) or when
    // the whole /24 is exhausted below — so a broker returning to a former address is
    // still eventually found.
    tried.insert(anchor);

    // Candidates: the anchor's /24, minus every address already proposed this outage.
    // Exhausting the subnet clears `tried` so the next pass re-scans from scratch (incl.
    // former anchors) instead of giving up.
    let candidates: Vec<Ipv4Addr> = slash24_candidates(anchor)
        .into_iter()
        .filter(|ip| !tried.contains(ip))
        .collect();
    if candidates.is_empty() {
        tried.clear();
        return None;
    }

    // Probe the broker port across the subnet; only open hosts advance.
    let open = probe_open(&candidates, cfg.mqtt_port).await;
    if open.is_empty() {
        eprintln!(
            "btmqttd: rediscovery: no untried host in {anchor}/24 has port {} open",
            cfg.mqtt_port
        );
        // No OPEN untried host this pass — the monotonic memory is now useless (there is
        // nothing left to propose), and keeping former anchors/candidates retired would
        // strand us on the wrong mapping if the real broker later returns on one of them
        // during the same outage. Clear it so the next pass re-probes the whole /24,
        // including previously-tried addresses (Codex P2).
        tried.clear();
        return None;
    }

    // MAC hint (best-effort): the ARP table only has entries for hosts contacted
    // recently — probing above just populated it for the open hosts.
    let arp = match tokio::fs::read_to_string("/proc/net/arp").await {
        Ok(t) => parse_proc_net_arp(&t),
        Err(e) => {
            // Only material in plaintext mode, where a MAC match is the trust gate:
            // without the ARP table no candidate can match, so surface WHY instead of
            // failing later with a misleading "no candidate matches the broker MAC".
            if cfg.broker_mac.is_some() {
                eprintln!(
                    "btmqttd: rediscovery: cannot read /proc/net/arp ({e}); MAC matching \
                     unavailable this pass"
                );
            }
            Vec::new()
        }
    };

    let ordered = order_candidates(&open, &arp, cfg.broker_mac, tried);
    // Trust gate: with TLS the reconnect authenticates the broker, so any open
    // candidate is fine to propose; without TLS, require a MAC match.
    let pick = if cfg.uses_tls() {
        ordered.into_iter().next()
    } else {
        ordered
            .into_iter()
            .find(|ip| mac_matches(*ip, &arp, cfg.broker_mac))
    };
    let pick = match pick {
        Some(ip) => ip,
        None => {
            eprintln!(
                "btmqttd: rediscovery: no open candidate in {anchor}/24 matches the broker MAC \
                 (plaintext config needs a MAC match to adopt)"
            );
            // Every open host was untrusted (MAC-mismatched). Like the no-open-host case,
            // the monotonic memory is now useless — a stray mismatched host staying open
            // would otherwise keep former anchors retired forever, stranding us if the
            // real broker returns to one of them. Clear so the next pass re-probes the
            // whole /24 (Codex P2); the MAC gate still guards adoption.
            tried.clear();
            return None;
        }
    };

    // Repoint ONLY the broker's mapping; the main client validates on reconnect.
    let rewritten = rewrite_hosts(&hosts, &cfg.mqtt_host, pick);
    match tokio::task::spawn_blocking(move || write_hosts_blocking(&rewritten)).await {
        Ok(Ok(())) => {
            tried.insert(pick);
            Some(pick)
        }
        Ok(Err(e)) => {
            eprintln!("btmqttd: rediscovery: could not rewrite {HOSTS_PATH}: {e}");
            None
        }
        Err(e) => {
            eprintln!("btmqttd: rediscovery: hosts rewrite task did not complete: {e}");
            None
        }
    }
}

/// TCP-connect-probe `port` on each candidate, returning those that accept. Batched to
/// `PROBE_CONCURRENCY` so a /24 sweep never floats hundreds of sockets at once.
async fn probe_open(candidates: &[Ipv4Addr], port: u16) -> Vec<Ipv4Addr> {
    let mut open = Vec::new();
    for chunk in candidates.chunks(PROBE_CONCURRENCY) {
        let mut handles = Vec::with_capacity(chunk.len());
        for &ip in chunk {
            handles.push(tokio::spawn(async move {
                let ok = matches!(
                    tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect((ip, port))).await,
                    Ok(Ok(_))
                );
                (ip, ok)
            }));
        }
        for h in handles {
            if let Ok((ip, true)) = h.await {
                open.push(ip);
            }
        }
    }
    open
}

/// Atomically replace the hosts file (runs on the blocking pool): resolve the symlink
/// to its real target, write a UNIQUE O_EXCL temp beside it, copy the target's
/// mode/owner onto the temp, then rename over the target — so a concurrent reader (the
/// device's other services) never sees a torn file and the file keeps its permissions.
/// If the symlink can't be resolved we return the error rather than fall back to the
/// literal path, whose rename would replace the `/etc/hosts` symlink itself with a
/// regular file and break the device's tmpfs indirection.
fn write_hosts_blocking(content: &str) -> std::io::Result<()> {
    let target = std::fs::canonicalize(HOSTS_PATH)?;
    let target = target.to_str().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "hosts path is not valid UTF-8")
    })?;
    let tmp = crate::receiver::create_unique_temp(target, content.as_bytes())?;
    crate::receiver::preserve_mode_owner(target, &tmp);
    if let Err(e) = std::fs::rename(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested). No I/O — every decision the driver makes routes
// through one of these so the logic is exercised without a live network.
// ---------------------------------------------------------------------------

/// The IPv4 address currently mapped to `name` in a hosts-file body, if any. Matching
/// is ASCII case-insensitive (hostnames are case-insensitive) and spans every alias
/// on the line. IPv6 rows and comments are ignored — rediscovery is IPv4 `/24` only.
fn parse_hosts_ip(hosts: &str, name: &str) -> Option<Ipv4Addr> {
    for raw in hosts.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut cols = line.split_whitespace();
        let Some(addr) = cols.next() else { continue };
        let Ok(ip) = addr.parse::<Ipv4Addr>() else { continue };
        if cols.any(|alias| alias.eq_ignore_ascii_case(name)) {
            return Some(ip);
        }
    }
    None
}

/// Whether `anchor`'s `/24` is safe to scan: only a **private** (RFC1918) LAN address
/// qualifies. `Ipv4Addr::is_private` is false for loopback, link-local, public and
/// other special ranges, so this one check keeps rediscovery from probing a non-local
/// subnet.
fn anchor_is_scannable(anchor: Ipv4Addr) -> bool {
    anchor.is_private()
}

/// Every host address in `anchor`'s `/24` except the network (.0), broadcast (.255)
/// and the anchor itself — i.e. the addresses worth probing for the moved broker.
fn slash24_candidates(anchor: Ipv4Addr) -> Vec<Ipv4Addr> {
    let o = anchor.octets();
    (1u8..=254)
        .map(|h| Ipv4Addr::new(o[0], o[1], o[2], h))
        .filter(|ip| *ip != anchor)
        .collect()
}

/// Parse `/proc/net/arp` into `(ip, mac)` pairs, skipping the header and any row whose
/// MAC is all-zero (an incomplete/unresolved entry).
fn parse_proc_net_arp(text: &str) -> Vec<(Ipv4Addr, [u8; 6])> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        // Columns: IP, HW type, Flags, HW address, Mask, Device.
        let mut cols = line.split_whitespace();
        let (Some(ip), _, _, Some(mac)) = (cols.next(), cols.next(), cols.next(), cols.next())
        else {
            continue;
        };
        let (Ok(ip), Some(mac)) = (ip.parse::<Ipv4Addr>(), parse_mac(mac)) else {
            continue;
        };
        if mac != [0u8; 6] {
            out.push((ip, mac));
        }
    }
    out
}

/// Parse a MAC address in the usual `aa:bb:cc:dd:ee:ff` form (also accepting `-`
/// separators), case-insensitive. Returns `None` for anything malformed.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split([':', '-']);
    for slot in out.iter_mut() {
        let byte = parts.next()?;
        if byte.len() != 2 {
            return None;
        }
        *slot = u8::from_str_radix(byte, 16).ok()?;
    }
    if parts.next().is_some() {
        return None; // more than six groups
    }
    Some(out)
}

/// Whether `ip`'s ARP entry matches the recorded broker MAC. `false` when no MAC is
/// configured or the ARP table has no (matching) entry for `ip`.
fn mac_matches(ip: Ipv4Addr, arp: &[(Ipv4Addr, [u8; 6])], broker_mac: Option<[u8; 6]>) -> bool {
    broker_mac.is_some_and(|want| arp.iter().any(|(aip, amac)| *aip == ip && *amac == want))
}

/// Order the open candidates for adoption: MAC-matched hosts first (when a broker MAC
/// is known and present in the ARP table), then the remaining open hosts, each group in
/// ascending address order. Anything in `tried` is excluded. Both groups are sorted so
/// selection is DETERMINISTIC regardless of the order `open` arrives in (the driver
/// picks `next()` from this list), matching the documented contract.
fn order_candidates(
    open: &[Ipv4Addr],
    arp: &[(Ipv4Addr, [u8; 6])],
    broker_mac: Option<[u8; 6]>,
    tried: &HashSet<Ipv4Addr>,
) -> Vec<Ipv4Addr> {
    let mut matched = Vec::new();
    let mut rest = Vec::new();
    for &ip in open {
        if tried.contains(&ip) {
            continue;
        }
        if mac_matches(ip, arp, broker_mac) {
            matched.push(ip);
        } else {
            rest.push(ip);
        }
    }
    matched.sort_unstable();
    rest.sort_unstable();
    matched.extend(rest);
    matched
}

/// Return a copy of the hosts body with the broker `name` repointed to `ip`. Only the
/// matched ALIAS moves: on a line that also carries OTHER aliases (e.g.
/// `192.168.50.64 broker.lan MyBroker`, repointing `broker.lan`), the other aliases
/// keep their original address (the line is rewritten without the matched name), and a
/// single `ip<TAB>name` line is appended. Lines that don't name the broker — localhost,
/// openserver, the OTA blocks, comments, blanks — are preserved verbatim, so rewriting
/// the broker mapping never disturbs the device's other name resolution. Only lines
/// whose first column is an **IPv4** address are considered: rediscovery is IPv4-only,
/// so an `IPv6` mapping for the same name (e.g. `::1 broker.lan`) is left untouched.
fn rewrite_hosts(hosts: &str, name: &str, ip: Ipv4Addr) -> String {
    let mut out = String::with_capacity(hosts.len() + 32);
    for raw in hosts.lines() {
        let body = raw.split('#').next().unwrap_or("").trim();
        let mut cols = body.split_whitespace();
        let addr = cols.next();
        // Only rewrite IPv4 rows; an IPv6 row naming the broker is preserved verbatim.
        let is_ipv4 = addr.is_some_and(|a| a.parse::<Ipv4Addr>().is_ok());
        let names_it = is_ipv4 && cols.clone().any(|alias| alias.eq_ignore_ascii_case(name));
        if !names_it {
            out.push_str(raw);
            out.push('\n');
            continue;
        }
        // The line maps the broker name. Keep any OTHER aliases at their original
        // address; drop only the matched name (it is repointed by the appended line).
        let others: Vec<&str> = cols.filter(|alias| !alias.eq_ignore_ascii_case(name)).collect();
        if !others.is_empty() {
            out.push_str(addr.unwrap());
            for alias in others {
                out.push('\t');
                out.push_str(alias);
            }
            out.push('\n');
        }
    }
    out.push_str(&format!("{ip}\t{name}\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hosts_ip_matches_name_case_insensitively_across_aliases() {
        let hosts = "\
127.0.0.1\tlocalhost
192.168.50.64\tbroker.lan MyBroker
::1 ip6-localhost
# 10.0.0.1 commented.host
";
        assert_eq!(
            parse_hosts_ip(hosts, "mybroker"),
            Some(Ipv4Addr::new(192, 168, 50, 64))
        );
        assert_eq!(
            parse_hosts_ip(hosts, "broker.lan"),
            Some(Ipv4Addr::new(192, 168, 50, 64))
        );
        assert_eq!(parse_hosts_ip(hosts, "localhost"), Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(parse_hosts_ip(hosts, "commented.host"), None);
        assert_eq!(parse_hosts_ip(hosts, "absent"), None);
    }

    #[test]
    fn parse_hosts_ip_ignores_ipv6_mapping() {
        let hosts = "fe80::1 broker.lan\n";
        assert_eq!(parse_hosts_ip(hosts, "broker.lan"), None);
    }

    #[test]
    fn anchor_is_scannable_only_for_private_lan() {
        assert!(anchor_is_scannable(Ipv4Addr::new(192, 168, 50, 64)));
        assert!(anchor_is_scannable(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(anchor_is_scannable(Ipv4Addr::new(172, 16, 5, 5)));
        assert!(!anchor_is_scannable(Ipv4Addr::new(127, 0, 0, 1))); // loopback
        assert!(!anchor_is_scannable(Ipv4Addr::new(169, 254, 1, 1))); // link-local
        assert!(!anchor_is_scannable(Ipv4Addr::new(8, 8, 8, 8))); // public
        assert!(!anchor_is_scannable(Ipv4Addr::new(172, 32, 0, 1))); // just outside 172.16/12
    }

    #[test]
    fn slash24_candidates_excludes_network_broadcast_and_anchor() {
        let c = slash24_candidates(Ipv4Addr::new(192, 168, 50, 64));
        assert_eq!(c.len(), 253); // 1..=254 minus the anchor
        assert!(!c.contains(&Ipv4Addr::new(192, 168, 50, 0)));
        assert!(!c.contains(&Ipv4Addr::new(192, 168, 50, 255)));
        assert!(!c.contains(&Ipv4Addr::new(192, 168, 50, 64)));
        assert!(c.contains(&Ipv4Addr::new(192, 168, 50, 1)));
        assert!(c.contains(&Ipv4Addr::new(192, 168, 50, 254)));
        assert!(c.iter().all(|ip| ip.octets()[..3] == [192, 168, 50]));
    }

    #[test]
    fn parse_mac_accepts_colon_and_dash_rejects_malformed() {
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff"), Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert_eq!(parse_mac("AA-BB-CC-DD-EE-FF"), Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert_eq!(parse_mac("00:11:22:33:44:55"), Some([0, 0x11, 0x22, 0x33, 0x44, 0x55]));
        assert_eq!(parse_mac("aa:bb:cc:dd:ee"), None); // too few
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff:00"), None); // too many
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:zz"), None); // non-hex
        assert_eq!(parse_mac("aabbccddeeff"), None); // no separators
        assert_eq!(parse_mac("a:b:c:d:e:f"), None); // single-digit groups
    }

    #[test]
    fn parse_proc_net_arp_skips_header_and_incomplete() {
        let arp = "\
IP address       HW type     Flags       HW address            Mask     Device
192.168.50.64    0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
192.168.50.1     0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.50.9     0x1         0x2         11:22:33:44:55:66     *        wlan0
";
        let got = parse_proc_net_arp(arp);
        assert_eq!(
            got,
            vec![
                (Ipv4Addr::new(192, 168, 50, 64), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
                (Ipv4Addr::new(192, 168, 50, 9), [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]),
            ]
        );
    }

    #[test]
    fn order_candidates_prefers_mac_match_then_excludes_tried() {
        let open = [
            Ipv4Addr::new(192, 168, 50, 5),
            Ipv4Addr::new(192, 168, 50, 9),
            Ipv4Addr::new(192, 168, 50, 20),
        ];
        let arp = [(Ipv4Addr::new(192, 168, 50, 9), [0x11, 0x22, 0x33, 0x44, 0x55, 0x66])];
        let mut tried = HashSet::new();
        tried.insert(Ipv4Addr::new(192, 168, 50, 5));

        let ordered = order_candidates(&open, &arp, Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]), &tried);
        // .5 is tried (dropped); .9 matches the MAC so it leads; .20 follows.
        assert_eq!(
            ordered,
            vec![Ipv4Addr::new(192, 168, 50, 9), Ipv4Addr::new(192, 168, 50, 20)]
        );
    }

    #[test]
    fn order_candidates_without_mac_sorts_by_address() {
        // Regardless of the input order, the result is ascending address order.
        let open = [Ipv4Addr::new(192, 168, 50, 20), Ipv4Addr::new(192, 168, 50, 9)];
        let ordered = order_candidates(&open, &[], None, &HashSet::new());
        assert_eq!(
            ordered,
            vec![Ipv4Addr::new(192, 168, 50, 9), Ipv4Addr::new(192, 168, 50, 20)]
        );
    }

    #[test]
    fn rewrite_hosts_repoints_only_the_broker_line() {
        // The device's own mapping is a single alias per line (bt_hosts.sh writes
        // `<ip>\t<name>`), so the stale line is dropped and the new one appended.
        let hosts = "\
127.0.0.1\tlocalhost
127.0.0.1\topenserver
192.168.50.64\tbroker.lan
127.0.0.1\tprodlegrandressourcespkg.blob.core.windows.net
";
        let out = rewrite_hosts(hosts, "broker.lan", Ipv4Addr::new(192, 168, 50, 200));
        // Every other mapping is preserved verbatim.
        assert!(out.contains("127.0.0.1\tlocalhost\n"));
        assert!(out.contains("127.0.0.1\topenserver\n"));
        assert!(out.contains("127.0.0.1\tprodlegrandressourcespkg.blob.core.windows.net\n"));
        // The stale broker mapping is gone; exactly one new one is present.
        assert!(!out.contains("192.168.50.64"));
        assert_eq!(out.matches("broker.lan").count(), 1);
        assert!(out.contains("192.168.50.200\tbroker.lan\n"));
        // Re-parsing yields the new IP.
        assert_eq!(
            parse_hosts_ip(&out, "broker.lan"),
            Some(Ipv4Addr::new(192, 168, 50, 200))
        );
    }

    #[test]
    fn rewrite_hosts_preserves_other_aliases_on_the_line() {
        // A line carrying more than the broker name: only the matched alias moves; the
        // other alias keeps its original address (CodeRabbit).
        let hosts = "192.168.50.64\tbroker.lan MyBroker\n";
        let out = rewrite_hosts(hosts, "broker.lan", Ipv4Addr::new(192, 168, 50, 200));
        // MyBroker stays put; broker.lan is repointed; neither is duplicated.
        assert_eq!(parse_hosts_ip(&out, "MyBroker"), Some(Ipv4Addr::new(192, 168, 50, 64)));
        assert_eq!(parse_hosts_ip(&out, "broker.lan"), Some(Ipv4Addr::new(192, 168, 50, 200)));
        assert_eq!(out.matches("broker.lan").count(), 1);
        assert_eq!(out.matches("MyBroker").count(), 1);
    }

    #[test]
    fn rewrite_hosts_leaves_ipv6_mappings_untouched() {
        // Rediscovery is IPv4-only: an IPv6 row for the same name must survive verbatim.
        let hosts = "\
fe80::1\tbroker.lan
192.168.50.64\tbroker.lan
";
        let out = rewrite_hosts(hosts, "broker.lan", Ipv4Addr::new(192, 168, 50, 200));
        assert!(out.contains("fe80::1\tbroker.lan\n")); // IPv6 mapping preserved
        assert!(out.contains("192.168.50.200\tbroker.lan\n")); // IPv4 repointed
        assert!(!out.contains("192.168.50.64")); // stale IPv4 gone
    }

    #[test]
    fn is_unreachable_only_for_network_class_errors() {
        use rumqttc::{ConnectReturnCode, ConnectionError};
        assert!(is_unreachable(&ConnectionError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "refused"
        ))));
        assert!(is_unreachable(&ConnectionError::NetworkTimeout));
        assert!(is_unreachable(&ConnectionError::FlushTimeout));
        assert!(is_unreachable(&ConnectionError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset"
        ))));
        // A broker-side CONNACK refusal (bad credentials) is NOT unreachable — the host
        // is the real broker, rejecting us; rediscovery must not retire it.
        assert!(!is_unreachable(&ConnectionError::ConnectionRefused(
            ConnectReturnCode::BadUserNamePassword
        )));
        // A local fault (cannot create the socket) is excluded — not a stale host.
        assert!(!is_unreachable(&ConnectionError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "denied"
        ))));
        // Unexpected bytes from a non-MQTT service at a reused address DO count (a wrong
        // host now serves the stale IP), so rediscovery engages.
        assert!(is_unreachable(&ConnectionError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "garbage"
        ))));
    }

    #[test]
    fn mac_matches_requires_a_configured_and_present_mac() {
        let ip = Ipv4Addr::new(192, 168, 50, 9);
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let arp = [(ip, mac)];
        assert!(mac_matches(ip, &arp, Some(mac)));
        assert!(!mac_matches(ip, &arp, None)); // no MAC configured
        assert!(!mac_matches(ip, &[], Some(mac))); // not in ARP
        assert!(!mac_matches(ip, &arp, Some([0; 6]))); // different MAC
    }

    #[test]
    fn rewrite_hosts_is_idempotent_on_the_target_name() {
        let hosts = "192.168.50.64\tbroker.lan\n";
        let once = rewrite_hosts(hosts, "broker.lan", Ipv4Addr::new(10, 0, 0, 5));
        let twice = rewrite_hosts(&once, "broker.lan", Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(once, twice);
        assert_eq!(once.matches("broker.lan").count(), 1);
    }
}
