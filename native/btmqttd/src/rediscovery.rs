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
//!   1. scans the UNION of the **last connect-confirmed** broker `/24` (the caller's persisted
//!      learned IP) and the immutable **build-time** `/24` — the same subnet when the broker
//!      never left (the DHCP case). Using only CONFIRMED anchors — never an unconfirmed mDNS
//!      proposal — keeps the scan from drifting, while covering both a subnet the broker
//!      legitimately moved to and its original one should it return there with mDNS down;
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
//! Scope of this module: opt-in (`MQTT_REDISCOVERY`, off by default) and only when the broker
//! is a name. A rediscovery pass now tries `mdns.rs` FIRST (issue #49 item 2 — the broker's
//! advertised `_mqtt._tcp` address, found by name across the link) and falls back to the
//! same-subnet (`/24`) scan. A learned address is also persisted across a reboot (issue #49
//! item 1): `persist.rs` remembers the connect-confirmed IP on the writable `cfg/extra`
//! partition and `main` seeds `/etc/hosts` from it at startup, so a reboot after the broker
//! moved reconnects immediately instead of re-scanning. Cross-subnet + port fallback (1883 ↔
//! 8883) remain follow-ups (#49 item 3).

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::net::TcpStream;

use crate::config::Config;
use crate::mdns;

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
/// `/etc/hosts` line to it — appending a mapping if none exists (the mDNS-first path can
/// repoint even when the name was never mapped), returning the proposed IP. `None` means
/// nothing was done this pass: no open/trusted candidate from either mDNS or the `/24`
/// scan, no scannable private-LAN anchor for the scan fallback, or the hosts rewrite failed.
///
/// Two exclusion sets track what has already been proposed this outage so proposals don't
/// oscillate between open-but-wrong hosts. `tried` holds the fallback SCAN's picks (plus the
/// current stale mapping); `mdns_rejected` holds every address mDNS has already proposed this
/// outage — inserted at proposal time, since a proposal that authenticates is confirmed by a
/// ConnAck (which clears both sets) and only a proposal that fails needs to stay excluded.
/// They are kept distinct because they re-arm differently: after a fruitless scan pass
/// [`retire_scan_subnets`] re-arms ONLY the scanned `/24` addresses in `tried` (so a broker that
/// returns to a former address is re-probed) while leaving `mdns_rejected` intact (so a wrong
/// advertiser inside an anchor `/24` isn't re-proposed every pass). To stay self-healing, after
/// `FULL_RESET_AFTER_DRY_CYCLES` consecutive fruitless passes it does a bounded FULL clear of
/// both sets. `dry_cycles` counts those fruitless passes and is reset ONLY on that full clear and
/// by the caller on a successful connect — never on a mere proposal (a hosts rewrite is not a
/// confirmation). The caller also clears both sets on a ConnAck.
///
/// The trust boundary is unchanged: this only PROPOSES an address. When the config uses
/// TLS, the main client validates the broker's certificate (pinned CA + hostname) on
/// reconnect, so proposing any open candidate is safe — a wrong one fails the handshake.
/// WITHOUT TLS there is no way to authenticate the broker on reconnect (a rogue/other
/// broker would simply accept the connection, and any credentials, in cleartext), so a
/// candidate is adopted ONLY when its `/proc/net/arp` MAC matches the recorded
/// `MQTT_BROKER_MAC` hint (issue #43 / Codex P1 / CodeRabbit). `main` additionally
/// refuses to activate rediscovery at all without one of these anchors.
pub async fn rediscover(
    cfg: &Config,
    tried: &mut HashSet<Ipv4Addr>,
    mdns_rejected: &mut HashSet<Ipv4Addr>,
    confirmed_anchor: Option<Ipv4Addr>,
    dry_cycles: &mut u32,
) -> Option<Ipv4Addr> {
    // Layer B (issue #49 item 2, #43): mDNS FIRST. A broker that advertises `_mqtt._tcp`
    // announces its IPv4 by name across the whole link — cheaper and broader than the /24
    // port scan below, and it finds a broker that moved to a DIFFERENT subnet on the same L2
    // segment. Trust boundary unchanged: this only PROPOSES the advertised address; the main
    // client's authenticated + pinned-TLS reconnect is the gate, and in plaintext mode the
    // proposal is additionally ARP-MAC-gated here (mirroring the scan). If mDNS proposes a
    // usable address, repoint and return; otherwise fall through to the subnet scan.
    // mDNS proposals are tracked in a SEPARATE set (`mdns_rejected`), never in `tried`: an
    // address mDNS has proposed this outage must stay excluded even as the scan re-arms its
    // `/24`s (a ConnAck clears it if it was right), because that proposal may sit INSIDE an
    // anchor `/24` — folding it into
    // `tried` would let `retire_scan_subnets` re-arm it every pass, so mDNS would re-propose the
    // same wrong broker forever and each optimistic repoint would reset `dry_cycles`, defeating
    // the periodic full-reset bound (Codex P2). Only the bounded full-reset clears it.
    if let Some(ip) = mdns_propose(cfg, tried, mdns_rejected).await {
        match seed_hosts(&cfg.mqtt_host, ip).await {
            Ok(true) => {
                mdns_rejected.insert(ip);
                // Deliberately do NOT reset `dry_cycles` here: a hosts rewrite is only a PROPOSAL,
                // not a confirmation — the reconnect may still fail the trust gate. Resetting on
                // every unconfirmed proposal would let two-or-more spurious open hosts in the
                // anchor /24 alternate forever, so `dry_cycles` would never reach the bound and
                // the mDNS-rejection full-reset would never fire (Codex P2). Only a ConnAck (in
                // `main`) resets the counter.
                eprintln!(
                    "btmqttd: rediscovery: mDNS repointed '{}' -> {ip} in {HOSTS_PATH}",
                    cfg.mqtt_host
                );
                return Some(ip);
            }
            // Already mapped to `ip` — i.e. the address currently failing. Nothing was
            // rewritten, so don't claim a repoint or skip the scan: retire it and fall through
            // to the subnet sweep (CodeRabbit).
            Ok(false) => {
                mdns_rejected.insert(ip);
            }
            Err(e) => eprintln!("btmqttd: rediscovery: mDNS repoint of {HOSTS_PATH} failed: {e}"),
        }
    }

    // Read the hosts file — needed to REWRITE it below while preserving the device's
    // other mappings (localhost, openserver, the OTA blocks, …).
    let hosts = match tokio::fs::read_to_string(HOSTS_PATH).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("btmqttd: rediscovery: cannot read {HOSTS_PATH}: {e}");
            return None;
        }
    };
    // Gather the subnets to scan. Three review findings converge here:
    //   * NEVER anchor on an UNCONFIRMED mDNS proposal sitting in /etc/hosts — that could
    //     strand the scan on the wrong /24 (Copilot);
    //   * DO follow the broker to a subnet it legitimately moved to and CONFIRMED
    //     (`confirmed_anchor`, advanced only by a ConnAck) — a DHCP move WITHIN that subnet is
    //     only recoverable by scanning it (Codex);
    //   * but ALSO keep scanning the immutable build-time subnet, so a broker that RETURNED to
    //     its original subnet while mDNS is unavailable is still found once the confirmed
    //     subnet is exhausted (Codex).
    // So the fallback scans the UNION of the last-confirmed /24 and the build-time /24 — the
    // same /24 (deduped) when the broker never left. Neither is an unconfirmed proposal, so
    // there is no drift. Fall back to the current /etc/hosts mapping only when neither a
    // confirmed IP nor a readable build-time mapping exists.
    let mut anchors: Vec<Ipv4Addr> = Vec::new();
    if let Some(a) = confirmed_anchor {
        anchors.push(a);
    }
    if let Some(a) = build_time_ip(&cfg.mqtt_host).await {
        anchors.push(a);
    }
    if anchors.is_empty() {
        if let Some(a) = parse_hosts_ip(&hosts, &cfg.mqtt_host) {
            anchors.push(a);
        }
    }
    // Only ever scan a private LAN /24: drop any anchor pinned to a public, loopback or
    // link-local address rather than probe a non-local subnet (Copilot).
    anchors.retain(|a| anchor_is_scannable(*a));
    if anchors.is_empty() {
        eprintln!(
            "btmqttd: rediscovery: broker name '{}' has no private-LAN IPv4 anchor in \
             {BOOT_HOSTS_SCRIPT} or {HOSTS_PATH}; cannot rediscover (is it pinned to a \
             local address?)",
            cfg.mqtt_host
        );
        return None;
    }

    // Retire the CURRENT (stale) mapping — the address the broker is pinned to now, and that
    // just failed — so a repoint can't bounce back to it. The anchors themselves stay
    // probeable (the build-time or confirmed address must be findable if the broker returned
    // there); only the current mapping is excluded, via `tried` (Codex). A current mapping
    // outside every anchor's /24 (a prior cross-subnet repoint) simply doesn't intersect the
    // candidates, so retiring it is then a harmless no-op.
    if let Some(current) = parse_hosts_ip(&hosts, &cfg.mqtt_host) {
        tried.insert(current);
    }

    // Candidates: the UNION of every anchor's /24 (deduped), minus every address already
    // proposed this outage — both the scan-tried set AND the mDNS rejections, so a wrong
    // in-/24 mDNS advertiser the scan would otherwise re-adopt (open port under TLS, or a
    // MAC that happens to match) stays excluded. Exhausting them re-arms the next pass (see
    // `retire_scan_subnets`).
    let excluded: HashSet<Ipv4Addr> = tried.iter().chain(mdns_rejected.iter()).copied().collect();
    let candidates = union_candidates(&anchors, &excluded);
    if candidates.is_empty() {
        eprintln!(
            "btmqttd: rediscovery: every address in the anchor /24(s) was already tried this \
             outage; re-arming the scan for the next pass"
        );
        retire_scan_subnets(&anchors, tried, mdns_rejected, dry_cycles);
        return None;
    }

    // A human-readable list of the /24(s) being swept, for the log lines below.
    let scanned = {
        let mut nets: Vec<String> = Vec::new();
        for a in &anchors {
            let o = a.octets();
            let net = format!("{}.{}.{}.0/24", o[0], o[1], o[2]);
            if !nets.contains(&net) {
                nets.push(net);
            }
        }
        nets.join(", ")
    };

    // Probe the broker port across the subnet(s); only open hosts advance.
    let open = probe_open(&candidates, cfg.mqtt_port).await;
    if open.is_empty() {
        eprintln!(
            "btmqttd: rediscovery: no untried host in {scanned} has port {} open",
            cfg.mqtt_port
        );
        // No OPEN untried host this pass — re-arm the scanned /24(s) so the next pass re-probes
        // them (incl. former anchors) in case the real broker returns there, WITHOUT forgetting
        // mDNS proposals already rejected this outage — in-/24 or cross-subnet (Codex P2).
        retire_scan_subnets(&anchors, tried, mdns_rejected, dry_cycles);
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
                "btmqttd: rediscovery: no open candidate in {scanned} matches the broker MAC \
                 (plaintext config needs a MAC match to adopt)"
            );
            // Every open host was untrusted (MAC-mismatched). Like the no-open-host case,
            // re-arm the scanned /24(s) for the next pass (the MAC gate still guards adoption)
            // without forgetting mDNS proposals already rejected — in-/24 or cross-subnet (Codex P2).
            retire_scan_subnets(&anchors, tried, mdns_rejected, dry_cycles);
            return None;
        }
    };

    // Repoint ONLY the broker's mapping; the main client validates on reconnect.
    let rewritten = rewrite_hosts(&hosts, &cfg.mqtt_host, pick);
    match tokio::task::spawn_blocking(move || write_hosts_blocking(&rewritten)).await {
        Ok(Ok(())) => {
            tried.insert(pick);
            // As in the mDNS branch above, do NOT reset `dry_cycles` on a scan proposal: a rewrite
            // is not a confirmation, so resetting here would defeat the bound when several
            // non-broker hosts answer on the port and get picked in turn (Codex P2). Only a
            // ConnAck resets it.
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

/// The IPv4 currently mapped to the broker `name` in `/etc/hosts`, if any. Async I/O
/// wrapper over the pure [`parse_hosts_ip`] used by the persist-on-connect path
/// (issue #49 item 1): on a successful `ConnAck`, `main` reads this confirmed-good IP
/// and remembers it. `None` if the file can't be read or the name isn't pinned.
pub async fn current_broker_ip(name: &str) -> Option<Ipv4Addr> {
    let hosts = tokio::fs::read_to_string(HOSTS_PATH).await.ok()?;
    parse_hosts_ip(&hosts, name)
}

/// The boot init script that re-seeds `/etc/hosts` at EVERY boot (installer-written by
/// `BtDaemonAppsHosts`, on the read-ONLY rootfs). Its `bt_hosts.sh add <host> <ip>` line
/// for the broker is the IMMUTABLE build-time mapping — unlike `/etc/hosts` (tmpfs,
/// mutated at runtime by rediscovery and the persistence seed).
pub const BOOT_HOSTS_SCRIPT: &str = "/etc/init.d/bt_daemon-apps.sh";

/// The build-time IPv4 the boot init seeds for broker `name`, read from
/// [`BOOT_HOSTS_SCRIPT`] — the IMMUTABLE source of the record's "base" (issue #49 item 1 /
/// Codex). Reading the build IP from here rather than the mutable `/etc/hosts` mapping is
/// what makes the persistence correct across a `bt_service_watchdog` respawn (where
/// `/etc/hosts` may already hold a rediscovered IP) and a firmware re-flash (which the
/// rootfs script reflects but tmpfs does not). `None` if the script can't be read or has
/// no mapping for the name.
pub async fn build_time_ip(name: &str) -> Option<Ipv4Addr> {
    let script = tokio::fs::read_to_string(BOOT_HOSTS_SCRIPT).await.ok()?;
    parse_boot_hosts_ip(&script, name)
}

/// Whether `ip` currently answers on `port` AND its `/proc/net/arp` MAC matches
/// `want_mac`. This is the PLAINTEXT trust gate re-applied before the boot seed restores
/// a persisted IP (issue #49 item 1 / Codex P1): `rediscover` only ever adopts a plaintext
/// candidate whose ARP MAC matches, so the boot restore must apply the same check — else
/// an address DHCP reassigned while the unit was off could take our credentials on the
/// first connect (a wrong broker would ConnAck and normal rediscovery would never run).
/// Probing the port both confirms reachability and populates the ARP entry we then read.
/// Best-effort: any unreachable/read failure ⇒ `false` (don't seed; fall back to the
/// build-time mapping and let normal rediscovery re-locate under its MAC gate). Under TLS
/// the reconnect's pinned-cert handshake is the gate, so callers skip this.
pub async fn arp_mac_matches(ip: Ipv4Addr, port: u16, want_mac: [u8; 6]) -> bool {
    if probe_open(&[ip], port).await.is_empty() {
        return false; // nothing answering here — can't confirm the broker's MAC
    }
    match tokio::fs::read_to_string("/proc/net/arp").await {
        Ok(t) => mac_matches(ip, &parse_proc_net_arp(&t), Some(want_mac)),
        Err(_) => false,
    }
}

/// Seed `/etc/hosts` so the broker `name` maps to `ip` — the boot-time restore of a
/// previously learned, connect-confirmed address (issue #49 item 1). Reuses the SAME
/// atomic, other-mappings-preserving rewrite as rediscovery, so seeding never disturbs
/// the device's other name resolution. Returns `Ok(true)` when the mapping was changed,
/// `Ok(false)` when it already pointed at `ip` (so `main` can skip a redundant rewrite
/// and log nothing). The reconnect still authenticates the broker, so seeding a stale
/// persisted IP is safe — it just fails and normal rediscovery resumes.
pub async fn seed_hosts(name: &str, ip: Ipv4Addr) -> std::io::Result<bool> {
    let hosts = tokio::fs::read_to_string(HOSTS_PATH).await?;
    if parse_hosts_ip(&hosts, name) == Some(ip) {
        return Ok(false); // already mapped there — nothing to do
    }
    let rewritten = rewrite_hosts(&hosts, name, ip);
    tokio::task::spawn_blocking(move || write_hosts_blocking(&rewritten))
        .await
        .map_err(std::io::Error::other)??;
    Ok(true)
}

/// How long to listen for mDNS answers per rediscovery pass. Long enough for LAN responders
/// to reply (they answer in ~ms), short enough that a broker which doesn't advertise mDNS
/// only delays the fallback subnet scan by a couple of seconds.
const MDNS_WINDOW: Duration = Duration::from_secs(2);

/// Propose a broker address discovered via mDNS (Layer B), or `None`. Queries the MQTT DNS-SD
/// services (`_mqtt._tcp` + the TLS `_secure-mqtt._tcp`), keeps the advertised IPv4s that are
/// private LAN addresses and not already
/// tried this outage (in discovery order), and applies the trust gate: under TLS the broker PORT
/// must be open (the pinned-cert reconnect is then the real trust gate); in plaintext the broker
/// PORT must be open AND the host's `/proc/net/arp` MAC must match the recorded `MQTT_BROKER_MAC`.
/// Requiring an open port under TLS keeps a stale/unrelated mDNS answer from triggering a repoint,
/// which on a chatty LAN could otherwise keep starving the `/24` fallback. The port probe is
/// BATCHED across all candidates in one concurrency-limited [`probe_open`] call (both modes), so
/// many mDNS answers don't serialize into `N * PROBE_TIMEOUT` before the fallback (Copilot); in
/// plaintext `/proc/net/arp` is then read ONCE and each candidate compared via [`mac_matches`].
/// The first candidate that passes its mode's gate, in discovery order, wins. Without TLS and
/// without a MAC, mDNS proposes nothing — same posture as `main`'s activation gate.
async fn mdns_propose(
    cfg: &Config,
    tried: &HashSet<Ipv4Addr>,
    mdns_rejected: &HashSet<Ipv4Addr>,
) -> Option<Ipv4Addr> {
    let candidates: Vec<Ipv4Addr> = mdns::discover_ips(MDNS_WINDOW)
        .await
        .into_iter()
        .filter(|ip| ip.is_private() && !tried.contains(ip) && !mdns_rejected.contains(ip))
        .collect();
    if candidates.is_empty() {
        return None;
    }
    if cfg.uses_tls() {
        // One batched probe across every candidate, then the first that answered, in order.
        let open: HashSet<Ipv4Addr> =
            probe_open(&candidates, cfg.mqtt_port).await.into_iter().collect();
        candidates.into_iter().find(|ip| open.contains(ip))
    } else if let Some(mac) = cfg.broker_mac {
        // Plaintext: batch the port probes once (to populate the ARP table for the open hosts),
        // read /proc/net/arp once, then pick the first discovery-ordered candidate that is open
        // AND whose ARP entry matches the recorded broker MAC — so many advertisers don't
        // serialize into N * PROBE_TIMEOUT before the /24 fallback (Copilot).
        let open: HashSet<Ipv4Addr> =
            probe_open(&candidates, cfg.mqtt_port).await.into_iter().collect();
        if open.is_empty() {
            return None;
        }
        let arp = match tokio::fs::read_to_string("/proc/net/arp").await {
            Ok(t) => parse_proc_net_arp(&t),
            Err(_) => return None, // no ARP table ⇒ no candidate can be MAC-confirmed this pass
        };
        candidates
            .into_iter()
            .find(|ip| open.contains(ip) && mac_matches(*ip, &arp, Some(mac)))
    } else {
        None // no TLS and no MAC → propose nothing
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

/// The IPv4 a `bt_hosts.sh add <host> <ip>` line in the boot init script maps `name` to,
/// if any. Matches the installer's line shape (`BtDaemonAppsHosts.MappingLine`:
/// `/bin/bt_hosts.sh add <host> <ip>`), host case-insensitively; commented lines and any
/// non-IPv4 address are ignored. The first matching line wins.
fn parse_boot_hosts_ip(script: &str, name: &str) -> Option<Ipv4Addr> {
    for raw in script.lines() {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        // Look for the `<…>bt_hosts.sh add <host> <ip>` shape anywhere on the line.
        for w in toks.windows(4) {
            if w[0].ends_with("bt_hosts.sh")
                && w[1] == "add"
                && w[2].eq_ignore_ascii_case(name)
            {
                if let Ok(ip) = w[3].parse::<Ipv4Addr>() {
                    return Some(ip);
                }
            }
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

/// Every host address (`.1`–`.254`) in `anchor`'s `/24` — the addresses worth probing for
/// the moved broker. The network (`.0`) and broadcast (`.255`) fall outside the range. The
/// anchor address itself is deliberately NOT excluded: with the anchor fixed to the immutable
/// build-time IP, that address must stay probeable so a broker that RETURNED to it is found
/// (Codex); the caller excludes the current stale mapping via `tried` instead.
fn slash24_candidates(anchor: Ipv4Addr) -> Vec<Ipv4Addr> {
    let o = anchor.octets();
    (1u8..=254)
        .map(|h| Ipv4Addr::new(o[0], o[1], o[2], h))
        .collect()
}

/// The candidate set for the fallback scan: the UNION of every anchor's `/24` (deduped), minus
/// every address already proposed this outage (`tried`). Shared by `rediscover` and its tests so
/// the two can't silently drift.
fn union_candidates(anchors: &[Ipv4Addr], tried: &HashSet<Ipv4Addr>) -> Vec<Ipv4Addr> {
    let mut seen: HashSet<Ipv4Addr> = HashSet::new();
    anchors
        .iter()
        .flat_map(|a| slash24_candidates(*a))
        .filter(|ip| seen.insert(*ip) && !tried.contains(ip))
        .collect()
}

/// After this many consecutive fruitless scan passes, `retire_scan_subnets` forgets EVERYTHING
/// (both the scanned `/24`s AND every mDNS rejection) so recovery stays self-healing even for
/// rejections that sit inside or outside an anchor `/24` — bounded, so a wrong mDNS broker isn't
/// re-proposed every pass.
const FULL_RESET_AFTER_DRY_CYCLES: u32 = 4;

/// Re-arm the fallback scan after a fruitless pass. Normally it drops just the scanned `/24`
/// addresses from `tried` so the next pass re-probes those subnets from scratch (a broker may
/// return to a former address), WITHOUT touching `mdns_rejected`: mDNS proposals refused this
/// outage stay excluded even when they sit INSIDE an anchor `/24`. Keeping them in a set the
/// scan re-arm never clears is what stops the mDNS layer from re-proposing the same wrong broker
/// every reset — otherwise each optimistic repoint would reset `dry_cycles` and the periodic
/// full-reset below would never fire, so discovery would oscillate instead of advancing (Codex).
///
/// But holding a rejection for the WHOLE outage isn't self-healing either: if the real broker
/// later takes over that IP (DHCP reassignment / restart) mid-outage, it would stay excluded
/// (Copilot). So after `FULL_RESET_AFTER_DRY_CYCLES` consecutive fruitless passes it does a FULL
/// clear of BOTH sets — giving every rejected address another chance, on a bounded cadence that
/// keeps the anti-oscillation guarantee. The trust gate still guards every adoption regardless.
///
/// `dry_cycles` counts consecutive fruitless passes and is reset to 0 ONLY here (on the full
/// clear) and by `main` on a ConnAck. It is deliberately NOT reset when `rediscover` merely
/// PROPOSES an address (an mDNS repoint or a scan pick): a hosts rewrite is not a confirmation,
/// and resetting on unconfirmed proposals would let two-or-more spurious open hosts in the /24
/// alternate forever without the counter ever reaching the bound (Codex P2).
fn retire_scan_subnets(
    anchors: &[Ipv4Addr],
    tried: &mut HashSet<Ipv4Addr>,
    mdns_rejected: &mut HashSet<Ipv4Addr>,
    dry_cycles: &mut u32,
) {
    *dry_cycles += 1;
    if *dry_cycles >= FULL_RESET_AFTER_DRY_CYCLES {
        tried.clear();
        mdns_rejected.clear();
        *dry_cycles = 0;
        return;
    }
    for a in anchors {
        for ip in slash24_candidates(*a) {
            tried.remove(&ip);
        }
    }
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
    fn parse_boot_hosts_ip_reads_the_installer_line() {
        // The installer writes tab-indented `/bin/bt_hosts.sh add <host> <ip>` lines.
        let script = "\
#!/bin/sh
\t/bin/bt_hosts.sh add openserver 127.0.0.1
\t/bin/bt_hosts.sh add broker.lan 192.168.50.64
# /bin/bt_hosts.sh add commented.host 10.0.0.1
";
        assert_eq!(parse_boot_hosts_ip(script, "broker.lan"), Some(Ipv4Addr::new(192, 168, 50, 64)));
        assert_eq!(parse_boot_hosts_ip(script, "BROKER.LAN"), Some(Ipv4Addr::new(192, 168, 50, 64)));
        assert_eq!(parse_boot_hosts_ip(script, "openserver"), Some(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!(parse_boot_hosts_ip(script, "commented.host"), None); // commented out
        assert_eq!(parse_boot_hosts_ip(script, "absent"), None);
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
    fn slash24_candidates_covers_the_whole_24_including_the_anchor() {
        // The anchor (build-time IP) is NOT excluded: a broker that returned to it must be
        // probeable; the caller drops the current stale mapping via `tried` (Codex).
        let c = slash24_candidates(Ipv4Addr::new(192, 168, 50, 64));
        assert_eq!(c.len(), 254); // .1..=.254 inclusive
        assert!(!c.contains(&Ipv4Addr::new(192, 168, 50, 0))); // network excluded by range
        assert!(!c.contains(&Ipv4Addr::new(192, 168, 50, 255))); // broadcast excluded by range
        assert!(c.contains(&Ipv4Addr::new(192, 168, 50, 64))); // anchor IS a candidate now
        assert!(c.contains(&Ipv4Addr::new(192, 168, 50, 1)));
        assert!(c.contains(&Ipv4Addr::new(192, 168, 50, 254)));
        assert!(c.iter().all(|ip| ip.octets()[..3] == [192, 168, 50]));
    }

    #[test]
    fn scan_keeps_the_build_time_anchor_when_the_current_mapping_differs() {
        // Codex: /etc/hosts points at a learned address in ANOTHER /24; the build-time
        // anchor must remain a scan candidate so a broker that returned to it is found.
        let anchor = Ipv4Addr::new(192, 168, 50, 64); // build-time IP
        let mut tried = HashSet::new();
        tried.insert(Ipv4Addr::new(10, 0, 0, 40)); // current mapping, a different subnet
        let candidates: Vec<Ipv4Addr> = slash24_candidates(anchor)
            .into_iter()
            .filter(|ip| !tried.contains(ip))
            .collect();
        assert!(candidates.contains(&anchor)); // the build-time IP is probeable
        assert_eq!(candidates.len(), 254); // the out-of-subnet current mapping dropped nothing
    }

    #[test]
    fn scan_drops_the_current_stale_mapping_inside_the_anchor_subnet() {
        // Common case (no drift): current mapping == build-time anchor and it just failed,
        // so it is retired as the stale address and not re-probed this pass.
        let anchor = Ipv4Addr::new(192, 168, 50, 64);
        let mut tried = HashSet::new();
        tried.insert(anchor); // current mapping == anchor, the failing address
        let candidates: Vec<Ipv4Addr> = slash24_candidates(anchor)
            .into_iter()
            .filter(|ip| !tried.contains(ip))
            .collect();
        assert!(!candidates.contains(&anchor));
        assert_eq!(candidates.len(), 253);
    }

    #[test]
    fn scan_union_covers_both_confirmed_and_build_time_subnets() {
        // Codex: sweep the union of the last-confirmed /24 and the build-time /24, so a broker
        // that RETURNED to its original subnet (mDNS down) is found alongside the confirmed one.
        let confirmed = Ipv4Addr::new(10, 0, 0, 40);
        let build_time = Ipv4Addr::new(192, 168, 50, 64);
        let candidates = union_candidates(&[confirmed, build_time], &HashSet::new());
        assert!(candidates.contains(&build_time)); // original address probeable
        assert!(candidates.contains(&confirmed)); // confirmed address too
        assert!(candidates.contains(&Ipv4Addr::new(192, 168, 50, 1)));
        assert!(candidates.contains(&Ipv4Addr::new(10, 0, 0, 254)));
        assert_eq!(candidates.len(), 254 + 254); // two disjoint /24s
    }

    #[test]
    fn retire_scan_subnets_keeps_mdns_rejections_in_and_out_of_subnet() {
        // A scan re-arm re-probes the scanned /24 addresses (from `tried`) but must NOT forget any
        // mDNS rejection this outage — whether it sits INSIDE an anchor /24 or in another subnet.
        // The in-/24 case is the Codex P2 regression: folding mDNS rejections into `tried` let the
        // re-arm re-propose the same wrong in-/24 broker every pass.
        let anchor = Ipv4Addr::new(192, 168, 50, 64);
        let mut tried = HashSet::new();
        tried.insert(Ipv4Addr::new(192, 168, 50, 64)); // in-/24 (scan) address
        tried.insert(Ipv4Addr::new(192, 168, 50, 9)); // another in-/24 scan address
        let mut mdns_rejected = HashSet::new();
        mdns_rejected.insert(Ipv4Addr::new(192, 168, 50, 99)); // in-/24 mDNS rejection
        mdns_rejected.insert(Ipv4Addr::new(10, 0, 0, 7)); // cross-subnet mDNS rejection
        let mut dry = 0u32;
        retire_scan_subnets(&[anchor], &mut tried, &mut mdns_rejected, &mut dry);
        assert_eq!(dry, 1);
        assert!(!tried.contains(&Ipv4Addr::new(192, 168, 50, 64))); // re-armed
        assert!(!tried.contains(&Ipv4Addr::new(192, 168, 50, 9))); // re-armed
        assert!(mdns_rejected.contains(&Ipv4Addr::new(192, 168, 50, 99))); // in-/24 rejection kept
        assert!(mdns_rejected.contains(&Ipv4Addr::new(10, 0, 0, 7))); // cross-subnet rejection kept
    }

    #[test]
    fn retire_scan_subnets_full_clears_after_enough_dry_cycles() {
        // After FULL_RESET_AFTER_DRY_CYCLES fruitless passes it forgets EVERYTHING — both `tried`
        // and every mDNS rejection (in-/24 and cross-subnet) — so recovery self-heals (Copilot),
        // on a bounded cadence.
        let anchor = Ipv4Addr::new(192, 168, 50, 64);
        let mut tried = HashSet::new();
        tried.insert(Ipv4Addr::new(192, 168, 50, 64)); // in-/24 scan address
        let mut mdns_rejected = HashSet::new();
        mdns_rejected.insert(Ipv4Addr::new(192, 168, 50, 99)); // in-/24 rejection
        mdns_rejected.insert(Ipv4Addr::new(10, 0, 0, 7)); // cross-subnet rejection
        let mut dry = 0u32;
        for _ in 0..FULL_RESET_AFTER_DRY_CYCLES - 1 {
            retire_scan_subnets(&[anchor], &mut tried, &mut mdns_rejected, &mut dry);
            assert!(mdns_rejected.contains(&Ipv4Addr::new(192, 168, 50, 99))); // still preserved
            assert!(mdns_rejected.contains(&Ipv4Addr::new(10, 0, 0, 7))); // still preserved
        }
        retire_scan_subnets(&[anchor], &mut tried, &mut mdns_rejected, &mut dry); // the Nth call
        assert!(tried.is_empty()); // full reset — scan set cleared
        assert!(mdns_rejected.is_empty()); // full reset — every mDNS rejection cleared
        assert_eq!(dry, 0); // counter reset
    }

    #[test]
    fn scan_union_dedups_when_both_anchors_share_a_subnet() {
        // The common case (broker never left): confirmed and build-time are the same /24, so
        // the union collapses to a single sweep.
        let candidates = union_candidates(
            &[Ipv4Addr::new(192, 168, 50, 64), Ipv4Addr::new(192, 168, 50, 200)],
            &HashSet::new(),
        );
        assert_eq!(candidates.len(), 254);
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
