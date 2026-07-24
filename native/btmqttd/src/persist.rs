//! Persist the connect-confirmed broker IP across reboots (issue #49 item 1).
//!
//! ## Why
//! Rediscovery (`rediscovery.rs`) repoints `/etc/hosts` when the broker moves to a new
//! LAN IP, but `/etc/hosts` is a tmpfs symlink (`/var/tmp/hosts`), so a reboot loses the
//! learned address: the boot init re-seeds the *build-time* IP and the unit must
//! rediscover from scratch — the full failure streak (`REDISCOVER_AFTER_FAILURES` ×
//! ~5 s backoff) in the dark, then a `/24` scan. Remembering the confirmed IP on a
//! writable, reboot-persistent partition lets the next boot seed `/etc/hosts` with it
//! directly, so the bridge reconnects immediately.
//!
//! ## Where (and the rootfs golden rule)
//! The rootfs is mounted **read-only** and must never be remounted `rw` (the device's
//! `dropbear` init is fragile), so we never write there. The unit exposes a SEPARATE
//! ext4 partition — `/dev/mmcblk2p7` mounted at `/home/bticino/cfg/extra`, `rw,sync` —
//! for persistent config (the vendor's own Azure/Eliot state lives there too); `sync`
//! makes each write durable across a power cut. State lives in a `btmqttd/` subdir. The
//! location is overridable via `$BTMQTTD_STATE_DIR` (tests/dev), mirroring `$BTMQTTD_CONF`
//! in `config.rs`.
//!
//! ## What is stored, and why the base IP matters
//! The record is `<host>\t<base_ip>\t<learned_ip>`:
//!   * `learned_ip` is the connect-confirmed address to seed at boot;
//!   * `base_ip` is the **build-time** `/etc/hosts` IP that was in effect when the move
//!     was learned. The boot restore applies `learned_ip` ONLY when `base_ip` still
//!     equals the current build-time mapping. This matters because the `cfg/extra`
//!     partition SURVIVES a firmware re-flash: without the base check, a firmware update
//!     that re-points the broker name to a NEW IP would be silently overridden by a
//!     stale learned address. A mismatched base ⇒ the record is stale ⇒ ignored.
//!
//! The caller applies the policy (`main`): it also recovers the base from an existing
//! record across a watchdog respawn, applies the plaintext MAC gate before seeding, and
//! `clear`s the record when the broker returns to the build-time IP.
//!
//! ## Trust boundary (unchanged)
//! Only an IP **confirmed by a successful authenticated/TLS `ConnAck`** is ever
//! persisted (`main.rs` writes on `ConnAck`), never a mere scan hit. And in plaintext
//! mode the boot restore re-applies the SAME ARP-MAC gate `rediscover` uses before
//! seeding (see `main`), so a DHCP-reassigned address can't take our credentials on the
//! first connect; under TLS the reconnect's pinned-cert handshake is the gate.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// The device's writable, reboot-persistent config partition (`/dev/mmcblk2p7`, ext4
/// `rw,sync`). `btmqttd` state lives in a subdir so it doesn't clutter the vendor's
/// `cfg/extra` area.
const DEFAULT_STATE_DIR: &str = "/home/bticino/cfg/extra/btmqttd";

/// The state file: one line, `<host>\t<base_ip>\t<learned_ip>`.
const STATE_FILE: &str = "broker-ip";

/// The state directory, honouring `$BTMQTTD_STATE_DIR` (tests/dev) like `config.rs`
/// honours `$BTMQTTD_CONF`.
fn state_dir() -> PathBuf {
    std::env::var_os("BTMQTTD_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR))
}

fn state_file_in(dir: &Path) -> PathBuf {
    dir.join(STATE_FILE)
}

/// The persisted `(base_ip, learned_ip)` record for `host`, or `None`. Returned when the
/// record is for THIS host (ASCII case-insensitive) and its learned address is a private
/// LAN IPv4 (the same bound rediscovery enforces). The caller compares `base_ip` against
/// the current build-time mapping — a mismatch (a firmware re-flash re-pointed the broker)
/// means the record is stale. `None` on a different host, a malformed/non-private learned
/// address, or a missing file. Blocking `std::fs`; call via `spawn_blocking` off the
/// async runtime.
pub fn read_record(host: &str) -> Option<(Ipv4Addr, Ipv4Addr)> {
    read_record_in(&state_dir(), host)
}

/// Persist `host`'s learned IP atomically, recording the `base_ip` (build-time mapping)
/// it was learned against. Writes a unique 0600 temp beside the target then renames over
/// it, so a concurrent reader (or a reboot mid-write) never sees a torn file. Best-effort
/// — a missing/full/unmounted partition just means we can't remember this pass; the
/// runtime repoint still worked, and the next boot falls back to the build-time seed.
/// Blocking; call via `spawn_blocking`.
pub fn store(host: &str, base_ip: Ipv4Addr, learned_ip: Ipv4Addr) {
    store_in(&state_dir(), host, base_ip, learned_ip);
}

/// Forget any persisted record (best-effort): called when the broker is confirmed back at
/// its build-time address, so a reboot doesn't seed a now-stale learned IP. A missing file
/// is success. Blocking; call via `spawn_blocking`.
pub fn clear() {
    clear_in(&state_dir());
}

// ---------------------------------------------------------------------------
// Directory-injected cores (unit-tested with a temp dir — no process-env
// mutation, so the tests are parallel-safe). The public fns above just resolve
// $BTMQTTD_STATE_DIR and delegate.
// ---------------------------------------------------------------------------

fn read_record_in(dir: &Path, host: &str) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let text = std::fs::read_to_string(state_file_in(dir)).ok()?;
    parse_record(&text, host)
}

fn store_in(dir: &Path, host: &str, base_ip: Ipv4Addr, learned_ip: Ipv4Addr) {
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("btmqttd: persist: cannot create {}: {e}", dir.display());
        return;
    }
    let path = state_file_in(dir);
    let Some(path_str) = path.to_str() else {
        eprintln!("btmqttd: persist: state path is not valid UTF-8");
        return;
    };
    let body = format_state(host, base_ip, learned_ip);
    match crate::receiver::create_unique_temp(path_str, body.as_bytes()) {
        Ok(tmp) => {
            if let Err(e) = std::fs::rename(&tmp, path_str) {
                let _ = std::fs::remove_file(&tmp);
                eprintln!("btmqttd: persist: cannot write {path_str}: {e}");
            }
        }
        Err(e) => eprintln!("btmqttd: persist: cannot create temp for {path_str}: {e}"),
    }
}

fn clear_in(dir: &Path) {
    let path = state_file_in(dir);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => eprintln!("btmqttd: persist: cannot clear {}: {e}", path.display()),
    }
}

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested). No I/O — parsing/formatting the state body.
// ---------------------------------------------------------------------------

/// The one-line state body: `<host>\t<base_ip>\t<learned_ip>\n` (tab-separated, like the
/// hosts file, so the record is human-greppable on the device).
fn format_state(host: &str, base_ip: Ipv4Addr, learned_ip: Ipv4Addr) -> String {
    format!("{host}\t{base_ip}\t{learned_ip}\n")
}

/// Parse the state body into `(base_ip, learned_ip)`, only when its first line records
/// `want_host` (ASCII case-insensitive — hostnames are case-insensitive) and the learned
/// address is a private LAN IPv4. Anything else — a different host, a non-private/malformed
/// learned address, a short or empty line — yields `None`. The base is returned as-is (the
/// caller decides whether it still matches the build-time IP).
fn parse_record(text: &str, want_host: &str) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let line = text.lines().next()?.trim();
    let mut cols = line.split_whitespace();
    let host = cols.next()?;
    let base = cols.next()?.parse::<Ipv4Addr>().ok()?;
    let learned = cols.next()?.parse::<Ipv4Addr>().ok()?;
    (host.eq_ignore_ascii_case(want_host) && learned.is_private()).then_some((base, learned))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUILD: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 64);
    const LEARNED: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 200);

    #[test]
    fn parse_record_returns_base_and_learned_when_host_matches() {
        let body = "Broker.LAN\t192.168.50.64\t192.168.50.200\n";
        assert_eq!(parse_record(body, "broker.lan"), Some((BUILD, LEARNED)));
        assert_eq!(parse_record(body, "BROKER.LAN"), Some((BUILD, LEARNED)));
    }

    #[test]
    fn parse_record_rejects_other_host() {
        let body = "old-broker\t192.168.50.64\t192.168.50.200\n";
        assert_eq!(parse_record(body, "new-broker"), None);
    }

    #[test]
    fn parse_record_rejects_non_private_or_malformed_learned() {
        assert_eq!(parse_record("b\t192.168.50.64\t8.8.8.8\n", "b"), None); // public
        assert_eq!(parse_record("b\t192.168.50.64\t127.0.0.1\n", "b"), None); // loopback
        assert_eq!(parse_record("b\t192.168.50.64\t169.254.1.1\n", "b"), None); // link-local
        assert_eq!(parse_record("b\t192.168.50.64\tnot-an-ip\n", "b"), None);
        assert_eq!(parse_record("b\t192.168.50.64\n", "b"), None); // no learned column
        assert_eq!(parse_record("b\n", "b"), None); // no base/learned
        assert_eq!(parse_record("", "b"), None); // empty
    }

    #[test]
    fn parse_record_keeps_base_verbatim_for_the_caller() {
        // The base is returned even when it differs from any build IP — the caller does
        // the base-vs-build comparison (a re-flash check), not the parser.
        let body = "b\t10.0.0.9\t192.168.50.200\n";
        assert_eq!(parse_record(body, "b"), Some((Ipv4Addr::new(10, 0, 0, 9), LEARNED)));
    }

    #[test]
    fn format_then_parse_roundtrips() {
        let body = format_state("broker.lan", BUILD, LEARNED);
        assert_eq!(body, "broker.lan\t192.168.50.64\t192.168.50.200\n");
        assert_eq!(parse_record(&body, "broker.lan"), Some((BUILD, LEARNED)));
    }

    #[test]
    fn store_read_clear_roundtrip_in_temp_dir() {
        // Directory-injected cores — no env mutation, so this is parallel-safe (Copilot).
        let dir = std::env::temp_dir().join(format!("btmqttd-persist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(read_record_in(&dir, "broker.lan"), None); // nothing yet
        store_in(&dir, "broker.lan", BUILD, LEARNED);
        assert_eq!(read_record_in(&dir, "broker.lan"), Some((BUILD, LEARNED)));
        // A different host does not read the stored value.
        assert_eq!(read_record_in(&dir, "other"), None);
        // Overwrite updates in place.
        let l2 = Ipv4Addr::new(192, 168, 50, 201);
        store_in(&dir, "broker.lan", BUILD, l2);
        assert_eq!(read_record_in(&dir, "broker.lan"), Some((BUILD, l2)));
        // Clear forgets it; clearing again is still fine (missing file is success).
        clear_in(&dir);
        assert_eq!(read_record_in(&dir, "broker.lan"), None);
        clear_in(&dir);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
