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
//! for persistent config; `sync` makes each write durable across a power cut. State
//! lives in a `btmqttd/` subdir there. The location is overridable via
//! `$BTMQTTD_STATE_DIR` (tests/dev), mirroring `$BTMQTTD_CONF` in `config.rs`.
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
//! The caller also `clear`s the record when the broker returns to the build-time IP, so
//! a broker that moves back home doesn't leave a stale learned address to seed.
//!
//! ## Trust boundary (unchanged)
//! Only an IP **confirmed by a successful authenticated/TLS `ConnAck`** is ever
//! persisted (`main.rs` writes on `ConnAck`), never a mere scan hit — the same trust
//! boundary rediscovery already enforces. And the boot seed only *repoints the name*;
//! the reconnect still validates the broker (pinned TLS / MAC-gated plaintext), so even
//! a stale persisted IP is safe — it fails to authenticate and normal rediscovery
//! resumes.

use std::net::Ipv4Addr;
use std::path::PathBuf;

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

fn state_path() -> PathBuf {
    state_dir().join(STATE_FILE)
}

/// The persisted learned IP to seed for `host`, or `None`. Returned only when the record
/// is for THIS host (ASCII case-insensitive), its stored base IP still equals the current
/// build-time mapping `build_ip` (else the firmware was re-flashed with a different broker
/// IP and the record is stale), and the learned address is a private LAN IPv4 (the same
/// bound rediscovery enforces). Any mismatch, malformed content, or missing file ⇒ `None`,
/// so the boot seed falls back to the build-time `/etc/hosts` mapping.
pub fn load(host: &str, build_ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let text = std::fs::read_to_string(state_path()).ok()?;
    parse_state(&text, host, build_ip)
}

/// Persist `host`'s learned IP atomically, recording the `base_ip` (build-time mapping)
/// it was learned against. Writes a unique 0600 temp beside the target then renames over
/// it, so a concurrent reader (or a reboot mid-write) never sees a torn file. Best-effort
/// — a missing/full/unmounted partition just means we can't remember this pass; the
/// runtime repoint still worked, and the next boot falls back to the build-time seed.
/// Creates the state dir first.
pub fn store(host: &str, base_ip: Ipv4Addr, learned_ip: Ipv4Addr) {
    let dir = state_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("btmqttd: persist: cannot create {}: {e}", dir.display());
        return;
    }
    let path = state_path();
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

/// Forget any persisted learned IP (best-effort): called when the broker is confirmed
/// back at its build-time address, so a reboot doesn't seed a now-stale learned IP. A
/// missing file is success (nothing to forget).
pub fn clear() {
    match std::fs::remove_file(state_path()) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => eprintln!("btmqttd: persist: cannot clear {}: {e}", state_path().display()),
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

/// Parse the state body, returning the learned IP only when its first line records
/// `want_host` (ASCII case-insensitive — hostnames are case-insensitive), the stored base
/// IP equals `build_ip` (the record is for the current firmware, not a stale pre-re-flash
/// one), and the learned address is a private LAN IPv4. Anything else — a different host,
/// a base that no longer matches, a non-private/malformed learned address, a short or
/// empty line — yields `None`.
fn parse_state(text: &str, want_host: &str, build_ip: Ipv4Addr) -> Option<Ipv4Addr> {
    let line = text.lines().next()?.trim();
    let mut cols = line.split_whitespace();
    let host = cols.next()?;
    let base = cols.next()?.parse::<Ipv4Addr>().ok()?;
    let learned = cols.next()?.parse::<Ipv4Addr>().ok()?;
    (host.eq_ignore_ascii_case(want_host) && base == build_ip && learned.is_private())
        .then_some(learned)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUILD: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 64);
    const LEARNED: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 200);

    #[test]
    fn parse_state_returns_learned_when_host_and_base_match() {
        let body = "Broker.LAN\t192.168.50.64\t192.168.50.200\n";
        assert_eq!(parse_state(body, "broker.lan", BUILD), Some(LEARNED));
        assert_eq!(parse_state(body, "BROKER.LAN", BUILD), Some(LEARNED));
    }

    #[test]
    fn parse_state_rejects_stale_base_after_reflash() {
        // The firmware was re-flashed pointing the broker at a NEW build IP; the record
        // (learned against the OLD base) must be ignored so it can't override the reflash.
        let body = "broker\t192.168.50.64\t192.168.50.200\n";
        let new_build = Ipv4Addr::new(192, 168, 50, 77);
        assert_eq!(parse_state(body, "broker", new_build), None);
    }

    #[test]
    fn parse_state_rejects_other_host() {
        let body = "old-broker\t192.168.50.64\t192.168.50.200\n";
        assert_eq!(parse_state(body, "new-broker", BUILD), None);
    }

    #[test]
    fn parse_state_rejects_non_private_or_malformed_learned() {
        assert_eq!(parse_state("b\t192.168.50.64\t8.8.8.8\n", "b", BUILD), None); // public
        assert_eq!(parse_state("b\t192.168.50.64\t127.0.0.1\n", "b", BUILD), None); // loopback
        assert_eq!(parse_state("b\t192.168.50.64\t169.254.1.1\n", "b", BUILD), None); // link-local
        assert_eq!(parse_state("b\t192.168.50.64\tnot-an-ip\n", "b", BUILD), None);
        assert_eq!(parse_state("b\t192.168.50.64\n", "b", BUILD), None); // no learned column
        assert_eq!(parse_state("b\n", "b", BUILD), None); // no base/learned
        assert_eq!(parse_state("", "b", BUILD), None); // empty
    }

    #[test]
    fn parse_state_accepts_all_private_learned_ranges() {
        let b10 = Ipv4Addr::new(10, 0, 0, 1);
        assert_eq!(parse_state("b\t10.0.0.1\t10.1.2.3\n", "b", b10), Some(Ipv4Addr::new(10, 1, 2, 3)));
        let b172 = Ipv4Addr::new(172, 16, 0, 1);
        assert_eq!(parse_state("b\t172.16.0.1\t172.16.5.5\n", "b", b172), Some(Ipv4Addr::new(172, 16, 5, 5)));
    }

    #[test]
    fn format_then_parse_roundtrips() {
        let body = format_state("broker.lan", BUILD, LEARNED);
        assert_eq!(body, "broker.lan\t192.168.50.64\t192.168.50.200\n");
        assert_eq!(parse_state(&body, "broker.lan", BUILD), Some(LEARNED));
    }

    #[test]
    fn store_load_clear_roundtrip_via_env_override() {
        // Isolate to a unique temp dir via $BTMQTTD_STATE_DIR; this test owns the var.
        let dir = std::env::temp_dir().join(format!("btmqttd-persist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // SAFETY: single-threaded test; set before any load/store/clear.
        unsafe { std::env::set_var("BTMQTTD_STATE_DIR", &dir) };

        assert_eq!(load("broker.lan", BUILD), None); // nothing yet
        store("broker.lan", BUILD, LEARNED);
        assert_eq!(load("broker.lan", BUILD), Some(LEARNED));
        // A different build IP (re-flash) ignores the stale record.
        assert_eq!(load("broker.lan", Ipv4Addr::new(192, 168, 50, 77)), None);
        // A different host does not read the stored value.
        assert_eq!(load("other", BUILD), None);
        // Overwrite updates in place.
        let l2 = Ipv4Addr::new(192, 168, 50, 201);
        store("broker.lan", BUILD, l2);
        assert_eq!(load("broker.lan", BUILD), Some(l2));
        // Clear forgets it; clearing again is still fine (missing file is success).
        clear();
        assert_eq!(load("broker.lan", BUILD), None);
        clear();

        unsafe { std::env::remove_var("BTMQTTD_STATE_DIR") };
        let _ = std::fs::remove_dir_all(&dir);
    }
}
