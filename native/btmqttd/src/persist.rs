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

/// The tracked stair-light on/off, one token `on`/`off` (issue: light switch). Persisted
/// on the same reboot-persistent partition so the switch survives a reboot with the right
/// state instead of guessing — the actuator has no readable state to re-query.
const LIGHT_FILE: &str = "light-state";

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

fn light_file_in(dir: &Path) -> PathBuf {
    dir.join(LIGHT_FILE)
}

/// The persisted state as `(file_exists, record)`, read in one pass. `file_exists` is
/// whether the state FILE is present at all (any content) — even one holding a record for a
/// DIFFERENT host or a corrupt one, neither of which parses — so the caller can clear it
/// after a build-IP connection and a later switch back to that host can't resurrect its
/// obsolete learned IP (Codex/Copilot). `record` is `Some((base_ip, learned_ip))` only when
/// the file parses a record for THIS host (ASCII case-insensitive) with a private LAN
/// learned IPv4; the caller compares `base_ip` against the build-time mapping (a re-flash
/// mismatch ⇒ stale). Blocking `std::fs`; call via `spawn_blocking` off the async runtime.
pub fn read_state(host: &str) -> (bool, Option<(Ipv4Addr, Ipv4Addr)>) {
    read_state_in(&state_dir(), host)
}

/// Persist `host`'s learned IP atomically, recording the `base_ip` (build-time mapping)
/// it was learned against. Writes a unique 0600 temp beside the target then renames over
/// it, so a concurrent reader (or a reboot mid-write) never sees a torn file. Returns
/// `true` only when the write landed, so the caller advances its in-memory change-gate
/// ONLY on success and retries on the next ConnAck if the partition was briefly
/// unavailable (Codex/Copilot). Blocking; call via `spawn_blocking`.
#[must_use]
pub fn store(host: &str, base_ip: Ipv4Addr, learned_ip: Ipv4Addr) -> bool {
    store_in(&state_dir(), host, base_ip, learned_ip)
}

/// Forget any persisted record: called when the broker is confirmed back at its build-time
/// address, so a reboot doesn't seed a now-stale learned IP. Returns `true` when the file
/// is gone (removed, or already absent); `false` on an I/O error so the caller retries.
/// Blocking; call via `spawn_blocking`.
#[must_use]
pub fn clear() -> bool {
    clear_in(&state_dir())
}

/// Read the tracked stair-light state for the actuator at `want_where`
/// (`Some(true)`=on / `Some(false)`=off), or `None` when unknown — no file, unparseable,
/// or a record for a DIFFERENT WHERE (a build that changed `LIGHT_WHERE` must not inherit
/// the previous actuator's state). Blocking; call via `spawn_blocking`.
pub fn read_light(want_where: &str) -> Option<bool> {
    read_light_in(&state_dir(), want_where)
}

/// Persist the tracked stair-light state, KEYED by the actuator `where_` so a later WHERE
/// change can't restore an unrelated relay's state. `None` clears it (an unknown state,
/// e.g. after a physical toggle from an unknown baseline). Atomic write + dir fsync like
/// [`store`], so a reboot mid-write never sees a torn file. Returns `true` on success.
/// Blocking; call via `spawn_blocking`.
#[must_use]
pub fn store_light(where_: &str, on: Option<bool>) -> bool {
    store_light_in(&state_dir(), where_, on)
}

/// Forget any persisted stair-light record — called when the feature is DISABLED, so
/// re-enabling the same WHERE later starts from an UNKNOWN baseline instead of restoring a
/// value that may have gone stale (physical toggles while tracking was off) — Codex. Returns
/// `true` when the file is gone (removed, or already absent). Blocking; call via
/// `spawn_blocking`.
#[must_use]
pub fn clear_light() -> bool {
    clear_light_in(&state_dir())
}

// ---------------------------------------------------------------------------
// Directory-injected cores (unit-tested with a temp dir — no process-env
// mutation, so the tests are parallel-safe). The public fns above just resolve
// $BTMQTTD_STATE_DIR and delegate.
// ---------------------------------------------------------------------------

fn read_state_in(dir: &Path, host: &str) -> (bool, Option<(Ipv4Addr, Ipv4Addr)>) {
    match std::fs::read_to_string(state_file_in(dir)) {
        Ok(text) => (true, parse_record(&text, host)),
        // Genuinely absent → nothing to clear later.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (false, None),
        // Present but unreadable (e.g. a permission blip): treat as existing so a build-IP
        // ConnAck still attempts to clear it, rather than leaving it to resurface.
        Err(_) => (true, None),
    }
}

/// Durably write `body` to `path` via a temp file + rename + directory fsync — the shared
/// atomicity-critical path for every persisted record (broker IP, light state). Creating
/// `dir` first, then writing a unique temp, renaming it over `path`, and fsync'ing the
/// DIRECTORY so the rename (the dir entry now pointing at the new inode) is durable, not
/// just the file bytes. A dir-sync failure is reported as a FAILED write (`false`) so the
/// caller doesn't advance its change-gate and retries later, rather than claiming a
/// durability it didn't get (CodeRabbit). Kept in ONE place so the two records can't drift.
fn atomic_write_in(dir: &Path, path: &Path, body: &[u8]) -> bool {
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("btmqttd: persist: cannot create {}: {e}", dir.display());
        return false;
    }
    let Some(path_str) = path.to_str() else {
        eprintln!("btmqttd: persist: path is not valid UTF-8");
        return false;
    };
    match crate::receiver::create_unique_temp(path_str, body) {
        Ok(tmp) => match std::fs::rename(&tmp, path_str) {
            Ok(()) => match std::fs::File::open(dir).and_then(|dirf| dirf.sync_all()) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("btmqttd: persist: cannot sync dir {}: {e}", dir.display());
                    false
                }
            },
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                eprintln!("btmqttd: persist: cannot write {path_str}: {e}");
                false
            }
        },
        Err(e) => {
            eprintln!("btmqttd: persist: cannot create temp for {path_str}: {e}");
            false
        }
    }
}

/// Remove `path`, treating an already-absent file as success — the shared "clear a record"
/// path (broker IP, light state → unknown). After a real unlink, fsync the PARENT directory
/// so the removal (a dir-entry change) is DURABLE, not just cached — otherwise a power loss
/// could restore the "deleted" file on reboot and resurrect a stale record (CodeRabbit);
/// symmetric with [`atomic_write_in`]'s dir fsync. A dir-sync failure is reported as a FAILED
/// clear (`false`) so the caller retries, rather than claiming a durability it didn't get.
/// Only a real removal error (or that dir-sync failure) is a failure; an already-absent file
/// is success (nothing to make durable).
fn remove_or_absent(path: &Path) -> bool {
    match std::fs::remove_file(path) {
        Ok(()) => match path.parent() {
            Some(dir) => match std::fs::File::open(dir).and_then(|d| d.sync_all()) {
                Ok(()) => true,
                Err(e) => {
                    eprintln!(
                        "btmqttd: persist: cannot sync dir {} after clearing {}: {e}",
                        dir.display(),
                        path.display()
                    );
                    false
                }
            },
            None => true, // no parent to sync (shouldn't happen for our joined paths)
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true, // already gone
        Err(e) => {
            eprintln!("btmqttd: persist: cannot clear {}: {e}", path.display());
            false
        }
    }
}

fn store_in(dir: &Path, host: &str, base_ip: Ipv4Addr, learned_ip: Ipv4Addr) -> bool {
    let body = format_state(host, base_ip, learned_ip);
    atomic_write_in(dir, &state_file_in(dir), body.as_bytes())
}

fn clear_in(dir: &Path) -> bool {
    remove_or_absent(&state_file_in(dir))
}

fn clear_light_in(dir: &Path) -> bool {
    remove_or_absent(&light_file_in(dir))
}

fn read_light_in(dir: &Path, want_where: &str) -> Option<bool> {
    let text = std::fs::read_to_string(light_file_in(dir)).ok()?;
    let line = text.lines().next()?.trim();
    // Record is `<where>\t<on|off>`. A record for a DIFFERENT WHERE (a build that changed
    // LIGHT_WHERE — the cfg/extra partition survives reflashes) must NOT be inherited.
    let (where_, token) = line.split_once('\t')?;
    if where_ != want_where {
        return None;
    }
    match token.trim() {
        "on" => Some(true),
        "off" => Some(false),
        _ => None,
    }
}

fn store_light_in(dir: &Path, where_: &str, on: Option<bool>) -> bool {
    let path = light_file_in(dir);
    // Unknown → remove the file (a missing file reads back as None).
    let Some(state) = on.map(|b| if b { "on" } else { "off" }) else {
        return remove_or_absent(&path);
    };
    let body = format!("{where_}\t{state}\n");
    atomic_write_in(dir, &path, body.as_bytes())
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
    // format_state writes EXACTLY one line of three fields, so reject anything extra as
    // corrupt: a non-empty trailing line, or a 4th token on the first line (CodeRabbit).
    if text.lines().skip(1).any(|rest| !rest.trim().is_empty()) {
        return None;
    }
    let mut cols = line.split_whitespace();
    let host = cols.next()?;
    let base = cols.next()?.parse::<Ipv4Addr>().ok()?;
    let learned = cols.next()?.parse::<Ipv4Addr>().ok()?;
    if cols.next().is_some() {
        return None; // extra field on the line → corrupt
    }
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
    fn parse_record_rejects_extra_fields_or_trailing_lines() {
        // format_state writes exactly three fields on one line; anything extra is corrupt.
        assert_eq!(parse_record("b\t192.168.50.64\t192.168.50.200\tjunk\n", "b"), None);
        assert_eq!(parse_record("b\t192.168.50.64\t192.168.50.200\nextra line\n", "b"), None);
        // A single trailing newline (what format_state emits) is fine.
        assert_eq!(parse_record("b\t192.168.50.64\t192.168.50.200\n", "b"), Some((BUILD, LEARNED)));
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
        // A per-call nonce (atop the pid) keeps the temp dir unique even if this pattern is
        // reused by another parallel test or a rerun in the same process (Copilot).
        use std::sync::atomic::{AtomicU32, Ordering};
        static NONCE: AtomicU32 = AtomicU32::new(0);
        let uniq = NONCE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir()
            .join(format!("btmqttd-persist-{}-{uniq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(read_state_in(&dir, "broker.lan"), (false, None)); // no file yet
        assert!(store_in(&dir, "broker.lan", BUILD, LEARNED));
        assert_eq!(read_state_in(&dir, "broker.lan"), (true, Some((BUILD, LEARNED))));
        // A different host: the FILE still exists (so it can be cleared) but no record parses.
        assert_eq!(read_state_in(&dir, "other"), (true, None));
        // Overwrite updates in place.
        let l2 = Ipv4Addr::new(192, 168, 50, 201);
        assert!(store_in(&dir, "broker.lan", BUILD, l2));
        assert_eq!(read_state_in(&dir, "broker.lan"), (true, Some((BUILD, l2))));
        // Clear forgets it; clearing again is still success (missing file is success).
        assert!(clear_in(&dir));
        assert_eq!(read_state_in(&dir, "broker.lan"), (false, None));
        assert!(clear_in(&dir));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn light_state_store_read_clear_roundtrip() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NONCE: AtomicU32 = AtomicU32::new(1000);
        let uniq = NONCE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("btmqttd-light-{}-{uniq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(read_light_in(&dir, "112"), None); // no file yet
        assert!(store_light_in(&dir, "112", Some(true)));
        assert_eq!(read_light_in(&dir, "112"), Some(true));
        assert!(store_light_in(&dir, "112", Some(false)));
        assert_eq!(read_light_in(&dir, "112"), Some(false));
        // A record for a DIFFERENT WHERE is NOT inherited (a changed LIGHT_WHERE).
        assert_eq!(read_light_in(&dir, "999"), None);
        // None clears the file → reads back as unknown.
        assert!(store_light_in(&dir, "112", None));
        assert_eq!(read_light_in(&dir, "112"), None);
        assert!(store_light_in(&dir, "112", None)); // clearing an absent file is still success

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_light_in_removes_the_record_and_is_idempotent() {
        // The disabled-mode cleanup path: an existing light-state record is removed (durably —
        // remove_or_absent fsyncs the dir), so a later re-enable reads back unknown; clearing
        // an already-absent record is still success.
        use std::sync::atomic::{AtomicU32, Ordering};
        static NONCE: AtomicU32 = AtomicU32::new(2000);
        let uniq = NONCE.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("btmqttd-clearlight-{}-{uniq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        assert!(store_light_in(&dir, "112", Some(true)));
        assert_eq!(read_light_in(&dir, "112"), Some(true));
        assert!(clear_light_in(&dir)); // disabled-mode cleanup removes it
        assert_eq!(read_light_in(&dir, "112"), None); // re-enable would start unknown
        assert!(clear_light_in(&dir)); // already absent → still success

        let _ = std::fs::remove_dir_all(&dir);
    }
}
