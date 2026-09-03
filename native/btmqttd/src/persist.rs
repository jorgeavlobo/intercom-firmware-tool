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

/// The LEARNED stair-light WHERE (digits), persisted so a unit that shipped in learn mode
/// (LIGHT_ENABLED with an empty WHERE) keeps the WHERE it learned across reboots.
const LIGHT_WHERE_FILE: &str = "light-where";

/// The LEARNED camera `sprop-parameter-sets` (issue #120), stored KEYED BY the video branch it was
/// learned on as a single line `<branch>\t<sprop>`. The parameter sets are branch-specific: the
/// hi- and lo-res `CAMERA_BRANCH` encode DIFFERENT SPS (the encoded resolution lives in the SPS), so
/// a value learned on one branch is wrong for the other. Because `cfg/extra` SURVIVES a reflash,
/// keying the record to the branch lets a reflash that FLIPS `CAMERA_BRANCH` reject the now-stale
/// value and re-learn (task #41) — the same "key the record so a config change can't restore a stale
/// value" discipline the light-state (`<where>\t…`) and broker-IP (base-IP) records use. Persisted so
/// the runtime tmpfs SDP (`/var/run/btmqttd/doorbell.sdp`) can be reassembled at every boot: go2rtcd
/// copies the read-only template SDP into tmpfs and, when a value for the CURRENT branch exists,
/// splices it into the fmtp line. `sprop.rs` learns it once per install and stores it here — the
/// durable source of truth for "provisioned", surviving reboots on the same cfg/extra partition.
const CAMERA_SPROP_FILE: &str = "camera-sprop";

/// The persisted idle-snapshot JPEG (issues #168/#169): the "empty doorway" still Home Assistant
/// polls for the camera-entity thumbnail, so a thumbnail poll never has to wake the live RTSP
/// stream (the on-demand thrash — issue #168). Phase 1 (#168) only READS it: the on-device HTTP
/// still endpoint (`still.rs`) serves this file when it is present and a valid JPEG, else a small
/// baked neutral placeholder. Phase 2 (#169) will WRITE it — capture the real idle view at first
/// run and on an HA "update idle snapshot" press. Lives on the same reboot- and reflash-persistent
/// `cfg/extra` partition as the other records (a captured idle image survives reboots and reflashes
/// so the thumbnail stays stable), NOT keyed: the newest capture is always the wanted one.
const IDLE_JPG_FILE: &str = "idle.jpg";

/// The last-known "latest available" bridge version (issue #114), one plain line. Persisted on
/// the same reboot-persistent partition so a daemon restart — or a firmware UPGRADE, where the
/// broker still holds the OLD binary's retained payload — re-asserts the correct
/// `installed_version` and any genuine "update available" at birth WITHOUT waiting for a network
/// fetch. Unlike the broker-IP/light/sprop records this is deliberately NOT keyed: a stale hint
/// is self-correcting — Home Assistant compares installed-vs-latest (a value older than the
/// running version simply reads as "up to date") and the daily check overwrites it with the
/// authoritative manifest value — so no reflash-staleness guard is needed.
const UPDATE_LATEST_FILE: &str = "update-latest";

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
/// obsolete learned IP. `record` is `Some((base_ip, learned_ip))` only when
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
/// unavailable. Blocking; call via `spawn_blocking`.
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

/// Outcome of restoring the persisted stair-light state for a configured WHERE.
pub enum LightRestore {
    /// A valid `on`/`off` record for THIS WHERE — restore it.
    State(bool),
    /// No usable record: no file, a record for a DIFFERENT WHERE (a build that changed
    /// `LIGHT_WHERE`), or a corrupt/unparseable one. Safe to CLEAR so a later WHERE change
    /// starts from a known-unknown baseline.
    Absent,
    /// The record could not be READ (a transient I/O error — a permission or storage blip).
    /// Do NOT clear it: a valid state may still be on disk, so keep it and retry next boot,
    /// rather than deleting a possibly-good record and starting from an unknown baseline.
    Unreadable,
}

/// Read the tracked stair-light state for the actuator at `want_where`. Distinguishes a valid
/// record ([`LightRestore::State`]) from a genuinely absent/mismatched/corrupt one
/// ([`LightRestore::Absent`], safe to clear) and from an I/O read failure
/// ([`LightRestore::Unreadable`], must be retained). Blocking; call via `spawn_blocking`.
pub fn read_light(want_where: &str) -> LightRestore {
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
/// value that may have gone stale (physical toggles while tracking was off). Returns
/// `true` when the file is gone (removed, or already absent). Blocking; call via
/// `spawn_blocking`.
#[must_use]
pub fn clear_light() -> bool {
    clear_light_in(&state_dir())
}

/// Persist the LEARNED stair-light WHERE (digits) so a learn-mode unit keeps it across
/// reboots. Atomic write + dir fsync like the other records. Returns `true` on success.
/// Blocking; call via `spawn_blocking`.
#[must_use]
pub fn store_light_where(where_: &str) -> bool {
    let dir = state_dir();
    atomic_write_in(&dir, &light_where_file_in(&dir), where_.as_bytes())
}

/// Forget any LEARNED stair-light WHERE — called when the feature is DISABLED, so disabling is
/// a clean reset: re-enabling in learn mode re-learns rather than silently restoring an address
/// from a past life. Returns `true` when the file is gone (removed, or already
/// absent). Blocking; call via `spawn_blocking`.
#[must_use]
pub fn clear_light_where() -> bool {
    clear_light_where_in(&state_dir())
}

/// Read the persisted LEARNED WHERE (digits only). Returns `None` when absent, unreadable,
/// or not a plain digit string — a caller then falls back to the build-time `LIGHT_WHERE`.
pub fn read_light_where() -> Option<String> {
    read_light_where_in(&state_dir())
}

fn light_where_file_in(dir: &Path) -> PathBuf {
    dir.join(LIGHT_WHERE_FILE)
}

fn read_light_where_in(dir: &Path) -> Option<String> {
    let s = std::fs::read_to_string(light_where_file_in(dir)).ok()?;
    let t = s.trim();
    (!t.is_empty() && t.bytes().all(|b| b.is_ascii_digit())).then(|| t.to_string())
}

/// Persist the LEARNED camera `sprop-parameter-sets` KEYED by the video `branch` it was learned on
/// (`<branch>\t<value>`), so the runtime SDP can be reassembled at boot from the read-only template +
/// this value, and a reflash that changes `CAMERA_BRANCH` re-learns instead of splicing the stale
/// value (task #41). Atomic write + dir fsync like the other records. Returns `true` on success.
/// Blocking; call via `spawn_blocking`.
#[must_use]
pub fn store_camera_sprop(branch: u8, value: &str) -> bool {
    store_camera_sprop_in(&state_dir(), branch, value)
}

fn store_camera_sprop_in(dir: &Path, branch: u8, value: &str) -> bool {
    atomic_write_in(dir, &camera_sprop_file_in(dir), format_camera_sprop(branch, value).as_bytes())
}

/// Forget any persisted camera sprop — a reflash re-learns from scratch, and clearing it is a
/// clean reset. Returns `true` when the file is gone (removed, or already absent). Blocking;
/// call via `spawn_blocking`.
#[must_use]
pub fn clear_camera_sprop() -> bool {
    clear_camera_sprop_in(&state_dir())
}

/// Read the persisted LEARNED camera sprop as `(branch, value)`. Returns `None` when absent,
/// unreadable, empty, or not in the `<branch>\t<value>` form — including a LEGACY bare value written
/// before the record was branch-keyed, which is treated as not-provisioned so the panel re-learns for
/// the current branch (a one-time relearn on upgrade). The caller compares `branch` against the
/// current `CAMERA_BRANCH`; a mismatch is stale (task #41). Trailing whitespace is trimmed.
pub fn read_camera_sprop() -> Option<(u8, String)> {
    read_camera_sprop_in(&state_dir())
}

/// Persist the last-known "latest available" bridge version (issue #114). Atomic write + dir
/// fsync like the other records. Returns `true` on success. Blocking; call via `spawn_blocking`.
#[must_use]
pub fn store_update_latest(value: &str) -> bool {
    let dir = state_dir();
    atomic_write_in(&dir, &update_latest_file_in(&dir), format!("{value}\n").as_bytes())
}

/// Read the persisted last-known "latest" bridge version — a single non-empty trimmed line, or
/// `None` when absent/unreadable/empty. The caller validates it as a plausible SemVer before use.
/// Blocking; call via `spawn_blocking`.
pub fn read_update_latest() -> Option<String> {
    read_update_latest_in(&state_dir())
}

fn update_latest_file_in(dir: &Path) -> PathBuf {
    dir.join(UPDATE_LATEST_FILE)
}

/// Upper bound on the idle-snapshot JPEG we will read into memory and serve (issue #168). A doorbell
/// still is tens of KB, so 256 KiB is generous headroom — and it matches the `write_file` decoded-data
/// contract, the cap on the only sanctioned way a file lands under `cfg/extra`. It BOUNDS the read: the
/// still endpoint reads this per request and up to `MAX_CONNS` handlers can do so concurrently, so an
/// oversized `idle.jpg` (one written outside the normal capture path — e.g. via the authenticated
/// `execute_command`) must not be slurped whole and copied N times. Over the cap ⇒ treat as absent ⇒
/// the endpoint serves the baked placeholder instead.
pub const MAX_IDLE_JPG_BYTES: u64 = 256 * 1024;

/// Read the persisted idle-snapshot JPEG (issue #168), or `None` when absent, unreadable, empty, or
/// LARGER than [`MAX_IDLE_JPG_BYTES`] (an oversized file falls back to the placeholder rather than
/// being loaded and copied per request). The bytes are returned VERBATIM — the caller (`still.rs`)
/// validates the JPEG magic before serving, so a truncated/garbage file never reaches Home Assistant.
/// Blocking `std::fs`; call via `spawn_blocking` off the async runtime. Only reads (Phase 1); Phase 2
/// (#169) adds the writer.
pub fn read_idle_jpg() -> Option<Vec<u8>> {
    read_idle_jpg_in(&state_dir())
}

/// Persist the captured idle-snapshot JPEG (issue #169): the first-run auto-capture and the HA
/// "Update idle snapshot" button write the real empty-doorway view here so the Phase-1 still endpoint
/// serves it on the next poll (no restart). Atomic write + dir fsync like every other record, so a
/// reboot mid-write never leaves a torn image — and, living on the reboot- and reflash-persistent
/// `cfg/extra` partition, the captured thumbnail survives both. NOT keyed: the newest capture is always
/// the wanted one. The caller has already validated the bytes are a real JPEG.
///
/// `commit_ok` is a COMMIT GATE evaluated at the LAST moment — after the temp file is written, in the
/// same blocking step, immediately before the atomic rename that makes it the new `idle.jpg`. `None`
/// discards the temp and leaves the existing `idle.jpg` UNTOUCHED; `Some(guard)` proceeds and the guard is
/// held ACROSS the rename (see [`atomic_write_gated_in`]). `capture_idle` returns a shared mutex guard
/// there and takes the same mutex in `note_ring()`, so the final ring check and the rename are one
/// critical section against ring detection on the runtime thread — a ring detected DURING the (blocking)
/// write can neither slip between the check and the rename nor get a visitor frame persisted as the
/// empty-doorway thumbnail. Returns `true` only when the rename committed AND the parent-dir fsync that
/// makes it durable succeeded; a post-rename fsync failure returns `false` even though `idle.jpg` may
/// already have been replaced in the (not-yet-durable) directory — treat `false` as "not reliably stored",
/// not as "unchanged". Blocking; call via `spawn_blocking`.
#[must_use]
pub fn store_idle_jpg<G>(bytes: &[u8], commit_ok: impl FnOnce() -> Option<G>) -> bool {
    let dir = state_dir();
    atomic_write_gated_in(&dir, &idle_jpg_file_in(&dir), bytes, commit_ok)
}

fn idle_jpg_file_in(dir: &Path) -> PathBuf {
    dir.join(IDLE_JPG_FILE)
}

fn read_idle_jpg_in(dir: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(idle_jpg_file_in(dir)).ok()?;
    // Read at most the cap PLUS ONE byte, so a file exactly at the cap is kept while anything larger is
    // detected (buf grows to cap+1) and rejected — without ever allocating more than cap+1 bytes.
    let mut buf = Vec::new();
    file.take(MAX_IDLE_JPG_BYTES + 1).read_to_end(&mut buf).ok()?;
    (!buf.is_empty() && buf.len() as u64 <= MAX_IDLE_JPG_BYTES).then_some(buf)
}

fn read_update_latest_in(dir: &Path) -> Option<String> {
    let s = std::fs::read_to_string(update_latest_file_in(dir)).ok()?;
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

fn camera_sprop_file_in(dir: &Path) -> PathBuf {
    dir.join(CAMERA_SPROP_FILE)
}

fn read_camera_sprop_in(dir: &Path) -> Option<(u8, String)> {
    let s = std::fs::read_to_string(camera_sprop_file_in(dir)).ok()?;
    parse_camera_sprop(&s)
}

fn clear_camera_sprop_in(dir: &Path) -> bool {
    remove_or_absent(&camera_sprop_file_in(dir))
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
/// durability it didn't get. Kept in ONE place so the two records can't drift.
fn atomic_write_in(dir: &Path, path: &Path, body: &[u8]) -> bool {
    atomic_write_gated_in(dir, path, body, || Some(()))
}

/// As [`atomic_write_in`], but `commit_ok` is a COMMIT GATE evaluated after the temp file is written and
/// immediately before the rename (the atomic commit): `None` discards the temp and leaves `path` untouched
/// (returns `false`); `Some(guard)` proceeds with the rename and — crucially — the returned `guard` is
/// HELD across the rename, then dropped the instant the swap is done (before the durability fsync). The
/// gate therefore does more than run without an async yield: a caller can return a lock guard so the
/// check-then-rename is one critical section against ANOTHER OS THREAD (the gate runs on the blocking
/// pool; a concurrent mutator runs on the runtime thread), not merely adjacent statements. `capture_idle`
/// uses this to serialize its final ring check + rename with `note_ring()` under a shared mutex, so a ring
/// detected on the runtime thread can land strictly before the check (→ vetoed) or strictly after the
/// rename (→ the visitor frame was still the empty doorway at commit time), never invisibly between them.
fn atomic_write_gated_in<G>(
    dir: &Path,
    path: &Path,
    body: &[u8],
    commit_ok: impl FnOnce() -> Option<G>,
) -> bool {
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("btmqttd: persist: cannot create {}: {e}", dir.display());
        return false;
    }
    let Some(path_str) = path.to_str() else {
        eprintln!("btmqttd: persist: path is not valid UTF-8");
        return false;
    };
    match crate::receiver::create_unique_temp(path_str, body) {
        Ok(tmp) => {
            let commit_guard = match commit_ok() {
                Some(g) => g,
                None => {
                    // Vetoed at the commit point (e.g. a ring was detected during the write) — discard the
                    // temp and leave the existing file in place.
                    let _ = std::fs::remove_file(&tmp);
                    return false;
                }
            };
            // Perform the atomic swap while still holding `commit_guard`, then release it BEFORE the dir
            // fsync: once the rename has run the new file IS `path`, so the guarded critical section is
            // exactly the check + rename (the fsync only makes the already-committed swap durable, and need
            // not stall a mutator waiting on the same lock).
            let renamed = std::fs::rename(&tmp, path_str);
            drop(commit_guard);
            match renamed {
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
            }
        }
        Err(e) => {
            eprintln!("btmqttd: persist: cannot create temp for {path_str}: {e}");
            false
        }
    }
}

/// Remove `path`, treating an already-absent file as success — the shared "clear a record"
/// path (broker IP, light state → unknown). Once the record is gone, fsync the PARENT
/// directory so the removal (a dir-entry change) is DURABLE, not just cached — otherwise a
/// power loss could restore the "deleted" file on reboot and resurrect a stale record
/// symmetric with [`atomic_write_in`]'s dir fsync. The fsync runs on BOTH the
/// just-removed AND the already-absent (`NotFound`) paths: if a previous attempt unlinked the
/// file but its dir-sync failed (returning `false`), a retry finds the file gone yet still
/// confirms durability rather than short-circuiting as "already durable". A dir-sync failure
/// is reported as a FAILED clear (`false`) so the caller retries; only a real removal error is
/// otherwise a failure.
fn remove_or_absent(path: &Path) -> bool {
    match std::fs::remove_file(path) {
        Ok(()) => sync_parent_dir(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => sync_parent_dir(path),
        Err(e) => {
            eprintln!("btmqttd: persist: cannot clear {}: {e}", path.display());
            false
        }
    }
}

/// fsync the parent directory of `path`, so a preceding unlink is durable. Returns `true` on
/// success; `false` on a sync/open error so the caller retries. A genuinely MISSING directory
/// means nothing was ever persisted there, so the record is durably absent → success.
fn sync_parent_dir(path: &Path) -> bool {
    let Some(dir) = path.parent() else {
        return true; // no parent to sync (shouldn't happen for our joined paths)
    };
    match std::fs::File::open(dir) {
        Ok(d) => match d.sync_all() {
            Ok(()) => true,
            Err(e) => {
                eprintln!("btmqttd: persist: cannot sync dir {} after clearing: {e}", dir.display());
                false
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => true, // dir absent → nothing persisted
        Err(e) => {
            eprintln!("btmqttd: persist: cannot open dir {} to sync: {e}", dir.display());
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

fn clear_light_where_in(dir: &Path) -> bool {
    remove_or_absent(&light_where_file_in(dir))
}

fn read_light_in(dir: &Path, want_where: &str) -> LightRestore {
    let text = match std::fs::read_to_string(light_file_in(dir)) {
        Ok(t) => t,
        // Genuinely absent → nothing to restore, safe to clear.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return LightRestore::Absent,
        // Present but unreadable (a transient I/O blip) → keep it, do not clear.
        Err(_) => return LightRestore::Unreadable,
    };
    let Some(line) = text.lines().next().map(str::trim) else {
        return LightRestore::Absent;
    };
    // Record is `<where>\t<on|off>`. A record for a DIFFERENT WHERE (a build that changed
    // LIGHT_WHERE — the cfg/extra partition survives reflashes) must NOT be inherited.
    let Some((where_, token)) = line.split_once('\t') else {
        return LightRestore::Absent;
    };
    if where_ != want_where {
        return LightRestore::Absent;
    }
    match token.trim() {
        "on" => LightRestore::State(true),
        "off" => LightRestore::State(false),
        _ => LightRestore::Absent, // corrupt token
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

/// The one-line camera-sprop body: `<branch>\t<value>\n` (tab-separated, same shape go2rtcd's
/// `assemble_sdp` parses with `cut -f1`/`cut -f2-`). Kept beside its parser so the two can't drift.
fn format_camera_sprop(branch: u8, value: &str) -> String {
    format!("{branch}\t{value}\n")
}

/// Parse a `<branch>\t<value>` sprop record into `(branch, value)`. `None` for a malformed line: a
/// missing TAB (a legacy bare value written before branch-keying), a non-numeric / out-of-`u8` branch,
/// or an empty value. The branch is NOT range-clamped here — the caller compares it against the
/// (already-clamped) current `CAMERA_BRANCH`, so an out-of-range branch simply never matches and is
/// re-learned. Pure — no I/O — so it is unit-tested directly.
fn parse_camera_sprop(text: &str) -> Option<(u8, String)> {
    let line = text.lines().next()?.trim();
    let (branch, value) = line.split_once('\t')?;
    let branch: u8 = branch.trim().parse().ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| (branch, value.to_string()))
}

/// Parse the state body into `(base_ip, learned_ip)`, only when its first line records
/// `want_host` (ASCII case-insensitive — hostnames are case-insensitive) and the learned
/// address is a private LAN IPv4. Anything else — a different host, a non-private/malformed
/// learned address, a short or empty line — yields `None`. The base is returned as-is (the
/// caller decides whether it still matches the build-time IP).
fn parse_record(text: &str, want_host: &str) -> Option<(Ipv4Addr, Ipv4Addr)> {
    let line = text.lines().next()?.trim();
    // format_state writes EXACTLY one line of three fields, so reject anything extra as
    // corrupt: a non-empty trailing line, or a 4th token on the first line.
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
        // Directory-injected cores — no env mutation, so this is parallel-safe.
        // A per-call nonce (atop the pid) keeps the temp dir unique even if this pattern is
        // reused by another parallel test or a rerun in the same process.
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

        assert!(matches!(read_light_in(&dir, "112"), LightRestore::Absent)); // no file yet
        assert!(store_light_in(&dir, "112", Some(true)));
        assert!(matches!(read_light_in(&dir, "112"), LightRestore::State(true)));
        assert!(store_light_in(&dir, "112", Some(false)));
        assert!(matches!(read_light_in(&dir, "112"), LightRestore::State(false)));
        // A record for a DIFFERENT WHERE is NOT inherited (a changed LIGHT_WHERE).
        assert!(matches!(read_light_in(&dir, "999"), LightRestore::Absent));
        // None clears the file → reads back as absent.
        assert!(store_light_in(&dir, "112", None));
        assert!(matches!(read_light_in(&dir, "112"), LightRestore::Absent));
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
        assert!(matches!(read_light_in(&dir, "112"), LightRestore::State(true)));
        assert!(clear_light_in(&dir)); // disabled-mode cleanup removes it
        // re-enable would start unknown
        assert!(matches!(read_light_in(&dir, "112"), LightRestore::Absent));
        // Already absent, but the DIRECTORY still exists → the NotFound path now fsyncs the dir
        // (confirming durability for a retry after a prior dir-sync failure) and still succeeds.
        assert!(clear_light_in(&dir));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_light_where_in_removes_the_learned_address_and_is_idempotent() {
        // The disabled-mode reset: a learned WHERE is durably forgotten, so re-enabling in learn
        // mode reads back none (re-learns) instead of restoring the old address; clearing an
        // already-absent file is still success.
        use std::sync::atomic::{AtomicU32, Ordering};
        static NONCE: AtomicU32 = AtomicU32::new(5000);
        let uniq = NONCE.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("btmqttd-clearwhere-{}-{uniq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        assert!(atomic_write_in(&dir, &light_where_file_in(&dir), b"112"));
        assert_eq!(read_light_where_in(&dir).as_deref(), Some("112"));
        assert!(clear_light_where_in(&dir)); // disabled-mode reset forgets it
        assert!(read_light_where_in(&dir).is_none());
        assert!(clear_light_where_in(&dir)); // already absent → still success

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_camera_sprop_reads_branch_and_value() {
        // Well-formed `<branch>\t<value>` records (task #41): branch parsed, value trimmed.
        assert_eq!(
            parse_camera_sprop("1\tZ0JAHqaAoD2Q,aM48gAA=\n"),
            Some((1, "Z0JAHqaAoD2Q,aM48gAA=".to_string()))
        );
        assert_eq!(parse_camera_sprop("0\tAAA,BBB="), Some((0, "AAA,BBB=".to_string())));
        // Malformed → None so the caller re-learns for the current branch:
        assert_eq!(parse_camera_sprop("Z0JAHqaAoD2Q,aM48gAA="), None); // legacy bare value, no TAB
        assert_eq!(parse_camera_sprop("1\t\n"), None); // empty value
        assert_eq!(parse_camera_sprop("x\tAAA,BBB="), None); // non-numeric branch
        assert_eq!(parse_camera_sprop("999\tAAA,BBB="), None); // branch out of u8 range
        assert_eq!(parse_camera_sprop(""), None); // empty file
    }

    #[test]
    fn camera_sprop_store_read_clear_roundtrip() {
        // Directory-injected cores — no env mutation, so this is parallel-safe. The learned camera
        // sprop is a single `<branch>\t<value>` line (task #41); store writes it keyed by branch, read
        // returns (branch, value), and clear forgets it (a reflash re-learns).
        use std::sync::atomic::{AtomicU32, Ordering};
        static NONCE: AtomicU32 = AtomicU32::new(6000);
        let uniq = NONCE.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("btmqttd-sprop-{}-{uniq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let file = camera_sprop_file_in(&dir);

        assert!(read_camera_sprop_in(&dir).is_none()); // no file yet
        assert!(store_camera_sprop_in(&dir, 1, "Z0JAHqaAoD2Q,aM48gAA="));
        assert_eq!(
            read_camera_sprop_in(&dir),
            Some((1, "Z0JAHqaAoD2Q,aM48gAA=".to_string()))
        );
        // A different branch is stored/read back distinctly (the reflash-flip case).
        assert!(store_camera_sprop_in(&dir, 0, "AAA,BBB="));
        assert_eq!(read_camera_sprop_in(&dir), Some((0, "AAA,BBB=".to_string())));
        // A legacy bare value (no branch prefix) reads back as None → re-learn.
        assert!(atomic_write_in(&dir, &file, b"Z0JAHqaAoD2Q,aM48gAA=\n"));
        assert!(read_camera_sprop_in(&dir).is_none());
        // An empty/whitespace file reads back as None (treated as not-yet-provisioned).
        assert!(atomic_write_in(&dir, &file, b"\n"));
        assert!(read_camera_sprop_in(&dir).is_none());
        // Clear forgets it; clearing again is still success (missing file is success).
        assert!(clear_camera_sprop_in(&dir));
        assert!(read_camera_sprop_in(&dir).is_none());
        assert!(clear_camera_sprop_in(&dir));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn update_latest_store_read_roundtrip() {
        // Directory-injected core (no env mutation → parallel-safe). The last-known "latest"
        // is one plain line: store writes it, read returns it trimmed, and a missing file /
        // empty content reads back as None (not-yet-known).
        use std::sync::atomic::{AtomicU32, Ordering};
        static NONCE: AtomicU32 = AtomicU32::new(7000);
        let uniq = NONCE.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("btmqttd-updlatest-{}-{uniq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let file = update_latest_file_in(&dir);

        assert_eq!(read_update_latest_in(&dir), None); // no file yet
        assert!(atomic_write_in(&dir, &file, b"0.2.0\n"));
        assert_eq!(read_update_latest_in(&dir).as_deref(), Some("0.2.0"));
        // Overwrite in place (a later fetch found a newer version).
        assert!(atomic_write_in(&dir, &file, b"0.3.0\n"));
        assert_eq!(read_update_latest_in(&dir).as_deref(), Some("0.3.0"));
        // An empty/whitespace file reads back as None.
        assert!(atomic_write_in(&dir, &file, b"\n"));
        assert_eq!(read_update_latest_in(&dir), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn idle_jpg_reads_bytes_verbatim_and_none_when_absent_or_empty() {
        // Directory-injected core (no env mutation → parallel-safe). The idle snapshot (issue
        // #168) is opaque bytes: read returns them verbatim (the caller validates the JPEG magic),
        // and a missing OR empty file reads back as None so the endpoint serves the baked
        // placeholder instead.
        use std::sync::atomic::{AtomicU32, Ordering};
        static NONCE: AtomicU32 = AtomicU32::new(8000);
        let uniq = NONCE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("btmqttd-idle-{}-{uniq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let file = idle_jpg_file_in(&dir);

        assert_eq!(read_idle_jpg_in(&dir), None); // no file yet
        let jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF payload \xff\xd9";
        assert!(atomic_write_in(&dir, &file, jpeg));
        assert_eq!(read_idle_jpg_in(&dir).as_deref(), Some(&jpeg[..]));
        // A file exactly AT the cap is still returned (the boundary is inclusive).
        let at_cap = vec![0xAAu8; MAX_IDLE_JPG_BYTES as usize];
        assert!(atomic_write_in(&dir, &file, &at_cap));
        assert_eq!(read_idle_jpg_in(&dir).map(|b| b.len()), Some(MAX_IDLE_JPG_BYTES as usize));
        // A file OVER the cap reads back as None → the endpoint serves the placeholder instead of
        // slurping and copying an oversized image per request (bounded-read hardening, issue #168).
        let over_cap = vec![0xAAu8; MAX_IDLE_JPG_BYTES as usize + 1];
        assert!(atomic_write_in(&dir, &file, &over_cap));
        assert_eq!(read_idle_jpg_in(&dir), None);
        // An empty file reads back as None (treated as "no idle image yet").
        assert!(atomic_write_in(&dir, &file, b""));
        assert_eq!(read_idle_jpg_in(&dir), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_gated_in_vetoes_the_commit_and_leaves_the_prior_file_intact() {
        // The commit gate (issue #169) lets capture_idle re-check ring-invalidation at the LAST moment,
        // in the same blocking step just before the atomic rename: a ring detected DURING the (blocking)
        // write must discard the freshly-written temp and leave the existing idle.jpg UNTOUCHED — never
        // publish a visitor frame as the empty-doorway thumbnail. Verify both branches, plus no temp leak.
        use std::sync::atomic::{AtomicU32, Ordering};
        static NONCE: AtomicU32 = AtomicU32::new(9000);
        let uniq = NONCE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("btmqttd-gate-{}-{uniq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let file = idle_jpg_file_in(&dir);

        // Seed a prior "empty doorway" image via the ungated path.
        let doorway = b"\xff\xd8\xff\xe0 doorway \xff\xd9";
        assert!(atomic_write_in(&dir, &file, doorway));
        assert_eq!(read_idle_jpg_in(&dir).as_deref(), Some(&doorway[..]));

        // A vetoed commit (gate returns None) must NOT replace the prior file and must return false.
        let visitor = b"\xff\xd8\xff\xe0 visitor \xff\xd9";
        assert!(!atomic_write_gated_in(&dir, &file, visitor, || Option::<()>::None));
        assert_eq!(read_idle_jpg_in(&dir).as_deref(), Some(&doorway[..]), "prior file must be untouched");

        // The vetoed write must not leave a temp behind (only the committed idle.jpg remains).
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .collect();
        assert_eq!(leftovers, vec![file.file_name().unwrap().to_owned()], "no temp file should linger");

        // An allowed commit (gate returns Some) replaces the file and returns true.
        assert!(atomic_write_gated_in(&dir, &file, visitor, || Some(())));
        assert_eq!(read_idle_jpg_in(&dir).as_deref(), Some(&visitor[..]));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_write_gated_in_holds_the_commit_guard_across_the_rename() {
        // The gate's guard must stay alive UNTIL the rename has run — that is what lets capture_idle hold a
        // shared mutex across its final ring check + rename so note_ring() (which takes the same mutex on
        // another thread) can't interleave. Prove it deterministically without threads: the guard's Drop
        // observes the file and asserts the rename has already committed the new body by the time it runs.
        use std::sync::atomic::{AtomicU32, Ordering};
        static NONCE: AtomicU32 = AtomicU32::new(9500);
        let uniq = NONCE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("btmqttd-guard-{}-{uniq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let file = idle_jpg_file_in(&dir);

        let doorway = b"\xff\xd8\xff\xe0 doorway \xff\xd9";
        assert!(atomic_write_in(&dir, &file, doorway));

        let visitor = b"\xff\xd8\xff\xe0 visitor \xff\xd9".to_vec();
        // A guard whose Drop asserts the rename already happened (the file now holds `expected`). If the
        // writer released the guard BEFORE the rename, this file would still be the doorway and the assert
        // would fire.
        struct RenameProof {
            path: PathBuf,
            expected: Vec<u8>,
        }
        impl Drop for RenameProof {
            fn drop(&mut self) {
                let got = std::fs::read(&self.path).expect("file must exist by guard drop");
                assert_eq!(got, self.expected, "rename must have committed before the commit guard dropped");
            }
        }
        let proof = RenameProof { path: file.clone(), expected: visitor.clone() };
        assert!(atomic_write_gated_in(&dir, &file, &visitor, move || Some(proof)));
        assert_eq!(read_idle_jpg_in(&dir).as_deref(), Some(&visitor[..]));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_light_in_reports_unreadable_on_io_error() {
        // A present-but-unreadable record must be Unreadable — NOT Absent — so main KEEPS it
        // instead of deleting a possibly-valid record on a transient I/O blip. Simulate
        // an I/O error that is NOT NotFound by making the record path a DIRECTORY (read_to_string
        // then fails with EISDIR).
        use std::sync::atomic::{AtomicU32, Ordering};
        static NONCE: AtomicU32 = AtomicU32::new(4000);
        let uniq = NONCE.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("btmqttd-lightio-{}-{uniq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(light_file_in(&dir)).unwrap(); // record path is a directory
        assert!(matches!(read_light_in(&dir, "112"), LightRestore::Unreadable));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_light_in_on_a_missing_dir_is_success() {
        // Fresh device: nothing was ever persisted and the btmqttd dir doesn't exist. Clearing
        // must be a (durably) successful no-op — NOT a false failure that main would retry and
        // then log — because there is no directory entry to make durable.
        use std::sync::atomic::{AtomicU32, Ordering};
        static NONCE: AtomicU32 = AtomicU32::new(3000);
        let uniq = NONCE.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("btmqttd-nodir-{}-{uniq}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir); // ensure it does NOT exist
        assert!(clear_light_in(&dir));
    }
}
