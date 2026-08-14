//! Automatic, transparent sprop-parameter-sets provisioning for the on-device camera (issue #120) —
//! a PASSIVE watcher.
//!
//! The panel's SDP carries no `sprop-parameter-sets`, and — hardware-confirmed on the C100X — its SIP
//! answer doesn't advertise them either (only `profile-level-id`). Its encoder emits an in-stream
//! SPS/PPS only about every 20 s, so go2rtc's `-c:v copy` ffmpeg blocks ~20 s on a cold open before it
//! can resolve the video and serve it. Rather than make the operator find and paste their panel's
//! parameter sets, btmqttd LEARNS them itself and reassembles the go2rtc SDP with them, so every open
//! (including the first) resolves in under a second and nothing is configured.
//!
//! ## Lifecycle (passive watch; learns once; persists the VALUE, not a patched file)
//! An earlier revision brought the panel up ITSELF (a silent on-demand INVITE) to run a one-shot ffmpeg
//! probe. Hardware testing proved that CAN'T WORK: the panel only sustains/feeds the video call for a
//! REAL consumed view, not a silent probe — so proactive probing just cycles the panel and never learns.
//! This task is therefore purely passive:
//!   * go2rtc's OWN `exec:` ffmpeg — which runs only while a client is actually watching — is asked
//!     (in `Go2RtcConfig.BuildOnDeviceYaml`) to write the parameter sets it resolves to a DERIVED SDP
//!     via `-sdp_file` ([`DERIVED_SDP_PATH`], = `Go2RtcConfig.OnDeviceDerivedSdpPath`). That is the same
//!     `-sdp_file` mechanism already proven to derive sprop, but driven by the live view instead of a
//!     probe. This task NEVER brings the panel up itself, so it can never cycle it.
//!   * This task just WATCHES that derived file every [`WATCH_INTERVAL`]. When a live view has produced
//!     an sprop in it, it PERSISTS the VALUE on the writable `cfg/extra` partition via
//!     `persist::store_camera_sprop` (the durable source of truth — `go2rtcd` reassembles the runtime
//!     SDP from template + persisted value at boot), best-effort patches THIS boot's runtime tmpfs SDP
//!     ([`SDP_PATH`]) so the current session speeds up without waiting for a reboot, and returns.
//!   * The first view is the ~20 s parser resolve (unchanged); every later view is fast. If the derived
//!     file is absent or has no sprop yet (no view has produced one), it just keeps polling.
//!
//! ## Why a tmpfs runtime SDP (the rootfs is read-only)
//! The device rootfs — including `/etc` — is mounted READ-ONLY (see `persist.rs`), so a runtime write to
//! the `/etc` SDP fails with `EROFS`. The design therefore SPLITS the SDP:
//!   * the installer's `/etc/.../doorbell.sdp` is the read-only TEMPLATE/seed;
//!   * go2rtc reads a RUNTIME copy on tmpfs (`/var/run/btmqttd/doorbell.sdp`), which the `go2rtcd` init
//!     script (re)assembles at EVERY boot: it copies the template into tmpfs and, if a learned value is
//!     persisted, splices `sprop-parameter-sets=<value>;` into the fmtp line. This task patches THAT
//!     runtime copy (writable) after a fresh learn. Reflash-safe by composition: `cfg/extra` survives a
//!     reflash, so a re-flashed unit that already learned keeps its value; a genuinely fresh unit has no
//!     persisted value and re-learns from the next live view.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use crate::config::Config;
use crate::persist;

/// The RUNTIME go2rtc SDP on tmpfs — what go2rtc's `exec -i` reads and what this task patches after a
/// fresh learn. `go2rtcd` (re)assembles it at every boot from [`TEMPLATE_SDP_PATH`] + the persisted
/// value. tmpfs is writable, so patching it (temp + rename below) works despite the read-only rootfs.
const SDP_PATH: &str = "/var/run/btmqttd/doorbell.sdp";
/// The READ-ONLY TEMPLATE SDP the installer wrote under `/etc` (Go2RtcDir + stream name), 0644 (it
/// carries no secret). Always present and never mutated — checked by `template_has_sprop` so a
/// pre-seeded image never runs a redundant watch.
const TEMPLATE_SDP_PATH: &str = "/etc/btmqttd/go2rtc/doorbell.sdp";
/// The DERIVED SDP that go2rtc's own `exec:` ffmpeg writes via `-sdp_file` while a client is watching
/// (its `sprop-parameter-sets` is computed from the panel's in-stream SPS/PPS once find_stream_info
/// resolves the H.264). Must match `Go2RtcConfig.OnDeviceDerivedSdpPath`. This task's only input.
const DERIVED_SDP_PATH: &str = "/var/run/btmqttd/derived.sdp";
/// The `a=fmtp` fragment we splice sprop in AFTER — matches Go2RtcConfig.BuildOnDeviceSdp's order so a
/// patched SDP equals what the installer would have written with CameraSprop set.
const FMTP_ANCHOR: &str = "packetization-mode=1;";

/// How often to re-check the derived SDP for a freshly-resolved sprop. A live view resolves it within
/// ~20 s of first frame; a ~10 s watch picks that up promptly without busy-polling.
const WATCH_INTERVAL: Duration = Duration::from_secs(10);

/// Watch the derived SDP and persist the panel's sprop once a live view has produced it, then return.
/// Spawned when the on-device camera is enabled. It holds no `view_tx` and publishes nothing — it only
/// reads a file and writes the persisted value / runtime SDP — so `main` aborts it at shutdown like
/// `av.rs`. `cfg` is unused (the paths are fixed installer locations); kept for a uniform task signature.
pub async fn run(_cfg: Arc<Config>, stopping: Arc<AtomicBool>) {
    // Already learned on a prior boot (the VALUE persisted on cfg/extra), or an operator pre-seeded the
    // template ⇒ nothing to do. The persist file — not the runtime SDP — is the source of truth:
    // go2rtcd already spliced the value into the runtime tmpfs SDP at boot. Idempotent guard so the
    // steady state after the first learn is a single cheap file read at startup.
    if already_learned().await {
        return;
    }
    let mut warned = false;
    while !stopping.load(Ordering::Relaxed) {
        if already_learned().await {
            return;
        }
        // Read the derived SDP go2rtc's own exec ffmpeg writes while a client is watching. Absent (no
        // view has produced it yet) or present-but-no-sprop-yet ⇒ keep polling; this is normal until
        // the first live view resolves the H.264.
        if let Ok(derived) = tokio::fs::read_to_string(DERIVED_SDP_PATH).await {
            if let Some(value) = parse_sprop(&derived) {
                // Durability first: PERSIST the value on cfg/extra. This is what makes the learn durable
                // (go2rtcd reassembles the runtime SDP from it at every boot), so success REQUIRES the
                // persist write to land. persist is blocking → spawn_blocking.
                let stored = {
                    let v = value.clone();
                    tokio::task::spawn_blocking(move || persist::store_camera_sprop(&v))
                        .await
                        .unwrap_or(false)
                };
                if stored {
                    // Best-effort: patch the RUNTIME tmpfs SDP so THIS boot's next view is fast without
                    // waiting for a reboot. A failure here is NON-fatal — the value is already persisted,
                    // so the next boot's go2rtcd splices it in regardless; just log and still succeed.
                    if let Err(e) = patch_sdp(&value).await {
                        eprintln!(
                            "btmqttd: sprop watcher: persisted the value but could not patch the runtime SDP ({e}); it takes effect on the next boot"
                        );
                    }
                    eprintln!(
                        "btmqttd: learned camera parameter sets (from a live view) — the on-device camera now resolves instantly"
                    );
                    return;
                }
                // The persist write failed (cfg/extra briefly unavailable). Log once and keep watching —
                // the derived value is stable, so the next poll persists the same value.
                if !warned {
                    eprintln!(
                        "btmqttd: sprop watcher: failed to persist the learned parameter sets; will retry"
                    );
                    warned = true;
                }
            }
        }
        // Re-check `stopping` before sleeping so a shutdown observed mid-poll exits promptly.
        if stopping.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(WATCH_INTERVAL).await;
    }
}

/// True iff there is nothing to provision: EITHER a value was already LEARNED and persisted on a prior
/// boot (the durable source of truth on cfg/extra), OR the installer PRE-SEEDED a `CameraSprop` into the
/// read-only `/etc` template SDP (an operator-supplied value — nothing to learn). A missing/unreadable
/// persist file AND template reads as "not provisioned" so the watch continues. Both reads are blocking
/// → spawn_blocking.
async fn already_learned() -> bool {
    let persisted = tokio::task::spawn_blocking(|| persist::read_camera_sprop().is_some())
        .await
        .unwrap_or(false);
    persisted || template_has_sprop().await
}

/// True iff the read-only `/etc` template SDP already carries an operator-supplied
/// `sprop-parameter-sets` (an install-time `CameraSprop`) — then there is nothing to learn. A
/// missing/unreadable template reads as "no sprop" so the watch proceeds normally.
async fn template_has_sprop() -> bool {
    matches!(tokio::fs::read_to_string(TEMPLATE_SDP_PATH).await, Ok(s) if has_sprop(&s))
}

/// Pure `sprop-parameter-sets=` presence check (factored so the provisioned-detection is unit-testable
/// without touching the fixed `/etc` template path).
fn has_sprop(sdp: &str) -> bool {
    sdp.contains("sprop-parameter-sets=")
}

/// Extract the `sprop-parameter-sets` value from an SDP fmtp line (base64 sets, comma-separated; ends
/// at the next `;` or whitespace).
fn parse_sprop(sdp: &str) -> Option<String> {
    const KEY: &str = "sprop-parameter-sets=";
    for line in sdp.lines() {
        if let Some(i) = line.find(KEY) {
            let val: String = line[i + KEY.len()..]
                .chars()
                .take_while(|&c| c != ';' && !c.is_whitespace())
                .collect();
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
}

/// Splice a learned sprop into the RUNTIME tmpfs SDP's ([`SDP_PATH`]) fmtp line and write it back
/// atomically (temp + rename, 0644 — the SDP carries no secret). The temp file sits in the SAME tmpfs
/// dir as the target, so the rename is atomic. Idempotent: a no-op if sprop is already present (e.g.
/// go2rtcd already spliced a persisted value at boot). This is a best-effort fast-path for the current
/// boot; durability comes from the persisted value, not from this write.
async fn patch_sdp(sprop: &str) -> std::io::Result<()> {
    let sdp = tokio::fs::read_to_string(SDP_PATH).await?;
    if sdp.contains("sprop-parameter-sets=") {
        return Ok(());
    }
    if !sdp.contains(FMTP_ANCHOR) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "go2rtc SDP has no packetization-mode fmtp to patch",
        ));
    }
    let patched = sdp.replacen(
        FMTP_ANCHOR,
        &format!("{FMTP_ANCHOR}sprop-parameter-sets={sprop};"),
        1,
    );
    // Write a temp file in the same directory, fsync, then rename over the target so a crash never
    // leaves go2rtc a half-written SDP.
    let tmp = format!("{SDP_PATH}.tmp");
    {
        let mut f = tokio::fs::File::create(&tmp).await?;
        f.write_all(patched.as_bytes()).await?;
        f.flush().await?;
        f.sync_all().await?;
    }
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).await?;
    tokio::fs::rename(&tmp, SDP_PATH).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sprop_from_a_derived_sdp() {
        // The shape ffmpeg's -sdp_file emits (spaces after ';', trailing profile-level-id).
        let sdp = "v=0\r\nm=video 9 RTP/AVP 96\r\n\
                   a=fmtp:96 packetization-mode=1; sprop-parameter-sets=Z0JAHqaAoD2Q,aM48gAA=; profile-level-id=42401E\r\n";
        assert_eq!(parse_sprop(sdp).as_deref(), Some("Z0JAHqaAoD2Q,aM48gAA="));
    }

    #[test]
    fn seeded_template_counts_as_provisioned() {
        // An installer-supplied CameraSprop lands in the template's fmtp line; has_sprop must detect it
        // so a pre-seeded image skips the watch (already_learned via template_has_sprop). A bare
        // template (no sprop) must NOT — the watch still runs to learn it (CodeRabbit).
        let seeded = "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0JAHqaAoD2Q,aM48gAA=;profile-level-id=42801f\n";
        assert!(has_sprop(seeded));
        let bare = "a=fmtp:96 packetization-mode=1;profile-level-id=42801f\n";
        assert!(!has_sprop(bare));
    }

    #[test]
    fn no_sprop_returns_none() {
        assert_eq!(
            parse_sprop("a=fmtp:96 packetization-mode=1;profile-level-id=42801f"),
            None
        );
        assert_eq!(parse_sprop(""), None);
    }

    #[test]
    fn patch_inserts_sprop_in_installer_order() {
        // Verify the in-memory splice matches BuildOnDeviceSdp's fmtp order:
        // packetization-mode=1;sprop-parameter-sets=...;profile-level-id=...
        let base = "a=fmtp:96 packetization-mode=1;profile-level-id=42801f\n";
        let patched = base.replacen(
            FMTP_ANCHOR,
            &format!("{FMTP_ANCHOR}sprop-parameter-sets=AAA,BBB=;"),
            1,
        );
        assert_eq!(
            patched,
            "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=AAA,BBB=;profile-level-id=42801f\n"
        );
    }
}
