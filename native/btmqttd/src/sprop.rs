//! Automatic, transparent sprop-parameter-sets provisioning for the on-device camera (issue #120).
//!
//! The panel's SDP carries no `sprop-parameter-sets`, and — hardware-confirmed on the C100X — its SIP
//! answer doesn't advertise them either (only `profile-level-id`). Its encoder emits an in-stream
//! SPS/PPS only about every 20 s, so go2rtc's `-c:v copy` ffmpeg blocks ~20 s on a cold open before it
//! can resolve the video and serve it. Rather than make the operator find and paste their panel's
//! parameter sets, btmqttd LEARNS them itself and reassembles the go2rtc SDP with them, so every open
//! (including the first) resolves in under a second and nothing is configured.
//!
//! ## Lifecycle (renew-only; learns once; persists the VALUE, not a patched file)
//!   * On startup, if no sprop has been learned yet (no persisted value), this task brings the panel up
//!     ON ITS OWN — a silent on-demand INVITE via the SIP UA (no ring, no on-screen view) — so the
//!     stream is live, then runs the vendored ffmpeg once to DERIVE the parameter sets from the live RTP
//!     (ffmpeg's `-sdp_file` writes an SDP whose `sprop-parameter-sets` is computed from the in-stream
//!     SPS/PPS). The probe reads the READ-ONLY TEMPLATE SDP the installer wrote under `/etc`
//!     ([`TEMPLATE_SDP_PATH`]) — always present, never mutated.
//!   * On a successful learn it PERSISTS the sprop VALUE on the writable `cfg/extra` partition via
//!     `persist::store_camera_sprop` (the durable source of truth), then best-effort patches the RUNTIME
//!     tmpfs SDP ([`SDP_PATH`]) so THIS boot's next view is fast without waiting for a reboot.
//!   * It is renew-only, like the auto-hold task: it only ever pokes `Start` and never sends `Stop`, so
//!     it can't cut a concurrent viewer — a provisioning-only session simply lapses on its own after
//!     `camera_view_idle_secs`.
//!
//! ## Why a tmpfs runtime SDP (the rootfs is read-only)
//! The device rootfs — including `/etc` — is mounted READ-ONLY (see `persist.rs`), so a runtime write to
//! the `/etc` SDP fails with `EROFS`. The design therefore SPLITS the SDP:
//!   * the installer's `/etc/.../doorbell.sdp` is the read-only TEMPLATE/seed (the probe input);
//!   * go2rtc reads a RUNTIME copy on tmpfs (`/var/run/btmqttd/doorbell.sdp`), which the `go2rtcd` init
//!     script (re)assembles at EVERY boot: it copies the template into tmpfs and, if a learned value is
//!     persisted, splices `sprop-parameter-sets=<value>;` into the fmtp line. This task patches THAT
//!     runtime copy (writable) after a fresh learn. Reflash-safe by composition: `cfg/extra` survives a
//!     reflash, so a re-flashed unit that already learned keeps its value; a genuinely fresh unit has no
//!     persisted value and re-learns.
//!
//! ## Port coordination (the provisioning probe vs. go2rtc's own ffmpeg)
//! Both the probe and go2rtc's `exec:` ffmpeg bind the same `127.0.0.2:<CameraVideoPort>` UDP input, so
//! only one can hold it. A viewer connecting starts go2rtc's producer, which must own the port. This task
//! keys off go2rtc's CONSUMERS (`hold::stream_has_consumer`): it SKIPS a round when a consumer is already
//! connected, and a `select!` branch YIELDS the probe (dropping it releases the port via `kill_on_drop`)
//! if a consumer appears mid-probe — so a real view always wins the port within ~a poll interval.
//!
//! Best-effort and self-healing: if the panel isn't reachable yet at boot, it retries with backoff. If
//! on-demand viewing is off (no SIP UA to originate a session), the task simply isn't started — the
//! operator can still supply CAMERA_SPROP at install time, or the ~20 s-first-frame fallback applies.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use crate::config::Config;
use crate::sip::ViewCmd;
use crate::{hold, persist};

/// The RUNTIME go2rtc SDP on tmpfs — what go2rtc's `exec -i` reads and what this task patches after a
/// fresh learn. `go2rtcd` (re)assembles it at every boot from [`TEMPLATE_SDP_PATH`] + the persisted
/// value. tmpfs is writable, so patching it (temp + rename below) works despite the read-only rootfs.
const SDP_PATH: &str = "/var/run/btmqttd/doorbell.sdp";
/// The READ-ONLY TEMPLATE SDP the installer wrote under `/etc` (Go2RtcDir + stream name), 0644 (it
/// carries no secret). Always present and never mutated — the ffmpeg probe reads THIS to describe the
/// panel's RTP, so provisioning never depends on the runtime tmpfs copy having been assembled yet.
const TEMPLATE_SDP_PATH: &str = "/etc/btmqttd/go2rtc/doorbell.sdp";
/// The vendored ffmpeg, installed here by `PayloadBinaries` (same InstallPath as the go2rtc exec uses).
const FFMPEG_PATH: &str = "/usr/sbin/ffmpeg";
/// Scratch path for ffmpeg's derived SDP (tmpfs).
const CAP_SDP_PATH: &str = "/tmp/btmqttd-sprop-cap.sdp";
/// The `a=fmtp` fragment we splice sprop in AFTER — matches Go2RtcConfig.BuildOnDeviceSdp's order so a
/// patched SDP equals what the installer would have written with CameraSprop set.
const FMTP_ANCHOR: &str = "packetization-mode=1;";

/// Bound the ffmpeg probe. The panel's SPS interval is ~20 s and we widen analyzeduration to wait for
/// it, so give the probe headroom past that before killing it.
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(45);
/// Let the INVITE complete and `av.rs` arm the `:30007` siphon before the probe starts reading RTP.
/// (The probe's own analyzeduration tolerates a late start, so this only needs to be small.)
const SIPHON_SETTLE: Duration = Duration::from_secs(3);
const INIT_BACKOFF: Duration = Duration::from_secs(10);
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// How often the yield-watch polls go2rtc for a consumer that connected mid-probe. Short so the probe
/// releases the shared UDP input port to go2rtc's own ffmpeg within ~a second of a real view starting.
const CONSUMER_POLL: Duration = Duration::from_secs(1);

/// Provision sprop once, then return. Spawned only when on-demand + on-device are enabled (so a SIP UA
/// exists to originate the session and the go2rtc SDP is local). Holds a `view_tx` clone, so `main`
/// stops this task BEFORE draining the SIP UA at shutdown.
pub async fn run(cfg: Arc<Config>, stopping: Arc<AtomicBool>, view_tx: mpsc::Sender<ViewCmd>) {
    // Already learned on a prior boot (the VALUE persisted on cfg/extra) ⇒ nothing to do. The persist
    // file — not the runtime SDP — is the source of truth: go2rtcd already spliced the value into the
    // runtime tmpfs SDP at boot. Idempotent guard so the steady state after the first learn is a single
    // cheap file read at startup. (cfg supplies the viewing-window length so the probe can keep the SIP
    // session alive for its full duration; the SDP/ffmpeg paths are fixed installer locations.)
    if already_learned().await {
        return;
    }
    let mut backoff = INIT_BACKOFF;
    let mut warned = false;
    while !stopping.load(Ordering::Relaxed) {
        if already_learned().await {
            return;
        }
        // Port coordination (#3): if a viewer's consumer is already connected, go2rtc's own `exec:`
        // ffmpeg owns the shared 127.0.0.2:<CameraVideoPort> UDP input — our probe would fail to bind
        // it. SKIP this round entirely (don't even bring the panel up) and retry after the backoff, so
        // the live view keeps the port. A poll error (API down) reads as "no consumer" and we proceed.
        if matches!(hold::stream_has_consumer().await, Ok(true)) {
            if stopping.load(Ordering::Relaxed) {
                break;
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
            continue;
        }
        // Bring the panel up silently so its stream is live for the probe. A closed channel means the
        // SIP UA is gone — we cannot originate a session, so there is nothing more to do.
        if view_tx.send(ViewCmd::Start).await.is_err() {
            return;
        }
        // Keep the SIP viewing window alive for the WHOLE probe. A single Start renews the window for
        // only `camera_view_idle_secs`, but the settle + capture can run longer (capture waits up to
        // ~30 s for the panel's sparse SPS/PPS). If the window were shorter than that, sip.rs would BYE
        // mid-capture, the siphon would dry, ffmpeg would derive no parameter sets, and provisioning
        // would retry forever without ever succeeding (Codex). So re-poke Start on an interval well under
        // the window while the settle + capture run. `renew_window` never returns unless the channel
        // closes, so the select resolves when the capture completes.
        let window = Duration::from_secs(cfg.camera_view_idle_secs.max(1));
        let renew_period = renew_period_for(window);
        let learned = tokio::select! {
            r = async {
                tokio::time::sleep(SIPHON_SETTLE).await;
                capture_sprop().await
            } => r,
            _ = renew_window(&view_tx, renew_period) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "SIP view channel closed during sprop capture",
            )),
            // Port coordination (#3): a consumer connecting mid-probe means go2rtc is about to start its
            // own ffmpeg on the same UDP input. YIELD — resolving this branch drops the capture future,
            // and the probe child's kill_on_drop(true) frees the port within ~a poll interval so go2rtc
            // owns it. Return an Err so the loop retries later (once the view ends).
            _ = wait_for_consumer() => Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "yielded the sprop probe's UDP port to a go2rtc consumer",
            )),
        };
        // Do NOT send Stop here — let the viewing window lapse on its own after `camera_view_idle_secs`.
        // Provisioning shares the single SIP window with the auto-hold task and the manual
        // view_camera/stop_camera actions, and it cannot reliably tell whether it is the SOLE reason the
        // session is up: a go2rtc consumer reveals an RTSP viewer (Home Assistant), but a manual
        // `view_camera` brings the panel up over SIP with NO go2rtc consumer, so no consumer signal
        // exists to detect it (Codex). Rather than track cross-source ownership, provisioning is
        // renew-only like the auto-hold task — it only ever pokes Start — so it never cuts a session
        // another source may want. The cost is that a provisioning-only run leaves the panel up for at
        // most one idle window; negligible, since this whole task is a one-shot that runs only until the
        // first learn persists.
        match learned {
            Ok(sprop) => {
                // Durability first: PERSIST the value on cfg/extra. This is what makes the learn
                // durable (go2rtcd reassembles the runtime SDP from it at every boot), so success
                // REQUIRES the persist write to land. persist is blocking → spawn_blocking.
                let value = sprop.clone();
                let stored =
                    tokio::task::spawn_blocking(move || persist::store_camera_sprop(&value))
                        .await
                        .unwrap_or(false);
                if stored {
                    // Best-effort: patch the RUNTIME tmpfs SDP so THIS boot's next view is fast without
                    // waiting for a reboot. A failure here is NON-fatal — the value is already persisted,
                    // so the next boot's go2rtcd splices it in regardless; just log and still succeed.
                    if let Err(e) = patch_sdp(&sprop).await {
                        eprintln!(
                            "btmqttd: sprop provisioning: persisted the value but could not patch the runtime SDP ({e}); it takes effect on the next boot"
                        );
                    }
                    eprintln!(
                        "btmqttd: learned camera parameter sets — the on-device camera now resolves instantly"
                    );
                    return;
                }
                // The persist write failed (cfg/extra briefly unavailable). Log and retry — the SPS is
                // stable, so the next attempt derives the same value.
                eprintln!(
                    "btmqttd: sprop provisioning: failed to persist the learned parameter sets; will retry"
                );
            }
            // A yield-to-viewer (Interrupted) is expected and benign — the probe stood aside so a real
            // view could own the port; retry silently after the backoff. Any other error means the probe
            // genuinely could not learn yet; log it once.
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                if !warned {
                    eprintln!(
                        "btmqttd: sprop provisioning: could not learn the parameter sets yet ({e}); will retry"
                    );
                    warned = true;
                }
            }
        }
        if stopping.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// True iff there is nothing to provision: EITHER a value was already LEARNED and persisted on a prior
/// boot (the durable source of truth on cfg/extra), OR the installer PRE-SEEDED a `CameraSprop` into the
/// read-only `/etc` template SDP (an operator-supplied value — nothing to learn). Checking the template
/// too means a correctly pre-seeded image never runs a redundant first-boot probe, which would also grab
/// the shared RTP input port before a viewer connects (CodeRabbit). A missing/unreadable persist file
/// AND template reads as "not provisioned" so the loop retries. Both reads are blocking → spawn_blocking.
async fn already_learned() -> bool {
    let persisted = tokio::task::spawn_blocking(|| persist::read_camera_sprop().is_some())
        .await
        .unwrap_or(false);
    persisted || template_has_sprop().await
}

/// True iff the read-only `/etc` template SDP already carries an operator-supplied
/// `sprop-parameter-sets` (an install-time `CameraSprop`) — then there is nothing to learn. A
/// missing/unreadable template reads as "no sprop" so provisioning proceeds normally.
async fn template_has_sprop() -> bool {
    matches!(tokio::fs::read_to_string(TEMPLATE_SDP_PATH).await, Ok(s) if has_sprop(&s))
}

/// Pure `sprop-parameter-sets=` presence check (factored so the provisioned-detection is unit-testable
/// without touching the fixed `/etc` template path).
fn has_sprop(sdp: &str) -> bool {
    sdp.contains("sprop-parameter-sets=")
}

/// Resolve as soon as go2rtc reports a connected consumer — the yield signal for the port-coordination
/// `select!` branch. Polls the loopback control API every [`CONSUMER_POLL`]; a poll error (API down)
/// is treated as "no consumer yet" and polling continues, so a transient API hiccup can't spuriously
/// abandon a probe. Never resolves while no viewer is connected, so it only ever fires to yield the port.
async fn wait_for_consumer() {
    loop {
        tokio::time::sleep(CONSUMER_POLL).await;
        if matches!(hold::stream_has_consumer().await, Ok(true)) {
            return;
        }
    }
}

/// The interval at which `renew_window` re-pokes `Start`, derived from the viewing `window`. It must be
/// STRICTLY LESS than the window so every poke lands before the SIP deadline (a positive margin), and
/// floored so a pathological tiny window can't spin the loop. Half the window gives a full window/2
/// margin; the 500 ms floor stays below even the 1 s minimum window (`camera_view_idle_secs.max(1)`),
/// so the margin is always positive. Mirrors the period derivation in `hold.rs`.
fn renew_period_for(window: Duration) -> Duration {
    (window / 2).max(Duration::from_millis(500))
}

/// Re-poke `ViewCmd::Start` every `period` to keep the SIP viewing window alive while a long operation
/// runs alongside it. Returns only if the channel closes (the SIP UA is gone). `Start` is idempotent —
/// each poke just renews the full window — so this can outlast a single `camera_view_idle_secs` window
/// (the sprop capture can wait ~30 s for the panel's sparse SPS/PPS).
async fn renew_window(view_tx: &mpsc::Sender<ViewCmd>, period: Duration) {
    loop {
        tokio::time::sleep(period).await;
        if view_tx.send(ViewCmd::Start).await.is_err() {
            return;
        }
    }
}

/// Run the vendored ffmpeg to derive the panel's sprop from the live RTP described by the TEMPLATE SDP.
/// It reads [`TEMPLATE_SDP_PATH`] — the read-only `/etc` seed the installer wrote — which is always
/// present and never depends on the runtime tmpfs copy having been assembled. `-sdp_file` writes an SDP
/// whose `sprop-parameter-sets` ffmpeg computed from the in-stream SPS/PPS; the widened analyzeduration
/// makes find_stream_info WAIT for the panel's sparse keyframe (without the reorder-buffer tuning that
/// broke the live path — this is a one-shot probe, latency is irrelevant).
async fn capture_sprop() -> std::io::Result<String> {
    let _ = tokio::fs::remove_file(CAP_SDP_PATH).await; // clear any stale file from a prior attempt
    let mut child = tokio::process::Command::new(FFMPEG_PATH)
        .args([
            "-hide_banner",
            "-protocol_whitelist",
            "file,udp,rtp",
            // Wait up to ~30 s for the panel's next in-stream SPS/PPS so the extradata (and thus the
            // sprop in -sdp_file) is populated before the muxer writes its header.
            "-analyzeduration",
            "30000000",
            "-probesize",
            "50000000",
            "-i",
            TEMPLATE_SDP_PATH,
            "-an",
            "-c:v",
            "copy",
            "-t",
            "1",
            "-sdp_file",
            CAP_SDP_PATH,
            "-f",
            "rtp",
            // Discard the muxed RTP — we only want the SDP the muxer derives.
            "rtp://127.0.0.1:9",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        // kill_on_drop so a shutdown that ABORTS this task (main aborts sprop_task before draining the
        // SIP UA) doesn't orphan the probe: dropping the aborted future drops this `Child`, and without
        // kill_on_drop the ffmpeg keeps running, holding the SDP's RTP input port until it times out —
        // a later boot's probe or go2rtc could then fail to bind. The explicit timeout path below still
        // start_kill()s + reaps; this only covers the cancellation (drop) path.
        .kill_on_drop(true)
        .spawn()?;
    match tokio::time::timeout(CAPTURE_TIMEOUT, child.wait()).await {
        Ok(status) => {
            // Propagate a wait() I/O error, but do NOT fail on a non-zero exit CODE: `-sdp_file` is
            // written when the muxer opens its header — after find_stream_info has read the sprop — so a
            // valid sprop can already be on disk even when ffmpeg later exits non-zero (e.g. the discard
            // RTP sink erroring at teardown). Fall through to the parse below, which is the real success
            // test; just log a non-zero exit so a genuine probe failure is diagnosable rather than
            // surfacing only as the downstream "derived no sprop" (Copilot).
            let status = status?;
            if !status.success() {
                eprintln!(
                    "btmqttd: sprop provisioning: ffmpeg probe exited non-zero ({status}); checking the derived SDP anyway"
                );
            }
        }
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "ffmpeg sprop probe timed out (no keyframe within the window)",
            ));
        }
    }
    let derived = tokio::fs::read_to_string(CAP_SDP_PATH).await?;
    let _ = tokio::fs::remove_file(CAP_SDP_PATH).await;
    parse_sprop(&derived).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ffmpeg derived no sprop-parameter-sets",
        )
    })
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
        // so a pre-seeded image skips the boot probe (already_learned via template_has_sprop). A bare
        // template (no sprop) must NOT — provisioning still runs to learn it (CodeRabbit).
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
    fn renew_period_stays_strictly_below_the_window() {
        // The renewal poke must land before the SIP deadline for EVERY accepted window, including the
        // 1 s minimum (camera_view_idle_secs.max(1)) — otherwise sip.rs could BYE mid-capture. Assert a
        // positive margin (period < window) and the 500 ms floor across the range.
        for secs in [1u64, 2, 3, 5, 30, 300] {
            let window = Duration::from_secs(secs);
            let period = renew_period_for(window);
            assert!(
                period < window,
                "window={secs}s: renew_period {period:?} must be strictly less than the window {window:?}"
            );
            assert!(
                period >= Duration::from_millis(500),
                "window={secs}s: renew_period {period:?} must not spin below the 500 ms floor"
            );
        }
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
