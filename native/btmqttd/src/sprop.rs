//! Automatic, transparent sprop-parameter-sets provisioning for the on-device camera (issue #120).
//!
//! The panel's SDP carries no `sprop-parameter-sets`, and — hardware-confirmed on the C100X — its SIP
//! answer doesn't advertise them either (only `profile-level-id`). Its encoder emits an in-stream
//! SPS/PPS only about every 20 s, so go2rtc's `-c:v copy` ffmpeg blocks ~20 s on a cold open before it
//! can resolve the video and serve it. Rather than make the operator find and paste their panel's
//! parameter sets, btmqttd LEARNS them itself and writes them into the go2rtc SDP, so every open
//! (including the first) resolves in under a second and nothing is configured.
//!
//! Proactive, one-shot, persistent — the behaviour the operator asked for:
//!   * On startup, if the go2rtc SDP has no sprop yet, this task brings the panel up ON ITS OWN — a
//!     silent on-demand INVITE via the SIP UA (no ring, no on-screen view) — so the stream is live.
//!   * It runs the vendored ffmpeg once to DERIVE the parameter sets from the live RTP (ffmpeg's
//!     `-sdp_file` writes an SDP whose `sprop-parameter-sets` is computed from the in-stream SPS/PPS),
//!     patches them into the go2rtc SDP, and releases the panel.
//!   * The patched SDP persists (it lives under /etc), so this runs EXACTLY ONCE per install: a reflash
//!     regenerates the SDP without sprop and it re-learns; otherwise the value (fixed per panel) never
//!     needs refreshing.
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

/// The go2rtc SDP the on-device stream reads. `MqttInstaller` writes it here (Go2RtcDir + stream name),
/// 0644 (it carries no secret), so this is fixed — the same way `av.rs`/`receiver.rs` hardcode the
/// on-device loopback ports.
const SDP_PATH: &str = "/etc/btmqttd/go2rtc/doorbell.sdp";
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

/// Provision sprop once, then return. Spawned only when on-demand + on-device are enabled (so a SIP UA
/// exists to originate the session and the go2rtc SDP is local). Holds a `view_tx` clone, so `main`
/// stops this task BEFORE draining the SIP UA at shutdown.
pub async fn run(cfg: Arc<Config>, stopping: Arc<AtomicBool>, view_tx: mpsc::Sender<ViewCmd>) {
    // Already provisioned on a prior boot (the SDP persisted) ⇒ nothing to do. Idempotent guard so the
    // steady state after the first learn is a single cheap file read at startup. (cfg supplies the
    // viewing-window length so the probe can keep the SIP session alive for its full duration; the
    // SDP/ffmpeg paths are fixed installer locations.)
    if sdp_has_sprop().await {
        return;
    }
    let mut backoff = INIT_BACKOFF;
    let mut warned = false;
    while !stopping.load(Ordering::Relaxed) {
        if sdp_has_sprop().await {
            return;
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
        };
        // Release the panel promptly — but ONLY if this one-shot probe is the sole reason it is up.
        // Start/Stop drive a single shared SIP window, so an unconditional Stop here would cut off a
        // real viewer who connected during the probe (Home Assistant, or a manual `view_camera`). The
        // probe reads the siphon directly, NOT through go2rtc, so a go2rtc producer means someone else
        // is consuming the stream — in that case leave the session to the auto-hold task (it renews the
        // window while a producer exists) / the idle timeout. We Stop only when go2rtc POSITIVELY
        // reports no producer; on a producer OR an API hiccup we conservatively skip the Stop (the
        // window simply lapses after `camera_view_idle_secs`). This is the ownership coordination
        // CodeRabbit/Codex flagged, done via the existing producer signal rather than a lease registry:
        // provisioning is a one-shot (first boot only) and auto-hold never Stops (renew-only), so the
        // only cross-source early-Stop is this one, and gating it on "no viewer" is sufficient.
        if matches!(crate::hold::stream_has_producer().await, Ok(false)) {
            let _ = view_tx.send(ViewCmd::Stop).await;
        }
        match learned {
            Ok(sprop) => match patch_sdp(&sprop).await {
                Ok(()) => {
                    eprintln!(
                        "btmqttd: learned camera parameter sets — the on-device camera now resolves instantly"
                    );
                    return;
                }
                // A patch failure is unusual (the installer wrote the SDP); log and retry — the SPS is
                // stable, so the next attempt derives the same value.
                Err(e) => {
                    eprintln!("btmqttd: sprop provisioning: failed to patch the go2rtc SDP: {e}")
                }
            },
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

/// True iff the go2rtc SDP already carries sprop (learned on a prior boot, or an operator-supplied
/// CAMERA_SPROP at install). A missing/unreadable file reads as "not provisioned" so the loop retries.
async fn sdp_has_sprop() -> bool {
    matches!(tokio::fs::read_to_string(SDP_PATH).await, Ok(s) if s.contains("sprop-parameter-sets="))
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

/// Run the vendored ffmpeg to derive the panel's sprop from the live RTP described by the go2rtc SDP.
/// `-sdp_file` writes an SDP whose `sprop-parameter-sets` ffmpeg computed from the in-stream SPS/PPS;
/// the widened analyzeduration makes find_stream_info WAIT for the panel's sparse keyframe (without the
/// reorder-buffer tuning that broke the live path — this is a one-shot probe, latency is irrelevant).
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
            SDP_PATH,
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

/// Splice a learned sprop into the go2rtc SDP's fmtp line and write it back atomically (temp + rename,
/// 0644 — the SDP carries no secret). Idempotent: a no-op if sprop is already present.
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
