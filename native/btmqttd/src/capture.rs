//! On-device still capture (issue #169, Phase 2).
//!
//! Grabs ONE JPEG frame of the entrance-panel camera and stores it, so Home Assistant can show a
//! real picture instead of a placeholder:
//!   * the **idle thumbnail** — the empty-doorway view captured at first run and re-captured on the
//!     HA "Update idle snapshot" button — persisted to `cfg/extra/btmqttd/idle.jpg` and served by
//!     the Phase-1 still endpoint at `/idle.jpg`;
//!   * the **ring snapshot** — who is at the door at the instant of a ring — written to a transient
//!     tmpfs file and served at `/ring.jpg`, used ONLY by the ring push notification. It NEVER
//!     overwrites the idle thumbnail.
//!
//! ## How a frame is grabbed
//! The panel's H.264 is already fanned out by go2rtc as `rtsp://…@127.0.0.1:8554/doorbell` — the
//! SAME stream Home Assistant consumes. We spawn the vendored ffmpeg to pull that stream, decode ONE
//! frame and MJPEG-encode it to a JPEG file (`-frames:v 1 -c:v mjpeg -f image2`), then read the bytes
//! back. go2rtc owns the RTP socket and fans the copy out to N consumers, so a capture never contends
//! with a live viewer. For an idle/button capture the panel must be woken first (nothing streams when
//! idle), so we poke the on-demand SIP UA (`ViewCmd::Start`) before connecting; a ring capture needs
//! no poke — the panel is already streaming because it is ringing.
//!
//! ## Bounds / safety
//! The whole capture is wrapped in [`CAPTURE_TIMEOUT`]; ffmpeg is KILLED if it overruns so a stuck
//! pull can never wedge the daemon. Only ONE capture runs at a time (an in-flight guard drops a
//! second request rather than launching a redundant pull). The JPEG lands in a UNIQUE private tmpfs
//! scratch file that is removed after it is read, so a concurrent request can't observe a torn file.
//! The result is size-capped ([`crate::persist::MAX_IDLE_JPG_BYTES`]) and structurally validated
//! before it is stored, so a truncated/garbage grab never reaches Home Assistant.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::config::Config;
use crate::sip::ViewCmd;

/// The vendored ffmpeg on the device rootfs — mirrors `PayloadBinaries.Ffmpeg.InstallPath` (C#).
/// Overridable via `$BTMQTTD_FFMPEG_BIN` (tests/dev).
const DEFAULT_FFMPEG_BIN: &str = "/usr/sbin/ffmpeg";

/// go2rtc's on-device RTSP port and stream name — mirror `Go2RtcConfig.OnDeviceRtspPort` /
/// `OnDeviceStreamName`. The capture reads the SAME loopback RTSP URL Home Assistant consumes.
const RTSP_PORT: u16 = 8554;
const STREAM_NAME: &str = "doorbell";

/// The transient ring snapshot on tmpfs (issue #169): captured at ring time, served at `/ring.jpg`,
/// and used ONLY by the push notification — it is deliberately NOT persisted (a stale "who rang"
/// picture must not survive a reboot). Same tmpfs dir the runtime SDP lives in (`go2rtcd` creates it
/// at boot); overridable via `$BTMQTTD_RUN_DIR` (tests/dev).
const DEFAULT_RUN_DIR: &str = "/var/run/btmqttd";
const RING_JPG_FILE: &str = "ring.jpg";

/// Overall capture budget: bring-up + connect + one keyframe + encode. The panel emits an in-stream
/// SPS/PPS only every ~20 s on a cold open (issue #120), and a fresh SIP bring-up adds a second or
/// two, so this must comfortably exceed that; ffmpeg is killed if it overruns.
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(25);

/// Settle delay before the FIRST-RUN capture, so go2rtc, the firewall and the SIP UA are all up
/// before we try to wake the panel on a fresh boot.
pub const FIRST_RUN_DELAY: Duration = Duration::from_secs(60);

/// At most one capture at a time. A capture holds the panel/stream briefly; a second concurrent
/// request (button mashing, or a ring during a first-run capture) is DROPPED rather than launching a
/// redundant ffmpeg — the first grab is as good as the second a moment later.
static CAPTURING: AtomicBool = AtomicBool::new(false);

/// Per-process nonce so overlapping-in-time scratch files never collide (atop the pid).
static NONCE: AtomicU32 = AtomicU32::new(0);

fn ffmpeg_bin() -> String {
    std::env::var("BTMQTTD_FFMPEG_BIN").unwrap_or_else(|_| DEFAULT_FFMPEG_BIN.to_string())
}

fn run_dir() -> std::path::PathBuf {
    std::env::var_os("BTMQTTD_RUN_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_RUN_DIR))
}

/// The tmpfs path the ring snapshot is served from.
fn ring_jpg_path() -> std::path::PathBuf {
    run_dir().join(RING_JPG_FILE)
}

/// Read the transient ring snapshot (for the `/ring.jpg` still-endpoint path). `None` when absent,
/// unreadable, empty, or larger than the cap — the endpoint then replies 404 (there is no current
/// ring image), never a stale/placeholder picture. Blocking `std::fs`; call via `spawn_blocking`.
pub fn read_ring_jpg() -> Option<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(ring_jpg_path()).ok()?;
    let mut buf = Vec::new();
    file.take(crate::persist::MAX_IDLE_JPG_BYTES + 1).read_to_end(&mut buf).ok()?;
    (!buf.is_empty() && buf.len() as u64 <= crate::persist::MAX_IDLE_JPG_BYTES).then_some(buf)
}

/// True iff `s` is safe to place verbatim in the `user:pass@` userinfo of an RTSP URL: non-empty and
/// free of the delimiters that would mis-split the URL (`@ : / \ ?  #`) or whitespace/control bytes.
/// ffmpeg uses the userinfo VERBATIM for RTSP auth (it does not percent-decode it), so we must pass it
/// raw — the installer's generated password is base64url (all of which is safe here); this guard only
/// fails closed on a hand-edited conf with a URL-breaking credential (skip capture rather than build a
/// malformed URL). Pure, so it unit-tests.
fn userinfo_is_url_safe(s: &str) -> bool {
    !s.is_empty()
        && s.chars().all(|c| {
            !c.is_control()
                && !c.is_whitespace()
                && !matches!(c, '@' | ':' | '/' | '\\' | '?' | '#' | '%')
        })
}

/// Build the loopback RTSP URL for the capture, or `None` when the credentials are missing/unsafe
/// (capture then declines rather than pulling an unauthenticated or malformed URL). Pure.
fn rtsp_url(user: &str, pass: &str) -> Option<String> {
    (userinfo_is_url_safe(user) && userinfo_is_url_safe(pass))
        .then(|| format!("rtsp://{user}:{pass}@127.0.0.1:{RTSP_PORT}/{STREAM_NAME}"))
}

/// The ffmpeg argument vector for a one-frame JPEG grab from `rtsp_url` into `out_path`. Pure (no
/// I/O, no spawn) so the exact recipe is unit-tested and kept in step with `native/ffmpeg/build.sh`
/// (which enables exactly the mjpeg encoder + image2 muxer this uses):
///   * `-rtsp_transport tcp` — go2rtc's loopback RTSP, matching how HA reads it (no UDP reorder);
///   * `-i <url>` then `-an` — video only (the snapshot has no audio);
///   * `-frames:v 1 -c:v mjpeg -f image2 -y <file>` — decode ONE frame, MJPEG-encode it, write a
///     single self-contained JPEG file, overwriting any stale scratch file.
///
/// No `-pix_fmt` is forced: the panel feed is yuv420p and the mjpeg encoder accepts it directly, so
/// no swscale is pulled into the size-constrained binary (see build.sh).
fn capture_argv(rtsp_url: &str, out_path: &str) -> Vec<String> {
    [
        "-nostdin",
        "-hide_banner",
        "-loglevel",
        "error",
        "-rtsp_transport",
        "tcp",
        "-i",
        rtsp_url,
        "-an",
        "-frames:v",
        "1",
        "-c:v",
        "mjpeg",
        "-f",
        "image2",
        "-y",
        out_path,
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// Grab one JPEG frame, returning the bytes. Assumes the caller already holds the [`CAPTURING`] guard
/// and (for an idle/button grab) has poked the panel up. Spawns the vendored ffmpeg against go2rtc's
/// loopback RTSP, bounded by [`CAPTURE_TIMEOUT`] (the child is killed on overrun), then reads back the
/// scratch file and removes it. `Err` on any failure (declined creds, spawn/exit/timeout, empty or
/// oversized output) — the caller logs and leaves the target unchanged.
async fn grab_jpeg(cfg: &Config) -> Result<Vec<u8>, String> {
    let url = rtsp_url(&cfg.camera_rtsp_user, cfg.camera_rtsp_pass.as_deref().unwrap_or(""))
        .ok_or_else(|| {
            "RTSP credentials missing or not URL-safe (CAMERA_RTSP_USER/CAMERA_RTSP_PASS)".to_string()
        })?;

    let dir = run_dir();
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        return Err(format!("cannot create {}: {e}", dir.display()));
    }
    let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
    let out = dir.join(format!("capture-{}-{nonce}.jpg", std::process::id()));
    let out_str = out.to_string_lossy().into_owned();

    let argv = capture_argv(&url, &out_str);
    let mut cmd = tokio::process::Command::new(ffmpeg_bin());
    cmd.args(&argv);
    cmd.kill_on_drop(true);
    // Detach stdio: the child writes only the file; we don't read its pipes, so let its stderr go to
    // ours (loglevel error only) and give it no stdin.
    cmd.stdin(std::process::Stdio::null());

    let result = async {
        let mut child = cmd.spawn().map_err(|e| format!("cannot spawn ffmpeg: {e}"))?;
        match tokio::time::timeout(CAPTURE_TIMEOUT, child.wait()).await {
            Ok(Ok(status)) if status.success() => Ok(()),
            Ok(Ok(status)) => Err(format!("ffmpeg exited with {status}")),
            Ok(Err(e)) => Err(format!("waiting for ffmpeg failed: {e}")),
            Err(_) => {
                // Overran the budget — kill it so a stuck pull can't linger (kill_on_drop also covers
                // an early return, but do it explicitly and reap so no zombie is left).
                let _ = child.kill().await;
                Err(format!("ffmpeg capture timed out after {}s", CAPTURE_TIMEOUT.as_secs()))
            }
        }
    }
    .await;

    // Read back (bounded) then ALWAYS remove the scratch file, whether or not ffmpeg succeeded.
    let bytes = match &result {
        Ok(()) => read_scratch(&out).await,
        Err(_) => None,
    };
    let _ = tokio::fs::remove_file(&out).await;

    result?;
    let bytes = bytes.ok_or_else(|| "ffmpeg produced no usable JPEG".to_string())?;
    if !crate::still::is_jpeg(&bytes) {
        return Err("captured file is not a structurally valid JPEG".to_string());
    }
    Ok(bytes)
}

/// Read the scratch capture file, bounded to the idle cap (a capture is tens of KB; the cap guards a
/// runaway file). `None` when absent/empty/oversized.
async fn read_scratch(path: &std::path::Path) -> Option<Vec<u8>> {
    let bytes = tokio::fs::read(path).await.ok()?;
    (!bytes.is_empty() && bytes.len() as u64 <= crate::persist::MAX_IDLE_JPG_BYTES).then_some(bytes)
}

/// Try to acquire the single-capture guard; `None` when a capture is already running (the caller then
/// skips). The returned guard releases the flag on drop.
fn try_lock_capture() -> Option<CaptureGuard> {
    (!CAPTURING.swap(true, Ordering::AcqRel)).then_some(CaptureGuard)
}

struct CaptureGuard;
impl Drop for CaptureGuard {
    fn drop(&mut self) {
        CAPTURING.store(false, Ordering::Release);
    }
}

/// Bring the panel up for an idle/button capture: poke the on-demand SIP UA (`ViewCmd::Start`) so it
/// INVITEs the panel, then wait briefly for the media to start flowing before ffmpeg connects. Best
/// effort — if on-demand viewing is off (`view_tx` is `None`) there is no way to wake an idle panel,
/// so the capture will simply time out and be reported as failed.
async fn wake_panel(view_tx: Option<&mpsc::Sender<ViewCmd>>) {
    if let Some(tx) = view_tx {
        // try_send: never block the caller; Start is idempotent (the UA re-checks on each poke).
        let _ = tx.try_send(ViewCmd::Start);
        // Give the SIP INVITE + the panel's media-start a moment before ffmpeg connects, so go2rtc's
        // producer has RTP to serve rather than opening onto silence. ffmpeg still waits for the first
        // keyframe within CAPTURE_TIMEOUT, so this is only a head start, not a correctness dependency.
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Capture the idle thumbnail and persist it to `cfg/extra/btmqttd/idle.jpg` (survives reboot +
/// reflash). Used by the first-run auto-capture and the HA "Update idle snapshot" button. Wakes the
/// panel first (idle panels don't stream). Returns whether a fresh idle image was captured AND stored.
/// Skips (returns `false`) if another capture is already running.
pub async fn capture_idle(cfg: &Config, view_tx: Option<&mpsc::Sender<ViewCmd>>) -> bool {
    let Some(_guard) = try_lock_capture() else {
        eprintln!("btmqttd: capture: idle capture skipped (a capture is already in progress)");
        return false;
    };
    wake_panel(view_tx).await;
    match grab_jpeg(cfg).await {
        Ok(bytes) => {
            // The atomic store is blocking std::fs — offload it off the single-threaded runtime.
            let stored = tokio::task::spawn_blocking(move || crate::persist::store_idle_jpg(&bytes))
                .await
                .unwrap_or(false);
            if stored {
                eprintln!("btmqttd: capture: idle snapshot updated");
            } else {
                eprintln!("btmqttd: capture: idle snapshot captured but could not be stored");
            }
            stored
        }
        Err(e) => {
            eprintln!("btmqttd: capture: idle capture failed: {e}");
            false
        }
    }
}

/// Capture the ring snapshot and write it to the transient tmpfs `ring.jpg` (served at `/ring.jpg`).
/// Does NOT wake the panel (a ring means it is already streaming) and does NOT touch `idle.jpg`.
/// Returns whether a ring image was captured and written. Skips (returns `false`) if a capture is
/// already running.
pub async fn capture_ring(cfg: &Config) -> bool {
    let Some(_guard) = try_lock_capture() else {
        eprintln!("btmqttd: capture: ring capture skipped (a capture is already in progress)");
        return false;
    };
    match grab_jpeg(cfg).await {
        Ok(bytes) => {
            let stored =
                tokio::task::spawn_blocking(move || store_ring_jpg(&bytes)).await.unwrap_or(false);
            if stored {
                eprintln!("btmqttd: capture: ring snapshot captured");
            } else {
                eprintln!("btmqttd: capture: ring snapshot captured but could not be written");
            }
            stored
        }
        Err(e) => {
            eprintln!("btmqttd: capture: ring capture failed: {e}");
            false
        }
    }
}

/// Write the transient ring snapshot to tmpfs atomically (temp + rename), so a concurrent
/// `/ring.jpg` read never sees a torn file. No dir fsync — tmpfs is volatile by design (the ring
/// image is deliberately not durable). Returns `true` on success. Blocking; call via `spawn_blocking`.
fn store_ring_jpg(bytes: &[u8]) -> bool {
    let dir = run_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("btmqttd: capture: cannot create {}: {e}", dir.display());
        return false;
    }
    let path = ring_jpg_path();
    let Some(path_str) = path.to_str() else {
        eprintln!("btmqttd: capture: ring path is not valid UTF-8");
        return false;
    };
    match crate::receiver::create_unique_temp(path_str, bytes) {
        Ok(tmp) => match std::fs::rename(&tmp, path_str) {
            Ok(()) => true,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                eprintln!("btmqttd: capture: cannot write {path_str}: {e}");
                false
            }
        },
        Err(e) => {
            eprintln!("btmqttd: capture: cannot create temp for {path_str}: {e}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn userinfo_safety_accepts_base64url_and_rejects_url_breakers() {
        // The installer's generated password is base64url — all of which is URL-safe here.
        assert!(userinfo_is_url_safe("camera"));
        assert!(userinfo_is_url_safe("aZ09-_bQ")); // base64url alphabet
        // Empty / URL-delimiter / whitespace / control → rejected (fail closed).
        assert!(!userinfo_is_url_safe(""));
        assert!(!userinfo_is_url_safe("a@b"));
        assert!(!userinfo_is_url_safe("a:b"));
        assert!(!userinfo_is_url_safe("a/b"));
        assert!(!userinfo_is_url_safe("a b"));
        assert!(!userinfo_is_url_safe("a\nb"));
        assert!(!userinfo_is_url_safe("a%b"));
    }

    #[test]
    fn rtsp_url_builds_loopback_url_or_declines() {
        assert_eq!(
            rtsp_url("camera", "s3cret-_"),
            Some("rtsp://camera:s3cret-_@127.0.0.1:8554/doorbell".to_string())
        );
        // A missing or unsafe credential declines (None) rather than building a malformed URL.
        assert_eq!(rtsp_url("camera", ""), None);
        assert_eq!(rtsp_url("", "p"), None);
        assert_eq!(rtsp_url("camera", "bad/pass"), None);
    }

    #[test]
    fn capture_argv_has_the_one_frame_mjpeg_recipe() {
        let argv = capture_argv("rtsp://camera:p@127.0.0.1:8554/doorbell", "/run/x.jpg");
        // The credentialed URL and the output path are passed through verbatim.
        assert!(argv.contains(&"rtsp://camera:p@127.0.0.1:8554/doorbell".to_string()));
        assert!(argv.contains(&"/run/x.jpg".to_string()));
        // Exactly one frame, video-only, MJPEG-encoded to a single image2 file over TCP RTSP.
        assert!(argv.windows(2).any(|w| w == ["-rtsp_transport", "tcp"]));
        assert!(argv.windows(2).any(|w| w == ["-frames:v", "1"]));
        assert!(argv.windows(2).any(|w| w == ["-c:v", "mjpeg"]));
        assert!(argv.windows(2).any(|w| w == ["-f", "image2"]));
        assert!(argv.contains(&"-an".to_string()));
        // No forced pixel format (would pull swscale, which the vendored ffmpeg deliberately omits).
        assert!(!argv.iter().any(|a| a == "-pix_fmt"));
    }

    #[test]
    fn capture_guard_is_exclusive() {
        let g1 = try_lock_capture();
        assert!(g1.is_some());
        assert!(try_lock_capture().is_none(), "a second capture must not acquire the guard");
        drop(g1);
        assert!(try_lock_capture().is_some(), "the guard is released on drop");
    }
}
