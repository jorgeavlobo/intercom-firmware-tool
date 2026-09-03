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
//! pull can never wedge the daemon. Captures are guarded PER KIND: an idle capture uses a try-lock (a
//! mashed "Update idle snapshot" button just skips while one is running — the earlier grab is as good
//! as the later), while ring captures are SERIALIZED on a mutex, so a time-critical ring is never
//! dropped just because an idle capture is running, and a second ring WAITS for an in-flight ring
//! rather than skipping (which would leave the older, staler frame standing). Each ring invalidates the
//! previous visitor's `ring.jpg` and re-captures UNDER the lock, so a failed/timed-out ring yields a
//! clean 404 for the notification (never a stale photo) and no superseded capture can rename an
//! out-of-date frame back over a newer ring's image.
//! The JPEG lands in a UNIQUE private tmpfs scratch file that is removed after it is read, so a
//! concurrent request can't observe a torn file. The result is size-capped
//! ([`crate::persist::MAX_IDLE_JPG_BYTES`]) and structurally validated before it is stored, so a
//! truncated/garbage grab never reaches Home Assistant.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::LazyLock;
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

/// How recent a ring snapshot must be to still be served at `/ring.jpg`. A ring image is a transient
/// "who just rang" frame the HA push fetches within seconds of the capture. This mtime bound puts a
/// CEILING on how long a previous ring's image can linger: one older than the window (a prior ring THIS
/// ring could not refresh — the broker was offline so the capture was skipped, or the capture failed)
/// ages out to a 404 rather than serving a stale visitor indefinitely. It is a backstop, not the primary
/// guard: the reason a skipped/failed ring never NOTIFIES with a stale image is that the HA push triggers
/// on the "snapshot ready" MQTT signal, which is published ONLY on a successful capture (see sender.rs).
/// A DIRECT read of `/ring.jpg` within the window can still return the prior ring's frame — bounded and
/// same-doorway, and never reached by the notification path. Judged by mtime (the capture writes it
/// "now"), so no fragile per-ring cache-invalidation is needed.
const RING_FRESH_WINDOW: Duration = Duration::from_secs(120);

/// Overall capture budget: bring-up + connect + one keyframe + encode. The panel emits an in-stream
/// SPS/PPS only every ~20 s on a cold open (issue #120), and a fresh SIP bring-up adds a second or
/// two, so this must comfortably exceed that; ffmpeg is killed if it overruns.
const CAPTURE_TIMEOUT: Duration = Duration::from_secs(25);

/// How long to hold the panel up for an idle/button capture. Comfortably longer than the warm-up
/// delay plus [`CAPTURE_TIMEOUT`], so the SIP session can't lapse mid-grab even under a very short
/// `CAMERA_VIEW_IDLE_SECS` (which a `ViewCmd::Start` window would honour and could cap at 1 s). We use
/// `ViewCmd::Hold` with this ABSOLUTE expiry: its deadline governs independently of that manual window
/// (see `sip::governing_deadline`), so a short manual window can't starve the capture.
const CAPTURE_HOLD: Duration = Duration::from_secs(30);

/// Settle delay before the FIRST-RUN capture, so go2rtc, the firewall and the SIP UA are all up
/// before we try to wake the panel on a fresh boot.
pub const FIRST_RUN_DELAY: Duration = Duration::from_secs(60);

/// One idle capture at a time — a try-lock the persisted idle thumbnail uses. A mashed "Update idle
/// snapshot" button (or first-run overlapping the button) just SKIPS while one is running: the earlier
/// grab is as good as the later, and idle has no ordering requirement. Separate from the ring path
/// (below) so a time-critical ring is never dropped because an idle capture (first-run / button, up to
/// ~27 s) is running — go2rtc fans the stream out to both.
static CAPTURING_IDLE: AtomicBool = AtomicBool::new(false);

/// Ring captures are SERIALIZED, not skip-on-busy: the transient ring snapshot is time-ORDERED (each
/// notification must carry ITS OWN visitor), so a second ring WAITS for an in-flight one rather than
/// skipping — skipping would leave the older ring's frame standing and, worse, let the older capture
/// rename a now-stale frame back over the newer ring's image after it unlinked. Under this mutex the
/// unlink→capture→rename of each ring is exclusive, so the NEWEST ring always ends with its own fresh
/// frame (or a clean 404 on failure). Rings are already coalesced upstream (`publish_call_event`
/// debounce), so only DISTINCT presses reach here and the serialized wait is bounded by one in-flight
/// capture's own [`CAPTURE_TIMEOUT`].
static CAPTURING_RING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Monotonic clock base (process start), for the ring timestamp below.
static CLOCK_BASE: LazyLock<std::time::Instant> = LazyLock::new(std::time::Instant::now);

/// Milliseconds since [`CLOCK_BASE`] — a cheap monotonic tick.
fn now_ms() -> u64 {
    CLOCK_BASE.elapsed().as_millis() as u64
}

/// [`now_ms`] of the last DETECTED entrance ring (via [`note_ring`]), or 0 if none yet. An idle capture
/// reads it to DECLINE while a visitor is/was recently at the door, so a visitor frame is never persisted
/// as the empty-doorway idle thumbnail. It is advanced at ring DETECTION on the bus — independent of
/// whether the ring's MQTT event or the snapshot notification can be published, and independent of the
/// ring capture (which the single-capture guard may skip) — so an idle capture is invalidated even by a
/// ring it never saw a publish for.
static LAST_RING_MS: AtomicU64 = AtomicU64::new(0);

/// If a ring was DETECTED within this window before an idle capture started (or at any time during it),
/// the idle capture is declined: a doorbell call may still be streaming the visitor, so the grabbed frame
/// is not the empty doorway. Generous on purpose — a false decline only skips one idle update (first-run
/// retries next boot; the "Update idle snapshot" button can be re-pressed), whereas a false ACCEPT would
/// persist a visitor as the idle thumbnail across reboots + reflashes.
const RECENT_RING_WINDOW: Duration = Duration::from_secs(120);

/// Record that an entrance ring was DETECTED (called from the bus monitor on every entrance-panel-call
/// signature, BEFORE and independent of any MQTT publish). Advances the idle-invalidation clock so a
/// concurrent or imminent idle capture discards its (visitor) frame rather than storing it as the idle
/// thumbnail.
pub fn note_ring() {
    LAST_RING_MS.store(now_ms(), Ordering::Relaxed);
}

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
    // Serve ONLY a recent ring snapshot: an image older than RING_FRESH_WINDOW is a previous ring that
    // could not be refreshed (broker offline ⇒ capture skipped, or the capture failed), so it ages out to
    // a 404 rather than serving a stale visitor indefinitely — a CEILING on staleness, not a per-ring
    // invalidation (within the window a direct read can still return the prior frame; the notification
    // never does — it fires on the ready signal, published only on a successful capture). Lenient if the
    // mtime can't be read (serve): mtime is available on the tmpfs it lives on, and a missing mtime should
    // not blank a genuinely-fresh capture.
    let stale = file
        .metadata()
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|m| m.elapsed().ok())
        .is_some_and(|age| age > RING_FRESH_WINDOW);
    if stale {
        return None;
    }
    let mut buf = Vec::new();
    file.take(crate::persist::MAX_IDLE_JPG_BYTES + 1).read_to_end(&mut buf).ok()?;
    (!buf.is_empty() && buf.len() as u64 <= crate::persist::MAX_IDLE_JPG_BYTES).then_some(buf)
}

/// Percent-encode a credential for an RTSP URL's userinfo (RFC 3986: keep only the unreserved set
/// `A-Za-z0-9-._~`, `%`-escape every other byte). This MATCHES the on-device setup guide's HA camera
/// URL (`Uri.EscapeDataString`), so the capture reads the stream with exactly the credentials the
/// installer accepts and go2rtc serves — including a hand-supplied password with URL punctuation
/// (`@ : / ? #`) that would otherwise mis-split the URL. The installer's generated password is
/// base64url, all of which is unreserved, so it passes through UNCHANGED (the common case is
/// byte-for-byte the raw value). Pure, so it unit-tests.
fn pct_encode_userinfo(s: &str) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Build the loopback RTSP URL for the capture, or `None` when a credential is missing (capture then
/// declines rather than pulling an unauthenticated URL). The user and password are percent-encoded into
/// the userinfo, so any credential the installer accepts (and go2rtc serves) is read correctly. Pure.
fn rtsp_url(user: &str, pass: &str) -> Option<String> {
    (!user.is_empty() && !pass.is_empty()).then(|| {
        format!(
            "rtsp://{}:{}@127.0.0.1:{RTSP_PORT}/{STREAM_NAME}",
            pct_encode_userinfo(user),
            pct_encode_userinfo(pass)
        )
    })
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
        .ok_or_else(|| "RTSP credentials missing (CAMERA_RTSP_USER/CAMERA_RTSP_PASS)".to_string())?;

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
                // Overran the budget: SIGKILL the child AND reap it so no zombie is left. tokio's
                // `Child::kill().await` both signals and AWAITS the child's exit (it is `start_kill()` +
                // `wait().await`), so this reaps here; `kill_on_drop` is only the belt-and-braces for an
                // early return that skips this arm.
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
/// runaway file). Reads at most `cap + 1` bytes so an unexpectedly large ffmpeg output is REJECTED
/// without ever allocating the whole file into memory on the constrained device (mirrors
/// `persist::read_idle_jpg` / `read_ring_jpg`). `None` when absent/empty/oversized.
async fn read_scratch(path: &std::path::Path) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let file = tokio::fs::File::open(path).await.ok()?;
    let mut reader = file.take(crate::persist::MAX_IDLE_JPG_BYTES + 1);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).await.ok()?;
    (!bytes.is_empty() && bytes.len() as u64 <= crate::persist::MAX_IDLE_JPG_BYTES).then_some(bytes)
}

/// Try to acquire a capture guard `flag`; `None` when a capture of that kind is already running (the
/// caller then skips). The returned guard releases the flag on drop.
fn try_lock(flag: &'static AtomicBool) -> Option<CaptureGuard> {
    (!flag.swap(true, Ordering::AcqRel)).then_some(CaptureGuard(flag))
}

struct CaptureGuard(&'static AtomicBool);
impl Drop for CaptureGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Bring the panel up for an idle/button capture: poke the on-demand SIP UA so it INVITEs the panel,
/// then wait briefly for the media to start flowing before ffmpeg connects. Best effort — if on-demand
/// viewing is off (`view_tx` is `None`) there is no way to wake an idle panel, so the capture will
/// simply time out and be reported as failed.
///
/// Uses `ViewCmd::Hold` with an ABSOLUTE [`CAPTURE_HOLD`] expiry, NOT `ViewCmd::Start`: `Start` arms
/// the operator-configurable `CAMERA_VIEW_IDLE_SECS` window, which can be as short as 1 s and would
/// then expire before a cold-stream grab completes. `Hold`'s deadline governs independently of that
/// window (`sip::governing_deadline` takes the max), so the panel stays up for the whole capture
/// regardless of how short the manual window is — and it does not shorten a concurrent manual view.
async fn wake_panel(view_tx: Option<&mpsc::Sender<ViewCmd>>) {
    if let Some(tx) = view_tx {
        // try_send: never block the caller; Hold is idempotent (the UA re-checks + renews on each poke).
        let _ = tx.try_send(ViewCmd::Hold(tokio::time::Instant::now() + CAPTURE_HOLD));
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
    let Some(_guard) = try_lock(&CAPTURING_IDLE) else {
        eprintln!("btmqttd: capture: idle capture skipped (an idle capture is already in progress)");
        return false;
    };
    // Note when this capture started. An idle and a ring capture can run concurrently (separate guards),
    // and an idle capture can even begin while a ring call is already streaming — either way a VISITOR is
    // at the door and the frame is NOT the empty doorway. We decline (below) if a ring was DETECTED within
    // RECENT_RING_WINDOW before this start, or at any time during the grab.
    let capture_start_ms = now_ms();
    wake_panel(view_tx).await;
    let bytes = match grab_jpeg(cfg).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("btmqttd: capture: idle capture failed: {e}");
            return false;
        }
    };
    let last_ring = LAST_RING_MS.load(Ordering::Relaxed);
    if last_ring != 0
        && last_ring.saturating_add(RECENT_RING_WINDOW.as_millis() as u64) >= capture_start_ms
    {
        // A ring is recent (within the window before this capture) or happened during it (last_ring >=
        // start). Discard rather than persist a visitor as the idle thumbnail (it survives reboots +
        // reflashes); first-run retries next boot and the button can be re-pressed once the door is clear.
        eprintln!(
            "btmqttd: capture: idle capture declined — a ring is recent/active (visitor present); \
             keeping the idle thumbnail as the empty doorway"
        );
        return false;
    }
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

/// Capture the ring snapshot and write it to the transient tmpfs `ring.jpg` (served at `/ring.jpg`).
/// Does NOT wake the panel (a ring means it is already streaming) and does NOT touch `idle.jpg`.
/// Returns whether a ring image was captured and written. Skips (returns `false`) if a capture is
/// already running.
pub async fn capture_ring(cfg: &Config) -> bool {
    // (Idle-capture invalidation is handled at ring DETECTION on the bus via `note_ring`, not here, so it
    // also covers a ring whose event/notification never published — see LAST_RING_MS.)
    // SERIALIZE on the ring mutex: a second ring WAITS for any in-flight capture instead of skipping, so
    // the newest ring always ends with ITS OWN fresh frame and no superseded capture can rename a stale
    // frame back afterwards. The wait is bounded by the in-flight capture's own CAPTURE_TIMEOUT, and
    // upstream debounce means only distinct presses ever queue here.
    let _guard = CAPTURING_RING.lock().await;
    // Invalidate any PRIOR visitor's ring image, then (re)capture — both UNDER the lock, so nothing can
    // slip between the unlink and this ring's rename. Even a ring that fails or times out therefore
    // leaves NO stale image: a direct read of /ring.jpg gets a clean 404 instead of the previous person's
    // photograph. (The HA push also triggers on the "snapshot ready" signal, published only on a
    // successful capture, so a failed ring never fires a notification regardless.) The write is
    // temp+rename, so a concurrent /ring.jpg read never sees a torn file.
    let _ = tokio::fs::remove_file(ring_jpg_path()).await;
    let bytes = match grab_jpeg(cfg).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("btmqttd: capture: ring capture failed: {e}");
            return false;
        }
    };
    let stored = tokio::task::spawn_blocking(move || store_ring_jpg(&bytes)).await.unwrap_or(false);
    if stored {
        eprintln!("btmqttd: capture: ring snapshot captured");
    } else {
        eprintln!("btmqttd: capture: ring snapshot captured but could not be written");
    }
    stored
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
    fn pct_encode_userinfo_passes_base64url_and_escapes_punctuation() {
        // base64url (the installer's generated password alphabet) is all-unreserved → unchanged.
        assert_eq!(pct_encode_userinfo("aZ09-_camera"), "aZ09-_camera");
        assert_eq!(pct_encode_userinfo("a.b~c"), "a.b~c");
        // URL punctuation / whitespace / control are percent-escaped so they can't mis-split the URL.
        assert_eq!(pct_encode_userinfo("a@b:c/d"), "a%40b%3Ac%2Fd");
        assert_eq!(pct_encode_userinfo("p ss"), "p%20ss");
        assert_eq!(pct_encode_userinfo("100%"), "100%25");
    }

    #[test]
    fn rtsp_url_builds_loopback_url_or_declines() {
        // A base64url credential passes through raw (unreserved) — matching how HA reads the same URL.
        assert_eq!(
            rtsp_url("camera", "s3cret-_"),
            Some("rtsp://camera:s3cret-_@127.0.0.1:8554/doorbell".to_string())
        );
        // A credential with URL punctuation is percent-encoded into the userinfo, NOT rejected: every
        // credential the installer accepts is read correctly.
        assert_eq!(
            rtsp_url("camera", "p@ss"),
            Some("rtsp://camera:p%40ss@127.0.0.1:8554/doorbell".to_string())
        );
        // A missing credential declines (None) rather than building an unauthenticated URL.
        assert_eq!(rtsp_url("camera", ""), None);
        assert_eq!(rtsp_url("", "p"), None);
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
    fn capture_guard_is_exclusive_and_released_on_drop() {
        static FLAG: AtomicBool = AtomicBool::new(false);
        let g1 = try_lock(&FLAG);
        assert!(g1.is_some());
        assert!(try_lock(&FLAG).is_none(), "a second lock of the same kind must not acquire the guard");
        drop(g1);
        assert!(try_lock(&FLAG).is_some(), "the guard is released on drop");
    }

    #[test]
    fn idle_and_ring_guards_are_independent() {
        // A ring during an idle capture must NOT be blocked: idle uses a try-lock (skip-if-busy) and ring
        // a serializing mutex, on separate statics, so holding the idle guard leaves the ring lock free to
        // proceed (and vice versa).
        let idle = try_lock(&CAPTURING_IDLE).expect("idle guard free");
        let ring = CAPTURING_RING.try_lock();
        assert!(ring.is_ok(), "the ring lock must be independent of the idle guard");
        drop(ring);
        drop(idle);
    }
}
