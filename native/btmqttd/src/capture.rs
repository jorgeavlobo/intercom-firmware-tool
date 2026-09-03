//! On-device still capture (issue #169, Phase 2).
//!
//! Grabs ONE JPEG frame of the entrance-panel camera and stores it, so Home Assistant can show a
//! real picture instead of a placeholder:
//!   * the **idle thumbnail** — the empty-doorway view captured at first run and re-captured on the
//!     HA "Update idle snapshot" button — persisted to `cfg/extra/btmqttd/idle.jpg` and served by
//!     the Phase-1 still endpoint at `/idle.jpg`;
//!   * the **ring snapshot** — who is at the door at the instant of a ring — written to a transient
//!     PER-EVENT tmpfs file and served at `/ring-<id>.jpg`, used ONLY by the ring push notification
//!     (which carries the event id, so it fetches exactly that ring's frame). It NEVER overwrites the
//!     idle thumbnail.
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
//! The ffmpeg grab — the one step that can block on the stream/network — is wrapped in
//! [`CAPTURE_TIMEOUT`]; ffmpeg is KILLED if it overruns so a stuck pull can never wedge the daemon. The
//! steps around it are fast, local tmpfs I/O (the brief wake-panel poke, a size-bounded scratch read, an
//! unlink, an atomic store), not network-bound, so they need no timeout of their own. An idle capture
//! uses a try-lock (a mashed "Update idle snapshot"
//! button just skips while one is running — the earlier grab is as good as the later). Ring captures
//! run through a BOUNDED single runner ([`run_ring_captures`]): at most one capture is ever active, and
//! a burst of distinct rings does not queue a task each — extra rings only update [`RING_NEWEST`] and
//! the active runner picks up the latest when it finishes, so work can't pile up minutes deep on the
//! constrained panel. The ring path is separate from the idle guard, so a time-critical ring is never
//! dropped because an idle capture is running. Each captured ring is an INDEPENDENT event addressed by
//! a unique id: it writes its own `ring-<id>.jpg` (atomically, temp+rename) and the ready signal the HA
//! push triggers on carries that id, so the notification fetches exactly that event's frame — two rings
//! can never cross images, and there is no shared mutable "latest" file to overwrite. Per-event files
//! are retained for [`RING_FRESH_WINDOW`] (so the notification's fetch always resolves) then pruned; an
//! aged one reads as 404 via [`read_ring_event`].
//! The JPEG lands in a UNIQUE private tmpfs scratch file that is removed after it is read, so a
//! concurrent request can't observe a torn file. The result is size-capped
//! ([`crate::persist::MAX_IDLE_JPG_BYTES`]) and structurally validated before it is stored, so a
//! truncated/garbage grab never reaches Home Assistant.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
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

/// The transient ring snapshots on tmpfs (issue #169). Each ring is its OWN event, addressed by a
/// unique id and served at `/ring-<id>.jpg` — the industry pattern (Ring / Nest / Frigate): the push
/// notification carries the event id and fetches THAT event's frame, so two rings can never cross
/// images. Deliberately NOT persisted (a stale "who rang" picture must not survive a reboot). Same
/// tmpfs dir the runtime SDP lives in (`go2rtcd` creates it at boot); overridable via `$BTMQTTD_RUN_DIR`
/// (tests/dev).
const DEFAULT_RUN_DIR: &str = "/var/run/btmqttd";
/// Filename prefix + suffix for a per-event ring snapshot (`ring-<id>.jpg`).
const RING_FILE_PREFIX: &str = "ring-";
const RING_FILE_SUFFIX: &str = ".jpg";

/// How long a ring snapshot is retained + servable. A ring image is a transient "who just rang" frame
/// the HA push fetches within seconds of the capture; each event's file is kept this long (so the
/// notification's fetch always resolves) and then aged out — both by `read_ring_event` (an older file
/// reads as 404) and by the post-store cleanup that unlinks ring files past this age, bounding tmpfs
/// use. This is a retention policy, exactly like Frigate's event-snapshot TTL — the per-event URL means
/// there is no cross-ring staleness to guard, only how long each event lingers.
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

/// Ring captures run through a BOUNDED single runner ([`run_ring_captures`]): at most one capture is
/// ever active, and a burst of distinct rings does NOT queue a task each — extra rings only update
/// [`RING_NEWEST`], and the one active runner loops to capture each successive newest ring (coalescing
/// the rest) rather than a task piling up per ring. So at any instant there is at most one active
/// capture plus one pending (the latest); over a sustained burst the runner iterates, but the number of
/// LIVE tasks stays O(1) — there is no unbounded queue, and no task captures minutes after its ring
/// ended. `true` means a runner is active; a fresh ring spawns the runner only if it can flip this
/// false→true, otherwise the existing runner will serve it.
static RING_RUNNER_ACTIVE: AtomicBool = AtomicBool::new(false);

/// The event id of the NEWEST pending ring. Each detected ring bumps [`RING_EVENT_SEQ`] and stores its
/// id here; the runner always captures for this value, so a burst COALESCES to the latest ring (each
/// captured frame is still its own immutable `ring-<id>.jpg`, and only captured events publish a ready
/// signal — coalesced-away rings simply don't notify). Read/written under [`Ordering::Relaxed`]; the
/// runner handshake below (release then re-check) is what makes a late ring never get lost.
static RING_NEWEST: AtomicU64 = AtomicU64::new(0);

/// The broker SESSION epoch (see `sender::BROKER_EPOCH`) in effect when the NEWEST pending ring was
/// DETECTED — stored alongside [`RING_NEWEST`] by [`note_pending_ring`] and handed back to the runner's
/// `on_ready` so the "snapshot ready" publish is bound to the ring's OWN session, not the (possibly
/// older) session the runner was started in. This is what lets a ring detected AFTER a reconnect — served
/// by a runner an earlier ring started — still publish, while a pre-reconnect ring is suppressed. All
/// reads/writes are on the single-threaded runtime (main's event loop, the sender, and the runner task
/// never run truly concurrently), so `Relaxed` with epoch-before-id store ordering is sufficient.
static RING_NEWEST_EPOCH: AtomicU64 = AtomicU64::new(0);

/// Monotonic ring-event id source. Each detected ring takes the next value (via [`note_pending_ring`])
/// as its event id, which names its snapshot `ring-<id>.jpg`; the ready signal carries that id so Home
/// Assistant fetches exactly that event's frame (never another ring's).
static RING_EVENT_SEQ: AtomicU64 = AtomicU64::new(0);

/// Whether [`seed_ring_event_seq`] established a DURABLE, reboot-unique ring-id namespace (the per-boot
/// counter persisted). Default `false` until the seed runs. When `false` — a flash read/write error or a
/// corrupt counter — ring-snapshot capture is SUPPRESSED (the entrance ring event still fires; no
/// `/ring-<id>.jpg` is captured or published), because an id we can't prove unique could let a stale
/// notification resolve to a new visitor's frame. Read by the sender before each ring capture.
static RING_IDS_DURABLE: AtomicBool = AtomicBool::new(false);

/// Whether on-device ring snapshots may be captured this run — `false` when the durable ring-id namespace
/// could not be established (see [`RING_IDS_DURABLE`]). The sender gates ring capture on this.
pub fn ring_ids_durable() -> bool {
    RING_IDS_DURABLE.load(Ordering::Relaxed)
}

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

/// Serializes the idle-capture COMMIT (its final ring check + the rename that publishes `idle.jpg`) with
/// [`note_ring`]'s advance of [`LAST_RING_MS`]. The two run on different OS threads — the commit inside a
/// `spawn_blocking` worker, `note_ring` on the Tokio runtime thread — so `LAST_RING_MS`'s atomic ordering
/// alone can't stop a ring from landing in the tiny gap between "check passed" and "rename". Both sides
/// take this mutex, making the check+rename atomic w.r.t. a ring detection: a ring lands strictly before
/// the check (→ the commit is vetoed) or strictly after the rename (→ the frame committed was still the
/// empty doorway at commit time), never invisibly between. Held only for the timestamp read/write plus the
/// rename — never across the ffmpeg grab or the temp write — so it can't stall the runtime thread for long.
static RING_COMMIT_LOCK: Mutex<()> = Mutex::new(());

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
    // Take RING_COMMIT_LOCK for the store so this advance is serialized with capture_idle's final ring
    // check + rename (which holds the same lock across its rename): the two can't interleave across the
    // blocking-pool and runtime threads, so a ring can't land invisibly between an idle commit's check
    // and its rename. (Tolerate a poisoned lock — a panic elsewhere must not silently stop ring
    // invalidation.) The guard is released immediately after the store.
    let _commit = RING_COMMIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Clamp to a MINIMUM of 1: `now_ms()` returns 0 for the first tick right after `CLOCK_BASE` is
    // initialized, but 0 is LAST_RING_MS's "no ring yet" sentinel — so a first-ever ring at t≈0 must
    // still store a non-zero tick, or `capture_idle`'s `last_ring != 0` guard would mistake it for "no
    // ring" and could persist that visitor as the idle thumbnail. Losing the true sub-millisecond value
    // is irrelevant to a 120 s window.
    LAST_RING_MS.store(now_ms().max(1), Ordering::Relaxed);
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

/// The tmpfs path of a specific ring event's snapshot (`ring-<id>.jpg`).
fn ring_event_path(id: u64) -> std::path::PathBuf {
    run_dir().join(format!("{RING_FILE_PREFIX}{id}{RING_FILE_SUFFIX}"))
}

/// Read one ring EVENT's snapshot by id (for the `/ring-<id>.jpg` still-endpoint path). `None` when
/// absent, unreadable, empty, larger than the cap, or older than [`RING_FRESH_WINDOW`] — the endpoint
/// then replies 404. Because each event has its OWN immutable file, this only ever returns THAT event's
/// frame (never another ring's); the freshness bound is just the retention TTL. Blocking `std::fs`;
/// call via `spawn_blocking`.
pub fn read_ring_event(id: u64) -> Option<Vec<u8>> {
    use std::io::Read;
    let path = ring_event_path(id);
    let file = std::fs::File::open(&path).ok()?;
    // Retention TTL: a ring file past the window has aged out (its notification is long delivered), so it
    // reads as 404. A mtime in the FUTURE — `elapsed()` errors — means the wall clock stepped BACKWARD
    // since the write (e.g. an NTP correction during boot), and must be treated as AGED, not "fresh
    // forever": otherwise a snapshot would be served/retained indefinitely. Only a positively-confirmed
    // age within the window serves; a genuinely-unreadable mtime stays LENIENT (serve) since mtime is
    // always present on the tmpfs it lives on and a rare metadata blip shouldn't blank a fresh grab.
    let stale = match file.metadata().and_then(|m| m.modified()) {
        Ok(mtime) => match mtime.elapsed() {
            Ok(age) => age > RING_FRESH_WINDOW,
            Err(_) => true, // mtime in the future (clock stepped back) → age out conservatively
        },
        Err(_) => false, // mtime unreadable → lenient (serve)
    };
    if stale {
        // Opportunistically unlink the aged file so a read cleans it even if no further ring ever fires
        // `prune_aged_ring_files` (which runs at capture time). Together they mean an aged ring file is
        // removed by whichever happens first — the next ring OR a read of its path (HA polls the still
        // endpoint) — and any residue is bounded by the last window's rings and cleared on reboot (tmpfs).
        let _ = std::fs::remove_file(&path);
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

/// Grab one JPEG frame, returning the bytes. Assumes the caller already holds its exclusivity guard
/// (the [`CAPTURING_IDLE`] try-lock for an idle/button grab, or the single-runner slot —
/// [`RING_RUNNER_ACTIVE`] — for a ring grab) and (for an idle/button grab) has poked the panel up.
/// Spawns the vendored ffmpeg against go2rtc's
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
    // Fail fast if the scratch path is not valid UTF-8 rather than passing ffmpeg a LOSSY rendering:
    // ffmpeg would then write to a different path than the `out` we read back and remove, silently
    // failing the capture and leaking the temp file. `to_str()` is exact (byte-for-byte the path), so the
    // arg and the `out` we read/remove stay identical. The run dir is UTF-8 on-device (see run_dir); this
    // only trips a pathological non-UTF-8 `$BTMQTTD_RUN_DIR` override.
    let out_str = out
        .to_str()
        .ok_or_else(|| format!("scratch path is not valid UTF-8: {}", out.display()))?;

    let argv = capture_argv(&url, out_str);
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
/// `persist::read_idle_jpg` / `read_ring_event`). `None` when absent/empty/oversized.
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
    // at the door and the frame is NOT the empty doorway. A ring DETECTED within RECENT_RING_WINDOW before
    // this start, or at any time during the grab, declines the capture.
    let capture_start_ms = now_ms();
    // LAST_RING_MS is only ever advanced, so re-reading this is monotonic. It is checked THREE times: as an
    // EARLY fast path (below, BEFORE waking the panel or the ~25 s grab — so an already-known ring costs
    // neither a panel wake nor an ffmpeg run on the constrained device), AGAIN after the grab, and finally
    // as the commit gate inside store_idle_jpg (a ring landing DURING the blocking write vetoes the rename
    // instead of replacing idle.jpg — which survives reboots + reflashes — with a visitor frame).
    let ring_recent = move || {
        let last_ring = LAST_RING_MS.load(Ordering::Relaxed);
        last_ring != 0 && last_ring.saturating_add(RECENT_RING_WINDOW.as_millis() as u64) >= capture_start_ms
    };
    if ring_recent() {
        // Already-known ring: decline UP FRONT, without waking the panel or spending the grab on a frame we
        // would only discard. first-run retries next boot; the button can be re-pressed once the door clears.
        eprintln!(
            "btmqttd: capture: idle capture declined up front — a ring is recent/active (visitor present); \
             keeping the idle thumbnail as the empty doorway"
        );
        return false;
    }
    wake_panel(view_tx).await;
    let bytes = match grab_jpeg(cfg).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("btmqttd: capture: idle capture failed: {e}");
            return false;
        }
    };
    if ring_recent() {
        // A ring became recent/active while we were waking the panel or grabbing — discard the (visitor)
        // frame. (The commit gate below re-checks once more, right before the atomic rename.)
        eprintln!(
            "btmqttd: capture: idle capture declined — a ring became recent/active during the grab \
             (visitor present); keeping the idle thumbnail as the empty doorway"
        );
        return false;
    }
    // The atomic store is blocking std::fs — offload it off the single-threaded runtime. The commit gate
    // takes RING_COMMIT_LOCK, re-checks `ring_recent()`, and (if clear) returns the guard so it is HELD
    // across the rename. note_ring() takes the SAME lock before advancing LAST_RING_MS, so a ring arriving
    // during the write is serialized: either it lands before the check (→ gate returns None, temp
    // discarded, prior thumbnail intact) or strictly after the rename (→ the doorway was still empty when
    // this frame committed). The MutexGuard lives and dies inside this one blocking task (never crosses a
    // thread), so the closure stays `Send`.
    let stored = tokio::task::spawn_blocking(move || {
        crate::persist::store_idle_jpg(&bytes, move || {
            let guard = RING_COMMIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            if ring_recent() { None } else { Some(guard) }
        })
    })
    .await
    .unwrap_or(false);
    if stored {
        eprintln!("btmqttd: capture: idle snapshot updated");
    } else {
        eprintln!(
            "btmqttd: capture: idle snapshot not stored (a ring arrived during the write, or an I/O error)"
        );
    }
    stored
}

/// Record a freshly-DETECTED ring as the newest pending capture and return its event id. Called once
/// per fresh (non-coalesced, publishable) ring. Advances [`RING_EVENT_SEQ`] and stores the id in
/// [`RING_NEWEST`] so the single runner captures the latest ring of a burst. Ids increase strictly for
/// the life of the process — `u64` at one ring/second wraps only after ~5.8e11 years — and are held
/// `>= 1`: `.max(1)` maps the single value a (practically unreachable) wrap could land on, `0`, forward,
/// since `0` is [`RING_NEWEST`]'s "no ring" sentinel and must never be a real event id.
///
/// `broker_epoch` is the caller's `sender::BROKER_EPOCH` at detection; it is stored in
/// [`RING_NEWEST_EPOCH`] BEFORE the id, so any reader that observes the new id also observes this event's
/// epoch (single-threaded runtime, so this ordering is enough). The runner hands it back via `on_ready`
/// to bind the readiness publish to THIS ring's session — so a ring detected after a reconnect and served
/// by an earlier ring's still-active runner is not mistaken for a pre-reconnect one.
pub fn note_pending_ring(broker_epoch: u64) -> u64 {
    let id = RING_EVENT_SEQ.fetch_add(1, Ordering::Relaxed).wrapping_add(1).max(1);
    RING_NEWEST_EPOCH.store(broker_epoch, Ordering::Relaxed);
    RING_NEWEST.store(id, Ordering::Relaxed);
    id
}

/// Per-process stride of the ring-event-id namespace: each daemon start owns the half-open range
/// `[boot * STRIDE, (boot+1) * STRIDE)`. A billion ids per process is unreachable (at one ring/second a
/// process would run ~31 years), so ids from different process lifetimes never overlap.
const RING_ID_BOOT_STRIDE: u64 = 1_000_000_000;

/// The base of a boot's ring-id range: `boot * RING_ID_BOOT_STRIDE`, or `None` if the boot's COMPLETE
/// range `[base, base + RING_ID_BOOT_STRIDE)` would not fit in `u64` (a boot above ~1.8e10 — physically
/// unreachable). Requiring the full range — by checking the NEXT boot's base `(boot+1) * STRIDE` also fits
/// — matters because `note_pending_ring` allocates ids with `wrapping_add`: a partial final range could
/// wrap past `u64::MAX` to a low, already-used id. `None` fails the seed closed, so ids are never derived
/// from a range that could wrap or overlap.
fn ring_seed_base(boot: u64) -> Option<u64> {
    let base = boot.checked_mul(RING_ID_BOOT_STRIDE)?;
    boot.checked_add(1).and_then(|next| next.checked_mul(RING_ID_BOOT_STRIDE))?;
    Some(base)
}

/// Seed [`RING_EVENT_SEQ`] so a fresh process never reuses a ring id that a still-undelivered
/// notification's `/ring-<id>.jpg` URL points at (reuse would hand the old event the NEW visitor's
/// picture, breaking the immutable-URL guarantee). Anchored to a DURABLE per-process counter
/// ([`persist::bump_ring_boot`], on the reboot-/reflash-persistent partition): each daemon start takes a
/// strictly-higher boot number and thus a DISJOINT id range ([`RING_ID_BOOT_STRIDE`] apart), a hard
/// uniqueness guarantee across restarts AND reboots — closing the gap a tmpfs-only or wall-clock seed left
/// (a same-second reboot or a backward clock step could repeat an id). The max surviving `ring-<id>.jpg`
/// on tmpfs is kept as a belt-and-braces FLOOR, so even if the durable counter is ever lost/reset
/// (corruption) while a prior process's files linger, ids still stay above them. Call ONCE at startup,
/// before any ring is handled. Blocking `std::fs`.
pub fn seed_ring_event_seq() {
    // The durable per-process counter is the id-uniqueness authority. `None` means it could not be trusted
    // (a flash read/write error or a corrupt counter): FAIL CLOSED — mark ring ids non-durable so
    // ring-snapshot capture is suppressed (see [`ring_ids_durable`]) rather than risk reusing an id.
    let (mut seed, durable) = match crate::persist::bump_ring_boot().and_then(ring_seed_base) {
        Some(base) => (base, true),
        None => (0, false),
    };
    // tmpfs floor: on the durable path a belt-and-braces guard against a lost counter with lingering files;
    // on the fail-closed path it keeps RING_EVENT_SEQ above any file that does exist (ring capture is
    // suppressed anyway, but this keeps the sequence self-consistent).
    if let Ok(entries) = std::fs::read_dir(run_dir()) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if let Some(id) = name
                .to_str()
                .and_then(|n| n.strip_prefix(RING_FILE_PREFIX))
                .and_then(|n| n.strip_suffix(RING_FILE_SUFFIX))
                .and_then(|mid| mid.parse::<u64>().ok())
            {
                seed = seed.max(id);
            }
        }
    }
    RING_EVENT_SEQ.store(seed, Ordering::Relaxed);
    RING_IDS_DURABLE.store(durable, Ordering::Relaxed);
}

/// Try to become THE ring-capture runner. `Some(guard)` (won the [`RING_RUNNER_ACTIVE`] false→true flip)
/// means the caller owns the single runner slot; the [`RingRunnerGuard`] releases it on drop — including
/// on a panic/abort — so a crashed runner can never leave the slot stuck `true` (which would silently
/// disable ring captures for the rest of the process). `None` means a runner is already active and will
/// serve the ring just noted.
pub fn try_acquire_ring_runner() -> Option<RingRunnerGuard> {
    (!RING_RUNNER_ACTIVE.swap(true, Ordering::AcqRel)).then_some(RingRunnerGuard)
}

/// RAII ownership of the ring-runner slot: releases [`RING_RUNNER_ACTIVE`] on drop.
pub struct RingRunnerGuard;
impl Drop for RingRunnerGuard {
    fn drop(&mut self) {
        RING_RUNNER_ACTIVE.store(false, Ordering::Release);
    }
}

/// Drive ring captures to completion under the single-runner bound. Captures the NEWEST pending ring and
/// calls `on_ready(id, epoch)` for it (the caller publishes the "snapshot ready" signal for that id) — but
/// ONLY if no newer ring arrived during the grab; a superseded capture is discarded unpublished (its live
/// frame may belong to the newer visitor) and the newer ring is captured on the next iteration. It loops
/// only while a still-newer ring arrived during the capture — so a burst of distinct rings COALESCES to a
/// single notification carrying the latest frame, and work is bounded to one active capture, never a queue.
/// Takes the runner `guard` by value (from a winning [`try_acquire_ring_runner`]); the slot is released
/// via the guard's drop, so even a panic inside a capture frees it. `on_ready` is invoked synchronously
/// (no `.await` inside it on the production path), so the id it publishes is still the one just written.
///
/// `epoch` is [`RING_NEWEST_EPOCH`] — the broker session THIS event was detected on, read together with
/// the still-newest confirmation so a runner started for an older ring hands the caller each served ring's
/// OWN epoch (not the runner's start epoch). That lets the caller correctly publish a ring detected after
/// a reconnect while still suppressing one detected before it.
pub async fn run_ring_captures<F: Fn(u64, u64)>(cfg: &Config, guard: RingRunnerGuard, on_ready: F) {
    // We hold the slot via `guard`; it releases on drop — including during unwind, so a panic in the
    // capture/publish below still frees the slot instead of wedging ring captures for the process life.
    let mut guard = guard;
    loop {
        let id = RING_NEWEST.load(Ordering::Relaxed);
        // `capture_ring_frame` grabs the LIVE frame, which belongs to whatever visitor is at the door
        // *now*. Only publish it for `id` if `id` is still the newest ring after the grab: a newer ring
        // that arrived during the (up-to-25 s) grab means the live frame may be the NEWER visitor, so
        // binding it to the older event would mislabel it. Discard the superseded result and let the next
        // loop iteration capture-and-publish the newer id — so a burst collapses to one notification with
        // the freshest frame, never an older event carrying a newer visitor's picture. Read the epoch
        // AFTER confirming `id` is still newest, so it is this event's own detecting epoch.
        if capture_ring_frame(cfg, id).await && RING_NEWEST.load(Ordering::Relaxed) == id {
            on_ready(id, RING_NEWEST_EPOCH.load(Ordering::Relaxed));
        }
        // Release the slot (drop the guard) BEFORE re-checking for a newer ring: this ordering (release
        // before the re-check, and a fresh ring stores RING_NEWEST before it tries to acquire) guarantees
        // a ring that arrives around now is never lost — either this runner sees it here and re-acquires,
        // or the fresh ring itself wins the freed slot and starts its own runner.
        drop(guard);
        if RING_NEWEST.load(Ordering::Relaxed) == id {
            return; // nothing newer arrived — done
        }
        guard = match try_acquire_ring_runner() {
            Some(g) => g,   // re-took the slot — loop for the newer ring
            None => return, // a fresh ring already started its own runner; let it handle it
        };
    }
}

/// Capture ONE ring frame for event `id` and write it to its own tmpfs `ring-<id>.jpg` (served at
/// `/ring-<id>.jpg`). Does NOT wake the panel (a ring means it is already streaming) and does NOT touch
/// `idle.jpg`. Returns whether the frame was captured AND written. Each ring is independent: it has its
/// own immutable file, so no ring's notification can ever carry another ring's picture.
async fn capture_ring_frame(cfg: &Config, id: u64) -> bool {
    let bytes = match grab_jpeg(cfg).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("btmqttd: capture: ring capture failed (event {id}): {e}");
            return false;
        }
    };
    // Write this event's own immutable file, then prune aged-out ring files. Blocking std::fs — offload it.
    let stored = tokio::task::spawn_blocking(move || store_ring_event(id, &bytes)).await.unwrap_or(false);
    if stored {
        eprintln!("btmqttd: capture: ring snapshot captured (event {id})");
    } else {
        eprintln!("btmqttd: capture: ring snapshot captured but could not be written (event {id})");
    }
    stored
}

/// Write ring event `id`'s snapshot to tmpfs atomically (temp + rename), so a concurrent
/// `/ring-<id>.jpg` read never sees a torn file, then prune ring files older than the retention window
/// so tmpfs use stays bounded. No dir fsync — tmpfs is volatile by design (ring images are deliberately
/// not durable). Returns `true` on a successful write. Blocking; call via `spawn_blocking`.
fn store_ring_event(id: u64, bytes: &[u8]) -> bool {
    let dir = run_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        eprintln!("btmqttd: capture: cannot create {}: {e}", dir.display());
        return false;
    }
    let path = ring_event_path(id);
    let Some(path_str) = path.to_str() else {
        eprintln!("btmqttd: capture: ring path is not valid UTF-8");
        return false;
    };
    let ok = match crate::receiver::create_unique_temp(path_str, bytes) {
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
    };
    prune_aged_ring_files(&dir);
    ok
}

/// Unlink `ring-*.jpg` files whose mtime is older than [`RING_FRESH_WINDOW`] — the retention sweep that
/// keeps per-event ring snapshots from accumulating on tmpfs. A just-written event is far newer than the
/// window, so its own notification's fetch is never pruned out from under it. Best-effort: any error
/// (unreadable dir/entry/mtime) is ignored — a leftover file is at worst harmless tmpfs use, aged out by
/// [`read_ring_event`] anyway. Blocking; runs inside the `spawn_blocking` store.
fn prune_aged_ring_files(dir: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !(name.starts_with(RING_FILE_PREFIX) && name.ends_with(RING_FILE_SUFFIX)) {
            continue;
        }
        // Prune past-window files; a FUTURE mtime (clock stepped back) ages out too, so a backward clock
        // step can't strand a file forever. A genuinely-unreadable mtime is left (read_ring_event's TTL
        // still gates serving it).
        let aged = match entry.metadata().and_then(|m| m.modified()) {
            Ok(mtime) => mtime.elapsed().map_or(true, |age| age > RING_FRESH_WINDOW),
            Err(_) => false,
        };
        if aged {
            let _ = std::fs::remove_file(entry.path());
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
    fn ring_runner_slot_is_exclusive_coalesces_and_records_per_event_epoch() {
        // The single-runner bound: only ONE task can hold the runner slot, extra rings just record the
        // newest id, and the slot is re-acquirable once released. Also covers per-EVENT epoch binding
        // (#169): the newest pending ring carries ITS OWN detecting epoch. (This is the sole test that
        // touches the process-global ring counters, so its consecutive-id / newest-epoch assertions can't
        // race another test.) These statics are read by production code, so snapshot and RESTORE them so a
        // later-added test can't inherit the perturbed state.
        let saved_seq = RING_EVENT_SEQ.load(Ordering::Relaxed);
        let saved_newest = RING_NEWEST.load(Ordering::Relaxed);
        let saved_epoch = RING_NEWEST_EPOCH.load(Ordering::Relaxed);
        let saved_runner = RING_RUNNER_ACTIVE.load(Ordering::Relaxed);
        RING_RUNNER_ACTIVE.store(false, Ordering::Relaxed);
        // Ring A detected on broker session epoch 1.
        let a = note_pending_ring(1);
        assert_eq!(RING_NEWEST.load(Ordering::Relaxed), a, "RING_NEWEST tracks ring A");
        assert_eq!(RING_NEWEST_EPOCH.load(Ordering::Relaxed), 1, "A's epoch is its own detecting epoch");
        // Broker bounced (epoch -> 2). Ring B is detected on the NEW session while A's runner is still busy.
        // Its epoch — what run_ring_captures hands on_ready — must be 2 (B's own), not A's start epoch 1, so
        // B publishes on the current session instead of being suppressed as a pre-reconnect ring.
        let b = note_pending_ring(2);
        assert_eq!(b, a + 1, "each ring takes the next event id");
        assert_eq!(RING_NEWEST.load(Ordering::Relaxed), b, "RING_NEWEST tracks the latest ring");
        assert_eq!(
            RING_NEWEST_EPOCH.load(Ordering::Relaxed),
            2,
            "the newest event carries ITS OWN epoch (2), not the runner's start epoch (1)"
        );
        let g = try_acquire_ring_runner();
        assert!(g.is_some(), "first acquire wins the runner slot");
        assert!(try_acquire_ring_runner().is_none(), "a second acquire is refused while active");
        drop(g); // the guard releases the slot on drop
        let g2 = try_acquire_ring_runner();
        assert!(g2.is_some(), "the slot is re-acquirable once the guard is dropped");
        drop(g2);
        // Restore the process-global ring state so any later-added test starts from clean state.
        RING_RUNNER_ACTIVE.store(saved_runner, Ordering::Relaxed);
        RING_EVENT_SEQ.store(saved_seq, Ordering::Relaxed);
        RING_NEWEST.store(saved_newest, Ordering::Relaxed);
        RING_NEWEST_EPOCH.store(saved_epoch, Ordering::Relaxed);
    }

    #[test]
    fn ring_seed_base_is_checked_at_the_u64_boundary() {
        // The per-boot id range base multiplies boot by the stride; it must FAIL CLOSED (None) rather than
        // saturate — a saturated base would overlap a prior range and reuse ids (#169).
        assert_eq!(ring_seed_base(0), Some(0));
        assert_eq!(ring_seed_base(1), Some(RING_ID_BOOT_STRIDE));
        // Largest boot whose COMPLETE range [base, base+STRIDE) still fits — i.e. (boot+1)*STRIDE does not
        // overflow. Its base is accepted...
        let max_full = u64::MAX / RING_ID_BOOT_STRIDE - 1;
        assert_eq!(ring_seed_base(max_full), Some(max_full * RING_ID_BOOT_STRIDE));
        // ...but the next boot's range would cross u64::MAX (a partial range note_pending_ring could wrap
        // through), so it fails closed — as does a base that overflows outright.
        assert_eq!(ring_seed_base(max_full + 1), None);
        assert_eq!(ring_seed_base(u64::MAX), None);
    }

    #[test]
    fn note_ring_serializes_with_the_held_commit_lock() {
        // note_ring() advances LAST_RING_MS only AFTER taking RING_COMMIT_LOCK, and capture_idle's commit
        // gate holds that same lock across its final ring check + rename. So while the gate holds the lock,
        // a concurrent ring cannot advance LAST_RING_MS — it can't wedge itself between the check and the
        // rename. Prove it deterministically (no sleeps): hold the lock as the gate does, start a note_ring
        // on another thread, and confirm LAST_RING_MS stays put until the lock is released. This is sound
        // regardless of scheduling because note_ring's store is strictly AFTER the lock acquire it cannot
        // complete while we hold the lock.
        use std::sync::mpsc;
        // LAST_RING_MS is a process-global read by production code, so snapshot and RESTORE it (below) —
        // this test leaves it advanced otherwise, which a later-added test could inherit.
        let saved_last_ring = LAST_RING_MS.load(Ordering::Relaxed);
        LAST_RING_MS.store(0, Ordering::Relaxed);
        let guard = RING_COMMIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (tx, rx) = mpsc::channel();
        let h = std::thread::spawn(move || {
            tx.send(()).unwrap(); // announce we are about to contend for the lock
            note_ring(); // blocks on RING_COMMIT_LOCK until the main thread drops `guard`
        });
        rx.recv().unwrap(); // the ring thread is now heading into note_ring()
        assert_eq!(
            LAST_RING_MS.load(Ordering::Relaxed),
            0,
            "note_ring must not advance LAST_RING_MS while the commit lock is held"
        );
        drop(guard); // release — note_ring may now take the lock and store
        h.join().unwrap();
        assert_ne!(
            LAST_RING_MS.load(Ordering::Relaxed),
            0,
            "note_ring advances LAST_RING_MS once the commit lock is free"
        );
        LAST_RING_MS.store(saved_last_ring, Ordering::Relaxed); // restore the global for any later test
    }
}
