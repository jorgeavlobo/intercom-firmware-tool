//! MQTT -> bus: dispatch a message received on TOPIC_RX. A raw OpenWebNet frame is
//! forwarded to the local gateway (127.0.0.1:30006). A JSON payload is one of two
//! things:
//!   * an UNGATED device-control ACTION (volume / mute / volume_step / lock — issues
//!     #40/#41): these actuate the OWN bus the same way a raw frame on TOPIC_RX
//!     already can (the broker ACL on TOPIC_RX is the trust boundary), so they are
//!     not behind the remote-shell gate; see handle_action for the posture note;
//!   * a GATED shell command (read_file / write_file / execute_command), honoured
//!     ONLY when the remote-command channel is unlocked (ALLOW_REMOTE_SHELL=1 AND the
//!     client is authenticated) — code execution, so it stays locked by default.
//!
//! Extends StartMqttReceive's dispatch/handle_json with the device-control actions.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rumqttc::{AsyncClient, QoS};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio::sync::Semaphore;

use tokio::sync::mpsc::{self, Sender};

use crate::config::{Config, OWN_PORT_CMD};
use crate::light::LightCtl;
use crate::lock::Lock;
use crate::own;
use crate::sip::ViewCmd;
use crate::volume::VolumeCtl;

/// Cap for read_file/write_file/execute_command payloads (256 KB), matching
/// `head -c 262144` in the shell — a huge/special file or runaway command must not
/// balloon memory or blow past the broker's message limit.
const CAP: usize = 262_144;

/// Wall-clock cap for an execute_command child (the shell relied on the reader
/// closing the pipe to SIGPIPE a runaway; we kill explicitly after this).
const EXEC_TIMEOUT: Duration = Duration::from_secs(60);

/// Wall-clock cap for forwarding a frame to the local gateway. The command worker
/// is single and ordered, so a gateway that accepts the connection but stops
/// reading (or hangs on connect) would block write_all/flush with no deadline and
/// stall EVERY subsequent command, not just this frame. Loopback + a tiny payload
/// makes this unlikely, but the bound keeps the worker live regardless.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(5);

/// Monotonic suffix so concurrent write_file tasks never share a temp path.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Fixed cap on command children that are running-or-awaiting-reap at once. A permit
/// is reserved BEFORE spawning the shell (see execute_command), so a flood of
/// CAP-hitting commands whose killed children momentarily block unreaped can't grow the
/// daemon's outstanding-child/task count without limit — the (N+1)-th is rejected.
const REAP_CONCURRENCY: usize = 16;

/// The fixed-capacity permit pool backing REAP_CONCURRENCY. A permit is held from just
/// before spawn until the child is reaped (released inline on a clean finish, or by the
/// reaper task on cap/timeout). `const_new` so it lives in a `static` with no lazy init.
static REAP_SLOTS: Semaphore = Semaphore::const_new(REAP_CONCURRENCY);

/// Dispatch one received payload. The shell receiver looped `while IFS= read -r
/// rxcmd`, so it processed EVERY `\n`-delimited line of a payload IN ORDER — a
/// multi-line message is several records, not one. We split on `\n` and run each
/// record through the same ordered path (`dispatch` is awaited sequentially by the
/// single command worker, so ordering is preserved). `read -r` consumes only the
/// `\n` separator and keeps any other byte, so `\r` is PRESERVED within each record
/// (a CRLF frame `*…##\r` therefore fails the OWN-frame check and is not forwarded,
/// exactly as the shell's `^\*.*##$` did). Never panics; every failure is logged and
/// swallowed so one bad record can't take the receiver down.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch(
    cfg: &Arc<Config>,
    client: &AsyncClient,
    vol: &Arc<VolumeCtl>,
    lock: &Sender<Lock>,
    light: Option<&Arc<LightCtl>>,
    view_tx: Option<&Sender<ViewCmd>>,
    restart: &Arc<Notify>,
    payload: &[u8],
) {
    let text = match std::str::from_utf8(payload) {
        Ok(t) => t,
        Err(_) => {
            eprintln!("btmqttd: ignoring non-UTF-8 command payload");
            return;
        }
    };
    for record in text.split('\n') {
        dispatch_record(cfg, client, vol, lock, light, view_tx, restart, record).await;
    }
}

/// Classify and act on ONE line (the shell's per-`read` record). `record` keeps its
/// `\r` and any interior/leading/trailing spaces — a space-prefixed " *…##" is not an
/// OWN frame (it falls to the ignored JSON path, as in the shell, rather than being
/// forwarded to the gateway and executed).
#[allow(clippy::too_many_arguments)]
async fn dispatch_record(
    cfg: &Arc<Config>,
    client: &AsyncClient,
    vol: &Arc<VolumeCtl>,
    lock: &Sender<Lock>,
    light: Option<&Arc<LightCtl>>,
    view_tx: Option<&Sender<ViewCmd>>,
    restart: &Arc<Notify>,
    record: &str,
) {
    // Blank / whitespace-only records are neither a frame nor JSON — ignore them.
    if record.trim().is_empty() {
        return;
    }
    if own::is_own_frame(record) {
        if let Err(e) = forward_to_gateway(record, FORWARD_TIMEOUT).await {
            eprintln!("btmqttd: forwarding frame to gateway failed: {e}");
        }
    } else {
        handle_json(cfg, client, vol, lock, light, view_tx, restart, record).await;
    }
}

/// Forward a raw OpenWebNet frame to the gateway's command-injection port. Always
/// the LOOPBACK gateway (127.0.0.1:30006), as StartMqttReceive did — OWN_HOST is
/// only the monitor (read) endpoint, not the command (write) endpoint. `pub(crate)`
/// so the lock task (`lock.rs`) can send its press/release frames the same way; it
/// passes a TIGHTER `timeout` so a full press+hold+release pulse fits inside the
/// shutdown drain window (the raw-command path passes [`FORWARD_TIMEOUT`]).
pub(crate) async fn forward_to_gateway(frame: &str, timeout: Duration) -> std::io::Result<()> {
    tokio::time::timeout(timeout, async {
        let mut sock = TcpStream::connect(("127.0.0.1", OWN_PORT_CMD)).await?;
        sock.write_all(frame.as_bytes()).await?;
        sock.write_all(b"\n").await?;
        sock.flush().await?;
        Ok::<_, std::io::Error>(())
    })
    .await
    .map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::TimedOut, "gateway forward timed out")
    })?
}

#[allow(clippy::too_many_arguments)]
async fn handle_json(
    cfg: &Arc<Config>,
    client: &AsyncClient,
    vol: &Arc<VolumeCtl>,
    lock: &Sender<Lock>,
    light: Option<&Arc<LightCtl>>,
    view_tx: Option<&Sender<ViewCmd>>,
    restart: &Arc<Notify>,
    msg: &str,
) {
    let v: Value = match serde_json::from_str(msg) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("btmqttd: ignored non-JSON command payload");
            return;
        }
    };
    // Device-control ACTIONS (volume / mute / lock) are UNGATED — the broker ACL on
    // TOPIC_RX is the trust boundary. TOPIC_RX is ALREADY a privileged control channel:
    // a raw frame on it is forwarded to the gateway (:30006) with no gate, so a
    // publisher can already actuate WHO=8 commands — including opening a lock
    // (*8*19*20##). The `main_lock`/`secondary_lock` actions here are exactly that same
    // :30006 capability. `volume`/`mute` additionally reach WHO=8 DIMENSION writes on
    // openserver (:20000), a capability a raw :30006 frame does NOT have — but volume is
    // low-stakes and strictly less sensitive than the lock a raw frame can already
    // trigger, so gating only the volume path (while raw frames stay ungated) would add
    // no real security. The arbitrary-shell channel below (read_file/write_file/
    // execute_command) is the one that stays behind ALLOW_REMOTE_SHELL, because it is
    // categorically more dangerous (code execution). These are the payloads the HA
    // volume/lock entities publish (via command_template / payload_press).
    if let Some(action) = v.get("action").and_then(Value::as_str) {
        // On-demand viewing (issue #104): `view_camera` pokes the SIP UA to bring the idle panel A/V
        // session up (and refresh its idle-hangup timer); `stop_camera` ends it now instead of waiting
        // for the idle timeout. NOTE (#129): when the on-device camera's auto-hold is active, a
        // `stop_camera` issued WHILE a viewer is connected is restarted within one poll (auto-hold is
        // authoritative — see hold.rs); it ends the session only when no viewer is connected. To end an
        // active view, close the viewer. Same ungated posture as the other actions — TOPIC_RX is the trust
        // boundary. try_send (never blocks the worker): Start is idempotent (the UA re-checks and
        // refreshes on each poke). A Stop dropped on a FULL queue is bounded and self-correcting:
        // while a session is UP the UA drains view_rx every select turn, so 8 messages can't pile up;
        // the queue only saturates while the UA is NOT draining (reconnect backoff / a sub-second
        // connect), and in that state there is no active session to leave streaming — a session that
        // then starts from a queued Start still auto-hangs-up after CAMERA_VIEW_IDLE_SECS, and the user
        // can press Stop again once the queue drains. A parallel priority signal isn't worth the
        // ordering complexity for that bounded case (Codex).
        if action == "view_camera" || action == "stop_camera" {
            let cmd = if action == "view_camera" { ViewCmd::Start } else { ViewCmd::Stop };
            match view_tx {
                Some(tx) => match tx.try_send(cmd) {
                    Ok(()) => {}
                    // Bounded queue momentarily full (the UA isn't draining — reconnect backoff / a
                    // sub-second connect). Harmless per the note above, but log it so a user who
                    // pressed the HA button and saw nothing has something to correlate.
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        eprintln!("btmqttd: dropped {action} (on-demand trigger queue full)");
                    }
                    // Distinct from Full: the SIP task has exited (channel closed), so on-demand
                    // viewing is effectively down until restart — log it differently for diagnosis.
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        eprintln!("btmqttd: dropped {action} (on-demand SIP task is gone)");
                    }
                },
                None => eprintln!(
                    "btmqttd: ignored {action}: on-demand viewing disabled \
                     (needs CAMERA_ENABLED=1 and CAMERA_ONDEMAND_ENABLED=1)"
                ),
            }
            return;
        }
        // Maintenance actions (issue #43): the HA "Reboot device" / "Restart bridge" buttons. Same
        // ungated posture and TOPIC_RX trust boundary as the controls above — a FIXED reboot/restart is
        // no wider a capability than the lock a raw frame on this topic can already actuate.
        if let Some(m) = parse_maintenance(action) {
            match m {
                Maintenance::Reboot => {
                    // Accept a reboot only while none is OUTSTANDING; ignore repeats so a `reboot` that
                    // hasn't exited can't be re-fired into unbounded processes (see [`reboot_in_progress`]).
                    // "Outstanding" spans BOTH this daemon's owned reboot (the in-memory gate) and any live
                    // `reboot` in `/proc` — including one a PRIOR daemon instance launched before a re-exec
                    // or watchdog respawn — so a fresh daemon can't pile a second `reboot` on a still-hung
                    // one. The single ordered worker means no press can race this check; once past it,
                    // latch the in-memory gate and `spawn_reboot` owns the process, releasing the gate only
                    // once it is OBSERVED to have exited — a hung reboot keeps the bound, an exited/failed
                    // one re-enables the button.
                    if reboot_in_progress().await {
                        eprintln!("btmqttd: reboot already in progress; ignoring this press");
                        return;
                    }
                    REBOOT_REQUESTED.store(true, Ordering::Relaxed);
                    eprintln!("btmqttd: reboot requested via MQTT; rebooting the device");
                    // Publish the HA feedback BEFORE rebooting so it can flush; then reboot.
                    publish_maintenance(client, cfg, "reboot").await;
                    spawn_reboot();
                }
                Maintenance::RestartBridge => {
                    // Reuse main.rs's in-place re-exec path: a clean shutdown (flush the MQTT `offline`
                    // will, drain the light-persist task) then `exec` of the SAME binary — same PID, so
                    // bt_service_watchdog's pgrep supervision is undisturbed and the bridge is back in
                    // ~1 s (vs a ~60 s watchdog respawn if we merely exited). btmqttd must NOT run the
                    // init script's `restart` on itself — that would SIGKILL this handler mid-flight.
                    //
                    // Stand down early while a reboot is OUTSTANDING. The AUTHORITATIVE guard is the main
                    // loop's `restart.notified()` arm (it covers BOTH restart producers — this button and
                    // the light-WHERE learn — from cancelling the reboot observer); rejecting here as well
                    // avoids publishing a misleading "restart_bridge" feedback and notifying for a press the
                    // loop would only drop. A reboot supersedes a bridge restart anyway — the box is going
                    // down — so the press is dropped, not queued; the button works again once the reboot is
                    // observed to have exited (gate cleared) or in a fresh daemon.
                    if reboot_in_progress().await {
                        eprintln!("btmqttd: restart ignored: a reboot is already in progress");
                        return;
                    }
                    eprintln!("btmqttd: restart requested via MQTT; re-execing the bridge");
                    // Publish the HA feedback first; the clean shutdown below flushes it before the BYE.
                    publish_maintenance(client, cfg, "restart_bridge").await;
                    restart.notify_one();
                }
                Maintenance::RestoreSsh => {
                    // On-demand SSH recovery net (issue #130): (re)start dropbear so sshd is listening. The
                    // MQTT command reaches us even when inbound `:22` is blocked (our broker link is
                    // outbound), so this brings SSH back without a reboot or power-cycle. It never touches
                    // the firewall (see `restore_ssh`). Idempotent; safe to repeat.
                    eprintln!("btmqttd: restore_ssh requested via MQTT");
                    restore_ssh().await;
                    // Publish the HA feedback AFTER the (fast, non-terminal) recovery so the ack reflects a
                    // completed action — unlike reboot/restart, which flush their feedback before going down.
                    publish_maintenance(client, cfg, "restore_ssh").await;
                }
            }
            return;
        }
        handle_action(vol, lock, light, action, &v).await;
        return;
    }

    if !cfg.remote_shell_allowed() {
        eprintln!(
            "btmqttd: ignored JSON command: remote channel disabled (needs \
             ALLOW_REMOTE_SHELL=1 and an authenticated broker: user/pass or mutual TLS)."
        );
        return;
    }
    let command = v.get("command").and_then(Value::as_str).unwrap_or("");
    let file_path = v.get("file_path").and_then(Value::as_str).unwrap_or("");
    // `data` as Option: a MISSING (or non-string) key is rejected per-command rather
    // than defaulting to "". Defaulting silently truncates a write_file target to
    // empty and runs execute_command as `sh -c ""` — dangerous on a remote command
    // surface. An EXPLICIT "data":"" is still honoured (an intentional truncate / no-op).
    let data = v.get("data").and_then(Value::as_str);

    match command {
        "read_file" => read_file(cfg, client, file_path).await,
        "write_file" => match data {
            Some(d) => write_file(file_path, d).await,
            None => eprintln!("btmqttd: write_file: missing 'data'"),
        },
        "execute_command" => match data {
            Some(d) => execute_command(cfg, client, d).await,
            None => eprintln!("btmqttd: execute_command: missing 'data'"),
        },
        "" => eprintln!("btmqttd: JSON command missing 'command'"),
        other => eprintln!("btmqttd: unsupported command: {other}"),
    }
}

/// A parsed MAINTENANCE action (issues #43, #130) — the HA "Reboot device" / "Restart bridge" /
/// "Restore SSH" buttons. These have a SIDE EFFECT outside the vol/lock/light surface `handle_action`
/// covers (a process spawn, a re-exec signal, or a dropbear start), so they are classified here and
/// dispatched inline in `handle_json`. Pure classifier, separated so the action-name mapping is
/// unit-testable without spawning a reboot, re-execing, or touching dropbear.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Maintenance {
    /// Reboot the whole device (`{"action":"reboot"}`).
    Reboot,
    /// Re-exec btmqttd in place (`{"action":"restart_bridge"}`).
    RestartBridge,
    /// On-demand SSH recovery — (re)start dropbear so sshd listens on `:22` (`{"action":"restore_ssh"}`).
    RestoreSsh,
}

/// Map an `action` string to a [`Maintenance`] variant, or `None` if it isn't a maintenance action.
fn parse_maintenance(action: &str) -> Option<Maintenance> {
    match action {
        "reboot" => Some(Maintenance::Reboot),
        "restart_bridge" => Some(Maintenance::RestartBridge),
        "restore_ssh" => Some(Maintenance::RestoreSsh),
        _ => None,
    }
}

/// Publish a RETAINED "last maintenance action" record to `topic_maintenance` for the HA feedback
/// sensor (issue #43) — the visible ack for an otherwise-stateless button press: `{"action":"<name>",
/// "at":"<iso>"}`. RETAINED so Home Assistant still shows it across the reboot / bridge re-exec that
/// immediately follows (HA re-reads the retained value on reconnect). Published BEFORE the action so a
/// restart's clean MQTT shutdown flushes it; for a reboot the unit's own offline blip is the primary
/// feedback if this last publish doesn't reach the broker before the box goes down (`restore_ssh`, which
/// doesn't restart anything, publishes AFTER it acts so the ack reflects a completed recovery). Best-effort
/// — a publish error is logged. `action` is a fixed internal token (`reboot`/`restart_bridge`/`restore_ssh`)
/// and the ISO timestamp has no JSON-special characters, so the hand-built object needs no escaping.
async fn publish_maintenance(client: &AsyncClient, cfg: &Arc<Config>, action: &str) {
    let payload = format!("{{\"action\":\"{action}\",\"at\":\"{}\"}}", own::utc_now_iso());
    if let Err(e) = client
        .publish(&cfg.topic_maintenance, QoS::AtLeastOnce, true, payload.into_bytes())
        .await
    {
        eprintln!("btmqttd: maintenance: publish to {} failed: {e}", cfg.topic_maintenance);
    }
}

/// Perform the "Restore SSH" recovery (issue #130): (re)start dropbear so sshd is listening on `:22`.
/// Best-effort and idempotent — logs and continues; the module's contract is "never panics".
///
/// Runs `/etc/init.d/dropbear start` (the same command `bt_service_watchdog` uses) but ONLY when the
/// rootfs is mounted READ-ONLY. The factory dropbear init takes its robust host-key path only under a `ro`
/// rootfs; the `rw` path can abort under `set -e` and leave sshd down. btmqttd never remounts, so `ro`
/// normally holds — assert it and log-and-skip rather than risk that path.
///
/// Deliberately does NOT touch the firewall. Every iptables invocation — even a read-only `-C`/`-S` —
/// takes the xtables lock at launch, and this handler fires on an MQTT press that CANNOT be sequenced
/// against the factory firewall's lock-less `INPUT` rebuild on interface-up; an overlap makes the factory's
/// own `-A INPUT` calls fail silently and drop rules (SSH/FTP/security), i.e. it could RECREATE the very
/// lockout it is meant to fix (task #42; see `go2rtc-net-hook`). So the factory `:22` rule stays entirely
/// the shell layer's concern: #129 keeps it intact, and the "Reboot device" button rebuilds the whole
/// factory firewall on boot if it is ever lost. This action's job is strictly to bring dropbear back.
async fn restore_ssh() {
    match tokio::fs::read_to_string("/proc/mounts").await {
        Ok(mounts) if rootfs_is_ro(&mounts) => start_dropbear().await,
        Ok(_) => eprintln!(
            "btmqttd: restore_ssh: rootfs is not mounted read-only; skipping dropbear start to avoid the \
             fragile rw host-key path (never remounting)"
        ),
        Err(e) => eprintln!(
            "btmqttd: restore_ssh: could not read /proc/mounts ({e}); skipping dropbear start to stay safe"
        ),
    }
}

/// Wall-clock cap for the `/etc/init.d/dropbear start` child, so a hung init script can't stall the single
/// command worker or delay the maintenance ack. Generous — a normal start is well under a second.
const DROPBEAR_START_TIMEOUT: Duration = Duration::from_secs(10);

/// Run `/etc/init.d/dropbear start` — the same idempotent command `bt_service_watchdog` uses to bring sshd
/// back (a no-op if dropbear is already listening). Std streams nulled off btmqttd's inherited fds. Spawned
/// in its OWN process group (`process_group(0)`) so a timeout can SIGKILL the WHOLE group — the init script
/// AND anything it spawned — not just the script interpreter, which would otherwise leave a reparented
/// descendant running and let repeated presses pile up stuck processes (Codex; same idiom as
/// `execute_command`). The wait is bounded by [`DROPBEAR_START_TIMEOUT`]; on expiry the group is killed and
/// the direct child handed to the detached, bounded [`reap`] task rather than awaited inline — a child stuck
/// in uninterruptible kernel I/O (D-state) won't return from `wait()` even after SIGKILL until its syscall
/// completes, and awaiting that here would pin the single ordered command worker (and delay the maintenance
/// ack) indefinitely. So a cleanup permit is reserved BEFORE spawning (skip if none free, like
/// `execute_command`): the reaper owns the killed child + permit off-worker, `start_dropbear` returns at
/// once, and the caller publishes the ack immediately. Best-effort — errors are logged, never fatal.
async fn start_dropbear() {
    // Reserve a cleanup permit BEFORE spawning so a child that must be killed can be reaped OFF the command
    // worker without the reaper count growing unbounded — same discipline as `execute_command`. If none is
    // free (that many children still outstanding, e.g. an earlier kill stuck in D-state) skip rather than
    // spawn a child we couldn't hand off; `bt_service_watchdog` still brings dropbear back within 60s.
    let permit = match REAP_SLOTS.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            eprintln!(
                "btmqttd: restore_ssh: too many outstanding children; skipping dropbear start (watchdog will retry)"
            );
            return;
        }
    };
    let mut child = match tokio::process::Command::new("/etc/init.d/dropbear")
        .arg("start")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0) // pgid == the script's pid, so a timeout can kill the whole group
        .kill_on_drop(true)
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!("btmqttd: restore_ssh: failed to run /etc/init.d/dropbear start: {e}");
            drop(permit); // nothing spawned — release the reserved slot
            return;
        }
    };
    match tokio::time::timeout(DROPBEAR_START_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) if status.success() => {
            eprintln!("btmqttd: restore_ssh: dropbear start ok");
            drop(child);
            drop(permit); // clean exit: child already reaped by child.wait() — release the slot
        }
        Ok(Ok(status)) => {
            eprintln!("btmqttd: restore_ssh: dropbear start exited {status}");
            drop(child);
            drop(permit);
        }
        Ok(Err(e)) => {
            eprintln!("btmqttd: restore_ssh: waiting on dropbear start failed: {e}");
            drop(child);
            drop(permit);
        }
        Err(_) => {
            eprintln!(
                "btmqttd: restore_ssh: dropbear start did not finish within {}s; killing its process group",
                DROPBEAR_START_TIMEOUT.as_secs()
            );
            // SIGKILL the whole process GROUP (pgid == the script's pid, set via process_group(0)), so any
            // descendant the init script spawned dies too — not just the script interpreter. ESRCH means the
            // group is already gone (benign); any OTHER error → fall back to the direct child so nothing
            // lingers.
            match child.id() {
                Some(pid) => {
                    let rc = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
                    if rc != 0 {
                        let err = std::io::Error::last_os_error();
                        if err.raw_os_error() != Some(libc::ESRCH) {
                            eprintln!(
                                "btmqttd: restore_ssh: killpg({pid}) failed: {err}; killing the script directly"
                            );
                            let _ = child.start_kill();
                        }
                    }
                }
                None => {
                    let _ = child.start_kill();
                }
            }
            // Hand the killed child + its permit to the detached bounded reaper instead of awaiting here: a
            // D-state child won't return from wait() until its syscall completes, and awaiting inline would
            // pin the single command worker. The reaper collects it off-worker and releases the slot then;
            // init reaps the group's reparented descendants.
            reap(child, permit);
        }
    }
}

/// Does `/proc/mounts` show the root filesystem (`/`) mounted READ-ONLY? Each line is
/// `dev mountpoint fstype options …`; the options are the 4th field, a comma list whose first element is
/// `ro` or `rw`. When several mounts share `/` (a later one shadows earlier ones) the LAST `/` entry is the
/// effective mount, so this checks that one. A missing `/` entry (never, in practice) reads as NOT ro
/// (conservative — the caller then skips the dropbear start). Pure (no I/O) so it is unit-tested directly.
fn rootfs_is_ro(mounts: &str) -> bool {
    mounts
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let _dev = fields.next()?;
            let mountpoint = fields.next()?;
            let _fstype = fields.next()?;
            let options = fields.next()?;
            (mountpoint == "/").then_some(options)
        })
        .next_back()
        .map(|options| options.split(',').any(|opt| opt == "ro"))
        .unwrap_or(false)
}

/// The IN-MEMORY half of the reboot bound (the `/proc` half is [`reboot_process_running`]; both are read
/// together via [`reboot_in_progress`]). Latched while THIS daemon owns a reboot attempt — from accepting
/// the "Reboot device" press until the `reboot` process is OBSERVED to have exited (or its launch is known
/// to have failed). While set it bounds the reboot path to ONE outstanding process, so repeated presses or
/// an automation can't spawn a pile of `reboot` processes and exhaust the process table; it also makes
/// `restart_bridge` stand down (a re-exec would cancel the exit-observer below). It is released by
/// [`spawn_reboot`]'s observer once that process is gone — so a still-running/hung `reboot` keeps the bound,
/// while an exited/failed one re-enables the button. A FRESH process — after a real reboot, or a `restart_bridge`
/// re-exec — starts with this reset, so the button works again afterward.
static REBOOT_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Whether a reboot attempt is currently OUTSTANDING. TRUE when THIS daemon owns a reboot (the in-memory
/// gate), OR when a `reboot` process is live anywhere on the system ([`reboot_process_running`]) — even one
/// this daemon never launched. The reboot accept path refuses while this holds, and the main loop consults
/// it before a bridge re-exec: EVERY restart producer — the "Restart bridge" button AND a newly-learned
/// light WHERE — funnels through one `restart.notified()` arm, and re-execing there would drop the runtime
/// and cancel [`spawn_reboot`]'s exit-observer, stranding a hung reboot and resetting the in-memory gate in
/// the fresh image. Guarding that single choke point covers both producers.
///
/// The `/proc` half is what makes the one-reboot bound survive a PROCESS BOUNDARY. The in-memory gate is
/// reset by anything that starts a fresh daemon — a re-exec, a plain exit + watchdog respawn, the next boot
/// — so on its own it can't stop a fresh daemon from launching a SECOND `reboot` while a prior, genuinely
/// hung one still runs; repeated restart→reboot cycles could then pile up hung processes. Deriving
/// the bound from real kernel state instead — a `reboot` this daemon can't see in memory it can still see
/// in `/proc` — holds the bound across every such boundary, and it self-clears with no lockout: once the
/// `reboot` process is gone (the box rebooted, or it exited), `/proc` is clear and the button works again.
pub(crate) async fn reboot_in_progress() -> bool {
    // Short-circuit on the in-memory gate so the common "this daemon owns the reboot" case skips the scan.
    REBOOT_REQUESTED.load(Ordering::Relaxed) || reboot_process_running().await
}

/// Scan `/proc` for a LIVE `reboot` process — a system-wide, restart-surviving view of whether a reboot is
/// still outstanding (see [`reboot_in_progress`]). Uses async `tokio::fs` (not blocking `std::fs`) so a
/// slow procfs read never stalls the single-threaded runtime, consistent with `hold.rs`/`sprop.rs`. A
/// per-entry read error SKIPS that entry and keeps scanning rather than aborting the whole enumeration —
/// the standard `/proc`-walk contract (`pgrep`/`procps` do the same), so one unreadable entry can't
/// false-negative and let a second reboot slip past the bound. Only genuine
/// exhaustion (`Ok(None)`) ends the scan; a small cap on consecutive errors guards against a pathological
/// directory stream that only ever errors. Best-effort throughout: an unreadable `/proc` (never, in
/// practice, for a root daemon) or a stat file that vanishes mid-scan (the process exited) doesn't match.
async fn reboot_process_running() -> bool {
    let Ok(mut entries) = tokio::fs::read_dir("/proc").await else {
        return false;
    };
    // `readdir` advances past an errored entry, so continuing is progress; the cap only backstops a stream
    // that returns nothing but errors forever (which would otherwise spin) — /proc has a few hundred entries.
    let mut errors = 0u32;
    loop {
        match entries.next_entry().await {
            Ok(Some(entry)) => {
                errors = 0; // a successful step ⇒ the stream is progressing; cap only CONSECUTIVE errors
                let name = entry.file_name();
                // Only numeric entries are process directories; skip `self`, `net`, etc.
                let Some(name) = name.to_str() else { continue };
                if name.is_empty() || !name.bytes().all(|b| b.is_ascii_digit()) {
                    continue;
                }
                if let Ok(stat) = tokio::fs::read_to_string(format!("/proc/{name}/stat")).await {
                    if stat_names_a_live_reboot(&stat) {
                        return true;
                    }
                }
            }
            Ok(None) => return false, // enumerated every entry — no live reboot found
            Err(_) => {
                errors += 1;
                if errors > 4096 {
                    return false;
                }
            }
        }
    }
}

/// Does one `/proc/<pid>/stat` line name a LIVE `reboot` process? The format is `pid (comm) state …`; the
/// comm can itself contain spaces or parentheses, so it is delimited by the FIRST `(` and the LAST `)`,
/// with the single-character run-state next. A zombie/dead reboot (`Z`, or dead `X`/`x` — some kernels
/// report `TASK_DEAD` lowercase) has already exited and will never reboot anything, so it does NOT count as
/// outstanding — counting it would wedge the button on a defunct entry until the box actually rebooted.
/// Pure (no I/O) so the parsing is unit-tested directly.
fn stat_names_a_live_reboot(stat: &str) -> bool {
    let (Some(open), Some(close)) = (stat.find('('), stat.rfind(')')) else {
        return false;
    };
    if open >= close || &stat[open + 1..close] != "reboot" {
        return false;
    }
    // Run-state is the first non-space character after the closing ')'.
    !matches!(stat[close + 1..].trim_start().chars().next(), Some('Z' | 'X' | 'x') | None)
}

/// Trigger `reboot` for the "Reboot device" maintenance button and OWN the resulting process so the gate
/// tracks its true lifetime. `reboot` is spawned DIRECTLY (no intervening shell), which gives two things a
/// backgrounded shell couldn't: the fork/`exec` handshake reports a launch failure (a missing/unrunnable
/// applet fails `spawn` with `Err`, unlike a `... &` async list that exits 0 before the job's `exec` is
/// known), and we hold the `Child` so we can observe when it exits. Its std streams are
/// nulled off btmqttd's inherited fds; `reboot` resolves via the daemon's inherited PATH (the init script
/// exports `PATH=/sbin:/usr/sbin:/usr/bin:/bin`) and the daemon runs as root.
///
/// The IN-MEMORY gate ([`REBOOT_REQUESTED`], latched by the caller) is released as soon as this side is done
/// observing the child; the `/proc` scan in [`reboot_in_progress`] remains the authoritative check for a
/// still-live reboot, so releasing the in-memory gate never allows a second one while a reboot is running:
///   * `spawn` fails → `exec` never happened, no process exists → clear the gate, allow a retry;
///   * the process EXITS (reaped by the observer, so no zombie) → clear the gate. On this target `reboot`
///     signals init and exits promptly whether or not the machine then goes down, so a normal exit is NOT
///     a failure — only a non-success status is logged; either way the process is gone;
///   * `wait()` itself ERRORS → clear the gate too, rather than latching both buttons off for the daemon's
///     lifetime if the error came after the child exited; a genuinely-live reboot is still caught by the
///     `/proc` scan;
///   * the process never exits (a truly hung `reboot`) → the observer stays pending, but the `/proc` scan
///     sees the live process, so the one-reboot bound holds anyway; `restart_bridge` stands down meanwhile
///     so no re-exec can cancel the observer and strand it. A fresh daemon starts reset regardless.
///
/// The observer runs as a detached task (not on the single ordered command worker) so a hung `reboot` never
/// stalls the worker; because `restart_bridge` refuses while the gate is latched, the observer can only be
/// dropped by a re-exec AFTER it has already cleared the gate — i.e. once there is no child left to strand.
/// Best-effort — a spawn failure is logged rather than panicking; the module's contract is "never panics".
fn spawn_reboot() {
    let child = match tokio::process::Command::new("reboot")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            // `exec` never happened, so no reboot process exists — release the gate for a retry.
            eprintln!("btmqttd: reboot: failed to spawn reboot: {e}");
            REBOOT_REQUESTED.store(false, Ordering::Relaxed);
            return;
        }
    };
    // Observe the reboot process off-worker: reap it (no zombie), then release the IN-MEMORY gate once
    // `wait()` returns — whether it reports the exit status or errors trying to. Releasing even on a
    // `wait()` error is safe (and avoids latching both buttons off for the daemon's lifetime if `wait()`
    // failed after the child already exited): the `/proc` scan in `reboot_in_progress` is the
    // AUTHORITATIVE "is a reboot still running" check, so a still-live reboot keeps the bound regardless of
    // the in-memory gate, and a departed one lets the button recover.
    tokio::spawn(async move {
        let mut child = child;
        match child.wait().await {
            // Exited — the process is gone. A non-success status means it could not initiate the reboot
            // (a success just means it signalled init and returned).
            Ok(status) if status.success() => {}
            Ok(status) => {
                eprintln!("btmqttd: reboot: reboot exited {status} without rebooting; re-enabling the button")
            }
            // Couldn't observe the exit; the `/proc` scan still gates a genuinely-live reboot.
            Err(e) => eprintln!("btmqttd: reboot: waiting on reboot failed: {e}; re-enabling the button"),
        }
        REBOOT_REQUESTED.store(false, Ordering::Relaxed);
    });
}

/// Handle an ungated device-control action (issue #40 volume, #41 lock). `v` is the
/// already-parsed action object; `action` is its `action` field. Unknown actions are
/// logged and ignored. A volume op that fails (gateway refused/unreachable) is logged;
/// the retained state stays whatever the monitor last observed, so HA is never left
/// showing a value the device didn't accept.
/// A parsed device-control action — the PURE classification of a JSON action object,
/// separated from the async dispatch so it can be unit-tested without a live gateway or
/// broker. Values are already validated/normalised (volume clamped/rounded, step
/// reduced to a direction).
#[derive(Debug, PartialEq, Eq)]
enum Action {
    /// Absolute volume set, `0..=100` — the slider `number`.
    Volume(u8),
    /// Mute (`true`) / unmute (`false`) — the mute `switch`.
    Mute(bool),
    /// Relative step: up (`true`) / down (`false`) — the ± `button`s. Only the SIGN of
    /// the JSON value matters (the step size is owned device-side).
    Step(bool),
    /// Momentary door-entry lock pulse (issue #41) — the Main/Secondary Lock `button`s.
    /// The variant carries WHICH actuator so one queue/task serialises both.
    Lock(Lock),
    /// Stair-light SWITCH desired state — `on` (`true`) / `off` (`false`). The daemon
    /// toggles the actuator only when the tracked state differs (see `light.rs`). Bistable only.
    Light(bool),
    /// Stair-light PRESS (momentary install): forward the actuator frame once to turn ON — the
    /// physical staircase timer switches it off. No state (see `light.rs`).
    LightPress,
    /// Stair-light RESYNC button: correct the tracked state (unknown→on→off→on) WITHOUT
    /// actuating the relay — realigns HA to the wall after a cold boot / missed press.
    LightResync,
    /// Stair-light LEARN button: open the capture window so the next physical press teaches
    /// the actuator WHERE (for a unit that shipped without a known WHERE).
    LightLearn,
}

/// Classify a JSON action object (`{"action":<name>,"value":…}`) into an [`Action`], or
/// `None` when the action name is unknown or its value is missing/invalid. Pure — the
/// async dispatch (device write / lock enqueue) lives in [`handle_action`].
fn parse_action(action: &str, v: &Value) -> Option<Action> {
    match action {
        "volume" => v.get("value").and_then(json_percent).map(Action::Volume),
        "mute" => match v.get("value").and_then(Value::as_str) {
            Some("on") => Some(Action::Mute(true)),
            Some("off") => Some(Action::Mute(false)),
            _ => None,
        },
        "volume_step" => match v.get("value").and_then(Value::as_i64) {
            Some(d) if d > 0 => Some(Action::Step(true)),
            Some(d) if d < 0 => Some(Action::Step(false)),
            _ => None,
        },
        "main_lock" => Some(Action::Lock(Lock::Main)),
        "secondary_lock" => Some(Action::Lock(Lock::Secondary)),
        "light" => match v.get("value").and_then(Value::as_str) {
            Some("on") => Some(Action::Light(true)),
            Some("off") => Some(Action::Light(false)),
            _ => None,
        },
        // Stateless BUTTON presses — no "value" field.
        "light_press" => Some(Action::LightPress),
        "light_resync" => Some(Action::LightResync),
        "light_learn" => Some(Action::LightLearn),
        _ => None,
    }
}

async fn handle_action(
    vol: &Arc<VolumeCtl>,
    lock: &Sender<Lock>,
    light: Option<&Arc<LightCtl>>,
    action: &str,
    v: &Value,
) {
    match parse_action(action, v) {
        Some(Action::Volume(n)) => log_action_err("volume", vol.set(n).await),
        Some(Action::Mute(on)) => log_action_err("mute", vol.mute(on).await),
        Some(Action::Step(up)) => log_action_err("volume_step", vol.step(up).await),
        // Enqueue a pulse request (WHICH lock) to the dedicated lock task (lock.rs),
        // which serialises press→hold→release off the command worker and is drained on
        // shutdown so the release always follows. Full => a burst faster than it can
        // pulse (drop, don't block the worker); Closed => the task is gone (shutting down).
        Some(Action::Lock(which)) => match lock.try_send(which) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                eprintln!("btmqttd: lock press dropped — pulse queue full");
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
        },
        // Stair-light SWITCH: set the desired absolute state. The controller toggles the
        // actuator only when the tracked state differs (no-op when already there). Ignored
        // if the feature is off (no WHERE configured) — the action shouldn't arrive then,
        // as the installer omits the entity, but stay defensive.
        Some(Action::Light(on)) => match light {
            Some(l) => l.command(on).await,
            None => eprintln!("btmqttd: ignored 'light' action — light feature not configured"),
        },
        // Momentary press: forward one ON pulse; the installation's timer owns the off.
        Some(Action::LightPress) => match light {
            Some(l) => l.press().await,
            None => eprintln!("btmqttd: ignored 'light_press' — light feature not configured"),
        },
        // Resync: correct the tracked state only (no relay actuation). Learn: open the WHERE
        // capture window. Both no-op when the light feature is off.
        Some(Action::LightResync) => match light {
            Some(l) => l.resync().await,
            None => eprintln!("btmqttd: ignored 'light_resync' — light feature not configured"),
        },
        Some(Action::LightLearn) => match light {
            Some(l) => l.learn().await,
            None => eprintln!("btmqttd: ignored 'light_learn' — light feature not configured"),
        },
        None => eprintln!(
            "btmqttd: ignored action {action:?} (unknown, or missing/invalid value {:?})",
            v.get("value")
        ),
    }
}

/// Parse a volume percent (0..=100) from a JSON number. Accepts an integer OR a
/// float: the installer's slider `command_template` renders `{{ value | int }}` (an
/// integer), but Home Assistant `number` entities carry the value as a float and
/// another publisher (or a hand-crafted payload) could still send `50.0`, so a float
/// is accepted DEFENSIVELY — rounded to the nearest integer. Both forms are clamped
/// to 0..=100. Returns `None` for a non-number or a non-finite float (NaN/∞).
fn json_percent(v: &Value) -> Option<u8> {
    if let Some(n) = v.as_u64() {
        return Some(n.min(100) as u8);
    }
    let f = v.as_f64()?;
    if !f.is_finite() {
        return None;
    }
    Some(f.round().clamp(0.0, 100.0) as u8)
}

/// Log a device-control action's error without aborting the worker (best-effort, like
/// the rest of the receiver): a failed set/step leaves HA on the last observed state.
fn log_action_err(action: &str, r: std::io::Result<()>) {
    if let Err(e) = r {
        eprintln!("btmqttd: action {action} failed: {e}");
    }
}

async fn read_file(cfg: &Arc<Config>, client: &AsyncClient, path: &str) {
    if path.is_empty() {
        eprintln!("btmqttd: read_file: missing file_path");
        return;
    }
    // Read at most CAP bytes — `.take(CAP)` bounds BOTH the MQTT payload and the RAM
    // used, so a huge or /proc-style file can't balloon memory (unlike reading the
    // whole file then truncating). Mirrors `head -c 262144`.
    let content = match tokio::fs::File::open(path).await {
        Ok(f) => {
            let mut buf = Vec::new();
            let mut capped = f.take(CAP as u64);
            if let Err(e) = capped.read_to_end(&mut buf).await {
                eprintln!("btmqttd: read_file {path}: {e}");
            }
            buf
        }
        Err(e) => {
            eprintln!("btmqttd: read_file {path}: {e}");
            Vec::new()
        }
    };
    publish(client, &cfg.topic_file_content, content, false).await;
}

async fn write_file(path: &str, data: &str) {
    if path.is_empty() {
        eprintln!("btmqttd: write_file: missing file_path");
        return;
    }
    let path = path.to_string();
    let bytes = data.as_bytes()[..data.len().min(CAP)].to_vec();
    // Do ALL the filesystem work on the blocking pool: open/chmod/chown/rename are
    // synchronous syscalls that would otherwise stall the single-threaded runtime
    // (delaying MQTT keepalives and other tasks).
    match tokio::task::spawn_blocking(move || write_file_blocking(&path, &bytes)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => eprintln!("btmqttd: write_file: {e}"),
        // JoinError is either a panic or a cancellation/abort; either way the write
        // didn't complete. Report it generically rather than asserting "panicked".
        Err(e) => eprintln!("btmqttd: write_file task did not complete: {e}"),
    }
}

/// Synchronous write-then-rename (runs on the blocking pool). Writes to a UNIQUE
/// 0600 temp in the same directory (O_EXCL, so concurrent write_file tasks for the
/// same path never share/clobber a temp inode), matches the existing file's
/// mode/owner (best-effort), then atomically renames over the target.
fn write_file_blocking(path: &str, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = create_unique_temp(path, bytes)?;
    preserve_mode_owner(path, &tmp);
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Create a fresh 0600 temp file (O_EXCL) beside `path` and write `bytes`, retrying
/// on the vanishingly unlikely name collision. Returns the temp path. Synchronous —
/// called only from the blocking pool (write_file_blocking, and rediscovery's hosts
/// rewrite).
pub(crate) fn create_unique_temp(path: &str, bytes: &[u8]) -> std::io::Result<String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let pid = std::process::id();
    for _ in 0..8 {
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let tmp = format!("{path}.tmp.{pid}.{seq}");
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true) // O_EXCL: never reuse another writer's temp
            .mode(0o600)
            .open(&tmp)
        {
            Ok(mut f) => {
                // Write + flush + fsync BEFORE the caller renames over the target, so a crash
                // right after the rename can't leave the new name pointing at unwritten/zeroed
                // data (CodeRabbit). A no-op on tmpfs (the hosts rewrite), a durability
                // guarantee on the persistent cfg partition. On ANY failure, remove the temp
                // before returning so repeated retries can't accumulate .tmp files and fill
                // the partition (CodeRabbit).
                let write = (|| -> std::io::Result<()> {
                    f.write_all(bytes)?;
                    f.flush()?;
                    f.sync_all()
                })();
                if let Err(e) = write {
                    drop(f);
                    let _ = std::fs::remove_file(&tmp);
                    return Err(e);
                }
                return Ok(tmp);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not create a unique temp file",
    ))
}

/// Best-effort: copy the existing target's mode and owner/group onto `tmp` so a
/// replace preserves them (as the shell's stat + chmod/chown did). Silent on error.
pub(crate) fn preserve_mode_owner(target: &str, tmp: &str) {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(target) {
        let _ = std::fs::set_permissions(tmp, std::fs::Permissions::from_mode(meta.mode() & 0o7777));
        // chown via libc (std has no owner setter). Best-effort; ignore failure.
        if let Ok(ctmp) = std::ffi::CString::new(tmp) {
            unsafe {
                libc::chown(ctmp.as_ptr(), meta.uid(), meta.gid());
            }
        }
    }
}

async fn execute_command(cfg: &Arc<Config>, client: &AsyncClient, data: &str) {
    // Run `sh -c "$data"` — the gated remote-command channel's whole purpose is to
    // run operator-supplied shell (identical to StartMqttReceive's `sh -c "$data"`),
    // reachable only when remote_shell_allowed() already held. stdin from /dev/null
    // so a command reading stdin can't swallow later work. Bound BOTH memory (stop at
    // CAP TOTAL bytes) and time (kill after EXEC_TIMEOUT), then reap the child.
    //
    // Reserve a cleanup permit BEFORE spawning, so the number of command children that
    // are running-or-awaiting-reap is HARD-bounded by REAP_CONCURRENCY. If none is free
    // (that many children still outstanding — e.g. earlier kills stuck in D-state), we
    // REJECT this command rather than spawn a shell we couldn't explicitly own and reap.
    // The single ordered worker means at most one child is actually running at a time;
    // the rest of the budget covers killed children still being awaited.
    let permit = match REAP_SLOTS.try_acquire() {
        Ok(p) => p,
        Err(_) => {
            let msg =
                b"btmqttd: execute_command rejected: too many outstanding command children".to_vec();
            publish(client, &cfg.topic_cmd_result, msg, false).await;
            return;
        }
    };
    use std::process::Stdio;
    let mut child = match tokio::process::Command::new("sh")
        .arg("-c")
        .arg(data)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Put the shell in its OWN process group (pgid == its pid). On timeout/CAP we
        // SIGKILL the whole group, not just the shell PID — otherwise a command like
        // `sleep 300; echo done` or a pipeline leaves grandchildren running (reparented
        // to init) after we publish the result, defeating the wall-clock/CAP bound and
        // leaking processes on repeated timeouts.
        .process_group(0)
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("btmqttd: execute_command failed to spawn: {e}");
            publish(client, &cfg.topic_cmd_result, msg.into_bytes(), false).await;
            return;
        }
    };
    // stdout/stderr are Some by construction (Stdio::piped() above), but handle None
    // gracefully rather than panicking — the module's contract is "never panics".
    let (Some(mut out), Some(mut err)) = (child.stdout.take(), child.stderr.take()) else {
        eprintln!("btmqttd: execute_command: child stdout/stderr pipe missing");
        let _ = child.start_kill();
        reap(child, permit); // reaper owns the child + its permit until reaped
        return;
    };

    // Read stdout+stderr CONCURRENTLY and stop the moment we have CAP bytes TOTAL —
    // like the shell's `... 2>&1 | head -c 262144` in the ONE sense that matters here:
    // a single combined diagnostic blob capped at CAP total bytes. We do NOT reproduce
    // the shell's exact merged-stream byte order — reading two separate pipes
    // interleaves by ARRIVAL order (arguably closer to real time than a buffered pipe),
    // and a command that writes to both streams may see them interleaved differently.
    // That's fine: the result is an opaque diagnostic blob, not a stream whose
    // stdout/stderr ordering is contractual. Reading each to its own CAP with
    // join! would instead WAIT for the second stream even after the first is full:
    // a command that writes >CAP to stdout and keeps running blocks on the (now
    // unread) full stdout pipe and never closes stderr, so join! would hang until the
    // timeout and drop the output we already had. Exiting at CAP total (then killing
    // the child below) returns the first 256 KB promptly instead.
    // One future for the WHOLE lifecycle — read up to CAP total, and (only when both
    // streams close before the cap) WAIT for the process to finish its side-effecting
    // work — under a SINGLE EXEC_TIMEOUT deadline. Doing the wait inside this future
    // (rather than a second timeout after it) keeps the total wall-clock at one
    // EXEC_TIMEOUT and the FIFO command worker isn't held for ~2x that. Returns
    // (bytes, hit_cap).
    let run = async {
        let mut buf: Vec<u8> = Vec::new();
        let mut ob = [0u8; 8192];
        let mut eb = [0u8; 8192];
        let mut out_open = true;
        let mut err_open = true;
        while buf.len() < CAP && (out_open || err_open) {
            tokio::select! {
                r = out.read(&mut ob), if out_open => match r {
                    Ok(0) | Err(_) => out_open = false,
                    Ok(n) => {
                        let take = (CAP - buf.len()).min(n);
                        buf.extend_from_slice(&ob[..take]);
                    }
                },
                r = err.read(&mut eb), if err_open => match r {
                    Ok(0) | Err(_) => err_open = false,
                    Ok(n) => {
                        let take = (CAP - buf.len()).min(n);
                        buf.extend_from_slice(&eb[..take]);
                    }
                },
            }
        }
        let capped = buf.len() >= CAP;
        // Clean EOF before the cap: the command may have redirected/closed its output
        // early yet still be doing work (e.g. `exec >/dev/null 2>&1; sleep 5; touch …`)
        // — let it finish rather than killing it (matches the shell). Bounded by the
        // shared timeout wrapping this whole future.
        if !capped {
            let _ = child.wait().await;
        }
        (buf, capped)
    };

    let (mut result, capped_or_timeout) = match tokio::time::timeout(EXEC_TIMEOUT, run).await {
        Ok((buf, capped)) => (buf, capped),
        // Timed out (slow producer, or a quiet command running past the deadline).
        Err(_) => (b"btmqttd: execute_command timed out".to_vec(), true),
    };
    // Kill only when we stopped at the cap or hit the timeout; on a clean finish the
    // child already exited (and was reaped by child.wait) inside `run`.
    if capped_or_timeout {
        // SIGKILL the whole process GROUP (pgid == the shell's pid, set via
        // process_group(0) at spawn), so any children/pipeline the shell spawned die
        // too — not just the shell.
        match child.id() {
            Some(pid) => {
                let rc = unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
                if rc != 0 {
                    let err = std::io::Error::last_os_error();
                    // ESRCH just means the group is already gone (the shell and its
                    // children exited on their own) — benign; reap() collects the
                    // zombie. Any OTHER error (e.g. EPERM) means the group may still be
                    // alive, so fall back to killing the direct child, otherwise it (and
                    // its REAP_SLOTS permit) could linger and stall further commands.
                    if err.raw_os_error() != Some(libc::ESRCH) {
                        eprintln!("btmqttd: killpg({pid}) failed: {err}; killing the shell directly");
                        let _ = child.start_kill();
                    }
                }
            }
            None => {
                let _ = child.start_kill();
            }
        }
        // Hand the killed child + its permit to the bounded reaper, which awaits it to
        // completion (explicit, not tokio's best-effort drop-time cleanup) and releases
        // the permit only once collected — so the slot stays reserved while the child
        // is still outstanding.
        reap(child, permit);
    } else {
        // Clean finish: the child already exited and was reaped by child.wait inside
        // `run`. No reaper task needed — just release the permit.
        drop(child);
        drop(permit);
    }
    result.truncate(CAP);
    publish(client, &cfg.topic_cmd_result, result, false).await;
}

/// Reap a killed command child, awaiting it to completion in a short-lived task that
/// carries the caller's cleanup `permit`. The permit was reserved (in execute_command)
/// BEFORE the shell was spawned, so the count of command children that are
/// running-or-awaiting-reap is hard-bounded by REAP_CONCURRENCY: the daemon never
/// spawns a child it can't explicitly own, and never falls back to tokio's
/// non-guaranteed best-effort drop-time cleanup. The permit is released when the wait
/// resolves — a normally-exiting or freshly-SIGKILLed child is collected at once.
///
/// A truly D-stuck process (uninterruptible kernel I/O) holds its process-table slot
/// until the kernel releases it no matter how it's waited; while stuck, its permit
/// stays taken, so further execute_command requests are REJECTED up-front — that is
/// the bound. (This channel is a gated, authenticated `sh -c` surface, so the bound is
/// about the daemon's own resources, not a defense against an operator who can already
/// run any command.)
fn reap(child: tokio::process::Child, permit: tokio::sync::SemaphorePermit<'static>) {
    tokio::spawn(async move {
        let _permit = permit; // released once the wait resolves
        let mut child = child;
        let _ = child.wait().await;
    });
}

async fn publish(client: &AsyncClient, topic: &str, payload: Vec<u8>, retain: bool) {
    // QoS 0 — the shell bridge's `mosquitto_pub` default for these diagnostic
    // replies (command result / file content); the command SUBSCRIPTION is the only
    // QoS-1 path.
    if let Err(e) = client.publish(topic, QoS::AtMostOnce, retain, payload).await {
        eprintln!("btmqttd: publish to {topic} failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The per-record classification dispatch_record() applies: a record is forwarded
    /// to the gateway as an OWN frame only when it is non-blank AND is_own_frame().
    /// Otherwise it goes to the (gated / possibly-ignored) JSON path. Encodes the
    /// shell parity boundary without needing the network.
    fn is_frame(record: &str) -> bool {
        !record.trim().is_empty() && own::is_own_frame(record)
    }

    /// Mirror dispatch()'s payload → records split so tests can assert per-line
    /// behaviour (the shell's `while IFS= read -r` loop).
    fn records(payload: &str) -> Vec<&str> {
        payload.split('\n').collect()
    }

    #[test]
    fn json_percent_accepts_int_and_float_clamped_and_rounded() {
        use serde_json::json;
        // Integer values pass through, clamped to 0..=100.
        assert_eq!(json_percent(&json!(0)), Some(0));
        assert_eq!(json_percent(&json!(50)), Some(50));
        assert_eq!(json_percent(&json!(100)), Some(100));
        assert_eq!(json_percent(&json!(150)), Some(100)); // clamp
        // Floats (what an HA `number` slider renders via `{{ value }}`) are rounded.
        assert_eq!(json_percent(&json!(50.0)), Some(50));
        assert_eq!(json_percent(&json!(49.6)), Some(50)); // round to nearest
        assert_eq!(json_percent(&json!(120.0)), Some(100)); // clamp after round
        assert_eq!(json_percent(&json!(-5.0)), Some(0)); // clamp low
        // Non-numbers / non-finite are rejected (fall to the invalid-value path).
        assert_eq!(json_percent(&json!("50")), None);
        assert_eq!(json_percent(&json!(null)), None);
    }

    #[test]
    fn parse_action_classifies_the_control_surface() {
        use serde_json::json;
        // volume: int or float, clamped/rounded (via json_percent).
        assert_eq!(parse_action("volume", &json!({"value": 50})), Some(Action::Volume(50)));
        assert_eq!(parse_action("volume", &json!({"value": 49.6})), Some(Action::Volume(50)));
        assert_eq!(parse_action("volume", &json!({"value": 150})), Some(Action::Volume(100)));
        // mute: only "on"/"off".
        assert_eq!(parse_action("mute", &json!({"value": "on"})), Some(Action::Mute(true)));
        assert_eq!(parse_action("mute", &json!({"value": "off"})), Some(Action::Mute(false)));
        // volume_step: only the SIGN matters.
        assert_eq!(parse_action("volume_step", &json!({"value": 10})), Some(Action::Step(true)));
        assert_eq!(parse_action("volume_step", &json!({"value": -10})), Some(Action::Step(false)));
        assert_eq!(parse_action("volume_step", &json!({"value": -1})), Some(Action::Step(false)));
        // locks: no value needed; each name maps to its actuator.
        assert_eq!(parse_action("main_lock", &json!({})), Some(Action::Lock(Lock::Main)));
        assert_eq!(
            parse_action("main_lock", &json!({"value": "ignored"})),
            Some(Action::Lock(Lock::Main))
        );
        assert_eq!(
            parse_action("secondary_lock", &json!({})),
            Some(Action::Lock(Lock::Secondary))
        );
        // light: on/off only.
        assert_eq!(parse_action("light", &json!({"value": "on"})), Some(Action::Light(true)));
        assert_eq!(parse_action("light", &json!({"value": "off"})), Some(Action::Light(false)));
        // light stateless buttons: press (momentary), resync, learn — no "value" field.
        assert_eq!(parse_action("light_press", &json!({})), Some(Action::LightPress));
        assert_eq!(parse_action("light_resync", &json!({})), Some(Action::LightResync));
        assert_eq!(parse_action("light_learn", &json!({})), Some(Action::LightLearn));
    }

    #[test]
    fn parse_action_rejects_unknown_and_invalid() {
        use serde_json::json;
        // Unknown action name.
        assert_eq!(parse_action("nope", &json!({"value": 1})), None);
        assert_eq!(parse_action("", &json!({})), None);
        // volume: missing / non-numeric / non-finite value.
        assert_eq!(parse_action("volume", &json!({})), None);
        assert_eq!(parse_action("volume", &json!({"value": "x"})), None);
        // mute: value other than on/off.
        assert_eq!(parse_action("mute", &json!({"value": "maybe"})), None);
        assert_eq!(parse_action("mute", &json!({"value": 1})), None);
        // volume_step: zero (no direction) / missing / non-integer.
        assert_eq!(parse_action("volume_step", &json!({"value": 0})), None);
        assert_eq!(parse_action("volume_step", &json!({})), None);
        assert_eq!(parse_action("volume_step", &json!({"value": "up"})), None);
    }

    #[test]
    fn parse_maintenance_classifies_the_buttons() {
        // The exact action strings the HA discovery payloads publish (issues #43, #130).
        assert_eq!(parse_maintenance("reboot"), Some(Maintenance::Reboot));
        assert_eq!(parse_maintenance("restart_bridge"), Some(Maintenance::RestartBridge));
        assert_eq!(parse_maintenance("restore_ssh"), Some(Maintenance::RestoreSsh));
        // Anything else is not a maintenance action (falls through to handle_action).
        assert_eq!(parse_maintenance(""), None);
        assert_eq!(parse_maintenance("restart"), None); // must be exactly `restart_bridge`
        assert_eq!(parse_maintenance("reboot_device"), None); // the object id, not the action
        assert_eq!(parse_maintenance("ssh"), None); // must be exactly `restore_ssh`
        assert_eq!(parse_maintenance("volume"), None);
    }

    #[test]
    fn rootfs_ro_is_read_from_the_effective_slash_mount() {
        // Real /proc/mounts shape: `dev mountpoint fstype options dump pass`. The `/` mount's options
        // (4th field) are a comma list; `ro`/`rw` is what restore_ssh gates the dropbear start on.
        let ro = "/dev/root / ext4 ro,relatime,errors=continue 0 0\n\
                  proc /proc proc rw,nosuid,nodev,noexec 0 0\n\
                  tmpfs /var/run tmpfs rw,nosuid,nodev 0 0\n";
        assert!(rootfs_is_ro(ro));

        // A read-write rootfs must NOT be treated as ro (the caller then skips the dropbear start).
        let rw = "/dev/root / ext4 rw,relatime 0 0\nproc /proc proc rw 0 0\n";
        assert!(!rootfs_is_ro(rw));

        // Only the `/` mount decides it — a ro `/proc` or ro `/other` must not flip the result.
        assert!(!rootfs_is_ro("/dev/root / ext4 rw 0 0\nproc /proc proc ro 0 0\n"));
        assert!(!rootfs_is_ro("/dev/x /other ext4 ro 0 0\n"));

        // When several mounts share `/`, the LAST (effective, shadowing) one wins.
        assert!(rootfs_is_ro("rootfs / rootfs rw 0 0\n/dev/root / ext4 ro,relatime 0 0\n"));
        assert!(!rootfs_is_ro("rootfs / rootfs ro 0 0\n/dev/root / ext4 rw,relatime 0 0\n"));

        // `rw` must not match on a substring (`ro` is a whole comma-separated option, not a prefix).
        assert!(!rootfs_is_ro("/dev/root / ext4 rw,errors=remount-ro 0 0\n"));

        // Malformed / empty input reads as NOT ro rather than panicking.
        assert!(!rootfs_is_ro(""));
        assert!(!rootfs_is_ro("garbage\n/dev/root /\n"));
    }

    #[test]
    fn stat_matches_a_live_reboot_process() {
        // A running (`S`) `reboot` applet — the system-wide "a reboot is outstanding" signal that survives
        // a re-exec / watchdog respawn (issue #43). Real busybox `/proc/<pid>/stat` shape.
        assert!(stat_names_a_live_reboot("1234 (reboot) S 1 1234 1234 0 -1 4194560 0 0"));
        // Other run-states of a live reboot still count (R running, D uninterruptible).
        assert!(stat_names_a_live_reboot("1234 (reboot) R 1 0 0"));
        assert!(stat_names_a_live_reboot("1234 (reboot) D 1 0 0"));
    }

    #[test]
    fn stat_ignores_zombie_dead_and_other_processes() {
        // A zombie/dead reboot has already exited — it will never reboot anything, so it must NOT wedge
        // the button (otherwise a defunct entry blocks every later reboot until the box actually reboots).
        assert!(!stat_names_a_live_reboot("1234 (reboot) Z 1 0 0"));
        assert!(!stat_names_a_live_reboot("1234 (reboot) X 1 0 0"));
        // Some kernels report a dead task lowercase (`x`); exclude it too, so a dead reboot never counts.
        assert!(!stat_names_a_live_reboot("1234 (reboot) x 1 0 0"));
        // A different process is never a reboot, even one whose name merely contains "reboot".
        assert!(!stat_names_a_live_reboot("1234 (btmqttd) S 1 0 0"));
        assert!(!stat_names_a_live_reboot("1234 (rebooter) S 1 0 0"));
        // A comm containing spaces/parens is delimited by the FIRST '(' and LAST ')', so the state is still
        // read correctly and such a process is not mistaken for `reboot`.
        assert!(!stat_names_a_live_reboot("1234 (weird )(name) S 1 0 0"));
        // Malformed / truncated lines never match rather than panicking.
        assert!(!stat_names_a_live_reboot(""));
        assert!(!stat_names_a_live_reboot("1234 (reboot)"));
        assert!(!stat_names_a_live_reboot("no parens here"));
    }

    #[test]
    fn crlf_frame_is_not_forwarded() {
        // `IFS= read -r` keeps the trailing \r, so `*…##\r` failed `^\*.*##$` and was
        // NOT forwarded. A naive \r/\n trim would have promoted it to a live command.
        assert!(!is_frame("*1*0*12##\r"));
        // A bare-LF (or no) terminator is the record separator the shell consumed —
        // the frame IS recognised.
        assert!(is_frame("*1*0*12##"));
    }

    #[test]
    fn every_line_is_a_record_second_line_forwarded() {
        // The shell looped over EVERY line, so junk on line 1 is ignored and a valid
        // frame on line 2 is still forwarded — btmqttd must not drop the 2nd record.
        let r = records("junk\n*1*0*12##");
        assert_eq!(r.len(), 2);
        assert!(!is_frame(r[0])); // "junk" -> JSON path -> ignored
        assert!(is_frame(r[1])); // frame -> forwarded
    }

    #[test]
    fn crlf_is_preserved_per_record() {
        // A CRLF-separated pair: record 0 keeps its \r (not forwarded), record 1 is a
        // clean LF-terminated frame (forwarded).
        let r = records("*1*0*12##\r\n*2*1*3##");
        assert_eq!(r, vec!["*1*0*12##\r", "*2*1*3##"]);
        assert!(!is_frame(r[0]));
        assert!(is_frame(r[1]));
    }

    #[test]
    fn blank_and_space_prefixed_records_ignored() {
        assert!(!is_frame("")); // empty record
        assert!(!is_frame("   ")); // whitespace-only
        assert!(!is_frame(" *1*0*12##")); // leading space -> JSON path, not a frame
        // A trailing blank record (from a trailing '\n') is ignored, not an error.
        let r = records("*1*0*12##\n");
        assert_eq!(r, vec!["*1*0*12##", ""]);
        assert!(is_frame(r[0]));
        assert!(!is_frame(r[1]));
    }
}
