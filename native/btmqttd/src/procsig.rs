//! Shared, best-effort "find the go2rtc `exec:` ffmpeg producer(s) in `/proc` and SIGTERM them in ONE
//! blocking pass" primitive (issues #146 and #180).
//!
//! go2rtc does NOT restart an `exec:` producer on its own (v1.9.14: "consumers must re-request the
//! stream"), so the way btmqttd nudges a producer to re-open its input is to SIGTERM it: the stream
//! drops, Home Assistant's camera reconnects, and go2rtc runs a FRESH producer that reads the current
//! state. TWO callers need exactly that respawn, differing ONLY in which producer they target:
//!   * [`crate::sprop`] (#146, fix B) respawns the LIVE producer after it patched the runtime SDP, so
//!     the current view re-reads the freshly-learned `sprop-parameter-sets` — a producer whose `-i` is
//!     the runtime SDP.
//!   * [`crate::av`] (#180) respawns whatever producer is running at the instant the siphon arms, so the
//!     wrapper script re-checks the `camera-live` signal and cuts the "Loading camera…" filler over to
//!     the live feed — a producer whose `-i` is EITHER the runtime SDP (already live) OR the filler clip
//!     (`loading.mp4`, cold).
//!
//! Both share the SAME safety-critical shape, which is why it lives here once rather than being copied:
//! the scan, the per-PID identity RE-VALIDATION, and the `kill` all happen in ONE synchronous pass with
//! NO async yield between confirming a PID is our producer and signalling it. That closes the PID-reuse
//! window — a recycled PID would itself have to be a `<ffmpeg> -i <one of our inputs>` child of the
//! go2rtc daemon in that microsecond gap, which is effectively impossible. (The device kernel — Linux
//! 4.9 — predates `pidfd`, the only mechanism that truly cannot follow PID reuse, so re-validation
//! immediately before the kill is the best available.) Every step is best-effort and NON-fatal: an
//! unreadable `/proc` entry is skipped, and finding no producer just means the change takes effect on
//! the producer's next start.

/// The go2rtc daemon path — the parent process of the `exec:` producer we signal
/// (`PayloadBinaries.Go2Rtc.InstallPath` / `go2rtcd`'s `$DAEMON`). go2rtc runs its `exec:` command
/// directly (v1.9.14: `exec.Command`, no shell of its own), so the producer's DIRECT parent IS this
/// daemon. Whether the `exec:` string is a bare `ffmpeg …` (the historical form) or `sh
/// camera-producer.sh {output}` (issue #180) the ffmpeg process still ends up a direct child of go2rtc,
/// because the wrapper `exec`s ffmpeg IN PLACE — replacing the `sh` PID — so its parent stays go2rtc.
pub(crate) const GO2RTC_DAEMON_PATH: &str = "/usr/sbin/go2rtc";

/// SIGTERM every go2rtc `exec:` ffmpeg producer currently reading one of `inputs`, so go2rtc respawns it
/// and it re-reads its input. `inputs` is the set of `-i` paths that identify OUR producer(s): a single
/// runtime-SDP entry for the sprop self-heal, or the runtime SDP + the filler clip for the av cutover.
/// `reason` is woven into the log line so an operator can tell the two callers apart. Best-effort and
/// non-fatal: a missing producer / a failed signal just defers the effect to the next producer start.
/// The `/proc` scan is blocking, so THIS fn offloads it to `spawn_blocking` INTERNALLY — callers just
/// `.await` it (do NOT wrap it again); the scan-validate-SIGTERM stays one synchronous pass in the
/// offloaded [`terminate_go2rtc_producers`] (no async yield between identifying a PID and signalling it).
pub(crate) async fn respawn_go2rtc_producers(
    inputs: &'static [&'static str],
    reason: &'static str,
) {
    // Do the whole scan-validate-signal in ONE blocking pass (no async yield between identifying a
    // producer and SIGTERMing it), so a PID can't be recycled out from under us across an await.
    let signalled = match tokio::task::spawn_blocking(move || {
        terminate_go2rtc_producers(crate::capture::DEFAULT_FFMPEG_BIN, GO2RTC_DAEMON_PATH, inputs, reason)
    })
    .await
    {
        Ok(n) => n,
        // The blocking task panicked. Log the JoinError so a "no respawn happened" report isn't confused
        // with "no producer found"; non-fatal — the change still takes effect on the next open/boot.
        Err(e) => {
            eprintln!("btmqttd: go2rtc producer-respawn task failed ({e}); relying on the next open/boot");
            return;
        }
    };
    if signalled == 0 {
        eprintln!(
            "btmqttd: no running go2rtc exec producer to respawn ({reason}); the change takes effect on its next start"
        );
    }
}

/// Whether ANY go2rtc `exec:` ffmpeg producer reading one of `inputs` is CURRENTLY running — a read-only
/// `/proc` scan with the exact same producer identification as [`terminate_go2rtc_producers`], signalling
/// nothing (issue #180). The av cutover uses it, passing the FILLER-only input, to confirm the "Loading
/// camera…" producer is actually gone before it declares the filler→live switch complete: the SIGTERM
/// respawn is best-effort and could race a producer whose wrapper is still in its transient `/bin/sh` exec
/// phase (not yet the matchable ffmpeg), so re-confirming the filler is gone — rather than trusting the
/// signal — closes that gap. The `/proc` scan is blocking, so THIS fn offloads it to `spawn_blocking`
/// INTERNALLY; callers just `.await` it.
///
/// A scan-task JoinError (panic/cancellation) does NOT map to `false`: that would be indistinguishable
/// from "confirmed no producer", which in the av cutover would wrongly mark the switch complete and DISABLE
/// the retry, stranding the viewer on the filler. It returns the CONSERVATIVE `true` instead — "a producer
/// MAY still be running" — so the cutover treats the switch as not-yet-complete and RETRIES, and logs the
/// failure so a "still not live" isn't mistaken for "none found". (A `scan_any_producer` that merely can't
/// read `/proc` still returns `false` — that is a real, completed scan that found nothing.)
pub(crate) async fn any_producer_running(inputs: &'static [&'static str]) -> bool {
    match tokio::task::spawn_blocking(move || {
        scan_any_producer(crate::capture::DEFAULT_FFMPEG_BIN, GO2RTC_DAEMON_PATH, inputs)
    })
    .await
    {
        Ok(found) => found,
        Err(e) => {
            eprintln!(
                "btmqttd: go2rtc producer scan task failed ({e}); assuming a producer may still be running"
            );
            true
        }
    }
}

/// Scan `/proc` for a go2rtc `exec:` ffmpeg producer reading one of `inputs`, returning whether one exists.
/// Same identification as [`terminate_go2rtc_producers`] ([`pid_is_producer`]) but read-only — it signals
/// nothing. Blocking; an unreadable `/proc` or entry is skipped (best-effort ⇒ `false`).
pub(crate) fn scan_any_producer(ffmpeg_path: &str, daemon_path: &str, inputs: &[&str]) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    entries.flatten().any(|entry| {
        entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<i32>().ok())
            .is_some_and(|pid| pid_is_producer(pid, ffmpeg_path, daemon_path, inputs))
    })
}

/// Scan `/proc` and SIGTERM every go2rtc `exec:` ffmpeg producer whose `-i` input is one of `inputs`,
/// returning how many were signalled. Each PID is VALIDATED and signalled in the SAME loop iteration —
/// identity checked ([`pid_is_producer`]) immediately before `kill`, with no async yield between — so PID
/// reuse between discovery and the signal can't make us terminate an unrelated process (see the module
/// note). Blocking (`read_dir` + per-pid reads); only numeric `/proc/<pid>` entries are considered and
/// any unreadable entry is skipped (best-effort). `reason` only shapes the per-signal log line.
pub(crate) fn terminate_go2rtc_producers(
    ffmpeg_path: &str,
    daemon_path: &str,
    inputs: &[&str],
    reason: &str,
) -> usize {
    let mut signalled = 0usize;
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return 0;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue; // not a numeric pid directory
        };
        if !pid_is_producer(pid, ffmpeg_path, daemon_path, inputs) {
            continue;
        }
        // Validated immediately above; SIGTERM now with no intervening await. SIGTERM lets ffmpeg exit
        // cleanly so go2rtc tears the producer down tidily.
        if unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) } == 0 {
            signalled += 1;
            eprintln!("btmqttd: signalled the go2rtc exec producer (pid {pid}) to {reason}");
        } else {
            // Non-fatal (the change still takes effect on the next open/boot), but log with the errno so a
            // "no respawn" report can be told apart: ESRCH means the producer exited in the gap (already
            // gone — its respawn reads the new state), EPERM a permission problem. Read last_os_error()
            // immediately, before any other syscall.
            eprintln!(
                "btmqttd: could not signal go2rtc exec producer (pid {pid}): {}",
                std::io::Error::last_os_error()
            );
        }
    }
    signalled
}

/// True iff `/proc/<pid>` is CURRENTLY a go2rtc `exec:` ffmpeg producer reading one of `inputs`: its
/// command line is `<ffmpeg_path> … -i <one of inputs> …` ([`cmdline_is_producer`]) AND its direct
/// parent is the go2rtc daemon ([`parent_is`]). Both are read live from `/proc`, so calling this
/// immediately before `kill` re-confirms the identity. Blocking; any unreadable entry ⇒ `false`.
fn pid_is_producer(pid: i32, ffmpeg_path: &str, daemon_path: &str, inputs: &[&str]) -> bool {
    matches!(
        std::fs::read(format!("/proc/{pid}/cmdline")),
        Ok(cmdline) if cmdline_is_producer(&cmdline, ffmpeg_path, inputs)
    ) && parent_is(pid, daemon_path)
}

/// True iff a raw `/proc/<pid>/cmdline` (arguments NUL-separated) is a go2rtc `exec:` ffmpeg producer
/// reading one of OUR inputs: argv[0] is EXACTLY `ffmpeg_path`, AND some `-i` argument is IMMEDIATELY
/// followed by an argument EXACTLY equal to one of `inputs` (the real input pairing). Requiring the
/// ffmpeg executable rejects a `tail`/`cat <input>`; requiring the `-i` adjacency rejects an input path
/// used as an OUTPUT or a positional argument, and the idle/ring capture ffmpeg (whose input is an
/// `rtsp://…/doorbell` URL, not one of these files) — while the EXACT match also rejects a `<input>.bak`
/// lookalike. Pure — no I/O — so it is unit-tested directly.
pub(crate) fn cmdline_is_producer(cmdline: &[u8], ffmpeg_path: &str, inputs: &[&str]) -> bool {
    let mut args = cmdline.split(|&b| b == 0).filter(|a| !a.is_empty());
    if args.next() != Some(ffmpeg_path.as_bytes()) {
        return false; // argv[0] is not the go2rtc exec ffmpeg
    }
    let mut after_i = false;
    for arg in args {
        if after_i && inputs.iter().any(|i| arg == i.as_bytes()) {
            return true; // `-i <one of our inputs>` — the input pairing
        }
        after_i = arg == b"-i";
    }
    false
}

/// True iff `pid`'s DIRECT parent process's executable is `exe_path` — read `PPid:` from
/// `/proc/<pid>/status` ([`parse_ppid`]), then `readlink /proc/<ppid>/exe`. Any read/parse failure ⇒
/// `false`: an unverifiable parent is never signalled. Blocking.
fn parent_is(pid: i32, exe_path: &str) -> bool {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return false;
    };
    let Some(ppid) = parse_ppid(&status) else {
        return false;
    };
    matches!(
        std::fs::read_link(format!("/proc/{ppid}/exe")),
        Ok(p) if p == std::path::Path::new(exe_path)
    )
}

/// Parse the `PPid:` field (the parent PID) out of `/proc/<pid>/status`. Returns `None` if the field is
/// absent or non-numeric. Pure — unit-tested.
pub(crate) fn parse_ppid(status: &str) -> Option<i32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .and_then(|rest| rest.trim().parse::<i32>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The runtime SDP the LIVE producer reads (mirrors `sprop::SDP_PATH` / the go2rtc.yaml exec -i).
    const SDP: &str = "/var/run/btmqttd/doorbell.sdp";
    /// The filler clip the COLD producer reads (mirrors `av::LOADING_CLIP_PATH` /
    /// `Go2RtcConfig.OnDeviceLoadingClipPath` / the wrapper's filler `-i`).
    const CLIP: &str = "/etc/btmqttd/go2rtc/loading.mp4";

    #[test]
    fn cmdline_matches_the_sdp_producer() {
        // The LIVE go2rtc exec producer: `<ffmpeg> … -i <runtime SDP> …` — argv[0] is ffmpeg and the SDP
        // is the argument right after `-i`. Matched whether the caller passes the SDP alone (sprop's
        // self-heal) or the SDP + filler set (av's cutover).
        let ff = crate::capture::DEFAULT_FFMPEG_BIN; // "/usr/sbin/ffmpeg"
        let producer = [
            ff.as_bytes(),
            b"-hide_banner",
            b"-protocol_whitelist",
            b"file,udp,rtp",
            b"-i",
            SDP.as_bytes(),
            b"-an",
            b"-c:v",
            b"copy",
        ]
        .join(&0u8);
        assert!(cmdline_is_producer(&producer, ff, &[SDP]));
        assert!(cmdline_is_producer(&producer, ff, &[SDP, CLIP]));
    }

    #[test]
    fn cmdline_matches_the_filler_producer_only_in_the_cutover_set() {
        // The COLD go2rtc exec producer (issue #180): `<ffmpeg> … -stream_loop -1 -i <loading.mp4> …`.
        // It matches ONLY when the caller includes the filler clip in its input set (av's cutover) — so
        // sprop's SDP-only respawn NEVER disturbs the filler, only the live producer.
        let ff = crate::capture::DEFAULT_FFMPEG_BIN;
        let filler = [
            ff.as_bytes(),
            b"-hide_banner",
            b"-re",
            b"-stream_loop",
            b"-1",
            b"-i",
            CLIP.as_bytes(),
            b"-an",
            b"-c:v",
            b"copy",
        ]
        .join(&0u8);
        assert!(cmdline_is_producer(&filler, ff, &[SDP, CLIP]));
        assert!(!cmdline_is_producer(&filler, ff, &[SDP])); // SDP-only set: filler is left alone
    }

    #[test]
    fn cmdline_rejects_lookalikes_and_non_producers() {
        let ff = crate::capture::DEFAULT_FFMPEG_BIN;
        let inputs: &[&str] = &[SDP, CLIP];

        // The idle/ring capture ffmpeg reads an rtsp:// URL, never one of these FILES — must NOT match.
        let capture = [ff.as_bytes(), b"-rtsp_transport", b"tcp", b"-i", b"rtsp://camera:p@127.0.0.1:8554/doorbell", b"-frames:v", b"1"]
            .join(&0u8);
        assert!(!cmdline_is_producer(&capture, ff, inputs));

        // go2rtc itself takes -config <yaml>, not one of the inputs — must NOT match.
        let go2rtc = [b"/usr/sbin/go2rtc".as_ref(), b"-config", b"/etc/btmqttd/go2rtc/go2rtc.yaml"].join(&0u8);
        assert!(!cmdline_is_producer(&go2rtc, ff, inputs));

        // The wrapper `sh camera-producer.sh {output}` itself: argv[0] is not the ffmpeg executable — must
        // NOT match. (It `exec`s ffmpeg in place, so only the resulting ffmpeg — matched above — is ever
        // a producer; the transient `sh` never is.)
        let wrapper = [b"/bin/sh".as_ref(), b"/etc/btmqttd/go2rtc/camera-producer.sh", b"rtsp://127.0.0.1:8554/doorbell"].join(&0u8);
        assert!(!cmdline_is_producer(&wrapper, ff, inputs));

        // `tail`/`cat <sdp>`: argv[0] is not the ffmpeg executable — must NOT match (an over-broad "any
        // argument equals an input" matcher would have wrongly killed these).
        let tail = [b"/usr/bin/tail".as_ref(), b"-f", SDP.as_bytes()].join(&0u8);
        assert!(!cmdline_is_producer(&tail, ff, inputs));

        // ffmpeg with an input as an OUTPUT / positional argument (not after `-i`) — must NOT match.
        let sdp_as_output = [ff.as_bytes(), b"-i", b"rtsp://x", b"-f", b"sdp", SDP.as_bytes()].join(&0u8);
        assert!(!cmdline_is_producer(&sdp_as_output, ff, inputs));

        // An input present but NOT paired to `-i` — must NOT match.
        let unpaired = [ff.as_bytes(), b"-map_metadata", CLIP.as_bytes(), b"-i", b"rtsp://x"].join(&0u8);
        assert!(!cmdline_is_producer(&unpaired, ff, inputs));

        // A trailing `-i` with no following argument — must NOT match (no input pairing).
        let dangling_i = [ff.as_bytes(), b"-hide_banner", b"-i"].join(&0u8);
        assert!(!cmdline_is_producer(&dangling_i, ff, inputs));

        // An EXACT-argument match, not a substring: a `<input>.bak` lookalike after `-i` must NOT match.
        let sdp_bak = [ff.as_bytes(), b"-i", b"/var/run/btmqttd/doorbell.sdp.bak"].join(&0u8);
        assert!(!cmdline_is_producer(&sdp_bak, ff, inputs));
        let clip_bak = [ff.as_bytes(), b"-i", b"/etc/btmqttd/go2rtc/loading.mp4.bak"].join(&0u8);
        assert!(!cmdline_is_producer(&clip_bak, ff, inputs));

        // Empty cmdline (e.g. a kernel thread) never matches.
        assert!(!cmdline_is_producer(&[], ff, inputs));
    }

    // NB: `scan_any_producer` (the read-only /proc walk) has no host-/proc test of its own — an assertion
    // over the live `/proc` would depend on ambient host processes (it could flake if a machine happened to
    // run a `/usr/sbin/go2rtc` parent with a matching `/usr/sbin/ffmpeg -i <input>` child). Its matching
    // logic IS covered hermetically by the pure `cmdline_is_producer` / `parse_ppid` tests above, exactly as
    // the analogous SIGTERM walk (`terminate_go2rtc_producers`) is; the live scan is exercised end-to-end by
    // the on-device cutover.

    #[test]
    fn parse_ppid_reads_the_parent_pid_field() {
        let status = "Name:\tffmpeg\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t4321\nPid:\t4321\nPPid:\t1234\nUid:\t0\t0\t0\t0\n";
        assert_eq!(parse_ppid(status), Some(1234));
        // PPid 0 (the idle task's parent) parses as 0 — a real value, distinct from absent.
        assert_eq!(parse_ppid("PPid:\t0\n"), Some(0));
        // Absent or non-numeric ⇒ None (an unverifiable parent is never signalled).
        assert_eq!(parse_ppid("Name:\tx\nUid:\t0\n"), None);
        assert_eq!(parse_ppid("PPid:\tnotanumber\n"), None);
    }
}
