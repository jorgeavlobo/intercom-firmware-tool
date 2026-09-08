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

/// The go2rtc exec-source WRAPPER script go2rtc runs as `/bin/sh <this> <output>`
/// (`Go2RtcConfig.OnDeviceProducerScriptPath`). During its transient `/bin/sh` phase — before it `exec`s
/// ffmpeg IN PLACE — the process is NOT yet a matchable ffmpeg producer ([`cmdline_is_producer`] requires
/// argv[0] to be ffmpeg, excluding `/bin/sh`), yet it has ALREADY chosen its branch and written/removed the
/// readiness file accordingly. `capture.rs`'s pre-grab frame-source gate counts this in-flight wrapper as "a
/// producer is present" (via [`any_producer_or_wrapper`]) so it waits for readiness rather than attaching to
/// a filler that is about to serve (issue #180). Only ever a direct child of the go2rtc daemon.
pub(crate) const PRODUCER_SCRIPT_PATH: &str = "/etc/btmqttd/go2rtc/camera-producer.sh";

/// SIGTERM every go2rtc `exec:` ffmpeg producer currently reading one of `inputs`, so go2rtc respawns it
/// and it re-reads its input. `inputs` is the set of `-i` paths that identify OUR producer(s): a single
/// runtime-SDP entry for the sprop self-heal, or the runtime SDP + the filler clip for the av cutover.
/// `reason` is woven into the log line so an operator can tell the two callers apart. Best-effort and
/// non-fatal: a missing producer / a failed signal just defers the effect to the next producer start.
/// The `/proc` scan is blocking, so THIS fn offloads it to `spawn_blocking` INTERNALLY — callers just
/// `.await` it (do NOT wrap it again); the scan-validate-SIGTERM stays one synchronous pass in the
/// offloaded [`terminate_go2rtc_producers`] (no async yield between identifying a PID and signalling it).
///
/// `warn_if_none` gates the "no running producer to respawn" line for the `signalled == 0` case: the
/// lifecycle callers (arm-time cutover, teardown/startup/shutdown, sprop self-heal) expect a producer to be
/// running and pass `true` so a missing one is logged, but the A/V monitor's per-iteration cutover RETRY
/// runs precisely while the siphon is armed but UNWATCHED (no consumer ⇒ no producer yet), where zero is the
/// normal steady state, and passes `false` so it does not spam the log at the loop cadence. A genuine scan
/// FAILURE (the `/proc` open or the blocking task failing) is always logged regardless — it is never the
/// expected steady state.
pub(crate) async fn respawn_go2rtc_producers(
    inputs: &'static [&'static str],
    reason: &'static str,
    warn_if_none: bool,
) {
    // Do the whole scan-validate-signal in ONE blocking pass (no async yield between identifying a
    // producer and SIGTERMing it), so a PID can't be recycled out from under us across an await.
    let signalled = match tokio::task::spawn_blocking(move || {
        terminate_go2rtc_producers(crate::capture::DEFAULT_FFMPEG_BIN, GO2RTC_DAEMON_PATH, inputs, reason)
    })
    .await
    {
        Ok(Ok(n)) => n,
        // The `/proc` scan itself failed to open — log it DISTINCTLY from "found no producer" so a real scan
        // failure isn't misread as "nothing was running". Non-fatal — the change takes effect on the next
        // producer (re)start (caller-agnostic: this helper serves sprop self-heal AND the A/V cutover/teardown
        // paths, where the fallback is the next producer start, not necessarily an open/boot).
        Ok(Err(e)) => {
            eprintln!(
                "btmqttd: could not scan /proc to respawn go2rtc producers ({e}) ({reason}); the change takes effect on the next producer start"
            );
            return;
        }
        // The blocking task panicked/was cancelled. Log the JoinError so a "no respawn happened" report
        // isn't confused with "no producer found"; non-fatal — same next-producer-start fallback.
        Err(e) => {
            eprintln!("btmqttd: go2rtc producer-respawn task failed ({e}); relying on the next producer start");
            return;
        }
    };
    if signalled == 0 && warn_if_none {
        eprintln!(
            "btmqttd: no running go2rtc exec producer to respawn ({reason}); the change takes effect on its next start"
        );
    }
}

/// Scan `/proc` and SIGTERM every go2rtc `exec:` ffmpeg producer whose `-i` input is one of `inputs`:
/// `Ok(n)` = a COMPLETED scan signalled `n` producers, `Err` = `/proc` itself could not be opened. Each PID
/// is VALIDATED and signalled in the SAME loop iteration — identity checked ([`pid_is_producer`])
/// immediately before `kill`, with no async yield between — so PID reuse between discovery and the signal
/// can't make us terminate an unrelated process (see the module note). Propagating the open failure as
/// `Err` (rather than the old `0`) lets the caller log a real scan failure distinctly from "found none".
/// Blocking (`read_dir` + per-pid reads); only numeric `/proc/<pid>` entries are considered and any
/// unreadable per-pid entry is skipped (best-effort). `reason` only shapes the per-signal log line.
pub(crate) fn terminate_go2rtc_producers(
    ffmpeg_path: &str,
    daemon_path: &str,
    inputs: &[&str],
    reason: &str,
) -> std::io::Result<usize> {
    let mut signalled = 0usize;
    let entries = std::fs::read_dir("/proc")?;
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
    Ok(signalled)
}

/// Whether ANY go2rtc `exec:` ffmpeg producer is currently reading one of `inputs`, WITHOUT signalling it
/// (issue #180). Used to CONFIRM a back-to-filler cutover: a producer still on the live SDP means a viewer
/// can sit on the now-silent live feed until go2rtc's i/o-timeout, so the caller keeps retrying until none
/// remains. Offloads the blocking scan to `spawn_blocking` INTERNALLY (callers just `.await`). A scan that
/// could not run — the `/proc` open failed, or the blocking task did — returns `true` CONSERVATIVELY (assume
/// one MAY be running, so the caller keeps retrying) rather than a false "all clear".
pub(crate) async fn any_producer_matches(inputs: &'static [&'static str]) -> bool {
    match tokio::task::spawn_blocking(move || {
        scan_go2rtc_producers(crate::capture::DEFAULT_FFMPEG_BIN, GO2RTC_DAEMON_PATH, inputs)
    })
    .await
    {
        Ok(Ok(n)) => n > 0,
        Ok(Err(e)) => {
            eprintln!("btmqttd: could not scan /proc to confirm the filler cutover ({e}); assuming a producer may still be live");
            true
        }
        Err(e) => {
            eprintln!("btmqttd: /proc producer-scan task failed ({e}); assuming a producer may still be live");
            true
        }
    }
}

/// Scan `/proc` and COUNT the go2rtc `exec:` ffmpeg producers reading one of `inputs`, WITHOUT signalling any
/// (issue #180) — the read-only mirror of [`terminate_go2rtc_producers`]. `Ok(n)` = a completed scan found
/// `n`; `Err` = `/proc` itself could not be opened. Blocking; each numeric `/proc/<pid>` is validated with
/// [`pid_is_producer`] and any unreadable entry is skipped (best-effort).
pub(crate) fn scan_go2rtc_producers(
    ffmpeg_path: &str,
    daemon_path: &str,
    inputs: &[&str],
) -> std::io::Result<usize> {
    let mut found = 0usize;
    for entry in std::fs::read_dir("/proc")?.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue; // not a numeric pid directory
        };
        if pid_is_producer(pid, ffmpeg_path, daemon_path, inputs) {
            found += 1;
        }
    }
    Ok(found)
}

/// Whether ANY go2rtc `exec:` ffmpeg producer reading one of `inputs` OR its in-flight `/bin/sh` wrapper is
/// currently running, WITHOUT signalling it (issue #180). Used by `capture.rs`'s PRE-grab frame-source gate:
/// unlike [`any_producer_matches`] (ffmpeg only), this ALSO counts a wrapper still in its transient `/bin/sh`
/// phase (before it `exec`s ffmpeg), so a filler wrapper that has not yet become a matchable ffmpeg is not
/// misread as "no producer running" — which would let the capture attach to a filler about to serve and then
/// accept its bytes if readiness flips right after the grab. Offloads the blocking scan to `spawn_blocking`
/// INTERNALLY (callers just `.await`). A scan that could not run returns `true` CONSERVATIVELY (assume one
/// MAY be running, so the gate waits for readiness rather than risk grabbing the filler).
pub(crate) async fn any_producer_or_wrapper(inputs: &'static [&'static str]) -> bool {
    match tokio::task::spawn_blocking(move || {
        scan_producers_or_wrappers(
            crate::capture::DEFAULT_FFMPEG_BIN,
            GO2RTC_DAEMON_PATH,
            inputs,
            PRODUCER_SCRIPT_PATH,
        )
    })
    .await
    {
        Ok(Ok(n)) => n > 0,
        Ok(Err(e)) => {
            eprintln!("btmqttd: could not scan /proc for a go2rtc producer/wrapper before a capture ({e}); assuming one may be running");
            true
        }
        Err(e) => {
            eprintln!("btmqttd: /proc producer/wrapper-scan task failed ({e}); assuming one may be running");
            true
        }
    }
}

/// Scan `/proc` and COUNT the go2rtc `exec:` ffmpeg producers reading one of `inputs` PLUS any in-flight
/// `/bin/sh` wrapper running `script_path` — each a direct child of the go2rtc daemon (issue #180). `Ok(n)` =
/// a completed scan found `n`; `Err` = `/proc` itself could not be opened. Blocking; the wrapper-aware
/// sibling of [`scan_go2rtc_producers`], kept separate so the SIGTERM/cutover-confirm paths (which target
/// only the ffmpeg producer, never the transient shell) are unaffected. Any unreadable entry is skipped.
pub(crate) fn scan_producers_or_wrappers(
    ffmpeg_path: &str,
    daemon_path: &str,
    inputs: &[&str],
    script_path: &str,
) -> std::io::Result<usize> {
    let mut found = 0usize;
    for entry in std::fs::read_dir("/proc")?.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue; // not a numeric pid directory
        };
        if pid_is_producer_or_wrapper(pid, ffmpeg_path, daemon_path, inputs, script_path) {
            found += 1;
        }
    }
    Ok(found)
}

/// True iff `/proc/<pid>` is CURRENTLY either a go2rtc `exec:` ffmpeg producer reading one of `inputs`
/// ([`cmdline_is_producer`]) OR its in-flight `/bin/sh` wrapper running `script_path` ([`cmdline_is_wrapper`])
/// — AND its direct parent is the go2rtc daemon ([`parent_is`]). The cmdline is read once and tested against
/// both shapes. Blocking; any unreadable entry ⇒ `false`.
fn pid_is_producer_or_wrapper(
    pid: i32,
    ffmpeg_path: &str,
    daemon_path: &str,
    inputs: &[&str],
    script_path: &str,
) -> bool {
    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    (cmdline_is_producer(&cmdline, ffmpeg_path, inputs) || cmdline_is_wrapper(&cmdline, script_path))
        && parent_is(pid, daemon_path)
}

/// True iff a raw `/proc/<pid>/cmdline` (arguments NUL-separated) is the go2rtc exec WRAPPER still in its
/// transient `/bin/sh` phase: some argument is EXACTLY `script_path` (go2rtc runs it as
/// `/bin/sh <script_path> <output>`). An EXACT-argument match (not a substring) rejects a `<script_path>.bak`
/// lookalike; once the wrapper `exec`s ffmpeg IN PLACE its argv no longer contains the script path, so this
/// matches ONLY the pre-`exec` phase (after which [`cmdline_is_producer`] takes over). The caller pairs this
/// with a parent-is-go2rtc check, so it need not itself re-derive the shell. Pure — no I/O — unit-tested.
pub(crate) fn cmdline_is_wrapper(cmdline: &[u8], script_path: &str) -> bool {
    cmdline
        .split(|&b| b == 0)
        .filter(|a| !a.is_empty())
        .any(|arg| arg == script_path.as_bytes())
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

    /// The go2rtc exec WRAPPER script path (mirrors `av::PRODUCER_SCRIPT_PATH` / the go2rtc.yaml exec).
    const SCRIPT: &str = "/etc/btmqttd/go2rtc/camera-producer.sh";

    #[test]
    fn cmdline_matches_the_inflight_wrapper_and_rejects_lookalikes() {
        let ff = crate::capture::DEFAULT_FFMPEG_BIN;

        // The in-flight wrapper (issue #180): go2rtc runs it as `/bin/sh <script> <output>` while it is still
        // in its `/bin/sh` phase, before it `exec`s ffmpeg in place. The exact script path is argv[1], so this
        // matches — letting the capture pre-grab gate count it as "a producer is present" and wait for
        // readiness rather than attach to a filler about to serve.
        let wrapper = [b"/bin/sh".as_ref(), SCRIPT.as_bytes(), b"rtsp://127.0.0.1:8554/doorbell"].join(&0u8);
        assert!(cmdline_is_wrapper(&wrapper, SCRIPT));

        // Once the wrapper `exec`s ffmpeg IN PLACE, its argv no longer contains the script path — it is now a
        // matchable ffmpeg producer (covered above), NOT a wrapper.
        let live = [ff.as_bytes(), b"-i", SDP.as_bytes(), b"-c:v", b"copy"].join(&0u8);
        assert!(!cmdline_is_wrapper(&live, SCRIPT));
        let filler = [ff.as_bytes(), b"-stream_loop", b"-1", b"-i", CLIP.as_bytes()].join(&0u8);
        assert!(!cmdline_is_wrapper(&filler, SCRIPT));

        // go2rtc itself (takes -config <yaml>, never the script path) must NOT match.
        let go2rtc = [b"/usr/sbin/go2rtc".as_ref(), b"-config", b"/etc/btmqttd/go2rtc/go2rtc.yaml"].join(&0u8);
        assert!(!cmdline_is_wrapper(&go2rtc, SCRIPT));

        // An EXACT-argument match, not a substring: a `<script>.bak` lookalike must NOT match.
        let script_bak = [b"/bin/sh".as_ref(), b"/etc/btmqttd/go2rtc/camera-producer.sh.bak"].join(&0u8);
        assert!(!cmdline_is_wrapper(&script_bak, SCRIPT));

        // Empty cmdline (e.g. a kernel thread) never matches.
        assert!(!cmdline_is_wrapper(&[], SCRIPT));
    }

    // NB: the `/proc` walk (`terminate_go2rtc_producers`) has no host-/proc test of its own — an assertion
    // over the live `/proc` would depend on ambient host processes. Its producer-matching logic IS covered
    // hermetically by the pure `cmdline_is_producer` / `parse_ppid` tests above; the live walk is exercised
    // end-to-end by the on-device sprop self-heal and the av cutover.

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
