using System.IO;
using System.Linq;
using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// Shape checks for the on-device go2rtc SysV init script (<c>go2rtcd</c>, issue #120). It mirrors
/// the btmqttd init script's supervision model (atomic mkdir mutex + DISABLED marker) but drives the
/// vendored go2rtc binary with the generated config. These lock in the key wiring from the embedded
/// resource — no ext4 image needed.
/// </summary>
public class Go2RtcdScriptTests
{
    private const string ResourceName =
        "IntercomFirmwareTool.Core.Payload.mqtt.go2rtcd";

    private static string ReadScript()
    {
        var asm = typeof(MqttOptions).Assembly; // any public Core type → the Core assembly
        using Stream? stream = asm.GetManifestResourceStream(ResourceName);
        Assert.NotNull(stream);
        using var reader = new StreamReader(stream!);
        return reader.ReadToEnd();
    }

    private static string[] CodeLines(string script) =>
        script.Replace("\r\n", "\n").Split('\n')
              .Select(l => l.Trim())
              .Where(l => l.Length > 0 && !l.StartsWith('#'))
              .ToArray();

    [Fact]
    public void Drives_the_go2rtc_binary_with_the_generated_config()
    {
        string[] code = CodeLines(ReadScript());
        Assert.Contains(code, l => l == "DAEMON=/usr/sbin/go2rtc");
        Assert.Contains(code, l => l == "CONFIG=/etc/btmqttd/go2rtc/go2rtc.yaml");
        // The launch line passes -config and backgrounds the daemon.
        Assert.Contains(code, l =>
            l.Contains("\"$DAEMON\" -config \"$CONFIG\"") && l.TrimEnd().EndsWith("&"));
    }

    [Fact]
    public void Assembles_the_tmpfs_runtime_sdp_from_the_readonly_template_before_launch()
    {
        // Issue #120: the rootfs (incl. /etc) is read-only, so go2rtc reads a tmpfs RUNTIME SDP the init
        // script reassembles at each launch — copy the read-only template, then splice the persisted
        // learned sprop into the fmtp line. The paths must match Go2RtcConfig.OnDeviceRuntimeSdpPath and
        // persist.rs (STATE_DIR + camera-sprop), and the assembly must run before the daemon starts.
        string s = ReadScript();
        string[] code = CodeLines(s);
        Assert.Contains("TEMPLATE_SDP=/etc/btmqttd/go2rtc/doorbell.sdp", s);
        Assert.Contains("RUNTIME_SDP=$RUNTIME_SDP_DIR/doorbell.sdp", s);
        Assert.Contains("RUNTIME_SDP_DIR=/var/run/btmqttd", s);
        // The runtime SDP path go2rtc reads must equal the C# const and sprop.rs's SDP_PATH.
        Assert.Equal("/var/run/btmqttd/doorbell.sdp", Go2RtcConfig.OnDeviceRuntimeSdpPath);
        // The persisted sprop file mirrors persist.rs: DEFAULT_STATE_DIR with the $BTMQTTD_STATE_DIR
        // override, and the camera-sprop filename.
        Assert.Contains("STATE_DIR=${BTMQTTD_STATE_DIR:-/home/bticino/cfg/extra/btmqttd}", s);
        Assert.Contains("SPROP_FILE=$STATE_DIR/camera-sprop", s);
        // tmpfs dir is (re)created (mkdir -p) and the splice inserts after packetization-mode=1; in the
        // exact BuildOnDeviceSdp order.
        Assert.Contains(code, l => l.Contains("mkdir -p \"$RUNTIME_SDP_DIR\""));
        Assert.Contains(code, l =>
            l.Contains("s/packetization-mode=1;/packetization-mode=1;sprop-parameter-sets="));
        // The assembly is atomic (temp + mv) and runs from launch_if_enabled before the daemon starts.
        Assert.Contains(code, l => l.Contains("mv \"$tmp\" \"$RUNTIME_SDP\""));
        string launch = s.Substring(s.IndexOf("launch_if_enabled()", System.StringComparison.Ordinal));
        int asm = launch.IndexOf("assemble_sdp", System.StringComparison.Ordinal);
        int run = launch.IndexOf("\"$DAEMON\" -config \"$CONFIG\"", System.StringComparison.Ordinal);
        Assert.True(asm >= 0 && run > asm, "assemble_sdp must run before the daemon is launched");
    }

    [Fact]
    public void Only_splices_a_sprop_whose_branch_matches_the_installed_camera_branch()
    {
        // Task #41: the persisted sprop record is `<branch>\t<value>` and cfg/extra survives a reflash,
        // so assemble_sdp must splice ONLY when the record's branch equals the current CAMERA_BRANCH —
        // otherwise a reflash that flips hi/lo-res would decode with the previous branch's SPS.
        string s = ReadScript();
        string[] code = CodeLines(s);
        // Reads the current branch from the installed conf (default 1 when absent, matching config.rs).
        Assert.Contains("CONF_FILE=/etc/btmqttd/btmqttd.conf", s);
        Assert.Contains(code, l => l.Contains("CAMERA_BRANCH=") && l.Contains("sed -n") && l.Contains("$CONF_FILE"));
        Assert.Contains(code, l => l.Contains("cur_branch=1"));
        // Splits the record on TAB: cut -f1 = branch, cut -f2- = value.
        Assert.Contains(code, l => l.Contains("rec_branch=") && l.Contains("cut -f1"));
        Assert.Contains(code, l => l.Contains("rec_value=") && l.Contains("cut -f2-"));
        // The gate: only assign $sprop when the record branch equals the current branch.
        Assert.Contains(code, l =>
            l.Contains("[ \"$rec_branch\" = \"$cur_branch\" ]") && l.Contains("sprop=\"$rec_value\""));
    }

    [Fact]
    public void Keeps_the_pgrep_exe_filter_so_it_never_matches_itself()
    {
        // Assert on executable lines so a comment can't satisfy the check. pgrep -x matches by comm;
        // the readlink /proc/PID/exe = $DAEMON filter ensures only the real daemon is counted — never
        // a same-named process or this init script's own shell.
        string[] code = CodeLines(ReadScript());
        Assert.Contains(code, l => l.Contains("pgrep -x \"$NAME\""));
        Assert.Contains(code, l => l.Contains("readlink /proc/\"$p\"/exe"));
    }

    [Fact]
    public void Provides_the_full_service_contract()
    {
        // Match each lifecycle verb on an executable line (its case label), never inside a comment.
        string[] code = CodeLines(ReadScript());
        foreach (var verb in new[] { "start)", "stop)", "status)", "restart)", "respawn)" })
            Assert.Contains(code, l => l == verb);
    }

    [Fact]
    public void Uses_its_own_markers_and_never_touches_core_bticino_services()
    {
        string s = ReadScript();
        // Its own lock/marker/log paths — distinct from btmqttd's, so the two services don't
        // collide on the mutex or the DISABLED marker.
        Assert.Contains("LOCKDIR=/var/run/go2rtc.lock", s);
        Assert.Contains("DISABLED=/var/run/go2rtc.disabled", s);
        Assert.Contains("LOGDIR=/var/log/go2rtc", s);
        // Like the watchdog, it must never poke the core BTicino stack.
        string[] code = CodeLines(s);
        Assert.DoesNotContain(code, l =>
            l.Contains("scsserver") || l.Contains("mosquitto") || l.Contains("bt_daemon"));
    }

    // Script with backslash line-continuations collapsed to single logical lines, so assertions on a
    // multi-line iptables command (split for readability) match the whole command.
    private static string JoinedScript() =>
        System.Text.RegularExpressions.Regex.Replace(
            ReadScript().Replace("\r\n", "\n"), @"\s*\\\s*\n\s*", " ");

    [Fact]
    public void Opens_only_the_rtsp_media_port_least_privilege_lan_restricted()
    {
        // Phase 1c-3: open :8554 on the LAN interface, source-restricted to the interface's own subnet.
        // The control API (:1984) must NOT be opened, and no other port is touched.
        string s = ReadScript();
        string joined = JoinedScript();
        string[] code = CodeLines(s);
        Assert.Contains("CAM_PORT=8554", s);
        Assert.Contains("CAM_IFACE=wlan0", s);
        // The single ACCEPT lives in OUR chain, matches tcp/CAM_PORT on the interface, SOURCE-RESTRICTED
        // to the derived LAN subnet.
        Assert.Contains(
            "iptables -w 5 -A \"$FW_CHAIN\" -i \"$CAM_IFACE\" -p tcp --dport \"$CAM_PORT\" -s \"$lan\" -j ACCEPT",
            joined);
        // LAN source derived at runtime; the ACCEPT is added ONLY when an address exists — with no address
        // the chain is left empty (port closed), never opened interface-wide.
        Assert.Contains(code, l => l.Contains("ip -4 addr show \"$CAM_IFACE\""));
        Assert.Contains(code, l => l.Contains("[ -n \"$lan\" ] && iptables -w 5 -A \"$FW_CHAIN\""));
        // The control API port is loopback-only — no executable line references 1984 (a comment may
        // mention it, so assert on code lines, not the whole script).
        Assert.DoesNotContain(code, l => l.Contains("1984"));
    }

    [Fact]
    public void Firewall_is_tied_to_the_running_daemon()
    {
        string[] code = CodeLines(ReadScript());
        // The rule is opened only when the daemon is actually running (a failed launch leaves no open
        // port) and closed on stop/disable/not-running. Assert the CALL SITES, not the definition line.
        Assert.Contains(code, l => l.Contains("if is_running; then firewall_open"));
        Assert.Contains(code, l => l.Contains("else firewall_close"));   // not-running / disabled respawn
        Assert.Contains(code, l => l == "firewall_close");               // disabled branch (bare call)
    }

    [Fact]
    public void Owns_its_rules_via_a_dedicated_chain_that_works_without_xt_comment()
    {
        // The target kernel (C100X v1.5.8, Linux 4.9) ships NO xt_comment match — a `-m comment` rule is
        // rejected by the kernel and would leave :8554 permanently closed. Ownership is instead a
        // dedicated namespaced chain (the Docker/kube-proxy/fail2ban model): we create/flush/populate/
        // delete only OUR chain plus one INPUT jump, and never touch a foreign rule.
        string s = ReadScript();
        string joined = JoinedScript();
        string[] code = CodeLines(s);
        Assert.Contains(code, l => l == "FW_CHAIN=GO2RTC");
        // No comment match on any executable line — it does not work on the target kernel.
        Assert.DoesNotContain(code, l => l.Contains("-m comment"));
        // open manages OUR chain: create (idempotent), flush (we own it), the ACCEPT, then the INPUT jump.
        Assert.Contains(code, l => l.Contains("iptables -w 5 -N \"$FW_CHAIN\""));
        Assert.Contains(code, l => l.Contains("iptables -w 5 -F \"$FW_CHAIN\""));
        // The jump is APPENDED (after the panel's factory filters), never inserted — any `-I INPUT` form
        // (with or without an explicit position) inserts at the top and would bypass a factory filter.
        Assert.Contains(code, l => l.Contains("iptables -w 5 -A INPUT -j \"$FW_CHAIN\""));
        Assert.DoesNotContain(code, l => l.Contains("-I INPUT"));
        // The jump is kept LAST in INPUT — repositioned if a concurrent factory `-F INPUT; -A …` rebuild
        // left it out of place — so it can never sit ahead of the factory filters. The listing is captured
        // first and a failed `iptables -S INPUT` changes nothing (an inspection error must not trigger a
        // destructive drain+re-append).
        Assert.Contains("inp=$(iptables -w 5 -S INPUT 2>/dev/null) || return 0", s);
        // The early-return is COUNT-AWARE: only exactly-one-jump-and-last is "already correct", so a stale
        // duplicate is never early-returned and a failed cleanup self-heals on a later pass.
        Assert.Contains("[ \"$n\" -eq 1 ] && [ \"$last\" = \"-A INPUT -j $FW_CHAIN\" ] && return 0", s);
        // On a reposition, the fresh jump is APPENDED before the older one(s) are deleted, so a jump to our
        // chain always exists during the swap (no window with none, even if the re-append were to fail).
        int fjStart = s.IndexOf("fw_jump()", System.StringComparison.Ordinal);
        int fjEnd = s.IndexOf("\n}", fjStart, System.StringComparison.Ordinal);
        string fj = s.Substring(fjStart, fjEnd - fjStart);
        Assert.True(
            fj.IndexOf("iptables -w 5 -A INPUT -j \"$FW_CHAIN\"", System.StringComparison.Ordinal)
            < fj.IndexOf("iptables -w 5 -D INPUT -j \"$FW_CHAIN\"", System.StringComparison.Ordinal),
            "fw_jump must append the new jump before deleting older ones");
        // Duplicate cleanup RE-COUNTS the LIVE ruleset each iteration, so a concurrent factory `-F INPUT`
        // flush after our listing can't make a stale count delete the freshly appended jump. It stops on
        // any failure (a failed `-D`, or a listing failure that yields count 0) and retries next pass.
        Assert.Contains(
            "while [ \"$(iptables -w 5 -S INPUT 2>/dev/null | grep -c -- \"^-A INPUT -j $FW_CHAIN\\$\")\" -gt 1 ]", fj);
        Assert.Contains("iptables -w 5 -D INPUT -j \"$FW_CHAIN\" 2>/dev/null || break", fj);
        // The ONLY thing we ever add to INPUT is the jump to our chain — never a bare rule in INPUT.
        // Code lines only: a COMMENT may legitimately describe the factory's `-F INPUT; -A INPUT` rebuild,
        // so skip comment lines (the invariant is about what the script EXECUTES, not what it documents).
        foreach (var l in System.Text.RegularExpressions.Regex.Split(joined, "\n"))
            if (!l.TrimStart().StartsWith("#", System.StringComparison.Ordinal)
                && (l.Contains(" -A INPUT ") || l.Contains(" -I INPUT ")))
                Assert.Contains("-j \"$FW_CHAIN\"", l);
        // close tears down only our own chain + jump, removing the jump BEFORE deleting the chain (-X
        // refuses a referenced chain).
        string closeBody = s.Replace("\r\n", "\n")
            .Substring(s.Replace("\r\n", "\n").IndexOf("firewall_close()", System.StringComparison.Ordinal));
        int delJump = closeBody.IndexOf("iptables -w 5 -D INPUT -j \"$FW_CHAIN\"", System.StringComparison.Ordinal);
        int delChain = closeBody.IndexOf("iptables -w 5 -X \"$FW_CHAIN\"", System.StringComparison.Ordinal);
        Assert.True(delJump >= 0 && delChain > delJump, "the jump must be removed before the chain is deleted");
    }

    [Fact]
    public void Never_touches_a_pre_existing_foreign_chain_it_did_not_create()
    {
        // CodeRabbit: a fixed chain name is a namespace convention, not proof of ownership. We manage the
        // chain ONLY when we created it this boot, recorded by a boot-scoped marker (FW_OWN). A GO2RTC
        // chain we did not create is left untouched by both open and close.
        string s = ReadScript().Replace("\r\n", "\n");
        string[] code = CodeLines(ReadScript());
        Assert.Contains(code, l => l == "FW_OWN=/var/run/go2rtc.fwown");
        int oOpen = s.IndexOf("firewall_open()", System.StringComparison.Ordinal);
        int cOpen = s.IndexOf("firewall_close()", System.StringComparison.Ordinal);
        string openBody = s.Substring(oOpen, cOpen - oOpen);
        string closeBody = s.Substring(cOpen);
        // A three-state existence probe distinguishes a CONFIRMED-absent chain from an inspection error,
        // so a transient `iptables -S` failure never sends us into the create/relinquish path.
        Assert.Contains("fw_chain_exists()", s);
        Assert.Contains("case \"$out\" in *\"No chain\"*) return 1 ;; esac", s);
        Assert.Contains("[ \"$fw_rc\" -eq 2 ]", openBody);  // inspection error → change nothing
        // open: if the chain already exists but we hold no ownership marker, bail before any flush/populate.
        int probe = openBody.IndexOf("fw_chain_exists; fw_rc=$?", System.StringComparison.Ordinal);
        int foreignBail = openBody.IndexOf("[ -e \"$FW_OWN\" ] || return 0", System.StringComparison.Ordinal);
        int claim = openBody.IndexOf(": > \"$FW_OWN\"", System.StringComparison.Ordinal);
        int flush = openBody.IndexOf("iptables -w 5 -F \"$FW_CHAIN\"", System.StringComparison.Ordinal);
        Assert.True(probe >= 0 && foreignBail > probe && foreignBail < flush,
            "open must bail on a foreign chain (ownership check before any flush)");
        Assert.True(claim > probe && claim < flush, "open claims ownership when it creates the chain");
        // close: guarded by the ownership marker before any teardown of the chain/jump.
        int closeGuard = closeBody.IndexOf("[ -e \"$FW_OWN\" ] || return 0", System.StringComparison.Ordinal);
        int delJump = closeBody.IndexOf("iptables -w 5 -D INPUT -j \"$FW_CHAIN\"", System.StringComparison.Ordinal);
        Assert.True(closeGuard >= 0 && closeGuard < delJump, "close must check ownership before tearing down");
    }

    [Fact]
    public void Keeps_chain_ownership_consistent_under_marker_and_teardown_failures()
    {
        // Codex/CodeRabbit: the ownership marker and the chain must never diverge.
        //  (1) claim ownership BEFORE creating the chain, so a failed marker write leaves nothing to
        //      orphan; if the create then fails, drop the marker again.
        //  (2) close drops ownership ONLY when a SUCCESSFUL listing confirms the chain AND its jump are
        //      gone — a failed listing (inspection error) or a still-present object keeps FW_OWN for retry
        //      (a failed `-S` piped into grep would look empty and be misread as "gone").
        string s = ReadScript().Replace("\r\n", "\n");
        int oOpen = s.IndexOf("firewall_open()", System.StringComparison.Ordinal);
        int cOpen = s.IndexOf("firewall_close()", System.StringComparison.Ordinal);
        string openBody = s.Substring(oOpen, cOpen - oOpen);
        string closeBody = s.Substring(cOpen);
        // (1) marker-first: claim before create, and un-claim if the create fails.
        int claim = openBody.IndexOf(": > \"$FW_OWN\" 2>/dev/null || return 0", System.StringComparison.Ordinal);
        int create = openBody.IndexOf("iptables -w 5 -N \"$FW_CHAIN\" 2>/dev/null || { rm -f \"$FW_OWN\"", System.StringComparison.Ordinal);
        Assert.True(claim >= 0 && create > claim, "ownership must be claimed before the chain is created");
        // If -N fails because a GO2RTC chain appeared in the race window (TOCTOU), we RELINQUISH the marker
        // (`|| { rm -f "$FW_OWN" … }`) so the next pass treats the newly appeared chain as foreign and never
        // flushes it — the create line above is the single (re)create path (no separate recreate branch).
        // (2) close captures ONE listing, bails on its failure, and confirms both objects gone before drop.
        int listing = closeBody.IndexOf("rules=$(iptables -w 5 -S 2>/dev/null) || return 0", System.StringComparison.Ordinal);
        int jumpChk = closeBody.IndexOf("grep -q -- \"^-A INPUT -j $FW_CHAIN\\$\" && return 0", System.StringComparison.Ordinal);
        int chainChk = closeBody.IndexOf("grep -q -- \"^-N $FW_CHAIN\\$\" && return 0", System.StringComparison.Ordinal);
        int drop = closeBody.IndexOf("rm -f \"$FW_OWN\"", System.StringComparison.Ordinal);
        Assert.True(listing >= 0 && jumpChk > listing && chainChk > listing && drop > jumpChk && drop > chainChk,
            "close must capture a successful listing and confirm chain+jump gone before dropping the marker");
    }

    [Fact]
    public void Reconciles_the_chain_statelessly_so_a_dhcp_change_needs_no_state_file()
    {
        // Reconciliation is stateless: each open flushes OUR chain and repopulates it from the CURRENT
        // address, so a DHCP subnet change drops the old ACCEPT and adds the new one with no remembered
        // state to drift. The chain itself is the state — there is no tmpfs state file or delete/confirm
        // dance to strand a rule under a transient failure.
        string s = ReadScript().Replace("\r\n", "\n");
        int oOpen = s.IndexOf("firewall_open()", System.StringComparison.Ordinal);
        int cOpen = s.IndexOf("firewall_close()", System.StringComparison.Ordinal);
        string openBody = s.Substring(oOpen, cOpen - oOpen);
        // Flush precedes the (address-gated) append, so the chain always reflects only the current subnet.
        int flush = openBody.IndexOf("iptables -w 5 -F \"$FW_CHAIN\"", System.StringComparison.Ordinal);
        int append = openBody.IndexOf("iptables -w 5 -A \"$FW_CHAIN\"", System.StringComparison.Ordinal);
        Assert.True(flush >= 0 && append > flush, "the chain must be flushed before it is repopulated");
        Assert.Contains("[ -n \"$lan\" ] && iptables -w 5 -A \"$FW_CHAIN\"", openBody);
        // The repopulation is GATED on a successful flush — a contended `-F` aborts the pass instead of
        // stacking a new ACCEPT on the stale one; mutating calls use `-w 5` to wait for the xtables lock.
        Assert.Contains("iptables -w 5 -F \"$FW_CHAIN\" 2>/dev/null || return 0", openBody);
        // No state file / state helpers anywhere (the whole FW_STATE/fw_gone/fw_del machinery is gone).
        string[] code = CodeLines(ReadScript());
        Assert.DoesNotContain(code, l =>
            l.Contains("FW_STATE") || l.Contains("fw_gone") || l.Contains("fw_del") || l.Contains("fw_installed"));
    }

    [Fact]
    public void Stop_closes_the_firewall_under_the_lock_and_only_if_still_disabled()
    {
        // Codex: the stop-time firewall cleanup must not race a concurrent `start`'s firewall_open. Guard
        // it under the mutex and skip it if a `start` re-enabled the service during the shutdown window.
        string s = ReadScript().Replace("\r\n", "\n");
        int stop = s.IndexOf("\tstop)", System.StringComparison.Ordinal);
        int status = s.IndexOf("\tstatus)", stop, System.StringComparison.Ordinal);
        Assert.True(stop >= 0 && status > stop);
        string stopBody = s.Substring(stop, status - stop);
        // Close only when still the desired-stopped state (DISABLED present).
        int guard = stopBody.IndexOf("[ -e \"$DISABLED\" ] && firewall_close", System.StringComparison.Ordinal);
        Assert.True(guard >= 0, "stop must gate firewall_close on the DISABLED marker");
        // …and inside a lock: an acquire precedes the guard and a release follows it.
        int acq = stopBody.LastIndexOf("acquire", guard, System.StringComparison.Ordinal);
        int rel = stopBody.IndexOf("release", guard, System.StringComparison.Ordinal);
        Assert.True(acq >= 0 && rel > guard, "the stop firewall_close must run between acquire and release");
    }

    [Fact]
    public void Firewall_open_is_zero_write_when_the_chain_already_matches()
    {
        // Task #42: the per-pass `-F` + `-A` write churn is what raced the factory firewall's lock-less
        // INPUT rebuild (making its own `-A INPUT` calls fail silently and dropping factory rules). So
        // firewall_open must be ZERO-WRITE in steady state: when OUR chain already holds exactly the one
        // desired ACCEPT for the current subnet (address present) or is already empty (no address), it
        // performs NO iptables writes — it only re-asserts the (already zero-write when last) INPUT jump
        // and returns, BEFORE ever reaching the destructive `-F`.
        string s = ReadScript().Replace("\r\n", "\n");
        string joined = JoinedScript();
        int oOpen = s.IndexOf("firewall_open()", System.StringComparison.Ordinal);
        int cOpen = s.IndexOf("firewall_close()", System.StringComparison.Ordinal);
        string openBody = s.Substring(oOpen, cOpen - oOpen);
        // The decision reads the LIVE chain: a rule-count (`grep -c "^-A "`) plus a `-C` membership check
        // (which canonicalizes arg order / `-m tcp` / subnet masking) for the CURRENT subnet. The listing
        // STATUS is captured separately — `n=-1` on a failed `-S` — so an inspection error never reads as
        // "already correct" and always falls through to the flush path.
        Assert.Contains("if fw_list=$(iptables -w 5 -S \"$FW_CHAIN\" 2>/dev/null); then", openBody);
        Assert.Contains("grep -c -- \"^-A \"", openBody);
        Assert.Contains("n=-1", openBody);
        Assert.Contains(
            "iptables -w 5 -C \"$FW_CHAIN\" -i \"$CAM_IFACE\" -p tcp --dport \"$CAM_PORT\" -s \"$lan\" -j ACCEPT",
            joined);
        // The fast path exits (fw_jump + return) for BOTH the already-correct (n==1 + -C match) and the
        // already-empty (no address, n==0) cases.
        Assert.Contains("[ \"$n\" -eq 1 ] && iptables -w 5 -C \"$FW_CHAIN\"", joined);
        Assert.Contains("[ \"$n\" -eq 0 ] && { fw_jump; return 0; }", openBody);
        // ZERO-WRITE PROOF: the first fast-path `{ fw_jump; return 0; }` must appear BEFORE the flush, so a
        // matching chain never reaches any `-F`/`-A` write.
        int fastReturn = openBody.IndexOf("{ fw_jump; return 0; }", System.StringComparison.Ordinal);
        int flush = openBody.IndexOf("iptables -w 5 -F \"$FW_CHAIN\"", System.StringComparison.Ordinal);
        int listing = openBody.IndexOf("if fw_list=$(iptables -w 5 -S \"$FW_CHAIN\"", System.StringComparison.Ordinal);
        Assert.True(fastReturn >= 0 && flush > fastReturn,
            "the zero-write fast path must return before the destructive flush");
        Assert.True(listing >= 0 && listing < fastReturn && listing < flush,
            "the chain listing must be read before the fast-path decision and the flush");
        // The full flush+repopulate path is still there for when the state DIFFERS (missing/extra rule,
        // changed subnet, freshly created chain), gated on a successful flush.
        Assert.Contains("iptables -w 5 -F \"$FW_CHAIN\" 2>/dev/null || return 0", openBody);
        Assert.Contains("[ -n \"$lan\" ] && iptables -w 5 -A \"$FW_CHAIN\"", openBody);
    }

    [Fact]
    public void Provides_a_firewall_only_fw_reassert_subcommand()
    {
        // Task #42: the if-up.d hook calls `go2rtcd fw-reassert` right after the factory firewall rebuild.
        // It must be a firewall-ONLY reconcile under the lock — no daemon launch/kill — reusing the same
        // firewall_open/firewall_close single source of truth, coupled to the running+enabled state.
        string s = ReadScript().Replace("\r\n", "\n");
        string[] code = CodeLines(s);
        Assert.Contains(code, l => l == "fw-reassert)");
        // Advertised in usage.
        Assert.Contains(code, l => l.Contains("{start|stop|status|restart|respawn|fw-reassert}"));
        // Isolate the arm (from its label to the next case label `stop)`).
        int arm = s.IndexOf("\tfw-reassert)", System.StringComparison.Ordinal);
        int next = s.IndexOf("\tstop)", arm, System.StringComparison.Ordinal);
        Assert.True(arm >= 0 && next > arm);
        string armBody = s.Substring(arm, next - arm);
        // Enabled (no marker) AND running → open; otherwise close. Under the lock.
        Assert.Contains("if [ ! -e \"$DISABLED\" ] && is_running; then", armBody);
        Assert.Contains("firewall_open", armBody);
        Assert.Contains("firewall_close", armBody);
        int acq = armBody.IndexOf("acquire", System.StringComparison.Ordinal);
        int rel = armBody.IndexOf("release", System.StringComparison.Ordinal);
        Assert.True(acq >= 0 && rel > acq, "fw-reassert must run its firewall reconcile under the lock");
        // Firewall ONLY: it must NEVER launch or kill the daemon.
        Assert.DoesNotContain("launch_if_enabled", armBody);
        Assert.DoesNotContain("kill_all", armBody);
    }

    [Fact]
    public void Waits_for_a_just_launched_daemon_before_deciding_the_firewall()
    {
        // Codex: the is_running check right after backgrounding go2rtc can race the child's exec, so a
        // manual start/restart could close the port until the next watchdog pass. launch_if_enabled must
        // report whether it launched, and start/respawn must wait for it to come up before the decision.
        string[] code = CodeLines(ReadScript());
        Assert.Contains(code, l => l.Contains("wait_running()"));
        // The wait only follows an actual launch (steady-state respawns never sleep).
        Assert.Contains(code, l => l.Contains("launch_if_enabled && wait_running"));
        // launch_if_enabled distinguishes "launched" (0) from "already up / disabled" (1) via return 1.
        Assert.Contains(code, l => l.Contains("is_running && return 1"));
    }
}
