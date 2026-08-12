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
        System.Text.RegularExpressions.Regex.Replace(ReadScript(), @"\s*\\\s*\n\s*", " ");

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
        // port) and closed on stop/disable/not-running.
        Assert.Contains(code, l => l.Contains("if is_running; then firewall_open"));
        Assert.Contains(code, l => l.Contains("firewall_close"));
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
        // The jump is APPENDED (after the panel's factory filters), never inserted at the top.
        Assert.Contains(code, l => l.Contains("iptables -w 5 -A INPUT -j \"$FW_CHAIN\""));
        Assert.DoesNotContain(code, l => l.Contains("-I INPUT 1"));
        // The ONLY thing we ever add to INPUT is the jump to our chain — never a bare rule in INPUT.
        foreach (var l in System.Text.RegularExpressions.Regex.Split(joined, "\n"))
            if (l.Contains(" -A INPUT ") || l.Contains(" -I INPUT "))
                Assert.Contains("-j \"$FW_CHAIN\"", l);
        // close tears down only our own chain + jump, removing the jump BEFORE deleting the chain (-X
        // refuses a referenced chain).
        string closeBody = s.Replace("\r\n", "\n")
            .Substring(s.Replace("\r\n", "\n").IndexOf("firewall_close()", System.StringComparison.Ordinal));
        int delJump = closeBody.IndexOf("iptables -D INPUT -j \"$FW_CHAIN\"", System.StringComparison.Ordinal);
        int delChain = closeBody.IndexOf("iptables -X \"$FW_CHAIN\"", System.StringComparison.Ordinal);
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
        // open: if the chain already exists but we hold no ownership marker, bail before any flush/populate.
        int existsCheck = openBody.IndexOf("iptables -S \"$FW_CHAIN\" >/dev/null 2>&1", System.StringComparison.Ordinal);
        int foreignBail = openBody.IndexOf("[ -e \"$FW_OWN\" ] || return 0", System.StringComparison.Ordinal);
        int claim = openBody.IndexOf(": > \"$FW_OWN\"", System.StringComparison.Ordinal);
        int flush = openBody.IndexOf("iptables -w 5 -F \"$FW_CHAIN\"", System.StringComparison.Ordinal);
        Assert.True(existsCheck >= 0 && foreignBail > existsCheck && foreignBail < flush,
            "open must bail on a foreign chain (ownership check before any flush)");
        Assert.True(claim > existsCheck && claim < flush, "open claims ownership when it creates the chain");
        // close: guarded by the ownership marker before any teardown of the chain/jump.
        int closeGuard = closeBody.IndexOf("[ -e \"$FW_OWN\" ] || return 0", System.StringComparison.Ordinal);
        int delJump = closeBody.IndexOf("iptables -D INPUT -j \"$FW_CHAIN\"", System.StringComparison.Ordinal);
        Assert.True(closeGuard >= 0 && closeGuard < delJump, "close must check ownership before tearing down");
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
