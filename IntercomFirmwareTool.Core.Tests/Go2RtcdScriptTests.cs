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
        // Our single INPUT rule is inserted at the TOP (above the policy DROP), matches a specific
        // tcp/dport on the interface, SOURCE-RESTRICTED to the derived LAN subnet, and TAGGED with our
        // ownership comment (see the ownership test below).
        Assert.Contains(
            "iptables -I INPUT -i \"$CAM_IFACE\" -p tcp --dport \"$CAM_PORT\" -s \"$lan\" "
            + "-m comment --comment \"$FW_TAG\" -j ACCEPT", joined);
        // LAN source derived from the interface address at runtime; with no address yet the port is NOT
        // opened interface-wide (stays LAN-only) — bail before inserting when there is no address.
        Assert.Contains(code, l => l.Contains("ip -4 addr show \"$CAM_IFACE\""));
        Assert.Contains(code, l => l.Contains("[ -z \"$lan\" ]"));   // no-address bail (insert nothing)
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
    public void Owns_its_rule_by_a_required_comment_tag_so_a_foreign_rule_is_never_deleted()
    {
        // CodeRabbit (final): a full rule spec is a matcher, not an identity — an admin's byte-identical
        // :8554 LAN ACCEPT rule (even inserted ABOVE ours) would be caught by a bare `-D`. So the rule
        // carries an ownership TAG via the iptables comment match, and BOTH insert and delete require that
        // comment. Cleanup therefore matches only rules bearing our tag; an untagged look-alike is
        // invisible to it. This is the industry-standard approach (Docker/firewalld tag their rules).
        string s = ReadScript();
        string joined = JoinedScript();
        string[] code = CodeLines(s);
        // No chain machinery at all (the earlier chain-ownership design is gone).
        Assert.DoesNotContain(code, l => l.Contains("iptables -N") || l.Contains("iptables -F"));
        Assert.DoesNotContain(code, l => l.Contains("GO2RTC")
            || l.Contains("firewall_ensure_chain") || l.Contains("firewall_chain_is_ours"));
        // The ownership tag is defined and applied to the inserted rule.
        Assert.Contains(code, l => l == "FW_TAG=go2rtcd");
        Assert.Contains(
            "iptables -I INPUT -i \"$CAM_IFACE\" -p tcp --dport \"$CAM_PORT\" -s \"$lan\" "
            + "-m comment --comment \"$FW_TAG\" -j ACCEPT", joined);
        // Deletion is COMMENT-SCOPED: it matches only rules carrying our tag, so an identical rule WITHOUT
        // the tag (an admin's) is invisible to it and never removed.
        Assert.Contains(
            "iptables -D INPUT -i \"$CAM_IFACE\" -p tcp --dport \"$CAM_PORT\" -s \"$1\" "
            + "-m comment --comment \"$FW_TAG\" -j ACCEPT", joined);
        // EVERY iptables INPUT mutation carries the comment tag — there is NO untagged insert or delete
        // that could ever touch a foreign rule.
        foreach (var l in System.Text.RegularExpressions.Regex.Split(joined, "\n"))
        {
            if ((l.Contains("iptables -I INPUT") || l.Contains("iptables -D INPUT"))
                && l.Contains("-j ACCEPT"))
                Assert.Contains("-m comment --comment \"$FW_TAG\"", l);
        }
        // The applied subnet is remembered so close/DHCP-change delete exactly what open added.
        Assert.Contains(code, l => l.Contains("printf '%s' \"$lan\""));
        Assert.Contains(code, l => l.StartsWith("FW_STATE=") && l.Contains("/var/run/"));
    }

    [Fact]
    public void Keeps_state_and_the_installed_rule_consistent_under_failures()
    {
        // CodeRabbit/Codex: state and the installed rule must never diverge, under any single- or
        // compound-failure sequence.
        //  (1) open writes FW_STATE BEFORE inserting, so an installed tagged rule is ALWAYS covered by
        //      cleanup state — no failure at/after the insert can strand the port open with no cleanup
        //      target. A failed state write returns without inserting (fail closed), and because each open
        //      first deletes the prior rule, a mid-pass failure leaves the rule deleted, never stranded.
        //  (2) close forgets the rule ONLY once fw_installed confirms it is gone — a transient
        //      `iptables -D` failure keeps FW_STATE so a later pass retries instead of stranding the port.
        string s = ReadScript().Replace("\r\n", "\n");
        int oOpen = s.IndexOf("firewall_open()", System.StringComparison.Ordinal);
        int cOpen = s.IndexOf("firewall_close()", System.StringComparison.Ordinal);
        string openBody = s.Substring(oOpen, cOpen - oOpen);
        string closeBody = s.Substring(cOpen);
        // (1) The state write precedes the insert, and a failed write returns without inserting.
        int write = openBody.IndexOf("> \"$FW_STATE\"", System.StringComparison.Ordinal);
        int insert = openBody.IndexOf("iptables -I INPUT", System.StringComparison.Ordinal);
        Assert.True(write >= 0 && insert >= 0 && write < insert,
            "FW_STATE must be persisted before the rule is inserted");
        Assert.Contains("printf '%s' \"$lan\" > \"$FW_STATE\" 2>/dev/null || { rm -f \"$FW_STATE\"", openBody);
        // (2) close clears state ONLY once fw_gone confirms the rule is absent via a SUCCESSFUL listing —
        //     a failed `iptables -S` (inspection error) or a still-present rule keeps the state.
        Assert.Contains("fw_gone()", s);
        Assert.Contains("out=$(iptables -S INPUT 2>/dev/null) || return 1", s); // inspection error != absent
        Assert.Contains("fw_gone && rm -f \"$FW_STATE\"", closeBody);
        // (3) open confirms the PRIOR rule is gone before overwriting FW_STATE — else a DHCP change whose
        //     old-rule delete failed would orphan it. On failure it keeps the old state and returns.
        int prevDel = openBody.IndexOf("fw_del \"$(cat \"$FW_STATE\")\"", System.StringComparison.Ordinal);
        int confirm = openBody.IndexOf("fw_gone || return 0", System.StringComparison.Ordinal);
        Assert.True(prevDel >= 0 && confirm > prevDel && confirm < write,
            "open must confirm the prior rule gone (fw_gone || return 0) after deleting it and before rewriting state");
    }

    [Fact]
    public void Removes_any_prior_rule_before_opening_so_no_stale_rule_survives()
    {
        // Codex: if wlan0 changes subnet or loses its address, the previously-applied rule must be removed
        // (not left stranded to admit off-subnet sources on a new prefix). firewall_open deletes the prior
        // rule (its remembered subnet) first, and with no address it inserts nothing and clears state.
        string script = ReadScript().Replace("\r\n", "\n");
        int open = script.IndexOf("firewall_open()", System.StringComparison.Ordinal);
        int close = script.IndexOf("firewall_close()", System.StringComparison.Ordinal);
        Assert.True(open >= 0 && close > open);
        string body = script.Substring(open, close - open);
        // The prior rule is dropped (fw_del of the remembered subnet) before anything is inserted.
        int delPrev = body.IndexOf("fw_del \"$(cat \"$FW_STATE\")\"", System.StringComparison.Ordinal);
        int insert = body.IndexOf("iptables -I INPUT", System.StringComparison.Ordinal);
        Assert.True(delPrev >= 0 && insert >= 0);
        Assert.True(delPrev < insert, "the prior rule must be deleted before a new one is inserted");
        // With no address we bail WITHOUT inserting so the port stays closed, and the bail precedes insert.
        int noAddr = body.IndexOf("[ -z \"$lan\" ]", System.StringComparison.Ordinal);
        Assert.True(noAddr >= 0 && noAddr < insert, "the no-address bail must precede the insert");
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
