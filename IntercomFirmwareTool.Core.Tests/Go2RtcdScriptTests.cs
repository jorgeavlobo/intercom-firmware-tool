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
        Assert.Contains(code, l => l.Contains("[ -n \"$lan\" ]") && l.Contains("return 0"));
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
    public void Owns_its_rule_by_a_comment_tag_so_an_identical_foreign_rule_is_never_deleted()
    {
        // CodeRabbit (final): a full rule spec is a matcher, not an identity — an admin's byte-identical
        // :8554 LAN ACCEPT rule would be caught by a bare `-D`. So the rule carries an ownership TAG via
        // the iptables comment match, and cleanup deletes only rules bearing THAT comment. This is the
        // industry-standard approach (Docker/firewalld tag their rules the same way).
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
        // Tagged deletion is COMMENT-SCOPED: it matches only rules carrying our tag, so an identical rule
        // WITHOUT the tag (an admin's) is invisible to it and never removed.
        Assert.Contains(
            "iptables -D INPUT -i \"$CAM_IFACE\" -p tcp --dport \"$CAM_PORT\" -s \"$2\" "
            + "-m comment --comment \"$FW_TAG\" -j ACCEPT", joined);
        // Graceful fallback: on a kernel without xt_comment we still open the port with an untagged rule,
        // and manage it conservatively (untagged deletion removes a SINGLE instance — never a drain — so
        // we never remove more than we added).
        Assert.Contains(code, l => l.Trim() == "mode=tagged");
        Assert.Contains(code, l => l.Trim() == "mode=untagged");
        // State remembers "<mode> <subnet>" so close/DHCP-change delete exactly what open added.
        Assert.Contains(code, l => l.Contains("printf '%s %s\\n' \"$mode\" \"$lan\""));
        Assert.Contains(code, l => l.StartsWith("FW_STATE=") && l.Contains("/var/run/"));
    }

    [Fact]
    public void Removes_any_prior_rule_before_opening_so_no_stale_rule_survives()
    {
        // Codex: if wlan0 changes subnet or loses its address, the previously-applied rule must be removed
        // (not left stranded to admit off-subnet sources on a new prefix). firewall_open deletes the prior
        // rule (its remembered mode+subnet) first, and with no address it inserts nothing and clears state.
        string script = ReadScript().Replace("\r\n", "\n");
        int open = script.IndexOf("firewall_open()", System.StringComparison.Ordinal);
        int close = script.IndexOf("firewall_close()", System.StringComparison.Ordinal);
        Assert.True(open >= 0 && close > open);
        string body = script.Substring(open, close - open);
        // The prior rule is dropped (fw_del of the remembered mode+subnet) before anything is inserted.
        int delPrev = body.IndexOf("fw_del \"$pmode\" \"$psub\"", System.StringComparison.Ordinal);
        int insert = body.IndexOf("iptables -I INPUT", System.StringComparison.Ordinal);
        Assert.True(delPrev >= 0 && insert >= 0);
        Assert.True(delPrev < insert, "the prior rule must be deleted before a new one is inserted");
        // With no address we bail WITHOUT inserting (and clear the state) so the port stays closed.
        Assert.Contains(CodeLines(body), l => l.Contains("[ -n \"$lan\" ]") && l.Contains("return 0"));
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
