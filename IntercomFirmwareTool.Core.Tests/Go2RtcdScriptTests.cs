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

    [Fact]
    public void Opens_only_the_rtsp_media_port_least_privilege_lan_restricted()
    {
        // Phase 1c-3: open :8554 on the LAN interface, source-restricted to the interface's own subnet.
        // The control API (:1984) must NOT be opened, and no other port is touched.
        string s = ReadScript();
        string[] code = CodeLines(s);
        Assert.Contains("CAM_PORT=8554", s);
        Assert.Contains("CAM_IFACE=wlan0", s);
        // The ACCEPT lives in OUR chain (so cleanup never touches the panel's policy), matches a specific
        // tcp/dport on the interface, and is SOURCE-RESTRICTED to the derived LAN subnet.
        Assert.Contains(code, l =>
            l.Contains("iptables -A \"$FW_CHAIN\"")
            && l.Contains("-i \"$CAM_IFACE\"")
            && l.Contains("--dport \"$CAM_PORT\"")
            && l.Contains("-s \"$lan\"")
            && l.Contains("-j ACCEPT"));
        // INPUT jumps to our chain (inserted at the top, above the policy DROP).
        Assert.Contains(code, l => l.Contains("iptables -I INPUT -j \"$FW_CHAIN\""));
        // LAN source derived from the interface address at runtime; with no address yet the port is NOT
        // opened interface-wide (stays LAN-only) — skip until an address is present.
        Assert.Contains(code, l => l.Contains("ip -4 addr show \"$CAM_IFACE\""));
        Assert.Contains(code, l => l.Contains("[ -n \"$lan\" ] || return 0"));
        // The control API port is loopback-only — no executable line references 1984 (a comment may
        // mention it, so assert on code lines, not the whole script).
        Assert.DoesNotContain(code, l => l.Contains("1984"));
    }

    [Fact]
    public void Firewall_uses_its_own_chain_tied_to_the_running_daemon()
    {
        string[] code = CodeLines(ReadScript());
        // A dedicated chain owns our rules, so cleanup only flushes OUR chain — never unrelated INPUT rules.
        Assert.Contains(code, l => l == "FW_CHAIN=GO2RTC");
        Assert.Contains(code, l => l.Contains("iptables -F \"$FW_CHAIN\""));
        // The exception is tied to the daemon actually running (a failed launch leaves no open port),
        // and it is closed on stop/disable.
        Assert.Contains(code, l => l.Contains("if is_running; then firewall_open"));
        Assert.Contains(code, l => l.Contains("firewall_close"));
    }

    [Fact]
    public void Never_touches_a_foreign_chain_of_the_same_name()
    {
        // CodeRabbit: if a chain named GO2RTC already exists but wasn't created by us (it holds any rule
        // other than our tcp/:CAM_PORT ACCEPT), we must not flush it, add to it, or jump to it. Both
        // firewall_open and firewall_close gate on an ownership probe before touching the chain.
        string[] code = CodeLines(ReadScript());
        // An ownership probe exists and inspects the chain's rules for anything that isn't our ACCEPT.
        Assert.Contains(code, l => l.Contains("firewall_chain_is_ours()"));
        Assert.Contains(code, l => l.Contains("iptables -S \"$FW_CHAIN\""));
        // Both open and close bail out early when the chain is not ours (guard runs before any mutation).
        Assert.Equal(2, code.Count(l => l.Contains("firewall_chain_is_ours || return 0")));
    }

    [Fact]
    public void Flushes_the_chain_before_the_no_address_bailout_so_no_stale_rule_survives()
    {
        // Codex: if wlan0 loses its address after a rule was installed, returning early WITHOUT flushing
        // would leave a stale ACCEPT for the old subnet — which could admit off-subnet sources once the
        // address returns on a different prefix. The flush must precede the no-address return.
        string script = ReadScript().Replace("\r\n", "\n");
        int open = script.IndexOf("firewall_open()", System.StringComparison.Ordinal);
        int close = script.IndexOf("firewall_close()", System.StringComparison.Ordinal);
        Assert.True(open >= 0 && close > open);
        string body = script.Substring(open, close - open);
        int flush = body.IndexOf("iptables -F \"$FW_CHAIN\"", System.StringComparison.Ordinal);
        int noAddr = body.IndexOf("[ -n \"$lan\" ] || return 0", System.StringComparison.Ordinal);
        Assert.True(flush >= 0 && noAddr >= 0);
        Assert.True(flush < noAddr, "the chain flush must come before the no-address early return");
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
