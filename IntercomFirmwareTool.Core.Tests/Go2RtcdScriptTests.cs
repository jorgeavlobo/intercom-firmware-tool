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
        // Phase 1c-3: open :8554 on the LAN interface, at the TOP of INPUT (above the panel's policy
        // DROP), source-restricted to the interface's own subnet. The control API (:1984) must NOT be
        // opened, and no other port is touched.
        string s = ReadScript();
        string[] code = CodeLines(s);
        Assert.Contains("CAM_PORT=8554", s);
        Assert.Contains("CAM_IFACE=wlan0", s);
        // Insert (not append) so it sits above the DROP; a specific tcp/dport ACCEPT on the interface.
        Assert.Contains(code, l =>
            l.Contains("iptables -I INPUT")
            && l.Contains("-i \"$CAM_IFACE\"")
            && l.Contains("--dport \"$CAM_PORT\"")
            && l.Contains("-j ACCEPT"));
        // LAN source restriction is derived from the interface address at runtime (DHCP-proof).
        Assert.Contains(code, l => l.Contains("ip -4 addr show \"$CAM_IFACE\""));
        Assert.Contains(code, l => l.Contains("src=\"-s $lan\""));
        // The control API port is loopback-only — never opened in the firewall.
        Assert.DoesNotContain("1984", s);
    }

    [Fact]
    public void Firewall_is_reasserted_when_enabled_and_removed_when_stopped()
    {
        // respawn (every watchdog pass) re-opens the port when enabled and closes it when disabled;
        // start opens it; stop closes it. Asserted on executable lines so a comment can't satisfy them.
        string[] code = CodeLines(ReadScript());
        Assert.Contains(code, l => l == "firewall_open");
        Assert.Contains(code, l => l == "firewall_close");
        // The flush deletes existing :8554 rules so re-assert/subnet-change stays idempotent.
        Assert.Contains(code, l => l.Contains("iptables -S INPUT") && l.Contains("--dport $CAM_PORT"));
        Assert.Contains(code, l => l.Contains("sed 's/^-A /-D /'"));
    }
}
