using System.IO;
using System.Linq;
using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// Shape checks for the on-device go2rtc ifupdown <c>if-up.d</c> hook (<c>go2rtc-net-hook</c>, task #42).
/// It runs right AFTER the factory <c>if-pre-up.d/iptables</c> rebuild on ANY interface bring-up and
/// re-asserts the GO2RTC :8554 rule via <c>go2rtcd fw-reassert</c>, so boot / WiFi-reconnect restore the
/// port sequentially instead of the watchdog racing the factory's lock-less INPUT writes. The embedded
/// resource asserted here is the exact one the installer's <c>InstallOnDeviceMediaServer</c> writes (and
/// <c>ValidateMqtt</c> byte-compares) on the on-device camera path — so a missing/renamed resource would
/// break the install wiring, and this test fails loudly if it disappears.
/// </summary>
public class PayloadGo2RtcNetHookTests
{
    // The installer loads this same resource via LoadScript(ResourcePrefix + "go2rtc-net-hook") and writes
    // it to /etc/network/if-up.d/go2rtc, 0755 root:root, gated on the on-device camera path.
    private const string ResourceName =
        "IntercomFirmwareTool.Core.Payload.mqtt.go2rtc-net-hook";

    private static string ReadHook()
    {
        var asm = typeof(MqttOptions).Assembly; // any public Core type → the Core assembly
        using Stream? stream = asm.GetManifestResourceStream(ResourceName);
        Assert.NotNull(stream); // embedded → the installer's LoadScript can find it (install-wiring guard)
        using var reader = new StreamReader(stream!);
        return reader.ReadToEnd();
    }

    private static string[] CodeLines(string script) =>
        script.Replace("\r\n", "\n").Split('\n')
              .Select(l => l.Trim())
              .Where(l => l.Length > 0 && !l.StartsWith('#'))
              .ToArray();

    [Fact]
    public void Is_a_posix_sh_script()
    {
        string s = ReadHook();
        Assert.StartsWith("#!/bin/sh", s.Replace("\r\n", "\n"));
    }

    [Fact]
    public void Reasserts_after_every_interface_event_not_only_wlan0()
    {
        // The factory if-pre-up.d/iptables rebuilds the WHOLE INPUT chain on ANY interface bring-up, so
        // filtering to wlan0 would leave :8554 unreachable after e.g. a usb0 bring-up flushed INPUT — and
        // the periodic watchdog no longer re-asserts (task #42 / Codex). So the hook must NOT gate on
        // $IFACE; fw-reassert re-opens the wlan0 rule regardless of which interface's event fired it.
        string[] code = CodeLines(ReadHook());
        // Any form of an interface gate must fail this test, not just one exact spelling — a reintroduced
        // `[ "$IFACE" = wlan0 ]`, `case "$IFACE" in wlan0)`, etc. would still leave :8554 unreachable after
        // a non-wlan0 bring-up. So reject any executable line that references IFACE or a specific interface.
        Assert.DoesNotContain(code, l => l.Contains("IFACE"));
        Assert.DoesNotContain(code, l => l.Contains("wlan0"));
    }

    [Fact]
    public void Is_defensive_on_a_non_camera_image()
    {
        // On an image without go2rtcd (a non-camera build) there is no GO2RTC rule to re-assert: guard on
        // the init script being present AND executable, and exit 0 otherwise.
        string[] code = CodeLines(ReadHook());
        Assert.Contains(code, l => l.Contains("[ -x /etc/init.d/go2rtcd ]") && l.Contains("|| exit 0"));
    }

    [Fact]
    public void Reasserts_the_firewall_only_never_failing_the_bring_up()
    {
        // It calls the firewall-ONLY subcommand (never start/stop/restart/respawn — those launch/kill the
        // daemon), is best-effort (`|| true`, output discarded), and always exits 0 so it can never fail
        // an interface bring-up.
        string s = ReadHook();
        string[] code = CodeLines(s);
        Assert.Contains(code, l =>
            l.Contains("/etc/init.d/go2rtcd fw-reassert") && l.Contains(">/dev/null 2>&1 || true"));
        foreach (var verb in new[] { "start", "stop", "restart", "respawn" })
            Assert.DoesNotContain(code, l => l.Contains("go2rtcd " + verb));
        Assert.Contains(code, l => l == "exit 0");
    }
}
