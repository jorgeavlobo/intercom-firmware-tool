using System.IO;
using System.Linq;
using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// Guards the <c>bt_service_watchdog</c> payload against ever again supervising the
/// core BTicino services. An earlier version restarted the whole app stack with
/// <c>ensure scsserver /etc/init.d/bt_daemon-apps.sh start</c> whenever scsserver was
/// momentarily absent (e.g. during the boot-time Cortex-M0 wait). That spawned a
/// SECOND bt_daemon/openserver which collided with the first on the SCS socket
/// ("Create socket to SCS server failed") and took the screen and gate/intercom
/// controls down about one watchdog interval (~60s) after every boot — a near-brick.
/// The watchdog must only keep THIS TOOL's own daemons (dropbear, btmqttd) alive.
/// </summary>
public class WatchdogScriptTests
{
    private const string ResourceName =
        "IntercomFirmwareTool.Core.Payload.mqtt.bt_service_watchdog";

    private static string ReadWatchdog()
    {
        var asm = typeof(MqttOptions).Assembly; // any public Core type → the Core assembly
        using Stream? stream = asm.GetManifestResourceStream(ResourceName);
        Assert.NotNull(stream);
        using var reader = new StreamReader(stream!);
        return reader.ReadToEnd();
    }

    // Executable lines only: trim indentation and drop blank / comment lines, so a
    // mention of a command inside an explanatory comment neither trips a "must-not"
    // assertion nor satisfies a "must" one.
    private static string[] CodeLines(string script) =>
        script.Replace("\r\n", "\n").Split('\n')
              .Select(l => l.Trim())
              .Where(l => l.Length > 0 && !l.StartsWith('#'))
              .ToArray();

    [Fact]
    public void Watchdog_never_touches_the_core_bticino_services()
    {
        // Reject ANY executable reference to a core service, not just the exact legacy
        // command strings — a differently-spelled reintroduction must fail too. None of
        // the legitimate executable lines mention these (btmqttd is not bt_daemon).
        string[] code = CodeLines(ReadWatchdog());
        Assert.DoesNotContain(code, l =>
            l.Contains("scsserver") ||
            l.Contains("mosquitto") ||
            l.Contains("bt_daemon"));
    }

    [Fact]
    public void Watchdog_still_keeps_ssh_and_the_bridge_alive()
    {
        // Assert on executable lines so the supervision cannot be satisfied by a comment.
        string[] code = CodeLines(ReadWatchdog());
        Assert.Contains(code, l => l.Contains("ensure_dropbear"));
        Assert.Contains(code, l => l.Contains("/etc/init.d/btmqttd respawn"));
    }
}
