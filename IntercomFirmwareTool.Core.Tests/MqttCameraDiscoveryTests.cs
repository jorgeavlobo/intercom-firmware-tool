using System.Linq;
using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// The on-device camera Home Assistant discovery entities (issue #169): the "Update idle snapshot"
/// button is emitted with a real payload only when the on-device camera AND on-demand viewing are both
/// on (capturing an idle panel means WAKING it via the SIP UA first, which needs on-demand); otherwise
/// its config is tombstoned (empty payload) so a previous build's button is cleared from HA rather than
/// lingering as a dead control — the same posture as the "View/Stop Camera" buttons.
/// </summary>
public class MqttCameraDiscoveryTests
{
    private static string UpdateIdleJson(MqttOptions opts) =>
        MqttInstaller.GenerateHaDiscovery(opts, restoreFirewallEligible: false)
            .Single(e => e.FileName == "update_idle.json").Json;

    [Fact]
    public void Update_idle_button_is_present_on_device_with_ondemand()
    {
        var json = UpdateIdleJson(new MqttOptions("broker.lan")
        {
            EnableHaDiscovery = true,
            CameraEnabled = true,
            CameraOnDevice = true,
            CameraOnDemand = true,
            CameraRtspPass = "s3cr3t",
        });
        Assert.False(string.IsNullOrEmpty(json), "the button should carry a real payload on-device+ondemand");
        // The human name, the object id, and the command payload action are all present.
        Assert.Contains("Update idle snapshot", json);
        Assert.Contains("update_idle", json);
        Assert.Contains("payload_press", json);
    }

    [Fact]
    public void Update_idle_button_is_tombstoned_when_prerequisites_are_missing()
    {
        // On-demand OFF: an idle panel can't be woken to photograph, so the button is tombstoned.
        Assert.Equal("", UpdateIdleJson(new MqttOptions("broker.lan")
        {
            EnableHaDiscovery = true,
            CameraEnabled = true,
            CameraOnDevice = true,
            CameraOnDemand = false,
            CameraRtspPass = "s3cr3t",
        }));
        // Off-device (classic go2rtc-on-HA) path: no on-box capture, so the button is tombstoned.
        Assert.Equal("", UpdateIdleJson(new MqttOptions("broker.lan")
        {
            EnableHaDiscovery = true,
            CameraEnabled = true,
            CameraOnDemand = true,
        }));
    }
}
