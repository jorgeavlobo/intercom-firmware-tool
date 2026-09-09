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

    private static string RingSnapshotJson(MqttOptions opts) =>
        MqttInstaller.GenerateHaDiscovery(opts, restoreFirewallEligible: false)
            .Single(e => e.FileName == "ring_snapshot.json").Json;

    [Fact]
    public void Ring_snapshot_image_is_emitted_on_device_even_without_on_demand()
    {
        // The ring capture needs NO SIP wake (a ring already has the panel streaming), so — unlike the
        // idle-refresh button — the image entity ships whenever the on-device camera is on, even with
        // on-demand OFF (issue #144).
        string json = RingSnapshotJson(new MqttOptions("broker.lan")
        {
            EnableHaDiscovery = true,
            CameraEnabled = true,
            CameraOnDevice = true,
            CameraOnDemand = false,
        });
        Assert.False(string.IsNullOrEmpty(json), "the image entity should carry a real payload on-device");
        Assert.Contains("Doorbell snapshot", json);
        Assert.Contains("ring_snapshot", json);
        // A url-topic image: bytes stay on the :8556 endpoint, only the id+url travel over MQTT, and the
        // per-event URL is resolved from the payload's `url`.
        Assert.Contains("url_topic", json);
        Assert.Contains("{{ value_json.url }}", json);
        // The discovery config carries NO device IP/URL — the daemon supplies it at runtime (issue #144).
        Assert.DoesNotContain("http", json);
    }

    [Fact]
    public void Ring_snapshot_image_survives_a_wildcard_command_topic()
    {
        // The image entity is READ-ONLY (no command topic), so it must ship even when TopicRx is a
        // wildcard filter — which makes ConcretePublishTopic return null and GenerateHaDiscovery take the
        // control-topic early return that only tombstones the command entities. Regression for the entity
        // being dropped from the manifest entirely in that path.
        string json = RingSnapshotJson(new MqttOptions("broker.lan")
        {
            EnableHaDiscovery = true,
            CameraEnabled = true,
            CameraOnDevice = true,
            TopicRx = "commands/#",
        });
        Assert.False(string.IsNullOrEmpty(json), "the read-only image entity must ship even with a wildcard TopicRx");
        Assert.Contains("Doorbell snapshot", json);
    }

    [Fact]
    public void Ring_snapshot_image_is_tombstoned_off_device()
    {
        // Off-device (classic go2rtc-on-HA) path: no on-box capture, so the image entity is tombstoned.
        Assert.Equal("", RingSnapshotJson(new MqttOptions("broker.lan")
        {
            EnableHaDiscovery = true,
            CameraEnabled = true,
            CameraOnDevice = false,
        }));
        // Camera feature off entirely: also tombstoned.
        Assert.Equal("", RingSnapshotJson(new MqttOptions("broker.lan")
        {
            EnableHaDiscovery = true,
            CameraEnabled = false,
            CameraOnDevice = true,
        }));
    }
}
