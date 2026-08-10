using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// Serialization of <c>CAMERA_TARGET_HOST</c> in the generated device <c>btmqttd.conf</c>
/// (issue #111). The locked default must reach the device BLANK so config.rs falls back to
/// <c>MQTT_HOST</c> and av.rs re-resolves the target each session (following Home Assistant to a
/// new IP without a reflash); only an explicit override is pinned. Reading back
/// <see cref="MqttInstaller.GenerateConf"/> — the byte-exact conf the installer writes — is a true
/// check that the App's <c>CameraTargetHost == null</c> is not silently promoted to the broker host.
/// </summary>
public class MqttCameraConfTests
{
    [Fact]
    public void Locked_enabled_camera_writes_an_empty_target()
    {
        // Default (locked) path: the App leaves CameraTargetHost null to mean "follow the broker
        // host". That MUST serialize blank — NOT the resolved MqttHost — so the device defers to
        // MQTT_HOST and tracks it.
        var conf = MqttInstaller.GenerateConf(new MqttOptions("broker.lan")
        {
            CameraEnabled = true,
            CameraTargetHost = null,
        });
        Assert.Contains("CAMERA_TARGET_HOST=''\n", conf);
        Assert.DoesNotContain("CAMERA_TARGET_HOST='broker.lan'\n", conf);
    }

    [Fact]
    public void Overridden_camera_pins_the_explicit_host()
    {
        // Override path: a distinct IPv4 the user entered is written verbatim (pinned).
        var conf = MqttInstaller.GenerateConf(new MqttOptions("broker.lan")
        {
            CameraEnabled = true,
            CameraTargetHost = "192.168.1.9",
        });
        Assert.Contains("CAMERA_TARGET_HOST='192.168.1.9'\n", conf);
    }

    [Theory]
    [InlineData("broker.lan")]  // exactly the broker host
    [InlineData("BROKER.LAN")]  // case-only difference — still redundant
    public void A_target_equal_to_the_broker_host_writes_empty(string target)
    {
        // A target that just repeats the broker host is redundant: serialize blank so the device
        // follows MQTT_HOST like the locked default, instead of pinning the literal (Copilot). The
        // comparison is case-insensitive, matching the App validator and MqttInstaller.
        var conf = MqttInstaller.GenerateConf(new MqttOptions("broker.lan")
        {
            CameraEnabled = true,
            CameraTargetHost = target,
        });
        Assert.Contains("CAMERA_TARGET_HOST=''\n", conf);
    }

    [Fact]
    public void Disabled_camera_writes_an_empty_target()
    {
        // Camera off: the target is irrelevant (av.rs never arms) and is never serialized — even a
        // value that is set — so a stray multi-line paste can't inject a second KEY=value line.
        var conf = MqttInstaller.GenerateConf(new MqttOptions("broker.lan")
        {
            CameraEnabled = false,
            CameraTargetHost = "192.168.1.9",
        });
        Assert.Contains("CAMERA_TARGET_HOST=''\n", conf);
    }
}
