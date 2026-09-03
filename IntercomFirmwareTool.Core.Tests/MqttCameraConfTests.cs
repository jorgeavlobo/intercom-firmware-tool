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
        // follows MQTT_HOST like the locked default, instead of pinning the literal. The
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
        // Camera off: the target is irrelevant (av.rs never arms). The CAMERA_TARGET_HOST line is
        // still emitted, but its value is forced empty — the user's value is never written — so a
        // stray multi-line paste can't inject a second KEY=value line.
        var conf = MqttInstaller.GenerateConf(new MqttOptions("broker.lan")
        {
            CameraEnabled = false,
            CameraTargetHost = "192.168.1.9",
        });
        Assert.Contains("CAMERA_TARGET_HOST=''\n", conf);
    }

    [Fact]
    public void On_device_mode_emits_the_flag_and_leaves_the_target_blank()
    {
        // On-device (#120): CAMERA_ONDEVICE=1, and CAMERA_TARGET_HOST stays blank — config.rs pins the
        // siphon to 127.0.0.2 and ignores the target host in this mode, even if one was set.
        var conf = MqttInstaller.GenerateConf(new MqttOptions("broker.lan")
        {
            CameraEnabled = true,
            CameraOnDevice = true,
            CameraTargetHost = "192.168.1.9",   // ignored on-device
        });
        Assert.Contains("CAMERA_ONDEVICE=1\n", conf);
        Assert.Contains("CAMERA_TARGET_HOST=''\n", conf);
    }

    [Fact]
    public void Conf_writes_the_ring_snapshot_ready_topic()
    {
        // #169: btmqttd publishes a "ring snapshot ready" signal (carrying the event id) after writing
        // that event's ring-<id>.jpg; the topic is written to the conf (default derived from the LWT
        // namespace) so the daemon and the HA recipe agree on it.
        var conf = MqttInstaller.GenerateConf(new MqttOptions("broker.lan") { CameraEnabled = true });
        Assert.Contains("TOPIC_RING_SNAPSHOT=", conf);
        var custom = MqttInstaller.GenerateConf(new MqttOptions("broker.lan")
        {
            TopicRingSnapshot = "home/i42/ring_snap",
        });
        Assert.Contains("TOPIC_RING_SNAPSHOT='home/i42/ring_snap'\n", custom);
    }

    [Fact]
    public void On_device_mode_writes_the_rtsp_credentials_for_capture()
    {
        // #169: the still-capture helper reads rtsp://<user>:<pass>@127.0.0.1:8554/doorbell, so the go2rtc
        // RTSP creds are written to the device conf (single-quoted) on-device.
        var conf = MqttInstaller.GenerateConf(new MqttOptions("broker.lan")
        {
            CameraEnabled = true,
            CameraOnDevice = true,
            CameraRtspUser = "camera",
            CameraRtspPass = "s3cret-_",
        });
        Assert.Contains("CAMERA_RTSP_USER='camera'\n", conf);
        Assert.Contains("CAMERA_RTSP_PASS='s3cret-_'\n", conf);
    }

    [Fact]
    public void Off_device_or_credential_less_mode_omits_the_rtsp_credentials()
    {
        // The capture path exists only on-device: an off-device conf writes neither RTSP key...
        var off = MqttInstaller.GenerateConf(new MqttOptions("broker.lan")
        {
            CameraEnabled = true,
            CameraRtspPass = "s3cret",
        });
        Assert.DoesNotContain("CAMERA_RTSP_USER=", off);
        Assert.DoesNotContain("CAMERA_RTSP_PASS=", off);
        // ...and an on-device flag with no password wired (a bare/library caller) writes neither rather
        // than emitting a half credential.
        var noPass = MqttInstaller.GenerateConf(new MqttOptions("broker.lan")
        {
            CameraEnabled = true,
            CameraOnDevice = true,
        });
        Assert.DoesNotContain("CAMERA_RTSP_USER=", noPass);
        Assert.DoesNotContain("CAMERA_RTSP_PASS=", noPass);
    }

    [Fact]
    public void On_device_flag_is_gated_on_the_camera_being_enabled()
    {
        // Default off-device path emits CAMERA_ONDEVICE=0.
        var off = MqttInstaller.GenerateConf(new MqttOptions("broker.lan") { CameraEnabled = true });
        Assert.Contains("CAMERA_ONDEVICE=0\n", off);
        // On-device requires the media path: a stray on-device flag with the camera OFF reads as 0.
        var strayOff = MqttInstaller.GenerateConf(new MqttOptions("broker.lan")
        {
            CameraEnabled = false,
            CameraOnDevice = true,
        });
        Assert.Contains("CAMERA_ONDEVICE=0\n", strayOff);
    }
}
