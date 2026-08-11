using System;
using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// Validation of the live-camera options in <see cref="MqttInstaller.Validate"/> (issue #103).
/// The fan-out target must be a hostname or an IPv4 literal (btmqttd's OWN `*7*300` frame is
/// IPv4-only), and the two UDP ports must be in range and distinct.
/// </summary>
public class MqttCameraValidationTests
{
    private static MqttOptions Cam(string? target, int video = 40000, int audio = 40002) =>
        new("broker.lan")
        {
            CameraEnabled = true,
            CameraTargetHost = target,
            CameraVideoPort = video,
            CameraAudioPort = audio,
        };

    [Theory]
    [InlineData(null)]              // blank → defaults to the broker host (pinned in /etc/hosts)
    [InlineData("broker.lan")]      // equals MqttHost → resolves via the broker's /etc/hosts pin
    [InlineData("192.168.1.9")]     // IPv4 literal → trivially resolvable on the device
    public void Accepts_blank_broker_host_or_ipv4(string? target)
    {
        MqttInstaller.Validate(Cam(target)); // must not throw
    }

    [Theory]
    [InlineData("127.0.0.1")]   // loopback — go2rtc/HA runs off-device; also collides with the
    [InlineData("127.1.2.3")]   // panel's own 127.0.0.1 media-start frames on the monitor
    [InlineData("0.0.0.0")]     // unspecified bind wildcard — not a routable receiver
    public void Rejects_a_loopback_or_unspecified_target(string target)
    {
        Assert.Throws<ArgumentException>(() => MqttInstaller.Validate(Cam(target)));
    }

    [Fact]
    public void Rejects_a_camera_target_pinned_to_loopback_openserver()
    {
        // "openserver" is the stock device alias the installer pins to 127.0.0.1. When it is the
        // broker host, a blank camera target defaults to it and would resolve to loopback on-device,
        // so the camera could never arm — the IP-literal loopback check can't see a hostname mapping.
        var opts = new MqttOptions("openserver") { CameraEnabled = true, CameraTargetHost = null };
        Assert.Throws<ArgumentException>(() => MqttInstaller.Validate(opts));
        // Case-insensitive, and also when set explicitly.
        var opts2 = new MqttOptions("broker.lan")
        {
            CameraEnabled = true,
            CameraTargetHost = "OpenServer",
        };
        Assert.Throws<ArgumentException>(() => MqttInstaller.Validate(opts2));
    }

    [Theory]
    [InlineData("ha.local")]              // a different LAN/mDNS name the device can't resolve
    [InlineData("homeassistant.local")]
    [InlineData("go2rtc.example.com")]
    public void Rejects_a_nonbroker_hostname_target(string target)
    {
        // The device pins only MQTT_HOST; any other hostname would never resolve, so it must be
        // rejected in favour of an IPv4 literal (or blank ⇒ the broker host).
        Assert.Throws<ArgumentException>(() => MqttInstaller.Validate(Cam(target)));
    }

    [Theory]
    [InlineData("::1")]             // IPv6 literal — av.rs resolves IPv4 only
    [InlineData("fe80::1")]
    [InlineData("http://ha.local")] // URL
    [InlineData("ha.local:1984")]   // host:port
    [InlineData("bad host")]        // space
    public void Rejects_ipv6_and_malformed_targets(string target)
    {
        Assert.Throws<ArgumentException>(() => MqttInstaller.Validate(Cam(target)));
    }

    [Theory]
    [InlineData(5000, 5000)]        // equal
    [InlineData(0, 40002)]          // out of range
    [InlineData(40000, 70000)]      // out of range
    public void Rejects_equal_or_out_of_range_ports(int video, int audio)
    {
        // Use an IPv4 target so it passes host validation and the throw is attributable to the
        // port checks (a hostname would fail the non-broker-target rule first).
        Assert.Throws<ArgumentException>(() => MqttInstaller.Validate(Cam("192.168.1.9", video, audio)));
    }

    [Fact]
    public void Disabled_camera_skips_camera_validation()
    {
        // A target that would be rejected when enabled is ignored when the camera is off — including
        // a would-be config-injecting multi-line value, which the disabled path never serializes.
        MqttInstaller.Validate(new MqttOptions("broker.lan")
        {
            CameraEnabled = false,
            CameraTargetHost = "x\nMQTT_HOST=bad",
        });
    }

    [Fact]
    public void On_device_mode_skips_the_off_device_target_checks()
    {
        // On-device (#120): the target is pinned to the loopback alias 127.0.0.2 (where the on-device
        // go2rtc listens), so the off-device "must be routable / not loopback / device-resolvable"
        // checks must NOT apply. EffectiveCameraTargetHost is 127.0.0.2 (loopback) yet Validate passes.
        // On-device RTSP auth is mandatory, so a valid on-device build supplies credentials.
        var opts = new MqttOptions("broker.lan")
        {
            CameraEnabled = true,
            CameraOnDevice = true,
            CameraRtspUser = "camera",
            CameraRtspPass = "s3cr3t",
        };
        Assert.Equal("127.0.0.2", opts.EffectiveCameraTargetHost);
        MqttInstaller.Validate(opts); // must not throw despite the loopback target

        // A stray CameraTargetHost is simply ignored on-device (not validated, not pinned).
        var opts2 = new MqttOptions("broker.lan")
        {
            CameraEnabled = true,
            CameraOnDevice = true,
            CameraTargetHost = "ha.local",   // would be rejected off-device; ignored here
            CameraRtspUser = "camera",
            CameraRtspPass = "s3cr3t",
        };
        MqttInstaller.Validate(opts2); // must not throw
    }

    [Fact]
    public void On_device_mode_still_validates_the_fan_out_ports()
    {
        // Build from OnDevice() so the required RTSP credentials are present — otherwise Validate could
        // throw for missing creds before it reaches the port checks, masking a port-validation regression.
        Assert.Throws<ArgumentException>(() =>
            MqttInstaller.Validate(OnDevice() with { CameraVideoPort = 5000, CameraAudioPort = 5000 }));
    }

    // A valid on-device build: RTSP auth is mandatory (#120), so both credentials must be set.
    private static MqttOptions OnDevice() => new("broker.lan")
    {
        CameraEnabled = true,
        CameraOnDevice = true,
        CameraRtspUser = "camera",
        CameraRtspPass = "s3cr3t",
    };

    [Fact]
    public void On_device_mode_requires_non_empty_rtsp_credentials()
    {
        MqttInstaller.Validate(OnDevice()); // both set → must not throw
        // go2rtc disables auth for a blank username, so an empty user OR pass is rejected.
        Assert.Throws<ArgumentException>(() => MqttInstaller.Validate(OnDevice() with { CameraRtspPass = null }));
        Assert.Throws<ArgumentException>(() => MqttInstaller.Validate(OnDevice() with { CameraRtspPass = "" }));
        Assert.Throws<ArgumentException>(() => MqttInstaller.Validate(OnDevice() with { CameraRtspUser = "" }));
    }

    [Theory]
    [InlineData("cam\nera", "s3cr3t")]      // LF
    [InlineData("camera", "s3\r\ncr3t")]    // CRLF
    [InlineData("camera", "s3\rcr3t")]      // CR
    [InlineData("cam\tera", "s3cr3t")]      // TAB
    [InlineData("camera", "s3\0cr3t")]      // NUL
    [InlineData("camera", "s3\u001bcr3t")]  // ESC
    public void On_device_mode_rejects_control_char_rtsp_credentials(string user, string pass)
    {
        // Any control char would land raw in the double-quoted YAML scalar (YamlDoubleQuoted escapes
        // only '\' and '"'), corrupting go2rtc.yaml — reject them all, not just CR/LF.
        Assert.Throws<ArgumentException>(() =>
            MqttInstaller.Validate(OnDevice() with { CameraRtspUser = user, CameraRtspPass = pass }));
    }

    [Fact]
    public void Off_device_mode_ignores_the_rtsp_credentials()
    {
        // The RTSP creds are used only on-device; an off-device camera build with blank creds is
        // valid (they never reach a config).
        MqttInstaller.Validate(new MqttOptions("192.168.1.9")
        {
            CameraEnabled = true,
            CameraTargetHost = "192.168.1.9",
            CameraRtspUser = "",
            CameraRtspPass = null,
        });
    }
}
