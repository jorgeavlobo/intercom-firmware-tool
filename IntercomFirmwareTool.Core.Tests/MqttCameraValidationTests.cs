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
    [InlineData("ha.local")]        // hostname
    [InlineData("192.168.1.9")]     // IPv4 literal
    [InlineData(null)]              // blank → defaults to the (valid) broker host
    public void Accepts_hostname_ipv4_and_blank_target(string? target)
    {
        MqttInstaller.Validate(Cam(target)); // must not throw
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
        Assert.Throws<ArgumentException>(() => MqttInstaller.Validate(Cam("ha.local", video, audio)));
    }

    [Fact]
    public void Disabled_camera_skips_camera_validation()
    {
        // A target that would be rejected when enabled is ignored when the camera is off.
        MqttInstaller.Validate(new MqttOptions("broker.lan")
        {
            CameraEnabled = false,
            CameraTargetHost = "::1",
        });
    }
}
