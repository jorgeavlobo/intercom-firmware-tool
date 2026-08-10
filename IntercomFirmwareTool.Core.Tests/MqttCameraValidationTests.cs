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
}
