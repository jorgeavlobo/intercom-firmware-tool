using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// Pure-logic tests for the go2rtc config generator (issue #103). No I/O, no network — the class is a
/// deterministic text builder, so these lock in the SDP/YAML shape the daemon's RTP fan-out requires.
/// </summary>
public class Go2RtcConfigTests
{
    private static MqttOptions Opts(int video = 40000, int audio = 40002, string? target = null) =>
        new("broker.lan")
        {
            CameraEnabled = true,
            CameraTargetHost = target,
            CameraVideoPort = video,
            CameraAudioPort = audio,
        };

    [Theory]
    [InlineData(null, "doorbell")]
    [InlineData("", "doorbell")]
    [InlineData("   ", "doorbell")]
    [InlineData("Front Door", "frontdoor")]
    [InlineData("gate-1", "gate-1")]
    [InlineData("Câmara!!", "cmara")]   // non-ASCII and punctuation dropped
    [InlineData("***", "doorbell")]      // all-invalid falls back
    public void SanitizeStreamName_keeps_only_the_safe_subset(string? input, string expected)
    {
        Assert.Equal(expected, Go2RtcConfig.SanitizeStreamName(input));
    }

    [Fact]
    public void BuildSdp_carries_the_configured_ports_and_verified_codecs()
    {
        string sdp = Go2RtcConfig.BuildSdp(Opts(video: 41000, audio: 41002));

        // The two RTP media lines carry the configured fan-out ports and the dynamic payload types.
        Assert.Contains("m=video 41000 RTP/AVP 96", sdp);
        Assert.Contains("m=audio 41002 RTP/AVP 110", sdp);
        // Firmware-verified codec parameters.
        Assert.Contains("a=rtpmap:96 H264/90000", sdp);
        Assert.Contains("a=fmtp:96 packetization-mode=1;profile-level-id=42801f", sdp);
        Assert.Contains("a=rtpmap:110 speex/8000", sdp);
        // Well-formed SDP: starts with the protocol version, LF line endings, trailing newline.
        Assert.StartsWith("v=0\n", sdp);
        Assert.EndsWith("\n", sdp);
        Assert.DoesNotContain("\r", sdp);
    }

    [Fact]
    public void BuildStreamsYaml_uses_the_sanitized_name_and_reads_the_sdp()
    {
        string yaml = Go2RtcConfig.BuildStreamsYaml(Opts(), "Front Door", "/config/go2rtc/frontdoor.sdp");
        Assert.Contains("streams:", yaml);
        Assert.Contains("  frontdoor:", yaml);              // sanitized key
        Assert.Contains("-protocol_whitelist file,udp,rtp", yaml);
        Assert.Contains("-i /config/go2rtc/frontdoor.sdp", yaml);
        Assert.Contains("-c:v copy", yaml);                 // H.264 passthrough
        Assert.Contains("{output}", yaml);                  // go2rtc RTSP sink placeholder
    }

    [Fact]
    public void BuildSetupGuide_defaults_the_target_to_the_broker_host()
    {
        // Target null → EffectiveCameraTargetHost falls back to MqttHost.
        string guide = Go2RtcConfig.BuildSetupGuide(Opts(target: null), "doorbell");
        Assert.Contains("broker.lan", guide);
        Assert.Contains("/config/go2rtc/doorbell.sdp", guide);
        // Explicit target wins.
        string guide2 = Go2RtcConfig.BuildSetupGuide(Opts(target: "192.168.1.9"), "doorbell");
        Assert.Contains("192.168.1.9", guide2);
        // The video-only fallback must instruct `-an` (deleting the audio encoder flags alone
        // leaves ffmpeg auto-selecting and failing to decode the SDP's audio stream) — Codex.
        Assert.Contains("`-an`", guide);
    }
}
