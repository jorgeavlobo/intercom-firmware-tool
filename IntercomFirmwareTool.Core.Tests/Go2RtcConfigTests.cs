using System;
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
    public void BuildOnDeviceSdp_is_video_only_and_binds_the_loopback_alias()
    {
        string sdp = Go2RtcConfig.BuildOnDeviceSdp(Opts(video: 40000, audio: 40002));
        // Video only — the vendored on-device ffmpeg has no audio codecs until Phase 3 (#105).
        Assert.Contains("m=video 40000 RTP/AVP 96", sdp);
        Assert.DoesNotContain("m=audio", sdp);
        Assert.Contains("a=rtpmap:96 H264/90000", sdp);
        Assert.Contains("a=fmtp:96 packetization-mode=1;profile-level-id=42801f", sdp);
        // Connection pinned to the loopback alias 127.0.0.2 — ingest binds loopback, never the LAN.
        Assert.Contains("c=IN IP4 127.0.0.2", sdp);
        Assert.DoesNotContain("0.0.0.0", sdp);
        Assert.StartsWith("v=0\n", sdp);
        Assert.EndsWith("\n", sdp);
        Assert.DoesNotContain("\r", sdp);
    }

    [Fact]
    public void BuildOnDeviceYaml_loopback_api_lan_rtsp_with_auth_and_video_only_stream()
    {
        string yaml = Go2RtcConfig.BuildOnDeviceYaml(
            "Front Door", "/usr/sbin/ffmpeg", "/etc/btmqttd/go2rtc/frontdoor.sdp",
            "camera", "s3cr3t");
        // Control API + web UI: loopback ONLY, never the LAN.
        Assert.Contains("api:", yaml);
        Assert.Contains("listen: \"127.0.0.1:1984\"", yaml);
        Assert.DoesNotContain("0.0.0.0:1984", yaml);
        // RTSP: served on the LAN with mandatory auth.
        Assert.Contains("rtsp:", yaml);
        Assert.Contains("listen: \":8554\"", yaml);
        Assert.Contains("username: \"camera\"", yaml);
        Assert.Contains("password: \"s3cr3t\"", yaml);
        // Stream: sanitized key, absolute ffmpeg + SDP paths, video-only H.264 copy.
        Assert.Contains("  frontdoor:", yaml);
        Assert.Contains("exec:/usr/sbin/ffmpeg", yaml);
        Assert.Contains("-i /etc/btmqttd/go2rtc/frontdoor.sdp", yaml);
        Assert.Contains("-an -c:v copy", yaml);
        Assert.Contains("{output}", yaml);
        Assert.DoesNotContain("\r", yaml);
    }

    [Fact]
    public void BuildOnDeviceYaml_escapes_special_chars_in_credentials()
    {
        // A generated/typed credential may contain YAML-special punctuation; double-quoted scalars
        // must escape a backslash and a double-quote so the file stays valid.
        string yaml = Go2RtcConfig.BuildOnDeviceYaml(
            "doorbell", "/usr/sbin/ffmpeg", "/x.sdp", "u\"x", "p\\y");
        Assert.Contains("username: \"u\\\"x\"", yaml);
        Assert.Contains("password: \"p\\\\y\"", yaml);
    }

    [Theory]
    [InlineData(null, "pass")]
    [InlineData("", "pass")]
    [InlineData("user", null)]
    [InlineData("user", "")]
    public void BuildOnDeviceYaml_rejects_empty_credentials(string? user, string? pass)
    {
        // RTSP is LAN-facing and auth is mandatory (#120): go2rtc skips auth for a blank username, so
        // an empty credential opens the stream unauthenticated. The builder must refuse it outright.
        Assert.Throws<ArgumentException>(() =>
            Go2RtcConfig.BuildOnDeviceYaml("doorbell", "/usr/sbin/ffmpeg", "/x.sdp", user!, pass!));
    }

    [Theory]
    [InlineData("u\nx", "pass")]    // LF
    [InlineData("user", "p\rq")]    // CR
    [InlineData("user", "p\r\nq")]  // CRLF
    [InlineData("us\tr", "pass")]   // TAB
    [InlineData("user", "p\0q")]    // NUL
    [InlineData("user", "p\u001bq")] // ESC
    public void BuildOnDeviceYaml_rejects_control_chars_in_credentials(string user, string pass)
    {
        // YamlDoubleQuoted escapes only '\' and '"', so ANY control character would land raw in the
        // double-quoted YAML scalar and corrupt the file — reject them all, not just CR/LF.
        Assert.Throws<ArgumentException>(() =>
            Go2RtcConfig.BuildOnDeviceYaml("doorbell", "/usr/sbin/ffmpeg", "/x.sdp", user, pass));
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
