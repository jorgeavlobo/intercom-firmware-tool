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
        // No CameraSprop set → the fmtp carries no sprop-parameter-sets (the ~20 s-first-frame fallback).
        Assert.Contains("a=fmtp:96 packetization-mode=1;profile-level-id=42801f", sdp);
        Assert.DoesNotContain("sprop-parameter-sets", sdp);
        // Connection pinned to the loopback alias 127.0.0.2 — ingest binds loopback, never the LAN.
        Assert.Contains("c=IN IP4 127.0.0.2", sdp);
        Assert.DoesNotContain("0.0.0.0", sdp);
        Assert.StartsWith("v=0\n", sdp);
        Assert.EndsWith("\n", sdp);
        Assert.DoesNotContain("\r", sdp);
    }

    [Fact]
    public void BuildOnDeviceSdp_embeds_sprop_parameter_sets_when_configured()
    {
        // With CameraSprop set (issue #120), the panel's SPS/PPS go into the fmtp line between
        // packetization-mode and profile-level-id, so go2rtc's `-c:v copy` ffmpeg resolves 640x480
        // in <1 s instead of waiting ~20 s for the panel's next in-stream keyframe.
        var opts = new MqttOptions("broker.lan")
        {
            CameraEnabled = true,
            CameraOnDevice = true,
            CameraVideoPort = 40000,
            CameraAudioPort = 40002,
            CameraSprop = "Z0JAHqaAoD2Q,aM48gAA=",
        };
        string sdp = Go2RtcConfig.BuildOnDeviceSdp(opts);
        Assert.Contains(
            "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0JAHqaAoD2Q,aM48gAA=;profile-level-id=42801f",
            sdp);
    }

    [Fact]
    public void BuildOnDeviceYaml_loopback_api_lan_rtsp_with_auth_and_video_only_stream()
    {
        string yaml = Go2RtcConfig.BuildOnDeviceYaml(
            "Front Door", "/usr/sbin/ffmpeg", "camera", "s3cr3t");
        // Control API + web UI: loopback ONLY, never the LAN.
        Assert.Contains("api:", yaml);
        Assert.Contains("listen: \"127.0.0.1:1984\"", yaml);
        Assert.DoesNotContain("0.0.0.0:1984", yaml);
        // RTSP: served on the LAN with mandatory auth.
        Assert.Contains("rtsp:", yaml);
        Assert.Contains("listen: \":8554\"", yaml);
        Assert.Contains("username: \"camera\"", yaml);
        Assert.Contains("password: \"s3cr3t\"", yaml);
        // Stream: sanitized key, absolute ffmpeg path, video-only H.264 copy. The exec -i reads the
        // tmpfs RUNTIME SDP (go2rtcd reassembles it at boot), NOT the read-only /etc template — the
        // rootfs is read-only, so go2rtc + sprop.rs both use /var/run/btmqttd/doorbell.sdp.
        Assert.Contains("  frontdoor:", yaml);
        Assert.Contains("exec:/usr/sbin/ffmpeg", yaml);
        Assert.Contains("-i /var/run/btmqttd/doorbell.sdp", yaml);
        Assert.DoesNotContain("-i /etc/btmqttd/go2rtc/", yaml);
        // Plain `-c:v copy` with default input options (issue #120, hardware-diagnosed on the C100X). The
        // vendored ffmpeg's H.264 parser recovers the SPS/PPS from the in-stream data, so the copy gets
        // its dimensions and publishes without any jitter-buffer tuning. An earlier revision widened
        // -reorder_queue_size/-max_delay to catch the sparse in-stream SPS/PPS, but the loopback ingest
        // never reorders, so that oversized queue made ffmpeg drop every packet as "received too late" and
        // 404 — reverting to defaults locks on in under a second. Guard that the harmful tuning and the
        // (now-removed) extract_extradata/dump_extra bitstream filters stay OUT of the generated exec.
        Assert.Contains("-i /var/run/btmqttd/doorbell.sdp -an -c:v copy -rtsp_transport tcp -f rtsp", yaml);
        // A SECOND output on the SAME live-view ffmpeg ships a raw H.264 RTP copy to btmqttd (sprop
        // learning, #120 / PR #129): sprop.rs binds this loopback port and parses the panel's in-band
        // SPS/PPS from the RTP payload — ffmpeg's -sdp_file can't emit sprop on a copy path (hardware-
        // confirmed), so there is NO derived.sdp any more.
        Assert.Contains(
            "-f rtsp {output} -c:v copy -f rtp rtp://127.0.0.1:40100",
            yaml);
        Assert.DoesNotContain("-sdp_file", yaml);
        Assert.DoesNotContain("derived.sdp", yaml);
        Assert.DoesNotContain("-reorder_queue_size", yaml);
        Assert.DoesNotContain("-max_delay", yaml);
        Assert.DoesNotContain("-analyzeduration", yaml);
        Assert.DoesNotContain("-bsf", yaml);
        Assert.Contains("{output}", yaml);
        Assert.DoesNotContain("\r", yaml);
    }

    [Fact]
    public void BuildOnDeviceYaml_escapes_special_chars_in_credentials()
    {
        // A generated/typed credential may contain YAML-special punctuation; double-quoted scalars
        // must escape a backslash and a double-quote so the file stays valid.
        string yaml = Go2RtcConfig.BuildOnDeviceYaml(
            "doorbell", "/usr/sbin/ffmpeg", "u\"x", "p\\y");
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
            Go2RtcConfig.BuildOnDeviceYaml("doorbell", "/usr/sbin/ffmpeg", user!, pass!));
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
            Go2RtcConfig.BuildOnDeviceYaml("doorbell", "/usr/sbin/ffmpeg", user, pass));
    }

    [Fact]
    public void BuildOnDeviceSetupGuide_shows_the_rtsp_url_with_credentials()
    {
        var opts = new MqttOptions("broker.lan")
        {
            CameraEnabled = true,
            CameraOnDevice = true,
            CameraRtspUser = "camera",
            CameraRtspPass = "s3cr3t",
        };
        string guide = Go2RtcConfig.BuildOnDeviceSetupGuide(opts, "Front Door");
        // The HA Generic Camera URL: creds embedded, sanitized stream name, on-device RTSP port.
        Assert.Contains("rtsp://camera:s3cr3t@<intercom-ip>:8554/frontdoor", guide);
        Assert.Contains("username: camera", guide);
        Assert.Contains("password: s3cr3t", guide);
        // The Still Image URL (issue #168): the cheap idle JPEG HA polls for the camera thumbnail, on the
        // on-device still port, with NO credentials in the URL.
        Assert.Contains("Still Image URL", guide);
        Assert.Contains("http://<intercom-ip>:8556/idle.jpg", guide);
        // The loopback-only API is called out; no HA-side go2rtc.
        Assert.Contains("127.0.0.1:1984", guide);
        Assert.DoesNotContain("\r", guide);
    }

    [Fact]
    public void BuildOnDeviceSetupGuide_documents_the_idle_button_and_ring_notification()
    {
        // #169: the guide explains the real captured idle thumbnail + the "Update idle snapshot" button,
        // and gives the transient ring snapshot URL plus an HA automation recipe for the ring push.
        var opts = new MqttOptions("broker.lan")
        {
            CameraEnabled = true,
            CameraOnDevice = true,
            CameraRtspUser = "camera",
            CameraRtspPass = "s3cr3t",
        };
        string guide = Go2RtcConfig.BuildOnDeviceSetupGuide(opts, "doorbell");
        // The idle thumbnail is a real captured view, refreshable via the HA button.
        Assert.Contains("Update idle snapshot", guide);
        // The ring snapshot lives on its own transient URL, on the still port (issue #169).
        Assert.Contains("http://<intercom-ip>:8556/ring.jpg", guide);
        // The ring-notification automation triggers on the ring-snapshot-READY topic (published only
        // after the frame is written), so it never fires on a fixed delay that a cold capture outlasts.
        Assert.Contains(opts.EffectiveTopicRingSnapshot, guide);
        Assert.DoesNotContain("delay:", guide);
        // The raw ring event topic is still mentioned (for automations that just need the ring signal).
        Assert.Contains(opts.EffectiveTopicEntrancePanelCall, guide);
        Assert.Contains("notify.mobile_app", guide);
        Assert.DoesNotContain("\r", guide);
    }

    [Fact]
    public void BuildOnDeviceSetupGuide_yaml_escapes_a_ring_topic_with_quote_or_backslash()
    {
        // Topic validation permits '"' and '\' (only newlines and MQTT wildcards are rejected), so a
        // library caller could supply one; the ring-notification recipe interpolates the topic into a
        // double-quoted YAML scalar, which must escape those two characters or the paste-ready automation
        // breaks / subscribes to a different topic.
        var opts = new MqttOptions("broker.lan")
        {
            CameraEnabled = true,
            CameraOnDevice = true,
            CameraRtspUser = "camera",
            CameraRtspPass = "s3cr3t",
            TopicRingSnapshot = "Bticino/ring\"\\snap",
        };
        string guide = Go2RtcConfig.BuildOnDeviceSetupGuide(opts, "doorbell");
        // The YAML trigger line carries the escaped form inside the double quotes...
        Assert.Contains("topic: \"Bticino/ring\\\"\\\\snap\"", guide);
        // ...and never the raw, unescaped topic (which would terminate the scalar early).
        Assert.DoesNotContain("\"Bticino/ring\"\\snap\"", guide);
    }

    [Fact]
    public void BuildOnDeviceSetupGuide_keeps_the_password_placeholder_readable_when_unset()
    {
        // With no password set (a bare/library caller — the App always sets one on-device), the URL must
        // keep the <password> placeholder LITERAL (not %3Cpassword%3E from URL-encoding) and the
        // instructions must tell the user to replace it.
        var opts = new MqttOptions("broker.lan")
        {
            CameraEnabled = true,
            CameraOnDevice = true,
            CameraRtspUser = "camera",
            CameraRtspPass = null,
        };
        string guide = Go2RtcConfig.BuildOnDeviceSetupGuide(opts, "doorbell");
        Assert.Contains("rtsp://camera:<password>@<intercom-ip>:8554/doorbell", guide);
        Assert.DoesNotContain("%3C", guide);   // placeholder not URL-encoded
        Assert.Contains("<password> with the RTSP password", guide);
    }

    [Fact]
    public void OnDeviceStreamName_is_stable_so_the_guide_url_matches_the_installed_stream()
    {
        // The installer always writes the on-device go2rtc stream under MqttInstaller.OnDeviceStreamName,
        // so the App must build the Home Assistant URL from THAT exact name (not the HA node id, which
        // would point at a nonexistent stream). Guard: the name is an already-sanitized stable token and
        // the guide URL ends in it.
        Assert.Equal(MqttInstaller.OnDeviceStreamName,
            Go2RtcConfig.SanitizeStreamName(MqttInstaller.OnDeviceStreamName));
        var opts = new MqttOptions("broker.lan")
        {
            CameraEnabled = true,
            CameraOnDevice = true,
            CameraRtspUser = "camera",
            CameraRtspPass = "s3cr3t",
        };
        string guide = Go2RtcConfig.BuildOnDeviceSetupGuide(opts, MqttInstaller.OnDeviceStreamName);
        Assert.Contains(":8554/" + MqttInstaller.OnDeviceStreamName + "\n", guide);
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
        // leaves ffmpeg auto-selecting and failing to decode the SDP's audio stream).
        Assert.Contains("`-an`", guide);
    }
}
