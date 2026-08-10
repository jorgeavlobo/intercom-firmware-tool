using System.Globalization;
using System.Text;

namespace IntercomFirmwareTool.Core
{
    /// <summary>
    /// Generates the off-device <a href="https://github.com/AlexxIT/go2rtc">go2rtc</a> configuration
    /// that turns btmqttd's live-camera RTP fan-out (issue #103) into a Home Assistant camera.
    ///
    /// <para>The daemon (<c>av.rs</c>) does NOT transcode: on every panel A/V session it asks the
    /// on-board <c>bt_av_media</c> daemon to also send a cleartext RTP copy of the entrance camera to
    /// <c>CAMERA_TARGET_HOST:CAMERA_VIDEO_PORT</c> (H.264) and <c>…:CAMERA_AUDIO_PORT</c> (speex). Those
    /// are raw RTP streams with no signalling, so the receiver must be told their shape out-of-band —
    /// an <b>SDP</b>. go2rtc ingests the SDP (via ffmpeg), copies the H.264 through untouched, and (best
    /// effort) transcodes the speex audio to a WebRTC-friendly codec, then republishes it as a stream
    /// Home Assistant adds as a WebRTC/RTSP camera.</para>
    ///
    /// <para>This class is a pure text generator — it performs no I/O. The App shows the result so the
    /// user can paste it into their go2rtc config; nothing here is installed on the intercom.</para>
    ///
    /// <para>The codec parameters below are firmware-verified on the Classe 100X and 300X: H.264
    /// (Baseline, <c>profile-level-id=42801f</c>, RTP payload type 96, 90 kHz clock) and speex
    /// (8 kHz, RTP payload type 110). The low-res branch is the universal video path (the only one the
    /// 100X exposes); the 300X additionally has a hi-res branch. Only the fan-out UDP ports differ per
    /// install, so the generated SDP is fully determined by <see cref="MqttOptions"/>.</para>
    /// </summary>
    public static class Go2RtcConfig
    {
        /// <summary>RTP payload type the panel uses for the H.264 video stream (dynamic, 96).</summary>
        public const int VideoPayloadType = 96;

        /// <summary>RTP clock rate for H.264 (90 kHz, the RFC 6184 standard).</summary>
        public const int VideoClockRate = 90000;

        /// <summary>RTP payload type the panel uses for the speex audio stream (dynamic, 110).</summary>
        public const int AudioPayloadType = 110;

        /// <summary>RTP clock rate for the panel's speex audio (8 kHz, narrowband).</summary>
        public const int AudioClockRate = 8000;

        /// <summary>H.264 SDP <c>profile-level-id</c> the panel advertises (Baseline / level 3.0).</summary>
        public const string VideoProfileLevelId = "42801f";

        /// <summary>Fallback stream name when the caller supplies none / an all-invalid one.</summary>
        public const string DefaultStreamName = "doorbell";

        /// <summary>
        /// Normalise a go2rtc stream name to the safe subset go2rtc keys and Home Assistant entity ids
        /// tolerate: lower-case ASCII letters, digits, <c>_</c> and <c>-</c>. Everything else is dropped;
        /// an empty or all-invalid input becomes <see cref="DefaultStreamName"/>. Deterministic so the
        /// SDP filename, the go2rtc key, and the HA camera all agree.
        /// </summary>
        public static string SanitizeStreamName(string? name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return DefaultStreamName;
            var sb = new StringBuilder(name!.Length);
            foreach (char c in name.ToLowerInvariant())
            {
                if (c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '_' or '-')
                    sb.Append(c);
            }
            return sb.Length == 0 ? DefaultStreamName : sb.ToString();
        }

        /// <summary>
        /// Build the SDP that describes the two RTP streams the daemon fans out. The connection address
        /// is <c>0.0.0.0</c> (receive on any local interface): the ports, not the address, select the
        /// streams, and go2rtc/ffmpeg binds locally to receive them. Ends with a trailing newline; uses
        /// LF line endings (ffmpeg and go2rtc accept them on every platform).
        /// </summary>
        public static string BuildSdp(MqttOptions opts)
        {
            var ci = CultureInfo.InvariantCulture;
            var sb = new StringBuilder();
            sb.Append("v=0\n");
            // Session-level: a null origin/connection is fine for a passive RTP receiver.
            sb.Append("o=- 0 0 IN IP4 0.0.0.0\n");
            sb.Append("s=BTicino Door Entry\n");
            sb.Append("c=IN IP4 0.0.0.0\n");
            sb.Append("t=0 0\n");
            // Video: H.264 in RTP, payload type 96, 90 kHz. packetization-mode=1 (non-interleaved) is
            // what the panel's GStreamer rtph264pay emits; profile-level-id is the verified Baseline 3.0.
            sb.Append(string.Create(ci, $"m=video {opts.CameraVideoPort} RTP/AVP {VideoPayloadType}\n"));
            sb.Append(string.Create(ci, $"a=rtpmap:{VideoPayloadType} H264/{VideoClockRate}\n"));
            sb.Append(string.Create(ci,
                $"a=fmtp:{VideoPayloadType} packetization-mode=1;profile-level-id={VideoProfileLevelId}\n"));
            sb.Append("a=recvonly\n");
            // Audio: speex narrowband (8 kHz), payload type 110.
            sb.Append(string.Create(ci, $"m=audio {opts.CameraAudioPort} RTP/AVP {AudioPayloadType}\n"));
            sb.Append(string.Create(ci, $"a=rtpmap:{AudioPayloadType} speex/{AudioClockRate}\n"));
            sb.Append("a=recvonly\n");
            return sb.ToString();
        }

        /// <summary>
        /// Build the go2rtc <c>streams:</c> entry that ingests the SDP. go2rtc runs ffmpeg via an
        /// <c>exec:</c> source: ffmpeg reads the SDP (the <c>-protocol_whitelist</c> is required for a
        /// file+udp+rtp input), copies H.264 untouched (zero-latency, no re-encode) and transcodes the
        /// speex audio to Opus for WebRTC, then publishes to go2rtc's internal RTSP (<c>{output}</c>).
        /// <paramref name="sdpPath"/> is the path to the SDP file ON THE go2rtc HOST.
        /// </summary>
        public static string BuildStreamsYaml(MqttOptions opts, string streamName, string sdpPath)
        {
            string name = SanitizeStreamName(streamName);
            var sb = new StringBuilder();
            sb.Append("streams:\n");
            sb.Append(string.Create(CultureInfo.InvariantCulture, $"  {name}:\n"));
            // The exec source: {output} is go2rtc's placeholder for its internal RTSP sink. Audio is
            // transcoded to Opus (WebRTC-native); if the go2rtc ffmpeg build lacks speex decoding, drop
            // the two audio flags and the stream is video-only.
            sb.Append("    - exec:ffmpeg -hide_banner -protocol_whitelist file,udp,rtp -i ");
            sb.Append(sdpPath);
            sb.Append(" -c:v copy -c:a libopus -ar 48000 -ac 1 -rtsp_transport tcp -f rtsp {output}\n");
            return sb.ToString();
        }

        /// <summary>
        /// Build a complete, copy-paste setup guide: where to put the SDP, the go2rtc <c>streams:</c>
        /// entry, and how Home Assistant then picks up the camera. Plain text, LF line endings. The App
        /// surfaces this so the user can wire go2rtc without leaving the tool.
        /// </summary>
        public static string BuildSetupGuide(MqttOptions opts, string streamName)
        {
            string name = SanitizeStreamName(streamName);
            string sdpFile = name + ".sdp";
            string sdpPath = "/config/go2rtc/" + sdpFile;
            string target = opts.EffectiveCameraTargetHost;
            var ci = CultureInfo.InvariantCulture;

            var sb = new StringBuilder();
            sb.Append("BTicino live doorbell camera — go2rtc setup\n");
            sb.Append("===========================================\n\n");
            sb.Append(string.Create(ci,
                $"The intercom fans a cleartext RTP copy of the entrance camera to this host\n" +
                $"({target}) whenever the panel shows video (a ring, an answered call, or the\n" +
                $"self-view eye): H.264 on UDP {opts.CameraVideoPort}, speex audio on UDP\n" +
                $"{opts.CameraAudioPort}. go2rtc turns that into a Home Assistant camera.\n\n"));

            sb.Append(string.Create(ci, $"1) Save this SDP as {sdpPath} on the go2rtc host:\n\n"));
            foreach (var line in BuildSdp(opts).Split('\n'))
            {
                if (line.Length == 0) continue;
                sb.Append("     ").Append(line).Append('\n');
            }
            sb.Append('\n');

            sb.Append("2) Add this to your go2rtc configuration (go2rtc.yaml, or Home\n");
            sb.Append("   Assistant's go2rtc add-on config):\n\n");
            foreach (var line in BuildStreamsYaml(opts, name, sdpPath).Split('\n'))
            {
                if (line.Length == 0) continue;
                sb.Append("     ").Append(line).Append('\n');
            }
            sb.Append('\n');

            sb.Append("3) Restart go2rtc. In Home Assistant, add the WebRTC Camera / go2rtc\n");
            sb.Append(string.Create(ci,
                $"   integration (or a `camera` via the stream name \"{name}\"). The picture\n" +
                $"   appears while the panel has an active A/V session; between sessions the\n" +
                $"   stream is idle (the panel only encodes on demand).\n\n"));

            sb.Append("Notes\n-----\n");
            sb.Append("- Video is copied through untouched (no re-encode, minimal latency).\n");
            sb.Append("- Audio is transcoded speex → Opus. If your go2rtc ffmpeg build cannot\n");
            sb.Append("  decode speex, REPLACE `-c:a libopus -ar 48000 -ac 1` with `-an` for a\n");
            sb.Append("  video-only stream. (Just deleting the audio flags is not enough —\n");
            sb.Append("  ffmpeg would still auto-select the SDP's audio stream and fail to\n");
            sb.Append("  decode it; `-an` drops audio outright.)\n");
            sb.Append(string.Create(ci,
                $"- The low-res branch is used by default (universal; the only one the 100X\n" +
                $"  exposes). On a 300X you may switch to the hi-res branch in the tool.\n"));
            return sb.ToString();
        }
    }
}
