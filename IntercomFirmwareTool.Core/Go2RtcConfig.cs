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

        /// <summary>H.264 SDP <c>profile-level-id</c> the panel advertises: Baseline, level 3.1
        /// (<c>level_idc = 0x1f = 31 = 3.1</c>).</summary>
        public const string VideoProfileLevelId = "42801f";

        /// <summary>Fallback stream name when the caller supplies none / an all-invalid one.</summary>
        public const string DefaultStreamName = "doorbell";

        // --- On-device media server (Phase 1c, #120) -----------------------------------------
        /// <summary>The port the on-device go2rtc serves RTSP on (LAN — the firewall opens only this).
        /// Home Assistant consumes it as a Generic Camera at <c>rtsp://…:8554/&lt;stream&gt;</c>.</summary>
        public const int OnDeviceRtspPort = 8554;

        /// <summary>The on-device go2rtc control/API + web UI port. Bound to <b>loopback only</b> — it is
        /// never exposed on the LAN (no firewall rule opens it).</summary>
        public const int OnDeviceApiPort = 1984;

        /// <summary>Absolute path of the vendored ffmpeg on the device (see <c>PayloadBinaries.Ffmpeg</c>).
        /// go2rtc's <c>exec:</c> source runs it to copy the panel's H.264 into RTSP.</summary>
        public const string OnDeviceFfmpegPath = "/usr/sbin/ffmpeg";

        /// <summary>
        /// The RUNTIME SDP go2rtc's <c>exec -i</c> reads on the device — on <b>tmpfs</b>, because the
        /// rootfs (including <c>/etc</c>) is mounted read-only. The installer writes the read-only
        /// TEMPLATE SDP under <c>/etc/btmqttd/go2rtc/</c>; the <c>go2rtcd</c> init script (re)assembles
        /// this runtime copy at every boot (copy the template into tmpfs, then splice in the persisted
        /// learned <c>sprop-parameter-sets</c>, if any). btmqttd's <c>sprop.rs</c> patches THIS path
        /// after a fresh learn, so it must equal <c>sprop.rs</c>'s <c>SDP_PATH</c>. Fixed (the on-device
        /// stream is always <see cref="DefaultStreamName"/>).
        /// </summary>
        public const string OnDeviceRuntimeSdpPath = "/var/run/btmqttd/doorbell.sdp";

        /// <summary>
        /// The loopback UDP endpoint btmqttd listens on for the raw H.264 RTP copy the on-device
        /// go2rtc live-view ffmpeg ships (its SECOND output). btmqttd's <c>sprop.rs</c> binds THIS
        /// EXACT <c>host:port</c> (its <c>SPROP_RTP_ADDR</c>) to receive the stream and parse the
        /// panel's periodic in-band SPS (NAL 7) / PPS (NAL 8) straight out of the RTP payload, so the
        /// two MUST stay in sync. Hardware testing (issue #120, PR #129) proved ffmpeg's
        /// <c>-sdp_file</c> can NOT emit the panel's <c>sprop-parameter-sets</c> on a copy path — it
        /// parses the SPS only far enough to learn the resolution and never writes the parameter sets
        /// into the SDP — so btmqttd parses the RTP itself instead. Port 40100 is loopback and collides
        /// with nothing else in the on-device design: not the 40000/40002 siphon (on 127.0.0.2), nor
        /// the RTSP (8554) / API (1984) listeners.
        /// </summary>
        public const string OnDeviceSpropRtpPort = "127.0.0.1:40100";

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
            // what the panel's GStreamer rtph264pay emits; profile-level-id is the verified Baseline 3.1.
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
        /// Build the SDP for the ON-DEVICE media server (issue #120): identical shape to
        /// <see cref="BuildSdp"/> but <b>video-only</b> (the vendored on-device ffmpeg has no audio
        /// codecs until Phase 3 / #105) and with the connection address pinned to the loopback alias
        /// <c>127.0.0.2</c> — where btmqttd fans the RTP — so ffmpeg binds loopback for ingest and the
        /// raw RTP never touches the LAN. LF line endings, trailing newline.
        /// </summary>
        public static string BuildOnDeviceSdp(MqttOptions opts)
        {
            var ci = CultureInfo.InvariantCulture;
            var sb = new StringBuilder();
            sb.Append("v=0\n");
            sb.Append(string.Create(ci, $"o=- 0 0 IN IP4 {MqttOptions.OnDeviceCameraTarget}\n"));
            sb.Append("s=BTicino Door Entry\n");
            sb.Append(string.Create(ci, $"c=IN IP4 {MqttOptions.OnDeviceCameraTarget}\n"));
            sb.Append("t=0 0\n");
            sb.Append(string.Create(ci, $"m=video {opts.CameraVideoPort} RTP/AVP {VideoPayloadType}\n"));
            sb.Append(string.Create(ci, $"a=rtpmap:{VideoPayloadType} H264/{VideoClockRate}\n"));
            // sprop-parameter-sets (issue #120, on-device, hardware-diagnosed on the C100X): the panel's
            // encoder emits an in-stream SPS/PPS only ~every 20 s, so with a bare fmtp go2rtc's `-c:v copy`
            // ffmpeg blocks ~20 s waiting for that keyframe before it can resolve 640x480 and publish —
            // a black wait on every cold open. Embedding the panel's parameter sets here lets ffmpeg
            // resolve in <1 s. The value is per-panel (MqttOptions.CameraSprop, base64+comma validated);
            // when unset we omit it and accept the ~20 s-first-frame fallback. It goes between
            // packetization-mode and profile-level-id, matching the order ffmpeg's own rtp muxer emits.
            string sprop = string.IsNullOrWhiteSpace(opts.CameraSprop)
                ? ""
                : $"sprop-parameter-sets={opts.CameraSprop};";
            sb.Append(string.Create(ci,
                $"a=fmtp:{VideoPayloadType} packetization-mode=1;{sprop}profile-level-id={VideoProfileLevelId}\n"));
            sb.Append("a=recvonly\n");
            return sb.ToString();
        }

        /// <summary>
        /// Build the COMPLETE on-device <c>go2rtc.yaml</c> (issue #120). go2rtc runs ON the panel: it
        /// reads the panel's cleartext RTP from the loopback SDP via the on-device ffmpeg, copies the
        /// H.264 into RTSP, and serves it to Home Assistant directly (no HA-side go2rtc). Policy:
        /// <list type="bullet">
        /// <item>the control API + web UI bind <b>loopback only</b> (<c>127.0.0.1:1984</c>) — never LAN;</item>
        /// <item>RTSP is served on the LAN (<c>:8554</c>, the only port the firewall opens) with
        /// <b>mandatory</b> username/password auth;</item>
        /// <item>the stream is <b>video-only</b> (Phase 1) — the ffmpeg <c>exec</c> uses <c>-an -c:v copy</c>.</item>
        /// </list>
        /// <paramref name="ffmpegPath"/> is an absolute on-device path. The <c>exec -i</c> input is fixed
        /// to the tmpfs <see cref="OnDeviceRuntimeSdpPath"/> (NOT the read-only <c>/etc</c> template):
        /// go2rtc reads the runtime SDP that <c>go2rtcd</c> reassembles at boot and that <c>sprop.rs</c>
        /// patches. LF line endings, trailing newline.
        /// </summary>
        public static string BuildOnDeviceYaml(
            string streamName, string ffmpegPath, string rtspUser, string rtspPass)
        {
            // RTSP is LAN-facing, so auth is MANDATORY (issue #120, decision #3). go2rtc treats an
            // EMPTY username as "no auth" and serves the stream to any LAN client — so an empty
            // credential doesn't weaken auth, it removes it. Refuse to emit a config that would do
            // that (CodeRabbit). The installer generates a strong random credential in 1c-2b; this
            // guard makes a blank one a hard error rather than a silent open stream.
            if (string.IsNullOrEmpty(rtspUser) || string.IsNullOrEmpty(rtspPass))
                throw new ArgumentException(
                    "On-device RTSP requires a non-empty username and password: go2rtc skips " +
                    "authentication for a blank username, exposing the LAN stream unauthenticated.");
            // Reject ANY control character. YamlDoubleQuoted escapes only '\\' and '\"', so a control
            // char in a credential would land raw in the double-quoted scalar: a CR/LF splits it across
            // lines, and NUL/ESC/TAB/etc. are forbidden in a YAML double-quoted scalar — either way
            // go2rtc fails to load the config (Copilot: CR/LF; Codex: the rest).
            if (rtspUser.Any(char.IsControl) || rtspPass.Any(char.IsControl))
                throw new ArgumentException(
                    "RTSP credentials must not contain control characters (CR/LF, NUL, ESC, ...): they would corrupt go2rtc.yaml.");
            string name = SanitizeStreamName(streamName);
            var ci = CultureInfo.InvariantCulture;
            var sb = new StringBuilder();
            sb.Append("# go2rtc on-device media server for the BTicino intercom (issue #120), generated by\n");
            sb.Append("# IntercomFirmwareTool. Serves the entrance camera as RTSP to Home Assistant directly\n");
            sb.Append("# (no HA-side go2rtc). The installer regenerates this file — do not edit by hand.\n");
            // Control API + web UI: loopback ONLY — never exposed on the LAN (no firewall rule opens it).
            sb.Append("api:\n");
            sb.Append(string.Create(ci, $"  listen: \"127.0.0.1:{OnDeviceApiPort}\"\n"));
            // RTSP: served on the LAN (the firewall opens only this port) with mandatory auth.
            sb.Append("rtsp:\n");
            sb.Append(string.Create(ci, $"  listen: \":{OnDeviceRtspPort}\"\n"));
            sb.Append(string.Create(ci, $"  username: {YamlDoubleQuoted(rtspUser)}\n"));
            sb.Append(string.Create(ci, $"  password: {YamlDoubleQuoted(rtspPass)}\n"));
            sb.Append("log:\n");
            sb.Append("  format: text\n");
            // The stream: ffmpeg reads the loopback SDP and copies H.264 into go2rtc's internal RTSP
            // ({output}). Video only — the minimal on-device ffmpeg has no audio codecs until Phase 3
            // (#105), so -an drops the SDP's (absent) audio outright.
            //
            // Deliberately PLAIN defaults on the input — no -analyzeduration/-probesize/-reorder_queue_size/
            // -max_delay tuning. Two paths get `-c:v copy` its 640x480 dimensions. The FAST path is the
            // sprop-parameter-sets in this SDP: btmqttd auto-provisions them into doorbell.sdp on first
            // boot (native/btmqttd/src/sprop.rs), and the decoder-enabled ffmpeg (native/ffmpeg/build.sh)
            // reads them at open to resolve in ~2.5 s. The FALLBACK — before that provisioning completes,
            // or if on-demand is off — is the H.264 PARSER recovering the SPS/PPS from the in-stream data;
            // correct but slow, since the panel emits an in-stream SPS only ~every 20 s. Either way
            // `-c:v copy` publishes to go2rtc with no input tuning.
            //
            // HARDWARE-DIAGNOSED (issue #120, C100X): an earlier revision widened the RTP jitter buffer
            // (-reorder_queue_size 3000 -max_delay 5000000) to catch the sparse in-stream SPS/PPS. That
            // was ACTIVELY HARMFUL here: the ingest is loopback (127.0.0.2), which never reorders, so the
            // oversized reorder queue made ffmpeg stall waiting for sequence numbers that never arrive and
            // drop every packet as "RTP: dropping old packet received too late" — the producer never
            // locked on and go2rtc answered DESCRIBE with 404. Reverting to plain defaults locks on in well
            // under a second (hardware-verified: 94 frames in 8 s). The extract_extradata/dump_extra
            // bitstream filters were likewise dropped — the parser already carries the parameter sets into
            // the announce SDP, so they bought nothing.
            //
            // sprop LEARNING (issue #120, hardware-diagnosed on the C100X, revised in PR #129): the panel
            // only sustains/feeds the video call for a REAL consumed view — a silent probe that brings the
            // panel up just to run ffmpeg TIMES OUT and never learns. Hardware testing ALSO proved ffmpeg's
            // -sdp_file CANNOT emit the panel's sprop-parameter-sets on this copy path: it parses the SPS
            // only far enough to resolve the resolution and never writes the parameter sets into the SDP
            // (confirmed even with a 25 s analyzeduration). So the derived-SDP mechanism is a dead end.
            // Instead this SAME ffmpeg (which runs only while a client is watching) is given a SECOND
            // output that ships a raw H.264 RTP copy to btmqttd:
            //   -c:v copy -f rtp rtp://{OnDeviceSpropRtpPort}
            // That RTP stream carries the panel's periodic in-band SPS/PPS. btmqttd's sprop.rs binds this
            // exact loopback port, parses the SPS (NAL 7) / PPS (NAL 8) straight out of the RTP payload,
            // base64-encodes them and persists sprop-parameter-sets=<b64SPS>,<b64PPS>. Because the output
            // only runs while a client is actually watching, the learning stays transparent and never
            // brings the panel up itself.
            sb.Append("streams:\n");
            sb.Append(string.Create(ci, $"  {name}:\n"));
            sb.Append(string.Create(ci,
                $"    - \"exec:{ffmpegPath} -hide_banner -protocol_whitelist file,udp,rtp -i {OnDeviceRuntimeSdpPath} -an -c:v copy -rtsp_transport tcp -f rtsp {{output}} -c:v copy -f rtp rtp://{OnDeviceSpropRtpPort}\"\n"));
            return sb.ToString();
        }

        /// <summary>Emit a YAML double-quoted scalar, escaping the two characters that are special inside
        /// a double-quoted YAML string (<c>\</c> and <c>"</c>). Used for the RTSP credentials, which may
        /// contain punctuation.</summary>
        private static string YamlDoubleQuoted(string s) =>
            "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

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

        /// <summary>
        /// Build the Home Assistant setup guide for the ON-DEVICE media server (issue #120). Unlike the
        /// off-device <see cref="BuildSetupGuide"/>, there is nothing to paste: the installer writes and
        /// supervises go2rtc + ffmpeg on the panel and serves the camera as authenticated RTSP directly
        /// (no go2rtc on Home Assistant). This just gives the user the RTSP URL and the generated
        /// credentials to add as a Home Assistant Generic Camera. Plain text, LF line endings.
        /// </summary>
        public static string BuildOnDeviceSetupGuide(MqttOptions opts, string streamName)
        {
            string name = SanitizeStreamName(streamName);
            string user = opts.CameraRtspUser;
            // The App always sets a password on-device; only a bare/library caller hits the placeholder.
            bool hasPass = !string.IsNullOrEmpty(opts.CameraRtspPass);
            // A space-free placeholder if no password was set yet: spaces in the RTSP URL userinfo would
            // make it awkward to copy-paste (Copilot).
            string pass = hasPass ? opts.CameraRtspPass! : "<password>";
            var ci = CultureInfo.InvariantCulture;

            var sb = new StringBuilder();
            sb.Append("BTicino live doorbell camera — on-device go2rtc (Home Assistant)\n");
            sb.Append("================================================================\n\n");
            sb.Append("The intercom runs go2rtc + ffmpeg itself and serves the entrance\n");
            sb.Append("camera as an authenticated RTSP stream — there is NO go2rtc on Home\n");
            sb.Append("Assistant. The installer writes and starts everything on the panel;\n");
            sb.Append("nothing here needs to be pasted into a go2rtc config.\n\n");

            sb.Append("Add it to Home Assistant as a Generic Camera (Settings -> Devices &\n");
            sb.Append("Services -> Add Integration -> Generic Camera) with this stream URL —\n");
            sb.Append(hasPass
                ? "replace <intercom-ip> with the panel's IP address on your network:\n\n"
                : "replace <intercom-ip> with the panel's IP and <password> with the RTSP password:\n\n");
            // URL-encode the credentials for the URL's userinfo: Validate rejects control chars but not
            // RTSP-URL-reserved punctuation (@ : / #), so escape defensively (today's fixed "camera" +
            // base64url password never need it, but a future caller might) — CodeRabbit. The labeled
            // credentials below stay RAW so the user copies the real values into HA's separate fields. The
            // <password> placeholder is left literal (not %3C…%3E) so it reads as a placeholder (Copilot).
            string userEnc = Uri.EscapeDataString(user);
            string passInUrl = hasPass ? Uri.EscapeDataString(pass) : pass;
            sb.Append(string.Create(ci,
                $"    rtsp://{userEnc}:{passInUrl}@<intercom-ip>:{OnDeviceRtspPort}/{name}\n\n"));

            sb.Append("Credentials (generated for this build):\n");
            sb.Append(string.Create(ci, $"    username: {user}\n"));
            sb.Append(string.Create(ci, $"    password: {pass}\n\n"));

            sb.Append("Notes\n-----\n");
            sb.Append(string.Create(ci,
                $"- RTSP is served on port {OnDeviceRtspPort}, on the LAN, with mandatory\n" +
                $"  authentication. The go2rtc control API stays bound to loopback only\n" +
                $"  (127.0.0.1:{OnDeviceApiPort}) and is never exposed on the network.\n"));
            sb.Append("- Video only for now (H.264 copied through untouched, no re-encode);\n");
            sb.Append("  audio + talkback are a later phase.\n");
            sb.Append(string.Create(ci,
                $"- The panel's firewall must allow port {OnDeviceRtspPort} from your LAN so\n" +
                $"  Home Assistant can reach the stream.\n"));
            sb.Append("- The picture appears while the panel has an active A/V session (a\n");
            sb.Append("  ring, an answered call, or the self-view eye); between sessions the\n");
            sb.Append("  stream is idle (the panel only encodes on demand).\n");
            return sb.ToString();
        }
    }
}
