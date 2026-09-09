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

        /// <summary>The port btmqttd serves the still-image (idle snapshot) HTTP endpoint on (issue #168).
        /// LAN-facing, opened by the <c>go2rtcd</c> firewall alongside <see cref="OnDeviceRtspPort"/>. Home
        /// Assistant's Generic Camera is pointed at <c>http://&lt;ip&gt;:8556/idle.jpg</c> as its <i>Still
        /// Image URL</i> so a thumbnail poll grabs this cheap JPEG instead of waking the live RTSP stream.
        /// Must equal btmqttd's <c>still::STILL_PORT</c> and the go2rtcd script's <c>CAM_STILL_PORT</c>.</summary>
        public const int OnDeviceStillPort = 8556;

        /// <summary>The on-device RTSP stream URL for <paramref name="host"/>, with URL-encoded
        /// credentials embedded (issue #171). Single source of truth for the URL shape, shared by the
        /// setup guide and the HA "Camera RTSP URL" diagnostic sensor. <paramref name="host"/> may be a
        /// literal address, a <c>&lt;placeholder&gt;</c>, or an HA template token like <c>{{ value }}</c>
        /// (the sensor renders the panel's mDNS host from the payload into it). <paramref name="userEnc"/>
        /// / <paramref name="passInUrl"/> must already be <see cref="Uri.EscapeDataString(string)"/>-escaped
        /// for the URL userinfo.</summary>
        public static string OnDeviceRtspUrl(string host, string userEnc, string passInUrl, string streamName) =>
            $"rtsp://{userEnc}:{passInUrl}@{host}:{OnDeviceRtspPort}/{streamName}";

        /// <summary>The on-device idle still-image URL for <paramref name="host"/> (no credentials).
        /// Single source of truth shared by the setup guide and the HA "Camera still image URL"
        /// diagnostic sensor (issue #171). <paramref name="host"/> may be a literal address, a
        /// <c>&lt;placeholder&gt;</c>, or an HA template token like <c>{{ value }}</c>.</summary>
        public static string OnDeviceStillUrl(string host) =>
            $"http://{host}:{OnDeviceStillPort}/idle.jpg";

        /// <summary>Absolute path of the vendored ffmpeg on the device (see <c>PayloadBinaries.Ffmpeg</c>).
        /// go2rtc's <c>exec:</c> source runs it to copy the panel's H.264 into RTSP.</summary>
        public const string OnDeviceFfmpegPath = "/usr/sbin/ffmpeg";

        /// <summary>
        /// The on-device "Loading camera…" filler clip (issue #180). go2rtc's producer wrapper
        /// (<see cref="BuildOnDeviceProducerScript"/>) loops this MP4 with <c>-stream_loop -1 -c copy</c>
        /// on a COLD open — before btmqttd has armed the real siphon — so go2rtc's lazy <c>exec:</c>
        /// producer ALWAYS has decodable H.264 to hand Home Assistant and never i/o-times-out during the
        /// panel's ~3 s SIP warm-up (the blank-on-cold-open bug). The installer ships the embedded
        /// <c>Payload/mqtt/loading.mp4</c> here (0644, static seed on the read-only rootfs — no runtime
        /// write needed). A container-framed MP4 is required (a raw <c>.h264</c> does NOT loop cleanly
        /// under <c>-stream_loop -c copy</c>).
        /// </summary>
        public const string OnDeviceLoadingClipPath = "/etc/btmqttd/go2rtc/loading.mp4";

        /// <summary>
        /// The on-device go2rtc producer WRAPPER script (issue #180) — a generated POSIX-sh script
        /// (<see cref="BuildOnDeviceProducerScript"/>) go2rtc runs as its <c>exec:</c> source instead of
        /// invoking ffmpeg directly. On each (re)start it checks <see cref="OnDeviceCameraLiveSignalPath"/>
        /// and <c>exec</c>s EITHER the live feed (reads <see cref="OnDeviceRuntimeSdpPath"/>, exactly
        /// today's live producer, so sprop learning is unchanged) or the filler
        /// (<see cref="OnDeviceLoadingClipPath"/>). Installed 0755 root:root.
        /// </summary>
        public const string OnDeviceProducerScriptPath = "/etc/btmqttd/go2rtc/camera-producer.sh";

        /// <summary>
        /// The on-device "camera is live now" signal file (issue #180). btmqttd's <c>av.rs</c> CREATES it
        /// the instant the real siphon arms (RTP now flowing) and REMOVES it when the siphon is released;
        /// the producer wrapper reads its EXISTENCE to choose the live feed over the filler. On tmpfs
        /// (<c>/var/run/btmqttd</c>, cleared every boot ⇒ defaults to "not live", so a cold boot serves the
        /// filler). Must equal <c>av.rs</c>'s <c>CAMERA_LIVE_SIGNAL_PATH</c> and the wrapper's <c>SIG=</c>.
        /// </summary>
        public const string OnDeviceCameraLiveSignalPath = "/var/run/btmqttd/camera-live";

        /// <summary>
        /// The on-device "the producer is actually serving the LIVE feed now" readiness file (issue #180).
        /// The producer WRAPPER writes it: it creates this file on the branch that <c>exec</c>s the live feed
        /// and removes it on the branch that <c>exec</c>s the filler — BEFORE the <c>exec</c>, so it records
        /// the branch the wrapper committed to even during its transient <c>/bin/sh</c> phase. btmqttd's
        /// <c>av.rs</c> READS its existence to confirm the filler→live cutover actually completed (a POSITIVE
        /// signal that closes the sub-millisecond race a "no filler process in <c>/proc</c>" check could not).
        /// On tmpfs (cleared every boot ⇒ absent = "not live yet"); the first cold producer's filler branch
        /// removes any stale copy. Must equal <c>av.rs</c>'s <c>LIVE_READY_PATH</c> and the wrapper's
        /// <c>READY=</c>.
        /// </summary>
        public const string OnDeviceCameraLiveReadyPath = "/var/run/btmqttd/camera-live-ready";

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
        public const string OnDeviceSpropRtpEndpoint = "127.0.0.1:40100";

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
        /// serves the entrance camera as RTSP to Home Assistant directly (no HA-side go2rtc). Policy:
        /// <list type="bullet">
        /// <item>the control API + web UI bind <b>loopback only</b> (<c>127.0.0.1:1984</c>) — never LAN;</item>
        /// <item>RTSP is served on the LAN (<c>:8554</c>, the only port the firewall opens) with
        /// <b>mandatory</b> username/password auth;</item>
        /// <item>the stream is <b>video-only</b> (Phase 1) — the ffmpeg the wrapper runs uses <c>-an -c:v copy</c>.</item>
        /// </list>
        /// The stream's <c>exec:</c> source is the generated producer WRAPPER
        /// (<c>/bin/sh <see cref="OnDeviceProducerScriptPath"/> {output}</c>, see
        /// <see cref="BuildOnDeviceProducerScript"/>) — NOT ffmpeg directly (issue #180). The shell is
        /// named by its ABSOLUTE path (<c>/bin/sh</c> — present on the BusyBox device): go2rtc may spawn
        /// its <c>exec:</c> command with a minimal <c>PATH</c>, so a bare <c>sh</c> could fail to resolve.
        /// The wrapper
        /// checks the <see cref="OnDeviceCameraLiveSignalPath"/> signal and <c>exec</c>s either the live
        /// feed (reading the tmpfs <see cref="OnDeviceRuntimeSdpPath"/>, exactly the pre-#180 producer, so
        /// sprop learning is unchanged) or the "Loading camera…" filler
        /// (<see cref="OnDeviceLoadingClipPath"/>) on a cold open. That indirection is why this yaml no
        /// longer names an ffmpeg path — the wrapper does. <c>{output}</c> stays go2rtc's own literal
        /// placeholder (it substitutes its internal RTSP sink and passes it to the wrapper as <c>$1</c>).
        /// LF line endings, trailing newline.
        /// </summary>
        public static string BuildOnDeviceYaml(
            string streamName, string rtspUser, string rtspPass)
        {
            // RTSP is LAN-facing, so auth is MANDATORY (issue #120, decision #3). go2rtc treats an
            // EMPTY username as "no auth" and serves the stream to any LAN client — so an empty
            // credential doesn't weaken auth, it removes it. Refuse to emit a config that would do
            // that. The installer generates a strong random credential in 1c-2b; this
            // guard makes a blank one a hard error rather than a silent open stream.
            if (string.IsNullOrEmpty(rtspUser) || string.IsNullOrEmpty(rtspPass))
                throw new ArgumentException(
                    "On-device RTSP requires a non-empty username and password: go2rtc skips " +
                    "authentication for a blank username, exposing the LAN stream unauthenticated.");
            // Reject ANY control character. YamlDoubleQuoted escapes only '\\' and '\"', so a control
            // char in a credential would land raw in the double-quoted scalar: a CR/LF splits it across
            // lines, and NUL/ESC/TAB/etc. are forbidden in a YAML double-quoted scalar — either way
            // go2rtc fails to load the config.
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
            // The stream (issue #180). go2rtc's exec: source is the producer WRAPPER, not ffmpeg directly:
            // go2rtc's lazy exec: producer is spawned only when a consumer asks for the stream, and on a
            // COLD open (Home Assistant opening the still panel while the panel is still ~3 s into its SIP
            // warm-up) an ffmpeg pointed straight at the not-yet-flowing RTP i/o-times-out before a single
            // frame arrives — so HA, which just waits on the still, never gets a picture and the stream
            // dies to a black wait. The wrapper fixes that: with no camera-live signal yet it exec's a
            // filler that loops loading.mp4 (always-decodable H.264), so the producer locks on instantly
            // and HA holds the "Loading camera…" card; the moment btmqttd arms the real siphon it creates
            // the signal and SIGTERMs the producer, and go2rtc respawns the wrapper into the LIVE feed. The
            // live branch is byte-for-byte the pre-#180 producer (same -i runtime SDP, same second
            // sprop-RTP output), so sprop learning is unchanged — see BuildOnDeviceProducerScript for the
            // full ffmpeg rationale (plain input defaults, the sprop-learning second output, etc.).
            //
            // {output} stays go2rtc's OWN literal placeholder: go2rtc substitutes its internal RTSP sink
            // and passes it to the wrapper as $1.
            sb.Append("streams:\n");
            sb.Append(string.Create(ci, $"  {name}:\n"));
            sb.Append(string.Create(ci,
                $"    - \"exec:/bin/sh {OnDeviceProducerScriptPath} {{output}}\"\n"));
            return sb.ToString();
        }

        /// <summary>
        /// Build the on-device go2rtc producer WRAPPER script (issue #180) — a POSIX-<c>sh</c> script
        /// go2rtc runs as its <c>exec:</c> source (see <see cref="BuildOnDeviceYaml"/>) INSTEAD of invoking
        /// ffmpeg directly, so the lazy producer can serve an always-ready filler until the real feed is
        /// live. On each (re)start the script tests <see cref="OnDeviceCameraLiveSignalPath"/> and
        /// <c>exec</c>s one of two ffmpeg pipelines:
        /// <list type="bullet">
        /// <item><b>signal present (siphon armed)</b> → the LIVE feed. This command is byte-for-byte the
        /// producer go2rtc ran before #180: read the tmpfs <see cref="OnDeviceRuntimeSdpPath"/>, copy H.264
        /// into RTSP (<c>{output}</c>, passed here as <c>$1</c>), AND ship a second raw-H.264 RTP copy to
        /// <see cref="OnDeviceSpropRtpEndpoint"/> — so <c>sprop.rs</c>'s parameter-set learning is entirely
        /// unchanged. Video only (<c>-an</c>); plain input defaults (a widened RTP jitter buffer was
        /// hardware-proven HARMFUL on the loopback ingest — issue #120).</item>
        /// <item><b>signal absent (cold)</b> → the FILLER: loop <see cref="OnDeviceLoadingClipPath"/> with
        /// <c>-re -stream_loop -1 -c copy</c> into RTSP. NO second/sprop output — the filler must never
        /// feed <c>sprop.rs</c> its own parameter sets, and it never brings the panel up (it reads a local
        /// file, not the panel), so the panel stays strictly on-demand.</item>
        /// </list>
        /// <c>exec</c> is used so the ffmpeg process REPLACES this shell — go2rtc tracks that ffmpeg PID
        /// directly, so btmqttd's SIGTERM → go2rtc respawns this script → it re-reads the signal (the
        /// filler→live cutover). <paramref name="ffmpegPath"/> is the absolute on-device ffmpeg path
        /// (<see cref="OnDeviceFfmpegPath"/> / <c>PayloadBinaries.Ffmpeg.InstallPath</c>). Every path woven
        /// into the script — <paramref name="ffmpegPath"/>, <see cref="OnDeviceRuntimeSdpPath"/> and
        /// <see cref="OnDeviceLoadingClipPath"/> — is a FIXED compile-time constant under our control; NO
        /// untrusted or operator-supplied input is ever interpolated here, so shell injection is not a
        /// concern. The ffmpeg executable path and each <c>-i</c> input path are still DOUBLE-QUOTED (as
        /// <c>"$1"</c> already is) as DEFENSIVE hygiene, so a constant that ever gained a SPACE would still
        /// parse as a single argument — NOT as an injection defense: double quotes still permit
        /// <c>$(…)</c>/backtick expansion, which is irrelevant precisely because these trusted constants
        /// contain none. The fixed <c>rtp://…</c> sprop endpoint has no spaces, so it is left unquoted.
        /// Emitted with LF line endings and a trailing newline (a CRLF shebang would run as
        /// <c>/bin/sh\r</c>); installed <c>0755</c> at <see cref="OnDeviceProducerScriptPath"/>.
        /// </summary>
        public static string BuildOnDeviceProducerScript(string ffmpegPath)
        {
            var ci = CultureInfo.InvariantCulture;
            var sb = new StringBuilder();
            sb.Append("#!/bin/sh\n");
            sb.Append("# go2rtc camera producer wrapper for the BTicino intercom (issue #180), generated by\n");
            sb.Append("# IntercomFirmwareTool. go2rtc runs this as its exec: source: on each (re)start it checks\n");
            sb.Append("# the camera-live signal and exec's EITHER the live feed OR the \"Loading camera…\" filler,\n");
            sb.Append("# so go2rtc's lazy producer ALWAYS has decodable H.264 and never i/o-times-out on a cold\n");
            sb.Append("# open. The installer regenerates this file — do not edit by hand.\n");
            sb.Append("#\n");
            sb.Append("# $1 is go2rtc's {output} RTSP sink. `exec` REPLACES this shell with ffmpeg so go2rtc tracks\n");
            sb.Append("# the ffmpeg PID directly (btmqttd's SIGTERM -> go2rtc respawns this script -> re-check SIG).\n");
            sb.Append("# READY records the branch we commit to (created for live, removed for filler) BEFORE exec,\n");
            sb.Append("# so btmqttd can confirm the live cutover from a positive signal, not a /proc process scan.\n");
            sb.Append(string.Create(ci, $"SIG={OnDeviceCameraLiveSignalPath}\n"));
            sb.Append(string.Create(ci, $"READY={OnDeviceCameraLiveReadyPath}\n"));
            sb.Append("if [ -e \"$SIG\" ]; then\n");
            // Live feed — EXACTLY the pre-#180 producer (same -i runtime SDP + same second sprop-RTP
            // output), so sprop.rs's learning is unchanged. Mark READY (we are serving live) BEFORE exec so
            // the signal reflects our decision even while this shell is still resolving into ffmpeg.
            sb.Append("\t: > \"$READY\"\n");
            sb.Append(string.Create(ci,
                $"\texec \"{ffmpegPath}\" -hide_banner -protocol_whitelist file,udp,rtp -i \"{OnDeviceRuntimeSdpPath}\" -an -c:v copy -rtsp_transport tcp -f rtsp \"$1\" -c:v copy -f rtp rtp://{OnDeviceSpropRtpEndpoint}\n"));
            sb.Append("else\n");
            // Not live — clear READY (we are serving the filler) BEFORE exec, so a wrapper that raced btmqttd
            // and took the filler branch records that fact and btmqttd's cutover keeps retrying until live.
            sb.Append("\trm -f \"$READY\"\n");
            // Filler — loop the loading clip; NO sprop output (must not learn the filler's SPS/PPS) and no
            // panel contact (reads a local file), so the panel stays strictly on-demand.
            sb.Append(string.Create(ci,
                $"\texec \"{ffmpegPath}\" -hide_banner -re -stream_loop -1 -i \"{OnDeviceLoadingClipPath}\" -an -c:v copy -rtsp_transport tcp -f rtsp \"$1\"\n"));
            sb.Append("fi\n");
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
            // make it awkward to copy-paste.
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
            sb.Append("Services -> Add Integration -> Generic Camera).\n\n");

            // Preferred path (issue #171) — ONLY when HA discovery is enabled, because the three
            // diagnostic sensors that carry the ready-to-paste URLs are created BY that discovery
            // (btmqttd clears them when HA_DISCOVERY=0). With discovery off they don't exist, so the
            // guide leads straight with the manual URLs instead of pointing at absent sensors.
            bool haveSensors = opts.EnableHaDiscovery;
            if (haveSensors)
            {
                sb.Append("Easiest — copy the ready-made URLs Home Assistant already has: the panel\n");
                sb.Append("auto-creates three diagnostic sensors — \"Camera mDNS host\", \"Camera RTSP\n");
                sb.Append("URL\" and \"Camera still image URL\". Their values use the panel's\n");
                sb.Append("<name>.local mDNS name, so they keep working if the panel's DHCP address\n");
                sb.Append("changes. Paste \"Camera RTSP URL\" as the stream and \"Camera still image\n");
                sb.Append("URL\" as the Still Image URL.\n\n");
            }

            // URL-encode the credentials for the URL's userinfo: Validate rejects control chars but not
            // RTSP-URL-reserved punctuation (@ : / #), so escape defensively (today's fixed "camera" +
            // base64url password never need it, but a future caller might). The labeled
            // credentials below stay RAW so the user copies the real values into HA's separate fields. The
            // <password> placeholder is left literal (not %3C…%3E) so it reads as a placeholder.
            string userEnc = Uri.EscapeDataString(user);
            string passInUrl = hasPass ? Uri.EscapeDataString(pass) : pass;
            // Manual URLs: the hand-entry FALLBACK when the sensors exist, or the PRIMARY path when
            // discovery is off (no "from the sensor above" pointer then). Prefer a DHCP reservation so
            // the literal IP stays put.
            string manualIntro = haveSensors
                ? (hasPass
                    ? "Or enter them by hand — replace <intercom-ip> with the panel's IP (a DHCP\nreservation keeps it stable), or its <name>.local host from the sensor above:\n\n"
                    : "Or enter them by hand — replace <intercom-ip> with the panel's IP and\n<password> with the RTSP password:\n\n")
                : (hasPass
                    ? "Set the stream URL — replace <intercom-ip> with the panel's IP (a DHCP\nreservation keeps it stable):\n\n"
                    : "Set the stream URL — replace <intercom-ip> with the panel's IP and\n<password> with the RTSP password:\n\n");
            sb.Append(manualIntro);
            sb.Append(string.Create(ci,
                $"    {OnDeviceRtspUrl("<intercom-ip>", userEnc, passInUrl, name)}\n\n"));

            sb.Append("Also set the Generic Camera's \"Still Image URL\" (no login):\n\n");
            sb.Append(string.Create(ci, $"    {OnDeviceStillUrl("<intercom-ip>")}\n\n"));

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
                $"- The panel's firewall must allow ports {OnDeviceRtspPort} and {OnDeviceStillPort}\n" +
                $"  from your LAN so Home Assistant can reach the stream and the still image.\n"));
            sb.Append("- The picture appears while the panel has an active A/V session (a\n");
            sb.Append("  ring, an answered call, or the self-view eye); between sessions the\n");
            sb.Append("  stream is idle (the panel only encodes on demand).\n");
            sb.Append(string.Create(ci,
                $"- The Still Image URL (:{OnDeviceStillPort}) serves the idle snapshot, so\n" +
                $"  Home Assistant's camera thumbnail never has to open the live stream (which\n" +
                $"  would otherwise wake the panel on every thumbnail refresh). Leaving it blank\n" +
                $"  makes Home Assistant grab thumbnails from the stream and keep the doorbell\n" +
                $"  session churning — so this field is recommended, not optional.\n"));
            sb.Append(string.Create(ci,
                $"- The idle snapshot at /idle.jpg is a REAL frame of the empty doorway: the\n" +
                $"  panel captures it automatically on first boot (best-effort — if that\n" +
                $"  boot's capture doesn't land, a later boot retries), and you can refresh it\n" +
                $"  any time with the \"Update idle snapshot\" button (press it to re-capture the\n" +
                $"  current view). It persists across reboots and reflashes. Both the\n" +
                $"  auto-capture and the button need on-demand viewing enabled (the panel must\n" +
                $"  be woken to photograph an idle doorway); with on-demand off, neither can run,\n" +
                $"  so /idle.jpg keeps serving whatever it already has — a previously captured\n" +
                $"  snapshot if one exists, otherwise the neutral placeholder.\n"));

            sb.Append("\nRing snapshot + notification\n----------------------------\n");
            sb.Append(string.Create(ci,
                $"When the doorbell rings, the panel captures a SEPARATE snapshot of who is at the\n" +
                $"door. Each ring is its own EVENT with a unique id, and its picture is served\n" +
                $"(transiently, on tmpfs) at a per-event URL:\n\n" +
                $"    http://<intercom-ip>:{OnDeviceStillPort}/ring-<id>.jpg\n\n"));
            // The auto-created "Doorbell snapshot" image entity exists only under MQTT discovery
            // (btmqttd clears its config when HA_DISCOVERY=0), so only promise it when discovery is on.
            // The snapshot TOPIC + the notification recipe below work regardless of discovery.
            if (haveSensors)
            {
                sb.Append("This never overwrites the idle thumbnail, and it needs no manual setup: the\n");
                sb.Append("panel auto-creates a \"Doorbell snapshot\" image entity in Home Assistant (via\n");
                sb.Append("MQTT discovery) that always shows the latest ring's frame. The snapshot topic\n");
                sb.Append("carries the event id and the device's LAN ip, published AFTER the frame is\n");
                sb.Append("written, so the picture is always exactly that ring's (two rings can never\n");
                sb.Append("cross images) and there is no fixed-delay guesswork.\n\n");
            }
            else
            {
                sb.Append("This never overwrites the idle thumbnail. With Home Assistant discovery\n");
                sb.Append("disabled the panel does NOT auto-create an image entity, but the snapshot\n");
                sb.Append("topic still carries the event id and the device's LAN ip (published AFTER the\n");
                sb.Append("frame is written), so the notification automation below works — the picture\n");
                sb.Append("is always exactly that ring's, with no fixed-delay guesswork.\n\n");
            }
            sb.Append("To also get a phone notification with the picture, add a Home Assistant\n");
            sb.Append("automation like this — replace notify.mobile_app_your_phone with your own (the\n");
            sb.Append("automation builds the image URL from the ip and id in the message):\n\n");
            // The topic goes into a double-quoted YAML scalar, so escape the two PRINTABLE characters a
            // double-quoted scalar treats specially — backslash first, then the quote. Topic validation
            // (MqttInstaller) already rejects every control character (newlines included) and the MQTT
            // wildcards, so those cannot reach here; only '"' and '\' — which a library caller could still
            // supply — need escaping, without which they would break the paste-ready recipe or silently
            // change the subscribed topic. The default/base64url topics contain neither, so the common case
            // is unchanged.
            var ringTopicYaml = opts.EffectiveTopicRingSnapshot.Replace("\\", "\\\\").Replace("\"", "\\\"");
            sb.Append(string.Create(ci,
                $"    alias: Doorbell ring notification\n" +
                $"    trigger:\n" +
                $"      - platform: mqtt\n" +
                $"        topic: \"{ringTopicYaml}\"\n" +
                $"    action:\n" +
                $"      - service: notify.mobile_app_your_phone\n" +
                $"        data:\n" +
                $"          message: \"Someone is at the door\"\n" +
                $"          data:\n" +
                $"            image: \"{{% set ip = trigger.payload_json.ip | default('', true) | regex_replace('[^0-9.]', '') %}}{{% if ip %}}http://{{{{ ip }}}}:{OnDeviceStillPort}/ring-{{{{ trigger.payload_json.id | int }}}}.jpg{{% endif %}}\"\n\n"));
            sb.Append(string.Create(ci,
                $"The snapshot payload is `{{\"at\":\"…\",\"id\":123,\"ip\":\"192.168.…\"}}` — the panel fills\n" +
                $"in its own LAN `ip` at ring time (so it tracks a DHCP change), published ONLY after the\n" +
                $"frame is written (no fixed-delay guesswork; a cold stream can take a while to produce a\n" +
                $"frame). The automation builds the URL from that `ip` with a FIXED scheme/port/path and an\n" +
                $"integer id, so a stray publisher can't redirect it off `:{OnDeviceStillPort}/ring-<id>.jpg`.\n" +
                $"If the panel can't resolve its address the `ip` is omitted; the `{{% if ip %}}` guard then\n" +
                $"renders no `image:` at all (the notification just arrives without a picture, never a broken\n" +
                $"URL). To still get a picture in that case, hard-code your panel's IP in the `image:` line.\n" +
                $"The raw ring event on \"{opts.EffectiveTopicEntrancePanelCall}\"\n" +
                $"still fires immediately, for automations that only need to know a ring happened.\n"));
            return sb.ToString();
        }
    }
}
