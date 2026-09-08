using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// The "Loading camera…" cold-open filler (issue #180): the embedded first-party MP4 is shipped and
/// SHA-verified like the other payloads, and the on-device media-server install writes it (0644) plus the
/// generated producer wrapper (0755) into <c>/etc/btmqttd/go2rtc/</c>. Driven against
/// <see cref="InMemoryExtFs"/> — no native SharpExt4 required, mirroring <see cref="MqttInstallerImageTests"/>.
/// </summary>
public class MqttLoadingClipTests
{
    private const string LoadingClipPath = "/etc/btmqttd/go2rtc/loading.mp4";
    private const string ProducerScriptPath = "/etc/btmqttd/go2rtc/camera-producer.sh";
    private const string LoadingClipResource = "IntercomFirmwareTool.Core.Payload.mqtt.loading.mp4";

    // The recorded integrity reference — must equal MqttInstaller.LoadingClipLength/LoadingClipSha256Hex
    // and the value the provenance doc (Payload/mqtt/README.md) records.
    private const int ExpectedLength = 19_486;
    private const string ExpectedSha256 =
        "49950e62a6ea6516c8f970f512e5c655e001fc197993cf2371f7680debd402c3";

    /// <summary>The factory firewall hook InstallOnDeviceMediaServer hardens; seed it (with an interpreter)
    /// so the patch step is a real no-op-safe pass, exactly as the factory-firewall image tests do.</summary>
    private static InMemoryExtFs SeededImage() =>
        new InMemoryExtFs()
            .AddExecutable("/bin/bash")
            .AddFile("/etc/network/if-pre-up.d/iptables",
                "#!/bin/bash\niptables -F INPUT\niptables -P INPUT DROP\n", InMemoryExtFs.Mode0755);

    private static MqttOptions OnDeviceCameraOpts() =>
        new("broker.lan")
        {
            CameraEnabled = true,
            CameraOnDevice = true,
            CameraRtspUser = "camera",
            CameraRtspPass = "s3cr3t",
        };

    private static byte[] ReadAll(IExtFs fs, string path)
    {
        using var s = fs.OpenFile(path, FileMode.Open, FileAccess.Read);
        using var buf = new MemoryStream();
        s.CopyTo(buf);
        return buf.ToArray();
    }

    [Fact]
    public void Embedded_loading_clip_is_present_and_matches_its_recorded_hash()
    {
        // The asset ships as an embedded resource (csproj EmbeddedResource + LogicalName) and is a real,
        // intact MP4 — length + SHA-256 are the integrity reference the installer re-verifies on read.
        var asm = typeof(MqttInstaller).Assembly;
        using Stream? stream = asm.GetManifestResourceStream(LoadingClipResource);
        Assert.NotNull(stream);
        using var buf = new MemoryStream();
        stream!.CopyTo(buf);
        byte[] bytes = buf.ToArray();

        Assert.Equal(ExpectedLength, bytes.Length);
        Assert.Equal(ExpectedSha256, Convert.ToHexStringLower(SHA256.HashData(bytes)));

        // MP4 signature: the ISO base-media 'ftyp' box tag at offset 4 (the container is REQUIRED — a raw
        // .h264 does not loop cleanly under `-stream_loop -c copy`, so a swapped-in .h264 must be caught).
        Assert.True(bytes.Length > 8);
        Assert.Equal("ftyp", Encoding.ASCII.GetString(bytes, 4, 4));
    }

    [Fact]
    public void Install_writes_the_loading_clip_and_producer_wrapper_on_the_ondevice_path()
    {
        var fs = SeededImage();
        MqttInstaller.InstallOnDeviceMediaServer(fs, OnDeviceCameraOpts());

        // The filler clip: present, 0644 root:root, and byte-for-byte the embedded, verified asset.
        Assert.True(fs.HasFile(LoadingClipPath));
        Assert.Equal(InMemoryExtFs.Mode0644, fs.ModeOf(LoadingClipPath));
        Assert.Equal((0u, 0u), fs.OwnerOf(LoadingClipPath)!.Value);
        byte[] clip = ReadAll(fs, LoadingClipPath);
        Assert.Equal(ExpectedLength, clip.Length);
        Assert.Equal(ExpectedSha256, Convert.ToHexStringLower(SHA256.HashData(clip)));

        // The producer wrapper: present, 0755 root:root, and byte-for-byte the generated script (with the
        // installed ffmpeg's path).
        Assert.True(fs.HasFile(ProducerScriptPath));
        Assert.Equal(InMemoryExtFs.Mode0755, fs.ModeOf(ProducerScriptPath));
        Assert.Equal((0u, 0u), fs.OwnerOf(ProducerScriptPath)!.Value);
        Assert.Equal(
            Go2RtcConfig.BuildOnDeviceProducerScript(PayloadBinaries.Ffmpeg.InstallPath),
            fs.ReadText(ProducerScriptPath));
    }

    [Fact]
    public void Install_writes_nothing_camera_specific_off_device()
    {
        // Off-device (or camera off) the on-device media server — and its filler/wrapper — must NOT be
        // written: the filler is an on-device-only concept (the off-device go2rtc/HA host owns its stream).
        var fs = SeededImage();
        MqttInstaller.InstallOnDeviceMediaServer(fs,
            OnDeviceCameraOpts() with { CameraOnDevice = false });
        Assert.False(fs.HasFile(LoadingClipPath));
        Assert.False(fs.HasFile(ProducerScriptPath));
    }
}
