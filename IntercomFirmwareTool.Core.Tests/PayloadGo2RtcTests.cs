using System;
using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// The embedded go2rtc streaming server (issue #120): the vendored third-party prebuilt is present,
/// loads through the length + SHA-256 guard, and ships its MIT license. Unlike ffmpeg/btmqttd it is
/// a statically-linked Go binary (no musl/libc), so it carries a single MIT notice and no additional
/// license resources. Declared but deliberately NOT in <see cref="PayloadBinaries.All"/> yet — the
/// gated on-device camera install writes it (with ffmpeg) in Phase 1c-2.
/// </summary>
public class PayloadGo2RtcTests
{
    [Fact]
    public void Go2rtc_binary_loads_and_matches_its_recorded_hash()
    {
        var bin = PayloadBinaries.Go2Rtc;
        Assert.Equal("go2rtc", bin.Name);
        Assert.Equal("/usr/sbin/go2rtc", bin.InstallPath);
        Assert.Equal("MIT", bin.LicenseSpdx);

        // 1c-1 embeds go2rtc but does NOT install it: MqttInstaller writes every entry in
        // PayloadBinaries.All, so go2rtc must stay out of All until the gated on-device camera
        // install lands in 1c-2. This negative assertion fails loudly if that changes silently.
        Assert.DoesNotContain(bin, PayloadBinaries.All);

        // A statically-linked Go binary: a single MIT notice, no additional (musl/libc) licenses.
        Assert.Null(bin.AdditionalLicenseResourceNames);

        // Read re-verifies length + SHA-256 and throws on any mismatch.
        byte[] bytes = PayloadBinaries.Read(bin);
        Assert.Equal(bin.Length, bytes.Length);

        // ELF magic — a sanity check that the actual binary was embedded.
        Assert.True(bytes.Length > 4
            && bytes[0] == 0x7F && bytes[1] == (byte)'E'
            && bytes[2] == (byte)'L' && bytes[3] == (byte)'F');
    }

    [Fact]
    public void Go2rtc_ships_its_MIT_license_text()
    {
        var bin = PayloadBinaries.Go2Rtc;

        // Primary (and only) license: go2rtc's own MIT text.
        string mit = PayloadBinaries.LicenseText(bin);
        Assert.Contains("MIT License", mit);
        Assert.Contains("Alexey Khit", mit);

        // Exactly one license resource — no additional (musl/libc) notice, unlike ffmpeg/btmqttd.
        var names = PayloadBinaries.LicenseResourceNames(bin);
        string only = Assert.Single(names);
        Assert.EndsWith("go2rtc-LICENSE.txt", only, StringComparison.Ordinal);
    }
}
