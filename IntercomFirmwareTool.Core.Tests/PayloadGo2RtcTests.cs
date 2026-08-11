using System;
using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// The embedded go2rtc streaming server (issue #120, Phase 1c): the vendored third-party prebuilt
/// is present, loads through the length + SHA-256 guard, is installed (in
/// <see cref="PayloadBinaries.All"/>), and ships its MIT license. Unlike ffmpeg/btmqttd it is a
/// statically-linked Go binary (no musl/libc), so it carries a single MIT notice and no additional
/// license resources.
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

        // Installed by the on-device media server (Phase 1c): MqttInstaller writes every entry in
        // PayloadBinaries.All, and go2rtc is one of them.
        Assert.Contains(bin, PayloadBinaries.All);

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
