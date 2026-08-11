using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// The embedded minimal ffmpeg (issue #120, Phase 1a): the vendored third-party LGPL
/// binary is present, loads through the length + SHA-256 guard, and ships its LGPL text.
/// Declared but deliberately NOT in <see cref="PayloadBinaries.All"/> yet — the installer
/// wires it in Phase 1c — so this is the coverage that the embed is wired correctly.
/// </summary>
public class PayloadFfmpegTests
{
    [Fact]
    public void Ffmpeg_binary_loads_and_matches_its_recorded_hash()
    {
        var bin = PayloadBinaries.Ffmpeg;
        Assert.Equal("ffmpeg", bin.Name);
        Assert.Equal("LGPL-2.1-or-later", bin.LicenseSpdx);

        // Read re-verifies length + SHA-256 and throws on any mismatch.
        byte[] bytes = PayloadBinaries.Read(bin);
        Assert.Equal(bin.Length, bytes.Length);

        // ELF magic — a sanity check that the actual binary was embedded.
        Assert.True(bytes.Length > 4
            && bytes[0] == 0x7F && bytes[1] == (byte)'E'
            && bytes[2] == (byte)'L' && bytes[3] == (byte)'F');
    }

    [Fact]
    public void Ffmpeg_ships_its_LGPL_license_text()
    {
        string license = PayloadBinaries.LicenseText(PayloadBinaries.Ffmpeg);
        Assert.Contains("GNU LESSER GENERAL PUBLIC LICENSE", license);
        Assert.Contains("Version 2.1", license);
    }
}
