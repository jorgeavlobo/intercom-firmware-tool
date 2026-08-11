using System;
using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// The embedded minimal ffmpeg (issue #120): the vendored third-party binary is present, loads
/// through the length + SHA-256 guard, is installed (in <see cref="PayloadBinaries.All"/> as of
/// Phase 1c, for the on-device media server), and ships its license notices (LGPL for FFmpeg +
/// the MIT musl notice for the statically-linked libc).
/// </summary>
public class PayloadFfmpegTests
{
    [Fact]
    public void Ffmpeg_binary_loads_and_matches_its_recorded_hash()
    {
        var bin = PayloadBinaries.Ffmpeg;
        Assert.Equal("ffmpeg", bin.Name);
        // FFmpeg core is LGPL-2.1; the static binary also links musl libc (MIT).
        Assert.Equal("LGPL-2.1-or-later AND MIT", bin.LicenseSpdx);

        // Phase 1c installs ffmpeg for the on-device media server: MqttInstaller writes every
        // entry in PayloadBinaries.All, and ffmpeg is now one of them. This assertion fails
        // loudly if it is ever silently dropped from the install set.
        Assert.Contains(bin, PayloadBinaries.All);

        // Read re-verifies length + SHA-256 and throws on any mismatch.
        byte[] bytes = PayloadBinaries.Read(bin);
        Assert.Equal(bin.Length, bytes.Length);

        // ELF magic — a sanity check that the actual binary was embedded.
        Assert.True(bytes.Length > 4
            && bytes[0] == 0x7F && bytes[1] == (byte)'E'
            && bytes[2] == (byte)'L' && bytes[3] == (byte)'F');
    }

    [Fact]
    public void Ffmpeg_ships_its_LGPL_and_musl_license_texts()
    {
        var bin = PayloadBinaries.Ffmpeg;

        // Primary: FFmpeg's LGPL-2.1 text.
        string lgpl = PayloadBinaries.LicenseText(bin);
        Assert.Contains("GNU LESSER GENERAL PUBLIC LICENSE", lgpl);
        Assert.Contains("Version 2.1", lgpl);

        // Additional: the statically-linked musl libc (MIT) COPYRIGHT must travel with it.
        var names = PayloadBinaries.LicenseResourceNames(bin);
        string muslResource = Assert.Single(
            names, n => n.EndsWith("musl-COPYRIGHT.txt", StringComparison.Ordinal));
        string musl = PayloadBinaries.LicenseTextByResource(muslResource);
        Assert.Contains("musl", musl);
        Assert.Contains("MIT license", musl);
    }
}
