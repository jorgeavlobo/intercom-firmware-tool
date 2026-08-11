using System;
using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// The embedded minimal ffmpeg (issue #120): the vendored third-party binary is present, loads
/// through the length + SHA-256 guard, and ships its license notices (LGPL for FFmpeg + the MIT
/// musl notice for the statically-linked libc). Declared but deliberately NOT in
/// <see cref="PayloadBinaries.All"/> yet — the gated on-device camera install writes it in Phase
/// 1c-2 — so this is the coverage that the embed is wired correctly.
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

        // 1c-1 embeds ffmpeg but does NOT install it: MqttInstaller writes every entry in
        // PayloadBinaries.All, so ffmpeg must stay out of All until the gated on-device camera
        // install lands in 1c-2. This negative assertion fails loudly if that changes silently.
        Assert.DoesNotContain(bin, PayloadBinaries.All);

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
