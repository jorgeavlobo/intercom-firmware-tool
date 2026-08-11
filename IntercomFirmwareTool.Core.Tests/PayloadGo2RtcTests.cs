using System;
using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// The embedded go2rtc streaming server (issue #120): the vendored third-party prebuilt is present,
/// loads through the length + SHA-256 guard, and ships its full notice set — go2rtc's own MIT license
/// plus the audited aggregate of its statically-linked Go runtime + module notices. Declared but
/// deliberately NOT in <see cref="PayloadBinaries.All"/> yet — the gated on-device camera install
/// writes it (with ffmpeg) in Phase 1c-2.
/// </summary>
public class PayloadGo2RtcTests
{
    // The audited SPDX expression over go2rtc v1.9.14's linked module graph (linux/arm, no cgo) +
    // the Go runtime. paho.mqtt is EPL-2.0/EDL-1.0 dual — used under the permissive EDL election.
    private const string ExpectedSpdx =
        "Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND MIT AND (EPL-2.0 OR BSD-3-Clause)";

    private const string BundleResource =
        "IntercomFirmwareTool.Core.licenses.go2rtc-THIRD-PARTY-LICENSES.txt";

    [Fact]
    public void Go2rtc_binary_loads_and_matches_its_recorded_hash()
    {
        var bin = PayloadBinaries.Go2Rtc;
        Assert.Equal("go2rtc", bin.Name);
        Assert.Equal("/usr/sbin/go2rtc", bin.InstallPath);
        Assert.Equal(ExpectedSpdx, bin.LicenseSpdx);

        // 1c-1 embeds go2rtc but does NOT install it: MqttInstaller writes every entry in
        // PayloadBinaries.All, so go2rtc must stay out of All until the gated on-device camera
        // install lands in 1c-2. This negative assertion fails loudly if that changes silently.
        Assert.DoesNotContain(bin, PayloadBinaries.All);

        // Statically-linked Go: besides its own MIT license it carries the audited Go runtime +
        // module notice bundle as an additional license resource.
        Assert.NotNull(bin.AdditionalLicenseResourceNames);
        Assert.Contains(BundleResource, bin.AdditionalLicenseResourceNames!);

        // Read re-verifies length + SHA-256 and throws on any mismatch.
        byte[] bytes = PayloadBinaries.Read(bin);
        Assert.Equal(bin.Length, bytes.Length);

        // ELF magic — a sanity check that the actual binary was embedded.
        Assert.True(bytes.Length > 4
            && bytes[0] == 0x7F && bytes[1] == (byte)'E'
            && bytes[2] == (byte)'L' && bytes[3] == (byte)'F');
    }

    [Fact]
    public void Go2rtc_ships_its_MIT_license_and_audited_dependency_notices()
    {
        var bin = PayloadBinaries.Go2Rtc;

        // Primary: go2rtc's own MIT text.
        string mit = PayloadBinaries.LicenseText(bin);
        Assert.Contains("MIT License", mit);
        Assert.Contains("Alexey Khit", mit);

        // Two license resources travel: the MIT primary + the audited Go runtime/module bundle.
        var names = PayloadBinaries.LicenseResourceNames(bin);
        Assert.Contains("IntercomFirmwareTool.Core.licenses.go2rtc-LICENSE.txt", names);
        string bundleResource = Assert.Single(
            names, n => n.EndsWith("go2rtc-THIRD-PARTY-LICENSES.txt", StringComparison.Ordinal));

        // The bundle reproduces the Go runtime (BSD-3-Clause) + the linked modules, including the
        // dual-licensed paho MQTT client — evidence the audit is real, not a stub.
        string bundle = PayloadBinaries.LicenseTextByResource(bundleResource);
        Assert.Contains("go-licenses", bundle);              // how it was generated
        Assert.Contains("The Go Authors", bundle);           // the Go runtime BSD-3-Clause text
        Assert.Contains("Eclipse Public License", bundle);   // paho, dual-licensed
        Assert.Contains("EDL-1.0", bundle);                  // the permissive election we take
    }
}
