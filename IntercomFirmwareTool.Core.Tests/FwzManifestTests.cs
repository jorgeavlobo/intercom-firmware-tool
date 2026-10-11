using System.Linq;
using System.Text;
using System.Xml.Linq;
using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// The fwz.xml manifest transform (issue #191): declaring &lt;req_hw_ver&gt; so MyHOME Suite does not
/// default required hardware to 03.00.00 and reject a hardware-2.0 Classe 300X13E with error 1063.
/// Pure (no I/O), so the logic is tested directly without a real .fwz.
/// </summary>
public class FwzManifestTests
{
    // A manifest WITHOUT req_hw_ver — the shape the 300X13E branch-1.7 firmware ships (the exact
    // root/child names are irrelevant to the transform, which only adds to the root element).
    private static byte[] ManifestWithout(string? extra = null) =>
        Encoding.UTF8.GetBytes(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<fwz><model>1.0.68</model><version>1.7.19</version>" + (extra ?? "") + "</fwz>");

    private static byte[] ManifestWith(string reqHwVer) =>
        Encoding.UTF8.GetBytes(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            $"<fwz><model>1.0.68</model><req_hw_ver>{reqHwVer}</req_hw_ver></fwz>");

    [Fact]
    public void Injects_req_hw_ver_when_absent()
    {
        byte[] outBytes = FwzManifest.InjectReqHwVer(ManifestWithout(), "02.00.00");

        // The injected value round-trips back out.
        Assert.Equal("02.00.00", FwzManifest.ReadReqHwVer(outBytes));

        // The rest of the manifest is preserved (still valid XML, original children intact).
        XDocument doc = XDocument.Parse(Encoding.UTF8.GetString(outBytes));
        Assert.Equal("fwz", doc.Root!.Name.LocalName);
        Assert.Equal("1.0.68", doc.Root!.Element("model")!.Value);
        Assert.Equal("1.7.19", doc.Root!.Element("version")!.Value);
        // Exactly one req_hw_ver element was added (not duplicated).
        Assert.Single(doc.Root!.Elements("req_hw_ver"));
    }

    [Fact]
    public void Is_idempotent_when_already_present_with_the_same_value()
    {
        // A manifest that already declares the wanted value must not throw and must stay single.
        byte[] outBytes = FwzManifest.InjectReqHwVer(ManifestWith("02.00.00"), "02.00.00");
        Assert.Equal("02.00.00", FwzManifest.ReadReqHwVer(outBytes));
        XDocument doc = XDocument.Parse(Encoding.UTF8.GetString(outBytes));
        Assert.Single(doc.Root!.Elements("req_hw_ver"));
    }

    [Fact]
    public void Refuses_to_override_a_different_declared_value()
    {
        // Never silently change a declared hardware requirement — the source for the fixed case has none.
        var ex = Assert.Throws<InvalidDataException>(
            () => FwzManifest.InjectReqHwVer(ManifestWith("03.00.00"), "02.00.00"));
        Assert.Contains("03.00.00", ex.Message);
    }

    [Theory]
    [InlineData("2.0.0")]    // not zero-padded / not 3x2 digits
    [InlineData("02.00")]    // too few groups
    [InlineData("02.00.00.00")] // too many groups
    [InlineData("xx.yy.zz")] // not digits
    [InlineData("٠٢.٠٠.٠٠")] // Arabic-Indic "٠٢.٠٠.٠٠": \d would accept, [0-9] must not
    [InlineData("02.00.00\n")] // trailing newline: .NET $ would accept, \z must not
    [InlineData("")]
    public void Rejects_a_malformed_hardware_version(string bad)
    {
        Assert.Throws<ArgumentException>(() => FwzManifest.InjectReqHwVer(ManifestWithout(), bad));
    }

    [Fact]
    public void ReadReqHwVer_is_null_when_absent()
    {
        Assert.Null(FwzManifest.ReadReqHwVer(ManifestWithout()));
    }

    [Fact]
    public void Output_strips_the_BOM_for_a_UTF16_declared_manifest()
    {
        // The no-BOM contract must hold for a non-UTF-8 manifest too: a manifest that declares (and is
        // encoded as) UTF-16 must still serialize without any byte-order mark.
        var utf16 = new UnicodeEncoding(bigEndian: false, byteOrderMark: true);
        byte[] input = utf16.GetPreamble()
            .Concat(utf16.GetBytes(
                "<?xml version=\"1.0\" encoding=\"utf-16\"?><fwz><model>1.0.68</model></fwz>"))
            .ToArray();

        byte[] outBytes = FwzManifest.InjectReqHwVer(input, "02.00.00");

        // No BOM of any Unicode flavour at the start of the output.
        Assert.False(outBytes.Length >= 2 && outBytes[0] == 0xFF && outBytes[1] == 0xFE, "no UTF-16 LE BOM");
        Assert.False(outBytes.Length >= 2 && outBytes[0] == 0xFE && outBytes[1] == 0xFF, "no UTF-16 BE BOM");
        Assert.False(outBytes.Length >= 3 && outBytes[0] == 0xEF && outBytes[1] == 0xBB && outBytes[2] == 0xBF,
            "no UTF-8 BOM");
        // The value still round-trips (the declaration's utf-16 lets the reader decode the output).
        Assert.Equal("02.00.00", FwzManifest.ReadReqHwVer(outBytes));
    }

    [Fact]
    public void Output_keeps_the_xml_declaration_and_emits_no_BOM()
    {
        byte[] outBytes = FwzManifest.InjectReqHwVer(ManifestWithout(), "02.00.00");
        // No UTF-8 BOM preamble (the BTicino manifest has none; a stray BOM could trip a strict reader).
        Assert.False(outBytes.Length >= 3 && outBytes[0] == 0xEF && outBytes[1] == 0xBB && outBytes[2] == 0xBF,
            "output must not start with a UTF-8 BOM");
        // The XML declaration is preserved.
        string text = Encoding.UTF8.GetString(outBytes);
        Assert.StartsWith("<?xml", text);
    }

    [Theory]
    [InlineData("02.00.00", true)]
    [InlineData("03.00.00", true)]
    [InlineData("10.20.30", true)]
    [InlineData("2.0.0", false)]
    [InlineData("02.00", false)]
    [InlineData("٠٢.٠٠.٠٠", false)] // Arabic-Indic digits are not ASCII
    [InlineData("02.00.00\n", false)] // trailing newline must be rejected (\z, not $)
    [InlineData("", false)]
    [InlineData(null, false)]
    public void IsValidHwVer_matches_the_NN_NN_NN_shape(string? value, bool expected)
    {
        Assert.Equal(expected, FwzManifest.IsValidHwVer(value));
    }

    [Fact]
    public void Registry_scopes_the_req_hw_ver_fix_to_the_300X13E_door_entry_firmwares()
    {
        // Gating invariant (#191): the fix is curated ONLY for the two exact Classe 300X13E Door Entry
        // (branch 1.7) originals whose fwz.xml omits req_hw_ver on a HW-2.0 unit — keyed by OriginalName,
        // NOT by Line+App. Keying it on the model line would legitimize auto-applying 02.00.00 to ANY
        // future 300X Door Entry firmware (a later branch, or a HW-3.0 generation that needs a different
        // value or none) — exactly the accidental expansion this invariant must catch. Every other
        // firmware (C100X, the Home+Security 300X/EOS, and any not-yet-vetted 300X) must carry no fix, so
        // its fwz.xml is left untouched and its output stays byte-for-byte as before. Any curated value
        // must itself be a valid NN.NN.NN.
        var eligibleOriginals = new HashSet<string>(StringComparer.Ordinal)
        {
            "C300X_010717.fwz", // 300X13E branch 1.7.17
            "C300X_010719.fwz", // 300X13E branch 1.7.19
        };
        foreach (var k in FirmwareRegistry.Known)
        {
            if (eligibleOriginals.Contains(k.OriginalName))
            {
                Assert.Equal("02.00.00", k.ReqHwVerFix);
                Assert.True(FwzManifest.IsValidHwVer(k.ReqHwVerFix));
            }
            else
            {
                Assert.Null(k.ReqHwVerFix);
            }
        }

        // Both curated originals are actually present in the registry (so the "iff" above is not
        // vacuously satisfied by their absence).
        foreach (var original in eligibleOriginals)
            Assert.Contains(FirmwareRegistry.Known, k => k.OriginalName == original);
    }
}
