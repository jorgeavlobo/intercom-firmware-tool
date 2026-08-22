using System;
using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// Tests that #156 routes <see cref="Ext4Probe"/>'s in-place auth-file edits (<c>/etc/passwd</c>,
/// <c>/etc/shadow</c>, <c>/etc/default/dropbear</c>) through the shared crash-safe primitive
/// (<see cref="ExtFsRewrite"/>). A truncated <c>/etc/shadow</c> is the highest-blast-radius corruption in the
/// image — it can lock every account out of login — so these assert the same crash-safety the factory-firewall
/// and hosts paths have: metadata preservation, rollback on a failed swap, recovery of an interrupted swap, and a
/// caught partial write — all against the in-memory <see cref="InMemoryExtFs"/>, no native SharpExt4 required.
/// </summary>
public class Ext4ProbeAuthRewriteTests
{
    private const string Shadow = "/etc/shadow";
    private const string BaseShadow = "root:$1$root$abc:18000:0:99999:7:::\n";
    private const string NewRoot2 = "root2:*:18033:0:99999:7:::";

    private const string DropbearDefaults = "/etc/default/dropbear";

    // ---- AppendLines (/etc/passwd, /etc/shadow) ----

    [Fact]
    public void AppendLines_appends_and_preserves_mode_and_owner()
    {
        // /etc/shadow must survive at 0600; a distinctive owner (4242,4343) makes the preservation assertion real —
        // the fake resets a rewritten file to 0644/root, so surviving 0600/(4242,4343) proves the crash-safe swap
        // re-applied the captured metadata rather than the raw create's defaults.
        const uint uid = 4242, gid = 4343;
        var fs = new InMemoryExtFs().AddFile(Shadow, BaseShadow, InMemoryExtFs.Mode0600, uid: uid, gid: gid);

        Ext4Probe.AppendLines(fs, Shadow, new[] { NewRoot2 });

        string result = fs.ReadText(Shadow)!;
        Assert.StartsWith(BaseShadow, result);                     // original line kept, new one appended after
        Assert.Contains(NewRoot2, result);
        Assert.Equal(InMemoryExtFs.Mode0600, fs.ModeOf(Shadow));   // preserved through the crash-safe swap
        Assert.Equal((uid, gid), fs.OwnerOf(Shadow)!.Value);
        Assert.False(fs.HasFile(Shadow + ".ift-tmp"));             // no swap siblings left behind
        Assert.False(fs.HasFile(Shadow + ".ift-bak"));
    }

    [Fact]
    public void AppendLines_refuses_a_missing_file()
    {
        var fs = new InMemoryExtFs();   // no /etc/shadow: creating it would give it unknown metadata
        Assert.Throws<InvalidOperationException>(() =>
            Ext4Probe.AppendLines(fs, Shadow, new[] { NewRoot2 }));
    }

    [Fact]
    public void AppendLines_leaves_the_original_intact_when_the_swap_rename_fails()
    {
        const uint uid = 4242, gid = 4343;
        var inner = new InMemoryExtFs().AddFile(Shadow, BaseShadow, InMemoryExtFs.Mode0600, uid: uid, gid: gid);
        string original = inner.ReadText(Shadow)!;
        var fs = new FaultyExtFs(inner, failRename: (src, dest) =>
            src.EndsWith(".ift-tmp", StringComparison.Ordinal) && dest == Shadow);

        Assert.ThrowsAny<Exception>(() => Ext4Probe.AppendLines(fs, Shadow, new[] { NewRoot2 }));

        Assert.Equal(original, inner.ReadText(Shadow));            // rolled back from .ift-bak — shadow not truncated
        Assert.Equal(InMemoryExtFs.Mode0600, inner.ModeOf(Shadow));
        Assert.Equal((uid, gid), inner.OwnerOf(Shadow)!.Value);
        Assert.False(inner.HasFile(Shadow + ".ift-tmp"));
        Assert.False(inner.HasFile(Shadow + ".ift-bak"));
    }

    [Fact]
    public void AppendLines_recovers_a_swap_interrupted_after_the_original_was_backed_up()
    {
        const uint uid = 4242, gid = 4343;
        // Crash between the two swap renames: shadow is absent while its .ift-bak backup holds the original.
        var fs = new InMemoryExtFs()
            .AddFile(Shadow + ".ift-bak", BaseShadow, InMemoryExtFs.Mode0600, uid: uid, gid: gid);
        Assert.False(fs.HasFile(Shadow));

        Ext4Probe.AppendLines(fs, Shadow, new[] { NewRoot2 });

        Assert.True(fs.HasFile(Shadow));                          // recovered from the backup, not "file missing"
        string result = fs.ReadText(Shadow)!;
        Assert.StartsWith(BaseShadow, result);
        Assert.Contains(NewRoot2, result);                        // then patched
        Assert.Equal(InMemoryExtFs.Mode0600, fs.ModeOf(Shadow));  // metadata carried through recovery + swap
        Assert.Equal((uid, gid), fs.OwnerOf(Shadow)!.Value);
        Assert.False(fs.HasFile(Shadow + ".ift-bak"));
        Assert.False(fs.HasFile(Shadow + ".ift-tmp"));
    }

    [Fact]
    public void AppendLines_catches_a_partial_temp_write_and_keeps_the_original()
    {
        const uint uid = 4242, gid = 4343;
        var inner = new InMemoryExtFs().AddFile(Shadow, BaseShadow, InMemoryExtFs.Mode0600, uid: uid, gid: gid);
        string original = inner.ReadText(Shadow)!;
        // The temp write lands only a prefix then throws; the failure is caught while the original is still in
        // place and nothing has moved yet.
        var fs = new FaultyExtFs(inner, failPartialWrite: p => p == Shadow + ".ift-tmp");

        Assert.ThrowsAny<Exception>(() => Ext4Probe.AppendLines(fs, Shadow, new[] { NewRoot2 }));

        Assert.Equal(original, inner.ReadText(Shadow));           // untouched
        Assert.Equal(InMemoryExtFs.Mode0600, inner.ModeOf(Shadow));
        Assert.Equal((uid, gid), inner.OwnerOf(Shadow)!.Value);
        Assert.False(inner.HasFile(Shadow + ".ift-tmp"));         // partial temp cleaned up
        Assert.False(inner.HasFile(Shadow + ".ift-bak"));
    }

    // ---- PatchDropbearDefaults (/etc/default/dropbear) ----

    [Fact]
    public void PatchDropbearDefaults_edits_the_existing_factory_file_and_asserts_canonical_meta()
    {
        // Factory file present with a non-standard mode/owner: the patch must land the -r directive, preserve the
        // factory line, go through the crash-safe swap (no siblings), and normalize to the canonical 0644 root:root.
        var fs = new InMemoryExtFs().AddFile(
            DropbearDefaults, "DROPBEAR_EXTRA_ARGS=\"-B\"\n", InMemoryExtFs.Mode0600, uid: 4242, gid: 4343);

        Ext4Probe.PatchDropbearDefaults(fs, pinRsa: false);

        string result = fs.ReadText(DropbearDefaults)!;
        Assert.StartsWith("DROPBEAR_EXTRA_ARGS=\"-B\"\n", result);       // factory content preserved
        Assert.Contains("-r " + Ext4Probe.EcdsaHostKeyPath, result);    // #37 directive appended
        Assert.Equal(InMemoryExtFs.Mode0644, fs.ModeOf(DropbearDefaults));  // canonical, re-asserted
        Assert.Equal((0u, 0u), fs.OwnerOf(DropbearDefaults)!.Value);
        Assert.False(fs.HasFile(DropbearDefaults + ".ift-tmp"));
        Assert.False(fs.HasFile(DropbearDefaults + ".ift-bak"));
    }

    [Fact]
    public void PatchDropbearDefaults_leaves_the_original_intact_when_the_swap_rename_fails()
    {
        const string factory = "DROPBEAR_EXTRA_ARGS=\"-B\"\n";
        var inner = new InMemoryExtFs().AddFile(DropbearDefaults, factory, InMemoryExtFs.Mode0644);
        var fs = new FaultyExtFs(inner, failRename: (src, dest) =>
            src.EndsWith(".ift-tmp", StringComparison.Ordinal) && dest == DropbearDefaults);

        Assert.ThrowsAny<Exception>(() => Ext4Probe.PatchDropbearDefaults(fs, pinRsa: false));

        Assert.Equal(factory, inner.ReadText(DropbearDefaults));   // rolled back — factory config not truncated
        Assert.False(inner.HasFile(DropbearDefaults + ".ift-tmp"));
        Assert.False(inner.HasFile(DropbearDefaults + ".ift-bak"));
    }

    [Fact]
    public void PatchDropbearDefaults_creates_the_file_when_absent()
    {
        var fs = new InMemoryExtFs();   // non-factory image: no /etc/default/dropbear
        Assert.False(fs.HasFile(DropbearDefaults));

        Ext4Probe.PatchDropbearDefaults(fs, pinRsa: true);

        Assert.True(fs.HasFile(DropbearDefaults));
        string result = fs.ReadText(DropbearDefaults)!;
        Assert.Contains("DROPBEAR_RSAKEY=" + Ext4Probe.RsaHostKeyPath, result);   // #38 pin
        Assert.Contains("-r " + Ext4Probe.EcdsaHostKeyPath, result);             // #37 directive
        Assert.Equal(InMemoryExtFs.Mode0644, fs.ModeOf(DropbearDefaults));
    }

    [Fact]
    public void PatchDropbearDefaults_is_a_no_op_when_already_configured()
    {
        string configured =
            "DROPBEAR_RSAKEY=" + Ext4Probe.RsaHostKeyPath + "\n" +
            "DROPBEAR_EXTRA_ARGS=\"$DROPBEAR_EXTRA_ARGS -r " + Ext4Probe.EcdsaHostKeyPath + "\"\n";
        // Distinctive 0600 makes the early-return provable: a rewrite would re-assert 0644, so surviving 0600 (and
        // identical content, no siblings) proves no write ran.
        var fs = new InMemoryExtFs().AddFile(DropbearDefaults, configured, InMemoryExtFs.Mode0600);

        Ext4Probe.PatchDropbearDefaults(fs, pinRsa: true);

        Assert.Equal(configured, fs.ReadText(DropbearDefaults));            // unchanged
        Assert.Equal(InMemoryExtFs.Mode0600, fs.ModeOf(DropbearDefaults));  // no rewrite → 0644 never asserted
        Assert.False(fs.HasFile(DropbearDefaults + ".ift-tmp"));
        Assert.False(fs.HasFile(DropbearDefaults + ".ift-bak"));
    }
}
