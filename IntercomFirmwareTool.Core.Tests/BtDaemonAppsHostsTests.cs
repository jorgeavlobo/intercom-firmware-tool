using System;
using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// Tests the boot-time hosts patcher (<see cref="BtDaemonAppsHosts"/>) now that #154 routes its in-place rewrite
/// of <c>/etc/init.d/bt_daemon-apps.sh</c> through the shared crash-safe primitive (<see cref="ExtFsRewrite"/>).
/// Beyond the mapping logic, these assert the same crash-safety the factory-firewall path has: metadata
/// preservation, rollback on a failed swap, and recovery of an interrupted swap — all against the in-memory
/// <see cref="InMemoryExtFs"/>, no native SharpExt4 required.
/// </summary>
public class BtDaemonAppsHostsTests
{
    private const string Script = "/etc/init.d/bt_daemon-apps.sh";
    private const string BaseScript =
        "#!/bin/sh\n" +
        "\t/bin/bt_hosts.sh add openserver 127.0.0.1\n";

    private static InMemoryExtFs FsWithScript(uint uid = 0, uint gid = 0) =>
        new InMemoryExtFs().AddFile(Script, BaseScript, InMemoryExtFs.Mode0755, uid: uid, gid: gid);

    [Fact]
    public void AddMappings_inserts_after_the_anchor_and_preserves_mode_and_owner()
    {
        // Non-root owner + distinctive mode so the preservation assertions are real (the fake resets a rewritten
        // file to 0644/root, so surviving 0755/(4242,4343) proves the swap re-applied the captured metadata).
        const uint uid = 4242, gid = 4343;
        var fs = FsWithScript(uid, gid);
        BtDaemonAppsHosts.AddMappings(fs, new[] { ("broker.example.com", "192.168.1.5") });

        Assert.True(BtDaemonAppsHosts.HasMapping(fs, "broker.example.com", "192.168.1.5"));
        Assert.Equal(InMemoryExtFs.Mode0755, fs.ModeOf(Script));   // preserved through the crash-safe swap
        Assert.Equal((uid, gid), fs.OwnerOf(Script)!.Value);
        Assert.False(fs.HasFile(Script + ".ift-tmp"));             // no swap siblings left behind
        Assert.False(fs.HasFile(Script + ".ift-bak"));
    }

    [Fact]
    public void AddMappings_is_idempotent_by_value()
    {
        var fs = FsWithScript();
        BtDaemonAppsHosts.AddMappings(fs, new[] { ("broker.example.com", "192.168.1.5") });
        string once = fs.ReadText(Script)!;
        BtDaemonAppsHosts.AddMappings(fs, new[] { ("broker.example.com", "192.168.1.5") });
        Assert.Equal(once, fs.ReadText(Script));                   // already present → no second insert, no rewrite
    }

    [Fact]
    public void AddMappings_leaves_the_original_intact_when_the_swap_rename_fails()
    {
        const uint uid = 4242, gid = 4343;
        var inner = FsWithScript(uid, gid);
        string original = inner.ReadText(Script)!;
        var fs = new FaultyExtFs(inner, failRename: (src, dest) =>
            src.EndsWith(".ift-tmp", StringComparison.Ordinal) && dest == Script);

        Assert.ThrowsAny<Exception>(() =>
            BtDaemonAppsHosts.AddMappings(fs, new[] { ("broker.example.com", "192.168.1.5") }));

        Assert.Equal(original, inner.ReadText(Script));            // rolled back from .ift-bak
        Assert.Equal(InMemoryExtFs.Mode0755, inner.ModeOf(Script));
        Assert.Equal((uid, gid), inner.OwnerOf(Script)!.Value);
        Assert.False(inner.HasFile(Script + ".ift-tmp"));
        Assert.False(inner.HasFile(Script + ".ift-bak"));
    }

    [Fact]
    public void AddMappings_recovers_a_swap_interrupted_after_the_original_was_backed_up()
    {
        const uint uid = 4242, gid = 4343;
        // Crash between the two swap renames: the script is absent while its .ift-bak backup holds the original.
        var fs = new InMemoryExtFs()
            .AddFile(Script + ".ift-bak", BaseScript, InMemoryExtFs.Mode0755, uid: uid, gid: gid);
        Assert.False(fs.HasFile(Script));

        BtDaemonAppsHosts.AddMappings(fs, new[] { ("broker.example.com", "192.168.1.5") });

        Assert.True(fs.HasFile(Script));                          // recovered from the backup, not "file missing"
        Assert.True(BtDaemonAppsHosts.HasMapping(fs, "broker.example.com", "192.168.1.5"));  // then patched
        Assert.Equal(InMemoryExtFs.Mode0755, fs.ModeOf(Script));  // metadata carried through recovery + swap
        Assert.Equal((uid, gid), fs.OwnerOf(Script)!.Value);
        Assert.False(fs.HasFile(Script + ".ift-bak"));
        Assert.False(fs.HasFile(Script + ".ift-tmp"));
    }
}
