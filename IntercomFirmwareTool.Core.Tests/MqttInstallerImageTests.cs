using System.Collections.Generic;
using System.Linq;
using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// Integration-style tests that drive the MQTT installer's FACTORY-FIREWALL image I/O (issue #145) against an
/// in-memory filesystem (<see cref="InMemoryExtFs"/>) — the install gate
/// (<see cref="MqttInstaller.PatchFactoryFirewallWaitForLock"/>) and the validation
/// (<see cref="MqttInstaller.CheckFactoryFirewall"/>). These paths — the camera-only gate, absent/symlink/
/// non-executable handling, interpreter resolution + execute bit, and mode/owner preservation — were previously
/// covered only by on-device hardware acceptance; here they run on any CI without SharpExt4 (issue #150).
/// </summary>
public class MqttInstallerImageTests
{
    private const string Hook = "/etc/network/if-pre-up.d/iptables";
    private const string FactoryScript =
        "#!/bin/bash\n" +
        "iptables -F INPUT\n" +
        "iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n" +
        "iptables -P INPUT DROP\n";

    private static InMemoryExtFs FsWithBash() => new InMemoryExtFs().AddExecutable("/bin/bash");

    // ----------------------------- install: PatchFactoryFirewallWaitForLock -----------------------------

    [Fact]
    public void Install_patches_a_clean_hook_and_preserves_mode_and_owner()
    {
        // Seed a DISTINCTIVE mode (0755, exec) and a NON-root owner so the preservation assertions are real:
        // the fake resets a rewritten file to mode 0644 / root, so surviving 0755 / (4242,4343) proves
        // RewritePreservingMeta re-applied the captured metadata (a regression that dropped it would fail here).
        const uint uid = 4242, gid = 4343;
        var fs = FsWithBash().AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0755, uid: uid, gid: gid);
        MqttInstaller.PatchFactoryFirewallWaitForLock(fs);

        string patched = fs.ReadText(Hook)!;
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(patched));
        Assert.Contains("iptables() { command iptables -w \"$@\"; }\n", patched);
        Assert.StartsWith("#!/bin/bash\n", patched);
        Assert.Equal(InMemoryExtFs.Mode0755, fs.ModeOf(Hook));    // mode preserved (a rewrite would leave 0644)
        Assert.Equal((uid, gid), fs.OwnerOf(Hook)!.Value);       // owner preserved (a rewrite would leave 0,0)
    }

    [Fact]
    public void Install_is_idempotent_by_value()
    {
        var fs = FsWithBash().AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0755);
        MqttInstaller.PatchFactoryFirewallWaitForLock(fs);
        string once = fs.ReadText(Hook)!;
        MqttInstaller.PatchFactoryFirewallWaitForLock(fs);
        Assert.Equal(once, fs.ReadText(Hook));                   // re-patch yields byte-identical content
    }

    [Fact]
    public void Install_leaves_no_temp_file_behind()
    {
        // The safe-replace (#151) writes through a sibling ".ift-tmp" and swaps it in; a successful patch must
        // not leave that temp on the image (it would look like a stray/dangling file to later validation).
        var fs = FsWithBash().AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0755);
        MqttInstaller.PatchFactoryFirewallWaitForLock(fs);
        Assert.False(fs.HasFile(Hook + ".ift-tmp"));
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(fs.ReadText(Hook)!));
    }

    [Fact]
    public void Install_recovers_when_a_stale_temp_file_is_present()
    {
        // A prior run interrupted mid-swap could leave a ".ift-tmp"; because RenameFile refuses to overwrite,
        // the replace must clear it first. Seed one and confirm the patch still succeeds and cleans it up.
        var fs = FsWithBash().AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0755);
        fs.AddFile(Hook + ".ift-tmp", "leftover garbage from an interrupted run", InMemoryExtFs.Mode0644);
        MqttInstaller.PatchFactoryFirewallWaitForLock(fs);
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(fs.ReadText(Hook)!));
        Assert.False(fs.HasFile(Hook + ".ift-tmp"));
    }

    [Fact]
    public void Install_leaves_the_original_intact_when_the_write_fails_midway()
    {
        // #151 crux: a failure while producing the replacement must NOT damage the good original. Inject a
        // throw on the temp write; the hook's content, mode and owner must all survive untouched, with no
        // half-written temp left behind — the exact guarantee a bare truncating write cannot make.
        const uint uid = 4242, gid = 4343;
        var inner = FsWithBash().AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0755, uid: uid, gid: gid);
        var fs = new FailOnCreateExtFs(inner, path => path.EndsWith(".ift-tmp", System.StringComparison.Ordinal));

        Assert.ThrowsAny<System.Exception>(() => MqttInstaller.PatchFactoryFirewallWaitForLock(fs));

        Assert.Equal(FactoryScript, inner.ReadText(Hook));        // original content untouched
        Assert.Equal(InMemoryExtFs.Mode0755, inner.ModeOf(Hook)); // original mode untouched
        Assert.Equal((uid, gid), inner.OwnerOf(Hook)!.Value);     // original owner untouched
        Assert.False(inner.HasFile(Hook + ".ift-tmp"));           // partial temp cleaned up
    }

    [Fact]
    public void Install_skips_when_the_hook_is_absent()
    {
        var fs = FsWithBash();
        MqttInstaller.PatchFactoryFirewallWaitForLock(fs);       // a variant that ships no factory hook: no-op
        Assert.False(fs.HasFile(Hook));
    }

    [Fact]
    public void Install_throws_when_the_hook_is_a_symlink()
    {
        var fs = FsWithBash().AddSymlink(Hook, "/some/target");
        Assert.Throws<System.InvalidOperationException>(
            () => MqttInstaller.PatchFactoryFirewallWaitForLock(fs));
    }

    [Fact]
    public void Install_throws_when_the_hook_is_not_executable()
    {
        // run-parts skips a non-executable if-pre-up.d hook, so the shim would never run.
        var fs = FsWithBash().AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0644);
        Assert.Throws<System.InvalidOperationException>(
            () => MqttInstaller.PatchFactoryFirewallWaitForLock(fs));
    }

    [Fact]
    public void Install_throws_when_the_interpreter_is_absent()
    {
        var fs = new InMemoryExtFs().AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0755);  // no /bin/bash
        Assert.Throws<System.InvalidOperationException>(
            () => MqttInstaller.PatchFactoryFirewallWaitForLock(fs));
    }

    [Fact]
    public void Install_throws_when_the_interpreter_is_not_executable()
    {
        var fs = new InMemoryExtFs()
            .AddFile("/bin/bash", "exe", InMemoryExtFs.Mode0644)   // present but not executable
            .AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0755);
        Assert.Throws<System.InvalidOperationException>(
            () => MqttInstaller.PatchFactoryFirewallWaitForLock(fs));
    }

    [Fact]
    public void Install_accepts_an_interpreter_reached_through_a_symlink()
    {
        // #!/bin/sh where /bin/sh -> /bin/busybox (executable): ResolveToRegularFile must follow the link.
        var fs = new InMemoryExtFs()
            .AddSymlink("/bin/sh", "/bin/busybox")
            .AddExecutable("/bin/busybox")
            .AddFile(Hook, "#!/bin/sh\niptables -F INPUT\n", InMemoryExtFs.Mode0755);
        MqttInstaller.PatchFactoryFirewallWaitForLock(fs);
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(fs.ReadText(Hook)!));
    }

    // ----------------------------- validate: CheckFactoryFirewall -----------------------------

    private static Ext4Check Named(IReadOnlyList<Ext4Check> checks, string fragment) =>
        checks.Single(c => c.Name.Contains(fragment));

    private static List<Ext4Check> Validate(InMemoryExtFs fs)
    {
        var checks = new List<Ext4Check>();
        MqttInstaller.CheckFactoryFirewall(fs, checks);
        return checks;
    }

    [Fact]
    public void Validate_a_properly_installed_hook_passes_every_check()
    {
        var fs = FsWithBash().AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0755);
        MqttInstaller.PatchFactoryFirewallWaitForLock(fs);

        var checks = Validate(fs);
        Assert.NotEmpty(checks);
        Assert.All(checks, c => Assert.True(c.Pass, $"{c.Name}: {c.Detail}"));
        Assert.True(Named(checks, "hardened to wait").Pass);
        Assert.True(Named(checks, "interpreter present and executable").Pass);
        Assert.True(Named(checks, "hook is executable").Pass);
    }

    [Fact]
    public void Validate_flags_a_non_executable_hook()
    {
        var fs = FsWithBash().AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0755);
        MqttInstaller.PatchFactoryFirewallWaitForLock(fs);
        fs.SetMode(Hook, InMemoryExtFs.Mode0644);                // demote after install: run-parts would skip it
        Assert.False(Named(Validate(fs), "hook is executable").Pass);
    }

    [Fact]
    public void Validate_flags_a_missing_interpreter()
    {
        // A hardened, executable hook whose #!/bin/bash interpreter is not in the image.
        string hardened = MqttInstaller.EnsureFactoryFirewallShim(FactoryScript);
        var fs = new InMemoryExtFs().AddFile(Hook, hardened, InMemoryExtFs.Mode0755);  // no /bin/bash
        Assert.False(Named(Validate(fs), "interpreter present and executable").Pass);
    }

    [Fact]
    public void Validate_flags_a_symlink_hook_as_not_regular()
    {
        var fs = FsWithBash().AddSymlink(Hook, "/some/target");
        Assert.False(Named(Validate(fs), "regular, hardenable").Pass);
    }

    [Fact]
    public void Validate_adds_no_checks_when_the_hook_is_absent()
    {
        Assert.Empty(Validate(FsWithBash()));
    }
}
