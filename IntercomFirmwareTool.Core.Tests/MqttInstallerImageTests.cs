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
        var fs = FsWithBash().AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0755, uid: 0, gid: 0);
        MqttInstaller.PatchFactoryFirewallWaitForLock(fs);

        string patched = fs.ReadText(Hook)!;
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(patched));
        Assert.Contains("iptables() { command iptables -w \"$@\"; }\n", patched);
        Assert.StartsWith("#!/bin/bash\n", patched);
        Assert.Equal(InMemoryExtFs.Mode0755, fs.ModeOf(Hook));    // mode preserved (a fresh file would be 0644)
        Assert.Equal((0u, 0u), fs.OwnerOf(Hook)!.Value);         // owner preserved
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
