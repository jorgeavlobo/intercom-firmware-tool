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
        Assert.False(fs.HasFile(Hook + ".ift-bak"));
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(fs.ReadText(Hook)!));
    }

    [Fact]
    public void Install_recovers_when_a_stale_temp_file_is_present()
    {
        // A prior run interrupted mid-swap could leave a ".ift-tmp" and/or ".ift-bak"; because RenameFile
        // refuses to overwrite, the replace must clear both first. Seed both and confirm the patch still
        // succeeds and cleans them up.
        var fs = FsWithBash().AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0755);
        fs.AddFile(Hook + ".ift-tmp", "leftover staged content from an interrupted run", InMemoryExtFs.Mode0644);
        fs.AddFile(Hook + ".ift-bak", "leftover backup from an interrupted run", InMemoryExtFs.Mode0644);
        MqttInstaller.PatchFactoryFirewallWaitForLock(fs);
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(fs.ReadText(Hook)!));
        Assert.False(fs.HasFile(Hook + ".ift-tmp"));
        Assert.False(fs.HasFile(Hook + ".ift-bak"));
    }

    [Fact]
    public void Install_leaves_the_original_intact_when_the_write_fails_midway()
    {
        // #151 crux: a failure while producing the replacement must NOT damage the good original. Inject a
        // throw on the temp write; the hook's content, mode and owner must all survive untouched, with no
        // half-written temp left behind — the exact guarantee a bare truncating write cannot make.
        const uint uid = 4242, gid = 4343;
        var inner = FsWithBash().AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0755, uid: uid, gid: gid);
        var fs = new FaultyExtFs(inner, failCreate: path => path.EndsWith(".ift-tmp", System.StringComparison.Ordinal));

        Assert.ThrowsAny<System.Exception>(() => MqttInstaller.PatchFactoryFirewallWaitForLock(fs));

        Assert.Equal(FactoryScript, inner.ReadText(Hook));        // original content untouched
        Assert.Equal(InMemoryExtFs.Mode0755, inner.ModeOf(Hook)); // original mode untouched
        Assert.Equal((uid, gid), inner.OwnerOf(Hook)!.Value);     // original owner untouched
        Assert.False(inner.HasFile(Hook + ".ift-tmp"));           // no temp was ever created
    }

    [Fact]
    public void Install_cleans_up_a_partially_written_temp_and_keeps_the_original()
    {
        // The scenario #151 targets: the write CREATES the temp, lands a prefix, then dies — leaving a partial
        // temp on the image. The original must be untouched (nothing has moved yet) and the partial temp must be
        // removed, not left dangling for the next run.
        const uint uid = 4242, gid = 4343;
        var inner = FsWithBash().AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0755, uid: uid, gid: gid);
        var fs = new FaultyExtFs(inner,
            failPartialWrite: path => path.EndsWith(".ift-tmp", System.StringComparison.Ordinal));

        Assert.ThrowsAny<System.Exception>(() => MqttInstaller.PatchFactoryFirewallWaitForLock(fs));

        Assert.Equal(FactoryScript, inner.ReadText(Hook));        // original content untouched
        Assert.Equal(InMemoryExtFs.Mode0755, inner.ModeOf(Hook)); // original mode untouched
        Assert.Equal((uid, gid), inner.OwnerOf(Hook)!.Value);     // original owner untouched
        Assert.False(inner.HasFile(Hook + ".ift-tmp"));           // the PARTIAL temp was cleaned up
    }

    [Fact]
    public void Install_rolls_the_original_back_when_the_final_swap_rename_fails()
    {
        // The crux the reviewers flagged: the commit is a backup-swap (original -> .ift-bak, temp -> hook), so
        // if the temp -> hook rename fails after the original has been moved aside, the original must be ROLLED
        // BACK from the backup — the hook can never be left absent. Inject a failure on exactly that rename.
        const uint uid = 4242, gid = 4343;
        var inner = FsWithBash().AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0755, uid: uid, gid: gid);
        var fs = new FaultyExtFs(inner, failRename: (src, dest) =>
            src.EndsWith(".ift-tmp", System.StringComparison.Ordinal) &&
            dest == Hook);

        Assert.ThrowsAny<System.Exception>(() => MqttInstaller.PatchFactoryFirewallWaitForLock(fs));

        Assert.Equal(FactoryScript, inner.ReadText(Hook));        // original rolled back into place
        Assert.Equal(InMemoryExtFs.Mode0755, inner.ModeOf(Hook)); // with its mode intact
        Assert.Equal((uid, gid), inner.OwnerOf(Hook)!.Value);     // and its owner intact
        Assert.False(inner.HasFile(Hook + ".ift-tmp"));           // staged temp cleaned up
        Assert.False(inner.HasFile(Hook + ".ift-bak"));           // backup consumed by the rollback
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

    [Fact]
    public void Install_recovers_a_swap_interrupted_after_the_original_was_backed_up()
    {
        // Simulate a crash between the two swap renames: the hook is absent while its ".ift-bak" backup still
        // holds the intact original. A fresh install must RESTORE the backup (not treat the hook as absent and
        // skip), then harden it — preserving the original's mode/owner through the recovery.
        const uint uid = 4242, gid = 4343;
        var fs = FsWithBash().AddFile(Hook + ".ift-bak", FactoryScript, InMemoryExtFs.Mode0755, uid: uid, gid: gid);
        Assert.False(fs.HasFile(Hook));                          // precondition: the real path is missing

        MqttInstaller.PatchFactoryFirewallWaitForLock(fs);

        Assert.True(fs.HasFile(Hook));                           // original recovered from the backup
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(fs.ReadText(Hook)!));
        Assert.Equal(InMemoryExtFs.Mode0755, fs.ModeOf(Hook));   // recovered with its mode
        Assert.Equal((uid, gid), fs.OwnerOf(Hook)!.Value);       // and its owner
        Assert.False(fs.HasFile(Hook + ".ift-bak"));             // backup consumed by the recovery
        Assert.False(fs.HasFile(Hook + ".ift-tmp"));
    }

    [Fact]
    public void Install_deletes_a_stale_backup_left_by_a_completed_swap()
    {
        // Crash AFTER the swap promoted temp -> hook but BEFORE the backup was deleted: the hook is present and
        // already hardened, so the idempotency check skips the rewrite. The stale (and executable) .ift-bak must
        // still be cleaned up on the next run rather than lingering permanently in the image.
        string hardened = MqttInstaller.EnsureFactoryFirewallShim(FactoryScript);
        var fs = FsWithBash().AddFile(Hook, hardened, InMemoryExtFs.Mode0755);
        fs.AddFile(Hook + ".ift-bak", FactoryScript, InMemoryExtFs.Mode0755);   // stale backup of the pre-swap original

        MqttInstaller.PatchFactoryFirewallWaitForLock(fs);

        Assert.False(fs.HasFile(Hook + ".ift-bak"));             // stale backup removed
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(fs.ReadText(Hook)!));   // hook itself untouched
    }

    [Fact]
    public void Install_deletes_a_stale_temp_when_the_target_is_already_hardened()
    {
        // Same completed-but-uncleaned shape, for the OTHER sibling: an already-hardened hook makes the
        // idempotency check skip the rewrite (and its ClearSwapSibling cleanup), so a stale .ift-tmp must be
        // dropped by recovery rather than left in the image.
        string hardened = MqttInstaller.EnsureFactoryFirewallShim(FactoryScript);
        var fs = FsWithBash().AddFile(Hook, hardened, InMemoryExtFs.Mode0755);
        fs.AddFile(Hook + ".ift-tmp", "leftover staged content from an interrupted run", InMemoryExtFs.Mode0644);

        MqttInstaller.PatchFactoryFirewallWaitForLock(fs);

        Assert.False(fs.HasFile(Hook + ".ift-tmp"));             // stale temp removed
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(fs.ReadText(Hook)!));   // hook itself untouched
    }

    [Fact]
    public void Install_fails_closed_when_a_swap_sibling_is_a_non_regular_node()
    {
        // A symlink/dir at a tool-reserved swap path is an anomaly. Recovery clears siblings via
        // ClearSwapSibling, which FAILS CLOSED on a non-regular node — so even an otherwise-idempotent run
        // (hook already hardened) must throw rather than silently leave the unexpected shape in the image.
        string hardened = MqttInstaller.EnsureFactoryFirewallShim(FactoryScript);
        var fs = FsWithBash().AddFile(Hook, hardened, InMemoryExtFs.Mode0755);
        fs.AddSymlink(Hook + ".ift-tmp", "/some/target");
        Assert.Throws<System.InvalidOperationException>(
            () => MqttInstaller.PatchFactoryFirewallWaitForLock(fs));
    }

    [Fact]
    public void Install_fails_closed_on_a_non_regular_sibling_even_when_the_target_is_absent()
    {
        // The absent-hook ("no factory firewall" variant) no-op must not become a loophole: a non-regular node
        // at a reserved swap path still fails closed, since recovery reconciles both siblings before the caller
        // decides the target is genuinely absent.
        var fs = FsWithBash();                                    // no hook present
        fs.AddSymlink(Hook + ".ift-bak", "/some/target");
        Assert.Throws<System.InvalidOperationException>(
            () => MqttInstaller.PatchFactoryFirewallWaitForLock(fs));
    }

    // ----------------------------- recovery: other RewritePreservingMeta callers -----------------------------

    [Fact]
    public void Flexisip_recovers_a_swap_interrupted_after_the_original_was_backed_up()
    {
        // The recovery must guard EVERY rewrite entry path, not just the firewall: PatchFlexisip throws
        // Mqtt_FileMissing if its target is absent, so without recovery an interrupted flexisip swap (original
        // stranded in .ift-bak) would be unrecoverable. Seed that crash state and assert it recovers + patches,
        // preserving the script's non-root mode/owner.
        const string Flexisip = "/etc/init.d/flexisipsh";
        const uint uid = 500, gid = 500;
        const string script =
            "#!/bin/sh\n" +
            "case \"$1\" in\n" +
            "start)\n" +
            "\tstart-stop-daemon --start --exec /usr/bin/flexisip\n" +
            "\t;;\n" +
            "esac\n";
        var fs = new InMemoryExtFs().AddFile(Flexisip + ".ift-bak", script, InMemoryExtFs.Mode0755, uid: uid, gid: gid);
        Assert.False(fs.HasFile(Flexisip));                       // precondition: target missing

        MqttInstaller.PatchFlexisip(fs);

        Assert.True(fs.HasFile(Flexisip));                        // recovered from .ift-bak, not thrown as missing
        Assert.Contains("/bin/touch /tmp/flexisip_restarted", fs.ReadText(Flexisip)!);   // then patched
        Assert.Equal(InMemoryExtFs.Mode0755, fs.ModeOf(Flexisip));// mode preserved through recovery + rewrite
        Assert.Equal((uid, gid), fs.OwnerOf(Flexisip)!.Value);    // owner preserved
        Assert.False(fs.HasFile(Flexisip + ".ift-bak"));          // transient swap backup consumed
        Assert.False(fs.HasFile(Flexisip + ".ift-tmp"));
        Assert.True(fs.HasFile(Flexisip + "_bak"));               // PatchFlexisip's persistent revert backup exists
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

    // ----------------------------- #149: interpreter reached through a SYMLINKED PARENT -----------------------------

    // A merged-/usr layout: `/bin` is a SYMLINK to `usr/bin`, and the real interpreter lives at
    // `/usr/bin/bash`. A `#!/bin/bash` hook must still resolve — the resolver has to follow the intermediate
    // `/bin` symlink, which the ext reader never traverses on the whole path (so a plain FileExists/ReadSymLink
    // on `/bin/bash` both fail). Before #149 this false-failed as an absent interpreter and aborted the install.
    private static InMemoryExtFs FsWithMergedUsrBash() =>
        new InMemoryExtFs().AddSymlink("/bin", "usr/bin").AddExecutable("/usr/bin/bash");

    [Fact]
    public void Install_hardens_when_the_interpreter_is_reached_through_a_symlinked_parent()
    {
        var fs = FsWithMergedUsrBash().AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0755);
        MqttInstaller.PatchFactoryFirewallWaitForLock(fs);           // must NOT throw Unhardenable (#149)
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(fs.ReadText(Hook)!));
    }

    [Fact]
    public void Validate_passes_when_the_interpreter_is_reached_through_a_symlinked_parent()
    {
        var fs = FsWithMergedUsrBash().AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0755);
        MqttInstaller.PatchFactoryFirewallWaitForLock(fs);
        Assert.True(Named(Validate(fs), "interpreter present and executable").Pass);
    }

    [Fact]
    public void Validate_passes_when_the_symlinked_parent_target_is_absolute()
    {
        // Same, but the parent symlink target is ABSOLUTE (`/bin -> /usr/bin`): resolution restarts from the root.
        var fs = new InMemoryExtFs().AddSymlink("/bin", "/usr/bin").AddExecutable("/usr/bin/bash")
            .AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0755);
        MqttInstaller.PatchFactoryFirewallWaitForLock(fs);
        Assert.True(Named(Validate(fs), "interpreter present and executable").Pass);
    }

    [Fact]
    public void Install_still_fails_closed_when_a_symlinked_parent_leads_to_a_non_executable_interpreter()
    {
        // Fail-safe preserved: resolving the parent must not paper over a real problem — a present-but-
        // NON-executable interpreter (0644) is still unhardenable.
        var fs = new InMemoryExtFs().AddSymlink("/bin", "usr/bin")
            .AddFile("/usr/bin/bash", "elf", InMemoryExtFs.Mode0644)  // reachable via the symlinked parent, but 0644
            .AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0755);
        Assert.Throws<System.InvalidOperationException>(
            () => MqttInstaller.PatchFactoryFirewallWaitForLock(fs));
    }

    [Fact]
    public void Validate_still_flags_a_dangling_symlinked_parent_interpreter()
    {
        // `/bin -> usr/bin` but nothing at `/usr/bin/bash`: the interpreter is genuinely absent → not hardened.
        string hardened = MqttInstaller.EnsureFactoryFirewallShim(FactoryScript);
        var fs = new InMemoryExtFs().AddSymlink("/bin", "usr/bin")
            .AddFile(Hook, hardened, InMemoryExtFs.Mode0755);         // no /usr/bin/bash anywhere
        Assert.False(Named(Validate(fs), "interpreter present and executable").Pass);
    }

    [Fact]
    public void Install_fails_closed_when_a_symlink_target_uses_dotdot_to_escape_a_nonexistent_component()
    {
        // A crafted target `missing/../sh` where `missing` does NOT exist: Linux fails resolution AT `missing`,
        // so the interpreter is unrunnable. The resolver must NOT collapse `..` lexically to reach the real
        // `/bin/sh` and falsely certify the hook — it must fail closed (#149, kernel-faithful `..`).
        var fs = new InMemoryExtFs()
            .AddSymlink("/bin/bash", "missing/../sh")   // `#!/bin/bash` → missing/../sh (relative to /bin)
            .AddExecutable("/bin/sh")                   // the real shell the `..` would wrongly reach
            .AddFile(Hook, FactoryScript, InMemoryExtFs.Mode0755);
        Assert.Throws<System.InvalidOperationException>(
            () => MqttInstaller.PatchFactoryFirewallWaitForLock(fs));
    }
}
