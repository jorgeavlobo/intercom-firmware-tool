using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// The factory-firewall xtables-lock hardening (issue #145). The panel's factory firewall
/// (<c>/etc/network/if-pre-up.d/iptables</c>) rebuilds INPUT with LOCK-LESS <c>iptables -A</c> calls; with
/// the on-device camera's go2rtc rule as a second iptables writer, a factory call that overlaps our lock
/// hold fails silently and a factory rule (SSH <c>:22</c>, the FTP-over-USB reflash <c>:21</c>, security
/// DROPs) goes missing — observed on hardware as SSH / reflash lockouts. The installer inserts a plain
/// shell shim after the script's shebang that shadows <c>iptables</c> with a function injecting
/// <c>--wait</c>, so every subsequent factory call blocks for the lock instead of dropping a rule. It is a
/// POSIX function shim (works under any <c>#!</c> interpreter) and is deliberately NOT tamper-proofed against
/// a hand-edit that later redefines <c>iptables</c> — that is out of scope for a fixed, known factory hook.
/// These tests pin the pure splice (<see cref="MqttInstaller.EnsureFactoryFirewallShim"/>): placement,
/// content, idempotency, CRLF normalization, tolerance of later redefinitions, and rejection of a malformed
/// (no-shebang or unterminated-block) script.
/// </summary>
public class MqttFactoryFirewallShimTests
{
    // A representative slice of the real C100X v1.5.8 factory script (shebang + a couple of the
    // lock-less rebuild lines) — enough to assert the shim lands between the shebang and the first call.
    private const string FactoryScript =
        "#!/bin/bash\n" +
        "\n" +
        "##   INPUT  ##\n" +
        "iptables -F INPUT\n" +
        "iptables -Z INPUT\n" +
        "for i in 22 53 67 68 5061 5353 5678 50003; do\n" +
        "\tiptables -A INPUT -p tcp -m tcp --dport $i -j ACCEPT\n" +
        "done\n" +
        "iptables -P INPUT DROP\n";

    [Fact]
    public void Shim_is_inserted_immediately_after_the_shebang()
    {
        string patched = MqttInstaller.EnsureFactoryFirewallShim(FactoryScript);
        var lines = patched.Split('\n');
        // Line 0 is still the original shebang; the shim's opening marker line comes right after it, so
        // the `iptables` function is defined before ANY factory `iptables` call runs.
        Assert.Equal("#!/bin/bash", lines[0]);
        Assert.StartsWith("# >>> IntercomFirmwareTool #145", lines[1]);
        // The ENTIRE original body after the shebang is preserved verbatim (order + content), after the
        // shim — so a regression that dropped or reordered any factory rule would fail, not just these two.
        int shebangEnd = FactoryScript.IndexOf('\n') + 1;
        Assert.EndsWith(FactoryScript[shebangEnd..], patched);
    }

    [Fact]
    public void Shim_defines_a_waiting_iptables_function()
    {
        string patched = MqttInstaller.EnsureFactoryFirewallShim(FactoryScript);
        // The whole point: shadow `iptables` with a function that injects --wait and reaches the real
        // binary via `command` (no recursion). A plain function shim — no readonly pin (out of scope; see
        // the FactoryFirewallShim comment).
        Assert.Contains("iptables() { command iptables -w \"$@\"; }\n", patched);
        Assert.DoesNotContain("readonly -f", patched);   // no pin — deliberately not tamper-proofed
    }

    [Fact]
    public void Shim_appears_before_the_first_factory_iptables_call()
    {
        string patched = MqttInstaller.EnsureFactoryFirewallShim(FactoryScript);
        int fnDef = patched.IndexOf("iptables() { command iptables -w", System.StringComparison.Ordinal);
        int firstCall = patched.IndexOf("iptables -F INPUT", System.StringComparison.Ordinal);
        Assert.True(fnDef >= 0 && firstCall >= 0);
        Assert.True(fnDef < firstCall, "the function shim must be defined before the first factory call");
    }

    [Fact]
    public void Patching_is_idempotent_no_second_block_on_an_already_hardened_script()
    {
        string once = MqttInstaller.EnsureFactoryFirewallShim(FactoryScript);
        string twice = MqttInstaller.EnsureFactoryFirewallShim(once);
        // A second pass must not insert a second shim — the output is byte-identical (the installer
        // compares by value and skips the redundant write).
        Assert.Equal(once, twice);
        // Exactly one shim block: two marker lines (the ">>>" opener and "<<<" closer).
        int count = 0, i = 0;
        while ((i = twice.IndexOf("IntercomFirmwareTool #145", i, System.StringComparison.Ordinal)) >= 0)
        { count++; i += 1; }
        Assert.Equal(2, count);
    }

    [Fact]
    public void A_script_without_a_trailing_newline_still_gets_the_shim()
    {
        // Degenerate shebang-only script with no newline: the shim is appended after the content, so the
        // function is still defined (before the — here absent — factory calls).
        string patched = MqttInstaller.EnsureFactoryFirewallShim("#!/bin/bash");
        Assert.Contains("iptables() { command iptables -w \"$@\"; }\n", patched);
        Assert.StartsWith("#!/bin/bash\n", patched);
    }

    [Fact]
    public void A_marker_comment_without_the_function_line_is_re_patched_not_skipped()
    {
        // The marker COMMENT alone must not count as hardened — only the operative function line does.
        // A script that kept the marker but lost the function (truncation / hand-edit) must be
        // re-patched so the factory calls actually wait for the lock.
        string tampered =
            "#!/bin/bash\n" +
            "# >>> IntercomFirmwareTool #145: make the factory firewall WAIT for the xtables lock >>>\n" +
            "# (function line removed by tampering)\n" +
            "# <<< IntercomFirmwareTool #145 <<<\n" +
            "iptables -F INPUT\n";
        string patched = MqttInstaller.EnsureFactoryFirewallShim(tampered);
        Assert.NotEqual(tampered, patched);                                   // the text actually changed (re-patched)
        Assert.Contains("iptables() { command iptables -w \"$@\"; }\n", patched); // now really hardened
    }

    [Fact]
    public void An_active_shim_before_the_calls_is_hardened_but_inert_text_is_not()
    {
        // The normal installer output — active function right after the shebang, before any call — is
        // effectively hardened.
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(
            MqttInstaller.EnsureFactoryFirewallShim(FactoryScript)));

        // The function text present ONLY inside a comment is inert: it does not shadow anything, so the
        // factory calls stay lock-less — NOT hardened, and re-patching makes it effective.
        string commented =
            "#!/bin/bash\n" +
            "# iptables() { command iptables -w \"$@\"; }\n" +   // commented — inert
            "iptables -F INPUT\n";
        Assert.False(MqttInstaller.IsFactoryFirewallHardened(commented));
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(
            MqttInstaller.EnsureFactoryFirewallShim(commented)));

        // A definition placed AFTER the first factory call does not shadow that call ⇒ NOT hardened.
        string late =
            "#!/bin/bash\n" +
            "iptables -F INPUT\n" +
            "iptables() { command iptables -w \"$@\"; }\n";
        Assert.False(MqttInstaller.IsFactoryFirewallHardened(late));

        // The shim function text inside an INACTIVE `if false` branch never actually defines the
        // function at run time ⇒ NOT hardened (the block isn't the exact one right after the shebang).
        string inactive =
            "#!/bin/bash\n" +
            "if false; then\n" +
            "iptables() { command iptables -w \"$@\"; }\n" +
            "fi\n" +
            "iptables -F INPUT\n";
        Assert.False(MqttInstaller.IsFactoryFirewallHardened(inactive));

        // The shim function text inside a QUOTED here-document is data, not code ⇒ NOT hardened.
        string heredoc =
            "#!/bin/bash\n" +
            "cat <<'EOF'\n" +
            "iptables() { command iptables -w \"$@\"; }\n" +
            "EOF\n" +
            "iptables -F INPUT\n";
        Assert.False(MqttInstaller.IsFactoryFirewallHardened(heredoc));
    }

    [Fact]
    public void A_crlf_factory_script_is_normalized_to_lf_when_patched()
    {
        // A CRLF factory hook is unrunnable on Linux (ifupdown would exec `#!/bin/bash\r`, a nonexistent
        // interpreter). Patching must NORMALIZE it to LF — not preserve the CRLF — so the result has no
        // '\r', a clean shebang, and an effective shim. A raw CRLF script is therefore NOT "already
        // hardened" (the LF-defined block never matches a CRLF one).
        string crlf =
            "#!/bin/bash\r\n" +
            "iptables -F INPUT\r\n" +
            "iptables -P INPUT DROP\r\n";
        Assert.False(MqttInstaller.IsFactoryFirewallHardened(crlf));
        string patched = MqttInstaller.EnsureFactoryFirewallShim(crlf);
        Assert.DoesNotContain("\r", patched);
        Assert.StartsWith("#!/bin/bash\n", patched);
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(patched));

        // A VALID, already-hardened script in CRLF form must normalize to LF WITHOUT duplicating the shim.
        // Build a CRLF copy of the COMPLETE LF-hardened output (marker block included), re-run, and assert
        // it round-trips to exactly that LF output — one block, no '\r'.
        string lfHardened = MqttInstaller.EnsureFactoryFirewallShim(FactoryScript);
        string crlfHardened = lfHardened.Replace("\n", "\r\n");
        string fixedUp = MqttInstaller.EnsureFactoryFirewallShim(crlfHardened);
        Assert.Equal(lfHardened, fixedUp);
        Assert.DoesNotContain("\r", fixedUp);
    }

    [Fact]
    public void A_prior_owned_block_with_an_altered_function_is_stripped_not_layered()
    {
        // A previously-installed block whose function was hand-altered (here: `-w` removed) must be REMOVED
        // on re-patch, not left below a fresh block — otherwise the shell's LAST definition (the altered,
        // lock-less one) would win. The result must carry exactly one block with the correct -w function
        // and no trace of the altered one.
        string tampered = MqttInstaller.EnsureFactoryFirewallShim(FactoryScript)
            .Replace("command iptables -w \"$@\"", "command iptables \"$@\"");  // remove -w inside the block
        Assert.DoesNotContain("command iptables -w \"$@\"", tampered);          // sanity: it's really gone

        string repatched = MqttInstaller.EnsureFactoryFirewallShim(tampered);
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(repatched));        // a clean block was restored
        Assert.Contains("iptables() { command iptables -w \"$@\"; }\n", repatched);  // correct function present
        Assert.DoesNotContain("command iptables \"$@\"", repatched);            // altered function stripped
        // Exactly one shim block: two marker lines (">>>" opener, "<<<" closer).
        int count = 0, i = 0;
        while ((i = repatched.IndexOf("IntercomFirmwareTool #145", i, System.StringComparison.Ordinal)) >= 0)
        { count++; i += 1; }
        Assert.Equal(2, count);
    }

    [Theory]
    // A LATER `iptables` redefinition after our block — only possible via a hand-edit of the factory hook,
    // which is a fixed, known script that contains none — is OUT OF SCOPE. We install the FIRST definition
    // and leave any such foreign text untouched. The script still reads as hardened (our exact block is
    // present right after the shebang) and re-patching is a clean strip-and-reinsert — no throw, no attempt
    // to statically parse or neutralize arbitrary shell.
    [InlineData("iptables() { command iptables \"$@\"; }\n")]              // plain, no -w
    [InlineData("if true; then iptables() { command iptables \"$@\"; }; fi\n")] // nested after `then`
    public void A_later_iptables_redefinition_is_left_in_place_out_of_scope(string foreign)
    {
        string clean = MqttInstaller.EnsureFactoryFirewallShim(FactoryScript);
        const string blockEnd = "# <<< IntercomFirmwareTool #145 <<<\n";
        int at = clean.IndexOf(blockEnd, System.StringComparison.Ordinal) + blockEnd.Length;
        string extended = clean[..at] + foreign + clean[at..];

        Assert.True(MqttInstaller.IsFactoryFirewallHardened(extended));       // our block is present
        string repatched = MqttInstaller.EnsureFactoryFirewallShim(extended); // must NOT throw
        Assert.Contains("iptables() { command iptables -w \"$@\"; }\n", repatched);
        Assert.Contains(foreign, repatched);                                  // foreign text left in place
    }

    [Theory]
    // The `iptables() { command iptables -w …; }` shim is POSIX, so any DIRECT shell-path shebang is hardened
    // — bash, sh, dash, BusyBox ash, ksh, zsh, with or without interpreter args — and a `set -e` hook is fine
    // too (there is no readonly pin whose failure mode errexit could trigger).
    [InlineData("#!/bin/bash\niptables -F INPUT\n")]
    [InlineData("#!/bin/sh\niptables -F INPUT\n")]
    [InlineData("#!/bin/dash\niptables -F INPUT\n")]
    [InlineData("#!/bin/ash\niptables -F INPUT\n")]
    [InlineData("#!/bin/ksh\niptables -F INPUT\n")]
    [InlineData("#!/usr/bin/zsh\niptables -F INPUT\n")]
    [InlineData("#!/bin/bash\nset -e\niptables -F INPUT\n")]             // errexit is now harmless (no pin)
    [InlineData("#!/bin/bash -e\niptables -F INPUT\n")]                  // errexit in the shebang — also fine
    [InlineData("#!/bin/busybox sh\niptables -F INPUT\n")]               // BusyBox multicall — sh applet
    [InlineData("#!/bin/busybox ash\niptables -F INPUT\n")]              // BusyBox multicall — ash applet
    public void Any_shell_shebang_is_hardened(string script)
    {
        string patched = MqttInstaller.EnsureFactoryFirewallShim(script);
        Assert.Contains("iptables() { command iptables -w \"$@\"; }\n", patched);
        Assert.DoesNotContain("readonly -f", patched);
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(patched));
    }

    [Theory]
    // Rejected as unhardenable — a shell shim must never be spliced in:
    //   * a NON-shell interpreter (python/perl/openrc) cannot run the shim or the factory's shell commands;
    //   * the `#!/usr/bin/env <shell>` indirection is not recognized — ifupdown hooks use a direct
    //     interpreter path, and Linux passes the whole post-`env` text as ONE argument, so multi-token forms
    //     (`env bash -e`, `env -i bash`, `env FOO=bar bash`) are not even runnable without `-S`. Rather than
    //     reproduce env's kernel shebang semantics, we reject every env form.
    [InlineData("#!/usr/bin/python\niptables -F INPUT\n")]
    [InlineData("#!/usr/bin/python3\nprint('x')\n")]
    [InlineData("#!/usr/bin/perl\nsystem('iptables -F');\n")]
    [InlineData("#!/sbin/openrc-run\n")]                                 // not a shell
    [InlineData("#!/usr/bin/env bash\niptables -F INPUT\n")]             // env form — not recognized
    [InlineData("#!/usr/bin/env sh\niptables -F INPUT\n")]
    [InlineData("#!/usr/bin/env bash -e\niptables -F INPUT\n")]          // not runnable (one kernel arg)
    [InlineData("#!/usr/bin/env -i bash\niptables -F INPUT\n")]          // not runnable
    [InlineData("#!/usr/bin/env FOO=bar bash\niptables -F INPUT\n")]     // not runnable
    [InlineData("#!/usr/bin/env python3\nprint('x')\n")]
    [InlineData("#!/bin/busybox awk\nBEGIN{}\n")]                        // busybox applet, but not a shell
    [InlineData("#!/bin/busybox sh -x\niptables -F INPUT\n")]            // 3 tokens — not runnable as a shebang
    [InlineData("#!/bin/busybox\niptables -F INPUT\n")]                  // busybox with no applet
    public void An_unsupported_shebang_is_rejected(string script)
    {
        Assert.Throws<System.InvalidOperationException>(
            () => MqttInstaller.EnsureFactoryFirewallShim(script));
        Assert.False(MqttInstaller.IsFactoryFirewallHardened(script));
    }

    [Fact]
    public void An_unterminated_owned_block_is_rejected_not_silently_truncated()
    {
        // A corrupt/tampered factory script carrying our OPENER marker but NO closer must FAIL the patch —
        // never silently drop the factory rules that follow it (SSH :22, FTP :21, the security DROPs). The
        // helper throws, so the install aborts and the on-disk script is left untouched (nothing written).
        string corrupt =
            "#!/bin/bash\n" +
            "# >>> IntercomFirmwareTool #145: make the factory firewall WAIT for the xtables lock >>>\n" +
            "iptables() { command iptables -w \"$@\"; }\n" +
            // closer marker deliberately missing
            "iptables -F INPUT\n" +
            "iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n" +
            "iptables -P INPUT DROP\n";
        Assert.Throws<System.InvalidOperationException>(
            () => MqttInstaller.EnsureFactoryFirewallShim(corrupt));
    }

    [Fact]
    public void A_script_without_a_shebang_is_rejected()
    {
        // A firewall script whose first line is a real command (no #! shebang) must be REJECTED, not
        // patched after an arbitrary line — otherwise that first line stays lock-less while the marker
        // suppresses retries and ValidateMqtt passes (#145). Fail loudly at build time instead.
        Assert.Throws<System.InvalidOperationException>(
            () => MqttInstaller.EnsureFactoryFirewallShim("iptables -F INPUT\niptables -P INPUT DROP\n"));
        // An empty script (no shebang) is likewise rejected rather than silently "hardened".
        Assert.Throws<System.InvalidOperationException>(
            () => MqttInstaller.EnsureFactoryFirewallShim(""));
        // A file that ALREADY carries the active shim function but has lost its shebang must STILL be
        // rejected — the shebang is checked before the idempotency shortcut, so it can't slip through as
        // "already hardened" and ship an unusable directly-executed if-pre-up.d hook.
        Assert.Throws<System.InvalidOperationException>(
            () => MqttInstaller.EnsureFactoryFirewallShim(
                "iptables() { command iptables -w \"$@\"; }\niptables -F INPUT\n"));
    }
}
