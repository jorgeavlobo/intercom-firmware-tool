using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// The factory-firewall xtables-lock hardening (issue #145). The panel's factory firewall
/// (<c>/etc/network/if-pre-up.d/iptables</c>) rebuilds INPUT with LOCK-LESS <c>iptables -A</c> calls; with
/// the on-device camera's go2rtc rule as a second iptables writer, a factory call that overlaps our lock
/// hold fails silently and a factory rule (SSH <c>:22</c>, the FTP-over-USB reflash <c>:21</c>, security
/// DROPs) goes missing — observed on hardware as SSH / reflash lockouts. The installer inserts a shell
/// shim after the script's shebang that shadows <c>iptables</c> with a function injecting <c>--wait</c>,
/// so every factory call blocks for the lock instead of dropping a rule, and pins that function with
/// <c>readonly -f</c> so a later redefinition anywhere below cannot silently drop back to a lock-less call.
/// The pin only holds on a bash hook with no <c>set -e</c>, so a hook that is non-bash or enables errexit is
/// REJECTED as unhardenable rather than shipped with a shim that only looks hardened. These tests pin the
/// pure splice (<see cref="MqttInstaller.EnsureFactoryFirewallShim"/>): placement, content, the readonly
/// pin, idempotency, tolerance of later redefinitions, and rejection of unpinnable hooks.
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
    public void Shim_defines_a_waiting_iptables_function_and_pins_it_readonly()
    {
        string patched = MqttInstaller.EnsureFactoryFirewallShim(FactoryScript);
        // The whole point: shadow `iptables` with a function that injects --wait and reaches the real
        // binary via `command` (no recursion).
        Assert.Contains("iptables() { command iptables -w \"$@\"; }\n", patched);
        // …then PIN it with `readonly -f` so any later redefinition in the script (any spacing, nested
        // after then/;/do) is rejected by bash at run time and this --wait version stays in force. The
        // installer only patches a bash hook with no `set -e` (see the rejection tests), so this pin is
        // always enforceable and its rejection of a later redefinition can never abort the hook.
        Assert.Contains("readonly -f iptables 2>/dev/null || true\n", patched);
        // The guard MUST come after the function definition (you can only pin an already-defined function).
        int fnDef = patched.IndexOf("iptables() { command iptables -w", System.StringComparison.Ordinal);
        int guard = patched.IndexOf("readonly -f iptables", System.StringComparison.Ordinal);
        Assert.True(fnDef >= 0 && guard > fnDef, "the readonly guard must follow the function definition");
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
    // A LATER `iptables` redefinition after our block — a firmware variant or hand-edited hook — is
    // NEUTRALIZED at run time by the block's `readonly -f iptables` guard: bash rejects the redefinition
    // (verified: `readonly -f` makes every one of these forms fail with "readonly function", and without
    // `set -e` the factory hook keeps running our --wait definition). So the installer must NOT try to
    // statically detect or reject these — that arms race is unwinnable (an `iptables()` after `if true;
    // then` is live, one after `if false; then` or inside a quoted here-doc is inert, and the two are
    // indistinguishable without executing the shell). The script stays HARDENED and re-patching SUCCEEDS.
    // These variants span every spacing/keyword/nesting form the redefinition could take.
    [InlineData("iptables() { command iptables \"$@\"; }\n")]              // plain, no -w
    [InlineData("iptables  () { command iptables \"$@\"; }\n")]            // two spaces before ()
    [InlineData("iptables\t() { command iptables \"$@\"; }\n")]            // a tab before ()
    [InlineData("function\tiptables { command iptables \"$@\"; }\n")]     // `function` keyword + tab
    [InlineData("if true; then iptables() { command iptables \"$@\"; }; fi\n")] // nested after `then`
    public void A_later_iptables_redefinition_is_neutralized_by_readonly_not_rejected(string foreign)
    {
        // Our EXACT block (function + `readonly -f` guard) sits right after the shebang; the foreign
        // redefinition is spliced in just after it. Because the guard pins the function at run time, the
        // script is still effectively hardened and re-patching is a clean no-op splice — no throw.
        string clean = MqttInstaller.EnsureFactoryFirewallShim(FactoryScript);
        const string blockEnd = "# <<< IntercomFirmwareTool #145 <<<\n";
        int at = clean.IndexOf(blockEnd, System.StringComparison.Ordinal) + blockEnd.Length;
        string extended = clean[..at] + foreign + clean[at..];

        Assert.True(MqttInstaller.IsFactoryFirewallHardened(extended));       // block+pin still present
        string repatched = MqttInstaller.EnsureFactoryFirewallShim(extended); // must NOT throw
        Assert.Contains("iptables() { command iptables -w \"$@\"; }\n", repatched);
        Assert.Contains("readonly -f iptables 2>/dev/null || true\n", repatched);
        Assert.Contains(foreign, repatched);                                  // foreign text left in place, inert
    }

    [Theory]
    // The shim's `readonly -f` pin only holds on a bash hook with no `set -e`. A hook we can't safely pin is
    // REJECTED (unhardenable), never patched with a shim that only LOOKS hardened:
    //   * a non-bash interpreter (POSIX sh / dash / BusyBox ash have no read-only-function mechanism, so the
    //     pin can't be enforced — and an unguarded `readonly -f` there would even abort the hook);
    //   * `set -e`, under which the pin's rejection of a later redefinition becomes a fatal command that
    //     aborts the hook before the remaining factory rules run.
    [InlineData("#!/bin/sh\niptables -F INPUT\n")]                       // POSIX sh — no readonly -f
    [InlineData("#!/bin/dash\niptables -F INPUT\n")]                     // dash — no readonly -f
    [InlineData("#!/bin/ash\niptables -F INPUT\n")]                      // BusyBox ash — no readonly -f
    [InlineData("#!/usr/bin/env sh\niptables -F INPUT\n")]               // env sh — non-bash
    [InlineData("#!/bin/bash\nset -e\niptables -F INPUT\n")]             // bash but errexit
    [InlineData("#!/bin/bash\nset -euo pipefail\niptables -F INPUT\n")]  // errexit inside a cluster
    [InlineData("#!/bin/bash\nset -o errexit\niptables -F INPUT\n")]     // errexit long form
    [InlineData("#!/bin/bash -e\niptables -F INPUT\n")]                  // errexit in the SHEBANG flags
    [InlineData("#!/bin/bash -eu\niptables -F INPUT\n")]                 // errexit clustered in the shebang
    [InlineData("#!/usr/bin/env bash -e\niptables -F INPUT\n")]         // errexit in an env-form shebang
    public void An_unpinnable_hook_non_bash_or_errexit_is_rejected(string script)
    {
        Assert.Throws<System.InvalidOperationException>(
            () => MqttInstaller.EnsureFactoryFirewallShim(script));
        Assert.False(MqttInstaller.IsFactoryFirewallHardened(script));
    }

    [Theory]
    // A bash hook the pin CAN hold is accepted: a bash shebang (plain, absolute-variant, or the env form)
    // with no errexit, or a `set` line that does not enable errexit. `set +e` DISABLES it; `set -x` /
    // `set -o pipefail` are unrelated — none must trip the errexit guard.
    [InlineData("#!/bin/bash\niptables -F INPUT\n")]
    [InlineData("#!/usr/bin/bash\niptables -F INPUT\n")]
    [InlineData("#!/usr/bin/env bash\niptables -F INPUT\n")]
    [InlineData("#!/bin/bash\nset -x\niptables -F INPUT\n")]             // xtrace, not errexit
    [InlineData("#!/bin/bash\nset -o pipefail\niptables -F INPUT\n")]    // pipefail, not errexit
    [InlineData("#!/bin/bash\nset +e\niptables -F INPUT\n")]            // explicitly DISABLES errexit
    [InlineData("#!/bin/bash -x\niptables -F INPUT\n")]                 // xtrace SHEBANG flag, not errexit
    public void A_pinnable_bash_hook_without_errexit_is_hardened(string script)
    {
        string patched = MqttInstaller.EnsureFactoryFirewallShim(script);
        Assert.Contains("iptables() { command iptables -w \"$@\"; }\n", patched);
        Assert.Contains("readonly -f iptables 2>/dev/null || true\n", patched);
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(patched));
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
