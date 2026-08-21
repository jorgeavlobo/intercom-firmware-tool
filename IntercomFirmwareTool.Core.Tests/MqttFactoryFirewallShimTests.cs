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
/// POSIX function shim (works under any POSIX shell — sh/dash/ash/bash — not shell-specific, which is why the
/// installer accepts only a shell shebang) and is deliberately NOT tamper-proofed against a hand-edit that
/// later redefines <c>iptables</c> — that is out of scope for a fixed, known factory hook.
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
    public void A_crlf_shebang_with_an_lf_shim_is_not_hardened()
    {
        // The MIXED case: a CRLF shebang line (`#!/bin/bash\r\n`) but an LF-encoded shim right below. The hook
        // is still unrunnable — the kernel takes `/bin/bash\r` as the interpreter — so the factory rules never
        // rebuild, yet the shim block below matches byte-for-byte. HasShellShebang trims the trailing '\r', so
        // the certification itself must reject the CR; otherwise ValidateMqtt would bless a non-executing hook.
        string patched = MqttInstaller.EnsureFactoryFirewallShim(FactoryScript);  // all-LF, genuinely hardened
        int nl = patched.IndexOf('\n');
        string crlfShebang = patched[..nl] + "\r\n" + patched[(nl + 1)..];        // only the shebang → CRLF
        Assert.False(MqttInstaller.IsFactoryFirewallHardened(crlfShebang));
    }

    [Fact]
    public void An_lf_shim_followed_by_a_crlf_factory_body_is_not_hardened()
    {
        // The other MIXED case: an LF shebang and our exact LF shim block, but the factory BODY below is CRLF.
        // The shim prefix matches byte-for-byte, yet the shell passes trailing-'\r' arguments to the factory
        // `iptables` calls (e.g. `INPUT\r`), so those rules fail — SSH/reflash lockout — while the certification
        // would otherwise report hardened. A genuinely hardened hook is pure LF (EnsureFactoryFirewallShim
        // normalizes before writing), so ANY '\r' must read as NOT hardened.
        string patched = MqttInstaller.EnsureFactoryFirewallShim(FactoryScript);  // all-LF, genuinely hardened
        const string blockEnd = "# <<< IntercomFirmwareTool #145 <<<\n";
        int at = patched.IndexOf(blockEnd, System.StringComparison.Ordinal) + blockEnd.Length;
        // Leave the shebang + shim block LF; convert only the factory body after our block to CRLF.
        string mixed = patched[..at] + patched[at..].Replace("\n", "\r\n");
        Assert.Contains("\r", mixed);                                            // sanity: the body really is CRLF
        Assert.False(MqttInstaller.IsFactoryFirewallHardened(mixed));
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

    [Fact]
    public void Two_stacked_owned_blocks_at_the_anchor_are_both_stripped_not_layered()
    {
        // A tampered input could carry TWO back-to-back owned blocks right after the shebang, the second one
        // altered to drop -w. Stripping only the first would leave the lock-less block below the fresh shim,
        // where the shell's LAST iptables() definition wins — yet IsFactoryFirewallHardened, which only checks
        // the block right after the shebang, would still read "hardened". Both anchor blocks must be peeled off
        // so the re-patch lands on a clean anchor with exactly one, correct block.
        string clean = MqttInstaller.EnsureFactoryFirewallShim(FactoryScript);
        int nl = clean.IndexOf('\n');
        string shebang = clean[..(nl + 1)];
        string body = clean[(nl + 1)..];
        // Extract just the owned block (opener→closer inclusive) from the clean output.
        const string blockEnd = "# <<< IntercomFirmwareTool #145 <<<\n";
        int end = body.IndexOf(blockEnd, System.StringComparison.Ordinal) + blockEnd.Length;
        string ownedBlock = body[..end];
        string rest = body[end..];
        string altered = ownedBlock.Replace("command iptables -w \"$@\"", "command iptables \"$@\"");
        // shebang + [clean block] + [altered block] + factory rules — two owned blocks stacked at the anchor.
        string stacked = shebang + ownedBlock + altered + rest;

        string repatched = MqttInstaller.EnsureFactoryFirewallShim(stacked);
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(repatched));        // a clean anchor was restored
        Assert.Contains("iptables() { command iptables -w \"$@\"; }\n", repatched);
        Assert.DoesNotContain("command iptables \"$@\"", repatched);            // altered block fully stripped
        // Exactly one shim block survives: two marker lines (">>>" opener, "<<<" closer).
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
    // The `iptables() { command iptables -w …; }` shim is POSIX, so any BARE direct shell-path shebang is
    // hardened — bash, sh, dash, BusyBox ash, ksh, zsh — as is the BusyBox/Toybox `<multicall> <shell>`
    // form. `set -e` on a LATER line is fine too (there is no readonly pin whose failure mode errexit could
    // trigger); only the shebang line itself is inspected.
    [InlineData("#!/bin/bash\niptables -F INPUT\n")]
    [InlineData("#!/bin/sh\niptables -F INPUT\n")]
    [InlineData("#!/bin/dash\niptables -F INPUT\n")]
    [InlineData("#!/bin/ash\niptables -F INPUT\n")]
    [InlineData("#!/bin/ksh\niptables -F INPUT\n")]
    [InlineData("#!/usr/bin/zsh\niptables -F INPUT\n")]
    [InlineData("#!/bin/bash\nset -e\niptables -F INPUT\n")]             // errexit on line 2 — harmless (no pin)
    [InlineData("#!/bin/busybox sh\niptables -F INPUT\n")]               // BusyBox multicall — sh applet
    [InlineData("#!/bin/busybox ash\niptables -F INPUT\n")]              // BusyBox multicall — ash applet
    [InlineData("#!/bin/toybox sh\niptables -F INPUT\n")]                // Toybox multicall — sh applet
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
    //   * a direct shell path WITH interpreter arguments — `#!/bin/bash -c` makes bash run the hook path as
    //     a command string (body never runs); we reject all args rather than enumerate safe-vs-unsafe flags;
    //   * the whole `#!/usr/bin/env <shell>` indirection — ifupdown hooks use a direct interpreter path, and
    //     Linux passes the whole post-`env` text as ONE argument (so `env -S` would be needed to split
    //     multi-token forms); rather than reproduce env's kernel semantics, we reject every env form.
    [InlineData("#!/usr/bin/python\niptables -F INPUT\n")]
    [InlineData("#!/usr/bin/python3\nprint('x')\n")]
    [InlineData("#!/usr/bin/perl\nsystem('iptables -F');\n")]
    [InlineData("#!/sbin/openrc-run\n")]                                 // not a shell
    [InlineData("#!/bin/bash -c\niptables -F INPUT\n")]                  // -c: bash runs the path as a command
    [InlineData("#!/bin/bash -e\niptables -F INPUT\n")]                  // any interpreter arg is rejected
    [InlineData("#!/bin/bash -x\niptables -F INPUT\n")]
    [InlineData("#!/usr/bin/env bash\niptables -F INPUT\n")]             // env form — not recognized (even runnable)
    [InlineData("#!/usr/bin/env sh\niptables -F INPUT\n")]
    [InlineData("#!/usr/bin/env bash -e\niptables -F INPUT\n")]          // not runnable (one kernel arg)
    [InlineData("#!/usr/bin/env -i bash\niptables -F INPUT\n")]          // not runnable
    [InlineData("#!/usr/bin/env FOO=bar bash\niptables -F INPUT\n")]     // not runnable
    [InlineData("#!/usr/bin/env python3\nprint('x')\n")]
    [InlineData("#!/bin/busybox awk\nBEGIN{}\n")]                        // busybox applet, but not a shell
    [InlineData("#!/bin/busybox sh -x\niptables -F INPUT\n")]            // 3 tokens — not runnable as a shebang
    [InlineData("#!/bin/busybox\niptables -F INPUT\n")]                  // busybox with no applet
    [InlineData("#!/bin/busybox /bin/sh\niptables -F INPUT\n")]          // applet is a PATH — busybox can't resolve it
    [InlineData("#!/bin/busybox bash\niptables -F INPUT\n")]             // busybox ships no `bash` applet
    [InlineData("#!/bin/toybox ash\niptables -F INPUT\n")]               // toybox ships no `ash` applet
    [InlineData("#!bash\niptables -F INPUT\n")]                          // relative interpreter — kernel resolves vs CWD, not $PATH
    [InlineData("#!sh\niptables -F INPUT\n")]                            // relative interpreter
    [InlineData("#!busybox sh\niptables -F INPUT\n")]                    // relative multicall path
    [InlineData("#!toybox sh\niptables -F INPUT\n")]                     // relative multicall path
    public void An_unsupported_shebang_is_rejected(string script)
    {
        Assert.Throws<System.InvalidOperationException>(
            () => MqttInstaller.EnsureFactoryFirewallShim(script));
        Assert.False(MqttInstaller.IsFactoryFirewallHardened(script));
    }

    [Theory]
    // ShebangInterpreterPath extracts the FIRST token after `#!` — the interpreter path the install/validate
    // paths then check actually EXISTS in the image (a bogus `#!/opt/missing/bash` must not certify hardened).
    [InlineData("#!/bin/bash\niptables -F INPUT\n", "/bin/bash")]
    [InlineData("#!/bin/sh\n", "/bin/sh")]
    [InlineData("#!/usr/bin/dash\n", "/usr/bin/dash")]
    [InlineData("#!/bin/busybox sh\n", "/bin/busybox")]     // multicall: the interpreter is the multicall binary
    [InlineData("#!/bin/toybox sh\n", "/bin/toybox")]
    [InlineData("#!/opt/missing/bash\n", "/opt/missing/bash")] // extracted verbatim; existence is checked later
    [InlineData("#!  /bin/bash  \n", "/bin/bash")]          // leading/trailing spaces trimmed by the token split
    [InlineData("#!/bin/bash\r\n", "/bin/bash")]            // trailing CR on the shebang line is stripped
    [InlineData("#!/bin/busybox\tsh\n", "/bin/busybox")]   // TAB separates interpreter from applet (kernel-legal)
    [InlineData("#!/bin/bash\n", "/bin/bash")] // vertical tab is NOT a kernel separator — kept in the token
    public void Shebang_interpreter_path_is_the_first_token(string script, string expected)
    {
        Assert.Equal(expected, MqttInstaller.ShebangInterpreterPath(script));
    }

    [Fact]
    public void Shebang_interpreter_path_is_null_without_a_shebang()
    {
        Assert.Null(MqttInstaller.ShebangInterpreterPath("iptables -F INPUT\n"));
        Assert.Null(MqttInstaller.ShebangInterpreterPath(""));
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
    public void An_anchor_opener_with_only_a_spoofed_closer_in_data_is_rejected_not_deleted()
    {
        // The nastier variant: an UNTERMINATED opener AT THE ANCHOR, real factory commands right below it, and
        // a line that LOOKS like our closer further down but is here-document DATA. The strip must not treat
        // that data line as the terminator and RemoveRange the factory rules between — it must fail closed.
        string spoof =
            "#!/bin/bash\n" +
            "# >>> IntercomFirmwareTool #145: make the factory firewall WAIT for the xtables lock >>>\n" +
            "iptables -F INPUT\n" +                                    // REAL rule — must NOT be deleted
            "iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n" + // REAL rule
            "cat <<'EOF'\n" +
            "# <<< IntercomFirmwareTool #145 <<<\n" +                  // spoofed closer: here-doc DATA
            "EOF\n" +
            "iptables -P INPUT DROP\n";
        Assert.Throws<System.InvalidOperationException>(
            () => MqttInstaller.EnsureFactoryFirewallShim(spoof));
    }

    [Fact]
    public void Marker_lines_that_are_heredoc_data_are_not_stripped_as_an_owned_block()
    {
        // A hook that carries a COMPLETE marker pair as DATA inside a quoted here-document (NOT at the anchor
        // — it's below `cat <<'EOF'`, not the first line after the shebang) must be preserved. Only the block
        // at the anchor is ever ours; deleting the lines between a marker pair elsewhere could strip real
        // factory rules. Patching inserts our block at the anchor and leaves the here-document verbatim.
        string hook =
            "#!/bin/bash\n" +
            "cat <<'EOF'\n" +
            "# >>> IntercomFirmwareTool #145: make the factory firewall WAIT for the xtables lock >>>\n" +
            "iptables() { command iptables \"$@\"; }\n" +   // here-doc DATA that must survive
            "# <<< IntercomFirmwareTool #145 <<<\n" +
            "EOF\n" +
            "iptables -F INPUT\n";
        string patched = MqttInstaller.EnsureFactoryFirewallShim(hook);
        // Our real block is spliced in at the anchor …
        Assert.StartsWith("#!/bin/bash\n# >>> IntercomFirmwareTool #145", patched);
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(patched));
        // … and the ENTIRE original body after the shebang (the here-doc + its marker-looking data) is kept
        // verbatim — nothing between the here-doc markers was deleted.
        int shebangEnd = hook.IndexOf('\n') + 1;
        Assert.EndsWith(hook[shebangEnd..], patched);
        Assert.Contains("iptables() { command iptables \"$@\"; }\n", patched);
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
