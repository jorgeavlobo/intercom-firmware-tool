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
/// so every factory call blocks for the lock instead of dropping a rule. These tests pin the pure splice
/// (<see cref="MqttInstaller.EnsureFactoryFirewallShim"/>): placement, content, and idempotency.
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
        // The original body is preserved verbatim, after the shim.
        Assert.Contains("iptables -F INPUT\n", patched);
        Assert.Contains("iptables -P INPUT DROP\n", patched);
    }

    [Fact]
    public void Shim_defines_a_waiting_iptables_function()
    {
        string patched = MqttInstaller.EnsureFactoryFirewallShim(FactoryScript);
        // The whole point: shadow `iptables` with a function that injects --wait and reaches the real
        // binary via `command` (no recursion).
        Assert.Contains("iptables() { command iptables -w \"$@\"; }\n", patched);
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

        // Even a script that already carries the function but in CRLF form is re-emitted as LF (its CRLF
        // shebang is unrunnable), so it is NOT an idempotent no-op — the result changes and has no '\r'.
        string crlfHardened =
            "#!/bin/bash\r\n" +
            "iptables() { command iptables -w \"$@\"; }\r\n" +
            "iptables -F INPUT\r\n";
        string fixedUp = MqttInstaller.EnsureFactoryFirewallShim(crlfHardened);
        Assert.DoesNotContain("\r", fixedUp);
        Assert.True(MqttInstaller.IsFactoryFirewallHardened(fixedUp));
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
