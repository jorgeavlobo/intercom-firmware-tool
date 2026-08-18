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
    public void Patching_is_idempotent_and_returns_the_same_reference_when_already_hardened()
    {
        string once = MqttInstaller.EnsureFactoryFirewallShim(FactoryScript);
        string twice = MqttInstaller.EnsureFactoryFirewallShim(once);
        // A second pass must not insert a second shim…
        Assert.Equal(once, twice);
        // …and must return the SAME string reference unchanged, so the installer skips a redundant write.
        Assert.Same(once, twice);
        // Exactly one shim marker in the doubly-processed text.
        int count = 0, i = 0;
        while ((i = twice.IndexOf("IntercomFirmwareTool #145", i, System.StringComparison.Ordinal)) >= 0)
        { count++; i += 1; }
        Assert.Equal(2, count); // the opening ">>>" and closing "<<<" marker lines — one shim block
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
    }
}
