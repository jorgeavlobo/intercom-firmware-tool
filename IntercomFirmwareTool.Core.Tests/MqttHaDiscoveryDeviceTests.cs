using System.Linq;
using System.Text.Json;
using IntercomFirmwareTool.Core;
using IntercomFirmwareTool.Core.Updates;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// The Home Assistant discovery <c>device</c> block's <c>sw_version</c> (issue #114): every entity that
/// groups under the intercom device (any supported model) carries the installed bridge daemon's version,
/// so HA shows it on the device page. The value is <see cref="PayloadBinaries.BridgeVersion"/>, which mirrors
/// <c>native/btmqttd/Cargo.toml</c> (the daemon's <c>CARGO_PKG_VERSION</c>); the two are kept in step by
/// <c>btmqttd-provenance.yml</c>. Because the installer bakes it into the JSON and btmqttd only republishes
/// those files, it must be a pure function of the build — <see cref="MqttInstaller.ValidateMqtt"/> re-generates
/// the identical set for its byte-compare.
/// </summary>
public class MqttHaDiscoveryDeviceTests
{
    private static readonly JsonDocumentOptions ParseOpts = default;

    // Returns the "device" element of an entity's JSON, or null when the entity carries no device block
    // (e.g. the empty tombstone payloads).
    private static JsonElement? DeviceOf(string json)
    {
        if (string.IsNullOrEmpty(json))
            return null;
        using var doc = JsonDocument.Parse(json, ParseOpts);
        return doc.RootElement.TryGetProperty("device", out var device)
            ? (JsonElement?)device.Clone()
            : null;
    }

    [Fact]
    public void Bridge_version_is_a_valid_semver()
    {
        // The value HA advertises must be a real SemVer (so an operator — and any future update check —
        // reads a well-formed version), and it is the single mirror of Cargo.toml the installer bakes in.
        Assert.True(
            SemanticVersion.TryParse(PayloadBinaries.BridgeVersion, out _),
            $"PayloadBinaries.BridgeVersion '{PayloadBinaries.BridgeVersion}' is not a valid SemVer");
    }

    [Fact]
    public void Status_entity_advertises_the_bridge_sw_version()
    {
        var entities = MqttInstaller.GenerateHaDiscovery(new MqttOptions("broker.lan"), restoreFirewallEligible: false);
        var status = entities.Single(e => e.FileName == "status.json");

        JsonElement? device = DeviceOf(status.Json);
        Assert.True(device.HasValue, "status.json carries no device block");
        Assert.True(device!.Value.TryGetProperty("sw_version", out var sw), "device block has no sw_version");
        Assert.Equal(PayloadBinaries.BridgeVersion, sw.GetString());
    }

    [Fact]
    public void Every_entity_with_a_device_block_carries_the_same_sw_version()
    {
        // The device object is shared across entities; a regression that split it (or dropped sw_version from
        // one path) would surface here. Assert EVERY device block agrees, and that we actually saw some.
        var entities = MqttInstaller.GenerateHaDiscovery(
            new MqttOptions("broker.lan") { EnableHaDiscovery = true },
            restoreFirewallEligible: false);

        int seen = 0;
        foreach (var e in entities)
        {
            JsonElement? device = DeviceOf(e.Json);
            if (device is null)
                continue;   // tombstone / device-less entity
            seen++;
            Assert.True(device.Value.TryGetProperty("sw_version", out var sw),
                $"{e.FileName} device block has no sw_version");
            Assert.Equal(PayloadBinaries.BridgeVersion, sw.GetString());
        }

        Assert.True(seen > 0, "no discovery entity carried a device block");
    }

    [Fact]
    public void Sw_version_is_deterministic_across_generations()
    {
        // ValidateMqtt re-generates discovery and byte-compares; the sw_version must therefore be identical
        // for identical inputs (it is a build constant, not read from the environment).
        var a = MqttInstaller.GenerateHaDiscovery(new MqttOptions("broker.lan"), false)
            .Single(e => e.FileName == "status.json").Json;
        var b = MqttInstaller.GenerateHaDiscovery(new MqttOptions("broker.lan"), false)
            .Single(e => e.FileName == "status.json").Json;
        Assert.Equal(a, b);
    }
}
