using System.Linq;
using System.Text.Json;
using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// The bridge update check (issue #114, second half): the generated <c>btmqttd.conf</c> keys
/// (<c>UPDATE_CHECK</c>, <c>TOPIC_UPDATE</c>) and the Home Assistant <c>update</c> discovery entity.
/// btmqttd fetches the version manifest, publishes <c>{"installed_version":…,"latest_version":…}</c>
/// to <c>TOPIC_UPDATE</c>, and HA's Update card reads it. NOTIFY-ONLY (no install/command topic —
/// the panel can't self-flash). Opt-out: with the check disabled the daemon publishes nothing and
/// the installer tombstones the entity.
/// </summary>
public class MqttUpdateEntityTests
{
    // ---------------------------- btmqttd.conf ----------------------------

    [Fact]
    public void Conf_enables_the_update_check_by_default()
    {
        var conf = MqttInstaller.GenerateConf(new MqttOptions("broker.lan"));
        Assert.Contains("UPDATE_CHECK=1\n", conf);
        // Default TOPIC_UPDATE is scoped to the last-will namespace ("Bticino/" -> "Bticino/update").
        Assert.Contains("TOPIC_UPDATE='Bticino/update'\n", conf);
    }

    [Fact]
    public void Conf_disables_the_update_check_when_opted_out()
    {
        var conf = MqttInstaller.GenerateConf(new MqttOptions("broker.lan") { UpdateCheckEnabled = false });
        Assert.Contains("UPDATE_CHECK=0\n", conf);
        // The topic is still written (harmless, unused) so the key set stays stable across toggles.
        Assert.Contains("TOPIC_UPDATE='Bticino/update'\n", conf);
    }

    [Fact]
    public void Update_topic_follows_a_custom_lastwill_namespace()
    {
        var conf = MqttInstaller.GenerateConf(new MqttOptions("broker.lan")
        {
            TopicLastWill = "home/intercom42/LastWillT",
        });
        Assert.Contains("TOPIC_UPDATE='home/intercom42/update'\n", conf);
    }

    [Fact]
    public void An_explicit_update_topic_is_pinned_verbatim()
    {
        var conf = MqttInstaller.GenerateConf(new MqttOptions("broker.lan") { TopicUpdate = "custom/upd" });
        Assert.Contains("TOPIC_UPDATE='custom/upd'\n", conf);
    }

    // ---------------------------- HA discovery ----------------------------

    private static JsonElement UpdateEntity(MqttOptions opts)
    {
        var e = MqttInstaller.GenerateHaDiscovery(opts, restoreFirewallEligible: false)
            .Single(x => x.FileName == "bridge_update.json");
        using var doc = JsonDocument.Parse(e.Json);
        return doc.RootElement.Clone();
    }

    [Fact]
    public void Discovery_emits_a_notify_only_firmware_update_entity()
    {
        var opts = new MqttOptions("broker.lan");
        var e = UpdateEntity(opts);

        Assert.Equal("firmware", e.GetProperty("device_class").GetString());
        Assert.Equal(opts.EffectiveTopicUpdate, e.GetProperty("state_topic").GetString());
        // NOTIFY-ONLY: no command/install path (the panel can't self-flash).
        Assert.False(e.TryGetProperty("command_topic", out _), "update entity must have no command_topic");
        Assert.False(e.TryGetProperty("payload_install", out _), "update entity must have no install payload");
        // Informational link to the releases page, and grouped under the shared device.
        Assert.True(e.TryGetProperty("release_url", out var url) && url.GetString()!.Contains("/releases"));
        Assert.True(e.TryGetProperty("device", out _), "update entity must carry the shared device block");
    }

    [Fact]
    public void Update_entity_is_tombstoned_when_opted_out()
    {
        var opts = new MqttOptions("broker.lan") { UpdateCheckEnabled = false };
        var e = MqttInstaller.GenerateHaDiscovery(opts, restoreFirewallEligible: false)
            .Single(x => x.FileName == "bridge_update.json");
        // Same config topic, EMPTY retained payload = HA drops the entity.
        Assert.Equal("", e.Json);
    }

    [Fact]
    public void Update_entity_state_topic_matches_the_conf_topic()
    {
        // The discovery state_topic and the conf TOPIC_UPDATE must be the same string, or HA would
        // read a topic the daemon never publishes to.
        var opts = new MqttOptions("broker.lan") { TopicLastWill = "home/unitA/LastWillT" };
        var e = UpdateEntity(opts);
        Assert.Equal("home/unitA/update", e.GetProperty("state_topic").GetString());
        Assert.Contains("TOPIC_UPDATE='home/unitA/update'\n", MqttInstaller.GenerateConf(opts));
    }

    [Fact]
    public void Update_entity_is_deterministic()
    {
        // ValidateMqtt re-generates discovery and byte-compares; the update entity must be identical
        // for identical inputs.
        var a = MqttInstaller.GenerateHaDiscovery(new MqttOptions("broker.lan"), false)
            .Single(x => x.FileName == "bridge_update.json").Json;
        var b = MqttInstaller.GenerateHaDiscovery(new MqttOptions("broker.lan"), false)
            .Single(x => x.FileName == "bridge_update.json").Json;
        Assert.Equal(a, b);
    }
}
