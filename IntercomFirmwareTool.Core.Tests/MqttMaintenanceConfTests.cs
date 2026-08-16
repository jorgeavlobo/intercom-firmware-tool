using IntercomFirmwareTool.Core;
using Xunit;

namespace IntercomFirmwareTool.Core.Tests;

/// <summary>
/// The retained "last maintenance action" feedback topic (issue #43) in the generated device
/// <c>btmqttd.conf</c>. btmqttd publishes <c>{"action":…,"at":…}</c> here when a reboot / restart-bridge
/// button is pressed, and the HA feedback sensor reads it back; the installer must therefore write
/// <c>TOPIC_MAINTENANCE</c>, scoped to the same per-unit namespace as the last-will topic (so it matches
/// <see cref="MqttOptions.EffectiveTopicMaintenance"/> that the discovery sensor's <c>state_topic</c>
/// uses, and the daemon's <c>TOPIC_MAINTENANCE</c> default key).
/// </summary>
public class MqttMaintenanceConfTests
{
    [Fact]
    public void Conf_writes_the_maintenance_topic_scoped_to_the_lastwill_namespace()
    {
        // Default LWT "Bticino/LastWillT" ⇒ namespace "Bticino/" ⇒ "Bticino/maintenance".
        var conf = MqttInstaller.GenerateConf(new MqttOptions("broker.lan"));
        Assert.Contains("TOPIC_MAINTENANCE='Bticino/maintenance'\n", conf);
    }

    [Fact]
    public void Maintenance_topic_follows_a_custom_lastwill_namespace()
    {
        // A per-unit last-will namespace scopes the derived maintenance topic with it.
        var conf = MqttInstaller.GenerateConf(new MqttOptions("broker.lan")
        {
            TopicLastWill = "home/intercom42/LastWillT",
        });
        Assert.Contains("TOPIC_MAINTENANCE='home/intercom42/maintenance'\n", conf);
    }

    [Fact]
    public void An_explicit_maintenance_topic_is_pinned_verbatim()
    {
        var conf = MqttInstaller.GenerateConf(new MqttOptions("broker.lan")
        {
            TopicMaintenance = "custom/maint",
        });
        Assert.Contains("TOPIC_MAINTENANCE='custom/maint'\n", conf);
    }
}
