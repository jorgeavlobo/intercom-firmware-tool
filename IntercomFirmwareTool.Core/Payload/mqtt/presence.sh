#!/bin/sh
# presence.sh - hold a persistent MQTT session for reliable HA availability.
#
# Runs the long-lived presence subscription (mqtt_presence): a mosquitto_sub that
# keeps an MQTT session open with a retained 'offline' last will on TOPIC_LASTWILL.
# If the bridge dies uncleanly (crash, power loss, network death) the broker
# delivers that will, so Home Assistant sees the bridge (and the entities whose
# availability is this topic) go offline. This is the RELIABLE half of availability
# and needs no cooperation from us — the broker does it.
#
# The 'online' (birth) half is refreshed by the orchestrator's watchdog loop, not
# here: mosquitto_sub reconnects INTERNALLY after a broker blip (the process stays
# alive across reconnects), and an unclean blip makes the broker retain 'offline',
# so a one-shot birth would leave availability stuck 'offline' after the first
# reconnect. Re-publishing 'online' each watchdog pass restores it within one loop
# once the broker is reachable again. (Atomically tying 'online' to this session's
# connect is not possible with the mosquitto CLI tools — a separate mosquitto_pub
# can't share this client's connection — so the periodic refresh is the pragmatic
# reliable approach; it's best-effort and errs toward a brief stale 'offline'
# rather than a stale 'online'. See the README availability limitation.)
#
# On a CLEAN shutdown the orchestrator publishes 'offline' explicitly (a clean
# disconnect suppresses the will).
#
# MIT-licensed, part of IntercomFirmwareTool's MQTT bridge payload.
PATH=/sbin:/usr/sbin:/usr/bin:/bin
. /etc/tcpdump2mqtt/mqtt_common.sh

child=
term=
# On stop, kill the mosquitto_sub child and WAIT for it, so the wrapper stays alive
# until the child is actually reaped (not merely signalled) — otherwise the watchdog
# could start a second presence.sh over a still-dying one. This is a CLEAN
# disconnect, so the will does NOT fire; the orchestrator announces 'offline'.
cleanup() {
	if [ -n "$child" ]; then
		kill "$child" 2>/dev/null
		wait "$child" 2>/dev/null
	fi
	exit 0
}

# A signal in the window between backgrounding mqtt_presence and capturing its PID
# can't yet be turned into a kill of the child. So install a lightweight RECORDER
# first (just note the request, don't exit), then the real cleanup trap once $child
# is known, then honour any request that landed in the window — closing the race
# that would otherwise leave a stray will-holder and let the watchdog spawn a
# duplicate.
trap 'term=1' INT TERM

# Hold the session. Output is irrelevant (we don't parse it), so discard it. The
# subscription itself just keeps the connection — and thus the will — alive.
mqtt_presence > /dev/null 2>&1 &
child=$!

trap cleanup INT TERM
[ -n "$term" ] && cleanup

# Blocks until mosquitto_sub exits (it reconnects internally, so normally only on a
# fatal error or when killed). On exit, the script ends and the watchdog respawns it.
wait "$child"
