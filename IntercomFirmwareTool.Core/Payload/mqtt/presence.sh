#!/bin/sh
# presence.sh - hold a persistent MQTT session for reliable HA availability.
#
# Runs the long-lived presence subscription (mqtt_presence) that keeps an MQTT
# session open with a retained 'offline' last will on TOPIC_LASTWILL. If the
# bridge dies uncleanly the broker fires that will and Home Assistant sees the
# bridge (and the entities whose availability is this topic) go offline.
#
# The orchestrator manages this script like the other back-ends: it announces
# 'online' after (re)starting it, respawns it if the broker drops it, and on a
# CLEAN shutdown publishes 'offline' explicitly (a clean disconnect suppresses
# the will). We run mqtt_presence as a child (not exec) so the orchestrator's
# pgrep liveness/kill on this script path keeps working, and a trap reaps the
# mosquitto_sub child when we're stopped.
#
# MIT-licensed, part of IntercomFirmwareTool's MQTT bridge payload.
PATH=/sbin:/usr/sbin:/usr/bin:/bin
. /etc/tcpdump2mqtt/mqtt_common.sh

child=
# On stop, kill the mosquitto_sub child. This is a CLEAN disconnect, so the will
# does NOT fire here — the orchestrator's exit handler announces 'offline'.
trap 'if [ -n "$child" ]; then kill "$child" 2>/dev/null; fi; exit 0' INT TERM

mqtt_presence &
child=$!
# Wait on the child; when the broker drops it (or it's killed) we return and the
# script exits, so the orchestrator's watchdog respawns us on its next pass.
wait "$child"
