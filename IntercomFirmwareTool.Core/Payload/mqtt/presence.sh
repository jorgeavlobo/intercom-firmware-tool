#!/bin/sh
# presence.sh - hold a persistent MQTT session for reliable HA availability.
#
# Runs the long-lived presence subscription (mqtt_presence) that keeps an MQTT
# session open with a retained 'offline' last will on TOPIC_LASTWILL. If the
# bridge dies uncleanly the broker delivers that will and Home Assistant sees the
# bridge (and the entities whose availability is this topic) go offline.
#
# Announcing 'online' is gated on the session ACTUALLY connecting, not on a timer:
# we run mosquitto_sub with protocol debug (-d) through a FIFO and publish the
# retained 'online' only after we see the SUBACK, which the broker sends only once
# the client has connected AND subscribed. This ties 'online' to a live will-holder
# — a plain sleep could publish 'online' after the session had already failed or
# dropped, leaving stale availability with no will behind it.
#
# The orchestrator respawns this script if the broker drops it, and on a CLEAN
# shutdown publishes 'offline' explicitly (a clean disconnect suppresses the will).
#
# MIT-licensed, part of IntercomFirmwareTool's MQTT bridge payload.
PATH=/sbin:/usr/sbin:/usr/bin:/bin
. /etc/tcpdump2mqtt/mqtt_common.sh

# Readiness FIFO in the root-owned runtime dir (NOT world-writable /tmp, so an
# unprivileged account can't pre-create or symlink it). $$ keeps it per-instance.
mkdir -p "$RUNDIR" 2>/dev/null
FIFO="$RUNDIR/presence.$$"
rm -f "$FIFO"
if ! mkfifo "$FIFO" 2>/dev/null; then
	echo "presence.sh: could not create FIFO $FIFO"
	exit 1
fi

child=
# On stop, kill the mosquitto_sub child and WAIT for it so it's reaped here rather
# than briefly orphaned. This is a CLEAN disconnect, so the will does NOT fire —
# the orchestrator's exit handler announces 'offline'.
cleanup() {
	if [ -n "$child" ]; then
		kill "$child" 2>/dev/null
		wait "$child" 2>/dev/null
	fi
	rm -f "$FIFO"
	exit 0
}
trap cleanup INT TERM

# Presence session with protocol debug so the reader can see the SUBACK. Both
# debug and any received payloads are merged into the FIFO.
mqtt_presence -d > "$FIFO" 2>&1 &
child=$!

# Drain the FIFO (so mosquitto_sub never blocks on a full pipe) and, on the first
# SUBACK, announce 'online' retained — once, tied to this live session. The loop
# ends when mosquitto_sub closes the FIFO (session dropped), so the script then
# exits and the orchestrator respawns it on its next watchdog pass.
announced=
while IFS= read -r line; do
	case "$line" in
		*SUBACK*)
			[ -n "$announced" ] && continue
			# A SUBACK proves the session was connected when the broker wrote that
			# line, but it may be buffered from a session that has since dropped
			# (whose retained LWT 'offline' the broker already delivered). Only
			# announce 'online' while the mosquitto_sub child is still alive, and
			# re-check right after the publish: if it died across it, reconcile back
			# to 'offline' so we never strand a stale 'online' with no will-holder.
			kill -0 "$child" 2>/dev/null || continue
			mqtt_pub -r -t "$TOPIC_LASTWILL" -m online
			if kill -0 "$child" 2>/dev/null; then
				announced=1
			else
				mqtt_pub -r -t "$TOPIC_LASTWILL" -m offline
			fi
			;;
	esac
done < "$FIFO"

# Session ended (broker dropped us). Reap the child and clean up; a respawn will
# re-establish presence and re-announce 'online' if the broker is back.
cleanup
