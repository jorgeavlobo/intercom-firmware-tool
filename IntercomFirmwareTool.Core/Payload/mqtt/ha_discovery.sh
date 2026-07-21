#!/bin/sh
# ha_discovery.sh - publish Home Assistant MQTT discovery configs (retained).
#
# Reads the manifest the installer wrote (one "config-topic<TAB>filename" line
# per entity) and publishes each JSON payload to its discovery config topic,
# RETAINED, so Home Assistant auto-creates the bridge's entities (connectivity,
# bus dump, last key) with no manual YAML.
#
# Launched by TcpDump2Mqtt. When HA_DISCOVERY=1 it PUBLISHES each config retained
# (so HA auto-creates the entities); when HA_DISCOVERY=0 it CLEARS the retained
# configs (empty payload) so an opt-out actually removes the entities from a broker
# that already saw them. Retained state only needs to land ONCE, so this retries a
# few times if the broker isn't up yet; on success it writes HA_MARKER and exits.
# The orchestrator watchdog re-launches this script until HA_MARKER exists, so a
# broker that is still down after these retries is picked up on the next loop (no
# reboot needed). Read-only: it publishes nothing to the OpenWebNet bus and creates
# no command entity.
#
# MIT-licensed, part of IntercomFirmwareTool's MQTT bridge payload.
PATH=/sbin:/usr/sbin:/usr/bin:/bin
. /etc/tcpdump2mqtt/mqtt_common.sh

HA_DIR=/etc/tcpdump2mqtt/ha
MANIFEST="$HA_DIR/manifest"

# The installer always writes the manifest, so a missing or empty one means a
# broken install — fail (don't silently report success).
if [ ! -s "$MANIFEST" ]; then
	echo "ha_discovery: manifest $MANIFEST missing or empty"
	exit 1
fi

TAB=$(printf '\t')

# Track the in-flight publisher so a stop signal reaps it instead of orphaning a
# blocked mosquitto_pub. During a broker/DNS stall a foreground publish can hang;
# if TcpDump2Mqtt's kill_childs then TERMs this script (matched by path), an
# un-reaped mosquitto_pub child would linger and could re-publish/clear after the
# watchdog started a replacement. So run each publish as a tracked background child
# and reap it on INT/TERM. NOTE: mqtt_pub is a FUNCTION, so "mqtt_pub &" makes
# pub_child the wrapper subshell, not the real /usr/bin/mosquitto_pub (bash doesn't
# exec-optimize a backgrounded function body) — hence kill_tree (kills the wrapper
# AND its mosquitto_pub child via pgrep -P), then wait reaps the wrapper.
pub_child=
term=
# Recorder trap: it must NOT exit on its own — a signal in the "mqtt_pub & ->
# pub_child=$!" window (before the PID is known) would otherwise leave the
# just-launched child untracked and orphaned. So it only flags the request (and
# reaps a child if one is already tracked); pub() then honours the flag at safe
# points once the PID is captured, closing the window.
sig() {
	term=1
	if [ -n "$pub_child" ]; then kill_tree "$pub_child"; wait "$pub_child" 2>/dev/null; pub_child=; fi
}
trap sig INT TERM

# Run one mqtt_pub as a tracked child so INT/TERM reaps it instead of orphaning it.
pub() {
	[ -n "$term" ] && exit 143
	mqtt_pub "$@" &
	pub_child=$!
	# A signal in the launch->capture window above set term but couldn't kill (PID
	# not yet known); now that it is, reap the child (wrapper + real publisher) and stop.
	[ -n "$term" ] && { kill_tree "$pub_child"; wait "$pub_child" 2>/dev/null; exit 143; }
	wait "$pub_child"
	_prc=$?
	pub_child=
	[ -n "$term" ] && exit 143
	return "$_prc"
}

# Apply the manifest once: publish each entity's config retained (HA_DISCOVERY=1)
# or clear the retained config with an empty message (HA_DISCOVERY=0). Returns
# non-zero if any row is malformed, any publish fails, or nothing was applied, so
# the caller retries the whole set rather than masking a broken install.
apply_all() {
	rc=0
	n=0
	while IFS="$TAB" read -r topic file; do
		# Tolerate a stray fully-blank line, but a half-populated row is malformed.
		if [ -z "$topic" ] && [ -z "$file" ]; then
			continue
		fi
		if [ -z "$topic" ] || [ -z "$file" ]; then
			echo "ha_discovery: malformed manifest row"
			rc=1
			continue
		fi
		# Defence-in-depth: the manifest is installer-written with fixed basenames,
		# but never let a tampered "$file" escape $HA_DIR (e.g. "../TcpDump2Mqtt.conf"
		# would otherwise be read and published, leaking config). Require a plain
		# basename — no '/' and not "..".
		case "$file" in
			*/* | ..)
				echo "ha_discovery: unsafe filename in manifest: $file"
				rc=1
				continue
				;;
		esac
		n=$((n + 1))
		if [ "${HA_DISCOVERY:-0}" = "1" ]; then
			if [ ! -f "$HA_DIR/$file" ]; then
				echo "ha_discovery: missing $HA_DIR/$file"
				rc=1
				continue
			fi
			# -r retained (HA re-reads configs on restart); -f reads the JSON
			# payload from the file (avoids quoting multi-line JSON on the CLI).
			pub -r -t "$topic" -f "$HA_DIR/$file" || rc=1
		else
			# Clear the retained config: an empty retained payload (-r -n) makes the
			# broker drop it, so HA removes the auto-discovered entity.
			pub -r -n -t "$topic" || rc=1
		fi
	done < "$MANIFEST"
	# No usable rows at all is itself a failure (empty/garbage manifest).
	[ "$n" -gt 0 ] || rc=1
	return $rc
}

if [ "${HA_DISCOVERY:-0}" = "1" ]; then action="publish"; else action="clear"; fi

i=0
while [ "$i" -lt 6 ]; do
	if apply_all; then
		echo "ha_discovery: ${action}ed Home Assistant discovery configs"
		# Signal convergence so the orchestrator stops re-launching us. ensure_rundir
		# creates the runtime dir 0700 (root-only) EVEN IF it already exists with a
		# looser mode (e.g. StartMqttSend made it under a permissive umask), so an
		# unprivileged account can't pre-create the marker or plant a symlink for the
		# root truncation below to follow. rm -rf first drops any symlink, file OR
		# directory planted at the marker path before the dir was locked down (a plain
		# rm -f can't clear a directory, which would then block ": >" forever).
		ensure_rundir
		rm -rf "$HA_MARKER" 2>/dev/null
		if : > "$HA_MARKER" 2>/dev/null; then
			exit 0
		fi
		# The configs were applied, but the convergence marker couldn't be written
		# (e.g. $RUNDIR unwritable). Without it the orchestrator will relaunch us
		# every watchdog pass and re-apply the retained configs. Surface it and fail
		# instead of a silent success, so the real problem is visible in the log.
		echo "ha_discovery: could not write marker $HA_MARKER; will re-run each pass"
		exit 1
	fi
	i=$((i + 1))
	# Backoff (capped): the broker may not be up yet at boot.
	sleep $((i * 5))
done

echo "ha_discovery: broker unreachable after retries; could not ${action} all discovery configs"
exit 1
