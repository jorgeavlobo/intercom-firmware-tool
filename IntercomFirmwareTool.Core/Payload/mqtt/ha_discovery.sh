#!/bin/sh
# ha_discovery.sh - publish Home Assistant MQTT discovery configs (retained).
#
# Reads the manifest the installer wrote (one "config-topic<TAB>filename" line
# per entity) and publishes each JSON payload to its discovery config topic,
# RETAINED, so Home Assistant auto-creates the bridge's entities (connectivity,
# bus dump, last key) with no manual YAML.
#
# Run once at startup by TcpDump2Mqtt. When HA_DISCOVERY=1 it PUBLISHES each config
# retained (so HA auto-creates the entities); when HA_DISCOVERY=0 it CLEARS the
# retained configs (empty payload) so an opt-out actually removes the entities
# from a broker that already saw them. Retained state only needs to land ONCE, so
# this retries a few times if the broker isn't up yet, then gives up (a reboot
# retries). Read-only: it publishes nothing to the OpenWebNet bus and creates no
# command entity.
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
			mqtt_pub -r -t "$topic" -f "$HA_DIR/$file" || rc=1
		else
			# Clear the retained config: an empty retained payload (-r -n) makes the
			# broker drop it, so HA removes the auto-discovered entity.
			mqtt_pub -r -n -t "$topic" || rc=1
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
		exit 0
	fi
	i=$((i + 1))
	# Backoff (capped): the broker may not be up yet at boot.
	sleep $((i * 5))
done

echo "ha_discovery: broker unreachable after retries; could not ${action} all discovery configs"
exit 1
