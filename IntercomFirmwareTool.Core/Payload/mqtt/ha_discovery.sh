#!/bin/sh
# ha_discovery.sh - publish Home Assistant MQTT discovery configs (retained).
#
# Reads the manifest the installer wrote (one "config-topic<TAB>filename" line
# per entity) and publishes each JSON payload to its discovery config topic,
# RETAINED, so Home Assistant auto-creates the bridge's entities (connectivity,
# bus dump, last key) with no manual YAML.
#
# Run once at startup by TcpDump2Mqtt when HA_DISCOVERY=1. Retained configs only
# need to land ONCE, so this retries a few times if the broker isn't up yet, then
# gives up (a reboot retries). Read-only: it publishes nothing to the OpenWebNet
# bus and creates no command entity.
#
# MIT-licensed, part of IntercomFirmwareTool's MQTT bridge payload.
PATH=/sbin:/usr/sbin:/usr/bin:/bin
. /etc/tcpdump2mqtt/mqtt_common.sh

HA_DIR=/etc/tcpdump2mqtt/ha
MANIFEST="$HA_DIR/manifest"

[ "${HA_DISCOVERY:-0}" = "1" ] || exit 0
if [ ! -f "$MANIFEST" ]; then
	echo "ha_discovery: no manifest ($MANIFEST); nothing to publish"
	exit 0
fi

TAB=$(printf '\t')

# Publish every entry once; return non-zero if any file is missing or any publish
# fails, so the caller retries the whole set.
publish_all() {
	rc=0
	while IFS="$TAB" read -r topic file; do
		[ -n "$topic" ] && [ -n "$file" ] || continue
		if [ ! -f "$HA_DIR/$file" ]; then
			echo "ha_discovery: missing $HA_DIR/$file"
			rc=1
			continue
		fi
		# -r retained (HA re-reads configs on restart); -f reads the JSON payload
		# from the file (avoids quoting a multi-line JSON on the command line).
		mqtt_pub -r -t "$topic" -f "$HA_DIR/$file" || rc=1
	done < "$MANIFEST"
	return $rc
}

i=0
while [ "$i" -lt 6 ]; do
	if publish_all; then
		echo "ha_discovery: published Home Assistant discovery configs"
		exit 0
	fi
	i=$((i + 1))
	# Backoff (capped): the broker may not be up yet at boot.
	sleep $((i * 5))
done

echo "ha_discovery: broker unreachable after retries; discovery configs not fully published"
exit 1
