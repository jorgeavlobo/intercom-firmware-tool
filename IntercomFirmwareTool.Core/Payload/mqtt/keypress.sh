#!/bin/sh
# keypress.sh - publish physical key presses on the unit to MQTT.
#
# Reads the front-panel input device with evtest and publishes a small JSON
# object to $TOPIC_KEY for each recognised key. Requires evtest and jq.
#
# MIT-licensed reimplementation of fquinto's mqtt_scripts/keypress.sh (GPL-2.0)
# for IntercomFirmwareTool. Note: fquinto's main.py never installed this script
# even though TcpDump2Mqtt launches it; the installer here ships it so the
# key-press feature actually works.
PATH=/sbin:/usr/sbin:/usr/bin:/bin
CFGFILE=/etc/tcpdump2mqtt/TcpDump2Mqtt.conf

if [ -z "${MQTT_HOST}" ] && [ -f "$CFGFILE" ]; then
	set -a
	. "$CFGFILE"
	set +a
fi

INPUT_DEVICE="/dev/input/event0"
TOPIC_KEY="${TOPIC_KEY:-Bticino/key}"

if [ ! -e "$INPUT_DEVICE" ]; then
	echo "Input device $INPUT_DEVICE not found."
	exit 1
fi

mpub() {
	if [ -n "${MQTT_USER}" ]; then
		/usr/bin/mosquitto_pub -h "${MQTT_HOST}" -p "${MQTT_PORT}" \
			-u "${MQTT_USER}" -P "${MQTT_PASS}" "$@"
	elif [ -n "${MQTT_CAFILE}" ]; then
		/usr/bin/mosquitto_pub -h "${MQTT_HOST}" -p "${MQTT_PORT}" \
			--cafile "${MQTT_CAFILE}" --cert "${MQTT_CERTFILE}" --key "${MQTT_KEYFILE}" "$@"
	else
		/usr/bin/mosquitto_pub -h "${MQTT_HOST}" -p "${MQTT_PORT}" "$@"
	fi
}

# Map the four front keys (event type 1 = EV_KEY; codes 2..5) to labels.
key_label() {
	case "$1" in
		2) echo "KEY_1 key" ;;
		3) echo "KEY_2 star" ;;
		4) echo "KEY_3 eye" ;;
		5) echo "KEY_4 phone" ;;
		*) echo "" ;;
	esac
}

evtest "$INPUT_DEVICE" | while read -r line; do
	event_type=$(echo "$line" | awk '{print $5}')
	event_code=$(echo "$line" | awk '{print $8}')
	event_value=$(echo "$line" | awk '{print $11}')

	[ "$event_type" = "1" ] || continue
	label=$(key_label "$event_code")
	[ -n "$label" ] || continue

	key_info=${label% *}
	draw=${label#* }
	if [ "$event_value" = "1" ]; then
		value="pressed"
	else
		value="released"
	fi

	json=$(jq -n --arg key_info "$key_info" --arg draw "$draw" --arg value "$value" \
		'{key_info:$key_info,draw:$draw,value:$value}')
	mpub -t "$TOPIC_KEY" -m "$json"
done
