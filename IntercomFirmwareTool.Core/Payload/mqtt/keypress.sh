#!/bin/sh
# keypress.sh - publish physical key presses on the unit to MQTT.
#
# Reads the front-panel input device with evtest and publishes a small JSON
# object to $TOPIC_KEY for each recognised key. Requires evtest and jq.
#
# MIT-licensed reimplementation of fquinto's mqtt_scripts/keypress.sh (GPL-2.0)
# for IntercomFirmwareTool. Note: fquinto's main.py never installed this script
# even though TcpDump2Mqtt launches it; the installer here ships it so the
# key-press feature actually works. Event fields are parsed by label (type/code/
# value) rather than fixed columns, so evtest spacing changes don't break it.
PATH=/sbin:/usr/sbin:/usr/bin:/bin
. /etc/tcpdump2mqtt/mqtt_common.sh

INPUT_DEVICE="/dev/input/event0"
TOPIC_KEY="${TOPIC_KEY:-Bticino/key}"

if [ ! -e "$INPUT_DEVICE" ]; then
	echo "Input device $INPUT_DEVICE not found."
	exit 1
fi

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

# evtest lines look like: "Event: time 1700000000.000000, type 1 (EV_KEY), code 2 (KEY_1), value 1"
evtest "$INPUT_DEVICE" | while read -r line; do
	event_type=$(echo "$line" | sed -n 's/.*type \([0-9][0-9]*\).*/\1/p')
	event_code=$(echo "$line" | sed -n 's/.*code \([0-9][0-9]*\).*/\1/p')
	event_value=$(echo "$line" | sed -n 's/.*value \([0-9][0-9]*\).*/\1/p')

	[ "$event_type" = "1" ] || continue
	label=$(key_label "$event_code")
	[ -n "$label" ] || continue

	key_info=${label% *}
	draw=${label#* }
	# 1 = press, 0 = release; ignore 2 (auto-repeat) and anything unexpected.
	case "$event_value" in
		1) value="pressed" ;;
		0) value="released" ;;
		*) continue ;;
	esac

	json=$(jq -n --arg key_info "$key_info" --arg draw "$draw" --arg value "$value" \
		'{key_info:$key_info,draw:$draw,value:$value}')
	mqtt_pub -t "$TOPIC_KEY" -m "$json"
done
