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
#
# Unlike upstream (which hard-coded a 4-key map for the C300X, KEY_1..KEY_4),
# this publishes EVERY key generically using the KEY_ name evtest prints, so it
# covers any keypad — e.g. the C100X keypad has 7 keys (KEY_1..KEY_7), which the
# 4-key map would have dropped. Fields are parsed by label, not fixed columns.
PATH=/sbin:/usr/sbin:/usr/bin:/bin
. /etc/tcpdump2mqtt/mqtt_common.sh

# Auto-detect the keypad's event node (the device whose Name contains "keypad"),
# falling back to event0. The node is not the same across models — it is event0
# on the C100X, but hard-coding it would break on a unit where it differs.
INPUT_DEVICE=$(awk '
	/^N: Name=/ { name=$0 }
	/^H: Handlers=/ {
		if (tolower(name) ~ /keypad/) {
			for (i = 1; i <= NF; i++) if ($i ~ /^event[0-9]+$/) { print "/dev/input/" $i; exit }
		}
	}' /proc/bus/input/devices 2>/dev/null)
[ -n "$INPUT_DEVICE" ] || INPUT_DEVICE=/dev/input/event0
# TOPIC_KEY default comes from mqtt_common.sh (centralised topic defaults).

if [ ! -e "$INPUT_DEVICE" ]; then
	echo "Input device $INPUT_DEVICE not found."
	exit 1
fi

# Needs evtest (read keys) and jq (build the JSON payload).
for dep in evtest jq; do
	if ! command -v "$dep" > /dev/null 2>&1; then
		echo "keypress.sh: required tool '$dep' not found."
		exit 1
	fi
done

# evtest lines look like: "Event: time 1700000000.000000, type 1 (EV_KEY), code 2 (KEY_1), value 1"
evtest "$INPUT_DEVICE" | while read -r line; do
	event_type=$(echo "$line" | sed -n 's/.*type \([0-9][0-9]*\).*/\1/p')
	event_code=$(echo "$line" | sed -n 's/.*code \([0-9][0-9]*\).*/\1/p')
	event_value=$(echo "$line" | sed -n 's/.*value \([0-9][0-9]*\).*/\1/p')
	# The KEY_ name evtest prints in parentheses after the code, e.g. "(KEY_5)".
	key_name=$(echo "$line" | sed -n 's/.*(\(KEY_[A-Z0-9_]*\)).*/\1/p')

	[ "$event_type" = "1" ] || continue       # EV_KEY events only
	[ -n "$key_name" ] || continue            # skip SYN_REPORT / non-key lines
	[ -n "$event_code" ] || continue
	# 1 = press, 0 = release; ignore 2 (auto-repeat) and anything unexpected.
	case "$event_value" in
		1) value="pressed" ;;
		0) value="released" ;;
		*) continue ;;
	esac

	json=$(jq -cn --arg key "$key_name" --argjson code "$event_code" --arg value "$value" \
		'{key:$key,code:$code,value:$value}')
	mqtt_pub -t "$TOPIC_KEY" -m "$json"
done
