#!/bin/sh
# mqtt_common.sh - shared config loader and MQTT helpers for the bridge.
#
# Sourced by TcpDump2Mqtt, StartMqttSend, StartMqttReceive and keypress.sh so the
# broker auth/TLS logic and the remote-command gate live in exactly one place.
# MIT-licensed, part of IntercomFirmwareTool's MQTT bridge payload.

MQTT_CFGFILE=/etc/tcpdump2mqtt/TcpDump2Mqtt.conf

# Load the config when the caller was started without the environment exported
# (functions are not inherited across exec, so every child sources this).
if [ -z "${MQTT_HOST}" ] && [ -f "$MQTT_CFGFILE" ]; then
	set -a
	. "$MQTT_CFGFILE"
	set +a
fi

# Topic defaults, centralised here (used by the sender/receiver/keypress).
: "${TOPIC_KEY:=Bticino/key}"
: "${TOPIC_FILE_CONTENT:=Bticino/file_content_topic}"
: "${TOPIC_CMD_RESULT:=Bticino/command_result_topic}"

# Capture back-end + OpenWebNet monitor endpoint, centralised so the sender AND
# the orchestrator (which builds pgrep kill patterns from these) agree. See
# StartMqttSend for what the modes mean; openserver's plaintext OwnPort is 20000.
: "${CAPTURE_MODE:=socket}"
: "${OWN_HOST:=127.0.0.1}"
: "${OWN_PORT_MON:=20000}"

# mosquitto_pub with auth AND TLS applied independently (compose, do not choose
# one or the other). Extra args (topic, -l, -r, -m ...) pass through; mosquitto
# accepts options in any order.
mqtt_pub() {
	set -- -h "${MQTT_HOST}" -p "${MQTT_PORT}" "$@"
	[ -n "${MQTT_USER}" ] && set -- "$@" -u "${MQTT_USER}" -P "${MQTT_PASS}"
	if [ -n "${MQTT_CAFILE}" ]; then
		set -- "$@" --cafile "${MQTT_CAFILE}"
		[ -n "${MQTT_CERTFILE}" ] && [ -n "${MQTT_KEYFILE}" ] && \
			set -- "$@" --cert "${MQTT_CERTFILE}" --key "${MQTT_KEYFILE}"
	fi
	/usr/bin/mosquitto_pub "$@"
}

# mosquitto_sub for exactly one message on TOPIC_RX, same auth/TLS composition,
# with the offline last will.
mqtt_sub_one() {
	# -R ignores RETAINED messages: TOPIC_RX is a live command channel, and each
	# -C 1 reconnect would otherwise re-receive a retained command and replay it
	# forever until it is cleared. Commands must be published non-retained.
	#
	# NOTE: the retained 'offline' last will only fires on an UNCLEAN drop. With
	# the -C 1 one-shot subscription each cycle ends in a clean disconnect, so
	# the will rarely triggers and TOPIC_LASTWILL can stay 'online'. Reliable
	# online/offline availability needs a persistent subscription (Phase 2, #12).
	set -- -h "${MQTT_HOST}" -p "${MQTT_PORT}" -C 1 -R \
		--will-topic "${TOPIC_LASTWILL}" --will-payload offline --will-retain -t "${TOPIC_RX}"
	[ -n "${MQTT_USER}" ] && set -- "$@" -u "${MQTT_USER}" -P "${MQTT_PASS}"
	if [ -n "${MQTT_CAFILE}" ]; then
		set -- "$@" --cafile "${MQTT_CAFILE}"
		[ -n "${MQTT_CERTFILE}" ] && [ -n "${MQTT_KEYFILE}" ] && \
			set -- "$@" --cert "${MQTT_CERTFILE}" --key "${MQTT_KEYFILE}"
	fi
	/usr/bin/mosquitto_sub "$@"
}

# The JSON remote-command channel is honoured only when explicitly enabled AND
# the CLIENT is authenticated: username/password, or mutual TLS (client cert+key).
# One-way TLS (CA only) verifies the broker but NOT the client, so it does not
# unlock this channel.
remote_shell_allowed() {
	[ "${ALLOW_REMOTE_SHELL:-0}" = "1" ] || return 1
	# Password auth: BOTH username and password.
	[ -n "${MQTT_USER}" ] && [ -n "${MQTT_PASS}" ] && return 0
	# Mutual TLS: CA + client cert + key — exactly what mqtt_pub/mqtt_sub_one
	# actually send (they only add --cert/--key when MQTT_CAFILE is set).
	[ -n "${MQTT_CAFILE}" ] && [ -n "${MQTT_CERTFILE}" ] && [ -n "${MQTT_KEYFILE}" ] && return 0
	return 1
}
