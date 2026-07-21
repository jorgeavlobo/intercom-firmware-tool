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

# Home Assistant discovery success marker. ha_discovery.sh writes it once the
# retained configs are reconciled; the orchestrator re-launches ha_discovery.sh
# from its watchdog loop until this file exists, so a broker that is still down
# at boot can't leave discovery unpublished.
#
# Shared runtime dir: holds this marker and StartMqttSend's socket-pipeline FIFOs.
# Deliberately NOT world-writable /tmp: a non-root local account (e.g. bticino2)
# could otherwise pre-create the marker (watchdog would treat discovery as
# converged and never publish/clear it) or plant a symlink that a root write would
# follow and truncate. It's on tmpfs, so a reboot clears the marker and discovery
# re-reconciles. Create it via ensure_rundir() so the mode is enforced regardless
# of the caller's umask (a bare `mkdir -p` would inherit a permissive one).
: "${RUNDIR:=/var/run/tcpdump2mqtt}"
: "${HA_MARKER:=$RUNDIR/ha_done}"

# Create $RUNDIR root-only (0700), enforcing the mode even if it already exists
# with looser perms — so only root can plant/replace files there. Callers that
# write a fixed-name file into it (e.g. the marker) should still rm -f it first to
# drop any symlink planted before this ran.
ensure_rundir() {
	mkdir -p "$RUNDIR" 2>/dev/null
	chmod 0700 "$RUNDIR" 2>/dev/null
}

# Kill each given PID AND its direct children. Backgrounding a shell FUNCTION
# (mqtt_pub, frame_own, …) runs it in a wrapper subshell, and the device's /bin/sh
# is bash, which does NOT exec-optimize a backgrounded function body — so $! is the
# wrapper subshell and the real /usr/bin/mosquitto_pub (or awk/nc) is its child.
# Killing only the wrapper would orphan a publisher stuck in DNS/TCP connect; pgrep
# -P reaps the real child too. Used by StartMqttSend (socket pipeline) and
# ha_discovery.sh (its publisher). A directly-backgrounded binary has no wrapper,
# so kill_tree just kills it and finds no children, which is fine.
kill_tree() {
	for _p in "$@"; do
		[ -n "$_p" ] || continue
		_kids=$(/usr/bin/pgrep -P "$_p" 2>/dev/null)
		# shellcheck disable=SC2086
		kill "$_p" $_kids 2>/dev/null
	done
}

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

# Persistent command subscription: a long-lived mosquitto_sub that STREAMS every
# message on TOPIC_RX and ALSO carries the retained 'offline' last will on
# TOPIC_LASTWILL — a single session that is both the command receiver AND the
# availability holder (see StartMqttReceive).
#
# Why one persistent session instead of the old one-shot (-C 1) receiver + a
# separate presence holder:
#   * No command-loss window. The one-shot model reconnected after every message,
#     and any command published in that resubscribe gap was dropped (with -R the
#     broker doesn't retain it). A session that stays subscribed receives them all.
#   * Reliable OFFLINE. Because the session stays open, an UNCLEAN drop (crash,
#     power loss, network death) makes the broker deliver the will, so Home
#     Assistant sees the bridge go offline. A one-shot -C 1 cycle disconnects
#     CLEANLY, which suppresses the will — it could never own availability, which
#     is why a dedicated presence session used to exist. With the receiver now
#     persistent, that second session is redundant and has been removed.
# mosquitto_sub reconnects INTERNALLY after a blip, re-registering the will, and it
# flushes stdout after each message, so piping it into `while read` delivers commands
# promptly. Same auth/TLS composition as mqtt_pub.
mqtt_sub_stream() {
	# -R ignores RETAINED messages: TOPIC_RX is a live command channel; a retained
	# command would otherwise be re-delivered on every reconnect and replay forever
	# until it is cleared. Commands must be published non-retained.
	#
	# TOPIC_RX is subscribed as-is (a "$share/<group>/<filter>" shared subscription
	# is fine here — this IS the sole command consumer, so it SHOULD join the group;
	# unlike the old separate presence holder, there's no second subscriber to steal
	# commands from). The will targets TOPIC_LASTWILL (publish/retain), a topic the
	# bridge is already allowed to write.
	set -- -h "${MQTT_HOST}" -p "${MQTT_PORT}" -R -t "${TOPIC_RX}" \
		--will-topic "${TOPIC_LASTWILL}" --will-payload offline --will-retain
	[ -n "${MQTT_USER}" ] && set -- "$@" -u "${MQTT_USER}" -P "${MQTT_PASS}"
	if [ -n "${MQTT_CAFILE}" ]; then
		set -- "$@" --cafile "${MQTT_CAFILE}"
		[ -n "${MQTT_CERTFILE}" ] && [ -n "${MQTT_KEYFILE}" ] && \
			set -- "$@" --cert "${MQTT_CERTFILE}" --key "${MQTT_KEYFILE}"
	fi
	# exec so mosquitto_sub REPLACES this function's subshell (the left side of the
	# receiver's `mqtt_sub_stream | while read` pipe): no wrapper subshell is left
	# holding the real process, so the orchestrator's pgrep -f "mosquitto_sub.*RX"
	# matches (and can signal) the actual client directly.
	exec /usr/bin/mosquitto_sub "$@"
}

# The JSON remote-command channel is honoured only when explicitly enabled AND
# the CLIENT is authenticated: username/password, or mutual TLS (client cert+key).
# One-way TLS (CA only) verifies the broker but NOT the client, so it does not
# unlock this channel.
remote_shell_allowed() {
	[ "${ALLOW_REMOTE_SHELL:-0}" = "1" ] || return 1
	# Password auth: BOTH username and password.
	[ -n "${MQTT_USER}" ] && [ -n "${MQTT_PASS}" ] && return 0
	# Mutual TLS: CA + client cert + key — exactly what mqtt_pub/mqtt_sub_stream
	# actually send (they only add --cert/--key when MQTT_CAFILE is set).
	[ -n "${MQTT_CAFILE}" ] && [ -n "${MQTT_CERTFILE}" ] && [ -n "${MQTT_KEYFILE}" ] && return 0
	return 1
}
