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

# mosquitto_sub for exactly one message on TOPIC_RX, same auth/TLS composition.
mqtt_sub_one() {
	# -R ignores RETAINED messages: TOPIC_RX is a live command channel, and each
	# -C 1 reconnect would otherwise re-receive a retained command and replay it
	# forever until it is cleared. Commands must be published non-retained.
	#
	# NOTE: no last will here. TOPIC_LASTWILL availability is owned SOLELY by the
	# persistent presence session (mqtt_presence / presence.sh). If this one-shot
	# receiver carried the will too, an UNCLEAN drop of one of its -C 1 cycles could
	# publish 'offline' and briefly flip a healthy bridge offline until the next
	# watchdog refresh — so the will stays only where it's meaningful.
	set -- -h "${MQTT_HOST}" -p "${MQTT_PORT}" -C 1 -R -t "${TOPIC_RX}"
	[ -n "${MQTT_USER}" ] && set -- "$@" -u "${MQTT_USER}" -P "${MQTT_PASS}"
	if [ -n "${MQTT_CAFILE}" ]; then
		set -- "$@" --cafile "${MQTT_CAFILE}"
		[ -n "${MQTT_CERTFILE}" ] && [ -n "${MQTT_KEYFILE}" ] && \
			set -- "$@" --cert "${MQTT_CERTFILE}" --key "${MQTT_KEYFILE}"
	fi
	/usr/bin/mosquitto_sub "$@"
}

# Persistent PRESENCE connection: a long-lived mosquitto_sub whose only job is to
# hold an MQTT session with a retained 'offline' last will on TOPIC_LASTWILL. When
# the bridge drops UNCLEANLY (crash, power loss, network death) the broker delivers
# that will, so Home Assistant sees the bridge go offline. The receiver's one-shot
# -C 1 subscription can't do this (each cycle disconnects cleanly, suppressing the
# will and leaving the topic 'online'); this dedicated session stays connected (and
# reconnects on its own after a blip, re-registering the will), so the OFFLINE side
# of availability is reliable. It subscribes to TOPIC_RX purely to keep the socket
# open (the payload is ignored — this is NOT the command receiver). TOPIC_RX is
# chosen deliberately: the bridge already needs SUBSCRIBE permission on it (the
# receiver uses it), so on a broker with topic ACLs that allow publishing status
# but only subscribing to the command topic, presence doesn't impose a new
# subscribe requirement on TOPIC_LASTWILL. The will still targets TOPIC_LASTWILL
# (publish/retain, which the bridge is already allowed to do). The ONLINE side is
# refreshed by the orchestrator loop, and clean shutdowns (which suppress the will)
# publish 'offline' explicitly there — see presence.sh / TcpDump2Mqtt. Same auth/TLS
# composition as mqtt_pub/mqtt_sub_one.
mqtt_presence() {
	# Hold-open topic = TOPIC_RX, but strip a "$share/<group>/" prefix if present:
	# a Mosquitto SHARED subscription distributes each message to ONE client in the
	# group, so joining the receiver's shared group would let presence swallow
	# commands meant for StartMqttReceive. Subscribing to the underlying (non-shared)
	# filter keeps the same ACL topic while staying out of the shared group.
	_pt="${TOPIC_RX}"
	case "$_pt" in
		'$share/'*) _pt="${_pt#\$share/}"; _pt="${_pt#*/}" ;;
	esac
	set -- -h "${MQTT_HOST}" -p "${MQTT_PORT}" -t "${_pt}" \
		--will-topic "${TOPIC_LASTWILL}" --will-payload offline --will-retain
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
