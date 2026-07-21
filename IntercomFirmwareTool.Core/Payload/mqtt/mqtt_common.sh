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

# Detect ONCE per process whether mosquitto_sub supports a durable session (-c) and
# cache it in MQTT_SUB_CLEAN ("-c" when supported, "" when not). The ${VAR+set} test
# treats a cached EMPTY result as "already probed", so the --help probe isn't re-run.
# StartMqttReceive calls this in its PARENT shell before the reconnect loop; the value
# is then inherited by every `mqtt_sub_stream | while read` pipeline subshell, so the
# extra "mosquitto_sub --help | grep" runs just once, not on every reconnect.
#
# Probe --help for the -c option's DESCRIPTION rather than the long flag name: older
# builds document it only as "-c : disable clean session/..." with no
# "--disable-clean-session" spelling, so match the (English-only, unlocalised)
# description text, which is present exactly when -c is supported.
mqtt_detect_clean() {
	if [ -z "${MQTT_SUB_CLEAN+set}" ]; then
		if /usr/bin/mosquitto_sub --help 2>&1 | grep -qiE -- '--disable-clean-session|disable clean session'; then
			MQTT_SUB_CLEAN=-c
		else
			MQTT_SUB_CLEAN=
		fi
	fi
}

mqtt_sub_stream() {
	# -R ignores RETAINED messages: TOPIC_RX is a live command channel; a retained
	# command would otherwise be re-delivered on every reconnect and replay forever
	# until it is cleared. Commands must be published non-retained. (-R suppresses only
	# messages with the RETAIN flag; queued session messages redelivered to a resuming
	# durable session are normal messages, so those are still delivered — see -c.)
	#
	# TOPIC_RX is subscribed as-is (a "$share/<group>/<filter>" shared subscription
	# is fine here — this IS the sole command consumer, so it SHOULD join the group;
	# unlike the old separate presence holder, there's no second subscriber to steal
	# commands from). The will targets TOPIC_LASTWILL (publish/retain), a topic the
	# bridge is already allowed to write.

	# Stable, per-unit client id so a DURABLE session (see -c below) can be RESUMED
	# across reconnects/restarts. Derived from TOPIC_LASTWILL: that topic must already
	# be distinct per unit for multi-unit-on-one-broker (see README), and it's stable
	# (config is stable) — unlike mosquitto's default PID-based id, which changes every
	# restart and so couldn't resume a session.
	#
	# A readable sanitised prefix ([A-Za-z0-9_-]) PLUS an INJECTIVE hex encoding of the
	# RAW topic. The sanitisation alone is lossy — two DISTINCT topics could collapse to
	# the same prefix (e.g. "Bticino/a/b" and "Bticino/a_b" both -> "Bticino_a_b") — so
	# the hex (a bijection: each byte -> two fixed hex chars) guarantees DISTINCT topics
	# always produce DISTINCT ids, not merely probabilistically (a 32-bit checksum could
	# still collide). This matters because a broker allows only ONE live connection per
	# client id, so a collision would make two otherwise-valid units evict each other and
	# flap the shared durable session. Length isn't capped because the broker already
	# accepts mosquitto's own long default ids. od is a standard busybox applet; were it
	# absent the hex is empty and the id degrades to the sanitised prefix (still distinct
	# for every non-pathological topic) — never one shared id, so not a hard failure.
	_lw="${TOPIC_LASTWILL:-default}"
	_cid="btrx-$(printf '%s' "$_lw" | tr -c 'A-Za-z0-9_-' '_')-$(printf '%s' "$_lw" | od -A n -t x1 | tr -d ' \n')"

	# Persistent (durable) session WHEN the client supports it: clean-session=0 lets
	# the broker QUEUE QoS>=1 commands published while the receiver is briefly
	# disconnected and deliver them on reconnect — closing the residual in-flight gap
	# that a clean session at QoS 0 can't (the broker discards anything sent during the
	# blip). The -c flag arrived in mosquitto 1.5; the intercom's client may predate it,
	# so support is probed (and cached) by mqtt_detect_clean, which falls back to a
	# clean session (still far better than the old per-message reconnect) when absent.
	mqtt_detect_clean

	# -q 1: subscribe at QoS 1 so queued/redelivered commands are at-least-once. (The
	# end-to-end guarantee also needs the PUBLISHER to use QoS 1; and at-least-once
	# means a command MAY be redelivered after a crash mid-processing — harmless for
	# bus frames / key presses, at most a re-run for execute_command.)
	#
	# ${MQTT_SUB_CLEAN} is intentionally UNQUOTED: it expands to the single arg -c when
	# supported, or to nothing (no empty arg) when the client lacks persistent-session
	# support.
	# shellcheck disable=SC2086
	set -- -h "${MQTT_HOST}" -p "${MQTT_PORT}" -i "${_cid}" ${MQTT_SUB_CLEAN} -q 1 -R -t "${TOPIC_RX}" \
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
