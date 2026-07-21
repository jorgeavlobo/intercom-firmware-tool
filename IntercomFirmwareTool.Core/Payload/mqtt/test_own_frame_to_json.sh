#!/bin/sh
# test_own_frame_to_json.sh - regression test for own_frame_to_json (mqtt_common.sh).
#
# own_frame_to_json is a hand-rolled structural parser: it turns raw OpenWebNet
# frames into one compact JSON object per line for PAYLOAD_FORMAT=json. This test
# pins its behaviour for representative COMMAND, REQUEST, short, and session
# ACK/NACK frames so a future edit to the jq program can't silently change the
# on-the-wire payload schema.
#
# Host-only: needs a POSIX sh + jq (the same jq the bridge ships on-device). It is
# NOT installed on the intercom — it lives beside the payload scripts as a dev/CI
# check. Run: sh test_own_frame_to_json.sh
#
# The emitted `ts` field is wall-clock (jq `now`), so it is stripped with
# `del(.ts)` before comparing; only the structural fields are asserted.
#
# MIT-licensed, part of IntercomFirmwareTool's MQTT bridge payload.

DIR=$(dirname "$0")
# Source the real helper so the test exercises the shipped function, not a copy.
# mqtt_common.sh is written to be sourced WITHOUT `set -u` (it reads some vars
# before defaulting them), so this test does not enable -u.
. "$DIR/mqtt_common.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not found on PATH" >&2; exit 0; }

fail=0

# check FRAME EXPECTED
#   FRAME    - a single raw OpenWebNet frame fed to own_frame_to_json
#   EXPECTED - the expected compact JSON with the ts field removed, or the empty
#              string when the frame must be dropped (produces no output)
#
# Fails CLOSED: a nonzero exit from own_frame_to_json, or output that is not a
# JSON object carrying a string `ts`, is a FAIL — never silently coerced to the
# empty string (which would let a broken parser masquerade as a valid ACK/NACK
# drop). Only genuinely empty output counts as a drop.
check() {
	frame=$1
	expected=$2

	# Run the parser and capture BOTH its output and exit status (no `|| true`).
	raw=$(printf '%s\n' "$frame" | own_frame_to_json)
	st=$?
	if [ "$st" -ne 0 ]; then
		printf 'FAIL  %-14s own_frame_to_json exited %d\n' "$frame" "$st" >&2
		fail=1
		return
	fi

	if [ -z "$raw" ]; then
		# No output: a legitimately dropped frame.
		got=""
	else
		# Non-empty output MUST be a JSON object with a string `ts`; then drop ts
		# for the structural comparison. `jq -e` + the explicit error() make a
		# malformed payload or a missing/non-string ts a hard failure.
		if ! got=$(printf '%s\n' "$raw" | jq -ce '
			if type == "object" and (.ts | type) == "string"
			then del(.ts)
			else error("payload is not an object with a string ts")
			end'); then
			printf 'FAIL  %-14s malformed payload: %s\n' "$frame" "$raw" >&2
			fail=1
			return
		fi
	fi

	if [ "$got" = "$expected" ]; then
		printf 'ok    %-14s -> %s\n' "$frame" "${got:-<dropped>}"
	else
		printf 'FAIL  %-14s\n  expected: %s\n  got:      %s\n' \
			"$frame" "${expected:-<dropped>}" "${got:-<dropped>}" >&2
		fail=1
	fi
}

# COMMAND frames: *WHO*WHAT*WHERE[*params…]##
check '*1*0*12##'      '{"frame":"*1*0*12##","type":"command","who":"1","what":"0","where":"12","params":[]}'
check '*2*1*21*100##'  '{"frame":"*2*1*21*100##","type":"command","who":"2","what":"1","where":"21","params":["100"]}'

# REQUEST frames: *#WHO*WHERE[*params…]## (what is always null for a stable schema)
check '*#1*12##'       '{"frame":"*#1*12##","type":"request","who":"1","what":null,"where":"12","params":[]}'
check '*#4*1*0##'      '{"frame":"*#4*1*0##","type":"request","who":"4","what":null,"where":"1","params":["0"]}'

# Short / degenerate frame: missing positions degrade to null / [] without erroring.
check '*1##'           '{"frame":"*1##","type":"command","who":"1","what":null,"where":null,"params":[]}'

# Session ACK / NACK control frames: dropped, no output.
check '*#*1##'         ''
check '*#*0##'         ''

if [ "$fail" -eq 0 ]; then
	echo "All own_frame_to_json regression checks passed."
else
	echo "own_frame_to_json regression checks FAILED." >&2
fi
exit "$fail"
