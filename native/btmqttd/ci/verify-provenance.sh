#!/usr/bin/env bash
# Verify btmqttd ARM binary provenance (issue #72).
#
#   verify-provenance.sh                     # metadata consistency only (FATAL)
#   verify-provenance.sh --rebuilt <binary>  # + source->binary reproduction (ADVISORY)
#
# Run from the repository root.
#
# Metadata consistency (always, FATAL): the committed vendored binary's SHA-256 + size
# must equal the values recorded in PayloadBinaries.cs and THIRD_PARTY.md. Deterministic,
# needs no build — catches the common "binary or metadata updated without the other".
#
# Source->binary reproduction (with --rebuilt, ADVISORY): the freshly cross-compiled
# binary SHOULD equal the committed one. A mismatch is reported as a warning, NOT a
# failure, because the ring C/asm cross-gcc is not yet pinned (a distro gcc update can
# change the object code and thus the SHA). Enforcing this fatally requires a hermetic,
# digest-pinned build environment — tracked in issue #76.
set -euo pipefail

usage() { echo "usage: verify-provenance.sh [--rebuilt <binary>]" >&2; exit 2; }

# Accept exactly nothing, or exactly `--rebuilt <binary>` with a non-empty path.
# Validating the total argument count (not just $1) rejects a bare `--rebuilt` with no
# path, an unknown first flag, and any trailing/extra arguments; requiring a non-empty
# $2 also rejects `--rebuilt ""` (e.g. an unset `$BIN` passed as "$BIN"), which would
# otherwise be accepted and then silently skip the reproduction check via `[ -n "$REBUILT" ]`.
REBUILT=""
case "$#" in
  0) ;;
  2) { [ "$1" = "--rebuilt" ] && [ -n "$2" ]; } || usage
     REBUILT="$2" ;;
  *) usage ;;
esac

VENDORED="IntercomFirmwareTool.Core/Payload/vendor/armhf/btmqttd"
CS="IntercomFirmwareTool.Core/Payload/PayloadBinaries.cs"
MD="IntercomFirmwareTool.Core/Payload/vendor/THIRD_PARTY.md"

fail() { echo "::error::btmqttd provenance: $*" >&2; exit 1; }
warn() { echo "::warning::btmqttd provenance: $*" >&2; }

for f in "$VENDORED" "$CS" "$MD"; do
  [ -f "$f" ] || fail "missing file: $f"
done

sha()  { sha256sum "$1" | cut -d' ' -f1; }
size() { stat -c%s "$1"; }

vend_sha="$(sha "$VENDORED")"; vend_size="$(size "$VENDORED")"

# Extract the recorded size/SHA. First isolate the btmqttd record in each file with
# awk, THEN grep within that block — so a second record added *before* btmqttd (a future
# ArmBinary, or another provenance table) can't shadow the value grep would otherwise take
# from the first match anywhere in the file. grep -m1 (first match) rather than `| head -1`
# avoids a pipeline that could SIGPIPE-fail grep under pipefail. Each extraction has an
# explicit `|| fail` so a missing record or a changed format produces an actionable error,
# not a bare non-zero exit. The SHA patterns require exactly 64 hex digits immediately
# followed by the closing delimiter (`"` / backtick): an unanchored `[0-9a-fA-F]+` would
# silently take the valid hex PREFIX of a suffixed digest (e.g. a stray trailing space in
# the recorded value), passing this check while `PayloadBinaries.Read` later compares the
# full suffixed string byte-for-byte and rejects the binary at load. Anchoring makes this
# gate reject the malformed record here instead.
#
# PayloadBinaries.cs — the `Btmqttd = new( ... );` block:  `Length: 1_383_056,`  /
# `Sha256Hex: "e324...",`
cs_block="$(awk '/Btmqttd = new\(/{f=1} f{print} f && /\);/{exit}' "$CS")"
cs_size="$(printf '%s\n' "$cs_block" | grep -m1 -oP 'Length:\s*\K[0-9_]+' | tr -d '_')" \
  || fail "could not extract 'Length' from the btmqttd record in $CS (format changed?)"
cs_sha="$(printf '%s\n' "$cs_block" | grep -m1 -oP 'Sha256Hex:\s*"\K[0-9a-fA-F]{64}(?=")')" \
  || fail "could not extract a 64-hex 'Sha256Hex' from the btmqttd record in $CS (format changed?)"
# THIRD_PARTY.md — the provenance table headed `| Field | \`btmqttd\` |`, read to the
# blank line that ends it:  `| Size | 1,383,056 bytes |`  /  `| SHA-256 | ` + backtick hex
md_block="$(awk '/^\|[[:space:]]*Field[[:space:]]*\|[[:space:]]*`btmqttd`/{f=1} f{if($0 ~ /^[[:space:]]*$/) exit; print}' "$MD")"
md_size="$(printf '%s\n' "$md_block" | grep -m1 -oP '\|\s*Size\s*\|\s*\K[0-9,]+' | tr -d ',')" \
  || fail "could not extract 'Size' from the btmqttd record in $MD (format changed?)"
md_sha="$(printf '%s\n' "$md_block" | grep -m1 -oP '\|\s*SHA-256\s*\|\s*`\K[0-9a-fA-F]{64}(?=`)')" \
  || fail "could not extract a 64-hex 'SHA-256' from the btmqttd record in $MD (format changed?)"

printf 'committed bin  : size=%s sha=%s\n' "$vend_size" "$vend_sha"
printf 'PayloadBinaries: size=%s sha=%s\n' "$cs_size" "$cs_sha"
printf 'THIRD_PARTY.md : size=%s sha=%s\n' "$md_size" "$md_sha"

# --- Metadata consistency (FATAL, deterministic) ---
[ "$vend_size" = "$cs_size" ] || fail "committed size $vend_size != PayloadBinaries Length $cs_size"
[ "$vend_sha"  = "$cs_sha"  ] || fail "committed SHA $vend_sha != PayloadBinaries Sha256Hex $cs_sha"
[ "$vend_size" = "$md_size" ] || fail "committed size $vend_size != THIRD_PARTY Size $md_size"
[ "$vend_sha"  = "$md_sha"  ] || fail "committed SHA $vend_sha != THIRD_PARTY SHA-256 $md_sha"
echo "OK: committed binary matches PayloadBinaries + THIRD_PARTY ($vend_sha)."

# --- Source -> binary reproduction (ADVISORY until the build is hermetic, #76) ---
if [ -n "$REBUILT" ]; then
  [ -f "$REBUILT" ] || fail "rebuilt binary not found: $REBUILT"
  r_sha="$(sha "$REBUILT")"; r_size="$(size "$REBUILT")"
  printf 'rebuilt binary : size=%s sha=%s\n' "$r_size" "$r_sha"
  if [ "$r_sha" = "$vend_sha" ] && [ "$r_size" = "$vend_size" ]; then
    echo "OK: rebuilt binary reproduces the committed binary bit-for-bit."
  else
    warn "rebuilt binary ($r_sha) does NOT match the committed binary ($vend_sha). \
Expected when the ring cross-gcc differs from the build host's (the environment is not \
yet hermetic, #76). If native/btmqttd source changed, rebuild + re-sync the vendored \
binary per BUILD.md. Advisory — not failing the job."
  fi
fi
