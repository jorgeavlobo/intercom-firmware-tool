#!/usr/bin/env bash
# Verify btmqttd ARM binary provenance (issue #72).
#
# Given a freshly cross-compiled binary, assert it matches BOTH the committed
# vendored binary and the recorded metadata (length + SHA-256) in PayloadBinaries.cs
# and THIRD_PARTY.md. Catches two kinds of drift:
#   1. metadata drift  — the vendored binary and its recorded size/SHA disagree.
#   2. source drift     — the committed binary no longer matches native/btmqttd source.
#
# Run from the repository root:
#   native/btmqttd/ci/verify-provenance.sh <freshly-built-binary>
set -euo pipefail

FRESH="${1:?usage: verify-provenance.sh <freshly-built-binary>}"
VENDORED="IntercomFirmwareTool.Core/Payload/vendor/armhf/btmqttd"
CS="IntercomFirmwareTool.Core/Payload/PayloadBinaries.cs"
MD="IntercomFirmwareTool.Core/Payload/vendor/THIRD_PARTY.md"

fail() { echo "::error::btmqttd provenance: $*" >&2; exit 1; }

for f in "$FRESH" "$VENDORED" "$CS" "$MD"; do
  [ -f "$f" ] || fail "missing file: $f"
done

sha()  { sha256sum "$1" | cut -d' ' -f1; }
size() { stat -c%s "$1"; }

fresh_sha="$(sha "$FRESH")";   fresh_size="$(size "$FRESH")"
vend_sha="$(sha "$VENDORED")"; vend_size="$(size "$VENDORED")"

# PayloadBinaries.cs — `Length: 1_383_056,`  /  `Sha256Hex: "e324...",`
cs_size="$(grep -oP 'Length:\s*\K[0-9_]+' "$CS" | head -1 | tr -d '_')"
cs_sha="$(grep -oP 'Sha256Hex:\s*"\K[0-9a-fA-F]+' "$CS" | head -1)"

# THIRD_PARTY.md — `| Size | 1,383,056 bytes |`  /  `| SHA-256 | ` + backtick-wrapped hex
md_size="$(grep -oP '\|\s*Size\s*\|\s*\K[0-9,]+' "$MD" | head -1 | tr -d ',')"
md_sha="$(grep -oP '\|\s*SHA-256\s*\|\s*`\K[0-9a-fA-F]+' "$MD" | head -1)"

printf 'fresh build   : size=%s sha=%s\n' "$fresh_size" "$fresh_sha"
printf 'committed bin : size=%s sha=%s\n' "$vend_size"  "$vend_sha"
printf 'PayloadBinaries: size=%s sha=%s\n' "$cs_size" "$cs_sha"
printf 'THIRD_PARTY.md : size=%s sha=%s\n' "$md_size" "$md_sha"

# 1. Metadata consistency (deterministic — no rebuild needed).
[ "$vend_size" = "$cs_size" ] || fail "committed size $vend_size != PayloadBinaries Length $cs_size"
[ "$vend_sha"  = "$cs_sha"  ] || fail "committed SHA $vend_sha != PayloadBinaries Sha256Hex $cs_sha"
[ "$vend_size" = "$md_size" ] || fail "committed size $vend_size != THIRD_PARTY Size $md_size"
[ "$vend_sha"  = "$md_sha"  ] || fail "committed SHA $vend_sha != THIRD_PARTY SHA-256 $md_sha"

# 2. Source -> binary reproduction (pinned toolchain + remapped paths, see BUILD.md).
[ "$fresh_size" = "$vend_size" ] || fail "rebuilt size $fresh_size != committed $vend_size — rebuild the vendored binary and sync metadata (BUILD.md)"
[ "$fresh_sha"  = "$vend_sha"  ] || fail "rebuilt SHA $fresh_sha != committed $vend_sha — the committed binary does not match native/btmqttd source; rebuild + sync (BUILD.md)"

echo "OK: btmqttd binary matches source and all metadata records ($vend_sha)."
