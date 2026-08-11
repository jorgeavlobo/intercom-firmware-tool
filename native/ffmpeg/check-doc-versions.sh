#!/bin/sh
# Single source of truth for the "docs match the pinned versions" guard (issue #120).
# Both workflows call THIS script so the check can't drift:
#   - .github/workflows/ffmpeg-build.yml       — fails the refresh BEFORE committing if a
#     pins.env bump forgot to update the human-facing version strings.
#   - .github/workflows/ffmpeg-provenance.yml  — same check on every PR/push, as a backstop
#     for a hand-edit that drifts pins.env from the notices.
#
# Why this exists: bumping FFMPEG_TAG / ZIG_VERSION in pins.env only re-derives the binary's
# size + SHA-256 (build/provenance handle those). The upstream *version* is ALSO written, in
# prose, into several notices and the project metadata. If those aren't updated in lockstep
# the commit identifies the wrong upstream release and — load-bearing for LGPL — points
# recipients at the wrong "corresponding source" tag, even though every automated check still
# passes.
#
# This guard is EXHAUSTIVE, not presence-only: it requires (1) the pinned version to appear in
# each version-bearing file, and (2) EVERY structured version token in those files to equal the
# pin — so a partial bump that updates one occurrence but leaves another stale (e.g. the
# displayed version updated but a `/tree/n7.1.1` corresponding-source URL left behind — Codex)
# still fails.
#
# Requires FFMPEG_TAG and ZIG_VERSION in the environment (the caller loads them from pins.env).
set -eu

: "${FFMPEG_TAG:?check-doc-versions.sh: FFMPEG_TAG not set (load native/ffmpeg/pins.env first)}"
: "${ZIG_VERSION:?check-doc-versions.sh: ZIG_VERSION not set (load native/ffmpeg/pins.env first)}"

# Run from the repo root so the paths below resolve.
root="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel 2>/dev/null || echo .)}"
cd "$root"

# The FFmpeg tag is named in every notice + the project metadata that tells an LGPL recipient
# which upstream source to fetch. The Zig toolchain version is a build input, documented only
# in the build docs.
FF_FILES='native/ffmpeg/BUILD.md
THIRD-PARTY-NOTICES.md
IntercomFirmwareTool.Core/Payload/vendor/THIRD_PARTY.md
IntercomFirmwareTool.Core/Payload/PayloadBinaries.cs
IntercomFirmwareTool.Core/IntercomFirmwareTool.Core.csproj'
ZIG_FILES='native/ffmpeg/BUILD.md
IntercomFirmwareTool.Core/Payload/vendor/THIRD_PARTY.md'

fail=0

# (1) Presence — the pinned version must appear at all (an all-tokens-match check alone would
#     pass vacuously on a file that dropped every reference).
for f in $FF_FILES; do
  grep -Fq "$FFMPEG_TAG" "$f" || { echo "::error file=$f::does not mention pinned FFmpeg tag '$FFMPEG_TAG'" >&2; fail=1; }
done
for f in $ZIG_FILES; do
  grep -Fq "$ZIG_VERSION" "$f" || { echo "::error file=$f::does not mention pinned Zig version '$ZIG_VERSION'" >&2; fail=1; }
done

# (2) No stale occurrence — every FFmpeg-tag reference must EXACTLY equal the pin.
# (2a) Tag tokens: capture the MAXIMAL numeric version — greedy `n<maj>.<min>[.<patch>...]`, with
# PCRE look-arounds (grep -oP, present on the ubuntu CI runners) so the token is neither a
# substring of a larger alnum token nor a truncated prefix of a longer numeric tag. A four-part
# n7.1.1.1 is thus captured whole (not as n7.1.1) and fails; the tag embedded in an asset name
# like `ffmpeg-n7.1.1-source.tar.gz` is captured as n7.1.1 and validated. No series-prefix
# exemption — a shorter series such as n7.1 identifies a DIFFERENT release (Codex). The docs carry
# no bare `n7.1`-style series token: BUILD.md's minimal-build note says "FFmpeg 7.1" (no `n`).
for f in $FF_FILES; do
  for tok in $(grep -oP '(?<![0-9A-Za-z])n[0-9]+(\.[0-9]+)+(?![0-9A-Za-z])' "$f" 2>/dev/null || true); do
    [ "$tok" = "$FFMPEG_TAG" ] || { echo "::error file=$f::stale FFmpeg tag '$tok' (pinned '$FFMPEG_TAG') — every FFmpeg-tag reference must be EXACTLY the pinned tag" >&2; fail=1; }
  done
done
# (2b) Corresponding-source ASSET NAMES must be complete, exact values — so a hyphen-suffixed
# variant like `ffmpeg-n7.1.1-old-source.tar.gz` (whose numeric token still reads n7.1.1 in 2a)
# can't misidentify the shipped source. The only valid names are the source + build-recipe
# archives release.yml ships for the pinned tag (Codex).
for f in $FF_FILES; do
  for asset in $(grep -oE 'ffmpeg-n[0-9A-Za-z.-]+\.tar\.gz' "$f" 2>/dev/null || true); do
    case "$asset" in
      "ffmpeg-${FFMPEG_TAG}-source.tar.gz"|"ffmpeg-${FFMPEG_TAG}-build-recipe.tar.gz") : ;;
      *) echo "::error file=$f::stale FFmpeg source-asset name '$asset' (expected ffmpeg-${FFMPEG_TAG}-source.tar.gz or ffmpeg-${FFMPEG_TAG}-build-recipe.tar.gz)" >&2; fail=1 ;;
    esac
  done
done

# Zig's version is a bare semver whose shape collides with unrelated versions (rustc, cross-gcc,
# kernel, NuGet packages), so only validate a semver that sits in a zig context: the first
# semver after "zig" (grep is line-scoped, and [^0-9] stops at that first digit run, so this
# captures the version belonging to the zig mention) or after an "x86_64-" download-name prefix.
# The separator allowance is generous (up to 24 non-digit chars) so documented phrasings like
# "Zig version X.Y.Z" / "Zig toolchain version X.Y.Z" — not just "Zig X.Y.Z" / "zig cc X.Y.Z" —
# are validated too (CodeRabbit).
for f in $ZIG_FILES; do
  for tok in $(grep -oiE '(zig[^0-9]{0,24}|x86_64-)[0-9]+\.[0-9]+\.[0-9]+' "$f" 2>/dev/null \
                 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true); do
    [ "$tok" = "$ZIG_VERSION" ] || { echo "::error file=$f::stale Zig version '$tok' (pinned '$ZIG_VERSION')" >&2; fail=1; }
  done
done

if [ "$fail" -ne 0 ]; then
  echo "check-doc-versions.sh: version-bearing docs are out of sync with native/ffmpeg/pins.env (FFmpeg $FFMPEG_TAG, Zig $ZIG_VERSION); see BUILD.md 'Refreshing the binary'." >&2
  exit 1
fi
echo "check-doc-versions.sh: all version references match pins (FFmpeg $FFMPEG_TAG, Zig $ZIG_VERSION)."
