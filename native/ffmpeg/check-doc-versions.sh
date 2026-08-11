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
# passes. This guard fails loudly until each version-bearing file mentions the pinned version.
#
# Requires FFMPEG_TAG and ZIG_VERSION in the environment (the caller loads them from pins.env).
set -eu

: "${FFMPEG_TAG:?check-doc-versions.sh: FFMPEG_TAG not set (load native/ffmpeg/pins.env first)}"
: "${ZIG_VERSION:?check-doc-versions.sh: ZIG_VERSION not set (load native/ffmpeg/pins.env first)}"

# Run from the repo root so the paths below resolve.
root="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel 2>/dev/null || echo .)}"
cd "$root"

fail=0
need() {  # need <file> <literal-version-string>
  if ! grep -Fq "$2" "$1"; then
    echo "::error file=$1::'$1' does not mention '$2' — pins.env drifted from the version-bearing docs; update it (see native/ffmpeg/BUILD.md, 'Refreshing the binary')." >&2
    fail=1
  fi
}

# The FFmpeg tag (e.g. n7.1.1) is named in every notice + the project metadata that tells an
# LGPL recipient which upstream source to fetch.
for f in \
  native/ffmpeg/BUILD.md \
  THIRD-PARTY-NOTICES.md \
  IntercomFirmwareTool.Core/Payload/vendor/THIRD_PARTY.md \
  IntercomFirmwareTool.Core/Payload/PayloadBinaries.cs \
  IntercomFirmwareTool.Core/IntercomFirmwareTool.Core.csproj
do
  need "$f" "$FFMPEG_TAG"
done

# The Zig toolchain version is documented only in the build docs (it's a build input, not a
# shipped-component version), so check just those.
for f in \
  native/ffmpeg/BUILD.md \
  IntercomFirmwareTool.Core/Payload/vendor/THIRD_PARTY.md
do
  need "$f" "$ZIG_VERSION"
done

if [ "$fail" -ne 0 ]; then
  echo "check-doc-versions.sh: version-bearing docs are out of sync with native/ffmpeg/pins.env (FFmpeg $FFMPEG_TAG, Zig $ZIG_VERSION)." >&2
  exit 1
fi
echo "check-doc-versions.sh: docs match pins (FFmpeg $FFMPEG_TAG, Zig $ZIG_VERSION)."
