#!/bin/sh
# Single source of truth for the minimal, LGPL, static-musl armv7 ffmpeg build recipe
# (issue #120). Both workflows call THIS script, so their recipes can never drift:
#   - .github/workflows/ffmpeg-build.yml       — produces the committed binary (dispatch-only)
#   - .github/workflows/ffmpeg-provenance.yml  — independently rebuilds + byte-compares
# A change here is a change under native/ffmpeg/**, which triggers the provenance workflow;
# it then rebuilds with the new recipe and byte-compares to the committed binary, so a recipe
# change that would alter the bytes fails until the binary is refreshed. See BUILD.md.
#
# Usage: build.sh <extracted-ffmpeg-source-dir>
#   - `zig` must be on PATH (the caller installs the pinned, SHA-256-verified zig).
#   - The source dir MUST be OUTSIDE any git worktree: FFmpeg's ffbuild/version.sh runs
#     `git describe`, and inside a repo checkout it would stamp that repo's commit hash as
#     the ffmpeg version (breaking byte-reproducibility). Callers extract under $RUNNER_TEMP.
#   - Builds in place; output is <dir>/ffmpeg (static armv7 musl, stripped).
set -eu

src="${1:?usage: build.sh <extracted-ffmpeg-source-dir>}"
cd "$src" || exit 1

# --extra-cflags is just -Os: no -ffile-prefix-map, whose value would embed the absolute
# build path into FFmpeg's `configuration:` string and break byte-reproducibility. We strip
# (-s) + --disable-debug, so no DWARF comp_dir survives, and FFmpeg compiles with relative
# __FILE__ paths — the output is path-independent. --nm=nm is host binutils nm (zig has no
# `nm` subcommand). LGPL only: never --enable-gpl/--enable-nonfree.
./configure \
  --cc="zig cc -target arm-linux-musleabihf -mcpu=generic+v7a+vfp3d16" \
  --ar="zig ar" --ranlib="zig ranlib" --nm="nm" --host-cc=cc \
  --enable-cross-compile --arch=arm --target-os=linux --pkg-config=false \
  --disable-everything --disable-autodetect --disable-doc --disable-debug \
  --disable-shared --enable-static --enable-small \
  --disable-programs --enable-ffmpeg --disable-asm --disable-stripping \
  --enable-protocol=file,udp,rtp,rtsp,tcp \
  --enable-demuxer=sdp,rtsp,rtp --enable-muxer=rtsp,rtp \
  --extra-cflags="-Os" --extra-ldflags="-static -s"

# -j1 (serial): FFmpeg's parallel build is not byte-reproducible across runs (object/archive
# ordering follows parallel completion order); the serial build is deterministic.
make -j1
