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

# ENFORCE the no-git-ancestor precondition (not just document it): a source tree inside a
# git worktree makes FFmpeg's ffbuild/version.sh stamp that repo's commit hash as the ffmpeg
# version, silently breaking byte-reproducibility. Fail fast instead.
if git -C "$src" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "build.sh: '$src' is inside a git worktree — extract the source to a scratch dir with no .git ancestor (CI uses \$RUNNER_TEMP)" >&2
  exit 1
fi

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
  --enable-protocol=file,udp,rtp,tcp \
  --enable-demuxer=sdp,rtsp,rtp --enable-muxer=rtsp,rtp \
  --enable-parser=h264 --enable-parser=hevc \
  --enable-decoder=h264 \
  --extra-cflags="-Os" --extra-ldflags="-static -s"
# --enable-decoder=h264: needed so `-c:v copy` resolves the video dimensions FAST. The C100X test
# (issue #120) proved the panel emits an in-stream SPS/PPS only ~every 20 s, so with the parser
# ALONE ffmpeg blocks ~20-30 s per cold open before it catches one ("Could not find codec
# parameters"). btmqttd learns the panel's parameter sets and puts them in the SDP's
# sprop-parameter-sets (extradata), but ffmpeg's find_stream_info reads the SPS out of extradata
# only by OPENING THE DECODER (the parser reads in-stream data only). So with the parser but no
# decoder the sprop is ignored and it still waits ~20-30 s; WITH the decoder, find_stream_info parses
# the sprop SPS at open and resolves 640x480 in <1 s. `-c:v copy` still never decodes a frame at
# runtime — the decoder is used only for that one-time parameter-set read — so the resident CPU cost
# is unchanged. The H.264 DECODER is LGPL (only the x264 ENCODER is GPL; not enabled). It pulls
# h264_sei.o (film-grain SEI) exactly as the parser did, so the HEVC-parser link dependency below
# still applies.
# --enable-parser=h264: the C100X hardware test (issue #120) proved `-c:v copy` DOES need
# in-stream parameter-set extraction after all. The panel's SDP carries no sprop-parameter-sets,
# so without the H.264 parser ffmpeg never extracts the SPS: it logs `parser not found for codec
# h264`, the stream's dimensions stay unset, and the rtsp/rtp muxer aborts with `dimensions not
# set` / `Could not write header` — go2rtc then serves nothing (RTSP 404). The parser fixes it
# (and the invalid-timestamp `dropping old packet received too late` flood it also caused). This
# is exactly the contingency BUILD.md documented as "deferred until the C100X test proves it
# necessary" — the test proved it.
# --enable-parser=hevc: a LINK-ONLY dependency, never invoked (we only ever feed H.264). Enabling
# the H.264 parser pulls h2645_sei.o (via CONFIG_H264_SEI), whose ff_h2645_sei_reset references
# ff_aom_uninit_film_grain_params. That symbol lives in aom_film_grain.o, which n7.1.1's
# libavcodec/Makefile compiles ONLY under CONFIG_HEVC_SEI / CONFIG_HEVC_DECODER — NOT under any
# AV1 target (so `--enable-decoder=av1` does NOT resolve it; the build still fails `ld.lld:
# undefined symbol`). The lightest lever that pulls CONFIG_HEVC_SEI is the HEVC *parser*
# (hevc_parser_select="hevcparse hevc_sei"; hevc_sei_select="atsc_a53 golomb" — no decoder, no
# dovi). All are LGPL FFmpeg components (no --enable-gpl/-nonfree).
# NB: bitstream filters are deliberately NOT enabled. A C100X test bench briefly added
# `--enable-bsf=extract_extradata,dump_extra` to force the SPS/PPS into go2rtc's announce, but
# hardware testing (issue #120) proved they were unnecessary: the H.264 parser already carries the
# parameter sets into the announce SDP, and `-c:v copy` publishes fine with plain default input
# options. (It also only half-worked — FFmpeg's `--enable-bsf=` took only the first name, leaving
# `dump_extra` out — another reason not to rely on it.) The real on-device fix was to DROP the
# oversized RTP reorder buffer in Go2RtcConfig's exec (loopback never reorders, so it stalled and
# dropped every packet as "received too late"); see IntercomFirmwareTool.Core/Go2RtcConfig.cs.
# NB: `rtsp` is deliberately NOT in --enable-protocol — FFmpeg has no `rtsp` URL protocol
# (RTSP is the demuxer/muxer enabled just above; it runs over tcp/udp/rtp, which ARE listed).
# `--enable-protocol=rtsp` matched nothing and only added a configure warning (CodeRabbit).

# -j1 (serial): FFmpeg's parallel build is not byte-reproducible across runs (object/archive
# ordering follows parallel completion order); the serial build is deterministic.
make -j1
