# Building the minimal `ffmpeg` for the on-device media server

This is the **minimal, LGPL, statically-linked armv7 `ffmpeg`** the on-device camera
path (issue #120, Phase 1) feeds to `go2rtc`: it reads the panel's cleartext RTP via an
SDP and **copies the H.264 through untouched** into `go2rtc`'s internal RTSP — no
decode, no encode, no transcode. It is embedded into the firmware image by
`MqttInstaller` via `PayloadBinaries` (length + SHA-256 verified on read), the same way
as `btmqttd` (see [`../btmqttd/BUILD.md`](../btmqttd/BUILD.md)).

Video-only in Phase 1. The speex→Opus audio path (and the #105 backchannel) come in
Phase 3 and will add `libspeex`-decode + `libopus`-encode to this same recipe.

## Why a custom build (not the generic static ffmpeg)

The spike used John Van Sickle's generic static ffmpeg — but that is a **GPL** build
(~31 MB), and shipping GPL in the firmware image carries source-offer obligations. This
build is:

- **LGPL only** — never `--enable-gpl`, never `--enable-nonfree`, no GPL-only libraries
  (no x264/x265/…). Only the LGPL core + LGPL externals (later: `libopus`).
- **Minimal** — `--disable-everything` plus exactly the RTP/SDP→RTSP H.264-copy path, so
  the binary is a few MB, not 31, with a tiny attack surface.

## Target

Identical to `btmqttd` — a **32-bit ARM EABI5, armv7 hard-float, static-musl** binary
that runs on the C100X/C300X (i.MX, kernel 4.9.11) with no dependency on the device libc.

| Property | Value |
|---|---|
| Triple | `arm-linux-musleabihf` (armv7-a, VFPv3-D16, hard-float) |
| libc | musl, **statically linked** |
| Device | BTicino Classe 100X / 300X (i.MX) |

## Toolchain — `zig cc` (pinned)

We cross-compile with **`zig cc`** as the C compiler/linker, pinned to a single Zig
version. Rationale, mirroring the `btmqttd` philosophy of pinning one compiler for a
host-independent SHA-256:

- Zig **bundles musl** headers + start files and links a fully static musl target from
  one self-contained download — no distro cross-toolchain whose package bumps silently
  change object code (the exact drift `btmqttd`'s provenance job guards against), and no
  reliance on `musl.cc` (blocked on some networks).
- One pinned `zig` + one pinned FFmpeg tarball + deterministic flags ⇒ a reproducible
  binary, verified byte-for-byte by CI (`.github/workflows/ffmpeg-provenance.yml`).

Pinned versions (bump deliberately; CI enforces the SHA against these):

| Input | Pin |
|---|---|
| Zig | `0.13.0` |
| FFmpeg | `n7.1.1` (release tarball) |

## Reproducible build

> The `configure` line below is the **intended** minimal recipe; the CI provenance job
> is the source of truth and the flag set is refined there on the first green build
> (FFmpeg's `configure` prunes unreachable components, so a missing dependency surfaces
> as a configure error, not a silent feature). Keep this file in sync with the workflow.

```sh
# Inputs (pinned)
ZIG=0.13.0
FFMPEG=n7.1.1

# Deterministic: fixed epoch + scrub the build path from any embedded strings.
export SOURCE_DATE_EPOCH=1700000000
CFLAGS="-Os -ffile-prefix-map=$(pwd)=. -fdebug-prefix-map=$(pwd)=."

./configure \
  --cc="zig cc -target arm-linux-musleabihf -mcpu=generic+v7a+vfp3d16" \
  --ar="zig ar" --ranlib="zig ranlib" --nm="zig nm" \
  --enable-cross-compile --arch=arm --target-os=linux \
  --pkg-config=false \
  --disable-everything \
  --disable-autodetect --disable-doc --disable-debug \
  --disable-shared --enable-static --enable-small \
  --disable-programs --enable-ffmpeg \
  --disable-asm \
  --enable-protocol=file,udp,rtp,rtsp,tcp \
  --enable-demuxer=sdp,rtsp,rtp \
  --enable-muxer=rtsp,rtp \
  --extra-cflags="$CFLAGS" \
  --extra-ldflags="-static -s"

make -j"$(nproc)"
# Output: ./ffmpeg  (statically linked, stripped)
```

Notes:
- **`--disable-asm`** — we only demux/copy/mux (no codec math), so ARM asm buys nothing
  and would add a nasm/asm-reproducibility variable. Disabling it keeps the build
  portable and deterministic across hosts.
- **No codec components at all** (no decoders, encoders, or parsers). `-c:v copy` never
  touches the pixels: the `sdp`/`rtp` demuxer + its H.264 RTP depayloader (libavformat)
  reconstruct the access units, and the `rtsp`/`rtp` muxer repackets them — no libavcodec
  parser/decoder needed. This also **sidesteps a known n7.1 minimal-build link failure**:
  enabling the H.264 parser (or decoder) pulls `h2645_sei.o`, whose `ff_h2645_sei_reset`
  references `ff_aom_uninit_film_grain_params` — a symbol only compiled with an AV1
  decoder — giving `ld.lld: undefined symbol` in an otherwise codec-free build.
  > If the on-device hardware test shows `-c:v copy` needs in-stream parameter-set
  > extraction (extradata), add `--enable-parser=h264` **and** resolve the film-grain
  > symbol by enabling a decoder that provides it (e.g. `--enable-decoder=av1`), then
  > re-measure size. Deferred until the C100X test proves it necessary.
- **LGPL guard** — the absence of `--enable-gpl`/`--enable-nonfree` is deliberate and
  load-bearing; do not add GPL libs. CI asserts `ffmpeg -L` / the config shows LGPL.

## Verify

```sh
# Executes on the armv7 target (not just links): print version + confirm 'configuration'
# has neither --enable-gpl nor --enable-nonfree, and the license is LGPL.
qemu-arm-static ./ffmpeg -hide_banner -version | sed -n '1,4p'

# Record for PayloadBinaries.cs + THIRD_PARTY.md
sha256sum ./ffmpeg; stat -c '%s bytes' ./ffmpeg
```

The SHA-256 + byte size go into `IntercomFirmwareTool.Core/Payload/PayloadBinaries.cs`
and `IntercomFirmwareTool.Core/Payload/vendor/THIRD_PARTY.md`, and the vendored binary
lives at `IntercomFirmwareTool.Core/Payload/vendor/armhf/ffmpeg` — enforced on load and
guarded against drift by `ffmpeg-provenance.yml` (rebuild → byte-for-byte match), exactly
like `btmqttd`.

## Cannot be built in the sandboxed dev container

The agent dev container has no musl/armv7 cross-toolchain and the egress proxy blocks
`ffmpeg.org` / `ziglang.org`, so the binary is produced by **CI** (GitHub Actions has
network + installs the pinned Zig) or on a capable host with this recipe. The committed
binary is then verified reproducibly by the provenance workflow.
