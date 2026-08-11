# Building the minimal `ffmpeg` for the on-device media server

This is the **minimal, LGPL, statically-linked armv7 `ffmpeg`** the on-device camera
path (issue #120, Phase 1) feeds to `go2rtc`: it reads the panel's cleartext RTP via an
SDP and **copies the H.264 through untouched** into `go2rtc`'s internal RTSP — no
decode, no encode, no transcode. In Phase 1a it is only **embedded into the
`IntercomFirmwareTool.Core` assembly** as a resource via `PayloadBinaries` (length +
SHA-256 verified on read), the same way as `btmqttd` (see
[`../btmqttd/BUILD.md`](../btmqttd/BUILD.md)); it is deliberately **not** in
`PayloadBinaries.All` yet, so `MqttInstaller` does not write it into the firmware image
until the installer wiring lands in Phase 1c.

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
version:

- Zig **bundles musl** headers + start files and links a fully static musl target from
  one self-contained download — no distro cross-toolchain whose package bumps silently
  change object code (the exact drift `btmqttd`'s provenance job guards against), and no
  reliance on `musl.cc` (blocked on some networks).
- **Byte-reproducible.** With one pinned `zig` and one pinned FFmpeg source, and with **no
  absolute build path leaking into the output** (we do *not* pass `-ffile-prefix-map`,
  whose value would embed `$(pwd)` into FFmpeg's `configuration:` string; we strip (`-s`)
  and `--disable-debug`, so no DWARF `comp_dir` survives, and FFmpeg compiles with relative
  `__FILE__` paths), two independent builds are **byte-identical**. So the committed binary
  is verified **byte-for-byte** by `ffmpeg-provenance.yml` — the same guarantee as the
  first-party `btmqttd`, not a weaker functional check.

Pinned versions (bump deliberately; CI enforces the SHA-256 against these):

| Input | Pin | SHA-256 |
|---|---|---|
| Zig | `0.13.0` (`zig-linux-x86_64-0.13.0.tar.xz`) | `d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea` |
| FFmpeg | `n7.1.1` (GitHub source archive `n7.1.1.tar.gz`) | `f117507dc501f2a6c11f9241d8d0c3213846cfad91764361af37befd6b6c523d` |

Both `ffmpeg-build.yml` and `ffmpeg-provenance.yml` download each input and fail the job
unless its SHA-256 matches the pin above (`ZIG_SHA256` / `FFMPEG_TARBALL_SHA256` in the
workflow `env`), so a rotated or tampered download can never feed the build.

## Build recipe

> **The recipe is [`build.sh`](build.sh) — a single source of truth.** Both
> `.github/workflows/ffmpeg-build.yml` (produces the committed binary) and
> `.github/workflows/ffmpeg-provenance.yml` (independently rebuilds + byte-compares) invoke
> the **same** `native/ffmpeg/build.sh`, so their recipes can never drift. Do not duplicate
> the `./configure`/`make` flags elsewhere — edit `build.sh`. A change to it lives under
> `native/ffmpeg/**`, which is in the provenance path filter, so provenance rebuilds and
> byte-compares to the committed binary, failing if the change would alter the bytes.

> **Build outside any git repository.** FFmpeg's `ffbuild/version.sh` runs `git describe`;
> if the source tree sits inside another repo's worktree, git walks up and stamps *that*
> repo's commit hash as the ffmpeg version (`ffmpeg version <hash>`), which changes every
> commit and destroys reproducibility. `build.sh` therefore requires the source dir to have
> no `.git` ancestor (CI extracts under `$RUNNER_TEMP`); then the version is deterministic.

```sh
# Inputs (pinned): Zig 0.13.0, FFmpeg n7.1.1 (both SHA-256-verified by the workflows).
# `zig` must be on PATH. Extract the pinned source into a scratch dir OUTSIDE any git
# worktree, then run the shared recipe against it:
sh native/ffmpeg/build.sh "$SRC_DIR"
# Output: "$SRC_DIR/ffmpeg"  (static armv7 musl, stripped, byte-reproducible)
```

`build.sh` runs FFmpeg's `./configure` with `--disable-everything` plus only the
RTP/SDP→RTSP H.264-copy path, LGPL-only (never `--enable-gpl`/`--enable-nonfree`),
`--disable-asm`, `--extra-cflags="-Os"` (no `-ffile-prefix-map`), `--extra-ldflags="-static -s"`,
and `make -j1` (serial — parallel is not byte-reproducible). See the script for the exact,
authoritative flags.

Notes:
- **`--extra-cflags="-Os"` only** — deliberately no `-ffile-prefix-map=$(pwd)=.`. That flag's
  *value* is echoed verbatim into FFmpeg's `configuration:` string, which would embed the
  absolute build path and make the binary differ by build directory (breaking
  reproducibility and any path-length-sensitive check). Because we strip and disable debug
  info, no DWARF `comp_dir` remains, and FFmpeg's sources compile with relative `__FILE__`
  paths, so dropping the prefix-map costs nothing and buys byte-reproducibility.
- **`--nm="nm"`** — the host binutils `nm` (architecture-agnostic symbol lister; reads the
  cross ARM objects fine). Note **`zig` has no `nm` subcommand**, so `--nm="zig nm"` prints
  `error: unknown command: nm` and silently defeats configure's nm-based probes.
- **`--disable-asm`** — we only demux/copy/mux (no codec math), so ARM asm buys nothing
  and would add a nasm/asm-reproducibility variable. Disabling it keeps the build
  portable and deterministic across hosts.
- **`--disable-stripping`** — FFmpeg's post-link `strip` uses the *host* `strip`, which
  can't read the cross-built ARM ELF (`Unable to recognise the format`). We strip at link
  time instead via `--extra-ldflags=-s`, which is deterministic and needs no target strip.
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
  load-bearing; do not add GPL libs. CI asserts the config shows LGPL.

## Verify

```sh
# Executes on the armv7 target (not just links): print version + confirm 'configuration'
# has neither --enable-gpl nor --enable-nonfree.
qemu-arm-static ./ffmpeg -hide_banner -version | sed -n '1,4p'

# Record for PayloadBinaries.cs + THIRD_PARTY.md
sha256sum ./ffmpeg; stat -c '%s bytes' ./ffmpeg
```

The SHA-256 + byte size go into `IntercomFirmwareTool.Core/Payload/PayloadBinaries.cs`
and `IntercomFirmwareTool.Core/Payload/vendor/THIRD_PARTY.md`, and the vendored binary
lives at `IntercomFirmwareTool.Core/Payload/vendor/armhf/ffmpeg` — enforced on load (length
+ SHA-256) and guarded by `ffmpeg-provenance.yml`, which enforces **byte-for-byte**
provenance (metadata integrity + a fresh build whose SHA-256 must equal the committed
binary's, runs under qemu, and is LGPL) — the same reproducible guarantee used for the
first-party `btmqttd`.

## Refreshing the binary

Two kinds of change, edited in different places:

- **Recipe** (`./configure`/`make` flags): edit **only** [`build.sh`](build.sh) — the single
  source of truth both workflows invoke. Do not touch the workflows for a recipe change.
- **Input pins** (Zig / FFmpeg versions + their SHA-256s): update the `env:` blocks in
  **both** `ffmpeg-build.yml` and `ffmpeg-provenance.yml`, and the pinned-versions table in
  this document.

Then run the dispatch-only
[`ffmpeg-build.yml`](../../.github/workflows/ffmpeg-build.yml): it rebuilds from the pinned
source (via `build.sh`), commits the new binary + license texts, and updates the SHA-256 +
size in `PayloadBinaries.cs` and `THIRD_PARTY.md` atomically. `ffmpeg-provenance.yml` then
proves, byte-for-byte, that the committed binary matches the pinned source.

## Cannot be built in the sandboxed dev container

The agent dev container has no musl/armv7 cross-toolchain and the egress proxy blocks
`ffmpeg.org` / `ziglang.org` / the GitHub source archive, so the binary is produced by
**CI** (GitHub Actions has network + installs the pinned Zig). The committed binary is then
verified byte-for-byte by the provenance workflow on every PR that touches it.
