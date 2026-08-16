# Third-party binaries shipped by the MQTT bridge installer

The optional **MQTT bridge** feature (off by default) installs prebuilt ARM
binaries into the firmware image, because they are **not** present in the factory
BTicino C300X/C100X firmware. The bridge itself installs **`btmqttd`**; **`ffmpeg`** and
**`go2rtc`** are embedded for the **on-device camera** (issue #120) and written to the image by
that camera's install, which lands in **Phase 1c-2** (they are embedded now, in 1c-1, but not yet
installed):

| Tool | Installed as | Purpose |
|---|---|---|
| `btmqttd` | `/usr/sbin/btmqttd` (`0775 root:root`) | the single-connection MQTT bridge daemon (issue #32) — OpenWebNet bus monitor → MQTT, MQTT → gateway command dispatch, front-panel keypad → MQTT, Home Assistant discovery, TLS, atomic birth/will availability |
| `ffmpeg` | `/usr/sbin/ffmpeg` (`0775 root:root`) | minimal **LGPL** FFmpeg `n7.1.1` — reads the panel's RTP via an SDP and **copies** the H.264 into RTSP for `go2rtc` (on-device camera, #120); no decode/encode |
| `go2rtc` | `/usr/sbin/go2rtc` (`0775 root:root`) | on-device streaming server (`v1.9.14`, **MIT**) — serves the camera as RTSP to Home Assistant as a native Generic Camera, with no HA-side go2rtc (#120) |

`btmqttd` is **our own program** (its source lives in this repository at
[`native/btmqttd/`](../../../native/btmqttd), built per
[`native/btmqttd/BUILD.md`](../../../native/btmqttd/BUILD.md)). It **replaces the
entire previous shell-orchestrated bridge** — `StartMqttSend`,
`StartMqttReceive`, `keypress.sh`, `filter.py`, `ha_discovery.sh`,
`mqtt_common.sh`, `TcpDump2Mqtt`/`TcpDump2Mqtt.sh` — **and** the two vendored
userland tools those scripts required: **`jq`** (JSON, now done natively with
`serde_json`) and **`evtest`** (keypad, now done natively with the pure-Rust
`evdev` crate). Removing `jq`/`evtest` also removes their copyleft obligations
(`evtest` was GPL-2.0-or-later; the static `jq` bundled LGPL-2.1 glibc): the
**MQTT bridge** (`btmqttd` + its scripts) no longer carries any GPL/LGPL
component. (Separately, this assembly also embeds the **LGPL-2.1** `ffmpeg` and the
**MIT** `go2rtc` for the on-device camera — embedded now, and written to the image by the
gated on-device camera install in Phase 1c-2 (#120); their notices + provenance are
documented in the `ffmpeg` and `go2rtc` sections below.)

`btmqttd` is a **statically-linked musl** binary, so it needs no runtime
interpreter, no shared libraries, and none of the device tools the shell bridge
depended on (`tcpdump`, `python`, `jq`, `nc`, `awk`, `mosquitto_pub`/`sub`). (The
installed *bridge* still uses `pgrep` — but in `bt_service_watchdog`, to
launch/respawn the daemon, not in `btmqttd` itself.) It bundles ~65
Rust crates, **all under permissive licenses** — MIT, Apache-2.0, ISC,
BSD-3-Clause and Unicode-3.0 — with **no copyleft**. The aggregated dependency
license texts and per-crate copyright notices travel with the binary in
[`licenses/btmqttd-THIRD-PARTY-LICENSES.txt`](../../../licenses/btmqttd-THIRD-PARTY-LICENSES.txt).

## Provenance & integrity

| Field | `btmqttd` |
|---|---|
| File | `armhf/btmqttd` |
| Size | 1,510,520 bytes |
| SHA-256 | `4e4bd63e160f97eff27cfdbad06bc8c9076d4f5c78ee535a5dccaec342d713c1` |
| ELF | 32-bit LSB, ARM EABI5, **statically linked** (musl), stripped |
| ABI | armv7 (`Tag_CPU_arch: v7`), **hard-float** (`Tag_FP_arch: VFPv3-D16`, `Tag_ABI_VFP_args: VFP registers`; ELF flags `0x5000400`) |
| Build ID | none (stripped; `rust-lld` emits no GNU build-id note) |
| Target triple | `armv7-unknown-linux-musleabihf` (armv7 hardfloat), **static musl** — no dependency on the device glibc 2.27 |
| Build toolchain | `rustc 1.94.1` + `arm-linux-gnueabihf-gcc` (for `ring`'s C/asm); `cargo build --release` per `BUILD.md` |
| Upstream version | `btmqttd` 0.1.0 (this repo, `native/btmqttd/`) |
| Statically bundles | ~65 Rust crates (MIT / Apache-2.0 / ISC / BSD-3-Clause / Unicode-3.0 — all permissive) + musl libc (MIT) |
| License | permissive only — see SPDX below |
| SPDX expression | `MIT AND Apache-2.0 AND ISC AND BSD-3-Clause AND Unicode-3.0` |
| License texts | [`licenses/btmqttd-THIRD-PARTY-LICENSES.txt`](../../../licenses/btmqttd-THIRD-PARTY-LICENSES.txt) |

The SHA-256 above is also enforced at load time by `PayloadBinaries` (the
accessor throws if the embedded binary's bytes do not match), so a corrupted or
swapped binary cannot be silently installed.

## `btmqttd` — permissive Rust, statically-linked musl

`btmqttd` is copyright the IntercomFirmwareTool authors and distributed under the
same license as the rest of this repository. The shipped binary is **statically
linked**, so the notices of the components it *contains* must travel with it —
that is the purpose of
[`licenses/btmqttd-THIRD-PARTY-LICENSES.txt`](../../../licenses/btmqttd-THIRD-PARTY-LICENSES.txt),
which reproduces, once each, the full MIT, Apache License 2.0, ISC,
BSD-3-Clause and Unicode-3.0 texts together with the real per-crate copyright
lines. The load-bearing non-MIT/Apache components are:

- **ring** (`Apache-2.0 AND ISC`) — the crypto backend behind rustls; bundles
  BoringSSL-derived code. Copyright 2015–2025 Brian Smith and the BoringSSL /
  OpenSSL authors.
- **rustls-webpki** and **untrusted** (ISC) — certificate/DER handling. Copyright
  2015 / 2015–2016 Brian Smith.
- **subtle** (BSD-3-Clause) — constant-time primitives. Copyright Isis Agora
  Lovecruft and Henry de Valence.
- **unicode-ident** (`(MIT OR Apache-2.0) AND Unicode-3.0`) — the Unicode data
  tables carry the Unicode, Inc. license (v3).

Every other crate is MIT and/or Apache-2.0 (we elect MIT where offered). None is
copyleft.

Beyond the Rust crates, the static binary links **musl libc** (MIT) via Rust's
`*-musleabihf` target. musl is not a crate, so its notice is not in the aggregated
crate file above; the MIT copyright + permission notice ships separately in
[`licenses/musl-COPYRIGHT.txt`](../../../licenses/musl-COPYRIGHT.txt) — the same shared musl
notice used by `ffmpeg`.

## Build & reproducibility

The binary is cross-compiled to `armv7-unknown-linux-musleabihf` (static musl,
hard-float) per [`native/btmqttd/BUILD.md`](../../../native/btmqttd/BUILD.md):
Rust's self-contained `rust-lld` + bundled musl link our pure-Rust code, and
`ring`'s small C/asm is compiled with an `arm-linux-gnueabihf` cross-gcc (only to
object code; the final static link and the runtime libc are musl). The exact
dependency versions are pinned in
[`native/btmqttd/Cargo.lock`](../../../native/btmqttd/Cargo.lock) and the
compiler in [`native/btmqttd/rust-toolchain.toml`](../../../native/btmqttd/rust-toolchain.toml)
(`rustc 1.94.1`). A recipient can rebuild the binary from that source + lockfile;
the recorded SHA-256 is the integrity reference, and `PayloadBinaries` re-verifies
it before every install.

The build is **bit-for-bit reproducible from pinned inputs**: `BUILD.md`'s recipe
passes `--remap-path-prefix` to scrub the builder's `CARGO_HOME` and workspace
prefixes (otherwise the `#[track_caller]` panic locations embed absolute host paths
that differ between a local build and CI), so the same source + lockfile + pinned
`rustc` **and the same `ring` C/asm cross-gcc** yield the same SHA-256. All three
inputs are pinned: the Rust side by `Cargo.lock` + `rust-toolchain.toml` (`rustc
1.94.1`), and the cross-gcc by an **immutable Ubuntu archive snapshot** —
CI installs `arm-linux-gnueabihf-gcc` at the exact version
`13.3.0-6ubuntu2~24.04.1cross1` from `snapshot.ubuntu.com`, so a distro gcc bump can
no longer change `ring`'s object code or the SHA. The GitHub Actions workflow
[`btmqttd-provenance.yml`](../../../.github/workflows/btmqttd-provenance.yml)
rebuilds on every PR touching the daemon and enforces **both** checks fatally: the
metadata-consistency check (committed binary ↔ this table ↔ `PayloadBinaries`) and
the source↔binary reproduction (rebuilt binary ↔ committed binary) — see issues #72
and #76. `trim-paths` would be the cleaner path scrub but is not stabilised in the
pinned Cargo, so the explicit remap is used.

**Scope.** The binary is embedded **unconditionally** in
`IntercomFirmwareTool.Core` (a compiled-in resource), so any distribution of that
assembly redistributes `btmqttd` and should carry
`btmqttd-THIRD-PARTY-LICENSES.txt` (this file travels with it for the same
reason). What the bridge toggle affects is the **generated firmware image**: the
installer writes `btmqttd` into an image only when the user enables the bridge;
an image built without the bridge (the default) contains no third-party binary
and carries no such obligation for the image. Because every bundled component is
permissive, meeting these obligations is limited to **reproducing the notices** —
there is no copyleft source-offer requirement, unlike the previous `jq`/`evtest`
binaries this daemon replaces.

---

## `ffmpeg` — minimal LGPL build for the on-device media server (issue #120)

Unlike `btmqttd` (our own program), **`ffmpeg` is genuinely third-party** — a minimal,
**LGPL-2.1-or-later** build of [FFmpeg](https://ffmpeg.org/) `n7.1.1`, cross-compiled to
a static-musl armv7 hard-float binary and embedded in `IntercomFirmwareTool.Core`. The
on-device media server (#120) runs it so go2rtc can read the panel's cleartext RTP via an
SDP and **copy** the H.264 into RTSP — no frame is ever encoded or transcoded. The build
does include the **H.264 decoder**, but only so `find_stream_info` can read the stream's
parameter sets (SPS/PPS) from the SDP's `sprop-parameter-sets` at open, resolving the video
dimensions in under a second; `-c:v copy` never decodes a frame at runtime. Built per
[`../../../native/ffmpeg/BUILD.md`](../../../native/ffmpeg/BUILD.md).

It is compiled `--disable-everything` plus only the RTP/SDP→RTSP H.264-copy path (the H.264
parser + decoder for parameter-set discovery, and the HEVC parser as a link-only dependency),
**never** `--enable-gpl`/`--enable-nonfree` and with no GPL-only libraries (no x264/x265/…),
so the whole binary is LGPL. **No encoders are built** — the one decoder is the LGPL H.264
decoder, used solely to read parameter sets at open (the GPL x264 *encoder* is never enabled).

### Provenance & integrity

| Field | `ffmpeg` |
|---|---|
| File | `armhf/ffmpeg` |
| Size | 2,746,872 bytes |
| SHA-256 | `ac8dfeed4c54d4416762b052e1af5ac7797e2bdc57f666a1013f2fdf7a095a8e` |
| ELF | 32-bit LSB, ARM EABI5, **statically linked** (musl), stripped |
| ABI | armv7, **hard-float** (ELF flags `0x5000400`) |
| Upstream | FFmpeg `n7.1.1` (release tag) |
| Build toolchain | `zig cc` 0.13.0 (bundled musl) per `BUILD.md` |
| Configuration | `--disable-everything` + `protocol=file,udp,rtp,tcp` · `demuxer=sdp,rtsp,rtp` · `muxer=rtsp,rtp` · `parser=h264,hevc` · `decoder=h264` · `--disable-asm` |
| License | **LGPL-2.1-or-later** (FFmpeg) **AND MIT** (statically-linked musl libc) |
| License text | [`licenses/ffmpeg-COPYING.LGPLv2.1.txt`](../../../licenses/ffmpeg-COPYING.LGPLv2.1.txt) · [`licenses/musl-COPYRIGHT.txt`](../../../licenses/musl-COPYRIGHT.txt) |
| SPDX expression | `LGPL-2.1-or-later AND MIT` |

The SHA-256 + size are enforced on read by `PayloadBinaries`. **Byte-reproducible** — like
`btmqttd`: with every build input pinned (Zig `0.13.0` and the FFmpeg `n7.1.1` source, both
SHA-256-verified) and no absolute build path leaking into the output (see `BUILD.md`), the
build is deterministic. So [`ffmpeg-provenance.yml`](../../../.github/workflows/ffmpeg-provenance.yml)
enforces **byte-for-byte** provenance: the metadata check (committed binary ↔ this table ↔
`PayloadBinaries`) **plus** a fresh rebuild from the pinned source whose SHA-256 must equal
the committed binary's (and which runs under `qemu-arm` and is LGPL, not GPL/nonfree). A
mismatch means the vendored binary is out of sync with the pinned source — the same
guarantee `btmqttd` provides. Refreshed via
[`ffmpeg-build.yml`](../../../.github/workflows/ffmpeg-build.yml) (dispatch-only).

### LGPL-2.1 obligations

The binary is a **standalone program** built from FFmpeg's own LGPL sources (statically
linked), so distributing it requires (a) shipping the **LGPL-2.1 license text** — done, in
`licenses/ffmpeg-COPYING.LGPLv2.1.txt`, which travels with the assembly — and (b) providing the
**corresponding source**. Every release **accompanies** the binary with the complete corresponding
source, in two parts, shipped by `.github/workflows/release.yml` as standalone assets **and**
bundled inside both `.zip` archives: (1) the unmodified upstream **FFmpeg `n7.1.1`** source as
`ffmpeg-n7.1.1-source.tar.gz`, downloaded from the pinned tag and **SHA-256-verified against the
same digest the binary is built from** (`native/ffmpeg/pins.env`), so the shipped source provably
corresponds to the shipped binary; and (2) the scripts that control its configuration and
compilation as `ffmpeg-n7.1.1-build-recipe.tar.gz` (`build.sh` + `pins.env` + `BUILD.md`), so
recipients have the exact recipe immutably, not via a mutable repo link. No changes to FFmpeg
source were made. As with `btmqttd`, the embedded resource is compiled into `IntercomFirmwareTool.Core`
unconditionally. The **firmware image** carries `ffmpeg` only when the user enables the on-device
camera. As of **1c-1** (#120) `ffmpeg` is embedded but **not** in `PayloadBinaries.All`, so
`MqttInstaller` does not yet write it to the device; the gated on-device camera install adds it
(with `go2rtc`) in **Phase 1c-2**.

### musl libc (MIT) — statically linked

`zig cc` statically links **musl libc** into the binary. musl is MIT-licensed; its COPYRIGHT
grants an exception for public headers and CRT files, but the general libc objects linked
from `libc.a` are **not** covered by that exception, so the MIT copyright + permission notice
must ship with the distribution. It does — [`licenses/musl-COPYRIGHT.txt`](../../../licenses/musl-COPYRIGHT.txt),
sourced from the pinned Zig distribution (which bundles musl) and embedded in the assembly.
The same upstream musl license also covers `btmqttd`'s statically-linked musl, so both
binaries share this one notice.

---

## `go2rtc` — on-device streaming server (issue #120)

Like `ffmpeg`, **`go2rtc` is genuinely third-party** — but unlike the binaries we build
ourselves, it is a **redistributed upstream prebuilt**: the official `go2rtc_linux_arm`
release asset of [go2rtc](https://github.com/AlexxIT/go2rtc) **`v1.9.14`** (a statically-linked
Go binary, **MIT**), embedded verbatim in `IntercomFirmwareTool.Core`. The on-device media
server (#120) runs it to read the panel's cleartext RTP (fanned to `127.0.0.2` by `btmqttd`)
via a generated SDP, invoke `ffmpeg` to **copy** the H.264 into RTSP, and serve that stream to
Home Assistant as a native Generic Camera — so no go2rtc runs on the Home Assistant side.

### Provenance & integrity

| Field | `go2rtc` |
|---|---|
| File | `armhf/go2rtc` |
| Size | 4,588,084 bytes |
| SHA-256 | `4d7e1639af5a2722a28e864468fd8099b3c1682565446c798bf9e3b38fde12e4` |
| ELF | 32-bit LSB, ARM EABI5, **statically linked** (no libc dependency), UPX-compressed |
| Upstream | go2rtc `v1.9.14` — AlexxIT/go2rtc release asset `go2rtc_linux_arm` |
| Build | upstream's own Go release build — **not** rebuilt from source here |
| License | **MIT** (go2rtc itself). The static Go binary also contains the **BSD-3-Clause Go runtime** and ~35 Go modules — all permissive (MIT / BSD-2 / BSD-3 / Apache-2.0); `paho.mqtt.golang` is EPL-2.0/EDL-1.0 dual-licensed, used here under the permissive **EDL-1.0 (BSD-3-Clause)** election, so no copyleft applies. |
| License texts | [`licenses/go2rtc-LICENSE.txt`](../../../licenses/go2rtc-LICENSE.txt) (go2rtc MIT) + [`licenses/go2rtc-THIRD-PARTY-LICENSES.txt`](../../../licenses/go2rtc-THIRD-PARTY-LICENSES.txt) (audited Go runtime + module notices) |
| SPDX expression | `Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND MIT AND (EPL-2.0 OR BSD-3-Clause)` |

The SHA-256 + size are enforced on read by `PayloadBinaries`. Because go2rtc is a **prebuilt
upstream release** (not reproducible-from-source in this repo), its provenance model is
**pin-and-verify** rather than a byte-for-byte rebuild: the exact release tag, asset name and
SHA-256 are pinned in [`native/go2rtc/pins.env`](../../../native/go2rtc/pins.env), and
[`go2rtc-provenance.yml`](../../../.github/workflows/go2rtc-provenance.yml) on every PR
**re-downloads the pinned release asset and byte-compares it** to this committed copy, in
addition to the metadata-consistency check (committed binary ↔ this table ↔ `PayloadBinaries`).
A mismatch means the vendored binary drifted from the pinned upstream release.

### License obligations & the audited dependency-notice bundle

Redistributing go2rtc requires shipping its **MIT license text** — done, in
[`licenses/go2rtc-LICENSE.txt`](../../../licenses/go2rtc-LICENSE.txt) (© 2022 Alexey Khit). But the
binary is **statically linked**, so it also contains the **Go runtime (BSD-3-Clause)** and ~35 Go
modules, whose notices must **likewise** travel with any redistribution. Those are reproduced in full
in [`licenses/go2rtc-THIRD-PARTY-LICENSES.txt`](../../../licenses/go2rtc-THIRD-PARTY-LICENSES.txt) —
an **audited aggregate generated with Google's [`go-licenses`](https://github.com/google/go-licenses)**
against go2rtc `v1.9.14`'s module graph **for the exact shipped build** (`GOOS=linux GOARCH=arm
CGO_ENABLED=0`), so build-tagged, non-linked packages (e.g. the `alsa`/`v4l2` cgo backends) are
correctly excluded. It records each module, its detected license, its source URL, and the full
license text, plus the Go runtime's BSD-3-Clause text.

**No copyleft.** Every linked component is permissive — MIT, BSD-2-Clause, BSD-3-Clause, or
Apache-2.0 — with one dual-licensed exception: `github.com/eclipse/paho.mqtt.golang` is
**EPL-2.0 / EDL-1.0 dual-licensed**, and we elect the permissive **EDL-1.0 (a BSD-3-Clause-equivalent
Eclipse Distribution License)**, so the EPL-2.0's reciprocal terms do not apply. Both texts still ship
(the upstream LICENSE presents both) and its corresponding source remains publicly available. The
audited SPDX expression is therefore
`Apache-2.0 AND BSD-2-Clause AND BSD-3-Clause AND MIT AND (EPL-2.0 OR BSD-3-Clause)`.

> **Regenerating on a pin bump.** When `native/go2rtc/pins.env` bumps `GO2RTC_TAG`, regenerate this
> bundle from the new tag's module graph (`go-licenses report`/`save` under `GOOS=linux GOARCH=arm
> CGO_ENABLED=0`) and update the SPDX above + `PayloadBinaries.Go2Rtc.LicenseSpdx`. Note: `go-licenses`
> labels the main go2rtc module's own source URL as `HEAD` (it has no module version in-tree) — pin it
> to the tag (`blob/<GO2RTC_TAG>/LICENSE`) by hand so every reference stays immutable.

Both license files are compiled into `IntercomFirmwareTool.Core` unconditionally and shipped in every
release (the `release.yml` packaging list throws if either is missing — a hard release gate). The
**firmware image** carries `go2rtc` only when the user enables the on-device camera — it is embedded
now but **not** yet in `PayloadBinaries.All`; the gated on-device camera install writes it in
**Phase 1c-2**.
