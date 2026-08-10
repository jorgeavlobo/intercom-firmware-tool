# Third-party binary shipped by the MQTT bridge installer

The optional **MQTT bridge** feature (off by default) installs one prebuilt ARM
binary into the firmware image, because it is **not** present in the factory
BTicino C300X/C100X firmware:

| Tool | Installed as | Purpose |
|---|---|---|
| `btmqttd` | `/usr/sbin/btmqttd` (`0775 root:root`) | the single-connection MQTT bridge daemon (issue #32) — OpenWebNet bus monitor → MQTT, MQTT → gateway command dispatch, front-panel keypad → MQTT, Home Assistant discovery, TLS, atomic birth/will availability |

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
firmware image and this assembly no longer carry any GPL/LGPL component.

`btmqttd` is a **statically-linked musl** binary, so it needs no runtime
interpreter, no shared libraries, and none of the device tools the shell bridge
depended on (`tcpdump`, `python`, `jq`, `nc`, `awk`, `mosquitto_pub`/`sub`). (The
installed *bridge* still uses `pgrep` — but in `bt_service_watchdog`, to
launch/respawn the daemon, not in `btmqttd` itself.) It bundles ~65
Rust crates, **all under permissive licenses** — MIT, Apache-2.0, ISC,
BSD-3-Clause and Unicode-3.0 — with **no copyleft**. The aggregated dependency
license texts and per-crate copyright notices travel with the binary in
[`licenses/btmqttd-THIRD-PARTY-LICENSES.txt`](licenses/btmqttd-THIRD-PARTY-LICENSES.txt).

## Provenance & integrity

| Field | `btmqttd` |
|---|---|
| File | `armhf/btmqttd` |
| Size | 1,453,360 bytes |
| SHA-256 | `01ee11860dce787f11cc001070a7567460f743adcf1e678752b5d58ae7412ad0` |
| ELF | 32-bit LSB, ARM EABI5, **statically linked** (musl), stripped |
| ABI | armv7 (`Tag_CPU_arch: v7`), **hard-float** (`Tag_FP_arch: VFPv3-D16`, `Tag_ABI_VFP_args: VFP registers`; ELF flags `0x5000400`) |
| Build ID | none (stripped; `rust-lld` emits no GNU build-id note) |
| Target triple | `armv7-unknown-linux-musleabihf` (armv7 hardfloat), **static musl** — no dependency on the device glibc 2.27 |
| Build toolchain | `rustc 1.94.1` + `arm-linux-gnueabihf-gcc` (for `ring`'s C/asm); `cargo build --release` per `BUILD.md` |
| Upstream version | `btmqttd` 0.1.0 (this repo, `native/btmqttd/`) |
| Statically bundles | ~65 Rust crates (MIT / Apache-2.0 / ISC / BSD-3-Clause / Unicode-3.0 — all permissive) + musl libc (MIT) |
| License | permissive only — see SPDX below |
| SPDX expression | `MIT AND Apache-2.0 AND ISC AND BSD-3-Clause AND Unicode-3.0` |
| License texts | [`licenses/btmqttd-THIRD-PARTY-LICENSES.txt`](licenses/btmqttd-THIRD-PARTY-LICENSES.txt) |

The SHA-256 above is also enforced at load time by `PayloadBinaries` (the
accessor throws if the embedded binary's bytes do not match), so a corrupted or
swapped binary cannot be silently installed.

## `btmqttd` — permissive Rust, statically-linked musl

`btmqttd` is copyright the IntercomFirmwareTool authors and distributed under the
same license as the rest of this repository. The shipped binary is **statically
linked**, so the notices of the components it *contains* must travel with it —
that is the purpose of
[`licenses/btmqttd-THIRD-PARTY-LICENSES.txt`](licenses/btmqttd-THIRD-PARTY-LICENSES.txt),
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
