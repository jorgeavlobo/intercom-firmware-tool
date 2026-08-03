# Building `btmqttd` for the intercom

`btmqttd` is the single-connection MQTT bridge daemon (issue #32) that replaces the
shell-orchestrated `mosquitto_pub`/`mosquitto_sub` bridge. It is cross-compiled to a
**statically-linked, 32-bit ARM EABI5, armv7 hard-float** binary (musl), the same
target as the shipped `jq`/`evtest`, and embedded into the firmware image by
`MqttInstaller` via `PayloadBinaries` (length + SHA-256 verified on read).

## Target

| Property | Value |
|---|---|
| Triple | `armv7-unknown-linux-musleabihf` |
| ABI | EABI5, **hard-float** (`Tag_ABI_VFP_args: VFP registers`, flags `0x5000400`) |
| CPU | armv7 (VFPv3-D16) |
| libc | musl, **statically linked** (no dependency on the device glibc 2.27) |
| Device | BTicino Classe 100X (i.MX, kernel 4.9.11) |

## Toolchain

Pure-Rust code links with Rust's self-contained `rust-lld` + bundled musl, so **no
external musl toolchain is needed for our code**. The one C dependency — `ring`
(rustls' crypto backend) — is compiled with an ARM cross-gcc selected via `CC_*`.

```sh
# 1. Rust target (rust-std for the triple)
rustup target add armv7-unknown-linux-musleabihf

# 2. ARM cross C compiler for ring's C/asm (Debian/Ubuntu)
sudo apt-get install -y gcc-arm-linux-gnueabihf
```

> Note: an armv7 **musl** cross toolchain would be the most consistent choice for
> ring's C (matching the musl runtime), but musl.cc is blocked on some networks. The
> glibc cross-gcc above only *compiles* ring's C to object code; the final static
> link (and the runtime libc) is **musl** via `rust-lld` — ring uses only
> ABI-stable libc functions, and the static link resolves every symbol against musl.
> Confirm on-device (or under qemu-arm) as part of the smoke test.

## Build

The link flags (rust-lld, self-contained musl, static CRT) live in
[`.cargo/config.toml`](.cargo/config.toml); the compiler is pinned to
**`rustc 1.94.1`** by [`rust-toolchain.toml`](rust-toolchain.toml) (rustup installs
it automatically) and the crate versions by [`Cargo.lock`](Cargo.lock).

Build with the **reproducible** recipe below. It adds `--remap-path-prefix` to
scrub the builder's `CARGO_HOME` and workspace prefixes from the binary, so its
SHA-256 is host-independent. (A plain `cargo build` links the same static binary
but embeds your local absolute paths in the `#[track_caller]` panic locations,
producing a different SHA-256 that CI will not reproduce.)

```sh
export CC_armv7_unknown_linux_musleabihf=arm-linux-gnueabihf-gcc
export AR_armv7_unknown_linux_musleabihf=arm-linux-gnueabihf-ar
# Host-independent paths: map CARGO_HOME -> /cargo and this dir -> /build.
export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_RUSTFLAGS="\
-Clinker-flavor=ld.lld -Clink-self-contained=yes -Ctarget-feature=+crt-static \
--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo \
--remap-path-prefix=$(pwd)=/build"
cargo build --release --locked --target armv7-unknown-linux-musleabihf
```

Output: `target/armv7-unknown-linux-musleabihf/release/btmqttd`.

> `CARGO_TARGET_*_RUSTFLAGS` **replaces** (does not merge with) the `rustflags` in
> `.cargo/config.toml`, so the link flags are repeated in the recipe. `trim-paths`
> would be the cleaner path scrub but is not stabilised in the pinned Cargo (1.94.1),
> so the explicit remap is used. Reproducibility also depends on the `ring` C/asm
> cross-gcc: build on Ubuntu 24.04 (`gcc-arm-linux-gnueabihf` 13.x), which the CI
> runner (`ubuntu-24.04`) matches.

## Verify

```sh
BIN=target/armv7-unknown-linux-musleabihf/release/btmqttd
file "$BIN"            # ELF 32-bit LSB, ARM, EABI5, statically linked, stripped
readelf -h "$BIN" | grep Flags   # 0x5000400 ... hard-float ABI
sha256sum "$BIN"; stat -c%s "$BIN"
```

Then update the embedded copy and its provenance:

1. Copy the binary to `IntercomFirmwareTool.Core/Payload/vendor/armhf/btmqttd`.
2. Update the `Length` + `Sha256Hex` in `PayloadBinaries` (`MqttInstaller`).
3. Update the `btmqttd` entry in `Payload/vendor/THIRD_PARTY.md`.
4. From the **repo root**, confirm the four records agree:

   ```sh
   native/btmqttd/ci/verify-provenance.sh \
     native/btmqttd/target/armv7-unknown-linux-musleabihf/release/btmqttd
   ```

This same check runs in CI on every PR that touches the daemon
([`.github/workflows/btmqttd-provenance.yml`](../../.github/workflows/btmqttd-provenance.yml)):
it rebuilds from source with the reproducible recipe and fails if the freshly built
SHA-256 / size do not match the committed binary, `PayloadBinaries`, and
`THIRD_PARTY.md` — so a source change without a matching rebuild (or vice-versa) is
caught in review (issue #72).

## Host checks (fast iteration)

Run these on a **Linux host (or WSL)**. btmqttd depends on Linux-specific APIs
(`evdev`, `tokio::signal::unix`, libc), so `cargo test`/`cargo check` on Windows or
macOS fail by design — the crate emits a clear `compile_error!` on non-Linux targets
(`cfg(not(target_os = "linux"))`; macOS is Unix but has no evdev, so it is excluded too).

```sh
cargo test     # config gate + OWN framing/JSON unit tests
cargo check    # type-check against the host target (Linux)
```

## Notes

- `opt-level="z"`, LTO, `strip`, `codegen-units=1` — size-first for a
  flash-constrained device. Current size ≈ 1.2 MB (cf. `jq` 1.34 MB). Unwinding is
  KEPT (no `panic="abort"`) so a panic in a spawned task is isolated by tokio
  instead of aborting the daemon.
- Single-threaded tokio runtime (`new_current_thread`) keeps the resident footprint
  small.
- MQTT 3.1.1 (rumqttc default) — the device broker is mosquitto v3.1, which accepts
  3.1.1 (`-V mqttv311`); it does **not** support v5.
