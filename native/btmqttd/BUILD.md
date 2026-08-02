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

The reproducible flags (linker, self-contained musl, static CRT) live in
[`.cargo/config.toml`](.cargo/config.toml). The currently committed binary was
built with **`rustc 1.94.1`** (recorded in `THIRD_PARTY.md` alongside the
SHA-256); the exact crate versions are pinned in
[`Cargo.lock`](Cargo.lock).

```sh
export CC_armv7_unknown_linux_musleabihf=arm-linux-gnueabihf-gcc
export AR_armv7_unknown_linux_musleabihf=arm-linux-gnueabihf-ar
cargo build --release --target armv7-unknown-linux-musleabihf
```

Output: `target/armv7-unknown-linux-musleabihf/release/btmqttd`.

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
