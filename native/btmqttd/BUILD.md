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
> This is confirmed automatically: the provenance workflow runs the vendored binary
> under `qemu-arm-static` (a present-but-empty config makes it print exactly
> `btmqttd: MQTT_HOST is not set in the config` and exit 1), proving it executes on the
> armv7 target — not just links. Confirm on real hardware before a release.

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
> cross-gcc: the committed binary was built with `arm-linux-gnueabihf-gcc`
> **13.3.0-6ubuntu2~24.04.1** (Ubuntu 24.04, `gcc-13`). CI pins that exact toolchain
> from an **immutable Ubuntu archive snapshot** — the package
> `gcc-13-arm-linux-gnueabihf=13.3.0-6ubuntu2~24.04.1cross1` (with its `cpp-13` and
> `binutils-arm-linux-gnueabihf=2.42-4ubuntu2.10` peers) from `snapshot.ubuntu.com`
> (see the workflow) — so the SHA is reproducible over time; locally, an Ubuntu 24.04
> host with the same `gcc-13` cross toolchain reproduces it.

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
4. From the **repo root**, confirm the records agree (and, with `--rebuilt`, that the
   fresh build reproduces the committed binary):

   ```sh
   native/btmqttd/ci/verify-provenance.sh --rebuilt \
     native/btmqttd/target/armv7-unknown-linux-musleabihf/release/btmqttd
   ```

This runs in CI on every PR that touches the daemon
([`.github/workflows/btmqttd-provenance.yml`](../../.github/workflows/btmqttd-provenance.yml)),
in two tiers:

- **Metadata consistency — enforced (fatal).** The committed binary's SHA-256 + size
  must equal `PayloadBinaries` and `THIRD_PARTY.md`. Deterministic; catches a binary or
  metadata updated without the other.
- **Source→binary reproduction — enforced (fatal).** CI rebuilds from source and requires
  a byte-for-byte match with the committed binary. This is enforceable because every build
  input is pinned: `rustc` (`rust-toolchain.toml`), crates (`Cargo.lock`), and the `ring`
  C/asm cross-gcc — CI installs it from an **immutable Ubuntu archive snapshot**
  (`snapshot.ubuntu.com`, exact version `13.3.0-6ubuntu2~24.04.1cross1`), so a distro gcc
  bump can no longer change the object code. A mismatch means the vendored binary is out
  of sync with the source: rebuild and re-sync per the steps above. (Resolves **#76**.)

## Bumping the bridge version (issue #114)

The daemon compiles its own version in (`env!("CARGO_PKG_VERSION")`), which surfaces to Home
Assistant as the device `sw_version` and drives the update-check comparison. That version lives
in **three files that CI keeps equal**, so bumping it is a small provenance chore, not a one-line
edit. To release e.g. `0.1.0 → 0.2.0`:

1. Set the new version in all three sources:
   - `native/btmqttd/Cargo.toml` — `[package] version` (the source of truth).
   - `IntercomFirmwareTool.Core/Payload/PayloadBinaries.cs` — `BridgeVersion`.
   - `.well-known/bridge.json` — `latestVersion`.
2. Refresh `Cargo.lock` so it records the new `btmqttd` version — otherwise the `--locked`
   build in the next step fails with "Cargo.lock needs to be updated":

   ```sh
   cd native/btmqttd && cargo update -p btmqttd --precise 0.2.0   # use the new version
   ```
3. Reproducibly rebuild (see **Build** above) — the baked-in version changes the binary.
4. Re-sync the vendored binary + provenance exactly as in **Verify** above (copy the binary,
   update `Length`/`Sha256Hex` and `THIRD_PARTY.md`, run `verify-provenance.sh --rebuilt`).
5. Confirm the three versions agree:

   ```sh
   native/btmqttd/ci/check-bridge-version.py \
     native/btmqttd/Cargo.toml \
     IntercomFirmwareTool.Core/Payload/PayloadBinaries.cs \
     .well-known/bridge.json
   ```

The guardrails make this hard to get wrong: `btmqttd-provenance.yml` fails the PR if the three
versions disagree (**"bridge version drift"**) **or** if the committed binary doesn't reproduce
bit-for-bit. After merge, master's `bridge.json` immediately advertises the new version (so
already-deployed panels show "update available"); the new binary itself reaches a panel on its
next USB reflash, at which point its `sw_version` updates. The SemVer bump size is a judgement
call based on what changed in the daemon.

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
