# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

Releases are tag-driven (`vX.Y.Z`) and each ships a portable Windows x64 build
with SHA-256 checksums and a SLSA build-provenance attestation (see the
[README](README.md#releases)). Development builds report version `0.0.0`.

## [Unreleased]

Everything below has landed on `master` and is slated for the first tagged
release, **v1.0.0**. Entries reference the pull request or issue that introduced
them.

### Added

- **Firmware preparation (core).** Clean-room reader/writer for BTicino/Legrand
  `.fwz` firmware images: read the ext4 rootfs from inside a `.fwz` and write a
  new, modified image without touching the original (#1, #16).
- **Official firmware download.** Optionally fetch the original, unmodified
  firmware straight from the official servers and verify it byte-for-byte
  (size + SHA-256) before use (#23, #68). Model/version catalog including
  Classe 100X, 300X and EOS Home + Security variants (#62, #65).
- **SSH access.** Every built image enables Dropbear SSH (the tool's core
  function); you configure the credentials (root password and/or public key). An
  optional **Modern SSH host key** setting adds an **ECDSA P-256 host key** so
  modern clients connect (#37) and a **stable RSA host key** pinned via
  `DROPBEAR_RSAKEY` to stop per-boot host-key regeneration (#38).
- **MQTT bridge — `btmqttd`.** A single statically-linked Rust daemon
  (OpenWebNet bus ↔ external MQTT broker) with Home Assistant auto-discovery,
  replacing the previous shell/Python payload and its vendored `jq`/`evtest`
  tools (#12, #30, #31, #64). Structured-JSON or raw-frame bus payloads and a
  persistent, durable command subscription that owns availability atomically
  (#31, #41).
- **Home Assistant entities.** Entrance-panel call and floor-call events,
  call-state, model-named device with entity prefix, and dual-lock support with a
  Home + Security customization guard (#66, #69, #71).
- **Exterior light control.** Opt-in door-entry stair-light with configurable
  `WHERE` (#67); a **learnable** exterior light with Resync and Learn buttons
  (#95); and a **momentary (staircase-timer)** light type that presses without
  tracking state, for installations whose hardware owns the off (#96).
- **Broker rediscovery.** Recovery when the broker's LAN IP changes — **on by
  default when the bridge is installed via the tool** (opt-out; the daemon itself
  defaults off and self-gates, needing a hostname config plus a TLS or
  captured-MAC trust anchor): hostname canonicalization + pinned IP, captured
  broker MAC as a plaintext trust anchor, mDNS/DNS-SD and a hardened `/24` scan,
  each behind a reconnect trust gate (#43, #52). DHCP-reservation + hostname
  remains the recommended setup.
- **Build options.** Optional "block firmware auto-updates (OTA)" (#21) and
  "keep `.sig` signature files" (#22) toggles.
- **Automatic update check (opt-out).** On startup, quietly informs when a newer
  release exists and, for a maintainer-flagged unsafe build, disables the firmware
  actions while keeping the app otherwise usable; makes at most one time-boxed
  HTTPS request that fetches a small version manifest and downloads no firmware,
  executable, or release asset (#85).
- **Localization.** Full UI + core messages in six languages (English, Italian,
  Spanish, French, German, Portuguese), with resource parity.
- **Release pipeline.** Tag-driven Windows x64 release producing a draft GitHub
  Release with a portable single-file `.exe`, a zipped copy, a loose-folder
  archive, per-asset SHA-256 checksums, and a SLSA build-provenance attestation
  (#79).
- **Project documentation.** `SECURITY.md`, `THREAT_MODEL.md`, `CLEANROOM.md`,
  and this `CHANGELOG.md` (#14).

### Changed

- **Native rewrite of the MQTT bridge.** The shell-orchestrated bridge
  (`filter.py`, `StartMqttSend`/`StartMqttReceive`, `keypress.sh`,
  `ha_discovery.sh`, `mqtt_common.sh`, `TcpDump2Mqtt`) was fully replaced by the
  in-process `btmqttd` daemon, eliminating the `tcpdump`/`python`/`jq`/`nc`/`awk`
  runtime tools (#12).
- **Gold-standard on-device layout.** `btmqttd` installs to `/usr/sbin`, config
  under `/etc/btmqttd`, with its own SysV init script (#63, #64).
- **Bridge targets an external broker.** Documented (and warned in the UI, though
  not hard-rejected by validation) that `MQTT_HOST` should point at your broker,
  not the device's internal `127.0.0.1:60000` IPC bus (#36).

### Fixed

- **Service watchdog no longer restarts the core BTicino stack**, which could
  take the intercom down ~60s after boot; it now supervises only this tool's own
  daemons (#94).
- **HA SRV record no longer misclassified as an MQTT broker** during mDNS
  correlation (#54).
- **Momentary call events** are dropped when offline, purged from the queue, and
  coalesced in bursts (#71).

### Security

- **Command channel is opt-in and off by default.** `read_file`/`write_file`/
  `execute_command` require `ALLOW_REMOTE_SHELL=1` **and** a credentialed bridge
  connection to the broker; the daemon does not authenticate individual
  publishers, so which clients may issue commands is governed by the broker's
  command-topic ACL (see [`THREAT_MODEL.md`](THREAT_MODEL.md)).
- **Reproducible, provenance-checked binary.** The embedded `btmqttd` ARM binary
  is guarded in CI by a two-tier check — committed SHA-256 + size must match the
  metadata, and a rebuild from fully pinned inputs must be byte-for-byte identical
  (#72, #76).
- **Supply-chain and static analysis in CI.** NuGet vulnerability audit,
  `cargo-deny` (RustSec advisories + permissive-only license policy),
  `dependency-review`, CodeQL (C#), and a QEMU-ARM smoke test that the vendored
  binary executes (#14).

[Unreleased]: https://github.com/jorgeavlobo/intercom-firmware-tool/commits/master
