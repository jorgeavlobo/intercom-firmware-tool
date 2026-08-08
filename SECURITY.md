# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue for a
suspected vulnerability.

Use GitHub's private reporting: on the repository's **Security** tab choose
**Report a vulnerability** (GitHub Security Advisories). This opens a private
channel with the maintainer and lets a fix be prepared before any public
disclosure.

When you report, please include:

- the affected component (the Windows desktop app, the `btmqttd` bridge, the
  installer/payload, or the CI/release pipeline);
- the version or commit you tested;
- a description of the impact and, where possible, steps to reproduce.

You can expect an initial acknowledgement within a few days. If a fix is
warranted, it lands on `master` and ships in the next tagged release, with the
advisory credited to the reporter unless anonymity is requested. There is no
paid bounty program.

## Supported versions

This project follows [Semantic Versioning](https://semver.org/) with
tag-driven releases (`vX.Y.Z`; see [`CHANGELOG.md`](CHANGELOG.md)). Security
fixes are made against the **latest release** and `master`. Older builds are not
back-patched — update to the latest release rather than staying on a pinned
version.

The app also carries a maintainer-controlled **minimum-supported-version**
signal: a build flagged unsafe (for example, one with a serious defect) shows a
red banner and disables the firmware actions on startup, while remaining
otherwise usable (read the message, switch language, open **About**, quit). This
is the mechanism used to retire a build with a known security-relevant bug.

## Safety posture

The tool is built to be **safe by default** and hard to use destructively:

- **It never flashes the device.** The tool only *prepares* a firmware image on
  your PC. You flash it yourself through the device's own official update
  mechanism, so there is no remote-bricking path through this software.
- **It never modifies the original firmware in place.** Official firmware is
  downloaded (optionally) and verified byte-for-byte (size + SHA-256) against the
  known-good original before use; a file that fails verification is discarded.
  Prepared output is written to a *new* image, leaving your source untouched.
- **Recovery-ready.** Because the original image is preserved and verifiable, you
  can use it to return to stock firmware whenever the device's official update
  mechanism remains available and accepts the image.
- **Releases are verifiable.** Every released desktop asset ships a SHA-256
  checksum and a [SLSA](https://slsa.dev/) build-provenance attestation proving it
  was built by this repository's CI (`gh attestation verify …`). The attestation —
  not an antivirus label — is the authoritative origin check for an unsigned
  build.
- **The update check is opt-out, fails open, and downloads nothing.** It makes at
  most one time-boxed HTTPS request to GitHub, sends no application or user data,
  and never downloads or runs anything itself. (Like any HTTPS request it exposes
  your IP address and a fixed `User-Agent` to GitHub; nothing more.)

## Dangerous features are opt-in and off by default

Everything that widens the device's attack surface is a deliberate, clearly
labelled choice, disabled unless you turn it on:

- **Remote command channel (`ALLOW_REMOTE_SHELL`).** The `btmqttd` bridge's
  `read_file` / `write_file` / `execute_command` capabilities are **off** unless
  this flag is set **and** the bridge's own broker connection is credentialed
  (username + password, or mTLS) — the daemon refuses a root-capable channel over
  an anonymous link. That self-check does not authenticate individual publishers;
  **which clients may issue commands is governed by your MQTT broker's ACL on the
  command topic**, so restrict that topic to intended, authenticated clients. With
  the flag off, the bridge only relays intercom events and the light/lock/volume
  controls. See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the full trust boundary.
- **SSH access.** Dropbear key-login and the optional ECDSA host key
  ([#37](../../issues/37)) / stable RSA host-key pinning ([#38](../../issues/38))
  are installed only when you enable SSH in the tool. No SSH `authorized_keys`
  mechanism exists in the factory firmware — it is created solely by opting in.
- **Secondary lock and learnable exterior light.** These control real hardware
  and are added only when explicitly selected in the installer.
- **Firmware auto-update block (OTA).** Blocking the device's own OTA updates is
  an explicit build option, not a default.

## Scope

In scope: the desktop app, the `btmqttd` bridge and its payload/installer, and
the CI/release pipeline in this repository.

Out of scope: vulnerabilities in the underlying BTicino/Legrand firmware, in
Home Assistant or your MQTT broker, or in third-party dependencies (report those
upstream — though we welcome a heads-up so we can pin or update). Misuse of the
opt-in features above on a network or device you do not own is out of scope by
definition.
