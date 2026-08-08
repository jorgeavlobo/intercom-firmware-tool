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
  your PC; you flash it yourself through the device's own official update
  mechanism, so there is no remote firmware-flashing path through this software.
  (This is about flashing only: if you enable `ALLOW_REMOTE_SHELL`, an authorized
  MQTT publisher can still write the device rootfs or run commands — an
  availability risk you accept by opting in, covered in
  [`THREAT_MODEL.md`](THREAT_MODEL.md).)
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
- **The update check is opt-out, fails open, and installs nothing.** It makes
  **one automatic, time-boxed** HTTPS request at startup to fetch a small version
  manifest from GitHub (plus one more each time *you* click "Check for updates
  now"), sends no application or user data, and never downloads or runs any
  firmware, executable, or release asset itself. "Fails open" means a failed or
  absent check never blocks the app — no internet, a timeout, or a malformed
  manifest simply means no banner and full functionality; only a *successful*
  check returning a maintainer-flagged unsafe version disables the firmware
  actions (see **Supported versions**). (As with any HTTPS request, GitHub still
  sees your IP address, a fixed `User-Agent`, and the ordinary request/network
  metadata; the request carries no application or user data of its own.)

## SSH is enabled by every build

Enabling SSH is the tool's **core function**, not an option: **every image the
tool builds adds Dropbear SSH** — the login accounts and the boot symlink that
starts it. What you configure is the *credentials* (a root password and/or an SSH
public key; an `authorized_keys` entry is written only when you supply a key) and
the optional **Modern SSH host key** handling (an ECDSA host key + a stable RSA
pin, [#37](../../issues/37) / [#38](../../issues/38), off by default). Treat every
image you build as SSH-exposed and give it a strong credential. No SSH
`authorized_keys` mechanism exists in the factory firmware — it is created solely
by this tool.

## Dangerous features are opt-in and off by default

The MQTT bridge itself is opt-in and off by default, and each capability below
that widens the device's attack surface is a further deliberate, clearly labelled
choice. (Note: once you install the bridge and configure a light/lock, its
**Tier 1** light/lock/volume controls (and the raw-frame path) operate as normal MQTT controls —
their access control is the broker's command-topic ACL, see
[`THREAT_MODEL.md`](THREAT_MODEL.md); they are not individually gated behind a
separate opt-in the way the items below are.)

- **Remote command channel (`ALLOW_REMOTE_SHELL`).** The `btmqttd` bridge's
  `read_file` / `write_file` / `execute_command` capabilities are **off** unless
  this flag is set **and** the bridge's own broker connection is credentialed
  (username + password, or mTLS) — the daemon refuses a root-capable channel over
  an anonymous link. That self-check does not authenticate individual publishers;
  **which clients may issue commands is governed by your MQTT broker's ACL on the
  command topic**, so restrict that topic to intended, authenticated clients. With
  the flag off, the bridge still relays intercom events **and forwards raw
  OpenWebNet frames** to the local gateway (which can actuate the bus — e.g. open a
  lock) alongside the structured light/lock/volume controls; these are all Tier 1,
  gated only by the broker's command-topic ACL. Only the shell capabilities above
  are behind the flag. When Tier 2 is on, also restrict *subscribe* on the
  response topics (`read_file`/`execute_command` publish their output there). See
  [`THREAT_MODEL.md`](THREAT_MODEL.md) for the full trust boundary.
- **Secondary lock and learnable exterior light.** These control real hardware
  and are added only when explicitly selected in the installer.
- **Firmware auto-update block (OTA).** Blocking the device's own OTA updates is
  an explicit build option, not a default.

## Scope

In scope: the desktop app, the `btmqttd` bridge and its payload/installer, and
the CI/release pipeline in this repository.

Out of scope: vulnerabilities in the underlying BTicino/Legrand firmware, or in
Home Assistant / your MQTT broker and other upstream products you run separately
(report those upstream). A vulnerability in a third-party component this project
**bundles or ships** — for example the `btmqttd` crates, or `lwext4` via
`SharpExt4.dll` — **is** in scope as a supply-chain report: please raise it here
as well as upstream, so we can pin, patch, or re-vendor. Misuse of the opt-in
features above on a network or device you do not own is out of scope by
definition.
