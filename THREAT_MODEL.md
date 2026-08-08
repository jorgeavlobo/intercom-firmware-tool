# Threat Model

This document formalizes the security reasoning behind IntercomFirmwareTool and,
in particular, the **remote command channel** exposed by the `btmqttd` MQTT
bridge. It complements the operational detail in
[`IntercomFirmwareTool.Core/Payload/mqtt/README.md`](IntercomFirmwareTool.Core/Payload/mqtt/README.md)
and the safety posture in [`SECURITY.md`](SECURITY.md).

It is a working model, not a formal proof. The goal is to make the trust
boundaries explicit so that each opt-in feature can be reasoned about
independently.

## System overview

Three components, with distinct trust properties:

1. **The desktop app** (WPF, `net10.0-windows`) — runs on the user's PC.
   Prepares a firmware image; **never flashes the device** and never talks to it
   during preparation. Optionally downloads official firmware (verified
   byte-for-byte) and, at runtime, makes at most one time-boxed update-check
   request to GitHub.
2. **The installer/payload** (`IntercomFirmwareTool.Core`) — writes files into a
   copy of the ext4 rootfs inside the `.fwz`: the `btmqttd` daemon, its config,
   Home Assistant discovery JSON, SysV init scripts, and optionally SSH host keys.
3. **The device-side bridge** (`btmqttd`, statically-linked Rust ARM binary) —
   runs on the intercom after the user flashes the prepared image. Bridges the
   OpenWebNet bus ↔ an external MQTT broker.

## Assets

- **The intercom itself** — door lock(s), exterior light, camera, audio, and the
  internal OpenWebNet/OWN bus (`127.0.0.1:20000` monitor, `127.0.0.1:30006`
  command, local `mosquitto` IPC bus on `127.0.0.1:60000`).
- **Physical access control** — the ability to open a door or gate is the
  highest-value asset in the system.
- **The device rootfs** — read/write of files on the device via the gated
  command channel.
- **The user's LAN and MQTT broker** — the transport the bridge depends on.
- **Firmware integrity** — the guarantee that a prepared image derives from a
  verified official image and nothing else.

## Actors and trust boundaries

| Actor | Trust | Notes |
|---|---|---|
| The user (operator) | Trusted | Owns the device; makes every opt-in choice. |
| The desktop app | Trusted, offline w.r.t. the device | Never flashes; only prepares an image. |
| The MQTT broker | Semi-trusted transport | The bridge authenticates to it; broker ACLs are a dependency (below). |
| An authenticated MQTT client | Trusted **only** for the capabilities its auth grants | e.g. Home Assistant. |
| A LAN peer / network attacker | Untrusted | Can see/replay traffic if TLS is off; cannot cross an authenticated boundary. |
| The internet | Untrusted | Only the update check reaches it, outbound, downloading nothing. |

The security-critical boundary is between **an authenticated MQTT client** and
**everyone else on the network**.

## The remote command channel (`btmqttd`)

`btmqttd` opens **one** MQTT connection and subscribes to a command topic
(`TOPIC_RX`, QoS 1, durable session). Commands fall into two tiers:

### Tier 1 — always available (event relay + gated device controls)

Raw OpenWebNet frames forwarded to the local gateway, plus the structured
light / lock / volume / call controls. These act only on the intercom's own
OWN bus and are the intended, benign function of the bridge. They are still
reachable only by a client that can publish to the broker's command topic — so
the **broker ACL is the access-control boundary** for them.

### Tier 2 — `read_file` / `write_file` / `execute_command` (the shell gate)

This is the high-value, high-risk capability: arbitrary file read/write and
command execution on the device rootfs. It is protected by **two independent
conditions, both required**:

1. **`ALLOW_REMOTE_SHELL=1`** must be set in `btmqttd.conf`. This is **off by
   default** and is a deliberate, clearly labelled opt-in in the installer.
2. **The MQTT client must be authenticated** to the broker. An unauthenticated
   publisher is rejected regardless of the flag.

With the flag off (the default), Tier 2 does not exist — the commands are
refused. This is the primary trust boundary of the whole system, and it is the
single most important thing to lock down. It is covered by automated tests in the
`btmqttd` Rust suite (`cargo test`) across the auth/TLS matrix.

### Dependencies and caveats

- **Broker ACL dependency.** `btmqttd` trusts that the broker enforces
  publish/subscribe ACLs. If *any* client can publish to the command topic, that
  client inherits whatever tier is enabled. Configure per-client ACLs so only
  intended clients (e.g. Home Assistant) can reach the command topic.
- **Cleartext without TLS.** If the broker link is plaintext (`1883`), a LAN
  attacker can read and inject MQTT traffic. Command payloads and events are then
  exposed, and — absent broker auth — injectable. **Use TLS (`8883`) with client
  authentication** whenever Tier 2 is enabled; the installer supports a pinned CA
  / mTLS configuration. Plaintext is a convenience for trusted-LAN, event-only
  deployments, not a secure command channel.
- **Availability, not integrity, on the internal bus.** The bridge talks to the
  device's own OWN services over loopback; it does not defend against a
  compromised device, only against remote network abuse of the exposed channel.

## Broker rediscovery trust gate

`btmqttd` can optionally rediscover a broker whose LAN IP changed
([#43](../../issues/43)). Rediscovery only ever *proposes* an address — adoption
is gated by the reconnect:

- **With TLS**, the reconnect validates the broker's **pinned certificate**, so a
  proposed host that is not the real broker fails the handshake and is never
  adopted.
- **Without TLS**, a candidate is adopted only when its ARP MAC matches the
  broker MAC captured during *Test connection* — a **trusted-LAN convenience, not
  authentication**.

The `/24` scan fallback is rate-limited, capped to a `/24`, and every candidate
still passes the trust gate above. The recommended configuration remains a DHCP
reservation + hostname, which never exercises rediscovery at all.

## SSH access

SSH is opt-in. When enabled, the installer provisions Dropbear key-login and
host keys:

- An optional **ECDSA P-256 host key** ([#37](../../issues/37)) so modern clients
  connect (the device's Dropbear 2017.75 predates Ed25519 host-key support).
  ECDSA — not Ed25519 — is chosen for exactly that compatibility reason.
- A **stable RSA host key** pinned via `DROPBEAR_RSAKEY` ([#38](../../issues/38)),
  fixing the factory behavior where a fresh RSA host key was regenerated every
  boot (the init copies the stable factory key to a volatile path only at
  runlevel 4, but the unit boots to runlevel 5). A stable host key is what makes
  client-side host-key pinning meaningful.

No `authorized_keys` mechanism exists in the factory firmware; it is created
solely by opting in. Access is guarded by the factory `/home/root` mode
(`0700 root:root`), so key files are unreachable by other users regardless of the
`.ssh` directory mode.

## Firmware integrity

- Official firmware, if downloaded through the tool, is verified byte-for-byte
  (size + SHA-256) against the known-good original before use.
- The embedded `btmqttd` ARM binary is guarded in CI by a two-tier provenance
  check ([#72](../../issues/72)/[#76](../../issues/76)): its committed SHA-256 +
  size must match the metadata, **and** a rebuild from fully pinned inputs must be
  byte-for-byte identical. A supply-chain substitution of the binary fails CI.
- Released desktop builds carry SHA-256 checksums and a SLSA provenance
  attestation.

## Non-goals / out of scope

- Defending a device an attacker already physically controls, or the underlying
  BTicino/Legrand firmware and its services.
- Security of the user's MQTT broker or Home Assistant instance (configure their
  auth/ACLs per their own documentation).
- Protecting misuse of opt-in features on a device or network the operator does
  not own.
- Confidentiality of MQTT traffic when the operator deliberately runs the broker
  link in plaintext.
