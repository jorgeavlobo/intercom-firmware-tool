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
  verified official image plus the documented project payload (the `btmqttd`
  daemon, its config, discovery JSON, init scripts) and the opt-in components you
  explicitly selected (e.g. SSH host keys) — and nothing else.

## Actors and trust boundaries

| Actor | Trust | Notes |
|---|---|---|
| The user (operator) | Trusted | Owns the device; makes every opt-in choice. |
| The desktop app | Trusted, offline w.r.t. the device | Never flashes; only prepares an image. |
| The MQTT broker | Semi-trusted transport + **authorization point** | The bridge authenticates *to* it; the broker's own client authentication + topic ACLs decide who may publish commands (below). TLS protects and authenticates the *connection*, not publishers. |
| An MQTT publisher authorized on the command topic | Trusted **only** for the capabilities the broker's ACL grants it | e.g. Home Assistant. An anonymous or mis-ACLed client must not be allowed to publish commands. |
| A LAN peer / network attacker | Untrusted | Can see/replay/inject traffic if TLS is off. TLS stops it tampering with the connection, but does **not** by itself authorize publishers — broker auth + ACLs do. |
| The internet | Untrusted | Two outbound paths only: the startup update check (downloads nothing), and — when you choose it — the **official-firmware download** from the Legrand/BTicino servers, which fetches the `.fwz` and then verifies it byte-for-byte (size + SHA-256) before use. |

The security-critical boundary is between **a publisher the broker authorizes on
the command topic** and everyone else on the network. `btmqttd` itself does not
authenticate individual publishers — MQTT delivers it no per-message identity —
so **the broker's authentication + topic ACLs are the authorization layer**. This
is the single most important thing to configure correctly.

## The remote command channel (`btmqttd`)

`btmqttd` opens **one** MQTT connection and subscribes to a command topic
(`TOPIC_RX`, QoS 1, durable session). Because the session is durable and QoS 1 is
*at-least-once*, the broker may deliver a **delayed or duplicated** command after
a reconnect. The command worker preserves order and bounds its queue, but it has
no message-id, expiry, or de-duplication guard — so a replayed command **repeats
its effect** (a second `light_press`, lock toggle, `volume_step`, or file/exec
command). Treat commands as non-idempotent and rely on the transport (TLS +
broker ACL) to keep the topic private, rather than on in-daemon replay defence.
Commands fall into two tiers:

### Tier 1 — always available (event relay + device controls)

Raw OpenWebNet frames forwarded to the local gateway, plus the structured
light / lock / volume / call controls. These act on the intercom's own OWN bus
and are the bridge's intended function. Their access control is entirely the
**broker ACL**: any publisher the broker admits to the command topic can invoke
them. Note that **`lock` is not benign** — it drives the physical access-control
asset (the highest-value asset above). It has no independent authorization,
replay protection, or audit inside the bridge, so a publisher authorized on the
command topic can open the door; lock down the command-topic ACL accordingly and
prefer TLS so the channel cannot be sniffed or injected on the LAN.

### Tier 2 — `read_file` / `write_file` / `execute_command` (the shell gate)

This is the high-value, high-risk capability: arbitrary file read/write and
command execution on the device rootfs. It is protected by **two independent
conditions, both required**:

1. **`ALLOW_REMOTE_SHELL=1`** must be set in `btmqttd.conf`. This is **off by
   default** and is a deliberate, clearly labelled opt-in in the installer.
2. **The bridge's own broker connection must itself be credentialed** — either
   username + password, or full mTLS (CA + client certificate + key). `btmqttd`
   refuses to expose a root-capable channel over an anonymous/uncredentialed
   broker link (`Config::remote_shell_allowed`). This is a property of the
   bridge's *own* connection; it is **not** per-publisher authentication — the
   daemon receives no publisher identity and cannot authenticate the sender of an
   individual command.

With the flag off (the default), Tier 2 does not exist — the commands are
refused. This condition-2 self-check is covered by automated tests in the
`btmqttd` Rust suite (`cargo test`) across the auth/TLS matrix. **Crucially, it
does not decide *who* may publish** — that remains the broker's ACL (see below).
So if the broker admits an anonymous or over-privileged publisher to the command
topic while `ALLOW_REMOTE_SHELL=1`, that publisher reaches Tier 2. Restricting
the command topic to intended, authenticated clients is therefore mandatory
whenever the shell gate is enabled.

### Dependencies and caveats

- **Broker ACL dependency.** `btmqttd` trusts that the broker enforces
  publish/subscribe ACLs. If *any* client can publish to the command topic, that
  client inherits whatever tier is enabled. Configure per-client ACLs so only
  intended clients (e.g. Home Assistant) can reach the command topic.
- **Cleartext without TLS.** If the broker link is plaintext (`1883`), a LAN
  attacker can read and inject MQTT traffic — command payloads and events are
  exposed and injectable. Broker username/password auth is **not** a mitigation
  here: those credentials are themselves sent in cleartext, so the same attacker
  can capture and replay them. **Use TLS (`8883`) with client authentication**
  whenever Tier 2 is enabled; the installer supports a pinned CA / mTLS
  configuration. Plaintext is a convenience for trusted-LAN, event-only
  deployments, not a secure command channel.
- **Availability, not integrity, on the internal bus.** The bridge talks to the
  device's own OWN services over loopback; it does not defend against a
  compromised device, only against remote network abuse of the exposed channel.

## Broker rediscovery trust gate

`btmqttd` can optionally rediscover a broker whose LAN IP changed
([#43](../../issues/43)). Rediscovery only ever *proposes* an address — adoption
is gated by the reconnect:

- **With TLS**, the reconnect validates the broker's certificate against the
  **CA pinned at install time** (plus the optional mTLS client credentials), so a
  proposed host whose certificate does not chain to that CA fails the handshake
  and is never adopted. (This is CA validation, not leaf-certificate/fingerprint
  pinning.)
- **Without TLS**, a candidate is adopted only when its ARP MAC matches the
  broker MAC captured during *Test connection* — a **trusted-LAN convenience, not
  authentication**.

The scan fallback is rate-limited and sweeps the **union of the last-confirmed
`/24` and the immutable build-time `/24`** — up to two `/24`s (the same one when
the broker has not moved subnet) — and every candidate still passes the trust
gate above. The recommended configuration remains a DHCP reservation + hostname,
which makes an address change — and therefore *adoption* of a rediscovered
broker — unnecessary. (It does not guarantee the scan never runs: after several
consecutive connection failures — e.g. a prolonged broker outage or network
partition — the daemon still runs mDNS and, failing that, the bounded `/24`
sweep, regardless of the reservation.)

## SSH access

SSH is opt-in. Enabling SSH allows login by **root password and/or SSH public
key**; an `authorized_keys` entry (key-login) is provisioned **only when you
supply a public key** — a password-only build writes no `authorized_keys`. A
**separate, also-optional** "Modern SSH host key" setting (off by default) then
provisions the host-key improvements below; if it is left unchecked, neither
applies and the device keeps its factory host-key behavior (including the
per-boot RSA regeneration described below):

- An **ECDSA P-256 host key** ([#37](../../issues/37)) so modern clients connect
  (the device's Dropbear 2017.75 predates Ed25519 host-key support). ECDSA — not
  Ed25519 — is chosen for exactly that compatibility reason.
- A **stable RSA host key** pinned via `DROPBEAR_RSAKEY` ([#38](../../issues/38)),
  fixing the factory behavior where a fresh RSA host key was regenerated every
  boot (the init copies the stable factory key to a volatile path only at
  runlevel 4, but the unit boots to runlevel 5). A stable host key is what makes
  client-side host-key pinning meaningful — and it exists only when this option
  is enabled.

No `authorized_keys` mechanism exists in the factory firmware; it is created
solely by opting in. Access is guarded by the factory `/home/root` mode
(`0700 root:root`), so key files are unreachable by other users regardless of the
`.ssh` directory mode.

## Firmware integrity

- Official firmware, if downloaded through the tool, is verified byte-for-byte
  (size + SHA-256) against the known-good original before use.
- The embedded `btmqttd` ARM binary is guarded in CI by a two-tier provenance
  check ([#72](../../issues/72)/[#76](../../issues/76)): a metadata tier requires
  its committed SHA-256 + size to match `PayloadBinaries.cs`/`THIRD_PARTY.md`, and
  a reproduction tier rebuilds from fully pinned inputs and requires the result to
  be byte-for-byte identical to the committed binary. On PRs that touch the daemon
  the provenance workflow supplies that rebuild, so a supply-chain substitution of
  the binary fails CI.
- Released **desktop** builds (the Windows app) carry per-asset SHA-256 checksums
  and a SLSA build-provenance attestation from the release workflow. This is a
  distinct mechanism from the `btmqttd` binary provenance above.

## Non-goals / out of scope

- Defending a device an attacker already physically controls, or the underlying
  BTicino/Legrand firmware and its services.
- Security of the user's MQTT broker or Home Assistant instance (configure their
  auth/ACLs per their own documentation).
- Protecting misuse of opt-in features on a device or network the operator does
  not own.
- Confidentiality of MQTT traffic when the operator deliberately runs the broker
  link in plaintext.
