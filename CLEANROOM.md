# Clean-room reimplementation methodology

This project is **MIT-licensed** and carries **no GPL-licensed content** in its
source or its releases. This document records how that is achieved and defended:
the tool reproduces the *functional result* of prior GPL-2.0 work through an
independent implementation, without copying any GPL source.

It complements the provenance record in
[`reference/fquinto/README.md`](reference/fquinto/README.md) and the licensing
note in
[`IntercomFirmwareTool.Core/Payload/mqtt/README.md`](IntercomFirmwareTool.Core/Payload/mqtt/README.md).

## The principle

Interfaces and factual results — file paths, TCP ports, MQTT topic names,
configuration-key names, file layout, permissions, and ordering — are **facts
about how the device works**. Reproducing those facts to interoperate with the
device is not copying an author's creative expression. What we never do is
translate or transcribe the upstream *code*.

Concretely:

- **Reproduced (facts / interface):** the set of rootfs edits needed to enable a
  feature; the OpenWebNet socket addresses; the MQTT topic and configuration-key
  names; the on-device file layout and permissions.
- **Never reproduced (expression):** the upstream source code — not copied, not
  translated line-by-line, not adapted. Our implementations are written from the
  interface description, not from the other project's code.

## Prior work referenced (GPL-2.0, not vendored)

The firmware-preparation behavior was first demonstrated by
**fquinto/bticinoClasse300x** (`main.py`), which is **GPL-2.0**. To keep this
repository free of GPL content, that file is **not included in the tree**.
Instead, [`reference/fquinto/README.md`](reference/fquinto/README.md) records:

- its exact provenance (upstream URL, author, license, fetch date);
- a deterministic **content anchor** (MD5 + line count + upstream version) so the
  interface facts we replicate can be re-verified against a specific revision,
  with a change-detection signal if upstream shifts;
- a **line-number map** of *what each section does* (the factual edits) — used
  only to confirm exact paths, contents, permissions, and ordering.

Anyone who fetches `main.py` via that URL for their own reference holds a
GPL-2.0 copy governed by its own terms; that does not affect this MIT project,
which never bundles it.

## What we reimplemented, independently

- **The firmware-preparation edits.** A clean-room C#/WPF implementation of the
  *result* (SSH users, key-login, host-key handling, init symlinks, permissions),
  written from the interface map rather than from the upstream script. Design
  rationale lives in [`docs/WRITE_PHASE_PLAN.md`](docs/WRITE_PHASE_PLAN.md).
- **The MQTT bridge (`btmqttd`).** An independent, statically-linked **Rust**
  daemon ([`native/btmqttd/`](native/btmqttd)) that reproduces only the
  *interface* of the earlier shell-orchestrated bridge — topic names, ports,
  config keys, file layout. It shares no code with any prior implementation, and
  it replaced the entire previous shell/Python payload (`filter.py`,
  `StartMqttSend`/`StartMqttReceive`, `keypress.sh`, `ha_discovery.sh`,
  `mqtt_common.sh`, `TcpDump2Mqtt`).
- **The service watchdog.** `bt_service_watchdog` is an MIT clean-room
  reimplementation of fquinto's `mqtt_scripts/bt_service_watchdog` (GPL-2.0); no
  upstream source is copied.

## Removing copyleft dependencies

The native rewrite also removed the copyleft obligations the old payload carried
through vendored userland tools:

- **`jq`** (bundled a static build linking **LGPL-2.1** glibc) → replaced by the
  `serde_json` Rust crate.
- **`evtest`** (**GPL-2.0-or-later**) → replaced by the pure-Rust `evdev` crate.

The 64 third-party crates that end up in the shipped binary (as inventoried in
the notice file below; `Cargo.lock` additionally lists build-only and
target-specific crates that are not linked in) are **all permissive**
(MIT / Apache-2.0 / ISC / BSD-3-Clause / Unicode-3.0 — no copyleft). This is not
just asserted; it is **enforced in CI**: `cargo-deny` checks the dependency
graph's licenses against a permissive-only allow-list
([`native/btmqttd/deny.toml`](native/btmqttd/deny.toml)), and `dependency-review`
blocks a pull request that *adds* a non-permissive (or vulnerable) dependency to
either the NuGet or the Cargo graph. Aggregated notices are in
[`IntercomFirmwareTool.Core/Payload/vendor/licenses/btmqttd-THIRD-PARTY-LICENSES.txt`](IntercomFirmwareTool.Core/Payload/vendor/licenses/btmqttd-THIRD-PARTY-LICENSES.txt).
Separately — and not a licensing check — the committed binary's byte-for-byte
provenance and integrity are recorded in
[`IntercomFirmwareTool.Core/Payload/vendor/THIRD_PARTY.md`](IntercomFirmwareTool.Core/Payload/vendor/THIRD_PARTY.md)
and enforced by the provenance workflow.

## Why this holds up

- **No GPL source is present** in the repository or its releases — the one
  GPL reference file is deliberately kept out of the tree, recorded only by
  provenance.
- **Only interface facts were reproduced**, from a documented map, not from
  transcribed code.
- **Copyleft runtime tools were eliminated**, and their absence is enforced by
  automated license scanning on every PR.

Together these keep the MIT claim defensible: the repository is an independent
work that interoperates with the device, not a derivative of GPL-2.0 code.

> This document explains the licensing methodology; it is not legal advice.
