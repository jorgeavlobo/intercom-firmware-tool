# Clean-room reimplementation methodology

This project's **own code is MIT-licensed** (top-level `LICENSE.txt`,
`Copyright (c) 2026 jorgeavlobo`), and it copies **no GPL-licensed *source***
into this repository: the tool reproduces the *functional result* of prior GPL-2.0
work through an independent implementation, without transcribing any GPL source.
This document records how that is achieved and defended.

One caveat up front, so this is not read as an absolute "no GPL anywhere" claim:
the **Windows release binary bundles one third-party GPL-2.0 component** —
`SharpExt4.dll`, which embeds the native `lwext4` library. That is disclosed and
handled separately below (and tracked in [#98](https://github.com/jorgeavlobo/intercom-firmware-tool/issues/98)); it does not come
from copying GPL source into this tree, and it does not change the clean-room
methodology described here.

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

The third-party crates that end up in the shipped binary (inventoried in the
notice file below; `Cargo.lock` additionally lists build-only and
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

## A bundled GPL-2.0 dependency: `SharpExt4` / `lwext4`

Reading and writing the device's ext4 rootfs (from inside the `.fwz`) is done via
**SharpExt4**, a mixed-mode C++/CLI wrapper over the native **`lwext4`** C library.
`lwext4` is **GPL-2.0** — its `ext4_xattr.c` / `ext4_extents.c` are GPLv2, which
makes the whole library GPLv2 (the rest of the modules are BSD-3-Clause, whose
notices must still travel with the binary) — and it is compiled into the shipped
`SharpExt4.dll`. So, unlike the clean-room items above, this is a genuine
**third-party GPL-2.0 binary that the Windows release distributes**.

This is **not** clean-room-reproduced GPL source — no `lwext4` source is copied
into or derived by this repository; it is a prebuilt dependency the release links
against. Its GPL-2.0 terms nonetheless apply to the distributed binary and must be
honored (license text, notices, and corresponding-source availability).

**What the release wiring already ships for GPL-2.0.** The release workflow
attaches [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md), the verbatim GPL-2.0
text ([`licenses/lwext4-LICENSE.txt`](licenses/lwext4-LICENSE.txt)), the
BSD-3-Clause notice for lwext4's BSD-licensed modules
([`licenses/lwext4-BSD-3-Clause-NOTICE.txt`](licenses/lwext4-BSD-3-Clause-NOTICE.txt)),
the app's own MIT text ([`LICENSE.txt`](LICENSE.txt)), the DiskPartitionInfo MIT
text, and the .NET-runtime MIT text (for `Ijwhost.dll`) as standalone release
assets (flat leaf names on the Releases page), and also copies them **inside both
`.zip` archives** (portable and loose-folder): `THIRD-PARTY-NOTICES.md` and
`LICENSE.txt` at the archive root beside the binary, the license texts under a
`licenses/` subdirectory (so the notice's links resolve). The app-local Microsoft
`vcruntime140.dll` is documented too.

**The corresponding-source obligation is now satisfied (source pinned + mirrored +
shipped).** The complete corresponding source for `SharpExt4.dll` — the `SharpExt4`
wrapper, the vendored GPL-2.0 `lwext4`, and the build scripts — is committed in-repo
as an immutable snapshot at [`third_party/SharpExt4/`](third_party/SharpExt4),
pinned to `nickdu088/SharpExt4@359d5f4` (mirrored durably at the maintainer's
`jorgeavlobo/SharpExt4` fork), and it is **shipped as a release asset** so the
binary is accompanied by its source (GPL-2.0 §3(a)) in addition to the written
§3(b) offer. The verbatim GPL-2.0 text and the common BSD-3-Clause notice ship too.
Two honest caveats remain (hardening, tracked in #98): the DLL is a prebuilt
upstream binary so byte-exact build-provenance is asserted rather than proven by a
CI rebuild, and the **exact per-file** BSD-3-Clause copyright notices for the pinned
revision are not yet transcribed.

**The remaining blocker — accepted as a known risk for v1.0.0.** The `SharpExt4`
*wrapper's own* license is UNRESOLVED — upstream declares no terms — so there is no
explicit grant to redistribute `SharpExt4.dll`, regardless of the GPL items above.
A license request is open upstream ([nickdu088/SharpExt4#27](https://github.com/nickdu088/SharpExt4/issues/27) /
[#28](https://github.com/nickdu088/SharpExt4/pull/28)); until the author responds,
the maintainer **knowingly accepts this redistribution risk** in order to ship
v1.0.0 (the practical exposure from a hobbyist author who publishes the DLL for
reuse is low, but it is not a formal grant). If the author later merges a license,
re-pin to that commit to clear the risk entirely. Whether the application is a
*derivative work* of `lwext4` or merely uses it across a library boundary is a
question deliberately left open; with the corresponding source now available it has
little practical bearing on distribution.

**Publishing decision.** The GPL-2.0 obligations for the bundled `lwext4` (license
texts, notices, and — now — pinned/mirrored/shipped corresponding source) are
handled, so v1.0.0 is publishable on that front. The one item that is *not* a
formal grant — the `SharpExt4` wrapper's unresolved license — is a risk the
maintainer **knowingly accepts** for this release; it is not a blocker imposed by
this document. The residual hardening (CI rebuild for proven provenance, per-file
BSD notices, and the author's license response) is tracked in
[#98](https://github.com/jorgeavlobo/intercom-firmware-tool/issues/98).

## Why this holds up

- **No GPL *source* is copied into the repository** — the one GPL reference file
  (`fquinto/main.py`) is deliberately kept out of the tree, recorded only by
  provenance. (The release *binary* separately bundles the third-party GPL-2.0
  `lwext4` via SharpExt4 — disclosed above and tracked in
  [#98](https://github.com/jorgeavlobo/intercom-firmware-tool/issues/98).)
- **Only interface facts were reproduced**, from a documented map, not from
  transcribed code.
- **Copyleft runtime tools were eliminated** — a one-time architectural change
  (`jq`/`evtest` removed in the Rust rewrite). CI's `cargo-deny` + `dependency-review`
  enforce the permissive-only policy over the **dependency graph**, so no copyleft
  crate can be pulled in; note this graph check does not scan arbitrary payload
  files, so reintroducing a copyleft *file* under the payload tree is caught by
  code review and this documented methodology, not by the license workflow.

Together these keep the MIT licensing for the project's **own code** defensible
(the MIT grant is in `LICENSE.txt`): it is an independent work that interoperates
with the device, not a translation of GPL-2.0 source. That statement is about this
repository's source; it is **not** a claim that the *combined binary* escapes
GPL-2.0, nor a ruling on whether the application is a derivative work of `lwext4`
(the app-vs-library boundary is left open — see #98). `lwext4` itself is a
third-party dependency that does not incorporate this project's code; its GPL-2.0
text, the common BSD-3-Clause notice, **and its pinned/mirrored corresponding
source** now ship with every release (see
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) and
[`third_party/SharpExt4/`](third_party/SharpExt4)). What remains for v1.0.0 is the
`SharpExt4` wrapper's unresolved license — a risk the maintainer knowingly accepts
for now — plus optional hardening (a CI rebuild for proven provenance and per-file
BSD notices), all tracked in
[#98](https://github.com/jorgeavlobo/intercom-firmware-tool/issues/98).

> This document explains the licensing methodology; it is not legal advice.
