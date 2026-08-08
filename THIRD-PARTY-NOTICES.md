# Third-party notices — Windows desktop release

The Windows build of **IntercomFirmwareTool** (the `.exe` and the DLLs beside it)
bundles the third-party native components listed below, in addition to the .NET
runtime. This file records each component's origin, license, and — for the
copyleft component — the corresponding-source obligation. It is distributed with
every release and referenced from the
[README](https://github.com/jorgeavlobo/intercom-firmware-tool/blob/master/README.md#releases).

> **Reading this from a release bundle?** The `licenses/…` links below are
> repository paths that also resolve **inside both `.zip` archives** (the portable
> `.zip` and the loose-folder `.zip`): `THIRD-PARTY-NOTICES.md` and `LICENSE.txt`
> sit at the archive root next to the executable, and the license texts are under
> the `licenses/` subdirectory (which is why the links resolve). The single-file
> portable `.exe`, by its nature, cannot embed sibling files — for that download the
> same documents travel as flat standalone assets on the GitHub **Releases page**
> (`THIRD-PARTY-NOTICES.md`, `LICENSE.txt`, `lwext4-LICENSE.txt`,
> `lwext4-BSD-3-Clause-NOTICE.txt`, `DiskPartitionInfo-LICENSE.txt`,
> `dotnet-runtime-LICENSE.txt`) accompanying it on the same release. Links to other repository documents (README, `CLEANROOM.md`)
> are absolute GitHub URLs so they resolve from anywhere.

## Licensing summary (read this first)

The two licensing questions here are **separate** and must not be conflated:

1. **`lwext4` is GPL-2.0.** It is statically compiled into `SharpExt4.dll`, so its
   GPL-2.0 terms attach to the shipped binary: its license text, the BSD-3-Clause
   notices for its BSD-licensed modules, and a corresponding-source path all have
   to travel with the release. Those obligations are addressed below.
2. **`SharpExt4` (the wrapper) has no stated license.** Upstream declares no terms,
   so there is **no explicit grant to redistribute `SharpExt4.dll` at all** — a
   blocker that is independent of, and not cured by, the GPL-2.0 items above.
   Clarification/permission is being sought (see
   [#98](https://github.com/jorgeavlobo/intercom-firmware-tool/issues/98)).

Because `lwext4` is statically linked in, the compiled `SharpExt4.dll` is a
**combined work** based on `lwext4` (under GNU guidance, static linking makes a
combined work, not a "mere aggregation"), which **would be conveyed under the GNU
GPL v2** *to the extent it may be redistributed at all* — which, per (2), is
currently unresolved.
Whether the application itself is a derivative work of `lwext4` or merely uses it
across a library boundary is **not settled here** and is part of #98. The
application's **own source code is MIT-licensed**
([`LICENSE.txt`](LICENSE.txt)); that is a statement about this repository's code,
not a conclusion about the combined binary. See
[`CLEANROOM.md`](https://github.com/jorgeavlobo/intercom-firmware-tool/blob/master/CLEANROOM.md)
for the full reasoning.

> This document is an engineering/compliance record, not legal advice.

---

## Components

### `SharpExt4.dll` — SharpExt4 (C++/CLI wrapper) + statically-linked lwext4

- **SharpExt4 (the wrapper):** a mixed-mode C++/CLI assembly that exposes ext4
  read/write to .NET.
  - Source: <https://github.com/nickdu088/SharpExt4>
  - **License status: UNRESOLVED.** The upstream repository declares no `LICENSE`
    file and states no license terms, so no explicit redistribution grant exists
    for the wrapper's own code. Until this is resolved (tracked in
    [#98](https://github.com/jorgeavlobo/intercom-firmware-tool/issues/98)),
    redistribution of `SharpExt4.dll` is **not fully authorized**, independently of
    the GPL obligations below.

- **lwext4 (compiled into the same DLL):**
  - Source: <https://github.com/gkostka/lwext4>
  - **License: GPL-2.0 (mixed tree).** Per lwext4's own README, most modules and
    headers are **BSD-3-Clause**, but `ext4_xattr.c` and `ext4_extent.c` are
    **GPLv2** — and because those are linked into the same library, the library as
    a whole is distributed under **GPL-2.0**. Both notices ship:
    - GPL-2.0 text: [`licenses/lwext4-LICENSE.txt`](licenses/lwext4-LICENSE.txt).
    - BSD-3-Clause notice (required to accompany binary redistribution of the
      BSD-licensed modules):
      [`licenses/lwext4-BSD-3-Clause-NOTICE.txt`](licenses/lwext4-BSD-3-Clause-NOTICE.txt).
  - **Corresponding source: pinned + mirrored.** The `lwext4` source (vendored
    inside SharpExt4) is included in the pinned corresponding-source snapshot at
    [`third_party/SharpExt4/`](third_party/SharpExt4); see the **Written offer**
    below for the full terms.

### `DiskPartitionInfo.dll` — DiskPartitionInfo

- MBR/GPT parsing used by SharpExt4.
- Source: <https://github.com/f1x3d/DiskPartitionInfo>
- **License: MIT**, Copyright (c) 2021 f1x3d. Full text:
  [`licenses/DiskPartitionInfo-LICENSE.txt`](licenses/DiskPartitionInfo-LICENSE.txt).

### `Ijwhost.dll` — .NET C++/CLI host shim

- The runtime host that loads the mixed-mode `SharpExt4.dll` (a native C++/CLI
  interop shim from the Microsoft **.NET runtime**,
  <https://github.com/dotnet/runtime>). It is the copy that ships **next to**
  `SharpExt4.dll` (from the SharpExt4 build); pinning its exact runtime version is
  part of #98.
- **License: MIT** (this file), Copyright (c) .NET Foundation and Contributors.
  Full text: [`licenses/dotnet-runtime-LICENSE.txt`](licenses/dotnet-runtime-LICENSE.txt).
- **Scope note:** this MIT text applies to `Ijwhost.dll` (an MIT-licensed
  dotnet/runtime component). The self-contained build *also* bundles the broader
  Microsoft .NET runtime; on Windows that redistribution is governed by the
  **Microsoft .NET Library License**, not blanket MIT — see Microsoft's
  component-licensing guidance
  (<https://github.com/dotnet/core/blob/main/license-information.md>). This notice
  does not relicense those files.

### `vcruntime140.dll` — Microsoft Visual C++ runtime

- The Visual C++ runtime that the mixed-mode `SharpExt4.dll` imports. It is bundled
  **app-local** by the release workflow — copied, **unmodified**, from the
  Microsoft-signed Visual C++ Redistributable on the CI runner (currently Visual
  Studio 2022), after verifying a valid `O=Microsoft Corporation` Authenticode
  signature.
- **License:** redistributed as **Distributable Code** under the **Microsoft
  Software License Terms** for the Visual Studio version used to build the app;
  `vcruntime140.dll` is on that version's **REDIST list**. It is shipped unmodified
  with Microsoft's copyright/trademark notices intact and is not covered by this
  project's MIT or the GPL-2.0 above. Terms and the redistributable-files list:
  <https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files>
  and <https://learn.microsoft.com/en-us/visualstudio/releases/2022/redistribution>.

---

## Written offer for corresponding source (GPL-2.0, for the whole `SharpExt4.dll`)

The `lwext4` code embedded in `SharpExt4.dll` is licensed under the GNU General
Public License, version 2; because it is statically linked into the DLL, the
**whole `SharpExt4.dll` is a combined work conveyed under GPL-2.0**, so a
**complete-corresponding-source** path for the entire DLL (not merely `lwext4`)
must accompany any GPL-conveying release.

**Status: source pinned + mirrored in this repository.** The complete corresponding
source for `SharpExt4.dll` (the `SharpExt4` wrapper, the vendored GPL-2.0 `lwext4`,
and the build scripts) is committed here as an immutable snapshot at
[`third_party/SharpExt4/`](third_party/SharpExt4):

- **Pinned commit:** `nickdu088/SharpExt4@359d5f425ab58a61e37869e9223f339c8763b13b`
  (authoritative origin), mirrored durably at
  `jorgeavlobo/SharpExt4@359d5f4` and archived in-repo as
  [`third_party/SharpExt4/SharpExt4-359d5f4.zip`](third_party/SharpExt4/SharpExt4-359d5f4.zip)
  (SHA-256 `1df3bb51b9fd09f11a79b28533b2c40bc11007b95e59b9bc3ced226995ce8b86`).
- The archived source travels with every release (see the release assets), so the
  binary is **accompanied by its source** (GPL-2.0 §3(a)) in addition to the offer
  below.

As a further guarantee, this is also an offer in the terms of **GPL-2.0 Section
3(b)**: for **at least three (3) years** from the date of each release, the
maintainer will give **any third party**, for a charge no more than the cost of
physically performing source distribution, a complete machine-readable copy of the
**complete corresponding source for the entire GPL-covered `SharpExt4.dll`**
conveyed with that release, on a medium customarily used for software interchange.
Because the whole DLL is a GPL-2.0 combined work, that corresponding source is
**not just `lwext4`** — per GPL-2.0 §3 it is everything needed to rebuild the
executable work: the **`SharpExt4` wrapper source**, the **embedded `lwext4`**, and
the **scripts used to control its compilation and installation** (all present in
the snapshot above). Request it by opening an issue at
<https://github.com/jorgeavlobo/intercom-firmware-tool/issues>.

The upstream source also remains at:

- **the wrapper (with vendored lwext4):** <https://github.com/nickdu088/SharpExt4>
- **lwext4 upstream:** <https://github.com/gkostka/lwext4>

> **Honest scope (tracked in [#98](https://github.com/jorgeavlobo/intercom-firmware-tool/issues/98)):**
> `SharpExt4.dll` is a prebuilt upstream binary; `359d5f4` is pinned as its
> corresponding-source revision but the project does not itself rebuild the DLL, so
> byte-exact build-provenance is asserted, not independently proven. Separately, the
> `SharpExt4` wrapper's **own license remains unresolved** (see the component note
> above) — that is a redistribution question independent of these GPL obligations.
>
> **Remaining hardening (optional, tracked in [#98](https://github.com/jorgeavlobo/intercom-firmware-tool/issues/98)):**
> the source is now pinned + mirrored and the copyright notices are enumerated in
> [`licenses/lwext4-BSD-3-Clause-NOTICE.txt`](licenses/lwext4-BSD-3-Clause-NOTICE.txt);
> what is left is to *rebuild* the DLL from this snapshot in CI so build-provenance
> is proven rather than asserted.
