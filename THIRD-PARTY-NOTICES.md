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
> (`THIRD-PARTY-NOTICES.md`, `LICENSE.txt`, `SharpExt4-LICENSE.txt`,
> `lwext4-LICENSE.txt`, `lwext4-BSD-3-Clause-NOTICE.txt`,
> `DiskPartitionInfo-LICENSE.txt`, `dotnet-runtime-LICENSE.txt`,
> `btmqttd-THIRD-PARTY-LICENSES.txt`, `ffmpeg-COPYING.LGPLv2.1.txt`,
> `musl-COPYRIGHT.txt`) accompanying it on
> the same release. Links to other repository documents (README, `CLEANROOM.md`)
> are absolute GitHub URLs so they resolve from anywhere.

## Licensing summary (read this first)

The two licensing questions here are **separate** and must not be conflated:

1. **`lwext4` is GPL-2.0.** It is statically compiled into `SharpExt4.dll`, so its
   GPL-2.0 terms attach to the shipped binary: its license text, the BSD-3-Clause
   notices for its BSD-licensed modules, and a corresponding-source path all have
   to travel with the release. Those obligations are addressed below.
2. **`SharpExt4` (the wrapper) is MIT-licensed.** Upstream now publishes an explicit
   **MIT** `LICENSE` (Copyright (c) 2021-2026 nickdu088), added via
   [nickdu088/SharpExt4#28](https://github.com/nickdu088/SharpExt4/pull/28) (issue
   [#27](https://github.com/nickdu088/SharpExt4/issues/27)), so the wrapper's own code
   carries a clear redistribution grant. MIT is **GPL-2.0-compatible**, so it does not
   conflict with the GPL-2.0 terms the `lwext4` link attaches to the combined binary.

Because `lwext4` is statically linked in, the compiled `SharpExt4.dll` is a
**combined work** based on `lwext4` (under GNU guidance, static linking makes a
combined work, not a "mere aggregation"), **conveyed under the GNU GPL v2**; the
MIT-licensed wrapper code within it is redistributable under both its own MIT grant
and, as part of the combined work, the GPL-2.0.
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
  - **License: MIT**, Copyright (c) 2021-2026 nickdu088. Upstream added an explicit
    `LICENSE` file via
    [PR #28](https://github.com/nickdu088/SharpExt4/pull/28) (issue
    [#27](https://github.com/nickdu088/SharpExt4/issues/27)), giving the wrapper's own
    code a clear redistribution grant. Full text:
    [`licenses/SharpExt4-LICENSE.txt`](licenses/SharpExt4-LICENSE.txt). The MIT terms
    cover the wrapper's own source; the GPL-2.0 obligations below still apply to the
    compiled DLL because of the statically-linked `lwext4`.

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

### Embedded ARM binaries (`btmqttd`, `ffmpeg`)

`IntercomFirmwareTool.Core` embeds two statically-linked **armv7 (musl)** binaries as
assembly resources. The tool writes **`btmqttd`** onto the BTicino intercom's firmware for
the optional MQTT bridge; **`ffmpeg`** is embedded for the upcoming on-device camera but is
**not yet written to the device** (a later phase installs it). Both ship inside this DLL, so
their notices travel with the release:

- **`btmqttd`** — first-party MQTT bridge daemon (built from this repo's
  `native/btmqttd/`). Its bundled Rust crates' notices (MIT / Apache-2.0 / ISC /
  BSD-3-Clause / Unicode-3.0):
  [`licenses/btmqttd-THIRD-PARTY-LICENSES.txt`](licenses/btmqttd-THIRD-PARTY-LICENSES.txt).
- **`ffmpeg`** — third-party, a minimal **LGPL-2.1-or-later** build of **FFmpeg `n7.1.1`**
  (unmodified upstream). **Corresponding source:** the complete, unmodified FFmpeg `n7.1.1`
  source **accompanies this release** — shipped as the asset **`ffmpeg-n7.1.1-source.tar.gz`**
  and bundled inside both `.zip` archives (the same pinned, SHA-256-verified tarball the binary
  is built from, so it provably matches). No changes to FFmpeg source were made; the exact build
  recipe is `native/ffmpeg/BUILD.md` in this project's repository. LGPL text:
  [`licenses/ffmpeg-COPYING.LGPLv2.1.txt`](licenses/ffmpeg-COPYING.LGPLv2.1.txt).
- **musl libc** (**MIT**) — statically linked into *both* binaries; its notice:
  [`licenses/musl-COPYRIGHT.txt`](licenses/musl-COPYRIGHT.txt).

Full provenance for these binaries — exact SHA-256, size, build toolchain, and
reproducible-build recipe — is recorded in the repository at
`IntercomFirmwareTool.Core/Payload/vendor/THIRD_PARTY.md`.

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

- **Pinned commit:** `nickdu088/SharpExt4@a9a41e1dcbc73a0ca38f7a89b1719dd794bbaa7e`
  (authoritative origin — the `main` commit that added the wrapper's MIT `LICENSE`),
  mirrored durably at `jorgeavlobo/SharpExt4` and archived in-repo as
  [`third_party/SharpExt4/SharpExt4-a9a41e1.zip`](third_party/SharpExt4/SharpExt4-a9a41e1.zip)
  (SHA-256 `17deba26c1dfaf04007ffa7bf337617ab9337ba1f25e8025d83d89eb57777d37`).
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
> `SharpExt4.dll` is a prebuilt upstream binary; `a9a41e1` is pinned as its
> corresponding-source revision but the project does not itself rebuild the DLL, so
> byte-exact build-provenance is asserted, not independently proven. The `SharpExt4`
> wrapper's **own license is now resolved** — upstream publishes an explicit MIT
> `LICENSE` at the pinned commit (see the component note above).
>
> **Remaining hardening (optional, tracked in [#98](https://github.com/jorgeavlobo/intercom-firmware-tool/issues/98)):**
> the source is now pinned + mirrored and the copyright notices are enumerated in
> [`licenses/lwext4-BSD-3-Clause-NOTICE.txt`](licenses/lwext4-BSD-3-Clause-NOTICE.txt);
> what is left is to *rebuild* the DLL from this snapshot in CI so build-provenance
> is proven rather than asserted.
