# Corresponding source — `SharpExt4.dll` (GPL-2.0)

This directory holds the **complete corresponding source** for the prebuilt
`SharpExt4.dll` that this project bundles
(`IntercomFirmwareTool.Core/lib/SharpExt4/SharpExt4.dll`). Because that DLL
statically links the GPL-2.0 `lwext4` library, the whole DLL is a **combined work**
based on `lwext4` (static linking makes a combined work under GNU guidance, not a
"mere aggregation"), conveyed under GPL-2.0, and its corresponding source must be
available (GPL-2.0 §3). This in-repo mirror makes that obligation **self-contained**
— it does not depend on any upstream repository staying online.

## Pinned snapshot

- **Archive:** [`SharpExt4-359d5f4.zip`](SharpExt4-359d5f4.zip)
- **SHA-256 (archive):** `1df3bb51b9fd09f11a79b28533b2c40bc11007b95e59b9bc3ced226995ce8b86`
- **Upstream (authoritative origin):** <https://github.com/nickdu088/SharpExt4>
- **Pinned commit:** `359d5f425ab58a61e37869e9223f339c8763b13b`
  (the commit id is also embedded as the ZIP's archive comment, so the snapshot is
  self-identifying)
- **Durable public mirror:** <https://github.com/jorgeavlobo/SharpExt4> — the same
  commit, in a fork controlled by this project's maintainer, so the source stays
  reachable even if upstream is removed.

## What the archive contains

The full source needed to rebuild the DLL:

- **`SharpExt4/`** — the mixed-mode C++/CLI wrapper (`.cpp`/`.h`) and its MSVC
  project files (`SharpExt4.vcxproj`, `SharpExt4.sln`).
- **`lwext4/`** — the vendored **GPL-2.0** `lwext4` C library (its `ext4_xattr.c` /
  `ext4_extents.c` are GPLv2, which makes the library GPLv2; the other modules are
  BSD-3-Clause — see the notices under [`../../licenses/`](../../licenses)).
- **`DiskPartitionInfo/`** — the MIT-licensed MBR/GPT helper.
- **`.github/workflows/msbuild.yml`** — the upstream build script (how the DLL is
  compiled), i.e. the scripts used to control compilation, as GPL-2.0 §3 requires.

## Binary ↔ source binding

The shipped binaries whose source **is** in this snapshot (SHA-256):

| File | SHA-256 |
| --- | --- |
| `SharpExt4.dll` | `b24f04afb4d317f8ae9c7510afb1dba41fc86175d6cbd2424a099c69eb1eef5e` |
| `DiskPartitionInfo.dll` | `fa1786b06df60d2dcb967992e736790cb80ab9a766410c63c5c14fb0f6d604e7` |

Companion binary whose source is **not** in this snapshot:

| File | SHA-256 | Source |
| --- | --- | --- |
| `Ijwhost.dll` | `9e955405b60acb095a89908d57fdd1d61e6454e91ae5b5ed5ab6804208ff1503` | Microsoft .NET runtime C++/CLI host shim (MIT) — from the .NET SDK, not from this archive. See [`../../licenses/dotnet-runtime-LICENSE.txt`](../../licenses/dotnet-runtime-LICENSE.txt). |

> **Provenance note (honest scope).** `SharpExt4.dll` is a **prebuilt** binary
> obtained from upstream; `359d5f4` is pinned as its corresponding source revision,
> but the project does **not** independently rebuild the DLL from this source, so
> byte-for-byte build-provenance is asserted, not proven. Rebuilding from this
> snapshot with MSVC (VS2022, C++/CLI, `Release`/`x64`, .NET 6) **is expected to
> reproduce** an equivalent DLL, though no build/comparison record is included here.
> Pinning to an exact rebuilt binary is tracked in
> [#98](https://github.com/jorgeavlobo/intercom-firmware-tool/issues/98).

See [`../../THIRD-PARTY-NOTICES.md`](../../THIRD-PARTY-NOTICES.md) for the full
licensing position and the GPL-2.0 §3(b) written offer.
