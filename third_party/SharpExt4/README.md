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
- **SHA-256 (archive):** `375b321e33b1cf648606d9b86bc9d8383c1f7aa5f6ec82ee758a07b255bfe46f`
- **Upstream (authoritative origin):** <https://github.com/nickdu088/SharpExt4>
- **Pinned commit:** `359d5f425ab58a61e37869e9223f339c8763b13b`
- **Durable public mirror:** <https://github.com/jorgeavlobo/SharpExt4> — the same
  commit, in a fork controlled by this project's maintainer, so the source stays
  reachable even if upstream is removed.

> **One deliberate change vs. the raw upstream download.** Upstream ships the
> vendored `DiskPartitionInfo/` source without its MIT license file, so a bare copy
> of the archive would redistribute MIT-licensed source without the required notice.
> This archive therefore adds **`DiskPartitionInfo/LICENSE`** (the MIT text,
> Copyright (c) 2021 f1x3d) so the archive is self-contained; the archive comment
> records this. Everything else is the verbatim upstream tree at the pinned commit.
> To verify the upstream portion, download commit `359d5f4` from GitHub and compare
> (it matches except for the added `DiskPartitionInfo/LICENSE`); the raw GitHub
> download's own SHA-256 is
> `1df3bb51b9fd09f11a79b28533b2c40bc11007b95e59b9bc3ced226995ce8b86`.

## What the archive contains

The full source needed to rebuild the DLL:

- **`SharpExt4.sln`** (at the archive root) — the Visual Studio solution.
- **`SharpExt4/`** — the mixed-mode C++/CLI wrapper (`.cpp`/`.h`) and its MSVC
  project file (`SharpExt4.vcxproj`).
- **`lwext4/`** — the vendored **GPL-2.0** `lwext4` C library (its `ext4_xattr.c` /
  `ext4_extent.c` are GPLv2, which makes the library GPLv2; the other modules are
  BSD-3-Clause — see the notices under [`../../licenses/`](../../licenses)).
- **`DiskPartitionInfo/`** — the MIT MBR/GPT helper. Upstream omitted its license
  file, so this archive adds **`DiskPartitionInfo/LICENSE`** (the MIT text,
  Copyright (c) 2021 f1x3d — see the note above); the same text is also at
  [`../../licenses/DiskPartitionInfo-LICENSE.txt`](../../licenses/DiskPartitionInfo-LICENSE.txt).
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
