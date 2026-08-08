# Third-party notices — Windows desktop release

The Windows build of **IntercomFirmwareTool** (the `.exe` and the DLLs beside it)
bundles the third-party native components listed below, in addition to the .NET
runtime. This file records each component's origin, license, and — for the
copyleft component — the corresponding-source obligation. It is distributed with
every release and referenced from the [README](README.md#releases).

> The `licenses/…-LICENSE.txt` links below are repository paths; they also resolve
> **inside the loose-folder `.zip`**, which keeps the `licenses/` subdirectory. On
> the GitHub **Releases page** the same texts appear as flat standalone assets
> (`lwext4-LICENSE.txt`, `DiskPartitionInfo-LICENSE.txt`) beside this file.

The application's **own source code is MIT-licensed** ([`LICENSE.txt`](LICENSE.txt)).
Because the release binary statically embeds a GPL-2.0 component (`lwext4`, via
`SharpExt4.dll`), the **release binary as an aggregate is conveyed under the terms
of the GNU GPL v2** — its corresponding source is this repository (MIT) plus the
upstream sources named below. See [`CLEANROOM.md`](CLEANROOM.md) for the full
licensing reasoning.

> This document is an engineering/compliance record, not legal advice.

---

## Components

### `SharpExt4.dll` — SharpExt4 (C++/CLI wrapper) + statically-linked lwext4

- **SharpExt4 (the wrapper):** a mixed-mode C++/CLI assembly that exposes ext4
  read/write to .NET.
  - Source: <https://github.com/nickdu088/SharpExt4>
  - **License status: UNRESOLVED.** The upstream repository declares no `LICENSE`
    file and states no license terms, so no explicit redistribution grant exists
    for the wrapper's own code. Clarification/permission is being sought from the
    author (see the tracking issue [#98](https://github.com/jorgeavlobo/intercom-firmware-tool/issues/98)).
    Until that is resolved, redistribution of `SharpExt4.dll` is **not fully
    authorized**, independently of the GPL obligations below.

- **lwext4 (compiled into the same DLL):**
  - Source: <https://github.com/gkostka/lwext4>
  - **License: GPL-2.0.** Per lwext4's own README, `ext4_xattr.c` and
    `ext4_extents.c` are GPLv2, which makes the whole library GPLv2 (the other
    modules are BSD-3-Clause). Full license text:
    [`licenses/lwext4-LICENSE.txt`](licenses/lwext4-LICENSE.txt).
  - Corresponding source: see the **Written offer** below.

### `DiskPartitionInfo.dll` — DiskPartitionInfo

- MBR/GPT parsing used by SharpExt4.
- Source: <https://github.com/f1x3d/DiskPartitionInfo>
- **License: MIT**, Copyright (c) 2021 f1x3d. Full text:
  [`licenses/DiskPartitionInfo-LICENSE.txt`](licenses/DiskPartitionInfo-LICENSE.txt).

### `Ijwhost.dll` — .NET C++/CLI host shim

- The runtime host that loads the mixed-mode `SharpExt4.dll`. Part of the
  Microsoft .NET runtime, distributed under the **MIT License**
  (<https://github.com/dotnet/runtime>).

---

## Written offer for corresponding source (GPL-2.0, for `lwext4`)

The `lwext4` code embedded in `SharpExt4.dll` is licensed under the GNU General
Public License, version 2. In accordance with that license, the **complete
corresponding source** for the GPL-2.0 portions is available from:

- **lwext4:** <https://github.com/gkostka/lwext4>
- **the wrapper that compiles it:** <https://github.com/nickdu088/SharpExt4>

For **three (3) years** from the date of each release, the maintainer of this
project will, on request, provide the complete corresponding source for the
GPL-2.0 `lwext4` code contained in the `SharpExt4.dll` shipped with that release —
open an issue at
<https://github.com/jorgeavlobo/intercom-firmware-tool/issues>.

> **To finalize (tracked in [#98](https://github.com/jorgeavlobo/intercom-firmware-tool/issues/98)):**
> pin the exact upstream revision (`SharpExt4` commit + the `lwext4` revision it
> vendors) that the shipped `SharpExt4.dll` was built from, and mirror that source
> in this repository so the offer is self-contained rather than dependent on the
> upstream repositories staying online.
