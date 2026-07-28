# Firmware samples

Reference copies of the **device root filesystem** extracted from BTicino
intercom firmware images, kept for analysis and development of the MQTT bridge
and other on-device payloads (e.g. confirming which runtime tools a given model
/ firmware version actually ships, before a build is accepted by
`MqttInstaller.ValidateMqtt`).

> ⚠️ **The firmware binaries themselves are NOT committed to this repository** —
> see [Redistribution & git](#redistribution--git) below. This folder tracks
> only the **structure + this documentation**; each person drops their own
> extracted files into the matching sub-folder locally.

## What a `.fwz` actually is

A BTicino `*.fwz` firmware file (e.g. `C100X_010508.fwz`) is a **ZipCrypto ZIP**
(password: `C100X`) containing **`btweb_only.ext4.gz`**. Gunzip that to get an
ext4 filesystem image (`btweb_only.ext4`) which is the **device's ROOT
filesystem**. That ext4 is what the tool modifies, and what we analyze here.

```
C100X_010508.fwz            ZipCrypto ZIP, password "C100X"
└── btweb_only.ext4.gz      gzip
    └── btweb_only.ext4     ext4 image = device root filesystem  ← analyze this
```

(The ZIP password is the **model code**, not a secret — it's the same for the
model line and is not the device's own password.)

## Layout & naming convention

One sub-folder per firmware image, holding its `btweb_only.ext4.gz`:

```
firmware-samples/
├── README.md                                   ← this file
├── .gitignore                                  ← keeps binaries out of git
└── <FWZ-STEM>__<Commercial-Ref>-<App>-v<Version>/
    └── btweb_only.ext4.gz                       (git-ignored)
```

- **`<FWZ-STEM>`** — the original `.fwz`/`.bin` filename stem (e.g.
  `C100X_010508`), so the folder always ties back to the exact source file.
- **`<Commercial-Ref>`** — the full commercial reference (e.g. `Classe-100X16E`,
  `Classe-300X13E`), **not** just the short model code.
- **`<App>`** — the paired mobile app (`DoorEntry` or `HomeSecurity`), PascalCase.
- **`v<Version>`** — the firmware version.

> **App axis (important).** BTicino ships the **same hardware** (e.g. Classe
> 100X16E / 300X13E) with **different firmware depending on the paired mobile
> app** — **Door Entry** or **Home + Security**. The `.fwz`/`.bin` stem does
> **not** encode the app, so the folder name carries it explicitly
> (`DoorEntry` / `HomeSecurity`). Determine it from the BTicino download page and
> confirm it in the image — e.g. the GUI's `MainPage.qml` shows `"Door Entry …
> App"`, and `etc/init.d/fwr_upgrade.sh` names the hardware bin (`C100X16E_hw*.bin`).

Decoding the folder `C100X_010508__Classe-100X16E-DoorEntry-v1.5.8`:

| Part             | Meaning                                             |
| ---------------- | --------------------------------------------------- |
| `C100X_010508`   | FWZ stem — model code `C100X`, firmware `010508`    |
| `Classe-100X16E` | commercial reference **Classe 100X16E**             |
| `DoorEntry`      | paired app **Door Entry** (vs `HomeSecurity`)       |
| `v1.5.8`         | firmware **v1.5.8** (`01.05.08`)                    |

## Catalog

| Folder                                                | Source               | Device                  | App             | Firmware |
| ----------------------------------------------------- | -------------------- | ----------------------- | --------------- | -------- |
| `C100X_010508__Classe-100X16E-DoorEntry-v1.5.8/`      | `C100X_010508.fwz`   | BTicino Classe 100X16E  | Door Entry      | v1.5.8   |
| `C100XR_020012__Classe-100X16E-HomeSecurity-v2.0.12/` | `C100XR_020012.fwz`  | BTicino Classe 100X16E  | Home + Security | v2.0.12  |
| `C100XR_020308__Classe-100X16E-HomeSecurity-v2.3.8/`  | `C100XR_020308.fwz`  | BTicino Classe 100X16E  | Home + Security | v2.3.8   |
| `C100XR_020311__Classe-100X16E-HomeSecurity-v2.3.11/` | `C100XR_020311.fwz`  | BTicino Classe 100X16E  | Home + Security | v2.3.11  |
| `C300X_010719__Classe-300X13E-DoorEntry-v1.7.19/`     | `C300X_010719.fwz`   | BTicino Classe 300X13E  | Door Entry      | v1.7.19  |
| `C3X2_010105__Classe-300X-HomeSecurity-v1.1.5/`       | `C3X2_010105.fwz`    | BTicino Classe 300X (344742/344743) | Home + Security | v1.1.5   |
| `MX_040012__Classe-300EOS-HomeSecurity-v4.0.12/`      | `MX_040012.fwz`      | BTicino Classe 300 EOS (344842/344884) | Home + Security | v4.0.12  |

_(Add a row per image. Same hardware + different app = a **separate** row, since
the firmware differs — see the App axis above. The **App** column shows the
human-readable app name — `Door Entry` / `Home + Security` — while the **folder**
name uses the filesystem-safe PascalCase token `DoorEntry` / `HomeSecurity`.)_

> ℹ️ **300X13E Door Entry v1.7.19** — the tool-recognised source is
> **`C300X_010719.fwz`**, registered in
> [`IntercomFirmwareTool.Core/FirmwareRegistry.cs`](../IntercomFirmwareTool.Core/FirmwareRegistry.cs)
> with its exact size + SHA-256/MD5. The folder is a placeholder awaiting the
> extracted `btweb_only.ext4.gz`. (Legrand also publishes the same release as an
> OTA `.bin`, `bt_344642_3_0_0-c300x_010719_1_7_19.bin` — but use the registered
> `.fwz`, which is the artifact the tool verifies.)

> ℹ️ **`C3X2_010105` (Classe 300X 344742)** and **`MX_040012` (Classe 300 EOS
> 344842)** are registered in `FirmwareRegistry.cs` (exact size + SHA-256/MD5),
> both **Home + Security**. (344742's `Classe 300X` is the newer Wi-Fi 6 unit,
> distinct from the older `Classe 300X13E` at 344642.)

## Adding a new sample

1. Take the original `<NAME>.fwz` (or `.bin` for OTA images).
2. Open it with 7-Zip (or any ZIP tool) using the password (the model code, e.g.
   `C100X`) and extract **`btweb_only.ext4.gz`**.
3. Identify the paired **app** (`DoorEntry` / `HomeSecurity`) — from the BTicino
   download page and/or the image (see the App axis above).
4. Create `firmware-samples/<NAME>__<Commercial-Ref>-<App>-vX.Y.Z/` and drop the
   `btweb_only.ext4.gz` inside.
5. Add a row to the [Catalog](#catalog) above.

## Extracting / inspecting the ext4 (Linux / WSL)

```sh
cd firmware-samples/C100X_010508__Classe-100X16E-DoorEntry-v1.5.8
gunzip -k btweb_only.ext4.gz                 # -> btweb_only.ext4 (keeps the .gz)
mkdir -p mnt
sudo mount -o loop,ro btweb_only.ext4 mnt    # read-only
ls -l mnt/usr/bin/python* mnt/bin/busybox    # e.g. inspect runtime deps
sudo umount mnt
```

(On Windows without WSL, the app's own **Inspect** function reads the ext4 via
DiscUtils; or use a tool like `ext2read`/`7-Zip` with an ext4 plugin.)

The uncompressed `btweb_only.ext4` and the `mnt/` mount point are **also
git-ignored** — only the compressed `.gz` sample is meant to live here, and even
that is ignored by default (below).

## Redistribution & git

BTicino firmware is **proprietary, copyrighted software**. It must **not** be
committed to a public repository (redistribution), and large binary blobs bloat
git history permanently. Therefore:

- `.gitignore` in this folder excludes `*.gz`, `*.ext4`, `*.fwz`, `*.img` — the
  firmware binaries **stay local** and are never pushed.
- Only this `README.md`, the `.gitignore`, and the (empty) folder structure are
  tracked.

**For Claude to analyze an image in a session:** because a remote Claude Code
session works from a *fresh clone*, git-ignored local files never reach it. So
sharing an image for analysis needs one of:

1. **Paste inspection output** — run the commands above (or the firmware-audit
   prompt) and paste the results. Best for a public repo; no firmware leaves your
   machine.
2. **A private data repo** — if you want Claude to read the raw ext4 directly,
   put the images in a **private** repository (never this public one) and add it
   to the session. Only do this where redistribution of the proprietary image is
   acceptable to you.

Do **not** remove the `.gitignore` entries to "just commit them" on the public
repo.
