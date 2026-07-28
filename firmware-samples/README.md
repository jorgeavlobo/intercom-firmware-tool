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
└── <FWZ-STEM>__<Line>-<Model>-v<Version>/
    └── btweb_only.ext4.gz                       (git-ignored)
```

- **`<FWZ-STEM>`** — the original `.fwz` filename without extension, so the
  folder always ties back to the exact source file.
- **`<Line>-<Model>-v<Version>`** — the human-readable decode of that stem.

Decoding the stem `C100X_010508`:

| Part      | Meaning                          |
| --------- | -------------------------------- |
| `C100X`   | BTicino **Classe 100X16E** (model) |
| `010508`  | firmware **v1.5.8** (`01.05.08`) |

## Catalog

| Folder                                   | Source `.fwz`        | Device                         | Firmware |
| ---------------------------------------- | -------------------- | ------------------------------ | -------- |
| `C100X_010508__Classe-100X16E-v1.5.8/`      | `C100X_010508.fwz`   | BTicino Classe 100X16E           | v1.5.8   |

_(Add a row per image.)_

## Adding a new sample

1. Take the original `<NAME>.fwz`.
2. Open it with 7-Zip (or any ZIP tool) using the password (the model code, e.g.
   `C100X`) and extract **`btweb_only.ext4.gz`**.
3. Create `firmware-samples/<NAME>__<Line>-<Model>-vX.Y.Z/` and drop the
   `btweb_only.ext4.gz` inside.
4. Add a row to the [Catalog](#catalog) above.

## Extracting / inspecting the ext4 (Linux / WSL)

```sh
cd firmware-samples/C100X_010508__Classe-100X16E-v1.5.8
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
