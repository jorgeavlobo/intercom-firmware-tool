# Project context for AI assistants

If you are an AI reviewing or contributing to this repository, read this first.

## What this project is

**IntercomFirmwareTool** is a **C#/WPF desktop application for Windows**
(.NET, **x64**) that prepares firmware images for a BTicino video intercom
(Classe 100X / 300X family).

Its purpose is to **replicate, on Windows, what the fquinto project's Python
script does on Linux** — but as a native Windows GUI tool, without needing
Linux, WSL, root, or `mount`.

- **Upstream we replicate:** https://github.com/fquinto/bticinoClasse300x
- **A verbatim copy of that script is in this repo** for offline reference:
  [`reference/fquinto/main.py`](../reference/fquinto/main.py) (GPL-2.0, external
  reference only — do **not** copy its code into our C# sources; we reimplement
  the *result*, clean-room).
- **The write-phase design** is in
  [`docs/WRITE_PHASE_PLAN.md`](WRITE_PHASE_PLAN.md).

## The core technical problem

The firmware payload is a Linux **ext4** filesystem. On Windows you cannot
`mount` ext4. fquinto uses `sudo mount -o loop` + shell tools (`cp`, `chmod`,
`ln -s`, `openssl passwd`); we cannot.

So we use **SharpExt4** — a .NET wrapper over the native **lwext4** C library —
to read and write the ext4 filesystem directly from Windows, then repackage.

- SharpExt4 is a **mixed-mode C++/CLI** assembly; its native part (`Ijwhost.dll`)
  is **x64-only**, so the whole app must be x64 and those DLLs must sit next to
  the executable. This is why the project pins `PlatformTarget=x64` and flattens
  the SharpExt4 DLLs to the output root via `TargetPath`.

## The pipeline (fquinto → us)

```
.fwz  (ZIP with ZipCrypto password, per model: C100X / C300X / SMARTDES)
  └─ btweb_only.ext4.gz   ── gunzip ──►  btweb_only.ext4   (a *bare* ext4 image)
        └─ modify the rootfs (enable SSH / root, etc.)
        └─ gzip back, repackage into a new .fwz
```

**Read chain** (done and proven on real firmware): open `.fwz` → try the known
passwords → select the `.gz` payload (name ends `.gz`, not `recovery`) → gunzip
→ read files from the ext4.

**Write phase** (done — see the status snapshot below): apply fquinto's rootfs
edits (create the SSH authorized_keys, the `/home/root/.ssh` dir, `/etc/shadow`
+ `/etc/passwd` entries, and the `S98dropbear` rc5.d symlink), then recut and
repackage.

## Important implementation detail: bare ext4 has no partition table

SharpExt4's `ExtDisk.Open` requires a **partitioned disk** (it runs
`ext4_mbr_scan`). The firmware payload is a **bare** ext4 (filesystem only, no
MBR). So we **wrap** the bare image in a temporary MBR disk (one Linux partition
at the 1 MiB offset), operate on it, then **recut** the partition region back
out to a raw ext4 of the same size. This wrapping/recut is internal plumbing,
not a change to the ext4 itself.

## Guiding principles (please respect these in reviews/changes)

1. **Replicate fquinto faithfully first.** Same paths, contents, permissions,
   symlink target. Innovate only after we match fquinto and validate.
2. **Read-only until validated.** The tool operates on **temp copies**; it never
   modifies the user's original `.fwz`, and the test buttons produce **no
   flashable firmware**.
3. **Validate logically, not byte-for-byte.** Two ext4 images with the same
   logical changes are never bit-identical (free-block allocation, timestamps).
   Compare file contents, modes, owners and symlink targets.
4. **SharpExt4 differences from fquinto must be handled explicitly.** fquinto
   mounts as root, so it gets `root:root` ownership for free and relies on the
   root umask for directory modes. We do **not** — we call `SetOwner(0,0)` and
   `SetMode(...)` explicitly on every new file/dir. Missing this would make
   dropbear reject the SSH key. One **deliberate divergence**: we set
   `/home/root/.ssh` to `0700`, whereas fquinto's `mkdir` leaves it at `0755`.
   Both satisfy dropbear/OpenSSH `StrictModes` (not group/other-writable), so
   both work; ours is just tighter. `ValidateSsh` therefore checks the
   **functional requirement** (not group/other-writable) rather than an exact
   mode, so both our and fquinto's output PASS.
5. **Passwords:** fquinto uses `openssl passwd -1` (MD5-crypt, `$1$`, salt
   `root`). We reimplement md5crypt in C# (`Md5Crypt.cs`), validated against a
   known test vector. Do not "modernize" to SHA-512 while replicating — that
   would diverge from fquinto.
6. **Safety:** nothing is flashed to a device from this tool. Any real flashing
   is a manual, out-of-band step the user does with recovery (USB/SAM-BA) ready,
   only after golden cross-validation against fquinto passes.

## Where things live

- `IntercomFirmwareTool.Core/` — the logic (no UI):
  - `Ext4Probe.cs` — read/write ext4 (wrapping, reading, the Phase A–D write
    routine `EnableSsh`, and `ValidateSsh`).
  - `FwzProbe.cs` — the `.fwz` chain (SharpZipLib ZipCrypto, gunzip, orchestration).
  - `Md5Crypt.cs` — the `$1$` MD5-crypt generator + self-test.
  - `lib/SharpExt4/` — the SharpExt4 + lwext4 binaries (x64 native).
- `IntercomFirmwareTool.App/` — the WPF UI. A single product flow: choose the
  original `.fwz`, an SSH public key and an output path, then **Build** a
  modified `.fwz` (verified by a full read-back round-trip). Two secondary
  actions **Verify an existing `.fwz`** and run the **MD5-crypt self-test**.
  A startup line reports 64-bit + DLL presence; it turns red if anything is off.
- `reference/fquinto/main.py` — the upstream script (reference only).
- `docs/WRITE_PHASE_PLAN.md` — the detailed write-phase plan.

## Status snapshot

- ✅ Read chain proven on real firmware (`/etc/hostname` → `Bticino_Classe_100_X`).
- ✅ ext4 write persists (`CanWrite=True`, survives flush + raw round-trip).
- ✅ MD5-crypt generator matches `openssl passwd -1` (self-test ALL PASS).
- ✅ Phase A–D write routine + logical validation (17 checks PASS on real firmware).
- ✅ Repackaging (re-gzip + ZipCrypto re-zip) round-trips through our read chain.
- ✅ **Golden cross-validation done** — fquinto (Docker/Linux) run on the same
  input produced the identical MD5-crypt hash, and its output `.fwz` passes our
  validator (the only divergence being our deliberate `.ssh` 0700-vs-0755
  hardening, which the functional-requirement check accepts on both sides).
- ✅ Product UI — a single Build flow (choose .fwz + key + output → build +
  verify), plus Verify-existing and self-test actions.
- ⏳ Next (user's call): optional real-device flashing with USB/SAM-BA recovery
  ready; optional 100%-faithful extras (e.g. fquinto's patch_github.xml edit).
