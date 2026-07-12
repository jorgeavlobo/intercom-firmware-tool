# Write-phase plan — faithful fquinto replication

**Goal:** make this C#/WPF tool produce a modified `.fwz` that is
**functionally identical** to what fquinto's `main.py` produces — same files,
same content, same permissions, same symlink — but via SharpExt4 instead of a
Linux `mount -o loop` (which is impossible on Windows).

**Principle:** replicate the *result*, not the *method*. Replicate faithfully
→ validate against fquinto → only then innovate. Everything is sandbox (temp
files) until validation passes; no flashable firmware is produced by the tests.

**Password decision:** replicate with **MD5-crypt (`$1$`)** — the primary
target, faithful to fquinto, with a test vector already validated (see §c).
**Plan B (documented):** set the shadow password field to `*`/`!` (key-only
SSH), used only if MD5-crypt in C# turns out to be problematic.

All operations below are verified against `reference/fquinto/main.py`
(line numbers verified in that copy).

---

## (a) Files touched vs untouched

Inside the `.fwz` — only 1 of the 4 entries is modified:

| Entry in the `.fwz` | Action |
|---|---|
| `btweb_only.ext4.gz` | ✏️ **modified** (the rootfs) |
| `btweb_only_recovery.ext4.gz` | ⬜ untouched, repacked as-is |
| `fwz.xml` | ⬜ untouched ¹ |
| `uImage.zip` | ⬜ untouched |

> ¹ Leaving `fwz.xml` untouched is safe **because fquinto leaves it untouched
> and its output works on real devices** → the updater does not verify a
> checksum/signature of the payload against `fwz.xml`. We rely on this
> empirical fact (and keep recovery ready before any flash).

Inside `btweb_only.ext4` — objects touched:

| Path | Action | Mode | Owner |
|---|---|---|---|
| `/etc/passwd` | append (2 lines) | (kept) | (kept) |
| `/etc/shadow` | append (2 lines) | (kept) | (kept) |
| `/home/root` | create if missing | — | 0:0 |
| `/home/root/.ssh` | create | **0700** | **0:0** |
| `/home/root/.ssh/authorized_keys` | create (public key) | **0600** | **0:0** |
| `/etc/dropbear` | create if missing | — | 0:0 if created |
| `/etc/dropbear/authorized_keys` | create (public key) | **0600** | **0:0** |
| `/etc/rc5.d/S98dropbear` | symlink → `../init.d/dropbear` | (symlink) | — |

---

## (b) Exact modification sequence (corrections integrated, in order)

**Phase A — accounts** (append; no dependencies):

1. Compute the MD5-crypt hash: `md5crypt(password, salt="root")` → `$1$root$…`.
   Default password `pwned123` (choosable). Same hash for both users.
2. **`/etc/passwd`** → ensure it ends with `\n` (correction #3), then append:
   - `root2:x:0:0:root:/home/root:/bin/sh`
   - `bticino2:x:1000:1000::/home/bticino:/bin/sh`
3. **`/etc/shadow`** → ensure `\n`, then append:
   - `root2:$1$root$…:18033:0:99999:7:::`
   - `bticino2:$1$root$…:18033:0:99999:7:::`

**Phase B — SSH key in root's home** (create parents first; set mode/owner
right after creating each object — corrections #1 and #2):

4. Ensure `/home` and `/home/root` exist (`mkdir -p` equivalent). If created,
   `SetOwner(0,0)`.
5. Create `/home/root/.ssh` → `SetMode(0700)` → `SetOwner(0,0)`.
6. Create `/home/root/.ssh/authorized_keys` (public key) → `SetMode(0600)` →
   `SetOwner(0,0)`.

**Phase C — SSH key in dropbear's path:**

7. Ensure `/etc/dropbear` exists.
8. Create `/etc/dropbear/authorized_keys` (public key) → `SetMode(0600)` →
   `SetOwner(0,0)`.

**Phase D — enable at boot:**

9. `CreateSymLink(target="../init.d/dropbear", path="/etc/rc5.d/S98dropbear")`.
   Prerequisite: `/etc/init.d/dropbear` and `/etc/rc5.d` must already exist.

> **Ownership (correction #1):** fquinto gets `root:root` for free (it mounts as
> root). We create via lwext4, so we must call `SetOwner(0,0)` on the **new**
> objects. `passwd`/`shadow` are appends → they keep their original inode,
> mode and owner, so they need nothing.

---

## (c) The MD5-crypt challenge + validated test vector

- **.NET has no built-in `crypt(3)`.** We implement md5crypt (`$1$`, the
  Poul-Henning Kamp algorithm) — see `IntercomFirmwareTool.Core/Md5Crypt.cs`.
- **Fixed salt `root`** (as fquinto). Both users share the same hash.
- **Golden test vector (validated by running real `openssl` during development,
  and by a self-test in the app):**
  ```
  md5crypt("pwned123", "root")  ==  $1$root$0i6hbFPn3JOGMeEF0LgEV1
  ```
  Also cross-checked against `openssl passwd -1` on many random inputs (empty
  passwords, salts of 1–8 chars, special characters) — 0 mismatches.
- **Implementation order:** the md5crypt generator is written and tested in
  isolation against the vector **before** touching the ext4. (Done — the app's
  "Test MD5-crypt" button reports ALL PASS.)
- **Plan B:** if md5crypt were problematic, set the shadow password field to
  `*`/`!` → key-only SSH (no password needed for key login).

---

## (d) C# write sequence (step by step)

Operating on the MBR-wrapped ext4 (RW), then recut to raw:

1. **Extract:** `.fwz` → password (`C100X`/`C300X`/`SMARTDES`) → select
   `btweb_only.ext4.gz` (ends in `.gz`, not `recovery`) → gunzip → bare `.ext4`
   (temp).
2. **Backup:** keep an untouched copy of the original bare ext4.
3. **Wrap** the bare ext4 in a temporary MBR disk.
4. **Open RW:** `ExtDisk.Open` + `ExtFileSystem.Open`; **guard `CanWrite`** —
   abort with a clear message if false.
5. **Apply Phase A–D** (§b), setting mode/owner right after each creation.
6. **In-memory self-check** (recommended): re-read each change before unmount.
7. **Dispose `fs` then `disk`** → flush + unmount (order matters; only then are
   all blocks written).
8. **Recut raw:** copy bytes `[1 MiB, 1 MiB + original size)` → modified bare
   `.ext4` (same format and size).
9. **Re-gzip:** modified `.ext4` → `btweb_only.ext4.gz`.
10. **Re-zip:** build a **new** `.fwz` with all 4 entries — the 3 originals
    copied byte-for-byte from the source zip, the modified entry replaced;
    ZipCrypto with the model password; **match the per-entry compression method
    of the original `.fwz`** (STORED vs DEFLATED — refinement #5).
11. **Output:** write to a **new** `.fwz`; the user's original is never touched.

---

## (e) Golden validation (logical, not byte-for-byte)

Before any flashing, prove our output equals fquinto's:

1. **Cross-validation:** run fquinto (Linux) and our tool on the **same** input
   `.fwz`, with the **same** password and public key. Extract both
   `btweb_only.ext4`.
2. **Logical comparison** (refinement #4 — the two ext4 images are **never**
   bit-identical: free-block allocation and inode timestamps differ). Compare:
   - `/etc/passwd` — the 2 identical lines;
   - `/etc/shadow` — the 2 lines, identical hash (fixed salt → identical);
   - `authorized_keys` (both) — content == public key;
   - `/etc/rc5.d/S98dropbear` — exists, target == `../init.d/dropbear`;
   - **modes** (`.ssh`=0700, `authorized_keys`=0600) **and owners** (0:0 on the
     new objects).
3. **Self-consistency:** reopen our modified ext4 (with our own tool) and re-read
   every change.
4. **Hash test vector:** the `$1$root$0i6hbFPn3JOGMeEF0LgEV1` check (§c).
5. **`.fwz` round-trip:** our repacked `.fwz` must be readable again by our own
   read chain (and ideally by fquinto's own unpack) without errors.

Only when all of this matches is replication done. **Only then** flash a real
unit (with USB/SAM-BA recovery ready), and **only then** consider innovations.

---

## (f) Honest caveats

- ⚠️ **MD5-crypt in C#** — must match the vector byte-for-byte (mitigated: we
  have the vector + a self-test; validated ALL PASS on real hardware).
- ⚠️ **SharpZipLib ZipCrypto *writing*** is still unproven — reading worked;
  producing a `.fwz` the device (or at least fquinto's unpack) accepts is the
  critical test. Per-entry compression method must match the original.
- ⚠️ **Ownership assigned by lwext4** to new objects is unknown — so
  `SetOwner(0,0)` explicitly on everything, without assuming.
- ⚠️ **`/etc/init.d/dropbear` must exist** in the image (fquinto relies on it).
- ⚠️ **Free space in the ext4** — additions are tiny (~1–3 KB); `ENOSPC` is
  theoretical but must surface as a clear error.
- ⚠️ **Home dir assumption** = `/home/root` (as fquinto) — the key goes there.
- ✅ Everything is sandbox until golden cross-validation passes. **No flashing
  before that**, and always with recovery ready.

---

## Implementation order (status)

1. **MD5-crypt generator** — isolated, tested against the vector. ✅ Done.
2. **ext4 write routine (Phase A–D) + recut** + logical validation. ✅ Done
   (the "APPLY SSH-enable (test)" button); pending on-device confirmation.
3. **Re-gzip + re-zip (ZipCrypto) + round-trip.** ⏳ Next.
4. **Golden cross-validation against fquinto.** ⏳ After step 3.
