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

All operations below are verified against fquinto's `main.py` (upstream, GPL-2.0
— not vendored here). The exact line numbers, raw URL, and MD5 are in
[`reference/fquinto/README.md`](../reference/fquinto/README.md).

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
>
> ² **The `.ssh` dir is 0755, matching fquinto exactly.** Neither
> `/home/root/.ssh` nor any `authorized_keys` exists in the factory firmware —
> the whole key-login mechanism is created here (verified on the original image:
> factory `/home/root` has only `.bash_history` and `.cache`; `/etc/dropbear`
> has only `dropbear_rsa_host_key`). There is no "factory mode" to copy; 0755 is
> simply fquinto's `mkdir -p` under the default umask, replicated for fidelity.
> Security is guaranteed by the parent: factory `/home/root` is **0700
> root:root** (verified `drwx------`), so anything inside is unreachable by other
> users whether `.ssh` is 0755 or 0700. dropbear accepts 0755 (confirmed: key
> login works) — it only rejects a group/other-**writable** `.ssh`, which 0755
> is not. The validator checks that functional requirement, so 0755 PASSES
> (0770/0777 would FAIL).

Inside `btweb_only.ext4` — objects touched:

| Path | Action | Mode | Owner |
|---|---|---|---|
| `/etc/passwd` | append (2 lines) | (kept) | (kept) |
| `/etc/shadow` | append (2 lines) | (kept) | (kept) |
| `/home/root` | create if missing | — | 0:0 |
| `/home/root/.ssh` | create | **0755** ² | **0:0** |
| `/home/root/.ssh/authorized_keys` | create (public key) | **0600** | **0:0** |
| `/etc/dropbear` | create if missing | — | 0:0 if created |
| `/etc/dropbear/authorized_keys` | create (public key) | **0600** | **0:0** |
| `/etc/rc5.d/S98dropbear` | symlink → `../init.d/dropbear` | (symlink) | — |

---

## (b) Exact modification sequence (corrections integrated, in order)

**Phase A — accounts** (append; no dependencies):

1. Compute the MD5-crypt hash: `md5crypt(password, salt="root")` → `$1$root$…`.
   The password is entered by the user (or key-only login disables it); no
   default is pre-filled. Same hash for both users.
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
5. Create `/home/root/.ssh` → `SetMode(0755)` → `SetOwner(0,0)`.
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
10. **Re-zip:** build a **new** `.fwz` — the modified entry replaced, the other
    entries' **contents** re-added from the source zip, **except `.sig`
    signature sidecars, which are dropped** (fquinto removes them by default, and
    keeping a signature for the now-modified payload could get the archive
    rejected). Every entry is re-compressed **DEFLATE level 9** and encrypted with
    ZipCrypto under the model password. This mirrors fquinto's
    `pyminizip.compress_multiple(level=9)` (which likewise re-compresses, rather
    than preserving each entry's original method byte-for-byte).
11. **Output:** the build is written to a temp file in the output directory,
    round-trip-verified, and only then moved onto the chosen path; the user's
    original `.fwz` is never touched and a failed build leaves no output file.

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
   - **modes** — `authorized_keys`=0600 (exact); `.ssh`=0755 (matching fquinto),
     checked by the **functional requirement** (not group/other-writable) so it
     PASSES — **and owners** (0:0 on the new objects).
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
- ✅ **SharpZipLib ZipCrypto *writing*** — proven: the repacked `.fwz`
  round-trips through our own read chain with every edit intact (step 3 below).
  What remains untested is acceptance by a real device's updater (deliberately
  not attempted until a flash with recovery ready). Per-entry compression method
  matches the original.
- ⚠️ **Ownership assigned by lwext4** to new objects is unknown — so
  `SetOwner(0,0)` explicitly on every new object (`EnsureDir` sets `0:0` + `0755`
  on directories it creates; files get `SetOwner(0,0)` after writing).
- ⚠️ **`/etc/init.d/dropbear` must exist** in the image (fquinto relies on it).
- ⚠️ **Free space in the ext4** — additions are tiny (~1–3 KB); `ENOSPC` is
  theoretical but must surface as a clear error.
- ⚠️ **Home dir assumption** = `/home/root` (as fquinto) — the key goes there.
- ✅ Everything is sandbox until golden cross-validation passes. **No flashing
  before that**, and always with recovery ready.

---

## Implementation order (status)

1. **MD5-crypt generator** — isolated, tested against the vector. ✅ Done
   (self-test ALL PASS on real hardware).
2. **ext4 write routine (Phase A–D) + recut** + logical validation. ✅ Done
   (all 18 checks PASS on real firmware, including SetOwner 0:0 and SetMode
   0755/0600).
3. **Re-gzip + re-zip (ZipCrypto) + round-trip.** ✅ Done
   ("BUILD modified .fwz (test)" button; the output .fwz round-trips through
   our own read chain with every edit intact — SharpZipLib ZipCrypto writing
   proven).
4. **Golden cross-validation against fquinto.** ✅ Done.
   fquinto was run in Docker on a Linux VPS against the **same** input
   (`c100x_1.5.8.fwz`), the **same** public key, and the password `pwned123` —
   producing `$1$root$0i6hbFPn3JOGMeEF0LgEV1` (the exact hash our MD5-crypt
   generates). fquinto's output `.fwz` was fed to our "Validate SSH-enable in
   an existing .fwz" button: with `.ssh` set to **0755** the output now matches
   fquinto with **no divergence** (a clean **ALL PASS**). Every operation was
   also cross-checked line-by-line against fquinto's `main.py` (its provenance
   and a line-number map are in `reference/fquinto/README.md`; the file itself
   is not vendored, to keep this MIT repo free of GPL-2.0 content), and the
   MD5-crypt matches `openssl passwd -1`.

5. **Product UI.** ✅ Done. The six PoC buttons were replaced with a single
   product flow: choose `.fwz` + public key + output → **Build modified
   firmware** (runs extract → SSH-enable → repack → read-back verification and
   reports a clear pass/fail summary). Secondary actions **Verify an existing
   `.fwz`** and the **MD5-crypt self-test** remain. A startup diagnostics line
   reports 64-bit + DLL presence (red if anything is wrong). The window carries
   the recovery/safety reminder.

**Still required before flashing a real unit:** USB/SAM-BA recovery ready (the
tool itself never flashes — that is a deliberate manual, out-of-band step).
