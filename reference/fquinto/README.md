# Reference: fquinto `main.py` (provenance — not vendored)

Our tool replicates the *result* of the fquinto firmware-preparation script.
The upstream script, **`main.py`, is GPL-2.0**, so to keep this MIT repository
free of GPL-licensed content it is **not vendored here** — this file records its
exact provenance and the map of the parts we replicate, so it stays reproducible
without carrying the file in the tree.

- **Source (raw):** https://raw.githubusercontent.com/fquinto/bticinoClasse300x/main/main.py
- **Author:** fquinto (and contributors)
- **License:** GPL-2.0 (as declared by the upstream repository)
- **Fetched / verified:** 2026-07 (branch `main`)
- **Content anchor (deterministic):** MD5 `a6b777888e140df789cc026a4673b7e9`,
  1068 lines, upstream version `0.0.13`. Fetch and verify the exact content the
  line-number map below refers to:
  ```shell
  curl -fsSL https://raw.githubusercontent.com/fquinto/bticinoClasse300x/main/main.py | md5sum
  # => a6b777888e140df789cc026a4673b7e9
  ```
  The MD5 pins the *content* (a tighter anchor than a branch name). If upstream
  ever changes `main.py`, the MD5 no longer matching `main` is the signal that
  the line numbers below may have shifted. It is a **change-detection
  convenience, not a security guarantee** — MD5 is collision-prone, so don't
  treat a match as tamper-proof. For a stronger identifier, use SHA-256:
  ```shell
  curl -fsSL https://raw.githubusercontent.com/fquinto/bticinoClasse300x/main/main.py | sha256sum
  ```

The tool is a clean-room C#/WPF reimplementation of the *result*
(see `docs/WRITE_PHASE_PLAN.md`), not a translation of this code. Do not copy
code from the upstream script into the C# sources; use it only to confirm exact
paths, contents, permissions and ordering.

## Licensing

This repository's own code is **intended to be MIT-licensed** (a top-level
`LICENSE` file is pending — tracked in issue #98) and vendors **no GPL *source***.
The upstream `main.py` is **GPL-2.0** and is **not included here**, so this GPL
script contributes no GPL content to the source tree or the releases. If you fetch
`main.py` via the URL above for your own reference, that copy remains GPL-2.0 and
its terms apply to *that* copy only — they do not affect this MIT project.

Separately (and unrelated to this script), the Windows **release binary** bundles
one third-party GPL-2.0 component — `lwext4`, compiled into `SharpExt4.dll`. That
is documented in [`CLEANROOM.md`](../../CLEANROOM.md), and its GPL-2.0 compliance
is tracked in issue #98.

## The rootfs edits this script makes (map to our C# plan)

Verified line numbers in the pinned content (MD5 above):

| Lines | What it does |
|------:|--------------|
| 501–503 | `openssl passwd -1 -salt root <password>` → MD5-crypt hash (`$1$root$…`) |
| 527–532 | `set_shadow_file`: append `root2:` and `bticino2:` to `/etc/shadow` |
| 535–540 | `set_passwd_file`: append `root2:` and `bticino2:` to `/etc/passwd` |
| 561–572 | `set_ssh_key`: copy pubkey to `/etc/dropbear/authorized_keys`, `mkdir /home/root/.ssh`, copy pubkey to `/home/root/.ssh/authorized_keys` |
| 899–905 | `setup_ssh_key_rights`: `chmod 600` on both `authorized_keys` |
| 908–915 | `enable_dropbear`: `cd /etc/rc5.d && ln -s ../init.d/dropbear S98dropbear` |
| 824–828 | verifies `/etc/rc5.d` exists before creating the symlink |

**On the `/home/root/.ssh` mode:** the script runs as root via `sudo mount`, so
new files/dirs are already `root:root` and it never `chown`s them, and it does
**not** `chmod` the `.ssh` directory — `mkdir -p` under the default umask leaves
it **0755**. We replicate exactly that (`.ssh` = 0755, `authorized_keys` = 0600,
owners 0:0). Note that neither `.ssh` nor any `authorized_keys` exists in the
factory firmware (verified on the original image: `/home/root` has only
`.bash_history` and `.cache`; `/etc/dropbear` has only `dropbear_rsa_host_key`),
so this whole key-login mechanism is created by the edits — there is no factory
mode to copy. Security is guaranteed by the parent directory: factory
`/home/root` is **0700 `root:root`** (verified `drwx------`), so its contents are
unreachable by other users whether `.ssh` is 0755 or 0700, and dropbear accepts
0755 because it only rejects a group/other-**writable** `.ssh`.
