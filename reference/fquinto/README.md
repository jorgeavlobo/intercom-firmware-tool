# Reference: fquinto `main.py`

`main.py` in this folder is a **verbatim, unmodified copy** of the firmware
preparation script from the fquinto project, kept here for **offline reference
only** — so we can compare our C# implementation against what it does without
going back to GitHub each time.

- **Source (raw):** https://raw.githubusercontent.com/fquinto/bticinoClasse300x/main/main.py
- **Author:** fquinto (and contributors)
- **License:** GPL-2.0 (as declared by the upstream repository); the full
  license text is in [`COPYING`](COPYING) in this folder
- **Fetched:** 2026-07 (branch `main`)
- **Content anchor (deterministic):** MD5 `a6b777888e140df789cc026a4673b7e9`,
  1068 lines, upstream version `0.0.13`. This exact byte-for-byte content was
  re-verified identical to upstream `main` HEAD. Verify with:
  ```
  curl -fsSL https://raw.githubusercontent.com/fquinto/bticinoClasse300x/main/main.py | md5sum
  # => a6b777888e140df789cc026a4673b7e9
  ```
  The MD5 pins the *content* (a tighter anchor than a branch name); the
  line-number map below is valid for exactly this file. A commit SHA could not
  be recorded from the build environment (the GitHub API is not reachable here),
  but if upstream ever changes `main.py`, the MD5 above no longer matching `main`
  is the signal to find the specific commit that produced this content.
- **Purpose here:** documentation / comparison only. It is **not** compiled,
  imported, executed, or shipped by this tool. Our tool is a clean-room C#/WPF
  reimplementation of the *result* (see `docs/WRITE_PHASE_PLAN.md`), not a
  translation of this code.

Because this file is GPL-2.0 and third-party, treat it as an external reference
document. Do not copy code from it into the C# sources; use it only to confirm
exact paths, contents, permissions and ordering.

## License and attribution

`main.py` is Copyright © the fquinto project authors and is licensed under the
**GNU General Public License, version 2 (GPL-2.0)**. The complete license text
is in [`COPYING`](COPYING) alongside this file.

`main.py` is included **verbatim and unmodified** — no changes have been made to
it. The rest of this repository is a separate, independent work under its own
license; `main.py` is kept here only as an external reference and is **not**
linked into, compiled with, or shipped as part of the tool's binaries.

## The rootfs edits this script makes (map to our C# plan)

Verified line numbers in this copy:

| Lines | What it does |
|------:|--------------|
| 501–503 | `openssl passwd -1 -salt root <password>` → MD5-crypt hash (`$1$root$…`) |
| 527–532 | `set_shadow_file`: append `root2:` and `bticino2:` to `/etc/shadow` |
| 535–540 | `set_passwd_file`: append `root2:` and `bticino2:` to `/etc/passwd` |
| 561–572 | `set_ssh_key`: copy pubkey to `/etc/dropbear/authorized_keys`, `mkdir /home/root/.ssh`, copy pubkey to `/home/root/.ssh/authorized_keys` |
| 899–905 | `setup_ssh_key_rights`: `chmod 600` on both `authorized_keys` |
| 908–915 | `enable_dropbear`: `cd /etc/rc5.d && ln -s ../init.d/dropbear S98dropbear` |
| 824–828 | verifies `/etc/rc5.d` exists before creating the symlink |

Note: the script runs as root via `sudo mount`, so new files/dirs are already
owned `root:root` and it never `chown`s them, and it doesn't `chmod` the `.ssh`
directory. Our SharpExt4 approach has no such luxury, so we set ownership
(`0:0`) and the `.ssh` mode (`0700`) explicitly — see the plan.
