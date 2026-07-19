# Third-party binaries shipped by the MQTT bridge installer

The optional **MQTT bridge** feature (off by default) installs two prebuilt
ARM userland tools into the firmware image, because they are **not** present in
the factory BTicino C300X/C100X firmware and the bridge scripts need them:

| Tool | Used by | Installed as | Purpose |
|---|---|---|---|
| `jq` | `StartMqttReceive`, `keypress.sh` | `/usr/bin/jq` (`0775 root:root`) | build/parse the small JSON command and key-press payloads |
| `evtest` | `keypress.sh` | `/usr/bin/evtest` (`0775 root:root`) | read front-panel key events from `/dev/input/eventN` |

These are **verbatim, unmodified** third-party binaries. They are redistributed
here under their own licenses (below), independently of the MIT license that
covers IntercomFirmwareTool's own code. **Bundling them does not relicense
them** — each keeps its own license, unchanged.

- `evtest` stays **GPL-2.0-or-later**: any firmware image that includes it must
  satisfy the GPL's obligations **for `evtest`** — ship its license notice and
  honour the written offer for corresponding source (below). Placing it on the
  same image as the otherwise-MIT tooling is *mere aggregation* (GPL v2 §2): that
  does not extend the GPL to the other components, but it also does not make the
  image "MIT as a whole".
- `jq` is a permissive program (MIT), **but the shipped binary is statically
  linked** and therefore *contains* code from other projects with their own
  terms: **Oniguruma** (BSD-2-Clause) and the **GNU C Library / glibc**
  (LGPL-2.1-or-later). The LGPL adds a relink/source obligation for the glibc
  portion — see the `jq` section below.

## Why `jq` 1.8.1 (not the version on the reference unit)

The reference C100X was running fquinto's older static **jq 1.7**, which is
affected by decNumber stack-buffer-overflow vulnerabilities
(**CVE-2023-50268**, **CVE-2024-53427**, present through jq 1.7.1) that are
reachable via the JSON parsed in `StartMqttReceive`. We therefore ship the
patched upstream release **jq 1.8.1** instead. It is the official jqlang
`jq-linux-armhf` asset, integrity-checked against the project's published
`sha256sum.txt`, and **smoke-tested on a live C100X** (kernel 4.9.11): despite
being built with a newer glibc toolchain (it uses `DT_RELR` relocations), the
fully-static binary runs correctly on that unit (`jq --version`, a `.command`
parse, and a `jq -cn` build all succeed). `evtest` is unchanged and remains
byte-for-byte identical to the copy observed on that unit.

## Provenance & integrity

| Field | `jq` | `evtest` |
|---|---|---|
| File | `armhf/jq` | `armhf/evtest` |
| Size | 1,331,968 bytes | 34,264 bytes |
| SHA-256 | `ac304e50cf7cd24933d83dc7d0e4f79892a71a92fb02336d4ecaffa8933760bd` | `96e3c20fb1742fc57b9b9efbc716cb4c7ae5a1faebe5621a14c1b3053d0d08c0` |
| ELF | 32-bit LSB, ARM EABI5, **statically linked**, stripped | 32-bit LSB PIE, ARM EABI5, **dynamically linked** (`/lib/ld-linux-armhf.so.3`), stripped |
| Build ID (SHA-1) | `1047040cbcda08213e9c23c51e59396af5e2d8f8` | `0b6cfc5075b98021a854b5d4519ed3e1c6fa808e` |
| Target triple | `arm-linux-gnueabihf` (armv7 hardfloat) | `arm-linux-gnueabihf` (armv7 hardfloat), glibc 2.27 |
| Upstream version | jq **1.8.1** (build: `--with-oniguruma=builtin --enable-all-static`) | evtest **1.35** |
| Statically bundles | Oniguruma (BSD-2-Clause), glibc (LGPL-2.1-or-later) | — (dynamic; links the device's own glibc) |
| License | **MIT** (jq) + BSD-2-Clause (Oniguruma) + LGPL-2.1-or-later (glibc) | **GPL-2.0-or-later** |
| License texts | [`licenses/jq-COPYING`](licenses/jq-COPYING), [`licenses/oniguruma-COPYING`](licenses/oniguruma-COPYING), [`licenses/glibc-LGPL-2.1.txt`](licenses/glibc-LGPL-2.1.txt) | [`licenses/evtest-COPYING`](licenses/evtest-COPYING) |

The SHA-256 values above are also enforced at load time by
`PayloadBinaries` (the accessor throws if an embedded binary's bytes do not
match), so a corrupted or swapped binary cannot be silently installed.

## `jq` — MIT, statically bundling Oniguruma (BSD) and glibc (LGPL-2.1)

`jq` itself is copyright (C) 2012 Stephen Dolan and contributors, distributed
under the MIT license. It also incorporates David M. Gay's `dtoa.c`/`g_fmt.c`
(Lucent permissive notice) and the `decNumber` library (ICU license). The
complete text of all of these, exactly as shipped with jq, is in
[`licenses/jq-COPYING`](licenses/jq-COPYING).

Source: <https://github.com/jqlang/jq> (tag `jq-1.8.1`). The `jq-linux-armhf`
release asset is built by the project's public CI, which is the reproducible
build recipe for this exact static binary.

Because the shipped binary is **statically linked** (`--enable-all-static`), it
also contains two further projects, whose notices must travel with it:

### Oniguruma — BSD-2-Clause

jq's regular-expression support is provided by the bundled **Oniguruma** library
(`--with-oniguruma=builtin`), copyright (c) K.Kosako and contributors, under the
2-clause BSD license. Its binary-redistribution clause requires this notice to
accompany the binary; the full text is in
[`licenses/oniguruma-COPYING`](licenses/oniguruma-COPYING).
Source: <https://github.com/kkos/oniguruma>.

### GNU C Library (glibc) — LGPL-2.1-or-later (statically linked)

The static `jq` links the **GNU C Library** into the executable. glibc is
licensed **LGPL-2.1-or-later**; the full text is in
[`licenses/glibc-LGPL-2.1.txt`](licenses/glibc-LGPL-2.1.txt). Static linking
triggers LGPL §6: recipients must be able to relink `jq` against a modified
glibc.

**How that obligation is met here (LGPL §6):** everything needed to produce a
functionally-equivalent `jq` with a different glibc is publicly available and
buildable — jq's own source is MIT (link above), and glibc's complete
corresponding source is available from the GNU project
(<https://sourceware.org/git/glibc.git>) and, **on request from the distributor
of this software** for at least three years, for no more than the cost of the
distribution. Rebuilding the official `jq-linux-armhf` asset from jq's public CI
against a chosen glibc yields the equivalent statically-linked binary.

## `evtest` — GPL-2.0-or-later

`evtest` is copyright (C) 1999-2000 Vojtech Pavlik and (C) 2009-2011 Red Hat,
Inc., distributed under the GNU General Public License, version 2 **or (at your
option) any later version**. The complete GPL v2 text exactly as shipped with
evtest is in [`licenses/evtest-COPYING`](licenses/evtest-COPYING).

### Written offer for corresponding source (GPL-2.0 §3)

The `evtest` binary shipped here is the unmodified upstream program. Its
**complete corresponding source code** is the `evtest` project source at
version 1.35:

- Upstream project: <https://gitlab.freedesktop.org/libevdev/evtest>
- The corresponding source for this exact binary — evtest **1.35** for
  `arm-linux-gnueabihf` (glibc 2.27) — can be obtained from the upstream
  project above, or **on request from the distributor of this software** for a
  period of at least three years, for no more than the cost of physically
  performing the source distribution.
- Build recipe (matches the shipped ELF target): cross-compile the unmodified
  evtest 1.35 source with an `arm-linux-gnueabihf` glibc 2.27 toolchain, e.g.

  ```sh
  arm-linux-gnueabihf-gcc -O2 -o evtest evtest.c
  ```

  (evtest is a single translation unit; no configure step is required.)

Because `evtest` is GPL-2.0-or-later (and the static `jq` carries LGPL-2.1
glibc), redistributors of any firmware image built **with the MQTT bridge
enabled** must pass these offers (or the source itself) along to their
recipients. Images built **without** the MQTT bridge (the default) contain
neither `evtest` nor `jq` and carry no such obligation.
