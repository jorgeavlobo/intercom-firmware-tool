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

## Why `jq` 1.8.2 (not the version on the reference unit)

The reference C100X was running fquinto's older static **jq 1.7**, which is
affected by decNumber stack-buffer-overflow vulnerabilities (**CVE-2023-50268**,
**CVE-2024-53427**, through jq 1.7.1). We ship the current patched upstream
release **jq 1.8.2** — a jq *security release* that, over 1.7/1.8.1, fixes a
large batch of issues, several reachable via the untrusted JSON parsed in
`StartMqttReceive`: parser memory-corruption (e.g. **CVE-2026-32316** heap
overflow, **CVE-2026-39979** out-of-bounds read, **CVE-2026-33948** NUL
truncation) and a hash-collision denial of service (**CVE-2026-40164**). (In our
layout that parse only runs behind the opt-in, authenticated command channel;
`keypress.sh` uses jq only to *build* JSON from trusted values. We still ship the
patched build rather than rely on that gating.)

It is the official jqlang `jq-linux-armhf` asset, integrity-checked against the
project's published `sha256sum.txt`, and **smoke-tested on a live C100X** (kernel
4.9.11): despite being built with a newer glibc toolchain (it uses `DT_RELR`
relocations), the fully-static binary runs correctly on that unit (`jq
--version`, a `.command` parse, and a `jq -cn` build all succeed). `evtest` is
unchanged and remains byte-for-byte identical to the copy observed on that unit.

## Provenance & integrity

| Field | `jq` | `evtest` |
|---|---|---|
| File | `armhf/jq` | `armhf/evtest` |
| Size | 1,340,000 bytes | 34,264 bytes |
| SHA-256 | `78458244fb546469b4042e9e07cf78714ef6848895eb9515df76b4eb0b1dc992` | `96e3c20fb1742fc57b9b9efbc716cb4c7ae5a1faebe5621a14c1b3053d0d08c0` |
| ELF | 32-bit LSB, ARM EABI5, **statically linked**, stripped | 32-bit LSB PIE, ARM EABI5, **dynamically linked** (`/lib/ld-linux-armhf.so.3`), stripped |
| Build ID (SHA-1) | `55019f17610f57bc2ae9817d7f1cc56a3b30fbd1` | `0b6cfc5075b98021a854b5d4519ed3e1c6fa808e` |
| Target triple | `arm-linux-gnueabihf` (armv7 hardfloat), statically links glibc 2.39 (jqlang CI on ubuntu-24.04) | `arm-linux-gnueabihf` (armv7 hardfloat), glibc 2.27 |
| Upstream version | jq **1.8.2** (build: `--with-oniguruma=builtin --enable-all-static`) | evtest **1.35** |
| Statically bundles | Oniguruma (BSD-2-Clause), glibc (LGPL-2.1-or-later) | — (dynamic; links the device's own glibc) |
| License | **MIT** (jq) + ICU (decNumber) + Lucent/dtoa + BSD-2-Clause (Oniguruma) + LGPL-2.1-or-later (glibc) | **GPL-2.0-or-later** |
| SPDX expression | `MIT AND ICU AND LicenseRef-dtoa AND BSD-2-Clause AND LGPL-2.1-or-later` | `GPL-2.0-or-later` |
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

Source: <https://github.com/jqlang/jq> (tag `jq-1.8.2`). The `jq-linux-armhf`
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

**How that obligation is met here (LGPL §6).** The shipped `jq-linux-armhf` is
built by the jqlang CI (workflow at tag `jq-1.8.2`,
<https://github.com/jqlang/jq/blob/jq-1.8.2/.github/workflows/ci.yml>) on
`ubuntu-24.04`, statically linking the armhf glibc from the distro package
`crossbuild-essential-armhf` — i.e. **glibc 2.39**, Ubuntu 24.04's system glibc.
The CI installs that toolchain with a non-pinned `apt-get`, so it fixes the glibc
**version (2.39)** rather than a byte-exact toolchain image; we therefore record
the version and its corresponding source rather than claiming a byte-reproducible
build. glibc 2.39's complete corresponding source is available as an immutable
upstream release — tag **`glibc-2.39`**
(<https://sourceware.org/git/?p=glibc.git;a=tag;h=refs/tags/glibc-2.39>, tarball
<https://ftp.gnu.org/gnu/glibc/glibc-2.39.tar.xz>) — and as the exact Ubuntu
source package `glibc 2.39-0ubuntu*` from Launchpad
(<https://launchpad.net/ubuntu/+source/glibc>). jq's own source is MIT (link
above). With both public, a recipient can rebuild and relink `jq` against a
modified glibc. The exact corresponding-source materials for this binary are
**also available on request from the distributor** — open an issue at
<https://github.com/jorgeavlobo/intercom-firmware-tool/issues> — for at least
three years, for no more than the cost of the distribution.

> **Note (dormant runtime plugins).** Even `--enable-all-static`, glibc keeps a
> few subsystems plugin-based at runtime (NSS name resolution, `iconv`/`gconv`
> converters, the locale archive). jq's use here — parse a small JSON object,
> build a small one, both UTF-8 — does **not** call `setlocale`, `iconv`, or
> hostname resolution, and the on-device smoke test exercised exactly those
> paths, so this dormant dependency is not reached on the C100X's minimal rootfs.
> The pinned glibc version above is the reference should any such path ever be
> needed.

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
  project above, or **on request from the distributor** — open an issue at
  <https://github.com/jorgeavlobo/intercom-firmware-tool/issues> — for a period
  of at least three years, for no more than the cost of physically performing
  the source distribution.
- Build recipe (matches the shipped ELF target): cross-compile the unmodified
  evtest 1.35 source with an `arm-linux-gnueabihf` glibc 2.27 toolchain, e.g.

  ```sh
  arm-linux-gnueabihf-gcc -O2 -o evtest evtest.c
  ```

  (evtest is a single translation unit; no configure step is required.)

**Scope of these obligations.** The binaries are embedded **unconditionally** in
`IntercomFirmwareTool.Core` (they are compiled-in resources), so any distribution
of that assembly/package — regardless of the bridge toggle — redistributes `jq`
and `evtest` and must therefore carry these notices and honour the source offers.
This file travels with them for that reason. What the bridge toggle affects is
the **generated firmware image**: the *planned* installer (Phase 1c, #10) *will*
write `jq` and `evtest` into an image only when the bridge is enabled, so whoever
redistributes such an image must likewise pass these offers along; an image built
**without** the bridge (the default) will contain neither binary and carry no
such obligation *for the image*. (No installer path exists yet — this phase only
embeds the binaries; the image-side behaviour above is what Phase 1c will do.)
The obligation on the tool's own assembly/package is unaffected either way.
