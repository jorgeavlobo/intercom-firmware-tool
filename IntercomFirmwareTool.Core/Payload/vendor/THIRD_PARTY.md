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
covers IntercomFirmwareTool's own code. **Bundling them does not relicense them,
and it does not make the resulting firmware image "MIT":** because `evtest` is
GPL-2.0-or-later, any firmware image that includes it is an *aggregate* that, as
a whole, must be distributed in accordance with the GPL (see the written offer
for source below). `jq` is permissively licensed (MIT and compatible notices).

The exact bytes committed here were confirmed **byte-for-byte identical** to the
copies observed running on a live C100X ("shark", Poky/Yocto 2.5.3 sumo, kernel
4.9.11 i.MX, **glibc 2.27, ARMv7l hardfloat**, `/lib/ld-linux-armhf.so.3`
present). No static/uClibc/musl rebuild is required for that platform.

## Provenance & integrity

| Field | `jq` | `evtest` |
|---|---|---|
| File | `armhf/jq` | `armhf/evtest` |
| Size | 1,324,676 bytes | 34,264 bytes |
| SHA-256 | `dd9786221a3a0f250ed227706b7300a69579529ac4a059c874c35a9efead68b1` | `96e3c20fb1742fc57b9b9efbc716cb4c7ae5a1faebe5621a14c1b3053d0d08c0` |
| ELF | 32-bit LSB, ARM EABI5, **statically linked**, stripped | 32-bit LSB PIE, ARM EABI5, **dynamically linked** (`/lib/ld-linux-armhf.so.3`), stripped |
| Build ID (SHA-1) | `fe95335f0be518bc466f45134639895bd7711293` | `0b6cfc5075b98021a854b5d4519ed3e1c6fa808e` |
| Target triple | `arm-linux-gnueabihf` (armv7 hardfloat) | `arm-linux-gnueabihf` (armv7 hardfloat), glibc 2.27 |
| Upstream version | jq **1.7** (JQ_VERSION `1.7`; build: `--with-oniguruma=builtin --enable-all-static`) | evtest **1.35** |
| License | **MIT** (with bundled dtoa/g_fmt and decNumber notices) | **GPL-2.0-or-later** |
| License text | [`licenses/jq-COPYING`](licenses/jq-COPYING) | [`licenses/evtest-COPYING`](licenses/evtest-COPYING) |

The SHA-256 values above are also enforced at load time by
`PayloadBinaries` (the accessor throws if an embedded binary's bytes do not
match), so a corrupted or swapped binary cannot be silently installed.

## `jq` — MIT

`jq` is copyright (C) 2012 Stephen Dolan and contributors, distributed under the
MIT license. `jq` also incorporates David M. Gay's `dtoa.c`/`g_fmt.c` (Lucent
permissive notice) and the `decNumber` library (ICU license). The complete text
of all of these notices, exactly as shipped with jq, is in
[`licenses/jq-COPYING`](licenses/jq-COPYING).

Source: <https://github.com/jqlang/jq> (tag `jq-1.7`).

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

Because `evtest` is GPL-2.0-or-later, redistributors of any firmware image built
**with the MQTT bridge enabled** must pass this offer (or the source itself)
along to their recipients. Images built **without** the MQTT bridge (the
default) contain neither `evtest` nor `jq` and carry no such obligation.
