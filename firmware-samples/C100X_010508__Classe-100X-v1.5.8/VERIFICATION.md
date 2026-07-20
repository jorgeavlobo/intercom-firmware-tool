# MQTT bridge — verification against C100X v1.5.8 firmware

This document records an **offline, end-to-end validation** of the MQTT bridge
(`MqttInstaller` + payload scripts + embedded ARM binaries) against the **real
device root filesystem** of a factory **Classe 100X, firmware `010508` (v1.5.8)**.

The `btweb_only.ext4` in this folder was mounted read-only and every assumption
the installer and payload make about the target was checked against what the
image actually contains. It confirms the fixes merged in **PR #17** (Phase 1d
UI), **PR #19** (firmware-samples), and — most importantly — **PR #20**
(`ValidateMqtt` symlink-blindness fix), which is what unblocks a real C100X
build.

> The firmware binaries are **not** committed (see the top-level
> [`../README.md`](../README.md)); this report captures the *findings* so the
> evidence survives without the proprietary bytes.

## Method

```
gunzip -kc btweb_only.ext4.gz > btweb_only.ext4      # ext4, 1 GiB, UUID dcf98ad1-…
mount -o loop,ro btweb_only.ext4 mnt                  # the device's real rootfs
```

Each `MqttInstaller` path/assumption was then replicated against `mnt/…`. The
key reproduction is `DependencyPresent`/`ResolveLinkTarget` (the #20 fix):
`FileExists` is modelled as "regular file, not a symlink", `ReadSymLink` as the
raw link target, and targets are resolved **rooted at the mount** (as the device
resolves them), not the host.

## 1. Runtime dependencies — the PR #20 fix, proven on real hardware

`ValidateMqtt` checks 9 runtime deps. Before #20 it used a bare `FileExists`,
which returns **false for a symlink**; a real C100X build failed with 5 spurious
"missing" errors. The audit predicted a 100 % correlation between "read-back
FAIL" and "the tool is a symlink". Confirmed exactly:

| Dep | On this image | old `FileExists` | new `DependencyPresent` (#20) |
|---|---|---|---|
| `mosquitto_pub` | `/usr/bin/mosquitto_pub` — regular file | ✅ | ✅ |
| `mosquitto_sub` | `/usr/bin/mosquitto_sub` — regular file | ✅ | ✅ |
| `mosquitto` (init) | `/etc/init.d/mosquitto` — regular file | ✅ | ✅ |
| `tcpdump` | `/usr/sbin/tcpdump` — regular file | ✅ | ✅ |
| **`python`** | symlink `→ python2 → python2.7` | ❌ | ✅ |
| **`pgrep`** | symlink `→ pgrep.procps` | ❌ | ✅ |
| **`nc`** | symlink `→ /bin/busybox.nosuid` | ❌ | ✅ |
| **`route`** | symlink `→ /bin/busybox.nosuid` | ❌ | ✅ |
| **`ping`** | symlink `→ /bin/busybox.suid` | ❌ | ✅ |

The 5 tools that failed the user's build are **exactly** the 5 symlinks, and each
chain now resolves to a real file. **With #20 all 9 deps PASS.** No dep is a
dangling symlink.

## 2. Patch targets (init-script edits)

| Target | State on image | Result |
|---|---|---|
| `/etc/init.d/flexisipsh` | exists, `1000:1000` (bticino) `0775`; one `start-stop-daemon --start` (line 24) inside the `start)` case (line 23); marker absent; `_bak` absent | anchor unambiguous ✅ |
| `/etc/init.d/bt_daemon-apps.sh` | exists, `root:root` `0700`; `/bin/bt_hosts.sh add openserver 127.0.0.1` anchor at line 101 | hosts patch anchor present ✅ |

Both are well under the 4 MiB `ReadAllText` cap (917 B / 4197 B).
`RewritePreservingMeta` keeps their non-root owner/mode.

## 3. Boot integration

- **Runlevel 5** is the default (`/etc/inittab`: `id:5:initdefault:`), and
  `l5:5:wait:/etc/init.d/rc 5` runs `/etc/rc5.d/S*` in sorted order
  (`/etc/init.d/rc` line 145). So the installed boot symlinks **do** execute.
- Factory `rc5.d` `S99` services are `S99avahi-daemon` and `S99rmnologin.sh`.
  The installed links `S99zBtServiceWatchdog` / `S99zTcpDump2Mqtt` sort **after**
  them (ASCII `z` = 122 > `a`/`r`), so the bridge starts once the factory
  services are up; `…zBtServiceWatchdog` sorts before `…zTcpDump2Mqtt`
  (`B` < `T`), so the watchdog comes first.
- `/etc/tcpdump2mqtt` is **absent** → the idempotency guard permits a clean
  install. `/etc/init.d` and `/etc/rc5.d` exist and are writable in the offline
  image.

## 4. Embedded ARM binaries — ABI match

Both shipped binaries match the device ABI exactly (**ARMv7, VFP-register /
hard-float**):

| Binary | CPU | FP ABI | Link | Interpreter |
|---|---|---|---|---|
| `jq` (embedded) | v7 | VFP registers | static | — |
| `evtest` (embedded) | v7 | VFP registers | dynamic | `/lib/ld-linux-armhf.so.3` |
| device `tcpdump`, `mosquitto_*`, `python2.7` | v7 | VFP registers | dynamic | `/lib/ld-linux-armhf.so.3` |

`evtest`'s interpreter `/lib/ld-linux-armhf.so.3 → ld-2.27.so` and its only
`NEEDED` lib `libc.so.6 → libc-2.27.so` are both present, so it runs. `jq` is
static. Install target `/usr/bin` is writable (`0755`) and **neither `jq` nor
`evtest` pre-exists** (no collision).

## 5. Gateway + command paths

- OpenWebNet gateway port **30006** is the video-door-entry client in the device
  stack (`/home/bticino/cfg/stack_open.xml`, `<bt_vct><port>30006</port>…
  <port_open>20000</port_open>`). This matches `StartMqttReceive`'s
  `nc 127.0.0.1 30006` and `StartMqttSend`'s `dst port 30006` filter.
- `openserver → 127.0.0.1` is aliased via `bt_hosts.sh` (the same mechanism the
  hostname-broker patch reuses). `/etc/hosts → /var/tmp/hosts` (tmpfs), so the
  runtime mapping write succeeds despite the read-only `/etc`.
- `/bin/sh → /bin/bash.bash`, so the `command -v` builtin used by the scripts is
  available.

## 6. Every external command the payload invokes is present

Resolved through PATH (`/sbin:/usr/sbin:/usr/bin:/bin`), following symlinks:

`date sleep rm cat touch mkdir chmod chown mv stat` (coreutils) · `sed awk grep
netstat nc route ping vi` (busybox applets — symlinked, i.e. enabled) · `head
printf wc tail mkfifo` (coreutils) · `kill pgrep` (procps; `-f`/`-x` supported) ·
`tcpdump` · `python` (2.7) · `mosquitto_pub` / `mosquitto_sub`.

Non-issues: `ss` is only a fallback for `netstat` (present); `command` is a shell
builtin, not a binary.

## Conclusion

Against the real C100X v1.5.8 rootfs, **every** install target, patch anchor,
boot hook, runtime dependency, gateway path and embedded-binary ABI checks out.
The PR #20 fix resolves the exact 5 symlinked deps that failed the build, and no
new blocker was found. A VS2026 build of this firmware with the MQTT bridge
enabled is expected to pass `ValidateMqtt` and produce a working image.

_Verified offline; on-device runtime behaviour (broker round-trip, key events)
still depends on the operator's broker/TLS configuration._
