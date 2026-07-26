# Ringtone volume & mute — reverse-engineering notes (issue #40)

How the BTicino indoor unit's **ringtone volume** and **mute** are actually controlled,
established empirically against a live device, and how `btmqttd` drives them for Home
Assistant. This is the durable record of a long investigation; read it before touching
`dimension.rs` / `volume.rs`.

## TL;DR

| Control | OWN frame (openserver `:20000`, `*99*0##` session) | Persists to | Range |
|---|---|---|---|
| **Ringtone volume** | `*#8**#41*<N>##` (write), `*#8**41##` (read) | `aswm_settings.ini` `[Volumes] Ring=<N>` | `0..=100`, 1:1 |
| **Ringtone mute** | `*#8**#33*<0\|1>##` (write), `*#8**33##` (read) | `aswm_settings.ini` `RingEnable=<0\|1>` | `0`=muted, `1`=audible |

- Volume and mute are **independent**: muting (`RingEnable=0`) does **not** change `Ring=`,
  so unmute rings again at the same level. Volume `0` is a low volume, **not** a mute.
- Both echo their dimension report on the reply **and** broadcast it on the monitor bus,
  so `btmqttd` learns changes made on the unit's own screen too (bidirectional state).
- Both writes are performed **by the device's own `bt_answering_machine`**, through the
  exact same path the on-screen slider uses — so remote changes behave identically to
  local ones, including persistence.

## Device

- Model: **Classe 300X**, board `imx6dl-shark-zl380tw` (i.MX6 DualLite, hostname `shark`).
- Audio codec: **Microsemi/Zarlink ZL380TW**, driven via ALSA.
- Firmware processes (all under the `bt_daemon` supervisor): `openserver` (OWN gateway),
  `bt_device`, `bt_vct`, `bt_av_media`, `bt_answering_machine`, `bt_dbus_manager`
  (network/connman only), `bt_eliot`, `bt_ipcamera`, and the Qt GUI **`BtClass100`**.

## The false negative that cost us most of the investigation

Earlier attempts "proved" the volume frame did nothing and a prior note even concluded
"dimension 41 is status-only telemetry." **That conclusion was wrong.** Two independent
verification traps made a working command look inert:

1. **The on-screen number is not the volume store.** The unit's volume **indicator**
   reads `settings.xml` (`cid=14123 → <ist volume=N>`); the **actual** ringtone volume
   is `aswm_settings.ini` `Ring=`. The OWN frame updates `Ring=` but **not** the on-screen
   `settings.xml`. Checking the screen therefore showed the old value while the real
   volume had changed.
2. **Idle has no sound.** The ALSA output gain (`AEC ROUT GAIN`, see below) sits at `0`
   when nothing is playing and is only applied at ring/call time. Testing "does it get
   louder" while idle can never hear a difference.

The fix was to verify against **`Ring=` on disk** (frame → file, audible-independent) and
then **audibly at the door station** (set `Ring=10`, ring → quiet; set `Ring=100`, ring →
loud). Both confirmed the frame changes the real ringtone volume.

## The audio path (why the on-screen number can't be synced)

`bt_av_media` applies the volume to ALSA at playback via `liblghal.so`. `hal_set_output_volume()`
switches on the board id and, on this board, sets the mixer control **`AEC ROUT GAIN`**
(`amixer -c0`, range `0..=127`) — the ZL380TW receive-out (speaker) gain. It is `0` at
idle and written from the stored level only while audio plays. (Other boards route through
`hal_set_zl_output_volume` via `/bin/zl38005_ioctl-v2` or `hal_set_amixer_output_volume`;
neither helper exists on this unit.)

The **on-screen indicator cannot be updated remotely.** The GUI (`BtClass100`, QtEmbedded)
holds the volume in RAM and only writes `settings.xml`; it never re-reads that file at
runtime. Three independent reasons make a remote sync infeasible:

1. **No D-Bus.** `BtClass100` exposes no D-Bus interface for volume (`bt_dbus_manager` is
   network/connman only), so `AVDevice::setRingtoneVolume()` cannot be called externally.
2. **A RAM poke wouldn't repaint.** The on-screen widget is bound to a Qt property and
   repaints on the `volumeChanged` **signal**; writing the value into `/proc/PID/mem`
   would change the variable but emit no signal, so the number would not refresh (besides
   being a fragile, crash-prone heap poke).
3. **The only levers are unacceptable for routine use** — restart the GUI (it re-reads
   `settings.xml` at start) or synthesise touch events on the slider.

This is a **hardware/firmware limitation**, not a `btmqttd` gap. The real volume is remote-
controllable and correct; only the cosmetic on-screen number can lag. Editing `settings.xml`
was tested and confirmed to have **no effect** on the display (the GUI ignores the file at
runtime), so `btmqttd` deliberately does **not** touch it.

## How the setting is applied and persisted

`bt_answering_machine` owns both `aswm_settings.ini` and `settings.xml`. It listens on an
internal **UDP message bus** (LivingConfig `LC02` framing, senders `aswm`/`qtdevices`/`OPEN`)
reachable through openserver `:20000`. On a volume/mute frame it **reads** `aswm_settings.ini`,
modifies it, and **atomically rewrites** it (`*.ini.XXXXXX` temp file → `rename()`), verified
by `strace`.

Persistence is **crash-safe**. `/home/bticino/cfg/extra` is its own flash partition
(`/dev/mmcblk2p7`) mounted `rw,noatime,sync,nodelalloc,data=journal` — separate from the
read-only rootfs (`mmcblk2p6`, `ro`). `sync` flushes each write to flash before the syscall
returns and `data=journal` journals data as well as metadata, so a value set over MQTT
survives a reboot or an abrupt power loss, exactly like a change made on the unit.

## OWN frame details

- Session: connect to `own_host:own_port_mon` (default `127.0.0.1:20000`), send `*99*0##`
  (**command** session — permits dimension read/write, unlike the read-only monitor
  `*99*1##`), then the frame. Gateway replies `*#*1##` (accepted) / `*#*0##` (rejected)
  and, for read/write, the dimension report `*#8**41*<N>##` / `*#8**33*<0|1>##`.
- The command-injection port `:30006` used for bt_vct ACTIONS does **not** handle WHO=8
  dimensions — these must go to the `:20000` main gateway.
- **`dim33` is boolean.** An early oracle test that wrote `dim33` with a percent value
  (23, 88) did nothing: the device silently rejects non-`0|1` writes to `RingEnable`.
  `parse_mute_report` enforces the same, keeping the two monitor streams cleanly separated.
- The volume slider on the unit also emits WHO=7 companions (`*#7**31#2#0*<N>##`) and
  WHO=8 status reports; these are **telemetry** (broadcast after the change), not the apply
  path, and are ignored except that the `dim41`/`dim33` reports feed state back.

## What `btmqttd` does

- **Volume** — `dimension::{volume_read_request, volume_write_frame, parse_volume_report,
  read_volume, write_volume}` (dim 41). HA `number` slider + ±10% `button`s.
- **Mute** — `dimension::{mute_read_request, mute_write_frame, parse_mute_report, read_mute,
  write_mute}` (dim 33). HA `switch`, driving the real `RingEnable` — no fake "volume 0"
  mute and no saved pre-mute level (the device keeps `Ring=` across a mute, so none is
  needed).
- `volume.rs` keeps `current` (volume) and `muted` independent, learns both authoritatively
  from write echoes, on-connect reads (`seed`), and monitor broadcasts (`sender` hook), and
  republishes two retained state topics (`Bticino/volume`, `Bticino/mute`) so HA is correct
  across restarts and unit-side changes.
