# MQTT bridge payload (clean-room, MIT)

These scripts are the payload that a **planned** installer (Phase 1c, issue #10)
*will* write into the firmware image when the user ticks the optional **Install
MQTT bridge** box in Advanced options (off by default). The payload scripts
(Phase 1a) and the embedded ARM binaries with SHA-256 integrity verification
(Phase 1b, see [`../vendor/`](../vendor/THIRD_PARTY.md)) are in the repository;
**nothing is wired into the build yet** — the installer, the UI checkbox, and the
read-back validation referenced below are still the planned Phase 1c/1d. The
bridge exposes the BTicino OpenWebNet/SCS bus and the front-panel keys over MQTT,
for Home Assistant-style integration.

## Provenance & licensing

They are an **independent, MIT-licensed reimplementation** of the behaviour of
fquinto's `mqtt_scripts/*` (which are **GPL-2.0**). To keep this repository
MIT-clean — the same reason `main.py` is not vendored (see
[`reference/fquinto/README.md`](../../../reference/fquinto/README.md)) — none of
the upstream shell/Python source is copied here; only the functional interface
that has to match for compatibility is reproduced: the file layout under
`/etc/tcpdump2mqtt`, the MQTT topic names, the OpenWebNet gateway port `30006`,
and the `TcpDump2Mqtt.conf` variable names.

The two ARM binaries the bridge needs (`jq` — MIT, but the static build bundles
Oniguruma BSD and glibc LGPL-2.1; `evtest` — GPL-2.0-or-later) are **not** in
this folder — they live under [`../vendor/`](../vendor/THIRD_PARTY.md) with their
own license notices, SHA-256 provenance and the written source offers (Phase 1b,
issue #9). `evtest` keeps its GPL-2.0-or-later license when shipped, so a
firmware image built **with** the
bridge enabled must satisfy the GPL obligations **for `evtest`** (its notice plus
the written offer for source). Bundling it alongside the otherwise-MIT tooling is
*mere aggregation* — it does not relicense the other components — see that notice.

## Files

All of these install under `/etc/tcpdump2mqtt/` except `bt_service_watchdog`
(which goes to `/etc/init.d/`). Runtime logs are written to the root-only
directory `/var/log/tcpdump2mqtt/`, never a predictable world-writable `/tmp`
path.

| File | Role |
|---|---|
| `TcpDump2Mqtt` | Orchestrator: keeps sender/receiver/keypress alive, publishes status, recovers from network outages. |
| `TcpDump2Mqtt.sh` | Init launcher (symlinked from `/etc/rc5.d/S99TcpDump2Mqtt`). |
| `mqtt_common.sh` | Shared helper sourced by the four scripts below: config load + `mqtt_pub`/`mqtt_sub_one` (auth+TLS) + the `remote_shell_allowed` gate. |
| `StartMqttSend` | `tcpdump` on `lo` → `filter.py` → publish frames to `TOPIC_DUMP`. |
| `StartMqttReceive` | Subscribe `TOPIC_RX` → OpenWebNet passthrough to the unit; gated JSON command channel. |
| `keypress.sh` | `evtest` front-panel keys → publish to `TOPIC_KEY`. |
| `filter.py` | Extract `*…##` OpenWebNet frames from the `tcpdump -A` text stream (installed at `/etc/tcpdump2mqtt/filter.py`). |
| `bt_service_watchdog` | Independent init service: restarts dropbear/scsserver/mosquitto/TcpDump2Mqtt if they die. |
| `TcpDump2Mqtt.conf` | Configuration template; the installer fills in broker/topics from the UI. |

## Fixes & hardening over the upstream behaviour

1. **Remote-root backdoor closed by default.** Upstream `StartMqttReceive`
   unconditionally honoured JSON `read_file` / `write_file` / `execute_command`
   on an unauthenticated broker — root-equivalent control to anyone who could
   publish. Here that channel is **off unless** `ALLOW_REMOTE_SHELL=1` **and** the
   client is authenticated — either `MQTT_USER`/`MQTT_PASS`, or mutual TLS (a
   client certificate and key, `MQTT_CERTFILE`+`MQTT_KEYFILE`, with `MQTT_CAFILE`).
   One-way TLS (CA only) verifies the broker but not the client, so it does not
   unlock it. The OpenWebNet passthrough (the real automation feature) is
   unaffected.
2. **`keypress.sh` is actually installed.** Upstream `main.py` never copied it,
   so the key-press feature was dead and `TcpDump2Mqtt` spawned a missing file
   every 30 s.
3. **No busy-loop.** `StartMqttReceive` now backs off (capped) when the broker
   is unreachable instead of spinning at 100 % CPU.
4. **POSIX sh.** Dropped the bash-only `function` keyword; validated with
   `dash -n`.
5. **Robust process tracking.** `pgrep -f` on explicit paths instead of fragile
   `ps -edf | grep | grep`.
6. **Standalone-safe.** Sender/receiver/keypress each source the config if
   started without the environment already exported.
7. **filter.py throughput.** Removed the fixed `sleep(0.2)` per frame that
   capped the bus feed to ~5 frames/s.
8. **Auth and TLS compose.** Username/password and TLS are applied independently
   (upstream's if/elif picked one, so user/pass *over* TLS silently dropped the
   TLS flags). One-way "CA only" TLS is allowed; client cert+key = mutual TLS.
9. **Command gate needs client auth.** `remote_shell_allowed` requires user/pass
   or mutual TLS (client cert+key) — one-way TLS (CA only) verifies the broker,
   not the client, so it no longer unlocks the command channel.
10. **Single self-contained layout.** `filter.py` installs under
    `/etc/tcpdump2mqtt/` with the rest (upstream split it to `/home/root`); the
    broker helper is factored into one `mqtt_common.sh` instead of copy-pasted
    into four scripts.
11. **Specific sender liveness.** The orchestrator checks its own
    `StartMqttSend`, not any `tcpdump` on the box, so an unrelated `tcpdump`
    can't block the sender from starting.
12. **Configurable reply topics.** `TOPIC_CMD_RESULT`/`TOPIC_FILE_CONTENT`
    replace the previously hard-coded result topics.
13. **Symlink-safe logs.** Logs go to the root-only `/var/log/tcpdump2mqtt/`
    (created 0700), with a symlink guard, instead of a predictable `/tmp` path a
    local user could pre-seed.
14. **Robust, model-agnostic keypad handling.** Key events are parsed by
    `type`/`code`/`value` labels (auto-repeat, value 2, ignored), and **every**
    key is published using the `KEY_` name evtest prints — not a hard-coded 4-key
    map. Upstream mapped only KEY_1..KEY_4 (the C300X layout); the C100X keypad
    has 7 keys (KEY_1..KEY_7, confirmed on-device), which the old map dropped.
    Payload is `{key, code, value}`. The keypad's input node is auto-detected from
    `/proc/bus/input/devices` (Name contains "keypad"), falling back to `event0`,
    so it isn't tied to a fixed `eventN` across models.
15. **Retained commands ignored.** The receiver subscribes with `-R`, so a
    command left RETAINED on `TOPIC_RX` is not replayed on every reconnect —
    commands must be published non-retained.
16. **Fail fast on missing deps + capped file ops.** `StartMqttSend` errors if
    no `python` is present; the JSON channel reports a missing `jq`; `keypress.sh`
    checks `evtest`+`jq`; and both `read_file` and `write_file` cap at 256 KB.
17. **LF line endings pinned.** `.gitattributes` forces LF on this payload so a
    Windows checkout can't introduce a CRLF shebang that would fail on the rootfs.
18. **One frame per message.** `filter.py` splits coalesced OpenWebNet frames
    (e.g. `*1##*2##` on one `tcpdump` line) so each `*…##` frame is published as
    its own MQTT message rather than a combined/garbled payload.

## Known limitations (addressed in later phases)

- **Availability (`TOPIC_LASTWILL`).** The `-C 1` one-shot subscription
  disconnects cleanly each cycle, so the retained `offline` last will rarely
  fires and the topic can stay `online`. Reliable online/offline needs a
  persistent subscription — tracked in #12 (Phase 2).
- **Cross-line frame splitting.** `filter.py` splits multiple frames coalesced
  on one `tcpdump` line, but a single frame split ACROSS lines is not
  reassembled (text scraping is line-oriented). Rare for small OpenWebNet frames;
  the proper fix is reading the gateway socket directly (#12, Phase 2).
- **Command-publisher authorization.** `ALLOW_REMOTE_SHELL` gates on THIS bridge
  authenticating to the broker; MQTT does not tell us whether the *publisher* of
  a `TOPIC_RX` command is authorized. On a shared broker, restrict publishing to
  `TOPIC_RX` with broker-side ACLs. A per-command shared secret is a possible
  future control (to be decided with the UI phase, #11).

## Runtime dependencies

**Base (factory firmware, confirmed present on a C100X):** `mosquitto_pub`,
`mosquitto_sub`, a local `mosquitto` broker, `tcpdump`, `nc`, `route`, `ping`,
`pgrep`, and `python` (2.7). Upstream relies on these; the planned installer's
read-back check (#10) will flag any that are missing before a build is accepted.

**Feature-specific (shipped by us as ARM binaries — Phase 1b / #9, embedded in
`IntercomFirmwareTool.Core`; see [`../vendor/THIRD_PARTY.md`](../vendor/THIRD_PARTY.md)):**
- `jq` — required by the gated JSON command channel (`StartMqttReceive`) and by
  `keypress.sh`. If absent: `keypress.sh` exits early with a clear message, and
  the JSON command channel logs "jq is not installed" and ignores the command
  (the OpenWebNet passthrough is unaffected).
- `evtest` — required by `keypress.sh` only. If absent: `keypress.sh` exits early
  with a clear message; the rest of the bridge is unaffected.

Both are installed to `/usr/bin` (`0775 root:root`) by the planned installer
(issue #10), so on a correctly-installed image they are always present; the
fail-fast checks guard against a partial or manual deployment. Both were
smoke-tested on a live C100X (kernel 4.9.11, armv7-hardfloat): `evtest` 1.35 is
the exact binary seen on that unit, and the patched `jq` 1.8.2 was confirmed to
run there too. The **embedded** payload bytes are SHA-256-verified by
`PayloadBinaries` before packaging/use; reading back and hashing the files
*after* they are written to the device's `/usr/bin` is the installer's job
(planned Phase 1c/1d, #10), not something this phase does yet.
