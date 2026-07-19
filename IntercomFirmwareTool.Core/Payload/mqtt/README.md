# MQTT bridge payload (clean-room, MIT)

These scripts are installed into the firmware image when the user ticks the
optional **Install MQTT bridge** box in Advanced options (off by default). They
expose the BTicino OpenWebNet/SCS bus and the front-panel keys over MQTT, for
Home Assistant-style integration.

## Provenance & licensing

They are an **independent, MIT-licensed reimplementation** of the behaviour of
fquinto's `mqtt_scripts/*` (which are **GPL-2.0**). To keep this repository
MIT-clean — the same reason `main.py` is not vendored (see
[`reference/fquinto/README.md`](../../../reference/fquinto/README.md)) — none of
the upstream shell/Python source is copied here; only the functional interface
that has to match for compatibility is reproduced: the file layout under
`/etc/tcpdump2mqtt`, the MQTT topic names, the OpenWebNet gateway port `30006`,
and the `TcpDump2Mqtt.conf` variable names.

The two ARM binaries the bridge needs (`jq`, MIT; `evtest`, GPL-2.0) are **not**
in this folder — they are handled separately by the installer with their own
license notices (see the installer's `THIRD_PARTY` notice).

## Files

| File | Role |
|---|---|
| `TcpDump2Mqtt` | Orchestrator: keeps sender/receiver/keypress alive, publishes status, recovers from network outages. |
| `TcpDump2Mqtt.sh` | Init launcher (symlinked from `/etc/rc5.d/S99TcpDump2Mqtt`). |
| `StartMqttSend` | `tcpdump` on `lo` → `filter.py` → publish frames to `TOPIC_DUMP`. |
| `StartMqttReceive` | Subscribe `TOPIC_RX` → OpenWebNet passthrough to the unit; gated JSON command channel. |
| `keypress.sh` | `evtest` front-panel keys → publish to `TOPIC_KEY`. |
| `filter.py` | Extract `*…##` OpenWebNet frames from the `tcpdump -A` text stream. |
| `bt_service_watchdog` | Independent init service: restarts dropbear/scsserver/mosquitto/TcpDump2Mqtt if they die. |
| `TcpDump2Mqtt.conf` | Configuration template; the installer fills in broker/topics from the UI. |

## Fixes & hardening over the upstream behaviour

1. **Remote-root backdoor closed by default.** Upstream `StartMqttReceive`
   unconditionally honoured JSON `read_file` / `write_file` / `execute_command`
   on an unauthenticated broker — root-equivalent control to anyone who could
   publish. Here that channel is **off unless** `ALLOW_REMOTE_SHELL=1` **and** the
   broker is authenticated (`MQTT_USER`) or TLS-protected (`MQTT_CAFILE`); the
   OpenWebNet passthrough (the real automation feature) is unaffected.
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

## Runtime dependencies (expected present in the firmware)

`mosquitto_pub`, `mosquitto_sub`, a local `mosquitto` broker, `tcpdump`, `nc`,
`route`, `ping`, `pgrep`, and `python`/`python3`. These ship in the C300X/C100X
firmware (upstream relies on them); the installer's read-back check flags any
that are missing before the build is accepted.
