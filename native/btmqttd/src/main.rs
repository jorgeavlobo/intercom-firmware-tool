//! btmqttd — single-connection MQTT bridge for the BTicino OpenWebNet bus.
//!
//! One long-lived MQTT client (one connection) that:
//!   * registers the retained `offline` last will at CONNECT and publishes the
//!     retained `online` birth in its on-connect handler — atomic availability, no
//!     30 s refresh hack (issue #32);
//!   * subscribes to TOPIC_RX (QoS 1) and dispatches commands (raw OWN frames to
//!     the gateway; gated JSON read_file/write_file/execute_command);
//!   * streams the OpenWebNet monitor socket to TOPIC_DUMP (raw or structured JSON);
//!   * publishes physical key presses to TOPIC_KEY (evdev);
//!   * reconciles Home Assistant discovery on every connect;
//!   * on SIGTERM/SIGINT publishes an explicit retained `offline` and exits cleanly.
//!
//! Replaces the shell-orchestrated mosquitto_pub/sub bridge (TcpDump2Mqtt,
//! StartMqttSend, StartMqttReceive, keypress.sh, ha_discovery.sh, mqtt_common.sh).

// btmqttd is a Linux daemon for the BTicino intercom: it depends on Linux-specific
// APIs (evdev for the keypad; tokio::signal::unix, libc chown/umask). Guard on
// target_os = "linux" — NOT merely `unix`, since macOS is also Unix but has no evdev
// and would otherwise slip past this guard only to fail deep inside a dependency with
// an opaque error. Fail early here with a clear message instead; build/test on Linux
// (or WSL).
#[cfg(not(target_os = "linux"))]
compile_error!("btmqttd targets Linux only — build and run host checks on Linux or WSL");

mod av;
mod config;
mod dimension;
mod ha;
mod hold;
mod keys;
mod light;
mod lock;
mod mdns;
mod own;
mod persist;
mod receiver;
mod rediscovery;
mod sender;
mod sip;
mod sprop;
mod volume;

use std::sync::Arc;
use std::time::Duration;

use rumqttc::{
    AsyncClient, Event, EventLoop, Incoming, LastWill, MqttOptions, Outgoing, QoS, Request,
    SubscribeReasonCode, TlsConfiguration, Transport,
};
use tokio::signal::unix::{signal, SignalKind};

use config::Config;

fn main() {
    // Single-threaded runtime: this daemon juggles a few sockets, not a workload —
    // one worker thread keeps the resident footprint small on the intercom.
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("btmqttd: cannot start runtime: {e}");
            std::process::exit(1);
        }
    };
    let reexec = match rt.block_on(run()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("btmqttd: {e}");
            std::process::exit(1);
        }
    };
    // Tear the runtime down (join workers, close their sockets) BEFORE replacing the process
    // image, so the re-exec starts from a clean slate.
    drop(rt);
    if reexec {
        reexec_self(); // returns ONLY on failure; on success the image is replaced
    }
}

/// Re-exec this daemon in place (same PID, so `bt_service_watchdog`'s pgrep supervision is
/// undisturbed) to activate a newly-learned light WHERE IMMEDIATELY. Exiting instead would leave
/// the WHOLE bridge offline until the watchdog's next ~60 s poll respawns it (Codex). Called only
/// AFTER the graceful shutdown in `run()`, so the learned WHERE is durably persisted and the MQTT
/// `offline` will/DISCONNECT is already sent; the fresh process re-reads the config, picks up the
/// persisted WHERE (learn-mode path), and reconnects. `exec` returns ONLY on error — then we fall
/// back to a normal exit and the watchdog respawns as before.
fn reexec_self() {
    use std::os::unix::process::CommandExt;
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "btmqttd: re-exec: cannot resolve current exe ({e}); exiting for watchdog respawn"
            );
            return;
        }
    };
    let err = std::process::Command::new(exe).args(std::env::args_os().skip(1)).exec();
    eprintln!("btmqttd: re-exec failed ({err}); exiting for watchdog respawn");
}

/// Returns `Ok(true)` when the caller should RE-EXEC the daemon immediately (a WHERE was just
/// learned), or `Ok(false)` for an ordinary signal-driven shutdown.
async fn run() -> Result<bool, String> {
    let cfg = Arc::new(Config::load()?);
    if cfg.mqtt_host.is_empty() {
        return Err("MQTT_HOST is not set in the config".into());
    }
    // Service activation time (UTC ISO-8601), captured once and republished retained
    // on every connect. Arc<str> so each spawned birth task gets a cheap clone.
    let start_iso: Arc<str> = own::utc_now_iso().into();

    let mut opts = MqttOptions::new(cfg.client_id(), cfg.mqtt_host.clone(), cfg.mqtt_port);
    opts.set_keep_alive(Duration::from_secs(60));
    // Transport-level packet-size ceiling (defense in depth). rumqttc's default
    // INCOMING limit is only 10 KB, which would reject a legitimate write_file whose
    // data approaches the 256 KB command contract; raise it to a bounded ceiling
    // ABOVE the daemon-side per-command cap (MAX_CMD_BYTES) so the daemon drops a
    // slightly-oversized command gracefully (log, keep the connection) while a wildly
    // oversized packet is refused at the transport. OUTGOING (our own replies, up to
    // the 256 KB read_file/command_result cap) needs far less.
    opts.set_max_packet_size(1024 * 1024, 512 * 1024);
    // DURABLE session (clean_session=false) with a stable, per-unit client id: the
    // broker QUEUES QoS 1 commands published to TOPIC_RX while the daemon is briefly
    // disconnected and delivers them on reconnect — closing the command-loss window a
    // clean session reopens (issue #31). Atomic birth/will still handles availability;
    // the durable session additionally preserves in-flight commands. The client id
    // folds in TOPIC_RX (see Config::client_id), so changing the command topic starts
    // a FRESH session instead of resuming the old topic's subscription.
    opts.set_clean_session(false);
    if let (Some(u), Some(p)) = (&cfg.mqtt_user, &cfg.mqtt_pass) {
        opts.set_credentials(u.clone(), p.clone());
    }
    // Retained `offline` last will: an unclean drop (crash/power loss) makes the
    // broker deliver it, so Home Assistant sees the bridge go offline. QoS 0 (the
    // shell bridge's default, and the usual convention for retained availability/LWT
    // — the retain flag, not the QoS, is what carries state to a late subscriber).
    opts.set_last_will(LastWill::new(
        cfg.topic_lastwill.clone(),
        "offline",
        QoS::AtMostOnce,
        true,
    ));
    if cfg.uses_tls() {
        opts.set_transport(Transport::tls_with_config(build_tls(&cfg)?));
    }

    let (client, mut eventloop) = AsyncClient::new(opts, 32);

    // Volume/mute state machine (issue #40), shared between the command worker (which
    // applies volume/mute/step actions) and the monitor task (which learns the real
    // volume from the bus broadcasts). All volume STATE lives here — HA is dumb.
    let volume = volume::VolumeCtl::new(&cfg, client.clone());

    // Stair-light SWITCH (opt-in; only when a WHERE is configured). The actuator has no
    // readable state, so we track the toggle and PERSIST it across reboots — restore the
    // last known on/off here so a reboot keeps the switch correct (issue: light). `None`
    // (feature off) threads through as no-op everywhere.
    // The controller does the RETAINED-MQTT + forward I/O; durable persistence runs on its
    // OWN task (`run_persist`), fed by a watch channel. That task is DRAINED at shutdown (via
    // the oneshot below) so a toggle actuated the instant before SIGTERM is still written —
    // the command worker is aborted, but the persist task is signalled + awaited.
    // Restart signal: fired to make `main` shut down cleanly and RE-EXEC in place. Two triggers:
    //   * a light WHERE is LEARNED at runtime (the state-persist task is keyed by WHERE at startup, so a
    //     clean restart is the simplest way to bind it), and
    //   * the HA "Restart bridge" maintenance button (issue #43), routed here from the command worker.
    let restart = Arc::new(tokio::sync::Notify::new());
    // LEARNABLE only in learn mode (a blank build-time WHERE). A CONFIGURED build's WHERE is
    // authoritative and always bound by the resolution below, so the HA Learn button must not be
    // able to persist a divergent address the daemon would then ignore on restart (Codex).
    let light_learnable = cfg.light_where.is_none();
    #[allow(clippy::type_complexity)]
    let (light, light_persist): (
        Option<Arc<light::LightCtl>>,
        Option<(tokio::sync::oneshot::Sender<()>, tokio::task::JoinHandle<()>)>,
    ) = if !cfg.light_enabled {
        // Feature DISABLED: forget any persisted light-state, so that re-enabling the same
        // WHERE later starts from an UNKNOWN baseline instead of restoring a value that may
        // have gone stale while untracked (a physical toggle we didn't see) — Codex. Also forget
        // any LEARNED WHERE: disabling is a deliberate reset, so re-enabling in learn mode
        // re-learns rather than silently restoring an address from a past life (CodeRabbit).
        clear_persisted_light("feature disabled").await;
        clear_persisted_light_where("feature disabled").await;
        (None, None)
    } else if let Some(where_) = {
        // Enabled. A build-time WHERE is AUTHORITATIVE: when the installer configured one, use it
        // so a later firmware can re-point the light and the reflash-surviving learned cache (on
        // the cfg/extra partition) can't silently override the newly-configured address (Codex).
        // Only when the build left WHERE blank (learn mode) do we fall back to what this unit
        // LEARNED at runtime and persisted, so a unit that shipped blank keeps it across reboots.
        match cfg.light_where.clone() {
            Some(w) => Some(w),
            None => tokio::task::spawn_blocking(persist::read_light_where).await.unwrap_or(None),
        }
    } {
        // A CONFIGURED WHERE is authoritative, so FORGET any learned WHERE now — otherwise a later
        // build that clears the field to enter learn mode would restore this stale learned address
        // (e.g. an old `112`) and control the wrong relay instead of re-learning (Codex). Only the
        // configured path clears it; the learn-mode path above is itself driven by that same file.
        if cfg.light_where.is_some() {
            clear_persisted_light_where("configured WHERE is authoritative").await;
        }
        if cfg.light_momentary {
            // MOMENTARY (staircase-timer install): the controller only forwards a PRESS — there is
            // NO tracked on/off, so no state to restore and no persist task to run. FORGET any
            // bistable state record: the relay can change while running momentary (the hardware
            // auto-offs), so a later switch back to bistable must start UNKNOWN, not restore a stale
            // on/off that could toggle the next command the wrong way (CodeRabbit).
            clear_persisted_light("momentary — no tracked state").await;
            let (ctl, _persist_rx) = light::LightCtl::new(
                &cfg,
                client.clone(),
                None,
                Some(where_),
                light_learnable,
                true, // momentary
                restart.clone(),
            );
            (Some(ctl), None)
        } else {
            let where_for_read = where_.clone();
            let restore = tokio::task::spawn_blocking(move || persist::read_light(&where_for_read))
                .await
                // A JOIN failure (the blocking read panicked) is "couldn't read" — treat as Unreadable
                // so we KEEP the record rather than deleting it.
                .unwrap_or(persist::LightRestore::Unreadable);
            // `initial` seeds the in-memory cache; `initial_uncertain` tells the persist task whether
            // the on-disk value is known to match `initial` (so an observed value equal to it must
            // still be durably written to overwrite a possibly-different record we couldn't read).
            let (initial, initial_uncertain) = match restore {
                // Normal reboot restore: a valid on/off record for THIS WHERE — disk matches `initial`.
                persist::LightRestore::State(on) => (Some(on), false),
                // No usable record (absent, a DIFFERENT WHERE's, or corrupt). Forget it, so a later
                // switch BACK to an old WHERE starts unknown instead of restoring a stale value (Codex).
                // Disk is now confirmed absent (= None), so the baseline is certain.
                persist::LightRestore::Absent => {
                    clear_persisted_light("no valid state for the configured WHERE").await;
                    (None, false)
                }
                // Present but UNREADABLE (transient I/O). Do NOT clear — a valid state may still be on
                // disk; keep it and retry next boot. Start the cache unknown, and mark the disk baseline
                // UNCERTAIN so the first observed value is durably written (overwriting whatever record
                // we couldn't read) rather than skipped as already-durable (Codex).
                persist::LightRestore::Unreadable => {
                    eprintln!(
                        "btmqttd: light: persisted state unreadable (I/O error) — keeping the record, \
                         starting from unknown"
                    );
                    (None, true)
                }
            };
            let (ctl, persist_rx) = light::LightCtl::new(
                &cfg,
                client.clone(),
                initial,
                Some(where_.clone()),
                light_learnable,
                false, // bistable
                restart.clone(),
            );
            let (persist_shutdown_tx, persist_shutdown_rx) = tokio::sync::oneshot::channel();
            // Pass the restored disk value as the persist task's durable BASELINE explicitly, so a
            // command/observe that bumps the channel before the task is first polled is still
            // persisted (not mistaken for the restored value).
            let persist_task = tokio::spawn(light::run_persist(
                where_,
                initial,
                initial_uncertain,
                persist_rx,
                persist_shutdown_rx,
            ));
            (Some(ctl), Some((persist_shutdown_tx, persist_task)))
        }
    } else {
        // LEARN MODE: enabled but no WHERE yet (blank build + none learned). The controller exists so
        // the Learn button works and the mode's control entity — a BISTABLE switch + resync, or a
        // MOMENTARY press button (no resync) — is present but UNAVAILABLE (topic_light_avail=offline).
        // No state-persist task runs until a WHERE is learned (restarting btmqttd into the where-known
        // path above). The momentary flag is carried through so command()/observe() behave once learned.
        // In momentary mode, forget any stale bistable state so a later bistable build starts unknown
        // (CodeRabbit) — mirrors the where-known momentary branch above.
        if cfg.light_momentary {
            clear_persisted_light("momentary — no tracked state").await;
        }
        let (ctl, _persist_rx) = light::LightCtl::new(
            &cfg,
            client.clone(),
            None,
            None,
            light_learnable,
            cfg.light_momentary,
            restart.clone(),
        );
        (Some(ctl), None)
    };

    // Locks (issue #41) run on their OWN task, fed by a small channel: the command worker
    // enqueues a press request (which actuator) and moves on (no 300 ms block), the lock
    // task serialises each press→hold→release, and shutdown DRAINS it (drops the sender +
    // awaits) so a press is never left without its release. See lock.rs.
    let (lock_tx, lock_rx) = tokio::sync::mpsc::channel::<lock::Lock>(lock::QUEUE_DEPTH);
    // Set at shutdown so the lock task finishes the pulse in progress but discards
    // queued (not-yet-started) presses — bounding the drain to one pulse.
    let lock_stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let lock_task = tokio::spawn(lock::run(lock_rx, lock_stopping.clone()));

    // On-demand viewing (Phase 2, issue #104): a loopback SIP UA that INVITEs the panel's local
    // answer-machine to bring the idle A/V session up on a `view_camera` action, then BYEs it after
    // an idle window. It drives ONLY signalling — the actual video is siphoned by `av`, which
    // auto-arms when the panel starts streaming — so this is gated on `camera_enabled` (the media
    // path) as well. `view_tx` feeds the trigger from receiver's action dispatch; `None` when the
    // feature is off threads through as a no-op (and receiver logs an ignored `view_camera`).
    let (sip_task, sip_stopping, view_tx): (
        Option<tokio::task::JoinHandle<()>>,
        Arc<std::sync::atomic::AtomicBool>,
        Option<tokio::sync::mpsc::Sender<sip::ViewCmd>>,
    ) = {
        let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
        if cfg.camera_enabled && cfg.camera_ondemand_enabled {
            let (tx, rx) = tokio::sync::mpsc::channel::<sip::ViewCmd>(8);
            let task = tokio::spawn(sip::run(cfg.clone(), stopping.clone(), rx));
            (Some(task), stopping, Some(tx))
        } else {
            (None, stopping, None)
        }
    };

    // Viewer-activity auto-hold (issue #120, hold.rs): the "someone is watching" signal the SIP hold
    // loop flagged as deferred. On-device ONLY — it counts ESTABLISHED sockets on local port 8554 in
    // /proc/net/tcp{,6} (a live RTSP viewer) and renews the short-linger window while one is connected, so
    // Home Assistant just opens the camera with no manual `view_camera` press. Shares `view_tx` with the
    // SIP UA (it pokes ViewCmd::Hold, which renews only the short linger — a separate deadline from the
    // manual `view_camera` full window), and only runs when that UA is up (Some view_tx).
    let (hold_task, hold_stopping): (Option<tokio::task::JoinHandle<()>>, Arc<std::sync::atomic::AtomicBool>) = {
        let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
        match (&view_tx, cfg.camera_ondevice) {
            (Some(tx), true) => (
                Some(tokio::spawn(hold::run(stopping.clone(), tx.clone()))),
                stopping,
            ),
            _ => (None, stopping),
        }
    };

    // Transparent sprop provisioning (issue #120, sprop.rs): the panel advertises no sprop-parameter-sets
    // (nor in its SIP answer — hardware-confirmed), so on-device only. It is a PASSIVE loopback RTP
    // listener: the panel only feeds a REAL consumed view (a silent probe times out — hardware-confirmed),
    // and ffmpeg's `-sdp_file` can't emit sprop on a copy path either (also hardware-confirmed, PR #129).
    // So go2rtc's own `exec:` ffmpeg (which runs while a client is watching) ships a raw H.264 RTP copy to
    // a loopback UDP port (127.0.0.1:40100), and this task binds that port and parses the SPS/PPS itself,
    // then persists the value — it never brings the panel up itself. Because it holds no SIP, it needs only
    // the on-device gate (not the SIP UA): spawn it whenever `camera_ondevice` is set. It returns on its
    // own once it learns; the handle is kept only to abort a still-listening task cleanly at shutdown (like
    // av.rs).
    let (sprop_task, sprop_stopping): (Option<tokio::task::JoinHandle<()>>, Arc<std::sync::atomic::AtomicBool>) = {
        let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
        if cfg.camera_ondevice {
            (Some(tokio::spawn(sprop::run(cfg.clone(), stopping.clone()))), stopping)
        } else {
            (None, stopping)
        }
    };
    // On-device camera OFF ⇒ forget any learned sprop, so a later re-enable (or a panel swap) re-learns
    // instead of reassembling the runtime SDP with a stale value. Mirrors the light-where disable reset.
    // (Only when the on-device feature itself is off; an on-device unit with on-demand viewing off keeps
    // its learned value — the operator may have supplied it, and the probe just can't run right now.)
    if !cfg.camera_ondevice {
        clear_persisted_camera_sprop("on-device camera disabled").await;
    }

    // Commands from TOPIC_RX go through a BOUNDED channel to a SINGLE ordered worker,
    // not a task-per-message. This does two things at once:
    //   * Order — the shell receiver consumed the subscription line-by-line, so
    //     sequential commands (ordered OWN frames, or write_file/execute_command
    //     series) were applied in order; one worker awaiting each dispatch preserves
    //     that. Per-message tasks could complete out of order.
    //   * Bound — a burst (or a slow execute_command) can't spawn unbounded tasks and
    //     exhaust memory / starve the single-threaded runtime; over the queue depth a
    //     command is DROPPED with a log line (predictable overload). The broker's
    //     TOPIC_RX ACL remains the primary gate.
    const CMD_QUEUE_DEPTH: usize = 8;
    // Per-command payload ceiling, enforced BEFORE cloning/enqueueing so the queue
    // bounds memory (<= depth x cap = 4 MB here), not just message count — otherwise
    // large publishes could accumulate while the worker is busy (e.g. a 60 s
    // execute_command). 512 KB = the 256 KB write_file DECODED-data contract plus room
    // for JSON string escaping (newlines/quotes/backslashes roughly double a text
    // config), so ordinary escaped writes fit; a pathological all-control-byte body
    // (which escapes ~6x) is still dropped with a log line, as is anything larger.
    const MAX_CMD_BYTES: usize = 512 * 1024;
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(CMD_QUEUE_DEPTH);
    let cmd_worker = tokio::spawn({
        let cfg = cfg.clone();
        let client = client.clone();
        let volume = volume.clone();
        let lock_tx = lock_tx.clone();
        let light = light.clone();
        let view_tx = view_tx.clone();
        // Shared with the light-learn path: the HA "Restart bridge" button (issue #43) fires this same
        // Notify to trigger the clean-shutdown-then-re-exec in `run`'s select loop below.
        let restart = restart.clone();
        async move {
            while let Some(payload) = cmd_rx.recv().await {
                receiver::dispatch(&cfg, &client, &volume, &lock_tx, light.as_ref(), view_tx.as_ref(), &restart, &payload).await;
            }
        }
    });

    // Bus -> MQTT and keypad -> MQTT run as independent tasks; they publish through
    // the shared client (rumqttc queues while disconnected and flushes on connect).
    // Keep their handles so shutdown can ABORT every MQTT-producing task before it
    // publishes the final retained `offline` — otherwise a task still in flight could
    // enqueue a publish AFTER `offline` and leave stale state retained on the broker.
    // Broker connectivity, driven by THIS event loop (true on ConnAck, false on drop below) and
    // read by the sender AND the keypad task: a momentary event (door call or keypress) fired while
    // the broker is down is DROPPED rather than enqueued, so rumqttc can't flush it late on reconnect
    // and fire a stale automation (#71).
    let broker_online = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let sender_task = tokio::spawn(sender::run(
        cfg.clone(),
        client.clone(),
        volume.clone(),
        light.clone(),
        broker_online.clone(),
    ));
    let keys_task = tokio::spawn(keys::run(cfg.clone(), client.clone(), broker_online.clone()));
    // Live doorbell camera (issue #103): opt-in. When enabled, this task runs its own
    // OWN monitor (:20000, independent of `sender`) and, whenever the panel brings an A/V
    // session up, adds a UDP client on `bt_av_media` (:30007) so a cleartext RTP copy is
    // fanned out to the go2rtc/HA host. It publishes NOTHING to MQTT (it drives the on-box
    // A/V daemon, not the broker), so it is NOT one of the tasks aborted before the final
    // retained `offline`; it is stopped separately at shutdown. There is no half-actuated
    // state to drain (it never tears the session down — the panel owns that), so a plain
    // `stopping`-flag + abort is enough. `None` (feature off) threads through as no-op.
    let (av_task, av_stopping): (
        Option<tokio::task::JoinHandle<()>>,
        Arc<std::sync::atomic::AtomicBool>,
    ) = {
        let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let task = if cfg.camera_enabled {
            Some(tokio::spawn(av::run(cfg.clone(), stopping.clone())))
        } else {
            None
        };
        (task, stopping)
    };
    // Birth is split across two events: SUBSCRIBE to the command topic on ConnAck,
    // then ANNOUNCE (online + start_date + HA) only after the broker confirms the
    // subscription (SubAck success). announce_task is the one that publishes
    // TOPIC_LASTWILL (`online`), so a lingering one could clobber the shutdown
    // `offline`; both are aborted on the next ConnAck and on exit.
    let mut subscribe_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut announce_task: Option<tokio::task::JoinHandle<()>> = None;

    let mut sig_term = signal(SignalKind::terminate()).map_err(|e| e.to_string())?;
    let mut sig_int = signal(SignalKind::interrupt()).map_err(|e| e.to_string())?;

    eprintln!(
        "btmqttd: starting (broker {}:{}, client-id {})",
        cfg.mqtt_host,
        cfg.mqtt_port,
        cfg.client_id()
    );

    // Broker rediscovery (issue #43) activates only when ALL of these hold:
    //   * opted in (MQTT_REDISCOVERY);
    //   * the broker is a NAME — the mechanism repoints the name's /etc/hosts mapping,
    //     which a bare-IP config never consults;
    //   * there is a TRUST ANCHOR — TLS (the reconnect validates the broker's pinned
    //     cert + hostname, so any proposed host that isn't the broker fails the
    //     handshake) OR a recorded broker MAC (adoption then requires an ARP match).
    // Without an anchor, rediscovery could repoint a plaintext bridge at the wrong open
    // :1883 (the on-box mosquitto, a neighbour's broker) and leak credentials/commands
    // to it — so we DISABLE it and say why, rather than adopt an unauthenticated host
    // (issue #43 / Codex P1 / CodeRabbit). Warnings are one-shot (startup only).
    let host_is_ip = cfg.mqtt_host.parse::<std::net::IpAddr>().is_ok();
    let has_trust_anchor = cfg.uses_tls() || cfg.broker_mac.is_some();
    let rediscovery_active = cfg.rediscovery && !host_is_ip && has_trust_anchor;
    if cfg.rediscovery && host_is_ip {
        eprintln!(
            "btmqttd: rediscovery enabled but MQTT_HOST is an IP ({}); it needs a hostname to \
             repoint — disabled",
            cfg.mqtt_host
        );
    } else if cfg.rediscovery && !has_trust_anchor {
        eprintln!(
            "btmqttd: rediscovery enabled but no trust anchor (no TLS CA and no \
             MQTT_BROKER_MAC); refusing to adopt an unauthenticated broker — disabled. Set \
             MQTT_CAFILE (TLS) or MQTT_BROKER_MAC to enable it."
        );
    }
    // Rediscovery state: how many consecutive UNREACHABLE poll failures have accrued
    // (a non-unreachable error resets it), and the addresses already proposed this
    // outage (so proposals are monotonic). Both reset on a successful connect.
    let mut conn_failures: u32 = 0;
    let mut tried_ips: std::collections::HashSet<std::net::Ipv4Addr> =
        std::collections::HashSet::new();
    // mDNS proposals refused this outage, kept SEPARATE from `tried_ips` so the per-pass scan
    // re-arm (retire_scan_subnets) never re-arms them: a wrong mDNS broker INSIDE an anchor /24
    // would otherwise be re-proposed every pass, resetting the dry-cycle bound forever (Codex P2).
    // Only a ConnAck or the bounded full-reset clears it.
    let mut mdns_rejected_ips: std::collections::HashSet<std::net::Ipv4Addr> =
        std::collections::HashSet::new();
    // How many consecutive rediscovery rounds have retired their /24 scan set without
    // finding the broker (a "dry" cycle). After FULL_RESET_AFTER_DRY_CYCLES of these,
    // `retire_scan_subnets` fully clears BOTH `tried` and `mdns_rejected_ips` (including
    // cross-subnet mDNS rejections) — so recovery stays self-healing if a mDNS-advertised
    // broker that was once (correctly) rejected later becomes reachable (Copilot). Reset on
    // any connect.
    let mut rediscover_dry_cycles: u32 = 0;

    // Persisted-IP boot restore (issue #49 item 1): the last connect-confirmed broker IP
    // is remembered on a writable, reboot-persistent partition. Seed /etc/hosts from it
    // BEFORE the first connect so a reboot after the broker moved reconnects to the
    // learned IP immediately — instead of re-running the whole failure-count + /24 scan.
    // Only when rediscovery is active (name broker + trust anchor).
    //
    // `build_ip` — the record's "base" — is read from the IMMUTABLE boot init script
    // (rediscovery::build_time_ip), NOT the mutable /etc/hosts mapping. That is what makes
    // this correct across a bt_service_watchdog RESPAWN (where /etc/hosts may already hold
    // a rediscovered IP) and a firmware RE-FLASH (which the rootfs script reflects but the
    // surviving cfg/extra record does not) — Codex.
    //
    // Two independent flags: `last_persisted` is the ADOPTED learned IP (what /etc/hosts is
    // seeded to), so a stable broker never rewrites the flash partition; `persisted_on_disk`
    // is whether the state FILE exists at all — even one holding a record for a DIFFERENT host
    // or a corrupt one (neither parses), so a build-IP ConnAck clears it and a later switch
    // back to that host can't resurrect its obsolete learned IP (Codex/Copilot). Persist I/O
    // is blocking std::fs, so it's offloaded to the blocking pool (single-threaded runtime —
    // Copilot).
    let build_ip = if rediscovery_active {
        rediscovery::build_time_ip(&cfg.mqtt_host).await
    } else {
        None
    };
    let (persisted_file_exists, record) = if rediscovery_active {
        let host = cfg.mqtt_host.clone();
        match tokio::task::spawn_blocking(move || persist::read_state(&host)).await {
            Ok(state) => state,
            // A JoinError here means the read_state task did NOT complete — it panicked or was
            // cancelled/aborted. Surface it (it's diagnosable), then fall back conservatively:
            // `record = None` (we have no valid learned IP to seed), but `persisted_file_exists =
            // true` — we DON'T know whether the file is there, so assume it MIGHT be, so a later
            // build-IP ConnAck can still run `persist::clear()` and drop a possibly-stale record
            // (clear is safe/idempotent when the file is absent). Reporting "absent" (false) could
            // instead strand a stale record on disk (Copilot).
            Err(e) => {
                eprintln!(
                    "btmqttd: persist: read_state task did not complete ({e}); treating the record \
                     as unreadable-but-possibly-present"
                );
                (true, None)
            }
        }
    } else {
        (false, None)
    };

    let mut last_persisted: Option<std::net::Ipv4Addr> = None;
    let mut persisted_on_disk = persisted_file_exists;
    // The last address the broker was CONFIRMED at — a ConnAck this session, or a persisted
    // learned IP we actually SEEDED at boot because it passed the trust gate. This anchors the
    // fallback /24 scan (rediscover's `confirmed_anchor`). It is deliberately SEPARATE from
    // `last_persisted`: the "MAC unconfirmed at boot" branch below sets `last_persisted` as a
    // write-comparison baseline for a REJECTED (un-seeded) record, and that address must never
    // become a scan anchor — doing so could sweep the wrong subnet (Codex P1 / Copilot).
    let mut last_confirmed_ip: Option<std::net::Ipv4Addr> = None;
    if let (Some(build_ip), Some((base, learned))) = (build_ip, record) {
        // Apply the record only while its base still matches this firmware's build IP; a
        // mismatch means a re-flash re-pointed the broker and the record is stale (it will
        // be cleared on the first build-IP ConnAck via `persisted_on_disk`).
        if base == build_ip {
            // Seed the learned IP. In PLAINTEXT mode re-apply the same ARP-MAC gate
            // rediscover() uses: a persisted IP that DHCP reassigned while the unit was off
            // must not receive our credentials on the first connect (Codex). Under TLS the
            // reconnect's pinned-cert handshake is the gate. seed_hosts is idempotent, so a
            // respawn whose /etc/hosts already holds the learned IP just no-ops.
            let trusted = if cfg.uses_tls() {
                true
            } else if let Some(mac) = cfg.broker_mac {
                rediscovery::arp_mac_matches(learned, cfg.mqtt_port, mac).await
            } else {
                false // rediscovery_active guarantees TLS or a MAC; belt-and-braces
            };
            if trusted {
                match rediscovery::seed_hosts(&cfg.mqtt_host, learned).await {
                    Ok(true) => {
                        last_persisted = Some(learned);
                        last_confirmed_ip = Some(learned); // seeded a trusted, previously-confirmed IP
                        eprintln!(
                            "btmqttd: seeded '{}' -> {learned} in {} from persisted state",
                            cfg.mqtt_host, rediscovery::HOSTS_PATH
                        );
                    }
                    Ok(false) => {
                        last_persisted = Some(learned); // already mapped (respawn)
                        last_confirmed_ip = Some(learned);
                    }
                    Err(e) => eprintln!("btmqttd: could not seed persisted broker IP: {e}"),
                }
            } else {
                // MAC unconfirmed at boot (broker unreachable, or its IP was reassigned): do
                // NOT seed /etc/hosts. But the record (base, learned) is already on disk, so
                // keep `learned` as the write-comparison baseline — if normal rediscovery later
                // confirms the broker AT that same learned IP, the ConnAck sees no change and
                // skips a redundant rewrite/fsync of the identical record; if it's elsewhere,
                // the ConnAck still updates it (Codex).
                last_persisted = Some(learned);
                eprintln!(
                    "btmqttd: persisted broker IP {learned} did not confirm the broker MAC \
                     at boot; not seeding (normal rediscovery will re-locate it)"
                );
            }
        }
    }

    // Set when the loop exits to activate a newly-learned WHERE (vs. an ordinary signal): the
    // caller then RE-EXECs instead of exiting, so the bridge is back in under a second rather than
    // after a full watchdog poll (~60 s).
    let mut reexec = false;
    loop {
        tokio::select! {
            _ = sig_term.recv() => break,
            _ = sig_int.recv() => break,
            // A restart was requested — a newly-learned light WHERE to activate, or the HA "Restart
            // bridge" button (#43). Shut down cleanly (same path as SIGTERM), then RE-EXEC so btmqttd
            // comes straight back up (with the learned WHERE active, and re-reading its config).
            _ = restart.notified() => {
                // Stand down while a reboot is OUTSTANDING. This is the single point BOTH restart
                // producers (the "Restart bridge" button and a newly-learned light WHERE) funnel
                // through, so guarding it — not just the button's dispatch site — is what actually
                // covers them: re-execing here drops the runtime and cancels the reboot process's
                // exit-observer, which would strand a hung reboot and reset its one-process bound in
                // the fresh image (CodeRabbit). A learned WHERE is already persisted, so it still
                // activates at the next process start; the button press is simply superseded by the
                // reboot. The gate clears once the reboot process is observed gone, re-enabling both.
                if receiver::reboot_in_progress() {
                    eprintln!("btmqttd: restart deferred: a reboot is already in progress");
                    continue;
                }
                eprintln!("btmqttd: restart requested; shutting down cleanly to re-exec");
                reexec = true;
                break;
            }
            ev = eventloop.poll() => {
                match ev {
                    Ok(Event::Incoming(Incoming::ConnAck(_))) => {
                        // Broker is up: momentary events (door call / keypress) may publish again (#71).
                        broker_online.store(true, std::sync::atomic::Ordering::Relaxed);
                        // Connected: clear the rediscovery failure streak and forget
                        // proposed addresses, so a later outage starts fresh and a broker
                        // that returns to a former address can be found again.
                        conn_failures = 0;
                        tried_ips.clear();
                        mdns_rejected_ips.clear();
                        rediscover_dry_cycles = 0;
                        // Persist the connect-confirmed broker IP (issue #49 item 1): this
                        // ConnAck means the current /etc/hosts mapping authenticated / passed
                        // the pinned-TLS handshake, so it is trustworthy to remember for the
                        // next boot. Only meaningful once a name broker has a build-time base
                        // to compare against (`build_ip`).
                        // The disk work runs on the blocking pool (the runtime is
                        // single-threaded — Copilot) and is AWAITED there: awaiting a
                        // spawn_blocking yields the reactor to other tasks rather than stalling
                        // it, and lets us advance the in-memory change-gate ONLY after the write
                        // actually lands — so a briefly-unavailable partition is retried on the
                        // next ConnAck instead of being suppressed forever (Codex/Copilot).
                        let confirmed_now = rediscovery::current_broker_ip(&cfg.mqtt_host).await;
                        // This IP just authenticated: record it as the fallback-scan anchor
                        // regardless of whether a build-time mapping is readable. Gating this on
                        // `build_ip` (as the persistence block below is) would, when the boot
                        // script has no broker line, leave the anchor unset — and rediscovery
                        // would then fall back to the current /etc/hosts value, i.e. possibly an
                        // unconfirmed mDNS proposal, the very drift the anchor prevents (CodeRabbit).
                        if let Some(confirmed) = confirmed_now {
                            last_confirmed_ip = Some(confirmed);
                        }
                        if let (Some(build_ip), Some(confirmed)) = (build_ip, confirmed_now) {
                            if confirmed == build_ip {
                                // The broker is at (or has returned to) its build-time IP, which
                                // the boot init re-seeds anyway. Forget any on-disk record —
                                // including one boot restore REJECTED (base mismatch / MAC gate),
                                // so `persisted_on_disk`, not `last_persisted`, drives the clear
                                // (CodeRabbit) — so a reboot doesn't seed a now-wrong address.
                                if persisted_on_disk
                                    && tokio::task::spawn_blocking(persist::clear)
                                        .await
                                        .unwrap_or(false)
                                {
                                    last_persisted = None;
                                    persisted_on_disk = false;
                                }
                            } else if last_persisted != Some(confirmed) {
                                // A rediscovered IP that just authenticated → remember it against
                                // the build-time base. Write only on a CHANGE, so a stable broker
                                // never churns the flash partition.
                                let host = cfg.mqtt_host.clone();
                                if tokio::task::spawn_blocking(move || {
                                    persist::store(&host, build_ip, confirmed)
                                })
                                .await
                                .unwrap_or(false)
                                {
                                    last_persisted = Some(confirmed);
                                    persisted_on_disk = true;
                                }
                            }
                        }
                        // SUBSCRIBE to the command topic, as its OWN task (not inline):
                        // the subscribe enqueues into the same bounded request channel
                        // THIS poll loop drains, so awaiting it here could deadlock if
                        // the bus/key tasks filled the channel during an outage.
                        // Announcing availability waits for the SubAck (below). Abort any
                        // still-running tasks from a previous connect first. The announce
                        // task is abort-AND-AWAITED (stop) because it may publish retained
                        // `online` OR `offline`: abort alone is async, so a stale one could
                        // still enqueue AFTER the next connect's availability publish and
                        // leave the wrong retained state on the broker.
                        if let Some(h) = subscribe_task.take() {
                            h.abort();
                        }
                        if let Some(h) = announce_task.take() {
                            stop(h).await;
                        }
                        subscribe_task =
                            Some(tokio::spawn(subscribe_cmd(cfg.clone(), client.clone())));
                    }
                    Ok(Event::Incoming(Incoming::SubAck(suback))) => {
                        // Announce availability ONLY after the broker confirms the command
                        // subscription AT QoS >= 1. A Failure (0x80 — ACL/bad filter) OR a
                        // QoS-0 DOWNGRADE grant both break reliable command delivery: the
                        // effective QoS is min(pub, sub), so a QoS-0 grant silently drops
                        // the QoS-1 / durable-session command queueing this bridge relies on
                        // (issue #12 item 2 / #31). In either case DON'T publish `online` —
                        // a false availability would let availability-triggered automations
                        // lose commands. TOPIC_RX is our only SUBSCRIBE, so this SubAck is
                        // it; log the granted codes to aid diagnosis.
                        let ready = !suback.return_codes.is_empty()
                            && suback.return_codes.iter().all(|c| {
                                matches!(
                                    c,
                                    SubscribeReasonCode::Success(
                                        QoS::AtLeastOnce | QoS::ExactlyOnce
                                    )
                                )
                            });
                        // abort-AND-AWAIT (stop): the previous availability task may be a
                        // refusal-path `announce_offline`; if only abort()ed it could still
                        // enqueue `offline` AFTER the `online` we spawn below and leave the
                        // bridge retained offline despite a command-ready subscription.
                        if let Some(h) = announce_task.take() {
                            stop(h).await;
                        }
                        if !ready {
                            eprintln!(
                                "btmqttd: subscription to {} not granted at QoS>=1 \
                                 (codes {:?}); not announcing online",
                                cfg.topic_rx, suback.return_codes
                            );
                            // Assert retained `offline`: the bridge is connected but can't
                            // reliably receive commands, so a stale retained `online` from a
                            // previous run must not leave HA thinking we're available.
                            // Tracked via announce_task so it's aborted on the next ConnAck /
                            // shutdown like the online announce.
                            announce_task =
                                Some(tokio::spawn(announce_offline(cfg.clone(), client.clone())));
                        } else {
                            announce_task = Some(tokio::spawn(announce(
                                cfg.clone(),
                                client.clone(),
                                start_iso.clone(),
                                volume.clone(),
                                light.clone(),
                            )));
                        }
                    }
                    Ok(Event::Incoming(Incoming::Publish(p))) => {
                        // TOPIC_RX is the ONLY subscription, so every incoming Publish
                        // is a command — match on the packet, not on p.topic ==
                        // cfg.topic_rx: a wildcard ("Bticino/+/rx") or shared
                        // ("$share/g/…") TOPIC_RX (which MqttInstaller permits) is
                        // delivered under its CONCRETE topic name, which would never
                        // equal the filter string.
                        //
                        // Commands must be published NON-retained. Drop a retained
                        // delivery (the subscribe-time retained message, or one
                        // mistakenly published retained) so a stale command isn't
                        // replayed on every connect — the shell used mosquitto_sub -R
                        // plus a startup retained-clear for this.
                        if p.retain {
                            eprintln!("btmqttd: ignoring retained message on {}", cfg.topic_rx);
                        } else if p.payload.len() > MAX_CMD_BYTES {
                            eprintln!(
                                "btmqttd: command dropped — {} bytes exceeds the {MAX_CMD_BYTES}-byte limit",
                                p.payload.len()
                            );
                        } else if let Err(e) = cmd_tx.try_send(p.payload.to_vec()) {
                            // Full -> overloaded (drop, don't queue unboundedly);
                            // Closed -> the worker is gone (shutting down).
                            match e {
                                tokio::sync::mpsc::error::TrySendError::Full(_) => eprintln!(
                                    "btmqttd: command dropped — handler queue full (>{CMD_QUEUE_DEPTH} pending)"
                                ),
                                tokio::sync::mpsc::error::TrySendError::Closed(_) => {}
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        // Broker is down: momentary events (door call / keypress) are now DROPPED (not
                        // queued for a late flush) until the next ConnAck re-sets this (issue #71).
                        broker_online.store(false, std::sync::atomic::Ordering::Relaxed);
                        // ...and PURGE any momentary events rumqttc already buffered for replay.
                        // poll() ran clean() on this error, moving the requests channel + unacked
                        // state into `pending` BEFORE returning Err; on the single-threaded runtime
                        // no task interleaves between that and here (no `.await` above), so every
                        // press queued during the disconnect-DETECTION window (up to ~keepalive, 60s)
                        // is in `pending` now. Drop them so none is flushed late on reconnect and
                        // fires a time-sensitive automation. Together with the gate above this makes
                        // the drop airtight: the gate stops events once the drop is DETECTED, this
                        // purge discards those queued before detection. (QoS-0 copies caught
                        // mid-flush are dropped by rumqttc itself — never tracked in `outgoing_pub`,
                        // and its write buffer is cleared on reconnect.) Retained state and the dump
                        // stream are KEPT: re-seeded on reconnect / a live QoS-0 stream.
                        eventloop
                            .pending
                            .retain(|req| !is_momentary_publish(req, &cfg));
                        // Connection dropped/unreachable. ABORT the in-flight birth tasks
                        // NOW — not at the next ConnAck. Otherwise a subscribe/announce
                        // task still running through the outage could enqueue a stale
                        // retained `online` while the eventloop isn't draining the request
                        // channel; rumqttc would then flush that stale `online` on
                        // reconnect BEFORE the fresh SubAck re-establishes the command
                        // subscription, reopening the availability-before-readiness gap the
                        // SubAck gate exists to close. AWAIT each (via stop) so it has
                        // definitely stopped before we reconnect; the next ConnAck
                        // re-subscribes and re-announces from scratch.
                        if let Some(h) = subscribe_task.take() {
                            stop(h).await;
                        }
                        if let Some(h) = announce_task.take() {
                            stop(h).await;
                        }
                        // rumqttc reconnects on the next poll; back off briefly so a
                        // hard-down broker doesn't spin. RACE the backoff against the
                        // shutdown signals — a plain sleep would block SIGTERM/SIGINT for
                        // up to 5 s while the broker is down.
                        eprintln!("btmqttd: connection: {e}");
                        // Only failures consistent with a STALE/WRONG address advance the
                        // streak (see is_unreachable): a socket-level I/O failure, a
                        // network timeout, or a TLS failure — the last meaning the peer
                        // at this address did NOT present our pinned cert, i.e. the IP is
                        // now a different host (DHCP-reuse). A broker-side MQTT refusal
                        // (bad credentials / not authorized), reached under TLS only
                        // AFTER the cert validated, means the hostname still points at the
                        // REAL broker rejecting US — so it does not advance the streak,
                        // and RESETS it so the threshold stays truly CONSECUTIVE (issue
                        // #43 / Codex P2 / Copilot).
                        let unreachable = rediscovery::is_unreachable(&e);
                        if unreachable {
                            conn_failures = conn_failures.saturating_add(1);
                        } else {
                            conn_failures = 0;
                        }
                        // Rediscover once an UNREACHABLE outage persists. Each wrong
                        // candidate is itself an unreachable failure — a wrong TLS host
                        // fails the pinned handshake (Tls), a dead address is refused/reset
                        // (Io) — so the streak stays above the threshold and the next pass
                        // proposes the next candidate, all without a separate "engaged"
                        // flag. Crucially, a broker-level MQTT refusal (bad credentials /
                        // ACL) is NOT unreachable: it reset the streak above, so once the
                        // scan lands on the REAL broker (which rejects us only at the MQTT
                        // layer) we STOP repointing and stay on it rather than wandering to
                        // another candidate (issue #43 / Codex P2). Each pass repoints the
                        // /etc/hosts mapping; the reconnect applies the normal
                        // authenticated/TLS-pinned connect (the trust gate). RACE it
                        // against shutdown so a scan can't delay SIGTERM/SIGINT.
                        if rediscovery_active
                            && unreachable
                            && conn_failures >= rediscovery::REDISCOVER_AFTER_FAILURES
                        {
                            tokio::select! {
                                _ = sig_term.recv() => break,
                                _ = sig_int.recv() => break,
                                // Anchor the fallback scan on the last CONFIRMED IP
                                // (`last_confirmed_ip` — a ConnAck, or a trusted seeded persisted
                                // IP; NEVER the MAC-rejected persistence baseline), so it follows
                                // a confirmed cross-subnet move yet never latches onto an
                                // unconfirmed mDNS proposal or a rejected record (Codex P1 /
                                // Copilot). `None` ⇒ anchor on the build-time mapping.
                                r = rediscovery::rediscover(&cfg, &mut tried_ips, &mut mdns_rejected_ips, last_confirmed_ip, &mut rediscover_dry_cycles) => {
                                    if let Some(ip) = r {
                                        eprintln!(
                                            "btmqttd: rediscovery: repointed '{}' -> {ip} in {}",
                                            cfg.mqtt_host, rediscovery::HOSTS_PATH
                                        );
                                    }
                                }
                            }
                        }
                        tokio::select! {
                            _ = sig_term.recv() => break,
                            _ = sig_int.recv() => break,
                            _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                        }
                    }
                }
            }
        }
    }

    // Stop every MQTT-producing task BEFORE the final `offline`, so none of them can
    // enqueue a publish after it and leave stale state (e.g. a lingering announce task
    // re-retaining `online`) on the broker. abort() alone is NOT enough — it is
    // asynchronous, so a task could still be mid-publish and enqueue AFTER `offline`;
    // AWAIT each aborted handle so it has definitely stopped (any request it already
    // enqueued is ordered before `offline` in rumqttc's FIFO channel) before we queue
    // the final `offline` + DISCONNECT.
    async fn stop(task: tokio::task::JoinHandle<()>) {
        task.abort();
        let _ = task.await;
    }
    if let Some(h) = subscribe_task.take() {
        stop(h).await;
    }
    if let Some(h) = announce_task.take() {
        stop(h).await;
    }
    stop(sender_task).await;
    stop(keys_task).await;
    stop(cmd_worker).await;
    // The command worker is now quiesced — no further `reboot` command can be dispatched — so the reboot
    // gate is STABLE from here. Re-check it before committing to a re-exec: the `restart.notified()` arm
    // tested the gate when it fired, but a `reboot` queued behind that restart can still have run during one
    // of the awaited task-stops ABOVE (each `stop(..).await` yields while this worker was alive), setting
    // the gate and spawning the reboot child + its exit-observer only now. Re-execing would drop the runtime,
    // cancel that observer, and resurrect with the gate reset — the stranded-hung-reboot the arm's guard is
    // meant to prevent (Codex). So if a reboot became outstanding, do NOT re-exec: fall back to a plain exit
    // (the watchdog respawns the bridge if the box does not actually go down), never racing a reboot with an
    // instant same-PID re-exec.
    if reexec && receiver::reboot_in_progress() {
        eprintln!("btmqttd: re-exec cancelled: a reboot became outstanding during shutdown; exiting instead");
        reexec = false;
    }
    // Drain the stair-light persist task LAST among the state producers: `command()` (on
    // cmd_worker) and `observe()` (on sender_task) are now stopped, so no further state can be
    // enqueued. Signal the task and await its final flush (bounded) so a toggle actuated in the
    // last instant reaches disk instead of being lost with the aborted worker.
    if let Some((persist_shutdown_tx, persist_task)) = light_persist {
        let _ = persist_shutdown_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(2), persist_task).await;
    }
    // Lock task: DRAIN rather than abort. Signal `stopping` FIRST so the task finishes
    // the pulse IN PROGRESS (its release is sent) but discards queued, not-yet-started
    // presses (which emitted nothing, so dropping them strands nothing). Then drop this
    // last sender (cmd_worker's is stopped above) to close the channel and await. The
    // wait is bounded to ONE worst-case pulse plus a margin (lock::MAX_PULSE covers
    // press+hold+release at the tight forward timeout) — enough for the in-flight release
    // regardless of how many were queued, yet an unresponsive gateway can't hang exit.
    // On a responsive gateway a pulse is ~300 ms, so this returns almost immediately.
    lock_stopping.store(true, std::sync::atomic::Ordering::Relaxed);
    drop(lock_tx);
    let _ = tokio::time::timeout(lock::MAX_PULSE + Duration::from_secs(1), lock_task).await;
    // Camera A/V siphon (issue #103): signal it to stop, then abort-and-await. It publishes
    // nothing to the broker (so its ordering vs. the final `offline` is irrelevant) and holds
    // no half-actuated bus state (it never sends a teardown), so this is a plain stop — the
    // dropped `:30007` socket lets the panel's own teardown reap our added client.
    if let Some(h) = av_task {
        av_stopping.store(true, std::sync::atomic::Ordering::Relaxed);
        stop(h).await;
    }
    // Viewer-activity auto-hold (hold.rs): stop it FIRST. It holds a `view_tx` clone, so it must be gone
    // before the SIP block below drops the LAST sender to close `view_rx` — otherwise a surviving clone
    // keeps the channel open and the SIP task never sees the shutdown. It neither publishes to the broker
    // nor holds half-actuated bus state (it only reads /proc and pokes Hold), so a plain abort is clean
    // and drops its `view_tx` clone.
    if let Some(h) = hold_task {
        hold_stopping.store(true, std::sync::atomic::Ordering::Relaxed);
        stop(h).await;
    }
    // Passive sprop listener (sprop.rs): a loopback UDP RTP listener that holds NO `view_tx` and
    // publishes nothing, so abort it like av.rs — its ordering vs. the SIP drain below is irrelevant.
    if let Some(h) = sprop_task {
        sprop_stopping.store(true, std::sync::atomic::Ordering::Relaxed);
        stop(h).await;
    }
    // On-demand SIP UA (issue #104): drain it gracefully. `stop(cmd_worker)` above already dropped
    // that task's `view_tx` clone, so dropping THIS last sender closes `view_rx`; the SIP task then
    // observes the closed channel (its `view_rx.recv()==None`) and sends its BYE to tear the panel
    // session down cleanly. AWAIT it with a bound rather than abort()-ing: an abort can drop the task
    // at an `.await` before the BYE is sent, leaving the panel session pinned (CodeRabbit). The 3 s
    // cap keeps shutdown bounded if the dialog is wedged.
    if let Some(h) = sip_task {
        sip_stopping.store(true, std::sync::atomic::Ordering::Relaxed);
        drop(view_tx);
        let _ = tokio::time::timeout(Duration::from_secs(3), h).await;
    }
    shutdown(&cfg, &client, &mut eventloop).await;
    Ok(reexec)
}

/// Best-effort clear of the persisted stair-light record (bounded retries, log on ultimate
/// failure). Used when the feature is DISABLED, and when an ENABLED build restored nothing for
/// its configured WHERE (no record, a record left by a DIFFERENT WHERE, or a corrupt one) — so
/// a later switch back to an old WHERE starts from an unknown baseline instead of a value that
/// went stale while that WHERE was untracked (Codex). The disk work runs on the blocking pool;
/// a transient failure is retried a few times, then logged rather than silently dropped.
async fn clear_persisted_light(reason: &str) {
    for _ in 0..3 {
        if tokio::task::spawn_blocking(persist::clear_light).await.unwrap_or(false) {
            return;
        }
    }
    eprintln!(
        "btmqttd: could not clear persisted light-state ({reason}); re-enabling an old \
         LIGHT_WHERE later may restore a stale value"
    );
}

/// Best-effort clear of the persisted LEARNED WHERE (bounded retries, log on ultimate failure).
/// Used when the feature is DISABLED, so disabling is a clean reset: re-enabling in learn mode
/// re-learns rather than silently restoring an address from a past life (CodeRabbit).
async fn clear_persisted_light_where(reason: &str) {
    for _ in 0..3 {
        if tokio::task::spawn_blocking(persist::clear_light_where).await.unwrap_or(false) {
            return;
        }
    }
    eprintln!(
        "btmqttd: could not clear persisted learned LIGHT_WHERE ({reason}); re-enabling in learn \
         mode later may restore the old learned address"
    );
}

/// Best-effort clear of the persisted LEARNED camera sprop (bounded retries, log on ultimate failure).
/// Used when the on-device camera is DISABLED, so disabling is a clean reset: re-enabling re-learns from
/// the panel rather than reassembling the runtime SDP with a value from a past life (issue #120).
async fn clear_persisted_camera_sprop(reason: &str) {
    for _ in 0..3 {
        if tokio::task::spawn_blocking(persist::clear_camera_sprop).await.unwrap_or(false) {
            return;
        }
    }
    eprintln!(
        "btmqttd: could not clear persisted camera sprop ({reason}); re-enabling the on-device \
         camera later may reassemble the SDP with a stale learned value"
    );
}

/// On-connect step 1: SUBSCRIBE to the command topic, then clear any stray retained
/// command. Spawned (not inline) so awaiting the request-channel enqueue can't block
/// the poll loop that drains it. The `online` announce is deferred to `announce()`,
/// gated on this subscription's SubAck (see the SubAck handler).
async fn subscribe_cmd(cfg: Arc<Config>, client: AsyncClient) {
    // Commands are subscribed at QoS 1 (at-least-once) — the one place QoS 1 matters,
    // so a command is redelivered rather than silently dropped (issue #12 item 2).
    if let Err(e) = client.subscribe(&cfg.topic_rx, QoS::AtLeastOnce).await {
        eprintln!("btmqttd: subscribe {} failed: {e}", cfg.topic_rx);
    }
    // Clear a stray retained value on a CONCRETE command topic. A command mistakenly
    // published RETAINED is stored by the broker; per MQTT-3.3.1-9 it is then
    // delivered to THIS already-established subscription with the RETAIN flag CLEARED
    // (retain=0), so the `p.retain` guard in the poll loop does NOT catch it and it
    // would be executed. (Only the subscribe-time retained delivery has retain=1 and
    // is skipped there.) Dropping the broker's retained copy (empty retained publish)
    // removes that. A wildcard/shared TOPIC_RX can't be published to — skip it.
    if is_concrete_topic(&cfg.topic_rx) {
        let _ = client
            .publish(&cfg.topic_rx, QoS::AtMostOnce, true, Vec::new())
            .await;
    }
}

/// On-connect step 2b (after a REFUSED/DOWNGRADED SubAck): assert retained `offline`.
/// The bridge is connected but can't reliably receive commands, so a stale retained
/// `online` from a previous run would otherwise leave HA thinking it's available.
/// Best-effort, QoS 0 retained (same convention as the online announce / the will).
async fn announce_offline(cfg: Arc<Config>, client: AsyncClient) {
    if let Err(e) = client
        .publish(&cfg.topic_lastwill, QoS::AtMostOnce, true, "offline")
        .await
    {
        eprintln!("btmqttd: publish offline (subscription not ready) failed: {e}");
    }
}

/// On-connect step 2 (after a successful SubAck): announce availability and status.
/// Runs only once command readiness is confirmed, so `online` never precedes a
/// working command subscription. QoS 0 retained — the shell default and the usual
/// convention (the retain flag carries state to a late subscriber).
async fn announce(
    cfg: Arc<Config>,
    client: AsyncClient,
    start_iso: Arc<str>,
    volume: Arc<volume::VolumeCtl>,
    light: Option<Arc<light::LightCtl>>,
) {
    // Assert the light-subsystem availability GATE *before* the bridge birth `online`. On a
    // reflash from a configured WHERE to blank learn mode, the broker can still hold a retained
    // light_avail=online from the previous run; publishing the current gate (offline in learn
    // mode) first closes the window where HA would see the bridge online alongside that stale
    // value and issue a light command the controller drops (WHERE still unbound) — Codex. seed()
    // below re-asserts it (idempotent, retained). An AWAITED, error-checked publish (not the
    // drop-on-full try-publish) so the bridge `online` cannot queue before this gate (CodeRabbit).
    // If the gate FAILS to queue, DEFER the bridge `online`: declaring the bridge online while a
    // stale retained light_avail=online lingers would re-open the race. A publish error means the
    // eventloop is gone, so a reconnect re-runs announce and retries (CodeRabbit).
    let light_gate_ok = match &light {
        Some(light) => light.announce_avail().await,
        None => {
            // Feature DISABLED: there is no controller, but the broker can still retain a
            // light_avail=online from a previous ENABLED run (and its discovery configs until
            // ha::reconcile tombstones them below). Assert `offline` here — an AWAITED retained
            // publish, before the bridge `online` — so the stale switch isn't briefly available
            // and can't accept a command the absent controller would drop (Codex).
            match client
                .publish(&cfg.topic_light_avail, QoS::AtMostOnce, true, "offline")
                .await
            {
                Ok(()) => true,
                Err(e) => {
                    eprintln!("btmqttd: publish light-disabled availability failed: {e}");
                    false
                }
            }
        }
    };
    if light_gate_ok {
        if let Err(e) = client
            .publish(&cfg.topic_lastwill, QoS::AtMostOnce, true, "online")
            .await
        {
            eprintln!("btmqttd: publish online failed: {e}");
        }
    } else {
        eprintln!(
            "btmqttd: deferring bridge online — light availability gate not queued (will retry on reconnect)"
        );
    }
    if let Err(e) = client
        .publish(&cfg.topic_startd, QoS::AtMostOnce, true, start_iso.as_bytes().to_vec())
        .await
    {
        eprintln!("btmqttd: publish start_date failed: {e}");
    }
    ha::reconcile(&cfg, &client).await;
    // Re-publish the tracked light state on every connect (a restarted broker dropped its
    // retained topics; a changed WHERE reusing the topic left a stale value). This is
    // INDEPENDENT of discovery — unlike the volume seed below it does NO gateway round-trip,
    // it just re-emits the already-restored cached value, so it's cheap and keeps the retained
    // state topic correct even with discovery off (the daemon still accepts light commands) —
    // Codex.
    if let Some(light) = &light {
        light.seed().await;
    }
    // Seed the volume slider/mute with the unit's real level via an on-demand GATEWAY READ, so
    // HA shows a value immediately on connect (the monitor keeps it live afterwards). Gated on
    // discovery: without an entity reading the state topics the extra gateway round-trip is
    // wasted (the retained publish itself would be harmless either way).
    if cfg.ha_discovery {
        volume.seed().await;
    }
}

/// A topic that can be PUBLISHED to (no `+`/`#` wildcard, not a `$share/` group).
fn is_concrete_topic(topic: &str) -> bool {
    !topic.contains('+') && !topic.contains('#') && !topic.starts_with("$share/")
}

/// True if `req` is a momentary-event publish that must NOT survive a disconnect: the entrance-panel
/// or floor call events, or a keypad key event. These are the ONLY requests purged from the event
/// loop's `pending` queue on a disconnect (issue #71): a queued momentary event must never be flushed
/// late on reconnect. Nothing else — retained state, the dump stream, or protocol packets — is ever
/// discarded.
///
/// Matched by destination topic AND publish shape: the momentary events are always QoS 0,
/// non-retained (see `publish_call_event` and `keys::session`), whereas the call-state sensor is
/// QoS 1, retained. The C# installer forbids the topics from aliasing (`Mqtt_PublishTopicsMustDiffer`),
/// but the daemon must not depend on that — if a hand-edited `.conf` pointed `TOPIC_CALL_STATE` at a
/// momentary topic, a topic-only predicate would purge the retained state publish too. Requiring
/// `AtMostOnce && !retain` makes this incapable of ever dropping a retained publish, and never loses
/// a real momentary event (they are always exactly QoS 0 / non-retained) — CodeRabbit.
fn is_momentary_publish(req: &Request, cfg: &Config) -> bool {
    matches!(
        req,
        Request::Publish(p)
            if p.qos == QoS::AtMostOnce
                && !p.retain
                && (p.topic == cfg.topic_entrance_panel_call
                    || p.topic == cfg.topic_floor_call
                    || p.topic == cfg.topic_key)
    )
}

/// Clean shutdown: publish an explicit retained `offline` (the will only fires on an
/// UNCLEAN drop) and disconnect, then keep DRIVING the event loop until the
/// disconnect actually flushes — `publish`/`disconnect` only QUEUE requests, so
/// without polling they would never reach the broker. Bounded by a timeout.
async fn shutdown(cfg: &Arc<Config>, client: &AsyncClient, eventloop: &mut EventLoop) {
    eprintln!("btmqttd: shutting down");
    // Enqueue the offline publish + disconnect from a SEPARATE task: they go onto the
    // same bounded request channel this poll loop drains, so awaiting them inline
    // before we resume polling could deadlock if the channel is already full.
    let c = client.clone();
    let will_topic = cfg.topic_lastwill.clone();
    tokio::spawn(async move {
        let _ = c.publish(will_topic, QoS::AtMostOnce, true, "offline").await;
        let _ = c.disconnect().await;
    });
    // Drive the loop so the queued offline PUBLISH is flushed and the DISCONNECT is
    // sent; stop when the outgoing DISCONNECT goes out or the connection closes.
    let _ = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match eventloop.poll().await {
                Ok(Event::Outgoing(Outgoing::Disconnect)) => break,
                Ok(_) => {}
                Err(_) => break, // connection closed / errored — nothing left to flush
            }
        }
    })
    .await;
}

/// Build the rustls TLS config from the CA (and optional mutual-TLS client cert +
/// key), mirroring mqtt_common.sh: `--cafile` alone is one-way TLS; adding
/// `--cert`/`--key` is mutual TLS.
fn build_tls(cfg: &Config) -> Result<TlsConfiguration, String> {
    let ca_path = cfg.ca_file.as_ref().expect("uses_tls() guarantees a CA file");
    let ca = std::fs::read(ca_path).map_err(|e| format!("reading CA {ca_path}: {e}"))?;
    let client_auth = match cfg.client_auth_files() {
        Some((cert, key)) => {
            let c = std::fs::read(cert).map_err(|e| format!("reading cert {cert}: {e}"))?;
            let k = std::fs::read(key).map_err(|e| format!("reading key {key}: {e}"))?;
            Some((c, k))
        }
        None => None,
    };
    Ok(TlsConfiguration::Simple { ca, alpn: None, client_auth })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rumqttc::{Publish, QoS};
    use std::collections::HashMap;

    #[test]
    fn purge_predicate_matches_only_momentary_publishes() {
        // The disconnect purge (#71) must drop ONLY momentary events (door call / keypad), never
        // retained state, the dump stream, or protocol packets — so a genuine sensor/state
        // republish still flushes.
        let cfg = Config::from_map(HashMap::new()); // default topics
        let pub_to = |t: &str| Request::Publish(Publish::new(t, QoS::AtMostOnce, "x"));

        // The momentary events, exactly as publish_call_event / keys::session emit them: QoS 0,
        // non-retained — the door calls AND the keypad key events (issue #71 + keypad follow-up).
        assert!(is_momentary_publish(&pub_to(&cfg.topic_entrance_panel_call), &cfg));
        assert!(is_momentary_publish(&pub_to(&cfg.topic_floor_call), &cfg));
        assert!(is_momentary_publish(&pub_to(&cfg.topic_key), &cfg));
        // Retained call-state sensor and other topics are KEPT (must survive to re-flush).
        assert!(!is_momentary_publish(&pub_to(&cfg.topic_call_state), &cfg));
        assert!(!is_momentary_publish(&pub_to("Bticino/dump"), &cfg));
        // Non-publish protocol packets are never momentary events.
        assert!(!is_momentary_publish(&Request::PingReq(rumqttc::PingReq), &cfg));
    }

    #[test]
    fn purge_predicate_keeps_retained_and_qos1_publishes_even_on_an_event_topic() {
        // Shape guard (CodeRabbit): the predicate also requires QoS 0 + non-retained, so even if a
        // hand-edited .conf ALIASED the call-state topic onto an event topic, the retained QoS 1
        // state publish is never purged. Build the publishes ON an event topic and vary the shape.
        let cfg = Config::from_map(HashMap::new());
        let mut retained = Publish::new(&cfg.topic_entrance_panel_call, QoS::AtMostOnce, "x");
        retained.retain = true;
        // Retained (as the call-state publish is) → KEPT, despite the event topic.
        assert!(!is_momentary_publish(&Request::Publish(retained), &cfg));
        // QoS 1 (as the call-state publish is) → KEPT, despite the event topic.
        let qos1 = Publish::new(&cfg.topic_floor_call, QoS::AtLeastOnce, "x");
        assert!(!is_momentary_publish(&Request::Publish(qos1), &cfg));
        // A retained QoS 1 publish (the exact call-state shape) aliased onto an event topic → KEPT.
        let mut state_shape = Publish::new(&cfg.topic_entrance_panel_call, QoS::AtLeastOnce, "x");
        state_shape.retain = true;
        assert!(!is_momentary_publish(&Request::Publish(state_shape), &cfg));
    }
}
