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

mod config;
mod dimension;
mod gate;
mod ha;
mod keys;
mod own;
mod persist;
mod receiver;
mod rediscovery;
mod sender;
mod volume;

use std::sync::Arc;
use std::time::Duration;

use rumqttc::{
    AsyncClient, Event, EventLoop, Incoming, LastWill, MqttOptions, Outgoing, QoS,
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
    if let Err(e) = rt.block_on(run()) {
        eprintln!("btmqttd: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
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

    // Gate (issue #41) runs on its OWN task, fed by a small channel: the command worker
    // enqueues a press request and moves on (no 300 ms block), the gate task serialises
    // each press→hold→release, and shutdown DRAINS it (drops the sender + awaits) so a
    // press is never left without its release. See gate.rs.
    let (gate_tx, gate_rx) = tokio::sync::mpsc::channel::<()>(gate::QUEUE_DEPTH);
    // Set at shutdown so the gate task finishes the pulse in progress but discards
    // queued (not-yet-started) presses — bounding the drain to one pulse.
    let gate_stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let gate_task = tokio::spawn(gate::run(gate_rx, gate_stopping.clone()));

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
        let gate_tx = gate_tx.clone();
        async move {
            while let Some(payload) = cmd_rx.recv().await {
                receiver::dispatch(&cfg, &client, &volume, &gate_tx, &payload).await;
            }
        }
    });

    // Bus -> MQTT and keypad -> MQTT run as independent tasks; they publish through
    // the shared client (rumqttc queues while disconnected and flushes on connect).
    // Keep their handles so shutdown can ABORT every MQTT-producing task before it
    // publishes the final retained `offline` — otherwise a task still in flight could
    // enqueue a publish AFTER `offline` and leave stale state retained on the broker.
    let sender_task = tokio::spawn(sender::run(cfg.clone(), client.clone(), volume.clone()));
    let keys_task = tokio::spawn(keys::run(cfg.clone(), client.clone()));
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
    // is merely whether a record FILE exists — including one the base or MAC gate rejected,
    // so a build-IP ConnAck can clear that stale file too (CodeRabbit). Persist I/O is
    // blocking std::fs, so it's offloaded to the blocking pool (single-threaded runtime —
    // Copilot).
    let build_ip = if rediscovery_active {
        rediscovery::build_time_ip(&cfg.mqtt_host).await
    } else {
        None
    };
    let record = if rediscovery_active {
        let host = cfg.mqtt_host.clone();
        tokio::task::spawn_blocking(move || persist::read_record(&host)).await.ok().flatten()
    } else {
        None
    };

    let mut last_persisted: Option<std::net::Ipv4Addr> = None;
    let mut persisted_on_disk = record.is_some();
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
                        eprintln!(
                            "btmqttd: seeded '{}' -> {learned} in {} from persisted state",
                            cfg.mqtt_host, rediscovery::HOSTS_PATH
                        );
                    }
                    Ok(false) => last_persisted = Some(learned), // already mapped (respawn)
                    Err(e) => eprintln!("btmqttd: could not seed persisted broker IP: {e}"),
                }
            } else {
                eprintln!(
                    "btmqttd: persisted broker IP {learned} did not confirm the broker MAC \
                     at boot; not seeding (normal rediscovery will re-locate it)"
                );
            }
        }
    }

    loop {
        tokio::select! {
            _ = sig_term.recv() => break,
            _ = sig_int.recv() => break,
            ev = eventloop.poll() => {
                match ev {
                    Ok(Event::Incoming(Incoming::ConnAck(_))) => {
                        // Connected: clear the rediscovery failure streak and forget
                        // proposed addresses, so a later outage starts fresh and a broker
                        // that returns to a former address can be found again.
                        conn_failures = 0;
                        tried_ips.clear();
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
                        if let (Some(build_ip), Some(confirmed)) =
                            (build_ip, rediscovery::current_broker_ip(&cfg.mqtt_host).await)
                        {
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
                                r = rediscovery::rediscover(&cfg, &mut tried_ips) => {
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
    // Gate task: DRAIN rather than abort. Signal `stopping` FIRST so the task finishes
    // the pulse IN PROGRESS (its release is sent) but discards queued, not-yet-started
    // presses (which emitted nothing, so dropping them strands nothing). Then drop this
    // last sender (cmd_worker's is stopped above) to close the channel and await. The
    // wait is bounded to ONE worst-case pulse plus a margin (gate::MAX_PULSE covers
    // press+hold+release at the tight gate timeout) — enough for the in-flight release
    // regardless of how many were queued, yet an unresponsive gateway can't hang exit.
    // On a responsive gateway a pulse is ~300 ms, so this returns almost immediately.
    gate_stopping.store(true, std::sync::atomic::Ordering::Relaxed);
    drop(gate_tx);
    let _ = tokio::time::timeout(gate::MAX_PULSE + Duration::from_secs(1), gate_task).await;
    shutdown(&cfg, &client, &mut eventloop).await;
    Ok(())
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
) {
    if let Err(e) = client
        .publish(&cfg.topic_lastwill, QoS::AtMostOnce, true, "online")
        .await
    {
        eprintln!("btmqttd: publish online failed: {e}");
    }
    if let Err(e) = client
        .publish(&cfg.topic_startd, QoS::AtMostOnce, true, start_iso.as_bytes().to_vec())
        .await
    {
        eprintln!("btmqttd: publish start_date failed: {e}");
    }
    ha::reconcile(&cfg, &client).await;
    // Seed the volume slider/mute with the unit's real level via an on-demand read, so
    // HA shows a value immediately on connect (the monitor keeps it live afterwards).
    // Only meaningful with discovery on — otherwise no entity reads the state topics —
    // but the retained publish is harmless either way; still, skip the extra gateway
    // round-trip when discovery is off.
    if cfg.ha_discovery {
        volume.seed().await;
    }
}

/// A topic that can be PUBLISHED to (no `+`/`#` wildcard, not a `$share/` group).
fn is_concrete_topic(topic: &str) -> bool {
    !topic.contains('+') && !topic.contains('#') && !topic.starts_with("$share/")
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
