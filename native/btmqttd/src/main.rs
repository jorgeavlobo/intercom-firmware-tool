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

mod config;
mod ha;
mod keys;
mod own;
mod receiver;
mod sender;

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
    // oversized packet is refused at the transport. OUTGOING is raised to match, so
    // our own up-to-256 KB replies (read_file / command_result) publish.
    opts.set_max_packet_size(512 * 1024, 512 * 1024);
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
    const CMD_QUEUE_DEPTH: usize = 32;
    // Per-command payload ceiling, enforced BEFORE cloning/enqueueing so the queue
    // bounds memory (<= depth x cap), not just message count — otherwise 32 large
    // publishes could accumulate while the worker is busy (e.g. a 60 s
    // execute_command). 320 KB fits the 256 KB read/write/exec contract plus JSON
    // overhead; a larger command is dropped with a log line.
    const MAX_CMD_BYTES: usize = 320 * 1024;
    let (cmd_tx, mut cmd_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(CMD_QUEUE_DEPTH);
    let cmd_worker = tokio::spawn({
        let cfg = cfg.clone();
        let client = client.clone();
        async move {
            while let Some(payload) = cmd_rx.recv().await {
                receiver::dispatch(&cfg, &client, &payload).await;
            }
        }
    });

    // Bus -> MQTT and keypad -> MQTT run as independent tasks; they publish through
    // the shared client (rumqttc queues while disconnected and flushes on connect).
    // Keep their handles so shutdown can ABORT every MQTT-producing task before it
    // publishes the final retained `offline` — otherwise a task still in flight could
    // enqueue a publish AFTER `offline` and leave stale state retained on the broker.
    let sender_task = tokio::spawn(sender::run(cfg.clone(), client.clone()));
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

    loop {
        tokio::select! {
            _ = sig_term.recv() => break,
            _ = sig_int.recv() => break,
            ev = eventloop.poll() => {
                match ev {
                    Ok(Event::Incoming(Incoming::ConnAck(_))) => {
                        // SUBSCRIBE to the command topic, as its OWN task (not inline):
                        // the subscribe enqueues into the same bounded request channel
                        // THIS poll loop drains, so awaiting it here could deadlock if
                        // the bus/key tasks filled the channel during an outage.
                        // Announcing `online` waits for the SubAck (below). Abort any
                        // still-running tasks from a previous connect first.
                        if let Some(h) = subscribe_task.take() {
                            h.abort();
                        }
                        if let Some(h) = announce_task.take() {
                            h.abort();
                        }
                        subscribe_task =
                            Some(tokio::spawn(subscribe_cmd(cfg.clone(), client.clone())));
                    }
                    Ok(Event::Incoming(Incoming::SubAck(suback))) => {
                        // Only announce availability AFTER the broker confirms the
                        // command subscription. If it REFUSED (ACL, bad filter →
                        // SubscribeReasonCode::Failure), don't publish `online`: the
                        // bridge is connected but cannot receive commands, and a false
                        // `online` would let availability-triggered automations lose
                        // commands. TOPIC_RX is our only SUBSCRIBE, so this SubAck is it.
                        if suback
                            .return_codes
                            .iter()
                            .any(|c| matches!(c, SubscribeReasonCode::Failure))
                        {
                            eprintln!(
                                "btmqttd: broker REFUSED subscription to {} (check ACLs / \
                                 topic filter); not announcing online",
                                cfg.topic_rx
                            );
                        } else {
                            if let Some(h) = announce_task.take() {
                                h.abort();
                            }
                            announce_task = Some(tokio::spawn(announce(
                                cfg.clone(),
                                client.clone(),
                                start_iso.clone(),
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
                        // Connection dropped/unreachable: rumqttc reconnects on the
                        // next poll; back off briefly so a hard-down broker doesn't spin.
                        eprintln!("btmqttd: connection: {e}");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        }
    }

    // Stop every MQTT-producing task BEFORE the final `offline`, so none of them can
    // enqueue a publish after it and leave stale state (e.g. a lingering announce task
    // re-retaining `online`) on the broker.
    if let Some(h) = subscribe_task.take() {
        h.abort();
    }
    if let Some(h) = announce_task.take() {
        h.abort();
    }
    sender_task.abort();
    keys_task.abort();
    cmd_worker.abort();
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

/// On-connect step 2 (after a successful SubAck): announce availability and status.
/// Runs only once command readiness is confirmed, so `online` never precedes a
/// working command subscription. QoS 0 retained — the shell default and the usual
/// convention (the retain flag carries state to a late subscriber).
async fn announce(cfg: Arc<Config>, client: AsyncClient, start_iso: Arc<str>) {
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
