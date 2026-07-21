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
    AsyncClient, Event, Incoming, LastWill, MqttOptions, QoS, TlsConfiguration, Transport,
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
    // on every connect.
    let start_iso = own::utc_now_iso();

    let mut opts = MqttOptions::new(cfg.client_id(), cfg.mqtt_host.clone(), cfg.mqtt_port);
    opts.set_keep_alive(Duration::from_secs(60));
    // Atomic birth/will makes a durable session unnecessary — use a clean session.
    opts.set_clean_session(true);
    if let (Some(u), Some(p)) = (&cfg.mqtt_user, &cfg.mqtt_pass) {
        opts.set_credentials(u.clone(), p.clone());
    }
    // Retained `offline` last will: an unclean drop (crash/power loss) makes the
    // broker deliver it, so Home Assistant sees the bridge go offline.
    opts.set_last_will(LastWill::new(
        cfg.topic_lastwill.clone(),
        "offline",
        QoS::AtLeastOnce,
        true,
    ));
    if cfg.uses_tls() {
        opts.set_transport(Transport::tls_with_config(build_tls(&cfg)?));
    }

    let (client, mut eventloop) = AsyncClient::new(opts, 32);

    // Bus -> MQTT and keypad -> MQTT run as independent tasks; they publish through
    // the shared client (rumqttc queues while disconnected and flushes on connect).
    tokio::spawn(sender::run(cfg.clone(), client.clone()));
    tokio::spawn(keys::run(cfg.clone(), client.clone()));

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
                        birth(&cfg, &client, &start_iso).await;
                    }
                    Ok(Event::Incoming(Incoming::Publish(p))) if p.topic == cfg.topic_rx => {
                        let cfg = cfg.clone();
                        let client = client.clone();
                        let payload = p.payload;
                        tokio::spawn(async move {
                            receiver::dispatch(&cfg, &client, &payload).await;
                        });
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

    shutdown(&cfg, &client).await;
    Ok(())
}

/// On-connect birth sequence: announce availability, republish the service start
/// time, reconcile HA discovery, and (re)subscribe to the command topic. Runs on
/// every connect, so a reconnect restores all retained state automatically.
async fn birth(cfg: &Arc<Config>, client: &AsyncClient, start_iso: &str) {
    if let Err(e) = client
        .publish(&cfg.topic_lastwill, QoS::AtLeastOnce, true, "online")
        .await
    {
        eprintln!("btmqttd: publish online failed: {e}");
    }
    if let Err(e) = client
        .publish(&cfg.topic_startd, QoS::AtLeastOnce, true, start_iso.as_bytes().to_vec())
        .await
    {
        eprintln!("btmqttd: publish start_date failed: {e}");
    }
    ha::reconcile(cfg, client).await;
    if let Err(e) = client.subscribe(&cfg.topic_rx, QoS::AtLeastOnce).await {
        eprintln!("btmqttd: subscribe {} failed: {e}", cfg.topic_rx);
    }
}

/// Clean shutdown: publish an explicit retained `offline` (the will only fires on an
/// UNCLEAN drop), give it a moment to flush, then disconnect.
async fn shutdown(cfg: &Arc<Config>, client: &AsyncClient) {
    eprintln!("btmqttd: shutting down");
    let _ = client
        .publish(&cfg.topic_lastwill, QoS::AtLeastOnce, true, "offline")
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = client.disconnect().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
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
