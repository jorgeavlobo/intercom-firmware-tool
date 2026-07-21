//! bus -> MQTT: open a MONITOR session on the local OpenWebNet gateway
//! (OWN_HOST:OWN_PORT_MON, default 127.0.0.1:20000), stream frames, and publish
//! each to TOPIC_DUMP as raw text or as one structured JSON object per frame.
//!
//! Native replacement for StartMqttSend's socket back-end (nc + awk framer). The
//! tcpdump/filter.py fallback is retired — this connects directly and retries.

use std::sync::Arc;
use std::time::Duration;

use rumqttc::{AsyncClient, QoS};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::Config;
use crate::own::{self, Framer};

/// Monitor-session request sent right after connect. The gateway replies with the
/// `*#*1##` ACK and then streams every bus frame.
const MONITOR_REQ: &[u8] = b"*99*1##";

/// Run forever: (re)connect to the monitor, stream + publish frames, and on any
/// drop back off (capped) and reconnect. Never returns under normal operation.
pub async fn run(cfg: Arc<Config>, client: AsyncClient) {
    let mut backoff = 0u64;
    loop {
        match session(&cfg, &client).await {
            Ok(()) => backoff = 0, // clean EOF after a healthy session — retry promptly
            Err(e) => {
                eprintln!(
                    "btmqttd: monitor {}:{} unavailable: {e}",
                    cfg.own_host, cfg.own_port_mon
                );
                backoff = (backoff + 1).min(6);
            }
        }
        if backoff > 0 {
            tokio::time::sleep(Duration::from_secs(backoff * 5)).await;
        }
    }
}

/// One monitor session: connect, handshake, then read + publish until the socket
/// closes or errors.
async fn session(cfg: &Arc<Config>, client: &AsyncClient) -> std::io::Result<()> {
    let mut sock = TcpStream::connect((cfg.own_host.as_str(), cfg.own_port_mon)).await?;
    sock.write_all(MONITOR_REQ).await?;
    sock.flush().await?;

    let mut framer = Framer::default();
    let mut buf = [0u8; 4096];
    let mut frames: Vec<String> = Vec::new();
    let mut got_any_frame = false;
    loop {
        let n = sock.read(&mut buf).await?;
        if n == 0 {
            // Treat an immediate EOF (accepted-then-closed with no frame ever read)
            // as an error so run() backs off, instead of a "healthy" session that
            // resets backoff and spins in a tight reconnect loop against a busy
            // monitor slot. A close AFTER real traffic is a normal, retry-promptly EOF.
            return if got_any_frame {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "monitor closed before any frame",
                ))
            };
        }
        frames.clear();
        framer.push(&buf[..n], &mut frames);
        got_any_frame |= !frames.is_empty();
        for frame in frames.drain(..) {
            publish_frame(cfg, client, &frame).await;
        }
    }
}

/// Publish one framed OWN string to TOPIC_DUMP — as compact JSON (PAYLOAD_FORMAT=
/// json, the default) or the raw frame. QoS 0, not retained, as the shell's
/// `mqtt_pub -l` did.
async fn publish_frame(cfg: &Arc<Config>, client: &AsyncClient, frame: &str) {
    let payload: Vec<u8> = if cfg.payload_json {
        match own::frame_to_json(frame) {
            Some(v) => v.to_string().into_bytes(),
            None => return, // ACK/NACK dropped
        }
    } else {
        frame.as_bytes().to_vec()
    };
    if let Err(e) = client
        .publish(&cfg.topic_dump, QoS::AtMostOnce, false, payload)
        .await
    {
        eprintln!("btmqttd: publish bus frame failed: {e}");
    }
}
