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
use crate::dimension;
use crate::own::{self, Framer};
use crate::volume::VolumeCtl;

/// Monitor-session request sent right after connect. The gateway replies with the
/// `*#*1##` ACK and then streams every bus frame.
const MONITOR_REQ: &[u8] = b"*99*1##";

/// How long a monitor session must last to count as "healthy" — a session that
/// stayed up this long was working (whether or not the bus was busy), so the next
/// reconnect is prompt; a session that dropped sooner backs off. Duration-based
/// (as the shell receiver did) rather than frame-based, so a legitimately QUIET but
/// long-lived monitor isn't penalised with backoff.
const HEALTHY_SESSION: Duration = Duration::from_secs(60);

/// Run forever: (re)connect to the monitor, stream + publish frames, and on any
/// drop back off (capped) and reconnect. Never returns under normal operation.
pub async fn run(cfg: Arc<Config>, client: AsyncClient, volume: Arc<VolumeCtl>) {
    let mut backoff = 0u64;
    loop {
        let start = tokio::time::Instant::now();
        if let Err(e) = session(&cfg, &client, &volume).await {
            eprintln!(
                "btmqttd: monitor {}:{} unavailable: {e}",
                cfg.own_host, cfg.own_port_mon
            );
        }
        // Reset backoff after a session that stayed up a while (healthy); a quick
        // accept-then-close (busy monitor slot, gateway not ready) backs off so we
        // don't spin in a tight reconnect loop.
        if start.elapsed() >= HEALTHY_SESSION {
            backoff = 0;
        } else {
            backoff = (backoff + 1).min(6);
        }
        if backoff > 0 {
            tokio::time::sleep(Duration::from_secs(backoff * 5)).await;
        }
    }
}

/// How long to wait for the monitor ACK before giving up on this connection.
const ACK_TIMEOUT: Duration = Duration::from_secs(5);

/// One monitor session: connect, handshake, VALIDATE the monitor ACK, then read +
/// publish until the socket closes (Ok) or errors. run() decides healthy-vs-backoff
/// from how long this ran.
async fn session(cfg: &Arc<Config>, client: &AsyncClient, volume: &Arc<VolumeCtl>) -> std::io::Result<()> {
    let mut sock = TcpStream::connect((cfg.own_host.as_str(), cfg.own_port_mon)).await?;
    sock.write_all(MONITOR_REQ).await?;
    sock.flush().await?;

    let mut framer = Framer::default();
    let mut buf = [0u8; 4096];
    let mut frames: Vec<String> = Vec::new();

    // Require the monitor ACK ("*#*1##") before streaming. The gateway may accept the
    // TCP connection but REFUSE the monitor session with a NACK ("*#*0##") — e.g. a
    // monitor slot is already in use — or just go idle. Without this check we'd sit on
    // a silent socket forever, publishing nothing while run()'s duration heuristic
    // treated the stuck session as healthy. The shell back-end probed for this ACK
    // before committing to the socket path. The ACK/NACK are dropped by the framer,
    // so scan the RAW bytes here; bytes trailing the ACK are handed to the framer.
    let mut pre: Vec<u8> = Vec::new();
    let outcome = tokio::time::timeout(ACK_TIMEOUT, async {
        loop {
            let n = sock.read(&mut buf).await?;
            if n == 0 {
                return Ok::<bool, std::io::Error>(false); // closed before any ACK
            }
            pre.extend_from_slice(&buf[..n]);
            if pre.windows(own::ACK.len()).any(|w| w == own::ACK) {
                return Ok(true);
            }
            if pre.windows(own::NACK.len()).any(|w| w == own::NACK) {
                return Ok(false); // monitor refused
            }
            if pre.len() > 4096 {
                return Ok(false); // unexpected chatter, no ACK — treat as refused
            }
        }
    })
    .await;
    match outcome {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "monitor session refused (NACK / no ACK)",
            ))
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "monitor ACK timed out",
            ))
        }
    }

    // Reset the retained call state to idle on every (re)connect. If the monitor dropped
    // mid-call — after a ringing/active frame but before the idle (`*#8**35*0*…`)
    // transition — the retained sensor would otherwise stay stuck at ringing/active
    // forever. Done BEFORE draining the buffered frames below, so a call frame that arrived
    // with the ACK still re-sets the real state; a genuinely-active call that produced no
    // new frame across the reconnect (rare) shows idle until its next transition —
    // preferable to a permanently stuck state. (Volume/mute reconcile via resync() below.)
    publish_call_state(cfg, client, 0).await;

    // Feed ONLY the bytes AFTER the ACK to the framer, so any bus frames that arrived
    // in the same read(s) as the ACK are published while the handshake ACK and any
    // pre-ACK banner/chatter are NOT framed (feeding all of `pre` could otherwise let
    // stray pre-ACK bytes merge into a garbage frame). We got here only on ACK, so the
    // search succeeds; slice past the first ACK occurrence.
    if let Some(pos) = pre.windows(own::ACK.len()).position(|w| w == own::ACK) {
        framer.push(&pre[pos + own::ACK.len()..], &mut frames);
        for frame in frames.drain(..) {
            publish_frame(cfg, client, volume, &frame).await;
        }
    }

    // Monitor (re)connected: force a fresh read of volume + mute so a change made on the
    // unit WHILE the stream was down — whose one-shot broadcast (`*#8**41*<N>##` for
    // volume, `*#8**33*<0|1>##` for mute) we missed — is reconciled, instead of leaving
    // the retained HA state stale until the next event. Spawned AFTER draining the frames
    // buffered with the ACK above, so those (unconditional `observe_*`) updates can't land
    // AFTER the resync read and clobber it with an already-buffered report — resync is the
    // FINAL reconciliation. Spawned (not awaited) so it never blocks the read loop below;
    // the read uses a separate command session, and a genuinely newer frame arriving in the
    // loop still wins via the generation guard.
    tokio::spawn({
        let volume = volume.clone();
        async move { volume.resync().await }
    });

    loop {
        let n = sock.read(&mut buf).await?;
        if n == 0 {
            return Ok(()); // gateway closed the monitor session
        }
        frames.clear();
        framer.push(&buf[..n], &mut frames);
        for frame in frames.drain(..) {
            publish_frame(cfg, client, volume, &frame).await;
        }
    }
}

/// Publish one framed OWN string to TOPIC_DUMP — as compact JSON (PAYLOAD_FORMAT=
/// json, the default) or the raw frame. QoS 0, not retained, as the shell's
/// `mqtt_pub -l` did.
async fn publish_frame(cfg: &Arc<Config>, client: &AsyncClient, volume: &Arc<VolumeCtl>, frame: &str) {
    // Learn the real volume AND mute from the bus (issue #40): the unit broadcasts
    // `*#8**41*<N>##` (volume) and `*#8**33*<0|1>##` (mute/RingEnable) on the monitor
    // whenever either changes by ANY path (slider, up/down, mute, or the unit's own menu),
    // so this is the single source of truth for `current`/`muted`. Parse BEFORE the format
    // branch so it works in raw mode too; a frame is at most one of the two, and any other
    // frame parses to None and is ignored.
    if let Some(pct) = dimension::parse_volume_report(frame) {
        volume.observe_volume(pct).await;
    } else if let Some(muted) = dimension::parse_mute_report(frame) {
        volume.observe_mute(muted).await;
    } else if let Some(where_) = dimension::parse_doorbell(frame) {
        // Entrance-panel CALL: fire a momentary "pressed" event.
        publish_doorbell(cfg, client, where_).await;
    } else if let Some(code) = dimension::parse_call_state(frame) {
        // Call STATE transition (idle/ringing/in_call, or "active" fallback): update the
        // retained sensor.
        publish_call_state(cfg, client, code).await;
    }
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

/// Publish a momentary doorbell "pressed" event to TOPIC_DOORBELL. NOT retained: an
/// event fires once, and a retained event would spuriously re-fire on every HA
/// reconnect. QoS 0 (like the non-idempotent lock/step actions): a doorbell press is
/// NON-idempotent, and QoS 1 may legitimately REDELIVER a publish (DUP on a lost PUBACK),
/// which would fire the HA event — and any doorbell automation — twice for one ring. A
/// press lost during a brief broker reconnect is preferable to a double actuation. The
/// payload carries the HA `event_type` plus the entrance-panel WHERE (informational).
async fn publish_doorbell(cfg: &Arc<Config>, client: &AsyncClient, where_: &str) {
    let payload = serde_json::json!({ "event_type": "pressed", "where": where_ }).to_string();
    if let Err(e) = client
        .publish(&cfg.topic_doorbell, QoS::AtMostOnce, false, payload.into_bytes())
        .await
    {
        eprintln!("btmqttd: publish doorbell event failed: {e}");
    }
}

/// Publish the call STATE to TOPIC_CALL_STATE, RETAINED so HA shows the current state
/// after a reconnect/restart. The payload carries the mapped label (idle/ringing/in_call,
/// or "active" for an unmapped code — see [`dimension::call_state_label`]) plus the raw
/// code as an attribute for finer protocol detail.
async fn publish_call_state(cfg: &Arc<Config>, client: &AsyncClient, code: u8) {
    let payload =
        serde_json::json!({ "state": dimension::call_state_label(code), "code": code }).to_string();
    if let Err(e) = client
        .publish(&cfg.topic_call_state, QoS::AtLeastOnce, true, payload.into_bytes())
        .await
    {
        eprintln!("btmqttd: publish call state failed: {e}");
    }
}
