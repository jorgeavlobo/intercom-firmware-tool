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
use crate::light::LightCtl;
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
pub async fn run(
    cfg: Arc<Config>,
    client: AsyncClient,
    volume: Arc<VolumeCtl>,
    light: Option<Arc<LightCtl>>,
) {
    let mut backoff = 0u64;
    loop {
        let start = tokio::time::Instant::now();
        if let Err(e) = session(&cfg, &client, &volume, light.as_ref()).await {
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

/// While a call is non-idle, the read loop re-queries the AUTHORITATIVE call state
/// (`*#8**35##`, confirmed answerable on the gateway) this often, so a missed transition
/// frame — e.g. a lost terminal `idle` — is corrected within one interval instead of
/// lingering until the next call. Also caps the monitor read so the loop still wakes to
/// poll on a QUIET bus. Every frame transition re-stamps the marker, so during a call WITH
/// flowing frames we rarely poll — only once the bus has gone silent while still non-idle,
/// exactly the missed-terminal-frame case.
const CALL_STATE_POLL: Duration = Duration::from_secs(30);

/// While the one-shot reconnect call-state query runs, re-poll the monitor socket this
/// often so buffered/live frames — notably a light echo whose ≤3 s guard is already
/// ticking — are drained promptly instead of waiting out the up-to-5 s query.
const RECONNECT_DRAIN_TICK: Duration = Duration::from_millis(200);

/// The call-state reconcile marker: `(last-known state, poll instant)`, or `None` when
/// idle (disarmed). The inner `Option<u8>` is `Some(code)` for a known non-idle state and
/// `None` for "unknown" — armed after a reconnect whose authoritative read failed, so the
/// poll loop reconciles without ever publishing a state we didn't actually read.
type CallWatch = Option<(Option<u8>, tokio::time::Instant)>;

/// Arm/disarm the reconcile marker from a freshly-KNOWN state `code`: idle (`0`) disarms
/// it; any non-idle code (re)arms it with the code and the current instant (which also
/// resets the poll timer).
fn update_call_watch(watch: &mut CallWatch, code: u8) {
    *watch = if code == 0 {
        None
    } else {
        Some((Some(code), tokio::time::Instant::now()))
    };
}

/// One monitor session: connect, handshake, VALIDATE the monitor ACK, then read +
/// publish until the socket closes (Ok) or errors. run() decides healthy-vs-backoff
/// from how long this ran.
async fn session(
    cfg: &Arc<Config>,
    client: &AsyncClient,
    volume: &Arc<VolumeCtl>,
    light: Option<&Arc<LightCtl>>,
) -> std::io::Result<()> {
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

    // Drain the ACK-buffered frames FIRST. Any bus frame that arrived in the same read(s)
    // as the ACK is framed and published here; the handshake ACK and any pre-ACK banner are
    // NOT framed (feeding all of `pre` could let stray pre-ACK bytes merge into a garbage
    // frame). We got here only on ACK, so the search succeeds; slice past the first ACK.
    // These bytes were read BEFORE the authoritative GET below, so the GET must run AFTER
    // them to have the FINAL say — a stale pre-GET call-state frame must not override it.
    let mut call_watch: CallWatch = None;
    if let Some(pos) = pre.windows(own::ACK.len()).position(|w| w == own::ACK) {
        framer.push(&pre[pos + own::ACK.len()..], &mut frames);
        for frame in frames.drain(..) {
            if let Some(code) = publish_frame(cfg, client, volume, light, &frame).await {
                update_call_watch(&mut call_watch, code);
            }
        }
    }

    // Reconcile the retained call state AUTHORITATIVELY on every (re)connect: query the
    // gateway (`*#8**35##`) for the REAL state rather than trusting the possibly-stale
    // buffered frames above (or blindly assuming idle), so a call genuinely in progress
    // across a monitor reconnect is preserved.
    //
    // Do NOT await this query in isolation: it can take up to `dimension::SESSION_TIMEOUT`
    // (5 s) — longer than the light `ECHO_GUARD` (3 s). If a light command's echo lands on
    // the fresh session while we sit here, blocking the monitor read would delay observe()
    // past the guard, and apply_observe would misread our OWN echo as a physical press —
    // committing a second flip and inverting the cache (Codex). So keep draining the
    // monitor socket CONCURRENTLY while the query runs: every frame (light echoes included)
    // is processed the moment it arrives, within its guard window. This also cuts general
    // reconnect frame latency, which previously waited out the whole query.
    //
    // The query result stays authoritative for call state: it completes at the END of this
    // drain window, so its snapshot reflects gateway state at least as fresh as any frame
    // processed during the drain — applying it unconditionally cannot be clobbered by a staler
    // drained frame (the buffered-idle-then-authoritative-ringing case, Codex). A genuinely
    // newer transition arriving AFTER the query completes is read by the main loop below and
    // supersedes it there. On a FAILED read (session refused / no reply) do NOT fabricate a
    // state — publishing idle would clobber a real ringing/in_call; keep what the frames left
    // and, if still disarmed, arm an "unknown" marker so a later poll re-queries.
    let reconcile = dimension::read_call_state(&cfg.own_host, cfg.own_port_mon);
    tokio::pin!(reconcile);
    loop {
        tokio::select! {
            biased;
            result = &mut reconcile => {
                match result {
                    Ok(Some(code)) => {
                        publish_call_state(cfg, client, code).await;
                        update_call_watch(&mut call_watch, code);
                    }
                    Ok(None) | Err(_) => {
                        if call_watch.is_none() {
                            call_watch = Some((None, tokio::time::Instant::now()));
                        }
                    }
                }
                break;
            }
            read = tokio::time::timeout(RECONNECT_DRAIN_TICK, sock.read(&mut buf)) => {
                // A completed read is drained now; a tick timeout just re-polls the select.
                if let Ok(read) = read {
                    let n = read?;
                    if n == 0 {
                        return Ok(()); // gateway closed the monitor session
                    }
                    frames.clear();
                    framer.push(&buf[..n], &mut frames);
                    for frame in frames.drain(..) {
                        if let Some(code) =
                            publish_frame(cfg, client, volume, light, &frame).await
                        {
                            update_call_watch(&mut call_watch, code);
                        }
                    }
                }
            }
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
        // Read with a CALL_STATE_POLL cap so the loop still wakes to run the reconcile below
        // on a QUIET bus (no frames). A completed read is handled; on a timeout the `if let`
        // simply falls through to the reconcile.
        if let Ok(read) = tokio::time::timeout(CALL_STATE_POLL, sock.read(&mut buf)).await {
            let n = read?;
            if n == 0 {
                return Ok(()); // gateway closed the monitor session
            }
            frames.clear();
            framer.push(&buf[..n], &mut frames);
            for frame in frames.drain(..) {
                if let Some(code) = publish_frame(cfg, client, volume, light, &frame).await {
                    update_call_watch(&mut call_watch, code);
                }
            }
        }

        // Authoritative reconcile: while a call is non-idle and no transition frame has
        // refreshed it for CALL_STATE_POLL, re-query dim-35 for the REAL state and publish
        // it if changed. This corrects a missed terminal `idle` (or any missed transition)
        // PRECISELY — no heuristic timeout and no risk of cutting a real call, because the
        // gateway reports the truth (`*#8**35*<N>*0*0##`). A failed query keeps the last
        // state and retries next interval rather than fabricating idle.
        if let Some((known, since)) = call_watch {
            if since.elapsed() >= CALL_STATE_POLL {
                match dimension::read_call_state(&cfg.own_host, cfg.own_port_mon).await {
                    Ok(Some(code)) => {
                        // Publish only on a real change — `known` is None ("unknown", from a
                        // failed reconnect read) so the first successful poll always writes.
                        if known != Some(code) {
                            publish_call_state(cfg, client, code).await;
                        }
                        update_call_watch(&mut call_watch, code);
                    }
                    Ok(None) | Err(_) => {
                        // Retry after the interval, preserving `known` either way. The two
                        // cases are semantically distinct but handled identically: a
                        // `Some(code)` retry just refreshes a known non-idle probe, whereas a
                        // `None` retry is a reconcile OBLIGATION left by a failed reconnect
                        // read — both must keep polling until an authoritative read succeeds.
                        call_watch = Some((known, tokio::time::Instant::now()));
                    }
                }
            }
        }
    }
}

/// Publish one framed OWN string to TOPIC_DUMP — as compact JSON (PAYLOAD_FORMAT=
/// json, the default) or the raw frame. QoS 0, not retained, as the shell's
/// `mqtt_pub -l` did.
/// Returns the call-state `code` when this frame was a call-state transition (so the
/// caller can arm/disarm the watchdog), else `None`.
async fn publish_frame(
    cfg: &Arc<Config>,
    client: &AsyncClient,
    volume: &Arc<VolumeCtl>,
    light: Option<&Arc<LightCtl>>,
    frame: &str,
) -> Option<u8> {
    // Stair-light SWITCH state tracking: a physical panel press of the light button appears
    // on the monitor as `*8*21*<WHERE>##`. Feed EVERY frame to the controller — it matches
    // its own WHERE and flips the tracked state (ignoring our own toggle's echo). Cheap: a
    // non-matching frame returns immediately. No-op when the feature is off.
    if let Some(light) = light {
        light.observe(frame).await;
    }

    // Learn the real volume AND mute from the bus (issue #40): the unit broadcasts
    // `*#8**41*<N>##` (volume) and `*#8**33*<0|1>##` (mute/RingEnable) on the monitor
    // whenever either changes by ANY path (slider, up/down, mute, or the unit's own menu),
    // so this is the single source of truth for `current`/`muted`. Parse BEFORE the format
    // branch so it works in raw mode too; a frame is at most one of the two, and any other
    // frame parses to None and is ignored.
    let mut call_code = None;
    if let Some(pct) = dimension::parse_volume_report(frame) {
        volume.observe_volume(pct).await;
    } else if let Some(muted) = dimension::parse_mute_report(frame) {
        volume.observe_mute(muted).await;
    } else if let Some(where_) = dimension::parse_doorbell(frame) {
        // Entrance-panel CALL: fire a momentary "pressed" event.
        publish_doorbell(cfg, client, where_).await;
    } else if let Some(code) = dimension::parse_call_state(frame) {
        // Call STATE transition (idle/ringing/in_call, or "active" fallback): update the
        // retained sensor and report the code so the caller can (dis)arm the watchdog.
        publish_call_state(cfg, client, code).await;
        call_code = Some(code);
    }
    let payload: Vec<u8> = if cfg.payload_json {
        match own::frame_to_json(frame) {
            Some(v) => v.to_string().into_bytes(),
            None => return call_code, // ACK/NACK dropped (never a call-state frame)
        }
    } else {
        frame.as_bytes().to_vec()
    };
    // NON-BLOCKING publish (try_publish, not publish().await): every publish on the monitor
    // read path must be non-blocking, or a broker outage could stall the reader. During an
    // outage main's poll loop stops draining the bounded (32) request channel for up to 5 s;
    // once it fills, an awaited publish here would BLOCK — and while blocked we'd never reach a
    // later light echo (same buffer or a later socket read), whose 3 s guard would then expire
    // and misread our own echo as a physical press, inverting the cache (Codex). Dropping a
    // frame when the queue is full is safe: the dump is a live QoS-0 stream, and every retained
    // topic (call state, volume/mute, light) is re-seeded on the next reconnect.
    if let Err(e) = client.try_publish(&cfg.topic_dump, QoS::AtMostOnce, false, payload) {
        eprintln!("btmqttd: publish bus frame failed: {e}");
    }
    call_code
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
    // Non-blocking (see publish_frame): never stall the monitor reader on a full request queue.
    // A doorbell press dropped during a broker outage matches this event's existing philosophy
    // (a lost press is preferable to a double actuation) — it is not retained or replayed.
    if let Err(e) =
        client.try_publish(&cfg.topic_doorbell, QoS::AtMostOnce, false, payload.into_bytes())
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
    // Non-blocking (see publish_frame): never stall the monitor reader on a full request queue.
    // This retained state is re-read authoritatively and republished on the next reconnect
    // (read_call_state), so a drop during an outage self-heals.
    if let Err(e) =
        client.try_publish(&cfg.topic_call_state, QoS::AtLeastOnce, true, payload.into_bytes())
    {
        eprintln!("btmqttd: publish call state failed: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn call_watch_arms_on_non_idle_and_disarms_on_idle() {
        let mut watch = None;
        // A non-idle state arms the reconcile marker with the KNOWN code...
        update_call_watch(&mut watch, 6);
        assert!(matches!(watch, Some((Some(6), _))));
        // ...a ringing phase re-arms it with the new code...
        update_call_watch(&mut watch, 2);
        assert!(matches!(watch, Some((Some(2), _))));
        // ...and idle (0) disarms it (so the loop stops polling once the call ends).
        update_call_watch(&mut watch, 0);
        assert!(watch.is_none());
    }
}
