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
    // Classifies each call as entrance-panel vs floor and keeps the two independent. Owned here so
    // its lifetime spans reconnects, but RESET to Idle at the start of each session (see
    // `on_reconnect` below): a monitor outage can end one call and start another in the gap, so no
    // classification survives it — the authoritative reconcile suppresses ambiguous rings and the
    // post-reconnect live frames reclassify, which is what keeps a floor call off the entrance
    // sensor across reconnects (Codex).
    let classifier = std::sync::Mutex::new(dimension::CallClassifier::new());
    let mut backoff = 0u64;
    loop {
        let start = tokio::time::Instant::now();
        if let Err(e) = session(&cfg, &client, &volume, light.as_ref(), &classifier).await {
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

/// How often the monitor loop re-publishes the retained states (light, volume/mute, call
/// state). This is the recovery path for a retained update dropped by a momentarily-full
/// request queue while the broker stayed CONNECTED (no reconnect re-seeds it). Coalesced by
/// nature — always the latest cached value — and off the per-frame path, so it never blocks
/// the reader. Bounds such staleness to at most one interval.
const RETAINED_RESEED_INTERVAL: Duration = Duration::from_secs(60);

/// How many times a call-state reconcile may RE-QUERY when a monitor transition is observed
/// while its dim-35 snapshot is in flight. The monitor and the query use separate connections,
/// so a drained transition can't be ordered against the snapshot by local receipt time; re-query
/// until one completes transition-free (unambiguously current). Bounded so a rapid transition
/// burst can't loop forever — at the cap the drained transitions have kept the state current.
const MAX_RECONCILE_REQUERIES: usize = 5;

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
    // Owned by run() and shared across sessions, so a call in progress over a monitor reconnect
    // keeps its entrance/floor classification (see run()). It holds the leading `*#8**35*1` ring
    // (which arrives BEFORE the classifying WHO=8 frame) until resolved, then either flushes it
    // (entrance) or suppresses it (floor).
    classifier: &std::sync::Mutex<dimension::CallClassifier>,
) -> std::io::Result<()> {
    let mut sock = TcpStream::connect((cfg.own_host.as_str(), cfg.own_port_mon)).await?;
    sock.write_all(MONITOR_REQ).await?;
    sock.flush().await?;

    let mut framer = Framer::default();
    let mut buf = [0u8; 4096];
    let mut frames: Vec<String> = Vec::new();

    // Reset the classifier for this session: a monitor outage loses every frame in the gap, so any
    // classification carried from the previous session is untrustworthy (the call may have ended and
    // another begun). Resetting to Idle makes the authoritative reconcile suppress ambiguous rings
    // and the post-reconnect live frames reclassify — no stale Floor/Entrance/Pending can leak a
    // call onto the wrong sensor. No-op on the first connect. (Sync call — guard released before the
    // awaits below.)
    lock_classifier(classifier).on_reconnect();

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
            if let FrameOutcome::CallStatePublished(code) =
                publish_frame(cfg, client, volume, light, classifier, &frame).await
            {
                update_call_watch(&mut call_watch, code);
            }
        }
    }

    // Reconcile the retained call state AUTHORITATIVELY on every (re)connect: query the
    // gateway (`*#8**35##`) for the REAL state rather than trusting the possibly-stale buffered
    // frames above (or blindly assuming idle), so a call genuinely in progress across a monitor
    // reconnect is preserved. The query drains the monitor for light meanwhile, so a light echo
    // landing on the fresh session isn't buffered past its guard (see read_call_state_draining).
    // Apply the authoritative snapshot ONLY IF no live call-state transition was observed on the
    // monitor during the query — if one was, the drain already published it and updated
    // `call_watch` (it is at least as recent as the snapshot, over a separate connection). On a
    // FAILED read (session refused / no reply) do NOT fabricate a state — publishing idle would
    // clobber a real ringing/in_call; keep what the frames left and, if still disarmed, arm an
    // "unknown" marker so a later poll re-queries.
    match read_call_state_draining(
        cfg, client, volume, light, classifier, &mut sock, &mut framer, &mut buf, &mut frames,
        &mut call_watch,
    )
    .await?
    {
        Reconcile::SocketClosed => return Ok(()),
        Reconcile::Done { saw_transition: true, .. } => {}
        Reconcile::Done { result: Ok(Some(code)), saw_transition: false } => {
            // Reconcile the authoritative snapshot against the live classification, which PERSISTS
            // across reconnects (see run()): a known FLOOR call — including one carried over a
            // monitor reconnect — (or a still-Pending, unresolved leading ring) suppresses a ringing
            // snapshot so it can't reach the entrance-panel sensor; an idle snapshot resets the
            // classifier. A classifier that is Idle/Entrance here publishes, so a genuine in-progress
            // ENTRANCE call (or one whose type was never seen) is still reconciled (Codex/Copilot).
            // Bind the action first so the (non-Send) guard is dropped before the await.
            let action = lock_classifier(classifier).reconcile_snapshot(code);
            if let dimension::CallStateAction::Publish(c) = action {
                publish_call_state(cfg, client, c).await;
                update_call_watch(&mut call_watch, c);
            }
        }
        Reconcile::Done { result: Ok(None) | Err(_), saw_transition: false } => {
            if call_watch.is_none() {
                call_watch = Some((None, tokio::time::Instant::now()));
            }
        }
        // Capped without a clean snapshot: arm UNKNOWN so the poll keeps reconciling.
        Reconcile::Exhausted => {
            call_watch = Some((None, tokio::time::Instant::now()));
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

    let mut last_reseed = tokio::time::Instant::now();
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
                if let FrameOutcome::CallStatePublished(code) =
                    publish_frame(cfg, client, volume, light, classifier, &frame).await
                {
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
                // Drain the monitor for light while this query runs (same reason as the reconnect
                // reconcile): a slow/timed-out poll must not block the read past a light echo's
                // 3 s guard (Codex).
                match read_call_state_draining(
                    cfg, client, volume, light, classifier, &mut sock, &mut framer, &mut buf,
                    &mut frames, &mut call_watch,
                )
                .await?
                {
                    Reconcile::SocketClosed => return Ok(()),
                    // A live transition during the drain already published + updated `call_watch`
                    // (in order, newer than this snapshot) — leave it.
                    Reconcile::Done { saw_transition: true, .. } => {}
                    Reconcile::Done { result: Ok(Some(code)), saw_transition: false } => {
                        // Reconcile against the live classification here too. call_watch is NOT armed
                        // only by entrance calls: a failed reconnect read / exhausted reconcile arms
                        // it as UNKNOWN (`Some((None, …))`), so a floor call starting before the retry
                        // sets the classifier to Floor (or leaves it Pending) while this poll is live —
                        // which would otherwise publish the floor ringing snapshot here (Codex).
                        let action = lock_classifier(classifier).reconcile_snapshot(code);
                        match action {
                            dimension::CallStateAction::Publish(c) => {
                                // Publish only on a real change — `known` is None ("unknown", from a
                                // failed reconnect read) so the first successful poll always writes.
                                if known != Some(c) {
                                    publish_call_state(cfg, client, c).await;
                                }
                                update_call_watch(&mut call_watch, c);
                            }
                            dimension::CallStateAction::Suppress => {
                                // Floor/pending in progress: publish nothing. Preserve the obligation
                                // (`known` unchanged) but reset the timer so we re-check after the
                                // interval instead of hot-looping; it converges once the call resolves
                                // and the next poll publishes the true state.
                                call_watch = Some((known, tokio::time::Instant::now()));
                            }
                        }
                    }
                    Reconcile::Done { result: Ok(None) | Err(_), saw_transition: false } => {
                        // Retry after the interval, preserving `known` either way. The two
                        // cases are semantically distinct but handled identically: a
                        // `Some(code)` retry just refreshes a known non-idle probe, whereas a
                        // `None` retry is a reconcile OBLIGATION left by a failed reconnect
                        // read — both must keep polling until an authoritative read succeeds.
                        call_watch = Some((known, tokio::time::Instant::now()));
                    }
                    // Capped without a clean snapshot: arm UNKNOWN (NOT the stale pre-drain
                    // `known`) so the poll keeps reconciling and the reseed republishes nothing
                    // until a clean snapshot lands (Codex).
                    Reconcile::Exhausted => {
                        call_watch = Some((None, tokio::time::Instant::now()));
                    }
                }
            }
        }

        // Periodically re-publish the retained states (light, volume/mute, call state) so a value
        // dropped by a full request queue while the broker stayed CONNECTED — which no reconnect
        // re-seeds — is corrected within RETAINED_RESEED_INTERVAL instead of lingering until the
        // topic next changes (Codex/CodeRabbit). This runs off the per-frame path and every publish
        // is non-blocking, so it never delays a light echo. Call state is included because a dropped
        // transition is not otherwise republished — a dropped idle disarms the poll and a dropped
        // non-idle looks already-known — and the monitor session does not restart on a
        // connected-only drop (Codex).
        if last_reseed.elapsed() >= RETAINED_RESEED_INTERVAL {
            if let Some(light) = light {
                light.seed().await;
            }
            volume.reseed().await;
            // Re-QUERY call state AUTHORITATIVELY here (not just republish the cache). This is the
            // guaranteed backstop for the cross-connection ordering residual (CodeRabbit): even if
            // a stale idle frame disarmed the poll, this unconditional re-query re-checks dim-35
            // within one interval and re-arms/corrects, so the call-state sensor can't remain stuck.
            match read_call_state_draining(
                cfg, client, volume, light, classifier, &mut sock, &mut framer, &mut buf,
                &mut frames, &mut call_watch,
            )
            .await?
            {
                Reconcile::SocketClosed => return Ok(()),
                // A live transition during the drain already published + updated the watch.
                Reconcile::Done { saw_transition: true, .. } => {}
                Reconcile::Done { result: Ok(Some(code)), saw_transition: false } => {
                    // Reconcile the periodic authoritative snapshot: a reseed landing during a FLOOR
                    // call (or a still-Pending ring) suppresses its dim-35 "ringing" so it can't reach
                    // the entrance-panel sensor; an idle snapshot also resets the classifier, repairing
                    // a missed terminal frame so a later floor call's ring isn't mis-published as
                    // entrance (Codex/Copilot). Bind first to drop the guard before the await.
                    let action = lock_classifier(classifier).reconcile_snapshot(code);
                    if let dimension::CallStateAction::Publish(c) = action {
                        publish_call_state(cfg, client, c).await;
                        update_call_watch(&mut call_watch, c);
                    }
                }
                Reconcile::Done { result: Ok(None) | Err(_), saw_transition: false } => {
                    // Query failed — best-effort republish the last cached value (the original
                    // reseed behavior), so a dropped retained update is still recovered. During a
                    // floor call, call_watch is disarmed (None) → this republishes idle(0), which is
                    // exactly right: the entrance-panel sensor stays idle through a floor call.
                    match call_watch {
                        None => publish_call_state(cfg, client, 0).await, // confirmed idle
                        Some((Some(code), _)) => publish_call_state(cfg, client, code).await,
                        Some((None, _)) => {} // unknown — nothing authoritative to republish
                    }
                }
                Reconcile::Exhausted => {
                    call_watch = Some((None, tokio::time::Instant::now()));
                }
            }
            last_reseed = tokio::time::Instant::now();
        }
    }
}

/// Outcome of a monitor-draining call-state query.
enum Reconcile {
    /// The query finished. `result` is its own Ok/Err; `saw_transition` is true when a LIVE
    /// call-state frame was observed on the monitor DURING the query — in which case the caller
    /// must NOT overwrite it with the (possibly older) snapshot, since the two arrive over
    /// separate connections and the monitor frame is at least as recent.
    Done {
        result: std::io::Result<Option<u8>>,
        saw_transition: bool,
    },
    /// Every attempt saw a transition, so no clean snapshot was obtained. The last drained frame
    /// is itself ambiguous, so the caller must NOT treat it as authoritative: it arms an UNKNOWN
    /// obligation (`Some((None, now))`) so the periodic poll keeps reconciling and the reseed
    /// republishes nothing until a clean snapshot lands (Codex).
    Exhausted,
    /// The monitor socket closed mid-drain — the caller should end the session.
    SocketClosed,
}

/// Run `read_call_state` while KEEPING the monitor socket drained, so a light echo landing on
/// the socket during a slow or timed-out query is still observed within its 3 s guard instead of
/// being read late and misjudged as a physical press (Codex). Used by BOTH the reconnect reconcile
/// and the periodic poll. Drained frames run the full [`publish_frame`] — light echoes, volume/mute,
/// entrance-panel/floor call events, dump AND call-state are all handled the moment they arrive. A call-state transition
/// seen here is a LIVE event from the monitor connection, at least as recent as the dim-35 snapshot
/// (which travels over a SEPARATE connection); it is published, updates `call_watch`, and sets
/// `saw_transition` so the caller leaves it in place rather than clobbering it with the snapshot
/// (Codex/CodeRabbit). The socket is drained even with NO light controller: call classification is
/// now time-sensitive on its own (a floor signature must reach the classifier BEFORE the snapshot
/// is accepted, or a floor ring leaks to the entrance-panel sensor), independent of the light echo
/// guard (Codex).
#[allow(clippy::too_many_arguments)]
async fn read_call_state_draining(
    cfg: &Arc<Config>,
    client: &AsyncClient,
    volume: &Arc<VolumeCtl>,
    light: Option<&Arc<LightCtl>>,
    classifier: &std::sync::Mutex<dimension::CallClassifier>,
    sock: &mut TcpStream,
    framer: &mut Framer,
    buf: &mut [u8],
    frames: &mut Vec<String>,
    call_watch: &mut CallWatch,
) -> std::io::Result<Reconcile> {
    // Cross-connection ordering can't be inferred from local receipt time — a monitor frame drained
    // during the query may PREDATE or POSTDATE the dim-35 snapshot. So whenever a live call-state
    // transition IS drained (published + applied in order below), the snapshot is ambiguous:
    // RE-QUERY for a clean one. This converges — once the call settles, a query completes with no
    // transition during it and its snapshot is unambiguously current. Bounded so a rapid transition
    // burst can't loop forever; at the cap the drained transitions have kept `call_watch` current.
    for _ in 0..MAX_RECONCILE_REQUERIES {
        let reconcile = dimension::read_call_state(&cfg.own_host, cfg.own_port_mon);
        tokio::pin!(reconcile);
        let mut saw_transition = false;
        let result = loop {
            tokio::select! {
                biased;
                r = &mut reconcile => break r,
                read = tokio::time::timeout(RECONNECT_DRAIN_TICK, sock.read(buf)) => {
                    // A completed read is processed now; a timeout re-polls.
                    if let Ok(read) = read {
                        let n = read?;
                        if n == 0 {
                            return Ok(Reconcile::SocketClosed);
                        }
                        frames.clear();
                        framer.push(&buf[..n], frames);
                        for frame in frames.drain(..) {
                            // A live call-state frame (published OR suppressed) or a classifying
                            // signature marks this snapshot ambiguous → re-query below; only a
                            // PUBLISHED code updates the watch, applied IN ORDER (Codex).
                            match publish_frame(cfg, client, volume, light, classifier, &frame).await
                            {
                                FrameOutcome::CallStatePublished(code) => {
                                    update_call_watch(call_watch, code);
                                    saw_transition = true;
                                }
                                FrameOutcome::ClassifierChanged => saw_transition = true,
                                FrameOutcome::Other => {}
                            }
                        }
                    }
                }
            }
        };
        // The biased select gives the query priority, so a monitor frame that was ALSO ready this
        // poll is still queued (it would otherwise be read AFTER we commit the snapshot — possibly
        // an OLDER delayed transition that then overwrites it). Drain any ready frames NOW
        // (non-blocking) before accepting the snapshot; a transition here makes it ambiguous, so
        // the outer loop re-queries rather than committing it (Codex/CodeRabbit).
        loop {
            match sock.try_read(buf) {
                Ok(0) => return Ok(Reconcile::SocketClosed),
                Ok(n) => {
                    frames.clear();
                    framer.push(&buf[..n], frames);
                    for frame in frames.drain(..) {
                        match publish_frame(cfg, client, volume, light, classifier, &frame).await {
                            FrameOutcome::CallStatePublished(code) => {
                                update_call_watch(call_watch, code);
                                saw_transition = true;
                            }
                            FrameOutcome::ClassifierChanged => saw_transition = true,
                            FrameOutcome::Other => {}
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        // A query that saw no transition — neither before it completed nor already-ready at
        // completion — is applied. This is BEST-EFFORT: the monitor and dim-35 use separate
        // connections with no gateway sequence marker (CodeRabbit), so a monitor frame could still
        // become readable in the instant AFTER this check and before the caller publishes, and such
        // a stale frame could even disarm the poll. The call-state sensor still self-heals, though:
        // the reseed loop RE-QUERIES dim-35 authoritatively every RETAINED_RESEED_INTERVAL
        // REGARDLESS of call_watch, so a stuck state is re-checked and corrected within one interval.
        if !saw_transition {
            return Ok(Reconcile::Done { result, saw_transition: false });
        }
    }
    // Transitions kept arriving through every attempt: no clean snapshot. Signal Exhausted so the
    // caller arms an UNKNOWN obligation rather than trusting the last (ambiguous) drained frame or
    // the stale pre-drain `known` (Codex).
    Ok(Reconcile::Exhausted)
}

/// What a monitor frame turned out to be, as far as call-state watching and reconciliation care.
/// The distinction between "published" and merely "changed the classifier" matters for the drain
/// in [`read_call_state_draining`]: ANY frame that touched the classifier makes a concurrent dim-35
/// snapshot AMBIGUOUS (it may have arrived after the snapshot and changed state the snapshot can't
/// see), so the query must re-run — but only a PUBLISHED call-state code may (dis)arm the entrance
/// watch (Codex).
enum FrameOutcome {
    /// A call-state transition that reached the sensor; `u8` is the code — (dis)arm the watch.
    CallStatePublished(u8),
    /// The frame changed the classifier but published no call-state code — a floor/entrance
    /// signature, or a suppressed/held dim-35 ring. Marks a snapshot ambiguous; does NOT arm the watch.
    ClassifierChanged,
    /// Any other frame (light echo, volume/mute, dump-only) — irrelevant to call-state reconcile.
    Other,
}

/// Lock the call classifier, RECOVERING the guard if the mutex was poisoned instead of
/// panicking the daemon (Copilot). The guarded operations are panic-free atomic state
/// transitions over a `CallKind` enum, so a poisoned lock can only mean an unrelated panic
/// elsewhere unwound past a still-held guard while the state stayed a valid variant — there is
/// no torn state to fear, so recovering keeps call classification (and the whole monitor) alive
/// rather than bringing it down for good. Never hold the returned guard across an `.await`.
fn lock_classifier(
    classifier: &std::sync::Mutex<dimension::CallClassifier>,
) -> std::sync::MutexGuard<'_, dimension::CallClassifier> {
    classifier.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Publish one framed OWN string to TOPIC_DUMP — as compact JSON (PAYLOAD_FORMAT=json, the default)
/// or the raw frame. QoS 0, not retained, as the shell's `mqtt_pub -l` did. Also feeds the frame to
/// the light/volume controllers and the call classifier. Returns a [`FrameOutcome`] describing what
/// the frame was for call-state purposes (see its doc).
async fn publish_frame(
    cfg: &Arc<Config>,
    client: &AsyncClient,
    volume: &Arc<VolumeCtl>,
    light: Option<&Arc<LightCtl>>,
    classifier: &std::sync::Mutex<dimension::CallClassifier>,
    frame: &str,
) -> FrameOutcome {
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
    let mut outcome = FrameOutcome::Other;
    if let Some(pct) = dimension::parse_volume_report(frame) {
        volume.observe_volume(pct).await;
    } else if let Some(muted) = dimension::parse_mute_report(frame) {
        volume.observe_mute(muted).await;
    } else if let Some(where_) = dimension::parse_entrance_panel_call(frame) {
        // Entrance-panel CALL (outdoor door station): fire a momentary "pressed" event AND
        // classify this call as an entrance-panel call. The `*#8**35*1` ringing frame arrives
        // BEFORE this classifying frame, so the classifier held it as Pending (Suppressed);
        // flush that held ring now that we know it's a real entrance call (arming the watchdog).
        let held = lock_classifier(classifier).saw_entrance_panel_call();
        if let Some(code) = held {
            publish_call_state(cfg, client, code).await;
            outcome = FrameOutcome::CallStatePublished(code);
        } else {
            // No held ring, but we still (re)classified to Entrance → snapshot ambiguous.
            outcome = FrameOutcome::ClassifierChanged;
        }
        publish_entrance_panel_call(cfg, client, where_).await;
    } else if let Some(where_) = dimension::parse_floor_call(frame) {
        // Floor CALL (dumb push-button at the apartment's own front door): a COMPLETELY
        // independent event from the entrance panel. Fire its own momentary event and arm the
        // classifier so the concurrent dim-35 ringing (which the gateway also raises for a floor
        // call) is SUPPRESSED — a floor call must never surface on the entrance-panel call_state.
        lock_classifier(classifier).saw_floor_call();
        outcome = FrameOutcome::ClassifierChanged; // reclassified to Floor → snapshot ambiguous
        publish_floor_call(cfg, client, where_).await;
    } else if let Some(code) = dimension::parse_call_state(frame) {
        // Call STATE transition (idle/ringing/in_call, or "active" fallback). Route it through the
        // classifier: an entrance-panel call publishes it (updating the retained sensor and reporting
        // the code so the caller can (dis)arm the watchdog); a floor call's ringing is suppressed; an
        // as-yet-unclassified leading ring is HELD until the classifying WHO=8 frame resolves it.
        // EITHER way it is a live call-state frame, so a concurrent reconcile snapshot is ambiguous —
        // a Suppress still reports ClassifierChanged so the query re-runs and does not commit a stale
        // snapshot that would clobber the held/floor state (Codex). Resolve the action and DROP the
        // (non-Send) guard before any `.await` — never hold a std::sync::MutexGuard across an await.
        let action = lock_classifier(classifier).on_call_state(code);
        outcome = match action {
            dimension::CallStateAction::Publish(c) => {
                publish_call_state(cfg, client, c).await;
                FrameOutcome::CallStatePublished(c)
            }
            dimension::CallStateAction::Suppress => FrameOutcome::ClassifierChanged,
        };
    }
    let payload: Vec<u8> = if cfg.payload_json {
        match own::frame_to_json(frame) {
            Some(v) => v.to_string().into_bytes(),
            None => return outcome, // ACK/NACK dropped (never a call-state frame → Other)
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
    outcome
}

/// Publish a momentary entrance-panel "pressed" event to TOPIC_ENTRANCE_PANEL_CALL. NOT
/// retained: an event fires once, and a retained event would spuriously re-fire on every HA
/// reconnect. QoS 0 (like the non-idempotent lock/step actions): a ring is NON-idempotent,
/// and QoS 1 may legitimately REDELIVER a publish (DUP on a lost PUBACK), which would fire the
/// HA event — and any automation — twice for one ring. A press lost during a brief broker
/// reconnect is preferable to a double actuation. The payload carries the HA `event_type` plus
/// the entrance-panel WHERE (informational).
async fn publish_entrance_panel_call(cfg: &Arc<Config>, client: &AsyncClient, where_: &str) {
    let payload = serde_json::json!({ "event_type": "pressed", "where": where_ }).to_string();
    // Non-blocking (see publish_frame): never stall the monitor reader on a full request queue.
    // A press dropped during a broker outage matches this event's existing philosophy (a lost
    // press is preferable to a double actuation) — it is not retained or replayed.
    if let Err(e) = client.try_publish(
        &cfg.topic_entrance_panel_call,
        QoS::AtMostOnce,
        false,
        payload.into_bytes(),
    ) {
        eprintln!("btmqttd: publish entrance-panel call event failed: {e}");
    }
}

/// Publish a momentary floor-call "pressed" event to TOPIC_FLOOR_CALL. This is the dumb
/// push-button wired to the apartment's own front door — a wholly independent ring from the
/// entrance panel, on its own HA `event` entity. Same delivery semantics as the entrance-panel
/// event (NOT retained, QoS 0, non-blocking) and for the same reasons: a ring is momentary and
/// non-idempotent, so a redelivered or replayed publish would double-fire the automation.
async fn publish_floor_call(cfg: &Arc<Config>, client: &AsyncClient, where_: &str) {
    let payload = serde_json::json!({ "event_type": "pressed", "where": where_ }).to_string();
    if let Err(e) = client.try_publish(
        &cfg.topic_floor_call,
        QoS::AtMostOnce,
        false,
        payload.into_bytes(),
    ) {
        eprintln!("btmqttd: publish floor call event failed: {e}");
    }
}

/// Publish the call STATE to TOPIC_CALL_STATE, RETAINED so HA shows the current state
/// after a reconnect/restart. The payload carries the mapped label (idle/ringing/in_call,
/// or "active" for an unmapped code — see [`dimension::call_state_label`]) plus the raw
/// code as an attribute for finer protocol detail.
async fn publish_call_state(cfg: &Arc<Config>, client: &AsyncClient, code: u8) {
    let payload =
        serde_json::json!({ "state": dimension::call_state_label(code), "code": code }).to_string();
    try_publish_retained(client, &cfg.topic_call_state, QoS::AtLeastOnce, payload.into_bytes());
}

/// Publish a RETAINED topic on the monitor read path WITHOUT ever blocking it: a single
/// `try_publish`. If the bounded request channel is momentarily full (a burst outran the
/// single-threaded event loop, or the broker is down) the value is DROPPED here rather than
/// awaited — the reader must never stall, or a following light echo could miss its 3 s guard
/// (Codex/CodeRabbit). A dropped retained value is recovered OFF the read path: the session
/// loop's periodic reseed re-publishes the latest light/volume/call state within
/// [`RETAINED_RESEED_INTERVAL`], and every reconnect re-seeds them too. The lossy dump and
/// the momentary call events (entrance-panel/floor) call `try_publish` directly.
pub(crate) fn try_publish_retained(client: &AsyncClient, topic: &str, qos: QoS, payload: Vec<u8>) {
    match client.try_publish(topic, qos, true, payload) {
        Ok(()) => {}
        // Full (or disconnected): drop; the periodic reseed / next reconnect republishes.
        Err(rumqttc::ClientError::TryRequest(_)) => {}
        Err(e) => eprintln!("btmqttd: publish retained {topic} failed: {e}"),
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
