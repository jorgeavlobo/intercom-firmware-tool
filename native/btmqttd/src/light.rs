//! Stair-light SWITCH — a WHO=8 toggle actuator with NO readable state.
//!
//! Reverse-engineering the firmware (`bt_vct`) showed the stair-light button is a
//! fire-and-forget push-button: sending `*8*21*<WHERE>##` to the command port TOGGLES the
//! building's light relay. There is NO discrete on/off (release `*8*22*…` is a no-op) and
//! NO status query — `bt_vct` turns the frame into a bare SCS bus pulse and never reads
//! back, and there is no OWN dimension for it (all confirmed on a live unit: press alone
//! flips it; `*#8*<w>##`/`*#1*<w>##` all NACK).
//!
//! So HA cannot READ the state; we TRACK it. Every observed toggle — ours or a PHYSICAL
//! panel press seen on the monitor as `*8*21*<WHERE>##` — flips a cached on/off, which is
//! PERSISTED (keyed by WHERE) across reboots. A command TOGGLES only when the desired
//! absolute state differs from the cache, and — crucially — commits ONLY after the frame
//! is successfully forwarded, so a failed actuation stays retryable and never shows HA a
//! state the relay didn't reach. The commit FLIPS the cache once (our injection is one
//! relay toggle) rather than absolute-setting it, so a physical press observed while the
//! forward is in flight COMPOSES with our toggle instead of being clobbered — the cache
//! stays equal to initial-XOR-(total toggles). An echo guard, armed BEFORE forwarding,
//! stops our own toggle's monitor echo from double-flipping the cache.
//!
//! Persistence is handled by a DEDICATED task ([`run_persist`]): the tracked state lives
//! behind a plain `std::sync::Mutex` (never held across an `.await`), so the stretch from a
//! successful forward to enqueuing the new state onto the persist channel is fully
//! SYNCHRONOUS — there is no `.await` at which a shutdown could abort the command worker
//! after the relay toggled but before the state was queued. `main` DRAINS the persist task
//! at shutdown (signals it after aborting the workers, then awaits it), so a toggle actuated
//! moments before SIGTERM is still written to disk.
//!
//! Residual imperfection (inherent to a stateless toggle): on the very FIRST cold boot the
//! cache is unknown, so the first command is optimistic; a toggle made while the daemon is
//! DOWN is missed; if SIGTERM lands DURING the forward itself (the frame reached the bus but
//! the `.await` hasn't returned) that single toggle can be lost; and if a command's echo is
//! LOST across a monitor reconnect (it was in flight on the socket that died), its expectation
//! lingers until its [`ECHO_GUARD`] deadline (≤3 s), during which a physical press is absorbed
//! as that (never-arriving) echo — the relay toggles but the cache does not, leaving it one
//! toggle behind until a later frame (another press, or the next command) rebalances it. The
//! EXPOSURE WINDOW is bounded (≤3 s) but the resulting desync can persist. This is deliberately
//! NOT special-cased at reconnect, because the tracker cannot distinguish a command whose echo
//! was lost on the dead socket (should be forgotten) from one still in-flight whose echo arrives
//! on the new socket (must be kept), so any reconnect-time clearing would either strand stale
//! guards or double-count an in-flight command — a worse, unbounded failure than this rare,
//! bounded-window residual.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rumqttc::{AsyncClient, QoS};
use tokio::sync::{oneshot, watch, Mutex as AsyncMutex, Notify};
use tokio::time::Instant;

use crate::config::Config;
use crate::receiver::forward_to_gateway;

/// How long a "Learn light" press keeps the capture window open: press the button in HA,
/// then press the PHYSICAL stair-light button once within this window to teach the WHERE.
const LEARN_WINDOW: Duration = Duration::from_secs(60);

/// Parse a stair-light press frame `*8*21*<WHERE>##` and return its WHERE (digits only).
/// Used by the learn capture to adopt whatever actuator the physical button drives.
fn parse_light_where(frame: &str) -> Option<&str> {
    let w = frame.strip_prefix("*8*21*")?.strip_suffix("##")?;
    (!w.is_empty() && w.bytes().all(|b| b.is_ascii_digit())).then_some(w)
}

/// Per-frame forward timeout for the toggle (loopback gateway; tight like the lock pulse).
const FORWARD_TIMEOUT: Duration = Duration::from_secs(2);

/// After WE inject a toggle, the gateway echoes the same `*8*21*<w>##` back on the monitor;
/// ignore an observed press within this window so our own toggle isn't counted a second time.
/// The window must OUTLAST a full command: a forward may take up to [`FORWARD_TIMEOUT`] and its
/// echo can arrive a little later still, so a shorter window would let a successful-but-late
/// echo be miscounted as a physical press on top of the commit (Codex). Kept well above
/// `FORWARD_TIMEOUT`. Loopback echo is normally near-instant, so this ceiling is rarely
/// approached; and while a window this long could absorb a concurrent PHYSICAL press as if it
/// were our echo, the toggle COUNT still balances (our commit plus one flip per extra frame),
/// so the cache stays correct.
const ECHO_GUARD: Duration = Duration::from_secs(3);

/// The tracked light state + echo guard. Its methods are PURE (no I/O), so the tracking
/// logic is unit-tested without a gateway or broker; [`LightCtl`] does the MQTT/forward I/O
/// around them.
struct State {
    /// Cached light state: `None` = unknown (first cold boot, no persisted value).
    on: Option<bool>,
    /// OUR injected toggles still awaiting their monitor echo, in arm order — each an
    /// `(generation, deadline)`: a fresh id plus that echo's OWN expiry (its arm time +
    /// [`ECHO_GUARD`]). Each armed command pushes one; each frame observed within a live
    /// window consumes the OLDEST (frames echo back in the order they hit the bus), instead of
    /// being counted as a physical press. A per-command QUEUE with per-echo deadlines — not a
    /// single flag, bare count, or shared deadline — so that: several commands issued faster
    /// than the bus echoes them each get their own echo absorbed; a failing command reclaims
    /// ONLY its own echo, never an earlier successful command's delayed echo; and a new
    /// command's arm can't extend an older expectation's window and let a stale count swallow a
    /// genuine later physical press (all Codex). An expectation whose echo never arrives (e.g.
    /// missed across a monitor reconnect) simply EXPIRES by its own deadline, at which point the
    /// next observed frame is judged fresh — no cross-session bookkeeping is needed.
    pending: VecDeque<(u64, Instant)>,
    /// Next generation to hand out (monotonic; wraps harmlessly — only equality is used).
    next_gen: u64,
}

impl State {
    /// Whether a command to reach `desired` must forward a toggle (the cache differs).
    fn needs_toggle(&self, desired: bool) -> bool {
        self.on != Some(desired)
    }

    /// Arm the echo guard — called BEFORE forwarding, so the echo (which can land as soon as
    /// the frame reaches the bus) is always covered. Queues ONE expected echo tagged with a
    /// fresh generation (returned to the caller for [`on_forward_failed`]) and its OWN deadline,
    /// so a later command's arm can't extend this expectation's window.
    fn arm_guard(&mut self, now: Instant) -> u64 {
        // Prune expired expectations first (front-first — arm order is deadline order, same as
        // apply_observe) so the queue is self-limiting: if the monitor stream is down while
        // commands keep succeeding, stale entries don't accumulate until the next observe().
        // A forward resolves within FORWARD_TIMEOUT (< ECHO_GUARD), so an in-flight command's
        // entry is never expired here — only genuinely stale ones (lost echoes) are dropped.
        while let Some(&(_, dl)) = self.pending.front() {
            if now >= dl {
                self.pending.pop_front();
            } else {
                break;
            }
        }
        let gen = self.next_gen;
        self.next_gen = self.next_gen.wrapping_add(1);
        self.pending.push_back((gen, now + ECHO_GUARD));
        gen
    }

    /// Called when the forward for the command tagged `gen` FAILED. If `gen` is still PENDING,
    /// its frame never reached the bus (nothing toggled): drop the expectation and return `None`
    /// (retryable). If it is GONE, an observed frame already consumed it — the frame reached the
    /// bus before the write error, or a concurrent physical press — so reclaim it: flip and
    /// return `Some(new_state)`. Echoes are consumed oldest-first, so an earlier command's
    /// delayed echo consumes THAT command's (older) generation, never this one.
    fn on_forward_failed(&mut self, gen: u64) -> Option<Option<bool>> {
        if let Some(pos) = self.pending.iter().position(|&(g, _)| g == gen) {
            self.pending.remove(pos);
            None
        } else {
            self.on = self.on.map(|b| !b); // reclaim the observed toggle; unknown stays unknown
            Some(self.on)
        }
    }

    /// Commit OUR injected toggle after a SUCCESSFUL forward, returning the new cached
    /// state to publish + persist. A KNOWN state FLIPS exactly once — our injection is one
    /// relay toggle — rather than being absolute-`set` to `desired_on`: an absolute set
    /// would CLOBBER a physical press that `observe()` applied concurrently while the
    /// forward was awaiting (the state lock is released across the forward), leaving the
    /// cache one toggle out of step with the relay. Flipping composes with that observation
    /// so the cache still equals initial-XOR-(total toggles). An UNKNOWN state (first cold
    /// boot) can't be flipped, so it is optimistically established at `desired_on` — and the
    /// gate only injects from a known state when it already differs, so a flip there reaches
    /// `desired_on` in the common (no concurrent press) case.
    fn commit_actuation(&mut self, desired_on: bool) -> Option<bool> {
        self.on = match self.on {
            Some(cur) => Some(!cur), // our injection = one toggle; compose, don't clobber
            None => Some(desired_on), // unknown → establish optimistically
        };
        self.on
    }

    /// Apply an observed `*8*21*<WHERE>##` press. Returns `Some(new_state)` to publish +
    /// persist (a PHYSICAL toggle), or `None` to ignore it (one of our own toggles' echoes,
    /// still within the window). `now` is checked against the echo deadline.
    fn apply_observe(&mut self, now: Instant) -> Option<Option<bool>> {
        // Drop outstanding echoes whose OWN window has passed (front-first — arm order is
        // deadline order), so a genuine later physical press isn't absorbed as one of ours.
        while let Some(&(_, dl)) = self.pending.front() {
            if now >= dl {
                self.pending.pop_front();
            } else {
                break;
            }
        }
        if self.pending.pop_front().is_some() {
            // Absorb the OLDEST still-live echo — already accounted for by its command's commit.
            return None;
        }
        self.on = self.on.map(|b| !b); // physical toggle; unknown stays unknown
        Some(self.on)
    }

    /// Correct the TRACKED state only — the "resync" button. The relay is a blind toggle, so
    /// after a cold boot (or a physical press while the daemon was down) our cache can be
    /// wrong; this lets the user realign HA to the real relay WITHOUT actuating it. The cycle
    /// is unknown → on → off → on, so from an unknown baseline one press establishes a known
    /// state and each further press flips it — the user stops when HA matches the wall. Returns
    /// the new state to publish + persist. Does NOT touch the echo-guard queue (no frame is
    /// sent, so there is no echo to absorb).
    fn resync(&mut self) -> Option<bool> {
        self.on = Some(match self.on {
            None => true,          // unknown → on (first press establishes a known state)
            Some(true) => false,   // on → off
            Some(false) => true,   // off → on
        });
        self.on
    }
}

/// Owns the stair-light toggle state. Shared (`Arc`) between the command worker
/// ([`command`]) and the monitor task ([`observe`]).
pub struct LightCtl {
    /// Tracked state — a PLAIN (sync) mutex, deliberately NOT a tokio mutex: it is only ever
    /// held for short synchronous sections and NEVER across an `.await`, which is what makes
    /// the post-forward "commit + enqueue persist" stretch free of any abort point (see the
    /// module doc). Do not `.await` while holding it.
    st: Mutex<State>,
    /// Serializes the retained MQTT PUBLISH ([`publish_current`]) so `command()`, `observe()`
    /// and a reconnect `seed()` — on separate tasks — can't interleave their publishes and
    /// momentarily retain a stale value; each re-reads the latest state under the lock.
    /// (Durable persistence is separate: it goes through `persist_tx` to [`run_persist`].)
    io_lock: AsyncMutex<()>,
    /// Latest state to PERSIST, handed to the dedicated [`run_persist`] task. A `watch` send
    /// is synchronous and coalescing (last value wins), so `command()`/`observe()` enqueue
    /// the new state with no `.await` — it can't be lost to a task abort — and the drained
    /// task guarantees it reaches disk even at shutdown.
    persist_tx: watch::Sender<Option<bool>>,
    /// The stair-light actuator WHERE (digits). `None` = LEARN MODE (LIGHT_ENABLED with an
    /// empty build-time WHERE and none learned yet): the switch/resync are inert and HA marks
    /// them unavailable until [`learn`] captures the WHERE. Behind a plain mutex, only held
    /// synchronously (never across `.await`), like `st`.
    where_: Mutex<Option<String>>,
    /// The "Learn light" capture deadline: `Some(t)` while armed (until `t`), else `None`.
    /// A monitor frame `*8*21*<W>##` seen while armed teaches the WHERE (see [`observe`]).
    learn_until: Mutex<Option<Instant>>,
    /// Whether this unit may LEARN (or re-learn) its WHERE. `false` for a CONFIGURED build (a
    /// non-empty build-time `LIGHT_WHERE`): that address is authoritative and `main` always binds
    /// it, so accepting a learned frame would persist an address the daemon then ignores on
    /// restart — a false "learned" that keeps toggling the old actuator (Codex). `true` only in
    /// learn mode (blank build), where the learned WHERE is what `main` actually binds.
    learnable: bool,
    /// MOMENTARY light (staircase-timer install): the actuator is fired once to turn ON and the
    /// physical installation auto-offs, so there is NO tracked state — [`press`] just forwards the
    /// frame, and [`observe`]/[`command`]/[`resync`]/[`seed`]'s state work is skipped. HA gets a
    /// press button (no switch/resync). `false` = the default BISTABLE toggle with tracked state.
    momentary: bool,
    /// Retained state topic HA reads back (`on`/`off`).
    topic_light: String,
    /// Retained light-subsystem availability topic: `online` once a WHERE is known, `offline`
    /// in learn mode — HA greys out the switch + resync until the WHERE is learned.
    topic_light_avail: String,
    /// Signalled when a WHERE is LEARNED: `main` treats it like SIGTERM and shuts down cleanly
    /// so the init script respawns btmqttd, which comes up with the learned WHERE active (the
    /// state-persist task is keyed by WHERE at startup, so a restart is the clean way to bind
    /// it — far simpler than rebuilding that task live).
    restart: Arc<Notify>,
    client: AsyncClient,
}

impl LightCtl {
    /// Build from config, restoring the persisted on/off (`initial`) so the switch keeps the
    /// right state across a reboot. `where_` is the bound actuator WHERE (`None` in learn mode);
    /// `learnable` is `true` only in learn mode (a blank build-time `LIGHT_WHERE`), where a learned
    /// WHERE is what `main` binds; `momentary` is `true` for a staircase-timer install (press-only,
    /// no tracked state — `initial` is then unused and no persist task is spawned). Returns the
    /// controller AND the `watch` receiver the caller must hand to [`run_persist`] (bistable only).
    pub fn new(
        cfg: &Arc<Config>,
        client: AsyncClient,
        initial: Option<bool>,
        where_: Option<String>,
        learnable: bool,
        momentary: bool,
        restart: Arc<Notify>,
    ) -> (Arc<Self>, watch::Receiver<Option<bool>>) {
        let (persist_tx, persist_rx) = watch::channel(initial);
        let ctl = Arc::new(LightCtl {
            st: Mutex::new(State { on: initial, pending: VecDeque::new(), next_gen: 0 }),
            io_lock: AsyncMutex::new(()),
            persist_tx,
            where_: Mutex::new(where_),
            learn_until: Mutex::new(None),
            learnable,
            momentary,
            topic_light: cfg.topic_light.clone(),
            topic_light_avail: cfg.topic_light_avail.clone(),
            restart,
            client,
        });
        (ctl, persist_rx)
    }

    /// The current `*8*21*<WHERE>##` frame, or `None` in learn mode (no WHERE yet).
    fn press_frame(&self) -> Option<String> {
        self.where_
            .lock()
            .expect("light where mutex poisoned")
            .as_ref()
            .map(|w| format!("*8*21*{w}##"))
    }

    /// Whether a WHERE is known (the switch/resync are live only then).
    fn have_where(&self) -> bool {
        self.where_.lock().expect("light where mutex poisoned").is_some()
    }

    /// Publish the cached state, RETAINED, so HA reflects it. `on`/`off` for a known state;
    /// an unknown (`None`) state publishes an EMPTY retained payload, which DELETES the
    /// broker's retained value (MQTT: a zero-length retained message clears the topic) so HA
    /// shows the switch as unknown. Clearing on unknown matters after a `LIGHT_WHERE` change:
    /// `read_light` returns `None` for the new actuator, and without this the broker would
    /// keep serving the OLD actuator's retained `on`/`off`, so HA would display a stale state
    /// instead of unknown until the first toggle (Codex).
    async fn publish(&self, on: Option<bool>) {
        let payload = match on {
            Some(true) => "on",
            Some(false) => "off",
            None => "", // empty retained → clears any stale retained value; HA shows unknown
        };
        // Non-blocking single try_publish: observe() runs on the monitor read path, so this must
        // never block on a full request queue — else the reader stalls and a following light echo
        // misses its 3 s guard (Codex/CodeRabbit). A drop while the queue is full is recovered off
        // the read path by the sender loop's periodic reseed (and by seed() on the next reconnect);
        // durable disk persistence goes through a separate, unaffected channel. See
        // sender::try_publish_retained.
        crate::sender::try_publish_retained(
            &self.client,
            &self.topic_light,
            QoS::AtLeastOnce,
            payload.as_bytes().to_vec(),
        );
    }

    /// On-connect (re)publish of the retained state — a restarted broker dropped retained
    /// topics, so re-send the known state (or, while unknown, an empty retained payload that
    /// clears any stale value the broker still holds — e.g. from a previous `LIGHT_WHERE`).
    pub async fn seed(&self) {
        // A MOMENTARY light has no tracked state → no state topic to re-assert; only the
        // availability gate is republished. Bistable re-asserts its retained on/off.
        if !self.momentary {
            self.publish_current().await;
        }
        self.publish_avail().await; // re-assert online/offline (learn-mode gate) on reconnect
    }

    /// Publish the CURRENT cached state (retained), SERIALIZED via `io_lock` so a physical
    /// `observe()`, an MQTT `command()` and a reconnect `seed()` can't interleave their
    /// publishes; the state is RE-READ under the lock so whichever call runs last retains the
    /// FINAL state. This is the RETAINED-MQTT side only — durable disk persistence goes
    /// through `persist_tx` to [`run_persist`], independently (and abort-safely).
    async fn publish_current(&self) {
        let _io = self.io_lock.lock().await;
        let on = self.st.lock().expect("light state mutex poisoned").on;
        self.publish(on).await;
    }

    /// Enqueue the current cached state for durable persistence. A `watch` send is
    /// SYNCHRONOUS (no `.await`), so callers must invoke this with no await between the state
    /// mutation and here — that is what keeps the toggle→persist path free of an abort point.
    fn enqueue_persist(&self) {
        let on = self.st.lock().expect("light state mutex poisoned").on;
        let _ = self.persist_tx.send(on);
    }

    /// HA commanded a desired ABSOLUTE state (`on`/`off`). Toggle the relay ONLY when it
    /// differs from the cache — and commit ONLY after the forward SUCCEEDS, so a failed
    /// actuation leaves the cache (and HA) unchanged and the command retryable. The echo
    /// guard is armed before forwarding and disarmed on failure. The commit FLIPS the cache
    /// (via [`State::commit_actuation`]) rather than absolute-setting it: the state lock is
    /// released across the forward, so a physical press `observe()` applies in that window
    /// must COMPOSE with our injection, not be clobbered.
    pub async fn command(&self, desired_on: bool) {
        // A MOMENTARY install exposes a press button, not a switch, so a bistable on/off command
        // should never arrive — but if a stale one does, honour "on" as a press and ignore "off"
        // (the hardware owns the off), never touching the (non-existent) tracked state.
        if self.momentary {
            if desired_on {
                self.press().await;
            }
            return;
        }
        // In learn mode (no WHERE yet) the switch is inert — HA also marks it unavailable
        // via topic_light_avail, but guard here too in case a command still arrives.
        let Some(press) = self.press_frame() else {
            eprintln!("btmqttd: light: ignoring on/off — WHERE not set yet (use Learn light)");
            return;
        };
        let gen = {
            let mut st = self.st.lock().expect("light state mutex poisoned");
            if !st.needs_toggle(desired_on) {
                return; // already in the desired state — nothing to actuate
            }
            st.arm_guard(Instant::now()) // before forwarding: the echo may land immediately
        };
        if let Err(e) = forward_to_gateway(&press, FORWARD_TIMEOUT).await {
            eprintln!("btmqttd: light toggle failed: {e}");
            // Actuation FAILED. If THIS command's echo was already absorbed during the forward,
            // its frame reached the bus (a real toggle) — reclaim it (flip + persist + publish).
            // Otherwise drop its expectation and leave the cache unchanged (retryable). Keyed by
            // `gen`, so an earlier command's delayed echo is never mistaken for our own observed
            // toggle: only THIS command's slot can be reclaimed.
            let reclaimed = self
                .st
                .lock()
                .expect("light state mutex poisoned")
                .on_forward_failed(gen);
            if reclaimed.is_some() {
                self.enqueue_persist();
                self.publish_current().await;
            }
            return;
        }
        // Post-forward: commit the toggle and ENQUEUE persistence with NO `.await` in between
        // (the state mutex is sync), so even if SIGTERM fires the instant the forward returns,
        // the new state is already on the persist channel and the drained task will write it.
        self.st.lock().expect("light state mutex poisoned").commit_actuation(desired_on);
        self.enqueue_persist();
        // Retained publish is best-effort and comes after (network I/O is the first yield).
        self.publish_current().await;
    }

    /// MOMENTARY "press": forward the actuator frame once (turn ON). The physical installation's
    /// own timer switches it off, so there is NO tracked state, no persistence and no publish —
    /// fire-and-forget. No-op if the WHERE is not known yet (learn mode; HA also marks the button
    /// unavailable via `topic_light_avail`).
    pub async fn press(&self) {
        let Some(press) = self.press_frame() else {
            eprintln!("btmqttd: light: ignoring press — WHERE not set yet (use Learn light)");
            return;
        };
        if let Err(e) = forward_to_gateway(&press, FORWARD_TIMEOUT).await {
            eprintln!("btmqttd: light press failed: {e}");
        }
    }

    /// Feed a monitor frame. When it is our WHERE's press (`*8*21*<WHERE>##`): if it is our
    /// own injected toggle's echo (within the guard) ignore it; otherwise it is a PHYSICAL
    /// panel press → flip the cache, enqueue persistence + republish. Any other frame is
    /// ignored, so the caller can hand every monitor frame here cheaply.
    pub async fn observe(&self, frame: &str) {
        // Learn capture takes precedence: while the window is open, the first stair-light
        // press `*8*21*<W>##` teaches the WHERE (see `adopt_learned_where`).
        if self.learn_active() {
            if let Some(w) = parse_light_where(frame) {
                self.adopt_learned_where(w).await;
            }
            return;
        }
        // MOMENTARY tracks no state, so a physical press is nothing to record (the hardware auto-offs
        // anyway). Learn capture above still runs; everything past here is bistable state tracking.
        if self.momentary {
            return;
        }
        let Some(press) = self.press_frame() else { return }; // learn mode: nothing to track
        if frame != press {
            return;
        }
        let flipped = self
            .st
            .lock()
            .expect("light state mutex poisoned")
            .apply_observe(Instant::now());
        if flipped.is_some() {
            self.enqueue_persist();
            self.publish_current().await;
        }
    }

    /// The "Resync light state" button: correct the TRACKED state without actuating the relay
    /// (cycle unknown→on→off→on), so the user can realign HA to the real wall state after a
    /// cold boot or a press missed while the daemon was down. No-op in learn mode (no WHERE,
    /// so no meaningful state). Persists + republishes the new state.
    pub async fn resync(&self) {
        // MOMENTARY has no tracked state to correct (HA doesn't even expose a resync button); guard
        // in case a stale command arrives.
        if self.momentary {
            return;
        }
        if !self.have_where() {
            eprintln!("btmqttd: light: ignoring resync — WHERE not set yet");
            return;
        }
        self.st.lock().expect("light state mutex poisoned").resync();
        self.enqueue_persist();
        self.publish_current().await;
    }

    /// The "Learn light" button: open the capture window. The next physical stair-light press
    /// within [`LEARN_WINDOW`] teaches the WHERE (see `observe`/`adopt_learned_where`).
    pub async fn learn(&self) {
        // A CONFIGURED build has a fixed, authoritative WHERE that `main` always binds; capturing
        // a learned frame here would persist an address the daemon ignores on restart (a false
        // "learned" that keeps toggling the old actuator) — so learning is refused. Learn mode
        // (blank build) is the only place a learned WHERE is what `main` actually binds (Codex).
        if !self.learnable {
            eprintln!(
                "btmqttd: light: ignoring learn — WHERE is fixed by configuration (LIGHT_WHERE)"
            );
            return;
        }
        *self.learn_until.lock().expect("light learn mutex poisoned") =
            Some(Instant::now() + LEARN_WINDOW);
        eprintln!("btmqttd: light: learn armed — press the physical stair-light button once");
    }

    /// Whether the learn window is currently open (armed and not expired).
    fn learn_active(&self) -> bool {
        matches!(
            *self.learn_until.lock().expect("light learn mutex poisoned"),
            Some(t) if Instant::now() < t
        )
    }

    /// Adopt a WHERE captured during learn: persist it durably, then signal `main` to restart
    /// so the light comes up ACTIVE (the state-persist task is bound to the WHERE at startup,
    /// so a clean restart is the simplest correct way to activate it). If it equals the WHERE
    /// we already have, just disarm — no restart needed.
    async fn adopt_learned_where(&self, w: &str) {
        // Disarm first so a second echo of the same press can't re-enter this path.
        *self.learn_until.lock().expect("light learn mutex poisoned") = None;
        if self.where_.lock().expect("light where mutex poisoned").as_deref() == Some(w) {
            // The physical press that taught us this WHERE is a REAL toggle. `observe()` diverted
            // it into this learn path before `apply_observe` could record it, and because the WHERE
            // is unchanged there is no restart to re-seed state — so apply that toggle to the
            // tracked state now (respecting the echo guard), or HA is left one toggle out of sync.
            eprintln!("btmqttd: light: learned WHERE {w} matches the current one — no change");
            let flipped = self.st.lock().expect("light state mutex poisoned").apply_observe(Instant::now());
            if flipped.is_some() {
                self.enqueue_persist();
                self.publish_current().await;
            }
            return;
        }
        let w_owned = w.to_string();
        let stored = tokio::task::spawn_blocking(move || crate::persist::store_light_where(&w_owned))
            .await
            .unwrap_or(false);
        if !stored {
            eprintln!("btmqttd: light: could not persist learned WHERE {w} — try Learn again");
            return;
        }
        eprintln!("btmqttd: light: learned WHERE {w} — restarting to activate it");
        self.restart.notify_one();
    }

    /// Publish the light-subsystem availability (retained): `online` once a WHERE is known,
    /// `offline` in learn mode. HA greys out the switch + resync until the WHERE is learned.
    /// Uses the drop-on-full `try_publish` because it runs on the reconnect `seed()` path where a
    /// dropped publish is recovered by the sender loop's periodic reseed; the ORDERED startup gate
    /// uses [`announce_avail`] instead.
    async fn publish_avail(&self) {
        let payload = if self.have_where() { "online" } else { "offline" };
        crate::sender::try_publish_retained(
            &self.client,
            &self.topic_light_avail,
            QoS::AtLeastOnce,
            payload.as_bytes().to_vec(),
        );
    }

    /// Assert the availability gate with an AWAITED, error-checked publish — used by `main` at
    /// startup so the bridge birth `online` is not published until this gate is actually QUEUED.
    /// `publish_avail`'s drop-on-full try-publish would let the gate be dropped and the bridge
    /// `online` still queue after capacity frees, re-exposing the stale-`online` race on a
    /// configured→learn-mode reflash (CodeRabbit). Retained, QoS 1, like the reconnect seed.
    ///
    /// Returns `true` when the gate was queued. The caller MUST NOT publish the bridge birth
    /// `online` on `false`: a failed gate leaves any stale retained `light_avail=online` in place,
    /// so declaring the bridge online would re-open the race — better to defer `online` to the next
    /// connect (a publish error means the eventloop is gone, which forces a reconnect + retry).
    #[must_use]
    pub async fn announce_avail(&self) -> bool {
        let payload = if self.have_where() { "online" } else { "offline" };
        match self
            .client
            .publish(&self.topic_light_avail, QoS::AtLeastOnce, true, payload.as_bytes().to_vec())
            .await
        {
            Ok(()) => true,
            Err(e) => {
                eprintln!("btmqttd: publish light availability gate failed: {e}");
                false
            }
        }
    }
}

/// Dedicated stair-light persistence task. `command()`/`observe()` enqueue the latest state
/// via `persist_tx` (a synchronous `watch` send, so it can't be lost to a task abort); this
/// task writes it to the reboot-persistent record off the runtime thread. It is DRAINED at
/// shutdown: `main` signals `shutdown` AFTER aborting the command/monitor tasks (so no
/// further state can be produced) and then awaits this task, whose final flush persists any
/// state queued in the last instant — so a toggle actuated moments before SIGTERM is durable
/// rather than lost with the aborted worker (Codex). Redundant writes are skipped.
/// `initial_uncertain` marks the disk baseline as NOT known to match `initial`: used when the
/// restore read FAILED (a valid record may still be on disk that we couldn't read), so the first
/// value — even one equal to `initial` — is durably written rather than assumed already on disk.
pub async fn run_persist(
    where_: String,
    initial: Option<bool>,
    initial_uncertain: bool,
    rx: watch::Receiver<Option<bool>>,
    shutdown: oneshot::Receiver<()>,
) {
    run_persist_with(initial, initial_uncertain, rx, shutdown, move |on| {
        let where_ = where_.clone();
        async move { write_light(&where_, on).await }
    })
    .await;
}

/// The persist loop, generic over the WRITER so the durability transitions are unit-tested
/// without touching the filesystem. Advances the "durable" marker ONLY on a successful write
/// and retries a failed one — on a timer while idle, and again at the final flush — so a
/// transient partition outage can't leave the on-disk record stale while the loop believes it
/// is durable (CodeRabbit). `write(v)` returns `true` on a durable write.
async fn run_persist_with<F, Fut>(
    initial: Option<bool>,
    initial_uncertain: bool,
    mut rx: watch::Receiver<Option<bool>>,
    shutdown: oneshot::Receiver<()>,
    mut write: F,
) where
    F: FnMut(Option<bool>) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    // How long to wait before re-attempting a failed write while otherwise idle.
    const RETRY: Duration = Duration::from_secs(5);
    // `written` = the value known to be DURABLE on disk: the value RESTORED from disk, passed
    // in EXPLICITLY. It must NOT be read from the watch channel here — a `command()`/`observe()`
    // can bump the channel before this task is first polled, and capturing that as the baseline
    // would make us skip persisting it, so a reboot would restore the older state (Codex). We
    // deliberately do NOT `borrow_and_update`: leaving any pending value unseen lets the first
    // loop iteration persist it (it differs from this disk baseline).
    let mut written = initial;
    // A prior WRITE did not confirm durability (the spawn_blocking failed, or `atomic_write_in`
    // renamed the new file but its directory fsync failed, possibly leaving an intermediate value).
    // Arm the retry timer and keep rewriting the LATEST value until a write confirms; an
    // unconfirmed write is NEVER mistaken for durable (Codex).
    let mut write_unconfirmed = false;
    // The RESTORED disk value could not be READ (`initial_uncertain`): a valid on/off record may
    // still be on disk. Force the FIRST genuine observation to be written even if it equals the
    // `None` baseline (to overwrite that unread record) — but do NOT arm the retry timer or
    // proactively write the initial `None`, or we would DELETE the record ~RETRY after boot even
    // though nothing was pressed/commanded (CodeRabbit). Cleared once any write confirms.
    let mut baseline_unreadable = initial_uncertain;
    tokio::pin!(shutdown);
    loop {
        let retry = async {
            if write_unconfirmed {
                tokio::time::sleep(RETRY).await;
            } else {
                std::future::pending::<()>().await; // nothing to retry → this arm never fires
            }
        };
        tokio::select! {
            _ = &mut shutdown => break,
            changed = rx.changed() => {
                if changed.is_err() {
                    break; // all senders dropped
                }
            }
            _ = retry => {}
        }
        // Woken by a new value or a retry tick (shutdown / channel-close break out above).
        let v = *rx.borrow_and_update();
        // Write when the latest differs from the last CONFIRMED value, OR a prior write is
        // unconfirmed (the disk may hold an intermediate value even when `v == written`), OR the
        // restored baseline was unreadable and THIS is a genuine observation that must overwrite
        // the unread record. `baseline_unreadable` only forces a write here — where we were woken
        // by an actual change (or a failed-write retry) — never a proactive write of the initial value.
        if v != written || write_unconfirmed || baseline_unreadable {
            if write(v).await {
                written = v;
                write_unconfirmed = false;
                baseline_unreadable = false;
            } else {
                write_unconfirmed = true;
            }
        }
    }
    // Final flush: the process is exiting, so there is no future tick — persist the latest if it
    // isn't known-durable (differs from the confirmed value, or a write is unconfirmed), retrying a
    // few times to ride out a brief outage. NOT forced by `baseline_unreadable` alone: with no
    // observation the unread record must be PRESERVED, not overwritten with the `None` baseline.
    let v = *rx.borrow();
    if v != written || write_unconfirmed {
        for _ in 0..3 {
            if write(v).await {
                break;
            }
        }
    }
}

/// Persist one light state off the runtime thread (blocking fs). Returns `true` on a durable
/// write (a dropped/failed blocking task counts as a failure so it is retried).
async fn write_light(where_: &str, on: Option<bool>) -> bool {
    let w = where_.to_string();
    tokio::task::spawn_blocking(move || crate::persist::store_light(&w, on))
        .await
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(on: Option<bool>) -> State {
        State { on, pending: VecDeque::new(), next_gen: 0 }
    }

    #[test]
    fn needs_toggle_only_when_state_differs() {
        assert!(state(Some(false)).needs_toggle(true));
        assert!(state(Some(true)).needs_toggle(false));
        assert!(!state(Some(true)).needs_toggle(true)); // already on → no-op
        assert!(!state(Some(false)).needs_toggle(false));
        assert!(state(None).needs_toggle(true)); // unknown → actuate (optimistic)
    }

    #[test]
    fn observe_ignores_our_echo_but_applies_a_physical_press() {
        let now = Instant::now();
        // Simulate a successful command: guard armed, state committed to `on`.
        let mut st = state(Some(true));
        st.arm_guard(now);
        // The echo lands within the window → ignored, state unchanged.
        assert_eq!(st.apply_observe(now + Duration::from_millis(10)), None);
        assert_eq!(st.on, Some(true));
        // A later PHYSICAL press (guard already consumed) → flips and reports the new state.
        assert_eq!(st.apply_observe(now + Duration::from_secs(5)), Some(Some(false)));
        assert_eq!(st.on, Some(false));
    }

    #[test]
    fn observe_after_guard_expiry_is_treated_as_physical() {
        let now = Instant::now();
        let mut st = state(Some(false));
        st.arm_guard(now);
        // The echo never arrived; a press AFTER the window is physical → flips.
        assert_eq!(st.apply_observe(now + ECHO_GUARD + Duration::from_millis(1)), Some(Some(true)));
        assert_eq!(st.on, Some(true));
    }

    #[test]
    fn observe_from_unknown_stays_unknown() {
        let mut st = state(None);
        assert_eq!(st.apply_observe(Instant::now()), Some(None));
        assert_eq!(st.on, None);
    }

    #[test]
    fn failed_forward_with_no_observation_leaves_state_and_guard_clean() {
        // command()'s failure path when NOTHING was observed during the forward: nothing
        // toggled, so the cache is unchanged and the command stays retryable.
        let mut st = state(Some(false));
        let gen = st.arm_guard(Instant::now());
        assert_eq!(st.on_forward_failed(gen), None); // its echo still queued → no reclaim
        assert_eq!(st.on, Some(false)); // NOT mutated to the desired state
        assert!(st.pending.is_empty()); // the expected echo was dropped
    }

    #[test]
    fn failed_forward_reclaims_an_absorbed_observation() {
        // A monitor frame lands within the guard window (assumed to be our echo, ignored) —
        // but the forward then FAILS, so that frame was actually a real relay toggle (a
        // concurrent physical press, or our frame that hit the bus before the write error).
        // on_forward_failed reclaims it: the cache flips to match the relay instead of losing
        // the toggle and leaving HA/persist inverted.
        let now = Instant::now();
        let mut st = state(Some(false));
        let gen = st.arm_guard(now);
        assert_eq!(st.apply_observe(now + Duration::from_millis(10)), None); // absorbed our echo
        assert_eq!(st.on_forward_failed(gen), Some(Some(true))); // gen gone → reclaimed → flipped
        assert_eq!(st.on, Some(true));
        assert!(st.pending.is_empty());
    }

    #[test]
    fn two_outstanding_command_echoes_are_each_absorbed() {
        // Rapid ON→OFF issued before the bus echoes the first (Codex): with a single-slot
        // guard the second arm would clobber the first, and OFF's echo would be counted as a
        // physical press. With the per-command QUEUE, both echoes are absorbed and the cache
        // matches the relay (on then off = off).
        let now = Instant::now();
        let mut st = state(Some(false));
        st.arm_guard(now); // ON
        st.commit_actuation(true); // → on
        st.arm_guard(now); // OFF (before ON's echo arrived)
        st.commit_actuation(false); // → off
        assert_eq!(st.pending.len(), 2);
        // Both echoes now arrive — each absorbed, neither treated as a physical press.
        assert_eq!(st.apply_observe(now + Duration::from_millis(10)), None);
        assert_eq!(st.apply_observe(now + Duration::from_millis(11)), None);
        assert!(st.pending.is_empty());
        assert_eq!(st.on, Some(false)); // matches the relay
    }

    #[test]
    fn failed_command_does_not_reclaim_an_earlier_commands_echo() {
        // Command A succeeds (echo still outstanding); command B arms; A's DELAYED echo is
        // absorbed during B's forward; then B FAILS. B must NOT reclaim A's echo — it belongs
        // to A (already committed). Keyed by generation: A's echo consumes A's (older) slot, so
        // B's slot is still queued and B's failure is a clean no-op (Codex / CodeRabbit / Copilot).
        let now = Instant::now();
        let mut st = state(Some(false));
        st.arm_guard(now); // A
        st.commit_actuation(true); // A → on
        let gen_b = st.arm_guard(now); // B
        assert_eq!(st.apply_observe(now + Duration::from_millis(10)), None); // absorbs A's echo
        assert_eq!(st.on_forward_failed(gen_b), None); // B's own echo still queued → no flip
        assert_eq!(st.on, Some(true)); // A's commit stands; B didn't invert it
    }

    #[test]
    fn a_new_arm_does_not_extend_an_older_echos_window() {
        // Per-echo deadlines (Codex): A's echo is lost; B arms near the end of A's window. A
        // physical press AFTER A's own 3 s window (but before B's later deadline) must NOT be
        // absorbed against A's stale slot — it's physical and flips.
        let now = Instant::now();
        let mut st = state(Some(false));
        st.arm_guard(now); // A at t0, deadline t0 + ECHO_GUARD
        st.commit_actuation(true); // → on
        // B arms late in A's window; B carries its OWN (later) deadline.
        let t_b = now + ECHO_GUARD - Duration::from_millis(100);
        st.arm_guard(t_b); // B, deadline t_b + ECHO_GUARD
        // A's echo never came. A press just after A's window expires: A's slot is dropped as
        // stale, B's is still live and absorbs this... so use TWO presses — the first absorbs
        // B's live echo, the second (still after A's window) is unambiguously physical.
        let t_press = now + ECHO_GUARD + Duration::from_millis(1);
        assert_eq!(st.apply_observe(t_press), None); // A stale-dropped, B's live slot absorbs one
        assert_eq!(st.apply_observe(t_press), Some(Some(false))); // now physical → flips
        assert_eq!(st.on, Some(false));
    }

    #[test]
    fn echo_guard_outlasts_the_forward_timeout() {
        // A successful-but-late echo (up to FORWARD_TIMEOUT plus latency) must still fall inside
        // the guard window, or apply_observe would count it as a physical press on top of the
        // commit and invert the cache (Codex).
        assert!(ECHO_GUARD > FORWARD_TIMEOUT);
    }

    #[test]
    fn commit_actuation_flips_a_known_state() {
        // The common case: a successful forward from a known state that DIFFERED reaches
        // desired_on by flipping once.
        let mut st = state(Some(false));
        assert_eq!(st.commit_actuation(true), Some(true));
        assert_eq!(st.on, Some(true));
    }

    #[test]
    fn commit_actuation_establishes_from_unknown() {
        // First cold boot: unknown can't be flipped, so it's optimistically set to desired.
        let mut st = state(None);
        assert_eq!(st.commit_actuation(true), Some(true));
        assert_eq!(st.on, Some(true));
    }

    #[test]
    fn commit_actuation_composes_with_a_concurrent_physical_press() {
        // The race Codex flagged: cache=off, HA commands ON. Our echo consumed the guard,
        // then a PHYSICAL press was observed while forward_to_gateway() was still awaiting —
        // observe() flipped the cache to on. The relay has now taken TWO toggles (ours +
        // the physical one) and is back OFF. A flip-commit composes correctly (on → off),
        // matching the relay; an absolute set(on) would have clobbered it and lied `on`.
        let now = Instant::now();
        let mut st = state(Some(false));
        st.arm_guard(now); // command() armed before forwarding
        assert_eq!(st.apply_observe(now + Duration::from_millis(10)), None); // our echo, guarded
        assert_eq!(st.apply_observe(now + Duration::from_millis(20)), Some(Some(true))); // physical
        assert_eq!(st.on, Some(true));
        // command()'s success commit runs LAST, flipping — not clobbering — the observation.
        assert_eq!(st.commit_actuation(true), Some(false));
        assert_eq!(st.on, Some(false)); // equals the relay after two toggles
    }

    #[test]
    fn resync_cycles_unknown_on_off_on() {
        // The resync button corrects the TRACKED state only: unknown → on → off → on, so the
        // user can realign HA to the wall in at most a couple of presses.
        let mut st = state(None);
        assert_eq!(st.resync(), Some(true)); // unknown → on
        assert_eq!(st.resync(), Some(false)); // on → off
        assert_eq!(st.resync(), Some(true)); // off → on
        // resync never queues an echo expectation (no frame is sent).
        assert!(st.pending.is_empty());
    }

    #[test]
    fn parse_light_where_accepts_only_digit_press_frames() {
        assert_eq!(parse_light_where("*8*21*112##"), Some("112"));
        assert_eq!(parse_light_where("*8*21*1##"), Some("1"));
        assert_eq!(parse_light_where("*8*21*##"), None); // empty WHERE
        assert_eq!(parse_light_where("*8*22*112##"), None); // release, not press
        assert_eq!(parse_light_where("*8*21*11a##"), None); // non-digit
        assert_eq!(parse_light_where("*1*1*21##"), None); // unrelated frame
    }

    #[tokio::test]
    async fn persist_worker_retries_a_failed_write_and_never_marks_it_durable() {
        use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
        // A writer that ALWAYS fails (simulated partition outage), counting attempts.
        let attempts = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = watch::channel::<Option<bool>>(None);
        let (sd_tx, sd_rx) = oneshot::channel();
        let a = attempts.clone();
        // Enqueue a toggled state BEFORE the worker is spawned: with the disk baseline passed
        // explicitly (None), the worker must still persist this pre-existing value rather than
        // mistaking it for the restored baseline (the race Codex flagged).
        tx.send(Some(true)).unwrap();
        let worker = tokio::spawn(run_persist_with(None, false, rx, sd_rx, move |_on| {
            let a = a.clone();
            async move {
                a.fetch_add(1, Relaxed);
                false // never durable
            }
        }));
        tokio::time::sleep(Duration::from_millis(20)).await; // let the worker attempt once
        // Shut down BEFORE the 5 s retry timer: the final flush must RE-attempt the still
        // unwritten value (it was never marked durable), proving a failed write isn't mistaken
        // for persisted — a reboot would otherwise restore a stale state.
        let _ = sd_tx.send(());
        let _ = worker.await;
        assert!(
            attempts.load(Relaxed) >= 2,
            "a failed write must be retried (loop + shutdown-flush), got {}",
            attempts.load(Relaxed)
        );
    }

    #[tokio::test]
    async fn unreadable_baseline_preserves_the_record_until_an_observation() {
        use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
        // An unreadable restore (`initial_uncertain = true`, baseline `None`): a valid on/off
        // record may still be on disk. With NO press/command, the worker must NOT write — writing
        // the `None` baseline would DELETE that record (CodeRabbit). The FIRST genuine observation
        // IS written, to overwrite the unread record.
        let writes = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = watch::channel::<Option<bool>>(None);
        let (sd_tx, sd_rx) = oneshot::channel();
        let w = writes.clone();
        let worker = tokio::spawn(run_persist_with(None, true, rx, sd_rx, move |_on| {
            let w = w.clone();
            async move {
                w.fetch_add(1, Relaxed);
                true
            }
        }));
        // No observation yet (well under the 5 s retry timer, which must NOT be armed here).
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            writes.load(Relaxed),
            0,
            "an unreadable baseline must not write (delete) the record before any observation"
        );
        // A genuine observation must be written, overwriting the unread record.
        tx.send(Some(true)).unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let _ = sd_tx.send(());
        let _ = worker.await;
        assert!(
            writes.load(Relaxed) >= 1,
            "the first observation must be written to overwrite the unread record, got {}",
            writes.load(Relaxed)
        );
    }
}
