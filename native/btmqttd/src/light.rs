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
//! DOWN is missed; and — irreducibly — if SIGTERM lands DURING the forward itself (the frame
//! reached the bus but the `.await` hasn't returned) that single toggle can be lost.
//! Persistence + the drained task remove the common cases; the rest is documented.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rumqttc::{AsyncClient, QoS};
use tokio::sync::{oneshot, watch, Mutex as AsyncMutex};
use tokio::time::Instant;

use crate::config::Config;
use crate::receiver::forward_to_gateway;

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
    /// How many of OUR injected toggles are still awaiting their monitor echo. Each armed
    /// command adds one; each frame observed within the window consumes one (absorbed as our
    /// echo) instead of being counted as a physical press. A COUNT — not a single flag — so
    /// several commands issued faster than the bus echoes them each get their echo absorbed,
    /// instead of a later command's arm clobbering an earlier one's guard and the stray echo
    /// double-flipping the cache (Codex).
    pending_echoes: u32,
    /// Deadline by which the outstanding echoes should have arrived. Once it passes, they are
    /// treated as lost (the count is reset) so a genuine later physical press isn't absorbed
    /// as one of ours. Extended on every [`arm_guard`].
    echo_deadline: Option<Instant>,
    /// Whether an echo was absorbed since the last [`arm_guard`]. Used ONLY by the failure
    /// path: if the forward FAILED but a frame was absorbed in its window, that frame was a
    /// real relay toggle (our frame reached the bus before the error, or a concurrent physical
    /// press) to reclaim.
    absorbed_since_arm: bool,
}

impl State {
    /// Whether a command to reach `desired` must forward a toggle (the cache differs).
    fn needs_toggle(&self, desired: bool) -> bool {
        self.on != Some(desired)
    }

    /// Arm the echo guard — called BEFORE forwarding, so the echo (which can land as soon as
    /// the frame reaches the bus) is always covered. Expects ONE more echo and (re)extends the
    /// window; clears the absorb flag so the reclaim only applies to THIS command's window.
    fn arm_guard(&mut self, now: Instant) {
        self.pending_echoes = self.pending_echoes.saturating_add(1);
        self.echo_deadline = Some(now + ECHO_GUARD);
        self.absorbed_since_arm = false;
    }

    /// Called when the forward FAILED. If a frame was ABSORBED since we armed, it was NOT a
    /// spurious echo — our injection didn't land — but a real relay toggle (a concurrent
    /// physical press, or our frame that reached the bus before the write error); reclaim it by
    /// flipping the cache and returning `Some(new_state)` to publish + persist (the echo
    /// accounting was already decremented when it was absorbed). Otherwise nothing toggled:
    /// undo the echo this command expected and return `None`, leaving the cache unchanged
    /// (retryable).
    fn on_forward_failed(&mut self) -> Option<Option<bool>> {
        if std::mem::take(&mut self.absorbed_since_arm) {
            self.on = self.on.map(|b| !b); // reclaim the observed toggle; unknown stays unknown
            Some(self.on)
        } else {
            self.pending_echoes = self.pending_echoes.saturating_sub(1);
            if self.pending_echoes == 0 {
                self.echo_deadline = None;
            }
            None
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
        // Expire outstanding echoes that never arrived, so a genuine later physical press isn't
        // absorbed as one of ours.
        if let Some(dl) = self.echo_deadline {
            if now >= dl {
                self.pending_echoes = 0;
                self.echo_deadline = None;
            }
        }
        if self.pending_echoes > 0 {
            // Absorb one outstanding echo — already accounted for by its command's commit.
            self.pending_echoes -= 1;
            if self.pending_echoes == 0 {
                self.echo_deadline = None;
            }
            self.absorbed_since_arm = true;
            return None;
        }
        self.on = self.on.map(|b| !b); // physical toggle; unknown stays unknown
        Some(self.on)
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
    /// The exact `*8*21*<WHERE>##` frame — sent to toggle AND matched on the monitor to
    /// detect a physical press. Built once from the configured WHERE. (Persistence is keyed
    /// by WHERE inside [`run_persist`], which owns its own copy.)
    press_frame: String,
    /// Retained state topic HA reads back (`on`/`off`).
    topic_light: String,
    client: AsyncClient,
}

impl LightCtl {
    /// Build from config, restoring the persisted on/off (`initial`) so the switch keeps
    /// the right state across a reboot. `cfg.light_where` MUST be set (the caller only
    /// constructs this when the feature is enabled). Returns the controller AND the `watch`
    /// receiver the caller must hand to [`run_persist`] (spawned as the drained persist task).
    pub fn new(
        cfg: &Arc<Config>,
        client: AsyncClient,
        initial: Option<bool>,
    ) -> (Arc<Self>, watch::Receiver<Option<bool>>) {
        let where_ = cfg.light_where.clone().unwrap_or_default();
        let (persist_tx, persist_rx) = watch::channel(initial);
        let ctl = Arc::new(LightCtl {
            st: Mutex::new(State {
                on: initial,
                pending_echoes: 0,
                echo_deadline: None,
                absorbed_since_arm: false,
            }),
            io_lock: AsyncMutex::new(()),
            persist_tx,
            press_frame: format!("*8*21*{where_}##"),
            topic_light: cfg.topic_light.clone(),
            client,
        });
        (ctl, persist_rx)
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
        if let Err(e) = self
            .client
            .publish(&self.topic_light, QoS::AtLeastOnce, true, payload)
            .await
        {
            eprintln!("btmqttd: publish light state failed: {e}");
        }
    }

    /// On-connect (re)publish of the retained state — a restarted broker dropped retained
    /// topics, so re-send the known state (or, while unknown, an empty retained payload that
    /// clears any stale value the broker still holds — e.g. from a previous `LIGHT_WHERE`).
    pub async fn seed(&self) {
        self.publish_current().await;
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
        {
            let mut st = self.st.lock().expect("light state mutex poisoned");
            if !st.needs_toggle(desired_on) {
                return; // already in the desired state — nothing to actuate
            }
            st.arm_guard(Instant::now()); // before forwarding: the echo may land immediately
        }
        if let Err(e) = forward_to_gateway(&self.press_frame, FORWARD_TIMEOUT).await {
            eprintln!("btmqttd: light toggle failed: {e}");
            // Actuation FAILED. Disarm the guard so it can't later swallow a genuine physical
            // press. If a frame was ABSORBED by the guard during this (failed) forward, it
            // wasn't our echo — it was a real relay toggle — so reclaim it (flip + persist +
            // publish). Otherwise nothing toggled: leave the cache unchanged (retryable).
            let reclaimed = self
                .st
                .lock()
                .expect("light state mutex poisoned")
                .on_forward_failed();
            if reclaimed.is_some() {
                self.enqueue_persist();
                self.publish_current().await;
            }
            return;
        }
        // Post-forward: commit the toggle and ENQUEUE persistence with NO `.await` in between
        // (the state mutex is sync), so even if SIGTERM fires the instant the forward returns,
        // the new state is already on the persist channel and the drained task will write it.
        self.st
            .lock()
            .expect("light state mutex poisoned")
            .commit_actuation(desired_on);
        self.enqueue_persist();
        // Retained publish is best-effort and comes after (network I/O is the first yield).
        self.publish_current().await;
    }

    /// Feed a monitor frame. When it is our WHERE's press (`*8*21*<WHERE>##`): if it is our
    /// own injected toggle's echo (within the guard) ignore it; otherwise it is a PHYSICAL
    /// panel press → flip the cache, enqueue persistence + republish. Any other frame is
    /// ignored, so the caller can hand every monitor frame here cheaply.
    pub async fn observe(&self, frame: &str) {
        if frame != self.press_frame {
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
}

/// Dedicated stair-light persistence task. `command()`/`observe()` enqueue the latest state
/// via `persist_tx` (a synchronous `watch` send, so it can't be lost to a task abort); this
/// task writes it to the reboot-persistent record off the runtime thread. It is DRAINED at
/// shutdown: `main` signals `shutdown` AFTER aborting the command/monitor tasks (so no
/// further state can be produced) and then awaits this task, whose final flush persists any
/// state queued in the last instant — so a toggle actuated moments before SIGTERM is durable
/// rather than lost with the aborted worker (Codex). Redundant writes are skipped.
pub async fn run_persist(
    where_: String,
    initial: Option<bool>,
    rx: watch::Receiver<Option<bool>>,
    shutdown: oneshot::Receiver<()>,
) {
    run_persist_with(initial, rx, shutdown, move |on| {
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
    // Set when the latest write FAILED, so we keep retrying until it lands or a newer value
    // supersedes it — a failed write is NEVER mistaken for durable.
    let mut retry_pending = false;
    tokio::pin!(shutdown);
    loop {
        let retry = async {
            if retry_pending {
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
        if v != written {
            if write(v).await {
                written = v;
                retry_pending = false;
            } else {
                retry_pending = true;
            }
        } else {
            retry_pending = false;
        }
    }
    // Final flush: the process is exiting, so there is no future tick — persist the latest if
    // it isn't known-durable, retrying a few times to ride out a brief outage.
    let v = *rx.borrow();
    if v != written {
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
        State { on, pending_echoes: 0, echo_deadline: None, absorbed_since_arm: false }
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
        st.arm_guard(Instant::now());
        assert_eq!(st.on_forward_failed(), None); // no absorbed frame → no reclaim
        assert_eq!(st.on, Some(false)); // NOT mutated to the desired state
        assert_eq!(st.pending_echoes, 0); // the expected echo was undone
        assert!(st.echo_deadline.is_none()); // no stale window to swallow a real press
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
        st.arm_guard(now);
        assert_eq!(st.apply_observe(now + Duration::from_millis(10)), None); // absorbed
        assert_eq!(st.on_forward_failed(), Some(Some(true))); // reclaimed → flipped
        assert_eq!(st.on, Some(true));
        assert_eq!(st.pending_echoes, 0); // the absorbed frame already cleared the expectation
        assert!(!st.absorbed_since_arm);
    }

    #[test]
    fn two_outstanding_command_echoes_are_each_absorbed() {
        // Rapid ON→OFF issued before the bus echoes the first (Codex): with a single-slot
        // guard the second arm would clobber the first, and OFF's echo would be counted as a
        // physical press. With the echo COUNT, both echoes are absorbed and the cache matches
        // the relay (on then off = off).
        let now = Instant::now();
        let mut st = state(Some(false));
        st.arm_guard(now); // ON
        st.commit_actuation(true); // → on
        st.arm_guard(now); // OFF (before ON's echo arrived)
        st.commit_actuation(false); // → off
        assert_eq!(st.pending_echoes, 2);
        // Both echoes now arrive — each absorbed, neither treated as a physical press.
        assert_eq!(st.apply_observe(now + Duration::from_millis(10)), None);
        assert_eq!(st.apply_observe(now + Duration::from_millis(11)), None);
        assert_eq!(st.pending_echoes, 0);
        assert_eq!(st.on, Some(false)); // matches the relay
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
        let worker = tokio::spawn(run_persist_with(None, rx, sd_rx, move |_on| {
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
}
