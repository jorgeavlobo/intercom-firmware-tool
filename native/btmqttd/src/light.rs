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
//! absolute state differs from the cache, and — crucially — commits the new state ONLY
//! after the frame is successfully forwarded, so a failed actuation stays retryable and
//! never shows HA a state the relay didn't reach. An echo guard, armed BEFORE forwarding,
//! stops our own toggle's monitor echo from double-flipping the cache.
//!
//! Residual imperfection (inherent to a stateless toggle): on the very FIRST cold boot the
//! cache is unknown, so the first command is optimistic; and a toggle made while the daemon
//! is DOWN is missed. Persistence removes the common reboot case; the rest is documented.

use std::sync::Arc;
use std::time::Duration;

use rumqttc::{AsyncClient, QoS};
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::config::Config;
use crate::receiver::forward_to_gateway;

/// Per-frame forward timeout for the toggle (loopback gateway; tight like the lock pulse).
const FORWARD_TIMEOUT: Duration = Duration::from_secs(2);

/// After WE inject a toggle, the gateway may echo the same `*8*21*<w>##` back on the
/// monitor. Ignore an observed press within this window so our own toggle isn't counted a
/// second time. Loopback echo is near-instant; a small window is ample and can't swallow a
/// genuine follow-up physical press (a human can't re-press within 1.5 s of an app toggle).
const ECHO_GUARD: Duration = Duration::from_millis(1500);

/// The tracked light state + echo guard. Its methods are PURE (no I/O), so the tracking
/// logic is unit-tested without a gateway or broker; [`LightCtl`] does the MQTT/forward I/O
/// around them.
struct State {
    /// Cached light state: `None` = unknown (first cold boot, no persisted value).
    on: Option<bool>,
    /// Set when WE just injected a toggle, so its monitor echo is ignored once.
    expect_echo_until: Option<Instant>,
}

impl State {
    /// Whether a command to reach `desired` must forward a toggle (the cache differs).
    fn needs_toggle(&self, desired: bool) -> bool {
        self.on != Some(desired)
    }

    /// Arm the echo guard — called BEFORE forwarding, so the echo (which can land as soon
    /// as the frame reaches the bus) is always covered.
    fn arm_guard(&mut self, now: Instant) {
        self.expect_echo_until = Some(now + ECHO_GUARD);
    }

    /// Disarm the guard — called when the forward FAILED, so a stale guard can't later
    /// swallow a genuine physical press.
    fn disarm_guard(&mut self) {
        self.expect_echo_until = None;
    }

    /// Commit the desired state after a SUCCESSFUL forward.
    fn set(&mut self, on: bool) {
        self.on = Some(on);
    }

    /// Apply an observed `*8*21*<WHERE>##` press. Returns `Some(new_state)` to publish +
    /// persist (a PHYSICAL toggle), or `None` to ignore it (our own toggle's echo, still
    /// within the guard). `now` is checked against the guard.
    fn apply_observe(&mut self, now: Instant) -> Option<Option<bool>> {
        if let Some(until) = self.expect_echo_until.take() {
            if now < until {
                return None; // our own toggle's echo — already accounted for
            }
            // else: a stale guard (echo never arrived) — fall through, this is physical.
        }
        self.on = self.on.map(|b| !b); // physical toggle; unknown stays unknown
        Some(self.on)
    }
}

/// Owns the stair-light toggle state. Shared (`Arc`) between the command worker
/// ([`command`]) and the monitor task ([`observe`]).
pub struct LightCtl {
    st: Mutex<State>,
    /// The configured actuator WHERE — persistence is keyed by it so a later WHERE change
    /// can't restore an unrelated relay's state.
    where_: String,
    /// The exact `*8*21*<WHERE>##` frame — sent to toggle AND matched on the monitor to
    /// detect a physical press. Built once from the configured WHERE.
    press_frame: String,
    /// Retained state topic HA reads back (`on`/`off`).
    topic_light: String,
    client: AsyncClient,
}

impl LightCtl {
    /// Build from config, restoring the persisted on/off (`initial`) so the switch keeps
    /// the right state across a reboot. `cfg.light_where` MUST be set (the caller only
    /// constructs this when the feature is enabled).
    pub fn new(cfg: &Arc<Config>, client: AsyncClient, initial: Option<bool>) -> Arc<Self> {
        let where_ = cfg.light_where.clone().unwrap_or_default();
        Arc::new(LightCtl {
            st: Mutex::new(State { on: initial, expect_echo_until: None }),
            press_frame: format!("*8*21*{where_}##"),
            where_,
            topic_light: cfg.topic_light.clone(),
            client,
        })
    }

    /// Publish the cached state, RETAINED, so HA reflects it. `on`/`off`; an unknown
    /// (`None`) state publishes nothing, leaving HA to show the switch unavailable until the
    /// first command or observed toggle establishes it.
    async fn publish(&self, on: Option<bool>) {
        let payload = match on {
            Some(true) => "on",
            Some(false) => "off",
            None => return,
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
    /// topics, so re-send the known state (no-op while still unknown).
    pub async fn seed(&self) {
        let on = self.st.lock().await.on;
        self.publish(on).await;
    }

    /// HA commanded a desired ABSOLUTE state (`on`/`off`). Toggle the relay ONLY when it
    /// differs from the cache — and commit the new state ONLY after the forward SUCCEEDS, so
    /// a failed actuation leaves the cache (and HA) unchanged and the command retryable. The
    /// echo guard is armed before forwarding and disarmed on failure.
    pub async fn command(&self, desired_on: bool) {
        {
            let mut st = self.st.lock().await;
            if !st.needs_toggle(desired_on) {
                return; // already in the desired state — nothing to actuate
            }
            st.arm_guard(Instant::now()); // before forwarding: the echo may land immediately
        }
        if let Err(e) = forward_to_gateway(&self.press_frame, FORWARD_TIMEOUT).await {
            eprintln!("btmqttd: light toggle failed: {e}");
            // Actuation FAILED: don't publish/persist a state the relay never reached, and
            // clear the guard so it can't swallow a later genuine physical press. The command
            // stays retryable (the cache is unchanged).
            self.st.lock().await.disarm_guard();
            return;
        }
        self.st.lock().await.set(desired_on);
        self.publish(Some(desired_on)).await;
        persist(self.where_.clone(), Some(desired_on)).await;
    }

    /// Feed a monitor frame. When it is our WHERE's press (`*8*21*<WHERE>##`): if it is our
    /// own injected toggle's echo (within the guard) ignore it; otherwise it is a PHYSICAL
    /// panel press → flip the cache, republish + persist. Any other frame is ignored, so the
    /// caller can hand every monitor frame here cheaply.
    pub async fn observe(&self, frame: &str) {
        if frame != self.press_frame {
            return;
        }
        let flipped = self.st.lock().await.apply_observe(Instant::now());
        if let Some(new_state) = flipped {
            self.publish(new_state).await;
            persist(self.where_.clone(), new_state).await;
        }
    }
}

/// Persist the tracked state (keyed by WHERE) off the async runtime (blocking fs).
/// Best-effort: a failed write just means a reboot may restore a slightly older state,
/// which the next toggle corrects.
async fn persist(where_: String, on: Option<bool>) {
    let _ = tokio::task::spawn_blocking(move || crate::persist::store_light(&where_, on)).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(on: Option<bool>) -> State {
        State { on, expect_echo_until: None }
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
    fn failed_forward_leaves_state_and_guard_clean() {
        // Mirrors command()'s failure path on the pure State: arm the guard, then (forward
        // failed) disarm it WITHOUT set() — the cache is unchanged, so the command retries.
        let mut st = state(Some(false));
        st.arm_guard(Instant::now());
        st.disarm_guard();
        assert_eq!(st.on, Some(false)); // NOT mutated to the desired state
        assert!(st.expect_echo_until.is_none()); // no stale guard to swallow a real press
    }
}
