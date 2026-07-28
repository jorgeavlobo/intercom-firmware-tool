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
//! PERSISTED across reboots (the actuator can't be re-queried, so persistence is what keeps
//! the switch correct through a restart). A command toggles only when the desired absolute
//! state differs from the cache; an echo guard stops our own injected toggle from
//! double-flipping when the gateway mirrors it back on the monitor.
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

struct State {
    /// Cached light state: `None` = unknown (first cold boot, no persisted value).
    on: Option<bool>,
    /// Set when WE just injected a toggle, so its monitor echo is ignored once.
    expect_echo_until: Option<Instant>,
}

/// Owns the stair-light toggle state. Shared (`Arc`) between the command worker
/// ([`command`]) and the monitor task ([`observe`]).
pub struct LightCtl {
    st: Mutex<State>,
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
    /// differs from the cache, then update + republish + persist. From an unknown cache the
    /// command is taken as correct (optimistic — the sole first-cold-boot inversion window;
    /// persistence prevents it across reboots).
    pub async fn command(&self, desired_on: bool) {
        let need_toggle = {
            let mut st = self.st.lock().await;
            let need = st.on != Some(desired_on);
            if need {
                st.on = Some(desired_on);
                st.expect_echo_until = Some(Instant::now() + ECHO_GUARD);
            }
            need
        };
        if !need_toggle {
            return; // already in the desired state — nothing to actuate
        }
        if let Err(e) = forward_to_gateway(&self.press_frame, FORWARD_TIMEOUT).await {
            eprintln!("btmqttd: light toggle failed: {e}");
        }
        self.publish(Some(desired_on)).await;
        persist(Some(desired_on)).await;
    }

    /// Feed a monitor frame. When it is our WHERE's press (`*8*21*<WHERE>##`): if it is our
    /// own injected toggle's echo (within the guard) consume the guard and ignore it;
    /// otherwise it is a PHYSICAL panel press → flip the cache, republish + persist. Any
    /// other frame is ignored, so the caller can hand every monitor frame here cheaply.
    pub async fn observe(&self, frame: &str) {
        if frame != self.press_frame {
            return;
        }
        let flipped = {
            let mut st = self.st.lock().await;
            if let Some(until) = st.expect_echo_until.take() {
                if Instant::now() < until {
                    return; // our own toggle's echo — already accounted for
                }
                // else: a stale guard (echo never arrived) — fall through, this is physical.
            }
            st.on = st.on.map(|b| !b); // physical toggle; unknown stays unknown
            st.on
        };
        self.publish(flipped).await;
        persist(flipped).await;
    }
}

/// Persist the tracked state off the async runtime (blocking fs). Best-effort: a failed
/// write just means a reboot may restore a slightly older state, which the next toggle
/// corrects.
async fn persist(on: Option<bool>) {
    let _ = tokio::task::spawn_blocking(move || crate::persist::store_light(on)).await;
}
