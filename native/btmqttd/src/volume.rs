//! Device-side volume state machine (issue #40) + gate pulse (issue #41).
//!
//! All volume STATE and logic live here — Home Assistant stays "dumb": it renders
//! four auto-discovered entities (slider `number`, `mute` switch, up/down `button`s)
//! whose commands arrive as small JSON actions on the existing command topic
//! (`TOPIC_RX`), and whose state is read back from two retained topics this module
//! publishes (`Bticino/volume`, `Bticino/mute`). No HA templating over the raw bus,
//! no automations — correct even across an HA restart or a change made on the unit.
//!
//! ## Single source of truth: the monitor
//! The device broadcasts `*#8**41*<N>##` on the monitor whenever the volume changes,
//! by ANY path (slider, up/down, mute, or the unit's own menu). [`observe`] consumes
//! those broadcasts (via the `sender` monitor hook) and an on-connect on-demand read
//! ([`seed`]) — that is the ONLY writer of `current`/`last_nonzero` and the retained
//! state topics. The command methods ([`set`]/[`mute`]/[`step`]) only WRITE to the
//! device; state then flows back through the monitor. This keeps HA and the derived
//! `muted` flag correct however the volume reaches 0.
//!
//! ## Smart mute (owned here, not HA)
//! `last_nonzero` tracks the last observed volume > 0, so UNMUTE restores the EXACT
//! pre-mute level — a static discovery `switch` could only restore a fixed level.
//! `muted` is derived as `current == 0`.

use std::sync::Arc;

use rumqttc::{AsyncClient, QoS};
use tokio::sync::Mutex;

use crate::config::Config;
use crate::dimension;

/// The step (percent) the up/down buttons move, and the discovery slider's step.
const STEP: u8 = 10;

/// The volume to restore on unmute if a non-zero level was NEVER observed (fresh
/// boot, muted before any change) — a sane audible default rather than staying at 0.
const DEFAULT_NONZERO: u8 = 50;

/// Learned volume state. `current` is `None` until the first observation (monitor
/// broadcast or on-connect read); `last_nonzero` seeds the unmute restore level.
struct State {
    current: Option<u8>,
    last_nonzero: u8,
}

/// Owns the volume state machine and the OWN command-session endpoint used to write
/// the dimension. Shared (`Arc`) between the command worker (which calls the command
/// methods) and the monitor task (which calls [`observe`]).
pub struct VolumeCtl {
    st: Mutex<State>,
    /// OWN gateway for DIMENSION read/write — the openserver main gateway
    /// (`own_host:own_port_mon`, default `127.0.0.1:20000`), NOT the `:30006` command
    /// port `receiver` uses for actions (which does not handle dimensions).
    host: String,
    port: u16,
    /// Retained state topics HA reads back.
    topic_volume: String,
    topic_mute: String,
    client: AsyncClient,
}

impl VolumeCtl {
    /// Build the controller from config. `last_nonzero` starts at [`DEFAULT_NONZERO`]
    /// so an unmute before any observation still restores an audible level.
    pub fn new(cfg: &Arc<Config>, client: AsyncClient) -> Arc<Self> {
        Arc::new(VolumeCtl {
            st: Mutex::new(State { current: None, last_nonzero: DEFAULT_NONZERO }),
            host: cfg.own_host.clone(),
            port: cfg.own_port_mon,
            topic_volume: cfg.topic_volume.clone(),
            topic_mute: cfg.topic_mute.clone(),
            client,
        })
    }

    /// Learn an AUTHORITATIVE volume (a monitor broadcast or an on-demand read):
    /// update `current`, refresh `last_nonzero` when it's > 0, and republish the
    /// retained `volume` + derived `mute` state. The single place state is written,
    /// so HA and `muted` stay correct however the volume reached this value.
    pub async fn observe(&self, pct: u8) {
        let pct = pct.min(100);
        {
            let mut st = self.st.lock().await;
            st.current = Some(pct);
            if pct > 0 {
                st.last_nonzero = pct;
            }
        }
        self.publish_state(pct).await;
    }

    /// On-connect seed: read the current volume once via the command session so HA
    /// shows a value before the first change. Best-effort — a refused or unavailable
    /// gateway just leaves `current` unknown until the first monitor broadcast.
    pub async fn seed(&self) {
        match dimension::read_volume(&self.host, self.port).await {
            Ok(Some(pct)) => self.observe(pct).await,
            Ok(None) => {} // no valid report — leave unknown, monitor will fill it in
            Err(e) => eprintln!("btmqttd: volume seed read failed: {e}"),
        }
    }

    /// Publish the retained `volume` (0..=100) and derived `mute` (`on`/`off`) state.
    async fn publish_state(&self, pct: u8) {
        let muted = if pct == 0 { "on" } else { "off" };
        self.publish_retained(&self.topic_volume, pct.to_string().into_bytes()).await;
        self.publish_retained(&self.topic_mute, muted.as_bytes().to_vec()).await;
    }

    async fn publish_retained(&self, topic: &str, payload: Vec<u8>) {
        if let Err(e) = self.client.publish(topic, QoS::AtMostOnce, true, payload).await {
            eprintln!("btmqttd: publish volume state to {topic} failed: {e}");
        }
    }

    /// Set the volume to `pct` (clamped 0..=100). Writes the dimension to the device;
    /// state is refreshed by the resulting monitor broadcast (see [`observe`]), so we
    /// do NOT optimistically mutate state here — the bus stays the source of truth.
    pub async fn set(&self, pct: u8) -> std::io::Result<()> {
        dimension::write_volume(&self.host, self.port, pct.min(100)).await
    }

    /// Mute (`on`) or unmute (`off`). Mute writes 0; unmute restores `last_nonzero`
    /// (the exact pre-mute level, or [`DEFAULT_NONZERO`] if none was ever observed).
    /// `last_nonzero` is maintained by [`observe`], so at mute time it already equals
    /// the current audible level.
    pub async fn mute(&self, on: bool) -> std::io::Result<()> {
        let target = if on { 0 } else { self.st.lock().await.last_nonzero };
        self.set(target).await
    }

    /// Step the volume by `delta` (the buttons pass +[`STEP`] / -[`STEP`]), clamped to
    /// 0..=100. Uses the last known `current`; if it's still unknown, reads it on
    /// demand first so the very first press steps from the real level, not a guess.
    pub async fn step(&self, up: bool) -> std::io::Result<()> {
        // Never observed and the read gives nothing either: step from a 0 base, so
        // up -> STEP and down -> 0 (both clamp correctly).
        let base = match self.st.lock().await.current {
            Some(c) => c,
            None => dimension::read_volume(&self.host, self.port).await?.unwrap_or(0),
        };
        let next = if up {
            base.saturating_add(STEP).min(100)
        } else {
            base.saturating_sub(STEP)
        };
        self.set(next).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The state-transition math the acceptance criteria pin down, exercised on the
    // pure `State` logic without a live gateway/broker (the network write is a thin
    // wrapper over dimension::write_volume, covered by dimension.rs's frame tests).

    /// Mirror of observe()'s state update, in isolation.
    fn observe(st: &mut State, pct: u8) {
        st.current = Some(pct);
        if pct > 0 {
            st.last_nonzero = pct;
        }
    }

    #[test]
    fn unmute_restores_the_exact_pre_mute_level_from_the_slider() {
        // slider 50% -> 0% ⇒ muted; unmute ⇒ 50%.
        let mut st = State { current: None, last_nonzero: DEFAULT_NONZERO };
        observe(&mut st, 50); // HA showed 50
        assert_eq!(st.last_nonzero, 50);
        observe(&mut st, 0); // slider driven to 0
        assert_eq!(st.current, Some(0));
        assert_eq!(st.last_nonzero, 50); // preserved across the zero
    }

    #[test]
    fn unmute_restores_the_level_right_before_it_hit_zero_via_down_button() {
        // down 10% -> 0% ⇒ muted; unmute ⇒ 10%.
        let mut st = State { current: None, last_nonzero: DEFAULT_NONZERO };
        observe(&mut st, 20);
        observe(&mut st, 10);
        observe(&mut st, 0);
        assert_eq!(st.last_nonzero, 10);
    }

    #[test]
    fn muted_is_derived_from_current_reaching_zero_by_any_path() {
        let mut st = State { current: None, last_nonzero: DEFAULT_NONZERO };
        observe(&mut st, 30);
        assert!(st.current != Some(0)); // not muted
        observe(&mut st, 0);
        assert_eq!(st.current, Some(0)); // muted, however it got here
    }

    #[test]
    fn default_nonzero_used_when_no_level_was_ever_observed() {
        // Muted from boot with no prior observation: unmute falls back to the default.
        let st = State { current: None, last_nonzero: DEFAULT_NONZERO };
        assert_eq!(st.last_nonzero, 50);
    }

    /// Mirror of step()'s clamp math.
    fn stepped(base: u8, up: bool) -> u8 {
        if up {
            base.saturating_add(STEP).min(100)
        } else {
            base.saturating_sub(STEP)
        }
    }

    #[test]
    fn step_clamps_at_the_bounds() {
        assert_eq!(stepped(0, false), 0); // down from 0 stays 0
        assert_eq!(stepped(0, true), 10);
        assert_eq!(stepped(100, true), 100); // up from 100 stays 100
        assert_eq!(stepped(100, false), 90);
        assert_eq!(stepped(50, true), 60);
        assert_eq!(stepped(50, false), 40);
    }
}
