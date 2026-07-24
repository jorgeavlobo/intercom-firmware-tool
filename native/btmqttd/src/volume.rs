//! Device-side volume state machine (issue #40). (The gate pulse of #41 lives in
//! `receiver.rs`, next to the other WHO=8 command-port actions.)
//!
//! All volume STATE and logic live here — Home Assistant stays "dumb": it renders
//! four auto-discovered entities (slider `number`, `mute` switch, up/down `button`s)
//! whose commands arrive as small JSON actions on the existing command topic
//! (`TOPIC_RX`), and whose state is read back from two retained topics this module
//! publishes (`Bticino/volume`, `Bticino/mute`). No HA templating over the raw bus,
//! no automations — correct even across an HA restart or a change made on the unit.
//!
//! ## Authoritative state: device-confirmed values only
//! `current`/`last_nonzero` and the retained state topics are written ONLY from values
//! the DEVICE confirmed, funnelled through [`observe`]:
//!   * the monitor broadcasts `*#8**41*<N>##` — emitted whenever the volume changes by
//!     ANY path (slider, up/down, mute, or the unit's own menu), consumed via the
//!     `sender` hook (this also catches changes made on the unit itself);
//!   * the level a write ECHOES back — [`set`] applies it at once so a rapid follow-up
//!     computes from the confirmed value rather than racing the monitor;
//!   * an on-demand read — [`seed`] on connect, and [`ensure_current`] before a
//!     first-command mute/step, so `last_nonzero` is right even before the monitor has
//!     spoken. The read is applied only if `current` is still unknown, keeping the
//!     monitor authoritative.
//!
//! No value is ever written optimistically from a request that the device hasn't
//! acknowledged, which keeps HA and the derived `muted` flag correct however the volume
//! reaches 0.
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
    /// Serialises the retained-state publishes so two concurrent observations can't
    /// interleave and leave the older value retained (see `publish_current`).
    publish_lock: Mutex<()>,
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
            publish_lock: Mutex::new(()),
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
        self.publish_current().await;
    }

    /// On-connect seed: read the current volume once via the command session so HA
    /// shows a value before the first change. Best-effort — a refused or unavailable
    /// gateway just leaves `current` unknown until the first monitor broadcast.
    pub async fn seed(&self) {
        // Learn the level if still unknown — ensure_current reads + observes, applying
        // the read ONLY while `current` is unknown (so a command/monitor update racing
        // the read isn't clobbered). Then ALWAYS republish the retained volume/mute
        // state: this runs on every (re)connect, and a broker that restarted dropped the
        // retained state topics — HA discovery is re-sent on connect but the slider/
        // switch would otherwise stay stateless until the next report/command, even when
        // `current` was already known. publish_current is a no-op while `current` is None.
        self.ensure_current().await;
        self.publish_current().await;
    }

    /// Publish the retained `volume` (0..=100) and derived `mute` (`on`/`off`) state,
    /// reading the LATEST `current` at publish time under a serialising lock. Two races
    /// are closed together: `publish_lock` serialises retained writes so a slow publish
    /// (broker backpressure) can't finish AFTER a newer one and leave the older value
    /// retained; and reading `current` here (rather than a value captured earlier) means
    /// every publish emits the newest observation, so the retained topics converge to the
    /// true current state even if observations interleave. No-op until the first value.
    async fn publish_current(&self) {
        let _pub = self.publish_lock.lock().await;
        let pct = match self.st.lock().await.current {
            Some(p) => p,
            None => return,
        };
        let muted = if pct == 0 { "on" } else { "off" };
        self.publish_retained(&self.topic_volume, pct.to_string().into_bytes()).await;
        self.publish_retained(&self.topic_mute, muted.as_bytes().to_vec()).await;
    }

    async fn publish_retained(&self, topic: &str, payload: Vec<u8>) {
        if let Err(e) = self.client.publish(topic, QoS::AtMostOnce, true, payload).await {
            // Topic-agnostic: this publishes both the volume and the mute state, so name
            // the actual topic rather than hard-coding "volume".
            eprintln!("btmqttd: publish retained state to {topic} failed: {e}");
        }
    }

    /// Set the volume to `pct` (clamped 0..=100). Writes the dimension to the device
    /// and applies the level the device ECHOES back via [`observe`], so a rapid
    /// follow-up [`step`]/[`set`] computes from the CONFIRMED value instead of racing
    /// the monitor broadcast (which could otherwise let consecutive up/down presses
    /// skip or repeat a step). The monitor broadcast reaffirms the same value shortly
    /// after; `observe` is idempotent, so the double update is harmless. A write the
    /// gateway refuses returns an error here and leaves state untouched.
    pub async fn set(&self, pct: u8) -> std::io::Result<()> {
        let pct = pct.min(100);
        // Zeroing before the level is known would strand `last_nonzero` at its default,
        // so a later unmute would restore that default instead of the true pre-zero
        // level. Learn the real level first when zeroing from an unknown state. This is
        // the single place the guard lives, so it covers EVERY zero path — mute-on,
        // slider-to-0, step-to-0, a JSON `volume` 0 — and ensure_current is a no-op once
        // `current` is known, so non-zero sets and repeat calls pay nothing.
        if pct == 0 {
            self.ensure_current().await;
        }
        let confirmed = dimension::write_volume(&self.host, self.port, pct).await?;
        self.observe(confirmed).await;
        Ok(())
    }

    /// Mute (`on`) or unmute (`off`). Mute writes 0; unmute restores `last_nonzero`
    /// (the exact pre-mute level, or [`DEFAULT_NONZERO`] if none was ever observed).
    /// `last_nonzero` is maintained by [`observe`], so at mute time it already equals
    /// the current audible level.
    pub async fn mute(&self, on: bool) -> std::io::Result<()> {
        // Mute writes 0 — set() learns the pre-zero level first (so unmute can restore
        // it); unmute writes `last_nonzero`, the exact pre-mute level (or DEFAULT_NONZERO
        // if none was ever observed).
        let target = if on { 0 } else { self.st.lock().await.last_nonzero };
        self.set(target).await
    }

    /// Return the current volume, learning it first if unknown: read it on demand and
    /// OBSERVE it (updating `current` AND `last_nonzero`) so the smart-mute invariant
    /// holds even when the FIRST action after start/reconnect precedes the on-connect
    /// seed / monitor update. Returns `None` only if the level is unknown AND the
    /// on-demand read yields nothing (gateway refused/unreachable); callers fall back.
    async fn ensure_current(&self) -> Option<u8> {
        let known = { self.st.lock().await.current };
        if let Some(c) = known {
            return Some(c);
        }
        let n = match dimension::read_volume(&self.host, self.port).await {
            Ok(Some(n)) => n,
            Ok(None) => return None,
            Err(e) => {
                eprintln!("btmqttd: volume read (ensure_current) failed: {e}");
                return None;
            }
        };
        // Apply the read ONLY if `current` is STILL unknown: the monitor is the source of
        // truth and may have learned a newer value while our read was in flight — don't
        // revert to the now-stale read. The check-and-set is atomic under the lock (the
        // monitor can't interleave between them); publish happens off the lock.
        let applied = {
            let mut st = self.st.lock().await;
            if st.current.is_none() {
                st.current = Some(n);
                if n > 0 {
                    st.last_nonzero = n;
                }
                true
            } else {
                false
            }
        };
        if applied {
            self.publish_current().await;
            Some(n)
        } else {
            self.st.lock().await.current
        }
    }

    /// Step the volume by `delta` (the buttons pass +[`STEP`] / -[`STEP`]), clamped to
    /// 0..=100. Uses the last known `current`; if it's still unknown, reads it on
    /// demand first so the very first press steps from the real level, not a guess.
    pub async fn step(&self, up: bool) -> std::io::Result<()> {
        // Resolve the base level, reading + OBSERVING it if still unknown (ensure_current
        // drops the lock before the read and records last_nonzero), so a step that lands
        // on 0 as the first action after start/reconnect still captures the true pre-zero
        // level — else unmute would restore the default, not e.g. 10. Unknown even after
        // the read -> step from 0 (up -> STEP, down -> 0, both clamp correctly).
        let base = self.ensure_current().await.unwrap_or(0);
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
