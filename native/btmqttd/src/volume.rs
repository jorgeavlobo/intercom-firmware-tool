//! Device-side ringtone volume + mute state machine (issue #40). (The gate pulse of #41
//! lives in `receiver.rs`, next to the other WHO=8 command-port actions.)
//!
//! All volume/mute STATE and logic live here — Home Assistant stays "dumb": it renders
//! four auto-discovered entities (slider `number`, `mute` switch, up/down `button`s)
//! whose commands arrive as small JSON actions on the existing command topic
//! (`TOPIC_RX`), and whose state is read back from two retained topics this module
//! publishes (`Bticino/volume`, `Bticino/mute`). No HA templating over the raw bus,
//! no automations — correct even across an HA restart or a change made on the unit.
//!
//! ## Volume and mute are INDEPENDENT (issue #40 reverse-engineering)
//! The two are separate WHO=8 dimensions with separate persistence, exactly as the
//! unit's own UI treats them:
//!   * VOLUME — dimension `41`, `aswm_settings.ini` `[Volumes] Ring=<N>`; the real
//!     ringtone loudness (proven audibly at the door station).
//!   * MUTE — dimension `33`, `aswm_settings.ini` `RingEnable=<0|1>`; the unit's "do not
//!     disturb" toggle. Muting SILENCES the ringtone WITHOUT changing the volume, so the
//!     slider keeps its level while muted and unmute restores sound at that same level
//!     for free — no need to save/restore a "pre-mute" level.
//!
//! ## Authoritative state: device-confirmed values only
//! `current` (volume) and `muted` and the retained state topics are written ONLY from
//! values the DEVICE confirmed, funnelled through [`observe_volume`] / [`observe_mute`]:
//!   * the monitor broadcasts `*#8**41*<N>##` (volume) and `*#8**33*<0|1>##` (mute) —
//!     emitted whenever either changes by ANY path (slider, up/down, mute, or the unit's
//!     own menu), consumed via the `sender` hook (this also catches changes made on the
//!     unit itself);
//!   * the value a write ECHOES back — [`set`]/[`mute`] apply it at once so a rapid
//!     follow-up computes from the confirmed value rather than racing the monitor;
//!   * an on-demand read — [`seed`] on connect, and [`ensure_current`] before a
//!     first-command step, so state is right even before the monitor has spoken. The
//!     read is applied only while state is still unknown, keeping the monitor
//!     authoritative.
//!
//! No value is ever written optimistically from a request the device hasn't
//! acknowledged, which keeps HA correct however the volume/mute is reached.

use std::sync::Arc;

use rumqttc::{AsyncClient, QoS};
use tokio::sync::Mutex;

use crate::config::Config;
use crate::dimension;

/// The step (percent) the up/down buttons move, and the discovery slider's step.
const STEP: u8 = 10;

/// Learned volume/mute state. Each field is `None` until the first observation (monitor
/// broadcast or on-connect read); the two are independent, mirroring the device.
struct State {
    /// Ringtone volume percent (dimension 41).
    current: Option<u8>,
    /// Ringtone muted, i.e. `RingEnable == 0` (dimension 33) — independent of `current`.
    muted: Option<bool>,
}

/// Owns the volume/mute state machine and the OWN command-session endpoint used to write
/// the dimensions. Shared (`Arc`) between the command worker (which calls the command
/// methods) and the monitor task (which calls [`observe_volume`]/[`observe_mute`]).
pub struct VolumeCtl {
    st: Mutex<State>,
    /// Serialises the retained-state publishes so two concurrent observations can't
    /// interleave and leave the older value retained (see `publish_volume`/`publish_mute`).
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
    /// Build the controller from config. Both learned values start unknown until the
    /// first observation (monitor broadcast or on-connect read).
    pub fn new(cfg: &Arc<Config>, client: AsyncClient) -> Arc<Self> {
        Arc::new(VolumeCtl {
            st: Mutex::new(State { current: None, muted: None }),
            publish_lock: Mutex::new(()),
            host: cfg.own_host.clone(),
            port: cfg.own_port_mon,
            topic_volume: cfg.topic_volume.clone(),
            topic_mute: cfg.topic_mute.clone(),
            client,
        })
    }

    /// Learn an AUTHORITATIVE volume (a monitor broadcast or an on-demand read): update
    /// `current` and republish the retained `volume` state. Mute is untouched — the two
    /// are independent.
    pub async fn observe_volume(&self, pct: u8) {
        let pct = pct.min(100);
        self.st.lock().await.current = Some(pct);
        self.publish_volume().await;
    }

    /// Learn an AUTHORITATIVE mute state (a monitor broadcast or an on-demand read):
    /// update `muted` and republish the retained `mute` state. Volume is untouched.
    pub async fn observe_mute(&self, muted: bool) {
        self.st.lock().await.muted = Some(muted);
        self.publish_mute().await;
    }

    /// On-connect seed: read the current volume AND mute once via the command session so
    /// HA shows values before the first change, then republish both retained topics.
    /// Best-effort — a refused/unavailable gateway just leaves state unknown until the
    /// first monitor broadcast. The republish matters because a broker that restarted
    /// dropped the retained topics: discovery is re-sent on connect, but the slider/switch
    /// would otherwise stay stateless until the next report even when state was known.
    /// Each publish is a no-op while its value is still unknown.
    pub async fn seed(&self) {
        self.ensure_current().await;
        self.ensure_muted().await;
        self.publish_volume().await;
        self.publish_mute().await;
    }

    /// Force a fresh read of BOTH volume and mute from the device and apply them,
    /// OVERWRITING any cached value. Called on each monitor (re)connect: while the
    /// monitor stream was down, a change made on the unit emits a one-shot broadcast that
    /// is lost, and the `ensure_*` "only if unknown" guard would otherwise keep the stale
    /// cached value indefinitely (the retained HA switch/slider staying wrong until the
    /// next event or command). A concurrent monitor broadcast is equally
    /// device-authoritative, so last-writer-wins between it and this read is harmless.
    /// Best-effort: a refused/unreachable gateway leaves the current value in place.
    pub async fn resync(&self) {
        match dimension::read_volume(&self.host, self.port).await {
            Ok(Some(n)) => self.observe_volume(n).await,
            Ok(None) => {}
            Err(e) => eprintln!("btmqttd: volume read (resync) failed: {e}"),
        }
        match dimension::read_mute(&self.host, self.port).await {
            Ok(Some(m)) => self.observe_mute(m).await,
            Ok(None) => {}
            Err(e) => eprintln!("btmqttd: mute read (resync) failed: {e}"),
        }
    }

    /// Publish the retained `volume` (0..=100) state, reading the LATEST `current` at
    /// publish time under a serialising lock. `publish_lock` serialises retained writes so
    /// a slow publish (broker backpressure) can't finish AFTER a newer one and leave the
    /// older value retained; reading `current` here (rather than a value captured earlier)
    /// means every publish emits the newest observation. No-op until the first value.
    async fn publish_volume(&self) {
        let _pub = self.publish_lock.lock().await;
        let pct = match self.st.lock().await.current {
            Some(p) => p,
            None => return,
        };
        self.publish_retained(&self.topic_volume, pct.to_string().into_bytes()).await;
    }

    /// Publish the retained `mute` (`on`/`off`) state under the same serialising lock and
    /// with the same latest-value read as [`publish_volume`]. No-op until the first value.
    async fn publish_mute(&self) {
        let _pub = self.publish_lock.lock().await;
        let muted = match self.st.lock().await.muted {
            Some(m) => m,
            None => return,
        };
        let payload = if muted { "on" } else { "off" };
        self.publish_retained(&self.topic_mute, payload.as_bytes().to_vec()).await;
    }

    async fn publish_retained(&self, topic: &str, payload: Vec<u8>) {
        if let Err(e) = self.client.publish(topic, QoS::AtMostOnce, true, payload).await {
            // Topic-agnostic: this publishes both the volume and the mute state, so name
            // the actual topic rather than hard-coding "volume".
            eprintln!("btmqttd: publish retained state to {topic} failed: {e}");
        }
    }

    /// Set the volume to `pct` (clamped 0..=100). Writes the dimension to the device and
    /// applies the level the device ECHOES back via [`observe_volume`], so a rapid
    /// follow-up [`step`]/[`set`] computes from the CONFIRMED value instead of racing the
    /// monitor broadcast (which could otherwise let consecutive up/down presses skip or
    /// repeat a step). The monitor broadcast reaffirms the same value shortly after;
    /// `observe_volume` is idempotent, so the double update is harmless. A write the
    /// gateway refuses returns an error here and leaves state untouched. `pct == 0` is now
    /// just a low volume, not a mute — mute is the separate [`mute`] dimension.
    pub async fn set(&self, pct: u8) -> std::io::Result<()> {
        let pct = pct.min(100);
        let confirmed = dimension::write_volume(&self.host, self.port, pct).await?;
        self.observe_volume(confirmed).await;
        Ok(())
    }

    /// Mute (`on == true`) or unmute the ringtone via the independent `RingEnable`
    /// dimension. Unlike a volume-to-zero fake mute, this leaves the volume level
    /// untouched, so unmute restores sound at the same level with no bookkeeping. Applies
    /// the state the device ECHOES back via [`observe_mute`]; a refused write errors and
    /// leaves state untouched.
    pub async fn mute(&self, on: bool) -> std::io::Result<()> {
        let confirmed = dimension::write_mute(&self.host, self.port, on).await?;
        self.observe_mute(confirmed).await;
        Ok(())
    }

    /// Return the current volume, learning it first if unknown: read it on demand and
    /// OBSERVE it so a step lands on the real level even when the FIRST action after
    /// start/reconnect precedes the on-connect seed / monitor update. Returns `None` only
    /// if the level is unknown AND the on-demand read yields nothing (gateway
    /// refused/unreachable); callers fall back.
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
                true
            } else {
                false
            }
        };
        if applied {
            self.publish_volume().await;
            Some(n)
        } else {
            self.st.lock().await.current
        }
    }

    /// Learn the mute state on demand if still unknown (used by [`seed`]). Mirrors
    /// [`ensure_current`]'s "apply only while still unknown" guard so a monitor broadcast
    /// racing the read stays authoritative.
    async fn ensure_muted(&self) {
        if self.st.lock().await.muted.is_some() {
            return;
        }
        let m = match dimension::read_mute(&self.host, self.port).await {
            Ok(Some(m)) => m,
            Ok(None) => return,
            Err(e) => {
                eprintln!("btmqttd: mute read (ensure_muted) failed: {e}");
                return;
            }
        };
        let applied = {
            let mut st = self.st.lock().await;
            if st.muted.is_none() {
                st.muted = Some(m);
                true
            } else {
                false
            }
        };
        if applied {
            self.publish_mute().await;
        }
    }

    /// Step the volume by `delta` (the buttons pass +[`STEP`] / -[`STEP`]), clamped to
    /// 0..=100. Uses the last known `current`; if it's still unknown, reads it on demand
    /// first so the very first press steps from the real level, not a guess.
    pub async fn step(&self, up: bool) -> std::io::Result<()> {
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

    // The state-transition math the acceptance criteria pin down, exercised on the pure
    // `State` logic without a live gateway/broker (the network writes are thin wrappers
    // over dimension::write_volume / write_mute, covered by dimension.rs's frame tests).

    /// Mirror of observe_volume()'s state update, in isolation.
    fn observe_volume(st: &mut State, pct: u8) {
        st.current = Some(pct);
    }

    /// Mirror of observe_mute()'s state update, in isolation.
    fn observe_mute(st: &mut State, muted: bool) {
        st.muted = Some(muted);
    }

    #[test]
    fn volume_and_mute_are_independent() {
        // Muting must NOT disturb the learned volume, and vice-versa — the whole point of
        // driving the real RingEnable dimension instead of faking mute with volume 0.
        let mut st = State { current: None, muted: None };
        observe_volume(&mut st, 80);
        observe_mute(&mut st, true); // mute on
        assert_eq!(st.current, Some(80)); // volume preserved while muted
        assert_eq!(st.muted, Some(true));
        observe_mute(&mut st, false); // unmute
        assert_eq!(st.current, Some(80)); // still 80 — sound returns at the same level
    }

    #[test]
    fn zero_volume_is_not_mute() {
        // A slider/down-button 0 is a low volume, not a mute: `muted` tracks RingEnable
        // only, so it stays whatever the device last reported.
        let mut st = State { current: None, muted: Some(false) };
        observe_volume(&mut st, 0);
        assert_eq!(st.current, Some(0));
        assert_eq!(st.muted, Some(false)); // NOT flipped to muted by volume reaching 0
    }

    #[test]
    fn state_starts_unknown() {
        let st = State { current: None, muted: None };
        assert_eq!(st.current, None);
        assert_eq!(st.muted, None);
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
