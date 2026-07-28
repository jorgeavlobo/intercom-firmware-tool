//! Device-side ringtone volume + mute state machine (issue #40). (The lock pulse of #41
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
//! `current` (volume), `muted`, and the retained state topics are written ONLY from
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
    /// Monotonic counters bumped on EVERY authoritative write to the field above. A
    /// [`resync`] read snapshots the counter before its (slow) command-session read and
    /// applies the reply only if the counter is unchanged — so a monitor broadcast that
    /// landed a newer value while the read was in flight is not clobbered by the older
    /// reply. Wrap on overflow (harmless: a false match needs exactly 2^64 intervening
    /// observations during one read).
    vol_gen: u64,
    mute_gen: u64,
}

/// Owns the volume/mute state machine and the OWN command-session endpoint used to write
/// the dimensions. Shared (`Arc`) between the command worker (which calls the command
/// methods) and the monitor task (which calls [`observe_volume`]/[`observe_mute`]).
pub struct VolumeCtl {
    st: Mutex<State>,
    /// Serialises the retained-state publishes so two concurrent observations can't
    /// interleave and leave the older value retained (see `publish_volume`/`publish_mute`).
    publish_lock: Mutex<()>,
    /// Serialises command-session operations (`set`/`mute`/`step`/`seed`/`resync`) against
    /// each other, so a slow READ can't interleave with a WRITE and make the generation
    /// guard misfire — a read that sampled the old value before the write could bump the
    /// generation mid-write and cause the device-confirmed echo to be discarded as if the
    /// read were a newer observation. The monitor path (`observe_*`) deliberately does NOT
    /// take this lock: its broadcasts stay concurrent and authoritative, which is exactly
    /// what the generation guard exists for. Command ops are low-frequency and the monitor
    /// stream is a separate task, so holding it across the round trip blocks nothing
    /// user-visible.
    cmd_lock: Mutex<()>,
    /// Dedups reconnect resyncs. A flapping monitor would otherwise `spawn` overlapping
    /// resync tasks; [`resync`] `try_lock`s this and returns early if another resync is
    /// already running (or queued on `cmd_lock`), so only one is ever in flight.
    resync_lock: Mutex<()>,
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
            st: Mutex::new(State { current: None, muted: None, vol_gen: 0, mute_gen: 0 }),
            publish_lock: Mutex::new(()),
            cmd_lock: Mutex::new(()),
            resync_lock: Mutex::new(()),
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
        {
            let mut st = self.st.lock().await;
            st.current = Some(pct);
            st.vol_gen = st.vol_gen.wrapping_add(1);
        }
        self.publish_volume().await;
    }

    /// Learn an AUTHORITATIVE mute state (a monitor broadcast or an on-demand read):
    /// update `muted` and republish the retained `mute` state. Volume is untouched.
    pub async fn observe_mute(&self, muted: bool) {
        {
            let mut st = self.st.lock().await;
            st.muted = Some(muted);
            st.mute_gen = st.mute_gen.wrapping_add(1);
        }
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
        {
            let _cmd = self.cmd_lock.lock().await;
            self.ensure_current().await;
            self.ensure_muted().await;
        }
        // Publish AFTER releasing cmd_lock so broker latency doesn't stall other commands.
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
        // Dedup: skip if another resync is already running or queued — a flapping monitor
        // would otherwise stack overlapping resync tasks (extra command-session load).
        let _resync = match self.resync_lock.try_lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        {
            // Serialise against writes so a set()/mute() in flight can't interleave with
            // these reads (the monitor path stays concurrent — see `cmd_lock`).
            let _cmd = self.cmd_lock.lock().await;
            // Snapshot the generation BEFORE each read; apply the reply only if no newer
            // authoritative observation (a monitor broadcast) bumped it while the read was
            // in flight — otherwise this slow reply would clobber the fresher value. Volume
            // and mute use separate counters so a change to one never discards the other's.
            let vol_gen = { self.st.lock().await.vol_gen };
            match dimension::read_volume(&self.host, self.port).await {
                Ok(Some(n)) => self.apply_volume_if_unchanged(n, vol_gen).await,
                Ok(None) => {}
                Err(e) => eprintln!("btmqttd: volume read (resync) failed: {e}"),
            }
            let mute_gen = { self.st.lock().await.mute_gen };
            match dimension::read_mute(&self.host, self.port).await {
                Ok(Some(m)) => self.apply_mute_if_unchanged(m, mute_gen).await,
                Ok(None) => {}
                Err(e) => eprintln!("btmqttd: mute read (resync) failed: {e}"),
            }
        }
        // Publish AFTER releasing cmd_lock (broker latency must not stall commands).
        self.publish_volume().await;
        self.publish_mute().await;
    }

    /// Apply a device-read volume value (a [`resync`] read or a [`set`] write echo) iff no
    /// newer authoritative observation landed while the (slow) command session was in
    /// flight — i.e. `vol_gen` is unchanged since the caller's snapshot. Otherwise the
    /// monitor already learned a fresher value (which the device also broadcasts), so the
    /// older reply is discarded. The generation check and the write are atomic under the
    /// state lock. Does NOT publish — the caller republishes AFTER releasing `cmd_lock`, so
    /// broker latency never extends the command-serialisation critical section.
    async fn apply_volume_if_unchanged(&self, pct: u8, gen_before: u64) {
        let mut st = self.st.lock().await;
        if st.vol_gen == gen_before {
            st.current = Some(pct.min(100));
            st.vol_gen = st.vol_gen.wrapping_add(1);
        }
    }

    /// Apply a device-read mute value (a [`resync`] read or a [`mute`] write echo) iff no
    /// newer observation landed while the command session was in flight — the mute twin of
    /// [`apply_volume_if_unchanged`] (and likewise does not publish).
    async fn apply_mute_if_unchanged(&self, muted: bool, gen_before: u64) {
        let mut st = self.st.lock().await;
        if st.mute_gen == gen_before {
            st.muted = Some(muted);
            st.mute_gen = st.mute_gen.wrapping_add(1);
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

    /// Set the volume to `pct` (clamped 0..=100). Writes the dimension (under `cmd_lock`)
    /// and applies the level the device ECHOES back via the generation-guarded
    /// [`apply_volume_if_unchanged`], so a rapid follow-up [`step`]/[`set`] computes from the
    /// CONFIRMED value instead of racing the monitor broadcast (which could otherwise let
    /// consecutive up/down presses skip or repeat a step). The monitor broadcast reaffirms
    /// the same value shortly after; the apply is idempotent, so the double update is
    /// harmless. Publishes the retained state AFTER releasing `cmd_lock`. A write the gateway
    /// refuses returns an error here and leaves state untouched. `pct == 0` is now just a low
    /// volume, not a mute — mute is the separate [`mute`] dimension.
    pub async fn set(&self, pct: u8) -> std::io::Result<()> {
        {
            let _cmd = self.cmd_lock.lock().await;
            self.set_inner(pct).await?;
        }
        // Publish AFTER releasing cmd_lock so broker latency/backpressure can't stall the
        // next command; publish_volume reads the LATEST state, so ordering stays correct.
        self.publish_volume().await;
        Ok(())
    }

    /// The volume write + generation-guarded echo apply, WITHOUT taking `cmd_lock` —
    /// callers ([`set`], [`step`]) already hold it so a read can't interleave with the
    /// write. Snapshot the generation before the (slow) write so its echo is applied only
    /// if no newer observation landed meanwhile: if the unit changed the volume during our
    /// write, the monitor already learned that fresher value and our older echo must not
    /// clobber it (the device broadcasts our own write too, so nothing is lost when the
    /// echo is discarded). The common no-contention case still applies the echo at once, so
    /// a rapid follow-up step/set computes from the confirmed value.
    async fn set_inner(&self, pct: u8) -> std::io::Result<()> {
        let pct = pct.min(100);
        let gen_before = { self.st.lock().await.vol_gen };
        let confirmed = dimension::write_volume(&self.host, self.port, pct).await?;
        self.apply_volume_if_unchanged(confirmed, gen_before).await;
        Ok(())
    }

    /// Mute (`on == true`) or unmute the ringtone via the independent `RingEnable`
    /// dimension. Unlike a volume-to-zero fake mute, this leaves the volume level
    /// untouched, so unmute restores sound at the same level with no bookkeeping. Applies
    /// the state the device ECHOES back via the generation-guarded
    /// [`apply_mute_if_unchanged`] and publishes AFTER releasing `cmd_lock`; a refused write
    /// errors and leaves state untouched.
    pub async fn mute(&self, on: bool) -> std::io::Result<()> {
        {
            let _cmd = self.cmd_lock.lock().await;
            // Same generation guard as set(): if the unit toggled mute during our write, the
            // monitor already learned it, so the older echo must not overwrite the fresher
            // value. Discarding the echo is safe — the device broadcasts our own write too.
            let gen_before = { self.st.lock().await.mute_gen };
            let confirmed = dimension::write_mute(&self.host, self.port, on).await?;
            self.apply_mute_if_unchanged(confirmed, gen_before).await;
        }
        // Publish AFTER releasing cmd_lock (see set()).
        self.publish_mute().await;
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
        // monitor can't interleave between them). Does NOT publish — the caller republishes
        // after releasing `cmd_lock`. Returns the resulting `current`.
        let mut st = self.st.lock().await;
        if st.current.is_none() {
            st.current = Some(n);
            st.vol_gen = st.vol_gen.wrapping_add(1);
        }
        st.current
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
        // Apply only while still unknown (monitor stays authoritative). Does NOT publish —
        // [`seed`] republishes after releasing `cmd_lock`.
        let mut st = self.st.lock().await;
        if st.muted.is_none() {
            st.muted = Some(m);
            st.mute_gen = st.mute_gen.wrapping_add(1);
        }
    }

    /// Step the volume by `delta` (the buttons pass +[`STEP`] / -[`STEP`]), clamped to
    /// 0..=100. Uses the last known `current`; if it's still unknown, reads it on demand
    /// first so the very first press steps from the real level, not a guess.
    pub async fn step(&self, up: bool) -> std::io::Result<()> {
        {
            // Hold cmd_lock across the read-base + write so the whole step is atomic against
            // other command ops (and calls set_inner, which does NOT re-take the lock).
            let _cmd = self.cmd_lock.lock().await;
            let base = self.ensure_current().await.unwrap_or(0);
            let next = if up {
                base.saturating_add(STEP).min(100)
            } else {
                base.saturating_sub(STEP)
            };
            self.set_inner(next).await?;
        }
        // Publish AFTER releasing cmd_lock (see set()).
        self.publish_volume().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The state-transition math the acceptance criteria pin down, exercised on the pure
    // `State` logic without a live gateway/broker (the network writes are thin wrappers
    // over dimension::write_volume / write_mute, covered by dimension.rs's frame tests).

    /// Mirror of observe_volume()'s state update, in isolation (bumps the generation).
    fn observe_volume(st: &mut State, pct: u8) {
        st.current = Some(pct);
        st.vol_gen = st.vol_gen.wrapping_add(1);
    }

    /// Mirror of observe_mute()'s state update, in isolation (bumps the generation).
    fn observe_mute(st: &mut State, muted: bool) {
        st.muted = Some(muted);
        st.mute_gen = st.mute_gen.wrapping_add(1);
    }

    /// Mirror of apply_volume_if_unchanged()'s generation-guarded apply.
    fn apply_volume_if_unchanged(st: &mut State, pct: u8, gen_before: u64) -> bool {
        if st.vol_gen == gen_before {
            st.current = Some(pct.min(100));
            st.vol_gen = st.vol_gen.wrapping_add(1);
            true
        } else {
            false
        }
    }

    /// Mirror of apply_mute_if_unchanged()'s generation-guarded apply.
    fn apply_mute_if_unchanged(st: &mut State, muted: bool, gen_before: u64) -> bool {
        if st.mute_gen == gen_before {
            st.muted = Some(muted);
            st.mute_gen = st.mute_gen.wrapping_add(1);
            true
        } else {
            false
        }
    }

    #[test]
    fn volume_and_mute_are_independent() {
        // Muting must NOT disturb the learned volume, and vice-versa — the whole point of
        // driving the real RingEnable dimension instead of faking mute with volume 0.
        let mut st = State { current: None, muted: None, vol_gen: 0, mute_gen: 0 };
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
        let mut st = State { current: None, muted: Some(false), vol_gen: 0, mute_gen: 0 };
        observe_volume(&mut st, 0);
        assert_eq!(st.current, Some(0));
        assert_eq!(st.muted, Some(false)); // NOT flipped to muted by volume reaching 0
    }

    #[test]
    fn resync_read_is_discarded_when_a_newer_observation_landed_during_it() {
        // A monitor broadcast (90) lands after resync snapshots the generation but before
        // its slower read reply (80) is applied — the stale reply must be discarded.
        let mut st = State { current: Some(50), muted: None, vol_gen: 3, mute_gen: 0 };
        let gen_before = st.vol_gen; // snapshot taken before the read
        observe_volume(&mut st, 90); // newer value observed while the read is in flight
        let applied = apply_volume_if_unchanged(&mut st, 80, gen_before);
        assert!(!applied);
        assert_eq!(st.current, Some(90)); // fresher monitor value preserved
    }

    #[test]
    fn resync_read_applies_when_nothing_changed_during_it() {
        let mut st = State { current: Some(50), muted: None, vol_gen: 3, mute_gen: 0 };
        let gen_before = st.vol_gen;
        let applied = apply_volume_if_unchanged(&mut st, 80, gen_before);
        assert!(applied);
        assert_eq!(st.current, Some(80));
    }

    #[test]
    fn resync_mute_read_is_discarded_when_a_newer_observation_landed_during_it() {
        // Mute twin of the volume test: RingEnable is inverted (muted == RingEnable 0) and
        // uses its own counter, so pin the discard behaviour down separately.
        let mut st = State { current: None, muted: Some(false), vol_gen: 0, mute_gen: 5 };
        let gen_before = st.mute_gen; // snapshot before the read
        observe_mute(&mut st, true); // unit muted while the read is in flight
        let applied = apply_mute_if_unchanged(&mut st, false, gen_before); // stale reply
        assert!(!applied);
        assert_eq!(st.muted, Some(true)); // fresher mute state preserved
    }

    #[test]
    fn resync_mute_read_applies_when_nothing_changed_during_it() {
        let mut st = State { current: None, muted: Some(false), vol_gen: 0, mute_gen: 5 };
        let gen_before = st.mute_gen;
        let applied = apply_mute_if_unchanged(&mut st, true, gen_before);
        assert!(applied);
        assert_eq!(st.muted, Some(true));
    }

    #[test]
    fn state_starts_unknown() {
        let st = State { current: None, muted: None, vol_gen: 0, mute_gen: 0 };
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
