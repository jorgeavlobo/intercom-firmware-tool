//! Gate momentary-press pulse (issue #41), on its OWN tracked task.
//!
//! A single Home Assistant `button` press is a press-then-release pulse on a WHO=8
//! actuator: `*8*19*<WHERE>##` (press), a short hold, then `*8*20*<WHERE>##` (release),
//! via the `:30006` command port (unlike volume dimensions, which need `:20000`). Two
//! actuators are exposed (see [`Lock`]): the main entrance lock (WHERE=20) and a
//! secondary actuator (WHERE=21 — e.g. a second gate/door). Verified frames on the unit.
//!
//! ## Why a dedicated task (not inline in the command worker, nor a detached spawn)
//! Running the pulse here, fed by a small channel, resolves three competing needs at
//! once:
//!   * **Responsive worker** — the single ordered command worker doesn't block for the
//!     ~300 ms hold; it just enqueues a request and moves on.
//!   * **Serialised** — one pulse runs at a time, so a press is ALWAYS followed by its
//!     own release before the next pulse begins (no interleaved/overlapping press and
//!     release on the bus from rapid double-presses).
//!   * **Release survives shutdown** — `main` OWNS this task and DRAINS it on shutdown:
//!     it sets `stopping` and closes the channel, so the pulse IN PROGRESS completes
//!     (its release is sent) while queued, not-yet-started presses are DISCARDED — a
//!     press that never started emitted nothing, so dropping it strands nothing. So a
//!     press is never left without its release (which would hold the gate line
//!     energised across a stop/restart), and the drain only ever waits for ONE pulse.
//!     A plain detached `tokio::spawn` would instead be dropped at runtime teardown,
//!     losing the release.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc::Receiver;

use crate::receiver::forward_to_gateway;

/// Depth of the gate request queue. Small: the gate is a low-frequency, human-driven
/// action, and a pulse is short — a few pending presses is ample, and a flood beyond
/// this is dropped with a log line rather than growing unboundedly.
pub const QUEUE_DEPTH: usize = 4;

/// Which door-entry actuator a momentary pulse targets. Both are WHO=8 press/release
/// actuators reached the same way on the `:30006` command port; only the WHERE differs.
/// Verified on the unit: `Main` = WHERE 20 (the entrance-panel lock), `Secondary` =
/// WHERE 21 (an auxiliary actuator, e.g. a second gate/door).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lock {
    Main,
    Secondary,
}

impl Lock {
    /// The `(press, release)` frames for this actuator.
    const fn frames(self) -> (&'static str, &'static str) {
        match self {
            Lock::Main => ("*8*19*20##", "*8*20*20##"),
            Lock::Secondary => ("*8*19*21##", "*8*20*21##"),
        }
    }

    /// Human-readable label for log lines.
    const fn label(self) -> &'static str {
        match self {
            Lock::Main => "main lock",
            Lock::Secondary => "secondary lock",
        }
    }
}

// The three timings below are defined ONCE in milliseconds and every Duration
// (including MAX_PULSE) is derived from them, so changing one can't leave MAX_PULSE —
// and hence main's shutdown-drain bound — silently out of sync.

/// Gap between the gate press and release (ms) — long enough to register a real
/// momentary press, short enough to feel instant. Mirrors a physical button tap.
const GATE_PULSE_MS: u64 = 300;
const GATE_PULSE: Duration = Duration::from_millis(GATE_PULSE_MS);

/// Per-frame forward timeout for the gate (ms) — TIGHTER than the raw-command path's
/// 5 s. The gateway is on loopback (frames land in ~ms), and a tight cap keeps a full
/// press+hold+release pulse bounded well under the shutdown drain window, so the drain
/// (see `main`) can wait out the pulse in progress and still exit promptly. A hung
/// gateway wouldn't deliver the frame anyway, so a shorter cap costs nothing there.
const GATE_FORWARD_TIMEOUT_MS: u64 = 2_000;
pub const GATE_FORWARD_TIMEOUT: Duration = Duration::from_millis(GATE_FORWARD_TIMEOUT_MS);

/// The longest a single pulse can take: press + hold + release (two forwards each
/// bounded by [`GATE_FORWARD_TIMEOUT`], plus the hold). DERIVED from the millis
/// constants above so it can't drift; `main` sizes the shutdown drain from it so the
/// in-progress pulse's release is sent before exit.
pub const MAX_PULSE: Duration =
    Duration::from_millis(2 * GATE_FORWARD_TIMEOUT_MS + GATE_PULSE_MS);

/// Run the gate task: for each queued press request, emit the full momentary pulse
/// (press, hold, release), ONE AT A TIME. Returns when the channel is closed and no
/// pulse is in progress.
///
/// `stopping` is set by `main` at shutdown: a pulse ALREADY in progress finishes
/// (its release is sent), but queued presses that have NOT started are DISCARDED — a
/// not-yet-started press has emitted nothing, so dropping it can't strand the gate.
/// This keeps the shutdown drain bounded to ONE pulse ([`MAX_PULSE`]) regardless of
/// how many were queued, instead of processing the whole backlog while the runtime
/// tears down (which could cancel a later pulse between its press and release).
pub async fn run(mut rx: Receiver<Lock>, stopping: Arc<AtomicBool>) {
    while let Some(lock) = rx.recv().await {
        if stopping.load(Ordering::Relaxed) {
            break; // shutdown began: don't START another pulse (the in-flight one is done)
        }
        pulse(lock).await;
    }
}

/// One momentary pulse: press, hold [`GATE_PULSE`], release. Each frame failure is
/// logged. The release is ALWAYS attempted — even if the press errored — so we never
/// leave a half-actuated button; a redundant release on a failed press is harmless.
async fn pulse(lock: Lock) {
    let (press, release) = lock.frames();
    if let Err(e) = forward_to_gateway(press, GATE_FORWARD_TIMEOUT).await {
        eprintln!("btmqttd: {} press failed: {e}", lock.label());
    }
    tokio::time::sleep(GATE_PULSE).await;
    if let Err(e) = forward_to_gateway(release, GATE_FORWARD_TIMEOUT).await {
        eprintln!("btmqttd: {} release failed: {e}", lock.label());
    }
}
