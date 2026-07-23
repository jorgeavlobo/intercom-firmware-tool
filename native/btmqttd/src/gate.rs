//! Gate momentary-press pulse (issue #41), on its OWN tracked task.
//!
//! A single Home Assistant `button` press is a press-then-release pulse on WHERE=20:
//! `*8*19*20##` (press), a short hold, then `*8*20*20##` (release) — both WHO=8
//! actions via the `:30006` command port (unlike volume dimensions, which need
//! `:20000`). Verified frames on the unit.
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

const GATE_PRESS: &str = "*8*19*20##";
const GATE_RELEASE: &str = "*8*20*20##";

/// Gap between the gate press and release — long enough to register a real momentary
/// press, short enough to feel instant. Mirrors a physical button tap.
const GATE_PULSE: Duration = Duration::from_millis(300);

/// Per-frame forward timeout for the gate — TIGHTER than the raw-command path's 5 s.
/// The gateway is on loopback (frames land in ~ms), and a tight cap keeps a full
/// press+hold+release pulse bounded well under the shutdown drain window: worst case
/// `2*GATE_FORWARD_TIMEOUT + GATE_PULSE` = 4.3 s, so the drain (see `main`) can wait
/// out the pulse in progress and still exit promptly. A hung gateway wouldn't deliver
/// the frame anyway, so a shorter cap costs nothing there.
pub const GATE_FORWARD_TIMEOUT: Duration = Duration::from_secs(2);

/// The longest a single pulse can take: press + hold + release, each forward bounded
/// by [`GATE_FORWARD_TIMEOUT`]. `main` sizes the shutdown drain from this so the
/// in-progress pulse's release is sent before exit. = 2×2 s + 300 ms.
pub const MAX_PULSE: Duration = Duration::from_millis(4_300);

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
pub async fn run(mut rx: Receiver<()>, stopping: Arc<AtomicBool>) {
    while rx.recv().await.is_some() {
        if stopping.load(Ordering::Relaxed) {
            break; // shutdown began: don't START another pulse (the in-flight one is done)
        }
        pulse().await;
    }
}

/// One momentary pulse: press, hold [`GATE_PULSE`], release. Each frame failure is
/// logged. The release is ALWAYS attempted — even if the press errored — so we never
/// leave a half-actuated button; a redundant release on a failed press is harmless.
async fn pulse() {
    if let Err(e) = forward_to_gateway(GATE_PRESS, GATE_FORWARD_TIMEOUT).await {
        eprintln!("btmqttd: gate press failed: {e}");
    }
    tokio::time::sleep(GATE_PULSE).await;
    if let Err(e) = forward_to_gateway(GATE_RELEASE, GATE_FORWARD_TIMEOUT).await {
        eprintln!("btmqttd: gate release failed: {e}");
    }
}
