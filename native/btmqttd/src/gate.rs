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
//!   * **Release survives shutdown** — `main` OWNS this task and DRAINS it on shutdown
//!     (drops the sender to close the channel, then awaits): any queued request plus
//!     the pulse in progress complete — the release is sent — so a press is never left
//!     without its release, which would hold the gate line energised across a
//!     stop/restart. A plain detached `tokio::spawn` would be dropped at runtime
//!     teardown, losing the release.

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

/// Run the gate task: for each queued press request, emit the full momentary pulse
/// (press, hold, release), ONE AT A TIME. Returns only when the channel is closed AND
/// drained — `main` drops the sender on shutdown, so any queued request and the pulse
/// in progress finish (release sent) before this returns.
pub async fn run(mut rx: Receiver<()>) {
    while rx.recv().await.is_some() {
        pulse().await;
    }
}

/// One momentary pulse: press, hold [`GATE_PULSE`], release. Each frame failure is
/// logged. The release is ALWAYS attempted — even if the press errored — so we never
/// leave a half-actuated button; a redundant release on a failed press is harmless.
async fn pulse() {
    if let Err(e) = forward_to_gateway(GATE_PRESS).await {
        eprintln!("btmqttd: gate press failed: {e}");
    }
    tokio::time::sleep(GATE_PULSE).await;
    if let Err(e) = forward_to_gateway(GATE_RELEASE).await {
        eprintln!("btmqttd: gate release failed: {e}");
    }
}
