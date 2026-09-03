//! Automatic, transparent sprop-parameter-sets provisioning for the on-device camera (issue #120) —
//! a PASSIVE loopback RTP listener.
//!
//! The panel's SDP carries no `sprop-parameter-sets`, and — hardware-confirmed on the C100X — its SIP
//! answer doesn't advertise them either (only `profile-level-id`). Its encoder emits an in-stream
//! SPS/PPS only about every 20 s, so go2rtc's `-c:v copy` ffmpeg blocks ~20 s on a cold open before it
//! can resolve the video and serve it. Rather than make the operator find and paste their panel's
//! parameter sets, btmqttd LEARNS them itself and reassembles the go2rtc SDP with them, so that once the
//! first real view has learned them, every LATER open resolves in under a second — nothing to configure.
//!
//! ## Lifecycle (passive listen; learns once; persists the VALUE, not a patched file)
//! An earlier revision brought the panel up ITSELF (a silent on-demand INVITE) to run a one-shot ffmpeg
//! probe. Hardware testing proved that CAN'T WORK: the panel only sustains/feeds the video call for a
//! REAL consumed view, not a silent probe — so proactive probing just cycles the panel and never learns.
//! A later revision watched a DERIVED SDP that go2rtc's live-view ffmpeg wrote via `-sdp_file`. Hardware
//! testing (PR #129) proved THAT can't work either: ffmpeg's `-sdp_file` parses the SPS only far enough
//! to learn the resolution and never writes the parameter sets into the SDP on a copy path (confirmed
//! even with a 25 s analyzeduration). So this task is purely passive AND parses the RTP itself.
//!
//! The learned value is persisted KEYED BY the current `CAMERA_BRANCH` (`<branch>\t<value>`), because
//! the hi- and lo-res branches encode different SPS. `cfg/extra` survives a reflash, so a reflash that
//! flips the branch would otherwise splice a stale value; keying the record makes such a unit re-learn
//! (task #41). The listen below therefore treats "already provisioned" as branch-specific:
//!   * go2rtc's OWN `exec:` ffmpeg — which runs only while a client is actually watching — is given a
//!     SECOND output (in `Go2RtcConfig.BuildOnDeviceYaml`) that ships a raw H.264 RTP copy to a loopback
//!     UDP port: `-c:v copy -f rtp rtp://{OnDeviceSpropRtpPort}`. That RTP stream carries the panel's
//!     periodic in-band SPS (NAL type 7) / PPS (NAL type 8). This task NEVER brings the panel up itself,
//!     so it can never cycle it.
//!   * This task binds that loopback port ([`SPROP_RTP_ADDR`], = `Go2RtcConfig.OnDeviceSpropRtpPort`),
//!     extracts the SPS/PPS straight out of the RTP payload (accumulating across packets — they may
//!     arrive as separate single NALs or bundled in one STAP-A), base64-encodes them and PERSISTS the
//!     VALUE `sprop-parameter-sets=<b64SPS>,<b64PPS>` on the writable `cfg/extra` partition via
//!     `persist::store_camera_sprop`, KEYED by the current `CAMERA_BRANCH` (the durable source of
//!     truth — `go2rtcd` reassembles the runtime SDP from template + persisted value at boot), best-
//!     effort patches THIS boot's runtime tmpfs SDP ([`SDP_PATH`]) so the current session speeds up
//!     without waiting for a reboot, and returns.
//!   * The first view is the ~20 s parser resolve (unchanged); every later view is fast. Until a live
//!     view produces the SPS/PPS, it just keeps listening.
//!
//! ## Self-heal the CURRENT view when the learn happens mid-view (issue #146, fix B)
//! Patching the tmpfs SDP fixes every LATER open, but go2rtc's `exec:` ffmpeg producer for the view that
//! is happening RIGHT NOW already read the BARE SDP at spawn and never re-reads it — so that view stays
//! undecodable (`non-existing PPS 0 referenced`) until the producer respawns. go2rtc does NOT restart an
//! `exec:` producer on its own (v1.9.14: "consumers must re-request the stream"). So, when the runtime
//! patch actually INSERTS sprop into a bare SDP (i.e. the running producer is stale), this task nudges
//! the producer to respawn by sending it SIGTERM ([`respawn_go2rtc_producer`]): the stream drops, Home
//! Assistant's camera reconnects, and go2rtc runs a fresh `exec:` ffmpeg that opens the PATCHED SDP with
//! the parameter sets from the first frame — the view self-heals in seconds, no `go2rtcd restart`, no
//! human, and no firewall touch (#145 discipline). This is a BACKSTOP: fix A (the #169 first-run warm-up)
//! learns before the first open in the common case, so the producer already reads a patched SDP and there
//! is nothing to respawn; the patch-then-respawn only fires when a real view learns first. In the rare
//! case a first-run warm-up capture is the view that learns, its one-frame grab may be interrupted by the
//! respawn and simply retries on the next boot — by which point the value is persisted, so `go2rtcd`
//! assembles the SDP with sprop at boot, the producer starts correct, and no runtime patch/respawn ever
//! fires again on that unit.
//!
//! ## Why a tmpfs runtime SDP (the rootfs is read-only)
//! The device rootfs — including `/etc` — is mounted READ-ONLY (see `persist.rs`), so a runtime write to
//! the `/etc` SDP fails with `EROFS`. The design therefore SPLITS the SDP:
//!   * the installer's `/etc/.../doorbell.sdp` is the read-only TEMPLATE/seed;
//!   * go2rtc reads a RUNTIME copy on tmpfs (`/var/run/btmqttd/doorbell.sdp`), which the `go2rtcd` init
//!     script (re)assembles at EVERY boot: it copies the template into tmpfs and, if a value learned on
//!     the CURRENT `CAMERA_BRANCH` is persisted, splices `sprop-parameter-sets=<value>;` into the fmtp
//!     line. This task patches THAT runtime copy (writable) after a fresh learn. Reflash-safe by
//!     composition: `cfg/extra` survives a reflash, so a re-flashed unit that already learned keeps its
//!     value WHEN the branch is unchanged; a reflash that flips `CAMERA_BRANCH` — or a genuinely fresh
//!     unit — has no matching persisted value and re-learns from the next live view (task #41).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use crate::config::Config;
use crate::persist;

/// The RUNTIME go2rtc SDP on tmpfs — what go2rtc's `exec -i` reads and what this task patches after a
/// fresh learn. `go2rtcd` (re)assembles it at every boot from [`TEMPLATE_SDP_PATH`] + the persisted
/// value. tmpfs is writable, so patching it (temp + rename below) works despite the read-only rootfs.
const SDP_PATH: &str = "/var/run/btmqttd/doorbell.sdp";
/// The READ-ONLY TEMPLATE SDP the installer wrote under `/etc` (Go2RtcDir + stream name), 0644 (it
/// carries no secret). Always present and never mutated — checked by `template_has_sprop` so a
/// pre-seeded image never runs a redundant listen.
const TEMPLATE_SDP_PATH: &str = "/etc/btmqttd/go2rtc/doorbell.sdp";
/// The loopback UDP endpoint go2rtc's own `exec:` ffmpeg ships a raw H.264 RTP copy to (its SECOND
/// output) while a client is watching. This task binds THIS EXACT address to receive that stream and
/// parse the panel's in-band SPS/PPS out of the RTP payload, so it MUST equal
/// `Go2RtcConfig.OnDeviceSpropRtpPort` — the two are coupled and must stay in sync.
const SPROP_RTP_ADDR: &str = "127.0.0.1:40100";
/// The `a=fmtp` fragment we splice sprop in AFTER — matches Go2RtcConfig.BuildOnDeviceSdp's order so a
/// patched SDP equals what the installer would have written with CameraSprop set.
const FMTP_ANCHOR: &str = "packetization-mode=1;";

/// How long a single `recv_from` waits before we loop back to re-check `stopping` / the persisted state.
/// Short enough that a shutdown (or an operator pre-seed) is observed promptly while a view is idle.
const RECV_TIMEOUT: Duration = Duration::from_secs(1);
/// Backoff between retries when binding [`SPROP_RTP_ADDR`] fails (e.g. the port is briefly in use). A
/// transient bind failure must not kill learning, so we sleep and retry rather than return.
const BIND_RETRY: Duration = Duration::from_secs(5);
/// Backoff after a `recv_from` ERROR (as opposed to a timeout). A recv error on a bound loopback UDP
/// socket is unusual, but if one recurs we must not spin: sleeping here keeps a persistent error from
/// pegging the single-threaded runtime.
const RECV_ERR_BACKOFF: Duration = Duration::from_secs(1);
/// Bounded retries for clearing the superseded learned record on a seeded image (see `run`'s
/// `ClearThenDone`). Enough to ride out a transient `cfg/extra` write failure (the partition briefly
/// unavailable) without treating the clear as done while the stale record survives; a persistent failure
/// is a hardware fault we log and move on from.
const CLEAR_RETRIES: u32 = 5;
/// Backoff between clear retries.
const CLEAR_RETRY_BACKOFF: Duration = Duration::from_secs(2);

/// Listen on the loopback RTP port, parse the panel's SPS/PPS from the H.264 the live-view ffmpeg ships
/// there, persist the learned `sprop-parameter-sets`, and return. Spawned when the on-device camera is
/// enabled. It holds no `view_tx` and publishes nothing — it only reads a UDP socket and writes the
/// persisted value / runtime SDP — so `main` aborts it at shutdown like `av.rs`. From `cfg` it reads
/// only `camera_branch`: the learned value is persisted keyed by it, and a persisted value for a
/// DIFFERENT branch (a reflash that flipped `CAMERA_BRANCH`) is not "already learned" (task #41).
pub async fn run(cfg: Arc<Config>, stopping: Arc<AtomicBool>) {
    // The video branch the panel is currently siphoned on. The learned SPS/PPS are branch-specific, so
    // this keys the persisted record and the "already learned" gate.
    let branch = cfg.camera_branch;
    // Decide from the two provisioning facts (see `provision_action`): a single cheap read of each at
    // startup; the steady state after the first learn is `Done`.
    match provision_action(template_has_sprop().await, persisted_for_branch(branch).await) {
        // A seeded template supersedes any learned record: CLEAR the stale record so a later bare reflash
        // re-learns instead of resurrecting the old value. Do NOT treat this as done until the
        // clear actually succeeds — if it fails (cfg/extra briefly unavailable) the stale record would
        // survive and a later bare reflash could re-splice it — so retry with a bounded
        // backoff and log an ultimate failure. `clear_camera_sprop` returns true when the file is gone
        // (removed OR already absent), so on the common seeded image with no record it succeeds at once.
        Provision::ClearThenDone => {
            for attempt in 0..CLEAR_RETRIES {
                if stopping.load(Ordering::Relaxed) {
                    return;
                }
                if tokio::task::spawn_blocking(persist::clear_camera_sprop)
                    .await
                    .unwrap_or(false)
                {
                    return;
                }
                if attempt + 1 < CLEAR_RETRIES {
                    tokio::time::sleep(CLEAR_RETRY_BACKOFF).await;
                }
            }
            eprintln!(
                "btmqttd: sprop: could not clear the superseded camera-sprop record; a later bare reflash may re-splice a stale value"
            );
            return;
        }
        Provision::Done => return,
        Provision::Listen => {}
    }

    // Bind the loopback RTP port. A transient failure (the port is briefly in use, tmpfs not ready)
    // must not kill learning, so log ONCE, back off, and retry until either we bind or shutdown.
    let socket = {
        let mut warned = false;
        loop {
            if stopping.load(Ordering::Relaxed) {
                return;
            }
            match tokio::net::UdpSocket::bind(SPROP_RTP_ADDR).await {
                Ok(s) => break s,
                Err(e) => {
                    if !warned {
                        eprintln!(
                            "btmqttd: sprop listener: cannot bind {SPROP_RTP_ADDR} ({e}); retrying"
                        );
                        warned = true;
                    }
                    tokio::time::sleep(BIND_RETRY).await;
                }
            }
        }
    };

    // Accumulate the SPS/PPS across datagrams: the panel may send them as two separate single-NAL
    // packets or bundled in one STAP-A. `buf` is generous for a param-set-carrying RTP packet.
    let mut buf = [0u8; 2048];
    let mut sps: Option<Vec<u8>> = None;
    let mut pps: Option<Vec<u8>> = None;
    let mut persist_warned = false;
    let mut recv_warned = false;
    while !stopping.load(Ordering::Relaxed) {
        match tokio::time::timeout(RECV_TIMEOUT, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _from))) => {
                let pkt = &buf[..n];
                if let Some(off) = rtp_payload_offset(pkt) {
                    // Trim any RTP padding first, so trailing pad bytes can't corrupt a STAP-A size
                    // walk or append garbage to a single NAL.
                    let end = rtp_payload_end(pkt, off);
                    collect_sps_pps(&pkt[off..end], &mut sps, &mut pps);
                }
                // Both parameter sets in hand ⇒ assemble the sprop value (SPS first, then PPS,
                // comma-separated, standard base64 with padding) and persist it.
                if let (Some(s), Some(p)) = (sps.as_ref(), pps.as_ref()) {
                    let value = format!("{},{}", b64(s), b64(p));
                    // Durability first: PERSIST the value on cfg/extra. This is what makes the learn
                    // durable (go2rtcd reassembles the runtime SDP from it at every boot), so success
                    // REQUIRES the persist write to land. persist is blocking → spawn_blocking.
                    let stored = {
                        let v = value.clone();
                        tokio::task::spawn_blocking(move || persist::store_camera_sprop(branch, &v))
                            .await
                            .unwrap_or(false)
                    };
                    if stored {
                        // Best-effort: patch the RUNTIME tmpfs SDP so THIS boot's next view is fast
                        // without waiting for a reboot. A failure here is NON-fatal — the value is
                        // already persisted, so the next boot's go2rtcd splices it in regardless; just
                        // log and still succeed.
                        match patch_sdp(&value).await {
                            // We just INSERTED sprop into a bare runtime SDP — the live go2rtc `exec:`
                            // producer already read that bare SDP and won't re-read it, so THIS view stays
                            // undecodable until the producer respawns (#146 fix B). Nudge it to respawn on
                            // the patched SDP so the current view self-heals; best-effort, non-fatal.
                            Ok(true) => respawn_go2rtc_producer().await,
                            // The runtime SDP already carried sprop (e.g. go2rtcd spliced a persisted value
                            // at boot), so the running producer already reads it — nothing to respawn.
                            Ok(false) => {}
                            Err(e) => eprintln!(
                                "btmqttd: sprop listener: persisted the value but could not patch the runtime SDP ({e}); it takes effect on the next boot"
                            ),
                        }
                        eprintln!(
                            "btmqttd: learned camera parameter sets (from a live view) — the on-device camera now resolves instantly"
                        );
                        return;
                    }
                    // The persist write failed (cfg/extra briefly unavailable). Log once and keep
                    // listening — the panel re-sends SPS/PPS periodically, so a later packet retries.
                    if !persist_warned {
                        eprintln!(
                            "btmqttd: sprop listener: failed to persist the learned parameter sets; will retry"
                        );
                        persist_warned = true;
                    }
                }
            }
            // A recv error on a bound loopback UDP socket is unusual; keep listening rather than exit,
            // but log ONCE and back off so a persistent error can't spin this into a busy loop on the
            // single-threaded runtime.
            Ok(Err(e)) => {
                if !recv_warned {
                    eprintln!("btmqttd: sprop listener: recv error ({e}); backing off and retrying");
                    recv_warned = true;
                }
                tokio::time::sleep(RECV_ERR_BACKOFF).await;
            }
            // Idle: no datagram this interval. Re-check ONLY the persisted value (an earlier boot's
            // learn on this branch) — the read-only `/etc` template can't change at runtime and was
            // already checked before the loop, so we skip that flash read here — then loop to re-check
            // `stopping`.
            Err(_timeout) => {
                if persisted_for_branch(branch).await {
                    return;
                }
            }
        }
    }
}

/// What sprop provisioning should do at startup, from two facts: whether the installer PRE-SEEDED a
/// `CameraSprop` into the read-only `/etc` template (`template_seeded`), and whether a value learned on
/// the CURRENT branch is already persisted (`learned_this_branch`). Pure, so the precedence is unit-tested.
///
/// A seeded template is AUTHORITATIVE for this image — go2rtcd uses the template's own sprop and ignores
/// the persisted record — so it SUPERSEDES any learned value, and we must CLEAR that record rather than
/// merely skip: a LATER reflash shipping a bare template would otherwise make go2rtcd splice the stale
/// value back in (it splices the persisted value ONLY when the template has none), and this gate would
/// then treat it as learned forever, corrupting video. So a seed always yields `ClearThenDone`,
/// EVEN when a same-branch value is learned. Otherwise a same-branch learned record means `Done` (go2rtcd
/// already spliced it into the runtime SDP at boot); anything else — nothing learned, or only a record for
/// a DIFFERENT branch after a `CAMERA_BRANCH` flip (task #41) — means `Listen` to learn the right sets.
enum Provision {
    ClearThenDone,
    Done,
    Listen,
}
fn provision_action(template_seeded: bool, learned_this_branch: bool) -> Provision {
    if template_seeded {
        Provision::ClearThenDone
    } else if learned_this_branch {
        Provision::Done
    } else {
        Provision::Listen
    }
}

/// True iff a value learned on THIS `branch` is already persisted on cfg/extra (the durable source of
/// truth). Split out so the idle re-check can poll JUST this — the read-only `/etc` template is immutable
/// at runtime (a seeded template makes `run` return before the loop), so the per-second idle path skips
/// that flash read. Blocking read → spawn_blocking.
async fn persisted_for_branch(branch: u8) -> bool {
    tokio::task::spawn_blocking(move || {
        matches!(persist::read_camera_sprop(), Some((b, _)) if b == branch)
    })
    .await
    .unwrap_or(false)
}

/// True iff the read-only `/etc` template SDP already carries an operator-supplied
/// `sprop-parameter-sets` (an install-time `CameraSprop`) — then there is nothing to learn. A
/// missing/unreadable template reads as "no sprop" so the listen proceeds normally.
async fn template_has_sprop() -> bool {
    matches!(tokio::fs::read_to_string(TEMPLATE_SDP_PATH).await, Ok(s) if has_sprop(&s))
}

/// Pure `sprop-parameter-sets=` presence check (factored so the provisioned-detection is unit-testable
/// without touching the fixed `/etc` template path).
fn has_sprop(sdp: &str) -> bool {
    sdp.contains("sprop-parameter-sets=")
}

/// True iff the RUNTIME tmpfs SDP go2rtc actually reads ([`SDP_PATH`]) currently carries
/// `sprop-parameter-sets`. This — NOT the persisted record — is what tells `hold.rs` whether go2rtc's
/// `-c:v copy` ffmpeg will resolve the video FAST (parameter sets already in the SDP ⇒ loopback publisher
/// within ~a second) or must wait for the panel's next in-band SPS/PPS (a cold lock-on, up to ~a keyframe
/// interval). It deliberately reads the runtime file rather than the persist record because the two can
/// diverge for one boot: a fresh learn PERSISTS the value durably but only BEST-EFFORT patches this boot's
/// runtime SDP, so if that patch failed the value is present for the NEXT boot yet absent from the SDP
/// go2rtc reads NOW — and the cold-lock-on grace must still apply until the next reboot splices it in.
/// A missing/unreadable runtime SDP reads as "no sprop" (assume cold). `pub(crate)` for `hold.rs`.
pub(crate) async fn runtime_sdp_has_sprop() -> bool {
    matches!(tokio::fs::read_to_string(SDP_PATH).await, Ok(s) if has_sprop(&s))
}

/// Compute the offset of the RTP payload (the bytes AFTER the fixed header, CSRC list and any header
/// extension) for an RTP packet. Returns `None` for anything that isn't a well-formed RTPv2 packet or
/// whose declared header would run past the packet. Pure — no I/O — so it is unit-tested directly.
fn rtp_payload_offset(pkt: &[u8]) -> Option<usize> {
    if pkt.len() < 12 {
        return None;
    }
    // Byte 0: V(2) P(1) X(1) CC(4). We require version 2.
    if pkt[0] >> 6 != 2 {
        return None;
    }
    let cc = (pkt[0] & 0x0F) as usize;
    let x = (pkt[0] >> 4) & 1;
    let base = 12 + 4 * cc;
    let header = if x == 1 {
        // Extension header: 16-bit profile + 16-bit length (in 32-bit words), then that many words.
        if pkt.len() < base + 4 {
            return None;
        }
        let ext_len = u16::from_be_bytes([pkt[base + 2], pkt[base + 3]]) as usize;
        base + 4 + 4 * ext_len
    } else {
        base
    };
    if header <= pkt.len() {
        Some(header)
    } else {
        None
    }
}

/// The END index of the H.264 payload within an RTP packet, trimming any RTP PADDING. When the RTP
/// Padding bit (`pkt[0] & 0x20`) is set, the LAST byte is the padding length P and the final P bytes
/// (that length byte included) are padding to ignore. `off` is the payload start from
/// [`rtp_payload_offset`]. A malformed pad count (0, or larger than the available payload) is treated as
/// "no valid padding" and the full length is returned, so a bad packet yields no NAL rather than a bad
/// parse. Pure — no I/O.
fn rtp_payload_end(pkt: &[u8], off: usize) -> usize {
    let len = pkt.len();
    if len > off && pkt[0] & 0x20 != 0 {
        let pad = pkt[len - 1] as usize;
        if pad >= 1 && pad <= len - off {
            return len - pad;
        }
    }
    len
}

/// Extract H.264 SPS (NAL type 7) and PPS (NAL type 8) from an RTP payload (the bytes AFTER the RTP
/// header). Accumulates first-wins into `sps`/`pps` — a second SPS/PPS never overwrites a set one.
/// Handles a single NAL unit (types 1..=23) and a STAP-A aggregation (type 24); FU-A and other packet
/// types are ignored (SPS/PPS are never fragmented — they fit one packet). The stored NAL bytes INCLUDE
/// the NAL header byte and carry NO Annex-B start code (RTP already strips start codes) — exactly what
/// sprop base64 expects. Pure — no I/O — so it is unit-tested directly.
fn collect_sps_pps(payload: &[u8], sps: &mut Option<Vec<u8>>, pps: &mut Option<Vec<u8>>) {
    if payload.is_empty() {
        return;
    }
    match payload[0] & 0x1F {
        // Single NAL unit packet: the payload IS the NAL (header byte + RBSP).
        1..=23 => set_param(payload, sps, pps),
        // STAP-A: 1-byte STAP header, then a series of (16-bit size, NAL) records.
        24 => {
            let len = payload.len();
            let mut i = 1;
            while i + 2 <= len {
                let size = u16::from_be_bytes([payload[i], payload[i + 1]]) as usize;
                i += 2;
                // A zero-size record can't hold even a NAL header, and `i += size` would not advance — a
                // malformed STAP-A (size 0) would spin this loop forever. Stop the walk on a zero-size or
                // out-of-bounds record. The listener is loopback-fed, but must not hang on a bad
                // packet.
                if size == 0 || i + size > len {
                    break;
                }
                set_param(&payload[i..i + size], sps, pps);
                i += size;
            }
        }
        _ => {}
    }
}

/// First-wins record of a single NAL into `sps`/`pps` by its NAL type (7 = SPS, 8 = PPS). Empty and
/// non-parameter NALs are ignored.
fn set_param(nal: &[u8], sps: &mut Option<Vec<u8>>, pps: &mut Option<Vec<u8>>) {
    match nal.first() {
        Some(&b) if b & 0x1F == 7 && sps.is_none() => *sps = Some(nal.to_vec()),
        Some(&b) if b & 0x1F == 8 && pps.is_none() => *pps = Some(nal.to_vec()),
        _ => {}
    }
}

/// Standard base64 (RFC 4648 alphabet, `=` padding, no whitespace). A tiny internal encoder so the
/// daemon needs no external base64 crate — keeping the dependency set and the reproducible build
/// unchanged. Used to encode the raw SPS/PPS NAL bytes into the sprop value.
fn b64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 0x3F) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3F) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Splice a learned sprop into the RUNTIME tmpfs SDP's ([`SDP_PATH`]) fmtp line and write it back
/// atomically (temp + rename, 0644 — the SDP carries no secret). Returns `Ok(true)` when it actually
/// INSERTED sprop, `Ok(false)` when it was a no-op because sprop is already present (e.g. go2rtcd already
/// spliced a persisted value at boot) — the caller respawns the go2rtc producer ONLY on a real insert
/// (#146 fix B), so a no-op never disturbs a producer that already reads the parameter sets. This is a
/// best-effort fast-path for the current boot; durability comes from the persisted value, not this write.
async fn patch_sdp(sprop: &str) -> std::io::Result<bool> {
    patch_sdp_in(SDP_PATH, sprop).await
}

/// [`patch_sdp`] with the target path injected, so the insert/no-op/atomic-rename behaviour is unit-tested
/// against a temp file rather than the fixed runtime path.
async fn patch_sdp_in(path: &str, sprop: &str) -> std::io::Result<bool> {
    let sdp = tokio::fs::read_to_string(path).await?;
    if sdp.contains("sprop-parameter-sets=") {
        return Ok(false);
    }
    if !sdp.contains(FMTP_ANCHOR) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "go2rtc SDP has no packetization-mode fmtp to patch",
        ));
    }
    let patched = sdp.replacen(
        FMTP_ANCHOR,
        &format!("{FMTP_ANCHOR}sprop-parameter-sets={sprop};"),
        1,
    );
    // Write a temp file in the same directory, fsync, then rename over the target so a crash never
    // leaves go2rtc a half-written SDP.
    let tmp = format!("{path}.tmp.{}", std::process::id());
    {
        let mut f = tokio::fs::File::create(&tmp).await?;
        f.write_all(patched.as_bytes()).await?;
        f.flush().await?;
        f.sync_all().await?;
    }
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).await?;
    tokio::fs::rename(&tmp, path).await?;
    Ok(true)
}

/// Nudge go2rtc to re-read a freshly-patched runtime SDP by terminating its `exec:` ffmpeg producer
/// (issue #146, fix B). That producer read the BARE SDP at spawn and never re-reads it, so the current
/// view stays undecodable until it respawns — and go2rtc does NOT restart an `exec:` producer itself
/// (v1.9.14). SIGTERM it: the stream drops, Home Assistant's camera reconnects, and go2rtc runs a fresh
/// ffmpeg that opens the PATCHED SDP with the parameter sets from the first frame. Best-effort and
/// NON-fatal — if no producer is found or the signal fails, the persisted value still fixes the next
/// open/boot. Touches no firewall (#145). Blocking `/proc` scan → `spawn_blocking`.
async fn respawn_go2rtc_producer() {
    let pids = tokio::task::spawn_blocking(|| find_sdp_producer_pids(SDP_PATH))
        .await
        .unwrap_or_default();
    if pids.is_empty() {
        eprintln!(
            "btmqttd: sprop: no running go2rtc exec producer to respawn; the patched SDP takes effect on its next start"
        );
        return;
    }
    for pid in pids {
        // SIGTERM lets ffmpeg exit cleanly so go2rtc tears the producer down tidily. `kill` is the only
        // way to make a producer that reads its input file ONLY at spawn pick up the patched SDP.
        if unsafe { libc::kill(pid, libc::SIGTERM) } == 0 {
            eprintln!(
                "btmqttd: sprop: signalled the go2rtc exec producer (pid {pid}) to re-read the patched SDP"
            );
        } else {
            // Non-fatal (the persisted value still fixes the next open/boot), but log with the errno so a
            // "no self-heal" report can be told apart from "no producer found": ESRCH means the producer
            // exited between the /proc scan and here (already gone — its respawn will read the patch),
            // EPERM a permission problem. Read last_os_error() immediately, before any other syscall.
            eprintln!(
                "btmqttd: sprop: could not signal go2rtc exec producer (pid {pid}): {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

/// Scan `/proc` for the PIDs of the go2rtc `exec:` ffmpeg producer(s) reading OUR runtime SDP, identified
/// by [`cmdline_is_sdp_producer`]. Blocking (`read_dir` + per-pid `read`). Only numeric `/proc/<pid>`
/// entries are considered; an unreadable `/proc` or cmdline is skipped (best-effort).
fn find_sdp_producer_pids(sdp_path: &str) -> Vec<libc::pid_t> {
    let mut pids = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return pids;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue; // not a numeric pid directory
        };
        if let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) {
            if cmdline_is_sdp_producer(&cmdline, sdp_path) {
                pids.push(pid as libc::pid_t);
            }
        }
    }
    pids
}

/// True iff a raw `/proc/<pid>/cmdline` (arguments NUL-separated) is the go2rtc `exec:` ffmpeg producer
/// reading OUR runtime SDP — i.e. one of its arguments is EXACTLY `sdp_path` (its `-i <sdp>` input). The
/// idle/ring capture ffmpeg reads an `rtsp://…/doorbell` URL and go2rtc itself takes `-config <yaml>`, so
/// neither carries the `.sdp` file path as an argument; the EXACT-argument match (not a substring) also
/// rejects a lookalike like `<sdp>.bak`. Pure — unit-tested.
fn cmdline_is_sdp_producer(cmdline: &[u8], sdp_path: &str) -> bool {
    cmdline.split(|&b| b == 0).any(|arg| arg == sdp_path.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_template_counts_as_provisioned() {
        // An installer-supplied CameraSprop lands in the template's fmtp line; has_sprop must detect it
        // so a pre-seeded image skips the listen (already_learned via template_has_sprop). A bare
        // template (no sprop) must NOT — the listen still runs to learn it.
        let seeded = "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0JAHqaAoD2Q,aM48gAA=;profile-level-id=42801f\n";
        assert!(has_sprop(seeded));
        let bare = "a=fmtp:96 packetization-mode=1;profile-level-id=42801f\n";
        assert!(!has_sprop(bare));
    }

    #[test]
    fn provision_action_seed_supersedes_learned() {
        use Provision::*;
        // A seeded template always wins and CLEARS any stale learned record — even when a same-branch
        // value is already learned. That is the case that would otherwise corrupt video after a
        // seed-then-bare reflash (go2rtcd re-splices the old value once the template is bare again).
        assert!(matches!(provision_action(true, true), ClearThenDone));
        assert!(matches!(provision_action(true, false), ClearThenDone));
        // No seed: a same-branch learned record is Done (go2rtcd already spliced it); nothing learned or a
        // different-branch record ⇒ Listen to learn the right sets.
        assert!(matches!(provision_action(false, true), Done));
        assert!(matches!(provision_action(false, false), Listen));
    }

    #[test]
    fn patch_inserts_sprop_in_installer_order() {
        // Verify the in-memory splice matches BuildOnDeviceSdp's fmtp order:
        // packetization-mode=1;sprop-parameter-sets=...;profile-level-id=...
        let base = "a=fmtp:96 packetization-mode=1;profile-level-id=42801f\n";
        let patched = base.replacen(
            FMTP_ANCHOR,
            &format!("{FMTP_ANCHOR}sprop-parameter-sets=AAA,BBB=;"),
            1,
        );
        assert_eq!(
            patched,
            "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=AAA,BBB=;profile-level-id=42801f\n"
        );
    }

    // --- RTP header parsing ---

    #[test]
    fn rtp_payload_offset_basic_header() {
        // V=2, P=0, X=0, CC=0 ⇒ 12-byte fixed header, payload starts at 12.
        let mut pkt = [0u8; 20];
        pkt[0] = 0x80; // version 2, no padding, no extension, cc 0
        assert_eq!(rtp_payload_offset(&pkt), Some(12));
    }

    #[test]
    fn rtp_payload_offset_with_csrc() {
        // CC=2 ⇒ two 4-byte CSRC entries after the fixed header, payload at 12 + 8 = 20.
        let pkt = [0u8; 24];
        let mut pkt = pkt;
        pkt[0] = 0x82; // version 2, cc 2
        assert_eq!(rtp_payload_offset(&pkt), Some(20));
    }

    #[test]
    fn rtp_payload_offset_with_extension() {
        // V=2, X=1, CC=0. Extension header at byte 12: profile(2) + length(2 words) + 2*4 bytes,
        // so payload starts at 12 + 4 + 8 = 24.
        let mut pkt = [0u8; 40];
        pkt[0] = 0x90; // version 2, extension bit set, cc 0
        pkt[14] = 0x00; // ext length high byte
        pkt[15] = 0x02; // ext length = 2 words
        assert_eq!(rtp_payload_offset(&pkt), Some(24));
    }

    #[test]
    fn rtp_payload_offset_rejects_short_and_bad_version() {
        assert_eq!(rtp_payload_offset(&[0x80; 8]), None); // < 12 bytes
        let mut pkt = [0u8; 20];
        pkt[0] = 0x40; // version 1 (top two bits 01) ⇒ rejected
        assert_eq!(rtp_payload_offset(&pkt), None);
    }

    #[test]
    fn rtp_payload_end_trims_rtp_padding() {
        // 12-byte header with V=2, P=1 (byte0 = 0xA0), 4 payload bytes of which the last 2 are padding
        // (the final byte is the pad count = 2). The payload end must trim to the 2 real bytes.
        let mut padded = vec![0xA0u8, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        padded.extend_from_slice(&[0x67, 0x42, 0x00, 0x02]);
        assert_eq!(rtp_payload_end(&padded, 12), 14);
        // P=0 (byte0 = 0x80): no padding ⇒ full length.
        let mut plain = vec![0x80u8, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        plain.extend_from_slice(&[0x67, 0x42]);
        assert_eq!(rtp_payload_end(&plain, 12), plain.len());
        // Malformed pad count (larger than the available payload) ⇒ treated as no padding, full length.
        let mut bad = vec![0xA0u8, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        bad.extend_from_slice(&[0x67, 0xFF]);
        assert_eq!(rtp_payload_end(&bad, 12), bad.len());
    }

    // --- NAL collection ---

    #[test]
    fn collect_single_sps_and_pps() {
        let mut sps = None;
        let mut pps = None;
        // A type-7 (SPS) single NAL: header byte 0x67 (F=0, NRI=3, type=7), then RBSP.
        collect_sps_pps(&[0x67, 0x11, 0x22], &mut sps, &mut pps);
        assert_eq!(sps.as_deref(), Some(&[0x67, 0x11, 0x22][..]));
        assert!(pps.is_none());
        // A type-8 (PPS) single NAL: header byte 0x68.
        collect_sps_pps(&[0x68, 0xAB], &mut sps, &mut pps);
        assert_eq!(pps.as_deref(), Some(&[0x68, 0xAB][..]));
    }

    #[test]
    fn collect_stap_a_bundles_both() {
        let mut sps = None;
        let mut pps = None;
        // STAP-A: header 0x78 (type 24), then (size=3, SPS 0x67 0x11 0x22), (size=2, PPS 0x68 0xAB).
        let payload = [
            0x78, // STAP-A header
            0x00, 0x03, 0x67, 0x11, 0x22, // SPS record
            0x00, 0x02, 0x68, 0xAB, // PPS record
        ];
        collect_sps_pps(&payload, &mut sps, &mut pps);
        assert_eq!(sps.as_deref(), Some(&[0x67, 0x11, 0x22][..]));
        assert_eq!(pps.as_deref(), Some(&[0x68, 0xAB][..]));
    }

    #[test]
    fn collect_stap_a_zero_size_record_terminates() {
        // A malformed STAP-A whose record size is 0 must not spin forever: `i += size` would never advance.
        // The walk must terminate (this test would hang without the size==0 guard), extracting nothing.
        let mut sps = None;
        let mut pps = None;
        let payload = [0x78, 0x00, 0x00]; // STAP-A header, then a single (size=0) record
        collect_sps_pps(&payload, &mut sps, &mut pps);
        assert!(sps.is_none());
        assert!(pps.is_none());
        // A zero-size record part-way through also stops the walk cleanly (no hang, no panic).
        let mut sps2 = None;
        let mut pps2 = None;
        let payload2 = [
            0x78, // STAP-A header
            0x00, 0x03, 0x67, 0x11, 0x22, // valid SPS record
            0x00, 0x00, // zero-size record ⇒ stop
            0x00, 0x02, 0x68, 0xAB, // never reached
        ];
        collect_sps_pps(&payload2, &mut sps2, &mut pps2);
        assert_eq!(sps2.as_deref(), Some(&[0x67, 0x11, 0x22][..]));
        assert!(pps2.is_none());
    }

    #[test]
    fn collect_ignores_non_param_nal() {
        let mut sps = None;
        let mut pps = None;
        // Type 1 (non-IDR slice): header byte 0x61 ⇒ neither SPS nor PPS.
        collect_sps_pps(&[0x61, 0x00, 0x00], &mut sps, &mut pps);
        assert!(sps.is_none());
        assert!(pps.is_none());
        // Empty payload is a no-op.
        collect_sps_pps(&[], &mut sps, &mut pps);
        assert!(sps.is_none());
        assert!(pps.is_none());
    }

    #[test]
    fn collect_is_first_wins() {
        let mut sps = None;
        let mut pps = None;
        collect_sps_pps(&[0x67, 0x01], &mut sps, &mut pps);
        // A second SPS must NOT overwrite the first.
        collect_sps_pps(&[0x67, 0x02], &mut sps, &mut pps);
        assert_eq!(sps.as_deref(), Some(&[0x67, 0x01][..]));
    }

    // --- base64 ---

    #[test]
    fn b64_known_vectors() {
        assert_eq!(b64(b"Man"), "TWFu");
        assert_eq!(b64(b"Ma"), "TWE=");
        assert_eq!(b64(b"M"), "TQ==");
        assert_eq!(b64(b""), "");
    }

    // --- end-to-end assembly ---

    #[test]
    fn assembled_value_encodes_sps_then_pps_and_patches_in_order() {
        // Fabricated SPS/PPS NAL byte sequences (header byte + RBSP), as extracted from the RTP.
        let sps = [0x67u8, 0x42, 0x80, 0x1f];
        let pps = [0x68u8, 0xce, 0x3c, 0x80];
        let value = format!("{},{}", b64(&sps), b64(&pps));
        assert_eq!(value, format!("{},{}", b64(&sps), b64(&pps)));
        // Splicing it through patch_sdp's logic yields the installer-order fmtp line.
        let base = "a=fmtp:96 packetization-mode=1;profile-level-id=42801f\n";
        let patched = base.replacen(
            FMTP_ANCHOR,
            &format!("{FMTP_ANCHOR}sprop-parameter-sets={value};"),
            1,
        );
        assert_eq!(
            patched,
            format!(
                "a=fmtp:96 packetization-mode=1;sprop-parameter-sets={value};profile-level-id=42801f\n"
            )
        );
    }

    // --- go2rtc exec producer identification (issue #146, fix B) ---

    #[test]
    fn cmdline_matches_only_the_sdp_input_producer() {
        let sdp = SDP_PATH; // "/var/run/btmqttd/doorbell.sdp"
        // The go2rtc exec producer: ffmpeg with `-i <runtime SDP>` — one arg is EXACTLY the SDP path.
        let producer = [
            b"/usr/sbin/ffmpeg".as_ref(),
            b"-hide_banner",
            b"-protocol_whitelist",
            b"file,udp,rtp",
            b"-i",
            sdp.as_bytes(),
            b"-an",
            b"-c:v",
            b"copy",
        ]
        .join(&0u8);
        assert!(cmdline_is_sdp_producer(&producer, sdp));

        // The idle/ring capture ffmpeg reads an rtsp:// URL, never the .sdp FILE — must NOT match.
        let capture = [
            b"/usr/sbin/ffmpeg".as_ref(),
            b"-rtsp_transport",
            b"tcp",
            b"-i",
            b"rtsp://camera:p@127.0.0.1:8554/doorbell",
            b"-frames:v",
            b"1",
        ]
        .join(&0u8);
        assert!(!cmdline_is_sdp_producer(&capture, sdp));

        // go2rtc itself takes -config <yaml>, not the SDP path — must NOT match.
        let go2rtc = [
            b"/usr/sbin/go2rtc".as_ref(),
            b"-config",
            b"/etc/btmqttd/go2rtc/go2rtc.yaml",
        ]
        .join(&0u8);
        assert!(!cmdline_is_sdp_producer(&go2rtc, sdp));

        // An EXACT-argument match, not a substring: a lookalike arg must NOT match.
        let lookalike = [b"/usr/sbin/ffmpeg".as_ref(), b"-i", b"/var/run/btmqttd/doorbell.sdp.bak"]
            .join(&0u8);
        assert!(!cmdline_is_sdp_producer(&lookalike, sdp));

        // Empty cmdline (e.g. a kernel thread) never matches.
        assert!(!cmdline_is_sdp_producer(&[], sdp));
    }

    #[tokio::test]
    async fn patch_sdp_in_inserts_once_then_is_a_noop() {
        // Unique temp target so the atomic temp+rename runs against a real file without the fixed path.
        let path = std::env::temp_dir()
            .join(format!("btmqttd-sprop-test-{}.sdp", std::process::id()))
            .to_string_lossy()
            .into_owned();
        let bare = "v=0\na=fmtp:96 packetization-mode=1;profile-level-id=42801f\na=recvonly\n";
        tokio::fs::write(&path, bare).await.unwrap();

        // First patch INSERTS and reports it (true), so the caller respawns the stale producer.
        assert!(patch_sdp_in(&path, "AAA,BBB=").await.unwrap(), "first patch inserts sprop");
        let after = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(
            after,
            "v=0\na=fmtp:96 packetization-mode=1;sprop-parameter-sets=AAA,BBB=;profile-level-id=42801f\na=recvonly\n"
        );

        // Second patch is a NO-OP (sprop already present) and reports false, so NO producer respawn fires.
        assert!(!patch_sdp_in(&path, "CCC,DDD=").await.unwrap(), "second patch is a no-op");
        assert_eq!(tokio::fs::read_to_string(&path).await.unwrap(), after, "a no-op leaves the SDP unchanged");

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn patch_sdp_in_errors_without_an_fmtp_anchor() {
        let path = std::env::temp_dir()
            .join(format!("btmqttd-sprop-noanchor-{}.sdp", std::process::id()))
            .to_string_lossy()
            .into_owned();
        tokio::fs::write(&path, "v=0\nc=IN IP4 127.0.0.2\n").await.unwrap();
        // No `packetization-mode=1;` to splice after ⇒ Err (nothing written), never a false "inserted".
        assert!(patch_sdp_in(&path, "AAA,BBB=").await.is_err());
        let _ = tokio::fs::remove_file(&path).await;
    }
}
