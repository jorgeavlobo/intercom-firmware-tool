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

/// How long a single `recv_from` waits before we loop back to re-check `stopping` / `already_learned`.
/// Short enough that a shutdown (or an operator pre-seed) is observed promptly while a view is idle.
const RECV_TIMEOUT: Duration = Duration::from_secs(1);
/// Backoff between retries when binding [`SPROP_RTP_ADDR`] fails (e.g. the port is briefly in use). A
/// transient bind failure must not kill learning, so we sleep and retry rather than return.
const BIND_RETRY: Duration = Duration::from_secs(5);
/// Backoff after a `recv_from` ERROR (as opposed to a timeout). A recv error on a bound loopback UDP
/// socket is unusual, but if one recurs we must not spin: sleeping here keeps a persistent error from
/// pegging the single-threaded runtime.
const RECV_ERR_BACKOFF: Duration = Duration::from_secs(1);

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
    // Already learned on a prior boot FOR THIS BRANCH (the VALUE persisted on cfg/extra), or an
    // operator pre-seeded the template ⇒ nothing to do. The persist file — not the runtime SDP — is the
    // source of truth: go2rtcd already spliced a matching-branch value into the runtime tmpfs SDP at
    // boot. Idempotent guard so the steady state after the first learn is a single cheap file read at
    // startup.
    if already_learned(branch).await {
        return;
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
                        if let Err(e) = patch_sdp(&value).await {
                            eprintln!(
                                "btmqttd: sprop listener: persisted the value but could not patch the runtime SDP ({e}); it takes effect on the next boot"
                            );
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

/// True iff there is nothing to provision FOR THE CURRENT `branch`: EITHER a value learned on this same
/// branch was persisted on a prior boot (the durable source of truth on cfg/extra), OR the installer
/// PRE-SEEDED a `CameraSprop` into the read-only `/etc` template SDP (an operator-supplied value —
/// nothing to learn). A value persisted for a DIFFERENT branch (a reflash that flipped `CAMERA_BRANCH`)
/// reads as "not provisioned", so the listen re-learns the correct parameter sets and OVERWRITES the
/// stale record on the next learn; go2rtcd independently refuses to splice a mismatched-branch value
/// (task #41). A missing/unreadable persist file AND template also reads as "not provisioned" so the
/// listen continues. Both reads are blocking → spawn_blocking.
async fn already_learned(branch: u8) -> bool {
    persisted_for_branch(branch).await || template_has_sprop().await
}

/// True iff a value learned on THIS `branch` is already persisted on cfg/extra (the durable source of
/// truth). Split out from [`already_learned`] so the idle re-check can poll JUST this — the read-only
/// `/etc` template is immutable at runtime (a set template makes `run` return before the loop), so the
/// per-second idle path skips that flash read. Blocking read → spawn_blocking.
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
                if i + size > len {
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
/// atomically (temp + rename, 0644 — the SDP carries no secret). The temp file sits in the SAME tmpfs
/// dir as the target, so the rename is atomic. Idempotent: a no-op if sprop is already present (e.g.
/// go2rtcd already spliced a persisted value at boot). This is a best-effort fast-path for the current
/// boot; durability comes from the persisted value, not from this write.
async fn patch_sdp(sprop: &str) -> std::io::Result<()> {
    let sdp = tokio::fs::read_to_string(SDP_PATH).await?;
    if sdp.contains("sprop-parameter-sets=") {
        return Ok(());
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
    let tmp = format!("{SDP_PATH}.tmp.{}", std::process::id());
    {
        let mut f = tokio::fs::File::create(&tmp).await?;
        f.write_all(patched.as_bytes()).await?;
        f.flush().await?;
        f.sync_all().await?;
    }
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).await?;
    tokio::fs::rename(&tmp, SDP_PATH).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_template_counts_as_provisioned() {
        // An installer-supplied CameraSprop lands in the template's fmtp line; has_sprop must detect it
        // so a pre-seeded image skips the listen (already_learned via template_has_sprop). A bare
        // template (no sprop) must NOT — the listen still runs to learn it (CodeRabbit).
        let seeded = "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0JAHqaAoD2Q,aM48gAA=;profile-level-id=42801f\n";
        assert!(has_sprop(seeded));
        let bare = "a=fmtp:96 packetization-mode=1;profile-level-id=42801f\n";
        assert!(!has_sprop(bare));
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
}
