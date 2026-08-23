//! Bridge update check (issue #114, second half): periodically fetch a tiny version
//! manifest from GitHub over HTTPS, compare it to this daemon's own compiled-in version,
//! and publish `{installed_version, latest_version}` to a retained MQTT topic that backs a
//! Home Assistant `update` entity. The panel can't self-flash (firmware is applied over
//! USB), so this is NOTIFY-ONLY: it tells the operator a newer bridge exists so they can
//! reflash — there is no install command.
//!
//! Design notes:
//!   * INSTALLED version is `env!("CARGO_PKG_VERSION")` — the same value baked into the HA
//!     discovery `device` block's `sw_version` (the installer mirrors it in
//!     `PayloadBinaries.BridgeVersion`, kept in step by `btmqttd-provenance.yml`).
//!   * LATEST version comes from `UPDATE_MANIFEST_URL` (default: the repo's
//!     `.well-known/bridge.json` on `raw.githubusercontent.com`). Until a fetch succeeds —
//!     or whenever one fails — we report `latest = installed` (i.e. "up to date"), so a
//!     network hiccup never produces a false "update available". FAIL-OPEN throughout.
//!   * TLS trust uses the device's own root store (`rustls-native-certs`, already pulled by
//!     rumqttc), the same anchors the firmware's `curl` validates against — no bundled
//!     roots (keeps the dependency tree copyleft-free per THIRD_PARTY.md).
//!   * OPT-OUT: `UPDATE_CHECK=0` disables the task entirely (no network, no publish); the
//!     installer then also omits the discovery entity.
//!
//! Only the standard library HTTP surface we need is hand-written (a single GET of a small
//! static JSON from a host we control) — no HTTP-client crate is added.

use std::sync::Arc;
use std::time::Duration;

use rumqttc::{AsyncClient, QoS};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

use crate::config::Config;

/// This daemon's own SemVer, compiled in from Cargo.toml (the single source of truth the
/// installer mirrors as `PayloadBinaries.BridgeVersion`).
pub const INSTALLED_VERSION: &str = env!("CARGO_PKG_VERSION");

/// How often to re-check after the first check (once a day is plenty for a reflash nudge).
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// Small settle delay after start so the check doesn't compete with the connect/birth burst.
const INITIAL_DELAY: Duration = Duration::from_secs(60);
/// Per-phase and overall network timeouts — a background nicety must never hang the runtime.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const OVERALL_TIMEOUT: Duration = Duration::from_secs(20);
/// Hard cap on the response we will buffer (the manifest is a few hundred bytes; this guards
/// against a hostile/oversized body).
const MAX_RESPONSE: usize = 64 * 1024;

/// The last successfully fetched latest version (None until the first success). Shared with
/// the birth sequence so a reconnect re-asserts the retained topic from cache.
pub type LatestVersion = Arc<Mutex<Option<String>>>;

/// Build the retained JSON payload HA's `update` entity reads: it parses these keys directly.
fn payload(latest: &str) -> String {
    // Serialize through serde_json so BOTH values are correctly escaped — belt-and-suspenders
    // with `is_plausible_semver` (which already rejects characters needing escaping): the
    // published state is always valid JSON even if a future caller relaxes validation.
    serde_json::json!({
        "installed_version": INSTALLED_VERSION,
        "latest_version": latest,
    })
    .to_string()
}

/// Publish the installed/latest pair retained (QoS 0, like the HA discovery configs). Best
/// effort: a publish error just means the eventloop is gone and a reconnect will re-announce.
async fn publish(cfg: &Config, client: &AsyncClient, latest: &str) {
    if let Err(e) = client
        .publish(&cfg.topic_update, QoS::AtMostOnce, true, payload(latest).into_bytes())
        .await
    {
        eprintln!("btmqttd: update: publish to {} failed: {e}", cfg.topic_update);
    }
}

/// Re-assert the retained update topic from cache during the birth sequence (so a broker that
/// restarted, dropping its retained set, is reconciled on reconnect). Reports `latest =
/// installed` when no successful fetch has happened yet — never a false "update available".
pub async fn announce(cfg: &Config, client: &AsyncClient, latest: &LatestVersion) {
    if !cfg.update_check {
        return;
    }
    let latest = latest.lock().await.clone();
    publish(cfg, client, latest.as_deref().unwrap_or(INSTALLED_VERSION)).await;
}

/// The background task: check now (after a short settle), then once a day. On each successful
/// fetch, cache the value and publish; on failure, keep the previous cache (fail-open).
pub async fn run(cfg: Arc<Config>, client: AsyncClient, latest: LatestVersion) {
    if !cfg.update_check {
        return; // opt-out: no network, no publish (the installer also omits the entity)
    }
    tokio::time::sleep(INITIAL_DELAY).await;
    loop {
        match check_once(&cfg).await {
            Ok(v) => {
                *latest.lock().await = Some(v.clone());
                publish(&cfg, &client, &v).await;
            }
            Err(e) => {
                // Fail-open: log and keep whatever we last knew (or "up to date").
                eprintln!("btmqttd: update: check failed (will retry): {e}");
            }
        }
        tokio::time::sleep(CHECK_INTERVAL).await;
    }
}

/// One full check: fetch the manifest, parse it, validate the version. Wrapped in an overall
/// timeout so a stuck socket can't wedge the (daily) loop.
async fn check_once(cfg: &Config) -> Result<String, String> {
    let body = timeout(OVERALL_TIMEOUT, fetch(&cfg.update_manifest_url))
        .await
        .map_err(|_| "timed out".to_string())??;
    let latest = parse_latest_version(&body)?;
    if !is_plausible_semver(&latest) {
        return Err(format!("manifest latestVersion is not a plausible SemVer: {latest:?}"));
    }
    Ok(latest)
}

/// Extract `latestVersion` from the manifest JSON. Deliberately tolerant of extra fields
/// (schemaVersion, comments) — we only need the one string.
fn parse_latest_version(body: &str) -> Result<String, String> {
    let doc: serde_json::Value =
        serde_json::from_str(body).map_err(|e| format!("manifest is not JSON: {e}"))?;
    doc.get("latestVersion")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| "manifest has no string latestVersion".to_string())
}

/// A dependency-free SemVer plausibility check validating the WHOLE string — not just the
/// numeric core — so no stray character (e.g. a quote in `1.2.3-"`) can reach `payload()`.
/// `MAJOR.MINOR.PATCH` (each part non-empty ASCII digits) with an optional `-prerelease` and
/// `+build`, each a dot-separated run of non-empty `[0-9A-Za-z-]` identifiers (SemVer §9/§10).
/// Not a full spec validator (it doesn't reject a numeric prerelease identifier with a leading
/// zero), but strict enough that we never publish arbitrary text as a version; HA does the real
/// installed-vs-latest comparison on the well-formed value.
fn is_plausible_semver(v: &str) -> bool {
    // Peel `+build` first (it follows any `-prerelease`), then `-prerelease` off the remainder.
    let (rest, build) = match v.split_once('+') {
        Some((r, b)) => (r, Some(b)),
        None => (v, None),
    };
    let (core, pre) = match rest.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (rest, None),
    };

    let core_ok = {
        let parts: Vec<&str> = core.split('.').collect();
        parts.len() == 3
            && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    };
    // Dot-separated identifiers, each non-empty and only [0-9A-Za-z-].
    let idents_ok = |s: &str| {
        s.split('.')
            .all(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
    };
    core_ok && pre.is_none_or(idents_ok) && build.is_none_or(idents_ok)
}

/// Fetch the manifest over HTTPS. Parses `https://host/path` (port 443 only), does a single
/// GET with `Connection: close`, and returns the response body. Non-2xx, redirects, and
/// unexpected transfer encodings are treated as errors (fail-open at the caller). We control
/// the endpoint (a small static file on raw.githubusercontent.com), so this stays minimal.
async fn fetch(url: &str) -> Result<String, String> {
    let (host, path) = split_https_url(url)?;

    let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect((host.as_str(), 443)))
        .await
        .map_err(|_| format!("connect to {host}:443 timed out"))?
        .map_err(|e| format!("connect to {host}:443: {e}"))?;

    let connector = tls_connector()?;
    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|e| format!("invalid server name {host:?}: {e}"))?;
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("TLS handshake with {host}: {e}"))?;

    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: btmqttd-update-check\r\n\
         Accept: application/json\r\n\
         Connection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("sending request: {e}"))?;
    stream.flush().await.map_err(|e| format!("flushing request: {e}"))?;

    // Read the whole (small) response, capped. We asked for `Connection: close`, so EOF marks
    // the end of the body.
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await.map_err(|e| format!("reading response: {e}"))?;
        if n == 0 {
            break;
        }
        if raw.len() + n > MAX_RESPONSE {
            return Err("response exceeds size cap".to_string());
        }
        raw.extend_from_slice(&chunk[..n]);
    }

    parse_http_response(&raw)
}

/// Split a `https://host/path` URL into (host, path). HTTPS only; an embedded port, userinfo,
/// or a plain-HTTP URL is rejected (we only ever talk to a fixed 443 host).
fn split_https_url(url: &str) -> Result<(String, String), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("not an https:// URL: {url:?}"))?;
    let (host, path) = match rest.split_once('/') {
        Some((h, p)) => (h.to_string(), format!("/{p}")),
        None => (rest.to_string(), "/".to_string()),
    };
    if host.is_empty() || host.contains(['@', ':']) {
        return Err(format!("unsupported host in URL: {host:?}"));
    }
    Ok((host, path))
}

/// Validate the status line (expects `2xx`), reject a chunked body (we don't decode it — our
/// endpoint sends identity), and return the body as UTF-8.
fn parse_http_response(raw: &[u8]) -> Result<String, String> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| "malformed HTTP response (no header terminator)".to_string())?;
    let head = &raw[..sep];
    let body = &raw[sep + 4..];

    let head = std::str::from_utf8(head).map_err(|_| "non-UTF-8 HTTP headers".to_string())?;
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or("");
    // "HTTP/1.1 200 OK" -> the code is the second whitespace-separated token.
    let code = status.split_whitespace().nth(1).unwrap_or("");
    if !code.starts_with('2') {
        return Err(format!("unexpected HTTP status: {status:?}"));
    }
    if lines.any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    }) {
        return Err("unexpected chunked transfer-encoding".to_string());
    }

    String::from_utf8(body.to_vec()).map_err(|_| "non-UTF-8 response body".to_string())
}

/// A rustls TLS connector trusting the device's native root store. Built per check (a daily
/// call — no need to cache), using the ring provider rumqttc already links.
fn tls_connector() -> Result<tokio_rustls::TlsConnector, String> {
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs()
        .map_err(|e| format!("loading native root certificates: {e}"))?;
    for cert in native {
        // Ignore a single malformed anchor rather than failing the whole store.
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        return Err("no usable native root certificates on device".to_string());
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("rustls protocol versions: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plausible_semver_accepts_real_versions() {
        for v in ["0.1.0", "1.0.0", "10.20.30", "1.2.3-rc.1", "1.2.3+build.5"] {
            assert!(is_plausible_semver(v), "should accept {v}");
        }
    }

    #[test]
    fn plausible_semver_rejects_junk() {
        for v in [
            "", "1", "1.2", "v1.2.3", "1.2.x", "latest", "1.2.3.4", "a.b.c", " 1.2.3",
            // Malformed prerelease/build must be rejected whole — not silently ignored.
            "1.2.3-", "1.2.3+", "1.2.3-\"", "1.2.3-rc.", "1.2.3+ meta", "1.2.3-a..b",
            "1.2.3-rc.1\"; drop", "1.2.3+build meta",
        ] {
            assert!(!is_plausible_semver(v), "should reject {v:?}");
        }
    }

    #[test]
    fn parses_latest_version_from_manifest() {
        let body = r#"{"_comment":"x","schemaVersion":1,"latestVersion":"1.2.3","minimumSupportedVersion":"0.0.0"}"#;
        assert_eq!(parse_latest_version(body).unwrap(), "1.2.3");
    }

    #[test]
    fn latest_version_errors_are_descriptive() {
        assert!(parse_latest_version("not json").is_err());
        assert!(parse_latest_version(r#"{"schemaVersion":1}"#).is_err());
        assert!(parse_latest_version(r#"{"latestVersion":5}"#).is_err());
    }

    #[test]
    fn payload_has_both_versions() {
        let p = payload("9.9.9");
        assert!(p.contains(r#""installed_version":"#));
        assert!(p.contains(r#""latest_version":"9.9.9""#));
        // Valid JSON.
        let v: serde_json::Value = serde_json::from_str(&p).unwrap();
        assert_eq!(v["latest_version"], "9.9.9");
    }

    #[test]
    fn splits_https_urls() {
        let (h, p) = split_https_url(
            "https://raw.githubusercontent.com/jorgeavlobo/intercom-firmware-tool/master/.well-known/bridge.json",
        )
        .unwrap();
        assert_eq!(h, "raw.githubusercontent.com");
        assert_eq!(p, "/jorgeavlobo/intercom-firmware-tool/master/.well-known/bridge.json");

        assert_eq!(split_https_url("https://host").unwrap(), ("host".into(), "/".into()));
    }

    #[test]
    fn rejects_non_https_or_hostful_urls() {
        assert!(split_https_url("http://host/x").is_err());
        assert!(split_https_url("https://host:8443/x").is_err());
        assert!(split_https_url("https://user@host/x").is_err());
        assert!(split_https_url("ftp://host/x").is_err());
    }

    #[test]
    fn parses_a_200_response_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(parse_http_response(raw).unwrap(), "{}");
    }

    #[test]
    fn rejects_non_2xx_and_chunked() {
        let notfound = b"HTTP/1.1 404 Not Found\r\n\r\nnope";
        assert!(parse_http_response(notfound).is_err());
        let chunked =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n";
        assert!(parse_http_response(chunked).is_err());
        let headerless = b"garbage without terminator";
        assert!(parse_http_response(headerless).is_err());
    }
}
