//! Registry proxy routes (DESIGN.md section 7): index pages are rewritten so every
//! artifact download comes back through Customs, and artifact downloads are scanned and
//! either streamed or refused.

pub mod npm;
pub mod pypi;

use axum::body::Body;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use customs_model::Decision;
use customs_scan::Ecosystem;
use tokio_util::io::ReaderStream;

use crate::config::Mode;
use crate::engine::{EngineError, Outcome};
use crate::util::{ecosystem_str, redact_urls};
use crate::verdict::Verdict;

/// Whether the policy can hide young versions; metadata is fetched for that only then.
fn hides_young(policy: &crate::config::Policy) -> bool {
    policy.hide_young_versions
        && policy.mode == Mode::Enforce
        && policy.min_age_days > 0
        && policy.min_age_severity == crate::config::AgeSeverity::Block
}

/// Fetch (and cache) the metadata [`young_versions`] reads, so it can run alongside the
/// upstream page request.
pub async fn prefetch_age_meta(state: &crate::server::AppState, eco: Ecosystem, name: &str) {
    let policy = state.engine.policy();
    if hides_young(&policy) {
        let _ = state
            .engine
            .registry
            .package_meta(&policy.upstream, eco, name)
            .await;
    }
}

/// Versions of `name` to leave out of the metadata served for it (see [`crate::cooldown`]).
/// `listed` are the versions the upstream page offers: cached metadata that lacks one of
/// them predates its release and is fetched again, or the new release would be served
/// without being judged young. A failed fetch hides nothing, and the archive request is
/// still judged on its own.
pub async fn young_versions(
    state: &crate::server::AppState,
    eco: Ecosystem,
    name: &str,
    listed: &[String],
) -> std::collections::HashSet<String> {
    let policy = state.engine.policy();
    if !hides_young(&policy) {
        return Default::default();
    }
    let need: Vec<&str> = listed.iter().map(String::as_str).collect();
    match state
        .engine
        .registry
        .package_meta_listing(&policy.upstream, eco, name, &need)
        .await
    {
        Ok(Some(meta)) => crate::cooldown::hidden_versions(&policy, &meta, crate::util::now()),
        Ok(None) => Default::default(),
        Err(e) => {
            tracing::warn!(name, error = %e, "metadata for release-age filtering failed");
            Default::default()
        }
    }
}

/// Header naming how many young versions were left out of a metadata response.
pub const HIDDEN_HEADER: &str = "x-customs-hidden-versions";

/// Base URL clients used to reach us, for absolute links in rewritten documents.
pub fn proxy_base(headers: &HeaderMap) -> String {
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(header::HOST))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1:7878");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .filter(|p| *p == "https" || *p == "http")
        .unwrap_or("http");
    format!("{proto}://{host}")
}

/// Whether a client-supplied (already percent-decoded) path is safe to append to an
/// upstream base URL. URL parsing would otherwise turn `?` and `#` into a query or
/// fragment, a backslash into a separator, and a leftover `%2e%2e` (double-encoded by the
/// client) into a parent segment, so the URL fetched could differ from the one the verdict
/// names.
pub fn safe_upstream_path(p: &str) -> bool {
    !p.is_empty()
        && !p
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || "\\?#%".contains(c))
        && p.split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// First token of the User-Agent (`pip/24.0`, `npm/10.9.4`), enough to tell clients apart.
pub fn client_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .and_then(|ua| ua.split_whitespace().next())
        .map(|s| s.chars().take(64).collect())
}

/// Plain-text explanation of a block, short enough to read in a terminal.
pub fn block_message(v: &Verdict, base: &str) -> String {
    let mut s = format!(
        "Customs blocked {} package {}{}.\n",
        ecosystem_str(v.ecosystem),
        v.display_name(),
        v.artifact
            .as_deref()
            .map(|a| format!(" ({a})"))
            .unwrap_or_default()
    );
    for h in v
        .policy_hits
        .iter()
        .filter(|h| h.severity >= Decision::Warn)
    {
        s.push_str(&format!("  - {}: {}\n", h.rule, h.detail));
    }
    if v.model_decision >= Decision::Warn {
        if let Some(r) = v.risk {
            s.push_str(&format!(
                "  - model risk {:.2} (block threshold {:.2})\n",
                r, v.thresholds.block
            ));
        }
        for r in v.reasons.iter().take(3) {
            s.push_str(&format!("    * {}\n", r.label));
        }
    }
    if let Some(id) = v.id {
        s.push_str(&format!("Details: {base}/api/verdicts/{id}\n"));
    }
    s
}

/// HTTP reason phrases must be visible ASCII; keep them short so pip prints one line.
fn reason_phrase(v: &Verdict) -> String {
    let text = format!("Blocked by Customs: {}", v.headline());
    let mut out: String = text
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '?'
            }
        })
        .collect();
    if out.len() > 120 {
        out.truncate(117);
        out.push_str("...");
    }
    out
}

fn verdict_headers(resp: &mut Response, v: &Verdict) {
    let h = resp.headers_mut();
    h.insert(
        "x-customs-decision",
        HeaderValue::from_static(v.decision.as_str()),
    );
    if let Some(id) = v.id {
        if let Ok(val) = HeaderValue::from_str(&id.to_string()) {
            h.insert("x-customs-verdict", val);
        }
    }
}

/// Stream the cached artifact, or refuse it when the verdict blocks and we enforce.
pub async fn artifact_response(eco: Ecosystem, out: Outcome, base: &str) -> Response {
    let v = &out.verdict;
    if v.decision == Decision::Block && v.mode == Mode::Enforce {
        let msg = block_message(v, base);
        let mut resp = match eco {
            // npm prints `body.error` after the status line.
            Ecosystem::Npm => (
                StatusCode::FORBIDDEN,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::json!({ "error": msg.trim_end() }).to_string(),
            )
                .into_response(),
            Ecosystem::Pypi => (
                StatusCode::FORBIDDEN,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                msg,
            )
                .into_response(),
        };
        if let Ok(p) = hyper::ext::ReasonPhrase::try_from(reason_phrase(v).into_bytes()) {
            resp.extensions_mut().insert(p);
        }
        verdict_headers(&mut resp, v);
        return resp;
    }
    let Some(path) = &out.path else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "artifact missing from cache",
        )
            .into_response();
    };
    let file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cache read failed: {e}"),
            )
                .into_response()
        }
    };
    let mut resp = Response::new(Body::from_stream(ReaderStream::new(file)));
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Ok(len) = HeaderValue::from_str(&out.size.to_string()) {
        h.insert(header::CONTENT_LENGTH, len);
    }
    verdict_headers(&mut resp, v);
    resp
}

/// Map an evaluation failure to a response the package manager can show.
pub fn error_response(e: &EngineError) -> Response {
    let status = match e {
        EngineError::NotFound(_) => StatusCode::NOT_FOUND,
        EngineError::Unresolvable(_) => StatusCode::UNPROCESSABLE_ENTITY,
        EngineError::TooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
        EngineError::Upstream(_) => StatusCode::BAD_GATEWAY,
        EngineError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    // Upstream errors name the URL, which may carry the registry credentials.
    let msg = redact_urls(&e.to_string());
    if status.is_server_error() {
        tracing::error!(error = %msg, "artifact evaluation failed");
    }
    (status, format!("customs: {msg}\n")).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_from_host() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("localhost:9000"));
        assert_eq!(proxy_base(&h), "http://localhost:9000");
        h.insert("x-forwarded-proto", HeaderValue::from_static("https"));
        h.insert(
            "x-forwarded-host",
            HeaderValue::from_static("customs.example"),
        );
        assert_eq!(proxy_base(&h), "https://customs.example");
    }

    #[test]
    fn upstream_paths() {
        assert!(safe_upstream_path("packages/aa/bb/requests-2.32.3.tar.gz"));
        assert!(safe_upstream_path("-/npm/v1/security/advisories/bulk"));
        assert!(safe_upstream_path("pkg-1.0+local.tar.gz"));
        for bad in [
            "",
            "a//b",
            "a/./b",
            "a/../b",
            "..",
            "a/",
            "evil-1.0.tar.gz#/requests-2.31.0.tar.gz",
            "evil.whl?x=.metadata",
            "a\\..\\b",
            "a/%2e%2e/b",
            "a b",
            "a\nb",
        ] {
            assert!(!safe_upstream_path(bad), "{bad:?}");
        }
    }

    #[test]
    fn client_token() {
        let mut h = HeaderMap::new();
        h.insert(
            header::USER_AGENT,
            HeaderValue::from_static("pip/24.0 {\"ci\":null,\"cpu\":\"x86_64\"}"),
        );
        assert_eq!(client_from_headers(&h).as_deref(), Some("pip/24.0"));
    }
}
