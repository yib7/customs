//! npm: packuments with `dist.tarball` pointed back at the proxy, and tarball downloads
//! through the scanner. Scoped names arrive as `@scope%2fname` (what npm sends) or
//! `@scope/name`; both are accepted.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use customs_scan::Ecosystem;
use serde_json::Value;

use super::{
    artifact_response, client_from_headers, error_response, proxy_base, safe_upstream_path,
};
use crate::engine::ArtifactRequest;
use crate::registry::npm_escape;
use crate::server::AppState;
use crate::util::{normalize_name, parse_npm_tarball};
use crate::verdict::EventKind;

/// What a path under `/npm/` refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NpmPath {
    /// `/{name}` or `/{name}/{version}`.
    Packument {
        name: String,
        version: Option<String>,
    },
    /// `/{name}/-/{file}.tgz`.
    Tarball { name: String, file: String },
    /// Registry endpoints such as `/-/npm/v1/security/advisories/bulk` (npm audit).
    Special(String),
}

fn valid_name(name: &str) -> bool {
    let (scope, bare) = match name.strip_prefix('@') {
        Some(rest) => match rest.split_once('/') {
            Some((s, b)) => (Some(s), b),
            None => return false,
        },
        None => (None, name),
    };
    let ok = |s: &str| {
        !s.is_empty()
            && !s.starts_with('.')
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "-._~".contains(c))
    };
    scope.is_none_or(ok) && ok(bare)
}

/// Parse the (percent-decoded) path after `/npm/`.
pub fn parse_npm_path(rest: &str) -> Option<NpmPath> {
    let rest = rest.trim_start_matches('/');
    if rest.starts_with("-/") {
        return safe_upstream_path(rest).then(|| NpmPath::Special(rest.to_string()));
    }
    // Decoding twice is harmless here and covers clients that double-escape `%252f`.
    let rest = rest.replace("%2f", "/").replace("%2F", "/");
    if !safe_upstream_path(rest.trim_end_matches('/')) {
        return None;
    }
    if let Some((name, file)) = rest.split_once("/-/") {
        if !valid_name(name) || file.contains('/') || !file.ends_with(".tgz") {
            return None;
        }
        return Some(NpmPath::Tarball {
            name: name.to_string(),
            file: file.to_string(),
        });
    }
    let segs: Vec<&str> = rest.split('/').filter(|s| !s.is_empty()).collect();
    let (name, tail) = if rest.starts_with('@') {
        if segs.len() < 2 {
            return None;
        }
        (format!("{}/{}", segs[0], segs[1]), &segs[2..])
    } else {
        (segs.first()?.to_string(), &segs[1..])
    };
    if !valid_name(&name) || tail.len() > 1 {
        return None;
    }
    Some(NpmPath::Packument {
        name,
        version: tail.first().map(|s| s.to_string()),
    })
}

/// Point every `dist.tarball` at the proxy. Works on full and abbreviated packuments and
/// on single-version documents.
pub fn rewrite_packument(v: &mut Value, proxy_base: &str) {
    let top_name = v.get("name").and_then(Value::as_str).map(str::to_string);
    let fix = |doc: &mut Value, fallback: Option<&str>| {
        let name = doc
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string)
            .or_else(|| fallback.map(str::to_string));
        let Some(name) = name else { return };
        if let Some(t) = doc.get_mut("dist").and_then(|d| d.get_mut("tarball")) {
            if let Some(file) = t
                .as_str()
                .and_then(|s| s.rsplit('/').next())
                .map(str::to_string)
            {
                *t = Value::String(format!("{proxy_base}/npm/{name}/-/{file}"));
            }
        }
    };
    if let Some(versions) = v.get_mut("versions").and_then(Value::as_object_mut) {
        for doc in versions.values_mut() {
            fix(doc, top_name.as_deref());
        }
    }
    if v.get("dist").is_some() {
        fix(v, None);
    }
}

/// `ANY /npm/{*rest}`
pub async fn npm_any(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    Path(rest): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(parsed) = parse_npm_path(&rest) else {
        return (StatusCode::NOT_FOUND, r#"{"error":"Not found"}"#).into_response();
    };
    match parsed {
        NpmPath::Special(p) => passthrough(&state, method, &p, uri.query(), &headers, body).await,
        _ if method != Method::GET && method != Method::HEAD => (
            StatusCode::METHOD_NOT_ALLOWED,
            r#"{"error":"customs is a read-only registry proxy"}"#,
        )
            .into_response(),
        NpmPath::Packument { name, version } => {
            packument(&state, &headers, &name, version.as_deref()).await
        }
        NpmPath::Tarball { name, file } => tarball(&state, &headers, &name, &file).await,
    }
}

async fn packument(
    state: &AppState,
    headers: &HeaderMap,
    name: &str,
    version: Option<&str>,
) -> Response {
    let policy = state.engine.policy();
    let mut url = format!("{}/{}", policy.upstream.npm, npm_escape(name));
    if let Some(v) = version {
        url.push('/');
        url.push_str(v);
    }
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");
    // The release-age metadata is fetched alongside the page, not after it.
    let held_back = async {
        if version.is_none() {
            super::prefetch_age_meta(state, Ecosystem::Npm, name).await;
        }
    };
    let (page, ()) = tokio::join!(
        state
            .engine
            .registry
            .get(&url, Some(accept), "npm_packument"),
        held_back
    );
    let page = match page {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(%url, error = %e, "upstream packument failed");
            return (
                StatusCode::BAD_GATEWAY,
                [(header::CONTENT_TYPE, "application/json")],
                serde_json::json!({ "error": format!("customs: upstream error: {e}") }).to_string(),
            )
                .into_response();
        }
    };
    if page.status == 404 && version.is_none() {
        if let Err(e) =
            state
                .engine
                .record_nonexistent(Ecosystem::Npm, name, client_from_headers(headers))
        {
            tracing::error!(error = %e, "recording nonexistent package failed");
        }
    }
    let ct = page
        .content_type
        .clone()
        .unwrap_or_else(|| "application/json".into());
    if page.status != 200 {
        return (
            StatusCode::from_u16(page.status).unwrap_or(StatusCode::BAD_GATEWAY),
            [(header::CONTENT_TYPE, ct)],
            page.body,
        )
            .into_response();
    }
    match serde_json::from_slice::<Value>(&page.body) {
        Ok(mut v) => {
            let n = match version {
                None => {
                    let listed: Vec<String> = v
                        .get("versions")
                        .and_then(Value::as_object)
                        .map(|o| o.keys().cloned().collect())
                        .unwrap_or_default();
                    let hidden = super::young_versions(state, Ecosystem::Npm, name, &listed).await;
                    crate::cooldown::filter_packument(&mut v, &hidden)
                }
                Some(_) => 0,
            };
            rewrite_packument(&mut v, &proxy_base(headers));
            let mut resp = ([(header::CONTENT_TYPE, ct)], v.to_string()).into_response();
            if n > 0 {
                resp.headers_mut()
                    .insert(super::HIDDEN_HEADER, header::HeaderValue::from(n));
            }
            resp
        }
        Err(_) => (
            StatusCode::BAD_GATEWAY,
            r#"{"error":"customs: invalid upstream JSON"}"#,
        )
            .into_response(),
    }
}

async fn tarball(state: &AppState, headers: &HeaderMap, name: &str, file: &str) -> Response {
    let policy = state.engine.policy();
    let url = format!("{}/{}/-/{}", policy.upstream.npm, name, file);
    let req = ArtifactRequest {
        ecosystem: Ecosystem::Npm,
        name: normalize_name(Ecosystem::Npm, name),
        version: parse_npm_tarball(name, file),
        filename: file.to_string(),
        url,
        client: client_from_headers(headers),
        kind: EventKind::Install,
        meta: None,
    };
    let base = proxy_base(headers);
    match state.engine.evaluate_artifact(req).await {
        Ok(out) => artifact_response(Ecosystem::Npm, out, &base).await,
        Err(e) => error_response(&e),
    }
}

/// Forward registry service endpoints (audit, search) unchanged, query string included
/// (`npm search` sends its terms as `?text=`).
async fn passthrough(
    state: &AppState,
    method: Method,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    let policy = state.engine.policy();
    let url = match query {
        Some(q) => format!("{}/{path}?{q}", policy.upstream.npm),
        None => format!("{}/{path}", policy.upstream.npm),
    };
    let Ok(m) = reqwest::Method::from_bytes(method.as_str().as_bytes()) else {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    };
    let mut req = state
        .engine
        .registry
        .client()
        .request(m, &url)
        .timeout(crate::registry::PAGE_TIMEOUT)
        .body(body);
    for h in [
        header::CONTENT_TYPE,
        header::ACCEPT,
        header::CONTENT_ENCODING,
    ] {
        if let Some(v) = headers.get(&h).and_then(|v| v.to_str().ok()) {
            req = req.header(h.as_str(), v);
        }
    }
    match req.send().await {
        Ok(resp) => {
            let status =
                StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let ct = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("application/json")
                .to_string();
            match resp.bytes().await {
                Ok(bytes) => (status, [(header::CONTENT_TYPE, ct)], bytes).into_response(),
                // A body cut short is an upstream failure, not an empty answer.
                Err(e) => upstream_error(e),
            }
        }
        Err(e) => upstream_error(e),
    }
}

fn upstream_error(e: reqwest::Error) -> Response {
    (
        StatusCode::BAD_GATEWAY,
        format!("customs: upstream error: {e}\n"),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_paths() {
        assert_eq!(
            parse_npm_path("left-pad"),
            Some(NpmPath::Packument {
                name: "left-pad".into(),
                version: None
            })
        );
        assert_eq!(
            parse_npm_path("@babel%2fcore"),
            Some(NpmPath::Packument {
                name: "@babel/core".into(),
                version: None
            })
        );
        assert_eq!(
            parse_npm_path("@babel/core"),
            Some(NpmPath::Packument {
                name: "@babel/core".into(),
                version: None
            })
        );
        assert_eq!(
            parse_npm_path("@babel/core/7.24.0"),
            Some(NpmPath::Packument {
                name: "@babel/core".into(),
                version: Some("7.24.0".into())
            })
        );
        assert_eq!(
            parse_npm_path("left-pad/-/left-pad-1.3.0.tgz"),
            Some(NpmPath::Tarball {
                name: "left-pad".into(),
                file: "left-pad-1.3.0.tgz".into()
            })
        );
        assert_eq!(
            parse_npm_path("@babel/core/-/core-7.24.0.tgz"),
            Some(NpmPath::Tarball {
                name: "@babel/core".into(),
                file: "core-7.24.0.tgz".into()
            })
        );
        assert_eq!(
            parse_npm_path("@babel%2Fcore/-/core-7.24.0.tgz"),
            Some(NpmPath::Tarball {
                name: "@babel/core".into(),
                file: "core-7.24.0.tgz".into()
            })
        );
        assert!(matches!(
            parse_npm_path("-/npm/v1/security/advisories/bulk"),
            Some(NpmPath::Special(_))
        ));
        assert_eq!(parse_npm_path("@scopeonly"), None);
        assert_eq!(parse_npm_path("../etc/passwd"), None);
        assert_eq!(parse_npm_path("a/b/c"), None);
        assert_eq!(parse_npm_path("x/-/../../y.tgz"), None);
        assert_eq!(parse_npm_path("x/-/x-1.0.0.zip"), None);
        // Already percent-decoded once by the router: whatever is still escaped, or would
        // become a query, fragment or separator upstream, is refused.
        assert_eq!(parse_npm_path("-/%2e%2e/evil/-/evil-1.0.0.tgz"), None);
        assert_eq!(parse_npm_path("-/v1/../../evil"), None);
        assert_eq!(parse_npm_path("x/-/x-1.0.0.tgz#/y-1.0.0.tgz"), None);
        assert_eq!(parse_npm_path("x/-/..\\x-1.0.0.tgz"), None);
        assert_eq!(parse_npm_path("x/-/x-1.0.0.tgz?a=.tgz"), None);
        assert_eq!(parse_npm_path("lodash%252e%252e"), None);
    }

    #[test]
    fn rewrites_full_packument() {
        let mut v: Value = serde_json::from_str(
            r#"{"_id": "@scope/pkg", "name": "@scope/pkg", "dist-tags": {"latest": "1.0.0"},
                "versions": {
                  "1.0.0": {"name": "@scope/pkg", "version": "1.0.0",
                            "dist": {"tarball": "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz",
                                     "shasum": "abc", "integrity": "sha512-xyz"}},
                  "0.9.0": {"version": "0.9.0",
                            "dist": {"tarball": "https://registry.npmjs.org/@scope/pkg/-/pkg-0.9.0.tgz"}}
                },
                "time": {"1.0.0": "2024-01-01T00:00:00.000Z"}}"#,
        )
        .unwrap();
        rewrite_packument(&mut v, "http://127.0.0.1:7878");
        assert_eq!(
            v["versions"]["1.0.0"]["dist"]["tarball"],
            "http://127.0.0.1:7878/npm/@scope/pkg/-/pkg-1.0.0.tgz"
        );
        assert_eq!(
            v["versions"]["0.9.0"]["dist"]["tarball"],
            "http://127.0.0.1:7878/npm/@scope/pkg/-/pkg-0.9.0.tgz"
        );
        // Integrity data is untouched so npm still verifies the bytes.
        assert_eq!(v["versions"]["1.0.0"]["dist"]["integrity"], "sha512-xyz");
        assert_eq!(v["time"]["1.0.0"], "2024-01-01T00:00:00.000Z");
    }

    #[test]
    fn rewrites_version_document() {
        let mut v: Value = serde_json::from_str(
            r#"{"name": "left-pad", "version": "1.3.0",
                "dist": {"tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}"#,
        )
        .unwrap();
        rewrite_packument(&mut v, "http://h");
        assert_eq!(
            v["dist"]["tarball"],
            "http://h/npm/left-pad/-/left-pad-1.3.0.tgz"
        );
    }
}
