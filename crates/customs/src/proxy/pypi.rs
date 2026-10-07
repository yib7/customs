//! PyPI: PEP 503 simple pages (HTML) and PEP 691 (JSON) with file links pointed back at
//! `/pypi/files/`, and file downloads through the scanner.

use std::sync::OnceLock;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use customs_scan::Ecosystem;
use regex::Regex;
use serde_json::Value;
use url::Url;

use super::{artifact_response, client_from_headers, error_response, proxy_base};
use crate::engine::ArtifactRequest;
use crate::server::AppState;
use crate::util::{normalize_name, parse_pypi_filename};
use crate::verdict::EventKind;

const DEFAULT_ACCEPT: &str =
    "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.1, text/html;q=0.01";

/// Bases used to recognize upstream URLs and build proxy URLs.
#[derive(Debug, Clone)]
pub struct Rewriter<'a> {
    pub simple_base: &'a str,
    pub files_base: &'a str,
    pub proxy_base: &'a str,
}

impl Rewriter<'_> {
    /// Map an upstream link to its proxy equivalent. Relative links resolve against the
    /// page URL. Links to hosts we do not proxy are left alone.
    pub fn rewrite_url(&self, href: &str, page_url: &Url) -> Option<String> {
        let abs = page_url.join(href).ok()?;
        let s = abs.as_str();
        if let Some(rest) = s
            .strip_prefix(self.files_base)
            .and_then(|r| r.strip_prefix('/'))
        {
            return Some(format!("{}/pypi/files/{}", self.proxy_base, rest));
        }
        if let Some(rest) = s
            .strip_prefix(self.simple_base)
            .and_then(|r| r.strip_prefix('/'))
        {
            return Some(format!("{}/pypi/simple/{}", self.proxy_base, rest));
        }
        None
    }

    pub fn rewrite_html(&self, body: &str, page_url: &Url) -> String {
        static HREF: OnceLock<Regex> = OnceLock::new();
        let re = HREF.get_or_init(|| {
            Regex::new(r#"(?i)((?-u:\b)href\s*=\s*)(["'])([^"']*)(["'])"#).unwrap()
        });
        re.replace_all(body, |c: &regex::Captures<'_>| {
            let href = &c[3];
            // Hrefs in HTML may carry entity-encoded ampersands; decode only for resolution.
            let decoded = href.replace("&amp;", "&");
            match self.rewrite_url(&decoded, page_url) {
                Some(new) => format!("{}{}{}{}", &c[1], &c[2], new.replace('&', "&amp;"), &c[4]),
                None => c[0].to_string(),
            }
        })
        .into_owned()
    }

    /// PEP 691: rewrite `files[].url` (project pages); index pages have no URLs.
    pub fn rewrite_json(&self, v: &mut Value, page_url: &Url) {
        if let Some(files) = v.get_mut("files").and_then(Value::as_array_mut) {
            for f in files {
                if let Some(u) = f.get_mut("url") {
                    if let Some(new) = u.as_str().and_then(|s| self.rewrite_url(s, page_url)) {
                        *u = Value::String(new);
                    }
                }
            }
        }
    }
}

async fn fetch_and_rewrite(
    state: &AppState,
    headers: &HeaderMap,
    upstream_path: &str,
    project: Option<&str>,
) -> Response {
    let policy = state.engine.policy();
    let up = &policy.upstream;
    let url = format!("{}/{}", up.pypi_simple, upstream_path);
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or(DEFAULT_ACCEPT);
    let page = match state
        .engine
        .registry
        .get(&url, Some(accept), "pypi_simple")
        .await
    {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(%url, error = %e, "upstream simple page failed");
            return (
                StatusCode::BAD_GATEWAY,
                format!("customs: upstream error: {e}\n"),
            )
                .into_response();
        }
    };
    if page.status == 404 {
        if let Some(p) = project {
            if let Err(e) =
                state
                    .engine
                    .record_nonexistent(Ecosystem::Pypi, p, client_from_headers(headers))
            {
                tracing::error!(error = %e, "recording nonexistent package failed");
            }
        }
        return (StatusCode::NOT_FOUND, "Not Found\n").into_response();
    }
    if page.status != 200 {
        return (
            StatusCode::from_u16(page.status).unwrap_or(StatusCode::BAD_GATEWAY),
            page.body,
        )
            .into_response();
    }
    let page_url = Url::parse(&page.url).or_else(|_| Url::parse(&url));
    let Ok(page_url) = page_url else {
        return (StatusCode::BAD_GATEWAY, "customs: bad upstream URL\n").into_response();
    };
    let base = proxy_base(headers);
    let rw = Rewriter {
        simple_base: &up.pypi_simple,
        files_base: &up.pypi_files,
        proxy_base: &base,
    };
    let ct = page
        .content_type
        .clone()
        .unwrap_or_else(|| "text/html".into());
    let body = if ct.contains("json") {
        match serde_json::from_slice::<Value>(&page.body) {
            Ok(mut v) => {
                rw.rewrite_json(&mut v, &page_url);
                v.to_string()
            }
            Err(_) => {
                return (StatusCode::BAD_GATEWAY, "customs: invalid upstream JSON\n")
                    .into_response()
            }
        }
    } else {
        rw.rewrite_html(&String::from_utf8_lossy(&page.body), &page_url)
    };
    ([(header::CONTENT_TYPE, ct)], body).into_response()
}

/// `GET /pypi/simple/`
pub async fn simple_index(State(state): State<AppState>, headers: HeaderMap) -> Response {
    fetch_and_rewrite(&state, &headers, "", None).await
}

/// `GET /pypi/simple/{project}/`
pub async fn simple_project(
    State(state): State<AppState>,
    Path(project): Path<String>,
    headers: HeaderMap,
) -> Response {
    let name = normalize_name(Ecosystem::Pypi, &project);
    if name.is_empty() || name.contains('/') {
        return (StatusCode::BAD_REQUEST, "invalid project name\n").into_response();
    }
    fetch_and_rewrite(&state, &headers, &format!("{name}/"), Some(&name)).await
}

/// `GET /pypi/files/{path}`
pub async fn file(
    State(state): State<AppState>,
    Path(path): Path<String>,
    headers: HeaderMap,
) -> Response {
    if path.split('/').any(|seg| seg == ".." || seg.is_empty()) {
        return (StatusCode::BAD_REQUEST, "invalid path\n").into_response();
    }
    let policy = state.engine.policy();
    let url = format!("{}/{}", policy.upstream.pypi_files, path);
    // PEP 658 metadata files are plain text pip reads before choosing a version; they hold
    // no code, so they pass through unscanned.
    if path.ends_with(".metadata") {
        return match state.engine.registry.get(&url, None, "pypi_metadata").await {
            Ok(p) => (
                StatusCode::from_u16(p.status).unwrap_or(StatusCode::BAD_GATEWAY),
                [(
                    header::CONTENT_TYPE,
                    p.content_type
                        .unwrap_or_else(|| "application/octet-stream".into()),
                )],
                p.body,
            )
                .into_response(),
            Err(e) => (
                StatusCode::BAD_GATEWAY,
                format!("customs: upstream error: {e}\n"),
            )
                .into_response(),
        };
    }
    let filename = path.rsplit('/').next().unwrap_or(&path).to_string();
    let (name, version) = match parse_pypi_filename(&filename) {
        Some((n, v)) => (normalize_name(Ecosystem::Pypi, &n), Some(v)),
        None => (filename.clone(), None),
    };
    let req = ArtifactRequest {
        ecosystem: Ecosystem::Pypi,
        name,
        version,
        filename,
        url,
        client: client_from_headers(&headers),
        kind: EventKind::Install,
        meta: None,
    };
    let base = proxy_base(&headers);
    match state.engine.evaluate_artifact(req).await {
        Ok(out) => artifact_response(Ecosystem::Pypi, out, &base).await,
        Err(e) => error_response(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rw(base: &str) -> Rewriter<'_> {
        Rewriter {
            simple_base: "https://pypi.org/simple",
            files_base: "https://files.pythonhosted.org",
            proxy_base: base,
        }
    }

    const PAGE: &str = r#"<!DOCTYPE html>
<html>
  <head>
    <meta name="pypi:repository-version" content="1.1">
    <title>Links for requests</title>
  </head>
  <body>
    <h1>Links for requests</h1>
    <a href="https://files.pythonhosted.org/packages/f9/9b/335f9764261e915ed497fcdeb11df5dfd6f7bf257d4a6a2a686d80da4d54/requests-2.32.3-py3-none-any.whl#sha256=70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6" data-requires-python="&gt;=3.8" data-dist-info-metadata="sha256=a0cbd7e4" data-core-metadata="sha256=a0cbd7e4">requests-2.32.3-py3-none-any.whl</a><br />
    <a href="https://files.pythonhosted.org/packages/63/70/2bf7780ad2d390a8d301ad0b550f1581eadbd9a20f896afe06353c2a2913/requests-2.32.3.tar.gz#sha256=55365417734eb18255590a9ff9eb97e9e1da868d4ccd6402399eaf68af20a760" data-requires-python="&gt;=3.8" >requests-2.32.3.tar.gz</a><br />
    <a href='../../packages/aa/bb/relative-1.0.tar.gz#sha256=00'>relative</a>
    <a href="https://example.com/elsewhere.tar.gz">elsewhere</a>
  </body>
</html>"#;

    #[test]
    fn rewrites_html_file_links() {
        let page = Url::parse("https://files.pythonhosted.org/simple/requests/").unwrap();
        let out = rw("http://127.0.0.1:7878").rewrite_html(PAGE, &page);
        assert!(out.contains(r#"href="http://127.0.0.1:7878/pypi/files/packages/f9/9b/335f9764261e915ed497fcdeb11df5dfd6f7bf257d4a6a2a686d80da4d54/requests-2.32.3-py3-none-any.whl#sha256=70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6""#));
        assert!(out.contains("/pypi/files/packages/63/70/"));
        // Relative links resolve against the page and are rewritten too.
        assert!(out.contains(
            "href='http://127.0.0.1:7878/pypi/files/packages/aa/bb/relative-1.0.tar.gz#sha256=00'"
        ));
        // Attributes other than href are untouched.
        assert!(out.contains(r#"data-requires-python="&gt;=3.8""#));
        assert!(out.contains(r#"href="https://example.com/elsewhere.tar.gz""#));
        assert_eq!(out.matches("files.pythonhosted.org").count(), 0);
    }

    #[test]
    fn rewrites_index_links() {
        let page = Url::parse("https://pypi.org/simple/").unwrap();
        let html = r#"<a href="/simple/0/">0</a><a href="/simple/requests/">requests</a>"#;
        let out = rw("http://h:1").rewrite_html(html, &page);
        assert_eq!(
            out,
            r#"<a href="http://h:1/pypi/simple/0/">0</a><a href="http://h:1/pypi/simple/requests/">requests</a>"#
        );
    }

    #[test]
    fn rewrites_pep691_json() {
        let page = Url::parse("https://pypi.org/simple/requests/").unwrap();
        let mut v: Value = serde_json::from_str(
            r#"{"meta": {"api-version": "1.1"}, "name": "requests",
                "files": [
                  {"filename": "requests-2.32.3.tar.gz",
                   "url": "https://files.pythonhosted.org/packages/63/70/2bf7/requests-2.32.3.tar.gz",
                   "hashes": {"sha256": "55365417"}, "requires-python": ">=3.8", "upload-time": "2024-05-29T15:37:49.536363Z"},
                  {"filename": "x.whl", "url": "https://mirror.example/x.whl", "hashes": {}}
                ], "versions": ["2.32.3"]}"#,
        )
        .unwrap();
        rw("http://localhost:7878").rewrite_json(&mut v, &page);
        assert_eq!(
            v["files"][0]["url"],
            "http://localhost:7878/pypi/files/packages/63/70/2bf7/requests-2.32.3.tar.gz"
        );
        assert_eq!(v["files"][1]["url"], "https://mirror.example/x.whl");
        assert_eq!(v["files"][0]["hashes"]["sha256"], "55365417");
    }
}
