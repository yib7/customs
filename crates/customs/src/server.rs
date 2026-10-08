//! HTTP server assembly: routes, middleware, static dashboard, graceful shutdown.

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};

use crate::engine::Engine;
use crate::proxy::{npm, pypi};

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Engine>,
    /// Flips to `true` when the server begins shutting down.
    pub shutdown: watch::Receiver<bool>,
    pub policy_auth: PolicyAuth,
}

/// Who may change the policy through `PUT /api/policy`.
#[derive(Clone, Debug, Default)]
pub enum PolicyAuth {
    /// Anyone who passes the Host and Origin checks: a loopback server without a token,
    /// or one started with `--allow-anonymous-policy-changes`.
    #[default]
    Open,
    /// Requests must carry `Authorization: Bearer <token>`.
    Token(Arc<str>),
    /// A server reachable from the network without a token: changes are refused, since
    /// anyone who can reach it could otherwise switch enforcement off.
    Disabled,
}

impl PolicyAuth {
    /// How an accepted change was authorized, for the policy change log.
    pub fn kind(&self) -> &'static str {
        match self {
            PolicyAuth::Token(_) => "token",
            PolicyAuth::Open | PolicyAuth::Disabled => "none",
        }
    }

    /// `None` when `headers` may change the policy, else the refusal.
    pub fn refuse(
        &self,
        headers: &axum::http::HeaderMap,
    ) -> Option<(StatusCode, &'static str, String)> {
        match self {
            PolicyAuth::Open => None,
            PolicyAuth::Disabled => Some((
                StatusCode::FORBIDDEN,
                "policy_changes_disabled",
                "policy changes over the API are off on a server reachable from the network; \
                 start it with CUSTOMS_ADMIN_TOKEN (or --admin-token-file) to allow them with \
                 that token, or edit the policy file and restart"
                    .into(),
            )),
            PolicyAuth::Token(token) => {
                let given = headers
                    .get(header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| {
                        let (scheme, rest) = v.trim().split_once(' ')?;
                        scheme.eq_ignore_ascii_case("bearer").then(|| rest.trim())
                    });
                match given {
                    Some(g) if constant_time_eq(g.as_bytes(), token.as_bytes()) => None,
                    Some(_) => Some((
                        StatusCode::UNAUTHORIZED,
                        "admin_token_invalid",
                        "the admin token is not valid".into(),
                    )),
                    None => Some((
                        StatusCode::UNAUTHORIZED,
                        "admin_token_required",
                        "changing the policy needs the admin token (Authorization: Bearer <token>)"
                            .into(),
                    )),
                }
            }
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Server options beyond the engine.
#[derive(Clone, Debug, Default)]
pub struct ServeOptions {
    /// Required on `PUT /api/policy` when set.
    pub admin_token: Option<String>,
    /// Accept policy changes without a token on a server reachable from the network.
    pub allow_anonymous_policy_changes: bool,
}

/// Shortest admin token accepted.
pub const MIN_ADMIN_TOKEN_LEN: usize = 16;

/// The dev server origin of the dashboard; the built dashboard is same-origin.
const DEV_ORIGIN: &str = "http://localhost:5173";

const NOT_BUILT: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Customs</title>
<style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;line-height:1.5}
code{background:#eee;padding:.1rem .3rem;border-radius:3px}@media(prefers-color-scheme:dark){body{background:#111;color:#ddd}code{background:#333}}</style>
</head><body>
<h1>Customs is running</h1>
<p>The dashboard is not built. Run <code>npm ci &amp;&amp; npm run build</code> in <code>web/</code>, then restart
<code>customs serve</code> (or pass <code>--ui-dir</code>).</p>
<p>The API is available: <a href="/api/events">/api/events</a>, <a href="/api/stats">/api/stats</a>,
<a href="/api/model">/api/model</a>, <a href="/metrics">/metrics</a>.</p>
</body></html>"#;

pub fn router(state: AppState, ui_dir: Option<&Path>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list([HeaderValue::from_static(DEV_ORIGIN)]))
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::ACCEPT, header::AUTHORIZATION]);

    let mut app = Router::new()
        .route("/pypi/simple", get(pypi::simple_index))
        .route("/pypi/simple/", get(pypi::simple_index))
        .route("/pypi/simple/{project}", get(pypi::simple_project))
        .route("/pypi/simple/{project}/", get(pypi::simple_project))
        .route("/pypi/files/{*path}", get(pypi::file))
        .route("/pypi/offsite/{file}", get(pypi::offsite))
        .route("/npm/{*rest}", any(npm::npm_any))
        .nest(
            "/api",
            crate::api::router()
                .layer(middleware::from_fn(guard_api))
                .layer(cors),
        )
        .route("/metrics", get(metrics))
        .route("/healthz", get(healthz));

    match ui_dir.filter(|d| d.join("index.html").is_file()) {
        Some(dir) => {
            let spa = ServeDir::new(dir).fallback(ServeFile::new(dir.join("index.html")));
            app = app.fallback_service(spa);
        }
        None => {
            app = app.fallback(|| async { Html(NOT_BUILT) });
        }
    }
    app.layer(middleware::from_fn_with_state(state.clone(), track))
        .with_state(state)
}

/// Host names, beyond loopback names and IP literals, under which the policy may be
/// changed (`CUSTOMS_ALLOWED_HOSTS`, comma-separated, ports ignored).
fn allowed_hosts() -> &'static [String] {
    static HOSTS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    HOSTS.get_or_init(|| {
        std::env::var("CUSTOMS_ALLOWED_HOSTS")
            .unwrap_or_default()
            .split(',')
            .map(|h| strip_port(h.trim()).to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect()
    })
}

fn strip_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split_once(']').map_or(host, |(h, _)| h);
    }
    match host.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    }
}

/// Whether a `Host` header names this machine in a way DNS rebinding cannot forge: an IP
/// literal, `localhost` (and `*.localhost`, which resolvers keep on loopback), or a name
/// the operator listed.
pub fn host_allowed(host: &str, extra: &[String]) -> bool {
    let h = strip_port(host).trim_end_matches('.').to_ascii_lowercase();
    !h.is_empty()
        && (h.parse::<std::net::IpAddr>().is_ok()
            || h == "localhost"
            || h.ends_with(".localhost")
            || extra.contains(&h))
}

/// A browser `Origin` that may send state-changing requests: the dashboard served by this
/// server (same host and port) or the Vite dev server.
pub fn origin_allowed(origin: &str, host: &str) -> bool {
    origin == DEV_ORIGIN
        || origin
            .strip_prefix("http://")
            .or_else(|| origin.strip_prefix("https://"))
            .is_some_and(|authority| authority.eq_ignore_ascii_case(host))
}

/// Refuse state-changing API calls a web page could have made. CORS keeps other origins
/// from reading responses, but a cross-site form or fetch can still send one, and DNS
/// rebinding makes the page same-origin: its host name resolves to 127.0.0.1, so the
/// browser sends `Host: attacker.example`. Non-browser clients send no `Origin`.
async fn guard_api(req: Request, next: Next) -> Response {
    if matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        return next.run(req).await;
    }
    // Owned copies: a borrow of the request (whose body is not `Sync`) must not live
    // across the await below.
    let (host, fwd_host, origin, is_policy) = {
        let header_str = |h: header::HeaderName| {
            req.headers()
                .get(h)
                .map(|v| v.to_str().unwrap_or("").to_string())
        };
        (
            header_str(header::HOST).unwrap_or_default(),
            header_str(header::HeaderName::from_static("x-forwarded-host")),
            header_str(header::ORIGIN),
            req.uri().path() == "/policy",
        )
    };
    let refuse = |why: String| {
        tracing::warn!(%host, origin = origin.as_deref().unwrap_or(""), "{why}");
        (StatusCode::FORBIDDEN, Json(json!({ "error": why }))).into_response()
    };
    if let Some(o) = &origin {
        // Behind a reverse proxy the dashboard's origin is the forwarded host.
        if !origin_allowed(o, &host) && !fwd_host.as_deref().is_some_and(|f| origin_allowed(o, f)) {
            return refuse(format!("cross-origin request from {o} refused"));
        }
    }
    // Changing the policy can switch enforcement off, so it also needs a Host that DNS
    // rebinding cannot produce. Checks stay reachable under any name (team servers).
    if is_policy && !host_allowed(&host, allowed_hosts()) {
        return refuse(format!(
            "policy changes are accepted only on localhost, an IP address, or a host in \
             CUSTOMS_ALLOWED_HOSTS (got {host:?})"
        ));
    }
    next.run(req).await
}

/// On a loopback listener every legitimate client names the server by a loopback name or
/// an IP address, so any other `Host` came from a browser page whose own host name was
/// rebound to 127.0.0.1. Without this, such a page could read the event log (what this
/// machine installs) and the policy. Requests without a `Host` (HTTP/2 carries the
/// authority in the URI) are judged by the URI's authority.
async fn guard_loopback_host(req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.uri().authority().map(|a| a.to_string()));
    if let Some(h) = host {
        if !host_allowed(&h, allowed_hosts()) {
            tracing::warn!(host = %h, "request for a foreign host name refused");
            return (
                StatusCode::FORBIDDEN,
                format!(
                    "customs: this server listens on loopback and answers only to localhost or an \
                     IP address (got Host {h:?}); add the name to CUSTOMS_ALLOWED_HOSTS to allow it\n"
                ),
            )
                .into_response();
        }
    }
    next.run(req).await
}

/// Count requests by route template and status.
async fn track(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "static".to_string());
    let resp = next.run(req).await;
    state.engine.metrics.request(&route, resp.status().as_u16());
    resp
}

async fn metrics(State(state): State<AppState>) -> Response {
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        state.engine.metrics.render(),
    )
        .into_response()
}

async fn healthz(State(state): State<AppState>) -> Response {
    let p = state.engine.policy();
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "model_version": state.engine.models.model_version(),
            "mode": p.mode,
        })),
    )
        .into_response()
}

/// Serve until `shutdown` resolves, then drain in-flight requests.
pub async fn serve_on(
    listener: TcpListener,
    engine: Arc<Engine>,
    ui_dir: Option<PathBuf>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    serve_with(listener, engine, ui_dir, ServeOptions::default(), shutdown).await
}

/// [`serve_on`] with [`ServeOptions`].
pub async fn serve_with(
    listener: TcpListener,
    engine: Arc<Engine>,
    ui_dir: Option<PathBuf>,
    opts: ServeOptions,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let addr = listener.local_addr()?;
    let policy_auth = match opts.admin_token {
        Some(t) => {
            anyhow::ensure!(
                t.len() >= MIN_ADMIN_TOKEN_LEN,
                "the admin token must be at least {MIN_ADMIN_TOKEN_LEN} characters"
            );
            PolicyAuth::Token(t.into())
        }
        None if addr.ip().is_loopback() || opts.allow_anonymous_policy_changes => PolicyAuth::Open,
        None => {
            tracing::warn!(
                %addr,
                "policy changes over the API are off: this server is reachable from the network \
                 and has no CUSTOMS_ADMIN_TOKEN"
            );
            PolicyAuth::Disabled
        }
    };
    let (tx, rx) = watch::channel(false);
    let state = AppState {
        engine,
        shutdown: rx,
        policy_auth,
    };
    let mut app = router(state, ui_dir.as_deref());
    if addr.ip().is_loopback() {
        app = app.layer(middleware::from_fn(guard_loopback_host));
    }
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown.await;
        let _ = tx.send(true);
    })
    .await?;
    Ok(())
}

/// Resolves on Ctrl-C or SIGTERM.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_that_rebinding_cannot_forge() {
        let none: &[String] = &[];
        for ok in [
            "127.0.0.1:7878",
            "localhost:7878",
            "LOCALHOST",
            "app.localhost:1",
            "[::1]:7878",
            "10.0.0.5",
            "localhost.",
        ] {
            assert!(host_allowed(ok, none), "{ok}");
        }
        for bad in [
            "evil.example:7878",
            "localhost.evil.example",
            "",
            "127.0.0.1.nip.io",
        ] {
            assert!(!host_allowed(bad, none), "{bad}");
        }
        let extra = vec!["customs.corp".to_string()];
        assert!(host_allowed("Customs.Corp:443", &extra));
    }

    #[test]
    fn admin_token() {
        use axum::http::HeaderMap;
        let auth = PolicyAuth::Token("0123456789abcdef".into());
        let with = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::AUTHORIZATION, v.parse().unwrap());
            h
        };
        assert!(auth.refuse(&with("Bearer 0123456789abcdef")).is_none());
        assert!(auth.refuse(&with("bearer  0123456789abcdef ")).is_none());
        let code = |h: &HeaderMap| auth.refuse(h).map(|r| (r.0, r.1));
        assert_eq!(
            code(&with("Bearer 0123456789abcdeX")),
            Some((StatusCode::UNAUTHORIZED, "admin_token_invalid"))
        );
        assert_eq!(
            code(&with("Basic 0123456789abcdef")),
            Some((StatusCode::UNAUTHORIZED, "admin_token_required"))
        );
        assert_eq!(
            code(&HeaderMap::new()),
            Some((StatusCode::UNAUTHORIZED, "admin_token_required"))
        );
        assert!(PolicyAuth::Open.refuse(&HeaderMap::new()).is_none());
        assert_eq!(
            PolicyAuth::Disabled.refuse(&HeaderMap::new()).map(|r| r.0),
            Some(StatusCode::FORBIDDEN)
        );
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn origins() {
        assert!(origin_allowed("http://127.0.0.1:7878", "127.0.0.1:7878"));
        assert!(origin_allowed(DEV_ORIGIN, "127.0.0.1:7878"));
        assert!(!origin_allowed("http://evil.example", "127.0.0.1:7878"));
        assert!(!origin_allowed("null", "127.0.0.1:7878"));
    }
}
