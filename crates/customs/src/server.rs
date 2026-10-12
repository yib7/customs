//! HTTP server assembly: routes, middleware, static dashboard, graceful shutdown.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{MatchedPath, Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tower_http::services::{ServeDir, ServeFile};

use crate::engine::Engine;
use crate::proxy::{npm, pypi};

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<Engine>,
    /// Flips to `true` when the server begins shutting down.
    pub shutdown: watch::Receiver<bool>,
    pub policy_auth: PolicyAuth,
    /// Host names, beyond loopback names and IP literals, under which the policy may be
    /// changed (lowercase, no port); see [`ServeOptions::allowed_hosts`].
    pub allowed_hosts: Arc<[String]>,
    /// Wrong admin tokens by client address.
    pub token_failures: Arc<TokenFailures>,
}

/// How long wrong admin tokens from one address count against it.
pub const TOKEN_FAILURE_WINDOW: Duration = Duration::from_secs(60);

/// Wrong admin tokens by client address (IPv6 by /64, the block one host usually holds),
/// so a token cannot be guessed at network speed: see [`MAX_TOKEN_FAILURES`].
#[derive(Debug, Default)]
pub struct TokenFailures(Mutex<HashMap<IpAddr, (u32, Instant)>>);

/// Addresses tracked before expired entries are swept.
const TOKEN_FAILURES_SWEEP_AT: usize = 4096;

fn failure_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
        v4 => v4,
    }
}

impl TokenFailures {
    /// Seconds until `ip` may send a token again, when it has used up its attempts.
    pub fn locked(&self, ip: IpAddr, now: Instant) -> Option<u64> {
        let map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let (n, since) = map.get(&failure_key(ip))?;
        let left = TOKEN_FAILURE_WINDOW.checked_sub(now.saturating_duration_since(*since))?;
        (*n >= MAX_TOKEN_FAILURES && !left.is_zero()).then(|| left.as_secs().max(1))
    }

    /// Count a wrong token from `ip`.
    pub fn failed(&self, ip: IpAddr, now: Instant) {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= TOKEN_FAILURES_SWEEP_AT {
            map.retain(|_, (_, since)| {
                now.saturating_duration_since(*since) < TOKEN_FAILURE_WINDOW
            });
        }
        let e = map.entry(failure_key(ip)).or_insert((0, now));
        if now.saturating_duration_since(e.1) >= TOKEN_FAILURE_WINDOW {
            *e = (0, now);
        }
        e.0 = e.0.saturating_add(1);
    }
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

    /// Who may change the policy, as `GET /api/policy` reports it in
    /// `X-Customs-Policy-Changes`: `open`, `token`, or `disabled`. The dashboard asks for
    /// the token, or says changes are off, before anyone edits the form.
    pub fn changes(&self) -> &'static str {
        match self {
            PolicyAuth::Open => "open",
            PolicyAuth::Token(_) => "token",
            PolicyAuth::Disabled => "disabled",
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
    /// Host names, beyond loopback names and IP literals, under which the policy may be
    /// changed and a loopback server answers (`--allowed-hosts`, `CUSTOMS_ALLOWED_HOSTS`;
    /// ports and case ignored).
    pub allowed_hosts: Vec<String>,
}

/// Shortest admin token accepted.
pub const MIN_ADMIN_TOKEN_LEN: usize = 16;

/// Wrong admin tokens one address may send within [`TOKEN_FAILURE_WINDOW`] before its
/// policy changes are refused until the window ends.
pub const MAX_TOKEN_FAILURES: u32 = 10;

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

/// Content-Security-Policy on every response. The built dashboard loads only its own
/// scripts, styles and API (the theme script is a file rather than inline for this reason);
/// React's `style={...}` goes through the CSSOM, which `style-src` does not govern.
const CSP: &str = concat!(
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; ",
    "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; ",
    "form-action 'self'; frame-ancestors 'none'"
);

/// The "not built" page carries its styles inline.
const NOT_BUILT_CSP: &str = concat!(
    "default-src 'self'; script-src 'self'; style-src 'unsafe-inline'; object-src 'none'; ",
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
);

/// Browser hardening on every response: no type sniffing, no framing (the Policy page must
/// not be clickjacked into switching enforcement off), no referrer, and the CSP above
/// unless the handler set its own.
async fn security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    h.entry(header::CONTENT_SECURITY_POLICY)
        .or_insert(HeaderValue::from_static(CSP));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    resp
}

/// No CORS: the built dashboard is same-origin, and the Vite dev server proxies `/api`
/// with the browser's `Host` (`changeOrigin: false`), so its dashboard is same-origin too.
pub fn router(state: AppState, ui_dir: Option<&Path>) -> Router {
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
            crate::api::router().layer(middleware::from_fn_with_state(state.clone(), guard_api)),
        )
        .route("/metrics", get(metrics))
        .route("/healthz", get(healthz));

    match ui_dir.filter(|d| d.join("index.html").is_file()) {
        Some(dir) => {
            let spa = ServeDir::new(dir).fallback(ServeFile::new(dir.join("index.html")));
            app = app.fallback_service(spa);
        }
        None => {
            app = app.fallback(|| async {
                (
                    [(
                        header::CONTENT_SECURITY_POLICY,
                        HeaderValue::from_static(NOT_BUILT_CSP),
                    )],
                    Html(NOT_BUILT),
                )
            });
        }
    }
    app.layer(middleware::from_fn_with_state(state.clone(), track))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// `names` as [`host_allowed`] compares them: trimmed, lowercase, without a port.
fn normalize_hosts(names: &[String]) -> Arc<[String]> {
    names
        .iter()
        .map(|h| strip_port(h.trim()).to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect()
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
/// server (same host and port). Any other page, a dev server on another port included, is
/// cross-origin.
pub fn origin_allowed(origin: &str, host: &str) -> bool {
    origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .is_some_and(|authority| authority.eq_ignore_ascii_case(host))
}

/// Refuse state-changing API calls a web page could have made. Without CORS headers other
/// origins cannot read responses, but a cross-site form or fetch can still send one, and DNS
/// rebinding makes the page same-origin: its host name resolves to 127.0.0.1, so the
/// browser sends `Host: attacker.example`. Non-browser clients send no `Origin`.
async fn guard_api(State(state): State<AppState>, req: Request, next: Next) -> Response {
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
    if is_policy && !host_allowed(&host, &state.allowed_hosts) {
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
async fn guard_loopback_host(
    State(allowed): State<Arc<[String]>>,
    req: Request,
    next: Next,
) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| req.uri().authority().map(|a| a.to_string()));
    if let Some(h) = host {
        if !host_allowed(&h, &allowed) {
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
    let m = &state.engine.models;
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "model_version": m.model_version(),
            // False: no models were found and verdicts come from the policy rules alone.
            "models_loaded": m.code_gbdt.is_some() || m.code_nn.is_some() || m.name_model.is_some(),
            "untrained": m.manifest.untrained,
            "mode": p.mode,
        })),
    )
        .into_response()
}

/// Who may change the policy on a server listening on `ip`: with a token, its holders;
/// without one, anyone on loopback (or with the opt-out), and nobody on a server the
/// network can reach.
pub fn policy_auth_for(ip: IpAddr, opts: &ServeOptions) -> anyhow::Result<PolicyAuth> {
    Ok(match &opts.admin_token {
        Some(t) => {
            anyhow::ensure!(
                t.len() >= MIN_ADMIN_TOKEN_LEN,
                "the admin token must be at least {MIN_ADMIN_TOKEN_LEN} characters"
            );
            PolicyAuth::Token(t.as_str().into())
        }
        None if ip.is_loopback() || opts.allow_anonymous_policy_changes => PolicyAuth::Open,
        None => {
            tracing::warn!(
                %ip,
                "policy changes over the API are off: this server is reachable from the network and has no CUSTOMS_ADMIN_TOKEN"
            );
            PolicyAuth::Disabled
        }
    })
}

/// Whether every request must name this machine by a loopback name, an IP address or an
/// `--allowed-hosts` name ([`guard_loopback_host`]): on a loopback listener, and on one
/// whose operator vouched that its published port is loopback
/// (`--allow-anonymous-policy-changes` without a token, the compose file's container).
/// Legitimate clients of either use such names, so any other `Host` is a rebound page.
pub fn host_guard_for(ip: IpAddr, opts: &ServeOptions) -> bool {
    ip.is_loopback() || (opts.allow_anonymous_policy_changes && opts.admin_token.is_none())
}

/// Serve on `listener` until `shutdown` resolves, then drain in-flight requests.
pub async fn serve_with(
    listener: TcpListener,
    engine: Arc<Engine>,
    ui_dir: Option<PathBuf>,
    opts: ServeOptions,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    let addr = listener.local_addr()?;
    let policy_auth = policy_auth_for(addr.ip(), &opts)?;
    let allowed_hosts = normalize_hosts(&opts.allowed_hosts);
    let (tx, rx) = watch::channel(false);
    tokio::spawn(maintain(engine.clone(), rx.clone()));
    let state = AppState {
        engine,
        shutdown: rx,
        policy_auth,
        allowed_hosts: allowed_hosts.clone(),
        token_failures: Arc::default(),
    };
    let mut app = router(state, ui_dir.as_deref());
    if host_guard_for(addr.ip(), &opts) {
        app = app.layer(middleware::from_fn_with_state(
            allowed_hosts,
            guard_loopback_host,
        ));
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

/// How often a running server drops expired package documents and returns freed memory.
const MAINTAIN_EVERY: Duration = Duration::from_secs(10);

/// Background upkeep until shutdown: without it, the resident size after a large install
/// stays at its peak for as long as the server runs (see [`crate::util::release_free_memory`]).
async fn maintain(engine: Arc<Engine>, mut shutdown: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(MAINTAIN_EVERY);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            // The only change ever sent is shutdown; a closed channel means the server is gone.
            _ = shutdown.changed() => return,
        }
        engine.registry.purge_expired_meta();
        let _ = tokio::task::spawn_blocking(crate::util::release_free_memory).await;
    }
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
    fn only_a_reachable_server_without_a_token_refuses_changes() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let open = ServeOptions::default();
        let opt_out = ServeOptions {
            allow_anonymous_policy_changes: true,
            ..Default::default()
        };
        let token = ServeOptions {
            admin_token: Some("0123456789abcdef".into()),
            ..Default::default()
        };
        for a in ["127.0.0.1", "::1"] {
            assert!(
                matches!(policy_auth_for(ip(a), &open), Ok(PolicyAuth::Open)),
                "{a}"
            );
        }
        for a in ["0.0.0.0", "192.0.2.1", "::"] {
            assert!(
                matches!(policy_auth_for(ip(a), &open), Ok(PolicyAuth::Disabled)),
                "{a}"
            );
            assert!(
                matches!(policy_auth_for(ip(a), &opt_out), Ok(PolicyAuth::Open)),
                "{a}"
            );
            assert!(
                matches!(policy_auth_for(ip(a), &token), Ok(PolicyAuth::Token(_))),
                "{a}"
            );
        }
        let short = ServeOptions {
            admin_token: Some("short".into()),
            ..Default::default()
        };
        assert!(policy_auth_for(ip("127.0.0.1"), &short).is_err());
    }

    #[test]
    fn host_names_are_checked_where_clients_use_loopback_names() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let open = ServeOptions::default();
        let anon = ServeOptions {
            allow_anonymous_policy_changes: true,
            ..Default::default()
        };
        assert!(host_guard_for(ip("127.0.0.1"), &open));
        assert!(host_guard_for(ip("::1"), &anon));
        // A team server is reached under its own names.
        assert!(!host_guard_for(ip("0.0.0.0"), &open));
        // A container told its published port is loopback (the compose file) is reached as
        // localhost too, so a rebound name must not read its events or policy.
        assert!(host_guard_for(ip("0.0.0.0"), &anon));
    }

    #[test]
    fn token_failures_lock_an_address_for_the_rest_of_the_window() {
        let f = TokenFailures::default();
        let t0 = Instant::now();
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        for _ in 0..MAX_TOKEN_FAILURES - 1 {
            f.failed(ip, t0);
        }
        assert_eq!(f.locked(ip, t0), None);
        f.failed(ip, t0);
        assert_eq!(f.locked(ip, t0), Some(TOKEN_FAILURE_WINDOW.as_secs()));
        // Another address is not affected; one in the same IPv6 /64 is.
        assert_eq!(f.locked("192.0.2.8".parse().unwrap(), t0), None);
        let v6 = |s: &str| s.parse::<IpAddr>().unwrap();
        for _ in 0..MAX_TOKEN_FAILURES {
            f.failed(v6("2001:db8:1:2::1"), t0);
        }
        assert!(f.locked(v6("2001:db8:1:2:ffff::9"), t0).is_some());
        assert_eq!(f.locked(v6("2001:db8:1:3::1"), t0), None);
        // The window ends, and the count starts over.
        let later = t0 + TOKEN_FAILURE_WINDOW;
        assert_eq!(f.locked(ip, later), None);
        f.failed(ip, later);
        assert_eq!(f.locked(ip, later), None);
    }

    #[test]
    fn origins() {
        assert!(origin_allowed("http://127.0.0.1:7878", "127.0.0.1:7878"));
        assert!(!origin_allowed("http://localhost:5173", "127.0.0.1:7878"));
        assert!(origin_allowed("http://localhost:5173", "localhost:5173"));
        assert!(!origin_allowed("http://evil.example", "127.0.0.1:7878"));
        assert!(!origin_allowed("null", "127.0.0.1:7878"));
    }
}
