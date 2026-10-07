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
}

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
        .allow_headers([header::CONTENT_TYPE, header::ACCEPT]);

    let mut app = Router::new()
        .route("/pypi/simple", get(pypi::simple_index))
        .route("/pypi/simple/", get(pypi::simple_index))
        .route("/pypi/simple/{project}", get(pypi::simple_project))
        .route("/pypi/simple/{project}/", get(pypi::simple_project))
        .route("/pypi/files/{*path}", get(pypi::file))
        .route("/npm/{*rest}", any(npm::npm_any))
        .nest("/api", crate::api::router().layer(cors))
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
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
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
    let (tx, rx) = watch::channel(false);
    let state = AppState {
        engine,
        shutdown: rx,
    };
    let app = router(state, ui_dir.as_deref());
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
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
