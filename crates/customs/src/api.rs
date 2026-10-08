//! JSON API under `/api` (DESIGN.md section 7).

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;

use crate::config::Policy;
use crate::engine::EngineError;
use crate::server::AppState;
use crate::store::EventFilter;
use crate::util::{parse_ecosystem, registry_name};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/check", post(check))
        .route("/events", get(events))
        .route("/events/stream", get(events_stream))
        .route("/verdicts/{id}", get(verdict))
        .route("/stats", get(stats))
        .route("/policy", get(get_policy).put(put_policy))
        .route("/model", get(model))
        .fallback(|| async { api_error(StatusCode::NOT_FOUND, "no such API route") })
}

pub fn api_error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({ "error": msg.into() }))).into_response()
}

fn engine_error(e: EngineError) -> Response {
    let status = match &e {
        EngineError::NotFound(_) => StatusCode::NOT_FOUND,
        EngineError::Unresolvable(_) => StatusCode::UNPROCESSABLE_ENTITY,
        EngineError::TooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
        EngineError::Upstream(_) => StatusCode::BAD_GATEWAY,
        EngineError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    api_error(status, e.to_string())
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CheckRequest {
    pub ecosystem: String,
    pub name: String,
    /// Exact version, range (`>=1,<2`, `^1.2`), dist-tag, or null for latest.
    #[serde(default)]
    pub version: Option<String>,
    /// Who is asking (`hook`, `cli`); recorded on the event.
    #[serde(default)]
    pub client: Option<String>,
    /// `served` (default): resolve an unpinned spec against the metadata this proxy
    /// serves, which leaves out versions `min_age_days` would block. `upstream`: against
    /// the registry's own, for an installer that does not use the proxy.
    #[serde(default)]
    pub resolve: Option<String>,
}

async fn check(
    State(state): State<AppState>,
    body: Result<Json<CheckRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(req) = match body {
        Ok(b) => b,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, e.body_text()),
    };
    let Some(eco) = parse_ecosystem(&req.ecosystem) else {
        return api_error(
            StatusCode::BAD_REQUEST,
            format!("unknown ecosystem '{}'", req.ecosystem),
        );
    };
    let name = req.name.trim();
    if name.is_empty() || name.len() > 214 || name.chars().any(char::is_whitespace) {
        return api_error(StatusCode::BAD_REQUEST, "invalid package name");
    }
    let client = req.client.or_else(|| Some("api".into()));
    let as_served = match req.resolve.as_deref() {
        None | Some("served") => true,
        Some("upstream") => false,
        Some(other) => {
            return api_error(
                StatusCode::BAD_REQUEST,
                format!("resolve must be 'served' or 'upstream', not '{other}'"),
            )
        }
    };
    match state
        .engine
        .check_resolving(eco, name, req.version.as_deref(), client, as_served)
        .await
    {
        // A name the registry does not know is a 404, with the verdict attached so the hook
        // and CLI can show the policy decision and the nearest popular name.
        Ok(v) if v.policy_hits.iter().any(|h| h.rule == "block_nonexistent") => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": format!("'{}' does not exist on {}", v.name, registry_name(v.ecosystem)),
                "code": "nonexistent_package",
                "verdict": v,
            })),
        )
            .into_response(),
        Ok(v) => Json(v).into_response(),
        Err(e) => engine_error(e),
    }
}

#[derive(Debug, Deserialize)]
struct EventsQuery {
    limit: Option<u32>,
    before: Option<i64>,
    decision: Option<String>,
    ecosystem: Option<String>,
    kind: Option<String>,
    q: Option<String>,
}

async fn events(State(state): State<AppState>, Query(q): Query<EventsQuery>) -> Response {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let nonempty = |s: Option<String>| s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let filter = EventFilter {
        before: q.before,
        decision: nonempty(q.decision),
        ecosystem: nonempty(q.ecosystem).map(|e| e.to_ascii_lowercase()),
        kind: nonempty(q.kind),
        q: nonempty(q.q),
    };
    match state.engine.store.events(limit, &filter) {
        Ok(ev) => Json(ev).into_response(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn events_stream(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<SseEvent, Infallible>>> {
    let rx = state.engine.subscribe();
    let mut shutdown = state.shutdown.clone();
    let stream = BroadcastStream::new(rx)
        .filter_map(|msg| async move {
            match msg {
                Ok(ev) => {
                    let data = serde_json::to_string(&ev).ok()?;
                    Some(Ok(SseEvent::default()
                        .event("install")
                        .id(ev.id.to_string())
                        .data(data)))
                }
                // A slow client missed some events; it can refetch /api/events.
                Err(BroadcastStreamRecvError::Lagged(n)) => {
                    Some(Ok(SseEvent::default().event("lagged").data(n.to_string())))
                }
            }
        })
        // End the stream on shutdown so graceful shutdown does not wait on open dashboards.
        .take_until(async move {
            let _ = shutdown.wait_for(|s| *s).await;
        });
    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

async fn verdict(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match state.engine.store.verdict(id) {
        Ok(Some(v)) => Json(v).into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, format!("no verdict {id}")),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct StatsQuery {
    days: Option<u32>,
}

async fn stats(State(state): State<AppState>, Query(q): Query<StatsQuery>) -> Response {
    match state.engine.store.stats(q.days.unwrap_or(30)) {
        Ok(s) => Json(s).into_response(),
        Err(e) => api_error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn get_policy(State(state): State<AppState>) -> Response {
    Json(&*state.engine.policy()).into_response()
}

async fn put_policy(State(state): State<AppState>, body: String) -> Response {
    let policy = match Policy::from_json(&body) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": e.to_string(),
                    "errors": [{ "field": e.key, "message": e.message }],
                })),
            )
                .into_response()
        }
    };
    if let Err(e) = state.engine.set_policy(policy) {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("saving policy: {e}"),
        );
    }
    tracing::info!(path = %state.engine.policy_path().display(), "policy updated");
    Json(&*state.engine.policy()).into_response()
}

/// `GET /api/model`: `models/metrics.json` merged with the manifest and the effective
/// thresholds, plus a summary of which components are loaded.
async fn model(State(state): State<AppState>) -> Response {
    let m = &state.engine.models;
    let policy = state.engine.policy();
    let eff = crate::policy::effective_thresholds(&policy, m.thresholds());
    let component = |loaded: bool, extra: Value| {
        let mut v = json!({ "loaded": loaded });
        if let (Some(o), Value::Object(e)) = (v.as_object_mut(), extra) {
            o.extend(e);
        }
        v
    };
    // metrics.json is either the evaluation summary itself or a document with a `metrics`
    // key plus extra top-level fields; either way it ends up under `metrics`.
    let mut out = serde_json::Map::new();
    match &m.metrics {
        Some(Value::Object(o)) if o.contains_key("metrics") => out.extend(o.clone()),
        Some(v) => {
            out.insert("metrics".into(), v.clone());
        }
        None => {
            out.insert("metrics".into(), Value::Null);
        }
    }
    let body = json!({
        "model_version": m.model_version(),
        "feature_schema_version": m.manifest.feature_schema_version,
        "untrained": m.manifest.untrained,
        "thresholds": eff,
        "model_thresholds": m.thresholds(),
        "manifest": m.manifest,
        "models_dir": m.dir.display().to_string(),
        "components": {
            "code_gbdt": component(m.code_gbdt.is_some(), m.code_gbdt.as_ref().map(|g| json!({
                "n_trees": g.n_trees(), "n_features": g.feature_names().len() })).unwrap_or(Value::Null)),
            "code_nn": component(m.code_nn.is_some(), m.code_nn.as_ref().map(|c| json!({
                "vocab_size": c.vocab_size(), "max_len": c.max_len() })).unwrap_or(Value::Null)),
            "name_model": component(m.name_model.is_some(), json!({
                "popular_pypi": m.popular_count(customs_scan::Ecosystem::Pypi),
                "popular_npm": m.popular_count(customs_scan::Ecosystem::Npm) })),
            "ensemble": component(m.ensemble_shipped, json!({ "weights": m.ensemble.weights, "bias": m.ensemble.bias })),
        },
    });
    if let Value::Object(b) = body {
        out.extend(b);
    }
    Json(Value::Object(out)).into_response()
}
