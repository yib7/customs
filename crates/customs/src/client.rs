//! How the CLI and the hook get verdicts: from a running `customs serve` when one answers,
//! otherwise from an in-process engine with the same policy and models.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use customs_scan::Ecosystem;
use serde_json::{json, Value};

use crate::config::resolve_policy;
use crate::engine::{default_scanner, load_models, Engine, EngineConfig, EngineError, Limits};
use crate::metrics::Metrics;
use crate::util::ecosystem_str;
use crate::verdict::Verdict;

/// Where to find configuration for an in-process engine.
#[derive(Debug, Clone, Default)]
pub struct LocalOptions {
    pub config: Option<PathBuf>,
    pub models: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
}

/// Default data directory for client-side (hook, CLI) in-process checks: a user cache
/// directory, so running the hook inside a project does not litter it.
pub fn default_client_data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("CUSTOMS_DATA_DIR") {
        return PathBuf::from(d);
    }
    if let Ok(d) = std::env::var("XDG_CACHE_HOME") {
        return PathBuf::from(d).join("customs");
    }
    if let Ok(h) = std::env::var("HOME") {
        return PathBuf::from(h).join(".cache").join("customs");
    }
    std::env::temp_dir().join("customs")
}

pub fn local_engine(opts: &LocalOptions) -> anyhow::Result<Arc<Engine>> {
    let data_dir = opts
        .data_dir
        .clone()
        .unwrap_or_else(default_client_data_dir);
    let (policy, source) =
        resolve_policy(opts.config.as_deref(), &data_dir).map_err(|e| anyhow::anyhow!("{e}"))?;
    Engine::new(EngineConfig {
        data_dir,
        models: load_models(opts.models.as_deref())?,
        policy,
        policy_path: source.path,
        scanner: default_scanner(),
        limits: Limits::default(),
        metrics: Arc::new(Metrics::new()),
    })
}

/// A failed check.
#[derive(Debug, Clone, PartialEq)]
pub enum CheckError {
    /// The package was understood but could not be checked (no matching version, no
    /// files). A person should look at it.
    Package(String),
    /// Customs itself failed (network, server error).
    Infrastructure(String),
}

impl std::fmt::Display for CheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckError::Package(m) | CheckError::Infrastructure(m) => f.write_str(m),
        }
    }
}

pub enum Checker {
    Remote { base: String, http: reqwest::Client },
    Local(Arc<Engine>),
}

/// True when `base` names this machine, which a corporate HTTP proxy must not see.
pub fn is_loopback(base: &str) -> bool {
    url::Url::parse(base)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .is_some_and(|h| h == "localhost" || h == "127.0.0.1" || h == "[::1]" || h == "::1")
}

impl Checker {
    /// Use the server at `base` if `/healthz` answers quickly, else build a local engine.
    pub async fn connect(base: &str, local: &LocalOptions) -> anyhow::Result<Self> {
        let base = base.trim_end_matches('/').to_string();
        let mut b = reqwest::Client::builder().timeout(Duration::from_secs(55));
        if is_loopback(&base) {
            // A corporate HTTP proxy must not see requests meant for the local server.
            b = b.no_proxy();
        }
        let http = b.build()?;
        let healthy = http
            .get(format!("{base}/healthz"))
            .timeout(Duration::from_millis(1500))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        if healthy {
            return Ok(Checker::Remote { base, http });
        }
        tracing::debug!(server = %base, "server not reachable; checking in-process");
        Ok(Checker::Local(local_engine(local)?))
    }

    pub fn describe(&self) -> String {
        match self {
            Checker::Remote { base, .. } => format!("server {base}"),
            Checker::Local(_) => "in-process".to_string(),
        }
    }

    pub fn verdict_url(&self, id: Option<i64>) -> Option<String> {
        match (self, id) {
            (Checker::Remote { base, .. }, Some(id)) => Some(format!("{base}/api/verdicts/{id}")),
            _ => None,
        }
    }

    pub async fn check(
        &self,
        eco: Ecosystem,
        name: &str,
        version: Option<&str>,
        client: &str,
    ) -> Result<Verdict, CheckError> {
        match self {
            Checker::Local(engine) => engine
                .check(eco, name, version, Some(client.to_string()))
                .await
                .map_err(|e| match e {
                    EngineError::NotFound(m)
                    | EngineError::Unresolvable(m)
                    | EngineError::TooLarge(m) => CheckError::Package(m),
                    EngineError::Upstream(m) | EngineError::Internal(m) => {
                        CheckError::Infrastructure(m)
                    }
                }),
            Checker::Remote { base, http } => {
                let resp = http
                    .post(format!("{base}/api/check"))
                    .json(&json!({
                        "ecosystem": ecosystem_str(eco),
                        "name": name,
                        "version": version,
                        "client": client,
                    }))
                    .send()
                    .await
                    .map_err(|e| CheckError::Infrastructure(format!("calling {base}: {e}")))?;
                let status = resp.status();
                let body = resp
                    .text()
                    .await
                    .map_err(|e| CheckError::Infrastructure(e.to_string()))?;
                if status.is_success() {
                    return serde_json::from_str(&body).map_err(|e| {
                        CheckError::Infrastructure(format!("bad verdict from server: {e}"))
                    });
                }
                let parsed = serde_json::from_str::<Value>(&body).ok();
                // A nonexistent package is a 404 that still carries a verdict.
                if let Some(v) = parsed.as_ref().and_then(|p| p.get("verdict")) {
                    if let Ok(v) = serde_json::from_value::<Verdict>(v.clone()) {
                        return Ok(v);
                    }
                }
                let msg = parsed
                    .and_then(|v| v.get("error").and_then(Value::as_str).map(str::to_string))
                    .unwrap_or(body);
                if matches!(status.as_u16(), 404 | 413 | 422) {
                    Err(CheckError::Package(msg))
                } else {
                    Err(CheckError::Infrastructure(format!(
                        "server returned {status}: {msg}"
                    )))
                }
            }
        }
    }
}
