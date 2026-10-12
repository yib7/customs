//! How the CLI and the hook get verdicts: from a running `customs serve` when one answers,
//! otherwise from an in-process engine with the same policy and models.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use customs_scan::Ecosystem;
use serde_json::{json, Value};

use crate::config::resolve_policy;
use crate::diff::ReleaseDiff;
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
    client_data_dir_from(|k| std::env::var(k).ok())
}

/// [`default_client_data_dir`] with the environment read through `env`: `CUSTOMS_DATA_DIR`,
/// else `$XDG_CACHE_HOME/customs`, `~/.cache/customs`, and on native Windows (no `HOME`)
/// `%LOCALAPPDATA%\customs` or `%USERPROFILE%\.cache\customs`. The temp directory, which
/// the OS may empty, is the last resort.
fn client_data_dir_from(env: impl Fn(&str) -> Option<String>) -> PathBuf {
    let var = |k: &str| env(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    if let Some(d) = var("CUSTOMS_DATA_DIR") {
        return d;
    }
    if let Some(d) = var("XDG_CACHE_HOME") {
        return d.join("customs");
    }
    if let Some(h) = var("HOME") {
        return h.join(".cache").join("customs");
    }
    if let Some(d) = var("LOCALAPPDATA") {
        return d.join("customs");
    }
    if let Some(h) = var("USERPROFILE") {
        return h.join(".cache").join("customs");
    }
    std::env::temp_dir().join("customs")
}

pub fn local_engine(opts: &LocalOptions) -> anyhow::Result<Arc<Engine>> {
    let data_dir = opts
        .data_dir
        .clone()
        .unwrap_or_else(default_client_data_dir);
    // No project directory: the hook, CLI and MCP server run in the agent's project, whose
    // `customs.toml` and `models/` must not choose how it is judged.
    let (policy, source) = resolve_policy(opts.config.as_deref(), &data_dir, None)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Engine::new(EngineConfig {
        data_dir,
        models: load_models(opts.models.as_deref(), None)?,
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
    Remote {
        base: String,
        http: reqwest::Client,
        /// Ecosystems whose installers in this environment fetch through `base`.
        routed: Vec<Ecosystem>,
    },
    Local(Arc<Engine>),
}

/// The variables `customs env` sets for each ecosystem.
const ROUTING_VARS: [(Ecosystem, &str, &str); 8] = [
    (Ecosystem::Pypi, "PIP_INDEX_URL", "/pypi/"),
    (Ecosystem::Pypi, "UV_INDEX_URL", "/pypi/"),
    (Ecosystem::Pypi, "UV_DEFAULT_INDEX", "/pypi/"),
    (Ecosystem::Pypi, "PIPENV_PYPI_MIRROR", "/pypi/"),
    (Ecosystem::Pypi, "PDM_PYPI_URL", "/pypi/"),
    (Ecosystem::Npm, "npm_config_registry", "/npm"),
    (Ecosystem::Npm, "NPM_CONFIG_REGISTRY", "/npm"),
    (Ecosystem::Npm, "YARN_NPM_REGISTRY_SERVER", "/npm"),
];

/// Ecosystems whose installers, going by `env`, fetch through the server at `base`. Only
/// for those does an unpinned check resolve the way the proxy serves the package; anywhere
/// else the installer sees every version, so the check must too.
pub fn routed_ecosystems(base: &str, env: impl Fn(&str) -> Option<String>) -> Vec<Ecosystem> {
    let base = base.trim_end_matches('/');
    let mut out = Vec::new();
    for (eco, var, path) in ROUTING_VARS {
        if !out.contains(&eco)
            && env(var).is_some_and(|v| v.trim().starts_with(&format!("{base}{path}")))
        {
            out.push(eco);
        }
    }
    out
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
        // A typo here would otherwise read as "server down" and quietly check in-process.
        if !url::Url::parse(&base)
            .is_ok_and(|u| matches!(u.scheme(), "http" | "https") && u.has_host())
        {
            anyhow::bail!(
                "the server '{base}' (--server or CUSTOMS_SERVER) is not an http(s) URL; use \
                 one like http://127.0.0.1:7878"
            );
        }
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
            let routed = routed_ecosystems(&base, |k| std::env::var(k).ok());
            return Ok(Checker::Remote { base, http, routed });
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
            // Nothing is proxied without a server, so resolve as the registry would.
            Checker::Local(engine) => engine
                .check_resolving(eco, name, version, Some(client.to_string()), false)
                .await
                .map_err(check_error),
            Checker::Remote { base, http, routed } => {
                let resp = http
                    .post(format!("{base}/api/check"))
                    .json(&json!({
                        "ecosystem": ecosystem_str(eco),
                        "name": name,
                        "version": version,
                        "client": client,
                        "resolve": if routed.contains(&eco) { "served" } else { "upstream" },
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

fn check_error(e: EngineError) -> CheckError {
    match e {
        EngineError::NotFound(m) | EngineError::Unresolvable(m) | EngineError::TooLarge(m) => {
            CheckError::Package(m)
        }
        EngineError::Upstream(m) | EngineError::Internal(m) => CheckError::Infrastructure(m),
    }
}

impl Checker {
    /// What release `to` (default: newest) changes relative to `from` (default: the
    /// release before it); see [`Engine::diff_releases`].
    pub async fn diff(
        &self,
        eco: Ecosystem,
        name: &str,
        from: Option<&str>,
        to: Option<&str>,
        client: &str,
    ) -> Result<ReleaseDiff, CheckError> {
        match self {
            Checker::Local(engine) => engine
                .diff_releases(eco, name, from, to, Some(client.to_string()))
                .await
                .map_err(check_error),
            Checker::Remote { base, http, .. } => {
                let mut query = vec![
                    ("ecosystem", ecosystem_str(eco).to_string()),
                    ("name", name.to_string()),
                    ("client", client.to_string()),
                ];
                if let Some(f) = from {
                    query.push(("from", f.to_string()));
                }
                if let Some(t) = to {
                    query.push(("to", t.to_string()));
                }
                // Two downloads and two scans on a cold cache.
                let resp = http
                    .get(format!("{base}/api/diff"))
                    .query(&query)
                    .timeout(Duration::from_secs(180))
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
                        CheckError::Infrastructure(format!("bad diff from server: {e}"))
                    });
                }
                let msg = serde_json::from_str::<Value>(&body)
                    .ok()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_data_dir_prefers_a_lasting_user_directory() {
        let dir = |pairs: &'static [(&'static str, &'static str)]| {
            client_data_dir_from(|k| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| v.to_string())
            })
        };
        assert_eq!(
            dir(&[("CUSTOMS_DATA_DIR", "/d"), ("HOME", "/h")]),
            PathBuf::from("/d")
        );
        assert_eq!(
            dir(&[("XDG_CACHE_HOME", "/x"), ("HOME", "/h")]),
            PathBuf::from("/x/customs")
        );
        assert_eq!(dir(&[("HOME", "/h")]), PathBuf::from("/h/.cache/customs"));
        // Native Windows has no HOME: not %TEMP%, which Storage Sense empties.
        let win = &[
            ("LOCALAPPDATA", "C:/Users/u/AppData/Local"),
            ("USERPROFILE", "C:/Users/u"),
        ];
        assert_eq!(dir(win), PathBuf::from("C:/Users/u/AppData/Local/customs"));
        assert_eq!(
            dir(&[("USERPROFILE", "C:/Users/u")]),
            PathBuf::from("C:/Users/u/.cache/customs")
        );
        assert_eq!(dir(&[("HOME", "")]), std::env::temp_dir().join("customs"));
    }

    #[test]
    fn routing_follows_customs_env() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        let base = "http://127.0.0.1:7878";
        assert_eq!(
            routed_ecosystems(
                base,
                env(&[
                    ("PIP_INDEX_URL", "http://127.0.0.1:7878/pypi/simple"),
                    ("NPM_CONFIG_REGISTRY", "https://registry.npmjs.org/"),
                ])
            ),
            vec![Ecosystem::Pypi]
        );
        assert_eq!(
            routed_ecosystems(
                base,
                env(&[("npm_config_registry", "http://127.0.0.1:7878/npm/")])
            ),
            vec![Ecosystem::Npm]
        );
        assert!(routed_ecosystems(base, env(&[])).is_empty());
    }
}
