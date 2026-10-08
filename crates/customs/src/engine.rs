//! The decision pipeline shared by the proxy, the API, the CLI, and the hook.
//!
//! For one artifact: fetch registry metadata and the archive (in parallel), store the
//! archive in the content-addressed cache, scan and score it (or reuse the cached result
//! for the same name, version, digest, and model version), apply the policy, persist the
//! verdict and an event, and broadcast the event to SSE subscribers. Concurrent requests
//! for the same artifact URL share one evaluation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use chrono::{DateTime, Utc};
use customs_model::{decide, Decision, Models, Reason, ScoreInput, Scores};
use customs_scan::{scan_archive, Ecosystem, Evidence, ScanError, ScanOptions, ScanReport};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, OnceCell};

use crate::config::{Policy, RuleSeverity};
use crate::history::{release_history, DependencyInfo, ReleaseHistory, MAX_ADDED_LOOKUPS};
use crate::metrics::Metrics;
use crate::policy::{effective_thresholds, evaluate, PolicyContext};
use crate::registry::{FetchError, FileMeta, Registry, VersionMeta};
use crate::resolve::resolve_version;
use crate::store::{ArtifactRow, NewEvent, ScanKey, Store};
use crate::util::{
    ecosystem_str, normalize_name, now, now_ts, parse_npm_tarball, parse_pypi_filename,
};
use crate::verdict::{Event, EventKind, PolicyHit, Verdict};

/// The scanner, injectable so tests can stand in for `customs-scan`.
pub type ScanFn =
    Arc<dyn Fn(&[u8], &str, Ecosystem) -> Result<ScanReport, ScanError> + Send + Sync>;

pub fn default_scanner() -> ScanFn {
    Arc::new(|bytes, filename, eco| {
        let opts = ScanOptions {
            tokens: true,
            ..ScanOptions::default()
        };
        scan_archive(bytes, filename, Some(eco), &opts)
    })
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Artifacts larger than this are not downloaded at all.
    pub max_download_bytes: u64,
    /// Artifacts larger than this are served but only scored on name and metadata.
    pub max_scan_bytes: u64,
    /// `POST /api/check` does not download artifacts larger than this.
    pub max_check_bytes: u64,
    /// The artifact cache is trimmed (least recently used first) when it grows past this.
    pub max_cache_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_download_bytes: 2 << 30,
            max_scan_bytes: 256 << 20,
            max_check_bytes: 64 << 20,
            max_cache_bytes: 10 << 30,
        }
    }
}

pub struct EngineConfig {
    pub data_dir: PathBuf,
    pub models: Models,
    pub policy: Policy,
    pub policy_path: PathBuf,
    pub scanner: ScanFn,
    pub limits: Limits,
    pub metrics: Arc<Metrics>,
}

/// Why an evaluation failed, mapped to HTTP statuses by the callers.
#[derive(Debug, Clone, PartialEq)]
pub enum EngineError {
    /// Upstream says the artifact or package does not exist.
    NotFound(String),
    /// A version constraint matched nothing.
    Unresolvable(String),
    /// Upstream failure or a transport error.
    Upstream(String),
    TooLarge(String),
    Internal(String),
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EngineError::NotFound(m)
            | EngineError::Unresolvable(m)
            | EngineError::Upstream(m)
            | EngineError::TooLarge(m)
            | EngineError::Internal(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for EngineError {}

impl From<FetchError> for EngineError {
    fn from(e: FetchError) -> Self {
        match e {
            FetchError::NotFound => EngineError::NotFound("not found upstream".into()),
            FetchError::TooLarge(_) => EngineError::TooLarge(e.to_string()),
            other => EngineError::Upstream(other.to_string()),
        }
    }
}

fn internal(e: impl std::fmt::Display) -> EngineError {
    EngineError::Internal(e.to_string())
}

/// Registry facts the policy needs.
#[derive(Debug, Clone, Default)]
pub struct MetaFacts {
    pub exists: bool,
    pub published: Option<DateTime<Utc>>,
    pub install_scripts: Vec<String>,
    /// The version compared with earlier releases, when the full package metadata was read.
    pub history: Option<ReleaseHistory>,
}

/// One artifact to evaluate.
#[derive(Debug, Clone)]
pub struct ArtifactRequest {
    pub ecosystem: Ecosystem,
    /// Normalized package name.
    pub name: String,
    pub version: Option<String>,
    pub filename: String,
    pub url: String,
    pub client: Option<String>,
    pub kind: EventKind,
    /// Precomputed metadata (from `check`); fetched when `None`.
    pub meta: Option<MetaFacts>,
}

/// Result of evaluating an artifact.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub verdict: Verdict,
    /// Cached archive, for streaming to the client.
    pub path: Option<PathBuf>,
    pub size: u64,
}

/// What the scan cache stores: everything in a verdict that depends only on the bytes,
/// the name, and the model version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ScanSummary {
    risk: Option<f64>,
    scores: Scores,
    reasons: Vec<Reason>,
    evidence: Vec<Evidence>,
    install_surface: Vec<String>,
    scan_errors: Vec<String>,
    install_scripts: Vec<String>,
    scanned_ms: u64,
    /// False when the archive was not scanned (too large, or the scanner rejected it).
    scanned: bool,
    #[serde(default)]
    not_scanned_reason: Option<String>,
    /// Code files the scanner could not read (over its per-file size cap).
    #[serde(default)]
    unread_code: Vec<String>,
    /// `.pth` files whose code launches a process, connects or downloads at every
    /// interpreter start.
    #[serde(default)]
    startup_hooks: Vec<String>,
}

type Flight = Arc<OnceCell<Result<Outcome, EngineError>>>;

pub struct Engine {
    policy: RwLock<Arc<Policy>>,
    policy_path: PathBuf,
    pub models: Arc<Models>,
    pub registry: Registry,
    pub store: Store,
    pub metrics: Arc<Metrics>,
    cache_dir: PathBuf,
    scanner: ScanFn,
    limits: Limits,
    events: broadcast::Sender<Event>,
    inflight: Mutex<HashMap<String, Flight>>,
    tmp_counter: AtomicU64,
    /// Bytes downloaded since the cache size was last checked.
    cache_growth: AtomicU64,
}

const INSTALL_SCRIPT_NAMES: [&str; 3] = ["preinstall", "install", "postinstall"];

fn install_scripts_from_report(r: &ScanReport) -> Vec<String> {
    let mut out: Vec<String> = r
        .install_surface
        .iter()
        .filter_map(|s| s.strip_prefix("package.json:scripts."))
        .filter(|s| INSTALL_SCRIPT_NAMES.contains(s))
        .map(str::to_string)
        .collect();
    if out.is_empty()
        && r.features
            .get("n_npm_install_scripts")
            .is_some_and(|n| *n > 0.0)
    {
        out.push("install script".into());
    }
    out
}

impl Engine {
    pub fn new(cfg: EngineConfig) -> anyhow::Result<Arc<Self>> {
        let cache_dir = cfg.data_dir.join("cache");
        std::fs::create_dir_all(cache_dir.join("tmp"))?;
        let store = Store::open(&cfg.data_dir.join("customs.db"))?;
        let (events, _) = broadcast::channel(1024);
        Ok(Arc::new(Self {
            policy: RwLock::new(Arc::new(cfg.policy)),
            policy_path: cfg.policy_path,
            models: Arc::new(cfg.models),
            registry: Registry::new(cfg.metrics.clone())?,
            store,
            metrics: cfg.metrics,
            cache_dir,
            scanner: cfg.scanner,
            limits: cfg.limits,
            events,
            inflight: Mutex::new(HashMap::new()),
            tmp_counter: AtomicU64::new(0),
            // Starting above the trigger makes the first download check the size.
            cache_growth: AtomicU64::new(u64::MAX / 2),
        }))
    }

    pub fn policy(&self) -> Arc<Policy> {
        self.policy
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn policy_path(&self) -> &Path {
        &self.policy_path
    }

    /// Persist and activate a validated policy.
    pub fn set_policy(&self, p: Policy) -> anyhow::Result<()> {
        if let Some(dir) = self.policy_path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let tmp = self.policy_path.with_extension("toml.tmp");
        std::fs::write(&tmp, p.to_toml())?;
        std::fs::rename(&tmp, &self.policy_path)?;
        *self.policy.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(p);
        Ok(())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    fn blob_path(&self, sha256: &str) -> PathBuf {
        self.cache_dir.join(&sha256[..2]).join(sha256)
    }

    /// Evaluate one artifact; concurrent calls for the same URL share a single evaluation.
    pub async fn evaluate_artifact(
        self: &Arc<Self>,
        req: ArtifactRequest,
    ) -> Result<Outcome, EngineError> {
        let key = req.url.clone();
        let cell = {
            let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            match map.get(&key) {
                Some(c) => {
                    self.metrics.singleflight_join();
                    c.clone()
                }
                None => {
                    let c: Flight = Arc::new(OnceCell::new());
                    map.insert(key.clone(), c.clone());
                    c
                }
            }
        };
        let this = self.clone();
        let result = cell
            .get_or_init(|| async move {
                // A spawned task finishes even if the client that started it disconnects,
                // so the other waiters still get a result.
                tokio::spawn(async move { this.evaluate_uncoalesced(req).await })
                    .await
                    .unwrap_or_else(|e| Err(internal(format!("evaluation task failed: {e}"))))
            })
            .await
            .clone();
        let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
        if map.get(&key).is_some_and(|c| Arc::ptr_eq(c, &cell)) {
            map.remove(&key);
        }
        result
    }

    async fn evaluate_uncoalesced(
        self: Arc<Self>,
        req: ArtifactRequest,
    ) -> Result<Outcome, EngineError> {
        let policy = self.policy();
        let meta_fut = async {
            match &req.meta {
                Some(m) => m.clone(),
                None => self.artifact_meta(&policy, &req).await,
            }
        };
        let (meta, fetched) = tokio::join!(meta_fut, self.fetch_artifact(&req.url, &req.filename));
        let (path, sha256, size) = fetched?;
        let (summary, cached) = self
            .scan_cached(
                req.ecosystem,
                &req.name,
                req.version.as_deref(),
                &sha256,
                &path,
                &req.filename,
                size,
            )
            .await?;
        let verdict = self.build_verdict(
            &policy,
            req.ecosystem,
            &req.name,
            req.version.clone(),
            Some(req.filename.clone()),
            Some(sha256),
            &summary,
            cached,
            &meta,
        );
        let verdict = self.record(verdict, req.kind, req.client.clone())?;
        Ok(Outcome {
            verdict,
            path: Some(path),
            size,
        })
    }

    /// Looks up each registry dependency a release added (npm), for
    /// `young_dependency_added`. A failed lookup leaves that dependency unjudged.
    async fn lookup_added_dependencies(&self, policy: &Policy, h: &mut ReleaseHistory) {
        if policy.young_dependency_added == RuleSeverity::Off || h.added_dependencies.is_empty() {
            return;
        }
        let lookups = h
            .added_dependencies
            .iter()
            .take(MAX_ADDED_LOOKUPS)
            .map(|d| {
                self.registry
                    .package_meta(&policy.upstream, Ecosystem::Npm, &d.name)
            })
            .collect::<Vec<_>>();
        let results = futures::future::join_all(lookups).await;
        for (d, r) in h.added_dependencies.iter_mut().zip(results) {
            d.info = match r {
                Ok(Some(m)) => Some(DependencyInfo {
                    exists: true,
                    created: m.created,
                    people: m.people.clone(),
                }),
                Ok(None) => Some(DependencyInfo::default()),
                Err(e) => {
                    tracing::debug!(dependency = %d.name, error = %e, "dependency lookup failed");
                    None
                }
            };
        }
    }

    /// Registry facts for an artifact requested through the proxy. Failures only cost the
    /// metadata rules, so they are logged and otherwise ignored.
    async fn artifact_meta(&self, policy: &Policy, req: &ArtifactRequest) -> MetaFacts {
        let mut facts = MetaFacts {
            exists: true,
            ..Default::default()
        };
        let Some(version) = &req.version else {
            return facts;
        };
        // npm needs the packument anyway. For PyPI the per-release document is enough unless
        // a release history rule that applies to PyPI is on; then the project document (also
        // cached for `check`) is read, falling back to the release document when it does not
        // list the version yet.
        let full = match req.ecosystem {
            Ecosystem::Npm => true,
            Ecosystem::Pypi => policy.pypi_history_rules_enabled(),
        };
        let mut result: Result<Option<VersionMeta>, FetchError> = Ok(None);
        if full {
            result = self
                .registry
                .package_meta(&policy.upstream, req.ecosystem, &req.name)
                .await
                .map(|m| {
                    m.and_then(|m| {
                        facts.history = release_history(&m, version);
                        m.version(version).cloned()
                    })
                });
        }
        if let Some(h) = facts.history.as_mut() {
            self.lookup_added_dependencies(policy, h).await;
        }
        if req.ecosystem == Ecosystem::Pypi && !matches!(result, Ok(Some(_))) {
            result = self
                .registry
                .pypi_release(&policy.upstream, &req.name, version)
                .await;
        }
        match result {
            Ok(Some(vm)) => {
                // Prefer the upload time of this exact file over the release time.
                facts.published = vm
                    .files
                    .iter()
                    .find(|f| f.filename == req.filename)
                    .and_then(|f| f.upload_time)
                    .or(vm.published);
                facts.install_scripts = vm.install_scripts;
            }
            Ok(None) => {
                tracing::debug!(name = %req.name, version, "no registry metadata for version")
            }
            Err(e) => {
                tracing::warn!(name = %req.name, version, error = %e, "registry metadata lookup failed")
            }
        }
        facts
    }

    /// Cached archive path, sha256, and size; downloads on a cache miss.
    async fn fetch_artifact(
        &self,
        url: &str,
        filename: &str,
    ) -> Result<(PathBuf, String, u64), EngineError> {
        if let Some(row) = self.store.artifact_get(url).map_err(internal)? {
            let p = self.blob_path(&row.sha256);
            if p.exists() {
                crate::cache::touch(&p);
                self.metrics.cache("artifact_hit");
                return Ok((p, row.sha256, row.size));
            }
        }
        self.metrics.cache("artifact_miss");
        let n = self.tmp_counter.fetch_add(1, Ordering::Relaxed);
        let tmp = self.cache_dir.join("tmp").join(format!(
            "{}-{}-{n}.part",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let dl = match self
            .registry
            .download(url, &tmp, self.limits.max_download_bytes)
            .await
        {
            Ok(d) => d,
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(e.into());
            }
        };
        let dest = self.blob_path(&dl.sha256);
        if let Some(dir) = dest.parent() {
            tokio::fs::create_dir_all(dir).await.map_err(internal)?;
        }
        tokio::fs::rename(&tmp, &dest).await.map_err(internal)?;
        self.store
            .artifact_put(
                url,
                &ArtifactRow {
                    sha256: dl.sha256.clone(),
                    filename: filename.to_string(),
                    size: dl.size,
                },
            )
            .map_err(internal)?;
        self.maybe_trim_cache(dl.size);
        Ok((dest, dl.sha256, dl.size))
    }

    /// Check the cache size after every 1/16 of the cap has been downloaded.
    fn maybe_trim_cache(&self, added: u64) {
        let max = self.limits.max_cache_bytes;
        let grown = self.cache_growth.fetch_add(added, Ordering::Relaxed) + added;
        if grown < max / 16 {
            return;
        }
        self.cache_growth.store(0, Ordering::Relaxed);
        let dir = self.cache_dir.clone();
        tokio::task::spawn_blocking(move || {
            let e = crate::cache::evict(&dir, max, std::time::Duration::from_secs(600));
            if e.files > 0 {
                tracing::info!(
                    files = e.files,
                    freed_mb = e.bytes >> 20,
                    remaining_mb = e.remaining_bytes >> 20,
                    "trimmed artifact cache"
                );
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    async fn scan_cached(
        &self,
        eco: Ecosystem,
        name: &str,
        version: Option<&str>,
        sha256: &str,
        path: &Path,
        filename: &str,
        size: u64,
    ) -> Result<(ScanSummary, bool), EngineError> {
        let key = ScanKey {
            ecosystem: eco,
            name: name.to_string(),
            version: version.map(str::to_string),
            sha256: sha256.to_string(),
            model_version: self.models.model_version().to_string(),
        };
        if let Some(json) = self.store.scan_cache_get(&key).map_err(internal)? {
            if let Ok(s) = serde_json::from_str::<ScanSummary>(&json) {
                self.metrics.cache("scan_hit");
                return Ok((s, true));
            }
        }
        self.metrics.cache("scan_miss");
        let started = Instant::now();
        let summary = if size > self.limits.max_scan_bytes {
            let limit = self.limits.max_scan_bytes >> 20;
            let mut s = self.name_only_summary(
                eco,
                name,
                Some(format!(
                    "archive is {} MB, above the {limit} MB scan limit; scored on name and metadata only",
                    size >> 20,
                )),
            );
            // Padding a package past the limit must not let its install-time code through
            // unread: list what would run, which the `unread_code` rule acts on.
            let (p, f) = (path.to_path_buf(), filename.to_string());
            let found =
                tokio::task::spawn_blocking(move || customs_scan::install_time_code(&p, eco, &f))
                    .await
                    .map_err(internal)?;
            s.unread_code = found
                .into_iter()
                .map(|c| format!("{c} (in an archive above the {limit} MB scan limit)"))
                .collect();
            s
        } else {
            let bytes = tokio::fs::read(path).await.map_err(internal)?;
            let scanner = self.scanner.clone();
            let models = self.models.clone();
            let (name, filename) = (name.to_string(), filename.to_string());
            tokio::task::spawn_blocking(move || {
                scan_and_score(&scanner, &models, &bytes, &filename, eco, &name)
            })
            .await
            .map_err(internal)?
        };
        self.metrics.scan_latency(started.elapsed());
        let json = serde_json::to_string(&summary).map_err(internal)?;
        self.store.scan_cache_put(&key, &json).map_err(internal)?;
        Ok((summary, false))
    }

    fn name_only_summary(
        &self,
        eco: Ecosystem,
        name: &str,
        not_scanned: Option<String>,
    ) -> ScanSummary {
        let a = self.models.assess(&ScoreInput {
            ecosystem: eco,
            name: Some(name),
            features: None,
            tokens: None,
        });
        ScanSummary {
            risk: a.risk,
            scores: a.scores,
            reasons: a.reasons,
            evidence: Vec::new(),
            install_surface: Vec::new(),
            scan_errors: Vec::new(),
            install_scripts: Vec::new(),
            scanned_ms: 0,
            scanned: false,
            not_scanned_reason: not_scanned,
            unread_code: Vec::new(),
            startup_hooks: Vec::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn build_verdict(
        &self,
        policy: &Policy,
        eco: Ecosystem,
        name: &str,
        version: Option<String>,
        artifact: Option<String>,
        sha256: Option<String>,
        s: &ScanSummary,
        cached: bool,
        meta: &MetaFacts,
    ) -> Verdict {
        let thresholds = effective_thresholds(policy, self.models.thresholds());
        let model_decision = s
            .risk
            .map(|r| decide(r, thresholds.warn, thresholds.block))
            .unwrap_or(Decision::Allow);
        let mut scripts = meta.install_scripts.clone();
        for x in &s.install_scripts {
            if !scripts.contains(x) {
                scripts.push(x.clone());
            }
        }
        let outcome = evaluate(
            policy,
            &PolicyContext {
                ecosystem: eco,
                name,
                version: version.as_deref(),
                exists: meta.exists,
                published: meta.published,
                install_scripts: scripts,
                history: meta.history.as_ref(),
                now: now(),
            },
        );
        let mut hits = outcome.hits.clone();
        hits.extend(scan_hits(policy, s));
        let decision = if outcome.denied {
            Decision::Block
        } else if outcome.allowed {
            Decision::Allow
        } else {
            hits.iter()
                .map(|h| h.severity)
                .fold(model_decision, std::cmp::max)
        };
        Verdict {
            id: None,
            ts: now_ts(),
            ecosystem: eco,
            name: name.to_string(),
            version,
            artifact,
            sha256,
            decision,
            risk: s.risk,
            model_decision,
            thresholds,
            scores: s.scores,
            policy_hits: hits,
            reasons: s.reasons.clone(),
            evidence: s.evidence.clone(),
            install_surface: s.install_surface.clone(),
            scan_errors: s.scan_errors.clone(),
            scanned_ms: s.scanned_ms,
            model_version: self.models.model_version().to_string(),
            cached,
            mode: policy.mode,
        }
    }

    /// Store a verdict and its event, update metrics, and notify subscribers.
    fn record(
        &self,
        mut v: Verdict,
        kind: EventKind,
        client: Option<String>,
    ) -> Result<Verdict, EngineError> {
        let id = self.store.insert_verdict(&v).map_err(internal)?;
        v.id = Some(id);
        let event = self
            .store
            .insert_event(NewEvent {
                ecosystem: v.ecosystem,
                name: v.name.clone(),
                version: v.version.clone(),
                client,
                kind,
                decision: Some(v.decision),
                risk: v.risk,
                verdict_id: Some(id),
            })
            .map_err(internal)?;
        self.metrics
            .verdict(v.decision.as_str(), ecosystem_str(v.ecosystem));
        self.metrics.event(kind.as_str());
        tracing::info!(
            kind = kind.as_str(),
            ecosystem = ecosystem_str(v.ecosystem),
            name = %v.name,
            version = v.version.as_deref().unwrap_or("-"),
            decision = v.decision.as_str(),
            risk = v.risk.unwrap_or(-1.0),
            verdict_id = id,
            cached = v.cached,
            "verdict"
        );
        // No subscribers is fine.
        let _ = self.events.send(event);
        Ok(v)
    }

    /// Record a request for a name the registry does not know (from the proxy).
    pub fn record_nonexistent(
        &self,
        eco: Ecosystem,
        name: &str,
        client: Option<String>,
    ) -> Result<Verdict, EngineError> {
        let policy = self.policy();
        let name = normalize_name(eco, name);
        let s = self.name_only_summary(eco, &name, None);
        let v = self.build_verdict(
            &policy,
            eco,
            &name,
            None,
            None,
            None,
            &s,
            false,
            &MetaFacts::default(),
        );
        self.record(v, EventKind::NonexistentPackage, client)
    }

    /// `POST /api/check`: resolve, fetch, scan, decide.
    pub async fn check(
        self: &Arc<Self>,
        eco: Ecosystem,
        name: &str,
        version: Option<&str>,
        client: Option<String>,
    ) -> Result<Verdict, EngineError> {
        let policy = self.policy();
        let name = normalize_name(eco, name);
        let Some(meta) = self
            .registry
            .package_meta(&policy.upstream, eco, &name)
            .await?
        else {
            return self.record_nonexistent(eco, &name, client);
        };
        let version = resolve_version(&meta, version).map_err(EngineError::Unresolvable)?;
        let vm = meta
            .version(&version)
            .cloned()
            .ok_or_else(|| EngineError::Unresolvable(format!("{name} has no version {version}")))?;
        let mut history = release_history(&meta, &version);
        if let Some(h) = history.as_mut() {
            self.lookup_added_dependencies(&policy, h).await;
        }
        let facts = MetaFacts {
            exists: true,
            published: vm.published,
            install_scripts: vm.install_scripts.clone(),
            history,
        };
        let Some(file) = choose_file(eco, &vm.files) else {
            return Err(EngineError::NotFound(format!(
                "{name} {version} has no downloadable files"
            )));
        };
        if file.size.is_some_and(|s| s > self.limits.max_check_bytes) {
            let s = self.name_only_summary(
                eco,
                &name,
                Some(format!(
                    "{} is {} MB, above the {} MB check limit; scored on name and metadata only",
                    file.filename,
                    file.size.unwrap_or(0) >> 20,
                    self.limits.max_check_bytes >> 20
                )),
            );
            let v = self.build_verdict(
                &policy,
                eco,
                &name,
                Some(version),
                Some(file.filename.clone()),
                file.sha256.clone(),
                &s,
                false,
                &facts,
            );
            return self.record(v, EventKind::Check, client);
        }
        let out = self
            .evaluate_artifact(ArtifactRequest {
                ecosystem: eco,
                name,
                version: Some(version),
                filename: file.filename.clone(),
                url: file.url.clone(),
                client,
                kind: EventKind::Check,
                meta: Some(facts),
            })
            .await?;
        Ok(out.verdict)
    }

    /// Scan a local archive without network access or persistence (`customs scan`).
    pub fn scan_local(
        &self,
        bytes: &[u8],
        filename: &str,
        eco: Ecosystem,
        name: Option<&str>,
    ) -> Verdict {
        let policy = self.policy();
        let guessed = match eco {
            Ecosystem::Pypi => parse_pypi_filename(filename),
            Ecosystem::Npm => None,
        };
        let s = scan_and_score(
            &self.scanner,
            &self.models,
            bytes,
            filename,
            eco,
            name.or(guessed.as_ref().map(|g| g.0.as_str()))
                .unwrap_or(""),
        );
        local_verdict(self, &policy, bytes, filename, eco, name, guessed, s)
    }
}

#[allow(clippy::too_many_arguments)]
fn local_verdict(
    engine: &Engine,
    policy: &Policy,
    bytes: &[u8],
    filename: &str,
    eco: Ecosystem,
    name: Option<&str>,
    guessed: Option<(String, String)>,
    s: ScanSummary,
) -> Verdict {
    use sha2::{Digest, Sha256};
    let sha = hex::encode(Sha256::digest(bytes));
    let name = name
        .map(str::to_string)
        .or(guessed.as_ref().map(|g| g.0.clone()))
        .unwrap_or_else(|| filename.to_string());
    let version = guessed
        .map(|g| g.1)
        .or_else(|| parse_npm_tarball(&name, filename));
    let facts = MetaFacts {
        exists: true,
        ..Default::default()
    };
    engine.build_verdict(
        policy,
        eco,
        &normalize_name(eco, &name),
        version,
        Some(filename.to_string()),
        Some(sha),
        &s,
        false,
        &facts,
    )
}

/// Policy hits about the scan itself: what the scanner could not read.
fn scan_hits(policy: &Policy, s: &ScanSummary) -> Vec<PolicyHit> {
    let mut hits = Vec::new();
    if let Some(severity) = policy.scan_error.decision() {
        if !s.scan_errors.is_empty() && !s.scanned {
            hits.push(PolicyHit {
                rule: "scan_error".into(),
                severity,
                detail: format!("archive could not be scanned: {}", s.scan_errors.join("; ")),
            });
        }
    }
    if let Some(r) = &s.not_scanned_reason {
        hits.push(PolicyHit {
            rule: "not_scanned".into(),
            severity: Decision::Allow,
            detail: r.clone(),
        });
    }
    if let (Some(severity), Some(first)) = (policy.unread_code.decision(), s.unread_code.first()) {
        let more = match s.unread_code.len() {
            1 => String::new(),
            n => format!(" and {} more", n - 1),
        };
        hits.push(PolicyHit {
            rule: "unread_code".into(),
            severity,
            detail: format!(
                "{first}{more} could not be read by the scanner (too large, encrypted or \
                 compressed with an unsupported method), so its code was never inspected; \
                 installing would run it"
            ),
        });
    }
    if let (Some(severity), Some(first)) = (policy.startup_hook.decision(), s.startup_hooks.first())
    {
        let more = match s.startup_hooks.len() {
            1 => String::new(),
            n => format!(" (and {} more)", n - 1),
        };
        hits.push(PolicyHit {
            rule: "startup_hook".into(),
            severity,
            detail: format!(
                "{first}{more}: a .pth file runs this at every Python start, not only at \
                 install"
            ),
        });
    }
    hits
}

/// Run the scanner and the models on an archive. Pure CPU work for `spawn_blocking`.
fn scan_and_score(
    scanner: &ScanFn,
    models: &Models,
    bytes: &[u8],
    filename: &str,
    eco: Ecosystem,
    name: &str,
) -> ScanSummary {
    let start = Instant::now();
    let name_opt = (!name.is_empty()).then_some(name);
    match scanner(bytes, filename, eco) {
        Ok(report) => {
            let name_for_model = name_opt.or(report.name.as_deref());
            let a = models.assess(&ScoreInput {
                ecosystem: eco,
                name: name_for_model,
                features: Some(&report.features),
                tokens: report.tokens.as_deref(),
            });
            ScanSummary {
                risk: a.risk,
                scores: a.scores,
                reasons: a.reasons,
                install_scripts: install_scripts_from_report(&report),
                evidence: report.evidence,
                install_surface: report.install_surface,
                scan_errors: report.errors,
                scanned_ms: start.elapsed().as_millis() as u64,
                scanned: true,
                not_scanned_reason: None,
                unread_code: report.unread_code,
                startup_hooks: report.startup_hooks,
            }
        }
        Err(e) => {
            let a = models.assess(&ScoreInput {
                ecosystem: eco,
                name: name_opt,
                features: None,
                tokens: None,
            });
            ScanSummary {
                risk: a.risk,
                scores: a.scores,
                reasons: a.reasons,
                evidence: Vec::new(),
                install_surface: Vec::new(),
                scan_errors: vec![e.to_string()],
                install_scripts: Vec::new(),
                scanned_ms: start.elapsed().as_millis() as u64,
                scanned: false,
                not_scanned_reason: None,
                unread_code: Vec::new(),
                startup_hooks: Vec::new(),
            }
        }
    }
}

/// Pick the artifact `check` scans. PyPI prefers the sdist, whose `setup.py` runs at
/// install time and which contains the full source, then a pure-Python wheel, then any
/// wheel; npm has exactly one tarball per version.
pub fn choose_file(eco: Ecosystem, files: &[FileMeta]) -> Option<&FileMeta> {
    let usable = |f: &&FileMeta| !f.url.is_empty() && !f.yanked;
    match eco {
        Ecosystem::Npm => files.iter().find(usable),
        Ecosystem::Pypi => files
            .iter()
            .filter(usable)
            .find(|f| f.packagetype == "sdist" || f.filename.ends_with(".tar.gz"))
            .or_else(|| {
                files
                    .iter()
                    .filter(usable)
                    .find(|f| f.filename.ends_with("-none-any.whl"))
            })
            .or_else(|| {
                files
                    .iter()
                    .filter(usable)
                    .filter(|f| f.filename.ends_with(".whl"))
                    .min_by_key(|f| f.size.unwrap_or(u64::MAX))
            })
            .or_else(|| files.iter().find(usable)),
    }
}

/// Find a model directory: an explicit path (or its `dev/` subdirectory), then
/// `CUSTOMS_MODELS`, `./models`, and paths relative to the executable. Real models in a
/// directory win over its `dev/` placeholders.
pub fn find_models_dir(explicit: Option<&Path>) -> Option<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    if let Some(p) = explicit {
        roots.push(p.to_path_buf());
    } else {
        if let Ok(p) = std::env::var("CUSTOMS_MODELS") {
            roots.push(PathBuf::from(p));
        }
        roots.push(PathBuf::from("models"));
        if let Ok(exe) = std::env::current_exe() {
            if let Some(dir) = exe.parent() {
                // target/{debug,release}/customs in a checkout, or <prefix>/bin/customs.
                roots.push(dir.join("../../models"));
                roots.push(dir.join("../share/customs/models"));
            }
        }
    }
    for root in roots {
        for dir in [root.clone(), root.join("dev")] {
            if dir.join("manifest.json").is_file() {
                return Some(dir);
            }
        }
    }
    None
}

/// Load models from [`find_models_dir`]; with nothing found, run policy-only.
pub fn load_models(explicit: Option<&Path>) -> anyhow::Result<Models> {
    match find_models_dir(explicit) {
        Some(dir) => {
            let m = Models::load(&dir)
                .map_err(|e| anyhow::anyhow!("loading models from {}: {e}", dir.display()))?;
            if m.manifest.untrained {
                tracing::warn!(dir = %dir.display(), version = m.model_version(), "using UNTRAINED placeholder models");
            } else {
                tracing::info!(dir = %dir.display(), version = m.model_version(), "loaded models");
            }
            Ok(m)
        }
        None => {
            if let Some(p) = explicit {
                anyhow::bail!("no manifest.json in {} or {}/dev", p.display(), p.display());
            }
            tracing::warn!("no models found; verdicts use policy rules only");
            Ok(Models::empty())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(name: &str, kind: &str, size: u64) -> FileMeta {
        FileMeta {
            filename: name.into(),
            url: format!("https://x/{name}"),
            upload_time: None,
            sha256: None,
            packagetype: kind.into(),
            size: Some(size),
            yanked: false,
        }
    }

    #[test]
    fn prefers_sdist_then_pure_wheel() {
        let files = vec![
            f("p-1.0-cp312-cp312-manylinux.whl", "bdist_wheel", 10),
            f("p-1.0-py3-none-any.whl", "bdist_wheel", 20),
            f("p-1.0.tar.gz", "sdist", 30),
        ];
        assert_eq!(
            choose_file(Ecosystem::Pypi, &files).unwrap().filename,
            "p-1.0.tar.gz"
        );
        assert_eq!(
            choose_file(Ecosystem::Pypi, &files[..2]).unwrap().filename,
            "p-1.0-py3-none-any.whl"
        );
        assert_eq!(
            choose_file(Ecosystem::Pypi, &files[..1]).unwrap().filename,
            "p-1.0-cp312-cp312-manylinux.whl"
        );
        assert!(choose_file(Ecosystem::Pypi, &[]).is_none());
    }

    #[test]
    fn unread_code_is_a_policy_hit() {
        let summary = |unread: &[&str]| ScanSummary {
            risk: Some(0.1),
            scores: Scores::default(),
            reasons: vec![],
            evidence: vec![],
            install_surface: vec![],
            scan_errors: vec![],
            install_scripts: vec![],
            scanned_ms: 1,
            scanned: true,
            not_scanned_reason: None,
            unread_code: unread.iter().map(|s| s.to_string()).collect(),
            startup_hooks: vec![],
        };
        let mut policy = Policy::default();
        assert!(scan_hits(&policy, &summary(&[])).is_empty());
        let hits = scan_hits(&policy, &summary(&["setup.py", "a.js", "b.js"]));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule, "unread_code");
        assert_eq!(hits[0].severity, Decision::Block);
        assert!(hits[0]
            .detail
            .starts_with("setup.py and 2 more could not be read"));
        policy.unread_code = RuleSeverity::Warn;
        assert_eq!(
            scan_hits(&policy, &summary(&["setup.py"]))[0].severity,
            Decision::Warn
        );
        policy.unread_code = RuleSeverity::Off;
        assert!(scan_hits(&policy, &summary(&["setup.py"])).is_empty());

        let mut rejected = summary(&[]);
        rejected.scanned = false;
        rejected.scan_errors = vec!["archive rejected: archive has more than 20000 entries".into()];
        let hits = scan_hits(&policy, &rejected);
        assert_eq!(
            (hits[0].rule.as_str(), hits[0].severity),
            ("scan_error", Decision::Block)
        );
        policy.scan_error = RuleSeverity::Warn;
        assert_eq!(scan_hits(&policy, &rejected)[0].severity, Decision::Warn);
        policy.scan_error = RuleSeverity::Off;
        assert!(scan_hits(&policy, &rejected).is_empty());
        // Cached summaries written before the field existed still deserialize.
        let mut old = serde_json::to_value(summary(&[])).unwrap();
        old.as_object_mut().unwrap().remove("unread_code");
        let back: ScanSummary = serde_json::from_value(old).unwrap();
        assert!(back.unread_code.is_empty());
    }

    #[test]
    fn startup_hooks_are_a_policy_hit() {
        let mut s = ScanSummary {
            risk: Some(0.09),
            scores: Scores::default(),
            reasons: vec![],
            evidence: vec![],
            install_surface: vec![],
            scan_errors: vec![],
            install_scripts: vec![],
            scanned_ms: 1,
            scanned: true,
            not_scanned_reason: None,
            unread_code: vec![],
            startup_hooks: vec![],
        };
        let mut policy = Policy::default();
        assert!(scan_hits(&policy, &s).is_empty());
        s.startup_hooks = vec!["litellm_init.pth: proc_exec, network, download_exec".into()];
        let hits = scan_hits(&policy, &s);
        assert_eq!(
            (hits[0].rule.as_str(), hits[0].severity),
            ("startup_hook", Decision::Block)
        );
        assert!(hits[0].detail.starts_with("litellm_init.pth: proc_exec"));
        policy.startup_hook = RuleSeverity::Warn;
        assert_eq!(scan_hits(&policy, &s)[0].severity, Decision::Warn);
        policy.startup_hook = RuleSeverity::Off;
        assert!(scan_hits(&policy, &s).is_empty());
        let mut old = serde_json::to_value(&s).unwrap();
        old.as_object_mut().unwrap().remove("startup_hooks");
        let back: ScanSummary = serde_json::from_value(old).unwrap();
        assert!(back.startup_hooks.is_empty());
    }

    #[test]
    fn install_scripts_from_surface() {
        let r = ScanReport {
            schema_version: 1,
            ecosystem: Ecosystem::Npm,
            archive: "x.tgz".into(),
            sha256: String::new(),
            name: None,
            version: None,
            features: Default::default(),
            evidence: vec![],
            install_surface: vec!["package.json:scripts.postinstall".into(), "index.js".into()],
            tokens: None,
            errors: vec![],
            unread_code: vec![],
            startup_hooks: vec![],
        };
        assert_eq!(install_scripts_from_report(&r), vec!["postinstall"]);
    }
}
