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
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use customs_model::{decide, Decision, Models, Reason, ScoreInput, Scores};
use customs_scan::{scan_archive, Ecosystem, Evidence, ScanError, ScanOptions, ScanReport};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, OnceCell};

use crate::config::{Policy, RuleSeverity};
use crate::diff::{ReleaseDiff, ReleaseSide};
use crate::history::{release_history, DependencyInfo, ReleaseHistory, MAX_ADDED_LOOKUPS};
use crate::metrics::Metrics;
use crate::policy::{effective_thresholds, evaluate, PolicyContext};
use crate::policy_log::PolicyChange;
use crate::registry::{FetchError, FileMeta, Registry, VersionMeta};
use crate::resolve::{exact_version, pinned_version, resolve_version};
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
    /// Artifacts larger than this are served unscanned, judged on metadata and policy rules.
    pub max_scan_bytes: u64,
    /// `POST /api/check` does not download a wheel the registry says is larger than this;
    /// sdists and npm tarballs are always read, up to `max_download_bytes`.
    pub max_check_bytes: u64,
    /// The artifact cache is trimmed (least recently used first) when it grows past this.
    pub max_cache_bytes: u64,
    /// An archive download that takes longer than this in all is abandoned (502), so an
    /// upstream that drips bytes cannot hold the download and everyone waiting on it.
    pub download_timeout: Duration,
    /// Archives scanned at the same time; more wait for a slot. Each scan holds its archive
    /// in memory, so this bounds memory under a burst of distinct packages.
    pub max_concurrent_scans: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_download_bytes: 2 << 30,
            max_scan_bytes: 256 << 20,
            max_check_bytes: 64 << 20,
            max_cache_bytes: 10 << 30,
            download_timeout: Duration::from_secs(600),
            max_concurrent_scans: std::thread::available_parallelism().map_or(4, |n| n.get()),
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
    /// The registry marks the version (or the requested file) yanked, or npm deprecated.
    pub yanked: bool,
    /// Metadata read fresh does not list the version or file, or could not be read, so its
    /// age is unknown.
    pub age_unknown: bool,
    /// Hits about how the version or the archive was chosen.
    pub notes: Vec<PolicyHit>,
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

/// Version of [`ScanSummary`]. Bump when its contents or the scoring for the same archive
/// change, so summaries cached by an earlier build are not served (see [`Engine::scan_identity`]).
const SCAN_SUMMARY_VERSION: u32 = 2;

/// What the scan cache stores: everything in a verdict that depends only on the bytes,
/// the name, the model version, and the scanner.
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
    /// AI coding CLI flags that turn off permission checks, in install-time code.
    #[serde(default)]
    agent_bypass: Vec<String>,
    /// Install-time code the interpreter runs but the scanner's feature pass did not
    /// see (code after a bare carriage return, inside f-string fields, ...).
    #[serde(default)]
    hidden_code: Vec<String>,
}

type Flight = Arc<OnceCell<Result<Outcome, EngineError>>>;
/// A flight with the event kind and client of the caller that started it.
type Leader = (Flight, EventKind, Option<String>);

/// A policy change that is live (see [`Engine::change_policy`]).
#[derive(Debug, Clone)]
pub struct AppliedChange {
    /// `id` is 0 when the change log could not record it.
    pub change: PolicyChange,
    /// Why the change log could not record it.
    pub log_error: Option<String>,
}

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
    policy_changes: broadcast::Sender<PolicyChange>,
    /// Serializes policy changes, so each diff is taken against the policy it replaces.
    policy_write: Mutex<()>,
    /// In-progress evaluations by artifact URL, with the event kind and client that started
    /// each one.
    inflight: Mutex<HashMap<String, Leader>>,
    tmp_counter: AtomicU64,
    /// Bytes downloaded since the cache size was last checked.
    cache_growth: AtomicU64,
    /// One permit per scan that may run now ([`Limits::max_concurrent_scans`]).
    scan_slots: tokio::sync::Semaphore,
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

/// Refuse a name no registry could hold before it becomes part of an upstream URL.
fn check_name(eco: Ecosystem, name: &str) -> Result<(), EngineError> {
    if crate::config::valid_package_name(eco, name) {
        return Ok(());
    }
    Err(EngineError::Unresolvable(format!(
        "'{name}' is not a valid {} package name",
        crate::util::registry_name(eco)
    )))
}

/// Partial downloads older than this were left by a crash. Age-gated rather than removed
/// outright because a server and in-process engines may share a data directory.
const STALE_PART_AGE: Duration = Duration::from_secs(3600);

/// Remove `.part` files in `tmp` last written more than `older_than` ago; returns how many.
fn remove_stale_parts(tmp: &Path, older_than: Duration) -> usize {
    let Ok(entries) = std::fs::read_dir(tmp) else {
        return 0;
    };
    let mut n = 0;
    for e in entries.flatten() {
        let stale = e.file_name().to_string_lossy().ends_with(".part")
            && e.metadata()
                .and_then(|m| m.modified())
                .is_ok_and(|t| t.elapsed().is_ok_and(|age| age > older_than));
        if stale && std::fs::remove_file(e.path()).is_ok() {
            n += 1;
        }
    }
    n
}

impl Engine {
    pub fn new(cfg: EngineConfig) -> anyhow::Result<Arc<Self>> {
        let cache_dir = cfg.data_dir.join("cache");
        std::fs::create_dir_all(cache_dir.join("tmp")).map_err(|e| {
            anyhow::anyhow!(
                "cannot use the data directory {}: {e}; pass --data-dir a writable directory",
                cfg.data_dir.display()
            )
        })?;
        let n = remove_stale_parts(&cache_dir.join("tmp"), STALE_PART_AGE);
        if n > 0 {
            tracing::info!(
                files = n,
                "removed partial downloads left by an earlier run"
            );
        }
        let store = Store::open(&cfg.data_dir.join("customs.db"))?;
        // Summaries from an earlier scanner or summary version are never read again.
        match store.scan_cache_prune(&scan_suffix(&cfg.limits)) {
            Ok(0) => {}
            Ok(n) => tracing::info!(rows = n, "dropped scan results of an earlier scanner"),
            Err(e) => tracing::warn!(error = %e, "pruning the scan cache failed"),
        }
        let (events, _) = broadcast::channel(1024);
        let (policy_changes, _) = broadcast::channel(64);
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
            policy_changes,
            policy_write: Mutex::new(()),
            inflight: Mutex::new(HashMap::new()),
            tmp_counter: AtomicU64::new(0),
            // Starting above the trigger makes the first download check the size.
            cache_growth: AtomicU64::new(u64::MAX / 2),
            scan_slots: tokio::sync::Semaphore::new(cfg.limits.max_concurrent_scans.max(1)),
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
        let text = p.to_toml()?;
        if let Some(dir) = self.policy_path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let tmp = self.policy_path.with_extension("toml.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &self.policy_path)?;
        *self.policy.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(p);
        Ok(())
    }

    /// Persist and activate a policy that came in through the API, and record what changed
    /// (`None` when nothing did). `change` carries who made it; its `changes` are filled in.
    /// An error means nothing changed. Once the policy is live it is counted and announced
    /// even if the change log cannot record it; [`AppliedChange::log_error`] says why.
    pub fn change_policy(
        &self,
        p: Policy,
        mut change: PolicyChange,
    ) -> anyhow::Result<Option<AppliedChange>> {
        let _guard = self.policy_write.lock().unwrap_or_else(|e| e.into_inner());
        change.changes = crate::policy_log::diff(&self.policy(), &p);
        self.set_policy(p)?;
        if change.changes.is_empty() {
            return Ok(None);
        }
        let (change, log_error) = match self.store.insert_policy_change(change.clone()) {
            Ok(c) => (c, None),
            Err(e) => {
                tracing::error!(error = %e, "policy applied but not recorded in the change log");
                change.ts = crate::util::now_ts();
                (change, Some(e.to_string()))
            }
        };
        self.metrics.policy_change("applied");
        let _ = self.policy_changes.send(change.clone());
        Ok(Some(AppliedChange { change, log_error }))
    }

    pub fn subscribe_policy_changes(&self) -> broadcast::Receiver<PolicyChange> {
        self.policy_changes.subscribe()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    fn blob_path(&self, sha256: &str) -> PathBuf {
        self.cache_dir.join(&sha256[..2]).join(sha256)
    }

    /// What a cached scan summary depends on besides the archive: the models, the scanner
    /// rules and feature schema, the summary layout, and the scan size limit. Stored in the
    /// scan cache's `model_version` column, so a new identity needs no schema change.
    fn scan_identity(&self) -> String {
        format!(
            "{}{}",
            self.models.model_version(),
            scan_suffix(&self.limits)
        )
    }

    /// Evaluate one artifact; concurrent calls for the same URL share a single evaluation.
    pub async fn evaluate_artifact(
        self: &Arc<Self>,
        req: ArtifactRequest,
    ) -> Result<Outcome, EngineError> {
        let key = req.url.clone();
        let me = (req.kind, req.client.clone());
        // `Some` when this call joined a flight another kind of request or client started.
        let (cell, joined_other) = {
            let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            match map.get(&key) {
                Some((c, kind, client)) => {
                    self.metrics.singleflight_join();
                    let other = (*kind, client.clone()) != me;
                    (c.clone(), other.then_some(me))
                }
                None => {
                    let c: Flight = Arc::new(OnceCell::new());
                    map.insert(key.clone(), (c.clone(), me.0, me.1.clone()));
                    (c, None)
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
        {
            let mut map = self.inflight.lock().unwrap_or_else(|e| e.into_inner());
            if map.get(&key).is_some_and(|(c, ..)| Arc::ptr_eq(c, &cell)) {
                map.remove(&key);
            }
        }
        // The evaluation recorded one event, for the request that started it. A proxy
        // install that joined a check (or a check that joined an install) is its own event.
        if let (Ok(o), Some((kind, client))) = (&result, joined_other) {
            self.record_event(&o.verdict, kind, client)?;
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

    /// Registry facts for an artifact requested through the proxy. Metadata that cannot be
    /// read, or does not list the file, leaves its age unknown (see
    /// [`MetaFacts::age_unknown`]), which the release-age rule does not give the benefit of
    /// the doubt.
    async fn artifact_meta(&self, policy: &Policy, req: &ArtifactRequest) -> MetaFacts {
        let mut facts = MetaFacts {
            exists: true,
            ..Default::default()
        };
        let Some(version) = &req.version else {
            // A file name that names no version of the package cannot be dated.
            facts.age_unknown = true;
            return facts;
        };
        // npm needs the packument anyway. For PyPI the per-release document is enough unless
        // a release history rule that applies to PyPI is on; then the project document (also
        // cached for `check`) is read, falling back to the release document when it does not
        // list the file. A cached document that lacks the version is fetched again: it may
        // predate the release.
        let full = match req.ecosystem {
            Ecosystem::Npm => true,
            Ecosystem::Pypi => policy.pypi_history_rules_enabled(),
        };
        let lists_file = |vm: &VersionMeta| vm.files.iter().any(|f| f.filename == req.filename);
        let mut result: Result<Option<VersionMeta>, FetchError> = Ok(None);
        if full {
            result = self
                .registry
                .package_meta_listing(&policy.upstream, req.ecosystem, &req.name, &[version])
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
        if req.ecosystem == Ecosystem::Pypi && !matches!(&result, Ok(Some(vm)) if lists_file(vm)) {
            // The release document is never cached, so it lists a file uploaded since.
            match self
                .registry
                .pypi_release(&policy.upstream, &req.name, version)
                .await
            {
                Ok(None) | Err(_) if matches!(result, Ok(Some(_))) => {}
                other => result = other,
            }
        }
        match result {
            Ok(Some(vm)) => {
                facts.install_scripts = vm.install_scripts.clone();
                match vm.files.iter().find(|f| f.filename == req.filename) {
                    // The upload time of this exact file, not the release's: a file added to
                    // an old release is as new as its upload.
                    Some(file) => {
                        facts.published = file.upload_time.or(vm.published);
                        facts.yanked = vm.yanked || file.yanked;
                    }
                    None => {
                        tracing::debug!(name = %req.name, version, file = %req.filename, "registry metadata does not list the file");
                        facts.yanked = vm.yanked;
                        facts.age_unknown = true;
                    }
                }
            }
            Ok(None) => {
                tracing::debug!(name = %req.name, version, "no registry metadata for version");
                facts.age_unknown = true;
            }
            // Unreadable metadata (a timeout, garbage, a 5xx) dates nothing either: treating
            // it as "no rule applies" would let a version published a minute ago through.
            Err(e) => {
                tracing::warn!(name = %req.name, version, error = %e, "registry metadata lookup failed");
                facts.age_unknown = true;
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
            // A blob cut short (a crash mid-write, a full disk) is a miss, not a hit.
            if std::fs::metadata(&p).is_ok_and(|m| m.len() == row.size) {
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
            .download(
                url,
                &tmp,
                self.limits.max_download_bytes,
                self.limits.download_timeout,
            )
            .await
        {
            Ok(d) => d,
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                return Err(e.into());
            }
        };
        let dest = self.blob_path(&dl.sha256);
        let moved = async {
            if let Some(dir) = dest.parent() {
                tokio::fs::create_dir_all(dir).await?;
            }
            tokio::fs::rename(&tmp, &dest).await
        }
        .await;
        if let Err(e) = moved {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(internal(e));
        }
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
            // The file name too: the scanner reads the same bytes as a wheel and as an
            // sdist differently. It leads, so the identity stays a suffix for pruning.
            model_version: format!("{filename}|{}", self.scan_identity()),
        };
        if let Some(json) = self.store.scan_cache_get(&key).map_err(internal)? {
            if let Ok(s) = serde_json::from_str::<ScanSummary>(&json) {
                self.metrics.cache("scan_hit");
                return Ok((s, true));
            }
        }
        self.metrics.cache("scan_miss");
        // Held until the summary is built: the archive is in memory for the whole scan.
        let _slot = self.scan_slots.acquire().await.map_err(internal)?;
        let started = Instant::now();
        let summary = if size > self.limits.max_scan_bytes {
            let limit = self.limits.max_scan_bytes >> 20;
            let mut s = self.name_only_summary(
                eco,
                name,
                Some(format!(
                    "archive is {} MB, above the {limit} MB scan limit; not scored by the models (archive not scanned), judged on metadata and policy rules only",
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
            agent_bypass: Vec::new(),
            hidden_code: Vec::new(),
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
                popular_rank: self.models.popular_rank(eco, name),
                yanked: meta.yanked,
                age_unknown: meta.age_unknown,
                now: now(),
            },
        );
        let mut hits = outcome.hits.clone();
        hits.extend(scan_hits(policy, s));
        hits.extend(meta.notes.iter().cloned());
        let decision = outcome.decide_with(model_decision, &hits);
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
        let new_event = NewEvent {
            ecosystem: v.ecosystem,
            name: v.name.clone(),
            version: v.version.clone(),
            client,
            kind,
            decision: Some(v.decision),
            risk: v.risk,
            verdict_id: None,
        };
        let (id, event) = self
            .store
            .insert_verdict_with_event(&v, new_event)
            .map_err(internal)?;
        v.id = Some(id);
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

    /// Record another request answered by the already stored verdict `v`.
    fn record_event(
        &self,
        v: &Verdict,
        kind: EventKind,
        client: Option<String>,
    ) -> Result<(), EngineError> {
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
                verdict_id: v.id,
            })
            .map_err(internal)?;
        self.metrics.event(kind.as_str());
        let _ = self.events.send(event);
        Ok(())
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

    /// Package metadata that lists `pins` when the registry does.
    async fn package_meta_with(
        &self,
        policy: &Policy,
        eco: Ecosystem,
        name: &str,
        pins: &[String],
    ) -> Result<Option<Arc<crate::registry::PackageMeta>>, FetchError> {
        let need: Vec<&str> = pins.iter().map(String::as_str).collect();
        self.registry
            .package_meta_listing(&policy.upstream, eco, name, &need)
            .await
    }

    /// `POST /api/check`: resolve, fetch, scan, decide. An unpinned spec resolves against
    /// the metadata the proxy serves.
    pub async fn check(
        self: &Arc<Self>,
        eco: Ecosystem,
        name: &str,
        version: Option<&str>,
        client: Option<String>,
    ) -> Result<Verdict, EngineError> {
        self.check_resolving(eco, name, version, client, true).await
    }

    /// [`Engine::check`]. With `as_served` false an unpinned spec resolves against the
    /// registry's own metadata, as an installer that does not use the proxy would.
    pub async fn check_resolving(
        self: &Arc<Self>,
        eco: Ecosystem,
        name: &str,
        version: Option<&str>,
        client: Option<String>,
        as_served: bool,
    ) -> Result<Verdict, EngineError> {
        check_name(eco, name)?;
        let policy = self.policy();
        let name = normalize_name(eco, name);
        // A pinned version the cached metadata lacks may have been published since.
        let pins: Vec<String> = version
            .and_then(|v| pinned_version(eco, v))
            .into_iter()
            .collect();
        let Some(meta) = self.package_meta_with(&policy, eco, &name, &pins).await? else {
            return self.record_nonexistent(eco, &name, client);
        };
        // Resolve an unpinned spec against the metadata the proxy serves, which leaves out
        // versions `min_age_days` would block; a version named exactly is checked as named.
        let hidden = if as_served {
            crate::cooldown::hidden_versions(&policy, &meta, now())
        } else {
            Default::default()
        };
        let mut note = None;
        let version = match exact_version(&meta, version) {
            Some(v) => Ok(v),
            None if hidden.is_empty() => resolve_version(&meta, version),
            None => {
                let served = resolve_version(&crate::cooldown::filter_meta(&meta, &hidden), version);
                if let (Ok(s), Ok(newest)) = (&served, resolve_version(&meta, version)) {
                    if *s != newest {
                        note = Some(PolicyHit {
                            rule: "min_age_resolution".into(),
                            severity: Decision::Allow,
                            detail: format!(
                                "resolved to {s}: {newest} is newer but younger than {} day{}, so the proxy does not offer it",
                                policy.min_age_days,
                                if policy.min_age_days == 1 { "" } else { "s" }
                            ),
                        });
                    }
                }
                served
            }
        }
        .map_err(EngineError::Unresolvable)?;
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
            yanked: vm.yanked,
            age_unknown: false,
            notes: note.into_iter().collect(),
        };
        let files = check_files(eco, &vm.files);
        if files.is_empty() {
            return Err(EngineError::NotFound(format!(
                "{name} {version} has no downloadable files"
            )));
        }
        // pip installs a compatible wheel when there is one, so the pure-Python wheel is
        // read as well as the sdist; both verdicts are recorded and the stricter returned.
        let checks = files.iter().map(|file| {
            let mut facts = facts.clone();
            if let Some(other) = files.iter().find(|f| f.filename != file.filename) {
                facts.notes.push(PolicyHit {
                    rule: "also_checked".into(),
                    severity: Decision::Allow,
                    detail: format!(
                        "{} was checked as well (an installer may pick either); the stricter verdict is returned",
                        other.filename
                    ),
                });
            }
            self.check_file(&policy, eco, &name, &version, file, facts, client.clone())
        });
        let verdicts = futures::future::join_all(checks).await;
        let mut best: Option<Verdict> = None;
        for v in verdicts {
            let v = v?;
            if best.as_ref().is_none_or(|b| v.decision > b.decision) {
                best = Some(v);
            }
        }
        best.ok_or_else(|| internal("no archive was checked"))
    }

    /// Check one archive of a release: its own upload time and yank status, read like the
    /// proxy reads it unless it is a wheel above the check limit.
    #[allow(clippy::too_many_arguments)]
    async fn check_file(
        self: &Arc<Self>,
        policy: &Policy,
        eco: Ecosystem,
        name: &str,
        version: &str,
        file: &FileMeta,
        mut facts: MetaFacts,
        client: Option<String>,
    ) -> Result<Verdict, EngineError> {
        // The archive's own upload time: an sdist added years after the wheels is new.
        facts.published = file.upload_time.or(facts.published);
        facts.yanked = facts.yanked || file.yanked;
        // Only a wheel may skip the download: it runs nothing at install but a top-level
        // `.pth` file. Anything else is read like the proxy reads it (up to the download
        // limit), since its install-time code must not go unread. PyPI reports a file's own
        // size; npm reports none (its `unpackedSize` is whatever the publisher wrote).
        if file.filename.ends_with(".whl")
            && file.size.is_some_and(|s| s > self.limits.max_check_bytes)
        {
            let s = self.name_only_summary(eco, name, None);
            facts.notes.push(PolicyHit {
                rule: "not_scanned".into(),
                severity: Decision::Warn,
                detail: format!(
                    "{} is {} MB, above the {} MB check limit, so it was not downloaded or read; not scored by the models, judged on metadata and policy rules only",
                    file.filename,
                    file.size.unwrap_or(0) >> 20,
                    self.limits.max_check_bytes >> 20
                ),
            });
            let v = self.build_verdict(
                policy,
                eco,
                name,
                Some(version.to_string()),
                Some(file.filename.clone()),
                file.sha256.clone(),
                &s,
                false,
                &facts,
            );
            return self.record(v, EventKind::Check, client);
        }
        on_upstream(policy, eco, file)?;
        let out = self
            .evaluate_artifact(ArtifactRequest {
                ecosystem: eco,
                name: name.to_string(),
                version: Some(version.to_string()),
                filename: file.filename.clone(),
                url: file.url.clone(),
                client,
                kind: EventKind::Check,
                meta: Some(facts),
            })
            .await?;
        Ok(out.verdict)
    }

    /// What release `to` (default: the newest) changes relative to `from` (default: the
    /// release published before it): registry metadata, dependencies, files, and the
    /// scanner findings and install-time code `from` does not have. Both archives are
    /// downloaded into the cache and scanned (the scans are cached as for any check), and
    /// `to` is checked, so its verdict is recorded as well.
    pub async fn diff_releases(
        self: &Arc<Self>,
        eco: Ecosystem,
        name: &str,
        from: Option<&str>,
        to: Option<&str>,
        client: Option<String>,
    ) -> Result<ReleaseDiff, EngineError> {
        check_name(eco, name)?;
        let policy = self.policy();
        let name = normalize_name(eco, name);
        let pins: Vec<String> = [from, to]
            .into_iter()
            .flatten()
            .filter_map(|v| pinned_version(eco, v))
            .collect();
        let Some(meta) = self.package_meta_with(&policy, eco, &name, &pins).await? else {
            return Err(EngineError::NotFound(format!(
                "'{name}' does not exist on {}",
                crate::util::registry_name(eco)
            )));
        };
        let to_v = match exact_version(&meta, to) {
            Some(v) => v,
            None => resolve_version(&meta, to).map_err(EngineError::Unresolvable)?,
        };
        let from_v = match from {
            Some(f) => exact_version(&meta, Some(f))
                .ok_or_else(|| EngineError::Unresolvable(format!("{name} has no version {f}")))?,
            None => release_history(&meta, &to_v)
                .and_then(|h| h.previous)
                .map(|p| p.version)
                .ok_or_else(|| {
                    EngineError::Unresolvable(format!(
                        "{name} {to_v} has no earlier release to compare with; pass --from"
                    ))
                })?,
        };
        if from_v == to_v {
            return Err(EngineError::Unresolvable(format!(
                "both sides are {name} {to_v}; name two different versions"
            )));
        }
        let missing = |v: &str| EngineError::Unresolvable(format!("{name} has no version {v}"));
        let vm_to = meta.version(&to_v).cloned().ok_or_else(|| missing(&to_v))?;
        let vm_from = meta
            .version(&from_v)
            .cloned()
            .ok_or_else(|| missing(&from_v))?;

        let verdict = self
            .check_resolving(eco, &name, Some(&to_v), client, false)
            .await?;

        let file_to = choose_file(eco, &vm_to.files).cloned();
        // Compare like with like: the same kind of archive (sdist, or the wheel with the
        // same tags) when the earlier release has one.
        let file_from = file_to.as_ref().and_then(|t| {
            let same_name = t.filename.replace(&to_v, &from_v);
            let usable = |f: &&FileMeta| !f.url.is_empty();
            vm_from
                .files
                .iter()
                .filter(usable)
                .find(|f| f.filename == same_name)
                .or_else(|| {
                    vm_from
                        .files
                        .iter()
                        .filter(usable)
                        .find(|f| f.packagetype == t.packagetype)
                })
                .or_else(|| choose_file(eco, &vm_from.files))
                .cloned()
        });
        let mut d = ReleaseDiff {
            ecosystem: eco,
            name: name.clone(),
            from: ReleaseSide {
                version: from_v.clone(),
                published: vm_from.published,
                filename: file_from.as_ref().map(|f| f.filename.clone()),
            },
            to: ReleaseSide {
                version: to_v.clone(),
                published: vm_to.published,
                filename: file_to.as_ref().map(|f| f.filename.clone()),
            },
            metadata: crate::diff::metadata_changes(&vm_from, &vm_to),
            dependencies: crate::diff::dependency_changes(&vm_from, &vm_to),
            files: None,
            files_note: None,
            new_evidence: Vec::new(),
            new_install_surface: Vec::new(),
            verdict: Some(verdict),
        };
        let (Some(file_from), Some(file_to)) = (file_from, file_to) else {
            d.files_note = Some("a release has no downloadable files".into());
            return Ok(d);
        };
        let limit = self.limits.max_check_bytes;
        if let Some(big) = [&file_from, &file_to]
            .into_iter()
            .find(|f| f.filename.ends_with(".whl") && f.size.is_some_and(|s| s > limit))
        {
            d.files_note = Some(format!(
                "{} is above the {} MB check limit",
                big.filename,
                limit >> 20
            ));
            return Ok(d);
        }
        on_upstream(&policy, eco, &file_from)?;
        on_upstream(&policy, eco, &file_to)?;
        let (a, b) = tokio::join!(
            self.fetch_artifact(&file_from.url, &file_from.filename),
            self.fetch_artifact(&file_to.url, &file_to.filename)
        );
        let ((path_a, sha_a, size_a), (path_b, sha_b, size_b)) = (a?, b?);
        let (scan_a, _) = self
            .scan_cached(
                eco,
                &name,
                Some(&from_v),
                &sha_a,
                &path_a,
                &file_from.filename,
                size_a,
            )
            .await?;
        let (scan_b, _) = self
            .scan_cached(
                eco,
                &name,
                Some(&to_v),
                &sha_b,
                &path_b,
                &file_to.filename,
                size_b,
            )
            .await?;
        d.new_evidence = crate::diff::new_evidence(&scan_a.evidence, &scan_b.evidence);
        d.new_install_surface =
            crate::diff::new_entries(&scan_a.install_surface, &scan_b.install_surface);
        if size_a.max(size_b) > self.limits.max_scan_bytes {
            d.files_note = Some(format!(
                "an archive is above the {} MB scan limit",
                self.limits.max_scan_bytes >> 20
            ));
            return Ok(d);
        }
        let _slot = self.scan_slots.acquire().await.map_err(internal)?;
        let (ra, rb) = tokio::join!(tokio::fs::read(&path_a), tokio::fs::read(&path_b));
        let (bytes_a, bytes_b) = (ra.map_err(internal)?, rb.map_err(internal)?);
        let files = tokio::task::spawn_blocking(move || {
            customs_scan::diff_archives(&bytes_a, &bytes_b, &ScanOptions::default())
        })
        .await
        .map_err(internal)?;
        match files {
            Ok(f) => d.files = Some(f),
            Err(e) => d.files_note = Some(format!("the archives could not be read: {e}")),
        }
        Ok(d)
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
    let given = name.is_some();
    let name = name
        .map(str::to_string)
        .or(guessed.as_ref().map(|g| g.0.clone()))
        .unwrap_or_else(|| filename.to_string());
    let version = guessed.map(|g| g.1).or_else(|| {
        if given {
            parse_npm_tarball(&name, filename)
        } else {
            crate::util::guess_npm_tarball_version(filename)
        }
    });
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

/// Refuse a file whose URL (from registry metadata) is not on a host the proxy fetches
/// archives from: the files and index hosts for PyPI, the registry for npm. A check must
/// not make the server fetch from wherever a metadata document points.
fn on_upstream(policy: &Policy, eco: Ecosystem, file: &FileMeta) -> Result<(), EngineError> {
    let origin = |s: &str| {
        url::Url::parse(s).ok().map(|u| {
            (
                u.scheme().to_string(),
                u.host_str().map(str::to_ascii_lowercase),
                u.port_or_known_default(),
            )
        })
    };
    let up = &policy.upstream;
    let hosts: &[&str] = match eco {
        Ecosystem::Pypi => &[&up.pypi_files, &up.pypi_simple],
        Ecosystem::Npm => &[&up.npm],
    };
    let o = origin(&file.url);
    if o.is_some() && hosts.iter().any(|h| origin(h) == o) {
        return Ok(());
    }
    Err(EngineError::Upstream(format!(
        "{} is hosted at {}, not on a configured upstream; Customs does not fetch it",
        file.filename,
        url::Url::parse(&file.url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_else(|| "an unparsable URL".into())
    )))
}

/// The scanner part of [`Engine::scan_identity`].
fn scan_suffix(limits: &Limits) -> String {
    format!(
        "|scan:{}.{}|summary:{SCAN_SUMMARY_VERSION}|max:{}",
        customs_scan::SCAN_RULES_VERSION,
        customs_scan::FEATURE_SCHEMA_VERSION,
        limits.max_scan_bytes
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
                "{first}{more} could not be read by the scanner (too large, encrypted, \
                 compressed with an unsupported method, or extracted differently by the \
                 installer), so its code was never inspected; installing would run it"
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
                "{first}{more}: Python runs this file at every interpreter start, not only \
                 at install"
            ),
        });
    }
    if let (Some(severity), Some(first)) = (policy.agent_bypass.decision(), s.agent_bypass.first())
    {
        let more = match s.agent_bypass.len() {
            1 => String::new(),
            n => format!(" (and {} more)", n - 1),
        };
        hits.push(PolicyHit {
            rule: "agent_bypass".into(),
            severity,
            detail: format!(
                "{first}{more}: install-time code runs an AI coding agent with its permission \
                 checks off"
            ),
        });
    }
    if let (Some(severity), Some(first)) = (policy.hidden_code.decision(), s.hidden_code.first()) {
        let more = match s.hidden_code.len() {
            1 => String::new(),
            n => format!(" (and {} more)", n - 1),
        };
        hits.push(PolicyHit {
            rule: "hidden_code".into(),
            severity,
            detail: format!(
                "{first}{more}: install-time code the interpreter runs but the scanner's \
                 model inputs leave out"
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
                agent_bypass: report.agent_bypass,
                hidden_code: report.hidden_code,
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
                agent_bypass: Vec::new(),
                hidden_code: Vec::new(),
            }
        }
    }
}

/// The archives `check` reads: [`choose_file`]'s pick and, when that is an sdist, the
/// pure-Python wheel of the same release, which pip installs in its place. A
/// platform-specific wheel is not read (the server does not know the client's platform).
pub fn check_files(eco: Ecosystem, files: &[FileMeta]) -> Vec<&FileMeta> {
    let Some(first) = choose_file(eco, files) else {
        return Vec::new();
    };
    let mut out = vec![first];
    if eco == Ecosystem::Pypi && !first.filename.ends_with(".whl") {
        if let Some(w) = files
            .iter()
            .find(|f| !f.url.is_empty() && !f.yanked && f.filename.ends_with("-none-any.whl"))
        {
            out.push(w);
        }
    }
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_suffix_misses_summaries_from_older_scanners() {
        // Summaries keyed scan:1.1|summary:1 lack the hidden_code scanner output and the
        // name-only risk change, and those keyed scan:2.1 flag `x.js/x.js` npm files as
        // unread. Neither may be served.
        let s = scan_suffix(&Limits::default());
        assert_eq!(s, format!("|scan:4.1|summary:2|max:{}", 256u64 << 20));
    }

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
            agent_bypass: vec![],
            hidden_code: vec![],
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
            agent_bypass: vec![],
            hidden_code: vec![],
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
    fn agent_bypass_is_a_policy_hit() {
        let mut s = ScanSummary {
            risk: Some(0.2),
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
            agent_bypass: vec![],
            hidden_code: vec![],
        };
        let mut policy = Policy::default();
        assert!(scan_hits(&policy, &s).is_empty());
        s.agent_bypass = vec![
            "telemetry.js:4: --dangerously-skip-permissions".into(),
            "telemetry.js:5: --yolo".into(),
        ];
        let hits = scan_hits(&policy, &s);
        assert_eq!(
            (hits[0].rule.as_str(), hits[0].severity),
            ("agent_bypass", Decision::Block)
        );
        assert_eq!(
            hits[0].detail,
            "telemetry.js:4: --dangerously-skip-permissions (and 1 more): install-time code \
             runs an AI coding agent with its permission checks off"
        );
        policy.agent_bypass = RuleSeverity::Warn;
        assert_eq!(scan_hits(&policy, &s)[0].severity, Decision::Warn);
        policy.agent_bypass = RuleSeverity::Off;
        assert!(scan_hits(&policy, &s).is_empty());
        // Verdicts cached before the field existed still load.
        let mut old = serde_json::to_value(&s).unwrap();
        old.as_object_mut().unwrap().remove("agent_bypass");
        let back: ScanSummary = serde_json::from_value(old).unwrap();
        assert!(back.agent_bypass.is_empty());
    }

    #[test]
    fn hidden_code_is_a_policy_hit() {
        let mut s: ScanSummary = serde_json::from_value(serde_json::json!({
            "risk": 0.1, "scores": Scores::default(), "reasons": [], "evidence": [],
            "install_surface": [], "scan_errors": [], "install_scripts": [],
            "scanned_ms": 1, "scanned": true,
        }))
        .unwrap();
        let mut policy = Policy::default();
        assert!(scan_hits(&policy, &s).is_empty());
        s.hidden_code = vec![
            "setup.py:3: proc_exec, ip_url (code after a bare carriage return)".into(),
            "helper.py:4: proc_exec (imported by setup.py after a byte-order mark)".into(),
        ];
        let hits = scan_hits(&policy, &s);
        assert_eq!(
            (hits[0].rule.as_str(), hits[0].severity),
            ("hidden_code", Decision::Block)
        );
        assert_eq!(
            hits[0].detail,
            "setup.py:3: proc_exec, ip_url (code after a bare carriage return) (and 1 more): \
             install-time code the interpreter runs but the scanner's model inputs leave out"
        );
        policy.hidden_code = RuleSeverity::Warn;
        assert_eq!(scan_hits(&policy, &s)[0].severity, Decision::Warn);
        policy.hidden_code = RuleSeverity::Off;
        assert!(scan_hits(&policy, &s).is_empty());
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
            agent_bypass: vec![],
            hidden_code: vec![],
        };
        assert_eq!(install_scripts_from_report(&r), vec!["postinstall"]);
    }

    #[test]
    fn stale_partial_downloads_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("1-1-0.part");
        let new = dir.path().join("2-2-0.part");
        std::fs::write(&old, b"x").unwrap();
        std::fs::write(&new, b"x").unwrap();
        std::fs::File::options()
            .append(true)
            .open(&old)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(7200))
            .unwrap();
        assert_eq!(remove_stale_parts(dir.path(), Duration::from_secs(3600)), 1);
        assert!(!old.exists());
        assert!(new.exists());
    }
}
