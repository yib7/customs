//! Upstream registry client: page fetches for the proxy, package metadata for policy and
//! version resolution, and artifact downloads into the cache.
//!
//! The HTTP client honors `HTTPS_PROXY`/`NO_PROXY` (reqwest's default) and trusts the
//! platform roots plus any bundle named by `CUSTOMS_CA_FILE` or `SSL_CERT_FILE`, which is
//! how TLS-intercepting corporate proxies are usually configured.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use customs_scan::Ecosystem;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use crate::config::Upstream;
use crate::metrics::Metrics;
use crate::util::{ecosystem_str, normalize_name};

const META_TTL: Duration = Duration::from_secs(300);
/// A cached document that was itself refetched for a missing version is served for this
/// long before another miss refetches it, so requests for a version that does not exist
/// cannot turn every lookup into an upstream request.
const META_REFRESH_GAP: Duration = Duration::from_secs(5);
/// Past this many cached documents, an insert first drops the expired ones.
const META_SOFT_CAP: usize = 512;
/// The cache never holds more documents than this; the oldest go first.
const META_HARD_CAP: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("not found upstream")]
    NotFound,
    #[error("upstream returned HTTP {0}")]
    Status(u16),
    #[error("artifact is larger than the {0} byte limit")]
    TooLarge(u64),
    #[error("upstream request failed: {0}")]
    Transport(String),
    #[error("{0}")]
    Other(String),
}

impl From<reqwest::Error> for FetchError {
    fn from(e: reqwest::Error) -> Self {
        // Include the source chain: reqwest's top-level message hides TLS and proxy causes.
        let mut msg = e.to_string();
        let mut src = std::error::Error::source(&e);
        while let Some(s) = src {
            msg.push_str(": ");
            msg.push_str(&s.to_string());
            src = s.source();
        }
        FetchError::Transport(msg)
    }
}

/// A fetched upstream page.
#[derive(Debug, Clone)]
pub struct Page {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Bytes,
    /// Final URL after redirects, used to resolve relative links.
    pub url: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FileMeta {
    pub filename: String,
    pub url: String,
    pub upload_time: Option<DateTime<Utc>>,
    pub sha256: Option<String>,
    /// `sdist`, `bdist_wheel`, or `tarball` (npm).
    pub packagetype: String,
    pub size: Option<u64>,
    pub yanked: bool,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct VersionMeta {
    pub version: String,
    /// Earliest upload time among the version's files (PyPI) or `time[version]` (npm).
    pub published: Option<DateTime<Utc>>,
    pub files: Vec<FileMeta>,
    /// npm lifecycle scripts that run on install (`preinstall`, `install`, `postinstall`).
    pub install_scripts: Vec<String>,
    /// The same scripts with their commands, `(script, command)`. The command is empty when
    /// only `hasInstallScript` is known, and capped at [`MAX_SCRIPT_CHARS`] characters.
    pub install_commands: Vec<(String, String)>,
    /// The version carries a provenance attestation: npm `dist.attestations`, or on PyPI a
    /// PEP 740 provenance object on at least one of its files (from the JSON simple index,
    /// see [`parse_pypi_simple_provenance`]).
    pub attested: bool,
    /// npm: the account that published the version (`_npmUser.name`). PyPI's JSON API does
    /// not name uploaders.
    pub publisher: Option<String>,
    /// npm: `dependencies` and `optionalDependencies` as `(name, spec)`, at most
    /// [`MAX_DEPENDENCIES`]. Empty for PyPI, whose JSON API does not list them per release.
    pub dependencies: Vec<(String, String)>,
    pub yanked: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PackageMeta {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub latest: Option<String>,
    pub dist_tags: BTreeMap<String, String>,
    pub versions: Vec<VersionMeta>,
    /// npm: when the package was first published (`time.created`).
    pub created: Option<DateTime<Utc>>,
    /// npm: accounts that maintain or have published the package (`maintainers[].name`
    /// and every version's `_npmUser.name`), at most [`MAX_PEOPLE`].
    pub people: Vec<String>,
}

impl PackageMeta {
    pub fn version(&self, v: &str) -> Option<&VersionMeta> {
        self.versions.iter().find(|x| x.version == v)
    }

    /// Whether the document lists version `v` (PyPI: any spelling with the same PEP 440
    /// value, as `1.0` for `1.0.0`).
    pub fn lists(&self, v: &str) -> bool {
        self.version(v).is_some()
            || (self.ecosystem == Ecosystem::Pypi
                && crate::resolve::Pep440::parse(v).is_some_and(|want| {
                    self.versions.iter().any(|x| {
                        crate::resolve::Pep440::parse(&x.version)
                            .is_some_and(|have| have.cmp(&want).is_eq())
                    })
                }))
    }
}

/// Result of downloading an artifact into a file.
#[derive(Debug, Clone)]
pub struct Download {
    pub sha256: String,
    pub size: u64,
}

pub struct Registry {
    client: reqwest::Client,
    metrics: Arc<Metrics>,
    meta: Mutex<HashMap<String, MetaEntry>>,
}

/// A cached package document.
struct MetaEntry {
    fetched: Instant,
    meta: Arc<PackageMeta>,
    /// Fetched because the copy before it did not list a version a caller needed.
    refreshed: bool,
}

/// Cache `entry` under `key`, keeping the map bounded: past [`META_SOFT_CAP`] entries the
/// expired ones are dropped, and past [`META_HARD_CAP`] the oldest quarter goes too.
fn insert_meta(map: &mut HashMap<String, MetaEntry>, key: String, entry: MetaEntry, now: Instant) {
    if map.len() >= META_SOFT_CAP {
        map.retain(|_, e| now.saturating_duration_since(e.fetched) < META_TTL);
    }
    map.insert(key, entry);
    if map.len() > META_HARD_CAP {
        let mut ages: Vec<(Instant, String)> =
            map.iter().map(|(k, e)| (e.fetched, k.clone())).collect();
        ages.sort();
        for (_, k) in ages.into_iter().take(map.len() - META_HARD_CAP * 3 / 4) {
            map.remove(&k);
        }
    }
}

fn parse_time(v: &Value) -> Option<DateTime<Utc>> {
    v.as_str()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&Utc))
}

const NPM_INSTALL_SCRIPTS: [&str; 3] = ["preinstall", "install", "postinstall"];

/// Longest install script command kept per version. Packuments of large packages list
/// thousands of versions, so metadata keeps only what the policy rules compare.
pub const MAX_SCRIPT_CHARS: usize = 512;
/// Dependencies kept per npm version; real packages stay far below this.
pub const MAX_DEPENDENCIES: usize = 400;
/// Maintainer and publisher names kept per npm package.
pub const MAX_PEOPLE: usize = 200;
const MAX_SPEC_CHARS: usize = 256;

fn npm_dependencies(doc: &Value) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for key in ["dependencies", "optionalDependencies"] {
        let Some(o) = doc.get(key).and_then(Value::as_object) else {
            continue;
        };
        for (name, spec) in o {
            if out.len() >= MAX_DEPENDENCIES {
                return out;
            }
            if out.iter().any(|(n, _)| n == name) {
                continue;
            }
            let spec = spec.as_str().unwrap_or("");
            out.push((name.clone(), spec.chars().take(MAX_SPEC_CHARS).collect()));
        }
    }
    out
}

/// URL path form of an npm package name: scoped names escape the slash.
pub fn npm_escape(name: &str) -> String {
    name.replacen('/', "%2f", 1)
}

impl Registry {
    pub fn new(metrics: Arc<Metrics>) -> anyhow::Result<Self> {
        let mut b = reqwest::Client::builder()
            .use_rustls_tls()
            .user_agent(concat!("customs/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(Duration::from_secs(60))
            .pool_idle_timeout(Duration::from_secs(60));
        for var in ["CUSTOMS_CA_FILE", "SSL_CERT_FILE"] {
            if let Ok(path) = std::env::var(var) {
                if let Ok(pem) = std::fs::read(&path) {
                    let certs = reqwest::Certificate::from_pem_bundle(&pem)
                        .with_context(|| format!("parsing {var}={path}"))?;
                    for c in certs {
                        b = b.add_root_certificate(c);
                    }
                }
            }
        }
        Ok(Self {
            client: b.build().context("building HTTP client")?,
            metrics,
            meta: Mutex::new(HashMap::new()),
        })
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// GET a page; any status is returned (the caller decides what a 404 means).
    pub async fn get(
        &self,
        url: &str,
        accept: Option<&str>,
        kind: &str,
    ) -> Result<Page, FetchError> {
        let start = Instant::now();
        let mut req = self.client.get(url);
        if let Some(a) = accept {
            req = req.header(reqwest::header::ACCEPT, a);
        }
        let resp = req.send().await;
        let result = async {
            let resp = resp?;
            let status = resp.status().as_u16();
            let final_url = resp.url().to_string();
            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let body = resp.bytes().await?;
            Ok(Page {
                status,
                content_type,
                body,
                url: final_url,
            })
        }
        .await;
        self.metrics.upstream_latency(kind, start.elapsed());
        result
    }

    async fn get_json(&self, url: &str, kind: &str) -> Result<Value, FetchError> {
        let page = self.get(url, Some("application/json"), kind).await?;
        match page.status {
            200 => serde_json::from_slice(&page.body)
                .map_err(|e| FetchError::Other(format!("invalid JSON from {url}: {e}"))),
            404 => Err(FetchError::NotFound),
            s => Err(FetchError::Status(s)),
        }
    }

    /// Package metadata, cached for a few minutes. `Ok(None)` when the name does not exist.
    pub async fn package_meta(
        &self,
        upstream: &Upstream,
        eco: Ecosystem,
        name: &str,
    ) -> Result<Option<Arc<PackageMeta>>, FetchError> {
        self.package_meta_listing(upstream, eco, name, &[]).await
    }

    /// [`Registry::package_meta`] for a caller that needs the versions in `need`: a cached
    /// document that does not list one of them predates its release and is fetched again
    /// (at most once per [`META_REFRESH_GAP`] while the version stays missing).
    pub async fn package_meta_listing(
        &self,
        upstream: &Upstream,
        eco: Ecosystem,
        name: &str,
        need: &[&str],
    ) -> Result<Option<Arc<PackageMeta>>, FetchError> {
        let key = format!("{}:{}", ecosystem_str(eco), normalize_name(eco, name));
        let mut refreshed = false;
        if let Some(e) = self
            .meta
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
        {
            let age = e.fetched.elapsed();
            if age < META_TTL {
                if need.iter().all(|v| e.meta.lists(v)) || (e.refreshed && age < META_REFRESH_GAP) {
                    return Ok(Some(e.meta.clone()));
                }
                refreshed = true;
            }
        }
        let parsed = match eco {
            Ecosystem::Pypi => {
                let url = format!("{}/{}/json", upstream.pypi_json, normalize_name(eco, name));
                let mut meta = match self.get_json(&url, "pypi_json").await {
                    Ok(v) => parse_pypi_project(&v),
                    Err(FetchError::NotFound) => return Ok(None),
                    Err(e) => return Err(e),
                };
                if let Some(m) = meta.as_mut() {
                    self.add_pypi_provenance(upstream, m).await;
                }
                meta
            }
            Ecosystem::Npm => {
                let url = format!("{}/{}", upstream.npm, npm_escape(name));
                match self.get_json(&url, "npm_packument").await {
                    Ok(v) => parse_npm_packument(&v),
                    Err(FetchError::NotFound) => return Ok(None),
                    Err(e) => return Err(e),
                }
            }
        }
        .ok_or_else(|| FetchError::Other(format!("unexpected metadata format for {key}")))?;
        let m = Arc::new(parsed);
        let now = Instant::now();
        insert_meta(
            &mut self.meta.lock().unwrap_or_else(|e| e.into_inner()),
            key,
            MetaEntry {
                fetched: now,
                meta: m.clone(),
                refreshed,
            },
            now,
        );
        Ok(Some(m))
    }

    /// Mark the releases that carry PEP 740 provenance. The project JSON API does not report
    /// it, but the JSON simple index (PEP 691) lists a `provenance` URL for every attested
    /// file, so one request covers the whole project. A failed or non-JSON response (an
    /// index mirror that serves only HTML) leaves every release unattested, which keeps
    /// `provenance_dropped` silent.
    async fn add_pypi_provenance(&self, upstream: &Upstream, meta: &mut PackageMeta) {
        let url = format!(
            "{}/{}/",
            upstream.pypi_simple.trim_end_matches('/'),
            normalize_name(Ecosystem::Pypi, &meta.name)
        );
        let page = match self
            .get(&url, Some(PYPI_SIMPLE_JSON), "pypi_simple_json")
            .await
        {
            Ok(p) if p.status == 200 => p,
            Ok(p) => {
                tracing::debug!(url, status = p.status, "no JSON simple index");
                return;
            }
            Err(e) => {
                tracing::debug!(url, error = %e, "JSON simple index lookup failed");
                return;
            }
        };
        let Ok(doc) = serde_json::from_slice::<Value>(&page.body) else {
            return;
        };
        let attested = parse_pypi_simple_provenance(&doc);
        for v in &mut meta.versions {
            v.attested = v
                .files
                .iter()
                .any(|f| attested.contains(f.filename.as_str()));
        }
    }

    /// Metadata of one PyPI release from the per-version endpoint, which is far smaller
    /// than the project document for packages with long histories.
    pub async fn pypi_release(
        &self,
        upstream: &Upstream,
        name: &str,
        version: &str,
    ) -> Result<Option<VersionMeta>, FetchError> {
        let url = format!(
            "{}/{}/{}/json",
            upstream.pypi_json,
            normalize_name(Ecosystem::Pypi, name),
            version
        );
        match self.get_json(&url, "pypi_json").await {
            Ok(v) => {
                let files = v
                    .get("urls")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(parse_pypi_file).collect())
                    .unwrap_or_default();
                Ok(Some(pypi_version(version.to_string(), files)))
            }
            Err(FetchError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Stream `url` into `dest`, hashing as it goes. Fails with `TooLarge` past `max_bytes`.
    pub async fn download(
        &self,
        url: &str,
        dest: &Path,
        max_bytes: u64,
    ) -> Result<Download, FetchError> {
        let start = Instant::now();
        let result = async {
            let mut resp = self.client.get(url).send().await?;
            match resp.status().as_u16() {
                200 => {}
                404 => return Err(FetchError::NotFound),
                s => return Err(FetchError::Status(s)),
            }
            if resp.content_length().is_some_and(|n| n > max_bytes) {
                return Err(FetchError::TooLarge(max_bytes));
            }
            let mut file = tokio::fs::File::create(dest)
                .await
                .map_err(|e| FetchError::Other(format!("cache write {}: {e}", dest.display())))?;
            let mut hasher = Sha256::new();
            let mut size = 0u64;
            while let Some(chunk) = resp.chunk().await? {
                size += chunk.len() as u64;
                if size > max_bytes {
                    return Err(FetchError::TooLarge(max_bytes));
                }
                hasher.update(&chunk);
                file.write_all(&chunk)
                    .await
                    .map_err(|e| FetchError::Other(format!("cache write: {e}")))?;
            }
            file.flush()
                .await
                .map_err(|e| FetchError::Other(format!("cache write: {e}")))?;
            Ok(Download {
                sha256: hex::encode(hasher.finalize()),
                size,
            })
        }
        .await;
        self.metrics.upstream_latency("artifact", start.elapsed());
        result
    }
}

/// Media type of the JSON simple index (PEP 691).
pub const PYPI_SIMPLE_JSON: &str = "application/vnd.pypi.simple.v1+json";

/// Filenames that carry a PEP 740 provenance object in a JSON simple index document.
pub fn parse_pypi_simple_provenance(v: &Value) -> std::collections::HashSet<String> {
    v.get("files")
        .and_then(Value::as_array)
        .map(|files| {
            files
                .iter()
                .filter(|f| f.get("provenance").is_some_and(|p| !p.is_null()))
                .filter_map(|f| f.get("filename")?.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_pypi_file(f: &Value) -> Option<FileMeta> {
    Some(FileMeta {
        filename: f.get("filename")?.as_str()?.to_string(),
        url: f.get("url")?.as_str()?.to_string(),
        upload_time: f
            .get("upload_time_iso_8601")
            .and_then(parse_time)
            .or_else(|| {
                // Older responses carry only a naive `upload_time` in UTC.
                f.get("upload_time")
                    .and_then(Value::as_str)
                    .and_then(|s| {
                        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").ok()
                    })
                    .map(|n| n.and_utc())
            }),
        sha256: f
            .get("digests")
            .and_then(|d| d.get("sha256"))
            .and_then(Value::as_str)
            .map(str::to_string),
        packagetype: f
            .get("packagetype")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        size: f.get("size").and_then(Value::as_u64),
        yanked: f.get("yanked").and_then(Value::as_bool).unwrap_or(false),
    })
}

fn pypi_version(version: String, files: Vec<FileMeta>) -> VersionMeta {
    let published = files.iter().filter_map(|f| f.upload_time).min();
    let yanked = !files.is_empty() && files.iter().all(|f| f.yanked);
    VersionMeta {
        version,
        published,
        files,
        yanked,
        ..Default::default()
    }
}

/// Parse the PyPI JSON API project document (`/pypi/{name}/json`).
pub fn parse_pypi_project(v: &Value) -> Option<PackageMeta> {
    let info = v.get("info")?;
    let name = info.get("name")?.as_str()?.to_string();
    let latest = info
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut versions: Vec<VersionMeta> = v
        .get("releases")
        .and_then(Value::as_object)
        .map(|rel| {
            rel.iter()
                .map(|(ver, files)| {
                    let files = files
                        .as_array()
                        .map(|a| a.iter().filter_map(parse_pypi_file).collect())
                        .unwrap_or_default();
                    pypi_version(ver.clone(), files)
                })
                .collect()
        })
        .unwrap_or_default();
    // The project document of very old packages may omit `releases`; fall back to `urls`.
    if versions.is_empty() {
        if let (Some(l), Some(urls)) = (&latest, v.get("urls").and_then(Value::as_array)) {
            versions.push(pypi_version(
                l.clone(),
                urls.iter().filter_map(parse_pypi_file).collect(),
            ));
        }
    }
    Some(PackageMeta {
        ecosystem: Ecosystem::Pypi,
        name,
        latest,
        dist_tags: BTreeMap::new(),
        versions,
        created: None,
        people: Vec::new(),
    })
}

/// Parse a full npm packument.
pub fn parse_npm_packument(v: &Value) -> Option<PackageMeta> {
    let name = v.get("name")?.as_str()?.to_string();
    let dist_tags: BTreeMap<String, String> = v
        .get("dist-tags")
        .and_then(Value::as_object)
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                .collect()
        })
        .unwrap_or_default();
    let time = v.get("time");
    let versions: Vec<VersionMeta> = v
        .get("versions")
        .and_then(Value::as_object)
        .map(|o| {
            o.iter()
                .map(|(ver, doc)| {
                    let dist = doc.get("dist");
                    let tarball = dist
                        .and_then(|d| d.get("tarball"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let filename = tarball.rsplit('/').next().unwrap_or("").to_string();
                    let published = time.and_then(|t| t.get(ver)).and_then(parse_time);
                    let mut install_commands: Vec<(String, String)> = doc
                        .get("scripts")
                        .and_then(Value::as_object)
                        .map(|s| {
                            NPM_INSTALL_SCRIPTS
                                .iter()
                                .filter_map(|k| {
                                    let cmd = s.get(*k)?.as_str().unwrap_or("");
                                    Some((
                                        k.to_string(),
                                        cmd.chars().take(MAX_SCRIPT_CHARS).collect(),
                                    ))
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    if install_commands.is_empty()
                        && doc.get("hasInstallScript").and_then(Value::as_bool) == Some(true)
                    {
                        install_commands.push(("install script".to_string(), String::new()));
                    }
                    let install_scripts = install_commands.iter().map(|(k, _)| k.clone()).collect();
                    let publisher = doc
                        .get("_npmUser")
                        .and_then(|u| u.get("name"))
                        .and_then(Value::as_str)
                        .filter(|n| !n.is_empty())
                        .map(|n| n.chars().take(214).collect());
                    let attested = dist
                        .and_then(|d| d.get("attestations"))
                        .is_some_and(|a| !a.is_null());
                    let dependencies = npm_dependencies(doc);
                    VersionMeta {
                        version: ver.clone(),
                        published,
                        files: vec![FileMeta {
                            filename,
                            url: tarball,
                            upload_time: published,
                            sha256: None,
                            packagetype: "tarball".into(),
                            // The packument has no tarball size; `dist.unpackedSize` is
                            // whatever the publisher wrote, so it is not used.
                            size: None,
                            yanked: false,
                        }],
                        install_scripts,
                        install_commands,
                        attested,
                        publisher,
                        dependencies,
                        yanked: doc.get("deprecated").is_some_and(|d| d.is_string()),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let mut people: Vec<String> = Vec::new();
    let maintainers = v
        .get("maintainers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|m| m.get("name").and_then(Value::as_str))
        .map(str::to_string);
    let publishers = versions
        .iter()
        .filter_map(|x: &VersionMeta| x.publisher.clone());
    for p in maintainers.chain(publishers) {
        if people.len() >= MAX_PEOPLE {
            break;
        }
        if !p.is_empty() && !people.contains(&p) {
            people.push(p);
        }
    }
    Some(PackageMeta {
        ecosystem: Ecosystem::Npm,
        name,
        latest: dist_tags.get("latest").cloned(),
        dist_tags,
        versions,
        created: time.and_then(|t| t.get("created")).and_then(parse_time),
        people,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_metadata_cache_stays_bounded() {
        let meta = Arc::new(PackageMeta {
            ecosystem: Ecosystem::Npm,
            name: "x".into(),
            latest: None,
            dist_tags: BTreeMap::new(),
            versions: vec![],
            created: None,
            people: vec![],
        });
        let entry = |fetched: Instant| MetaEntry {
            fetched,
            meta: meta.clone(),
            refreshed: false,
        };
        let t0 = Instant::now();
        let mut map = HashMap::new();
        for i in 0..META_SOFT_CAP {
            insert_meta(&mut map, format!("old{i}"), entry(t0), t0);
        }
        assert_eq!(map.len(), META_SOFT_CAP);
        // Once the old entries have expired, the next insert past the bound sweeps them.
        let later = t0 + META_TTL + Duration::from_secs(1);
        insert_meta(&mut map, "new".into(), entry(later), later);
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("new"));

        // Fresh entries are never swept, but the hard cap drops the oldest.
        let mut map = HashMap::new();
        for i in 0..META_HARD_CAP + 10 {
            let t = t0 + Duration::from_millis(i as u64);
            insert_meta(&mut map, format!("k{i}"), entry(t), t);
        }
        assert!(map.len() <= META_HARD_CAP);
        let last = format!("k{}", META_HARD_CAP + 9);
        assert!(map.contains_key(&last));
        assert!(!map.contains_key("k0"));
    }

    #[test]
    fn parses_pypi_project() {
        let v: Value = serde_json::from_str(
            r#"{"info": {"name": "Demo", "version": "1.1"},
                "releases": {
                  "1.0": [{"filename": "demo-1.0.tar.gz", "url": "https://files.example/demo-1.0.tar.gz",
                           "upload_time_iso_8601": "2020-01-02T03:04:05.123456Z",
                           "digests": {"sha256": "ab"}, "packagetype": "sdist", "size": 10, "yanked": false}],
                  "1.1": [{"filename": "demo-1.1-py3-none-any.whl", "url": "u", "upload_time": "2021-01-01T00:00:00",
                           "packagetype": "bdist_wheel", "yanked": true}]
                }}"#,
        )
        .unwrap();
        let m = parse_pypi_project(&v).unwrap();
        assert_eq!(m.latest.as_deref(), Some("1.1"));
        let v10 = m.version("1.0").unwrap();
        assert_eq!(v10.files[0].sha256.as_deref(), Some("ab"));
        assert_eq!(
            v10.published.unwrap().to_rfc3339(),
            "2020-01-02T03:04:05.123456+00:00"
        );
        let v11 = m.version("1.1").unwrap();
        assert!(v11.yanked);
        assert!(v11.published.is_some());
    }

    #[test]
    fn reads_pypi_provenance_from_the_json_index() {
        let v: Value = serde_json::from_str(
            r#"{"meta": {"api-version": "1.1"}, "name": "demo", "files": [
                 {"filename": "demo-1.0.tar.gz", "provenance": "https://pypi.org/integrity/demo/1.0/demo-1.0.tar.gz/provenance"},
                 {"filename": "demo-1.1.tar.gz", "provenance": null},
                 {"filename": "demo-1.2.tar.gz"}]}"#,
        )
        .unwrap();
        let a = parse_pypi_simple_provenance(&v);
        assert_eq!(a.len(), 1);
        assert!(a.contains("demo-1.0.tar.gz"));
        assert!(parse_pypi_simple_provenance(&serde_json::json!({"files": "x"})).is_empty());
    }

    #[test]
    fn parses_npm_packument() {
        let v: Value = serde_json::from_str(
            r#"{"name": "@s/p", "dist-tags": {"latest": "2.0.0", "next": "3.0.0-rc.1"},
                "time": {"2.0.0": "2024-05-01T00:00:00.000Z"},
                "versions": {
                  "2.0.0": {"dist": {"tarball": "https://r/@s/p/-/p-2.0.0.tgz"}, "scripts": {"postinstall": "node x.js", "test": "jest"}},
                  "3.0.0-rc.1": {"dist": {"tarball": "https://r/@s/p/-/p-3.0.0-rc.1.tgz"}, "hasInstallScript": true}
                }}"#,
        )
        .unwrap();
        let m = parse_npm_packument(&v).unwrap();
        assert_eq!(m.latest.as_deref(), Some("2.0.0"));
        let v2 = m.version("2.0.0").unwrap();
        assert_eq!(v2.install_scripts, vec!["postinstall"]);
        assert_eq!(v2.files[0].filename, "p-2.0.0.tgz");
        assert!(v2.published.is_some());
        assert_eq!(m.version("3.0.0-rc.1").unwrap().install_scripts.len(), 1);
    }

    #[test]
    fn keeps_release_history_fields() {
        let long = "x".repeat(MAX_SCRIPT_CHARS + 50);
        let v: Value = serde_json::from_str(&format!(
            r#"{{"name": "@s/p",
                "time": {{"1.0.0": "2024-05-01T00:00:00.000Z", "1.0.1": "2024-06-01T00:00:00.000Z"}},
                "versions": {{
                  "1.0.0": {{"_npmUser": {{"name": "alice", "email": "a@x"}},
                            "dist": {{"tarball": "t", "attestations": {{"url": "u", "provenance": {{}}}}}},
                            "scripts": {{"install": "node-gyp rebuild", "postinstall": "{long}", "build": "tsc"}}}},
                  "1.0.1": {{"_npmUser": {{"name": ""}}, "dist": {{"tarball": "t", "attestations": null}},
                            "scripts": {{"preinstall": 5}}}}
                }}}}"#
        ))
        .unwrap();
        let m = parse_npm_packument(&v).unwrap();
        let a = m.version("1.0.0").unwrap();
        assert!(a.attested);
        assert_eq!(a.publisher.as_deref(), Some("alice"));
        assert_eq!(a.install_scripts, vec!["install", "postinstall"]);
        assert_eq!(a.install_commands[0].1, "node-gyp rebuild");
        assert_eq!(a.install_commands[1].1.len(), MAX_SCRIPT_CHARS);
        let b = m.version("1.0.1").unwrap();
        assert!(!b.attested);
        assert_eq!(b.publisher, None);
        // A non-string command still counts as a script, with an unknown command.
        assert_eq!(
            b.install_commands,
            vec![("preinstall".to_string(), String::new())]
        );
        // PyPI metadata has none of these.
        let p = parse_pypi_project(&serde_json::json!({"info": {"name": "d"},
            "releases": {"1.0": [{"filename": "d-1.0.tar.gz", "url": "u"}]}}))
        .unwrap();
        let r = p.version("1.0").unwrap();
        assert!(!r.attested && r.publisher.is_none() && r.install_commands.is_empty());
    }

    #[test]
    fn keeps_dependencies_and_people() {
        let v = serde_json::json!({
            "name": "app",
            "maintainers": [{"name": "alice", "email": "a@x"}, {"name": "bob"}],
            "time": {"created": "2020-01-01T00:00:00.000Z", "1.0.0": "2020-01-01T00:00:00.000Z"},
            "versions": {"1.0.0": {
                "_npmUser": {"name": "carol"},
                "dist": {"tarball": "t"},
                "dependencies": {"left-pad": "^1.0.0", "x": 5},
                "optionalDependencies": {"fsevents": "^2", "left-pad": "^9"}
            }}
        });
        let m = parse_npm_packument(&v).unwrap();
        assert_eq!(m.people, vec!["alice", "bob", "carol"]);
        assert_eq!(
            m.created,
            Some("2020-01-01T00:00:00Z".parse::<DateTime<Utc>>().unwrap())
        );
        // `dependencies` wins over a duplicate optional entry; a non-string spec is empty.
        assert_eq!(
            m.version("1.0.0").unwrap().dependencies,
            vec![
                ("left-pad".to_string(), "^1.0.0".to_string()),
                ("x".to_string(), String::new()),
                ("fsevents".to_string(), "^2".to_string()),
            ]
        );
    }

    #[test]
    fn escapes_scoped_names() {
        assert_eq!(npm_escape("@babel/core"), "@babel%2fcore");
        assert_eq!(npm_escape("left-pad"), "left-pad");
    }
}
