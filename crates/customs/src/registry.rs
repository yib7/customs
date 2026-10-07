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

#[derive(Debug, Clone, PartialEq)]
pub struct VersionMeta {
    pub version: String,
    /// Earliest upload time among the version's files (PyPI) or `time[version]` (npm).
    pub published: Option<DateTime<Utc>>,
    pub files: Vec<FileMeta>,
    /// npm lifecycle scripts that run on install (`preinstall`, `install`, `postinstall`).
    pub install_scripts: Vec<String>,
    pub yanked: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PackageMeta {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub latest: Option<String>,
    pub dist_tags: BTreeMap<String, String>,
    pub versions: Vec<VersionMeta>,
}

impl PackageMeta {
    pub fn version(&self, v: &str) -> Option<&VersionMeta> {
        self.versions.iter().find(|x| x.version == v)
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
    meta: Mutex<HashMap<String, (Instant, Arc<PackageMeta>)>>,
}

fn parse_time(v: &Value) -> Option<DateTime<Utc>> {
    v.as_str()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&Utc))
}

const NPM_INSTALL_SCRIPTS: [&str; 3] = ["preinstall", "install", "postinstall"];

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
    pub async fn get(&self, url: &str, accept: Option<&str>, kind: &str) -> Result<Page, FetchError> {
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
        let key = format!("{}:{}", ecosystem_str(eco), normalize_name(eco, name));
        if let Some((t, m)) = self.meta.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
            if t.elapsed() < META_TTL {
                return Ok(Some(m.clone()));
            }
        }
        let parsed = match eco {
            Ecosystem::Pypi => {
                let url = format!("{}/{}/json", upstream.pypi_json, normalize_name(eco, name));
                match self.get_json(&url, "pypi_json").await {
                    Ok(v) => parse_pypi_project(&v),
                    Err(FetchError::NotFound) => return Ok(None),
                    Err(e) => return Err(e),
                }
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
        self.meta
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, (Instant::now(), m.clone()));
        Ok(Some(m))
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
    pub async fn download(&self, url: &str, dest: &Path, max_bytes: u64) -> Result<Download, FetchError> {
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
                    .and_then(|s| chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").ok())
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
        install_scripts: Vec::new(),
        yanked,
    }
}

/// Parse the PyPI JSON API project document (`/pypi/{name}/json`).
pub fn parse_pypi_project(v: &Value) -> Option<PackageMeta> {
    let info = v.get("info")?;
    let name = info.get("name")?.as_str()?.to_string();
    let latest = info.get("version").and_then(Value::as_str).map(str::to_string);
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
    let versions = v
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
                    let mut install_scripts: Vec<String> = doc
                        .get("scripts")
                        .and_then(Value::as_object)
                        .map(|s| {
                            NPM_INSTALL_SCRIPTS
                                .iter()
                                .filter(|k| s.contains_key(**k))
                                .map(|k| k.to_string())
                                .collect()
                        })
                        .unwrap_or_default();
                    if install_scripts.is_empty()
                        && doc.get("hasInstallScript").and_then(Value::as_bool) == Some(true)
                    {
                        install_scripts.push("install script".to_string());
                    }
                    VersionMeta {
                        version: ver.clone(),
                        published,
                        files: vec![FileMeta {
                            filename,
                            url: tarball,
                            upload_time: published,
                            sha256: None,
                            packagetype: "tarball".into(),
                            size: dist.and_then(|d| d.get("unpackedSize")).and_then(Value::as_u64),
                            yanked: false,
                        }],
                        install_scripts,
                        yanked: doc.get("deprecated").is_some_and(|d| d.is_string()),
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    Some(PackageMeta {
        ecosystem: Ecosystem::Npm,
        name,
        latest: dist_tags.get("latest").cloned(),
        dist_tags,
        versions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(v10.published.unwrap().to_rfc3339(), "2020-01-02T03:04:05.123456+00:00");
        let v11 = m.version("1.1").unwrap();
        assert!(v11.yanked);
        assert!(v11.published.is_some());
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
    fn escapes_scoped_names() {
        assert_eq!(npm_escape("@babel/core"), "@babel%2fcore");
        assert_eq!(npm_escape("left-pad"), "left-pad");
    }
}
