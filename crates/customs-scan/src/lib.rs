//! Static analysis of package archives (PyPI sdists and wheels, npm tarballs).
//!
//! This crate is the single implementation of the feature schema in `docs/DESIGN.md`
//! section 4. Training (through the `customs-scan` CLI or the `customs_scan` Python module)
//! and serving (the `customs` proxy) both call [`scan_archive`], so features cannot drift
//! between the two.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Version of the feature schema emitted by this crate.
pub const FEATURE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Pypi,
    Npm,
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Emit the install-surface token stream used by the neural model.
    pub tokens: bool,
    /// Maximum number of evidence items to keep.
    pub max_evidence: usize,
    /// Upper bound on total uncompressed bytes read from an archive.
    pub max_total_bytes: u64,
    /// Upper bound on the size of a single archive entry.
    pub max_entry_bytes: u64,
    /// Upper bound on the number of archive entries.
    pub max_entries: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            tokens: false,
            max_evidence: 50,
            max_total_bytes: 256 * 1024 * 1024,
            max_entry_bytes: 32 * 1024 * 1024,
            max_entries: 20_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub indicator: String,
    pub file: String,
    pub line: u32,
    pub snippet: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: u32,
    pub ecosystem: Ecosystem,
    pub archive: String,
    pub sha256: String,
    pub name: Option<String>,
    pub version: Option<String>,
    /// Fixed key set: every name from [`feature_names`] is always present.
    pub features: BTreeMap<String, f64>,
    pub evidence: Vec<Evidence>,
    pub install_surface: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens: Option<Vec<String>>,
    pub errors: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("unsupported archive format: {0}")]
    UnsupportedFormat(String),
    #[error("archive rejected: {0}")]
    Rejected(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Ordered list of every feature name in the schema.
pub fn feature_names() -> Vec<&'static str> {
    Vec::new()
}

/// Guess the ecosystem from an archive file name (`.whl`, `.tar.gz`, `.zip` are PyPI unless
/// the archive turns out to contain `package/package.json`; `.tgz` is npm).
pub fn guess_ecosystem(filename: &str) -> Option<Ecosystem> {
    let f = filename.to_ascii_lowercase();
    if f.ends_with(".tgz") {
        Some(Ecosystem::Npm)
    } else if f.ends_with(".whl")
        || f.ends_with(".tar.gz")
        || f.ends_with(".zip")
        || f.ends_with(".tar.bz2")
    {
        Some(Ecosystem::Pypi)
    } else {
        None
    }
}

/// Scan an archive held in memory. Never executes or imports any of its content.
pub fn scan_archive(
    bytes: &[u8],
    filename: &str,
    ecosystem: Option<Ecosystem>,
    opts: &ScanOptions,
) -> Result<ScanReport, ScanError> {
    let _ = (bytes, opts);
    let eco = ecosystem
        .or_else(|| guess_ecosystem(filename))
        .ok_or_else(|| ScanError::UnsupportedFormat(filename.to_string()))?;
    Ok(ScanReport {
        schema_version: FEATURE_SCHEMA_VERSION,
        ecosystem: eco,
        archive: filename.to_string(),
        sha256: String::new(),
        name: None,
        version: None,
        features: BTreeMap::new(),
        evidence: Vec::new(),
        install_surface: Vec::new(),
        tokens: None,
        errors: Vec::new(),
    })
}
