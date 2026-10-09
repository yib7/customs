//! `customs audit`: check every dependency pinned in a project's lockfiles (DESIGN.md
//! section 11).
//!
//! Lockfiles are parsed without network access into exact (ecosystem, name, version) pins,
//! each with the file and line that pins it. Every distinct pin is then checked through the
//! same [`Checker`] as `customs check` (a running server, else in-process), a bounded number
//! at a time, and the results are printed as text, JSON, or SARIF 2.1.0 for GitHub code
//! scanning.

mod bun;
mod deno;
pub mod mcp;
mod package_lock;
mod pipfile;
mod pnpm;
mod poetry;
mod requirements;
pub mod sarif;
mod uv;
mod yarn;

use std::collections::{HashMap, HashSet};
use std::path::{Component, Path, PathBuf};

use clap::ValueEnum;
use customs_model::Decision;
use customs_scan::Ecosystem;
use futures::stream::{self, StreamExt};
use serde::Serialize;
use serde_json::{json, Value};

use crate::client::{CheckError, Checker, LocalOptions};
use crate::hook::parse::valid_npm_name;
use crate::util::{ecosystem_str, normalize_name};
use crate::verdict::Verdict;

/// One exact pin found in a lockfile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Dependency {
    pub ecosystem: Ecosystem,
    /// Normalized name.
    pub name: String,
    pub version: String,
    pub file: PathBuf,
    /// 1-based.
    pub line: usize,
    /// False for a package an MCP configuration launches without an exact version:
    /// `version` is then the range or tag it asks for (`latest` when none), and the check
    /// resolves it to the release that would run now.
    pub pinned: bool,
}

impl Dependency {
    pub fn label(&self) -> String {
        format!(
            "{} {} {}",
            ecosystem_str(self.ecosystem),
            self.name,
            self.version
        )
    }
}

/// Why an entry is not checked. Decided by the parser, never from the reason text, which
/// can quote lockfile-controlled URLs and hosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipKind {
    /// The project's own files: a local path, an editable install, a workspace member.
    Local,
    /// A range or bare name that a resolver pins later.
    Unpinned,
    /// A git repository or a URL.
    Source,
    /// A package index or registry Customs does not check.
    CustomIndex,
    /// Anything else that installs code Customs did not check: an entry it could not read,
    /// a JSR package, a container image, a launcher it does not recognise.
    Other,
}

/// An entry that is not checked: not pinned to an exact version, or not from a registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skipped {
    pub file: PathBuf,
    pub line: usize,
    pub spec: String,
    pub kind: SkipKind,
    pub reason: String,
}

impl Skipped {
    /// Whether installing this entry downloads code from somewhere (git, a URL, an index
    /// Customs does not check), as opposed to the project's own files or a range a resolver
    /// will pin later.
    pub fn fetched(&self) -> bool {
        !matches!(self.kind, SkipKind::Local | SkipKind::Unpinned)
    }
}

/// An npm lockfile entry whose registry `resolved` URL is not this package's tarball:
/// npm installs whatever the URL serves, so the recorded name is not what gets installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Mismatch {
    /// The package the entry claims to be.
    pub dep: Dependency,
    pub message: String,
}

/// What the parsers produce.
#[derive(Debug, Default)]
pub struct Parsed {
    pub deps: Vec<Dependency>,
    pub skipped: Vec<Skipped>,
    pub mismatches: Vec<Mismatch>,
}

impl Parsed {
    fn dep(&mut self, eco: Ecosystem, name: &str, version: &str, file: &Path, line: usize) {
        self.deps.push(Dependency {
            ecosystem: eco,
            name: normalize_name(eco, name),
            version: version.to_string(),
            file: file.to_path_buf(),
            line,
            pinned: true,
        });
    }

    /// A package an MCP server configuration launches.
    fn server_dep(
        &mut self,
        eco: Ecosystem,
        name: &str,
        version: &str,
        pinned: bool,
        file: &Path,
        line: usize,
    ) {
        self.deps.push(Dependency {
            ecosystem: eco,
            name: normalize_name(eco, name),
            version: version.to_string(),
            file: file.to_path_buf(),
            line,
            pinned,
        });
    }

    fn mismatch(&mut self, name: &str, version: &str, file: &Path, line: usize, message: String) {
        self.mismatches.push(Mismatch {
            dep: Dependency {
                ecosystem: Ecosystem::Npm,
                name: normalize_name(Ecosystem::Npm, name),
                version: version.to_string(),
                file: file.to_path_buf(),
                line,
                pinned: true,
            },
            message,
        });
    }

    fn skip(
        &mut self,
        file: &Path,
        line: usize,
        spec: &str,
        kind: SkipKind,
        reason: impl Into<String>,
    ) {
        self.skipped.push(Skipped {
            file: file.to_path_buf(),
            line,
            spec: spec.to_string(),
            kind,
            reason: reason.into(),
        });
    }

    /// Keep the first occurrence of each pin and of each skipped line.
    fn dedup(&mut self) {
        let mut seen = HashSet::new();
        self.deps.retain(|d| {
            seen.insert((
                ecosystem_str(d.ecosystem),
                d.name.clone(),
                d.version.clone(),
            ))
        });
        let mut seen = HashSet::new();
        self.skipped
            .retain(|s| seen.insert((s.file.clone(), s.line, s.spec.clone())));
        let mut seen = HashSet::new();
        self.mismatches
            .retain(|m| seen.insert((m.dep.file.clone(), m.dep.line)));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockKind {
    Requirements,
    PoetryLock,
    UvLock,
    PipfileLock,
    PackageLock,
    PnpmLock,
    YarnLock,
    BunLock,
    DenoLock,
    /// An agent's MCP server configuration (see [`mcp`]).
    McpConfig,
}

impl LockKind {
    /// The format of a file named on the command line.
    pub fn detect(path: &Path) -> Option<Self> {
        if mcp::is_mcp_config(path) {
            return Some(LockKind::McpConfig);
        }
        let name = path.file_name()?.to_str()?;
        Some(match name {
            "poetry.lock" => LockKind::PoetryLock,
            "uv.lock" => LockKind::UvLock,
            "Pipfile.lock" => LockKind::PipfileLock,
            "package-lock.json" | "npm-shrinkwrap.json" => LockKind::PackageLock,
            "pnpm-lock.yaml" => LockKind::PnpmLock,
            "yarn.lock" => LockKind::YarnLock,
            "bun.lock" => LockKind::BunLock,
            "deno.lock" => LockKind::DenoLock,
            n if n.ends_with(".txt") => LockKind::Requirements,
            _ => return None,
        })
    }

    /// Whether a directory search picks up a file of this name.
    fn discoverable(name: &str) -> bool {
        matches!(
            name,
            "poetry.lock"
                | "uv.lock"
                | "Pipfile.lock"
                | "package-lock.json"
                | "npm-shrinkwrap.json"
                | "pnpm-lock.yaml"
                | "yarn.lock"
                | "bun.lock"
                | "deno.lock"
                | ".mcp.json"
                | "mcp.json"
        ) || (name.starts_with("requirements") && name.ends_with(".txt"))
    }
}

/// Directories a recursive search never enters.
const SKIP_DIRS: &[&str] = &["node_modules", ".git", ".venv", "target"];

/// Lockfiles named by `paths`: files as given, directories searched for known names.
pub fn find_lockfiles(paths: &[PathBuf], recursive: bool) -> Result<Vec<PathBuf>, String> {
    let mut found = Vec::new();
    for p in paths {
        if p.is_file() {
            if p.file_name().is_some_and(|n| n == "bun.lockb") {
                return Err(format!(
                    "{}: Bun's binary lockfile is not readable; run `bun install --save-text-lockfile` to write bun.lock",
                    p.display()
                ));
            }
            if LockKind::detect(p).is_none() {
                return Err(format!(
                    "{}: not a lockfile Customs can read (requirements*.txt, poetry.lock, uv.lock, Pipfile.lock, package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock, bun.lock, deno.lock) or an MCP server configuration (.mcp.json, mcp.json, .gemini/settings.json, .codex/config.toml, claude_desktop_config.json)",
                    p.display()
                ));
            }
            found.push(p.clone());
        } else if p.is_dir() {
            search_dir(p, recursive, &mut found)
                .map_err(|e| format!("reading {}: {e}", p.display()))?;
        } else {
            return Err(format!("{}: no such file or directory", p.display()));
        }
    }
    let mut seen = HashSet::new();
    found.retain(|f| seen.insert(std::fs::canonicalize(f).unwrap_or_else(|_| f.clone())));
    if found.is_empty() {
        let shown: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        return Err(format!(
            "no lockfiles found in {}{}",
            shown.join(", "),
            if recursive {
                ""
            } else {
                " (use --recursive to search subdirectories)"
            }
        ));
    }
    Ok(found)
}

fn search_dir(dir: &Path, recursive: bool, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(|e| e.file_name());
    let mut subdirs = Vec::new();
    for e in entries {
        let name = e.file_name().to_string_lossy().into_owned();
        // `file_type` does not follow symlinks, so linked directories cannot loop.
        let ft = e.file_type()?;
        if ft.is_dir() {
            if recursive && !SKIP_DIRS.contains(&name.as_str()) {
                subdirs.push(e.path());
            }
        } else if LockKind::discoverable(&name) && e.path().is_file() {
            out.push(e.path());
        }
    }
    // Agents keep MCP configurations in hidden folders a non-recursive search skips.
    for rel in mcp::PROJECT_CONFIGS {
        let p = dir.join(rel);
        if p.is_file() && !out.contains(&p) {
            out.push(p);
        }
    }
    for d in subdirs {
        search_dir(&d, recursive, out)?;
    }
    Ok(())
}

/// Parse one lockfile.
pub fn parse_lockfile(path: &Path) -> Result<Parsed, String> {
    let kind = LockKind::detect(path)
        .ok_or_else(|| format!("{}: unrecognized lockfile name", path.display()))?;
    let mut out = Parsed::default();
    if kind == LockKind::Requirements {
        requirements::parse(path, &mut out)?;
        return Ok(out);
    }
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    match kind {
        LockKind::PoetryLock => poetry::parse(text, path, &mut out),
        LockKind::UvLock => uv::parse(text, path, &mut out),
        LockKind::PipfileLock => pipfile::parse(text, path, &mut out),
        LockKind::PackageLock => package_lock::parse(text, path, &mut out),
        LockKind::PnpmLock => pnpm::parse(text, path, &mut out),
        LockKind::YarnLock => yarn::parse(text, path, &mut out),
        LockKind::BunLock => bun::parse(text, path, &mut out),
        LockKind::DenoLock => deno::parse(text, path, &mut out),
        LockKind::McpConfig => mcp::parse(text, path, &mut out),
        LockKind::Requirements => unreachable!(),
    }
    .map_err(|e| format!("{}: {e}", path.display()))?;
    // JSON maps come back sorted by key; report in file order.
    out.deps.sort_by_key(|d| d.line);
    out.skipped.sort_by_key(|s| s.line);
    Ok(out)
}

/// Parse every lockfile and merge the pins; `Err` lists every file that failed.
pub fn collect(files: &[PathBuf]) -> Result<Parsed, Vec<String>> {
    let mut all = Parsed::default();
    let mut errors = Vec::new();
    for f in files {
        match parse_lockfile(f) {
            Ok(p) => {
                all.deps.extend(p.deps);
                all.skipped.extend(p.skipped);
                all.mismatches.extend(p.mismatches);
            }
            Err(e) => errors.push(e),
        }
    }
    if !errors.is_empty() {
        return Err(errors);
    }
    all.dedup();
    Ok(all)
}

// ------------------------------------------------------------------ parser helpers

/// Byte offset to 1-based line number.
struct LineIndex(Vec<usize>);

impl LineIndex {
    fn new(text: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(
            text.bytes()
                .enumerate()
                .filter(|(_, b)| *b == b'\n')
                .map(|(i, _)| i + 1),
        );
        Self(starts)
    }

    fn line(&self, offset: usize) -> usize {
        match self.0.binary_search(&offset) {
            Ok(i) => i + 1,
            Err(i) => i,
        }
    }
}

/// Line of every object key whose value is an object or array, by key path (`["packages",
/// "node_modules/a"]`). serde_json does not keep positions, so the JSON lockfile parsers
/// look lines up here. Run it only on text serde_json accepted, which bounds the nesting.
fn json_key_lines(text: &str) -> HashMap<Vec<String>, usize> {
    let mut s = KeyLines {
        s: text.as_bytes(),
        i: 0,
        line: 1,
        path: Vec::new(),
        out: HashMap::new(),
    };
    let _ = s.value();
    s.out
}

struct KeyLines<'a> {
    s: &'a [u8],
    i: usize,
    line: usize,
    path: Vec<String>,
    out: HashMap<Vec<String>, usize>,
}

impl KeyLines<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn ws(&mut self) {
        while let Some(c) = self.peek() {
            match c {
                b'\n' => self.line += 1,
                b' ' | b'\t' | b'\r' => {}
                _ => break,
            }
            self.i += 1;
        }
    }

    /// A string starting at the current `"`; decoding is left to serde_json.
    fn string(&mut self) -> Option<String> {
        let start = self.i;
        self.i += 1;
        loop {
            match self.peek()? {
                b'"' => break,
                b'\\' => self.i += 2,
                _ => self.i += 1,
            }
        }
        self.i += 1;
        serde_json::from_slice(self.s.get(start..self.i)?).ok()
    }

    fn value(&mut self) -> Option<()> {
        self.ws();
        match self.peek()? {
            b'{' => {
                self.i += 1;
                loop {
                    self.ws();
                    match self.peek()? {
                        b'}' => {
                            self.i += 1;
                            return Some(());
                        }
                        b',' => {
                            self.i += 1;
                            continue;
                        }
                        b'"' => {}
                        _ => return None,
                    }
                    let line = self.line;
                    let key = self.string()?;
                    self.ws();
                    if self.peek()? != b':' {
                        return None;
                    }
                    self.i += 1;
                    self.ws();
                    self.path.push(key);
                    if matches!(self.peek()?, b'{' | b'[') {
                        self.out.insert(self.path.clone(), line);
                    }
                    self.value()?;
                    self.path.pop();
                }
            }
            b'[' => {
                self.i += 1;
                let mut n = 0usize;
                loop {
                    self.ws();
                    match self.peek()? {
                        b']' => {
                            self.i += 1;
                            return Some(());
                        }
                        b',' => {
                            self.i += 1;
                            n += 1;
                            continue;
                        }
                        _ => {}
                    }
                    self.path.push(n.to_string());
                    self.value()?;
                    self.path.pop();
                }
            }
            b'"' => self.string().map(|_| ()),
            _ => {
                while let Some(c) = self.peek() {
                    if matches!(c, b',' | b'}' | b']') || c.is_ascii_whitespace() {
                        break;
                    }
                    self.i += 1;
                }
                Some(())
            }
        }
    }
}

fn key_line(lines: &HashMap<Vec<String>, usize>, path: &[&str]) -> usize {
    let key: Vec<String> = path.iter().map(|s| s.to_string()).collect();
    lines.get(&key).copied().unwrap_or(1)
}

/// Public registries, and loopback hosts (lockfiles written through `customs serve`).
/// Packages from any other index are not checked against the public registry.
fn known_registry(url: &str) -> bool {
    let Some(host) = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
    else {
        return false;
    };
    matches!(
        host.as_str(),
        "pypi.org"
            | "files.pythonhosted.org"
            | "pypi.python.org"
            | "registry.npmjs.org"
            | "registry.yarnpkg.com"
            | "localhost"
            | "127.0.0.1"
            | "[::1]"
    )
}

fn host_of(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| url.to_string())
}

/// The package and version a registry tarball URL serves: `.../lodash/-/lodash-4.17.21.tgz`,
/// `.../@babel/core/-/core-7.24.0.tgz` (also `@babel%2fcore`), under any path prefix such
/// as the proxy's `/npm/`. `None` when the URL is not shaped like a registry tarball.
fn tarball_identity(url: &str) -> Option<(String, String)> {
    let u = url::Url::parse(url).ok()?;
    let path = percent_encoding::percent_decode_str(u.path())
        .decode_utf8()
        .ok()?;
    let (dir, file) = path.rsplit_once("/-/")?;
    let mut segs = dir.rsplit('/');
    let base = segs.next().filter(|b| !b.is_empty())?;
    let name = match segs.next() {
        Some(scope) if scope.starts_with('@') => format!("{scope}/{base}"),
        _ => base.to_string(),
    };
    let version = file
        .strip_prefix(base)?
        .strip_prefix('-')?
        .strip_suffix(".tgz")?;
    if version.is_empty() || version.contains('/') {
        return None;
    }
    Some((name, version.to_string()))
}

/// `name@range` with an optional `@scope/` prefix into name and range.
fn split_npm_spec(spec: &str) -> Option<(&str, &str)> {
    let start = usize::from(spec.starts_with('@'));
    let at = spec[start..].find('@')? + start;
    Some((&spec[..at], &spec[at + 1..]))
}

/// A concrete registry version (`1.2.3`, `1.0.0-rc.1+build`), not a URL or a range.
fn is_npm_version(v: &str) -> bool {
    v.starts_with(|c: char| c.is_ascii_digit())
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}

/// An npm pin; `resolved` is where the lockfile says the tarball comes from, if recorded.
fn npm_pin(
    out: &mut Parsed,
    file: &Path,
    line: usize,
    name: &str,
    version: &str,
    resolved: Option<&str>,
) {
    // npm v1 lockfiles record aliases as `"version": "npm:real-name@1.0.0"`.
    let (name, version) = match version.strip_prefix("npm:").and_then(split_npm_spec) {
        Some((real, v)) => (real, v),
        None => (name, version),
    };
    let spec = format!("{name}@{version}");
    if !valid_npm_name(name) || !is_npm_version(version) {
        let local = ["file:", "link:", ".", "/"]
            .iter()
            .any(|p| version.starts_with(p));
        if local {
            out.skip(
                file,
                line,
                &spec,
                SkipKind::Local,
                "installed from a local path",
            );
        } else {
            out.skip(
                file,
                line,
                &spec,
                SkipKind::Source,
                "not a registry package (git or URL)",
            );
        }
        return;
    }
    if let Some(r) = resolved {
        if !(r.starts_with("https://") || r.starts_with("http://")) {
            let kind = if r.starts_with("file:") {
                SkipKind::Local
            } else {
                SkipKind::Source
            };
            out.skip(
                file,
                line,
                &spec,
                kind,
                format!("resolved from {r}, not a registry"),
            );
            return;
        }
        if !known_registry(r) {
            out.skip(
                file,
                line,
                &spec,
                SkipKind::CustomIndex,
                format!("from a custom registry ({})", host_of(r)),
            );
            return;
        }
        // npm installs the tarball at `resolved` without comparing it with the entry's
        // name, so a lockfile edit can swap in another package under a trusted name.
        match tarball_identity(r) {
            Some((n, v))
                if normalize_name(Ecosystem::Npm, &n) == normalize_name(Ecosystem::Npm, name)
                    && v == version => {}
            Some((n, v)) => {
                let installed = format!("{n}@{v}");
                out.mismatch(
                    name,
                    version,
                    file,
                    line,
                    format!("lockfile installs {installed} from {r}, not {spec}"),
                );
                if valid_npm_name(&n) && is_npm_version(&v) {
                    out.dep(Ecosystem::Npm, &n, &v, file, line);
                } else {
                    out.skip(
                        file,
                        line,
                        &installed,
                        SkipKind::Other,
                        "not a registry package version",
                    );
                }
                return;
            }
            None => {
                out.mismatch(
                    name,
                    version,
                    file,
                    line,
                    format!("resolved URL {r} is not a registry tarball of {spec}"),
                );
                return;
            }
        }
    }
    out.dep(Ecosystem::Npm, name, version, file, line);
}

// ------------------------------------------------------------------ checking

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum Format {
    #[default]
    Text,
    Json,
    Sarif,
}

/// Which findings make `customs audit` exit 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum FailOn {
    Warn,
    #[default]
    Block,
    Never,
}

/// Result of checking one pin.
#[derive(Debug, Clone)]
pub enum Outcome {
    Checked {
        verdict: Box<Verdict>,
        url: Option<String>,
    },
    /// The registry has no such version (or no files for it). Counted as a warning: a
    /// pinned version that disappeared is worth a look.
    Unavailable(String),
    /// Customs itself failed (network, server error).
    Failed(String),
    /// The lockfile entry installs a different package than it names. Counted as a block.
    Mismatch(String),
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub dep: Dependency,
    pub outcome: Outcome,
}

impl Finding {
    /// Severity for `--fail-on`; `None` when the check failed.
    pub fn level(&self) -> Option<Decision> {
        match &self.outcome {
            Outcome::Checked { verdict, .. } => Some(verdict.decision),
            Outcome::Unavailable(_) => Some(Decision::Warn),
            Outcome::Mismatch(_) => Some(Decision::Block),
            Outcome::Failed(_) => None,
        }
    }

    fn status(&self) -> &'static str {
        match &self.outcome {
            Outcome::Checked { verdict, .. } => verdict.decision.as_str(),
            Outcome::Unavailable(_) => "unavailable",
            Outcome::Failed(_) => "failed",
            Outcome::Mismatch(_) => "mismatch",
        }
    }

    fn verdict(&self) -> Option<&Verdict> {
        match &self.outcome {
            Outcome::Checked { verdict, .. } => Some(verdict),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Report {
    pub files: Vec<PathBuf>,
    pub findings: Vec<Finding>,
    pub skipped: Vec<Skipped>,
    /// Where verdicts came from (`server ...`, `in-process`).
    pub via: String,
}

impl Report {
    fn count(&self, status: &str) -> usize {
        self.findings
            .iter()
            .filter(|f| f.status() == status)
            .count()
    }

    /// 1 when a finding meets `fail_on`, else 2 when any check failed, else 0.
    pub fn exit_code(&self, fail_on: FailOn) -> i32 {
        let threshold = match fail_on {
            FailOn::Warn => Some(Decision::Warn),
            FailOn::Block => Some(Decision::Block),
            FailOn::Never => None,
        };
        if let Some(t) = threshold {
            if self
                .findings
                .iter()
                .any(|f| f.level().is_some_and(|l| l >= t))
            {
                return 1;
            }
        }
        if self
            .findings
            .iter()
            .any(|f| matches!(f.outcome, Outcome::Failed(_)))
        {
            return 2;
        }
        0
    }
}

/// Check every pin, `jobs` at a time, in input order.
pub async fn check_all(checker: &Checker, deps: Vec<Dependency>, jobs: usize) -> Vec<Finding> {
    stream::iter(deps)
        .map(|dep| async move {
            // `==` keeps a PyPI version the registry lacks from resolving to another one.
            let spec = match dep.ecosystem {
                _ if !dep.pinned && dep.version == "latest" => None,
                _ if !dep.pinned => Some(dep.version.clone()),
                Ecosystem::Pypi => Some(format!("=={}", dep.version)),
                Ecosystem::Npm => Some(dep.version.clone()),
            };
            let outcome = match checker
                .check(dep.ecosystem, &dep.name, spec.as_deref(), "audit")
                .await
            {
                Ok(v) => Outcome::Checked {
                    url: checker.verdict_url(v.id),
                    verdict: Box::new(v),
                },
                Err(CheckError::Package(m)) => Outcome::Unavailable(m),
                Err(CheckError::Infrastructure(m)) => Outcome::Failed(m),
            };
            Finding { dep, outcome }
        })
        .buffered(jobs.max(1))
        .collect()
        .await
}

/// Lockfile entries that install another package than they name, as block findings.
pub fn mismatch_findings(mismatches: Vec<Mismatch>) -> Vec<Finding> {
    mismatches
        .into_iter()
        .map(|m| Finding {
            dep: m.dep,
            outcome: Outcome::Mismatch(m.message),
        })
        .collect()
}

impl Report {
    /// The most severe finding: a mismatch counts as a block, an unavailable pin as a
    /// warning. Failed checks do not count; see [`Report::failed`].
    pub fn decision(&self) -> Decision {
        self.findings
            .iter()
            .filter_map(Finding::level)
            .max()
            .unwrap_or(Decision::Allow)
    }

    pub fn failed(&self) -> usize {
        self.count("failed")
    }
}

pub struct AuditOptions {
    pub paths: Vec<PathBuf>,
    pub recursive: bool,
    pub format: Format,
    pub output: Option<PathBuf>,
    pub fail_on: FailOn,
    pub jobs: usize,
    pub server: String,
    pub local: LocalOptions,
}

/// Run `customs audit`; returns the exit code (2 for usage and parse errors).
pub async fn run(opts: AuditOptions) -> i32 {
    let paths = if opts.paths.is_empty() {
        vec![PathBuf::from(".")]
    } else {
        opts.paths.clone()
    };
    let files = match find_lockfiles(&paths, opts.recursive) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("customs audit: {e}");
            return 2;
        }
    };
    let parsed = match collect(&files) {
        Ok(p) => p,
        Err(errors) => {
            for e in errors {
                eprintln!("customs audit: {e}");
            }
            return 2;
        }
    };
    let mismatched = mismatch_findings(parsed.mismatches);
    let (mut findings, via) = if parsed.deps.is_empty() {
        (Vec::new(), "nothing to check".to_string())
    } else {
        let checker = match Checker::connect(&opts.server, &opts.local).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("customs audit: {e:#}");
                return 2;
            }
        };
        eprintln!(
            "customs audit: checking {} package{} from {} lockfile{} ({})",
            parsed.deps.len(),
            plural(parsed.deps.len()),
            files.len(),
            plural(files.len()),
            checker.describe()
        );
        (
            check_all(&checker, parsed.deps, opts.jobs).await,
            checker.describe(),
        )
    };
    findings.splice(0..0, mismatched);
    let report = Report {
        files,
        findings,
        skipped: parsed.skipped,
        via,
    };
    for f in &report.findings {
        if let Outcome::Failed(m) = &f.outcome {
            eprintln!("customs audit: checking {} failed: {m}", f.dep.label());
        }
    }
    let cwd = std::env::current_dir().unwrap_or_default();
    let rendered = match opts.format {
        Format::Text => render_text(&report, &cwd),
        Format::Json => pretty_json(&render_json(&report, &cwd)),
        Format::Sarif => pretty_json(&sarif::to_sarif(&report, &cwd)),
    };
    match &opts.output {
        Some(p) => {
            if let Err(e) = std::fs::write(p, &rendered) {
                eprintln!("customs audit: writing {}: {e}", p.display());
                return 2;
            }
        }
        None => print!("{rendered}"),
    }
    report.exit_code(opts.fail_on)
}

fn pretty_json(v: &Value) -> String {
    let mut s = serde_json::to_string_pretty(v).unwrap_or_default();
    s.push('\n');
    s
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

/// `path` relative to `cwd` when it is inside it, with forward slashes.
pub fn display_path(path: &Path, cwd: &Path) -> String {
    let abs = normalize(&cwd.join(path));
    let rel = abs
        .strip_prefix(normalize(cwd))
        .map(Path::to_path_buf)
        .ok()
        .or_else(|| {
            let (a, c) = (
                std::fs::canonicalize(&abs).ok()?,
                std::fs::canonicalize(cwd).ok()?,
            );
            a.strip_prefix(c).map(Path::to_path_buf).ok()
        })
        .unwrap_or(abs);
    rel.to_string_lossy().replace('\\', "/")
}

/// Remove `.` and resolve `..` without touching the filesystem.
fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Policy details and the model's top reasons, for messages.
pub fn top_reasons(v: &Verdict, n: usize) -> Vec<String> {
    let mut out: Vec<String> = v
        .policy_hits
        .iter()
        .filter(|h| h.severity >= Decision::Warn)
        .map(|h| h.detail.clone())
        .collect();
    if v.model_decision >= Decision::Warn {
        out.extend(v.reasons.iter().take(n).map(|r| r.label.clone()));
    } else if v.policy_hits.iter().any(|h| h.rule == "block_nonexistent") {
        // For a hallucinated name, the closest real package is the most useful hint.
        out.extend(
            v.reasons
                .iter()
                .find(|r| r.feature.starts_with("name_"))
                .map(|r| r.label.clone()),
        );
    }
    out
}

fn risk_str(v: Option<&Verdict>) -> String {
    v.and_then(|v| v.risk)
        .map(|r| format!("{r:.2}"))
        .unwrap_or_else(|| "-".into())
}

pub fn render_text(r: &Report, cwd: &Path) -> String {
    let mut s = format!(
        "Audited {} package{} from {} lockfile{} ({}): {} block, {} warn, {} allow",
        r.findings.len(),
        plural(r.findings.len()),
        r.files.len(),
        plural(r.files.len()),
        r.via,
        r.count("block"),
        r.count("warn"),
        r.count("allow"),
    );
    for (status, label) in [
        ("mismatch", "mismatched"),
        ("unavailable", "unavailable"),
        ("failed", "failed"),
    ] {
        let n = r.count(status);
        if n > 0 {
            s.push_str(&format!(", {n} {label}"));
        }
    }
    if !r.skipped.is_empty() {
        s.push_str(&format!(", {} not checked", r.skipped.len()));
    }
    s.push('\n');

    let rank = |f: &Finding| match f.status() {
        "mismatch" | "block" => 0,
        "warn" => 1,
        "unavailable" => 2,
        _ => 3,
    };
    let mut rows: Vec<&Finding> = r
        .findings
        .iter()
        .filter(|f| f.status() != "allow")
        .collect();
    rows.sort_by_key(|f| rank(f));
    if !rows.is_empty() {
        let table: Vec<[String; 5]> = rows
            .iter()
            .map(|f| {
                let reason = match &f.outcome {
                    Outcome::Checked { verdict, .. } => verdict.headline(),
                    Outcome::Unavailable(m) | Outcome::Failed(m) | Outcome::Mismatch(m) => {
                        m.clone()
                    }
                };
                [
                    f.status().to_uppercase(),
                    risk_str(f.verdict()),
                    f.dep.label(),
                    format!("{}:{}", display_path(&f.dep.file, cwd), f.dep.line),
                    reason,
                ]
            })
            .collect();
        let header = ["DECISION", "RISK", "PACKAGE", "LOCATION", "REASON"].map(String::from);
        let mut widths = [0usize; 4];
        for row in std::iter::once(&header).chain(&table) {
            for (w, cell) in widths.iter_mut().zip(row.iter()) {
                *w = (*w).max(cell.chars().count());
            }
        }
        s.push('\n');
        for row in std::iter::once(&header).chain(&table) {
            for (w, cell) in widths.iter().zip(row.iter()) {
                s.push_str(&format!("{cell:<w$}  "));
            }
            s.push_str(&row[4]);
            s.push('\n');
        }
    }
    let unpinned: Vec<&Finding> = r.findings.iter().filter(|f| !f.dep.pinned).collect();
    if !unpinned.is_empty() {
        s.push_str(
            "\nMCP servers without a pinned version (each start runs the newest matching release;\n\
             pin one, so a new release reaches you only when you change the pin):\n",
        );
        for f in unpinned {
            let resolved = f
                .verdict()
                .and_then(|v| v.version.as_deref())
                .map(|v| format!(", now {v}"))
                .unwrap_or_default();
            s.push_str(&format!(
                "  {}:{}  {} {} ({}{resolved})  {}\n",
                display_path(&f.dep.file, cwd),
                f.dep.line,
                ecosystem_str(f.dep.ecosystem),
                f.dep.name,
                f.dep.version,
                f.status(),
            ));
        }
    }
    if !r.skipped.is_empty() {
        s.push_str("\nNot checked:\n");
        for k in &r.skipped {
            s.push_str(&format!(
                "  {}:{}  {}  ({})\n",
                display_path(&k.file, cwd),
                k.line,
                k.spec,
                k.reason
            ));
        }
    }
    s
}

pub fn render_json(r: &Report, cwd: &Path) -> Value {
    let results: Vec<Value> = r
        .findings
        .iter()
        .map(|f| {
            let v = f.verdict();
            json!({
                "ecosystem": ecosystem_str(f.dep.ecosystem),
                "name": f.dep.name,
                "version": f.dep.version,
                "pinned": f.dep.pinned,
                "resolved_version": v.and_then(|v| v.version.clone()),
                "file": display_path(&f.dep.file, cwd),
                "line": f.dep.line,
                "status": f.status(),
                "risk": v.and_then(|v| v.risk),
                "reason": match &f.outcome {
                    Outcome::Mismatch(m) => Some(m.clone()),
                    _ => v.map(Verdict::headline),
                },
                "error": match &f.outcome {
                    Outcome::Unavailable(m) | Outcome::Failed(m) => Some(m.as_str()),
                    Outcome::Checked { .. } | Outcome::Mismatch(_) => None,
                },
                "verdict_url": match &f.outcome {
                    Outcome::Checked { url, .. } => url.as_deref(),
                    _ => None,
                },
                "verdict": v,
            })
        })
        .collect();
    let skipped: Vec<Value> = r
        .skipped
        .iter()
        .map(|k| {
            json!({
                "file": display_path(&k.file, cwd),
                "line": k.line,
                "spec": k.spec,
                "reason": k.reason,
            })
        })
        .collect();
    json!({
        "via": r.via,
        "files": r.files.iter().map(|f| display_path(f, cwd)).collect::<Vec<_>>(),
        "summary": {
            "packages": r.findings.len(),
            "block": r.count("block"),
            "warn": r.count("warn"),
            "allow": r.count("allow"),
            "mismatch": r.count("mismatch"),
            "unavailable": r.count("unavailable"),
            "failed": r.count("failed"),
            "not_checked": r.skipped.len(),
        },
        "results": results,
        "not_checked": skipped,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::verdict::PolicyHit;
    use customs_model::{Reason, Scores, Thresholds};

    pub(crate) fn pins(p: &Parsed) -> Vec<(String, String, usize)> {
        p.deps
            .iter()
            .map(|d| (d.name.clone(), d.version.clone(), d.line))
            .collect()
    }

    pub(crate) fn verdict(name: &str, decision: Decision, rule: Option<&str>) -> Verdict {
        Verdict {
            id: None,
            ts: "t".into(),
            ecosystem: Ecosystem::Pypi,
            name: name.into(),
            version: Some("1.0.0".into()),
            artifact: None,
            sha256: None,
            decision,
            risk: Some(if rule.is_some() { 0.1 } else { 0.97 }),
            model_decision: if rule.is_some() {
                Decision::Allow
            } else {
                decision
            },
            thresholds: Thresholds::default(),
            scores: Scores::default(),
            policy_hits: rule
                .map(|r| PolicyHit {
                    rule: r.into(),
                    severity: decision,
                    detail: format!("{r} fired"),
                })
                .into_iter()
                .collect(),
            reasons: vec![Reason {
                feature: "inst_download_exec".into(),
                value: Some(2.0),
                contribution: 1.5,
                label: "Downloads and executes a payload at install time".into(),
            }],
            evidence: vec![],
            install_surface: vec![],
            scan_errors: vec![],
            scanned_ms: 0,
            model_version: "m".into(),
            cached: false,
            mode: crate::config::Mode::Enforce,
        }
    }

    pub(crate) fn finding(name: &str, line: usize, outcome: Outcome) -> Finding {
        Finding {
            dep: Dependency {
                ecosystem: Ecosystem::Pypi,
                name: name.into(),
                version: "1.0.0".into(),
                file: PathBuf::from("sub/requirements.txt"),
                line,
                pinned: true,
            },
            outcome,
        }
    }

    pub(crate) fn checked(v: Verdict) -> Outcome {
        Outcome::Checked {
            verdict: Box::new(v),
            url: None,
        }
    }

    #[test]
    fn key_lines_track_nested_keys() {
        let text = "{\n  \"a\": {\n    \"b\\\"q\": {\"c\": 1},\n    \"list\": [{\"x\": {}}, 2]\n  },\n  \"s\": \"}{\"\n}\n";
        serde_json::from_str::<Value>(text).unwrap();
        let l = json_key_lines(text);
        assert_eq!(l[&vec!["a".to_string()]], 2);
        assert_eq!(l[&vec!["a".to_string(), "b\"q".to_string()]], 3);
        assert_eq!(
            l[&vec![
                "a".to_string(),
                "list".to_string(),
                "0".to_string(),
                "x".to_string()
            ]],
            4
        );
        assert!(!l.contains_key(&vec!["s".to_string()]));
    }

    #[test]
    fn line_index() {
        let idx = LineIndex::new("ab\ncd\n\nef");
        assert_eq!(idx.line(0), 1);
        assert_eq!(idx.line(2), 1);
        assert_eq!(idx.line(3), 2);
        assert_eq!(idx.line(6), 3);
        assert_eq!(idx.line(8), 4);
    }

    #[test]
    fn discovery_and_dedup() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::write(
            d.join("requirements.txt"),
            "a==1.0\n-r requirements-dev.txt\n",
        )
        .unwrap();
        std::fs::write(d.join("requirements-dev.txt"), "a==1.0\nb==2.0\n").unwrap();
        std::fs::write(d.join("README.md"), "x").unwrap();
        for sub in ["node_modules/x", "app", ".git"] {
            std::fs::create_dir_all(d.join(sub)).unwrap();
            std::fs::write(d.join(sub).join("package-lock.json"), "{}").unwrap();
        }
        let flat = find_lockfiles(&[d.to_path_buf()], false).unwrap();
        assert_eq!(flat.len(), 2);
        let deep = find_lockfiles(&[d.to_path_buf()], true).unwrap();
        assert_eq!(deep.len(), 3);
        assert!(deep[2].ends_with("app/package-lock.json"));
        // Named twice: parsed once.
        let twice = find_lockfiles(&[d.to_path_buf(), d.join("requirements.txt")], false).unwrap();
        assert_eq!(twice.len(), 2);

        let parsed = collect(&flat).unwrap();
        assert_eq!(parsed.deps.len(), 2);
        assert!(parsed.deps[0].file.ends_with("requirements-dev.txt"));
        assert_eq!(parsed.deps[0].line, 1);

        assert!(find_lockfiles(&[d.join("README.md")], false).is_err());
        assert!(find_lockfiles(&[d.join("missing")], false).is_err());
        let empty = tempfile::tempdir().unwrap();
        let e = find_lockfiles(&[empty.path().to_path_buf()], false).unwrap_err();
        assert!(e.contains("--recursive"), "{e}");
    }

    #[test]
    fn parse_errors_name_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("package-lock.json");
        std::fs::write(&f, "{ not json").unwrap();
        let e = collect(&[f]).unwrap_err();
        assert!(e[0].contains("package-lock.json"), "{e:?}");
    }

    #[test]
    fn npm_pins_and_registries() {
        let f = Path::new("x");
        let mut p = Parsed::default();
        npm_pin(
            &mut p,
            f,
            1,
            "a",
            "1.0.0",
            Some("https://registry.npmjs.org/a/-/a-1.0.0.tgz"),
        );
        npm_pin(&mut p, f, 2, "b", "1.0.0", None);
        npm_pin(&mut p, f, 3, "alias", "npm:@real/pkg@2.0.0", None);
        npm_pin(
            &mut p,
            f,
            4,
            "c",
            "1.0.0",
            Some("https://npm.corp.example/c/-/c-1.0.0.tgz"),
        );
        npm_pin(
            &mut p,
            f,
            5,
            "d",
            "git+ssh://git@github.com/x/d.git#abc",
            None,
        );
        npm_pin(&mut p, f, 6, "e", "1.0.0", Some("file:../e"));
        npm_pin(
            &mut p,
            f,
            7,
            "g",
            "1.0.0",
            Some("http://127.0.0.1:7878/npm/g/-/g-1.0.0.tgz"),
        );
        assert_eq!(
            pins(&p),
            vec![
                ("a".into(), "1.0.0".into(), 1),
                ("b".into(), "1.0.0".into(), 2),
                ("@real/pkg".into(), "2.0.0".into(), 3),
                ("g".into(), "1.0.0".into(), 7),
            ]
        );
        assert_eq!(p.skipped.len(), 3);
        assert!(p.skipped[0].reason.contains("npm.corp.example"));
    }

    #[test]
    fn fetched_comes_from_the_kind_not_the_lockfile_text() {
        let f = Path::new("package-lock.json");
        let mut p = Parsed::default();
        // Hosts and URLs the lockfile controls that contain "local" or "editable".
        npm_pin(
            &mut p,
            f,
            1,
            "a",
            "1.0.0",
            Some("git+https://github.com/x/localize.git#abc"),
        );
        npm_pin(
            &mut p,
            f,
            2,
            "b",
            "1.0.0",
            Some("https://npm.local.corp/b/-/b-1.0.0.tgz"),
        );
        npm_pin(
            &mut p,
            f,
            3,
            "c",
            "1.0.0",
            Some("https://editable.example/c/-/c-1.0.0.tgz"),
        );
        // The project's own files are not fetched.
        npm_pin(&mut p, f, 4, "d", "file:../d", None);
        let fetched: Vec<(usize, bool)> = p.skipped.iter().map(|s| (s.line, s.fetched())).collect();
        assert_eq!(
            fetched,
            vec![(1, true), (2, true), (3, true), (4, false)],
            "{:?}",
            p.skipped
        );
        assert_eq!(p.skipped[0].kind, SkipKind::Source);
        assert_eq!(p.skipped[1].kind, SkipKind::CustomIndex);
    }

    #[test]
    fn tarball_identities() {
        let id = |u: &str| tarball_identity(u);
        let pair = |n: &str, v: &str| Some((n.to_string(), v.to_string()));
        assert_eq!(
            id("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"),
            pair("lodash", "4.17.21")
        );
        assert_eq!(
            id("https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz"),
            pair("@babel/core", "7.24.0")
        );
        assert_eq!(
            id("https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.24.2.tgz#5a3f9"),
            pair("@babel/code-frame", "7.24.2")
        );
        assert_eq!(
            id("http://127.0.0.1:7878/npm/@types%2Fnode/-/node-20.11.30.tgz"),
            pair("@types/node", "20.11.30")
        );
        assert_eq!(
            id("https://registry.npmjs.org/a-b/-/a-b-1.0.0-rc.1.tgz"),
            pair("a-b", "1.0.0-rc.1")
        );
        assert_eq!(id("https://registry.npmjs.org/lodash"), None);
        assert_eq!(
            id("https://registry.npmjs.org/lodash/-/evil-1.0.0.tgz"),
            None
        );
        assert_eq!(id("https://registry.npmjs.org/lodash/-/lodash-.tgz"), None);
    }

    #[test]
    fn resolved_url_must_match_the_entry() {
        let f = Path::new("package-lock.json");
        let mut p = Parsed::default();
        // Another package's tarball under a trusted name: the tarball's package is checked.
        npm_pin(
            &mut p,
            f,
            1,
            "lodash",
            "4.17.21",
            Some("https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz"),
        );
        // Same package, older version than recorded.
        npm_pin(
            &mut p,
            f,
            2,
            "debug",
            "4.3.4",
            Some("https://registry.npmjs.org/debug/-/debug-2.6.8.tgz"),
        );
        // Registry host, but not a tarball URL: nothing to check, still a mismatch.
        npm_pin(
            &mut p,
            f,
            3,
            "ms",
            "2.1.2",
            Some("https://registry.npmjs.org/ms"),
        );
        // Matching entries stay ordinary pins, scoped and percent-encoded ones included.
        npm_pin(
            &mut p,
            f,
            4,
            "@types/node",
            "20.11.30",
            Some("http://localhost:7878/npm/@types%2fnode/-/node-20.11.30.tgz"),
        );
        npm_pin(
            &mut p,
            f,
            5,
            "alias",
            "npm:chalk@2.4.2",
            Some("https://registry.npmjs.org/chalk/-/chalk-2.4.2.tgz"),
        );
        assert_eq!(
            pins(&p),
            vec![
                ("evil-pkg".into(), "1.0.0".into(), 1),
                ("debug".into(), "2.6.8".into(), 2),
                ("@types/node".into(), "20.11.30".into(), 4),
                ("chalk".into(), "2.4.2".into(), 5),
            ]
        );
        let m: Vec<(&str, &str, usize)> = p
            .mismatches
            .iter()
            .map(|m| (m.dep.name.as_str(), m.dep.version.as_str(), m.dep.line))
            .collect();
        assert_eq!(
            m,
            vec![
                ("lodash", "4.17.21", 1),
                ("debug", "4.3.4", 2),
                ("ms", "2.1.2", 3)
            ]
        );
        assert_eq!(
            p.mismatches[0].message,
            "lockfile installs evil-pkg@1.0.0 from \
             https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz, not lodash@4.17.21"
        );
        assert!(p.mismatches[2].message.contains("not a registry tarball"));
        assert!(p.skipped.is_empty());
    }

    #[test]
    fn mismatches_block_and_render() {
        let cwd = Path::new("/work");
        let report = Report {
            files: vec![PathBuf::from("/work/package-lock.json")],
            findings: vec![
                finding("ok", 1, checked(verdict("ok", Decision::Allow, None))),
                finding("lodash", 2, Outcome::Mismatch("lockfile installs x".into())),
            ],
            skipped: vec![],
            via: "test".into(),
        };
        assert_eq!(report.exit_code(FailOn::Block), 1);
        assert_eq!(report.exit_code(FailOn::Never), 0);
        let t = render_text(&report, cwd);
        assert!(
            t.starts_with("Audited 2 packages from 1 lockfile (test): 0 block, 0 warn, 1 allow, 1 mismatched\n"),
            "{t}"
        );
        assert!(t.contains("MISMATCH  -     pypi lodash 1.0.0"), "{t}");
        assert!(t.trim_end().ends_with("lockfile installs x"), "{t}");
        let j = render_json(&report, cwd);
        assert_eq!(j["summary"]["mismatch"], 1);
        assert_eq!(j["results"][1]["status"], "mismatch");
        assert_eq!(j["results"][1]["reason"], "lockfile installs x");
        assert!(j["results"][1]["error"].is_null());
    }

    #[test]
    fn exit_codes() {
        let r = |findings| Report {
            files: vec![],
            findings,
            skipped: vec![],
            via: "test".into(),
        };
        let block = finding("x", 1, checked(verdict("x", Decision::Block, None)));
        let warn = finding("y", 2, checked(verdict("y", Decision::Warn, None)));
        let gone = finding("z", 3, Outcome::Unavailable("no version".into()));
        let failed = finding("w", 4, Outcome::Failed("timeout".into()));
        assert_eq!(r(vec![block.clone()]).exit_code(FailOn::Block), 1);
        assert_eq!(r(vec![block.clone()]).exit_code(FailOn::Never), 0);
        assert_eq!(r(vec![warn.clone()]).exit_code(FailOn::Block), 0);
        assert_eq!(r(vec![warn]).exit_code(FailOn::Warn), 1);
        assert_eq!(r(vec![gone.clone()]).exit_code(FailOn::Warn), 1);
        assert_eq!(r(vec![gone]).exit_code(FailOn::Block), 0);
        assert_eq!(r(vec![failed.clone()]).exit_code(FailOn::Never), 2);
        assert_eq!(r(vec![failed, block]).exit_code(FailOn::Block), 1);
        assert_eq!(r(vec![]).exit_code(FailOn::Warn), 0);
    }

    #[test]
    fn text_and_json_output() {
        let cwd = Path::new("/work");
        let report = Report {
            files: vec![PathBuf::from("/work/sub/requirements.txt")],
            findings: vec![
                finding("ok", 1, checked(verdict("ok", Decision::Allow, None))),
                finding(
                    "nope",
                    2,
                    checked(verdict("nope", Decision::Block, Some("block_nonexistent"))),
                ),
                finding("evil", 3, checked(verdict("evil", Decision::Warn, None))),
            ],
            skipped: vec![Skipped {
                file: PathBuf::from("sub/requirements.txt"),
                line: 4,
                spec: "flask>=2".into(),
                kind: SkipKind::Unpinned,
                reason: "not pinned".into(),
            }],
            via: "in-process".into(),
        };
        let t = render_text(&report, cwd);
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(
            lines[0],
            "Audited 3 packages from 1 lockfile (in-process): 1 block, 1 warn, 1 allow, 1 not checked"
        );
        assert!(lines[2].starts_with("DECISION  RISK  PACKAGE"), "{t}");
        assert!(
            lines[3].starts_with("BLOCK     0.10  pypi nope 1.0.0"),
            "{t}"
        );
        assert!(lines[3].contains("sub/requirements.txt:2"), "{t}");
        assert!(
            lines[3].ends_with("block_nonexistent: block_nonexistent fired"),
            "{t}"
        );
        assert!(lines[4].starts_with("WARN"), "{t}");
        assert!(
            t.contains("sub/requirements.txt:4  flask>=2  (not pinned)"),
            "{t}"
        );

        let j = render_json(&report, cwd);
        assert_eq!(j["files"][0], "sub/requirements.txt");
        assert_eq!(j["summary"]["block"], 1);
        assert_eq!(j["results"][1]["status"], "block");
        assert_eq!(j["results"][1]["line"], 2);
        assert_eq!(j["results"][1]["verdict"]["name"], "nope");
        assert_eq!(j["not_checked"][0]["line"], 4);
    }

    #[test]
    fn paths_are_relative_with_forward_slashes() {
        let cwd = Path::new("/work/repo");
        assert_eq!(display_path(Path::new("./a/b.lock"), cwd), "a/b.lock");
        assert_eq!(
            display_path(Path::new("/work/repo/x/y.txt"), cwd),
            "x/y.txt"
        );
        assert_eq!(
            display_path(Path::new("../other/y.txt"), cwd),
            "/work/other/y.txt"
        );
    }
}
