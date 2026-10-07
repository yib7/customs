//! Static analysis of package archives (PyPI sdists and wheels, npm tarballs).
//!
//! This crate is the single implementation of the feature schema in `docs/DESIGN.md`
//! section 4. Training (through the `customs-scan` CLI or the `customs_scan` Python module)
//! and serving (the `customs` proxy) both call [`scan_archive`], so features cannot drift
//! between the two.
//!
//! Nothing in an archive is ever executed, imported or written to disk: archives are read in
//! memory under the caps in [`ScanOptions`], and code is only lexed.

mod archive;
mod delta;
mod indicators;
mod lexer;
mod manifest;
mod surface;
mod tokens;

use archive::{extension, Contents, Entry};
use indicators::{FileAnalysis, EVIDENCE_RANK, INDICATORS, N_IND};
use lexer::Lang;
use manifest::Meta;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};

pub use delta::{new_lines, DeltaStats};
pub use indicators::INDICATORS as INDICATOR_NAMES;

/// Version of the feature schema emitted by this crate.
pub const FEATURE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Pypi,
    Npm,
}

impl Ecosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Ecosystem::Pypi => "pypi",
            Ecosystem::Npm => "npm",
        }
    }
}

impl std::str::FromStr for Ecosystem {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "pypi" => Ok(Ecosystem::Pypi),
            "npm" => Ok(Ecosystem::Npm),
            other => Err(format!(
                "unknown ecosystem {other:?} (expected pypi or npm)"
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Emit the install-surface token stream used by the neural model.
    pub tokens: bool,
    /// Maximum number of evidence items to keep.
    pub max_evidence: usize,
    /// Upper bound on total uncompressed bytes read from an archive.
    pub max_total_bytes: u64,
    /// Upper bound on the size of a single archive entry. Larger entries are counted but
    /// their content is not analyzed.
    pub max_entry_bytes: u64,
    /// Upper bound on the number of archive entries.
    pub max_entries: usize,
    /// Reject archives whose decompressed size exceeds this multiple of the compressed size
    /// (checked once more than 1 MiB has been decompressed).
    pub max_compression_ratio: f64,
    /// How many levels of archives inside the archive are expanded (0 disables).
    pub max_nesting_depth: u32,
    /// Cap on the token stream length.
    pub max_tokens: usize,
    /// Read every entry in full, not only source and text files (release deltas compare
    /// file contents line by line).
    pub read_all: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            tokens: false,
            max_evidence: 50,
            max_total_bytes: 256 * 1024 * 1024,
            max_entry_bytes: 32 * 1024 * 1024,
            max_entries: 20_000,
            max_compression_ratio: 250.0,
            max_nesting_depth: 1,
            max_tokens: 4096,
            read_all: false,
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

/// Every feature name, in schema order. Indicator counts come first (`inst_` then `all_`,
/// each in [`INDICATOR_NAMES`] order), then structural features, then manifest features.
const FEATURE_NAMES: &[&str] = &[
    "inst_proc_exec",
    "inst_dyn_code",
    "inst_network",
    "inst_decode_obf",
    "inst_env_access",
    "inst_secret_paths",
    "inst_persistence",
    "inst_recon",
    "inst_download_exec",
    "inst_exfil_endpoint",
    "inst_ip_url",
    "inst_url",
    "inst_file_write",
    "inst_crypto_wallet",
    "all_proc_exec",
    "all_dyn_code",
    "all_network",
    "all_decode_obf",
    "all_env_access",
    "all_secret_paths",
    "all_persistence",
    "all_recon",
    "all_download_exec",
    "all_exfil_endpoint",
    "all_ip_url",
    "all_url",
    "all_file_write",
    "all_crypto_wallet",
    "n_files",
    "total_bytes",
    "max_file_bytes",
    "n_py",
    "n_js",
    "n_shell",
    "n_binary",
    "n_hidden",
    "n_minified_js",
    "has_setup_py",
    "has_pyproject",
    "has_package_json",
    "n_npm_install_scripts",
    "inst_n_lines",
    "inst_bytes",
    "all_n_lines",
    "inst_max_line_len",
    "all_max_line_len",
    "inst_max_str_entropy",
    "all_max_str_entropy",
    "inst_mean_str_entropy",
    "inst_longest_b64_run",
    "all_longest_b64_run",
    "inst_hex_escape_count",
    "all_hex_escape_count",
    "inst_obf_ident_ratio",
    "inst_nonascii_ratio",
    "inst_long_line_ratio",
    "inst_hidden_ws_lines",
    "all_hidden_ws_lines",
    "inst_exec_decoded",
    "all_exec_decoded",
    "inst_max_file_kinds",
    "all_max_file_kinds",
    "all_top_file_share",
    "inst_n_files",
    "n_links",
    "n_unsafe_paths",
    "meta_desc_len",
    "meta_has_homepage",
    "meta_has_repo",
    "meta_has_author_email",
    "meta_has_license",
    "meta_n_deps",
    "meta_readme_bytes",
    "meta_version_major",
    "meta_version_is_zero",
    "meta_version_huge",
    "meta_n_keywords",
];

/// Ordered list of every feature name in the schema.
pub fn feature_names() -> Vec<&'static str> {
    FEATURE_NAMES.to_vec()
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

/// Scan an archive file on disk.
pub fn scan_path(
    path: &std::path::Path,
    ecosystem: Option<Ecosystem>,
    opts: &ScanOptions,
) -> Result<ScanReport, ScanError> {
    let bytes = std::fs::read(path)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    scan_archive(&bytes, &name, ecosystem, opts)
}

/// Scan an archive held in memory. Never executes or imports any of its content.
///
/// `ecosystem` overrides detection. Otherwise the archive content decides (a root
/// `package/package.json` means npm; `PKG-INFO`, `setup.py`, `pyproject.toml` or a
/// `.dist-info` directory mean PyPI), falling back to the file name.
pub fn scan_archive(
    bytes: &[u8],
    filename: &str,
    ecosystem: Option<Ecosystem>,
    opts: &ScanOptions,
) -> Result<ScanReport, ScanError> {
    let sha256 = hex(&Sha256::digest(bytes));
    let contents = archive::read_archive(bytes, opts)?;
    let eco = ecosystem
        .or_else(|| detect_ecosystem(&contents))
        .or_else(|| guess_ecosystem(filename))
        .ok_or_else(|| {
            ScanError::UnsupportedFormat(format!(
                "cannot tell whether {filename} is a PyPI or npm package"
            ))
        })?;
    Ok(Scanner::new(&contents, eco, opts).run(filename, sha256))
}

/// A scan of what changed between two releases of one package (see the `delta` module).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeltaScan {
    pub stats: DeltaStats,
    pub report: ScanReport,
}

/// Scan only the part of `cur` that is new relative to `prev` (the previous release).
///
/// Both archives are read under the same caps as [`scan_archive`]. The report describes
/// the delta: new files, the new lines of changed files, and the root manifests.
pub fn scan_delta(
    prev: &[u8],
    cur: &[u8],
    filename: &str,
    ecosystem: Ecosystem,
    opts: &ScanOptions,
) -> Result<DeltaScan, ScanError> {
    let read = ScanOptions {
        read_all: true,
        ..opts.clone()
    };
    let prev_c = archive::read_archive(prev, &read)?;
    let cur_c = archive::read_archive(cur, &read)?;
    let (d, stats) = delta::delta(&prev_c, &cur_c);
    let sha256 = hex(&Sha256::digest(cur));
    let report = Scanner::new(&d, ecosystem, opts).run(filename, sha256);
    Ok(DeltaScan { stats, report })
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn root_entry<'a>(c: &'a Contents, path: &str) -> Option<&'a Entry> {
    c.entries.iter().find(|e| e.depth == 0 && e.path == path)
}

fn detect_ecosystem(c: &Contents) -> Option<Ecosystem> {
    let root_has = |p: &str| root_entry(c, p).is_some();
    let npm_prefix = c
        .stripped_prefix
        .as_deref()
        .is_some_and(|p| p == "package" || p.ends_with("/package"));
    if npm_prefix && root_has("package.json") {
        return Some(Ecosystem::Npm);
    }
    let dist_info = c.entries.iter().any(|e| {
        e.depth == 0
            && e.path
                .split_once('/')
                .is_some_and(|(d, f)| d.ends_with(".dist-info") && f == "METADATA")
    });
    if dist_info
        || ["PKG-INFO", "setup.py", "pyproject.toml", "setup.cfg"]
            .iter()
            .any(|p| root_has(p))
    {
        return Some(Ecosystem::Pypi);
    }
    if root_has("package.json") {
        return Some(Ecosystem::Npm);
    }
    None
}

fn lang_of(path: &str, data: &[u8]) -> Option<Lang> {
    match extension(path).to_ascii_lowercase().as_str() {
        "py" | "pyw" | "pth" => Some(Lang::Python),
        "js" | "mjs" | "cjs" | "ts" | "jsx" | "tsx" => Some(Lang::Js),
        "sh" | "bash" | "bat" | "cmd" | "ps1" => Some(Lang::Shell),
        _ => {
            let head = &data[..data.len().min(128)];
            let first = head.split(|&b| b == b'\n').next().unwrap_or(&[]);
            if !first.starts_with(b"#!") {
                return None;
            }
            let first = String::from_utf8_lossy(first);
            Some(if first.contains("python") {
                Lang::Python
            } else if first.contains("node") {
                Lang::Js
            } else {
                Lang::Shell
            })
        }
    }
}

/// Source file extensions that form the `all_` surface (DESIGN.md section 4.1).
fn is_source(path: &str) -> bool {
    matches!(
        extension(path).to_ascii_lowercase().as_str(),
        "py" | "js" | "mjs" | "cjs" | "ts" | "sh" | "bat" | "ps1" | "cmd"
    )
}

/// A unit of code to analyze: an archive file, an npm script command, or inline code.
struct Unit {
    label: String,
    text: String,
    lang: Lang,
    /// Added to analysis line numbers (npm script commands report their package.json line).
    line_offset: u32,
    inst: bool,
}

struct Scanner<'a> {
    c: &'a Contents,
    eco: Ecosystem,
    opts: &'a ScanOptions,
    /// Root-level (depth 0) path to entry index.
    index: HashMap<&'a str, usize>,
    units: Vec<Unit>,
    /// Entry index to unit index, so each file is analyzed once.
    entry_unit: HashMap<usize, usize>,
    install_surface: Vec<String>,
    errors: Vec<String>,
    n_npm_install_scripts: u32,
}

impl<'a> Scanner<'a> {
    fn new(c: &'a Contents, eco: Ecosystem, opts: &'a ScanOptions) -> Self {
        let mut index = HashMap::new();
        for (i, e) in c.entries.iter().enumerate() {
            if e.depth == 0 {
                index.entry(e.path.as_str()).or_insert(i);
            }
        }
        Self {
            c,
            eco,
            opts,
            index,
            units: Vec::new(),
            entry_unit: HashMap::new(),
            install_surface: Vec::new(),
            errors: Vec::new(),
            n_npm_install_scripts: 0,
        }
    }

    fn text_of(&self, path: &str) -> Option<String> {
        let e = &self.c.entries[*self.index.get(path)?];
        e.full
            .then(|| String::from_utf8_lossy(&e.data).into_owned())
    }

    /// Register an archive file as a unit; returns false when it is missing or unreadable.
    fn add_entry_unit(&mut self, idx: usize, lang_hint: Option<Lang>, inst: bool) -> bool {
        if let Some(&u) = self.entry_unit.get(&idx) {
            if inst && !self.units[u].inst {
                self.units[u].inst = true;
                self.install_surface.push(self.units[u].label.clone());
            }
            return true;
        }
        let e = &self.c.entries[idx];
        if !e.full {
            return false;
        }
        let Some(lang) = lang_hint.or_else(|| lang_of(&e.path, &e.data)) else {
            return false;
        };
        let text = String::from_utf8_lossy(&e.data).into_owned();
        if inst {
            self.install_surface.push(e.path.clone());
        }
        self.entry_unit.insert(idx, self.units.len());
        self.units.push(Unit {
            label: e.path.clone(),
            text,
            lang,
            line_offset: 0,
            inst,
        });
        true
    }

    fn add_inst_path(&mut self, path: &str, lang: Option<Lang>) -> Option<usize> {
        let idx = *self.index.get(path)?;
        self.add_entry_unit(idx, lang, true).then_some(idx)
    }

    fn resolve_node(&mut self, path: &str, lang: Lang) -> Option<usize> {
        let norm = surface::resolve_relative("", path)?;
        // `require('./package.json')` loads data, not code.
        if norm.to_ascii_lowercase().ends_with(".json") {
            return None;
        }
        let cands = if lang == Lang::Js {
            surface::node_candidates(&norm)
        } else {
            vec![norm]
        };
        cands.iter().find_map(|c| self.add_inst_path(c, Some(lang)))
    }

    /// Put a shell command that runs at install on the surface, with inline code it runs
    /// and the package files it points at. Returns the package.json scripts it invokes.
    fn add_install_command(
        &mut self,
        label: &str,
        cmd: &str,
        line: u32,
        script_files: &mut Vec<usize>,
    ) -> Vec<String> {
        self.install_surface.push(label.to_string());
        self.units.push(Unit {
            label: label.to_string(),
            text: cmd.to_string(),
            lang: Lang::Shell,
            line_offset: line.saturating_sub(1),
            inst: true,
        });
        let refs = surface::command_refs(cmd);
        for (code, lang) in refs.inline {
            // `node -e "require('./postinstall')"` runs that file too.
            let required = if lang == Lang::Js {
                indicators::analyze(&code, Lang::Js).relative_imports
            } else {
                Vec::new()
            };
            self.units.push(Unit {
                label: label.to_string(),
                text: code,
                lang,
                line_offset: line.saturating_sub(1),
                inst: true,
            });
            for spec in required {
                if let Some(idx) = self.resolve_node(&spec, Lang::Js) {
                    script_files.push(idx);
                }
            }
        }
        for (path, lang) in refs.files {
            if let Some(idx) = self.resolve_node(&path, lang) {
                script_files.push(idx);
            }
        }
        refs.scripts
    }

    fn npm_surface(&mut self) -> Option<Meta> {
        let pj_text = self.text_of("package.json")?;
        let meta = manifest::parse_package_json(&pj_text);
        if meta.is_none() {
            self.errors.push("package.json is not valid JSON".into());
            return None;
        }
        let pj: serde_json::Value =
            serde_json::from_str(pj_text.trim_start_matches('\u{feff}')).ok()?;
        let scripts = pj.get("scripts").and_then(|s| s.as_object());
        let mut script_files: Vec<usize> = Vec::new();
        // Install hooks first, then scripts they invoke by name (`npm run setup`,
        // `yarn setup`, `bun run setup`), so a hook that delegates to another script does
        // not move that script's code off the install surface.
        let mut queue: Vec<(String, u32)> = surface::NPM_INSTALL_HOOKS
            .iter()
            .map(|h| (h.to_string(), 0))
            .collect();
        queue.reverse();
        let mut visited: HashSet<String> = HashSet::new();
        let mut runs_gyp = false;
        while let Some((name, depth)) = queue.pop() {
            if !visited.insert(name.clone()) || visited.len() > 16 {
                continue;
            }
            let Some(cmd) = scripts
                .and_then(|s| s.get(&name))
                .and_then(|v| v.as_str())
                .filter(|c| !c.trim().is_empty())
            else {
                continue;
            };
            if depth == 0 {
                self.n_npm_install_scripts += 1;
            }
            let label = format!("package.json:scripts.{name}");
            let line = line_of_key(&pj_text, &name);
            if cmd.contains("gyp") {
                runs_gyp = true;
            }
            let scripts_run = self.add_install_command(&label, cmd, line, &mut script_files);
            if depth < 3 {
                for s in scripts_run.into_iter().rev() {
                    queue.push((s, depth + 1));
                }
            }
        }
        // npm runs `node-gyp rebuild` for a package with a root binding.gyp and no install
        // hook of its own (unless `gypfile` is false), and node-gyp runs the commands in the
        // file's `<!(...)` expansions while it configures the build.
        let has_hook = |h: &str| scripts.is_some_and(|s| s.contains_key(h));
        let gypfile = self.index.contains_key("binding.gyp")
            && pj.get("gypfile").and_then(|v| v.as_bool()) != Some(false);
        if gypfile && !has_hook("install") && !has_hook("preinstall") {
            self.n_npm_install_scripts += 1;
            runs_gyp = true;
            self.add_install_command(
                "package.json:scripts.install (implicit, binding.gyp)",
                "node-gyp rebuild",
                0,
                &mut script_files,
            );
        }
        if gypfile && runs_gyp {
            let gyp = self.text_of("binding.gyp").unwrap_or_default();
            for (cmd, line) in surface::gyp_commands(&gyp) {
                self.add_install_command("binding.gyp", &cmd, line, &mut script_files);
            }
        }
        // Follow relative requires from script-referenced files, so moving the payload
        // into a helper module does not move it off the install surface.
        let mut frontier = script_files;
        let mut seen: HashSet<usize> = frontier.iter().copied().collect();
        for _ in 0..2 {
            let mut next = Vec::new();
            for idx in frontier {
                let Some(&u) = self.entry_unit.get(&idx) else {
                    continue;
                };
                if self.units[u].lang != Lang::Js {
                    continue;
                }
                let rel = indicators::analyze(&self.units[u].text, Lang::Js).relative_imports;
                let path = self.c.entries[idx].path.clone();
                let dir = path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
                for spec in rel {
                    if seen.len() >= 32 {
                        break;
                    }
                    let Some(target) = surface::resolve_relative(dir, &spec) else {
                        continue;
                    };
                    if let Some(i) = self.resolve_node(&target, Lang::Js) {
                        if seen.insert(i) {
                            next.push(i);
                        }
                    }
                }
            }
            frontier = next;
        }
        let main = pj
            .get("main")
            .and_then(|m| m.as_str())
            .filter(|m| !m.trim().is_empty())
            .unwrap_or("index.js")
            .to_string();
        self.resolve_node(&main, Lang::Js);
        meta
    }

    fn pypi_surface(&mut self) -> Meta {
        let mut meta = Meta::default();
        if let Some(t) = self.text_of("PKG-INFO") {
            meta.merge(manifest::parse_core_metadata(&t));
        }
        let wheel_meta = self
            .c
            .entries
            .iter()
            .find(|e| {
                e.depth == 0
                    && e.path
                        .split_once('/')
                        .is_some_and(|(d, f)| d.ends_with(".dist-info") && f == "METADATA")
            })
            .map(|e| e.path.clone());
        if let Some(t) = wheel_meta.and_then(|p| self.text_of(&p)) {
            meta.merge(manifest::parse_core_metadata(&t));
        }
        let pyproject = self.text_of("pyproject.toml");
        if let Some(t) = &pyproject {
            match manifest::parse_pyproject(t) {
                Some(m) => meta.merge(m),
                None => self.errors.push("pyproject.toml is not valid TOML".into()),
            }
        }
        let setup_cfg = self.text_of("setup.cfg");
        if let Some(t) = &setup_cfg {
            meta.merge(manifest::parse_setup_cfg(t));
        }
        if let Some(t) = self.text_of("setup.py") {
            meta.merge(manifest::parse_setup_py(&t));
        }

        self.add_inst_path("setup.py", Some(Lang::Python));
        if let Some(t) = &setup_cfg {
            for f in surface::setup_cfg_cmdclass_files(t) {
                self.add_inst_path(&f, Some(Lang::Python));
            }
        }
        if let Some(t) = &pyproject {
            for f in surface::in_tree_backend_files(t) {
                self.add_inst_path(&f, Some(Lang::Python));
            }
        }
        let mut inits: Vec<&str> = self
            .index
            .keys()
            .copied()
            .filter(|p| {
                let parts: Vec<&str> = p.split('/').collect();
                matches!(
                    parts.as_slice(),
                    [_, "__init__.py"] | ["src", _, "__init__.py"]
                )
            })
            .collect();
        // Namespace packages (PEP 420) have no `__init__.py` of their own; importing one
        // runs its subpackages' `__init__.py` instead (`mistralai.client`).
        const NOT_PACKAGES: &[&str] = &[
            "tests",
            "test",
            "docs",
            "doc",
            "examples",
            "example",
            "sources",
            "scripts",
            "benchmarks",
        ];
        const MAX_NAMESPACE_INITS: usize = 8;
        let mut ns_inits: Vec<&str> = self
            .index
            .keys()
            .copied()
            .filter(|p| {
                let parts: Vec<&str> = p.split('/').collect();
                let (ns, sub) = match parts.as_slice() {
                    [ns, sub, "__init__.py"] => (format!("{ns}/"), *sub),
                    ["src", ns, sub, "__init__.py"] => (format!("src/{ns}/"), *sub),
                    _ => return false,
                };
                let name = ns.trim_end_matches('/').rsplit('/').next().unwrap_or("");
                !NOT_PACKAGES.contains(&name)
                    && !NOT_PACKAGES.contains(&sub)
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                    && !self.index.contains_key(format!("{ns}__init__.py").as_str())
            })
            .collect();
        ns_inits.sort_unstable();
        ns_inits.truncate(MAX_NAMESPACE_INITS);
        inits.extend(ns_inits);
        inits.sort_unstable();
        let mut pths: Vec<&str> = self
            .index
            .keys()
            .copied()
            .filter(|p| p.to_ascii_lowercase().ends_with(".pth"))
            .collect();
        pths.sort_unstable();
        let inits: Vec<String> = inits.into_iter().map(str::to_string).collect();
        let pths: Vec<String> = pths.into_iter().map(str::to_string).collect();
        for p in inits.iter().chain(&pths) {
            self.add_inst_path(p, Some(Lang::Python));
        }
        self.follow_python_imports();
        meta
    }

    /// Put the package's own modules imported (transitively) by setup-time Python files
    /// (`setup.py`, cmdclass and in-tree build backend modules) on the install surface
    /// too, so a payload moved out of `setup.py` into a helper module stays on it.
    /// An `__init__.py` reached this way joins the surface, but its own imports are not
    /// followed: in a benign package they lead into the whole library, and measured on
    /// the corpus that dilutes the install surface more than it uncovers payloads.
    fn follow_python_imports(&mut self) {
        const MAX_HOPS: usize = 3;
        const MAX_FILES: usize = 48;
        let mut frontier: Vec<usize> = self
            .entry_unit
            .iter()
            .filter(|(_, &u)| self.units[u].inst && self.units[u].lang == Lang::Python)
            .map(|(&idx, _)| idx)
            .filter(|&idx| self.follows_imports(idx))
            .collect();
        frontier.sort_unstable();
        let mut seen: HashSet<usize> = frontier.iter().copied().collect();
        for _ in 0..MAX_HOPS {
            let mut next = Vec::new();
            for idx in frontier {
                let Some(&u) = self.entry_unit.get(&idx) else {
                    continue;
                };
                let path = self.c.entries[idx].path.clone();
                let dir = path
                    .rsplit_once('/')
                    .map(|(d, _)| d)
                    .unwrap_or("")
                    .to_string();
                for imp in indicators::python_imports(&self.units[u].text) {
                    for cand in self.python_module_files(&dir, &imp) {
                        if seen.len() >= MAX_FILES {
                            break;
                        }
                        if let Some(i) = self.add_inst_path(&cand, Some(Lang::Python)) {
                            if seen.insert(i) && self.follows_imports(i) {
                                next.push(i);
                            }
                        }
                    }
                }
            }
            frontier = next;
        }
    }

    fn follows_imports(&self, idx: usize) -> bool {
        let p = self.c.entries[idx].path.to_ascii_lowercase();
        !(p == "__init__.py" || p.ends_with("/__init__.py") || p.ends_with(".pth"))
    }

    /// Files in this archive that an import loads: the module itself, the `__init__.py` of
    /// each enclosing package, and imported names that are submodules. Absolute imports
    /// resolve only to top-level packages shipped in the archive (at the root or in `src/`).
    fn python_module_files(&self, dir: &str, imp: &indicators::PyImport) -> Vec<String> {
        let mut base: Vec<String> = if imp.level > 0 {
            let mut parts: Vec<String> = dir
                .split('/')
                .filter(|p| !p.is_empty())
                .map(str::to_string)
                .collect();
            for _ in 1..imp.level {
                if parts.pop().is_none() {
                    return Vec::new();
                }
            }
            parts
        } else {
            let Some(top) = imp.module.split('.').next().filter(|t| !t.is_empty()) else {
                return Vec::new();
            };
            let shipped = |root: &str| {
                self.index
                    .contains_key(format!("{root}{top}/__init__.py").as_str())
                    || self.index.contains_key(format!("{root}{top}.py").as_str())
            };
            if shipped("") {
                Vec::new()
            } else if shipped("src/") {
                vec!["src".to_string()]
            } else {
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for part in imp.module.split('.').filter(|p| !p.is_empty()) {
            base.push(part.to_string());
            out.push(format!("{}/__init__.py", base.join("/")));
        }
        if !base.is_empty() {
            out.push(format!("{}.py", base.join("/")));
        }
        for name in &imp.names {
            let mut sub = base.clone();
            sub.push(name.clone());
            let sub = sub.join("/");
            out.push(format!("{sub}.py"));
            out.push(format!("{sub}/__init__.py"));
        }
        out
    }

    fn run(mut self, filename: &str, sha256: String) -> ScanReport {
        let meta = match self.eco {
            Ecosystem::Npm => self.npm_surface().unwrap_or_default(),
            Ecosystem::Pypi => self.pypi_surface(),
        };
        // The all_ surface: every source file, plus whatever is already on the inst surface.
        for i in 0..self.c.entries.len() {
            if is_source(&self.c.entries[i].path) {
                self.add_entry_unit(i, None, false);
            }
        }
        let analyses: Vec<FileAnalysis> = self
            .units
            .iter()
            .map(|u| indicators::analyze(&u.text, u.lang))
            .collect();

        let mut features: BTreeMap<String, f64> =
            FEATURE_NAMES.iter().map(|n| (n.to_string(), 0.0)).collect();
        let mut set = |k: &str, v: f64| {
            debug_assert!(features.contains_key(k), "unknown feature {k}");
            features.insert(k.to_string(), v);
        };

        let inst = Agg::over(
            self.units
                .iter()
                .zip(&analyses)
                .filter(|(u, _)| u.inst)
                .map(|(_, a)| a),
        );
        let all = Agg::over(analyses.iter());
        for (k, name) in INDICATORS.iter().enumerate() {
            set(&format!("inst_{name}"), inst.counts[k] as f64);
            set(&format!("all_{name}"), all.counts[k] as f64);
        }
        set("inst_n_lines", inst.n_lines as f64);
        set("inst_bytes", inst.bytes as f64);
        set("all_n_lines", all.n_lines as f64);
        set("inst_max_line_len", inst.max_line_len as f64);
        set("all_max_line_len", all.max_line_len as f64);
        set("inst_max_str_entropy", inst.max_entropy);
        set("all_max_str_entropy", all.max_entropy);
        set(
            "inst_mean_str_entropy",
            ratio(inst.entropy_sum, inst.n_entropy as f64),
        );
        set("inst_longest_b64_run", inst.b64 as f64);
        set("all_longest_b64_run", all.b64 as f64);
        set("inst_hex_escape_count", inst.hex as f64);
        set("all_hex_escape_count", all.hex as f64);
        set(
            "inst_obf_ident_ratio",
            ratio(inst.obf as f64, inst.idents as f64),
        );
        set(
            "inst_nonascii_ratio",
            ratio(inst.nonascii as f64, inst.chars as f64),
        );
        set(
            "inst_long_line_ratio",
            ratio(inst.long_lines as f64, inst.n_lines as f64),
        );
        set("inst_hidden_ws_lines", inst.hidden_ws as f64);
        set("all_hidden_ws_lines", all.hidden_ws as f64);
        set("inst_exec_decoded", inst.exec_decoded as f64);
        set("all_exec_decoded", all.exec_decoded as f64);
        set("inst_max_file_kinds", inst.max_file_kinds as f64);
        set("all_max_file_kinds", all.max_file_kinds as f64);
        set(
            "all_top_file_share",
            ratio(all.top_file_hits as f64, all.behavior_hits as f64),
        );
        set(
            "inst_n_files",
            self.units.iter().filter(|u| u.inst).count() as f64,
        );

        let s = structural(self.c);
        for (k, v) in s {
            set(k, v);
        }
        set("n_npm_install_scripts", self.n_npm_install_scripts as f64);
        set("n_links", self.c.n_links as f64);
        set("n_unsafe_paths", self.c.n_unsafe_paths as f64);

        let (fname, fver) = manifest::name_version_from_filename(filename);
        let name = meta.name.clone().filter(|n| !n.trim().is_empty()).or(fname);
        let version = meta
            .version
            .clone()
            .filter(|v| !v.trim().is_empty())
            .or(fver);
        set(
            "meta_desc_len",
            meta.description
                .as_deref()
                .map(|d| d.chars().count())
                .unwrap_or(0) as f64,
        );
        set("meta_has_homepage", flag(meta.homepage));
        set("meta_has_repo", flag(meta.repo));
        set("meta_has_author_email", flag(meta.author_email));
        set("meta_has_license", flag(meta.license));
        set("meta_n_deps", meta.n_deps.unwrap_or(0) as f64);
        set("meta_n_keywords", meta.n_keywords.unwrap_or(0) as f64);
        let readme = self
            .c
            .entries
            .iter()
            .find(|e| {
                e.depth == 0
                    && !e.path.contains('/')
                    && e.path.to_ascii_lowercase().starts_with("readme")
            })
            .map(|e| e.size)
            .or(meta.long_description_bytes)
            .unwrap_or(0);
        set("meta_readme_bytes", readme as f64);
        // Version features come from the manifest only. The file name is not part of the
        // package content (training archives are stored under content hashes, the proxy
        // sees registry file names), so a feature derived from it would differ between
        // training and serving for the same package.
        if let Some(v) = meta.version.as_deref().filter(|v| !v.trim().is_empty()) {
            let (major, minor) = manifest::version_parts(v);
            set("meta_version_major", major.unwrap_or(0) as f64);
            set(
                "meta_version_is_zero",
                flag(Some(major == Some(0) && minor == Some(0))),
            );
            set(
                "meta_version_huge",
                flag(Some(major.is_some_and(|m| m >= 90))),
            );
        }

        let evidence = self.select_evidence(&analyses);
        let tokens = self.opts.tokens.then(|| {
            let mut out = Vec::new();
            for u in self.units.iter().filter(|u| u.inst) {
                tokens::push_unit_tokens(&mut out, &u.text, u.lang, self.opts.max_tokens);
            }
            out
        });

        let mut errors = self.c.errors.clone();
        errors.append(&mut self.errors);
        const MAX_ERRORS: usize = 100;
        if errors.len() > MAX_ERRORS {
            let extra = errors.len() - MAX_ERRORS;
            errors.truncate(MAX_ERRORS);
            errors.push(format!("... and {extra} more"));
        }

        ScanReport {
            schema_version: FEATURE_SCHEMA_VERSION,
            ecosystem: self.eco,
            archive: filename.to_string(),
            sha256,
            name,
            version,
            features,
            evidence,
            install_surface: self.install_surface,
            tokens,
            errors,
        }
    }

    /// Install-surface hits first; within a tier, take one hit per indicator in turn (most
    /// telling first) so a hundred plain URLs cannot crowd out one `eval`.
    fn select_evidence(&self, analyses: &[FileAnalysis]) -> Vec<Evidence> {
        let mut out = Vec::new();
        let mut seen = HashSet::new();
        for tier_inst in [true, false] {
            let mut queues: Vec<Vec<(usize, u32)>> = vec![Vec::new(); N_IND];
            for (ui, (u, a)) in self.units.iter().zip(analyses).enumerate() {
                if u.inst != tier_inst {
                    continue;
                }
                for &(ind, line) in &a.hits {
                    queues[ind].push((ui, line));
                }
            }
            let mut cursors = [0usize; N_IND];
            loop {
                let mut progressed = false;
                for &ind in EVIDENCE_RANK.iter() {
                    if out.len() >= self.opts.max_evidence {
                        return out;
                    }
                    let q = &queues[ind];
                    while cursors[ind] < q.len() {
                        let (ui, line) = q[cursors[ind]];
                        cursors[ind] += 1;
                        let u = &self.units[ui];
                        let reported = line + u.line_offset;
                        if seen.insert((ind, u.label.clone(), reported)) {
                            out.push(Evidence {
                                indicator: INDICATORS[ind].to_string(),
                                file: u.label.clone(),
                                line: reported,
                                snippet: snippet(&u.text, line),
                            });
                            progressed = true;
                            break;
                        }
                    }
                }
                if !progressed {
                    break;
                }
            }
        }
        out
    }
}

fn flag(b: Option<bool>) -> f64 {
    if b == Some(true) {
        1.0
    } else {
        0.0
    }
}

fn ratio(a: f64, b: f64) -> f64 {
    if b > 0.0 {
        a / b
    } else {
        0.0
    }
}

const SNIPPET_CHARS: usize = 160;

/// The evidence line, trimmed and cut to `SNIPPET_CHARS`. Code hidden after a long
/// whitespace run is pulled into view with a marker, so the snippet shows what the run hid.
fn snippet(text: &str, line: u32) -> String {
    let l = text
        .lines()
        .nth(line.saturating_sub(1) as usize)
        .unwrap_or("")
        .trim();
    let shown = match indicators::hidden_ws_offset(l) {
        Some(at) => {
            let head = l[..at].trim_end();
            let hidden = at - head.len();
            format!("{head} [{hidden} blank columns] {}", &l[at..])
        }
        None => l.to_string(),
    };
    shown.chars().take(SNIPPET_CHARS).collect()
}

/// 1-based line of the first `"key"` in a JSON document (1 when absent).
fn line_of_key(json: &str, key: &str) -> u32 {
    let needle = format!("\"{key}\"");
    json.find(&needle)
        .map(|p| json[..p].bytes().filter(|&b| b == b'\n').count() as u32 + 1)
        .unwrap_or(1)
}

#[derive(Default)]
struct Agg {
    counts: [u64; N_IND],
    n_lines: u64,
    bytes: u64,
    max_line_len: u64,
    long_lines: u64,
    chars: u64,
    nonascii: u64,
    max_entropy: f64,
    entropy_sum: f64,
    n_entropy: u64,
    b64: u64,
    hex: u64,
    idents: u64,
    obf: u64,
    hidden_ws: u64,
    exec_decoded: u64,
    /// Most distinct behavior kinds (`BEHAVIOR`) seen together in one file.
    max_file_kinds: u64,
    /// Behavior hits in the file that has the most of them.
    top_file_hits: u64,
    behavior_hits: u64,
}

/// Indicators that describe what code does. `url` and `file_write` are left out: nearly
/// every library has them, so they say little about where a payload sits.
const BEHAVIOR: [usize; 12] = [
    indicators::PROC_EXEC,
    indicators::DYN_CODE,
    indicators::NETWORK,
    indicators::DECODE_OBF,
    indicators::ENV_ACCESS,
    indicators::SECRET_PATHS,
    indicators::PERSISTENCE,
    indicators::RECON,
    indicators::DOWNLOAD_EXEC,
    indicators::EXFIL_ENDPOINT,
    indicators::IP_URL,
    indicators::CRYPTO_WALLET,
];

impl Agg {
    fn over<'x>(it: impl Iterator<Item = &'x FileAnalysis>) -> Self {
        let mut g = Agg::default();
        for a in it {
            for k in 0..N_IND {
                g.counts[k] += a.counts[k] as u64;
            }
            g.n_lines += a.n_lines;
            g.bytes += a.bytes;
            g.max_line_len = g.max_line_len.max(a.max_line_len);
            g.long_lines += a.long_lines;
            g.chars += a.chars;
            g.nonascii += a.nonascii_chars;
            g.max_entropy = g.max_entropy.max(a.max_str_entropy);
            g.entropy_sum += a.str_entropy_sum;
            g.n_entropy += a.n_entropy_strs;
            g.b64 = g.b64.max(a.longest_b64_run);
            g.hex += a.hex_escapes;
            g.idents += a.n_idents;
            g.obf += a.n_obf_idents;
            g.hidden_ws += a.hidden_ws_lines;
            g.exec_decoded += a.exec_decoded_lines;
            let kinds = BEHAVIOR.iter().filter(|&&k| a.counts[k] > 0).count() as u64;
            let hits: u64 = BEHAVIOR.iter().map(|&k| a.counts[k] as u64).sum();
            g.max_file_kinds = g.max_file_kinds.max(kinds);
            g.top_file_hits = g.top_file_hits.max(hits);
            g.behavior_hits += hits;
        }
        g
    }
}

fn is_binary_magic(d: &[u8]) -> bool {
    d.starts_with(b"\x7fELF")
        || d.starts_with(b"MZ")
        || [
            [0xfe, 0xed, 0xfa, 0xce],
            [0xfe, 0xed, 0xfa, 0xcf],
            [0xce, 0xfa, 0xed, 0xfe],
            [0xcf, 0xfa, 0xed, 0xfe],
            [0xca, 0xfe, 0xba, 0xbe],
        ]
        .iter()
        .any(|m| d.starts_with(m))
}

fn structural(c: &Contents) -> Vec<(&'static str, f64)> {
    let mut n_py = 0u64;
    let mut n_js = 0u64;
    let mut n_shell = 0u64;
    let mut n_binary = 0u64;
    let mut n_hidden = 0u64;
    let mut n_min = 0u64;
    let mut total = 0u64;
    let mut max = 0u64;
    for e in &c.entries {
        total += e.size;
        max = max.max(e.size);
        let ext = extension(&e.path).to_ascii_lowercase();
        match ext.as_str() {
            "py" => n_py += 1,
            "js" | "mjs" | "cjs" | "ts" => n_js += 1,
            "sh" | "bat" | "ps1" | "cmd" => n_shell += 1,
            _ => {}
        }
        if matches!(ext.as_str(), "js" | "mjs" | "cjs") && e.full && !e.data.is_empty() {
            let lines = e.data.iter().filter(|&&b| b == b'\n').count() as u64 + 1;
            if e.data.len() as u64 / lines > 500 {
                n_min += 1;
            }
        }
        if is_binary_magic(&e.data) {
            n_binary += 1;
        }
        let inner = e.path.rsplit("!/").next().unwrap_or(&e.path);
        if inner.split('/').any(|p| p.starts_with('.')) {
            n_hidden += 1;
        }
    }
    let root_has = |p: &str| flag(Some(root_entry(c, p).is_some()));
    vec![
        ("n_files", c.entries.len() as f64),
        ("total_bytes", total as f64),
        ("max_file_bytes", max as f64),
        ("n_py", n_py as f64),
        ("n_js", n_js as f64),
        ("n_shell", n_shell as f64),
        ("n_binary", n_binary as f64),
        ("n_hidden", n_hidden as f64),
        ("n_minified_js", n_min as f64),
        ("has_setup_py", root_has("setup.py")),
        ("has_pyproject", root_has("pyproject.toml")),
        ("has_package_json", root_has("package.json")),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_names_cover_every_indicator_and_are_unique() {
        let names = feature_names();
        let set: HashSet<_> = names.iter().collect();
        assert_eq!(set.len(), names.len(), "duplicate feature names");
        for ind in INDICATORS {
            assert!(set.contains(&format!("inst_{ind}").as_str()));
            assert!(set.contains(&format!("all_{ind}").as_str()));
        }
        for (i, ind) in INDICATORS.iter().enumerate() {
            assert_eq!(names[i], format!("inst_{ind}"));
            assert_eq!(names[N_IND + i], format!("all_{ind}"));
        }
    }

    #[test]
    fn snippet_truncates() {
        let long = "x".repeat(500);
        assert_eq!(snippet(&format!("a\n  {long}  \n"), 2).chars().count(), 160);
        assert_eq!(snippet("a\nb", 9), "");
        let hidden = format!("import os{};exec(x)", " ".repeat(250));
        assert_eq!(
            snippet(&hidden, 1),
            "import os [250 blank columns] ;exec(x)"
        );
    }

    #[test]
    fn json_key_line() {
        assert_eq!(
            line_of_key(
                "{\n  \"scripts\": {\n    \"postinstall\": \"x\"\n}}",
                "postinstall"
            ),
            3
        );
    }

    #[test]
    fn ecosystem_parse() {
        assert_eq!("NPM".parse::<Ecosystem>(), Ok(Ecosystem::Npm));
        assert!("cargo".parse::<Ecosystem>().is_err());
    }
}
