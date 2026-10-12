//! `customs doctor` (DESIGN.md section 7): the ways installs in a project would reach a
//! registry without passing through the proxy. The rules come from real installs through
//! `customs serve` with a denied package:
//!
//! - The registry variables `customs env` prints beat `.npmrc`, `bunfig.toml` and pip
//!   config files, so a plain `registry=` line there is harmless once they are set.
//! - Scoped registries (`@scope:registry=` in `.npmrc`, `[install.scopes]` in
//!   `bunfig.toml`, `npmScopes` in `.yarnrc.yml`) are fetched directly by pnpm, Bun and
//!   Yarn 2+. npm still sends the tarballs through the proxy.
//! - Lockfile URLs: npm redirects only `registry.npmjs.org` URLs to the configured registry.
//!   pnpm, Bun and Deno download any URL their lockfile records as written, and Yarn 1
//!   downloads every `resolved` URL in `yarn.lock` as written, so a classic `yarn.lock`
//!   never reaches the proxy. `uv sync --frozen` downloads the file URLs in `uv.lock`;
//!   plain `uv sync` resolves again through the proxy and `--locked` refuses to run.
//! - Extra indexes and find-links (pip, uv) are other hosts by definition, and Poetry has
//!   no environment variable for its index at all.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};

use crate::cli::env_vars;
use crate::util::{redact_url, redact_urls};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Ok,
    /// Needs attention, but nothing skips the proxy because of it.
    Warn,
    /// Some installs reach a registry without the proxy.
    Bypass,
}

impl Level {
    fn label(self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::Warn => "WARN",
            Level::Bypass => "BYPASS",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub level: Level,
    /// What was inspected: `environment`, a file name.
    pub subject: String,
    pub detail: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub fix: String,
}

/// A finding; URLs in it lose their credentials and query (index URLs often carry a
/// token), since doctor output lands in terminals, CI logs and JSON reports.
fn finding(level: Level, subject: &str, detail: String, fix: &str) -> Finding {
    Finding {
        level,
        subject: subject.to_string(),
        detail: redact_urls(&detail),
        fix: redact_urls(fix),
    }
}

/// The proxy's `host:port`, to tell its URLs from everyone else's.
fn authority(url: &str) -> Option<String> {
    let u = url::Url::parse(url).ok()?;
    Some(format!(
        "{}:{}",
        u.host_str()?.to_ascii_lowercase(),
        u.port_or_known_default()?
    ))
}

fn host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_else(|| url.to_string())
}

/// Everything `doctor` reads besides the server: the project directory, the home
/// directory for user-level config, and the environment.
pub struct Inputs<'a> {
    pub dir: &'a Path,
    pub home: Option<&'a Path>,
    pub server: &'a str,
    pub env: &'a dyn Fn(&str) -> Option<String>,
    /// Machine-wide pip configuration files ([`system_pip_configs`] outside tests).
    pub system_pip_configs: &'a [PathBuf],
}

/// pip's machine-wide configuration files on this platform.
pub fn system_pip_configs(env: &dyn Fn(&str) -> Option<String>) -> Vec<PathBuf> {
    if cfg!(windows) {
        env("PROGRAMDATA")
            .map(|p| vec![Path::new(&p).join("pip").join("pip.ini")])
            .unwrap_or_default()
    } else {
        vec!["/etc/pip.conf".into(), "/etc/xdg/pip/pip.conf".into()]
    }
}

/// Every finding about `inputs`, most severe first.
pub fn inspect(inputs: &Inputs) -> Vec<Finding> {
    let mut out = Vec::new();
    environment(inputs, &mut out);
    let proxy = authority(inputs.server).unwrap_or_default();
    let mut config_dirs = vec![inputs.dir.to_path_buf()];
    config_dirs.extend(inputs.home.map(Path::to_path_buf));
    for d in &config_dirs {
        npmrc(&d.join(".npmrc"), &proxy, &mut out);
        bunfig(&d.join("bunfig.toml"), &proxy, &mut out);
        yarnrc(&d.join(".yarnrc.yml"), &proxy, &mut out);
    }
    if let Some(h) = inputs.home {
        bunfig(&h.join(".bunfig.toml"), &proxy, &mut out);
    }
    for f in pip_config_files(inputs) {
        pip_config(&f, &mut out);
    }
    python_project(inputs.dir, &mut out);
    lockfiles(inputs.dir, &proxy, &mut out);
    claude_hook(inputs, &mut out);
    other_agent_hooks(inputs, &mut out);
    codex_hooks(inputs, &mut out);
    mcp_servers(inputs, &mut out);
    out.sort_by_key(|f| std::cmp::Reverse(f.level));
    out
}

/// Where the Customs hook is registered in Claude Code settings, and whether its matcher
/// lets it see file edits (section 9.2). Says nothing when it is not registered at all:
/// not every project uses Claude Code.
fn claude_hook(inputs: &Inputs, out: &mut Vec<Finding>) {
    let mut files = vec![
        inputs.dir.join(".claude/settings.json"),
        inputs.dir.join(".claude/settings.local.json"),
    ];
    files.extend(inputs.home.map(|h| h.join(".claude/settings.json")));
    for f in files {
        let Some(v) = std::fs::read_to_string(&f)
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
        else {
            continue;
        };
        let entries = v["hooks"]["PreToolUse"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let matchers: Vec<String> = entries
            .iter()
            .filter(|e| {
                e["hooks"].as_array().is_some_and(|hs| {
                    hs.iter().any(|h| {
                        h["command"]
                            .as_str()
                            .is_some_and(|c| c.contains("customs hook claude-code"))
                    })
                })
            })
            .map(|e| e["matcher"].as_str().unwrap_or("").to_string())
            .collect();
        if matchers.is_empty() {
            continue;
        }
        let subject = f.display().to_string();
        let sees = |tool: &str| matchers.iter().any(|m| matcher_covers(m, tool));
        if !sees("Bash") {
            out.push(finding(
                Level::Warn,
                &subject,
                "the Customs hook is registered, but its matcher does not include Bash, so it checks no install".into(),
                "set the matcher to Bash|Edit|Write|MultiEdit|NotebookEdit (deploy/hooks/claude-code-settings.json)",
            ));
        } else if !(sees("Edit") && sees("Write")) {
            out.push(finding(
                Level::Warn,
                &subject,
                "the Customs hook sees only shell commands: an Edit or Write call can remove it from these settings or repoint .npmrc without confirmation".into(),
                "set the matcher to Bash|Edit|Write|MultiEdit|NotebookEdit (deploy/hooks/claude-code-settings.json)",
            ));
        } else {
            out.push(finding(
                Level::Ok,
                &subject,
                "the Customs hook checks shell commands and file edits".into(),
                "",
            ));
        }
    }
}

/// Matchers of the hook entries under `event` whose command runs `customs hook <agent>`.
fn customs_matchers(v: &Value, event: &str, agent: &str, nested: bool) -> Vec<String> {
    let needle = format!("customs hook {agent}");
    v["hooks"][event]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| {
            let runs = |h: &Value| h["command"].as_str().is_some_and(|c| c.contains(&needle));
            if nested {
                e["hooks"].as_array().is_some_and(|hs| hs.iter().any(runs))
            } else {
                runs(e)
            }
        })
        .map(|e| e["matcher"].as_str().unwrap_or("").to_string())
        .collect()
}

/// Whether a Codex hook matcher selects `tool` (or one of its aliases): empty or `*` is
/// every tool, a `|`-list of plain names is exact, anything else an unanchored regex.
fn codex_matches(matcher: &str, tool: &str, aliases: &[&str]) -> bool {
    let m = matcher.trim();
    if m.is_empty() || m == "*" {
        return true;
    }
    let names = std::iter::once(tool).chain(aliases.iter().copied());
    if m.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '|')
    {
        let alts: Vec<&str> = m.split('|').collect();
        return names.into_iter().any(|n| alts.contains(&n));
    }
    regex::Regex::new(m).is_ok_and(|r| names.into_iter().any(|n| r.is_match(n)))
}

/// Codex registrations: `hooks.json` and the `[hooks]` table of `config.toml`, in the
/// project's and the user's `.codex` folder.
fn codex_hooks(inputs: &Inputs, out: &mut Vec<Finding>) {
    let mut dirs = vec![inputs.dir.join(".codex")];
    dirs.extend(inputs.home.map(|h| h.join(".codex")));
    for dir in dirs {
        for f in [dir.join("hooks.json"), dir.join("config.toml")] {
            let Ok(text) = std::fs::read_to_string(&f) else {
                continue;
            };
            let v: Option<Value> = if f.extension().is_some_and(|e| e == "toml") {
                toml::from_str::<toml::Value>(&text)
                    .ok()
                    .and_then(|t| serde_json::to_value(t).ok())
            } else {
                serde_json::from_str(&text).ok()
            };
            let Some(v) = v else { continue };
            let matchers = customs_matchers(&v, "PreToolUse", "codex", true);
            if matchers.is_empty() {
                continue;
            }
            let sees = |tool: &str, aliases: &[&str]| {
                matchers.iter().any(|m| codex_matches(m, tool, aliases))
            };
            let fix = "set the matcher to Bash|apply_patch (deploy/hooks/codex-hooks.json)";
            let subject = f.display().to_string();
            if !sees("Bash", &[]) {
                out.push(finding(
                    Level::Warn,
                    &subject,
                    "the Customs hook is registered, but its matcher does not include Bash, so it checks no install".into(),
                    fix,
                ));
            } else if !sees("apply_patch", &["Write", "Edit"]) {
                out.push(finding(
                    Level::Warn,
                    &subject,
                    "the Customs hook sees only shell commands: an apply_patch edit can remove it from these settings or repoint .npmrc without confirmation".into(),
                    fix,
                ));
            } else {
                out.push(finding(
                    Level::Ok,
                    &subject,
                    "the Customs hook checks shell commands and file edits (if Codex lists it as untrusted, trust it in /hooks)".into(),
                    "",
                ));
            }
        }
    }
}

/// MCP servers that agents start without a pinned version: each start runs the newest
/// release, outside the hook and often outside the proxy (DESIGN.md section 11).
fn mcp_servers(inputs: &Inputs, out: &mut Vec<Finding>) {
    use crate::audit::mcp;
    let mut files: Vec<PathBuf> = mcp::PROJECT_CONFIGS
        .iter()
        .map(|r| inputs.dir.join(r))
        .collect();
    if let Some(h) = inputs.home {
        files.extend(
            [
                ".claude.json",
                ".cursor/mcp.json",
                ".gemini/settings.json",
                ".codex/config.toml",
                ".codeium/windsurf/mcp_config.json",
            ]
            .iter()
            .map(|r| h.join(r)),
        );
    }
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        let mut parsed = crate::audit::Parsed::default();
        if mcp::parse(&text, &f, &mut parsed).is_err() || parsed.deps.is_empty() {
            continue;
        }
        let subject = f.display().to_string();
        let loose: Vec<String> = parsed
            .deps
            .iter()
            .filter(|d| !d.pinned)
            .map(|d| format!("{} ({}, line {})", d.name, d.version, d.line))
            .collect();
        if loose.is_empty() {
            out.push(finding(
                Level::Ok,
                &subject,
                format!(
                    "{} MCP server package{} pinned to exact versions",
                    parsed.deps.len(),
                    if parsed.deps.len() == 1 { "" } else { "s" }
                ),
                "",
            ));
        } else {
            out.push(finding(
                Level::Warn,
                &subject,
                format!(
                    "MCP servers start without a pinned version, so each start runs the newest release: {}",
                    loose.join(", ")
                ),
                "pin each package to an exact version (name@1.2.3, name==1.2.3), and check the configuration with customs audit",
            ));
        }
    }
}

/// Cursor (`.cursor/hooks.json`) and Gemini CLI (`.gemini/settings.json`) registrations.
fn other_agent_hooks(inputs: &Inputs, out: &mut Vec<Finding>) {
    let read = |f: &Path| {
        std::fs::read_to_string(f)
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
    };
    let mut cursor = vec![inputs.dir.join(".cursor/hooks.json")];
    cursor.extend(inputs.home.map(|h| h.join(".cursor/hooks.json")));
    for f in cursor {
        let Some(v) = read(&f) else { continue };
        let matchers = customs_matchers(&v, "beforeShellExecution", "cursor", false);
        if matchers.is_empty() {
            continue;
        }
        // Cursor's matcher filters commands, so any matcher can let an install through.
        let (level, detail, fix) = if matchers.iter().any(|m| m.is_empty()) {
            (
                Level::Ok,
                "the Customs hook checks every shell command".to_string(),
                "",
            )
        } else {
            (
                Level::Warn,
                format!(
                    "the Customs hook runs only for commands matching {}, so other installs go unchecked",
                    matchers.join(" or ")
                ),
                "remove the matcher (deploy/hooks/cursor-hooks.json)",
            )
        };
        out.push(finding(level, &f.display().to_string(), detail, fix));
    }
    let mut gemini = vec![inputs.dir.join(".gemini/settings.json")];
    gemini.extend(inputs.home.map(|h| h.join(".gemini/settings.json")));
    for f in gemini {
        let Some(v) = read(&f) else { continue };
        let matchers = customs_matchers(&v, "BeforeTool", "gemini", true);
        if matchers.is_empty() {
            continue;
        }
        // Gemini CLI tests the matcher as an unanchored regex.
        let sees = |tool: &str| {
            matchers.iter().any(|m| {
                let m = m.trim();
                m.is_empty()
                    || m == "*"
                    || regex::Regex::new(m).map_or(m == tool, |r| r.is_match(tool))
            })
        };
        let fix =
            "set the matcher to run_shell_command|write_file|replace (deploy/hooks/gemini-settings.json)";
        let subject = f.display().to_string();
        if !sees("run_shell_command") {
            out.push(finding(
                Level::Warn,
                &subject,
                "the Customs hook is registered, but its matcher does not include run_shell_command, so it checks no install".into(),
                fix,
            ));
        } else if !(sees("write_file") && sees("replace")) {
            out.push(finding(
                Level::Warn,
                &subject,
                "the Customs hook sees only shell commands: a write_file or replace call can remove it from these settings or repoint .npmrc without confirmation".into(),
                fix,
            ));
        } else {
            out.push(finding(
                Level::Ok,
                &subject,
                "the Customs hook checks shell commands and file edits".into(),
                "",
            ));
        }
    }
}

/// Whether a tool-name matcher (a regex over the whole name; empty or `*` for all) covers
/// `tool`.
fn matcher_covers(matcher: &str, tool: &str) -> bool {
    matcher.is_empty()
        || matcher == "*"
        || regex::Regex::new(&format!("^(?:{matcher})$")).is_ok_and(|r| r.is_match(tool))
}

/// Installers that read each variable `customs env` sets.
fn readers(var: &str) -> &'static str {
    match var {
        "PIP_INDEX_URL" => "pip and pipx",
        "UV_INDEX_URL" | "UV_DEFAULT_INDEX" => "uv",
        "PIPENV_PYPI_MIRROR" => "pipenv",
        "PDM_PYPI_URL" => "PDM",
        "npm_config_registry" => "npm, pnpm, Yarn 1 and Bun",
        "NPM_CONFIG_REGISTRY" => "Deno",
        "YARN_NPM_REGISTRY_SERVER" | "YARN_UNSAFE_HTTP_WHITELIST" => "Yarn 2+",
        _ => "",
    }
}

fn environment(inputs: &Inputs, out: &mut Vec<Finding>) {
    let env = inputs.env;
    let same = |a: &str, b: &str| a.trim_end_matches('/') == b.trim_end_matches('/');
    let mut problems = Vec::new();
    let mut uv_ok = false;
    for (var, want) in env_vars(inputs.server) {
        if var == "CUSTOMS_SERVER" {
            continue;
        }
        let got = env(var);
        let ok = got.as_deref().is_some_and(|g| same(g, &want));
        if matches!(var, "UV_INDEX_URL" | "UV_DEFAULT_INDEX") {
            // uv reads either; one pointing at the proxy is enough unless the other
            // points somewhere else.
            uv_ok |= ok;
            if got.as_deref().is_none_or(|g| same(g, &want)) {
                continue;
            }
        }
        if !ok {
            problems.push((var, got));
        }
    }
    if !uv_ok && !problems.iter().any(|(v, _)| v.starts_with("UV_")) {
        problems.push(("UV_DEFAULT_INDEX", None));
    }
    if problems.is_empty() {
        out.push(finding(
            Level::Ok,
            "environment",
            "pip, uv, pipenv, PDM, npm, pnpm, Yarn, Bun and Deno point at the proxy".into(),
            "",
        ));
    }
    let registry_unset = problems
        .iter()
        .any(|(v, got)| *v == "YARN_NPM_REGISTRY_SERVER" && got.is_none());
    for (var, got) in problems {
        let fix =
            "eval \"$(customs env)\" in the shell (or the agent's environment) that runs installs";
        if var == "YARN_UNSAFE_HTTP_WHITELIST" {
            // Without it Yarn 2+ refuses the plain-HTTP proxy: installs fail, none slip by.
            if !registry_unset {
                out.push(finding(
                    Level::Warn,
                    "environment",
                    format!("{var} does not list the proxy's host, so Yarn 2+ refuses to use a plain-HTTP proxy"),
                    fix,
                ));
            }
            continue;
        }
        let detail = match got {
            Some(g) => format!("{var} is {g}, so installs with {} use that", readers(var)),
            None => format!(
                "{var} is not set, so installs with {} use the public registry",
                readers(var)
            ),
        };
        out.push(finding(Level::Bypass, "environment", detail, fix));
    }
    for var in [
        "PIP_EXTRA_INDEX_URL",
        "PIP_FIND_LINKS",
        "UV_EXTRA_INDEX_URL",
        "UV_INDEX",
        "UV_FIND_LINKS",
    ] {
        if let Some(v) = env(var).filter(|v| !v.trim().is_empty()) {
            out.push(finding(
                Level::Bypass,
                "environment",
                format!("{var} adds {v}, which installers query without the proxy"),
                "unset it; an extra index also lets a public package shadow a private one",
            ));
        }
    }
}

/// The text of a file doctor inspects. A missing file is skipped quietly; one it cannot
/// read or decode is a warning, so a bypass in it is not silently missed. UTF-16 with a
/// byte order mark (what Windows PowerShell 5.1 `>` writes) is decoded.
fn read(path: &Path, out: &mut Vec<Finding>) -> Option<String> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => return unreadable(path, &e.to_string(), out),
    };
    let utf16 = |be: bool| {
        let units: Vec<u16> = bytes[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| {
                if be {
                    u16::from_be_bytes(c)
                } else {
                    u16::from_le_bytes(c)
                }
            })
            .collect();
        String::from_utf16(&units).ok()
    };
    let text = match bytes.as_slice() {
        [0xff, 0xfe, ..] => utf16(false),
        [0xfe, 0xff, ..] => utf16(true),
        [0xef, 0xbb, 0xbf, rest @ ..] => String::from_utf8(rest.to_vec()).ok(),
        _ => String::from_utf8(bytes.clone()).ok(),
    };
    match text {
        Some(t) => Some(t),
        None => unreadable(path, "it is not UTF-8 or UTF-16 text", out),
    }
}

fn unreadable(path: &Path, why: &str, out: &mut Vec<Finding>) -> Option<String> {
    out.push(finding(
        Level::Warn,
        &display(path),
        format!("could not read it ({why}), so it was not inspected for registry settings"),
        "save it as UTF-8 and make it readable, then run customs doctor again",
    ));
    None
}

fn display(path: &Path) -> String {
    path.display().to_string()
}

const SCOPE_FIX: &str = "Customs does not check these packages; if that registry also serves public packages, route it through the proxy instead";

fn npmrc(path: &Path, proxy: &str, out: &mut Vec<Finding>) {
    let Some(text) = read(path, out) else {
        return;
    };
    for line in text.lines() {
        let line = line.trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim().trim_matches('"'));
        let Some(scope) = key.strip_suffix(":registry").filter(|s| s.starts_with('@')) else {
            continue;
        };
        if authority(value).as_deref() == Some(proxy) {
            continue;
        }
        out.push(finding(
            Level::Bypass,
            &display(path),
            format!("{scope} packages come from {value}: pnpm and Bun fetch them there directly (npm still sends the tarballs through the proxy)"),
            SCOPE_FIX,
        ));
    }
}

fn bunfig(path: &Path, proxy: &str, out: &mut Vec<Finding>) {
    let Some(doc) = read(path, out).and_then(|t| toml::from_str::<toml::Value>(&t).ok()) else {
        return;
    };
    let Some(scopes) = doc
        .get("install")
        .and_then(|i| i.get("scopes"))
        .and_then(toml::Value::as_table)
    else {
        return;
    };
    for (scope, v) in scopes {
        let url = match v {
            toml::Value::String(s) => s.as_str(),
            toml::Value::Table(t) => t.get("url").and_then(toml::Value::as_str).unwrap_or(""),
            _ => "",
        };
        if authority(url).as_deref() == Some(proxy) {
            continue;
        }
        out.push(finding(
            Level::Bypass,
            &display(path),
            format!(
                "Bun fetches @{} packages from {url} directly",
                scope.trim_start_matches('@')
            ),
            SCOPE_FIX,
        ));
    }
}

fn yarnrc(path: &Path, proxy: &str, out: &mut Vec<Finding>) {
    let Some(text) = read(path, out) else {
        return;
    };
    // `npmScopes:` then `  name:` then `    npmRegistryServer: "url"`.
    let mut in_scopes = false;
    let mut scope = String::new();
    for line in text.lines() {
        let indent = line.len() - line.trim_start().len();
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if indent == 0 {
            in_scopes = t.starts_with("npmScopes:");
            continue;
        }
        if !in_scopes {
            continue;
        }
        if let Some(url) = t.strip_prefix("npmRegistryServer:") {
            let url = url.trim().trim_matches(|c| c == '"' || c == '\'');
            if authority(url).as_deref() != Some(proxy) {
                out.push(finding(
                    Level::Bypass,
                    &display(path),
                    format!("Yarn 2+ fetches @{scope} packages from {url} directly"),
                    SCOPE_FIX,
                ));
            }
        } else if t.ends_with(':') {
            scope = t
                .trim_end_matches(':')
                .trim_matches(|c| c == '"' || c == '\'')
                .trim_start_matches('@')
                .to_string();
        }
    }
}

fn pip_config_files(inputs: &Inputs) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = Vec::new();
    if let Some(f) = (inputs.env)("PIP_CONFIG_FILE") {
        files.push(f.into());
    }
    if let Some(h) = inputs.home {
        files.push(h.join(".pip/pip.conf"));
        files.push(h.join(".config/pip/pip.conf"));
        // Windows: the legacy per-user file.
        files.push(h.join("pip/pip.ini"));
    }
    if let Some(a) = (inputs.env)("APPDATA") {
        files.push(Path::new(&a).join("pip").join("pip.ini"));
    }
    if let Some(v) = (inputs.env)("VIRTUAL_ENV") {
        files.push(Path::new(&v).join("pip.conf"));
        files.push(Path::new(&v).join("pip.ini"));
    }
    files.extend(inputs.system_pip_configs.iter().cloned());
    files
}

fn pip_config(path: &Path, out: &mut Vec<Finding>) {
    let Some(text) = read(path, out) else {
        return;
    };
    // configparser rules: `#`/`;` comment lines, `=` or `:` between key and value, and
    // indented lines continue the previous value (pip splits values on whitespace).
    let mut key: Option<String> = None;
    let push = |key: &str, value: &str, out: &mut Vec<Finding>| {
        for url in value.split_whitespace() {
            out.push(finding(
                Level::Bypass,
                &display(path),
                format!("{key} = {url}: pip also installs from there without the proxy"),
                "remove it; an extra index also lets a public package shadow a private one",
            ));
        }
    };
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with(';') {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            if let Some(k) = &key {
                push(k, t, out);
            }
            continue;
        }
        if t.starts_with('[') {
            key = None;
            continue;
        }
        let Some(at) = t.find(['=', ':']) else {
            key = None;
            continue;
        };
        let k = t[..at].trim().replace('_', "-");
        if matches!(k.as_str(), "extra-index-url" | "find-links") {
            push(&k, &t[at + 1..], out);
            key = Some(k);
        } else {
            key = None;
        }
    }
}

fn python_project(dir: &Path, out: &mut Vec<Finding>) {
    // requirements files: options there override the environment.
    if let Ok(entries) = std::fs::read_dir(dir) {
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("requirements") && n.ends_with(".txt"))
            .collect();
        names.sort();
        for n in names {
            let Some(text) = read(&dir.join(&n), out) else {
                continue;
            };
            for (i, line) in text.lines().enumerate() {
                let t = line.trim();
                let opt = [
                    "--index-url",
                    "-i",
                    "--extra-index-url",
                    "--find-links",
                    "-f",
                ]
                .into_iter()
                .find(|o| {
                    t.strip_prefix(o)
                        .is_some_and(|r| r.starts_with([' ', '=', '\t']))
                });
                if let Some(o) = opt {
                    out.push(finding(
                        Level::Bypass,
                        &format!("{n}:{}", i + 1),
                        format!("`{t}` sends pip to another index, overriding PIP_INDEX_URL"),
                        if o == "--index-url" || o == "-i" {
                            "remove the line and let PIP_INDEX_URL choose the index"
                        } else {
                            "remove it; an extra index also lets a public package shadow a private one"
                        },
                    ));
                }
            }
        }
    }
    let pyproject =
        read(&dir.join("pyproject.toml"), out).and_then(|t| toml::from_str::<toml::Value>(&t).ok());
    let uv_toml =
        read(&dir.join("uv.toml"), out).and_then(|t| toml::from_str::<toml::Value>(&t).ok());
    let uv_tables = [
        pyproject
            .as_ref()
            .and_then(|p| p.get("tool"))
            .and_then(|t| t.get("uv"))
            .map(|u| ("pyproject.toml [tool.uv]", u)),
        uv_toml.as_ref().map(|u| ("uv.toml", u)),
    ];
    for (subject, uv) in uv_tables.into_iter().flatten() {
        let indexes = uv.get("index").and_then(toml::Value::as_array);
        for idx in indexes.into_iter().flatten() {
            let url = idx.get("url").and_then(toml::Value::as_str).unwrap_or("");
            // The environment's UV_DEFAULT_INDEX replaces a `default = true` index.
            if idx.get("default").and_then(toml::Value::as_bool) == Some(true) {
                continue;
            }
            out.push(finding(
                Level::Bypass,
                subject,
                format!("uv also resolves from the index at {url}"),
                "packages from it are not checked; drop the index or put it behind the proxy",
            ));
        }
        for key in ["extra-index-url", "find-links"] {
            let urls = match uv.get(key) {
                Some(toml::Value::String(s)) => vec![s.clone()],
                Some(toml::Value::Array(a)) => a
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect(),
                _ => vec![],
            };
            for u in urls {
                out.push(finding(
                    Level::Bypass,
                    subject,
                    format!("{key} {u}: uv also installs from there without the proxy"),
                    "remove it; an extra index also lets a public package shadow a private one",
                ));
            }
        }
    }
    let poetry = pyproject
        .as_ref()
        .and_then(|p| p.get("tool"))
        .and_then(|t| t.get("poetry"));
    if poetry.is_some() || dir.join("poetry.lock").is_file() {
        out.push(finding(
            Level::Bypass,
            "Poetry",
            "Poetry reads no environment variable for its index, so `poetry install` and `poetry add` go to PyPI directly".into(),
            "poetry source add --priority=primary customs <server>/pypi/simple; the Claude Code hook also checks poetry.lock before poetry install runs",
        ));
    }
    if let Some(doc) =
        read(&dir.join("Pipfile"), out).and_then(|t| toml::from_str::<toml::Value>(&t).ok())
    {
        for s in doc
            .get("source")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            let url = s.get("url").and_then(toml::Value::as_str).unwrap_or("");
            if host(url) == "pypi.org" {
                continue;
            }
            out.push(finding(
                Level::Bypass,
                "Pipfile",
                format!("pipenv installs from the source {url}; PIPENV_PYPI_MIRROR replaces only pypi.org"),
                "packages from it are not checked; put that index behind the proxy",
            ));
        }
    }
}

/// URLs a lockfile records that its installer downloads as written, by host.
fn direct_urls(name: &str, text: &str, proxy: &str) -> Option<BTreeMap<String, usize>> {
    let mut urls: Vec<String> = Vec::new();
    let json = || serde_json::from_str::<Value>(text).ok();
    match name {
        "package-lock.json" | "npm-shrinkwrap.json" => {
            let doc = json()?;
            fn walk(v: &Value, out: &mut Vec<String>) {
                if let Some(o) = v.as_object() {
                    if let Some(r) = o.get("resolved").and_then(Value::as_str) {
                        out.push(r.to_string());
                    }
                    for (k, child) in o {
                        if matches!(k.as_str(), "packages" | "dependencies") || child.is_object() {
                            walk(child, out);
                        }
                    }
                }
            }
            walk(&doc, &mut urls);
            // npm swaps the default registry's host for the configured one.
            urls.retain(|u| host(u) != "registry.npmjs.org");
        }
        "yarn.lock" => {
            if text.contains("__metadata:") {
                return None; // Yarn 2+ records no URLs for registry packages.
            }
            for line in text.lines() {
                if let Some(r) = line.trim().strip_prefix("resolved ") {
                    urls.push(r.trim().trim_matches('"').to_string());
                }
            }
        }
        "pnpm-lock.yaml" => {
            for part in text.split("tarball: ").skip(1) {
                let end = part.find([',', '}', '\n']).unwrap_or(part.len());
                urls.push(part[..end].trim().trim_matches(['\'', '"']).to_string());
            }
        }
        "bun.lock" => {
            for line in text.lines() {
                // `"name": ["name@1.0.0", "https://...", {...}, "sha512-..."],`
                if let Some(start) = line.find("\", \"http") {
                    let rest = &line[start + 4..];
                    if let Some(end) = rest.find('"') {
                        urls.push(rest[..end].to_string());
                    }
                }
            }
        }
        "deno.lock" => {
            let doc = json()?;
            let npm = doc
                .get("npm")
                .or_else(|| doc.get("packages").and_then(|p| p.get("npm")))?;
            for e in npm.as_object()?.values() {
                if let Some(t) = e.get("tarball").and_then(Value::as_str) {
                    urls.push(t.to_string());
                }
            }
        }
        "uv.lock" => {
            let doc = toml::from_str::<toml::Value>(text).ok()?;
            for p in doc.get("package")?.as_array()? {
                let sdist = p.get("sdist").into_iter();
                let wheels = p
                    .get("wheels")
                    .and_then(toml::Value::as_array)
                    .into_iter()
                    .flatten();
                for f in sdist.chain(wheels) {
                    if let Some(u) = f.get("url").and_then(toml::Value::as_str) {
                        urls.push(u.to_string());
                    }
                }
            }
        }
        _ => return None,
    }
    let mut by_host = BTreeMap::new();
    for u in urls {
        if !(u.starts_with("http://") || u.starts_with("https://")) {
            continue; // git, file: and the like are listed by `customs audit`
        }
        if authority(&u).as_deref() == Some(proxy) {
            continue;
        }
        *by_host.entry(host(&u)).or_insert(0) += 1;
    }
    Some(by_host)
}

fn lockfiles(dir: &Path, proxy: &str, out: &mut Vec<Finding>) {
    for name in [
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock",
        "deno.lock",
        "uv.lock",
    ] {
        let Some(text) = read(&dir.join(name), out) else {
            continue;
        };
        let Some(hosts) = direct_urls(name, &text, proxy) else {
            continue;
        };
        if hosts.is_empty() {
            out.push(finding(
                Level::Ok,
                name,
                "installs from it go through the proxy".into(),
                "",
            ));
            continue;
        }
        let n: usize = hosts.values().sum();
        let list = hosts
            .iter()
            .map(|(h, c)| format!("{h}: {c}"))
            .collect::<Vec<_>>()
            .join(", ");
        let (level, detail, fix) = match name {
            "yarn.lock" => (
                Level::Bypass,
                format!("Yarn 1 downloads {} this lockfile records as written ({list}), whatever npm_config_registry says", plural(n, "URL", "URLs")),
                "Yarn 1 cannot send locked packages through a registry proxy: check this lockfile with `customs audit` in CI, install through the Claude Code hook (it checks every pin first), or move to Yarn 2+",
            ),
            "uv.lock" => (
                Level::Warn,
                format!("`uv sync --frozen` downloads {} this lockfile records ({list}) directly; `uv sync` and `uv sync --locked` go through the proxy", plural(n, "file URL", "file URLs")),
                "use `uv sync` or `uv sync --locked` instead of --frozen, or relock through the proxy (`uv lock`) so the URLs point at it",
            ),
            "package-lock.json" | "npm-shrinkwrap.json" => (
                Level::Bypass,
                format!("npm redirects only registry.npmjs.org URLs to the proxy; {} from elsewhere ({list})", plural(n, "entry downloads", "entries download")),
                "check them with `customs audit`; regenerate these entries through the proxy if they should come from the public registry",
            ),
            _ => (
                Level::Bypass,
                format!("{} a download URL that the installer uses as written ({list})", plural(n, "entry records", "entries record")),
                "check them with `customs audit`, or regenerate the lockfile through the proxy so the URLs point at it",
            ),
        };
        out.push(finding(level, name, detail, fix));
    }
}

/// `n` with the singular or plural noun phrase.
fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// The server's `/healthz`, or why it could not be read.
async fn health(server: &str) -> Result<Value, String> {
    let base = server.trim_end_matches('/');
    let r = reqwest::Client::new()
        .get(format!("{base}/healthz"))
        .timeout(Duration::from_secs(3))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !r.status().is_success() {
        return Err(format!("HTTP {}", r.status()));
    }
    r.json::<Value>().await.map_err(|e| e.to_string())
}

/// What the server's `/healthz` says about enforcement: monitor mode blocks nothing, and a
/// server without (trained) models judges on the policy rules alone.
pub fn server_finding(server: &str, h: &Value) -> Finding {
    let mode = h["mode"].as_str().unwrap_or("?");
    let version = h["model_version"].as_str().unwrap_or("?");
    // Servers before `models_loaded` report "none" for a missing model directory.
    let loaded = h["models_loaded"].as_bool().unwrap_or(version != "none");
    let untrained = h["untrained"].as_bool().unwrap_or(false);
    let answers = format!("{server} answers: mode {mode}, models {version}");
    if mode != "enforce" {
        return finding(
            Level::Warn,
            "server",
            answers,
            "in this mode the proxy records verdicts but blocks nothing; set mode = \"enforce\" in the policy",
        );
    }
    if !loaded {
        return finding(
            Level::Warn,
            "server",
            format!("{answers}; it runs without the classifier, so only the policy rules judge packages"),
            "pass --models DIR or set CUSTOMS_MODELS for `customs serve`",
        );
    }
    if untrained {
        return finding(
            Level::Warn,
            "server",
            format!("{answers}; these are the untrained development placeholders, not a trained classifier"),
            "point --models or CUSTOMS_MODELS at the trained models/ directory",
        );
    }
    finding(Level::Ok, "server", answers, "")
}

pub struct DoctorOptions {
    pub dir: PathBuf,
    pub server: String,
    pub json: bool,
}

/// Exit 1 when anything bypasses the proxy or the server is unreachable.
pub async fn run(opts: DoctorOptions) -> i32 {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    let env = |k: &str| std::env::var(k).ok();
    let system = system_pip_configs(&env);
    let inputs = Inputs {
        dir: &opts.dir,
        home: home.as_deref(),
        server: &opts.server,
        env: &env,
        system_pip_configs: &system,
    };
    let mut findings = inspect(&inputs);
    match health(&opts.server).await {
        Ok(h) => findings.push(server_finding(&opts.server, &h)),
        Err(e) => findings.push(finding(
            Level::Bypass,
            "server",
            format!("{} does not answer ({e}): installers pointed at it fail, and the hook falls back to in-process checks", opts.server),
            "start it with `customs serve`, or pass --server",
        )),
    }
    findings.sort_by_key(|f| std::cmp::Reverse(f.level));
    let bypasses = findings.iter().filter(|f| f.level == Level::Bypass).count();
    if opts.json {
        let doc = json!({
            "dir": opts.dir.display().to_string(),
            "server": redact_url(&opts.server),
            "bypasses": bypasses,
            "findings": findings,
        });
        println!("{}", serde_json::to_string_pretty(&doc).unwrap_or_default());
    } else {
        print!("{}", render(&opts.dir, &findings));
    }
    i32::from(bypasses > 0)
}

pub fn render(dir: &Path, findings: &[Finding]) -> String {
    let mut s = format!("customs doctor: {}\n\n", dir.display());
    let width = findings.iter().map(|f| f.subject.len()).max().unwrap_or(0);
    for f in findings {
        s.push_str(&format!(
            "{:<6}  {:<width$}  {}\n",
            f.level.label(),
            f.subject,
            f.detail
        ));
        if !f.fix.is_empty() {
            s.push_str(&format!("{:<6}  {:<width$}  fix: {}\n", "", "", f.fix));
        }
    }
    let n = findings.iter().filter(|f| f.level == Level::Bypass).count();
    s.push_str(&match n {
        0 => "\nNo way around the proxy found.\n".to_string(),
        1 => "\n1 way around the proxy found.\n".to_string(),
        n => format!("\n{n} ways around the proxy found.\n"),
    });
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const SERVER: &str = "http://127.0.0.1:7878";

    fn write(dir: &Path, name: &str, text: &str) {
        let p = dir.join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    fn run_with(dir: &Path, home: Option<&Path>, env: HashMap<&str, String>) -> Vec<Finding> {
        let lookup = move |k: &str| env.get(k).cloned();
        inspect(&Inputs {
            dir,
            home,
            server: SERVER,
            env: &lookup,
            system_pip_configs: &[],
        })
    }

    fn full_env() -> HashMap<&'static str, String> {
        env_vars(SERVER).into_iter().collect()
    }

    fn bypasses(f: &[Finding]) -> Vec<(String, String)> {
        f.iter()
            .filter(|f| f.level == Level::Bypass)
            .map(|f| (f.subject.clone(), f.detail.clone()))
            .collect()
    }

    #[test]
    fn claude_hook_registration() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join(".claude")).unwrap();
        let write = |matcher: &str| {
            let v = json!({"hooks": {"PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "other"}]},
                {"matcher": matcher, "hooks": [{"type": "command", "command": "customs hook claude-code"}]}
            ]}});
            std::fs::write(d.path().join(".claude/settings.json"), v.to_string()).unwrap();
        };
        let hook = |f: Vec<Finding>| {
            f.into_iter()
                .filter(|f| f.subject.ends_with("settings.json"))
                .map(|f| (f.level, f.detail))
                .collect::<Vec<_>>()
        };
        assert!(hook(run_with(d.path(), None, full_env())).is_empty());
        write("Bash");
        let f = hook(run_with(d.path(), None, full_env()));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].0, Level::Warn);
        assert!(f[0].1.contains("only shell commands"), "{}", f[0].1);
        write("Bash|Edit|Write|MultiEdit|NotebookEdit");
        assert_eq!(hook(run_with(d.path(), None, full_env()))[0].0, Level::Ok);
        write("*");
        assert_eq!(hook(run_with(d.path(), None, full_env()))[0].0, Level::Ok);
        write("Edit");
        assert!(hook(run_with(d.path(), None, full_env()))[0]
            .1
            .contains("does not include Bash"));
    }

    #[test]
    fn cursor_and_gemini_hook_registration() {
        let d = tempfile::tempdir().unwrap();
        for dir in [".cursor", ".gemini"] {
            std::fs::create_dir_all(d.path().join(dir)).unwrap();
        }
        let found = |name: &str| {
            run_with(d.path(), None, full_env())
                .into_iter()
                .filter(|f| f.subject.ends_with(name))
                .map(|f| (f.level, f.detail))
                .collect::<Vec<_>>()
        };
        let cursor = |entry: Value| {
            let v = json!({"version": 1, "hooks": {"beforeShellExecution": [entry]}});
            std::fs::write(d.path().join(".cursor/hooks.json"), v.to_string()).unwrap();
        };
        cursor(json!({"command": "./other.sh"}));
        assert!(found("hooks.json").is_empty());
        cursor(json!({"command": "customs hook cursor"}));
        assert_eq!(found("hooks.json")[0].0, Level::Ok);
        cursor(json!({"command": "customs hook cursor", "matcher": "pip"}));
        let f = found("hooks.json");
        assert_eq!(f[0].0, Level::Warn);
        assert!(f[0].1.contains("matching pip"), "{}", f[0].1);

        let gemini = |matcher: &str| {
            let v = json!({"hooks": {"BeforeTool": [
                {"matcher": matcher, "hooks": [{"type": "command", "command": "customs hook gemini"}]}
            ]}});
            std::fs::write(d.path().join(".gemini/settings.json"), v.to_string()).unwrap();
        };
        gemini("run_shell_command|write_file|replace");
        assert_eq!(found("settings.json")[0].0, Level::Ok);
        gemini("run_shell_command");
        assert!(found("settings.json")[0].1.contains("only shell commands"));
        gemini("write_file");
        assert!(found("settings.json")[0]
            .1
            .contains("does not include run_shell_command"));
    }

    #[test]
    fn unpinned_mcp_servers() {
        let d = tempfile::tempdir().unwrap();
        let found = || {
            run_with(d.path(), None, full_env())
                .into_iter()
                .filter(|f| f.subject.ends_with(".mcp.json"))
                .map(|f| (f.level, f.detail))
                .collect::<Vec<_>>()
        };
        let write = |args: &str| {
            let v = format!(r#"{{"mcpServers": {{"x": {{"command": "npx", "args": {args}}}}}}}"#);
            std::fs::write(d.path().join(".mcp.json"), v).unwrap();
        };
        write(r#"["-y", "mcp-x"]"#);
        let f = found();
        assert_eq!(f[0].0, Level::Warn);
        assert!(f[0].1.ends_with("mcp-x (latest, line 1)"), "{}", f[0].1);
        write(r#"["-y", "mcp-x@1.4.0"]"#);
        assert_eq!(found()[0].0, Level::Ok);
        write(r#"["./local.js"]"#);
        assert!(found().is_empty());
    }

    #[test]
    fn codex_hook_registration() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join(".codex")).unwrap();
        let found = |name: &str| {
            run_with(d.path(), None, full_env())
                .into_iter()
                .filter(|f| f.subject.ends_with(name))
                .map(|f| (f.level, f.detail))
                .collect::<Vec<_>>()
        };
        let hooks = |matcher: &str| {
            let v = json!({"hooks": {"PreToolUse": [
                {"matcher": matcher, "hooks": [{"type": "command", "command": "customs hook codex"}]}
            ]}});
            std::fs::write(d.path().join(".codex/hooks.json"), v.to_string()).unwrap();
        };
        hooks("Bash|apply_patch");
        assert_eq!(found("hooks.json")[0].0, Level::Ok);
        hooks("*");
        assert_eq!(found("hooks.json")[0].0, Level::Ok);
        hooks("Bash|Edit");
        assert_eq!(found("hooks.json")[0].0, Level::Ok);
        hooks("Bash");
        assert!(found("hooks.json")[0].1.contains("only shell commands"));
        hooks("Bas");
        assert!(found("hooks.json")[0].1.contains("does not include Bash"));
        hooks("^(Bash|apply_patch)$");
        assert_eq!(found("hooks.json")[0].0, Level::Ok);
        std::fs::remove_file(d.path().join(".codex/hooks.json")).unwrap();

        let toml = r#"
model = "o4"

[[hooks.PreToolUse]]
matcher = "Bash"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "customs hook codex"
"#;
        std::fs::write(d.path().join(".codex/config.toml"), toml).unwrap();
        let f = found("config.toml");
        assert_eq!(f[0].0, Level::Warn);
        assert!(f[0].1.contains("only shell commands"), "{}", f[0].1);
        std::fs::write(d.path().join(".codex/config.toml"), "model = \"o4\"\n").unwrap();
        assert!(found("config.toml").is_empty());
    }

    #[test]
    fn environment_rules() {
        let d = tempfile::tempdir().unwrap();
        let f = run_with(d.path(), None, full_env());
        assert_eq!(bypasses(&f), vec![]);
        assert_eq!(f[0].subject, "environment");

        // Only the lower-case npm variable: Deno goes straight to npmjs.
        let mut env = full_env();
        env.remove("NPM_CONFIG_REGISTRY");
        env.remove("UV_INDEX_URL");
        env.insert("PIP_INDEX_URL", "https://pypi.org/simple".into());
        env.insert("PIP_EXTRA_INDEX_URL", "https://corp.example/simple".into());
        let b = bypasses(&run_with(d.path(), None, env));
        assert_eq!(b.len(), 3, "{b:?}");
        assert_eq!(
            b[0].1,
            "PIP_INDEX_URL is https://pypi.org/simple, so installs with pip and pipx use that"
        );
        assert_eq!(
            b[1].1,
            "NPM_CONFIG_REGISTRY is not set, so installs with Deno use the public registry"
        );
        assert!(b[2]
            .1
            .contains("PIP_EXTRA_INDEX_URL adds https://corp.example/simple"));

        // Nothing set at all: one line per installer family.
        let b = bypasses(&run_with(d.path(), None, HashMap::new()));
        assert_eq!(b.len(), 7, "{b:?}");
    }

    #[test]
    fn scoped_registries_and_extra_indexes() {
        let d = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        write(
            d.path(),
            ".npmrc",
            "registry=https://registry.npmjs.org/\n@corp:registry=https://npm.corp.example/\n@ok:registry=http://127.0.0.1:7878/npm/\n",
        );
        write(
            d.path(),
            "bunfig.toml",
            "[install.scopes]\nacme = { url = \"https://npm.acme.example/\", token = \"x\" }\n",
        );
        write(
            d.path(),
            ".yarnrc.yml",
            "nodeLinker: node-modules\nnpmScopes:\n  \"@corp\":\n    npmRegistryServer: \"https://npm.corp.example\"\n",
        );
        write(
            home.path(),
            ".config/pip/pip.conf",
            "[global]\nindex-url = https://pypi.org/simple\nextra-index-url = https://corp.example/simple\n",
        );
        write(
            d.path(),
            "requirements-dev.txt",
            "--extra-index-url https://download.pytorch.org/whl/cpu\ntorch==2.4.0\n-r requirements.txt\n",
        );
        write(
            d.path(),
            "pyproject.toml",
            "[project]\nname = \"x\"\n[[tool.uv.index]]\nname = \"mirror\"\nurl = \"https://mirror.example/simple\"\ndefault = true\n[[tool.uv.index]]\nname = \"torch\"\nurl = \"https://download.pytorch.org/whl/cpu\"\nexplicit = true\n",
        );
        write(
            d.path(),
            "Pipfile",
            "[[source]]\nurl = \"https://pypi.org/simple\"\nname = \"pypi\"\n[[source]]\nurl = \"https://corp.example/simple\"\nname = \"corp\"\n",
        );
        let b = bypasses(&run_with(d.path(), Some(home.path()), full_env()));
        let details: Vec<&str> = b.iter().map(|(_, d)| d.as_str()).collect();
        assert_eq!(details.len(), 7, "{details:#?}");
        assert!(details[0].starts_with("@corp packages come from https://npm.corp.example/"));
        assert_eq!(
            details[1],
            "Bun fetches @acme packages from https://npm.acme.example/ directly"
        );
        assert_eq!(
            details[2],
            "Yarn 2+ fetches @corp packages from https://npm.corp.example directly"
        );
        assert!(details[3].starts_with("extra-index-url = https://corp.example/simple"));
        assert!(details[4].starts_with("`--extra-index-url https://download.pytorch.org"));
        assert_eq!(b[4].0, "requirements-dev.txt:1");
        assert_eq!(
            details[5],
            "uv also resolves from the index at https://download.pytorch.org/whl/cpu"
        );
        assert!(
            details[6].starts_with("pipenv installs from the source https://corp.example/simple")
        );
    }

    #[test]
    fn lockfile_urls() {
        let d = tempfile::tempdir().unwrap();
        // Written straight against the public registries.
        write(
            d.path(),
            "yarn.lock",
            "is-number@7.0.0:\n  version \"7.0.0\"\n  resolved \"https://registry.yarnpkg.com/is-number/-/is-number-7.0.0.tgz#abc\"\n",
        );
        write(
            d.path(),
            "package-lock.json",
            r#"{"lockfileVersion": 3, "packages": {"": {},
                "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"},
                "node_modules/b": {"version": "1.0.0", "resolved": "https://registry.yarnpkg.com/b/-/b-1.0.0.tgz"},
                "node_modules/c": {"version": "1.0.0", "resolved": "http://127.0.0.1:7878/npm/c/-/c-1.0.0.tgz"},
                "node_modules/g": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/g.git#abc"}}}"#,
        );
        write(
            d.path(),
            "pnpm-lock.yaml",
            "packages:\n\n  is-number@7.0.0:\n    resolution: {tarball: https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz, integrity: sha512-x}\n  ms@2.1.3:\n    resolution: {integrity: sha512-y}\n",
        );
        write(
            d.path(),
            "bun.lock",
            "{\n  \"packages\": {\n    \"a\": [\"a@1.0.0\", \"\", {}, \"sha512-x\"],\n    \"b\": [\"b@1.0.0\", \"https://npm.corp.example/b/-/b-1.0.0.tgz\", {}, \"sha512-y\"],\n  }\n}\n",
        );
        write(
            d.path(),
            "uv.lock",
            "version = 1\n[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nsource = { registry = \"https://pypi.org/simple\" }\nsdist = { url = \"https://files.pythonhosted.org/packages/six-1.16.0.tar.gz\", hash = \"sha256:x\" }\nwheels = [\n  { url = \"https://files.pythonhosted.org/packages/six-1.16.0-py2.py3-none-any.whl\", hash = \"sha256:y\" },\n]\n",
        );
        write(
            d.path(),
            "deno.lock",
            r#"{"version": "5", "npm": {"ms@2.1.3": {"integrity": "sha512-x", "tarball": "http://127.0.0.1:7878/npm/ms/-/ms-2.1.3.tgz"}}}"#,
        );
        let f = run_with(d.path(), None, full_env());
        let by: HashMap<&str, &Finding> = f
            .iter()
            .filter(|f| f.subject != "environment")
            .map(|f| (f.subject.as_str(), f))
            .collect();
        assert_eq!(by["yarn.lock"].level, Level::Bypass);
        assert!(by["yarn.lock"].detail.contains("(registry.yarnpkg.com: 1)"));
        assert_eq!(by["package-lock.json"].level, Level::Bypass);
        assert!(by["package-lock.json"]
            .detail
            .contains("1 entry downloads from elsewhere (registry.yarnpkg.com: 1)"));
        assert!(by["pnpm-lock.yaml"].detail.starts_with("1 entry records"));
        assert!(by["bun.lock"].detail.contains("(npm.corp.example: 1)"));
        assert_eq!(by["uv.lock"].level, Level::Warn);
        assert!(by["uv.lock"].detail.contains("2 file URLs"));
        assert_eq!(by["deno.lock"].level, Level::Ok);
        // Yarn 2+ lockfiles record no URLs.
        write(
            d.path(),
            "yarn.lock",
            "__metadata:\n  version: 8\n\"a@npm:1.0.0\":\n  resolution: \"a@npm:1.0.0\"\n",
        );
        assert!(run_with(d.path(), None, full_env())
            .iter()
            .all(|f| f.subject != "yarn.lock"));
        assert!(render(d.path(), &f).ends_with("4 ways around the proxy found.\n"));
    }

    #[test]
    fn poetry_has_no_variable() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "poetry.lock",
            "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\n",
        );
        let b = bypasses(&run_with(d.path(), None, full_env()));
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].0, "Poetry");
    }

    #[test]
    fn a_server_without_a_trained_classifier_is_a_warning() {
        let f = |v: Value| server_finding(SERVER, &v);
        let ok = f(json!({"mode": "enforce", "model_version": "2026.06",
            "models_loaded": true, "untrained": false}));
        assert_eq!(ok.level, Level::Ok, "{ok:?}");
        let none = f(json!({"mode": "enforce", "model_version": "none",
            "models_loaded": false, "untrained": true}));
        assert_eq!(none.level, Level::Warn);
        assert!(none.detail.contains("without the classifier"), "{none:?}");
        assert!(none.fix.contains("CUSTOMS_MODELS"), "{none:?}");
        let dev = f(json!({"mode": "enforce", "model_version": "dev-untrained",
            "models_loaded": true, "untrained": true}));
        assert_eq!(dev.level, Level::Warn);
        assert!(dev.detail.contains("untrained"), "{dev:?}");
        // An older server reports only the model version.
        let old = f(json!({"mode": "enforce", "model_version": "none"}));
        assert_eq!(old.level, Level::Warn);
        let monitor = f(json!({"mode": "monitor", "model_version": "2026.06",
            "models_loaded": true, "untrained": false}));
        assert_eq!(monitor.level, Level::Warn);
        assert!(monitor.fix.contains("enforce"), "{monitor:?}");
    }

    #[test]
    fn findings_never_show_url_credentials() {
        let d = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let url = "https://u:s3cret@corp.example/simple?token=t0k";
        write(
            home.path(),
            ".config/pip/pip.conf",
            &format!("[global]\nextra-index-url = {url}\n"),
        );
        write(
            d.path(),
            "requirements.txt",
            &format!("--index-url {url}\nx==1\n"),
        );
        write(
            d.path(),
            "uv.toml",
            &format!("[[index]]\nname = \"corp\"\nurl = \"{url}\"\n"),
        );
        let mut env = full_env();
        env.insert("PIP_INDEX_URL", url.to_string());
        env.insert("PIP_EXTRA_INDEX_URL", url.to_string());
        let f = run_with(d.path(), Some(home.path()), env);
        assert!(bypasses(&f).len() >= 5, "{f:#?}");
        let text = render(d.path(), &f);
        let json = serde_json::to_string(&f).unwrap();
        for out in [&text, &json] {
            assert!(!out.contains("s3cret") && !out.contains("t0k"), "{out}");
        }
        assert!(text.contains("https://***@corp.example/simple"), "{text}");
    }

    #[test]
    fn system_pip_config_comes_from_inputs() {
        let d = tempfile::tempdir().unwrap();
        let sys = tempfile::tempdir().unwrap();
        let appdata = tempfile::tempdir().unwrap();
        write(
            sys.path(),
            "pip.conf",
            "[global]\nextra-index-url = https://sys.example/simple\n",
        );
        write(
            appdata.path(),
            "pip/pip.ini",
            "[global]\nfind-links = https://win.example/links\n",
        );
        let lookup = |k: &str| (k == "APPDATA").then(|| appdata.path().display().to_string());
        let configs = [sys.path().join("pip.conf")];
        let f = inspect(&Inputs {
            dir: d.path(),
            home: None,
            server: SERVER,
            env: &lookup,
            system_pip_configs: &configs,
        });
        let b = bypasses(&f);
        assert!(b.iter().any(|(_, d)| d.contains("sys.example")), "{b:?}");
        assert!(b.iter().any(|(_, d)| d.contains("win.example")), "{b:?}");
        // Without system configs nothing outside the inputs is read (no /etc/pip.conf).
        let f = run_with(d.path(), None, HashMap::new());
        assert!(f.iter().all(|f| !f.subject.contains("pip.conf")), "{f:?}");
    }

    #[test]
    fn pip_config_continuation_lines_are_bypasses() {
        let d = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        write(
            home.path(),
            ".config/pip/pip.conf",
            "[global]\nindex-url = https://pypi.org/simple\nextra-index-url =\n    \
             https://a.example/simple\n\thttps://b.example/simple\n\
             # find-links = https://commented.example\n; also a comment\n\
             find-links: https://c.example/links\ntimeout = 60\n    https://not-a-key.example\n",
        );
        let b = bypasses(&run_with(d.path(), Some(home.path()), full_env()));
        let details: Vec<&str> = b.iter().map(|(_, d)| d.as_str()).collect();
        assert_eq!(details.len(), 3, "{details:#?}");
        assert!(details[0].starts_with("extra-index-url = https://a.example/simple"));
        assert!(details[1].starts_with("extra-index-url = https://b.example/simple"));
        assert!(details[2].starts_with("find-links = https://c.example/links"));
    }

    #[test]
    fn unreadable_project_file_is_a_warning() {
        let d = tempfile::tempdir().unwrap();
        // PowerShell 5.1 `>` writes UTF-16LE with a byte order mark.
        let mut utf16 = vec![0xff, 0xfe];
        for u in "--extra-index-url https://x.example/simple\r\ntorch\r\n".encode_utf16() {
            utf16.extend(u.to_le_bytes());
        }
        std::fs::write(d.path().join("requirements.txt"), utf16).unwrap();
        // Latin-1, not UTF-8.
        std::fs::write(
            d.path().join(".npmrc"),
            b"# caf\xe9\n@corp:registry=https://npm.corp.example/\n",
        )
        .unwrap();
        let f = run_with(d.path(), None, full_env());
        let b = bypasses(&f);
        assert!(
            b.iter()
                .any(|(s, d)| s == "requirements.txt:1" && d.contains("x.example")),
            "{f:#?}"
        );
        let warn = f
            .iter()
            .find(|f| f.level == Level::Warn && f.subject.ends_with(".npmrc"))
            .unwrap_or_else(|| panic!("{f:#?}"));
        assert!(warn.detail.contains("not inspected"), "{warn:?}");
    }
}
