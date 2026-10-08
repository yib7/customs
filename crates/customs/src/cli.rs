//! Command-line interface.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use clap::{Args, Parser, Subcommand, ValueEnum};
use customs_model::Decision;
use customs_scan::Ecosystem;

use crate::audit::{AuditOptions, FailOn, Format};
use crate::client::{Checker, LocalOptions};
use crate::config::resolve_policy;
use crate::engine::{default_scanner, load_models, Engine, EngineConfig, Limits};
use crate::hook::{run_claude_code, HookOptions};
use crate::mcp::{run_mcp, McpOptions};
use crate::metrics::Metrics;
use crate::notify::{Format as NotifyFormat, NotifyConfig};
use crate::server::{serve_on, shutdown_signal};
use crate::util::{ecosystem_str, parse_ecosystem};
use crate::verdict::Verdict;

const DEFAULT_SERVER: &str = "http://127.0.0.1:7878";

#[derive(Debug, Parser)]
#[command(
    name = "customs",
    version,
    about = "Package firewall for AI coding agents"
)]
pub struct Cli {
    /// Log as JSON lines (to stderr).
    #[arg(long, global = true, env = "CUSTOMS_LOG_JSON")]
    pub log_json: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the registry proxy, API, and dashboard.
    Serve(ServeArgs),
    /// Check one package: `customs check pypi requests==2.32.3`, `customs check npm @scope/pkg@^1`.
    Check(CheckArgs),
    /// Check every package pinned in lockfiles: `customs audit`, `customs audit -r --format sarif`.
    Audit(AuditArgs),
    /// Scan a local archive offline and print the verdict.
    Scan(ScanArgs),
    /// Print shell exports that route pip, uv, pipenv, PDM, npm, pnpm, Yarn, Bun and Deno through the proxy.
    Env(EnvArgs),
    /// Find installs in a project that would skip the proxy: unset variables, scoped
    /// registries, extra indexes, lockfile URLs installers download as written.
    Doctor(DoctorArgs),
    /// Model Context Protocol server on stdio, so agents can check packages before installing.
    Mcp(McpArgs),
    /// Agent integrations.
    Hook {
        #[command(subcommand)]
        target: HookTarget,
    },
}

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Policy file (TOML). Default: ./customs.toml, then <data-dir>/policy.toml.
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long, default_value = "127.0.0.1:7878", env = "CUSTOMS_BIND")]
    pub bind: String,
    #[arg(long, default_value = ".customs", env = "CUSTOMS_DATA_DIR")]
    pub data_dir: PathBuf,
    #[arg(long, default_value = "web/dist")]
    pub ui_dir: PathBuf,
    /// Model directory (falls back to its dev/ placeholders).
    #[arg(long, env = "CUSTOMS_MODELS")]
    pub models: Option<PathBuf>,
    /// Artifact cache size cap in MiB; least recently used archives are removed past it.
    #[arg(long, default_value_t = 10240, env = "CUSTOMS_CACHE_MAX_MB")]
    pub cache_max_mb: u64,
    /// Webhook to post warn or block verdicts to (Slack, Discord, or any JSON receiver).
    #[arg(long, env = "CUSTOMS_NOTIFY_URL", hide_env_values = true)]
    pub notify_url: Option<String>,
    /// Payload format; `auto` picks Slack or Discord from the webhook's host, else JSON.
    #[arg(long, value_enum, default_value_t = NotifyFormatArg::Auto, env = "CUSTOMS_NOTIFY_FORMAT")]
    pub notify_format: NotifyFormatArg,
    /// The least severe decision to announce.
    #[arg(long, value_enum, default_value_t = NotifyOnArg::Block, env = "CUSTOMS_NOTIFY_ON")]
    pub notify_on: NotifyOnArg,
    /// Dashboard address used in notification links (default: the bind address when it
    /// is a specific IP).
    #[arg(long, env = "CUSTOMS_PUBLIC_URL")]
    pub public_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum NotifyFormatArg {
    Auto,
    Json,
    Slack,
    Discord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum NotifyOnArg {
    Warn,
    Block,
}

#[derive(Debug, Args, Clone)]
pub struct LocalArgs {
    /// Policy file for in-process checks.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Model directory for in-process checks.
    #[arg(long, env = "CUSTOMS_MODELS")]
    pub models: Option<PathBuf>,
    /// Cache and database directory for in-process checks (default: ~/.cache/customs).
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
}

impl LocalArgs {
    fn options(&self) -> LocalOptions {
        LocalOptions {
            config: self.config.clone(),
            models: self.models.clone(),
            data_dir: self.data_dir.clone(),
        }
    }
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// pypi or npm, or the whole spec as `<ecosystem>:<name>@<version>`.
    pub ecosystem: String,
    /// name, name==version, or name@version.
    pub package: Option<String>,
    #[arg(long)]
    pub json: bool,
    /// Server to ask; when unreachable the check runs in-process.
    #[arg(long, default_value = DEFAULT_SERVER, env = "CUSTOMS_SERVER")]
    pub server: String,
    #[command(flatten)]
    pub local: LocalArgs,
}

#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Lockfiles, or directories to search for them (default: the current directory).
    pub paths: Vec<PathBuf>,
    /// Search directories recursively, skipping node_modules, .git, .venv and target.
    #[arg(long, short)]
    pub recursive: bool,
    #[arg(long, value_enum, default_value_t)]
    pub format: Format,
    /// Write the report here instead of stdout.
    #[arg(long, short)]
    pub output: Option<PathBuf>,
    /// Exit 1 when any package is at least this severe.
    #[arg(long, value_enum, default_value_t)]
    pub fail_on: FailOn,
    /// Packages checked at once.
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u16).range(1..=256))]
    pub jobs: u16,
    /// Server to ask; when unreachable the checks run in-process.
    #[arg(long, default_value = DEFAULT_SERVER, env = "CUSTOMS_SERVER")]
    pub server: String,
    #[command(flatten)]
    pub local: LocalArgs,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Project directory (default: the current directory).
    #[arg(default_value = ".")]
    pub dir: PathBuf,
    /// The proxy installs should go through.
    #[arg(long, default_value = DEFAULT_SERVER, env = "CUSTOMS_SERVER")]
    pub server: String,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct McpArgs {
    /// Server to ask; when unreachable, checks run in-process.
    #[arg(long, default_value = DEFAULT_SERVER, env = "CUSTOMS_SERVER")]
    pub server: String,
    #[command(flatten)]
    pub local: LocalArgs,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    pub archive: PathBuf,
    #[arg(long, value_enum)]
    pub ecosystem: Option<EcoArg>,
    /// Package name for the name model (default: from the file name).
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub config: Option<PathBuf>,
    #[arg(long, env = "CUSTOMS_MODELS")]
    pub models: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum EcoArg {
    Pypi,
    Npm,
}

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum ShellArg {
    #[default]
    Sh,
    Fish,
    Powershell,
}

#[derive(Debug, Args)]
pub struct EnvArgs {
    #[arg(long, default_value = DEFAULT_SERVER, env = "CUSTOMS_SERVER")]
    pub server: String,
    #[arg(long, value_enum, default_value_t)]
    pub shell: ShellArg,
}

#[derive(Debug, Subcommand)]
pub enum HookTarget {
    /// Claude Code PreToolUse hook: reads the tool call on stdin, prints a decision.
    ClaudeCode {
        #[arg(long, default_value = DEFAULT_SERVER, env = "CUSTOMS_SERVER")]
        server: String,
        /// Deny the command when Customs itself fails (default: allow and log to stderr).
        #[arg(long, env = "CUSTOMS_HOOK_FAIL_CLOSED")]
        fail_closed: bool,
        #[command(flatten)]
        local: LocalArgs,
    },
}

pub fn init_logging(json: bool, default_level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_env("CUSTOMS_LOG")
        .or_else(|_| tracing_subscriber::EnvFilter::try_from_default_env())
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));
    // Logs go to stderr: the hook's stdout must carry only its JSON decision.
    use std::io::IsTerminal;
    let b = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal());
    let _ = if json {
        b.json().try_init()
    } else {
        b.try_init()
    };
}

/// Run the CLI; returns the process exit code.
pub async fn run(cli: Cli) -> i32 {
    let level = match cli.command {
        Command::Serve(_) => "info",
        _ => "warn",
    };
    init_logging(cli.log_json, level);
    let result = match cli.command {
        Command::Serve(a) => serve(a).await.map(|_| 0),
        Command::Check(a) => check(a).await,
        Command::Audit(a) => Ok(crate::audit::run(AuditOptions {
            paths: a.paths,
            recursive: a.recursive,
            format: a.format,
            output: a.output,
            fail_on: a.fail_on,
            jobs: usize::from(a.jobs),
            server: a.server,
            local: a.local.options(),
        })
        .await),
        Command::Scan(a) => scan(a),
        Command::Mcp(a) => Ok(run_mcp(McpOptions {
            server: a.server,
            local: a.local.options(),
        })
        .await),
        Command::Env(a) => {
            print!("{}", env_exports(&a.server, a.shell));
            Ok(0)
        }
        Command::Doctor(a) => Ok(crate::doctor::run(crate::doctor::DoctorOptions {
            dir: a.dir,
            server: a.server,
            json: a.json,
        })
        .await),
        Command::Hook {
            target:
                HookTarget::ClaudeCode {
                    server,
                    fail_closed,
                    local,
                },
        } => Ok(run_claude_code(HookOptions {
            server,
            fail_closed,
            local: local.options(),
        })
        .await),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("customs: {e:#}");
            1
        }
    }
}

async fn serve(a: ServeArgs) -> anyhow::Result<()> {
    let (policy, source) =
        resolve_policy(a.config.as_deref(), &a.data_dir).map_err(|e| anyhow::anyhow!("{e}"))?;
    if source.loaded {
        tracing::info!(path = %source.path.display(), mode = policy.mode.as_str(), "loaded policy");
    } else {
        tracing::info!(save_to = %source.path.display(), "no policy file; using defaults");
    }
    let models = load_models(a.models.as_deref())?;
    let engine = Engine::new(EngineConfig {
        data_dir: a.data_dir.clone(),
        models,
        policy,
        policy_path: source.path,
        scanner: default_scanner(),
        limits: Limits {
            max_cache_bytes: a.cache_max_mb << 20,
            ..Limits::default()
        },
        metrics: Arc::new(Metrics::new()),
    })?;
    let listener = tokio::net::TcpListener::bind(&a.bind)
        .await
        .map_err(|e| anyhow::anyhow!("binding {}: {e}", a.bind))?;
    let addr = listener.local_addr()?;
    let ui = a
        .ui_dir
        .join("index.html")
        .is_file()
        .then(|| a.ui_dir.clone());
    if ui.is_none() {
        tracing::warn!(ui_dir = %a.ui_dir.display(), "dashboard not built; serving a placeholder page");
    }
    if let Some(url) = a.notify_url.filter(|u| !u.trim().is_empty()) {
        let public_url = a
            .public_url
            .or_else(|| (!addr.ip().is_unspecified()).then(|| format!("http://{addr}")));
        let cfg = NotifyConfig {
            format: match a.notify_format {
                NotifyFormatArg::Auto => NotifyFormat::detect(&url),
                NotifyFormatArg::Json => NotifyFormat::Json,
                NotifyFormatArg::Slack => NotifyFormat::Slack,
                NotifyFormatArg::Discord => NotifyFormat::Discord,
            },
            url,
            min_decision: match a.notify_on {
                NotifyOnArg::Warn => Decision::Warn,
                NotifyOnArg::Block => Decision::Block,
            },
            public_url,
        };
        cfg.validate().map_err(|e| anyhow::anyhow!("{e}"))?;
        crate::notify::spawn(engine.clone(), cfg);
    }
    tracing::info!(%addr, "customs listening; run `customs env` for client settings");
    serve_on(listener, engine, ui, shutdown_signal()).await
}

/// `name==1.0`, `name@1.0`, `@scope/name@^1` into name and optional version.
pub fn split_package_arg(eco: Ecosystem, s: &str) -> (String, Option<String>) {
    if let Some((n, v)) = s.split_once("==") {
        return (n.trim().to_string(), Some(v.trim().to_string()));
    }
    let at = match eco {
        Ecosystem::Npm | Ecosystem::Pypi => s.rfind('@').filter(|i| *i > 0),
    };
    match at {
        Some(i) => (
            s[..i].to_string(),
            Some(s[i + 1..].to_string()).filter(|v| !v.is_empty()),
        ),
        None => (s.to_string(), None),
    }
}

async fn check(a: CheckArgs) -> anyhow::Result<i32> {
    let (eco_str, package) = match &a.package {
        Some(p) => (a.ecosystem.as_str(), p.as_str()),
        None => a.ecosystem.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("expected `<ecosystem> <package>` or `<ecosystem>:<package>`")
        })?,
    };
    let eco = parse_ecosystem(eco_str)
        .ok_or_else(|| anyhow::anyhow!("unknown ecosystem '{eco_str}' (use pypi or npm)"))?;
    let (name, version) = split_package_arg(eco, package);
    let checker = Checker::connect(&a.server, &a.local.options()).await?;
    let v = checker
        .check(eco, &name, version.as_deref(), "cli")
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if a.json {
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        print!(
            "{}",
            pretty(
                &v,
                checker.verdict_url(v.id).as_deref(),
                &checker.describe()
            )
        );
    }
    Ok(exit_code(v.decision))
}

/// 0 allow, 2 warn, 3 block (1 is reserved for errors).
pub fn exit_code(d: Decision) -> i32 {
    match d {
        Decision::Allow => 0,
        Decision::Warn => 2,
        Decision::Block => 3,
    }
}

fn scan(a: ScanArgs) -> anyhow::Result<i32> {
    let eco = a.ecosystem.map(|e| match e {
        EcoArg::Pypi => Ecosystem::Pypi,
        EcoArg::Npm => Ecosystem::Npm,
    });
    let v = scan_file(
        &a.archive,
        eco,
        a.name.as_deref(),
        a.config.as_deref(),
        a.models.as_deref(),
    )?;
    if a.json {
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        print!("{}", pretty(&v, None, "offline scan"));
    }
    Ok(exit_code(v.decision))
}

/// Scan a local archive offline (`customs scan`, the MCP `scan_archive` tool). The
/// ecosystem is guessed from the file name when not given.
pub fn scan_file(
    archive: &Path,
    eco: Option<Ecosystem>,
    name: Option<&str>,
    config: Option<&Path>,
    models: Option<&Path>,
) -> anyhow::Result<Verdict> {
    static SCANS: AtomicU64 = AtomicU64::new(0);
    let bytes = std::fs::read(archive)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", archive.display()))?;
    let filename = archive
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("archive")
        .to_string();
    let eco = match eco {
        Some(e) => e,
        None => customs_scan::guess_ecosystem(&filename).ok_or_else(|| {
            anyhow::anyhow!("cannot tell the ecosystem of {filename}; pass --ecosystem")
        })?,
    };
    // Offline: an in-memory engine with no network use, in a throwaway data dir.
    let tmp = std::env::temp_dir().join(format!(
        "customs-scan-{}-{}",
        std::process::id(),
        SCANS.fetch_add(1, Ordering::Relaxed)
    ));
    let (policy, source) = resolve_policy(config, &tmp).map_err(|e| anyhow::anyhow!("{e}"))?;
    let engine = Engine::new(EngineConfig {
        data_dir: tmp.clone(),
        models: load_models(models)?,
        policy,
        policy_path: source.path,
        scanner: default_scanner(),
        limits: Limits::default(),
        metrics: Arc::new(Metrics::new()),
    })?;
    let v = engine.scan_local(&bytes, &filename, eco, name);
    drop(engine);
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(v)
}

/// Human-readable verdict.
pub fn pretty(v: &Verdict, url: Option<&str>, via: &str) -> String {
    let mut s = String::new();
    let risk = v
        .risk
        .map(|r| format!("risk {r:.2}"))
        .unwrap_or_else(|| "risk n/a".into());
    s.push_str(&format!(
        "{} {} {}  {}  {}  (model {}, {})\n",
        ecosystem_str(v.ecosystem),
        v.name,
        v.version.as_deref().unwrap_or("-"),
        v.decision.as_str().to_uppercase(),
        risk,
        v.model_version,
        via
    ));
    if let Some(a) = &v.artifact {
        let sha = v
            .sha256
            .as_deref()
            .map(|h| &h[..h.len().min(12)])
            .unwrap_or("-");
        s.push_str(&format!(
            "  artifact  {a} (sha256 {sha}...){}\n",
            if v.cached { " [cached]" } else { "" }
        ));
    }
    let f = |x: Option<f64>| x.map(|v| format!("{v:.2}")).unwrap_or_else(|| "-".into());
    s.push_str(&format!(
        "  scores    code_gbdt {}  code_nn {}  name {}  (warn {:.2}, block {:.2})\n",
        f(v.scores.code_gbdt),
        f(v.scores.code_nn),
        f(v.scores.name),
        v.thresholds.warn,
        v.thresholds.block
    ));
    if !v.policy_hits.is_empty() {
        s.push_str("  policy\n");
        for h in &v.policy_hits {
            s.push_str(&format!("    [{}] {}: {}\n", h.severity, h.rule, h.detail));
        }
    }
    if !v.reasons.is_empty() {
        s.push_str("  reasons\n");
        for r in &v.reasons {
            let val = r.value.map(|x| format!(" = {x}")).unwrap_or_default();
            s.push_str(&format!(
                "    {:+.2}  {} ({}{val})\n",
                r.contribution, r.label, r.feature
            ));
        }
    }
    if !v.evidence.is_empty() {
        s.push_str("  evidence\n");
        for e in v.evidence.iter().take(10) {
            s.push_str(&format!(
                "    {}:{}  {}  {}\n",
                e.file, e.line, e.indicator, e.snippet
            ));
        }
    }
    for e in &v.scan_errors {
        s.push_str(&format!("  scan error: {e}\n"));
    }
    if let Some(u) = url {
        s.push_str(&format!("  details   {u}\n"));
    }
    s
}

/// Shell exports that send pip, uv, pipenv, PDM, npm, pnpm, Yarn, Bun and Deno through the
/// proxy. Bun, pnpm and Yarn 1 read `npm_config_registry`; Deno reads only the upper-case
/// `NPM_CONFIG_REGISTRY`, and Linux environment names are case-sensitive. Yarn 2+ reads
/// only its own variables and refuses plain-HTTP registries other than localhost unless
/// whitelisted. Pipenv takes its index from the Pipfile and ignores `PIP_INDEX_URL` unless
/// `PIPENV_PYPI_MIRROR` replaces pypi.org.
pub fn env_exports(server: &str, shell: ShellArg) -> String {
    let mut out = String::new();
    for (k, v) in env_vars(server) {
        out.push_str(&match shell {
            ShellArg::Sh => format!("export {k}=\"{v}\"\n"),
            ShellArg::Fish => format!("set -gx {k} \"{v}\"\n"),
            ShellArg::Powershell => format!("$env:{k} = \"{v}\"\n"),
        });
    }
    out
}

/// The variables behind [`env_exports`], in order.
pub fn env_vars(server: &str) -> Vec<(&'static str, String)> {
    let base = server.trim_end_matches('/');
    let simple = format!("{base}/pypi/simple");
    let npm = format!("{base}/npm/");
    let mut vars = vec![
        ("PIP_INDEX_URL", simple.clone()),
        ("UV_INDEX_URL", simple.clone()),
        ("UV_DEFAULT_INDEX", simple.clone()),
        ("PIPENV_PYPI_MIRROR", simple.clone()),
        ("PDM_PYPI_URL", simple),
        ("npm_config_registry", npm.clone()),
        ("NPM_CONFIG_REGISTRY", npm.clone()),
        ("YARN_NPM_REGISTRY_SERVER", npm),
    ];
    if let Ok(u) = url::Url::parse(base) {
        if u.scheme() == "http" {
            if let Some(host) = u.host_str() {
                vars.push(("YARN_UNSAFE_HTTP_WHITELIST", host.to_string()));
            }
        }
    }
    vars.push(("CUSTOMS_SERVER", base.to_string()));
    vars
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_args() {
        assert_eq!(
            split_package_arg(Ecosystem::Pypi, "requests==2.0"),
            ("requests".into(), Some("2.0".into()))
        );
        assert_eq!(
            split_package_arg(Ecosystem::Pypi, "requests"),
            ("requests".into(), None)
        );
        assert_eq!(
            split_package_arg(Ecosystem::Npm, "@babel/core@7.0.0"),
            ("@babel/core".into(), Some("7.0.0".into()))
        );
        assert_eq!(
            split_package_arg(Ecosystem::Npm, "@babel/core"),
            ("@babel/core".into(), None)
        );
        assert_eq!(
            split_package_arg(Ecosystem::Npm, "left-pad@^1"),
            ("left-pad".into(), Some("^1".into()))
        );
    }

    #[test]
    fn env_output() {
        let e = env_exports("http://127.0.0.1:7878/", ShellArg::Sh);
        assert!(e.contains("export PIP_INDEX_URL=\"http://127.0.0.1:7878/pypi/simple\""));
        assert!(e.contains("export npm_config_registry=\"http://127.0.0.1:7878/npm/\""));
        assert!(e.contains("export NPM_CONFIG_REGISTRY=\"http://127.0.0.1:7878/npm/\""));
        assert!(e.contains("UV_INDEX_URL"));
        assert!(e.contains("export PIPENV_PYPI_MIRROR=\"http://127.0.0.1:7878/pypi/simple\""));
        assert!(e.contains("export YARN_NPM_REGISTRY_SERVER=\"http://127.0.0.1:7878/npm/\""));
        assert!(e.contains("export YARN_UNSAFE_HTTP_WHITELIST=\"127.0.0.1\""));
        // Yarn needs no exception for an HTTPS proxy.
        assert!(!env_exports("https://customs.example", ShellArg::Sh).contains("WHITELIST"));
        assert!(env_exports("http://h", ShellArg::Fish).contains("set -gx PIP_INDEX_URL"));
    }

    #[test]
    fn cli_parses() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
        let c = Cli::try_parse_from(["customs", "hook", "claude-code", "--fail-closed"]).unwrap();
        assert!(matches!(
            c.command,
            Command::Hook {
                target: HookTarget::ClaudeCode {
                    fail_closed: true,
                    ..
                }
            }
        ));
        let c = Cli::try_parse_from(["customs", "check", "npm:@scope/pkg@1.0.0"]).unwrap();
        assert!(matches!(
            c.command,
            Command::Check(CheckArgs { package: None, .. })
        ));
        let c = Cli::try_parse_from([
            "customs",
            "audit",
            "a/uv.lock",
            "b",
            "--format",
            "sarif",
            "--fail-on",
            "warn",
            "--jobs",
            "4",
            "--recursive",
        ])
        .unwrap();
        let Command::Audit(a) = c.command else {
            panic!("expected audit");
        };
        assert_eq!(a.paths.len(), 2);
        assert_eq!(
            (a.format, a.fail_on, a.jobs, a.recursive),
            (Format::Sarif, FailOn::Warn, 4, true)
        );
        let Command::Audit(a) = Cli::try_parse_from(["customs", "audit"]).unwrap().command else {
            panic!("expected audit");
        };
        assert_eq!(
            (a.format, a.fail_on, a.jobs),
            (Format::Text, FailOn::Block, 8)
        );
        assert!(Cli::try_parse_from(["customs", "audit", "--jobs", "0"]).is_err());
        let c = Cli::try_parse_from(["customs", "mcp", "--server", "http://h:1"]).unwrap();
        assert!(
            matches!(c.command, Command::Mcp(McpArgs { ref server, .. }) if server == "http://h:1")
        );
        let c = Cli::try_parse_from(["customs", "serve", "--bind", "0.0.0.0:9000"]).unwrap();
        assert!(
            matches!(c.command, Command::Serve(ServeArgs { ref bind, .. }) if bind == "0.0.0.0:9000")
        );
        let c = Cli::try_parse_from([
            "customs",
            "serve",
            "--notify-url",
            "https://hooks.slack.com/services/x",
            "--notify-on",
            "warn",
        ])
        .unwrap();
        let Command::Serve(a) = c.command else {
            panic!("not serve")
        };
        assert_eq!(a.notify_on, NotifyOnArg::Warn);
        assert_eq!(a.notify_format, NotifyFormatArg::Auto);
    }
}
