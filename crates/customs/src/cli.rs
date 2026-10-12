//! Command-line interface.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use clap::builder::BoolishValueParser;
use clap::{Args, Parser, Subcommand, ValueEnum};
use customs_model::Decision;
use customs_scan::Ecosystem;

use crate::audit::{AuditOptions, FailOn, Format};
use crate::client::{default_client_data_dir, Checker, LocalOptions};
use crate::config::resolve_policy;
use crate::engine::{default_scanner, load_models, Engine, EngineConfig, Limits};
use crate::hook::{run_agent, run_claude_code, Agent, HookOptions};
use crate::mcp::{run_mcp, McpOptions};
use crate::metrics::Metrics;
use crate::notify::{Format as NotifyFormat, NotifyConfig};
use crate::server::{serve_with, shutdown_signal, ServeOptions};
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
    #[arg(long, global = true, env = "CUSTOMS_LOG_JSON", value_parser = BoolishValueParser::new())]
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
    /// Show what a release changes relative to the one before it: `customs diff npm axios@1.14.1`, `customs diff pypi requests --from 2.31.0`.
    Diff(DiffArgs),
    /// Check every package pinned in lockfiles or launched by MCP server configurations: `customs audit`, `customs audit -r --format sarif`.
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
    /// Dashboard directory. Default: ./web/dist, then paths relative to the executable.
    #[arg(long, env = "CUSTOMS_UI_DIR")]
    pub ui_dir: Option<PathBuf>,
    /// Model directory (falls back to its dev/ placeholders). Default: ./models, then paths
    /// relative to the executable.
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
    /// Token required to change the policy through the API (`Authorization: Bearer`), at
    /// least 16 characters.
    #[arg(
        long,
        env = "CUSTOMS_ADMIN_TOKEN",
        hide_env_values = true,
        conflicts_with = "admin_token_file"
    )]
    pub admin_token: Option<String>,
    /// File holding the admin token (a mounted secret).
    #[arg(long, env = "CUSTOMS_ADMIN_TOKEN_FILE")]
    pub admin_token_file: Option<PathBuf>,
    /// Accept policy changes without a token on a server that listens beyond loopback,
    /// for a container whose published port is itself bound to loopback.
    #[arg(long, env = "CUSTOMS_ALLOW_ANONYMOUS_POLICY_CHANGES", value_parser = BoolishValueParser::new())]
    pub allow_anonymous_policy_changes: bool,
    /// Host names (comma-separated) under which the dashboard may change the policy, and a
    /// loopback server answers, besides localhost and IP addresses.
    #[arg(long, env = "CUSTOMS_ALLOWED_HOSTS", value_delimiter = ',')]
    pub allowed_hosts: Vec<String>,
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
    /// Policy file for in-process checks (default: <data-dir>/policy.toml; a project's
    /// customs.toml is never read).
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Model directory for in-process checks (default: paths relative to the executable; a
    /// project's models/ is never read).
    #[arg(long, env = "CUSTOMS_MODELS")]
    pub models: Option<PathBuf>,
    /// Cache and database directory for in-process checks (default: ~/.cache/customs, or
    /// %LOCALAPPDATA%\customs on Windows without HOME).
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
pub struct DiffArgs {
    /// pypi or npm, or the whole spec as `<ecosystem>:<name>@<version>`.
    pub ecosystem: String,
    /// name, or name@version / name==version for the newer release (default: the newest).
    pub package: Option<String>,
    /// The earlier release (default: the one published before).
    #[arg(long)]
    pub from: Option<String>,
    #[arg(long)]
    pub json: bool,
    /// Server to ask; when unreachable the diff runs in-process.
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
        #[arg(long, env = "CUSTOMS_HOOK_FAIL_CLOSED", value_parser = BoolishValueParser::new())]
        fail_closed: bool,
        #[command(flatten)]
        local: LocalArgs,
    },
    /// Cursor beforeShellExecution hook (register in .cursor/hooks.json).
    Cursor {
        #[command(flatten)]
        args: AgentHookArgs,
    },
    /// Gemini CLI BeforeTool hook (register in .gemini/settings.json).
    Gemini {
        #[command(flatten)]
        args: AgentHookArgs,
    },
    /// Codex CLI PreToolUse hook (register in ~/.codex/hooks.json).
    Codex {
        #[command(flatten)]
        args: AgentHookArgs,
    },
}

#[derive(Debug, Args)]
pub struct AgentHookArgs {
    #[arg(long, default_value = DEFAULT_SERVER, env = "CUSTOMS_SERVER")]
    pub server: String,
    /// Deny the command when Customs itself fails (default: allow and log to stderr).
    #[arg(long, env = "CUSTOMS_HOOK_FAIL_CLOSED", value_parser = BoolishValueParser::new())]
    pub fail_closed: bool,
    #[command(flatten)]
    pub local: LocalArgs,
}

impl AgentHookArgs {
    fn options(self) -> HookOptions {
        HookOptions {
            server: self.server,
            fail_closed: self.fail_closed,
            local: self.local.options(),
        }
    }
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
        Command::Diff(a) => diff(a).await,
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
        Command::Doctor(a) if !a.dir.is_dir() => {
            Err(anyhow::anyhow!("no such directory: {}", a.dir.display()))
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
        Command::Hook {
            target: HookTarget::Cursor { args },
        } => Ok(run_agent(args.options(), Agent::Cursor).await),
        Command::Hook {
            target: HookTarget::Gemini { args },
        } => Ok(run_agent(args.options(), Agent::Gemini).await),
        Command::Hook {
            target: HookTarget::Codex { args },
        } => Ok(run_agent(args.options(), Agent::Codex).await),
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
    // Settings that need no engine are checked first, so a typo fails fast.
    let ui = find_ui_dir(a.ui_dir.as_deref())?;
    let admin_token = admin_token(a.admin_token, a.admin_token_file)?;
    // The operator starts the server, so its working directory may hold the configuration.
    let here = Some(Path::new("."));
    let (policy, source) = resolve_policy(a.config.as_deref(), &a.data_dir, here)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if source.loaded {
        tracing::info!(path = %source.path.display(), mode = policy.mode.as_str(), "loaded policy");
    } else {
        tracing::info!(save_to = %source.path.display(), "no policy file; using defaults");
    }
    let models = load_models(a.models.as_deref(), here)?;
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
    let listener = tokio::net::TcpListener::bind(&a.bind).await.map_err(|e| {
        let hint = if e.kind() == std::io::ErrorKind::AddrInUse {
            "; another `customs serve` may be running there: pick another address with \
             --bind or CUSTOMS_BIND"
        } else {
            ""
        };
        anyhow::anyhow!("binding {}: {e}{hint}", a.bind)
    })?;
    let addr = listener.local_addr()?;
    if ui.is_none() {
        tracing::warn!("dashboard not built (npm run build in web/); serving a placeholder page");
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
    let opts = ServeOptions {
        admin_token,
        allow_anonymous_policy_changes: a.allow_anonymous_policy_changes,
        allowed_hosts: a.allowed_hosts,
    };
    tracing::info!(%addr, "customs listening; run `customs env` for client settings");
    serve_with(listener, engine, ui, opts, shutdown_signal()).await
}

/// The admin token from `--admin-token` / `CUSTOMS_ADMIN_TOKEN` or the token file. A token
/// that was set but is empty is an error: quietly running without one would leave a
/// loopback server open to anonymous policy changes.
fn admin_token(token: Option<String>, file: Option<PathBuf>) -> anyhow::Result<Option<String>> {
    let token = match (token, file) {
        (Some(t), _) => {
            let t = t.trim().to_string();
            anyhow::ensure!(
                !t.is_empty(),
                "the admin token (--admin-token or CUSTOMS_ADMIN_TOKEN) is empty; set one of \
                 at least {} characters, or leave it unset",
                crate::server::MIN_ADMIN_TOKEN_LEN
            );
            Some(t)
        }
        (None, Some(path)) => {
            let t = std::fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?
                .trim()
                .to_string();
            anyhow::ensure!(
                !t.is_empty(),
                "the admin token file {} is empty",
                path.display()
            );
            Some(t)
        }
        (None, None) => None,
    };
    // clap reads an empty variable as unset; one set to nothing is still a mistake.
    if token.is_none() {
        for var in ["CUSTOMS_ADMIN_TOKEN", "CUSTOMS_ADMIN_TOKEN_FILE"] {
            if std::env::var_os(var).is_some_and(|v| v.is_empty()) {
                anyhow::bail!(
                    "{var} is set but empty; give it a value, or unset it to run without an \
                     admin token"
                );
            }
        }
    }
    Ok(token)
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
    let (eco, name, version) = package_spec(&a.ecosystem, a.package.as_deref())?;
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

fn package_spec<'a>(
    ecosystem: &'a str,
    package: Option<&'a str>,
) -> anyhow::Result<(Ecosystem, String, Option<String>)> {
    let (eco_str, package) = match package {
        Some(p) => (ecosystem, p),
        None => ecosystem.split_once(':').ok_or_else(|| {
            anyhow::anyhow!("expected `<ecosystem> <package>` or `<ecosystem>:<package>`")
        })?,
    };
    let eco = parse_ecosystem(eco_str)
        .ok_or_else(|| anyhow::anyhow!("unknown ecosystem '{eco_str}' (use pypi or npm)"))?;
    let (name, version) = split_package_arg(eco, package);
    Ok((eco, name, version))
}

/// Exit code as for `check`, from the newer release's verdict.
async fn diff(a: DiffArgs) -> anyhow::Result<i32> {
    let (eco, name, to) = package_spec(&a.ecosystem, a.package.as_deref())?;
    let checker = Checker::connect(&a.server, &a.local.options()).await?;
    let d = checker
        .diff(eco, &name, a.from.as_deref(), to.as_deref(), "cli")
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    if a.json {
        println!("{}", serde_json::to_string_pretty(&d)?);
    } else {
        let url = d.verdict.as_ref().and_then(|v| checker.verdict_url(v.id));
        print!("{}", crate::diff::render_text(&d, url.as_deref()));
    }
    Ok(d.verdict.as_ref().map_or(0, |v| exit_code(v.decision)))
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
        None,
    )?;
    if a.json {
        println!("{}", serde_json::to_string_pretty(&v)?);
    } else {
        print!("{}", pretty(&v, None, "offline scan"));
    }
    Ok(exit_code(v.decision))
}

/// Scan a local archive offline (`customs scan`, the MCP `scan_archive` tool). The
/// ecosystem is guessed from the file name when not given. The policy is `config`, else
/// `<data_dir>/policy.toml` (default: the client data directory), as for in-process checks:
/// never the working directory's `customs.toml` or `models/`.
pub fn scan_file(
    archive: &Path,
    eco: Option<Ecosystem>,
    name: Option<&str>,
    config: Option<&Path>,
    models: Option<&Path>,
    data_dir: Option<&Path>,
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
    // Offline: an in-memory engine with no network use, in a throwaway data dir that is
    // removed however this returns.
    struct RemoveOnDrop(PathBuf);
    impl Drop for RemoveOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let tmp = RemoveOnDrop(std::env::temp_dir().join(format!(
        "customs-scan-{}-{}",
        std::process::id(),
        SCANS.fetch_add(1, Ordering::Relaxed)
    )));
    let policy_dir = data_dir.map_or_else(default_client_data_dir, Path::to_path_buf);
    let (policy, source) =
        resolve_policy(config, &policy_dir, None).map_err(|e| anyhow::anyhow!("{e}"))?;
    let engine = Engine::new(EngineConfig {
        data_dir: tmp.0.clone(),
        models: load_models(models, None)?,
        policy,
        policy_path: source.path,
        scanner: default_scanner(),
        limits: Limits::default(),
        metrics: Arc::new(Metrics::new()),
    })?;
    let v = engine.scan_local(&bytes, &filename, eco, name);
    // The engine holds the database open; close it before the directory goes.
    drop(engine);
    drop(tmp);
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
            .map(|h| h.chars().take(12).collect::<String>())
            .unwrap_or_else(|| "-".into());
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

/// The built dashboard: `explicit` if given (an error when it holds no `index.html`), else
/// the first of [`ui_dir_candidates`] that holds one.
fn find_ui_dir(explicit: Option<&Path>) -> anyhow::Result<Option<PathBuf>> {
    match explicit {
        Some(dir) => match first_ui_dir(&[dir.to_path_buf()]) {
            Some(d) => Ok(Some(d)),
            None => anyhow::bail!(
                "no dashboard in {} (--ui-dir or CUSTOMS_UI_DIR): it has no index.html; build \
                 it with `npm run build` in web/ and pass web/dist, or leave the option unset",
                dir.display()
            ),
        },
        None => Ok(first_ui_dir(&ui_dir_candidates(
            std::env::current_exe().ok().as_deref(),
        ))),
    }
}

/// `web/dist` under the working directory, then beside the executable: in a checkout
/// (`target/release/customs`) and in an install prefix (`bin/customs`).
fn ui_dir_candidates(exe: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from("web/dist")];
    if let Some(dir) = exe.and_then(Path::parent) {
        dirs.push(dir.join("../../web/dist"));
        dirs.push(dir.join("../share/customs/ui"));
    }
    dirs
}

fn first_ui_dir(candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates
        .iter()
        .find(|d| d.join("index.html").is_file())
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_is_found_beside_an_installed_binary() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("bin")).unwrap();
        let exe = root.path().join("bin/customs");
        let candidates = ui_dir_candidates(Some(&exe));
        assert_eq!(candidates[0], PathBuf::from("web/dist"));
        assert!(candidates.contains(&root.path().join("bin/../../web/dist")));
        let share = root.path().join("bin/../share/customs/ui");
        assert!(candidates.contains(&share));

        assert_eq!(first_ui_dir(&candidates), None);
        std::fs::create_dir_all(root.path().join("share/customs/ui")).unwrap();
        std::fs::write(root.path().join("share/customs/ui/index.html"), "<html>").unwrap();
        assert_eq!(first_ui_dir(&candidates), Some(share));
    }

    #[test]
    fn an_explicit_dashboard_dir_is_the_only_one_tried() {
        let dir = tempfile::tempdir().unwrap();
        let e = find_ui_dir(Some(dir.path())).unwrap_err().to_string();
        assert!(e.contains(&dir.path().display().to_string()), "{e}");
        std::fs::write(dir.path().join("index.html"), "<html>").unwrap();
        assert_eq!(
            find_ui_dir(Some(dir.path())).unwrap(),
            Some(dir.path().to_path_buf())
        );
    }

    #[test]
    fn pretty_survives_a_non_ascii_sha256() {
        let v: Verdict = serde_json::from_value(serde_json::json!({
            "ts": "2026-01-01T00:00:00.000Z", "ecosystem": "pypi", "name": "x", "version": "1",
            "artifact": "x-1.tar.gz", "sha256": "ééééééééééééééé", "decision": "allow",
            "risk": null, "model_decision": "allow", "thresholds": {"warn": 0.5, "block": 0.9},
            "scores": {}, "policy_hits": [], "reasons": [], "evidence": [],
            "scanned_ms": 0, "model_version": "none", "cached": false, "mode": "enforce"
        }))
        .unwrap();
        let text = pretty(&v, None, "test");
        assert!(text.contains("(sha256 éééééééééééé...)"), "{text}");
    }

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
        let c = Cli::try_parse_from([
            "customs",
            "serve",
            "--admin-token-file",
            "/run/secrets/token",
            "--allow-anonymous-policy-changes",
        ])
        .unwrap();
        let Command::Serve(a) = c.command else {
            panic!("not serve")
        };
        assert_eq!(
            a.admin_token_file.as_deref(),
            Some(std::path::Path::new("/run/secrets/token"))
        );
        assert!(a.allow_anonymous_policy_changes);
        assert!(Cli::try_parse_from([
            "customs",
            "serve",
            "--admin-token",
            "x",
            "--admin-token-file",
            "y"
        ])
        .is_err());
        for agent in ["cursor", "gemini", "codex"] {
            let c = Cli::try_parse_from(["customs", "hook", agent, "--fail-closed"]).unwrap();
            assert!(matches!(
                c.command,
                Command::Hook {
                    target: HookTarget::Cursor {
                        args: AgentHookArgs {
                            fail_closed: true,
                            ..
                        }
                    } | HookTarget::Gemini {
                        args: AgentHookArgs {
                            fail_closed: true,
                            ..
                        }
                    } | HookTarget::Codex {
                        args: AgentHookArgs {
                            fail_closed: true,
                            ..
                        }
                    }
                }
            ));
        }
    }
}
