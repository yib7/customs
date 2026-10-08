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
];

/// Configuration files where a registry or index URL can be set.
const REGISTRY_FILES: &[&str] = &[
    ".npmrc",
    "pip.conf",
    "pip.ini",
    ".yarnrc",
    ".yarnrc.yml",
    "bunfig.toml",
    "uv.toml",
];

/// Programs that write or remove the files named in their arguments.
const WRITERS: &[&str] = &[
    "tee", "cp", "mv", "rm", "unlink", "shred", "truncate", "dd", "install", "ln", "rsync",
    "sponge", "ed", "ex", "vi", "vim", "nvim", "nano", "emacs", "python", "python3", "node",
    "ruby", "chmod", "chown",
];

/// Leading words that run the rest of the line as the command.
const WRAPPERS: &[&str] = &["sudo", "doas", "command", "exec", "nohup", "time", "nice"];

fn base(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// The program and its arguments, past wrappers, `env` options and variable assignments.
fn program(words: &[String]) -> Option<(&str, &[String])> {
    let mut i = 0;
    while i < words.len() {
        let w = words[i].as_str();
        let b = base(w);
        if is_assignment(w) || WRAPPERS.contains(&b) || (i > 0 && w.starts_with('-')) {
            i += 1;
        } else if b == "env" {
            i += 1;
            // `env -u VAR` takes a value.
            while i < words.len() && words[i].starts_with('-') {
                i += if words[i] == "-u" { 2 } else { 1 };
            }
        } else {
            return Some((b, &words[i + 1..]));
        }
    }
    None
}

fn is_assignment(w: &str) -> bool {
    w.split_once('=').is_some_and(|(k, _)| {
        !k.is_empty()
            && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !k.starts_with(|c: char| c.is_ascii_digit())
    })
}

/// Whether a value points at this Customs server (same port on a loopback name, or the
/// server's own authority).
fn points_at_customs(value: &str, server: &str) -> bool {
    let authority = server
        .split_once("://")
        .map_or(server, |(_, r)| r)
        .split('/')
        .next()
        .unwrap_or("");
    if !authority.is_empty() && value.contains(authority) {
        return true;
    }
    let port = authority.rsplit_once(':').map(|(_, p)| p).unwrap_or("");
    !port.is_empty()
        && ["localhost", "127.0.0.1", "[::1]"]
            .iter()
            .any(|h| value.contains(&format!("{h}:{port}")))
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
        }
    }
    if writes
        && REGISTRY_FILES.iter().any(|f| lower.contains(f))
        && ["registry", "index"].iter().any(|k| lower.contains(k))
        && !points_at_customs(command, server)
    {
        out.push("changes a package manager's registry or index configuration".to_string());
    }

    for words in &cmds {
        // Assignments before a command, and `export`/`declare` arguments.
        let assigned = words
            .iter()
            .take_while(|w| is_assignment(w) || matches!(w.as_str(), "export" | "declare"))
            .chain(
                program(words)
                    .filter(|(p, _)| matches!(*p, "export" | "declare" | "set"))
                    .map(|(_, a)| a.iter())
                    .into_iter()
                    .flatten(),
            )
            .filter_map(|w| w.split_once('='));
        for (k, v) in assigned {
            if REGISTRY_VARS.contains(&k.to_ascii_lowercase().as_str())
                && !points_at_customs(v, server)
            {
                out.push(format!("points {k} away from the Customs proxy"));
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
        let arg = |i: usize| args.get(i).map(String::as_str).unwrap_or("");
        let mentions_customs = args
            .iter()
            .any(|a| a.to_ascii_lowercase().contains("customs"));
        match p {
            "npm" | "pnpm" | "yarn" | "bun" if arg(0) == "config" => {
                let key = arg(2).to_ascii_lowercase();
                let changes = matches!(arg(1), "set" | "delete" | "rm" | "unset" | "edit");
                if changes
                    && (key.contains("registry") || arg(1) == "edit")
                    && !args.iter().any(|a| points_at_customs(a, server))
                {
                    out.push(format!("changes the {p} registry setting"));
                }
            }
            "pip" | "pip3" if arg(0) == "config" => {
                let changes = matches!(arg(1), "set" | "unset" | "edit");
                if changes
                    && (arg(2).contains("index") || arg(1) == "edit")
                    && !args.iter().any(|a| points_at_customs(a, server))
                {
                    out.push("changes pip's index setting".to_string());
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

/// Reason an Edit, Write or MultiEdit call on `path` would disable or bypass Customs.
/// Files where an agent registers the Customs hook (project, user and system scopes).
const AGENT_SETTINGS: [(&str, &str); 4] = [
    (".claude/settings", "Claude Code settings"),
    ("cursor/hooks.json", "Cursor hooks"),
    (".gemini/settings.json", "Gemini CLI settings"),
    ("gemini-cli/settings.json", "Gemini CLI settings"),
];

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
    if REGISTRY_FILES.contains(&name) {
        let text = tool_input.to_string().to_ascii_lowercase();
        if ["registry", "index"].iter().any(|k| text.contains(k))
            && !points_at_customs(&text, server)
        {
            return Some("changes a package manager's registry or index configuration".into());
        }
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
}
