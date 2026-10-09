//! MCP server configurations: `.mcp.json` (Claude Code), `.cursor/mcp.json`,
//! `.vscode/mcp.json`, `.gemini/settings.json`, `.codex/config.toml`, Claude Desktop's
//! `claude_desktop_config.json`, Windsurf's `mcp_config.json` and `~/.claude.json`.
//!
//! An agent starts each configured server itself, usually as `npx -y package` or
//! `uvx package`, before any tool call, so the hook never sees the install, and a desktop
//! app does not read the shell variables that point installers at the proxy. Without a
//! version the launcher fetches the newest release at every start, which is how a
//! compromised release reaches every user at once (postmark-mcp 1.0.16, September 2025,
//! copied every email it sent to its author). Each launched package is checked: a pinned
//! one at its version, an unpinned one at the newest release, which is what would run now.

use std::path::Path;

use customs_scan::Ecosystem;
use serde_json::Value;

use super::{json_key_lines, key_line, Parsed, SkipKind};
use crate::hook::parse::{looks_like_path, looks_like_url, parse_command, Target};

/// File names read as MCP configurations. `settings.json` and `config.toml` count only
/// inside `.gemini` and `.codex`.
pub fn is_mcp_config(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let parent = path
        .parent()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("");
    matches!(
        name,
        ".mcp.json"
            | "mcp.json"
            | "mcp_config.json"
            | "claude_desktop_config.json"
            | ".claude.json"
    ) || (name == "settings.json" && parent == ".gemini")
        || (name == "config.toml" && parent == ".codex")
}

/// Where agents keep project MCP configurations, relative to the project directory.
pub const PROJECT_CONFIGS: &[&str] = &[
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".gemini/settings.json",
    ".codex/config.toml",
];

/// One configured server: its name, the line that names it, and how it is started.
struct Server {
    name: String,
    line: usize,
    command: String,
    args: Vec<String>,
}

fn servers_in(map: &Value, key_path: &[&str], lines: &dyn Fn(&[&str]) -> usize) -> Vec<Server> {
    let Some(obj) = map.as_object() else {
        return Vec::new();
    };
    obj.iter()
        .filter_map(|(name, s)| {
            let command = s.get("command")?.as_str()?.to_string();
            let args = s
                .get("args")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let mut path = key_path.to_vec();
            path.push(name);
            Some(Server {
                name: name.clone(),
                line: lines(&path),
                command,
                args,
            })
        })
        .collect()
}

fn shell_word(s: &str) -> String {
    let plain = !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b));
    if plain {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// An exact registry version, as opposed to a range or a tag.
fn is_exact(eco: Ecosystem, v: &str) -> bool {
    let v = v.strip_prefix("==").unwrap_or(v);
    v.starts_with(|c: char| c.is_ascii_digit())
        && match eco {
            Ecosystem::Npm => v
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+')),
            Ecosystem::Pypi => !v.contains(['<', '>', '=', '!', '~', '*', ',', ';', ' ']),
        }
}

pub fn parse(text: &str, path: &Path, out: &mut Parsed) -> Result<(), String> {
    let is_toml = path.extension().is_some_and(|e| e == "toml");
    let servers = if is_toml {
        let doc: toml::Value = toml::from_str(text).map_err(|e| e.message().to_string())?;
        let v = serde_json::to_value(doc).map_err(|e| e.to_string())?;
        let header_line = |p: &[&str]| {
            let name = p.last().copied().unwrap_or("");
            text.lines()
                .position(|l| {
                    let l = l.trim();
                    l == format!("[mcp_servers.{name}]") || l == format!("[mcp_servers.\"{name}\"]")
                })
                .map_or(1, |i| i + 1)
        };
        servers_in(&v["mcp_servers"], &["mcp_servers"], &header_line)
    } else {
        let v: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let lines = json_key_lines(text);
        let at = |p: &[&str]| key_line(&lines, p);
        let mut all = servers_in(&v["mcpServers"], &["mcpServers"], &at);
        // VS Code.
        all.extend(servers_in(&v["servers"], &["servers"], &at));
        // `~/.claude.json` keeps each project's servers under its path.
        if let Some(projects) = v["projects"].as_object() {
            for (dir, p) in projects {
                all.extend(servers_in(
                    &p["mcpServers"],
                    &["projects", dir, "mcpServers"],
                    &at,
                ));
            }
        }
        all
    };
    let mut servers = servers;
    // JSON objects come back sorted by key; report in file order.
    servers.sort_by_key(|s| s.line);
    let cwd = path.parent().unwrap_or(Path::new("."));
    for s in servers {
        let cmd = if s.args.is_empty() {
            // Some clients accept the whole command line in `command`.
            s.command.clone()
        } else {
            std::iter::once(shell_word(&s.command))
                .chain(s.args.iter().map(|a| shell_word(a)))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let base = s
            .command
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(&s.command)
            .trim_end_matches(".exe")
            .to_string();
        if matches!(base.as_str(), "docker" | "podman") {
            out.skip(
                path,
                s.line,
                &format!("{}: {cmd}", s.name),
                SkipKind::Other,
                "a container image; Customs checks PyPI and npm packages",
            );
            continue;
        }
        for install in parse_command(&cmd, cwd) {
            for t in install.targets {
                match t {
                    Target::Package {
                        ecosystem,
                        name,
                        version,
                    } => {
                        let pinned = version.as_deref().is_some_and(|v| is_exact(ecosystem, v));
                        let version = match version {
                            Some(v) if pinned => v.trim_start_matches("==").to_string(),
                            Some(v) => v,
                            None => "latest".into(),
                        };
                        out.server_dep(ecosystem, &name, &version, pinned, path, s.line);
                    }
                    Target::Unverifiable { spec, reason, .. } => {
                        let kind = if looks_like_url(&spec) {
                            SkipKind::Source
                        } else if looks_like_path(&spec) {
                            SkipKind::Local
                        } else {
                            SkipKind::Other
                        };
                        out.skip(path, s.line, &format!("{}: {spec}", s.name), kind, reason);
                    }
                    Target::RemoteScript { url, runner } => {
                        out.skip(
                            path,
                            s.line,
                            &format!("{}: {url}", s.name),
                            SkipKind::Source,
                            format!("downloads a script and runs it with {runner}"),
                        );
                    }
                    Target::Project { .. } => {}
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn deps(text: &str, file: &str) -> Parsed {
        let mut out = Parsed::default();
        parse(text, Path::new(file), &mut out).unwrap();
        out
    }

    #[test]
    fn reads_each_agents_config() {
        let claude = r#"{
  "mcpServers": {
    "postmark": { "command": "npx", "args": ["-y", "postmark-mcp"] },
    "fs": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.8.21", "/tmp"] },
    "fetch": { "command": "uvx", "args": ["mcp-server-fetch==2025.4.7"] },
    "git": { "command": "uvx", "args": ["--from", "git+https://github.com/x/y", "y"] },
    "gh": { "command": "docker", "args": ["run", "-i", "ghcr.io/github/github-mcp-server"] },
    "local": { "command": "node", "args": ["./server.js"] },
    "remote": { "type": "http", "url": "https://mcp.example/mcp" }
  }
}"#;
        let p = deps(claude, "proj/.mcp.json");
        let got: Vec<(&str, &str, bool, usize)> = p
            .deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str(), d.pinned, d.line))
            .collect();
        assert_eq!(
            got,
            vec![
                ("postmark-mcp", "latest", false, 3),
                (
                    "@modelcontextprotocol/server-filesystem",
                    "2025.8.21",
                    true,
                    4
                ),
                ("mcp-server-fetch", "2025.4.7", true, 5),
            ]
        );
        assert_eq!(p.deps[2].ecosystem, Ecosystem::Pypi);
        let skipped: Vec<(usize, &str)> = p
            .skipped
            .iter()
            .map(|s| (s.line, s.reason.as_str()))
            .collect();
        assert_eq!(skipped.len(), 2, "{skipped:?}");
        assert_eq!(skipped[0].0, 6);
        assert!(skipped[1].1.contains("container image"), "{skipped:?}");

        let vscode = r#"{"inputs": [], "servers": {"pw": {"type": "stdio", "command": "npx", "args": ["@playwright/mcp@^0.0.40"]}}}"#;
        let p = deps(vscode, "proj/.vscode/mcp.json");
        assert_eq!(p.deps[0].name, "@playwright/mcp");
        assert_eq!(p.deps[0].version, "^0.0.40");
        assert!(!p.deps[0].pinned);

        let codex = "model = \"o4\"\n\n[mcp_servers.docs]\ncommand = \"npx\"\nargs = [\"-y\", \"some-docs-mcp@1.2.3\"]\n";
        let p = deps(codex, "proj/.codex/config.toml");
        assert_eq!(
            (p.deps[0].name.as_str(), p.deps[0].pinned, p.deps[0].line),
            ("some-docs-mcp", true, 3)
        );

        let user =
            r#"{"projects": {"/home/u/app": {"mcpServers": {"x": {"command": "npx -y mcp-x"}}}}}"#;
        let p = deps(user, "home/.claude.json");
        assert_eq!(p.deps[0].name, "mcp-x");
        assert_eq!(p.deps[0].line, 1);
    }

    #[test]
    fn recognizes_config_files() {
        for f in [
            ".mcp.json",
            "a/.cursor/mcp.json",
            "a/.gemini/settings.json",
            "a/.codex/config.toml",
            "Claude/claude_desktop_config.json",
        ] {
            assert!(is_mcp_config(Path::new(f)), "{f}");
        }
        for f in ["a/settings.json", "a/config.toml", "package.json"] {
            assert!(!is_mcp_config(Path::new(f)), "{f}");
        }
    }
}
