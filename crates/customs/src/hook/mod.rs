//! Claude Code PreToolUse hook (DESIGN.md section 9).
//!
//! Claude Code runs `customs hook claude-code` before every Bash tool call with a JSON
//! description of the call on stdin. We find package installs in the command, check each
//! package, and answer on stdout with a `permissionDecision`: `deny` when anything is
//! blocked, `ask` when anything is warned or cannot be checked, and nothing at all (exit 0,
//! empty stdout) when everything is allowed, which leaves the normal permission flow alone.
//! Exit code 2 would also block, but its message format is less clear, so we always exit 0
//! and use JSON.

pub mod parse;
pub mod project;
pub mod shell;

use std::path::PathBuf;
use std::time::Duration;

use customs_model::Decision;
use futures::stream::{self, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::client::{CheckError, Checker, LocalOptions};
use crate::util::ecosystem_str;
use crate::verdict::Verdict;
use parse::{parse_command, Target};

#[derive(Debug, Clone)]
pub struct HookOptions {
    pub server: String,
    pub fail_closed: bool,
    pub local: LocalOptions,
}

#[derive(Debug, Deserialize)]
struct HookInput {
    #[serde(default)]
    hook_event_name: Option<String>,
    #[serde(default)]
    tool_name: Option<String>,
    #[serde(default)]
    tool_input: Option<Value>,
    #[serde(default)]
    cwd: Option<String>,
}

/// The hook's answer.
#[derive(Debug, Clone, PartialEq)]
pub struct HookDecision {
    /// `deny` or `ask`.
    pub decision: &'static str,
    pub reason: String,
}

impl HookDecision {
    pub fn to_json(&self) -> Value {
        json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": self.decision,
                "permissionDecisionReason": self.reason,
            }
        })
    }
}

/// Outcome for one target.
#[derive(Debug, Clone)]
pub enum TargetResult {
    Verdict {
        label: String,
        verdict: Box<Verdict>,
        url: Option<String>,
    },
    Unverifiable {
        label: String,
        reason: String,
    },
    PackageError {
        label: String,
        message: String,
    },
    Failed {
        label: String,
        message: String,
    },
    /// A lockfile entry that installs a different package than it names.
    Mismatch {
        label: String,
        message: String,
    },
}

pub fn target_label(t: &Target) -> String {
    match t {
        Target::Package {
            ecosystem,
            name,
            version,
        } => match version {
            Some(v) => format!("{}:{name} ({v})", ecosystem_str(*ecosystem)),
            None => format!("{}:{name}", ecosystem_str(*ecosystem)),
        },
        Target::Unverifiable {
            ecosystem, spec, ..
        } => format!("{}:{spec}", ecosystem_str(*ecosystem)),
        Target::Project { manager, dir } => {
            format!("{} project in {}", manager.as_str(), dir.display())
        }
    }
}

/// Targets with every [`Target::Project`] expanded.
#[derive(Debug, Default)]
pub struct Expanded {
    pub targets: Vec<Target>,
    /// Per target: pinned by a project's lockfile, so a warning does not count.
    pub locked: Vec<bool>,
    /// Lockfile entries that install another package than they name, each with a
    /// placeholder target.
    pub mismatches: Vec<(Target, TargetResult)>,
}

impl Expanded {
    /// Whether the result for target `i` is a warning about a package a lockfile pins.
    pub fn locked_warning(&self, i: usize, r: &TargetResult) -> bool {
        self.locked.get(i).copied().unwrap_or(false)
            && matches!(r, TargetResult::Verdict { verdict, .. } if verdict.decision == Decision::Warn)
    }
}

/// Replace each [`Target::Project`] with what that install would fetch (see [`project`]).
pub fn expand_projects(targets: Vec<Target>) -> Expanded {
    let mut out = Expanded::default();
    for t in targets {
        let Target::Project { manager, dir } = t else {
            out.targets.push(t);
            out.locked.push(false);
            continue;
        };
        let e = project::expand(manager, &dir);
        for (label, message) in e.mismatches {
            let placeholder = Target::Unverifiable {
                ecosystem: manager.ecosystem(),
                spec: label.clone(),
                reason: message.clone(),
            };
            out.mismatches
                .push((placeholder, TargetResult::Mismatch { label, message }));
        }
        out.locked
            .extend((0..e.targets.len()).map(|i| i < e.locked));
        out.targets.extend(e.targets);
    }
    out
}

/// Why a verdict came out the way it did, in one line.
pub fn verdict_summary(v: &Verdict) -> String {
    let mut parts: Vec<String> = v
        .policy_hits
        .iter()
        .filter(|h| h.severity >= Decision::Warn)
        .map(|h| h.detail.clone())
        .collect();
    if v.model_decision >= Decision::Warn {
        let mut m = match v.risk {
            Some(r) => format!("model risk {r:.2}"),
            None => "model flagged it".to_string(),
        };
        let labels: Vec<&str> = v.reasons.iter().take(3).map(|r| r.label.as_str()).collect();
        if !labels.is_empty() {
            m.push_str(&format!(" ({})", labels.join("; ")));
        }
        parts.push(m);
    } else if v.policy_hits.iter().any(|h| h.rule == "block_nonexistent") {
        // For a hallucinated name, the closest real package is the most useful hint.
        if let Some(r) = v.reasons.iter().find(|r| r.feature.starts_with("name_")) {
            parts.push(format!("name: {}", r.label));
        }
    }
    if parts.is_empty() {
        parts.push(format!("decision {}", v.decision));
    }
    parts.join("; ")
}

/// Combine per-target results into the hook answer.
pub fn decide(results: &[TargetResult], fail_closed: bool) -> Option<HookDecision> {
    let mut blocked = Vec::new();
    let mut review = Vec::new();
    for r in results {
        match r {
            TargetResult::Verdict { verdict, url, .. } => {
                let mut line = format!(
                    "{}:{}{}: {}",
                    ecosystem_str(verdict.ecosystem),
                    verdict.name,
                    verdict
                        .version
                        .as_deref()
                        .map(|v| format!(" {v}"))
                        .unwrap_or_default(),
                    verdict_summary(verdict)
                );
                if let Some(u) = url {
                    line.push_str(&format!(" [{u}]"));
                }
                match verdict.decision {
                    Decision::Block => blocked.push(line),
                    Decision::Warn => review.push(line),
                    Decision::Allow => {}
                }
            }
            TargetResult::Unverifiable { label, reason } => {
                review.push(format!("{label}: not checked, {reason}"))
            }
            TargetResult::PackageError { label, message } => {
                review.push(format!("{label}: could not be checked: {message}"))
            }
            TargetResult::Failed { label, message } => {
                if fail_closed {
                    blocked.push(format!("{label}: Customs check failed: {message}"));
                }
            }
            TargetResult::Mismatch { label, message } => {
                blocked.push(format!("{label}: {message}"))
            }
        }
    }
    if !blocked.is_empty() {
        let mut reason = String::from("Customs blocked this install:\n");
        for b in &blocked {
            reason.push_str(&format!("- {b}\n"));
        }
        for r in &review {
            reason.push_str(&format!("- (review) {r}\n"));
        }
        reason.push_str(
            "Do not retry with a different spelling or source; ask the user how to proceed.",
        );
        return Some(HookDecision {
            decision: "deny",
            reason,
        });
    }
    if !review.is_empty() {
        let mut reason = String::from("Customs flagged this install for review:\n");
        for r in &review {
            reason.push_str(&format!("- {r}\n"));
        }
        return Some(HookDecision {
            decision: "ask",
            reason: reason.trim_end().to_string(),
        });
    }
    None
}

/// Evaluate one hook invocation. `Err` is an internal failure (bad input, no checker).
pub async fn evaluate(input: &str, opts: &HookOptions) -> anyhow::Result<Option<HookDecision>> {
    let input: HookInput =
        serde_json::from_str(input).map_err(|e| anyhow::anyhow!("invalid hook input: {e}"))?;
    if input
        .hook_event_name
        .as_deref()
        .is_some_and(|e| e != "PreToolUse")
    {
        return Ok(None);
    }
    if input.tool_name.as_deref() != Some("Bash") {
        return Ok(None);
    }
    let Some(command) = input
        .tool_input
        .as_ref()
        .and_then(|t| t.get("command"))
        .and_then(Value::as_str)
    else {
        return Ok(None);
    };
    let cwd = input
        .cwd
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    let installs = parse_command(command, &cwd);
    let targets: Vec<Target> = installs.into_iter().flat_map(|i| i.targets).collect();
    let expanded = expand_projects(targets);
    let targets = &expanded.targets;
    if targets.is_empty() && expanded.mismatches.is_empty() {
        return Ok(None);
    }
    let needs_checker = targets.iter().any(|t| matches!(t, Target::Package { .. }));
    let checker = if needs_checker {
        Some(Checker::connect(&opts.server, &opts.local).await?)
    } else {
        None
    };
    let results = check_targets_within(
        targets,
        checker.as_ref(),
        "claude-code-hook",
        Some(HOOK_BUDGET),
    )
    .await;
    let mut results: Vec<TargetResult> = results
        .into_iter()
        .enumerate()
        .filter(|(i, r)| !expanded.locked_warning(*i, r))
        .map(|(_, r)| r)
        .collect();
    results.extend(expanded.mismatches.iter().map(|(_, r)| r.clone()));
    for r in &results {
        if let TargetResult::Failed { label, message } = r {
            eprintln!("customs hook: checking {label} failed: {message}");
        }
    }
    Ok(decide(&results, opts.fail_closed))
}

/// How long the hook spends checking before it stops; Claude Code's hook timeout in
/// `hooks/claude-code-settings.json` is 60 seconds. Only a large project install whose
/// verdicts are not cached yet comes near it.
const HOOK_BUDGET: Duration = Duration::from_secs(40);

/// Check every target, a few at a time. `checker` may be `None` only when no target is a
/// registry package. Results keep the order of `targets`.
pub async fn check_targets(
    targets: &[Target],
    checker: Option<&Checker>,
    client: &str,
) -> Vec<TargetResult> {
    check_targets_within(targets, checker, client, None).await
}

/// [`check_targets`], stopping after `budget`: whatever is left is reported as one
/// unverified result, so results no longer line up with `targets` then.
pub async fn check_targets_within(
    targets: &[Target],
    checker: Option<&Checker>,
    client: &str,
    budget: Option<Duration>,
) -> Vec<TargetResult> {
    let checks = stream::iter(targets.iter().cloned())
        .map(|t| async move {
            let label = target_label(&t);
            match t {
                Target::Unverifiable { reason, .. } => TargetResult::Unverifiable { label, reason },
                Target::Project { .. } => TargetResult::Failed {
                    label,
                    message: "project install was not expanded".into(),
                },
                Target::Package {
                    ecosystem,
                    name,
                    version,
                } => {
                    let Some(c) = checker else {
                        return TargetResult::Failed {
                            label,
                            message: "no checker".into(),
                        };
                    };
                    match c.check(ecosystem, &name, version.as_deref(), client).await {
                        Ok(v) => TargetResult::Verdict {
                            label,
                            url: c.verdict_url(v.id),
                            verdict: Box::new(v),
                        },
                        Err(CheckError::Package(m)) => {
                            TargetResult::PackageError { label, message: m }
                        }
                        Err(CheckError::Infrastructure(m)) => {
                            TargetResult::Failed { label, message: m }
                        }
                    }
                }
            }
        })
        .buffered(8);
    let Some(budget) = budget else {
        return checks.collect().await;
    };
    let mut results: Vec<TargetResult> = checks
        .take_until(tokio::time::sleep(budget))
        .collect()
        .await;
    let left = targets.len() - results.len();
    if left > 0 {
        results.push(TargetResult::Unverifiable {
            label: format!("{left} more package{}", if left == 1 { "" } else { "s" }),
            reason: format!(
                "not checked within {}s; run `customs audit` on the project's lockfile",
                budget.as_secs()
            ),
        });
    }
    results
}

/// Entry point: read stdin, print the decision. Always exits 0 (see module docs).
pub async fn run_claude_code(opts: HookOptions) -> i32 {
    let mut input = String::new();
    if let Err(e) = std::io::Read::read_to_string(&mut std::io::stdin(), &mut input) {
        return finish_error(&format!("reading stdin: {e}"), opts.fail_closed);
    }
    match evaluate(&input, &opts).await {
        Ok(Some(d)) => {
            println!("{}", d.to_json());
            0
        }
        Ok(None) => 0,
        Err(e) => finish_error(&e.to_string(), opts.fail_closed),
    }
}

fn finish_error(msg: &str, fail_closed: bool) -> i32 {
    eprintln!("customs hook: {msg}");
    if fail_closed {
        let d = HookDecision {
            decision: "deny",
            reason: format!(
                "Customs could not check this command ({msg}) and is configured to fail closed."
            ),
        };
        println!("{}", d.to_json());
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::PolicyHit;
    use customs_model::{Scores, Thresholds};
    use customs_scan::Ecosystem;

    fn verdict(decision: Decision) -> Verdict {
        Verdict {
            id: Some(7),
            ts: "t".into(),
            ecosystem: Ecosystem::Pypi,
            name: "reqeusts".into(),
            version: None,
            artifact: None,
            sha256: None,
            decision,
            risk: Some(0.4),
            model_decision: Decision::Allow,
            thresholds: Thresholds::default(),
            scores: Scores::default(),
            policy_hits: vec![PolicyHit {
                rule: "block_nonexistent".into(),
                severity: decision,
                detail: "'reqeusts' does not exist on PyPI".into(),
            }],
            reasons: vec![customs_model::Reason {
                feature: "name_min_edit_distance".into(),
                value: Some(1.0),
                contribution: 1.0,
                label: "1 edit from popular package 'requests'".into(),
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

    #[test]
    fn deny_mentions_reason_and_nearest_name() {
        let r = vec![TargetResult::Verdict {
            label: "pypi:reqeusts".into(),
            verdict: Box::new(verdict(Decision::Block)),
            url: Some("http://x/api/verdicts/7".into()),
        }];
        let d = decide(&r, false).unwrap();
        assert_eq!(d.decision, "deny");
        assert!(d.reason.contains("does not exist on PyPI"), "{}", d.reason);
        assert!(d.reason.contains("'requests'"), "{}", d.reason);
        assert!(d.reason.contains("http://x/api/verdicts/7"));
        let j = d.to_json();
        assert_eq!(j["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(j["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    #[test]
    fn warn_and_unverifiable_ask() {
        let r = vec![
            TargetResult::Verdict {
                label: "pypi:x".into(),
                verdict: Box::new(verdict(Decision::Warn)),
                url: None,
            },
            TargetResult::Unverifiable {
                label: "pypi:git+https://x".into(),
                reason: "installs from a URL".into(),
            },
        ];
        assert_eq!(decide(&r, false).unwrap().decision, "ask");
        let allow = vec![TargetResult::Verdict {
            label: "pypi:x".into(),
            verdict: Box::new(verdict(Decision::Allow)),
            url: None,
        }];
        assert_eq!(decide(&allow, false), None);
    }

    #[test]
    fn failures_respect_fail_mode() {
        let r = vec![TargetResult::Failed {
            label: "npm:x".into(),
            message: "connection refused".into(),
        }];
        assert_eq!(decide(&r, false), None);
        assert_eq!(decide(&r, true).unwrap().decision, "deny");
    }

    #[tokio::test]
    async fn ignores_other_tools_and_non_installs() {
        let opts = HookOptions {
            server: "http://127.0.0.1:1".into(),
            fail_closed: false,
            local: LocalOptions::default(),
        };
        let edit =
            r#"{"hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":"x"}}"#;
        assert_eq!(evaluate(edit, &opts).await.unwrap(), None);
        let ls = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls -la"},"cwd":"/tmp"}"#;
        assert_eq!(evaluate(ls, &opts).await.unwrap(), None);
        // Unverifiable specs need no checker at all.
        let git = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"pip install git+https://github.com/a/b"},"cwd":"/tmp"}"#;
        assert_eq!(evaluate(git, &opts).await.unwrap().unwrap().decision, "ask");
        assert!(evaluate("not json", &opts).await.is_err());
    }
}
