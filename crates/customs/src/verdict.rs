//! Wire types shared by the proxy, the API, the CLI and the hook (DESIGN.md sections 6, 7).

use customs_model::{Decision, Reason, Scores, Thresholds};
use customs_scan::{Ecosystem, Evidence};
use serde::{Deserialize, Serialize};

use crate::config::Mode;

/// A policy rule that fired.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyHit {
    pub rule: String,
    /// `allow` (an informational or allow-list hit), `warn`, or `block`.
    pub severity: Decision,
    pub detail: String,
}

/// The full decision record for one package artifact (or one name that does not exist).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    /// Row id in the verdict store; `None` until stored.
    #[serde(default)]
    pub id: Option<i64>,
    pub ts: String,
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: Option<String>,
    pub artifact: Option<String>,
    pub sha256: Option<String>,
    pub decision: Decision,
    /// Calibrated model risk; `null` when no model component could run.
    pub risk: Option<f64>,
    /// Decision from the model alone, before policy rules.
    pub model_decision: Decision,
    pub thresholds: Thresholds,
    pub scores: Scores,
    pub policy_hits: Vec<PolicyHit>,
    pub reasons: Vec<Reason>,
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub install_surface: Vec<String>,
    #[serde(default)]
    pub scan_errors: Vec<String>,
    pub scanned_ms: u64,
    pub model_version: String,
    pub cached: bool,
    pub mode: Mode,
}

impl Verdict {
    /// One line for logs, 403 reason phrases and hook messages.
    pub fn headline(&self) -> String {
        let mut parts = Vec::new();
        for h in &self.policy_hits {
            if h.severity >= Decision::Warn {
                parts.push(format!("{}: {}", h.rule, h.detail));
            }
        }
        // An `established` hit sets the model aside, so its score is not a cause.
        let model_set_aside = self.policy_hits.iter().any(|h| h.rule == "established");
        if self.model_decision >= Decision::Warn && !model_set_aside {
            if let Some(r) = self.risk {
                parts.push(format!("model risk {r:.2}"));
            }
            if let Some(reason) = self.reasons.first() {
                parts.push(reason.label.clone());
            }
        }
        if parts.is_empty() {
            parts.push(format!("decision {}", self.decision));
        }
        parts.join("; ")
    }

    pub fn display_name(&self) -> String {
        match &self.version {
            Some(v) => format!("{} {}", self.name, v),
            None => self.name.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// An artifact download through the registry proxy.
    Install,
    /// A `POST /api/check` (hook, CLI, or API).
    Check,
    /// A request for a name the registry does not know.
    NonexistentPackage,
}

impl EventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventKind::Install => "install",
            EventKind::Check => "check",
            EventKind::NonexistentPackage => "nonexistent_package",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "install" => Some(EventKind::Install),
            "check" => Some(EventKind::Check),
            "nonexistent_package" => Some(EventKind::NonexistentPackage),
            _ => None,
        }
    }
}

/// One install attempt, as listed by `GET /api/events` and streamed over SSE.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub id: i64,
    pub ts: String,
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: Option<String>,
    pub client: Option<String>,
    pub kind: EventKind,
    pub decision: Option<Decision>,
    pub risk: Option<f64>,
    pub verdict_id: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use customs_model::{Reason, Scores, Thresholds};

    fn verdict(hits: Vec<PolicyHit>) -> Verdict {
        Verdict {
            id: None,
            ts: "t".into(),
            ecosystem: Ecosystem::Npm,
            name: "react".into(),
            version: Some("18.0.0".into()),
            artifact: None,
            sha256: None,
            decision: Decision::Block,
            risk: Some(0.97),
            model_decision: Decision::Block,
            thresholds: Thresholds::default(),
            scores: Scores::default(),
            policy_hits: hits,
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
            mode: Mode::Enforce,
        }
    }

    fn hit(rule: &str, severity: Decision) -> PolicyHit {
        PolicyHit {
            rule: rule.into(),
            severity,
            detail: format!("{rule} fired"),
        }
    }

    #[test]
    fn headline_omits_the_model_when_established() {
        let v = verdict(vec![hit("deny", Decision::Block)]);
        assert_eq!(
            v.headline(),
            "deny: deny fired; model risk 0.97; Downloads and executes a payload at install time"
        );
        // The established-package prior set the model aside, so it is not a cause.
        let v = verdict(vec![
            hit("established", Decision::Allow),
            hit("deny", Decision::Block),
        ]);
        assert_eq!(v.headline(), "deny: deny fired");
    }
}
