//! Policy evaluation (DESIGN.md section 8).
//!
//! Policy rules use what the model cannot see: registry metadata (age, existence), install
//! scripts in young packages, and explicit allow and deny lists. A verdict's decision is
//! the most severe of the model decision and every rule hit, except that an allow-list
//! entry overrides everything but a deny-list entry.

use chrono::{DateTime, Utc};
use customs_model::{Decision, Thresholds};
use customs_scan::Ecosystem;

use crate::config::{Policy, Threshold};
use crate::util::{human_duration, normalize_name, registry_name};
use crate::verdict::PolicyHit;

/// Facts about one package version that the rules look at.
#[derive(Debug, Clone)]
pub struct PolicyContext<'a> {
    pub ecosystem: Ecosystem,
    pub name: &'a str,
    pub version: Option<&'a str>,
    /// False when the registry does not know the name.
    pub exists: bool,
    /// Publication time of this version (or file), when the registry reports it.
    pub published: Option<DateTime<Utc>>,
    /// Install scripts declared (npm `preinstall`/`install`/`postinstall`), if known.
    pub install_scripts: Vec<String>,
    pub now: DateTime<Utc>,
}

/// Outcome of the rules for one package.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyOutcome {
    pub hits: Vec<PolicyHit>,
    pub allowed: bool,
    pub denied: bool,
}

impl PolicyOutcome {
    /// Combine with the model decision.
    pub fn decide(&self, model: Decision) -> Decision {
        if self.denied {
            return Decision::Block;
        }
        if self.allowed {
            return Decision::Allow;
        }
        self.hits
            .iter()
            .map(|h| h.severity)
            .fold(model, std::cmp::max)
    }
}

pub fn evaluate(policy: &Policy, ctx: &PolicyContext<'_>) -> PolicyOutcome {
    let name = normalize_name(ctx.ecosystem, ctx.name);
    let mut hits = Vec::new();

    let denied = policy
        .deny_rules()
        .iter()
        .find(|r| r.matches(ctx.ecosystem, &name, ctx.version))
        .map(|r| {
            hits.push(PolicyHit {
                rule: "deny".into(),
                severity: Decision::Block,
                detail: format!("{r} is on the deny list"),
            })
        })
        .is_some();
    let allowed = !denied
        && policy
            .allow_rules()
            .iter()
            .find(|r| r.matches(ctx.ecosystem, &name, ctx.version))
            .map(|r| {
                hits.push(PolicyHit {
                    rule: "allow".into(),
                    severity: Decision::Allow,
                    detail: format!("{r} is on the allow list"),
                })
            })
            .is_some();

    if !ctx.exists {
        hits.push(PolicyHit {
            rule: "block_nonexistent".into(),
            severity: if policy.block_nonexistent {
                Decision::Block
            } else {
                Decision::Warn
            },
            detail: format!(
                "'{}' does not exist on {} (possibly a hallucinated or mistyped name)",
                ctx.name,
                registry_name(ctx.ecosystem)
            ),
        });
    }

    let min_age = chrono::Duration::days(policy.min_age_days as i64);
    let young = match ctx.published {
        Some(p) if policy.min_age_days > 0 => {
            let age = ctx.now - p;
            (age < min_age).then_some(age)
        }
        _ => None,
    };
    if let Some(age) = young {
        hits.push(PolicyHit {
            rule: "min_age_days".into(),
            severity: policy.min_age_severity.decision(),
            detail: format!(
                "published {} ago (policy: {} day{})",
                human_duration(age),
                policy.min_age_days,
                if policy.min_age_days == 1 { "" } else { "s" }
            ),
        });
        if policy.block_install_scripts_from_new
            && ctx.ecosystem == Ecosystem::Npm
            && !ctx.install_scripts.is_empty()
        {
            hits.push(PolicyHit {
                rule: "block_install_scripts_from_new".into(),
                severity: Decision::Block,
                detail: format!(
                    "runs install scripts ({}) and was published {} ago",
                    ctx.install_scripts.join(", "),
                    human_duration(age)
                ),
            });
        }
    }
    PolicyOutcome {
        hits,
        allowed,
        denied,
    }
}

/// Thresholds after applying numeric overrides from the policy.
pub fn effective_thresholds(policy: &Policy, model: Thresholds) -> Thresholds {
    let pick = |t: Threshold, m: f64| match t {
        Threshold::Model => m,
        Threshold::Value(v) => v,
    };
    Thresholds {
        warn: pick(policy.warn_threshold, model.warn),
        block: pick(policy.block_threshold, model.block),
        ..model
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AgeSeverity;

    fn ctx<'a>(eco: Ecosystem, name: &'a str, version: Option<&'a str>) -> PolicyContext<'a> {
        PolicyContext {
            ecosystem: eco,
            name,
            version,
            exists: true,
            published: None,
            install_scripts: Vec::new(),
            now: Utc::now(),
        }
    }

    fn policy() -> Policy {
        Policy {
            allow: vec!["pypi:requests".into(), "npm:event-stream".into()],
            deny: vec!["npm:event-stream@3.3.6".into(), "pypi:evil-pkg".into()],
            ..Policy::default()
        }
    }

    #[test]
    fn clean_package_passes() {
        let o = evaluate(&policy(), &ctx(Ecosystem::Pypi, "flask", Some("3.0.0")));
        assert!(o.hits.is_empty());
        assert_eq!(o.decide(Decision::Allow), Decision::Allow);
        assert_eq!(o.decide(Decision::Warn), Decision::Warn);
    }

    #[test]
    fn allow_overrides_model_and_age() {
        let mut c = ctx(Ecosystem::Pypi, "Requests", Some("2.0"));
        c.published = Some(c.now - chrono::Duration::hours(1));
        let o = evaluate(&policy(), &c);
        assert!(o.allowed);
        assert_eq!(o.decide(Decision::Block), Decision::Allow);
        assert!(o.hits.iter().any(|h| h.rule == "min_age_days"));
    }

    #[test]
    fn deny_beats_allow() {
        let o = evaluate(
            &policy(),
            &ctx(Ecosystem::Npm, "event-stream", Some("3.3.6")),
        );
        assert!(o.denied && !o.allowed);
        assert_eq!(o.decide(Decision::Allow), Decision::Block);
        let o = evaluate(
            &policy(),
            &ctx(Ecosystem::Npm, "event-stream", Some("4.0.0")),
        );
        assert!(o.allowed);
        let o = evaluate(&policy(), &ctx(Ecosystem::Pypi, "evil_pkg", None));
        assert!(o.denied);
    }

    #[test]
    fn nonexistent() {
        let mut c = ctx(Ecosystem::Pypi, "reqeusts", None);
        c.exists = false;
        let o = evaluate(&policy(), &c);
        assert_eq!(o.decide(Decision::Allow), Decision::Block);
        assert!(o.hits[0].detail.contains("does not exist on PyPI"));
        let p = Policy {
            block_nonexistent: false,
            ..policy()
        };
        assert_eq!(evaluate(&p, &c).decide(Decision::Allow), Decision::Warn);
    }

    #[test]
    fn min_age_and_install_scripts() {
        let mut c = ctx(Ecosystem::Npm, "fresh", Some("1.0.0"));
        c.published = Some(c.now - chrono::Duration::hours(2));
        let o = evaluate(&policy(), &c);
        assert_eq!(o.hits.len(), 1);
        assert_eq!(o.hits[0].detail, "published 2 hours ago (policy: 3 days)");
        assert_eq!(o.decide(Decision::Allow), Decision::Block);

        // With a warn-only age rule, install scripts are what escalate to block.
        let p = Policy {
            min_age_severity: AgeSeverity::Warn,
            ..policy()
        };
        assert_eq!(evaluate(&p, &c).decide(Decision::Allow), Decision::Warn);
        c.install_scripts = vec!["postinstall".into()];
        let o = evaluate(&p, &c);
        assert_eq!(o.decide(Decision::Allow), Decision::Block);
        assert!(o.hits[1].detail.contains("postinstall"));
        let p2 = Policy {
            block_install_scripts_from_new: false,
            ..p.clone()
        };
        assert_eq!(evaluate(&p2, &c).decide(Decision::Allow), Decision::Warn);

        // Old enough: nothing fires.
        c.published = Some(c.now - chrono::Duration::days(10));
        assert!(evaluate(&p, &c).hits.is_empty());
        // Disabled rule.
        c.published = Some(c.now);
        let p3 = Policy {
            min_age_days: 0,
            ..policy()
        };
        assert!(evaluate(&p3, &c).hits.is_empty());
    }

    #[test]
    fn threshold_overrides() {
        let m = Thresholds {
            warn: 0.5,
            block: 0.9,
            target_fpr_block: Some(0.001),
            target_fpr_warn: None,
        };
        let p = Policy {
            block_threshold: Threshold::Value(0.8),
            ..Policy::default()
        };
        let t = effective_thresholds(&p, m);
        assert_eq!((t.warn, t.block), (0.5, 0.8));
    }
}
