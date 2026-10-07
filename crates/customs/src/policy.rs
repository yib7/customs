//! Policy evaluation (DESIGN.md section 8).
//!
//! Policy rules use what the model cannot see: registry metadata (age, existence, and how
//! a release compares with the ones before it), install scripts in young packages, and
//! explicit allow and deny lists. A verdict's decision is
//! the most severe of the model decision and every rule hit, except that an allow-list
//! entry overrides everything but a deny-list entry.

use chrono::{DateTime, Utc};
use customs_model::{Decision, Thresholds};
use customs_scan::Ecosystem;

use crate::config::{Policy, RuleSeverity, Threshold};
use crate::history::{is_nonregistry_spec, ReleaseHistory};
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
    /// This version and the releases before it, when the full package metadata was read.
    pub history: Option<&'a ReleaseHistory>,
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
    if let Some(h) = ctx.history {
        hits.extend(history_hits(policy, ctx.ecosystem, h));
    }
    PolicyOutcome {
        hits,
        allowed,
        denied,
    }
}

/// Longest install script command shown in a hit.
const SHOWN_COMMAND_CHARS: usize = 120;

fn shown_command(cmd: &str) -> String {
    let clean: String = cmd
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if clean.chars().count() > SHOWN_COMMAND_CHARS {
        let head: String = clean.chars().take(SHOWN_COMMAND_CHARS).collect();
        format!("{head}...")
    } else {
        clean
    }
}

/// The release history rules, which compare a version with the releases published before
/// it. These are heuristics, not proof: maintainers move publishing on or off CI, add native
/// build steps, hand packages over, and revive old projects. That is why most warn by
/// default (`install_script_added`, rare in legitimate releases, blocks); the model still
/// judges the archive's content.
pub fn history_hits(policy: &Policy, eco: Ecosystem, h: &ReleaseHistory) -> Vec<PolicyHit> {
    let mut hits = Vec::new();
    let mut hit = |rule: &str, severity: RuleSeverity, detail: String| {
        if let Some(severity) = severity.decision() {
            hits.push(PolicyHit {
                rule: rule.into(),
                severity,
                detail,
            });
        }
    };
    let cur = &h.current;
    let npm = eco == Ecosystem::Npm;
    let dormant = chrono::Duration::days(policy.dormant_days as i64);

    if let Some(prev) = &h.previous {
        // npm only: PyPI's JSON API reports neither attestations nor uploaders, and PyPI
        // packages have no install scripts in their metadata.
        if npm && !cur.attested && prev.attested {
            hit(
                "provenance_dropped",
                policy.provenance_dropped,
                format!(
                    "{} has no provenance attestation, but the previous release {} had one",
                    cur.version, prev.version
                ),
            );
        }
        if npm {
            let changes: Vec<String> = cur
                .install_commands
                .iter()
                .filter_map(|(script, cmd)| {
                    let before = prev.install_commands.iter().find(|(s, _)| s == script);
                    let what = match before {
                        // An empty command means only `hasInstallScript` was known.
                        Some((_, b)) if !b.is_empty() && !cmd.is_empty() && b != cmd => "changed",
                        Some(_) => return None,
                        None if cmd.is_empty() && !prev.install_commands.is_empty() => return None,
                        None => "added",
                    };
                    Some(if cmd.is_empty() {
                        format!("{script} {what} since {}", prev.version)
                    } else {
                        format!(
                            "{script} {what} since {}: {}",
                            prev.version,
                            shown_command(cmd)
                        )
                    })
                })
                .collect();
            if !changes.is_empty() {
                hit(
                    "install_script_added",
                    policy.install_script_added,
                    changes.join("; "),
                );
            }
            let off_registry: Vec<String> = cur
                .dependencies
                .iter()
                .filter(|(n, s)| {
                    is_nonregistry_spec(s)
                        && !prev.dependencies.iter().any(|(p, q)| p == n && q == s)
                })
                .map(|(n, s)| format!("{n} -> {}", shown_command(s)))
                .collect();
            if !off_registry.is_empty() {
                hit(
                    "nonregistry_dependency_added",
                    policy.nonregistry_dependency_added,
                    format!(
                        "dependency fetched outside the registry, new since {}: {}",
                        prev.version,
                        off_registry.join("; ")
                    ),
                );
            }
        }
        if let (Some(c), Some(p)) = (cur.published, prev.published) {
            if c - p > dormant {
                hit(
                    "dormant_revival",
                    policy.dormant_revival,
                    format!(
                        "first release in {}: the previous release {} was published on {} (policy: {} days)",
                        human_duration(c - p),
                        prev.version,
                        p.format("%Y-%m-%d"),
                        policy.dormant_days
                    ),
                );
            }
        }
    }

    if npm {
        if let Some(p) = &cur.publisher {
            if !h.recent_publishers.is_empty() && !h.recent_publishers.contains(p) {
                let before: Vec<String> = h
                    .recent_publishers
                    .iter()
                    .map(|n| format!("'{n}'"))
                    .collect();
                hit(
                    "publisher_changed",
                    policy.publisher_changed,
                    format!(
                        "published by '{p}'; the previous releases were published by {}",
                        before.join(", ")
                    ),
                );
            }
        }
    }

    if npm {
        let young = chrono::Duration::days(policy.young_dependency_days as i64);
        let flagged: Vec<String> = h
            .added_dependencies
            .iter()
            .filter_map(|d| {
                let info = d.info.as_ref()?;
                if !info.exists {
                    return Some(format!("{} is not on the registry", d.name));
                }
                // A maintainer's own new package (platform binaries, monorepo siblings) is
                // routine; a brand-new package from someone else is how hijacked releases
                // pull in their payload.
                if info.people.iter().any(|p| h.people.contains(p)) {
                    return None;
                }
                let (created, published) = (info.created?, cur.published?);
                (published - created < young).then(|| {
                    format!(
                        "{} was first published {} before this release",
                        d.name,
                        human_duration(published - created)
                    )
                })
            })
            .collect();
        if !flagged.is_empty() {
            hit(
                "young_dependency_added",
                policy.young_dependency_added,
                format!(
                    "new dependency from outside the maintainers: {}",
                    flagged.join("; ")
                ),
            );
        }
    }

    if let (Some(major), Some(hi)) = (h.current_major, &h.highest_prior) {
        let detail = if major > hi.major.saturating_add(1) {
            Some(format!(
                "jumps from {} to {}, more than one major version",
                hi.version, cur.version
            ))
        } else if major < hi.major {
            let quiet = match (&h.line_previous, cur.published) {
                (None, _) => Some(format!("there was no earlier {major}.x release")),
                (Some(lp), Some(c)) if c - lp.published > dormant => Some(format!(
                    "the {major}.x line had no release for {} (since {})",
                    human_duration(c - lp.published),
                    lp.version
                )),
                _ => None,
            };
            quiet.map(|q| {
                format!(
                    "{} extends the old {major}.x line while {} is out; {q}",
                    cur.version, hi.version
                )
            })
        } else {
            None
        };
        if let Some(d) = detail {
            hit("version_anomaly", policy.version_anomaly, d);
        }
    }
    hits
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
            history: None,
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

    // ------------------------------------------------------------ release history rules

    use crate::history::{release_history, DependencyInfo};
    use crate::registry::{parse_npm_packument, parse_pypi_project, PackageMeta};
    use serde_json::{json, Value};

    /// A version document: publisher, provenance, and scripts.
    fn doc(publisher: Option<&str>, attested: bool, scripts: Value) -> Value {
        let mut d = json!({"dist": {"tarball": "https://r/x.tgz"}, "scripts": scripts});
        if let Some(p) = publisher {
            d["_npmUser"] = json!({"name": p, "email": "p@example.com"});
        }
        if attested {
            d["dist"]["attestations"] = json!({
                "url": "https://registry.npmjs.org/-/npm/v1/attestations/x",
                "provenance": {"predicateType": "https://slsa.dev/provenance/v1"}
            });
        }
        d
    }

    fn npm(rows: &[(&str, &str, Value)]) -> PackageMeta {
        let mut time = serde_json::Map::new();
        let mut versions = serde_json::Map::new();
        for (v, t, d) in rows {
            time.insert(v.to_string(), json!(t));
            versions.insert(v.to_string(), d.clone());
        }
        parse_npm_packument(&json!({"name": "@acme/widget", "time": time, "versions": versions}))
            .unwrap()
    }

    fn history_for(p: &Policy, m: &PackageMeta, v: &str) -> Vec<PolicyHit> {
        history_hits(p, m.ecosystem, &release_history(m, v).unwrap())
    }

    fn rules(hits: &[PolicyHit]) -> Vec<&str> {
        hits.iter().map(|h| h.rule.as_str()).collect()
    }

    #[test]
    fn provenance_dropped() {
        let m = npm(&[
            (
                "1.0.0",
                "2025-01-01T00:00:00Z",
                doc(Some("a"), false, json!({})),
            ),
            (
                "1.1.0",
                "2025-02-01T00:00:00Z",
                doc(Some("a"), true, json!({})),
            ),
            (
                "1.2.0-rc.1",
                "2025-02-15T00:00:00Z",
                doc(Some("a"), true, json!({})),
            ),
            (
                "1.1.1",
                "2025-03-01T00:00:00Z",
                doc(Some("a"), false, json!({})),
            ),
            (
                "1.2.0-rc.2",
                "2025-03-02T00:00:00Z",
                doc(Some("a"), false, json!({})),
            ),
        ]);
        let p = Policy::default();
        let hits = history_for(&p, &m, "1.1.1");
        assert_eq!(rules(&hits), vec!["provenance_dropped"]);
        assert_eq!(hits[0].severity, Decision::Warn);
        assert_eq!(
            hits[0].detail,
            "1.1.1 has no provenance attestation, but the previous release 1.1.0 had one"
        );
        // Attested releases, and a release after an unattested one, are fine.
        assert!(history_for(&p, &m, "1.1.0").is_empty());
        assert!(history_for(&p, &m, "1.0.0").is_empty());
        // A prerelease is compared with whatever was published just before it.
        let hits = history_for(&p, &m, "1.2.0-rc.2");
        assert!(hits.is_empty(), "{hits:?}");

        let block = Policy {
            provenance_dropped: RuleSeverity::Block,
            ..Policy::default()
        };
        assert_eq!(
            history_for(&block, &m, "1.1.1")[0].severity,
            Decision::Block
        );
        let off = Policy {
            provenance_dropped: RuleSeverity::Off,
            ..Policy::default()
        };
        assert!(history_for(&off, &m, "1.1.1").is_empty());

        // A stable release skips the attested prerelease published just before it, and a
        // prerelease does not.
        let m = npm(&[
            ("2.0.0", "2025-01-01T00:00:00Z", doc(None, false, json!({}))),
            (
                "2.1.0-rc.1",
                "2025-01-02T00:00:00Z",
                doc(None, true, json!({})),
            ),
            ("2.1.0", "2025-01-03T00:00:00Z", doc(None, false, json!({}))),
            (
                "2.2.0-rc.1",
                "2025-01-04T00:00:00Z",
                doc(None, false, json!({})),
            ),
        ]);
        assert!(history_for(&p, &m, "2.1.0").is_empty());
        let m = npm(&[
            ("2.0.0", "2025-01-01T00:00:00Z", doc(None, false, json!({}))),
            (
                "2.1.0-rc.1",
                "2025-01-02T00:00:00Z",
                doc(None, true, json!({})),
            ),
            (
                "2.1.0-rc.2",
                "2025-01-03T00:00:00Z",
                doc(None, false, json!({})),
            ),
        ]);
        assert_eq!(
            rules(&history_for(&p, &m, "2.1.0-rc.2")),
            vec!["provenance_dropped"]
        );
    }

    #[test]
    fn install_script_added() {
        let long = format!("node -e \"{}\"", "x".repeat(300));
        let m = npm(&[
            (
                "1.0.0",
                "2025-01-01T00:00:00Z",
                doc(None, false, json!({"test": "jest"})),
            ),
            (
                "1.0.1",
                "2025-01-02T00:00:00Z",
                doc(None, false, json!({"postinstall": "node setup.js"})),
            ),
            (
                "1.0.2",
                "2025-01-03T00:00:00Z",
                doc(None, false, json!({"postinstall": "node setup.js"})),
            ),
            (
                "1.0.3",
                "2025-01-04T00:00:00Z",
                doc(
                    None,
                    false,
                    json!({"postinstall": "node bundle.js", "preinstall": "sh x.sh"}),
                ),
            ),
            (
                "1.0.4",
                "2025-01-05T00:00:00Z",
                doc(None, false, json!({"postinstall": long})),
            ),
            (
                "1.0.5",
                "2025-01-06T00:00:00Z",
                json!({"hasInstallScript": true}),
            ),
        ]);
        let p = Policy::default();
        let hits = history_for(&p, &m, "1.0.1");
        assert_eq!(rules(&hits), vec!["install_script_added"]);
        assert_eq!(
            hits[0].detail,
            "postinstall added since 1.0.0: node setup.js"
        );
        assert!(history_for(&p, &m, "1.0.2").is_empty());
        let hits = history_for(&p, &m, "1.0.3");
        assert_eq!(
            hits[0].detail,
            "preinstall added since 1.0.2: sh x.sh; postinstall changed since 1.0.2: node bundle.js"
        );
        let hits = history_for(&p, &m, "1.0.4");
        let shown = hits[0].detail.split_once(": ").unwrap().1;
        assert_eq!(shown.chars().count(), 123, "{shown}");
        assert!(shown.ends_with("..."));
        // Only `hasInstallScript` known, after a release that had scripts: not a change.
        assert!(history_for(&p, &m, "1.0.5").is_empty());
        // The first release has nothing to compare with.
        assert!(history_for(&p, &m, "1.0.0").is_empty());

        // Removing a script is fine; `hasInstallScript` alone after none is an addition.
        let m = npm(&[
            (
                "1.0.0",
                "2025-01-01T00:00:00Z",
                doc(None, false, json!({"install": "node-gyp rebuild"})),
            ),
            ("1.1.0", "2025-01-02T00:00:00Z", doc(None, false, json!({}))),
            (
                "1.2.0",
                "2025-01-03T00:00:00Z",
                json!({"hasInstallScript": true}),
            ),
        ]);
        assert!(history_for(&p, &m, "1.1.0").is_empty());
        let hits = history_for(&p, &m, "1.2.0");
        assert_eq!(hits[0].detail, "install script added since 1.1.0");
    }

    #[test]
    fn publisher_changed() {
        let row = |v: &'static str, day: u32, who: Option<&str>| {
            (
                v,
                format!("2025-01-{day:02}T00:00:00Z"),
                doc(who, false, json!({})),
            )
        };
        let rows = [
            row("1.0.0", 1, Some("old-owner")),
            row("1.0.1", 2, Some("alice")),
            row("1.0.2", 3, Some("bob")),
            row("1.0.3", 4, Some("alice")),
            row("1.0.4", 5, None),
            row("1.0.5", 6, Some("bob")),
            row("1.0.6", 7, Some("mallory")),
            row("1.0.7", 8, Some("old-owner")),
            row("1.0.8", 9, None),
        ];
        let rows: Vec<(&str, &str, Value)> = rows
            .iter()
            .map(|(v, t, d)| (*v, t.as_str(), d.clone()))
            .collect();
        let m = npm(&rows);
        let p = Policy::default();
        let hits = history_for(&p, &m, "1.0.6");
        assert_eq!(rules(&hits), vec!["publisher_changed"]);
        assert_eq!(
            hits[0].detail,
            "published by 'mallory'; the previous releases were published by 'bob', 'alice'"
        );
        // 'old-owner' published 1.0.0, which is not among the last five releases.
        assert_eq!(
            rules(&history_for(&p, &m, "1.0.7")),
            vec!["publisher_changed"]
        );
        assert!(history_for(&p, &m, "1.0.5").is_empty());
        // Unknown publisher, or no earlier publisher known: nothing to compare.
        assert!(history_for(&p, &m, "1.0.8").is_empty());
        assert!(history_for(&p, &m, "1.0.0").is_empty());
    }

    #[test]
    fn dormant_revival() {
        let m = npm(&[
            ("0.9.0", "2020-06-01T00:00:00Z", doc(None, false, json!({}))),
            ("1.0.0", "2021-01-01T00:00:00Z", doc(None, false, json!({}))),
            ("1.0.1", "2023-01-01T00:00:00Z", doc(None, false, json!({}))),
        ]);
        let p = Policy::default();
        let hits = history_for(&p, &m, "1.0.1");
        assert_eq!(rules(&hits), vec!["dormant_revival"]);
        assert_eq!(
            hits[0].detail,
            "first release in 730 days: the previous release 1.0.0 was published on 2021-01-01 (policy: 365 days)"
        );
        assert!(history_for(&p, &m, "1.0.0").is_empty());
        let p = Policy {
            dormant_days: 30,
            ..Policy::default()
        };
        assert_eq!(
            rules(&history_for(&p, &m, "1.0.0")),
            vec!["dormant_revival"]
        );

        // PyPI gets this rule, but none of the npm-only ones.
        let file = |v: &str, t: &str| {
            json!([{"filename": format!("demo-{v}.tar.gz"), "url": "u",
                    "upload_time_iso_8601": t, "packagetype": "sdist"}])
        };
        let m = parse_pypi_project(&json!({"info": {"name": "demo", "version": "2.0"},
            "releases": {"1.0": file("1.0", "2018-01-01T00:00:00Z"),
                         "2.0": file("2.0", "2024-01-01T00:00:00Z")}}))
        .unwrap();
        let hits = history_for(&Policy::default(), &m, "2.0");
        assert_eq!(rules(&hits), vec!["dormant_revival"]);
    }

    #[test]
    fn version_anomaly() {
        let m = npm(&[
            ("1.0.0", "2020-01-01T00:00:00Z", doc(None, false, json!({}))),
            ("1.4.2", "2020-06-01T00:00:00Z", doc(None, false, json!({}))),
            ("2.0.0", "2023-01-01T00:00:00Z", doc(None, false, json!({}))),
            ("4.0.0", "2023-02-01T00:00:00Z", doc(None, false, json!({}))),
            ("4.0.1", "2023-03-01T00:00:00Z", doc(None, false, json!({}))),
            ("1.4.3", "2023-04-01T00:00:00Z", doc(None, false, json!({}))),
            ("2.0.1", "2023-04-02T00:00:00Z", doc(None, false, json!({}))),
            ("3.0.0", "2023-04-03T00:00:00Z", doc(None, false, json!({}))),
        ]);
        // Off by default.
        let default_rules = rules(&history_for(&Policy::default(), &m, "4.0.0"))
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        assert!(!default_rules.contains(&"version_anomaly".to_string()));
        let p = Policy {
            version_anomaly: RuleSeverity::Warn,
            dormant_revival: RuleSeverity::Off,
            ..Policy::default()
        };
        let hits = history_for(&p, &m, "4.0.0");
        assert_eq!(rules(&hits), vec!["version_anomaly"]);
        assert_eq!(
            hits[0].detail,
            "jumps from 2.0.0 to 4.0.0, more than one major version"
        );
        // One major up, or within a major: fine.
        assert!(history_for(&p, &m, "2.0.0").is_empty());
        assert!(history_for(&p, &m, "4.0.1").is_empty());
        // A patch to the 1.x line, quiet for almost three years while 4.x is out.
        let hits = history_for(&p, &m, "1.4.3");
        assert_eq!(
            hits[0].detail,
            "1.4.3 extends the old 1.x line while 4.0.1 is out; the 1.x line had no release for 1034 days (since 1.4.2)"
        );
        // A backport to a line that was active recently is normal maintenance.
        assert!(history_for(&p, &m, "2.0.1").is_empty());
        // A major line that never had a release.
        let hits = history_for(&p, &m, "3.0.0");
        assert!(
            hits[0].detail.ends_with("there was no earlier 3.x release"),
            "{}",
            hits[0].detail
        );
    }

    fn with_deps(deps: Value) -> Value {
        let mut d = doc(Some("alice"), false, json!({}));
        d["dependencies"] = deps;
        d
    }

    #[test]
    fn nonregistry_dependency_added() {
        let m = npm(&[
            (
                "1.0.0",
                "2025-01-01T00:00:00Z",
                with_deps(json!({"a": "^1", "fork": "github:me/fork#v1"})),
            ),
            (
                "1.0.1",
                "2025-01-02T00:00:00Z",
                with_deps(json!({"a": "^1", "fork": "github:me/fork#v1"})),
            ),
            (
                "1.0.2",
                "2025-01-03T00:00:00Z",
                with_deps(
                    json!({"a": "^1", "fork": "github:me/fork#v1", "setup": "github:x/y#abc"}),
                ),
            ),
        ]);
        let p = Policy::default();
        // An unchanged git dependency is not news.
        assert!(history_for(&p, &m, "1.0.1").is_empty());
        let hits = history_for(&p, &m, "1.0.2");
        assert_eq!(rules(&hits), vec!["nonregistry_dependency_added"]);
        assert_eq!(hits[0].severity, Decision::Block);
        assert!(
            hits[0].detail.contains("setup -> github:x/y#abc"),
            "{}",
            hits[0].detail
        );
    }

    #[test]
    fn young_dependency_added() {
        let mut m = npm(&[
            (
                "1.0.0",
                "2025-01-01T00:00:00Z",
                with_deps(json!({"a": "^1"})),
            ),
            (
                "1.0.1",
                "2025-03-01T00:00:00Z",
                with_deps(json!({"a": "^1", "lure": "^1", "old": "^1", "own": "^1"})),
            ),
        ]);
        m.people = vec!["alice".into()];
        let mut h = release_history(&m, "1.0.1").unwrap();
        let t = |s: &str| s.parse::<DateTime<Utc>>().unwrap();
        let p = Policy::default();
        // Not looked up yet: nothing to judge.
        assert!(history_hits(&p, Ecosystem::Npm, &h).is_empty());
        for d in h.added_dependencies.iter_mut() {
            d.info = Some(match d.name.as_str() {
                "lure" => DependencyInfo {
                    exists: true,
                    created: Some(t("2025-02-28T12:00:00Z")),
                    people: vec!["stranger".into()],
                },
                "old" => DependencyInfo {
                    exists: true,
                    created: Some(t("2020-01-01T00:00:00Z")),
                    people: vec!["someone".into()],
                },
                // The maintainer's own new package.
                _ => DependencyInfo {
                    exists: true,
                    created: Some(t("2025-03-01T00:00:00Z")),
                    people: vec!["alice".into()],
                },
            });
        }
        let hits = history_hits(&p, Ecosystem::Npm, &h);
        assert_eq!(rules(&hits), vec!["young_dependency_added"]);
        assert_eq!(
            hits[0].detail,
            "new dependency from outside the maintainers: lure was first published 12 hours before this release"
        );
        // A dependency the registry does not know.
        h.added_dependencies[0].info = Some(DependencyInfo::default());
        let hits = history_hits(&p, Ecosystem::Npm, &h);
        assert!(
            hits[0].detail.contains("lure is not on the registry"),
            "{}",
            hits[0].detail
        );
        // The window is configurable.
        h.added_dependencies[0].info = Some(DependencyInfo {
            exists: true,
            created: Some(t("2025-02-20T00:00:00Z")),
            people: vec![],
        });
        assert!(history_hits(&p, Ecosystem::Npm, &h).is_empty());
        let wide = Policy {
            young_dependency_days: 30,
            ..Policy::default()
        };
        assert_eq!(
            rules(&history_hits(&wide, Ecosystem::Npm, &h)),
            vec!["young_dependency_added"]
        );
    }

    #[test]
    fn history_hits_flow_through_evaluate() {
        let m = npm(&[
            (
                "1.0.0",
                "2025-01-01T00:00:00Z",
                doc(Some("a"), true, json!({})),
            ),
            (
                "1.0.1",
                "2025-01-02T00:00:00Z",
                doc(Some("b"), false, json!({"preinstall": "node x.js"})),
            ),
        ]);
        let h = release_history(&m, "1.0.1").unwrap();
        let mut c = ctx(Ecosystem::Npm, "@acme/widget", Some("1.0.1"));
        c.history = Some(&h);
        let o = evaluate(&policy(), &c);
        assert_eq!(
            rules(&o.hits),
            vec![
                "provenance_dropped",
                "install_script_added",
                "publisher_changed"
            ]
        );
        // `install_script_added` blocks by default; the other two warn.
        assert_eq!(o.decide(Decision::Allow), Decision::Block);
        let warn_only = Policy {
            install_script_added: RuleSeverity::Warn,
            ..policy()
        };
        assert_eq!(
            evaluate(&warn_only, &c).decide(Decision::Allow),
            Decision::Warn
        );
        // The allow list still overrides.
        let p = Policy {
            allow: vec!["npm:@acme/widget".into()],
            ..Policy::default()
        };
        assert_eq!(evaluate(&p, &c).decide(Decision::Allow), Decision::Allow);
    }
}
