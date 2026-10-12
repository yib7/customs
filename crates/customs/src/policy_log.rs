//! A record of policy changes made through `PUT /api/policy`: when, from where, with what
//! authorization, and which fields changed. Switching to monitor mode, allow-listing a
//! package or repointing an upstream turns protection off for everyone using the server, so
//! each change is kept in the store, listed by `GET /api/policy/changes`, and announced by
//! the webhook notifier.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::config::Policy;

/// One changed field, named by its dotted path (`mode`, `upstream.npm`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldChange {
    pub field: String,
    pub before: Value,
    pub after: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyChange {
    pub id: i64,
    pub ts: String,
    /// Address of the connection the change came in on (a proxy in front of Customs shows
    /// up as itself).
    pub remote: Option<String>,
    /// First token of the User-Agent.
    pub client: Option<String>,
    /// `token` when the admin token authorized the change, `none` when the server accepts
    /// changes without one.
    pub auth: String,
    pub changes: Vec<FieldChange>,
}

/// The fields that differ between two policies, sorted by field path. Upstream URLs are
/// compared with their credentials but shown with `***` in their place, since the change is
/// stored, listed and announced.
pub fn diff(before: &Policy, after: &Policy) -> Vec<FieldChange> {
    let mut out = Vec::new();
    let (Ok(a), Ok(b)) = (serde_json::to_value(before), serde_json::to_value(after)) else {
        return out;
    };
    walk("", &a, &b, &mut out);
    for c in &mut out {
        if c.field.starts_with("upstream.") {
            for v in [&mut c.before, &mut c.after] {
                if let Value::String(u) = v {
                    *u = crate::config::redact_upstream(u);
                }
            }
        }
    }
    out
}

fn walk(prefix: &str, a: &Value, b: &Value, out: &mut Vec<FieldChange>) {
    if let (Value::Object(x), Value::Object(y)) = (a, b) {
        let keys = x.keys().chain(y.keys().filter(|k| !x.contains_key(*k)));
        for k in keys {
            let path = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}.{k}")
            };
            walk(
                &path,
                x.get(k).unwrap_or(&Value::Null),
                y.get(k).unwrap_or(&Value::Null),
                out,
            );
        }
    } else if a != b {
        out.push(FieldChange {
            field: prefix.to_string(),
            before: a.clone(),
            after: b.clone(),
        });
    }
}

fn show(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "unset".into(),
        other => other.to_string(),
    }
}

/// One line per change: `mode: enforce -> monitor`, or for a list the entries added and
/// removed (`allow: added npm:left-pad`).
pub fn describe(c: &FieldChange) -> String {
    if let (Value::Array(a), Value::Array(b)) = (&c.before, &c.after) {
        let added: Vec<String> = b.iter().filter(|v| !a.contains(v)).map(show).collect();
        let removed: Vec<String> = a.iter().filter(|v| !b.contains(v)).map(show).collect();
        let mut parts = Vec::new();
        if !added.is_empty() {
            parts.push(format!("added {}", added.join(", ")));
        }
        if !removed.is_empty() {
            parts.push(format!("removed {}", removed.join(", ")));
        }
        if parts.is_empty() {
            parts.push("reordered".into());
        }
        return format!("{}: {}", c.field, parts.join("; "));
    }
    format!("{}: {} -> {}", c.field, show(&c.before), show(&c.after))
}

/// Whether a change can let through something the old policy stopped: a looser mode,
/// threshold or rule, a shorter age limit or history window, an allow-list entry, a removed deny-list entry,
/// or a new upstream.
pub fn loosens(c: &FieldChange) -> bool {
    let rank = |v: &Value| match v.as_str() {
        Some("off") | Some("monitor") => Some(0),
        Some("warn") => Some(1),
        Some("block") | Some("enforce") => Some(2),
        _ => None,
    };
    match (c.field.as_str(), &c.before, &c.after) {
        ("allow", Value::Array(a), Value::Array(b)) => b.iter().any(|v| !a.contains(v)),
        ("deny", Value::Array(a), Value::Array(b)) => a.iter().any(|v| !b.contains(v)),
        (f, _, _) if f.starts_with("upstream") => true,
        // The established-package prior sets the model aside: switching it on, or widening it to
        // more names or younger releases, loosens.
        ("established.enabled", Value::Bool(a), Value::Bool(b)) => !*a && *b,
        ("established.top", a, b) => match (a.as_u64(), b.as_u64()) {
            (Some(x), Some(y)) => y > x,
            _ => true,
        },
        ("established.min_age_days", a, b) => match (a.as_u64(), b.as_u64()) {
            (Some(x), Some(y)) => y < x,
            _ => true,
        },
        (_, Value::Bool(a), Value::Bool(b)) => *a && !*b,
        ("warn_threshold" | "block_threshold", a, b) => match (a.as_f64(), b.as_f64()) {
            (Some(x), Some(y)) => y > x,
            // "model" to a number, or back: cannot tell without the model's threshold.
            _ => true,
        },
        ("min_age_days" | "young_dependency_days", a, b) => {
            // Shorter is looser, and 0 (the shortest) disables the rule.
            match (a.as_u64(), b.as_u64()) {
                (Some(x), Some(y)) => y < x,
                _ => true,
            }
        }
        ("dormant_days", a, b) => match (a.as_u64(), b.as_u64()) {
            (Some(x), Some(y)) => y > x,
            _ => true,
        },
        // A shorter window exempts more releases from the history rules; 0 applies them at
        // any age, the tightest setting.
        ("history_window_days", a, b) => match (a.as_u64(), b.as_u64()) {
            (Some(_), Some(0)) => false,
            (Some(0), Some(_)) => true,
            (Some(x), Some(y)) => y < x,
            _ => true,
        },
        (_, a, b) => matches!((rank(a), rank(b)), (Some(x), Some(y)) if y < x),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Mode, RuleSeverity};

    #[test]
    fn lists_changed_fields() {
        let a = Policy::default();
        assert!(diff(&a, &a).is_empty());
        let mut b = a.clone();
        b.mode = Mode::Monitor;
        b.allow.push("npm:left-pad".into());
        b.startup_hook = RuleSeverity::Warn;
        b.upstream.npm = "https://npm.example".into();
        let d = diff(&a, &b);
        let lines: Vec<String> = d.iter().map(describe).collect();
        assert_eq!(
            lines,
            vec![
                "allow: added npm:left-pad",
                "mode: enforce -> monitor",
                "startup_hook: block -> warn",
                "upstream.npm: https://registry.npmjs.org -> https://npm.example",
            ],
        );
        assert!(d.iter().all(loosens), "{d:?}");
        // The reverse change tightens everything but the upstream.
        let back: Vec<String> = diff(&b, &a)
            .into_iter()
            .filter(loosens)
            .map(|c| c.field)
            .collect();
        assert_eq!(back, vec!["upstream.npm"]);
    }

    #[test]
    fn judges_numbers_and_lists() {
        let c = |field: &str, before: Value, after: Value| FieldChange {
            field: field.into(),
            before,
            after,
        };
        use serde_json::json;
        assert!(loosens(&c("min_age_days", json!(3), json!(0))));
        assert!(loosens(&c("min_age_days", json!(3), json!(1))));
        assert!(!loosens(&c("min_age_days", json!(0), json!(3))));
        assert!(!loosens(&c("min_age_days", json!(3), json!(7))));
        assert!(loosens(&c("block_threshold", json!(0.8), json!(0.95))));
        assert!(!loosens(&c("block_threshold", json!(0.95), json!(0.8))));
        assert!(loosens(&c("block_threshold", json!("model"), json!(0.9))));
        assert!(loosens(&c(
            "deny",
            json!(["npm:x", "npm:y"]),
            json!(["npm:y"])
        )));
        assert!(!loosens(&c(
            "deny",
            json!(["npm:y"]),
            json!(["npm:x", "npm:y"])
        )));
        assert!(loosens(&c(
            "hide_young_versions",
            json!(true),
            json!(false)
        )));
        assert!(!loosens(&c("version_anomaly", json!("off"), json!("warn"))));
        assert_eq!(
            describe(&c(
                "deny",
                json!(["npm:x", "npm:y"]),
                json!(["npm:y", "npm:z"])
            )),
            "deny: added npm:z; removed npm:x"
        );
    }

    #[test]
    fn established_loosens_when_it_widens() {
        let c = |field: &str, before: Value, after: Value| FieldChange {
            field: field.into(),
            before,
            after,
        };
        use serde_json::json;
        // Switching the prior on sets the model aside for more packages.
        assert!(loosens(&c(
            "established.enabled",
            json!(false),
            json!(true)
        )));
        assert!(!loosens(&c(
            "established.enabled",
            json!(true),
            json!(false)
        )));
        assert!(loosens(&c("established.top", json!(5000), json!(10000))));
        assert!(!loosens(&c("established.top", json!(5000), json!(100))));
        assert!(loosens(&c("established.min_age_days", json!(30), json!(7))));
        assert!(!loosens(&c(
            "established.min_age_days",
            json!(30),
            json!(90)
        )));
        let a = Policy::default();
        let mut b = a.clone();
        b.established.enabled = false;
        let d = diff(&a, &b);
        assert_eq!(
            d.iter().map(describe).collect::<Vec<_>>(),
            vec!["established.enabled: true -> false"]
        );
        assert!(!loosens(&d[0]));
    }

    #[test]
    fn shrinking_the_history_window_loosens() {
        use serde_json::json;
        let c = |before: Value, after: Value| FieldChange {
            field: "history_window_days".into(),
            before,
            after,
        };
        // 0 applies the rules at any age, the tightest setting.
        assert!(loosens(&c(json!(90), json!(1))));
        assert!(!loosens(&c(json!(1), json!(90))));
        assert!(!loosens(&c(json!(90), json!(0))));
        assert!(loosens(&c(json!(0), json!(30))));
    }
}
