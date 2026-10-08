//! Release-age resolution: hide versions younger than `min_age_days` from registry metadata.
//!
//! A blocking `min_age_days` would otherwise fail every unpinned install of a package for
//! the days after each of its releases: the resolver picks the newest version and the
//! proxy then refuses its archive. With the young versions left out of the npm packument
//! and marked yanked on the PyPI simple page, the resolver picks the newest version that
//! is old enough, which is what `minimumReleaseAge` (pnpm) and `--exclude-newer` (uv) do.
//! A version named exactly (a pin, a lockfile) is still requested, and still blocked with
//! the rule's reason; on npm a pin of a hidden version fails as "no matching version".

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};

use chrono::{DateTime, Utc};
use customs_scan::Ecosystem;
use regex::Regex;
use serde_json::Value;

use crate::config::{AgeSeverity, Mode, Policy};
use crate::registry::PackageMeta;
use crate::resolve::{compare_versions, Pep440};
use crate::util::{normalize_name, parse_pypi_filename};

/// Versions of `meta` to leave out of metadata. Empty unless enforcement would block them
/// anyway; allow-listed versions stay; and when every version is young nothing is hidden,
/// so the install fails on the rule's own message instead of "no matching version".
pub fn hidden_versions(policy: &Policy, meta: &PackageMeta, now: DateTime<Utc>) -> HashSet<String> {
    if !policy.hide_young_versions
        || policy.mode != Mode::Enforce
        || policy.min_age_days == 0
        || policy.min_age_severity != AgeSeverity::Block
    {
        return HashSet::new();
    }
    let min_age = chrono::Duration::days(policy.min_age_days as i64);
    let name = normalize_name(meta.ecosystem, &meta.name);
    let allow = policy.allow_rules();
    let deny = policy.deny_rules();
    let hidden: HashSet<String> = meta
        .versions
        .iter()
        .filter(|v| v.published.is_some_and(|p| now - p < min_age))
        .filter(|v| {
            let allowed = allow
                .iter()
                .any(|r| r.matches(meta.ecosystem, &name, Some(&v.version)));
            let denied = deny
                .iter()
                .any(|r| r.matches(meta.ecosystem, &name, Some(&v.version)));
            denied || !allowed
        })
        .map(|v| v.version.clone())
        .collect();
    if meta.versions.iter().all(|v| hidden.contains(&v.version)) {
        return HashSet::new();
    }
    hidden
}

fn is_pre(eco: Ecosystem, v: &str) -> bool {
    match eco {
        Ecosystem::Npm => semver::Version::parse(v).is_ok_and(|v| !v.pre.is_empty()),
        Ecosystem::Pypi => Pep440::parse(v).is_some_and(|v| v.is_pre()),
    }
}

/// Where a dist-tag that pointed at a hidden version should point now: the newest visible
/// version below it, a prerelease only when the tag named one. `None` drops the tag.
pub fn retarget<'a>(
    eco: Ecosystem,
    target: &str,
    visible: impl Iterator<Item = &'a str>,
) -> Option<String> {
    let pre_ok = is_pre(eco, target);
    visible
        .filter(|v| compare_versions(eco, v, target) == Ordering::Less)
        .filter(|v| pre_ok || !is_pre(eco, v))
        .max_by(|a, b| compare_versions(eco, a, b))
        .map(str::to_string)
}

fn fix_tags(
    eco: Ecosystem,
    tags: &mut BTreeMap<String, String>,
    visible: &[&str],
    hidden: &HashSet<String>,
) {
    let moved: Vec<(String, Option<String>)> = tags
        .iter()
        .filter(|(_, v)| hidden.contains(*v))
        .map(|(t, v)| (t.clone(), retarget(eco, v, visible.iter().copied())))
        .collect();
    for (tag, to) in moved {
        match to {
            Some(v) => {
                tags.insert(tag, v);
            }
            None => {
                tags.remove(&tag);
            }
        }
    }
}

/// `meta` as the proxy serves it, for resolving unpinned specs the same way.
pub fn filter_meta(meta: &PackageMeta, hidden: &HashSet<String>) -> PackageMeta {
    let mut m = meta.clone();
    if hidden.is_empty() {
        return m;
    }
    m.versions.retain(|v| !hidden.contains(&v.version));
    let visible: Vec<&str> = meta
        .versions
        .iter()
        .map(|v| v.version.as_str())
        .filter(|v| !hidden.contains(*v))
        .collect();
    fix_tags(meta.ecosystem, &mut m.dist_tags, &visible, hidden);
    m.latest = match &meta.latest {
        Some(l) if hidden.contains(l) => m
            .dist_tags
            .get("latest")
            .cloned()
            .or_else(|| retarget(meta.ecosystem, l, visible.iter().copied())),
        other => other.clone(),
    };
    m
}

/// Remove hidden versions from an npm packument (full or abbreviated) and move dist-tags
/// off them. Returns how many versions were removed.
pub fn filter_packument(doc: &mut Value, hidden: &HashSet<String>) -> usize {
    if hidden.is_empty() {
        return 0;
    }
    let mut removed = 0;
    let mut visible: Vec<String> = Vec::new();
    if let Some(versions) = doc.get_mut("versions").and_then(Value::as_object_mut) {
        let before = versions.len();
        versions.retain(|k, _| !hidden.contains(k));
        removed = before - versions.len();
        visible = versions.keys().cloned().collect();
    }
    if removed == 0 {
        return 0;
    }
    if let Some(tags) = doc.get_mut("dist-tags").and_then(Value::as_object_mut) {
        let mut map: BTreeMap<String, String> = tags
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
            .collect();
        let refs: Vec<&str> = visible.iter().map(String::as_str).collect();
        fix_tags(Ecosystem::Npm, &mut map, &refs, hidden);
        *tags = map
            .into_iter()
            .map(|(k, v)| (k, Value::String(v)))
            .collect();
    }
    removed
}

/// Whether a file on a PyPI simple page belongs to a hidden version of `project`.
fn hidden_file(project: &str, filename: &str, hidden: &HashSet<String>) -> bool {
    parse_pypi_filename(filename).is_some_and(|(n, v)| {
        normalize_name(Ecosystem::Pypi, &n) == project
            && (hidden.contains(&v)
                || Pep440::parse(&v).is_some_and(|pv| {
                    hidden
                        .iter()
                        .any(|h| Pep440::parse(h).is_some_and(|ph| ph.cmp(&pv) == Ordering::Equal))
                }))
    })
}

/// Why a held-back PyPI file is marked yanked; pip and uv print it when a pin selects one.
pub fn yank_reason(min_age_days: u32) -> String {
    format!(
        "Customs: published less than {min_age_days} days ago (min_age_days); \
         installing it is blocked"
    )
}

/// Mark hidden versions' files yanked (PEP 592) on a PEP 691 JSON simple page. Resolvers
/// skip yanked files unless a requirement pins the version with `==`, so unpinned installs
/// resolve to an older version while a pin still requests the file and gets the block
/// reason from the proxy. Files already yanked keep their reason. Returns how many files
/// were marked.
pub fn filter_simple_json(
    doc: &mut Value,
    project: &str,
    hidden: &HashSet<String>,
    reason: &str,
) -> usize {
    if hidden.is_empty() {
        return 0;
    }
    let mut marked = 0;
    if let Some(files) = doc.get_mut("files").and_then(Value::as_array_mut) {
        for f in files {
            let held = f
                .get("filename")
                .and_then(Value::as_str)
                .is_some_and(|n| hidden_file(project, n, hidden));
            let yanked = f
                .get("yanked")
                .is_some_and(|y| y.as_bool() != Some(false) && !y.is_null());
            if held && !yanked {
                f["yanked"] = Value::String(reason.to_string());
                marked += 1;
            }
        }
    }
    marked
}

fn anchor_re() -> &'static Regex {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)<a\s[^>]*>(.*?)</a>[ \t]*(?:<br\s*/?>)?[ \t]*\r?\n?").unwrap()
    })
}

/// Mark hidden versions' links yanked (`data-yanked`, PEP 592) on a PEP 503 HTML simple
/// page; see [`filter_simple_json`]. The link text is the file name on PyPI and its
/// mirrors. Returns how many links were marked.
pub fn filter_simple_html(
    html: &str,
    project: &str,
    hidden: &HashSet<String>,
    reason: &str,
) -> (String, usize) {
    if hidden.is_empty() {
        return (html.to_string(), 0);
    }
    let attr = reason
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    let mut marked = 0;
    let out = anchor_re().replace_all(html, |c: &regex::Captures| {
        let all = &c[0];
        let open_tag = &all[..all.find('>').unwrap_or(all.len())];
        if hidden_file(project, c[1].trim(), hidden)
            && !open_tag.to_ascii_lowercase().contains("data-yanked")
        {
            marked += 1;
            format!("<a data-yanked=\"{attr}\"{}", &all[2..])
        } else {
            all.to_string()
        }
    });
    (out.into_owned(), marked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::VersionMeta;
    use serde_json::json;

    fn meta(eco: Ecosystem, versions: &[(&str, i64)], latest: &str) -> PackageMeta {
        let now = now();
        PackageMeta {
            ecosystem: eco,
            name: "pkg".into(),
            latest: Some(latest.into()),
            dist_tags: [("latest".to_string(), latest.to_string())].into(),
            versions: versions
                .iter()
                .map(|(v, days_ago)| VersionMeta {
                    version: v.to_string(),
                    published: Some(now - chrono::Duration::days(*days_ago)),
                    ..Default::default()
                })
                .collect(),
            created: None,
            people: vec![],
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    #[test]
    fn hides_young_versions_only_when_enforcing() {
        let m = meta(
            Ecosystem::Npm,
            &[("1.0.0", 400), ("1.1.0", 30), ("1.2.0", 1)],
            "1.2.0",
        );
        let p = Policy::default();
        assert_eq!(hidden_versions(&p, &m, now()), ["1.2.0".to_string()].into());
        for off in [
            Policy {
                hide_young_versions: false,
                ..Policy::default()
            },
            Policy {
                mode: Mode::Monitor,
                ..Policy::default()
            },
            Policy {
                min_age_severity: AgeSeverity::Warn,
                ..Policy::default()
            },
            Policy {
                min_age_days: 0,
                ..Policy::default()
            },
            Policy {
                allow: vec!["npm:pkg".into()],
                ..Policy::default()
            },
        ] {
            assert!(hidden_versions(&off, &m, now()).is_empty());
        }
        // A package with only young versions keeps them, so the block explains itself.
        let fresh = meta(Ecosystem::Npm, &[("0.1.0", 1)], "0.1.0");
        assert!(hidden_versions(&p, &fresh, now()).is_empty());
    }

    #[test]
    fn tags_move_to_the_newest_older_version() {
        let m = meta(
            Ecosystem::Npm,
            &[
                ("1.0.0", 400),
                ("1.1.0", 30),
                ("2.0.0-rc.1", 20),
                ("2.0.0", 1),
            ],
            "2.0.0",
        );
        let hidden = hidden_versions(&Policy::default(), &m, now());
        let f = filter_meta(&m, &hidden);
        assert_eq!(f.latest.as_deref(), Some("1.1.0"));
        assert_eq!(f.dist_tags["latest"], "1.1.0");
        assert!(f.version("2.0.0").is_none());
        assert_eq!(
            retarget(
                Ecosystem::Npm,
                "2.0.0-rc.2",
                ["1.1.0", "2.0.0-rc.1"].into_iter()
            ),
            Some("2.0.0-rc.1".into())
        );
        assert_eq!(
            retarget(Ecosystem::Npm, "1.0.0", ["1.1.0"].into_iter()),
            None
        );
    }

    #[test]
    fn filters_npm_packuments() {
        let mut doc = json!({
            "name": "pkg",
            "dist-tags": {"latest": "1.2.0", "next": "1.2.0", "legacy": "1.0.0"},
            "versions": {"1.0.0": {}, "1.1.0": {}, "1.2.0": {}}
        });
        let hidden: HashSet<String> = ["1.2.0".to_string()].into();
        assert_eq!(filter_packument(&mut doc, &hidden), 1);
        assert_eq!(
            doc["dist-tags"],
            json!({"latest": "1.1.0", "next": "1.1.0", "legacy": "1.0.0"})
        );
        assert!(doc["versions"].get("1.2.0").is_none());
    }

    #[test]
    fn marks_young_pypi_files_yanked() {
        let hidden: HashSet<String> = ["2.0".to_string()].into();
        let html = "<html><body>\n<a href=\"https://f/p/demo-1.0.tar.gz#sha256=1\">demo-1.0.tar.gz</a><br/>\n<a href=\"https://f/p/demo-2.0-py3-none-any.whl#sha256=2\" data-requires-python=\"&gt;=3.8\">demo-2.0-py3-none-any.whl</a><br/>\n<a href=\"https://f/p/demo-2.0.tar.gz\" data-yanked=\"broken\">demo-2.0.tar.gz</a>\n</body></html>";
        let (out, n) = filter_simple_html(html, "demo", &hidden, "too \"new\"");
        assert_eq!(n, 1, "{out}");
        assert!(
            out.contains("<a href=\"https://f/p/demo-1.0.tar.gz#sha256=1\">"),
            "{out}"
        );
        assert!(
            out.contains("<a data-yanked=\"too &quot;new&quot;\" href=\"https://f/p/demo-2.0-py3"),
            "{out}"
        );
        // A file the project already yanked keeps its own reason.
        assert!(
            out.contains("data-yanked=\"broken\">demo-2.0.tar.gz"),
            "{out}"
        );
        let mut doc = json!({
            "name": "demo",
            "files": [
                {"filename": "demo-1.0.tar.gz", "yanked": false},
                {"filename": "demo-2.0.0-py3-none-any.whl"},
                {"filename": "demo-2.0.tar.gz", "yanked": "broken"}
            ],
            "versions": ["1.0", "2.0"]
        });
        // `2.0.0` in a file name is the same PEP 440 version as `2.0`.
        assert_eq!(filter_simple_json(&mut doc, "demo", &hidden, "young"), 1);
        assert_eq!(doc["files"][0]["yanked"], json!(false));
        assert_eq!(doc["files"][1]["yanked"], json!("young"));
        assert_eq!(doc["files"][2]["yanked"], json!("broken"));
        assert_eq!(doc["versions"], json!(["1.0", "2.0"]));
        // Another project's files on the page are left alone.
        let (_, n) = filter_simple_html("<a href=\"x\">other-2.0.tar.gz</a>", "demo", &hidden, "r");
        assert_eq!(n, 0);
    }
}
