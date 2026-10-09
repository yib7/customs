//! Release history around one requested version, for the release history rules in
//! [`crate::policy`]: `provenance_dropped`, `install_script_added`, `publisher_changed`,
//! `dormant_revival`, `version_anomaly`, `nonregistry_dependency_added`, and
//! `young_dependency_added`.
//!
//! Account takeovers (the 2025 chalk/debug compromise, the Shai-Hulud worm) publish a new
//! version of a real library with a payload buried in legitimate code, which is where the
//! classifier is weakest. Registry metadata often shows what the archive does not: the
//! release lost the provenance attestation its predecessors had, gained an install script,
//! came from a different account, or broke a long silence. These are heuristics with known
//! false positives (maintainers move CI, add native builds, hand a package over, revive an
//! old project), which is why most rules warn by default. `install_script_added` and the two
//! dependency rules block: measured on npm, together they fire on 5 of 14,897 legitimate
//! releases and lift the share of test-period compromised releases blocked from 44% to at
//! least 96% (DESIGN.md section 8).

use chrono::{DateTime, Utc};
use customs_scan::Ecosystem;

use crate::registry::{PackageMeta, VersionMeta};
use crate::resolve::{compare_versions, Pep440};

/// How many earlier releases `publisher_changed` compares against.
pub const RECENT_RELEASES: usize = 5;

/// How much older the "settled" release is that `install_script_added` and the dependency
/// rules also compare against, so a burst of releases cannot hide a change.
pub const SETTLED_HOURS: i64 = 24;

/// The registry facts of one release that the rules compare.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ReleaseFacts {
    pub version: String,
    pub published: Option<DateTime<Utc>>,
    pub attested: bool,
    pub publisher: Option<String>,
    /// `(script, command)` for npm install scripts.
    pub install_commands: Vec<(String, String)>,
    /// npm `dependencies` and `optionalDependencies` as `(name, spec)`.
    pub dependencies: Vec<(String, String)>,
}

impl ReleaseFacts {
    fn of(v: &VersionMeta) -> Self {
        Self {
            version: v.version.clone(),
            published: v.published,
            attested: v.attested,
            publisher: v.publisher.clone(),
            install_commands: v.install_commands.clone(),
            dependencies: v.dependencies.clone(),
        }
    }
}

/// Registry facts about a dependency the requested release added, filled in by the engine
/// with one metadata lookup per added dependency.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DependencyInfo {
    /// False when the registry does not know the name.
    pub exists: bool,
    /// When the dependency was first published.
    pub created: Option<DateTime<Utc>>,
    /// Its maintainers and publishers.
    pub people: Vec<String>,
}

/// A registry dependency that the requested release lists and the previous release did not.
#[derive(Debug, Clone, PartialEq)]
pub struct AddedDependency {
    pub name: String,
    pub spec: String,
    /// `None` until the engine looks it up (or when the lookup failed).
    pub info: Option<DependencyInfo>,
}

/// The most added dependencies looked up per release; real releases add a handful.
pub const MAX_ADDED_LOOKUPS: usize = 20;

/// True for npm dependency specs that are not fetched from the registry: git, GitHub and
/// other hosted-git shorthands, URLs, and local paths. npm installs these without asking the
/// registry, so they bypass the proxy and its scan.
pub fn is_nonregistry_spec(spec: &str) -> bool {
    const PREFIXES: [&str; 10] = [
        "git+",
        "git:",
        "github:",
        "gitlab:",
        "bitbucket:",
        "gist:",
        "http:",
        "https:",
        "file:",
        "link:",
    ];
    let s = spec.trim();
    if PREFIXES.iter().any(|p| s.starts_with(p)) {
        return true;
    }
    // `owner/repo` and `owner/repo#ref`: GitHub shorthand.
    let repo = s.split('#').next().unwrap_or("");
    let mut parts = repo.split('/');
    let ok = |p: &str| {
        !p.is_empty()
            && p.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    matches!((parts.next(), parts.next(), parts.next()), (Some(a), Some(b), None) if ok(a) && ok(b) && !a.starts_with('@'))
}

/// The package a dependency entry installs: the key, unless the spec is an npm alias
/// (`"left-pad": "npm:real@^1"` or `"npm:@scope/real"`), which installs `real` under the
/// key's name.
fn install_target<'a>(key: &'a str, spec: &'a str) -> &'a str {
    let Some(aliased) = spec.trim().strip_prefix("npm:") else {
        return key;
    };
    let start = usize::from(aliased.starts_with('@'));
    let name = match aliased[start..].find('@') {
        Some(at) => &aliased[..start + at],
        None => aliased,
    };
    if name.is_empty() {
        key
    } else {
        name
    }
}

/// An earlier release, as `version_anomaly` sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct VersionRef {
    pub version: String,
    pub major: u64,
    pub published: DateTime<Utc>,
}

/// The requested release and what was published before it.
///
/// "Earlier releases" are the other versions published strictly before the requested one.
/// Prereleases among them are ignored unless the requested version is itself a
/// prerelease, so a stable release is compared with the stable line.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ReleaseHistory {
    pub current: ReleaseFacts,
    /// The most recently published earlier release.
    pub previous: Option<ReleaseFacts>,
    /// The most recently published release at least [`SETTLED_HOURS`] older: the version a
    /// user had before a burst of releases.
    pub settled: Option<ReleaseFacts>,
    /// Distinct publishers of the up to [`RECENT_RELEASES`] most recent earlier releases,
    /// newest first. Releases without a known publisher are skipped.
    pub recent_publishers: Vec<String>,
    /// Major version of the requested release, when it parses.
    pub current_major: Option<u64>,
    /// The highest earlier version.
    pub highest_prior: Option<VersionRef>,
    /// The most recently published earlier release with the same major version.
    pub line_previous: Option<VersionRef>,
    /// npm: maintainers and publishers of the package itself.
    pub people: Vec<String>,
    /// npm: registry dependencies new since the previous release or since the settled one,
    /// sorted by name.
    pub added_dependencies: Vec<AddedDependency>,
}

fn is_prerelease(eco: Ecosystem, v: &str) -> bool {
    match eco {
        Ecosystem::Npm => semver::Version::parse(v)
            .map(|x| !x.pre.is_empty())
            .unwrap_or_else(|_| v.contains('-')),
        Ecosystem::Pypi => Pep440::parse(v).is_some_and(|p| p.is_pre()),
    }
}

fn major(eco: Ecosystem, v: &str) -> Option<u64> {
    match eco {
        Ecosystem::Npm => semver::Version::parse(v).ok().map(|x| x.major),
        Ecosystem::Pypi => Pep440::parse(v).map(|p| p.major()),
    }
}

fn version_ref(eco: Ecosystem, v: &VersionMeta) -> Option<VersionRef> {
    Some(VersionRef {
        version: v.version.clone(),
        major: major(eco, &v.version)?,
        published: v.published?,
    })
}

/// History of `version` within `meta`. `None` when the version is unknown or has no
/// publication time, since "earlier" is then undefined.
pub fn release_history(meta: &PackageMeta, version: &str) -> Option<ReleaseHistory> {
    let eco = meta.ecosystem;
    let cur = meta.version(version)?;
    let cur_time = cur.published?;
    let cur_pre = is_prerelease(eco, version);
    let mut earlier: Vec<&VersionMeta> = meta
        .versions
        .iter()
        .filter(|v| {
            v.version != version
                && v.published.is_some_and(|t| t < cur_time)
                && (cur_pre || !is_prerelease(eco, &v.version))
        })
        .collect();
    // Newest first.
    earlier.sort_by_key(|v| std::cmp::Reverse(v.published));

    let mut recent_publishers: Vec<String> = Vec::new();
    for p in earlier
        .iter()
        .take(RECENT_RELEASES)
        .filter_map(|v| v.publisher.as_ref())
    {
        if !recent_publishers.contains(p) {
            recent_publishers.push(p.clone());
        }
    }
    let current_major = major(eco, version);
    let highest_prior = earlier
        .iter()
        .filter(|v| major(eco, &v.version).is_some())
        .max_by(|a, b| compare_versions(eco, &a.version, &b.version))
        .and_then(|v| version_ref(eco, v));
    let line_previous = current_major.and_then(|m| {
        earlier
            .iter()
            .find(|v| major(eco, &v.version) == Some(m))
            .and_then(|v| version_ref(eco, v))
    });
    let settled = earlier
        .iter()
        .find(|v| {
            v.published
                .is_some_and(|t| cur_time - t >= chrono::Duration::hours(SETTLED_HOURS))
        })
        .copied();
    // Compared by the package installed, not the key: an alias can swap the package behind
    // an existing key, or give a new package a familiar key.
    let lacks = |v: &VersionMeta, n: &str| {
        !v.dependencies
            .iter()
            .any(|(k, s)| install_target(k, s) == n)
    };
    let added_dependencies = match earlier.first() {
        Some(prev) => {
            let mut added: Vec<AddedDependency> = cur
                .dependencies
                .iter()
                .map(|(k, s)| (install_target(k, s), s))
                .filter(|(n, s)| {
                    *n != meta.name
                        && !is_nonregistry_spec(s)
                        && (lacks(prev, n) || settled.is_some_and(|v| lacks(v, n)))
                })
                .map(|(n, s)| AddedDependency {
                    name: n.to_string(),
                    spec: s.clone(),
                    info: None,
                })
                .collect();
            added.sort_by(|a, b| a.name.cmp(&b.name));
            // Two keys can alias one package.
            added.dedup_by(|a, b| a.name == b.name);
            added
        }
        None => Vec::new(),
    };
    Some(ReleaseHistory {
        current: ReleaseFacts::of(cur),
        previous: earlier.first().map(|v| ReleaseFacts::of(v)),
        settled: settled.map(ReleaseFacts::of),
        people: meta.people.clone(),
        added_dependencies,
        recent_publishers,
        current_major,
        highest_prior,
        line_previous,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::parse_npm_packument;
    use serde_json::{json, Value};

    #[test]
    fn nonregistry_specs() {
        for s in [
            "github:tanstack/router#79ac49e",
            "git+https://github.com/a/b.git",
            "git://github.com/a/b",
            "https://example.com/x.tgz",
            "file:../local",
            "owner/repo",
            "owner/repo#main",
            "gitlab:a/b",
        ] {
            assert!(is_nonregistry_spec(s), "{s}");
        }
        for s in [
            "^1.2.3",
            "1.x || >=2.5.0",
            "latest",
            "npm:other@^1",
            "*",
            "",
            "@scope/name",
            ">=1 <2",
        ] {
            assert!(!is_nonregistry_spec(s), "{s}");
        }
    }

    #[test]
    fn added_dependencies_compare_with_the_previous_release() {
        let v = serde_json::json!({
            "name": "app",
            "time": {"1.0.0": "2024-01-01T00:00:00Z", "1.0.1": "2024-02-01T00:00:00Z"},
            "versions": {
                "1.0.0": {"dist": {"tarball": "t"}, "dependencies": {"a": "^1"}},
                "1.0.1": {"dist": {"tarball": "t"}, "dependencies":
                    {"a": "^2", "z-new": "^1", "b-new": "^1", "app": "^1", "g": "github:x/y"}}
            }
        });
        let m = parse_npm_packument(&v).unwrap();
        let h = release_history(&m, "1.0.1").unwrap();
        // Sorted; version bumps, self references and off-registry specs are not additions.
        let names: Vec<&str> = h
            .added_dependencies
            .iter()
            .map(|d| d.name.as_str())
            .collect();
        assert_eq!(names, vec!["b-new", "z-new"]);
        assert!(release_history(&m, "1.0.0")
            .unwrap()
            .added_dependencies
            .is_empty());
    }

    #[test]
    fn aliased_dependency_counts_as_added_under_its_real_name() {
        let v = serde_json::json!({
            "name": "app",
            "time": {"1.0.0": "2024-01-01T00:00:00Z", "1.0.1": "2024-02-01T00:00:00Z"},
            "versions": {
                "1.0.0": {"dist": {"tarball": "t"}, "dependencies":
                    {"left-pad": "^1.3.0", "lodash": "^4.17.21", "types": "npm:@types/node@^20"}},
                "1.0.1": {"dist": {"tarball": "t"}, "dependencies": {
                    // Same key, another package.
                    "left-pad": "npm:fresh-evil@1.0.0",
                    // Still the real lodash, now through an alias: not an addition.
                    "lodash": "npm:lodash@^4.17.21",
                    // A new key named after a well-known package.
                    "react": "npm:@evil/react",
                    "types": "npm:@types/node@^22"
                }}
            }
        });
        let m = parse_npm_packument(&v).unwrap();
        let h = release_history(&m, "1.0.1").unwrap();
        let added: Vec<(&str, &str)> = h
            .added_dependencies
            .iter()
            .map(|d| (d.name.as_str(), d.spec.as_str()))
            .collect();
        assert_eq!(
            added,
            vec![
                ("@evil/react", "npm:@evil/react"),
                ("fresh-evil", "npm:fresh-evil@1.0.0"),
            ]
        );
        assert_eq!(install_target("x", "npm:@scope/real@^1"), "@scope/real");
        assert_eq!(install_target("x", "npm:real"), "real");
        assert_eq!(install_target("x", "^1"), "x");
    }

    type Row<'a> = (&'a str, &'a str, Option<&'a str>, bool, Option<&'a str>);

    /// A packument with one entry per `(version, time, publisher, attested, postinstall)`.
    fn packument(name: &str, rows: &[Row<'_>]) -> Value {
        let mut time = serde_json::Map::new();
        let mut versions = serde_json::Map::new();
        for (v, t, publisher, attested, script) in rows {
            time.insert(v.to_string(), json!(t));
            let mut doc = json!({
                "name": name,
                "version": v,
                "dist": {"tarball": format!("https://r/{name}/-/x-{v}.tgz")},
            });
            if let Some(p) = publisher {
                doc["_npmUser"] = json!({"name": p, "email": "x@example.com"});
            }
            if *attested {
                doc["dist"]["attestations"] = json!({
                    "url": "https://registry.npmjs.org/-/npm/v1/attestations/x",
                    "provenance": {"predicateType": "https://slsa.dev/provenance/v1"}
                });
            }
            if let Some(s) = script {
                doc["scripts"] = json!({"postinstall": s, "test": "jest"});
            }
            versions.insert(v.to_string(), doc);
        }
        json!({"name": name, "time": time, "versions": versions})
    }

    #[test]
    fn previous_release_is_by_publish_time_and_skips_prereleases() {
        let v = packument(
            "@scope/lib",
            &[
                ("1.0.0", "2024-01-01T00:00:00Z", Some("alice"), true, None),
                ("2.0.0", "2024-03-01T00:00:00Z", Some("alice"), true, None),
                // A backport published after 2.0.0.
                ("1.0.1", "2024-04-01T00:00:00Z", Some("bob"), true, None),
                (
                    "2.1.0-rc.1",
                    "2024-05-01T00:00:00Z",
                    Some("carol"),
                    false,
                    None,
                ),
                (
                    "2.1.0",
                    "2024-06-01T00:00:00Z",
                    Some("mallory"),
                    false,
                    None,
                ),
                (
                    "2.2.0-beta.1",
                    "2024-07-01T00:00:00Z",
                    Some("dave"),
                    false,
                    None,
                ),
            ],
        );
        let m = parse_npm_packument(&v).unwrap();
        let h = release_history(&m, "2.1.0").unwrap();
        assert_eq!(h.current.version, "2.1.0");
        assert_eq!(h.current.publisher.as_deref(), Some("mallory"));
        let prev = h.previous.as_ref().unwrap();
        assert_eq!(prev.version, "1.0.1");
        assert!(prev.attested);
        assert_eq!(h.recent_publishers, vec!["bob", "alice"]);
        assert_eq!(h.current_major, Some(2));
        assert_eq!(h.highest_prior.as_ref().unwrap().version, "2.0.0");
        assert_eq!(h.line_previous.as_ref().unwrap().version, "2.0.0");

        // A prerelease is compared with everything before it, prereleases included.
        let h = release_history(&m, "2.2.0-beta.1").unwrap();
        assert_eq!(h.previous.unwrap().version, "2.1.0");
        assert_eq!(
            h.recent_publishers,
            vec!["mallory", "carol", "bob", "alice"]
        );

        // The first release has no history.
        let h = release_history(&m, "1.0.0").unwrap();
        assert!(h.previous.is_none() && h.highest_prior.is_none());
        assert!(h.recent_publishers.is_empty());

        assert!(release_history(&m, "9.9.9").is_none());
    }

    #[test]
    fn recent_publishers_cover_five_releases() {
        let rows: Vec<(String, String)> = (0..8)
            .map(|i| (format!("1.0.{i}"), format!("2024-01-0{}T00:00:00Z", i + 1)))
            .collect();
        let names = ["a", "b", "c", "d", "e", "f", "g", "h"];
        let table: Vec<Row<'_>> = rows
            .iter()
            .zip(names)
            .map(|((v, t), n)| (v.as_str(), t.as_str(), Some(n), false, None))
            .collect();
        let m = parse_npm_packument(&packument("lib", &table)).unwrap();
        let h = release_history(&m, "1.0.7").unwrap();
        assert_eq!(h.recent_publishers, vec!["g", "f", "e", "d", "c"]);
    }

    #[test]
    fn missing_fields_are_tolerated() {
        // No time map: no history at all. No publishers: an empty list.
        let v = json!({"name": "bare", "versions": {"1.0.0": {}, "1.0.1": {}}});
        let m = parse_npm_packument(&v).unwrap();
        assert!(release_history(&m, "1.0.1").is_none());
        let v = json!({"name": "bare",
            "time": {"1.0.0": "2024-01-01T00:00:00Z", "1.0.1": "2024-02-01T00:00:00Z", "weird": "2024-01-15T00:00:00Z"},
            "versions": {"1.0.0": {}, "1.0.1": {}, "weird": {}}});
        let m = parse_npm_packument(&v).unwrap();
        let h = release_history(&m, "1.0.1").unwrap();
        assert!(h.recent_publishers.is_empty());
        assert!(!h.previous.as_ref().unwrap().attested);
        // An unparseable version is a previous release but not a highest version.
        assert_eq!(h.previous.unwrap().version, "weird");
        assert_eq!(h.highest_prior.unwrap().version, "1.0.0");
    }

    #[test]
    fn pypi_history_uses_pep440() {
        use crate::registry::parse_pypi_project;
        let file = |v: &str, t: &str| {
            json!([{"filename": format!("demo-{v}.tar.gz"), "url": "u",
                    "upload_time_iso_8601": t, "packagetype": "sdist"}])
        };
        let v = json!({"info": {"name": "demo", "version": "3.0"},
        "releases": {
            "1.0": file("1.0", "2019-01-01T00:00:00Z"),
            "2.0": file("2.0", "2020-01-01T00:00:00Z"),
            "3.0rc1": file("3.0rc1", "2023-06-01T00:00:00Z"),
            "3.0": file("3.0", "2023-07-01T00:00:00Z"),
            "empty": []
        }});
        let m = parse_pypi_project(&v).unwrap();
        let h = release_history(&m, "3.0").unwrap();
        assert_eq!(h.previous.unwrap().version, "2.0");
        assert_eq!(h.current_major, Some(3));
        assert_eq!(h.highest_prior.unwrap().version, "2.0");
        assert!(h.line_previous.is_none());
        let h = release_history(&m, "3.0rc1").unwrap();
        assert_eq!(h.previous.unwrap().version, "2.0");
    }
}
