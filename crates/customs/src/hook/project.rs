//! Whole-project installs (DESIGN.md section 9). `npm install`, `npm ci`, `pnpm install`,
//! bare `yarn`, `bun install`, `uv sync`, `poetry install` and `pipenv install|sync` name no
//! packages: they fetch everything the project's lockfile pins, plus whatever its manifest
//! lists that the lockfile does not pin yet (an agent adds a dependency to `package.json`,
//! then runs `npm install`). Both come back as targets for the usual checks, and lockfile
//! entries whose tarball URL serves another package (`customs audit`'s mismatch) come back
//! as blocks. For packages the lockfile already pins only a block counts: a project
//! fetches hundreds of them, and at the warn threshold's false-positive rate nearly every
//! install would stop for review.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use customs_scan::Ecosystem;
use serde_json::Value;

use super::parse::{deno_spec, parse_npm_spec, parse_pypi_spec, Manager, Target};
use crate::audit;
use crate::registry::{PackageMeta, VersionMeta};
use crate::resolve;
use crate::util::ecosystem_str;

/// What a project install would fetch.
#[derive(Debug, Default)]
pub struct Expanded {
    pub targets: Vec<Target>,
    /// `(label, reason)` for each lockfile entry that installs another package than it names.
    pub mismatches: Vec<(String, String)>,
    /// The lockfile read, if the project has one.
    pub lockfile: Option<PathBuf>,
    /// How many of `targets`, from the front, the lockfile pins.
    pub locked: usize,
}

impl Manager {
    /// Lockfiles this manager installs from, in the order it prefers them.
    fn lockfiles(self) -> &'static [&'static str] {
        match self {
            Manager::Npm => &["npm-shrinkwrap.json", "package-lock.json"],
            Manager::Pnpm => &["pnpm-lock.yaml"],
            Manager::Yarn => &["yarn.lock"],
            Manager::Bun => &["bun.lock"],
            Manager::Uv => &["uv.lock"],
            Manager::Poetry => &["poetry.lock"],
            Manager::Pipenv => &["Pipfile.lock"],
            Manager::Pip => &[],
            Manager::Deno => &["deno.lock"],
        }
    }
}

/// `extras` are the optional-dependency groups of a `pip install .[extras]`.
pub fn expand(manager: Manager, dir: &Path, extras: &[String]) -> Expanded {
    let eco = manager.ecosystem();
    let mut out = Expanded::default();
    // Locked versions by package name.
    let mut pinned: HashMap<String, Vec<String>> = HashMap::new();
    let mut unchecked = Vec::new();
    let lock = manager
        .lockfiles()
        .iter()
        .map(|n| dir.join(n))
        .find(|p| p.is_file());
    if let Some(lock) = &lock {
        match audit::parse_lockfile(lock) {
            Ok(p) => {
                for m in p.mismatches {
                    out.mismatches.push((
                        format!(
                            "{}:{} {}",
                            ecosystem_str(m.dep.ecosystem),
                            m.dep.name,
                            m.dep.version
                        ),
                        m.message,
                    ));
                }
                unchecked = p.skipped.into_iter().filter(|k| k.fetched()).collect();
                out.locked = p.deps.len();
                for d in p.deps {
                    pinned
                        .entry(package_key(d.ecosystem, &d.name))
                        .or_default()
                        .push(d.version.clone());
                    out.targets.push(Target::Package {
                        ecosystem: d.ecosystem,
                        name: d.name,
                        version: Some(d.version),
                    });
                }
            }
            Err(e) => out.targets.push(Target::Unverifiable {
                ecosystem: eco,
                spec: lock.display().to_string(),
                reason: format!("the lockfile could not be read ({e})"),
            }),
        }
        out.lockfile = Some(lock.clone());
    }
    for t in manifest_targets(manager, dir, extras) {
        match &t {
            Target::Package {
                ecosystem,
                name,
                version,
            } if pinned
                .get(&package_key(*ecosystem, name))
                .is_some_and(|locked| {
                    lock_satisfies(*ecosystem, name, version.as_deref(), locked)
                }) =>
            {
                continue
            }
            // With a lockfile, git and URL dependencies are pinned there under their own
            // terms; without one they are fetched as written and need a look.
            Target::Unverifiable { .. } if lock.is_some() => continue,
            _ => out.targets.push(t),
        }
    }
    // Lockfile entries fetched from git, a URL or another registry install code nothing
    // has checked; a lockfile edit can point one at any host.
    for k in unchecked.iter().take(MAX_UNCHECKED_SHOWN) {
        out.targets.push(Target::Unverifiable {
            ecosystem: eco,
            spec: k.spec.clone(),
            reason: format!("{} (lockfile line {})", k.reason, k.line),
        });
    }
    if let (Some(more), Some(lock)) = (unchecked.len().checked_sub(MAX_UNCHECKED_SHOWN), &lock) {
        if more > 0 {
            out.targets.push(Target::Unverifiable {
                ecosystem: eco,
                spec: format!("{more} more lockfile entries"),
                reason: format!(
                    "from git, URLs or other registries; `customs audit {}` lists them",
                    lock.display()
                ),
            });
        }
    }
    out
}

/// A package name as the registry compares it: PyPI ignores case and treats runs of `-`,
/// `_` and `.` alike.
fn package_key(eco: Ecosystem, name: &str) -> String {
    match eco {
        Ecosystem::Npm => name.to_string(),
        Ecosystem::Pypi => {
            let mut key = String::new();
            for c in name.chars() {
                if matches!(c, '-' | '_' | '.') {
                    if !key.ends_with('-') {
                        key.push('-');
                    }
                } else {
                    key.push(c.to_ascii_lowercase());
                }
            }
            key
        }
    }
}

/// A locked version satisfies the manifest's `version` (an exact version or a range), so
/// the install fetches what the lockfile pins rather than something new. A range Customs
/// cannot read counts as satisfied, as it did when only names were compared.
fn lock_satisfies(eco: Ecosystem, name: &str, version: Option<&str>, locked: &[String]) -> bool {
    let meta = PackageMeta {
        ecosystem: eco,
        name: name.to_string(),
        latest: None,
        dist_tags: BTreeMap::new(),
        versions: locked
            .iter()
            .map(|v| VersionMeta {
                version: v.clone(),
                ..VersionMeta::default()
            })
            .collect(),
        created: None,
        people: Vec::new(),
    };
    // A bare PyPI version is exact (Poetry and Pipfile write them that way).
    let exact;
    let version = match version {
        Some(v) if eco == Ecosystem::Pypi && v.starts_with(|c: char| c.is_ascii_digit()) => {
            exact = format!("=={v}");
            Some(exact.as_str())
        }
        v => v,
    };
    resolve::resolve_version(&meta, version).is_ok()
}

/// Unchecked lockfile entries listed one by one before the rest are counted.
const MAX_UNCHECKED_SHOWN: usize = 5;

/// Direct dependencies the manifest lists, as install specs.
fn manifest_targets(manager: Manager, dir: &Path, extras: &[String]) -> Vec<Target> {
    match manager {
        Manager::Npm | Manager::Pnpm | Manager::Yarn | Manager::Bun => {
            package_json(&dir.join("package.json"))
        }
        Manager::Uv | Manager::Poetry | Manager::Pip => {
            pyproject(&dir.join("pyproject.toml"), manager, extras)
        }
        Manager::Pipenv => pipfile(&dir.join("Pipfile"), extras),
        Manager::Deno => {
            let mut t = deno_json(dir);
            t.extend(package_json(&dir.join("package.json")));
            t
        }
    }
}

/// The `npm:`, `jsr:` and URL entries of the import map in `deno.json` or `deno.jsonc`.
fn deno_json(dir: &Path) -> Vec<Target> {
    let Some(doc) = ["deno.json", "deno.jsonc"].iter().find_map(|n| {
        let text = std::fs::read_to_string(dir.join(n)).ok()?;
        serde_json::from_str::<Value>(&strip_jsonc(&text)).ok()
    }) else {
        return vec![];
    };
    let Some(imports) = doc.get("imports").and_then(Value::as_object) else {
        return vec![];
    };
    imports
        .values()
        .filter_map(Value::as_str)
        .filter_map(|v| deno_spec(v, false))
        .collect()
}

/// JSON with comments and trailing commas (`deno.jsonc`) as plain JSON.
fn strip_jsonc(text: &str) -> String {
    let no_comments = strip_outside_strings(text.as_bytes(), |b, i| match b[i] {
        b'/' if b.get(i + 1) == Some(&b'/') => b[i..]
            .iter()
            .position(|&c| c == b'\n')
            .map_or(b.len(), |n| i + n),
        b'/' if b.get(i + 1) == Some(&b'*') => b[i + 2..]
            .windows(2)
            .position(|w| w == b"*/")
            .map_or(b.len(), |n| i + 2 + n + 2),
        _ => i,
    });
    let out = strip_outside_strings(&no_comments, |b, i| {
        let closes = b[i + 1..]
            .iter()
            .find(|c| !c.is_ascii_whitespace())
            .is_some_and(|c| matches!(c, b'}' | b']'));
        if b[i] == b',' && closes {
            i + 1
        } else {
            i
        }
    });
    String::from_utf8_lossy(&out).into_owned()
}

/// `b` without the spans `skip(b, i)` reports (it returns where the span ends, or `i`
/// for none), never looking inside JSON strings.
fn strip_outside_strings(b: &[u8], skip: impl Fn(&[u8], usize) -> usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'"' {
            let start = i;
            i += 1;
            while i < b.len() && b[i] != b'"' {
                i += if b[i] == b'\\' { 2 } else { 1 };
            }
            i = (i + 1).min(b.len());
            out.extend_from_slice(&b[start..i]);
            continue;
        }
        let end = skip(b, i);
        if end > i {
            i = end;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// The project's own folders and links, never fetched from anywhere.
fn local_npm_range(range: &str) -> bool {
    ["workspace:", "file:", "link:", "portal:"]
        .iter()
        .any(|p| range.starts_with(p))
}

fn package_json(path: &Path) -> Vec<Target> {
    let Some(doc) = std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str::<Value>(&t).ok())
    else {
        return vec![];
    };
    let mut out = Vec::new();
    // npm 7 and later install peer dependencies unless `peerDependenciesMeta` marks them
    // optional.
    let optional_peer = |name: &str| {
        doc.get("peerDependenciesMeta")
            .and_then(|m| m.get(name))
            .and_then(|m| m.get("optional"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
    };
    for section in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        let Some(deps) = doc.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (name, range) in deps {
            let Some(range) = range.as_str() else {
                continue;
            };
            if local_npm_range(range) || (section == "peerDependencies" && optional_peer(name)) {
                continue;
            }
            out.push(parse_npm_spec(&format!("{name}@{range}")));
        }
    }
    out
}

fn read_toml(path: &Path) -> Option<toml::Value> {
    toml::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// A Poetry or Pipfile version constraint (`"^1.2"`, `"1.2.3"`, `"*"`, or a table with
/// `version`) as a PEP 508 requirement; `None` for git, path and URL tables.
fn toml_requirement(name: &str, v: &toml::Value) -> Option<String> {
    let c = match v {
        toml::Value::String(s) => s.trim().to_string(),
        toml::Value::Table(t) => match t.get("version").and_then(toml::Value::as_str) {
            Some(s) => s.trim().to_string(),
            None if ["git", "path", "file", "url"]
                .iter()
                .any(|k| t.contains_key(*k)) =>
            {
                return None
            }
            None => String::new(),
        },
        _ => return None,
    };
    Some(if c.is_empty() || c == "*" {
        name.to_string()
    } else if c.starts_with(|ch: char| ch.is_ascii_digit()) {
        // Poetry reads a bare version as exact.
        format!("{name}=={c}")
    } else {
        format!("{name}{c}")
    })
}

fn pyproject(path: &Path, manager: Manager, extras: &[String]) -> Vec<Target> {
    let Some(doc) = read_toml(path) else {
        return vec![];
    };
    let mut reqs: Vec<String> = Vec::new();
    let strings = |v: Option<&toml::Value>| -> Vec<String> {
        v.and_then(toml::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(toml::Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    reqs.extend(strings(
        doc.get("project").and_then(|p| p.get("dependencies")),
    ));
    for extra in extras {
        reqs.extend(strings(
            doc.get("project")
                .and_then(|p| p.get("optional-dependencies"))
                .and_then(|o| o.get(extra.as_str())),
        ));
    }
    let mut indexes = Vec::new();
    if manager == Manager::Uv {
        // `uv sync` installs the dev group by default.
        reqs.extend(strings(
            doc.get("dependency-groups").and_then(|g| g.get("dev")),
        ));
        let uv_indexes = doc
            .get("tool")
            .and_then(|t| t.get("uv"))
            .and_then(|u| u.get("index"))
            .and_then(toml::Value::as_array);
        for index in uv_indexes.into_iter().flatten() {
            indexes.extend(
                index
                    .get("url")
                    .and_then(toml::Value::as_str)
                    .map(str::to_string),
            );
        }
    }
    if manager == Manager::Poetry {
        let poetry = doc.get("tool").and_then(|t| t.get("poetry"));
        // Poetry installs every dependency group not marked `optional = true`.
        let groups = poetry
            .and_then(|p| p.get("group"))
            .and_then(toml::Value::as_table)
            .into_iter()
            .flatten()
            .filter(|(_, g)| g.get("optional").and_then(toml::Value::as_bool) != Some(true))
            .map(|(_, g)| g.get("dependencies"));
        let tables = [poetry.and_then(|p| p.get("dependencies"))]
            .into_iter()
            .chain(groups)
            .chain([poetry.and_then(|p| p.get("dev-dependencies"))]);
        for t in tables.flatten().filter_map(toml::Value::as_table) {
            for (name, v) in t {
                if name != "python" {
                    reqs.extend(toml_requirement(name, v));
                }
            }
        }
    }
    let mut out: Vec<Target> = reqs.iter().map(|r| parse_pypi_spec(r)).collect();
    out.extend(custom_indexes(
        indexes,
        "pyproject.toml names it in `tool.uv.index`",
    ));
    out
}

/// `extras` holds `dev` for `pipenv install --dev`, which adds `[dev-packages]`.
fn pipfile(path: &Path, extras: &[String]) -> Vec<Target> {
    let Some(doc) = read_toml(path) else {
        return vec![];
    };
    let mut sections = vec!["packages"];
    if extras.iter().any(|e| e == "dev") {
        sections.push("dev-packages");
    }
    let mut out: Vec<Target> = sections
        .into_iter()
        .filter_map(|s| doc.get(s).and_then(toml::Value::as_table))
        .flatten()
        .filter_map(|(name, v)| toml_requirement(name, v))
        .map(|r| parse_pypi_spec(&r))
        .collect();
    let sources = doc
        .get("source")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|s| s.get("url").and_then(toml::Value::as_str))
        .map(str::to_string)
        .collect();
    out.extend(custom_indexes(
        sources,
        "the Pipfile names it as a `[[source]]`",
    ));
    out
}

/// Package indexes other than PyPI, which serve packages Customs does not check. With a
/// lockfile they are dropped again: the lockfile's own entries say where each comes from.
fn custom_indexes(urls: Vec<String>, why: &str) -> Vec<Target> {
    urls.into_iter()
        .filter(|u| {
            let host = url::Url::parse(u)
                .ok()
                .and_then(|u| u.host_str().map(str::to_ascii_lowercase));
            !matches!(host.as_deref(), Some("pypi.org" | "pypi.python.org"))
        })
        .map(|u| Target::Unverifiable {
            ecosystem: Ecosystem::Pypi,
            spec: u,
            reason: format!("a package index other than PyPI, which Customs cannot check ({why})"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, text: &str) {
        std::fs::write(dir.join(name), text).unwrap();
    }

    fn names(e: &Expanded) -> Vec<String> {
        e.targets
            .iter()
            .map(|t| match t {
                Target::Package { name, version, .. } => {
                    format!("{name} {}", version.as_deref().unwrap_or("-"))
                }
                Target::Unverifiable { spec, .. } => format!("? {spec}"),
                Target::RemoteScript { url, .. } => format!("script {url}"),
                Target::Project { .. } => "project".into(),
            })
            .collect()
    }

    #[test]
    fn npm_lockfile_plus_new_manifest_dependencies() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "package.json",
            r#"{"dependencies": {"debug": "^4.3.4", "left-pad": "^1.3.0", "lib": "workspace:*",
                "fork": "github:x/fork", "sw": "npm:string-width@^4"},
               "devDependencies": {"typescript": "5.4.5"}}"#,
        );
        write(
            d.path(),
            "package-lock.json",
            r#"{"lockfileVersion": 3, "packages": {
  "": {"name": "app"},
  "node_modules/debug": {"version": "4.3.4", "resolved": "https://registry.npmjs.org/debug/-/debug-4.3.4.tgz"},
  "node_modules/sw": {"name": "string-width", "version": "4.2.3"},
  "node_modules/fork": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/fork.git#abc"},
  "node_modules/ms": {"version": "2.1.2", "resolved": "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz"},
  "node_modules/chalk": {"version": "5.3.0", "resolved": "https://evil.example/chalk/-/chalk-5.3.0.tgz"},
  "node_modules/mine": {"version": "file:../mine"}
}}"#,
        );
        let e = expand(Manager::Npm, d.path(), &[]);
        assert_eq!(
            names(&e),
            vec![
                "debug 4.3.4",
                "string-width 4.2.3",
                "is-number 7.0.0",
                "left-pad ^1.3.0",
                "typescript 5.4.5",
                // Fetched from elsewhere, so they need a look; the local folder does not.
                "? fork@1.0.0",
                "? chalk@5.3.0"
            ]
        );
        assert!(matches!(
            &e.targets[6],
            Target::Unverifiable { reason, .. } if reason == "from a custom registry (evil.example) (lockfile line 7)"
        ));
        assert_eq!(e.mismatches.len(), 1);
        assert_eq!(e.mismatches[0].0, "npm:ms 2.1.2");
        assert!(e.mismatches[0].1.contains("is-number@7.0.0"));
        assert_eq!(e.locked, 3);
        assert!(e.lockfile.unwrap().ends_with("package-lock.json"));
    }

    #[test]
    fn npm_without_lockfile_checks_the_manifest() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "package.json",
            r#"{"dependencies": {"debug": "^4", "fork": "github:x/fork", "local": "file:../x"}}"#,
        );
        assert_eq!(
            names(&expand(Manager::Npm, d.path(), &[])),
            vec!["debug ^4", "? fork@github:x/fork"]
        );
        // Another manager's lockfile is not this one's.
        write(d.path(), "yarn.lock", "debug@^4:\n  version \"4.3.4\"\n");
        assert!(expand(Manager::Npm, d.path(), &[]).lockfile.is_none());
        assert_eq!(
            names(&expand(Manager::Yarn, d.path(), &[])),
            vec!["debug 4.3.4"]
        );
    }

    #[test]
    fn uv_poetry_and_pipenv_projects() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "pyproject.toml",
            r#"
[project]
name = "app"
dependencies = ["requests>=2", "Flask==3.0.0"]

[dependency-groups]
dev = ["pytest", {include-group = "lint"}]

[tool.poetry.dependencies]
python = "^3.10"
rich = "^13.7"
attrs = "23.2.0"
mylib = {path = "../mylib"}
httpx = {version = ">=0.27", extras = ["http2"]}
"#,
        );
        write(
            d.path(),
            "uv.lock",
            "version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.32.3\"\nsource = { registry = \"https://pypi.org/simple\" }\n",
        );
        assert_eq!(
            names(&expand(Manager::Uv, d.path(), &[])),
            vec!["requests 2.32.3", "flask 3.0.0", "pytest -"]
        );
        assert_eq!(
            names(&expand(Manager::Poetry, d.path(), &[])),
            vec![
                "requests >=2",
                "flask 3.0.0",
                "attrs 23.2.0",
                "httpx >=0.27",
                "rich ^13.7"
            ]
        );
        write(
            d.path(),
            "Pipfile",
            "[packages]\nrequests = \"*\"\ndjango = {version = \"==5.0\"}\nlocal = {path = \".\", editable = true}\n",
        );
        assert_eq!(
            names(&expand(Manager::Pipenv, d.path(), &[])),
            vec!["django 5.0", "requests -"]
        );
        let e = expand(Manager::Pipenv, Path::new("/nonexistent"), &[]);
        assert!(e.targets.is_empty() && e.lockfile.is_none());
        assert_eq!(Manager::Pipenv.ecosystem(), Ecosystem::Pypi);
    }

    #[test]
    fn manifest_version_outside_the_lock_is_checked() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "package-lock.json",
            r#"{"lockfileVersion": 3, "packages": {
  "": {"name": "app"},
  "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}
}}"#,
        );
        // The manifest was bumped past the lock: npm fetches 9.9.9.
        write(
            d.path(),
            "package.json",
            r#"{"dependencies": {"left-pad": "9.9.9"}}"#,
        );
        let e = expand(Manager::Npm, d.path(), &[]);
        assert_eq!(names(&e), vec!["left-pad 1.3.0", "left-pad 9.9.9"]);
        assert_eq!(e.locked, 1);
        // A range the locked version satisfies installs the locked version.
        write(
            d.path(),
            "package.json",
            r#"{"dependencies": {"left-pad": "^1.3.0"}}"#,
        );
        assert_eq!(
            names(&expand(Manager::Npm, d.path(), &[])),
            vec!["left-pad 1.3.0"]
        );

        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "uv.lock",
            "version = 1\n\n[[package]]\nname = \"requests\"\nversion = \"2.32.3\"\nsource = { registry = \"https://pypi.org/simple\" }\n",
        );
        write(
            d.path(),
            "pyproject.toml",
            "[project]\nname = \"app\"\ndependencies = [\"Requests>=3\"]\n",
        );
        assert_eq!(
            names(&expand(Manager::Uv, d.path(), &[])),
            vec!["requests 2.32.3", "requests >=3"]
        );
        write(
            d.path(),
            "pyproject.toml",
            "[project]\nname = \"app\"\ndependencies = [\"Requests>=2,<3\"]\n",
        );
        assert_eq!(
            names(&expand(Manager::Uv, d.path(), &[])),
            vec!["requests 2.32.3"]
        );

        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "poetry.lock",
            "[[package]]\nname = \"attrs\"\nversion = \"23.2.0\"\ndescription = \"\"\noptional = false\npython-versions = \">=3.7\"\nfiles = []\n",
        );
        write(
            d.path(),
            "pyproject.toml",
            "[tool.poetry.dependencies]\npython = \"^3.10\"\nattrs = \"24.1.0\"\n",
        );
        assert_eq!(
            names(&expand(Manager::Poetry, d.path(), &[])),
            vec!["attrs 23.2.0", "attrs 24.1.0"]
        );
    }

    #[test]
    fn project_installs_more_than_the_main_dependencies() {
        let d = tempfile::tempdir().unwrap();
        // npm 7 and later install peer dependencies.
        write(
            d.path(),
            "package.json",
            r#"{"dependencies": {"a": "1.0.0"}, "peerDependencies": {"react": "^18"}}"#,
        );
        assert_eq!(
            names(&expand(Manager::Npm, d.path(), &[])),
            vec!["a 1.0.0", "react ^18"]
        );
        // Poetry installs every group that is not optional.
        write(
            d.path(),
            "pyproject.toml",
            r#"
[tool.poetry.dependencies]
attrs = "23.2.0"
[tool.poetry.group.docs.dependencies]
sphinx = "*"
[tool.poetry.group.extra]
optional = true
[tool.poetry.group.extra.dependencies]
heavy = "*"
"#,
        );
        assert_eq!(
            names(&expand(Manager::Poetry, d.path(), &[])),
            vec!["attrs 23.2.0", "sphinx -"]
        );
        // `pipenv install --dev` adds the dev packages; an index other than PyPI with no
        // lockfile is fetched from as written.
        write(
            d.path(),
            "Pipfile",
            "[[source]]\nurl = \"https://pypi.org/simple\"\nname = \"pypi\"\n\n[[source]]\nurl = \"https://evil.example/simple\"\nname = \"corp\"\n\n[packages]\nrequests = \"*\"\n\n[dev-packages]\npytest = \"*\"\n",
        );
        assert_eq!(
            names(&expand(Manager::Pipenv, d.path(), &[])),
            vec!["requests -", "? https://evil.example/simple"]
        );
        assert_eq!(
            names(&expand(Manager::Pipenv, d.path(), &["dev".into()])),
            vec!["requests -", "pytest -", "? https://evil.example/simple"]
        );
        // So is a uv index.
        write(
            d.path(),
            "pyproject.toml",
            "[project]\nname = \"app\"\ndependencies = []\n[[tool.uv.index]]\nname = \"corp\"\nurl = \"https://evil.example/simple\"\n",
        );
        assert_eq!(
            names(&expand(Manager::Uv, d.path(), &[])),
            vec!["? https://evil.example/simple"]
        );
    }

    #[test]
    fn pip_installs_what_pyproject_declares() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "pyproject.toml",
            r#"
[project]
name = "app"
dependencies = ["requests>=2"]
[project.optional-dependencies]
dev = ["pytest==8.2.0"]
docs = ["sphinx"]
[dependency-groups]
dev = ["ruff"]
"#,
        );
        assert_eq!(
            names(&expand(Manager::Pip, d.path(), &[])),
            vec!["requests >=2"]
        );
        assert_eq!(
            names(&expand(Manager::Pip, d.path(), &["dev".into()])),
            vec!["requests >=2", "pytest 8.2.0"]
        );
    }

    #[test]
    fn deno_lockfile_plus_import_map() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "deno.jsonc",
            r#"{
  // Import map: npm and JSR packages, a remote module, a local folder.
  "imports": {
    "chalk": "npm:chalk@5", /* pinned below */
    "preact/": "npm:preact@10.22.0/",
    "@std/path": "jsr:@std/path@^1",
    "oak": "https://deno.land/x/oak@v12.6.1/mod.ts",
    "~/": "./src/",
  },
}"#,
        );
        assert_eq!(
            names(&expand(Manager::Deno, d.path(), &[])),
            vec![
                "? jsr:@std/path@^1",
                "chalk 5",
                "? https://deno.land/x/oak@v12.6.1/mod.ts",
                "preact 10.22.0"
            ]
        );
        write(
            d.path(),
            "package.json",
            r#"{"dependencies": {"zod": "^3"}}"#,
        );
        write(
            d.path(),
            "deno.lock",
            r#"{"version": "5", "npm": {
  "chalk@5.3.0": {"integrity": "sha512-x"},
  "ms@2.1.2": {"integrity": "sha512-y", "tarball": "https://registry.yarnpkg.com/is-number/-/is-number-7.0.0.tgz"}
}}"#,
        );
        let e = expand(Manager::Deno, d.path(), &[]);
        assert_eq!(
            names(&e),
            vec!["chalk 5.3.0", "is-number 7.0.0", "preact 10.22.0", "zod ^3"]
        );
        assert_eq!(e.mismatches.len(), 1);
        assert_eq!(e.locked, 2);
    }

    #[test]
    fn many_unchecked_entries_are_counted() {
        let d = tempfile::tempdir().unwrap();
        let entries: Vec<String> = (0..8)
            .map(|i| {
                format!(
                    r#""node_modules/p{i}": {{"version": "1.0.0", "resolved": "https://npm.corp.example/p{i}/-/p{i}-1.0.0.tgz"}}"#
                )
            })
            .collect();
        write(
            d.path(),
            "package-lock.json",
            &format!(
                r#"{{"lockfileVersion": 3, "packages": {{{}}}}}"#,
                entries.join(",")
            ),
        );
        let e = expand(Manager::Npm, d.path(), &[]);
        let n = names(&e);
        assert_eq!(n.len(), 6);
        assert_eq!(n[0], "? p0@1.0.0");
        assert!(n[5].starts_with("? 3 more lockfile entries"), "{n:?}");
    }

    #[test]
    fn unreadable_lockfile_needs_a_look() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "bun.lock", "{ not json");
        let e = expand(Manager::Bun, d.path(), &[]);
        assert_eq!(e.targets.len(), 1);
        assert!(matches!(
            &e.targets[0],
            Target::Unverifiable { reason, .. } if reason.contains("could not be read")
        ));
    }
}
