//! Whole-project installs (DESIGN.md section 9). `npm install`, `npm ci`, `pnpm install`,
//! bare `yarn`, `bun install`, `uv sync`, `poetry install` and `pipenv install|sync` name no
//! packages: they fetch everything the project's lockfile pins, plus whatever its manifest
//! lists that the lockfile does not pin yet (an agent adds a dependency to `package.json`,
//! then runs `npm install`). Both come back as targets for the usual checks, and lockfile
//! entries whose tarball URL serves another package (`customs audit`'s mismatch) come back
//! as blocks. For packages the lockfile already pins only a block counts: a project
//! fetches hundreds of them, and at the warn threshold's false-positive rate nearly every
//! install would stop for review.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::parse::{deno_spec, parse_npm_spec, parse_pypi_spec, Manager, Target};
use crate::audit;
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
    let mut pinned = HashSet::new();
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
                    pinned.insert(d.name.clone());
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
            Target::Package { name, .. } if pinned.contains(name) => continue,
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
        Manager::Pipenv => pipfile(&dir.join("Pipfile")),
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
    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(deps) = doc.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (name, range) in deps {
            let Some(range) = range.as_str() else {
                continue;
            };
            if local_npm_range(range) {
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
    if manager == Manager::Uv {
        // `uv sync` installs the dev group by default.
        reqs.extend(strings(
            doc.get("dependency-groups").and_then(|g| g.get("dev")),
        ));
    }
    if manager == Manager::Poetry {
        let poetry = doc.get("tool").and_then(|t| t.get("poetry"));
        let tables = [
            poetry.and_then(|p| p.get("dependencies")),
            poetry
                .and_then(|p| p.get("group"))
                .and_then(|g| g.get("dev"))
                .and_then(|d| d.get("dependencies")),
            poetry.and_then(|p| p.get("dev-dependencies")),
        ];
        for t in tables
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_table)
        {
            for (name, v) in t {
                if name != "python" {
                    reqs.extend(toml_requirement(name, v));
                }
            }
        }
    }
    reqs.iter().map(|r| parse_pypi_spec(r)).collect()
}

fn pipfile(path: &Path) -> Vec<Target> {
    let Some(doc) = read_toml(path) else {
        return vec![];
    };
    let Some(pkgs) = doc.get("packages").and_then(toml::Value::as_table) else {
        return vec![];
    };
    pkgs.iter()
        .filter_map(|(name, v)| toml_requirement(name, v))
        .map(|r| parse_pypi_spec(&r))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use customs_scan::Ecosystem;

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
