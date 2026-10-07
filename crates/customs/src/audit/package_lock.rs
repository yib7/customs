//! `package-lock.json` and `npm-shrinkwrap.json`. Versions 2 and 3 list every installed
//! package in `packages`, keyed by its `node_modules` path; version 1 has only the nested
//! `dependencies` tree.

use std::collections::HashMap;
use std::path::Path;

use serde_json::{Map, Value};

use super::{json_key_lines, key_line, npm_pin, Parsed};

pub(super) fn parse(text: &str, file: &Path, out: &mut Parsed) -> Result<(), String> {
    let doc: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let lines = json_key_lines(text);
    if let Some(packages) = doc.get("packages").and_then(Value::as_object) {
        for (key, e) in packages {
            // "" is the project itself; links point at workspace folders.
            if key.is_empty() || e.get("link").and_then(Value::as_bool) == Some(true) {
                continue;
            }
            // Without a node_modules segment the key is a workspace folder.
            let Some(i) = key.rfind("node_modules/") else {
                continue;
            };
            let field = |k: &str| e.get(k).and_then(Value::as_str);
            // Aliased installs (`"foo": "npm:bar@1"`) record the real name.
            let name = field("name").unwrap_or(&key[i + "node_modules/".len()..]);
            let line = key_line(&lines, &["packages", key]);
            match field("version") {
                Some(v) => npm_pin(out, file, line, name, v, field("resolved")),
                None => out.skip(file, line, key, "no version recorded"),
            }
        }
        return Ok(());
    }
    if let Some(deps) = doc.get("dependencies").and_then(Value::as_object) {
        walk_v1(deps, &mut vec!["dependencies".into()], &lines, file, out);
    }
    Ok(())
}

fn walk_v1(
    deps: &Map<String, Value>,
    path: &mut Vec<String>,
    lines: &HashMap<Vec<String>, usize>,
    file: &Path,
    out: &mut Parsed,
) {
    for (name, e) in deps {
        path.push(name.clone());
        let line = lines.get(path.as_slice()).copied().unwrap_or(1);
        let field = |k: &str| e.get(k).and_then(Value::as_str);
        match field("version") {
            Some(v) => npm_pin(out, file, line, name, v, field("resolved")),
            None => out.skip(file, line, name, "no version recorded"),
        }
        if let Some(sub) = e.get("dependencies").and_then(Value::as_object) {
            path.push("dependencies".into());
            walk_v1(sub, path, lines, file, out);
            path.pop();
        }
        path.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::pins;
    use super::*;

    const V3: &str = r#"{
  "name": "web",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "web",
      "version": "1.0.0",
      "workspaces": ["packages/*"],
      "dependencies": {
        "@babel/core": "^7.24.0",
        "debug": "^4.3.4"
      }
    },
    "node_modules/@babel/core": {
      "version": "7.24.0",
      "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz",
      "integrity": "sha512-AAAA",
      "dev": true
    },
    "node_modules/@babel/core/node_modules/semver": {
      "version": "6.3.1",
      "resolved": "https://registry.npmjs.org/semver/-/semver-6.3.1.tgz",
      "dev": true,
      "bin": {
        "semver": "bin/semver.js"
      }
    },
    "node_modules/debug": {
      "version": "4.3.4",
      "resolved": "https://registry.npmjs.org/debug/-/debug-4.3.4.tgz",
      "dependencies": {
        "ms": "2.1.2"
      }
    },
    "node_modules/my-lib": {
      "resolved": "packages/my-lib",
      "link": true
    },
    "node_modules/semver": {
      "version": "7.6.0",
      "resolved": "https://registry.npmjs.org/semver/-/semver-7.6.0.tgz"
    },
    "node_modules/string-width-cjs": {
      "name": "string-width",
      "version": "4.2.3",
      "resolved": "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz"
    },
    "node_modules/from-git": {
      "version": "1.0.0",
      "resolved": "git+ssh://git@github.com/x/from-git.git#0123abc"
    },
    "packages/my-lib": {
      "version": "0.0.1"
    },
    "packages/my-lib/node_modules/debug": {
      "version": "4.3.4",
      "resolved": "https://registry.npmjs.org/debug/-/debug-4.3.4.tgz"
    }
  }
}
"#;

    const V1: &str = r#"{
  "name": "old",
  "version": "1.0.0",
  "lockfileVersion": 1,
  "requires": true,
  "dependencies": {
    "@types/node": {
      "version": "20.11.30",
      "resolved": "https://registry.npmjs.org/@types/node/-/node-20.11.30.tgz",
      "integrity": "sha512-AAAA"
    },
    "chalk": {
      "version": "2.4.2",
      "resolved": "https://registry.npmjs.org/chalk/-/chalk-2.4.2.tgz",
      "requires": {
        "ansi-styles": "^3.2.1"
      },
      "dependencies": {
        "ansi-styles": {
          "version": "3.2.1",
          "resolved": "https://registry.npmjs.org/ansi-styles/-/ansi-styles-3.2.1.tgz"
        }
      }
    },
    "ansi-styles": {
      "version": "4.3.0",
      "resolved": "https://registry.npmjs.org/ansi-styles/-/ansi-styles-4.3.0.tgz"
    },
    "local": {
      "version": "file:../local"
    },
    "aliased": {
      "version": "npm:lodash@4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    }
  }
}
"#;

    #[test]
    fn lockfile_v3_with_nested_scoped_and_aliases() {
        let mut p = Parsed::default();
        parse(V3, Path::new("package-lock.json"), &mut p).unwrap();
        let mut got = pins(&p);
        got.sort_by_key(|x| x.2);
        assert_eq!(
            got,
            vec![
                ("@babel/core".into(), "7.24.0".into(), 16),
                ("semver".into(), "6.3.1".into(), 22),
                ("debug".into(), "4.3.4".into(), 30),
                ("semver".into(), "7.6.0".into(), 41),
                ("string-width".into(), "4.2.3".into(), 45),
                ("debug".into(), "4.3.4".into(), 57),
            ]
        );
        assert_eq!(p.skipped.len(), 1);
        assert!(p.mismatches.is_empty());
        assert_eq!(p.skipped[0].line, 50);
        assert!(p.skipped[0].reason.contains("git+ssh"));
    }

    #[test]
    fn lockfile_v1_tree() {
        let mut p = Parsed::default();
        parse(V1, Path::new("package-lock.json"), &mut p).unwrap();
        let mut got = pins(&p);
        got.sort_by_key(|x| x.2);
        assert_eq!(
            got,
            vec![
                ("@types/node".into(), "20.11.30".into(), 7),
                ("chalk".into(), "2.4.2".into(), 12),
                ("ansi-styles".into(), "3.2.1".into(), 19),
                ("ansi-styles".into(), "4.3.0".into(), 25),
                ("lodash".into(), "4.17.21".into(), 32),
            ]
        );
        assert_eq!(p.skipped.len(), 1);
        assert!(p.mismatches.is_empty());
        assert_eq!(p.skipped[0].line, 29);
    }

    #[test]
    fn resolved_tarball_of_another_package() {
        let lock = r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "x"},
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz",
      "integrity": "sha512-EVIL"
    },
    "node_modules/semver": {
      "version": "7.6.0",
      "resolved": "https://registry.npmjs.org/semver/-/semver-7.6.0.tgz"
    }
  }
}"#;
        let mut p = Parsed::default();
        parse(lock, Path::new("package-lock.json"), &mut p).unwrap();
        let mut got = pins(&p);
        got.sort_by_key(|x| x.2);
        assert_eq!(
            got,
            vec![
                ("evil-pkg".into(), "1.0.0".into(), 5),
                ("semver".into(), "7.6.0".into(), 10),
            ]
        );
        assert_eq!(p.mismatches.len(), 1);
        assert_eq!(p.mismatches[0].dep.name, "lodash");
        assert_eq!(p.mismatches[0].dep.line, 5);
    }

    #[test]
    fn empty_lockfile() {
        let mut p = Parsed::default();
        parse(
            r#"{"name": "x", "lockfileVersion": 3, "packages": {"": {"name": "x"}}}"#,
            Path::new("package-lock.json"),
            &mut p,
        )
        .unwrap();
        assert!(p.deps.is_empty() && p.skipped.is_empty());
    }
}
