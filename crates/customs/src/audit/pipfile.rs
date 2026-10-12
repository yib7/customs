//! `Pipfile.lock`: JSON with `default` and `develop` maps of name to `{"version": "==x"}`.

use std::path::Path;

use customs_scan::Ecosystem;
use serde_json::Value;

use super::{host_of, json_key_lines, key_line, Parsed, SkipKind};
use crate::hook::parse::looks_like_url;

pub(super) fn parse(text: &str, file: &Path, out: &mut Parsed) -> Result<(), String> {
    let doc: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let lines = json_key_lines(text);
    // In order: the first is pipenv's default index.
    let sources: Vec<(&str, &str)> = doc
        .pointer("/_meta/sources")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|s| Some((s.get("name")?.as_str()?, s.get("url")?.as_str()?)))
        .collect();
    for section in ["default", "develop"] {
        let Some(entries) = doc.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (name, e) in entries {
            let line = key_line(&lines, &[section, name]);
            let field = |k: &str| e.get(k).and_then(Value::as_str);
            let version = field("version").unwrap_or("");
            let spec = format!("{name}{version}");
            // A git checkout is fetched even when it is installed editable.
            if let Some(url) = field("git").or_else(|| field("file").filter(|f| looks_like_url(f)))
            {
                out.skip(
                    file,
                    line,
                    &spec,
                    SkipKind::Source,
                    format!("installed from {url}"),
                );
                continue;
            }
            if e.get("editable").and_then(Value::as_bool) == Some(true)
                || field("path").is_some()
                || field("file").is_some()
            {
                out.skip(
                    file,
                    line,
                    &spec,
                    SkipKind::Local,
                    "installed from a local path",
                );
                continue;
            }
            // Without an `index`, pipenv installs from the first source.
            let url = match field("index") {
                Some(i) => match sources.iter().find(|(n, _)| *n == i) {
                    Some((_, url)) => Some(*url),
                    None => {
                        out.skip(
                            file,
                            line,
                            &spec,
                            SkipKind::CustomIndex,
                            format!("from package index '{i}', which _meta.sources does not list"),
                        );
                        continue;
                    }
                },
                None => sources.first().map(|(_, url)| *url),
            };
            if let Some(url) = url.filter(|u| !out.known_registry(u)) {
                out.skip(
                    file,
                    line,
                    &spec,
                    SkipKind::CustomIndex,
                    format!("from a custom package index ({})", host_of(url)),
                );
                continue;
            }
            match version.strip_prefix("==").filter(|v| !v.is_empty()) {
                Some(v) => out.dep(Ecosystem::Pypi, name, v, file, line),
                None => out.skip(file, line, &spec, SkipKind::Unpinned, "no exact version"),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::pins;
    use super::*;

    const LOCK: &str = r#"{
    "_meta": {
        "hash": {
            "sha256": "0000"
        },
        "pipfile-spec": 6,
        "requires": {
            "python_version": "3.11"
        },
        "sources": [
            {
                "name": "pypi",
                "url": "https://pypi.org/simple",
                "verify_ssl": true
            },
            {
                "name": "corp",
                "url": "https://pypi.corp.example/simple",
                "verify_ssl": true
            }
        ]
    },
    "default": {
        "requests": {
            "hashes": [
                "sha256:58cd2187c01e70e6e26505bca751777aa9f2ee0b7f4300988b709f44e013003f"
            ],
            "index": "pypi",
            "markers": "python_version >= '3.7'",
            "version": "==2.31.0"
        },
        "corp-tools": {
            "index": "corp",
            "version": "==1.0.0"
        },
        "mypkg": {
            "editable": true,
            "path": "."
        }
    },
    "develop": {
        "pytest": {
            "hashes": [],
            "index": "pypi",
            "version": "==8.1.1"
        },
        "requests": {
            "version": "==2.31.0"
        },
        "fork": {
            "git": "https://github.com/x/fork.git",
            "ref": "abc"
        },
        "editable-fork": {
            "editable": true,
            "git": "https://github.com/x/editable-fork.git",
            "ref": "abc"
        }
    }
}
"#;

    #[test]
    fn pipfile_lock() {
        let mut p = Parsed::default();
        parse(LOCK, Path::new("Pipfile.lock"), &mut p).unwrap();
        let mut got = pins(&p);
        got.sort_by_key(|x| x.2);
        assert_eq!(
            got,
            vec![
                ("requests".into(), "2.31.0".into(), 24),
                ("pytest".into(), "8.1.1".into(), 42),
                ("requests".into(), "2.31.0".into(), 47),
            ]
        );
        let mut skipped: Vec<usize> = p.skipped.iter().map(|s| s.line).collect();
        skipped.sort();
        assert_eq!(skipped, vec![32, 36, 50, 54]);
        let kind = |line: usize| p.skipped.iter().find(|s| s.line == line).unwrap().kind;
        assert_eq!(kind(36), SkipKind::Local);
        assert_eq!(kind(50), SkipKind::Source);
        // Editable does not make a git checkout the project's own code.
        assert_eq!(kind(54), SkipKind::Source);
    }
    #[test]
    fn no_index_uses_the_first_source() {
        // pipenv installs entries without an `index` from the first source.
        let lock = r#"{
    "_meta": {"sources": [{"name": "corp", "url": "https://pypi.corp.example/simple"}]},
    "default": {
        "tool": {"version": "==1.0"},
        "other": {"index": "gone", "version": "==2.0"}
    }
}"#;
        let mut p = Parsed::default();
        parse(lock, Path::new("Pipfile.lock"), &mut p).unwrap();
        assert!(p.deps.is_empty(), "{:?}", p.deps);
        p.skipped.sort_by_key(|s| s.line);
        assert_eq!(p.skipped.len(), 2, "{:?}", p.skipped);
        for s in &p.skipped {
            assert_eq!(s.kind, SkipKind::CustomIndex, "{s:?}");
        }
        assert!(
            p.skipped[0].reason.contains("pypi.corp.example"),
            "{:?}",
            p.skipped[0]
        );
        // An index the sources do not name could be anything.
        assert!(p.skipped[1].reason.contains("gone"), "{:?}", p.skipped[1]);
        // PyPI as the first source changes nothing.
        let lock = lock.replace(
            "https://pypi.corp.example/simple",
            "https://pypi.org/simple",
        );
        let mut p = Parsed::default();
        parse(&lock, Path::new("Pipfile.lock"), &mut p).unwrap();
        assert_eq!(p.deps.len(), 1, "{:?}", p.deps);
    }
}
