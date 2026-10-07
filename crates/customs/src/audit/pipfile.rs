//! `Pipfile.lock`: JSON with `default` and `develop` maps of name to `{"version": "==x"}`.

use std::collections::HashMap;
use std::path::Path;

use customs_scan::Ecosystem;
use serde_json::Value;

use super::{host_of, json_key_lines, key_line, known_registry, Parsed};

pub(super) fn parse(text: &str, file: &Path, out: &mut Parsed) -> Result<(), String> {
    let doc: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let lines = json_key_lines(text);
    let sources: HashMap<&str, &str> = doc
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
            if e.get("editable").and_then(Value::as_bool) == Some(true) || field("path").is_some() {
                out.skip(file, line, &spec, "installed from a local path");
                continue;
            }
            if let Some(url) = field("git").or_else(|| field("file")) {
                out.skip(file, line, &spec, format!("installed from {url}"));
                continue;
            }
            if let Some(url) = field("index").and_then(|i| sources.get(i)) {
                if !known_registry(url) {
                    out.skip(
                        file,
                        line,
                        &spec,
                        format!("from a custom package index ({})", host_of(url)),
                    );
                    continue;
                }
            }
            match version.strip_prefix("==").filter(|v| !v.is_empty()) {
                Some(v) => out.dep(Ecosystem::Pypi, name, v, file, line),
                None => out.skip(file, line, &spec, "no exact version"),
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
        assert_eq!(skipped, vec![32, 36, 50]);
    }
}
