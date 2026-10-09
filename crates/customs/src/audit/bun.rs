//! `bun.lock`, the text lockfile Bun writes since 1.2: JSON with trailing commas. Every
//! installed package is a `packages` entry keyed by its install path (`debug/ms` for a
//! nested copy, an alias for `npm:` installs) whose value is an array: `name@resolution`
//! first, then for registry packages the tarball URL, empty for the default registry.
//! Bun installs that URL without comparing it with the entry's name, like npm.

use std::path::Path;

use serde_json::Value;

use super::{json_key_lines, key_line, npm_pin, split_npm_spec, Parsed, SkipKind};

pub(super) fn parse(text: &str, file: &Path, out: &mut Parsed) -> Result<(), String> {
    let text = strip_trailing_commas(text);
    let doc: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let lines = json_key_lines(&text);
    let Some(packages) = doc.get("packages").and_then(Value::as_object) else {
        return Ok(());
    };
    for (key, e) in packages {
        let line = key_line(&lines, &["packages", key]);
        let Some((name, res)) = e.get(0).and_then(Value::as_str).and_then(split_npm_spec) else {
            out.skip(file, line, key, SkipKind::Other, "no resolution recorded");
            continue;
        };
        // The project's own workspace folders.
        if res.starts_with("workspace:") || res.starts_with("root:") {
            continue;
        }
        // Registry entries carry a URL string; git, tarball and path entries an object.
        let resolved = e.get(1).and_then(Value::as_str).filter(|r| !r.is_empty());
        npm_pin(out, file, line, name, res, resolved);
    }
    Ok(())
}

/// `text` with every comma that closes an object or array blanked out, so serde_json
/// accepts it. Line numbers are unchanged.
fn strip_trailing_commas(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = b.to_vec();
    let mut in_str = false;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if in_str {
            match c {
                b'\\' => i += 1,
                b'"' => in_str = false,
                _ => {}
            }
        } else if c == b'"' {
            in_str = true;
        } else if c == b',' {
            let next = b[i + 1..].iter().find(|c| !c.is_ascii_whitespace());
            if matches!(next, Some(b'}' | b']')) {
                out[i] = b' ';
            }
        }
        i += 1;
    }
    // Only ASCII commas were replaced with ASCII spaces.
    String::from_utf8(out).expect("still UTF-8")
}

#[cfg(test)]
mod tests {
    use super::super::tests::pins;
    use super::*;

    // Written by Bun 1.4 (`bun install`), with a custom-registry and a swapped entry added.
    const LOCK: &str = r#"{
  "lockfileVersion": 2,
  "configVersion": 1,
  "workspaces": {
    "": {
      "name": "app",
      "dependencies": {
        "@types/ms": "0.7.34",
        "debug": "4.3.4",
        "lib": "workspace:*",
        "localdep": "file:./local",
        "ms-tar": "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz",
        "sw": "npm:string-width@4.2.3",
      },
    },
    "packages/lib": {
      "name": "lib",
      "version": "0.1.0",
      "dependencies": {
        "ms": "2.1.3",
      },
    },
  },
  "packages": {
    "@types/ms": ["@types/ms@0.7.34", "", {}, "sha512-AAAA"],

    "debug": ["debug@4.3.4", "", { "dependencies": { "ms": "2.1.2" }, "peerDependencies": { "supports-color": "*" }, "optionalPeers": ["supports-color"] }, "sha512-BBBB"],

    "lib": ["lib@workspace:packages/lib"],

    "localdep": ["localdep@file:local", {}],

    "ms": ["ms@2.1.3", "http://127.0.0.1:7878/npm/ms/-/ms-2.1.3.tgz", {}, "sha512-CCCC"],

    "ms-tar": ["ms@https://registry.npmjs.org/ms/-/ms-2.0.0.tgz", {}, "sha512-DDDD"],

    "internal": ["internal@1.0.0", "https://npm.corp.example/internal/-/internal-1.0.0.tgz", {}, "sha512-EEEE"],

    "sw": ["string-width@4.2.3", "", { "dependencies": { "emoji-regex": "^8.0.0" } }, "sha512-FFFF"],

    "debug/ms": ["ms@2.1.2", "", {}, "sha512-GGGG"],
  }
}
"#;

    #[test]
    fn bun_lock() {
        let mut p = Parsed::default();
        parse(LOCK, Path::new("bun.lock"), &mut p).unwrap();
        // `parse_lockfile` puts entries in file order; serde_json sorts them by key.
        p.deps.sort_by_key(|d| d.line);
        p.skipped.sort_by_key(|s| s.line);
        assert_eq!(
            pins(&p),
            vec![
                ("@types/ms".into(), "0.7.34".into(), 25),
                ("debug".into(), "4.3.4".into(), 27),
                ("ms".into(), "2.1.3".into(), 33),
                ("string-width".into(), "4.2.3".into(), 39),
                ("ms".into(), "2.1.2".into(), 41),
            ]
        );
        let skipped: Vec<(usize, &str)> = p
            .skipped
            .iter()
            .map(|s| (s.line, s.spec.as_str()))
            .collect();
        assert_eq!(
            skipped,
            vec![
                (31, "localdep@file:local"),
                (35, "ms@https://registry.npmjs.org/ms/-/ms-2.0.0.tgz"),
                (37, "internal@1.0.0"),
            ]
        );
        assert!(p.skipped[2].reason.contains("npm.corp.example"));
        assert!(p.mismatches.is_empty());
    }

    #[test]
    fn bun_tarball_of_another_package() {
        // Bun 1.4 installs is-number into node_modules/debug from this entry.
        let lock = r#"{
  "lockfileVersion": 1,
  "packages": {
    "debug": ["debug@4.3.4", "https://registry.npmjs.org/is-number/-/is-number-7.0.0.tgz", {}, "sha512-AAAA"],
  },
}"#;
        let mut p = Parsed::default();
        parse(lock, Path::new("bun.lock"), &mut p).unwrap();
        assert_eq!(pins(&p), vec![("is-number".into(), "7.0.0".into(), 4)]);
        assert_eq!(p.mismatches.len(), 1);
        assert!(p.mismatches[0].message.contains("not debug@4.3.4"));
    }

    #[test]
    fn trailing_commas_outside_strings_only() {
        assert_eq!(
            strip_trailing_commas("{\"a,}\": [1, 2,\n],\n}"),
            "{\"a,}\": [1, 2 \n] \n}"
        );
        assert_eq!(strip_trailing_commas(r#"["\",]", 1]"#), r#"["\",]", 1]"#);
    }
}
