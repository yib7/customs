//! `deno.lock`, the lockfile Deno writes for `deno add`, `deno install` and npm: imports.
//! Version 4 and 5 keep npm packages in a top-level `npm` map, version 3 under
//! `packages.npm`. Keys are `name@version`, followed by `_peer@version` for each peer
//! dependency the copy was resolved against. An entry carries a `tarball` URL when the
//! registry is not the default one; Deno downloads that URL without comparing it with the
//! entry's name, so it gets the same check as npm's `resolved`. JSR packages and remote
//! modules are listed as not checked.

use std::path::Path;

use serde_json::{Map, Value};

use super::{json_key_lines, key_line, npm_pin, split_npm_spec, Parsed};

pub(super) fn parse(text: &str, file: &Path, out: &mut Parsed) -> Result<(), String> {
    let doc: Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let lines = json_key_lines(text);
    let (root, base): (&Value, &[&str]) = match doc.get("packages") {
        Some(p) if p.get("npm").is_some() || p.get("jsr").is_some() => (p, &["packages"]),
        _ => (&doc, &[]),
    };
    let path = |section: &str, key: &str| -> usize {
        let mut p: Vec<&str> = base.to_vec();
        p.push(section);
        p.push(key);
        key_line(&lines, &p)
    };
    let empty = Map::new();
    let section = |name: &str| root.get(name).and_then(Value::as_object).unwrap_or(&empty);
    for (key, e) in section("npm") {
        let line = path("npm", key);
        let Some((name, rest)) = split_npm_spec(key) else {
            out.skip(file, line, key, "not a name@version entry");
            continue;
        };
        // Peer dependencies are recorded after the version: `18.3.1_react@18.3.1`.
        let version = rest.split('_').next().unwrap_or(rest);
        let tarball = e.get("tarball").and_then(Value::as_str);
        npm_pin(out, file, line, name, version, tarball);
    }
    for key in section("jsr").keys() {
        out.skip(
            file,
            path("jsr", key),
            &format!("jsr:{key}"),
            "JSR packages are not checked",
        );
    }
    let remote = doc
        .get("remote")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    for url in remote.keys() {
        // Remote entries map to a hash string, which `json_key_lines` does not record.
        let quoted = serde_json::to_string(url).unwrap_or_default();
        let line = text
            .find(&format!("{quoted}:"))
            .map_or(1, |at| text[..at].matches('\n').count() + 1);
        out.skip(file, line, url, "remote module, not a registry package");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Written by Deno 2.9 through `customs serve` (so every entry records its tarball),
    // with one entry edited to install another package from another host.
    const LOCK: &str = r#"{
  "version": "5",
  "specifiers": {
    "jsr:@std/path@1.0.8": "1.0.8",
    "npm:@sindresorhus/is@4.6.0": "4.6.0",
    "npm:ms@2.1.2": "2.1.2",
    "npm:react-dom@18.3.1": "18.3.1_react@18.3.1"
  },
  "jsr": {
    "@std/path@1.0.8": {
      "integrity": "548fa456bb6a04d3c1a1e7477986b6cffbce95102d0bb447c67c4ee70e0364be"
    }
  },
  "npm": {
    "@sindresorhus/is@4.6.0": {
      "integrity": "sha512-t09vSN3MdfsyCHoFcTRCH/iUtG7OJ0CsjzB8cjAmKc/va/kIgeDI/TxsigdncE/4be734m0cvIYwNaV4i2XqAw==",
      "tarball": "http://127.0.0.1:7979/npm/@sindresorhus/is/-/is-4.6.0.tgz"
    },
    "ms@2.1.2": {
      "integrity": "sha512-wGMH1g==",
      "tarball": "https://registry.yarnpkg.com/is-number/-/is-number-7.0.0.tgz"
    },
    "react-dom@18.3.1_react@18.3.1": {
      "integrity": "sha512-5m4nQKp+rZRb09LNH59GM4BxTh9251/ylbKIbpe7TpGxfJ+9kv6BLkLBXIjjspbgbnIBNqlI23tRnTWT0snUIw==",
      "dependencies": [
        "react"
      ]
    },
    "react@18.3.1": {
      "integrity": "sha512-wS+hAgJShR0KhEvPJArfuPVN1+Hz1t0Y6n5jLrGQbkb4urgPE/0Rve+1kMB1v/oWgHgm4WIcV+i7F2pTVj+2iQ=="
    }
  },
  "remote": {
    "https://deno.land/std@0.224.0/path/mod.ts": "f065032a7189404fdac3ad1a1551a9ac84751d2f25c431e101787846c86c79f5"
  },
  "workspace": {
    "dependencies": [
      "jsr:@std/path@1.0.8",
      "npm:react-dom@18.3.1"
    ]
  }
}"#;

    #[test]
    fn deno_lock() {
        let f = Path::new("deno.lock");
        let mut p = Parsed::default();
        parse(LOCK, f, &mut p).unwrap();
        let deps: Vec<_> = p
            .deps
            .iter()
            .map(|d| (d.name.as_str(), d.version.as_str(), d.line))
            .collect();
        assert_eq!(
            deps,
            [
                ("@sindresorhus/is", "4.6.0", 15),
                ("is-number", "7.0.0", 19),
                ("react-dom", "18.3.1", 23),
                ("react", "18.3.1", 29)
            ]
        );
        assert_eq!(p.mismatches.len(), 1);
        assert_eq!(p.mismatches[0].dep.name, "ms");
        assert!(p.mismatches[0].message.contains("is-number@7.0.0"));
        let skipped: Vec<_> = p
            .skipped
            .iter()
            .map(|s| (s.spec.as_str(), s.line))
            .collect();
        assert_eq!(
            skipped,
            [
                ("jsr:@std/path@1.0.8", 10),
                ("https://deno.land/std@0.224.0/path/mod.ts", 34)
            ]
        );

        // Version 3 keeps the same maps under `packages`.
        let v3 = r#"{"version": "3", "packages": {"specifiers": {"npm:ms@2.1.2": "npm:ms@2.1.2"},
            "npm": {"ms@2.1.2": {"integrity": "sha512-x", "dependencies": {}}}}, "remote": {}}"#;
        let mut p = Parsed::default();
        parse(v3, f, &mut p).unwrap();
        assert_eq!(p.deps.len(), 1);
        assert_eq!(
            (p.deps[0].name.as_str(), p.deps[0].version.as_str()),
            ("ms", "2.1.2")
        );
    }
}
