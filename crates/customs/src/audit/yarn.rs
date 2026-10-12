//! `yarn.lock`, classic (v1) and berry (v2+). Each entry is an unindented header listing
//! the specs it satisfies, followed by indented fields; only `version`, `resolved`
//! (classic), and `resolution` (berry) are needed.

use std::path::Path;

use super::{npm_pin, split_npm_spec, Parsed, SkipKind};

/// Protocols of a project's own packages, skipped silently. Berry decides from an entry's
/// `resolution`, so a header that also lists one of these does not hide a registry entry.
const LOCAL_PROTOCOLS: &[&str] = &["workspace:", "link:", "portal:"];

#[derive(Default)]
struct Entry {
    line: usize,
    specs: Vec<String>,
    version: Option<String>,
    resolved: Option<String>,
    resolution: Option<String>,
}

pub(super) fn parse(text: &str, file: &Path, out: &mut Parsed) -> Result<(), String> {
    let mut cur: Option<Entry> = None;
    for (i, raw) in text.lines().enumerate() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent == 0 {
            if let Some(e) = cur.take() {
                finish(e, file, out);
            }
            let Some(header) = trimmed.strip_suffix(':') else {
                continue;
            };
            cur = Some(Entry {
                line: i + 1,
                specs: header
                    .split(',')
                    .map(|s| s.trim().trim_matches('"').to_string())
                    .filter(|s| !s.is_empty())
                    .collect(),
                ..Entry::default()
            });
            continue;
        }
        let Some(e) = cur.as_mut() else {
            continue;
        };
        // Fields of the entry itself, not of its nested `dependencies` maps.
        if indent != 2 {
            continue;
        }
        let Some((key, value)) = trimmed.split_once(|c: char| c.is_whitespace()) else {
            continue;
        };
        let value = Some(value.trim().trim_matches('"').to_string());
        match key.trim_end_matches(':') {
            "version" => e.version = value,
            "resolved" => e.resolved = value,
            "resolution" => e.resolution = value,
            _ => {}
        }
    }
    if let Some(e) = cur.take() {
        finish(e, file, out);
    }
    Ok(())
}

fn finish(e: Entry, file: &Path, out: &mut Parsed) {
    let Some(first) = e.specs.first() else {
        return;
    };
    if first == "__metadata" {
        return;
    }
    match &e.resolution {
        Some(res) => berry(&e, res, file, out),
        None => classic(&e, first, file, out),
    }
}

/// Berry: `resolution` is the locator Yarn fetches, `real-name@npm:1.2.3`, with
/// `::__archiveUrl=<percent-encoded URL>` appended when the tarball does not come from the
/// configured registry. The header only lists the requests the entry satisfies, and the
/// `version` field is informational.
fn berry(e: &Entry, res: &str, file: &Path, out: &mut Parsed) {
    let Some((name, r)) = split_npm_spec(res) else {
        out.skip(
            file,
            e.line,
            res,
            SkipKind::Other,
            "could not parse the resolution",
        );
        return;
    };
    if LOCAL_PROTOCOLS.iter().any(|p| r.starts_with(p)) {
        return;
    }
    // A patched copy; the unpatched package it starts from has its own entry.
    if r.starts_with("patch:") {
        return;
    }
    if r.starts_with("file:") {
        out.skip(
            file,
            e.line,
            res,
            SkipKind::Local,
            "installed from a local path",
        );
        return;
    }
    let Some(locator) = r.strip_prefix("npm:") else {
        out.skip(
            file,
            e.line,
            res,
            SkipKind::Source,
            "not a registry package (git or URL)",
        );
        return;
    };
    let (version, params) = locator.split_once("::").unwrap_or((locator, ""));
    let archive = params
        .split('&')
        .find_map(|p| p.strip_prefix("__archiveUrl="))
        .map(|u| {
            percent_encoding::percent_decode_str(u)
                .decode_utf8_lossy()
                .into_owned()
        });
    if let Some(recorded) = e.version.as_deref().filter(|v| *v != version) {
        out.mismatch(
            name,
            recorded,
            file,
            e.line,
            format!("lockfile installs {name}@{version} (its resolution), not {name}@{recorded}"),
        );
    }
    npm_pin(out, file, e.line, name, version, archive.as_deref());
}

/// Classic: the first header spec names the package (`alias@npm:real@range` installs
/// `real`), and `resolved` is the tarball Yarn downloads.
fn classic(e: &Entry, first: &str, file: &Path, out: &mut Parsed) {
    let Some((name, range)) = split_npm_spec(first) else {
        out.skip(
            file,
            e.line,
            first,
            SkipKind::Other,
            "could not parse the entry",
        );
        return;
    };
    let name = range
        .strip_prefix("npm:")
        .and_then(split_npm_spec)
        .map(|(real, _)| real)
        .unwrap_or(name);
    let Some(version) = e.version.as_deref() else {
        out.skip(file, e.line, first, SkipKind::Other, "no version recorded");
        return;
    };
    if range.contains("://") || range.starts_with("git") {
        out.skip(
            file,
            e.line,
            first,
            SkipKind::Source,
            "not a registry package (git or URL)",
        );
        return;
    }
    // A header protocol says nothing about an entry that downloads a tarball.
    let downloaded = e
        .resolved
        .as_deref()
        .is_some_and(|r| r.starts_with("https://") || r.starts_with("http://"));
    if !downloaded {
        if LOCAL_PROTOCOLS.iter().any(|p| range.starts_with(p)) {
            return;
        }
        if range.starts_with("file:") {
            out.skip(
                file,
                e.line,
                first,
                SkipKind::Local,
                "installed from a local path",
            );
            return;
        }
    }
    npm_pin(out, file, e.line, name, version, e.resolved.as_deref());
}

#[cfg(test)]
mod tests {
    use super::super::tests::pins;
    use super::*;

    const CLASSIC: &str = r#"# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.22.13":
  version "7.24.2"
  resolved "https://registry.yarnpkg.com/@babel/code-frame/-/code-frame-7.24.2.tgz#5a3f9"
  integrity sha512-AAAA
  dependencies:
    "@babel/highlight" "^7.24.2"
    picocolors "^1.0.0"

js-tokens@^4.0.0:
  version "4.0.0"
  resolved "https://registry.yarnpkg.com/js-tokens/-/js-tokens-4.0.0.tgz#19203"
  integrity sha512-BBBB

string-width-cjs@npm:string-width@^4.2.0:
  version "4.2.3"
  resolved "https://registry.yarnpkg.com/string-width/-/string-width-4.2.3.tgz"

"forked@git+https://github.com/x/forked.git#abc":
  version "1.0.0"
  resolved "git+https://github.com/x/forked.git#abc"

internal@^1.0.0:
  version "1.0.0"
  resolved "https://npm.corp.example/internal/-/internal-1.0.0.tgz"
"#;

    const BERRY: &str = r#"# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 8
  cacheKey: 10c0

"@babel/core@npm:^7.12.3, @babel/core@npm:^7.23.9":
  version: 7.24.0
  resolution: "@babel/core@npm:7.24.0"
  dependencies:
    "@babel/code-frame": "npm:^7.23.5"
    version: "npm:99.0.0"
  checksum: 10c0/abc
  languageName: node
  linkType: hard

"my-app@workspace:.":
  version: 0.0.0-use.local
  resolution: "my-app@workspace:."
  languageName: unknown
  linkType: soft

"resolve@patch:resolve@npm%3A^1.20.0#optional!builtin<compat/resolve>":
  version: 1.22.8
  resolution: "resolve@patch:resolve@npm%3A1.22.8#optional!builtin<compat/resolve>::version=1.22.8&hash=c3c19d"
  languageName: node
  linkType: hard

"resolve@npm:^1.20.0":
  version: 1.22.8
  resolution: "resolve@npm:1.22.8"
  languageName: node
  linkType: hard

"lodash-es@https://github.com/x/lodash.git#commit=abc":
  version: 4.17.21
  resolution: "lodash-es@https://github.com/x/lodash.git#commit=abc"
  languageName: node
  linkType: hard

"sw@npm:string-width@^4":
  version: 4.2.3
  resolution: "string-width@npm:4.2.3"
  languageName: node
  linkType: hard
"#;

    #[test]
    fn yarn_classic_resolved_elsewhere() {
        let lock = "\
lodash@^4.17.21:
  version \"4.17.21\"
  resolved \"https://registry.yarnpkg.com/lodash-utils/-/lodash-utils-1.0.0.tgz#abc\"
";
        let mut p = Parsed::default();
        parse(lock, Path::new("yarn.lock"), &mut p).unwrap();
        assert_eq!(pins(&p), vec![("lodash-utils".into(), "1.0.0".into(), 1)]);
        assert_eq!(p.mismatches.len(), 1);
        assert!(p.mismatches[0].message.contains("not lodash@4.17.21"));
    }

    #[test]
    fn yarn_classic() {
        let mut p = Parsed::default();
        parse(CLASSIC, Path::new("yarn.lock"), &mut p).unwrap();
        assert_eq!(
            pins(&p),
            vec![
                ("@babel/code-frame".into(), "7.24.2".into(), 5),
                ("js-tokens".into(), "4.0.0".into(), 13),
                ("string-width".into(), "4.2.3".into(), 18),
            ]
        );
        let skipped: Vec<usize> = p.skipped.iter().map(|s| s.line).collect();
        assert_eq!(skipped, vec![22, 26]);
        assert!(p.mismatches.is_empty());
        assert!(p.skipped[1].reason.contains("npm.corp.example"));
    }

    #[test]
    fn yarn_berry_installs_what_the_resolution_names() {
        let lock = r#"__metadata:
  version: 8

"debug@npm:^4.3.1":
  version: 4.3.1
  resolution: "debug@npm:4.4.2"
  languageName: node

"ms@npm:2.1.2":
  version: 2.1.2
  resolution: "ms@npm:2.1.2::__archiveUrl=https%3A%2F%2Fevil.example%2Fms%2F-%2Fms-2.1.2.tgz"
  languageName: node

"chalk@npm:5.3.0":
  version: 5.3.0
  resolution: "chalk@npm:5.3.0::__archiveUrl=https%3A%2F%2Fregistry.npmjs.org%2Fevil-pkg%2F-%2Fevil-pkg-1.0.0.tgz"
  languageName: node

"left-pad@npm:^1.3.0, left-pad@workspace:packages/left-pad":
  version: 1.3.0
  resolution: "left-pad@npm:1.3.0"
  languageName: node

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."
  languageName: unknown
"#;
        let mut p = Parsed::default();
        parse(lock, Path::new("yarn.lock"), &mut p).unwrap();
        // The version in `resolution` is the one fetched; the `version:` field is checked
        // against it.
        assert_eq!(
            pins(&p),
            vec![
                ("debug".into(), "4.4.2".into(), 4),
                ("evil-pkg".into(), "1.0.0".into(), 14),
                ("left-pad".into(), "1.3.0".into(), 19),
            ]
        );
        let m: Vec<(&str, &str, usize)> = p
            .mismatches
            .iter()
            .map(|m| (m.dep.name.as_str(), m.dep.version.as_str(), m.dep.line))
            .collect();
        assert_eq!(m, vec![("debug", "4.3.1", 4), ("chalk", "5.3.0", 14)]);
        assert!(
            p.mismatches[0].message.contains("debug@4.4.2"),
            "{}",
            p.mismatches[0].message
        );
        // An archive URL on another host is a custom registry.
        assert_eq!(p.skipped.len(), 1, "{:?}", p.skipped);
        assert_eq!(p.skipped[0].line, 9);
        assert!(p.skipped[0].reason.contains("evil.example"));
        assert!(p.skipped[0].fetched());
    }

    #[test]
    fn yarn_berry() {
        let mut p = Parsed::default();
        parse(BERRY, Path::new("yarn.lock"), &mut p).unwrap();
        assert_eq!(
            pins(&p),
            vec![
                ("@babel/core".into(), "7.24.0".into(), 8),
                ("resolve".into(), "1.22.8".into(), 30),
                ("string-width".into(), "4.2.3".into(), 42),
            ]
        );
        assert_eq!(p.skipped.len(), 1);
        assert_eq!(p.skipped[0].line, 36);
    }
}
