//! `pnpm-lock.yaml`. Only the keys of the top-level `packages:` map are needed, so the file
//! is read line by line instead of with a YAML parser. Key formats: v5 `/name/1.2.3_peer`,
//! v6 `/name@1.2.3(peer@1)`, v9 `name@1.2.3` (scoped names quoted).

use std::path::Path;

use super::{npm_pin, split_npm_spec, Parsed};

pub(super) fn parse(text: &str, file: &Path, out: &mut Parsed) -> Result<(), String> {
    let mut in_packages = false;
    let mut entry_indent: Option<usize> = None;
    // The entry being read: its line, key, and `resolution.tarball` once seen.
    let mut pending: Option<(usize, String, Option<String>)> = None;
    for (i, raw) in text.lines().enumerate() {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if indent == 0 {
            flush(pending.take(), file, out);
            in_packages = trimmed == "packages:";
            entry_indent = None;
            continue;
        }
        if !in_packages {
            continue;
        }
        let indent_of_entries = *entry_indent.get_or_insert(indent);
        if indent > indent_of_entries {
            if let (Some(p), Some(t)) = (pending.as_mut(), tarball(trimmed)) {
                p.2 = Some(t);
            }
            continue;
        }
        if indent != indent_of_entries {
            continue;
        }
        flush(pending.take(), file, out);
        if let Some(key) = entry_key(trimmed) {
            pending = Some((i + 1, key, tarball(trimmed)));
        }
    }
    flush(pending, file, out);
    Ok(())
}

fn flush(entry: Option<(usize, String, Option<String>)>, file: &Path, out: &mut Parsed) {
    let Some((line, key, tarball)) = entry else {
        return;
    };
    match split_key(&key) {
        Some((name, version)) => npm_pin(out, file, line, name, version, tarball.as_deref()),
        None if key.contains("file:") || key.contains("link:") => {
            out.skip(file, line, &key, "installed from a local path")
        }
        None => out.skip(file, line, &key, "not a registry package (git or URL)"),
    }
}

/// The URL in `tarball: URL` (inline `resolution: {integrity: ..., tarball: URL}` or on
/// its own line). pnpm downloads from it when present, so it is checked like npm's
/// `resolved`.
fn tarball(line: &str) -> Option<String> {
    if !(line.starts_with("resolution:") || line.starts_with("tarball:")) {
        return None;
    }
    let rest = &line[line.find("tarball:")? + "tarball:".len()..];
    let url = rest
        .trim_start()
        .split([',', '}'])
        .next()?
        .trim()
        .trim_matches(|c| c == '\'' || c == '"');
    url.contains("://").then(|| url.to_string())
}

/// The map key on an entry line: `/a@1.0.0:`, `'@s/a@1.0.0':`, `a@1.0.0: {}`.
fn entry_key(line: &str) -> Option<String> {
    if let Some(q) = line.chars().next().filter(|c| *c == '\'' || *c == '"') {
        let end = line[1..].find(q)? + 1;
        return Some(line[1..end].to_string());
    }
    if let Some(k) = line.strip_suffix(':') {
        return Some(k.to_string());
    }
    line.rsplit_once(": ").map(|(k, _)| k.to_string())
}

/// Name and version from a package key, without peer-dependency suffixes.
fn split_key(key: &str) -> Option<(&str, &str)> {
    let key = key.strip_prefix('/').unwrap_or(key);
    let key = key.split('(').next().unwrap_or(key);
    // v5: `/name/1.2.3` or `/@scope/name/1.2.3_peer@1.0.0`; the version follows the
    // name's last `/` and peers follow `_`.
    let skip = if key.starts_with('@') {
        key.find('/').map(|i| i + 1)
    } else {
        Some(0)
    };
    if let Some(slash) = skip.and_then(|s| key[s..].find('/').map(|i| i + s)) {
        let version = &key[slash + 1..];
        if version.starts_with(|c: char| c.is_ascii_digit()) {
            return Some((&key[..slash], version.split('_').next().unwrap_or(version)));
        }
    }
    split_npm_spec(key).or_else(|| key.rsplit_once('/'))
}

#[cfg(test)]
mod tests {
    use super::super::tests::pins;
    use super::*;

    const V6: &str = "\
lockfileVersion: '6.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

dependencies:
  react-dom:
    specifier: ^18.2.0
    version: 18.2.0(react@18.2.0)

packages:

  /@babel/runtime@7.24.0:
    resolution: {integrity: sha512-AAAA}
    engines: {node: '>=6.9.0'}
    dependencies:
      regenerator-runtime: 0.14.1
    dev: false

  /@testing-library/react@14.2.1(react-dom@18.2.0)(react@18.2.0):
    resolution: {integrity: sha512-BBBB}
    peerDependencies:
      react: ^18.0.0
    dev: true

  /react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: sha512-CCCC}
    dev: false

  /react@18.2.0:
    resolution: {integrity: sha512-DDDD}
    dev: false

  github.com/x/forked/0123abc:
    resolution: {tarball: https://codeload.github.com/x/forked/tar.gz/0123abc}
    name: forked
    version: 1.0.0
    dev: false
";

    const V9: &str = "\
lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      '@types/node':
        specifier: ^20
        version: 20.11.30

packages:

  '@types/node@20.11.30':
    resolution: {integrity: sha512-AAAA}

  ms@2.1.2:
    resolution: {integrity: sha512-BBBB}

  local-thing@file:packages/local:
    resolution: {directory: packages/local, type: directory}

snapshots:

  '@types/node@20.11.30':
    dependencies:
      undici-types: 5.26.5

  ms@2.1.2: {}
";

    const V5: &str = "\
lockfileVersion: 5.4

packages:

  /@emotion/react/11.11.4_react@18.2.0:
    resolution: {integrity: sha512-AAAA}

  /left-pad/1.3.0:
    resolution: {integrity: sha512-BBBB}
";

    #[test]
    fn pnpm_v6_with_peer_suffixes() {
        let mut p = Parsed::default();
        parse(V6, Path::new("pnpm-lock.yaml"), &mut p).unwrap();
        assert_eq!(
            pins(&p),
            vec![
                ("@babel/runtime".into(), "7.24.0".into(), 14),
                ("@testing-library/react".into(), "14.2.1".into(), 21),
                ("react-dom".into(), "18.2.0".into(), 27),
                ("react".into(), "18.2.0".into(), 31),
            ]
        );
        assert_eq!(p.skipped.len(), 1);
        assert!(p.mismatches.is_empty());
        assert_eq!(p.skipped[0].line, 35);
    }

    #[test]
    fn pnpm_tarball_is_checked() {
        let lock = "\
lockfileVersion: '9.0'

packages:

  lodash@4.17.21:
    resolution: {integrity: sha512-AAAA, tarball: https://registry.npmjs.org/evil/-/evil-2.0.0.tgz}

  ms@2.1.2:
    resolution:
      integrity: sha512-BBBB
      tarball: 'https://registry.npmjs.org/ms/-/ms-2.1.2.tgz'
    dependencies:
      tarball: 1.0.0

  internal@1.0.0:
    resolution: {integrity: sha512-CCCC, tarball: https://npm.corp.example/internal/-/internal-1.0.0.tgz}
";
        let mut p = Parsed::default();
        parse(lock, Path::new("pnpm-lock.yaml"), &mut p).unwrap();
        assert_eq!(
            pins(&p),
            vec![
                ("evil".into(), "2.0.0".into(), 5),
                ("ms".into(), "2.1.2".into(), 8),
            ]
        );
        assert_eq!(p.mismatches.len(), 1);
        assert_eq!(p.mismatches[0].dep.name, "lodash");
        assert_eq!(p.skipped.len(), 1);
        assert!(p.skipped[0].reason.contains("npm.corp.example"));
    }

    #[test]
    fn pnpm_v9_and_v5() {
        let mut p = Parsed::default();
        parse(V9, Path::new("pnpm-lock.yaml"), &mut p).unwrap();
        assert_eq!(
            pins(&p),
            vec![
                ("@types/node".into(), "20.11.30".into(), 13),
                ("ms".into(), "2.1.2".into(), 16),
            ]
        );
        assert_eq!(p.skipped.len(), 1);
        assert_eq!(p.skipped[0].spec, "local-thing@file:packages/local");

        let mut p = Parsed::default();
        parse(V5, Path::new("pnpm-lock.yaml"), &mut p).unwrap();
        assert_eq!(
            pins(&p),
            vec![
                ("@emotion/react".into(), "11.11.4".into(), 5),
                ("left-pad".into(), "1.3.0".into(), 8),
            ]
        );
    }
}
