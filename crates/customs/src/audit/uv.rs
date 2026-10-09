//! `uv.lock`: one `[[package]]` table per locked package, with a `source` table saying
//! where it comes from.

use std::cmp::Ordering;
use std::path::Path;

use customs_scan::Ecosystem;
use serde::Deserialize;
use toml::Spanned;

use super::{host_of, LineIndex, Parsed, SkipKind};
use crate::resolve::compare_versions;
use crate::util::normalize_name;

#[derive(Deserialize)]
struct Lock {
    #[serde(default)]
    package: Vec<Package>,
}

#[derive(Deserialize)]
struct Package {
    name: Spanned<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    source: Option<toml::Table>,
    #[serde(default)]
    sdist: Option<Dist>,
    #[serde(default)]
    wheels: Vec<Dist>,
}

/// A file uv downloads for the package.
#[derive(Deserialize)]
struct Dist {
    #[serde(default)]
    url: Option<String>,
}

pub(super) fn parse(text: &str, file: &Path, out: &mut Parsed) -> Result<(), String> {
    let lock: Lock = toml::from_str(text).map_err(|e| e.to_string().trim_end().to_string())?;
    let lines = LineIndex::new(text);
    for p in lock.package {
        let line = lines.line(p.name.span().start);
        let name = p.name.get_ref();
        let source = p.source.unwrap_or_default();
        // The project itself and workspace members.
        if ["editable", "virtual", "directory"]
            .iter()
            .any(|k| source.contains_key(*k))
        {
            continue;
        }
        let Some(version) = p.version else {
            out.skip(file, line, name, SkipKind::Other, "no version recorded");
            continue;
        };
        let spec = format!("{name}=={version}");
        if source.contains_key("path") {
            out.skip(
                file,
                line,
                &spec,
                SkipKind::Local,
                "installed from a local path",
            );
        } else if let Some(url) = source.get("git").or_else(|| source.get("url")) {
            out.skip(
                file,
                line,
                &spec,
                SkipKind::Source,
                format!("installed from {}", url.as_str().unwrap_or("a URL")),
            );
        } else {
            match source.get("registry").and_then(|r| r.as_str()) {
                Some(r) if !out.known_registry(r) => out.skip(
                    file,
                    line,
                    &spec,
                    SkipKind::CustomIndex,
                    format!("from a custom package index ({})", host_of(r)),
                ),
                _ => {
                    let urls: Vec<&str> = p
                        .sdist
                        .iter()
                        .chain(&p.wheels)
                        .filter_map(|d| d.url.as_deref())
                        .collect();
                    registry_pin(out, file, line, name, &version, &urls);
                }
            }
        }
    }
    Ok(())
}

/// A registry entry and the files uv downloads for it. uv fetches those URLs as written, so
/// a file on another host is not what the registry serves, and a file of another package
/// is checked in place of the name the entry shows.
fn registry_pin(
    out: &mut Parsed,
    file: &Path,
    line: usize,
    name: &str,
    version: &str,
    urls: &[&str],
) {
    let spec = format!("{name}=={version}");
    if let Some(u) = urls.iter().find(|u| !out.known_registry(u)) {
        out.skip(
            file,
            line,
            &spec,
            SkipKind::CustomIndex,
            format!("downloads from {}", host_of(u)),
        );
        return;
    }
    let want = normalize_name(Ecosystem::Pypi, name);
    for u in urls {
        let Some((n, v)) = dist_identity(u) else {
            continue;
        };
        if normalize_name(Ecosystem::Pypi, &n) != want
            || compare_versions(Ecosystem::Pypi, &v, version) != Ordering::Equal
        {
            out.mismatch_in(
                Ecosystem::Pypi,
                name,
                version,
                file,
                line,
                format!("lockfile downloads {n} {v} ({u}), not {name} {version}"),
            );
            out.dep(Ecosystem::Pypi, &n, &v, file, line);
            return;
        }
    }
    out.dep(Ecosystem::Pypi, name, version, file, line);
}

/// The name and version a distribution file name carries: `name-ver-....whl` for a wheel,
/// `name-ver.tar.gz` (or `.zip`, `.tar.bz2`) for an sdist, where older sdists keep dashes
/// in the name.
fn dist_identity(url: &str) -> Option<(String, String)> {
    let path = url::Url::parse(url).ok()?.path().to_string();
    let file = percent_encoding::percent_decode_str(path.rsplit('/').next()?)
        .decode_utf8()
        .ok()?
        .into_owned();
    if let Some(stem) = file.strip_suffix(".whl") {
        let mut parts = stem.split('-');
        let (n, v) = (parts.next()?, parts.next()?);
        return Some((n.to_string(), v.to_string()));
    }
    let stem = [".tar.gz", ".zip", ".tar.bz2", ".tar.xz", ".tgz"]
        .iter()
        .find_map(|e| file.strip_suffix(e))?;
    let (n, v) = stem.rsplit_once('-')?;
    Some((n.to_string(), v.to_string()))
}

#[cfg(test)]
mod tests {
    use super::super::tests::pins;
    use super::*;

    const LOCK: &str = r#"version = 1
requires-python = ">=3.12"

[[package]]
name = "anyio"
version = "4.3.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "idna" },
    { name = "sniffio" },
]
sdist = { url = "https://files.pythonhosted.org/packages/anyio-4.3.0.tar.gz", hash = "sha256:f75253795a87df48568485fd18cdd2a3fa5c4f7c5be8e5e36637733fce06fed6", size = 159642 }

[[package]]
name = "demo"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "anyio" },
]

[[package]]
name = "idna"
version = "3.6"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "corp-utils"
version = "2.0.0"
source = { registry = "https://pypi.corp.example/simple" }

[[package]]
name = "member"
version = "0.0.1"
source = { virtual = "packages/member" }

[[package]]
name = "vendored"
version = "1.0"
source = { path = "wheels/vendored-1.0-py3-none-any.whl" }

[[package]]
name = "from-git"
version = "0.3.0"
source = { git = "https://github.com/x/from-git?rev=abc#abc" }

[[package]]
name = "Sniffio"
version = "1.3.1"
source = { registry = "http://127.0.0.1:7878/pypi/simple" }
"#;

    #[test]
    fn uv_lock() {
        let mut p = Parsed::default();
        parse(LOCK, Path::new("uv.lock"), &mut p).unwrap();
        assert_eq!(
            pins(&p),
            vec![
                ("anyio".into(), "4.3.0".into(), 5),
                ("idna".into(), "3.6".into(), 23),
                ("sniffio".into(), "1.3.1".into(), 48),
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
                (28, "corp-utils==2.0.0"),
                (38, "vendored==1.0"),
                (43, "from-git==0.3.0")
            ]
        );
        assert!(p.skipped[2].reason.contains("github.com"));
    }
    #[test]
    fn download_urls_must_match_the_entry() {
        let lock = r#"version = 1

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/ab/evil-1.0-py3-none-any.whl", hash = "sha256:00" },
]

[[package]]
name = "idna"
version = "3.6"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://evil.example/idna-3.6.tar.gz", hash = "sha256:00" }

[[package]]
name = "nover"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "zope-interface"
version = "6.2.0"
source = { registry = "https://pypi.org/simple" }
sdist = { url = "https://files.pythonhosted.org/packages/zope.interface-6.2.tar.gz", hash = "sha256:00" }
wheels = [
    { url = "https://files.pythonhosted.org/packages/zope.interface-6.2-cp312-cp312-manylinux_2_17_x86_64.whl", hash = "sha256:00" },
    { url = "https://files.pythonhosted.org/packages/Zope_Interface-6.2-1-cp311-cp311-win_amd64.whl", hash = "sha256:00" },
]
"#;
        let mut p = Parsed::default();
        parse(lock, Path::new("uv.lock"), &mut p).unwrap();
        // A wheel of another package under a trusted name is a mismatch, checked as what
        // it serves.
        let m: Vec<(&str, &str, Ecosystem, usize)> = p
            .mismatches
            .iter()
            .map(|m| {
                (
                    m.dep.name.as_str(),
                    m.dep.version.as_str(),
                    m.dep.ecosystem,
                    m.dep.line,
                )
            })
            .collect();
        assert_eq!(m, vec![("requests", "2.31.0", Ecosystem::Pypi, 4)]);
        assert!(
            p.mismatches[0].message.contains("evil"),
            "{}",
            p.mismatches[0].message
        );
        // A file from another host, and an entry without a version, are listed.
        let skipped: Vec<(usize, &str, SkipKind)> = p
            .skipped
            .iter()
            .map(|s| (s.line, s.reason.as_str(), s.kind))
            .collect();
        assert_eq!(skipped.len(), 2, "{skipped:?}");
        assert_eq!((skipped[0].0, skipped[0].2), (12, SkipKind::CustomIndex));
        assert!(skipped[0].1.contains("evil.example"), "{skipped:?}");
        assert_eq!((skipped[1].0, skipped[1].2), (18, SkipKind::Other));
        assert!(skipped[1].1.contains("no version"), "{skipped:?}");
        // Normalised names and equal versions match.
        assert_eq!(
            pins(&p),
            vec![
                ("evil".into(), "1.0".into(), 4),
                ("zope-interface".into(), "6.2.0".into(), 22)
            ]
        );
    }
}
