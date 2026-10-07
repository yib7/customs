//! `uv.lock`: one `[[package]]` table per locked package, with a `source` table saying
//! where it comes from.

use std::path::Path;

use customs_scan::Ecosystem;
use serde::Deserialize;
use toml::Spanned;

use super::{host_of, known_registry, LineIndex, Parsed};

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
            continue;
        };
        let spec = format!("{name}=={version}");
        if source.contains_key("path") {
            out.skip(file, line, &spec, "installed from a local path");
        } else if let Some(url) = source.get("git").or_else(|| source.get("url")) {
            out.skip(
                file,
                line,
                &spec,
                format!("installed from {}", url.as_str().unwrap_or("a URL")),
            );
        } else {
            match source.get("registry").and_then(|r| r.as_str()) {
                Some(r) if !known_registry(r) => out.skip(
                    file,
                    line,
                    &spec,
                    format!("from a custom package index ({})", host_of(r)),
                ),
                _ => out.dep(Ecosystem::Pypi, name, &version, file, line),
            }
        }
    }
    Ok(())
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
}
