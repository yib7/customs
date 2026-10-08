//! Archives too large to scan (DESIGN.md section 4.7): what they would run at install,
//! read by streaming entry headers from disk instead of holding the archive in memory.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use serde_json::Value;

use crate::archive::{normalize_path, sniff_format, Format};
use crate::surface::NPM_INSTALL_HOOKS;
use crate::Ecosystem;

const MAX_MANIFEST_BYTES: u64 = 1 << 20;

/// Install-time code in an archive the scanner will not read, as labels (`package.json:
/// scripts.postinstall`, `setup.py`, `foo.pth`). Empty when nothing runs at install. An
/// archive whose layout cannot be read is reported as one label, so callers fail closed.
pub fn install_time_code(path: &Path, eco: Ecosystem, filename: &str) -> Vec<String> {
    let lower = filename.to_ascii_lowercase();
    match eco {
        // Building an sdist runs its setup.py or build backend.
        Ecosystem::Pypi if !lower.ends_with(".whl") => vec!["sdist build (setup.py)".into()],
        Ecosystem::Pypi => wheel_pth(path).unwrap_or_else(|| vec!["unreadable archive".into()]),
        Ecosystem::Npm => npm_hooks(path).unwrap_or_else(|| vec!["unreadable archive".into()]),
    }
}

/// `.pth` files at the root of a wheel land in site-packages, where Python runs their
/// import lines at every interpreter start.
fn wheel_pth(path: &Path) -> Option<Vec<String>> {
    let zip = zip::ZipArchive::new(BufReader::new(File::open(path).ok()?)).ok()?;
    Some(
        zip.file_names()
            .filter_map(normalize_path)
            .filter(|n| {
                let n = n
                    .split_once(".data/purelib/")
                    .map_or(n.as_str(), |(_, r)| r);
                let n = n.split_once(".data/platlib/").map_or(n, |(_, r)| r);
                !n.contains('/') && n.to_ascii_lowercase().ends_with(".pth")
            })
            .collect(),
    )
}

/// npm install hooks declared in the root `package.json`, plus the implicit
/// `node-gyp rebuild` of a root `binding.gyp`.
fn npm_hooks(path: &Path) -> Option<Vec<String>> {
    let mut f = File::open(path).ok()?;
    let mut head = [0u8; 512];
    let n = f.read(&mut head).ok()?;
    f.seek(SeekFrom::Start(0)).ok()?;
    let reader: Box<dyn Read> = match sniff_format(&head[..n])? {
        Format::Gzip => Box::new(flate2::read::MultiGzDecoder::new(BufReader::new(f))),
        Format::Tar => Box::new(BufReader::new(f)),
        _ => return None,
    };
    let mut pj: Option<Value> = None;
    let mut gyp = false;
    let mut tar = tar::Archive::new(reader);
    for entry in tar.entries().ok()? {
        let mut e = entry.ok()?;
        let Some(p) = normalize_path(&String::from_utf8_lossy(&e.path_bytes())) else {
            continue;
        };
        // npm tarballs hold one top-level directory (usually `package/`).
        let Some((_, rest)) = p.split_once('/') else {
            continue;
        };
        if rest == "binding.gyp" {
            gyp = true;
        } else if rest == "package.json" && pj.is_none() {
            let mut text = String::new();
            (&mut e)
                .take(MAX_MANIFEST_BYTES)
                .read_to_string(&mut text)
                .ok()?;
            pj = Some(serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?);
        }
    }
    let pj = pj?;
    let scripts = pj.get("scripts").and_then(Value::as_object);
    let has = |h: &str| {
        scripts
            .and_then(|s| s.get(h))
            .and_then(Value::as_str)
            .is_some_and(|c| !c.trim().is_empty())
    };
    let mut out: Vec<String> = NPM_INSTALL_HOOKS
        .iter()
        .filter(|h| has(h))
        .map(|h| format!("package.json:scripts.{h}"))
        .collect();
    let gypfile = pj.get("gypfile").and_then(Value::as_bool) != Some(false);
    if gyp && gypfile && !has("install") && !has("preinstall") {
        out.push("binding.gyp (implicit node-gyp rebuild)".into());
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("customs-large-{}-{name}", std::process::id()));
        std::fs::write(&p, bytes).unwrap();
        p
    }

    fn tgz(files: &[(&str, &str)]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (p, d) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(d.len() as u64);
            h.set_mode(0o644);
            b.append_data(&mut h, p, d.as_bytes()).unwrap();
        }
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(&b.into_inner().unwrap()).unwrap();
        e.finish().unwrap()
    }

    fn whl(names: &[&str]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        for n in names {
            w.start_file(*n, zip::write::SimpleFileOptions::default())
                .unwrap();
            w.write_all(b"x").unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn npm_install_hooks_and_implicit_gyp() {
        let p = tmp(
            "hooks.tgz",
            &tgz(&[
                (
                    "package/package.json",
                    r#"{"name":"a","scripts":{"postinstall":"node x.js","test":"jest","prepare":" "}}"#,
                ),
                ("package/x.js", "1"),
            ]),
        );
        assert_eq!(
            install_time_code(&p, Ecosystem::Npm, "a-1.0.0.tgz"),
            vec!["package.json:scripts.postinstall"]
        );
        let p = tmp(
            "gyp.tgz",
            &tgz(&[
                ("package/package.json", r#"{"name":"a"}"#),
                ("package/binding.gyp", "{}"),
            ]),
        );
        assert_eq!(
            install_time_code(&p, Ecosystem::Npm, "a-1.0.0.tgz"),
            vec!["binding.gyp (implicit node-gyp rebuild)"]
        );
        let p = tmp(
            "plain.tgz",
            &tgz(&[("package/package.json", r#"{"name":"a","main":"x.js"}"#)]),
        );
        assert!(install_time_code(&p, Ecosystem::Npm, "a-1.0.0.tgz").is_empty());
        let p = tmp("junk.tgz", b"not an archive");
        assert_eq!(
            install_time_code(&p, Ecosystem::Npm, "a-1.0.0.tgz"),
            vec!["unreadable archive"]
        );
    }

    #[test]
    fn pypi_sdists_build_and_wheels_only_run_pth() {
        let p = tmp("sdist.tar.gz", b"irrelevant");
        assert_eq!(
            install_time_code(&p, Ecosystem::Pypi, "a-1.0.tar.gz"),
            vec!["sdist build (setup.py)"]
        );
        let p = tmp(
            "plain.whl",
            &whl(&["a/__init__.py", "a-1.0.dist-info/METADATA", "a/data/x.pth"]),
        );
        assert!(install_time_code(&p, Ecosystem::Pypi, "a-1.0-py3-none-any.whl").is_empty());
        let p = tmp(
            "pth.whl",
            &whl(&["a/__init__.py", "a-hook.pth", "a-1.0.data/purelib/b.pth"]),
        );
        assert_eq!(
            install_time_code(&p, Ecosystem::Pypi, "a-1.0-py3-none-any.whl"),
            vec!["a-hook.pth", "a-1.0.data/purelib/b.pth"]
        );
    }
}
