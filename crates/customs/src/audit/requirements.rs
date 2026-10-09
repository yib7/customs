//! pip requirements files. Only `name==version` (or `===`) pins are checked; `-r` includes
//! are followed relative to the including file. An index other than PyPI (`-i`,
//! `--extra-index-url`, `--find-links`, `--no-index`) leaves every pin unchecked.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use customs_scan::Ecosystem;
use regex::Regex;

use super::{host_of, Parsed, SkipKind};
use crate::hook::parse::{looks_like_path, looks_like_url};

const MAX_INCLUDE_DEPTH: usize = 10;

pub(super) fn parse(path: &Path, out: &mut Parsed) -> Result<(), String> {
    let mut own = Parsed {
        trusted: out.trusted.clone(),
        ..Parsed::default()
    };
    let mut index = None;
    parse_file(path, &mut own, &mut HashSet::new(), 0, &mut index)?;
    // Index options apply to the whole install, wherever they appear: with another index in
    // play, pip may take any pin from it, so a PyPI verdict says nothing about what is
    // installed (dependency confusion).
    if let Some(reason) = index {
        for d in std::mem::take(&mut own.deps) {
            let spec = format!("{}=={}", d.name, d.version);
            own.skip(
                &d.file,
                d.line,
                &spec,
                SkipKind::CustomIndex,
                reason.clone(),
            );
        }
    }
    out.deps.extend(own.deps);
    out.skipped.extend(own.skipped);
    Ok(())
}

/// The file's text: UTF-8, or UTF-16 with a byte order mark, which Windows PowerShell 5.1
/// writes for `pip freeze > requirements.txt`.
fn read_text(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let utf16 = |body: &[u8], unit: fn([u8; 2]) -> u16| {
        let units: Vec<u16> = body
            .chunks(2)
            .map(|c| unit([c[0], c.get(1).copied().unwrap_or(0)]))
            .collect();
        String::from_utf16(&units).map_err(|_| format!("{}: not valid UTF-16 text", path.display()))
    };
    match bytes.as_slice() {
        [0xFF, 0xFE, body @ ..] => utf16(body, u16::from_le_bytes),
        [0xFE, 0xFF, body @ ..] => utf16(body, u16::from_be_bytes),
        _ => String::from_utf8(bytes).map_err(|_| {
            format!(
                "{}: not valid UTF-8 text; re-save the file as UTF-8",
                path.display()
            )
        }),
    }
}

fn parse_file(
    path: &Path,
    out: &mut Parsed,
    seen: &mut HashSet<PathBuf>,
    depth: usize,
    index: &mut Option<String>,
) -> Result<(), String> {
    if !seen.insert(std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())) {
        return Ok(());
    }
    let text = read_text(path)?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let dir = path.parent().unwrap_or(Path::new(""));
    for (line, content) in logical_lines(text) {
        let t = content.trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with('-') {
            let (flag, value) = split_option(t);
            match flag {
                "-r" | "--requirement" | "--requirements" => {
                    if looks_like_url(value) {
                        return Err(format!(
                            "{}:{line}: remote requirements file {value} is not supported; download it and audit the copy",
                            path.display()
                        ));
                    }
                    let included = dir.join(value);
                    if depth + 1 > MAX_INCLUDE_DEPTH {
                        return Err(format!(
                            "{}:{line}: requirement files nested too deeply",
                            path.display()
                        ));
                    }
                    if !included.is_file() {
                        return Err(format!(
                            "{}:{line}: included file {} not found",
                            path.display(),
                            included.display()
                        ));
                    }
                    parse_file(&included, out, seen, depth + 1, index)?;
                }
                "-e" | "--editable" => {
                    // `-e git+https://...` checks out and installs code from elsewhere.
                    let kind = if looks_like_url(value) {
                        SkipKind::Source
                    } else {
                        SkipKind::Local
                    };
                    out.skip(path, line, t, kind, "editable install");
                }
                "-i" | "--index-url" | "--extra-index-url" if !out.known_registry(value) => {
                    index.get_or_insert_with(|| {
                        format!("from a custom package index ({})", host_of(value))
                    });
                }
                "-f" | "--find-links" if !(looks_like_url(value) && out.known_registry(value)) => {
                    let shown = if looks_like_url(value) {
                        host_of(value)
                    } else {
                        value.to_string()
                    };
                    index.get_or_insert_with(|| {
                        format!("from a custom package index (--find-links {shown})")
                    });
                }
                "--no-index" => {
                    index.get_or_insert_with(|| {
                        "from a custom package index (--no-index: pip does not use PyPI)".into()
                    });
                }
                // Constraints pin versions but install nothing; build options do not name
                // packages.
                _ => {}
            }
            continue;
        }
        requirement(t, path, line, out);
    }
    Ok(())
}

/// Logical lines with comments removed and `\` continuations joined, numbered by their
/// first physical line.
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut cur: Option<(usize, String)> = None;
    for (i, raw) in text.lines().enumerate() {
        let l = strip_comment(raw);
        let (body, continued) = match l.strip_suffix('\\') {
            Some(b) => (b, true),
            None => (l, false),
        };
        match &mut cur {
            Some((_, s)) => {
                s.push(' ');
                s.push_str(body);
            }
            None => cur = Some((i + 1, body.to_string())),
        }
        if !continued {
            out.extend(cur.take());
        }
    }
    out.extend(cur.take());
    out
}

/// pip's rule: `#` starts a comment at the start of a line or after whitespace, so URL
/// fragments such as `#egg=` survive.
fn strip_comment(l: &str) -> &str {
    let b = l.as_bytes();
    for (i, c) in l.char_indices() {
        if c == '#' && (i == 0 || b[i - 1].is_ascii_whitespace()) {
            return &l[..i];
        }
    }
    l
}

/// `-r file`, `-rfile`, `--requirement=file`, `--requirement file`.
fn split_option(t: &str) -> (&str, &str) {
    if t.starts_with("--") {
        let end = t
            .find(|c: char| c == '=' || c.is_whitespace())
            .unwrap_or(t.len());
        let value = t[end..].trim_start_matches(|c: char| c == '=' || c.is_whitespace());
        (&t[..end], value.trim())
    } else {
        let end = t.char_indices().nth(2).map(|(i, _)| i).unwrap_or(t.len());
        let value = t[end..].trim_start_matches(|c: char| c == '=' || c.is_whitespace());
        (&t[..end], value.trim())
    }
}

fn requirement(t: &str, path: &Path, line: usize, out: &mut Parsed) {
    // Per-requirement options such as `--hash=sha256:...` follow the requirement.
    static OPT: OnceLock<Regex> = OnceLock::new();
    let opt = OPT.get_or_init(|| Regex::new(r"\s+--?[A-Za-z]").unwrap());
    let req = match opt.find(t) {
        Some(m) => &t[..m.start()],
        None => t,
    }
    .trim();
    if looks_like_url(req) {
        out.skip(
            path,
            line,
            req,
            SkipKind::Source,
            "installed from a URL or VCS",
        );
        return;
    }
    // Environment markers do not change what is pinned.
    let spec = req.split(';').next().unwrap_or("").trim();
    if looks_like_path(spec) || spec.contains('/') {
        out.skip(
            path,
            line,
            req,
            SkipKind::Local,
            "installed from a local path",
        );
        return;
    }
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$")
            .unwrap()
    });
    let Some(c) = re.captures(spec) else {
        out.skip(
            path,
            line,
            req,
            SkipKind::Other,
            "could not parse the requirement",
        );
        return;
    };
    let compact: String = c[3].chars().filter(|c| !c.is_whitespace()).collect();
    let compact = compact.trim_start_matches('(').trim_end_matches(')');
    let pinned = compact
        .strip_prefix("===")
        .or_else(|| compact.strip_prefix("=="))
        .filter(|v| {
            !v.is_empty()
                && v.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+' | '!'))
        });
    match pinned {
        Some(v) => out.dep(Ecosystem::Pypi, &c[1], v, path, line),
        None => out.skip(
            path,
            line,
            req,
            SkipKind::Unpinned,
            if compact.is_empty() {
                "no version pinned (use name==version)"
            } else {
                "not pinned to an exact version (use ==)"
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::pins;
    use super::*;

    #[test]
    fn requirements_with_includes_markers_hashes_and_continuations() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        std::fs::create_dir_all(d.join("reqs")).unwrap();
        std::fs::write(
            d.join("requirements.txt"),
            "\
# Production dependencies
--index-url https://pypi.org/simple
Django==4.2.11  # LTS
requests[socks,security] == 2.31.0 ; python_version >= \"3.8\"
-r reqs/base.txt
flask>=2.0
numpy
cryptography==42.0.5 \\
    --hash=sha256:aaaa \\
    --hash=sha256:bbbb
-e ./local-lib
-e git+https://github.com/x/y.git#egg=y
pkg @ https://example.com/pkg-1.0.tar.gz
./wheels/thing-1.0-py3-none-any.whl
zope.interface===6.2
Typing_Extensions==4.10.0;python_version<'3.11'
pinned-wild==1.2.*
-c constraints.txt
urllib3==2.2.1 \\
  # a comment ends the continuation
six==1.16.0
",
        )
        .unwrap();
        std::fs::write(
            d.join("reqs/base.txt"),
            "attrs==23.2.0\n-r ../requirements.txt\n--requirement=more.txt\n",
        )
        .unwrap();
        std::fs::write(d.join("reqs/more.txt"), "\n\nidna==3.6\n").unwrap();

        let mut p = Parsed::default();
        parse(&d.join("requirements.txt"), &mut p).unwrap();
        assert_eq!(
            pins(&p),
            vec![
                ("django".into(), "4.2.11".into(), 3),
                ("requests".into(), "2.31.0".into(), 4),
                ("attrs".into(), "23.2.0".into(), 1),
                ("idna".into(), "3.6".into(), 3),
                ("cryptography".into(), "42.0.5".into(), 8),
                ("zope-interface".into(), "6.2".into(), 15),
                ("typing-extensions".into(), "4.10.0".into(), 16),
                ("urllib3".into(), "2.2.1".into(), 19),
                ("six".into(), "1.16.0".into(), 21),
            ]
        );
        assert!(p.deps[2].file.ends_with("reqs/base.txt"));
        assert!(p.deps[3].file.ends_with("reqs/more.txt"));
        let skipped: Vec<(usize, &str)> = p
            .skipped
            .iter()
            .map(|s| (s.line, s.reason.as_str()))
            .collect();
        assert_eq!(skipped.len(), 7, "{skipped:?}");
        assert_eq!(skipped[0].0, 6);
        assert!(skipped[0].1.contains("exact version"));
        assert_eq!(skipped[1].0, 7);
        assert!(skipped[1].1.contains("no version pinned"));
        assert_eq!(skipped[2].0, 11);
        assert!(skipped[2].1.contains("editable"));
        // An editable local path is the project's own code; an editable VCS URL fetches it.
        assert!(!p.skipped[2].fetched());
        assert_eq!(skipped[3].0, 12);
        assert_eq!(p.skipped[3].kind, SkipKind::Source);
        assert!(p.skipped[3].fetched());
        assert_eq!(skipped[4].0, 13);
        assert!(skipped[4].1.contains("URL"));
        assert_eq!(skipped[5].0, 14);
        assert!(skipped[5].1.contains("local path"));
        assert_eq!(skipped[6].0, 17);
    }

    #[test]
    fn custom_indexes_leave_pins_unchecked() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        for (text, host) in [
            (
                "requests==2.31.0\n--extra-index-url https://evil.example/simple\n",
                "evil.example",
            ),
            (
                "-i https://pypi.corp.example/simple\nrequests==2.31.0\n",
                "pypi.corp.example",
            ),
            (
                "--index-url=https://pypi.corp.example/simple\nrequests==2.31.0\n",
                "pypi.corp.example",
            ),
            ("--find-links ./wheels\nrequests==2.31.0\n", "./wheels"),
            (
                "-f https://wheels.example/\nrequests==2.31.0\n",
                "wheels.example",
            ),
            ("--no-index\nrequests==2.31.0\n", "--no-index"),
        ] {
            std::fs::write(d.join("requirements.txt"), text).unwrap();
            let mut p = Parsed::default();
            parse(&d.join("requirements.txt"), &mut p).unwrap();
            assert!(p.deps.is_empty(), "{text}: {:?}", p.deps);
            assert_eq!(p.skipped.len(), 1, "{text}: {:?}", p.skipped);
            let s = &p.skipped[0];
            assert_eq!(s.spec, "requests==2.31.0", "{text}");
            assert_eq!(s.kind, SkipKind::CustomIndex, "{text}");
            assert!(s.reason.contains(host), "{text}: {}", s.reason);
        }
        // An index option in an included file applies to the whole install.
        std::fs::write(
            d.join("base.txt"),
            "--extra-index-url https://evil.example/simple\n",
        )
        .unwrap();
        std::fs::write(
            d.join("requirements.txt"),
            "requests==2.31.0\n-r base.txt\n",
        )
        .unwrap();
        let mut p = Parsed::default();
        parse(&d.join("requirements.txt"), &mut p).unwrap();
        assert!(p.deps.is_empty(), "{:?}", p.deps);
        // PyPI itself is fine.
        std::fs::write(
            d.join("requirements.txt"),
            "--index-url https://pypi.org/simple/\nrequests==2.31.0\n",
        )
        .unwrap();
        let mut p = Parsed::default();
        parse(&d.join("requirements.txt"), &mut p).unwrap();
        assert_eq!(p.deps.len(), 1);
    }

    #[test]
    fn remote_includes_and_utf16_files_get_clear_errors() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("requirements.txt");
        std::fs::write(&f, "a==1\n-r https://example.com/reqs.txt\n").unwrap();
        let e = parse(&f, &mut Parsed::default()).unwrap_err();
        assert!(
            e.contains("requirements.txt:2") && e.contains("remote"),
            "{e}"
        );
        // `pip freeze > requirements.txt` in Windows PowerShell 5.1 writes UTF-16 LE.
        let mut bytes = vec![0xFF, 0xFE];
        for u in "six==1.16.0\r\nidna==3.6\r\n".encode_utf16() {
            bytes.extend(u.to_le_bytes());
        }
        std::fs::write(&f, bytes).unwrap();
        let mut p = Parsed::default();
        parse(&f, &mut p).unwrap();
        assert_eq!(
            pins(&p),
            vec![
                ("six".into(), "1.16.0".into(), 1),
                ("idna".into(), "3.6".into(), 2)
            ]
        );
        std::fs::write(&f, [0x61, 0x3d, 0x3d, 0xff, 0x0a]).unwrap();
        let e = parse(&f, &mut Parsed::default()).unwrap_err();
        assert!(e.contains("UTF-8"), "{e}");
    }

    #[test]
    fn missing_include_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("requirements.txt");
        std::fs::write(&f, "a==1\n-r nope.txt\n").unwrap();
        let e = parse(&f, &mut Parsed::default()).unwrap_err();
        assert!(
            e.contains("requirements.txt:2") && e.contains("nope.txt"),
            "{e}"
        );
    }

    #[test]
    fn options() {
        assert_eq!(split_option("-r a.txt"), ("-r", "a.txt"));
        assert_eq!(split_option("-ra.txt"), ("-r", "a.txt"));
        assert_eq!(
            split_option("--requirement=a.txt"),
            ("--requirement", "a.txt")
        );
        assert_eq!(
            split_option("--requirement  a.txt"),
            ("--requirement", "a.txt")
        );
        assert_eq!(strip_comment("x==1 # c"), "x==1 ");
        assert_eq!(
            strip_comment("git+https://h/x#egg=x"),
            "git+https://h/x#egg=x"
        );
    }
}
