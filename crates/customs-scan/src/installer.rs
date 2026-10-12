//! Files an installer extracts differently from how the scanner reads the archive.
//!
//! The scanner reads the first copy of a duplicated path, strips only a single top-level
//! directory, and never follows links. pip and npm keep the last copy, npm strips the first
//! path component of every entry, and pip extracts a tar link as a file. The features keep
//! the scanner's own view (they are what the models were trained on); each code file the
//! installer would see differently is reported instead, as an `unread_code` label with the
//! reason in parentheses.

use std::collections::{HashMap, HashSet};

use crate::archive::{is_code_like, node_tar_path, normalize_path, Contents, Entry, Format};

fn same(a: &Entry, b: &Entry) -> bool {
    a.full == b.full && a.data == b.data
}

/// Code paths of the package root that appear more than once with different content.
/// Installers write every copy in turn, so the last one is what gets installed.
pub(crate) fn duplicates(c: &Contents) -> Vec<(String, String)> {
    let mut first_last: HashMap<&str, (usize, usize)> = HashMap::new();
    let mut order: Vec<&str> = Vec::new();
    for (i, e) in c.entries.iter().enumerate().filter(|(_, e)| e.depth == 0) {
        first_last
            .entry(e.path.as_str())
            .and_modify(|fl| fl.1 = i)
            .or_insert_with(|| {
                order.push(e.path.as_str());
                (i, i)
            });
    }
    order
        .into_iter()
        .filter(|p| {
            let (f, l) = first_last[p];
            f != l && !same(&c.entries[f], &c.entries[l]) && is_code_like(p, &c.entries[l].data)
        })
        .map(|p| {
            (
                p.to_string(),
                format!("{p} (duplicate entry; installers keep the last copy)"),
            )
        })
        .collect()
}

/// Code files that npm writes to a path where the scanner read something else, or
/// nothing. npm extracts with node-tar and `strip: 1` (see [`node_tar_path`]), the last
/// copy of a path winning; the scanner strips a top-level directory only when it is the
/// only one. Paths in `skip` are already reported.
pub(crate) fn npm_mismatches(
    c: &Contents,
    index: &HashMap<&str, usize>,
    skip: &HashSet<String>,
) -> Vec<String> {
    if !matches!(c.format, Some(Format::Gzip | Format::Tar | Format::Bzip2)) {
        return Vec::new();
    }
    let mut view: HashMap<String, usize> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for (i, e) in c.entries.iter().enumerate().filter(|(_, e)| e.depth == 0) {
        let Some(p) = node_tar_path(&e.raw) else {
            continue;
        };
        if view.insert(p.clone(), i).is_none() {
            order.push(p);
        }
    }
    order
        .into_iter()
        .filter(|p| {
            let e = &c.entries[view[p]];
            is_code_like(p, &e.data)
                && !skip.contains(p)
                && !index
                    .get(p.as_str())
                    .is_some_and(|&j| same(&c.entries[j], e))
        })
        .map(|p| format!("{p} (npm extracts a different file than the scanner read)"))
        .collect()
}

/// Tar link entries pip would extract as code files the scanner never read. pip extracts a
/// hard link with its target's content and an in-archive symlink as a link, so an
/// installer-run file can be one. A link is let through only when its target is a
/// scanned source file of the archive and the link itself sits nowhere the install runs
/// (`install_time`); old sdists do ship symlinked and hardlinked copies of modules.
pub(crate) fn pypi_links(
    c: &Contents,
    index: &HashMap<&str, usize>,
    install_time: &dyn Fn(&str) -> bool,
) -> Vec<String> {
    let mut out = Vec::new();
    for l in &c.links {
        if !is_code_like(&l.path, b"") {
            continue;
        }
        let target = if l.hard {
            // Relative to the archive root, as written.
            normalize_path(&l.target).and_then(|t| {
                c.entries
                    .iter()
                    .rposition(|e| e.depth == 0 && normalize_path(&e.raw).as_deref() == Some(&t))
            })
        } else {
            let dir = l.path.rsplit_once('/').map_or("", |(d, _)| d);
            resolve_symlink(dir, &l.target).and_then(|t| index.get(t.as_str()).copied())
        };
        let scanned = target.is_some_and(|i| {
            let e = &c.entries[i];
            e.full && crate::is_source(&e.path)
        });
        if !scanned || install_time(&l.path) {
            let kind = if l.hard { "hardlink" } else { "symlink" };
            out.push(format!(
                "{} ({kind} to {}; pip extracts the link as a file)",
                l.path, l.target
            ));
        }
    }
    out
}

/// A relative symlink target resolved against the link's directory, within the package
/// root; `None` for an absolute target or one that leaves the root.
fn resolve_symlink(dir: &str, target: &str) -> Option<String> {
    if target.starts_with(['/', '\\']) || target.as_bytes().get(1) == Some(&b':') {
        return None;
    }
    let mut parts: Vec<&str> = dir.split('/').filter(|p| !p.is_empty()).collect();
    for comp in target.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            c => parts.push(c),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_tar_strips_one_component_then_the_root() {
        for (raw, want) in [
            ("package/package.json", Some("package.json")),
            ("zzz/lib/x.js", Some("lib/x.js")),
            ("/package.json", Some("package.json")),
            ("package//x.js", Some("x.js")),
            ("package/./x.js", Some("x.js")),
            ("./package/x.js", Some("package/x.js")),
            ("package/C:/x.js", Some("x.js")),
            ("package/\\\\srv\\share\\x.js", Some("x.js")),
            ("package/a\\b.js", Some("a\\b.js")),
            ("package/../x.js", None),
            ("package/a\\..\\x.js", None),
            ("package.json", None),
            ("package/", None),
        ] {
            assert_eq!(node_tar_path(raw).as_deref(), want, "{raw}");
        }
    }

    #[test]
    fn symlink_targets_resolve_inside_the_root() {
        assert_eq!(
            resolve_symlink("p", "compat3.py").as_deref(),
            Some("p/compat3.py")
        );
        assert_eq!(resolve_symlink("p/q", "../x.py").as_deref(), Some("p/x.py"));
        assert_eq!(resolve_symlink("", "../LICENSE"), None);
        assert_eq!(resolve_symlink("p", "/etc/passwd"), None);
        assert_eq!(resolve_symlink("p", "C:x"), None);
    }
}
