//! Release deltas: the part of a release that is new relative to the previous release.
//!
//! Mirrors `build_delta` in `python/customs_ml/diff.py`, which built the training data:
//!
//! * files new in this release are kept whole;
//! * files whose bytes changed keep only their new lines (the lines left after removing,
//!   as a multiset, every line of the old file), or the whole file when either side is
//!   binary (a NUL byte in the first 8 KiB);
//! * root manifests (and a wheel's `*.dist-info/METADATA`) are always kept whole so the
//!   install surface can still be found;
//! * unchanged and removed files are dropped.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::archive::{Contents, Entry};

const MANIFESTS: &[&str] = &[
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "PKG-INFO",
    "package.json",
];
const BINARY_SNIFF: usize = 8192;

/// Root manifests, plus a wheel's `*.dist-info/METADATA` (a wheel has no root manifest).
fn is_manifest(path: &str) -> bool {
    MANIFESTS.contains(&path)
        || path
            .split_once('/')
            .is_some_and(|(d, f)| d.ends_with(".dist-info") && f == "METADATA" && d.len() > 10)
}

/// Change-size statistics of a delta (the `p_` model features are derived from these).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeltaStats {
    pub n_added: u64,
    pub n_modified: u64,
    pub n_unchanged: u64,
    pub n_removed: u64,
    pub added_bytes: u64,
    pub cur_files: u64,
}

fn is_binary(e: &Entry) -> bool {
    // Content that was not read in full is never compared line by line.
    !e.full || e.data[..e.data.len().min(BINARY_SNIFF)].contains(&0)
}

/// Lines of `new` not accounted for by `old`, joined by `\n` (Python's
/// `bytes.split(b"\n")` semantics, so a trailing newline yields a trailing empty line).
pub fn new_lines(old: &[u8], new: &[u8]) -> Vec<u8> {
    let mut have: HashMap<&[u8], usize> = HashMap::new();
    for line in old.split(|&b| b == b'\n') {
        *have.entry(line).or_default() += 1;
    }
    let mut out: Vec<&[u8]> = Vec::new();
    for line in new.split(|&b| b == b'\n') {
        match have.get_mut(line) {
            Some(n) if *n > 0 => *n -= 1,
            _ => out.push(line),
        }
    }
    out.join(&b'\n')
}

/// Python's `bytes.strip()` whitespace (ASCII space, \t, \n, \r, \x0b, \x0c).
fn is_blank(b: &[u8]) -> bool {
    b.iter()
        .all(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c))
}

fn same(a: &Entry, b: &Entry) -> bool {
    a.size == b.size && a.full == b.full && a.data == b.data
}

/// Build the delta of `cur` against `prev`. Both must come from `read_archive`.
pub fn delta(prev: &Contents, cur: &Contents) -> (Contents, DeltaStats) {
    let prev_index: HashMap<&str, &Entry> = prev
        .entries
        .iter()
        .filter(|e| e.depth == 0)
        .map(|e| (e.path.as_str(), e))
        .collect();
    let mut top: Vec<&Entry> = cur.entries.iter().filter(|e| e.depth == 0).collect();
    top.sort_by(|a, b| a.path.cmp(&b.path));
    top.dedup_by(|a, b| a.path == b.path);
    let mut stats = DeltaStats {
        cur_files: top.len() as u64,
        ..DeltaStats::default()
    };
    let mut kept: Vec<Entry> = Vec::new();
    for e in &top {
        let manifest = is_manifest(&e.path);
        match prev_index.get(e.path.as_str()) {
            None => {
                stats.n_added += 1;
                stats.added_bytes += e.size;
                kept.push((*e).clone());
            }
            Some(old) if same(old, e) => {
                stats.n_unchanged += 1;
                if manifest {
                    kept.push((*e).clone());
                }
            }
            Some(old) => {
                stats.n_modified += 1;
                if is_binary(e) || is_binary(old) {
                    stats.added_bytes += e.size;
                    kept.push((*e).clone());
                    continue;
                }
                let part = new_lines(&old.data, &e.data);
                stats.added_bytes += part.len() as u64;
                if manifest {
                    kept.push((*e).clone());
                } else if !is_blank(&part) {
                    kept.push(Entry {
                        path: e.path.clone(),
                        size: part.len() as u64,
                        data: part,
                        full: true,
                        depth: 0,
                    });
                }
            }
        }
    }
    let cur_paths: std::collections::HashSet<&str> = top.iter().map(|e| e.path.as_str()).collect();
    stats.n_removed = prev_index
        .keys()
        .filter(|p| !cur_paths.contains(*p))
        .count() as u64;
    // Entries unpacked from a nested archive follow their outer file.
    let kept_paths: std::collections::HashSet<String> =
        kept.iter().map(|e| e.path.clone()).collect();
    let nested: Vec<Entry> = cur
        .entries
        .iter()
        .filter(|e| {
            e.depth > 0
                && e.path
                    .split_once("!/")
                    .is_some_and(|(outer, _)| kept_paths.contains(outer))
        })
        .cloned()
        .collect();
    kept.extend(nested);
    let out = Contents {
        entries: kept,
        n_links: 0,
        n_unsafe_paths: 0,
        stripped_prefix: cur.stripped_prefix.clone(),
        errors: Vec::new(),
        unread: cur.unread.clone(),
    };
    (out, stats)
}

/// One file in a [`FileDiff`]. Line counts are for text files whose content was read in
/// full on both sides; a binary or unread file has none.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FileChange {
    pub path: String,
    /// Size in the newer release (the older one for a removed file).
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lines_added: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lines_removed: Option<u64>,
}

/// Which files of a release are new, changed or gone relative to an earlier release.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FileDiff {
    pub added: Vec<FileChange>,
    pub modified: Vec<FileChange>,
    pub removed: Vec<FileChange>,
    pub unchanged: u64,
}

fn count_lines(b: &[u8]) -> u64 {
    if is_blank(b) {
        return 0;
    }
    b.split(|&c| c == b'\n').filter(|l| !is_blank(l)).count() as u64
}

fn text_lines(e: &Entry) -> Option<u64> {
    (!is_binary(e)).then(|| count_lines(&e.data))
}

/// File-level comparison of two releases' top-level entries, sorted by path.
pub fn file_diff(prev: &Contents, cur: &Contents) -> FileDiff {
    let index = |c: &Contents| -> std::collections::BTreeMap<String, Entry> {
        c.entries
            .iter()
            .filter(|e| e.depth == 0)
            .map(|e| (e.path.clone(), e.clone()))
            .collect()
    };
    let (old, new) = (index(prev), index(cur));
    let mut out = FileDiff::default();
    for (path, e) in &new {
        match old.get(path) {
            None => out.added.push(FileChange {
                path: path.clone(),
                size: e.size,
                lines_added: text_lines(e),
                lines_removed: None,
            }),
            Some(o) if same(o, e) => out.unchanged += 1,
            Some(o) => {
                let text = !is_binary(e) && !is_binary(o);
                out.modified.push(FileChange {
                    path: path.clone(),
                    size: e.size,
                    lines_added: text.then(|| count_lines(&new_lines(&o.data, &e.data))),
                    lines_removed: text.then(|| count_lines(&new_lines(&e.data, &o.data))),
                });
            }
        }
    }
    for (path, o) in &old {
        if !new.contains_key(path) {
            out.removed.push(FileChange {
                path: path.clone(),
                size: o.size,
                lines_added: None,
                lines_removed: text_lines(o),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_diff_lists_changes() {
        let prev = contents(&[
            ("index.js", b"a\nb\nc\n"),
            ("README.md", b"same"),
            ("old.js", b"x\ny\n"),
        ]);
        let cur = contents(&[
            ("index.js", b"a\nc\nd\ne\n"),
            ("README.md", b"same"),
            ("setup.js", b"require('child_process')\n\nrun()\n"),
            ("bin/tool", b"\x7fELF\x00\x01"),
        ]);
        let d = file_diff(&prev, &cur);
        assert_eq!(d.unchanged, 1);
        let added: Vec<(&str, Option<u64>)> = d
            .added
            .iter()
            .map(|f| (f.path.as_str(), f.lines_added))
            .collect();
        assert_eq!(added, vec![("bin/tool", None), ("setup.js", Some(2))]);
        assert_eq!(d.modified[0].path, "index.js");
        assert_eq!(
            (d.modified[0].lines_added, d.modified[0].lines_removed),
            (Some(2), Some(1))
        );
        assert_eq!(d.removed[0].path, "old.js");
        assert_eq!(d.removed[0].lines_removed, Some(2));
    }

    fn entry(path: &str, data: &[u8]) -> Entry {
        Entry {
            path: path.into(),
            size: data.len() as u64,
            data: data.to_vec(),
            full: true,
            depth: 0,
        }
    }

    fn contents(files: &[(&str, &[u8])]) -> Contents {
        Contents {
            entries: files.iter().map(|(p, d)| entry(p, d)).collect(),
            ..Contents::default()
        }
    }

    #[test]
    fn new_lines_is_a_multiset_difference() {
        assert_eq!(new_lines(b"a\nb\na\n", b"a\nb\nc\na\na\n"), b"c\na");
        assert_eq!(new_lines(b"x", b"x"), b"");
        // A trailing newline added to a file is one new empty line.
        assert_eq!(new_lines(b"x", b"x\n"), b"");
        assert_eq!(new_lines(b"", b"y\n"), b"y");
    }

    #[test]
    fn keeps_added_changed_and_manifests_only() {
        let prev = contents(&[
            ("package.json", b"{\"version\":\"1.0.0\"}"),
            ("index.js", b"module.exports = 1;\n"),
            ("lib/a.js", b"same\n"),
            ("old.js", b"gone\n"),
        ]);
        let cur = contents(&[
            ("package.json", b"{\"version\":\"1.0.1\"}"),
            (
                "index.js",
                b"module.exports = 1;\nrequire('child_process');\n",
            ),
            ("lib/a.js", b"same\n"),
            ("bundle.js", b"payload()\n"),
        ]);
        let (d, s) = delta(&prev, &cur);
        let paths: Vec<&str> = d.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["bundle.js", "index.js", "package.json"]);
        let idx = d.entries.iter().find(|e| e.path == "index.js").unwrap();
        assert_eq!(idx.data, b"require('child_process');");
        assert_eq!(
            s,
            DeltaStats {
                n_added: 1,
                n_modified: 2,
                n_unchanged: 1,
                n_removed: 1,
                added_bytes: 10 + 25 + 19,
                cur_files: 4,
            }
        );
    }

    #[test]
    fn whitespace_only_changes_are_dropped_and_binaries_kept_whole() {
        let prev = contents(&[("a.py", b"x = 1\n"), ("b.bin", b"\0\x01")]);
        let cur = contents(&[("a.py", b"x = 1\n\n  \n"), ("b.bin", b"\0\x02")]);
        let (d, s) = delta(&prev, &cur);
        let paths: Vec<&str> = d.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, ["b.bin"]);
        assert_eq!(s.n_modified, 2);
        assert_eq!(s.added_bytes, 3 + 2);
    }
}
