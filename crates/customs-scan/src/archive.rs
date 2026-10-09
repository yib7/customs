//! Hardened in-memory archive reading (DESIGN.md section 3).
//!
//! Nothing is ever written to disk. Entries with absolute or `..` paths and link entries
//! are skipped and counted; caps on entry count, per-entry size, total decompressed bytes,
//! compression ratio and nesting depth bound the work an archive can force on the scanner.

use crate::{ScanError, ScanOptions};
use std::cell::Cell;
use std::io::{self, Cursor, Read};
use std::rc::Rc;

/// Ratios are only enforced past this many decompressed bytes, so tiny, highly compressible
/// files (a 10 KB run of spaces) do not trip the zip bomb guard.
const RATIO_GRACE_BYTES: u64 = 1024 * 1024;
/// Bytes kept from entries whose content is not needed, enough for magic-number checks.
const PREFIX_BYTES: usize = 8;

#[derive(Debug, Clone)]
pub struct Entry {
    /// Normalized relative path with `/` separators. Entries from nested archives are
    /// prefixed with `<outer path>!/`.
    pub path: String,
    /// Uncompressed size (bytes actually present, or the declared size when skipped).
    pub size: u64,
    /// Full content when `full`, otherwise a short prefix.
    pub data: Vec<u8>,
    pub full: bool,
    /// Depth of the archive the entry came from (0 for the scanned archive itself).
    pub depth: u32,
}

#[derive(Debug, Default)]
pub struct Contents {
    pub entries: Vec<Entry>,
    pub n_links: u64,
    pub n_unsafe_paths: u64,
    /// Top-level directories that were stripped (`package`, `foo-1.0`), joined by `/`.
    pub stripped_prefix: Option<String>,
    pub errors: Vec<String>,
    /// Code entries of the scanned archive itself whose content could not be read
    /// (encrypted, an unsupported compression method, a read error). An installer that
    /// can read them would run code the scanner never saw.
    pub unread: Vec<String>,
}

/// Record an entry of the scanned archive that could not be read, when it is code.
/// Nested archives are left out: installers do not unpack them, and test fixtures in
/// legitimate packages include deliberately broken and encrypted ones.
fn note_unread(out: &mut Contents, depth: u32, path: &str) {
    if depth == 0 && !is_nested_archive(path) && is_code_like(path, b"") {
        out.unread.push(path.to_string());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Gzip,
    Bzip2,
    Zip,
    Tar,
}

pub fn sniff_format(bytes: &[u8]) -> Option<Format> {
    if bytes.starts_with(&[0x1f, 0x8b]) {
        Some(Format::Gzip)
    } else if bytes.starts_with(b"BZh") {
        Some(Format::Bzip2)
    } else if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
        Some(Format::Zip)
    } else if bytes.len() > 262 && &bytes[257..262] == b"ustar" {
        Some(Format::Tar)
    } else {
        None
    }
}

/// Extensions whose content is read in full; everything else keeps a short prefix.
const TEXT_EXTS: &[&str] = &[
    "py", "pyw", "pth", "js", "mjs", "cjs", "ts", "jsx", "tsx", "sh", "bash", "bat", "cmd", "ps1",
    "json", "toml", "cfg", "txt", "md", "rst", "in", "ini", "yml", "yaml", "gyp", "pyi",
];
const NESTED_EXTS: &[&str] = &[
    ".zip", ".whl", ".tar.gz", ".tgz", ".tar.bz2", ".tar", ".egg",
];

pub fn extension(path: &str) -> &str {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rfind('.') {
        Some(0) | None => "",
        Some(i) => &name[i + 1..],
    }
}

pub(crate) fn wants_full(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let ext = extension(path).to_ascii_lowercase();
    ext.is_empty()
        || TEXT_EXTS.contains(&ext.as_str())
        || matches!(name, "PKG-INFO" | "METADATA" | "WHEEL" | "RECORD")
        || name.to_ascii_lowercase().starts_with("readme")
        || is_nested_archive(path)
}

/// Files an installer or the package can run or that steer installation: source and script
/// extensions, `binding.gyp`, manifests, and extensionless files starting with `#!`.
/// `prefix` is the start of the content (the reader keeps a few bytes of skipped entries).
pub(crate) fn is_code_like(path: &str, prefix: &[u8]) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let ext = extension(path).to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "py" | "pyw"
            | "pth"
            | "pyi"
            | "js"
            | "mjs"
            | "cjs"
            | "ts"
            | "jsx"
            | "tsx"
            | "sh"
            | "bash"
            | "bat"
            | "cmd"
            | "ps1"
            | "gyp"
    ) || matches!(
        name,
        "package.json" | "setup.cfg" | "pyproject.toml" | "PKG-INFO" | "METADATA"
    ) || (ext.is_empty() && prefix.starts_with(b"#!"))
}

pub fn is_nested_archive(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    NESTED_EXTS.iter().any(|e| lower.ends_with(e))
}

/// Normalize an archive path. Returns `None` for absolute paths, drive letters and `..`.
pub fn normalize_path(raw: &str) -> Option<String> {
    if raw.starts_with('/') || raw.starts_with('\\') {
        return None;
    }
    let b = raw.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        return None;
    }
    let mut parts = Vec::new();
    for comp in raw.split(['/', '\\']) {
        match comp {
            "" | "." => continue,
            ".." => return None,
            c => parts.push(c),
        }
    }
    collapse_doubled(&mut parts);
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
    }
}

/// Collapse a path whose trailing components repeat (`pkg/mod.py/pkg/mod.py` becomes
/// `pkg/mod.py`). Some malware sample collections re-extract each file of a wheel into a
/// directory named after it; normalizing here keeps training samples shaped like the
/// archives seen in serving. Single-component repeats only collapse for file-like names,
/// so a real `docs/docs` directory is left alone.
fn collapse_doubled(parts: &mut Vec<&str>) {
    let n = parts.len();
    for k in 1..=n / 2 {
        if parts[n - 2 * k..n - k] == parts[n - k..] && (k >= 2 || parts[n - 1].contains('.')) {
            parts.truncate(n - k);
            return;
        }
    }
}

/// Shared budget across an archive and everything nested in it.
struct Budget {
    entries: usize,
    total: u64,
}

/// Counts decompressed bytes and fails once the total or the expansion ratio is exceeded.
struct Guard<R> {
    inner: R,
    read: u64,
    already_used: u64,
    max_total: u64,
    compressed_len: u64,
    max_ratio: f64,
    tripped: Rc<Cell<Option<&'static str>>>,
}

impl<R: Read> Read for Guard<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read += n as u64;
        let reason = if self.already_used + self.read > self.max_total {
            Some("total uncompressed size exceeds cap")
        } else if self.read > RATIO_GRACE_BYTES
            && self.read as f64 / self.compressed_len.max(1) as f64 > self.max_ratio
        {
            Some("compression ratio exceeds cap (possible archive bomb)")
        } else {
            None
        };
        if let Some(r) = reason {
            self.tripped.set(Some(r));
            return Err(io::Error::other(r));
        }
        Ok(n)
    }
}

pub fn read_archive(bytes: &[u8], opts: &ScanOptions) -> Result<Contents, ScanError> {
    let mut contents = Contents::default();
    let mut budget = Budget {
        entries: 0,
        total: 0,
    };
    read_into(bytes, "", 0, opts, &mut budget, &mut contents)?;
    strip_prefix(&mut contents);
    Ok(contents)
}

fn read_into(
    bytes: &[u8],
    prefix: &str,
    depth: u32,
    opts: &ScanOptions,
    budget: &mut Budget,
    out: &mut Contents,
) -> Result<(), ScanError> {
    let fmt = sniff_format(bytes).ok_or_else(|| {
        ScanError::UnsupportedFormat(
            "unrecognized archive content (not gzip, bzip2, zip or tar)".into(),
        )
    })?;
    let first_new = out.entries.len();
    match fmt {
        Format::Zip => read_zip(bytes, prefix, depth, opts, budget, out)?,
        Format::Gzip => {
            let dec = flate2::read::MultiGzDecoder::new(Cursor::new(bytes));
            read_tar(dec, bytes.len() as u64, prefix, depth, opts, budget, out)?
        }
        Format::Bzip2 => {
            let dec = bzip2::read::MultiBzDecoder::new(Cursor::new(bytes));
            read_tar(dec, bytes.len() as u64, prefix, depth, opts, budget, out)?
        }
        Format::Tar => read_tar(
            Cursor::new(bytes),
            bytes.len() as u64,
            prefix,
            depth,
            opts,
            budget,
            out,
        )?,
    }
    // Expand nested archives after the outer pass so their entries follow the outer ones.
    let nested: Vec<usize> = (first_new..out.entries.len())
        .filter(|&i| out.entries[i].full && is_nested_archive(&out.entries[i].path))
        .collect();
    for i in nested {
        if depth + 1 > opts.max_nesting_depth {
            out.errors.push(format!(
                "nested archive not expanded (depth cap {}): {}",
                opts.max_nesting_depth, out.entries[i].path
            ));
            continue;
        }
        let data = std::mem::take(&mut out.entries[i].data);
        let inner_prefix = format!("{}!/", out.entries[i].path);
        let (n_entries, n_budget) = (out.entries.len(), budget.entries);
        let result = read_into(&data, &inner_prefix, depth + 1, opts, budget, out);
        out.entries[i].data = data;
        match result {
            Ok(()) => {}
            // A nested archive over a limit is left unexpanded, like one past the depth
            // cap: installers do not unpack it, so it must not make the whole package
            // unscannable (cmake's sdist bundles its 20,000-file source tarball). Its
            // decompressed bytes stay spent, so many of them cannot multiply the work.
            Err(ScanError::Rejected(r)) => {
                out.entries.truncate(n_entries);
                budget.entries = n_budget;
                out.errors.push(format!(
                    "nested archive not expanded ({r}): {}",
                    out.entries[i].path
                ));
            }
            Err(e) => out.errors.push(format!(
                "nested archive {} unreadable: {e}",
                out.entries[i].path
            )),
        }
    }
    Ok(())
}

fn admit_entry(budget: &mut Budget, opts: &ScanOptions) -> Result<(), ScanError> {
    budget.entries += 1;
    if budget.entries > opts.max_entries {
        return Err(ScanError::Rejected(format!(
            "archive has more than {} entries",
            opts.max_entries
        )));
    }
    Ok(())
}

/// Read up to `cap + 1` bytes so oversize content is detected without buffering it all.
fn read_capped<R: Read>(r: &mut R, want_full: bool, cap: u64) -> io::Result<(Vec<u8>, bool)> {
    if !want_full {
        let mut buf = vec![0u8; PREFIX_BYTES];
        let mut n = 0;
        while n < PREFIX_BYTES {
            let k = r.read(&mut buf[n..])?;
            if k == 0 {
                break;
            }
            n += k;
        }
        buf.truncate(n);
        return Ok((buf, false));
    }
    let mut buf = Vec::new();
    r.take(cap + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > cap {
        buf.truncate(PREFIX_BYTES);
        return Ok((buf, false));
    }
    Ok((buf, true))
}

fn read_tar<R: Read>(
    reader: R,
    compressed_len: u64,
    prefix: &str,
    depth: u32,
    opts: &ScanOptions,
    budget: &mut Budget,
    out: &mut Contents,
) -> Result<(), ScanError> {
    let tripped = Rc::new(Cell::new(None));
    let guard = Guard {
        inner: reader,
        read: 0,
        already_used: budget.total,
        max_total: opts.max_total_bytes,
        compressed_len,
        max_ratio: opts.max_compression_ratio,
        tripped: tripped.clone(),
    };
    let start_total = budget.total;
    let mut archive = tar::Archive::new(guard);
    let rejected = |tripped: &Rc<Cell<Option<&'static str>>>| {
        tripped.get().map(|r| ScanError::Rejected(r.into()))
    };
    let entries = match archive.entries() {
        Ok(e) => e,
        Err(e) => return Err(rejected(&tripped).unwrap_or(ScanError::Io(e))),
    };
    for (n_read, entry) in entries.enumerate() {
        let mut entry = match entry {
            Ok(e) => e,
            Err(e) => {
                if let Some(r) = rejected(&tripped) {
                    return Err(r);
                }
                // At depth 0 the rest of the archive is unknown, and installers disagree
                // about it (node-tar skips a bad header and keeps reading), so refuse.
                if depth == 0 {
                    let at = if n_read == 0 {
                        ""
                    } else {
                        " after the first entry"
                    };
                    return Err(ScanError::Rejected(format!("corrupt archive{at}: {e}")));
                }
                out.errors
                    .push(format!("archive truncated or corrupt: {e}"));
                break;
            }
        };
        admit_entry(budget, opts)?;
        let raw = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            continue;
        }
        if kind.is_symlink() || kind.is_hard_link() {
            out.n_links += 1;
            out.errors.push(format!("link entry skipped: {raw}"));
            continue;
        }
        if !(kind.is_file() || kind == tar::EntryType::Continuous) {
            if !(kind.is_pax_global_extensions()
                || kind.is_pax_local_extensions()
                || kind.is_gnu_longname()
                || kind.is_gnu_longlink())
            {
                out.errors.push(format!("special entry skipped: {raw}"));
            }
            continue;
        }
        let Some(path) = normalize_path(&raw) else {
            out.n_unsafe_paths += 1;
            out.errors.push(format!("unsafe path skipped: {raw}"));
            continue;
        };
        let declared = entry.header().size().unwrap_or(0);
        let full = opts.read_all || wants_full(&path);
        let (data, got_full) = match read_capped(&mut entry, full, opts.max_entry_bytes) {
            Ok(v) => v,
            Err(e) => {
                if let Some(r) = rejected(&tripped) {
                    return Err(r);
                }
                if depth == 0 {
                    return Err(ScanError::Rejected(format!(
                        "corrupt archive: entry unreadable: {path}: {e}"
                    )));
                }
                out.errors.push(format!("entry unreadable: {path}: {e}"));
                break;
            }
        };
        if full && !got_full {
            out.errors
                .push(format!("entry over size cap, content skipped: {path}"));
        }
        let size = if got_full {
            data.len() as u64
        } else {
            declared
        };
        out.entries.push(Entry {
            path: format!("{prefix}{path}"),
            size,
            data,
            full: got_full,
            depth,
        });
    }
    // The tar reader skips unread entry data through the guard, so its count is the true
    // amount of decompressed work.
    let used = archive.into_inner().read;
    budget.total = start_total + used;
    Ok(())
}

fn read_zip(
    bytes: &[u8],
    prefix: &str,
    depth: u32,
    opts: &ScanOptions,
    budget: &mut Budget,
    out: &mut Contents,
) -> Result<(), ScanError> {
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|e| ScanError::Rejected(format!("corrupt zip archive: {e}")))?;
    if budget.entries + zip.len() > opts.max_entries {
        return Err(ScanError::Rejected(format!(
            "archive has more than {} entries",
            opts.max_entries
        )));
    }
    for i in 0..zip.len() {
        admit_entry(budget, opts)?;
        // zip decodes names as UTF-8 or else CP437, which maps every byte, so the error
        // case does not occur in practice.
        let name = zip
            .name_for_index(i)
            .and_then(Result::ok)
            .and_then(|n| normalize_path(&n));
        let mut f = match zip.by_index(i) {
            Ok(f) => f,
            Err(e) => {
                out.errors.push(format!(
                    "zip entry {} unreadable: {e}",
                    name.as_deref().unwrap_or(&i.to_string())
                ));
                if let Some(path) = name {
                    note_unread(out, depth, &path);
                }
                continue;
            }
        };
        let raw = String::from_utf8_lossy(f.name_raw()).into_owned();
        if f.is_dir() {
            continue;
        }
        if f.is_symlink() {
            out.n_links += 1;
            out.errors.push(format!("link entry skipped: {raw}"));
            continue;
        }
        let Some(path) = normalize_path(&raw) else {
            out.n_unsafe_paths += 1;
            out.errors.push(format!("unsafe path skipped: {raw}"));
            continue;
        };
        let declared = f.size();
        let compressed = f.compressed_size();
        let full = opts.read_all || wants_full(&path);
        let tripped = Rc::new(Cell::new(None));
        let mut guard = Guard {
            inner: &mut f,
            read: 0,
            already_used: budget.total,
            max_total: opts.max_total_bytes,
            compressed_len: compressed,
            max_ratio: opts.max_compression_ratio,
            tripped: tripped.clone(),
        };
        let res = read_capped(&mut guard, full, opts.max_entry_bytes);
        budget.total += guard.read;
        if let Some(r) = tripped.get() {
            return Err(ScanError::Rejected(r.into()));
        }
        let (data, got_full) = match res {
            Ok(v) => v,
            Err(e) => {
                out.errors.push(format!("entry unreadable: {path}: {e}"));
                note_unread(out, depth, &path);
                continue;
            }
        };
        if full && !got_full {
            out.errors
                .push(format!("entry over size cap, content skipped: {path}"));
        }
        let size = if got_full {
            data.len() as u64
        } else {
            declared
        };
        out.entries.push(Entry {
            path: format!("{prefix}{path}"),
            size,
            data,
            full: got_full,
            depth,
        });
    }
    Ok(())
}

/// Files whose presence marks the package root.
const ROOT_MARKERS: &[&str] = &[
    "package.json",
    "PKG-INFO",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
];
const MAX_STRIP_LEVELS: usize = 16;

/// A metadata file sitting next to the package directory (sample collections store a
/// `package_info-*.json` there). It lies outside the package root, so it is dropped.
fn is_sidecar(path: &str) -> bool {
    !path.contains('/') && path != "package.json" && path.to_ascii_lowercase().ends_with(".json")
}

/// Strip top-level directories until the package root is reached: `foo-1.0/` in sdists,
/// `package/` in npm tarballs, and the wrapper levels sample collections add
/// (`tmp/tmpXXXX/foo/foo-1.0/`). A level is descended only when it holds exactly one
/// directory and nothing else but sidecar JSON files, and stripping stops at a level that
/// holds a manifest or a `.dist-info` directory, so wheels are left alone.
fn strip_prefix(c: &mut Contents) {
    let mut stripped: Vec<String> = Vec::new();
    let mut dropped = 0usize;
    for _ in 0..MAX_STRIP_LEVELS {
        let top: Vec<&Entry> = c.entries.iter().filter(|e| e.depth == 0).collect();
        let at_root = top.iter().any(|e| {
            ROOT_MARKERS.contains(&e.path.as_str())
                || e.path
                    .split_once('/')
                    .is_some_and(|(d, _)| d.ends_with(".dist-info"))
        });
        if at_root {
            break;
        }
        let mut dirs = top
            .iter()
            .filter_map(|e| e.path.split_once('/').map(|(d, _)| d));
        let Some(root) = dirs.next().map(str::to_string) else {
            break;
        };
        let single_dir = dirs.all(|d| d == root);
        let only_sidecars = top
            .iter()
            .all(|e| e.path.contains('/') || is_sidecar(&e.path));
        if !single_dir || !only_sidecars {
            break;
        }
        let before = c.entries.len();
        c.entries.retain(|e| e.depth > 0 || !is_sidecar(&e.path));
        dropped += before - c.entries.len();
        let cut = root.len() + 1;
        for e in c.entries.iter_mut() {
            if e.path.len() > cut
                && e.path.starts_with(&root)
                && e.path.as_bytes()[root.len()] == b'/'
            {
                e.path = e.path[cut..].to_string();
            }
        }
        for u in c.unread.iter_mut() {
            if u.len() > cut && u.starts_with(&root) && u.as_bytes()[root.len()] == b'/' {
                *u = u[cut..].to_string();
            }
        }
        stripped.push(root);
    }
    reroot_nested(c, &mut stripped);
    if dropped > 0 {
        c.errors.push(format!(
            "{dropped} metadata file(s) outside the package root ignored"
        ));
    }
    if !stripped.is_empty() {
        c.stripped_prefix = Some(stripped.join("/"));
    }
}

fn has_root_marker(c: &Contents) -> bool {
    c.entries.iter().any(|e| {
        e.depth == 0
            && (ROOT_MARKERS.contains(&e.path.as_str())
                || e.path
                    .split_once('/')
                    .is_some_and(|(d, _)| d.ends_with(".dist-info")))
    })
}

/// When stripping stops above the package (the top level holds more than one directory,
/// as in `foo/foo-1.0/setup.py` next to a `sources/` checkout), use the shallowest
/// directory that holds a manifest or an unpacked wheel's `.dist-info` as the root, if
/// exactly one does. Files outside it keep their paths, so they are still scanned; they
/// just cannot be mistaken for the package's own manifest or install hooks.
fn reroot_nested(c: &mut Contents, stripped: &mut Vec<String>) {
    if has_root_marker(c) {
        return;
    }
    // (depth, directory, holds a built distribution's own metadata)
    let mut dirs: Vec<(usize, &str, bool)> = Vec::new();
    for e in c.entries.iter().filter(|e| e.depth == 0) {
        if let Some((dir, file)) = e.path.rsplit_once('/') {
            if ROOT_MARKERS.contains(&file) {
                let built = file == "PKG-INFO" || file == "package.json";
                dirs.push((dir.matches('/').count(), dir, built));
            }
        }
        // `<dir>/<name>.dist-info/...`: `<dir>` is an unpacked wheel.
        let mut start = 0;
        while let Some(i) = e.path[start..].find(".dist-info/") {
            let end = start + i;
            if let Some(slash) = e.path[..end].rfind('/') {
                let dir = &e.path[..slash];
                dirs.push((dir.matches('/').count(), dir, true));
            }
            start = end + ".dist-info/".len();
        }
    }
    let Some(min) = dirs.iter().map(|(d, _, _)| *d).min() else {
        return;
    };
    let mut cands: Vec<(&str, bool)> = dirs
        .iter()
        .filter(|(d, _, _)| *d == min)
        .map(|(_, p, b)| (*p, *b))
        .collect();
    cands.sort_unstable();
    cands.dedup();
    // A directory counts as built when any of its markers says so.
    let mut roots: Vec<&str> = cands.iter().map(|(p, _)| *p).collect();
    roots.dedup();
    if roots.len() > 1 {
        // A built distribution next to a source checkout of the same project: prefer the
        // directory with the distribution's own metadata (`PKG-INFO`, `package.json`, a
        // wheel's `.dist-info`).
        roots = cands.iter().filter(|(_, b)| *b).map(|(p, _)| *p).collect();
        roots.dedup();
    }
    if roots.len() != 1 || min + 1 > MAX_STRIP_LEVELS {
        return;
    }
    let root = roots[0].to_string();
    let prefix = format!("{root}/");
    for e in c.entries.iter_mut().filter(|e| e.depth == 0) {
        if let Some(rest) = e.path.strip_prefix(&prefix) {
            e.path = rest.to_string();
        }
    }
    stripped.push(root);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_rejects_traversal() {
        assert_eq!(normalize_path("a/./b//c"), Some("a/b/c".into()));
        assert_eq!(normalize_path("../etc/passwd"), None);
        assert_eq!(normalize_path("a/../../b"), None);
        assert_eq!(normalize_path("/etc/passwd"), None);
        assert_eq!(normalize_path("C:\\x"), None);
        assert_eq!(normalize_path("a\\..\\b"), None);
        assert_eq!(normalize_path("./"), None);
    }

    #[test]
    fn doubled_paths_collapse() {
        assert_eq!(
            normalize_path("t/pkg/mod.py/pkg/mod.py"),
            Some("t/pkg/mod.py".into())
        );
        assert_eq!(
            normalize_path("x.dist-info/WHEEL/x.dist-info/WHEEL"),
            Some("x.dist-info/WHEEL".into())
        );
        assert_eq!(normalize_path("setup.py/setup.py"), Some("setup.py".into()));
        assert_eq!(normalize_path("docs/docs"), Some("docs/docs".into()));
        assert_eq!(normalize_path("a/b/c.py"), Some("a/b/c.py".into()));
    }

    fn entry(path: &str) -> Entry {
        Entry {
            path: path.into(),
            size: 1,
            data: vec![b'x'],
            full: true,
            depth: 0,
        }
    }

    #[test]
    fn strip_wrappers_and_sidecars() {
        let mut c = Contents {
            entries: vec![
                entry("tmp/tmpx/foo/package_info-foo-1.0.json"),
                entry("tmp/tmpx/foo/foo-1.0/PKG-INFO"),
                entry("tmp/tmpx/foo/foo-1.0/foo/__init__.py"),
            ],
            ..Default::default()
        };
        strip_prefix(&mut c);
        let paths: Vec<&str> = c.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["PKG-INFO", "foo/__init__.py"]);
        assert_eq!(c.stripped_prefix.as_deref(), Some("tmp/tmpx/foo/foo-1.0"));

        // Code next to the directory stops wrapper stripping; the package is re-rooted at
        // its manifest and the stray file keeps its own path, so it is still scanned.
        let mut c = Contents {
            entries: vec![entry("evil.py"), entry("pkg-1.0/setup.py")],
            ..Default::default()
        };
        strip_prefix(&mut c);
        let paths: Vec<&str> = c.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["evil.py", "setup.py"]);
        assert_eq!(c.stripped_prefix.as_deref(), Some("pkg-1.0"));

        // A package nested next to another directory is re-rooted at its manifest.
        let mut c = Contents {
            entries: vec![
                entry("pd-1.0/pd/pd-1.0/setup.py"),
                entry("pd-1.0/pd/pd-1.0/pd/game.py"),
                entry("pd-1.0/sources/pd/.git/config"),
            ],
            ..Default::default()
        };
        strip_prefix(&mut c);
        let paths: Vec<&str> = c.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["setup.py", "pd/game.py", "sources/pd/.git/config"]
        );
        assert_eq!(c.stripped_prefix.as_deref(), Some("pd-1.0/pd/pd-1.0"));

        // A distribution next to a source checkout: the one with PKG-INFO wins.
        let mut c = Contents {
            entries: vec![
                entry("x/dist/pd-1.0/PKG-INFO"),
                entry("x/dist/pd-1.0/setup.py"),
                entry("x/src/pd/setup.py"),
            ],
            ..Default::default()
        };
        strip_prefix(&mut c);
        assert_eq!(c.stripped_prefix.as_deref(), Some("x/dist/pd-1.0"));

        // An unpacked wheel next to a source checkout: the wheel wins, even though only
        // the checkout has a manifest file.
        let mut c = Contents {
            entries: vec![
                entry("dt-1.0/dt/dt/__init__.py"),
                entry("dt-1.0/dt/dt-1.0.dist-info/METADATA"),
                entry("dt-1.0/sources/dt/pyproject.toml"),
                entry("dt-1.0/sources/dt/dt/__init__.py"),
            ],
            ..Default::default()
        };
        strip_prefix(&mut c);
        let paths: Vec<&str> = c.entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "dt/__init__.py",
                "dt-1.0.dist-info/METADATA",
                "sources/dt/pyproject.toml",
                "sources/dt/dt/__init__.py"
            ]
        );
        assert_eq!(c.stripped_prefix.as_deref(), Some("dt-1.0/dt"));

        // Two candidate roots at the same depth: ambiguous, left alone.
        let mut c = Contents {
            entries: vec![entry("a/setup.py"), entry("b/setup.py")],
            ..Default::default()
        };
        strip_prefix(&mut c);
        assert!(c.stripped_prefix.is_none());

        // Wheels keep their layout.
        let mut c = Contents {
            entries: vec![
                entry("foo/__init__.py"),
                entry("foo-1.0.dist-info/METADATA"),
            ],
            ..Default::default()
        };
        strip_prefix(&mut c);
        assert!(c.stripped_prefix.is_none());
    }

    #[test]
    fn sniff() {
        assert_eq!(sniff_format(&[0x1f, 0x8b, 8]), Some(Format::Gzip));
        assert_eq!(sniff_format(b"PK\x03\x04rest"), Some(Format::Zip));
        assert_eq!(sniff_format(b"BZh91AY"), Some(Format::Bzip2));
        assert_eq!(sniff_format(b"hello"), None);
    }

    #[test]
    fn extension_of() {
        assert_eq!(extension("a/b.tar.gz"), "gz");
        assert_eq!(extension("a/.bashrc"), "");
        assert_eq!(extension("a/Makefile"), "");
        assert_eq!(extension("x.py"), "py");
    }
}
