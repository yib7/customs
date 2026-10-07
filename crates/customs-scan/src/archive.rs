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
    /// The single top-level directory that was stripped (`package`, `foo-1.0`), if any.
    pub stripped_prefix: Option<String>,
    pub errors: Vec<String>,
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

fn wants_full(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    let ext = extension(path).to_ascii_lowercase();
    ext.is_empty()
        || TEXT_EXTS.contains(&ext.as_str())
        || matches!(name, "PKG-INFO" | "METADATA" | "WHEEL" | "RECORD")
        || name.to_ascii_lowercase().starts_with("readme")
        || is_nested_archive(path)
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
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("/"))
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
        let result = read_into(&data, &inner_prefix, depth + 1, opts, budget, out);
        out.entries[i].data = data;
        match result {
            Ok(()) => {}
            Err(e @ ScanError::Rejected(_)) => return Err(e),
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
                if n_read == 0 && depth == 0 {
                    return Err(ScanError::Rejected(format!("corrupt archive: {e}")));
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
        let full = wants_full(&path);
        let (data, got_full) = match read_capped(&mut entry, full, opts.max_entry_bytes) {
            Ok(v) => v,
            Err(e) => {
                if let Some(r) = rejected(&tripped) {
                    return Err(r);
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
        let mut f = match zip.by_index(i) {
            Ok(f) => f,
            Err(e) => {
                out.errors.push(format!("zip entry {i} unreadable: {e}"));
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
        let full = wants_full(&path);
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

/// Strip a single top-level directory shared by every top-level entry (`foo-1.0/` in sdists,
/// `package/` in npm tarballs). Wheels have at least the package and `.dist-info` at the
/// root, so they are left alone.
fn strip_prefix(c: &mut Contents) {
    let top: Vec<&Entry> = c.entries.iter().filter(|e| e.depth == 0).collect();
    let Some(first) = top.first() else { return };
    let Some((root, _)) = first.path.split_once('/') else {
        return;
    };
    let root = root.to_string();
    let all_under = top.iter().all(|e| {
        e.path.len() > root.len() + 1
            && e.path.starts_with(&root)
            && e.path.as_bytes()[root.len()] == b'/'
    });
    if !all_under {
        return;
    }
    let cut = root.len() + 1;
    for e in c.entries.iter_mut() {
        e.path = e.path[cut..].to_string();
    }
    c.stripped_prefix = Some(root);
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
