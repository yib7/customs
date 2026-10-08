mod common;

use common::*;
use customs_scan::{scan_archive, Ecosystem, ScanError, ScanOptions};

fn scan(
    bytes: &[u8],
    name: &str,
    opts: &ScanOptions,
) -> Result<customs_scan::ScanReport, ScanError> {
    scan_archive(bytes, name, None, opts)
}

#[test]
fn traversal_and_absolute_entries_are_skipped() {
    let bytes = tar_gz(&[
        TarItem::File("pkg-1.0/setup.py", b"print('hi')\n"),
        TarItem::RawPath("pkg-1.0/../../escape.py", b"import os\nos.system('id')\n"),
        TarItem::RawPath("/etc/cron.d/evil", b"* * * * * root id\n"),
    ]);
    let r = scan(&bytes, "pkg-1.0.tar.gz", &ScanOptions::default()).unwrap();
    assert_eq!(r.features["n_unsafe_paths"], 2.0);
    assert_eq!(r.features["n_files"], 1.0);
    assert_eq!(r.features["all_proc_exec"], 0.0);
    assert!(r.errors.iter().any(|e| e.contains("unsafe path")));
}

#[test]
fn zip_traversal_entry_is_skipped() {
    let bytes = zip_files(&[
        ("pkg/__init__.py", b"x = 1\n"),
        ("../evil.py", b"eval(x)\n"),
    ]);
    let r = scan(&bytes, "pkg-1.0-py3-none-any.whl", &ScanOptions::default()).unwrap();
    assert_eq!(r.features["n_unsafe_paths"], 1.0);
    assert_eq!(r.features["all_dyn_code"], 0.0);
}

#[test]
fn symlinks_and_hardlinks_are_not_followed() {
    let bytes = tar_gz(&[
        TarItem::File("pkg-1.0/setup.py", b"x = 1\n"),
        TarItem::Symlink("pkg-1.0/creds", "/home/user/.ssh/id_rsa"),
        TarItem::HardLink("pkg-1.0/passwd", "/etc/passwd"),
    ]);
    let r = scan(&bytes, "pkg-1.0.tar.gz", &ScanOptions::default()).unwrap();
    assert_eq!(r.features["n_links"], 2.0);
    assert_eq!(r.features["n_files"], 1.0);

    let z = zip_with_symlink("/etc/passwd");
    let r = scan(&z, "pkg-1.0-py3-none-any.whl", &ScanOptions::default()).unwrap();
    assert_eq!(r.features["n_links"], 1.0);
}

#[test]
fn oversized_entry_is_counted_but_not_analyzed() {
    let big = format!("import os\n{}", "os.system('x')\n".repeat(200));
    let bytes = tar_gz_files(&[
        ("pkg-1.0/setup.py", "x = 1\n"),
        ("pkg-1.0/pkg/big.py", &big),
    ]);
    let opts = ScanOptions {
        max_entry_bytes: 1000,
        ..Default::default()
    };
    let r = scan(&bytes, "pkg-1.0.tar.gz", &opts).unwrap();
    assert_eq!(r.features["n_files"], 2.0);
    assert_eq!(r.features["max_file_bytes"], big.len() as f64);
    assert_eq!(r.features["all_proc_exec"], 0.0);
    assert!(r.errors.iter().any(|e| e.contains("over size cap")));
}

#[test]
fn oversized_code_is_reported_as_unread() {
    let pad = "#".repeat(2000);
    let bytes = tar_gz_files(&[
        (
            "pkg-1.0/setup.py",
            &format!("{pad}\nimport os\nos.system('x')\n"),
        ),
        ("pkg-1.0/bin/tool", &format!("#!/bin/sh\n{pad}")),
        ("pkg-1.0/data/table.json", &format!("[\"{pad}\"]")),
        ("pkg-1.0/docs/notes.txt", &pad),
        ("pkg-1.0/pkg/__init__.py", "x = 1\n"),
    ]);
    let opts = ScanOptions {
        max_entry_bytes: 1000,
        ..Default::default()
    };
    let r = scan(&bytes, "pkg-1.0.tar.gz", &opts).unwrap();
    // Paths are relative to the package root, like evidence paths.
    assert_eq!(r.unread_code, vec!["setup.py", "bin/tool"]);
    assert_eq!(r.features["inst_proc_exec"], 0.0);

    let r = scan(&bytes, "pkg-1.0.tar.gz", &ScanOptions::default()).unwrap();
    assert!(r.unread_code.is_empty());
    assert!(r.features["inst_proc_exec"] > 0.0);
}

#[test]
fn tar_gz_bomb_is_rejected() {
    let zeros = vec![b' '; 40 * 1024 * 1024];
    let bytes = tar_gz(&[TarItem::File("pkg-1.0/data.txt", &zeros)]);
    assert!(bytes.len() < 200 * 1024, "fixture should compress well");
    match scan(&bytes, "pkg-1.0.tar.gz", &ScanOptions::default()) {
        Err(ScanError::Rejected(msg)) => assert!(msg.contains("ratio"), "{msg}"),
        other => panic!("expected rejection, got {other:?}"),
    }
}

#[test]
fn zip_bomb_is_rejected() {
    let zeros = vec![0u8; 40 * 1024 * 1024];
    let bytes = zip_files(&[("pkg/__init__.py", b"x = 1\n"), ("pkg/data.json", &zeros)]);
    match scan(&bytes, "pkg-1.0-py3-none-any.whl", &ScanOptions::default()) {
        Err(ScanError::Rejected(msg)) => assert!(msg.contains("ratio"), "{msg}"),
        other => panic!("expected rejection, got {other:?}"),
    }
}

#[test]
fn total_size_cap_is_enforced() {
    let filler = "a = 1\n".repeat(50_000);
    let bytes = tar_gz_files(&[("pkg-1.0/a.py", &filler), ("pkg-1.0/b.py", &filler)]);
    let opts = ScanOptions {
        max_total_bytes: 400_000,
        ..Default::default()
    };
    assert!(matches!(
        scan(&bytes, "pkg-1.0.tar.gz", &opts),
        Err(ScanError::Rejected(_))
    ));
}

#[test]
fn too_many_entries_is_rejected() {
    let names: Vec<String> = (0..30).map(|i| format!("pkg-1.0/m{i}.py")).collect();
    let files: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "x = 1\n")).collect();
    let opts = ScanOptions {
        max_entries: 10,
        ..Default::default()
    };
    assert!(matches!(
        scan(&tar_gz_files(&files), "pkg-1.0.tar.gz", &opts),
        Err(ScanError::Rejected(_))
    ));
    let zfiles: Vec<(&str, &[u8])> = names
        .iter()
        .map(|n| (n.as_str(), &b"x = 1\n"[..]))
        .collect();
    assert!(matches!(
        scan(&zip_files(&zfiles), "pkg-1.0.zip", &opts),
        Err(ScanError::Rejected(_))
    ));
}

#[test]
fn nested_archive_over_a_limit_is_left_unexpanded() {
    // Installers do not unpack a bundled archive, so one too big to expand must not make
    // the package itself unscannable (cmake's sdist bundles its own source tarball).
    let names: Vec<String> = (0..20).map(|i| format!("src/f{i}.py")).collect();
    let inner_files: Vec<(&str, &[u8])> = names
        .iter()
        .map(|n| (n.as_str(), &b"eval(x)\n"[..]))
        .collect();
    let inner = zip_files(&inner_files);
    let bytes = tar_gz(&[
        TarItem::File("pkg-1.0/setup.py", b"import os\nos.system('id')\n"),
        TarItem::File("pkg-1.0/vendor/src.zip", &inner),
    ]);
    let opts = ScanOptions {
        max_entries: 10,
        ..Default::default()
    };
    let r = scan(&bytes, "pkg-1.0.tar.gz", &opts).unwrap();
    assert_eq!(r.features["n_files"], 2.0);
    assert_eq!(r.features["inst_proc_exec"], 1.0);
    assert_eq!(r.features["all_dyn_code"], 0.0);
    assert!(
        r.errors
            .iter()
            .any(|e| e.starts_with("nested archive not expanded (archive has more than 10")),
        "{:?}",
        r.errors
    );
    // The outer archive itself over the limit is still rejected.
    let outer: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "x = 1\n")).collect();
    assert!(matches!(
        scan(&tar_gz_files(&outer), "pkg-1.0.tar.gz", &opts),
        Err(ScanError::Rejected(_))
    ));
}

#[test]
fn nested_archives_are_expanded_to_the_depth_cap() {
    let inner2 = zip_files(&[("deep.py", b"eval(x)\n")]);
    let inner = zip_files(&[
        ("payload.py", b"import os\nos.system('id')\n"),
        ("deeper.zip", &inner2),
    ]);
    let bytes = tar_gz(&[
        TarItem::File("pkg-1.0/setup.py", b"x = 1\n"),
        TarItem::File("pkg-1.0/data/blob.zip", &inner),
    ]);
    let r = scan(&bytes, "pkg-1.0.tar.gz", &ScanOptions::default()).unwrap();
    // Depth 1 is expanded and counts toward the all_ surface only.
    assert_eq!(r.features["all_proc_exec"], 1.0);
    assert_eq!(r.features["inst_proc_exec"], 0.0);
    // Depth 2 is not expanded.
    assert_eq!(r.features["all_dyn_code"], 0.0);
    assert!(r
        .errors
        .iter()
        .any(|e| e.contains("nested archive not expanded")));

    let opts = ScanOptions {
        max_nesting_depth: 0,
        ..Default::default()
    };
    let r = scan(&bytes, "pkg-1.0.tar.gz", &opts).unwrap();
    assert_eq!(r.features["all_proc_exec"], 0.0);
}

#[test]
fn garbage_input_is_an_error_not_a_panic() {
    assert!(matches!(
        scan(
            b"definitely not an archive",
            "x.tar.gz",
            &ScanOptions::default()
        ),
        Err(ScanError::UnsupportedFormat(_))
    ));
    let mut truncated = benign_sdist();
    truncated.truncate(truncated.len() / 3);
    // Either a partial report with an error, or a rejection; never a panic.
    if let Ok(r) = scan(&truncated, "demo-1.0.0.tar.gz", &ScanOptions::default()) {
        assert!(!r.errors.is_empty());
    }
    let mut bad_zip = benign_wheel();
    let n = bad_zip.len();
    bad_zip[n / 2..].fill(0);
    let _ = scan(
        &bad_zip,
        "demo-1.0.0-py3-none-any.whl",
        &ScanOptions::default(),
    );
}

#[test]
fn bzip2_sdist_is_supported() {
    use std::io::Write;
    let tar = tar_bytes(&[TarItem::File(
        "demo-1.0/setup.py",
        BENIGN_SETUP_PY.as_bytes(),
    )]);
    let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    enc.write_all(&tar).unwrap();
    let bytes = enc.finish().unwrap();
    let r = scan(&bytes, "demo-1.0.tar.bz2", &ScanOptions::default()).unwrap();
    assert_eq!(r.ecosystem, Ecosystem::Pypi);
    assert_eq!(r.install_surface, vec!["setup.py"]);
}
