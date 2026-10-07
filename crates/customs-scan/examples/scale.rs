//! Scaling probe: time a scan of one file holding a token repeated N times, at doubling N.
//!
//! A scan should grow about linearly with input size. A ratio near 4 between rows means
//! some pass is quadratic. Used to triage slow inputs found by the `fuzz` example.
//!
//! Usage: `scale <path-in-archive> <token> [max-n] [prefix] [suffix]`, where the strings
//! accept `\n`, `\t` and `\"` escapes, e.g. `scale package/index.js 'https://x.io/a '`.
//! The prefix and suffix wrap the run, to place it inside a string literal or a comment.

use std::io::Write;
use std::time::Instant;

use customs_scan::{scan_archive, ScanOptions};

fn archive(path: &str, body: &[u8]) -> Vec<u8> {
    let root = path.split('/').next().unwrap_or("package");
    let manifest: (String, &[u8]) = if root == "package" {
        (
            "package/package.json".into(),
            br#"{"name":"p","version":"1.0.0"}"#,
        )
    } else {
        (
            format!("{root}/PKG-INFO"),
            b"Metadata-Version: 2.1\nName: p\nVersion: 1.0\n",
        )
    };
    let mut b = tar::Builder::new(Vec::new());
    for (p, d) in [(manifest.0.as_str(), manifest.1), (path, body)] {
        let mut h = tar::Header::new_gnu();
        h.set_size(d.len() as u64);
        h.set_mode(0o644);
        h.set_path(p).expect("path");
        h.set_cksum();
        b.append(&h, d).expect("append");
    }
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(&b.into_inner().expect("tar")).expect("gzip");
    enc.finish().expect("gzip")
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args
        .get(1)
        .map(String::as_str)
        .unwrap_or("package/index.js");
    let unescape = |t: &String| {
        t.replace("\\n", "\n")
            .replace("\\t", "\t")
            .replace("\\\"", "\"")
    };
    let token = args.get(2).map(unescape).unwrap_or_else(|| "a ".into());
    let prefix = args.get(4).map(unescape).unwrap_or_default();
    let suffix = args.get(5).map(unescape).unwrap_or_default();
    let max: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(64_000);
    let opts = ScanOptions {
        tokens: true,
        ..Default::default()
    };
    let mut n = 4_000;
    let mut last = 0.0;
    while n <= max {
        let body = format!("{prefix}{}{suffix}", token.repeat(n));
        let bytes = archive(path, body.as_bytes());
        let t = Instant::now();
        let _ = scan_archive(&bytes, "p.tgz", None, &opts);
        let ms = t.elapsed().as_secs_f64() * 1e3;
        let ratio = if last > 0.0 { ms / last } else { 0.0 };
        println!(
            "n={n:>7} bytes={:>9} {ms:>10.1} ms  x{ratio:.2}",
            body.len()
        );
        last = ms;
        n *= 2;
    }
}
