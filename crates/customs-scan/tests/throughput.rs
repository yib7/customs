//! Throughput benchmark on synthetic archives. Ignored by default; run with
//! `cargo test --release -p customs-scan --test throughput -- --ignored --nocapture`.

mod common;

use common::*;
use customs_scan::{scan_archive, ScanOptions};
use rayon::prelude::*;
use std::time::Instant;

fn synthetic_sdist(i: usize) -> (String, Vec<u8>) {
    let module: String = (0..150)
        .map(|j| {
            format!(
                "def f{j}(x):\n    \"\"\"Doc {j}.\"\"\"\n    return requests.get('https://example.com/{j}', params={{'q': x}})\n"
            )
        })
        .collect();
    let names: Vec<String> = (0..20).map(|k| format!("syn{i}-1.0/syn/m{k}.py")).collect();
    let mut files: Vec<(&str, &str)> = names
        .iter()
        .map(|n| (n.as_str(), module.as_str()))
        .collect();
    let setup = BENIGN_SETUP_PY.to_string();
    let setup_path = format!("syn{i}-1.0/setup.py");
    let init_path = format!("syn{i}-1.0/syn/__init__.py");
    files.push((&setup_path, &setup));
    files.push((&init_path, BENIGN_INIT));
    (format!("syn{i}-1.0.tar.gz"), tar_gz_files(&files))
}

fn synthetic_npm(i: usize) -> (String, Vec<u8>) {
    let js: String = (0..200)
        .map(|j| format!("function g{j}(a, b) {{ return fetch(`https://example.com/${{a}}/{j}`).then(r => r.json()); }}\n"))
        .collect();
    let names: Vec<String> = (0..15).map(|k| format!("package/lib/m{k}.js")).collect();
    let mut files: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), js.as_str())).collect();
    files.push(("package/package.json", BENIGN_PACKAGE_JSON));
    (format!("syn{i}-1.2.3.tgz"), tar_gz_files(&files))
}

#[test]
#[ignore]
fn throughput() {
    let corpus: Vec<(String, Vec<u8>)> = (0..100)
        .flat_map(|i| [synthetic_sdist(i), synthetic_npm(i)])
        .collect();
    let mb: f64 = corpus.iter().map(|(_, b)| b.len() as f64).sum::<f64>() / 1e6;
    let opts = ScanOptions {
        tokens: true,
        ..Default::default()
    };
    let t = Instant::now();
    for (name, bytes) in &corpus {
        scan_archive(bytes, name, None, &opts).unwrap();
    }
    let single = corpus.len() as f64 / t.elapsed().as_secs_f64();
    let t = Instant::now();
    corpus.par_iter().for_each(|(name, bytes)| {
        scan_archive(bytes, name, None, &opts).unwrap();
    });
    let parallel = corpus.len() as f64 / t.elapsed().as_secs_f64();
    println!(
        "throughput: {} archives ({mb:.1} MB compressed), single thread {single:.0} archives/s, {} threads {parallel:.0} archives/s",
        corpus.len(),
        rayon::current_num_threads()
    );
}
