//! Structure-aware mutation fuzzer for the scanner, on stable Rust.
//!
//! The scanner parses untrusted archives inside the proxy's request path, so a panic is an
//! internal error on an install and a pathological input ties up a blocking thread. This
//! takes real archives as seeds and mutates them at three levels: raw bytes (the container
//! parsers), tar headers inside a recompressed gzip (paths, sizes, entry types), and file
//! contents inside a rebuilt tar.gz (the lexers, manifest parsers and surface rules). Every
//! input runs under `catch_unwind`; panics and inputs slower than `--slow-ms` are written to
//! `--out` for replay.
//!
//! ```sh
//! cargo run --release -p customs-scan --example fuzz -- \
//!     --seeds seeds.txt --seconds 600 --out fuzz-out
//! cargo run --release -p customs-scan --example fuzz -- --replay fuzz-out/crash-0.bin
//! ```

use std::io::{Read, Write};
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use customs_scan::{scan_archive, ScanOptions};
use rayon::prelude::*;

/// Byte strings that sit on the parsers' decision points.
const DICT: &[&[u8]] = &[
    b"\"",
    b"'",
    b"'''",
    b"\"\"\"",
    b"`",
    b"${",
    b"}",
    b"\\",
    b"\\\"",
    b"\n",
    b"\r\n",
    b"#",
    b"//",
    b"/*",
    b"*/",
    b"(",
    b")",
    b"[",
    b"]",
    b"{",
    b"<!(",
    b"<!@(",
    b"\xc3\xa9",
    b"\xe2\x80\x8b",
    b"\xf0\x9f\x92\xa9",
    b"\xff",
    b"\x00",
    b"exec(",
    b"eval(",
    b"b64decode(",
    b"zlib.decompress(b64decode('",
    b"eval(atob('",
    b"Buffer.from('aW1wb3J0IG9zCg==', 'base64')",
    b"'aW1wb3J0IHNvY2tldApzb2NrZXQuc29ja2V0KCk='",
    b"'eJzLzC3ILypRKM5Pzk4t4YJQehBKQ1MvOT8vLzW5RENDKbUsM0cvtSIxtyAnVUlHwQQINDW5AM3KFM4='",
    b"[sys.executable, '-c', '",
    b"__import__('builtins').exec(",
    b"''.join(['",
    b"].join(",
    b"[::-1]",
    b"var _s = ['a', 'b'];",
    b"_s[0x1]",
    b"_s[0]",
    b"require(",
    b"import ",
    b"from . import ",
    b"from .. import x",
    b"node -e \"",
    b"python -c '",
    b"\"scripts\": {\"postinstall\": \"",
    b"\"gypfile\": true",
    b"\"main\": \"",
    b"cmdclass",
    b"build-backend",
    b"backend-path",
    b"npm run ",
    b"bun run ",
    b"&&",
    b"|",
    b"$(",
    b"\t",
    b"                                                                     ",
    b".dist-info/",
    b"__init__.py",
    b".pth",
    b"../",
    b"sources/",
    b"package/",
    b"https://x.io/a ",
    b"~/.ssh/id_rsa ",
    b"http://1.2.3.4/ ",
    b"\n",
    b"\x41",
    b"bitcoin ",
    b"curl x | sh\n",
    b"exec(b64decode(x))\n",
    b"a\nb\n",
];

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

struct Seed {
    name: String,
    bytes: Vec<u8>,
    /// Decompressed tar for gzip seeds.
    tar: Option<Vec<u8>>,
    /// `(path, data)` of regular files, for content mutations.
    files: Vec<(String, Vec<u8>)>,
    /// Scan time of the unmutated seed; "slow" is relative to it.
    base: Duration,
}

fn load_seed(path: &Path) -> Option<Seed> {
    let bytes = std::fs::read(path).ok()?;
    let name = path.file_name()?.to_string_lossy().into_owned();
    let mut tar = None;
    let mut files = Vec::new();
    if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&bytes[..])
            .take(64 << 20)
            .read_to_end(&mut out)
            .ok()?;
        let mut ar = tar::Archive::new(&out[..]);
        if let Ok(entries) = ar.entries() {
            for e in entries.flatten().take(400) {
                let mut e = e;
                if e.header().entry_type().is_file() && e.size() <= 256 << 10 {
                    let p = e.path().ok()?.to_string_lossy().into_owned();
                    let mut d = Vec::new();
                    if e.read_to_end(&mut d).is_ok() {
                        files.push((p, d));
                    }
                }
            }
        }
        tar = Some(out);
    }
    Some(Seed {
        name,
        bytes,
        tar,
        files,
        base: Duration::ZERO,
    })
}

fn mutate_bytes(rng: &mut Rng, data: &mut Vec<u8>, other: &[u8]) {
    for _ in 0..1 + rng.below(8) {
        match rng.below(8) {
            0 if !data.is_empty() => {
                let i = rng.below(data.len());
                data[i] ^= 1 << rng.below(8);
            }
            1 if !data.is_empty() => {
                let i = rng.below(data.len());
                data[i] = rng.next() as u8;
            }
            2 => {
                let i = rng.below(data.len() + 1);
                let d = DICT[rng.below(DICT.len())];
                data.splice(i..i, d.iter().copied());
            }
            3 if !data.is_empty() => {
                let i = rng.below(data.len());
                let n = 1 + rng.below((data.len() - i).min(64));
                data.drain(i..i + n);
            }
            4 if !data.is_empty() => {
                data.truncate(rng.below(data.len()));
            }
            5 if !other.is_empty() && !data.is_empty() => {
                let i = rng.below(data.len());
                let j = rng.below(other.len());
                let n = 1 + rng.below((other.len() - j).min(4096));
                data.splice(i..i, other[j..j + n].iter().copied());
            }
            6 if !data.is_empty() => {
                // Repeat a slice: deep nesting and long runs.
                let i = rng.below(data.len());
                let n = 1 + rng.below((data.len() - i).min(16));
                let chunk = data[i..i + n].to_vec();
                for _ in 0..rng.below(2000) {
                    data.splice(i..i, chunk.iter().copied());
                }
            }
            7 => {
                // Mass repetition of one token, often inside a string literal: probes
                // anything super-linear in the size of a file, a line or a literal.
                let i = rng.below(data.len() + 1);
                let d = DICT[rng.below(DICT.len())];
                let n = 1 + rng.below(200_000);
                let q: &[u8] = [&b"\""[..], b"'", b"`", b""][rng.below(4)];
                let mut ins = q.to_vec();
                for _ in 0..n {
                    ins.extend_from_slice(d);
                }
                ins.extend_from_slice(q);
                data.splice(i..i, ins);
            }
            _ => {}
        }
    }
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(data).expect("in-memory write");
    enc.finish().expect("in-memory gzip")
}

/// Mutate the bytes inside the gzip: tar headers, sizes, paths and entry types.
fn mutate_tar(rng: &mut Rng, tar: &[u8]) -> Vec<u8> {
    let mut t = tar.to_vec();
    let blocks = t.len() / 512;
    for _ in 0..1 + rng.below(4) {
        if blocks == 0 {
            break;
        }
        let b = rng.below(blocks) * 512;
        match rng.below(5) {
            // name field
            0 => {
                let d = DICT[rng.below(DICT.len())];
                let at = b + rng.below(100);
                for (k, &c) in d.iter().enumerate() {
                    if at + k < b + 100 {
                        t[at + k] = c;
                    }
                }
            }
            // size field (octal, 12 bytes at 124)
            1 => {
                let digits = format!("{:011o}", rng.next() % (1 << 33));
                t[b + 124..b + 135].copy_from_slice(digits.as_bytes());
            }
            // type flag
            2 => t[b + 156] = b"0125LKxgS\0"[rng.below(10)],
            // link name
            3 => {
                let d = DICT[rng.below(DICT.len())];
                for (k, &c) in d.iter().enumerate().take(100) {
                    t[b + 157 + k] = c;
                }
            }
            _ => {
                let i = b + rng.below(512);
                t[i] = rng.next() as u8;
            }
        }
    }
    t
}

/// Mutate file contents and paths, then rebuild a well-formed tar.gz.
fn mutate_files(rng: &mut Rng, seed: &Seed, other: &[u8]) -> Vec<u8> {
    let mut files = seed.files.clone();
    for _ in 0..1 + rng.below(3) {
        if files.is_empty() {
            break;
        }
        let i = rng.below(files.len());
        if rng.below(6) == 0 {
            // A new file next to the package root, or a renamed one.
            let root = files[i]
                .0
                .split('/')
                .next()
                .unwrap_or("package")
                .to_string();
            let names = [
                "binding.gyp",
                "setup.py",
                "package.json",
                "x.pth",
                "pkg/__init__.py",
                "pkg-1.0.dist-info/METADATA",
                "sources/pkg/pyproject.toml",
                "index.js",
            ];
            let p = format!("{root}/{}", names[rng.below(names.len())]);
            let data = files[i].1.clone();
            files.push((p, data));
        } else {
            mutate_bytes(rng, &mut files[i].1, other);
        }
    }
    let mut b = tar::Builder::new(Vec::new());
    for (p, d) in &files {
        let mut h = tar::Header::new_gnu();
        h.set_size(d.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        if h.set_path(p).is_err() {
            continue;
        }
        h.set_cksum();
        let _ = b.append(&h, &d[..]);
    }
    gzip(&b.into_inner().unwrap_or_default())
}

fn make_input(rng: &mut Rng, seeds: &[Seed]) -> (String, Duration, Vec<u8>) {
    let s = &seeds[rng.below(seeds.len())];
    let other = &seeds[rng.below(seeds.len())];
    let other_bytes: &[u8] = other
        .files
        .get(rng.below(other.files.len().max(1)))
        .map(|f| &f.1[..])
        .unwrap_or(&other.bytes);
    let level = rng.below(10);
    let bytes = match (&s.tar, level) {
        (Some(_), 0..=5) if !s.files.is_empty() => mutate_files(rng, s, other_bytes),
        (Some(t), 6..=7) => gzip(&mutate_tar(rng, t)),
        _ => {
            let mut b = s.bytes.clone();
            mutate_bytes(rng, &mut b, &other.bytes);
            b
        }
    };
    (s.name.clone(), s.base, bytes)
}

fn run_one(name: &str, bytes: &[u8], opts: &ScanOptions) -> (Option<String>, Duration) {
    let t = Instant::now();
    let r = panic::catch_unwind(AssertUnwindSafe(|| {
        let _ = scan_archive(bytes, name, None, opts);
    }));
    let msg = r.err().map(|e| {
        e.downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_else(|| "non-string panic".into())
    });
    (msg, t.elapsed())
}

fn arg(args: &[String], key: &str) -> Option<String> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1).cloned())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let opts = ScanOptions {
        tokens: true,
        ..Default::default()
    };
    if let Some(p) = arg(&args, "--replay") {
        let bytes = std::fs::read(&p).expect("readable input");
        let (msg, dt) = run_one("replay.tar.gz", &bytes, &opts);
        println!("{p}: {:?} in {dt:?}", msg);
        return;
    }
    let seeds_file = arg(&args, "--seeds").expect("--seeds <file with one archive path per line>");
    let seconds: u64 = arg(&args, "--seconds").map_or(60, |s| s.parse().expect("seconds"));
    let slow_ms: u128 = arg(&args, "--slow-ms").map_or(2000, |s| s.parse().expect("ms"));
    let out = PathBuf::from(arg(&args, "--out").unwrap_or_else(|| "fuzz-out".into()));
    let seed0: u64 =
        arg(&args, "--seed").map_or(0x9e37_79b9_7f4a_7c15, |s| s.parse().expect("seed"));
    std::fs::create_dir_all(&out).expect("output directory");
    let mut seeds: Vec<Seed> = std::fs::read_to_string(&seeds_file)
        .expect("seed list")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| load_seed(Path::new(l.trim())))
        .collect();
    assert!(!seeds.is_empty(), "no readable seeds");
    seeds
        .par_iter_mut()
        .for_each(|s| s.base = run_one(&s.name, &s.bytes, &opts).1);
    eprintln!("{} seeds", seeds.len());
    // Panics are caught and reported; keep the default hook from printing each one.
    panic::set_hook(Box::new(|_| {}));

    let deadline = Instant::now() + Duration::from_secs(seconds);
    let execs = AtomicU64::new(0);
    let found = Mutex::new(Vec::<String>::new());
    let stop = AtomicBool::new(false);
    let threads = rayon::current_num_threads() as u64;
    (0..threads).into_par_iter().for_each(|w| {
        let mut rng = Rng(seed0 ^ (w + 1).wrapping_mul(0x2545_f491_4f6c_dd1d));
        while !stop.load(Ordering::Relaxed) {
            if Instant::now() > deadline {
                stop.store(true, Ordering::Relaxed);
                break;
            }
            let (name, base, bytes) = make_input(&mut rng, &seeds);
            // An abort (stack overflow, out of memory) cannot be caught: keep the input
            // in flight on disk so the run that died leaves it behind.
            std::fs::write(out.join(format!("inflight-{w}.bin")), &bytes).expect("write input");
            let (msg, dt) = run_one(&name, &bytes, &opts);
            let n = execs.fetch_add(1, Ordering::Relaxed);
            let slow = dt.as_millis() > slow_ms.max(4 * base.as_millis());
            let kind = match (&msg, slow) {
                (Some(_), _) => "crash",
                (None, true) => "slow",
                _ => continue,
            };
            let mut f = found.lock().expect("lock");
            let path = out.join(format!("{kind}-{}.bin", f.len()));
            std::fs::write(&path, &bytes).expect("write finding");
            let line = format!(
                "{kind} after {n} execs, {} ms, seed {name}: {}",
                dt.as_millis(),
                msg.unwrap_or_default()
            );
            eprintln!("{line} -> {}", path.display());
            f.push(line);
        }
    });
    let found = found.into_inner().expect("lock");
    println!(
        "{} execs in {seconds} s on {threads} threads, {} findings",
        execs.load(Ordering::Relaxed),
        found.len()
    );
    std::fs::write(out.join("findings.txt"), found.join("\n")).expect("write summary");
}
