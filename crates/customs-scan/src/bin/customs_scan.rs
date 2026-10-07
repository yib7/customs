//! `customs-scan`: scan package archives and print feature reports as JSON.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use customs_scan::{feature_names, scan_delta, scan_path, Ecosystem, ScanOptions};
use rayon::prelude::*;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "customs-scan",
    version,
    about = "Static feature extraction for package archives"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Scan one archive and print its report.
    File {
        archive: PathBuf,
        /// Include the install-surface token stream.
        #[arg(long)]
        tokens: bool,
        /// Force the ecosystem instead of detecting it.
        #[arg(long, value_parser = parse_eco)]
        ecosystem: Option<Ecosystem>,
        /// Print a single line instead of indented JSON.
        #[arg(long)]
        compact: bool,
    },
    /// Scan many archives in parallel, writing one JSON line per archive in input order.
    Batch {
        /// File with one archive path per line.
        #[arg(long)]
        input: PathBuf,
        /// JSONL output file.
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        tokens: bool,
        #[arg(long, value_parser = parse_eco)]
        ecosystem: Option<Ecosystem>,
        /// Worker threads (defaults to the number of CPUs).
        #[arg(long)]
        jobs: Option<usize>,
    },
    /// Scan what changed between two releases (new files and new lines only).
    Delta {
        /// The previous release's archive.
        #[arg(long)]
        prev: PathBuf,
        /// The release being checked.
        #[arg(long)]
        cur: PathBuf,
        #[arg(long, value_parser = parse_eco)]
        ecosystem: Ecosystem,
        #[arg(long)]
        tokens: bool,
    },
    /// Print the ordered feature name list, one per line.
    Features {
        /// Print a JSON array instead.
        #[arg(long)]
        json: bool,
    },
}

fn parse_eco(s: &str) -> Result<Ecosystem, String> {
    s.parse()
}

/// Scan one path; failures and panics both become an error object so one bad archive can
/// never abort a batch.
fn scan_line(path: &str, eco: Option<Ecosystem>, opts: &ScanOptions) -> Value {
    let p = Path::new(path);
    let result = std::panic::catch_unwind(|| scan_path(p, eco, opts));
    match result {
        Ok(Ok(report)) => {
            let mut v =
                serde_json::to_value(report).unwrap_or_else(|e| json!({"error": e.to_string()}));
            if let Some(o) = v.as_object_mut() {
                o.insert("path".into(), Value::String(path.to_string()));
            }
            v
        }
        Ok(Err(e)) => json!({"archive": path, "error": e.to_string()}),
        Err(panic) => {
            let msg = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "unknown panic".into());
            json!({"archive": path, "error": format!("internal error: {msg}")})
        }
    }
}

fn batch(
    input: &Path,
    output: &Path,
    opts: &ScanOptions,
    eco: Option<Ecosystem>,
    jobs: Option<usize>,
) -> Result<()> {
    let reader = BufReader::new(
        std::fs::File::open(input).with_context(|| format!("opening {}", input.display()))?,
    );
    let paths: Vec<String> = reader
        .lines()
        .collect::<std::io::Result<Vec<_>>>()?
        .into_iter()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    let mut builder = rayon::ThreadPoolBuilder::new();
    if let Some(j) = jobs {
        builder = builder.num_threads(j.max(1));
    }
    let pool = builder.build()?;
    let mut out = BufWriter::new(
        std::fs::File::create(output).with_context(|| format!("creating {}", output.display()))?,
    );
    let started = std::time::Instant::now();
    let mut n_err = 0usize;
    // Chunks keep memory bounded while preserving input order in the output.
    for chunk in paths.chunks(512) {
        let lines: Vec<Value> =
            pool.install(|| chunk.par_iter().map(|p| scan_line(p, eco, opts)).collect());
        for v in lines {
            if v.get("error").is_some() {
                n_err += 1;
            }
            serde_json::to_writer(&mut out, &v)?;
            out.write_all(b"\n")?;
        }
    }
    out.flush()?;
    let secs = started.elapsed().as_secs_f64();
    eprintln!(
        "scanned {} archives ({} errors) in {:.1}s ({:.1} archives/s)",
        paths.len(),
        n_err,
        secs,
        paths.len() as f64 / secs.max(1e-9)
    );
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::File {
            archive,
            tokens,
            ecosystem,
            compact,
        } => {
            let opts = ScanOptions {
                tokens,
                ..Default::default()
            };
            let report = scan_path(&archive, ecosystem, &opts)
                .with_context(|| format!("scanning {}", archive.display()))?;
            let s = if compact {
                serde_json::to_string(&report)?
            } else {
                serde_json::to_string_pretty(&report)?
            };
            println!("{s}");
        }
        Cmd::Batch {
            input,
            output,
            tokens,
            ecosystem,
            jobs,
        } => {
            let opts = ScanOptions {
                tokens,
                ..Default::default()
            };
            batch(&input, &output, &opts, ecosystem, jobs)?;
        }
        Cmd::Delta {
            prev,
            cur,
            ecosystem,
            tokens,
        } => {
            let opts = ScanOptions {
                tokens,
                ..Default::default()
            };
            let read =
                |p: &Path| std::fs::read(p).with_context(|| format!("reading {}", p.display()));
            let name = cur
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let d = scan_delta(&read(&prev)?, &read(&cur)?, &name, ecosystem, &opts)?;
            println!("{}", serde_json::to_string(&d)?);
        }
        Cmd::Features { json } => {
            let names = feature_names();
            if json {
                println!("{}", serde_json::to_string(&names)?);
            } else {
                for n in names {
                    println!("{n}");
                }
            }
        }
    }
    Ok(())
}
