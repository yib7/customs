//! Size cap for the artifact cache.
//!
//! Blobs live at `<cache>/<sha[..2]>/<sha>`. A blob's mtime is its last use (hits touch it),
//! so eviction removes the least recently used blobs until the cache is back under its low
//! watermark. Blobs used within the grace period are never removed, so a file that is being
//! served or scanned right now stays on disk. A removed blob only costs a re-download: its
//! scan verdict lives in the database, and `fetch_artifact` treats a missing blob as a miss.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Eviction stops once the cache is at or below this fraction of its cap.
const LOW_WATERMARK: f64 = 0.8;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Evicted {
    pub files: u64,
    pub bytes: u64,
    pub remaining_bytes: u64,
}

/// Mark a blob as used now.
pub fn touch(path: &Path) {
    if let Ok(f) = std::fs::File::options().append(true).open(path) {
        let _ = f.set_modified(SystemTime::now());
    }
}

fn blobs(dir: &Path) -> Vec<(SystemTime, u64, PathBuf)> {
    let mut out = Vec::new();
    let Ok(shards) = std::fs::read_dir(dir) else {
        return out;
    };
    for shard in shards.flatten() {
        // Two-hex-digit shard directories only; `tmp/` holds downloads in progress.
        let name = shard.file_name();
        if name.len() != 2 || !shard.path().is_dir() {
            continue;
        }
        let Ok(files) = std::fs::read_dir(shard.path()) else {
            continue;
        };
        for f in files.flatten() {
            if let Ok(m) = f.metadata() {
                if m.is_file() {
                    let t = m.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                    out.push((t, m.len(), f.path()));
                }
            }
        }
    }
    out
}

/// Remove least recently used blobs until the cache is under `LOW_WATERMARK * max_bytes`.
/// Does nothing while the cache is within `max_bytes`.
pub fn evict(dir: &Path, max_bytes: u64, grace: Duration) -> Evicted {
    let mut all = blobs(dir);
    let mut total: u64 = all.iter().map(|b| b.1).sum();
    let mut out = Evicted::default();
    if total > max_bytes {
        let target = (max_bytes as f64 * LOW_WATERMARK) as u64;
        let cutoff = SystemTime::now()
            .checked_sub(grace)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        all.sort_by_key(|b| b.0);
        for (t, size, path) in all {
            if total <= target || t > cutoff {
                break;
            }
            if std::fs::remove_file(&path).is_ok() {
                total -= size;
                out.files += 1;
                out.bytes += size;
            }
        }
    }
    out.remaining_bytes = total;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(dir: &Path, name: &str, size: usize, age_s: u64) -> PathBuf {
        let p = dir.join(&name[..2]).join(name);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, vec![0u8; size]).unwrap();
        let f = std::fs::File::options().append(true).open(&p).unwrap();
        f.set_modified(SystemTime::now() - Duration::from_secs(age_s))
            .unwrap();
        p
    }

    #[test]
    fn evicts_oldest_first_down_to_the_low_watermark() {
        let d = tempfile::tempdir().unwrap();
        let old = blob(d.path(), "aa01", 400, 3000);
        let mid = blob(d.path(), "bb02", 400, 2000);
        let new = blob(d.path(), "cc03", 400, 1000);
        // In-progress downloads are not blobs.
        std::fs::create_dir_all(d.path().join("tmp")).unwrap();
        std::fs::write(d.path().join("tmp/x.part"), vec![0u8; 5000]).unwrap();

        // Within the cap: nothing happens.
        let e = evict(d.path(), 1200, Duration::from_secs(60));
        assert_eq!(e.files, 0);
        assert_eq!(e.remaining_bytes, 1200);

        // Over the cap of 1000: remove until <= 800.
        let e = evict(d.path(), 1000, Duration::from_secs(60));
        assert_eq!((e.files, e.bytes, e.remaining_bytes), (1, 400, 800));
        assert!(!old.exists() && mid.exists() && new.exists());

        // Touching a blob makes it the most recently used.
        touch(&mid);
        let e = evict(d.path(), 500, Duration::from_secs(60));
        assert_eq!(e.files, 1);
        assert!(mid.exists() && !new.exists());
    }

    #[test]
    fn recently_used_blobs_survive_even_over_the_cap() {
        let d = tempfile::tempdir().unwrap();
        let a = blob(d.path(), "aa01", 400, 10);
        let e = evict(d.path(), 100, Duration::from_secs(600));
        assert_eq!(e.files, 0);
        assert!(a.exists());
    }
}
