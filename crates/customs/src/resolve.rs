//! Version resolution for `POST /api/check`: turn `null`, an exact version, a dist-tag, or
//! a range into the concrete version a package manager would most likely install.
//!
//! This is deliberately approximate. It picks the newest non-yanked version that
//! satisfies the constraint (npm prefers the `latest` tag when it satisfies), which is what
//! a fresh install without a lock file does. Anything it cannot parse falls back to the
//! latest version, since checking something beats checking nothing.

use std::cmp::Ordering;

use customs_scan::Ecosystem;

use crate::registry::PackageMeta;

/// Resolve `spec` against `meta`. Errors carry a user-facing message.
pub fn resolve_version(meta: &PackageMeta, spec: Option<&str>) -> Result<String, String> {
    let spec = spec
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "latest" && *s != "*");
    let latest = || {
        meta.latest
            .clone()
            .filter(|l| meta.version(l).is_some() || meta.versions.is_empty())
            .or_else(|| newest(meta, |_| true))
            .ok_or_else(|| format!("{} has no published versions", meta.name))
    };
    let Some(spec) = spec else {
        return latest();
    };
    let exact = spec.strip_prefix("==").unwrap_or(spec).trim();
    let exact = exact.strip_prefix('=').unwrap_or(exact).trim();
    let exact = exact
        .strip_prefix('v')
        .filter(|_| meta.ecosystem == Ecosystem::Npm)
        .unwrap_or(exact);
    if meta.version(exact).is_some() {
        return Ok(exact.to_string());
    }
    if let Some(v) = meta.dist_tags.get(spec) {
        return Ok(v.clone());
    }
    match meta.ecosystem {
        Ecosystem::Npm => resolve_npm(meta, spec),
        Ecosystem::Pypi => resolve_pypi(meta, spec),
    }
    .unwrap_or_else(|| latest().map_err(|e| e.to_string()))
}

fn newest(meta: &PackageMeta, ok: impl Fn(&str) -> bool) -> Option<String> {
    let mut best: Option<&str> = None;
    for v in meta.versions.iter().filter(|v| !v.yanked && ok(&v.version)) {
        let better = match best {
            None => true,
            Some(b) => compare_versions(meta.ecosystem, &v.version, b) == Ordering::Greater,
        };
        if better {
            best = Some(&v.version);
        }
    }
    best.map(str::to_string)
}

pub(crate) fn compare_versions(eco: Ecosystem, a: &str, b: &str) -> Ordering {
    match eco {
        Ecosystem::Npm => match (semver::Version::parse(a), semver::Version::parse(b)) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            _ => a.cmp(b),
        },
        Ecosystem::Pypi => match (Pep440::parse(a), Pep440::parse(b)) {
            (Some(x), Some(y)) => x.cmp(&y),
            _ => a.cmp(b),
        },
    }
}

/// `Some(Ok)` resolved, `Some(Err)` parsed but unsatisfiable, `None` unparseable.
fn resolve_npm(meta: &PackageMeta, spec: &str) -> Option<Result<String, String>> {
    let alternatives: Vec<semver::VersionReq> = spec
        .split("||")
        .map(|alt| npm_range_to_req(alt.trim()))
        .collect::<Option<Vec<_>>>()?;
    let ok = |v: &str| {
        semver::Version::parse(v)
            .map(|v| alternatives.iter().any(|r| r.matches(&v)))
            .unwrap_or(false)
    };
    if let Some(l) = &meta.latest {
        if ok(l) {
            return Some(Ok(l.clone()));
        }
    }
    Some(newest(meta, ok).ok_or_else(|| format!("no version of {} matches '{spec}'", meta.name)))
}

/// npm separates comparators with spaces where Cargo-style requirements use commas, and
/// treats a bare version as exact where Cargo treats it as a caret range.
fn npm_range_to_req(alt: &str) -> Option<semver::VersionReq> {
    if alt.is_empty() || alt == "*" || alt == "x" {
        return semver::VersionReq::parse("*").ok();
    }
    if let Some((lo, hi)) = alt.split_once(" - ") {
        return semver::VersionReq::parse(&format!(">={}, <={}", lo.trim(), hi.trim())).ok();
    }
    let mut parts: Vec<String> = Vec::new();
    let mut pending_op = String::new();
    for tok in alt.split_whitespace() {
        if matches!(tok, ">" | ">=" | "<" | "<=" | "=" | "^" | "~") {
            pending_op = tok.to_string();
            continue;
        }
        let tok = format!("{pending_op}{tok}");
        pending_op.clear();
        let starts_with_op = tok.starts_with(['>', '<', '=', '^', '~']);
        let is_wild = tok.contains(['x', 'X', '*']);
        parts.push(if starts_with_op || is_wild {
            tok.replace(['x', 'X'], "*")
        } else {
            format!("={tok}")
        });
    }
    semver::VersionReq::parse(&parts.join(", ")).ok()
}

fn resolve_pypi(meta: &PackageMeta, spec: &str) -> Option<Result<String, String>> {
    let clauses = parse_pep440_specifier(spec)?;
    let mentions_pre = clauses.iter().any(|c| c.version.is_pre());
    let ok = |allow_pre: bool| {
        let clauses = &clauses;
        move |v: &str| {
            Pep440::parse(v).is_some_and(|pv| {
                (allow_pre || !pv.is_pre()) && clauses.iter().all(|c| c.matches(&pv))
            })
        }
    };
    let found = newest(meta, ok(mentions_pre)).or_else(|| newest(meta, ok(true)));
    Some(found.ok_or_else(|| format!("no version of {} matches '{spec}'", meta.name)))
}

#[derive(Debug, Clone, PartialEq)]
struct Clause {
    op: String,
    version: Pep440,
    /// `==1.2.*` and the prefix part of `~=`.
    wildcard: bool,
}

impl Clause {
    fn matches(&self, v: &Pep440) -> bool {
        let ord = v.cmp(&self.version);
        match self.op.as_str() {
            "==" | "===" if self.wildcard => v.release_starts_with(&self.version.release),
            "!=" if self.wildcard => !v.release_starts_with(&self.version.release),
            "==" | "===" => ord == Ordering::Equal,
            "!=" => ord != Ordering::Equal,
            ">=" => ord != Ordering::Less,
            "<=" => ord != Ordering::Greater,
            ">" => ord == Ordering::Greater,
            "<" => ord == Ordering::Less,
            "~=" => {
                let n = self.version.release.len().saturating_sub(1).max(1);
                ord != Ordering::Less && v.release_starts_with(&self.version.release[..n])
            }
            _ => false,
        }
    }
}

/// Parse `>=1.0,<2`, `~=1.4.2`, `==1.2.*`, and Poetry-style `^1.2` / `~1.2`.
fn parse_pep440_specifier(spec: &str) -> Option<Vec<Clause>> {
    let spec = spec.trim().trim_start_matches('(').trim_end_matches(')');
    let mut out = Vec::new();
    for raw in spec.split(',') {
        let c: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
        if c.is_empty() {
            continue;
        }
        if let Some(v) = c.strip_prefix('^') {
            let lo = Pep440::parse(v)?;
            let mut hi = lo.release.clone();
            let idx = hi.iter().position(|x| *x != 0).unwrap_or(hi.len() - 1);
            hi.truncate(idx + 1);
            hi[idx] += 1;
            out.push(Clause {
                op: ">=".into(),
                version: lo,
                wildcard: false,
            });
            out.push(Clause {
                op: "<".into(),
                version: Pep440::from_release(hi),
                wildcard: false,
            });
            continue;
        }
        if let Some(v) = c.strip_prefix('~').filter(|v| !v.starts_with('=')) {
            let lo = Pep440::parse(v)?;
            let mut hi = lo.release.clone();
            if hi.len() >= 2 {
                hi.truncate(2);
                hi[1] += 1;
            } else {
                hi[0] += 1;
            }
            out.push(Clause {
                op: ">=".into(),
                version: lo,
                wildcard: false,
            });
            out.push(Clause {
                op: "<".into(),
                version: Pep440::from_release(hi),
                wildcard: false,
            });
            continue;
        }
        let op_len = ["===", "==", "!=", "~=", ">=", "<=", ">", "<"]
            .iter()
            .find(|op| c.starts_with(**op))
            .map(|op| op.len())?;
        let (op, v) = c.split_at(op_len);
        let (v, wildcard) = match v.strip_suffix(".*") {
            Some(p) => (p, true),
            None => (v, false),
        };
        out.push(Clause {
            op: op.to_string(),
            version: Pep440::parse(v)?,
            wildcard,
        });
    }
    (!out.is_empty()).then_some(out)
}

/// Ordering key: epoch, trimmed release, pre-release, post-release, dev-release.
type SortKey = (u64, Vec<u64>, (i8, u8, u64), (i8, u64), (i8, u64));

/// A PEP 440 version reduced to what ordering needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pep440 {
    epoch: u64,
    release: Vec<u64>,
    /// (0 = a, 1 = b, 2 = rc, n)
    pre: Option<(u8, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
}

impl Pep440 {
    fn from_release(release: Vec<u64>) -> Self {
        Self {
            epoch: 0,
            release,
            pre: None,
            post: None,
            dev: None,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim().to_ascii_lowercase();
        let s = s.strip_prefix('v').unwrap_or(&s);
        let s = s.split('+').next()?; // local version labels do not affect ordering here
        let (epoch, rest) = match s.split_once('!') {
            Some((e, r)) => (e.parse().ok()?, r),
            None => (0, s),
        };
        let bytes = rest.as_bytes();
        let mut i = 0;
        let mut release = Vec::new();
        loop {
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            if start == i {
                return None;
            }
            release.push(rest[start..i].parse().ok()?);
            if i + 1 < bytes.len() && bytes[i] == b'.' && bytes[i + 1].is_ascii_digit() {
                i += 1;
                continue;
            }
            break;
        }
        let mut v = Self::from_release(release);
        v.epoch = epoch;
        let mut tail = &rest[i..];
        let num = |t: &str| -> (u64, usize) {
            let t2 = t.trim_start_matches(['.', '-', '_']);
            let skipped = t.len() - t2.len();
            let d: String = t2.chars().take_while(|c| c.is_ascii_digit()).collect();
            (d.parse().unwrap_or(0), skipped + d.len())
        };
        while !tail.is_empty() {
            let t = tail.trim_start_matches(['.', '-', '_']);
            let lead = tail.len() - t.len();
            let mut matched = false;
            for (kw, kind) in [
                ("alpha", 0u8),
                ("beta", 1),
                ("preview", 2),
                ("pre", 2),
                ("rc", 2),
                ("a", 0),
                ("b", 1),
                ("c", 2),
            ] {
                if let Some(r) = t.strip_prefix(kw) {
                    let (n, used) = num(r);
                    v.pre = Some((kind, n));
                    tail = &tail[lead + kw.len() + used..];
                    matched = true;
                    break;
                }
            }
            if matched {
                continue;
            }
            if let Some(r) = t
                .strip_prefix("post")
                .or_else(|| t.strip_prefix("rev"))
                .or_else(|| t.strip_prefix('r'))
            {
                let (n, used) = num(r);
                v.post = Some(n);
                tail = &tail[lead + (t.len() - r.len()) + used..];
                continue;
            }
            if let Some(r) = t.strip_prefix("dev") {
                let (n, used) = num(r);
                v.dev = Some(n);
                tail = &tail[lead + 3 + used..];
                continue;
            }
            if lead > 0 && t.starts_with(|c: char| c.is_ascii_digit()) && tail.starts_with('-') {
                // `1.0-1` is an implicit post release.
                let (n, used) = num(t);
                v.post = Some(n);
                tail = &tail[lead + used..];
                continue;
            }
            return None;
        }
        Some(v)
    }

    pub fn is_pre(&self) -> bool {
        self.pre.is_some() || self.dev.is_some()
    }

    /// First release segment (`2` in `2.31.0`).
    pub fn major(&self) -> u64 {
        self.release.first().copied().unwrap_or(0)
    }

    fn release_starts_with(&self, prefix: &[u64]) -> bool {
        prefix
            .iter()
            .enumerate()
            .all(|(i, p)| self.release.get(i).copied().unwrap_or(0) == *p)
    }

    fn key(&self) -> SortKey {
        let mut rel = self.release.clone();
        while rel.len() > 1 && rel.last() == Some(&0) {
            rel.pop();
        }
        let pre = match (self.pre, self.post, self.dev) {
            (None, None, Some(_)) => (-1, 0, 0),
            (None, _, _) => (1, 0, 0),
            (Some((k, n)), _, _) => (0, k, n),
        };
        let post = self.post.map(|n| (0, n)).unwrap_or((-1, 0));
        let dev = self.dev.map(|n| (0, n)).unwrap_or((1, 0));
        (self.epoch, rel, pre, post, dev)
    }
}

impl Ord for Pep440 {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}

impl PartialOrd for Pep440 {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::VersionMeta;
    use std::collections::BTreeMap;

    fn meta(eco: Ecosystem, versions: &[&str], latest: &str) -> PackageMeta {
        PackageMeta {
            ecosystem: eco,
            name: "demo".into(),
            latest: Some(latest.into()),
            dist_tags: [
                ("latest".to_string(), latest.to_string()),
                ("next".to_string(), "3.0.0-rc.1".to_string()),
            ]
            .into_iter()
            .collect::<BTreeMap<_, _>>(),
            versions: versions
                .iter()
                .map(|v| VersionMeta {
                    version: v.to_string(),
                    yanked: *v == "1.9.9",
                    ..Default::default()
                })
                .collect(),
            created: None,
            people: Vec::new(),
        }
    }

    #[test]
    fn pep440_ordering() {
        let order = [
            "1.0.dev1",
            "1.0a1.dev1",
            "1.0a1",
            "1.0a1.post1",
            "1.0b2",
            "1.0rc1",
            "1.0",
            "1.0.post1.dev1",
            "1.0.post1",
            "1.0.1",
            "1.1",
            "2!0.1",
        ];
        for w in order.windows(2) {
            let (a, b) = (Pep440::parse(w[0]).unwrap(), Pep440::parse(w[1]).unwrap());
            assert!(a < b, "{} < {}", w[0], w[1]);
        }
        assert!(Pep440::parse("1.0").is_some());
        assert_eq!(
            Pep440::parse("1.0")
                .unwrap()
                .cmp(&Pep440::parse("1.0.0").unwrap()),
            Ordering::Equal
        );
        assert!(Pep440::parse("not a version").is_none());
        assert!(Pep440::parse("1.0-1").unwrap().post.is_some());
    }

    #[test]
    fn pypi_specifiers() {
        let m = meta(
            Ecosystem::Pypi,
            &["1.0", "1.4.2", "1.4.9", "1.5.0", "1.9.9", "2.0", "2.1rc1"],
            "2.0",
        );
        let r = |s: &str| resolve_version(&m, Some(s)).unwrap();
        assert_eq!(resolve_version(&m, None).unwrap(), "2.0");
        assert_eq!(r("1.4.2"), "1.4.2");
        assert_eq!(r("==1.4.2"), "1.4.2");
        assert_eq!(r(">=1,<2"), "1.5.0"); // 1.9.9 is yanked
        assert_eq!(r("~=1.4.2"), "1.4.9");
        assert_eq!(r("==1.4.*"), "1.4.9");
        assert_eq!(r("!=2.0"), "1.5.0");
        assert_eq!(r(">=2.1rc1"), "2.1rc1");
        assert_eq!(r("^1.4"), "1.5.0");
        assert_eq!(r("~1.4"), "1.4.9");
        assert_eq!(r("(>=1.0, <1.4)"), "1.0");
        assert!(resolve_version(&m, Some(">=5")).is_err());
        // Unparseable falls back to latest.
        assert_eq!(r("@@@"), "2.0");
    }

    #[test]
    fn npm_ranges() {
        let m = meta(
            Ecosystem::Npm,
            &["1.0.0", "1.2.3", "1.9.0", "2.0.0", "3.0.0-rc.1"],
            "2.0.0",
        );
        let r = |s: &str| resolve_version(&m, Some(s)).unwrap();
        assert_eq!(r("^1.0.0"), "1.9.0");
        assert_eq!(r("^1"), "1.9.0");
        assert_eq!(r("~1.2.0"), "1.2.3");
        assert_eq!(r("1.x"), "1.9.0");
        assert_eq!(r("1.2.3"), "1.2.3");
        assert_eq!(r("v1.2.3"), "1.2.3");
        assert_eq!(r(">=1.0.0 <1.5.0"), "1.2.3");
        assert_eq!(r("^1 || ^2"), "2.0.0");
        assert_eq!(r("1.0.0 - 1.5.0"), "1.2.3");
        assert_eq!(r("next"), "3.0.0-rc.1");
        assert_eq!(r("latest"), "2.0.0");
        assert_eq!(r("*"), "2.0.0");
        assert!(resolve_version(&m, Some("^9")).is_err());
    }
}
