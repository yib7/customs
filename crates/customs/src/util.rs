//! Small helpers shared by several modules.

use chrono::{DateTime, SecondsFormat, Utc};
use customs_scan::Ecosystem;

pub fn ecosystem_str(e: Ecosystem) -> &'static str {
    match e {
        Ecosystem::Pypi => "pypi",
        Ecosystem::Npm => "npm",
    }
}

pub fn parse_ecosystem(s: &str) -> Option<Ecosystem> {
    match s.to_ascii_lowercase().as_str() {
        "pypi" | "pip" | "python" => Some(Ecosystem::Pypi),
        "npm" | "node" | "js" => Some(Ecosystem::Npm),
        _ => None,
    }
}

/// Registry display name of an ecosystem, for messages.
pub fn registry_name(e: Ecosystem) -> &'static str {
    match e {
        Ecosystem::Pypi => "PyPI",
        Ecosystem::Npm => "npm",
    }
}

/// Canonical package name (PEP 503 for PyPI, lowercase for npm).
pub fn normalize_name(e: Ecosystem, name: &str) -> String {
    customs_model::name::normalize(e, name)
}

pub fn now() -> DateTime<Utc> {
    Utc::now()
}

pub fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn now_ts() -> String {
    ts(now())
}

/// "3 minutes", "5 hours", "2 days".
pub fn human_duration(d: chrono::Duration) -> String {
    let s = d.num_seconds().max(0);
    let (n, unit) = if s < 120 {
        (s, "second")
    } else if s < 2 * 3600 {
        (s / 60, "minute")
    } else if s < 2 * 86400 {
        (s / 3600, "hour")
    } else {
        (s / 86400, "day")
    };
    format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
}

/// Name and version from a PyPI distribution file name.
///
/// Wheels are `{name}-{version}(-{build})?-{py}-{abi}-{plat}.whl` with `-` escaped in the
/// name, so splitting on `-` is exact. Sdists are `{name}-{version}.{ext}`; the name may
/// contain hyphens, so the version starts at the first hyphen followed by a digit.
pub fn parse_pypi_filename(filename: &str) -> Option<(String, String)> {
    if let Some(stem) = filename.strip_suffix(".whl") {
        let parts: Vec<&str> = stem.split('-').collect();
        if parts.len() >= 5 {
            return Some((parts[0].to_string(), parts[1].to_string()));
        }
        return None;
    }
    let stem = [".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".tar"]
        .iter()
        .find_map(|ext| filename.strip_suffix(ext))?;
    let bytes = stem.as_bytes();
    let idx = (0..bytes.len().saturating_sub(1))
        .find(|&i| bytes[i] == b'-' && bytes[i + 1].is_ascii_digit())?;
    Some((stem[..idx].to_string(), stem[idx + 1..].to_string()))
}

/// Version from an npm tarball file name `{bare}-{version}.tgz`.
pub fn parse_npm_tarball(package: &str, filename: &str) -> Option<String> {
    let stem = filename.strip_suffix(".tgz")?;
    let bare = package.rsplit('/').next().unwrap_or(package);
    if let Some(v) = stem.strip_prefix(&format!("{bare}-")) {
        return Some(v.to_string());
    }
    let bytes = stem.as_bytes();
    let idx = (0..bytes.len().saturating_sub(1))
        .find(|&i| bytes[i] == b'-' && bytes[i + 1].is_ascii_digit())?;
    Some(stem[idx + 1..].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pypi_filenames() {
        assert_eq!(
            parse_pypi_filename("requests-2.32.3-py3-none-any.whl"),
            Some(("requests".into(), "2.32.3".into()))
        );
        assert_eq!(
            parse_pypi_filename("python_dateutil-2.9.0.post0-py2.py3-none-any.whl"),
            Some(("python_dateutil".into(), "2.9.0.post0".into()))
        );
        assert_eq!(
            parse_pypi_filename("python-dateutil-2.8.2.tar.gz"),
            Some(("python-dateutil".into(), "2.8.2".into()))
        );
        assert_eq!(
            parse_pypi_filename("jinja2-time-0.2.0.zip"),
            Some(("jinja2-time".into(), "0.2.0".into()))
        );
        assert_eq!(parse_pypi_filename("weird.exe"), None);
        assert_eq!(parse_pypi_filename("bad.whl"), None);
    }

    #[test]
    fn npm_tarballs() {
        assert_eq!(
            parse_npm_tarball("left-pad", "left-pad-1.3.0.tgz").as_deref(),
            Some("1.3.0")
        );
        assert_eq!(
            parse_npm_tarball("@babel/core", "core-7.24.0.tgz").as_deref(),
            Some("7.24.0")
        );
        assert_eq!(
            parse_npm_tarball("x", "x-1.0.0-beta.1.tgz").as_deref(),
            Some("1.0.0-beta.1")
        );
        assert_eq!(parse_npm_tarball("x", "x.zip"), None);
    }

    #[test]
    fn durations() {
        assert_eq!(human_duration(chrono::Duration::seconds(30)), "30 seconds");
        assert_eq!(human_duration(chrono::Duration::minutes(90)), "90 minutes");
        assert_eq!(human_duration(chrono::Duration::hours(2)), "2 hours");
        assert_eq!(human_duration(chrono::Duration::days(1)), "24 hours");
        assert_eq!(human_duration(chrono::Duration::days(3)), "3 days");
    }
}
