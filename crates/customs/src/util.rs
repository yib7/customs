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

fn ts(t: DateTime<Utc>) -> String {
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

/// `url` safe to show: a user name or password becomes `***` and the query and fragment
/// (where tokens also travel) are dropped. A URL with none of those comes back unchanged.
pub fn redact_url(url: &str) -> String {
    if let Ok(mut u) = url::Url::parse(url) {
        if !u.has_host() {
            return url.to_string();
        }
        let userinfo = !u.username().is_empty() || u.password().is_some();
        if !userinfo && u.query().is_none() && u.fragment().is_none() {
            return url.to_string();
        }
        if userinfo {
            let _ = u.set_password(None);
            let _ = u.set_username("***");
        }
        u.set_query(None);
        u.set_fragment(None);
        return u.to_string();
    }
    // Not parseable: still cut `user:pass@` from the authority and anything after `?`/`#`.
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let rest = &rest[..rest.find(['?', '#']).unwrap_or(rest.len())];
    let end = rest.find('/').unwrap_or(rest.len());
    let (authority, path) = rest.split_at(end);
    match authority.rsplit_once('@') {
        Some((_, host)) => format!("{scheme}://***@{host}{path}"),
        None => format!("{scheme}://{authority}{path}"),
    }
}

/// `text` with every `scheme://...` token passed through [`redact_url`].
pub fn redact_urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("://") {
        let start = rest[..i]
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || "+.-".contains(c)))
            .map_or(0, |j| j + 1);
        let end = rest[i..]
            .find(|c: char| c.is_whitespace() || "\"'`,;<>()[]{}".contains(c))
            .map_or(rest.len(), |j| i + j);
        out.push_str(&rest[..start]);
        out.push_str(&redact_url(&rest[start..end]));
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// Name and version from a PyPI distribution file name.
///
/// Wheels are `{name}-{version}(-{build})?-{py}-{abi}-{plat}.whl` with `-` escaped in the
/// name, so splitting on `-` is exact. Sdists are `{name}-{version}.{ext}`; legacy names
/// may contain hyphens and PEP 440 versions do not, so the version starts at the last
/// hyphen followed by a digit. Splitting at the first one would read the project
/// `requests-2x` as `requests`, inheriting that name's allow-list entry and registry
/// history. Extensions are the ones pip unpacks.
pub fn parse_pypi_filename(filename: &str) -> Option<(String, String)> {
    if let Some(stem) = filename.strip_suffix(".whl") {
        let parts: Vec<&str> = stem.split('-').collect();
        if parts.len() >= 5 {
            return Some((parts[0].to_string(), parts[1].to_string()));
        }
        return None;
    }
    let stem = [
        ".tar.gz",
        ".tar.bz2",
        ".tar.xz",
        ".tar.lzma",
        ".tar.lz",
        ".tgz",
        ".tbz",
        ".txz",
        ".tlz",
        ".zip",
        ".tar",
    ]
    .iter()
    .find_map(|ext| filename.strip_suffix(ext))?;
    let bytes = stem.as_bytes();
    let idx = (1..bytes.len().saturating_sub(1))
        .rev()
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
        assert_eq!(
            parse_pypi_filename("requests-2x-1.0.tar.gz"),
            Some(("requests-2x".into(), "1.0".into()))
        );
        assert_eq!(
            parse_pypi_filename("py-2fa-0.1.0rc1.tar.bz2"),
            Some(("py-2fa".into(), "0.1.0rc1".into()))
        );
        assert_eq!(
            parse_pypi_filename("demo-1.0.txz"),
            Some(("demo".into(), "1.0".into()))
        );
        assert_eq!(parse_pypi_filename("-1.0.tar.gz"), None);
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

    #[test]
    fn urls_lose_their_credentials() {
        assert_eq!(
            redact_url("https://__token__:pypi-s3cret@corp.example/simple?token=t#x"),
            "https://***@corp.example/simple"
        );
        assert_eq!(
            redact_url("http://user@127.0.0.1:1234/npm"),
            "http://***@127.0.0.1:1234/npm"
        );
        // Nothing to hide: unchanged, no trailing slash added.
        assert_eq!(redact_url("https://pypi.org"), "https://pypi.org");
        assert_eq!(redact_url("not a url"), "not a url");
        assert_eq!(
            redact_url("https://u:p@[bad host/x?y"),
            "https://***@[bad host/x"
        );
        assert_eq!(
            redact_urls("`--index-url https://u:s3cret@h.example/x?k=v` sends pip elsewhere, and \"http://a:b@c/\""),
            "`--index-url https://***@h.example/x` sends pip elsewhere, and \"http://***@c/\""
        );
        assert_eq!(redact_urls("no urls here"), "no urls here");
    }
}
