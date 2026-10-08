//! Package metadata from manifests (DESIGN.md section 4.4).
//!
//! Sources, in priority order. npm: `package.json`. PyPI: `PKG-INFO` (sdist) or
//! `*.dist-info/METADATA` (wheel), then `pyproject.toml`, `setup.cfg`, and finally literal
//! keyword arguments of the `setup(...)` call in `setup.py`. Each field takes the first
//! source that provides it, so an sdist whose `PKG-INFO` lacks `Requires-Dist` still gets a
//! dependency count from `setup.py`.

use crate::lexer::{lex, Lang, TokKind};
use serde_json::Value;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Meta {
    pub name: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub homepage: Option<bool>,
    pub repo: Option<bool>,
    pub author_email: Option<bool>,
    pub license: Option<bool>,
    pub n_deps: Option<usize>,
    pub n_keywords: Option<usize>,
    /// Long description length when no README file is present.
    pub long_description_bytes: Option<u64>,
    /// URL fields that can name a source repository (repository, homepage, bug tracker,
    /// project URLs), as written.
    pub repo_urls: Vec<String>,
}

impl Meta {
    /// Fill every field still unset from `other`.
    pub fn merge(&mut self, other: Meta) {
        fn fill<T>(a: &mut Option<T>, b: Option<T>) {
            if a.is_none() {
                *a = b;
            }
        }
        fn fill_bool(a: &mut Option<bool>, b: Option<bool>) {
            match (*a, b) {
                (None, b) => *a = b,
                (Some(false), Some(true)) => *a = Some(true),
                _ => {}
            }
        }
        fill(&mut self.name, other.name);
        fill(&mut self.version, other.version);
        fill(&mut self.description, other.description);
        fill_bool(&mut self.homepage, other.homepage);
        fill_bool(&mut self.repo, other.repo);
        fill_bool(&mut self.author_email, other.author_email);
        fill_bool(&mut self.license, other.license);
        fill(&mut self.n_deps, other.n_deps);
        fill(&mut self.n_keywords, other.n_keywords);
        fill(
            &mut self.long_description_bytes,
            other.long_description_bytes,
        );
        if self.repo_urls.is_empty() {
            self.repo_urls = other.repo_urls;
        }
    }
}

fn nonempty(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty() && !t.eq_ignore_ascii_case("unknown") && !t.eq_ignore_ascii_case("none")
}

fn is_repo_url(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    [
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "codeberg.org",
        "sr.ht",
        "git+",
        ".git",
    ]
    .iter()
    .any(|h| l.contains(h))
}

/// Owner and repository name of a URL on a public forge, lowercased.
fn forge_repo(url: &str) -> Option<(String, String)> {
    let l = url.to_ascii_lowercase();
    let (_, rest) = ["github.com", "gitlab.com", "bitbucket.org", "codeberg.org"]
        .iter()
        .find_map(|h| l.split_once(h))?;
    let mut parts = rest
        .trim_start_matches([':', '/'])
        .split(['/', '#', '?'])
        .filter(|p| !p.is_empty());
    let owner = parts.next()?.to_string();
    let repo = parts.next()?.trim_end_matches(".git").to_string();
    (!repo.is_empty()).then_some((owner, repo))
}

fn alnum(s: &str) -> String {
    s.chars().filter(char::is_ascii_alphanumeric).collect()
}

/// Whether the package points at a forge repository that names a different project.
///
/// `None` when no URL names a forge repository. A repository matches when its name or
/// owner contains the package name (or an npm scope), or the other way round, after
/// dropping case and punctuation: `psf/requests` matches `requests`, `babel/babel`
/// matches `@babel/helpers`, `python/typeshed` does not match `types-pyyaml`. Starjacking
/// copies a popular project's repository link to borrow its reputation, and a placeholder
/// such as `yourname/yourproject` is left by packages nobody maintains.
pub fn repo_mismatch(name: &str, urls: &[String]) -> Option<bool> {
    let lower = name.to_ascii_lowercase();
    let (scope, base) = match lower.strip_prefix('@').and_then(|s| s.split_once('/')) {
        Some((s, b)) => (Some(alnum(s)), alnum(b)),
        None => (None, alnum(&lower)),
    };
    let names: Vec<&str> = std::iter::once(base.as_str())
        .chain(scope.as_deref())
        .filter(|n| n.len() >= 3)
        .collect();
    let close = |a: &str, n: &str| a.len() >= 3 && (a.contains(n) || n.contains(a));
    let mut seen = false;
    for (owner, repo) in urls.iter().filter_map(|u| forge_repo(u)) {
        seen = true;
        let (o, r) = (alnum(&owner), alnum(&repo));
        if names
            .iter()
            .any(|n| close(&r, n) || (o.len() > 3 && close(&o, n)))
        {
            return Some(false);
        }
    }
    seen.then_some(true)
}

fn count_keywords(s: &str) -> usize {
    if s.contains(',') {
        s.split(',').filter(|k| !k.trim().is_empty()).count()
    } else {
        s.split_whitespace().count()
    }
}

pub fn parse_package_json(text: &str) -> Option<Meta> {
    let v: Value = serde_json::from_str(text.trim_start_matches('\u{feff}')).ok()?;
    let o = v.as_object()?;
    let s = |k: &str| o.get(k).and_then(Value::as_str).map(str::to_string);
    let repo = match o.get("repository") {
        Some(Value::String(s)) => nonempty(s),
        Some(Value::Object(r)) => r.get("url").and_then(Value::as_str).is_some_and(nonempty),
        _ => false,
    };
    let email_in = |v: Option<&Value>| match v {
        Some(Value::String(s)) => s.contains('@'),
        Some(Value::Object(a)) => a.get("email").and_then(Value::as_str).is_some_and(nonempty),
        _ => false,
    };
    let author_email = email_in(o.get("author"))
        || o.get("maintainers")
            .and_then(Value::as_array)
            .is_some_and(|a| a.iter().any(|m| email_in(Some(m))));
    let license = match o.get("license") {
        Some(Value::String(s)) => nonempty(s),
        Some(Value::Object(l)) => l.get("type").and_then(Value::as_str).is_some_and(nonempty),
        _ => o
            .get("licenses")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty()),
    };
    let mut repo_urls = Vec::new();
    for k in ["repository", "homepage", "bugs"] {
        let u = match o.get(k) {
            Some(Value::String(s)) => Some(s.as_str()),
            Some(Value::Object(r)) => r.get("url").and_then(Value::as_str),
            _ => None,
        };
        if let Some(u) = u {
            // npm shorthand: "owner/repo" and "github:owner/repo" mean GitHub.
            let u = u.strip_prefix("github:").unwrap_or(u);
            if k == "repository" && !u.contains(':') && u.matches('/').count() == 1 {
                repo_urls.push(format!("github.com/{u}"));
            } else {
                repo_urls.push(u.to_string());
            }
        }
    }
    let n_deps = o
        .get("dependencies")
        .and_then(Value::as_object)
        .map(|d| d.len())
        .unwrap_or(0);
    let n_keywords = match o.get("keywords") {
        Some(Value::Array(a)) => a.len(),
        Some(Value::String(s)) => count_keywords(s),
        _ => 0,
    };
    Some(Meta {
        name: s("name"),
        version: s("version"),
        description: Some(s("description").unwrap_or_default()),
        homepage: Some(s("homepage").is_some_and(|h| nonempty(&h))),
        repo: Some(repo),
        author_email: Some(author_email),
        license: Some(license),
        n_deps: Some(n_deps),
        n_keywords: Some(n_keywords),
        long_description_bytes: None,
        repo_urls,
    })
}

/// Parse core metadata (`PKG-INFO`, `METADATA`): RFC 822 style headers, then a body.
pub fn parse_core_metadata(text: &str) -> Meta {
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut body_start = None;
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let l = line.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            body_start = Some(offset + line.len());
            break;
        }
        if l.starts_with([' ', '\t']) {
            if let Some(last) = headers.last_mut() {
                last.1.push('\n');
                last.1.push_str(l.trim());
            }
        } else if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
        offset += line.len();
    }
    let get = |k: &str| {
        headers
            .iter()
            .find(|(h, _)| h == k)
            .map(|(_, v)| v.as_str())
    };
    let all = |k: &'static str| {
        headers
            .iter()
            .filter(move |(h, _)| h == k)
            .map(|(_, v)| v.as_str())
    };

    let project_urls: Vec<(String, String)> = all("project-url")
        .filter_map(|v| v.split_once(','))
        .map(|(l, u)| (l.trim().to_ascii_lowercase(), u.trim().to_string()))
        .collect();
    let home_page = get("home-page").filter(|h| nonempty(h));
    let homepage = home_page.is_some()
        || project_urls
            .iter()
            .any(|(l, _)| matches!(l.as_str(), "homepage" | "home" | "home-page"));
    let repo = home_page.is_some_and(is_repo_url)
        || project_urls.iter().any(|(l, u)| {
            ["source", "repository", "code", "github", "gitlab"]
                .iter()
                .any(|k| l.contains(k))
                || is_repo_url(u)
        });
    let author_email =
        get("author-email").is_some_and(nonempty) || get("maintainer-email").is_some_and(nonempty);
    let license = get("license").is_some_and(nonempty)
        || get("license-expression").is_some_and(nonempty)
        || get("license-file").is_some()
        || all("classifier").any(|c| c.starts_with("License ::"));
    let n_deps = all("requires-dist")
        .filter(|d| !d.contains("extra =="))
        .count();
    let n_keywords = get("keywords").map(count_keywords).unwrap_or(0);
    let body_len = body_start
        .map(|s| text.len().saturating_sub(s) as u64)
        .unwrap_or(0);
    let long_desc = if body_len > 0 {
        body_len
    } else {
        get("description").map(|d| d.len() as u64).unwrap_or(0)
    };
    Meta {
        name: get("name").map(str::to_string),
        version: get("version").map(str::to_string),
        description: Some(
            get("summary")
                .filter(|s| nonempty(s))
                .unwrap_or("")
                .to_string(),
        ),
        homepage: Some(homepage),
        repo: Some(repo),
        author_email: Some(author_email),
        license: Some(license),
        n_deps: Some(n_deps),
        n_keywords: Some(n_keywords),
        long_description_bytes: Some(long_desc),
        repo_urls: home_page
            .into_iter()
            .chain(get("download-url"))
            .map(str::to_string)
            .chain(project_urls.iter().map(|(_, u)| u.clone()))
            .collect(),
    }
}

pub fn parse_pyproject(text: &str) -> Option<Meta> {
    let v: toml::Table = text.parse().ok()?;
    let mut meta = Meta::default();
    if let Some(p) = v.get("project").and_then(|p| p.as_table()) {
        let s = |k: &str| p.get(k).and_then(|x| x.as_str()).map(str::to_string);
        let urls = p.get("urls").and_then(|u| u.as_table());
        meta.name = s("name");
        meta.version = s("version");
        meta.description = s("description");
        meta.homepage = Some(urls.is_some_and(|u| {
            u.keys()
                .any(|k| matches!(k.to_ascii_lowercase().as_str(), "homepage" | "home"))
        }));
        meta.repo_urls = urls
            .map(|u| {
                u.values()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        meta.repo = Some(urls.is_some_and(|u| {
            u.iter().any(|(k, val)| {
                let k = k.to_ascii_lowercase();
                k.contains("source")
                    || k.contains("repository")
                    || val.as_str().is_some_and(is_repo_url)
            })
        }));
        let has_email = |key: &str| {
            p.get(key)
                .and_then(|a| a.as_array())
                .is_some_and(|a| a.iter().any(|x| x.get("email").is_some()))
        };
        meta.author_email = Some(has_email("authors") || has_email("maintainers"));
        meta.license = Some(p.get("license").is_some() || p.get("license-files").is_some());
        meta.n_deps = p
            .get("dependencies")
            .and_then(|d| d.as_array())
            .map(|a| a.len());
        meta.n_keywords = p
            .get("keywords")
            .and_then(|k| k.as_array())
            .map(|a| a.len());
    }
    if let Some(po) = v
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.as_table())
    {
        let s = |k: &str| po.get(k).and_then(|x| x.as_str()).map(str::to_string);
        let poetry = Meta {
            name: s("name"),
            version: s("version"),
            description: s("description"),
            homepage: Some(po.get("homepage").is_some()),
            repo: Some(po.get("repository").is_some()),
            author_email: Some(
                po.get("authors")
                    .and_then(|a| a.as_array())
                    .is_some_and(|a| {
                        a.iter()
                            .any(|x| x.as_str().is_some_and(|s| s.contains('@')))
                    }),
            ),
            license: Some(po.get("license").is_some()),
            n_deps: po
                .get("dependencies")
                .and_then(|d| d.as_table())
                .map(|t| t.keys().filter(|k| k.as_str() != "python").count()),
            n_keywords: po
                .get("keywords")
                .and_then(|k| k.as_array())
                .map(|a| a.len()),
            long_description_bytes: None,
            repo_urls: ["repository", "homepage"]
                .iter()
                .filter_map(|k| po.get(*k).and_then(|x| x.as_str()).map(str::to_string))
                .collect(),
        };
        meta.merge(poetry);
    }
    Some(meta)
}

/// Minimal INI reading of `setup.cfg` `[metadata]` and `[options]`.
pub fn parse_setup_cfg(text: &str) -> Meta {
    let mut section = String::new();
    let mut key = String::new();
    let mut kv: Vec<(String, String, String)> = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with('#') || t.starts_with(';') {
            continue;
        }
        if t.starts_with('[') && t.ends_with(']') {
            section = t[1..t.len() - 1].trim().to_ascii_lowercase();
            continue;
        }
        if line.starts_with([' ', '\t']) && !t.is_empty() {
            if let Some(last) = kv.last_mut() {
                if last.1 == key {
                    last.2.push('\n');
                    last.2.push_str(t);
                }
            }
            continue;
        }
        if let Some((k, v)) = t.split_once(['=', ':']) {
            key = k.trim().to_ascii_lowercase().replace('-', "_");
            kv.push((section.clone(), key.clone(), v.trim().to_string()));
        }
    }
    let get = |sec: &str, k: &str| {
        kv.iter()
            .find(|(s, kk, _)| s == sec && kk == k)
            .map(|(_, _, v)| v.as_str())
    };
    let url = get("metadata", "url").or_else(|| get("metadata", "home_page"));
    Meta {
        name: get("metadata", "name").map(str::to_string),
        version: get("metadata", "version")
            .filter(|v| !v.starts_with("attr:") && !v.starts_with("file:"))
            .map(str::to_string),
        description: get("metadata", "description").map(str::to_string),
        homepage: url.map(nonempty),
        repo: Some(
            url.is_some_and(is_repo_url)
                || get("metadata", "project_urls").is_some_and(is_repo_url),
        ),
        author_email: get("metadata", "author_email").map(nonempty),
        license: get("metadata", "license").map(nonempty),
        n_deps: get("options", "install_requires").map(|d| {
            d.split(['\n', ';'])
                .filter(|l| !l.trim().is_empty())
                .count()
        }),
        n_keywords: get("metadata", "keywords").map(count_keywords),
        long_description_bytes: None,
        repo_urls: url
            .into_iter()
            .chain(
                get("metadata", "project_urls")
                    .into_iter()
                    .flat_map(str::lines),
            )
            .map(|l| l.split_once('=').map_or(l, |(_, u)| u).trim().to_string())
            .filter(|u| !u.is_empty())
            .collect(),
    }
}

/// Literal keyword arguments of the `setup(...)` call in `setup.py`. Values computed at
/// runtime are invisible here, which is acceptable: this is the last-resort source.
pub fn parse_setup_py(text: &str) -> Meta {
    let toks: Vec<_> = lex(text, Lang::Python)
        .into_iter()
        .filter(|t| t.kind != TokKind::Newline)
        .collect();
    let mut meta = Meta::default();
    let Some(start) = (0..toks.len()).find(|&i| {
        toks[i].kind == TokKind::Ident
            && toks[i].text == "setup"
            && toks.get(i + 1).is_some_and(|t| t.text == "(")
            && (i == 0 || toks[i - 1].text != "def")
    }) else {
        return meta;
    };
    let mut depth = 0usize;
    let mut i = start + 1;
    while i < toks.len() {
        let t = &toks[i];
        if t.kind == TokKind::Punct {
            match t.text {
                "(" | "[" | "{" => depth += 1,
                ")" | "]" | "}" => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
        }
        let is_kwarg = depth == 1
            && t.kind == TokKind::Ident
            && toks.get(i + 1).is_some_and(|n| n.text == "=");
        if is_kwarg {
            let val = toks.get(i + 2);
            let lit = val
                .filter(|v| v.kind == TokKind::Str)
                .map(|v| v.text.to_string());
            match t.text {
                "name" => meta.name = lit.clone(),
                "version" => meta.version = lit.clone(),
                "description" => meta.description = lit.clone(),
                "url" => meta.homepage = Some(lit.as_deref().is_some_and(nonempty)),
                "author_email" | "maintainer_email" => {
                    if lit.as_deref().is_some_and(nonempty) {
                        meta.author_email = Some(true);
                    }
                }
                "license" => meta.license = Some(lit.as_deref().is_some_and(nonempty)),
                "project_urls" => meta.repo = Some(true),
                "install_requires" | "keywords" => {
                    let n = if val.is_some_and(|v| v.text == "[" || v.text == "(") {
                        let mut d = 0usize;
                        let mut n = 0;
                        for tok in &toks[i + 2..] {
                            match tok.text {
                                "[" | "(" | "{" if tok.kind == TokKind::Punct => d += 1,
                                "]" | ")" | "}" if tok.kind == TokKind::Punct => {
                                    d -= 1;
                                    if d == 0 {
                                        break;
                                    }
                                }
                                _ if tok.kind == TokKind::Str && d == 1 => n += 1,
                                _ => {}
                            }
                        }
                        Some(n)
                    } else {
                        lit.as_deref().map(count_keywords)
                    };
                    if t.text == "keywords" {
                        meta.n_keywords = n;
                    } else {
                        meta.n_deps = n;
                    }
                }
                _ => {}
            }
            if t.text == "url" && lit.as_deref().is_some_and(is_repo_url) {
                meta.repo = Some(true);
            }
            if matches!(t.text, "url" | "download_url") {
                meta.repo_urls.extend(lit);
            }
        }
        i += 1;
    }
    meta
}

/// `(major, minor)` of a version string, tolerating a leading `v` and PEP 440 epochs.
pub fn version_parts(v: &str) -> (Option<u64>, Option<u64>) {
    let v = v.trim().trim_start_matches(['v', 'V']);
    let v = v.split_once('!').map(|(_, r)| r).unwrap_or(v);
    let mut it = v.split(['.', '-', '+']);
    let num = |s: Option<&str>| {
        s.and_then(|p| {
            let digits: String = p.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse().ok()
        })
    };
    let major = num(it.next());
    let minor = num(it.next());
    (major, minor)
}

/// Best-effort `(name, version)` from an archive file name.
pub fn name_version_from_filename(filename: &str) -> (Option<String>, Option<String>) {
    let base = filename.rsplit(['/', '\\']).next().unwrap_or(filename);
    let lower = base.to_ascii_lowercase();
    let stem_len = [".tar.gz", ".tar.bz2", ".tgz", ".zip", ".whl", ".tar"]
        .iter()
        .find(|e| lower.ends_with(*e))
        .map(|e| base.len() - e.len());
    let Some(stem_len) = stem_len else {
        return (None, None);
    };
    let mut stem = &base[..stem_len];
    if lower.ends_with(".whl") {
        let mut parts = stem.split('-');
        return (
            parts.next().map(str::to_string),
            parts.next().map(str::to_string),
        );
    }
    // Sample collections name files `YYYY-MM-DD-name-vX.Y`.
    let sb = stem.as_bytes();
    if sb.len() > 11
        && sb[..10].iter().enumerate().all(|(i, b)| {
            if i == 4 || i == 7 {
                *b == b'-'
            } else {
                b.is_ascii_digit()
            }
        })
        && sb[10] == b'-'
    {
        stem = &stem[11..];
    }
    // Versions start with a digit (or `v` and a digit) right after a hyphen; names may
    // contain hyphens.
    let b = stem.as_bytes();
    for i in 0..b.len().saturating_sub(1) {
        if b[i] != b'-' {
            continue;
        }
        if b[i + 1].is_ascii_digit() {
            return (Some(stem[..i].to_string()), Some(stem[i + 1..].to_string()));
        }
        if b[i + 1] == b'v' && b.get(i + 2).is_some_and(u8::is_ascii_digit) {
            return (Some(stem[..i].to_string()), Some(stem[i + 2..].to_string()));
        }
    }
    (Some(stem.to_string()), None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_mismatch() {
        let m = |name: &str, urls: &[&str]| {
            let urls: Vec<String> = urls.iter().map(|u| u.to_string()).collect();
            repo_mismatch(name, &urls)
        };
        assert_eq!(
            m("requests", &["https://github.com/psf/requests"]),
            Some(false)
        );
        assert_eq!(
            m(
                "python-dateutil",
                &["git+https://github.com/dateutil/dateutil.git"]
            ),
            Some(false)
        );
        assert_eq!(
            m("@babel/helpers", &["https://github.com/babel/babel.git"]),
            Some(false)
        );
        assert_eq!(
            m("dagit", &["https://github.com/dagster-io/dagster"]),
            Some(true)
        );
        assert_eq!(
            m("trustwallet", &["https://github.com/psf/requests"]),
            Some(true)
        );
        assert_eq!(
            m("web3x", &["https://github.com/yourusername/yourproject"]),
            Some(true)
        );
        // Any matching URL clears it; a docs site is not a forge repository.
        assert_eq!(
            m(
                "dagit",
                &[
                    "https://github.com/dagster-io/dagster",
                    "https://github.com/x/dagit"
                ]
            ),
            Some(false)
        );
        assert_eq!(m("requests", &["https://requests.readthedocs.io"]), None);
        assert_eq!(m("requests", &[]), None);
        assert_eq!(m("requests", &["https://github.com/psf"]), None);

        let pj = parse_package_json(
            r#"{"name":"x-tool","repository":"psf/requests","bugs":{"url":"https://github.com/psf/requests/issues"}}"#,
        )
        .unwrap();
        assert_eq!(
            pj.repo_urls,
            [
                "github.com/psf/requests",
                "https://github.com/psf/requests/issues"
            ]
        );
        assert_eq!(repo_mismatch("x-tool", &pj.repo_urls), Some(true));
        let core = parse_core_metadata(
            "Name: types-pyyaml\nHome-page: https://github.com/python/typeshed\nProject-URL: Source, https://github.com/python/typeshed\n\nbody",
        );
        assert_eq!(core.repo_urls.len(), 2);
        let cfg = parse_setup_cfg(
            "[metadata]\nname = x\nproject_urls =\n    Source = https://github.com/a/b\n",
        );
        assert_eq!(cfg.repo_urls, ["https://github.com/a/b"]);
    }

    #[test]
    fn package_json() {
        let m = parse_package_json(
            r#"{"name":"left-pad","version":"1.3.0","description":"pad","homepage":"https://x",
               "repository":{"type":"git","url":"git+https://github.com/a/b.git"},
               "author":"A <a@b.c>","license":"MIT","dependencies":{"x":"1","y":"2"},
               "keywords":["pad","left"]}"#,
        )
        .unwrap();
        assert_eq!(m.name.as_deref(), Some("left-pad"));
        assert_eq!(m.homepage, Some(true));
        assert_eq!(m.repo, Some(true));
        assert_eq!(m.author_email, Some(true));
        assert_eq!(m.license, Some(true));
        assert_eq!(m.n_deps, Some(2));
        assert_eq!(m.n_keywords, Some(2));
        assert!(parse_package_json("not json").is_none());
    }

    #[test]
    fn core_metadata() {
        let m = parse_core_metadata(
            "Metadata-Version: 2.1\nName: foo\nVersion: 0.0.1\nSummary: A thing\nHome-page: https://github.com/a/foo\nAuthor-email: a@b.c\nLicense: MIT\nKeywords: a,b,c\nRequires-Dist: requests>=2\nRequires-Dist: pytest; extra == \"test\"\n\nLong description\nhere\n",
        );
        assert_eq!(m.name.as_deref(), Some("foo"));
        assert_eq!(m.version.as_deref(), Some("0.0.1"));
        assert_eq!(m.description.as_deref(), Some("A thing"));
        assert_eq!(m.homepage, Some(true));
        assert_eq!(m.repo, Some(true));
        assert_eq!(m.n_deps, Some(1));
        assert_eq!(m.n_keywords, Some(3));
        assert_eq!(m.long_description_bytes, Some(22));
    }

    #[test]
    fn pyproject() {
        let m = parse_pyproject(
            "[project]\nname = \"bar\"\nversion = \"2.0\"\ndependencies = [\"a\", \"b\"]\nkeywords = [\"k\"]\nlicense = {text = \"MIT\"}\nauthors = [{name = \"x\", email = \"x@y.z\"}]\n[project.urls]\nSource = \"https://github.com/x/bar\"\n",
        )
        .unwrap();
        assert_eq!(m.name.as_deref(), Some("bar"));
        assert_eq!(m.n_deps, Some(2));
        assert_eq!(m.repo, Some(true));
        assert_eq!(m.author_email, Some(true));
        assert_eq!(m.license, Some(true));
    }

    #[test]
    fn setup_py_kwargs() {
        let m = parse_setup_py(
            "from setuptools import setup\n# setup(name='nope')\nsetup(\n    name='baz',\n    version=\"1.2.3\",\n    install_requires=['a', 'b>=1', \"c\"],\n    keywords='x y',\n    url='https://github.com/q/baz',\n    author_email=EMAIL,\n)\n",
        );
        assert_eq!(m.name.as_deref(), Some("baz"));
        assert_eq!(m.version.as_deref(), Some("1.2.3"));
        assert_eq!(m.n_deps, Some(3));
        assert_eq!(m.n_keywords, Some(2));
        assert_eq!(m.repo, Some(true));
        assert_eq!(m.author_email, None);
    }

    #[test]
    fn setup_cfg() {
        let m = parse_setup_cfg(
            "[metadata]\nname = qux\nversion = 0.1\nlicense = BSD\n[options]\ninstall_requires =\n    a\n    b\n",
        );
        assert_eq!(m.name.as_deref(), Some("qux"));
        assert_eq!(m.n_deps, Some(2));
        assert_eq!(m.license, Some(true));
    }

    #[test]
    fn versions_and_filenames() {
        assert_eq!(version_parts("v99.1.0"), (Some(99), Some(1)));
        assert_eq!(version_parts("1!2.0"), (Some(2), Some(0)));
        assert_eq!(version_parts("0.0.1rc1"), (Some(0), Some(0)));
        assert_eq!(
            name_version_from_filename("my-pkg-1.0.0.tar.gz"),
            (Some("my-pkg".into()), Some("1.0.0".into()))
        );
        assert_eq!(
            name_version_from_filename("foo_bar-2.1-py3-none-any.whl"),
            (Some("foo_bar".into()), Some("2.1".into()))
        );
        assert_eq!(
            name_version_from_filename("left-pad-1.3.0.tgz"),
            (Some("left-pad".into()), Some("1.3.0".into()))
        );
        assert_eq!(
            name_version_from_filename("2023-05-03-1337test-v1.2.zip"),
            (Some("1337test".into()), Some("1.2".into()))
        );
    }
}
