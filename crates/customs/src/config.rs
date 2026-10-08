//! Policy configuration (`customs.toml`, DESIGN.md section 8).
//!
//! The same structure is read from TOML at startup and from JSON on `PUT /api/policy`, and
//! both paths run [`Policy::validate`], so a bad value is rejected with the key that holds
//! it instead of surfacing later as odd behavior.

use std::fmt;
use std::path::{Path, PathBuf};

use customs_model::Decision;
use customs_scan::Ecosystem;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::util::{ecosystem_str, normalize_name, parse_ecosystem};

/// A configuration problem, tied to the key that caused it.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigError {
    /// Dotted path of the offending key (`upstream.npm`, `allow[2]`), empty for syntax errors.
    pub key: String,
    pub message: String,
}

impl ConfigError {
    fn new(key: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.key.is_empty() {
            write!(f, "{}", self.message)
        } else {
            write!(f, "invalid value for `{}`: {}", self.key, self.message)
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Block artifacts whose verdict is `block`.
    #[default]
    Enforce,
    /// Record verdicts but serve every artifact.
    Monitor,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Enforce => "enforce",
            Mode::Monitor => "monitor",
        }
    }
}

/// `"model"` (use the thresholds shipped in `ensemble.json`) or a fixed probability.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum Threshold {
    #[default]
    Model,
    Value(f64),
}

impl Serialize for Threshold {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Threshold::Model => s.serialize_str("model"),
            Threshold::Value(v) => s.serialize_f64(*v),
        }
    }
}

impl<'de> Deserialize<'de> for Threshold {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Str(String),
            Num(f64),
        }
        match Repr::deserialize(d)? {
            Repr::Str(s) if s == "model" => Ok(Threshold::Model),
            Repr::Str(s) => Err(serde::de::Error::custom(format!(
                "expected \"model\" or a number between 0 and 1, got \"{s}\""
            ))),
            Repr::Num(v) => Ok(Threshold::Value(v)),
        }
    }
}

/// Severity for the `min_age_days` rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AgeSeverity {
    Warn,
    #[default]
    Block,
}

impl AgeSeverity {
    pub fn decision(&self) -> Decision {
        match self {
            AgeSeverity::Warn => Decision::Warn,
            AgeSeverity::Block => Decision::Block,
        }
    }
}

/// Severity of a rule that can also be switched off (the release history rules).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSeverity {
    Off,
    Warn,
    Block,
}

impl RuleSeverity {
    /// The decision a hit carries, or `None` when the rule is off.
    pub fn decision(&self) -> Option<Decision> {
        match self {
            RuleSeverity::Off => None,
            RuleSeverity::Warn => Some(Decision::Warn),
            RuleSeverity::Block => Some(Decision::Block),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    #[serde(default = "default_pypi_simple")]
    pub pypi_simple: String,
    #[serde(default = "default_pypi_files")]
    pub pypi_files: String,
    #[serde(default = "default_pypi_json")]
    pub pypi_json: String,
    #[serde(default = "default_npm")]
    pub npm: String,
}

fn default_pypi_simple() -> String {
    "https://pypi.org/simple".into()
}
fn default_pypi_files() -> String {
    "https://files.pythonhosted.org".into()
}
fn default_pypi_json() -> String {
    "https://pypi.org/pypi".into()
}
fn default_npm() -> String {
    "https://registry.npmjs.org".into()
}

impl Default for Upstream {
    fn default() -> Self {
        Self {
            pypi_simple: default_pypi_simple(),
            pypi_files: default_pypi_files(),
            pypi_json: default_pypi_json(),
            npm: default_npm(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_min_age() -> u32 {
    3
}
fn default_warn() -> RuleSeverity {
    RuleSeverity::Warn
}
fn default_block() -> RuleSeverity {
    RuleSeverity::Block
}
fn default_off() -> RuleSeverity {
    RuleSeverity::Off
}
fn default_dormant_days() -> u32 {
    365
}
fn default_young_dependency_days() -> u32 {
    7
}

/// The active policy. Field names and defaults follow DESIGN.md section 8.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub warn_threshold: Threshold,
    #[serde(default)]
    pub block_threshold: Threshold,
    /// Versions published fewer than this many days ago hit `min_age_days`; 0 disables.
    #[serde(default = "default_min_age")]
    pub min_age_days: u32,
    /// Severity of a `min_age_days` hit. With `warn`, `block_install_scripts_from_new` is
    /// what turns a young package with install scripts into a block.
    #[serde(default)]
    pub min_age_severity: AgeSeverity,
    /// Hold back the versions `min_age_days` would block: leave them out of npm packuments
    /// and mark their files yanked on PyPI simple pages, so an unpinned install resolves to
    /// the newest version old enough instead of failing (enforce mode with a blocking
    /// `min_age_days` only).
    #[serde(default = "default_true")]
    pub hide_young_versions: bool,
    #[serde(default = "default_true")]
    pub block_nonexistent: bool,
    #[serde(default = "default_true")]
    pub block_install_scripts_from_new: bool,
    // Release history rules: compare the requested version with the releases published
    // before it to catch compromised releases of established packages. They are heuristics
    // with known false positives (CI changes, new native builds, new maintainers), so most
    // warn by default and the model still judges the archive itself. `install_script_added`
    // blocks: it fired on 0.02% of legitimate npm releases and on at least 37% of
    // compromised ones (DESIGN.md section 8).
    /// npm and PyPI: this version has no provenance attestation but the previous release had
    /// one.
    #[serde(default = "default_warn")]
    pub provenance_dropped: RuleSeverity,
    /// npm: this version adds an install script or changes its command.
    #[serde(default = "default_block")]
    pub install_script_added: RuleSeverity,
    /// npm: this version was published by an account that published none of the previous
    /// five releases.
    #[serde(default = "default_warn")]
    pub publisher_changed: RuleSeverity,
    /// The previous release is more than `dormant_days` older than this version.
    #[serde(default = "default_warn")]
    pub dormant_revival: RuleSeverity,
    #[serde(default = "default_dormant_days")]
    pub dormant_days: u32,
    /// Jumps of more than one major version, and releases on an old major line that had
    /// been quiet for `dormant_days` while a newer major exists.
    #[serde(default = "default_off")]
    pub version_anomaly: RuleSeverity,
    /// npm: this version adds a dependency fetched from git, a URL or a local path, which
    /// npm installs without asking the registry (and so without passing the proxy).
    #[serde(default = "default_block")]
    pub nonregistry_dependency_added: RuleSeverity,
    /// npm: this version adds a dependency first published fewer than
    /// `young_dependency_days` before it, by accounts that do not maintain this package, or a
    /// dependency the registry does not know.
    #[serde(default = "default_block")]
    pub young_dependency_added: RuleSeverity,
    #[serde(default = "default_young_dependency_days")]
    pub young_dependency_days: u32,
    /// The archive holds code the scanner could not read: a code file or manifest over
    /// the 32 MiB per-file cap, an encrypted entry or one compressed with a method the
    /// scanner lacks, or install-time code (an npm install hook, an sdist build, a wheel
    /// `.pth`) in an archive above the scan size limit. The installer runs it, but no rule
    /// or model saw its content. None of the 22,258 benign archives in the corpus has
    /// any, while padding `setup.py` past the cap hides any payload.
    #[serde(default = "default_block")]
    pub unread_code: RuleSeverity,
    /// The scanner rejected the archive (more than 20,000 entries or 256 MiB unpacked, an
    /// archive bomb, a corrupt or unknown format), so the model never saw its code. None
    /// of 22,258 benign archives in the corpus is rejected, while 20,001 empty files are
    /// enough to make any package unscannable.
    #[serde(default = "default_block")]
    pub scan_error: RuleSeverity,
    /// A `.pth` file on the install surface launches a process, connects, downloads or
    /// reads secrets. Python runs it at every interpreter start. 19 malicious archives in
    /// the corpus have one (among them litellm 1.82.8, which the model scored 0.09) and no
    /// benign archive does: benign `.pth` files extend `sys.path` or switch on a feature.
    #[serde(default = "default_block")]
    pub startup_hook: RuleSeverity,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub upstream: Upstream,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            mode: Mode::Enforce,
            warn_threshold: Threshold::Model,
            block_threshold: Threshold::Model,
            min_age_days: default_min_age(),
            min_age_severity: AgeSeverity::Block,
            hide_young_versions: true,
            block_nonexistent: true,
            block_install_scripts_from_new: true,
            provenance_dropped: default_warn(),
            install_script_added: default_block(),
            publisher_changed: default_warn(),
            dormant_revival: default_warn(),
            dormant_days: default_dormant_days(),
            version_anomaly: default_off(),
            nonregistry_dependency_added: default_block(),
            young_dependency_added: default_block(),
            young_dependency_days: default_young_dependency_days(),
            unread_code: default_block(),
            scan_error: default_block(),
            startup_hook: default_block(),
            allow: Vec::new(),
            deny: Vec::new(),
            upstream: Upstream::default(),
        }
    }
}

/// A parsed `allow`/`deny` entry: `eco:name`, `eco:name@version`, or `eco:name==version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRule {
    pub ecosystem: Ecosystem,
    /// Normalized name.
    pub name: String,
    pub version: Option<String>,
}

impl PackageRule {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (eco, rest) = s
            .split_once(':')
            .ok_or_else(|| format!("'{s}' should look like 'pypi:<name>' or 'npm:<name>'"))?;
        let ecosystem = parse_ecosystem(eco.trim())
            .ok_or_else(|| format!("'{s}': unknown ecosystem '{eco}' (use pypi or npm)"))?;
        let rest = rest.trim();
        let (name, version) = if let Some((n, v)) = rest.split_once("==") {
            (n, Some(v))
        } else {
            // The last '@' after position 0 separates a version; position 0 is an npm scope.
            match rest.rfind('@') {
                Some(i) if i > 0 => (&rest[..i], Some(&rest[i + 1..])),
                _ => (rest, None),
            }
        };
        let name = name.trim();
        if name.is_empty() || name.contains(char::is_whitespace) {
            return Err(format!("'{s}': missing or invalid package name"));
        }
        let version = version.map(str::trim).filter(|v| !v.is_empty());
        Ok(Self {
            ecosystem,
            name: normalize_name(ecosystem, name),
            version: version.map(str::to_string),
        })
    }

    pub fn matches(&self, eco: Ecosystem, normalized: &str, version: Option<&str>) -> bool {
        self.ecosystem == eco
            && self.name == normalized
            && match (&self.version, version) {
                (None, _) => true,
                (Some(v), Some(w)) => v == w,
                (Some(_), None) => false,
            }
    }
}

impl fmt::Display for PackageRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", ecosystem_str(self.ecosystem), self.name)?;
        if let Some(v) = &self.version {
            write!(f, "@{v}")?;
        }
        Ok(())
    }
}

fn check_url(key: &str, v: &str) -> Result<(), ConfigError> {
    let u = url::Url::parse(v)
        .map_err(|e| ConfigError::new(key, format!("'{v}' is not a URL: {e}")))?;
    if !matches!(u.scheme(), "http" | "https") {
        return Err(ConfigError::new(
            key,
            format!("'{v}' must be an http or https URL"),
        ));
    }
    Ok(())
}

impl Policy {
    /// Parse TOML text and validate it.
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let p: Policy = toml::from_str(text).map_err(|e| {
            // toml's message already names the key and shows the offending line.
            ConfigError::new("", e.to_string().trim_end().to_string())
        })?;
        p.validated()
    }

    /// Parse a JSON body (the `PUT /api/policy` shape) and validate it.
    pub fn from_json(text: &str) -> Result<Self, ConfigError> {
        let p: Policy =
            serde_json::from_str(text).map_err(|e| ConfigError::new("", e.to_string()))?;
        p.validated()
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::new("", format!("cannot read {}: {e}", path.display())))?;
        Self::from_toml(&text).map_err(|e| ConfigError {
            key: e.key,
            message: format!("{}: {}", path.display(), e.message),
        })
    }

    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }

    /// Check every value and normalize URLs (no trailing slash).
    pub fn validated(mut self) -> Result<Self, ConfigError> {
        let prob = |key: &str, t: Threshold| -> Result<Option<f64>, ConfigError> {
            match t {
                Threshold::Model => Ok(None),
                Threshold::Value(v) if (0.0..=1.0).contains(&v) => Ok(Some(v)),
                Threshold::Value(v) => Err(ConfigError::new(
                    key,
                    format!("{v} is outside [0, 1]; use \"model\" or a probability"),
                )),
            }
        };
        let w = prob("warn_threshold", self.warn_threshold)?;
        let b = prob("block_threshold", self.block_threshold)?;
        if let (Some(w), Some(b)) = (w, b) {
            if w > b {
                return Err(ConfigError::new(
                    "warn_threshold",
                    format!("warn_threshold {w} is above block_threshold {b}"),
                ));
            }
        }
        if self.min_age_days > 3650 {
            return Err(ConfigError::new("min_age_days", "must be at most 3650"));
        }
        if !(1..=3650).contains(&self.dormant_days) {
            return Err(ConfigError::new(
                "dormant_days",
                "must be between 1 and 3650 (set dormant_revival = \"off\" to disable)",
            ));
        }
        if !(1..=365).contains(&self.young_dependency_days) {
            return Err(ConfigError::new(
                "young_dependency_days",
                "must be between 1 and 365 (set young_dependency_added = \"off\" to disable)",
            ));
        }
        for (list, key) in [(&self.allow, "allow"), (&self.deny, "deny")] {
            for (i, entry) in list.iter().enumerate() {
                PackageRule::parse(entry)
                    .map_err(|m| ConfigError::new(format!("{key}[{i}]"), m))?;
            }
        }
        for (key, v) in [
            ("upstream.pypi_simple", &mut self.upstream.pypi_simple),
            ("upstream.pypi_files", &mut self.upstream.pypi_files),
            ("upstream.pypi_json", &mut self.upstream.pypi_json),
            ("upstream.npm", &mut self.upstream.npm),
        ] {
            check_url(key, v)?;
            while v.ends_with('/') {
                v.pop();
            }
        }
        Ok(self)
    }

    /// Whether a release history rule that applies to PyPI is on. Those rules need the
    /// project document, which the proxy otherwise does not read.
    pub fn pypi_history_rules_enabled(&self) -> bool {
        self.dormant_revival != RuleSeverity::Off
            || self.version_anomaly != RuleSeverity::Off
            || self.provenance_dropped != RuleSeverity::Off
    }

    pub fn allow_rules(&self) -> Vec<PackageRule> {
        self.allow
            .iter()
            .filter_map(|s| PackageRule::parse(s).ok())
            .collect()
    }

    pub fn deny_rules(&self) -> Vec<PackageRule> {
        self.deny
            .iter()
            .filter_map(|s| PackageRule::parse(s).ok())
            .collect()
    }
}

/// Where the policy came from and where `PUT /api/policy` writes it.
#[derive(Debug, Clone)]
pub struct PolicySource {
    pub path: PathBuf,
    /// Whether `path` existed when the server started.
    pub loaded: bool,
}

/// Resolve the policy file: an explicit `--config` must exist; otherwise `./customs.toml`,
/// then `<data_dir>/policy.toml`, and if neither exists the defaults are used and later
/// edits are saved to `<data_dir>/policy.toml`.
pub fn resolve_policy(
    explicit: Option<&Path>,
    data_dir: &Path,
) -> Result<(Policy, PolicySource), ConfigError> {
    if let Some(p) = explicit {
        let policy = Policy::load(p)?;
        return Ok((
            policy,
            PolicySource {
                path: p.to_path_buf(),
                loaded: true,
            },
        ));
    }
    for candidate in [PathBuf::from("customs.toml"), data_dir.join("policy.toml")] {
        if candidate.exists() {
            let policy = Policy::load(&candidate)?;
            return Ok((
                policy,
                PolicySource {
                    path: candidate,
                    loaded: true,
                },
            ));
        }
    }
    Ok((
        Policy::default(),
        PolicySource {
            path: data_dir.join("policy.toml"),
            loaded: false,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
mode = "enforce"
warn_threshold = "model"
block_threshold = 0.95
min_age_days = 3
block_nonexistent = true
block_install_scripts_from_new = true
allow = ["pypi:requests", "npm:react"]
deny  = ["npm:event-stream@3.3.6"]
[upstream]
pypi_simple = "https://pypi.org/simple/"
pypi_files = "https://files.pythonhosted.org"
pypi_json = "https://pypi.org/pypi"
npm = "https://registry.npmjs.org"
"#;

    #[test]
    fn parses_design_example() {
        let p = Policy::from_toml(EXAMPLE).unwrap();
        assert_eq!(p.mode, Mode::Enforce);
        assert_eq!(p.warn_threshold, Threshold::Model);
        assert_eq!(p.block_threshold, Threshold::Value(0.95));
        assert_eq!(p.upstream.pypi_simple, "https://pypi.org/simple");
        assert_eq!(p.deny_rules()[0].version.as_deref(), Some("3.3.6"));
        // Round trip through TOML and JSON.
        assert_eq!(Policy::from_toml(&p.to_toml()).unwrap(), p);
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(Policy::from_json(&json).unwrap(), p);
    }

    #[test]
    fn defaults_when_empty() {
        let p = Policy::from_toml("").unwrap();
        assert_eq!(p, Policy::default());
    }

    #[test]
    fn errors_name_the_key() {
        let e = Policy::from_toml("min_age = 3").unwrap_err();
        assert!(e.message.contains("min_age"), "{e}");
        let e = Policy::from_toml("warn_threshold = 1.5").unwrap_err();
        assert_eq!(e.key, "warn_threshold");
        let e = Policy::from_toml("block_threshold = \"high\"").unwrap_err();
        assert!(e.to_string().contains("block_threshold"), "{e}");
        let e = Policy::from_toml("allow = [\"pypi:ok\", \"cargo:serde\"]").unwrap_err();
        assert_eq!(e.key, "allow[1]");
        let e = Policy::from_toml("[upstream]\nnpm = \"ftp://x\"").unwrap_err();
        assert_eq!(e.key, "upstream.npm");
        let e = Policy::from_toml("mode = \"strict\"").unwrap_err();
        assert!(e.to_string().contains("mode"), "{e}");
        let e = Policy::from_toml("warn_threshold = 0.9\nblock_threshold = 0.5").unwrap_err();
        assert_eq!(e.key, "warn_threshold");
        let e = Policy::from_json(r#"{"mode": "monitor", "bogus": 1}"#).unwrap_err();
        assert!(e.message.contains("bogus"), "{e}");
    }

    #[test]
    fn release_history_keys() {
        let p = Policy::default();
        assert_eq!(p.provenance_dropped, RuleSeverity::Warn);
        assert_eq!(p.install_script_added, RuleSeverity::Block);
        assert_eq!(p.publisher_changed, RuleSeverity::Warn);
        assert_eq!(p.dormant_revival, RuleSeverity::Warn);
        assert_eq!(p.dormant_days, 365);
        assert_eq!(p.version_anomaly, RuleSeverity::Off);
        assert!(p.pypi_history_rules_enabled());

        let p = Policy::from_toml(
            "provenance_dropped = \"block\"\ninstall_script_added = \"off\"\n\
             publisher_changed = \"warn\"\ndormant_revival = \"off\"\ndormant_days = 730\n\
             version_anomaly = \"off\"",
        )
        .unwrap();
        assert_eq!(p.provenance_dropped, RuleSeverity::Block);
        assert_eq!(p.provenance_dropped.decision(), Some(Decision::Block));
        assert_eq!(p.install_script_added.decision(), None);
        assert_eq!(p.dormant_days, 730);
        // provenance_dropped applies to PyPI too.
        assert!(p.pypi_history_rules_enabled());
        let mut q = p.clone();
        q.provenance_dropped = RuleSeverity::Off;
        assert!(!q.pypi_history_rules_enabled());
        assert_eq!(Policy::from_toml(&p.to_toml()).unwrap(), p);
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["provenance_dropped"], "block");
        assert_eq!(json["install_script_added"], "off");
        let p = Policy::from_json(r#"{"version_anomaly": "warn", "dormant_days": 90}"#).unwrap();
        assert_eq!(p.version_anomaly, RuleSeverity::Warn);

        assert_eq!(p.nonregistry_dependency_added, RuleSeverity::Block);
        assert_eq!(p.young_dependency_added, RuleSeverity::Block);
        assert_eq!(p.unread_code, RuleSeverity::Block);
        assert_eq!(p.scan_error, RuleSeverity::Block);
        assert_eq!(p.startup_hook, RuleSeverity::Block);
        assert_eq!(Policy::default().young_dependency_days, 7);
        let e = Policy::from_toml("young_dependency_days = 0").unwrap_err();
        assert_eq!(e.key, "young_dependency_days");
        let e = Policy::from_toml("dormant_days = 0").unwrap_err();
        assert_eq!(e.key, "dormant_days");
        let e = Policy::from_json(r#"{"dormant_days": 5000}"#).unwrap_err();
        assert_eq!(e.key, "dormant_days");
        let e = Policy::from_toml("publisher_changed = \"maybe\"").unwrap_err();
        assert!(e.to_string().contains("publisher_changed"), "{e}");
        let e = Policy::from_toml("provenance_dropped = true").unwrap_err();
        assert!(e.to_string().contains("provenance_dropped"), "{e}");
    }

    #[test]
    fn package_rules() {
        let r = PackageRule::parse("npm:@Scope/Pkg@1.0.0").unwrap();
        assert_eq!(r.name, "@scope/pkg");
        assert_eq!(r.version.as_deref(), Some("1.0.0"));
        let r = PackageRule::parse("npm:@scope/pkg").unwrap();
        assert_eq!(r.version, None);
        let r = PackageRule::parse("pypi:Python_DateUtil==2.8.2").unwrap();
        assert_eq!(r.name, "python-dateutil");
        assert!(r.matches(Ecosystem::Pypi, "python-dateutil", Some("2.8.2")));
        assert!(!r.matches(Ecosystem::Pypi, "python-dateutil", Some("2.9.0")));
        assert!(PackageRule::parse("requests").is_err());
        assert!(PackageRule::parse("pypi:").is_err());
    }
}
