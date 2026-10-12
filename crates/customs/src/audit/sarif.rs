//! SARIF 2.1.0 output for GitHub code scanning: one result per warned or blocked package,
//! located at the lockfile line that pins it.

use std::path::Path;

use customs_model::Decision;
use serde_json::{json, Value};

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

use super::{display_path, normalize, top_reasons, Finding, Outcome, Report};
use crate::util::ecosystem_str;
use crate::verdict::Verdict;

const INFORMATION_URI: &str = "https://github.com/yib7/customs";
const SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

struct Rule {
    id: String,
    name: String,
    short: String,
    full: String,
    level: &'static str,
}

/// Rule metadata. Policy rule ids from `policy.rs` and `engine.rs` get their own rules;
/// an id this table does not know still gets a generic one.
fn rule(id: &str) -> Rule {
    let (name, short, full, level) = match id {
        "customs/model-block" => (
            "MaliciousPackageBlocked",
            "Malware classifier blocks this package",
            "The Customs malware classifier scored this package archive above the block threshold.",
            "error",
        ),
        "customs/model-warn" => (
            "SuspiciousPackageWarned",
            "Malware classifier flags this package for review",
            "The Customs malware classifier scored this package archive above the warn threshold.",
            "warning",
        ),
        "customs/nonexistent-package" => (
            "NonexistentPackage",
            "Package does not exist on the registry",
            "The pinned name is unknown to the registry: possibly a hallucinated or mistyped name that an attacker could register.",
            "error",
        ),
        "customs/deny-list" => (
            "DeniedPackage",
            "Package is on the deny list",
            "The package (or this version of it) is on the deny list in customs.toml.",
            "error",
        ),
        "customs/min-age" => (
            "PackageTooNew",
            "Version is newer than the minimum age",
            "This version was published more recently than min_age_days allows; most malicious uploads are removed within days.",
            "error",
        ),
        "customs/install-scripts-from-new-package" => (
            "InstallScriptsFromNewPackage",
            "Young package runs install scripts",
            "A package younger than min_age_days declares npm preinstall, install, or postinstall scripts.",
            "error",
        ),
        "customs/scan-error" => (
            "UnscannableArchive",
            "Package archive could not be scanned",
            "The scanner rejected the archive, so the malware classifier could not inspect its code.",
            "warning",
        ),
        "customs/not-scanned" => (
            "NotScanned",
            "Package archive was not scanned",
            "The archive is above the scan size limit, so the malware classifier did not inspect its code. The policy allows such archives unless a rule says otherwise.",
            "note",
        ),
        "customs/min-age-resolution" => (
            "MinAgeResolution",
            "Resolved to an older release because of the minimum age",
            "The newest matching release is younger than min_age_days, so Customs resolved the request to an older release.",
            "note",
        ),
        "customs/install-script-added" => (
            "InstallScriptAdded",
            "Release added or changed an install script",
            "This version adds an npm preinstall, install, or postinstall script, or changes its command, compared with the previous release. Account takeovers usually ship their payload this way.",
            "error",
        ),
        "customs/nonregistry-dependency-added" => (
            "NonRegistryDependencyAdded",
            "Release added a dependency from outside the registry",
            "This version adds a git, URL, or local-path dependency. npm fetches it without the registry, so no registry-side check sees its code.",
            "error",
        ),
        "customs/young-dependency-added" => (
            "YoungDependencyAdded",
            "Release added a brand-new dependency",
            "This version adds a dependency first published days before it by accounts that do not maintain the package, or one the registry does not know. Hijacked releases pull in their payload this way.",
            "error",
        ),
        "customs/provenance-dropped" => (
            "ProvenanceDropped",
            "Release dropped its provenance attestation",
            "This version has no provenance attestation, but the previous release had one. A release published with a stolen token, rather than from the project's CI, usually loses its provenance.",
            "warning",
        ),
        "customs/publisher-changed" => (
            "PublisherChanged",
            "Release published by a new account",
            "The npm account that published this version published none of the previous five releases. Account takeovers and hostile handovers show up this way.",
            "warning",
        ),
        "customs/dormant-revival" => (
            "DormantRevival",
            "First release after a long dormancy",
            "The previous release is older than dormant_days. Abandoned packages taken over by someone else often publish their first release in years.",
            "warning",
        ),
        "customs/version-anomaly" => (
            "VersionAnomaly",
            "Unusual version number",
            "The major version jumps by more than one, or the release extends an old major line that saw no release for dormant_days while a newer one exists, which reaches users who pin the old range.",
            "warning",
        ),
        "customs/lockfile-mismatch" => (
            "LockfileResolvedMismatch",
            "Lockfile installs a different package than it names",
            "The lockfile entry's resolved URL is a registry tarball of another package or version, or not a tarball at all. npm installs from that URL, so the dependency named here is not the code that gets installed.",
            "error",
        ),
        "customs/unread-code" => (
            "UnreadCode",
            "Package ships code the scanner could not read",
            "The archive holds code the scanner could not read: a code file or manifest above the 32 MiB per-file limit, an encrypted entry or one compressed with an unsupported method, or install-time code in an archive above the scan size limit. The installer runs it, but no rule or model inspected it; padding or re-encoding a payload this way is an evasion.",
            "error",
        ),
        "customs/startup-hook" => (
            "StartupHook",
            "Package installs a file that runs code at every Python start",
            "A .pth file, sitecustomize.py or usercustomize.py in the package launches a process, opens a connection, downloads, or reads secrets. Python executes it whenever any interpreter starts, so the code keeps running long after the install.",
            "error",
        ),
        "customs/hidden-code" => (
            "HiddenInstallCode",
            "Install-time code is hidden from the scanner's model inputs",
            "Code that runs at install, import or interpreter start reads one way to Python or Node and another to the scanner's feature lexers: it follows a bare carriage return or a Unicode line separator, a backslash-CRLF continuation, sits inside a Python f-string field, is imported past a byte-order mark, or installs as a top-level package from a wheel's .data directory. That code launches a process, connects, downloads, runs dynamic code or reads secrets.",
            "error",
        ),
        "customs/agent-bypass" => (
            "AgentPermissionBypass",
            "Install-time code runs an AI coding agent with its permission checks off",
            "Code that runs during install passes a flag such as --dangerously-skip-permissions, --yolo or --trust-all-tools to an AI coding CLI, so the agent on the developer's machine acts on the package's prompt without asking. The s1ngularity compromise of Nx used this to have the developer's own agents search the disk for secrets.",
            "error",
        ),
        "customs/unpinned-mcp-server" => (
            "UnpinnedMcpServer",
            "MCP server starts a package without a pinned version",
            "An agent configuration starts this MCP server with npx, uvx or a similar launcher and no exact version, so each start fetches the newest release. The current release passed Customs, but a compromised release would run at the next start without review. Pin an exact version.",
            "note",
        ),
        "customs/unavailable" => (
            "UnavailableVersion",
            "Pinned version is not available on the registry",
            "The registry has no installable files for the pinned version; it may have been removed.",
            "warning",
        ),
        "customs/unchecked-source" => (
            "UncheckedSource",
            "Dependency is fetched from a source Customs did not check",
            "The entry installs code from a git repository, a URL, a custom package index or a launcher Customs does not recognize, so no verdict covers it. Check where it comes from, or install it from the public registry.",
            "note",
        ),
        _ => ("", "", "", "warning"),
    };
    if name.is_empty() {
        let rule = id.trim_start_matches("customs/");
        return Rule {
            id: id.to_string(),
            name: rule.split('-').map(capitalize).collect(),
            short: format!("Customs policy rule {rule}"),
            full: format!("The Customs policy rule {rule} fired for this package."),
            level,
        };
    }
    Rule {
        id: id.to_string(),
        name: name.into(),
        short: short.into(),
        full: full.into(),
        level,
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_ascii_uppercase().to_string() + c.as_str())
        .unwrap_or_default()
}

/// SARIF rule id for a policy rule (`block_nonexistent` -> `customs/nonexistent-package`).
fn policy_rule_id(rule: &str) -> String {
    match rule {
        "deny" => "customs/deny-list".into(),
        "block_nonexistent" => "customs/nonexistent-package".into(),
        "min_age_days" => "customs/min-age".into(),
        "block_install_scripts_from_new" => "customs/install-scripts-from-new-package".into(),
        "scan_error" => "customs/scan-error".into(),
        other => format!("customs/{}", other.replace('_', "-")),
    }
}

/// The rule a verdict is reported under: the most specific reason for its decision.
fn primary_rule(v: &Verdict) -> String {
    let hit = |rule: &str| {
        v.policy_hits
            .iter()
            .any(|h| h.rule == rule && h.severity == v.decision)
    };
    for r in ["deny", "block_nonexistent"] {
        if hit(r) {
            return policy_rule_id(r);
        }
    }
    if v.model_decision == v.decision {
        return if v.decision == Decision::Block {
            "customs/model-block".into()
        } else {
            "customs/model-warn".into()
        };
    }
    let order = [
        "agent_bypass",
        "startup_hook",
        "hidden_code",
        "unread_code",
        "block_install_scripts_from_new",
        "min_age_days",
        "scan_error",
    ];
    let pick = order
        .iter()
        .find(|r| hit(r))
        .map(|r| r.to_string())
        .or_else(|| {
            v.policy_hits
                .iter()
                .find(|h| h.severity == v.decision)
                .map(|h| h.rule.clone())
        });
    match pick {
        Some(r) => policy_rule_id(&r),
        None if v.decision == Decision::Block => "customs/model-block".into(),
        None => "customs/model-warn".into(),
    }
}

fn level(d: Decision) -> &'static str {
    match d {
        Decision::Block => "error",
        _ => "warning",
    }
}

/// (rule id, level, message) for a finding that becomes a result.
fn describe(f: &Finding) -> Option<(String, &'static str, String)> {
    let label = f.dep.label();
    match &f.outcome {
        Outcome::Checked { verdict, .. } if verdict.decision >= Decision::Warn => {
            let risk = verdict
                .risk
                .map(|r| format!("risk {r:.2}"))
                .unwrap_or_else(|| "risk n/a".into());
            let action = if verdict.decision == Decision::Block {
                "blocked"
            } else {
                "flagged for review"
            };
            let mut msg = format!("{label} is {action} by Customs ({risk})");
            let reasons = top_reasons(verdict, 3);
            if !reasons.is_empty() {
                msg.push_str(&format!(": {}", reasons.join("; ")));
            }
            msg.push('.');
            Some((primary_rule(verdict), level(verdict.decision), msg))
        }
        Outcome::Checked { verdict, .. } if !f.dep.pinned => Some((
            "customs/unpinned-mcp-server".into(),
            "note",
            format!(
                "{label}: this MCP server runs the newest release at every start (now {}); pin an exact version.",
                verdict.version.as_deref().unwrap_or("unknown")
            ),
        )),
        Outcome::Mismatch(m) => Some((
            "customs/lockfile-mismatch".into(),
            "error",
            format!("{label}: {m}."),
        )),
        Outcome::Unavailable(m) => Some((
            "customs/unavailable".into(),
            "warning",
            format!("{label} could not be checked: {m}."),
        )),
        _ => None,
    }
}

/// Characters a URI path segment cannot carry as they are.
const SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

/// A file inside the working directory is a relative URI under `%SRCROOT%`; one outside it
/// is a `file://` URI, since `%SRCROOT%` cannot reach it.
fn artifact_location(file: &Path, cwd: &Path) -> Value {
    let shown = display_path(file, cwd);
    let encoded = || {
        shown
            .split('/')
            .map(|seg| utf8_percent_encode(seg, SEGMENT).to_string())
            .collect::<Vec<_>>()
            .join("/")
    };
    if Path::new(&shown).is_absolute() || shown.starts_with('/') {
        return match url::Url::from_file_path(normalize(&cwd.join(file))) {
            Ok(u) => json!({ "uri": u.as_str() }),
            Err(()) => json!({ "uri": encoded() }),
        };
    }
    json!({ "uri": encoded(), "uriBaseId": "%SRCROOT%" })
}

/// Severity order of SARIF levels.
fn rank(level: &str) -> u8 {
    match level {
        "error" => 3,
        "warning" => 2,
        "note" => 1,
        _ => 0,
    }
}

pub fn to_sarif(report: &Report, cwd: &Path) -> Value {
    let mut rule_ids: Vec<String> = vec!["customs/model-block".into(), "customs/model-warn".into()];
    // The most severe level each rule's results reach: a rule configured above its default
    // severity is rated by what it reports.
    let mut strongest: Vec<&'static str> = vec!["note", "note"];
    let mut results = Vec::new();
    for f in &report.findings {
        let Some((rule_id, lvl, message)) = describe(f) else {
            continue;
        };
        let index = match rule_ids.iter().position(|r| *r == rule_id) {
            Some(i) => i,
            None => {
                rule_ids.push(rule_id.clone());
                strongest.push("note");
                rule_ids.len() - 1
            }
        };
        if rank(lvl) > rank(strongest[index]) {
            strongest[index] = lvl;
        }
        let eco = ecosystem_str(f.dep.ecosystem);
        let verdict = match &f.outcome {
            Outcome::Checked { verdict, url } => Some((verdict, url)),
            _ => None,
        };
        let mut properties = json!({
            "ecosystem": eco,
            "package": f.dep.name,
            "version": f.dep.version,
        });
        if let Some((v, url)) = verdict {
            properties["decision"] = json!(v.decision.as_str());
            properties["risk"] = json!(v.risk);
            properties["modelVersion"] = json!(v.model_version);
            properties["policyRules"] =
                json!(v.policy_hits.iter().map(|h| &h.rule).collect::<Vec<_>>());
            if let Some(u) = url {
                properties["verdictUrl"] = json!(u);
            }
        }
        results.push(json!({
            "ruleId": rule_id,
            "ruleIndex": index,
            "level": lvl,
            "message": { "text": message },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": artifact_location(&f.dep.file, cwd),
                    "region": { "startLine": f.dep.line },
                }
            }],
            "partialFingerprints": {
                "customsPackage/v1": format!("{eco}/{}/{}", f.dep.name, f.dep.version),
            },
            "properties": properties,
        }));
    }
    // Entries that fetch code nothing checked; the project's own files and unpinned ranges
    // are left out. Notes, so `--fail-on` is unaffected.
    for k in report.skipped.iter().filter(|k| k.fetched()) {
        let rule_id = "customs/unchecked-source";
        let index = match rule_ids.iter().position(|r| r == rule_id) {
            Some(i) => i,
            None => {
                rule_ids.push(rule_id.into());
                strongest.push("note");
                rule_ids.len() - 1
            }
        };
        results.push(json!({
            "ruleId": rule_id,
            "ruleIndex": index,
            "level": "note",
            "message": { "text": format!("{} was not checked: {}.", k.spec, k.reason) },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": artifact_location(&k.file, cwd),
                    "region": { "startLine": k.line },
                }
            }],
            "partialFingerprints": {
                "customsPackage/v1": format!("unchecked/{}", k.spec),
            },
        }));
    }
    let rules: Vec<Value> = rule_ids
        .iter()
        .zip(&strongest)
        .map(|(id, seen)| {
            let r = rule(id);
            let rated = if rank(seen) > rank(r.level) {
                *seen
            } else {
                r.level
            };
            json!({
                "id": r.id,
                "name": r.name,
                "shortDescription": { "text": r.short },
                "fullDescription": { "text": r.full },
                "helpUri": format!("{INFORMATION_URI}/blob/main/docs/github-action.md"),
                "help": { "text": if r.id == "customs/unchecked-source" {
                    r.full.clone()
                } else {
                    format!("{} Review the package before installing it; to accept it, add it to `allow` in customs.toml.", r.full)
                } },
                "defaultConfiguration": { "level": r.level },
                "properties": {
                    "tags": ["security", "supply-chain"],
                    "precision": if rated == "error" { "high" } else { "medium" },
                    "security-severity": match rated {
                        "error" => "9.0",
                        "warning" => "5.0",
                        _ => "2.0",
                    },
                },
            })
        })
        .collect();
    let failures: Vec<Value> = report
        .errors
        .iter()
        .map(|e| {
            json!({
                "level": "error",
                "message": { "text": format!("could not read {e}") },
            })
        })
        .chain(report.findings.iter().filter_map(|f| match &f.outcome {
            Outcome::Failed(m) => Some(json!({
                "level": "error",
                "message": { "text": format!("checking {} failed: {m}", f.dep.label()) },
            })),
            _ => None,
        }))
        .collect();
    json!({
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Customs",
                    "informationUri": INFORMATION_URI,
                    "version": env!("CARGO_PKG_VERSION"),
                    "semanticVersion": env!("CARGO_PKG_VERSION"),
                    "rules": rules,
                }
            },
            "invocations": [{
                "executionSuccessful": failures.is_empty(),
                "toolExecutionNotifications": failures,
            }],
            "results": results,
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::super::tests::{checked, finding, verdict};
    use super::*;
    use crate::audit::{Dependency, SkipKind, Skipped};
    use std::path::PathBuf;

    #[test]
    fn sarif_shape() {
        let report = Report {
            files: vec![PathBuf::from("sub/requirements.txt")],
            findings: vec![
                finding("ok", 1, checked(verdict("ok", Decision::Allow, None))),
                finding("evil", 2, checked(verdict("evil", Decision::Block, None))),
                finding(
                    "nope",
                    3,
                    checked(verdict("nope", Decision::Block, Some("block_nonexistent"))),
                ),
                finding("sus", 4, checked(verdict("sus", Decision::Warn, None))),
                finding(
                    "young",
                    5,
                    checked(verdict("young", Decision::Warn, Some("min_age_days"))),
                ),
                finding(
                    "odd",
                    6,
                    checked(verdict("odd", Decision::Warn, Some("future_rule"))),
                ),
                finding("gone", 7, Outcome::Unavailable("no version 1.0.0".into())),
                finding("err", 8, Outcome::Failed("timeout".into())),
                finding("swap", 9, Outcome::Mismatch("lockfile installs x".into())),
            ],
            skipped: vec![],
            errors: vec![],
            via: "test".into(),
        };
        let s = to_sarif(&report, Path::new("/work"));
        assert_eq!(s["version"], "2.1.0");
        assert!(s["$schema"].as_str().unwrap().contains("sarif-2.1.0"));
        let runs = s["runs"].as_array().unwrap();
        assert_eq!(runs.len(), 1);
        let run = &runs[0];
        let driver = &run["tool"]["driver"];
        assert_eq!(driver["name"], "Customs");
        assert_eq!(driver["informationUri"], "https://github.com/yib7/customs");
        let rules = driver["rules"].as_array().unwrap();
        let ids: Vec<&str> = rules.iter().map(|r| r["id"].as_str().unwrap()).collect();
        assert_eq!(
            ids,
            vec![
                "customs/model-block",
                "customs/model-warn",
                "customs/nonexistent-package",
                "customs/min-age",
                "customs/future-rule",
                "customs/unavailable",
                "customs/lockfile-mismatch",
            ]
        );
        for r in rules {
            for k in [
                "id",
                "name",
                "shortDescription",
                "fullDescription",
                "defaultConfiguration",
            ] {
                assert!(!r[k].is_null(), "rule missing {k}: {r}");
            }
            assert!(!r["shortDescription"]["text"].as_str().unwrap().is_empty());
        }
        assert_eq!(rules[4]["name"], "FutureRule");

        let results = run["results"].as_array().unwrap();
        assert_eq!(results.len(), 7, "allow and failed checks are not results");
        let expect = [
            ("customs/model-block", "error", 2, "evil"),
            ("customs/nonexistent-package", "error", 3, "nope"),
            ("customs/model-warn", "warning", 4, "sus"),
            ("customs/min-age", "warning", 5, "young"),
            ("customs/future-rule", "warning", 6, "odd"),
            ("customs/unavailable", "warning", 7, "gone"),
            ("customs/lockfile-mismatch", "error", 9, "swap"),
        ];
        for (res, (rule, lvl, line, name)) in results.iter().zip(expect) {
            assert_eq!(res["ruleId"], rule);
            assert_eq!(res["level"], lvl);
            let idx = res["ruleIndex"].as_u64().unwrap() as usize;
            assert_eq!(rules[idx]["id"], rule);
            let text = res["message"]["text"].as_str().unwrap();
            assert!(text.contains(name), "{text}");
            let loc = &res["locations"][0]["physicalLocation"];
            assert_eq!(loc["artifactLocation"]["uri"], "sub/requirements.txt");
            assert_eq!(loc["region"]["startLine"], line);
            assert_eq!(
                res["partialFingerprints"]["customsPackage/v1"],
                format!("pypi/{name}/1.0.0")
            );
        }
        let evil = results[0]["message"]["text"].as_str().unwrap();
        assert!(evil.contains("risk 0.97"), "{evil}");
        assert!(evil.contains("Downloads and executes a payload"), "{evil}");
        assert!(results[1]["message"]["text"]
            .as_str()
            .unwrap()
            .contains("block_nonexistent fired"));

        let inv = &run["invocations"][0];
        assert_eq!(inv["executionSuccessful"], false);
        assert_eq!(
            inv["toolExecutionNotifications"].as_array().unwrap().len(),
            1
        );
    }

    #[test]
    fn git_entries_become_notes() {
        let skip = |line: usize, spec: &str, kind: SkipKind| Skipped {
            file: PathBuf::from("requirements.txt"),
            line,
            spec: spec.into(),
            kind,
            reason: "installed from a URL or VCS".into(),
        };
        let report = Report {
            files: vec![PathBuf::from("requirements.txt")],
            findings: vec![],
            skipped: vec![
                skip(1, "git+https://github.com/x/y.git", SkipKind::Source),
                skip(2, "flask>=2", SkipKind::Unpinned),
                skip(3, "./lib", SkipKind::Local),
                skip(4, "corp-tool==1.0", SkipKind::CustomIndex),
            ],
            errors: vec![],
            via: "test".into(),
        };
        let s = to_sarif(&report, Path::new("/work"));
        let run = &s["runs"][0];
        let results = run["results"].as_array().unwrap();
        // Code fetched from somewhere Customs did not check; not the project's own files
        // or ranges a resolver pins later.
        let got: Vec<(&str, &str, u64)> = results
            .iter()
            .map(|r| {
                (
                    r["ruleId"].as_str().unwrap(),
                    r["level"].as_str().unwrap(),
                    r["locations"][0]["physicalLocation"]["region"]["startLine"]
                        .as_u64()
                        .unwrap(),
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("customs/unchecked-source", "note", 1),
                ("customs/unchecked-source", "note", 4)
            ]
        );
        assert!(results[0]["message"]["text"]
            .as_str()
            .unwrap()
            .contains("git+https://github.com/x/y.git"));
        assert_eq!(
            results[1]["partialFingerprints"]["customsPackage/v1"],
            "unchecked/corp-tool==1.0"
        );
        let idx = results[0]["ruleIndex"].as_u64().unwrap() as usize;
        let r = &run["tool"]["driver"]["rules"][idx];
        assert_eq!(r["name"], "UncheckedSource");
        // Notes never fail the build.
        assert_eq!(report.exit_code(super::super::FailOn::Warn), 0);
    }

    #[test]
    fn paths_outside_the_root_are_file_uris() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let far = outside.path().join("my dir").join("req#1.txt");
        let report = Report {
            files: vec![],
            findings: vec![
                Finding {
                    dep: Dependency {
                        file: far.clone(),
                        ..finding("a", 1, Outcome::Mismatch("x".into())).dep
                    },
                    outcome: Outcome::Mismatch("x".into()),
                },
                Finding {
                    dep: Dependency {
                        file: PathBuf::from("sub dir/requirements 100%.txt"),
                        ..finding("b", 2, Outcome::Mismatch("x".into())).dep
                    },
                    outcome: Outcome::Mismatch("x".into()),
                },
            ],
            skipped: vec![],
            errors: vec![],
            via: "test".into(),
        };
        let s = to_sarif(&report, root.path());
        let loc = |i: usize| {
            s["runs"][0]["results"][i]["locations"][0]["physicalLocation"]["artifactLocation"]
                .clone()
        };
        let far_loc = loc(0);
        let uri = far_loc["uri"].as_str().unwrap();
        assert!(uri.starts_with("file:///"), "{uri}");
        assert!(uri.ends_with("/my%20dir/req%231.txt"), "{uri}");
        assert_eq!(url::Url::parse(uri).unwrap().to_file_path().unwrap(), far);
        assert!(far_loc.get("uriBaseId").is_none(), "{far_loc}");
        let near = loc(1);
        assert_eq!(near["uri"], "sub%20dir/requirements%20100%25.txt");
        assert_eq!(near["uriBaseId"], "%SRCROOT%");
    }

    #[test]
    fn every_policy_rule_has_metadata() {
        // Every rule policy.rs and engine.rs can report, except the allow-only `allow` and
        // `established`.
        for policy in [
            "deny",
            "block_nonexistent",
            "min_age_days",
            "block_install_scripts_from_new",
            "install_script_added",
            "nonregistry_dependency_added",
            "provenance_dropped",
            "publisher_changed",
            "dormant_revival",
            "young_dependency_added",
            "version_anomaly",
            "scan_error",
            "not_scanned",
            "unread_code",
            "startup_hook",
            "agent_bypass",
            "min_age_resolution",
        ] {
            let r = rule(&policy_rule_id(policy));
            assert!(
                !r.short.starts_with("Customs policy rule"),
                "{policy} has no SARIF metadata"
            );
        }
    }

    #[test]
    fn security_severity_follows_the_strongest_result() {
        // provenance_dropped warns by default; configured to block, its alerts are errors.
        let report = Report {
            files: vec![PathBuf::from("package-lock.json")],
            findings: vec![finding(
                "x",
                1,
                checked(verdict("x", Decision::Block, Some("provenance_dropped"))),
            )],
            skipped: vec![],
            errors: vec![],
            via: "test".into(),
        };
        let s = to_sarif(&report, Path::new("/work"));
        let run = &s["runs"][0];
        let result = &run["results"][0];
        assert_eq!(result["ruleId"], "customs/provenance-dropped");
        assert_eq!(result["level"], "error");
        let idx = result["ruleIndex"].as_u64().unwrap() as usize;
        let r = &run["tool"]["driver"]["rules"][idx];
        assert_eq!(r["defaultConfiguration"]["level"], "warning");
        assert_eq!(r["properties"]["security-severity"], "9.0");
    }

    #[test]
    fn rule_ids_for_policy_rules() {
        assert_eq!(policy_rule_id("deny"), "customs/deny-list");
        for (policy, name) in [
            ("install_script_added", "InstallScriptAdded"),
            ("nonregistry_dependency_added", "NonRegistryDependencyAdded"),
            ("young_dependency_added", "YoungDependencyAdded"),
            ("agent_bypass", "AgentPermissionBypass"),
        ] {
            let r = rule(&policy_rule_id(policy));
            assert_eq!(r.name, name);
            assert_eq!(r.level, "error");
        }
        assert_eq!(
            policy_rule_id("block_install_scripts_from_new"),
            "customs/install-scripts-from-new-package"
        );
        let mut v = verdict("x", Decision::Block, Some("min_age_days"));
        v.policy_hits.push(crate::verdict::PolicyHit {
            rule: "block_install_scripts_from_new".into(),
            severity: Decision::Block,
            detail: "runs install scripts".into(),
        });
        assert_eq!(primary_rule(&v), "customs/install-scripts-from-new-package");
        v.policy_hits.push(crate::verdict::PolicyHit {
            rule: "agent_bypass".into(),
            severity: Decision::Block,
            detail: "telemetry.js:4: --yolo".into(),
        });
        assert_eq!(primary_rule(&v), "customs/agent-bypass");
        v.policy_hits.push(crate::verdict::PolicyHit {
            rule: "deny".into(),
            severity: Decision::Block,
            detail: "denied".into(),
        });
        assert_eq!(primary_rule(&v), "customs/deny-list");
    }
}
