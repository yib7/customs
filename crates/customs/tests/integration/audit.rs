//! `customs audit`: lockfiles and MCP configurations checked package by package.

use super::*;

/// Run the real binary's `audit` in `cwd`.
fn run_audit(cwd: &std::path::Path, args: &[&str]) -> (String, String, i32) {
    let o = customs_cmd(&cwd.join("audit-data"), None)
        .arg("audit")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap();
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
        o.status.code().unwrap_or(-1),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_audit_checks_packages_mcp_configs_launch() {
    let h = Harness::start(|_| {}).await;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(
        d.join(".mcp.json"),
        r#"{
  "mcpServers": {
    "mail": { "command": "npx", "args": ["-y", "evil-js"] },
    "lib": { "command": "npx", "args": ["-y", "@scope/lib@1.2.3"] },
    "remote": { "type": "http", "url": "https://mcp.example/mcp" }
  }
}
"#,
    )
    .unwrap();
    std::fs::create_dir_all(d.join(".cursor")).unwrap();
    std::fs::write(
        d.join(".cursor/mcp.json"),
        r#"{"mcpServers": {"fetch": {"command": "uvx", "args": ["goodpkg"]}}}"#,
    )
    .unwrap();
    let base = h.base.clone();
    let cwd = d.to_path_buf();
    let out = tokio::task::spawn_blocking(move || {
        let srv = ["--server", base.as_str()];
        vec![
            run_audit(&cwd, &[&["--format", "json"], &srv[..]].concat()),
            run_audit(&cwd, &[&[".mcp.json"], &srv[..]].concat()),
            run_audit(
                &cwd,
                &[&["--format", "sarif", "-o", "out.sarif"], &srv[..]].concat(),
            ),
        ]
    })
    .await
    .unwrap();

    let (json_out, err, code) = &out[0];
    assert_eq!(*code, 1, "{err}");
    let v: Value = serde_json::from_str(json_out).unwrap();
    let mut got: Vec<(String, String, bool, String, String)> = v["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["file"].as_str().unwrap().to_string(),
                r["name"].as_str().unwrap().to_string(),
                r["pinned"].as_bool().unwrap(),
                r["resolved_version"].as_str().unwrap_or("").to_string(),
                r["status"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    got.sort();
    let row = |f: &str, n: &str, p: bool, ver: &str, st: &str| {
        (f.into(), n.into(), p, ver.into(), st.into())
    };
    assert_eq!(
        got,
        vec![
            row(".cursor/mcp.json", "goodpkg", false, "1.1.0", "allow"),
            row(".mcp.json", "@scope/lib", true, "1.2.3", "allow"),
            row(".mcp.json", "evil-js", false, "6.6.6", "block"),
        ],
        "{json_out}"
    );

    let (text, err, code) = &out[1];
    assert_eq!(*code, 1, "{err}");
    assert!(
        text.contains("MCP servers without a pinned version"),
        "{text}"
    );
    assert!(
        text.contains(".mcp.json:3  npm evil-js (latest, now 6.6.6)  block"),
        "{text}"
    );

    // SARIF: the block as an error, the allowed unpinned server as a note.
    assert_eq!(out[2].2, 1, "{}", out[2].1);
    let sarif: Value =
        serde_json::from_str(&std::fs::read_to_string(d.join("out.sarif")).unwrap()).unwrap();
    let mut results: Vec<(String, String, String)> = sarif["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                r["ruleId"].as_str().unwrap().to_string(),
                r["level"].as_str().unwrap().to_string(),
                r["properties"]["package"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    results.sort();
    assert_eq!(results.len(), 2, "{results:?}");
    assert_eq!(
        results[1],
        (
            "customs/unpinned-mcp-server".into(),
            "note".into(),
            "goodpkg".into()
        )
    );
    assert_eq!(results[0].1, "error");
    assert_eq!(results[0].2, "evil-js");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_audit_reports_lockfile_findings() {
    let h = Harness::start(|_| {}).await;
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::write(
        d.join("requirements.txt"),
        "# deps\ngoodpkg==1.0.0\nnope-not-here==1.0.0\nevilpkg==0.0.1 \\\n    --hash=sha256:00\nflask>=2\n-e .\n",
    )
    .unwrap();
    std::fs::create_dir_all(d.join("web")).unwrap();
    std::fs::write(
        d.join("web/package-lock.json"),
        r#"{
  "name": "web",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "web"},
    "node_modules/@scope/lib": {"version": "1.2.3"},
    "node_modules/a/node_modules/@scope/lib": {"version": "1.2.3"}
  }
}
"#,
    )
    .unwrap();
    // In-process fallback: no server answers, and the registry is the local mock.
    let cfg = d.join("offline.toml");
    std::fs::write(
        &cfg,
        format!(
            "[upstream]\npypi_simple = \"{b}/simple\"\npypi_files = \"{b}/files\"\npypi_json = \"{b}/pypi\"\nnpm = \"{b}/npm\"\n",
            b = h.mock.base
        ),
    )
    .unwrap();
    let offline = tempfile::tempdir().unwrap();
    std::fs::write(
        offline.path().join("requirements.txt"),
        "nope-not-here==1.0.0\n",
    )
    .unwrap();
    std::fs::write(
        offline.path().join("package-lock.json"),
        r#"{"lockfileVersion": 3, "packages": {"": {}}}"#,
    )
    .unwrap();

    let base = h.base.clone();
    let cwd = d.to_path_buf();
    let off = offline.path().to_path_buf();
    let models = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../models/dev");
    let out = tokio::task::spawn_blocking(move || {
        let srv = ["--server", base.as_str()];
        let cfg = cfg.display().to_string();
        let models = models.display().to_string();
        vec![
            run_audit(
                &cwd,
                &[&["-r", "--format", "sarif", "-o", "out.sarif"], &srv[..]].concat(),
            ),
            run_audit(
                &cwd,
                &[&[".", "--format", "json", "--fail-on", "never"], &srv[..]].concat(),
            ),
            run_audit(&cwd, &[&["--recursive"], &srv[..]].concat()),
            run_audit(
                &off,
                &[
                    "requirements.txt",
                    "--format",
                    "json",
                    "--server",
                    "http://127.0.0.1:9",
                    "--config",
                    &cfg,
                    "--models",
                    &models,
                ],
            ),
            run_audit(&off, &["package-lock.json", "--format", "json"]),
            run_audit(&off, &["missing.lock"]),
            run_audit(&cwd, &["offline.toml"]),
        ]
    })
    .await
    .unwrap();

    // SARIF: exit 1 (a block), results at the lockfile lines.
    let (_, err, code) = &out[0];
    assert_eq!(*code, 1, "{err}");
    let sarif: Value =
        serde_json::from_str(&std::fs::read_to_string(d.join("out.sarif")).unwrap()).unwrap();
    let run = &sarif["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "Customs");
    let results = run["results"].as_array().unwrap();
    let found: Vec<(&str, &str, u64)> = results
        .iter()
        .map(|r| {
            let loc = &r["locations"][0]["physicalLocation"];
            (
                r["ruleId"].as_str().unwrap(),
                loc["artifactLocation"]["uri"].as_str().unwrap(),
                loc["region"]["startLine"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        found,
        vec![
            ("customs/nonexistent-package", "requirements.txt", 3),
            ("customs/model-block", "requirements.txt", 4),
        ],
        "{results:?}"
    );
    assert!(results.iter().all(|r| r["level"] == "error"));
    assert_eq!(
        results[1]["partialFingerprints"]["customsPackage/v1"],
        "pypi/evilpkg/0.0.1"
    );

    // JSON, not recursive: only requirements.txt; --fail-on never exits 0.
    let (stdout, err, code) = &out[1];
    assert_eq!(*code, 0, "{err}");
    let j: Value = serde_json::from_str(stdout).unwrap();
    assert_eq!(j["files"], json!(["requirements.txt"]));
    assert_eq!(j["summary"]["packages"], 3);
    assert_eq!(j["summary"]["block"], 2);
    assert_eq!(j["summary"]["allow"], 1);
    assert_eq!(j["summary"]["not_checked"], 2);
    assert_eq!(j["results"][0]["name"], "goodpkg");
    assert_eq!(j["results"][0]["status"], "allow");
    assert_eq!(j["results"][1]["status"], "block");
    assert!(j["via"].as_str().unwrap().starts_with("server "));

    // Text: a summary line and a table of the packages that are not allowed.
    let (stdout, err, code) = &out[2];
    assert_eq!(*code, 1, "{err}");
    assert!(
        stdout.starts_with("Audited 4 packages from 2 lockfiles"),
        "{stdout}"
    );
    assert!(
        stdout.contains("2 block, 0 warn, 2 allow, 2 not checked"),
        "{stdout}"
    );
    assert!(stdout.contains("BLOCK"), "{stdout}");
    assert!(stdout.contains("requirements.txt:4"), "{stdout}");
    assert!(!stdout.contains("@scope/lib"), "{stdout}");

    // In-process against the mock registry.
    let (stdout, err, code) = &out[3];
    assert_eq!(*code, 1, "{err}");
    let j: Value = serde_json::from_str(stdout).unwrap();
    assert_eq!(j["via"], "in-process");
    assert_eq!(j["results"][0]["status"], "block");
    assert!(j["results"][0]["reason"]
        .as_str()
        .unwrap()
        .contains("block_nonexistent"));

    // Nothing to check: no checker is built, exit 0.
    let (stdout, err, code) = &out[4];
    assert_eq!(*code, 0, "{err}");
    let j: Value = serde_json::from_str(stdout).unwrap();
    assert_eq!(j["summary"]["packages"], 0);
    assert_eq!(j["via"], "nothing to check");

    // Usage errors.
    assert_eq!(out[5].2, 2, "{}", out[5].1);
    assert!(out[5].1.contains("no such file"), "{}", out[5].1);
    assert_eq!(out[6].2, 2, "{}", out[6].1);
    assert!(out[6].1.contains("not a lockfile"), "{}", out[6].1);
    h.stop().await;
}

#[test]
fn cli_audit_lists_what_it_can_read_past_a_broken_config() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    // Nothing pinned, so nothing is checked and no registry is needed.
    std::fs::write(d.join("requirements.txt"), "flask>=2\n").unwrap();
    std::fs::create_dir_all(d.join(".gemini")).unwrap();
    std::fs::write(d.join(".gemini/settings.json"), "{ \"mcpServers\": ").unwrap();
    std::fs::create_dir_all(d.join(".vscode")).unwrap();
    std::fs::write(
        d.join(".vscode/mcp.json"),
        "{\n  // comments are allowed here\n  \"servers\": {\"x\": {\"command\": \"weird-launcher\"},},\n}\n",
    )
    .unwrap();
    let (stdout, err, code) = run_audit(d, &[]);
    // An unreadable file leaves the audit incomplete: exit 2, but the rest is reported.
    assert_eq!(code, 2, "{stdout}\n{err}");
    assert!(err.contains(".gemini"), "{err}");
    assert!(stdout.contains("1 unreadable file"), "{stdout}");
    assert!(stdout.contains("Could not read"), "{stdout}");
    assert!(stdout.contains("requirements.txt:1  flask>=2"), "{stdout}");
    assert!(stdout.contains("launcher not recognized"), "{stdout}");
}
