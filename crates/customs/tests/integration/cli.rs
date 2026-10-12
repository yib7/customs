//! The `customs` commands other than `hook`, `audit` and `mcp`: `check` and `diff` against a
//! running server or in-process, `serve` startup errors, and `doctor`.

use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn check_resolves_versions() {
    let h = Harness::start(|_| {}).await;
    let (s, v) = h.check("pypi", "goodpkg", None).await;
    assert_eq!(s, 200);
    assert_eq!(v["version"], "1.1.0");
    let (_, v) = h.check("pypi", "goodpkg", Some("<1.1")).await;
    assert_eq!(v["version"], "1.0.0");
    let (_, v) = h.check("pypi", "goodpkg", Some("==1.0.0")).await;
    assert_eq!(v["version"], "1.0.0");
    let (s, v) = h.check("pypi", "goodpkg", Some(">=9")).await;
    assert_eq!(s, 422, "{v}");
    let (_, v) = h.check("npm", "@scope/lib", Some("^1")).await;
    assert_eq!(v["version"], "1.2.3");
    assert_eq!(v["decision"], "allow");
    let (s, _) = h.check("cargo", "serde", None).await;
    assert_eq!(s, 400);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cli_check_uses_running_server() {
    let h = Harness::start(|_| {}).await;
    let base = h.base.clone();
    let data = tempfile::tempdir().unwrap();
    let (data_dir, registry) = (data.path().to_path_buf(), h.mock.base.clone());
    let out = tokio::task::spawn_blocking(move || {
        let run = |args: &[&str]| {
            let o = customs_cmd(&data_dir, Some(&registry))
                .args(args)
                .args(["--server", &base])
                .output()
                .unwrap();
            (
                String::from_utf8_lossy(&o.stdout).into_owned(),
                o.status.code().unwrap(),
            )
        };
        vec![
            run(&["check", "pypi", "evilpkg==0.0.1"]),
            run(&["check", "npm:@scope/lib@1.2.3", "--json"]),
            run(&["check", "pypi", "nope-not-here"]),
        ]
    })
    .await
    .unwrap();
    assert_eq!(out[0].1, 3, "{}", out[0].0);
    assert!(
        out[0].0.starts_with("pypi evilpkg 0.0.1  BLOCK"),
        "{}",
        out[0].0
    );
    // The server answered, not an in-process fallback.
    assert!(
        out[0].0.contains(&format!(", server {})", h.base)),
        "{}",
        out[0].0
    );
    assert_eq!(out[1].1, 0);
    let v: Value = serde_json::from_str(&out[1].0).unwrap();
    assert_eq!(v["name"], "@scope/lib");
    assert_eq!(out[2].1, 3, "{}", out[2].0);
    assert!(out[2].0.contains("block_nonexistent"));
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn diff_shows_what_a_release_adds() {
    let h = Harness::start(|_| {}).await;
    let d: Value = h
        .get("/api/diff?ecosystem=npm&name=diffpkg")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(
        (&d["from"]["version"], &d["to"]["version"]),
        (&json!("1.0.0"), &json!("1.0.1"))
    );
    assert_eq!(
        d["dependencies"],
        json!([{"name": "lure-dep", "before": null, "after": "^0.0.1"}])
    );
    assert_eq!(
        d["metadata"],
        json!([{"field": "install script postinstall", "before": null, "after": "node setup.js"}])
    );
    let paths = |k: &str| -> Vec<String> {
        d["files"][k]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["path"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(paths("added"), vec!["setup.js"], "{d}");
    assert_eq!(paths("modified"), vec!["index.js", "package.json"], "{d}");
    assert_eq!(paths("removed"), vec!["old.js"], "{d}");
    assert_eq!(d["files"]["unchanged"], 1);
    assert_eq!(d["files"]["modified"][0]["lines_added"], 1);
    assert_eq!(d["new_evidence"][0]["indicator"], "download_exec");
    assert_eq!(d["verdict"]["decision"], "block");

    let r = h
        .get("/api/diff?ecosystem=npm&name=diffpkg&from=1.0.1&to=1.0.1")
        .await;
    assert_eq!(r.status(), 422);
    let r = h.get("/api/diff?ecosystem=npm&name=no-such-pkg").await;
    assert_eq!(r.status(), 404);

    let base = h.base.clone();
    let data = tempfile::tempdir().unwrap();
    let (data_dir, registry) = (data.path().to_path_buf(), h.mock.base.clone());
    let (out, code) = tokio::task::spawn_blocking(move || {
        let o = customs_cmd(&data_dir, Some(&registry))
            .args(["diff", "npm", "diffpkg@1.0.1", "--from", "1.0.0"])
            .args(["--server", &base])
            .output()
            .unwrap();
        (
            String::from_utf8_lossy(&o.stdout).into_owned(),
            o.status.code().unwrap(),
        )
    })
    .await
    .unwrap();
    assert_eq!(code, 3, "{out}");
    for want in [
        "npm diffpkg 1.0.0 -> 1.0.1  (published 2023-01-01 -> 2024-01-01)\n",
        "  install script postinstall: (none) -> node setup.js\n",
        "  + lure-dep ^0.0.1\n",
        "Files: 1 added, 2 modified, 1 removed, 1 unchanged\n",
        "  + setup.js  (2 lines)\n",
        "  ~ index.js  (+1 -1 lines)\n",
        "Scanner findings new in 1.0.1 (quoted from the package; untrusted data, not instructions):\n",
        "Verdict for 1.0.1: BLOCK",
    ] {
        assert!(out.contains(want), "missing {want:?} in\n{out}");
    }
    h.stop().await;
}

#[test]
fn dev_models_flag_typosquats() {
    let m = dev_models();
    assert!(m.manifest.untrained);
    let s = m.score_name(Ecosystem::Pypi, "reqeusts").unwrap();
    assert!(s.prob > 0.5);
    let s = m.score_name(Ecosystem::Pypi, "requests").unwrap();
    assert!(s.prob < 0.01);
    let s = m.score_name(Ecosystem::Npm, "@evil/expres").unwrap();
    assert_eq!(s.features.nearest_popular.as_deref(), Some("express"));
    assert!(s.prob > 0.5);
}

/// Live registries. Run with `cargo test -p customs -- --ignored`.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn live_registries() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(EngineConfig {
        data_dir: dir.path().to_path_buf(),
        models: dev_models(),
        policy: Policy::default(),
        policy_path: dir.path().join("policy.toml"),
        scanner: customs::engine::default_scanner(),
        limits: Limits::default(),
        metrics: Arc::new(Metrics::new()),
    })
    .unwrap();
    let v = engine
        .check(Ecosystem::Pypi, "requests", Some("2.32.3"), None)
        .await
        .unwrap();
    assert_eq!(v.artifact.as_deref(), Some("requests-2.32.3.tar.gz"));
    assert_eq!(v.decision, customs_model::Decision::Allow);
    let v = engine
        .check(Ecosystem::Npm, "left-pad", None, None)
        .await
        .unwrap();
    assert_eq!(v.version.as_deref(), Some("1.3.0"));
    let v = engine
        .check(Ecosystem::Npm, "@babel/core", Some("^7"), None)
        .await
        .unwrap();
    assert!(v.version.unwrap().starts_with("7."));
    let v = engine
        .check(
            Ecosystem::Pypi,
            "this-package-should-not-exist-customs-test",
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(v.decision, customs_model::Decision::Block);
}

/// Run the real binary (see [`customs_cmd`]) with extra environment and stdin, killed after
/// `secs`: (stdout, stderr, exit code, or -1 when it had to be killed).
fn run_customs(
    args: &[&str],
    envs: &[(&str, &str)],
    stdin: &str,
    secs: u64,
) -> (String, String, i32) {
    use std::io::{Read, Write};
    use std::process::Stdio;
    let data = tempfile::tempdir().unwrap();
    let mut child = customs_cmd(data.path(), None)
        .args(args)
        .envs(envs.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    let code = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s.code().unwrap_or(-1);
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break -1;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let (mut out, mut err) = (String::new(), String::new());
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut out)
        .unwrap();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    (out, err, code)
}

#[test]
fn env_backed_flags_accept_1_0_yes_and_no() {
    let dir = tempfile::tempdir().unwrap();
    // The shipped compose file and k8s manifest set CUSTOMS_LOG_JSON to "1".
    for v in ["1", "0", "yes", "true"] {
        let (out, err, code) = run_customs(&["env"], &[("CUSTOMS_LOG_JSON", v)], "", 30);
        assert_eq!(code, 0, "CUSTOMS_LOG_JSON={v}: {err}");
        assert!(out.contains("PIP_INDEX_URL"), "{out}");
    }
    let input = json!({
        "session_id": "t",
        "cwd": dir.path(),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "ls"},
    })
    .to_string();
    let server = dead_server();
    for v in ["1", "0", "no"] {
        let (_, err, code) = run_customs(
            &["hook", "claude-code", "--server", &server],
            &[("CUSTOMS_HOOK_FAIL_CLOSED", v)],
            &input,
            30,
        );
        assert_eq!(code, 0, "CUSTOMS_HOOK_FAIL_CLOSED={v}: {err}");
        assert!(!err.contains("invalid value"), "{err}");
    }
}

#[test]
fn serve_refuses_a_missing_explicit_dashboard_dir() {
    let dir = tempfile::tempdir().unwrap();
    let ui = dir.path().join("no-such-ui");
    let data = dir.path().join("data");
    let (_, err, code) = run_customs(
        &[
            "serve",
            "--bind",
            "127.0.0.1:0",
            "--data-dir",
            data.to_str().unwrap(),
            "--ui-dir",
            ui.to_str().unwrap(),
        ],
        &[("CUSTOMS_ALLOW_ANONYMOUS_POLICY_CHANGES", "1")],
        "",
        30,
    );
    assert_eq!(code, 1, "{err}");
    assert!(err.contains(ui.to_str().unwrap()), "{err}");
}

#[test]
fn serve_refuses_an_empty_admin_token() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let data = data.to_str().unwrap();
    let (_, err, code) = run_customs(
        &["serve", "--bind", "127.0.0.1:0", "--data-dir", data],
        &[("CUSTOMS_ADMIN_TOKEN", "")],
        "",
        30,
    );
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("CUSTOMS_ADMIN_TOKEN"), "{err}");
    let file = dir.path().join("token");
    std::fs::write(&file, "\n").unwrap();
    let (_, err, code) = run_customs(
        &[
            "serve",
            "--bind",
            "127.0.0.1:0",
            "--data-dir",
            data,
            "--admin-token-file",
            file.to_str().unwrap(),
        ],
        &[],
        "",
        30,
    );
    assert_eq!(code, 1, "{err}");
    assert!(err.contains(file.to_str().unwrap()), "{err}");
}

#[test]
fn an_unusable_data_dir_is_named_with_a_remedy() {
    let dir = tempfile::tempdir().unwrap();
    // A data dir below a regular file cannot be created.
    let file = dir.path().join("plain-file");
    std::fs::write(&file, "x").unwrap();
    let bad = file.join("data");
    let bad = bad.to_str().unwrap();
    let server = dead_server();
    let (_, err, code) = run_customs(
        &[
            "check",
            "pypi",
            "requests",
            "--server",
            &server,
            "--data-dir",
            bad,
        ],
        &[],
        "",
        60,
    );
    assert_eq!(code, 1, "{err}");
    assert!(err.contains(bad), "{err}");
    assert!(err.contains("--data-dir"), "{err}");
    let (_, err, code) = run_customs(
        &["serve", "--bind", "127.0.0.1:0", "--data-dir", bad],
        &[],
        "",
        30,
    );
    assert_eq!(code, 1, "{err}");
    assert!(err.contains(bad), "{err}");
}

#[test]
fn serve_on_a_taken_port_says_how_to_pick_another() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = taken.local_addr().unwrap().to_string();
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let (_, err, code) = run_customs(
        &[
            "serve",
            "--bind",
            &addr,
            "--data-dir",
            data.to_str().unwrap(),
        ],
        &[],
        "",
        30,
    );
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("--bind"), "{err}");
    assert!(err.contains("CUSTOMS_BIND"), "{err}");
}

#[test]
fn doctor_refuses_a_missing_directory() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nope");
    let server = dead_server();
    let (out, err, code) = run_customs(
        &["doctor", missing.to_str().unwrap(), "--server", &server],
        &[],
        "",
        30,
    );
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("no such directory"), "{err}");
    assert!(err.contains(missing.to_str().unwrap()), "{err}");
    assert!(out.is_empty(), "{out}");
}

/// `[upstream]` lines pointing every registry at `base`.
fn upstream_toml(base: &str) -> String {
    format!(
        "[upstream]\npypi_simple = \"{base}/simple\"\npypi_files = \"{base}/files\"\npypi_json = \"{base}/pypi\"\nnpm = \"{base}/npm\"\n"
    )
}

/// The hook, `check` and `scan` run in the agent's project, which may be hostile: its
/// `customs.toml` and `models/` must not steer the in-process checks.
#[tokio::test(flavor = "multi_thread")]
async fn in_process_checks_ignore_a_projects_customs_toml_and_models() {
    let mock = start_mock().await;
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::write(
        data.join("policy.toml"),
        format!(
            "deny = [\"pypi:goodpkg\", \"npm:left-padd\"]\n{}",
            upstream_toml(&mock.base)
        ),
    )
    .unwrap();
    // The project allows what the user denies, and plants its own models.
    let project = dir.path().join("project");
    let planted = project.join("models");
    std::fs::create_dir_all(&planted).unwrap();
    let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../models/dev");
    for f in std::fs::read_dir(&dev).unwrap() {
        let f = f.unwrap().path();
        std::fs::copy(&f, planted.join(f.file_name().unwrap())).unwrap();
    }
    let manifest = std::fs::read_to_string(planted.join("manifest.json")).unwrap();
    std::fs::write(
        planted.join("manifest.json"),
        manifest.replace("dev-untrained", "project-planted"),
    )
    .unwrap();
    std::fs::write(
        project.join("customs.toml"),
        format!(
            "mode = \"monitor\"\nallow = [\"pypi:goodpkg\", \"npm:left-padd\"]\n{}",
            upstream_toml(&mock.base)
        ),
    )
    .unwrap();
    std::fs::write(
        project.join("left-padd-1.0.0.tgz"),
        npm_tgz(&[(
            "package/package.json",
            r#"{"name":"left-padd","version":"1.0.0"}"#,
        )]),
    )
    .unwrap();
    let server = dead_server();
    let run = {
        let (data, project) = (data.clone(), project.clone());
        move |args: &[&str], keep_models: bool, stdin: &str| {
            use std::io::Write;
            use std::process::Stdio;
            let mut c = customs_cmd(&data, None);
            if !keep_models {
                c.env_remove("CUSTOMS_MODELS");
            }
            let mut child = c
                .args(args)
                .current_dir(&project)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(stdin.as_bytes())
                .unwrap();
            let o = child.wait_with_output().unwrap();
            (
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
                o.status.code().unwrap_or(-1),
            )
        }
    };
    let hook_input = json!({
        "session_id": "t",
        "cwd": project,
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "pip install goodpkg==1.0.0"},
    })
    .to_string();
    let srv = server.clone();
    let (checked, scanned, hooked, malformed) = tokio::task::spawn_blocking(move || {
        let checked = run(
            &[
                "check",
                "pypi",
                "goodpkg==1.0.0",
                "--json",
                "--server",
                &srv,
            ],
            false,
            "",
        );
        let scanned = run(
            &[
                "scan",
                "left-padd-1.0.0.tgz",
                "--name",
                "left-padd",
                "--json",
            ],
            true,
            "",
        );
        let hooked = run(
            &["hook", "claude-code", "--server", &srv],
            false,
            &hook_input,
        );
        // A malformed project file must not make the hook fail open either.
        std::fs::write(project.join("customs.toml"), "mode = \"off\"\n[[[").unwrap();
        let malformed = run(
            &["hook", "claude-code", "--server", &srv],
            false,
            &hook_input,
        );
        (checked, scanned, hooked, malformed)
    })
    .await
    .unwrap();

    let (out, err, code) = &checked;
    assert_eq!(*code, 3, "{out}{err}");
    let v: Value = serde_json::from_str(out).unwrap();
    assert_eq!(v["decision"], "block", "{v}");
    assert_eq!(v["mode"], "enforce", "{v}");
    assert_ne!(v["model_version"], "project-planted", "{v}");
    let (out, err, code) = &scanned;
    assert_eq!(*code, 3, "{out}{err}");
    let v: Value = serde_json::from_str(out).unwrap();
    assert!(rules_of(&v).contains(&"deny".to_string()), "{v}");
    for (out, err, code) in [&hooked, &malformed] {
        assert_eq!(*code, 0, "{err}");
        let d: Value = serde_json::from_str(out.trim()).unwrap_or_else(|_| panic!("{out:?} {err}"));
        assert_eq!(d["hookSpecificOutput"]["permissionDecision"], "deny", "{d}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn check_reads_npm_install_code_whatever_unpacked_size_says() {
    let h = Harness::start(|_| {}).await;
    // The publisher claims a terabyte; the packument lists no install script, the tarball
    // has one (the stand-in scanner reports a postinstall for archives ending in "fresh").
    let mut f = ExtraFile::new(
        "bigclaim",
        "1.0.0",
        "bigclaim-1.0.0.tgz",
        b"benign but fresh",
        "2019-05-01T00:00:00.000Z".into(),
    );
    f.doc = json!({"dist": {"unpackedSize": 1_099_511_627_776u64}});
    h.mock.extra_npm.lock().unwrap().push(f);
    let (s, v) = h.check("npm", "bigclaim", None).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(h.mock.hits("npm:bigclaim-1.0.0.tgz"), 1);
    assert!(hit(&v, "not_scanned").is_none(), "{v}");
    assert!(
        v["install_surface"]
            .as_array()
            .unwrap()
            .contains(&json!("package.json:scripts.postinstall")),
        "{v}"
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn check_reads_an_oversize_sdist_like_the_proxy() {
    let limits = Limits {
        max_check_bytes: 4,
        ..Limits::default()
    };
    let h = Harness::start_full(|_| {}, None, limits).await;
    // An sdist runs code at install, so it is read whatever its size.
    let (s, v) = h.check("pypi", "goodpkg", Some("1.0.0")).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(h.mock.hits("packages/ab/cd/goodpkg-1.0.0.tar.gz"), 1);
    assert!(hit(&v, "not_scanned").is_none(), "{v}");
    assert_eq!(h.scans.load(Ordering::SeqCst), 1);
    // A wheel above the check limit is not downloaded, and the check says it did not look.
    h.mock.extra_pypi.lock().unwrap().push(ExtraFile::new(
        "bigwheel",
        "1.0.0",
        "bigwheel-1.0.0-py3-none-any.whl",
        b"benign big wheel",
        "2020-01-01T00:00:00.000000Z".into(),
    ));
    let (s, v) = h.check("pypi", "bigwheel", None).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(
        h.mock
            .hits("packages/ab/cd/bigwheel-1.0.0-py3-none-any.whl"),
        0
    );
    let ns = hit(&v, "not_scanned").unwrap_or_else(|| panic!("{v}"));
    assert_eq!(ns["severity"], "warn", "{v}");
    assert_eq!(v["decision"], "warn", "{v}");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn check_dates_the_file_it_scans() {
    let h = Harness::start(|_| {}).await;
    // An old release of a popular name gets an sdist today.
    {
        let mut x = h.mock.extra_pypi.lock().unwrap();
        x.push(ExtraFile::new(
            "six",
            "1.15.0",
            "six-1.15.0-py3-none-any.whl",
            b"benign six wheel",
            "2020-05-01T00:00:00.000000Z".into(),
        ));
        x.push(ExtraFile::new(
            "six",
            "1.15.0",
            "six-1.15.0.tar.gz",
            b"benign six sdist",
            now_rfc3339(),
        ));
    }
    let (s, v) = h.check("pypi", "six", Some("1.15.0")).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["artifact"], "six-1.15.0.tar.gz", "{v}");
    assert!(hit(&v, "established").is_none(), "{v}");
    assert!(hit(&v, "min_age_days").is_some(), "{v}");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn check_also_reads_the_pure_python_wheel() {
    let h = Harness::start(|_| {}).await;
    // pip installs the wheel; the payload is only there.
    {
        let mut x = h.mock.extra_pypi.lock().unwrap();
        x.push(ExtraFile::new(
            "wheelonly",
            "1.0.0",
            "wheelonly-1.0.0.tar.gz",
            b"benign sdist",
            "2020-05-01T00:00:00.000000Z".into(),
        ));
        x.push(ExtraFile::new(
            "wheelonly",
            "1.0.0",
            "wheelonly-1.0.0-py3-none-any.whl",
            b"EVIL wheel payload",
            "2020-05-01T00:00:00.000000Z".into(),
        ));
    }
    let (s, v) = h.check("pypi", "wheelonly", None).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["decision"], "block", "{v}");
    assert_eq!(v["artifact"], "wheelonly-1.0.0-py3-none-any.whl", "{v}");
    let note = hit(&v, "also_checked").unwrap_or_else(|| panic!("{v}"));
    assert!(
        note["detail"]
            .as_str()
            .unwrap()
            .contains("wheelonly-1.0.0.tar.gz"),
        "{v}"
    );
    // Both archives were read and both verdicts recorded.
    assert_eq!(h.scans.load(Ordering::SeqCst), 2);
    assert_eq!(h.events().await.len(), 2);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_proxy_install_joining_a_check_records_an_install_event() {
    let h = Arc::new(Harness::start(|_| {}).await);
    let gate = hold_downloads(&h);
    let check = {
        let h = h.clone();
        tokio::spawn(async move { h.check("pypi", "goodpkg", Some("1.0.0")).await })
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while h.mock.hits("packages/ab/cd/goodpkg-1.0.0.tar.gz") == 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "check never fetched"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let install = {
        let h = h.clone();
        tokio::spawn(async move { h.get(&pypi_file_path("goodpkg", "1.0.0")).await.status() })
    };
    wait_for_metric(&h, "customs_singleflight_joins_total 1").await;
    gate.add_permits(1);
    let (status, v) = check.await.unwrap();
    assert_eq!(status, 200, "{v}");
    assert_eq!(install.await.unwrap(), 200);
    assert_eq!(h.scans.load(Ordering::SeqCst), 1);

    let ev = h.events().await;
    let mut kinds: Vec<&str> = ev.iter().map(|e| e["kind"].as_str().unwrap()).collect();
    kinds.sort();
    assert_eq!(kinds, ["check", "install"], "{ev:?}");
    assert!(ev.iter().all(|e| e["verdict_id"] == v["id"]), "{ev:?} {v}");
    Arc::try_unwrap(h).ok().unwrap().stop().await;
}

#[test]
fn serve_with_a_malformed_bind_says_the_form() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let (_, err, code) = run_customs(
        &["serve", "--data-dir", data.to_str().unwrap()],
        &[("CUSTOMS_BIND", "not-an-address")],
        "",
        30,
    );
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("HOST:PORT"), "{err}");
    assert!(err.contains("127.0.0.1:7878"), "{err}");
}

#[test]
fn a_server_that_is_not_a_url_is_named_not_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let (_, err, code) = run_customs(
        &[
            "check",
            "pypi",
            "requests",
            "--data-dir",
            data.to_str().unwrap(),
        ],
        &[("CUSTOMS_SERVER", "garbage")],
        "",
        30,
    );
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("'garbage'"), "{err}");
    assert!(err.contains("CUSTOMS_SERVER"), "{err}");
}

#[test]
fn a_missing_models_dir_says_where_to_point() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    let missing = dir.path().join("nope");
    let (_, err, code) = run_customs(
        &[
            "check",
            "pypi",
            "requests",
            "--models",
            missing.to_str().unwrap(),
            "--data-dir",
            data.to_str().unwrap(),
            "--server",
            "http://127.0.0.1:1",
        ],
        &[],
        "",
        30,
    );
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("manifest.json"), "{err}");
    assert!(err.contains("CUSTOMS_MODELS"), "{err}");
}

/// A check fetches an archive only from the hosts the proxy itself fetches from: a file URL
/// in registry metadata that points elsewhere (an internal address, another host) is refused,
/// not downloaded by the server.
#[tokio::test(flavor = "multi_thread")]
async fn checks_download_only_from_the_configured_upstream_hosts() {
    let elsewhere = dead_server();
    let h = Harness::start(|p| {
        // The metadata comes from the mock and lists files on the mock's host, which is
        // not among the hosts archives are fetched from in this setup.
        p.upstream.pypi_files = format!("{elsewhere}/files");
        p.upstream.pypi_simple = format!("{elsewhere}/simple");
    })
    .await;
    let (s, v) = h.check("pypi", "goodpkg", Some("1.0.0")).await;
    assert_eq!(s, 502, "{v}");
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("not on a configured upstream"),
        "{v}"
    );
    let file = format!("packages/ab/cd/{}", file_name("goodpkg", "1.0.0"));
    assert_eq!(h.mock.hits(&file), 0);
    h.stop().await;
    // With the default upstreams the same file is on a configured host and is fetched.
    let h = Harness::start(|_| {}).await;
    let (s, v) = h.check("pypi", "goodpkg", Some("1.0.0")).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(h.mock.hits(&file), 1);
    h.stop().await;
}
