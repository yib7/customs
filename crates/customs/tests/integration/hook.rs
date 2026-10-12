//! `customs hook`: agent hook input in, a permission decision out.

use super::*;

/// Run the real binary as Claude Code would.
fn run_hook(
    server: &str,
    command: &str,
    cwd: &std::path::Path,
    extra: &[&str],
) -> (String, String, i32) {
    let input = json!({
        "session_id": "test",
        "transcript_path": "/tmp/t.jsonl",
        "cwd": cwd,
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command, "description": "install"},
    });
    run_hook_input(server, input, cwd, extra)
}

/// Run `customs hook claude-code` on one PreToolUse input.
fn run_hook_input(
    server: &str,
    input: Value,
    cwd: &std::path::Path,
    extra: &[&str],
) -> (String, String, i32) {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = customs_cmd(&cwd.join("hook-data"), None)
        .args(["hook", "claude-code", "--server", server])
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code().unwrap_or(-1),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn hook_checks_mcp_servers_an_edit_adds() {
    let h = Harness::start(|_| {}).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join(".mcp.json");
    std::fs::write(
        &cfg,
        "{\n  \"mcpServers\": {\n    \"lib\": { \"command\": \"npx\", \"args\": [\"-y\", \"@scope/lib@1.2.3\"] }\n  }\n}\n",
    )
    .unwrap();
    let edit = |old: &str, new: &str| {
        json!({
            "session_id": "test",
            "cwd": dir.path(),
            "hook_event_name": "PreToolUse",
            "tool_name": "Edit",
            "tool_input": {"file_path": cfg, "old_string": old, "new_string": new},
        })
    };
    let base = h.base.clone();
    let path = dir.path().to_path_buf();
    let inputs = vec![
        // Adds a server whose newest release is malicious.
        edit(
            "\"lib\": {",
            "\"mail\": { \"command\": \"npx\", \"args\": [\"-y\", \"evil-js\"] },\n    \"lib\": {",
        ),
        // Adds a benign server.
        edit(
            "\"lib\": {",
            "\"fetch\": { \"command\": \"uvx\", \"args\": [\"goodpkg\"] },\n    \"lib\": {",
        ),
        // Leaves the existing server as it is.
        edit("\"-y\", \"@scope", "\"--yes\", \"@scope"),
    ];
    let out = tokio::task::spawn_blocking(move || {
        inputs
            .into_iter()
            .map(|i| run_hook_input(&base, i, &path, &[]))
            .collect::<Vec<_>>()
    })
    .await
    .unwrap();
    let (stdout, err, code) = &out[0];
    assert_eq!(*code, 0, "{err}");
    let v: Value = serde_json::from_str(stdout).unwrap_or_else(|_| panic!("{stdout} {err}"));
    let hso = &v["hookSpecificOutput"];
    assert_eq!(hso["permissionDecision"], "deny", "{v}");
    let reason = hso["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.starts_with("This edit adds MCP servers"), "{reason}");
    assert!(reason.contains("npm:evil-js 6.6.6"), "{reason}");
    assert_eq!(out[1].0.trim(), "", "{:?}", out[1]);
    assert_eq!(out[2].0.trim(), "", "{:?}", out[2]);
    let events: Value = h.get("/api/events").await.json().await.unwrap();
    let names: Vec<&str> = events
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"evil-js") && names.contains(&"goodpkg"),
        "{names:?}"
    );
    assert!(!names.contains(&"@scope/lib"), "{names:?}");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn claude_code_hook_end_to_end() {
    let h = Harness::start(|_| {}).await;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("requirements.txt"),
        "goodpkg==1.0.0\nevilpkg\n",
    )
    .unwrap();
    let base = h.base.clone();
    let cwd = dir.path().to_path_buf();
    let results = tokio::task::spawn_blocking(move || {
        vec![
            run_hook(
                &base,
                "cd /x && FOO=1 pip install 'evilpkg==0.0.1'",
                &cwd,
                &[],
            ),
            run_hook(
                &base,
                "pip install goodpkg && npm i @scope/lib@^1",
                &cwd,
                &[],
            ),
            run_hook(&base, "pip install reqeusts", &cwd, &[]),
            run_hook(
                &base,
                "python -m pip install -r requirements.txt",
                &cwd,
                &[],
            ),
            run_hook(&base, "pip install nope-not-here", &cwd, &[]),
            run_hook(&base, "git status", &cwd, &[]),
        ]
    })
    .await
    .unwrap();

    let decision = |out: &str| -> Value { serde_json::from_str(out.trim()).unwrap() };
    let (out, _, code) = &results[0];
    assert_eq!(*code, 0);
    let d = decision(out);
    assert_eq!(d["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(d["hookSpecificOutput"]["permissionDecision"], "deny");
    let reason = d["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("pypi:evilpkg 0.0.1"), "{reason}");
    assert!(
        reason.contains("Downloads and executes a payload"),
        "{reason}"
    );

    assert_eq!(
        results[1].0.trim(),
        "",
        "allowed installs print nothing: {:?}",
        results[1]
    );
    assert_eq!(results[1].2, 0);

    assert_eq!(
        decision(&results[2].0)["hookSpecificOutput"]["permissionDecision"],
        "ask"
    );
    let d = decision(&results[3].0);
    assert_eq!(d["hookSpecificOutput"]["permissionDecision"], "deny");
    let d = decision(&results[4].0);
    let reason = d["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("does not exist on PyPI"), "{reason}");
    assert_eq!(results[5].0, "");

    // The server recorded the hook's checks.
    let ev = h.events().await;
    assert!(ev.iter().any(|e| e["client"] == "claude-code-hook"));
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hook_checks_project_installs() {
    let h = Harness::start(|_| {}).await;
    let lock = |entries: &str| {
        format!(r#"{{"lockfileVersion": 3, "packages": {{"": {{"name": "app"}}{entries}}}}}"#)
    };
    let entry = |path: &str, name: &str, version: &str| {
        format!(
            r#", "node_modules/{path}": {{"version": "{version}", "resolved": "https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"}}"#
        )
    };
    let scoped = r#", "node_modules/@scope/lib": {"version": "1.2.3", "resolved": "https://registry.npmjs.org/@scope/lib/-/lib-1.2.3.tgz"}"#;
    let projects = [
        // The lockfile pins a malicious package.
        (
            r#"{"dependencies": {"@scope/lib": "^1", "evil-js": "^6"}}"#.to_string(),
            lock(&format!("{scoped}{}", entry("evil-js", "evil-js", "6.6.6"))),
        ),
        // A dependency added to package.json but not locked yet is checked too.
        (
            r#"{"dependencies": {"@scope/lib": "^1", "plainlib": "^0.1.0"}}"#.to_string(),
            lock(scoped),
        ),
        (
            r#"{"dependencies": {"@scope/lib": "^1", "evil-js": "^6"}}"#.to_string(),
            lock(scoped),
        ),
        // A trusted name whose tarball URL serves another package.
        (
            r#"{"dependencies": {"plainlib": "^0.1.0"}}"#.to_string(),
            lock(&entry("plainlib", "evil-js", "6.6.6")),
        ),
    ];
    let dirs: Vec<tempfile::TempDir> = projects
        .iter()
        .map(|(manifest, lockfile)| {
            let d = tempfile::tempdir().unwrap();
            std::fs::write(d.path().join("package.json"), manifest).unwrap();
            std::fs::write(d.path().join("package-lock.json"), lockfile).unwrap();
            d
        })
        .collect();
    let base = h.base.clone();
    let paths: Vec<std::path::PathBuf> = dirs.iter().map(|d| d.path().to_path_buf()).collect();
    let results = tokio::task::spawn_blocking(move || {
        vec![
            run_hook(&base, "npm ci", &paths[0], &[]),
            run_hook(&base, "npm install", &paths[1], &[]),
            run_hook(&base, "cd x; npm i --no-audit", &paths[2], &[]),
            run_hook(&base, "npm ci", &paths[3], &[]),
            run_hook(&base, "npm run build", &paths[0], &[]),
        ]
    })
    .await
    .unwrap();
    let reason = |out: &str| -> (String, String) {
        let d: Value = serde_json::from_str(out.trim()).unwrap();
        let o = &d["hookSpecificOutput"];
        (
            o["permissionDecision"].as_str().unwrap().to_string(),
            o["permissionDecisionReason"].as_str().unwrap().to_string(),
        )
    };
    let (d, r) = reason(&results[0].0);
    assert_eq!(d, "deny");
    assert!(r.contains("npm:evil-js 6.6.6"), "{r}");
    assert_eq!(results[1].0.trim(), "", "{:?}", results[1]);
    let (d, r) = reason(&results[2].0);
    assert_eq!(d, "deny", "{r}");
    assert!(r.contains("npm:evil-js"), "{r}");
    let (d, r) = reason(&results[3].0);
    assert_eq!(d, "deny");
    assert!(
        r.contains("npm:plainlib 6.6.6") && r.contains("lockfile installs evil-js@6.6.6"),
        "{r}"
    );
    assert_eq!(results[4].0, "");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn project_installs_count_only_blocks_for_locked_packages() {
    // freshpkg warns (min_age_days at warn severity).
    let h = Harness::start(|p| {
        p.min_age_severity = customs::config::AgeSeverity::Warn;
        p.block_install_scripts_from_new = false;
    })
    .await;
    let locked = r#"{"lockfileVersion": 3, "packages": {"": {"name": "app"},
  "node_modules/freshpkg": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/freshpkg/-/freshpkg-1.0.0.tgz"}}}"#;
    let empty = r#"{"lockfileVersion": 3, "packages": {"": {"name": "app"}}}"#;
    let dirs: Vec<tempfile::TempDir> = [locked, empty]
        .iter()
        .map(|lock| {
            let d = tempfile::tempdir().unwrap();
            std::fs::write(
                d.path().join("package.json"),
                r#"{"dependencies": {"freshpkg": "1.0.0"}}"#,
            )
            .unwrap();
            std::fs::write(d.path().join("package-lock.json"), lock).unwrap();
            d
        })
        .collect();
    let base = h.base.clone();
    let paths: Vec<std::path::PathBuf> = dirs.iter().map(|d| d.path().to_path_buf()).collect();
    let results = tokio::task::spawn_blocking(move || {
        vec![
            run_hook(&base, "npm ci", &paths[0], &[]),
            run_hook(&base, "npm install", &paths[1], &[]),
            run_hook(&base, "npm install freshpkg", &paths[0], &[]),
        ]
    })
    .await
    .unwrap();
    assert_eq!(results[0].0.trim(), "", "{:?}", results[0]);
    for (out, _, _) in &results[1..] {
        let d: Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(
            d["hookSpecificOutput"]["permissionDecision"], "ask",
            "{out}"
        );
    }
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn hook_failure_modes() {
    let dir = tempfile::tempdir().unwrap();
    // A config whose upstreams refuse connections: the server is unreachable, the
    // in-process fallback cannot reach the registry either.
    std::fs::write(
        dir.path().join("customs.toml"),
        "[upstream]\npypi_simple = \"http://127.0.0.1:9/simple\"\npypi_files = \"http://127.0.0.1:9/f\"\npypi_json = \"http://127.0.0.1:9/pypi\"\nnpm = \"http://127.0.0.1:9/npm\"\n",
    )
    .unwrap();
    let cfg = dir.path().join("customs.toml").display().to_string();
    let cwd = dir.path().to_path_buf();
    let (open, closed, garbage) = tokio::task::spawn_blocking(move || {
        let open = run_hook(
            "http://127.0.0.1:9",
            "pip install anything",
            &cwd,
            &["--config", &cfg],
        );
        let closed = run_hook(
            "http://127.0.0.1:9",
            "pip install anything",
            &cwd,
            &["--config", &cfg, "--fail-closed"],
        );
        let garbage = {
            use std::io::Write;
            use std::process::Stdio;
            let mut c = customs_cmd(&cwd.join("garbage-data"), None)
                .args(["hook", "claude-code"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            c.stdin.take().unwrap().write_all(b"{not json").unwrap();
            let o = c.wait_with_output().unwrap();
            (
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
                o.status.code().unwrap(),
            )
        };
        (open, closed, garbage)
    })
    .await
    .unwrap();
    assert_eq!(open.2, 0);
    assert_eq!(open.0, "", "fail open prints no decision");
    assert!(open.1.contains("customs hook"), "{}", open.1);
    let d: Value = serde_json::from_str(closed.0.trim()).unwrap();
    assert_eq!(d["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(garbage.2, 0);
    assert_eq!(garbage.0, "");
    assert!(garbage.1.contains("invalid hook input"), "{}", garbage.1);
}

/// A config whose upstreams refuse connections, so no package can be checked.
fn dead_upstreams(dir: &std::path::Path) -> String {
    let cfg = dir.join("customs.toml");
    std::fs::write(
        &cfg,
        "[upstream]\npypi_simple = \"http://127.0.0.1:9/simple\"\npypi_files = \"http://127.0.0.1:9/f\"\npypi_json = \"http://127.0.0.1:9/pypi\"\nnpm = \"http://127.0.0.1:9/npm\"\n",
    )
    .unwrap();
    cfg.display().to_string()
}

#[tokio::test(flavor = "multi_thread")]
async fn hook_fails_closed_on_input_that_once_panicked() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dead_upstreams(dir.path());
    let cwd = dir.path().to_path_buf();
    let (stdout, stderr, code) = tokio::task::spawn_blocking(move || {
        run_hook(
            "http://127.0.0.1:9",
            "pip install -\u{e9}x; pip install zzevil",
            &cwd,
            &["--config", &cfg, "--fail-closed"],
        )
    })
    .await
    .unwrap();
    assert_eq!(code, 0, "{stderr}");
    let d: Value =
        serde_json::from_str(stdout.trim()).unwrap_or_else(|_| panic!("{stdout} {stderr}"));
    assert_eq!(d["hookSpecificOutput"]["permissionDecision"], "deny", "{d}");
    let reason = d["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("zzevil"), "{reason}");
}

#[tokio::test(flavor = "multi_thread")]
async fn hook_checks_installs_that_runners_start() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dead_upstreams(dir.path());
    let cwd = dir.path().to_path_buf();
    for command in [
        "uv run pip install zzevil",
        "npx -y pnpm add zzevil",
        "bash -euo pipefail -c 'pip install zzevil'",
        "cmd /c npx -y zzevil",
    ] {
        let (cwd, cfg) = (cwd.clone(), cfg.clone());
        let (stdout, stderr, code) = tokio::task::spawn_blocking(move || {
            run_hook(
                "http://127.0.0.1:9",
                command,
                &cwd,
                &["--config", &cfg, "--fail-closed"],
            )
        })
        .await
        .unwrap();
        assert_eq!(code, 0, "{stderr}");
        let d: Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|_| panic!("{command}: {stdout} {stderr}"));
        assert_eq!(d["hookSpecificOutput"]["permissionDecision"], "deny", "{d}");
        let reason = d["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap();
        assert!(reason.contains("zzevil"), "{command}: {reason}");
    }
}
