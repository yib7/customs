//! The REST API and the dashboard: policy changes and who may make them, events, SSE,
//! health, webhooks, error bodies and security headers.

use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn sse_delivers_events() {
    let h = Harness::start(|_| {}).await;
    let mut stream = h.get("/api/events/stream").await;
    assert_eq!(stream.headers()["content-type"], "text/event-stream");
    let (_, v) = h.check("pypi", "goodpkg", Some("1.0.0")).await;
    let mut buf = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !buf.contains("\n\n") {
        let chunk = tokio::time::timeout_at(deadline, stream.chunk())
            .await
            .expect("no SSE frame")
            .unwrap()
            .unwrap();
        buf.push_str(&String::from_utf8_lossy(&chunk));
    }
    assert!(buf.starts_with("event: install\n"), "{buf}");
    let data = buf.lines().find_map(|l| l.strip_prefix("data: ")).unwrap();
    let ev: Value = serde_json::from_str(data).unwrap();
    assert_eq!(ev["kind"], "check");
    assert_eq!(ev["verdict_id"], v["id"]);
    assert_eq!(ev["client"], "test");
    // Shutdown must not hang on the open stream.
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_api_validates_and_persists() {
    let h = Harness::start(|_| {}).await;
    let mut p: Value = h.get("/api/policy").await.json().await.unwrap();
    assert_eq!(p["mode"], "enforce");
    assert_eq!(p["warn_threshold"], "model");
    assert_eq!(p["provenance_dropped"], "warn");
    assert_eq!(p["version_anomaly"], "off");
    assert_eq!(p["dormant_days"], 365);
    p["deny"] = json!(["pypi:goodpkg"]);
    p["block_threshold"] = json!(0.8);
    p["publisher_changed"] = json!("block");
    p["dormant_days"] = json!(400);
    let r = h
        .http
        .put(format!("{}/api/policy", h.base))
        .json(&p)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let saved = std::fs::read_to_string(h.engine.policy_path()).unwrap();
    assert!(saved.contains("block_threshold = 0.8"), "{saved}");
    assert!(saved.contains("\"pypi:goodpkg\""), "{saved}");
    assert!(saved.contains("publisher_changed = \"block\""), "{saved}");
    assert!(saved.contains("dormant_days = 400"), "{saved}");
    let r = h.get(&pypi_file_path("goodpkg", "1.0.0")).await;
    assert_eq!(r.status(), 403);

    let mut bad = p.clone();
    bad["dormant_days"] = json!(0);
    let r = h
        .http
        .put(format!("{}/api/policy", h.base))
        .json(&bad)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let e: Value = r.json().await.unwrap();
    assert_eq!(e["errors"][0]["field"], "dormant_days");

    p["warn_threshold"] = json!(1.5);
    let r = h
        .http
        .put(format!("{}/api/policy", h.base))
        .json(&p)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let e: Value = r.json().await.unwrap();
    assert_eq!(e["errors"][0]["field"], "warn_threshold");
    let r = h
        .http
        .put(format!("{}/api/policy", h.base))
        .body(r#"{"mode": "strict"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    // The bad updates did not change the active policy.
    let now: Value = h.get("/api/policy").await.json().await.unwrap();
    assert_eq!(now["block_threshold"], 0.8);

    // On a loopback listener a rebound host name cannot even read.
    for path in ["/api/events", "/api/policy", "/pypi/simple/goodpkg/"] {
        let r = h
            .http
            .get(format!("{}{path}", h.base))
            .header("host", "rebind.attacker.example:7878")
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403, "{path}");
    }
    let r = h
        .http
        .get(format!("{}/healthz", h.base))
        .header("host", "localhost:7878")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // A page on another origin, or one reached through DNS rebinding (its own host name
    // resolving to 127.0.0.1), cannot switch enforcement off.
    let mut off = p.clone();
    off["warn_threshold"] = json!("model");
    off["mode"] = json!("monitor");
    for (name, value) in [
        ("host", "rebind.attacker.example:7878"),
        ("origin", "http://attacker.example"),
    ] {
        let r = h
            .http
            .put(format!("{}/api/policy", h.base))
            .header(name, value)
            .json(&off)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403, "{name}: {value}");
    }
    let r = h
        .http
        .post(format!("{}/api/check", h.base))
        .header("origin", "http://attacker.example")
        .json(&json!({"ecosystem": "pypi", "name": "goodpkg"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let now: Value = h.get("/api/policy").await.json().await.unwrap();
    assert_eq!(now["mode"], "enforce");
    // The dashboard's own origin is accepted.
    let r = h
        .http
        .put(format!("{}/api/policy", h.base))
        .header("origin", h.base.as_str())
        .json(&off)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn events_filters_stats_model_metrics_health() {
    let h = Harness::start(|_| {}).await;
    h.get(&pypi_file_path("goodpkg", "1.0.0")).await;
    h.get(&pypi_file_path("evilpkg", "0.0.1")).await;
    h.get("/npm/plainlib/-/plainlib-0.1.0.tgz").await;
    let ev: Vec<Value> = h
        .get("/api/events?decision=block")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0]["name"], "evilpkg");
    let ev: Vec<Value> = h
        .get("/api/events?ecosystem=npm")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(ev.len(), 1);
    let ev: Vec<Value> = h
        .get("/api/events?q=PKG&limit=1")
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(ev.len(), 1);
    let older: Vec<Value> = h
        .get(&format!("/api/events?q=pkg&before={}", ev[0]["id"]))
        .await
        .json()
        .await
        .unwrap();
    assert_eq!(older.len(), 1);
    assert_eq!(older[0]["name"], "goodpkg");

    let s: Value = h.get("/api/stats").await.json().await.unwrap();
    assert_eq!(s["total"], 3);
    assert_eq!(s["by_decision"]["block"], 1);
    assert_eq!(s["by_ecosystem"]["pypi"]["allow"], 1);
    assert_eq!(s["by_kind"]["install"], 3);
    assert_eq!(s["blocks_per_day"].as_array().unwrap().len(), 30);
    // Find the day by date: the block may have landed just before UTC midnight.
    let ev = h.events().await;
    let block = ev.iter().find(|e| e["decision"] == "block").unwrap();
    let day = &block["ts"].as_str().unwrap()[..10];
    let blocks: Vec<(&str, u64)> = s["blocks_per_day"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| (d["date"].as_str().unwrap(), d["count"].as_u64().unwrap()))
        .filter(|(_, n)| *n > 0)
        .collect();
    assert_eq!(blocks, [(day, 1)]);
    assert_eq!(s["top_reasons"][0]["feature"], "inst_download_exec");

    let m: Value = h.get("/api/model").await.json().await.unwrap();
    assert_eq!(m["model_version"], "dev-untrained");
    assert_eq!(m["feature_schema_version"], 1);
    assert_eq!(m["untrained"], true);
    assert_eq!(m["thresholds"]["warn"], 0.5);
    assert_eq!(m["components"]["code_gbdt"]["loaded"], true);
    // Where the server keeps its files is not the API's business.
    let text = m.to_string();
    let models = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../models/dev");
    assert!(m.get("models_dir").is_none(), "{text}");
    assert!(!text.contains(models.to_str().unwrap()), "{text}");

    let metrics = h.get("/metrics").await.text().await.unwrap();
    assert!(
        metrics
            .contains(r#"customs_http_requests_total{route="/pypi/files/{*path}",status="403"} 1"#),
        "{metrics}"
    );
    assert!(metrics.contains(r#"customs_verdicts_total{decision="block",ecosystem="pypi"} 1"#));
    assert!(metrics.contains("customs_scan_duration_seconds_count 3"));
    assert!(metrics.contains(r#"customs_upstream_fetch_duration_seconds_count{kind="artifact"} 3"#));

    let health: Value = h.get("/healthz").await.json().await.unwrap();
    assert_eq!(health["status"], "ok");
    let r = h.get("/api/nope").await;
    assert_eq!(r.status(), 404);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dashboard_serving() {
    let h = Harness::start(|_| {}).await;
    let body = h.get("/").await.text().await.unwrap();
    assert!(body.contains("dashboard is not built"));
    h.stop().await;

    let ui = tempfile::tempdir().unwrap();
    std::fs::write(ui.path().join("index.html"), "<html>SPA</html>").unwrap();
    std::fs::create_dir(ui.path().join("assets")).unwrap();
    std::fs::write(ui.path().join("assets/app.js"), "console.log(1)").unwrap();
    let h = Harness::start_with_ui(|_| {}, Some(ui.path().to_path_buf())).await;
    assert_eq!(h.get("/").await.text().await.unwrap(), "<html>SPA</html>");
    assert_eq!(
        h.get("/assets/app.js").await.text().await.unwrap(),
        "console.log(1)"
    );
    let r = h.get("/verdicts/12").await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "<html>SPA</html>");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn blocks_are_posted_to_the_webhook_once() {
    use customs::notify::{Format, NotifyConfig};
    let received: Arc<std::sync::Mutex<Vec<Value>>> = Arc::default();
    let sink = received.clone();
    let hook = Router::new().route(
        "/hook/secret",
        axum::routing::post(move |Json(v): Json<Value>| {
            let sink = sink.clone();
            async move {
                sink.lock().unwrap().push(v);
                StatusCode::OK
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hook_url = format!("http://{}/hook/secret", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, hook).await.unwrap() });

    let h = Harness::start(|p| p.deny = vec!["pypi:goodpkg@1.0.0".into()]).await;
    customs::notify::spawn(
        h.engine.clone(),
        NotifyConfig {
            url: hook_url,
            format: Format::Json,
            min_decision: customs_model::Decision::Block,
            public_url: Some("http://customs.test".into()),
        },
    );
    // Allowed: no message. Blocked twice (an agent retrying): one message.
    assert_eq!(
        h.get(&pypi_file_path("goodpkg", "1.1.0")).await.status(),
        200
    );
    for _ in 0..2 {
        let r = h.get(&pypi_file_path("goodpkg", "1.0.0")).await;
        assert_eq!(r.status(), 403);
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while received.lock().unwrap().is_empty() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // The second block was seen and held back as a repeat, not merely late.
    wait_for_metric(&h, "customs_notifications_total{outcome=\"repeat\"} 1").await;
    let got = received.lock().unwrap().clone();
    assert_eq!(got.len(), 1, "{got:?}");
    let text = got[0]["text"].as_str().unwrap();
    assert!(
        text.starts_with("Customs blocked pypi package goodpkg 1.0.0 (install"),
        "{text}"
    );
    assert!(text.contains("is on the deny list"), "{text}");
    assert_eq!(got[0]["verdict"]["decision"], "block");
    let url = got[0]["url"].as_str().unwrap();
    assert!(url.starts_with("http://customs.test/verdicts/"), "{url}");

    // A policy change is announced, whatever the rate limit holds back.
    let mut p: Value = h.get("/api/policy").await.json().await.unwrap();
    p["mode"] = json!("monitor");
    p["deny"] = json!([]);
    let r = h
        .http
        .put(format!("{}/api/policy", h.base))
        .json(&p)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while received.lock().unwrap().len() < 2 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let got = received.lock().unwrap().clone();
    assert_eq!(got.len(), 2, "{got:?}");
    let text = got[1]["text"].as_str().unwrap();
    assert_eq!(
        text,
        "Customs policy loosened (from 127.0.0.1, without a token)\n\
         - deny: removed pypi:goodpkg@1.0.0\n- mode: enforce -> monitor\n\
         http://customs.test/policy"
    );
    assert_eq!(got[1]["loosened"], json!(true));
    // The sender counts a message once the webhook has answered, which can be just after
    // the receiver above recorded it.
    let sent = "customs_notifications_total{outcome=\"sent\"} 2";
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut metrics = h.get("/metrics").await.text().await.unwrap();
    while !metrics.contains(sent) && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
        metrics = h.get("/metrics").await.text().await.unwrap();
    }
    assert!(metrics.contains(sent), "{metrics}");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_changes_need_the_admin_token_when_one_is_set() {
    let token = "s3cret-token-0123456789";
    let opts = ServeOptions {
        admin_token: Some(token.into()),
        ..Default::default()
    };
    let h = Harness::start_serving(|_| {}, None, Limits::default(), "127.0.0.1:0", opts).await;
    let mut p: Value = h.get("/api/policy").await.json().await.unwrap();
    p["mode"] = json!("monitor");
    let put = |auth: Option<&str>| {
        let mut r = h.http.put(format!("{}/api/policy", h.base)).json(&p);
        if let Some(a) = auth {
            r = r.header("authorization", a);
        }
        r.send()
    };
    let r = put(None).await.unwrap();
    assert_eq!(r.status(), 401);
    assert!(r.headers()["www-authenticate"]
        .to_str()
        .unwrap()
        .starts_with("Bearer"));
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["code"], "admin_token_required");
    let r = put(Some("Bearer wrong-token-0123456789")).await.unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(h.engine.policy().mode, customs::config::Mode::Enforce);
    let r = put(Some(&format!("Bearer {token}"))).await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(h.engine.policy().mode, customs::config::Mode::Monitor);
    // Reads and checks need no token.
    assert_eq!(h.get("/api/events").await.status(), 200);

    // The change is logged with where it came from; resending the same policy is not.
    let r = put(Some(&format!("Bearer {token}"))).await.unwrap();
    assert_eq!(r.status(), 200);
    let log: Value = h.get("/api/policy/changes").await.json().await.unwrap();
    let changes = log["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 1, "{log}");
    assert_eq!(changes[0]["auth"], "token");
    assert_eq!(changes[0]["remote"], "127.0.0.1");
    assert_eq!(
        changes[0]["changes"],
        json!([{"field": "mode", "before": "enforce", "after": "monitor"}])
    );
    let metrics = h.get("/metrics").await.text().await.unwrap();
    assert!(
        metrics.contains("customs_policy_changes_total{result=\"applied\"} 1"),
        "{metrics}"
    );
    assert!(
        metrics.contains("customs_policy_changes_total{result=\"refused\"} 2"),
        "{metrics}"
    );
    h.stop().await;
}

/// A server listening beyond loopback without a token refuses policy changes. Which servers
/// those are is `server::policy_auth_for` (unit-tested there); this serves the resulting
/// state on loopback, so the test never listens on the network.
#[tokio::test(flavor = "multi_thread")]
async fn a_network_facing_server_without_a_token_refuses_policy_changes() {
    use customs::server::{AppState, PolicyAuth};
    let h = Harness::start(|_| {}).await;
    let (_shutdown, rx) = tokio::sync::watch::channel(false);
    let app = customs::server::router(
        AppState {
            engine: h.engine.clone(),
            shutdown: rx,
            policy_auth: PolicyAuth::Disabled,
            allowed_hosts: Arc::from(Vec::new()),
            token_failures: Arc::default(),
        },
        None,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let p: Value = h.get("/api/policy").await.json().await.unwrap();
    let r = h
        .http
        .put(format!("{base}/api/policy"))
        .json(&p)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["code"], "policy_changes_disabled");
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("CUSTOMS_ADMIN_TOKEN"));
    server.abort();
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn the_vite_dev_origin_cannot_change_the_policy() {
    let h = Harness::start(|_| {}).await;
    let mut p: Value = h.get("/api/policy").await.json().await.unwrap();
    p["mode"] = json!("monitor");
    // Any page served on Vite's default port, from any project.
    let r = h
        .http
        .put(format!("{}/api/policy", h.base))
        .header("origin", "http://localhost:5173")
        .json(&p)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    assert_eq!(h.engine.policy().mode, Mode::Enforce);
    let r = h
        .http
        .get(format!("{}/api/events", h.base))
        .header("origin", "http://localhost:5173")
        .send()
        .await
        .unwrap();
    assert!(r.headers().get("access-control-allow-origin").is_none());
    // The dev server proxies /api with the browser's Host, so its dashboard is same-origin.
    let r = h
        .http
        .put(format!("{}/api/policy", h.base))
        .header("host", "localhost:5173")
        .header("origin", "http://localhost:5173")
        .json(&p)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn healthz_says_whether_the_models_are_trained() {
    let h = Harness::start(|_| {}).await;
    let v: Value = h.get("/healthz").await.json().await.unwrap();
    assert_eq!(v["status"], "ok");
    assert_eq!(v["untrained"], true, "{v}");
    assert_eq!(v["models_loaded"], true, "{v}");
    h.stop().await;

    // A server that found no models runs on the policy rules alone, and says so.
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(EngineConfig {
        data_dir: dir.path().to_path_buf(),
        models: Models::empty(),
        policy: Policy::default(),
        policy_path: dir.path().join("policy.toml"),
        scanner: fake_scanner(Arc::default()),
        limits: Limits::default(),
        metrics: Arc::new(Metrics::new()),
    })
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(customs::server::serve_with(
        listener,
        engine,
        None,
        ServeOptions::default(),
        async move {
            let _ = rx.await;
        },
    ));
    let http = reqwest::Client::builder().no_proxy().build().unwrap();
    let v: Value = http
        .get(format!("{base}/healthz"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["models_loaded"], false, "{v}");
    assert_eq!(v["model_version"], "none", "{v}");
    let _ = tx.send(());
    server.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_policy_change_the_log_cannot_record_is_still_reported_as_applied() {
    let h = Harness::start(|_| {}).await;
    let db = rusqlite::Connection::open(h._dir.path().join("customs.db")).unwrap();
    db.execute_batch("DROP TABLE policy_changes").unwrap();
    drop(db);
    let mut changes = h.engine.subscribe_policy_changes();
    let mut p: Value = h.get("/api/policy").await.json().await.unwrap();
    p["mode"] = json!("monitor");
    let r = h
        .http
        .put(format!("{}/api/policy", h.base))
        .json(&p)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let warning = r.headers()["x-customs-warning"]
        .to_str()
        .unwrap()
        .to_string();
    assert!(warning.contains("change log"), "{warning}");
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["mode"], "monitor");
    assert_eq!(h.engine.policy().mode, Mode::Monitor);
    // Counted and announced (the webhook listens to this) like any applied change.
    let ch = changes.try_recv().unwrap();
    assert_eq!(ch.changes[0].field, "mode");
    let metrics = h.get("/metrics").await.text().await.unwrap();
    assert!(
        metrics.contains("customs_policy_changes_total{result=\"applied\"} 1"),
        "{metrics}"
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_query_and_path_parameters_get_json_errors() {
    let h = Harness::start(|_| {}).await;
    for path in [
        "/api/events?limit=abc",
        "/api/stats?days=x",
        "/api/policy/changes?limit=-1",
        "/api/verdicts/abc",
    ] {
        let r = h.get(path).await;
        assert_eq!(r.status(), 400, "{path}");
        let v: Value = r.json().await.unwrap();
        assert!(v["error"].is_string(), "{path}: {v}");
    }
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_partial_policy_put_is_refused_with_the_missing_keys() {
    let h = Harness::start(|p| p.deny = vec!["npm:evil-js".into()]).await;
    let r = h
        .http
        .put(format!("{}/api/policy", h.base))
        .body(r#"{"mode": "enforce"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let e: Value = r.json().await.unwrap();
    let msg = e["error"].as_str().unwrap();
    assert!(msg.contains("deny") && msg.contains("upstream"), "{msg}");
    assert!(e["errors"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["field"] == "allow"));
    // A nested table must be whole too.
    let mut p: Value = h.get("/api/policy").await.json().await.unwrap();
    p["established"] = json!({"enabled": false});
    let r = h
        .http
        .put(format!("{}/api/policy", h.base))
        .json(&p)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let e: Value = r.json().await.unwrap();
    assert!(
        e["error"].as_str().unwrap().contains("established.top"),
        "{e}"
    );
    assert_eq!(h.engine.policy().deny, vec!["npm:evil-js".to_string()]);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn upstream_credentials_are_redacted_but_kept() {
    let h = Harness::start(|p| {
        p.upstream.npm = p.upstream.npm.replace("http://", "http://user:s3cret@");
    })
    .await;
    let text = h.get("/api/policy").await.text().await.unwrap();
    assert!(!text.contains("s3cret"), "{text}");
    assert!(text.contains("http://***@127.0.0.1"), "{text}");
    // Sending back what the dashboard read keeps the stored credentials.
    let mut p: Value = serde_json::from_str(&text).unwrap();
    p["mode"] = json!("monitor");
    let r = h
        .http
        .put(format!("{}/api/policy", h.base))
        .json(&p)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(!r.text().await.unwrap().contains("s3cret"));
    assert!(h.engine.policy().upstream.npm.contains("user:s3cret@"));
    let saved = std::fs::read_to_string(h.engine.policy_path()).unwrap();
    assert!(saved.contains("user:s3cret@"), "{saved}");
    // New credentials are accepted, and the change log shows neither.
    p["upstream"]["npm"] = json!("https://other:pw-two@npm.example/registry");
    let r = h
        .http
        .put(format!("{}/api/policy", h.base))
        .json(&p)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(h.engine.policy().upstream.npm.contains("pw-two"));
    let log = h.get("/api/policy/changes").await.text().await.unwrap();
    assert!(!log.contains("s3cret") && !log.contains("pw-two"), "{log}");
    assert!(log.contains("https://***@npm.example/registry"), "{log}");
    h.stop().await;
}

/// `--allowed-hosts` (`CUSTOMS_ALLOWED_HOSTS`) comes in through the server's options, so
/// the developer's own environment does not change what these tests see.
#[tokio::test(flavor = "multi_thread")]
async fn an_allowed_host_name_may_change_the_policy() {
    let opts = ServeOptions {
        allowed_hosts: vec!["Customs".into()],
        ..Default::default()
    };
    let h = Harness::start_serving(|_| {}, None, Limits::default(), "127.0.0.1:0", opts).await;
    let p: Value = h.get("/api/policy").await.json().await.unwrap();
    for (host, status) in [("customs:7878", 200), ("other.example:7878", 403)] {
        let r = h
            .http
            .put(format!("{}/api/policy", h.base))
            .header("host", host)
            .json(&p)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), status, "{host}");
    }
    let r = h
        .http
        .get(format!("{}/api/events", h.base))
        .header("host", "customs:7878")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    h.stop().await;
}

/// A stalled or failed verdict delivery does not hold up policy-change alerts, and a
/// message that could not be delivered is counted in the next one.
#[tokio::test(flavor = "multi_thread")]
async fn webhook_failures_are_counted_and_do_not_delay_policy_alerts() {
    use customs::notify::{Format, NotifyConfig};
    use std::sync::atomic::AtomicBool;
    let received: Arc<Mutex<Vec<Value>>> = Arc::default();
    let first_done = Arc::new(AtomicBool::new(false));
    let policy_during_first = Arc::new(AtomicBool::new(false));
    let (sink, done, during) = (
        received.clone(),
        first_done.clone(),
        policy_during_first.clone(),
    );
    let hook = Router::new().route(
        "/hook",
        axum::routing::post(move |Json(v): Json<Value>| {
            let (sink, done, during) = (sink.clone(), done.clone(), during.clone());
            async move {
                let first = {
                    let mut got = sink.lock().unwrap();
                    got.push(v.clone());
                    v.get("event").is_some()
                        && got.iter().filter(|m| m.get("event").is_some()).count() == 1
                };
                if v.get("policy_change").is_some() && !done.load(Ordering::SeqCst) {
                    during.store(true, Ordering::SeqCst);
                }
                if first {
                    // A slow receiver that then refuses (4xx: not retried).
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    done.store(true, Ordering::SeqCst);
                    return StatusCode::GONE;
                }
                StatusCode::OK
            }
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hook_url = format!("http://{}/hook", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, hook).await.unwrap() });

    let h = Harness::start(|p| p.deny = vec!["pypi:goodpkg".into()]).await;
    customs::notify::spawn(
        h.engine.clone(),
        NotifyConfig {
            url: hook_url,
            format: Format::Json,
            min_decision: customs_model::Decision::Block,
            public_url: None,
        },
    );
    let wait_for = |n: usize| {
        let received = received.clone();
        async move {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while received.lock().unwrap().len() < n && std::time::Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            received.lock().unwrap().clone()
        }
    };
    let r = h.get(&pypi_file_path("goodpkg", "1.0.0")).await;
    assert_eq!(r.status(), 403);
    wait_for(1).await;
    // While that delivery hangs, a policy change is announced.
    let mut p: Value = h.get("/api/policy").await.json().await.unwrap();
    p["min_age_days"] = json!(1);
    let r = h
        .http
        .put(format!("{}/api/policy", h.base))
        .json(&p)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let got = wait_for(2).await;
    assert!(got[1].get("policy_change").is_some(), "{got:?}");
    assert!(policy_during_first.load(Ordering::SeqCst));
    // The undelivered block is counted in the next message.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !first_done.load(Ordering::SeqCst) && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let r = h.get(&pypi_file_path("goodpkg", "1.1.0")).await;
    assert_eq!(r.status(), 403);
    let got = wait_for(3).await;
    let text = got[2]["text"].as_str().unwrap_or_default();
    assert!(text.contains("goodpkg 1.1.0"), "{got:?}");
    assert!(text.contains("1 earlier notification not sent"), "{text}");
    h.stop().await;
}

/// Upstream credentials go to the upstream only: not into the log (at any level), not into
/// the errors the proxy hands pip and npm, and not into API errors. Current-thread runtime,
/// so every task the server spawns logs to this test's subscriber.
#[tokio::test(flavor = "current_thread")]
async fn upstream_credentials_stay_out_of_logs_and_errors() {
    let logs = LogBuf::default();
    let sub = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(sub);

    let with_creds = |base: &str| base.replace("http://", "http://user:s3cret@");
    let garbage = with_creds(&start_garbage_registry().await);
    let dead = with_creds(&dead_server());
    let h = Harness::start(|p| {
        p.upstream.pypi_simple = format!("{garbage}/simple");
        p.upstream.pypi_json = format!("{garbage}/pypi");
        p.upstream.pypi_files = format!("{dead}/files");
        p.upstream.npm = format!("{dead}/npm");
    })
    .await;
    let mut bodies = Vec::new();
    for path in [
        "/pypi/simple/six/",
        "/pypi/files/ab/cd/six-1.0.0.tar.gz",
        "/npm/left-pad",
        "/npm/left-pad/-/left-pad-1.3.0.tgz",
        "/npm/-/v1/search?text=x",
    ] {
        let r = h.get(path).await;
        bodies.push(format!("{path} {} {}", r.status(), r.text().await.unwrap()));
    }
    for (eco, name, version) in [
        ("pypi", "six", Some("1.0.0")),
        ("npm", "left-pad", Some("1.3.0")),
    ] {
        let (status, v) = h.check(eco, name, version).await;
        bodies.push(format!("check {eco} {status} {v}"));
    }
    h.stop().await;
    let bodies = bodies.join("\n");
    let log = logs.text();
    // The failures above were logged, with the URLs they concern.
    assert!(log.contains("upstream packument failed"), "{log}");
    assert!(log.contains("***@127.0.0.1"), "{log}");
    assert!(!bodies.contains("s3cret"), "{bodies}");
    assert!(!log.contains("s3cret"), "{log}");
}

/// Dashboard pages, API answers and the "not built" page all tell the browser not to sniff
/// types, not to be framed, not to send the URL on as a referrer, and to load nothing from
/// other origins.
#[tokio::test(flavor = "multi_thread")]
async fn responses_carry_security_headers() {
    fn check(r: &reqwest::Response, what: &str) {
        let hdr = |n: &str| {
            r.headers()
                .get(n)
                .map(|v| v.to_str().unwrap().to_string())
                .unwrap_or_default()
        };
        assert_eq!(hdr("x-content-type-options"), "nosniff", "{what}");
        assert_eq!(hdr("x-frame-options"), "DENY", "{what}");
        assert_eq!(hdr("referrer-policy"), "no-referrer", "{what}");
        let csp = hdr("content-security-policy");
        for part in [
            "default-src 'self'",
            "script-src 'self'",
            "object-src 'none'",
            "base-uri 'none'",
            "frame-ancestors 'none'",
        ] {
            assert!(csp.contains(part), "{what}: {csp}");
        }
        assert!(!csp.contains("script-src 'self' 'unsafe"), "{what}: {csp}");
    }
    let h = Harness::start(|_| {}).await;
    check(&h.get("/").await, "not-built page");
    h.stop().await;

    let ui = tempfile::tempdir().unwrap();
    std::fs::write(ui.path().join("index.html"), "<html>SPA</html>").unwrap();
    std::fs::create_dir(ui.path().join("assets")).unwrap();
    std::fs::write(ui.path().join("assets/app.js"), "console.log(1)").unwrap();
    let h = Harness::start_with_ui(|_| {}, Some(ui.path().to_path_buf())).await;
    for path in [
        "/",
        "/assets/app.js",
        "/verdicts/12",
        "/api/stats",
        "/api/nope",
    ] {
        check(&h.get(path).await, path);
    }
    let r = h
        .http
        .put(format!("{}/api/policy", h.base))
        .header("origin", "http://evil.example")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    check(&r, "refused PUT");
    // No CORS: other origins get no permission to read the API.
    let r = h
        .http
        .get(format!("{}/api/events", h.base))
        .header("origin", "http://evil.example")
        .send()
        .await
        .unwrap();
    assert!(r.headers().get("access-control-allow-origin").is_none());
    h.stop().await;
}

/// Guessing the admin token is cut off: after repeated wrong tokens from one address,
/// that address is refused (429) for a while, even with the right token.
#[tokio::test(flavor = "multi_thread")]
async fn repeated_wrong_admin_tokens_are_throttled() {
    let token = "right-token-0123456789";
    let opts = ServeOptions {
        admin_token: Some(token.into()),
        ..Default::default()
    };
    let h = Harness::start_serving(|_| {}, None, Limits::default(), "127.0.0.1:0", opts).await;
    let mut p: Value = h.get("/api/policy").await.json().await.unwrap();
    p["mode"] = json!("monitor");
    let put = |auth: String| {
        h.http
            .put(format!("{}/api/policy", h.base))
            .header("authorization", auth)
            .json(&p)
            .send()
    };
    for i in 0..customs::server::MAX_TOKEN_FAILURES {
        let r = put(format!("Bearer wrong-{i:02}-0123456789"))
            .await
            .unwrap();
        assert_eq!(r.status(), 401, "attempt {i}");
    }
    let r = put(format!("Bearer {token}")).await.unwrap();
    assert_eq!(r.status(), 429);
    assert!(r.headers().get("retry-after").is_some());
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["code"], "too_many_attempts");
    assert_eq!(h.engine.policy().mode, customs::config::Mode::Enforce);
    // Reads are not affected.
    assert_eq!(h.get("/api/policy").await.status(), 200);
    h.stop().await;
}

/// Package names are checked at the API boundary: anything a registry could not hold is a
/// 400, so a name cannot add a query, a fragment or `..` segments to the upstream URL the
/// server requests with its registry credentials.
#[tokio::test(flavor = "multi_thread")]
async fn api_refuses_names_that_are_not_package_names() {
    let h = Harness::start(|_| {}).await;
    for (eco, name) in [
        ("pypi", "six?x=1"),
        ("pypi", "six#frag"),
        ("pypi", "../../admin"),
        ("pypi", "six/1.0.0"),
        ("pypi", "-six"),
        ("npm", "left-pad?write=true"),
        ("npm", "@scope/pkg/../../-/user/x"),
        ("npm", "../-/whoami"),
        ("npm", "a%2fb"),
    ] {
        let (status, v) = h.check(eco, name, None).await;
        assert_eq!(status, 400, "{eco} {name}: {v}");
        assert_eq!(v["error"], "invalid package name", "{eco} {name}");
        let r = h
            .http
            .get(format!("{}/api/diff", h.base))
            .query(&[("ecosystem", eco), ("name", name)])
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400, "diff {eco} {name}");
    }
    // Real names still pass.
    assert_eq!(h.check("pypi", "goodpkg", Some("1.0.0")).await.0, 200);
    assert_eq!(h.check("npm", "@scope/lib", None).await.0, 200);
    assert_eq!(h.check("npm", "plainlib", None).await.0, 200);
    h.stop().await;
}
