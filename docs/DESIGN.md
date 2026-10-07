# Customs: design

Customs is a package firewall for AI coding agents. It sits between a package manager
(pip, uv, npm, pnpm, yarn) and the public registry, inspects every package archive before
it reaches the machine, and blocks archives that a malware classifier trained on real
malicious packages scores as dangerous. It also plugs into Claude Code as a PreToolUse hook,
so an agent that tries to `pip install` a hallucinated or malicious package is stopped
before the command runs.

This document is the contract between components. Anything that crosses a component
boundary (feature names, artifact formats, HTTP routes, JSON shapes) is defined here.

## 1. Why

Coding agents now install dependencies on their own. Two threats follow:

1. **Malicious packages.** Hundreds of thousands of malicious npm and PyPI packages have been
   reported (the OSSF malicious-packages dataset alone lists over 230K). Most execute at
   install time (`setup.py`, npm `preinstall`/`postinstall`) or import time, steal
   credentials, or download a second stage.
2. **Slopsquatting.** LLMs hallucinate plausible package names. Attackers register those
   names. An agent that trusts its own suggestion installs the attacker's package.

Existing defenses are either commercial, rule-based heuristics, or vulnerability scanners
(CVE databases) that say nothing about a brand-new malicious upload. Customs combines a
learned detector, registry-metadata policy rules, and agent integration in one local tool.

## 2. Components

```
                +---------------------- customs (Rust binary) ----------------------+
 pip / npm ---> | registry proxy  ->  policy engine  ->  scanner  ->  model ensemble  | ---> pypi.org / registry.npmjs.org
 Claude Code -> | hook / check API                                                  |
 browser  ----> | dashboard (static React app) + REST + SSE + /metrics              |
                |                     SQLite (events, verdicts) + artifact cache     |
                +-------------------------------------------------------------------+

 python/customs_ml   dataset build, training, evaluation, model export (offline)
```

| Path | Language | Role |
|---|---|---|
| `crates/customs-scan` | Rust | Safe archive unpacking and static feature extraction. Library plus `customs-scan` CLI (batch JSONL mode for training). Single implementation of features used by training and serving, so there is no train/serve skew. |
| `crates/customs-model` | Rust | Loads exported model artifacts and runs inference: gradient-boosted trees, the package-name model, and the code neural network. Produces calibrated risk plus per-feature contributions. |
| `crates/customs-py` | Rust (PyO3) | Python bindings for `customs-scan` (`import customs_scan`), built with maturin. |
| `crates/customs` | Rust | The `customs` binary: proxy server, policy engine, REST API, Claude Code hook, CLI. |
| `python/customs_ml` | Python | Dataset pipeline, dedup and splits, training (LightGBM, PyTorch), evaluation, baselines, export. |
| `web/` | TypeScript, React | Dashboard, built by Vite and served by the proxy. |
| `models/` | artifacts | Exported model files loaded by `customs-model`. |
| `deploy/` | Docker, k8s | Container image, compose file, Kubernetes manifests. |

## 3. Safety rules for handling malware

- Malware samples are never executed, imported, or installed. Analysis is static only.
- Samples live outside the repository (default `$CUSTOMS_DATA`, for example
  `/tmp/customs-data`). Nothing derived from a sample other than numeric features, labels,
  and short evidence strings in evaluation reports is committed.
- Archive unpacking is hardened: no absolute paths, no `..` traversal, no symlinks or
  hardlinks followed, per-file and total size caps, entry-count cap, nesting-depth cap,
  compression-ratio cap (zip bomb defense). The scanner reads archives in memory or into a
  private temp dir and never sets executable bits.

## 4. Feature specification (schema version 1)

`customs-scan` produces, for one archive:

```json
{
  "schema_version": 1,
  "ecosystem": "pypi" | "npm",
  "archive": "foo-1.0.0.tar.gz",
  "sha256": "...",
  "name": "foo",              // from manifest when available, else from filename
  "version": "1.0.0",
  "features": { "<name>": <number>, ... },   // fixed key set, all keys always present
  "evidence": [ { "indicator": "proc_exec", "file": "setup.py", "line": 12, "snippet": "os.system(...)" } ],
  "install_surface": ["setup.py", "package.json:scripts.postinstall", "index.js"],
  "tokens": ["os", ".", "system", "(", ...],  // only with --tokens; install-surface token stream for the neural model
  "errors": []
}
```

### 4.1 Code surfaces

Every indicator is counted on two surfaces and emitted with a prefix:

- `inst_`: code that runs at install or import time without the user calling anything.
  PyPI: `setup.py`, `setup.cfg` cmdclass targets when resolvable, every top-level
  `__init__.py` of a package directory, `*.pth` files. npm: commands in `package.json`
  `scripts.preinstall|install|postinstall|prepare|preprepare|postprepare`, files those commands
  reference (`node x.js`), and the `main` entry file (default `index.js`).
- `all_`: every source file in the archive (`.py`, `.js`, `.mjs`, `.cjs`, `.ts`, `.sh`,
  `.bat`, `.ps1`, `.cmd`).

### 4.2 Indicator families (each emitted as `inst_<x>` and `all_<x>` counts)

| Indicator | Meaning (Python and JavaScript patterns) |
|---|---|
| `proc_exec` | `subprocess.*`, `os.system`, `os.popen`, `os.exec*`, `os.spawn*`, `pty.spawn`, `child_process`, `exec(`/`execSync`/`spawn`/`fork` from child_process |
| `dyn_code` | `eval(`, `exec(`, `compile(`, `__import__(`, `importlib.import_module`, `new Function(`, `Function(`, `vm.run*`, `require(` with a non-literal argument |
| `network` | `requests.`, `urllib`, `http.client`, `socket.`, `httpx`, `aiohttp`, `fetch(`, `axios`, `http.request`, `https.get`, `net.connect`, `dns.lookup`, `XMLHttpRequest`, `WebSocket` |
| `decode_obf` | `base64.b64decode`, `b64decode`, `atob(`, `Buffer.from(... 'base64'|'hex')`, `zlib.decompress`, `marshal.loads`, `codecs.decode`, `bytes.fromhex`, `String.fromCharCode`, `unescape(`, `rot13` |
| `env_access` | `os.environ`, `os.getenv`, `process.env` |
| `secret_paths` | strings naming credential stores: `.ssh`, `id_rsa`, `.aws/credentials`, `.npmrc`, `.pypirc`, `.git-credentials`, `.docker/config.json`, `Login Data`, `Local State`, `cookies.sqlite`, `leveldb`, `Discord`, `wallet`, `keychain`, `/etc/passwd`, `/etc/shadow`, `.kube/config` |
| `persistence` | `crontab`, `.bashrc`, `.zshrc`, `.profile`, `Startup` folder, `Run` registry key, `LaunchAgents`, `systemd`, `schtasks` |
| `recon` | `platform.node`, `socket.gethostname`, `getpass.getuser`, `os.getlogin`, `os.hostname`, `os.userInfo`, `os.networkInterfaces`, `whoami`, `ifconfig`, `ipconfig`, `uname` |
| `download_exec` | `curl ... | sh`, `wget ... | sh`, `powershell -e`/`-enc`, `Invoke-WebRequest`, `iwr `, `certutil -urlcache`, `bitsadmin`, `chmod +x` followed by execution, writing a file then executing it |
| `exfil_endpoint` | URLs or hosts commonly used for exfiltration or callbacks: `discord.com/api/webhooks`, `discordapp.com/api/webhooks`, `api.telegram.org`, `pastebin.com`, `ngrok`, `webhook.site`, `pipedream.net`, `burpcollaborator`, `oast.`, `interact.sh`, `requestbin`, `transfer.sh`, `ipinfo.io`, `ifconfig.me`, `api.ipify.org` |
| `ip_url` | URL whose host is an IPv4 literal |
| `url` | any `http://` or `https://` URL literal |
| `file_write` | `open(... 'w'|'wb'|'a')`, `fs.writeFile*`, `fs.createWriteStream`, `shutil.copy*`, `os.chmod` |
| `crypto_wallet` | `bitcoin`, `ethereum`, `metamask`, `exodus`, `electrum`, wallet address regexes |

### 4.3 Structural and obfuscation features (no prefix unless stated)

`n_files`, `total_bytes`, `max_file_bytes`, `n_py`, `n_js`, `n_shell` (sh, bat, ps1, cmd),
`n_binary` (ELF, PE, Mach-O magic), `n_hidden` (dotfiles), `n_minified_js` (avg line length
over 500), `has_setup_py`, `has_pyproject`, `has_package_json`, `n_npm_install_scripts`,
`inst_n_lines`, `inst_bytes`, `all_n_lines`,
`inst_max_line_len`, `all_max_line_len`, `inst_max_str_entropy`, `all_max_str_entropy`,
`inst_mean_str_entropy`, `inst_longest_b64_run`, `all_longest_b64_run`, `inst_hex_escape_count`,
`all_hex_escape_count`, `inst_obf_ident_ratio` (identifiers matching `_0x[0-9a-f]+` or of
length over 30 with high entropy, over all identifiers), `inst_nonascii_ratio`,
`inst_long_line_ratio` (lines over 1000 chars over all lines).

### 4.4 Manifest features

`meta_desc_len`, `meta_has_homepage`, `meta_has_repo`, `meta_has_author_email`,
`meta_has_license`, `meta_n_deps`, `meta_readme_bytes`, `meta_version_major`,
`meta_version_is_zero` (0.0.0 or 0.0.1 style), `meta_version_huge` (major at least 90, a
dependency-confusion tell), `meta_n_keywords`.

Features never include the package name or registry metadata (age, downloads). Those are
unavailable for removed malicious packages and would leak the label. Name signals live in
the separate name model; registry signals live in the policy engine.

### 4.5 Name features (computed by `customs-model::name`)

Given `(ecosystem, name)` and the shipped popular-package list for that ecosystem:
`len`, `n_digits`, `n_hyphens`, `n_underscores`, `n_dots`, `min_edit_distance` (Damerau
Levenshtein to the top-N popular names, excluding exact matches), `nearest_popular`,
`is_popular`, `contains_popular_token` (a popular name appears as a hyphen/underscore token
with extra tokens), `scope_squat` (npm scope differs from a popular scoped package),
`char_ngram_score` (logistic model over hashed character 1 to 4 grams), `keyboard_typo`
(edit is an adjacent-key substitution).

## 5. Model artifacts (`models/`)

All artifacts are JSON (small, diffable, and loadable without native dependencies).

`models/manifest.json`
```json
{ "model_version": "2026.10.0", "feature_schema_version": 1,
  "code_gbdt": "code_gbdt.json", "name_model": "name_model.json",
  "code_nn": "code_nn.json", "ensemble": "ensemble.json",
  "popular_names": { "pypi": "popular_pypi.txt", "npm": "popular_npm.txt" } }
```

`code_gbdt.json`: tree ensemble in a format independent of LightGBM:
```json
{ "feature_names": ["inst_proc_exec", ...], "base_score": 0.0, "objective": "binary",
  "trees": [ { "nodes": [
      { "split": 3, "threshold": 0.5, "left": 1, "right": 2, "default_left": true },
      { "leaf": -0.42 }, { "leaf": 1.31 } ] } ],
  "calibration": { "method": "isotonic", "x": [...], "y": [...] } }
```
Inference: raw = base_score + sum of leaf values; a missing value or NaN follows
`default_left`; comparisons are `value <= threshold` go left. Probability = sigmoid(raw),
then calibrated by piecewise-linear interpolation over `(x, y)`. Contributions use the
Saabas path method (difference in expected node value along the decision path), which
needs per-node `value` (mean leaf output under that node); the exporter writes `value` on
every split node.

`name_model.json`: logistic regression over the name features plus hashed character
n-grams (`n_buckets`, `ngram_min`, `ngram_max`, `weights`, `bias`, hash = FNV-1a 32-bit of
the UTF-8 n-gram with `^`/`$` boundary marks, modulo `n_buckets`).

`code_nn.json`: a small convolutional network over install-surface tokens:
`vocab` (token to id, with `<unk>` = 1 and `<pad>` = 0), `max_len`, embedding matrix,
conv layers (kernel sizes, weights, biases), ReLU, global max pool, dense layers. Weights
stored as base64 little-endian float32 with shapes. The Rust implementation must match
PyTorch output within 1e-4 on shipped parity fixtures (`models/parity/*.json`).

`ensemble.json`: stacking weights over `(code_gbdt_logit, code_nn_logit, name_logit)` plus
isotonic calibration of the final score, and decision thresholds chosen on the validation
split: `{"warn": t1, "block": t2, "target_fpr_block": 0.001}`.

## 6. Verdict

```json
{
  "ecosystem": "pypi", "name": "foo", "version": "1.0.0", "artifact": "foo-1.0.0.tar.gz",
  "sha256": "...",
  "decision": "allow" | "warn" | "block",
  "risk": 0.97,
  "scores": { "code_gbdt": 0.99, "code_nn": 0.93, "name": 0.71 },
  "policy_hits": [ { "rule": "min_age_days", "severity": "block", "detail": "published 2 hours ago (policy: 3 days)" } ],
  "reasons": [ { "feature": "inst_proc_exec", "value": 2, "contribution": 1.84, "label": "Runs shell commands at install time" } ],
  "evidence": [ { "indicator": "proc_exec", "file": "setup.py", "line": 12, "snippet": "os.system(\"curl ...\")" } ],
  "scanned_ms": 14, "model_version": "2026.10.0", "cached": false
}
```
`decision` is the most severe of the model decision and every policy hit. In `monitor`
mode the proxy records the verdict and serves the artifact anyway.

## 7. HTTP interface of `customs serve`

Default bind `127.0.0.1:7878`.

Registry proxy:
- `GET /pypi/simple/` and `GET /pypi/simple/{project}/`: proxied PEP 503 HTML (and PEP 691
  JSON when requested by Accept), with every file URL rewritten to `/pypi/files/{path}`.
  A 404 upstream is recorded as a `nonexistent_package` event (slopsquat signal).
- `GET /pypi/files/{path}`: fetches `https://files.pythonhosted.org/{path}`, scans, decides,
  streams the archive or returns 403 with a plain-text explanation.
- `GET /npm/{package}` (scoped: `/npm/@scope%2fname` and `/npm/@scope/name`): packument with
  `dist.tarball` rewritten to `/npm/{package}/-/{file}.tgz`.
- `GET /npm/{package}/-/{file}.tgz`: fetch, scan, decide, stream or 403.

API (JSON):
- `POST /api/check` `{ "ecosystem": "pypi", "name": "foo", "version": null }`: resolve
  version (latest when null), apply policy, fetch, scan, return a verdict. Used by the hook
  and the CLI.
- `GET /api/events?limit=&before=`: install attempts, newest first.
  Event: `{ "id", "ts", "ecosystem", "name", "version", "client", "kind": "install" | "check" | "nonexistent_package", "decision", "risk", "verdict_id" }`.
- `GET /api/events/stream`: Server-Sent Events, one `event: install` per new event.
- `GET /api/verdicts/{id}`: full verdict.
- `GET /api/stats`: totals by decision and ecosystem, blocks per day, top reasons.
- `GET /api/policy`, `PUT /api/policy`: the active policy (see below).
- `GET /api/model`: model manifest and headline evaluation metrics.
- `GET /metrics`: Prometheus text format. `GET /healthz`.
- `GET /` and static assets: the dashboard.

## 8. Policy (`customs.toml`)

```toml
mode = "enforce"            # or "monitor"
warn_threshold = "model"    # "model" uses ensemble.json thresholds, or a number
block_threshold = "model"
min_age_days = 3            # block versions published less recently (registry metadata)
block_nonexistent = true    # requesting a name the registry does not know is recorded and denied in hooks
block_install_scripts_from_new = true  # npm install scripts in packages younger than min_age_days
allow = ["pypi:requests", "npm:react"]  # always allow (exact names)
deny  = ["npm:event-stream@3.3.6"]
[upstream]
pypi_simple = "https://pypi.org/simple"
pypi_files = "https://files.pythonhosted.org"
pypi_json = "https://pypi.org/pypi"
npm = "https://registry.npmjs.org"
```

## 9. Claude Code integration

`customs hook claude-code` is a PreToolUse command hook for the `Bash` tool. It parses the
command for package installs (`pip install`, `pip3 install`, `python -m pip install`,
`uv pip install`, `uv add`, `poetry add`, `pipx install`, `npm install|i|add`,
`pnpm add|install`, `yarn add`, `bun add`, `npx <pkg>`), resolves each requirement, calls the
running server's `/api/check` (or scans in-process when no server is running), and returns
a PreToolUse decision: `deny` with an explanation when any package is blocked, `ask` when
any is warned, nothing otherwise. Local paths, URLs, `-r requirements.txt` and editable
installs are handled (requirements files are read and each line checked).

## 10. Evaluation protocol (python/customs_ml)

- Data: Datadog malicious-software-packages-dataset (real npm and PyPI samples), OSSF
  malicious-packages (names, for the name model), benign archives downloaded from PyPI and
  npm (popular packages plus a long-tail sample reached through dependency crawling and
  recent uploads), filtered against the OSSF list.
- Dedup: malware campaigns publish hundreds of near-identical packages. Samples are
  clustered by MinHash over install-surface token shingles; splits are by cluster so no
  campaign appears in both train and test.
- Splits: a temporal split (train on samples first seen before a cutoff, test after) is the
  headline; a cluster-grouped random split is reported alongside.
- Metrics: ROC AUC, PR AUC, recall at FPR 0.1% and 1%, calibration (Brier, reliability
  curve), bootstrap 95% CIs. Stratified by ecosystem and by package size so a size shortcut
  cannot hide.
- Baseline: Datadog GuardDog run on the same test archives; compared at matched FPR.
- Robustness: semantics-preserving obfuscation transforms applied to held-out malicious
  samples (identifier renaming, string splitting and concatenation, base64 wrapping of
  payloads, moving code from install scripts into imported modules); report recall drop.
- Results are written to `docs/EVALUATION.md` and `models/metrics.json`.
