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
| `crates/customs` | Rust | The `customs` binary: proxy server, policy engine, REST API, Claude Code hook, MCP server, CLI. |
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

Implementation details (`customs-scan`, schema 1):

- PyPI install surface, in order: `setup.py`; `setup.cfg` `cmdclass` targets
  (`install = pkg.mod.Cls` resolves `pkg/mod.py`, `pkg/mod/__init__.py`, or the same under
  `src/`); an in-tree PEP 517 backend (`pyproject.toml` `build-system.backend-path`), which
  runs during the build; `<pkg>/__init__.py` and `src/<pkg>/__init__.py` for every directory
  one level below the root (or below `src/`), sorted; every `*.pth` file at any depth, sorted.
  Wheels use the same rules (their root is site-packages).
- npm install surface, in order: for each hook in the order `preinstall, install,
  postinstall, preprepare, prepare, postprepare`, the command string itself (a shell unit
  named `package.json:scripts.<hook>`), inline code it runs (`node -e`/`--eval`/`-p`,
  `sh|bash -c`, `python -c`, `powershell -Command`, analyzed in that language under the same
  name), and files it runs (`node [flags] x`, `node -r x`, `sh x.sh`, `python x.py`,
  `powershell -File x`, `./x`), resolved like Node (`x`, `x.js`, `x.cjs`, `x.mjs`,
  `x/index.js`). From those files and from inline JavaScript, relative `require`/`import`
  specifiers are followed two levels deep (at most 32 files), so moving a payload into a
  helper module keeps it on the install surface. Then `main`. `.json` targets are never code.
- `all_` is every source file (including files inside nested archives, see 4.7) plus every
  install-surface unit, so `all_<x> >= inst_<x>` always holds and npm script commands count
  on both surfaces.
- Each file is analyzed once; a unit is in `install_surface` (report field) in the order
  above, without duplicates.

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

How indicators are counted (`customs-scan`, schema 1):

- Python and JavaScript are tokenized by a hand-written lexer that drops comments and
  separates identifiers, string literals (template literal chunks and `${...}` code are
  split), regex literals, numbers and punctuation. Call and module patterns (`os.system`,
  `eval(`, `require('child_process')`) match tokens only, so a name in a comment never
  counts and a name inside a string never counts as a call. Python module names
  (`requests`, `socket`, ...) count when imported or dereferenced (`x.`), not when used as a
  plain variable. JavaScript `exec(`/`spawn(`/`fork(` count only in files that reference
  `child_process`. Method calls (`re.compile`, `cursor.exec`) and `def`s do not count.
- String-content patterns (`secret_paths`, `persistence`, `recon` command names,
  `download_exec`, `exfil_endpoint`, `ip_url`, `url`, `crypto_wallet` words, and
  `curl`/`wget` as `network`) are regexes over string literal contents. Shell files and npm
  script commands are matched as whole comment-stripped text, with extra shell rules:
  `nc`/`ncat`/`netcat`/`irm`/`scp`/`ftp`/`telnet` (network), `sh -c`/`cmd /c`/`powershell`/
  `nohup` (proc_exec), `eval`/`iex`/`node -e`/`python -c` (dyn_code), `$env:`/`printenv`/
  `%VAR%` (env_access), redirection to a file (not `/dev/null`), `chmod`, `tee`,
  `Set-Content`, `Out-File` (file_write).
- Every match counts once (counts, not booleans). Additions to the table: `exfil_endpoint`
  also matches `interactsh`, `pipedream.com`, `dnslog.cn`, `ceye.io`, `hookbin.com`,
  `canarytokens`; `secret_paths` also matches `id_dsa|id_ecdsa|id_ed25519`, `.bash_profile`
  is `persistence`, and `decode_obf` also matches `base64 -d`, `FromBase64String`, `xxd -r`
  and zlib/gzip/lzma/bz2 decompression in both languages.
- `secret_paths` does not count `discord` when it is part of a `discord.com`/`discordapp.com`
  host (that is an `exfil_endpoint`). `ip_url` excludes loopback (`127.0.0.0/8`) and
  `0.0.0.0`. Wallet address regexes (BTC base58 and bech32, ETH `0x` + 40 hex, TRON) apply to
  whole string literals only.
- `download_exec` additionally counts once per Python/JavaScript file that has `network`,
  `file_write` and `proc_exec` all nonzero (fetch, write, run).

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

Added in implementation (still schema 1): `inst_n_files` (number of install-surface units),
`n_links` (symlink and hardlink entries skipped), `n_unsafe_paths` (absolute or `..` entries
skipped).

Definitions: file counts include every regular file, nested-archive entries too
(`n_js` counts `.js .mjs .cjs .ts`; `n_minified_js` only `.js .mjs .cjs`); `n_hidden` counts
files with any path component starting with `.`; `has_*` look at the package root only.
Line lengths are in bytes. String entropy is Shannon entropy in bits per byte over string
literals of at least 20 bytes (shell: quoted strings); the mean is over all such strings on
the surface. `longest_b64_run` is the longest run of `[A-Za-z0-9+/=_-]` inside a string
literal (shell: quoted strings and words). `hex_escape_count` counts `\xNN`, `\uNNNN` and
`\u{...}` in the raw text. "High entropy" for identifiers means above 4.3 bits per byte.
Ratios are 0 when the denominator is 0.

Feature order (`feature_names()`, 70 names): the 14 `inst_<indicator>` in table order, the
14 `all_<indicator>`, then the 28 features above in the order listed, then `inst_n_files`,
`n_links`, `n_unsafe_paths`, then the 11 manifest features in the order listed in 4.4.

### 4.4 Manifest features

`meta_desc_len`, `meta_has_homepage`, `meta_has_repo`, `meta_has_author_email`,
`meta_has_license`, `meta_n_deps`, `meta_readme_bytes`, `meta_version_major`,
`meta_version_is_zero` (0.0.0 or 0.0.1 style), `meta_version_huge` (major at least 90, a
dependency-confusion tell), `meta_n_keywords`.

Sources: npm `package.json`; PyPI `PKG-INFO` or `*.dist-info/METADATA`, then
`pyproject.toml` (`[project]`, `[tool.poetry]`), `setup.cfg`, then literal keyword arguments
of `setup(...)` in `setup.py`; each field takes the first source that has it. Details:
`meta_desc_len` is the character length of `Summary` (PyPI) or `description` (npm);
`meta_n_deps` counts `Requires-Dist` without an `extra ==` marker (npm: `dependencies`);
`meta_readme_bytes` is the size of a root `README*` file, else the long description length;
`meta_version_is_zero` means major 0 and minor 0; unparsable versions give 0 for all
version features.

Features never include the package name or registry metadata (age, downloads). Those are
unavailable for removed malicious packages and would leak the label. Name signals live in
the separate name model; registry signals live in the policy engine.

### 4.5 Name features (computed by `customs-model::name`)

Given `(ecosystem, name)` and the popular-package list for that ecosystem (one normalized
name per line, most popular first):

- normalize: PyPI lowercases and collapses runs of `-`, `_`, `.` to `-` (PEP 503); npm
  lowercases and keeps the scope.
- `bare(n)`: the part after the first `/` when `n` starts with `@` and contains `/`, else `n`.
- `len`: Unicode characters of `bare`; `n_digits`: ASCII digits in `bare`; `n_hyphens`,
  `n_underscores`, `n_dots`: counts of `-`, `_`, `.` in `bare`.
- `has_scope`: the normalized name starts with `@`. `is_popular`: the normalized full name
  is in the popular set.
- `d`: minimum optimal string alignment distance (insert, delete, substitute, adjacent
  transposition; no substring edited twice) between `bare(name)` and `bare(p)` over
  Unicode characters, ignoring exact matches (distance 0); values above `max_distance`
  become `max_distance + 1`, as does an empty list. `dist1`, `dist2`, `dist3` are `d == 1`,
  `d == 2`, `d == 3` as 0/1. The nearest name (ties: the more popular one) is reported for
  explanations.
- `contains_popular_token`: tokens are `bare` split on `-`, `_`, `.` with empty tokens
  dropped; `long_pop` is the set of `bare(p)` with at least 4 characters; 1 when there is
  more than one token, `bare` is not in `long_pop`, and some token is.
- `digit_suffix`: `bare` is non-empty and ends in an ASCII digit.
- character n-grams: `s = "^" + normalized + "$"`; every window of `n` Unicode characters
  for `n` in `ngram_min..=ngram_max`; FNV-1a 32-bit (offset `0x811C9DC5`, prime
  `0x01000193`) over the window's UTF-8 bytes, modulo `n_buckets`; the set of distinct
  buckets is used (each counts once). `char_ngram_score` is the n-gram part of the logit.

Scoring one name against about 5,000 popular names takes well under a millisecond
(length buckets, a character-histogram lower bound, and an early-exit banded DP).

### 4.6 Token stream (`tokens`, input of the code neural network)

Produced only on request (`--tokens`, `tokens=True`). Rules, which training consumes
verbatim (changing them requires a schema version bump):

1. Install-surface units are visited in `install_surface` order (inline code right after
   its script command). Each unit starts with the marker token `<file>`.
2. Comments and Python newline markers produce no tokens.
3. Python and JavaScript identifiers are lowercased (`Popen` becomes `popen`).
4. String literals and JavaScript regex literals become `<str>`, except when the content is
   1 to 24 bytes and only ASCII letters, digits and `_ - . : / @`: then the lowercased
   content is kept without quotes (`'child_process'` becomes `child_process`,
   `"discord.com"` stays `discord.com`). Template literal chunks are separate strings.
5. Numbers become `<num>`.
6. Punctuation is kept verbatim; multi-character operators are single tokens (`==`, `=>`,
   `**`, `...`, `?.`, `//` in Python).
7. Shell units (npm script commands, `.sh .bat .ps1 .cmd`): words follow rule 4, quoted
   strings follow rule 4, operators (`|`, `||`, `&&`, `;`, `>`, `>>`, `(`, `)`) are kept.
8. The stream is truncated at 4096 tokens in total.

### 4.7 Archive handling

Formats are detected from content, not the file name: gzip and bzip2 tarballs, plain tar,
zip (sdist `.zip`, wheels). Defaults: 20,000 entries, 32 MiB per entry (larger entries are
counted with their declared size but not analyzed), 256 MiB decompressed in total, a
compression ratio of 250 (checked once 1 MiB has been decompressed), and one level of
nested archives (`.zip .whl .tar.gz .tgz .tar.bz2 .tar .egg` inside the package are expanded
into `outer!/inner` paths that count toward `all_` and the structural features only).
Exceeding the entry, total or ratio cap rejects the archive; unsafe and link entries are
skipped and counted. Only content needed for analysis is kept in memory (source, manifest,
README and nested-archive entries in full, a short magic-number prefix otherwise).

Root normalization: top-level directories are stripped while the current level holds
exactly one directory and nothing besides sidecar `*.json` files (other than
`package.json`), stopping at a level that has `package.json`, `PKG-INFO`, `setup.py`,
`setup.cfg`, `pyproject.toml` or a `*.dist-info/` directory. This removes `name-version/`
from sdists, `package/` from npm tarballs, and the wrapper directories and
`package_info-*.json` sidecars of sample collections such as the Datadog dataset
(`tmp/tmpXXXX/name/name-version/`). Paths whose trailing components repeat
(`pkg/mod.py/pkg/mod.py`, an artifact of re-extracted wheels in that dataset) collapse to
`pkg/mod.py`. Ecosystem detection: an explicit argument wins; otherwise a stripped
`package/` with `package.json` is npm; `PKG-INFO`, `setup.py`, `pyproject.toml`, `setup.cfg`
or `*.dist-info/METADATA` at the root is PyPI; a root `package.json` is npm; then the file
name decides (`.tgz` npm; `.whl .tar.gz .zip .tar.bz2` PyPI). Name and version come from the
manifest, else from the file name (`name-1.0.tar.gz`, wheel tags, and dated sample names
`YYYY-MM-DD-name-v1.0.zip`).

Evidence: at most `max_evidence` (default 50) items; install-surface hits first, and within
each surface one hit per indicator in turn, most telling first (`download_exec`,
`exfil_endpoint`, `dyn_code`, `decode_obf`, `proc_exec`, `secret_paths`, `persistence`,
`ip_url`, `network`, `recon`, `env_access`, `crypto_wallet`, `file_write`, `url`). `line` is
1-based (for npm script units, the line of the script key in `package.json`); `snippet` is
the trimmed source line cut to 160 characters.

CLI batch mode (`customs-scan batch --input paths.txt --output out.jsonl [--tokens]
[--jobs N]`) writes one line per input path in input order: the report plus a `path` field,
or `{"archive": "<path>", "error": "<message>"}` when that archive fails.

## 5. Model artifacts (`models/`)

All artifacts are JSON (small, diffable, and loadable without native dependencies).
Float tensors `T` are `{"shape": [...], "data": "<base64 of little-endian f32, row-major>"}`.
The server loads `models/manifest.json`; when it is absent it falls back to the untrained
placeholders in `models/dev/` (marked `"untrained": true`). A component whose manifest
entry is missing or null is not shipped.

`models/manifest.json`
```json
{ "model_version": "2026.10.0", "feature_schema_version": 1,
  "code_gbdt": "code_gbdt.json", "name_model": "name_model.json",
  "code_nn": "code_nn.json", "ensemble": "ensemble.json",
  "popular_names": { "pypi": "popular_pypi.txt", "npm": "popular_npm.txt" },
  "metrics": "metrics.json", "untrained": false }
```
`feature_schema_version` must equal the one `customs-scan` produces or loading fails.

`code_gbdt.json`: tree ensemble in a format independent of LightGBM:
```json
{ "feature_names": ["inst_proc_exec", ...], "base_score": 0.0, "objective": "binary",
  "trees": [ { "nodes": [
      { "split": 3, "threshold": 0.5, "left": 1, "right": 2, "default_left": true, "value": 0.12 },
      { "leaf": -0.42 }, { "leaf": 1.31 } ] } ],
  "calibration": { "method": "isotonic", "x": [...], "y": [...] } }
```
Inference: features are looked up by name in the scanner's feature map (a missing feature
is NaN); raw = base_score + sum of leaf values; NaN follows `default_left`; `value <=
threshold` goes left. Children must come after their parent in `nodes`. Probability =
sigmoid(raw), then calibrated (when `calibration` is not null) by piecewise-linear
interpolation over `(x, y)` with clamping at both ends. Saabas contributions: bias =
base_score + sum of each tree's root `value` (or root leaf); at each split on the path,
`contribution[split] += child_value - node.value` where `child_value` is the child's
`leaf` or `value`. Bias plus contributions equals raw.

`name_model.json` (format `customs-name-lr-v1`):
```json
{ "format": "customs-name-lr-v1",
  "numeric_features": ["len","n_digits","n_hyphens","n_underscores","n_dots","has_scope",
                       "is_popular","dist1","dist2","dist3","contains_popular_token","digit_suffix"],
  "max_distance": 4, "ngram_min": 1, "ngram_max": 4, "n_buckets": 65536, "hash": "fnv1a32",
  "ecosystems": { "pypi": { "popular": "popular_pypi.txt", "mean": [12 floats], "std": [12 floats],
                            "numeric_weights": [12 floats],
                            "ngram_weights": "<base64 f32 x n_buckets>", "bias": -3.1 },
                  "npm": { ... } } }
```
Popular files are relative to `models/`. `logit = bias + sum_i ((x_i - mean_i) / std_i) *
numeric_weights_i + sum over distinct buckets of ngram_weights[bucket]` (a `std` of 0 is
treated as 1). Features are defined in 4.5. The model outputs the logit and an explanation
("1 edit from popular package 'requests'", "wraps popular name 'requests' in extra words").

`code_nn.json` (format `customs-code-cnn-v1`): a small convolutional network over the
install-surface tokens (`ScanReport.tokens`, scanned with `tokens: true`):
```json
{ "format": "customs-code-cnn-v1", "max_len": 512, "vocab": { "<pad>": 0, "<unk>": 1, "os": 2, ... },
  "embedding": T [V, D],
  "convs": [ { "kernel": 3, "weight": T [C, D, k], "bias": T [C] }, ... ],
  "dense": [ { "weight": T [out, in], "bias": T [out], "activation": "relu" | "none" }, ... ] }
```
Forward: ids = vocab lookup (unknown = 1) of the first `max_len` tokens; if fewer than
`max(16, largest kernel)`, right-pad with 0 to that length; x = embedding rows (L, D); per
conv `y[l][c] = bias[c] + sum_{d,j} w[c][d][j] * x[l+j][d]` for `l` in `0..L-k+1` (valid),
ReLU, max over `l`; concatenate convs in order; dense layers in order with their activation;
the single output is a logit (no sigmoid). An empty or absent token stream skips the CNN.
The Rust implementation must match PyTorch output within 1e-4 on shipped parity fixtures
(`models/parity/*.json`); `crates/customs-model/tests/gen_fixtures.py` is a numpy reference
of every formula in this section, checked to 1e-5.

`ensemble.json` (format `customs-ensemble-v1`):
```json
{ "format": "customs-ensemble-v1", "components": ["code_gbdt", "code_nn", "name"],
  "weights": { "code_gbdt": 1.2, "code_nn": 0.6, "name": 0.8 }, "bias": -0.3,
  "fallbacks": [ { "missing": ["code_nn"], "weights": {...}, "bias": -0.2 },
                 { "missing": ["name"], "weights": {...}, "bias": -0.1 },
                 { "missing": ["code_nn", "name"], "weights": {...}, "bias": 0.0 } ],
  "calibration": { "method": "isotonic", "x": [...], "y": [...] },
  "thresholds": { "warn": 0.42, "block": 0.91, "target_fpr_warn": 0.01, "target_fpr_block": 0.001 } }
```
Inputs are component logits (the uncalibrated gbdt raw score, the CNN logit, the name
logit). A component is unavailable when its artifact is not shipped or its input is absent
(no features, no tokens, no name). `z = bias + sum_c w_c * logit_c` over available
components, using the fallback whose `missing` set equals the unavailable set (a fallback
may carry its own `calibration`); when none matches, the primary weights are applied to
the components that ran (`weight_set` `"partial:<missing>"`). `risk = isotonic(sigmoid(z))`;
`risk >= block` blocks, `risk >= warn` warns. Verdict `scores` are per-component
probabilities: the gbdt calibrated probability, sigmoid of the CNN and name logits.

`metrics.json`: the evaluation summary served by `/api/model` (section 7).

## 6. Verdict

```json
{
  "id": 42, "ts": "2026-10-07T01:24:29.505Z",
  "ecosystem": "pypi", "name": "foo", "version": "1.0.0", "artifact": "foo-1.0.0.tar.gz",
  "sha256": "...",
  "decision": "allow" | "warn" | "block",
  "risk": 0.97,
  "model_decision": "block",
  "thresholds": { "warn": 0.5, "block": 0.9, "target_fpr_block": 0.001 },
  "scores": { "code_gbdt": 0.99, "code_nn": 0.93, "name": 0.71 },
  "policy_hits": [ { "rule": "min_age_days", "severity": "block", "detail": "published 2 hours ago (policy: 3 days)" } ],
  "reasons": [ { "feature": "inst_proc_exec", "value": 2, "contribution": 1.84, "label": "Runs shell commands at install time" } ],
  "evidence": [ { "indicator": "proc_exec", "file": "setup.py", "line": 12, "snippet": "os.system(\"curl ...\")" } ],
  "install_surface": ["setup.py"], "scan_errors": [],
  "scanned_ms": 14, "model_version": "2026.10.0", "cached": false, "mode": "enforce"
}
```
`decision` is the most severe of the model decision and every policy hit, except that an
allow-list entry makes it `allow` and a deny-list entry makes it `block` (deny wins over
allow). `risk` and component scores are `null` when that part of the model could not run
(for example a package that does not exist has only a name score). `thresholds` are the
effective ones (policy overrides applied). Policy `severity` is `allow` for informational
hits (`allow`, `not_scanned`), else `warn` or `block`. Rules: `deny`, `allow`,
`block_nonexistent`, `min_age_days`, `block_install_scripts_from_new`, `scan_error`
(scanner rejected the archive, warn), `not_scanned` (archive above the scan size limit).
`reasons` mix model features (positive contributions to the stacked logit, largest first)
and name signals (`name_dist1`, `name_contains_popular_token`, ...). In `monitor` mode the
proxy records the verdict and serves the artifact anyway (`mode` says which applied).

## 7. HTTP interface of `customs serve`

Default bind `127.0.0.1:7878`.

Registry proxy:
- `GET /pypi/simple/` and `GET /pypi/simple/{project}/`: proxied PEP 503 HTML (and PEP 691
  JSON when requested by Accept), with every file URL rewritten to `/pypi/files/{path}`
  (absolute, built from the request `Host`). A 404 upstream is recorded as a
  `nonexistent_package` event (slopsquat signal).
- `GET /pypi/files/{path}`: fetches `https://files.pythonhosted.org/{path}`, scans, decides,
  streams the archive or returns 403 with a plain-text explanation. The HTTP reason phrase
  is `Blocked by Customs: <rule or reason>`, which pip prints. PEP 658 `*.metadata` files
  pass through unscanned.
- `GET /npm/{package}` (scoped: `/npm/@scope%2fname` and `/npm/@scope/name`): packument with
  `dist.tarball` rewritten to `/npm/{package}/-/{file}.tgz`. `/npm/{package}/{version}` is
  also proxied. A 404 is recorded as `nonexistent_package`.
- `GET /npm/{package}/-/{file}.tgz`: fetch, scan, decide, stream or 403 with
  `{"error": "<explanation>"}` (npm prints `error`).
- `/npm/-/...` (audit and other registry endpoints) passes through unchanged.
- Artifact responses carry `x-customs-decision` and `x-customs-verdict` (verdict id).

API (JSON). CORS allows only `http://localhost:5173` (the Vite dev server).
- `POST /api/check` `{ "ecosystem": "pypi", "name": "foo", "version": null, "client": "cli" }`:
  `version` is null (latest), an exact version, a range (`>=1,<2`, `~=1.4`, `^1.2`, npm
  ranges), or an npm dist-tag; it resolves to the newest matching non-yanked version. The
  server applies policy, fetches (PyPI prefers the sdist, then a pure wheel, then the
  smallest wheel), scans, and returns a verdict. Errors: 400 bad input, 404
  `{ "error", "code": "nonexistent_package", "verdict": {...} }` when the registry does not
  know the name (the verdict carries the `block_nonexistent` decision), 422 no matching
  version, 502 upstream failure; all as `{ "error": "..." }`.
- `GET /api/events?limit=&before=&decision=&ecosystem=&kind=&q=`: a JSON array of events,
  newest first. `before` is an event id (pagination), `q` a case-insensitive name substring.
  Event: `{ "id", "ts", "ecosystem", "name", "version", "client", "kind": "install" | "check" | "nonexistent_package", "decision", "risk", "verdict_id" }`.
  `ts` is RFC 3339 UTC with milliseconds.
- `GET /api/events/stream`: Server-Sent Events, one `event: install` per new event of any
  kind (`id:` is the event id, `data:` the event JSON); `event: lagged` if a slow client
  missed events.
- `GET /api/verdicts/{id}`: full verdict (section 6).
- `GET /api/stats?days=30`: `{ "total", "by_decision": {allow, warn, block},
  "by_ecosystem": { "pypi": {allow, warn, block}, "npm": {...} },
  "by_kind": {install, check, nonexistent_package},
  "blocks_per_day": [ { "date": "YYYY-MM-DD", "count" } ],
  "top_reasons": [ { "feature", "label", "count" } ] }`. `blocks_per_day` has one entry per
  day of the window, zeros included; `top_reasons` counts policy rules and the top model
  reasons of warn and block verdicts.
- `GET /api/policy`, `PUT /api/policy`: the active policy as JSON with the `customs.toml`
  keys (thresholds are `"model"` or a number). `PUT` takes the full policy (omitted keys
  take their defaults), validates, persists to the policy file, and returns it; invalid
  input returns 400 `{ "error", "errors": [ { "field", "message" } ] }`.
- `GET /api/model`: the contents of `metrics.json` (under `metrics`, or merged when the file
  already has a `metrics` key) plus `model_version`, `feature_schema_version`, `untrained`,
  `thresholds` (effective), `model_thresholds`, `manifest`, `models_dir`, and `components`
  (`loaded` flags and sizes). `metrics` is null when no metrics file is shipped.
- `GET /metrics`: Prometheus text format (`customs_http_requests_total{route,status}`,
  `customs_verdicts_total{decision,ecosystem}`, `customs_events_total{kind}`,
  `customs_cache_total{result}`, `customs_singleflight_joins_total`,
  `customs_scan_duration_seconds`, `customs_upstream_fetch_duration_seconds{kind}`).
  `GET /healthz`: `{ "status": "ok", "version", "model_version", "mode" }`.
- `GET /` and static assets: the dashboard from `--ui-dir` (default `web/dist`), with
  unknown non-API paths served `index.html`; a placeholder page when it is not built.

Caching: archives are stored by sha256 under `<data-dir>/cache`, verdict inputs (scan and
model output) in SQLite keyed by (ecosystem, name, version, sha256, model_version).
Concurrent requests for the same artifact URL share one download and one scan.

## 8. Policy (`customs.toml`)

```toml
mode = "enforce"            # or "monitor"
warn_threshold = "model"    # "model" uses ensemble.json thresholds, or a number
block_threshold = "model"
min_age_days = 3            # versions published less recently hit min_age_days; 0 disables
min_age_severity = "block"  # or "warn"
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
Age comes from registry metadata: PyPI `upload_time_iso_8601` of the specific file (else
the earliest file of the release), npm `time[version]`. `min_age_severity = "warn"` makes
young versions a warning, so that `block_install_scripts_from_new` is what blocks young npm
packages with `preinstall`/`install`/`postinstall` scripts. List entries are
`<ecosystem>:<name>` with an optional `@version` or `==version`; names are normalized. Deny
beats allow; allow overrides the model and the other rules. `block_nonexistent = false`
turns nonexistent names into warnings. Unknown keys and bad values are rejected with the
key that holds them. Without `--config`, the server reads `./customs.toml`, then
`<data-dir>/policy.toml`, and `PUT /api/policy` writes to the file it read (or
`<data-dir>/policy.toml`).

## 9. Claude Code integration

`customs hook claude-code` is a PreToolUse command hook for the `Bash` tool. It parses the
command for package installs (`pip install`, `pip3 install`, `python -m pip install`,
`uv pip install`, `uv add`, `poetry add`, `pipx install`, `npm install|i|add`,
`pnpm add|install`, `yarn add`, `bun add`, `npx <pkg>`, `uvx <pkg>`), resolves each requirement, calls the
running server's `/api/check` (or scans in-process when no server is running), and returns
a PreToolUse decision: `deny` with an explanation when any package is blocked, `ask` when
any is warned, nothing otherwise. Local paths, URLs, `-r requirements.txt` and editable
installs are handled (requirements files are read and each line checked).

Output is JSON on stdout with exit code 0:
`{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny" | "ask", "permissionDecisionReason": "..."}}`.
Specs that cannot be checked (git, URL, local path, custom index) produce `ask`; editable
local paths are skipped. When Customs itself fails, the hook fails open (no decision,
message on stderr) unless run with `--fail-closed`, which denies. Setup: `hooks/README.md`.

### 9.1 MCP server

`customs mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server for any
MCP client (Claude Code, Claude Desktop, Cursor). Where the hook stops an install the
agent already decided to run, the MCP tools let the agent ask first, before it proposes a
package or a command. Transport is the MCP stdio transport: JSON-RPC 2.0, one message per
line on stdin and stdout, implemented by hand in `crates/customs/src/mcp.rs` with
serde_json and tokio (no SDK). Supported: `initialize` (protocol `2025-06-18`, or the
client's version when it is `2025-03-26` or `2024-11-05`), `ping`, `tools/list`,
`tools/call`, and notifications, which never get a reply. Errors use the JSON-RPC codes
-32700 (parse error), -32600 (invalid request), -32601 (unknown method) and -32602
(unknown tool, or arguments that do not match the input schema). Requests run
concurrently. Stdout carries protocol messages only; logs go to stderr.

| Tool | Arguments | Does |
|---|---|---|
| `check_package` | `ecosystem` (`pypi`/`npm`), `name`, `version?` | Same path as `customs check`: summary text (decision, risk, top reasons, policy hits, nearest popular name for a typosquat or nonexistent name) plus the verdict as `structuredContent` |
| `check_install_command` | `command`, `cwd?` | Parses the command with the hook parser (section 9), checks every target, returns a per-package table and the most severe decision |
| `explain_verdict` | `id` | `GET /api/verdicts/{id}` on the server, rendered with reasons and evidence (file, line, snippet) |
| `scan_archive` | `path`, `ecosystem?`, `name?` | Same as `customs scan`: offline, a throwaway engine, nothing stored |

Checks go through the same `client::Checker` as `customs check` and the hook: the server at
`--server` / `CUSTOMS_SERVER` when its `/healthz` answers, otherwise an in-process engine
built from `--config`, `--models` and `--data-dir`. The checker is chosen on the first
check and kept for the session, so verdict ids always refer to one store; when it is
in-process, `explain_verdict` reads that store instead of the server. A block is a normal
result (`isError: false`); `isError: true` means the check itself failed (registry or
server unreachable, unreadable archive, unknown version). Evidence snippets are quoted
from untrusted package code, so the text marks them as data and keeps each to one bounded
line. Setup: `hooks/README.md`.

## 10. Evaluation protocol (python/customs_ml)

As implemented; results are in `docs/EVALUATION.md` and `models/metrics.json`.

- **Data.** Datadog malicious-software-packages-dataset (real npm and PyPI samples, capped
  per discovery date so one worm cannot dominate), OSSF malicious-packages (names, for the
  name model and to filter the benign set), and benign archives downloaded from PyPI and
  npm in three popularity tiers: top (most downloaded), mid (further down the popularity
  lists), and tail (uniform draws from the PyPI index, npm keyword search and dependency
  crawling), tail packages at least 90 days old.
- **Canonicalization.** Both classes are repacked into the same deterministic tarball
  layout before scanning (`malicious.canonicalize`), so packaging cannot leak the label.
- **Dedup.** MinHash (128 permutations) over install-surface token 5-grams with LSH (16
  bands of 8 rows), confirmed at estimated Jaccard 0.7; short documents group only with
  exact copies and empty ones stay singletons.
- **Splits.** Temporal (headline): malware by discovery date, 70/10/20 quantiles; benign at
  random by cluster in the same proportions. Cluster-grouped random split as a reference.
  The name model only learns from OSSF names reported before the validation cutoff, and
  never from a name present in the code dataset.
- **Weights.** 1/sqrt(cluster size), classes balanced within the split being fit.
- **Models.** LightGBM (small grid on validation PR AUC), a PyTorch CNN over install-time
  tokens (early stopping on validation PR AUC), the name model, and a logistic stacker fit
  on validation with 5-fold cluster-grouped cross-fitting; isotonic calibration and the
  warn and block thresholds (target FPR 1% and 0.1%) come from out-of-fold scores.
- **Metrics.** ROC AUC, PR AUC, detection rate and realized FPR at the frozen thresholds,
  Brier score and expected calibration error, all with 1,000-resample cluster-bootstrap
  95% CIs. Slices: ecosystem, novel versus seen campaigns, compromised libraries, benign
  popularity tiers, and benign-tercile size strata.
- **Baseline.** GuardDog 3.2 on a fixed random sample of the test set (1,500 per class),
  compared at its own operating points (any finding, `high_risk`) with a paired cluster
  bootstrap.
- **Ablation.** The tree model retrained on behavior features only (no manifest metadata,
  sizes, or file counts).
- **Robustness and augmentation.** Text-level evasions applied to held-out malware and
  re-scored: string splitting, base64 wrapping, burial in a real library, install-surface
  indirection, metadata mimicry, starjacking. The augmentation stage then adds starjacked
  and buried copies of training malware (benign training donors only) and everything is
  retrained; the report shows before and after, separating evasion families used in
  training from unseen ones.
