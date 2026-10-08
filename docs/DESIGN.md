# Customs: design

Customs is a package firewall for AI coding agents. It sits between a package manager
(pip, uv, pipenv, PDM, npm, pnpm, Yarn, Bun, Deno) and the public registry, inspects every package
archive before it reaches the machine, and blocks archives that a malware classifier trained
on real malicious packages scores as dangerous. It also plugs into Claude Code as a
PreToolUse hook, so an agent that tries to `pip install` a hallucinated or malicious package
is stopped before the command runs.

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
  `__init__.py` of a package directory, `*.pth` files and a top-level `sitecustomize.py` or
  `usercustomize.py`. npm: commands in `package.json`
  `scripts.preinstall|install|postinstall|prepare|preprepare|postprepare`, files those commands
  reference (`node x.js`, `bun x.js`, `bun run x.js`), scripts they invoke by name
  (`npm run setup`, `pnpm run setup`, `yarn setup`, `bun run setup`, `run-s a b`; up to
  three levels and 16 scripts), and the `main` entry file (default `index.js`). Before this
  was followed, a hook such as `bun run index.js` put a file named `run` on the surface and
  missed `index.js`, and `postinstall: npm run setup` hid whatever `setup` runs. A root
  `binding.gyp` counts too: npm installs a package that has one and no `install` or
  `preinstall` hook (and no `"gypfile": false`) by running `node-gyp rebuild`, and node-gyp
  runs every command in the file's `<!(...)` and `<!@(...)` expansions while configuring, so
  those commands, and the files they reference, join the surface whenever the implicit
  build or an install hook that mentions gyp applies. The 2026 autotel and awaitly
  takeovers used exactly this: `"sources": ["<!(node index.js > /dev/null 2>&1 && echo
  stub.c)"]` beside a 4.5 MB obfuscated `index.js`, with no install script in
  `package.json`.
- `all_`: every source file in the archive (`.py`, `.js`, `.mjs`, `.cjs`, `.ts`, `.sh`,
  `.bat`, `.ps1`, `.cmd`).

Implementation details (`customs-scan`, schema 1):

- PyPI install surface, in order: `setup.py`; `setup.cfg` `cmdclass` targets
  (`install = pkg.mod.Cls` resolves `pkg/mod.py`, `pkg/mod/__init__.py`, or the same under
  `src/`); an in-tree PEP 517 backend (`pyproject.toml` `build-system.backend-path`), which
  runs during the build; `<pkg>/__init__.py` and `src/<pkg>/__init__.py` for every directory
  one level below the root (or below `src/`), sorted, plus, for a namespace package (a
  directory with no `__init__.py` of its own, such as `mistralai/` in mistralai 2.x), the
  `__init__.py` of each subpackage one level further down (at most 8, skipping `tests`,
  `docs`, `examples` and similar), because importing `mistralai.client` runs
  `mistralai/client/__init__.py`; every `*.pth` file at any depth, sorted, and
  `sitecustomize.py` or `usercustomize.py` at the root (or under `src/`), which Python
  imports from site-packages at every interpreter start. Across the 23K PyPI archives in
  the corpus a root-level copy appears only in four malicious `rlask` releases; the twelve
  benign packages that ship one keep it in a test or bootstrap folder.
  Then the package's own imports are followed from the setup-time files (`setup.py`,
  cmdclass targets, an in-tree backend), three hops deep (at most 48 files): relative
  imports (`from .core import run`, `from . import util`, `from ..x import y`) and absolute
  imports whose top-level name is a package or module shipped in the archive (at the root
  or under `src/`). An import adds the module file, the `__init__.py` of each enclosing
  package, and imported names that are submodules, so a payload moved out of `setup.py`
  into a helper module stays on the install surface. Imports inside an `__init__.py` or a
  `.pth` file are not followed. A first version followed them too (importing a package
  does run them), but in a benign package they lead into the library itself: the share of
  benign PyPI packages with network code on the install surface rose from 2.3% to 18%, and
  detection of novel MalRegistry malware at a 1% false positive rate fell from 50.0% to
  45.3%. Imports of anything not in the archive (the standard library, dependencies) are
  ignored.
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
  `main`'s own requires, `bin` targets (what `npx pkg` runs) and the `.` export are not
  followed. Among missed test malware with indicators only off the surface, those files
  are where the evidence sits, so both were tried and measured on 1,500 benign and 1,500
  malicious npm training archives. Following `main` one level raised the share with any
  behavior indicator on the surface from 23.2% to 39.3% for benign packages and from
  75.9% to 82.5% for malicious ones; adding just the `bin` and `exports` files raised them
  from 23.2% to 27.9% and from 75.9% to 77.6%. A command-line tool's entry point spawns
  processes and reads the environment as its job, so in both versions benign packages
  gained more than malicious ones and the install surface lost contrast.
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
  plain variable. A module loaded by a literal name counts as imported, the Python
  counterpart of `require('child_process')`: `__import__('subprocess')` and
  `importlib.import_module('socket')` count like `import subprocess` and `import socket`,
  `__import__('os').system(...)` like `os.system(...)`, and `getattr(os, 'system')` (also
  on `__import__('os')`) like `os.system`. JavaScript `exec(`/`spawn(`/`fork(` count only
  in files that reference `child_process`. Method calls (`re.compile`, `cursor.exec`) and
  `def`s do not count.
- A string that is run as code is read as code: the literal argument of Python `exec`,
  `eval` and `compile`, and of JavaScript `eval` and the `Function` body, has its `\n`,
  `\t` and quote escapes undone and goes through the same rules as the file (three levels
  deep), in place of the string-content patterns, so its URL is counted once. Its hits land
  on the literal's line (or on the matching lines of a literal written over several lines),
  and the file-level dropper rule sees the file and its literals together. A 2026 PyPI
  dropper campaign (`tlask`, `rlask`, `gpsea`, `pyphetools`, `nhmpy` and others) put the
  whole payload in an `exec('...')` string inside a `-setup.pth` file, which Python runs at
  every interpreter start: the scanner had seen `dyn_code` and a URL only, and it now sees
  the download, the write and the process launch. Bundler modules are left as strings (an
  eval string that names itself with a `sourceURL` comment, as webpack's development builds
  wrap every module): on the first try they put library behavior on the install surface of
  two benign archives. On 6,000 corpus archives the change touched 70 malicious and 9 benign
  ones, and every indicator that appeared where there was none before was in malware.
  Three more forms are read the same way. A call over one base64 literal decoded in place
  (`exec(b64decode('...'))`, `eval(atob('...'))`, `eval(Buffer.from('...',
  'base64').toString())`, with zlib or gzip inflation when the call also names
  `decompress` or `inflateSync`) reads the decoded text when it is mostly printable UTF-8;
  the encoded literal keeps its length and entropy statistics. A literal after `'-c'` in a
  list that names `sys.executable` or a `python` program is Python code: litellm 1.82.8
  shipped its payload as `Popen([sys.executable, "-c", "import base64;
  exec(base64.b64decode('...'))"])` in a `.pth` file, two layers this now reads through.
  `builtins.exec` and `__import__('builtins').exec` count as the builtin. On the 6,000
  corpus archives these forms and string-table reads together changed 29 malicious archives
  and no benign one, and every indicator that appeared was in malware; litellm 1.82.8 went
  from four process launches and no download to 15 launches, a download-and-run and two
  file writes on its install surface.
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
- String literals joined by `+`, or written side by side in Python (`'a' 'b'`), are folded
  into one literal before any rule runs, so `require('child_' + 'process')` is
  `require('child_process')` and a host split across literals is still one URL. Folding
  follows precedence: a literal next to a tighter operator (`n * 'a' + 'b'`,
  `'a' + 'b'.join(x)`) stays apart, and parentheses that only group the folded expression
  are dropped. The CNN token stream (4.6) folds the same way. String entropy statistics stay
  per original literal, since folding long messages in benign code would move them while a
  chunked blob is high-entropy chunk by chunk; the base64 run length uses the folded text.
  On 6,000 random corpus archives, folding changed features in 45 of 4,784 malicious and 9
  of 1,216 benign archives, and every indicator that appeared where there was none before
  appeared in malware.
- Before folding, string literals are decoded the way the interpreter would read them.
  Escapes that spell characters by number (`\x63`, `\u0063`, `\u{63}`, Python's
  `\U00000063`) are decoded; control characters stay escaped so line numbers do not move,
  and Python raw strings keep their backslashes. A literal reversed at run time is read
  forwards: Python `'...'[::-1]` (over the whole run of adjacent literals, which Python joins
  first) and `''.join(reversed('...'))`, JavaScript `'...'.split('').reverse().join('')` and
  `[...'...'].reverse().join('')`. A list of literals joined at run time is read as the
  joined string: Python `sep.join(['...', '...'])` over a list or tuple, JavaScript
  `['...', '...'].join(sep)` (a comma when `sep` is left out), where `sep` is a literal;
  joins come after reversals, so a reversed piece is joined forwards, and before `+`
  folding. All three came from the red team (section 10): spelling every literal as escapes
  cut automatic blocking of held-out malware from 67.1% to 60.6%, reversing every literal
  cut it from 67.2% to 60.5%, and splitting every literal into joined pieces cut it from
  67.5% to 59.8%. On the same 6,000 corpus archives, decoding escapes changed features in
  232 malicious and 60 benign archives (mostly string entropy) and reading reversals forwards
  in 5 malicious and no benign ones, and every indicator that appeared where there was none
  before appeared in malware. Joining lists changed features in 79 malicious and 19 benign
  archives: URL counts rose in 41 malicious archives and 1 benign one, the rest is string
  entropy, and no indicator appeared where there was none. After retraining on joined
  features the joined-pieces rewrite is blocked at 59.9% against 62.0% for the clean
  samples, a 2.1-point gap from 7.8.
  A string table (every literal moved into one array and read back by index, as
  javascript-obfuscator lays it out) is read in place: a name assigned once to a list of
  plain literals, never touched through `.` (so the `push`/`shift` rotation the obfuscator
  adds leaves it alone) and never written by index, has each `name[3]` read (decimal or hex)
  replaced by its literal on the line of the read, and a literal read this way leaves the
  table so it counts once. The red team's table rewrite cost 0.4 points of block recall with
  the earlier models and 2.75 points once the models had learned from joined literals.
  Building literals from character codes (`String.fromCharCode(...)`,
  `''.join(map(chr, [...]))`) is not decoded: `decode_obf` and the CNN already flag
  character codes, and the red team found it costs no detection.

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
skipped). Added after the MalRegistry error analysis (section 10.1):
`inst_hidden_ws_lines`/`all_hidden_ws_lines`, lines where code resumes after a run of 100 or
more spaces or tabs (code pushed past the right edge of an editor or diff view; evidence
snippets show such a line as `head [N blank columns] hidden code`), and
`inst_exec_decoded`/`all_exec_decoded`, lines holding both a `dyn_code` and a `decode_obf`
hit (`exec(b64decode(...))` on one line). The same call written inside a string literal
counts too (`subprocess.Popen([sys.executable, "-c", "import base64;
exec(base64.b64decode('...'))"])`, `node -e "eval(Buffer.from(p, 'base64')...)"`), which is
how the 2026 litellm and telnyx takeover releases started their payload in a child process;
string contents are otherwise only matched against the string rules, so the call was
invisible. The string rule needs the decoder within one run of identifier, dot, quote and
bracket characters after `exec(`, so prose that mentions both does not match. Added for compromised releases of large
libraries, where a payload is a small share of the code: `inst_max_file_kinds` and
`all_max_file_kinds`, the most distinct behavior indicators (every indicator except `url`
and `file_write`) present together in a single file, and `all_top_file_share`, the share of
all behavior hits that sit in the file with the most of them. An injected payload packs
network, process, decoding and secret access into one file; a large benign library
spreads the same indicators thinly across many.

Definitions: file counts include every regular file, nested-archive entries too
(`n_js` counts `.js .mjs .cjs .ts`; `n_minified_js` only `.js .mjs .cjs`); `n_hidden` counts
files with any path component starting with `.`; `has_*` look at the package root only.
Line lengths are in bytes. String entropy is Shannon entropy in bits per byte over string
literals of at least 20 bytes (shell: quoted strings); the mean is over all such strings on
the surface. `longest_b64_run` is the longest run of `[A-Za-z0-9+/=_-]` inside a string
literal (shell: quoted strings and words). `hex_escape_count` counts `\xNN`, `\uNNNN` and
`\u{...}` in the raw text. "High entropy" for identifiers means above 4.3 bits per byte.
Ratios are 0 when the denominator is 0.

Feature order (`feature_names()`, 77 names): the 14 `inst_<indicator>` in table order, the
14 `all_<indicator>`, then the 28 features above in the order listed, then
`inst_hidden_ws_lines`, `all_hidden_ws_lines`, `inst_exec_decoded`, `all_exec_decoded`,
`inst_max_file_kinds`, `all_max_file_kinds`, `all_top_file_share`, `inst_n_files`, `n_links`, `n_unsafe_paths`, then the 11 manifest features in the order
listed in 4.4. Models bind features by name, so adding features never breaks an older model
file.

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
Exceeding the entry, total or ratio cap rejects the archive; a nested archive that would
exceed one is left unexpanded instead (its entries are dropped, its decompressed bytes stay
counted), since installers never unpack it: cmake's sdist bundles its own 20,000-file source
tarball and was rejected whole before. Unsafe and link entries are skipped and counted.

Content the scanner does not read cannot be judged, and an attacker controls what it does
not read. Padding `setup.py` past the per-entry cap with comment lines turned a test
payload scored 1.00 into 0.59 (allowed), and 20,001 empty files made any archive
unscannable, which the proxy only warned about. Two policy rules close this, both
blocking by default: `unread_code` fires when a code file or manifest (source and script
extensions, `binding.gyp`, `package.json`, `setup.cfg`, `pyproject.toml`, `PKG-INFO`,
extensionless files starting with `#!`) was over the per-entry cap, and `scan_error` when
the archive was rejected. In a rescan of the 42,748 corpus archives, neither fires on a
single benign archive (no entry of any kind exceeds 32 MiB; the only two rejections were
the nested cases above). Archives above the 256 MiB download scan limit are still scored
on name and metadata only (`not_scanned`): large legitimate wheels are common, PyPI caps
uploads at 100 MB by default, and age and history rules still apply to them. Only content needed for analysis is kept in memory (source, manifest,
README and nested-archive entries in full, a short magic-number prefix otherwise).

Root normalization: top-level directories are stripped while the current level holds
exactly one directory and nothing besides sidecar `*.json` files (other than
`package.json`), stopping at a level that has `package.json`, `PKG-INFO`, `setup.py`,
`setup.cfg`, `pyproject.toml` or a `*.dist-info/` directory. This removes `name-version/`
from sdists, `package/` from npm tarballs, and the wrapper directories and
`package_info-*.json` sidecars of sample collections such as the Datadog dataset
(`tmp/tmpXXXX/name/name-version/`). If stripping stops with no manifest at the root (the
top level holds a package directory beside something else), the shallowest directory that
holds a manifest or a `*.dist-info/` directory becomes the root, provided it is unique; a
tie between a built distribution and a source checkout goes to the one with `PKG-INFO`,
`package.json` or a `*.dist-info/` (an unpacked wheel).
Files outside the new root keep their paths and are still scanned. Before this rule,
69 malicious and 6 benign PyPI archives in the corpus had their manifest below such a level
and so no install surface at all (one campaign stored each release beside a `sources/`
git checkout of the same project). Recent entries of the Datadog dataset store an
unpacked wheel (`name/`, with its `.dist-info`) beside such a checkout; the wheel has no
manifest file, so until `.dist-info` counted, the checkout became the root and the clean
upstream source was scanned in place of the published package. That hid the payload of
44 PyPI archives (3 benign), among them the 2026 durabletask, mistralai and telnyx
takeover releases. Paths whose trailing components repeat
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

### 4.8 Hostile inputs

The scanner parses attacker-chosen bytes inside the proxy's request path: a panic fails an
install and a slow input holds a blocking thread. `crates/customs-scan/examples/fuzz.rs` is
a structure-aware mutation fuzzer on stable Rust. It takes real corpus archives as seeds
and mutates them at three levels: raw bytes (the container parsers), tar header fields
inside a recompressed gzip (paths, sizes, entry types, link names), and file contents
inside a rebuilt tar.gz, where it also adds the files that switch on install surfaces
(`binding.gyp`, `setup.py`, `.pth`, a `.dist-info/`, a `sources/` checkout). Content
mutations splice tokens that sit on parser decision points (quotes, comment openers,
`<!(`, `exec(`, invalid UTF-8) and repeat one up to 200,000 times. Every input runs under
`catch_unwind`; a panic, or a scan slower than 2 s and four times its seed's own time, is
saved for replay. `examples/scale.rs` then times one file holding a token repeated at
doubling counts: a ratio near 2 per row is linear, near 4 is quadratic.

The repetition mutation found two slow paths, both since fixed:

- Line numbers for matches inside a string literal were computed by counting newlines from
  the start of the string for each match. A 780 KB string holding 55K copies of
  `~/.ssh/id_rsa` took 115 s, and a larger one 8 minutes. Each string now builds a
  line index once, on its first match.
- A Unicode `\b` stops the regex crate's lazy DFA at the first non-ASCII byte, which falls
  back to an engine about 100x slower. One accented character in a long string literal or
  shell script cost about 1 s per MB (7 s for one 7.6 MB line). Indicator rules now
  compile with ASCII word boundaries. On 6,000 random corpus archives the features are
  identical for 5,997, and the batch ran 4.2x faster (50 to 213 archives a second). The
  other 3 are malware that gain hits where an indicator word touches CJK text
  (`获取whoami失败`): CJK characters count as word characters under Unicode rules, so
  `\b` never matched there.

After the fixes, 514K mutated inputs in 20 minutes on 4 threads produced no panic and no
slow scan.

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
{ "format": "customs-code-cnn-v1", "max_len": 768, "vocab": { "<pad>": 0, "<unk>": 1, "os": 2, ... },
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
  "thresholds": { "warn": 0.42, "block": 0.91, "target_fpr_warn": 0.01, "target_fpr_block": 0.001 },
  "clip": 4.0 }
```
Inputs are component logits (the uncalibrated gbdt raw score, the CNN logit, the name
logit). A component is unavailable when its artifact is not shipped or its input is absent
(no features, no tokens, no name). `z = bias + sum_c w_c * logit_c` over available
components, with each logit first bounded to `[-clip, clip]` when `clip` is set, using the
fallback whose `missing` set equals the unavailable set (a fallback
may carry its own `calibration`); when none matches, the primary weights are applied to
the components that ran (`weight_set` `"partial:<missing>"`). `risk = calibrate(sigmoid(z))`;
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
`block_nonexistent`, `min_age_days`, `block_install_scripts_from_new`, the release history
rules of section 8 (`provenance_dropped`, `install_script_added`, `publisher_changed`,
`dormant_revival`, `version_anomaly`, `nonregistry_dependency_added`,
`young_dependency_added`), `scan_error` (scanner rejected the archive, block by default),
`unread_code` (a code file over the per-file scan limit, block by default), `not_scanned`
(archive above the scan size limit).
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

Clients: `customs env` prints the variables that point installers at the proxy, checked with
real installs through it. pip and pipx read `PIP_INDEX_URL`; uv `UV_DEFAULT_INDEX` (and the
older `UV_INDEX_URL`); PDM `PDM_PYPI_URL`. Pipenv installs from the Pipfile's `[[source]]` and
ignores `PIP_INDEX_URL`; `PIPENV_PYPI_MIRROR` replaces pypi.org there. npm, pnpm, Yarn 1 and
Bun read `npm_config_registry`. Deno reads only `NPM_CONFIG_REGISTRY`, and environment names
are case-sensitive on Linux and macOS: with the lower-case variable alone, `deno add` fetched
straight from registry.npmjs.org, so both spellings are set. Yarn 2 and later read only `YARN_NPM_REGISTRY_SERVER`, and
refuse a plain-HTTP registry on any host but `localhost` until it is listed in
`YARN_UNSAFE_HTTP_WHITELIST`, which is set for an `http://` server. Poetry has no
environment variable that replaces PyPI, so `poetry install` goes straight to pypi.org; the
Claude Code hook (section 9) still checks every `poetry.lock` pin before the command runs.

What the variables do not cover was measured the same way, with a denied package and
lockfiles written straight against the public registries. The variables beat a
`registry=` line in `.npmrc` or `bunfig.toml` and pip's config files. Scoped registries do
not: pnpm and Bun fetched a scope set in `.npmrc` or `[install.scopes]` from that registry
directly, while npm still sent the tarball through the proxy. Lockfile URLs are used as
written: npm redirects only `registry.npmjs.org` URLs to the configured registry; pnpm, Bun
and Deno download any URL their lockfile records, even a `registry.npmjs.org` one; Yarn 1
downloads every `resolved` URL in `yarn.lock`, so a classic `yarn.lock` never reaches the
proxy. `uv sync --frozen` downloads the file URLs in `uv.lock`, while plain `uv sync`
resolved again through the proxy and `uv sync --locked` refused to run. `customs doctor
[DIR]` checks a project and the current environment for each of these (unset or
different variables, scoped registries, extra indexes and find-links in pip and uv
settings or requirements files, non-PyPI Pipfile sources, Poetry, lockfile URLs off the
proxy) and exits 1 when it finds a way around the proxy. Packages that bypass the proxy
are still checked by the Claude Code hook and `customs audit`, which read the lockfile
itself.

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
# Release history rules: "off", "warn" or "block"
provenance_dropped = "warn"    # npm: no provenance attestation, the previous release had one
install_script_added = "block" # npm: install script added or its command changed
publisher_changed = "warn"     # npm: publisher of none of the previous 5 releases
dormant_revival = "warn"       # previous release is more than dormant_days older
dormant_days = 365
version_anomaly = "off"        # major version jump, or a release on a long-quiet old major
nonregistry_dependency_added = "block"  # npm: new git/URL/file dependency since the previous release
young_dependency_added = "block"        # npm: new dependency first published days before, by strangers
young_dependency_days = 7
# Scan coverage: "off", "warn" or "block"
unread_code = "block"       # a code file or manifest over the 32 MiB per-file scan limit
scan_error = "block"        # the scanner rejected the archive (limits, bomb, corrupt)
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

**Release history rules.** Account takeovers (the 2025 chalk/debug compromise, the
Shai-Hulud worm) publish new versions of established libraries with a payload inside
legitimate code, the classifier's weakest slice. These rules compare the requested version
with the releases published before it, using only the registry metadata Customs already
reads (`customs::history`). "Earlier releases" are the other versions with a strictly
earlier publish time; prereleases among them are ignored unless the requested version is
itself a prerelease. A version without a publish time gets no history rules.

| Rule | Ecosystems | Fires when |
|---|---|---|
| `provenance_dropped` | npm | `dist.attestations` is absent but the previous release had it |
| `install_script_added` | npm | a `preinstall`/`install`/`postinstall` script is new or its command changed since the previous release, or since the newest release at least 24 hours older (the detail shows the command, cut at 120 characters) |
| `publisher_changed` | npm | `_npmUser.name` differs from every known publisher of the previous 5 releases |
| `dormant_revival` | npm, PyPI | the previous release is more than `dormant_days` (1 to 3650) older |
| `version_anomaly` | npm, PyPI | the major version is more than one above the highest earlier version, or the release extends an older major line while a newer major exists and that line had no release for `dormant_days` (or never had one) |
| `nonregistry_dependency_added` | npm | a `dependencies` or `optionalDependencies` entry whose spec fetches code outside the registry (`git+`, `github:`, `owner/repo`, `http(s):`, `file:`, `link:` and the like) is new or changed since the previous release, or since the newest release at least 24 hours older |
| `young_dependency_added` | npm | a dependency new since the previous release (or since the newest release at least 24 hours older) does not exist on the registry, or was first published less than `young_dependency_days` (1 to 365) before this release, and shares no maintainer or publisher with the package |

These are heuristics with known false positives: maintainers move publishing on or off CI
(provenance comes and goes), add native builds (`install: node-gyp rebuild`), hand packages
to new owners, and revive old projects. The defaults follow a measurement
(`python -m customs_ml.history_eval`, "Release history rules" in the evaluation report) on
the corpus's compromised npm releases and on two years of releases of 260 benign npm
packages:

| Rule | Default | Compromised releases | Benign releases |
|---|---|---:|---:|
| `install_script_added` | block | 69% to 72% | 0.03% |
| `provenance_dropped` | warn | unknown (most malicious versions were unpublished) | 0.19% |
| `publisher_changed` | warn | unknown (same) | 1.06% |
| `dormant_revival` | warn | 16% | 0.50% |
| `version_anomaly` | off | 3% | 0.09% |
| `nonregistry_dependency_added` | block | 9% to 40% (unknown where an earlier release was unpublished) | 0 of 14,897 |
| `young_dependency_added` | block | 6% to 42% (same) | 1 of 14,897 |

`install_script_added` blocks because it is both common in takeovers and rare in
legitimate releases: 4 of 14,897, well under the 0.1% budget of the model's block
threshold. On the compromised npm releases of the test period it raises the share blocked
from 44% to at least 78%. Comparing with the settled release (the newest one at least 24
hours older) as well as the previous one matters here: attackers publish several malicious
versions within hours, and against the previous release alone the second one shows no
change. Before that comparison, and before an added root `binding.gyp` counted as an added
install script (npm runs `node-gyp rebuild` for it), the rule fired on 38% of compromised
releases; now it fires on 69%, while legitimate releases went from 3 to 4. The others warn (and `version_anomaly`, which fires on releases
the model already flags, is off); the model still judges the archive itself, and `block` is
available for teams that would rather review such releases first. Provenance is weaker
evidence than it looks: an attacker who takes over the project's CI publishes with valid
provenance, and 2 of the 3 still-listed compromised releases that followed an attested
release carry it. The Python replay of the rules matches `customs check` on 107 of 107
sampled releases.

The two dependency rules cover takeovers whose payload arrives through a dependency, which
leaves nothing for the scanner in the package's own archive: the Mastra wave added
`easy-day-js`, a package published the day before, the axios compromise added
`plain-crypto-js`, and the TanStack wave added an optional dependency on a GitHub commit.
Both compare with the settled release too. On the 51 test-period compromised npm releases
the model lets through, they catch 28, and with every blocking rule the share blocked rises
from 44% to between 96% and 99% (the range covers earlier releases that were unpublished
and whose facts are unknown), at a cost of 5 of 14,897 legitimate releases. A new dependency is exempt from
`young_dependency_added` when it shares a maintainer or publisher with the package, since
maintainers routinely publish new platform or sibling packages alongside a release. The
proxy fetches the packuments of at most 20 added dependencies per release, concurrently and
through its metadata cache, and only while the rule is on; a failed lookup skips that
dependency. The npm rules
read the full packument; PyPI's JSON API names neither uploaders nor attestations, so
`provenance_dropped` and `publisher_changed` are npm only (PEP 740 attestations through
PyPI's Integrity API are future work, since they cost a request per file). For PyPI
downloads through the proxy, the project document `/pypi/<name>/json` is read instead of
the per-release one while `dormant_revival` or `version_anomaly` is on. The rules apply
both to proxied downloads and to `POST /api/check`.

## 9. Claude Code integration

`customs hook claude-code` is a PreToolUse command hook for the `Bash` tool. It parses the
command for package installs (`pip install`, `pip3 install`, `python -m pip install`,
`uv pip install`, `uv add`, `poetry add`, `pipx install`, `npm install|i|add`,
`pnpm add|install`, `yarn add`, `bun add`, `npx <pkg>`, `uvx <pkg>`, and the scaffolding
commands `npm init|create <x>`, `pnpm|yarn|bun create <x>`, which run `create-<x>`, or
`@scope/create-<x>` for `@scope/<x>`; and Deno: `deno add|install npm:<x>` (a name without
a prefix is an npm package there), `deno install -g`, `deno run|serve|compile|cache
npm:<x>`, `deno x|dx <x>` and `deno create npm:<x>`, which maps initializers the way npm
does; `jsr:` packages and remote `https:` modules cannot be checked and produce `ask`), resolves each requirement, calls the
running server's `/api/check` (or scans in-process when no server is running), and returns
a PreToolUse decision: `deny` with an explanation when any package is blocked, `ask` when
any is warned, nothing otherwise. Local paths, URLs, `-r requirements.txt` and editable
installs are handled (requirements files are read and each line checked).

Output is JSON on stdout with exit code 0:
`{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny" | "ask", "permissionDecisionReason": "..."}}`.
Specs that cannot be checked (git, URL, local path, custom index) produce `ask`; editable
local paths are skipped. When Customs itself fails, the hook fails open (no decision,
message on stderr) unless run with `--fail-closed`, which denies. Setup: `hooks/README.md`.

**Project installs.** `npm install` or `npm ci` with no package (also `--prefix`), `pnpm
install` (`-C`), bare `yarn` or `yarn install` (`--cwd`), `bun install` (`--cwd`), `deno
install` with no package and `deno ci`, `uv sync`
(`--directory`, `--project`), `poetry install|sync` (`-C`) and `pipenv install|sync`
install a whole project (`crates/customs/src/hook/project.rs`). The hook reads that
manager's lockfile in the project directory with the `customs audit` parsers (section 11):
`npm-shrinkwrap.json` or `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `deno.lock`,
`uv.lock`, `poetry.lock`, `Pipfile.lock`. Every pin is checked, and an entry whose tarball
URL serves another package is a block. Entries the audit cannot check because they come
from git, a URL or a registry other than npm's, PyPI or a Customs proxy produce `ask` (the
first five by name with their lockfile line, then a count): a lockfile edit can point an
entry at any host under a trusted name, and a test with Deno 2.9 installed such an entry
without going through the proxy. The project's own local folders do not count. Direct dependencies in the manifest that the
lockfile does not pin yet are checked too, as the ranges they name: `package.json`
`dependencies`, `devDependencies` and `optionalDependencies` (skipping `workspace:`,
`file:`, `link:` and `portal:`), `pyproject.toml` `[project].dependencies` (plus
`[dependency-groups].dev` for uv and the Poetry dependency tables for Poetry), and
Pipfile `[packages]`. This is the case where an agent adds a dependency to `package.json`
and then runs `npm install`. `pip install .`, `pip install -e .` and `uv pip install -e
'.[dev]'` (also `-e` lines in requirements files) are treated the same way when the
directory has a `pyproject.toml`: there is no lockfile, so the hook checks
`[project].dependencies` plus the optional-dependency groups named as extras. The local
project itself is not scanned; a non-editable `pip install .` still asks for that reason. Without a lockfile, the manifest's git and URL dependencies
produce `ask` like any other unverifiable spec.

For packages a lockfile already pins, only a block counts. On this repository's
`web/package-lock.json`, 4 of about 300 legitimate packages are over the warn threshold,
so counting warnings would stop nearly every `npm ci` for review. The block threshold's
false-positive rate is 0.09%, and new manifest dependencies keep the warn check. Checks run
8 at a time; a 300-package lockfile took 13.5 s with nothing cached and 0.12 s cached. The
hook stops checking after 40 s (Claude Code's hook timeout is 60 s) and reports the
packages it did not reach as one `ask` line that points to `customs audit`.
`check_install_command` over MCP (section 9.1) expands project installs the same way and,
above 40 packages, lists only the ones that are not allowed.

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
| `audit_lockfile` | `path`, `recursive?` | Same as `customs audit` (section 11) with the default 8 concurrent checks: the overall decision, a summary, and one row per package that is not allowed (mismatched download URLs included); allowed rows are only counted so a large lockfile stays small |
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
  on validation with 5-fold cluster-grouped cross-fitting; Platt calibration and the
  warn and block thresholds (target FPR 1% and 0.1%) come from out-of-fold scores.
- **CNN input length.** The CNN reads the first 768 install-surface tokens; the stream
  itself stops at 4,096, and 55% of compromised-library releases in test run past 768
  (22% of benign packages do). Scoring the same trained CNN on the full stream (its
  global max-pool accepts any length) lowered its own test ROC AUC from 0.912 to 0.909,
  and on compromised releases longer than 768 tokens from 0.707 to 0.668: over more
  legitimate code the max-pool finds more payload-like fragments in benign packages too.
  Restacked, the headline and compromised-library numbers stayed within seed noise.
- **Bounded stacking.** Component logits are clipped to `[-c, c]` before stacking, with `c`
  chosen from {none, 16, 12, 8, 6, 4, 3, 2} by out-of-fold recall averaged over every
  validation threshold up to 1% FPR. The block threshold sits at the 0.1% FPR point of
  2,172 validation benign packages, so two or three of them set it. Unclipped, those were
  packages the CNN scored with logits of 17 to 20, and the threshold came out far
  stricter than intended: 0.024% FPR on test and 53% recall, against 71% at a true 0.1%.
  The gap was found by comparing the realized test FPR with its target; the bound itself
  is chosen on validation only.
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
  re-scored: string splitting, hex and Unicode escapes, character codes, reversed literals,
  joined literal lists, a string table, base64 wrapping, burial in a real library, install-surface indirection, metadata mimicry,
  starjacking. The augmentation stage then adds starjacked
  and buried copies of training malware (benign training donors only) and everything is
  retrained; the report shows before and after, separating evasion families used in
  training from unseen ones.

### 10.1 Independent dataset (`customs_ml/external.py`)

MalRegistry (lxyeternal/pypi_malregistry, ASE 2023) is a PyPI malware corpus collected by a
different team. Archives are fetched, canonicalized like the corpus, and scored by the
shipped binary at its shipped thresholds. A sample is *novel* when its normalized name
never appears in the training data and its token stream does not share a MinHash cluster
with any training malware. Novel clusters are split in half by a hash of the cluster id:
the **dev** half is for error analysis and training (and holds every cluster any sample of
which was looked at), the **held-out** half is only ever reported. Rates are given per
archive and per cluster (one sample each), since one campaign can contribute hundreds of
copies.

- **Frozen sets.** Cluster ids shift when a scanner change alters token streams, so the
  first run's halves, novelty and clusters are stored by archive hash
  (`external_malregistry_split.json`) and reused by every later run.
- **Matched FPR.** Shipped thresholds move with every retrain, so runs are compared at
  thresholds giving the same false positive rate on the benign test split.
- **Code-only scores.** Most MalRegistry names are in the OSSF name list the name model
  trains on. The binary is also run with the name model left out of the manifest, so the
  ensemble uses its code-only fallback weights.

Dev-half error analysis drove three scanner changes: import following from setup-time
files (4.1), and the `hidden_ws_lines` and `exec_decoded` features (4.3). After a scanner
change, `pipeline refresh` rescans the corpus (features and tokens) while keeping clusters
and splits, and every model is retrained. These changes raised dev-half recall more than
held-out recall (see the report).

`external.adapt(fraction)` is the experiment that added training data instead: a copy of
the data directory gets the dev half (all of its clusters, or a random fraction) as
training malware, every model is retrained, and the held-out half is scored code-only.
The pipeline stage `malregistry` does the same for the shipped models, after `augment`
(augmentation draws only from the primary corpus). The held-out half never enters training.

### 10.2 Experiment: release diff model (`customs_ml/diff.py`, `customs-scan delta`)

A compromised release of a popular library is the previous release plus a payload. The
delta of a release keeps files added since the previous release whole, reduces changed
files to their new lines (multiset line difference), keeps binaries and root manifests
(plus a wheel's `*.dist-info/METADATA`) whole, and drops unchanged and removed files.
Python and Rust build identical deltas (checked on real pairs). Training pairs: a benign
release and its predecessor (negative), and the same pair with a training-split malware
payload injected into the newer release (positive; npm: new postinstall file, appended to
the entry point, or a shell install script; PyPI: appended to `setup.py`, appended to the
top `__init__.py`, or a new imported module). Real compromised releases are test only.
The diff model uses `all_` and structural features plus change-size features; `inst_`
features are excluded because the install surface of a delta is not well defined.
Thresholds come from benign validation pairs at FPR 0.5% and 0.1%. The comparison with the
base model is made at matched false positive rates. It was not adopted (see the report).

## 11. Lockfile audit (`customs audit`)

`customs audit [PATHS...]` checks every dependency a project pins, for CI and for reviewing
a pull request before anything is installed. PATHS are lockfiles or directories
(searched for known names; `--recursive` walks subdirectories, skipping `node_modules`,
`.git`, `.venv` and `target`). Parsing is offline (`crates/customs/src/audit/`):

| File | Pins taken from |
|---|---|
| `requirements*.txt` | `name==version` / `===` lines; `-r` includes relative to the file; markers, extras, `--hash` and `\` continuations handled |
| `poetry.lock`, `uv.lock` | `[[package]]` `name` and `version` |
| `Pipfile.lock` | `default` and `develop`, `"version": "==x"` |
| `package-lock.json`, `npm-shrinkwrap.json` | v2/v3 `packages` (node_modules paths, nested and scoped, `name` for aliases); v1 `dependencies` tree |
| `pnpm-lock.yaml` | `packages:` keys (v5 `/a/1.0.0`, v6 `/a@1.0.0(peer@1)`, v9 `a@1.0.0`), read line by line |
| `yarn.lock` | classic and berry entry headers with `version` (berry `resolution` names the installed package) |
| `bun.lock` | `packages` entries: `name@version` first (the real name for aliases), then the tarball URL, empty for the default registry; trailing commas allowed. `bun.lockb` is binary and refused with a hint to write `bun.lock` |
| `deno.lock` | v4/v5 `npm` map (v3: `packages.npm`), keys `name@version` with `_peer@version` suffixes, `tarball` when the registry is not the default; `jsr` packages and `remote` modules listed as not checked |

Each pin keeps its file and 1-based line. Pins are deduplicated on (ecosystem, normalized
name, version), keeping the first location. Entries that cannot be checked are listed as
"not checked" with a reason: unpinned requirements, editable installs, URLs, VCS and local
paths, and packages resolved from a registry other than PyPI, npm, Yarn's npm mirror or a
loopback host (a Customs proxy). The project's own workspace packages (`editable`,
`virtual`, `workspace:`, `link:`, `portal:`, npm `link: true`) and berry `patch:` entries
(the unpatched entry is listed too) are skipped silently.

npm, Yarn classic, pnpm, Bun and Deno install from the URL the lockfile records (`resolved`,
pnpm `resolution.tarball`, the second element of a `bun.lock` entry, `deno.lock`'s
`tarball`), and none of them
compares the tarball with the entry's name. A lockfile edit in a pull request can
therefore point `node_modules/lodash` at
`https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz` with a matching `integrity`:
the diff shows a trusted name, and `npm ci` installs the other package. Bun 1.4 with
`--frozen-lockfile` does the same and prints the trusted name as installed, and so does
`deno ci` in Deno 2.9: a `deno.lock` entry `ms@2.1.2` pointing at another host's
`is-number` tarball installed `is-number` into `node_modules/ms`, without going through
the proxy, and printed `+ npm:ms 2.1.2`. The audit reads the
package and version back out of every registry tarball URL (`<name>/-/<base>-<version>.tgz`,
scoped and percent-encoded names, any path prefix such as the proxy's `/npm/`) and reports a
`mismatch` when they differ from the entry or the URL is not a tarball path. A mismatch
counts as block, and the package the URL actually serves is checked in its place. uv
records file URLs too, but it validates the downloaded distribution's name and version
against the lock entry, so `uv.lock` gets no such check.

Pins are checked through the same client as `customs check` (a running server, else
in-process), `--jobs` (default 8) at a time; PyPI pins are sent as `==version` so a version
the registry lacks is reported as unavailable instead of resolving to another one. The
verdict cache makes repeated audits cheap.

Exit codes: 1 when a package meets `--fail-on` (`block` by default, `warn`, or `never`; an
unavailable version counts as warn and a mismatch as block), otherwise 2 when a check failed (network, server) or
on usage and parse errors, otherwise 0. `--format text` prints a summary line and a table
of non-allowed packages; `json` prints every result with its full verdict; `sarif` prints
SARIF 2.1.0 with one run (driver `Customs`), rules `customs/model-block`,
`customs/model-warn`, `customs/unavailable`, `customs/lockfile-mismatch` and one per policy rule that appears
(`customs/deny-list`, `customs/nonexistent-package`, `customs/min-age`,
`customs/install-scripts-from-new-package`, `customs/scan-error`), and one result per warned
or blocked package, or mismatched entry, at its lockfile line (path relative to the working directory) with
`partialFingerprints.customsPackage/v1 = <ecosystem>/<name>/<version>`, so GitHub keeps one
alert per package version across runs. `action.yml` wraps this for GitHub Actions
(`docs/github-action.md`).
