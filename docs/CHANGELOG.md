# Changelog

Versions follow [semantic versioning](https://semver.org). Each release title names what
shipped in it.

## v1.0.0: registry firewall, agent hooks and lockfile audit

Released 2026-10-12. First public release.

### Firewall

- `customs serve` proxies PyPI (simple index, PEP 691 JSON) and npm, scans every archive
  in memory before handing it over, and answers allow, warn or block.
- Malware classifier: gradient-boosted trees over 78 static features, a 1D CNN over the
  install-time token stream, and a package-name model for typosquats, stacked and
  calibrated. Inference runs in Rust from JSON exports, with parity tests against the
  Python reference.
- Policy rules in `customs.toml`: allow and deny lists, names that do not exist, a release
  cooldown (`min_age_days`), install scripts in new packages, and release history rules
  (provenance dropped, install script added, new publisher, dormant revival, git or URL
  dependency added, young dependency added).
- Fail-closed rules for code Customs cannot vouch for:
  - `unread_code`: code the scanner cannot read, or that pip or npm would install
    differently from what it read (a path stored twice, links and sparse entries at
    install-time paths, absolute paths, entries node-tar extracts after an end-of-archive
    block, Python coding cookies that change what runs, an empty npm install script
    beside `binding.gyp`).
  - `hidden_code`: install-time code that Python or Node runs but the model inputs leave
    out (code after a bare CR, U+2028/2029 or a backslash-CRLF continuation, behind a
    byte-order mark, or in f-string fields).
  - `startup_hook`: `.pth` files that run code, `sitecustomize.py` and
    `usercustomize.py`, including wheel `.data` copies.
  - `agent_bypass`: install-time code that starts an AI coding CLI with its permission
    checks off.
- An established-package prior (`[established]`): a release of one of the 5,000 most
  popular PyPI or npm packages, at least 30 days old and not yanked, is allowed over the
  model. This clears the model's false positives on `requests` 2.32.3 (block) and 2.34.2
  (warn). The deny list and every other rule still apply.
- Packages that were not scanned (nonexistent, too large, or rejected by the scanner) get
  no model risk. The verdict still names the popular package a lookalike imitates.
- `POST /api/check` reads both the sdist and the pure-Python wheel and returns the
  stricter verdict, dating each archive by its own upload time.
- Dashboard with a live install feed, verdict explanations with code evidence, a package
  checker, policy editing behind the admin token, and a policy change log.
- Webhook alerts for Slack, Discord or any JSON receiver; Prometheus metrics.
- `customs serve` hands memory back after a burst of installs: a run of `check next`, a
  12-package pip install and an npm install of about 450 packages peaks under 0.5 GB and settles
  under 0.2 GB.

### Agents

- Pre-execution hooks for Claude Code (Bash and PowerShell tools), Cursor, Gemini CLI and
  Codex CLI. They find the packages a shell command would install, including behind
  wrappers and runners, in Windows shells, in inline code, in PEP 723 script headers, in
  Deno imports, in MCP servers a Codex patch adds and in project lockfiles, and deny the
  command when a package is blocked.
- Commands and edits that would switch Customs off (registry rewrites, pip and npm config
  files, `HOME` and prefix changes, also inside `bash -c`, `pwsh -Command` and `cmd /c`)
  come back to the user for confirmation.
- `customs mcp`, a Model Context Protocol server with six tools.
- `customs doctor` finds installs in a project that would skip the proxy.

### CI and supply chain

- `customs audit` checks every pin in nine lockfile formats and in MCP server configs
  (JSONC included), blocks lockfile injection, lists MCP servers whose launcher it does
  not recognize, and writes SARIF for GitHub code scanning. `action.yml` wraps it as a
  GitHub Action.
- `customs diff` shows what a release adds over an earlier one.

### Security

- Upstream credentials are shown as `***` in the API, change log, webhooks and logs, and
  never reach the errors pip and npm show. `customs doctor` never prints index URL
  credentials.
- A network-facing server takes policy changes only with the admin token, and only under
  a `Host` that DNS rebinding cannot produce (an IP address, `localhost`, or a name in
  `serve --allowed-hosts`); ten wrong tokens in a minute lock that address out for the
  rest of the minute.
- Every response carries a Content-Security-Policy, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.
- Upstream requests have overall time limits, `/api/check` and `/api/diff` fetch archives
  only from the configured upstream hosts, the npm passthrough forwards only reads and audit queries, and index
  pages, metadata and passthrough answers are capped at 256 MB. Scans run at most one per
  CPU at a time.
- Model loading rejects non-finite weights and malformed calibrations; a non-finite risk
  blocks.

### Distribution

- Each GitHub release carries prebuilt archives for Linux (x86_64) and macOS (Apple
  silicon) with the binaries, models, dashboard and third-party license notices, plus a
  container image on ghcr.io.

### Known issues

- A fresh release of a popular package still gets the model's verdict, false positive or
  not: `postcss` 8.5.29 (published 2026-10-05) warns until it is 30 days old.
- Windows is not tested.
