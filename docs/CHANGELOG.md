# Changelog

Versions follow [semantic versioning](https://semver.org). Each release title names what
shipped in it.

## v1.0.0: audit fixes across the firewall, hooks, dashboard and training tools

First public release. Not tagged yet.

### Added

- `hidden_code` policy rule (block by default): install-time code that Python or Node
  runs but the scanner's model inputs leave out (code after a bare CR, U+2028/2029 or a
  backslash-CRLF continuation, behind a byte-order mark, or in f-string fields). The
  dashboard's Policy page has a toggle for it.
- `serve --allowed-hosts` (env `CUSTOMS_ALLOWED_HOSTS`) for host names allowed to change
  the policy.
- Hooks check Claude Code's PowerShell tool, installs behind runners and Windows shells,
  MCP servers a Codex patch adds, and manifest versions the lockfile does not satisfy.
- `customs audit` reads JSONC MCP configs, yarn berry resolutions, deno.lock v2, pip index
  options and uv.lock download URLs; lists MCP servers whose launcher it does not
  recognise; writes SARIF metadata for every policy rule and notes for entries that fetch
  code Customs did not check.

### Changed

- Packages that were not scanned (nonexistent, too large, or rejected by the scanner) get
  no model risk instead of a made-up 0.70 to 0.78. The verdict still names the popular
  package a lookalike imitates.
- `unread_code` also covers code pip or npm would install differently from what the
  scanner read: a path stored twice, links and sparse entries at install-time paths,
  absolute paths, entries node-tar extracts after an end-of-archive block, Python coding
  cookies that change what runs, and an empty npm install script beside `binding.gyp`.
- `startup_hook` also covers `sitecustomize.py` and `usercustomize.py`, including wheel
  `.data` copies.
- `POST /api/check` reads both the sdist and the pure-Python wheel and returns the
  stricter verdict, dates each archive by its own upload time, and always reads sdists
  and npm tarballs whatever size the registry reports.
- `PUT /api/policy` refuses a body that leaves keys out, listing each one, instead of
  resetting them to defaults.
- The scan cache is keyed on the scanner and summary versions; results from earlier
  builds are dropped at startup. The database schema is versioned.
- Boolean environment variables accept 1/0/yes/no. The client never takes the policy or
  models from the working directory. On Windows without `HOME` the client cache lives in
  `%LOCALAPPDATA%\customs`.

### Fixed

- Upstream requests have overall time limits (10 minutes for an archive, 2 minutes for
  pages and metadata); a slow upstream gets a 502 instead of hanging. A cut-off npm
  passthrough body is a 502, not an empty 200. Truncated cached archives are downloaded
  again, and partial downloads left by a crash are removed at startup.
- PyPI pins match by PEP 440 equality, caret bounds never overflow, npm aliases are
  compared by the package they install, and bare local paths count as non-registry
  dependencies.
- The hook never panics on unusual input (non-ASCII short options), keeps tampering
  findings when no checker starts, and matches the Customs address by parsed host and
  port.
- MCP: unknown tool arguments are rejected, at most 16 requests run at once, lockfile
  reads no longer block the server, and `audit_lockfile` never answers allow when checks
  failed.
- Model loading rejects non-finite weights, calibrations that are not a non-decreasing
  probability and GBDT features the scanner does not produce; a non-finite risk blocks.
  A corrupt `metrics.json` is logged and ignored instead of stopping startup.
- Webhooks count failed deliveries in the next message, and policy alerts no longer wait
  behind verdict retries.
- Dashboard: refuses non-JSON success responses instead of showing a default policy,
  recovers the live feed after a late server start and catches up on lagged events, keeps
  Activity search and paging in the URL, handles bad verdict ids, accepts version ranges
  on the Check page, says what monitor mode and checks did with a blocked package, and
  no longer squeezes Policy rule labels to one word per line.
- Hardening: upstream registry credentials no longer appear in the server log or in the
  errors pip and npm show; every response carries a Content-Security-Policy,
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Referrer-Policy:
  no-referrer`; ten wrong admin tokens in a minute lock that address out of policy
  changes for the rest of the minute; scans run at most one per CPU at a time, which
  bounds memory under a burst of large packages; `GET /api/model` no longer names the
  server's models directory.
- Hardening: registry metadata that does not list a file, or cannot be read, no longer
  skips the age rule (it counts as an unknown publish time); `/api/check` and
  `/api/diff` refuse names that are not package names and fetch archives only from the
  configured upstream hosts; the npm passthrough forwards only reads and audit queries,
  never writes with the proxy's credentials; index pages, metadata and passthrough
  answers are capped at 256 MB; scan summaries are cached per file name; the host check
  also applies with `--allow-anonymous-policy-changes`; the scanner reads long lines of
  unclosed regex literals and many U+2028 separators in linear time, and says so when a
  file has more hidden imports than it follows; failed cache writes leave no partial
  files; the GitHub Action's log summary cannot start a workflow command.
- Hooks also flag `typeset`, `readonly`, `local`, `setx` and PowerShell variable forms,
  `HOME`, `XDG_CONFIG_HOME`, `APPDATA` and `NPM_CONFIG_PREFIX`, find-links lines, the
  global `npmrc` and pnpm's config files, and the same changes inside `bash -c`,
  `pwsh -Command` and `cmd /c`.
- Clearer startup errors: an empty admin token, a missing dashboard directory, an
  unwritable data directory, an unreadable `CUSTOMS_CA_FILE`, a malformed `--bind`, a
  models directory without a manifest, and no models found (the warning lists where it
  looked). A `--server` that is not a URL is named instead of silently checking
  in-process.
- npm files inside a directory of the same name (`dist/compiled/ipaddr.js/ipaddr.js` in
  `next`) are no longer reported as `unread_code`, which blocked `next` 16.4.0.
- `customs serve` hands memory back after a burst of installs: one `npm install` of about
  450 packages left it at 1.2 GB resident for good. With two glibc malloc arenas
  (`MALLOC_ARENA_MAX` still overrides) and a trim every 10 seconds, a larger run (`check
  next`, a 12-package pip install and that npm install) peaks under 0.5 GB and settles
  under 0.2 GB. Expired package metadata is dropped while idle.
- Training tools: UTF-8 for all text I/O, and a missing GuardDog, an empty held-out half,
  a timed-out parity check or a CNN run without a usable validation PR AUC give a clear
  error or a recorded result instead of a crash. MalRegistry dev-half rows that
  near-duplicate validation or test malware are dropped.

### Security

- Upstream credentials are shown as `***` in the API, change log, webhook and logs;
  sending `***` back for the same URL keeps the stored credentials. Upstream URLs with a
  query or fragment are rejected. `customs doctor` never prints index URL credentials.
- The Vite dev origin is gone from CORS and the Origin check.
- `customs audit` trusts a loopback registry only at the Customs server's port.
- More registry rewrites are flagged by the hook (`npm set registry`, `python -m pip
  config`, `PIP_CONFIG_FILE`, Windows `npm.cmd`).

## v0.9.0: registry firewall, agent hooks and lockfile audit

Never tagged; everything here ships in 1.0.0.

### Firewall

- `customs serve` proxies PyPI (simple index, PEP 691 JSON) and npm, scans every archive
  in memory before handing it over, and answers allow, warn or block.
- Malware classifier: gradient-boosted trees over 77 static features, a 1D CNN over the
  install-time token stream, and a package-name model for typosquats, stacked and
  calibrated. Inference runs in Rust from JSON exports, with parity tests against the
  Python reference.
- Policy rules in `customs.toml`: allow and deny lists, names that do not exist, a release
  cooldown (`min_age_days`), install scripts in new packages, and release history rules
  (provenance dropped, install script added, new publisher, dormant revival, git or URL
  dependency added, young dependency added).
- An established-release prior (`[established]`): a release of one of the 5,000 most
  popular PyPI or npm packages, at least 30 days old and not yanked, is allowed over the
  model. This clears the model's false positives on `requests` 2.32.3 (block) and 2.34.2
  (warn). The deny list and every other rule still apply.
- Fail-closed rules for code the scanner cannot read, `.pth` startup hooks that run
  code, and install-time code that starts an AI coding CLI with its permission checks off.
- Dashboard with a live install feed, verdict explanations with code evidence, a package
  checker, policy editing and a policy change log.
- Webhook alerts for Slack, Discord or any JSON receiver; Prometheus metrics.

### Agents

- Pre-execution hooks for Claude Code, Cursor, Gemini CLI and Codex CLI. They find the
  packages a shell command would install, including behind wrappers, in inline code, in
  PEP 723 script headers, in Deno imports and in project lockfiles, and deny the command
  when a package is blocked.
- Commands and edits that would switch Customs off come back to the user for
  confirmation.
- `customs mcp`, a Model Context Protocol server with six tools.
- `customs doctor` finds installs in a project that would skip the proxy.

### CI and supply chain

- `customs audit` checks every pin in nine lockfile formats and in MCP server configs,
  blocks lockfile injection, and writes SARIF for GitHub code scanning. `action.yml`
  wraps it as a GitHub Action.
- `customs diff` shows what a release adds over an earlier one.

### Distribution

- Each GitHub release carries prebuilt archives for Linux (x86_64) and macOS (Apple
  silicon) with the binaries, models and dashboard, plus a container image on ghcr.io.

### Known issues

- A fresh release of a popular package still gets the model's verdict, false positive or
  not: `postcss` 8.5.29 (published 2026-10-05) warns until it is 30 days old.
- Windows is not tested.
