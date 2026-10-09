# Changelog

Versions follow [semantic versioning](https://semver.org). Each release title names what
shipped in it.

## v0.9.0: registry firewall, agent hooks and lockfile audit

First public release. Not tagged yet.

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

- The model scores the `requests` 2.32.3 sdist above the block threshold and warns on
  `requests` 2.34.2 and `postcss` 8.5.29. Until the next retrain, add `pypi:requests` and
  `npm:postcss` to `allow` in `customs.toml`.
- Windows is not tested.
