# Customs in GitHub Actions

The `action.yml` at the root of this repository runs `customs audit` on the lockfiles in
your repository and uploads the result to GitHub code scanning. Every pinned package is
checked with the malware classifier and the policy rules (nonexistent names, deny list,
minimum age, install scripts in young packages), and npm, Yarn and pnpm entries whose
`resolved` tarball URL names a different package or version than the entry are blocked as
lockfile injection. Blocked and warned packages show up as
code scanning alerts on the lockfile line that pins them, and in the pull request diff.

MCP server configurations in the repository (`.mcp.json`, `.cursor/mcp.json`,
`.vscode/mcp.json`, `.gemini/settings.json`, `.codex/config.toml`) are checked the same
way: each package a server launches with `npx`, `uvx` or a similar launcher, at its
pinned version or, without one, at the newest release. A server without an exact version
also gets a note-level alert (`customs/unpinned-mcp-server`), since each agent start runs
whatever release is newest.

Entries that fetch code Customs cannot check (git and URL dependencies, packages from a
custom index, MCP servers with a launcher it does not recognise) get a note-level alert
(`customs/unchecked-source`) at their line. Notes never fail the job, whatever `fail-on`
says.

## Workflow

Save this as `.github/workflows/customs.yml`:

```yaml
name: Customs

on:
  pull_request:
    paths:
      - "**/requirements*.txt"
      - "**/poetry.lock"
      - "**/uv.lock"
      - "**/Pipfile.lock"
      - "**/package-lock.json"
      - "**/npm-shrinkwrap.json"
      - "**/pnpm-lock.yaml"
      - "**/yarn.lock"
      - "**/bun.lock"
      - "customs.toml"
  # Code scanning compares pull requests against the default branch, so audit it too.
  push:
    branches: [main]
    paths:
      - "**/requirements*.txt"
      - "**/poetry.lock"
      - "**/uv.lock"
      - "**/Pipfile.lock"
      - "**/package-lock.json"
      - "**/npm-shrinkwrap.json"
      - "**/pnpm-lock.yaml"
      - "**/yarn.lock"
      - "**/bun.lock"
      - "customs.toml"

permissions:
  contents: read
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: yib7/customs@main
        with:
          paths: .
          recursive: true
          fail-on: block
```

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `paths` | `.` | Lockfiles or directories, separated by spaces or newlines |
| `recursive` | `false` | Search directories recursively (skips `node_modules`, `.git`, `.venv`, `target`) |
| `fail-on` | `block` | Fail the job when a package is at least this severe: `block`, `warn`, or `never` |
| `upload-sarif` | `true` | Upload the report to code scanning (needs `security-events: write`) |
| `sarif-file` | `customs.sarif` | Where the report is written |
| `config` | | Policy file; by default `./customs.toml` is used when present |
| `jobs` | `8` | Packages checked at once |
| `cache` | `true` | Cache the built binary and the scan results between runs |

Outputs: `exit-code` (0 clean, 1 findings at or above `fail-on`, 2 error) and
`sarif-file`. The SARIF report is uploaded before the job fails, so alerts appear even on
a failing run.

## Notes

- The first run builds Customs from source with `cargo install` (a few minutes on a
  GitHub-hosted runner, which has Rust preinstalled); later runs restore the binary from
  the Actions cache. Self-hosted runners need a Rust toolchain.
- The trained models ship in the action's `models/` directory and are used through
  `CUSTOMS_MODELS`; no model download happens.
- Package archives are downloaded from PyPI and npm (or the `[upstream]` registries in
  your `customs.toml`) and scanned on the runner. Results are cached by archive digest, so
  unchanged dependencies are not rescanned.
- Packages from private registries or custom indexes, VCS and URL dependencies, local
  paths, and unpinned requirements are listed as "not checked" in the log and are not
  alerts. To accept a package Customs flags, add it to `allow` in `customs.toml`.
- Run the same audit locally with `customs audit -r`, or `customs audit -r --format json`.
