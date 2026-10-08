# Claude Code hook

`customs hook claude-code` is a [PreToolUse hook](https://code.claude.com/docs/en/hooks)
for the `Bash` tool and the file-editing tools. Before Claude Code runs a shell command,
the hook finds package installs in it, checks every package, and answers:

| Outcome | Hook output |
|---|---|
| any package is blocked (malicious, nonexistent, too new, denied) | `permissionDecision: "deny"` with the reasons |
| any package is warned, or cannot be checked (git URL, local path, custom index) | `permissionDecision: "ask"` so you decide |
| everything is allowed, or the command installs nothing | no output, exit 0 (normal permission flow) |

The hook always exits 0 and speaks JSON on stdout, for example:

```json
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
  "permissionDecisionReason": "Customs blocked this install:\n- pypi:reqeusts: 'reqeusts' does not exist on PyPI (possibly a hallucinated or mistyped name); model risk 0.83 (1 edit from popular package 'requests') [http://127.0.0.1:7878/api/verdicts/12]\n..."}}
```

## Install

1. Put `customs` on your `PATH` (`cargo install --path crates/customs`).
2. Optionally start the proxy so verdicts are shared and shown in the dashboard:
   `customs serve` (default `http://127.0.0.1:7878`). Without a running server the hook
   checks in-process, using `~/.cache/customs` for its cache.
3. Merge [`claude-code-settings.json`](claude-code-settings.json) into
   `~/.claude/settings.json` (all projects) or `.claude/settings.json` (one project):

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash|Edit|Write|MultiEdit|NotebookEdit",
        "hooks": [ { "type": "command", "command": "customs hook claude-code", "timeout": 60 } ] }
    ]
  }
}
```

Run `/hooks` in Claude Code to confirm it is registered.

## What it recognizes

`pip`/`pip3`/`python -m pip` `install` (also `download` and `wheel`, which run `setup.py`),
`uv pip install`, `uv add`, `uv tool install`, `uv run --with`, `uvx`, `poetry add`,
`pdm add`, `pipx install|run|inject`, `npm install|i|add` (and npm's aliases),
`npm exec`, `pnpm add`, `pnpm dlx`, `yarn add`, `yarn dlx`, `bun add`, `bunx`, and `npx`.
Scaffolding commands run a package too: `npm create vite` and `npm init vite` run
`create-vite`, and so do `pnpm create`, `yarn create` and `bun create` (`@scope/app` is
`@scope/create-app`); `bun create` from a GitHub repository comes back for review.
Deno: `deno add` and `deno install` with `npm:` packages, `deno install -g`, `deno run`,
`deno x` and `dx` with an npm package, and `deno create npm:<x>`. JSR packages and remote
`https:` modules cannot be checked and come back for review.

Project installs too: `npm install` and `npm ci` with no package, `pnpm install`, `yarn`,
`bun install`, `deno install`, `deno ci`, `uv sync`, `poetry install`, `pipenv install`, `pipenv sync`, and
`pip install -e .` (with extras such as `.[dev]`) for a directory with a `pyproject.toml`. The hook
reads the project's lockfile, checks every pinned package, and denies the command when one
is blocked or when a lockfile entry's tarball URL serves a different package than it
names. Lockfile entries fetched from git, a URL or another registry come back for review,
since nothing has checked them. Dependencies in `package.json`, `deno.json`, `pyproject.toml` or `Pipfile` that the lockfile does
not pin yet (one the agent just added) are checked as well. Warnings about packages the
lockfile already pins do not stop the command; on a real 300-package lockfile, about 1% of
legitimate packages are over the warn threshold. A large project with nothing cached yet
is checked for up to 40 seconds; anything left is reported for review.

The command is split like a shell would: `&&`, `||`, `;`, pipes, subshells, quotes,
escapes, line continuations, comments, redirections, `$(...)` and backticks, and wrappers
such as `sudo`, `env FOO=1`, `timeout 60`, `nohup`, `bash -c '...'`, and `eval`. Option
values (`--target dir`, `-c constraints.txt`) are never mistaken for packages.

Requirements: `pkg`, `pkg==1.2`, `pkg>=1,<2`, `pkg[extra]`, `pkg; markers`, Poetry and uv
`pkg@^1.2`, npm `pkg@1.2.3`, `@scope/pkg@^1`, dist-tags, and aliases `a@npm:b@1`. Ranges are
resolved by the server to the version a fresh install would pick. `-r requirements.txt`
(relative to the hook input's `cwd`, nested `-r` relative to the including file) is read
and every line checked. Editable installs of local paths (`-e .`) are skipped; git, URL,
local path, and tarball specs and custom indexes (`-i`, `--extra-index-url`, `--registry`)
cannot be checked and produce `ask`.

## Tampering

An agent that can run shell commands can also turn the firewall off, and a prompt
injection that wants a package installed would start there. These come back as `ask`
with the reason, so you confirm them:

- changing the policy through `PUT /api/policy`, or writing to `customs.toml`;
- stopping the server (`pkill`, `killall`, `kill` naming customs, `systemctl stop`,
  `docker stop`);
- editing `.claude/settings*.json`, where this hook is registered, from the shell or with
  the Edit and Write tools;
- pointing an installer away from the proxy: setting or unsetting `PIP_INDEX_URL`,
  `npm_config_registry` and the other variables `customs env` sets, `npm|pnpm|yarn|bun
  config set registry`, `pip config set global.index-url`, or writing a registry or index
  line into `.npmrc`, `pip.conf`, `.yarnrc.yml`, `bunfig.toml` or `uv.toml`. Values that
  point at the Customs server are fine.

The matcher `Bash|Edit|Write|MultiEdit|NotebookEdit` in the settings above is what lets
the hook see file edits. A command that builds itself at run time (`echo ... | base64 -d
| sh`) is beyond any static check, so treat this as a tripwire for the obvious routes, not
a sandbox; the proxy's own `PUT /api/policy` also refuses requests a browser page could
send.

## Options

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--server URL` | `CUSTOMS_SERVER` | `http://127.0.0.1:7878` | Server to ask; in-process when unreachable |
| `--fail-closed` | `CUSTOMS_HOOK_FAIL_CLOSED` | off | Deny when Customs itself fails (bad input, registry unreachable) instead of staying silent |
| `--config FILE` | | `./customs.toml` | Policy for in-process checks |
| `--models DIR` | `CUSTOMS_MODELS` | `./models`, then next to the binary | Models for in-process checks |
| `--data-dir DIR` | `CUSTOMS_DATA_DIR` | `~/.cache/customs` | Cache for in-process checks |

By default the hook fails open: if it cannot check a package it writes the reason to
stderr and returns no decision, so a broken Customs setup does not stop your work. Use
`--fail-closed` where an unchecked install is worse than a blocked command.

# MCP server

`customs mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server over
stdio. The hook above stops an install the agent already decided to run; the MCP tools let
the agent ask before it proposes a package or a command at all. It works with any MCP
client: Claude Code, Claude Desktop, Cursor, and others.

| Tool | Use |
|---|---|
| `check_package` | Check one package (`ecosystem`, `name`, optional `version`) |
| `check_install_command` | Check every package a shell command would install |
| `explain_verdict` | Reasons and code evidence for a verdict id (needs `customs serve`) |
| `audit_lockfile` | Check every package a lockfile or project directory pins, e.g. when reviewing a change to a lockfile |
| `scan_archive` | Scan a local archive file offline |

A block is an ordinary answer; a tool reports an error only when the check itself failed.

## Register it

Claude Code:

```sh
claude mcp add customs -- customs mcp
```

Add `--scope user` (before `--`) to use it in every project, or `--scope project` to share
it with the repository through `.mcp.json`. For other clients, merge
[`mcp.json`](mcp.json) into their MCP configuration (Claude Desktop:
`claude_desktop_config.json`; Cursor: `.cursor/mcp.json`):

```json
{ "mcpServers": { "customs": { "command": "customs", "args": ["mcp"] } } }
```

Run `/mcp` in Claude Code to confirm the server is connected.

## MCP options

`customs mcp` takes the same `--server`, `--config`, `--models` and `--data-dir` options as
the hook (table above), with the same defaults: it asks a running `customs serve` when one
answers and otherwise checks in-process. Pass them after `mcp`, for example
`claude mcp add customs -- customs mcp --server http://10.0.0.5:7878`.
