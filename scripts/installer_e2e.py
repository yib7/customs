#!/usr/bin/env python3
"""Real installers through Customs, against a local fake registry.

    python3 scripts/installer_e2e.py [--bin target/debug/customs]

Starts a fake PyPI (simple index in HTML and JSON, JSON API, files) and a fake npm
registry on 127.0.0.1, both serving wheels and tarballs built here, then `customs serve`
with its upstream pointed at them, and drives pip, uv, npm, pnpm, yarn and bun through
the proxy (each that is installed; --require lists the ones that must be):

- a plain install, with a dependency resolved through the proxy;
- an unpinned install of a package whose newest release is younger than min_age_days
  gets the newest older release, and pinning the young release fails;
- a wheel with a startup .pth hook and an npm release that adds an install script are
  refused.

Nothing installed here is executed: wheels are installed with --target (no .pth file is
ever on a site path), npm runs with --ignore-scripts, and the fixtures' hooks only echo.
Uses only the standard library. Exits non-zero on the first failed expectation.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request
import zipfile
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime.now(UTC)


def ago(**kw) -> str:
    return (NOW - timedelta(**kw)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ---------------------------------------------------------------------------- fixtures

# Ordinary library code, so the fixtures look like the small utilities they stand in for
# (the model blocks tiny packages with no description or repository, as throwaway
# malware usually is).
PY_CODE = '''"""Small text helpers."""

import re
import unicodedata

_WS = re.compile(r"\\s+")


def slugify(text: str, sep: str = "-") -> str:
    """Lower-case ASCII slug of `text`."""
    norm = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode()
    words = re.findall(r"[a-z0-9]+", norm.lower())
    return sep.join(words)


def squash(text: str) -> str:
    """Collapse runs of whitespace into single spaces."""
    return _WS.sub(" ", text).strip()


def truncate(text: str, width: int, ellipsis: str = "...") -> str:
    """Cut `text` to `width` characters, ending on a word where possible."""
    if len(text) <= width:
        return text
    cut = text[: max(0, width - len(ellipsis))]
    if " " in cut:
        cut = cut[: cut.rfind(" ")]
    return cut + ellipsis


def chunks(items, size: int):
    """Yield lists of `size` items."""
    if size < 1:
        raise ValueError("size must be positive")
    batch = []
    for item in items:
        batch.append(item)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


def plural(word: str, count: int) -> str:
    """`word` with an English plural suffix when `count` is not 1."""
    if count == 1:
        return word
    if word.endswith(("s", "x", "z", "ch", "sh")):
        return word + "es"
    if word.endswith("y") and word[-2:-1] not in "aeiou":
        return word[:-1] + "ies"
    return word + "s"
'''

JS_CODE = """'use strict';

/** Small text helpers. */

function slugify(text, sep = '-') {
  return String(text)
    .normalize('NFKD')
    .replace(/[\\u0300-\\u036f]/g, '')
    .toLowerCase()
    .match(/[a-z0-9]+/g)
    ?.join(sep) ?? '';
}

function squash(text) {
  return String(text).replace(/\\s+/g, ' ').trim();
}

function truncate(text, width, ellipsis = '...') {
  if (text.length <= width) return text;
  let cut = text.slice(0, Math.max(0, width - ellipsis.length));
  const space = cut.lastIndexOf(' ');
  if (space > 0) cut = cut.slice(0, space);
  return cut + ellipsis;
}

function chunks(items, size) {
  if (size < 1) throw new RangeError('size must be positive');
  const out = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

function plural(word, count) {
  if (count === 1) return word;
  if (/(s|x|z|ch|sh)$/.test(word)) return word + 'es';
  if (/[^aeiou]y$/.test(word)) return word.slice(0, -1) + 'ies';
  return word + 's';
}

module.exports = { slugify, squash, truncate, chunks, plural };
"""

README = """# {name}

Small text helpers: `slugify`, `squash`, `truncate`, `chunks` and `plural`.

## Install

    {install} {name}

## Usage

Each function takes a string (or a list for `chunks`) and returns a new value; nothing is
modified in place. `truncate` ends on a word boundary when the cut falls inside a word.

## License

MIT
"""


def wheel(
    name: str,
    version: str,
    requires: tuple[str, ...] | list[str] = (),
    extra: dict[str, str] | None = None,
):
    """A pure-Python wheel: (file name, bytes, METADATA bytes)."""
    dist = name.replace("-", "_")
    info = f"{dist}-{version}.dist-info"
    files = {
        f"{dist}/__init__.py": f'__version__ = "{version}"\n\n'
        "from .text import chunks, plural, slugify, squash, truncate  # noqa: F401\n",
        f"{dist}/text.py": PY_CODE,
        f"{info}/METADATA": "Metadata-Version: 2.1\n"
        f"Name: {name}\nVersion: {version}\n"
        "Summary: Small text helpers: slugify, squash, truncate, chunks and plural\n"
        f"Home-page: https://github.com/example/{name}\n"
        "Author: Example Maintainers\nLicense: MIT\n"
        f"Project-URL: Source, https://github.com/example/{name}\n"
        "Classifier: License :: OSI Approved :: MIT License\n"
        "Classifier: Programming Language :: Python :: 3\n"
        "Requires-Python: >=3.8\n"
        + "".join(f"Requires-Dist: {r}\n" for r in requires)
        + "Description-Content-Type: text/markdown\n\n"
        + README.format(name=name, install="pip install"),
        f"{info}/WHEEL": "Wheel-Version: 1.0\nGenerator: customs-e2e\n"
        "Root-Is-Purelib: true\nTag: py3-none-any\n",
        **(extra or {}),
    }
    record = []
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for path, text in files.items():
            data = text.encode()
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
            record.append(f"{path},sha256={digest.decode()},{len(data)}")
            z.writestr(path, data)
        record.append(f"{info}/RECORD,,")
        z.writestr(f"{info}/RECORD", "\n".join(record) + "\n")
    return f"{dist}-{version}-py3-none-any.whl", buf.getvalue(), files[f"{info}/METADATA"].encode()


def npm_tarball(manifest: dict, files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        entries = {"package.json": json.dumps(manifest, indent=2), **files}
        for path, text in entries.items():
            data = text.encode()
            ti = tarfile.TarInfo(f"package/{path}")
            ti.size = len(data)
            ti.mtime = 499162500
            ti.mode = 0o644
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


# The startup hook only echoes; it never runs, since the wheel is refused (and --target
# keeps it off any site path if it were not).
PTH_HOOK = 'import subprocess; subprocess.Popen(["echo", "customs-e2e-fixture"])\n'

PYPI = [
    # (name, version, uploaded, requires, extra files)
    ("calm-lib", "1.0.0", ago(days=200), [], None),
    ("calm-lib", "1.1.0", ago(hours=2), [], None),
    ("plain-util", "2.0.0", ago(days=300), ["calm-lib>=1.0"], None),
    ("evil-helper", "0.1.0", ago(days=90), [], {"evil_helper_init.pth": PTH_HOOK}),
]

NPM = [
    # (name, version, published, dependencies, scripts)
    ("calm-js", "1.0.0", ago(days=200), {}, {}),
    ("calm-js", "1.1.0", ago(hours=2), {}, {}),
    ("plain-js", "2.0.0", ago(days=300), {"calm-js": "^1.0.0"}, {}),
    ("evil-js", "1.0.0", ago(days=200), {}, {}),
    ("evil-js", "1.0.1", ago(days=30), {}, {"postinstall": "node setup.js"}),
]
EVIL_SETUP = "require('child_process').exec('echo customs-e2e-fixture');\n"


class Registry:
    def __init__(self):
        self.base = ""
        self.paths: list[str] = []
        self.wheels: dict[str, list[dict]] = {}
        self.files: dict[str, bytes] = {}
        for name, ver, t, req, extra in PYPI:
            fname, data, meta = wheel(name, ver, req, extra)
            self.files[fname] = data
            # PEP 658: resolvers read the metadata file before choosing a version.
            self.files[fname + ".metadata"] = meta
            self.wheels.setdefault(name, []).append(
                {
                    "version": ver,
                    "filename": fname,
                    "time": t,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "meta_sha256": hashlib.sha256(meta).hexdigest(),
                    "size": len(data),
                }
            )
        self.tarballs: dict[str, bytes] = {}
        self.packuments: dict[str, dict] = {}
        for name, ver, t, deps, scripts in NPM:
            manifest = {
                "name": name,
                "version": ver,
                "description": "Small text helpers: slugify, squash, truncate, chunks and plural",
                "main": "index.js",
                "keywords": ["string", "slug", "text"],
                "author": "Example Maintainers",
                "license": "MIT",
                "repository": {"type": "git", "url": f"git+https://github.com/example/{name}.git"},
                "homepage": f"https://github.com/example/{name}#readme",
                "dependencies": deps,
                "scripts": {"test": "node --test", **scripts},
            }
            files = {
                "index.js": JS_CODE,
                "README.md": README.format(name=name, install="npm install"),
            }
            if scripts:
                files["setup.js"] = EVIL_SETUP
            data = npm_tarball(manifest, files)
            self.tarballs[f"{name}-{ver}.tgz"] = data
            doc = self.packuments.setdefault(
                name, {"name": name, "dist-tags": {}, "time": {"created": t}, "versions": {}}
            )
            doc["versions"][ver] = {
                **manifest,
                "_npmUser": {"name": "maintainer"},
                "dist": {
                    "tarball": f"@BASE@/npm/{name}/-/{name}-{ver}.tgz",
                    "shasum": hashlib.sha1(data).hexdigest(),
                    "integrity": "sha512-"
                    + base64.b64encode(hashlib.sha512(data).digest()).decode(),
                },
            }
            doc["time"][ver] = t
            doc["dist-tags"]["latest"] = ver

    def handler(self):
        reg = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def send(self, code, body, ctype="application/json"):
                if isinstance(body, (dict, list)):
                    body = json.dumps(body).replace("@BASE@", reg.base).encode()
                elif isinstance(body, str):
                    body = body.encode()
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                p = self.path.split("?")[0]
                reg.paths.append(p)
                parts = [x for x in p.split("/") if x]
                if parts[:1] == ["simple"] and len(parts) == 2:
                    return self.simple(parts[1])
                if parts[:1] == ["pypi"] and parts[-1] == "json":
                    return self.pypi_json(parts[1], parts[2] if len(parts) == 4 else None)
                if parts[:1] == ["files"] and parts[-1] in reg.files:
                    return self.send(200, reg.files[parts[-1]], "application/octet-stream")
                if parts[:1] == ["npm"] and "-" in parts and parts[-1] in reg.tarballs:
                    return self.send(200, reg.tarballs[parts[-1]], "application/octet-stream")
                if parts[:1] == ["npm"] and len(parts) == 2 and parts[1] in reg.packuments:
                    return self.send(200, reg.packuments[parts[1]])
                self.send(404, {"error": "Not found"})

            def simple(self, project):
                rows = reg.wheels.get(project)
                if not rows:
                    return self.send(404, "Not Found", "text/plain")

                def url(r):
                    return f"{reg.base}/files/packages/ab/cd/{r['filename']}"

                if "application/vnd.pypi.simple.v1+json" in self.headers.get("Accept", ""):
                    return self.send(
                        200,
                        {
                            "meta": {"api-version": "1.1"},
                            "name": project,
                            "versions": [r["version"] for r in rows],
                            "files": [
                                {
                                    "filename": r["filename"],
                                    "url": url(r),
                                    "hashes": {"sha256": r["sha256"]},
                                    "core-metadata": {"sha256": r["meta_sha256"]},
                                    "upload-time": r["time"],
                                    "size": r["size"],
                                }
                                for r in rows
                            ],
                        },
                        "application/vnd.pypi.simple.v1+json",
                    )
                links = "\n".join(
                    f'<a href="{url(r)}#sha256={r["sha256"]}" data-requires-python="&gt;=3.8" '
                    f'data-dist-info-metadata="sha256={r["meta_sha256"]}" '
                    f'data-core-metadata="sha256={r["meta_sha256"]}">{r["filename"]}</a><br/>'
                    for r in rows
                )
                self.send(
                    200, f"<!DOCTYPE html><html><body>\n{links}\n</body></html>\n", "text/html"
                )

            def pypi_json(self, project, version):
                rows = reg.wheels.get(project)
                if not rows:
                    return self.send(404, {"message": "Not Found"})

                def file(r):
                    return {
                        "filename": r["filename"],
                        "url": f"{reg.base}/files/packages/ab/cd/{r['filename']}",
                        "upload_time_iso_8601": r["time"],
                        "packagetype": "bdist_wheel",
                        "size": r["size"],
                        "digests": {"sha256": r["sha256"]},
                        "yanked": False,
                    }

                if version:
                    r = next((r for r in rows if r["version"] == version), None)
                    if r is None:
                        return self.send(404, {"message": "Not Found"})
                    return self.send(
                        200, {"info": {"name": project, "version": version}, "urls": [file(r)]}
                    )
                return self.send(
                    200,
                    {
                        "info": {"name": project, "version": rows[-1]["version"]},
                        "releases": {r["version"]: [file(r)] for r in rows},
                    },
                )

        return H


# ---------------------------------------------------------------------------- harness


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


FAILURES = 0


def expect(ok: bool, what: str, detail: str = "") -> None:
    global FAILURES
    print(("ok    " if ok else "FAIL  ") + what)
    if not ok:
        FAILURES += 1
        if detail:
            print("      " + detail.strip().replace("\n", "\n      ")[-3000:])


def run(
    cmd: list[str], cwd: Path | None = None, env: dict | None = None
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
        encoding="utf-8",
        errors="replace",
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--bin", default=str(ROOT / "target/debug/customs"))
    ap.add_argument(
        "--require", default="pip,uv,npm", help="comma-separated installers that must be present"
    )
    args = ap.parse_args()
    required = set(filter(None, args.require.split(",")))

    work = Path(tempfile.mkdtemp(prefix="customs-e2e-"))
    reg = Registry()
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), reg.handler())
    reg.base = f"http://127.0.0.1:{upstream.server_address[1]}"
    threading.Thread(target=upstream.serve_forever, daemon=True).start()

    port = free_port()
    url = f"http://127.0.0.1:{port}"
    (work / "customs.toml").write_text(
        "min_age_days = 3\n"
        "[upstream]\n"
        f'pypi_simple = "{reg.base}/simple"\n'
        f'pypi_files = "{reg.base}/files"\n'
        f'pypi_json = "{reg.base}/pypi"\n'
        f'npm = "{reg.base}/npm"\n',
        encoding="utf-8",
    )
    with open(work / "server.log", "w", encoding="utf-8") as log:
        server = subprocess.Popen(
            [
                args.bin,
                "serve",
                "--bind",
                f"127.0.0.1:{port}",
                "--data-dir",
                str(work / "data"),
                "--config",
                str(work / "customs.toml"),
            ],
            stdout=log,
            stderr=subprocess.STDOUT,
            cwd=ROOT,
        )
        try:
            if not wait_healthy(url, server):
                print((work / "server.log").read_text(encoding="utf-8"))
                print("customs serve did not start")
                return 1
            scenarios(url, work, required)
            metadata = [p for p in reg.paths if p.endswith(".whl.metadata")]
            expect(bool(metadata), "resolvers read PEP 658 metadata files through the proxy")
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
            upstream.shutdown()
            if FAILURES:
                print("--- server log (tail)")
                print((work / "server.log").read_text(encoding="utf-8")[-4000:])
            shutil.rmtree(work, ignore_errors=True)
    print(f"\n{FAILURES} failed" if FAILURES else "\nall passed")
    return 1 if FAILURES else 0


def js_manager(tool: str, url: str, work: Path, env: dict) -> None:
    """The npm scenarios with another client: pnpm and bun read the abbreviated packument."""
    print(f"== {tool}")
    registry = f"{url}/npm/"
    proj = work / tool
    proj.mkdir()
    (proj / "package.json").write_text(
        '{"name": "e2e", "version": "1.0.0", "private": true}\n', encoding="utf-8"
    )
    tool_env = {
        **env,
        "npm_config_registry": registry,
        "npm_config_ignore_scripts": "true",
        "npm_config_store_dir": str(work / f"{tool}-store"),
        "YARN_CACHE_FOLDER": str(work / f"{tool}-cache"),
        "BUN_INSTALL_CACHE_DIR": str(work / f"{tool}-cache"),
        "BUN_CONFIG_REGISTRY": registry,
    }
    add = {
        "pnpm": ["pnpm", "add", "--ignore-scripts", "--registry", registry],
        "yarn": ["yarn", "add", "--ignore-scripts", "--non-interactive", "--registry", registry],
        "bun": ["bun", "add", "--ignore-scripts", "--registry", registry],
    }[tool]

    def version(pkg: str) -> str | None:
        p = proj / "node_modules" / pkg / "package.json"
        return json.loads(p.read_text(encoding="utf-8"))["version"] if p.exists() else None

    r = run([*add, "plain-js"], cwd=proj, env=tool_env)
    expect(
        r.returncode == 0 and version("plain-js") == "2.0.0",
        "plain-js installs",
        r.stdout + r.stderr,
    )
    # pnpm keeps transitive dependencies out of the top-level node_modules.
    nested = proj / "node_modules" / "plain-js" / "node_modules" / "calm-js" / "package.json"
    calm = version("calm-js") or (
        json.loads(nested.read_text(encoding="utf-8"))["version"] if nested.exists() else None
    )
    if calm is None:
        store = proj / "node_modules" / ".pnpm"
        calm = (
            next((d.name.split("@")[-1] for d in store.glob("calm-js@*")), None)
            if store.exists()
            else None
        )
    expect(calm == "1.0.0", "its dependency resolves to calm-js 1.0.0", str(calm))
    r = run([*add, "evil-js@1.0.1"], cwd=proj, env=tool_env)
    expect(
        r.returncode != 0 and version("evil-js") is None,
        "evil-js 1.0.1 is refused",
        r.stdout + r.stderr,
    )


def wait_healthy(url: str, server: subprocess.Popen, seconds: float = 60) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and server.poll() is None:
        try:
            urllib.request.urlopen(f"{url}/healthz", timeout=1).read()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def installed(target: Path) -> set[str]:
    return {p.name for p in target.glob("*.dist-info")} if target.exists() else set()


def scenarios(url: str, work: Path, required: set[str]) -> None:
    env = {
        **os.environ,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_CACHE_DIR": "1",
        "PIP_NO_INPUT": "1",
    }
    index = f"{url}/pypi/simple"

    print("== pip (HTML simple index)")
    pip = [sys.executable, "-m", "pip", "install", "--index-url", index, "--no-compile"]
    t = work / "pip1"
    r = run(pip + ["--target", str(t), "plain-util"], env=env)
    expect(
        r.returncode == 0
        and installed(t) == {"plain_util-2.0.0.dist-info", "calm_lib-1.0.0.dist-info"},
        "plain-util installs, its dependency resolves to calm-lib 1.0.0 (1.1.0 is 2 hours old)",
        r.stdout + r.stderr + str(installed(t)),
    )
    t = work / "pip2"
    r = run(pip + ["--target", str(t), "calm-lib==1.1.0"], env=env)
    out = r.stdout + r.stderr
    expect(
        r.returncode != 0 and not installed(t) and "403" in out and "min_age_days" in out,
        "pinning calm-lib==1.1.0 selects the yanked-marked file and gets the 403 with the reason",
        out,
    )
    t = work / "pip3"
    r = run(pip + ["--target", str(t), "evil-helper"], env=env)
    expect(
        r.returncode != 0 and not installed(t) and "403" in r.stdout + r.stderr,
        "evil-helper (startup .pth hook) is refused with 403",
        r.stdout + r.stderr,
    )
    r = run(pip + ["--target", str(work / "pip4"), "no-such-pkg-e2e"], env=env)
    expect(r.returncode != 0, "an unknown name is not found", r.stdout + r.stderr)

    if shutil.which("uv"):
        print("== uv (JSON simple index)")
        uv = [
            "uv",
            "pip",
            "install",
            "--no-cache",
            "--python",
            sys.executable,
            "--index-url",
            index,
        ]
        t = work / "uv1"
        r = run(uv + ["--target", str(t), "plain-util"], env=env)
        expect(
            r.returncode == 0
            and installed(t) == {"plain_util-2.0.0.dist-info", "calm_lib-1.0.0.dist-info"},
            "plain-util installs, calm-lib resolves to 1.0.0",
            r.stdout + r.stderr + str(installed(t)),
        )
        r = run(uv + ["--target", str(work / "uv2"), "calm-lib==1.1.0"], env=env)
        expect(
            r.returncode != 0 and "403" in r.stdout + r.stderr,
            "pinning calm-lib==1.1.0 gets the 403",
            r.stdout + r.stderr,
        )
        r = run(uv + ["--target", str(work / "uv3"), "evil-helper"], env=env)
        expect(
            r.returncode != 0 and not installed(work / "uv3"),
            "evil-helper is refused",
            r.stdout + r.stderr,
        )
    else:
        expect(
            "uv" not in required, "uv is installed", "uv is required (--require) but not on PATH"
        )

    if shutil.which("npm"):
        print("== npm")
        registry = f"{url}/npm/"
        proj = work / "npm1"
        proj.mkdir()
        (proj / "package.json").write_text(
            '{"name": "e2e", "version": "1.0.0", "private": true}\n', encoding="utf-8"
        )
        npm_env = {
            **env,
            "npm_config_cache": str(work / "npm-cache"),
            "npm_config_update_notifier": "false",
        }
        npm = [
            "npm",
            "install",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--registry",
            registry,
        ]

        def version(pkg: str) -> str | None:
            p = proj / "node_modules" / pkg / "package.json"
            return json.loads(p.read_text(encoding="utf-8"))["version"] if p.exists() else None

        r = run(npm + ["plain-js"], cwd=proj, env=npm_env)
        expect(
            r.returncode == 0 and version("plain-js") == "2.0.0" and version("calm-js") == "1.0.0",
            "plain-js installs, its dependency resolves to calm-js 1.0.0",
            r.stdout + r.stderr,
        )
        r = run(npm + ["calm-js"], cwd=proj, env=npm_env)
        dep = (
            json.loads((proj / "package.json").read_text(encoding="utf-8"))
            .get("dependencies", {})
            .get("calm-js")
        )
        expect(
            r.returncode == 0 and version("calm-js") == "1.0.0" and dep == "^1.0.0",
            "npm install calm-js saves ^1.0.0",
            r.stdout + r.stderr + str(dep),
        )
        r = run(npm + ["calm-js@1.1.0"], cwd=proj, env=npm_env)
        expect(
            r.returncode != 0 and version("calm-js") == "1.0.0",
            "pinning calm-js@1.1.0 fails (npm reports no matching version)",
            r.stdout + r.stderr,
        )
        r = run(npm + ["evil-js@1.0.1"], cwd=proj, env=npm_env)
        expect(
            r.returncode != 0 and version("evil-js") is None and "403" in r.stdout + r.stderr,
            "evil-js 1.0.1 (install script added) is refused with 403",
            r.stdout + r.stderr,
        )
        lock = json.loads((proj / "package-lock.json").read_text(encoding="utf-8"))
        resolved = lock["packages"]["node_modules/calm-js"]["resolved"]
        expect(
            resolved.startswith(registry), "package-lock.json resolves through the proxy", resolved
        )
    else:
        expect(
            "npm" not in required, "npm is installed", "npm is required (--require) but not on PATH"
        )

    for tool in ("pnpm", "yarn", "bun"):
        if shutil.which(tool):
            js_manager(tool, url, work, env)
        else:
            expect(
                tool not in required, f"{tool} is installed", f"{tool} is required but not on PATH"
            )

    print("== verdicts")
    events = json.load(urllib.request.urlopen(f"{url}/api/events?limit=200"))
    decisions: dict[tuple, set] = {}
    rules: dict[tuple, set] = {}
    for e in events:
        key = (e["ecosystem"], e["name"], e["version"])
        decisions.setdefault(key, set()).add(e["decision"])
        if e.get("verdict_id") is not None and key not in rules:
            v = json.load(urllib.request.urlopen(f"{url}/api/verdicts/{e['verdict_id']}"))
            rules[key] = {
                h["rule"] for h in v.get("policy_hits", []) if h.get("severity") == "block"
            }
    for key in [("pypi", "plain-util", "2.0.0"), ("pypi", "calm-lib", "1.0.0")] + (
        [("npm", "plain-js", "2.0.0"), ("npm", "calm-js", "1.0.0")] if shutil.which("npm") else []
    ):
        expect(
            decisions.get(key, set()) <= {"allow", "warn"} and key in decisions,
            f"{key[1]} {key[2]} is not blocked",
            str(decisions.get(key)),
        )
    expectations = [
        (("pypi", "evil-helper", "0.1.0"), "startup_hook"),
        (("pypi", "calm-lib", "1.1.0"), "min_age_days"),
    ]
    if shutil.which("npm"):
        expectations.append((("npm", "evil-js", "1.0.1"), "install_script_added"))
    for key, rule in expectations:
        expect(
            rule in rules.get(key, set()),
            f"{key[1]} {key[2]} is blocked by {rule}",
            str(rules.get(key)),
        )


if __name__ == "__main__":
    sys.exit(main())
