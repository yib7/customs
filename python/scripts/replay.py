#!/usr/bin/env python3
"""Replay held-out real malware through the running Rust firewall, end to end.

Real malicious packages are removed from PyPI and npm within days, so to exercise the
actual proxy on them this script plays the registry: it serves test-split archives (and
benign ones for contrast) from a local fake npm/PyPI upstream, starts `customs serve`
pointed at it, and requests every tarball *through the proxy* with plain HTTP. Nothing is
installed or executed; allowed bytes are discarded.

It then compares the proxy's verdicts with the Python pipeline's scores for the same rows,
which checks that the shipped binary (scanner + Rust inference + policy) reproduces the
evaluation end to end.

    CUSTOMS_DATA=/path/to/data python python/scripts/replay.py --n 300 [--keep]

Requires the dataset built by `customs-ml` (see README). The firewall binary is
`$CUSTOMS_BIN`, else `target/release/customs` (under `$CARGO_TARGET_DIR` when set).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
OLD = "2025-01-01T00:00:00.000Z"  # older than any min-age policy: the model decides


def customs_bin() -> str:
    """``$CUSTOMS_BIN``, else this checkout's ``target/release/customs`` (under
    ``$CARGO_TARGET_DIR`` when set, ``.exe`` on Windows)."""
    env = os.environ.get("CUSTOMS_BIN")
    if env:
        return env
    target = os.environ.get("CARGO_TARGET_DIR")
    base = Path(target) if target else ROOT / "target"
    return str(base / "release" / ("customs.exe" if os.name == "nt" else "customs"))


def require_free_port(port: int) -> None:
    """Exit if something already listens on ``port``: its answers would be counted as ours."""
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            sys.exit(f"port {port} is in use; pick another with --port")


def wait_healthy(proxy: str, server: subprocess.Popen, log: Path, seconds: float = 30) -> None:
    """Return once the server we started answers ``/healthz``; exit with its log otherwise."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and server.poll() is None:
        try:
            urllib.request.urlopen(f"{proxy}/healthz", timeout=1).read()
            if server.poll() is None:
                return
        except OSError:
            time.sleep(0.1)
    sys.exit("customs serve did not start:\n" + log.read_text(encoding="utf-8")[-3000:])


def finite(x) -> float | None:
    """``x`` as a float, or None for NaN (an empty group), so the JSON stays valid."""
    x = float(x)
    return x if math.isfinite(x) else None


def dist_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9.]+", "_", name)


class Registry:
    def __init__(self, rows: pd.DataFrame):
        self.npm: dict[str, tuple[str, str, Path]] = {}
        self.pypi: dict[str, tuple[str, str, Path]] = {}
        self.files: dict[str, Path] = {}
        for r in rows.itertuples():
            v = str(r.version)
            if r.ecosystem == "npm":
                bare = r.name.split("/", 1)[-1]
                fname = f"{bare}-{v}.tgz"
                self.npm[r.name] = (v, fname, Path(r.canonical_path))
            else:
                fname = f"{dist_name(r.name)}-{v}.tar.gz"
                key = re.sub(r"[-_.]+", "-", r.name).lower()
                self.pypi[key] = (v, fname, Path(r.canonical_path))
                self.files[f"{key}/{fname}"] = Path(r.canonical_path)

    def handler(self, base: str):
        reg = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def send(self, code: int, body: bytes, ctype: str = "application/json"):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                path = urllib.parse.unquote(self.path.split("?", 1)[0])
                if path.startswith("/npm/"):
                    rest = path[len("/npm/") :]
                    if "/-/" in rest:
                        name, fname = rest.split("/-/", 1)
                        hit = reg.npm.get(name)
                        if hit and hit[1] == fname:
                            return self.send(200, hit[2].read_bytes(), "application/octet-stream")
                        return self.send(404, b"{}")
                    hit = reg.npm.get(rest)
                    if not hit:
                        return self.send(404, b'{"error":"Not found"}')
                    v, fname, _ = hit
                    doc = {
                        "name": rest,
                        "dist-tags": {"latest": v},
                        "versions": {
                            v: {
                                "name": rest,
                                "version": v,
                                "dist": {"tarball": f"{base}/npm/{rest}/-/{fname}"},
                            }
                        },
                        "time": {"created": OLD, "modified": OLD, v: OLD},
                    }
                    return self.send(200, json.dumps(doc).encode())
                m = re.match(r"^/pypi/([^/]+)/json$", path)
                if m:
                    key = re.sub(r"[-_.]+", "-", m[1]).lower()
                    hit = reg.pypi.get(key)
                    if not hit:
                        return self.send(404, b'{"message":"Not Found"}')
                    v, fname, _ = hit
                    f = {
                        "filename": fname,
                        "url": f"{base}/files/{key}/{fname}",
                        "packagetype": "sdist",
                        "upload_time_iso_8601": OLD,
                        "upload_time": OLD[:19],
                        "yanked": False,
                    }
                    doc = {"info": {"name": m[1], "version": v}, "releases": {v: [f]}, "urls": [f]}
                    return self.send(200, json.dumps(doc).encode())
                if path.startswith("/files/"):
                    p = reg.files.get(path[len("/files/") :])
                    if p:
                        return self.send(200, p.read_bytes(), "application/octet-stream")
                return self.send(404, b"{}")

        return H


def fetch(url: str) -> tuple[int, dict]:
    req = urllib.request.Request(url, headers={"User-Agent": "customs-replay"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            r.read()
            return r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        e.read()
        return e.code, dict(e.headers)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--n", type=int, default=300, help="samples per class")
    ap.add_argument("--port", type=int, default=7979)
    ap.add_argument("--keep", action="store_true", help="leave the firewall running")
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()

    data = Path(os.environ.get("CUSTOMS_DATA") or Path(tempfile.gettempdir()) / "customs-data")
    df = pd.read_parquet(data / "work" / "dataset.parquet")
    if "augmented" in df:
        df = df[df.augmented.isna()]
    test = df[
        (df.split_temporal == "test")
        & df.canonical_path.map(lambda p: bool(p) and Path(p).exists())
    ]
    rows = pd.concat(
        [
            test[test.label == 1].sample(
                min(args.n, (test.label == 1).sum()), random_state=args.seed
            ),
            test[test.label == 0].sample(
                min(args.n, (test.label == 0).sum()), random_state=args.seed
            ),
        ]
    )
    # One row per (ecosystem, name): the fake registry serves a single version per name.
    rows = rows.drop_duplicates(["ecosystem", "name"])

    fake = ThreadingHTTPServer(("127.0.0.1", 0), None)
    base = f"http://127.0.0.1:{fake.server_address[1]}"
    fake.RequestHandlerClass = Registry(rows).handler(base)
    threading.Thread(target=fake.serve_forever, daemon=True).start()

    work = Path(tempfile.mkdtemp(prefix="customs-replay-"))
    policy = work / "customs.toml"
    policy.write_text(
        'mode = "enforce"\nmin_age_days = 0\nblock_nonexistent = true\n'
        "block_install_scripts_from_new = false\n"
        # The upload times served here are fake (OLD), so the established-package prior is
        # off and the model decides every sample, as in the evaluation.
        "[established]\nenabled = false\n"
        f'[upstream]\npypi_simple = "{base}/simple"\npypi_files = "{base}/files"\n'
        f'pypi_json = "{base}/pypi"\nnpm = "{base}/npm"\n',
        encoding="utf-8",
    )
    proxy = f"http://127.0.0.1:{args.port}"
    require_free_port(args.port)
    with open(work / "server.log", "w", encoding="utf-8") as log:
        server = subprocess.Popen(
            [
                customs_bin(),
                "serve",
                "--bind",
                f"127.0.0.1:{args.port}",
                "--config",
                str(policy),
                "--data-dir",
                str(work / "data"),
                "--ui-dir",
                str(ROOT / "web/dist"),
                "--models",
                str(ROOT / "models"),
            ],
            stdout=subprocess.DEVNULL,
            stderr=log,
        )
        try:
            wait_healthy(proxy, server, work / "server.log")
            out = []
            t0 = time.time()
            for r in rows.itertuples():
                v = str(r.version)
                if r.ecosystem == "npm":
                    bare = r.name.split("/", 1)[-1]
                    url = f"{proxy}/npm/{r.name}/-/{bare}-{v}.tgz"
                else:
                    key = re.sub(r"[-_.]+", "-", r.name).lower()
                    url = f"{proxy}/pypi/files/{key}/{dist_name(r.name)}-{v}.tar.gz"
                status, headers = fetch(url)
                vid = headers.get("x-customs-verdict") or headers.get("X-Customs-Verdict")
                verdict = {}
                if vid:
                    with urllib.request.urlopen(f"{proxy}/api/verdicts/{vid}") as resp:
                        verdict = json.load(resp)
                out.append(
                    {
                        "name": r.name,
                        "url": url,
                        "label": r.label,
                        "ecosystem": r.ecosystem,
                        "status": status,
                        "decision": verdict.get("decision"),
                        "risk": verdict.get("risk"),
                        "py_risk": r.ens_risk_temporal,
                        "scores": verdict.get("scores"),
                        "py_logits": [r.gbdt_logit_temporal, r.cnn_logit_temporal, r.name_logit],
                    }
                )
            elapsed = time.time() - t0
            res = pd.DataFrame(out)
            ens = json.loads((ROOT / "models/ensemble.json").read_text(encoding="utf-8"))[
                "thresholds"
            ]
            res["py_decision"] = np.select(
                [res.py_risk >= ens["block"], res.py_risk >= ens["warn"]],
                ["block", "warn"],
                "allow",
            )
            ok = res.risk.notna()
            summary = {
                "requests": len(res),
                "seconds_per_request": round(elapsed / max(len(res), 1), 3),
                "malicious_blocked": finite((res[res.label == 1].status == 403).mean()),
                "malicious_block_or_warn": finite(
                    res[res.label == 1].decision.isin(["block", "warn"]).mean()
                ),
                "benign_blocked": finite((res[res.label == 0].status == 403).mean()),
                "benign_warned": finite((res[res.label == 0].decision == "warn").mean()),
                "decision_agreement_with_python": finite(
                    (res.decision == res.py_decision)[ok].mean()
                ),
                "max_abs_risk_diff": finite((res.risk - res.py_risk).abs()[ok].max()),
            }
            summary["status_counts"] = {
                str(k): int(v) for k, v in res.status.value_counts().items()
            }
            summary["no_verdict"] = int((~ok).sum())
            bad = res[~ok]
            if len(bad):
                print(bad.head(10).to_string())
            print(json.dumps(summary, indent=1))
            (data / "work" / "replay.json").write_text(
                json.dumps(summary, indent=1, allow_nan=False), encoding="utf-8"
            )
            res.to_json(data / "work" / "replay_rows.jsonl", orient="records", lines=True)
            if args.keep:
                print(f"firewall running at {proxy} (pid {server.pid}); Ctrl-C to stop")
                # Not signal.pause(): Windows has none. Returns if the server exits.
                while server.poll() is None:
                    time.sleep(1)
        finally:
            if not args.keep:
                server.terminate()
                server.wait(timeout=30)
                # The firewall's artifact cache holds every replayed archive.
                shutil.rmtree(work, ignore_errors=True)
            fake.shutdown()


if __name__ == "__main__":
    sys.exit(main())
