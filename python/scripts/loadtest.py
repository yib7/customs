#!/usr/bin/env python3
"""Latency and throughput of the firewall under concurrent installs.

Plays the registry with the same local fake upstream as `replay.py` (real test-split
archives, nothing installed or executed), starts `customs serve` in enforce mode pointed
at it, and measures:

* direct: each archive fetched from the fake upstream without the firewall, the baseline
  the firewall's overhead is measured against;
* cold: first request for an archive, which fetches, scans, scores and decides, at several
  client concurrency levels (each level gets its own archives, so nothing is cached);
* warm: the same archives requested again, served from the verdict and artifact cache;
* single flight: many clients requesting the same uncached archive at once, which should
  cost one scan.

    CUSTOMS_DATA=/path/to/data python python/scripts/loadtest.py --n 150 --concurrency 1 4 16

Writes `$CUSTOMS_DATA/work/loadtest.json`. The firewall binary is `$CUSTOMS_BIN`, else
`target/release/customs` (under `$CARGO_TARGET_DIR` when set).
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location("replay", Path(__file__).with_name("replay.py"))
replay = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(replay)


def timed(url: str) -> tuple[float, int]:
    t = time.perf_counter()
    status, _ = replay.fetch(url)
    return time.perf_counter() - t, status


def run_batch(urls: list[str], conc: int) -> dict:
    t0 = time.perf_counter()
    with ThreadPoolExecutor(conc) as ex:
        res = list(ex.map(timed, urls))
    wall = time.perf_counter() - t0
    lat = np.array([r[0] for r in res]) * 1000
    return {
        "requests": len(urls),
        "concurrency": conc,
        "throughput_per_s": len(urls) / wall,
        "p50_ms": float(np.percentile(lat, 50)),
        "p95_ms": float(np.percentile(lat, 95)),
        "p99_ms": float(np.percentile(lat, 99)),
        "max_ms": float(lat.max()),
        "statuses": {
            str(k): int(v) for k, v in pd.Series([r[1] for r in res]).value_counts().items()
        },
        "_lat": lat,
    }


def metrics(proxy: str) -> dict[str, float]:
    with urllib.request.urlopen(f"{proxy}/metrics", timeout=30) as r:
        text = r.read().decode()
    out = {}
    for line in text.splitlines():
        if line.startswith("#") or " " not in line:
            continue
        k, v = line.rsplit(" ", 1)
        with contextlib.suppress(ValueError):
            out[k] = float(v)
    return out


def proxy_url(proxy: str, r) -> str:
    v = str(r.version)
    if r.ecosystem == "npm":
        bare = r.name.split("/", 1)[-1]
        return f"{proxy}/npm/{r.name}/-/{bare}-{v}.tgz"
    key = re.sub(r"[-_.]+", "-", r.name).lower()
    return f"{proxy}/pypi/files/{key}/{replay.dist_name(r.name)}-{v}.tar.gz"


def direct_url(base: str, r) -> str:
    v = str(r.version)
    if r.ecosystem == "npm":
        bare = r.name.split("/", 1)[-1]
        return f"{base}/npm/{r.name}/-/{bare}-{v}.tgz"
    key = re.sub(r"[-_.]+", "-", r.name).lower()
    return f"{base}/files/{key}/{replay.dist_name(r.name)}-{v}.tar.gz"


def strip(d: dict) -> dict:
    return {k: v for k, v in d.items() if not k.startswith("_")}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--n", type=int, default=150, help="archives per concurrency level")
    ap.add_argument("--concurrency", type=int, nargs="+", default=[1, 4, 16])
    ap.add_argument("--flight-packages", type=int, default=20)
    ap.add_argument("--flight-clients", type=int, default=16)
    ap.add_argument("--port", type=int, default=7980)
    ap.add_argument("--seed", type=int, default=3)
    args = ap.parse_args()

    data = Path(os.environ.get("CUSTOMS_DATA") or Path(tempfile.gettempdir()) / "customs-data")
    df = pd.read_parquet(
        data / "work" / "dataset.parquet",
        columns=["ecosystem", "name", "version", "label", "split_temporal", "canonical_path"],
    )
    test = df[
        (df.split_temporal == "test")
        & df.canonical_path.map(lambda p: bool(p) and Path(p).exists())
    ]
    test = test.drop_duplicates(["ecosystem", "name"])
    need = args.n * len(args.concurrency) + args.flight_packages
    rows = test.sample(min(need, len(test)), random_state=args.seed).reset_index(drop=True)
    rows["bytes"] = rows.canonical_path.map(lambda p: Path(p).stat().st_size)

    fake = ThreadingHTTPServer(("127.0.0.1", 0), None)
    base = f"http://127.0.0.1:{fake.server_address[1]}"
    fake.RequestHandlerClass = replay.Registry(rows).handler(base)
    threading.Thread(target=fake.serve_forever, daemon=True).start()

    work = Path(tempfile.mkdtemp(prefix="customs-load-"))
    policy = work / "customs.toml"
    policy.write_text(
        'mode = "enforce"\nmin_age_days = 0\nblock_nonexistent = true\n'
        "block_install_scripts_from_new = false\n"
        # The upload times served here are fake (OLD), so the established-release prior is
        # off and the model decides every sample, as in the evaluation.
        "[established]\nenabled = false\n"
        f'[upstream]\npypi_simple = "{base}/simple"\npypi_files = "{base}/files"\n'
        f'pypi_json = "{base}/pypi"\nnpm = "{base}/npm"\n',
        encoding="utf-8",
    )
    proxy = f"http://127.0.0.1:{args.port}"
    replay.require_free_port(args.port)
    with open(work / "server.log", "w", encoding="utf-8") as log:
        server = subprocess.Popen(
            [
                replay.customs_bin(),
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
        res: dict = {"archives": len(rows), "cpus": os.cpu_count()}
        try:
            replay.wait_healthy(proxy, server, work / "server.log")
            res["archive_kb"] = {
                "p50": float(rows.bytes.quantile(0.5) / 1024),
                "p95": float(rows.bytes.quantile(0.95) / 1024),
                "max": float(rows.bytes.max() / 1024),
            }
            first = rows.iloc[: args.n]
            res["direct"] = strip(run_batch([direct_url(base, r) for r in first.itertuples()], 1))

            cold = {}
            m0 = metrics(proxy)
            for i, c in enumerate(args.concurrency):
                part = rows.iloc[i * args.n : (i + 1) * args.n]
                b = run_batch([proxy_url(proxy, r) for r in part.itertuples()], c)
                if i == 0:
                    # Latency against archive size, on the sequential run.
                    lat = b["_lat"]
                    kb = part.bytes.to_numpy() / 1024
                    b["p50_ms_by_size"] = {
                        name: float(np.median(lat[m])) if m.any() else None
                        for name, m in (
                            ("under_100kb", kb < 100),
                            ("100kb_to_1mb", (kb >= 100) & (kb < 1024)),
                            ("over_1mb", kb >= 1024),
                        )
                    }
                    b["overhead_p50_ms"] = b["p50_ms"] - res["direct"]["p50_ms"]
                cold[str(c)] = strip(b)
            m1 = metrics(proxy)
            n_scans = m1.get("customs_scan_duration_seconds_count", 0) - m0.get(
                "customs_scan_duration_seconds_count", 0
            )
            scan_sum = m1.get("customs_scan_duration_seconds_sum", 0) - m0.get(
                "customs_scan_duration_seconds_sum", 0
            )
            res["cold"] = cold
            res["server_scan_mean_ms"] = 1000 * scan_sum / max(n_scans, 1)
            res["server_scans"] = int(n_scans)

            warm_rows = rows.iloc[: args.n]
            res["warm"] = strip(
                run_batch(
                    [proxy_url(proxy, r) for r in warm_rows.itertuples()], max(args.concurrency)
                )
            )

            fl = rows.iloc[args.n * len(args.concurrency) :]
            before = metrics(proxy)
            lats = []
            for r in fl.itertuples():
                b = run_batch([proxy_url(proxy, r)] * args.flight_clients, args.flight_clients)
                lats.append(b["p50_ms"])
            after = metrics(proxy)
            res["single_flight"] = {
                "packages": len(fl),
                "clients_per_package": args.flight_clients,
                "requests": len(fl) * args.flight_clients,
                "scans": int(
                    after.get("customs_scan_duration_seconds_count", 0)
                    - before.get("customs_scan_duration_seconds_count", 0)
                ),
                "joins": int(
                    after.get("customs_singleflight_joins_total", 0)
                    - before.get("customs_singleflight_joins_total", 0)
                ),
                "p50_ms": float(np.median(lats)),
            }
            print(json.dumps(res, indent=1))
            (data / "work" / "loadtest.json").write_text(
                json.dumps(res, indent=1), encoding="utf-8"
            )
        finally:
            server.terminate()
            server.wait(timeout=30)
            shutil.rmtree(work, ignore_errors=True)
            fake.shutdown()


if __name__ == "__main__":
    sys.exit(main())
