#!/usr/bin/env python3
"""Prospective study: scan every new PyPI release as it is published, then see which ones
PyPI takes down.

Every other number in docs/EVALUATION.md comes from malware that someone already found.
This measures the firewall forward in time on live traffic: the models are frozen, every
release published to PyPI during the watch window goes through a running `customs serve`
(downloaded and scanned in memory, never installed or executed), and the outcome is read
off later from the registry itself (a release that PyPI removed) and from the OpenSSF
malicious-packages reports.

    python scripts/live_watch.py watch  --out work/live [--server http://127.0.0.1:7878]
    python scripts/live_watch.py follow --out work/live          # re-check takedowns
    python scripts/live_watch.py report --out work/live          # summary JSON + table

`watch` follows PyPI's changelog serial (XML-RPC `changelog_since_serial`), which lists
every release event, so nothing is sampled. A release is scanned a few minutes after it
appears so its files have finished uploading.
"""

from __future__ import annotations

import argparse
import json
import queue
import sys
import threading
import time
import urllib.error
import urllib.request
import xmlrpc.client
from datetime import datetime, timezone
from pathlib import Path

PYPI = "https://pypi.org"
DELAY = 180  # seconds between a release event and its scan
OSSF_TREE = (
    "https://api.github.com/repos/ossf/malicious-packages/git/trees/main?recursive=1"
)
OSSF_REPO = "https://github.com/ossf/malicious-packages"
OSSF_RAW = "https://raw.githubusercontent.com/ossf/malicious-packages/main/"


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def post_json(url: str, body: dict, timeout: float = 180) -> tuple[int, dict]:
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.load(e)
        except Exception:  # noqa: BLE001
            return e.code, {}


def get_status(url: str, timeout: float = 30) -> int:
    req = urllib.request.Request(url, headers={"User-Agent": "customs-live-study"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read(1)
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except OSError:
        return -1


# ------------------------------------------------------------------ watch


def watch(out: Path, server: str, workers: int, hours: float) -> None:
    out.mkdir(parents=True, exist_ok=True)
    scans = out / "scans.jsonl"
    state_path = out / "state.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {}
    seen: set[tuple[str, str]] = set()
    if scans.exists():
        for line in scans.read_text().splitlines():
            r = json.loads(line)
            seen.add((r["name"], r["version"]))
    rpc = xmlrpc.client.ServerProxy(f"{PYPI}/pypi")
    serial = state.get("serial") or rpc.changelog_last_serial()
    state.setdefault("started", now())
    pending: queue.Queue = queue.Queue()
    lock = threading.Lock()
    created: dict[str, float] = {}

    def worker() -> None:
        while True:
            due, name, version, ts = pending.get()
            wait = due - time.time()
            if wait > 0:
                time.sleep(wait)
            t0 = time.time()
            code, body = post_json(
                f"{server}/api/check",
                {
                    "ecosystem": "pypi",
                    "name": name,
                    "version": version,
                    "client": "live-study",
                },
            )
            v = body.get("verdict", body) if isinstance(body, dict) else {}
            row = {
                "name": name,
                "version": version,
                "published": ts,
                "new_project": name in created,
                "scanned_at": now(),
                "status": code,
                "error": body.get("error") if code >= 400 else None,
                "artifact": v.get("artifact"),
                "risk": v.get("risk"),
                "model_decision": v.get("model_decision"),
                "scores": v.get("scores"),
                "reasons": [
                    r.get("label") or r.get("feature") for r in v.get("reasons", [])
                ][:6],
                "evidence": [
                    {k: e.get(k) for k in ("file", "line", "indicator", "snippet")}
                    for e in v.get("evidence", [])[:4]
                ],
                "install_surface": v.get("install_surface", [])[:20],
                "scanned_ms": v.get("scanned_ms"),
                "seconds": round(time.time() - t0, 2),
            }
            with lock, scans.open("a") as f:
                f.write(json.dumps(row) + "\n")
            pending.task_done()

    for _ in range(workers):
        threading.Thread(target=worker, daemon=True).start()

    stop_at = time.time() + hours * 3600
    print(
        f"watching from serial {serial} until {datetime.fromtimestamp(stop_at, timezone.utc)}",
        flush=True,
    )
    while time.time() < stop_at:
        try:
            events = rpc.changelog_since_serial(serial)
        except Exception as e:  # noqa: BLE001 - transient network errors
            print(f"changelog error: {e}", flush=True)
            time.sleep(60)
            continue
        for name, version, ts, action, ser in events:
            serial = max(serial, ser)
            if action == "create":
                created[name] = ts
            if action == "new release" and version and (name, version) not in seen:
                seen.add((name, version))
                pending.put((ts + DELAY, name, version, ts))
        state["serial"] = serial
        state["queued"] = len(seen)
        state_path.write_text(json.dumps(state))
        print(
            f"{now()} serial {serial} queued {len(seen)} backlog {pending.qsize()}",
            flush=True,
        )
        time.sleep(60)
    pending.join()
    state["stopped"] = now()
    state_path.write_text(json.dumps(state))


# ------------------------------------------------------------------ follow-up


def follow(out: Path) -> None:
    """Record, for every scanned release, whether PyPI still serves its project and whether
    an OpenSSF malicious-package report covers that release."""
    rows = [json.loads(line) for line in (out / "scans.jsonl").read_text().splitlines()]
    names = sorted({r["name"] for r in rows})
    ossf = ossf_matches(rows, ossf_pypi_reports())
    status: dict[str, int] = {}
    lock = threading.Lock()

    def check(name: str) -> None:
        s = get_status(f"{PYPI}/pypi/{name}/json")
        with lock:
            status[name] = s

    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(16) as ex:
        list(ex.map(check, names))
    rec = {"checked_at": now(), "status": status, "ossf": ossf}
    with (out / "followups.jsonl").open("a") as f:
        f.write(json.dumps(rec) + "\n")
    gone = sum(1 for s in status.values() if s == 404)
    print(
        f"{len(names)} names; {gone} removed; OSSF reports cover {len(ossf)} releases: {ossf}"
    )


def ossf_pypi_reports() -> dict[str, list[str]]:
    """Report paths per lowercased PyPI name in OpenSSF malicious-packages: from the GitHub
    tree API, or, when that is unavailable, from a blobless clone (file names only)."""
    req = urllib.request.Request(
        OSSF_TREE, headers={"User-Agent": "customs-live-study"}
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            paths = [t["path"] for t in json.load(r)["tree"]]
    except Exception as e:  # noqa: BLE001
        print(f"OSSF tree API unavailable ({e}); listing a blobless clone")
        paths = ossf_paths_from_clone()
    out: dict[str, list[str]] = {}
    for p in paths:
        if p.startswith("osv/malicious/pypi/") and p.count("/") == 4:
            out.setdefault(p.split("/")[3].lower(), []).append(p)
    return out


def report_covers(report: dict, version: str) -> bool:
    """Whether an OSV report lists this version, or covers every version of the package
    (a range introduced at 0 with no fix), as reports on wholly malicious packages do."""
    for a in report.get("affected", []):
        if version in (a.get("versions") or []):
            return True
        for rng in a.get("ranges") or []:
            ev = rng.get("events") or []
            if any(e.get("introduced") == "0" for e in ev) and not any(
                "fixed" in e for e in ev
            ):
                return True
    return False


def ossf_matches(rows: list[dict], reports: dict[str, list[str]]) -> list[str]:
    """`name==version` for scanned releases that an OpenSSF report covers."""
    out = []
    cache: dict[str, dict] = {}
    for r in rows:
        for path in reports.get(r["name"].lower(), []):
            if path not in cache:
                try:
                    with urllib.request.urlopen(OSSF_RAW + path, timeout=60) as f:
                        cache[path] = json.load(f)
                except Exception as e:  # noqa: BLE001
                    print(f"cannot read {path}: {e}")
                    cache[path] = {}
            if report_covers(cache[path], r["version"]):
                out.append(f"{r['name']}=={r['version']}")
                break
    return sorted(set(out))


def ossf_paths_from_clone() -> list[str]:
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        try:
            subprocess.run(
                [
                    "git",
                    "clone",
                    "-q",
                    "--depth",
                    "1",
                    "--filter=blob:none",
                    "--no-checkout",
                    OSSF_REPO,
                    td,
                ],
                check=True,
                timeout=600,
            )
            ls = subprocess.run(
                [
                    "git",
                    "-C",
                    td,
                    "ls-tree",
                    "-r",
                    "--name-only",
                    "HEAD",
                    "osv/malicious/pypi",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=600,
            )
        except (subprocess.SubprocessError, OSError) as e:
            print(f"OSSF clone failed: {e}")
            return []
    return ls.stdout.splitlines()


# ------------------------------------------------------------------ report


def report(out: Path) -> dict:
    import pandas as pd

    rows = pd.read_json(out / "scans.jsonl", lines=True)
    ups = [
        json.loads(line) for line in (out / "followups.jsonl").read_text().splitlines()
    ]
    last = ups[-1]
    first_gone: dict[str, str] = {}
    for u in ups:
        for n, s in u["status"].items():
            if s == 404 and n not in first_gone:
                first_gone[n] = u["checked_at"]
    rows["removed"] = rows.name.map(lambda n: last["status"].get(n) == 404)
    covered = set(last["ossf"])
    rows["ossf"] = [
        f"{n}=={v}" in covered for n, v in zip(rows.name, rows.version, strict=True)
    ]
    scored = rows[rows.risk.notna()]
    by = scored.groupby("model_decision")
    summary = {
        "window": [
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(t)))
            for t in (rows.published.min(), rows.published.max())
        ],
        "releases": len(rows),
        "scanned": len(scored),
        "new_projects": int(rows.new_project.sum()),
        "decisions": {
            k: int(v) for k, v in scored.model_decision.value_counts().items()
        },
        "removed_by_decision": {
            k: {
                "n": len(g),
                "removed": int(g.removed.sum()),
                "ossf": int(g.ossf.sum()),
            }
            for k, g in by
        },
        "removed_total": int(rows.removed.sum()),
        "ossf_total": int(rows.ossf.sum()),
        # Project, decision, and when the removal was first seen.
        "removed_projects": {
            n: {
                "first_seen_removed": first_gone[n],
                "decision": rows[rows.name == n].model_decision.iloc[-1],
            }
            for n in sorted(first_gone)
            if last["status"].get(n) == 404
        },
    }
    (out / "report.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary, indent=1))
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("cmd", choices=["watch", "follow", "report"])
    ap.add_argument("--out", type=Path, default=Path("work/live"))
    ap.add_argument("--server", default="http://127.0.0.1:7878")
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--hours", type=float, default=24.0)
    a = ap.parse_args()
    if a.cmd == "watch":
        watch(a.out, a.server, a.workers, a.hours)
    elif a.cmd == "follow":
        follow(a.out)
    else:
        report(a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
