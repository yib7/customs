"""Run Datadog's GuardDog on the same canonical archives, as the comparison baseline.

GuardDog is the open-source scanner most of the Datadog dataset's samples were originally
found with, so this comparison is tilted in its favour: its rules helped choose the
positives. Matching or beating it on that data is therefore a conservative result.

GuardDog is installed in its own virtualenv (it pins dependencies that conflict with the
training stack); point ``GUARDDOG_BIN`` at its executable.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd

from . import config


def guarddog_bin() -> str:
    return os.environ.get("GUARDDOG_BIN", "guarddog")


def scan_one(path: str, ecosystem: str, timeout: int = 180) -> dict:
    cmd = [guarddog_bin(), ecosystem, "scan", path, "--output-format", "json"]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace"
        )
        d = json.loads(out.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        return {"path": path, "gd_error": type(e).__name__}
    rs = d.get("risk_score") or {}
    return {
        "path": path,
        "gd_score": float(rs.get("score", 0.0)),
        "gd_label": rs.get("label", ""),
        "gd_issues": int(d.get("issues", 0)),
        "gd_rules": sorted(k for k, v in (d.get("results") or {}).items() if v),
        "gd_error": "",
    }


def run(rows: pd.DataFrame, workers: int = 3) -> pd.DataFrame:
    """Scan ``rows`` (needs ``canonical_path`` and ``ecosystem``); cached per path."""
    cache = config.sub("work") / "guarddog.jsonl"
    done = {}
    if cache.exists():
        for line in cache.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            done[r["path"]] = r
    todo = [
        (p, e)
        for p, e in zip(rows.canonical_path, rows.ecosystem, strict=True)
        if p not in done and Path(p).exists()
    ]
    if todo and shutil.which(guarddog_bin()) is None:
        from .pipeline import log

        log(f"GuardDog not found ({guarddog_bin()}; set GUARDDOG_BIN): comparison skipped")
        return pd.DataFrame()
    with ThreadPoolExecutor(workers) as ex, cache.open("a", encoding="utf-8") as fh:
        for r in ex.map(lambda pe: scan_one(*pe), todo):
            fh.write(json.dumps(r) + "\n")
            fh.flush()
            done[r["path"]] = r
    return pd.DataFrame([done[p] for p in rows.canonical_path if p in done])
