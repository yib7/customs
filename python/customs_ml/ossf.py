"""Parse the OSSF malicious-packages dataset (OSV JSON reports) into one table.

Each report names a malicious package and, usually, the versions affected. The table feeds
the package-name model (malicious names are the positive class) and the benign-corpus
filter (a benign candidate whose name appears here is dropped).
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

ECOSYSTEMS = {"npm": "npm", "PyPI": "pypi"}


def parse_report(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as f:
        rep = json.load(f)
    rows = []
    for aff in rep.get("affected", []):
        pkg = aff.get("package", {})
        eco = ECOSYSTEMS.get(pkg.get("ecosystem", ""))
        if eco is None:
            continue
        origins = (rep.get("database_specific") or {}).get("malicious-packages-origins") or []
        rows.append(
            {
                "id": rep.get("id"),
                "ecosystem": eco,
                "name": pkg.get("name"),
                "versions": list(aff.get("versions") or []),
                "all_versions": not aff.get("versions"),
                "published": rep.get("published"),
                "withdrawn": "withdrawn" in rep,
                "sources": sorted({o.get("source", "") for o in origins} - {""}),
                "summary": rep.get("summary", ""),
            }
        )
    return rows


def build_table(repo: Path) -> pd.DataFrame:
    rows: list[dict] = []
    for sub in ("malicious", "withdrawn"):
        for eco_dir in ("npm", "pypi"):
            base = repo / "osv" / sub / eco_dir
            if not base.exists():
                continue
            for p in base.rglob("*.json"):
                if not p.is_file():
                    continue
                for r in parse_report(p):
                    r["withdrawn"] = r["withdrawn"] or sub == "withdrawn"
                    rows.append(r)
    df = pd.DataFrame(rows)
    df["published"] = pd.to_datetime(df["published"], utc=True, errors="coerce")
    return df
