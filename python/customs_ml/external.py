"""Cross-dataset test on an independent PyPI malware corpus.

Every malicious sample used for training and testing comes from one source (Datadog's
dataset), so a model can learn that source's collection habits. MalRegistry
(github.com/lxyeternal/pypi_malregistry, from "An Empirical Study of Malicious Code In
PyPI Ecosystem", ASE 2023) was collected independently from PyPI by a different team. Here
it is only scored, never trained on: archives are canonicalized exactly like the corpus,
scanned, de-duplicated against the training malware (same normalized name, or MinHash
near-duplicate code), and scored by the frozen firewall binary at its shipped thresholds.

Nothing is installed or executed. Archives are read into memory, rewritten in canonical
form, and the originals are deleted.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np
import pandas as pd

from . import config, dedup, features
from .malicious import canonicalize, read_any, strip_common_root

RAW = "https://raw.githubusercontent.com/lxyeternal/pypi_malregistry/HEAD/"
ROOT = Path(__file__).resolve().parents[2]


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _fetch_one(rel: str, out_dir: Path) -> dict:
    parts = rel.split("/")
    row = {"source": rel, "name": parts[0], "version": parts[1] if len(parts) > 2 else ""}
    for i in range(3):
        try:
            url = RAW + urllib.parse.quote(rel)
            with urllib.request.urlopen(url, timeout=120) as r:
                data = r.read()
            files = strip_common_root(read_any(data, parts[-1]))
            if not files:
                raise ValueError("empty archive")
            blob = canonicalize(files, "pypi", row["name"], row["version"])
            digest = hashlib.sha256(blob).hexdigest()
            path = out_dir / digest[:2] / f"{digest}.tar.gz"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(blob)
            return {**row, "path": str(path), "sha256": digest, "n_files": len(files)}
        except Exception as e:  # noqa: BLE001 - recorded per sample
            err = f"{type(e).__name__}: {e}"[:200]
            if "HTTP Error 404" in err:
                break
            time.sleep(2**i)
    return {**row, "error": err}


def fetch(listing: Path, workers: int = 16) -> Path:
    out_dir = config.sub("external") / "malregistry"
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = out_dir / "manifest.jsonl"
    done = set()
    if manifest.exists():
        done = {json.loads(x)["source"] for x in manifest.read_text().splitlines()}
    todo = [x for x in listing.read_text().splitlines() if x and x not in done]
    with ThreadPoolExecutor(workers) as ex, manifest.open("a") as mf:
        for n, row in enumerate(ex.map(lambda r: _fetch_one(r, out_dir), todo), 1):
            mf.write(json.dumps(row) + "\n")
            if n % 1000 == 0:
                print(f"{n}/{len(todo)}", flush=True)
    return manifest


def score_with_binary(paths: list[str], names: list[str], jobs: int = 4) -> list[dict]:
    """Verdicts from the shipped binary (`customs scan --json`), so this tests what ships."""
    binary = str(ROOT / "target/release/customs")

    def one(args):
        path, name = args
        p = subprocess.run(
            [
                binary,
                "scan",
                path,
                "--ecosystem",
                "pypi",
                "--name",
                name,
                "--json",
                "--models",
                str(ROOT / "models"),
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        try:
            v = json.loads(p.stdout)
        except ValueError:
            return {"error": p.stderr[-300:]}
        return {
            "risk": v.get("risk"),
            "model_decision": v.get("model_decision"),
            "scores": v.get("scores"),
        }

    with ThreadPoolExecutor(jobs) as ex:
        return list(ex.map(one, zip(paths, names, strict=True)))


def evaluate() -> dict:
    from .pipeline import load_table, work

    out_dir = config.sub("external") / "malregistry"
    ext = pd.read_json(out_dir / "manifest.jsonl", lines=True)
    ext = ext[ext.get("path").notna()].drop_duplicates("sha256").reset_index(drop=True)
    df = load_table()
    df = df[df.augmented.isna()] if "augmented" in df else df
    train_mal = df[(df.label == 1) & (df.split_temporal == "train")]
    all_mal_names = set(df[df.label == 1].name.map(norm))

    reports = features.scan_paths(list(ext.path), tokens=True)
    ext["tokens"] = [r.get("tokens") or [] for r in reports]
    ext["name_seen"] = ext.name.map(norm).isin(all_mal_names)
    # Near-duplicates: cluster external and training malware together; an external sample
    # whose cluster holds any training sample is not novel.
    docs = list(train_mal.tokens) + list(ext.tokens)
    labels = dedup.cluster(docs)
    train_clusters = set(labels[: len(train_mal)])
    ext["near_dup"] = [c in train_clusters for c in labels[len(train_mal) :]]
    ext["novel"] = ~ext.name_seen & ~ext.near_dup

    verdicts = score_with_binary(list(ext.path), list(ext.name))
    ext["risk"] = [v.get("risk") for v in verdicts]
    ext["model_decision"] = [v.get("model_decision") for v in verdicts]
    ext["gbdt"] = [(v.get("scores") or {}).get("code_gbdt") for v in verdicts]
    ext["cnn"] = [(v.get("scores") or {}).get("code_nn") for v in verdicts]
    ext["name_score"] = [(v.get("scores") or {}).get("name") for v in verdicts]

    ens = json.loads((ROOT / "models/ensemble.json").read_text())["thresholds"]

    def rates(g: pd.DataFrame) -> dict:
        r = g.risk.dropna().to_numpy()
        return {
            "n": int(len(g)),
            "scored": int(len(r)),
            "warn_or_block": float(np.mean(r >= ens["warn"])) if len(r) else None,
            "block": float(np.mean(r >= ens["block"])) if len(r) else None,
            "median_risk": float(np.median(r)) if len(r) else None,
        }

    # Unique payloads: one sample per near-duplicate cluster, so a campaign with 60
    # copies counts once.
    ext["cluster"] = labels[len(train_mal) :]
    summary = {
        "source": "MalRegistry (lxyeternal/pypi_malregistry)",
        "archives": int(len(ext)),
        "all": rates(ext),
        "novel": rates(ext[ext.novel]),
        "novel_one_per_cluster": rates(ext[ext.novel].drop_duplicates("cluster")),
        "name_seen_in_training_data": int(ext.name_seen.sum()),
        "near_duplicate_of_training": int(ext.near_dup.sum()),
        "thresholds": ens,
    }
    ext.drop(columns=["tokens"]).to_parquet(work() / "external_malregistry.parquet")
    (work() / "external_malregistry.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary, indent=1))
    return summary
