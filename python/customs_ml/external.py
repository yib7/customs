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
import shutil
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
# Samples whose scores or contents were looked at during error analysis. Their clusters go
# to the dev half so the held-out half stays unseen.
INSPECTED = {
    "cipherbcrypt",
    "security-alerts-sdk",
    "code-transfering-3",
    "fernetpy",
    "discord-solver",
    "api-hypixel",
    "wallet-rpc",
    "circleinfo",
    "urlsser",
    "quarejma-botnetx",
    "notebook-intelligence",
    "windowsrequir",
    "browser-history-analysis",
    "pyswyfter",
    "req-tools",
}
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


def score_with_binary(
    paths: list[str], names: list[str], jobs: int = 4, models: Path | None = None
) -> list[dict]:
    """Verdicts from the shipped binary (`customs scan --json`), so this tests what ships."""
    binary = str(ROOT / "target/release/customs")
    models = models or ROOT / "models"

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
                str(models),
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


def code_only_models(out: Path) -> Path:
    """The shipped models without the name model, so the ensemble uses its code-only
    fallback weights.

    The name model is trained on OSSF malicious package names, and most MalRegistry names
    are among them (the corpus is the same malware, reported to OSSF). The in-domain test
    holds its own names out of name-model training; here the only way to keep a memorized
    name from scoring the sample is to leave the name model out.
    """
    out.mkdir(parents=True, exist_ok=True)
    for f in (ROOT / "models").iterdir():
        if f.is_file():
            shutil.copy(f, out / f.name)
    man = json.loads((out / "manifest.json").read_text())
    man["name_model"] = None
    (out / "manifest.json").write_text(json.dumps(man, indent=1))
    return out


def code_only_risk(df: pd.DataFrame, ens: dict, scheme: str = "temporal") -> np.ndarray:
    """Python equivalent of the binary's code-only fallback score for corpus rows."""
    from . import gbdt

    fb = next(f for f in ens["fallbacks"] if f["missing"] == ["name"])
    z = (
        fb["bias"]
        + fb["weights"]["code_gbdt"] * df[f"gbdt_logit_{scheme}"].to_numpy()
        + fb["weights"]["code_nn"] * df[f"cnn_logit_{scheme}"].to_numpy()
    )
    return gbdt.apply_calibration(ens["calibration"], 1 / (1 + np.exp(-z)))


def _matched_fpr(df: pd.DataFrame, g: pd.DataFrame, col: str = "risk") -> dict:
    """Detection at thresholds that give the same false positive rate on the benign test
    split, so runs whose shipped thresholds differ are compared on equal terms.

    ``col`` names the score both in ``g`` and, as ``ens_<col>``, in the corpus table."""
    ben = df[(df.label == 0) & (df.split_temporal == "test")][f"ens_{col}"].to_numpy()
    r = g[col].dropna().to_numpy()
    out = {"benign_test_n": int(len(ben))}
    for fpr in (0.001, 0.005, 0.01):
        t = float(np.quantile(ben, 1 - fpr))
        out[str(fpr)] = {"threshold": t, "recall": float(np.mean(r >= t)) if len(r) else None}
    return out


def evaluate() -> dict:
    from .pipeline import load_table, work

    out_dir = config.sub("external") / "malregistry"
    ext = pd.read_json(out_dir / "manifest.jsonl", lines=True)
    ext = ext[ext.get("path").notna()].drop_duplicates("sha256").reset_index(drop=True)
    df = load_table()
    df = df[df.augmented.isna()] if "augmented" in df else df
    df = df.assign(
        ens_risk=df.ens_risk_temporal,
        ens_risk_code=code_only_risk(df, json.loads((ROOT / "models/ensemble.json").read_text())),
    )
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
    code_only = score_with_binary(
        list(ext.path), list(ext.name), models=code_only_models(work() / "models_code_only")
    )
    ext["risk_code"] = [v.get("risk") for v in code_only]
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
    # Dev half for error analysis, held-out half for reporting. Halves are drawn per
    # cluster, so near-duplicates never straddle them.
    seen = set(ext[ext.name.isin(INSPECTED)].cluster)
    ext["half"] = [
        "dev"
        if c in seen or int(hashlib.sha256(str(c).encode()).hexdigest(), 16) % 2 == 0
        else "heldout"
        for c in ext.cluster
    ]
    # Cluster ids, and so novelty and halves, shift when a scanner change alters token
    # streams. The first run's assignment is frozen by archive hash, so every later run
    # (after a scanner change or a retrain) is measured on exactly the same samples.
    frozen_path = work() / "external_malregistry_split.json"
    if frozen_path.exists():
        frozen = json.loads(frozen_path.read_text())
        for col in ("half", "novel", "cluster"):
            ext[col] = [
                frozen.get(h, {}).get(col, v) for h, v in zip(ext.sha256, ext[col], strict=True)
            ]
    else:
        frozen_path.write_text(
            json.dumps(
                {
                    h: {"half": a, "novel": bool(n), "cluster": int(c)}
                    for h, a, n, c in zip(ext.sha256, ext.half, ext.novel, ext.cluster, strict=True)
                }
            )
        )
    ext["novel"] = ext.novel.astype(bool)
    nv = ext[ext.novel]
    summary = {
        "source": "MalRegistry (lxyeternal/pypi_malregistry)",
        "archives": int(len(ext)),
        "all": rates(ext),
        "novel": rates(ext[ext.novel]),
        "novel_one_per_cluster": rates(nv.drop_duplicates("cluster")),
        "novel_dev": rates(nv[nv.half == "dev"]),
        "novel_heldout": rates(nv[nv.half == "heldout"]),
        "novel_heldout_one_per_cluster": rates(nv[nv.half == "heldout"].drop_duplicates("cluster")),
        "recall_at_matched_fpr": _matched_fpr(df, nv[nv.half == "heldout"]),
        "code_only_recall_at_matched_fpr": _matched_fpr(df, nv[nv.half == "heldout"], "risk_code"),
        "name_seen_in_training_data": int(ext.name_seen.sum()),
        "near_duplicate_of_training": int(ext.near_dup.sum()),
        "thresholds": ens,
    }
    ext.drop(columns=["tokens"]).to_parquet(work() / "external_malregistry.parquet")
    (work() / "external_malregistry.json").write_text(json.dumps(summary, indent=1))
    print(json.dumps(summary, indent=1))
    return summary


def _corpus_rows(df: pd.DataFrame, sel: pd.DataFrame, work_dir: Path) -> pd.DataFrame:
    """MalRegistry archives as corpus table rows (split taken from ``sel.split``)."""
    from . import name_model, names

    reports = features.scan_paths(list(sel.path), tokens=True)
    pop = name_model.Popular.from_list("pypi", names.popular("pypi"))
    nm = json.loads((work_dir / "name_model.json").read_text())
    base = int(df.cluster.max()) + 1
    rows = []
    for r, rep in zip(sel.itertuples(), reports, strict=True):
        if "features" not in rep:
            continue
        row = {
            "ecosystem": "pypi",
            "name": r.name,
            "version": str(r.version),
            "label": 1,
            "date": pd.NaT,
            "tier": None,
            "kind": "malicious_intent",
            "canonical_path": r.path,
            "scan_error": None,
            "tokens": rep.get("tokens") or [],
            "cluster": base + int(r.cluster),
            "split_temporal": r.split,
            "split_grouped": r.split,
            "name_logit": name_model.score_exported(nm, "pypi", r.name, pop),
            "augmented": None,
            "source": "malregistry",
        }
        row.update({f"f_{k}": v for k, v in rep["features"].items()})
        rows.append(row)
    return pd.DataFrame(rows)


def adapt(fraction: float = 1.0, seed: int = 0) -> dict:
    """Experiment: add MalRegistry dev-half malware to training, test on the held-out half.

    Runs in a copy of the data directory (``$CUSTOMS_DATA-adapt``) and never exports, so
    the shipped models and the main work files are untouched. The dev half (every cluster,
    novel or not, or a random ``fraction`` of its clusters) joins the training split;
    novel held-out samples are added under split ``external`` so every stage scores them
    but none trains on them. Halves are drawn per near-duplicate cluster, so no held-out
    sample has a relative in the added data. Scores are code-only (no name model), as in
    ``evaluate``, and compared with the main models at matched benign test FPR.
    """
    import os

    from . import nn as cnn
    from . import pipeline

    main = config.data_dir()
    exp = main.parent / f"{main.name}-adapt"
    (exp / "work").mkdir(parents=True, exist_ok=True)
    for d in ("benign", "benign_canonical", "malicious", "external", "names", "ossf"):
        if not (exp / d).exists():
            (exp / d).symlink_to(main / d)
    for f in ("dataset.parquet", "split_meta.json", "name_model.json"):
        shutil.copy(main / "work" / f, exp / "work" / f)
    ext = pd.read_parquet(main / "work" / "external_malregistry.parquet")
    dev_clusters = np.unique(ext[ext.half == "dev"].cluster)
    rng = np.random.default_rng(seed)
    keep = set(rng.choice(dev_clusters, int(round(fraction * len(dev_clusters))), replace=False))
    dev = ext[(ext.half == "dev") & ext.cluster.isin(keep)].assign(split="train")
    held = ext[(ext.half == "heldout") & ext.novel].assign(split="external")

    prev = os.environ.get("CUSTOMS_DATA")
    os.environ["CUSTOMS_DATA"] = str(exp)
    try:
        df = pipeline.load_table()
        control = df.copy()
        rows = _corpus_rows(df, pd.concat([dev, held]), exp / "work")
        df = pd.concat([df, rows], ignore_index=True)
        df.to_parquet(pipeline.work() / "dataset.parquet")
        pipeline.log(f"adapt: +{int((rows.split_temporal == 'train').sum())} training rows")
        pipeline.stage_gbdt()
        pipeline.stage_cnn(cfg=cnn.Config(max_len=768, epochs=10, patience=3))
        pipeline.stage_ensemble()
        df = pipeline.load_table()
        ens = json.loads((pipeline.work() / "ensemble_temporal.json").read_text())
    finally:
        if prev is None:
            os.environ.pop("CUSTOMS_DATA", None)
        else:
            os.environ["CUSTOMS_DATA"] = prev

    main_ens = json.loads((ROOT / "models/ensemble.json").read_text())
    control = control[control.augmented.isna()]
    control = control.assign(ens_risk=control.ens_risk_temporal)
    control["ens_risk_code"] = code_only_risk(control, main_ens)
    adapted = df[df.augmented.isna() & (df.split_temporal != "external")]
    adapted = adapted.assign(ens_risk=adapted.ens_risk_temporal)
    adapted["ens_risk_code"] = code_only_risk(adapted, ens)
    scored = df[df.split_temporal == "external"]
    scored = scored.assign(risk_code=code_only_risk(scored, ens))

    def in_domain(t: pd.DataFrame, e: dict) -> dict:
        from sklearn.metrics import roc_auc_score

        te = t[t.split_temporal == "test"]
        y, s = te.label.to_numpy(), te.ens_risk.to_numpy()
        thr = e["thresholds"]
        return {
            "roc_auc": float(roc_auc_score(y, s)),
            "recall_warn": float(np.mean(s[y == 1] >= thr["warn"])),
            "fpr_warn": float(np.mean(s[y == 0] >= thr["warn"])),
            "recall_block": float(np.mean(s[y == 1] >= thr["block"])),
            "fpr_block": float(np.mean(s[y == 0] >= thr["block"])),
        }

    out = {
        "fraction": fraction,
        "added_training_archives": int(len(dev)),
        "added_training_clusters": int(len(keep)),
        "heldout_novel_archives": int(len(scored)),
        "heldout_novel_clusters": int(held.cluster.nunique()),
        "in_domain": {"main": in_domain(control, main_ens), "adapted": in_domain(adapted, ens)},
        "heldout_code_only": {
            "main": _matched_fpr(control, held, "risk_code"),
            "adapted": _matched_fpr(adapted, scored, "risk_code"),
        },
    }
    dest = main / "work" / f"external_adapt_{int(round(fraction * 100))}.json"
    dest.write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))
    return out
