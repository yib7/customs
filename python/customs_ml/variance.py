"""Retrain variance: how much do the headline numbers move when only the random seed changes?

Every model change in this project is judged by retraining and comparing test metrics. A
comparison means nothing without knowing how far two retrains on identical data drift
apart, so this stage retrains the tree model and the CNN with several seeds on the cached
dataset, stacks each pair the same way the pipeline does, and records the spread.

Nothing here writes models or touches ``dataset.parquet``: results go to
``work/seed_variance.json`` only. Seeds are never chosen by these numbers; the shipped
models keep the pipeline's fixed seed.

    python -m customs_ml.variance 7 11 23 42 101
    python -m customs_ml.variance compare old=path/to/models new=path/to/models

``compare`` scores exported model directories on the current features, which separates
what a scanner change did to the test data from what retraining did to the model.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from . import gbdt, metrics, splits
from . import nn as cnn
from .pipeline import (
    FPR_BLOCK,
    FPR_WARN,
    SCHEME,
    _fit_cnn,
    _fit_gbdt,
    feature_cols,
    fit_ensemble,
    load_table,
    log,
    work,
)

DEFAULT_SEEDS = (7, 11, 23, 42, 101)


def _roc_recall(y: np.ndarray, s: np.ndarray, fpr: float) -> float:
    neg = np.sort(s[y == 0])[::-1]
    k = int(np.floor(fpr * len(neg)))
    t = neg[k] if k < len(neg) else -np.inf
    return float(np.mean(s[y == 1] > t))


def test_metrics(df: pd.DataFrame, risk: np.ndarray, thr: dict, scheme: str = SCHEME) -> dict:
    """Headline and slice numbers for one stacked score, at the validation thresholds."""
    split = df[f"split_{scheme}"]
    te = (split == splits.TEST).to_numpy()
    y, s = df.label.to_numpy()[te], risk[te]
    out = {
        "roc_auc": metrics.summarize(y, s, thr).roc_auc,
        "recall_block": float(np.mean(s[y == 1] >= thr["block"])),
        "recall_warn": float(np.mean(s[y == 1] >= thr["warn"])),
        "fpr_block": float(np.mean(s[y == 0] >= thr["block"])),
        "fpr_warn": float(np.mean(s[y == 0] >= thr["warn"])),
        "roc_recall_0_001": _roc_recall(y, s, FPR_BLOCK),
        "roc_recall_0_01": _roc_recall(y, s, FPR_WARN),
    }
    T = df[te]
    slices = {
        "compromised_lib": ((T.kind == "compromised_lib") & (T.label == 1)).to_numpy(),
        "pypi": ((T.ecosystem == "pypi") & (T.label == 1)).to_numpy(),
    }
    for name, m in slices.items():
        keep = m | (y == 0)
        sm = metrics.summarize(y[keep], s[keep], thr)
        out[f"{name}_roc_auc"] = sm.roc_auc
        out[f"{name}_recall_block"] = sm.recall_at["block"]
        out[f"{name}_recall_warn"] = sm.recall_at["warn"]
    return out


def run_seed(df: pd.DataFrame, seed: int, scheme: str = SCHEME) -> dict:
    split = df[f"split_{scheme}"]
    cols = feature_cols(df)
    best, *_ = _fit_gbdt(df, split, cols, seed=seed)
    g = gbdt.predict_raw(best, df[cols].to_numpy(dtype=float))
    cfg = cnn.Config(seed=seed, max_len=768, epochs=10, patience=3)
    _, _, c, _, _ = _fit_cnn(df, split, cfg)
    np.savez_compressed(work() / f"seed_logits_{seed}.npz", gbdt=g, cnn=c)
    d = df.copy(deep=False)
    d[f"gbdt_logit_{scheme}"] = g
    d[f"cnn_logit_{scheme}"] = c
    ens, risk = fit_ensemble(d, scheme)
    thr = {"warn": ens["thresholds"]["warn"], "block": ens["thresholds"]["block"]}
    return {
        "seed": seed,
        "clip": ens.get("clip"),
        "weights": ens["weights"],
        "thresholds": thr,
        "test": test_metrics(d, risk, thr, scheme),
    }


def bagged(df: pd.DataFrame, seeds: list[int], scheme: str = SCHEME) -> dict:
    """Average the saved gbdt and CNN logits of several seeds, then stack as usual."""
    z = [np.load(work() / f"seed_logits_{s}.npz") for s in seeds]
    d = df.copy(deep=False)
    d[f"gbdt_logit_{scheme}"] = np.mean([x["gbdt"] for x in z], axis=0)
    d[f"cnn_logit_{scheme}"] = np.mean([x["cnn"] for x in z], axis=0)
    ens, risk = fit_ensemble(d, scheme)
    thr = {"warn": ens["thresholds"]["warn"], "block": ens["thresholds"]["block"]}
    return {"seeds": seeds, "test": test_metrics(d, risk, thr, scheme)}


def summarize_runs(runs: list[dict]) -> dict:
    keys = runs[0]["test"].keys()
    out = {}
    for k in keys:
        v = np.array([r["test"][k] for r in runs], dtype=float)
        out[k] = {
            "mean": float(v.mean()),
            "std": float(v.std(ddof=1)) if len(v) > 1 else 0.0,
            "min": float(v.min()),
            "max": float(v.max()),
        }
    return out


def run(seeds: tuple[int, ...] = DEFAULT_SEEDS, scheme: str = SCHEME) -> dict:
    df = load_table()
    runs = []
    path = work() / "seed_variance.json"
    for s in seeds:
        log(f"== seed {s}")
        r = run_seed(df, s, scheme)
        log("seed", s, {k: round(v, 4) for k, v in r["test"].items()})
        runs.append(r)
        res = {"scheme": scheme, "seeds": list(seeds), "runs": runs}
        res["spread"] = summarize_runs(runs)
        path.write_text(json.dumps(res, indent=1), encoding="utf-8")
    return res


def score_exported(df: pd.DataFrame, models: Path) -> tuple[np.ndarray, dict]:
    """Risk for every row from an exported model directory (gbdt, cnn, ensemble JSON)."""
    g_m = json.loads((models / "code_gbdt.json").read_text(encoding="utf-8"))
    n_m = json.loads((models / "code_nn.json").read_text(encoding="utf-8"))
    ens = json.loads((models / "ensemble.json").read_text(encoding="utf-8"))
    X = df[["f_" + n for n in g_m["feature_names"]]].to_numpy(dtype=float)
    g = gbdt.predict_raw_exported(g_m, X)
    c = np.array([cnn.numpy_forward(n_m, list(t)) for t in df.tokens])
    w, b = ens["weights"], ens.get("clip") or np.inf
    g, c, n = (np.clip(x, -b, b) for x in (g, c, df.name_logit.to_numpy()))
    z = ens["bias"] + w["code_gbdt"] * g + w["code_nn"] * c + w["name"] * n
    thr = {"warn": ens["thresholds"]["warn"], "block": ens["thresholds"]["block"]}
    return gbdt.apply_calibration(ens["calibration"], 1 / (1 + np.exp(-z))), thr


def compare(models: dict[str, Path], scheme: str = SCHEME) -> dict:
    df = load_table()
    if "augmented" in df:
        df = df[df.augmented.isna()]
    df = df[df[f"split_{scheme}"] == splits.TEST].reset_index(drop=True)
    out = {}
    for label, path in models.items():
        risk, thr = score_exported(df, path)
        out[label] = test_metrics(df, risk, thr, scheme)
        log("compare", label, {k: round(v, 4) for k, v in out[label].items()})
    (work() / "model_compare.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    return out


def main(argv: list[str]) -> None:
    if argv[:1] == ["compare"]:
        compare({a.split("=", 1)[0]: Path(a.split("=", 1)[1]) for a in argv[1:]})
        return
    seeds = tuple(int(a) for a in argv) or DEFAULT_SEEDS
    res = run(seeds)
    for k, v in res["spread"].items():
        print(f"{k:32s} mean {v['mean']:.4f} sd {v['std']:.4f} [{v['min']:.4f}, {v['max']:.4f}]")


if __name__ == "__main__":
    main(sys.argv[1:])
