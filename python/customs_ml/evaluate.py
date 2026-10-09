"""Test-set evaluation, figures, the written report, and export of model artifacts.

Every threshold used on the test set was chosen on the validation set. The only exception
is the GuardDog comparison at matched false-positive rate, where both tools are put at the
same test FPR on purpose (that is the definition of the comparison) and the report says so.
"""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.metrics import roc_curve  # noqa: E402

from . import baselines, config, metrics, names, registry_status, splits  # noqa: E402
from .pipeline import FPR_BLOCK, FPR_WARN, SCHEME, load_table, log, work  # noqa: E402

FIG_DIR = config.DOCS_DIR / "figures"
COMPONENT_COLS = {
    "Customs (ensemble)": "ens_risk_{s}",
    "Code model (GBDT)": "gbdt_logit_{s}",
    "Code model (CNN)": "cnn_logit_{s}",
    "Name model": "name_logit",
}


def _thresholds(df: pd.DataFrame, col: str, split: pd.Series) -> dict[str, float]:
    va = (split == splits.VAL).to_numpy()
    y, s = df.label.to_numpy()[va], df[col].to_numpy()[va]
    return {
        "warn": metrics.threshold_at_fpr(y, s, FPR_WARN),
        "block": metrics.threshold_at_fpr(y, s, FPR_BLOCK),
    }


def _ci(y, s, c, fn, n_boot=1000):
    pt, lo, hi = metrics.cluster_bootstrap(y, s, c, fn, n_boot=n_boot)
    return {"value": pt, "ci_low": lo, "ci_high": hi}


def _recall_fn(t):
    return lambda y, s: metrics.recall_at_threshold(y, s, t)


def _roc_recall_fn(fpr):
    return lambda y, s: metrics.recall_at_threshold(y, s, metrics.threshold_at_fpr(y, s, fpr))


def _fpr_fn(t):
    return lambda y, s: metrics.fpr_at_threshold(y, s, t)


def _auc(y, s):
    return metrics.summarize(y, s, {}).roc_auc


def _ap(y, s):
    return metrics.summarize(y, s, {}).pr_auc


def run(scheme: str = SCHEME, with_guarddog: bool = True) -> dict:
    df = load_table()
    split = df[f"split_{scheme}"]
    te = (split == splits.TEST).to_numpy()
    T = df[te].reset_index(drop=True)
    y, cl = T.label.to_numpy(), T.cluster.to_numpy()
    ens = json.loads((work() / f"ensemble_{scheme}.json").read_text(encoding="utf-8"))
    thr_ens = {"warn": ens["thresholds"]["warn"], "block": ens["thresholds"]["block"]}
    novel = splits.novel_mask(df, split).to_numpy()[te]
    res: dict = {"scheme": scheme, "generated": datetime.now(UTC).isoformat(timespec="seconds")}
    res["split_meta"] = json.loads((work() / "split_meta.json").read_text(encoding="utf-8"))
    res["counts"] = {
        s: {
            "malicious": int(((split == s) & (df.label == 1)).sum()),
            "benign": int(((split == s) & (df.label == 0)).sum()),
        }
        for s in (splits.TRAIN, splits.VAL, splits.TEST)
    }

    comp = {}
    for label, tmpl in COMPONENT_COLS.items():
        col = tmpl.format(s=scheme)
        if col not in T:
            continue
        thr = thr_ens if col.startswith("ens_") else _thresholds(df, col, split)
        s = T[col].to_numpy()
        sm = metrics.summarize(y, s, thr)
        comp[label] = {"column": col, "thresholds": thr, **sm.as_dict()}
    res["components"] = comp

    s = T[f"ens_risk_{scheme}"].to_numpy()
    head = {
        "roc_auc": _ci(y, s, cl, _auc),
        "pr_auc": _ci(y, s, cl, _ap),
        "recall_at_fpr_0_001": _ci(y, s, cl, _recall_fn(thr_ens["block"])),
        "recall_at_fpr_0_01": _ci(y, s, cl, _recall_fn(thr_ens["warn"])),
        "test_fpr_block": _ci(y, s, cl, _fpr_fn(thr_ens["block"])),
        "test_fpr_warn": _ci(y, s, cl, _fpr_fn(thr_ens["warn"])),
        # Threshold-free: detection at exactly this FPR on the test ROC. Separates model
        # quality from the noise of estimating a 0.1% threshold on ~2,000 validation
        # packages (each bootstrap resample re-derives its own threshold).
        "roc_recall_at_fpr_0_001": _ci(y, s, cl, _roc_recall_fn(FPR_BLOCK)),
        "roc_recall_at_fpr_0_01": _ci(y, s, cl, _roc_recall_fn(FPR_WARN)),
        "brier": metrics.brier(y, s),
        "ece": metrics.expected_calibration_error(y, s),
    }
    res["headline"] = head
    res["reliability"] = metrics.reliability_curve(y, s)

    # Slices: which kinds of malware and which benign packages are hard.
    sl = {}

    def add(name, mask):
        m = np.asarray(mask)
        yy = y[m | (y == 0)] if name.startswith("malicious:") else y[m]
        ss = s[m | (y == 0)] if name.startswith("malicious:") else s[m]
        sl[name] = metrics.summarize(yy, ss, thr_ens).as_dict()

    for eco in ("pypi", "npm"):
        add(f"ecosystem:{eco}", (T.ecosystem == eco).to_numpy())
    add("malicious:novel_campaigns", novel & (y == 1))
    add("malicious:seen_campaigns", ~novel & (y == 1))
    for kind in ("malicious_intent", "compromised_lib"):
        add(f"malicious:{kind}", ((T.kind == kind) & (y == 1)).to_numpy())
    snap = registry_status.load()
    if snap is not None:
        reg = np.array(registry_status.status_column(T, snap), dtype=object)
        for c in ("removed", "still_published"):
            add(f"malicious:registry_{c}", (reg == c) & (y == 1))
        res["registry_snapshot"] = snap["fetched"]
    for tier in ("top", "mid", "tail"):
        m = ((T.tier == tier) & (y == 0)).to_numpy()
        sl[f"benign:{tier}"] = {
            "n": int(m.sum()),
            "fpr_block": float(np.mean(s[m] >= thr_ens["block"])) if m.any() else None,
            "fpr_warn": float(np.mean(s[m] >= thr_ens["warn"])) if m.any() else None,
        }
    # Size strata, cut on benign terciles of total source lines, so a "small means bad"
    # shortcut would show up as a drop in AUC within strata.
    lines = T["f_all_n_lines"].to_numpy()
    q = np.quantile(lines[y == 0], [1 / 3, 2 / 3])
    for i, (lo, hi) in enumerate([(-1, q[0]), (q[0], q[1]), (q[1], np.inf)]):
        add(f"size:tercile_{i + 1}", (lines > lo) & (lines <= hi))
    res["slices"] = sl

    if with_guarddog:
        res["guarddog"] = _guarddog(T, y, cl, s)

    _figures(df, T, scheme, res)
    (work() / f"eval_{scheme}.json").write_text(
        json.dumps(res, indent=1, default=float), encoding="utf-8"
    )
    log("headline", {k: (v["value"] if isinstance(v, dict) else v) for k, v in head.items()})
    return res


GUARDDOG_PER_CLASS = 1500


def _guarddog(T: pd.DataFrame, y, cl, s) -> dict:
    # GuardDog takes seconds per package, so it runs on a fixed random sample of the test
    # set (up to GUARDDOG_PER_CLASS per class); Customs is compared on exactly those rows.
    sample = T.groupby("label", group_keys=False).apply(
        lambda g: g.sample(min(len(g), GUARDDOG_PER_CLASS), random_state=0)
    )
    gd = baselines.run(sample)
    if gd.empty:
        return {}
    m = T.merge(gd, left_on="canonical_path", right_on="path", how="left")
    ok = (m.gd_error == "").to_numpy()
    yy, cc, ss = y[ok], cl[ok], s[ok]
    if yy.sum() == 0 or (yy == 0).sum() == 0:
        log("GuardDog returned results for one class only: comparison skipped")
        return {}
    g = m.gd_score.to_numpy()[ok]
    flagged = (g > 0).astype(float)
    gd_fpr = float(flagged[yy == 0].mean())
    gd_recall = float(flagged[yy == 1].mean())
    # Customs at the same test FPR GuardDog runs at (thresholds set on test benign on
    # purpose, for both tools: that is what "matched FPR" means). The recall gain CI is a
    # paired cluster bootstrap over the same resampled rows for both tools.
    t_match = metrics.threshold_at_fpr(yy, ss, gd_fpr)
    rng = np.random.default_rng(0)
    uniq, inv = np.unique(cc, return_inverse=True)
    members = [np.flatnonzero(inv == i) for i in range(len(uniq))]
    deltas = []
    for _ in range(1000):
        idx = np.concatenate([members[i] for i in rng.integers(0, len(uniq), len(uniq))])
        a, b, lab = ss[idx], flagged[idx], yy[idx]
        if lab.sum() == 0 or (lab == 0).sum() == 0:
            continue
        deltas.append(np.mean(a[lab == 1] >= t_match) - np.mean(b[lab == 1] > 0.5))
    lo, hi = np.percentile(deltas, [2.5, 97.5]) if deltas else (np.nan, np.nan)
    gd_high = (m.gd_label.to_numpy()[ok] == "high_risk").astype(float)
    high_fpr = float(gd_high[yy == 0].mean())
    t_high = metrics.threshold_at_fpr(yy, ss, high_fpr)
    return {
        "n": int(ok.sum()),
        "n_malicious": int(yy.sum()),
        "n_benign": int((yy == 0).sum()),
        "roc_auc": _auc(yy, g),
        "customs_roc_auc_same_rows": _auc(yy, ss),
        "fpr": gd_fpr,
        "recall": gd_recall,
        "high_risk_fpr": high_fpr,
        "high_risk_recall": float(gd_high[yy == 1].mean()),
        "customs_recall_at_high_risk_fpr": float(np.mean(ss[yy == 1] >= t_high)),
        "customs_recall_at_matched_fpr": float(np.mean(ss[yy == 1] >= t_match)),
        "customs_fpr_at_matched": float(np.mean(ss[yy == 0] >= t_match)),
        "recall_gain_ci": [float(lo), float(hi)],
    }


def _figures(df: pd.DataFrame, T: pd.DataFrame, scheme: str, res: dict) -> None:
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    y = T.label.to_numpy()
    fig, ax = plt.subplots(figsize=(6.4, 4.6))
    for label, tmpl in COMPONENT_COLS.items():
        col = tmpl.format(s=scheme)
        if col in T:
            fpr, tpr, _ = roc_curve(y, T[col].to_numpy())
            ax.plot(np.maximum(fpr, 1e-4), tpr, label=label, lw=1.6)
    gd_path = work() / "guarddog.jsonl"
    if gd_path.exists() and res.get("guarddog"):
        gd = pd.read_json(gd_path, lines=True)
        m = T.merge(gd, left_on="canonical_path", right_on="path")
        m = m[m.gd_error == ""]
        fpr, tpr, _ = roc_curve(m.label, m.gd_score)
        ax.plot(np.maximum(fpr, 1e-4), tpr, label="GuardDog (risk score)", lw=1.6, ls="--")
    for f in (FPR_BLOCK, FPR_WARN):
        ax.axvline(f, color="0.6", lw=0.8, ls=":")
    ax.set_xscale("log")
    ax.set_xlim(1e-4, 1)
    ax.set_xlabel("False-positive rate (benign packages flagged), log scale")
    ax.set_ylabel("Detection rate (malicious packages caught)")
    ax.set_title(f"Test set ROC, {scheme} split")
    ax.legend(loc="lower right", fontsize=8)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "roc.png", dpi=150)
    plt.close(fig)

    rel = res["reliability"]
    fig, ax = plt.subplots(figsize=(4.6, 4.6))
    ax.plot([0, 1], [0, 1], color="0.6", lw=0.8, ls=":")
    ax.plot([r["mean_pred"] for r in rel], [r["frac_pos"] for r in rel], marker="o")
    ax.set_xlabel("Predicted risk")
    ax.set_ylabel("Observed fraction malicious")
    ax.set_title("Calibration (test)")
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIG_DIR / "calibration.png", dpi=150)
    plt.close(fig)

    imp = pd.read_csv(work() / f"gbdt_importance_{scheme}.csv", index_col=0).iloc[:15, 0]
    fig, ax = plt.subplots(figsize=(6.4, 4.6))
    ax.barh(imp.index[::-1], imp.values[::-1] / imp.values.sum())
    ax.set_xlabel("Share of total split gain")
    ax.set_title("Code model: most informative features")
    fig.tight_layout()
    fig.savefig(FIG_DIR / "feature_importance.png", dpi=150)
    plt.close(fig)


# ---------------------------------------------------------------- export


def export(scheme: str = SCHEME) -> None:
    """Copy trained artifacts into ``models/`` and write manifest and metrics."""
    out = config.MODELS_DIR
    out.mkdir(exist_ok=True)
    (out / "parity").mkdir(exist_ok=True)
    shutil.copy(work() / f"code_gbdt_{scheme}.json", out / "code_gbdt.json")
    shutil.copy(work() / f"code_nn_{scheme}.json", out / "code_nn.json")
    shutil.copy(work() / "name_model.json", out / "name_model.json")
    shutil.copy(work() / f"ensemble_{scheme}.json", out / "ensemble.json")
    shutil.copy(work() / f"cnn_parity_{scheme}.json", out / "parity" / "code_nn.json")
    shutil.copy(work() / "name_parity.json", out / "parity" / "name_model.json")
    for eco in ("pypi", "npm"):
        (out / f"popular_{eco}.txt").write_text(
            "\n".join(names.popular(eco)) + "\n", encoding="utf-8"
        )
    _gbdt_parity(scheme, out / "parity" / "code_gbdt.json")
    ev = json.loads((work() / f"eval_{scheme}.json").read_text(encoding="utf-8"))
    ens = json.loads((work() / f"ensemble_{scheme}.json").read_text(encoding="utf-8"))
    version = datetime.now(UTC).strftime("%Y.%m.%d")
    manifest = {
        "model_version": version,
        "feature_schema_version": 1,
        "code_gbdt": "code_gbdt.json",
        "code_nn": "code_nn.json",
        "name_model": "name_model.json",
        "ensemble": "ensemble.json",
        "popular_names": {"pypi": "popular_pypi.txt", "npm": "popular_npm.txt"},
        "metrics": "metrics.json",
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    h = ev["headline"]
    gd = ev.get("guarddog") or {}
    m = {
        "model_version": version,
        "feature_schema_version": 1,
        "thresholds": ens["thresholds"],
        "metrics": {
            "split": f"{scheme} (test: malware found from {ev['split_meta']['test_cutoff']})",
            "roc_auc": h["roc_auc"],
            "pr_auc": h["pr_auc"],
            "recall_at_fpr_0_001": h["recall_at_fpr_0_001"],
            "recall_at_fpr_0_01": h["recall_at_fpr_0_01"],
            "test_fpr_block": h["test_fpr_block"],
            "brier": h["brier"],
            "n_test_malicious": ev["counts"]["test"]["malicious"],
            "n_test_benign": ev["counts"]["test"]["benign"],
            "baselines": {
                "guarddog": {
                    "fpr": gd.get("fpr"),
                    "recall": gd.get("recall"),
                    "customs_recall_at_matched_fpr": gd.get("customs_recall_at_matched_fpr"),
                }
            }
            if gd
            else {},
        },
    }
    (out / "metrics.json").write_text(
        json.dumps(m, indent=1, default=float) + "\n", encoding="utf-8"
    )
    log("exported to", out)


def _gbdt_parity(scheme: str, path: Path) -> None:
    from . import gbdt

    df = load_table()
    model = json.loads((work() / f"code_gbdt_{scheme}.json").read_text(encoding="utf-8"))
    cols = ["f_" + n for n in model["feature_names"]]
    rows = df.sample(25, random_state=0)
    X = rows[cols].to_numpy(dtype=float)
    raw = gbdt.predict_raw_exported(model, X)
    fx = []
    for i in range(len(rows)):
        bias, contrib = gbdt.contributions_exported(model, X[i])
        fx.append(
            {
                "features": dict(zip(model["feature_names"], X[i].tolist(), strict=True)),
                "raw": float(raw[i]),
                "bias": float(bias),
                "top_contributions": sorted(
                    (
                        {"feature": f, "contribution": float(c)}
                        for f, c in zip(model["feature_names"], contrib, strict=True)
                        if c != 0
                    ),
                    key=lambda d: -abs(d["contribution"]),
                )[:5],
            }
        )
    path.write_text(json.dumps(fx, indent=1), encoding="utf-8")
