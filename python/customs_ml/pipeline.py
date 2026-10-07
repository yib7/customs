"""End-to-end training pipeline: dataset -> clusters -> splits -> models -> evaluation -> export.

Each stage caches its output under ``$CUSTOMS_DATA/work`` so stages can be re-run alone:

    python -m customs_ml.pipeline table cluster split gbdt cnn names ensemble evaluate export

``all`` runs every stage in order.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score

from . import config, dedup, features, gbdt, metrics, name_model, names, splits
from . import nn as cnn

FPR_WARN = 0.01
FPR_BLOCK = 0.001
SCHEME = "temporal"


def work() -> Path:
    return config.sub("work")


def log(*a) -> None:
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def load_table() -> pd.DataFrame:
    return pd.read_parquet(work() / "dataset.parquet")


def feature_cols(df: pd.DataFrame) -> list[str]:
    return [c for c in df.columns if c.startswith("f_")]


# ---------------------------------------------------------------- stages


def stage_table() -> None:
    df = features.build_table()
    log("table", df.shape, df.groupby(["ecosystem", "label"]).size().to_dict())
    df.to_parquet(work() / "dataset.parquet")


def stage_refresh() -> None:
    """Rescan every corpus archive and replace the feature columns and token streams.

    For a scanner change after the corpus was built. Clusters and splits stay as they are,
    so results remain comparable across scanner versions; retrain the models afterwards
    (``augment gbdt ablation cnn ensemble evaluate export``). Augmented rows are dropped
    (they have no archive on disk) and rebuilt by the ``augment`` stage.
    """
    df = load_table()
    if "augmented" in df:
        df = df[df.augmented.isna()].reset_index(drop=True)
    t = time.time()
    reports = features.scan_paths(df.canonical_path.tolist(), tokens=True)
    fdf = pd.DataFrame([r.get("features") or {} for r in reports]).add_prefix("f_")
    changed = sum(
        list(a) != (r.get("tokens") or []) for a, r in zip(df.tokens, reports, strict=True)
    )
    df["tokens"] = [r.get("tokens") or [] for r in reports]
    log(f"token streams changed for {changed} of {len(df)} archives")
    old = feature_cols(df)
    added = sorted(set(fdf.columns) - set(old))
    df = pd.concat([df.drop(columns=old), fdf], axis=1)
    log(f"rescanned {len(df)} archives in {time.time() - t:.0f}s; new features: {added}")
    df.to_parquet(work() / "dataset.parquet")


def stage_cluster() -> None:
    df = load_table()
    t = time.time()
    df["cluster"] = dedup.cluster([list(x) for x in df.tokens])
    sizes = df.groupby("cluster").size()
    log(
        f"clusters: {len(sizes)} for {len(df)} rows in {time.time() - t:.0f}s; "
        f"largest {sizes.max()}; malicious clusters "
        f"{df[df.label == 1].cluster.nunique()} for {int(df.label.sum())} samples"
    )
    mixed = df.groupby("cluster").label.nunique()
    log(f"clusters containing both labels: {int((mixed > 1).sum())}")
    df.to_parquet(work() / "dataset.parquet")


def stage_split() -> None:
    df = load_table()
    t = splits.assign_temporal(df)
    df["split_temporal"] = t.values
    df["split_grouped"] = splits.assign_grouped(df).values
    meta = {"val_cutoff": t.attrs["val_cutoff"], "test_cutoff": t.attrs["test_cutoff"]}
    (work() / "split_meta.json").write_text(json.dumps(meta))
    for s in ("split_temporal", "split_grouped"):
        log(s, df.groupby([s, "label"]).size().to_dict())
    log("temporal cutoffs", meta)
    df.to_parquet(work() / "dataset.parquet")


def _xy(df: pd.DataFrame, cols: list[str], split: pd.Series, which: str):
    m = (split == which).to_numpy()
    return df.loc[m, cols].to_numpy(dtype=float), df.label.to_numpy()[m], m


def _fit_gbdt(df: pd.DataFrame, split: pd.Series, cols: list[str]):
    names_ = [c[2:] for c in cols]
    w = splits.sample_weights(df, split)
    Xtr, ytr, mtr = _xy(df, cols, split, splits.TRAIN)
    Xva, yva, mva = _xy(df, cols, split, splits.VAL)
    best, best_ap = None, -1.0
    for leaves in (15, 31, 63):
        for min_leaf in (10, 40):
            t = gbdt.train(
                Xtr,
                ytr,
                w[mtr],
                Xva,
                yva,
                w[mva],
                names_,
                {"num_leaves": leaves, "min_data_in_leaf": min_leaf},
            )
            ap = average_precision_score(yva, gbdt.predict_raw(t, Xva))
            log(
                f"gbdt leaves={leaves} min_leaf={min_leaf} iters={t.best_iteration} val AP={ap:.4f}"
            )
            if ap > best_ap:
                best, best_ap = t, ap
    return best, Xva, yva, names_


def behavior_cols(df: pd.DataFrame) -> list[str]:
    """Indicator and obfuscation features only: no manifest metadata, no size or file counts.

    These describe what the code does. Metadata (README size, repository link) is a strong
    signal on today's malware but costs an attacker nothing to fake.
    """
    size_like = ("n_lines", "bytes", "n_files")
    return [
        c
        for c in feature_cols(df)
        if c.startswith(("f_inst_", "f_all_")) and not c.endswith(size_like)
    ]


def stage_gbdt(scheme: str = SCHEME) -> None:
    df = load_table()
    split = df[f"split_{scheme}"]
    cols = feature_cols(df)
    best, Xva, yva, names_ = _fit_gbdt(df, split, cols)
    raw_va = gbdt.predict_raw(best, Xva)
    model = gbdt.export(best, gbdt.fit_isotonic(raw_va, yva))
    gbdt.save(model, work() / f"code_gbdt_{scheme}.json")
    df[f"gbdt_logit_{scheme}"] = gbdt.predict_raw(best, df[cols].to_numpy(dtype=float))
    imp = pd.Series(best.booster.feature_importance("gain"), index=names_).sort_values(
        ascending=False
    )
    imp.to_csv(work() / f"gbdt_importance_{scheme}.csv")
    log("top features", imp.head(12).round(1).to_dict())
    df.to_parquet(work() / "dataset.parquet")


def stage_cnn(scheme: str = SCHEME, cfg: cnn.Config | None = None) -> None:
    df = load_table()
    split = df[f"split_{scheme}"]
    cfg = cfg or cnn.Config()
    docs = [list(t) for t in df.tokens]
    tr = (split == splits.TRAIN).to_numpy()
    va = (split == splits.VAL).to_numpy()
    vocab = cnn.build_vocab([d for d, m in zip(docs, tr, strict=True) if m], cfg)
    X = cnn.encode(docs, vocab, cfg.max_len)
    y = df.label.to_numpy()
    w = splits.sample_weights(df, split)
    log(f"cnn vocab {len(vocab)}, train {tr.sum()}, val {va.sum()}")
    model, hist = cnn.train(X[tr], y[tr], w[tr], X[va], y[va], len(vocab), cfg, log=log)
    exported = cnn.export(model, vocab, cfg)
    cnn.save(exported, work() / f"code_nn_{scheme}.json")
    (work() / f"cnn_history_{scheme}.json").write_text(json.dumps(hist))
    df[f"cnn_logit_{scheme}"] = cnn.predict_logits(model, X)
    # Parity fixtures for the Rust forward pass, from real data.
    rng = np.random.default_rng(0)
    pick = rng.choice(len(docs), size=min(25, len(docs)), replace=False)
    fx = [{"tokens": docs[i], "logit": float(cnn.numpy_forward(exported, docs[i]))} for i in pick]
    (work() / f"cnn_parity_{scheme}.json").write_text(json.dumps(fx))
    df.to_parquet(work() / "dataset.parquet")


def stage_names() -> None:
    """Train one name model per ecosystem on OSSF names, holding out code-dataset names."""
    df = load_table()
    nd = names.load()
    held = set(
        zip(
            df.ecosystem,
            [name_model.normalize(e, n) for e, n in zip(df.ecosystem, df.name, strict=True)],
            strict=True,
        )
    )
    nd["held"] = [(e, n) in held for e, n in zip(nd.ecosystem, nd.norm, strict=True)]
    # Malicious names reported after the validation cutoff are future knowledge: the
    # temporal evaluation must not let the name model learn from them.
    cutoff = pd.Timestamp(
        json.loads((work() / "split_meta.json").read_text())["val_cutoff"], tz="UTC"
    )
    nd = nd[(nd.label == 0) | (nd.published < cutoff)]
    models, report = {}, {}
    rng = np.random.default_rng(3)
    for eco in ("pypi", "npm"):
        pop = name_model.Popular.from_list(eco, names.popular(eco))
        d = nd[(nd.ecosystem == eco) & ~nd.held].copy()
        # Balance the classes by subsampling the larger one; cap size for training time.
        n = min(int(d.label.sum()), int((1 - d.label).sum()), 120_000)
        d = pd.concat(
            [d[d.label == 1].sample(n, random_state=1), d[d.label == 0].sample(n, random_state=1)]
        )
        hold = rng.uniform(0, 1, len(d)) < 0.2
        clf, mean, std = name_model.train(d.norm[~hold].tolist(), d.label[~hold].to_numpy(), pop)
        Xh, _, _ = name_model.design_matrix(d.norm[hold].tolist(), pop, mean, std)
        sh = clf.decision_function(Xh)
        s = metrics.summarize(d.label[hold].to_numpy(), sh, {})
        report[eco] = {"n_train": int((~hold).sum()), "holdout": s.as_dict()}
        log(f"name model {eco}: holdout ROC AUC {s.roc_auc:.4f} PR AUC {s.pr_auc:.4f}")
        models[eco] = (clf, mean, std)
        rows = df.ecosystem == eco
        norm = [name_model.normalize(eco, x) for x in df.loc[rows, "name"]]
        Xd, _, _ = name_model.design_matrix(norm, pop, mean, std)
        df.loc[rows, "name_logit"] = clf.decision_function(Xd)
    exported = name_model.export(models, {"pypi": "popular_pypi.txt", "npm": "popular_npm.txt"})
    name_model.save(exported, work() / "name_model.json")
    (work() / "name_report.json").write_text(json.dumps(report, indent=2))
    fx = []
    for eco in ("pypi", "npm"):
        pop = name_model.Popular.from_list(eco, names.popular(eco))
        sample = [
            "requests",
            "reqeusts",
            "numpy-utils-pro",
            "@types/node",
            "@typs/node",
            "left-pad",
            "lodahs",
            "colorama2",
            "python-dateutil",
            "discord.js-selfbot-v14",
        ]
        for s in sample:
            fx.append(
                {
                    "ecosystem": eco,
                    "name": s,
                    "logit": name_model.score_exported(exported, eco, s, pop),
                }
            )
    (work() / "name_parity.json").write_text(json.dumps(fx, indent=1))
    df.to_parquet(work() / "dataset.parquet")


def stage_ablation(scheme: str = SCHEME) -> None:
    """Behavior-only tree model, evaluated on test next to the full one."""
    df = load_table()
    split = df[f"split_{scheme}"]
    cols = behavior_cols(df)
    best, Xva, yva, _ = _fit_gbdt(df, split, cols)
    raw = gbdt.predict_raw(best, df[cols].to_numpy(dtype=float))
    df[f"gbdt_behavior_logit_{scheme}"] = raw
    out = {"n_features": len(cols), "features": [c[2:] for c in cols]}
    va = (split == splits.VAL).to_numpy()
    te = (split == splits.TEST).to_numpy()
    y = df.label.to_numpy()
    for name, col in (("all_features", f"gbdt_logit_{scheme}"), ("behavior_only", None)):
        sc = raw if col is None else df[col].to_numpy()
        thr = {
            "warn": metrics.threshold_at_fpr(y[va], sc[va], FPR_WARN),
            "block": metrics.threshold_at_fpr(y[va], sc[va], FPR_BLOCK),
        }
        out[name] = metrics.summarize(y[te], sc[te], thr).as_dict()
        log("ablation", name, out[name])
    (work() / f"ablation_{scheme}.json").write_text(json.dumps(out, indent=1))
    df.to_parquet(work() / "dataset.parquet")


COMPONENTS = ["code_gbdt", "code_nn", "name"]


def _component_matrix(df: pd.DataFrame, scheme: str) -> np.ndarray:
    return np.c_[df[f"gbdt_logit_{scheme}"], df[f"cnn_logit_{scheme}"], df["name_logit"]]


def _fit_stacker(Z: np.ndarray, y: np.ndarray, w: np.ndarray) -> LogisticRegression:
    clf = LogisticRegression(C=1.0, max_iter=1000)
    clf.fit(Z, y, sample_weight=w)
    return clf


def stage_ensemble(scheme: str = SCHEME) -> None:
    """Stack component logits on the validation split with cluster-grouped cross-fitting.

    Out-of-fold stacked scores on validation are used to fit the calibration (Platt, see
    gbdt.fit_platt) and to pick thresholds, so neither is tuned on scores the stacker was
    fit to.
    """
    df = load_table()
    split = df[f"split_{scheme}"]
    va = (split == splits.VAL).to_numpy()
    Z = _component_matrix(df, scheme)
    y = df.label.to_numpy()
    w = splits.sample_weights(df, split, which=splits.VAL)
    Zv, yv, wv, cv = Z[va], y[va], w[va], df.cluster.to_numpy()[va]
    folds = (
        pd.Series(cv)
        .map(
            pd.Series(
                np.random.default_rng(0).integers(0, 5, len(np.unique(cv))), index=np.unique(cv)
            )
        )
        .to_numpy()
    )
    oof = np.zeros(len(Zv))
    for k in range(5):
        m = folds == k
        clf = _fit_stacker(Zv[~m], yv[~m], wv[~m])
        oof[m] = clf.decision_function(Zv[m])
    final = _fit_stacker(Zv, yv, wv)
    p_oof = 1 / (1 + np.exp(-oof))
    cal = gbdt.fit_platt(oof, yv)
    risk_oof = gbdt.apply_calibration(cal, p_oof)
    t_warn = metrics.threshold_at_fpr(yv, risk_oof, FPR_WARN)
    t_block = metrics.threshold_at_fpr(yv, risk_oof, FPR_BLOCK)
    fallbacks = []
    for missing in (["code_nn"], ["name"], ["code_nn", "name"]):
        keep = [i for i, c in enumerate(COMPONENTS) if c not in missing]
        fb = _fit_stacker(Zv[:, keep], yv, wv)
        fallbacks.append(
            {
                "missing": missing,
                "weights": {
                    COMPONENTS[i]: float(c) for i, c in zip(keep, fb.coef_[0], strict=True)
                },
                "bias": float(fb.intercept_[0]),
            }
        )
    ens = {
        "format": "customs-ensemble-v1",
        "components": COMPONENTS,
        "weights": {c: float(v) for c, v in zip(COMPONENTS, final.coef_[0], strict=True)},
        "bias": float(final.intercept_[0]),
        "fallbacks": fallbacks,
        "calibration": cal,
        "thresholds": {
            "warn": float(t_warn),
            "block": float(t_block),
            "target_fpr_warn": FPR_WARN,
            "target_fpr_block": FPR_BLOCK,
        },
    }
    (work() / f"ensemble_{scheme}.json").write_text(json.dumps(ens, indent=1))
    z = final.decision_function(Z)
    df[f"ens_risk_{scheme}"] = gbdt.apply_calibration(cal, 1 / (1 + np.exp(-z)))
    log("ensemble weights", ens["weights"], "thresholds", ens["thresholds"])
    df.to_parquet(work() / "dataset.parquet")


def main(argv: list[str]) -> None:
    stages = {
        "table": stage_table,
        "refresh": stage_refresh,
        "cluster": stage_cluster,
        "split": stage_split,
        "gbdt": stage_gbdt,
        "cnn": stage_cnn,
        "names": stage_names,
        "ensemble": stage_ensemble,
        "ablation": stage_ablation,
    }
    from . import augment

    stages["augment"] = augment.stage_augment
    try:
        from . import evaluate

        stages["evaluate"] = evaluate.run
        stages["export"] = evaluate.export
    except ImportError:
        pass
    todo = list(stages) if argv == ["all"] else argv
    for s in todo:
        log("== stage", s)
        stages[s]()


if __name__ == "__main__":
    main(sys.argv[1:])
