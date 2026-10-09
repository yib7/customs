import json

import numpy as np
import pandas as pd

from customs_ml import variance


def test_bagged_writes_seed_bagging(monkeypatch, tmp_path):
    rng = np.random.default_rng(0)
    n = 40
    df = pd.DataFrame(
        {
            "label": np.r_[np.zeros(n // 2), np.ones(n // 2)].astype(int),
            "split_temporal": ["test"] * n,
            "kind": ["malicious_intent"] * n,
            "ecosystem": ["pypi"] * n,
        }
    )
    for s in (1, 2, 3):
        np.savez_compressed(
            tmp_path / f"seed_logits_{s}.npz", gbdt=rng.normal(size=n), cnn=rng.normal(size=n)
        )
    monkeypatch.setattr(variance, "work", lambda: tmp_path)
    monkeypatch.setattr(variance, "load_table", lambda: df)

    def fit(d, scheme):
        z = d["gbdt_logit_temporal"].to_numpy() + d["cnn_logit_temporal"].to_numpy()
        return {"thresholds": {"warn": 0.5, "block": 0.9}}, 1 / (1 + np.exp(-z))

    monkeypatch.setattr(variance, "fit_ensemble", fit)
    out = variance.bag((1, 2, 3))
    saved = json.loads((tmp_path / "seed_bagging.json").read_text(encoding="utf-8"))
    assert json.dumps(saved) == json.dumps(out)  # NaN-safe (no compromised rows here)
    # Every subset of each size: 3 singles, 3 pairs, 1 triple; the report reads these keys.
    assert {k: v["n"] for k, v in saved.items()} == {"1": 3, "2": 3, "3": 1}
    for k in ("recall_block", "fpr_block", "recall_warn", "roc_auc"):
        assert {"mean", "min", "max"} <= set(saved["1"]["spread"][k])
