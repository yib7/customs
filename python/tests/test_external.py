import numpy as np
import pandas as pd

from customs_ml import external


def test_matched_fpr_uses_benign_test_quantiles():
    rng = np.random.default_rng(0)
    df = pd.DataFrame(
        {
            "label": [0] * 1000 + [1] * 10,
            "split_temporal": ["test"] * 1010,
            "ens_risk": np.r_[rng.uniform(0, 1, 1000), np.ones(10)],
        }
    )
    g = pd.DataFrame({"risk": [0.995, 0.5, 0.0, np.nan]})
    out = external._matched_fpr(df, g)
    assert out["benign_test_n"] == 1000
    # Threshold near the 99th percentile of uniform benign scores; NaN risks are dropped.
    assert abs(out["0.01"]["threshold"] - 0.99) < 0.02
    assert out["0.01"]["recall"] == 1 / 3
    assert out["0.001"]["threshold"] > out["0.01"]["threshold"]


def test_code_only_risk_uses_the_no_name_fallback():
    ens = {
        "fallbacks": [
            {"missing": ["code_nn"], "weights": {"code_gbdt": 9.0, "name": 9.0}, "bias": 9.0},
            {"missing": ["name"], "weights": {"code_gbdt": 1.0, "code_nn": 0.5}, "bias": -1.0},
        ],
        "calibration": {"x": [0.0, 1.0], "y": [0.0, 1.0]},
    }
    df = pd.DataFrame({"gbdt_logit_temporal": [2.0, 0.0], "cnn_logit_temporal": [0.0, 2.0]})
    r = external.code_only_risk(df, ens)
    z = np.array([1.0, 0.0])
    assert np.allclose(r, 1 / (1 + np.exp(-z)))
