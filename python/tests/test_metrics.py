import numpy as np

from customs_ml import metrics


def test_threshold_at_fpr_respects_budget():
    rng = np.random.default_rng(0)
    y = np.r_[np.zeros(1000), np.ones(100)].astype(int)
    s = np.r_[rng.normal(0, 1, 1000), rng.normal(3, 1, 100)]
    for fpr in (0.001, 0.01, 0.1):
        t = metrics.threshold_at_fpr(y, s, fpr)
        assert metrics.fpr_at_threshold(y, s, t) <= fpr
    # Zero budget means nothing negative may pass.
    t0 = metrics.threshold_at_fpr(y, s, 0.0)
    assert metrics.fpr_at_threshold(y, s, t0) == 0.0


def test_summary_perfect_separation():
    y = np.array([0, 0, 1, 1])
    s = np.array([0.1, 0.2, 0.8, 0.9])
    sm = metrics.summarize(y, s, {"t": 0.5})
    assert sm.roc_auc == 1.0 and sm.recall_at["t"] == 1.0 and sm.fpr_at["t"] == 0.0


def test_calibration_of_calibrated_scores_is_small():
    rng = np.random.default_rng(1)
    p = rng.uniform(0, 1, 20000)
    y = (rng.uniform(0, 1, 20000) < p).astype(int)
    assert metrics.expected_calibration_error(y, p) < 0.02


def test_cluster_bootstrap_ci_contains_point():
    rng = np.random.default_rng(2)
    y = np.r_[np.zeros(300), np.ones(300)].astype(int)
    s = np.r_[rng.normal(0, 1, 300), rng.normal(1.5, 1, 300)]
    clusters = np.arange(600) // 3
    pt, lo, hi = metrics.cluster_bootstrap(
        y, s, clusters, lambda a, b: metrics.summarize(a, b, {}).roc_auc, n_boot=200
    )
    assert lo <= pt <= hi and hi - lo < 0.1
