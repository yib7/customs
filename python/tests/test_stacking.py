import numpy as np

from customs_ml import pipeline


def test_partial_recall_counts_only_the_low_fpr_end():
    y = np.r_[np.zeros(1000), np.ones(4)]
    # Benign scores 0..999; positives above all of them except one, which sits mid-range
    # and should only count at thresholds far beyond 1% FPR.
    s = np.r_[np.arange(1000.0), [2000, 2001, 2002, 500.5]]
    assert pipeline.partial_recall(y, s, max_fpr=0.01) == 0.75
    assert pipeline.partial_recall(y, s, max_fpr=1.0) > 0.75


def test_clip_bounds_every_component():
    Z = np.array([[20.0, -30.0, 0.5], [1.0, 2.0, -3.0]])
    assert pipeline.clip_logits(Z, None) is Z
    np.testing.assert_array_equal(pipeline.clip_logits(Z, 2.0), [[2, -2, 0.5], [1, 2, -2]])


def test_clip_rescues_the_threshold_from_one_outlier_component():
    """One benign row with a huge component logit dominates an unclipped linear stack."""
    rng = np.random.default_rng(1)
    n = 2000
    y = np.r_[np.zeros(n), np.ones(n)]
    g = np.r_[rng.normal(-2, 1, n), rng.normal(2, 1, n)]
    c = np.r_[rng.normal(-2, 1, n), rng.normal(2, 1, n)]
    c[:5] = 25.0
    Z = np.c_[g, c]
    w = np.ones(len(y))
    raw = pipeline._fit_stacker(Z, y, w).decision_function(Z)
    Zc = pipeline.clip_logits(Z, 4.0)
    clipped = pipeline._fit_stacker(Zc, y, w).decision_function(Zc)
    assert pipeline.partial_recall(y, clipped, 0.001) > pipeline.partial_recall(y, raw, 0.001)
