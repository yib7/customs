import numpy as np

from customs_ml import gbdt


def _data(n=3000, d=12, seed=0):
    rng = np.random.default_rng(seed)
    X = rng.poisson(1.0, (n, d)).astype(float)
    logit = 1.5 * X[:, 0] - 1.0 * X[:, 1] + 0.8 * (X[:, 2] > 2) - 1.0
    y = (rng.uniform(0, 1, n) < 1 / (1 + np.exp(-logit))).astype(int)
    return X, y


def _trained():
    X, y = _data()
    names = [f"f{i}" for i in range(X.shape[1])]
    w = np.ones(len(y))
    t = gbdt.train(
        X[:2000], y[:2000], w[:2000], X[2000:], y[2000:], w[2000:], names, num_boost_round=200
    )
    return t, X


def test_export_matches_lightgbm_exactly():
    t, X = _trained()
    model = gbdt.export(t, None)
    ref = gbdt.predict_raw(t, X[:300])
    got = gbdt.predict_raw_exported(model, X[:300])
    np.testing.assert_allclose(got, ref, rtol=0, atol=1e-9)


def test_saabas_contributions_sum_to_raw_score():
    t, X = _trained()
    model = gbdt.export(t, None)
    raw = gbdt.predict_raw_exported(model, X[:20])
    for i in range(20):
        bias, c = gbdt.contributions_exported(model, X[i])
        assert abs(bias + c.sum() - raw[i]) < 1e-9


def test_isotonic_calibration_is_monotone():
    rng = np.random.default_rng(3)
    raw = rng.normal(0, 2, 5000)
    y = (rng.uniform(0, 1, 5000) < 1 / (1 + np.exp(-raw))).astype(int)
    cal = gbdt.fit_isotonic(raw, y)
    p = gbdt.apply_calibration(cal, np.linspace(0, 1, 101))
    assert np.all(np.diff(p) >= 0)
