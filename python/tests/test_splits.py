import numpy as np
import pandas as pd

from customs_ml import splits


def _frame(n=1000, seed=0):
    rng = np.random.default_rng(seed)
    label = rng.integers(0, 2, n)
    dates = pd.to_datetime("2024-01-01", utc=True) + pd.to_timedelta(rng.integers(0, 900, n), "D")
    cluster = rng.integers(0, 300, n)
    return pd.DataFrame({"label": label, "date": dates, "cluster": cluster})


def test_temporal_malicious_ordering():
    df = _frame()
    s = splits.assign_temporal(df)
    mal = df[df.label == 1]
    assert (
        mal.loc[s[mal.index] == "train", "date"].max()
        < mal.loc[s[mal.index] == "test", "date"].min()
    )


def test_benign_clusters_do_not_straddle():
    df = _frame()
    s = splits.assign_temporal(df)
    ben = df[df.label == 0].assign(split=s)
    assert (ben.groupby("cluster").split.nunique() == 1).all()


def test_grouped_split_no_cluster_overlap():
    df = _frame()
    s = splits.assign_grouped(df)
    assert (df.assign(split=s).groupby("cluster").split.nunique() == 1).all()


def test_weights_balance_classes_in_train():
    df = _frame()
    s = splits.assign_grouped(df)
    w = splits.sample_weights(df, s)
    tr = (s == "train").to_numpy()
    y = df.label.to_numpy()
    assert np.isclose(w[tr & (y == 1)].sum(), w[tr & (y == 0)].sum())
