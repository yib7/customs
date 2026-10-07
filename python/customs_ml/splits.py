"""Train / validation / test splits that do not leak.

Two schemes, both grouping by near-duplicate cluster (see :mod:`customs_ml.dedup`):

``temporal`` (headline): malicious samples are split by discovery date, so the test set is
malware found after everything the model trained on, the situation a deployed firewall
faces. Benign packages have no meaningful "discovery" date (a popular package's latest
upload is recent simply because it is maintained), so they are split at random by cluster
in the same proportions. A cluster never straddles two benign splits. Malicious clusters
may continue across the date cutoff, which is realistic (a campaign keeps publishing), so
the evaluation also reports the "novel campaign" subset: test malware whose cluster has no
member in training.

``grouped``: every cluster goes to one split at random. Easier, reported for reference.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

TRAIN, VAL, TEST = "train", "val", "test"


def temporal_cutoffs(dates: pd.Series, val_q: float = 0.70, test_q: float = 0.80) -> tuple:
    d = dates.dropna().sort_values()
    return d.quantile(val_q), d.quantile(test_q)


def assign_temporal(
    df: pd.DataFrame, seed: int = 0, val_q: float = 0.70, test_q: float = 0.80
) -> pd.Series:
    mal = df.label == 1
    val_cut, test_cut = temporal_cutoffs(df.loc[mal, "date"], val_q, test_q)
    split = pd.Series(TRAIN, index=df.index)
    d = df.loc[mal, "date"]
    split.loc[d[d >= val_cut].index] = VAL
    split.loc[d[d >= test_cut].index] = TEST
    ben = df[~mal]
    split.loc[ben.index] = _random_by_cluster(ben.cluster, (val_q, test_q), seed).values
    split.attrs["val_cutoff"] = str(val_cut.date())
    split.attrs["test_cutoff"] = str(test_cut.date())
    return split


def assign_grouped(df: pd.DataFrame, seed: int = 0, val_q: float = 0.70, test_q: float = 0.80):
    return pd.Series(_random_by_cluster(df.cluster, (val_q, test_q), seed).values, index=df.index)


def _random_by_cluster(clusters: pd.Series, qs: tuple[float, float], seed: int) -> pd.Series:
    rng = np.random.default_rng(seed)
    uniq = clusters.unique()
    u = pd.Series(rng.uniform(0, 1, len(uniq)), index=uniq)
    r = clusters.map(u)
    out = pd.Series(TRAIN, index=clusters.index)
    out[r >= qs[0]] = VAL
    out[r >= qs[1]] = TEST
    return out


def novel_mask(df: pd.DataFrame, split: pd.Series) -> pd.Series:
    """Test rows whose cluster never appears in the training split."""
    train_clusters = set(df.loc[split == TRAIN, "cluster"])
    return (split == TEST) & ~df.cluster.isin(train_clusters)


def sample_weights(df: pd.DataFrame, split: pd.Series, which: str = TRAIN) -> np.ndarray:
    """Down-weight big clusters (weight 1/sqrt(size)) and balance classes within ``which``.

    Without this a single worm that published 400 copies would dominate what the model
    learns about malware.
    """
    size = df.groupby("cluster").cluster.transform("size")
    w = 1.0 / np.sqrt(size.to_numpy(dtype=float))
    tr = (split == which).to_numpy()
    y = df.label.to_numpy()
    for cls in (0, 1):
        m = tr & (y == cls)
        if m.any():
            w[m] *= 0.5 * tr.sum() / w[m].sum()
    return w
