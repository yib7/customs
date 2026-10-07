"""Evaluation metrics with uncertainty.

A firewall lives or dies by its false-positive rate: blocking one popular package a week
gets the tool uninstalled. So beyond ROC AUC the headline numbers are recall (detection
rate) at fixed, low false-positive rates, with thresholds picked on the validation split
and then frozen for test.

Confidence intervals use a cluster bootstrap: whole near-duplicate clusters are resampled,
because samples inside a malware campaign are not independent and an ordinary bootstrap
would overstate precision.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score


def threshold_at_fpr(y: np.ndarray, score: np.ndarray, fpr: float) -> float:
    """Smallest threshold whose false-positive rate on ``y == 0`` is at most ``fpr``.

    Decision rule everywhere is ``score >= threshold``.
    """
    neg = np.sort(score[y == 0])[::-1]
    if len(neg) == 0:
        return float("-inf")
    k = int(np.floor(fpr * len(neg)))  # number of negatives allowed above threshold
    if k >= len(neg):
        return float(neg[-1])
    # Strictly above the (k+1)-th highest negative keeps at most k false positives.
    return float(np.nextafter(neg[k], np.inf))


def recall_at_threshold(y: np.ndarray, score: np.ndarray, t: float) -> float:
    pos = score[y == 1]
    return float(np.mean(pos >= t)) if len(pos) else float("nan")


def fpr_at_threshold(y: np.ndarray, score: np.ndarray, t: float) -> float:
    neg = score[y == 0]
    return float(np.mean(neg >= t)) if len(neg) else float("nan")


def brier(y: np.ndarray, p: np.ndarray) -> float:
    return float(np.mean((p - y) ** 2))


def expected_calibration_error(y: np.ndarray, p: np.ndarray, bins: int = 15) -> float:
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    ece = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            ece += m.mean() * abs(p[m].mean() - y[m].mean())
    return float(ece)


def reliability_curve(y: np.ndarray, p: np.ndarray, bins: int = 10) -> list[dict]:
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    out = []
    for b in range(bins):
        m = idx == b
        if m.any():
            out.append(
                {
                    "bin_low": float(edges[b]),
                    "bin_high": float(edges[b + 1]),
                    "mean_pred": float(p[m].mean()),
                    "frac_pos": float(y[m].mean()),
                    "n": int(m.sum()),
                }
            )
    return out


@dataclass
class Summary:
    n_pos: int
    n_neg: int
    roc_auc: float
    pr_auc: float
    recall_at: dict[str, float]  # keyed by the frozen threshold's name
    fpr_at: dict[str, float]

    def as_dict(self) -> dict:
        return {
            "n_pos": self.n_pos,
            "n_neg": self.n_neg,
            "roc_auc": self.roc_auc,
            "pr_auc": self.pr_auc,
            "recall_at": self.recall_at,
            "fpr_at": self.fpr_at,
        }


def summarize(y: np.ndarray, score: np.ndarray, thresholds: dict[str, float]) -> Summary:
    y = np.asarray(y).astype(int)
    score = np.asarray(score, dtype=float)
    both = len(np.unique(y)) == 2
    return Summary(
        n_pos=int(y.sum()),
        n_neg=int((1 - y).sum()),
        roc_auc=float(roc_auc_score(y, score)) if both else float("nan"),
        pr_auc=float(average_precision_score(y, score)) if both else float("nan"),
        recall_at={k: recall_at_threshold(y, score, t) for k, t in thresholds.items()},
        fpr_at={k: fpr_at_threshold(y, score, t) for k, t in thresholds.items()},
    )


def cluster_bootstrap(
    y: np.ndarray,
    score: np.ndarray,
    clusters: np.ndarray,
    stat,
    n_boot: int = 1000,
    seed: int = 0,
    alpha: float = 0.05,
) -> tuple[float, float, float]:
    """Point estimate and percentile CI of ``stat(y, score)`` resampling whole clusters."""
    rng = np.random.default_rng(seed)
    y = np.asarray(y)
    score = np.asarray(score)
    uniq, inv = np.unique(clusters, return_inverse=True)
    members = [np.flatnonzero(inv == i) for i in range(len(uniq))]
    point = stat(y, score)
    vals = []
    for _ in range(n_boot):
        pick = rng.integers(0, len(uniq), len(uniq))
        idx = np.concatenate([members[i] for i in pick])
        yy, ss = y[idx], score[idx]
        if len(np.unique(yy)) < 2:
            continue
        vals.append(stat(yy, ss))
    lo, hi = np.nanpercentile(vals, [100 * alpha / 2, 100 * (1 - alpha / 2)])
    return float(point), float(lo), float(hi)


def paired_bootstrap_diff(
    y: np.ndarray,
    score_a: np.ndarray,
    score_b: np.ndarray,
    clusters: np.ndarray,
    stat,
    n_boot: int = 1000,
    seed: int = 0,
) -> tuple[float, float, float, float]:
    """Difference stat(a) - stat(b) with a cluster-bootstrap CI and a two-sided p-value."""
    rng = np.random.default_rng(seed)
    uniq, inv = np.unique(clusters, return_inverse=True)
    members = [np.flatnonzero(inv == i) for i in range(len(uniq))]
    point = stat(y, score_a) - stat(y, score_b)
    diffs = []
    for _ in range(n_boot):
        pick = rng.integers(0, len(uniq), len(uniq))
        idx = np.concatenate([members[i] for i in pick])
        if len(np.unique(y[idx])) < 2:
            continue
        diffs.append(stat(y[idx], score_a[idx]) - stat(y[idx], score_b[idx]))
    diffs = np.asarray(diffs)
    lo, hi = np.percentile(diffs, [2.5, 97.5])
    p = 2 * min(np.mean(diffs <= 0), np.mean(diffs >= 0))
    return float(point), float(lo), float(hi), float(min(p, 1.0))
