"""Package-name model: is this name likely to belong to a malicious package?

This is the only signal available before an archive is downloaded, and the one that
speaks to typosquatting and slopsquatting. It is a logistic regression over:

* a few structural features of the name,
* typosquat features against the ecosystem's popular-package list (edit distance to the
  nearest popular name, whether the name is popular itself, whether it wraps a popular
  name in extra tokens, like ``requests-toolbelt-pro``),
* hashed character 1- to 4-grams with boundary marks.

Every piece is simple enough to re-implement exactly in Rust. :func:`score_exported` is
the reference implementation; parity fixtures generated from it pin the Rust version.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from rapidfuzz.distance import OSA
from rapidfuzz.process import cdist
from scipy import sparse
from sklearn.linear_model import LogisticRegression

N_BUCKETS = 1 << 16
NGRAM_MIN, NGRAM_MAX = 1, 4
MAX_DIST = 4  # distances are capped: beyond a few edits a name is simply different

NUMERIC = [
    "len",
    "n_digits",
    "n_hyphens",
    "n_underscores",
    "n_dots",
    "has_scope",
    "is_popular",
    "dist1",
    "dist2",
    "dist3",
    "contains_popular_token",
    "digit_suffix",
]


def normalize(ecosystem: str, name: str) -> str:
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def fnv1a32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def ngram_buckets(name: str) -> list[int]:
    s = f"^{name}$"
    out = []
    for n in range(NGRAM_MIN, NGRAM_MAX + 1):
        for i in range(len(s) - n + 1):
            out.append(fnv1a32(s[i : i + n].encode("utf-8")) % N_BUCKETS)
    return out


@dataclass
class Popular:
    names: list[str]
    index: set[str]

    @classmethod
    def from_list(cls, ecosystem: str, names: Sequence[str]) -> Popular:
        norm = [normalize(ecosystem, n) for n in names]
        return cls(norm, set(norm))


def _bare(name: str) -> str:
    """Drop an npm scope for distance and token comparisons."""
    return name.split("/", 1)[1] if name.startswith("@") and "/" in name else name


def numeric_features(names: Sequence[str], pop: Popular) -> np.ndarray:
    """Numeric features for already-normalized names (vectorized edit distances)."""
    bare = [_bare(n) for n in names]
    pop_bare = [_bare(p) for p in pop.names]
    # Distances to every popular name, capped at MAX_DIST + 1; exact matches are excluded
    # from the minimum so a popular package is not "0 edits from itself".
    min_d = np.full(len(names), MAX_DIST + 1)
    chunk = 10_000  # bounds the dense distance matrix to chunk x len(popular)
    for s in range(0, len(bare) if pop_bare else 0, chunk):
        d = cdist(
            bare[s : s + chunk],
            pop_bare,
            scorer=OSA.distance,
            score_cutoff=MAX_DIST,
            workers=-1,
            dtype=np.int32,
        )
        d = np.where(d > MAX_DIST, MAX_DIST + 1, d)
        d[d == 0] = MAX_DIST + 1
        min_d[s : s + chunk] = d.min(axis=1)
    long_pop = {p for p in pop_bare if len(p) >= 4}
    rows = []
    for n, b, md in zip(names, bare, min_d, strict=True):
        toks = [t for t in re.split(r"[-_.]", b) if t]
        rows.append(
            [
                len(b),
                sum(c in "0123456789" for c in b),
                b.count("-"),
                b.count("_"),
                b.count("."),
                float(n.startswith("@")),
                float(n in pop.index),
                float(md == 1),
                float(md == 2),
                float(md == 3),
                float(len(toks) > 1 and b not in long_pop and any(t in long_pop for t in toks)),
                float(b[-1:] in tuple("0123456789")),
            ]
        )
    return np.asarray(rows, dtype=np.float64)


def design_matrix(names: Sequence[str], pop: Popular, mean=None, std=None):
    num = numeric_features(names, pop)
    if mean is None:
        mean, std = num.mean(axis=0), num.std(axis=0) + 1e-9
    num_s = (num - mean) / std
    rows, cols = [], []
    for i, n in enumerate(names):
        for b in set(ngram_buckets(n)):
            rows.append(i)
            cols.append(b)
    grams = sparse.csr_matrix((np.ones(len(rows)), (rows, cols)), shape=(len(names), N_BUCKETS))
    X = sparse.hstack([sparse.csr_matrix(num_s), grams]).tocsr()
    return X, mean, std


def train(names: Sequence[str], y: np.ndarray, pop: Popular, C: float = 0.5):
    X, mean, std = design_matrix(names, pop)
    clf = LogisticRegression(C=C, max_iter=2000, solver="liblinear")
    clf.fit(X, y)
    return clf, mean, std


def export(ecosystem_models: dict, popular_files: dict[str, str]) -> dict:
    """``ecosystem_models`` maps ecosystem to (clf, mean, std)."""

    def b64(a: np.ndarray) -> str:
        return base64.b64encode(np.asarray(a, dtype="<f4").tobytes()).decode("ascii")

    out = {
        "format": "customs-name-lr-v1",
        "numeric_features": NUMERIC,
        "max_distance": MAX_DIST,
        "ngram_min": NGRAM_MIN,
        "ngram_max": NGRAM_MAX,
        "n_buckets": N_BUCKETS,
        "hash": "fnv1a32",
        "ecosystems": {},
    }
    for eco, (clf, mean, std) in ecosystem_models.items():
        w = clf.coef_.ravel()
        out["ecosystems"][eco] = {
            "popular": popular_files[eco],
            "mean": [float(v) for v in mean],
            "std": [float(v) for v in std],
            "numeric_weights": [float(v) for v in w[: len(NUMERIC)]],
            "ngram_weights": b64(w[len(NUMERIC) :]),
            "bias": float(clf.intercept_[0]),
        }
    return out


def score_exported(model: dict, ecosystem: str, name: str, pop: Popular) -> float:
    """Reference logit for one name (mirrors the Rust implementation)."""
    m = model["ecosystems"][ecosystem]
    n = normalize(ecosystem, name)
    num = numeric_features([n], pop)[0]
    z = (num - np.asarray(m["mean"])) / np.asarray(m["std"])
    logit = float(z @ np.asarray(m["numeric_weights"])) + m["bias"]
    w = np.frombuffer(base64.b64decode(m["ngram_weights"]), dtype="<f4")
    for b in set(ngram_buckets(n)):
        logit += float(w[b])
    return logit


def nearest_popular(name: str, pop: Popular) -> tuple[str | None, int]:
    b = _bare(name)
    best, bd = None, MAX_DIST + 1
    for p in pop.names:
        pb = _bare(p)
        if pb == b:
            continue
        d = OSA.distance(b, pb, score_cutoff=MAX_DIST)
        if d < bd:
            best, bd = p, d
    return best, bd


def save(model: dict, path: Path) -> None:
    path.write_text(json.dumps(model, separators=(",", ":")), encoding="utf-8")
