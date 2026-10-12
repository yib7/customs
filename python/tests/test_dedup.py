import random
from collections.abc import Sequence

import numpy as np

from customs_ml import dedup


def estimated_jaccard(a: Sequence[str], b: Sequence[str]) -> float:
    """Share of equal MinHash signature slots: the Jaccard estimate ``cluster`` relies on."""
    vocab: dict[str, int] = {}
    mh = dedup.MinHasher()
    sa = mh.signature(dedup.shingles(dedup._token_ids(a, vocab)))
    sb = mh.signature(dedup.shingles(dedup._token_ids(b, vocab)))
    return float(np.mean(sa == sb))


def _doc(rng: random.Random, n: int) -> list[str]:
    return [
        rng.choice(["os", "system", "(", ")", "<str>", "import", "requests", "get", "x", "y"])
        + str(rng.randint(0, 50))
        for _ in range(n)
    ]


def test_identical_and_near_duplicates_cluster_together():
    rng = random.Random(0)
    base = _doc(rng, 400)
    near = list(base)
    for i in range(0, 400, 80):  # five single-token edits
        near[i] = "edited"
    other = _doc(rng, 400)
    labels = dedup.cluster([base, list(base), near, other])
    assert labels[0] == labels[1] == labels[2]
    assert labels[3] != labels[0]


def test_jaccard_estimate_is_close():
    rng = random.Random(1)
    a = _doc(rng, 600)
    assert estimated_jaccard(a, a) == 1.0
    assert estimated_jaccard(a, _doc(rng, 600)) < 0.2


def test_short_and_empty_docs():
    labels = dedup.cluster([[], [], ["a"], ["a", "b"]])
    assert len(labels) == 4


def test_empty_docs_stay_singletons_and_short_exact_copies_merge():
    labels = dedup.cluster([[], [], ["a", "b"], ["a", "b"], ["a", "c"]])
    assert labels[0] != labels[1]
    assert labels[2] == labels[3] != labels[4]
