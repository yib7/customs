"""Near-duplicate clustering with MinHash and locality-sensitive hashing.

Malware campaigns publish hundreds of near-identical packages (the same payload under
different names). If copies of one campaign land in both train and test, the test score
measures memorization. Clusters computed here become the grouping unit for every split.

Documents are install-surface token streams from the scanner. Shingles are token 5-grams,
hashed to 64-bit integers; MinHash signatures use 128 universal hash functions; LSH uses
16 bands of 8 rows, which puts the 50% detection point near Jaccard 0.71. Candidate pairs
are confirmed with the signature-estimated Jaccard before union-find merges them.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence

import numpy as np

N_PERM = 128
BANDS = 16
ROWS = N_PERM // BANDS
SHINGLE = 5
THRESHOLD = 0.7
_MERSENNE = np.uint64((1 << 61) - 1)


def _token_ids(tokens: Sequence[str], vocab: dict[str, int]) -> np.ndarray:
    out = np.empty(len(tokens), dtype=np.uint64)
    for i, t in enumerate(tokens):
        j = vocab.get(t)
        if j is None:
            j = vocab[t] = len(vocab) + 1
        out[i] = j
    return out


def shingles(ids: np.ndarray, k: int = SHINGLE) -> np.ndarray:
    """64-bit hashes of every k-gram, via a polynomial rolling combination."""
    if len(ids) == 0:
        return np.zeros(1, dtype=np.uint64)
    if len(ids) < k:
        k = len(ids)
    n = len(ids) - k + 1
    h = np.zeros(n, dtype=np.uint64)
    base = np.uint64(1_000_003)
    with np.errstate(over="ignore"):
        for j in range(k):
            h = h * base + ids[j : j + n]
        # Final avalanche (splitmix64) so nearby ids do not give correlated hashes.
        h ^= h >> np.uint64(30)
        h *= np.uint64(0xBF58476D1CE4E5B9)
        h ^= h >> np.uint64(27)
        h *= np.uint64(0x94D049BB133111EB)
        h ^= h >> np.uint64(31)
    return np.unique(h)


class MinHasher:
    def __init__(self, n_perm: int = N_PERM, seed: int = 1):
        rng = np.random.default_rng(seed)
        self.a = rng.integers(1, int(_MERSENNE), n_perm, dtype=np.uint64)
        self.b = rng.integers(0, int(_MERSENNE), n_perm, dtype=np.uint64)

    def signature(self, sh: np.ndarray) -> np.ndarray:
        # (a * x + b) mod p over 64-bit values: reduce x first so the product fits the
        # 61-bit Mersenne field approximately; exact universality is not needed here.
        x = (sh % _MERSENNE)[:, None]
        with np.errstate(over="ignore"):
            v = (
                self.a[None, :] * (x >> np.uint64(32))
                + self.a[None, :] * (x & np.uint64(0xFFFFFFFF))
                + self.b[None, :]
            ) % _MERSENNE
        return v.min(axis=0)


class UnionFind:
    def __init__(self, n: int):
        self.p = list(range(n))

    def find(self, x: int) -> int:
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)


MIN_LSH_TOKENS = 4 * SHINGLE


def cluster(docs: Sequence[Sequence[str]], threshold: float = THRESHOLD) -> np.ndarray:
    """Return a cluster id per document (ids are the smallest member index).

    Documents too short for meaningful shingling are grouped only with exact copies, and
    empty documents stay singletons: "no install-time code" is common and says nothing
    about shared origin.
    """
    vocab: dict[str, int] = {}
    mh = MinHasher()
    uf = UnionFind(len(docs))
    long_idx = [i for i, d in enumerate(docs) if len(d) >= MIN_LSH_TOKENS]
    exact: dict[tuple, int] = {}
    for i, d in enumerate(docs):
        if 0 < len(d) < MIN_LSH_TOKENS:
            key = tuple(d)
            if key in exact:
                uf.union(exact[key], i)
            else:
                exact[key] = i
    if not long_idx:
        return np.array([uf.find(i) for i in range(len(docs))])
    sigs = np.zeros((len(docs), N_PERM), dtype=np.uint64)
    for i in long_idx:
        sigs[i] = mh.signature(shingles(_token_ids(docs[i], vocab)))
    for band in range(BANDS):
        buckets: dict[bytes, list[int]] = defaultdict(list)
        block = sigs[:, band * ROWS : (band + 1) * ROWS]
        for i in long_idx:
            buckets[block[i].tobytes()].append(i)
        for members in buckets.values():
            if len(members) < 2:
                continue
            first = members[0]
            for other in members[1:]:
                if uf.find(first) == uf.find(other):
                    continue
                if np.mean(sigs[first] == sigs[other]) >= threshold:
                    uf.union(first, other)
    return np.array([uf.find(i) for i in range(len(docs))])


def estimated_jaccard(a: Sequence[str], b: Sequence[str]) -> float:
    vocab: dict[str, int] = {}
    mh = MinHasher()
    sa = mh.signature(shingles(_token_ids(a, vocab)))
    sb = mh.signature(shingles(_token_ids(b, vocab)))
    return float(np.mean(sa == sb))
