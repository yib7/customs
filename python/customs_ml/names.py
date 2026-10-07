"""Data for the package-name model.

Positives are names from OSSF malicious-package reports. Negatives are names that exist on
the registry and are not reported: for PyPI a uniform sample of the full simple index, for
npm the union of the high-impact list, keyword-search results, and the benign corpus (npm
has no public full-name listing reachable here, so the npm negative set leans toward
packages that search can find; the evaluation reports PyPI and npm separately for that
reason).

Names that appear in the code dataset are held out of name-model training entirely, so the
ensemble that combines name and code scores is never evaluated on names the name model
memorized.
"""

from __future__ import annotations

import itertools
import random
import re
import string
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pandas as pd
import requests

from . import config
from .benign import NPM_SEARCH, PYPI_SIMPLE, TOP_PYPI, normalize

NPM_TOP = "https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js"


def popular_pypi(n: int = 5000) -> list[str]:
    rows = requests.get(TOP_PYPI, timeout=60).json()["rows"]
    return [normalize("pypi", r["project"]) for r in rows[:n]]


def popular_npm(n: int = 5000) -> list[str]:
    js = requests.get(NPM_TOP, timeout=60).text
    return re.findall(r"'([^']+)'", js)[:n]


def pypi_all_names() -> list[str]:
    idx = requests.get(
        PYPI_SIMPLE, headers={"Accept": "application/vnd.pypi.simple.v1+json"}, timeout=180
    ).json()
    return [p["name"] for p in idx["projects"]]


def npm_search_names(queries: list[str], pages: int = 4, workers: int = 8) -> set[str]:
    def run(q: str) -> list[str]:
        out = []
        s = requests.Session()
        for p in range(pages):
            try:
                r = s.get(NPM_SEARCH, params={"text": q, "size": 250, "from": 250 * p}, timeout=30)
                objs = r.json().get("objects", []) if r.ok else []
            except (requests.RequestException, ValueError):
                break
            out += [o["package"]["name"] for o in objs]
            if len(objs) < 250:
                break
        return out

    names: set[str] = set()
    with ThreadPoolExecutor(workers) as ex:
        for res in ex.map(run, queries):
            names.update(res)
    return names


def default_npm_queries(seed: int = 3) -> list[str]:
    two = ["".join(p) for p in itertools.product(string.ascii_lowercase, repeat=2)]
    rng = random.Random(seed)
    rng.shuffle(two)
    return two


def build(n_pypi_neg: int = 250_000, seed: int = 5) -> pd.DataFrame:
    """Assemble (ecosystem, name, label, source) rows and write popular-name lists."""
    rng = random.Random(seed)
    ossf = pd.read_parquet(config.sub("ossf") / "ossf_reports.parquet")
    ossf = ossf[~ossf.withdrawn]
    pos = ossf[["ecosystem", "name", "published"]].dropna(subset=["name"]).copy()
    pos["norm"] = [normalize(e, n) for e, n in zip(pos.ecosystem, pos.name, strict=True)]
    pos = pos.drop_duplicates(["ecosystem", "norm"])
    pos["label"] = 1
    pos["source"] = "ossf"
    bad = set(zip(pos.ecosystem, pos.norm, strict=True))

    pypi_all = pypi_all_names()
    pypi_neg = [
        n
        for n in rng.sample(pypi_all, min(n_pypi_neg, len(pypi_all)))
        if ("pypi", normalize("pypi", n)) not in bad
    ]
    npm_names = npm_search_names(default_npm_queries())
    npm_names |= set(popular_npm(20000))
    # Sorted: set order follows the process's string hash seed, and the name model's
    # training sample is drawn by position from this table.
    npm_neg = [n for n in sorted(npm_names) if ("npm", n.lower()) not in bad]

    neg = pd.DataFrame(
        [("pypi", n, "pypi_index") for n in pypi_neg] + [("npm", n, "npm_search") for n in npm_neg],
        columns=["ecosystem", "name", "source"],
    )
    neg["norm"] = [normalize(e, n) for e, n in zip(neg.ecosystem, neg.name, strict=True)]
    neg = neg.drop_duplicates(["ecosystem", "norm"])
    neg["label"] = 0
    neg["published"] = pd.NaT
    df = pd.concat([pos, neg], ignore_index=True)[
        ["ecosystem", "name", "norm", "label", "source", "published"]
    ]
    out = config.sub("names")
    df.to_parquet(out / "names.parquet")
    (out / "popular_pypi.txt").write_text("\n".join(popular_pypi()) + "\n")
    (out / "popular_npm.txt").write_text("\n".join(popular_npm()) + "\n")
    return df


def load() -> pd.DataFrame:
    return pd.read_parquet(config.sub("names") / "names.parquet")


def popular(ecosystem: str) -> list[str]:
    return Path(config.sub("names") / f"popular_{ecosystem}.txt").read_text().split()
