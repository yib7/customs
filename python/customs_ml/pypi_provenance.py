"""How often ``provenance_dropped`` fires on legitimate PyPI releases.

PyPI's project JSON API does not report PEP 740 attestations, but the JSON simple index
(PEP 691) lists a ``provenance`` URL for every attested file, so one request per project
shows which releases carry provenance. The proxy reads that index
(``crates/customs/src/registry.rs``) and applies the npm rule unchanged: a release with no
attested file whose previous release (the most recently published earlier one, ignoring
prereleases unless the requested version is one) had an attested file.

This module replays the rule on every release from the last year of the most downloaded
PyPI projects, which are all legitimate: the false-alarm cost per release. No malicious
release can be measured the same way, because PyPI removes them and the index with them.

    python -m customs_ml.pypi_provenance [--projects 5000] [--days 365]

Writes ``work/pypi_provenance.json``.
"""

from __future__ import annotations

import argparse
import http.client
import json
import re
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

from packaging.version import InvalidVersion, Version

from . import names
from .pipeline import log, work

SIMPLE = "https://pypi.org/simple/{}/"
ACCEPT = "application/vnd.pypi.simple.v1+json"
ARCHIVE_EXT = (".tar.gz", ".zip", ".whl", ".tar.bz2", ".tgz", ".egg")


def version_of(filename: str) -> str | None:
    """Version in a distribution file name (sdist ``name-1.0.tar.gz``, wheel or egg)."""
    ext = next((e for e in ARCHIVE_EXT if filename.endswith(e)), None)
    if ext is None:
        return None
    base = filename[: -len(ext)]
    if ext in (".whl", ".egg"):
        parts = base.split("-")
        return parts[1] if len(parts) > 1 else None
    m = re.match(r"^(.*?)-(\d[^-]*)$", base)
    return m.group(2) if m else None


def is_prerelease(v: str) -> bool:
    try:
        return Version(v).is_prerelease
    except InvalidVersion:
        return False


def releases(doc: dict) -> dict[str, tuple[str, bool]]:
    """``version -> (first upload time, any file attested)`` from a JSON simple index."""
    out: dict[str, list] = {}
    for f in doc.get("files", []):
        v = version_of(f.get("filename", ""))
        t = f.get("upload-time")
        if not v or not t:
            continue
        r = out.setdefault(v, [t, False])
        r[0] = min(r[0], t)
        r[1] = r[1] or bool(f.get("provenance"))
    return {v: (t, a) for v, (t, a) in out.items()}


def fires(rel: dict[str, tuple[str, bool]], since: str) -> tuple[int, list[tuple[str, str]]]:
    """Releases published since ``since`` that have a previous release, and the
    ``(previous, version)`` pairs on which the rule fires."""
    order = sorted(rel.items(), key=lambda kv: kv[1][0])
    n, hits = 0, []
    for i, (v, (t, attested)) in enumerate(order):
        if t < since:
            continue
        pre = is_prerelease(v)
        prev = next(
            (
                (pv, pa)
                for pv, (pt, pa) in reversed(order[:i])
                if pt < t and (pre or not is_prerelease(pv))
            ),
            None,
        )
        if prev is None:
            continue
        n += 1
        if prev[1] and not attested:
            hits.append((prev[0], v))
    return n, hits


def _fetch(name: str) -> tuple[str, dict | None]:
    req = urllib.request.Request(
        SIMPLE.format(name), headers={"Accept": ACCEPT, "User-Agent": "customs-eval"}
    )
    for _ in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return name, json.load(r)
        except (OSError, ValueError, http.client.HTTPException):
            continue
    return name, None


def run(projects: int = 5000, days: int = 365) -> dict:
    todo = names.popular("pypi")[:projects]
    since = (datetime.now(UTC) - timedelta(days=days)).isoformat()
    with ThreadPoolExecutor(16) as ex:
        docs = dict(ex.map(_fetch, todo))
    n_rel = n_hit = n_attesting = 0
    hit_projects = []
    for name, doc in docs.items():
        if doc is None:
            continue
        rel = releases(doc)
        n_attesting += any(a for _, a in rel.values())
        n, hits = fires(rel, since)
        n_rel += n
        n_hit += len(hits)
        if hits:
            hit_projects.append({"name": name, "pairs": hits})
    fetched = sum(d is not None for d in docs.values())
    res = {
        "date": datetime.now(UTC).date().isoformat(),
        "days": days,
        "projects": fetched,
        "projects_attesting": n_attesting,
        "releases": n_rel,
        "fired": n_hit,
        "fire_rate": n_hit / max(n_rel, 1),
        "projects_fired": len(hit_projects),
        "examples": hit_projects[:50],
    }
    (work() / "pypi_provenance.json").write_text(json.dumps(res, indent=1))
    log(
        f"provenance_dropped on PyPI: {n_hit} of {n_rel} releases"
        f" ({res['fire_rate']:.2%}), {len(hit_projects)} of {fetched} projects"
    )
    return res


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--projects", type=int, default=5000)
    ap.add_argument("--days", type=int, default=365)
    a = ap.parse_args(argv)
    run(a.projects, a.days)


if __name__ == "__main__":
    main()
