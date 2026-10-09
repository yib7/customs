"""Registry status of test malware: is each flagged version still published?

The malware labels come from a collector's own analysis. npm and PyPI remove packages they
confirm as malicious, usually within days (npm leaves a ``0.0.1-security`` placeholder), so
a flagged version that is still served months later was either never confirmed or is a
false positive of the collector. A hand audit of such packages found both: proof-of-concept
and dependency-confusion probes the registry left up, and ordinary releases such as
per-platform prebuilt binaries of open-source projects.

The evaluation reports recall on the two groups separately. ``removed`` is the cleaner
label; ``still_published`` mixes real malware with label noise. The snapshot is fetched
once and stored with its date, so reports are reproducible until it is refreshed:

    python -m customs_ml.registry_status
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from .pipeline import SCHEME, load_table, log, work

PATH_NAME = "registry_status.json"


def _url(eco: str, name: str) -> str:
    if eco == "pypi":
        return f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json"
    return "https://registry.npmjs.org/" + name.replace("/", "%2f")


def _fetch(key: tuple[str, str]) -> tuple[tuple[str, str], dict]:
    eco, name = key
    err = ""
    for _ in range(3):
        try:
            req = urllib.request.Request(_url(eco, name), headers={"User-Agent": "customs-eval"})
            with urllib.request.urlopen(req, timeout=30) as r:
                j = json.load(r)
            if eco == "pypi":
                # A release whose files were all deleted is not installable: count it gone.
                versions = sorted(v for v, files in (j.get("releases") or {}).items() if files)
            else:
                versions = sorted(j.get("versions") or {})
            return key, {"status": 200, "versions": versions}
        except urllib.error.HTTPError as e:
            return key, {"status": e.code, "versions": []}
        except (OSError, ValueError) as e:
            err = str(e)[:80]
    return key, {"status": err or "error", "versions": []}


def classify(version: str, entry: dict | None) -> str | None:
    """``removed``, ``still_published``, or None when the lookup failed."""
    if entry is None:
        return None
    if entry["status"] == 404:
        return "removed"
    if entry["status"] != 200:
        return None
    vs = entry["versions"]
    if vs and all("security" in v for v in vs):
        return "removed"
    return "still_published" if str(version) in vs else "removed"


def load() -> dict | None:
    p = work() / PATH_NAME
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def status_column(df, snapshot: dict) -> list[str | None]:
    st = snapshot["status"]
    return [
        classify(str(v), st.get(f"{e}|{n}"))
        for e, n, v in zip(df.ecosystem, df.name, df.version, strict=True)
    ]


def stage_registry_status(scheme: str = SCHEME, path: Path | None = None) -> dict:
    df = load_table()
    if "augmented" in df:
        df = df[df.augmented.isna()]
    t = df[(df[f"split_{scheme}"] == "test") & (df.label == 1)]
    keys = sorted(set(zip(t.ecosystem, t.name, strict=True)))
    with ThreadPoolExecutor(12) as ex:
        res = dict(ex.map(_fetch, keys))
    snap = {
        "fetched": datetime.now(UTC).isoformat(timespec="seconds"),
        "status": {f"{e}|{n}": v for (e, n), v in res.items()},
    }
    (path or work() / PATH_NAME).write_text(json.dumps(snap), encoding="utf-8")
    cls = status_column(t, snap)
    counts = {c: cls.count(c) for c in ("removed", "still_published", None)}
    log("registry status of test malware:", counts)
    return snap


if __name__ == "__main__":
    stage_registry_status()
