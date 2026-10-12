"""How often the proxy's release history rules fire on compromised and legitimate npm releases.

The rules in ``crates/customs/src/history.rs`` and ``policy.rs`` (``provenance_dropped``,
``install_script_added``, ``publisher_changed``, ``dormant_revival``, ``version_anomaly``,
``nonregistry_dependency_added``, ``young_dependency_added``) compare a requested version
with the releases published before it, using only registry metadata (for
``young_dependency_added``, also the packuments of newly added dependencies, as they are
today). This module replays them in Python on two sets:

* every compromised npm release in the corpus (``kind == "compromised_lib"``). Most of these
  versions were unpublished after the incident, which removes their metadata from the
  packument but keeps their publish time. The malicious release's install scripts and
  dependencies come from the archive's own ``package.json`` (npm derives the packument's
  from it), so ``install_script_added``, the dependency rules, ``dormant_revival`` and
  ``version_anomaly`` are known for every row whose previous release is still listed.
  Provenance and publisher are known only for versions still listed; elsewhere a rule that
  depends on them is *unknown*, and the report gives both bounds;
* every release in the last two years of a sample of the corpus's benign npm packages, which
  are all still listed, so every rule is known: the false-alarm cost per release.

Results are joined with the ensemble's warn verdicts to show what the rules add to the model
on the slice where it is weakest. Archives are read in memory; nothing is installed or run.
Packuments are slimmed and cached under ``work/packuments2``.

    python -m customs_ml.history_eval [--benign 400] [--parity target/release/customs]

Writes ``work/history_eval.json`` and, with ``--parity``, ``work/history_parity.json``: the
replay compared with the proxy's own ``customs check`` on a sample of benign releases.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
import pandas as pd

from .pipeline import SCHEME, load_table, log, work

RULES = (
    "provenance_dropped",
    "install_script_added",
    "publisher_changed",
    "dormant_revival",
    "version_anomaly",
    "nonregistry_dependency_added",
    "young_dependency_added",
)
# Rules on under the default policy (`version_anomaly` defaults to off), and the ones of
# those that block.
DEFAULT_ON = tuple(r for r in RULES if r != "version_anomaly")
BLOCKING = ("install_script_added", "nonregistry_dependency_added", "young_dependency_added")
INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")
RECENT_RELEASES = 5
DORMANT_DAYS = 365
SETTLED_HOURS = 24  # history.rs SETTLED_HOURS
MAX_SCRIPT_CHARS = 512  # registry.rs MAX_SCRIPT_CHARS
MAX_DEPENDENCIES = 400  # registry.rs MAX_DEPENDENCIES
MAX_SPEC_CHARS = 256  # registry.rs MAX_SPEC_CHARS
MAX_PEOPLE = 200  # registry.rs MAX_PEOPLE
YOUNG_DEPENDENCY_DAYS = 7
MAX_ADDED_LOOKUPS = 20  # history.rs MAX_ADDED_LOOKUPS
NONREGISTRY_PREFIXES = (
    "git+",
    "git:",
    "github:",
    "gitlab:",
    "bitbucket:",
    "gist:",
    "http:",
    "https:",
    "file:",
    "link:",
)
REPO_PART = re.compile(r"^[A-Za-z0-9._-]+$")
SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def _time(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _scripts(doc: dict) -> list[list[str]]:
    """``(script, command)`` pairs the way ``registry.rs`` reads them."""
    s = doc.get("scripts") if isinstance(doc.get("scripts"), dict) else {}
    if (
        doc.get("_binding_gyp")
        and doc.get("gypfile") is not False
        and "install" not in s
        and "preinstall" not in s
    ):
        # npm publishes a package with a root binding.gyp and no install hook with
        # `install: node-gyp rebuild` added, which is what the packument then shows.
        s = {**s, "install": "node-gyp rebuild"}
    out = [
        [k, (s[k] if isinstance(s[k], str) else "")[:MAX_SCRIPT_CHARS]]
        for k in INSTALL_SCRIPTS
        if k in s
    ]
    if not out and doc.get("hasInstallScript") is True:
        out.append(["install script", ""])
    return out


def _dependencies(doc: dict) -> list[list[str]]:
    """``(name, spec)`` pairs the way ``registry.rs`` reads them: ``dependencies`` then
    ``optionalDependencies``, names in sorted order, the first entry for a name wins."""
    out: list[list[str]] = []
    seen = set()
    for key in ("dependencies", "optionalDependencies"):
        d = doc.get(key)
        if not isinstance(d, dict):
            continue
        for name in sorted(d):
            if len(out) >= MAX_DEPENDENCIES:
                return out
            if name in seen:
                continue
            seen.add(name)
            spec = d[name] if isinstance(d[name], str) else ""
            out.append([name, spec[:MAX_SPEC_CHARS]])
    return out


def is_nonregistry_spec(spec: str) -> bool:
    """Mirror of ``history::is_nonregistry_spec``: git, URL, file and GitHub shorthand."""
    s = spec.strip()
    if s.startswith(NONREGISTRY_PREFIXES):
        return True
    parts = s.split("#", 1)[0].split("/")
    return (
        len(parts) == 2 and all(REPO_PART.match(x) for x in parts) and not parts[0].startswith("@")
    )


def slim(doc: dict) -> dict:
    """Keep only the packument fields the history rules read."""
    versions = {}
    for v, m in (doc.get("versions") or {}).items():
        if not isinstance(m, dict):
            continue
        user = (
            (m.get("_npmUser") or {}).get("name") if isinstance(m.get("_npmUser"), dict) else None
        )
        versions[v] = {
            "attested": bool((m.get("dist") or {}).get("attestations")),
            "publisher": user or None,
            "install": _scripts(m),
            "deps": _dependencies(m),
        }
    # A fully unpublished package has `time.unpublished`, an object, beside the versions.
    times = {
        k: v
        for k, v in (doc.get("time") or {}).items()
        if isinstance(v, str) and k not in ("created", "modified")
    }
    # Maintainers, then every version's publisher (versions in sorted order, as serde_json
    # keeps them), deduplicated: who already ships code in this package.
    people: list[str] = []
    maint = doc.get("maintainers") if isinstance(doc.get("maintainers"), list) else []
    names = [m.get("name") for m in maint if isinstance(m, dict)]
    names += [versions[v]["publisher"] for v in sorted(versions)]
    for n in names:
        if len(people) >= MAX_PEOPLE:
            break
        if isinstance(n, str) and n and n not in people:
            people.append(n)
    created = (doc.get("time") or {}).get("created")
    return {
        "time": times,
        "versions": versions,
        "created": created if isinstance(created, str) else None,
        "people": people,
    }


def fetch(name: str, cache: Path) -> dict:
    """The slimmed packument, ``{"missing": True}`` when the registry answers 404, or ``{}``
    when the request failed (not cached, so a later run retries)."""
    path = cache / (hashlib.sha1(name.encode()).hexdigest() + ".json")
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    url = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@")
    try:
        with urllib.request.urlopen(url, timeout=120) as r:
            doc = slim(json.load(r))
    except urllib.error.HTTPError as e:
        if e.code != 404:
            return {}
        doc = {"missing": True}
    except OSError, ValueError:
        return {}
    path.write_text(json.dumps(doc), encoding="utf-8")
    return doc


def packument(name: str, cache: Path) -> dict | None:
    doc = fetch(name, cache)
    return None if not doc or doc.get("missing") else doc


def archive_package_json(path: str) -> dict | None:
    """``package/package.json`` from an npm tarball, read in memory."""
    try:
        with tarfile.open(path) as t:
            members = [m for m in t.getmembers() if m.isfile() and m.name.count("/") == 1]
            pj = next((m for m in members if m.name.endswith("/package.json")), None)
            if pj is None or pj.size > 4 << 20:
                return None
            doc = json.loads(t.extractfile(pj).read())
            if not isinstance(doc, dict):
                return None
            root = pj.name.rsplit("/", 1)[0]
            doc["_binding_gyp"] = any(m.name == f"{root}/binding.gyp" for m in members)
            return doc
    except OSError, tarfile.TarError, ValueError, EOFError, AttributeError:
        return None


def archive_scripts(path: str) -> list[list[str]] | None:
    """Install scripts from an npm tarball's ``package.json``."""
    doc = archive_package_json(path)
    return None if doc is None else _scripts(doc)


def _semver(v: str):
    m = SEMVER.match(v)
    if not m:
        return None
    pre = m.group(4)
    # Order like semver: a prerelease sorts below its release; identifiers compare
    # numerically when both are numbers.
    pre_key = (
        (1,)
        if pre is None
        else (0, *[(0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split(".")])
    )
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), pre_key)


def is_pre(v: str) -> bool:
    s = _semver(v)
    return s[3] != (1,) if s else "-" in v


def _earlier(meta: dict, version: str) -> list[tuple[datetime, str]]:
    """Releases published strictly before ``version``, newest first. Prereleases count
    only when ``version`` is one."""
    times = meta["time"]
    t0 = _time(times[version])
    pre = is_pre(version)
    return sorted(
        (
            (_time(times[v]), v)
            for v in times
            if v != version and _time(times[v]) < t0 and (pre or not is_pre(v))
        ),
        reverse=True,
    )


def added_dependencies(meta: dict, name: str, cur: dict, prev: dict) -> list[str]:
    """Registry dependencies of ``cur`` missing from ``prev`` by name, sorted
    (``ReleaseHistory::added_dependencies``)."""
    before = {n for n, _ in prev["deps"]}
    return sorted(
        n
        for n, spec in cur["deps"]
        if n != name and not is_nonregistry_spec(spec) and n not in before
    )


def young_dependencies(
    meta: dict,
    version: str,
    added: list[str],
    lookup: Callable[[str], dict],
    days: int = YOUNG_DEPENDENCY_DAYS,
) -> tuple[list[tuple[str, str]], bool]:
    """``young_dependency_added`` for the first ``MAX_ADDED_LOOKUPS`` added dependencies:
    the ones that fire with why, and whether any lookup failed."""
    t0 = _time(meta["time"][version])
    own = set(meta.get("people") or [])
    hits, failed = [], False
    for d in added[:MAX_ADDED_LOOKUPS]:
        info = lookup(d)
        if not info:
            failed = True
        elif info.get("missing"):
            hits.append((d, "missing"))
        elif own & set(info.get("people") or []):
            continue
        elif info.get("created") and t0 - _time(info["created"]) < timedelta(days=days):
            hits.append((d, "young"))
    return hits, failed


def _settled(earlier: list[tuple[datetime, str]], t0: datetime) -> str | None:
    """The newest earlier release at least ``SETTLED_HOURS`` older than ``t0``."""
    return next((v for t, v in earlier if t0 - t >= timedelta(hours=SETTLED_HOURS)), None)


def _any3(vals) -> bool | None:
    """True when any value is True, else None when any is unknown, else False."""
    vals = list(vals)
    return True if True in vals else (None if None in vals else False)


def _added_union(meta: dict, name: str, cur: dict, bases: list) -> tuple[list[str], bool]:
    """Registry dependencies of ``cur`` missing from any known base, and whether every base
    and ``cur``'s own dependencies are known."""
    if cur.get("deps") is None:
        return [], False
    added = sorted(
        {d for b in bases if b is not None for d in added_dependencies(meta, name, cur, b)}
    )
    return added, all(b is not None for b in bases)


def _install_change(cur: list | None, base: dict | None) -> bool | None:
    """Whether an install script of ``cur`` is new or changed since ``base``'s."""
    if cur is None or (base is None and cur):
        return None
    if base is None:
        return False
    before = dict(map(tuple, base["install"]))
    for script, cmd in cur:
        if script in before:
            b = before[script]
            if b and cmd and b != cmd:
                return True
        elif not (cmd == "" and base["install"]):
            return True
    return False


def history_rules(
    meta: dict,
    version: str,
    current: dict | None = None,
    dormant_days: int = DORMANT_DAYS,
    lookup: Callable[[str], dict] | None = None,
    name: str = "",
) -> dict | None:
    """Which rules fire for ``version``: True, False, or None when the inputs are unknown.

    ``current`` overrides the release's own facts (``attested``, ``install`` and ``deps``
    possibly None, ``publisher_unknown`` set) for versions no longer listed. Earlier
    releases are the other versions with a strictly earlier publish time, including
    unpublished ones, since those were live when the requested version appeared; their
    unknown facts stay unknown. ``lookup`` fetches an added dependency's packument (see
    ``fetch``); without it ``young_dependency_added`` is unknown whenever a dependency was
    added. ``name`` is the package's own name, which never counts as an added dependency.
    """
    times = meta["time"]
    if version not in times:
        return None
    t0 = _time(times[version])
    cur = current or meta["versions"].get(version)
    if cur is None:
        return None
    earlier = _earlier(meta, version)
    facts = lambda v: meta["versions"].get(v)  # noqa: E731
    out = dict.fromkeys(RULES, False)
    if earlier:
        pt, pv = earlier[0]
        prev = facts(pv)
        # provenance_dropped
        if prev is None:
            out["provenance_dropped"] = None
        elif prev["attested"]:
            out["provenance_dropped"] = None if cur["attested"] is None else not cur["attested"]
        # install_script_added and the dependency rules compare with the previous release
        # and, when it is a different one, the newest release at least SETTLED_HOURS older.
        bases = [pv]
        settled = _settled(earlier, t0)
        if settled is not None and settled != pv:
            bases.append(settled)
        out["install_script_added"] = _any3(
            _install_change(cur["install"], facts(b)) for b in bases
        )
        deps = cur.get("deps")
        out["nonregistry_dependency_added"] = _any3(
            None
            if deps is None or facts(b) is None
            else any(
                is_nonregistry_spec(spec) and dict(map(tuple, facts(b)["deps"])).get(n) != spec
                for n, spec in deps
            )
            for b in bases
        )
        added, known = _added_union(meta, name, cur, [facts(b) for b in bases])
        if added and lookup is None:
            out["young_dependency_added"] = None
        else:
            hits, failed = (
                young_dependencies(meta, version, added, lookup) if added else ([], False)
            )
            out["young_dependency_added"] = (
                True if hits else (None if failed or not known else False)
            )
        # dormant_revival
        out["dormant_revival"] = (t0 - pt) > timedelta(days=dormant_days)
    # publisher_changed: the publishers of the five most recent earlier releases.
    recent = [facts(v) for _, v in earlier[:RECENT_RELEASES]]
    pubs = {f["publisher"] for f in recent if f and f["publisher"]}
    unknown_recent = any(f is None for f in recent)
    if cur.get("publisher_unknown"):
        out["publisher_changed"] = None if pubs or unknown_recent else False
    elif cur["publisher"]:
        if pubs and cur["publisher"] not in pubs:
            out["publisher_changed"] = None if unknown_recent else True
        elif not pubs and unknown_recent:
            out["publisher_changed"] = None
    # version_anomaly
    sv = _semver(version)
    prior = [(v, _semver(v), t) for t, v in earlier if _semver(v)]
    if sv and prior:
        _, hs, _ = max(prior, key=lambda x: x[1])
        if sv[0] > hs[0] + 1:
            out["version_anomaly"] = True
        elif sv[0] < hs[0]:
            line = [t for _, s, t in prior if s[0] == sv[0]]
            out["version_anomaly"] = not line or (t0 - max(line)) > timedelta(days=dormant_days)
    return out


def _rates(rows: list[dict], rules=RULES) -> dict:
    """Fire rate per rule, with unknowns counted as not firing (low) and firing (high)."""
    out = {}
    n = len(rows)
    for r in (*rules, "any_default"):
        vals = [
            (
                any(x[k] is True for k in DEFAULT_ON),
                any(x[k] is not False for k in DEFAULT_ON),
            )
            if r == "any_default"
            else (x[r] is True, x[r] is not False)
            for x in rows
        ]
        lo = sum(a for a, _ in vals)
        hi = sum(b for _, b in vals)
        out[r] = {"fired": lo, "unknown": hi - lo, "low": lo / max(n, 1), "high": hi / max(n, 1)}
    return out


def compromised(df: pd.DataFrame, cache: Path, thr: dict, scheme: str) -> dict:
    rows = df[(df.ecosystem == "npm") & (df.kind == "compromised_lib")]
    rows = rows.sort_values(f"ens_risk_{scheme}", ascending=False).drop_duplicates(
        ["name", "version"]
    )
    names = sorted(set(rows.name))
    with ThreadPoolExecutor(8) as ex:
        metas = dict(zip(names, ex.map(lambda n: packument(n, cache), names), strict=True))
    todo = []
    for r in rows.itertuples():
        meta = metas.get(r.name)
        if not meta or r.version not in meta["time"]:
            continue
        listed = meta["versions"].get(r.version)
        pj = archive_package_json(r.canonical_path)
        # The archive is what was installed; prefer its scripts and dependencies.
        arch = {} if pj is None else {"install": _scripts(pj), "deps": _dependencies(pj)}
        cur = (
            dict(listed)
            if listed is not None
            else {
                "attested": None,
                "publisher": None,
                "publisher_unknown": True,
                "install": None,
                "deps": None,
            }
        )
        cur.update({k: v for k, v in arch.items() if v or listed is None})
        todo.append((r, meta, listed, cur))
    lookup = _prefetching_lookup(cache, [(t[1], str(t[0].version), t[3], t[0].name) for t in todo])
    res = []
    for r, meta, listed, cur in todo:
        v = str(r.version)
        hits = history_rules(meta, v, cur, lookup=lookup, name=r.name)
        earlier = _earlier(meta, v)
        if hits is None or not earlier:
            continue
        prev_facts = meta["versions"].get(earlier[0][1])
        bases = {earlier[0][1], _settled(earlier, _time(meta["time"][v]))} - {None}
        added, _ = _added_union(meta, r.name, cur, [meta["versions"].get(b) for b in bases])
        young = young_dependencies(meta, v, added, lookup)[0] if added else []
        res.append(
            {
                "name": r.name,
                "version": v,
                "split": getattr(r, f"split_{scheme}"),
                "listed": listed is not None,
                "attested": cur["attested"],
                "prev_attested": prev_facts["attested"] if prev_facts else None,
                "model_warn": bool(getattr(r, f"ens_risk_{scheme}") >= thr["warn"]),
                "model_block": bool(getattr(r, f"ens_risk_{scheme}") >= thr["block"]),
                # Dependencies behind `young_dependency_added`; "missing" ones were usually
                # removed after the incident, so at the time they existed (and were young).
                "young_dependencies": young,
                **hits,
            }
        )
    return {"rows": res, "n_names": len(names), "n_without_history": int(len(rows) - len(res))}


def _prefetching_lookup(cache: Path, items: list[tuple[dict, str, dict | None, str]]):
    """A dependency lookup for ``history_rules`` with every packument it will ask for
    fetched first, in parallel. ``items`` are ``(meta, version, current, name)``."""
    wanted: set[str] = set()

    def record(d: str) -> dict:
        wanted.add(d)
        return {}

    for meta, v, cur, name in items:
        history_rules(meta, v, cur, lookup=record, name=name)
    with ThreadPoolExecutor(8) as ex:
        docs = dict(
            zip(sorted(wanted), ex.map(lambda d: fetch(d, cache), sorted(wanted)), strict=True)
        )
    return lambda d: docs[d] if d in docs else fetch(d, cache)


def benign(df: pd.DataFrame, cache: Path, n: int, years: float, seed: int) -> list[dict]:
    names = df[(df.ecosystem == "npm") & (df.label == 0)].drop_duplicates("name")
    names = names.sample(min(n, len(names)), random_state=seed)
    with ThreadPoolExecutor(8) as ex:
        metas = dict(
            zip(names.name, ex.map(lambda x: packument(x, cache), names.name), strict=True)
        )
    cut = datetime.now(UTC) - timedelta(days=365 * years)
    todo = [
        (metas[name], v, None, name, tier)
        for name, tier in zip(names.name, names.tier, strict=True)
        if metas.get(name)
        for v, ts in metas[name]["time"].items()
        if v in metas[name]["versions"] and _time(ts) >= cut
    ]
    lookup = _prefetching_lookup(cache, [t[:4] for t in todo])
    out = []
    for meta, v, _, name, tier in todo:
        hits = history_rules(meta, v, lookup=lookup, name=name)
        if hits is not None:
            out.append({"name": name, "tier": tier, "version": v, **hits})
    return out


MIN_FAMILY = 3


def family(name: str) -> str:
    """A package family for grouping a takeover wave: the npm scope (``@scope/*``), else
    the name up to its first hyphen (``autotel-*``), else the name itself."""
    if name.startswith("@") and "/" in name:
        return name.split("/", 1)[0] + "/*"
    return name.split("-", 1)[0] + "-*" if "-" in name else name


def summarize(comp: dict, ben: list[dict]) -> dict:
    rows = comp["rows"]
    out: dict = {
        "compromised": {
            "n_releases": len(rows),
            "n_listed": sum(r["listed"] for r in rows),
            # Releases still listed whose previous release carried provenance, and how many
            # of those carry it themselves (published from the project's own CI).
            "listed_after_attested": sum(r["listed"] and r["prev_attested"] is True for r in rows),
            "listed_after_attested_still_attested": sum(
                r["listed"] and r["prev_attested"] is True and r["attested"] is True for r in rows
            ),
            "n_names": comp["n_names"],
            "n_without_history": comp["n_without_history"],
            "rules": _rates(rows),
        }
    }
    for sp in ("test", "all"):
        sub = [r for r in rows if sp == "all" or r["split"] == sp]
        if not sub:
            continue
        mw = np.array([r["model_warn"] for r in sub])
        lo = np.array([any(r[k] is True for k in DEFAULT_ON) for r in sub])
        hi = np.array([any(r[k] is not False for k in DEFAULT_ON) for r in sub])
        missed = ~mw
        mb = np.array([r["model_block"] for r in sub])
        isa_lo = np.array([r["install_script_added"] is True for r in sub])
        isa_hi = np.array([r["install_script_added"] is not False for r in sub])
        blk_lo = np.array([any(r[k] is True for k in BLOCKING) for r in sub])
        blk_hi = np.array([any(r[k] is not False for k in BLOCKING) for r in sub])
        dep = np.array([any(r[k] is True for k in BLOCKING[1:]) for r in sub])
        dep_strict = np.array(
            [
                r["nonregistry_dependency_added"] is True
                or any(why == "young" for _, why in r["young_dependencies"])
                for r in sub
            ]
        )
        out["compromised"][f"union_{sp}"] = {
            "n": len(sub),
            "model_warn": float(mw.mean()),
            "model_or_rules_low": float((mw | lo).mean()),
            "model_or_rules_high": float((mw | hi).mean()),
            # Blocks under the default policy: the model's block verdict or a blocking
            # `install_script_added` hit.
            "model_block": float(mb.mean()),
            "block_with_install_rule_low": float((mb | isa_lo).mean()),
            "block_with_install_rule_high": float((mb | isa_hi).mean()),
            # Blocks under the default policy now: the model or any blocking rule.
            "block_with_rules_low": float((mb | blk_lo).mean()),
            "block_with_rules_high": float((mb | blk_hi).mean()),
            # Releases the model does not warn on caught by a dependency rule; "strict" leaves
            # out those resting only on dependencies that are gone from the registry today.
            "dependency_rules_on_missed": int((~mw & dep).sum()),
            "dependency_rules_on_missed_strict": int((~mw & dep_strict).sum()),
            "missed_by_model": int(missed.sum()),
            "rules_on_missed": _rates([r for r, m in zip(sub, missed, strict=True) if m]),
        }
    test = [r for r in rows if r["split"] == "test"]
    fams: dict[str, list[dict]] = {}
    for r in test:
        fams.setdefault(family(r["name"]), []).append(r)
    out["compromised"]["families_test"] = sorted(
        (
            {
                "family": f,
                "n": len(g),
                "packages": len({r["name"] for r in g}),
                "model_block": sum(bool(r["model_block"]) for r in g),
                "rules_block": sum(any(r[k] is True for k in BLOCKING) for r in g),
                "block_with_rules": sum(
                    bool(r["model_block"]) or any(r[k] is True for k in BLOCKING) for r in g
                ),
            }
            for f, g in fams.items()
            if len(g) >= MIN_FAMILY
        ),
        key=lambda x: (-x["n"], x["family"]),
    )
    pkgs = {r["name"] for r in ben}
    by_pkg = pd.DataFrame(ben)
    out["benign"] = {
        "n_packages": len(pkgs),
        "n_releases": len(ben),
        "rules": _rates(ben),
        "packages_with_alarm": {
            k: float(by_pkg.groupby("name")[k].any().mean()) if len(by_pkg) else 0.0 for k in RULES
        },
        "by_tier": {
            str(t): {
                "n_releases": len(g),
                "any_default": float(g[list(DEFAULT_ON)].any(axis=1).mean()),
            }
            for t, g in by_pkg.groupby("tier")
        }
        if len(by_pkg)
        else {},
    }
    return out


def run(n_benign: int = 400, years: float = 2.0, seed: int = 5, scheme: str = SCHEME) -> dict:
    df = load_table()
    if "augmented" in df:
        df = df[df.augmented.isna()]
    if "source" in df:
        df = df[df.source.isna()]
    cache = work() / "packuments2"
    cache.mkdir(exist_ok=True)
    thr = json.loads((work() / f"ensemble_{scheme}.json").read_text(encoding="utf-8"))["thresholds"]
    comp = compromised(df, cache, thr, scheme)
    ben = benign(df, cache, n_benign, years, seed)
    res = summarize(comp, ben)
    res["benign_window_years"] = years
    (work() / "history_eval.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
    (work() / "history_eval_rows.json").write_text(
        json.dumps({"compromised": comp["rows"], "benign": ben}), encoding="utf-8"
    )
    log(
        "history_eval",
        res["compromised"]["rules"]["any_default"],
        res["benign"]["rules"]["any_default"],
    )
    return res


def parity(binary: Path, models: Path, per_rule: int = 20, quiet: int = 30, seed: int = 1) -> dict:
    """Check this replay against the proxy itself on benign releases still listed.

    Runs ``customs check --json`` in process (every history rule at ``warn``, no age rule)
    on releases where each rule fired here, plus releases where none did, and compares the
    rules it reports with the replay's.
    """
    rows = pd.DataFrame(
        json.loads((work() / "history_eval_rows.json").read_text(encoding="utf-8"))["benign"]
    )
    known = rows[list(RULES)].map(lambda v: v is not None).all(axis=1)
    rows = rows[known]
    picks = []
    for k in RULES:
        hit = rows[rows[k] == True]  # noqa: E712
        picks.append(hit.sample(min(per_rule, len(hit)), random_state=seed))
    none = rows[~rows[list(RULES)].astype(bool).any(axis=1)]
    picks.append(none.sample(min(quiet, len(none)), random_state=seed))
    sample = pd.concat(picks).drop_duplicates(["name", "version"])
    tmp = Path(tempfile.mkdtemp(prefix="customs-parity-"))
    policy = tmp / "policy.toml"
    policy.write_text(
        'min_age_days = 0\nprovenance_dropped = "warn"\ninstall_script_added = "warn"\n'
        'publisher_changed = "warn"\ndormant_revival = "warn"\nversion_anomaly = "warn"\n'
        'nonregistry_dependency_added = "warn"\nyoung_dependency_added = "warn"\n'
        # Historical releases: replay the rules as they applied at publication.
        "history_window_days = 0\n",
        encoding="utf-8",
    )

    def check(r) -> list[str] | None:
        cmd = [str(binary), "check", "--json", "--server", "http://127.0.0.1:9"]
        cmd += ["--config", str(policy), "--models", str(models), "--data-dir", str(tmp)]
        try:
            p = subprocess.run(
                [*cmd, "npm", f"{r.name}@{r.version}"],
                capture_output=True,
                text=True,
                timeout=300,
                encoding="utf-8",
            )
        except subprocess.TimeoutExpired:
            return None  # no verdict, like unparsable output
        try:
            hits = json.loads(p.stdout).get("policy_hits", [])
        except ValueError:
            return None
        return sorted({h["rule"] for h in hits if h["rule"] in RULES})

    try:
        with ThreadPoolExecutor(4) as ex:
            got = list(ex.map(check, sample.itertuples()))
    finally:
        # Every checked package's archive lands here: 100 MB or more per run.
        shutil.rmtree(tmp, ignore_errors=True)
    out = {"checked": 0, "agree": 0, "disagree": []}
    for r, g in zip(sample.itertuples(), got, strict=True):
        if g is None:
            continue
        mine = sorted(k for k in RULES if getattr(r, k) is True)
        out["checked"] += 1
        if mine == g:
            out["agree"] += 1
        else:
            out["disagree"].append(
                {"name": r.name, "version": r.version, "replay": mine, "proxy": g}
            )
    (work() / "history_parity.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--benign", type=int, default=400)
    ap.add_argument("--years", type=float, default=2.0)
    ap.add_argument(
        "--parity",
        metavar="CUSTOMS_BINARY",
        help="after the replay, compare it with `customs check` from this binary",
    )
    args = ap.parse_args()
    print(json.dumps(run(args.benign, args.years), indent=1))
    if args.parity:
        root = Path(__file__).resolve().parents[2]
        print(json.dumps(parity(Path(args.parity), root / "models"), indent=1))
