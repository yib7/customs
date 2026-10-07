"""Release diff: score what changed since a package's previous release.

The single-archive model is weakest on compromised releases of real libraries (an attacker
with a stolen token publishes a new version of a popular package with a payload added).
There, a few hundred bytes of payload sit inside thousands of lines of legitimate library
code, and package-level counts are diluted. A maintainer never ships a whole package; they
ship a change. This module builds the *delta* between a release and the one before it and
trains a model on that.

Delta construction (mirrored exactly by the Rust firewall, see ``crates/customs/src/diff.rs``):

* Files new in this release are included whole.
* Files whose bytes changed contribute only their *new lines*: lines of the new file left
  over after removing, as a multiset, every line of the old file. Binary files (a NUL in
  the first 8 KiB) are included whole.
* Root manifests (``package.json``, ``setup.py``, ``setup.cfg``, ``pyproject.toml``,
  ``PKG-INFO``, and a wheel's ``*.dist-info/METADATA``) are always included whole so the
  scanner can still tell which files run at install time.
* Unchanged and removed files are dropped.

Training data. There are only a few hundred real compromised releases, far too few to train
on and the only real test there is, so the training positives are *synthetic compromises*:
a real benign release pair from the training split with the payload of a real malicious
package from the training split injected the way real compromises did it (a new file run
from a ``postinstall`` script, code appended to the main entry point or ``setup.py``, a new
module imported from ``__init__.py``). The real compromised releases are held out entirely
and only used to evaluate, against benign release pairs from the test split.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np
import pandas as pd

from . import config
from .malicious import MANIFESTS, canonicalize, read_any, read_tar_tree, strip_common_root

Files = dict[str, bytes]
UA = {"User-Agent": "customs-research (package firewall dataset builder)"}
NPM = "https://registry.npmjs.org"
PYPI = "https://pypi.org/pypi"
MAX_PREV_BYTES = 64 * 1024 * 1024
MAX_PAYLOAD = 256 * 1024


# ------------------------------------------------------------------ versions

_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def semver_key(v: str):
    """Sort key following semver precedence; ``None`` for strings that are not semver."""
    m = _SEMVER.match(v.strip())
    if not m:
        return None
    major, minor, patch, pre = int(m[1]), int(m[2]), int(m[3]), m[4]
    if pre is None:
        return (major, minor, patch, 1, ())
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (major, minor, patch, 0, ids)


def pep440_key(v: str):
    from packaging.version import InvalidVersion, Version

    try:
        return Version(v)
    except InvalidVersion:
        return None


def is_prerelease(eco: str, v: str) -> bool:
    if eco == "npm":
        k = semver_key(v)
        return k is not None and k[3] == 0
    k = pep440_key(v)
    return k is not None and (k.is_prerelease or k.is_devrelease)


def previous_version(eco: str, version: str, candidates: list[str]) -> str | None:
    """The highest candidate below ``version``; prereleases only for a prerelease."""
    key = semver_key if eco == "npm" else pep440_key
    cur = key(version)
    if cur is None:
        return None
    allow_pre = is_prerelease(eco, version)
    best, best_k = None, None
    for c in candidates:
        if c == version:
            continue
        k = key(c)
        if k is None or not (k < cur):
            continue
        if not allow_pre and is_prerelease(eco, c):
            continue
        if best_k is None or k > best_k:
            best, best_k = c, k
    return best


# ------------------------------------------------------------------ delta


def _is_binary(b: bytes) -> bool:
    return b"\x00" in b[:8192]


def new_lines(old: bytes, new: bytes) -> bytes:
    """Lines of ``new`` that are not accounted for by ``old`` (multiset difference)."""
    have = Counter(old.split(b"\n"))
    out = []
    for line in new.split(b"\n"):
        if have[line] > 0:
            have[line] -= 1
        else:
            out.append(line)
    return b"\n".join(out)


def is_manifest(p: str) -> bool:
    """Root manifests, plus a wheel's ``*.dist-info/METADATA`` (a wheel has no root one)."""
    return p in MANIFESTS or re.fullmatch(r"[^/]+\.dist-info/METADATA", p) is not None


def build_delta(prev: Files, cur: Files) -> tuple[Files, dict]:
    delta: Files = {}
    added = modified = unchanged = 0
    added_bytes = 0
    for p in sorted(cur):
        data = cur[p]
        if is_manifest(p):
            delta[p] = data
        old = prev.get(p)
        if old is None:
            added += 1
            added_bytes += len(data)
            delta[p] = data
        elif old == data:
            unchanged += 1
        else:
            modified += 1
            part = data if (_is_binary(data) or _is_binary(old)) else new_lines(old, data)
            added_bytes += len(part)
            if not is_manifest(p) and part.strip():
                delta[p] = part
    removed = sum(1 for p in prev if p not in cur)
    stats = {
        "n_added": added,
        "n_modified": modified,
        "n_unchanged": unchanged,
        "n_removed": removed,
        "added_bytes": added_bytes,
        "cur_files": len(cur),
        "prev_files": len(prev),
    }
    return delta, stats


# ------------------------------------------------------------------ registry


def _get(
    url: str, accept: str | None = None, timeout: float = 60, retries: int = 3
) -> bytes | None:
    headers = dict(UA)
    if accept:
        headers["Accept"] = accept
    for i in range(retries):
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, headers=headers), timeout=timeout
            ) as r:
                return r.read(MAX_PREV_BYTES + 1)
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):
                return None
            time.sleep(2**i)
        except OSError:
            time.sleep(2**i)
    return None


def is_wheel_tree(files: Files) -> bool:
    return any(re.match(r"^[^/]+\.dist-info/", p) for p in files) and "PKG-INFO" not in files


def resolve_previous(eco: str, name: str, version: str, wheel: bool) -> tuple[str, str] | None:
    """(previous version, archive URL) from the live registry, or ``None``."""
    if eco == "npm":
        quoted = name.replace("/", "%2f")
        raw = _get(f"{NPM}/{quoted}", accept="application/vnd.npm.install-v1+json")
        if raw is None:
            return None
        doc = json.loads(raw)
        versions = doc.get("versions") or {}
        prev = previous_version(eco, version, list(versions))
        if prev is None:
            return None
        url = (versions[prev].get("dist") or {}).get("tarball")
        return (prev, url) if url else None
    raw = _get(f"{PYPI}/{urllib.parse.quote(name)}/json")
    if raw is None:
        return None
    releases = json.loads(raw).get("releases") or {}
    live = {v: fs for v, fs in releases.items() if fs and not all(f.get("yanked") for f in fs)}
    prev = previous_version(eco, version, list(live))
    if prev is None:
        return None
    files = [f for f in live[prev] if not f.get("yanked")]
    if wheel:
        pick = [f for f in files if f["filename"].endswith("-none-any.whl")] or [
            f for f in files if f["filename"].endswith(".whl")
        ]
    else:
        pick = [f for f in files if f.get("packagetype") == "sdist"]
    if not pick:
        return None
    pick.sort(key=lambda f: f.get("size") or 0)
    return prev, pick[0]["url"]


def load_tree(path: str) -> Files:
    """Files of a canonical archive with the root directory removed."""
    files = read_tar_tree(Path(path).read_bytes())
    return {p.split("/", 1)[1]: d for p, d in files.items() if "/" in p}


def registry_tree(eco: str, data: bytes, url: str) -> Files:
    """Prepare a downloaded archive exactly as the corpus was prepared."""
    fname = urllib.parse.urlparse(url).path.rsplit("/", 1)[-1]
    files = strip_common_root(read_any(data, fname))
    if eco == "npm" and any(p.startswith("package/") for p in files):
        files = {p[len("package/") :]: d for p, d in files.items() if p.startswith("package/")}
    return files


# ------------------------------------------------------------------ synthetic compromises


_SUSPICIOUS = re.compile(
    rb"child_process|execSync|spawn\(|https?\.(?:request|get)|fetch\(|eval\(|Function\(|"
    rb"Buffer\.from|process\.env|homedir|\.ssh|dns\.|net\.Socket|webhook|discord|"
    rb"subprocess|os\.system|urllib|requests\.|socket\.|base64|exec\(|getenv|__import__"
)


def _rank(files: Files, paths: list[str]) -> list[str]:
    scored = [(len(_SUSPICIOUS.findall(files[p][:MAX_PAYLOAD])), -len(files[p]), p) for p in paths]
    return [p for s, _, p in sorted(scored, reverse=True) if s > 0]


def _npm_payload(files: Files) -> tuple[bytes, str | None]:
    """The JS a malicious npm package runs, and its install-script shell command if any."""
    try:
        pkg = json.loads(files.get("package.json", b"{}"))
    except ValueError:
        pkg = {}
    pkg = pkg if isinstance(pkg, dict) else {}
    scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
    shell = None
    for hook in ("preinstall", "install", "postinstall"):
        cmd = scripts.get(hook)
        if isinstance(cmd, str) and not re.search(r"\bnode\b", cmd) and len(cmd) > 12:
            shell = cmd
            break
    js = [p for p in files if p.endswith((".js", ".cjs", ".mjs")) and "node_modules/" not in p]
    picked = _rank(files, js)[:3]
    code = b"\n".join(files[p] for p in picked)[:MAX_PAYLOAD]
    return code, shell


def _py_payload(files: Files) -> bytes:
    """The Python a malicious PyPI package runs: its most suspicious source files."""
    py = [p for p in files if p.endswith(".py")]
    picked = _rank(files, py)[:2]
    return b"\n".join(files[p] for p in picked)[:MAX_PAYLOAD]


def _npm_main(files: Files) -> str:
    try:
        pkg = json.loads(files.get("package.json", b"{}"))
        main = pkg.get("main") if isinstance(pkg, dict) else None
    except ValueError:
        main = None
    main = (main if isinstance(main, str) else "index.js").lstrip("./")
    if not main.endswith((".js", ".cjs", ".mjs")):
        main = main.rstrip("/") + ("/index.js" if main + "/index.js" in files else ".js")
    return main


def _set_script(files: Files, hook: str, cmd: str) -> Files:
    out = dict(files)
    try:
        pkg = json.loads(files.get("package.json", b"{}"))
    except ValueError:
        return out
    if not isinstance(pkg, dict):
        return out
    scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
    scripts[hook] = cmd
    pkg["scripts"] = scripts
    out["package.json"] = json.dumps(pkg, indent=2).encode()
    return out


NPM_MODES = ("postinstall_file", "entry_append", "script_shell")
PY_MODES = ("setup_append", "init_append", "new_module")
FILE_NAMES = (
    "bundle.js",
    "setup.js",
    "install.js",
    "lib/telemetry.js",
    "dist/init.js",
    "scripts/postinstall.js",
)
MODULE_NAMES = ("_compat", "telemetry", "_version_check", "utils_net", "_patch")


def payload_ok(eco: str, donor: Files) -> bool:
    if eco == "npm":
        code, shell = _npm_payload(donor)
        return len(code) >= 64 or shell is not None
    return len(_py_payload(donor)) >= 64


def inject(eco: str, cur: Files, donor: Files, rng: random.Random) -> tuple[Files, str]:
    out = dict(cur)
    if eco == "npm":
        code, shell = _npm_payload(donor)
        if len(code) < 64:
            return _set_script(out, "preinstall", shell or ""), "script_shell"
        modes = list(NPM_MODES) if shell else [m for m in NPM_MODES if m != "script_shell"]
        mode = rng.choice(modes)
        if mode == "script_shell":
            return _set_script(out, "preinstall", shell), mode
        if mode == "postinstall_file":
            fname = rng.choice(FILE_NAMES)
            out[fname] = code
            return _set_script(out, "postinstall", f"node {fname}"), mode
        main = _npm_main(cur)
        out[main] = cur.get(main, b"") + b"\n" + code
        return out, mode
    code = _py_payload(donor)
    inits = sorted((p for p in cur if p.endswith("__init__.py")), key=lambda p: (p.count("/"), p))
    modes = [m for m in PY_MODES if m != "setup_append" or "setup.py" in cur]
    if not inits:
        modes = [m for m in modes if m == "setup_append"] or ["new_file"]
    mode = rng.choice(modes)
    if mode == "setup_append":
        out["setup.py"] = cur["setup.py"] + b"\n" + code
    elif mode == "init_append":
        out[inits[0]] = cur[inits[0]] + b"\n" + code
    elif mode == "new_module":
        pkg_dir = inits[0].rsplit("/", 1)[0] if "/" in inits[0] else ""
        mod = rng.choice(MODULE_NAMES)
        out[f"{pkg_dir}/{mod}.py".lstrip("/")] = code
        out[inits[0]] = cur[inits[0]] + f"\nfrom . import {mod}\n".encode()
    else:
        out["setup.py"] = code
    return out, mode


# ------------------------------------------------------------------ stage: pairs


def _write_delta(files: Files, eco: str, name: str, version: str, out_dir: Path) -> str:
    blob = canonicalize(files, eco, name, version)
    digest = hashlib.sha256(blob).hexdigest()
    ext = ".tgz" if eco == "npm" else ".tar.gz"
    out = out_dir / eco / digest[:2] / f"{digest}{ext}"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(blob)
    return str(out)


_DONORS: dict[str, list[str]] = {}


def _pair_one(task: dict) -> list[dict]:
    eco, name, version = task["ecosystem"], task["name"], task["version"]
    base = {k: task[k] for k in ("row", "ecosystem", "name", "version", "label", "kind", "split")}
    out_dir = Path(task["out_dir"])
    try:
        cur = load_tree(task["canonical_path"])
        wheel = eco == "pypi" and is_wheel_tree(cur)
        res = resolve_previous(eco, name, version, wheel)
        if res is None:
            return [{**base, "error": "no previous release"}]
        prev_v, url = res
        data = _get(url, timeout=120)
        if data is None or len(data) > MAX_PREV_BYTES:
            return [{**base, "prev_version": prev_v, "error": "previous archive unavailable"}]
        prev = registry_tree(eco, data, url)
        rows = []
        delta, stats = build_delta(prev, cur)
        rows.append(
            {
                **base,
                "prev_version": prev_v,
                "synthetic": None,
                "wheel": wheel,
                **stats,
                "delta_path": _write_delta(delta, eco, name, version, out_dir),
            }
        )
        donors = task.get("donors") or []
        if task["label"] == 0 and donors:
            rng = random.Random(f"{eco}/{name}/{version}")
            for _ in range(8):
                donor_path = donors[rng.randrange(len(donors))]
                donor = load_tree(donor_path)
                if payload_ok(eco, donor):
                    break
            injected, mode = inject(eco, cur, donor, rng)
            d2, s2 = build_delta(prev, injected)
            rows.append(
                {
                    **base,
                    "label": 1,
                    "kind": "synthetic_compromise",
                    "prev_version": prev_v,
                    "synthetic": mode,
                    "donor": donor_path,
                    "wheel": wheel,
                    **s2,
                    "delta_path": _write_delta(d2, eco, name, version, out_dir),
                }
            )
        return rows
    except Exception as e:  # noqa: BLE001 - recorded per pair
        return [{**base, "error": f"{type(e).__name__}: {e}"[:300]}]


def stage_pairs(workers: int = 12, limit: int | None = None) -> Path:
    """Fetch previous releases and write delta archives for every eligible row.

    Eligible: every benign row and every real compromised release. Malicious packages that
    were never a real library (typosquats, fresh malware) have no meaningful previous
    release, so they only serve as payload donors.
    """
    from .pipeline import load_table

    df = load_table()
    if "augmented" in df:
        df = df[df.augmented.isna()]
    df = df[df.canonical_path.map(lambda p: bool(p) and Path(p).exists())]
    split = df["split_temporal"]
    donors = {
        eco: sorted(
            df[
                (df.label == 1)
                & (df.kind == "malicious_intent")
                & (split == "train")
                & (df.ecosystem == eco)
            ]
            .groupby("cluster")
            .head(2)
            .canonical_path
        )
        for eco in ("npm", "pypi")
    }
    rows = df[(df.label == 0) | (df.kind == "compromised_lib")]
    if limit:
        rows = rows.sample(limit, random_state=0)
    out_dir = config.sub("diff")
    manifest = out_dir / "pairs.jsonl"
    done = set()
    if manifest.exists():
        done = {json.loads(x)["row"] for x in manifest.read_text().splitlines()}
    tasks = [
        {
            "row": int(i),
            "ecosystem": r.ecosystem,
            "name": r["name"],
            "version": str(r.version),
            "label": int(r.label),
            "kind": r.kind if isinstance(r.kind, str) else "benign",
            "split": r.split_temporal,
            "canonical_path": r.canonical_path,
            "donors": donors[r.ecosystem] if r.label == 0 else None,
            "out_dir": str(out_dir),
        }
        for i, r in rows.iterrows()
        if int(i) not in done
    ]
    print(
        f"{len(tasks)} pairs to build ({len(done)} done); donors",
        {k: len(v) for k, v in donors.items()},
        flush=True,
    )
    t0 = time.time()
    with ProcessPoolExecutor(workers) as ex, manifest.open("a") as mf:
        for n, res in enumerate(ex.map(_pair_one, tasks, chunksize=4), 1):
            for r in res:
                mf.write(json.dumps(r) + "\n")
            if n % 500 == 0:
                mf.flush()
                print(f"{n}/{len(tasks)} pairs, {time.time() - t0:.0f}s", flush=True)
    return manifest


# ------------------------------------------------------------------ stage: table


STAT_COLS = ["n_added", "n_modified", "n_unchanged", "added_bytes", "cur_files"]


def pair_features(stats: pd.DataFrame) -> pd.DataFrame:
    """Change-size features shared with the Rust firewall (see diff.rs)."""
    out = pd.DataFrame(index=stats.index)
    total = stats.cur_files.clip(lower=1)
    out["p_n_added"] = stats.n_added
    out["p_n_modified"] = stats.n_modified
    out["p_frac_changed"] = (stats.n_added + stats.n_modified) / total
    out["p_log_added_bytes"] = np.log1p(stats.added_bytes)
    out["p_log_cur_files"] = np.log1p(stats.cur_files)
    return out


def sweep(min_batch: int = 1) -> int:
    """Scan delta archives written so far, record features, and delete the archives.

    Deltas of large releases can be hundreds of KB each, so they are scanned as they are
    produced instead of being kept for the whole corpus.
    """
    from . import features

    out_dir = config.sub("diff")
    feats = out_dir / "features.jsonl"
    seen = set()
    if feats.exists():
        seen = {json.loads(x)["delta_path"] for x in feats.read_text().split("\n") if x}
    paths = []
    for line in (out_dir / "pairs.jsonl").read_text().split("\n"):
        if not line:
            continue
        p = json.loads(line).get("delta_path")
        if p and p not in seen and Path(p).exists():
            seen.add(p)
            paths.append(p)
    if len(paths) < min_batch:
        return 0
    by_eco: dict[str, list[str]] = {}
    for p in paths:
        by_eco.setdefault("npm" if "/diff/npm/" in p else "pypi", []).append(p)
    paths = [p for eco in sorted(by_eco) for p in by_eco[eco]]
    reports = [
        r
        for eco in sorted(by_eco)
        for r in features.scan_paths(by_eco[eco], tokens=True, ecosystem=eco)
    ]
    with feats.open("a") as f:
        for p, r in zip(paths, reports, strict=True):
            f.write(
                json.dumps(
                    {
                        "delta_path": p,
                        "features": r.get("features"),
                        "tokens": r.get("tokens") or [],
                        "scan_error": r.get("error"),
                    }
                )
                + "\n"
            )
    for p in paths:
        Path(p).unlink(missing_ok=True)
    return len(paths)


def sweep_forever(interval: float = 120) -> None:
    while True:
        n = sweep()
        print(time.strftime("%H:%M:%S"), f"swept {n}", flush=True)
        time.sleep(interval)


def stage_table() -> Path:
    from .pipeline import work

    sweep()
    out_dir = config.sub("diff")
    pairs = pd.read_json(out_dir / "pairs.jsonl", lines=True)
    ok = pairs[pairs.delta_path.notna()].reset_index(drop=True)
    print(
        f"{len(ok)} deltas of {len(pairs)} attempts; errors:",
        pairs[pairs.delta_path.isna()].error.str.slice(0, 40).value_counts().head(8).to_dict(),
        flush=True,
    )
    feats = pd.read_json(out_dir / "features.jsonl", lines=True).drop_duplicates("delta_path")
    ok = ok.merge(feats, on="delta_path", how="inner")
    f = pd.DataFrame([{f"f_{k}": v for k, v in (x or {}).items()} for x in ok.features])
    table = pd.concat([ok.drop(columns=["features"]), f, pair_features(ok)], axis=1)
    path = work() / "diff_dataset.parquet"
    table.to_parquet(path)
    print(f"wrote {path} {table.shape}", flush=True)
    return path


# ------------------------------------------------------------------ stage: train + evaluate

DIFF_FPR_WARN = 0.005
DIFF_FPR_BLOCK = 0.001


# Features left out of the diff model. A delta omits unchanged files, so which delta
# files an install hook reaches (the inst_ surface) is not well defined, and these two were
# added to the scanner after the deltas were scanned.
DIFF_EXCLUDE = ("f_inst_", "f_all_hidden_ws_lines", "f_all_exec_decoded")


def diff_feature_cols(table: pd.DataFrame) -> list[str]:
    return [
        c for c in table.columns if c.startswith(("f_", "p_")) and not c.startswith(DIFF_EXCLUDE)
    ]


def stage_train() -> dict:
    """Train on benign pairs vs synthetic compromises; evaluate on real compromises.

    Splits follow the corpus's temporal split of the *current* release, so every benign
    pair and every donor payload used in training is from the training split. Real
    compromised releases never enter training or threshold selection.
    """
    from sklearn.metrics import average_precision_score

    from . import gbdt, metrics
    from .pipeline import load_table, log, work

    table = pd.read_parquet(work() / "diff_dataset.parquet")
    table = table[table.scan_error.isna()].reset_index(drop=True)
    base = load_table()
    base = base[base.augmented.isna()] if "augmented" in base else base
    table["cluster"] = table.row.map(base.cluster)
    table["base_risk"] = table.row.map(base.ens_risk_temporal)
    table["tier"] = table.row.map(base.tier)
    cols = diff_feature_cols(table)
    real = table.kind == "compromised_lib"
    fit = ~real
    w = np.where(
        table.label == 1,
        0.5 / max((fit & (table.label == 1)).sum(), 1),
        0.5 / max((fit & (table.label == 0)).sum(), 1),
    ) * len(table)

    def xy(m):
        return table.loc[m, cols].to_numpy(dtype=float), table.label.to_numpy()[m.to_numpy()]

    tr, va = fit & (table.split == "train"), fit & (table.split == "val")
    Xtr, ytr = xy(tr)
    Xva, yva = xy(va)
    best, best_ap = None, -1.0
    for leaves in (15, 31, 63):
        for min_leaf in (20, 80):
            t = gbdt.train(
                Xtr,
                ytr,
                w[tr.to_numpy()],
                Xva,
                yva,
                w[va.to_numpy()],
                [c[2:] if c.startswith("f_") else c for c in cols],
                {"num_leaves": leaves, "min_data_in_leaf": min_leaf},
            )
            ap = average_precision_score(yva, gbdt.predict_raw(t, Xva))
            log(
                f"diff gbdt leaves={leaves} min_leaf={min_leaf} "
                f"iters={t.best_iteration} val AP={ap:.4f}"
            )
            if ap > best_ap:
                best, best_ap = t, ap
    raw_va = gbdt.predict_raw(best, Xva)
    cal = gbdt.fit_platt(raw_va, yva)
    model = gbdt.export(best, cal)
    table["diff_raw"] = gbdt.predict_raw(best, table[cols].to_numpy(dtype=float))
    table["diff_risk"] = gbdt.apply_calibration(cal, 1 / (1 + np.exp(-table.diff_raw.to_numpy())))
    rva = table.diff_risk.to_numpy()[va.to_numpy()]
    thresholds = {
        "warn": metrics.threshold_at_fpr(yva, rva, DIFF_FPR_WARN),
        "block": metrics.threshold_at_fpr(yva, rva, DIFF_FPR_BLOCK),
    }
    ens = json.loads((Path(__file__).resolve().parents[2] / "models/ensemble.json").read_text())[
        "thresholds"
    ]
    ens = {k: ens[k] for k in ("warn", "block")}
    val_benign = table[(table.label == 0) & (table.split == "val")]

    def tail_score(ref: np.ndarray, x: np.ndarray) -> np.ndarray:
        """-log of the smoothed share of validation benign pairs scoring at least x."""
        ref = np.sort(ref)
        return -np.log((len(ref) - np.searchsorted(ref, x, side="left") + 1) / (len(ref) + 1))

    def block(rows: pd.DataFrame, with_base: bool = True) -> dict:
        y = rows.label.to_numpy()
        d, b = rows.diff_risk.to_numpy(), rows.base_risk.to_numpy()
        out = {
            "n_pos": int(y.sum()),
            "n_neg": int((1 - y).sum()),
            "diff": metrics.summarize(y, d, thresholds).__dict__,
        }
        if not with_base:
            return out
        out["base"] = metrics.summarize(y, b, ens).__dict__
        # Base and diff combined by taking the larger benign tail score, then compared with
        # the base model alone at the same false positive rate on these negatives.
        comb = np.maximum(
            tail_score(val_benign.base_risk.to_numpy(), b),
            tail_score(val_benign.diff_risk.to_numpy(), d),
        )
        matched = {}
        for f in (0.001, 0.005, 0.01):
            tb, tc = np.quantile(b[y == 0], 1 - f), np.quantile(comb[y == 0], 1 - f)
            matched[str(f)] = {
                "base_recall": float((b[y == 1] > tb).mean()),
                "combined_recall": float((comb[y == 1] > tc).mean()),
            }
        out["matched_fpr"] = matched
        tb, td = np.quantile(b[y == 0], 0.995), np.quantile(d[y == 0], 0.995)
        out["overlap_at_fpr_0.005"] = {
            "both": int(((b > tb) & (d > td))[y == 1].sum()),
            "base_only": int(((b > tb) & (d <= td))[y == 1].sum()),
            "diff_only": int(((b <= tb) & (d > td))[y == 1].sum()),
            "neither": int(((b <= tb) & (d <= td))[y == 1].sum()),
        }
        if 0 < y.sum() < len(y):
            cl = rows.cluster.fillna(-1).to_numpy()
            from sklearn.metrics import roc_auc_score

            out["diff_auc_ci"] = metrics.cluster_bootstrap(y, d, cl, roc_auc_score, n_boot=500)
            out["base_auc_ci"] = metrics.cluster_bootstrap(y, b, cl, roc_auc_score, n_boot=500)
        return out

    neg_test = table[(table.label == 0) & (table.split == "test")]
    report = {
        "pairs": {k: int(v) for k, v in table.kind.value_counts().items()},
        "features": len(cols),
        "best_val_ap": best_ap,
        "thresholds": thresholds,
        "fpr_targets": {"warn": DIFF_FPR_WARN, "block": DIFF_FPR_BLOCK},
        "real_compromised_test": block(
            pd.concat([table[real & (table.split == "test")], neg_test])
        ),
        "real_compromised_all": block(pd.concat([table[real], neg_test])),
        # Synthetic positives have no full-package base score, so only the diff model.
        "synthetic_test": block(table[(table.split == "test") & ~real], with_base=False),
        "synthetic_test_by_mode": {
            m: float((g.diff_risk >= thresholds["warn"]).mean())
            for m, g in table[
                (table.split == "test") & (table.kind == "synthetic_compromise")
            ].groupby("synthetic")
        },
    }
    imp = pd.Series(best.booster.feature_importance("gain"), index=cols).sort_values(
        ascending=False
    )
    report["top_features"] = imp.head(15).round(1).to_dict()
    out = {"format": "customs-diff-v1", "features": cols, "thresholds": thresholds, "model": model}
    (work() / "diff_model.json").write_text(json.dumps(out))
    (work() / "diff_eval.json").write_text(json.dumps(report, indent=1, default=float))
    table.drop(columns=["tokens"]).to_parquet(work() / "diff_scored.parquet")
    log(json.dumps({k: report[k] for k in ("pairs", "thresholds", "best_val_ap")}, default=float))
    return report
