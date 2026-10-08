"""Adversarial data augmentation for the training split.

The robustness suite showed the tree model leaning on manifest metadata (README size,
repository link): signals an attacker can fake in a minute. This stage adds disguised
copies of training malware so the models learn what the code does instead:

``starjack``   copy README, description, repository, homepage, license, and keywords from a
               real benign project (attackers do this, it is called starjacking).
``bury``       add the source files of a real benign package next to the payload, so size
               and file counts look like a normal library.
``starjack_self`` starjack, with the copied repository links renamed to the sample's own
               name. A repository link that names the package is free to write, so the
               model must not read it as a sign of a real project.
``starjack+bury`` both.

Donors come from the benign *training* split only. Augmented rows inherit the source
sample's cluster and are always in the training split, so validation and test are
untouched. Three other evasions (string splitting, base64 wrapping, install-surface
indirection) are deliberately not used here; the robustness report treats them as unseen
attacks.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import numpy as np
import pandas as pd

from . import config, features
from .malicious import canonicalize, read_tar_tree
from .pipeline import SCHEME, load_table, log, work

Files = dict[str, bytes]
TRANSFORMS = ("starjack", "starjack_self", "bury", "starjack+bury")
FORGE_RE = re.compile(
    r"(github\.com|gitlab\.com|bitbucket\.org)([/:])([\w.-]+)/([\w.-]+?)(\.git)?(?=[/#?\s\"]|$)"
)


def _strip_root(files: Files) -> Files:
    return {p.split("/", 1)[1]: d for p, d in files.items() if "/" in p}


def load_files(path: str) -> Files:
    return _strip_root(read_tar_tree(Path(path).read_bytes()))


def _is_code(p: str) -> bool:
    return p.endswith((".py", ".js", ".cjs", ".mjs"))


def starjack(files: Files, eco: str, donor: Files) -> Files:
    out = dict(files)
    for p, d in donor.items():
        if "/" not in p and p.lower().startswith("readme"):
            out[p] = d
    if eco == "npm":
        try:
            pkg = json.loads(files.get("package.json", b"{}"))
            dpkg = json.loads(donor.get("package.json", b"{}"))
        except ValueError:
            return out
        if isinstance(pkg, dict) and isinstance(dpkg, dict):
            for k in (
                "description",
                "repository",
                "homepage",
                "license",
                "keywords",
                "author",
                "bugs",
                "contributors",
            ):
                if k in dpkg:
                    pkg[k] = dpkg[k]
            out["package.json"] = json.dumps(pkg, indent=2).encode()
    else:
        dinfo = donor.get("PKG-INFO")
        if dinfo:
            own = files.get("PKG-INFO", b"")
            # Keep the sample's own name and version lines, take everything else.
            keep = [ln for ln in own.split(b"\n") if ln.startswith((b"Name:", b"Version:"))]
            rest = [ln for ln in dinfo.split(b"\n") if not ln.startswith((b"Name:", b"Version:"))]
            out["PKG-INFO"] = b"\n".join(keep + rest)
    return out


def _own_name(files: Files, eco: str) -> str | None:
    if eco == "npm":
        try:
            name = json.loads(files.get("package.json", b"{}")).get("name")
        except (ValueError, AttributeError):
            return None
        return name.rsplit("/", 1)[-1] if isinstance(name, str) and name else None
    for ln in files.get("PKG-INFO", b"").split(b"\n"):
        if ln.startswith(b"Name:"):
            return ln[5:].strip().decode("utf-8", "replace") or None
    return None


def self_repo(files: Files, eco: str) -> Files:
    """Point every forge repository link at a repository named after the package itself,
    adding one when there is none."""
    name = _own_name(files, eco)
    if not name:
        return files
    owner = "dev-" + hashlib.sha256(name.encode()).hexdigest()[:6]

    def rename(text: str) -> str:
        return FORGE_RE.sub(lambda m: f"{m[1]}{m[2]}{m[3]}/{name}{m[5] or ''}", text)

    out = dict(files)
    url = f"https://github.com/{owner}/{name}"
    if eco == "npm":
        try:
            pkg = json.loads(files.get("package.json", b"{}"))
        except ValueError:
            return files
        if not isinstance(pkg, dict):
            return files
        for k in ("repository", "homepage", "bugs"):
            if k in pkg:
                pkg[k] = json.loads(rename(json.dumps(pkg[k])))
        if not FORGE_RE.search(json.dumps(pkg.get("repository", ""))):
            pkg["repository"] = {"type": "git", "url": f"git+{url}.git"}
        out["package.json"] = json.dumps(pkg, indent=2).encode()
    elif "PKG-INFO" in files:
        head, sep, body = files["PKG-INFO"].decode("utf-8", "replace").partition("\n\n")
        lines = [
            rename(ln) if ln.startswith(("Home-page:", "Project-URL:", "Download-URL:")) else ln
            for ln in head.split("\n")
        ]
        if not any(FORGE_RE.search(ln) for ln in lines):
            lines.append(f"Project-URL: Source, {url}")
        out["PKG-INFO"] = ("\n".join(lines) + sep + body).encode()
    return out


def bury(files: Files, eco: str, donor: Files, prefix: str = "lib") -> Files:
    out = {f"{prefix}/{p}": d for p, d in donor.items() if _is_code(p)}
    out.update(files)
    return out


def apply(name: str, files: Files, eco: str, donor: Files) -> Files:
    if name == "starjack":
        return starjack(files, eco, donor)
    if name == "starjack_self":
        return self_repo(starjack(files, eco, donor), eco)
    if name == "bury":
        return bury(files, eco, donor)
    return bury(starjack(files, eco, donor), eco, donor)


def stage_augment(
    scheme: str = SCHEME, per_cluster: int = 4, max_rows: int = 8000, seed: int = 11
) -> None:
    df = load_table()
    if "augmented" in df:
        df = df[df.augmented.isna()].reset_index(drop=True)
    split = df[f"split_{scheme}"]
    rng = np.random.default_rng(seed)
    src = df[(split == "train") & (df.label == 1)]
    # Augment the primary corpus only, so adding a second source leaves this stage as is.
    if "source" in src:
        src = src[src.source.isna()]
    src = src.groupby("cluster", group_keys=False).apply(
        lambda g: g.sample(min(len(g), per_cluster), random_state=seed)
    )
    src = src.sample(min(len(src), max_rows), random_state=seed)
    donors = {
        eco: df[
            (split == "train")
            & (df.label == 0)
            & (df.ecosystem == eco)
            & df.tier.isin(["top", "mid"])
            & (df.f_all_n_lines.between(200, 20000))
        ]
        for eco in ("pypi", "npm")
    }
    tmp = config.sub("augment_tmp")
    paths, meta, rows = [], [], []

    def flush() -> None:
        # Scan and delete in batches, so disk use stays at one batch of archives.
        reports = features.scan_paths(paths, tokens=True)
        for (idx, tname), rep, p in zip(meta, reports, paths, strict=True):
            Path(p).unlink(missing_ok=True)
            if "features" not in rep:
                continue
            base = df.loc[idx].to_dict()
            base.update({f"f_{k}": v for k, v in rep["features"].items()})
            base["tokens"] = rep.get("tokens") or []
            base["augmented"] = tname
            base["canonical_path"] = ""
            rows.append(base)
        paths.clear()
        meta.clear()

    for i, row in enumerate(src.itertuples()):
        d = donors[row.ecosystem]
        donor_row = d.iloc[int(rng.integers(0, len(d)))]
        tname = TRANSFORMS[int(rng.integers(0, len(TRANSFORMS)))]
        try:
            files = apply(
                tname,
                load_files(row.canonical_path),
                row.ecosystem,
                load_files(donor_row.canonical_path),
            )
        except Exception:  # noqa: BLE001 - skip a sample that fails to rewrite
            continue
        blob = canonicalize(files, row.ecosystem, row.name, str(row.version))
        ext = ".tgz" if row.ecosystem == "npm" else ".tar.gz"
        out = tmp / f"aug_{i}{ext}"
        out.write_bytes(blob)
        paths.append(str(out))
        meta.append((row.Index, tname))
        if len(paths) >= 500:
            flush()
    if paths:
        flush()
    aug = pd.DataFrame(rows)
    df["augmented"] = None
    out = pd.concat([df, aug], ignore_index=True)
    log(f"augmented {len(aug)} training rows:", aug.augmented.value_counts().to_dict())
    out.to_parquet(work() / "dataset.parquet")
