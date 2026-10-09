"""Adversarial robustness: does detection survive the evasions attackers actually use?

Static detectors are known to fall to adaptive attackers, so this is reported rather than
assumed. Each transform rewrites held-out malicious archives as text (nothing is ever run)
and the rewritten archive is re-scanned and re-scored with the exported models:

``string_split``      split string literals into concatenations, defeating literal matching
                      of hosts, paths, and commands.
``hex_escape``        write every string literal as ``\\xNN`` escapes, which Python and
                      JavaScript decode to the same string at run time.
``char_codes``        build every string literal from character codes at run time:
                      ``String.fromCharCode(...)`` in JavaScript, ``''.join(map(chr, [...]))``
                      in Python.
``reverse_strings``   store every string literal reversed and reverse it at run time:
                      ``"..."[::-1]`` in Python, ``.split('').reverse().join('')`` in
                      JavaScript.
``array_join``        split every string literal into pieces and join them at run time:
                      ``''.join(['ev', 'al'])`` in Python, ``['ev', 'al'].join('')`` in
                      JavaScript.
``string_table``      move every string literal into one array at the top of the file and
                      read it back by index (``_s[3]``), the string-array layout
                      javascript-obfuscator produces.
``base64_wrap``       replace each install-time script with a stub that base64-decodes and
                      executes the original (the most common real-world wrapper).
``zlib_wrap``         the same stub over zlib-compressed bytes:
                      ``exec(zlib.decompress(base64.b64decode(...)))``.
``trojan_padding``    bury the payload inside a large benign codebase by adding the source of
                      a real popular package, mimicking a compromised library.
``indirection``       move install-time Python code into a helper module that setup.py
                      imports, so it leaves the scanned install surface.

The point is to find out where the model is brittle and say so, not to show a perfect
number. Results go into the evaluation report.
"""

from __future__ import annotations

import base64
import json
import re
import zlib
from collections.abc import Callable
from pathlib import Path

import numpy as np

from . import config, features, gbdt
from . import nn as cnn
from .augment import load_files, starjack
from .malicious import canonicalize, read_tar_tree
from .pipeline import SCHEME, load_table, log, work

Files = dict[str, bytes]
# Families the augmentation stage trains on (see augment.py); the rest are unseen attacks.
SEEN_IN_TRAINING = {"metadata_mimicry", "starjack", "trojan_padding"}

STR_RE = re.compile(r"""(?P<q>["'])(?P<body>[A-Za-z0-9_./:@\-]{6,200})(?P=q)""")


def _is_code(path: str) -> bool:
    return path.endswith((".py", ".js", ".cjs", ".mjs"))


def string_split(files: Files, eco: str) -> Files:
    out = {}
    for p, data in files.items():
        if not _is_code(p):
            out[p] = data
            continue
        text = data.decode("utf-8", "replace")

        def split(m: re.Match) -> str:
            q, body = m["q"], m["body"]
            mid = len(body) // 2
            return f"({q}{body[:mid]}{q} + {q}{body[mid:]}{q})"

        out[p] = STR_RE.sub(split, text).encode()
    return out


def hex_escape(files: Files, eco: str) -> Files:
    out = {}
    for p, data in files.items():
        if not _is_code(p):
            out[p] = data
            continue
        text = data.decode("utf-8", "replace")

        def escape(m: re.Match) -> str:
            # A prefix letter makes it a raw, bytes or f-string, where escapes differ.
            if m.start() > 0 and m.string[m.start() - 1].isalpha():
                return m[0]
            q, body = m["q"], m["body"]
            return q + "".join(f"\\x{ord(c):02x}" for c in body) + q

        out[p] = STR_RE.sub(escape, text).encode()
    return out


def char_codes(files: Files, eco: str) -> Files:
    out = {}
    for p, data in files.items():
        if not _is_code(p):
            out[p] = data
            continue
        text = data.decode("utf-8", "replace")
        py = p.endswith(".py")

        def build(m: re.Match, py: bool = py) -> str:
            if m.start() > 0 and m.string[m.start() - 1].isalpha():
                return m[0]
            codes = ", ".join(str(ord(c)) for c in m["body"])
            return f"''.join(map(chr, [{codes}]))" if py else f"String.fromCharCode({codes})"

        out[p] = STR_RE.sub(build, text).encode()
    return out


def reverse_strings(files: Files, eco: str) -> Files:
    out = {}
    for p, data in files.items():
        if not _is_code(p):
            out[p] = data
            continue
        text = data.decode("utf-8", "replace")
        py = p.endswith(".py")

        def rev(m: re.Match, py: bool = py) -> str:
            if m.start() > 0 and m.string[m.start() - 1].isalpha():
                return m[0]
            q, body = m["q"], m["body"][::-1]
            return f"{q}{body}{q}[::-1]" if py else f"{q}{body}{q}.split('').reverse().join('')"

        out[p] = STR_RE.sub(rev, text).encode()
    return out


def _pieces(body: str) -> list[str]:
    """Cut a literal into two to four pieces of at least two characters."""
    k = min(4, max(2, len(body) // 4))
    step = -(-len(body) // k)
    return [body[i : i + step] for i in range(0, len(body), step)]


def array_join(files: Files, eco: str) -> Files:
    out = {}
    for p, data in files.items():
        if not _is_code(p):
            out[p] = data
            continue
        text = data.decode("utf-8", "replace")
        py = p.endswith(".py")

        def join(m: re.Match, py: bool = py) -> str:
            if m.start() > 0 and m.string[m.start() - 1].isalpha():
                return m[0]
            q = m["q"]
            items = ", ".join(f"{q}{s}{q}" for s in _pieces(m["body"]))
            return f"''.join([{items}])" if py else f"[{items}].join('')"

        out[p] = STR_RE.sub(join, text).encode()
    return out


FUTURE_RE = re.compile(r"^(?:from __future__ import [^\n]*\n)+", re.M)


def string_table(files: Files, eco: str) -> Files:
    out = {}
    for p, data in files.items():
        if not _is_code(p):
            out[p] = data
            continue
        text = data.decode("utf-8", "replace")
        table: list[str] = []
        index: dict[str, int] = {}

        def ref(m: re.Match, table: list[str] = table, index: dict[str, int] = index) -> str:
            if m.start() > 0 and m.string[m.start() - 1].isalpha():
                return m[0]
            body = m["body"]
            if body not in index:
                index[body] = len(table)
                table.append(body)
            return f"_s[{index[body]}]"

        body = STR_RE.sub(ref, text)
        if not table:
            out[p] = data
            continue
        decl = "[" + ", ".join(json.dumps(s) for s in table) + "]"
        if p.endswith(".py"):
            # `from __future__` imports have to stay first.
            m = FUTURE_RE.match(body)
            at = m.end() if m else 0
            body = body[:at] + f"_s = {decl}\n" + body[at:]
        else:
            body = f"var _s = {decl};\n" + body
        out[p] = body.encode()
    return out


def base64_wrap(files: Files, eco: str) -> Files:
    out = dict(files)
    if eco == "pypi":
        targets = [p for p in files if p == "setup.py" or p.endswith("/__init__.py")]
        for p in targets:
            b64 = base64.b64encode(files[p]).decode()
            out[p] = f"import base64\nexec(base64.b64decode('{b64}'))\n".encode()
    else:
        for p in [p for p in files if p.endswith(".js")]:
            b64 = base64.b64encode(files[p]).decode()
            out[p] = f"eval(Buffer.from('{b64}', 'base64').toString());\n".encode()
    return out


def zlib_wrap(files: Files, eco: str) -> Files:
    out = dict(files)
    if eco == "pypi":
        targets = [p for p in files if p == "setup.py" or p.endswith("/__init__.py")]
        for p in targets:
            b64 = base64.b64encode(zlib.compress(files[p])).decode()
            stub = f"exec(zlib.decompress(base64.b64decode('{b64}')))\n"
            out[p] = ("import base64, zlib\n" + stub).encode()
    else:
        for p in [p for p in files if p.endswith(".js")]:
            b64 = base64.b64encode(zlib.compress(files[p])).decode()
            out[p] = (
                f"eval(require('zlib').inflateSync(Buffer.from('{b64}', 'base64')).toString());\n"
            ).encode()
    return out


def make_trojan_padding(donor: Files) -> Callable[[Files, str], Files]:
    def pad(files: Files, eco: str) -> Files:
        out = {f"vendor/{p}": d for p, d in donor.items() if _is_code(p)}
        out.update(files)
        return out

    return pad


def make_metadata_mimicry(readme: bytes) -> Callable[[Files, str], Files]:
    """Give the package the trappings of a maintained project: README, repository link,
    homepage, description, license. Costs an attacker a minute; tests whether the model
    leans on metadata."""

    def mimic(files: Files, eco: str) -> Files:
        out = dict(files)
        out["README.md"] = readme
        if eco == "npm":
            try:
                pkg = json.loads(files.get("package.json", b"{}"))
            except ValueError:
                pkg = {}
            if not isinstance(pkg, dict):
                pkg = {}
            name = pkg.get("name", "pkg")
            pkg.update(
                {
                    "description": "Fast, well-tested utilities for modern JavaScript projects.",
                    "repository": {
                        "type": "git",
                        "url": f"git+https://github.com/example/{name}.git",
                    },
                    "homepage": f"https://github.com/example/{name}#readme",
                    "license": "MIT",
                    "author": "Example Maintainer <maintainer@example.com>",
                    "keywords": ["utility", "helpers", "toolkit"],
                }
            )
            out["package.json"] = json.dumps(pkg, indent=2).encode()
        else:
            info = files.get("PKG-INFO", b"Metadata-Version: 2.1\nName: pkg\nVersion: 1.0\n")
            head, _, body = info.partition(b"\n\n")
            head += (
                b"\nSummary: Fast, well-tested utilities for modern Python projects."
                b"\nHome-page: https://github.com/example/pkg"
                b"\nProject-URL: Source, https://github.com/example/pkg"
                b"\nAuthor-email: Example Maintainer <maintainer@example.com>"
                b"\nLicense: MIT\nKeywords: utility,helpers,toolkit"
                b"\nDescription-Content-Type: text/markdown"
            )
            out["PKG-INFO"] = head + b"\n\n" + (body or readme)
        return out

    return mimic


def indirection(files: Files, eco: str) -> Files:
    if eco != "pypi" or "setup.py" not in files:
        return files
    out = dict(files)
    out["_build_helpers.py"] = files["setup.py"]
    out["setup.py"] = b"import _build_helpers  # noqa\n"
    return out


# ---------------------------------------------------------------- scoring


class Scorer:
    """Scores scanner reports with the exported artifacts (reference implementation)."""

    def __init__(self, scheme: str = SCHEME):
        self.gbdt = json.loads((work() / f"code_gbdt_{scheme}.json").read_text(encoding="utf-8"))
        self.nn = json.loads((work() / f"code_nn_{scheme}.json").read_text(encoding="utf-8"))
        self.ens = json.loads((work() / f"ensemble_{scheme}.json").read_text(encoding="utf-8"))

    def score(self, reports: list[dict], name_logits: np.ndarray) -> np.ndarray:
        names_ = self.gbdt["feature_names"]
        X = np.array([[r["features"].get(n, np.nan) for n in names_] for r in reports])
        g = gbdt.predict_raw_exported(self.gbdt, X)
        c = np.array([cnn.numpy_forward(self.nn, r.get("tokens") or []) for r in reports])
        w = self.ens["weights"]
        b = self.ens.get("clip") or np.inf
        g, c, n = (np.clip(x, -b, b) for x in (g, c, name_logits))
        z = self.ens["bias"] + w["code_gbdt"] * g + w["code_nn"] * c + w["name"] * n
        return gbdt.apply_calibration(self.ens["calibration"], 1 / (1 + np.exp(-z)))


def _starjack(files: Files, eco: str, donors: dict[str, Files]) -> Files:
    return starjack(files, eco, donors[eco]) if eco in donors else files


def _readme(donor: Files) -> bytes:
    for p, d in donor.items():
        if p.lower().startswith("readme"):
            return d[:8000]
    return b"# Utilities\n\n" + b"A small, dependable toolkit. " * 200


def run(n: int = 600, scheme: str = SCHEME, seed: int = 0, only: list[str] | None = None) -> dict:
    """Score every transform; ``only`` restricts the run to some transforms and leaves the
    saved report alone."""
    df = load_table()
    split = df[f"split_{scheme}"]
    ens = json.loads((work() / f"ensemble_{scheme}.json").read_text(encoding="utf-8"))
    t_block, t_warn = ens["thresholds"]["block"], ens["thresholds"]["warn"]
    mal = df[(split == "test") & (df.label == 1)]
    mal = mal.sample(min(n, len(mal)), random_state=seed)
    # Donor for trojan padding: a mid-sized popular benign package from the test split.
    ben = df[(split == "test") & (df.label == 0) & (df.tier == "top")]
    donor_row = ben.iloc[(ben.f_all_n_lines - 3000).abs().argsort().iloc[0]]
    donor = read_tar_tree(Path(donor_row.canonical_path).read_bytes())
    donor = {p.split("/", 1)[1]: d for p, d in donor.items() if "/" in p}
    # Starjacking copies metadata from a real project of the same ecosystem; donors here
    # come from the benign *test* split, never from training.
    donors = {}
    for eco in ("pypi", "npm"):
        cand = ben[ben.ecosystem == eco]
        if len(cand):
            r = cand.sample(1, random_state=seed).iloc[0]
            donors[eco] = load_files(r.canonical_path)
    transforms = {
        "none": lambda f, e: f,
        "string_split": string_split,
        "hex_escape": hex_escape,
        "char_codes": char_codes,
        "reverse_strings": reverse_strings,
        "array_join": array_join,
        "string_table": string_table,
        "base64_wrap": base64_wrap,
        "zlib_wrap": zlib_wrap,
        "trojan_padding": make_trojan_padding(donor),
        "indirection": indirection,
        "metadata_mimicry": make_metadata_mimicry(_readme(donor)),
        "starjack": lambda f, e: _starjack(f, e, donors),
    }
    if only:
        transforms = {k: v for k, v in transforms.items() if k in only}
    scorer = Scorer(scheme)
    tmp = config.sub("robustness")
    results = {}
    for tname, fn in transforms.items():
        paths = []
        for row in mal.itertuples():
            files = read_tar_tree(Path(row.canonical_path).read_bytes())
            files = {p.split("/", 1)[1]: d for p, d in files.items() if "/" in p}
            blob = canonicalize(fn(files, row.ecosystem), row.ecosystem, row.name, str(row.version))
            ext = ".tgz" if row.ecosystem == "npm" else ".tar.gz"
            out = tmp / f"{tname}_{row.Index}{ext}"
            out.write_bytes(blob)
            paths.append(str(out))
        reports = features.scan_paths(paths, tokens=True)
        ok = np.array(["features" in r for r in reports])
        risk = scorer.score([r for r in reports if "features" in r], mal.name_logit.to_numpy()[ok])
        results[tname] = {
            "n": int(ok.sum()),
            "recall_block": float(np.mean(risk >= t_block)),
            "recall_warn": float(np.mean(risk >= t_warn)),
            "by_ecosystem": {
                eco: float(np.mean(risk[(mal.ecosystem.to_numpy()[ok] == eco)] >= t_block))
                for eco in ("pypi", "npm")
                if (mal.ecosystem.to_numpy()[ok] == eco).any()
            },
        }
        log("robustness", tname, results[tname])
        for p in paths:
            Path(p).unlink(missing_ok=True)
    if only:
        return results
    results["donor"] = {"name": donor_row["name"], "ecosystem": donor_row.ecosystem}
    results["seen_in_training"] = sorted(SEEN_IN_TRAINING)
    (work() / f"robustness_{scheme}.json").write_text(
        json.dumps(results, indent=1), encoding="utf-8"
    )
    return results
