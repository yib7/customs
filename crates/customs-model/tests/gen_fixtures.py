#!/usr/bin/env python3
"""Generate parity fixtures for customs-model.

This is a reference implementation, in numpy and the standard library only, of every
computation the Rust crate performs (DESIGN.md sections 4.5 and 5):

- tree ensemble inference with `default_left` for missing values, `<=` going left,
  sigmoid, isotonic calibration by `np.interp`, and Saabas contributions;
- package-name features (PEP 503 / npm normalization, optimal string alignment distance
  to popular names clipped at 5, token wrapping, npm scope squatting, keyboard typos) and
  the hashed character n-gram logistic regression (FNV-1a 32-bit over `^name$`);
- the code CNN forward pass (embedding, valid 1D convolutions, ReLU, global max pool,
  dense layers);
- logistic stacking with fallback weight sets and final calibration.

It writes a small model bundle to `fixtures/models/` plus `fixtures/expected_*.json`; the
Rust tests in `parity.rs` load both and require agreement within 1e-5. The training
pipeline can reuse these functions as the specification of the serving math.

Usage: python3 crates/customs-model/tests/gen_fixtures.py
"""

import base64
import json
import os
import re

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "fixtures")
MODELS = os.path.join(OUT, "models")
EDIT_DISTANCE_CAP = 5
COMPONENTS = ["code_gbdt", "code_nn", "name"]

rng = np.random.default_rng(20261007)


def sigmoid(x):
    x = float(x)
    if x >= 0:
        return 1.0 / (1.0 + np.exp(-x))
    e = np.exp(x)
    return e / (1.0 + e)


def b64(arr):
    a = np.ascontiguousarray(np.asarray(arr, dtype="<f4"))
    return {"shape": list(a.shape), "data": base64.b64encode(a.tobytes()).decode("ascii")}


def dump(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
        f.write("\n")


# ---------------------------------------------------------------- tree ensemble

GBDT_FEATURES = [
    "inst_proc_exec", "inst_network", "inst_decode_obf", "inst_exfil_endpoint",
    "inst_env_access", "all_url", "n_files", "has_setup_py", "inst_max_str_entropy",
    "n_npm_install_scripts", "meta_has_repo", "inst_download_exec",
]
THRESHOLDS = [0.0, 0.5, 1.0, 2.0, 3.5, 4.2]


def make_tree(max_depth):
    nodes = []

    def build(depth):
        idx = len(nodes)
        if depth >= max_depth or (depth > 0 and rng.random() < 0.25):
            v = float(np.round(rng.normal(0, 0.6), 6))
            nodes.append({"leaf": v})
            return idx, v, float(rng.integers(1, 50))
        nodes.append(None)
        f = int(rng.integers(0, len(GBDT_FEATURES)))
        t = float(rng.choice(THRESHOLDS))
        dl = bool(rng.random() < 0.5)
        li, lv, lc = build(depth + 1)
        ri, rv, rc = build(depth + 1)
        cover = lc + rc
        # Cover-weighted expected value, as LightGBM's internal_value would be.
        value = (lv * lc + rv * rc) / cover
        nodes[idx] = {"split": f, "threshold": t, "left": li, "right": ri,
                      "default_left": dl, "value": value}
        return idx, value, cover

    build(0)
    return {"nodes": nodes}


def gbdt_predict(model, feats):
    names = model["feature_names"]
    row = [feats.get(n, float("nan")) for n in names]
    raw = model["base_score"]
    bias = model["base_score"]
    contrib = [0.0] * len(names)

    def val(n):
        return n["leaf"] if "leaf" in n else n["value"]

    for tree in model["trees"]:
        nodes = tree["nodes"]
        bias += val(nodes[0])
        i = 0
        while "leaf" not in nodes[i]:
            n = nodes[i]
            x = row[n["split"]]
            if np.isnan(x):
                nxt = n["left"] if n["default_left"] else n["right"]
            else:
                nxt = n["left"] if x <= n["threshold"] else n["right"]
            contrib[n["split"]] += val(nodes[nxt]) - n["value"]
            i = nxt
        raw += nodes[i]["leaf"]
    prob = sigmoid(raw)
    cal = model.get("calibration")
    calibrated = float(np.interp(prob, cal["x"], cal["y"])) if cal else prob
    return {"raw": raw, "prob": prob, "calibrated": calibrated, "bias": bias,
            "contributions": contrib}


def random_features():
    feats = {}
    for n in GBDT_FEATURES:
        r = rng.random()
        if r < 0.2:
            continue  # missing
        if r < 0.5:
            feats[n] = float(rng.choice(THRESHOLDS))  # exact threshold hits
        else:
            feats[n] = float(np.round(rng.uniform(0, 5), 3))
    if rng.random() < 0.3:
        feats["unused_feature"] = 7.0
    return feats


def isotonic(n):
    x = np.sort(rng.uniform(0.02, 0.98, n))
    x = np.unique(np.round(x, 4))
    y = np.sort(rng.uniform(0, 1, len(x)))
    return {"method": "isotonic", "x": [float(v) for v in x], "y": [float(v) for v in y]}


# ---------------------------------------------------------------- name model

KEYBOARD_ROWS = ["1234567890-", "qwertyuiop", "asdfghjkl", "zxcvbnm"]


def normalize(eco, name):
    name = name.strip()
    if eco == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def split_scope(name):
    if name.startswith("@") and "/" in name:
        scope, bare = name[1:].split("/", 1)
        return scope, bare
    return None, name


def osa(a, b):
    n, m = len(a), len(b)
    d = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(n + 1):
        d[i][0] = i
    for j in range(m + 1):
        d[0][j] = j
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[n][m]


def key_pos(c):
    for r, row in enumerate(KEYBOARD_ROWS):
        if c in row:
            return r, row.index(c)
    return None


def keyboard_adjacent(a, b):
    pa, pb = key_pos(a), key_pos(b)
    if pa is None or pb is None:
        return False
    if pa[0] == pb[0]:
        return abs(pa[1] - pb[1]) == 1
    up, lo = (pa, pb) if pa[0] < pb[0] else (pb, pa)
    return lo[0] - up[0] == 1 and lo[1] in (up[1], up[1] - 1)


class Popular:
    def __init__(self, eco, names):
        self.eco = eco
        self.names = []
        for raw in names:
            n = normalize(eco, raw)
            if n and n not in self.names:
                self.names.append(n)
        self.set = set(self.names)
        self.token_names = set(normalize("pypi", split_scope(n)[1]) for n in self.names)
        self.scoped_bare = {}
        self.scopes = []
        if eco == "npm":
            for n in self.names:
                s, bare = split_scope(n)
                if s is not None:
                    self.scoped_bare.setdefault(bare, []).append(s)
                    if s not in self.scopes:
                        self.scopes.append(s)

    def nearest(self, q):
        best = None
        for r, n in enumerate(self.names):
            if n == q:
                continue
            d = min(osa(q, n), EDIT_DISTANCE_CAP)
            if best is None or (d, r) < best:
                best = (d, r)
        return best

    def contained_token(self, q):
        bare = split_scope(q)[1] if self.eco == "npm" else q
        toks = [t for t in re.split(r"[-_.]", bare) if t]
        if len(toks) < 2:
            return None
        found = None
        for i in range(len(toks)):
            for j in range(i + 1, len(toks) + 1):
                if j - i == len(toks):
                    continue
                joined = "-".join(toks[i:j])
                if len(joined) < 3 or joined not in self.token_names:
                    continue
                if found is None or len(joined.encode()) > len(found.encode()):
                    found = joined
        return found

    def scope_squat(self, q):
        if self.eco != "npm":
            return None
        scope, bare = split_scope(q)
        if scope is None:
            return None
        for s in self.scoped_bare.get(bare, []):
            if s != scope:
                return "@%s/%s" % (s, bare)
        if len(scope) < 3 or scope in self.scopes:
            return None
        best = None
        for s in self.scopes:
            d = osa(scope, s)
            if d <= 2 and (best is None or d < best[0]):
                best = (d, s)
        return "@" + best[1] if best else None


def fnv1a32(data):
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def ngram_buckets(norm, nmin, nmax, n_buckets):
    chars = ["^"] + list(norm) + ["$"]
    out = []
    for n in range(max(nmin, 1), nmax + 1):
        if n > len(chars):
            break
        for i in range(len(chars) - n + 1):
            out.append(fnv1a32("".join(chars[i:i + n]).encode("utf-8")) % n_buckets)
    return out


def name_features(eco, name, pop):
    q = normalize(eco, name)
    f = {
        "normalized": q,
        "len": len(q),
        "n_digits": sum(c.isdigit() and c.isascii() for c in q),
        "n_hyphens": q.count("-"),
        "n_underscores": q.count("_"),
        "n_dots": q.count("."),
        "min_edit_distance": EDIT_DISTANCE_CAP,
        "nearest_popular": None,
        "is_popular": 0,
        "contains_popular_token": None,
        "scope_squat": None,
        "keyboard_typo": 0,
    }
    f["is_popular"] = int(q in pop.set)
    nb = pop.nearest(q)
    if nb is not None:
        d, r = nb
        f["min_edit_distance"] = d
        near = pop.names[r]
        f["nearest_popular"] = near
        if d == 1 and len(near) == len(q):
            diffs = [(a, b) for a, b in zip(q, near) if a != b]
            f["keyboard_typo"] = int(len(diffs) == 1 and keyboard_adjacent(*diffs[0]))
    if not f["is_popular"]:
        f["contains_popular_token"] = pop.contained_token(q)
        f["scope_squat"] = pop.scope_squat(q)
    return f


def numeric(f, key):
    v = f[key]
    if key in ("contains_popular_token", "scope_squat"):
        return 1.0 if v is not None else 0.0
    return float(v)


def name_score(model, eco, name, pop):
    f = name_features(eco, name, pop)
    w = model["weights"]
    buckets = ngram_buckets(f["normalized"], model["ngram_min"], model["ngram_max"],
                            model["n_buckets"])
    ng = float(sum(w[b] for b in buckets))
    f["char_ngram_score"] = ng
    logit = model["bias"] + ng
    for i, k in enumerate(model["feature_names"]):
        logit += model["feature_weights"][i] * (numeric(f, k) - model["feature_mean"][i]) \
            / model["feature_scale"][i]
    return f, buckets, logit


POPULAR_PYPI = [
    "boto3", "urllib3", "requests", "setuptools", "certifi", "typing-extensions",
    "charset-normalizer", "idna", "python-dateutil", "numpy", "packaging", "six", "pyyaml",
    "s3transfer", "botocore", "cryptography", "pip", "wheel", "attrs", "pandas", "click",
    "jinja2", "markupsafe", "flask", "django", "pytest", "pydantic", "scipy", "matplotlib",
    "Pillow", "sqlalchemy", "colorama", "tqdm", "rich", "httpx", "aiohttp", "fastapi",
    "uvicorn", "torch", "tensorflow", "scikit-learn", "beautifulsoup4", "lxml", "openai",
]
POPULAR_NPM = [
    "react", "react-dom", "lodash", "express", "axios", "chalk", "commander", "debug",
    "@babel/core", "@babel/parser", "@types/node", "@types/react", "typescript", "webpack",
    "vue", "moment", "uuid", "tslib", "semver", "left-pad", "@angular/core", "rxjs",
    "eslint", "prettier", "jest", "next", "dotenv", "cross-env", "colors", "event-stream",
]

NAME_CASES = [
    ("pypi", "requests"), ("pypi", "reqeusts"), ("pypi", "requezts"), ("pypi", "Requests"),
    ("pypi", "requests_toolbelt"), ("pypi", "python-dateutil-ng"), ("pypi", "Python.DateUtil"),
    ("pypi", "numpi"), ("pypi", "nunpy"), ("pypi", "beautifulsoup"), ("pypi", "openai-helper-tools"),
    ("pypi", "zzqxj-unrelated-name"), ("pypi", "torch2"), ("pypi", "pandas_v2.1"),
    ("pypi", "x"), ("pypi", "scikit_learn"), ("pypi", "dj4ngo"), ("pypi", "flask-sqlalchemy"),
    ("npm", "react"), ("npm", "raect"), ("npm", "@babel/core"), ("npm", "@bable/core"),
    ("npm", "@babel-js/parser"), ("npm", "@acme/react"), ("npm", "lodash.merge"),
    ("npm", "express-session-helper"), ("npm", "axois"), ("npm", "crossenv"),
    ("npm", "@types/nodee"), ("npm", "left-pad"), ("npm", "eventstream"), ("npm", "@Types/React"),
]

NAME_FEATURES = ["len", "n_digits", "n_hyphens", "n_underscores", "n_dots",
                 "min_edit_distance", "is_popular", "contains_popular_token", "scope_squat",
                 "keyboard_typo"]


# ---------------------------------------------------------------- code CNN


def cnn_encode(model, tokens):
    vocab = model["vocab"]
    max_k = max(c["kernel_size"] for c in model["convs"])
    ids = [vocab.get(t, 1) for t in tokens[: model["max_len"]]]
    target = max(model["max_len"], max_k) if model.get("pad_to_max_len", True) \
        else max(len(ids), max_k)
    return ids + [0] * (target - len(ids))


def cnn_forward(model, arrays, tokens):
    ids = cnn_encode(model, tokens)
    emb = arrays["embedding"].astype(np.float64)[ids]  # (L, D)
    pooled = []
    for w, b in arrays["convs"]:
        w = w.astype(np.float64)
        b = b.astype(np.float64)
        c_out, _, k = w.shape
        L = emb.shape[0]
        out = np.empty((c_out, L - k + 1))
        for t in range(L - k + 1):
            window = emb[t:t + k]  # (k, D)
            out[:, t] = b + np.einsum("cdk,kd->c", w, window)
        pooled.append(np.maximum(out.max(axis=1), 0.0))
    h = np.concatenate(pooled)
    for i, (w, b) in enumerate(arrays["dense"]):
        h = w.astype(np.float64) @ h + b.astype(np.float64)
        if i + 1 < len(arrays["dense"]):
            h = np.maximum(h, 0.0)
    return ids, float(h[0])


# ---------------------------------------------------------------- ensemble


def ensemble_combine(ens, logits):
    avail = [c for c in COMPONENTS if logits.get(c) is not None]
    if not avail:
        return None
    key = "+".join(avail)
    if key == "+".join(COMPONENTS):
        w, bias, cal, ws = ens["weights"], ens["bias"], ens.get("calibration"), "primary"
    elif key in ens.get("fallbacks", {}):
        fb = ens["fallbacks"][key]
        w, bias = fb["weights"], fb.get("bias", 0.0)
        cal = fb.get("calibration") or ens.get("calibration")
        ws = key
    else:
        w, bias, cal, ws = ens["weights"], ens["bias"], ens.get("calibration"), "partial:" + key
    z = bias
    for c in COMPONENTS:
        if logits.get(c) is not None:
            z += w.get(c, 0.0) * logits[c]
    raw = sigmoid(z)
    risk = float(np.interp(raw, cal["x"], cal["y"])) if cal else raw
    return {"z": z, "raw": raw, "risk": risk, "weight_set": ws}


def main():
    os.makedirs(MODELS, exist_ok=True)

    # Tree ensemble.
    gbdt = {
        "feature_names": GBDT_FEATURES,
        "base_score": -1.25,
        "objective": "binary",
        "trees": [make_tree(int(rng.integers(1, 5))) for _ in range(25)],
        "calibration": isotonic(12),
    }
    dump(os.path.join(MODELS, "code_gbdt.json"), gbdt)
    cases = []
    for _ in range(60):
        feats = random_features()
        cases.append({"features": feats, **gbdt_predict(gbdt, feats)})
    cases.append({"features": {}, **gbdt_predict(gbdt, {})})
    dump(os.path.join(OUT, "expected_gbdt.json"), {"cases": cases})

    # Name model.
    with open(os.path.join(MODELS, "popular_pypi.txt"), "w") as f:
        f.write("# fixture list, most popular first\n" + "\n".join(POPULAR_PYPI) + "\n")
    with open(os.path.join(MODELS, "popular_npm.txt"), "w") as f:
        f.write("\n".join(POPULAR_NPM) + "\n")
    pops = {"pypi": Popular("pypi", POPULAR_PYPI), "npm": Popular("npm", POPULAR_NPM)}
    n_buckets = 4096
    name_model = {
        "feature_names": NAME_FEATURES,
        "feature_weights": [float(np.round(v, 6)) for v in rng.normal(0, 0.8, len(NAME_FEATURES))],
        "feature_mean": [float(np.round(v, 4)) for v in rng.uniform(0, 2, len(NAME_FEATURES))],
        "feature_scale": [float(np.round(v, 4)) for v in rng.uniform(0.5, 3, len(NAME_FEATURES))],
        "n_buckets": n_buckets,
        "ngram_min": 1,
        "ngram_max": 4,
        "weights": [float(np.round(v, 6)) for v in rng.normal(0, 0.05, n_buckets)],
        "bias": -0.75,
    }
    dump(os.path.join(MODELS, "name_model.json"), name_model)
    ncases = []
    for eco, name in NAME_CASES:
        f, buckets, logit = name_score(name_model, eco, name, pops[eco])
        ncases.append({"ecosystem": eco, "name": name, "features": f, "buckets": buckets,
                       "logit": logit, "prob": sigmoid(logit)})
    dump(os.path.join(OUT, "expected_name.json"), {"cases": ncases})

    # Code CNN.
    vocab_tokens = ["<pad>", "<unk>", "os", ".", "system", "(", ")", "import", "subprocess",
                    "requests", "get", "base64", "b64decode", "exec", "eval", "=", "'", "\"",
                    "require", "child_process", "process", "env", "fetch", "http", "https",
                    "Buffer", "from", "STR", "NUM", "ID", ",", ";", "{", "}", "def", "return"]
    vocab = {t: i for i, t in enumerate(vocab_tokens)}
    V, D = len(vocab_tokens), 8
    emb = rng.normal(0, 0.4, (V, D)).astype(np.float32)
    emb[0] = 0.0  # padding_idx=0 in PyTorch
    convs = []
    for k in (2, 3, 5):
        w = rng.normal(0, 0.3, (6, D, k)).astype(np.float32)
        b = rng.normal(0, 0.1, 6).astype(np.float32)
        convs.append((w, b))
    dense = [
        (rng.normal(0, 0.3, (10, 18)).astype(np.float32), rng.normal(0, 0.1, 10).astype(np.float32)),
        (rng.normal(0, 0.3, (1, 10)).astype(np.float32), rng.normal(0, 0.1, 1).astype(np.float32)),
    ]
    cnn = {
        "vocab": vocab,
        "max_len": 40,
        "pad_to_max_len": True,
        "embedding": b64(emb),
        "convs": [{"kernel_size": int(w.shape[2]), "weight": b64(w), "bias": b64(b)}
                  for w, b in convs],
        "dense": [{"weight": b64(w), "bias": b64(b)} for w, b in dense],
    }
    dump(os.path.join(MODELS, "code_nn.json"), cnn)
    arrays = {"embedding": emb, "convs": convs, "dense": dense}
    ccases = []
    token_pool = vocab_tokens[2:] + ["unknown_a", "unknown_b", "zzz"]
    for i in range(25):
        n = [0, 1, 3, 4, 10, 39, 40, 41, 75][i % 9]
        toks = [str(token_pool[j]) for j in rng.integers(0, len(token_pool), n)]
        ids, logit = cnn_forward(cnn, arrays, toks)
        ccases.append({"tokens": toks, "ids": ids, "logit": logit})
    dump(os.path.join(OUT, "expected_cnn.json"), {"cases": ccases})

    # Ensemble.
    ens = {
        "weights": {"code_gbdt": 1.1, "code_nn": 0.6, "name": 0.9},
        "bias": -0.4,
        "fallbacks": {
            "code_gbdt+name": {"weights": {"code_gbdt": 1.4, "name": 1.0}, "bias": -0.3},
            "name": {"weights": {"name": 1.2}, "bias": -0.8, "calibration": isotonic(6)},
        },
        "calibration": isotonic(10),
        "thresholds": {"warn": 0.5, "block": 0.85, "target_fpr_block": 0.001},
    }
    dump(os.path.join(MODELS, "ensemble.json"), ens)
    ecases = []
    for i in range(30):
        logits = {}
        for c in COMPONENTS:
            if rng.random() < 0.7 or i == 0:
                logits[c] = float(np.round(rng.normal(0, 2.5), 6))
            else:
                logits[c] = None
        ecases.append({"logits": logits, "out": ensemble_combine(ens, logits)})
    dump(os.path.join(OUT, "expected_ensemble.json"), {"cases": ecases})

    manifest = {
        "model_version": "fixture.1",
        "feature_schema_version": 1,
        "code_gbdt": "code_gbdt.json",
        "name_model": "name_model.json",
        "code_nn": "code_nn.json",
        "ensemble": "ensemble.json",
        "popular_names": {"pypi": "popular_pypi.txt", "npm": "popular_npm.txt"},
        "untrained": True,
        "description": "Parity fixtures generated by tests/gen_fixtures.py; random weights.",
    }
    dump(os.path.join(MODELS, "manifest.json"), manifest)

    # End-to-end assessments through the bundle.
    acases = []
    for i in range(12):
        eco, name = NAME_CASES[(i * 5) % len(NAME_CASES)]
        feats = random_features() if i % 4 != 3 else {}
        toks = [] if i % 3 == 2 else [str(token_pool[j]) for j in rng.integers(0, len(token_pool), 20)]
        use_name = i % 5 != 4
        logits, scores = {}, {}
        if feats:
            g = gbdt_predict(gbdt, feats)
            logits["code_gbdt"], scores["code_gbdt"] = g["raw"], g["calibrated"]
        else:
            logits["code_gbdt"], scores["code_gbdt"] = None, None
        if toks:
            _, l = cnn_forward(cnn, arrays, toks)
            logits["code_nn"], scores["code_nn"] = l, sigmoid(l)
        else:
            logits["code_nn"], scores["code_nn"] = None, None
        if use_name:
            _, _, l = name_score(name_model, eco, name, pops[eco])
            logits["name"], scores["name"] = l, sigmoid(l)
        else:
            logits["name"], scores["name"] = None, None
        out = ensemble_combine(ens, logits)
        acases.append({"ecosystem": eco, "name": name if use_name else None,
                       "features": feats, "tokens": toks, "scores": scores,
                       "risk": out["risk"] if out else None,
                       "weight_set": out["weight_set"] if out else None})
    dump(os.path.join(OUT, "expected_assess.json"), {"cases": acases})
    print("wrote fixtures to", OUT)


if __name__ == "__main__":
    main()
