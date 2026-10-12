#!/usr/bin/env python3
"""Generate parity fixtures for customs-model.

This is a reference implementation, in numpy and the standard library only, of every
computation the Rust crate performs (DESIGN.md sections 4.5 and 5):

- tree ensemble inference with `default_left` for missing values, `<=` going left,
  sigmoid, isotonic calibration by `np.interp`, and Saabas contributions;
- the `customs-name-lr-v1` name model: PEP 503 / npm normalization, bare names (npm scope
  removed), optimal string alignment distance to popular names (distance 0 ignored, values
  above max_distance become max_distance + 1), wrapped popular tokens, digit suffix, and
  the hashed character n-gram logistic regression (FNV-1a 32-bit over `^name$`, distinct
  buckets);
- the `customs-code-cnn-v1` forward pass (embedding, valid 1D convolutions, ReLU, global
  max pool, dense layers with per-layer activation, short inputs padded to 16), with
  email-shaped tokens looked up by their hashed vocabulary key;
- `customs-ensemble-v1` logistic stacking of clipped logits with fallback weight sets
  selected by the set of missing components (no risk for a set without one unless the file
  sets `partial`), then calibration.

It writes a small model bundle to `fixtures/models/` plus `fixtures/expected_*.json`, and
`fixtures/expected_shipped_ensemble.json` from the shipped `models/ensemble.json`; the
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
SHIPPED_ENSEMBLE = os.path.join(HERE, "..", "..", "..", "models", "ensemble.json")
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


# ---------------------------------------------------------------- name model (customs-name-lr-v1)

KEYBOARD_ROWS = ["1234567890-", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
NUMERIC_FEATURES = ["len", "n_digits", "n_hyphens", "n_underscores", "n_dots", "has_scope",
                    "is_popular", "dist1", "dist2", "dist3", "contains_popular_token",
                    "digit_suffix"]
MAX_DISTANCE = 4


def normalize(eco, name):
    name = name.strip()
    if eco == "pypi":
        return re.sub(r"[-_.]+", "-", name.lower())
    return name.lower()


def bare(name):
    if name.startswith("@") and "/" in name:
        return name.split("/", 1)[1]
    return name


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


class Popular:
    def __init__(self, eco, names):
        self.names = []
        for raw in names:
            n = normalize(eco, raw)
            if n and n not in self.names:
                self.names.append(n)
        self.full = set(self.names)
        self.long_pop = set(bare(p) for p in self.names if len(bare(p)) >= 4)

    def nearest(self, bq):
        best = None
        for r, p in enumerate(self.names):
            d = osa(bq, bare(p))
            if d == 0 or d > MAX_DISTANCE:
                continue
            if best is None or (d, r) < best:
                best = (d, r)
        if best is None:
            return MAX_DISTANCE + 1, None
        return best[0], self.names[best[1]]


def fnv1a32(data):
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def distinct_buckets(norm, nmin, nmax, n_buckets):
    chars = ["^"] + list(norm) + ["$"]
    out = set()
    for n in range(max(nmin, 1), nmax + 1):
        if n > len(chars):
            break
        for i in range(len(chars) - n + 1):
            out.add(fnv1a32("".join(chars[i:i + n]).encode("utf-8")) % n_buckets)
    return sorted(out)


def name_features(eco, name, pop):
    q = normalize(eco, name)
    bq = bare(q)
    d, near = pop.nearest(bq)
    toks = [t for t in re.split(r"[-_.]", bq) if t]
    wrapped = None
    if len(toks) > 1 and bq not in pop.long_pop:
        wrapped = next((t for t in toks if t in pop.long_pop), None)
    return {
        "normalized": q,
        "bare": bq,
        "len": len(bq),
        "n_digits": sum(1 for c in bq if c in "0123456789"),
        "n_hyphens": bq.count("-"),
        "n_underscores": bq.count("_"),
        "n_dots": bq.count("."),
        "has_scope": int(q.startswith("@")),
        "is_popular": int(q in pop.full),
        "distance": d,
        "nearest_popular": near,
        "dist1": int(d == 1),
        "dist2": int(d == 2),
        "dist3": int(d == 3),
        "contains_popular_token": wrapped,
        "digit_suffix": int(bool(bq) and bq[-1] in "0123456789"),
    }


def numeric(f, key):
    v = f[key]
    if key == "contains_popular_token":
        return 1.0 if v is not None else 0.0
    return float(v)


def name_score(model, eco, name, pop, ngw):
    e = model["ecosystems"][eco]
    f = name_features(eco, name, pop)
    buckets = distinct_buckets(f["normalized"], model["ngram_min"], model["ngram_max"],
                               model["n_buckets"])
    ng = float(sum(float(ngw[b]) for b in buckets))
    f["char_ngram_score"] = ng
    logit = e["bias"] + ng
    for i, k in enumerate(model["numeric_features"]):
        logit += (numeric(f, k) - e["mean"][i]) / e["std"][i] * e["numeric_weights"][i]
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
    ("pypi", "six-helpers"), ("pypi", "éclair"),
    ("npm", "react"), ("npm", "raect"), ("npm", "@babel/core"), ("npm", "@bable/core"),
    ("npm", "@babel-js/parser"), ("npm", "@acme/react"), ("npm", "lodash.merge"),
    ("npm", "express-session-helper"), ("npm", "axois"), ("npm", "crossenv"),
    ("npm", "@types/nodee"), ("npm", "left-pad"), ("npm", "eventstream"), ("npm", "@Types/React"),
    ("npm", "lodash4"),
]


# ---------------------------------------------------------------- code CNN (customs-code-cnn-v1)

MIN_LEN = 16
# An email-shaped token: local part, one or more dotted domain labels, a letters-only TLD.
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}")


def fnv1a64(data):
    h = 0xCBF29CE484222325
    for b in data:
        h ^= b
        h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def vocab_key(token):
    """Email-shaped tokens are looked up (and stored) as `<email:{fnv1a64:016x}>`."""
    if EMAIL.fullmatch(token):
        return "<email:%016x>" % fnv1a64(token.encode("utf-8"))
    return token


def cnn_encode(model, tokens):
    # Keys in the file may be plaintext or already hashed; both map to the same key.
    vocab = {vocab_key(k): v for k, v in model["vocab"].items()}
    max_k = max(c["kernel"] for c in model["convs"])
    ids = [vocab.get(vocab_key(t), 1) for t in tokens[: model["max_len"]]]
    target = max(MIN_LEN, max_k)
    if len(ids) < target:
        ids = ids + [0] * (target - len(ids))
    return ids


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
            out[:, t] = b + np.einsum("cdk,kd->c", w, emb[t:t + k])
        pooled.append(np.maximum(out, 0.0).max(axis=1))
    h = np.concatenate(pooled)
    for (w, b), act in zip(arrays["dense"], arrays["activations"]):
        h = w.astype(np.float64) @ h + b.astype(np.float64)
        if act == "relu":
            h = np.maximum(h, 0.0)
    return ids, float(h[0])


# ---------------------------------------------------------------- ensemble (customs-ensemble-v1)


def ensemble_combine(ens, logits):
    missing = [c for c in COMPONENTS if logits.get(c) is None]
    if len(missing) == len(COMPONENTS):
        return None
    fb = next((f for f in ens["fallbacks"] if set(f["missing"]) == set(missing)), None)
    if not missing:
        w, bias, cal, ws = ens["weights"], ens["bias"], ens.get("calibration"), "primary"
    elif fb is not None:
        w, bias = fb["weights"], fb.get("bias", 0.0)
        cal = fb.get("calibration") or ens.get("calibration")
        ws = "missing:" + "+".join(missing)
    elif ens.get("partial", False):
        w, bias, cal = ens["weights"], ens["bias"], ens.get("calibration")
        ws = "partial:" + "+".join(missing)
    else:
        # No weights were fitted for this set of inputs: no risk.
        return None
    clip = ens.get("clip")
    z = bias
    for c in COMPONENTS:
        if logits.get(c) is not None:
            v = logits[c]
            if clip is not None:
                v = min(max(v, -clip), clip)
            z += w.get(c, 0.0) * v
    raw = sigmoid(z)
    risk = float(np.interp(raw, cal["x"], cal["y"])) if cal else raw
    return {"z": z, "raw": raw, "risk": risk, "weight_set": ws}


def shipped_ensemble():
    """Reference outputs of the shipped `models/ensemble.json` (read only): every subset of
    components, logits inside and beyond its clip, sets without fitted weights (no risk)."""
    with open(SHIPPED_ENSEMBLE) as f:
        ens = json.load(f)
    triples = [(-9.0, 11.0, -0.4), (0.7, -2.5, 6.0), (3.2, 0.0, -6.0), (11.0, -9.0, 0.7),
               (-0.4, 3.2, 11.0), (6.5, 6.5, -9.0), (-1.3, -0.2, 2.1)]
    cases = []
    for mask in range(8):
        for t in triples:
            logits = {c: (t[i] if mask >> i & 1 else None) for i, c in enumerate(COMPONENTS)}
            cases.append({"logits": logits, "out": ensemble_combine(ens, logits)})
    dump(os.path.join(OUT, "expected_shipped_ensemble.json"),
         {"source": "models/ensemble.json", "cases": cases})


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
        f.write("\n".join(normalize("pypi", n) for n in POPULAR_PYPI) + "\n")
    with open(os.path.join(MODELS, "popular_npm.txt"), "w") as f:
        f.write("\n".join(normalize("npm", n) for n in POPULAR_NPM) + "\n")
    pops = {"pypi": Popular("pypi", POPULAR_PYPI), "npm": Popular("npm", POPULAR_NPM)}
    n_buckets = 4096
    nf = len(NUMERIC_FEATURES)
    name_model = {
        "format": "customs-name-lr-v1",
        "numeric_features": NUMERIC_FEATURES,
        "max_distance": MAX_DISTANCE,
        "ngram_min": 1,
        "ngram_max": 4,
        "n_buckets": n_buckets,
        "hash": "fnv1a32",
        "ecosystems": {},
    }
    ngws = {}
    for eco in ("pypi", "npm"):
        ngw = rng.normal(0, 0.05, n_buckets).astype(np.float32)
        ngws[eco] = ngw
        name_model["ecosystems"][eco] = {
            "popular": "popular_%s.txt" % eco,
            "mean": [float(np.round(v, 4)) for v in rng.uniform(0, 2, nf)],
            "std": [float(np.round(v, 4)) for v in rng.uniform(0.5, 3, nf)],
            "numeric_weights": [float(np.round(v, 6)) for v in rng.normal(0, 0.8, nf)],
            "ngram_weights": b64(ngw)["data"],
            "bias": -0.75 if eco == "pypi" else -0.5,
        }
    dump(os.path.join(MODELS, "name_model.json"), name_model)
    ncases = []
    for eco, name in NAME_CASES:
        f, buckets, logit = name_score(name_model, eco, name, pops[eco], ngws[eco])
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
    # Email tokens reuse existing rows: one key stored in plaintext, one already hashed
    # (as the exporter writes it), so lookups must key both the file and the token.
    vocab["maintainer@example.com"] = vocab["STR"]
    vocab[vocab_key("dev@example.org")] = vocab["http"]
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
    activations = ["relu", "none"]
    cnn = {
        "format": "customs-code-cnn-v1",
        "max_len": 40,
        "vocab": vocab,
        "embedding": b64(emb),
        "convs": [{"kernel": int(w.shape[2]), "weight": b64(w), "bias": b64(b)} for w, b in convs],
        "dense": [{"weight": b64(w), "bias": b64(b), "activation": a}
                  for (w, b), a in zip(dense, activations)],
    }
    dump(os.path.join(MODELS, "code_nn.json"), cnn)
    arrays = {"embedding": emb, "convs": convs, "dense": dense, "activations": activations}
    ccases = []
    token_pool = vocab_tokens[2:] + ["unknown_a", "unknown_b", "zzz"]
    for i in range(27):
        n = [0, 1, 3, 4, 10, 15, 16, 17, 39, 40, 41, 75][i % 12]
        toks = [str(token_pool[j]) for j in rng.integers(0, len(token_pool), n)]
        ids, logit = cnn_forward(cnn, arrays, toks)
        ccases.append({"tokens": toks, "ids": ids, "logit": logit})
    for toks in (
        ["setup", "(", "author_email", "=", "maintainer@example.com", ")"],
        ["dev@example.org", "Dev@Example.org", "other@example.org", "a@b", "x@y.c",
         "user@host.co.uk", "dev@example.org."],
    ):
        ids, logit = cnn_forward(cnn, arrays, toks)
        ccases.append({"tokens": toks, "ids": ids, "logit": logit})
    dump(os.path.join(OUT, "expected_cnn.json"), {"cases": ccases})

    # Ensemble.
    ens = {
        "format": "customs-ensemble-v1",
        "components": COMPONENTS,
        "weights": {"code_gbdt": 1.1, "code_nn": 0.6, "name": 0.9},
        "bias": -0.4,
        "fallbacks": [
            {"missing": ["code_nn"], "weights": {"code_gbdt": 1.4, "name": 1.0}, "bias": -0.3},
            {"missing": ["name"], "weights": {"code_gbdt": 1.2, "code_nn": 0.7}, "bias": -0.2},
            {"missing": ["code_nn", "name"], "weights": {"code_gbdt": 1.5}, "bias": -0.6,
             "calibration": isotonic(6)},
        ],
        "calibration": isotonic(10),
        "thresholds": {"warn": 0.5, "block": 0.85, "target_fpr_warn": 0.01,
                       "target_fpr_block": 0.001},
        "clip": 4.0,
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
    # Logits beyond the clip, and a name alone (no fallback fitted for it: no risk).
    for logits in (
        {"code_gbdt": 9.5, "code_nn": -12.0, "name": 0.3},
        {"code_gbdt": -7.25, "code_nn": None, "name": 5.5},
        {"code_gbdt": None, "code_nn": None, "name": 8.0},
        {"code_gbdt": 4.0, "code_nn": None, "name": None},
    ):
        ecases.append({"logits": logits, "out": ensemble_combine(ens, logits)})
    dump(os.path.join(OUT, "expected_ensemble.json"), {"cases": ecases})

    manifest = {
        "model_version": "fixture.2",
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
    for i in range(14):
        eco, name = NAME_CASES[(i * 5) % len(NAME_CASES)]
        feats = random_features() if i % 4 != 3 else {}
        # None: the archive was never tokenized, so the CNN is skipped. []: tokenized with no
        # install-time code, which the CNN still scores (it was trained on such packages).
        if i % 6 == 2:
            toks = None
        elif i % 6 == 5:
            toks = []
        else:
            toks = [str(token_pool[j]) for j in rng.integers(0, len(token_pool), 20)]
        use_name = i % 5 != 4
        logits, scores = {}, {}
        if feats:
            g = gbdt_predict(gbdt, feats)
            logits["code_gbdt"], scores["code_gbdt"] = g["raw"], g["calibrated"]
        else:
            logits["code_gbdt"], scores["code_gbdt"] = None, None
        if toks is not None:
            _, l = cnn_forward(cnn, arrays, toks)
            logits["code_nn"], scores["code_nn"] = l, sigmoid(l)
        else:
            logits["code_nn"], scores["code_nn"] = None, None
        if use_name:
            _, _, l = name_score(name_model, eco, name, pops[eco], ngws[eco])
            logits["name"], scores["name"] = l, sigmoid(l)
        else:
            logits["name"], scores["name"] = None, None
        out = ensemble_combine(ens, logits)
        acases.append({"ecosystem": eco, "name": name if use_name else None,
                       "features": feats, "tokens": toks, "scores": scores,
                       "risk": out["risk"] if out else None,
                       "weight_set": out["weight_set"] if out else None})
    dump(os.path.join(OUT, "expected_assess.json"), {"cases": acases})
    shipped_ensemble()
    print("wrote fixtures to", OUT)


if __name__ == "__main__":
    main()
