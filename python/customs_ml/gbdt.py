"""Gradient-boosted trees over scanner features, plus export to the Customs JSON format.

The exported format (docs/DESIGN.md section 5) is independent of LightGBM so the Rust
firewall can score packages with no native ML dependency. :func:`predict_raw_exported`
re-implements the Rust inference in Python; tests assert it matches LightGBM exactly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import lightgbm as lgb
import numpy as np
from sklearn.isotonic import IsotonicRegression

DEFAULT_PARAMS = {
    "objective": "binary",
    "learning_rate": 0.05,
    "num_leaves": 31,
    "min_data_in_leaf": 20,
    "feature_fraction": 0.8,
    "bagging_fraction": 0.8,
    "bagging_freq": 1,
    "lambda_l2": 1.0,
    # Features are never missing; disabling missing-value handling keeps every split a
    # plain `x <= threshold` test, which is what the exported format encodes.
    "use_missing": False,
    "verbose": -1,
    "num_threads": 4,
    "seed": 7,
    "deterministic": True,
}


@dataclass
class Trained:
    booster: lgb.Booster
    feature_names: list[str]
    best_iteration: int


def train(
    X_tr: np.ndarray,
    y_tr: np.ndarray,
    w_tr: np.ndarray,
    X_va: np.ndarray,
    y_va: np.ndarray,
    w_va: np.ndarray,
    feature_names: list[str],
    params: dict | None = None,
    num_boost_round: int = 2000,
) -> Trained:
    p = {**DEFAULT_PARAMS, **(params or {})}
    dtr = lgb.Dataset(X_tr, y_tr, weight=w_tr, feature_name=feature_names, free_raw_data=False)
    dva = lgb.Dataset(X_va, y_va, weight=w_va, reference=dtr)
    booster = lgb.train(
        p,
        dtr,
        num_boost_round=num_boost_round,
        valid_sets=[dva],
        callbacks=[lgb.early_stopping(100, verbose=False)],
    )
    return Trained(booster, feature_names, booster.best_iteration or num_boost_round)


def predict_raw(t: Trained, X: np.ndarray) -> np.ndarray:
    return t.booster.predict(X, raw_score=True, num_iteration=t.best_iteration)


# ---------------------------------------------------------------- calibration


def fit_isotonic(raw: np.ndarray, y: np.ndarray, w: np.ndarray | None = None) -> dict:
    """Isotonic map from sigmoid(raw) to probability, as interpolation knots."""
    p = 1.0 / (1.0 + np.exp(-raw))
    iso = IsotonicRegression(y_min=0.0, y_max=1.0, out_of_bounds="clip")
    iso.fit(p, y, sample_weight=w)
    return {
        "method": "isotonic",
        "x": [float(v) for v in iso.X_thresholds_],
        "y": [float(v) for v in iso.y_thresholds_],
    }


def fit_platt(raw: np.ndarray, y: np.ndarray, w: np.ndarray | None = None) -> dict:
    """Platt scaling, written as dense piecewise-linear knots over sigmoid(raw).

    Isotonic regression is a step function: at the top of the score range it ties many
    packages into one plateau, so a strict threshold (0.1% FPR) has to sit above the whole
    plateau and throws away detections. Platt scaling is strictly increasing, so ranking
    is preserved and thresholds are as fine-grained as the scores. Encoding it as knots
    lets it share the isotonic map's artifact format and Rust interpolation code.
    """
    from sklearn.linear_model import LogisticRegression

    lr = LogisticRegression(C=1e6, max_iter=1000)
    lr.fit(raw.reshape(-1, 1), y, sample_weight=w)
    a, b = float(lr.coef_[0, 0]), float(lr.intercept_[0])
    z = np.linspace(-16.0, 16.0, 641)
    x = 1.0 / (1.0 + np.exp(-z))
    yk = 1.0 / (1.0 + np.exp(-(a * z + b)))
    return {"method": "platt", "a": a, "b": b, "x": x.tolist(), "y": yk.tolist()}


def apply_calibration(cal: dict, p: np.ndarray) -> np.ndarray:
    return np.interp(p, np.asarray(cal["x"]), np.asarray(cal["y"]))


def stacked_risk(
    ens: dict,
    logits: dict[str, np.ndarray],
    weights: dict[str, float] | None = None,
    bias: float | None = None,
) -> np.ndarray:
    """Calibrated risk from an exported ensemble: clipped component logits, weighted sum,
    sigmoid, calibration (what the binary computes). ``weights``/``bias`` default to the
    full stack; pass a fallback's to score without a component (``logits`` then omits it).
    """
    w = ens["weights"] if weights is None else weights
    z = ens["bias"] if bias is None else bias
    b = ens.get("clip") or np.inf
    for k, x in logits.items():
        z = z + w[k] * np.clip(x, -b, b)
    return apply_calibration(ens["calibration"], 1 / (1 + np.exp(-z)))


# ---------------------------------------------------------------- export


def export(t: Trained, calibration: dict | None) -> dict:
    dump = t.booster.dump_model(num_iteration=t.best_iteration)
    names = dump["feature_names"]
    trees = []
    for info in dump["tree_info"]:
        nodes: list[dict] = []
        _flatten(info["tree_structure"], nodes)
        trees.append({"nodes": nodes})
    return {
        "feature_names": names,
        "base_score": 0.0,
        "objective": "binary",
        "trees": trees,
        "calibration": calibration,
    }


def _flatten(node: dict, out: list[dict]) -> int:
    idx = len(out)
    if "leaf_value" in node:
        out.append({"leaf": float(node["leaf_value"])})
        return idx
    if node.get("decision_type", "<=") != "<=":
        raise ValueError(f"unsupported split type {node.get('decision_type')}")
    out.append({})  # placeholder, children are appended after
    left = _flatten(node["left_child"], out)
    right = _flatten(node["right_child"], out)
    out[idx] = {
        "split": int(node["split_feature"]),
        "threshold": float(node["threshold"]),
        "left": left,
        "right": right,
        "default_left": bool(node.get("default_left", True)),
        "value": float(node["internal_value"]),
    }
    return idx


def predict_raw_exported(model: dict, X: np.ndarray) -> np.ndarray:
    """Reference implementation of the Rust tree inference (for parity tests)."""
    out = np.full(len(X), model["base_score"], dtype=float)
    for tree in model["trees"]:
        nodes = tree["nodes"]
        for i, x in enumerate(X):
            n = nodes[0]
            while "leaf" not in n:
                v = x[n["split"]]
                go_left = n["default_left"] if np.isnan(v) else v <= n["threshold"]
                n = nodes[n["left"] if go_left else n["right"]]
            out[i] += n["leaf"]
    return out


def contributions_exported(model: dict, x: np.ndarray) -> tuple[float, np.ndarray]:
    """Saabas path attribution: (bias, per-feature contribution) summing to the raw score."""
    contrib = np.zeros(len(model["feature_names"]))
    bias = model["base_score"]
    for tree in model["trees"]:
        nodes = tree["nodes"]
        n = nodes[0]
        if "leaf" in n:
            bias += n["leaf"]
            continue
        bias += n["value"]
        while "leaf" not in n:
            v = x[n["split"]]
            go_left = n["default_left"] if np.isnan(v) else v <= n["threshold"]
            child = nodes[n["left"] if go_left else n["right"]]
            child_val = child["leaf"] if "leaf" in child else child["value"]
            contrib[n["split"]] += child_val - n["value"]
            n = child
    return bias, contrib


def save(model: dict, path: Path) -> None:
    path.write_text(json.dumps(model, separators=(",", ":")), encoding="utf-8")
