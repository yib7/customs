import numpy as np
import pandas as pd

from customs_ml import external


def test_matched_fpr_uses_benign_test_quantiles():
    rng = np.random.default_rng(0)
    df = pd.DataFrame(
        {
            "label": [0] * 1000 + [1] * 10,
            "split_temporal": ["test"] * 1010,
            "ens_risk": np.r_[rng.uniform(0, 1, 1000), np.ones(10)],
        }
    )
    g = pd.DataFrame({"risk": [0.995, 0.5, 0.0, np.nan]})
    out = external._matched_fpr(df, g)
    assert out["benign_test_n"] == 1000
    # Threshold near the 99th percentile of uniform benign scores; NaN risks are dropped.
    assert abs(out["0.01"]["threshold"] - 0.99) < 0.02
    assert out["0.01"]["recall"] == 1 / 3
    assert out["0.001"]["threshold"] > out["0.01"]["threshold"]


def test_code_only_risk_uses_the_no_name_fallback():
    ens = {
        "fallbacks": [
            {"missing": ["code_nn"], "weights": {"code_gbdt": 9.0, "name": 9.0}, "bias": 9.0},
            {"missing": ["name"], "weights": {"code_gbdt": 1.0, "code_nn": 0.5}, "bias": -1.0},
        ],
        "calibration": {"x": [0.0, 1.0], "y": [0.0, 1.0]},
    }
    df = pd.DataFrame({"gbdt_logit_temporal": [2.0, 0.0], "cnn_logit_temporal": [0.0, 2.0]})
    r = external.code_only_risk(df, ens)
    z = np.array([1.0, 0.0])
    assert np.allclose(r, 1 / (1 + np.exp(-z)))


def _toks(tag: str) -> list[str]:
    return [f"{tag}{i}" for i in range(40)]


def test_external_rows_take_corpus_clusters_and_never_train_next_to_val_or_test():
    corpus = pd.DataFrame(
        {
            "label": [1, 1, 1, 0],
            "cluster": [10, 20, 30, 40],
            "split_temporal": ["train", "test", "train", "test"],
            "split_grouped": ["train", "train", "val", "test"],
            "tokens": [_toks("a"), _toks("b"), _toks("c"), _toks("d")],
        }
    )
    rows = pd.DataFrame(
        {
            "name": ["twin-of-train", "twin-of-test", "twin-of-val", "fresh", "fresh-copy", "held"],
            "split_temporal": ["train"] * 5 + ["external"],
            "split_grouped": ["train"] * 5 + ["external"],
            "tokens": [_toks("a"), _toks("b"), _toks("c"), _toks("e"), _toks("e"), _toks("b")],
            "cluster": [0, 1, 2, 3, 3, 5],  # positions from evaluate(), not corpus ids
        }
    )
    out = external.place_rows(corpus, rows)
    by = dict(zip(out.name, out.cluster, strict=True))
    # A near-duplicate of a val or test malware sample must not join training.
    assert set(out.name) == {"twin-of-train", "fresh", "fresh-copy", "held"}
    # A near-duplicate of corpus malware shares the corpus cluster id, so novel_mask and the
    # cluster-grouped splits see it as the same campaign.
    assert by["twin-of-train"] == 10
    # Held-out (scored, never trained) rows are kept and take the corpus cluster too.
    assert by["held"] == 20
    # New campaigns get fresh ids above every corpus id, shared by their near-duplicates.
    assert by["fresh"] == by["fresh-copy"] > corpus.cluster.max()


def test_training_row_next_to_a_scored_external_row_is_dropped():
    # adapt() adds held-out rows under split "external": scored, never trained on. A
    # training row in the same near-duplicate cluster would leak that campaign.
    corpus = pd.DataFrame(
        {
            "label": [1],
            "cluster": [7],
            "split_temporal": ["train"],
            "split_grouped": ["train"],
            "tokens": [_toks("a")],
        }
    )
    rows = pd.DataFrame(
        {
            "name": ["dev-copy", "scored", "dev-other"],
            "split_temporal": ["train", "external", "train"],
            "split_grouped": ["train", "external", "train"],
            "tokens": [_toks("x"), _toks("x"), _toks("y")],
            "cluster": [0, 1, 2],
        }
    )
    out = external.place_rows(corpus, rows)
    assert set(out.name) == {"scored", "dev-other"}
    assert out.cluster.min() > 7


def test_score_with_binary_timeout_is_recorded(monkeypatch):
    import subprocess

    def slow(cmd, **kw):
        raise subprocess.TimeoutExpired(cmd, kw.get("timeout"))

    monkeypatch.setattr(subprocess, "run", slow)
    monkeypatch.setenv("CUSTOMS_BIN", "/opt/customs")
    assert external.score_with_binary(["a.tar.gz"], ["a"]) == [{"error": "timeout"}]
