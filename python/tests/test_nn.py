import numpy as np
import torch

from customs_ml import nn as cnn


def test_export_forward_matches_torch():
    rng = np.random.default_rng(0)
    toks = ["os", "system", "(", "<str>", ")", "import", "base64", "exec", "requests", "get"]
    docs = [[toks[i] for i in rng.integers(0, len(toks), rng.integers(1, 80))] for _ in range(40)]
    cfg = cnn.Config(max_len=64, emb_dim=8, channels=6, hidden=5, kernels=(3, 5), min_df=1)
    vocab = cnn.build_vocab(docs, cfg)
    torch.manual_seed(0)
    model = cnn.CodeCNN(len(vocab), cfg).eval()
    exported = cnn.export(model, vocab, cfg)
    X = cnn.encode(docs, vocab, cfg.max_len)
    for i, d in enumerate(docs):
        with torch.no_grad():
            ref = float(model(cnn._trim(torch.from_numpy(X[i : i + 1]))))
        assert abs(cnn.numpy_forward(exported, d) - ref) < 1e-4


def test_training_learns_a_trivial_signal():
    rng = np.random.default_rng(1)
    docs, y = [], []
    for _ in range(300):
        bad = rng.uniform() < 0.5
        d = ["import", "x", "=", "<num>"] * int(rng.integers(2, 10))
        if bad:
            d[rng.integers(0, len(d))] = "exec"
        docs.append(d)
        y.append(int(bad))
    y = np.array(y)
    cfg = cnn.Config(
        max_len=64,
        emb_dim=8,
        channels=8,
        hidden=8,
        kernels=(3,),
        epochs=15,
        patience=15,
        min_df=1,
        lr=1e-2,
    )
    vocab = cnn.build_vocab(docs, cfg)
    X = cnn.encode(docs, vocab, cfg.max_len)
    model, hist = cnn.train(
        X[:200], y[:200], np.ones(200), X[200:], y[200:], len(vocab), cfg, log=lambda *_: None
    )
    assert hist[-1]["val_pr_auc"] > 0.95 or max(h["val_pr_auc"] for h in hist) > 0.95


def test_batched_scores_equal_single_document_scores():
    rng = np.random.default_rng(2)
    toks = ["os", "system", "(", "<str>", ")", "import", "exec", "x", "=", "<num>"]
    # Lengths straddle MIN_LEN so batches mix padded and unpadded documents.
    docs = [[toks[i] for i in rng.integers(0, len(toks), n)] for n in (3, 15, 16, 40, 200, 7)]
    cfg = cnn.Config(max_len=256, emb_dim=8, channels=6, hidden=5, kernels=(3, 9), min_df=1)
    vocab = cnn.build_vocab(docs, cfg)
    torch.manual_seed(1)
    model = cnn.CodeCNN(len(vocab), cfg).eval()
    # Non-zero conv biases make padding windows score high if they leak into the max.
    with torch.no_grad():
        for c in model.convs:
            c.bias.fill_(0.5)
    exported = cnn.export(model, vocab, cfg)
    batched = cnn.predict_logits(model, cnn.encode(docs, vocab, cfg.max_len), batch=6)
    for d, b in zip(docs, batched, strict=True):
        assert abs(cnn.numpy_forward(exported, d) - b) < 1e-4


def test_vocab_does_not_depend_on_hash_seed():
    # Equal document frequencies everywhere: the cut and the ids must come from the tokens,
    # not from set iteration order, which changes with PYTHONHASHSEED.
    import subprocess
    import sys

    code = (
        "from customs_ml import nn as cnn\n"
        "docs = [[f't{i}' for i in range(200)] for _ in range(3)]\n"
        "cfg = cnn.Config(vocab_size=52, min_df=1)\n"
        "print(sorted(cnn.build_vocab(docs, cfg).items(), key=lambda kv: kv[1]))\n"
    )
    outs = {
        subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
            env={**__import__("os").environ, "PYTHONHASHSEED": seed},
            encoding="utf-8",
        ).stdout
        for seed in ("1", "2", "3")
    }
    assert len(outs) == 1


def test_vocab_key_hashes_emails():
    # Same value as vocab_key's test in crates/customs-model/src/cnn.rs.
    assert cnn.vocab_key("dev@example.org") == "<email:3506ad6ec84933e2>"
    for t in [
        "os",
        "@",
        "@babel/core",
        "@out.txt",
        "user@localhost",
        "a@b.c",
        "x@1.2.3.4",
        "a@b..com",
        "a@@b.com",
        "<email:3506ad6ec84933e2>",
    ]:
        assert cnn.vocab_key(t) == t


def test_vocabulary_never_stores_plaintext_emails():
    docs = [["setup", "dev@example.org", "os"]] * 3
    cfg = cnn.Config(max_len=8, emb_dim=4, channels=2, hidden=2, kernels=(1,), min_df=1)
    vocab = cnn.build_vocab(docs, cfg)
    assert "dev@example.org" not in vocab
    assert "<email:3506ad6ec84933e2>" in vocab
    X = cnn.encode(docs, vocab, cfg.max_len)
    assert X[0, 1] == vocab["<email:3506ad6ec84933e2>"]
    torch.manual_seed(0)
    exported = cnn.export(cnn.CodeCNN(len(vocab), cfg).eval(), vocab, cfg)
    plain = dict(
        exported,
        vocab={("dev@example.org" if k.startswith("<email:") else k): v for k, v in vocab.items()},
    )
    assert cnn.numpy_forward(exported, docs[0]) == cnn.numpy_forward(plain, docs[0])


def test_parity_streams_are_synthetic_and_cover_lengths():
    vocab = {"<pad>": 0, "<unk>": 1, "os": 2, "exec": 3}
    streams = cnn.parity_streams({"vocab": vocab, "max_len": 32}, n=25, seed=0)
    assert len(streams) == 25
    lengths = {len(s) for s in streams}
    assert {0, 1, 31, 32, 33, 64} <= lengths
    allowed = set(vocab) | {
        "<file>",
        "import",
        ".",
        "system",
        "(",
        ")",
        "<str>",
        "setup",
        "author_email",
        "=",
        "dev@example.org",
    }
    assert all(t in allowed or t.startswith("unseen_") for s in streams for t in s)
    assert streams == cnn.parity_streams({"vocab": vocab, "max_len": 32}, n=25, seed=0)
