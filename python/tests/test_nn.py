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
