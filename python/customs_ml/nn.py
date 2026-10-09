"""A small convolutional network over install-surface tokens (PyTorch).

The tree model sees counts of hand-defined indicators. This model reads the code itself:
the token stream of everything that runs at install or import time, so it can pick up
patterns no indicator names (unusual call sequences, payload-staging idioms, obfuscator
output). It is deliberately small (about 1 million parameters) so it trains on CPU and runs
in the Rust firewall with a plain forward pass.

Architecture: token embedding, parallel 1D convolutions with several kernel widths, ReLU,
global max pooling, then a two-layer MLP to one logit. Exported to the JSON format in
docs/DESIGN.md section 5.
"""

from __future__ import annotations

import base64
import json
import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import torch
from torch import nn

PAD, UNK = 0, 1
# Documents shorter than this are right-padded to it (also in the Rust forward pass).
MIN_LEN = 16
# Email-shaped tokens are stored in the vocabulary as a hash (see ``vocab_key``), so a
# trained model never ships a plaintext address. Mirrors ``is_email`` in
# crates/customs-model/src/cnn.rs.
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}")


def fnv1a64(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


def vocab_key(token: str) -> str:
    """``<email:{fnv1a64:016x}>`` for an email-shaped token, the token itself otherwise."""
    if "@" in token and EMAIL.fullmatch(token):
        return f"<email:{fnv1a64(token.encode()):016x}>"
    return token


@dataclass
class Config:
    max_len: int = 1024
    vocab_size: int = 16000
    min_df: int = 3
    emb_dim: int = 48
    kernels: tuple[int, ...] = (3, 5, 9)
    channels: int = 96
    hidden: int = 64
    dropout: float = 0.3
    # Probability of replacing a training token with <unk>. Forces the model to use many
    # weak cues instead of memorizing one campaign's exact strings, which matters on a
    # time split where test campaigns are new.
    token_dropout: float = 0.0
    lr: float = 2e-3
    weight_decay: float = 1e-4
    batch_size: int = 64
    epochs: int = 12
    patience: int = 3
    seed: int = 7
    extra: dict = field(default_factory=dict)


def build_vocab(docs: Sequence[Sequence[str]], cfg: Config) -> dict[str, int]:
    """Vocabulary by document frequency, so a token repeated 1,000 times in one file
    does not outrank a token used once in many packages.

    Ties break by token. ``Counter.most_common`` would break them by insertion order, which
    follows ``set`` iteration and so changes with each process's string hash seed: the
    same data and seed then gave a different vocabulary, and a different model, per run.
    """
    df = Counter()
    for d in docs:
        df.update(set(d[: cfg.max_len]))
    ranked = sorted(df.items(), key=lambda tc: (-tc[1], tc[0]))[: cfg.vocab_size - 2]
    common = [t for t, c in ranked if c >= cfg.min_df]
    vocab = {"<pad>": PAD, "<unk>": UNK}
    for t in common:
        vocab.setdefault(vocab_key(t), len(vocab))
    return vocab


def encode(docs: Sequence[Sequence[str]], vocab: dict[str, int], max_len: int) -> np.ndarray:
    # Length is at least the widest kernel so an empty document still yields a valid conv.
    out = np.zeros((len(docs), max_len), dtype=np.int64)
    for i, d in enumerate(docs):
        ids = [vocab.get(vocab_key(t), UNK) for t in d[:max_len]]
        out[i, : len(ids)] = ids
    return out


class CodeCNN(nn.Module):
    def __init__(self, vocab_size: int, cfg: Config):
        super().__init__()
        self.emb = nn.Embedding(vocab_size, cfg.emb_dim, padding_idx=PAD)
        self.convs = nn.ModuleList(nn.Conv1d(cfg.emb_dim, cfg.channels, k) for k in cfg.kernels)
        self.drop = nn.Dropout(cfg.dropout)
        self.fc1 = nn.Linear(cfg.channels * len(cfg.kernels), cfg.hidden)
        self.fc2 = nn.Linear(cfg.hidden, 1)

    def forward(self, ids: torch.Tensor) -> torch.Tensor:
        x = self.emb(ids).transpose(1, 2)  # (B, D, L)
        # A document scored alone is padded to MIN_LEN (or the widest kernel) and no
        # further; in a batch it is padded to the longest member. Windows that exist only
        # because of that extra batch padding are masked out (set to 0 after ReLU, which
        # cannot change a max over non-negative values), so a score never depends on what
        # else was in the batch and matches the single-document forward pass in Rust.
        eff = (ids != PAD).sum(dim=1).clamp(min=MIN_LEN)  # (B,)
        pooled = []
        for c in self.convs:
            y = torch.relu(c(x))  # (B, C, L - k + 1)
            k = c.kernel_size[0]
            pos = torch.arange(y.shape[2], device=y.device)
            valid = pos[None, :] <= (torch.maximum(eff, torch.tensor(k)) - k)[:, None]
            pooled.append((y * valid[:, None, :]).amax(dim=2))
        h = self.drop(torch.cat(pooled, dim=1))
        h = self.drop(torch.relu(self.fc1(h)))
        return self.fc2(h).squeeze(1)


def train(
    X_tr: np.ndarray,
    y_tr: np.ndarray,
    w_tr: np.ndarray,
    X_va: np.ndarray,
    y_va: np.ndarray,
    vocab_size: int,
    cfg: Config,
    log=print,
) -> tuple[CodeCNN, list[dict]]:
    from sklearn.metrics import average_precision_score

    torch.manual_seed(cfg.seed)
    rng = np.random.default_rng(cfg.seed)
    model = CodeCNN(vocab_size, cfg)
    opt = torch.optim.AdamW(model.parameters(), lr=cfg.lr, weight_decay=cfg.weight_decay)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=cfg.epochs)
    loss_fn = nn.BCEWithLogitsLoss(reduction="none")
    Xt, yt, wt = (
        torch.from_numpy(X_tr),
        torch.from_numpy(y_tr).float(),
        torch.from_numpy(w_tr).float(),
    )
    best, best_state, bad, history = -1.0, None, 0, []
    lengths = (X_tr != PAD).sum(axis=1)
    for epoch in range(cfg.epochs):
        model.train()
        total = 0.0
        for batch in _length_buckets(lengths, cfg.batch_size, rng):
            idx = torch.from_numpy(batch)
            # Trim padding columns shared by the whole batch: most packages are short.
            xb = _trim(Xt[idx])
            if cfg.token_dropout > 0:
                drop = (torch.rand(xb.shape) < cfg.token_dropout) & (xb != PAD)
                xb = xb.masked_fill(drop, UNK)
            loss = (loss_fn(model(xb), yt[idx]) * wt[idx]).sum() / wt[idx].sum()
            opt.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            total += loss.item() * len(idx)
        sched.step()
        va = predict_logits(model, X_va)
        ap = float(average_precision_score(y_va, va))
        history.append({"epoch": epoch, "train_loss": total / len(Xt), "val_pr_auc": ap})
        log(f"epoch {epoch} loss {total / len(Xt):.4f} val PR-AUC {ap:.4f}")
        if ap > best:
            best, bad = ap, 0
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= cfg.patience:
                break
    model.load_state_dict(best_state)
    return model, history


def _length_buckets(lengths: np.ndarray, batch_size: int, rng: np.random.Generator):
    """Batches of similar length in random order.

    Token counts range from a few dozen to the cap, so random batches would spend most of
    their compute on padding. Shuffling, then sorting within windows of 50 batches, keeps
    batches length-homogeneous while preserving randomness across epochs.
    """
    order = rng.permutation(len(lengths))
    window = batch_size * 50
    batches = []
    for s in range(0, len(order), window):
        chunk = order[s : s + window]
        chunk = chunk[np.argsort(lengths[chunk], kind="stable")]
        batches += [chunk[i : i + batch_size] for i in range(0, len(chunk), batch_size)]
    rng.shuffle(batches)
    return batches


def _trim(xb: torch.Tensor, min_len: int = MIN_LEN) -> torch.Tensor:
    nz = (xb != PAD).any(dim=0).nonzero()
    end = int(nz.max()) + 1 if len(nz) else 0
    return xb[:, : max(end, min_len)]


@torch.no_grad()
def predict_logits(model: CodeCNN, X: np.ndarray, batch: int = 256) -> np.ndarray:
    model.eval()
    out = []
    # Score in length order (much less padding), then restore the input order.
    order = np.argsort((X != PAD).sum(axis=1), kind="stable")
    Xt = torch.from_numpy(X[order])
    for s in range(0, len(Xt), batch):
        out.append(model(_trim(Xt[s : s + batch])).numpy())
    res = np.empty(len(X), dtype=np.float32)
    if out:
        res[order] = np.concatenate(out)
    return res


# ---------------------------------------------------------------- export


def _tensor(t: torch.Tensor) -> dict:
    a = t.detach().cpu().numpy().astype("<f4")
    return {"shape": list(a.shape), "data": base64.b64encode(a.tobytes()).decode("ascii")}


def export(model: CodeCNN, vocab: dict[str, int], cfg: Config) -> dict:
    return {
        "format": "customs-code-cnn-v1",
        "max_len": cfg.max_len,
        "vocab": vocab,
        "embedding": _tensor(model.emb.weight),
        "convs": [
            {"kernel": c.kernel_size[0], "weight": _tensor(c.weight), "bias": _tensor(c.bias)}
            for c in model.convs
        ],
        "dense": [
            {
                "weight": _tensor(model.fc1.weight),
                "bias": _tensor(model.fc1.bias),
                "activation": "relu",
            },
            {
                "weight": _tensor(model.fc2.weight),
                "bias": _tensor(model.fc2.bias),
                "activation": "none",
            },
        ],
    }


def numpy_forward(exported: dict, tokens: Sequence[str]) -> float:
    """Reference forward pass from the exported JSON (mirrors the Rust implementation)."""

    def arr(t):
        return np.frombuffer(base64.b64decode(t["data"]), dtype="<f4").reshape(t["shape"])

    vocab = {vocab_key(k): v for k, v in exported["vocab"].items()}
    ids = [vocab.get(vocab_key(t), UNK) for t in tokens[: exported["max_len"]]]
    emb = arr(exported["embedding"])
    max_k = max(c["kernel"] for c in exported["convs"])
    # Sequences shorter than MIN_LEN are right-padded with <pad> to MIN_LEN.
    ids = ids + [PAD] * max(0, max(MIN_LEN, max_k) - len(ids))
    x = emb[ids].astype(np.float32)  # (L, D)
    pooled = []
    for c in exported["convs"]:
        w, b, k = arr(c["weight"]), arr(c["bias"]), c["kernel"]  # w: (C, D, k)
        L = x.shape[0] - k + 1
        windows = np.stack([x[i : i + L] for i in range(k)], axis=2)  # (L, D, k)
        y = np.einsum("ldk,cdk->lc", windows, w) + b
        pooled.append(np.maximum(y, 0).max(axis=0))
    h = np.concatenate(pooled)
    for layer in exported["dense"]:
        h = arr(layer["weight"]) @ h + arr(layer["bias"])
        if layer["activation"] == "relu":
            h = np.maximum(h, 0)
    return float(h[0])


def parity_streams(exported: dict, n: int = 25, seed: int = 0) -> list[list[str]]:
    """Synthetic token streams for the Rust parity fixtures (``models/parity/code_nn.json``).

    Draws from the model's own vocabulary plus tokens it has never seen, at lengths from
    empty to past ``max_len``, so the fixtures exercise lookup, padding and truncation
    without copying any real package's code into the repository.
    """
    rng = np.random.default_rng(seed)
    vocab = [t for t in exported["vocab"] if t not in ("<pad>", "<unk>")]
    max_len = exported["max_len"]
    fixed = [
        [],
        ["<file>"],
        ["<file>", "import", "os", "os", ".", "system", "(", "<str>", ")"],
        ["<file>", "setup", "(", "author_email", "=", "dev@example.org", ")"],
    ]
    lengths = [1, 3, 8, 15, 16, 17, 40, 100, 300, max_len - 1, max_len, max_len + 1, 2 * max_len]
    out = [list(f) for f in fixed]
    while len(out) < n:
        length = lengths[(len(out) - len(fixed)) % len(lengths)]
        stream = ["<file>"]
        while len(stream) < length:
            if rng.random() < 0.05:
                stream.append(f"unseen_{int(rng.integers(0, 1000))}")
            else:
                stream.append(vocab[int(rng.integers(0, len(vocab)))])
        out.append(stream[:length])
    return out[:n]


def save(exported: dict, path: Path) -> None:
    path.write_text(json.dumps(exported, separators=(",", ":")), encoding="utf-8")
