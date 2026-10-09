"""Run the Rust scanner over the corpus and assemble the training table.

Features come from ``customs-scan``, the same code the firewall runs at install time, so
the model is trained on exactly what it will see in production. The Python bindings are
used when importable; otherwise the CLI's parallel batch mode.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pandas as pd

from . import config
from .malicious import canonicalize_benign


def scanner_bin() -> str:
    """``$CUSTOMS_SCAN_BIN``, else this checkout's release build, else ``customs-scan`` on PATH."""
    env = os.environ.get("CUSTOMS_SCAN_BIN")
    if env:
        return env
    repo_bin = config.repo_binary("customs-scan")
    if repo_bin.exists():
        return str(repo_bin)
    found = shutil.which("customs-scan")
    if not found:
        raise FileNotFoundError(
            "customs-scan not found; run `cargo build --release -p customs-scan` first"
        )
    return found


SCAN_CHUNK = 4000


def scan_paths(
    paths: list[str], tokens: bool = True, jobs: int | None = None, ecosystem: str | None = None
) -> list[dict]:
    """Scan archives in parallel; returns one dict per input path, in order.

    Runs the scanner on chunks of ``SCAN_CHUNK`` paths, so the scanner's JSON output (token
    streams make it about 40 KB per archive) never needs more than a bounded amount of
    temporary disk.
    """
    if len(paths) > SCAN_CHUNK:
        out: list[dict] = []
        for i in range(0, len(paths), SCAN_CHUNK):
            out += scan_paths(paths[i : i + SCAN_CHUNK], tokens, jobs, ecosystem)
        return out
    with tempfile.TemporaryDirectory() as td:
        inp = Path(td) / "paths.txt"
        out = Path(td) / "out.jsonl"
        inp.write_text("\n".join(paths) + "\n", encoding="utf-8")
        cmd = [scanner_bin(), "batch", "--input", str(inp), "--output", str(out)]
        if tokens:
            cmd.append("--tokens")
        if jobs:
            cmd += ["--jobs", str(jobs)]
        if ecosystem:
            cmd += ["--ecosystem", ecosystem]
        subprocess.run(cmd, check=True)
        # split("\n"), not splitlines(): scanner output can contain U+2028 and friends.
        return [json.loads(line) for line in out.read_text(encoding="utf-8").split("\n") if line]


def canonicalize_benign_corpus(
    manifest: Path, out_dir: Path, delete_original: bool = False
) -> pd.DataFrame:
    """Rewrite every benign archive in the canonical form used for malicious samples.

    With ``delete_original`` the upstream archive is removed once its canonical copy
    exists, which halves the corpus footprint on disk.
    """
    df = pd.read_json(manifest, lines=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    canon = []
    for row in df.itertuples():
        ext = ".tgz" if row.ecosystem == "npm" else ".tar.gz"
        dest = out_dir / row.ecosystem / f"{row.sha256[:2]}" / f"{row.sha256}{ext}"
        if not dest.exists():
            if not Path(row.path).exists():
                canon.append(None)
                continue
            try:
                blob = canonicalize_benign(
                    Path(row.path), row.ecosystem, row.name, str(row.version)
                )
            except Exception:  # noqa: BLE001 - malformed upstream archive, skip it
                canon.append(None)
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(blob)
        if delete_original and Path(row.path).exists():
            Path(row.path).unlink()
        canon.append(str(dest))
    df["canonical_path"] = canon
    return df.dropna(subset=["canonical_path"])


def build_table() -> pd.DataFrame:
    """Join corpus metadata with scanner output into one table (features + tokens)."""
    mal = pd.read_json(config.sub("malicious") / "manifest.jsonl", lines=True)
    mal = mal[(mal.error == "") & mal.path.astype(bool)].copy()
    mal = mal.drop_duplicates("sha256")
    mal["label"] = 1
    mal["date"] = pd.to_datetime(mal.discovered, utc=True)
    mal["tier"] = mal.kind
    mal["canonical_path"] = mal.path

    ben = canonicalize_benign_corpus(
        config.sub("benign") / "manifest.jsonl", config.sub("benign_canonical")
    )
    ben = ben.drop_duplicates("sha256").copy()
    ben["label"] = 0
    ben["date"] = pd.to_datetime(ben.upload_time, utc=True, errors="coerce")
    ben["kind"] = "benign"

    cols = ["ecosystem", "name", "version", "label", "date", "tier", "kind", "canonical_path"]
    df = pd.concat([mal[cols], ben[cols]], ignore_index=True)
    reports = scan_paths(df.canonical_path.tolist(), tokens=True)
    feats, toks, errs = [], [], []
    for r in reports:
        if "error" in r and "features" not in r:
            feats.append(None)
            toks.append(None)
            errs.append(r["error"])
        else:
            feats.append(r["features"])
            toks.append(r.get("tokens") or [])
            errs.append(";".join(r.get("errors") or []))
    df["scan_error"] = errs
    df["tokens"] = toks
    ok = [f is not None for f in feats]
    df = df[ok].reset_index(drop=True)
    fdf = pd.DataFrame([f for f in feats if f is not None])
    return pd.concat([df, fdf.add_prefix("f_")], axis=1)
