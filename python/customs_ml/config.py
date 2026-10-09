"""Filesystem layout for datasets and intermediate artifacts.

Everything derived from malware samples lives under ``CUSTOMS_DATA`` (outside the
repository). Only trained model artifacts and aggregate metrics are written into the repo.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODELS_DIR = REPO_ROOT / "models"
DOCS_DIR = REPO_ROOT / "docs"


def repo_binary(name: str) -> Path:
    """``target/release/<name>`` of this checkout (``.exe`` on Windows), under
    ``$CARGO_TARGET_DIR`` instead of ``target`` when that is set, as cargo builds it."""
    target = os.environ.get("CARGO_TARGET_DIR")
    base = Path(target) if target else REPO_ROOT / "target"
    return base / "release" / (name + (".exe" if os.name == "nt" else ""))


def customs_bin() -> str:
    """The ``customs`` binary: ``$CUSTOMS_BIN``, else ``repo_binary("customs")``."""
    return os.environ.get("CUSTOMS_BIN") or str(repo_binary("customs"))


def data_dir() -> Path:
    """``$CUSTOMS_DATA``, else ``customs-data`` in the system temp directory."""
    root = Path(os.environ.get("CUSTOMS_DATA") or Path(tempfile.gettempdir()) / "customs-data")
    root.mkdir(parents=True, exist_ok=True)
    return root


def sub(*parts: str) -> Path:
    p = data_dir().joinpath(*parts)
    p.mkdir(parents=True, exist_ok=True)
    return p
