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


def data_dir() -> Path:
    """``$CUSTOMS_DATA``, else ``customs-data`` in the system temp directory."""
    root = Path(os.environ.get("CUSTOMS_DATA") or Path(tempfile.gettempdir()) / "customs-data")
    root.mkdir(parents=True, exist_ok=True)
    return root


def sub(*parts: str) -> Path:
    p = data_dir().joinpath(*parts)
    p.mkdir(parents=True, exist_ok=True)
    return p
