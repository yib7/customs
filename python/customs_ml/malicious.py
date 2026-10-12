"""Ingest Datadog's malicious-software-packages-dataset into canonical archives.

Each Datadog sample is a ZIP (password ``infected``) holding an already extracted package
tree under ``tmp/<random>/<name>/...``, plus, for npm, a ``package_info-*.json`` registry
snapshot that Datadog added. That snapshot is excluded: it is not part of the package and
would leak the label.

Benign archives go through the exact same canonicalization (see :func:`canonicalize`),
so the classifier never sees a packaging difference between the classes: both end up as
gzip tarballs with a ``name-version/`` (PyPI) or ``package/`` (npm) root, sorted entries,
fixed mtimes, and no file modes beyond 0644.

Nothing here executes, imports, or writes sample files to disk unpacked: entries are read
from the encrypted ZIP into memory and written straight into the output tarball.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
import zipfile
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path

from . import config

PASSWORD = b"infected"
MAX_ENTRY = 32 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
MAX_ENTRIES = 20_000
SOURCE_SUFFIXES = (".tar.gz", ".tgz", ".zip", ".whl", ".tar.bz2")

SAMPLE_RE = re.compile(
    r"samples/(?P<eco>npm|pypi)/(?P<kind>malicious_intent|compromised_lib)/"
    r"(?P<name>.+)/(?P<version>[^/]+)/(?P<date>\d{4}-\d{2}-\d{2})-[^/]+\.zip$"
)


@dataclass
class Sample:
    ecosystem: str
    kind: str
    name: str
    version: str
    discovered: str
    source: str
    path: str = ""
    sha256: str = ""
    n_files: int = 0
    error: str = ""


def decode_name(ecosystem: str, name: str) -> str:
    """Datadog stores a scoped npm package ``@scope/name`` in a directory ``@scope@name``.

    Left encoded, every scoped malicious name would contain a second ``@`` that no benign
    name has: a label leak through the name model.
    """
    if ecosystem == "npm" and name.startswith("@") and "/" not in name and "@" in name[1:]:
        scope, _, rest = name[1:].partition("@")
        return f"@{scope}/{rest}"
    return name


def parse_sample_path(rel: str) -> Sample | None:
    m = SAMPLE_RE.search(rel)
    if not m:
        return None
    return Sample(
        ecosystem=m["eco"],
        kind=m["kind"],
        name=decode_name(m["eco"], m["name"]),
        version=m["version"],
        discovered=m["date"],
        source=rel,
    )


# ------------------------------------------------------------- canonical archives


def _safe_rel(name: str) -> str | None:
    """Reject absolute paths and traversal; normalize separators."""
    name = name.replace("\\", "/")
    if name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        return None
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        return None
    return "/".join(parts)


def canonicalize(files: dict[str, bytes], ecosystem: str, name: str, version: str) -> bytes:
    """Write ``files`` (relative path to content) as a deterministic gzip tarball.

    The root directory is ``package/`` for npm (what npm itself uses) and
    ``<name>-<version>/`` for PyPI (the sdist convention).
    """
    root = "package" if ecosystem == "npm" else f"{_dist_name(name)}-{version}"
    buf = io.BytesIO()
    # mtime=0 on the gzip header and every member keeps output byte-stable.
    with (
        io.BytesIO() as raw,
        tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tf,
    ):
        for rel in sorted(files):
            data = files[rel]
            ti = tarfile.TarInfo(f"{root}/{rel}")
            ti.size = len(data)
            ti.mode = 0o644
            ti.mtime = 0
            tf.addfile(ti, io.BytesIO(data))
        tf.close()
        import gzip

        with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0, compresslevel=6) as gz:
            gz.write(raw.getvalue())
    return buf.getvalue()


def _dist_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9.]+", "_", name)


MANIFESTS = {"setup.py", "setup.cfg", "pyproject.toml", "PKG-INFO", "package.json"}


def strip_common_root(files: dict[str, bytes]) -> dict[str, bytes]:
    """Remove wrapper directories shared by every path.

    Stops as soon as the current root holds a package manifest, so a package whose code
    all lives in one directory keeps that directory.
    """
    while files:
        if any(p in MANIFESTS for p in files):
            break
        heads = {p.split("/", 1)[0] for p in files}
        if len(heads) != 1 or any("/" not in p for p in files):
            break
        files = {p.split("/", 1)[1]: d for p, d in files.items()}
    return files


def read_zip_tree(data: bytes, password: bytes | None = PASSWORD) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > MAX_ENTRIES:
            raise ValueError("too many entries")
        for info in infos:
            rel = _safe_rel(info.filename)
            if rel is None or info.file_size > MAX_ENTRY:
                continue
            # External attributes with the symlink bit set are skipped, never followed.
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                continue
            total += info.file_size
            if total > MAX_TOTAL:
                raise ValueError("archive too large")
            files[rel] = zf.read(info, pwd=password)
    return files


def read_tar_tree(data: bytes) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        for n, m in enumerate(tf):
            if n >= MAX_ENTRIES:
                raise ValueError("too many entries")
            if not m.isreg():
                continue
            rel = _safe_rel(m.name)
            if rel is None or m.size > MAX_ENTRY:
                continue
            total += m.size
            if total > MAX_TOTAL:
                raise ValueError("archive too large")
            f = tf.extractfile(m)
            if f is not None:
                files[rel] = f.read()
    return files


def read_any(data: bytes, filename: str) -> dict[str, bytes]:
    lower = filename.lower()
    if lower.endswith((".zip", ".whl")):
        return read_zip_tree(data, password=None)
    return read_tar_tree(data)


def unwrap_sample(files: dict[str, bytes], ecosystem: str) -> dict[str, bytes]:
    """Turn a Datadog sample tree into the package's own file tree.

    Layout is ``tmp/<rand>/<name>/<payload>`` where payload is either an extracted tree
    or, occasionally, the original archive file. npm samples also carry a
    ``package_info-*.json`` sibling that is dropped.
    """
    files = {p: d for p, d in files.items() if not re.search(r"(^|/)package_info-[^/]*\.json$", p)}
    files = strip_common_root(files)
    # A sample that is a single original archive gets opened (one level only).
    if len(files) == 1:
        ((only, data),) = files.items()
        if only.lower().endswith(SOURCE_SUFFIXES):
            files = strip_common_root(read_any(data, only))
    if ecosystem == "npm" and any(p.startswith("package/") for p in files):
        files = {p[len("package/") :]: d for p, d in files.items() if p.startswith("package/")}
    return files


def _ingest_one(args: tuple[str, str, str]) -> dict:
    repo, rel, out_dir = args
    s = parse_sample_path(rel)
    assert s is not None
    try:
        raw = (Path(repo) / rel).read_bytes()
        files = unwrap_sample(read_zip_tree(raw), s.ecosystem)
        if not files:
            raise ValueError("empty sample")
        blob = canonicalize(files, s.ecosystem, s.name, s.version)
        digest = hashlib.sha256(blob).hexdigest()
        ext = ".tgz" if s.ecosystem == "npm" else ".tar.gz"
        out = Path(out_dir) / s.ecosystem / f"{digest[:2]}" / f"{digest}{ext}"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(blob)
        s.path, s.sha256, s.n_files = str(out), digest, len(files)
    except Exception as e:  # noqa: BLE001 - recorded per sample
        s.error = f"{type(e).__name__}: {e}"
    return asdict(s)


def iter_sample_paths(repo: Path, tree_listing: Path | None = None) -> Iterator[str]:
    if tree_listing is not None:
        for line in tree_listing.read_text(encoding="utf-8").splitlines():
            if SAMPLE_RE.search(line) and (repo / line).exists():
                yield line
        return
    for p in (repo / "samples").rglob("*.zip"):
        rel = str(p.relative_to(repo))
        if SAMPLE_RE.search(rel):
            yield rel


def ingest(repo: Path, workers: int = 4, tree_listing: Path | None = None) -> Path:
    out_dir = config.sub("malicious")
    manifest = out_dir / "manifest.jsonl"
    done = set()
    if manifest.exists():
        done = {
            json.loads(line)["source"] for line in manifest.read_text(encoding="utf-8").splitlines()
        }
    todo = [(str(repo), rel, str(out_dir)) for rel in iter_sample_paths(repo, tree_listing)]
    todo = [t for t in todo if t[1] not in done]
    with ProcessPoolExecutor(workers) as ex, manifest.open("a", encoding="utf-8") as mf:
        for row in ex.map(_ingest_one, todo, chunksize=16):
            mf.write(json.dumps(row) + "\n")
    return manifest


def canonicalize_benign(path: Path, ecosystem: str, name: str, version: str) -> bytes:
    """Benign archives get the same treatment so packaging is identical across classes."""
    files = strip_common_root(read_any(path.read_bytes(), path.name))
    if ecosystem == "npm" and any(p.startswith("package/") for p in files):
        files = {p[len("package/") :]: d for p, d in files.items() if p.startswith("package/")}
    return canonicalize(files, ecosystem, name, version)
