import io
import tarfile

import pytest

from customs_ml import malicious


def test_scoped_npm_names_are_decoded():
    s = malicious.parse_sample_path(
        "samples/npm/malicious_intent/@acme@internal-utils/1.0.0/2025-03-01-@acme_internal-utils-v1.0.0.zip"
    )
    assert s.name == "@acme/internal-utils" and s.version == "1.0.0"
    assert s.discovered == "2025-03-01" and s.kind == "malicious_intent"
    p = malicious.parse_sample_path(
        "samples/pypi/malicious_intent/requests-darwin/2.0/2023-01-02-requests-darwin-v2.0.zip"
    )
    assert p.name == "requests-darwin" and p.ecosystem == "pypi"


def test_unwrap_strips_wrappers_and_sidecar():
    files = {
        "tmp/tmpab12/pkg/package/package.json": b"{}",
        "tmp/tmpab12/pkg/package/index.js": b"1",
        "tmp/tmpab12/pkg/package_info-pkg-1.0.json": b"{}",
    }
    assert sorted(malicious.unwrap_sample(files, "npm")) == ["index.js", "package.json"]


def test_canonical_archive_is_deterministic_and_rooted():
    files = {"setup.py": b"x=1\n", "pkg/__init__.py": b""}
    a = malicious.canonicalize(files, "pypi", "my-pkg", "1.0")
    assert a == malicious.canonicalize(dict(reversed(list(files.items()))), "pypi", "my-pkg", "1.0")
    with tarfile.open(fileobj=io.BytesIO(a)) as tf:
        names = tf.getnames()
    assert names == ["my_pkg-1.0/pkg/__init__.py", "my_pkg-1.0/setup.py"]


def test_traversal_entries_are_dropped():
    assert malicious._safe_rel("../etc/passwd") is None
    assert malicious._safe_rel("/abs/path") is None
    assert malicious._safe_rel("a/./b") == "a/b"


def test_tar_entry_cap(monkeypatch):
    def tar(n: int) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for i in range(n):
                info = tarfile.TarInfo(f"pkg/f{i}.py")
                info.size = 1
                tf.addfile(info, io.BytesIO(b"x"))
        return buf.getvalue()

    monkeypatch.setattr(malicious, "MAX_ENTRIES", 2)
    assert len(malicious.read_tar_tree(tar(2))) == 2
    with pytest.raises(ValueError, match="too many entries"):
        malicious.read_tar_tree(tar(3))
