"""The red team's string rewrites must keep a program's meaning, or a detection drop says
nothing about evasion. Each rewrite is applied to a small benign Python module, which is run
before and after; the values it computes have to match."""

import pytest

from customs_ml import robustness as r

SRC = b"""from __future__ import annotations
import os
HOST = 'https://example.org/path'
NAMES = ['child_process', 'module.name']
JOINED = os.path.join('folder_a', 'file_b.txt')
LABEL = f'prefix-{HOST}'
"""

REWRITES = [
    r.string_split,
    r.hex_escape,
    r.char_codes,
    r.reverse_strings,
    r.array_join,
    r.string_table,
]


def run(src: bytes) -> dict:
    scope: dict = {}
    exec(compile(src, "setup.py", "exec"), scope)
    return {k: scope[k] for k in ("HOST", "NAMES", "JOINED", "LABEL")}


@pytest.mark.parametrize("rewrite", REWRITES, ids=lambda f: f.__name__)
def test_rewrites_keep_python_meaning(rewrite):
    out = rewrite({"setup.py": SRC, "README.md": b"'untouched_literal'"}, "pypi")
    assert out["README.md"] == b"'untouched_literal'"
    assert out["setup.py"] != SRC
    assert run(out["setup.py"]) == run(SRC)


def test_array_join_and_string_table_shapes():
    js = {"index.js": b"require('child_process').exec('curl_example');\n"}
    joined = r.array_join(js, "npm")["index.js"].decode()
    assert "['child', '_proc', 'ess'].join('')" in joined
    table = r.string_table(js, "npm")["index.js"].decode()
    assert table.startswith('var _s = ["child_process", "curl_example"];\n')
    assert "require(_s[0]).exec(_s[1])" in table
    # A repeated literal gets one table slot.
    twice = r.string_table({"a.py": b"x = 'abcdef'\ny = 'abcdef'\n"}, "pypi")["a.py"]
    assert twice == b'_s = ["abcdef"]\nx = _s[0]\ny = _s[0]\n'


def test_pieces_cover_the_literal():
    for n in range(6, 201):
        s = "".join(chr(97 + i % 26) for i in range(n))
        parts = r._pieces(s)
        assert "".join(parts) == s
        assert 2 <= len(parts) <= 4
        assert min(map(len, parts)) >= 2
