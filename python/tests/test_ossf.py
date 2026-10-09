import json

import pytest

from customs_ml import ossf


def test_wrong_repo_raises_clear_error(tmp_path):
    with pytest.raises(ValueError, match="osv/malicious"):
        ossf.build_table(tmp_path)


def test_repo_without_reports_gives_an_empty_table(tmp_path):
    (tmp_path / "osv" / "malicious" / "npm").mkdir(parents=True)
    df = ossf.build_table(tmp_path)
    assert df.empty and "published" in df.columns


def test_reports_are_parsed(tmp_path):
    d = tmp_path / "osv" / "malicious" / "pypi" / "evil"
    d.mkdir(parents=True)
    rep = {
        "id": "MAL-1",
        "published": "2024-01-02T00:00:00Z",
        "affected": [{"package": {"ecosystem": "PyPI", "name": "evil"}, "versions": ["1.0"]}],
    }
    (d / "MAL-1.json").write_text(json.dumps(rep), encoding="utf-8")
    df = ossf.build_table(tmp_path)
    assert list(df.name) == ["evil"] and df.published.notna().all()
