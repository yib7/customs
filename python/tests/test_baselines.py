import pandas as pd

from customs_ml import baselines


def test_missing_guarddog_is_skipped(monkeypatch, tmp_path):
    monkeypatch.setenv("CUSTOMS_DATA", str(tmp_path / "data"))
    monkeypatch.setenv("GUARDDOG_BIN", str(tmp_path / "no-such-guarddog"))
    archive = tmp_path / "a.tar.gz"
    archive.write_bytes(b"x")
    rows = pd.DataFrame({"canonical_path": [str(archive)], "ecosystem": ["pypi"]})
    assert baselines.run(rows).empty


def test_scan_one_records_os_errors(monkeypatch, tmp_path):
    monkeypatch.setenv("GUARDDOG_BIN", str(tmp_path / "no-such-guarddog"))
    r = baselines.scan_one(str(tmp_path / "a.tar.gz"), "pypi")
    assert r["gd_error"] == "FileNotFoundError"
