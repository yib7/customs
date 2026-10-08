import tempfile
from pathlib import Path

from customs_ml import config


def test_data_dir_defaults_to_the_platform_temp_dir(monkeypatch, tmp_path):
    monkeypatch.delenv("CUSTOMS_DATA", raising=False)
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    assert config.data_dir() == tmp_path / "customs-data"
    assert (tmp_path / "customs-data").is_dir()


def test_data_dir_follows_customs_data(monkeypatch, tmp_path):
    monkeypatch.setenv("CUSTOMS_DATA", str(tmp_path / "elsewhere"))
    assert config.data_dir() == Path(tmp_path / "elsewhere")
