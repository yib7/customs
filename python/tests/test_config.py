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


def test_repo_binary_honours_env_and_target_dir(monkeypatch, tmp_path):
    exe = ".exe" if config.os.name == "nt" else ""
    monkeypatch.delenv("CARGO_TARGET_DIR", raising=False)
    monkeypatch.delenv("CUSTOMS_BIN", raising=False)
    assert (
        config.repo_binary("customs") == config.REPO_ROOT / "target" / "release" / f"customs{exe}"
    )
    assert config.customs_bin() == str(config.REPO_ROOT / "target" / "release" / f"customs{exe}")
    monkeypatch.setenv("CARGO_TARGET_DIR", str(tmp_path / "t"))
    assert config.repo_binary("customs-scan") == tmp_path / "t" / "release" / f"customs-scan{exe}"
    monkeypatch.setenv("CUSTOMS_BIN", "/opt/customs")
    assert config.customs_bin() == "/opt/customs"
