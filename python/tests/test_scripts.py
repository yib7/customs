"""The helper scripts in scripts/ (loaded from their files; they are not a package)."""

import importlib.util
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_replay_binary_honours_customs_bin_and_cargo_target_dir(monkeypatch, tmp_path):
    replay = _load("replay")
    exe = "customs.exe" if replay.os.name == "nt" else "customs"
    monkeypatch.delenv("CUSTOMS_BIN", raising=False)
    monkeypatch.delenv("CARGO_TARGET_DIR", raising=False)
    assert replay.customs_bin() == str(replay.ROOT / "target" / "release" / exe)
    monkeypatch.setenv("CARGO_TARGET_DIR", str(tmp_path))
    assert replay.customs_bin() == str(tmp_path / "release" / exe)
    monkeypatch.setenv("CUSTOMS_BIN", "/opt/customs")
    assert replay.customs_bin() == "/opt/customs"


def test_replay_fails_with_the_server_log_when_the_server_dies(tmp_path):
    replay = _load("replay")
    log = tmp_path / "server.log"
    log.write_text("binding 127.0.0.1:1: address in use\n", encoding="utf-8")
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    with pytest.raises(SystemExit) as e:
        replay.wait_healthy("http://127.0.0.1:9", dead, log, seconds=5)
    assert "address in use" in str(e.value)


def test_replay_refuses_a_port_in_use():
    replay = _load("replay")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen()
        with pytest.raises(SystemExit):
            replay.require_free_port(s.getsockname()[1])


def test_replay_summary_numbers_are_json_safe():
    replay = _load("replay")
    assert replay.finite(float("nan")) is None
    assert json.dumps({"x": replay.finite(0.5)}, allow_nan=False) == '{"x": 0.5}'
