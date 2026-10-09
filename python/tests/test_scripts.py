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


def test_live_watch_worker_survives_a_failed_scan():
    import queue
    import threading
    import urllib.error

    live = _load("live_watch")
    pending: queue.Queue = queue.Queue()
    inflight = live.Inflight()
    rows: list[dict] = []

    def scan(item):
        if item[1] == "down":
            raise urllib.error.URLError("connection refused")
        return {"name": item[1], "version": item[2], "status": 200}

    threading.Thread(
        target=live.work_loop, args=(pending, scan, rows.append, inflight), daemon=True
    ).start()
    for ser, name in ((101, "down"), (102, "up")):
        inflight.add(ser)
        pending.put((0, name, "1.0", 1700000000, ser))
    joined = threading.Thread(target=pending.join, daemon=True)
    joined.start()
    joined.join(timeout=10)
    assert not joined.is_alive(), "pending.join() hung after a failed scan"
    assert [r["name"] for r in rows] == ["down", "up"]
    assert rows[0]["status"] is None and "URLError" in rows[0]["error"]
    assert inflight.safe(200) == 200


def test_live_watch_resumes_before_the_oldest_unscanned_release():
    live = _load("live_watch")
    inflight = live.Inflight()
    inflight.add(50)
    inflight.add(40)
    inflight.add(40)
    assert inflight.safe(60) == 39
    inflight.done(40)
    assert inflight.safe(60) == 39
    inflight.done(40)
    assert inflight.safe(60) == 49
    inflight.done(50)
    assert inflight.safe(60) == 60


def test_live_watch_report_writes_the_copy_the_evaluation_report_reads(monkeypatch, tmp_path):
    live = _load("live_watch")
    out = tmp_path / "live"
    out.mkdir()
    rows = [
        {
            "name": "a",
            "version": "1",
            "published": 1700000000,
            "new_project": True,
            "risk": 0.9,
            "model_decision": "block",
        },
        {
            "name": "b",
            "version": "1",
            "published": 1700000600,
            "new_project": False,
            "risk": None,
            "model_decision": None,
            "error": "URLError: down",
        },
    ]
    (out / "scans.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    up = {"checked_at": "2026-01-01T00:00:00+00:00", "status": {"a": 404, "b": 200}, "ossf": []}
    (out / "followups.jsonl").write_text(json.dumps(up) + "\n", encoding="utf-8")
    monkeypatch.setenv("CUSTOMS_DATA", str(tmp_path / "data"))
    summary = live.report(out)
    copy = json.loads((tmp_path / "data" / "work" / "live_study.json").read_text(encoding="utf-8"))
    assert copy == summary
    assert (summary["releases"], summary["scanned"], summary["removed_total"]) == (2, 1, 1)
