import subprocess

import pytest

from customs_ml import cli


def _git(*args, cwd):
    # Independent of the user's git config: no signing prompt, no hooks.
    hermetic = ["-c", "commit.gpgsign=false", "-c", "core.hooksPath=", "-c", "init.templateDir="]
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *hermetic, *args],
        cwd=cwd,
        check=True,
        capture_output=True,
    )


def test_datadog_listing_keeps_non_ascii_sample_paths(tmp_path):
    repo = tmp_path / "repo"
    paths = [
        "samples/npm/malicious_intent/caf\u00e9-utils/1.0.0/2024-01-02-caf\u00e9-utils-v1.0.0.zip",
        "samples/pypi/compromised_lib/plain/2.0/2024-03-04-plain-v2.0.zip",
        "README.md",
    ]
    for p in paths:
        f = repo / p
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"x")
    _git("init", "-q", str(repo), cwd=tmp_path)
    _git("add", ".", cwd=repo)
    _git("commit", "-q", "-m", "x", cwd=repo)
    assert sorted(cli._datadog_listing(repo.as_uri())) == sorted(paths[:2])


class _Resp:
    def __init__(self, status: int, content: bytes = b""):
        self.status_code, self.content, self.ok = status, content, status < 400


class _Session:
    def __init__(self, resp):
        self.resp = resp

    def get(self, url, timeout):
        return self.resp


def test_fetch_is_atomic(monkeypatch, tmp_path):
    from pathlib import Path

    dest = tmp_path / "npm" / "x" / "sample.zip"
    real = Path.write_bytes

    def torn(self, data):  # the process dies halfway through the write
        real(self, data[: len(data) // 2])
        raise OSError("disk full")

    monkeypatch.setattr(Path, "write_bytes", torn)
    with pytest.raises(OSError):
        cli.fetch_to(_Session(_Resp(200, b"0123456789")), "https://x/sample.zip", dest)
    monkeypatch.undo()
    # A torn download must not look like a finished one (`fetch` skips existing files).
    assert not dest.exists()
    assert cli.fetch_to(_Session(_Resp(200, b"0123456789")), "https://x/sample.zip", dest)
    assert dest.read_bytes() == b"0123456789"
    assert not list(dest.parent.glob("*.part"))


def test_fetch_reports_a_failed_download(tmp_path, capsys):
    dest = tmp_path / "sample.zip"
    assert not cli.fetch_to(_Session(_Resp(404)), "https://x/sample.zip", dest)
    assert not dest.exists()
    assert "404" in capsys.readouterr().out
