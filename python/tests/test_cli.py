import subprocess

from customs_ml import cli


def _git(*args, cwd):
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
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
