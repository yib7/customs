from customs_ml.pypi_provenance import fires, releases, version_of


def test_version_of():
    assert version_of("demo-1.2.0.tar.gz") == "1.2.0"
    assert version_of("my-pkg-2.0rc1.tar.gz") == "2.0rc1"
    assert version_of("demo-1.2.0-py3-none-any.whl") == "1.2.0"
    assert version_of("demo-1.2.0.exe") is None


def f(name, t, prov):
    return {"filename": name, "upload-time": t, "provenance": "u" if prov else None}


def test_releases_any_file_attested():
    doc = {
        "files": [
            f("d-1.0.tar.gz", "2026-01-02", False),
            f("d-1.0-py3-none-any.whl", "2026-01-01", True),
            f("d-1.1.tar.gz", "2026-02-01", False),
        ]
    }
    assert releases(doc) == {"1.0": ("2026-01-01", True), "1.1": ("2026-02-01", False)}


def test_fires_like_the_proxy():
    rel = {
        "1.0": ("2026-01-01", True),
        "1.1": ("2026-02-01", False),  # dropped: fires
        "1.2rc1": ("2026-03-01", True),
        "1.2": ("2026-03-02", False),  # compares with 1.1 (the prerelease is skipped): quiet
        "1.3": ("2026-04-01", True),
        "1.4": ("2026-05-01", True),
    }
    n, hits = fires(rel, "2026-01-15")
    assert n == 5
    assert hits == [("1.0", "1.1")]
    # Releases before the window are context only.
    n, hits = fires(rel, "2026-03-15")
    assert (n, hits) == (2, [])
