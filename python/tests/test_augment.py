import json

from customs_ml.augment import self_repo, starjack


def test_self_repo_renames_npm_links():
    files = {"package.json": json.dumps({"name": "@evil/left-padd", "version": "1.0.0"}).encode()}
    donor = {
        "package.json": json.dumps(
            {
                "name": "left-pad",
                "repository": {
                    "type": "git",
                    "url": "git+https://github.com/stevemao/left-pad.git",
                },
                "homepage": "https://github.com/stevemao/left-pad#readme",
            }
        ).encode(),
        "README.md": b"# left-pad",
    }
    pkg = json.loads(self_repo(starjack(files, "npm", donor), "npm")["package.json"])
    assert pkg["name"] == "@evil/left-padd"
    assert pkg["repository"]["url"] == "git+https://github.com/stevemao/left-padd.git"
    assert pkg["homepage"] == "https://github.com/stevemao/left-padd#readme"


def test_self_repo_adds_a_link_when_there_is_none():
    files = {"package.json": json.dumps({"name": "x-util"}).encode()}
    pkg = json.loads(self_repo(files, "npm")["package.json"])
    assert pkg["repository"]["url"].endswith("/x-util.git")


def test_self_repo_renames_core_metadata_headers_only():
    info = (
        b"Metadata-Version: 2.1\nName: reqeusts\nVersion: 1.0\n"
        b"Home-page: https://github.com/psf/requests\n"
        b"Project-URL: Source, https://github.com/psf/requests.git\n\n"
        b"See https://github.com/psf/requests for docs.\n"
    )
    out = self_repo({"PKG-INFO": info}, "pypi")["PKG-INFO"].decode()
    head, body = out.split("\n\n", 1)
    assert "Home-page: https://github.com/psf/reqeusts" in head
    assert "Project-URL: Source, https://github.com/psf/reqeusts.git" in head
    assert "github.com/psf/requests for docs" in body
