import io
import json
import tarfile

from customs_ml import history_eval as he


def _meta(rows):
    """rows: (version, iso time, publisher, attested, install) with install a dict or None."""
    doc = {"time": {"created": "2020-01-01T00:00:00Z"}, "versions": {}}
    for v, t, pub, att, inst in rows:
        doc["time"][v] = t
        if inst is not None or pub is not None:
            m = {"dist": {"tarball": "x"}}
            if pub:
                m["_npmUser"] = {"name": pub}
            if att:
                m["dist"]["attestations"] = {"url": "u"}
            if inst:
                m["scripts"] = inst
            doc["versions"][v] = m
    return he.slim(doc)


HIJACKED = [
    ("1.0.0", "2023-01-01T00:00:00Z", "alice", True, {}),
    ("1.1.0", "2023-03-01T00:00:00Z", "alice", True, {}),
    ("1.1.1", "2024-06-01T00:00:00Z", "mallory", False, {"postinstall": "node bundle.js"}),
]


def fired(hits):
    return sorted(k for k, v in hits.items() if v is True)


def test_hijacked_release_matches_the_rust_rules():
    meta = _meta(HIJACKED)
    assert fired(he.history_rules(meta, "1.1.1")) == [
        "dormant_revival",
        "install_script_added",
        "provenance_dropped",
        "publisher_changed",
    ]
    assert fired(he.history_rules(meta, "1.1.0")) == []
    assert he.history_rules(meta, "9.9.9") is None


def test_unlisted_release_leaves_metadata_rules_unknown():
    meta = _meta(HIJACKED[:2])
    meta["time"]["1.1.1"] = "2023-04-01T00:00:00Z"
    cur = {
        "attested": None,
        "publisher": None,
        "publisher_unknown": True,
        "install": [["postinstall", "node bundle.js"]],
    }
    hits = he.history_rules(meta, "1.1.1", cur)
    assert hits["provenance_dropped"] is None
    assert hits["publisher_changed"] is None
    assert hits["install_script_added"] is True
    assert hits["dormant_revival"] is False


def test_install_script_changes_and_has_install_script():
    rows = [
        ("1.0.0", "2023-01-01T00:00:00Z", "a", False, {"install": "node-gyp rebuild"}),
        ("1.0.1", "2023-02-01T00:00:00Z", "a", False, {"install": "node-gyp rebuild"}),
        ("1.0.2", "2023-03-01T00:00:00Z", "a", False, {"install": "curl x | sh"}),
    ]
    meta = _meta(rows)
    assert he.history_rules(meta, "1.0.1")["install_script_added"] is False
    assert he.history_rules(meta, "1.0.2")["install_script_added"] is True
    # Only `hasInstallScript` known for the new release: not a change.
    meta["versions"]["1.0.2"]["install"] = [["install script", ""]]
    assert he.history_rules(meta, "1.0.2")["install_script_added"] is False


def test_prereleases_and_version_anomaly():
    rows = [
        ("1.0.0", "2022-01-01T00:00:00Z", "a", False, {}),
        ("2.0.0-beta.1", "2022-02-01T00:00:00Z", "a", False, {}),
        ("2.0.0", "2022-03-01T00:00:00Z", "a", False, {}),
        ("1.0.1", "2024-01-01T00:00:00Z", "a", False, {}),
        ("5.0.0", "2024-02-01T00:00:00Z", "a", False, {}),
    ]
    meta = _meta(rows)
    # A stable release ignores earlier prereleases.
    assert he.history_rules(meta, "2.0.0")["dormant_revival"] is False
    # 1.x had been quiet for two years while 2.0.0 was out.
    assert he.history_rules(meta, "1.0.1")["version_anomaly"] is True
    assert he.history_rules(meta, "5.0.0")["version_anomaly"] is True
    assert he.is_pre("2.0.0-beta.1") and not he.is_pre("2.0.0")


def test_slim_drops_unpublished_marker():
    doc = {"time": {"unpublished": {"time": "x"}, "1.0.0": "2023-01-01T00:00:00Z"}}
    assert he.slim(doc)["time"] == {"1.0.0": "2023-01-01T00:00:00Z"}


def test_archive_scripts(tmp_path):
    p = tmp_path / "x.tgz"
    pj = json.dumps({"scripts": {"postinstall": "node a.js", "test": "jest"}}).encode()
    with tarfile.open(p, "w:gz") as t:
        info = tarfile.TarInfo("package/package.json")
        info.size = len(pj)
        t.addfile(info, io.BytesIO(pj))
    assert he.archive_scripts(str(p)) == [["postinstall", "node a.js"]]
