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


def test_nonregistry_specs_match_the_rust_helper():
    for s in ("github:a/b#1", "git+https://x/y.git", "https://x/y.tgz", "file:../a", "a/b#main"):
        assert he.is_nonregistry_spec(s), s
    for s in ("^1.2.3", "latest", "npm:other@1", "@scope/pkg", "1.x || 2.x", "a/b/c"):
        assert not he.is_nonregistry_spec(s), s


def _dep_meta():
    doc = {
        "maintainers": [{"name": "alice"}],
        "time": {
            "created": "2020-01-01T00:00:00Z",
            "1.0.0": "2023-12-01T00:00:00Z",
            "1.0.1": "2024-01-02T00:00:00Z",
        },
        "versions": {
            "1.0.0": {"_npmUser": {"name": "alice"}, "dependencies": {"plain": "^1.0.0"}},
            "1.0.1": {
                "_npmUser": {"name": "alice"},
                "dependencies": {"plain": "^1.0.0", "lure": "^0.0.1", "own-new": "1.0.0"},
                "optionalDependencies": {"@x/setup": "github:evil/payload#abc", "plain": "2"},
            },
        },
    }
    return he.slim(doc)


DEPS = {
    "lure": {"created": "2024-01-01T00:00:00Z", "people": ["mallory"]},
    "own-new": {"created": "2024-01-01T00:00:00Z", "people": ["alice"]},
}


def test_dependency_rules():
    meta = _dep_meta()
    assert meta["people"] == ["alice"]
    # dependencies win over optionalDependencies for the same name.
    assert ["plain", "^1.0.0"] in meta["versions"]["1.0.1"]["deps"]
    hits = he.history_rules(meta, "1.0.1", lookup=lambda d: DEPS.get(d, {}), name="pkg")
    assert hits["nonregistry_dependency_added"] is True
    assert hits["young_dependency_added"] is True
    added = he.added_dependencies(meta, "pkg", meta["versions"]["1.0.1"], meta["versions"]["1.0.0"])
    assert added == ["lure", "own-new"]
    young, failed = he.young_dependencies(meta, "1.0.1", added, lambda d: DEPS[d])
    assert young == [("lure", "young")] and not failed
    # Old enough, missing, or a failed lookup.
    old = {"lure": {"created": "2023-01-01T00:00:00Z", "people": []}, "own-new": DEPS["own-new"]}
    assert not he.history_rules(meta, "1.0.1", lookup=old.get, name="pkg")["young_dependency_added"]
    gone = {"lure": {"missing": True}, "own-new": DEPS["own-new"]}
    assert he.history_rules(meta, "1.0.1", lookup=gone.get, name="pkg")["young_dependency_added"]
    failed = {"lure": {}, "own-new": DEPS["own-new"]}
    assert (
        he.history_rules(meta, "1.0.1", lookup=failed.get, name="pkg")["young_dependency_added"]
        is None
    )
    # Without lookups the rule is unknown; the first release has no history at all.
    assert he.history_rules(meta, "1.0.1")["young_dependency_added"] is None
    assert he.history_rules(meta, "1.0.0", lookup=DEPS.get)["young_dependency_added"] is False


def test_archive_scripts_adds_npm_implicit_gyp_install(tmp_path):
    def pack(name, scripts, gyp=True):
        p = tmp_path / name
        pj = json.dumps({"scripts": scripts}).encode()
        with tarfile.open(p, "w:gz") as t:
            files = [("package/package.json", pj)]
            if gyp:
                files.append(("package/binding.gyp", b"{}"))
            for n, data in files:
                info = tarfile.TarInfo(n)
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
        return str(p)

    assert he.archive_scripts(pack("a.tgz", {})) == [["install", "node-gyp rebuild"]]
    assert he.archive_scripts(pack("b.tgz", {"preinstall": "x"})) == [["preinstall", "x"]]
    assert he.archive_scripts(pack("c.tgz", {}, gyp=False)) == []


def test_install_script_added_sees_through_a_burst():
    rows = [
        ("1.0.0", "2025-01-01T00:00:00Z", "a", False, {}),
        ("1.0.1", "2025-02-01T10:00:00Z", "a", False, {"postinstall": "node x.js"}),
        ("1.0.2", "2025-02-01T12:00:00Z", "a", False, {"postinstall": "node x.js"}),
        ("1.0.3", "2025-02-03T12:00:00Z", "a", False, {"postinstall": "node x.js"}),
    ]
    meta = _meta(rows)
    assert he.history_rules(meta, "1.0.1")["install_script_added"] is True
    assert he.history_rules(meta, "1.0.2")["install_script_added"] is True
    assert he.history_rules(meta, "1.0.3")["install_script_added"] is False
    # The burst's first release unpublished: the settled baseline still decides.
    del meta["versions"]["1.0.1"]
    assert he.history_rules(meta, "1.0.2")["install_script_added"] is True


def test_dependency_rules_see_through_a_burst():
    doc = _dep_meta()
    doc["time"]["1.0.2"] = "2024-01-02T03:00:00Z"
    doc["versions"]["1.0.2"] = {
        **doc["versions"]["1.0.1"],
        "deps": list(doc["versions"]["1.0.1"]["deps"]),
    }
    # 1.0.2 repeats 1.0.1 three hours later; the settled release is still 1.0.0.
    hits = he.history_rules(doc, "1.0.2", lookup=lambda d: DEPS.get(d, {}), name="pkg")
    assert hits["nonregistry_dependency_added"] is True
    assert hits["young_dependency_added"] is True
    # A day later 1.0.1 is the settled release and nothing is new.
    doc["time"]["1.0.2"] = "2024-01-04T00:00:00Z"
    hits = he.history_rules(doc, "1.0.2", lookup=lambda d: DEPS.get(d, {}), name="pkg")
    assert hits["nonregistry_dependency_added"] is False
    assert hits["young_dependency_added"] is False
