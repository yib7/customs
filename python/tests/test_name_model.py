import numpy as np

from customs_ml import name_model as nm


def test_fnv1a_reference_values():
    assert nm.fnv1a32(b"") == 0x811C9DC5
    assert nm.fnv1a32(b"a") == 0xE40C292C
    assert nm.fnv1a32(b"foobar") == 0xBF9CF968


def test_typosquat_features():
    pop = nm.Popular.from_list("pypi", ["requests", "numpy", "flask"])
    f = dict(
        zip(
            nm.NUMERIC,
            nm.numeric_features(["reqeusts", "requests", "flask-utils-pro", "zzzzzz"], pop)[0],
            strict=True,
        )
    )
    assert f["dist1"] == 1.0  # transposition counts as one edit (OSA)
    rows = nm.numeric_features(["reqeusts", "requests", "flask-utils-pro", "zzzzzz"], pop)
    col = {n: i for i, n in enumerate(nm.NUMERIC)}
    assert rows[1, col["is_popular"]] == 1 and rows[1, col["dist1"]] == 0
    assert rows[2, col["contains_popular_token"]] == 1
    assert rows[3, col["dist1"]] == rows[3, col["dist2"]] == rows[3, col["dist3"]] == 0


def test_export_score_matches_sklearn():
    rng = np.random.default_rng(0)
    pop = nm.Popular.from_list("npm", ["react", "lodash", "express", "@types/node"])
    good = ["react", "lodash", "left-pad", "my-cool-lib", "@babel/core", "chalk"]
    bad = [
        "raect",
        "lodahs",
        "express-auth-helper99",
        "@typs/node",
        "internal-corp-utils",
        "xpress",
    ]
    names = [rng.choice(good + bad) + ("" if rng.uniform() < 0.5 else str(i)) for i in range(200)]
    y = np.array([int(any(n.startswith(b) for b in bad)) for n in names])
    clf, mean, std = nm.train(names, y, pop)
    model = nm.export({"npm": (clf, mean, std)}, {"npm": "popular_npm.txt"})
    X, _, _ = nm.design_matrix(names[:20], pop, mean, std)
    ref = clf.decision_function(X)
    got = [nm.score_exported(model, "npm", n, pop) for n in names[:20]]
    np.testing.assert_allclose(got, ref, atol=1e-4)


def test_normalize_matches_rust():
    # Expected strings come from crates/customs-model/src/name.rs::normalize: str::trim
    # (Unicode White_Space only), PyPI lowercases per character (no final-sigma rule),
    # npm uses str::to_lowercase (with the final-sigma rule).
    cases = [
        ("pypi", "  ΟΔΟΣ  ", "οδοσ"),
        ("pypi", "ΟΔΟΣ-ΟΔΟΣ", "οδοσ-οδοσ"),
        ("pypi", "\u00a0Foo__Bar..baz\u3000", "foo-bar-baz"),
        ("pypi", "\x1cAbc\x1f", "\x1cabc\x1f"),
        ("pypi", "İx", "i\u0307x"),
        ("npm", "  ΟΔΟΣ  ", "οδος"),
        ("npm", "ΟΔΟΣ-ΟΔΟΣ", "οδος-οδος"),
        ("npm", "\t@Scope/Foo_Bar\n", "@scope/foo_bar"),
        ("npm", "\x1cAbc\x1f", "\x1cabc\x1f"),
    ]
    for eco, raw, want in cases:
        assert nm.normalize(eco, raw) == want, (eco, raw)
