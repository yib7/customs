from customs_ml.popular_check import record, summarize


def verdict(decision, model, risk, hits=(), reasons=()):
    return {
        "version": "1.0.0",
        "artifact": "x-1.0.0.tgz",
        "decision": decision,
        "model_decision": model,
        "risk": risk,
        "policy_hits": [{"rule": r, "severity": s} for r, s in hits],
        "reasons": [{"feature": f} for f in reasons],
    }


def test_record_keeps_rules_that_change_the_decision():
    v = verdict(
        "warn",
        "allow",
        0.1,
        hits=[("allow", "allow"), ("dormant_revival", "warn")],
        reasons=["a", "b", "c", "d", "e"],
    )
    r = record("npm", "x", v)
    assert r["rules"] == ["dormant_revival"]
    assert r["top"] == ["a", "b", "c", "d"]
    assert r["decision"] == "warn" and r["model_decision"] == "allow"


def test_summarize_per_ecosystem():
    rows = [
        record("npm", "a", verdict("allow", "allow", 0.01)),
        record("npm", "b", verdict("block", "allow", 0.02, hits=[("min_age_days", "block")])),
        record("npm", "c", verdict("warn", "warn", 0.9, reasons=["env"])),
        {"eco": "npm", "name": "d", "error": "upstream timed out"},
        record("pypi", "e", verdict("allow", "allow", 0.03)),
    ]
    s = summarize(rows)
    npm = s["npm"]
    assert npm["n"] == 4 and npm["errors"] == 1 and npm["checked"] == 3
    assert npm["model"] == {"allow": 2, "warn": 1, "block": 0}
    assert npm["final"] == {"allow": 1, "warn": 1, "block": 1}
    assert npm["rules"] == {"min_age_days": 1}
    assert [r["name"] for r in npm["model_flagged"]] == ["c"]
    assert npm["risk_max"] == 0.9
    assert s["pypi"]["model"] == {"allow": 1, "warn": 0, "block": 0}
    assert s["pypi"]["model_flagged"] == []
