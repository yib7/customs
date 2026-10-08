from customs_ml.registry_status import classify


def test_classify():
    assert classify("1.0.0", None) is None
    assert classify("1.0.0", {"status": 404, "versions": []}) == "removed"
    assert classify("1.0.0", {"status": "timeout", "versions": []}) is None
    assert classify("1.0.0", {"status": 200, "versions": ["0.0.1-security"]}) == "removed"
    assert classify("1.0.0", {"status": 200, "versions": ["0.9.0"]}) == "removed"
    assert classify("1.0.0", {"status": 200, "versions": ["0.9.0", "1.0.0"]}) == "still_published"
