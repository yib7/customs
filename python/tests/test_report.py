from customs_ml import report


def test_second_source_note_carries_the_leak_caveat_until_the_stage_checks_held_out():
    unchecked = report.second_source_note(None)
    assert "Caveat" in unchecked and "not yet measured" in unchecked
    checked = report.second_source_note({"added": 10, "dropped_near_heldout": 3})
    assert "Caveat" not in checked and "(3 of them)" in checked
