import pytest

from customs_ml import external, pipeline


def _record(monkeypatch, fetched: bool) -> list[str]:
    calls: list[str] = []
    monkeypatch.setattr(
        pipeline, "_stages", lambda: {s: (lambda s=s: calls.append(s)) for s in pipeline.STAGES}
    )
    monkeypatch.setattr(external, "fetched", lambda: fetched)
    return calls


def test_all_runs_stages_in_declared_order(monkeypatch):
    calls = _record(monkeypatch, fetched=True)
    pipeline.main(["all"])
    assert calls == pipeline.plan()
    # Training data is complete before the models that use it are trained.
    first_export = calls.index("export")
    assert calls.index("cluster") < calls.index("split") < calls.index("gbdt") < first_export
    aug = calls.index("augment")
    assert aug > first_export and "gbdt" in calls[aug:] and "cnn" in calls[aug:]
    mal = calls.index("malregistry")
    assert calls[mal - 1] == "external" and calls[-1] == "external"
    assert "export" in calls[mal:]
    assert "refresh" not in calls


def test_all_without_malregistry_archives_skips_the_external_stages(monkeypatch):
    calls = _record(monkeypatch, fetched=False)
    pipeline.main(["all"])
    assert calls == pipeline.plan(malregistry=False)
    assert "external" not in calls and "malregistry" not in calls


def test_unknown_stage_errors(monkeypatch, capsys):
    calls = _record(monkeypatch, fetched=True)
    with pytest.raises(SystemExit):
        pipeline.main(["table", "no-such-stage"])
    assert calls == []
    assert "no-such-stage" in capsys.readouterr().err


def test_every_planned_stage_exists():
    assert set(pipeline.plan()) <= set(pipeline._stages()) == set(pipeline.STAGES)
