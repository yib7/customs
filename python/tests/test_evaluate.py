import numpy as np
import pandas as pd

from customs_ml import evaluate


def test_guarddog_section_is_skipped_when_one_class_has_no_result(monkeypatch):
    T = pd.DataFrame(
        {
            "canonical_path": ["m1", "m2", "b1", "b2"],
            "label": [1, 1, 0, 0],
            "cluster": [0, 1, 2, 3],
        }
    )
    gd = pd.DataFrame(
        {
            "path": ["m1", "m2", "b1", "b2"],
            "gd_score": [1.0, 0.0, 0.0, 0.0],
            "gd_label": ["", "", "", ""],
            "gd_error": ["", "", "TimeoutExpired", "TimeoutExpired"],
        }
    )
    monkeypatch.setattr(evaluate.baselines, "run", lambda rows: gd)
    y = T.label.to_numpy()
    assert evaluate._guarddog(T, y, T.cluster.to_numpy(), np.array([0.9, 0.8, 0.1, 0.2])) == {}
