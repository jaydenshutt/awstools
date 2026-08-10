"""Anomaly detection unit tests."""

import pandas as pd

from awstools.cost.anomalies import detect_anomalies


def test_detect_total_spike():
    pivot = pd.DataFrame(
        {
            "AmazonEC2": [100.0, 100.0, 200.0],
            "total": [100.0, 100.0, 200.0],
        },
        index=pd.date_range("2025-01-01", periods=3, freq="MS"),
    )
    anoms = detect_anomalies(pivot, threshold_pct=0.2)
    assert any(a["type"] == "total_mom" for a in anoms)
    assert any(a.get("change_pct", 0) and a["change_pct"] >= 50 for a in anoms)


def test_empty_pivot():
    assert detect_anomalies(pd.DataFrame()) == []
