"""Tests for cost series helpers and dry-run analysis."""

from pathlib import Path

import pandas as pd

from awstools.cost.costs import (
    SAMPLE_COSTS,
    prepare_timeseries,
    forecast_linear,
    parse_cur_local,
)
from awstools.cost.analyze import AnalysisConfig, run_analysis
from awstools.common.session import create_session


def test_prepare_timeseries():
    pivot = prepare_timeseries(SAMPLE_COSTS)
    assert not pivot.empty
    assert "total" in pivot.columns
    assert pivot["total"].iloc[-1] > 0


def test_forecast_linear_non_negative():
    s = pd.Series(
        [100.0, 80.0, 60.0],
        index=pd.date_range("2025-01-01", periods=3, freq="MS"),
    )
    f = forecast_linear(s, months=3)
    assert len(f) == 3
    assert (f >= 0).all()


def test_parse_cur_local(tmp_path: Path):
    csv = tmp_path / "cur.csv"
    csv.write_text(
        "lineItem/ResourceId,lineItem/UnblendedCost,lineItem/UsageStartDate\n"
        "i-abc,10.5,2025-06-01\n"
        "i-abc,2.0,2025-06-15\n"
        "vol-xyz,3.0,2025-06-01\n",
        encoding="utf-8",
    )
    costs = parse_cur_local(str(csv))
    assert abs(costs["i-abc"] - 12.5) < 0.01
    assert abs(costs["vol-xyz"] - 3.0) < 0.01


def test_dry_run_analysis(tmp_path: Path):
    session = create_session()
    config = AnalysisConfig(
        output_dir=tmp_path,
        html_name="report.html",
        pdf_name="report.pdf",
        csv_name="costs.csv",
        export_actions="actions.csv",
        dry_run=True,
        write_html=True,
    )
    summary = run_analysis(session, config)
    assert summary["account_id"] == "000000000000"
    assert summary["latest_total"] > 0
    assert (tmp_path / "report.html").exists()
    assert (tmp_path / "summary.json").exists()
    assert (tmp_path / "costs.csv").exists()
    assert (tmp_path / "actions.csv").exists()
    html = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert "AWS cost report" in html or "AWS Cost Analysis" in html
    assert "Executive summary" in html
