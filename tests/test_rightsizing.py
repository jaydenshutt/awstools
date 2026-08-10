"""Rightsizing detector samples and formulas."""

from awstools.waste.rightsizing import sample_rightsizing_findings
from awstools.waste.scan import sample_findings, scan_waste
from awstools.common.session import create_session


def test_sample_rightsizing():
    fs = sample_rightsizing_findings()
    assert fs[0].category == "ec2_rightsizing"
    assert fs[0].confidence == "Medium"
    assert "cpu" in fs[0].evidence.lower()


def test_sample_findings_include_rightsizing():
    cats = {f.category for f in sample_findings()}
    assert "ec2_rightsizing" in cats


def test_waste_offline_with_rightsizing_detector():
    result = scan_waste(
        create_session(),
        dry_run=True,
        detectors={"ec2_rightsizing"},
    )
    assert result["finding_count"] == 1
    assert result["findings"][0].category == "ec2_rightsizing"
    # Medium confidence → headline high savings may be 0
    assert result["estimated_monthly_savings_usd"] == 0.0
    assert result["estimated_monthly_savings_all_confidence_usd"] > 0
