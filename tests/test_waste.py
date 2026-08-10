"""Waste scan dry-run and finding helpers."""

from awstools.common.findings import Finding, has_protect_tag, total_savings, findings_to_rows
from awstools.waste.scan import scan_waste
from awstools.common.session import create_session


def test_has_protect_tag():
    assert has_protect_tag({"awstools:protect": "true"})
    assert has_protect_tag({"Protect": "yes"})
    assert not has_protect_tag({"env": "prod"})


def test_total_savings_skips_protected():
    fs = [
        Finding("a", "x", "r1", "us-east-1", "del", 10.0, "High", "e"),
        Finding("b", "x", "r2", "us-east-1", "del", 5.0, "High", "e", protected=True),
    ]
    assert total_savings(fs) == 10.0


def test_waste_dry_run():
    session = create_session()
    result = scan_waste(session, dry_run=True)
    assert result["finding_count"] >= 2
    assert result["estimated_monthly_savings_usd"] > 0
    rows = findings_to_rows(result["findings"])
    assert rows[0]["estimated_monthly_usd"] >= rows[-1]["estimated_monthly_usd"]


def test_cli_waste_dry_run(tmp_path):
    from awstools.cli import main

    code = main(
        ["waste", "--dry-run", "--output-dir", str(tmp_path), "--format", "json", "--quiet"]
    )
    assert code in (0, 5)
    assert (tmp_path / "findings.json").exists()
    assert (tmp_path / "findings.csv").exists()
