"""Tests for service-scoped recommendations."""

import pandas as pd

from awstools.cost.recommendations import (
    build_recommendations,
    match_service_key,
    service_spend_map,
    compute_priority_confidence,
)


def test_match_service_key():
    assert match_service_key("Amazon Elastic Compute Cloud - Compute") == "ec2"
    assert match_service_key("Amazon Simple Storage Service") == "s3"
    assert match_service_key("Amazon Relational Database Service") == "rds"
    assert match_service_key("AWS Lambda") == "lambda"


def test_service_spend_map():
    top = [
        ("Amazon Elastic Compute Cloud - Compute", 200.0),
        ("Amazon Simple Storage Service", 50.0),
    ]
    m = service_spend_map(top)
    assert m["ec2"] == 200.0
    assert m["s3"] == 50.0


def test_recommendations_scoped_to_spend():
    pivot = pd.DataFrame(
        {"total": [100.0, 110.0, 120.0]},
        index=pd.date_range("2025-01-01", periods=3, freq="MS"),
    )
    top = [
        ("Amazon Elastic Compute Cloud - Compute", 90.0),
        ("Amazon Simple Storage Service", 30.0),
    ]
    wasted = {"unattached_ebs": ["vol-1", "vol-2"], "unassociated_eips": []}
    resources = {"EC2": 3, "S3_buckets": 2, "RDS": 0}
    recs, objs, summary, per_svc, glossary = build_recommendations(
        120.0, pivot, top, wasted, resources
    )
    assert "120.00" in summary or "120" in summary
    services = {o["service"] for o in objs}
    assert any("EC2" in s or "EBS" in s for s in services)
    # EC2 estimate should be ~15% of 90 = 13.5
    ec2_obj = next(o for o in objs if "EC2" in o["service"] and o["id"].startswith("rec_"))
    assert abs(ec2_obj["estimated_monthly_savings"] - 13.5) < 0.01
    # Wasted EBS: 2 * $5
    ebs_w = next(o for o in objs if o["id"] == "wasted_ebs")
    assert ebs_w["estimated_monthly_savings"] == 10.0
    assert glossary


def test_no_generic_rds_when_absent():
    pivot = pd.DataFrame(
        {"total": [50.0, 50.0]},
        index=pd.date_range("2025-01-01", periods=2, freq="MS"),
    )
    top = [("Amazon Simple Storage Service", 50.0)]
    wasted = {}
    resources = {"S3_buckets": 3, "RDS": 0, "EC2": 0}
    _, objs, _, per_svc, _ = build_recommendations(50.0, pivot, top, wasted, resources)
    labels = " ".join(per_svc.keys()).lower()
    assert "rds" not in labels
    assert any("S3" in k for k in per_svc)


def test_priority_confidence_wasted():
    pr, conf, reason, score = compute_priority_confidence(
        50.0, 1000.0, source="wasted", extra={"count": 10}
    )
    assert conf == "High"
    assert "10" in reason
    assert score > 0
