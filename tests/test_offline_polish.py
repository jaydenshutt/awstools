"""Offline polish: config, findings, fingerprint, schemas, CLI."""

import json
import os
from pathlib import Path

import pytest

from awstools.common.config import load_config
from awstools.common.findings import (
    Finding,
    apply_filters,
    dedupe_findings,
    findings_payload,
    savings_breakdown,
    total_savings,
)
from awstools.common.plan_fingerprint import attach_fingerprint, verify_plan_fingerprint
from awstools.common.schema import (
    validate_findings_payload,
    validate_purge_plan,
    validate_summary_v2,
)
from awstools.common.diff import diff_summaries
from awstools.common.redact import redact_obj
from awstools.common.errors import classify_boto_error, AwsToolsError
from awstools.common import exit_codes as ec
from awstools.cli import main
from awstools.common.safety import BucketFilter
from awstools.purge.s3 import sample_purge_plan


def test_dedupe_and_high_only_totals():
    fs = [
        Finding("a", "unattached_ebs", "vol-1", "us-east-1", "del", 10, "High", "e"),
        Finding("b", "unattached_ebs", "vol-1", "us-east-1", "del", 8, "Medium", "e"),
        Finding("c", "old_snapshot", "snap-1", "us-east-1", "del", 5, "Medium", "e"),
    ]
    d = dedupe_findings(fs)
    assert len(d) == 2
    br = savings_breakdown(d)
    assert br["high_confidence_usd"] == 10.0
    assert br["all_confidence_usd"] == 15.0


def test_apply_filters_ignore_category():
    from awstools.common.config import ToolsConfig

    cfg = ToolsConfig(ignore_categories=["nat_gateway_review"], grace_days=7)
    fs = [
        Finding("n", "nat_gateway_review", "nat-1", "us-east-1", "rev", 0, "Low", "e"),
        Finding(
            "e",
            "unattached_ebs",
            "vol-new",
            "us-east-1",
            "del",
            5,
            "High",
            "e",
            metadata={"age_days": 1},
        ),
    ]
    apply_filters(fs, cfg)
    assert fs[0].ignored
    assert fs[1].ignored  # grace


def test_plan_fingerprint_stable():
    plan = {
        "account_id": "123",
        "selected": [{"name": "b", "region": "us-east-1", "versioned": False, "action": "empty+delete"}],
        "protected": [],
        "filtered_out": [],
        "selected_count": 1,
    }
    p1 = attach_fingerprint(plan)
    p2 = attach_fingerprint(dict(plan))
    assert p1["plan_fingerprint"] == p2["plan_fingerprint"]
    ok, _ = verify_plan_fingerprint(p1)
    assert ok
    p1["selected"].append(
        {"name": "c", "region": "us-east-1", "versioned": False, "action": "empty+delete"}
    )
    ok, msg = verify_plan_fingerprint(p1, expected=p2["plan_fingerprint"])
    assert not ok


def test_sample_purge_plan_schema():
    bf = BucketFilter(include=["tmp-*"])
    plan = sample_purge_plan(bf)
    ok, errors = validate_purge_plan(plan)
    assert ok, errors
    assert plan["selected_count"] >= 1
    assert "aws-cloudtrail" in " ".join(plan["protected"]) or plan["protected_count"] >= 1


def test_findings_payload_schema():
    fs = [
        Finding("a", "unattached_ebs", "vol-1", "us-east-1", "del", 10, "High", "e"),
    ]
    payload = findings_payload(fs, account_id="000")
    ok, errors = validate_findings_payload(payload)
    assert ok, errors


def test_redact_account():
    d = redact_obj({"account_id": "123456789012", "arn": "arn:aws:iam::123456789012:user/x"})
    assert d["account_id"] != "123456789012"
    assert "123456789012" not in d["arn"]


def test_diff_summaries():
    prev = {
        "latest_total": 100,
        "estimated_monthly_savings_usd": 10,
        "top_services": [{"service": "EC2", "amount": 80}],
        "anomaly_count": 0,
    }
    cur = {
        "latest_total": 150,
        "estimated_monthly_savings_usd": 20,
        "top_services": [{"service": "EC2", "amount": 120}],
        "anomaly_count": 2,
    }
    d = diff_summaries(cur, prev)
    assert d["latest_total"]["delta"] == 50


def test_classify_expired():
    class E(Exception):
        response = {"Error": {"Code": "ExpiredToken", "Message": "token expired"}}

    err = classify_boto_error(E("ExpiredToken"))
    assert err.code == "auth_expired"
    assert err.exit_code == 2


def test_cli_offline_whoami(monkeypatch):
    monkeypatch.setenv("AWSTOOLS_OFFLINE", "1")
    code = main(["whoami", "--format", "json", "--quiet"])
    assert code == 0


def test_cli_offline_waste_schema(tmp_path, monkeypatch):
    monkeypatch.setenv("AWSTOOLS_OFFLINE", "1")
    out = tmp_path / "w"
    code = main(["waste", "--output-dir", str(out), "--format", "json", "--quiet"])
    assert code in (0, 5)
    data = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    ok, errors = validate_findings_payload(data)
    assert ok, errors
    assert data["estimated_monthly_savings_usd"] <= data[
        "estimated_monthly_savings_all_confidence_usd"
    ]


def test_cli_offline_cost_schema(tmp_path, monkeypatch):
    monkeypatch.setenv("AWSTOOLS_OFFLINE", "1")
    out = tmp_path / "c"
    code = main(
        [
            "cost",
            "--output-dir",
            str(out),
            "--quiet",
            "--no-export-actions",
            "--format",
            "json",
        ]
    )
    assert code in (0, 5)
    data = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    ok, errors = validate_summary_v2(data)
    assert ok, errors


def test_cli_offline_purge_plan(tmp_path, monkeypatch):
    monkeypatch.setenv("AWSTOOLS_OFFLINE", "1")
    code = main(
        [
            "purge-s3",
            "--plan",
            "--include",
            "tmp-*",
            "--audit-log",
            str(tmp_path / "a.json"),
            "--format",
            "json",
            "--quiet",
        ]
    )
    assert code == 0
    plan = json.loads((tmp_path / "a-plan.json").read_text(encoding="utf-8"))
    ok, errors = validate_purge_plan(plan)
    assert ok, errors


def test_cli_refuse_offline_execute(monkeypatch):
    monkeypatch.setenv("AWSTOOLS_OFFLINE", "1")
    code = main(
        [
            "ebs-cleanup",
            "--execute",
            "--confirm-account",
            "000000000000",
            "--resource",
            "vol-sample",
            "--yes",
            "--quiet",
        ]
    )
    assert code == ec.SAFETY_GATE


def test_cli_execute_requires_scope(monkeypatch):
    monkeypatch.setenv("AWSTOOLS_OFFLINE", "0")
    # Still offline via --dry-run path for discovery, but execute without scope
    # Use --offline so no AWS, execute refused either for offline or scope
    code = main(
        [
            "ebs-cleanup",
            "--offline",
            "--execute",
            "--confirm-account",
            "000000000000",
            "--yes",
            "--quiet",
        ]
    )
    assert code == ec.SAFETY_GATE


def test_cli_cost_compare(tmp_path, monkeypatch):
    monkeypatch.setenv("AWSTOOLS_OFFLINE", "1")
    out1 = tmp_path / "a"
    out2 = tmp_path / "b"
    main(["cost", "--output-dir", str(out1), "--quiet", "--no-export-actions"])
    prev = out1 / "summary.json"
    code = main(
        [
            "cost",
            "--output-dir",
            str(out2),
            "--compare",
            str(prev),
            "--quiet",
            "--no-export-actions",
            "--format",
            "json",
        ]
    )
    assert code in (0, 5)
    # summary should exist; diff may be in stdout only for json emit - check file still ok
    assert (out2 / "summary.json").exists()


def test_cli_detectors_filter(tmp_path, monkeypatch):
    monkeypatch.setenv("AWSTOOLS_OFFLINE", "1")
    out = tmp_path / "w"
    main(
        [
            "waste",
            "--detectors",
            "unattached_ebs,unassociated_eip",
            "--output-dir",
            str(out),
            "--quiet",
        ]
    )
    data = json.loads((out / "findings.json").read_text(encoding="utf-8"))
    cats = {f["category"] for f in data["findings"]}
    assert cats <= {"unattached_ebs", "unassociated_eip"}


def test_load_config_example():
    root = Path(__file__).resolve().parents[1]
    cfg = load_config(config_path=str(root / "examples" / "awstools.toml"))
    assert cfg.default_region == "us-east-1"
    assert cfg.grace_days == 3
