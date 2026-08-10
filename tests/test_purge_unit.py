"""Unit tests for purge helpers (no AWS calls)."""

from awstools.purge.s3 import PurgeResult, BucketOutcome
from awstools.common.safety import BucketFilter


def test_purge_result_audit(tmp_path):
    r = PurgeResult(
        account_id="123456789012",
        caller_arn="arn:aws:iam::123456789012:user/test",
        dry_run=True,
        started_at="2025-01-01T00:00:00+00:00",
        selected=["a"],
        protected=["aws-cloudtrail-x"],
        filtered_out=[],
        outcomes=[BucketOutcome(name="a", region="us-east-1", objects_deleted=3)],
    )
    r.finished_at = "2025-01-01T00:01:00+00:00"
    path = tmp_path / "audit.json"
    r.write_audit_log(path)
    text = path.read_text(encoding="utf-8")
    assert "123456789012" in text
    assert "aws-cloudtrail-x" in text
    assert "dry_run" in text


def test_classify_integration():
    bf = BucketFilter(include=["lab-*"])
    c = bf.classify(["lab-1", "lab-2", "prod", "aws-logs-123"])
    assert set(c["selected"]) == {"lab-1", "lab-2"}
    assert "aws-logs-123" in c["protected"]
