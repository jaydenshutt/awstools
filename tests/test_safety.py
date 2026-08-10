"""Tests for safety rails and bucket filters."""

from awstools.common.safety import (
    BucketFilter,
    DEFAULT_PROTECTED_PATTERNS,
    confirm_account_gate,
    is_valid_account_id,
)


def test_valid_account_id():
    assert is_valid_account_id("123456789012")
    assert not is_valid_account_id("123")
    assert not is_valid_account_id("abcdefghijkl")


def test_account_gate_match():
    ok, _ = confirm_account_gate("123456789012", "123456789012", "123456789012")
    assert ok


def test_account_gate_mismatch():
    ok, msg = confirm_account_gate("111111111111", "222222222222")
    assert not ok
    assert "mismatch" in msg.lower()


def test_account_gate_typed_wrong():
    ok, _ = confirm_account_gate(None, "123456789012", "000000000000")
    assert not ok


def test_protected_cloudtrail():
    bf = BucketFilter()
    assert bf.is_protected("aws-cloudtrail-logs-123456789012")
    assert bf.is_protected("my-terraform-state-prod")
    assert bf.is_protected("company-tf-state")
    assert not bf.is_protected("my-app-assets")


def test_allow_protected_disables_protection():
    bf = BucketFilter(allow_protected=True)
    assert not bf.is_protected("aws-cloudtrail-logs-123")


def test_include_filter():
    bf = BucketFilter(include=["tmp-*", "scratch-bucket"])
    names = ["tmp-1", "scratch-bucket", "prod-data", "aws-cloudtrail-x"]
    c = bf.classify(names)
    assert "tmp-1" in c["selected"]
    assert "scratch-bucket" in c["selected"]
    assert "prod-data" in c["filtered_out"]
    assert "aws-cloudtrail-x" in c["protected"]


def test_exclude_and_prefix():
    bf = BucketFilter(exclude=["*-keep"], require_prefix="dev-")
    c = bf.classify(["dev-a", "dev-b-keep", "prod-a"])
    assert c["selected"] == ["dev-a"]
    assert "dev-b-keep" in c["filtered_out"]
    assert "prod-a" in c["filtered_out"]


def test_default_patterns_nonempty():
    assert len(DEFAULT_PROTECTED_PATTERNS) >= 5
