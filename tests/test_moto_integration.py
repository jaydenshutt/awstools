"""Integration-style tests with moto (no live AWS)."""

from __future__ import annotations

import boto3
import pytest

moto = pytest.importorskip("moto")
from moto import mock_aws  # noqa: E402

from awstools.common.safety import BucketFilter
from awstools.cleanup.ebs import find_unattached_volumes
from awstools.cleanup.eip import find_unassociated_eips
from awstools.purge.s3 import build_purge_plan, is_versioning_active, get_bucket_region
from awstools.common.session import client as aws_client
from awstools.common.schema import validate_purge_plan


@pytest.fixture
def aws_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.delenv("AWSTOOLS_OFFLINE", raising=False)


@mock_aws
def test_purge_plan_with_real_s3_shape(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="tmp-lab-data")
    s3.create_bucket(Bucket="my-app-assets")
    s3.create_bucket(Bucket="aws-cloudtrail-logs-123456789012")
    s3.put_object(Bucket="tmp-lab-data", Key="a.txt", Body=b"hello")

    sts = session.client("sts")
    account = sts.get_caller_identity()["Account"]

    bf = BucketFilter(include=["tmp-*"])
    plan = build_purge_plan(
        session,
        bf,
        account_id=account,
        caller_arn="arn:aws:iam::%s:user/test" % account,
        estimate_objects=True,
        offline=False,
    )
    ok, errors = validate_purge_plan(plan)
    assert ok, errors
    names = [r["name"] for r in plan["selected"]]
    assert "tmp-lab-data" in names
    assert "my-app-assets" not in names
    assert plan["protected_count"] >= 1
    assert plan["plan_fingerprint"]


@mock_aws
def test_unattached_ebs_and_eip(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")

    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=20, VolumeType="gp3")
    vol_id = vol["VolumeId"]
    # Wait not needed in moto
    alloc = ec2.allocate_address(Domain="vpc")

    findings_v = find_unattached_volumes(session, regions=["us-east-1"], offline=False)
    ids = {f.resource_id for f in findings_v}
    assert vol_id in ids

    findings_e = find_unassociated_eips(session, regions=["us-east-1"], offline=False)
    assert any(
        f.resource_id == alloc.get("AllocationId") or f.metadata.get("public_ip") == alloc.get("PublicIp")
        for f in findings_e
    )


@mock_aws
def test_bucket_region_and_versioning(aws_credentials):
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="versioned-bucket-xyz")
    s3.put_bucket_versioning(
        Bucket="versioned-bucket-xyz",
        VersioningConfiguration={"Status": "Enabled"},
    )
    assert get_bucket_region(s3, "versioned-bucket-xyz") == "us-east-1"
    assert is_versioning_active(s3, "versioned-bucket-xyz") is True
