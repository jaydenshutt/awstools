"""boto3 session helpers with consistent profile / region handling."""

from __future__ import annotations

import os
from typing import Any, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, ProfileNotFound, NoCredentialsError

from awstools.common.errors import AwsToolsError, classify_boto_error
from awstools.common.offline import SAMPLE_ACCOUNT_ID, SAMPLE_CALLER_ARN, is_offline

_BOTO_CONFIG = Config(
    retries={"max_attempts": 10, "mode": "adaptive"},
    user_agent_extra="awstools/2.0",
)


def create_session(
    profile: Optional[str] = None,
    region: Optional[str] = None,
) -> boto3.Session:
    """Create a boto3 Session from optional profile and region."""
    kwargs: dict[str, Any] = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    elif not os.environ.get("AWS_REGION") and not os.environ.get("AWS_DEFAULT_REGION"):
        kwargs.setdefault("region_name", "us-east-1")
    try:
        return boto3.Session(**kwargs)
    except ProfileNotFound as e:
        raise classify_boto_error(e) from e
    except Exception as e:
        # Don't mask unrelated errors
        if "profile" in str(e).lower():
            raise classify_boto_error(e) from e
        raise


def client(session: boto3.Session, service: str, region_name: Optional[str] = None):
    """Create a service client with shared retry config."""
    return session.client(service, region_name=region_name, config=_BOTO_CONFIG)


def get_account_id(session: boto3.Session, *, offline: bool = False) -> str:
    if offline or is_offline():
        return SAMPLE_ACCOUNT_ID
    try:
        sts = client(session, "sts")
        return sts.get_caller_identity()["Account"]
    except (BotoCoreError, ClientError, NoCredentialsError) as e:
        raise classify_boto_error(e) from e


def get_caller_arn(session: boto3.Session, *, offline: bool = False) -> str:
    if offline or is_offline():
        return SAMPLE_CALLER_ARN
    try:
        sts = client(session, "sts")
        return sts.get_caller_identity().get("Arn", "unknown")
    except (BotoCoreError, ClientError, NoCredentialsError) as e:
        raise classify_boto_error(e) from e


def resolve_identity(session: boto3.Session, *, offline: bool = False) -> dict:
    """Return account_id + arn or raise AwsToolsError."""
    if offline or is_offline():
        return {
            "account_id": SAMPLE_ACCOUNT_ID,
            "arn": SAMPLE_CALLER_ARN,
            "offline": True,
        }
    try:
        sts = client(session, "sts")
        ident = sts.get_caller_identity()
        return {
            "account_id": ident["Account"],
            "arn": ident.get("Arn", "unknown"),
            "offline": False,
        }
    except (BotoCoreError, ClientError, NoCredentialsError) as e:
        raise classify_boto_error(e) from e


def resolve_regions(
    session: boto3.Session,
    regions: Optional[list[str]] = None,
    all_regions: bool = False,
) -> list[str]:
    """Resolve the list of regions to scan."""
    if regions:
        return regions
    if all_regions:
        try:
            return sorted(session.get_available_regions("ec2"))
        except Exception:
            pass
    region = (
        session.region_name
        or os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or "us-east-1"
    )
    return [region]
