"""Offline / dry-run development mode (no AWS account required)."""

from __future__ import annotations

import os
from typing import Optional


OFFLINE_ENV = "AWSTOOLS_OFFLINE"
SAMPLE_ACCOUNT_ID = "000000000000"
SAMPLE_CALLER_ARN = "arn:aws:iam::000000000000:user/awstools-dry-run"


def env_offline() -> bool:
    """True when AWSTOOLS_OFFLINE is set to a truthy value."""
    return os.environ.get(OFFLINE_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def is_offline(dry_run: bool = False, force_offline: bool = False) -> bool:
    """Resolve whether we should avoid live AWS calls."""
    return bool(force_offline or dry_run or env_offline())


def require_live_or_offline(
    *,
    dry_run: bool = False,
    offline_flag: bool = False,
    command: str = "command",
) -> tuple[bool, Optional[str]]:
    """
    Returns (offline, error_message).

    If AWSTOOLS_OFFLINE=1 and user did not pass dry-run/offline, still force offline
    for safety during development - never call AWS when env is set.
    """
    if env_offline() or offline_flag or dry_run:
        return True, None
    return False, None


def offline_identity() -> dict:
    return {
        "account_id": SAMPLE_ACCOUNT_ID,
        "arn": SAMPLE_CALLER_ARN,
        "offline": True,
    }
