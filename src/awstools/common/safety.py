"""Safety rails for destructive operations."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional


# Buckets that are commonly critical and should never be bulk-deleted by accident.
DEFAULT_PROTECTED_PATTERNS = (
    "aws-cloudtrail-*",
    "aws-logs-*",
    "cf-templates-*",
    "cloudformation-*",
    "*-cloudtrail-*",
    "*-access-logs*",
    "*-alb-logs*",
    "*-elb-logs*",
    "*-vpc-flow-logs*",
    "*-config-bucket*",
    "*-terraform-state*",
    "terraform-state*",
    "tfstate*",
    "*-tf-state*",
    "cdk-*",
    "aws-controltower-*",
    "log-archive-*",
    "audit-*",
    "*-logging",
    "*-logging-*",
)


@dataclass
class BucketFilter:
    """Filter which buckets are in-scope for purge operations."""

    include: list[str] = field(default_factory=list)  # exact or glob
    exclude: list[str] = field(default_factory=list)  # exact or glob
    protect_patterns: list[str] = field(
        default_factory=lambda: list(DEFAULT_PROTECTED_PATTERNS)
    )
    require_prefix: Optional[str] = None
    allow_protected: bool = False

    def is_protected(self, name: str) -> bool:
        if self.allow_protected:
            return False
        for pattern in self.protect_patterns:
            if fnmatch.fnmatch(name, pattern):
                return True
        return False

    def matches(self, name: str) -> bool:
        if self.require_prefix and not name.startswith(self.require_prefix):
            return False
        if self.exclude:
            for pattern in self.exclude:
                if fnmatch.fnmatch(name, pattern) or name == pattern:
                    return False
        if self.include:
            return any(fnmatch.fnmatch(name, p) or name == p for p in self.include)
        return True

    def classify(self, names: Iterable[str]) -> dict[str, list[str]]:
        """Split bucket names into selected / protected / filtered_out."""
        selected: list[str] = []
        protected: list[str] = []
        filtered_out: list[str] = []
        for name in names:
            if self.is_protected(name):
                protected.append(name)
                continue
            if self.matches(name):
                selected.append(name)
            else:
                filtered_out.append(name)
        return {
            "selected": selected,
            "protected": protected,
            "filtered_out": filtered_out,
        }


def confirm_account_gate(
    expected_account_id: Optional[str],
    actual_account_id: str,
    typed_confirmation: Optional[str] = None,
) -> tuple[bool, str]:
    """
    Gate destructive ops on account ID.

    - If expected_account_id is set, it must match actual.
    - If typed_confirmation is provided, it must equal actual_account_id.
    """
    if expected_account_id and expected_account_id != actual_account_id:
        return (
            False,
            f"Account mismatch: expected {expected_account_id}, got {actual_account_id}",
        )
    if typed_confirmation is not None and typed_confirmation.strip() != actual_account_id:
        return (
            False,
            f"Confirmation text must exactly match account ID {actual_account_id}",
        )
    return True, "ok"


def is_valid_account_id(value: str) -> bool:
    return bool(re.fullmatch(r"\d{12}", value.strip()))
