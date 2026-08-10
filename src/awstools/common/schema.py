"""Lightweight schema checks for machine-readable outputs."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple


def _require(d: Dict[str, Any], keys: List[str]) -> List[str]:
    return [k for k in keys if k not in d]


def validate_summary_v2(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    errors = _require(
        data,
        [
            "schema_version",
            "account_id",
            "latest_total",
            "coverage",
            "warnings",
        ],
    )
    if data.get("schema_version") not in (2, "2"):
        errors.append("schema_version must be 2")
    if "coverage" in data and not isinstance(data["coverage"], dict):
        errors.append("coverage must be object")
    return (len(errors) == 0, errors)


def validate_findings_payload(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    errors = _require(
        data,
        [
            "schema_version",
            "finding_count",
            "estimated_monthly_savings_usd",
            "findings",
            "savings_breakdown",
        ],
    )
    if not isinstance(data.get("findings"), list):
        errors.append("findings must be a list")
    else:
        for i, f in enumerate(data["findings"][:5]):
            if not isinstance(f, dict):
                errors.append(f"findings[{i}] not object")
                continue
            for k in ("id", "category", "resource_id", "confidence", "estimated_monthly_usd"):
                if k not in f:
                    errors.append(f"findings[{i}] missing {k}")
    br = data.get("savings_breakdown") or {}
    if not isinstance(br, dict) or "high_confidence_usd" not in br:
        errors.append("savings_breakdown.high_confidence_usd required")
    return (len(errors) == 0, errors)


def validate_purge_plan(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    errors = _require(
        data,
        ["account_id", "selected_count", "selected", "blast_radius", "plan_fingerprint"],
    )
    return (len(errors) == 0, errors)
