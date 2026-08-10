"""Plan fingerprinting so execute matches a reviewed plan."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional


def canonical_plan_body(plan: Dict[str, Any]) -> Dict[str, Any]:
    """Strip volatile fields before hashing."""
    body = {
        "account_id": plan.get("account_id"),
        "selected": [
            {
                "name": r.get("name"),
                "region": r.get("region"),
                "versioned": r.get("versioned"),
                "action": r.get("action"),
            }
            for r in (plan.get("selected") or [])
        ],
        "protected": sorted(plan.get("protected") or []),
        "filtered_out": sorted(plan.get("filtered_out") or []),
        "selected_count": plan.get("selected_count"),
    }
    return body


def fingerprint_plan(plan: Dict[str, Any]) -> str:
    raw = json.dumps(canonical_plan_body(plan), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def attach_fingerprint(plan: Dict[str, Any]) -> Dict[str, Any]:
    plan = dict(plan)
    plan["plan_fingerprint"] = fingerprint_plan(plan)
    return plan


def verify_plan_fingerprint(
    plan: Dict[str, Any], expected: Optional[str] = None
) -> tuple[bool, str]:
    """
    Verify plan integrity.

    If expected is None, use plan['plan_fingerprint'] and recompute.
    """
    expected = expected or plan.get("plan_fingerprint")
    if not expected:
        return False, "Plan has no plan_fingerprint; re-run with --plan"
    actual = fingerprint_plan(plan)
    if actual != expected:
        return (
            False,
            f"Plan fingerprint mismatch (expected {expected[:12]}… got {actual[:12]}…). "
            "Filters or bucket set changed - generate a new plan.",
        )
    return True, "ok"
