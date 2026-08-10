"""Savings Plans / RI coverage hints via Cost Explorer (best-effort)."""

from __future__ import annotations

import logging
from datetime import date, timedelta
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from awstools.common.session import client as aws_client

LOG = logging.getLogger("awstools.cost.commitments")


def fetch_commitment_coverage(session, dry_run: bool = False) -> Dict[str, Any]:
    """
    Return rough coverage signals using CE group-by RECORD_TYPE / purchase option.

    Not a full SP/RI analyzer - directional only.
    """
    if dry_run:
        return {
            "available": True,
            "on_demand_share_pct": 72.0,
            "reserved_share_pct": 18.0,
            "savings_plan_share_pct": 10.0,
            "hint": (
                "Sample: ~72% on-demand. Consider Compute Savings Plans "
                "if steady-state EC2/Fargate/Lambda load exists."
            ),
            "notes": [],
        }

    ce = aws_client(session, "ce")
    end = date.today().replace(day=1)
    start = (end - timedelta(days=60)).replace(day=1)
    start_str, end_str = start.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d")

    # Try purchase option dimension
    buckets = {"On Demand": 0.0, "Reserved": 0.0, "Spot": 0.0, "Savings Plans": 0.0}
    notes: List[str] = []
    try:
        resp = ce.get_cost_and_usage(
            TimePeriod={"Start": start_str, "End": end_str},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "PURCHASE_TYPE"}],
        )
        for r in resp.get("ResultsByTime", []):
            for g in r.get("Groups", []):
                key = g.get("Keys", ["Unknown"])[0]
                amt = float(g.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", 0))
                # normalize keys
                kl = key.lower()
                if "savings" in kl:
                    buckets["Savings Plans"] = buckets.get("Savings Plans", 0) + amt
                elif "reserved" in kl or "reservation" in kl:
                    buckets["Reserved"] += amt
                elif "spot" in kl:
                    buckets["Spot"] += amt
                elif "on demand" in kl or "ondemand" in kl.replace(" ", ""):
                    buckets["On Demand"] += amt
                else:
                    buckets[key] = buckets.get(key, 0.0) + amt
    except ClientError as e:
        LOG.debug("PURCHASE_TYPE grouping failed: %s", e)
        notes.append(f"Purchase type grouping unavailable: {e}")
        return {"available": False, "hint": None, "notes": notes, "error": str(e)}
    except Exception as e:
        return {"available": False, "hint": None, "notes": [str(e)], "error": str(e)}

    total = sum(buckets.values()) or 1.0
    on_d = buckets.get("On Demand", 0.0)
    reserved = buckets.get("Reserved", 0.0)
    sp = buckets.get("Savings Plans", 0.0)

    on_pct = 100.0 * on_d / total
    hint = None
    if on_pct >= 60 and on_d >= 50:
        hint = (
            f"About {on_pct:.0f}% of recent compute-related purchase types look On-Demand. "
            "If load is steady, model a 1-year Compute Savings Plan on the largest EC2/Lambda "
            "baseline (validate with AWS Cost Explorer recommendations)."
        )
    elif on_pct < 40:
        hint = (
            "Commitment coverage looks relatively healthy versus on-demand share. "
            "Re-check after major workload changes."
        )
    else:
        hint = (
            "Mixed purchase profile. Review Cost Explorer Rightsizing and SP recommendations "
            "before buying commitments."
        )

    return {
        "available": True,
        "buckets_usd": {k: round(v, 2) for k, v in buckets.items() if v},
        "on_demand_share_pct": round(on_pct, 1),
        "reserved_share_pct": round(100.0 * reserved / total, 1),
        "savings_plan_share_pct": round(100.0 * sp / total, 1),
        "hint": hint,
        "notes": notes,
    }


def fetch_ce_forecast(session, months: int = 3, dry_run: bool = False) -> Optional[Dict[str, Any]]:
    """Best-effort GetCostForecast for next period."""
    if dry_run:
        return {
            "available": True,
            "mean_value": 400.0,
            "unit": "USD",
            "start": str(date.today()),
            "end": str(date.today() + timedelta(days=30 * months)),
            "source": "sample",
        }
    try:
        ce = aws_client(session, "ce")
        start = date.today()
        # CE forecast end exclusive
        end = start + timedelta(days=max(months, 1) * 30)
        resp = ce.get_cost_forecast(
            TimePeriod={"Start": start.strftime("%Y-%m-%d"), "End": end.strftime("%Y-%m-%d")},
            Metric="UNBLENDED_COST",
            Granularity="MONTHLY",
        )
        total = resp.get("Total", {})
        return {
            "available": True,
            "mean_value": float(total.get("Amount", 0) or 0),
            "unit": total.get("Unit", "USD"),
            "start": start.isoformat(),
            "end": end.isoformat(),
            "source": "ce_get_cost_forecast",
            "forecast_results": resp.get("ForecastResultsByTime", [])[:6],
        }
    except Exception as e:
        LOG.debug("GetCostForecast unavailable: %s", e)
        return {"available": False, "error": str(e)}
