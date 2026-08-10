"""Cost Explorer and CUR data access."""

from __future__ import annotations

import gzip
import logging
import tempfile
from datetime import date, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
from botocore.exceptions import BotoCoreError, ClientError

from awstools.common.session import client as aws_client

LOG = logging.getLogger("awstools.cost.costs")

SAMPLE_COSTS = [
    {"date": "2025-04-01", "amount": 120.0, "service": "Amazon Elastic Compute Cloud - Compute"},
    {"date": "2025-05-01", "amount": 150.0, "service": "Amazon Elastic Compute Cloud - Compute"},
    {"date": "2025-06-01", "amount": 200.0, "service": "Amazon Elastic Compute Cloud - Compute"},
    {"date": "2025-04-01", "amount": 80.0, "service": "Amazon Simple Storage Service"},
    {"date": "2025-05-01", "amount": 90.0, "service": "Amazon Simple Storage Service"},
    {"date": "2025-06-01", "amount": 110.0, "service": "Amazon Simple Storage Service"},
    {"date": "2025-04-01", "amount": 40.0, "service": "Amazon Relational Database Service"},
    {"date": "2025-05-01", "amount": 45.0, "service": "Amazon Relational Database Service"},
    {"date": "2025-06-01", "amount": 60.0, "service": "Amazon Relational Database Service"},
]


class CostExplorerError(Exception):
    """Raised when Cost Explorer cannot be queried (not enabled / denied)."""

    def __init__(self, message: str, code: Optional[str] = None):
        super().__init__(message)
        self.code = code


def fetch_costs_ce(
    session,
    months: int = 6,
    dry_run: bool = False,
    tag_keys: Optional[List[str]] = None,
    raise_on_ce_error: bool = True,
) -> Tuple[List[Dict], List[Dict], Dict[str, Dict[str, float]]]:
    """
    Fetch monthly cost by service via Cost Explorer.

    Returns (service_costs, resource_level_costs, tag_aggregates).
    Raises CostExplorerError when CE is unavailable and raise_on_ce_error=True.
    """
    if dry_run:
        return list(SAMPLE_COSTS), [], {}

    ce = aws_client(session, "ce")
    end = date.today().replace(day=1)
    # Approximate months back
    start = (end - timedelta(days=max(months, 1) * 31)).replace(day=1)
    start_str = start.strftime("%Y-%m-%d")
    end_str = end.strftime("%Y-%m-%d")

    results: List[Dict] = []
    try:
        # Paginate Cost Explorer results
        token = None
        while True:
            kwargs: Dict[str, Any] = {
                "TimePeriod": {"Start": start_str, "End": end_str},
                "Granularity": "MONTHLY",
                "Metrics": ["UnblendedCost"],
                "GroupBy": [{"Type": "DIMENSION", "Key": "SERVICE"}],
            }
            if token:
                kwargs["NextPageToken"] = token
            resp = ce.get_cost_and_usage(**kwargs)
            for r in resp.get("ResultsByTime", []):
                period_start = r.get("TimePeriod", {}).get("Start")
                for g in r.get("Groups", []):
                    service = g.get("Keys", ["Unknown"])[0]
                    amount = float(
                        g.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", 0.0)
                    )
                    if amount == 0:
                        continue
                    results.append(
                        {"date": period_start, "amount": amount, "service": service}
                    )
            token = resp.get("NextPageToken")
            if not token:
                break
    except (BotoCoreError, ClientError) as e:
        code = None
        if isinstance(e, ClientError):
            code = e.response.get("Error", {}).get("Code")
        msg = (
            f"Cost Explorer query failed ({code or type(e).__name__}): {e}. "
            "Enable Cost Explorer in the account (Billing console) and ensure "
            "ce:GetCostAndUsage permission. Data can lag ~24h after enablement."
        )
        LOG.error(msg)
        if raise_on_ce_error:
            raise CostExplorerError(msg, code=code) from e
        return [], [], {}

    resource_level: List[Dict] = []
    try:
        token = None
        while True:
            kwargs = {
                "TimePeriod": {"Start": start_str, "End": end_str},
                "Granularity": "MONTHLY",
                "Metrics": ["UnblendedCost"],
                "GroupBy": [{"Type": "DIMENSION", "Key": "RESOURCE_ID"}],
            }
            if token:
                kwargs["NextPageToken"] = token
            resp_r = ce.get_cost_and_usage(**kwargs)
            for r in resp_r.get("ResultsByTime", []):
                period_start = r.get("TimePeriod", {}).get("Start")
                for g in r.get("Groups", []):
                    rid = g.get("Keys", ["Unknown"])[0]
                    amount = float(
                        g.get("Metrics", {}).get("UnblendedCost", {}).get("Amount", 0.0)
                    )
                    if amount == 0:
                        continue
                    resource_level.append(
                        {"date": period_start, "resource_id": rid, "amount": amount}
                    )
            token = resp_r.get("NextPageToken")
            if not token:
                break
    except Exception as e:
        LOG.debug("RESOURCE_ID grouping unavailable: %s", e)
        resource_level = []

    tag_aggregates: Dict[str, Dict[str, float]] = {}
    if tag_keys:
        for tag in tag_keys:
            try:
                resp_t = ce.get_cost_and_usage(
                    TimePeriod={"Start": start_str, "End": end_str},
                    Granularity="MONTHLY",
                    Metrics=["UnblendedCost"],
                    GroupBy=[{"Type": "TAG", "Key": f"user:{tag}"}],
                )
                tag_totals: Dict[str, float] = {}
                for r in resp_t.get("ResultsByTime", []):
                    for g in r.get("Groups", []):
                        k = g.get("Keys", ["Unknown"])[0]
                        amt = float(
                            g.get("Metrics", {})
                            .get("UnblendedCost", {})
                            .get("Amount", 0.0)
                        )
                        tag_totals[k] = tag_totals.get(k, 0.0) + amt
                tag_aggregates[tag] = tag_totals
            except Exception as e:
                LOG.warning("Tag aggregation failed for %s: %s", tag, e)
                tag_aggregates[tag] = {}

    return results, resource_level, tag_aggregates


def parse_cur_local(path: str) -> Dict[str, float]:
    """Parse a local CUR CSV (optionally .gz) → resource_id -> cost."""
    p = Path(path)
    opener = gzip.open if p.suffix == ".gz" or path.endswith(".gz") else open
    try:
        with opener(path, "rt", encoding="utf-8") as f:
            df = pd.read_csv(f)
    except Exception as e:
        LOG.error("Failed to read CUR file %s: %s", path, e)
        return {}

    cols_lower = {c.lower(): c for c in df.columns}
    rid_col = None
    for candidate in ("lineitem/resourceid", "resourceid", "resource_id", "resource"):
        if candidate in cols_lower:
            rid_col = cols_lower[candidate]
            break
    # Also match columns containing resourceid
    if not rid_col:
        for low, orig in cols_lower.items():
            if "resourceid" in low.replace("_", "").replace("/", ""):
                rid_col = orig
                break
    if not rid_col:
        LOG.warning("No resource id column found in CUR")
        return {}

    cost_col = None
    for candidate in (
        "lineitem/unblendedcost",
        "unblendedcost",
        "lineitemunblendedcost",
        "cost",
    ):
        if candidate in cols_lower:
            cost_col = cols_lower[candidate]
            break
    if not cost_col:
        for low, orig in cols_lower.items():
            if "unblendedcost" in low.replace("_", "").replace("/", ""):
                cost_col = orig
                break
    if not cost_col:
        LOG.warning("No cost column found in CUR")
        return {}

    date_cols = [c for c in df.columns if "date" in c.lower() or "usage" in c.lower()]
    df_recent = df
    if date_cols:
        try:
            df["_parsed_date"] = pd.to_datetime(df[date_cols[0]], errors="coerce")
            recent_month = df["_parsed_date"].dt.to_period("M").max()
            df_recent = df[df["_parsed_date"].dt.to_period("M") == recent_month]
        except Exception:
            df_recent = df

    grouped = df_recent.groupby(rid_col)[cost_col].sum()
    return {str(k): float(v) for k, v in grouped.to_dict().items() if k and str(k) != "nan"}


def parse_cur_s3(session, bucket: str, prefix: str) -> Dict[str, float]:
    """Download and parse CUR objects under s3://bucket/prefix."""
    s3 = aws_client(session, "s3")
    costs: Dict[str, float] = {}
    try:
        paginator = s3.get_paginator("list_objects_v2")
        keys: List[str] = []
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                key = obj.get("Key", "")
                if key.endswith((".csv", ".csv.gz", ".gz")) or "csv" in key.lower():
                    keys.append(key)
        if not keys:
            LOG.warning("No CUR CSV objects found under s3://%s/%s", bucket, prefix)
            return {}

        with tempfile.TemporaryDirectory(prefix="awstools-cur-") as tmp:
            tmpdir = Path(tmp)
            for key in keys[:20]:  # safety cap
                local = tmpdir / Path(key).name
                LOG.info("Downloading CUR object s3://%s/%s", bucket, key)
                s3.download_file(bucket, key, str(local))
                part = parse_cur_local(str(local))
                for k, v in part.items():
                    costs[k] = costs.get(k, 0.0) + v
    except Exception as e:
        LOG.error("Failed to read CUR from S3: %s", e)
    return costs


def prepare_timeseries(cost_events: List[Dict]) -> pd.DataFrame:
    df = pd.DataFrame(cost_events)
    if df.empty:
        return pd.DataFrame()
    df["date"] = pd.to_datetime(df["date"]).dt.to_period("M").dt.to_timestamp()
    pivot = df.pivot_table(
        index="date", columns="service", values="amount", aggfunc="sum", fill_value=0.0
    )
    pivot["total"] = pivot.sum(axis=1)
    return pivot.sort_index()


def forecast_linear(series: pd.Series, months: int = 3) -> pd.Series:
    import numpy as np

    if series.empty:
        return pd.Series(dtype=float)
    x = np.arange(len(series))
    y = series.values.astype(float)
    if len(x) < 2:
        last = float(y[-1]) if len(y) else 0.0
        idx = pd.date_range(
            series.index[-1] + pd.offsets.MonthBegin(), periods=months, freq="MS"
        )
        return pd.Series([last] * months, index=idx)
    A = np.vstack([x, np.ones_like(x)]).T
    m, c = np.linalg.lstsq(A, y, rcond=None)[0]
    future_x = np.arange(len(series), len(series) + months)
    preds = m * future_x + c
    # Floor at zero - negative spend forecasts are not useful
    preds = np.maximum(preds, 0.0)
    idx = pd.date_range(
        series.index[-1] + pd.offsets.MonthBegin(), periods=months, freq="MS"
    )
    return pd.Series(preds, index=idx)


def forecast_exponential_smoothing(
    series: pd.Series, months: int = 3, alpha: float = 0.3
) -> pd.Series:
    if series.empty:
        return pd.Series(dtype=float)
    values = series.astype(float).values
    s = float(values[0])
    for v in values[1:]:
        s = alpha * float(v) + (1 - alpha) * s
    if len(values) >= 2:
        recent_growth = (values[-1] - values[-2]) / max(abs(values[-2]), 1e-6)
        recent_growth = max(min(recent_growth, 0.5), -0.5)
    else:
        recent_growth = 0.0
    preds = []
    curr = s
    for _ in range(months):
        curr = max(curr * (1 + recent_growth), 0.0)
        preds.append(curr)
    idx = pd.date_range(
        series.index[-1] + pd.offsets.MonthBegin(), periods=months, freq="MS"
    )
    return pd.Series(preds, index=idx)
