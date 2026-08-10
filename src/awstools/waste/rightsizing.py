"""Optional EC2 rightsizing hints from CloudWatch CPU (fixture-friendly)."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from awstools.common.findings import Finding, has_protect_tag
from awstools.common.session import client as aws_client

LOG = logging.getLogger("awstools.waste.rightsizing")

# If average CPU over lookback is below this, suggest downsize review
CPU_LOW_THRESHOLD = 10.0  # percent
# Conservative savings: assume ~30% of a rough instance monthly floor
INSTANCE_MONTHLY_FLOOR = 30.0  # t3.medium-ish placeholder when type unknown
DOWNSIZE_FACTOR = 0.30


def sample_rightsizing_findings() -> List[Finding]:
    return [
        Finding(
            id="rightsizing:i-sample-lowcpu",
            category="ec2_rightsizing",
            resource_id="i-sample-lowcpu",
            region="us-east-1",
            service="Amazon EC2",
            action="review downsize / schedule stop for low-CPU instance",
            estimated_monthly_usd=9.0,
            confidence="Medium",
            evidence="CPU avg 3.2% over 14d (sample); instance_type=t3.large",
            estimate_formula="instance_monthly_floor * 0.30 (conservative)",
            metadata={
                "cpu_avg": 3.2,
                "lookback_days": 14,
                "instance_type": "t3.large",
                "age_days": 60,
            },
        )
    ]


def _tags_from_list(tag_list) -> Dict[str, str]:
    return {t["Key"]: t.get("Value", "") for t in (tag_list or []) if "Key" in t}


def _cpu_average(cw, instance_id: str, days: int = 14) -> Optional[float]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    try:
        resp = cw.get_metric_statistics(
            Namespace="AWS/EC2",
            MetricName="CPUUtilization",
            Dimensions=[{"Name": "InstanceId", "Value": instance_id}],
            StartTime=start,
            EndTime=end,
            Period=86400,
            Statistics=["Average"],
        )
        points = resp.get("Datapoints") or []
        if not points:
            return None
        vals = [float(p["Average"]) for p in points if "Average" in p]
        if not vals:
            return None
        return sum(vals) / len(vals)
    except ClientError as e:
        LOG.debug("CW CPU for %s: %s", instance_id, e)
        return None


def scan_ec2_rightsizing(
    session,
    region: str,
    *,
    max_instances: int = 50,
    lookback_days: int = 14,
    cpu_threshold: float = CPU_LOW_THRESHOLD,
) -> List[Finding]:
    """
    Flag running instances with low average CPU (directional only).

    Not a full rightsizing engine - Medium confidence, review required.
    """
    findings: List[Finding] = []
    try:
        ec2 = aws_client(session, "ec2", region_name=region)
        cw = aws_client(session, "cloudwatch", region_name=region)
    except Exception as e:
        LOG.debug("rightsizing clients %s: %s", region, e)
        return findings

    instance_ids: List[Dict[str, Any]] = []
    try:
        for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ):
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    instance_ids.append(inst)
                    if len(instance_ids) >= max_instances:
                        break
                if len(instance_ids) >= max_instances:
                    break
    except ClientError as e:
        LOG.debug("describe_instances %s: %s", region, e)
        return findings

    for inst in instance_ids:
        iid = inst.get("InstanceId")
        if not iid:
            continue
        itype = inst.get("InstanceType") or "unknown"
        tags = _tags_from_list(inst.get("Tags"))
        cpu = _cpu_average(cw, iid, days=lookback_days)
        if cpu is None or cpu >= cpu_threshold:
            continue
        est = round(INSTANCE_MONTHLY_FLOOR * DOWNSIZE_FACTOR, 2)
        findings.append(
            Finding(
                id=f"rightsizing:{iid}",
                category="ec2_rightsizing",
                resource_id=iid,
                region=region,
                service="Amazon EC2",
                action="review downsize, Graviton migration, or schedule stop",
                estimated_monthly_usd=est,
                confidence="Medium",
                evidence=(
                    f"CPU avg {cpu:.1f}% over {lookback_days}d "
                    f"(threshold {cpu_threshold}%); type={itype}"
                ),
                estimate_formula="~instance_monthly_floor * 0.30 (not on-demand price lookup)",
                tags=tags,
                protected=has_protect_tag(tags),
                metadata={
                    "cpu_avg": round(cpu, 2),
                    "lookback_days": lookback_days,
                    "instance_type": itype,
                },
            )
        )
    return findings
