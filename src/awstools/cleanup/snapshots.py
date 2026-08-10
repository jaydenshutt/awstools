"""Old snapshot listing and optional delete with retention policy."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from awstools.common.findings import Finding, has_protect_tag
from awstools.common.session import client as aws_client, resolve_regions

LOG = logging.getLogger("awstools.cleanup.snapshots")


def _tags(tag_list) -> Dict[str, str]:
    return {t["Key"]: t.get("Value", "") for t in (tag_list or []) if "Key" in t}


def find_old_snapshots(
    session,
    older_than_days: int = 90,
    regions: Optional[List[str]] = None,
    all_regions: bool = False,
    offline: bool = False,
) -> List[Finding]:
    if offline:
        return [
            Finding(
                id="snap:snap-sample",
                category="old_snapshot",
                resource_id="snap-sample",
                region="us-east-1",
                service="Amazon EBS Snapshots",
                action=f"delete snapshot older than {older_than_days}d",
                estimated_monthly_usd=2.5,
                confidence="Medium",
                evidence=f"offline sample age>{older_than_days}d size=50GiB",
                estimate_formula="size_gb * 0.05",
                metadata={"age_days": older_than_days + 30, "size_gb": 50},
            )
        ]
    findings: List[Finding] = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=older_than_days)
    for region in resolve_regions(session, regions=regions, all_regions=all_regions):
        ec2 = aws_client(session, "ec2", region_name=region)
        try:
            for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"]):
                for s in page.get("Snapshots", []):
                    started = s.get("StartTime")
                    if not started or started >= cutoff:
                        continue
                    tags = _tags(s.get("Tags"))
                    size = float(s.get("VolumeSize") or 0)
                    age = (datetime.now(timezone.utc) - started).days
                    findings.append(
                        Finding(
                            id=f"snap:{s['SnapshotId']}",
                            category="old_snapshot",
                            resource_id=s["SnapshotId"],
                            region=region,
                            service="Amazon EBS Snapshots",
                            action=f"delete snapshot older than {older_than_days}d",
                            estimated_monthly_usd=round(size * 0.05, 2),
                            confidence="Medium",
                            evidence=f"age={age}d size={size}GiB",
                            tags=tags,
                            protected=has_protect_tag(tags),
                            metadata={"age_days": age, "size_gb": size},
                        )
                    )
        except ClientError as e:
            LOG.warning("Snapshot list failed in %s: %s", region, e)
    return findings


def delete_snapshots(
    session, findings: List[Finding], dry_run: bool = True
) -> Dict[str, Any]:
    deleted = []
    skipped = []
    errors = []
    for f in findings:
        if f.protected:
            skipped.append({"id": f.resource_id, "reason": "protected tag"})
            continue
        if dry_run:
            LOG.info("[dry-run] would delete snapshot %s", f.resource_id)
            deleted.append(f.resource_id)
            continue
        try:
            ec2 = aws_client(session, "ec2", region_name=f.region)
            ec2.delete_snapshot(SnapshotId=f.resource_id)
            deleted.append(f.resource_id)
            LOG.info("Deleted snapshot %s", f.resource_id)
        except ClientError as e:
            errors.append(f"{f.resource_id}: {e}")
    return {"deleted": deleted, "skipped": skipped, "errors": errors, "dry_run": dry_run}
