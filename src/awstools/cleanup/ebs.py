"""Unattached EBS cleanup - report default, delete with execute gates."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from awstools.common.findings import Finding, has_protect_tag
from awstools.common.session import client as aws_client, resolve_regions

LOG = logging.getLogger("awstools.cleanup.ebs")


def _tags(tag_list) -> Dict[str, str]:
    return {t["Key"]: t.get("Value", "") for t in (tag_list or []) if "Key" in t}


def find_unattached_volumes(
    session,
    regions: Optional[List[str]] = None,
    all_regions: bool = False,
    offline: bool = False,
) -> List[Finding]:
    if offline:
        return [
            Finding(
                id="ebs:vol-sample",
                category="unattached_ebs",
                resource_id="vol-sample",
                region="us-east-1",
                service="Amazon EBS",
                action="delete unattached volume",
                estimated_monthly_usd=8.0,
                confidence="High",
                evidence="offline sample available 100GiB",
                estimate_formula="max(size_gb * 0.08, 5.0)",
                metadata={"size_gb": 100},
            )
        ]
    findings: List[Finding] = []
    for region in resolve_regions(session, regions=regions, all_regions=all_regions):
        ec2 = aws_client(session, "ec2", region_name=region)
        try:
            for page in ec2.get_paginator("describe_volumes").paginate(
                Filters=[{"Name": "status", "Values": ["available"]}]
            ):
                for v in page.get("Volumes", []):
                    tags = _tags(v.get("Tags"))
                    size = float(v.get("Size") or 0)
                    est = max(size * 0.08, 5.0) if size else 5.0
                    findings.append(
                        Finding(
                            id=f"ebs:{v['VolumeId']}",
                            category="unattached_ebs",
                            resource_id=v["VolumeId"],
                            region=region,
                            service="Amazon EBS",
                            action="delete unattached volume",
                            estimated_monthly_usd=round(est, 2),
                            confidence="High",
                            evidence=f"available {size}GiB {v.get('VolumeType')}",
                            tags=tags,
                            protected=has_protect_tag(tags),
                        )
                    )
        except ClientError as e:
            LOG.warning("EBS list failed in %s: %s", region, e)
    return findings


def delete_volumes(
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
            LOG.info("[dry-run] would delete volume %s in %s", f.resource_id, f.region)
            deleted.append(f.resource_id)
            continue
        try:
            ec2 = aws_client(session, "ec2", region_name=f.region)
            ec2.delete_volume(VolumeId=f.resource_id)
            LOG.info("Deleted volume %s", f.resource_id)
            deleted.append(f.resource_id)
        except ClientError as e:
            errors.append(f"{f.resource_id}: {e}")
    return {
        "deleted": deleted,
        "skipped": skipped,
        "errors": errors,
        "dry_run": dry_run,
    }
