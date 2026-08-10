"""Unassociated Elastic IP release - report default, release with execute gates."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from awstools.common.findings import Finding, has_protect_tag
from awstools.common.session import client as aws_client, resolve_regions

LOG = logging.getLogger("awstools.cleanup.eip")
EIP_MONTHLY = 3.65


def _tags(tag_list) -> Dict[str, str]:
    return {t["Key"]: t.get("Value", "") for t in (tag_list or []) if "Key" in t}


def find_unassociated_eips(
    session,
    regions: Optional[List[str]] = None,
    all_regions: bool = False,
    offline: bool = False,
) -> List[Finding]:
    if offline:
        return [
            Finding(
                id="eip:eipalloc-sample",
                category="unassociated_eip",
                resource_id="eipalloc-sample",
                region="us-east-1",
                service="EC2 Elastic IP",
                action="release unassociated Elastic IP",
                estimated_monthly_usd=EIP_MONTHLY,
                confidence="High",
                evidence="offline sample",
                estimate_formula="0.005 USD/hour * 730 ≈ 3.65",
                metadata={"allocation_id": "eipalloc-sample"},
            )
        ]
    findings: List[Finding] = []
    for region in resolve_regions(session, regions=regions, all_regions=all_regions):
        ec2 = aws_client(session, "ec2", region_name=region)
        try:
            # describe_addresses is not a paginated operation in botocore
            for a in ec2.describe_addresses().get("Addresses", []):
                if a.get("InstanceId") or a.get("NetworkInterfaceId"):
                    continue
                alloc = a.get("AllocationId")
                rid = alloc or a.get("PublicIp") or "unknown"
                tags = _tags(a.get("Tags"))
                findings.append(
                    Finding(
                        id=f"eip:{rid}",
                        category="unassociated_eip",
                        resource_id=str(rid),
                        region=region,
                        service="EC2 Elastic IP",
                        action="release unassociated Elastic IP",
                        estimated_monthly_usd=EIP_MONTHLY,
                        confidence="High",
                        evidence=f"publicIp={a.get('PublicIp')}",
                        estimate_formula="0.005 USD/hour * 730 ≈ 3.65",
                        tags=tags,
                        protected=has_protect_tag(tags),
                        metadata={"allocation_id": alloc, "public_ip": a.get("PublicIp")},
                    )
                )
        except ClientError as e:
            LOG.warning("EIP list failed in %s: %s", region, e)
    return findings


def release_eips(session, findings: List[Finding], dry_run: bool = True) -> Dict[str, Any]:
    released = []
    skipped = []
    errors = []
    for f in findings:
        if f.protected:
            skipped.append({"id": f.resource_id, "reason": "protected tag"})
            continue
        alloc = (f.metadata or {}).get("allocation_id")
        if dry_run:
            LOG.info("[dry-run] would release EIP %s in %s", f.resource_id, f.region)
            released.append(f.resource_id)
            continue
        try:
            ec2 = aws_client(session, "ec2", region_name=f.region)
            if alloc:
                ec2.release_address(AllocationId=alloc)
            else:
                ec2.release_address(PublicIp=f.resource_id)
            released.append(f.resource_id)
            LOG.info("Released EIP %s", f.resource_id)
        except ClientError as e:
            errors.append(f"{f.resource_id}: {e}")
    return {"released": released, "skipped": skipped, "errors": errors, "dry_run": dry_run}
