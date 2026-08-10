"""Multi-region waste scan producing normalized Findings."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from awstools.common.findings import (
    Finding,
    apply_filters,
    dedupe_findings,
    has_protect_tag,
    savings_breakdown,
)
from awstools.common.session import client as aws_client, resolve_regions
from awstools.waste.rightsizing import sample_rightsizing_findings

LOG = logging.getLogger("awstools.waste")

# Conservative unit estimates (USD / month) - document in estimate_formula fields
EBS_UNATTACHED_PER_VOL = 5.0  # floor when size unknown
EBS_GB_MONTH = 0.08  # approx gp3 us-east-1
EIP_MONTHLY = 3.65  # ~$0.005/hr public IPv4
IDLE_ELB_MONTHLY = 16.0  # rough ALB minimum hourly*730
SNAPSHOT_PER_GB = 0.05
GP2_TO_GP3_SAVE_PER_GB = 0.02  # rough differential
ENI_UNATTACHED = 0.0  # hygiene, not direct $
MULTIPART_PER_GB = 0.023

# Detector category names (match config DEFAULT_DETECTORS)
DETECTOR_CATEGORIES = frozenset(
    {
        "unattached_ebs",
        "unassociated_eip",
        "idle_elb",
        "incomplete_multipart",
        "old_snapshot",
        "gp2_to_gp3",
        "old_ami",
        "nat_gateway_review",
        "unattached_eni",
        "ec2_rightsizing",
    }
)


def sample_findings() -> List[Finding]:
    """Rich offline sample set covering all detector categories."""
    return [
        Finding(
            id="ebs-unattached:vol-sample",
            category="unattached_ebs",
            resource_id="vol-sample",
            region="us-east-1",
            service="Amazon EBS",
            action="delete unattached volume",
            estimated_monthly_usd=8.0,
            confidence="High",
            evidence="status=available size=100GiB (sample)",
            estimate_formula="max(size_gb * 0.08, 5.0)",
            metadata={"size_gb": 100, "age_days": 45},
        ),
        Finding(
            id="eip-unassoc:eipalloc-sample",
            category="unassociated_eip",
            resource_id="eipalloc-sample",
            region="us-east-1",
            service="EC2 Elastic IP",
            action="release EIP",
            estimated_monthly_usd=3.65,
            confidence="High",
            evidence="sample dry-run finding",
            estimate_formula="0.005 USD/hour * 730 ≈ 3.65",
        ),
        Finding(
            id="elb-idle:sample-alb",
            category="idle_elb",
            resource_id="arn:aws:elasticloadbalancing:us-east-1:000:loadbalancer/app/sample/x",
            region="us-east-1",
            service="Elastic Load Balancing",
            action="delete idle load balancer",
            estimated_monthly_usd=16.0,
            confidence="High",
            evidence="no targets (sample)",
            estimate_formula="≈$0.0225/hour * 730 ≈ 16",
        ),
        Finding(
            id="multipart:sample-bucket",
            category="incomplete_multipart",
            resource_id="sample-bucket",
            region="us-east-1",
            service="Amazon S3",
            action="abort incomplete multipart uploads",
            estimated_monthly_usd=0.5,
            confidence="High",
            evidence="5 incomplete uploads (sample)",
            estimate_formula="upload_count * 0.1 (rough)",
            metadata={"upload_count": 5},
        ),
        Finding(
            id="snap-old:snap-sample",
            category="old_snapshot",
            resource_id="snap-sample",
            region="us-east-1",
            service="Amazon EBS Snapshots",
            action="review retention; delete if obsolete",
            estimated_monthly_usd=2.5,
            confidence="Medium",
            evidence="age=120d size=50GiB (sample)",
            estimate_formula="size_gb * 0.05",
            metadata={"age_days": 120, "size_gb": 50},
        ),
        Finding(
            id="gp2-gp3:vol-gp2-sample",
            category="gp2_to_gp3",
            resource_id="vol-gp2-sample",
            region="us-east-1",
            service="Amazon EBS",
            action="migrate volume type gp2 → gp3",
            estimated_monthly_usd=2.0,
            confidence="Medium",
            evidence="type=gp2 size=100GiB (sample)",
            estimate_formula="size_gb * 0.02",
            metadata={"size_gb": 100},
        ),
        Finding(
            id="ami-old:ami-sample",
            category="old_ami",
            resource_id="ami-sample",
            region="us-east-1",
            service="Amazon EC2 AMI",
            action="deregister unused AMI",
            estimated_monthly_usd=1.0,
            confidence="Medium",
            evidence="age>180d unused (sample)",
            estimate_formula="flat 1.0 placeholder for snapshot bloat",
            metadata={"age_days": 200},
        ),
        Finding(
            id="nat:nat-sample",
            category="nat_gateway_review",
            resource_id="nat-sample",
            region="us-east-1",
            service="NAT Gateway",
            action="confirm required; prefer VPC endpoints",
            estimated_monthly_usd=0.0,
            confidence="Low",
            evidence="NAT available (sample) - review only",
            estimate_formula="not auto-counted (~$32+/mo if removable)",
        ),
        Finding(
            id="eni-unattached:eni-sample",
            category="unattached_eni",
            resource_id="eni-sample",
            region="us-east-1",
            service="EC2 ENI",
            action="review and delete unused ENI",
            estimated_monthly_usd=0.0,
            confidence="Medium",
            evidence="status=available (sample)",
            estimate_formula="hygiene only (0 USD direct)",
        ),
    ] + sample_rightsizing_findings()


def _tags_from_list(tag_list) -> Dict[str, str]:
    out = {}
    for t in tag_list or []:
        if isinstance(t, dict) and "Key" in t:
            out[t["Key"]] = t.get("Value", "")
    return out


def _scan_region(session, region: str, detectors: Optional[set] = None) -> List[Finding]:
    findings: List[Finding] = []
    enabled = detectors or set(DETECTOR_CATEGORIES)
    ec2 = aws_client(session, "ec2", region_name=region)

    # Unattached EBS
    try:
        for page in ec2.get_paginator("describe_volumes").paginate(
            Filters=[{"Name": "status", "Values": ["available"]}]
        ):
            for v in page.get("Volumes", []):
                vid = v.get("VolumeId", "")
                size = float(v.get("Size") or 0)
                # gp3 ~$0.08/GB-mo
                est = max(size * 0.08, EBS_UNATTACHED_PER_VOL) if size else EBS_UNATTACHED_PER_VOL
                tags = _tags_from_list(v.get("Tags"))
                findings.append(
                    Finding(
                        id=f"ebs-unattached:{vid}",
                        category="unattached_ebs",
                        resource_id=vid,
                        region=region,
                        service="Amazon EBS",
                        action="snapshot (optional) then delete unattached volume",
                        estimated_monthly_usd=round(est, 2),
                        confidence="High",
                        evidence=f"status=available size={size}GiB type={v.get('VolumeType')}",
                        estimate_formula="max(size_gb * 0.08, 5.0)",
                        tags=tags,
                        protected=has_protect_tag(tags),
                        metadata={"size_gb": size, "volume_type": v.get("VolumeType")},
                    )
                )
    except ClientError as e:
        LOG.debug("EBS scan %s: %s", region, e)

    # Unassociated EIPs
    try:
        for a in ec2.describe_addresses().get("Addresses", []):
            if a.get("InstanceId") or a.get("NetworkInterfaceId"):
                continue
            rid = a.get("AllocationId") or a.get("PublicIp") or "unknown"
            tags = _tags_from_list(a.get("Tags"))
            findings.append(
                Finding(
                    id=f"eip-unassoc:{rid}",
                    category="unassociated_eip",
                    resource_id=str(rid),
                    region=region,
                    service="EC2 Elastic IP",
                    action="release unassociated Elastic IP",
                    estimated_monthly_usd=EIP_MONTHLY,
                    confidence="High",
                    evidence="not associated with instance or ENI",
                    estimate_formula="0.005 USD/hour * 730 ≈ 3.65",
                    tags=tags,
                    protected=has_protect_tag(tags),
                )
            )
    except ClientError as e:
        LOG.debug("EIP scan %s: %s", region, e)

    # Unattached ENIs (available)
    try:
        for page in ec2.get_paginator("describe_network_interfaces").paginate(
            Filters=[{"Name": "status", "Values": ["available"]}]
        ):
            for eni in page.get("NetworkInterfaces", []):
                # skip if description suggests AWS-managed
                desc = (eni.get("Description") or "").lower()
                if "elb" in desc or "aws" in desc[:3]:
                    continue
                nid = eni.get("NetworkInterfaceId", "")
                tags = _tags_from_list(eni.get("TagSet"))
                findings.append(
                    Finding(
                        id=f"eni-unattached:{nid}",
                        category="unattached_eni",
                        resource_id=nid,
                        region=region,
                        service="EC2 ENI",
                        action="review and delete unused network interface",
                        estimated_monthly_usd=ENI_UNATTACHED,
                        confidence="Medium",
                        evidence=f"status=available desc={eni.get('Description')}",
                        tags=tags,
                        protected=has_protect_tag(tags),
                    )
                )
    except ClientError as e:
        LOG.debug("ENI scan %s: %s", region, e)

    # Old snapshots (>90d)
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"]):
            for s in page.get("Snapshots", []):
                started = s.get("StartTime")
                if not started or started >= cutoff:
                    continue
                sid = s.get("SnapshotId", "")
                size = float(s.get("VolumeSize") or 0)
                est = size * SNAPSHOT_PER_GB
                tags = _tags_from_list(s.get("Tags"))
                age_days = (datetime.now(timezone.utc) - started).days
                findings.append(
                    Finding(
                        id=f"snap-old:{sid}",
                        category="old_snapshot",
                        resource_id=sid,
                        region=region,
                        service="Amazon EBS Snapshots",
                        action="review retention; delete if obsolete",
                        estimated_monthly_usd=round(est, 2),
                        confidence="Medium",
                        evidence=f"age={age_days}d size={size}GiB",
                        tags=tags,
                        protected=has_protect_tag(tags),
                        metadata={"age_days": age_days, "size_gb": size},
                    )
                )
    except ClientError as e:
        LOG.debug("Snapshot scan %s: %s", region, e)

    # gp2 volumes still in use (migration savings)
    try:
        for page in ec2.get_paginator("describe_volumes").paginate(
            Filters=[{"Name": "volume-type", "Values": ["gp2"]}]
        ):
            for v in page.get("Volumes", []):
                vid = v.get("VolumeId", "")
                size = float(v.get("Size") or 0)
                est = size * GP2_TO_GP3_SAVE_PER_GB
                if est < 0.5:
                    continue
                tags = _tags_from_list(v.get("Tags"))
                findings.append(
                    Finding(
                        id=f"gp2-gp3:{vid}",
                        category="gp2_to_gp3",
                        resource_id=vid,
                        region=region,
                        service="Amazon EBS",
                        action="migrate volume type gp2 → gp3",
                        estimated_monthly_usd=round(est, 2),
                        confidence="Medium",
                        evidence=f"type=gp2 size={size}GiB state={v.get('State')}",
                        tags=tags,
                        protected=has_protect_tag(tags),
                        metadata={"size_gb": size},
                    )
                )
    except ClientError as e:
        LOG.debug("gp2 scan %s: %s", region, e)

    # NAT gateways (review only - expensive but often required)
    try:
        for page in ec2.get_paginator("describe_nat_gateways").paginate(
            Filters=[{"Name": "state", "Values": ["available"]}]
        ):
            for n in page.get("NatGateways", []):
                nid = n.get("NatGatewayId", "")
                tags = _tags_from_list(n.get("Tags"))
                findings.append(
                    Finding(
                        id=f"nat:{nid}",
                        category="nat_gateway_review",
                        resource_id=nid,
                        region=region,
                        service="NAT Gateway",
                        action="confirm required; prefer VPC endpoints for S3/DynamoDB",
                        estimated_monthly_usd=0.0,
                        confidence="Low",
                        evidence="NAT gateway available (~$32+/mo + data)",
                        tags=tags,
                        protected=has_protect_tag(tags),
                    )
                )
    except ClientError as e:
        LOG.debug("NAT scan %s: %s", region, e)

    # Idle-ish load balancers: no targets registered
    try:
        elbv2 = aws_client(session, "elbv2", region_name=region)
        lbs = []
        for page in elbv2.get_paginator("describe_load_balancers").paginate():
            lbs.extend(page.get("LoadBalancers", []))
        for lb in lbs:
            arn = lb.get("LoadBalancerArn", "")
            name = lb.get("LoadBalancerName", arn)
            # target groups
            try:
                tgs = elbv2.describe_target_groups(LoadBalancerArn=arn).get("TargetGroups", [])
            except ClientError:
                tgs = []
            total_targets = 0
            for tg in tgs:
                tg_arn = tg.get("TargetGroupArn")
                try:
                    health = elbv2.describe_target_health(TargetGroupArn=tg_arn)
                    total_targets += len(health.get("TargetHealthDescriptions", []))
                except ClientError:
                    pass
            if total_targets == 0:
                findings.append(
                    Finding(
                        id=f"elb-idle:{name}",
                        category="idle_elb",
                        resource_id=arn or name,
                        region=region,
                        service="Elastic Load Balancing",
                        action="delete idle load balancer if unused",
                        estimated_monthly_usd=IDLE_ELB_MONTHLY,
                        confidence="High",
                        evidence="no registered targets across target groups",
                        metadata={"name": name, "type": lb.get("Type")},
                    )
                )
    except ClientError as e:
        LOG.debug("ELB scan %s: %s", region, e)

    # Old AMIs (>180d) owned by self, not in use by instances (best-effort)
    try:
        cutoff_ami = datetime.now(timezone.utc) - timedelta(days=180)
        images = []
        for page in ec2.get_paginator("describe_images").paginate(Owners=["self"]):
            images.extend(page.get("Images", []))
        # instances' image ids
        used_amis = set()
        for page in ec2.get_paginator("describe_instances").paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    if inst.get("ImageId"):
                        used_amis.add(inst["ImageId"])
        for img in images:
            created_raw = img.get("CreationDate")
            if not created_raw:
                continue
            try:
                created = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
            except Exception:
                continue
            if created >= cutoff_ami:
                continue
            ami = img.get("ImageId", "")
            if ami in used_amis:
                continue
            tags = _tags_from_list(img.get("Tags"))
            findings.append(
                Finding(
                    id=f"ami-old:{ami}",
                    category="old_ami",
                    resource_id=ami,
                    region=region,
                    service="Amazon EC2 AMI",
                    action="deregister unused AMI and delete backing snapshots",
                    estimated_monthly_usd=1.0,
                    confidence="Medium",
                    evidence=f"age>180d name={img.get('Name')} not used by running/stopped instances",
                    tags=tags,
                    protected=has_protect_tag(tags),
                )
            )
    except ClientError as e:
        LOG.debug("AMI scan %s: %s", region, e)

    if "ec2_rightsizing" in enabled:
        try:
            from awstools.waste.rightsizing import scan_ec2_rightsizing

            findings.extend(scan_ec2_rightsizing(session, region))
        except Exception as e:
            LOG.debug("rightsizing %s: %s", region, e)

    return findings


def _scan_s3_multipart(session) -> List[Finding]:
    """Incomplete multipart uploads across all buckets (sample first 50 buckets)."""
    findings: List[Finding] = []
    try:
        s3 = aws_client(session, "s3")
        buckets = s3.list_buckets().get("Buckets", [])[:50]
    except Exception as e:
        LOG.debug("S3 list failed: %s", e)
        return findings

    for b in buckets:
        name = b.get("Name")
        if not name:
            continue
        try:
            # resolve region
            loc = s3.get_bucket_location(Bucket=name).get("LocationConstraint")
            region = loc or "us-east-1"
            if region == "EU":
                region = "eu-west-1"
            regional = aws_client(session, "s3", region_name=region)
            paginator = regional.get_paginator("list_multipart_uploads")
            count = 0
            total_parts_hint = 0
            try:
                for page in paginator.paginate(Bucket=name):
                    uploads = page.get("Uploads") or []
                    count += len(uploads)
                    total_parts_hint += len(uploads)
            except ClientError:
                continue
            if count:
                # rough: assume 1GB stranded average if unknown
                est = count * 0.5 * MULTIPART_PER_GB * 30 / 30  # ~0.5GB each
                est = max(count * 0.1, est)
                findings.append(
                    Finding(
                        id=f"multipart:{name}",
                        category="incomplete_multipart",
                        resource_id=name,
                        region=region,
                        service="Amazon S3",
                        action="abort incomplete multipart uploads",
                        estimated_monthly_usd=round(est, 2),
                        confidence="High",
                        evidence=f"{count} incomplete multipart upload(s)",
                        metadata={"upload_count": count},
                    )
                )
        except Exception as e:
            LOG.debug("multipart %s: %s", name, e)
    return findings


def scan_waste(
    session,
    regions: Optional[List[str]] = None,
    all_regions: bool = False,
    concurrency: int = 6,
    dry_run: bool = False,
    include_s3_multipart: bool = True,
    detectors: Optional[set] = None,
    config=None,
) -> Dict[str, Any]:
    """Run waste detectors; return findings + summary."""
    enabled = set(detectors) if detectors is not None else set(DETECTOR_CATEGORIES)

    if dry_run:
        findings = [f for f in sample_findings() if f.category in enabled]
        return _pack(findings, ["us-east-1"], dry_run=True, config=config)

    region_list = resolve_regions(session, regions=regions, all_regions=all_regions)
    findings: List[Finding] = []
    errors: List[str] = []

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
        futs = {ex.submit(_scan_region, session, r, enabled): r for r in region_list}
        for fut in as_completed(futs):
            r = futs[fut]
            try:
                findings.extend(fut.result())
            except Exception as e:
                errors.append(f"{r}: {e}")
                LOG.warning("Waste scan failed for %s: %s", r, e)

    if include_s3_multipart and "incomplete_multipart" in enabled:
        try:
            findings.extend(_scan_s3_multipart(session))
        except Exception as e:
            errors.append(f"s3-multipart: {e}")

    findings = [f for f in findings if f.category in enabled]
    return _pack(findings, region_list, dry_run=False, errors=errors, config=config)


def _pack(
    findings: List[Finding],
    regions: List[str],
    dry_run: bool,
    errors: Optional[List[str]] = None,
    config=None,
) -> Dict[str, Any]:
    findings = dedupe_findings(findings)
    if config is not None:
        apply_filters(findings, config)
    br = savings_breakdown(findings)
    by_cat: Dict[str, int] = {}
    for f in findings:
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
    actionable = [f for f in findings if not f.protected and not f.ignored]
    return {
        "findings": findings,
        "finding_count": len(findings),
        "actionable_count": len(actionable),
        # Headline uses High confidence only
        "estimated_monthly_savings_usd": br["high_confidence_usd"],
        "estimated_monthly_savings_all_confidence_usd": br["all_confidence_usd"],
        "savings_breakdown": br,
        "by_category": by_cat,
        "regions_scanned": regions,
        "errors": errors or [],
        "dry_run": dry_run,
        "partial": bool(errors),
    }
