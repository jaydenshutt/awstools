"""Service-aware, spend-scoped FinOps recommendations."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

# Map Cost Explorer service names / substrings → internal keys
SERVICE_ALIASES = {
    "ec2": ["elastic compute cloud", "amazonec2", "ec2", "compute"],
    "rds": ["relational database", "amazonrds", "rds"],
    "s3": ["simple storage", "amazons3", "s3"],
    "ebs": ["elastic block store", "ebs"],
    "lambda": ["lambda"],
    "ecr": ["ecr", "elastic container registry"],
    "eks": ["eks", "elastic kubernetes"],
    "dynamodb": ["dynamodb"],
    "cloudfront": ["cloudfront"],
    "elb": ["elastic load balancing", "elb", "load balancer"],
    "nat": ["nat gateway", "vpc"],
    "data_transfer": ["data transfer"],
}

# Conservative savings factors applied to *that service's* monthly spend
SERVICE_SAVINGS_FACTORS = {
    "ec2": 0.15,
    "rds": 0.10,
    "s3": 0.05,
    "ebs": 0.20,  # of EBS-related; unattached handled separately
    "lambda": 0.05,
    "ecr": 0.15,
    "eks": 0.10,
    "dynamodb": 0.08,
    "cloudfront": 0.05,
    "elb": 0.10,
}

ADVICE: Dict[str, Dict[str, Any]] = {
    "ec2": {
        "label": "Amazon EC2",
        "explanation": (
            "Virtual machines billed by instance type, count, and uptime. "
            "Largest savings usually come from rightsizing, stopping idle "
            "workloads, and commitment discounts (Savings Plans / RIs)."
        ),
        "actions": [
            "Rightsize instances using CPU/memory utilization",
            "Purchase Compute Savings Plans for steady-state load",
            "Use Spot for fault-tolerant / non-prod workloads",
            "Enable autoscaling to shed idle capacity",
        ],
    },
    "rds": {
        "label": "Amazon RDS",
        "explanation": (
            "Managed databases; cost drivers include instance class, storage, "
            "IOPS, Multi-AZ, and backup retention."
        ),
        "actions": [
            "Downsize or stop idle non-prod databases",
            "Consider Aurora Serverless v2 for spiky load",
            "Use reserved instances for steady production DBs",
            "Review backup retention and snapshot sprawl",
        ],
    },
    "s3": {
        "label": "Amazon S3",
        "explanation": (
            "Object storage billed by volume, storage class, requests, and egress."
        ),
        "actions": [
            "Apply lifecycle policies (Standard → IA → Glacier)",
            "Enable Intelligent-Tiering for unknown access patterns",
            "Clean incomplete multipart uploads and old versions",
            "Review high-egress buckets and CloudFront caching",
        ],
    },
    "ebs": {
        "label": "Amazon EBS",
        "explanation": "Block volumes and snapshots; unattached volumes still bill monthly.",
        "actions": [
            "Delete or snapshot-then-delete unattached volumes",
            "Migrate gp2 → gp3 where appropriate",
            "Expire unused snapshots with a retention policy",
        ],
    },
    "lambda": {
        "label": "AWS Lambda",
        "explanation": "Billed by invocations, duration, and memory configuration.",
        "actions": [
            "Tune memory to minimize GB-seconds",
            "Reduce cold starts and over-provisioned concurrency",
            "Remove unused functions and event sources",
        ],
    },
    "ecr": {
        "label": "Amazon ECR",
        "explanation": "Image storage and data transfer for container registries.",
        "actions": [
            "Enable lifecycle policies for untagged / old images",
            "Delete unused repositories and large layers",
        ],
    },
    "eks": {
        "label": "Amazon EKS",
        "explanation": (
            "Control plane plus node groups, storage, and load balancers. "
            "Node rightsizing usually dominates savings."
        ),
        "actions": [
            "Rightsize node groups; use Cluster Autoscaler / Karpenter",
            "Consider Fargate or Spot for suitable workloads",
            "Remove unused clusters and idle node groups",
        ],
    },
    "dynamodb": {
        "label": "Amazon DynamoDB",
        "explanation": "Capacity mode, storage, and GSIs drive cost.",
        "actions": [
            "Use on-demand for spiky traffic or auto-scale provisioned capacity",
            "Remove unused global secondary indexes",
            "Enable TTL for expiring items",
        ],
    },
    "cloudfront": {
        "label": "Amazon CloudFront",
        "explanation": "CDN billed by data transfer and requests.",
        "actions": [
            "Increase cache TTLs and improve cache hit ratio",
            "Enable compression and modern protocols",
            "Review price classes for geographic reach needed",
        ],
    },
    "elb": {
        "label": "Elastic Load Balancing",
        "explanation": "Hourly LB charges plus LCU / data processing.",
        "actions": [
            "Delete idle load balancers",
            "Consolidate listeners and target groups",
            "Prefer ALB/NLB only where needed",
        ],
    },
}

GLOSSARY = {
    "Monthly cost": "Approximate unblended billed amount for the month.",
    "Rightsizing": "Matching instance or database size to actual utilization.",
    "Savings Plans / Reserved Instances": (
        "Commitment discounts in exchange for 1-3 year usage commitments."
    ),
    "Spot instances": "Deeply discounted compute for interruptible workloads.",
    "CUR": "AWS Cost and Usage Report - detailed billing export for allocation.",
    "Unattached EBS": "Volumes not attached to any instance; still incur storage cost.",
}


def _normalize(name: str) -> str:
    return name.lower().replace(" ", "").replace("-", "").replace("_", "")


def match_service_key(service_name: str) -> Optional[str]:
    n = service_name.lower()
    n_compact = _normalize(service_name)
    for key, aliases in SERVICE_ALIASES.items():
        for alias in aliases:
            if alias in n or _normalize(alias) in n_compact:
                return key
    return None


def service_spend_map(top_services: List[Tuple[str, float]]) -> Dict[str, float]:
    """Map internal service keys → monthly USD from top services list."""
    spend: Dict[str, float] = {}
    for name, amount in top_services:
        key = match_service_key(name)
        if key:
            spend[key] = spend.get(key, 0.0) + float(amount)
        else:
            spend.setdefault("_other", 0.0)
            spend["_other"] += float(amount)
    return spend


def build_recommendations(
    latest_total: float,
    pivot,
    top_services: List[Tuple[str, float]],
    wasted: Dict[str, List[str]],
    resources: Dict[str, Any],
) -> Tuple[List[str], List[Dict], str, Dict[str, Dict], Dict[str, str]]:
    """
    Build recommendations scoped to services that actually appear in spend
    or inventory. Savings estimates use service-level spend when available.
    """
    recs: List[str] = []
    rec_objs: List[Dict] = []
    per_service: Dict[str, Dict] = {}

    # Executive summary
    if latest_total and pivot is not None and getattr(pivot, "shape", (0,))[0] >= 2:
        recent = pivot["total"].pct_change().dropna()
        avg_growth = float(recent.tail(3).mean()) if not recent.empty else 0.0
        if avg_growth > 0.03:
            trend = "increasing"
        elif avg_growth < -0.03:
            trend = "decreasing"
        else:
            trend = "stable"
        exec_summary = (
            f"Most recent monthly spend is ${latest_total:.2f}. Over the analyzed "
            f"period spend appears {trend} (recent avg monthly change "
            f"{avg_growth * 100:.1f}%). Below: high-cost services and prioritized actions."
        )
    else:
        exec_summary = (
            f"Latest monthly spend is ${latest_total:.2f}. "
            "Limited history - trend confidence is low."
        )

    spend = service_spend_map(top_services)

    # Only advise on services with meaningful spend OR inventory presence
    min_spend = max(1.0, latest_total * 0.005) if latest_total else 1.0
    present_keys = set()
    for key, amount in spend.items():
        if key != "_other" and amount >= min_spend:
            present_keys.add(key)

    # Inventory signals
    inv_map = {
        "ec2": resources.get("EC2", 0),
        "rds": resources.get("RDS", 0),
        "s3": resources.get("S3_buckets", 0),
        "ebs": resources.get("EBS_volumes", 0),
        "lambda": resources.get("Lambda_functions", 0),
        "ecr": resources.get("ECR_repos", 0),
        "eks": resources.get("EKS_clusters", 0),
        "dynamodb": resources.get("DynamoDB_tables", 0),
        "cloudfront": resources.get("CloudFront_distributions", 0),
        "elb": resources.get("LoadBalancers", 0),
    }
    for key, count in inv_map.items():
        if isinstance(count, int) and count > 0:
            present_keys.add(key)

    for key in sorted(present_keys, key=lambda k: spend.get(k, 0.0), reverse=True):
        if key not in ADVICE:
            continue
        info = ADVICE[key]
        svc_amount = spend.get(key, 0.0)
        factor = SERVICE_SAVINGS_FACTORS.get(key, 0.05)
        # Prefer service-scoped estimate; fall back to tiny share of total if no CE split
        if svc_amount > 0:
            est = svc_amount * factor
        elif latest_total > 0 and inv_map.get(key, 0):
            est = latest_total * factor * 0.05  # very conservative without spend split
        else:
            est = 0.0

        label = info["label"]
        per_service[label] = {
            "explanation": info["explanation"],
            "actions": info["actions"],
            "estimated_monthly_savings": est,
            "service_monthly_spend": svc_amount,
        }
        recs.append(
            f"{label}: {info['explanation']} "
            f"Actions: {', '.join(info['actions'][:3])}. "
            f"Estimated potential monthly saving: ${est:.2f} "
            f"(~{factor * 100:.0f}% of service spend ${svc_amount:.2f})."
        )
        rec_objs.append(
            {
                "id": f"rec_{key}",
                "service": label,
                "estimated_monthly_savings": est,
                "note": "; ".join(info["actions"]),
                "source": "service_spend" if svc_amount > 0 else "inventory_heuristic",
            }
        )

    # Wasted resources - higher confidence, fixed unit estimates
    unattached = wasted.get("unattached_ebs") or []
    if unattached:
        # ~$0.08/GB-month gp3; use $5/vol conservative default without size
        est = len(unattached) * 5.0
        recs.append(
            f"Found {len(unattached)} unattached EBS volume(s). "
            f"Snapshot (if needed) then delete after validation. "
            f"Estimated monthly saving: ${est:.2f}."
        )
        rec_objs.append(
            {
                "id": "wasted_ebs",
                "service": "Amazon EBS",
                "estimated_monthly_savings": est,
                "note": "delete or snapshot unattached volumes",
                "source": "wasted",
                "count": len(unattached),
            }
        )

    unassoc = wasted.get("unassociated_eips") or []
    if unassoc:
        est = len(unassoc) * 3.65  # ~$0.005/hour public IPv4
        recs.append(
            f"Found {len(unassoc)} unassociated Elastic IP(s). "
            f"Release if unused. Estimated monthly saving: ${est:.2f}."
        )
        rec_objs.append(
            {
                "id": "wasted_eip",
                "service": "EC2 Elastic IP",
                "estimated_monthly_savings": est,
                "note": "release unassociated Elastic IPs",
                "source": "wasted",
                "count": len(unassoc),
            }
        )

    old_snaps = wasted.get("old_available_snapshots") or []
    if old_snaps:
        est = min(len(old_snaps) * 1.0, latest_total * 0.05 if latest_total else len(old_snaps))
        recs.append(
            f"Found {len(old_snaps)} snapshot(s) older than 90 days (sample). "
            f"Review retention policies. Rough potential saving: ${est:.2f}/mo."
        )
        rec_objs.append(
            {
                "id": "old_snapshots",
                "service": "Amazon EBS Snapshots",
                "estimated_monthly_savings": est,
                "note": "expire unused snapshots via lifecycle policy",
                "source": "wasted",
                "count": len(old_snaps),
            }
        )

    nats = wasted.get("available_nat_gateways") or []
    if nats and len(nats) > 0:
        # NAT is expensive (~$32+/mo + data); flag for review only
        recs.append(
            f"Found {len(nats)} NAT Gateway(s). Each costs ~$32+/month plus data processing. "
            "Confirm they are required; consider VPC endpoints for S3/DynamoDB traffic."
        )
        rec_objs.append(
            {
                "id": "nat_review",
                "service": "NAT Gateway",
                "estimated_monthly_savings": 0.0,
                "note": "review NAT gateways; use VPC endpoints where possible",
                "source": "inventory_review",
                "count": len(nats),
            }
        )

    if top_services:
        top_name, top_amt = top_services[0]
        recs.insert(
            0,
            f"Largest cost center: {top_name} at ${top_amt:.2f}/mo - prioritize this first.",
        )

    if not rec_objs:
        recs.append(
            "No high-confidence optimization targets detected. "
            "Enable Cost Explorer, tag resources, and re-run with --all-regions."
        )

    return recs, rec_objs, exec_summary, per_service, GLOSSARY


def compute_priority_confidence(
    est_value: float,
    latest_total: float,
    source: str = "heuristic",
    extra: Any = None,
) -> Tuple[str, str, str, float]:
    """Return (priority, confidence, reason, priority_score)."""
    pr = "Low"
    conf = "Medium"
    reason = "Heuristic estimate based on service-level spend"
    score = 0.0
    try:
        pct = (est_value / latest_total) if latest_total and latest_total > 0 else 0.0
        score = pct * 100.0 + min(est_value / 10.0, 10.0)

        if pct >= 0.05 or est_value >= 100.0:
            pr = "High"
        elif pct >= 0.01 or est_value >= 20.0:
            pr = "Medium"
        else:
            pr = "Low"

        if source == "wasted":
            conf = "High"
            count = extra.get("count") if isinstance(extra, dict) else None
            if count is not None:
                reason = f"Detected {count} unused resource(s) via inventory scan"
                score += min(count * 2.0, 20.0)
            else:
                reason = "Detected unused resource via inventory scan"
        elif source in ("cur", "exact"):
            conf = "High"
            reason = "Per-resource cost available"
            score += 10.0
        elif source == "service_spend":
            conf = "Medium"
            reason = "Estimate scoped to that service's Cost Explorer spend"
            score += 3.0
        elif source == "inventory_review":
            conf = "Low"
            reason = "Inventory flag for human review (no automatic savings assumed)"
        else:
            if extra:
                reason = f"Heuristic: {extra}"
    except Exception:
        pr, conf, reason, score = "Low", "Low", "Failed to compute confidence", 0.0

    return pr, conf, reason, float(score)
