"""Multi-region AWS resource inventory with pagination and partial-error reporting."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from awstools.common.session import client as aws_client, resolve_regions

LOG = logging.getLogger("awstools.cost.inventory")

SAMPLE_RESOURCES = {
    "EC2": 3,
    "RDS": 1,
    "S3_buckets": 5,
    "EBS_volumes": 2,
    "Lambda_functions": 1,
    "ECR_repos": 1,
    "EKS_clusters": 1,
    "SQS_queues": 1,
    "EC2_list": ["i-0123456789abcdef0", "i-0fedcba9876543210", "i-00aa11bb22cc33dd4"],
    "EBS_volumes_list": ["vol-0123", "vol-0456"],
    "RDS_list": ["db-1"],
    "S3_buckets_list": ["my-bucket-a", "my-bucket-b"],
    "Lambda_functions_list": ["my-func-a"],
    "ECR_repos_list": ["repo-a"],
    "EKS_clusters_list": ["cluster-a"],
    "SQS_queues_list": ["https://sqs.us-east-1.amazonaws.com/123456789012/my-queue"],
    "_errors": [],
    "_regions_scanned": ["us-east-1"],
}


def _paginate_ids(paginator, result_key: str, id_key: str) -> List[str]:
    ids: List[str] = []
    for page in paginator.paginate():
        for item in page.get(result_key, []):
            if isinstance(item, dict):
                val = item.get(id_key)
                if val:
                    ids.append(val)
            elif isinstance(item, str):
                ids.append(item)
    return ids


def collect_region(session, region: str) -> Dict[str, Any]:
    """Collect regional resource inventory for one region."""
    d: Dict[str, Any] = {"_region": region, "_errors": []}

    def safe(label: str, fn):
        try:
            return fn()
        except Exception as e:
            d["_errors"].append(f"{region}/{label}: {e}")
            LOG.debug("Inventory error %s/%s: %s", region, label, e)
            return None

    # EC2 instances
    def ec2_instances():
        ec2 = aws_client(session, "ec2", region_name=region)
        ids: List[str] = []
        for page in ec2.get_paginator("describe_instances").paginate():
            for reservation in page.get("Reservations", []):
                for inst in reservation.get("Instances", []):
                    # Include all states; stopped still costs EBS
                    ids.append(inst.get("InstanceId"))
        return ids

    ids = safe("ec2", ec2_instances)
    if ids is not None:
        d["EC2_list"] = ids
        d["EC2"] = len(ids)

    def ebs_volumes():
        ec2 = aws_client(session, "ec2", region_name=region)
        return _paginate_ids(ec2.get_paginator("describe_volumes"), "Volumes", "VolumeId")

    vols = safe("ebs", ebs_volumes)
    if vols is not None:
        d["EBS_volumes_list"] = vols
        d["EBS_volumes"] = len(vols)

    def eips():
        ec2 = aws_client(session, "ec2", region_name=region)
        addrs = ec2.describe_addresses().get("Addresses", [])
        return [a.get("AllocationId") or a.get("PublicIp") for a in addrs]

    eip_list = safe("eip", eips)
    if eip_list is not None:
        d["EIPs_list"] = eip_list
        d["EIPs"] = len(eip_list)

    def lambdas():
        lam = aws_client(session, "lambda", region_name=region)
        arns: List[str] = []
        for page in lam.get_paginator("list_functions").paginate():
            for f in page.get("Functions", []):
                arns.append(f.get("FunctionArn"))
        return arns

    fns = safe("lambda", lambdas)
    if fns is not None:
        d["Lambda_functions_list"] = fns
        d["Lambda_functions"] = len(fns)

    def rds():
        rds_c = aws_client(session, "rds", region_name=region)
        ids: List[str] = []
        for page in rds_c.get_paginator("describe_db_instances").paginate():
            for db in page.get("DBInstances", []):
                ids.append(db.get("DBInstanceIdentifier"))
        return ids

    dbs = safe("rds", rds)
    if dbs is not None:
        d["RDS_list"] = dbs
        d["RDS"] = len(dbs)

    def ecr():
        ecr_c = aws_client(session, "ecr", region_name=region)
        names: List[str] = []
        try:
            for page in ecr_c.get_paginator("describe_repositories").paginate():
                for r in page.get("repositories", []):
                    names.append(r.get("repositoryName"))
        except ClientError:
            # Some regions may not support ECR
            raise
        return names

    repos = safe("ecr", ecr)
    if repos is not None:
        d["ECR_repos_list"] = repos
        d["ECR_repos"] = len(repos)

    def eks():
        eks_c = aws_client(session, "eks", region_name=region)
        clusters: List[str] = []
        for page in eks_c.get_paginator("list_clusters").paginate():
            clusters.extend(page.get("clusters", []))
        return clusters

    clusters = safe("eks", eks)
    if clusters is not None:
        d["EKS_clusters_list"] = clusters
        d["EKS_clusters"] = len(clusters)

    def sqs():
        sqs_c = aws_client(session, "sqs", region_name=region)
        urls: List[str] = []
        # list_queues is not fully paginated the same way; handle NextToken
        token = None
        while True:
            kwargs = {}
            if token:
                kwargs["NextToken"] = token
            resp = sqs_c.list_queues(**kwargs)
            urls.extend(resp.get("QueueUrls") or [])
            token = resp.get("NextToken")
            if not token:
                break
        return urls

    queues = safe("sqs", sqs)
    if queues is not None:
        d["SQS_queues_list"] = queues
        d["SQS_queues"] = len(queues)

    def efs():
        efs_c = aws_client(session, "efs", region_name=region)
        return _paginate_ids(
            efs_c.get_paginator("describe_file_systems"), "FileSystems", "FileSystemId"
        )

    fss = safe("efs", efs)
    if fss is not None:
        d["EFS_file_systems_list"] = fss
        d["EFS_file_systems"] = len(fss)

    def elbv2():
        elb = aws_client(session, "elbv2", region_name=region)
        arns: List[str] = []
        for page in elb.get_paginator("describe_load_balancers").paginate():
            for lb in page.get("LoadBalancers", []):
                arns.append(lb.get("LoadBalancerArn"))
        return arns

    lbs = safe("elbv2", elbv2)
    if lbs is not None:
        d["LoadBalancers_list"] = lbs
        d["LoadBalancers"] = len(lbs)

    def dynamodb():
        ddb = aws_client(session, "dynamodb", region_name=region)
        names: List[str] = []
        for page in ddb.get_paginator("list_tables").paginate():
            names.extend(page.get("TableNames", []))
        return names

    tables = safe("dynamodb", dynamodb)
    if tables is not None:
        d["DynamoDB_tables_list"] = tables
        d["DynamoDB_tables"] = len(tables)

    def asg():
        asg_c = aws_client(session, "autoscaling", region_name=region)
        names: List[str] = []
        for page in asg_c.get_paginator("describe_auto_scaling_groups").paginate():
            for g in page.get("AutoScalingGroups", []):
                names.append(g.get("AutoScalingGroupName"))
        return names

    groups = safe("asg", asg)
    if groups is not None:
        d["AutoScalingGroups_list"] = groups
        d["AutoScalingGroups"] = len(groups)

    def snapshots():
        ec2 = aws_client(session, "ec2", region_name=region)
        # Own snapshots only
        ids: List[str] = []
        for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"]):
            for s in page.get("Snapshots", []):
                ids.append(s.get("SnapshotId"))
        return ids

    snaps = safe("snapshots", snapshots)
    if snaps is not None:
        d["EBS_snapshots_list"] = snaps
        d["EBS_snapshots"] = len(snaps)

    def nat_gateways():
        ec2 = aws_client(session, "ec2", region_name=region)
        ids: List[str] = []
        for page in ec2.get_paginator("describe_nat_gateways").paginate(
            Filters=[{"Name": "state", "Values": ["available", "pending"]}]
        ):
            for n in page.get("NatGateways", []):
                ids.append(n.get("NatGatewayId"))
        return ids

    nats = safe("nat", nat_gateways)
    if nats is not None:
        d["NAT_gateways_list"] = nats
        d["NAT_gateways"] = len(nats)

    return d


def inventory_resources(
    session,
    regions: Optional[List[str]] = None,
    all_regions: bool = False,
    concurrency: int = 6,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Collect inventory across regions; merges counts and lists."""
    if dry_run:
        return dict(SAMPLE_RESOURCES)

    region_list = resolve_regions(session, regions=regions, all_regions=all_regions)
    out: Dict[str, Any] = {
        "_errors": [],
        "_regions_scanned": list(region_list),
    }

    # Global: S3 buckets
    try:
        s3 = aws_client(session, "s3")
        buckets = s3.list_buckets().get("Buckets", [])
        out["S3_buckets"] = len(buckets)
        out["S3_buckets_list"] = [b.get("Name") for b in buckets]
    except Exception as e:
        out["S3_buckets"] = 0
        out["S3_buckets_list"] = []
        out["_errors"].append(f"s3/list_buckets: {e}")

    # Global: CloudFront
    try:
        cf = aws_client(session, "cloudfront")
        dists: List[str] = []
        marker = None
        while True:
            kwargs = {}
            if marker:
                kwargs["Marker"] = marker
            resp = cf.list_distributions(**kwargs)
            listing = resp.get("DistributionList") or {}
            for item in listing.get("Items") or []:
                dists.append(item.get("Id"))
            if not listing.get("IsTruncated"):
                break
            marker = listing.get("NextMarker")
            if not marker:
                break
        out["CloudFront_distributions"] = len(dists)
        out["CloudFront_distributions_list"] = dists
    except Exception as e:
        out["CloudFront_distributions"] = 0
        out["CloudFront_distributions_list"] = []
        out["_errors"].append(f"cloudfront: {e}")

    aggregated: Dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
        futures = {ex.submit(collect_region, session, r): r for r in region_list}
        for fut in as_completed(futures):
            region = futures[fut]
            try:
                res = fut.result()
                for err in res.get("_errors", []):
                    out["_errors"].append(err)
                for k, v in res.items():
                    if k.startswith("_"):
                        continue
                    if k.endswith("_list"):
                        aggregated.setdefault(k, [])
                        aggregated[k].extend(v if isinstance(v, list) else [])
                    elif isinstance(v, int):
                        aggregated[k] = aggregated.get(k, 0) + v
            except Exception as e:
                out["_errors"].append(f"{region}: {e}")
                LOG.warning("Region inventory failed for %s: %s", region, e)

    out.update(aggregated)
    if out["_errors"]:
        LOG.warning("Inventory completed with %d error(s)", len(out["_errors"]))
    return out


def detect_wasted_resources(
    session,
    regions: Optional[List[str]] = None,
    all_regions: bool = False,
    concurrency: int = 6,
    dry_run: bool = False,
) -> Dict[str, List[str]]:
    """Detect common wasted resources across regions."""
    if dry_run:
        return {
            "unattached_ebs": ["vol-sample-unattached"],
            "unassociated_eips": ["eipalloc-sample"],
            "available_nat_gateways": [],
            "old_available_snapshots": [],
        }

    region_list = resolve_regions(session, regions=regions, all_regions=all_regions)
    unattached: List[str] = []
    unassoc: List[str] = []
    nats: List[str] = []
    old_snaps: List[str] = []

    def check(region: str):
        r_unatt, r_eip, r_nat, r_snap = [], [], [], []
        try:
            ec2 = aws_client(session, "ec2", region_name=region)
            for page in ec2.get_paginator("describe_volumes").paginate(
                Filters=[{"Name": "status", "Values": ["available"]}]
            ):
                for v in page.get("Volumes", []):
                    r_unatt.append(f"{v.get('VolumeId')}@{region}")

            for a in ec2.describe_addresses().get("Addresses", []):
                if not a.get("InstanceId") and not a.get("NetworkInterfaceId"):
                    rid = a.get("AllocationId") or a.get("PublicIp")
                    r_eip.append(f"{rid}@{region}")

            for page in ec2.get_paginator("describe_nat_gateways").paginate(
                Filters=[{"Name": "state", "Values": ["available"]}]
            ):
                for n in page.get("NatGateways", []):
                    # NAT gateways are often necessary; flag for review only
                    r_nat.append(f"{n.get('NatGatewayId')}@{region}")

            # Snapshots older than ~90 days with no obvious tags - flag for review
            from datetime import datetime, timezone, timedelta

            cutoff = datetime.now(timezone.utc) - timedelta(days=90)
            for page in ec2.get_paginator("describe_snapshots").paginate(OwnerIds=["self"]):
                for s in page.get("Snapshots", []):
                    started = s.get("StartTime")
                    if started and started < cutoff:
                        r_snap.append(f"{s.get('SnapshotId')}@{region}")
        except Exception as e:
            LOG.debug("Waste scan failed in %s: %s", region, e)
        return r_unatt, r_eip, r_nat, r_snap

    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
        futures = [ex.submit(check, r) for r in region_list]
        for fut in as_completed(futures):
            try:
                a, b, c, d = fut.result()
                unattached.extend(a)
                unassoc.extend(b)
                nats.extend(c)
                old_snaps.extend(d)
            except Exception:
                pass

    return {
        "unattached_ebs": unattached,
        "unassociated_eips": unassoc,
        "available_nat_gateways": nats,
        "old_available_snapshots": old_snaps[:200],  # cap noise
    }
