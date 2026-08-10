"""S3 bucket purge with safety rails, region-correct deletes, and audit logging.

Destructive by design. Dry-run is the default path when --execute is not set
at the CLI layer. Prefer filters + account confirmation for any real run.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from awstools.common.safety import BucketFilter
from awstools.common.session import client as aws_client

LOG = logging.getLogger("awstools.purge")


@dataclass
class BucketOutcome:
    name: str
    region: str = "unknown"
    versioned: bool = False
    objects_deleted: int = 0
    errors: List[str] = field(default_factory=list)
    deleted_bucket: bool = False
    skipped: bool = False
    skip_reason: str = ""


@dataclass
class PurgeResult:
    account_id: str
    caller_arn: str
    dry_run: bool
    started_at: str
    finished_at: str = ""
    selected: List[str] = field(default_factory=list)
    protected: List[str] = field(default_factory=list)
    filtered_out: List[str] = field(default_factory=list)
    outcomes: List[BucketOutcome] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d

    def write_audit_log(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        LOG.info("Audit log written to %s", path)


def get_bucket_region(s3_client, bucket_name: str) -> str:
    """Resolve the region for a bucket (LocationConstraint quirks handled)."""
    try:
        resp = s3_client.get_bucket_location(Bucket=bucket_name)
        loc = resp.get("LocationConstraint")
        # us-east-1 returns None or empty string
        if not loc:
            return "us-east-1"
        # EU legacy alias
        if loc == "EU":
            return "eu-west-1"
        return loc
    except ClientError as e:
        LOG.warning("Could not resolve region for %s: %s", bucket_name, e)
        return "us-east-1"


def is_versioning_active(s3_client, bucket_name: str) -> bool:
    """True when versioning is Enabled OR Suspended (versions may still exist)."""
    try:
        resp = s3_client.get_bucket_versioning(Bucket=bucket_name)
        status = resp.get("Status")
        # Suspended buckets still have versions and delete markers
        return status in ("Enabled", "Suspended")
    except ClientError as e:
        LOG.warning("Could not determine versioning for %s: %s", bucket_name, e)
        return True  # safest: attempt versioned delete path


def _batch_delete(
    s3_client,
    bucket_name: str,
    objects: List[Dict[str, str]],
    dry_run: bool,
) -> tuple[int, List[str]]:
    if not objects:
        return 0, []
    if dry_run:
        LOG.debug("[dry-run] would delete %d objects from %s", len(objects), bucket_name)
        return len(objects), []
    try:
        resp = s3_client.delete_objects(
            Bucket=bucket_name,
            Delete={"Objects": objects, "Quiet": True},
        )
        deleted = len(resp.get("Deleted", []))
        # Quiet mode may omit Deleted list; assume success count
        if deleted == 0 and not resp.get("Errors"):
            deleted = len(objects)
        errors = [
            f"{err.get('Key')}: {err.get('Code')} {err.get('Message')}"
            for err in resp.get("Errors", [])
        ]
        return deleted, errors
    except ClientError as e:
        return 0, [str(e)]


def empty_bucket(s3_client, bucket_name: str, versioned: bool, dry_run: bool) -> tuple[int, List[str]]:
    """Delete all objects (and versions/markers if versioned). Returns (count, errors)."""
    total = 0
    errors: List[str] = []
    if versioned:
        paginator = s3_client.get_paginator("list_object_versions")
        batch: List[Dict[str, str]] = []
        for page in paginator.paginate(Bucket=bucket_name):
            for ver in page.get("Versions", []):
                batch.append({"Key": ver["Key"], "VersionId": ver["VersionId"]})
                if len(batch) >= 1000:
                    n, errs = _batch_delete(s3_client, bucket_name, batch, dry_run)
                    total += n
                    errors.extend(errs)
                    batch = []
            for marker in page.get("DeleteMarkers", []):
                batch.append({"Key": marker["Key"], "VersionId": marker["VersionId"]})
                if len(batch) >= 1000:
                    n, errs = _batch_delete(s3_client, bucket_name, batch, dry_run)
                    total += n
                    errors.extend(errs)
                    batch = []
        if batch:
            n, errs = _batch_delete(s3_client, bucket_name, batch, dry_run)
            total += n
            errors.extend(errs)
    else:
        paginator = s3_client.get_paginator("list_objects_v2")
        batch = []
        for page in paginator.paginate(Bucket=bucket_name):
            for obj in page.get("Contents", []):
                batch.append({"Key": obj["Key"]})
                if len(batch) >= 1000:
                    n, errs = _batch_delete(s3_client, bucket_name, batch, dry_run)
                    total += n
                    errors.extend(errs)
                    batch = []
        if batch:
            n, errs = _batch_delete(s3_client, bucket_name, batch, dry_run)
            total += n
            errors.extend(errs)
    return total, errors


def delete_bucket(s3_client, bucket_name: str, dry_run: bool) -> tuple[bool, Optional[str]]:
    if dry_run:
        LOG.info("[dry-run] would delete bucket %s", bucket_name)
        return True, None
    try:
        s3_client.delete_bucket(Bucket=bucket_name)
        LOG.info("Deleted bucket %s", bucket_name)
        return True, None
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        msg = str(e)
        # Object Lock / MFA Delete / non-empty residual
        if code in ("BucketNotEmpty", "AccessDenied", "InvalidBucketState"):
            return False, f"{code}: {msg}"
        return False, msg


def sample_purge_plan(
    bucket_filter: BucketFilter,
    account_id: str = "000000000000",
    caller_arn: str = "arn:aws:iam::000000000000:user/awstools-dry-run",
) -> Dict[str, Any]:
    """Offline sample plan for --dry-run / AWSTOOLS_OFFLINE."""
    from awstools.common.plan_fingerprint import attach_fingerprint

    names = [
        "tmp-lab-data",
        "tmp-scratch-1",
        "my-app-assets",
        "aws-cloudtrail-logs-000000000000",
        "terraform-state-prod",
    ]
    classified = bucket_filter.classify(names)
    plan_rows = [
        {
            "name": n,
            "region": "us-east-1",
            "versioned": n.startswith("tmp"),
            "object_estimate": 42 if n.startswith("tmp") else 10,
            "action": "empty+delete",
        }
        for n in classified["selected"]
    ]
    plan = {
        "account_id": account_id,
        "caller_arn": caller_arn,
        "total_buckets": len(names),
        "selected_count": len(classified["selected"]),
        "protected_count": len(classified["protected"]),
        "filtered_out_count": len(classified["filtered_out"]),
        "protected": classified["protected"],
        "filtered_out": classified["filtered_out"],
        "selected": plan_rows,
        "blast_radius": {
            "buckets_to_delete": len(classified["selected"]),
            "objects_estimate_partial": sum(
                r["object_estimate"] for r in plan_rows if isinstance(r["object_estimate"], int)
            ),
            "note": "Offline sample plan - no AWS calls",
        },
        "offline": True,
    }
    return attach_fingerprint(plan)


def build_purge_plan(
    session,
    bucket_filter: BucketFilter,
    account_id: str = "unknown",
    caller_arn: str = "unknown",
    estimate_objects: bool = True,
    max_estimate_buckets: int = 50,
    offline: bool = False,
) -> Dict[str, Any]:
    """
    Build a blast-radius plan without deleting anything.

    Returns plan dict with selected/protected buckets, object estimates, fingerprint.
    """
    from awstools.common.plan_fingerprint import attach_fingerprint

    if offline:
        return sample_purge_plan(bucket_filter, account_id=account_id, caller_arn=caller_arn)

    s3 = aws_client(session, "s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        raise RuntimeError(f"Failed to list buckets: {e}") from e

    names = [b["Name"] for b in buckets]
    classified = bucket_filter.classify(names)
    plan_rows: List[Dict[str, Any]] = []
    total_objects_est = 0

    for name in classified["selected"]:
        region = get_bucket_region(s3, name)
        regional = aws_client(session, "s3", region_name=region)
        versioned = is_versioning_active(regional, name)
        obj_est = None
        if estimate_objects and len(plan_rows) < max_estimate_buckets:
            try:
                count = 0
                if versioned:
                    paginator = regional.get_paginator("list_object_versions")
                    for i, page in enumerate(
                        paginator.paginate(Bucket=name, PaginationConfig={"MaxItems": 5000})
                    ):
                        count += len(page.get("Versions") or [])
                        count += len(page.get("DeleteMarkers") or [])
                        if i >= 4:
                            count = f"{count}+"
                            break
                else:
                    paginator = regional.get_paginator("list_objects_v2")
                    for i, page in enumerate(
                        paginator.paginate(Bucket=name, PaginationConfig={"MaxItems": 5000})
                    ):
                        count += len(page.get("Contents") or [])
                        if i >= 4:
                            count = f"{count}+"
                            break
                obj_est = count
                if isinstance(count, int):
                    total_objects_est += count
            except ClientError as e:
                obj_est = f"error: {e.response.get('Error', {}).get('Code', 'err')}"
        plan_rows.append(
            {
                "name": name,
                "region": region,
                "versioned": versioned,
                "object_estimate": obj_est,
                "action": "empty+delete",
            }
        )

    plan = {
        "account_id": account_id,
        "caller_arn": caller_arn,
        "total_buckets": len(names),
        "selected_count": len(classified["selected"]),
        "protected_count": len(classified["protected"]),
        "filtered_out_count": len(classified["filtered_out"]),
        "protected": classified["protected"],
        "filtered_out": classified["filtered_out"],
        "selected": plan_rows,
        "blast_radius": {
            "buckets_to_delete": len(classified["selected"]),
            "objects_estimate_partial": total_objects_est,
            "note": "Object counts may be capped samples for large buckets",
        },
        "offline": False,
    }
    return attach_fingerprint(plan)


def purge_buckets(
    session,
    bucket_filter: BucketFilter,
    dry_run: bool = True,
    account_id: str = "unknown",
    caller_arn: str = "unknown",
    plan_only: bool = False,
) -> PurgeResult:
    """List buckets, apply filters/protections, empty and delete selected buckets."""
    started = datetime.now(timezone.utc).isoformat()
    s3 = aws_client(session, "s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        raise RuntimeError(f"Failed to list buckets: {e}") from e

    names = [b["Name"] for b in buckets]
    classified = bucket_filter.classify(names)

    result = PurgeResult(
        account_id=account_id,
        caller_arn=caller_arn,
        dry_run=dry_run or plan_only,
        started_at=started,
        selected=classified["selected"],
        protected=classified["protected"],
        filtered_out=classified["filtered_out"],
    )

    LOG.info(
        "Buckets: %d total | %d selected | %d protected | %d filtered out | dry_run=%s plan_only=%s",
        len(names),
        len(result.selected),
        len(result.protected),
        len(result.filtered_out),
        dry_run,
        plan_only,
    )
    for p in result.protected:
        LOG.warning("Protected (skipped): %s", p)
    for name in result.selected:
        LOG.info("Selected: %s", name)

    if plan_only:
        # Record planned outcomes without API deletes
        for name in result.selected:
            region = get_bucket_region(s3, name)
            regional = aws_client(session, "s3", region_name=region)
            result.outcomes.append(
                BucketOutcome(
                    name=name,
                    region=region,
                    versioned=is_versioning_active(regional, name),
                    skipped=True,
                    skip_reason="plan_only",
                )
            )
        result.finished_at = datetime.now(timezone.utc).isoformat()
        return result

    for name in result.selected:
        outcome = BucketOutcome(name=name)
        try:
            region = get_bucket_region(s3, name)
            outcome.region = region
            regional = aws_client(session, "s3", region_name=region)
            versioned = is_versioning_active(regional, name)
            outcome.versioned = versioned

            LOG.info(
                "Emptying %s (region=%s versioned=%s dry_run=%s)",
                name,
                region,
                versioned,
                dry_run,
            )
            deleted_count, errs = empty_bucket(regional, name, versioned, dry_run)
            outcome.objects_deleted = deleted_count
            outcome.errors.extend(errs)

            if errs and not dry_run:
                LOG.warning("Errors while emptying %s: %s", name, errs[:5])

            ok, err = delete_bucket(regional, name, dry_run)
            outcome.deleted_bucket = ok
            if err:
                outcome.errors.append(err)
                LOG.error("Failed to delete bucket %s: %s", name, err)
            else:
                LOG.info(
                    "%s bucket %s (%d objects)",
                    "Would delete" if dry_run else "Deleted",
                    name,
                    deleted_count,
                )
        except Exception as e:
            outcome.errors.append(str(e))
            LOG.error("Error processing bucket %s: %s", name, e)
        result.outcomes.append(outcome)
        # Light pacing to reduce throttling on large accounts
        if not dry_run:
            time.sleep(0.05)

    result.finished_at = datetime.now(timezone.utc).isoformat()
    return result
