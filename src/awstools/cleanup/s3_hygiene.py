"""S3 hygiene: incomplete multiparts and version bloat (read-only + optional abort)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from awstools.common.findings import Finding
from awstools.common.session import client as aws_client
from awstools.purge.s3 import get_bucket_region

LOG = logging.getLogger("awstools.cleanup.s3")


def scan_s3_hygiene(session, max_buckets: int = 100, offline: bool = False) -> Dict[str, Any]:
    if offline:
        findings = [
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
                estimate_formula="upload_count * 0.1",
                metadata={"upload_count": 5},
            ),
            Finding(
                id="version-bloat:sample-versioned",
                category="s3_version_bloat",
                resource_id="sample-versioned",
                region="us-east-1",
                service="Amazon S3",
                action="add lifecycle rule to expire noncurrent versions",
                estimated_monthly_usd=5.0,
                confidence="Medium",
                evidence="versioning=Enabled; sample bloat signal",
                estimate_formula="flat 5.0 heuristic when version page dense",
            ),
        ]
        return {
            "findings": findings,
            "errors": [],
            "estimated_monthly_savings_usd": 0.5,  # high only
            "finding_count": len(findings),
            "offline": True,
        }
    s3 = aws_client(session, "s3")
    findings: List[Finding] = []
    errors: List[str] = []
    try:
        buckets = s3.list_buckets().get("Buckets", [])[:max_buckets]
    except ClientError as e:
        return {"findings": [], "errors": [str(e)], "estimated_monthly_savings_usd": 0.0}

    for b in buckets:
        name = b["Name"]
        try:
            region = get_bucket_region(s3, name)
            regional = aws_client(session, "s3", region_name=region)

            # Incomplete multiparts
            uploads = 0
            try:
                for page in regional.get_paginator("list_multipart_uploads").paginate(Bucket=name):
                    uploads += len(page.get("Uploads") or [])
            except ClientError as e:
                errors.append(f"{name}/multipart: {e}")
                uploads = 0
            if uploads:
                findings.append(
                    Finding(
                        id=f"multipart:{name}",
                        category="incomplete_multipart",
                        resource_id=name,
                        region=region,
                        service="Amazon S3",
                        action="abort incomplete multipart uploads",
                        estimated_monthly_usd=round(uploads * 0.1, 2),
                        confidence="High",
                        evidence=f"{uploads} incomplete multipart upload(s)",
                        metadata={"upload_count": uploads},
                    )
                )

            # Versioning bloat signal: count versions (sample first page only for speed)
            try:
                ver = regional.get_bucket_versioning(Bucket=name)
                status = ver.get("Status")
                if status in ("Enabled", "Suspended"):
                    resp = regional.list_object_versions(Bucket=name, MaxKeys=1000)
                    n_ver = len(resp.get("Versions") or [])
                    n_del = len(resp.get("DeleteMarkers") or [])
                    if n_ver + n_del > 100:
                        findings.append(
                            Finding(
                                id=f"version-bloat:{name}",
                                category="s3_version_bloat",
                                resource_id=name,
                                region=region,
                                service="Amazon S3",
                                action="add lifecycle rule to expire noncurrent versions",
                                estimated_monthly_usd=5.0,
                                confidence="Medium",
                                evidence=(
                                    f"versioning={status}; sample shows "
                                    f"{n_ver} versions + {n_del} delete markers in first page"
                                ),
                                metadata={"versioning": status},
                            )
                        )
            except ClientError as e:
                errors.append(f"{name}/versions: {e}")
        except Exception as e:
            errors.append(f"{name}: {e}")

    savings = sum(f.estimated_monthly_usd for f in findings)
    return {
        "findings": findings,
        "errors": errors,
        "estimated_monthly_savings_usd": round(savings, 2),
        "finding_count": len(findings),
    }


def abort_incomplete_multiparts(
    session, bucket: str, dry_run: bool = True
) -> Dict[str, Any]:
    s3_global = aws_client(session, "s3")
    region = get_bucket_region(s3_global, bucket)
    s3 = aws_client(session, "s3", region_name=region)
    aborted = 0
    errors: List[str] = []
    try:
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads") or []:
                key = u["Key"]
                upload_id = u["UploadId"]
                if dry_run:
                    LOG.info("[dry-run] abort multipart s3://%s/%s uploadId=%s", bucket, key, upload_id)
                    aborted += 1
                    continue
                try:
                    s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
                    aborted += 1
                except ClientError as e:
                    errors.append(f"{key}: {e}")
    except ClientError as e:
        errors.append(str(e))
    return {"bucket": bucket, "aborted": aborted, "dry_run": dry_run, "errors": errors}
