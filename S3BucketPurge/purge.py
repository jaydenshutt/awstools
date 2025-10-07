"""S3 Bucket Purge Tool

Deletes all objects from all buckets in an AWS account (using an AWS CLI profile) and removes the buckets.

Features:
- Uses AWS CLI profile via boto3.Session(profile_name=...)
- Detects bucket versioning and deletes versions + delete markers when enabled
- Batch deletes objects (up to 1000 per DeleteObjects call)
- Dry-run mode and interactive confirmation

WARNING: This is destructive. Use --dry-run first and verify the profile and buckets.
"""
from __future__ import annotations

import argparse
import logging
import sys
from typing import Dict, List

import boto3
from botocore.exceptions import ClientError


LOG = logging.getLogger("s3purge")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Purge all S3 buckets for an AWS CLI profile and delete the buckets.")
    p.add_argument("--profile", "-p", required=True, help="AWS CLI profile name to use")
    p.add_argument("--region", "-r", default=None, help="AWS region (optional)")
    p.add_argument("--dry-run", action="store_true", help="Do everything except actually delete objects/buckets")
    p.add_argument("--yes", action="store_true", help="Skip confirmation prompt and proceed")
    p.add_argument("--verbose", "-v", action="store_true", help="Show debug logs")
    return p.parse_args()


def get_all_buckets(s3_client) -> List[Dict]:
    resp = s3_client.list_buckets()
    return resp.get("Buckets", [])


def is_bucket_versioned(s3_client, bucket_name: str) -> bool:
    try:
        resp = s3_client.get_bucket_versioning(Bucket=bucket_name)
        status = resp.get("Status")
        return status == "Enabled"
    except ClientError as e:
        LOG.warning("Could not determine versioning for %s: %s", bucket_name, e)
        return False


def delete_objects_non_versioned(s3_client, bucket_name: str, dry_run: bool = True) -> None:
    paginator = s3_client.get_paginator("list_objects_v2")
    to_delete = []
    for page in paginator.paginate(Bucket=bucket_name):
        for obj in page.get("Contents", []):
            to_delete.append({"Key": obj["Key"]})
            if len(to_delete) >= 1000:
                _batch_delete(s3_client, bucket_name, to_delete, dry_run=dry_run)
                to_delete = []
    if to_delete:
        _batch_delete(s3_client, bucket_name, to_delete, dry_run=dry_run)


def delete_objects_versioned(s3_client, bucket_name: str, dry_run: bool = True) -> None:
    paginator = s3_client.get_paginator("list_object_versions")
    to_delete = []
    for page in paginator.paginate(Bucket=bucket_name):
        for ver in page.get("Versions", []):
            to_delete.append({"Key": ver["Key"], "VersionId": ver["VersionId"]})
            if len(to_delete) >= 1000:
                _batch_delete(s3_client, bucket_name, to_delete, dry_run=dry_run)
                to_delete = []
        for marker in page.get("DeleteMarkers", []):
            to_delete.append({"Key": marker["Key"], "VersionId": marker["VersionId"]})
            if len(to_delete) >= 1000:
                _batch_delete(s3_client, bucket_name, to_delete, dry_run=dry_run)
                to_delete = []
    if to_delete:
        _batch_delete(s3_client, bucket_name, to_delete, dry_run=dry_run)


def _batch_delete(s3_client, bucket_name: str, objects: List[Dict], dry_run: bool = True) -> None:
    if not objects:
        return
    LOG.debug("Deleting %d objects from %s (dry_run=%s)", len(objects), bucket_name, dry_run)
    if dry_run:
        for o in objects:
            LOG.info("[dry-run] %s %s", bucket_name, o)
        return
    try:
        # DeleteObjects accepts up to 1000 objects per request
        resp = s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": objects})
        deleted = resp.get("Deleted", [])
        errors = resp.get("Errors", [])
        LOG.info("Deleted %d items from %s", len(deleted), bucket_name)
        if errors:
            LOG.warning("Errors deleting some objects from %s: %s", bucket_name, errors)
    except ClientError as e:
        LOG.error("Failed to delete objects in %s: %s", bucket_name, e)


def empty_bucket(s3_client, bucket_name: str, versioned: bool, dry_run: bool = True) -> None:
    LOG.info("Emptying bucket %s (versioned=%s)", bucket_name, versioned)
    if versioned:
        delete_objects_versioned(s3_client, bucket_name, dry_run=dry_run)
    else:
        delete_objects_non_versioned(s3_client, bucket_name, dry_run=dry_run)


def delete_bucket(s3_client, bucket_name: str, dry_run: bool = True) -> None:
    LOG.info("Deleting bucket %s (dry_run=%s)", bucket_name, dry_run)
    if dry_run:
        LOG.info("[dry-run] Would delete bucket %s", bucket_name)
        return
    try:
        s3_client.delete_bucket(Bucket=bucket_name)
        LOG.info("Deleted bucket %s", bucket_name)
    except ClientError as e:
        LOG.error("Failed to delete bucket %s: %s", bucket_name, e)


def confirm(prompt: str = "Proceed? (yes/no): ") -> bool:
    try:
        choice = input(prompt).strip().lower()
    except EOFError:
        return False
    return choice in ("y", "yes")


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s: %(message)s")

    LOG.debug("Using profile=%s region=%s dry_run=%s", args.profile, args.region, args.dry_run)

    session_kwargs = {"profile_name": args.profile}
    if args.region:
        session_kwargs["region_name"] = args.region

    try:
        session = boto3.Session(**session_kwargs)
        s3 = session.client("s3")
    except Exception as e:
        LOG.error("Failed to create boto3 session: %s", e)
        return 2

    try:
        buckets = get_all_buckets(s3)
    except ClientError as e:
        LOG.error("Failed to list buckets: %s", e)
        return 3

    if not buckets:
        LOG.info("No buckets found for profile %s", args.profile)
        return 0

    bucket_names = [b["Name"] for b in buckets]
    LOG.info("Found %d buckets", len(bucket_names))
    for name in bucket_names:
        LOG.info("  - %s", name)

    if not args.yes:
        LOG.warning("This operation is destructive. Use --dry-run to preview or --yes to skip confirmation.")
        if not confirm("Delete all objects and buckets listed above? Type 'yes' to continue: "):
            LOG.info("Aborted by user")
            return 0

    for name in bucket_names:
        try:
            v = is_bucket_versioned(s3, name)
            empty_bucket(s3, name, v, dry_run=args.dry_run)
            delete_bucket(s3, name, dry_run=args.dry_run)
        except Exception as e:
            LOG.error("Error processing bucket %s: %s", name, e)

    LOG.info("Done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
