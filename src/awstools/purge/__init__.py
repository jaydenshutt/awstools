"""Safe S3 purge operations."""

from awstools.purge.s3 import purge_buckets, PurgeResult

__all__ = ["purge_buckets", "PurgeResult"]
