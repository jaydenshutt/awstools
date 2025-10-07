# S3 Bucket Purge

Small tool to delete all objects in all S3 buckets for a given AWS CLI profile and then remove the buckets.

Warning: This is destructive. Use --dry-run first and verify the profile.

Usage:

1. Install requirements:

```powershell
python -m pip install -r requirements.txt
```

2. Run the script (dry-run recommended):

```powershell
python purge.py --profile myprofile --dry-run
```

To run for real (careful):

```powershell
python purge.py --profile myprofile --yes
```

Options:
- --profile / -p : AWS CLI profile name (required)
- --region / -r : Optional region to initialize session with
- --dry-run : Show what would be deleted but don't perform destructive actions
- --yes : Skip interactive confirmation
- --verbose / -v : Show debug logs

Notes:
- Script uses boto3 and the profile from your AWS CLI configuration.
- For versioned buckets the script deletes all versions and delete markers.
- For very large buckets this may take time; it's batched in chunks of up to 1000 items per API call.
