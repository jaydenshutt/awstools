#!/usr/bin/env python3
"""Backward-compatible wrapper for S3 purge.

Prefer:

    awstools purge-s3 --profile PROFILE          # dry-run
    awstools purge-s3 --profile PROFILE --execute --confirm-account 123456789012
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from awstools.cli import main


if __name__ == "__main__":
    # Legacy: --dry-run was explicit; default is now dry-run.
    # Legacy --yes maps through; --dry-run is ignored (already default).
    args = ["purge-s3"]
    legacy = sys.argv[1:]
    i = 0
    execute = False
    while i < len(legacy):
        a = legacy[i]
        if a == "--dry-run":
            i += 1
            continue
        if a == "--yes":
            # Old --yes skipped confirm; still need account gate for execute.
            args.append("--yes")
            i += 1
            continue
        # If user did not pass --dry-run and passed something implying real run...
        # Legacy real run was default when --dry-run absent. That is too dangerous.
        # We keep safe default: dry-run unless AWSTOOLS_LEGACY_PURGE_EXECUTE=1
        args.append(a)
        i += 1

    # Breaking change by design: never auto-execute from legacy wrapper.
    # Print a note when it looks like an old-style real run (no --dry-run in original).
    if "--dry-run" not in sys.argv and "--execute" not in args:
        print(
            "NOTE: purge now dry-runs by default. "
            "Pass --execute --confirm-account <12-digit-id> to delete.",
            file=sys.stderr,
        )

    raise SystemExit(main(args))
