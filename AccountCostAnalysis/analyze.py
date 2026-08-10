#!/usr/bin/env python3
"""Backward-compatible wrapper.

Prefer the unified CLI:

    awstools cost --profile PROFILE --output-dir ./output

Or:

    python -m awstools.cli cost --dry-run
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running from a git checkout without install
_ROOT = Path(__file__).resolve().parents[1]
_SRC = _ROOT / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from awstools.cli import main


if __name__ == "__main__":
    # Map legacy bare invocation to: cost [args...]
    argv = ["cost", *sys.argv[1:]]
    # Legacy used --output for HTML path; map to output-dir + html when possible
    if "--output" in argv or "-o" in argv:
        # Keep argparse happy: cost uses -o as output-dir. Leave as-is if user
        # already uses new flags. For classic "--output report.html", rewrite.
        new_argv = ["cost"]
        args = sys.argv[1:]
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("--output",) and i + 1 < len(args):
                out = args[i + 1]
                p = Path(out)
                new_argv.extend(["--output-dir", str(p.parent if p.parent != Path(".") else "output")])
                new_argv.extend(["--html", p.name])
                i += 2
                continue
            if a == "-o" and i + 1 < len(args) and args[i + 1].endswith((".html", ".htm")):
                out = args[i + 1]
                p = Path(out)
                new_argv.extend(["--output-dir", str(p.parent if str(p.parent) not in (".", "") else "output")])
                new_argv.extend(["--html", p.name])
                i += 2
                continue
            new_argv.append(a)
            i += 1
        argv = new_argv
    raise SystemExit(main(argv))
