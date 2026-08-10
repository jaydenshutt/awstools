"""Human and machine-readable command output."""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional

from awstools.branding import ATTRIBUTION_PLAIN, NO_WARRANTY_SHORT


def emit(
    data: Dict[str, Any],
    fmt: str = "text",
    text_lines: Optional[list[str]] = None,
    *,
    show_attribution: bool = True,
) -> None:
    """Print JSON object or human text lines to stdout."""
    if fmt == "json":
        payload = dict(data)
        payload.setdefault("created_by", ATTRIBUTION_PLAIN)
        payload.setdefault("no_warranty", NO_WARRANTY_SHORT)
        json.dump(payload, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
        return
    if text_lines:
        for line in text_lines:
            print(line)
    else:
        for k, v in data.items():
            if k.startswith("_"):
                continue
            print(f"{k}: {v}")
    if show_attribution and fmt == "text":
        print(f"- {ATTRIBUTION_PLAIN}")
        print(f"- {NO_WARRANTY_SHORT}")


def load_json_file(path: str) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)
