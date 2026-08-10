"""Redact sensitive identifiers for shareable reports."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Union


def _hash_id(value: str, n: int = 10) -> str:
    h = hashlib.sha256(value.encode("utf-8")).hexdigest()[:n]
    return f"redacted-{h}"


_ACCOUNT_RE = re.compile(r"\b\d{12}\b")
_ARN_RE = re.compile(r"arn:aws[a-zA-Z-]*:[^:\s]*:[^:\s]*:\d{12}:[^\s]+")


def redact_string(s: str) -> str:
    s = _ARN_RE.sub(lambda m: _hash_id(m.group(0)), s)
    s = _ACCOUNT_RE.sub(lambda m: _hash_id(m.group(0), 8), s)
    return s


def redact_obj(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if lk in ("account_id", "account"):
                out[k] = _hash_id(str(v), 8) if v else v
            elif lk in ("arn", "caller_arn"):
                out[k] = _hash_id(str(v)) if v else v
            elif lk in ("resource_id", "resource", "name") and isinstance(v, str):
                # keep category-friendly prefix if present
                if v.startswith("i-") or v.startswith("vol-") or v.startswith("arn:"):
                    out[k] = _hash_id(v)
                else:
                    out[k] = redact_string(v)
            else:
                out[k] = redact_obj(v)
        return out
    if isinstance(obj, list):
        return [redact_obj(x) for x in obj]
    if isinstance(obj, str):
        return redact_string(obj)
    return obj
