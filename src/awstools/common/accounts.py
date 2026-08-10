"""Multi-account / multi-profile configuration."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class AccountTarget:
    profile: Optional[str] = None
    region: Optional[str] = None
    regions: Optional[List[str]] = None
    all_regions: bool = False
    name: Optional[str] = None  # friendly label

    def label(self) -> str:
        return self.name or self.profile or "default"


def _from_dict(d: Dict[str, Any]) -> AccountTarget:
    regions = d.get("regions")
    if isinstance(regions, str):
        regions = [r.strip() for r in regions.split(",") if r.strip()]
    return AccountTarget(
        profile=d.get("profile"),
        region=d.get("region"),
        regions=regions,
        all_regions=bool(d.get("all_regions", False)),
        name=d.get("name"),
    )


def load_accounts_file(path: str | Path) -> List[AccountTarget]:
    """
    Load accounts from JSON or simple YAML-like JSON.

    Supported shapes:
      { "accounts": [ { "profile": "dev", "regions": ["us-east-1"] } ] }
      [ { "profile": "dev" }, { "profile": "prod", "all_regions": true } ]
    """
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    # Prefer JSON; allow minimal YAML subset via json after stripping comments if pure json
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Minimal YAML support without PyYAML: profile: x lines under accounts
        data = _parse_simple_yaml(text)

    if isinstance(data, list):
        return [_from_dict(x) for x in data]
    if isinstance(data, dict):
        accounts = data.get("accounts") or data.get("profiles") or []
        return [_from_dict(x) for x in accounts]
    raise ValueError(f"Unsupported accounts file format: {path}")


def _parse_simple_yaml(text: str) -> Any:
    """
    Very small YAML subset for accounts files:

        accounts:
          - profile: dev
            region: us-east-1
          - profile: prod
            all_regions: true
    """
    accounts: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    in_accounts = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped in ("accounts:", "profiles:"):
            in_accounts = True
            continue
        if not in_accounts:
            continue
        if stripped.startswith("- "):
            if current:
                accounts.append(current)
            current = {}
            rest = stripped[2:].strip()
            if rest and ":" in rest:
                k, v = rest.split(":", 1)
                current[k.strip()] = _coerce(v.strip())
            continue
        if current is not None and ":" in stripped:
            k, v = stripped.split(":", 1)
            key = k.strip()
            val = v.strip()
            if key == "regions":
                # regions: [a, b] or regions: a, b
                val = val.strip("[]")
                current[key] = [x.strip().strip("\"'") for x in val.split(",") if x.strip()]
            else:
                current[key] = _coerce(val)
    if current:
        accounts.append(current)
    if not accounts:
        raise ValueError("No accounts found in file (use JSON or simple YAML list)")
    return {"accounts": accounts}


def _coerce(v: str) -> Any:
    if v.lower() in ("true", "yes"):
        return True
    if v.lower() in ("false", "no"):
        return False
    if v.lower() in ("null", "none", "~", ""):
        return None
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    return v
