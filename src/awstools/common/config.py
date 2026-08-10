"""Load awstools.toml / ignore rules / deny lists (no PyYAML required)."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


DEFAULT_DETECTORS = (
    "unattached_ebs",
    "unassociated_eip",
    "idle_elb",
    "incomplete_multipart",
    "old_snapshot",
    "gp2_to_gp3",
    "old_ami",
    "nat_gateway_review",
    "unattached_eni",
    "ec2_rightsizing",
)


@dataclass
class ToolsConfig:
    """Runtime configuration merged from file + CLI."""

    default_region: Optional[str] = None
    all_regions: bool = False
    concurrency: int = 6
    output_dir: str = "output"
    detectors: List[str] = field(default_factory=lambda: list(DEFAULT_DETECTORS))
    fail_on_waste_usd: Optional[float] = None
    fail_on_savings_usd: Optional[float] = None
    grace_days: int = 3  # ignore resources younger than this when age known
    high_confidence_only_totals: bool = True
    # Ignore rules
    ignore_categories: List[str] = field(default_factory=list)
    ignore_resource_globs: List[str] = field(default_factory=list)
    ignore_regions: List[str] = field(default_factory=list)
    ignore_tag_key_values: Dict[str, str] = field(default_factory=dict)
    # Deny (hard block execute)
    deny_account_ids: List[str] = field(default_factory=list)
    deny_bucket_globs: List[str] = field(default_factory=list)
    deny_resource_globs: List[str] = field(default_factory=list)
    # Paths
    config_path: Optional[str] = None

    def enabled_detectors(self, override: Optional[List[str]] = None) -> Set[str]:
        if override:
            return set(override)
        return set(self.detectors or DEFAULT_DETECTORS)


def _parse_simple_tomlish(text: str) -> Dict[str, Any]:
    """
    Minimal TOML-like parser for flat keys and simple lists/bools/numbers.
    Supports:
      key = "value"
      key = true
      key = 6
      key = ["a", "b"]
      [section] ignored for nesting except we flatten section.key
    """
    data: Dict[str, Any] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        full = f"{section}.{key}" if section else key
        data[full] = _parse_value(val)
    return data


def _parse_value(val: str) -> Any:
    if val.lower() in ("true", "false"):
        return val.lower() == "true"
    if val.startswith("[") and val.endswith("]"):
        inner = val[1:-1].strip()
        if not inner:
            return []
        parts = []
        for p in inner.split(","):
            p = p.strip().strip('"').strip("'")
            if p:
                parts.append(p)
        return parts
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        return val[1:-1]
    try:
        if "." in val:
            return float(val)
        return int(val)
    except ValueError:
        return val


def _apply_flat(cfg: ToolsConfig, flat: Dict[str, Any]) -> ToolsConfig:
    mapping = {
        "default_region": "default_region",
        "region": "default_region",
        "all_regions": "all_regions",
        "concurrency": "concurrency",
        "output_dir": "output_dir",
        "detectors": "detectors",
        "fail_on_waste_usd": "fail_on_waste_usd",
        "fail_on_savings_usd": "fail_on_savings_usd",
        "grace_days": "grace_days",
        "high_confidence_only_totals": "high_confidence_only_totals",
        "ignore.categories": "ignore_categories",
        "ignore.resources": "ignore_resource_globs",
        "ignore.regions": "ignore_regions",
        "deny.accounts": "deny_account_ids",
        "deny.buckets": "deny_bucket_globs",
        "deny.resources": "deny_resource_globs",
    }
    for src, dest in mapping.items():
        if src in flat and flat[src] is not None:
            setattr(cfg, dest, flat[src])
    # tags: ignore.tags.Env = prod  style → we accept ignore.tags as dict via JSON only
    return cfg


def load_ignore_file(path: Path) -> Dict[str, Any]:
    """JSON or simple key lists for ignore rules."""
    text = path.read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # simple format: categories: a, b
        out: Dict[str, Any] = {
            "categories": [],
            "resources": [],
            "regions": [],
            "tags": {},
        }
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            k, v = line.split(":", 1)
            k, v = k.strip().lower(), v.strip()
            if k in ("categories", "resources", "regions"):
                out[k] = [x.strip() for x in v.split(",") if x.strip()]
            elif k.startswith("tag."):
                tag = k.split(".", 1)[1]
                out.setdefault("tags", {})[tag] = v
        return out


def discover_config_path(cli_path: Optional[str] = None) -> Optional[Path]:
    if cli_path:
        p = Path(cli_path)
        return p if p.exists() else None
    candidates = [
        Path("awstools.toml"),
        Path(".awstools.toml"),
        Path.home() / ".awstools" / "config.toml",
        Path.home() / ".config" / "awstools" / "config.toml",
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def load_config(
    config_path: Optional[str] = None,
    ignore_path: Optional[str] = None,
) -> ToolsConfig:
    cfg = ToolsConfig()
    path = discover_config_path(config_path)
    if path:
        flat = _parse_simple_tomlish(path.read_text(encoding="utf-8"))
        cfg = _apply_flat(cfg, flat)
        cfg.config_path = str(path)

    ign = None
    if ignore_path:
        ign = Path(ignore_path)
    else:
        for c in (
            Path("awstools-ignore.json"),
            Path("ignore.json"),
            Path.home() / ".awstools" / "ignore.json",
        ):
            if c.is_file():
                ign = c
                break
    if ign and ign.is_file():
        data = load_ignore_file(ign)
        cfg.ignore_categories = list(data.get("categories") or cfg.ignore_categories)
        cfg.ignore_resource_globs = list(data.get("resources") or cfg.ignore_resource_globs)
        cfg.ignore_regions = list(data.get("regions") or cfg.ignore_regions)
        if isinstance(data.get("tags"), dict):
            cfg.ignore_tag_key_values = {str(k): str(v) for k, v in data["tags"].items()}

    # Env overrides
    if os.environ.get("AWSTOOLS_GRACE_DAYS"):
        try:
            cfg.grace_days = int(os.environ["AWSTOOLS_GRACE_DAYS"])
        except ValueError:
            pass
    return cfg


def config_to_dict(cfg: ToolsConfig) -> Dict[str, Any]:
    return asdict(cfg)
