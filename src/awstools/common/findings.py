"""Normalized finding model, filtering, confidence totals, and deduplication."""

from __future__ import annotations

import fnmatch
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, TYPE_CHECKING

if TYPE_CHECKING:
    from awstools.common.config import ToolsConfig

FINDINGS_SCHEMA_VERSION = 1


@dataclass
class Finding:
    id: str
    category: str
    resource_id: str
    region: str
    action: str
    estimated_monthly_usd: float
    confidence: str  # High | Medium | Low
    evidence: str
    service: str = ""
    tags: Dict[str, str] = field(default_factory=dict)
    protected: bool = False
    ignored: bool = False
    ignore_reason: str = ""
    estimate_formula: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        # dataclass fields
        from dataclasses import fields

        kwargs = {}
        for f in fields(cls):
            if f.name in d:
                kwargs[f.name] = d[f.name]
        return cls(**kwargs)


def has_protect_tag(tags: Dict[str, str]) -> bool:
    for k, v in (tags or {}).items():
        kl = k.lower().replace("_", ":")
        if kl in ("awstools:protect", "awstoolsprotect", "protect") or k == "awstools:protect":
            if str(v).lower() in ("true", "yes", "1", "protected"):
                return True
    return False


def apply_filters(
    findings: List[Finding],
    config: Optional["ToolsConfig"] = None,
    grace_days: Optional[int] = None,
) -> List[Finding]:
    """Mark ignored/protected findings based on config; return same list mutated."""
    if config is None and grace_days is None:
        return findings
    gdays = grace_days if grace_days is not None else (config.grace_days if config else 0)

    for f in findings:
        if f.protected or has_protect_tag(f.tags):
            f.protected = True
            continue
        if config:
            if f.category in (config.ignore_categories or []):
                f.ignored = True
                f.ignore_reason = f"category {f.category} ignored"
                continue
            if f.region in (config.ignore_regions or []):
                f.ignored = True
                f.ignore_reason = f"region {f.region} ignored"
                continue
            for glob in config.ignore_resource_globs or []:
                if fnmatch.fnmatch(f.resource_id, glob) or fnmatch.fnmatch(f.id, glob):
                    f.ignored = True
                    f.ignore_reason = f"resource matches {glob}"
                    break
            if f.ignored:
                continue
            for tk, tv in (config.ignore_tag_key_values or {}).items():
                if f.tags.get(tk) == tv:
                    f.ignored = True
                    f.ignore_reason = f"tag {tk}={tv}"
                    break
        if gdays and not f.ignored:
            age = f.metadata.get("age_days")
            if age is not None:
                try:
                    if float(age) < gdays:
                        f.ignored = True
                        f.ignore_reason = f"younger than grace_days={gdays}"
                except (TypeError, ValueError):
                    pass
    return findings


def dedupe_findings(findings: List[Finding]) -> List[Finding]:
    """
    Keep highest-confidence / highest-$ finding per (category, resource_id, region).
    Prefer High > Medium > Low; then higher estimated_monthly_usd.
    """
    rank = {"High": 3, "Medium": 2, "Low": 1}
    best: Dict[tuple, Finding] = {}
    for f in findings:
        key = (f.category, f.resource_id, f.region)
        prev = best.get(key)
        if prev is None:
            best[key] = f
            continue
        pr = rank.get(prev.confidence, 0)
        cr = rank.get(f.confidence, 0)
        if cr > pr or (
            cr == pr and f.estimated_monthly_usd > prev.estimated_monthly_usd
        ):
            best[key] = f
    return list(best.values())


def actionable(findings: Iterable[Finding]) -> List[Finding]:
    return [f for f in findings if not f.protected and not f.ignored]


def total_savings(
    findings: List[Finding],
    *,
    high_only: bool = False,
    include_ignored: bool = False,
) -> float:
    total = 0.0
    for f in findings:
        if f.protected:
            continue
        if not include_ignored and f.ignored:
            continue
        if high_only and f.confidence != "High":
            continue
        total += float(f.estimated_monthly_usd or 0)
    return round(total, 2)


def savings_breakdown(findings: List[Finding]) -> Dict[str, float]:
    return {
        "high_confidence_usd": total_savings(findings, high_only=True),
        "all_confidence_usd": total_savings(findings, high_only=False),
        "medium_low_review_usd": round(
            total_savings(findings, high_only=False) - total_savings(findings, high_only=True),
            2,
        ),
    }


def filter_unprotected(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if not f.protected and not f.ignored]


def findings_to_rows(findings: List[Finding]) -> List[Dict[str, Any]]:
    rows = []
    for f in sorted(
        findings,
        key=lambda x: (
            0 if x.confidence == "High" else 1 if x.confidence == "Medium" else 2,
            -x.estimated_monthly_usd,
        ),
    ):
        rows.append(
            {
                "id": f.id,
                "category": f.category,
                "resource_id": f.resource_id,
                "region": f.region,
                "service": f.service,
                "action": f.action,
                "estimated_monthly_usd": round(f.estimated_monthly_usd, 2),
                "confidence": f.confidence,
                "evidence": f.evidence,
                "estimate_formula": f.estimate_formula,
                "protected": f.protected,
                "ignored": f.ignored,
                "ignore_reason": f.ignore_reason,
            }
        )
    return rows


def findings_payload(findings: List[Finding], **extra: Any) -> Dict[str, Any]:
    cleaned = dedupe_findings(list(findings))
    br = savings_breakdown(cleaned)
    return {
        "schema_version": FINDINGS_SCHEMA_VERSION,
        "finding_count": len(cleaned),
        "actionable_count": len(actionable(cleaned)),
        "estimated_monthly_savings_usd": br["high_confidence_usd"],
        "estimated_monthly_savings_all_confidence_usd": br["all_confidence_usd"],
        "savings_breakdown": br,
        "findings": findings_to_rows(cleaned),
        **extra,
    }


def load_findings_file(path: str) -> List[Finding]:
    """Load findings from a findings.json produced by awstools."""
    import json
    from pathlib import Path

    data = json.loads(Path(path).read_text(encoding="utf-8"))
    raw = data.get("findings") if isinstance(data, dict) else data
    if not isinstance(raw, list):
        raise ValueError("findings file must contain a list or {findings: [...]}")
    out: List[Finding] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        # rows may lack tags/metadata
        out.append(
            Finding(
                id=str(item.get("id") or item.get("resource_id")),
                category=str(item.get("category") or "unknown"),
                resource_id=str(item.get("resource_id") or ""),
                region=str(item.get("region") or ""),
                action=str(item.get("action") or ""),
                estimated_monthly_usd=float(item.get("estimated_monthly_usd") or 0),
                confidence=str(item.get("confidence") or "Medium"),
                evidence=str(item.get("evidence") or ""),
                service=str(item.get("service") or ""),
                protected=bool(item.get("protected")),
                ignored=bool(item.get("ignored")),
                estimate_formula=str(item.get("estimate_formula") or ""),
                metadata=dict(item.get("metadata") or {}),
            )
        )
    return out


def filter_findings_by_ids(
    findings: List[Finding], resource_ids: Optional[List[str]] = None
) -> List[Finding]:
    if not resource_ids:
        return findings
    wanted = set(resource_ids)
    return [f for f in findings if f.resource_id in wanted or f.id in wanted]
