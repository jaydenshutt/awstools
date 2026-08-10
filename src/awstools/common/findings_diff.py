"""Compare two findings.json payloads (week-over-week waste)."""

from __future__ import annotations

from typing import Any, Dict, List, Set, Tuple


def _key(row: Dict[str, Any]) -> Tuple[str, str, str]:
    return (
        str(row.get("category") or ""),
        str(row.get("resource_id") or ""),
        str(row.get("region") or ""),
    )


def _index(findings: List[Dict[str, Any]]) -> Dict[Tuple[str, str, str], Dict[str, Any]]:
    out = {}
    for f in findings or []:
        if isinstance(f, dict):
            out[_key(f)] = f
    return out


def diff_findings(
    current: Dict[str, Any],
    previous: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Diff two findings payloads.

    Returns new / resolved / changed / savings deltas.
    """
    cur_list = current.get("findings") if isinstance(current, dict) else []
    prev_list = previous.get("findings") if isinstance(previous, dict) else []
    if not isinstance(cur_list, list):
        cur_list = []
    if not isinstance(prev_list, list):
        prev_list = []

    cur_i = _index(cur_list)
    prev_i = _index(prev_list)
    cur_keys: Set = set(cur_i)
    prev_keys: Set = set(prev_i)

    new_keys = cur_keys - prev_keys
    resolved_keys = prev_keys - cur_keys
    common = cur_keys & prev_keys

    changed = []
    for k in common:
        c, p = cur_i[k], prev_i[k]
        c_usd = float(c.get("estimated_monthly_usd") or 0)
        p_usd = float(p.get("estimated_monthly_usd") or 0)
        if abs(c_usd - p_usd) >= 0.01 or c.get("confidence") != p.get("confidence"):
            changed.append(
                {
                    "category": k[0],
                    "resource_id": k[1],
                    "region": k[2],
                    "previous_usd": round(p_usd, 2),
                    "current_usd": round(c_usd, 2),
                    "delta_usd": round(c_usd - p_usd, 2),
                    "previous_confidence": p.get("confidence"),
                    "current_confidence": c.get("confidence"),
                }
            )

    def _brief(keys, idx):
        rows = []
        for k in sorted(keys, key=lambda x: -float(idx[x].get("estimated_monthly_usd") or 0))[:50]:
            f = idx[k]
            rows.append(
                {
                    "category": k[0],
                    "resource_id": k[1],
                    "region": k[2],
                    "estimated_monthly_usd": float(f.get("estimated_monthly_usd") or 0),
                    "confidence": f.get("confidence"),
                }
            )
        return rows

    cur_high = float(
        (current.get("savings_breakdown") or {}).get("high_confidence_usd")
        or current.get("estimated_monthly_savings_usd")
        or 0
    )
    prev_high = float(
        (previous.get("savings_breakdown") or {}).get("high_confidence_usd")
        or previous.get("estimated_monthly_savings_usd")
        or 0
    )

    return {
        "new_count": len(new_keys),
        "resolved_count": len(resolved_keys),
        "changed_count": len(changed),
        "new": _brief(new_keys, cur_i),
        "resolved": _brief(resolved_keys, prev_i),
        "changed": sorted(changed, key=lambda x: abs(x["delta_usd"]), reverse=True)[:50],
        "high_confidence_savings_usd": {
            "previous": round(prev_high, 2),
            "current": round(cur_high, 2),
            "delta": round(cur_high - prev_high, 2),
        },
    }


def format_findings_diff_lines(diff: Dict[str, Any]) -> List[str]:
    s = diff["high_confidence_savings_usd"]
    lines = [
        f"High-confidence waste $: ${s['previous']:.2f} → ${s['current']:.2f} "
        f"(Δ ${s['delta']:.2f})",
        f"New findings: {diff['new_count']} · Resolved: {diff['resolved_count']} · "
        f"Changed $: {diff['changed_count']}",
    ]
    if diff["new"]:
        lines.append("New (top):")
        for r in diff["new"][:8]:
            lines.append(
                f"  + [{r['confidence']}] {r['category']} {r['resource_id']} "
                f"@ {r['region']} ~${r['estimated_monthly_usd']}/mo"
            )
    if diff["resolved"]:
        lines.append("Resolved (top):")
        for r in diff["resolved"][:8]:
            lines.append(
                f"  - [{r['confidence']}] {r['category']} {r['resource_id']} "
                f"@ {r['region']}"
            )
    return lines
