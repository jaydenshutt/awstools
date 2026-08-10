"""Compare cost summary.json artifacts (offline)."""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def diff_summaries(current: Dict[str, Any], previous: Dict[str, Any]) -> Dict[str, Any]:
    """Produce a structured diff between two cost summary documents."""
    cur_total = float(current.get("latest_total") or 0)
    prev_total = float(previous.get("latest_total") or 0)
    delta = cur_total - prev_total
    pct = (delta / prev_total * 100.0) if prev_total else None

    def _svc_map(summary: Dict[str, Any]) -> Dict[str, float]:
        out = {}
        for item in summary.get("top_services") or []:
            if isinstance(item, dict):
                out[str(item.get("service"))] = float(item.get("amount") or 0)
            elif isinstance(item, (list, tuple)) and len(item) >= 2:
                out[str(item[0])] = float(item[1])
        return out

    cur_svc = _svc_map(current)
    prev_svc = _svc_map(previous)
    keys = set(cur_svc) | set(prev_svc)
    service_deltas = []
    for k in sorted(keys, key=lambda x: abs(cur_svc.get(x, 0) - prev_svc.get(x, 0)), reverse=True):
        c, p = cur_svc.get(k, 0.0), prev_svc.get(k, 0.0)
        if abs(c - p) < 0.01:
            continue
        service_deltas.append(
            {
                "service": k,
                "previous": round(p, 2),
                "current": round(c, 2),
                "delta": round(c - p, 2),
            }
        )

    cur_save = float(current.get("estimated_monthly_savings_usd") or 0)
    prev_save = float(previous.get("estimated_monthly_savings_usd") or 0)

    return {
        "account_id": current.get("account_id") or previous.get("account_id"),
        "previous_account_id": previous.get("account_id"),
        "latest_total": {
            "previous": round(prev_total, 2),
            "current": round(cur_total, 2),
            "delta": round(delta, 2),
            "delta_pct": round(pct, 2) if pct is not None else None,
        },
        "estimated_savings_usd": {
            "previous": round(prev_save, 2),
            "current": round(cur_save, 2),
            "delta": round(cur_save - prev_save, 2),
        },
        "service_deltas": service_deltas[:20],
        "anomaly_count": {
            "previous": previous.get("anomaly_count"),
            "current": current.get("anomaly_count"),
        },
    }


def format_diff_lines(diff: Dict[str, Any]) -> List[str]:
    lt = diff["latest_total"]
    lines = [
        f"Total: ${lt['previous']:.2f} → ${lt['current']:.2f} "
        f"(Δ ${lt['delta']:.2f}"
        + (f", {lt['delta_pct']}%" if lt.get("delta_pct") is not None else "")
        + ")",
    ]
    es = diff["estimated_savings_usd"]
    lines.append(
        f"Est. high-confidence savings: ${es['previous']:.2f} → ${es['current']:.2f}"
    )
    if diff["service_deltas"]:
        lines.append("Top service changes:")
        for s in diff["service_deltas"][:8]:
            lines.append(
                f"  {s['service']}: ${s['previous']:.2f} → ${s['current']:.2f} (Δ ${s['delta']:.2f})"
            )
    return lines
