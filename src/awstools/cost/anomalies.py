"""Simple month-over-month spend anomaly detection."""

from __future__ import annotations

from typing import Any, Dict, List

import pandas as pd


def detect_anomalies(pivot: pd.DataFrame, threshold_pct: float = 0.25) -> List[Dict[str, Any]]:
    """
    Flag months / services where MoM change exceeds threshold.

    Returns list of {type, service, month, prev, curr, change_pct, message}.
    """
    anomalies: List[Dict[str, Any]] = []
    if pivot is None or pivot.empty or len(pivot) < 2:
        return anomalies

    # Total MoM
    if "total" in pivot.columns:
        totals = pivot["total"]
        for i in range(1, len(totals)):
            prev, curr = float(totals.iloc[i - 1]), float(totals.iloc[i])
            if prev <= 0:
                continue
            change = (curr - prev) / prev
            if abs(change) >= threshold_pct:
                anomalies.append(
                    {
                        "type": "total_mom",
                        "service": "TOTAL",
                        "month": str(totals.index[i].date()),
                        "prev": round(prev, 2),
                        "curr": round(curr, 2),
                        "change_pct": round(change * 100, 1),
                        "message": (
                            f"Total spend {'rose' if change > 0 else 'fell'} "
                            f"{abs(change)*100:.1f}% MoM "
                            f"(${prev:.2f} → ${curr:.2f})"
                        ),
                    }
                )

    services = [c for c in pivot.columns if c != "total"]
    for svc in services:
        series = pivot[svc]
        for i in range(1, len(series)):
            prev, curr = float(series.iloc[i - 1]), float(series.iloc[i])
            # ignore tiny absolute noise
            if prev < 5 and curr < 5:
                continue
            if prev <= 0:
                if curr >= 20:
                    anomalies.append(
                        {
                            "type": "new_service_spend",
                            "service": svc,
                            "month": str(series.index[i].date()),
                            "prev": 0.0,
                            "curr": round(curr, 2),
                            "change_pct": None,
                            "message": f"New/renewed spend on {svc}: ${curr:.2f}",
                        }
                    )
                continue
            change = (curr - prev) / prev
            if abs(change) >= threshold_pct and abs(curr - prev) >= 10:
                anomalies.append(
                    {
                        "type": "service_mom",
                        "service": svc,
                        "month": str(series.index[i].date()),
                        "prev": round(prev, 2),
                        "curr": round(curr, 2),
                        "change_pct": round(change * 100, 1),
                        "message": (
                            f"{svc}: {change*100:+.1f}% MoM "
                            f"(${prev:.2f} → ${curr:.2f})"
                        ),
                    }
                )

    # Keep most recent / largest absolute moves
    anomalies.sort(key=lambda a: abs(a.get("curr", 0) - a.get("prev", 0)), reverse=True)
    return anomalies[:40]
