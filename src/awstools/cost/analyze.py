"""Orchestrate cost analysis end-to-end."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from awstools.branding import ATTRIBUTION_PLAIN, NO_WARRANTY_SHORT
from awstools.common.session import get_account_id
from awstools.cost.anomalies import detect_anomalies
from awstools.cost.commitments import fetch_ce_forecast, fetch_commitment_coverage
from awstools.cost.costs import (
    CostExplorerError,
    fetch_costs_ce,
    parse_cur_local,
    parse_cur_s3,
    prepare_timeseries,
)
from awstools.cost.inventory import inventory_resources, detect_wasted_resources
from awstools.cost.recommendations import build_recommendations
from awstools.cost.reports import (
    generate_plots,
    write_html_report,
    write_pdf_report,
    write_actions_export,
)

LOG = logging.getLogger("awstools.cost")

# Stable summary.json schema version for automation
SUMMARY_SCHEMA_VERSION = 2


@dataclass
class AnalysisConfig:
    output_dir: Path
    html_name: str = "report.html"
    pdf_name: Optional[str] = None
    csv_name: Optional[str] = None
    export_actions: Optional[str] = None
    months: int = 6
    forecast_months: int = 3
    dry_run: bool = False
    all_regions: bool = False
    regions: Optional[List[str]] = None
    concurrency: int = 6
    tag_keys: Optional[List[str]] = None
    cur_file: Optional[str] = None
    cur_s3_bucket: Optional[str] = None
    cur_prefix: Optional[str] = None
    write_html: bool = True
    anomaly_threshold_pct: float = 0.25
    warnings: List[str] = field(default_factory=list)


def run_analysis(session, config: AnalysisConfig) -> Dict[str, Any]:
    """Run full analysis and write reports. Returns a summary dict."""
    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    assets_dir = output_dir / "assets"
    warnings: List[str] = list(config.warnings or [])

    if config.dry_run:
        account_id = "000000000000"
    else:
        try:
            account_id = get_account_id(session)
        except Exception as e:
            raise RuntimeError(f"Unable to resolve AWS identity: {e}") from e

    LOG.info("Analyzing account %s (dry_run=%s)", account_id, config.dry_run)

    ce_error = None
    try:
        costs, resource_level_costs, tag_aggregates = fetch_costs_ce(
            session,
            months=config.months,
            dry_run=config.dry_run,
            tag_keys=config.tag_keys,
            raise_on_ce_error=True,
        )
    except CostExplorerError as e:
        ce_error = str(e)
        warnings.append(ce_error)
        costs, resource_level_costs, tag_aggregates = [], [], {}
        LOG.error("Continuing with inventory-only mode: %s", e)

    resources = inventory_resources(
        session,
        regions=config.regions,
        all_regions=config.all_regions,
        concurrency=config.concurrency,
        dry_run=config.dry_run,
    )
    inv_errors = resources.get("_errors") or []
    if inv_errors:
        warnings.append(f"Inventory completed with {len(inv_errors)} error(s)")

    wasted = detect_wasted_resources(
        session,
        regions=config.regions,
        all_regions=config.all_regions,
        concurrency=config.concurrency,
        dry_run=config.dry_run,
    )

    pivot = prepare_timeseries(costs)

    if config.csv_name:
        csv_path = output_dir / Path(config.csv_name).name
        if not pivot.empty:
            pivot.to_csv(csv_path)
            LOG.info("Cost time series CSV written to %s", csv_path)
        else:
            warnings.append("No cost time series to write (empty CE data)")

    latest_total = 0.0
    top_services: List = []
    if not pivot.empty:
        latest = (
            pivot.iloc[-1].drop(labels=["total"])
            if "total" in pivot.columns
            else pivot.iloc[-1]
        )
        latest_total = (
            float(pivot["total"].iloc[-1])
            if "total" in pivot.columns
            else float(latest.sum())
        )
        top = latest.sort_values(ascending=False).head(8)
        top_services = [(str(svc), float(v)) for svc, v in top.items()]

    anomalies = detect_anomalies(pivot, threshold_pct=config.anomaly_threshold_pct)
    commitments = fetch_commitment_coverage(session, dry_run=config.dry_run)
    ce_forecast = fetch_ce_forecast(
        session, months=config.forecast_months, dry_run=config.dry_run
    )

    top_resources = []
    if resource_level_costs:
        import pandas as pd

        df_res = pd.DataFrame(resource_level_costs)
        if not df_res.empty:
            df_res["date"] = pd.to_datetime(df_res["date"]).dt.to_period("M").dt.to_timestamp()
            last_date = df_res["date"].max()
            lastdf = df_res[df_res["date"] == last_date]
            topr = (
                lastdf.groupby("resource_id")["amount"]
                .sum()
                .sort_values(ascending=False)
                .head(15)
            )
            top_resources = [(rid, float(v)) for rid, v in topr.items()]

    cur_resource_costs: Dict[str, float] = {}
    if config.cur_file:
        cur_resource_costs = parse_cur_local(config.cur_file)
    elif config.cur_s3_bucket and config.cur_prefix:
        cur_resource_costs = parse_cur_s3(
            session, config.cur_s3_bucket, config.cur_prefix
        )
    if cur_resource_costs:
        cr_sorted = sorted(cur_resource_costs.items(), key=lambda x: x[1], reverse=True)[
            :20
        ]
        top_resources = [(rid, float(v)) for rid, v in cr_sorted]

    recommendations, rec_objects, executive_summary, per_service_advice, glossary = (
        build_recommendations(
            latest_total, pivot, top_services, wasted, resources
        )
    )
    if commitments.get("hint"):
        recommendations.insert(0, f"Commitments: {commitments['hint']}")
        rec_objects.insert(
            0,
            {
                "id": "commitments_hint",
                "service": "Commitments (SP/RI)",
                "estimated_monthly_savings": 0.0,
                "note": commitments["hint"],
                "source": "ce_purchase_type",
            },
        )

    plots = generate_plots(pivot, assets_dir)

    start = pivot.index[0].strftime("%Y-%m-%d") if not pivot.empty else "N/A"
    end = pivot.index[-1].strftime("%Y-%m-%d") if not pivot.empty else "N/A"
    regions_scanned = resources.get("_regions_scanned") or []
    error_count = len(inv_errors)

    display_resources = {
        k: v for k, v in resources.items() if not k.startswith("_")
    }

    # Estimated savings from rec objects
    est_savings = sum(
        float(o.get("estimated_monthly_savings") or 0) for o in (rec_objects or [])
    )

    html_path = output_dir / Path(config.html_name).name
    context = {
        "start": start,
        "end": end,
        "latest_total": latest_total,
        "top_services": top_services,
        "top_resources": top_resources,
        "tag_aggregates": tag_aggregates or {},
        "wasted_resources": wasted,
        "recommendations": recommendations,
        "rec_objects": rec_objects,
        "executive_summary": executive_summary,
        "per_service_advice": per_service_advice,
        "glossary": glossary,
        "account_id": account_id,
        "regions_scanned": len(regions_scanned),
        "error_count": error_count,
        "warnings": warnings,
        "anomalies": anomalies,
        "commitments": commitments,
        "ce_forecast": ce_forecast or {},
        "ce_error": ce_error,
        "resources_json": json.dumps(display_resources, indent=2, default=str),
        **plots,
    }

    if config.write_html:
        write_html_report(html_path, dict(context))

    actionable_rows = None
    if config.export_actions:
        actions_path = output_dir / Path(config.export_actions).name
        actionable_rows = write_actions_export(
            actions_path, rec_objects, wasted, latest_total
        )

    pdf_path = None
    if config.pdf_name:
        pdf_path = output_dir / Path(config.pdf_name).name
        try:
            write_pdf_report(
                pdf_path,
                start=start,
                end=end,
                latest_total=latest_total,
                top_services=top_services,
                recommendations=recommendations,
                plots=plots,
                resources=display_resources,
                top_resources=top_resources,
                tag_aggregates=tag_aggregates,
                wasted=wasted,
                rec_objects=rec_objects,
                executive_summary=executive_summary,
                actionable_rows=actionable_rows,
                account_id=account_id,
            )
        except Exception as e:
            LOG.error("PDF export failed: %s", e)
            warnings.append(f"PDF export failed: {e}")

    coverage = {
        "regions_requested": regions_scanned,
        "regions_count": len(regions_scanned),
        "inventory_errors": inv_errors[:50],
        "inventory_error_count": error_count,
        "cost_explorer_ok": ce_error is None and not pivot.empty,
        "cost_explorer_error": ce_error,
        "partial": bool(warnings) or error_count > 0 or ce_error is not None,
    }

    summary = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "created_by": ATTRIBUTION_PLAIN,
        "no_warranty": NO_WARRANTY_SHORT,
        "account_id": account_id,
        "latest_total": latest_total,
        "period_start": start,
        "period_end": end,
        "top_services": [{"service": s, "amount": a} for s, a in top_services],
        "recommendation_count": len(rec_objects),
        "estimated_monthly_savings_usd": round(est_savings, 2),
        "anomaly_count": len(anomalies),
        "anomalies": anomalies[:20],
        "commitments": commitments,
        "ce_forecast": ce_forecast,
        "wasted_counts": {k: len(v) for k, v in wasted.items()},
        "coverage": coverage,
        "warnings": warnings,
        "html": str(html_path) if config.write_html else None,
        "pdf": str(pdf_path) if pdf_path else None,
        "output_dir": str(output_dir),
        "dry_run": config.dry_run,
    }
    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    LOG.info("Summary written to %s", summary_path)
    LOG.info(
        "Done. Latest monthly total=$%.2f recommendations=%d anomalies=%d",
        latest_total,
        len(rec_objects),
        len(anomalies),
    )
    return summary
