"""Unified awstools CLI - FinOps, waste, hygiene, and guarded cleanup."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from awstools import __version__
from awstools.branding import ATTRIBUTION_PLAIN, banner_line, version_string
from awstools.common import exit_codes as ec
from awstools.common.config import DEFAULT_DETECTORS, ToolsConfig, load_config
from awstools.common.destructive import require_execute_gates
from awstools.common.diff import diff_summaries, format_diff_lines
from awstools.common.errors import AwsToolsError
from awstools.common.findings import (
    apply_filters,
    dedupe_findings,
    filter_findings_by_ids,
    findings_payload,
    findings_to_rows,
    load_findings_file,
    savings_breakdown,
)
from awstools.common.findings_diff import diff_findings, format_findings_diff_lines
from awstools.common.logging_config import setup_logging
from awstools.common.offline import env_offline, is_offline, offline_identity
from awstools.common.output import emit
from awstools.common.plan_fingerprint import verify_plan_fingerprint
from awstools.common.redact import redact_obj
from awstools.common.safety import BucketFilter
from awstools.common.session import create_session, resolve_identity


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--profile", "-p", default=None, help="AWS CLI profile name")
    p.add_argument("--region", "-r", default=None, help="Default AWS region")
    p.add_argument("--verbose", "-v", action="store_true", help="Debug logging")
    p.add_argument("--quiet", "-q", action="store_true", help="Warnings and errors only")
    p.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format (default: text)",
    )
    p.add_argument(
        "--offline",
        action="store_true",
        help="Force offline mode (no AWS calls; same as AWSTOOLS_OFFLINE=1)",
    )
    p.add_argument(
        "--config",
        default=None,
        help="Path to awstools.toml config",
    )
    p.add_argument(
        "--ignore-file",
        default=None,
        help="Path to ignore.json rules",
    )
    p.add_argument(
        "--redact",
        action="store_true",
        help="Redact account IDs/ARNs/resource IDs in JSON/text output",
    )


def _add_region_scope(p: argparse.ArgumentParser) -> None:
    p.add_argument("--all-regions", action="store_true", help="Scan all EC2 regions")
    p.add_argument(
        "--regions",
        default=None,
        help="Comma-separated regions (overrides --all-regions)",
    )
    p.add_argument("--concurrency", type=int, default=None, help="Parallel region workers")


def _add_execute_gates(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--execute",
        action="store_true",
        help="Perform destructive actions (default is dry-run / report only)",
    )
    p.add_argument(
        "--yes",
        action="store_true",
        help="Skip interactive account re-type (still needs --confirm-account)",
    )
    p.add_argument(
        "--confirm-account",
        default=None,
        metavar="ACCOUNT_ID",
        help="12-digit account ID required with --execute",
    )
    p.add_argument(
        "--from-findings",
        default=None,
        help="Only act on resource IDs listed in this findings.json",
    )
    p.add_argument(
        "--resource",
        action="append",
        default=[],
        help="Limit execute/report to these resource IDs (repeatable)",
    )


def _parse_regions(args) -> Optional[List[str]]:
    if getattr(args, "regions", None):
        return [r.strip() for r in args.regions.split(",") if r.strip()]
    return None


def _offline(args, dry_run: bool = False) -> bool:
    return is_offline(
        dry_run=dry_run or getattr(args, "dry_run", False),
        force_offline=getattr(args, "offline", False) or env_offline(),
    )


def _load_cfg(args) -> ToolsConfig:
    return load_config(
        config_path=getattr(args, "config", None),
        ignore_path=getattr(args, "ignore_file", None),
    )


def _maybe_redact(args, payload: Dict[str, Any]) -> Dict[str, Any]:
    if getattr(args, "redact", False):
        return redact_obj(payload)
    return payload


def _emit_error(args, err: Exception) -> int:
    if isinstance(err, AwsToolsError):
        payload = _maybe_redact(args, err.to_dict())
        emit(payload, getattr(args, "format", "text"), err.format_lines())
        return err.exit_code
    payload = _maybe_redact(args, {"ok": False, "error": str(err), "code": "error"})
    emit(payload, getattr(args, "format", "text"), [f"ERROR: {err}"])
    return ec.ANALYSIS_ERROR


def _write_findings_csv(path: Path, findings) -> None:
    rows = findings_to_rows(findings)
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "id",
        "category",
        "resource_id",
        "region",
        "service",
        "action",
        "estimated_monthly_usd",
        "confidence",
        "evidence",
        "estimate_formula",
        "protected",
        "ignored",
        "ignore_reason",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})


def _resolve_session_and_identity(args, *, dry_run: bool = False):
    offline = _offline(args, dry_run=dry_run)
    cfg = _load_cfg(args)
    region = args.region or cfg.default_region
    if offline:
        # Never require a real profile/credentials offline
        try:
            session = create_session(profile=None, region=region or "us-east-1")
        except Exception:
            session = create_session(region="us-east-1")
        return session, offline_identity(), True, cfg
    try:
        session = create_session(profile=args.profile, region=region)
        ident = resolve_identity(session, offline=False)
    except AwsToolsError:
        raise
    except Exception as e:
        from awstools.common.errors import classify_boto_error

        raise classify_boto_error(e) from e
    return session, ident, False, cfg


def _check_deny_account(cfg: ToolsConfig, account_id: str) -> None:
    if account_id in (cfg.deny_account_ids or []):
        raise AwsToolsError(
            f"Account {account_id} is on the deny list",
            code="deny_account",
            hint="Remove it from deny.accounts in config to proceed.",
            exit_code=ec.SAFETY_GATE,
        )


def _select_findings(args, findings, cfg: ToolsConfig):
    apply_filters(findings, cfg)
    findings = dedupe_findings(findings)
    if args.from_findings:
        loaded = load_findings_file(args.from_findings)
        ids = [f.resource_id for f in loaded] + [f.id for f in loaded]
        findings = filter_findings_by_ids(findings, ids)
    if args.resource:
        findings = filter_findings_by_ids(findings, list(args.resource))
    return findings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="awstools",
        description=(
            "AWS FinOps and guarded cleanup toolkit for teams. "
            "Offline development: --dry-run / --offline / AWSTOOLS_OFFLINE=1 (no account needed). "
            "Destructive actions require --execute --confirm-account."
        ),
        epilog=(
            f"{ATTRIBUTION_PLAIN}. "
            "Team guide: docs/TEAMS.md · Offline: docs/OFFLINE.md · First run: docs/FIRST_RUN.md"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=version_string(__version__),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    who = sub.add_parser("whoami", help="Show caller identity (offline sample with --offline)")
    _add_common(who)

    cost = sub.add_parser("cost", help="Cost analysis, anomalies, savings")
    _add_common(cost)
    _add_region_scope(cost)
    cost.add_argument("--output-dir", "-o", default=None, help="Report directory")
    cost.add_argument("--html", default="report.html")
    cost.add_argument("--no-html", action="store_true")
    cost.add_argument("--pdf", default=None)
    cost.add_argument("--csv", default=None)
    cost.add_argument("--export-actions", default="actions.csv")
    cost.add_argument("--no-export-actions", action="store_true")
    cost.add_argument("--months", type=int, default=6)
    cost.add_argument("--forecast-months", type=int, default=3)
    cost.add_argument("--dry-run", action="store_true", help="Sample data; no AWS")
    cost.add_argument("--tag-keys", default=None)
    cost.add_argument("--cur-file", default=None)
    cost.add_argument("--cur-s3-bucket", default=None)
    cost.add_argument("--cur-prefix", default=None)
    cost.add_argument("--anomaly-threshold", type=float, default=0.25)
    cost.add_argument("--fail-on-savings-usd", type=float, default=None)
    cost.add_argument(
        "--compare",
        default=None,
        help="Path to previous summary.json for offline diff",
    )

    waste = sub.add_parser("waste", help="High-confidence waste scan")
    _add_common(waste)
    _add_region_scope(waste)
    waste.add_argument("--dry-run", action="store_true")
    waste.add_argument("--output-dir", "-o", default=None)
    waste.add_argument("--fail-on-waste-usd", type=float, default=None)
    waste.add_argument("--no-s3-multipart", action="store_true")
    waste.add_argument(
        "--detectors",
        default=None,
        help=f"Comma-separated detectors (default: all). Options: {','.join(DEFAULT_DETECTORS)}",
    )
    waste.add_argument(
        "--compare",
        default=None,
        help="Path to previous findings.json for week-over-week waste diff",
    )

    purge = sub.add_parser("purge-s3", help="Empty/delete S3 buckets (dry-run default)")
    _add_common(purge)
    _add_execute_gates(purge)
    purge.add_argument("--plan", action="store_true", help="Write plan + fingerprint only")
    purge.add_argument(
        "--plan-file",
        default=None,
        help="Existing plan JSON; required fingerprint check on --execute",
    )
    purge.add_argument("--include", action="append", default=[])
    purge.add_argument("--exclude", action="append", default=[])
    purge.add_argument("--prefix", default=None)
    purge.add_argument("--allow-protected", action="store_true")
    purge.add_argument("--audit-log", default=None)
    purge.add_argument(
        "--dry-run",
        action="store_true",
        help="Offline sample plan (no AWS). Implied when --offline.",
    )

    hyg = sub.add_parser("s3-hygiene", help="S3 multipart + version bloat")
    _add_common(hyg)
    _add_execute_gates(hyg)
    hyg.add_argument("--abort-multipart", metavar="BUCKET", default=None)
    hyg.add_argument("--output-dir", "-o", default=None)
    hyg.add_argument("--dry-run", action="store_true")

    ebs = sub.add_parser("ebs-cleanup", help="Unattached EBS volumes")
    _add_common(ebs)
    _add_region_scope(ebs)
    _add_execute_gates(ebs)
    ebs.add_argument("--output-dir", "-o", default=None)
    ebs.add_argument("--fail-on-waste-usd", type=float, default=None)
    ebs.add_argument("--dry-run", action="store_true")

    eip = sub.add_parser("eip-release", help="Unassociated Elastic IPs")
    _add_common(eip)
    _add_region_scope(eip)
    _add_execute_gates(eip)
    eip.add_argument("--output-dir", "-o", default=None)
    eip.add_argument("--fail-on-waste-usd", type=float, default=None)
    eip.add_argument("--dry-run", action="store_true")

    snap = sub.add_parser("snapshot-age", help="Old EBS snapshots")
    _add_common(snap)
    _add_region_scope(snap)
    _add_execute_gates(snap)
    snap.add_argument("--older-than-days", type=int, default=90)
    snap.add_argument("--output-dir", "-o", default=None)
    snap.add_argument("--fail-on-waste-usd", type=float, default=None)
    snap.add_argument("--dry-run", action="store_true")

    run = sub.add_parser("run", help="Multi-account cost/waste from accounts file")
    _add_common(run)
    run.add_argument("--accounts", required=True)
    run.add_argument("--commands", default="cost,waste")
    run.add_argument("--output-dir", "-o", default="output-multi")
    run.add_argument("--fail-on-waste-usd", type=float, default=None)
    run.add_argument("--dry-run", action="store_true")

    return parser


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_whoami(args: argparse.Namespace) -> int:
    setup_logging(verbose=args.verbose, quiet=args.quiet)
    try:
        session, ident, offline, _cfg = _resolve_session_and_identity(args)
    except Exception as e:
        return _emit_error(args, e)
    data = {
        "ok": True,
        "account_id": ident["account_id"],
        "arn": ident["arn"],
        "profile": args.profile,
        "region": getattr(session, "region_name", None),
        "offline": offline,
        "tool": banner_line(__version__),
    }
    data = _maybe_redact(args, data)
    emit(
        data,
        args.format,
        [
            banner_line(__version__),
            f"Account: {data['account_id']}",
            f"Arn:     {data['arn']}",
            f"Profile: {args.profile or '(default)'}",
            f"Offline: {offline}",
        ],
    )
    return ec.OK


def cmd_cost(args: argparse.Namespace) -> int:
    log = setup_logging(verbose=args.verbose, quiet=args.quiet)
    from awstools.cost.analyze import AnalysisConfig, run_analysis

    try:
        session, ident, offline, cfg = _resolve_session_and_identity(
            args, dry_run=args.dry_run
        )
        _check_deny_account(cfg, ident["account_id"])
    except Exception as e:
        return _emit_error(args, e)

    out_dir = args.output_dir or cfg.output_dir
    regions = _parse_regions(args)
    all_regions = args.all_regions or cfg.all_regions
    concurrency = args.concurrency if args.concurrency is not None else cfg.concurrency
    fail_usd = (
        args.fail_on_savings_usd
        if args.fail_on_savings_usd is not None
        else cfg.fail_on_savings_usd
    )

    tag_keys = None
    if args.tag_keys:
        tag_keys = [k.strip() for k in args.tag_keys.split(",") if k.strip()]
    export_actions = None if args.no_export_actions else args.export_actions

    config = AnalysisConfig(
        output_dir=Path(out_dir),
        html_name=args.html,
        pdf_name=args.pdf,
        csv_name=args.csv,
        export_actions=export_actions,
        months=args.months,
        forecast_months=args.forecast_months,
        dry_run=offline or args.dry_run,
        all_regions=all_regions,
        regions=regions,
        concurrency=concurrency,
        tag_keys=tag_keys,
        cur_file=args.cur_file,
        cur_s3_bucket=args.cur_s3_bucket,
        cur_prefix=args.cur_prefix,
        write_html=not args.no_html,
        anomaly_threshold_pct=args.anomaly_threshold,
    )
    try:
        summary = run_analysis(session, config)
    except Exception as e:
        log.error("Cost analysis failed: %s", e)
        return _emit_error(args, e if isinstance(e, AwsToolsError) else e)

    # Confidence note: rec savings already mixed; leave as-is but add offline flag
    summary["offline"] = offline
    if args.compare:
        try:
            prev = json.loads(Path(args.compare).read_text(encoding="utf-8"))
            summary["diff"] = diff_summaries(summary, prev)
        except Exception as e:
            summary["diff_error"] = str(e)

    # Persist redacted copy optionally
    if args.redact:
        red_path = Path(out_dir) / "summary.redacted.json"
        red_path.write_text(
            json.dumps(redact_obj(summary), indent=2, default=str), encoding="utf-8"
        )
        summary["redacted_summary"] = str(red_path)

    out = _maybe_redact(args, {"ok": True, **summary})
    lines = [
        f"Account {summary['account_id']}: ${summary['latest_total']:.2f}/mo",
        f"Recommendations: {summary['recommendation_count']} · "
        f"Est. savings: ${summary.get('estimated_monthly_savings_usd', 0):.2f}/mo · "
        f"Anomalies: {summary.get('anomaly_count', 0)}"
        + (" · OFFLINE" if offline else ""),
    ]
    if summary.get("html"):
        lines.append(f"HTML: {summary['html']}")
    if summary.get("diff"):
        lines.append("Diff vs previous:")
        lines.extend("  " + x for x in format_diff_lines(summary["diff"]))
    if summary.get("warnings"):
        lines.append(f"Warnings: {len(summary['warnings'])}")
    emit(out, args.format, lines)

    code = ec.PARTIAL_SUCCESS if summary.get("coverage", {}).get("partial") else ec.OK
    if fail_usd is not None and summary.get("estimated_monthly_savings_usd", 0) >= fail_usd:
        return ec.THRESHOLD_EXCEEDED
    return code


def cmd_waste(args: argparse.Namespace) -> int:
    setup_logging(verbose=args.verbose, quiet=args.quiet)
    from awstools.waste.scan import scan_waste

    try:
        session, ident, offline, cfg = _resolve_session_and_identity(
            args, dry_run=args.dry_run
        )
        _check_deny_account(cfg, ident["account_id"])
    except Exception as e:
        return _emit_error(args, e)

    det = None
    if args.detectors:
        det = {d.strip() for d in args.detectors.split(",") if d.strip()}
    else:
        det = cfg.enabled_detectors()

    regions = _parse_regions(args)
    all_regions = args.all_regions or cfg.all_regions
    concurrency = args.concurrency if args.concurrency is not None else cfg.concurrency
    fail_usd = (
        args.fail_on_waste_usd
        if args.fail_on_waste_usd is not None
        else cfg.fail_on_waste_usd
    )

    try:
        result = scan_waste(
            session,
            regions=regions,
            all_regions=all_regions,
            concurrency=concurrency,
            dry_run=offline or args.dry_run,
            include_s3_multipart=not args.no_s3_multipart,
            detectors=det,
            config=cfg,
        )
    except Exception as e:
        return _emit_error(args, e)

    findings = result["findings"]
    payload = findings_payload(
        findings,
        account_id=ident["account_id"],
        by_category=result["by_category"],
        regions_scanned=result["regions_scanned"],
        errors=result["errors"],
        dry_run=result["dry_run"],
        offline=offline,
        partial=result.get("partial", False),
        ok=True,
    )
    # Prefer pack savings (already high-only) so headline matches scan_waste
    if "estimated_monthly_savings_usd" in result:
        payload["estimated_monthly_savings_usd"] = result["estimated_monthly_savings_usd"]
    if "estimated_monthly_savings_all_confidence_usd" in result:
        payload["estimated_monthly_savings_all_confidence_usd"] = result[
            "estimated_monthly_savings_all_confidence_usd"
        ]
    if result.get("savings_breakdown"):
        payload["savings_breakdown"] = result["savings_breakdown"]
    else:
        payload["savings_breakdown"] = savings_breakdown(findings)

    if args.compare:
        try:
            prev = json.loads(Path(args.compare).read_text(encoding="utf-8"))
            # Diff resource rows only; savings come from savings_breakdown
            payload["diff"] = diff_findings(payload, prev)
        except Exception as e:
            payload["diff_error"] = str(e)

    if args.output_dir:
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        to_write = redact_obj(payload) if args.redact else payload
        (out / "findings.json").write_text(
            json.dumps(to_write, indent=2, default=str), encoding="utf-8"
        )
        _write_findings_csv(out / "findings.csv", findings)
        if payload.get("diff"):
            (out / "findings-diff.json").write_text(
                json.dumps(payload["diff"], indent=2, default=str), encoding="utf-8"
            )

    br = payload["savings_breakdown"]
    lines = [
        f"Account {ident['account_id']}: {payload['finding_count']} findings"
        + (" [OFFLINE]" if offline else ""),
        f"High-confidence savings: ${br['high_confidence_usd']:.2f}/mo "
        f"(all confidences: ${br['all_confidence_usd']:.2f}; "
        f"review medium/low: ${br['medium_low_review_usd']:.2f})",
        f"By category: {result['by_category']}",
    ]
    for row in payload["findings"][:15]:
        if row.get("ignored") or row.get("protected"):
            continue
        formula = row.get("estimate_formula") or ""
        extra = f" [{formula}]" if formula else ""
        lines.append(
            f"  [{row['confidence']}] {row['category']}: {row['resource_id']} "
            f"@ {row['region']} ~${row['estimated_monthly_usd']}/mo{extra}"
        )
    if payload.get("diff"):
        lines.append("Waste diff vs previous:")
        lines.extend("  " + x for x in format_findings_diff_lines(payload["diff"]))
    emit(_maybe_redact(args, payload), args.format, lines)

    if fail_usd is not None and br["high_confidence_usd"] >= fail_usd:
        return ec.THRESHOLD_EXCEEDED
    if result.get("errors"):
        return ec.PARTIAL_SUCCESS
    return ec.OK


def cmd_purge(args: argparse.Namespace) -> int:
    log = setup_logging(verbose=args.verbose, quiet=args.quiet)
    from awstools.purge.s3 import build_purge_plan, purge_buckets

    offline = _offline(args, dry_run=args.dry_run or args.plan)
    try:
        session, ident, offline, cfg = _resolve_session_and_identity(
            args, dry_run=offline
        )
        account_id = ident["account_id"]
        caller_arn = ident["arn"]
        _check_deny_account(cfg, account_id)
    except Exception as e:
        return _emit_error(args, e)

    if not offline:
        print(
            f"\n=== ACTIVE IDENTITY ===\nAccount: {account_id}\nArn:     {caller_arn}\n",
            file=sys.stderr,
        )
    else:
        print("\n=== OFFLINE / SAMPLE PLAN (no AWS calls) ===\n", file=sys.stderr)

    bucket_filter = BucketFilter(
        include=list(args.include or []),
        exclude=list(args.exclude or []) + list(cfg.deny_bucket_globs or []),
        require_prefix=args.prefix,
        allow_protected=args.allow_protected,
    )

    # Load prior plan if provided
    prior_plan = None
    if args.plan_file:
        prior_plan = json.loads(Path(args.plan_file).read_text(encoding="utf-8"))

    try:
        plan = build_purge_plan(
            session,
            bucket_filter,
            account_id=account_id,
            caller_arn=caller_arn,
            estimate_objects=not offline,
            offline=offline,
        )
    except Exception as e:
        return _emit_error(args, e)

    audit = args.audit_log or f"purge-audit-{account_id}.json"
    audit_path = Path(audit)
    plan_path = audit_path.with_name(audit_path.stem + "-plan.json")
    plan_path.write_text(json.dumps(plan, indent=2, default=str), encoding="utf-8")

    plan_lines = [
        f"PURGE PLAN for account {account_id}"
        + (" [OFFLINE SAMPLE]" if offline else ""),
        f"Fingerprint: {plan.get('plan_fingerprint', '')[:16]}…",
        f"Total buckets: {plan['total_buckets']} | Selected: {plan['selected_count']} | "
        f"Protected: {plan['protected_count']} | Filtered: {plan['filtered_out_count']}",
        f"Blast radius: {plan['blast_radius']}",
    ]
    for row in plan["selected"][:30]:
        plan_lines.append(
            f"  - {row['name']}  region={row['region']}  "
            f"versioned={row['versioned']}  objects~{row['object_estimate']}"
        )

    if args.plan or (offline and not args.execute):
        # Plan-only path (always for offline unless someone insists execute - block execute offline)
        emit(
            _maybe_redact(
                args,
                {
                    "ok": True,
                    "mode": "PLAN",
                    "account_id": account_id,
                    "plan": plan,
                    "plan_log": str(plan_path),
                    "offline": offline,
                },
            ),
            args.format,
            plan_lines + [f"Plan written: {plan_path}"],
        )
        if offline and args.execute:
            return _emit_error(
                args,
                AwsToolsError(
                    "Refusing --execute in offline mode",
                    code="offline_execute",
                    hint="Unset AWSTOOLS_OFFLINE and omit --offline/--dry-run for live execute.",
                    exit_code=ec.SAFETY_GATE,
                ),
            )
        return ec.OK

    if args.execute:
        if offline:
            return _emit_error(
                args,
                AwsToolsError(
                    "Refusing --execute in offline mode",
                    code="offline_execute",
                    exit_code=ec.SAFETY_GATE,
                ),
            )
        # Fingerprint gate: compare to --plan-file if provided, else require fingerprint on fresh plan
        check_plan = prior_plan or plan
        if prior_plan:
            # Recompute current selection fingerprint must match prior
            ok_fp, msg = verify_plan_fingerprint(prior_plan)
            if not ok_fp:
                return _emit_error(
                    args,
                    AwsToolsError(msg, code="plan_fingerprint", exit_code=ec.SAFETY_GATE),
                )
            if fingerprint_selected_names(prior_plan) != fingerprint_selected_names(plan):
                return _emit_error(
                    args,
                    AwsToolsError(
                        "Live bucket selection no longer matches --plan-file",
                        code="plan_stale",
                        hint="Re-run --plan and review before --execute.",
                        exit_code=ec.SAFETY_GATE,
                    ),
                )
        else:
            log.warning(
                "Executing without --plan-file; fingerprint of current plan is %s",
                plan.get("plan_fingerprint", "")[:16],
            )

        ok, msg, code = require_execute_gates(
            execute=True,
            confirm_account=args.confirm_account,
            actual_account_id=account_id,
            yes=args.yes,
            prompt_label="S3 buckets and all their objects",
        )
        if not ok:
            return _emit_error(
                args, AwsToolsError(msg, code="safety_gate", exit_code=code)
            )

    if args.format == "text":
        for line in plan_lines:
            print(line)

    try:
        result = purge_buckets(
            session,
            bucket_filter=bucket_filter,
            dry_run=not args.execute,
            account_id=account_id,
            caller_arn=caller_arn,
            plan_only=False,
        )
    except Exception as e:
        return _emit_error(args, e)

    result.write_audit_log(audit_path)
    errors = sum(len(o.errors) for o in result.outcomes)
    mode = "EXECUTED" if args.execute else "DRY-RUN"
    payload = {
        "ok": (errors == 0) or (not args.execute),
        "mode": mode,
        "account_id": account_id,
        "plan": plan,
        "result": result.to_dict(),
        "audit_log": str(audit_path),
        "plan_log": str(plan_path),
        "offline": offline,
    }
    lines = [
        f"[{mode}] account={account_id} selected={len(result.selected)} errors={errors}",
        f"Audit: {audit_path}",
        f"Plan:  {plan_path}",
    ]
    if not args.execute:
        lines.append(
            f"No deletions. Execute: --execute --confirm-account {account_id} "
            f"--plan-file {plan_path}"
        )
    emit(_maybe_redact(args, payload), args.format, lines)
    if errors and args.execute:
        return ec.ANALYSIS_ERROR
    return ec.OK


def fingerprint_selected_names(plan: Dict[str, Any]) -> tuple:
    return tuple(sorted(r.get("name") for r in (plan.get("selected") or [])))


def _cleanup_report(
    args,
    findings,
    account_id: str,
    offline: bool,
    name: str,
    action_result: Optional[Dict] = None,
) -> int:
    br = savings_breakdown(findings)
    payload = findings_payload(
        findings,
        account_id=account_id,
        offline=offline,
        ok=True,
        action=action_result,
    )
    payload["estimated_monthly_savings_usd"] = br["high_confidence_usd"]
    if args.output_dir:
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        to_write = redact_obj(payload) if args.redact else payload
        (out / f"{name}.json").write_text(
            json.dumps(to_write, indent=2, default=str), encoding="utf-8"
        )
        _write_findings_csv(out / f"{name}.csv", findings)
    lines = [
        f"{name} account {account_id}: {len(findings)} findings "
        f"high~${br['high_confidence_usd']:.2f}/mo"
        + (" [OFFLINE]" if offline else ""),
    ]
    for row in payload["findings"][:20]:
        if row.get("ignored") or row.get("protected"):
            continue
        lines.append(
            f"  [{row['confidence']}] {row['resource_id']} @ {row['region']} "
            f"~${row['estimated_monthly_usd']}"
        )
    emit(_maybe_redact(args, payload), args.format, lines)
    fail = getattr(args, "fail_on_waste_usd", None)
    if fail is not None and br["high_confidence_usd"] >= fail:
        return ec.THRESHOLD_EXCEEDED
    if action_result and action_result.get("errors"):
        return ec.ANALYSIS_ERROR
    return ec.OK


def cmd_s3_hygiene(args: argparse.Namespace) -> int:
    setup_logging(verbose=args.verbose, quiet=args.quiet)
    from awstools.cleanup.s3_hygiene import abort_incomplete_multiparts, scan_s3_hygiene

    try:
        session, ident, offline, cfg = _resolve_session_and_identity(
            args, dry_run=args.dry_run
        )
        _check_deny_account(cfg, ident["account_id"])
    except Exception as e:
        return _emit_error(args, e)

    if args.abort_multipart:
        if offline:
            result = {
                "bucket": args.abort_multipart,
                "aborted": 3,
                "dry_run": True,
                "errors": [],
                "offline": True,
            }
            emit(
                _maybe_redact(args, {"ok": True, "account_id": ident["account_id"], **result}),
                args.format,
                [f"[OFFLINE] would abort multiparts in {args.abort_multipart}: 3"],
            )
            return ec.OK
        if args.execute:
            ok, msg, code = require_execute_gates(
                execute=True,
                confirm_account=args.confirm_account,
                actual_account_id=ident["account_id"],
                yes=args.yes,
                prompt_label=f"multipart uploads in s3://{args.abort_multipart}",
            )
            if not ok:
                return _emit_error(
                    args, AwsToolsError(msg, code="safety_gate", exit_code=code)
                )
        result = abort_incomplete_multiparts(
            session, args.abort_multipart, dry_run=not args.execute
        )
        emit(
            _maybe_redact(args, {"ok": True, "account_id": ident["account_id"], **result}),
            args.format,
            [
                f"Bucket {args.abort_multipart}: aborted={result['aborted']} "
                f"dry_run={result['dry_run']}"
            ],
        )
        return ec.OK if not result["errors"] else ec.ANALYSIS_ERROR

    result = scan_s3_hygiene(session, offline=offline)
    findings = _select_findings(args, result["findings"], cfg)
    return _cleanup_report(
        args, findings, ident["account_id"], offline, "s3-hygiene"
    )


def cmd_ebs_cleanup(args: argparse.Namespace) -> int:
    setup_logging(verbose=args.verbose, quiet=args.quiet)
    from awstools.cleanup.ebs import delete_volumes, find_unattached_volumes

    try:
        session, ident, offline, cfg = _resolve_session_and_identity(
            args, dry_run=args.dry_run
        )
        _check_deny_account(cfg, ident["account_id"])
    except Exception as e:
        return _emit_error(args, e)

    findings = find_unattached_volumes(
        session,
        regions=_parse_regions(args),
        all_regions=args.all_regions or cfg.all_regions,
        offline=offline,
    )
    findings = _select_findings(args, findings, cfg)

    if args.execute:
        if offline:
            return _emit_error(
                args,
                AwsToolsError(
                    "Refusing --execute in offline mode",
                    code="offline_execute",
                    exit_code=ec.SAFETY_GATE,
                ),
            )
        if not args.from_findings and not args.resource:
            return _emit_error(
                args,
                AwsToolsError(
                    "--execute requires --from-findings FILE or --resource ID",
                    code="execute_scope",
                    hint="Generate a report first, then execute only reviewed IDs.",
                    exit_code=ec.SAFETY_GATE,
                ),
            )
        ok, msg, code = require_execute_gates(
            execute=True,
            confirm_account=args.confirm_account,
            actual_account_id=ident["account_id"],
            yes=args.yes,
            prompt_label=f"{len(findings)} unattached EBS volume(s)",
        )
        if not ok:
            return _emit_error(
                args, AwsToolsError(msg, code="safety_gate", exit_code=code)
            )
        action = delete_volumes(session, findings, dry_run=False)
    else:
        action = delete_volumes(session, findings, dry_run=True)

    return _cleanup_report(
        args, findings, ident["account_id"], offline, "ebs-cleanup", action
    )


def cmd_eip_release(args: argparse.Namespace) -> int:
    setup_logging(verbose=args.verbose, quiet=args.quiet)
    from awstools.cleanup.eip import find_unassociated_eips, release_eips

    try:
        session, ident, offline, cfg = _resolve_session_and_identity(
            args, dry_run=args.dry_run
        )
        _check_deny_account(cfg, ident["account_id"])
    except Exception as e:
        return _emit_error(args, e)

    findings = find_unassociated_eips(
        session,
        regions=_parse_regions(args),
        all_regions=args.all_regions or cfg.all_regions,
        offline=offline,
    )
    findings = _select_findings(args, findings, cfg)

    if args.execute:
        if offline:
            return _emit_error(
                args,
                AwsToolsError(
                    "Refusing --execute in offline mode",
                    code="offline_execute",
                    exit_code=ec.SAFETY_GATE,
                ),
            )
        if not args.from_findings and not args.resource:
            return _emit_error(
                args,
                AwsToolsError(
                    "--execute requires --from-findings FILE or --resource ID",
                    code="execute_scope",
                    exit_code=ec.SAFETY_GATE,
                ),
            )
        ok, msg, code = require_execute_gates(
            execute=True,
            confirm_account=args.confirm_account,
            actual_account_id=ident["account_id"],
            yes=args.yes,
            prompt_label=f"{len(findings)} Elastic IP(s)",
        )
        if not ok:
            return _emit_error(
                args, AwsToolsError(msg, code="safety_gate", exit_code=code)
            )
        action = release_eips(session, findings, dry_run=False)
    else:
        action = release_eips(session, findings, dry_run=True)

    return _cleanup_report(
        args, findings, ident["account_id"], offline, "eip-release", action
    )


def cmd_snapshot_age(args: argparse.Namespace) -> int:
    setup_logging(verbose=args.verbose, quiet=args.quiet)
    from awstools.cleanup.snapshots import delete_snapshots, find_old_snapshots

    try:
        session, ident, offline, cfg = _resolve_session_and_identity(
            args, dry_run=args.dry_run
        )
        _check_deny_account(cfg, ident["account_id"])
    except Exception as e:
        return _emit_error(args, e)

    findings = find_old_snapshots(
        session,
        older_than_days=args.older_than_days,
        regions=_parse_regions(args),
        all_regions=args.all_regions or cfg.all_regions,
        offline=offline,
    )
    findings = _select_findings(args, findings, cfg)

    if args.execute:
        if offline:
            return _emit_error(
                args,
                AwsToolsError(
                    "Refusing --execute in offline mode",
                    code="offline_execute",
                    exit_code=ec.SAFETY_GATE,
                ),
            )
        if not args.from_findings and not args.resource:
            return _emit_error(
                args,
                AwsToolsError(
                    "--execute requires --from-findings FILE or --resource ID",
                    code="execute_scope",
                    exit_code=ec.SAFETY_GATE,
                ),
            )
        ok, msg, code = require_execute_gates(
            execute=True,
            confirm_account=args.confirm_account,
            actual_account_id=ident["account_id"],
            yes=args.yes,
            prompt_label=f"{len(findings)} old snapshot(s)",
        )
        if not ok:
            return _emit_error(
                args, AwsToolsError(msg, code="safety_gate", exit_code=code)
            )
        action = delete_snapshots(session, findings, dry_run=False)
    else:
        action = delete_snapshots(session, findings, dry_run=True)

    return _cleanup_report(
        args, findings, ident["account_id"], offline, "snapshot-age", action
    )


def cmd_run(args: argparse.Namespace) -> int:
    log = setup_logging(verbose=args.verbose, quiet=args.quiet)
    from awstools.common.accounts import load_accounts_file

    offline = _offline(args, dry_run=args.dry_run)
    try:
        targets = load_accounts_file(args.accounts)
    except Exception as e:
        return _emit_error(args, e)

    commands = [c.strip() for c in args.commands.split(",") if c.strip()]
    base = Path(args.output_dir)
    base.mkdir(parents=True, exist_ok=True)
    results: List[Dict[str, Any]] = []
    worst_code = ec.OK
    max_waste = 0.0

    for t in targets:
        label = t.label()
        out_dir = base / label
        out_dir.mkdir(parents=True, exist_ok=True)
        entry: Dict[str, Any] = {
            "account_label": label,
            "profile": t.profile,
            "commands": {},
        }
        log.info("=== Target: %s ===", label)

        for cmd in commands:
            argv = [cmd, "--format", "json", "--quiet", "--output-dir"]
            if cmd == "cost":
                argv.append(str(out_dir / "cost"))
            else:
                argv.append(str(out_dir / cmd))
            if t.profile and not offline:
                argv.extend(["--profile", t.profile])
            if t.region:
                argv.extend(["--region", t.region])
            if t.regions:
                argv.extend(["--regions", ",".join(t.regions)])
            elif t.all_regions:
                argv.append("--all-regions")
            if offline or args.dry_run:
                argv.append("--dry-run")
            if args.offline or env_offline():
                argv.append("--offline")
            if args.config:
                argv.extend(["--config", args.config])
            if args.redact:
                argv.append("--redact")
            code = main(argv)
            summary = {}
            if cmd == "cost":
                sp = out_dir / "cost" / "summary.json"
                if sp.exists():
                    summary = json.loads(sp.read_text(encoding="utf-8"))
            elif cmd == "waste":
                fp = out_dir / "waste" / "findings.json"
                if fp.exists():
                    summary = json.loads(fp.read_text(encoding="utf-8"))
                    max_waste = max(
                        max_waste,
                        float(summary.get("estimated_monthly_savings_usd") or 0),
                    )
            entry["commands"][cmd] = {"exit_code": code, "summary": summary}
            if code not in (ec.OK, ec.PARTIAL_SUCCESS) and code > worst_code:
                worst_code = code
        results.append(entry)

    rollup = {
        "ok": True,
        "accounts": results,
        "max_high_confidence_waste_usd": max_waste,
        "output_dir": str(base),
        "offline": offline,
    }
    (base / "rollup.json").write_text(
        json.dumps(redact_obj(rollup) if args.redact else rollup, indent=2, default=str),
        encoding="utf-8",
    )
    emit(
        _maybe_redact(args, rollup),
        args.format,
        [
            f"Multi-account run: {len(results)} target(s) → {base}",
            f"Max high-confidence waste: ${max_waste:.2f}/mo",
            f"Rollup: {base / 'rollup.json'}",
        ],
    )
    fail = args.fail_on_waste_usd
    if fail is not None and max_waste >= fail:
        return ec.THRESHOLD_EXCEEDED
    return worst_code if worst_code else ec.OK


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Attribution banner on stderr for interactive team runs (not quiet/json)
    if (
        getattr(args, "format", "text") == "text"
        and not getattr(args, "quiet", False)
        and args.command
    ):
        print(banner_line(__version__), file=sys.stderr)

    dispatch = {
        "whoami": cmd_whoami,
        "cost": cmd_cost,
        "waste": cmd_waste,
        "purge-s3": cmd_purge,
        "s3-hygiene": cmd_s3_hygiene,
        "ebs-cleanup": cmd_ebs_cleanup,
        "eip-release": cmd_eip_release,
        "snapshot-age": cmd_snapshot_age,
        "run": cmd_run,
    }
    fn = dispatch.get(args.command)
    if not fn:
        parser.print_help()
        return ec.ANALYSIS_ERROR
    try:
        return fn(args)
    except AwsToolsError as e:
        return _emit_error(args, e)
    except Exception as e:
        return _emit_error(args, e)


if __name__ == "__main__":
    sys.exit(main())
