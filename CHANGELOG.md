# Changelog

## 2.3.0 - team finish + attribution

- **Created by Jayden Shutt** on run: `--version`, help epilog, stderr banner, JSON `created_by`, HTML/PDF
- Team guide: `docs/TEAMS.md` (weekly loop, IAM, CI, sharing, execute policy)
- `CONTRIBUTING.md`
- `waste --compare previous/findings.json` week-over-week diff (+ `findings-diff.json`)
- HTML “How estimates work” transparency section
- Legacy folder READMEs marked deprecated

## 2.2.0 - packaging, CI, HTML v2, moto, rightsizing

- HTML executive report redesign (KPIs, top actions, engineer appendix)
- Optional `ec2_rightsizing` waste detector (CloudWatch CPU; Medium confidence)
- `moto` integration tests for S3 plan, EBS, EIP
- GitHub Actions CI (pytest + offline smoke + twine check)
- Dockerfile (offline default CMD / healthcheck)
- `SECURITY.md`, `MANIFEST.in`, `requirements-dev.txt` + lock snapshot
- PyPI metadata polish (`pyproject.toml` classifiers/keywords)
- Fix non-pageable `describe_addresses` usage

## 2.1.0 - offline polish (no AWS required for development)

- `AWSTOOLS_OFFLINE` / `--offline` / dry-run parity for all commands
- Classified auth/CE/throttle errors with remediation hints
- Config (`awstools.toml`) + ignore.json + deny lists
- Detector toggles (`--detectors`)
- Findings: schema v1, dedupe, grace days, estimate_formula, high-confidence headline totals
- Purge plan fingerprint + `--plan-file` verify; offline sample plan
- Cleanup `--execute` requires `--from-findings` or `--resource`
- `--compare` summary diff · `--redact` for shareable output
- Docs: OFFLINE.md, SCHEMAS.md · examples config/ignore
- Contract tests for schemas and offline CLI paths

## 2.0.0 - local polish (Phases 1-5)

### Phase 1 - Trust & first-run
- `docs/FIRST_RUN.md`, richer root README
- Cost Explorer failures surface as explicit warnings/errors (not silent $0)
- Stable `summary.json` with `schema_version: 2` and coverage block
- Default actionable export for `cost`
- HTML coverage, warnings, anomaly, and commitment sections

### Phase 2 - Waste pack
- New `awstools waste` with multi-region detectors:
  unattached EBS, unassociated EIP, idle ELB, multiparts, old snapshots,
  gp2→gp3, old AMIs, NAT review, unattached ENIs
- Normalized `Finding` model + CSV/JSON export
- Honor `awstools:protect=true`

### Phase 3 - Workflow / automation
- `--format json|text` on all commands
- Exit codes: 0/1/2/3/4/5
- `--fail-on-waste-usd` / `--fail-on-savings-usd`
- `awstools run --accounts` multi-profile orchestrator (JSON + simple YAML)
- Examples: `accounts.json`, `accounts.yaml`, GitHub Action workflow

### Phase 4 - Cleanup suite
- `s3-hygiene` (multipart + version bloat; optional abort)
- `ebs-cleanup`, `eip-release`, `snapshot-age`
- Shared execute chassis: dry-run default, `--confirm-account`, audit-friendly JSON
- `purge-s3 --plan` blast-radius plan with object estimates

### Phase 5 - Deeper FinOps signals
- MoM anomaly detection
- CE purchase-type commitment coverage hint (SP/RI directional)
- Optional `GetCostForecast` integration into reports

### Packaging
- `python -m awstools` entry (`__main__.py`)
- Version **2.0.0**

## 1.0.0

Initial unified package: `cost`, `purge-s3`, `whoami`, safety rails, tests.
