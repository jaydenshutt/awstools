# awstools

**Created by Jayden Shutt.**

Command-line toolkit for AWS cost visibility, waste detection, and guarded cleanup. Built for individuals and teams who manage accounts without a commercial FinOps platform.

- Analyze spend with Cost Explorer, inventory, and plain-language recommendations
- Find high-confidence waste (unattached EBS, idle EIPs, empty load balancers, and more)
- Clean up carefully with dry-run defaults, account confirmation, and audit logs
- Automate multi-account scans for weekly team reviews
- Develop and test **without AWS credentials** (`--offline` / `AWSTOOLS_OFFLINE=1`)

## Install

```bash
python -m pip install -e ".[dev]"
python -m awstools --help
python -m awstools --version
# awstools 2.3.0 - Created by Jayden Shutt
```

Python 3.9+. Prefer `python -m awstools` if the `awstools` script is not on your `PATH`.

## Documentation

| Doc | Contents |
|-----|----------|
| [docs/FIRST_RUN.md](docs/FIRST_RUN.md) | Install and first offline/live steps |
| [docs/TEAMS.md](docs/TEAMS.md) | Weekly team loop, IAM, CI, sharing, execute policy |
| [docs/OFFLINE.md](docs/OFFLINE.md) | Offline development and CI without AWS |
| [docs/SCHEMAS.md](docs/SCHEMAS.md) | `summary.json`, findings, and purge plan contracts |
| [docs/SUPPORT.md](docs/SUPPORT.md) | Support matrix |
| [SECURITY.md](SECURITY.md) | Security reporting and threat model notes |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to contribute |
| [examples/](examples/) | Config, ignore rules, accounts file, GitHub Action sample |
| [policies/](policies/) | Sample IAM policies |

## Commands

| Command | Purpose |
|---------|---------|
| `whoami` | Show account ID and caller ARN |
| `cost` | Cost Explorer analysis, inventory, anomalies, HTML/PDF/CSV reports |
| `waste` | Multi-region waste scan with confidence-scored findings |
| `s3-hygiene` | Incomplete multiparts and version bloat signals |
| `ebs-cleanup` | Unattached EBS volumes (report; optional delete) |
| `eip-release` | Unassociated Elastic IPs (report; optional release) |
| `snapshot-age` | Old snapshots (report; optional delete) |
| `purge-s3` | Empty and delete buckets (plan/dry-run by default) |
| `run` | Multi-account `cost` / `waste` from an accounts file |

### Shared flags

- `--format text|json`, `--profile`, `--region`, `--verbose` / `--quiet`
- `--offline`, `--config`, `--ignore-file`, `--redact`
- Destructive work: `--execute --confirm-account <12-digit-id>`
- Cleanup execute also needs `--from-findings` or `--resource`
- Purge: prefer `--plan` then `--plan-file` with `--execute`
- CI: `--fail-on-waste-usd` / `--fail-on-savings-usd`
- Compare: `cost --compare prior/summary.json`, `waste --compare prior/findings.json`

Exit codes: `0` ok, `1` error, `2` auth, `3` safety gate, `4` threshold exceeded, `5` partial success.

## Quick start

### Offline (no AWS account)

```bash
# PowerShell
$env:AWSTOOLS_OFFLINE = "1"

python -m awstools whoami
python -m awstools cost --output-dir ./output --export-actions actions.csv
python -m awstools waste --output-dir ./waste-out
python -m awstools purge-s3 --plan --include "tmp-*"
```

Open `./output/report.html`.

### Live read-only analysis

Enable Cost Explorer in the account, attach [policies/cost-analysis-readonly.json](policies/cost-analysis-readonly.json) (or equivalent), then:

```bash
python -m awstools whoami --profile myprofile
python -m awstools cost --profile myprofile --output-dir ./output --export-actions actions.csv
python -m awstools waste --profile myprofile --all-regions --output-dir ./waste-out
```

### Team multi-account

```bash
# Edit examples/accounts.json with your SSO profiles
python -m awstools run --accounts examples/accounts.json --output-dir ./multi --commands cost,waste
```

See [docs/TEAMS.md](docs/TEAMS.md) for a full weekly workflow.

### Guarded cleanup (examples)

```bash
# Report only
python -m awstools ebs-cleanup --profile lab --all-regions -o ./ebs-out

# Execute only after review (scoped)
python -m awstools ebs-cleanup --profile lab --execute --confirm-account 123456789012 \
  --from-findings ./ebs-out/ebs-cleanup.json

# S3 purge plan, then execute with fingerprint file
python -m awstools purge-s3 --profile lab --include "tmp-*" --plan --audit-log purge.json
python -m awstools purge-s3 --profile lab --include "tmp-*" --execute --confirm-account 123456789012 \
  --plan-file purge-plan.json
```

Protect resources with tag `awstools:protect=true`. Use [examples/ignore.json](examples/ignore.json) and [examples/awstools.toml](examples/awstools.toml) for team defaults.

## What you get from `cost`

Under `--output-dir`:

| Artifact | Description |
|----------|-------------|
| `report.html` | Executive KPIs, top actions, charts, engineer detail |
| `summary.json` | Machine-readable summary (`schema_version: 2`) |
| `actions.csv` / `.xlsx` | Prioritized recommendations (default export) |
| `assets/*.png` | Charts |
| optional `--pdf` / `--csv` | PDF and cost time series |

Includes MoM anomalies, directional Savings Plans/RI purchase-type hints, and optional Cost Explorer forecast.

## What `waste` finds

| Category | Typical confidence |
|----------|-------------------|
| Unattached EBS, unassociated EIP, idle ELB, incomplete multiparts | High |
| Old snapshots, gp2 to gp3, old AMIs, unattached ENIs, EC2 CPU rightsizing | Medium |
| NAT gateway review | Low (review only; not counted in headline savings) |

**Headline savings use High confidence only.** Medium/Low are for human review. Each finding can include an `estimate_formula`.

```bash
python -m awstools waste --compare ./last-week/findings.json -o ./this-week
```

## Safety model

- Read paths are default; deletes are never the default
- Offline mode refuses `--execute`
- Account ID confirmation for live execute
- Purge plan fingerprints; cleanup scoped to findings file or resource IDs
- Config deny lists and protect tags
- Audit/plan JSON for change records

## IAM samples

- [policies/cost-analysis-readonly.json](policies/cost-analysis-readonly.json) for cost, inventory, and waste reads
- [policies/s3-purge.json](policies/s3-purge.json) for purge (high privilege; narrow in production)

## Development

```bash
python -m pip install -e ".[dev]"
# or: pip install -r requirements-dev.txt
$env:AWSTOOLS_OFFLINE = "1"
python -m pytest -q
```

### Docker

```bash
docker build -t awstools .
docker run --rm -v ${PWD}/out:/tmp/awstools-out awstools
```

Default image command is offline cost analysis (no credentials required).

CI: [.github/workflows/ci.yml](.github/workflows/ci.yml)

## Caveats

- Savings figures are heuristics unless backed by measured sizes or CUR. Validate before buying commitments or deleting resources.
- Cost Explorer must be enabled for live cost data; data can lag after first enablement.
- S3 Object Lock, MFA Delete, and replication can block bucket deletion; errors are recorded in the audit log.
- EC2 rightsizing uses CloudWatch CPU only (Medium confidence). SP/RI coverage is directional.

## No warranty / use at your own risk

This software is provided **AS IS**, **without warranty of any kind**, express or implied, including but not limited to merchantability, fitness for a particular purpose, and noninfringement.

**You use awstools entirely at your own risk.** The author and copyright holders are not liable for any claim, damage, data loss, unexpected AWS charges, failed deletes, incorrect recommendations, or other consequences of using the tool (including destructive commands such as purge and cleanup).

Full legal terms: [LICENSE](LICENSE) (MIT). The same notice is shown in CLI help, command banners, reports, and JSON output (`no_warranty`).

## License

MIT. See [LICENSE](LICENSE). The license includes the standard disclaimer of all warranties and limitation of liability.

## Author

**Created by [Jayden Shutt](https://www.linkedin.com/in/jaydenshutt/).**

Attribution appears on `--version`, CLI help, command banners, HTML/PDF reports, and JSON `created_by`.
