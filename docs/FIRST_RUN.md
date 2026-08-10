# First run (5 minutes)

## No warranty

This tool is provided **AS IS**, without warranty of any kind. You use it at your own risk (including any AWS charges or data loss from cleanup/purge). See [LICENSE](../LICENSE).

## 1. Install

```bash
cd awstools
python -m pip install -e ".[dev]"
```

On Windows Store Python, `awstools` may not be on `PATH`. Always works:

```bash
python -m awstools --help
```

## 2. Demo without AWS (recommended for development)

No account required. Prefer offline mode while developing:

```bash
# PowerShell
$env:AWSTOOLS_OFFLINE = "1"

python -m awstools whoami
python -m awstools cost --output-dir ./output
python -m awstools waste --output-dir ./waste-out --format json
python -m awstools purge-s3 --plan --include "tmp-*"
```

Or pass `--dry-run` / `--offline` per command. See [OFFLINE.md](OFFLINE.md).

Open `./output/report.html` in a browser.

Schemas: [SCHEMAS.md](SCHEMAS.md).

## 3. Point at a real account

```bash
aws sso login --profile myprofile   # if using SSO
python -m awstools whoami --profile myprofile
```

**Cost Explorer** must be enabled in the account (Billing → Cost Explorer). After first enablement, data can lag ~24 hours.

Attach a read-only policy similar to [`policies/cost-analysis-readonly.json`](../policies/cost-analysis-readonly.json).

```bash
python -m awstools cost --profile myprofile --output-dir ./output --export-actions actions.csv
python -m awstools waste --profile myprofile --all-regions --output-dir ./waste-out
```

## 4. Safety rules for cleanup

Every destructive command defaults to **dry-run**:

| Command | What it does on dry-run | Execute |
|---------|-------------------------|---------|
| `purge-s3` | Plan + blast radius | `--execute --confirm-account 12digits` |
| `ebs-cleanup` | List unattached volumes | same gates |
| `eip-release` | List unassociated EIPs | same gates |
| `snapshot-age` | List old snapshots | same gates |
| `s3-hygiene --abort-multipart B` | Count multiparts | same gates |

Protect resources with tag: `awstools:protect=true`.

## 5. Multi-account

Copy `examples/accounts.json`, edit profiles, then:

```bash
python -m awstools run --accounts examples/accounts.json --output-dir ./multi --commands cost,waste
```

## 6. CI exit codes

| Code | Meaning |
|------|---------|
| 0 | OK |
| 1 | Analysis / API error |
| 2 | Auth / identity error |
| 3 | Safety gate failed |
| 4 | Threshold exceeded (`--fail-on-waste-usd` / `--fail-on-savings-usd`) |
| 5 | Partial success (coverage gaps / non-fatal errors) |
