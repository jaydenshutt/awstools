# Using awstools with a team

Created by **Jayden Shutt**.

This guide is for small teams / platform / FinOps-minded engineers who want a **repeatable weekly loop**, not a full commercial FinOps platform.

## Roles

| Role | Typical use |
|------|-------------|
| Platform / cloud engineer | Runs scans, owns IAM roles, reviews High-confidence waste |
| App owner | Gets CSV/actions; fixes tagged resources |
| Manager | Reads HTML executive page + $ trend (treat estimates as directional) |

## Recommended weekly loop

```bash
# 1) Identity check
python -m awstools whoami --profile team-readonly

# 2) Cost briefing (share HTML or redacted JSON)
python -m awstools cost --profile team-readonly \
  --output-dir "./reports/$(date +%Y-%m-%d)/cost" \
  --export-actions actions.csv \
  --compare ./reports/last/cost/summary.json

# 3) Waste findings
python -m awstools waste --profile team-readonly --all-regions \
  --output-dir "./reports/$(date +%Y-%m-%d)/waste" \
  --compare ./reports/last/waste/findings.json

# 4) Multi-account (edit examples/accounts.json first)
python -m awstools run --accounts team-accounts.json \
  --output-dir "./reports/$(date +%Y-%m-%d)/multi" \
  --commands cost,waste
```

Copy last week’s folder to `reports/last` (or keep dated paths and pass `--compare` explicitly).

## IAM for teams

- **Analysis / waste (default):** attach `policies/cost-analysis-readonly.json` to a dedicated role.
- **Cleanup / purge:** separate break-glass role; never daily driver credentials.
- Prefer **SSO + short-lived roles** over long-lived access keys.
- Use one **read-only** profile for automation; human execute only with explicit account confirm.

## CI / automation

```yaml
# Conceptual - see examples/github-action-finops.yml
# Fail the job if high-confidence waste exceeds budget:
python -m awstools waste --fail-on-waste-usd 100 --format json -o out/waste
python -m awstools cost --fail-on-savings-usd 500 --format json -o out/cost
```

Exit codes for pipelines: see README (0/1/2/3/4/5).

## Sharing safely

```bash
python -m awstools cost --redact -o ./share
python -m awstools waste --redact -o ./share-waste
```

Do not commit raw `summary.json` / findings with production account IDs to public repos.

## Ignore / protect conventions

| Mechanism | Purpose |
|-----------|---------|
| Tag `awstools:protect=true` | Never suggest delete / skip in cleanup |
| `examples/ignore.json` | Suppress noisy categories or resource globs |
| `examples/awstools.toml` `[deny]` | Hard-block execute on accounts/buckets |
| Grace days in config | Ignore very new resources |

## Estimate honesty (say this in team reviews)

- **High confidence** waste $ is the headline number for tickets.
- Service-level “save 15% of EC2” style tips are **planning ranges**, not invoices.
- Always validate before RI/SP purchases or deletes.

## Destructive changes (team policy)

1. Report / dry-run only in the shared channel.
2. Owner reviews findings file.
3. Execute only with:
   - `--execute --confirm-account <12-digit>`
   - `--from-findings` or `--resource` for cleanup
   - `--plan-file` for purge when possible
4. Keep audit JSON for the change ticket.

## Offline demos (onboarding)

No AWS account required for training:

```bash
$env:AWSTOOLS_OFFLINE = "1"   # PowerShell
python -m awstools cost -o ./demo
python -m awstools waste -o ./demo-waste
```

## No warranty

awstools is provided **AS IS with no warranty**. Teams and individuals use it **at their own risk**, including for cost estimates and any destructive operations. See [LICENSE](../LICENSE) and the disclaimer in the root [README](../README.md).

## Support matrix

See [SUPPORT.md](SUPPORT.md). Security reports: [SECURITY.md](../SECURITY.md).
