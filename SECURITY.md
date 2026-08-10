# Security policy

## Supported versions

Security fixes are accepted for the latest minor release on `main`.

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| 1.x     | Best effort |
| &lt; 1.0  | No        |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security-sensitive reports.

1. Email the maintainer privately (see GitHub profile / LinkedIn on the project README), **or**
2. Use GitHub **Private vulnerability reporting** if enabled on the repository.

Include:

- Affected command(s) and flags
- Whether credentials or account data can leak
- Reproduction steps (prefer offline/`moto` fixtures)
- Impact assessment

You should receive an acknowledgment within a reasonable time. Please allow time for a fix before public disclosure.

## Threat model (summary)

| Surface | Notes |
|---------|--------|
| Credentials | Tool uses standard AWS SDK credential chain; never log secrets |
| Destructive ops | Default dry-run; `--execute` needs account confirmation; offline execute refused |
| Reports | May contain account IDs, ARNs, resource IDs - use `--redact` before sharing |
| Supply chain | Pin deps in CI; review `pyproject.toml` changes |

## What this tool will not do

- Leave AWS Organizations or delete the management account
- Create IAM users/access keys
- Purchase Savings Plans or Reserved Instances automatically
- Disable CloudTrail or GuardDuty
- Bypass Object Lock / MFA Delete (S3 deletes may fail and are audited)

## Safe defaults

- Prefer read-only IAM (`policies/cost-analysis-readonly.json`) for analysis
- Never store long-lived keys in the repo or CI logs
- Use `AWSTOOLS_OFFLINE=1` for local development without credentials
