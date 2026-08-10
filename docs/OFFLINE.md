# Offline development (no AWS account)

Development and CI never need live AWS credentials.

## Ways to stay offline

| Mechanism | Effect |
|-----------|--------|
| `--dry-run` | Sample data for that command |
| `--offline` | Force offline identity + sample paths |
| `AWSTOOLS_OFFLINE=1` | Env-wide offline (recommended for local dev shells) |

```bash
# PowerShell
$env:AWSTOOLS_OFFLINE = "1"
python -m awstools whoami
python -m awstools cost --output-dir ./output
python -m awstools waste --output-dir ./waste-out
python -m awstools purge-s3 --plan --include "tmp-*"
python -m awstools ebs-cleanup
python -m awstools run --accounts examples/accounts.json -o ./multi --dry-run
```

## Guarantees

- **`--execute` is refused** while offline (safety).
- Offline purge produces a **sample plan + fingerprint** only.
- Exit codes and JSON schemas match live mode as closely as possible.
- Use fixtures under `tests/fixtures/` and `pytest` for regressions.

## Mocked failure UX

Errors are classified into codes such as:

- `auth_expired` → run `aws sso login`
- `auth_missing` → configure profile or stay offline
- `ce_not_enabled` / `ce_unavailable` → enable Cost Explorer
- `access_denied` → attach sample IAM policy
- `throttled` → lower concurrency

These are exercised via unit tests without AWS.

## Config without AWS

```bash
python -m awstools waste --offline --config examples/awstools.toml --ignore-file examples/ignore.json
```
