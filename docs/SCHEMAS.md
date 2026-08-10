# Machine-readable schemas

## `summary.json` (cost) - schema_version 2

Required keys:

- `schema_version` (2)
- `account_id`
- `latest_total`
- `coverage` (object; includes `partial`, `cost_explorer_ok`, errors)
- `warnings` (list)
- `estimated_monthly_savings_usd`
- `anomaly_count`
- `top_services` (list of `{service, amount}`)

Optional: `diff` (from `--compare`), `ce_forecast`, `commitments`, `html`, `pdf`.

## `findings.json` - schema_version 1

Required:

- `schema_version` (1)
- `finding_count`
- `estimated_monthly_savings_usd` - **High confidence only** (headline)
- `estimated_monthly_savings_all_confidence_usd`
- `savings_breakdown`: `{high_confidence_usd, all_confidence_usd, medium_low_review_usd}`
- `findings` (list of finding rows)

Each finding row:

- `id`, `category`, `resource_id`, `region`, `action`
- `estimated_monthly_usd`, `confidence` (`High`|`Medium`|`Low`)
- `evidence`, `estimate_formula`
- `protected`, `ignored`, `ignore_reason`

## Purge plan - with fingerprint

Required:

- `account_id`, `selected_count`, `selected`, `protected`, `blast_radius`
- `plan_fingerprint` (SHA-256 over canonical selected set)

Execute should pass `--plan-file` so the fingerprint/selection can be verified.
