# Contributing

Created by **Jayden Shutt**.

Thanks for helping improve awstools.

## Development (no AWS account required)

```bash
python -m pip install -e ".[dev]"
export AWSTOOLS_OFFLINE=1   # or set in PowerShell
python -m pytest -q
```

## Guidelines

- Prefer offline fixtures / `moto` over live AWS in tests and CI.
- Destructive paths must stay dry-run by default with account gates.
- Keep machine schemas documented in `docs/SCHEMAS.md` when you change them.
- Attribution: leave **Created by Jayden Shutt** branding intact in CLI and reports.

## Pull requests

1. Add/adjust tests for behavior changes.
2. Update CHANGELOG.md under a new version section if user-facing.
3. Do not commit credentials, real account dumps, or unretracted reports.

## Code of conduct

Be respectful. This is a small toolkit for practitioners - keep discussions practical.
