# Support matrix

| Item | Supported |
|------|-----------|
| Python | 3.10-3.13 (3.9 best-effort) |
| OS | Windows, macOS, Linux |
| AWS partition | Commercial (`aws`) best-effort; GovCloud/China untested |
| Live AWS | Optional - not required for development or CI |
| Offline | `--offline`, `--dry-run`, `AWSTOOLS_OFFLINE=1` |

## Install targets

| Method | Status |
|--------|--------|
| `pip install -e .` from source | Primary |
| Docker image (local build) | Supported via `Dockerfile` |
| PyPI | Ready to publish when you choose (`python -m build && twine check`) |
