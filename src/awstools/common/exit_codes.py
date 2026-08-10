"""Standard process exit codes for scripting and CI."""

from __future__ import annotations

OK = 0
ANALYSIS_ERROR = 1
AUTH_ERROR = 2
SAFETY_GATE = 3
THRESHOLD_EXCEEDED = 4  # findings / waste over configured limit
PARTIAL_SUCCESS = 5  # completed with non-fatal coverage gaps
