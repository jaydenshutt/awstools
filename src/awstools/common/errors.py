"""User-facing error formatting (no raw stack traces as the only signal)."""

from __future__ import annotations

from typing import Any, Optional


class AwsToolsError(Exception):
    """Base error with a short code and remediation hint."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "error",
        hint: Optional[str] = None,
        exit_code: int = 1,
    ):
        super().__init__(message)
        self.code = code
        self.hint = hint
        self.exit_code = exit_code

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"ok": False, "error": str(self), "code": self.code}
        if self.hint:
            d["hint"] = self.hint
        return d

    def format_lines(self) -> list[str]:
        lines = [f"ERROR [{self.code}]: {self}"]
        if self.hint:
            lines.append(f"Hint: {self.hint}")
        return lines


def classify_boto_error(exc: BaseException) -> AwsToolsError:
    """Map botocore/SDK exceptions to actionable CLI errors."""
    msg = str(exc)
    name = type(exc).__name__
    code = None
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        code = resp.get("Error", {}).get("Code")

    blob = f"{code or ''} {msg} {name}".lower()

    if "expiredtoken" in blob or "token has expired" in blob or "request has expired" in blob:
        return AwsToolsError(
            "AWS credentials or SSO session has expired.",
            code="auth_expired",
            hint="Run: aws sso login --profile <profile>  (or refresh your credentials)",
            exit_code=2,
        )
    if "could not connect to the endpoint" in blob or "endpoint" in blob and "connect" in blob:
        return AwsToolsError(
            "Could not reach AWS endpoints (network or wrong partition/region).",
            code="network",
            hint="Check network/VPN/proxy and region. For offline work use --dry-run or AWSTOOLS_OFFLINE=1.",
            exit_code=1,
        )
    if "accessdenied" in blob or "unauthorized" in blob or "not authorized" in blob:
        return AwsToolsError(
            f"Access denied by AWS IAM{f' ({code})' if code else ''}: {msg}",
            code="access_denied",
            hint="Attach the sample policy in policies/cost-analysis-readonly.json (or the cleanup/purge policy you need).",
            exit_code=2,
        )
    if "nosuchentity" in blob and "cost" in blob:
        return AwsToolsError(
            "Cost Explorer appears unavailable or not enabled.",
            code="ce_unavailable",
            hint="Enable Cost Explorer in the Billing console; data may lag ~24h after enablement.",
            exit_code=1,
        )
    if "subscriptionrequired" in blob or "cost explorer" in blob:
        return AwsToolsError(
            "Cost Explorer is not enabled for this account.",
            code="ce_not_enabled",
            hint="Billing → Cost Explorer → Enable. Then wait for data population.",
            exit_code=1,
        )
    if "throttl" in blob or "toomanyrequests" in blob or "rate exceeded" in blob:
        return AwsToolsError(
            "AWS API throttling - too many requests.",
            code="throttled",
            hint="Re-run with lower --concurrency, fewer regions, or wait and retry.",
            exit_code=1,
        )
    if "invalidclienttokenid" in blob or "unrecognizedclient" in blob or "unable to locate credentials" in blob:
        return AwsToolsError(
            "No valid AWS credentials found.",
            code="auth_missing",
            hint="Configure a profile, or use --dry-run / AWSTOOLS_OFFLINE=1 for offline development.",
            exit_code=2,
        )
    if "profile" in blob and ("not found" in blob or "could not be found" in blob):
        return AwsToolsError(
            f"AWS profile error: {msg}",
            code="profile_missing",
            hint="Check ~/.aws/config and --profile name. Offline: --dry-run.",
            exit_code=2,
        )

    return AwsToolsError(
        f"{name}: {msg}",
        code=(code or "aws_error").lower() if code else "aws_error",
        hint="Re-run with --verbose for details. Offline development: --dry-run or AWSTOOLS_OFFLINE=1.",
        exit_code=1,
    )
