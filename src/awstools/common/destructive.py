"""Shared safety chassis for any destructive / execute-mode command."""

from __future__ import annotations

import logging
from typing import Optional, Tuple

from awstools.common.safety import confirm_account_gate, is_valid_account_id

LOG = logging.getLogger("awstools.destructive")


def require_execute_gates(
    *,
    execute: bool,
    confirm_account: Optional[str],
    actual_account_id: str,
    yes: bool,
    prompt_label: str = "resources",
) -> Tuple[bool, str, int]:
    """
    Returns (ok, message, exit_code_if_not_ok).

    When execute is False, always ok (dry-run).
    When execute is True, requires matching --confirm-account and optional interactive type.
    """
    if not execute:
        return True, "dry-run", 0

    if not confirm_account:
        return (
            False,
            "--execute requires --confirm-account <12-digit-account-id>",
            3,
        )
    if not is_valid_account_id(confirm_account):
        return False, "--confirm-account must be a 12-digit AWS account ID", 3

    ok, msg = confirm_account_gate(confirm_account, actual_account_id, confirm_account)
    if not ok:
        return False, msg, 3

    if not yes:
        print(
            f"\nWARNING: About to modify/delete {prompt_label} in account {actual_account_id}.\n"
            "This software is provided AS IS with no warranty. You proceed at your own risk.\n"
            "Type the account ID to proceed, or press Enter to abort."
        )
        try:
            typed = input("Account ID: ").strip()
        except EOFError:
            typed = ""
        ok, msg = confirm_account_gate(actual_account_id, actual_account_id, typed)
        if not ok:
            return False, f"Aborted: {msg}", 3

    return True, "ok", 0
