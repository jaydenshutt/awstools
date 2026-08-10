"""Product identity and attribution (shown when the tool runs)."""

from __future__ import annotations

AUTHOR_NAME = "Jayden Shutt"
AUTHOR_URL = "https://www.linkedin.com/in/jaydenshutt/"
PRODUCT_NAME = "awstools"
ATTRIBUTION = f"Created by {AUTHOR_NAME}"
ATTRIBUTION_HTML = (
    f'Created by <a href="{AUTHOR_URL}">{AUTHOR_NAME}</a>'
)
ATTRIBUTION_PLAIN = f"Created by {AUTHOR_NAME}"


def banner_line(version: str) -> str:
    return f"{PRODUCT_NAME} {version} - {ATTRIBUTION_PLAIN}"


def version_string(version: str) -> str:
    return f"{PRODUCT_NAME} {version} - {ATTRIBUTION_PLAIN}"
