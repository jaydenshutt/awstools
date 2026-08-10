"""Product identity, attribution, and warranty disclaimer."""

from __future__ import annotations

AUTHOR_NAME = "Jayden Shutt"
AUTHOR_URL = "https://www.linkedin.com/in/jaydenshutt/"
PRODUCT_NAME = "awstools"
ATTRIBUTION = f"Created by {AUTHOR_NAME}"
ATTRIBUTION_HTML = (
    f'Created by <a href="{AUTHOR_URL}">{AUTHOR_NAME}</a>'
)
ATTRIBUTION_PLAIN = f"Created by {AUTHOR_NAME}"

# Short form for CLI banners and footers
NO_WARRANTY_SHORT = (
    "Provided AS IS with no warranty of any kind. Use at your own risk."
)

# Longer form for README, help, and reports
NO_WARRANTY_PLAIN = (
    "THIS SOFTWARE IS PROVIDED AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR "
    "IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, "
    "FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. YOU USE THIS TOOL "
    "ENTIRELY AT YOUR OWN RISK. The authors and copyright holders are not "
    "liable for any claim, damage, data loss, unexpected AWS charges, or other "
    "liability arising from use of the software (including destructive "
    "operations such as deletes). See the MIT LICENSE for the full terms."
)

NO_WARRANTY_HTML = (
    "<strong>No warranty.</strong> This software is provided <em>as is</em>, "
    "without warranty of any kind. You use it entirely at your own risk. "
    "The authors are not liable for damages, data loss, or AWS charges arising "
    "from use (including destructive operations). See the MIT LICENSE."
)


def banner_line(version: str) -> str:
    return f"{PRODUCT_NAME} {version} - {ATTRIBUTION_PLAIN}"


def version_string(version: str) -> str:
    return f"{PRODUCT_NAME} {version} - {ATTRIBUTION_PLAIN}"


def disclaimer_lines() -> list[str]:
    return [NO_WARRANTY_SHORT, "Full terms: LICENSE (MIT)."]
