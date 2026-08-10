"""CLI surface smoke tests for new commands."""

from awstools.cli import build_parser, main
from awstools.common import exit_codes as ec


def test_parser_subcommands_exist():
    p = build_parser()
    for cmd in (
        "whoami",
        "cost",
        "waste",
        "purge-s3",
        "s3-hygiene",
        "ebs-cleanup",
        "eip-release",
        "snapshot-age",
    ):
        args = p.parse_args([cmd])
        assert args.command == cmd


def test_parser_run_requires_accounts():
    p = build_parser()
    args = p.parse_args(["run", "--accounts", "accounts.json"])
    assert args.command == "run"
    assert args.accounts == "accounts.json"


def test_parser_waste_flags():
    p = build_parser()
    args = p.parse_args(
        ["waste", "--all-regions", "--fail-on-waste-usd", "50", "--format", "json"]
    )
    assert args.fail_on_waste_usd == 50.0
    assert args.format == "json"


def test_parser_purge_plan():
    p = build_parser()
    args = p.parse_args(["purge-s3", "--plan", "--include", "tmp-*"])
    assert args.plan
    assert args.include == ["tmp-*"]


def test_cost_fail_threshold(tmp_path):
    code = main(
        [
            "cost",
            "--dry-run",
            "--output-dir",
            str(tmp_path),
            "--fail-on-savings-usd",
            "1",
            "--quiet",
            "--no-export-actions",
        ]
    )
    assert code == ec.THRESHOLD_EXCEEDED


def test_waste_fail_threshold(tmp_path):
    code = main(
        [
            "waste",
            "--dry-run",
            "--output-dir",
            str(tmp_path),
            "--fail-on-waste-usd",
            "1",
            "--quiet",
        ]
    )
    assert code == ec.THRESHOLD_EXCEEDED


def test_module_main_importable():
    import awstools.__main__  # noqa: F401
