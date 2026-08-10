"""CLI smoke tests."""

from awstools.cli import build_parser, main


def test_parser_cost_defaults():
    p = build_parser()
    args = p.parse_args(["cost", "--dry-run", "-o", "out"])
    assert args.command == "cost"
    assert args.dry_run
    assert args.output_dir == "out"


def test_parser_purge_requires_subcommand_only():
    p = build_parser()
    args = p.parse_args(["purge-s3", "--include", "tmp-*"])
    assert args.command == "purge-s3"
    assert not args.execute
    assert args.include == ["tmp-*"]


def test_main_cost_dry_run(tmp_path):
    code = main(
        [
            "cost",
            "--dry-run",
            "--output-dir",
            str(tmp_path),
            "--export-actions",
            "actions.csv",
            "--quiet",
        ]
    )
    assert code == 0
    assert (tmp_path / "report.html").exists()


def test_version_flag():
    p = build_parser()
    try:
        p.parse_args(["--version"])
    except SystemExit as e:
        assert e.code == 0
