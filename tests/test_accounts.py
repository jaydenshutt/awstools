"""Multi-account config loading."""

from pathlib import Path

from awstools.common.accounts import load_accounts_file


def test_load_json(tmp_path: Path):
    p = tmp_path / "a.json"
    p.write_text(
        '{"accounts": [{"name": "dev", "profile": "dev", "regions": ["us-east-1"]}]}',
        encoding="utf-8",
    )
    targets = load_accounts_file(p)
    assert len(targets) == 1
    assert targets[0].profile == "dev"
    assert targets[0].regions == ["us-east-1"]


def test_load_simple_yaml(tmp_path: Path):
    p = tmp_path / "a.yaml"
    p.write_text(
        "accounts:\n"
        "  - name: sandbox\n"
        "    profile: sandbox\n"
        "    all_regions: true\n",
        encoding="utf-8",
    )
    targets = load_accounts_file(p)
    assert targets[0].name == "sandbox"
    assert targets[0].all_regions is True


def test_cli_run_dry(tmp_path: Path):
    from awstools.cli import main

    acc = tmp_path / "accounts.json"
    acc.write_text(
        '{"accounts": [{"name": "demo", "profile": null}]}',
        encoding="utf-8",
    )
    out = tmp_path / "multi"
    code = main(
        [
            "run",
            "--accounts",
            str(acc),
            "--output-dir",
            str(out),
            "--commands",
            "cost,waste",
            "--dry-run",
            "--format",
            "json",
            "--quiet",
        ]
    )
    assert code in (0, 5)
    assert (out / "rollup.json").exists()
    assert (out / "demo" / "cost" / "summary.json").exists()
    assert (out / "demo" / "waste" / "findings.json").exists()
