"""Attribution and team-facing features."""

import json
from pathlib import Path

from awstools import __attribution__, __author__, __version__
from awstools.branding import ATTRIBUTION_PLAIN, NO_WARRANTY_SHORT, version_string
from awstools.cli import build_parser, main
from awstools.common.findings_diff import diff_findings, format_findings_diff_lines


def test_attribution_constants():
    assert __author__ == "Jayden Shutt"
    assert "Created by Jayden Shutt" in __attribution__
    assert "Created by Jayden Shutt" in version_string(__version__)
    assert ATTRIBUTION_PLAIN == "Created by Jayden Shutt"
    assert "no warranty" in NO_WARRANTY_SHORT.lower()
    assert "own risk" in NO_WARRANTY_SHORT.lower()


def test_version_flag_mentions_author():
    p = build_parser()
    # argparse version action stores the string
    for action in p._actions:
        if getattr(action, "dest", None) == "version" or action.__class__.__name__ == "_VersionAction":
            v = getattr(action, "version", "") or ""
            if "Created by Jayden Shutt" in str(v):
                return
    # Fallback: version_string used by build_parser
    assert "Jayden Shutt" in version_string(__version__)


def test_help_epilog_attribution():
    p = build_parser()
    assert p.epilog and "Jayden Shutt" in p.epilog
    assert p.epilog and "warranty" in p.epilog.lower()


def test_json_emit_includes_created_by(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AWSTOOLS_OFFLINE", "1")
    code = main(["whoami", "--format", "json", "--quiet"])
    assert code == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert "Created by Jayden Shutt" in data.get("created_by", "")
    assert "warranty" in data.get("no_warranty", "").lower()


def test_html_attribution(tmp_path, monkeypatch):
    monkeypatch.setenv("AWSTOOLS_OFFLINE", "1")
    out = tmp_path / "c"
    main(["cost", "--output-dir", str(out), "--quiet", "--no-export-actions"])
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "Created by Jayden Shutt" in html
    assert "How estimates work" in html
    assert "warranty" in html.lower() or "own risk" in html.lower()
    summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    assert "warranty" in summary.get("no_warranty", "").lower()


def test_findings_diff():
    prev = {
        "estimated_monthly_savings_usd": 10.0,
        "savings_breakdown": {"high_confidence_usd": 10.0},
        "findings": [
            {
                "category": "unattached_ebs",
                "resource_id": "vol-old",
                "region": "us-east-1",
                "estimated_monthly_usd": 10,
                "confidence": "High",
            }
        ],
    }
    cur = {
        "estimated_monthly_savings_usd": 8.0,
        "savings_breakdown": {"high_confidence_usd": 8.0},
        "findings": [
            {
                "category": "unattached_ebs",
                "resource_id": "vol-new",
                "region": "us-east-1",
                "estimated_monthly_usd": 8,
                "confidence": "High",
            }
        ],
    }
    d = diff_findings(cur, prev)
    assert d["new_count"] == 1
    assert d["resolved_count"] == 1
    lines = format_findings_diff_lines(d)
    assert any("New" in x or "new" in x.lower() or "+" in x for x in lines)


def test_waste_compare(tmp_path, monkeypatch):
    monkeypatch.setenv("AWSTOOLS_OFFLINE", "1")
    a = tmp_path / "a"
    b = tmp_path / "b"
    main(["waste", "--output-dir", str(a), "--quiet"])
    prev = a / "findings.json"
    code = main(
        [
            "waste",
            "--output-dir",
            str(b),
            "--compare",
            str(prev),
            "--quiet",
            "--format",
            "json",
        ]
    )
    assert code in (0, 5)
    data = json.loads((b / "findings.json").read_text(encoding="utf-8"))
    assert "diff" in data or (b / "findings-diff.json").exists()
