"""HTML executive report structure."""

from pathlib import Path

from awstools.cli import main


def test_html_has_executive_sections(tmp_path, monkeypatch):
    monkeypatch.setenv("AWSTOOLS_OFFLINE", "1")
    out = tmp_path / "r"
    code = main(
        ["cost", "--output-dir", str(out), "--quiet", "--no-export-actions"]
    )
    assert code in (0, 5)
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "Executive summary" in html
    assert "Top actions" in html
    assert "Engineer detail" in html
    assert 'id="exec"' in html
    assert 'id="actions"' in html
    assert "AWS cost report" in html
