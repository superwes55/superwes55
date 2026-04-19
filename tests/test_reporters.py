"""Tests for JSON and HTML reporters."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secretscope.models import Finding, ScanResult, Severity, SourceType
from secretscope.reporters.html_reporter import write_html
from secretscope.reporters.json_reporter import write_json


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(**kwargs: object) -> Finding:
    defaults: dict[str, object] = dict(
        rule_id="test_rule",
        rule_name="Test Rule",
        severity=Severity.HIGH,
        match="TEST_MATCH_VALUE",
        context="surrounding context TEST_MATCH_VALUE more text",
        source_url="https://example.com/app.js",
        source_type=SourceType.EXTERNAL_JS,
        line_number=42,
        offset=100,
    )
    defaults.update(kwargs)
    return Finding(**defaults)  # type: ignore[arg-type]


def _make_result(findings: list[Finding] | None = None, **kwargs: object) -> ScanResult:
    defaults: dict[str, object] = dict(
        target_url="https://example.com",
        findings=findings or [],
        pages_scanned=1,
        scan_duration_seconds=1.23,
        errors=[],
    )
    defaults.update(kwargs)
    return ScanResult(**defaults)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# JSON reporter
# ---------------------------------------------------------------------------

class TestJsonReporter:
    def test_write_json_to_file(self, tmp_path: Path) -> None:
        result = _make_result([_make_finding()])
        out = tmp_path / "report.json"
        write_json(result, out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["target_url"] == "https://example.com"

    def test_output_is_valid_json(self, tmp_path: Path) -> None:
        result = _make_result([_make_finding(), _make_finding(rule_id="r2", rule_name="R2")])
        out = tmp_path / "out.json"
        write_json(result, out)
        parsed = json.loads(out.read_text())
        assert isinstance(parsed, dict)

    def test_findings_in_output(self, tmp_path: Path) -> None:
        finding = _make_finding(rule_id="aws_access_key_id", severity=Severity.CRITICAL)
        result = _make_result([finding])
        out = tmp_path / "r.json"
        write_json(result, out)
        data = json.loads(out.read_text())
        assert len(data["findings"]) == 1
        assert data["findings"][0]["rule_id"] == "aws_access_key_id"
        assert data["findings"][0]["severity"] == "critical"

    def test_summary_counts(self, tmp_path: Path) -> None:
        findings = [
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.LOW),
        ]
        result = _make_result(findings)
        out = tmp_path / "r.json"
        write_json(result, out)
        data = json.loads(out.read_text())
        assert data["summary"]["total"] == 4
        assert data["summary"]["by_severity"]["critical"] == 1
        assert data["summary"]["by_severity"]["high"] == 2
        assert data["summary"]["by_severity"]["low"] == 1

    def test_empty_findings(self, tmp_path: Path) -> None:
        result = _make_result([])
        out = tmp_path / "r.json"
        write_json(result, out)
        data = json.loads(out.read_text())
        assert data["findings"] == []
        assert data["summary"]["total"] == 0

    def test_write_to_stdout(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = _make_result([_make_finding()])
        write_json(result, None)
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "findings" in data

    def test_errors_included(self, tmp_path: Path) -> None:
        result = _make_result([], errors=["https://x.com: timeout"])
        out = tmp_path / "r.json"
        write_json(result, out)
        data = json.loads(out.read_text())
        assert data["errors"] == ["https://x.com: timeout"]


# ---------------------------------------------------------------------------
# HTML reporter
# ---------------------------------------------------------------------------

class TestHtmlReporter:
    def test_write_html_creates_file(self, tmp_path: Path) -> None:
        result = _make_result([_make_finding()])
        out = tmp_path / "report.html"
        write_html(result, out)
        assert out.exists()
        assert out.stat().st_size > 0

    def test_html_contains_target_url(self, tmp_path: Path) -> None:
        result = _make_result([_make_finding()])
        out = tmp_path / "r.html"
        write_html(result, out)
        content = out.read_text()
        assert "https://example.com" in content

    def test_html_contains_rule_name(self, tmp_path: Path) -> None:
        finding = _make_finding(rule_name="AWS Access Key ID")
        result = _make_result([finding])
        out = tmp_path / "r.html"
        write_html(result, out)
        assert "AWS Access Key ID" in out.read_text()

    def test_html_contains_severity_badge(self, tmp_path: Path) -> None:
        finding = _make_finding(severity=Severity.CRITICAL)
        result = _make_result([finding])
        out = tmp_path / "r.html"
        write_html(result, out)
        html = out.read_text()
        assert "critical" in html.lower()

    def test_html_is_valid_structure(self, tmp_path: Path) -> None:
        result = _make_result([_make_finding()])
        out = tmp_path / "r.html"
        write_html(result, out)
        html = out.read_text()
        assert "<!DOCTYPE html>" in html
        assert "</html>" in html
        assert "<table" in html

    def test_html_no_findings_shows_empty_state(self, tmp_path: Path) -> None:
        result = _make_result([])
        out = tmp_path / "r.html"
        write_html(result, out)
        html = out.read_text()
        assert "No findings detected" in html
        assert "<table" not in html

    def test_html_escapes_special_chars(self, tmp_path: Path) -> None:
        finding = _make_finding(
            match="<script>alert('xss')</script>",
            context="surrounding <b>text</b>",
        )
        result = _make_result([finding])
        out = tmp_path / "r.html"
        write_html(result, out)
        html = out.read_text()
        # Jinja2 autoescape should have encoded angle brackets
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html

    def test_html_contains_disclaimer(self, tmp_path: Path) -> None:
        result = _make_result()
        out = tmp_path / "r.html"
        write_html(result, out)
        assert "Authorized use only" in out.read_text()

    def test_html_multiple_findings(self, tmp_path: Path) -> None:
        findings = [
            _make_finding(rule_id="r1", rule_name="Rule One", severity=Severity.CRITICAL),
            _make_finding(rule_id="r2", rule_name="Rule Two", severity=Severity.LOW),
        ]
        result = _make_result(findings)
        out = tmp_path / "r.html"
        write_html(result, out)
        html = out.read_text()
        assert "Rule One" in html
        assert "Rule Two" in html

    def test_html_contains_filter_js(self, tmp_path: Path) -> None:
        result = _make_result([_make_finding()])
        out = tmp_path / "r.html"
        write_html(result, out)
        html = out.read_text()
        assert "setFilter" in html
        assert "applySearch" in html
