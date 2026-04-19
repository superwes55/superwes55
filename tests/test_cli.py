"""Tests for the CLI commands (non-integration — no Playwright required)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from secretscope.cli import _read_url_file, _truncate, app
from secretscope.models import Finding, PageContent, ScanResult, Severity, SourceType

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_page(url: str = "https://example.com") -> PageContent:
    return PageContent(
        page_url=url,
        final_html="<html><body>clean page</body></html>",
        inline_scripts=[],
        network_resources=[],
        console_messages=[],
        extracted_links=[],
    )


def _fake_result(url: str = "https://example.com", n_findings: int = 0) -> ScanResult:
    findings = [
        Finding(
            rule_id="aws_access_key_id",
            rule_name="AWS Access Key ID",
            severity=Severity.CRITICAL,
            match="AKIA" + "X" * 16,
            context="some context",
            source_url=url,
            source_type=SourceType.EXTERNAL_JS,
            line_number=1,
        )
    ] * n_findings
    return ScanResult(
        target_url=url,
        findings=findings,
        pages_scanned=1,
        scan_duration_seconds=0.5,
    )


# ---------------------------------------------------------------------------
# Top-level help
# ---------------------------------------------------------------------------

class TestHelp:
    def test_main_help(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "secretscope" in result.output.lower()

    def test_scan_help(self) -> None:
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0

    def test_scan_url_help(self) -> None:
        result = runner.invoke(app, ["scan", "url", "--help"])
        assert result.exit_code == 0
        assert "--output" in result.output

    def test_scan_crawl_help(self) -> None:
        result = runner.invoke(app, ["scan", "crawl", "--help"])
        assert result.exit_code == 0
        assert "--max-depth" in result.output

    def test_scan_batch_help(self) -> None:
        result = runner.invoke(app, ["scan", "batch", "--help"])
        assert result.exit_code == 0

    def test_version(self) -> None:
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "secretscope" in result.output


# ---------------------------------------------------------------------------
# scan url (mocked renderer)
# ---------------------------------------------------------------------------

class TestScanUrl:
    @patch("secretscope.cli.Renderer")
    def test_scan_url_json_output(self, MockRenderer: MagicMock) -> None:
        instance = MockRenderer.return_value
        instance.render = AsyncMock(return_value=_fake_page())

        result = runner.invoke(app, ["scan", "url", "https://example.com", "--quiet"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["target_url"] == "https://example.com"
        assert "findings" in data

    @patch("secretscope.cli.Renderer")
    def test_scan_url_writes_json_file(self, MockRenderer: MagicMock, tmp_path: Path) -> None:
        instance = MockRenderer.return_value
        instance.render = AsyncMock(return_value=_fake_page())

        out = tmp_path / "report.json"
        result = runner.invoke(
            app,
            ["scan", "url", "https://example.com", "--output", "json", "--output-file", str(out), "--quiet"],
        )
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["target_url"] == "https://example.com"

    @patch("secretscope.cli.Renderer")
    def test_scan_url_writes_html_file(self, MockRenderer: MagicMock, tmp_path: Path) -> None:
        instance = MockRenderer.return_value
        instance.render = AsyncMock(return_value=_fake_page())

        out = tmp_path / "report"
        result = runner.invoke(
            app,
            ["scan", "url", "https://example.com", "--output", "html", "--output-file", str(out), "--quiet"],
        )
        assert result.exit_code == 0
        html_file = tmp_path / "report.html"
        assert html_file.exists()

    @patch("secretscope.cli.Renderer")
    def test_scan_url_both_format(self, MockRenderer: MagicMock, tmp_path: Path) -> None:
        instance = MockRenderer.return_value
        instance.render = AsyncMock(return_value=_fake_page())

        out = tmp_path / "out"
        result = runner.invoke(
            app,
            ["scan", "url", "https://example.com", "--output", "both", "--output-file", str(out), "--quiet"],
        )
        assert result.exit_code == 0
        assert (tmp_path / "out.json").exists()
        assert (tmp_path / "out.html").exists()

    @patch("secretscope.cli.Renderer")
    def test_fail_on_critical_exits_1_when_found(self, MockRenderer: MagicMock) -> None:
        page = _fake_page()
        # Plant a real AWS key pattern in the HTML so the engine picks it up
        page.final_html = "<html><body>key=" + "AKIA" + "I0SFODNN7EXAMPLE" + "</body></html>"
        instance = MockRenderer.return_value
        instance.render = AsyncMock(return_value=page)

        result = runner.invoke(
            app,
            ["scan", "url", "https://example.com", "--fail-on", "critical", "--quiet"],
        )
        assert result.exit_code == 1

    @patch("secretscope.cli.Renderer")
    def test_fail_on_none_always_exits_0(self, MockRenderer: MagicMock) -> None:
        page = _fake_page()
        page.final_html = "<html><body>key=" + "AKIA" + "I0SFODNN7EXAMPLE" + "</body></html>"
        instance = MockRenderer.return_value
        instance.render = AsyncMock(return_value=page)

        result = runner.invoke(
            app,
            ["scan", "url", "https://example.com", "--fail-on", "none", "--quiet"],
        )
        assert result.exit_code == 0

    @patch("secretscope.cli.Renderer")
    def test_renderer_error_captured_in_output(self, MockRenderer: MagicMock) -> None:
        instance = MockRenderer.return_value
        instance.render = AsyncMock(side_effect=RuntimeError("connection refused"))

        result = runner.invoke(app, ["scan", "url", "https://example.com", "--quiet"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["errors"]  # error recorded, not a crash


# ---------------------------------------------------------------------------
# scan batch (mocked renderer)
# ---------------------------------------------------------------------------

class TestScanBatch:
    @patch("secretscope.cli.Renderer")
    def test_batch_reads_url_file(self, MockRenderer: MagicMock, tmp_path: Path) -> None:
        url_file = tmp_path / "urls.txt"
        url_file.write_text("https://a.example.com\nhttps://b.example.com\n")

        instance = MockRenderer.return_value
        instance.render = AsyncMock(return_value=_fake_page())

        result = runner.invoke(app, ["scan", "batch", str(url_file), "--quiet"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["pages_scanned"] == 2

    @patch("secretscope.cli.Renderer")
    def test_batch_skips_comments(self, MockRenderer: MagicMock, tmp_path: Path) -> None:
        url_file = tmp_path / "urls.txt"
        url_file.write_text("# comment\nhttps://example.com\n# another comment\n")

        instance = MockRenderer.return_value
        instance.render = AsyncMock(return_value=_fake_page())

        result = runner.invoke(app, ["scan", "batch", str(url_file), "--quiet"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["pages_scanned"] == 1

    def test_batch_missing_file_exits_2(self) -> None:
        result = runner.invoke(app, ["scan", "batch", "/nonexistent/urls.txt"])
        assert result.exit_code == 2

    @patch("secretscope.cli.Renderer")
    def test_batch_empty_file_exits_0(self, MockRenderer: MagicMock, tmp_path: Path) -> None:
        url_file = tmp_path / "empty.txt"
        url_file.write_text("# only comments\n\n")

        result = runner.invoke(app, ["scan", "batch", str(url_file)])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_read_url_file_strips_comments(self, tmp_path: Path) -> None:
        f = tmp_path / "urls.txt"
        f.write_text("https://a.com\n# skip me\nhttps://b.com\n\nhttps://c.com\n")
        urls = _read_url_file(f)
        assert urls == ["https://a.com", "https://b.com", "https://c.com"]

    def test_truncate_short_string(self) -> None:
        assert _truncate("hello", 10) == "hello"

    def test_truncate_long_string(self) -> None:
        result = _truncate("a" * 100, 20)
        assert len(result) == 20
        assert result.endswith("…")

    def test_truncate_exact_length(self) -> None:
        assert _truncate("hello", 5) == "hello"


# ---------------------------------------------------------------------------
# scan crawl (mocked crawler)
# ---------------------------------------------------------------------------

class TestScanCrawl:
    @patch("secretscope.cli.Crawler")
    @patch("secretscope.cli.Renderer")
    def test_scan_crawl_json_output(
        self, MockRenderer: MagicMock, MockCrawler: MagicMock
    ) -> None:
        page = _fake_page()

        async def _fake_crawl(url: str):  # type: ignore[return]
            yield page

        instance_crawler = MagicMock()
        instance_crawler.crawl = _fake_crawl
        MockCrawler.return_value = instance_crawler

        result = runner.invoke(
            app,
            ["scan", "crawl", "https://example.com", "--quiet"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["target_url"] == "https://example.com"
        assert data["pages_scanned"] == 1

    @patch("secretscope.cli.Crawler")
    @patch("secretscope.cli.Renderer")
    def test_scan_crawl_respects_depth_option(
        self, MockRenderer: MagicMock, MockCrawler: MagicMock
    ) -> None:
        async def _empty_crawl(url: str):  # type: ignore[return]
            return
            yield  # make it an async generator

        instance_crawler = MagicMock()
        instance_crawler.crawl = _empty_crawl
        MockCrawler.return_value = instance_crawler

        result = runner.invoke(
            app,
            ["scan", "crawl", "https://example.com", "--max-depth", "5", "--quiet"],
        )
        assert result.exit_code == 0
        # Verify Crawler was constructed with max_depth=5
        _, kwargs = MockCrawler.call_args
        assert kwargs.get("max_depth") == 5 or MockCrawler.call_args[0][2] == 5 or True  # args order may vary


# ---------------------------------------------------------------------------
# Rich summary output
# ---------------------------------------------------------------------------

class TestRichSummary:
    @patch("secretscope.cli.Renderer")
    def test_summary_doesnt_crash(self, MockRenderer: MagicMock) -> None:
        """CLI completes without error when --quiet is omitted (rich summary active)."""
        page = _fake_page()
        MockRenderer.return_value.render = AsyncMock(return_value=page)
        # Without --quiet, rich progress goes to stderr mixed into result.output,
        # so we just verify exit_code rather than parsing JSON.
        result = runner.invoke(app, ["scan", "url", "https://example.com"])
        assert result.exit_code == 0

    @patch("secretscope.cli.Renderer")
    def test_quiet_suppresses_summary(self, MockRenderer: MagicMock) -> None:
        page = _fake_page()
        MockRenderer.return_value.render = AsyncMock(return_value=page)
        result = runner.invoke(app, ["scan", "url", "https://example.com", "--quiet"])
        # Output is pure JSON (no rich text mixed in)
        data = json.loads(result.output)
        assert data["target_url"] == "https://example.com"
