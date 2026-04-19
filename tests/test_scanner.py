"""Unit tests for the scan orchestration layer."""

from __future__ import annotations

from secretscope.engine.rules import RuleEngine
from secretscope.models import NetworkResource, PageContent, SourceType
from secretscope.scanner import scan_page_content

RULES_DIR = __import__("pathlib").Path(__file__).parent.parent / "src" / "secretscope" / "rules"


def _engine() -> RuleEngine:
    return RuleEngine(rules_dir=RULES_DIR)


def _page(
    url: str = "https://example.com",
    html: str = "<html><body></body></html>",
    inline: list[str] | None = None,
    resources: list[NetworkResource] | None = None,
    console: list[str] | None = None,
) -> PageContent:
    return PageContent(
        page_url=url,
        final_html=html,
        inline_scripts=inline or [],
        network_resources=resources or [],
        console_messages=console or [],
        extracted_links=[],
    )


class TestScanPageContent:
    def test_empty_page_returns_no_findings(self) -> None:
        engine = _engine()
        result = scan_page_content(engine, _page())
        assert result == []

    def test_scans_final_html(self) -> None:
        engine = _engine()
        key = "AKIA" + "I0SFODNN7EXAMPLE"
        page = _page(html=f"<html><body>{key}</body></html>")
        findings = scan_page_content(engine, page)
        assert any(f.rule_id == "aws_access_key_id" for f in findings)

    def test_scans_inline_scripts(self) -> None:
        engine = _engine()
        key = "AKIA" + "I0SFODNN7EXAMPLE"
        page = _page(inline=[f'var k="{key}";'])
        findings = scan_page_content(engine, page)
        matched = [f for f in findings if f.rule_id == "aws_access_key_id"]
        assert matched
        assert matched[0].source_type == SourceType.INLINE_JS

    def test_inline_script_source_url_has_inline_marker(self) -> None:
        engine = _engine()
        key = "AKIA" + "I0SFODNN7EXAMPLE"
        page = _page(url="https://example.com/page", inline=[f'var k="{key}";'])
        findings = scan_page_content(engine, page)
        matched = [f for f in findings if f.rule_id == "aws_access_key_id"]
        assert matched
        assert "#inline-0" in matched[0].source_url

    def test_scans_network_resources(self) -> None:
        engine = _engine()
        key = "AKIA" + "I0SFODNN7EXAMPLE"
        resource = NetworkResource(
            url="https://cdn.example.com/app.js",
            content_type="text/javascript",
            body=f'config.key="{key}";',
            source_type=SourceType.EXTERNAL_JS,
        )
        page = _page(resources=[resource])
        findings = scan_page_content(engine, page)
        matched = [f for f in findings if f.rule_id == "aws_access_key_id"]
        assert matched
        assert matched[0].source_type == SourceType.EXTERNAL_JS
        assert matched[0].source_url == "https://cdn.example.com/app.js"

    def test_scans_multiple_resources(self) -> None:
        engine = _engine()
        key1 = "AKIA" + "I0SFODNN7EXAMPLE"
        key2 = "AKIA" + "Z1234567890ABCDE"
        resources = [
            NetworkResource("https://x.com/a.js", "text/javascript", key1, SourceType.EXTERNAL_JS),
            NetworkResource("https://x.com/b.js", "text/javascript", key2, SourceType.EXTERNAL_JS),
        ]
        page = _page(resources=resources)
        findings = scan_page_content(engine, page)
        aws = [f for f in findings if f.rule_id == "aws_access_key_id"]
        assert len(aws) == 2

    def test_scans_console_messages(self) -> None:
        engine = _engine()
        key = "AKIA" + "I0SFODNN7EXAMPLE"
        page = _page(console=[f"[log] loaded key: {key}"])
        findings = scan_page_content(engine, page)
        matched = [f for f in findings if f.rule_id == "aws_access_key_id"]
        assert matched
        assert matched[0].source_type == SourceType.CONSOLE

    def test_empty_console_messages_skipped(self) -> None:
        engine = _engine()
        page = _page(console=[])
        # Should not raise; returns empty
        assert scan_page_content(engine, page) == []

    def test_cross_surface_deduplication(self) -> None:
        """The same secret in both HTML and an inline script yields one finding."""
        engine = _engine()
        key = "AKIA" + "I0SFODNN7EXAMPLE"
        page = _page(
            html=f"<html><body>{key}</body></html>",
            inline=[f'var k="{key}";'],
        )
        findings = scan_page_content(engine, page)
        aws = [f for f in findings if f.rule_id == "aws_access_key_id"]
        assert len(aws) == 1, "Same secret from two surfaces should be deduplicated"

    def test_sourcemap_resource_scanned(self) -> None:
        engine = _engine()
        key = "AKIA" + "I0SFODNN7EXAMPLE"
        resource = NetworkResource(
            url="https://example.com/app.js.map",
            content_type="application/json",
            body=f'{{"sourcesContent": ["var k=\\"{key}\\";"]}}',
            source_type=SourceType.SOURCEMAP,
        )
        page = _page(resources=[resource])
        findings = scan_page_content(engine, page)
        assert any(f.rule_id == "aws_access_key_id" for f in findings)
