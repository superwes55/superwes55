"""Tests for the fetcher/renderer and crawler modules."""

from __future__ import annotations

import asyncio
import json

import pytest

from secretscope.fetcher.crawler import (
    Crawler,
    RobotsTxtChecker,
    _normalize_url,
    _same_origin,
)
from secretscope.fetcher.renderer import (
    Renderer,
    _classify_source,
    _decode_inline_sourcemap,
    _extract_sources_content,
    _is_capturable,
)
from secretscope.models import SourceType


# ---------------------------------------------------------------------------
# _is_capturable
# ---------------------------------------------------------------------------

class TestIsCapturable:
    @pytest.mark.parametrize("ct", [
        "text/javascript",
        "application/javascript",
        "application/x-javascript",
        "text/javascript; charset=utf-8",
        "application/json",
        "text/html",
        "text/plain",
        "text/css",
    ])
    def test_capturable_types(self, ct: str) -> None:
        assert _is_capturable(ct)

    @pytest.mark.parametrize("ct", [
        "image/png",
        "image/jpeg",
        "font/woff2",
        "audio/mpeg",
        "video/mp4",
        "application/octet-stream",
        "",
    ])
    def test_non_capturable_types(self, ct: str) -> None:
        assert not _is_capturable(ct)


# ---------------------------------------------------------------------------
# _classify_source
# ---------------------------------------------------------------------------

class TestClassifySource:
    def test_html(self) -> None:
        assert _classify_source("text/html", "https://example.com/") == SourceType.HTML

    def test_javascript_by_content_type(self) -> None:
        assert _classify_source("text/javascript", "https://example.com/app.js") == SourceType.EXTERNAL_JS

    def test_javascript_by_url_extension(self) -> None:
        assert _classify_source("application/octet-stream", "https://example.com/bundle.js") == SourceType.EXTERNAL_JS

    def test_sourcemap_by_url_extension(self) -> None:
        assert _classify_source("application/json", "https://example.com/app.js.map") == SourceType.SOURCEMAP

    def test_json_response(self) -> None:
        assert _classify_source("application/json", "https://api.example.com/config") == SourceType.NETWORK_RESPONSE

    def test_mjs_extension(self) -> None:
        assert _classify_source("", "https://example.com/lib.mjs") == SourceType.EXTERNAL_JS


# ---------------------------------------------------------------------------
# _extract_sources_content
# ---------------------------------------------------------------------------

class TestExtractSourcesContent:
    def test_extracts_each_source(self) -> None:
        sm = json.dumps({
            "version": 3,
            "sources": ["a.ts", "b.ts"],
            "sourcesContent": ["const a = 1;", "const b = 2;"],
        })
        results = _extract_sources_content(sm, "https://example.com/app.js.map")
        assert len(results) == 2
        assert results[0].source_type == SourceType.SOURCEMAP
        assert results[0].body == "const a = 1;"
        assert "#source[0]" in results[0].url

    def test_skips_empty_sources(self) -> None:
        sm = json.dumps({"sourcesContent": ["", None, "valid"]})
        results = _extract_sources_content(sm, "https://example.com/app.js.map")
        assert len(results) == 1
        assert results[0].body == "valid"

    def test_no_sources_content_key(self) -> None:
        sm = json.dumps({"version": 3, "sources": []})
        assert _extract_sources_content(sm, "https://example.com/app.js.map") == []

    def test_invalid_json(self) -> None:
        assert _extract_sources_content("not json {{", "https://example.com/app.js.map") == []


# ---------------------------------------------------------------------------
# _decode_inline_sourcemap
# ---------------------------------------------------------------------------

class TestDecodeInlineSourcemap:
    def test_decodes_base64(self) -> None:
        import base64
        sm = json.dumps({"sourcesContent": ["console.log('hello');"]})
        encoded = base64.b64encode(sm.encode()).decode()
        data_uri = f"data:application/json;base64,{encoded}"
        results = _decode_inline_sourcemap(data_uri, "https://example.com/app.js")
        assert len(results) >= 1
        map_resource = next(r for r in results if "inline.map" in r.url)
        assert map_resource.source_type == SourceType.SOURCEMAP

    def test_no_base64_marker(self) -> None:
        assert _decode_inline_sourcemap("data:application/json,{}", "https://x.com/a.js") == []

    def test_invalid_base64(self) -> None:
        result = _decode_inline_sourcemap("data:application/json;base64,!!!", "https://x.com/a.js")
        assert result == []


# ---------------------------------------------------------------------------
# RobotsTxtChecker
# ---------------------------------------------------------------------------

class TestRobotsTxtChecker:
    def _make(self, robots_txt: str) -> RobotsTxtChecker:
        return RobotsTxtChecker._parse(robots_txt)

    def test_disallow_path_blocked(self) -> None:
        checker = self._make("User-agent: *\nDisallow: /admin/\n")
        assert not checker.is_allowed("/admin/dashboard")

    def test_allowed_path_passes(self) -> None:
        checker = self._make("User-agent: *\nDisallow: /admin/\n")
        assert checker.is_allowed("/public/page")

    def test_empty_disallow_allows_all(self) -> None:
        checker = self._make("User-agent: *\nDisallow:\n")
        assert checker.is_allowed("/anything")

    def test_blank_robots_allows_all(self) -> None:
        checker = self._make("")
        assert checker.is_allowed("/secret")

    def test_specific_agent_ignored(self) -> None:
        # Only * and secretscope blocks apply
        robots = "User-agent: googlebot\nDisallow: /private/\n"
        checker = self._make(robots)
        assert checker.is_allowed("/private/page")

    def test_secretscope_agent_respected(self) -> None:
        robots = "User-agent: secretscope\nDisallow: /no-scan/\n"
        checker = self._make(robots)
        assert not checker.is_allowed("/no-scan/data")

    def test_multiple_disallow_rules(self) -> None:
        robots = "User-agent: *\nDisallow: /admin/\nDisallow: /api/internal/\n"
        checker = self._make(robots)
        assert not checker.is_allowed("/api/internal/keys")
        assert not checker.is_allowed("/admin/")
        assert checker.is_allowed("/api/public/")

    def test_comments_ignored(self) -> None:
        robots = "# comment\nUser-agent: *\n# another comment\nDisallow: /private/\n"
        checker = self._make(robots)
        assert not checker.is_allowed("/private/data")

    @pytest.mark.asyncio
    async def test_fetch_unreachable_allows_all(self) -> None:
        # A URL that definitely won't resolve should return a permissive checker
        checker = await RobotsTxtChecker.fetch("http://localhost:19999")
        assert checker.is_allowed("/anything")


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

class TestUrlHelpers:
    def test_normalize_strips_fragment(self) -> None:
        assert _normalize_url("https://example.com/page#section") == "https://example.com/page"

    def test_normalize_preserves_query(self) -> None:
        assert _normalize_url("https://example.com/search?q=test") == "https://example.com/search?q=test"

    def test_normalize_no_op_on_clean_url(self) -> None:
        url = "https://example.com/page"
        assert _normalize_url(url) == url

    def test_same_origin_http(self) -> None:
        assert _same_origin("http://example.com/path") == "http://example.com"

    def test_same_origin_https(self) -> None:
        assert _same_origin("https://example.com/path") == "https://example.com"

    def test_same_origin_with_port(self) -> None:
        assert _same_origin("http://localhost:8080/path") == "http://localhost:8080"

    def test_same_origin_standard_port_omitted(self) -> None:
        # Standard ports (80, 443) are not included in netloc by urlparse
        assert _same_origin("https://example.com:443/path") == "https://example.com:443"


# ---------------------------------------------------------------------------
# Integration tests (require `playwright install chromium`)
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.asyncio
async def test_renderer_captures_html(httpserver: object) -> None:
    """Renderer returns final_html containing page content."""
    from pytest_httpserver import HTTPServer  # type: ignore[import]
    assert isinstance(httpserver, HTTPServer)

    httpserver.expect_request("/").respond_with_data(  # type: ignore[attr-defined]
        "<html><body><h1>Hello</h1></body></html>",
        content_type="text/html",
    )
    url = httpserver.url_for("/")  # type: ignore[attr-defined]
    renderer = Renderer(wait_until="load")
    content = await renderer.render(url)
    assert "Hello" in content.final_html
    assert content.page_url == url


@pytest.mark.integration
@pytest.mark.asyncio
async def test_renderer_captures_external_js(httpserver: object) -> None:
    """Renderer captures externally loaded JS in network_resources."""
    from pytest_httpserver import HTTPServer  # type: ignore[import]
    assert isinstance(httpserver, HTTPServer)

    # Plant a fake secret in JS — built programmatically to avoid push protection
    gcp_key = "AIza" + "SyBFAKEEXAMPLEKEYVALUEHERE123456789"
    js_body = f'var config = {{ apiKey: "{gcp_key}" }};'

    httpserver.expect_request("/app.js").respond_with_data(  # type: ignore[attr-defined]
        js_body, content_type="text/javascript"
    )
    httpserver.expect_request("/").respond_with_data(  # type: ignore[attr-defined]
        '<html><head><script src="/app.js"></script></head><body></body></html>',
        content_type="text/html",
    )

    url = httpserver.url_for("/")  # type: ignore[attr-defined]
    renderer = Renderer(wait_until="load")
    content = await renderer.render(url)

    js_resources = [r for r in content.network_resources if r.source_type == SourceType.EXTERNAL_JS]
    assert js_resources, "Expected at least one external JS resource"
    assert any(gcp_key in r.body for r in js_resources)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_renderer_captures_inline_script(httpserver: object) -> None:
    """Renderer extracts inline <script> blocks."""
    from pytest_httpserver import HTTPServer  # type: ignore[import]
    assert isinstance(httpserver, HTTPServer)

    aws_key = "AKIA" + "I0SFODNN7EXAMPLE"
    html = f'<html><body><script>var k="{aws_key}";</script></body></html>'
    httpserver.expect_request("/").respond_with_data(html, content_type="text/html")  # type: ignore[attr-defined]

    url = httpserver.url_for("/")  # type: ignore[attr-defined]
    renderer = Renderer(wait_until="load")
    content = await renderer.render(url)

    assert any(aws_key in s for s in content.inline_scripts)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_renderer_extracts_links(httpserver: object) -> None:
    """Renderer surfaces anchor hrefs for the crawler."""
    from pytest_httpserver import HTTPServer  # type: ignore[import]
    assert isinstance(httpserver, HTTPServer)

    httpserver.expect_request("/page2").respond_with_data(  # type: ignore[attr-defined]
        "<html><body>page 2</body></html>", content_type="text/html"
    )
    httpserver.expect_request("/").respond_with_data(  # type: ignore[attr-defined]
        '<html><body><a href="/page2">Page 2</a></body></html>',
        content_type="text/html",
    )

    url = httpserver.url_for("/")  # type: ignore[attr-defined]
    renderer = Renderer(wait_until="load")
    content = await renderer.render(url)

    assert any("page2" in link for link in content.extracted_links)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_renderer_fetches_sourcemap(httpserver: object) -> None:
    """Renderer follows sourceMappingURL and extracts sourcesContent."""
    from pytest_httpserver import HTTPServer  # type: ignore[import]
    assert isinstance(httpserver, HTTPServer)

    original_src = "const secret = 'from_original_source';"
    sm = json.dumps({
        "version": 3,
        "sources": ["original.ts"],
        "sourcesContent": [original_src],
        "mappings": "",
    })
    httpserver.expect_request("/app.js.map").respond_with_data(  # type: ignore[attr-defined]
        sm, content_type="application/json"
    )
    js_body = "var x=1;\n//# sourceMappingURL=/app.js.map"
    httpserver.expect_request("/app.js").respond_with_data(  # type: ignore[attr-defined]
        js_body, content_type="text/javascript"
    )
    httpserver.expect_request("/").respond_with_data(  # type: ignore[attr-defined]
        '<html><head><script src="/app.js"></script></head><body></body></html>',
        content_type="text/html",
    )

    url = httpserver.url_for("/")  # type: ignore[attr-defined]
    renderer = Renderer(wait_until="load")
    content = await renderer.render(url)

    sourcemap_resources = [r for r in content.network_resources if r.source_type == SourceType.SOURCEMAP]
    assert sourcemap_resources, "Expected sourcemap resources"
    assert any(original_src in r.body for r in sourcemap_resources)


@pytest.mark.integration
@pytest.mark.asyncio
async def test_crawler_visits_same_origin_links(httpserver: object) -> None:
    """Crawler follows same-origin links up to max_depth."""
    from pytest_httpserver import HTTPServer  # type: ignore[import]
    assert isinstance(httpserver, HTTPServer)

    httpserver.expect_request("/page2").respond_with_data(  # type: ignore[attr-defined]
        "<html><body>page 2</body></html>", content_type="text/html"
    )
    httpserver.expect_request("/").respond_with_data(  # type: ignore[attr-defined]
        '<html><body><a href="/page2">P2</a></body></html>',
        content_type="text/html",
    )

    url = httpserver.url_for("/")  # type: ignore[attr-defined]
    renderer = Renderer(wait_until="load")
    crawler = Crawler(
        renderer=renderer,
        max_depth=1,
        max_pages=5,
        concurrency=1,
        rate_limit_delay=0,
        respect_robots=False,
    )

    pages = [c async for c in crawler.crawl(url)]
    urls_visited = {p.page_url for p in pages}
    assert any("page2" in u for u in urls_visited), "Should have crawled /page2"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_crawler_respects_max_pages(httpserver: object) -> None:
    """Crawler stops at max_pages even when more links are available."""
    from pytest_httpserver import HTTPServer  # type: ignore[import]
    assert isinstance(httpserver, HTTPServer)

    for i in range(1, 10):
        next_link = f"/page{i+1}" if i < 9 else ""
        body = f'<html><body>page{i}' + (f'<a href="/page{i+1}">n</a>' if next_link else "") + "</body></html>"
        httpserver.expect_request(f"/page{i}").respond_with_data(body, content_type="text/html")  # type: ignore[attr-defined]

    start_body = '<html><body>' + "".join(f'<a href="/page{i}">p</a>' for i in range(1, 10)) + "</body></html>"
    httpserver.expect_request("/").respond_with_data(start_body, content_type="text/html")  # type: ignore[attr-defined]

    url = httpserver.url_for("/")  # type: ignore[attr-defined]
    renderer = Renderer(wait_until="load")
    crawler = Crawler(
        renderer=renderer,
        max_depth=2,
        max_pages=3,
        concurrency=1,
        rate_limit_delay=0,
        respect_robots=False,
    )

    pages = [c async for c in crawler.crawl(url)]
    assert len(pages) <= 3
