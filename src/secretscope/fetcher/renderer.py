"""Playwright-based headless renderer.

Captures the final rendered DOM, all network-loaded resources (JS, JSON,
text), inline scripts, sourcemaps, and browser console output for a given URL.
"""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import urljoin

import httpx
from playwright.async_api import Response as PlaywrightResponse
from playwright.async_api import async_playwright

from secretscope.models import NetworkResource, PageContent, SourceType

_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")

_CAPTURABLE_TYPES: frozenset[str] = frozenset(
    [
        "text/html",
        "text/javascript",
        "application/javascript",
        "application/x-javascript",
        "text/x-javascript",
        "module",
        "application/json",
        "text/plain",
        "text/css",
    ]
)


def _is_capturable(content_type: str) -> bool:
    ct = content_type.split(";")[0].lower().strip()
    return any(ct.startswith(t) for t in _CAPTURABLE_TYPES)


def _classify_source(content_type: str, url: str) -> SourceType:
    ct = content_type.split(";")[0].lower().strip()
    if "html" in ct:
        return SourceType.HTML
    if url.endswith(".map"):
        return SourceType.SOURCEMAP
    if (
        "javascript" in ct
        or "ecmascript" in ct
        or "module" in ct
        or url.endswith(".js")
        or url.endswith(".mjs")
    ):
        return SourceType.EXTERNAL_JS
    return SourceType.NETWORK_RESPONSE


class Renderer:
    """Renders a URL with Playwright Chromium and returns all captured content."""

    def __init__(
        self,
        timeout_ms: int = 30_000,
        wait_until: str = "networkidle",
        user_agent: str | None = None,
    ) -> None:
        self._timeout_ms = timeout_ms
        self._wait_until = wait_until
        self._user_agent = user_agent

    async def render(self, url: str) -> PageContent:
        """Render *url* and return a :class:`PageContent` with all captured data."""
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            try:
                ctx_kwargs: dict[str, object] = {"ignore_https_errors": True}
                if self._user_agent:
                    ctx_kwargs["user_agent"] = self._user_agent
                context = await browser.new_context(**ctx_kwargs)
                page = await context.new_page()

                network_resources: list[NetworkResource] = []
                console_messages: list[str] = []

                async def on_response(resp: PlaywrightResponse) -> None:
                    ct = resp.headers.get("content-type", "")
                    if not _is_capturable(ct):
                        return
                    try:
                        body = await resp.text()
                    except Exception:
                        return
                    network_resources.append(
                        NetworkResource(
                            url=resp.url,
                            content_type=ct,
                            body=body,
                            source_type=_classify_source(ct, resp.url),
                        )
                    )

                page.on("response", on_response)
                page.on(
                    "console",
                    lambda msg: console_messages.append(f"[{msg.type}] {msg.text}"),
                )

                try:
                    await page.goto(
                        url,
                        wait_until=self._wait_until,
                        timeout=self._timeout_ms,
                    )
                except Exception:
                    # Fall back to 'load' if networkidle times out
                    try:
                        await page.goto(url, wait_until="load", timeout=self._timeout_ms)
                    except Exception:
                        pass

                final_html = await page.content()

                inline_scripts: list[str] = await page.evaluate(
                    """() => Array.from(document.querySelectorAll('script:not([src])'))
                              .map(s => s.textContent || '')
                              .filter(t => t.trim().length > 0)"""
                )

                extracted_links: list[str] = await page.evaluate(
                    """() => Array.from(document.querySelectorAll('a[href]'))
                              .map(a => a.href)
                              .filter(h => h.startsWith('http'))"""
                )

                sourcemap_resources = await _fetch_sourcemaps(network_resources)
                network_resources.extend(sourcemap_resources)

                return PageContent(
                    page_url=url,
                    final_html=final_html,
                    inline_scripts=inline_scripts,
                    network_resources=network_resources,
                    console_messages=console_messages,
                    extracted_links=extracted_links,
                )
            finally:
                await browser.close()


async def _fetch_sourcemaps(resources: list[NetworkResource]) -> list[NetworkResource]:
    """Find sourceMappingURL references in JS and fetch or decode the maps."""
    results: list[NetworkResource] = []

    for resource in resources:
        if resource.source_type != SourceType.EXTERNAL_JS:
            continue
        m = _SOURCEMAP_RE.search(resource.body)
        if not m:
            continue
        map_ref = m.group(1)

        if map_ref.startswith("data:"):
            results.extend(_decode_inline_sourcemap(map_ref, resource.url))
            continue

        map_url = urljoin(resource.url, map_ref)
        try:
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                resp = await client.get(map_url, follow_redirects=True)
            if resp.status_code != 200:
                continue
            body = resp.text
            results.append(
                NetworkResource(
                    url=map_url,
                    content_type="application/json",
                    body=body,
                    source_type=SourceType.SOURCEMAP,
                )
            )
            results.extend(_extract_sources_content(body, map_url))
        except Exception:
            pass

    return results


def _decode_inline_sourcemap(data_uri: str, js_url: str) -> list[NetworkResource]:
    if "base64," not in data_uri:
        return []
    try:
        raw = base64.b64decode(data_uri.split("base64,", 1)[1], validate=True).decode("utf-8", errors="replace")
        inline_url = js_url + ".inline.map"
        resources = [
            NetworkResource(
                url=inline_url,
                content_type="application/json",
                body=raw,
                source_type=SourceType.SOURCEMAP,
            )
        ]
        resources.extend(_extract_sources_content(raw, inline_url))
        return resources
    except Exception:
        return []


def _extract_sources_content(map_json: str, map_url: str) -> list[NetworkResource]:
    """Pull individual source files out of sourcemap sourcesContent array."""
    try:
        data = json.loads(map_json)
    except Exception:
        return []
    results: list[NetworkResource] = []
    for i, src in enumerate(data.get("sourcesContent") or []):
        if src and src.strip():
            results.append(
                NetworkResource(
                    url=f"{map_url}#source[{i}]",
                    content_type="text/javascript",
                    body=src,
                    source_type=SourceType.SOURCEMAP,
                )
            )
    return results
