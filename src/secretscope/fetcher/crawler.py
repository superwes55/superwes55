"""Same-origin BFS web crawler with robots.txt support."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from urllib.parse import urlparse, urlunparse

import httpx

from secretscope.fetcher.renderer import Renderer
from secretscope.models import PageContent


class RobotsTxtChecker:
    """Minimal robots.txt parser — honours Disallow rules for `*` user-agent."""

    def __init__(self, disallow_paths: list[str]) -> None:
        self._disallow = disallow_paths

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_allowed(self, path: str) -> bool:
        for prefix in self._disallow:
            if path.startswith(prefix):
                return False
        return True

    @classmethod
    async def fetch(cls, base_url: str) -> "RobotsTxtChecker":
        robots_url = _robots_url(base_url)
        try:
            async with httpx.AsyncClient(timeout=5, verify=False) as client:
                resp = await client.get(robots_url, follow_redirects=True)
            if resp.status_code == 200:
                return cls._parse(resp.text)
        except Exception:
            pass
        return cls([])

    @classmethod
    def _parse(cls, text: str) -> "RobotsTxtChecker":
        disallow: list[str] = []
        in_block = False
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key == "user-agent":
                in_block = value in ("*", "secretscope")
            elif key == "disallow" and in_block and value:
                disallow.append(value)
        return cls(disallow)


class Crawler:
    """BFS crawler that stays within the same origin as the start URL.

    Pages are processed in batches of up to *concurrency* at a time.  A polite
    delay of *rate_limit_delay* seconds is applied between batches.
    """

    def __init__(
        self,
        renderer: Renderer | None = None,
        max_depth: int = 3,
        max_pages: int = 50,
        concurrency: int = 3,
        rate_limit_delay: float = 0.5,
        respect_robots: bool = True,
        timeout_ms: int = 30_000,
    ) -> None:
        self._renderer = renderer or Renderer(timeout_ms=timeout_ms)
        self._max_depth = max_depth
        self._max_pages = max_pages
        self._concurrency = concurrency
        self._rate_limit_delay = rate_limit_delay
        self._respect_robots = respect_robots

    async def crawl(self, start_url: str) -> AsyncGenerator[PageContent, None]:
        """Yield :class:`PageContent` for each crawled page."""
        origin = _same_origin(start_url)
        robots: RobotsTxtChecker | None = None
        if self._respect_robots:
            robots = await RobotsTxtChecker.fetch(start_url)

        visited: set[str] = set()
        # Queue entries: (url, depth)
        queue: list[tuple[str, int]] = [(_normalize_url(start_url), 0)]
        visited.add(_normalize_url(start_url))
        pages_crawled = 0

        while queue and pages_crawled < self._max_pages:
            # Build next batch
            batch: list[tuple[str, int]] = []
            while queue and len(batch) < self._concurrency:
                url, depth = queue.pop(0)
                path = urlparse(url).path or "/"
                if robots and not robots.is_allowed(path):
                    continue
                batch.append((url, depth))

            if not batch:
                break

            # Rate-limit between batches
            if pages_crawled > 0:
                await asyncio.sleep(self._rate_limit_delay)

            pages_crawled += len(batch)
            tasks = [self._renderer.render(url) for url, _ in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for (url, depth), result in zip(batch, results):
                if isinstance(result, BaseException):
                    continue
                content: PageContent = result  # type: ignore[assignment]
                yield content

                if depth < self._max_depth:
                    for link in content.extracted_links:
                        norm = _normalize_url(link)
                        if norm not in visited and norm.startswith(origin) and pages_crawled + len(queue) < self._max_pages:
                            visited.add(norm)
                            queue.append((norm, depth + 1))


# ------------------------------------------------------------------
# URL helpers (also used by the CLI)
# ------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    """Strip URL fragment and normalise trailing slash for deduplication."""
    parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment=""))


def _same_origin(url: str) -> str:
    """Return the scheme + host + port prefix for *url*."""
    p = urlparse(url)
    port_part = f":{p.port}" if p.port else ""
    return f"{p.scheme}://{p.hostname}{port_part}"


def _robots_url(base_url: str) -> str:
    p = urlparse(base_url)
    return f"{p.scheme}://{p.netloc}/robots.txt"
