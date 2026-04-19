"""secretscope CLI — passive scanner for externally exposed secrets."""

from __future__ import annotations

import asyncio
import sys
import time
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import box

from secretscope import __version__
from secretscope.engine.rules import RuleEngine
from secretscope.fetcher.crawler import Crawler
from secretscope.fetcher.renderer import Renderer
from secretscope.models import Finding, PageContent, ScanResult, Severity
from secretscope.reporters.html_reporter import write_html
from secretscope.reporters.json_reporter import write_json
from secretscope.scanner import scan_page_content

# ---------------------------------------------------------------------------
# App + sub-app wiring
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="secretscope",
    help=(
        "Passive CLI scanner for externally exposed secrets in web applications.\n\n"
        "Authorised use only. Do not scan systems you do not own or have explicit "
        "written permission to test."
    ),
    add_completion=False,
)
scan_app = typer.Typer(help="Scan subcommands.")
app.add_typer(scan_app, name="scan")

_err = Console(stderr=True)  # progress/status → stderr
_out = Console()             # final rich summaries → stdout (won't conflict with JSON)


# ---------------------------------------------------------------------------
# Shared option enums
# ---------------------------------------------------------------------------

class OutputFormat(str, Enum):
    JSON = "json"
    HTML = "html"
    BOTH = "both"


class FailOn(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Version callback
# ---------------------------------------------------------------------------

def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"secretscope {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    pass


# ---------------------------------------------------------------------------
# scan url
# ---------------------------------------------------------------------------

@scan_app.command("url")
def scan_url_cmd(
    url: str = typer.Argument(help="Target URL to scan."),
    output: OutputFormat = typer.Option(OutputFormat.JSON, "--output", "-o", help="Output format."),
    output_file: Optional[Path] = typer.Option(None, "--output-file", "-f", help="Output file path (prefix when --output both)."),
    rules_dir: Optional[Path] = typer.Option(None, "--rules-dir", help="Custom rules directory."),
    fail_on: FailOn = typer.Option(FailOn.NONE, "--fail-on", help="Exit 1 when findings at/above this severity are found."),
    timeout: int = typer.Option(30_000, "--timeout", help="Page load timeout (ms)."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output."),
) -> None:
    """Scan a single URL for exposed secrets."""
    result = asyncio.run(_scan_single(url, rules_dir, timeout, quiet))
    _emit(result, output, output_file, fail_on, quiet)


# ---------------------------------------------------------------------------
# scan crawl
# ---------------------------------------------------------------------------

@scan_app.command("crawl")
def scan_crawl_cmd(
    url: str = typer.Argument(help="Start URL for the crawl."),
    output: OutputFormat = typer.Option(OutputFormat.JSON, "--output", "-o"),
    output_file: Optional[Path] = typer.Option(None, "--output-file", "-f"),
    rules_dir: Optional[Path] = typer.Option(None, "--rules-dir"),
    fail_on: FailOn = typer.Option(FailOn.NONE, "--fail-on"),
    timeout: int = typer.Option(30_000, "--timeout", help="Per-page timeout (ms)."),
    max_depth: int = typer.Option(3, "--max-depth", help="Maximum crawl depth."),
    max_pages: int = typer.Option(50, "--max-pages", help="Maximum pages to crawl."),
    concurrency: int = typer.Option(3, "--concurrency", help="Concurrent page renders."),
    rate_limit: float = typer.Option(0.5, "--rate-limit", help="Seconds between request batches."),
    no_robots: bool = typer.Option(False, "--no-robots", help="Ignore robots.txt."),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Crawl a site (same origin) and scan every page for exposed secrets."""
    result = asyncio.run(
        _scan_crawl(
            url, rules_dir, timeout, max_depth, max_pages,
            concurrency, rate_limit, not no_robots, quiet,
        )
    )
    _emit(result, output, output_file, fail_on, quiet)


# ---------------------------------------------------------------------------
# scan batch
# ---------------------------------------------------------------------------

@scan_app.command("batch")
def scan_batch_cmd(
    url_file: Path = typer.Argument(help="File containing one URL per line (# lines are comments)."),
    output: OutputFormat = typer.Option(OutputFormat.JSON, "--output", "-o"),
    output_file: Optional[Path] = typer.Option(None, "--output-file", "-f"),
    rules_dir: Optional[Path] = typer.Option(None, "--rules-dir"),
    fail_on: FailOn = typer.Option(FailOn.NONE, "--fail-on"),
    timeout: int = typer.Option(30_000, "--timeout"),
    concurrency: int = typer.Option(3, "--concurrency", help="Concurrent URL scans."),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
) -> None:
    """Scan a newline-delimited list of URLs for exposed secrets."""
    if not url_file.exists():
        _err.print(f"[red]File not found:[/red] {url_file}")
        raise typer.Exit(2)

    urls = _read_url_file(url_file)
    if not urls:
        _err.print("[yellow]No URLs found in file.[/yellow]")
        raise typer.Exit(0)

    result = asyncio.run(
        _scan_batch(urls, str(url_file), rules_dir, timeout, concurrency, quiet)
    )
    _emit(result, output, output_file, fail_on, quiet)


# ---------------------------------------------------------------------------
# Async scan implementations
# ---------------------------------------------------------------------------

async def _scan_single(
    url: str,
    rules_dir: Optional[Path],
    timeout: int,
    quiet: bool,
) -> ScanResult:
    engine = RuleEngine(rules_dir=rules_dir)
    renderer = Renderer(timeout_ms=timeout)
    errors: list[str] = []
    findings: list[Finding] = []
    t0 = time.monotonic()

    if not quiet:
        _err.print(f"[cyan]Rendering[/cyan] {url} …")

    try:
        content = await renderer.render(url)
        findings = scan_page_content(engine, content)
    except Exception as exc:
        errors.append(f"{url}: {exc}")
        if not quiet:
            _err.print(f"[red]Error:[/red] {exc}")

    return ScanResult(
        target_url=url,
        findings=findings,
        pages_scanned=1,
        scan_duration_seconds=time.monotonic() - t0,
        errors=errors,
    )


async def _scan_crawl(
    start_url: str,
    rules_dir: Optional[Path],
    timeout: int,
    max_depth: int,
    max_pages: int,
    concurrency: int,
    rate_limit: float,
    respect_robots: bool,
    quiet: bool,
) -> ScanResult:
    engine = RuleEngine(rules_dir=rules_dir)
    renderer = Renderer(timeout_ms=timeout)
    crawler = Crawler(
        renderer=renderer,
        max_depth=max_depth,
        max_pages=max_pages,
        concurrency=concurrency,
        rate_limit_delay=rate_limit,
        respect_robots=respect_robots,
    )
    all_findings: list[Finding] = []
    seen: set[str] = set()
    errors: list[str] = []
    pages = 0
    t0 = time.monotonic()

    if not quiet:
        _err.print(f"[cyan]Crawling[/cyan] {start_url} (max_depth={max_depth}, max_pages={max_pages}) …")

    try:
        async for content in crawler.crawl(start_url):
            pages += 1
            if not quiet:
                _err.print(f"  [{pages}] {content.page_url}")
            for f in scan_page_content(engine, content):
                if f.fingerprint not in seen:
                    seen.add(f.fingerprint)
                    all_findings.append(f)
    except Exception as exc:
        errors.append(str(exc))

    return ScanResult(
        target_url=start_url,
        findings=all_findings,
        pages_scanned=pages,
        scan_duration_seconds=time.monotonic() - t0,
        errors=errors,
    )


async def _scan_batch(
    urls: list[str],
    source_label: str,
    rules_dir: Optional[Path],
    timeout: int,
    concurrency: int,
    quiet: bool,
) -> ScanResult:
    engine = RuleEngine(rules_dir=rules_dir)
    renderer = Renderer(timeout_ms=timeout)
    all_findings: list[Finding] = []
    seen: set[str] = set()
    errors: list[str] = []
    pages = 0
    t0 = time.monotonic()
    sem = asyncio.Semaphore(concurrency)

    if not quiet:
        _err.print(f"[cyan]Batch scanning[/cyan] {len(urls)} URLs …")

    async def _render_one(url: str) -> PageContent | None:
        async with sem:
            try:
                return await renderer.render(url)
            except Exception as exc:
                errors.append(f"{url}: {exc}")
                return None

    tasks = [_render_one(u) for u in urls]
    results = await asyncio.gather(*tasks)

    for url, content in zip(urls, results):
        if content is None:
            continue
        pages += 1
        if not quiet:
            _err.print(f"  ✓ {url}")
        for f in scan_page_content(engine, content):
            if f.fingerprint not in seen:
                seen.add(f.fingerprint)
                all_findings.append(f)

    return ScanResult(
        target_url=f"batch:{source_label}",
        findings=all_findings,
        pages_scanned=pages,
        scan_duration_seconds=time.monotonic() - t0,
        errors=errors,
    )


# ---------------------------------------------------------------------------
# Output dispatch
# ---------------------------------------------------------------------------

def _emit(
    result: ScanResult,
    fmt: OutputFormat,
    output_file: Optional[Path],
    fail_on: FailOn,
    quiet: bool,
) -> None:
    if not quiet:
        _print_rich_summary(result)

    if fmt in (OutputFormat.JSON, OutputFormat.BOTH):
        if output_file:
            target = output_file.with_suffix(".json") if fmt == OutputFormat.BOTH else output_file
            write_json(result, target)
            if not quiet:
                _err.print(f"[green]JSON report:[/green] {target}")
        else:
            write_json(result, None)  # stdout

    if fmt in (OutputFormat.HTML, OutputFormat.BOTH):
        if output_file:
            html_path = output_file.with_suffix(".html")
        else:
            safe = result.target_url.replace("://", "_").replace("/", "_").replace(":", "")[:40]
            html_path = Path(f"secretscope_{safe}.html")
        write_html(result, html_path)
        if not quiet:
            _err.print(f"[green]HTML report:[/green] {html_path}")

    # Exit code
    if fail_on != FailOn.NONE:
        threshold = Severity(fail_on.value)
        if any(f.severity.numeric >= threshold.numeric for f in result.findings):
            raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Rich summary table
# ---------------------------------------------------------------------------

def _print_rich_summary(result: ScanResult) -> None:
    counts = {s: 0 for s in ("critical", "high", "medium", "low")}
    for f in result.findings:
        counts[f.severity.value] += 1

    _err.print()
    _err.print(
        f"[bold]Scan complete[/bold] — "
        f"[red]{counts['critical']} critical[/red]  "
        f"[yellow]{counts['high']} high[/yellow]  "
        f"[blue]{counts['medium']} medium[/blue]  "
        f"[green]{counts['low']} low[/green]  "
        f"({result.pages_scanned} page(s), {result.scan_duration_seconds:.1f}s)"
    )

    if not result.findings:
        _err.print("[green]No findings.[/green]")
        return

    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold")
    tbl.add_column("Severity", width=10)
    tbl.add_column("Rule")
    tbl.add_column("Source URL")
    tbl.add_column("Line", width=6, justify="right")
    tbl.add_column("Match (truncated)")

    severity_style = {
        "critical": "bold red",
        "high": "bold yellow",
        "medium": "blue",
        "low": "green",
    }
    for f in result.findings:
        tbl.add_row(
            f"[{severity_style[f.severity.value]}]{f.severity.value}[/{severity_style[f.severity.value]}]",
            f.rule_name,
            _truncate(f.source_url, 55),
            str(f.line_number) if f.line_number else "—",
            _truncate(f.match, 40),
        )

    _err.print(tbl)
    if result.errors:
        _err.print(f"[yellow]{len(result.errors)} error(s) during scan.[/yellow]")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_url_file(path: Path) -> list[str]:
    urls: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            urls.append(stripped)
    return urls


def _truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"
