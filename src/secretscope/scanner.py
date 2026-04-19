"""Scan orchestration: applies the rule engine to all text surfaces from a rendered page."""

from __future__ import annotations

from secretscope.engine.rules import RuleEngine
from secretscope.models import Finding, PageContent, SourceType


def scan_page_content(engine: RuleEngine, content: PageContent) -> list[Finding]:
    """Apply *engine* to every text surface in *content*.

    Scans the final rendered DOM, each inline <script> block, every captured
    network resource, and browser console messages.  Findings are deduplicated
    across all surfaces by fingerprint before returning.
    """
    all_findings: list[Finding] = []
    # Deduplicate across surfaces by (rule_id, match) so the same literal
    # secret discovered in both HTML and an inline script appears only once.
    seen: set[tuple[str, str]] = set()

    def _add(findings: list[Finding]) -> None:
        for f in findings:
            key = (f.rule_id, f.match)
            if key not in seen:
                seen.add(key)
                all_findings.append(f)

    _add(engine.scan(content.final_html, content.page_url, SourceType.HTML))

    for i, script in enumerate(content.inline_scripts):
        _add(engine.scan(script, f"{content.page_url}#inline-{i}", SourceType.INLINE_JS))

    for resource in content.network_resources:
        _add(engine.scan(resource.body, resource.url, resource.source_type))

    if content.console_messages:
        _add(engine.scan("\n".join(content.console_messages), content.page_url, SourceType.CONSOLE))

    return all_findings
