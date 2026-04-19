"""Core data models shared across the secretscope package."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def numeric(self) -> int:
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class SourceType(str, Enum):
    HTML = "html"
    INLINE_JS = "inline_js"
    EXTERNAL_JS = "external_js"
    NETWORK_RESPONSE = "network_response"
    SOURCEMAP = "sourcemap"
    CONSOLE = "console"


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: Severity
    match: str
    context: str
    source_url: str
    source_type: SourceType
    line_number: int | None = None
    offset: int | None = None
    fingerprint: str = field(default="")

    def __post_init__(self) -> None:
        if not self.fingerprint:
            digest = hashlib.sha256(
                f"{self.rule_id}:{self.match}:{self.source_url}".encode()
            ).hexdigest()
            self.fingerprint = digest[:16]

    def to_dict(self) -> dict[str, object]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "match": self.match,
            "context": self.context,
            "source_url": self.source_url,
            "source_type": self.source_type.value,
            "line_number": self.line_number,
            "offset": self.offset,
        }


@dataclass
class NetworkResource:
    """A single network response body captured during page rendering."""

    url: str
    content_type: str
    body: str
    source_type: SourceType


@dataclass
class PageContent:
    """Everything captured from rendering a single page."""

    page_url: str
    final_html: str
    inline_scripts: list[str]
    network_resources: list[NetworkResource]
    console_messages: list[str]
    extracted_links: list[str]


@dataclass
class ScanResult:
    target_url: str
    findings: list[Finding]
    pages_scanned: int
    scan_duration_seconds: float
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        by_severity = {
            sev.value: sum(1 for f in self.findings if f.severity == sev)
            for sev in Severity
        }
        return {
            "target_url": self.target_url,
            "timestamp": self.timestamp,
            "pages_scanned": self.pages_scanned,
            "scan_duration_seconds": round(self.scan_duration_seconds, 3),
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "summary": {
                "total": len(self.findings),
                "by_severity": by_severity,
            },
        }
