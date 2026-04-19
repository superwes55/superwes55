"""YAML-driven rule engine for secret pattern detection."""

from __future__ import annotations

import bisect
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from secretscope.engine.entropy import entropy_for_secret
from secretscope.models import Finding, Severity, SourceType

CONTEXT_CHARS = 120


@dataclass
class Rule:
    id: str
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    description: str
    tags: list[str] = field(default_factory=list)
    entropy_threshold: float | None = None
    min_length: int | None = None
    example: str | None = None


def _bundled_rules_dir() -> Path:
    """Return the rules/ directory bundled inside the installed package."""
    return Path(__file__).parent.parent / "rules"


def _load_rule(data: dict[str, object]) -> Rule:
    return Rule(
        id=str(data["id"]),
        name=str(data["name"]),
        pattern=re.compile(str(data["pattern"])),
        severity=Severity(str(data["severity"])),
        description=str(data["description"]),
        tags=list(data.get("tags", [])),  # type: ignore[arg-type]
        entropy_threshold=float(data["entropy_threshold"]) if "entropy_threshold" in data else None,
        min_length=int(data["min_length"]) if "min_length" in data else None,
        example=str(data["example"]) if "example" in data else None,
    )


class RuleEngine:
    """Loads YAML rule files and scans text blobs for secret patterns."""

    def __init__(self, rules_dir: Path | None = None) -> None:
        self._rules: list[Rule] = []
        target = rules_dir if rules_dir is not None else _bundled_rules_dir()
        if target.is_dir():
            self.load_rules_dir(target)

    # ------------------------------------------------------------------
    # Rule loading
    # ------------------------------------------------------------------

    def load_rules_dir(self, path: Path) -> None:
        """Load all *.yaml files from *path* in alphabetical order."""
        for yaml_file in sorted(path.glob("*.yaml")):
            self.load_rules_file(yaml_file)

    def load_rules_file(self, path: Path) -> None:
        """Load rules from a single YAML file."""
        with open(path) as fh:
            data = yaml.safe_load(fh)
        for rule_data in data.get("rules", []):
            try:
                self._rules.append(_load_rule(rule_data))
            except (KeyError, ValueError, re.error) as exc:
                warnings.warn(f"Skipping invalid rule in {path.name}: {exc}", stacklevel=2)

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def scan(
        self,
        text: str,
        source_url: str,
        source_type: SourceType,
    ) -> list[Finding]:
        """Scan *text* and return a deduplicated list of :class:`Finding` objects."""
        findings: list[Finding] = []
        seen: set[str] = set()
        line_offsets = _compute_line_offsets(text)

        for rule in self._rules:
            for match in rule.pattern.finditer(text):
                secret = _extract_secret(match)

                if rule.min_length and len(secret) < rule.min_length:
                    continue

                if rule.entropy_threshold is not None:
                    if entropy_for_secret(secret) < rule.entropy_threshold:
                        continue

                line_no = bisect.bisect_right(line_offsets, match.start())
                context = _build_context(text, match.start(), match.end())

                finding = Finding(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    match=secret,
                    context=context,
                    source_url=source_url,
                    source_type=source_type,
                    line_number=line_no,
                    offset=match.start(),
                )

                if finding.fingerprint not in seen:
                    seen.add(finding.fingerprint)
                    findings.append(finding)

        return findings


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _extract_secret(match: re.Match[str]) -> str:
    """Return group(1) when the pattern uses a capture group; otherwise the full match."""
    if match.lastindex and match.lastindex >= 1:
        return match.group(1) or match.group(0)
    return match.group(0)


def _compute_line_offsets(text: str) -> list[int]:
    """Return the character offset at which each line starts (1-indexed via bisect_right)."""
    offsets = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            offsets.append(i + 1)
    return offsets


def _build_context(text: str, start: int, end: int, width: int = CONTEXT_CHARS) -> str:
    ctx_start = max(0, start - width)
    ctx_end = min(len(text), end + width)
    return text[ctx_start:ctx_end].strip()
