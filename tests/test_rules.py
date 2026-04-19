"""Unit tests for the rule engine."""

from pathlib import Path

import pytest

from secretscope.engine.rules import (
    RuleEngine,
    _build_context,
    _compute_line_offsets,
    _extract_secret,
)
from secretscope.models import Severity, SourceType

URL = "https://example.com/app.js"
STYPE = SourceType.EXTERNAL_JS


# ---------------------------------------------------------------------------
# RuleEngine loading
# ---------------------------------------------------------------------------

class TestRuleLoading:
    def test_default_rules_loaded(self, engine: RuleEngine) -> None:
        assert len(engine.rules) > 10, "Expected a substantial bundled rule set"

    def test_rules_have_required_fields(self, engine: RuleEngine) -> None:
        for rule in engine.rules:
            assert rule.id
            assert rule.name
            assert rule.pattern
            assert isinstance(rule.severity, Severity)

    def test_load_from_custom_dir(self, tmp_path: Path) -> None:
        yaml_content = """
rules:
  - id: test_rule
    name: Test Rule
    pattern: 'SECRET_([A-Z]{8})'
    severity: high
    description: Test pattern
    tags: [test]
"""
        (tmp_path / "custom.yaml").write_text(yaml_content)
        custom_engine = RuleEngine(rules_dir=tmp_path)
        assert len(custom_engine.rules) == 1
        assert custom_engine.rules[0].id == "test_rule"

    def test_bad_rule_skipped_with_warning(self, tmp_path: Path) -> None:
        yaml_content = """
rules:
  - id: good_rule
    name: Good Rule
    pattern: 'GOOD_([A-Z]+)'
    severity: low
    description: Fine
  - id: bad_rule
    name: Bad Rule
    pattern: '(?P<bad>(?P<bad>[A-Z]+))'
    severity: invalid_severity
    description: Will fail
"""
        (tmp_path / "mixed.yaml").write_text(yaml_content)
        with pytest.warns(UserWarning):
            e = RuleEngine(rules_dir=tmp_path)
        # Only the good rule should have loaded
        ids = [r.id for r in e.rules]
        assert "good_rule" in ids
        assert "bad_rule" not in ids

    def test_empty_dir_produces_no_rules(self, tmp_path: Path) -> None:
        e = RuleEngine(rules_dir=tmp_path)
        assert e.rules == []


# ---------------------------------------------------------------------------
# AWS rule detection
# ---------------------------------------------------------------------------

class TestAwsRules:
    def test_detects_access_key_id(self, engine: RuleEngine) -> None:
        # Built programmatically — AKIA prefix + 16 uppercase alphanumeric chars.
        key = "AKIA" + "I0SFODNN7EXAMPLE"
        text = f'var key = "{key}";'
        findings = engine.scan(text, URL, STYPE)
        matched = [f for f in findings if f.rule_id == "aws_access_key_id"]
        assert matched, "Should detect AWS Access Key ID"
        assert matched[0].severity == Severity.CRITICAL
        assert key in matched[0].match

    def test_rejects_short_key_id(self, engine: RuleEngine) -> None:
        text = 'var x = "AKIASHORT";'  # too short — only 9 chars after prefix
        findings = engine.scan(text, URL, STYPE)
        assert not any(f.rule_id == "aws_access_key_id" for f in findings)

    def test_detects_asca_prefix(self, engine: RuleEngine) -> None:
        # ASCA prefix + exactly 16 chars = 20-char key.
        key = "ASCA" + "IOSFODNN7EXAMPLE"
        findings = engine.scan(key, URL, STYPE)
        assert any(f.rule_id == "aws_access_key_id" for f in findings)

    def test_detects_secret_key_with_context(self, engine: RuleEngine) -> None:
        # 40-char high-entropy base64-safe string, split to avoid literal scanner hits.
        secret = "wJalrXUtnFEM" + "I/K7MDENG/bP" + "xRfiCYEXAMPL" + "EKEY"
        assert len(secret) == 40
        text = f'aws_secret_key = "{secret}"'
        findings = engine.scan(text, URL, STYPE)
        assert any(f.rule_id == "aws_secret_access_key" for f in findings)

    def test_secret_key_low_entropy_skipped(self, engine: RuleEngine) -> None:
        # All the same character → entropy ≈ 0, should not match
        text = 'secret_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
        findings = engine.scan(text, URL, STYPE)
        assert not any(f.rule_id == "aws_secret_access_key" for f in findings)


# ---------------------------------------------------------------------------
# JWT detection
# ---------------------------------------------------------------------------

class TestJwtRules:
    def test_detects_jwt(self, engine: RuleEngine) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0VXNlciIsInJvbGUiOiJhZG1pbiJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        findings = engine.scan(jwt, URL, STYPE)
        assert any(f.rule_id == "jwt_token" for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_rejects_short_base64_segments(self, engine: RuleEngine) -> None:
        # Each segment must be ≥10 chars and total ≥50
        short = "eyJx.eyJx.eyJx"
        findings = engine.scan(short, URL, STYPE)
        assert not any(f.rule_id == "jwt_token" for f in findings)


# ---------------------------------------------------------------------------
# Web services detection
# ---------------------------------------------------------------------------

class TestWebServiceRules:
    def test_detects_stripe_secret_key(self, engine: RuleEngine) -> None:
        # Built programmatically so the literal never appears in source.
        key = "sk_" + "live" + "_" + "A" * 24
        text = f'stripe.key = "{key}";'
        findings = engine.scan(text, URL, STYPE)
        assert any(f.rule_id == "stripe_secret_key" for f in findings)

    def test_detects_slack_bot_token(self, engine: RuleEngine) -> None:
        # Built programmatically so the literal never appears in source.
        token = "xoxb-" + "0" * 12 + "-" + "0" * 12 + "-" + "A" * 24
        text = f'token = "{token}"'
        findings = engine.scan(text, URL, STYPE)
        assert any(f.rule_id == "slack_bot_token" for f in findings)

    def test_detects_github_pat(self, engine: RuleEngine) -> None:
        pat = "ghp_" + "A" * 36
        text = f'const token = "{pat}";'
        findings = engine.scan(text, URL, STYPE)
        assert any(f.rule_id == "github_personal_access_token" for f in findings)

    def test_detects_sendgrid_key(self, engine: RuleEngine) -> None:
        # SG. + 22 chars + . + 43 chars
        key = "SG." + "A" * 22 + "." + "B" * 43
        findings = engine.scan(key, URL, STYPE)
        assert any(f.rule_id == "sendgrid_api_key" for f in findings)


# ---------------------------------------------------------------------------
# GCP / Azure detection
# ---------------------------------------------------------------------------

class TestGcpRules:
    def test_detects_gcp_api_key(self, engine: RuleEngine) -> None:
        text = 'apiKey: "AIzaSyBFAKEEXAMPLEKEYVALUEHERE123456789"'  # AIza + 35 chars
        findings = engine.scan(text, URL, STYPE)
        assert any(f.rule_id == "gcp_api_key" for f in findings)


class TestAzureRules:
    def test_detects_storage_connection_string(self, engine: RuleEngine) -> None:
        conn = (
            "DefaultEndpointsProtocol=https;AccountName=myaccount;"
            "AccountKey=" + "A" * 88 + ";EndpointSuffix=core.windows.net"
        )
        findings = engine.scan(conn, URL, STYPE)
        assert any(f.rule_id == "azure_storage_connection_string" for f in findings)


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

class TestDeduplication:
    def test_same_secret_twice_yields_one_finding(self, engine: RuleEngine) -> None:
        key = "AKIA" + "I0SFODNN7EXAMPLE"
        text = f'var a = "{key}"; var b = "{key}";'
        findings = engine.scan(text, URL, STYPE)
        matched = [f for f in findings if f.rule_id == "aws_access_key_id"]
        assert len(matched) == 1, "Duplicate secret should be deduplicated"

    def test_different_secrets_yield_separate_findings(self, engine: RuleEngine) -> None:
        key1 = "AKIA" + "I0SFODNN7EXAMPLE"
        key2 = "AKIA" + "Z1234567890ABCDE"
        text = f'var a = "{key1}"; var b = "{key2}";'
        findings = engine.scan(text, URL, STYPE)
        matched = [f for f in findings if f.rule_id == "aws_access_key_id"]
        assert len(matched) == 2


# ---------------------------------------------------------------------------
# Context and line numbers
# ---------------------------------------------------------------------------

_AWS_KEY = "AKIA" + "I0SFODNN7EXAMPLE"  # 20-char key, built to avoid literal scanner hits


class TestContextAndLineNumbers:
    def test_context_includes_surrounding_text(self, engine: RuleEngine) -> None:
        text = f'before_text {_AWS_KEY} after_text'
        findings = engine.scan(text, URL, STYPE)
        matched = [f for f in findings if f.rule_id == "aws_access_key_id"]
        assert matched
        assert "before_text" in matched[0].context
        assert "after_text" in matched[0].context

    def test_line_number_single_line(self, engine: RuleEngine) -> None:
        findings = engine.scan(_AWS_KEY, URL, STYPE)
        matched = [f for f in findings if f.rule_id == "aws_access_key_id"]
        assert matched
        assert matched[0].line_number == 1

    def test_line_number_multiline(self, engine: RuleEngine) -> None:
        text = f"line1\nline2\n{_AWS_KEY}\nline4"
        findings = engine.scan(text, URL, STYPE)
        matched = [f for f in findings if f.rule_id == "aws_access_key_id"]
        assert matched
        assert matched[0].line_number == 3


# ---------------------------------------------------------------------------
# Source type propagation
# ---------------------------------------------------------------------------

class TestSourceType:
    def test_source_type_is_propagated(self, engine: RuleEngine) -> None:
        text = "AKIAIOSFODNN7EXAMPLE"
        for stype in SourceType:
            findings = engine.scan(text, URL, stype)
            for f in findings:
                assert f.source_type == stype


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_compute_line_offsets(self) -> None:
        offsets = _compute_line_offsets("line1\nline2\nline3")
        assert offsets == [0, 6, 12]

    def test_build_context_truncates(self) -> None:
        text = "A" * 300
        ctx = _build_context(text, start=150, end=160, width=50)
        assert len(ctx) <= 110 + 10  # 50+50 + match width + strip

    def test_extract_secret_uses_group1(self) -> None:
        import re
        m = re.match(r"PREFIX_([A-Z]+)", "PREFIX_SECRET")
        assert m is not None
        assert _extract_secret(m) == "SECRET"

    def test_extract_secret_falls_back_to_group0(self) -> None:
        import re
        m = re.match(r"PREFIX_[A-Z]+", "PREFIX_SECRET")
        assert m is not None
        assert _extract_secret(m) == "PREFIX_SECRET"


# ---------------------------------------------------------------------------
# Severity model
# ---------------------------------------------------------------------------

class TestSeverityModel:
    def test_severity_ordering(self) -> None:
        assert Severity.LOW.numeric < Severity.MEDIUM.numeric
        assert Severity.MEDIUM.numeric < Severity.HIGH.numeric
        assert Severity.HIGH.numeric < Severity.CRITICAL.numeric

    def test_severity_is_string_enum(self) -> None:
        assert Severity.CRITICAL == "critical"
