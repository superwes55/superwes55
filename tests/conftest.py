"""Shared pytest fixtures."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from secretscope.engine.rules import RuleEngine

RULES_DIR = Path(__file__).parent.parent / "src" / "secretscope" / "rules"


def _playwright_available() -> bool:
    """Return True when a Playwright browser binary is reachable."""
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            exe = pw.chromium.executable_path
        return Path(exe).exists()
    except Exception:
        return False


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Auto-skip integration tests when Playwright browser is not installed."""
    if _playwright_available():
        return
    skip = pytest.mark.skip(reason="Playwright Chromium not installed — run `playwright install chromium`")
    for item in items:
        if item.get_closest_marker("integration"):
            item.add_marker(skip)


@pytest.fixture(scope="session")
def engine() -> RuleEngine:
    """RuleEngine loaded with the bundled default rule set."""
    return RuleEngine(rules_dir=RULES_DIR)


@pytest.fixture(scope="session")
def rules_dir() -> Path:
    return RULES_DIR
