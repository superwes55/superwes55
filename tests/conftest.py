"""Shared pytest fixtures."""

from pathlib import Path
import pytest
from secretscope.engine.rules import RuleEngine

RULES_DIR = Path(__file__).parent.parent / "src" / "secretscope" / "rules"


@pytest.fixture(scope="session")
def engine() -> RuleEngine:
    """RuleEngine loaded with the bundled default rule set."""
    return RuleEngine(rules_dir=RULES_DIR)


@pytest.fixture(scope="session")
def rules_dir() -> Path:
    return RULES_DIR
