# Contributing

Thank you for your interest in contributing to secretscope.

## Development Setup

```bash
git clone https://github.com/superwes55/superwes55.git
cd superwes55
pip install -e ".[dev]"
playwright install chromium
```

## Running Tests

```bash
pytest --cov=secretscope tests/
```

## Linting & Type Checking

```bash
ruff check src/ tests/
mypy src/
```

## Adding Rules

See the [Rule Authoring Guide](README.md#rule-authoring-guide) in the README.

## Pull Requests

- Keep PRs focused on a single change.
- Add or update tests for any new behaviour.
- Run the full lint + test suite before opening a PR.
