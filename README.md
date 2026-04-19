# secretscope

[![CI](https://github.com/superwes55/superwes55/actions/workflows/ci.yml/badge.svg)](https://github.com/superwes55/superwes55/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A passive CLI security scanner that detects externally exposed secrets, API keys, tokens, and credentials in web applications — including those assembled at runtime by JavaScript.

> **Authorized use only.** Only scan applications you own or have explicit written permission to test.

---

## Features

- **Full JS rendering** via headless Chromium (Playwright): captures runtime-built DOM, dynamic scripts, XHR/fetch responses, and sourcemaps
- **27 built-in detection rules**: AWS, GCP, Azure, JWT, GitHub, Stripe, Slack, Twilio, private keys, and more
- **Shannon entropy filtering** to reduce false positives on generic patterns
- **Three scan modes**: single URL, BFS crawler, and batch file
- **Pluggable YAML rule engine**: drop in `.yaml` files to add custom patterns
- **JSON + self-contained HTML reports** with severity filters and full-text search
- **Robots.txt aware** (honours `*` and `secretscope` user-agent directives)
- **Cross-surface deduplication**: same secret in HTML and an inline script appears once

---

## Architecture

```
secretscope
├── fetcher/
│   ├── renderer.py      # Playwright headless rendering + network interception
│   └── crawler.py       # BFS crawler with robots.txt and rate limiting
├── engine/
│   ├── rules.py         # YAML rule loader + regex/entropy scanner
│   └── entropy.py       # Shannon entropy with charset filtering
├── reporters/
│   ├── json_reporter.py # JSON output (stdout or file)
│   └── html_reporter.py # Self-contained HTML report (Jinja2)
├── scanner.py           # Orchestrates engine across all page surfaces
├── cli.py               # Typer CLI: scan url / crawl / batch
└── rules/               # Bundled YAML rule definitions
    ├── aws.yaml
    ├── gcp.yaml
    ├── azure.yaml
    ├── jwt.yaml
    ├── private_keys.yaml
    ├── web_services.yaml
    └── generic.yaml
```

**Data flow:**

```
URL(s)
  └─► Renderer (Playwright)
        ├── final rendered HTML
        ├── inline <script> blocks
        ├── network responses (JS, JSON, CSS, sourcemaps)
        └── browser console messages
              └─► scanner.py (deduplication)
                    └─► RuleEngine (regex + entropy per rule)
                          └─► [Finding, ...]
                                └─► JSON / HTML reporter
```

---

## Installation

Requires Python 3.11+ and a Chromium browser for rendering.

```bash
pip install secretscope          # install the package
playwright install chromium      # download the headless browser
```

### Development install

```bash
git clone https://github.com/superwes55/superwes55.git
cd superwes55
pip install -e ".[dev]"
playwright install chromium
```

---

## Quick start

### Scan a single URL

```bash
secretscope scan url https://example.com
```

Output defaults to a colour summary on stderr. Add `--quiet` for pure JSON stdout:

```bash
secretscope scan url https://example.com --quiet | jq .
```

Save an HTML report:

```bash
secretscope scan url https://example.com --output html --output-file report
# writes report.html
```

Save both JSON and HTML:

```bash
secretscope scan url https://example.com --output both --output-file report
# writes report.json and report.html
```

Fail with exit code 1 when critical findings are detected (useful in CI):

```bash
secretscope scan url https://example.com --fail-on critical
```

### Crawl a site (BFS)

```bash
secretscope scan crawl https://example.com --max-depth 3 --max-pages 50
```

Options:

| Flag | Default | Description |
|---|---|---|
| `--max-depth` | 2 | Maximum BFS depth |
| `--max-pages` | 100 | Page cap |
| `--concurrency` | 5 | Parallel page renders |
| `--rate-limit` | 1.0 | Seconds between batches |
| `--no-robots` | false | Ignore robots.txt |

### Batch scan from a file

```bash
secretscope scan batch urls.txt --output both --output-file results
```

`urls.txt` format — one URL per line, `#` comments ignored:

```
# production targets
https://app.example.com
https://api.example.com
# https://staging.example.com   (commented out)
```

---

## Output schema

JSON output from `--quiet` or `--output json`:

```json
{
  "target_url": "https://example.com",
  "scan_duration_seconds": 2.31,
  "pages_scanned": 1,
  "timestamp": "2024-01-15T12:00:00",
  "errors": [],
  "summary": {
    "total": 2,
    "by_severity": {
      "critical": 1,
      "high": 1,
      "medium": 0,
      "low": 0
    }
  },
  "findings": [
    {
      "rule_id": "aws_access_key_id",
      "rule_name": "AWS Access Key ID",
      "severity": "critical",
      "match": "AKIA...",
      "context": "...surrounding 120 chars...",
      "source_url": "https://example.com/bundle.js",
      "source_type": "external_js",
      "line_number": 42,
      "offset": 1337,
      "fingerprint": "sha256hex"
    }
  ]
}
```

`source_type` values: `html`, `inline_js`, `external_js`, `network_response`, `sourcemap`, `console`

---

## Writing custom rules

Create a `.yaml` file anywhere and pass `--rules-dir /path/to/rules/`:

```yaml
rules:
  - id: my_internal_token
    name: Internal Auth Token
    severity: high           # critical | high | medium | low
    pattern: 'MYAPP-[A-Za-z0-9]{32}'
    description: Internal service authentication token
    tags: [internal, auth]
    min_length: 38           # optional: reject shorter matches
    entropy_threshold: 3.5   # optional: Shannon entropy gate
    example: "MYAPP-<32-alphanumeric>"
```

Rules in the custom directory are merged with the built-in rules. To replace a built-in rule, give it the same `id`.

### Entropy thresholds

`entropy_threshold` is evaluated against the matched string using the maximum entropy across three charset families (Base64, Hex, and full Unicode). A threshold of `3.5` is a good starting point for tokens with mixed case and digits; use `4.5`+ for long random secrets.

---

## CI integration

```yaml
# .github/workflows/security-scan.yml
name: Secret scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install secretscope && playwright install chromium
      - run: secretscope scan url ${{ env.STAGING_URL }} --fail-on high --quiet
```

---

## Development

```bash
# Run tests (integration tests auto-skip without Playwright)
pytest

# With coverage
pytest --cov=secretscope --cov-report=term-missing

# Lint + format
ruff check src/ tests/
ruff format src/ tests/

# Type-check
mypy src/secretscope/
```

Tests are organised by layer:
- `tests/test_scanner.py` — scan orchestration and deduplication
- `tests/test_renderer.py` — renderer helpers and mocked Playwright
- `tests/test_reporters.py` — JSON and HTML reporter output
- `tests/test_cli.py` — CLI commands with mocked renderer

Integration tests (marked `@pytest.mark.integration`) require a real Playwright Chromium install and are skipped automatically when the browser is absent.

---

## Responsible use

secretscope is a **passive, read-only** tool. It:

- Makes no changes to target applications
- Does not exploit vulnerabilities — it only reports what is externally observable
- Respects `robots.txt` by default
- Truncates matched secrets in reports to limit exposure

**You are solely responsible for ensuring you have authorization before scanning any target.**

---

## License

MIT — see [LICENSE](LICENSE).
