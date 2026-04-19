"""HTML reporter — renders a standalone, filterable report via Jinja2."""

from __future__ import annotations

from pathlib import Path

import jinja2

from secretscope.models import ScanResult

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(str(_TEMPLATE_DIR)),
    autoescape=jinja2.select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


def write_html(result: ScanResult, path: Path) -> None:
    """Render *result* as a self-contained HTML report and write it to *path*."""
    template = _env.get_template("report.html")
    data = result.to_dict()
    html = template.render(**data)
    path.write_text(html, encoding="utf-8")
