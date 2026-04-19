"""Output reporters: JSON and standalone HTML."""

from secretscope.reporters.json_reporter import write_json
from secretscope.reporters.html_reporter import write_html

__all__ = ["write_json", "write_html"]
