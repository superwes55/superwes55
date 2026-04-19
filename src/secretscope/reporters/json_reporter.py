"""JSON reporter — writes ScanResult to a file or stdout."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from secretscope.models import ScanResult


def write_json(result: ScanResult, path: Path | None = None) -> None:
    """Serialise *result* as pretty-printed JSON.

    If *path* is ``None`` the output is written to stdout; otherwise it is
    written to the file at *path* (created or overwritten).
    """
    payload = json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
    if path is None:
        sys.stdout.write(payload + "\n")
    else:
        path.write_text(payload + "\n", encoding="utf-8")
