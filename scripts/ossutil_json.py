"""Parse the JSON document emitted by ossutil API commands.

ossutil 2.x appends a human-readable elapsed-time line to otherwise valid JSON
output.  Keep accepting that documented CLI decoration while rejecting any
other trailing bytes so API responses remain fail-closed.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_ELAPSED_SUFFIX = re.compile(r"\d+(?:\.\d+)?\(s\) elapsed")


def load_ossutil_json(path: str | Path) -> Any:
    """Load one JSON document from an ossutil output file.

    The parser accepts leading whitespace and ossutil's trailing elapsed-time
    line, but rejects any other trailing output or malformed JSON.
    """

    raw = Path(path).read_text(encoding="utf-8")
    document = raw.lstrip("\ufeff \t\r\n")
    if not document.startswith(("{", "[")):
        raise ValueError("ossutil output does not start with a JSON object or array")
    decoder = json.JSONDecoder()
    value, end = decoder.raw_decode(document)
    trailing = document[end:].strip()
    if trailing and not _ELAPSED_SUFFIX.fullmatch(trailing):
        raise ValueError("unexpected output after ossutil JSON document")
    return value
