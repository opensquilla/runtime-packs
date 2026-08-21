from __future__ import annotations

import json

import pytest

from scripts.ossutil_json import load_ossutil_json


def test_load_ossutil_json_accepts_elapsed_suffix(tmp_path) -> None:
    output = tmp_path / "response.json"
    output.write_text(
        json.dumps({"Status": "Enabled"}, indent=2) + "\n\n0.012345(s) elapsed\n",
        encoding="utf-8",
    )

    assert load_ossutil_json(output) == {"Status": "Enabled"}


def test_load_ossutil_json_rejects_unexpected_trailing_output(tmp_path) -> None:
    output = tmp_path / "response.json"
    output.write_text('{"Status": "Enabled"}\nwarning\n', encoding="utf-8")

    with pytest.raises(ValueError, match="unexpected output"):
        load_ossutil_json(output)


def test_load_ossutil_json_rejects_missing_document(tmp_path) -> None:
    output = tmp_path / "response.json"
    output.write_text("0.012345(s) elapsed\n", encoding="utf-8")

    with pytest.raises(ValueError, match="does not start"):
        load_ossutil_json(output)
