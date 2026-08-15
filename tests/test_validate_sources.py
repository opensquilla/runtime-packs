from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from scripts.validate_sources import SourceValidationError, load_sources, validate_sources

ROOT = Path(__file__).resolve().parents[1]


def _valid() -> dict:
    return json.loads((ROOT / "sources.json").read_text(encoding="utf-8"))


def test_checked_in_sources_are_complete_and_native() -> None:
    value = load_sources(ROOT / "sources.json")
    assert value["catalogVersion"] == "2026-07-30.1"
    assert set(value["targets"]) == {
        "darwin-arm64",
        "darwin-x64",
        "linux-arm64",
        "linux-x64",
        "windows-arm64",
        "windows-x64",
    }


def test_rejects_non_https_or_unapproved_origin() -> None:
    value = _valid()
    value["targets"]["darwin-arm64"]["python"]["url"] = "https://example.com/python.tgz"
    with pytest.raises(SourceValidationError, match="unapproved origin"):
        validate_sources(value)


def test_rejects_missing_native_runner_label() -> None:
    value = _valid()
    value["targets"]["windows-arm64"]["runner"] = ["self-hosted", "opensquilla-runtime"]
    with pytest.raises(SourceValidationError, match="native organization runner"):
        validate_sources(value)


def test_rejects_extra_runner_label() -> None:
    value = _valid()
    value["targets"]["darwin-arm64"]["runner"].append("unreviewed-runner")
    with pytest.raises(SourceValidationError, match="exactly identify"):
        validate_sources(value)


def test_rejects_git_sfx_for_non_git_component() -> None:
    value = _valid()
    value["targets"]["windows-x64"]["python"]["archiveType"] = "7z-sfx"
    with pytest.raises(SourceValidationError, match="only for Git Bash"):
        validate_sources(value)


def test_rejects_payload_escape() -> None:
    value = copy.deepcopy(_valid())
    value["targets"]["linux-x64"]["node"]["executables"]["node"] = "../node"
    with pytest.raises(SourceValidationError, match="inside payload"):
        validate_sources(value)


def test_rejects_mutable_or_signed_source_url() -> None:
    value = _valid()
    value["targets"]["linux-x64"]["node"]["url"] += "?token=temporary"
    with pytest.raises(SourceValidationError, match="queries"):
        validate_sources(value)


def test_rejects_cross_target_version_drift() -> None:
    value = _valid()
    value["targets"]["linux-x64"]["node"]["version"] = "24.18.2"
    with pytest.raises(SourceValidationError, match="differs across native targets"):
        validate_sources(value)


def test_rejects_source_date_epoch_unrelated_to_catalog_date() -> None:
    value = _valid()
    value["sourceDateEpoch"] += 1
    with pytest.raises(SourceValidationError, match="midnight UTC"):
        validate_sources(value)
