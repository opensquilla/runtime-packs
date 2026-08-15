#!/usr/bin/env python3
"""Validate the reviewed Runtime Pack source pins and native-runner matrix."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

TARGET_COMPONENTS = {
    "darwin-arm64": ("python", "node"),
    "darwin-x64": ("python", "node"),
    "linux-arm64": ("python", "node"),
    "linux-x64": ("python", "node"),
    "windows-arm64": ("python", "node", "gitBash"),
    "windows-x64": ("python", "node", "gitBash"),
}
COMPONENT_EXECUTABLES = {
    "python": {"python"},
    "node": {"node", "npm", "npx"},
    "gitBash": {"git", "bash"},
}
COMPONENT_HOSTS = {
    "python": {"github.com"},
    "node": {"nodejs.org"},
    "gitBash": {"github.com"},
}
ARCHIVE_TYPES = {"tar.gz", "tar.xz", "zip", "7z-sfx"}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SAFE_VALUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
CATALOG_VERSION_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})\.([1-9]\d*)$")


class SourceValidationError(ValueError):
    """Raised when reviewed source metadata is incomplete or unsafe."""


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SourceValidationError(f"{field} must be an object")
    return value


def _text(value: Any, field: str) -> str:
    text = value if isinstance(value, str) else ""
    if not SAFE_VALUE_RE.fullmatch(text):
        raise SourceValidationError(f"{field} is invalid")
    return text


def _relative(value: Any, field: str, *, allow_dot: bool = False) -> str:
    if not isinstance(value, str) or not value:
        raise SourceValidationError(f"{field} must be a non-empty path")
    normalized = value.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts or (not allow_dot and path == PurePosixPath(".")):
        raise SourceValidationError(f"{field} must stay inside payload")
    if any(part in {"", "."} for part in path.parts if not (allow_dot and part == ".")):
        raise SourceValidationError(f"{field} is not normalized")
    return normalized


def _validate_component(target: str, component_id: str, value: Any) -> None:
    field = f"targets.{target}.{component_id}"
    component = _mapping(value, field)
    expected = {
        "version",
        "url",
        "sha256",
        "archiveType",
        "stripComponents",
        "binDirs",
        "executables",
    }
    if set(component) != expected:
        raise SourceValidationError(f"{field} fields must be exactly {sorted(expected)}")
    _text(component["version"], f"{field}.version")
    url = component["url"]
    if not isinstance(url, str):
        raise SourceValidationError(f"{field}.url must be a string")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in COMPONENT_HOSTS[component_id]:
        raise SourceValidationError(f"{field}.url has an unapproved origin")
    if (
        parsed.username
        or parsed.password
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise SourceValidationError(
            f"{field}.url must not contain credentials, ports, queries, or fragments"
        )
    if not parsed.path.startswith("/") or parsed.path.endswith("/"):
        raise SourceValidationError(f"{field}.url must identify one immutable asset path")
    if not SHA256_RE.fullmatch(str(component["sha256"])):
        raise SourceValidationError(f"{field}.sha256 must be lowercase SHA-256")
    if component["archiveType"] not in ARCHIVE_TYPES:
        raise SourceValidationError(f"{field}.archiveType is unsupported")
    if (component["archiveType"] == "7z-sfx") != (component_id == "gitBash"):
        raise SourceValidationError("7z-sfx is allowed only for Git Bash")
    strip_components = component["stripComponents"]
    if isinstance(strip_components, bool) or not isinstance(strip_components, int):
        raise SourceValidationError(f"{field}.stripComponents must be an integer")
    if not 0 <= strip_components <= 4:
        raise SourceValidationError(f"{field}.stripComponents is outside the safety limit")
    bin_dirs = component["binDirs"]
    if not isinstance(bin_dirs, Sequence) or isinstance(bin_dirs, str | bytes) or not bin_dirs:
        raise SourceValidationError(f"{field}.binDirs must be a non-empty array")
    for index, directory in enumerate(bin_dirs):
        _relative(directory, f"{field}.binDirs[{index}]", allow_dot=True)
    executables = _mapping(component["executables"], f"{field}.executables")
    if set(executables) != COMPONENT_EXECUTABLES[component_id]:
        raise SourceValidationError(f"{field}.executables has an incomplete executable set")
    for name, executable in executables.items():
        _relative(executable, f"{field}.executables.{name}")


def validate_sources(raw: Any) -> dict[str, Any]:
    root = dict(_mapping(raw, "sources"))
    if set(root) != {
        "schemaVersion",
        "catalogVersion",
        "releaseTag",
        "sourceDateEpoch",
        "targets",
    }:
        raise SourceValidationError("sources contains unknown or missing top-level fields")
    if root["schemaVersion"] != 1:
        raise SourceValidationError("schemaVersion must be 1")
    catalog_version = _text(root["catalogVersion"], "catalogVersion")
    match = CATALOG_VERSION_RE.fullmatch(catalog_version)
    if match is None:
        raise SourceValidationError("catalogVersion must be YYYY-MM-DD.revision")
    try:
        catalog_date = datetime(
            int(match.group(1)), int(match.group(2)), int(match.group(3)), tzinfo=UTC
        )
    except ValueError as exc:
        raise SourceValidationError("catalogVersion contains an invalid calendar date") from exc
    expected_tag = "v" + catalog_version.replace("-", ".", 2)
    if root["releaseTag"] != expected_tag:
        raise SourceValidationError(
            "releaseTag must use the vYYYY.MM.DD.revision spelling of catalogVersion"
        )
    epoch = root["sourceDateEpoch"]
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch <= 0:
        raise SourceValidationError("sourceDateEpoch must be a positive integer")
    if epoch != int(catalog_date.timestamp()):
        raise SourceValidationError("sourceDateEpoch must be catalog-date midnight UTC")
    targets = _mapping(root["targets"], "targets")
    if set(targets) != set(TARGET_COMPONENTS):
        raise SourceValidationError("targets must contain the complete six-target matrix")
    seen_urls: set[str] = set()
    component_versions: dict[str, str] = {}
    for target, expected_components in TARGET_COMPONENTS.items():
        target_value = _mapping(targets[target], f"targets.{target}")
        if set(target_value) != {"runner", *expected_components}:
            raise SourceValidationError(f"targets.{target} has an incomplete component matrix")
        runner = target_value["runner"]
        expected_runner = ["self-hosted", "opensquilla-runtime", target]
        if target.startswith("linux-"):
            expected_runner.append("glibc")
        if not isinstance(runner, list) or runner != expected_runner:
            raise SourceValidationError(
                f"targets.{target}.runner must exactly identify the native organization runner"
            )
        for component_id in expected_components:
            component = target_value[component_id]
            _validate_component(target, component_id, component)
            component_mapping = _mapping(component, "component")
            url = str(component_mapping["url"])
            if url in seen_urls:
                raise SourceValidationError(f"upstream URL is reused: {url}")
            seen_urls.add(url)
            version = str(component_mapping["version"])
            previous_version = component_versions.setdefault(component_id, version)
            if version != previous_version:
                raise SourceValidationError(
                    f"{component_id} version differs across native targets"
                )
    return root


def load_sources(path: str | Path) -> dict[str, Any]:
    source_path = Path(path)
    try:
        raw = json.loads(source_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SourceValidationError(f"cannot read {source_path}: {exc}") from exc
    return validate_sources(raw)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    sources = load_sources(args.path)
    component_count = sum(len(TARGET_COMPONENTS[target]) for target in sources["targets"])
    print(
        f"validated catalog {sources['catalogVersion']}: "
        f"{len(TARGET_COMPONENTS)} targets, {component_count} component packs"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
