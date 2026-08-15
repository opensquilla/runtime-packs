from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from scripts.validate_sources import TARGET_COMPONENTS

ROOT = Path(__file__).resolve().parents[1]


def _workflow(name: str) -> tuple[str, dict]:
    text = (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")
    parsed = yaml.safe_load(text)
    assert isinstance(parsed, dict)
    assert isinstance(parsed.get("jobs"), dict)
    return text, parsed


def test_native_build_workflow_covers_exact_component_matrix() -> None:
    workflow, parsed = _workflow("build-release.yml")
    pairs = {
        (target, component)
        for target, component in re.findall(
            r"target: ([a-z0-9-]+), component: ([A-Za-z]+), runner:",
            workflow,
        )
    }
    expected = {
        (target, component)
        for target, components in TARGET_COMPONENTS.items()
        for component in components
    }
    assert pairs == expected
    sources = json.loads((ROOT / "sources.json").read_text(encoding="utf-8"))
    matrix = parsed["jobs"]["build"]["strategy"]["matrix"]["include"]
    for entry in matrix:
        assert json.loads(entry["runner"]) == sources["targets"][entry["target"]]["runner"]


def test_release_workflow_can_only_create_a_draft() -> None:
    workflow, _parsed = _workflow("build-release.yml")
    assert "--draft" in workflow
    assert "gh release create" in workflow
    assert "gh release edit" not in workflow
    assert "--latest" not in workflow
    assert '"refs/heads/main"' in workflow
    assert "Download and re-audit the exact Draft Release assets" in workflow
    assert "OPENSQUILLA_TRUSTED_WINDOWS_CI" in workflow


def test_oss_workflow_has_no_moving_alias_and_uses_separate_credentials() -> None:
    workflow, _parsed = _workflow("mirror-oss.yml")
    assert "runtime-packs/${RELEASE_TAG}/${name}" in workflow
    assert "RUNTIME_PACK_OSS_ACCESS_KEY_ID" in workflow
    assert "RUNTIME_PACK_OSS_ACCESS_KEY_SECRET" in workflow
    assert "stable.json" not in workflow
    assert "latest.json" not in workflow
    assert "/latest/" not in workflow
    assert ".immutable // false" in workflow
    assert "get-bucket-versioning" in workflow
    assert "list-objects-v2" in workflow
    assert "OSS exact object set mismatch" in workflow
    assert '"opensquilla-releases"' in workflow
    assert '"https://oss-cn-beijing.aliyuncs.com"' in workflow


def test_all_external_actions_are_pinned_to_full_commit_sha() -> None:
    for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        for action in re.findall(r"^\s*- uses:\s*([^\s#]+)", text, flags=re.MULTILINE):
            assert re.fullmatch(r"[^@]+@[0-9a-f]{40}", action), (path.name, action)


def test_every_workflow_is_valid_yaml() -> None:
    for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(parsed, dict), path.name
        assert isinstance(parsed.get("jobs"), dict), path.name


def test_catalog_identity_matches_release_tag_contract() -> None:
    sources = json.loads((ROOT / "sources.json").read_text(encoding="utf-8"))
    assert sources["catalogVersion"] == "2026-07-30.1"
    assert sources["releaseTag"] == "v2026.07.30.1"
