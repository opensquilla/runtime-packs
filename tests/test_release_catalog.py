from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

import scripts.generate_release as release_tools
from scripts.build_pack import sha256_file
from scripts.validate_sources import TARGET_COMPONENTS

ROOT = Path(__file__).resolve().parents[1]
CATALOG_COMPONENT_FIELDS = {
    "asset",
    "archiveType",
    "version",
    "sizeBytes",
    "unpackedSizeBytes",
    "sha256",
    "trustedArchiveSha256",
}


def _sources() -> dict[str, Any]:
    return json.loads((ROOT / "sources.json").read_text(encoding="utf-8"))


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _write_native_outputs(
    build_dir: Path,
    sources: Mapping[str, Any],
) -> dict[tuple[str, str], str]:
    catalog_version = sources["catalogVersion"]
    current_digests: dict[tuple[str, str], str] = {}
    for target, component_ids in TARGET_COMPONENTS.items():
        for component_id in component_ids:
            name = f"OpenSquilla-Runtime-{component_id}-{catalog_version}-{target}.tar.xz"
            pack_path = build_dir / target / name
            pack_path.parent.mkdir(parents=True, exist_ok=True)
            body = f"synthetic {target}/{component_id}\n".encode()
            pack_path.write_bytes(body)
            metadata = {
                "target": target,
                "componentId": component_id,
                "asset": name,
                "archiveType": "tar.xz",
                "version": sources["targets"][target][component_id]["version"],
                "sizeBytes": len(body),
                "unpackedSizeBytes": len(body),
                "sha256": sha256_file(pack_path),
            }
            pack_path.with_suffix(pack_path.suffix + ".json").write_text(
                json.dumps(metadata),
                encoding="utf-8",
            )
            current_digests[(target, component_id)] = metadata["sha256"]
    return current_digests


def _fake_pack_audit(
    _path: Path,
    metadata: Mapping[str, Any],
    _catalog_version: str,
    **_kwargs: Any,
) -> dict[str, str]:
    return {
        "documentNamespace": (
            "https://example.invalid/runtime-pack/"
            f"{metadata['target']}/{metadata['componentId']}"
        )
    }


def _build_release(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, dict[str, Any]]:
    sources = _sources()
    sources["targets"]["linux-x64"]["node"]["trustedArchiveSha256"] = [
        _digest("previous linux-x64 node pack")
    ]
    sources_path = tmp_path / "sources.json"
    sources_path.write_text(json.dumps(sources), encoding="utf-8")
    build_dir = tmp_path / "native"
    release_dir = tmp_path / "release"
    _write_native_outputs(build_dir, sources)
    monkeypatch.setattr(release_tools, "audit_pack_archive", _fake_pack_audit)
    catalog = release_tools.generate_release(sources_path, build_dir, release_dir)
    return sources_path, release_dir, catalog


def _write_catalog(release_dir: Path, catalog: Mapping[str, Any]) -> None:
    (release_dir / "runtime-pack-catalog.json").write_bytes(
        release_tools._json_bytes(catalog)
    )
    names = sorted(path.name for path in release_dir.iterdir() if path.name != "SHA256SUMS")
    (release_dir / "SHA256SUMS").write_text(
        "".join(f"{sha256_file(release_dir / name)}  {name}\n" for name in names),
        encoding="utf-8",
    )


def test_generator_emits_exact_client_compatible_trusted_history_field(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources_path, release_dir, catalog = _build_release(tmp_path, monkeypatch)

    emitted = json.loads(
        (release_dir / "runtime-pack-catalog.json").read_text(encoding="utf-8")
    )
    assert emitted == catalog
    assert release_tools.audit_published_release(sources_path, release_dir) == catalog
    entries = [
        entry
        for components in emitted["targets"].values()
        for entry in components.values()
    ]
    assert len(entries) == 14
    assert all(set(entry) == CATALOG_COMPONENT_FIELDS for entry in entries)
    assert emitted["targets"]["linux-x64"]["node"]["trustedArchiveSha256"] == [
        _digest("previous linux-x64 node pack")
    ]


def test_generator_rejects_current_pack_digest_in_trusted_history() -> None:
    current_digest = _digest("current pack")
    metadata = {
        "target": "linux-x64",
        "componentId": "node",
        "asset": "OpenSquilla-Runtime-node-test-linux-x64.tar.xz",
        "version": "test",
        "sizeBytes": 1,
        "unpackedSizeBytes": 1,
        "sha256": current_digest,
    }
    source_component = {"trustedArchiveSha256": [current_digest]}

    with pytest.raises(release_tools.ReleaseBuildError, match="current pack SHA-256"):
        release_tools._catalog_component_entry(metadata, source_component)


def test_generator_rejects_another_components_current_digest_in_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources = _sources()
    build_dir = tmp_path / "native"
    current_digests = _write_native_outputs(build_dir, sources)
    sources["targets"]["darwin-arm64"]["node"]["trustedArchiveSha256"] = [
        current_digests[("darwin-arm64", "python")]
    ]
    sources_path = tmp_path / "sources.json"
    sources_path.write_text(json.dumps(sources), encoding="utf-8")
    monkeypatch.setattr(release_tools, "audit_pack_archive", _fake_pack_audit)

    with pytest.raises(
        release_tools.ReleaseBuildError,
        match=r"current pack SHA-256 for darwin-arm64/python: darwin-arm64/node",
    ):
        release_tools.generate_release(sources_path, build_dir, tmp_path / "release")


def test_release_audit_requires_trusted_history_field(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources_path, release_dir, catalog = _build_release(tmp_path, monkeypatch)
    del catalog["targets"]["linux-x64"]["node"]["trustedArchiveSha256"]
    _write_catalog(release_dir, catalog)

    with pytest.raises(release_tools.ReleaseBuildError, match="catalog entry is invalid"):
        release_tools.audit_published_release(sources_path, release_dir)


def test_release_audit_rejects_history_different_from_reviewed_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources_path, release_dir, catalog = _build_release(tmp_path, monkeypatch)
    catalog["targets"]["linux-x64"]["node"]["trustedArchiveSha256"] = [
        _digest("unreviewed pack")
    ]
    _write_catalog(release_dir, catalog)

    with pytest.raises(release_tools.ReleaseBuildError, match="differs from reviewed sources"):
        release_tools.audit_published_release(sources_path, release_dir)


def test_release_audit_rejects_current_pack_digest_in_reviewed_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources_path, release_dir, catalog = _build_release(tmp_path, monkeypatch)
    current_digest = catalog["targets"]["linux-x64"]["node"]["sha256"]
    catalog["targets"]["linux-x64"]["node"]["trustedArchiveSha256"] = [current_digest]
    sources = json.loads(sources_path.read_text(encoding="utf-8"))
    sources["targets"]["linux-x64"]["node"]["trustedArchiveSha256"] = [current_digest]
    sources_path.write_text(json.dumps(sources), encoding="utf-8")
    (release_dir / "runtime-pack-sources.json").write_bytes(release_tools._json_bytes(sources))
    _write_catalog(release_dir, catalog)

    with pytest.raises(release_tools.ReleaseBuildError, match="current pack SHA-256"):
        release_tools.audit_published_release(sources_path, release_dir)


def test_release_audit_rejects_another_components_current_digest_in_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources_path, release_dir, catalog = _build_release(tmp_path, monkeypatch)
    current_digest = catalog["targets"]["darwin-arm64"]["python"]["sha256"]
    catalog["targets"]["linux-x64"]["node"]["trustedArchiveSha256"] = [current_digest]
    sources = json.loads(sources_path.read_text(encoding="utf-8"))
    sources["targets"]["linux-x64"]["node"]["trustedArchiveSha256"] = [current_digest]
    sources_path.write_text(json.dumps(sources), encoding="utf-8")
    (release_dir / "runtime-pack-sources.json").write_bytes(release_tools._json_bytes(sources))
    _write_catalog(release_dir, catalog)

    with pytest.raises(
        release_tools.ReleaseBuildError,
        match=r"current pack SHA-256 for darwin-arm64/python: linux-x64/node",
    ):
        release_tools.audit_published_release(sources_path, release_dir)
