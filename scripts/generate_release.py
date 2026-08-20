#!/usr/bin/env python3
"""Aggregate native build outputs into a complete immutable Runtime Pack release."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import tarfile
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from scripts.build_pack import (
    COPY_CHUNK_BYTES,
    MAX_EXPANSION_RATIO,
    MAX_MEMBERS,
    MAX_UNPACKED_BYTES,
    PackBuildError,
    _portable_key,
    _safe_member_path,
    sha256_file,
)
from scripts.validate_sources import TARGET_COMPONENTS, load_sources

PACK_TOP_LEVEL = {"pack-manifest.json", "payload", "licenses", "SBOM.spdx.json"}
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
ASSET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
PACK_METADATA_FIELDS = {
    "target",
    "componentId",
    "asset",
    "archiveType",
    "version",
    "sizeBytes",
    "unpackedSizeBytes",
    "sha256",
}
CATALOG_COMPONENT_BASE_FIELDS = {
    "asset",
    "archiveType",
    "version",
    "sizeBytes",
    "unpackedSizeBytes",
    "sha256",
}
CATALOG_COMPONENT_FIELDS = {
    *CATALOG_COMPONENT_BASE_FIELDS,
    "trustedArchiveSha256",
}


class ReleaseBuildError(RuntimeError):
    """Raised when native artifacts cannot form one complete release."""


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def _safe_name(raw: str) -> PurePosixPath:
    try:
        path = _safe_member_path(raw, 0)
    except PackBuildError as exc:
        raise ReleaseBuildError(f"unsafe pack member {raw!r}: {exc}") from exc
    if path is None:
        raise ReleaseBuildError("pack contains an empty member path")
    return path


def _validate_metadata(metadata: Mapping[str, Any], path: Path) -> None:
    if set(metadata) != PACK_METADATA_FIELDS:
        raise ReleaseBuildError(f"pack metadata fields are invalid: {path.name}")
    for field in ("target", "componentId", "asset", "archiveType", "version"):
        if not isinstance(metadata[field], str) or not metadata[field]:
            raise ReleaseBuildError(f"pack metadata {field} is invalid: {path.name}")
    for field in ("sizeBytes", "unpackedSizeBytes"):
        value = metadata[field]
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ReleaseBuildError(f"pack metadata {field} is invalid: {path.name}")
    if metadata["unpackedSizeBytes"] > MAX_UNPACKED_BYTES:
        raise ReleaseBuildError(f"pack metadata unpacked size is unsafe: {path.name}")
    if not SHA_RE.fullmatch(str(metadata["sha256"])):
        raise ReleaseBuildError(f"pack metadata SHA-256 is invalid: {path.name}")


def _catalog_component_entry(
    metadata: Mapping[str, Any],
    source_component: Mapping[str, Any],
) -> dict[str, Any]:
    trusted_archive_sha256 = list(source_component["trustedArchiveSha256"])
    if metadata["sha256"] in trusted_archive_sha256:
        raise ReleaseBuildError(
            "trusted Runtime Pack archive history contains the current pack SHA-256: "
            f"{metadata['target']}/{metadata['componentId']}"
        )
    return {
        "asset": metadata["asset"],
        "archiveType": "tar.xz",
        "version": metadata["version"],
        "sizeBytes": metadata["sizeBytes"],
        "unpackedSizeBytes": metadata["unpackedSizeBytes"],
        "sha256": metadata["sha256"],
        "trustedArchiveSha256": trusted_archive_sha256,
    }


def _validate_release_archive_history(
    current_archive_sha256: Mapping[tuple[str, str], str],
    sources: Mapping[str, Any],
) -> None:
    current_owners = {
        digest: f"{target}/{component_id}"
        for (target, component_id), digest in current_archive_sha256.items()
    }
    for target, component_ids in TARGET_COMPONENTS.items():
        for component_id in component_ids:
            history = sources["targets"][target][component_id]["trustedArchiveSha256"]
            for digest in history:
                current_owner = current_owners.get(digest)
                if current_owner is not None:
                    raise ReleaseBuildError(
                        "trusted Runtime Pack archive history contains a current pack "
                        f"SHA-256 for {current_owner}: {target}/{component_id}"
                    )


def _register_pack_path(
    relative: PurePosixPath,
    kind: str,
    kinds: dict[str, str],
    parent_keys: set[str],
    *,
    case_sensitive: bool,
) -> None:
    key = _portable_key(relative, case_sensitive=case_sensitive)
    if key in kinds:
        raise ReleaseBuildError(f"pack has duplicate paths: {relative}")
    ancestors = [PurePosixPath(*relative.parts[:index]) for index in range(1, len(relative.parts))]
    for ancestor in ancestors:
        ancestor_kind = kinds.get(_portable_key(ancestor, case_sensitive=case_sensitive))
        if ancestor_kind is not None and ancestor_kind != "directory":
            raise ReleaseBuildError(f"pack path descends through a file: {relative}")
    if kind != "directory" and key in parent_keys:
        raise ReleaseBuildError(f"pack file shadows an existing directory: {relative}")
    kinds[key] = kind
    parent_keys.update(
        _portable_key(ancestor, case_sensitive=case_sensitive) for ancestor in ancestors
    )


def _read_member_bytes(archive: tarfile.TarFile, member: tarfile.TarInfo, limit: int) -> bytes:
    if member.size > limit:
        raise ReleaseBuildError(f"pack metadata file is too large: {member.name}")
    extracted = archive.extractfile(member)
    if extracted is None:
        raise ReleaseBuildError(f"cannot read pack member: {member.name}")
    with extracted:
        value = extracted.read(limit + 1)
    if len(value) != member.size or len(value) > limit:
        raise ReleaseBuildError(f"pack member size mismatch: {member.name}")
    return value


def _hash_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    extracted = archive.extractfile(member)
    if extracted is None:
        raise ReleaseBuildError(f"cannot read pack member: {member.name}")
    digest = hashlib.sha256()
    received = 0
    with extracted:
        for chunk in iter(lambda: extracted.read(COPY_CHUNK_BYTES), b""):
            received += len(chunk)
            if received > member.size:
                raise ReleaseBuildError(f"pack member exceeded its declared size: {member.name}")
            digest.update(chunk)
    if received != member.size:
        raise ReleaseBuildError(f"pack member ended before its declared size: {member.name}")
    return digest.hexdigest()


def audit_pack_archive(
    path: Path,
    metadata: Mapping[str, Any],
    catalog_version: str,
    *,
    source_date_epoch: int | None = None,
    expected_component: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    _validate_metadata(metadata, path)
    if path.stat().st_size != metadata.get("sizeBytes"):
        raise ReleaseBuildError(f"pack size mismatch: {path.name}")
    digest = sha256_file(path)
    if digest != metadata.get("sha256") or not SHA_RE.fullmatch(digest):
        raise ReleaseBuildError(f"pack digest mismatch: {path.name}")
    kinds: dict[str, str] = {}
    parent_keys: set[str] = set()
    top_level: set[str] = set()
    total_bytes = 0
    manifest_bytes: bytes | None = None
    sbom_bytes: bytes | None = None
    payload_hashes: dict[str, str] = {}
    license_files = 0
    member_names: list[str] = []
    case_sensitive_paths = str(metadata["target"]).startswith("linux-")
    with tarfile.open(path, mode="r:xz") as archive:
        for index, member in enumerate(archive, 1):
            if index > MAX_MEMBERS:
                raise ReleaseBuildError(f"pack has too many members: {path.name}")
            relative = _safe_name(member.name)
            top_level.add(relative.parts[0])
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise ReleaseBuildError(f"pack contains a link or special file: {path.name}")
            if member.isdir():
                kind = "directory"
            elif member.isfile():
                kind = "file"
            else:
                raise ReleaseBuildError(f"pack contains an unsupported member: {path.name}")
            _register_pack_path(
                relative,
                kind,
                kinds,
                parent_keys,
                case_sensitive=case_sensitive_paths,
            )
            member_names.append(relative.as_posix())
            if source_date_epoch is not None:
                if member.mtime != source_date_epoch or member.uid != 0 or member.gid != 0:
                    raise ReleaseBuildError(f"pack has non-deterministic metadata: {path.name}")
                if member.uname or member.gname:
                    raise ReleaseBuildError(f"pack records host ownership names: {path.name}")
                expected_modes = {0o755} if member.isdir() else {0o644, 0o755}
                if stat.S_IMODE(member.mode) not in expected_modes:
                    raise ReleaseBuildError(f"pack has a non-canonical mode: {path.name}")
            if member.isfile():
                if member.size < 0:
                    raise ReleaseBuildError(f"pack contains a negative file size: {path.name}")
                total_bytes += member.size
                if total_bytes > MAX_UNPACKED_BYTES:
                    raise ReleaseBuildError(f"pack exceeds unpacked-size limit: {path.name}")
                if total_bytes > path.stat().st_size * MAX_EXPANSION_RATIO:
                    raise ReleaseBuildError(f"pack expansion ratio is unsafe: {path.name}")
                if relative.as_posix() == "pack-manifest.json":
                    manifest_bytes = _read_member_bytes(archive, member, 1024 * 1024)
                elif relative.as_posix() == "SBOM.spdx.json":
                    sbom_bytes = _read_member_bytes(archive, member, 256 * 1024**2)
                elif relative.parts[0] == "payload":
                    payload_hashes["./" + relative.as_posix()] = _hash_member(archive, member)
                elif relative.parts[0] == "licenses":
                    license_files += 1
                    _hash_member(archive, member)
    if top_level != PACK_TOP_LEVEL:
        raise ReleaseBuildError(
            f"pack top-level entries differ from the contract: {path.name}: {sorted(top_level)}"
        )
    if total_bytes != metadata.get("unpackedSizeBytes"):
        raise ReleaseBuildError(f"pack unpacked-size mismatch: {path.name}")
    if member_names != sorted(member_names):
        raise ReleaseBuildError(f"pack member ordering is non-deterministic: {path.name}")
    if not payload_hashes or not license_files:
        raise ReleaseBuildError(f"pack payload or license set is empty: {path.name}")
    try:
        manifest = json.loads((manifest_bytes or b"").decode("utf-8"))
        sbom = json.loads((sbom_bytes or b"").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseBuildError(f"pack metadata is invalid JSON: {path.name}") from exc
    expected_manifest = {
        "schemaVersion": 1,
        "catalogVersion": catalog_version,
        "componentId": metadata["componentId"],
        "target": metadata["target"],
        "version": metadata["version"],
    }
    for field, expected in expected_manifest.items():
        if manifest.get(field) != expected:
            raise ReleaseBuildError(f"pack manifest {field} mismatch: {path.name}")
    if set(manifest) != {*expected_manifest, "executables", "binDirs"}:
        raise ReleaseBuildError(f"pack manifest is incomplete: {path.name}")
    if expected_component is not None:
        if manifest.get("executables") != expected_component.get("executables"):
            raise ReleaseBuildError(f"pack manifest executables mismatch: {path.name}")
        if manifest.get("binDirs") != expected_component.get("binDirs"):
            raise ReleaseBuildError(f"pack manifest binDirs mismatch: {path.name}")
    executables = manifest.get("executables")
    bin_dirs = manifest.get("binDirs")
    if not isinstance(executables, dict) or not executables:
        raise ReleaseBuildError(f"pack manifest executables are invalid: {path.name}")
    if not isinstance(bin_dirs, list) or not bin_dirs:
        raise ReleaseBuildError(f"pack manifest binDirs are invalid: {path.name}")
    for relative_executable in executables.values():
        if not isinstance(relative_executable, str):
            raise ReleaseBuildError(f"pack manifest executable path is invalid: {path.name}")
        executable_path = _safe_name("payload/" + relative_executable)
        if "./" + executable_path.as_posix() not in payload_hashes:
            raise ReleaseBuildError(f"pack executable is missing: {path.name}")
    for relative_directory in bin_dirs:
        if not isinstance(relative_directory, str):
            raise ReleaseBuildError(f"pack manifest bin directory is invalid: {path.name}")
        directory_name = "payload" if relative_directory == "." else "payload/" + relative_directory
        directory = _safe_name(directory_name)
        if kinds.get(
            _portable_key(directory, case_sensitive=case_sensitive_paths)
        ) != "directory" and not any(
            name.startswith("./" + directory.as_posix() + "/") for name in payload_hashes
        ):
            raise ReleaseBuildError(f"pack bin directory is missing: {path.name}")
    if sbom.get("spdxVersion") != "SPDX-2.3":
        raise ReleaseBuildError(f"pack SBOM is not SPDX 2.3: {path.name}")
    sbom_files = sbom.get("files")
    if not isinstance(sbom_files, list):
        raise ReleaseBuildError(f"pack SBOM files are invalid: {path.name}")
    sbom_hashes: dict[str, str] = {}
    spdx_ids: set[str] = set()
    for entry in sbom_files:
        if not isinstance(entry, dict):
            raise ReleaseBuildError(f"pack SBOM file entry is invalid: {path.name}")
        file_name = entry.get("fileName")
        spdx_id = entry.get("SPDXID")
        checksums = entry.get("checksums")
        if (
            not isinstance(file_name, str)
            or not file_name.startswith("./payload/")
            or not isinstance(spdx_id, str)
            or spdx_id in spdx_ids
            or not isinstance(checksums, list)
            or len(checksums) != 1
            or not isinstance(checksums[0], dict)
            or checksums[0].get("algorithm") != "SHA256"
            or not SHA_RE.fullmatch(str(checksums[0].get("checksumValue")))
        ):
            raise ReleaseBuildError(f"pack SBOM file entry is invalid: {path.name}")
        spdx_ids.add(spdx_id)
        if file_name in sbom_hashes:
            raise ReleaseBuildError(f"pack SBOM repeats a file: {path.name}")
        sbom_hashes[file_name] = str(checksums[0]["checksumValue"])
    if sbom_hashes != payload_hashes:
        raise ReleaseBuildError(f"pack SBOM does not match payload bytes: {path.name}")
    return sbom


def _metadata_files(build_dir: Path) -> dict[tuple[str, str], tuple[Path, dict[str, Any]]]:
    result: dict[tuple[str, str], tuple[Path, dict[str, Any]]] = {}
    for metadata_path in build_dir.rglob("OpenSquilla-Runtime-*.tar.xz.json"):
        if metadata_path.is_symlink() or not stat.S_ISREG(
            metadata_path.stat(follow_symlinks=False).st_mode
        ):
            raise ReleaseBuildError(f"native metadata is not a regular file: {metadata_path}")
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ReleaseBuildError(f"cannot read {metadata_path}: {exc}") from exc
        if not isinstance(metadata, dict):
            raise ReleaseBuildError(f"metadata must be an object: {metadata_path}")
        _validate_metadata(metadata, metadata_path)
        key = (str(metadata.get("target")), str(metadata.get("componentId")))
        if key in result:
            raise ReleaseBuildError(f"duplicate native build metadata: {key}")
        pack_path = metadata_path.with_suffix("")
        if (
            not pack_path.is_file()
            or pack_path.is_symlink()
            or not stat.S_ISREG(pack_path.stat(follow_symlinks=False).st_mode)
        ):
            raise ReleaseBuildError(f"native pack is missing: {pack_path}")
        result[key] = (pack_path, metadata)
    return result


def generate_release(sources_path: Path, build_dir: Path, output_dir: Path) -> dict[str, Any]:
    sources = load_sources(sources_path)
    catalog_version = sources["catalogVersion"]
    metadata_files = _metadata_files(build_dir)
    expected_keys = {
        (target, component_id)
        for target, component_ids in TARGET_COMPONENTS.items()
        for component_id in component_ids
    }
    if set(metadata_files) != expected_keys:
        missing = sorted(expected_keys - set(metadata_files))
        extra = sorted(set(metadata_files) - expected_keys)
        raise ReleaseBuildError(f"native pack matrix mismatch; missing={missing}, extra={extra}")
    _validate_release_archive_history(
        {key: metadata["sha256"] for key, (_path, metadata) in metadata_files.items()},
        sources,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    targets: dict[str, dict[str, Any]] = {target: {} for target in TARGET_COMPONENTS}
    pack_sboms: list[dict[str, Any]] = []
    pack_names: list[str] = []
    for target in sorted(TARGET_COMPONENTS):
        for component_id in TARGET_COMPONENTS[target]:
            pack_path, metadata = metadata_files[(target, component_id)]
            expected_name = f"OpenSquilla-Runtime-{component_id}-{catalog_version}-{target}.tar.xz"
            if pack_path.name != expected_name or metadata.get("asset") != expected_name:
                raise ReleaseBuildError(f"native pack filename mismatch: {target}/{component_id}")
            source_component = sources["targets"][target][component_id]
            if metadata.get("archiveType") != "tar.xz":
                raise ReleaseBuildError(
                    f"native pack archive type mismatch: {target}/{component_id}"
                )
            if metadata.get("version") != source_component["version"]:
                raise ReleaseBuildError(f"native pack version mismatch: {target}/{component_id}")
            sbom = audit_pack_archive(
                pack_path,
                metadata,
                catalog_version,
                source_date_epoch=sources["sourceDateEpoch"],
                expected_component=source_component,
            )
            pack_sboms.append(sbom)
            destination = output_dir / expected_name
            if destination.resolve() != pack_path.resolve():
                shutil.copyfile(pack_path, destination)
            targets[target][component_id] = _catalog_component_entry(
                metadata,
                source_component,
            )
            pack_names.append(expected_name)
    catalog = {
        "schemaVersion": 1,
        "catalogVersion": catalog_version,
        "releaseTag": sources["releaseTag"],
        "finalized": True,
        "targets": targets,
    }
    _atomic_write(output_dir / "runtime-pack-catalog.json", _json_bytes(catalog))
    _atomic_write(
        output_dir / "runtime-pack-sources.json",
        _json_bytes(sources),
    )
    notices = [
        "# OpenSquilla Runtime Pack Third-Party Notices",
        "",
        f"Catalog: `{catalog_version}`",
        "",
        "Every component archive contains the upstream license files collected from its payload.",
        "The source URLs and reviewed SHA-256 pins are published in `runtime-pack-sources.json`.",
        "",
    ]
    for target in sorted(TARGET_COMPONENTS):
        for component_id in TARGET_COMPONENTS[target]:
            component = sources["targets"][target][component_id]
            notices.append(
                f"- `{target}` / `{component_id}` {component['version']}: {component['url']}"
            )
    _atomic_write(output_dir / "THIRD_PARTY_NOTICES.md", ("\n".join(notices) + "\n").encode())
    aggregate_sbom = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"OpenSquilla Runtime Packs {catalog_version}",
        "documentNamespace": (
            "https://opensquilla.com/spdx/runtime-packs/release/"
            + hashlib.sha256(_json_bytes(catalog)).hexdigest()
        ),
        "creationInfo": {
            "created": datetime.fromtimestamp(sources["sourceDateEpoch"], UTC).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "creators": ["Tool: OpenSquilla Runtime Pack Builder"],
        },
        "externalDocumentRefs": [
            {
                "externalDocumentId": f"DocumentRef-Pack-{index:02d}",
                "spdxDocument": sbom["documentNamespace"],
                "checksum": {
                    "algorithm": "SHA256",
                    "checksumValue": hashlib.sha256(_json_bytes(sbom)).hexdigest(),
                },
            }
            for index, sbom in enumerate(pack_sboms, 1)
        ],
    }
    _atomic_write(output_dir / "SBOM.spdx.json", _json_bytes(aggregate_sbom))
    checksummed = sorted(
        [
            *pack_names,
            "runtime-pack-catalog.json",
            "runtime-pack-sources.json",
            "THIRD_PARTY_NOTICES.md",
            "SBOM.spdx.json",
        ]
    )
    checksum_lines = [f"{sha256_file(output_dir / name)}  {name}" for name in checksummed]
    _atomic_write(output_dir / "SHA256SUMS", ("\n".join(checksum_lines) + "\n").encode())
    audit_published_release(sources_path, output_dir)
    return catalog


def audit_release_directory(root: Path, *, expected_names: set[str] | None = None) -> None:
    if not root.is_dir() or root.is_symlink():
        raise ReleaseBuildError("release path must be a real directory")
    entries = list(root.iterdir())
    for path in entries:
        metadata = path.stat(follow_symlinks=False)
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ReleaseBuildError(f"release contains a non-regular asset: {path.name}")
        if not ASSET_RE.fullmatch(path.name):
            raise ReleaseBuildError(f"release contains an unsafe asset name: {path.name}")
    actual = {path.name for path in entries}
    checksum_path = root / "SHA256SUMS"
    if not checksum_path.is_file():
        raise ReleaseBuildError("release is missing SHA256SUMS")
    listed: set[str] = set()
    for line_number, line in enumerate(checksum_path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            digest, name = line.split(None, 1)
        except ValueError as exc:
            raise ReleaseBuildError(f"invalid SHA256SUMS line {line_number}") from exc
        name = name.lstrip("*")
        if (
            not SHA_RE.fullmatch(digest)
            or not ASSET_RE.fullmatch(name)
            or Path(name).name != name
            or name == "SHA256SUMS"
        ):
            raise ReleaseBuildError(f"unsafe SHA256SUMS line {line_number}")
        if name in listed:
            raise ReleaseBuildError(f"duplicate SHA256SUMS entry: {name}")
        listed.add(name)
        path = root / name
        if not path.is_file() or sha256_file(path) != digest:
            raise ReleaseBuildError(f"SHA256SUMS mismatch: {name}")
    contract = expected_names or {*listed, "SHA256SUMS"}
    if actual != contract or listed != contract - {"SHA256SUMS"}:
        raise ReleaseBuildError(
            "release exact asset set mismatch; "
            f"actual={sorted(actual)}, expected={sorted(contract)}"
        )


def audit_published_release(
    sources_path: Path,
    release_dir: Path,
) -> dict[str, Any]:
    sources = load_sources(sources_path)
    expected_pack_names = {
        f"OpenSquilla-Runtime-{component_id}-{sources['catalogVersion']}-{target}.tar.xz"
        for target, component_ids in TARGET_COMPONENTS.items()
        for component_id in component_ids
    }
    expected_names = {
        *expected_pack_names,
        "runtime-pack-catalog.json",
        "runtime-pack-sources.json",
        "THIRD_PARTY_NOTICES.md",
        "SBOM.spdx.json",
        "SHA256SUMS",
    }
    audit_release_directory(release_dir, expected_names=expected_names)
    catalog_path = release_dir / "runtime-pack-catalog.json"
    sources_copy_path = release_dir / "runtime-pack-sources.json"
    try:
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        sources_copy = json.loads(sources_copy_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseBuildError(f"release catalog metadata is unreadable: {exc}") from exc
    if sources_copy != sources:
        raise ReleaseBuildError("release source pins differ from the reviewed repository sources")
    if not isinstance(catalog, dict) or set(catalog) != {
        "schemaVersion",
        "catalogVersion",
        "releaseTag",
        "finalized",
        "targets",
    }:
        raise ReleaseBuildError("release catalog has invalid top-level fields")
    if (
        catalog.get("schemaVersion") != 1
        or catalog.get("catalogVersion") != sources["catalogVersion"]
        or catalog.get("releaseTag") != sources["releaseTag"]
        or catalog.get("finalized") is not True
    ):
        raise ReleaseBuildError("release catalog identity differs from reviewed sources")
    targets = catalog.get("targets")
    if not isinstance(targets, dict) or set(targets) != set(TARGET_COMPONENTS):
        raise ReleaseBuildError("release catalog target matrix is incomplete")

    current_archive_sha256: dict[tuple[str, str], str] = {}
    for target, component_ids in TARGET_COMPONENTS.items():
        components = targets.get(target)
        if not isinstance(components, dict) or set(components) != set(component_ids):
            raise ReleaseBuildError(f"release catalog components are incomplete: {target}")
        for component_id in component_ids:
            value = components[component_id]
            if not isinstance(value, dict) or set(value) != CATALOG_COMPONENT_FIELDS:
                raise ReleaseBuildError(
                    f"release catalog entry is invalid: {target}/{component_id}"
                )
            current_archive_sha256[(target, component_id)] = str(value["sha256"])
    _validate_release_archive_history(current_archive_sha256, sources)

    pack_names: set[str] = set()
    pack_sboms: list[dict[str, Any]] = []
    for target, component_ids in TARGET_COMPONENTS.items():
        components = targets[target]
        for component_id in component_ids:
            value = components[component_id]
            expected_name = (
                f"OpenSquilla-Runtime-{component_id}-{sources['catalogVersion']}-{target}.tar.xz"
            )
            source_component = sources["targets"][target][component_id]
            metadata = {
                "target": target,
                "componentId": component_id,
                **{field: value[field] for field in CATALOG_COMPONENT_BASE_FIELDS},
            }
            expected_entry = _catalog_component_entry(metadata, source_component)
            if (
                value.get("asset") != expected_name
                or value.get("archiveType") != "tar.xz"
                or value.get("version") != source_component["version"]
                or value != expected_entry
            ):
                raise ReleaseBuildError(
                    f"release catalog entry differs from reviewed sources: {target}/{component_id}"
                )
            pack_sboms.append(
                audit_pack_archive(
                    release_dir / expected_name,
                    metadata,
                    sources["catalogVersion"],
                    source_date_epoch=sources["sourceDateEpoch"],
                    expected_component=source_component,
                )
            )
            pack_names.add(expected_name)

    if pack_names != expected_pack_names:
        raise ReleaseBuildError("release catalog pack asset set is incomplete")
    try:
        aggregate_sbom = json.loads(
            (release_dir / "SBOM.spdx.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseBuildError(f"aggregate SBOM is unreadable: {exc}") from exc
    if aggregate_sbom.get("spdxVersion") != "SPDX-2.3":
        raise ReleaseBuildError("aggregate SBOM is not SPDX 2.3")
    expected_external_refs = [
        {
            "externalDocumentId": f"DocumentRef-Pack-{index:02d}",
            "spdxDocument": sbom["documentNamespace"],
            "checksum": {
                "algorithm": "SHA256",
                "checksumValue": hashlib.sha256(_json_bytes(sbom)).hexdigest(),
            },
        }
        for index, sbom in enumerate(pack_sboms, 1)
    ]
    if aggregate_sbom.get("externalDocumentRefs") != expected_external_refs:
        raise ReleaseBuildError("aggregate SBOM does not reference the exact pack SBOM set")
    try:
        notices = (release_dir / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ReleaseBuildError(f"third-party notices are unreadable: {exc}") from exc
    for target, component_ids in TARGET_COMPONENTS.items():
        for component_id in component_ids:
            component = sources["targets"][target][component_id]
            if component["url"] not in notices or component["version"] not in notices:
                raise ReleaseBuildError(
                    f"third-party notices omit {target}/{component_id}"
                )
    return catalog


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", type=Path, default=Path("sources.json"))
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--audit-only", action="store_true")
    args = parser.parse_args()
    if args.audit_only:
        audit_published_release(args.sources, args.output_dir)
    else:
        if args.build_dir is None:
            parser.error("--build-dir is required unless --audit-only is used")
        catalog = generate_release(args.sources, args.build_dir, args.output_dir)
        print(json.dumps(catalog, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
