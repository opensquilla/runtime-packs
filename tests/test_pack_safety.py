from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from scripts.build_pack import (
    PackBuildError,
    _audit_7z_listing_text,
    _deterministic_tar_xz,
    _extract_tar,
    sha256_file,
)
from scripts.generate_release import (
    ReleaseBuildError,
    audit_pack_archive,
    audit_release_directory,
)


def _tar_member(path: Path, name: str, data: bytes, *, kind: bytes | None = None) -> None:
    with tarfile.open(path, "w:gz") as archive:
        info = tarfile.TarInfo(name)
        info.size = len(data)
        if kind is not None:
            info.type = kind
            info.linkname = "../../outside"
            info.size = 0
        archive.addfile(info, io.BytesIO(data) if info.size else None)


def test_tar_extraction_rejects_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "input.tar.gz"
    _tar_member(archive, "root/../../outside", b"bad")
    with pytest.raises(PackBuildError, match="escapes payload"):
        _extract_tar(archive, tmp_path / "payload", 1)
    assert not (tmp_path / "outside").exists()


def test_tar_extraction_rejects_links(tmp_path: Path) -> None:
    archive = tmp_path / "input.tar.gz"
    _tar_member(archive, "root/link", b"", kind=tarfile.SYMTYPE)
    with pytest.raises(PackBuildError, match="link escapes payload"):
        _extract_tar(archive, tmp_path / "payload", 1)


def test_tar_extraction_materializes_safe_internal_symlink(tmp_path: Path) -> None:
    archive = tmp_path / "input.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        directory = tarfile.TarInfo("root/lib/")
        directory.type = tarfile.DIRTYPE
        handle.addfile(directory)
        target = tarfile.TarInfo("root/lib/tool")
        target.mode = 0o755
        target.size = len(b"tool\n")
        handle.addfile(target, io.BytesIO(b"tool\n"))
        link = tarfile.TarInfo("root/bin/tool")
        link.type = tarfile.SYMTYPE
        link.linkname = "../lib/tool"
        handle.addfile(link)
    payload = tmp_path / "payload"
    _extract_tar(archive, payload, 1)
    assert (payload / "bin" / "tool").read_bytes() == b"tool\n"
    assert not (payload / "bin" / "tool").is_symlink()


@pytest.mark.parametrize("name", ["root/NUL.txt", "root/file:stream", "root/trailing. "])
def test_tar_extraction_rejects_nonportable_names(tmp_path: Path, name: str) -> None:
    archive = tmp_path / "input.tar.gz"
    _tar_member(archive, name, b"bad")
    with pytest.raises(PackBuildError, match="portable|device|suffix"):
        _extract_tar(archive, tmp_path / "payload", 1)


def test_tar_extraction_rejects_file_directory_shadowing(tmp_path: Path) -> None:
    archive = tmp_path / "input.tar.gz"
    with tarfile.open(archive, "w:gz") as handle:
        parent = tarfile.TarInfo("root/path")
        parent.size = 1
        handle.addfile(parent, io.BytesIO(b"x"))
        child = tarfile.TarInfo("root/path/child")
        child.size = 1
        handle.addfile(child, io.BytesIO(b"y"))
    with pytest.raises(PackBuildError, match="descends through a file"):
        _extract_tar(archive, tmp_path / "payload", 1)


def test_git_sfx_listing_rejects_traversal_and_links() -> None:
    with pytest.raises(PackBuildError, match="escapes payload"):
        _audit_7z_listing_text("Path = ../../outside.exe\n")
    with pytest.raises(PackBuildError, match="contains a link"):
        _audit_7z_listing_text("Path = bin/bash.exe\nSymbolic Link = ../../outside\n")


def test_deterministic_tar_has_identical_bytes(tmp_path: Path) -> None:
    source = tmp_path / "source"
    (source / "payload" / "bin").mkdir(parents=True)
    executable = source / "payload" / "bin" / "tool"
    executable.write_bytes(b"tool\n")
    executable.chmod(0o755)
    first = tmp_path / "first.tar.xz"
    second = tmp_path / "second.tar.xz"
    _deterministic_tar_xz(source, first, 1_785_369_600)
    _deterministic_tar_xz(source, second, 1_785_369_600)
    assert first.read_bytes() == second.read_bytes()


def test_pack_audit_checks_contract_and_metadata(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "payload" / "bin").mkdir(parents=True)
    (root / "payload" / "bin" / "node").write_bytes(b"node")
    (root / "licenses").mkdir()
    (root / "licenses" / "LICENSE").write_text("example", encoding="utf-8")
    manifest = {
        "schemaVersion": 1,
        "catalogVersion": "2026-07-30.1",
        "componentId": "node",
        "target": "linux-x64",
        "version": "24.18.1",
        "binDirs": ["bin"],
        "executables": {"node": "bin/node"},
    }
    (root / "pack-manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "documentNamespace": "https://example.invalid/sbom",
        "files": [
            {
                "SPDXID": "SPDXRef-File-node",
                "fileName": "./payload/bin/node",
                "checksums": [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": hashlib.sha256(b"node").hexdigest(),
                    }
                ],
            }
        ],
    }
    (root / "SBOM.spdx.json").write_text(json.dumps(sbom), encoding="utf-8")
    pack = tmp_path / "OpenSquilla-Runtime-node-2026-07-30.1-linux-x64.tar.xz"
    _deterministic_tar_xz(root, pack, 1_785_369_600)
    unpacked = sum(path.stat().st_size for path in root.rglob("*") if path.is_file())
    metadata = {
        "componentId": "node",
        "target": "linux-x64",
        "asset": pack.name,
        "archiveType": "tar.xz",
        "version": "24.18.1",
        "sizeBytes": pack.stat().st_size,
        "unpackedSizeBytes": unpacked,
        "sha256": sha256_file(pack),
    }
    assert audit_pack_archive(pack, metadata, "2026-07-30.1") == sbom


def test_release_audit_rejects_unchecksummed_asset(tmp_path: Path) -> None:
    payload = tmp_path / "asset.bin"
    payload.write_bytes(b"asset")
    (tmp_path / "SHA256SUMS").write_text(
        f"{sha256_file(payload)}  {payload.name}\n",
        encoding="utf-8",
    )
    (tmp_path / "unexpected.bin").write_bytes(b"unexpected")
    with pytest.raises(ReleaseBuildError, match="exact asset set"):
        audit_release_directory(tmp_path)
