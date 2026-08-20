#!/usr/bin/env python3
"""Build one deterministic, native-probed OpenSquilla Runtime Pack."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unicodedata
import urllib.request
import uuid
import zipfile
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from scripts.validate_sources import TARGET_COMPONENTS, load_sources

MAX_ARCHIVE_BYTES = 2 * 1024**3
MAX_UNPACKED_BYTES = 4 * 1024**3
MAX_MEMBERS = 250_000
MAX_EXPANSION_RATIO = 400
COPY_CHUNK_BYTES = 1024 * 1024
MAX_LICENSE_FILES = 10_000
MAX_LICENSE_FILE_BYTES = 5 * 1024**2
MAX_LICENSE_TOTAL_BYTES = 128 * 1024**2
LICENSE_NAMES = re.compile(r"^(license|licence|copying|copyright|notice)([._-].*)?$", re.I)
MACHINE_ALIASES = {
    "amd64": "x64",
    "x86_64": "x64",
    "arm64": "arm64",
    "aarch64": "arm64",
}
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
WINDOWS_FORBIDDEN_CHARS = frozenset('<>:"|?*')


class PackBuildError(RuntimeError):
    """Raised when an input or generated pack violates the release contract."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(COPY_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def verify_native_target(target: str) -> None:
    expected_system, expected_arch = target.split("-", 1)
    actual_system = {
        "darwin": "darwin",
        "linux": "linux",
        "windows": "windows",
    }.get(platform.system().lower())
    actual_arch = MACHINE_ALIASES.get(platform.machine().lower())
    if actual_system != expected_system or actual_arch != expected_arch:
        raise PackBuildError(
            f"native probe required for {target}; runner is {actual_system or 'unknown'}-"
            f"{actual_arch or platform.machine().lower()}"
        )
    if expected_system == "linux":
        libc_name, _libc_version = platform.libc_ver()
        if libc_name.lower() not in {"glibc", "gnu libc"}:
            raise PackBuildError("Linux Runtime Packs require a GNU/glibc runner")


def download_pinned(url: str, expected_sha256: str, destination: Path) -> int:
    request = urllib.request.Request(url, headers={"User-Agent": "OpenSquilla-Runtime-Packs/1"})
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".part")
    digest = hashlib.sha256()
    received = 0
    try:
        with (
            urllib.request.urlopen(request, timeout=60) as response,
            temporary.open("wb") as output,
        ):
            final_url = response.geturl()
            if not final_url.lower().startswith("https://"):
                raise PackBuildError("upstream redirected outside HTTPS")
            header = response.headers.get("Content-Length")
            if header:
                declared = int(header)
                if declared <= 0 or declared > MAX_ARCHIVE_BYTES:
                    raise PackBuildError("upstream Content-Length exceeds the archive limit")
            while chunk := response.read(COPY_CHUNK_BYTES):
                received += len(chunk)
                if received > MAX_ARCHIVE_BYTES:
                    raise PackBuildError("upstream archive exceeds the archive limit")
                digest.update(chunk)
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        if digest.hexdigest() != expected_sha256:
            raise PackBuildError("upstream SHA-256 mismatch")
        os.replace(temporary, destination)
        return received
    finally:
        temporary.unlink(missing_ok=True)


def _validate_portable_parts(parts: tuple[str, ...], raw_name: str) -> None:
    if len("/".join(parts).encode("utf-8")) > 32_768:
        raise PackBuildError(f"archive member path is too long: {raw_name}")
    for part in parts:
        if unicodedata.normalize("NFC", part) != part:
            raise PackBuildError(f"archive member path is not NFC-normalized: {raw_name}")
        if len(part.encode("utf-8")) > 255:
            raise PackBuildError(f"archive member segment is too long: {raw_name}")
        if any(ord(character) < 32 or ord(character) == 127 for character in part):
            raise PackBuildError(f"archive member contains a control character: {raw_name}")
        if any(character in WINDOWS_FORBIDDEN_CHARS for character in part):
            raise PackBuildError(f"archive member is not portable to Windows: {raw_name}")
        if part.endswith((" ", ".")):
            raise PackBuildError(f"archive member has a non-portable suffix: {raw_name}")
        if part.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES:
            raise PackBuildError(f"archive member uses a Windows device name: {raw_name}")


def _canonical_member_parts(raw_name: str) -> tuple[str, ...]:
    if "\x00" in raw_name:
        raise PackBuildError("archive member contains NUL")
    normalized = raw_name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or re.match(r"^[A-Za-z]:", normalized) or ".." in path.parts:
        raise PackBuildError(f"archive member escapes payload: {raw_name}")
    parts = tuple(part for part in path.parts if part not in {"", "."})
    _validate_portable_parts(parts, raw_name)
    return parts


def _safe_member_path(raw_name: str, strip_components: int) -> PurePosixPath | None:
    parts = _canonical_member_parts(raw_name)
    if len(parts) <= strip_components:
        return None
    stripped = PurePosixPath(*parts[strip_components:])
    if not stripped.parts or ".." in stripped.parts:
        raise PackBuildError(f"archive member is invalid after stripping: {raw_name}")
    return stripped


def _portable_key(path: PurePosixPath, *, case_sensitive: bool = False) -> str:
    normalized = "/".join(unicodedata.normalize("NFC", part) for part in path.parts)
    return normalized if case_sensitive else normalized.casefold()


def _register_path_shape(
    relative: PurePosixPath,
    kind: str,
    kinds: dict[str, str],
    parent_keys: set[str],
    *,
    case_sensitive: bool = False,
) -> None:
    key = _portable_key(relative, case_sensitive=case_sensitive)
    if key in kinds:
        raise PackBuildError(f"duplicate archive member: {relative}")
    ancestors = [PurePosixPath(*relative.parts[:index]) for index in range(1, len(relative.parts))]
    for ancestor in ancestors:
        ancestor_kind = kinds.get(_portable_key(ancestor, case_sensitive=case_sensitive))
        if ancestor_kind is not None and ancestor_kind != "directory":
            raise PackBuildError(f"archive path descends through a file: {relative}")
    if kind != "directory" and key in parent_keys:
        raise PackBuildError(f"archive file shadows an existing directory: {relative}")
    kinds[key] = kind
    parent_keys.update(
        _portable_key(ancestor, case_sensitive=case_sensitive) for ancestor in ancestors
    )


def _resolve_tar_link_path(
    member: tarfile.TarInfo,
    strip_components: int,
) -> PurePosixPath:
    raw_target = member.linkname.replace("\\", "/")
    target_path = PurePosixPath(raw_target)
    if target_path.is_absolute() or re.match(r"^[A-Za-z]:", raw_target):
        raise PackBuildError(f"archive link escapes payload: {member.name} -> {member.linkname}")
    member_parts = _canonical_member_parts(member.name)
    combined = (
        (*member_parts[:-1], *target_path.parts)
        if member.issym()
        else target_path.parts
    )
    collapsed: list[str] = []
    for part in combined:
        if part in {"", "."}:
            continue
        if part == "..":
            if not collapsed:
                raise PackBuildError(
                    f"archive link escapes payload: {member.name} -> {member.linkname}"
                )
            collapsed.pop()
            continue
        collapsed.append(part)
    parts = tuple(collapsed)
    _validate_portable_parts(parts, member.linkname)
    if len(parts) <= strip_components:
        raise PackBuildError(
            f"archive link escapes stripped payload: {member.name} -> {member.linkname}"
        )
    return PurePosixPath(*parts[strip_components:])


def _check_budget(member_count: int, total_bytes: int, compressed_bytes: int) -> None:
    if member_count > MAX_MEMBERS:
        raise PackBuildError("archive has too many members")
    if total_bytes > MAX_UNPACKED_BYTES:
        raise PackBuildError("archive exceeds the unpacked-size limit")
    if compressed_bytes > 0 and total_bytes > compressed_bytes * MAX_EXPANSION_RATIO:
        raise PackBuildError("archive expansion ratio exceeds the safety limit")


def _copy_exact(source: BinaryIO, destination: Path, expected_size: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    remaining = expected_size
    with destination.open("xb") as output:
        while remaining:
            chunk = source.read(min(COPY_CHUNK_BYTES, remaining))
            if not chunk:
                raise PackBuildError("archive member ended before its declared size")
            output.write(chunk)
            remaining -= len(chunk)
        if source.read(1):
            raise PackBuildError("archive member exceeded its declared size")


def _extract_tar(
    archive: Path,
    payload: Path,
    strip_components: int,
    *,
    case_sensitive_paths: bool = False,
) -> None:
    entries: list[tuple[tarfile.TarInfo, PurePosixPath, str]] = []
    kinds: dict[str, str] = {}
    parent_keys: set[str] = set()
    total_bytes = 0
    with tarfile.open(archive, mode="r:*") as handle:
        for member in handle:
            relative = _safe_member_path(member.name, strip_components)
            if relative is None:
                continue
            if member.isdir():
                kind = "directory"
            elif member.isfile():
                kind = "file"
            elif member.issym() or member.islnk():
                kind = "link"
            else:
                raise PackBuildError(f"unsupported archive member: {relative}")
            _register_path_shape(
                relative,
                kind,
                kinds,
                parent_keys,
                case_sensitive=case_sensitive_paths,
            )
            if member.isfile():
                if member.size < 0:
                    raise PackBuildError("archive member has a negative size")
                total_bytes += member.size
            entries.append((member, relative, kind))
            _check_budget(len(entries), total_bytes, archive.stat().st_size)
        for member, relative, kind in entries:
            destination = payload.joinpath(*relative.parts)
            if kind == "directory":
                destination.mkdir(parents=True, exist_ok=True)
                continue
            if kind == "link":
                continue
            source = handle.extractfile(member)
            if source is None:
                raise PackBuildError(f"cannot read archive member: {relative}")
            with source:
                _copy_exact(source, destination, member.size)
            if member.mode & 0o111:
                destination.chmod(0o755)

        by_key = {
            _portable_key(relative, case_sensitive=case_sensitive_paths): (
                member,
                relative,
                kind,
            )
            for member, relative, kind in entries
        }
        resolving: set[str] = set()

        def materialize(relative: PurePosixPath) -> Path:
            key = _portable_key(relative, case_sensitive=case_sensitive_paths)
            entry = by_key.get(key)
            if entry is None:
                raise PackBuildError(f"archive link target is missing: {relative}")
            member, actual_relative, kind = entry
            destination = payload.joinpath(*actual_relative.parts)
            if kind == "directory":
                raise PackBuildError(f"archive links to a directory: {actual_relative}")
            if kind == "file":
                return destination
            if key in resolving:
                raise PackBuildError(f"archive contains a link cycle: {actual_relative}")
            resolving.add(key)
            try:
                target_relative = _resolve_tar_link_path(member, strip_components)
                source = materialize(target_relative)
                destination.parent.mkdir(parents=True, exist_ok=True)
                if destination.exists():
                    raise PackBuildError(
                        f"archive link destination already exists: {actual_relative}"
                    )
                shutil.copyfile(source, destination)
                destination.chmod(0o755 if source.stat().st_mode & 0o111 else 0o644)
                return destination
            finally:
                resolving.remove(key)

        for _member, relative, kind in entries:
            if kind == "link":
                materialize(relative)

    _validate_physical_tree(
        payload,
        compressed_bytes=archive.stat().st_size,
        case_sensitive_paths=case_sensitive_paths,
    )


def _zip_kind(info: zipfile.ZipInfo) -> str:
    mode = (info.external_attr >> 16) & 0xFFFF
    kind = stat.S_IFMT(mode)
    if info.is_dir() or kind == stat.S_IFDIR:
        return "directory"
    if kind in {0, stat.S_IFREG}:
        return "file"
    return "special"


def _extract_zip(archive: Path, payload: Path, strip_components: int) -> None:
    entries: list[tuple[zipfile.ZipInfo, PurePosixPath, str]] = []
    kinds: dict[str, str] = {}
    parent_keys: set[str] = set()
    total_bytes = 0
    with zipfile.ZipFile(archive) as handle:
        for member in handle.infolist():
            relative = _safe_member_path(member.filename, strip_components)
            if relative is None:
                continue
            kind = _zip_kind(member)
            if kind == "special":
                raise PackBuildError(f"links and special archive members are forbidden: {relative}")
            _register_path_shape(relative, kind, kinds, parent_keys)
            if member.file_size < 0 or member.compress_size < 0:
                raise PackBuildError("archive member has an invalid size")
            if kind == "file":
                total_bytes += member.file_size
                if (
                    member.compress_size
                    and member.file_size > member.compress_size * MAX_EXPANSION_RATIO
                ):
                    raise PackBuildError(f"archive member expansion ratio is unsafe: {relative}")
            entries.append((member, relative, kind))
            _check_budget(len(entries), total_bytes, archive.stat().st_size)
        for member, relative, kind in entries:
            destination = payload.joinpath(*relative.parts)
            if kind == "directory":
                destination.mkdir(parents=True, exist_ok=True)
                continue
            with handle.open(member, "r") as source:
                _copy_exact(source, destination, member.file_size)
            mode = (member.external_attr >> 16) & 0o777
            if mode & 0o111:
                destination.chmod(0o755)

    _validate_physical_tree(payload, compressed_bytes=archive.stat().st_size)


def _validate_physical_tree(
    root: Path,
    *,
    compressed_bytes: int = 0,
    case_sensitive_paths: bool = False,
) -> None:
    seen: set[str] = set()
    total_bytes = 0
    count = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix().casefold()):
        relative = path.relative_to(root)
        key = _portable_key(relative, case_sensitive=case_sensitive_paths)
        if key in seen:
            raise PackBuildError(f"case-insensitive duplicate extracted path: {relative}")
        seen.add(key)
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not (
            stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)
        ):
            raise PackBuildError(f"extracted links and special files are forbidden: {relative}")
        count += 1
        if stat.S_ISREG(metadata.st_mode):
            total_bytes += metadata.st_size
        _check_budget(count, total_bytes, compressed_bytes)


def _audit_7z_listing_text(listing: str) -> None:
    paths: list[PurePosixPath] = []
    seen: set[str] = set()
    for line in listing.splitlines():
        if line.startswith(("Symbolic Link = ", "Hard Link = ")):
            raise PackBuildError("Git Bash SFX contains a link")
        if not line.startswith("Path = "):
            continue
        relative = _safe_member_path(line.removeprefix("Path = "), 0)
        if relative is None:
            raise PackBuildError("Git Bash SFX contains an empty path")
        key = _portable_key(relative)
        if key in seen:
            raise PackBuildError(f"Git Bash SFX contains a duplicate path: {relative}")
        seen.add(key)
        paths.append(relative)
        _check_budget(len(paths), 0, 0)
    if not paths:
        raise PackBuildError("7-Zip did not report any Git Bash SFX members")


def _verify_authenticode_signature(path: Path) -> None:
    powershell = (
        shutil.which("pwsh")
        or shutil.which("powershell")
        or shutil.which("powershell.exe")
    )
    if powershell is None:
        raise PackBuildError("PowerShell is required for the Git Bash Authenticode gate")
    environment = os.environ.copy()
    environment["OPENSQUILLA_SIGNATURE_PATH"] = str(path.resolve())
    script = (
        "$signature = Get-AuthenticodeSignature -LiteralPath "
        "$env:OPENSQUILLA_SIGNATURE_PATH; "
        "[PSCustomObject]@{Status=[string]$signature.Status; "
        "Subject=[string]$signature.SignerCertificate.Subject} | "
        "ConvertTo-Json -Compress"
    )
    completed = subprocess.run(
        [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=120,
        env=environment,
    )
    try:
        signature = json.loads(completed.stdout.strip())
    except (json.JSONDecodeError, TypeError) as exc:
        raise PackBuildError(
            f"cannot audit Authenticode signature for {path.name}: {completed.stdout[-1000:]}"
        ) from exc
    if (
        completed.returncode != 0
        or not isinstance(signature, Mapping)
        or signature.get("Status") != "Valid"
        or not isinstance(signature.get("Subject"), str)
        or not signature["Subject"].strip()
    ):
        raise PackBuildError(
            f"invalid Authenticode signature for {path.name}: {completed.stdout[-1000:]}"
        )


def extract_upstream(
    archive: Path,
    archive_type: str,
    strip_components: int,
    payload: Path,
    *,
    case_sensitive_paths: bool = False,
) -> None:
    payload.mkdir(parents=True, exist_ok=False)
    if archive_type in {"tar.gz", "tar.xz"}:
        _extract_tar(
            archive,
            payload,
            strip_components,
            case_sensitive_paths=case_sensitive_paths,
        )
    elif archive_type == "zip":
        _extract_zip(archive, payload, strip_components)
    elif archive_type == "7z-sfx":
        trusted_ci = (
            os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
            and os.environ.get("OPENSQUILLA_TRUSTED_WINDOWS_CI") == "1"
        )
        if platform.system() != "Windows" or strip_components != 0 or not trusted_ci:
            raise PackBuildError("Git Bash SFX may be unpacked only by native Windows CI")
        _verify_authenticode_signature(archive)
        executable = shutil.which("7z") or shutil.which("7za")
        if executable is None:
            raise PackBuildError("7-Zip is required on the trusted Git Bash build runner")
        listing = subprocess.run(
            [executable, "l", "-slt", "-ba", str(archive)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=300,
        )
        if listing.returncode != 0:
            raise PackBuildError(f"7-Zip listing failed: {listing.stdout[-2000:]}")
        _audit_7z_listing_text(listing.stdout)
        completed = subprocess.run(
            [
                executable,
                "x",
                "-y",
                f"-o{payload}",
                str(archive),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=600,
        )
        if completed.returncode != 0:
            raise PackBuildError(f"7-Zip extraction failed: {completed.stdout[-2000:]}")
    else:
        raise PackBuildError(f"unsupported upstream archive: {archive_type}")
    _validate_physical_tree(payload, case_sensitive_paths=case_sensitive_paths)


def _probe_command(component_id: str, name: str, executable: Path) -> list[str]:
    if component_id == "python":
        return [str(executable), "--version"]
    if component_id == "node":
        return [str(executable), "--version"]
    if component_id == "gitBash" and name == "git":
        return [str(executable), "--version"]
    if component_id == "gitBash" and name == "bash":
        return [str(executable), "--version"]
    raise PackBuildError(f"no probe for {component_id}.{name}")


def probe_payload(
    component_id: str,
    version: str,
    executables: Mapping[str, str],
    payload: Path,
) -> None:
    outputs: dict[str, str] = {}
    probe_names = {
        "python": {"python"},
        "node": {"node"},
        "gitBash": {"git", "bash"},
    }[component_id]
    for name, relative in sorted(executables.items()):
        executable = payload.joinpath(*PurePosixPath(relative).parts)
        if not executable.is_file():
            raise PackBuildError(f"required executable is missing: {relative}")
        if name not in probe_names:
            continue
        if component_id == "gitBash":
            _verify_authenticode_signature(executable)
        completed = subprocess.run(
            _probe_command(component_id, name, executable),
            cwd=payload,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60,
        )
        output = completed.stdout.strip()
        if completed.returncode != 0 or not output:
            raise PackBuildError(f"native probe failed for {component_id}.{name}: {output[-1000:]}")
        outputs[name] = output
    expected = version.split("+", 1)[0]
    primary_name = (
        "python" if component_id == "python" else "node" if component_id == "node" else "git"
    )
    primary = outputs[primary_name]
    if expected not in primary:
        raise PackBuildError(
            f"native {component_id} probe did not report pinned version {expected}: {primary}"
        )


def collect_licenses(payload: Path, destination: Path) -> None:
    candidates: list[Path] = []
    total_bytes = 0
    for path in payload.rglob("*"):
        if not path.is_file() or not LICENSE_NAMES.fullmatch(path.name):
            continue
        size = path.stat().st_size
        if size > MAX_LICENSE_FILE_BYTES:
            raise PackBuildError(f"upstream license file exceeds the safety limit: {path.name}")
        candidates.append(path)
        total_bytes += size
        if len(candidates) > MAX_LICENSE_FILES or total_bytes > MAX_LICENSE_TOTAL_BYTES:
            raise PackBuildError("upstream license set exceeds the safety limit")
    if not candidates:
        raise PackBuildError("upstream payload contains no auditable license file")
    destination.mkdir(parents=True, exist_ok=False)
    for index, source in enumerate(sorted(candidates, key=lambda item: item.as_posix()), 1):
        relative = source.relative_to(payload).as_posix().replace("/", "__")
        target = destination / f"{index:05d}__{relative}"
        shutil.copyfile(source, target)


def build_spdx(
    component_id: str,
    version: str,
    payload: Path,
    source_date_epoch: int,
) -> dict[str, Any]:
    files = []
    for path in sorted(
        (path for path in payload.rglob("*") if path.is_file()),
        key=lambda item: item.as_posix(),
    ):
        relative = path.relative_to(payload).as_posix()
        digest = sha256_file(path)
        file_id = hashlib.sha256(f"{relative}\0{digest}".encode()).hexdigest()
        files.append(
            {
                "SPDXID": "SPDXRef-File-" + file_id,
                "fileName": f"./payload/{relative}",
                "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
    document_namespace = (
        "https://opensquilla.com/spdx/runtime-packs/"
        f"{component_id}/{version}/{hashlib.sha256(_json_bytes(files)).hexdigest()}"
    )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"OpenSquilla Runtime Pack {component_id} {version}",
        "documentNamespace": document_namespace,
        "creationInfo": {
            "created": datetime.fromtimestamp(source_date_epoch, UTC).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "creators": ["Tool: OpenSquilla Runtime Pack Builder"],
        },
        "packages": [
            {
                "name": component_id,
                "SPDXID": "SPDXRef-Package",
                "versionInfo": version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        ],
        "files": files,
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package",
            },
            *(
                {
                    "spdxElementId": "SPDXRef-Package",
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": file["SPDXID"],
                }
                for file in files
            ),
        ],
    }


def _tree_size(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def _deterministic_tar_xz(source: Path, destination: Path, epoch: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.{uuid.uuid4().hex}.tmp")
    try:
        with tarfile.open(temporary, mode="w:xz", preset=9) as output:
            for path in sorted(
                source.rglob("*"), key=lambda item: item.relative_to(source).as_posix()
            ):
                relative = path.relative_to(source).as_posix()
                metadata = path.lstat()
                info = tarfile.TarInfo(relative + ("/" if path.is_dir() else ""))
                info.mtime = epoch
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.pax_headers = {}
                if path.is_dir():
                    info.type = tarfile.DIRTYPE
                    info.mode = 0o755
                    info.size = 0
                    output.addfile(info)
                elif path.is_file():
                    info.type = tarfile.REGTYPE
                    info.mode = 0o755 if metadata.st_mode & 0o111 else 0o644
                    info.size = metadata.st_size
                    with path.open("rb") as handle:
                        output.addfile(info, handle)
                else:
                    raise PackBuildError(f"cannot archive special path: {relative}")
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def build_pack(
    sources_path: Path,
    target: str,
    component_id: str,
    output_dir: Path,
    *,
    upstream_archive: Path | None = None,
) -> dict[str, Any]:
    sources = load_sources(sources_path)
    if target not in TARGET_COMPONENTS or component_id not in TARGET_COMPONENTS[target]:
        raise PackBuildError(f"unsupported target/component: {target}/{component_id}")
    verify_native_target(target)
    component = sources["targets"][target][component_id]
    catalog_version = sources["catalogVersion"]
    asset = f"OpenSquilla-Runtime-{component_id}-{catalog_version}-{target}.tar.xz"
    with tempfile.TemporaryDirectory(prefix="opensquilla-runtime-pack-") as temporary:
        work = Path(temporary)
        archive = work / "upstream.archive"
        if upstream_archive is None:
            download_pinned(component["url"], component["sha256"], archive)
        else:
            if sha256_file(upstream_archive) != component["sha256"]:
                raise PackBuildError("provided upstream archive SHA-256 mismatch")
            shutil.copyfile(upstream_archive, archive)
        pack_root = work / "pack"
        pack_root.mkdir()
        payload = pack_root / "payload"
        extract_upstream(
            archive,
            component["archiveType"],
            component["stripComponents"],
            payload,
            case_sensitive_paths=target.startswith("linux-"),
        )
        probe_payload(component_id, component["version"], component["executables"], payload)
        collect_licenses(payload, pack_root / "licenses")
        manifest = {
            "schemaVersion": 1,
            "catalogVersion": catalog_version,
            "componentId": component_id,
            "target": target,
            "version": component["version"],
            "binDirs": component["binDirs"],
            "executables": component["executables"],
        }
        _atomic_write(pack_root / "pack-manifest.json", _json_bytes(manifest))
        _atomic_write(
            pack_root / "SBOM.spdx.json",
            _json_bytes(
                build_spdx(
                    component_id,
                    component["version"],
                    payload,
                    sources["sourceDateEpoch"],
                )
            ),
        )
        unpacked_size = _tree_size(pack_root)
        destination = output_dir / asset
        _deterministic_tar_xz(pack_root, destination, sources["sourceDateEpoch"])
    result = {
        "target": target,
        "componentId": component_id,
        "asset": asset,
        "archiveType": "tar.xz",
        "version": component["version"],
        "sizeBytes": destination.stat().st_size,
        "unpackedSizeBytes": unpacked_size,
        "sha256": sha256_file(destination),
    }
    _atomic_write(output_dir / f"{asset}.json", _json_bytes(result))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources", type=Path, default=Path("sources.json"))
    parser.add_argument("--target", required=True)
    parser.add_argument("--component", required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("dist"))
    parser.add_argument("--upstream-archive", type=Path)
    args = parser.parse_args()
    result = build_pack(
        args.sources,
        args.target,
        args.component,
        args.output_dir,
        upstream_archive=args.upstream_archive,
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
