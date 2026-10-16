#!/usr/bin/env python3
"""Deterministic transport for an already authenticated SDK candidate directory.

This module records and checks file identities only. The caller remains
responsible for authenticating and separately approving the actual candidate.
It makes no signature, publisher, cryptographic-acceptance, or R1 claim.
"""
from __future__ import annotations

import hashlib
import io
import lzma
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile
from typing import Iterable


MAX_FILES = 512
MAX_TOTAL_BYTES = 32 * 1024 * 1024
TAR_MTIME = 1_791_936_000
MAX_TAR_BYTES = MAX_TOTAL_BYTES + MAX_FILES * tarfile.BLOCKSIZE + 2 * tarfile.RECORDSIZE
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_XZ_MEMORY = 128 * 1024 * 1024
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_RESERVED_WINDOWS_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{number}" for number in range(1, 10)),
    *(f"LPT{number}" for number in range(1, 10)),
}


def _absolute(path: Path, label: str) -> Path:
    value = Path(path)
    if not value.is_absolute():
        raise ValueError(label + " must be an absolute path")
    return value


def _real_directory(path: Path, label: str) -> Path:
    value = _absolute(path, label)
    try:
        resolved = value.resolve(strict=True)
        info = value.lstat()
    except OSError as error:
        raise ValueError(label + " must be an existing real directory") from error
    if resolved != value or not stat.S_ISDIR(info.st_mode):
        raise ValueError(label + " must be an existing real directory without symlink components")
    return value


def _fresh_file_path(path: Path, label: str) -> Path:
    value = _absolute(path, label)
    parent = _real_directory(value.parent, label + " parent")
    if parent != value.parent or not value.name or value.name in {".", ".."}:
        raise ValueError(label + " must have a fresh leaf in a real directory")
    try:
        value.lstat()
    except FileNotFoundError:
        return value
    except OSError as error:
        raise ValueError(label + " path could not be checked") from error
    raise ValueError(label + " path must be fresh")


def _fresh_directory_path(path: Path, label: str) -> tuple[Path, Path]:
    value = _absolute(path, label)
    parent = _real_directory(value.parent, label + " parent")
    if parent != value.parent or not value.name or value.name in {".", ".."}:
        raise ValueError(label + " must have a fresh leaf in a real directory")
    try:
        value.lstat()
    except FileNotFoundError:
        return value, parent
    except OSError as error:
        raise ValueError(label + " path could not be checked") from error
    raise ValueError(label + " path must be fresh")


def _safe_component(component: str) -> None:
    if (not component or component in {".", ".."}
            or component.endswith((".", " "))
            or any(ord(char) < 32 or ord(char) == 127 for char in component)
            or any(char in '<>:"\\|?*' for char in component)):
        raise ValueError("bundle contains an unsafe or nonportable path component")
    try:
        encoded = component.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("bundle paths must use portable ASCII characters") from error
    if len(encoded) > 100:
        raise ValueError("bundle path component exceeds the portable USTAR limit")
    windows_base = component.split(".", 1)[0].upper()
    if windows_base in _RESERVED_WINDOWS_NAMES:
        raise ValueError("bundle contains a reserved Windows path component")


def _safe_relative_path(path: str) -> str:
    if type(path) is not str or not path or path.startswith("/") or "\\" in path:
        raise ValueError("bundle member path must be a portable relative POSIX path")
    parts = path.split("/")
    for part in parts:
        _safe_component(part)
    encoded = path.encode("ascii")
    if len(encoded) > 255:
        raise ValueError("bundle member path exceeds the portable USTAR path limit")
    if len(encoded) > 100:
        if not any(0 < len(prefix) <= 155 and len(name) <= 100
                   for index, byte in enumerate(encoded)
                   if byte == ord("/")
                   for prefix, name in [(encoded[:index], encoded[index + 1:])]):
            raise ValueError("bundle member path does not fit a USTAR name and prefix")
    return path


def _validate_path_set(paths: list[str]) -> None:
    variants: dict[str, str] = {}
    file_keys: set[str] = set()
    parts_by_path: list[list[str]] = []
    for path in paths:
        _safe_relative_path(path)
        parts = path.split("/")
        parts_by_path.append(parts)
        for index in range(len(parts)):
            prefix = "/".join(parts[:index + 1])
            key = prefix.casefold()
            previous = variants.setdefault(key, prefix)
            if previous != prefix:
                raise ValueError("bundle paths collide on case-insensitive filesystems")
        file_key = path.casefold()
        if file_key in file_keys:
            raise ValueError("bundle contains duplicate or case-colliding file paths")
        file_keys.add(file_key)
    for parts in parts_by_path:
        for index in range(1, len(parts)):
            if "/".join(parts[:index]).casefold() in file_keys:
                raise ValueError("bundle file path is also a parent directory")


def _signature(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _read_regular_at(parent_fd: int, name: str, expected: os.stat_result,
                     maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        file_fd = os.open(name, flags, dir_fd=parent_fd)
    except OSError as error:
        raise ValueError("bundle file changed or could not be opened safely") from error
    try:
        opened = os.fstat(file_fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or not _same_identity(expected, opened)
                or _signature(expected) != _signature(opened)):
            raise ValueError("bundle contains a linked or changing file")
        if opened.st_size < 0 or opened.st_size > maximum:
            raise ValueError("bundle exceeds the raw byte limit")
        data = bytearray()
        while True:
            block = os.read(file_fd, min(1024 * 1024, maximum - len(data) + 1))
            if not block:
                break
            data.extend(block)
            if len(data) > maximum:
                raise ValueError("bundle exceeds the raw byte limit")
        after = os.fstat(file_fd)
        if _signature(opened) != _signature(after) or len(data) != opened.st_size:
            raise ValueError("bundle file changed while it was being read")
        return bytes(data)
    finally:
        os.close(file_fd)


def _scan_bundle(bundle: Path) -> list[tuple[str, bytes]]:
    root = _real_directory(bundle, "bundle")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise RuntimeError("safe directory-relative file access is unavailable on this platform")
    root_info = root.lstat()
    root_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        root_fd = os.open(str(root), root_flags)
    except OSError as error:
        raise ValueError("bundle root could not be opened safely") from error
    if _signature(root_info) != _signature(os.fstat(root_fd)):
        os.close(root_fd)
        raise ValueError("bundle root changed while it was being opened")
    files: list[tuple[str, bytes]] = []
    total = 0

    def walk(directory_fd: int, prefix: str) -> None:
        nonlocal total
        before = os.fstat(directory_fd)
        try:
            names = sorted(os.listdir(directory_fd))
        except OSError as error:
            raise ValueError("bundle directory changed or could not be read") from error
        for name in names:
            _safe_component(name)
            relative = name if not prefix else prefix + "/" + name
            _safe_relative_path(relative)
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as error:
                raise ValueError("bundle entry changed while it was being inspected") from error
            if stat.S_ISDIR(info.st_mode):
                child_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
                try:
                    child_fd = os.open(name, child_flags, dir_fd=directory_fd)
                except OSError as error:
                    raise ValueError("bundle contains a symlink or changing directory") from error
                try:
                    child_info = os.fstat(child_fd)
                    if (not stat.S_ISDIR(child_info.st_mode)
                            or not _same_identity(info, child_info)):
                        raise ValueError("bundle contains a symlink or changing directory")
                    walk(child_fd, relative)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise ValueError("bundle contains a hard-linked file")
                if len(files) >= MAX_FILES:
                    raise ValueError("bundle exceeds the file count limit")
                if info.st_size < 0 or total + info.st_size > MAX_TOTAL_BYTES:
                    raise ValueError("bundle exceeds the raw byte limit")
                data = _read_regular_at(directory_fd, name, info, MAX_TOTAL_BYTES - total)
                total += len(data)
                files.append((relative, data))
            else:
                raise ValueError("bundle contains a symlink or non-regular entry")
        after = os.fstat(directory_fd)
        if _signature(before) != _signature(after):
            raise ValueError("bundle directory changed while it was being read")

    try:
        walk(root_fd, "")
    finally:
        os.close(root_fd)
    files.sort(key=lambda item: item[0])
    _validate_path_set([path for path, _ in files])
    if len(files) > MAX_FILES or sum(len(data) for _, data in files) > MAX_TOTAL_BYTES:
        raise ValueError("bundle exceeds the existing file or raw byte limit")
    return files


def _inventory(files: Iterable[tuple[str, bytes]]) -> list[dict[str, object]]:
    return [
        {"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for path, data in files
    ]


def _canonical_tar(files: Iterable[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    try:
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT,
                          encoding="ascii", errors="strict") as archive:
            for path, data in files:
                info = tarfile.TarInfo(path)
                info.type = tarfile.REGTYPE
                info.mode = 0o644
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = TAR_MTIME
                info.size = len(data)
                info.linkname = ""
                info.devmajor = 0
                info.devminor = 0
                info.pax_headers = {}
                archive.addfile(info, io.BytesIO(data))
    except (tarfile.TarError, UnicodeError, ValueError, OverflowError) as error:
        raise ValueError("bundle cannot be represented as canonical USTAR") from error
    result = output.getvalue()
    if len(result) > MAX_TAR_BYTES:
        raise ValueError("bundle transport exceeds the raw archive limit")
    return result


def _make_record(name: str, archive_bytes: bytes,
                 files: list[tuple[str, bytes]]) -> dict[str, object]:
    return {
        "archive": {
            "name": name,
            "bytes": len(archive_bytes),
            "sha256": hashlib.sha256(archive_bytes).hexdigest(),
        },
        "files": _inventory(files),
    }


def pack_bundle(bundle: Path, archive: Path) -> dict[str, object]:
    """Pack an authenticated candidate's regular files into deterministic tar.xz.

    The bundle must already have been authenticated and approved by its caller.
    The returned record contains only archive and regular-file byte identities.
    """
    bundle_path = _real_directory(Path(bundle), "bundle")
    archive_path = _fresh_file_path(Path(archive), "archive")
    _safe_component(archive_path.name)
    if bundle_path == archive_path.parent or bundle_path in archive_path.parents:
        raise ValueError("archive path must be outside the candidate bundle")
    files = _scan_bundle(bundle_path)
    tar_bytes = _canonical_tar(files)
    archive_data = lzma.compress(
        tar_bytes, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC64, preset=6
    )
    if len(archive_data) > MAX_ARCHIVE_BYTES:
        raise ValueError("compressed bundle exceeds the transport size bound")

    # Link a fully written temporary file into the fresh destination atomically.
    # The temporary directory is private and shares the destination filesystem.
    with tempfile.TemporaryDirectory(prefix=".public-transport-", dir=archive_path.parent) as temp_dir:
        temporary = Path(temp_dir) / "bundle.tar.xz"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        file_fd = os.open(str(temporary), flags, 0o600)
        try:
            view = memoryview(archive_data)
            while view:
                written = os.write(file_fd, view)
                if written <= 0:
                    raise OSError("short write while creating transport archive")
                view = view[written:]
            os.fsync(file_fd)
        finally:
            os.close(file_fd)
        try:
            os.link(temporary, archive_path, follow_symlinks=False)
        except OSError as error:
            raise ValueError("archive destination was not fresh or could not be installed atomically") from error
    return _make_record(archive_path.name, archive_data, files)


def _validate_record(record: dict) -> tuple[str, int, str, list[dict[str, object]]]:
    if type(record) is not dict or set(record) != {"archive", "files"}:
        raise ValueError("external bundle record has an unexpected shape")
    archive = record["archive"]
    if type(archive) is not dict or set(archive) != {"name", "bytes", "sha256"}:
        raise ValueError("external archive record has an unexpected shape")
    archive_name = archive["name"]
    archive_size = archive["bytes"]
    archive_digest = archive["sha256"]
    if type(archive_name) is not str:
        raise ValueError("external archive name pin is invalid")
    _safe_component(archive_name)
    inventory = record["files"]
    if type(archive_size) is not int or not 0 < archive_size <= MAX_ARCHIVE_BYTES:
        raise ValueError("external archive byte pin is invalid")
    if type(archive_digest) is not str or not _DIGEST_RE.fullmatch(archive_digest):
        raise ValueError("external archive SHA-256 pin is invalid")
    if type(inventory) is not list or len(inventory) > MAX_FILES:
        raise ValueError("external bundle inventory is invalid")
    normalized: list[dict[str, object]] = []
    paths: list[str] = []
    total = 0
    previous = None
    for row in inventory:
        if type(row) is not dict or set(row) != {"path", "bytes", "sha256"}:
            raise ValueError("external bundle inventory row has an unexpected shape")
        path, size, digest = row["path"], row["bytes"], row["sha256"]
        _safe_relative_path(path)
        if type(size) is not int or size < 0 or size > MAX_TOTAL_BYTES - total:
            raise ValueError("external bundle file byte pin is invalid")
        if type(digest) is not str or not _DIGEST_RE.fullmatch(digest):
            raise ValueError("external bundle file SHA-256 pin is invalid")
        if previous is not None and path <= previous:
            raise ValueError("external bundle inventory must be sorted and unique")
        previous = path
        total += size
        paths.append(path)
        normalized.append({"path": path, "bytes": size, "sha256": digest})
    _validate_path_set(paths)
    return archive_name, archive_size, archive_digest, normalized


def _read_pinned_archive(path: Path, expected_name: str,
                         expected_size: int, expected_digest: str) -> bytes:
    value = _absolute(path, "archive")
    if value.name != expected_name:
        raise ValueError("archive name differs from the external pin")
    try:
        resolved = value.resolve(strict=True)
        info = value.lstat()
    except OSError as error:
        raise ValueError("archive must be an existing regular file") from error
    if (resolved != value or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_size != expected_size):
        raise ValueError("archive does not match the external byte pin")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        file_fd = os.open(str(value), flags)
    except OSError as error:
        raise ValueError("archive could not be opened safely") from error
    try:
        opened = os.fstat(file_fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or _signature(opened) != _signature(info)):
            raise ValueError("archive changed before it could be read")
        data = bytearray()
        digest = hashlib.sha256()
        while True:
            block = os.read(file_fd, min(1024 * 1024, expected_size - len(data) + 1))
            if not block:
                break
            data.extend(block)
            digest.update(block)
            if len(data) > expected_size:
                raise ValueError("archive does not match the external byte pin")
        after = os.fstat(file_fd)
        if (_signature(opened) != _signature(after) or len(data) != expected_size
                or digest.hexdigest() != expected_digest):
            raise ValueError("archive does not match the external byte or SHA-256 pin")
        return bytes(data)
    finally:
        os.close(file_fd)


def _decompress_single_xz(data: bytes) -> bytes:
    try:
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=MAX_XZ_MEMORY)
        output = bytearray(decoder.decompress(data, max_length=MAX_TAR_BYTES + 1))
        if len(output) > MAX_TAR_BYTES:
            raise ValueError("decompressed transport exceeds the archive size bound")
        while not decoder.eof:
            if decoder.needs_input:
                raise ValueError("transport contains a truncated XZ stream")
            block = decoder.decompress(b"", max_length=MAX_TAR_BYTES - len(output) + 1)
            if len(output) + len(block) > MAX_TAR_BYTES:
                raise ValueError("decompressed transport exceeds the archive size bound")
            if not block and not decoder.eof and not decoder.needs_input:
                raise ValueError("XZ decoder made no progress")
            output.extend(block)
        if decoder.unused_data:
            raise ValueError("transport contains trailing bytes or concatenated XZ streams")
        return bytes(output)
    except lzma.LZMAError as error:
        raise ValueError("transport is not a valid single XZ stream") from error


def _read_tar_files(tar_data: bytes,
                    expected: list[dict[str, object]]) -> list[tuple[str, bytes]]:
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:",
                          encoding="ascii", errors="strict") as archive:
            members = []
            for member in archive:
                members.append(member)
                if len(members) > MAX_FILES:
                    raise ValueError("transport exceeds the file count limit")
            paths: list[str] = []
            for member in members:
                path = _safe_relative_path(member.name)
                paths.append(path)
                if (member.type != tarfile.REGTYPE or member.linkname != ""
                        or member.pax_headers or member.mode != 0o644
                        or member.uid != 0 or member.gid != 0
                        or member.uname != "" or member.gname != ""
                        or member.mtime != TAR_MTIME
                        or member.devmajor != 0 or member.devminor != 0):
                    raise ValueError("transport has noncanonical tar metadata or a non-regular member")
            _validate_path_set(paths)
            expected_paths = [row["path"] for row in expected]
            if paths != expected_paths:
                raise ValueError("transport members do not match the complete external inventory")
            files: list[tuple[str, bytes]] = []
            total = 0
            for member, row in zip(members, expected, strict=True):
                if type(member.size) is not int or member.size != row["bytes"]:
                    raise ValueError("transport member size differs from the external inventory")
                total += member.size
                if total > MAX_TOTAL_BYTES:
                    raise ValueError("transport exceeds the raw file byte limit")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("transport contains a non-regular member")
                with stream:
                    content = stream.read(member.size)
                    if len(content) != member.size or stream.read(1):
                        raise ValueError("transport member size is inconsistent")
                if hashlib.sha256(content).hexdigest() != row["sha256"]:
                    raise ValueError("transport member SHA-256 differs from the external inventory")
                files.append((row["path"], content))
    except (tarfile.TarError, UnicodeError, OSError, EOFError) as error:
        raise ValueError("transport is not a readable canonical USTAR archive") from error
    canonical = _canonical_tar(files)
    if canonical != tar_data:
        raise ValueError("transport tar bytes or metadata are not canonical")
    return files


def _write_stage(parent: Path, destination: Path,
                 files: list[tuple[str, bytes]]) -> tuple[Path, tuple[int, int]]:
    stage = Path(tempfile.mkdtemp(prefix="." + destination.name + ".stage-", dir=parent))
    stage_info = stage.lstat()
    identity = (stage_info.st_dev, stage_info.st_ino)
    try:
        for relative, content in files:
            parts = relative.split("/")
            current = stage
            for component in parts[:-1]:
                current = current / component
                try:
                    current.mkdir(mode=0o700)
                except FileExistsError:
                    info = current.lstat()
                    if not stat.S_ISDIR(info.st_mode):
                        raise ValueError("staging path collides with a non-directory")
            output = current / parts[-1]
            flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
            try:
                file_fd = os.open(str(output), flags, 0o644)
            except OSError as error:
                raise ValueError("could not create a staged regular bundle file") from error
            try:
                view = memoryview(content)
                while view:
                    written = os.write(file_fd, view)
                    if written <= 0:
                        raise OSError("short write while staging bundle file")
                    view = view[written:]
                os.fchmod(file_fd, 0o644)
                os.fsync(file_fd)
            finally:
                os.close(file_fd)
        staged_files = _scan_bundle(stage)
        if _inventory(staged_files) != _inventory(files):
            raise ValueError("staged files differ from the checked transport inventory")
        return stage, identity
    except BaseException:
        _remove_owned_stage(stage, identity)
        raise


def _remove_owned_stage(stage: Path, identity: tuple[int, int]) -> None:
    try:
        info = stage.lstat()
    except FileNotFoundError:
        return
    if (stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == identity):
        shutil.rmtree(stage)


def unpack_bundle(archive: Path, record: dict, destination: Path) -> dict[str, object]:
    """Read a transport only after its externally trusted archive and file pins match.

    The record must come from an independent trusted source. This function checks
    byte identity and safe transport structure; it does not authenticate a
    publisher, verify a signature, or declare R1 acceptance.
    """
    expected_name, expected_size, expected_digest, expected_files = _validate_record(record)
    destination_path, parent = _fresh_directory_path(Path(destination), "destination")
    archive_data = _read_pinned_archive(Path(archive), expected_name,
                                        expected_size, expected_digest)
    tar_data = _decompress_single_xz(archive_data)
    files = _read_tar_files(tar_data, expected_files)
    receipt = _make_record(expected_name, archive_data, files)
    stage, identity = _write_stage(parent, destination_path, files)
    try:
        # The final name is fresh and the complete private staging tree is ready.
        try:
            destination_path.lstat()
        except FileNotFoundError:
            pass
        else:
            raise ValueError("destination path must remain fresh")
        os.rename(stage, destination_path)
    except BaseException:
        _remove_owned_stage(stage, identity)
        raise
    return receipt
