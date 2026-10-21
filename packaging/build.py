#!/usr/bin/env python3
"""Build deterministic APT and archive packages from pinned SDK inputs."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import lzma
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA = "ami-rust-package-inputs-v1"
REPORT_SCHEMA = "ami-rust-packaging-report-v1"
INVENTORY_SCHEMA = "ami-rust-package-inventory-v1"
PROOF_SUBJECT_LABELS = ("SHA256SUMS", "payload.tar.xz", "payload.spdx.json", "transport.json")
MAX_ASSET_BYTES = 128 * 1024 * 1024
MAX_TOTAL_ASSET_BYTES = 256 * 1024 * 1024
MAX_PROOF_BYTES = 16 * 1024 * 1024
MAX_TOTAL_PROOF_BYTES = 64 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_SOURCE_BYTES = 24 * 1024 * 1024
MAX_EPOCH = (1 << 33) - 1
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class BuildError(ValueError):
    """Raised when a package input violates the pinned build contract."""


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


def _read_json(path: Path, label: str, limit: int) -> tuple[Any, bytes]:
    data = _read_regular(path, label, limit)
    try:
        return _parse_json(data, label), data
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BuildError(f"{label} is not valid UTF-8 JSON: {exc}") from exc


def _parse_json(data: bytes, label: str) -> Any:
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise BuildError(f"{label} contains a duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise BuildError(f"{label} contains an invalid JSON constant: {value}")

    return json.loads(
        data.decode("utf-8"), object_pairs_hook=unique_pairs, parse_constant=reject_constant
    )


def _read_regular(path: Path, label: str, limit: int) -> bytes:
    """Read one bounded regular file without following a final symlink."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise BuildError(f"cannot open {label}: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise BuildError(f"{label} must be a regular, non-linked file")
        if info.st_size > limit:
            raise BuildError(f"{label} exceeds the {limit}-byte input limit")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > limit:
            raise BuildError(f"{label} exceeds the {limit}-byte input limit")
        if len(data) != info.st_size:
            raise BuildError(f"{label} changed while it was being read")
        return data
    finally:
        os.close(fd)


def _require_directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise BuildError(f"{label} directory is unavailable: {exc}") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise BuildError(f"{label} must be a real directory, not a link")


def _safe_leaf(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."}:
        raise BuildError(f"{label} must be a safe flat filename")
    if "/" in value or "\\" in value or "\x00" in value:
        raise BuildError(f"{label} must be a safe flat filename")
    if PurePosixPath(value).name != value:
        raise BuildError(f"{label} must be a safe flat filename")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}", value):
        raise BuildError(f"{label} must use a plain ASCII filename")
    return value


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_pins(source: Path) -> tuple[dict[str, Any], bytes, dict[str, dict[str, Any]]]:
    pins_path = source / "packaging" / "pins.json"
    pins, raw = _read_json(pins_path, "packaging/pins.json", MAX_SOURCE_FILE_BYTES)
    if not isinstance(pins, dict) or pins.get("schema") != SCHEMA:
        raise BuildError(f"packaging/pins.json must use schema {SCHEMA}")
    sdk_version = pins.get("sdk_version")
    package_version = pins.get("package_version")
    if not isinstance(sdk_version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", sdk_version):
        raise BuildError("pins.json sdk_version is invalid")
    if not isinstance(package_version, str) or not re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+-[0-9]+", package_version
    ):
        raise BuildError("pins.json package_version is invalid")
    revision = pins.get("packaging_revision")
    if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
        raise BuildError("pins.json packaging_revision is invalid")
    packaging_tag = pins.get("packaging_tag")
    if not isinstance(packaging_tag, str) or not re.fullmatch(
        rf"v{re.escape(sdk_version)}\+packaging\.{revision}", packaging_tag
    ):
        raise BuildError("pins.json packaging_tag is invalid")
    maintainer = pins.get("maintainer")
    if (
        not isinstance(maintainer, str)
        or not maintainer.strip()
        or any(char in maintainer for char in "\r\n\x00")
    ):
        raise BuildError("pins.json maintainer is invalid")
    records = pins.get("assets")
    if not isinstance(records, list) or len(records) != 6:
        raise BuildError("pins.json must contain exactly six SDK asset pins")
    by_name: dict[str, dict[str, Any]] = {}
    total = 0
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "bytes", "sha256"}:
            raise BuildError("each SDK asset pin must contain path, bytes and sha256")
        name = _safe_leaf(record["path"], "pinned asset path")
        size = record["bytes"]
        digest = record["sha256"]
        if name in by_name:
            raise BuildError(f"duplicate pinned asset path: {name}")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0 or size > MAX_ASSET_BYTES:
            raise BuildError(f"invalid or oversized pinned asset length: {name}")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise BuildError(f"invalid pinned asset SHA-256: {name}")
        by_name[name] = record
        total += size
    if total > MAX_TOTAL_ASSET_BYTES:
        raise BuildError("pinned SDK assets exceed the total input limit")
    return pins, raw, by_name


def _directory_names(path: Path, label: str) -> set[str]:
    _require_directory(path, label)
    names: set[str] = set()
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                name = _safe_leaf(entry.name, f"{label} entry")
                if name in names:
                    raise BuildError(f"duplicate {label} entry: {name}")
                info = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    raise BuildError(f"{label}/{name} must be a regular, non-linked file")
                names.add(name)
    except OSError as exc:
        raise BuildError(f"cannot inspect {label} directory: {exc}") from exc
    return names


def _read_assets(directory: Path, expected: dict[str, dict[str, Any]]) -> dict[str, bytes]:
    names = _directory_names(directory, "assets")
    if names != set(expected):
        missing = sorted(set(expected) - names)
        extra = sorted(names - set(expected))
        raise BuildError(f"assets directory differs from pins.json (missing={missing}, extra={extra})")
    result: dict[str, bytes] = {}
    for name in sorted(expected):
        record = expected[name]
        data = _read_regular(directory / name, f"assets/{name}", record["bytes"])
        if len(data) != record["bytes"] or _sha256(data) != record["sha256"]:
            raise BuildError(f"pinned SDK asset does not match pins.json: {name}")
        if name.endswith(".json"):
            try:
                _parse_json(data, f"assets/{name}")
            except (BuildError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BuildError(f"SDK JSON asset is invalid: {name}: {exc}") from exc
        result[name] = data
    return result


def _asset_subject_map(assets: dict[str, bytes]) -> dict[str, str]:
    matches: dict[str, list[str]] = {subject: [] for subject in PROOF_SUBJECT_LABELS}
    for name in assets:
        if name == "SHA256SUMS":
            matches["SHA256SUMS"].append(name)
        if name.endswith("-release.tar.xz"):
            matches["payload.tar.xz"].append(name)
        if name.endswith("-release.tar.xz.spdx.json"):
            matches["payload.spdx.json"].append(name)
        if name.endswith("-transport.json"):
            matches["transport.json"].append(name)
    for subject, names in matches.items():
        if len(names) != 1:
            raise BuildError(f"SDK asset pins must identify exactly one {subject} subject")
    return {subject: names[0] for subject, names in matches.items()}


def _read_proofs(
    directory: Path, index_path: Path, expected_subjects: set[str]
) -> tuple[dict[str, bytes], bytes, dict[str, Any]]:
    index, index_raw = _read_json(index_path, "proof index", MAX_SOURCE_FILE_BYTES)
    if not isinstance(index, dict) or set(index) != {"subjects"}:
        raise BuildError("proof index must contain only a subjects object")
    subjects = index["subjects"]
    if not isinstance(subjects, dict) or set(subjects) != expected_subjects:
        raise BuildError("proof index must cover exactly the four SDK proof subjects")
    proof_names: set[str] = set()
    path_aliases: dict[str, tuple[int, str]] = {}
    digest_sizes: dict[str, int] = {}
    normalized: dict[str, list[dict[str, Any]]] = {}
    for subject in sorted(expected_subjects):
        rows = subjects[subject]
        if not isinstance(rows, list) or not rows:
            raise BuildError(f"proof index subject {subject} must have at least one proof")
        if len(rows) > 64:
            raise BuildError(f"proof index subject {subject} exceeds the proof-count limit")
        normalized_rows: list[dict[str, Any]] = []
        seen_subject_paths: set[str] = set()
        seen_subject_digests: set[str] = set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}:
                raise BuildError(f"proof record for {subject} must contain path, bytes and sha256")
            name = _safe_leaf(row["path"], "proof path")
            size = row["bytes"]
            digest = row["sha256"]
            if not isinstance(size, int) or isinstance(size, bool) or size < 1 or size > MAX_PROOF_BYTES:
                raise BuildError(f"invalid or oversized proof length: {name}")
            if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
                raise BuildError(f"invalid proof SHA-256: {name}")
            if name in seen_subject_paths or digest in seen_subject_digests:
                raise BuildError(f"proof index repeats a proof within subject {subject}: {name}")
            previous_alias = path_aliases.get(name)
            if previous_alias is not None and previous_alias != (size, digest):
                raise BuildError(f"proof path has conflicting subject aliases: {name}")
            previous_size = digest_sizes.get(digest)
            if previous_size is not None and previous_size != size:
                raise BuildError(f"proof digest has conflicting sizes: {digest}")
            path_aliases[name] = (size, digest)
            digest_sizes[digest] = size
            seen_subject_paths.add(name)
            seen_subject_digests.add(digest)
            proof_names.add(name)
            normalized_rows.append({"path": name, "bytes": size, "sha256": digest})
        normalized[subject] = normalized_rows
    total_expected = sum(digest_sizes.values())
    if total_expected > MAX_TOTAL_PROOF_BYTES:
        raise BuildError("proof files exceed the total input limit")
    actual_names = _directory_names(directory, "proofs")
    if actual_names != proof_names:
        missing = sorted(proof_names - actual_names)
        extra = sorted(actual_names - proof_names)
        raise BuildError(f"proof files differ from proof index (missing={missing}, extra={extra})")
    proofs: dict[str, bytes] = {}
    for subject in sorted(normalized):
        for row in normalized[subject]:
            name = row["path"]
            data = _read_regular(directory / name, f"proofs/{name}", row["bytes"])
            if len(data) != row["bytes"] or _sha256(data) != row["sha256"]:
                raise BuildError(f"proof file does not match proof index: {name}")
            try:
                _parse_json(data, f"proofs/{name}")
            except (BuildError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise BuildError(f"proof file is not valid JSON: {name}: {exc}") from exc
            proofs[name] = data
    return proofs, index_raw, {"subjects": normalized}


def _verify_pinned_publisher_proofs(
    pins: dict[str, Any], subject_map: dict[str, str], normalized_index: dict[str, Any]
) -> None:
    """Bind packaged proof bytes to the proof identities frozen in pins.json.

    Development fixtures predating publisher_proofs remain usable, but release
    pins that include this field must enumerate exactly the four actual asset
    subject names and the complete proof digest set for each one. Paths are
    intentionally omitted from the pins: the identity is the proof bytes.
    """
    if "publisher_proofs" not in pins:
        return
    expected_subjects = set(subject_map.values())
    pinned = pins["publisher_proofs"]
    if not isinstance(pinned, dict) or set(pinned) != expected_subjects:
        raise BuildError("pins.json publisher_proofs must cover exactly the four actual SDK asset subjects")

    actual_subjects = normalized_index.get("subjects")
    if not isinstance(actual_subjects, dict) or set(actual_subjects) != expected_subjects:
        raise BuildError("normalized proof index differs from the pinned SDK asset subjects")
    for subject in sorted(expected_subjects):
        rows = pinned[subject]
        if not isinstance(rows, list) or not rows or len(rows) > 64:
            raise BuildError(f"pins.json publisher_proofs for {subject} must be a bounded nonempty list")
        pinned_identities: list[tuple[int, str]] = []
        for row in rows:
            if not isinstance(row, dict) or set(row) != {"bytes", "sha256"}:
                raise BuildError(f"pins.json publisher proof for {subject} must contain bytes and sha256")
            size, digest = row["bytes"], row["sha256"]
            if (not isinstance(size, int) or isinstance(size, bool) or not 1 <= size <= MAX_PROOF_BYTES
                    or not isinstance(digest, str) or not SHA256_RE.fullmatch(digest)):
                raise BuildError(f"pins.json publisher proof has invalid metadata for {subject}")
            pinned_identities.append((size, digest))
        if len(set(pinned_identities)) != len(pinned_identities):
            raise BuildError(f"pins.json publisher_proofs repeats a proof for {subject}")

        indexed_rows = actual_subjects[subject]
        if not isinstance(indexed_rows, list):
            raise BuildError(f"normalized proof index is malformed for {subject}")
        indexed_identities = [(row["bytes"], row["sha256"]) for row in indexed_rows]
        if sorted(indexed_identities) != sorted(pinned_identities):
            raise BuildError(f"publisher proof bytes for {subject} differ from pins.json")


def _write_file(root: Path, relative: str, data: bytes, mode: int) -> None:
    destination = root.joinpath(*PurePosixPath(relative).parts)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    with destination.open("xb") as stream:
        stream.write(data)
    os.chmod(destination, mode)


def _file_digest(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return {"bytes": size, "sha256": digest.hexdigest()}


def _inventory(libexec_root: Path, sdk_version: str, package_version: str) -> bytes:
    rows: list[dict[str, Any]] = []
    for path in sorted(libexec_root.rglob("*")):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise BuildError(f"generated package tree contains a non-regular file: {path.name}")
        relative = path.relative_to(libexec_root).as_posix()
        digest = _file_digest(path)
        rows.append(
            {
                "path": relative,
                "bytes": digest["bytes"],
                "sha256": digest["sha256"],
                "mode": stat.S_IMODE(info.st_mode),
            }
        )
    rows.sort(key=lambda row: row["path"])
    return _json_bytes(
        {
            "schema": INVENTORY_SCHEMA,
            "sdk_version": sdk_version,
            "package_version": package_version,
            "files": rows,
        }
    )


def _tar_bytes(
    files: dict[str, tuple[bytes, int]], epoch: int, *, prefix: str = "", gzip_compression: bool = False
) -> bytes:
    out = io.BytesIO()
    if gzip_compression:
        with _gzip_writer(out) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                _write_tar_members(archive, files, epoch, prefix)
    else:
        with tarfile.open(
            fileobj=out, mode="w:xz", format=tarfile.USTAR_FORMAT, preset=9
        ) as archive:
            _write_tar_members(archive, files, epoch, prefix)
    return out.getvalue()


class _gzip_writer:
    """gzip writer that emits a stable header with a zero timestamp."""

    def __init__(self, destination: io.BytesIO) -> None:
        import gzip

        self._stream = gzip.GzipFile(filename="", mode="wb", fileobj=destination, compresslevel=9, mtime=0)

    def __enter__(self):
        return self._stream

    def __exit__(self, exc_type, exc, traceback):
        self._stream.close()
        return False


def _write_tar_members(archive: tarfile.TarFile, files: dict[str, tuple[bytes, int]], epoch: int, prefix: str) -> None:
    all_paths = {prefix.rstrip("/")} if prefix else set()
    for relative in files:
        full = f"{prefix.rstrip('/')}/{relative}" if prefix else relative
        parent = PurePosixPath(full).parent
        while parent != PurePosixPath("."):
            all_paths.add(parent.as_posix())
            parent = parent.parent
    for directory in sorted(all_paths, key=lambda value: (value.count("/"), value)):
        name = directory.rstrip("/") + "/"
        info = tarfile.TarInfo(name)
        info.type = tarfile.DIRTYPE
        info.size = 0
        info.mode = 0o755
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = epoch
        archive.addfile(info)
    for relative in sorted(files):
        data, mode = files[relative]
        name = f"{prefix.rstrip('/')}/{relative}" if prefix else relative
        info = tarfile.TarInfo(name)
        info.type = tarfile.REGTYPE
        info.size = len(data)
        info.mode = mode
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = epoch
        archive.addfile(info, io.BytesIO(data))


def _debian_control(pins: dict[str, Any], files: dict[str, tuple[bytes, int]]) -> bytes:
    install_size = sum(len(data) for data, _mode in files.values())
    kb = (install_size + 1023) // 1024
    lines = [
        "Package: ami-rust",
        f"Version: {pins['package_version']}",
        "Section: devel",
        "Priority: optional",
        "Architecture: amd64",
        f"Maintainer: {pins['maintainer']}",
        "Depends: python3 (>= 3.10), git, ca-certificates",
        f"Installed-Size: {kb}",
        "Description: Native PC x86-64 AROS ABI-v1 SDK host tooling",
        " Installs the pinned ami-rust SDK payload and package verifier.",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def _ar_member(name: str, data: bytes, epoch: int, mode: int = 0o100644) -> bytes:
    encoded_name = (name + "/").encode("ascii")
    if len(encoded_name) > 16:
        raise BuildError(f"ar member name is too long: {name}")
    header = (
        encoded_name.ljust(16, b" ")
        + str(epoch).encode("ascii").ljust(12, b" ")
        + b"0".ljust(6, b" ")
        + b"0".ljust(6, b" ")
        + format(mode, "o").encode("ascii").ljust(8, b" ")
        + str(len(data)).encode("ascii").ljust(10, b" ")
        + b"`\n"
    )
    if len(header) != 60:
        raise AssertionError("invalid ar header length")
    return header + data + (b"\n" if len(data) % 2 else b"")


def _ar_bytes(members: list[tuple[str, bytes]], epoch: int) -> bytes:
    return b"!<arch>\n" + b"".join(_ar_member(name, data, epoch) for name, data in members)


def _parse_ar(data: bytes) -> dict[str, bytes]:
    if not data.startswith(b"!<arch>\n"):
        raise BuildError("generated Debian package has an invalid ar signature")
    position = 8
    result: dict[str, bytes] = {}
    while position < len(data):
        if position + 60 > len(data):
            raise BuildError("generated Debian package has a truncated ar header")
        header = data[position : position + 60]
        if header[58:60] != b"`\n":
            raise BuildError("generated Debian package has an invalid ar member header")
        try:
            name = header[:16].decode("ascii").strip().rstrip("/")
            size = int(header[48:58].decode("ascii").strip())
        except (UnicodeDecodeError, ValueError) as exc:
            raise BuildError("generated Debian package has malformed ar metadata") from exc
        position += 60
        end = position + size
        if end > len(data) or name in result:
            raise BuildError("generated Debian package has an invalid ar member length/name")
        result[name] = data[position:end]
        position = end + (size % 2)
    if position != len(data):
        raise BuildError("generated Debian package has trailing ar bytes")
    return result


def _read_tar_members(data: bytes, *, gzip_compression: bool = False) -> dict[str, tuple[bytes, int]]:
    try:
        mode = "r:gz" if gzip_compression else "r:xz"
        with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as archive:
            result: dict[str, tuple[bytes, int]] = {}
            for member in archive.getmembers():
                name = member.name
                if name.startswith("/") or "\\" in name or any(part in {"", ".", ".."} for part in name.rstrip("/").split("/")):
                    raise BuildError(f"generated package contains an unsafe archive path: {name}")
                if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                    raise BuildError(f"generated package contains an unsupported archive entry: {name}")
                if member.isdir():
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    raise BuildError(f"cannot read generated archive member: {name}")
                if name in result:
                    raise BuildError(f"generated archive contains a duplicate file: {name}")
                result[name] = (stream.read(), member.mode)
            return result
    except (tarfile.TarError, lzma.LZMAError) as exc:
        raise BuildError(f"generated package archive cannot be read: {exc}") from exc


def _expected_install_files(tree: Path) -> dict[str, tuple[bytes, int]]:
    result: dict[str, tuple[bytes, int]] = {}
    for path in sorted(tree.rglob("*")):
        info = path.lstat()
        relative = path.relative_to(tree).as_posix()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise BuildError(f"generated install tree contains a non-regular file: {relative}")
        result[relative] = (path.read_bytes(), stat.S_IMODE(info.st_mode))
    return result


def _verify_readback(
    archive_data: bytes,
    deb_data: bytes,
    expected: dict[str, tuple[bytes, int]],
    package_version: str,
    control_bytes: bytes,
) -> None:
    archive_files = _read_tar_members(archive_data)
    archive_prefix = f"ami-rust-{package_version}"
    archive_expected = {f"{archive_prefix}/{path}": value for path, value in expected.items()}
    if archive_files != archive_expected:
        raise BuildError("generated release archive failed file inventory readback")
    members = _parse_ar(deb_data)
    if set(members) != {"debian-binary", "control.tar.gz", "data.tar.xz"}:
        raise BuildError("generated Debian package has an unexpected member inventory")
    if members["debian-binary"] != b"2.0\n":
        raise BuildError("generated Debian package has an invalid debian-binary member")
    control_files = _read_tar_members(members["control.tar.gz"], gzip_compression=True)
    if set(control_files) != {"control"} or control_files["control"][0] != control_bytes:
        raise BuildError("generated Debian control archive failed readback")
    data_files = _read_tar_members(members["data.tar.xz"])
    if data_files != expected:
        raise BuildError("generated Debian package failed file inventory readback")


def build(*args: Any, **kwargs: Any) -> dict[str, Any]:
    """The CLI-package producer is retired; no files may be generated."""
    raise BuildError(
        "The ami-rust CLI package producer was retired on 2026-10-21. "
        "The replacement rustup/Cargo toolchain and crate release is not yet qualified."
    )

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, help="source checkout (defaults to this script's repository)")
    parser.add_argument("--assets", type=Path, required=True, help="directory containing the six pinned SDK assets")
    parser.add_argument("--proofs", type=Path, required=True, help="flat directory of indexed proof JSON files")
    parser.add_argument("--proof-index", type=Path, required=True, help="JSON index for the four proof subjects")
    parser.add_argument("--output", type=Path, required=True, help="fresh output directory")
    parser.add_argument("--epoch", type=int, required=True, help="fixed Unix timestamp for package metadata")
    args = parser.parse_args(argv)
    try:
        report = build(args.source, args.assets, args.proofs, args.proof_index, args.output, args.epoch)
    except (BuildError, OSError, tarfile.TarError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
