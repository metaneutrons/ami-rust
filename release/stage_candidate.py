#!/usr/bin/env python3
"""Assemble an offline SDK release candidate for later external verification.

The input bundle must already have been authenticated and accepted by its
caller. This module checks byte identities and safe transport structure only;
it does not verify signatures, contact a publisher, or claim R1 acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from types import ModuleType
from typing import Any


_COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_INNER_SBOM_NAME = "sbom.spdx.json"
_SMALL_JSON_LIMIT = 1024 * 1024
_CHECKSUM_LIMIT = 16 * 1024


def _load_sibling(filename: str, module_name: str) -> ModuleType:
    path = Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load release helper " + filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_TRANSPORT = _load_sibling("public_transport.py", "_ami_rust_stage_public_transport")
_REPLAY = _load_sibling("public_replay.py", "_ami_rust_stage_public_replay")


def asset_names(tag: str) -> dict[str, str]:
    """Return the complete, canonical six-file candidate asset set."""
    core = _REPLAY.release_core(tag)
    payload = f"ami-rust-{core}-release.tar.xz"
    transport = f"ami-rust-{core}-transport.json"
    return {
        "payload": payload,
        "sbom": payload + ".spdx.json",
        "payload_signature": payload + ".sigstore.json",
        "transport": transport,
        "transport_signature": transport + ".sigstore.json",
        "checksums": "SHA256SUMS",
    }


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON contains a duplicate object key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("JSON contains a nonstandard numeric constant")


def _json_object(raw: bytes, label: str) -> dict[str, Any]:
    if not raw:
        raise ValueError(label + " must be nonempty JSON")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(label + " must be valid UTF-8 JSON") from error
    if type(value) is not dict:
        raise ValueError(label + " must be a JSON object")
    return value


def _real_input_directory(path: Path, label: str) -> Path:
    value = Path(path)
    if not value.is_absolute():
        raise ValueError(label + " must be an absolute path")
    try:
        resolved = value.resolve(strict=True)
        info = value.lstat()
    except OSError as error:
        raise ValueError(label + " must be an existing real directory") from error
    if resolved != value or not stat.S_ISDIR(info.st_mode):
        raise ValueError(label + " must be an existing real directory without symlink components")
    return value


def _fresh_output_path(path: Path) -> tuple[Path, Path]:
    value = Path(path)
    if not value.is_absolute() or not value.name or value.name in {".", ".."}:
        raise ValueError("output must be an absolute fresh directory path")
    parent = value.parent
    try:
        resolved_parent = parent.resolve(strict=True)
        parent_info = parent.lstat()
    except OSError as error:
        raise ValueError("output parent must be an existing real directory") from error
    if resolved_parent != parent or not stat.S_ISDIR(parent_info.st_mode):
        raise ValueError("output parent must be a real directory without symlink components")
    try:
        value.lstat()
    except FileNotFoundError:
        return value, parent
    except OSError as error:
        raise ValueError("output path could not be checked") from error
    raise ValueError("output path must be fresh")


def _check_separate(bundle: Path, output: Path) -> None:
    if (bundle == output or bundle in output.parents or output in bundle.parents):
        raise ValueError("output directory must be outside and separate from the input bundle")


def _record_files(record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    try:
        _TRANSPORT._validate_record(record)
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("transport metadata does not match the public transport schema") from error
    rows = record["files"]
    return {row["path"]: row for row in rows}


def _validate_release_manifest(manifest_bytes: bytes, record: dict[str, Any],
                               expected_version: str, sbom_name: str
                               ) -> tuple[dict[str, Any], str]:
    manifest = _json_object(manifest_bytes, "release.json")
    if (manifest.get("schema") != "ami-rust-release-v1"
            or manifest.get("version") != expected_version
            or manifest.get("qualification_only") is not False):
        raise ValueError("release.json must identify the selected production release core")
    producer = manifest.get("producer")
    source_commit = producer.get("source_sha") if type(producer) is dict else None
    if type(source_commit) is not str or _COMMIT_RE.fullmatch(source_commit) is None:
        raise ValueError("release.json producer.source_sha must be a canonical lowercase 40-character commit")

    files = _record_files(record)
    rows = manifest.get("assets")
    if type(rows) is not list:
        raise ValueError("release.json assets must be a list")
    declared: set[str] = set()
    for row in rows:
        if type(row) is not dict or set(row) != {"path", "bytes", "sha256"}:
            raise ValueError("release.json contains a malformed asset row")
        relative = row["path"]
        try:
            _TRANSPORT._safe_relative_path(relative)
        except (TypeError, ValueError) as error:
            raise ValueError("release.json contains an unsafe asset path") from error
        if relative in declared:
            raise ValueError("release.json contains a duplicate asset path")
        declared.add(relative)
        size, digest = row["bytes"], row["sha256"]
        if (type(size) is not int or size < 0 or type(digest) is not str
                or _DIGEST_RE.fullmatch(digest) is None):
            raise ValueError("release.json contains an invalid asset byte or digest pin")
        record_row = files.get(relative)
        if (record_row is None or record_row["bytes"] != size
                or record_row["sha256"] != digest):
            raise ValueError("release.json asset pins differ from the complete transport inventory")
        if relative == sbom_name:
            if size == 0:
                raise ValueError("release.json SBOM asset must be nonempty")

    if sbom_name not in declared:
        raise ValueError("release.json does not declare the " + sbom_name + " asset")
    if sbom_name not in files:
        raise ValueError("transport inventory does not contain " + sbom_name)
    return manifest, source_commit


def _inspect_payload(payload_path: Path, record: dict[str, Any], tag: str,
                     temp_parent: Path, *, outer_sbom: bytes | None = None
                     ) -> tuple[dict[str, Any], bytes, str, str]:
    names = asset_names(tag)
    expected_version = _REPLAY.release_core(tag)
    if payload_path.name != names["payload"]:
        raise ValueError("payload name differs from the selected release core")
    record_files = _record_files(record)
    expected_archive = record["archive"]
    if expected_archive["name"] != names["payload"]:
        raise ValueError("transport archive pins differ from the release payload")
    if "release.json" not in record_files or _INNER_SBOM_NAME not in record_files:
        raise ValueError("transport inventory must contain release.json and " + _INNER_SBOM_NAME)

    with tempfile.TemporaryDirectory(prefix=".stage-readback-", dir=temp_parent) as readback_root:
        destination = Path(readback_root) / "bundle"
        receipt = _TRANSPORT.unpack_bundle(payload_path, record, destination)
        if receipt != record:
            raise ValueError("transport readback record differs from the complete prepared record")
        extracted = dict(_TRANSPORT._scan_bundle(destination))
        manifest_bytes = extracted.get("release.json")
        sbom_bytes = extracted.get(_INNER_SBOM_NAME)
        if manifest_bytes is None or sbom_bytes is None:
            raise ValueError("transport readback omits release.json or " + _INNER_SBOM_NAME)
        manifest, source_commit = _validate_release_manifest(
            manifest_bytes, record, expected_version, _INNER_SBOM_NAME)
        expected_sbom_row = next(row for row in manifest["assets"]
                                 if row["path"] == _INNER_SBOM_NAME)
        actual_sbom_digest = hashlib.sha256(sbom_bytes).hexdigest()
        if (len(sbom_bytes) != expected_sbom_row["bytes"]
                or actual_sbom_digest != expected_sbom_row["sha256"]):
            raise ValueError("release.json SBOM asset hashes do not match the packed bundle")
        if outer_sbom is not None and outer_sbom != sbom_bytes:
            raise ValueError("copied SBOM differs from the exact bundle asset bytes")
        manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
        return manifest, sbom_bytes, source_commit, manifest_digest


def _scan_output(output: Path, tag: str, *keys: str) -> tuple[Path, dict[str, bytes]]:
    root = Path(output)
    names = asset_names(tag)
    expected = _expected_paths(names, *keys) if keys else set(names.values())
    return root, _scan_candidate_files(root, expected, names)


def _outer_limits(names: dict[str, str]) -> dict[str, int]:
    return {
        names["payload"]: _TRANSPORT.MAX_ARCHIVE_BYTES,
        names["sbom"]: _TRANSPORT.MAX_TOTAL_BYTES,
        names["transport"]: _SMALL_JSON_LIMIT,
        names["payload_signature"]: _SMALL_JSON_LIMIT,
        names["transport_signature"]: _SMALL_JSON_LIMIT,
        names["checksums"]: _CHECKSUM_LIMIT,
    }


def _scan_candidate_files(output: Path, expected: set[str],
                          names: dict[str, str]) -> dict[str, bytes]:
    """Read an exact flat asset set with per-file bounds and safe file handles."""
    root = _TRANSPORT._real_directory(Path(output), "output")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise RuntimeError("safe directory-relative file access is unavailable on this platform")
    limits = _outer_limits(names)
    root_info = root.lstat()
    root_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        root_fd = os.open(str(root), root_flags)
    except OSError as error:
        raise ValueError("output directory could not be opened safely") from error
    if _TRANSPORT._signature(root_info) != _TRANSPORT._signature(os.fstat(root_fd)):
        os.close(root_fd)
        raise ValueError("output directory changed while it was being opened")
    files: dict[str, bytes] = {}
    try:
        before = os.fstat(root_fd)
        entries = sorted(os.listdir(root_fd))
        if set(entries) != expected:
            missing = sorted(expected - set(entries))
            extra = sorted(set(entries) - expected)
            detail = []
            if missing:
                detail.append("missing " + ", ".join(missing))
            if extra:
                detail.append("unexpected " + ", ".join(extra))
            raise ValueError("release candidate has the wrong file set (" + "; ".join(detail) + ")")
        for name in entries:
            _TRANSPORT._safe_component(name)
            try:
                info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            except OSError as error:
                raise ValueError("output entry changed while it was being inspected") from error
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("release candidate contains a link or non-regular member")
            maximum = limits.get(name)
            if maximum is None:
                raise ValueError("release candidate contains an unrecognized filename")
            files[name] = _TRANSPORT._read_regular_at(root_fd, name, info, maximum)
        after = os.fstat(root_fd)
        if (_TRANSPORT._signature(before) != _TRANSPORT._signature(after)
                or sorted(os.listdir(root_fd)) != entries):
            raise ValueError("output directory changed while it was being read")
    finally:
        os.close(root_fd)
    return files


def _expected_paths(names: dict[str, str], *keys: str) -> set[str]:
    return {names[key] for key in keys}


def _require_exact_paths(files: dict[str, bytes], expected: set[str], label: str) -> None:
    observed = set(files)
    if observed != expected:
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("unexpected " + ", ".join(extra))
        raise ValueError(label + " has the wrong file set (" + "; ".join(detail) + ")")


def _load_transport(files: dict[str, bytes], names: dict[str, str]
                    ) -> dict[str, Any]:
    raw = files[names["transport"]]
    record = _json_object(raw, names["transport"])
    if _canonical_json(record) != raw:
        raise ValueError("transport metadata is not canonical JSON")
    _record_files(record)
    return record


def _checksum_bytes(files: dict[str, bytes], names: dict[str, str]) -> bytes:
    rows = []
    for filename in sorted(name for key, name in names.items() if key != "checksums"):
        raw = files[filename]
        rows.append(hashlib.sha256(raw).hexdigest() + "  " + filename + "\n")
    return "".join(rows).encode("ascii")


def _write_new_file(directory: Path, name: str, data: bytes) -> None:
    """Create one fresh file without following a link in the output directory."""
    root = _real_input_directory(directory, "output")
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise RuntimeError("safe directory-relative file creation is unavailable on this platform")
    root_info = root.lstat()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        root_fd = os.open(str(root), flags)
    except OSError as error:
        raise ValueError("output directory could not be opened safely") from error
    file_fd = -1
    try:
        opened_root = os.fstat(root_fd)
        if (not stat.S_ISDIR(opened_root.st_mode)
                or (root_info.st_dev, root_info.st_ino) != (opened_root.st_dev, opened_root.st_ino)):
            raise ValueError("output directory changed while it was being opened")
        file_flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                      | getattr(os, "O_CLOEXEC", 0))
        try:
            file_fd = os.open(name, file_flags, 0o600, dir_fd=root_fd)
        except OSError as error:
            raise ValueError("checksum destination was not fresh or could not be created safely") from error
        created = os.fstat(file_fd)
        if not stat.S_ISREG(created.st_mode) or created.st_nlink != 1:
            raise ValueError("checksum destination is linked or not a regular file")
        view = memoryview(data)
        while view:
            written = os.write(file_fd, view)
            if written <= 0:
                raise OSError("short write while creating SHA256SUMS")
            view = view[written:]
        os.fsync(file_fd)
    except BaseException:
        if file_fd >= 0:
            try:
                os.unlink(name, dir_fd=root_fd)
            except OSError:
                pass
        raise
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(root_fd)


def _validate_prepared(output: Path, tag: str, files: dict[str, bytes],
                       *, signatures: bool, checksums: bool = False
                       ) -> tuple[dict[str, Any], str, str]:
    names = asset_names(tag)
    keys = ("payload", "sbom", "transport", "payload_signature", "transport_signature") if signatures else (
        "payload", "sbom", "transport")
    if checksums:
        keys = (*keys, "checksums")
    _require_exact_paths(files, _expected_paths(names, *keys), "release candidate")
    record = _load_transport(files, names)
    for key in ("payload_signature", "transport_signature"):
        if signatures:
            _json_object(files[names[key]], names[key])
    with tempfile.TemporaryDirectory(prefix=".stage-payload-check-", dir=output.parent) as private:
        # The payload path is already in the safely scanned output. The bounded
        # transport reader pins it again before extraction.
        payload_path = output / names["payload"]
        manifest, _sbom, source_commit, manifest_digest = _inspect_payload(
            payload_path, record, tag, Path(private), outer_sbom=files[names["sbom"]])
        return manifest, source_commit, manifest_digest


def _asset_inventory(files: dict[str, bytes]) -> list[dict[str, object]]:
    return [
        {"path": path, "bytes": len(files[path]), "sha256": hashlib.sha256(files[path]).hexdigest()}
        for path in sorted(files)
    ]


def _summary(tag: str, files: dict[str, bytes], source_commit: str,
             manifest_digest: str) -> dict[str, object]:
    return {
        "tag": tag,
        "version": _REPLAY.release_core(tag),
        "source_commit": source_commit,
        "release_json_sha256": manifest_digest,
        "assets": _asset_inventory(files),
    }


def prepare(tag: str, bundle: Path, output: Path) -> dict[str, object]:
    """Stage a bundle already authenticated and accepted by the caller.

    All checks here are structural and byte-identity checks. The caller remains
    responsible for establishing bundle trust and for any later cryptographic
    verification or R1 decision. Installation uses an exclusive fresh directory
    and exclusive file creation; an I/O error may leave a partial directory,
    which finalize and verify_candidate reject until all files are present.
    """
    names = asset_names(tag)
    bundle_path = _real_input_directory(Path(bundle), "bundle")
    target, parent = _fresh_output_path(Path(output))
    _check_separate(bundle_path, target)

    with tempfile.TemporaryDirectory(prefix=".release-candidate-", dir=parent) as temporary:
        stage = Path(temporary)
        payload_path = stage / names["payload"]
        record = _TRANSPORT.pack_bundle(bundle_path, payload_path)
        transport_bytes = _canonical_json(record)
        _manifest, sbom_bytes, source_commit, manifest_digest = _inspect_payload(
            payload_path, record, tag, stage)
        (stage / names["transport"]).write_bytes(transport_bytes)
        (stage / names["sbom"]).write_bytes(sbom_bytes)
        staged_files = _scan_candidate_files(
            stage, _expected_paths(names, "payload", "sbom", "transport"), names)
        _require_exact_paths(staged_files, _expected_paths(names, "payload", "sbom", "transport"),
                             "prepared release candidate")
        if (staged_files[names["transport"]] != transport_bytes
                or staged_files[names["sbom"]] != sbom_bytes
                or hashlib.sha256(staged_files[names["payload"]]).hexdigest()
                != record["archive"]["sha256"]):
            raise ValueError("prepared release candidate changed before installation")
        # The transport readback above also checked every declared asset pin,
        # including the SBOM, against the full packed bundle inventory.
        try:
            target.mkdir(mode=0o700)
        except FileExistsError as error:
            raise ValueError("output path must remain fresh until the candidate is installed") from error
        for filename in sorted(staged_files):
            _write_new_file(target, filename, staged_files[filename])
        installed_files = _scan_candidate_files(
            target, _expected_paths(names, "payload", "sbom", "transport"), names)
        if installed_files != staged_files:
            raise ValueError("installed release candidate differs from the validated private stage")
        return _summary(tag, installed_files, source_commit, manifest_digest)


def finalize(output: Path, tag: str) -> dict[str, object]:
    """Bind the five prepared assets to exact-byte SHA256SUMS after signatures exist.

    Signature files are required to be nonempty JSON objects. Their signatures
    are not verified here; the caller must perform that cryptographic check.
    """
    names = asset_names(tag)
    root, files = _scan_output(
        Path(output), tag, "payload", "sbom", "transport",
        "payload_signature", "transport_signature")
    _require_exact_paths(
        files,
        _expected_paths(names, "payload", "sbom", "transport",
                        "payload_signature", "transport_signature"),
        "pre-final candidate",
    )
    _validate_prepared(root, tag, files, signatures=True)
    checksum_data = _checksum_bytes(files, names)
    _write_new_file(root, names["checksums"], checksum_data)
    return verify_candidate(root, tag)


def verify_candidate(output: Path, tag: str) -> dict[str, object]:
    """Check the exact six-file set and checksum bytes without changing output.

    This function records hashes only. It does not verify Sigstore signatures
    or claim publisher authentication or R1 acceptance.
    """
    names = asset_names(tag)
    root, files = _scan_output(Path(output), tag)
    _require_exact_paths(files, set(names.values()), "release candidate")
    for key in ("payload_signature", "transport_signature"):
        _json_object(files[names[key]], names[key])
    expected_checksums = _checksum_bytes(files, names)
    if files[names["checksums"]] != expected_checksums:
        raise ValueError("SHA256SUMS does not match the exact five candidate assets")
    _manifest, source_commit, manifest_digest = _validate_prepared(
        root, tag, files, signatures=True, checksums=True)
    return _summary(tag, files, source_commit, manifest_digest)


def _cli() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare", help="pack an already accepted release bundle")
    prepare_parser.add_argument("--tag", required=True)
    prepare_parser.add_argument("--bundle", type=Path, required=True)
    prepare_parser.add_argument("--output", type=Path, required=True)
    finalize_parser = commands.add_parser("finalize", help="write SHA256SUMS after signatures are present")
    finalize_parser.add_argument("--tag", required=True)
    finalize_parser.add_argument("--output", type=Path, required=True)
    verify_parser = commands.add_parser("verify", help="check a finalized local candidate")
    verify_parser.add_argument("--tag", required=True)
    verify_parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        if arguments.command == "prepare":
            result = prepare(arguments.tag, arguments.bundle, arguments.output)
        elif arguments.command == "finalize":
            result = finalize(arguments.output, arguments.tag)
        else:
            result = verify_candidate(arguments.output, arguments.tag)
    except (OSError, RuntimeError, ValueError) as error:
        parser.exit(2, "stage_candidate: " + str(error) + "\n")
    sys.stdout.buffer.write(_canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
