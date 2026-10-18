#!/usr/bin/env python3
"""Seal and verify an offline package-release file inventory.

This records byte identities only. It does not verify GitHub attestations or
Cosign signatures; those checks belong to the separate publication workflow.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any


PINS_SCHEMA = "ami-rust-package-inputs-v1"
CANDIDATE_SCHEMA = "ami-rust-package-candidate-v1"
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
MAX_EPOCH = (1 << 33) - 1
MAX_PAYLOAD_BYTES = 512 * 1024 * 1024
MAX_SBOM_BYTES = 128 * 1024 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_SUM_BYTES = 16 * 1024
CHUNK_BYTES = 1024 * 1024


class CandidateError(ValueError):
    """Raised when pins or a candidate inventory violate the package contract."""


def _canonical_json(value: Any) -> bytes:
    try:
        return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                           allow_nan=False) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise CandidateError("candidate metadata is not canonical JSON data") from error


def _parse_json(raw: bytes, label: str) -> Any:
    def unique_pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in rows:
            if key in value:
                raise CandidateError(f"{label} contains a duplicate JSON key: {key}")
            value[key] = item
        return value

    def reject_constant(value: str) -> None:
        raise CandidateError(f"{label} contains a nonstandard JSON constant: {value}")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                          parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise CandidateError(f"{label} is not valid bounded UTF-8 JSON") from error


def _read_regular(path: Path, label: str, limit: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise CandidateError(f"cannot open {label}") from error
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size <= 0 or info.st_size > limit):
            raise CandidateError(f"{label} is linked, empty, non-regular or oversized")
        chunks: list[bytes] = []
        size = 0
        while True:
            block = os.read(fd, min(CHUNK_BYTES, limit - size + 1))
            if not block:
                break
            size += len(block)
            if size > limit:
                raise CandidateError(f"{label} exceeds its byte bound")
            chunks.append(block)
        if size != info.st_size:
            raise CandidateError(f"{label} changed while being read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _digest_regular(path: Path, label: str, limit: int) -> dict[str, Any]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise CandidateError(f"cannot open {label}") from error
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_size <= 0 or info.st_size > limit):
            raise CandidateError(f"{label} is linked, empty, non-regular or oversized")
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(fd, CHUNK_BYTES)
            if not block:
                break
            size += len(block)
            if size > limit:
                raise CandidateError(f"{label} exceeds its byte bound")
            digest.update(block)
        if size != info.st_size:
            raise CandidateError(f"{label} changed while being hashed")
        return {"bytes": size, "sha256": digest.hexdigest()}
    finally:
        os.close(fd)


def _write_new(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags, 0o644)
    except OSError as error:
        raise CandidateError(f"candidate output already exists or cannot be created: {path.name}") from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise CandidateError(f"candidate output is not a new regular file: {path.name}")
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("short candidate write")
            view = view[count:]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        raise
    else:
        os.close(fd)


def _load_pins(path: Path) -> dict[str, Any]:
    raw = _read_regular(path, "pins.json", MAX_METADATA_BYTES)
    pins = _parse_json(raw, "pins.json")
    if type(pins) is not dict or pins.get("schema") != PINS_SCHEMA:
        raise CandidateError(f"pins must use schema {PINS_SCHEMA}")
    version = pins.get("sdk_version")
    revision = pins.get("packaging_revision")
    if (type(version) is not str or VERSION_RE.fullmatch(version) is None
            or type(revision) is not int or revision < 1):
        raise CandidateError("pins SDK version or packaging revision is invalid")
    package_version = f"{version}-{revision}"
    if (pins.get("package_version") != package_version
            or pins.get("sdk_tag") != f"v{version}"
            or pins.get("packaging_tag") != f"v{version}+packaging.{revision}"):
        raise CandidateError("pins package version or tags are inconsistent")
    if type(pins.get("repository")) is not str or not pins["repository"]:
        raise CandidateError("pins repository is invalid")
    for key in ("source_commit", "source_tree"):
        if type(pins.get(key)) is not str or COMMIT_RE.fullmatch(pins[key]) is None:
            raise CandidateError(f"pins {key} is invalid")
    for key in ("manifest_sha256", "transport_sha256"):
        if type(pins.get(key)) is not str or SHA256_RE.fullmatch(pins[key]) is None:
            raise CandidateError(f"pins {key} is invalid")
    for key in ("sdk_run_id", "sdk_run_attempt"):
        if type(pins.get(key)) is not int or pins[key] <= 0:
            raise CandidateError(f"pins {key} is invalid")
    return pins


def asset_names(pins: dict[str, Any]) -> list[str]:
    """Return the ten exact package, metadata, and signature filenames."""
    version = pins["sdk_version"]
    revision = pins["packaging_revision"]
    package_version = pins["package_version"]
    archive = f"ami-rust-{version}-packaging.{revision}.tar.xz"
    deb = f"ami-rust_{package_version}_amd64.deb"
    payloads = (archive, deb)
    names = [
        *payloads,
        *(payload + ".spdx.json" for payload in payloads),
        "ami-rust.rb",
        "packaging-report.json",
        "metadata-report.json",
        *(payload + ".sigstore.json" for payload in payloads),
        "ami-rust.rb.sigstore.json",
    ]
    return sorted(names)


def _file_limit(name: str) -> int:
    if name.endswith((".tar.xz", ".deb")):
        return MAX_PAYLOAD_BYTES
    if name.endswith(".spdx.json"):
        return MAX_SBOM_BYTES
    if name.endswith(".sigstore.json"):
        return MAX_SIGNATURE_BYTES
    return MAX_METADATA_BYTES


def _directory(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise CandidateError("candidate directory must exist") from error
    if not stat.S_ISDIR(info.st_mode) or resolved != path:
        raise CandidateError("candidate directory must be a real directory without symlink components")
    return path


def _scan(path: Path, expected: set[str]) -> dict[str, Path]:
    _directory(path)
    found: dict[str, Path] = {}
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                name = entry.name
                if (not name or name in {".", ".."} or "/" in name or "\\" in name
                        or "\x00" in name):
                    raise CandidateError("candidate directory contains an unsafe filename")
                info = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise CandidateError(f"candidate entry is linked or not a regular file: {name}")
                if name in found:
                    raise CandidateError(f"candidate directory contains a duplicate filename: {name}")
                found[name] = path / name
    except OSError as error:
        raise CandidateError("cannot inspect candidate directory") from error
    if set(found) != expected:
        missing = sorted(expected - set(found))
        extra = sorted(set(found) - expected)
        raise CandidateError(f"candidate file set differs (missing={missing}, extra={extra})")
    return found


def _original_sdk_identity(pins: dict[str, Any]) -> dict[str, Any]:
    return {
        "repository": pins["repository"],
        "version": pins["sdk_version"],
        "tag": pins["sdk_tag"],
        "source_commit": pins["source_commit"],
        "source_tree": pins["source_tree"],
        "run_id": pins["sdk_run_id"],
        "run_attempt": pins["sdk_run_attempt"],
        "manifest_sha256": pins["manifest_sha256"],
        "transport_sha256": pins["transport_sha256"],
    }


def _validate_source(source_commit: str, source_tree: str, run_id: int,
                     run_attempt: int, epoch: int | None, pins: dict[str, Any]) -> None:
    if type(source_commit) is not str or COMMIT_RE.fullmatch(source_commit) is None:
        raise CandidateError("packaging source commit must be a lowercase 40-character Git id")
    if type(source_tree) is not str or COMMIT_RE.fullmatch(source_tree) is None:
        raise CandidateError("packaging source tree must be a lowercase 40-character Git id")
    if source_commit == pins["source_commit"] or source_tree == pins["source_tree"]:
        raise CandidateError("packaging source identity must differ from the pinned SDK source")
    if type(run_id) is not int or run_id <= 0 or type(run_attempt) is not int or run_attempt <= 0:
        raise CandidateError("packaging workflow run identity must use positive integers")
    if epoch is not None and (type(epoch) is not int or not 0 <= epoch <= MAX_EPOCH):
        raise CandidateError(f"epoch must be an integer from 0 through {MAX_EPOCH}")


def _candidate_record(pins: dict[str, Any], source_commit: str, source_tree: str,
                      run_id: int, run_attempt: int, epoch: int,
                      assets: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema": CANDIDATE_SCHEMA,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "epoch": epoch,
        "original_sdk": _original_sdk_identity(pins),
        "assets": [
            {"path": name, **assets[name]}
            for name in sorted(assets)
        ],
    }


def _sums_bytes(rows: dict[str, dict[str, Any]]) -> bytes:
    return "".join(
        f"{rows[name]['sha256']}  {name}\n" for name in sorted(rows)
    ).encode("ascii")


def seal(pins_path: str | os.PathLike[str], directory: str | os.PathLike[str],
         source_commit: str, source_tree: str, run_id: int, run_attempt: int,
         epoch: int) -> dict[str, Any]:
    """Write candidate.json and SHA256SUMS into a fresh ten-file output set."""
    pins = _load_pins(Path(pins_path))
    _validate_source(source_commit, source_tree, run_id, run_attempt, epoch, pins)
    root = _directory(Path(directory))
    files = _scan(root, set(asset_names(pins)))
    rows: dict[str, dict[str, Any]] = {}
    total = 0
    for name in sorted(files):
        row = _digest_regular(files[name], name, _file_limit(name))
        rows[name] = row
        total += row["bytes"]
    if total > 2 * MAX_PAYLOAD_BYTES + 2 * MAX_SBOM_BYTES + 3 * MAX_SIGNATURE_BYTES + 3 * MAX_METADATA_BYTES:
        raise CandidateError("candidate assets exceed the total byte bound")

    candidate = _candidate_record(pins, source_commit, source_tree, run_id,
                                  run_attempt, epoch, rows)
    candidate_raw = _canonical_json(candidate)
    if len(candidate_raw) > MAX_METADATA_BYTES:
        raise CandidateError("candidate.json exceeds its byte bound")
    _write_new(root / "candidate.json", candidate_raw)

    rows["candidate.json"] = {"bytes": len(candidate_raw),
                              "sha256": hashlib.sha256(candidate_raw).hexdigest()}
    sums = _sums_bytes(rows)
    if len(sums) > MAX_SUM_BYTES:
        raise CandidateError("SHA256SUMS exceeds its byte bound")
    _write_new(root / "SHA256SUMS", sums)
    return candidate


def verify(pins_path: str | os.PathLike[str], directory: str | os.PathLike[str],
           source_commit: str, source_tree: str, run_id: int, run_attempt: int,
           epoch: int | None = None) -> dict[str, Any]:
    """Verify exact inventory and checksums; no signature authentication is performed."""
    pins = _load_pins(Path(pins_path))
    _validate_source(source_commit, source_tree, run_id, run_attempt, epoch, pins)
    root = _directory(Path(directory))
    expected_names = set(asset_names(pins)) | {"candidate.json", "SHA256SUMS"}
    files = _scan(root, expected_names)
    rows: dict[str, dict[str, Any]] = {}
    total = 0
    for name in sorted(expected_names - {"SHA256SUMS"}):
        limit = MAX_METADATA_BYTES if name == "candidate.json" else _file_limit(name)
        row = _digest_regular(files[name], name, limit)
        rows[name] = row
        total += row["bytes"]
    if total > 2 * MAX_PAYLOAD_BYTES + 2 * MAX_SBOM_BYTES + 3 * MAX_SIGNATURE_BYTES + 4 * MAX_METADATA_BYTES:
        raise CandidateError("candidate files exceed the total byte bound")

    candidate_raw = _read_regular(files["candidate.json"], "candidate.json", MAX_METADATA_BYTES)
    if (len(candidate_raw) != rows["candidate.json"]["bytes"]
            or hashlib.sha256(candidate_raw).hexdigest() != rows["candidate.json"]["sha256"]):
        raise CandidateError("candidate.json changed while being verified")
    candidate = _parse_json(candidate_raw, "candidate.json")
    expected_keys = {
        "schema", "source_commit", "source_tree", "run_id", "run_attempt",
        "epoch", "original_sdk", "assets",
    }
    if type(candidate) is not dict or set(candidate) != expected_keys:
        raise CandidateError("candidate.json has an unexpected schema")
    if candidate_raw != _canonical_json(candidate):
        raise CandidateError("candidate.json is not canonical")
    if (candidate.get("schema") != CANDIDATE_SCHEMA
            or candidate.get("source_commit") != source_commit
            or candidate.get("source_tree") != source_tree
            or candidate.get("run_id") != run_id
            or candidate.get("run_attempt") != run_attempt
            or (epoch is not None and candidate.get("epoch") != epoch)
            or type(candidate.get("run_id")) is not int
            or type(candidate.get("run_attempt")) is not int
            or type(candidate.get("epoch")) is not int
            or not 0 <= candidate["epoch"] <= MAX_EPOCH):
        raise CandidateError("candidate source, run, or epoch identity differs from expectations")
    if _canonical_json(candidate.get("original_sdk")) != _canonical_json(_original_sdk_identity(pins)):
        raise CandidateError("candidate original SDK identity differs from pins.json")

    declared = candidate.get("assets")
    if type(declared) is not list or len(declared) != len(asset_names(pins)):
        raise CandidateError("candidate asset inventory has the wrong size")
    declared_rows: dict[str, dict[str, Any]] = {}
    for item in declared:
        if type(item) is not dict or set(item) != {"path", "bytes", "sha256"}:
            raise CandidateError("candidate asset inventory row is malformed")
        name = item["path"]
        if type(name) is not str or name in declared_rows:
            raise CandidateError("candidate asset inventory has an invalid or duplicate path")
        size = item["bytes"]
        digest = item["sha256"]
        if (type(size) is not int or size < 1 or type(digest) is not str
                or SHA256_RE.fullmatch(digest) is None):
            raise CandidateError("candidate asset inventory has an invalid byte count or digest")
        declared_rows[name] = {"bytes": size, "sha256": digest}
    expected_assets = set(asset_names(pins))
    if set(declared_rows) != expected_assets or [item["path"] for item in declared] != sorted(expected_assets):
        raise CandidateError("candidate asset inventory differs from pins-derived package names")
    for name in expected_assets:
        if declared_rows[name] != rows[name]:
            raise CandidateError(f"candidate asset differs from its inventory: {name}")

    sums_raw = _read_regular(files["SHA256SUMS"], "SHA256SUMS", MAX_SUM_BYTES)
    if sums_raw != _sums_bytes(rows):
        raise CandidateError("SHA256SUMS does not match the exact candidate file set")
    return candidate


def _add_common_arguments(parser: argparse.ArgumentParser, *, sealing: bool) -> None:
    parser.add_argument("--pins", required=True, type=Path)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--run-id", required=True, type=int)
    parser.add_argument("--run-attempt", required=True, type=int)
    parser.add_argument("--epoch", required=sealing, type=int)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    seal_parser = commands.add_parser("seal", help="write an offline candidate inventory and checksums")
    _add_common_arguments(seal_parser, sealing=True)
    verify_parser = commands.add_parser("verify", help="check the offline candidate inventory and checksums")
    _add_common_arguments(verify_parser, sealing=False)
    args = parser.parse_args(argv)
    try:
        if args.mode == "seal":
            record = seal(args.pins, args.directory, args.source_commit, args.source_tree,
                          args.run_id, args.run_attempt, args.epoch)
            status = "SEALED_OFFLINE_INVENTORY_ONLY"
        else:
            record = verify(args.pins, args.directory, args.source_commit, args.source_tree,
                            args.run_id, args.run_attempt, args.epoch)
            status = "VERIFIED_OFFLINE_INVENTORY_ONLY"
    except (CandidateError, OSError) as error:
        sys.stderr.write("ami-rust candidate: " + str(error) + "\n")
        return 2
    sys.stdout.write(json.dumps({"status": status, "source_commit": record["source_commit"],
                                 "source_tree": record["source_tree"],
                                 "run_id": record["run_id"],
                                 "run_attempt": record["run_attempt"],
                                 "asset_count": len(record["assets"])}) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
