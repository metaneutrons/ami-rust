#!/usr/bin/env python3
"""Fetch pinned public SDK assets and their original GitHub attestations."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
from typing import Any, Callable
from urllib.parse import quote
from urllib.request import urlopen


SCHEMA = "ami-rust-package-inputs-v1"
REPORT_SCHEMA = "ami-rust-package-fetch-report-v1"
APPROVED_REPOSITORY = "metaneutrons/ami-rust"
APPROVED_SDK_TAG = "v0.1.0"
MAX_ASSET_BYTES = 128 * 1024 * 1024
MAX_TOTAL_ASSET_BYTES = 256 * 1024 * 1024
MAX_PROOFS_PER_SUBJECT = 8
MAX_PROOF_LINE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_PROOF_BYTES = 32 * 1024 * 1024
MAX_SOURCE_BYTES = 1024 * 1024
CHUNK_BYTES = 1024 * 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class FetchError(ValueError):
    """Raised when remote package inputs do not match their bounded pins."""


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False) + "\n").encode(
        "utf-8"
    )


def _parse_json(data: bytes, label: str) -> Any:
    def unique_pairs(rows: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in rows:
            if key in result:
                raise FetchError(f"{label} contains a duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise FetchError(f"{label} contains a nonstandard JSON constant: {value}")

    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise FetchError(f"{label} is not valid bounded UTF-8 JSON") from error


def _safe_filename(value: Any) -> str:
    if (type(value) is not str or not value or value in {".", ".."}
            or "/" in value or "\\" in value or "\x00" in value
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}", value) is None):
        raise FetchError("pinned SDK asset path is not a safe flat filename")
    return value


def _validate_pins(
    pins: Any,
) -> tuple[dict[str, dict[str, Any]], dict[str, str], dict[str, list[dict[str, Any]]]]:
    if type(pins) is not dict or pins.get("schema") != SCHEMA:
        raise FetchError(f"pins must use schema {SCHEMA}")
    try:
        pins_bytes = json.dumps(pins, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise FetchError("pins must be a bounded JSON-compatible object") from error
    if len(pins_bytes) > MAX_SOURCE_BYTES:
        raise FetchError("pins exceed the one MiB source input bound")
    if pins.get("repository") != APPROVED_REPOSITORY:
        raise FetchError("pins repository is not the approved public SDK repository")
    if pins.get("sdk_tag") != APPROVED_SDK_TAG or pins.get("sdk_version") != "0.1.0":
        raise FetchError("pins must identify the approved SDK release v0.1.0")
    records = pins.get("assets")
    if type(records) is not list or len(records) != 6:
        raise FetchError("pins must identify exactly six SDK assets")

    expected_names = {
        "SHA256SUMS",
        "ami-rust-0.1.0-release.tar.xz",
        "ami-rust-0.1.0-release.tar.xz.sigstore.json",
        "ami-rust-0.1.0-release.tar.xz.spdx.json",
        "ami-rust-0.1.0-transport.json",
        "ami-rust-0.1.0-transport.json.sigstore.json",
    }
    by_name: dict[str, dict[str, Any]] = {}
    total = 0
    for record in records:
        if type(record) is not dict or set(record) != {"path", "bytes", "sha256"}:
            raise FetchError("each asset pin must contain only path, bytes and sha256")
        name = _safe_filename(record["path"])
        size = record["bytes"]
        digest = record["sha256"]
        if name in by_name:
            raise FetchError("pins contain a duplicate SDK asset path")
        if type(size) is not int or not 1 <= size <= MAX_ASSET_BYTES:
            raise FetchError(f"pinned SDK asset length is invalid or oversized: {name}")
        if type(digest) is not str or SHA256_RE.fullmatch(digest) is None:
            raise FetchError(f"pinned SDK asset SHA-256 is invalid: {name}")
        by_name[name] = {"path": name, "bytes": size, "sha256": digest}
        total += size
    if set(by_name) != expected_names:
        raise FetchError("pins do not name the exact six v0.1.0 SDK assets")
    if total > MAX_TOTAL_ASSET_BYTES:
        raise FetchError("pinned SDK assets exceed the total download bound")

    for identity in ("source_commit", "source_tree", "manifest_sha256", "transport_sha256"):
        value = pins.get(identity)
        pattern = r"[0-9a-f]{40}" if identity in {"source_commit", "source_tree"} else SHA256_RE.pattern
        if type(value) is not str or re.fullmatch(pattern, value) is None:
            raise FetchError(f"pins {identity} is invalid")
    transport = by_name["ami-rust-0.1.0-transport.json"]
    if pins["transport_sha256"] != transport["sha256"]:
        raise FetchError("pins transport digest disagrees with its SDK asset pin")

    subjects = {
        "SHA256SUMS": "SHA256SUMS",
        "ami-rust-0.1.0-release.tar.xz": "ami-rust-0.1.0-release.tar.xz",
        "ami-rust-0.1.0-release.tar.xz.spdx.json": "ami-rust-0.1.0-release.tar.xz.spdx.json",
        "ami-rust-0.1.0-transport.json": "ami-rust-0.1.0-transport.json",
    }
    publisher_proofs = pins.get("publisher_proofs")
    expected_subjects = set(subjects.values())
    if type(publisher_proofs) is not dict or set(publisher_proofs) != expected_subjects:
        raise FetchError("pins must identify publisher proofs for the exact four SDK subjects")
    validated_proofs: dict[str, list[dict[str, Any]]] = {}
    all_pinned: dict[str, int] = {}
    for subject in sorted(expected_subjects):
        records = publisher_proofs[subject]
        if type(records) is not list or not 1 <= len(records) <= MAX_PROOFS_PER_SUBJECT:
            raise FetchError(f"publisher proof pins are absent or exceed bounds: {subject}")
        seen: set[str] = set()
        validated: list[dict[str, Any]] = []
        for record in records:
            if type(record) is not dict or set(record) != {"bytes", "sha256"}:
                raise FetchError(f"publisher proof pin is malformed: {subject}")
            size = record["bytes"]
            digest = record["sha256"]
            if type(size) is not int or not 1 <= size <= MAX_PROOF_LINE_BYTES:
                raise FetchError(f"publisher proof pin length is invalid or oversized: {subject}")
            if type(digest) is not str or SHA256_RE.fullmatch(digest) is None:
                raise FetchError(f"publisher proof pin SHA-256 is invalid: {subject}")
            if digest in seen:
                raise FetchError(f"publisher proof pins contain a duplicate row: {subject}")
            if digest in all_pinned and all_pinned[digest] != size:
                raise FetchError("shared publisher proof pins disagree on byte length")
            seen.add(digest)
            all_pinned[digest] = size
            validated.append({"bytes": size, "sha256": digest})
        validated_proofs[subject] = sorted(validated, key=lambda row: row["sha256"])
    if sum(all_pinned.values()) > MAX_TOTAL_PROOF_BYTES:
        raise FetchError("pinned GH proofs exceed the total proof bound")
    return by_name, subjects, validated_proofs


def _write_new(path: Path, data: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(data)
    os.chmod(path, 0o644)


def _download_asset(url: str, destination: Path, pin: dict[str, Any],
                    opener: Callable[..., Any]) -> dict[str, Any]:
    digest = hashlib.sha256()
    size = 0
    try:
        response = opener(url, timeout=60)
        with response:
            with destination.open("xb") as output:
                while True:
                    # Read at most one byte past the remaining pin, then fail
                    # without writing that byte to disk.
                    limit = min(CHUNK_BYTES, pin["bytes"] - size + 1)
                    block = response.read(limit)
                    if not block:
                        break
                    if len(block) > pin["bytes"] - size:
                        raise FetchError(f"download exceeds its pinned byte length: {pin['path']}")
                    output.write(block)
                    digest.update(block)
                    size += len(block)
    except FetchError:
        raise
    except (OSError, TimeoutError) as error:
        raise FetchError(f"could not retrieve pinned SDK asset: {pin['path']}") from error
    actual_digest = digest.hexdigest()
    if size != pin["bytes"]:
        raise FetchError(f"download byte length differs from pins: {pin['path']}")
    if actual_digest != pin["sha256"]:
        raise FetchError(f"download SHA-256 differs from pins: {pin['path']}")
    return {"path": pin["path"], "pinned_bytes": pin["bytes"], "actual_bytes": size,
            "pinned_sha256": pin["sha256"], "actual_sha256": actual_digest}


def _read_regular_bounded(path: Path, label: str, limit: int) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise FetchError(f"cannot open {label}") from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise FetchError(f"{label} must be a regular, non-linked file")
        if info.st_size <= 0 or info.st_size > limit:
            raise FetchError(f"{label} is empty or exceeds its byte bound")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            block = os.read(fd, min(CHUNK_BYTES, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
        data = b"".join(chunks)
        if len(data) > limit or len(data) != info.st_size:
            raise FetchError(f"{label} changed or exceeds its byte bound")
        return data
    finally:
        os.close(fd)


def _parse_proof_line(raw: bytes) -> dict[str, Any]:
    value = _parse_json(raw, "GH attestation JSONL entry")
    if type(value) is not dict:
        raise FetchError("GH attestation JSONL entries must be JSON objects")
    return value


def _download_subject_proofs(asset: Path, asset_digest: str, download_dir: Path,
                             gh: str, runner: Callable[..., Any]) -> list[bytes]:
    command = [gh, "attestation", "download", str(asset), "--repo", APPROVED_REPOSITORY,
               "--hostname", "github.com", "--predicate-type", "https://slsa.dev/provenance/v1",
               "--limit", str(MAX_PROOFS_PER_SUBJECT)]
    try:
        process = runner(
            command,
            cwd=download_dir,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=300,
            check=False,
        )
    except (OSError, subprocess.SubprocessError, TimeoutError) as error:
        raise FetchError("GitHub CLI could not retrieve public attestation proofs") from error
    if getattr(process, "returncode", 1) != 0:
        raise FetchError("GitHub CLI rejected public attestation proof retrieval")

    entries = list(download_dir.iterdir())
    if len(entries) != 1:
        raise FetchError("GitHub CLI must produce exactly one attestation JSONL file per subject")
    jsonl = entries[0]
    expected_name = re.compile(r"sha256[:-]" + re.escape(asset_digest) + r"\.jsonl\Z")
    if jsonl.is_symlink() or expected_name.fullmatch(jsonl.name) is None:
        raise FetchError("GitHub CLI attestation JSONL has an unexpected canonical filename")
    raw = _read_regular_bounded(
        jsonl, "GitHub attestation JSONL", MAX_PROOFS_PER_SUBJECT * MAX_PROOF_LINE_BYTES
    )
    lines = raw.splitlines()
    if not 1 <= len(lines) <= MAX_PROOFS_PER_SUBJECT:
        raise FetchError("GitHub attestation JSONL exceeds its per-subject proof-count bound")
    for line in lines:
        if not line or len(line) > MAX_PROOF_LINE_BYTES:
            raise FetchError("GitHub attestation JSONL contains an empty or oversized proof line")
        _parse_proof_line(line)
    return lines


def fetch(pins: dict[str, Any], output: Path, gh: str = "gh",
          opener: Callable[..., Any] = urlopen,
          runner: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    """Download the six pinned SDK assets and original public GH proof lines.

    ``output`` must not exist. On any failure it is deliberately retained with
    partial files and per-subject GH output so the failed retrieval is inspectable.
    """
    by_name, subjects, publisher_proofs = _validate_pins(pins)
    if type(gh) is not str or not gh or "\x00" in gh:
        raise FetchError("gh must be a nonempty executable name or path")
    output = Path(output)
    if output.exists() or output.is_symlink():
        raise FetchError("fetch output must be a fresh directory")
    try:
        output.mkdir(mode=0o755)
    except OSError as error:
        raise FetchError("cannot create fresh fetch output directory") from error
    assets_dir = output / "assets"
    proofs_dir = output / "proofs"
    downloads_dir = output / ".gh-downloads"
    assets_dir.mkdir(mode=0o755)
    proofs_dir.mkdir(mode=0o755)
    downloads_dir.mkdir(mode=0o700)

    release_base = (
        f"https://github.com/{APPROVED_REPOSITORY}/releases/download/"
        f"{quote(pins['sdk_tag'], safe='')}"
    )
    asset_report: list[dict[str, Any]] = []
    asset_digests: dict[str, str] = {}
    for name in sorted(by_name):
        pin = by_name[name]
        url = release_base + "/" + quote(name, safe="")
        row = _download_asset(url, assets_dir / name, pin, opener)
        asset_report.append(row)
        asset_digests[name] = row["actual_sha256"]

    proof_rows: dict[str, list[dict[str, Any]]] = {}
    proof_line_count = 0
    proof_bytes = 0
    proof_ignored_count = 0
    unique_proofs: dict[str, bytes] = {}
    for index, subject in enumerate(sorted(subjects.values())):
        asset = assets_dir / subject
        subject_dir = downloads_dir / f"subject-{index}"
        subject_dir.mkdir(mode=0o700)
        lines = _download_subject_proofs(
            asset, asset_digests[subject], subject_dir, gh, runner
        )
        proof_line_count += len(lines)
        rows: dict[str, dict[str, Any]] = {}
        pinned = {row["sha256"]: row for row in publisher_proofs[subject]}
        found: set[str] = set()
        for line in lines:
            proof_bytes += len(line)
            if proof_bytes > MAX_TOTAL_PROOF_BYTES:
                raise FetchError("GH proof set exceeds the 32 MiB total proof bound")
            digest = hashlib.sha256(line).hexdigest()
            expected = pinned.get(digest)
            if expected is None:
                proof_ignored_count += 1
                continue
            if len(line) != expected["bytes"]:
                raise FetchError(f"pinned GH attestation proof byte length differs: {subject}")
            found.add(digest)
            path = proofs_dir / (digest + ".json")
            if digest in unique_proofs:
                if unique_proofs[digest] != line:
                    raise FetchError("deduplicated GH proof content changed")
            elif path.exists() or path.is_symlink():
                existing = _read_regular_bounded(path, "deduplicated GH proof", MAX_PROOF_LINE_BYTES)
                if existing != line:
                    raise FetchError("deduplicated GH proof content changed")
                unique_proofs[digest] = existing
            else:
                _write_new(path, line)
                unique_proofs[digest] = line
            rows[digest] = {"path": digest + ".json", "bytes": len(line), "sha256": digest}
        missing = set(pinned) - found
        if missing:
            raise FetchError(f"a pinned GH attestation proof was not returned for {subject}")
        if not rows:
            raise FetchError("GitHub attestation download returned no pinned proof objects")
        proof_rows[subject] = [rows[digest] for digest in sorted(rows)]

    proof_index = {"subjects": proof_rows}
    index_raw = _canonical_json(proof_index)
    _write_new(output / "proofs.json", index_raw)
    report = {
        "schema": REPORT_SCHEMA,
        "pins": pins,
        "source": {
            "repository": APPROVED_REPOSITORY,
            "sdk_tag": pins["sdk_tag"],
            "release_url": release_base + "/",
            "source_commit": pins["source_commit"],
            "source_tree": pins["source_tree"],
            "manifest_sha256": pins["manifest_sha256"],
            "transport_sha256": pins["transport_sha256"],
        },
        "assets": asset_report,
        "proof_counts": {subject: len(rows) for subject, rows in sorted(proof_rows.items())},
        "proof_line_count": proof_line_count,
        "proof_unique_count": len(unique_proofs),
        "proof_ignored_count": proof_ignored_count,
        "proof_bytes": proof_bytes,
    }
    _write_new(output / "fetch-report.json", _canonical_json(report))
    shutil.rmtree(downloads_dir)
    return report


def _load_adjacent_pins() -> dict[str, Any]:
    path = Path(__file__).with_name("pins.json")
    data = _read_regular_bounded(path, "packaging/pins.json", MAX_SOURCE_BYTES)
    pins = _parse_json(data, "packaging/pins.json")
    if type(pins) is not dict:
        raise FetchError("packaging/pins.json must contain a JSON object")
    return pins


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--gh", default="gh")
    args = parser.parse_args(argv)
    try:
        report = fetch(_load_adjacent_pins(), args.output, gh=args.gh)
    except (FetchError, OSError) as error:
        sys.stderr.write("ami-rust fetch: " + str(error) + "\n")
        return 2
    sys.stdout.write(json.dumps({"status": "FETCHED_PINNED_PUBLIC_INPUTS",
                                 "output": str(args.output),
                                 "proof_unique_count": report["proof_unique_count"]}) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
