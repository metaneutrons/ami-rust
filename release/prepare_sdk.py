#!/usr/bin/env python3
"""Prepare a deterministic, qualification-only source SDK with hosted Cargo receipts.

This packages source and component identities. It does not include Cargo binaries,
build an SDK, or claim release qualification.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import io
import json
import math
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile


EPOCH = 1791936000
HOSTS = {
    "macos-aarch64": "aarch64-apple-darwin",
    "linux-x86_64": "x86_64-unknown-linux-gnu",
}
PORTABLE_CSDK_HOSTS = ("linux-aarch64", "linux-x86_64", "macos-aarch64")
PORTABLE_CSDK_ARM_TOOLCHAIN_ARCHIVE_URL = "https://github.com/metaneutrons/aros-toolchains/releases/download/v0.1.4/aros-toolchain-v1-llvm11.0.0-linux-aarch64-pc-x86_64.tar.xz"
REQUIRED_EXTRAS = {
    "README.md",
    "contract/linux-x86_64-profile.json",
    "contract/macos-aarch64-profile.json",
    "contract/source.json",
    "inputs/budgets.json",
}
PINNED_CARGO_COMMIT = "3efb1f477e99b42974b982d939fd100303cdf7db"
PINNED_CARGO_PATCH = "1f22b7e2c6a7f4469cc6c2f4a84019d8d8ade558e78241d1e996d88a7f1de97f"
PINNED_RUST_COMMIT = "48a229ceaefd4985c50990b14116b6d856af0985"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PORTABLE_CSDK_SPEC = "release/portable-csdk/spec.json"
PORTABLE_CSDK_ORIGINAL_PROFILE = "release/portable-csdk/original-profile.json"
PORTABLE_CSDK_CANDIDATE_PROFILE = "release/portable-csdk/profile.json"
PORTABLE_CSDK_ORIGINAL_ARCHIVE = "release/inputs/csdk.tar.xz"
PORTABLE_CSDK_CANDIDATE_ARCHIVE = "release/inputs/portable-csdk.tar.xz"
PORTABLE_CSDK_CANDIDATE_ARCHIVE_NAME = "csdk-component.tar.xz"
PORTABLE_CSDK_REQUIRED_COUNTS = {
    "regular_files": 2835,
    "changed_files": 532,
    "public_headers": 530,
}
PORTABLE_CSDK_NON_HEADER_CHANGES = {
    "lib/libdrm_nouveau.a",
    "lib/pkgconfig/aom.pc",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ValueError(f"portable C-SDK {label} SHA-256 pin is malformed")
    return value


def _validate_portable_csdk_spec(spec: dict) -> None:
    expected_keys = {
        "schema", "status", "original", "candidate", "nouveau", "patch_series",
        "required_counts", "source_capsule", "source_manifest", "toolchains",
    }
    if set(spec) != expected_keys or spec.get("schema") != "ami-rust-portable-csdk-v1":
        raise ValueError("portable C-SDK specification has an unsupported schema or fields")
    if spec.get("status") != "PINNED_CANDIDATE_THREE_HOST_QUALIFICATION_REQUIRED":
        raise ValueError("portable C-SDK specification does not identify an unqualified candidate")

    def validate_path_pin(value: object, label: str, *, path_key: str = "path") -> None:
        if not isinstance(value, dict) or set(value) != {path_key, "bytes", "sha256"}:
            raise ValueError(f"portable C-SDK {label} pin is malformed")
        safe_path(value.get(path_key))
        if type(value.get("bytes")) is not int or value["bytes"] <= 0:
            raise ValueError(f"portable C-SDK {label} byte pin is malformed")
        _require_sha256(value.get("sha256"), label)

    original = spec.get("original")
    candidate = spec.get("candidate")
    if (not isinstance(original, dict) or set(original) != {"profile", "archive"}
            or not isinstance(candidate, dict) or set(candidate) != {"profile", "archive"}):
        raise ValueError("portable C-SDK original or candidate identity is malformed")
    validate_path_pin(original["profile"], "original profile")
    validate_path_pin(candidate["profile"], "candidate profile")
    validate_path_pin(original["archive"], "original archive")
    if original["archive"]["path"] != PORTABLE_CSDK_ORIGINAL_ARCHIVE:
        raise ValueError("portable C-SDK original archive path differs from the normative path")
    candidate_archive = candidate["archive"]
    if (not isinstance(candidate_archive, dict)
            or set(candidate_archive) != {"path", "name", "bytes", "sha256"}):
        raise ValueError("portable C-SDK candidate archive pin is malformed")
    safe_path(candidate_archive.get("path"))
    safe_path(candidate_archive.get("name"))
    if (candidate_archive["path"] != PORTABLE_CSDK_CANDIDATE_ARCHIVE
            or candidate_archive["name"] != PORTABLE_CSDK_CANDIDATE_ARCHIVE_NAME):
        raise ValueError("portable C-SDK candidate archive path differs from the repository prerequisite")
    if type(candidate_archive.get("bytes")) is not int or candidate_archive["bytes"] <= 0:
        raise ValueError("portable C-SDK candidate archive byte pin is malformed")
    _require_sha256(candidate_archive.get("sha256"), "candidate archive")
    if original["profile"]["path"] != PORTABLE_CSDK_ORIGINAL_PROFILE:
        raise ValueError("portable C-SDK original profile path differs from the normative path")
    if candidate["profile"]["path"] != PORTABLE_CSDK_CANDIDATE_PROFILE:
        raise ValueError("portable C-SDK candidate profile path differs from the normative path")

    for name in ("patch_series", "source_capsule", "source_manifest"):
        validate_path_pin(spec.get(name), name.replace("_", " "))

    nouveau_fields = {
        "archive_path", "derived_bytes", "derived_sha256", "historical_source_prefix",
        "objects", "original_bytes", "original_sha256", "path_changed_members",
        "symbols", "unchanged_members",
    }
    nouveau = spec.get("nouveau")
    if not isinstance(nouveau, dict) or set(nouveau) != nouveau_fields:
        raise ValueError("portable C-SDK nouveau identity is malformed")
    safe_path(nouveau.get("archive_path"))
    if not isinstance(nouveau.get("historical_source_prefix"), str):
        raise ValueError("portable C-SDK historical source prefix is malformed")
    for key in ("derived_sha256", "original_sha256"):
        _require_sha256(nouveau.get(key), f"nouveau {key}")
    for key in ("derived_bytes", "objects", "original_bytes", "path_changed_members", "symbols",
                "unchanged_members"):
        if type(nouveau.get(key)) is not int or nouveau[key] < 0:
            raise ValueError(f"portable C-SDK nouveau {key} count is malformed")

    counts = spec.get("required_counts")
    if (not isinstance(counts, dict) or set(counts) != set(PORTABLE_CSDK_REQUIRED_COUNTS)
            or any(type(counts.get(key)) is not int for key in PORTABLE_CSDK_REQUIRED_COUNTS)
            or counts != PORTABLE_CSDK_REQUIRED_COUNTS):
        raise ValueError("portable C-SDK required file and change counts differ from the reviewed values")

    toolchains = spec.get("toolchains")
    if not isinstance(toolchains, dict) or set(toolchains) != set(PORTABLE_CSDK_HOSTS):
        raise ValueError("portable C-SDK toolchain pins are incomplete")
    for host, components in toolchains.items():
        expected = {"compiler", "profile"} | ({"archive"} if host == "linux-aarch64" else set())
        if not isinstance(components, dict) or set(components) != expected:
            raise ValueError(f"portable C-SDK {host} toolchain identity is malformed")
        if host == "linux-aarch64":
            archive = components["archive"]
            if (not isinstance(archive, dict)
                    or set(archive) != {"kind", "url", "bytes", "sha256", "archive_root"}
                    or archive.get("kind") != "tar"
                    or archive.get("url") != PORTABLE_CSDK_ARM_TOOLCHAIN_ARCHIVE_URL
                    or archive.get("archive_root") != "toolchain"
                    or type(archive.get("bytes")) is not int or archive["bytes"] <= 0
                    or not isinstance(archive.get("sha256"), str)
                    or not SHA256.fullmatch(archive["sha256"])):
                raise ValueError("malformed portable C-SDK Linux/AArch64 archive pin")
        validate_path_pin(components["compiler"], f"{host} compiler")
        validate_path_pin(components["profile"], f"{host} toolchain profile")


def _portable_csdk_rows(profile: dict, label: str) -> dict[str, dict]:
    if set(profile) != {"files", "symlinks"} or profile.get("symlinks") != []:
        raise ValueError(f"portable C-SDK {label} profile must contain files and no symlinks")
    rows = profile.get("files")
    if not isinstance(rows, list):
        raise ValueError(f"portable C-SDK {label} profile file list is malformed")
    if len(rows) != PORTABLE_CSDK_REQUIRED_COUNTS["regular_files"]:
        raise ValueError(f"portable C-SDK {label} profile has the wrong regular-file count")
    result = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}:
            raise ValueError(f"portable C-SDK {label} profile row is malformed")
        name = safe_path(row.get("path"))
        if name in result:
            raise ValueError(f"portable C-SDK {label} profile has duplicate paths")
        if type(row.get("bytes")) is not int or row["bytes"] < 0:
            raise ValueError(f"portable C-SDK {label} profile byte count is malformed")
        _require_sha256(row.get("sha256"), f"{label} profile row")
        result[name] = row
    return result


def _validate_portable_csdk_profiles(original_profile: dict, candidate_profile: dict) -> set[str]:
    original_rows = _portable_csdk_rows(original_profile, "original")
    candidate_rows = _portable_csdk_rows(candidate_profile, "candidate")
    if set(original_rows) != set(candidate_rows):
        raise ValueError("portable C-SDK candidate file set differs from the frozen original")
    changed = {name for name in original_rows if original_rows[name] != candidate_rows[name]}
    changed_headers = {name for name in changed if name.startswith("include/")}
    changed_other = changed - changed_headers
    if (len(changed) != PORTABLE_CSDK_REQUIRED_COUNTS["changed_files"]
            or len(changed_headers) != PORTABLE_CSDK_REQUIRED_COUNTS["public_headers"]
            or any(not name.endswith(".h") for name in changed_headers)
            or changed_other != PORTABLE_CSDK_NON_HEADER_CHANGES):
        raise ValueError("portable C-SDK changed-file set differs from the reviewed candidate counts")
    return changed


def _load_portable_csdk(source: Path, tracked: set[str]) -> tuple[dict, bytes, bytes, bytes, set[str]]:
    spec_bytes = tracked_regular(source, tracked, PORTABLE_CSDK_SPEC)
    spec = read_json(source / PORTABLE_CSDK_SPEC)
    _validate_portable_csdk_spec(spec)
    original_pin = spec["original"]["profile"]
    candidate_pin = spec["candidate"]["profile"]
    original_raw = tracked_regular(source, tracked, original_pin["path"])
    candidate_raw = tracked_regular(source, tracked, candidate_pin["path"])
    if len(original_raw) != original_pin["bytes"] or digest(original_raw) != original_pin["sha256"]:
        raise ValueError("portable C-SDK original profile differs from its exact normative pin")
    if len(candidate_raw) != candidate_pin["bytes"] or digest(candidate_raw) != candidate_pin["sha256"]:
        raise ValueError("portable C-SDK candidate profile differs from its exact normative pin")
    original_profile = read_json(source / original_pin["path"])
    candidate_profile = read_json(source / candidate_pin["path"])
    changed = _validate_portable_csdk_profiles(original_profile, candidate_profile)
    return spec, spec_bytes, original_raw, candidate_raw, changed


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()


def read_json(path: Path, limit: int = 32 * 1024 * 1024) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError(f"missing, linked or oversized JSON file: {path.name}")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_nonfinite(token: str):
        raise ValueError(f"non-finite JSON number: {token}")

    def finite_float(token: str) -> float:
        value = float(token)
        if not math.isfinite(value):
            raise ValueError(f"non-finite JSON number: {token}")
        return value

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique,
                       parse_constant=reject_nonfinite, parse_float=finite_float)
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path.name}")
    return value


def safe_path(value: object) -> str:
    if (not isinstance(value, str) or not value or len(value) > 240 or "\\" in value or ":" in value
            or any(ord(c) < 32 or ord(c) >= 127 for c in value)):
        raise ValueError("manifest paths must be portable relative paths")
    path = PurePosixPath(value)
    parts = value.split("/")
    if path.is_absolute() or len(parts) > 24 or any(
            not re.fullmatch(r"[A-Za-z0-9._+-]{1,120}", part) or part in (".", "..")
            or part.endswith(".") or part.split(".", 1)[0].upper() in {"CON", "PRN", "AUX", "NUL"}
            or re.fullmatch(r"(?:COM|LPT)[1-9]", part.split(".", 1)[0].upper()) for part in parts):
        raise ValueError(f"unsafe manifest path: {value}")
    return path.as_posix()


def tracked_regular(source: Path, tracked: set[str], name: str) -> bytes:
    name = safe_path(name)
    path = source / name
    if name not in tracked or path.is_symlink() or not path.is_file():
        raise ValueError(f"required tracked regular source file is missing: {name}")
    return path.read_bytes()


def source_identity(source: Path) -> tuple[str, set[str]]:
    root = subprocess.run(["git", "-C", str(source), "rev-parse", "--show-toplevel"],
                          check=True, capture_output=True, text=True).stdout.strip()
    if Path(root).resolve() != source.resolve(strict=True):
        raise ValueError("--source must name the public Git checkout root")
    remote = subprocess.run(["git", "-C", str(source), "remote", "get-url", "origin"],
                            check=True, capture_output=True, text=True).stdout.strip().lower()
    if remote not in {
        "https://github.com/metaneutrons/ami-rust",
        "https://github.com/metaneutrons/ami-rust.git",
        "git@github.com:metaneutrons/ami-rust.git",
        "ssh://git@github.com/metaneutrons/ami-rust.git",
    }:
        raise ValueError("--source origin must be the public metaneutrons/ami-rust repository")
    head = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                          check=True, capture_output=True, text=True).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("selected source HEAD is not a full Git commit")
    status = subprocess.run(["git", "-C", str(source), "status", "--porcelain=v1", "-z",
                             "--untracked-files=all"], check=True, capture_output=True).stdout
    if status:
        raise ValueError("public source checkout must be clean, including untracked files")
    listing = subprocess.run(["git", "-C", str(source), "ls-files", "-z"],
                             check=True, capture_output=True).stdout
    tracked = {item.decode("utf-8") for item in listing.split(b"\0") if item}
    if "contract/sdk.json" not in tracked:
        raise ValueError("selected public HEAD does not track contract/sdk.json")
    return head, tracked


def verify_expected_inputs(source: Path, tracked: set[str], resources_path: Path) -> tuple[dict, dict, str, str]:
    inputs_rel = "release/ci-bootstrap-inputs.json"
    resources_rel = "release/ci-resources.json"
    inputs_bytes = tracked_regular(source, tracked, inputs_rel)
    policy_bytes = tracked_regular(source, tracked, resources_rel)
    inputs_path = source / inputs_rel
    source_policy = source / resources_rel
    if resources_path.is_symlink() or not resources_path.is_file():
        raise ValueError("--resources must be a regular normative policy file")
    external_policy_bytes = resources_path.read_bytes()
    if external_policy_bytes != policy_bytes:
        raise ValueError("--resources bytes differ from the selected checkout's normative policy")
    inputs = read_json(inputs_path)
    resources = read_json(source_policy)
    if inputs.get("schema") != "ami-rust-ci-cargo-inputs-v1" or resources.get("schema") != "ami-rust-hosted-resources-v1":
        raise ValueError("unrecognized hosted bootstrap inputs or resource policy schema")
    custom = inputs.get("custom_cargo", {})
    rust = inputs.get("rust", {})
    if (custom.get("commit") != PINNED_CARGO_COMMIT or custom.get("patch_sha256") != PINNED_CARGO_PATCH
            or rust.get("release") != "1.98.1" or rust.get("commit") != PINNED_RUST_COMMIT):
        raise ValueError("selected checkout does not carry the required Cargo/Rust bootstrap pins")
    build = resources.get("build")
    expected_build = {"jobs": 2, "rss_bytes": 4 * 1024**3, "seconds": 1200,
                      "workspace_bytes": 12 * 1024**3, "log_bytes": 16 * 1024**2}
    capacity = resources.get("host_capacity", {})
    if (build != expected_build or capacity.get("schema") != "ami-rust-host-capacity-v1"
            or capacity.get("ram_minimum_bytes", 0) < 6 * 1024**3
            or capacity.get("disk_free_minimum_bytes", 0) < 24 * 1024**3):
        raise ValueError("normative hosted resource policy does not meet the admitted profile")
    if digest(tracked_regular(source, tracked, "host/build.py")) != inputs["producer_helpers"]["host_supervisor_sha256"]:
        raise ValueError("host/build.py differs from its normative producer pin")
    if digest(tracked_regular(source, tracked, "host/cargo-repro/produce.py")) != inputs["producer_helpers"]["producer_sha256"]:
        raise ValueError("Cargo producer differs from its normative producer pin")
    if digest(tracked_regular(source, tracked, "host/cargo-repro/prepare-overlay.py")) != inputs["producer_helpers"]["overlay_helper_sha256"]:
        raise ValueError("overlay helper differs from its normative producer pin")
    return inputs, resources, digest(inputs_bytes), digest(policy_bytes)


def _validate_capacity(report: dict, resources: dict) -> None:
    capacity = report.get("capacity_preflight")
    if not isinstance(capacity, dict) or set(capacity) != {"work", "output"}:
        raise ValueError("producer capacity preflight is incomplete")
    minima = resources["host_capacity"]
    for label, row in capacity.items():
        if not isinstance(row, dict):
            raise ValueError("producer capacity row is malformed")
        if (row.get("ram_minimum_bytes") != minima["ram_minimum_bytes"]
                or row.get("disk_free_minimum_bytes") != minima["disk_free_minimum_bytes"]
                or type(row.get("physical_ram_bytes")) is not int
                or row["physical_ram_bytes"] < minima["ram_minimum_bytes"]
                or type(row.get("free_disk_bytes")) is not int
                or row["free_disk_bytes"] < minima["disk_free_minimum_bytes"]):
            raise ValueError(f"producer capacity preflight failed for {label}")


def _archive_pins(inputs: dict, target: str) -> list[dict]:
    components = inputs["rust"]["components"][target]
    rows = []
    for name in ("cargo", "rust-std", "rustc"):
        row = components[name]
        rows.append({"component": name, "url": row["url"], "bytes": row["http_content_length"],
                     "sha256": row["sha256"]})
    return rows


def canonical_producer(report_path: Path, host: str, inputs: dict, resources: dict,
                       inputs_sha: str, resources_sha: str, source: Path,
                       tracked: set[str]) -> bytes:
    if report_path.is_symlink() or not report_path.is_file():
        raise ValueError(f"producer report is not a regular file for {host}")
    report = read_json(report_path)
    if (report.get("schema") != "ami-rust-hosted-custom-cargo-producer-v1"
            or report.get("status") != "PRODUCED_PREREQUISITE_ONLY_NOT_R1_QUALIFICATION"
            or report.get("host") != host or report.get("rust_target") != HOSTS[host]
            or report.get("build_profile") != "release" or report.get("budgets") != resources["build"]):
        raise ValueError(f"producer report is unsuccessful or for the wrong host/profile: {host}")
    _validate_capacity(report, resources)
    _validate_execution_receipt(report, resources)
    material = report.get("input_materials")
    if not isinstance(material, dict):
        raise ValueError("producer report lacks input material receipts")
    if material.get("inputs_sha256") != inputs_sha or material.get("resource_policy_sha256") != resources_sha:
        raise ValueError("producer report input/resource policy digests do not match this checkout")
    rust = inputs["rust"]
    if (material.get("rust_release") != rust["release"] or material.get("rust_commit") != rust["commit"]
            or material.get("bootstrap_cargo_commit") != rust["cargo_commit"]
            or material.get("rust_channel_manifest") != rust["manifest"]):
        raise ValueError("producer Rust bootstrap receipt differs from normative pins")
    python = material.get("python", {})
    if python.get("sha256") != inputs["python"][host]["sha256"] or python.get("pinned_sha256") != python.get("sha256"):
        raise ValueError("producer Python receipt differs from the host pin")

    custom = inputs["custom_cargo"]
    upstream = material.get("cargo_upstream", {})
    target_rows = [{"path": row["path"], "upstream_sha256": row["upstream_sha256"],
                    "patched_sha256": row["patched_sha256"]} for row in custom["patch_targets"]]
    if (upstream.get("upstream", "").removesuffix(".git") != custom["upstream"].removesuffix(".git")
            or upstream.get("commit") != custom["commit"]
            or upstream.get("cargo_lock_sha256") != custom["cargo_lock"]["sha256"]
            or upstream.get("patch_sha256") != custom["patch_sha256"]
            or upstream.get("patch_targets") != target_rows):
        raise ValueError("producer Cargo source, lock, or patch receipt differs from the pins")
    patch = material.get("cargo_patch", {})
    if (patch.get("path") != custom["patch_path"] or patch.get("sha256") != custom["patch_sha256"]
            or patch.get("targets") != target_rows):
        raise ValueError("producer Cargo patch receipt is malformed")
    if material.get("openssl_overlay_recipe_sha256") != inputs["openssl_overlay"]["recipe_sha256"]:
        raise ValueError("producer overlay recipe differs from its pin")
    if material.get("openssl_overlay_patch_sha256") != inputs["openssl_overlay"]["patch_sha256"]:
        raise ValueError("producer overlay patch differs from its pin")
    vendor = report.get("vendor", {})
    overlay = vendor.get("overlay_identity", {})
    changed_files = sorted(inputs["openssl_overlay"]["exact_changed_paths"])
    if (overlay.get("overlay_pin_sha256") != inputs["openssl_overlay"]["recipe_sha256"]
            or overlay.get("patch_sha256") != inputs["openssl_overlay"]["patch_sha256"]
            or overlay.get("changed_files") != changed_files
            or overlay.get("original_vendor_recheck") != "PASS"):
        raise ValueError("producer OpenSSL vendor overlay receipt is malformed")

    helpers = material.get("producer_helpers", {})
    expected_helpers = inputs["producer_helpers"]
    actual_helpers = helpers.get("actual_sha256", {})
    helper_expected = {
        "produce.py": expected_helpers["producer_sha256"],
        "prepare-overlay.py": expected_helpers["overlay_helper_sha256"],
        "build.py": expected_helpers["host_supervisor_sha256"],
                    "ci_cargo.py": digest(tracked_regular(source, tracked, "release/ci_cargo.py")),
    }
    if (helpers.get("ci_input_pins") != expected_helpers or actual_helpers != helper_expected
            or helpers.get("driver_sha256") != helper_expected["ci_cargo.py"]):
        raise ValueError("producer helper identities differ from tracked/pinned helpers")

    archive_rows = material.get("rust_archives")
    expected_archives = _archive_pins(inputs, HOSTS[host])
    if not isinstance(archive_rows, list) or len(archive_rows) != 3:
        raise ValueError("producer Rust archive receipts are incomplete")
    seen = {}
    for row in archive_rows:
        if not isinstance(row, dict) or row.get("component") in seen:
            raise ValueError("duplicate or malformed Rust archive receipt")
        seen[row["component"]] = row
    for expected in expected_archives:
        actual = seen.get(expected["component"], {})
        if any(actual.get(key) != expected[key] for key in ("url", "sha256")) or actual.get("bytes") != expected["bytes"]:
            raise ValueError("producer Rust archive differs from its official checksum/size pin")

    artifact = report.get("custom_cargo_artifact", {})
    artifact_bytes = artifact.get("bytes")
    artifact_sha = artifact.get("sha256")
    version = artifact.get("version")
    if (type(artifact_bytes) is not int or artifact_bytes <= 0 or artifact_bytes > 256 * 1024**2
            or not isinstance(artifact_sha, str) or not SHA256.fullmatch(artifact_sha)
            or not isinstance(version, str) or len(version) > 4096):
        raise ValueError("producer Cargo artifact metadata is malformed")
    if f"commit-hash: {custom['commit']}" not in version or f"host: {HOSTS[host]}" not in version:
        raise ValueError("producer Cargo version does not identify the pinned source and host")
    if re.search(r"(?:^|[\s=])/(?:[^\s]+)|[A-Za-z]:\\[^\s]+", version):
        raise ValueError("Cargo version metadata contains a local filesystem path")
    rel = safe_path(artifact.get("relative_path"))
    if not rel.endswith("target/release/cargo"):
        raise ValueError("producer artifact path is not a release Cargo output")

    normalized = {
        "schema": "ami-rust-hosted-cargo-component-producer-v1",
        "qualification_only": True,
        "producer_schema": report["schema"],
        "producer_status": report["status"],
        "host": host,
        "rust_target": HOSTS[host],
        "build_profile": "release",
        "input_identities": {"inputs_sha256": inputs_sha, "resource_policy_sha256": resources_sha},
        "bootstrap": {
            "rust_release": rust["release"], "rust_commit": rust["commit"],
            "channel_manifest_sha256": rust["manifest"]["sha256"],
            "archives": expected_archives,
            "bootstrap_cargo_commit": rust["cargo_commit"],
        },
        "cargo_source": {
            "upstream": custom["upstream"], "commit": custom["commit"],
            "cargo_lock_sha256": custom["cargo_lock"]["sha256"],
            "patch_sha256": custom["patch_sha256"], "patch_targets": target_rows,
        },
        "openssl_overlay": {
            "recipe_sha256": inputs["openssl_overlay"]["recipe_sha256"],
            "patch_sha256": inputs["openssl_overlay"]["patch_sha256"],
            "source_sha256": inputs["openssl_overlay"]["source_sha256"],
            "patched_sha256": inputs["openssl_overlay"]["patched_sha256"],
            "changed_paths": changed_files,
        },
        "producer_helpers": actual_helpers,
        "host_capacity": resources["host_capacity"],
        "budgets": resources["build"],
        "artifact": {"path": "bin/cargo", "bytes": artifact_bytes,
                     "sha256": artifact_sha, "version": version},
    }
    return canonical_json(normalized)


def _finite_nonnegative(value: object, label: str) -> int | float:
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or (isinstance(value, float) and not math.isfinite(value)) or value < 0):
        raise ValueError(f"producer {label} must be a finite nonnegative number")
    return value


def _validate_execution_receipt(report: dict, resources: dict) -> None:
    peaks = report.get("peaks")
    if not isinstance(peaks, dict):
        raise ValueError("producer report lacks resource peak measurements")
    rss = _finite_nonnegative(peaks.get("rss_observed_bytes"), "RSS peak")
    workspace = _finite_nonnegative(peaks.get("work_plus_output_observed_bytes"), "workspace peak")
    _finite_nonnegative(peaks.get("checkout_initial_bytes"), "checkout size")
    _finite_nonnegative(peaks.get("elapsed_seconds"), "elapsed time")
    if rss > resources["build"]["rss_bytes"] or workspace > resources["build"]["workspace_bytes"]:
        raise ValueError("producer report exceeded its hosted RSS or workspace ceiling")
    commands = peaks.get("commands")
    if not isinstance(commands, list) or not commands:
        raise ValueError("producer report has no supervised command receipts")
    labels = set()
    for command in commands:
        if not isinstance(command, dict) or not isinstance(command.get("label"), str):
            raise ValueError("producer command receipt is malformed")
        labels.add(command["label"])
        if type(command.get("exit_code")) is not int or command["exit_code"] != 0 or command.get("stop_reason") is not None:
            raise ValueError(f"producer command did not complete cleanly: {command['label']}")
        elapsed = _finite_nonnegative(command.get("elapsed_seconds"), "command elapsed time")
        command_rss = _finite_nonnegative(command.get("rss_peak_observed_bytes"), "command RSS peak")
        command_workspace = _finite_nonnegative(command.get("managed_peak_observed_bytes"),
                                                "command workspace peak")
        if (command_rss > resources["build"]["rss_bytes"] or command_rss > rss
                or command_workspace > resources["build"]["workspace_bytes"]
                or command_workspace > workspace):
            raise ValueError(f"producer command peaks disagree with the accepted summary: {command['label']}")
        limits = {"cargo-vendor": 600, "cargo-vendor-overlay": 600, "cargo-build": 1200}
        if command["label"] in limits and elapsed > limits[command["label"]]:
            raise ValueError(f"producer command exceeded its time budget: {command['label']}")
    required = {"cargo-vendor", "cargo-vendor-overlay", "cargo-build"}
    if not required <= labels:
        raise ValueError("producer command receipts omit a required Cargo phase")


def _component_manifest(artifact: dict, producer_bytes: bytes) -> bytes:
    rows = [
        {"path": "bin/cargo", "bytes": artifact["bytes"], "sha256": artifact["sha256"]},
        {"path": "producer.json", "bytes": len(producer_bytes), "sha256": digest(producer_bytes)},
    ]
    return canonical_json({
        "files": rows,
        "symlinks": [],
        "producer_identity_spec": {
            "schema": "ami-rust-hosted-cargo-component-producer-v1",
            "serialization": "UTF-8 JSON with sorted keys, two-space indentation, and one trailing LF",
            "record_is_exact_producer_json_payload": True,
            "volatile_report_fields_excluded": [
                "capacity_preflight", "peaks", "relative_files", "source_inventory",
                "vendor.upstream_inventory", "vendor.overlay_inventory",
                "custom_cargo_artifact.relative_path", "run_id",
            ],
            "bytes": len(producer_bytes),
            "sha256": digest(producer_bytes),
            "record": json.loads(producer_bytes),
        },
    })


def _file_rows(file_bytes: dict[str, bytes]) -> list[dict]:
    return [{"path": name, "bytes": len(content), "sha256": digest(content)}
            for name, content in sorted(file_bytes.items())]


def _tar_bytes(files: dict[str, bytes]) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:xz", format=tarfile.USTAR_FORMAT,
                      preset=6) as archive:
        for name in sorted(files):
            safe_path(name)
            data = files[name]
            info = tarfile.TarInfo(name)
            info.type = tarfile.REGTYPE
            info.size = len(data)
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = EPOCH
            archive.addfile(info, io.BytesIO(data))
    return out.getvalue()


def _verify_archive(archive_bytes: bytes, expected: dict[str, bytes]) -> None:
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:xz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)) or names != sorted(names) or set(names) != set(expected):
            raise ValueError("archive member set differs from complete SDK inventory")
        for member in members:
            safe_path(member.name)
            if (not member.isfile() or member.mode != 0o644 or member.uid != 0 or member.gid != 0
                    or member.uname or member.gname or member.mtime != EPOCH
                    or member.size != len(expected[member.name])):
                raise ValueError(f"archive metadata is not canonical: {member.name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError(f"archive member has no payload: {member.name}")
            actual = stream.read()
            if len(actual) != member.size or digest(actual) != digest(expected[member.name]):
                raise ValueError(f"archive payload differs from prepared member: {member.name}")
    manifest = json.loads(expected["contract/sdk.json"])
    expected_rows = _file_rows({name: data for name, data in expected.items() if name != "contract/sdk.json"})
    if manifest.get("files") != expected_rows:
        raise ValueError("read-back SDK manifest does not inventory every packaged source file")


def portable_rust_profile(raw: bytes, host: str) -> tuple[bytes, list[dict]]:
    """Remove only installer records whose contents depend on installation cwd.

    Compiler, standard-library, rust-src, notices and executable bytes stay
    unchanged. The provisioner removes these same five generated admin files
    from its fresh owned root before a complete inventory check.
    """
    profile = json.loads(raw)
    excluded = {"lib/rustlib/install.log", "lib/rustlib/manifest-cargo",
                "lib/rustlib/manifest-rust-src", "lib/rustlib/manifest-rustc",
                f"lib/rustlib/manifest-rust-std-{HOSTS[host]}"}
    rows = profile.get("files")
    if not isinstance(rows, list) or len({r["path"] for r in rows}) != len(rows):
        raise ValueError("Rust prerequisite inventory is malformed or duplicated")
    removed = [row for row in rows if row["path"] in excluded]
    if {row["path"] for row in removed} != excluded:
        raise ValueError("Rust installer administrative file set differs from the reviewed five")
    profile["files"] = [row for row in rows if row["path"] not in excluded]
    return canonical_json(profile), removed


def prepare(source: Path, output: Path, resources_path: Path,
            producer_reports: dict[str, Path], *, production_candidate: bool = False) -> dict:
    if source.is_symlink() or not source.is_dir():
        raise ValueError("--source must be a public Git checkout directory")
    source = source.resolve(strict=True)
    head, tracked = source_identity(source)
    if resources_path.is_symlink() or not resources_path.is_file():
        raise ValueError("--resources must be a regular normative policy file")
    inputs, resources, inputs_sha, resources_sha = verify_expected_inputs(source, tracked, resources_path)
    tracked_regular(source, tracked, "contract/sdk.json")
    template = read_json(source / "contract/sdk.json")
    if template.get("schema") != "ami-rust-sdk-v1" or not isinstance(template.get("files"), list):
        raise ValueError("selected checkout has no supported SDK source template")
    rows = template["files"]
    if len(rows) != 88:
        raise ValueError("selected SDK template must contain the reviewed 88-file base inventory")
    template_map: dict[str, bytes] = {}
    for row in rows:
        name = safe_path(row.get("path"))
        if name in template_map or type(row.get("bytes")) is not int or not SHA256.fullmatch(row.get("sha256", "")):
            raise ValueError("template SDK inventory has duplicate or malformed rows")
        data = tracked_regular(source, tracked, name)
        if len(data) != row["bytes"] or digest(data) != row["sha256"]:
            helper_pin = {
                "host/build.py": inputs["producer_helpers"]["host_supervisor_sha256"],
                "host/cargo-repro/produce.py": inputs["producer_helpers"]["producer_sha256"],
            }.get(name)
            if helper_pin is None or digest(data) != helper_pin:
                raise ValueError(f"selected source differs from the pinned template inventory: {name}")
        template_map[name] = data
    if REQUIRED_EXTRAS & set(template_map):
        raise ValueError("required tracked extras unexpectedly overlap the 88-row source inventory")
    for name in REQUIRED_EXTRAS:
        tracked_regular(source, tracked, name)

    profile_names = {host: f"contract/{host}-profile.json" for host in HOSTS}
    for host, name in profile_names.items():
        extra_profile = read_json(source / name)
        if extra_profile != template.get("profiles", {}).get(host):
            raise ValueError(f"tracked {host} profile does not agree with contract/sdk.json")
        profile = template["profiles"][host]
        component = profile.get("components", {}).get("cargo")
        if (profile.get("rust_host") != HOSTS[host] or profile.get("cargo_binary") != "bin/cargo"
                or not isinstance(component, dict)
                or component.get("manifest") != f"host/profiles/{host}/cargo.json"):
            raise ValueError(f"malformed {host} Cargo profile in the selected template")

    portable_csdk_metadata = None
    if production_candidate:
        (portable_spec, portable_spec_bytes, original_csdk_profile,
         candidate_csdk_profile, csdk_changed_paths) = _load_portable_csdk(source, tracked)
        for host in HOSTS:
            name = f"host/profiles/{host}/csdk.json"
            component = template["profiles"][host].get("components", {}).get("csdk")
            if (name not in template_map or not isinstance(component, dict)
                    or component.get("manifest") != name
                    or component.get("sha256") != digest(template_map[name])
                    or template_map[name] != original_csdk_profile):
                raise ValueError("original C-SDK profile does not match the frozen template profile and references")
        for host in HOSTS:
            name = f"host/profiles/{host}/csdk.json"
            template_map[name] = candidate_csdk_profile
            template["profiles"][host]["components"]["csdk"]["sha256"] = digest(candidate_csdk_profile)
        distribution_spec = copy.deepcopy(portable_spec)
        distribution_spec["nouveau"].pop("historical_source_prefix")
        portable_csdk_metadata = {
            "spec_path": PORTABLE_CSDK_SPEC,
            "spec_bytes": len(portable_spec_bytes),
            "spec_sha256": digest(portable_spec_bytes),
            "distribution_spec": distribution_spec,
            "candidate_archive": portable_spec["candidate"]["archive"],
            "replacements": {
                host: {
                    "manifest": f"host/profiles/{host}/csdk.json",
                    "sha256": digest(candidate_csdk_profile),
                }
                for host in HOSTS
            },
            "changed_profile_rows": len(csdk_changed_paths),
        }

    if set(producer_reports) != set(HOSTS):
        raise ValueError("exactly one Cargo producer report is required for each supported host")
    producer_bytes = {}
    artifact_rows = {}
    cargo_component_bytes = {}
    for host in HOSTS:
        report = read_json(producer_reports[host])
        artifact = report.get("custom_cargo_artifact", {})
        producer = canonical_producer(producer_reports[host], host, inputs, resources,
                                      inputs_sha, resources_sha, source, tracked)
        producer_bytes[host] = producer
        artifact_rows[host] = artifact
        component = _component_manifest(artifact, producer)
        cargo_component_bytes[host] = component
        cargo_path = f"host/profiles/{host}/cargo.json"
        if cargo_path not in template_map:
            raise ValueError(f"template is missing the {host} Cargo component manifest")
        template_map[cargo_path] = component
        template["profiles"][host]["components"]["cargo"]["sha256"] = digest(component)

    omitted_rust_admin = {}
    if production_candidate:
        for host in HOSTS:
            name = f"host/profiles/{host}/rust.json"
            reference = template["profiles"][host]["components"]["rust"]
            if (reference.get("manifest") != name or name not in template_map
                    or digest(template_map[name]) != reference.get("sha256")):
                raise ValueError("Rust prerequisite profile differs from the frozen template")
            portable, removed = portable_rust_profile(template_map[name], host)
            template_map[name] = portable
            reference["sha256"] = digest(portable)
            omitted_rust_admin[host] = removed

    # README explains the boundary between producer metadata and consumer asset distribution.
    readme = tracked_regular(source, tracked, "README.md").decode("utf-8")
    old_boundary = "The CI workflow runs isolated installer regression fixtures on Linux and macOS.\nIt does not build or qualify the SDK, run AROS, validate a publisher identity,\nor create release artifacts. An offline test signature is not a publisher\nsignature. No SDK publication is authorized by this repository workflow."
    new_boundary = ("Protected hosted CI can produce pinned Cargo prerequisites and source SDK candidates for macOS ARM64 and Linux x86-64. "
                    "This SDK archive contains source and component identities; consumer asset distribution remains separate. "
                    "A production trust candidate is not an R1 acceptance or publication decision. "
                    "Real publisher evidence, consumer replay and guest qualification remain separate gates. "
                    "An offline test signature is not a publisher signature.")
    if old_boundary in readme:
        readme = readme.replace(old_boundary, new_boundary)
    elif "consumer asset distribution remains separate" not in readme:
        readme = readme.rstrip() + "\n\n" + new_boundary + "\n"

    source_template = read_json(source / "contract/source.json")
    source_record = {
        "schema": "ami-rust-sdk-source-v1",
        "scope": "SDK/host/test sources copied from this clean selected public Git commit; hosted Cargo producer identities are metadata only.",
        "source_commit": head,
        "previous_template": source_template,
    }
    # Preserve the historical sealed runtime limits exactly; only the prospective hosted build ceiling changes.
    budget_bytes = tracked_regular(source, tracked, "inputs/budgets.json")
    sealed_budget_sha = resources.get("basis", {}).get("old_runtime_budget_sha256")
    if not isinstance(sealed_budget_sha, str) or digest(budget_bytes) != sealed_budget_sha:
        raise ValueError("historical runtime budget differs from its sealed policy hash")
    if template.get("budgets") != read_json(source / "inputs/budgets.json"):
        raise ValueError("SDK template runtime budgets differ from the sealed input")

    template.update({
        "version": "0.1.0" if production_candidate else "0.1.0-rc.4-hosted",
        "qualification_only": not production_candidate,
        "source_identity": head,
        "host_capacity": resources["host_capacity"],
    })
    template["budgets"]["build_rss_bytes"] = resources["build"]["rss_bytes"]
    if production_candidate:
        template.setdefault("packaging", {})["rust_provisioning"] = {
            "omitted_installer_administrative_files": omitted_rust_admin,
            "compiler_library_and_source_bytes": "unchanged from frozen prerequisite inventories",
            "complete_inventory_required_after_provisioning": True,
        }
        template["packaging"]["portable_csdk"] = portable_csdk_metadata
        template["packaging"]["release_acceptance"] = (
            "Production trust candidate only; not an R1 acceptance or publication decision.")
    template["hosted_cargo"] = {
        "status": ("separately_delivered_host_component_required" if production_candidate
                   else "producer_metadata_only_consumer_distribution_unresolved"),
        "binary_payload_included": False,
        "profiles": {
            host: {
                "manifest": f"host/profiles/{host}/cargo.json",
                "manifest_sha256": digest(cargo_component_bytes[host]),
                "producer_sha256": digest(producer_bytes[host]),
                "artifact_sha256": artifact_rows[host]["sha256"],
                "artifact_bytes": artifact_rows[host]["bytes"],
            }
            for host in HOSTS
        },
    }
    template["files"] = []  # filled after generated profile files and extras are finalized
    files = dict(template_map)
    files["README.md"] = readme.encode()
    files["contract/source.json"] = canonical_json(source_record)
    files["contract/macos-aarch64-profile.json"] = canonical_json(template["profiles"]["macos-aarch64"])
    files["contract/linux-x86_64-profile.json"] = canonical_json(template["profiles"]["linux-x86_64"])
    files["inputs/budgets.json"] = budget_bytes
    if len(files) != 93:
        raise ValueError("prepared SDK must contain exactly 93 non-manifest files")
    template["files"] = _file_rows(files)
    files["contract/sdk.json"] = canonical_json(template)
    if len(files) != 94:
        raise ValueError("prepared SDK must contain exactly 94 regular files including its manifest")

    archive_bytes = _tar_bytes(files)
    _verify_archive(archive_bytes, files)
    final_head, final_tracked = source_identity(source)
    if final_head != head or final_tracked != tracked:
        raise ValueError("public source checkout changed while preparing the SDK archive")
    if output.exists() or output.is_symlink():
        raise ValueError("--output must name a fresh directory")
    if not output.parent.is_dir():
        raise ValueError("--output parent directory must already exist")
    output = output.parent.resolve(strict=True) / output.name
    if output.exists() or output.is_symlink():
        raise ValueError("--output must name a fresh directory")
    if output == source or source in output.parents or output in source.parents:
        raise ValueError("--output must not overlap the source checkout")
    output.mkdir()
    archive_path = output / ("ami-rust-sdk-0.1.0.tar.xz" if production_candidate
                             else "ami-rust-sdk-0.1.0-rc.4-hosted.tar.xz")
    try:
        with archive_path.open("xb") as stream:
            stream.write(archive_bytes)
    except BaseException:
        try:
            archive_path.unlink(missing_ok=True)
            output.rmdir()
        except OSError as cleanup_error:
            raise RuntimeError("archive write failed and partial output cleanup also failed") from cleanup_error
        raise
    return {
        "status": ("PREPARED_PRODUCTION_TRUST_CANDIDATE_NOT_R1_ACCEPTED" if production_candidate
                   else "PREPARED_QUALIFICATION_ONLY_METADATA_NOT_DISTRIBUTION"),
        "source_commit": head,
        "archive": archive_path.name,
        "archive_bytes": len(archive_bytes),
        "archive_sha256": digest(archive_bytes),
        "member_count": len(files),
        "manifest_sha256": digest(files["contract/sdk.json"]),
        "cargo_component_manifests": {host: digest(cargo_component_bytes[host]) for host in HOSTS},
        "qualification_only": not production_candidate,
        "cargo_binary_payload_included": False,
    }


def parse_report(value: str) -> tuple[str, Path]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("--cargo-producer must be HOST=REPORT")
    host, name = value.split("=", 1)
    if host not in HOSTS or not name:
        raise argparse.ArgumentTypeError("--cargo-producer host must be macos-aarch64 or linux-x86_64")
    return host, Path(name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cargo-producer", action="append", type=parse_report, required=True)
    parser.add_argument("--resources", type=Path, required=True)
    parser.add_argument("--production-candidate", action="store_true",
                        help="prepare version 0.1.0 for real publisher verification; does not grant R1 acceptance")
    args = parser.parse_args(argv)
    reports = {}
    for host, path in args.cargo_producer:
        if host in reports:
            parser.error(f"duplicate --cargo-producer for {host}")
        reports[host] = path
    try:
        result = prepare(args.source, args.output, args.resources, reports,
                         production_candidate=args.production_candidate)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError,
            json.JSONDecodeError, subprocess.CalledProcessError) as error:
        print(f"prepare_sdk: {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
