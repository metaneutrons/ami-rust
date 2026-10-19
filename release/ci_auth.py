#!/usr/bin/env python3
"""Assemble a real publisher candidate and its exact SLSA input statements.

This helper never grants R1 acceptance or publishes a release. The protected
workflow signs its outputs; the independent consumer verifies real bundles.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import importlib.util
import io
import json
import lzma
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parent.parent
HOSTS = ("linux-x86_64", "macos-aarch64")
REPO = "metaneutrons/ami-rust"
WORKFLOW = ".github/workflows/sdk-qualify.yml"
SUBJECTS = ("release.json", "sdk.tar.xz", "SHAUTIL")
FILE_LIMIT = 16 * 1024**2
TREE_LIMIT = 32 * 1024**2
PORTABLE_CSDK_SPEC = "release/portable-csdk/spec.json"
PORTABLE_CSDK_ORIGINAL_ARCHIVE = "release/inputs/csdk.tar.xz"
PORTABLE_CSDK_CANDIDATE_ARCHIVE = "release/inputs/portable-csdk.tar.xz"
PORTABLE_CSDK_CANDIDATE_ARCHIVE_NAME = "csdk-component.tar.xz"
PORTABLE_CSDK_COUNTS = {"changed_files": 532, "public_headers": 530, "regular_files": 2835}
SDK_PRODUCER_RECEIPT_SCHEMA = "ami-rust-hosted-sdk-producer-v1"
SDK_PRODUCER_RECEIPT_STATUS = "PRODUCED_HOSTED_SDK_CANDIDATE_NOT_R1_ACCEPTED"
GITHUB_INTERNAL_PARAMETERS = {
    "event_name": "workflow_dispatch",
    "repository_id": "1421182484",
    "repository_owner_id": "436979",
    "runner_environment": "github-hosted",
}
PREFLIGHT_SUBJECT = b"ami-rust GitHub provenance ingestion preflight; not an SDK candidate\n"
IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1"
IN_TOTO_JSON = "application/vnd.in-toto+json"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def rel(value):
    if (not isinstance(value, str) or not value or len(value) > 240 or "\\" in value or ":" in value
            or any(ord(c) < 32 or ord(c) >= 127 for c in value)
            or len(value.split("/")) > 24
            or any(not re.fullmatch(r"[A-Za-z0-9._+-]{1,120}", p) or p in (".", "..") or p.endswith(".")
                   or p.split(".", 1)[0].upper() in {"CON", "PRN", "AUX", "NUL"}
                   or re.fullmatch(r"(?:COM|LPT)[1-9]", p.split(".", 1)[0].upper()) for p in value.split("/"))
            or PurePosixPath(value).is_absolute()):
        raise ValueError("unsafe relative publisher path")
    return value


def read(path, cap=FILE_LIMIT):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > cap:
        raise ValueError("publisher input must be a bounded regular file: " + path.name)
    raw = path.read_bytes()
    if len(raw) != info.st_size:
        raise ValueError("publisher input changed while reading")
    return raw


def parsed(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError("duplicate publisher JSON key")
            result[key] = value
        return result
    def constant(_):
        raise ValueError("nonfinite publisher JSON")
    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("nonfinite publisher JSON exponent")
        return number
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=finite_float)


def below(root, name):
    rel(name)
    current = root
    for part in name.split("/"):
        current = current / part
        if current.is_symlink():
            raise ValueError("symlink in publisher input path")
    current.resolve(strict=True).relative_to(root.resolve(strict=True))
    return current


def context(source):
    expected = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": REPO,
                "GITHUB_REF": "refs/heads/main", "SOURCE_IS_PROTECTED": "true",
                "PUBLISHER_ENVIRONMENT": "release", "RUNNER_ENVIRONMENT": "github-hosted",
                "GITHUB_EVENT_NAME": GITHUB_INTERNAL_PARAMETERS["event_name"],
                "GITHUB_REPOSITORY_ID": GITHUB_INTERNAL_PARAMETERS["repository_id"],
                "GITHUB_REPOSITORY_OWNER_ID": GITHUB_INTERNAL_PARAMETERS["repository_owner_id"]}
    if any(os.environ.get(k) != v for k, v in expected.items()):
        raise ValueError("publisher requires the designated protected hosted release workflow")
    head = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if (not re.fullmatch(r"[0-9a-f]{40}", head) or os.environ.get("GITHUB_SHA") != head
            or os.environ.get("GITHUB_WORKFLOW_SHA") != head
            or os.environ.get("GITHUB_WORKFLOW_REF") != f"{REPO}/{WORKFLOW}@refs/heads/main"):
        raise ValueError("publisher checkout/source/workflow identity mismatch")
    run = int(os.environ["GITHUB_RUN_ID"])
    attempt = int(os.environ["GITHUB_RUN_ATTEMPT"])
    if run <= 0 or attempt <= 0:
        raise ValueError("invalid publisher run identity")
    return {"source_sha": head, "workflow_sha": head, "run_id": run, "run_attempt": attempt}


def github_internal_parameters():
    actual = {
        "event_name": os.environ.get("GITHUB_EVENT_NAME"),
        "repository_id": os.environ.get("GITHUB_REPOSITORY_ID"),
        "repository_owner_id": os.environ.get("GITHUB_REPOSITORY_OWNER_ID"),
        "runner_environment": os.environ.get("RUNNER_ENVIRONMENT"),
    }
    if actual != GITHUB_INTERNAL_PARAMETERS:
        raise ValueError("GitHub provenance parameters differ from the protected repository workflow")
    return actual


def _portable_pin(pin, label, path_key="path"):
    if not isinstance(pin, dict) or set(pin) != {path_key, "bytes", "sha256"}:
        raise ValueError("malformed portable C-SDK " + label + " pin")
    rel(pin.get(path_key))
    if type(pin.get("bytes")) is not int or pin["bytes"] <= 0:
        raise ValueError("malformed portable C-SDK " + label + " byte pin")
    if not isinstance(pin.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]):
        raise ValueError("malformed portable C-SDK " + label + " digest")


def _validate_portable_csdk_spec(spec):
    keys = {"schema", "status", "original", "candidate", "nouveau", "patch_series",
            "required_counts", "source_capsule", "source_manifest", "toolchains"}
    if (not isinstance(spec, dict) or set(spec) != keys
            or spec.get("schema") != "ami-rust-portable-csdk-v1"
            or spec.get("status") != "PINNED_CANDIDATE_TWO_HOST_QUALIFICATION_REQUIRED"):
        raise ValueError("unsupported portable C-SDK specification")
    if (not isinstance(spec["original"], dict) or set(spec["original"]) != {"profile", "archive"}
            or not isinstance(spec["candidate"], dict)
            or set(spec["candidate"]) != {"profile", "archive"}):
        raise ValueError("malformed portable C-SDK original or candidate identity")
    for label in ("original profile", "candidate profile", "original archive"):
        section, field = label.split(" ", 1)
        _portable_pin(spec[section][field], label)
    for label in ("patch_series", "source_capsule", "source_manifest"):
        _portable_pin(spec[label], label.replace("_", " "))
    candidate_archive = spec["candidate"]["archive"]
    if (not isinstance(candidate_archive, dict)
            or set(candidate_archive) != {"path", "name", "bytes", "sha256"}):
        raise ValueError("malformed portable C-SDK candidate archive pin")
    rel(candidate_archive["path"])
    rel(candidate_archive["name"])
    if (candidate_archive["path"] != PORTABLE_CSDK_CANDIDATE_ARCHIVE
            or candidate_archive["name"] != PORTABLE_CSDK_CANDIDATE_ARCHIVE_NAME
            or type(candidate_archive["bytes"]) is not int or candidate_archive["bytes"] <= 0
            or not isinstance(candidate_archive["sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", candidate_archive["sha256"])):
        raise ValueError("portable C-SDK candidate archive differs from its repository prerequisite")
    if (spec["original"]["archive"]["path"] != PORTABLE_CSDK_ORIGINAL_ARCHIVE
            or spec["original"]["profile"]["path"] != "release/portable-csdk/original-profile.json"
            or spec["candidate"]["profile"]["path"] != "release/portable-csdk/profile.json"):
        raise ValueError("portable C-SDK original or candidate path is not normative")
    if (spec["patch_series"]["path"] != "release/patches/portable-csdk/series.json"
            or spec["source_capsule"]["path"] != "release/csdk-source/csdk-corresponding-source.tar.xz"
            or spec["source_manifest"]["path"] != "release/csdk-source/manifest.json"):
        raise ValueError("portable C-SDK source material path is not normative")
    if (not isinstance(spec["required_counts"], dict)
            or spec["required_counts"] != PORTABLE_CSDK_COUNTS):
        raise ValueError("portable C-SDK change counts differ from the reviewed values")
    nouveau_keys = {"archive_path", "derived_bytes", "derived_sha256", "historical_source_prefix",
                    "objects", "original_bytes", "original_sha256", "path_changed_members", "symbols",
                    "unchanged_members"}
    nouveau = spec["nouveau"]
    if not isinstance(nouveau, dict) or set(nouveau) != nouveau_keys:
        raise ValueError("malformed portable C-SDK nouveau identity")
    rel(nouveau["archive_path"])
    for key in ("derived_sha256", "original_sha256"):
        if not isinstance(nouveau[key], str) or not re.fullmatch(r"[0-9a-f]{64}", nouveau[key]):
            raise ValueError("malformed portable C-SDK nouveau digest")
    if (not isinstance(nouveau["historical_source_prefix"], str)
            or any(type(nouveau[key]) is not int or nouveau[key] < 0
                   for key in ("derived_bytes", "objects", "original_bytes", "path_changed_members",
                               "symbols", "unchanged_members"))):
        raise ValueError("malformed portable C-SDK nouveau measurements")
    toolchains = spec["toolchains"]
    if not isinstance(toolchains, dict) or set(toolchains) != set(HOSTS):
        raise ValueError("portable C-SDK toolchain profiles are incomplete")
    for host, components in toolchains.items():
        if not isinstance(components, dict) or set(components) != {"compiler", "profile"}:
            raise ValueError("malformed portable C-SDK " + host + " toolchain identity")
        compiler = components["compiler"]
        if (not isinstance(compiler, dict) or set(compiler) != {"path", "bytes", "sha256"}
                or compiler.get("path") != "bin/clang-11"):
            raise ValueError("malformed portable C-SDK " + host + " compiler pin")
        _portable_pin(components["profile"], host + " toolchain profile")
        if components["profile"]["path"] != f"release/portable-csdk/toolchains/{host}.json":
            raise ValueError("portable C-SDK " + host + " toolchain profile path is not normative")
        if (type(compiler.get("bytes")) is not int or compiler["bytes"] <= 0
                or not isinstance(compiler.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", compiler["sha256"])):
            raise ValueError("malformed portable C-SDK " + host + " compiler digest")


def _verify_pinned_file(source, pin, label, *, cap=FILE_LIMIT, keep=False):
    path = below(source, pin["path"])
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size != pin["bytes"] or info.st_size > cap:
        raise ValueError("portable C-SDK " + label + " differs from its pinned size")
    if keep:
        raw = read(path, cap)
        value = sha(raw)
    else:
        with path.open("rb") as stream:
            value = hashlib.file_digest(stream, "sha256").hexdigest()
        raw = None
    if value != pin["sha256"]:
        raise ValueError("portable C-SDK " + label + " differs from its source pin")
    return raw


def load_portable_csdk(source, inputs, *, full=False, add_material=None):
    pin = inputs.get("portable_csdk")
    if (not isinstance(pin, dict) or set(pin) != {"path", "bytes", "sha256"}
            or pin.get("path") != PORTABLE_CSDK_SPEC):
        raise ValueError("CI inputs do not pin the portable C-SDK specification")
    _portable_pin(pin, "specification")
    spec_raw = _verify_pinned_file(source, pin, "specification", keep=True)
    spec = parsed(spec_raw)
    _validate_portable_csdk_spec(spec)

    original_archive = spec["original"]["archive"]
    shared_csdk = inputs.get("shared", {}).get("csdk")
    if (not isinstance(shared_csdk, dict)
            or any(shared_csdk.get(key) != original_archive[key] for key in ("path", "bytes", "sha256"))):
        raise ValueError("portable C-SDK original archive differs from the shared CI input pin")

    original_profile = _verify_pinned_file(
        source, spec["original"]["profile"], "original profile", keep=True)
    candidate_profile = _verify_pinned_file(
        source, spec["candidate"]["profile"], "candidate profile", keep=True)
    _verify_pinned_file(source, spec["candidate"]["archive"], "candidate archive")
    for host in HOSTS:
        _verify_pinned_file(source, spec["toolchains"][host]["profile"], host + " toolchain profile")

    if full:
        series_raw = _verify_pinned_file(source, spec["patch_series"], "patch series", keep=True)
        source_manifest_raw = _verify_pinned_file(
            source, spec["source_manifest"], "source manifest", keep=True)
        _verify_pinned_file(source, spec["source_capsule"], "source capsule", cap=104 * 1024**2)
        series = parsed(series_raw)
        source_manifest = parsed(source_manifest_raw)
        capsule = source_manifest.get("capsule")
        if not isinstance(capsule, dict):
            raise ValueError("portable C-SDK source manifest has no pinned capsule")
        capsule_name = "release/csdk-source/" + rel(capsule.get("path"))
        capsule_pin = spec["source_capsule"]
        if (capsule_name != capsule_pin["path"] or capsule.get("bytes") != capsule_pin["bytes"]
                or capsule.get("sha256") != capsule_pin["sha256"]
                or series.get("original_source_capsule_sha256") != capsule_pin["sha256"]):
            raise ValueError("portable C-SDK capsule, manifest and patch series pins disagree")
        patch_rows = series.get("patches")
        if not isinstance(patch_rows, list):
            raise ValueError("portable C-SDK patch series has no patch list")
        for patch in patch_rows:
            if not isinstance(patch, dict) or not {"patch", "patch_sha256"} <= set(patch):
                raise ValueError("malformed portable C-SDK patch pin")
            name = "release/patches/portable-csdk/" + rel(patch["patch"])
            patch_pin = {"path": name, "bytes": patch.get("bytes"), "sha256": patch["patch_sha256"]}
            if type(patch_pin["bytes"]) is not int or patch_pin["bytes"] <= 0:
                # Existing series entries predate byte pins; the digest remains the exact content pin.
                path = below(source, name)
                if not stat.S_ISREG(path.lstat().st_mode) or sha(read(path)) != patch["patch_sha256"]:
                    raise ValueError("portable C-SDK patch differs from its source pin")
            else:
                _verify_pinned_file(source, patch_pin, "patch")
            if add_material:
                add_material(f"git+https://github.com/{REPO}#{name}", "sha256", patch["patch_sha256"])

    if add_material:
        pins = [pin, spec["original"]["profile"], spec["candidate"]["profile"],
                spec["original"]["archive"], spec["candidate"]["archive"], spec["patch_series"],
                spec["source_capsule"], spec["source_manifest"],
                *(spec["toolchains"][host]["profile"] for host in HOSTS)]
        if not full:
            pins = pins[:5] + [*(spec["toolchains"][host]["profile"] for host in HOSTS)]
        for item in pins:
            add_material(f"git+https://github.com/{REPO}#{item['path']}", "sha256", item["sha256"])

    return {"spec": spec, "spec_raw": spec_raw, "original_profile": original_profile,
            "candidate_profile": candidate_profile}


def input_manifest(source):
    materials = {}
    def add(uri, algorithm, digest):
        if not re.fullmatch(r"[0-9a-f]{64}" if algorithm == "sha256" else r"[0-9a-f]{40}", digest):
            raise ValueError("invalid publisher input digest")
        row = {"uri": uri, "digest": {algorithm: digest}}
        if uri in materials and materials[uri] != row:
            raise ValueError("conflicting publisher material identity")
        materials[uri] = row
    inputs = parsed(read(source / "release/ci-sdk-inputs.json"))
    bootstrap = parsed(read(source / "release/ci-bootstrap-inputs.json"))
    python = parsed(read(source / "release/ci-python-inputs.json"))
    channel = inputs["channel_manifest"]
    add(channel["url"], "sha256", channel["sha256"])
    for host in HOSTS:
        for row in inputs["hosts"][host]["rust"]["archives"]:
            add(row["url"], "sha256", row["sha256"])
        for component in ("toolchain", "collector"):
            row = inputs["hosts"][host][component]
            add(row["url"], "sha256", row["sha256"])
        row = python["hosts"][host]
        add(row["url"], "sha256", row["sha256"])
    for target in bootstrap["rust"]["components"].values():
        for component in ("rustc", "rust-std", "cargo"):
            row = target[component]
            add(row["url"], "sha256", row["sha256"])
    cargo = bootstrap["custom_cargo"]
    add(cargo["upstream"] + "@" + cargo["commit"], "gitCommit", cargo["commit"])
    for row in inputs["shared"].values():
        path = below(source, row["path"])
        if len(read(path)) != row["bytes"] or sha(read(path)) != row["sha256"]:
            raise ValueError("repository SDK input differs from its pin")
        add(f"git+https://github.com/{REPO}#{row['path']}", "sha256", row["sha256"])
    load_portable_csdk(source, inputs, full=True, add_material=add)
    for name in ("release/ci-sdk-inputs.json", "release/ci-bootstrap-inputs.json",
                 "release/ci-python-inputs.json", "release/ci-resources.json",
                 "release/native-reference.json", "release/bundle-files.json",
                 "release/ci-auth-tools.json", "release/patches/portable-csdk/series.json",
                 "release/csdk-source/manifest.json",
                 "host/cargo-repro/cargo-metadata.patch", "host/cargo-repro/openssl-paths.patch"):
        add(f"git+https://github.com/{REPO}#{name}", "sha256", sha(read(below(source, name))))
    tools = parsed(read(below(source, "release/ci-auth-tools.json")))
    for host in HOSTS:
        for component in ("gh", "cosign"):
            pin = tools["hosts"][host][component]
            add(pin["url"], "sha256", pin["sha256"])
    for pin in tools["roots"].values():
        raw = read(below(source, pin["path"]))
        if len(raw) != pin["bytes"] or sha(raw) != pin["sha256"]:
            raise ValueError("authentication trust root differs from its source pin")
        add(f"git+https://github.com/{REPO}#{pin['path']}", "sha256", pin["sha256"])
    return {"schema": "ami-rust-publisher-inputs-v1",
            "materials": [materials[k] for k in sorted(materials)]}


def input_manifest_for_sdk(source, sdk_version):
    """Extend the historical publisher materials for native SDK generations."""
    legacy = input_manifest(source)
    if sdk_version == "0.1.0":
        return legacy

    materials = {}

    def add(uri, algorithm, digest):
        if (not isinstance(uri, str)
                or algorithm not in ("sha256", "gitCommit")
                or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}" if algorithm == "sha256" else r"[0-9a-f]{40}", digest)):
            raise ValueError("invalid publisher input material")
        row = {"uri": uri, "digest": {algorithm: digest}}
        if uri in materials and materials[uri] != row:
            raise ValueError("conflicting publisher material identity")
        materials[uri] = row

    for row in legacy["materials"]:
        digest = row["digest"]
        if not isinstance(digest, dict) or len(digest) != 1:
            raise ValueError("invalid legacy publisher material digest")
        algorithm, value = next(iter(digest.items()))
        add(row["uri"], algorithm, value)

    config_path = "release/native-tooling-inputs.json"
    config_raw = read(below(Path(source), config_path))
    config = parsed(config_raw)
    config_fields = {"schema", "sdk_version", "cli_version", "legacy_release", "cargo_lock",
                     "registry_crates", "source_files"}
    if not isinstance(config, dict) or set(config) != config_fields:
        raise ValueError("malformed native tooling inputs")
    if (config.get("schema") != "ami-rust-native-tooling-inputs-v1"
            or config.get("sdk_version") != sdk_version or sdk_version == "0.1.0"):
        raise ValueError("native tooling inputs select a different SDK generation")
    cli_version = config.get("cli_version")
    if not isinstance(cli_version, str) or cli_version.split("-", 1)[0] != sdk_version:
        raise ValueError("native CLI and SDK version cores differ")

    def pin(value, label):
        if not isinstance(value, dict) or set(value) != {"path", "bytes", "sha256"}:
            raise ValueError("malformed " + label + " pin")
        path = rel(value.get("path"))
        size = value.get("bytes")
        digest = value.get("sha256")
        if type(size) is not int or size <= 0:
            raise ValueError("malformed " + label + " byte pin")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("malformed " + label + " digest")
        return path, size, digest

    lock_path, lock_size, lock_digest = pin(config["cargo_lock"], "native Cargo lock")
    if lock_path != "tooling/Cargo.lock":
        raise ValueError("native producer must pin tooling/Cargo.lock")
    lock_raw = read(below(Path(source), lock_path))
    if len(lock_raw) != lock_size or sha(lock_raw) != lock_digest:
        raise ValueError("native Cargo lock differs from its source pin")

    baseline = parsed(read(below(Path(source), "tooling/fixtures/accepted-r1-inputs.json")))
    try:
        accepted_archive = baseline["accepted_release"]["public_provenance"]["public_release_archive_asset"]
    except (KeyError, TypeError) as exc:
        raise ValueError("accepted R1 baseline omits its public release archive pin") from exc
    capsule = config["legacy_release"]
    if not isinstance(capsule, dict) or set(capsule) != {"url", "bytes", "sha256"}:
        raise ValueError("malformed accepted input capsule")
    capsule_url = capsule.get("url")
    capsule_size = capsule.get("bytes")
    capsule_digest = capsule.get("sha256")
    accepted_size = accepted_archive.get("bytes") if isinstance(accepted_archive, dict) else None
    accepted_digest = accepted_archive.get("sha256") if isinstance(accepted_archive, dict) else None
    if (capsule_url != "https://github.com/metaneutrons/ami-rust/releases/download/v0.1.0/ami-rust-0.1.0-release.tar.xz"
            or type(capsule_size) is not int or capsule_size <= 0
            or not isinstance(capsule_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", capsule_digest)
            or type(accepted_size) is not int or accepted_size != capsule_size
            or accepted_digest != capsule_digest):
        raise ValueError("native producer input capsule differs from the accepted baseline")
    add(capsule_url, "sha256", capsule_digest)

    source_files = config["source_files"]
    if not isinstance(source_files, list) or not 1 <= len(source_files) <= 1000:
        raise ValueError("invalid native producer source inventory length")
    previous = None
    for path in source_files:
        if not isinstance(path, str):
            raise ValueError("native source path must be a string")
        rel(path)
        if (not (path.startswith("tooling/")
                 or path in ("tools/bootstrap-host-rust.sh", "tools/build-native-cli.sh"))
                or (previous is not None and previous >= path)):
            raise ValueError("native source inventory has unsupported or unordered paths")
        previous = path
        add("git+https://github.com/" + REPO + "#" + path, "sha256",
            sha(read(below(Path(source), path))))
    required_sources = ("tooling/Cargo.lock", "tooling/Cargo.toml",
                        "tooling/crates/core/build.rs",
                        "tooling/crates/core/src/macos_process_snapshot.c",
                        "tooling/crates/core/src/macos_process_snapshot.rs",
                        "tooling/crates/xtask/src/native_release.rs",
                        "tooling/crates/xtask/src/consumer_observe.rs",
                        "tooling/crates/xtask/src/consumer_report.rs",
                        "tooling/crates/xtask/src/consumer_runtime.rs",
                        "tooling/crates/xtask/src/legacy_migration_fixture.rs",
                        "tooling/crates/xtask/src/prepare_sigterm.rs",
                        "tooling/fixtures/accepted-r1-inputs.json",
                        "tooling/fixtures/accepted-r1-support-inputs.json",
                        "tools/bootstrap-host-rust.sh", "tools/build-native-cli.sh")
    if any(path not in source_files for path in required_sources):
        raise ValueError("native producer source inventory omits a required input")

    registry_crates = config["registry_crates"]
    if not isinstance(registry_crates, list) or len(registry_crates) != 29:
        raise ValueError("native producer registry set differs from the reviewed 29-crate selection")
    previous = None
    for crate in registry_crates:
        if not isinstance(crate, dict) or set(crate) != {"name", "version", "url", "sha256"}:
            raise ValueError("malformed native registry crate")
        name, version = crate.get("name"), crate.get("version")
        if (not isinstance(name, str) or not name
                or not all(c.isascii() and (c.isalnum() or c in "_-") for c in name)
                or not isinstance(version, str) or not version
                or not all(c.isascii() and (c.isalnum() or c in ".+-") for c in version)
                or (previous is not None and previous >= (name, version))
                or crate.get("url") != f"https://static.crates.io/crates/{name}/{name}-{version}.crate"):
            raise ValueError("invalid or unordered native registry crate identity")
        previous = (name, version)
        add(crate["url"], "sha256", crate.get("sha256"))

    add("git+https://github.com/" + REPO + "#" + config_path, "sha256", sha(config_raw))
    return {"schema": "ami-rust-publisher-inputs-v1",
            "materials": [materials[uri] for uri in sorted(materials)]}


def sdk_contents(raw):
    # Reuse the delivered installer's bounded XZ parser, before tar parsing.
    spec = importlib.util.spec_from_file_location("_ci_auth_installer", ROOT / "release/install.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    plain = module._decompress_xz(raw)
    data = {}
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:") as tar:
        for member in tar:
            name = rel(member.name)
            if not member.isfile() or name in data or member.size > FILE_LIMIT or len(data) >= 1000:
                raise ValueError("invalid SDK publisher archive member")
            data[name] = tar.extractfile(member).read()
    manifest = parsed(data["contract/sdk.json"])
    if (manifest.get("schema") != "ami-rust-sdk-v1" or manifest.get("version") != "0.1.0"
            or manifest.get("qualification_only") is not False):
        raise ValueError("SDK must be the explicit production trust candidate")
    declared = module._inventory(manifest["files"], "publisher SDK member",
                                 count_limit=module.ARCHIVE_MEMBERS_LIMIT,
                                 total_limit=module.ARCHIVE_LIMIT,
                                 file_limit=module.ARCHIVE_LIMIT)
    expected = {x["path"]: x for x in manifest["files"]}
    if set(data) != set(expected) | {"contract/sdk.json"}:
        raise ValueError("SDK publisher inventory is incomplete")
    for name, row in expected.items():
        if len(data[name]) != row["bytes"] or sha(data[name]) != row["sha256"]:
            raise ValueError("SDK publisher member digest mismatch")
    verified, _ = module._verify_archive(raw, {
        **declared, "contract/sdk.json": (len(data["contract/sdk.json"]), sha(data["contract/sdk.json"]))})
    return manifest, verified


def bounded_xz(raw, maximum):
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 * 1024**2)
    output = bytearray()
    pending = raw
    while True:
        output.extend(decoder.decompress(pending, max_length=maximum + 1 - len(output)))
        pending = b""
        if len(output) > maximum:
            raise ValueError("expanded publisher archive exceeds its ceiling")
        if decoder.eof:
            if decoder.unused_data:
                raise ValueError("trailing or concatenated publisher archive")
            return bytes(output)
        if decoder.needs_input:
            raise ValueError("truncated publisher archive")


def cargo_matches(raw, profile):
    expected = {x["path"]: x for x in profile["files"]}
    if len(expected) != len(profile["files"]) or set(expected) != {"bin/cargo", "producer.json"}:
        raise ValueError("Cargo profile must cover exactly the binary and producer receipt")
    found = {}
    expanded = 0
    with tarfile.open(fileobj=io.BytesIO(bounded_xz(raw, 256 * 1024**2)), mode="r:") as tar:
        for member in tar:
            name = rel(member.name)
            expanded += member.size
            if (not member.isfile() or name not in expected or name in found
                    or expanded > 256 * 1024**2):
                raise ValueError("unexpected Cargo component archive member")
            h = hashlib.sha256()
            size = 0
            stream = tar.extractfile(member)
            for block in iter(lambda: stream.read(65536), b""):
                size += len(block)
                h.update(block)
            found[name] = {"path": name, "bytes": size, "sha256": h.hexdigest()}
    if found != expected:
        raise ValueError("Cargo component payload differs from the SDK profile")


def static_assets(source, reserved=()):
    """Read the exact pinned static distribution files without building an SDK."""
    assets = {}
    static = parsed(read(source / "release/bundle-files.json"))
    if static.get("schema") != "ami-rust-bundle-files-v1":
        raise ValueError("invalid static release bundle map")
    for row in static["files"]:
        name = rel(row["path"])
        if name in assets or name in reserved or name == "release.json" or name.startswith(".auth/"):
            raise ValueError("duplicate/reserved static asset")
        raw = read(below(source, row["source"]))
        if len(raw) != row["bytes"] or sha(raw) != row["sha256"]:
            raise ValueError("static release asset differs from tracked publisher pin")
        assets[name] = raw
    return assets


def validate_sdk_producer_receipt(payload, host, source_sha):
    try:
        receipt = parsed(read(below(Path(payload), "sdk-producer.json")))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError("missing or invalid SDK producer receipt for " + host) from exc
    source = receipt.get("source") if isinstance(receipt, dict) else None
    if (not isinstance(receipt, dict)
            or receipt.get("schema") != SDK_PRODUCER_RECEIPT_SCHEMA
            or receipt.get("status") != SDK_PRODUCER_RECEIPT_STATUS
            or receipt.get("host") != host
            or receipt.get("reference_proposal") is not False
            or not isinstance(source, dict)
            or source.get("commit") != source_sha):
        raise ValueError("SDK producer receipt is not an accepted non-proposal candidate for " + host)


def _assemble(source, payloads, output, *, check_sdk_producer_receipts):
    source = Path(source).resolve(strict=True)
    output = Path(output)
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError("fresh publisher output required")
    destination = output.resolve()
    if destination == source or source in destination.parents:
        raise ValueError("publisher output must be outside the source checkout")
    for payload in payloads.values():
        payload = Path(payload)
        if payload.is_symlink() or payload.resolve(strict=True) != payload.absolute():
            raise ValueError("payload root must not contain symlink components")
        if destination == payload or payload in destination.parents or destination in payload.parents:
            raise ValueError("publisher output overlaps a producer payload")
    identity = context(source)
    sdk_inputs = parsed(read(below(source, "release/ci-sdk-inputs.json")))
    portable_csdk = load_portable_csdk(source, sdk_inputs)
    if check_sdk_producer_receipts:
        for host in HOSTS:
            validate_sdk_producer_receipt(payloads[host], host, identity["source_sha"])
    sdk = [read(below(Path(payloads[h]), "sdk.tar.xz")) for h in HOSTS]
    if sdk[0] != sdk[1]:
        raise ValueError("host SDK archives are not byte-identical")
    sdk_manifest, sdk_files = sdk_contents(sdk[0])
    if sdk_manifest.get("source_identity") != identity["source_sha"]:
        raise ValueError("SDK source differs from the publisher workflow checkout")
    spec = portable_csdk["spec"]
    distribution_spec = copy.deepcopy(spec)
    distribution_spec["nouveau"].pop("historical_source_prefix")
    expected_csdk_metadata = {
        "spec_path": PORTABLE_CSDK_SPEC,
        "spec_bytes": len(portable_csdk["spec_raw"]),
        "spec_sha256": sha(portable_csdk["spec_raw"]),
        "distribution_spec": distribution_spec,
        "candidate_archive": spec["candidate"]["archive"],
        "replacements": {
            host: {"manifest": f"host/profiles/{host}/csdk.json",
                   "sha256": sha(portable_csdk["candidate_profile"])}
            for host in HOSTS
        },
        "changed_profile_rows": spec["required_counts"]["changed_files"],
    }
    packaging = sdk_manifest.get("packaging")
    if (not isinstance(packaging, dict)
            or packaging.get("portable_csdk") != expected_csdk_metadata):
        raise ValueError("SDK portable C-SDK metadata differs from the source-pinned specification")
    profiles = sdk_manifest.get("profiles")
    if not isinstance(profiles, dict):
        raise ValueError("SDK host C-SDK profiles are missing")
    for host in HOSTS:
        name = f"host/profiles/{host}/csdk.json"
        if sdk_files.get(name) != portable_csdk["candidate_profile"]:
            raise ValueError("SDK host C-SDK profile differs from the source-pinned candidate profile")
        profile = profiles.get(host)
        component = profile.get("components", {}).get("csdk") if isinstance(profile, dict) else None
        if (not isinstance(component, dict) or component.get("manifest") != name
                or component.get("sha256") != sha(portable_csdk["candidate_profile"])):
            raise ValueError("SDK host C-SDK profile reference differs from the source-pinned candidate")
    assets = {"sdk.tar.xz": sdk[0]}
    gold = parsed(read(source / "release/native-reference.json"))["hosts"]
    for host in HOSTS:
        native = read(below(Path(payloads[host]), "native/sha256sum.AMIRUST"))
        expected = gold[host]["sha256sum"]["AMIRUST"]
        if len(native) != expected["bytes"] or sha(native) != expected["sha256"]:
            raise ValueError("reference utility differs from qualified native bytes")
        if "SHAUTIL" in assets and assets["SHAUTIL"] != native:
            raise ValueError("host reference utilities are not byte-identical")
        assets["SHAUTIL"] = native
        cargo = read(below(Path(payloads[host]), "cargo-component.tar.xz"))
        profile = parsed(sdk_files[f"host/profiles/{host}/cargo.json"])
        cargo_matches(cargo, profile)
        assets[f"cargo-{host}.tar.xz"] = cargo
    assets.update(static_assets(source, set(assets)))
    if sum(map(len, assets.values())) > TREE_LIMIT - 1024 * 1024:
        raise ValueError("release payload exceeds the authentication bundle ceiling")
    python = parsed(read(source / "release/ci-python-inputs.json"))
    manifest = {"schema": "ami-rust-release-v1", "version": "0.1.0", "qualification_only": False,
                "sdk_archive": "sdk.tar.xz", "sdk_manifest_sha256": sha(sdk_files["contract/sdk.json"]),
                "assets": [{"path": k, "bytes": len(v), "sha256": sha(v)} for k, v in sorted(assets.items())],
                "sdk_files": [{"path": k, "bytes": len(v), "sha256": sha(v)} for k, v in sorted(sdk_files.items())],
                "host_interpreters": {h: {"sha256": python["hosts"][h]["runtime_sha256"]} for h in HOSTS},
                "producer": {"kind": "protected-github-actions", "repository": REPO,
                             "workflow": WORKFLOW, **identity,
                             "acceptance": "R1 acceptance and publication are separate gates"}}
    output.mkdir()
    for name, raw in assets.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    (output / "release.json").write_bytes(encoded(manifest))
    auth = output / ".auth"
    auth.mkdir()
    (auth / "inputs.json").write_bytes(encoded(input_manifest(source)))
    return {"schema": "ami-rust-publisher-candidate-v1", "source": identity,
            "manifest_sha256": sha(encoded(manifest)), "assets": len(assets),
            "claim": "Unsigned candidate prepared; real signatures, independent verification and R1 acceptance required"}


def assemble(source, payloads, output):
    """Assemble only payloads backed by accepted non-proposal SDK receipts."""
    return _assemble(source, payloads, output, check_sdk_producer_receipts=True)


def _predicate_for(producer, inputs_raw, materials, host):
    publisher_policy = {
        "environment": "release", "runnerEnvironment": "github-hosted",
        "repository": REPO, "workflow": WORKFLOW, "workflowSha": producer["workflow_sha"],
        "sourceSha": producer["source_sha"], "sourceRef": "refs/heads/main",
        "inputsManifestSha256": sha(inputs_raw), "hostProfile": host,
    }
    return {"buildDefinition": {"buildType": "https://actions.github.io/buildtypes/workflow/v1",
                "externalParameters": {"workflow": {"repository": f"https://github.com/{REPO}",
                                                     "path": WORKFLOW, "ref": "refs/heads/main"}},
                "internalParameters": {"github": dict(GITHUB_INTERNAL_PARAMETERS),
                                        "publisherPolicy": publisher_policy},
                "resolvedDependencies": [{"uri": f"git+https://github.com/{REPO}@refs/heads/main",
                                          "digest": {"gitCommit": producer["source_sha"]}}, *materials]},
            "runDetails": {"builder": {"id": f"https://github.com/{REPO}/{WORKFLOW}@refs/heads/main"},
                "metadata": {"invocationId": f"https://github.com/{REPO}/actions/runs/{producer['run_id']}/attempts/{producer['run_attempt']}"}}}


def predicate(bundle, host, source=None):
    if host not in HOSTS:
        raise ValueError("invalid predicate host profile")
    bundle = Path(bundle)
    release = parsed(read(bundle / "release.json"))
    producer = release["producer"]
    if source is not None:
        identity = context(source)
        if any(producer.get(key) != value for key, value in identity.items()):
            raise ValueError("authentication predicate source/run differs from protected workflow context")
    inputs_raw = read(bundle / ".auth/inputs.json")
    materials = parsed(inputs_raw)["materials"]
    return _predicate_for(producer, inputs_raw, materials, host)


def _fresh_external_file(path, source, raw):
    path = Path(path)
    if not path.is_absolute() or path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise ValueError("preflight output must be a fresh absolute file")
    resolved = path.resolve(strict=False)
    source = Path(source).resolve(strict=True)
    if resolved == source or source in resolved.parents:
        raise ValueError("preflight output must be outside the source checkout")
    with path.open("xb") as stream:
        stream.write(raw)


def preflight(source, subject_path, predicate_path):
    """Create a tiny, explicitly non-SDK subject for real action ingestion."""
    source = Path(source).resolve(strict=True)
    identity = context(source)
    github_internal_parameters()
    subject_path = Path(subject_path)
    predicate_path = Path(predicate_path)
    if subject_path.resolve(strict=False) == predicate_path.resolve(strict=False):
        raise ValueError("preflight subject and predicate paths must differ")
    input_raw = encoded({"schema": "ami-rust-publisher-inputs-v1", "materials": []})
    probe = _predicate_for(identity, input_raw, [], "admission-ingestion-probe")
    predicate_raw = encoded(probe)
    _fresh_external_file(subject_path, source, PREFLIGHT_SUBJECT)
    try:
        _fresh_external_file(predicate_path, source, predicate_raw)
    except Exception:
        subject_path.unlink(missing_ok=True)
        raise
    result = {"status": "PREFLIGHT_READY_NOT_SDK_AUTHENTICATION",
              "subject_sha256": sha(PREFLIGHT_SUBJECT),
              "predicate_sha256": sha(predicate_raw),
              "source_sha": identity["source_sha"], "workflow_sha": identity["workflow_sha"],
              "run_id": identity["run_id"], "run_attempt": identity["run_attempt"]}
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with Path(output).open("a", encoding="utf-8") as stream:
            stream.write(f"subject_sha256={result['subject_sha256']}\n")
            stream.write(f"predicate_sha256={result['predicate_sha256']}\n")
    return result


def _preflight_statement(bundle_raw):
    try:
        bundle = parsed(bundle_raw)
    except (UnicodeError, ValueError) as error:
        raise ValueError("actions/attest output bundle is invalid JSON") from error
    envelope = bundle.get("dsseEnvelope") if isinstance(bundle, dict) else None
    if not isinstance(envelope, dict) or envelope.get("payloadType") != IN_TOTO_JSON:
        raise ValueError("actions/attest bundle has no in-toto DSSE envelope")
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures or any(not isinstance(row, dict) for row in signatures):
        raise ValueError("actions/attest bundle has no structurally valid DSSE signature rows")
    encoded_payload = envelope.get("payload")
    if not isinstance(encoded_payload, str) or len(encoded_payload) > 96 * 1024:
        raise ValueError("actions/attest bundle has a missing or oversized DSSE payload")
    try:
        payload = base64.b64decode(encoded_payload, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError("actions/attest bundle DSSE payload is not valid base64") from error
    if len(payload) > 64 * 1024:
        raise ValueError("actions/attest bundle DSSE statement exceeds its size limit")
    try:
        statement = parsed(payload)
    except (UnicodeError, ValueError) as error:
        raise ValueError("actions/attest DSSE statement JSON is invalid") from error
    if not isinstance(statement, dict):
        raise ValueError("actions/attest bundle DSSE payload is not an in-toto statement")
    return statement


def verify_preflight(source, subject_path, predicate_path, bundle_path, attestation_id, attestation_url,
                     expected_subject_sha256, expected_predicate_sha256):
    identity = context(source)
    subject_raw = read(subject_path, 4096)
    predicate_raw = read(predicate_path, 256 * 1024)
    bundle_raw = read(bundle_path, 128 * 1024)
    if subject_raw != PREFLIGHT_SUBJECT or sha(subject_raw) != expected_subject_sha256:
        raise ValueError("admission provenance subject differs from the generated non-SDK fixture")
    expected_predicate = encoded(_predicate_for(
        identity, encoded({"schema": "ami-rust-publisher-inputs-v1", "materials": []}),
        [], "admission-ingestion-probe"))
    if (sha(predicate_raw) != expected_predicate_sha256
            or predicate_raw != expected_predicate):
        raise ValueError("admission provenance predicate differs from its generated digest")
    statement = _preflight_statement(bundle_raw)
    expected_statement = {
        "_type": IN_TOTO_STATEMENT_V1,
        "subject": [{"name": "ami-rust-github-provenance-probe.txt",
                     "digest": {"sha256": expected_subject_sha256}}],
        "predicateType": SLSA_PREDICATE_TYPE,
        "predicate": parsed(expected_predicate),
    }
    if statement != expected_statement:
        raise ValueError("actions/attest DSSE statement differs from the exact admission probe subject, predicate, or run")
    if (not isinstance(attestation_id, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", attestation_id)
            or attestation_url != f"https://github.com/{REPO}/attestations/{attestation_id}"):
        raise ValueError("actions/attest did not return a valid persisted attestation identity")
    github = github_internal_parameters()
    bundle_base64 = base64.b64encode(bundle_raw).decode("ascii")
    return {"status": "PREFLIGHT_ATTESTATION_INGESTED_NOT_SDK_AUTHENTICATION",
            "repository": REPO, "github": github,
            "subject_sha256": sha(subject_raw), "predicate_sha256": sha(predicate_raw),
            "bundle_sha256": sha(bundle_raw), "bundle_bytes": len(bundle_raw),
            "bundle_base64_chunks": [bundle_base64[i:i + 4096]
                                     for i in range(0, len(bundle_base64), 4096)],
            "attestation_id": attestation_id, "attestation_url": attestation_url,
            "source_sha": identity["source_sha"], "workflow_sha": identity["workflow_sha"],
            "run_id": identity["run_id"], "run_attempt": identity["run_attempt"]}


def audit(source, bundle, work):
    """Reconstruct the unsigned candidate from trusted source on each signer.

    Downloading an artifact is not itself evidence of correct publisher input.
    The signer requires byte equality with its own fresh assembly before OIDC.
    """
    source = Path(source).resolve(strict=True)
    bundle = Path(bundle)
    work = Path(work)
    if work.exists() or work.is_symlink() or not work.parent.is_dir():
        raise ValueError("fresh signer audit work required")
    if work.resolve() == source or source in work.resolve().parents:
        raise ValueError("signer audit work must be outside source")
    if bundle.is_symlink() or bundle.resolve(strict=True) != bundle.absolute():
        raise ValueError("signer input root must not contain symlinks")
    if bundle == work or bundle in work.parents or work in bundle.parents:
        raise ValueError("signer input and audit work overlap")
    work.mkdir()
    payloads = {}
    for host in HOSTS:
        payload = work / host
        (payload / "native").mkdir(parents=True)
        for destination, original in (("sdk.tar.xz", "sdk.tar.xz"),
                                      ("cargo-component.tar.xz", f"cargo-{host}.tar.xz"),
                                      ("native/sha256sum.AMIRUST", "SHAUTIL")):
            (payload / destination).write_bytes(read(below(bundle, original)))
        payloads[host] = payload
    expected = work / "expected"
    # The signer reconstructs from the final bundle, which does not carry the
    # producer's potentially large diagnostic receipt. Receipt admission was
    # enforced before the publisher created that bundle.
    report = _assemble(source, payloads, expected, check_sdk_producer_receipts=False)
    expected_files = {p.relative_to(expected).as_posix() for p in expected.rglob("*") if p.is_file()}
    observed = set()
    total = 0
    for path in bundle.rglob("*"):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        name = path.relative_to(bundle).as_posix()
        if name not in expected_files or read(below(bundle, name)) != read(below(expected, name)):
            raise ValueError("signer candidate differs from independently assembled source: " + name)
        observed.add(name)
        total += info.st_size
    if observed != expected_files or total > TREE_LIMIT:
        raise ValueError("signer candidate inventory is incomplete or oversized")
    digests = {name: sha(read(below(bundle, name))) for name in SUBJECTS}
    shutil.rmtree(work)
    return {"schema": "ami-rust-signer-audit-v1", "status": "PASS_UNSIGNED_CANDIDATE_ONLY",
            "source": report["source"], "subjects": digests, "owned_audit_work_remaining_bytes": 0}


def finalize(bundle, host, gh, cosign):
    if host not in HOSTS or set(gh) != set(SUBJECTS) or set(cosign) != set(SUBJECTS):
        raise ValueError("authentication must cover exactly all three subjects")
    bundle = Path(bundle)
    release_raw = read(bundle / "release.json")
    release = parsed(release_raw)
    producer = release["producer"]
    record = {"schema": "ami-rust-authentication-v2", "manifest_sha256": sha(release_raw),
              "workflow_runs": [{"run_id": producer["run_id"], "run_attempt": producer["run_attempt"],
                                 "host_profile": host}], "gh_attestations": [], "cosign_bundles": []}
    additions = {}
    for name in SUBJECTS:
        for kind, mapping, cap in (("gh", gh, 2 * 1024**2), ("cosign", cosign, 1024**2)):
            raw = read(mapping[name], cap)
            if not isinstance(parsed(raw), dict):
                raise ValueError("authentication bundle must be a JSON object")
            destination = bundle / ".auth" / kind / (name + ".json")
            if destination.exists() or destination.is_symlink() or destination.parent.is_symlink():
                raise FileExistsError("authentication destination is not fresh")
            additions[destination] = raw
            row = {"path": name, "bundle": destination.relative_to(bundle).as_posix()}
            if kind == "gh":
                row["host_profile"] = host
                record["gh_attestations"].append(row)
            else:
                record["cosign_bundles"].append(row)
    additions[bundle / ".auth/authentication.json"] = encoded(record)
    existing = sum(path.lstat().st_size for path in bundle.rglob("*") if path.is_file())
    # Native-v2 is a new prospective format with two host binaries. The
    # immutable historical-v1 authentication profile remains unchanged.
    tree_limit = 64 * 1024**2 if release.get("schema") == "ami-rust-release-v2" else TREE_LIMIT
    if existing + sum(map(len, additions.values())) > tree_limit - 4096:
        raise ValueError("authenticated candidate exceeds retained artifact ceiling")
    for path, raw in additions.items():
        path.parent.mkdir(exist_ok=True)
        with path.open("xb") as stream:
            stream.write(raw)
    return record


def mapping(values):
    result = {}
    for value in values:
        name, path = value.split("=", 1)
        if name in result:
            raise ValueError("duplicate authentication subject")
        result[name] = Path(path)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    prepare = subs.add_parser("prepare")
    prepare.add_argument("--source", type=Path, required=True)
    prepare.add_argument("--macos", type=Path, required=True)
    prepare.add_argument("--linux", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)
    pred = subs.add_parser("predicate")
    pred.add_argument("--bundle", type=Path, required=True)
    pred.add_argument("--host", choices=HOSTS, required=True)
    pred.add_argument("--source", type=Path, required=True)
    pred.add_argument("--output", type=Path, required=True)
    inspect = subs.add_parser("audit")
    inspect.add_argument("--source", type=Path, required=True)
    inspect.add_argument("--bundle", type=Path, required=True)
    inspect.add_argument("--work", type=Path, required=True)
    probe = subs.add_parser("preflight")
    probe.add_argument("--source", type=Path, required=True)
    probe.add_argument("--subject", type=Path, required=True)
    probe.add_argument("--predicate", type=Path, required=True)
    verify_probe = subs.add_parser("verify-preflight")
    verify_probe.add_argument("--source", type=Path, required=True)
    verify_probe.add_argument("--subject", type=Path, required=True)
    verify_probe.add_argument("--predicate", type=Path, required=True)
    verify_probe.add_argument("--bundle", type=Path, required=True)
    verify_probe.add_argument("--attestation-id", required=True)
    verify_probe.add_argument("--attestation-url", required=True)
    verify_probe.add_argument("--expected-subject-sha256", required=True)
    verify_probe.add_argument("--expected-predicate-sha256", required=True)
    final = subs.add_parser("finalize")
    final.add_argument("--bundle", type=Path, required=True)
    final.add_argument("--host", choices=HOSTS, required=True)
    final.add_argument("--gh", action="append", default=[])
    final.add_argument("--cosign", action="append", default=[])
    args = parser.parse_args()
    if args.command == "prepare":
        result = assemble(args.source, {"macos-aarch64": args.macos, "linux-x86_64": args.linux}, args.output)
    elif args.command == "predicate":
        value = predicate(args.bundle, args.host, args.source)
        with args.output.open("xb") as stream:
            stream.write(encoded(value))
        result = {"predicate_sha256": sha(encoded(value))}
    elif args.command == "audit":
        result = audit(args.source, args.bundle, args.work)
        if os.environ.get("GITHUB_OUTPUT"):
            with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
                for name, key in (("release.json", "manifest"), ("sdk.tar.xz", "sdk"), ("SHAUTIL", "utility")):
                    stream.write(f"{key}={result['subjects'][name]}\n")
    elif args.command == "preflight":
        result = preflight(args.source, args.subject, args.predicate)
    elif args.command == "verify-preflight":
        result = verify_preflight(args.source, args.subject, args.predicate, args.bundle,
                                  args.attestation_id, args.attestation_url,
                                  args.expected_subject_sha256, args.expected_predicate_sha256)
    else:
        result = finalize(args.bundle, args.host, mapping(args.gh), mapping(args.cosign))
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
