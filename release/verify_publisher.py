#!/usr/bin/env python3
"""Fail-closed verification for an externally pinned ami-rust publisher policy.

This module delegates cryptographic checks to hash-pinned, offline-capable gh
and cosign CLIs. Predicate publisherPolicy values are signed workflow claims;
they are not independent Fulcio certificate claims.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import threading
import time
import tempfile
from pathlib import Path


class PublisherVerificationError(ValueError):
    """Publisher evidence or trust policy failed validation."""


POLICY_SCHEMA = "ami-rust-publisher-trust-v2"
AUTH_SCHEMA = "ami-rust-authentication-v2"
INPUTS_SCHEMA = "ami-rust-publisher-inputs-v1"
REPOSITORY = "metaneutrons/ami-rust"
WORKFLOW = ".github/workflows/sdk-qualify.yml"
SOURCE_REF = "refs/heads/main"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "https://actions.github.io/buildtypes/workflow/v1"
HOSTS = {"macos-aarch64", "linux-x86_64"}
DIRECT_SUBJECTS = {"release.json", "sdk.tar.xz", "SHAUTIL"}
INPUTS_MANIFEST = ".auth/inputs.json"
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_AUTH_JSON = 1024 * 1024
_MAX_GH_BUNDLE = 2 * 1024 * 1024
_MAX_COSIGN_BUNDLE = 1024 * 1024
_MAX_ROOT = 16 * 1024 * 1024
_MAX_TOOL = 512 * 1024 * 1024
_MAX_OUT = 4 * 1024 * 1024
_MAX_ERR = 64 * 1024
_MAX_FILES = 512
_MAX_TREE = 32 * 1024 * 1024
_TOTAL_SECONDS = 300
_COMMAND_SECONDS = 60


def _fail(message):
    raise PublisherVerificationError(message)


def _strict_json(raw: bytes, label: str):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                _fail(f"duplicate JSON key in {label}: {key}")
            value[key] = item
        return value

    def constant(value):
        _fail(f"invalid JSON constant in {label}: {value}")

    def finite_float(value):
        number = float(value)
        if not math.isfinite(number):
            _fail(f"nonfinite JSON exponent in {label}")
        return number

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=constant, parse_float=finite_float)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublisherVerificationError(f"invalid UTF-8 JSON in {label}: {error}") from error


def _read_regular(path: Path, limit: int, label: str) -> bytes:
    try:
        info = path.lstat()
    except OSError as error:
        raise PublisherVerificationError(f"missing {label}: {error}") from error
    if not stat.S_ISREG(info.st_mode) or info.st_size < 0 or info.st_size > limit:
        _fail(f"{label} must be a bounded regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise PublisherVerificationError(f"cannot open {label}: {error}") from error
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_ino != info.st_ino or opened.st_dev != info.st_dev:
            _fail(f"{label} changed while opening")
        result = bytearray()
        while len(result) <= limit:
            block = os.read(fd, min(65536, limit + 1 - len(result)))
            if not block:
                break
            result.extend(block)
        if len(result) > limit or len(result) != opened.st_size:
            _fail(f"{label} changed or exceeds its size limit")
        return bytes(result)
    finally:
        os.close(fd)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha_file(path: Path, limit: int, label: str) -> str:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as stream:
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > limit:
                    _fail(f"oversized {label}")
                digest.update(block)
    except OSError as error:
        raise PublisherVerificationError(f"cannot hash {label}: {error}") from error
    return digest.hexdigest()


def _rel_path(value, label):
    if (not isinstance(value, str) or not value or len(value) > 240
            or value.startswith("/") or "\\" in value or ":" in value
            or any(ord(c) < 32 or ord(c) >= 127 for c in value)):
        _fail(f"invalid {label}")
    parts = value.split("/")
    if len(parts) > 24 or any(p in ("", ".", "..") for p in parts):
        _fail(f"unsafe {label}: {value}")
    if any(not re.fullmatch(r"[A-Za-z0-9._+-]{1,120}", p) or p.endswith(".") for p in parts):
        _fail(f"nonportable {label}: {value}")
    return value


def _inside(root: Path, relative: str, label: str) -> Path:
    _rel_path(relative, label)
    path = root
    for part in relative.split("/"):
        path = path / part
        try:
            info = path.lstat()
        except OSError as error:
            raise PublisherVerificationError(f"missing {label}: {relative}") from error
        if stat.S_ISLNK(info.st_mode):
            _fail(f"symlink forbidden in {label}: {relative}")
    if not stat.S_ISREG(path.lstat().st_mode):
        _fail(f"{label} is not a regular file: {relative}")
    return path


def _scan_bundle(root: Path, allowed_dirs):
    try:
        root_info = root.lstat()
    except OSError as error:
        raise PublisherVerificationError(f"missing bundle directory: {error}") from error
    if not stat.S_ISDIR(root_info.st_mode):
        _fail("bundle must be a real directory")
    found = set()
    count = 0
    total = 0

    def walk(directory: Path, prefix: str):
        nonlocal count, total
        try:
            entries = list(os.scandir(directory))
        except OSError as error:
            raise PublisherVerificationError(f"cannot inspect bundle: {error}") from error
        for entry in entries:
            rel = f"{prefix}/{entry.name}" if prefix else entry.name
            _rel_path(rel, "bundle entry")
            info = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                _fail(f"bundle symlink forbidden: {rel}")
            if stat.S_ISDIR(info.st_mode):
                if rel not in allowed_dirs:
                    _fail(f"unlisted bundle directory: {rel}")
                walk(Path(entry.path), rel)
            elif stat.S_ISREG(info.st_mode):
                count += 1
                total += info.st_size
                if count > _MAX_FILES or total > _MAX_TREE:
                    _fail("authentication bundle exceeds file or size limits")
                found.add(rel)
            else:
                _fail(f"non-regular bundle entry: {rel}")

    walk(root, "")
    return found


def _policy(policy):
    fields = {"schema", "repository", "workflow", "workflow_sha", "source_sha",
              "source_ref", "oidc_issuer", "cert_identity",
              "inputs_manifest_sha256", "allowed_host_profiles", "gh", "cosign",
              "gh_trusted_roots", "cosign_trusted_root"}
    if not isinstance(policy, dict) or set(policy) != fields:
        _fail("publisher policy has unknown or missing fields")
    if (policy["schema"] != POLICY_SCHEMA or policy["repository"] != REPOSITORY
            or policy["workflow"] != WORKFLOW or policy["source_ref"] != SOURCE_REF
            or policy["oidc_issuer"] != OIDC_ISSUER):
        _fail("publisher policy constants do not match this verifier")
    for field in ("workflow_sha", "source_sha"):
        if not isinstance(policy[field], str) or not _HEX40.fullmatch(policy[field]):
            _fail(f"invalid policy {field}")
    if (not isinstance(policy["inputs_manifest_sha256"], str)
            or not _HEX64.fullmatch(policy["inputs_manifest_sha256"])):
        _fail("invalid policy inputs_manifest_sha256")
    allowed_hosts = policy["allowed_host_profiles"]
    if (not isinstance(allowed_hosts, list) or not allowed_hosts
            or any(not isinstance(host, str) for host in allowed_hosts)
            or len(set(allowed_hosts)) != len(allowed_hosts)
            or not set(allowed_hosts) <= HOSTS):
        _fail("invalid allowed_host_profiles policy")
    identity = f"https://github.com/{REPOSITORY}/{WORKFLOW}@{SOURCE_REF}"
    if policy["cert_identity"] != identity:
        _fail("publisher policy certificate identity mismatch")
    result = dict(policy)
    for field in ("gh", "cosign", "gh_trusted_roots", "cosign_trusted_root"):
        entry = policy[field]
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            _fail(f"invalid pinned {field} entry")
        if not isinstance(entry["sha256"], str) or not _HEX64.fullmatch(entry["sha256"]):
            _fail(f"invalid {field} SHA-256")
        raw_path = entry["path"]
        if not isinstance(raw_path, str) or not Path(raw_path).is_absolute() or os.path.normpath(raw_path) != raw_path:
            _fail(f"{field} path must be a normalized absolute path")
        try:
            resolved = Path(raw_path).resolve(strict=True)
        except OSError as error:
            raise PublisherVerificationError(f"missing pinned {field}: {error}") from error
        info = resolved.stat()
        if not stat.S_ISREG(info.st_mode):
            _fail(f"pinned {field} must resolve to a regular file")
        if field in ("gh", "cosign") and (not os.access(resolved, os.X_OK) or not info.st_mode & 0o111):
            _fail(f"pinned {field} is not executable")
        cap = _MAX_TOOL if field in ("gh", "cosign") else _MAX_ROOT
        if _sha_file(resolved, cap, field) != entry["sha256"]:
            _fail(f"pinned {field} SHA-256 mismatch")
        result[field] = {"path": str(resolved), "sha256": entry["sha256"]}
    ghroot = _read_regular(Path(result["gh_trusted_roots"]["path"]), _MAX_ROOT, "GitHub trusted roots")
    lines = [line for line in ghroot.splitlines() if line.strip()]
    if not lines:
        _fail("GitHub trusted roots file is empty")
    for index, line in enumerate(lines, 1):
        root_value = _strict_json(line, f"GitHub trusted root line {index}")
        if not isinstance(root_value, dict):
            _fail("GitHub trusted root line must be an object")
    cosroot = _strict_json(_read_regular(Path(result["cosign_trusted_root"]["path"]), _MAX_ROOT,
                                         "Sigstore trusted root"), "Sigstore trusted root")
    if not isinstance(cosroot, dict):
        _fail("Sigstore trusted root must be an object")
    return result


def _inputs_manifest(root: Path, policy: dict):
    raw = _read_regular(_inside(root, INPUTS_MANIFEST, "pinned inputs manifest"),
                        _MAX_AUTH_JSON, "pinned inputs manifest")
    if _sha256(raw) != policy["inputs_manifest_sha256"]:
        _fail("inputs manifest digest does not match trusted policy")
    value = _strict_json(raw, "pinned inputs manifest")
    if not isinstance(value, dict) or set(value) != {"schema", "materials"}:
        _fail("pinned inputs manifest has unknown or missing fields")
    if value["schema"] != INPUTS_SCHEMA:
        _fail("pinned inputs manifest schema mismatch")
    materials = value["materials"]
    if not isinstance(materials, list) or not materials or len(materials) > 512:
        _fail("pinned inputs manifest must contain 1 to 512 materials")
    seen = set()
    result = []
    for row in materials:
        if not isinstance(row, dict) or set(row) != {"uri", "digest"}:
            _fail("invalid pinned material row")
        uri, digests = row["uri"], row["digest"]
        if (not isinstance(uri, str) or not uri or len(uri) > 2048
                or any(ord(c) <= 32 or ord(c) >= 127 for c in uri)
                or not uri.startswith(("https://", "git+https://", "oci://"))):
            _fail("invalid pinned material URI")
        if uri in seen:
            _fail(f"duplicate pinned material URI: {uri}")
        seen.add(uri)
        if not isinstance(digests, dict) or len(digests) != 1:
            _fail(f"invalid pinned material digest: {uri}")
        algorithm, digest = next(iter(digests.items()))
        if (algorithm == "sha256" and isinstance(digest, str) and _HEX64.fullmatch(digest)):
            pass
        elif algorithm == "gitCommit" and isinstance(digest, str) and _HEX40.fullmatch(digest):
            pass
        else:
            _fail(f"unsupported or invalid pinned material digest: {uri}")
        result.append({"uri": uri, "digest": {algorithm: digest}})
    if any(row["uri"] == f"git+https://github.com/{REPOSITORY}@{SOURCE_REF}" for row in result):
        _fail("main repository source must be represented by the exact source policy pin")
    return raw, result


def _inventory(manifest):
    if not isinstance(manifest, dict) or not isinstance(manifest.get("assets"), list):
        _fail("manifest must contain an assets array")
    if manifest.get("qualification_only") is not False:
        _fail("production publisher verification requires qualification_only=false")
    assets = {}
    folded = set()
    total = 0
    for row in manifest["assets"]:
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}:
            _fail("invalid manifest asset row")
        path = _rel_path(row["path"], "manifest asset path")
        if (path in {"release.json", ".auth"} or path.startswith(".auth/")
                or path in assets or path.casefold() in folded):
            _fail(f"duplicate or reserved manifest asset: {path}")
        size, digest = row["bytes"], row["sha256"]
        if type(size) is not int or size < 0 or size > 16 * 1024 * 1024:
            _fail(f"invalid manifest asset size: {path}")
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            _fail(f"invalid manifest asset digest: {path}")
        total += size
        if total > 32 * 1024 * 1024:
            _fail("manifest assets exceed total size limit")
        assets[path] = (size, digest)
        folded.add(path.casefold())
    if not assets:
        _fail("manifest asset inventory is empty")
    for path in assets:
        parts = path.split("/")
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index])
            if parent.casefold() in folded:
                _fail(f"manifest file/directory path conflict: {path}")
    return assets


def _auth_metadata(root: Path, manifest_raw: bytes, assets: dict, policy: dict):
    auth_dir = root / ".auth"
    try:
        auth_info = auth_dir.lstat()
    except OSError as error:
        raise PublisherVerificationError("missing .auth directory") from error
    if not stat.S_ISDIR(auth_info.st_mode):
        _fail(".auth must be a real directory")
    auth_path = auth_dir / "authentication.json"
    auth = _strict_json(_read_regular(auth_path, _MAX_AUTH_JSON, "authentication metadata"),
                        "authentication metadata")
    if not isinstance(auth, dict) or set(auth) != {"schema", "manifest_sha256", "workflow_runs",
                                                    "gh_attestations", "cosign_bundles"}:
        _fail("authentication metadata has unknown or missing fields")
    if auth["schema"] != AUTH_SCHEMA or auth["manifest_sha256"] != _sha256(manifest_raw):
        _fail("authentication metadata does not bind this manifest")
    if not isinstance(auth["workflow_runs"], list) or len(auth["workflow_runs"]) != 1:
        _fail("exactly one authenticated workflow run is required per host bundle")
    runs = {}
    run_ids = set()
    for row in auth["workflow_runs"]:
        keys = {"run_id", "run_attempt", "host_profile"}
        if not isinstance(row, dict) or set(row) != keys:
            _fail("invalid workflow run metadata")
        rid, attempt, host = row["run_id"], row["run_attempt"], row["host_profile"]
        if type(rid) is not int or rid <= 0 or type(attempt) is not int or attempt <= 0:
            _fail("invalid GitHub workflow run ID or attempt")
        if (not isinstance(host, str) or host not in policy["allowed_host_profiles"]
                or host in runs or rid in run_ids):
            _fail("workflow run host is not allowed or run identity is duplicated")
        runs[host] = {"run_id": rid, "run_attempt": attempt}
        run_ids.add(rid)
    if len(runs) != 1:
        _fail("one allowed host profile must be selected")

    rows = auth["gh_attestations"]
    required_gh = set(DIRECT_SUBJECTS)
    if not {"sdk.tar.xz", "SHAUTIL"} <= set(assets):
        _fail("required GH/Cosign subjects are absent from manifest")
    if not isinstance(rows, list) or len(rows) != len(required_gh):
        _fail("GitHub mappings must cover exactly the three authenticated subjects")
    mapped = {}
    bundle_paths = {}
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "host_profile", "bundle"}:
            _fail("invalid GitHub attestation mapping")
        path, host, bundle = row["path"], row["host_profile"], row["bundle"]
        if not isinstance(path, str) or not isinstance(host, str) or not isinstance(bundle, str):
            _fail("GitHub attestation mapping fields must be strings")
        if path not in required_gh:
            _fail(f"GitHub attestation names an unexpected subject: {path}")
        if not isinstance(host, str) or host not in runs or (path, host) in seen:
            _fail("duplicate or invalid GitHub attestation mapping")
        if not isinstance(bundle, str) or not bundle.startswith(".auth/gh/") or not bundle.endswith(".json"):
            _fail("GitHub attestation bundle must be under .auth/gh and end in .json")
        _rel_path(bundle, "GitHub attestation bundle path")
        seen.add((path, host))
        mapped.setdefault(host, set()).add(path)
        bundle_paths[path] = bundle
    selected_host = next(iter(runs))
    if mapped[selected_host] != required_gh or len(mapped) != 1:
        _fail("the selected host run must attest exactly release.json, sdk.tar.xz and SHAUTIL")

    cosign_rows = auth["cosign_bundles"]
    required_cosign = set(DIRECT_SUBJECTS)
    if not isinstance(cosign_rows, list) or len(cosign_rows) != len(required_cosign):
        _fail("Cosign bundle mapping must cover exactly the required subjects")
    cosign = {}
    for row in cosign_rows:
        if not isinstance(row, dict) or set(row) != {"path", "bundle"}:
            _fail("invalid Cosign bundle mapping")
        path, bundle = row["path"], row["bundle"]
        if not isinstance(path, str) or not isinstance(bundle, str):
            _fail("Cosign bundle mapping fields must be strings")
        if path not in required_cosign or path in cosign:
            _fail("unexpected or duplicate Cosign subject")
        if path != "release.json" and path not in assets:
            _fail(f"Cosign subject is absent from manifest: {path}")
        if not isinstance(bundle, str) or not bundle.startswith(".auth/cosign/") or not bundle.endswith(".json"):
            _fail("Cosign bundle must be under .auth/cosign and end in .json")
        _rel_path(bundle, "Cosign bundle path")
        cosign[path] = bundle
    if set(cosign) != required_cosign:
        _fail("incomplete Cosign subjects")
    all_bundle_paths = set(bundle_paths.values()) | set(cosign.values())
    if len(all_bundle_paths) != 6 or len({p.casefold() for p in all_bundle_paths}) != 6:
        _fail("three distinct GH and three distinct Cosign bundle paths are required")
    expected_files = {"release.json", ".auth/authentication.json", INPUTS_MANIFEST} | set(assets) | all_bundle_paths
    allowed_dirs = set()
    for rel in expected_files:
        parts = rel.split("/")
        for index in range(1, len(parts)):
            allowed_dirs.add("/".join(parts[:index]))
    actual_files = _scan_bundle(root, allowed_dirs)
    if actual_files != expected_files:
        missing, extra = sorted(expected_files - actual_files), sorted(actual_files - expected_files)
        _fail(f"bundle file set mismatch (missing={missing[:3]}, extra={extra[:3]})")
    return auth, runs, mapped, bundle_paths, cosign


def _read_bundle(root, rel, kind):
    limit = _MAX_GH_BUNDLE if kind == "gh" else _MAX_COSIGN_BUNDLE
    path = _inside(root, rel, f"{kind} bundle")
    raw = _read_regular(path, limit, f"{kind} bundle {rel}")
    parsed = _strict_json(raw, f"{kind} bundle {rel}")
    if not isinstance(parsed, dict):
        _fail(f"{kind} bundle must be a JSON object")
    return path


def _run_command(argv, *, deadline, env):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        _fail("total publisher verification timeout")
    timeout = min(_COMMAND_SECONDS, remaining)
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=env, close_fds=True)
    except OSError as error:
        raise PublisherVerificationError(f"cannot execute pinned verifier: {error}") from error
    outputs = {"out": bytearray(), "err": bytearray()}
    overflow = threading.Event()
    reader_errors = []
    timed_out = False

    def drain(name, pipe, cap):
        try:
            while True:
                block = pipe.read(65536)
                if not block:
                    return
                target = outputs[name]
                if len(target) + len(block) > cap:
                    overflow.set()
                    try:
                        process.kill()
                    except OSError:
                        pass
                    return
                target.extend(block)
        except OSError as error:
            reader_errors.append(error)

    threads = [threading.Thread(target=drain, args=("out", process.stdout, _MAX_OUT), daemon=True),
               threading.Thread(target=drain, args=("err", process.stderr, _MAX_ERR), daemon=True)]
    for thread in threads:
        thread.start()
    started = time.monotonic()
    while process.poll() is None:
        if overflow.is_set():
            break
        if time.monotonic() - started >= timeout:
            timed_out = True
            try:
                process.kill()
            except OSError:
                pass
            break
        time.sleep(0.02)
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    for thread in threads:
        thread.join(timeout=2)
    for pipe in (process.stdout, process.stderr):
        try:
            pipe.close()
        except OSError:
            pass
    if overflow.is_set():
        _fail("pinned verifier output exceeded its limit")
    if timed_out or time.monotonic() - started > timeout:
        _fail("pinned verifier command timed out")
    if reader_errors:
        _fail(f"could not read pinned verifier output: {reader_errors[0]}")
    if process.returncode != 0:
        detail = outputs["err"].decode("utf-8", "replace")[:1000]
        _fail(f"pinned verifier rejected evidence ({process.returncode}): {detail}")
    return bytes(outputs["out"])


def _statement_result(raw, label):
    value = _strict_json(raw, label)
    if not isinstance(value, list) or len(value) != 1:
        _fail(f"{label} must contain exactly one verification result")
    item = value[0]
    if not isinstance(item, dict) or set(item) != {"attestation", "verificationResult"}:
        _fail(f"malformed {label}")
    if not isinstance(item["attestation"], dict):
        _fail(f"{label} lacks the verified bundle")
    verification = item["verificationResult"]
    if not isinstance(verification, dict):
        _fail(f"malformed {label} verificationResult")
    statement = verification.get("statement")
    signature = verification.get("signature")
    if not isinstance(statement, dict) or not isinstance(signature, dict) or not isinstance(signature.get("certificate"), dict):
        _fail(f"{label} lacks verified certificate or statement")
    return statement


def _check_predicate(statement, *, policy, run, host, subject_paths, manifest,
                     input_materials):
    if statement.get("predicateType") != PREDICATE_TYPE:
        _fail("GitHub attestation predicate type mismatch")
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        _fail("attestation statement has no subjects")
    if len(subject_paths) != 1:
        _fail("each GH bundle must authenticate exactly one subject")
    expected = {}
    for path in subject_paths:
        expected[path] = manifest[path]
    actual = {}
    for row in subjects:
        if not isinstance(row, dict) or set(row) != {"name", "digest"}:
            _fail("invalid SLSA subject")
        name, digests = row["name"], row["digest"]
        if not isinstance(name, str) or not isinstance(digests, dict) or set(digests) != {"sha256"}:
            _fail("invalid SLSA subject digest")
        digest = digests["sha256"]
        if not isinstance(digest, str) or not _HEX64.fullmatch(digest) or name in actual:
            _fail("duplicate or invalid SLSA subject")
        actual[name] = digest
    if actual != {path: value[1] for path, value in expected.items()}:
        _fail(f"SLSA subject set mismatch for {host}")

    predicate = statement.get("predicate")
    if not isinstance(predicate, dict) or set(predicate) != {"buildDefinition", "runDetails"}:
        _fail("invalid SLSA provenance predicate")
    definition = predicate["buildDefinition"]
    run_details = predicate["runDetails"]
    if not isinstance(definition, dict) or definition.get("buildType") != BUILD_TYPE:
        _fail("SLSA build type mismatch")
    external = definition.get("externalParameters")
    expected_workflow = {"repository": f"https://github.com/{REPOSITORY}",
                         "path": WORKFLOW, "ref": SOURCE_REF}
    if not isinstance(external, dict) or external.get("workflow") != expected_workflow:
        _fail("SLSA workflow parameters mismatch")
    dependencies = definition.get("resolvedDependencies")
    expected_deps = [{"uri": f"git+https://github.com/{REPOSITORY}@{SOURCE_REF}",
                      "digest": {"gitCommit": policy["source_sha"]}}, *input_materials]
    if (not isinstance(dependencies, list) or len(dependencies) != len(expected_deps)
            or set(map(_canonical, dependencies)) != set(map(_canonical, expected_deps))):
        _fail("SLSA resolved dependencies do not match the pinned repository source and input manifest")
    if not isinstance(run_details, dict):
        _fail("invalid SLSA runDetails")
    metadata = run_details.get("metadata")
    if not isinstance(metadata, dict):
        _fail("SLSA run metadata is missing")
    invocation = f"https://github.com/{REPOSITORY}/actions/runs/{run['run_id']}/attempts/{run['run_attempt']}"
    if metadata.get("invocationId") != invocation:
        _fail("SLSA invocationId does not match authentication metadata")
    publisher = metadata.get("publisherPolicy")
    expected_publisher = {
        "environment": "release", "runnerEnvironment": "github-hosted",
        "repository": REPOSITORY, "workflow": WORKFLOW,
        "workflowSha": policy["workflow_sha"], "sourceSha": policy["source_sha"],
        "sourceRef": SOURCE_REF,
        "inputsManifestSha256": policy["inputs_manifest_sha256"],
        "hostProfile": host,
    }
    if publisher != expected_publisher:
        _fail("signed publisherPolicy does not match trusted producer policy")


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def verify(bundle: Path, manifest: dict, policy: dict) -> dict:
    """Verify bundle subjects and provenance under externally pinned policy.

    `manifest` must be the strict parsed release.json object. This function
    verifies bytes and metadata only; it does not publish, install, or execute
    SDK content. GH's custom root and Cosign's trusted root are mandatory.
    """
    start = time.monotonic()
    deadline = start + _TOTAL_SECONDS
    policy = _policy(policy)
    root = Path(bundle)
    if not root.is_absolute():
        _fail("bundle path must be absolute")
    try:
        if not stat.S_ISDIR(root.lstat().st_mode):
            _fail("bundle path must be a real directory, not a symlink")
        root = root.resolve(strict=True)
    except OSError as error:
        raise PublisherVerificationError(f"invalid bundle path: {error}") from error
    for field in ("gh", "cosign", "gh_trusted_roots", "cosign_trusted_root"):
        pinned = Path(policy[field]["path"])
        if pinned == root or root in pinned.parents:
            _fail("publisher tools and trust roots must be external to the bundle")
    raw_manifest = _read_regular(root / "release.json", 4 * 1024 * 1024, "release manifest")
    parsed_manifest = _strict_json(raw_manifest, "release manifest")
    if parsed_manifest != manifest:
        _fail("supplied manifest differs from bundle release.json")
    assets = _inventory(manifest)
    auth, runs, mapped, gh_paths, cosign_paths = _auth_metadata(root, raw_manifest, assets, policy)
    _, input_materials = _inputs_manifest(root, policy)

    actual_paths = {"release.json": (len(raw_manifest), _sha256(raw_manifest)), **assets}
    for rel, (size, digest) in actual_paths.items():
        path = _inside(root, rel, "manifest payload")
        if path.stat().st_size != size or _sha_file(path, 16 * 1024 * 1024, rel) != digest:
            _fail(f"manifest payload digest or size mismatch: {rel}")

    # Verify pinned tool and root bytes once before any subprocess invocation.
    try:
        home = Path(tempfile.mkdtemp(prefix="ami-rust-verify-"))
    except OSError as error:
        raise PublisherVerificationError(f"cannot create isolated verifier home: {error}") from error
    gh_config = home / "gh"
    env = {"HOME": str(home), "GH_CONFIG_DIR": str(gh_config), "PATH": os.defpath,
           "LC_ALL": "C", "LANG": "C", "GH_PROMPT_DISABLED": "1", "NO_COLOR": "1",
           "COSIGN_EXPERIMENTAL": "0"}
    try:
        gh_config.mkdir(mode=0o700)
        for host in sorted(runs):
            for subject in sorted(mapped[host]):
                gh_bundle = _read_bundle(root, gh_paths[subject], "gh")
                file_path = _inside(root, subject, "GH attestation subject")
                command = [policy["gh"]["path"], "attestation", "verify", str(file_path),
                           "--repo", REPOSITORY, "--bundle", str(gh_bundle),
                           "--custom-trusted-root", policy["gh_trusted_roots"]["path"],
                           "--signer-workflow", f"{REPOSITORY}/{WORKFLOW}",
                           "--signer-digest", policy["workflow_sha"],
                           "--source-digest", policy["source_sha"], "--source-ref", SOURCE_REF,
                           "--deny-self-hosted-runners",
                           "--predicate-type", PREDICATE_TYPE,
                           "--cert-identity", policy["cert_identity"],
                           "--cert-oidc-issuer", policy["oidc_issuer"], "--format=json"]
                output = _run_command(command, deadline=deadline, env=env)
                statement = _statement_result(output, "gh attestation verify JSON")
                _check_predicate(statement, policy=policy, run=runs[host], host=host,
                                 subject_paths={subject}, manifest={**assets, "release.json": (len(raw_manifest), _sha256(raw_manifest))},
                                 input_materials=input_materials)

        for subject in ("release.json", "sdk.tar.xz", "SHAUTIL"):
            bundle_path = _read_bundle(root, cosign_paths[subject], "cosign")
            file_path = _inside(root, subject, "Cosign subject")
            command = [policy["cosign"]["path"], "verify-blob", str(file_path),
                       "--bundle", str(bundle_path), "--trusted-root",
                       policy["cosign_trusted_root"]["path"],
                       "--certificate-identity", policy["cert_identity"],
                       "--certificate-oidc-issuer", policy["oidc_issuer"],
                       "--certificate-github-workflow-repository", REPOSITORY,
                       "--certificate-github-workflow-ref", SOURCE_REF,
                       "--certificate-github-workflow-sha", policy["workflow_sha"],
                       "--certificate-github-workflow-trigger", "workflow_dispatch"]
            _run_command(command, deadline=deadline, env=env)
    finally:
        # Cleanup is part of successful verification; failures cannot be hidden.
        shutil.rmtree(home)

    return {
        "schema": "ami-rust-publisher-verification-v2", "verified": True,
        "repository": REPOSITORY, "workflow": WORKFLOW,
        "workflowSha": policy["workflow_sha"], "sourceSha": policy["source_sha"],
        "sourceRef": SOURCE_REF, "manifestSha256": _sha256(raw_manifest),
        "workflowRuns": [{"runId": runs[h]["run_id"], "runAttempt": runs[h]["run_attempt"],
                           "hostProfile": h} for h in sorted(runs)],
        "attestedSubjects": sorted(DIRECT_SUBJECTS),
        "manifestBoundAssets": sorted(assets),
        "cosignSubjects": sorted(DIRECT_SUBJECTS),
        "publisherPolicyEvidence": (
            "environment and runnerEnvironment are signed SLSA predicate claims verified under the exact pinned workflow SHA; "
            "they are not independent Fulcio certificate fields"),
        "verificationMode": "offline pinned GH bundle/custom root and Cosign bundle/trusted root",
        "elapsedSeconds": round(time.monotonic() - start, 3),
    }
