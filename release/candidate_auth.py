#!/usr/bin/env python3
"""Prepare and verify an outer release candidate without making an R1 decision.

The inner Linux bundle is authenticated with the production publisher verifier
before it is packed. Outer GitHub attestations are verified one subject at a
time, and Cosign verifies only the payload and transport signatures. A
successful report means outer cryptographic verification only; acceptance and
publication remain separate decisions.
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
import time
from types import ModuleType
from typing import Any, Callable


SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parent.parent
HOST = "linux-x86_64"
PREPARED_SCHEMA = "ami-rust-outer-candidate-preparation-v1"
PREPARED_STATUS = "OUTER_CANDIDATE_PREPARED_SIGNING_REQUIRED_NOT_R1_ACCEPTED"
VERIFICATION_SCHEMA = "ami-rust-outer-candidate-verification-v1"
VERIFIED_STATUS = "OUTER_CRYPTO_VERIFIED_NOT_R1_ACCEPTED"
FAILED_STATUS = "OUTER_VERIFICATION_FAILED"
MAX_CANDIDATE_PROOF_BYTES = 96 * 1024 * 1024
MAX_PREDICATE_BYTES = 1024 * 1024
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX40 = re.compile(r"[0-9a-f]{40}\Z")


def _load_sibling(filename: str, module_name: str) -> ModuleType:
    path = SCRIPT.with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load trusted release helper " + filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


ci_verify = _load_sibling("ci_verify.py", "_ami_rust_outer_ci_verify")
stage_candidate = _load_sibling("stage_candidate.py", "_ami_rust_outer_stage_candidate")
verifier = _load_sibling("verify_publisher.py", "_ami_rust_outer_verify_publisher")
ci_auth = ci_verify.ci_auth


class CandidateAuthenticationError(ValueError):
    """Outer candidate evidence did not satisfy the protected-source policy."""


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _safe_directory(path: Path, label: str, *, fresh: bool = False) -> Path:
    value = Path(path)
    if not value.is_absolute() or value != Path(os.path.abspath(value)):
        raise CandidateAuthenticationError(label + " must be an absolute normalized path")
    try:
        resolved = value.resolve(strict=not fresh)
        info = value.lstat()
    except FileNotFoundError:
        if fresh:
            parent = value.parent.resolve(strict=True)
            parent_info = value.parent.lstat()
            if parent != value.parent or not stat.S_ISDIR(parent_info.st_mode):
                raise CandidateAuthenticationError(label + " parent must be a real directory")
            return value
        raise CandidateAuthenticationError(label + " must be an existing real directory")
    except OSError as error:
        raise CandidateAuthenticationError(label + " could not be inspected") from error
    if fresh:
        raise CandidateAuthenticationError(label + " must be fresh")
    if resolved != value or not stat.S_ISDIR(info.st_mode):
        raise CandidateAuthenticationError(label + " must be a real directory without symlink components")
    return value


def _safe_regular(path: Path, label: str, limit: int) -> bytes:
    value = Path(path)
    if not value.is_absolute() or value.resolve(strict=True) != value:
        raise CandidateAuthenticationError(label + " must be an absolute path without symlink components")
    try:
        return verifier._read_regular(value, limit, label)
    except (OSError, verifier.PublisherVerificationError) as error:
        raise CandidateAuthenticationError(str(error)) from error


def _require_disjoint(named_paths: dict[str, Path]) -> None:
    rows = list(named_paths.items())
    for index, (left_name, left) in enumerate(rows):
        for right_name, right in rows[index + 1:]:
            if left == right or left in right.parents or right in left.parents:
                raise CandidateAuthenticationError(left_name + " and " + right_name + " must be separate")


def _tree_inventory(root: Path, *, limit: int) -> dict[str, tuple[int, str]]:
    """Inventory a flat or nested artifact tree without following links."""
    directory = _safe_directory(root, "artifact directory")
    rows: dict[str, tuple[int, str]] = {}
    total = 0
    for path in sorted(directory.rglob("*")):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise CandidateAuthenticationError("artifact contains a link or special file")
        relative = path.relative_to(directory).as_posix()
        raw = _safe_regular(path, "artifact file " + relative, limit)
        total += len(raw)
        if total > limit:
            raise CandidateAuthenticationError("candidate and proof artifact exceeds 96 MiB")
        rows[relative] = (len(raw), _sha256(raw))
    return rows


def _tree_bytes(root: Path, *, limit: int) -> int:
    return sum(size for size, _digest in _tree_inventory(root, limit=limit).values())


def _validate_managed_roots(work: Path, metadata: Path, python_root: Path) -> None:
    """Check the bootstrapped work/runtime roots while allowing artifact metadata below output."""
    for path, label in ((work, "trusted verifier work"), (metadata, "candidate metadata"),
                        (python_root, "Python bootstrap root")):
        _safe_directory(path, label)
        if path.resolve().is_relative_to(ROOT.resolve()):
            raise CandidateAuthenticationError(label + " must be outside the protected source checkout")
        info = path.lstat()
        if info.st_uid != os.getuid():
            raise CandidateAuthenticationError(label + " must belong to the current workflow user")
    if (work.resolve().parent != python_root.resolve().parent
            or work.resolve() == python_root.resolve()
            or work.resolve() == metadata.resolve()
            or python_root.resolve() == metadata.resolve()
            or work.resolve() in metadata.resolve().parents
            or metadata.resolve() in work.resolve().parents
            or python_root.resolve() in metadata.resolve().parents
            or metadata.resolve() in python_root.resolve().parents):
        raise CandidateAuthenticationError("work, Python bootstrap and artifact metadata roots must be separate")
    for path, label in ((work, "trusted verifier work"), (metadata, "candidate metadata")):
        if stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise CandidateAuthenticationError(label + " must be a private directory")


def _write_new_file(directory: Path, name: str, raw: bytes) -> Path:
    root = _safe_directory(directory, "artifact directory")
    if Path(name).name != name or name in {"", ".", ".."}:
        raise CandidateAuthenticationError("invalid artifact filename")
    path = root / name
    if path.exists() or path.is_symlink():
        raise CandidateAuthenticationError("artifact destination must be fresh: " + name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as error:
        raise CandidateAuthenticationError("cannot create artifact file " + name) from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise CandidateAuthenticationError("artifact file is linked or not regular: " + name)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("short artifact write")
            view = view[count:]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            path.unlink()
        except OSError:
            pass
        raise
    else:
        os.close(fd)
    return path


def _write_nested_new_file(root: Path, relative: str, raw: bytes) -> Path:
    parts = relative.split("/")
    if len(parts) < 2 or any(part in {"", ".", ".."} for part in parts):
        raise CandidateAuthenticationError("invalid nested artifact path")
    parent = root
    for part in parts[:-1]:
        parent = parent / part
        try:
            parent.mkdir(mode=0o700)
        except FileExistsError:
            info = parent.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise CandidateAuthenticationError("nested artifact path contains a link or non-directory")
    return _write_new_file(parent, parts[-1], raw)


def _write_report(metadata: Path, report: dict[str, Any], candidate: Path) -> None:
    raw = _canonical_json(report)
    if len(raw) > MAX_PREDICATE_BYTES:
        raise CandidateAuthenticationError("verification report exceeds its size limit")
    artifact_bytes = (_tree_bytes(candidate, limit=MAX_CANDIDATE_PROOF_BYTES)
                      + _tree_bytes(metadata, limit=MAX_CANDIDATE_PROOF_BYTES)
                      + len(raw))
    if artifact_bytes > MAX_CANDIDATE_PROOF_BYTES:
        raise CandidateAuthenticationError("candidate and proof artifact exceeds 96 MiB including its report")
    _write_new_file(metadata, "outer-verification.json", raw)


def _validate_tool_receipt(work: Path, metadata: Path, python_root: Path,
                           identity: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], Path]:
    host = ci_verify.host_identity()
    if host != HOST:
        raise CandidateAuthenticationError("outer release candidate authentication requires Linux x86-64")
    _validate_managed_roots(work, metadata, python_root)
    executable, python_receipt = ci_verify.ci_sdk.verify_python_bootstrap(python_root, host)
    manifest_path = ROOT / "release/ci-auth-tools.json"
    manifest = ci_verify.strict_json(manifest_path, 1024 * 1024)
    pins = ci_verify.validate_tool_manifest(manifest, host)
    _safe_directory(work / "tools", "pinned verifier tools")
    _safe_directory(work / "trust", "pinned verifier trust roots")
    receipt = ci_verify.strict_json(metadata / "tool-bootstrap.json", 256 * 1024)
    expected_fields = {"schema", "status", "host", "source_commit", "tools_manifest_sha256",
                       "python_bootstrap", "tools", "roots", "commands", "budgets", "claim"}
    if set(receipt) != expected_fields:
        raise CandidateAuthenticationError("pinned verifier tool receipt has unknown or missing fields")
    if (receipt.get("schema") != ci_verify.TOOL_RECEIPT_SCHEMA
            or receipt.get("status") != "PINNED_VERIFIER_TOOLS_READY"
            or receipt.get("host") != host
            or receipt.get("source_commit") != identity["source_sha"]
            or receipt.get("tools_manifest_sha256") != ci_verify.sha256(manifest_path)
            or receipt.get("python_bootstrap") != python_receipt):
        raise CandidateAuthenticationError("pinned verifier tool receipt differs from protected source")
    expected_tools = {}
    for name in ("gh", "cosign"):
        pin = pins[name]
        expected_tools[name] = {
            "path": str(work / "tools" / name),
            "bytes": pin["binary_bytes"], "sha256": pin["binary_sha256"],
            "version": pin["version"], "archive_sha256": pin["sha256"],
            "archive_bytes": pin["bytes"],
        }
    if receipt.get("tools") != expected_tools:
        raise CandidateAuthenticationError("pinned verifier tools differ from the exact bootstrap receipt")
    for name in ("gh", "cosign"):
        tool_path = work / "tools" / name
        _safe_regular(tool_path, "pinned " + name + " executable", verifier._MAX_TOOL)
        if not os.access(tool_path, os.X_OK):
            raise CandidateAuthenticationError("pinned verifier executable is not executable: " + name)
    expected_roots = {
        name: {"path": str(work / "trust" / Path(pins["roots"][name]["path"]).name),
               "bytes": pins["roots"][name]["bytes"], "sha256": pins["roots"][name]["sha256"]}
        for name in ("gh", "cosign")
    }
    if receipt.get("roots") != expected_roots:
        raise CandidateAuthenticationError("pinned verifier roots differ from the exact bootstrap receipt")
    for name in ("gh", "cosign"):
        _safe_regular(work / "trust" / Path(pins["roots"][name]["path"]).name,
                      "pinned " + name + " trust root", verifier._MAX_ROOT)
    expected_budgets = {"workspace_bytes": ci_verify.ci_sdk.MAX_WORK_BYTES,
                        "rss_bytes": ci_verify.ci_sdk.MAX_RSS_BYTES,
                        "log_bytes": ci_verify.ci_sdk.MAX_LOG_BYTES,
                        "command_seconds": ci_verify.ci_sdk.MAX_COMMAND_SECONDS}
    if (receipt.get("budgets") != expected_budgets
            or not isinstance(receipt.get("commands"), list)
            or receipt.get("claim") != (
                "Hash-pinned verifier tools and roots are ready; no SDK candidate or publisher evidence has been verified.")):
        raise CandidateAuthenticationError("pinned verifier bootstrap limits or command receipt is invalid")
    # The common helper rechecks both executable and root hashes against the
    # tracked manifest, and rejects a source checkout with local modifications.
    checked = ci_verify._verify_tool_receipt(work, metadata, host, manifest)
    policy_path, policy = ci_verify._write_source_policy(identity, checked["roots"], work, reuse=True)
    policy_raw = _safe_regular(policy_path, "protected publisher policy", 1024 * 1024)
    if policy_raw != ci_verify.canonical_json(policy):
        raise CandidateAuthenticationError("protected publisher policy differs from the exact source policy")
    return receipt, policy, executable


def _trusted_context(work: Path, metadata: Path, python_root: Path):
    identity = ci_auth.context(ROOT)
    receipt, policy, python = _validate_tool_receipt(work, metadata, python_root, identity)
    if Path(sys.executable).resolve(strict=True) != python.resolve(strict=True):
        raise CandidateAuthenticationError("candidate_auth.py must run under the pinned Python bootstrap")
    if not sys.flags.isolated or not sys.dont_write_bytecode:
        raise CandidateAuthenticationError("candidate_auth.py must run with pinned Python -I -B")
    return identity, receipt, policy, python


def _load_inner_bundle(bundle: Path, policy: dict[str, Any], identity: dict[str, Any]):
    root = _safe_directory(bundle, "inner bundle")
    raw_manifest = verifier._read_regular(root / "release.json", 4 * 1024 * 1024, "inner release manifest")
    manifest = verifier._strict_json(raw_manifest, "inner release manifest")
    if not isinstance(manifest, dict):
        raise CandidateAuthenticationError("inner release manifest must be a JSON object")
    producer = manifest.get("producer")
    if not isinstance(producer, dict):
        raise CandidateAuthenticationError("inner release manifest has no protected producer identity")
    expected = {"kind": "protected-github-actions", "repository": ci_auth.REPO,
                "workflow": ci_auth.WORKFLOW, "source_sha": identity["source_sha"],
                "workflow_sha": identity["workflow_sha"], "run_id": identity["run_id"],
                "run_attempt": identity["run_attempt"],
                "acceptance": "R1 acceptance and publication are separate gates"}
    if producer != expected:
        raise CandidateAuthenticationError("inner candidate source or run does not match this protected workflow")
    if manifest.get("schema") != "ami-rust-release-v1" or manifest.get("qualification_only") is not False:
        raise CandidateAuthenticationError("inner bundle is not a production release candidate")
    version = manifest.get("version")
    if not isinstance(version, str):
        raise CandidateAuthenticationError("inner release version is missing")
    tag = "v" + version
    try:
        if stage_candidate._REPLAY.release_core(tag) != version:
            raise ValueError("release version is not a canonical production core")
    except ValueError as error:
        raise CandidateAuthenticationError("inner release version cannot select an exact release tag") from error

    result = verifier.verify(root, manifest, policy)
    if (result.get("verified") is not True or result.get("sourceSha") != identity["source_sha"]
            or result.get("workflowSha") != identity["workflow_sha"]
            or result.get("sourceRef") != "refs/heads/main"
            or result.get("manifestSha256") != _sha256(raw_manifest)
            or result.get("workflowRuns") != [{"runId": identity["run_id"],
                                                "runAttempt": identity["run_attempt"],
                                                "hostProfile": HOST}]):
        raise CandidateAuthenticationError("real publisher verification returned a different inner source/run")
    return root, manifest, raw_manifest, tag, result


def _predicate_bytes(bundle: Path) -> tuple[dict[str, Any], bytes]:
    predicate = ci_auth.predicate(bundle, HOST)
    raw = ci_auth.encoded(predicate)
    if not raw or len(raw) > MAX_PREDICATE_BYTES:
        raise CandidateAuthenticationError("outer predicate is empty or exceeds its size limit")
    return predicate, raw


def _prepared_metadata(identity: dict[str, Any], raw_manifest: bytes, tag: str,
                       predicate_raw: bytes, candidate_summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": PREPARED_SCHEMA,
        "status": PREPARED_STATUS,
        "source_commit": identity["source_sha"],
        "workflow_commit": identity["workflow_sha"],
        "run_id": identity["run_id"],
        "run_attempt": identity["run_attempt"],
        "host_profile": HOST,
        "inner_manifest_sha256": _sha256(raw_manifest),
        "tag": tag,
        "predicate_sha256": _sha256(predicate_raw),
        "candidate": candidate_summary,
        "r1_accepted": False,
        "publication_authorized": False,
    }


def _github_outputs(candidate_summary: dict[str, Any]) -> dict[str, str]:
    names = stage_candidate.asset_names(candidate_summary["tag"])
    digests = {row["path"]: row["sha256"] for row in candidate_summary["assets"]}
    values = {"tag": candidate_summary["tag"]}
    for key in ("payload", "sbom", "transport", "payload_signature", "transport_signature", "checksums"):
        filename = names[key]
        values[key + "_name"] = filename
        if key in ("payload", "sbom", "transport"):
            values[key + "_sha256"] = digests[filename]
    return values


def _write_github_outputs(values: dict[str, str]) -> None:
    output_name = os.environ.get("GITHUB_OUTPUT")
    if not output_name:
        return
    path = Path(output_name)
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise CandidateAuthenticationError("GITHUB_OUTPUT must be an absolute regular file")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise CandidateAuthenticationError("GITHUB_OUTPUT must be an existing regular file")
    with path.open("a", encoding="utf-8") as stream:
        for name, value in values.items():
            if "\n" in value or "\r" in value or "=" in name:
                raise CandidateAuthenticationError("invalid GitHub output value")
            stream.write(name + "=" + value + "\n")


def prepare(bundle: Path, candidate: Path, work: Path, metadata: Path,
            python_bootstrap_root: Path) -> dict[str, Any]:
    """Authenticate the inner Linux bundle, then prepare the unsigned outer set."""
    work = _safe_directory(work, "trusted verifier work")
    metadata = _safe_directory(metadata, "tool bootstrap metadata")
    python_bootstrap_root = _safe_directory(python_bootstrap_root, "Python bootstrap root")
    bundle = _safe_directory(bundle, "inner bundle")
    candidate = _safe_directory(candidate, "fresh outer candidate", fresh=True)
    _require_disjoint({"inner bundle": bundle, "outer candidate": candidate,
                       "work": work, "metadata": metadata,
                       "Python bootstrap": python_bootstrap_root, "source": ROOT.resolve()})
    if set(_tree_inventory(metadata, limit=MAX_CANDIDATE_PROOF_BYTES)) != {"tool-bootstrap.json"}:
        raise CandidateAuthenticationError("prepare requires only the existing pinned tool bootstrap receipt")
    identity, _receipt, policy, _python = _trusted_context(work, metadata, python_bootstrap_root)
    inner_root, manifest, raw_manifest, tag, inner_verification = _load_inner_bundle(bundle, policy, identity)

    predicate, predicate_raw = _predicate_bytes(inner_root)
    candidate_summary = stage_candidate.prepare(tag, inner_root, candidate)
    prepared = _prepared_metadata(identity, raw_manifest, tag, predicate_raw, candidate_summary)
    _write_new_file(metadata, "outer-predicate.json", predicate_raw)
    _write_new_file(metadata, "outer-prepared.json", _canonical_json(prepared))
    if _tree_bytes(candidate, limit=MAX_CANDIDATE_PROOF_BYTES) + _tree_bytes(
            metadata, limit=MAX_CANDIDATE_PROOF_BYTES) > MAX_CANDIDATE_PROOF_BYTES:
        raise CandidateAuthenticationError("prepared candidate and proof metadata exceed 96 MiB")
    result = {
        **prepared,
        "inner_verification": {"manifest_sha256": inner_verification["manifestSha256"],
                               "source_sha": inner_verification["sourceSha"],
                               "workflow_sha": inner_verification["workflowSha"],
                               "workflow_runs": inner_verification["workflowRuns"]},
        "github_outputs": _github_outputs(candidate_summary),
        "claim": "Prepared after real inner publisher verification; outer signatures and attestations remain required.",
    }
    _write_github_outputs(result["github_outputs"])
    return result


def _parse_gh_values(values: list[str], expected_subjects: set[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        if "=" not in value:
            raise CandidateAuthenticationError("each --gh value must be subject=path")
        subject, raw_path = value.split("=", 1)
        if subject not in expected_subjects or subject in result or not raw_path:
            raise CandidateAuthenticationError("outer GH attestations must map exactly one bundle per subject")
        result[subject] = Path(raw_path)
    if set(result) != expected_subjects:
        raise CandidateAuthenticationError("outer GH attestation set is incomplete")
    return result


def _validate_prepared_metadata(metadata: Path, identity: dict[str, Any], raw_manifest: bytes,
                                tag: str, predicate_raw: bytes,
                                candidate_summary: dict[str, Any]) -> dict[str, Any]:
    expected = _prepared_metadata(identity, raw_manifest, tag, predicate_raw,
                                  {"tag": candidate_summary["tag"],
                                   "version": candidate_summary["version"],
                                   "source_commit": candidate_summary["source_commit"],
                                   "release_json_sha256": candidate_summary["release_json_sha256"],
                                   "assets": [row for row in candidate_summary["assets"]
                                              if row["path"] in {
                                                  stage_candidate.asset_names(tag)["payload"],
                                                  stage_candidate.asset_names(tag)["sbom"],
                                                  stage_candidate.asset_names(tag)["transport"]}]})
    prepared_raw = _safe_regular(metadata / "outer-prepared.json", "outer preparation metadata", 1024 * 1024)
    prepared = verifier._strict_json(prepared_raw, "outer preparation metadata")
    if prepared != expected:
        raise CandidateAuthenticationError("outer preparation metadata differs from the verified bundle and candidate")
    return expected


def _verified_gh_bundle_snapshots(metadata: Path, bundle_inputs: dict[str, Path]
                                  ) -> tuple[dict[str, Path], dict[str, dict[str, Any]]]:
    snapshots: dict[str, Path] = {}
    evidence: dict[str, dict[str, Any]] = {}
    raw_rows: dict[str, bytes] = {}
    for subject, source in bundle_inputs.items():
        raw = _safe_regular(source, "outer GitHub attestation bundle for " + subject,
                            verifier._MAX_GH_BUNDLE)
        parsed = verifier._strict_json(raw, "outer GitHub attestation bundle")
        if not isinstance(parsed, dict):
            raise CandidateAuthenticationError("outer GitHub attestation bundle must be a JSON object")
        raw_rows[subject] = raw
        evidence[subject] = {"bytes": len(raw), "sha256": _sha256(raw)}
    gh_dir = metadata / "gh"
    if gh_dir.exists() or gh_dir.is_symlink():
        raise CandidateAuthenticationError("outer GH proof destination must be fresh")
    for subject, raw in raw_rows.items():
        destination = _write_nested_new_file(metadata, "gh/" + subject + ".json", raw)
        snapshots[subject] = destination
        evidence[subject]["path"] = destination.relative_to(metadata).as_posix()
    return snapshots, evidence


def _expected_publisher_workflow(policy: dict[str, Any], host: str) -> dict[str, Any]:
    return {
        "environment": "release", "runnerEnvironment": "github-hosted",
        "repository": verifier.REPOSITORY, "workflow": verifier.WORKFLOW,
        "workflowSha": policy["workflow_sha"], "sourceSha": policy["source_sha"],
        "sourceRef": verifier.SOURCE_REF,
        "inputsManifestSha256": policy["inputs_manifest_sha256"],
        "hostProfile": host,
    }


def _command_env(home: Path) -> dict[str, str]:
    gh_config = home / "gh"
    gh_config.mkdir(mode=0o700)
    return {"HOME": str(home), "GH_CONFIG_DIR": str(gh_config), "PATH": os.defpath,
            "LC_ALL": "C", "LANG": "C", "GH_PROMPT_DISABLED": "1", "NO_COLOR": "1",
            "COSIGN_EXPERIMENTAL": "0"}


def _exit_code(error: BaseException) -> int | None:
    match = re.search(r"rejected evidence \((\d+)\)", str(error))
    return int(match.group(1)) if match else None


def _run_logged(argv: list[str], *, deadline: float, env: dict[str, str],
                label: str, commands: list[dict[str, Any]],
                runner: Callable[..., bytes] | None = None) -> bytes:
    execute = verifier._run_command if runner is None else runner
    row: dict[str, Any] = {"label": label, "argv": argv}
    commands.append(row)
    try:
        output = execute(argv, deadline=deadline, env=env)
    except verifier.PublisherVerificationError as error:
        row.update({"exit_code": _exit_code(error), "status": "rejected",
                    "error": str(error)[:2000]})
        raise
    except OSError as error:
        row.update({"exit_code": None, "status": "not_started", "error": str(error)[:1000]})
        raise
    row.update({"exit_code": 0, "status": "accepted", "stdout_sha256": _sha256(output),
                "stdout_bytes": len(output)})
    return output


def _gh_command(path: Path, bundle: Path, policy: dict[str, Any]) -> list[str]:
    return [policy["gh"]["path"], "attestation", "verify", str(path),
            "--repo", verifier.REPOSITORY, "--bundle", str(bundle),
            "--custom-trusted-root", policy["gh_trusted_roots"]["path"],
            "--signer-digest", policy["workflow_sha"],
            "--source-digest", policy["source_sha"], "--source-ref", verifier.SOURCE_REF,
            "--deny-self-hosted-runners", "--predicate-type", verifier.PREDICATE_TYPE,
            *verifier._gh_certificate_identity_args(policy), "--format=json"]


def _cosign_command(path: Path, bundle: Path, policy: dict[str, Any]) -> list[str]:
    return [policy["cosign"]["path"], "verify-blob", str(path), "--bundle", str(bundle),
            "--trusted-root", policy["cosign_trusted_root"]["path"],
            "--certificate-identity", policy["cert_identity"],
            "--certificate-oidc-issuer", policy["oidc_issuer"],
            "--certificate-github-workflow-repository", verifier.REPOSITORY,
            "--certificate-github-workflow-ref", verifier.SOURCE_REF,
            "--certificate-github-workflow-sha", policy["workflow_sha"],
            "--certificate-github-workflow-trigger", "workflow_dispatch"]


def _verify_gh_attestations(candidate: Path, tag: str, asset_rows: dict[str, tuple[int, str]],
                            gh_bundles: dict[str, Path], policy: dict[str, Any],
                            identity: dict[str, Any], expected_predicate: dict[str, Any],
                            input_materials: list[dict[str, Any]], env: dict[str, str],
                            deadline: float, commands: list[dict[str, Any]],
                            runner: Callable[..., bytes] | None = None) -> None:
    names = stage_candidate.asset_names(tag)
    subjects = {names[key] for key in ("payload", "sbom", "transport", "checksums")}
    if set(gh_bundles) != subjects:
        raise CandidateAuthenticationError("outer GitHub attestation set must cover exactly four subjects")
    if set(asset_rows) != set(stage_candidate.asset_names(tag).values()):
        raise CandidateAuthenticationError("candidate asset inventory is incomplete")
    run = {"run_id": identity["run_id"], "run_attempt": identity["run_attempt"]}
    for subject in sorted(subjects):
        bundle = gh_bundles[subject]
        if not bundle.is_absolute() or bundle.resolve(strict=True) != bundle:
            raise CandidateAuthenticationError("outer GitHub proof snapshot has a linked or noncanonical path")
        output = _run_logged(_gh_command(candidate / subject, bundle, policy), deadline=deadline,
                             env=env, label="github-attestation:" + subject,
                             commands=commands, runner=runner)
        statement = verifier._statement_result(output, "outer GH attestation verification JSON")
        verifier._check_predicate(statement, policy=policy, run=run, host=HOST,
                                  subject_paths={subject}, manifest={subject: asset_rows[subject]},
                                  input_materials=input_materials)
        if statement.get("predicate") != expected_predicate:
            raise CandidateAuthenticationError("outer GH predicate differs from exact protected-source predicate")


def _verify_cosign(candidate: Path, tag: str, policy: dict[str, Any], env: dict[str, str],
                   deadline: float, commands: list[dict[str, Any]],
                   runner: Callable[..., bytes] | None = None) -> None:
    names = stage_candidate.asset_names(tag)
    for key in ("payload", "transport"):
        asset = names[key]
        bundle = candidate / names[key + "_signature"]
        raw = _safe_regular(bundle, "outer Cosign signature bundle", verifier._MAX_COSIGN_BUNDLE)
        parsed = verifier._strict_json(raw, "outer Cosign signature bundle")
        if not isinstance(parsed, dict):
            raise CandidateAuthenticationError("outer Cosign signature bundle must be a JSON object")
        _run_logged(_cosign_command(candidate / asset, bundle, policy), deadline=deadline,
                    env=env, label="cosign-signature:" + asset, commands=commands, runner=runner)


def _expected_rejection(argv: list[str], *, deadline: float, env: dict[str, str],
                        label: str, commands: list[dict[str, Any]],
                        runner: Callable[..., bytes] | None = None) -> dict[str, Any]:
    execute = verifier._run_command if runner is None else runner
    row: dict[str, Any] = {"label": label, "argv": argv}
    commands.append(row)
    try:
        output = execute(argv, deadline=deadline, env=env)
    except verifier.PublisherVerificationError as error:
        code = _exit_code(error)
        row.update({"exit_code": code, "status": "rejected", "error": str(error)[:2000]})
        return {"rejected": code is not None and code != 0, "exit_code": code,
                "error": str(error)[:2000]}
    except OSError as error:
        row.update({"exit_code": None, "status": "not_started", "error": str(error)[:1000]})
        return {"rejected": False, "exit_code": None, "error": str(error)[:1000]}
    row.update({"exit_code": 0, "status": "accepted", "stdout_sha256": _sha256(output),
                "stdout_bytes": len(output)})
    return {"rejected": False, "exit_code": 0, "error": "mutated subject was accepted"}


def _counterprobes(candidate: Path, tag: str, policy: dict[str, Any],
                   gh_payload_bundle: Path, work: Path, env: dict[str, str],
                   deadline: float, commands: list[dict[str, Any]],
                   runner: Callable[..., bytes] | None = None) -> dict[str, Any]:
    names = stage_candidate.asset_names(tag)
    with tempfile.TemporaryDirectory(prefix="ami-rust-outer-counterprobe-", dir=work) as temporary:
        probe_root = Path(temporary)
        copied = probe_root / "candidate"
        candidate_files = stage_candidate._scan_candidate_files(candidate, set(names.values()), names)
        copied.mkdir(mode=0o700)
        for name, raw in candidate_files.items():
            _write_new_file(copied, name, raw)
        missing = names["sbom"]
        backup = probe_root / "sbom-backup"
        os.replace(copied / missing, backup)
        try:
            try:
                stage_candidate.verify_candidate(copied, tag)
            except (OSError, RuntimeError, ValueError) as error:
                missing_result = {"rejected": True, "missing_asset": missing,
                                  "error_type": type(error).__name__, "error": str(error)[:1000]}
            else:
                missing_result = {"rejected": False, "missing_asset": missing,
                                  "error": "candidate verifier accepted a missing asset"}
        finally:
            os.replace(backup, copied / missing)
        if not missing_result["rejected"]:
            raise CandidateAuthenticationError("missing-asset structural counterprobe unexpectedly passed")
        stage_candidate.verify_candidate(copied, tag)

        payload_path = copied / names["payload"]
        original = verifier._read_regular(payload_path, stage_candidate._TRANSPORT.MAX_ARCHIVE_BYTES,
                                          "outer payload counterprobe source")
        changed = bytearray(original)
        offset = 0
        before = changed[offset]
        changed[offset] ^= 1
        after = changed[offset]
        with payload_path.open("r+b") as stream:
            stream.seek(offset)
            stream.write(bytes([after]))
            stream.flush()
            os.fsync(stream.fileno())
        mutated_raw = bytes(changed)
        mutated_sha = _sha256(mutated_raw)
        if mutated_sha == _sha256(original):
            raise CandidateAuthenticationError("payload counterprobe did not change the asset digest")
        gh_result = _expected_rejection(
            _gh_command(payload_path, gh_payload_bundle, policy), deadline=deadline,
            env=env, label="counterprobe:github-mutated-payload", commands=commands, runner=runner)
        cosign_bundle = candidate / names["payload_signature"]
        cosign_result = _expected_rejection(
            _cosign_command(payload_path, cosign_bundle, policy), deadline=deadline,
            env=env, label="counterprobe:cosign-mutated-payload", commands=commands, runner=runner)
        if not gh_result["rejected"] or not cosign_result["rejected"]:
            raise CandidateAuthenticationError("mutated payload was not rejected by both real verifier commands")
        return {
            "missing_asset": missing_result,
            "mutated_payload": {
                "original_sha256": _sha256(original), "mutated_sha256": mutated_sha,
                "flip_recipe": {"offset": offset, "xor_mask": 1,
                                "before_hex": f"{before:02x}", "after_hex": f"{after:02x}"},
                "github": gh_result, "cosign": cosign_result,
            },
        }


def _candidate_asset_rows(summary: dict[str, Any]) -> dict[str, tuple[int, str]]:
    rows: dict[str, tuple[int, str]] = {}
    for row in summary.get("assets", []):
        if not isinstance(row, dict) or set(row) != {"path", "bytes", "sha256"}:
            raise CandidateAuthenticationError("candidate verifier returned a malformed asset inventory")
        if (not isinstance(row["path"], str) or type(row["bytes"]) is not int
                or row["bytes"] < 0 or not isinstance(row["sha256"], str)
                or not _HEX64.fullmatch(row["sha256"]) or row["path"] in rows):
            raise CandidateAuthenticationError("candidate verifier returned invalid asset hashes")
        rows[row["path"]] = (row["bytes"], row["sha256"])
    return rows


def verify(candidate: Path, bundle: Path, work: Path, metadata: Path,
           python_bootstrap_root: Path, gh_values: list[str], *,
           runner: Callable[..., bytes] | None = None) -> dict[str, Any]:
    """Verify candidate structure and real outer GH/Cosign evidence, retaining a report."""
    work = _safe_directory(work, "trusted verifier work")
    metadata = _safe_directory(metadata, "candidate proof metadata")
    python_bootstrap_root = _safe_directory(python_bootstrap_root, "Python bootstrap root")
    candidate = _safe_directory(candidate, "outer candidate")
    bundle = _safe_directory(bundle, "inner bundle")
    _require_disjoint({"candidate": candidate, "inner bundle": bundle, "work": work,
                       "metadata": metadata, "Python bootstrap": python_bootstrap_root,
                       "source": ROOT.resolve()})
    report_path = metadata / "outer-verification.json"
    if report_path.exists() or report_path.is_symlink():
        raise CandidateAuthenticationError("outer verification report destination must be fresh")
    identity: dict[str, Any] | None = None
    report: dict[str, Any] = {
        "schema": VERIFICATION_SCHEMA, "status": FAILED_STATUS,
        "r1_accepted": False, "publication_authorized": False,
        "commands": [], "counterprobes": {}, "assets": [], "gh_bundles": {},
    }
    try:
        identity, _receipt, policy, _python = _trusted_context(work, metadata, python_bootstrap_root)
        report.update({"source_commit": identity["source_sha"], "workflow_commit": identity["workflow_sha"],
                       "run_id": identity["run_id"], "run_attempt": identity["run_attempt"],
                       "host_profile": HOST})
        if set(_tree_inventory(metadata, limit=MAX_CANDIDATE_PROOF_BYTES)) != {
                "tool-bootstrap.json", "outer-predicate.json", "outer-prepared.json",
                "outer-finalized.json"}:
            raise CandidateAuthenticationError("verify requires a fresh prepared metadata directory")
        inner_root, _manifest, raw_manifest, tag, inner_verification = _load_inner_bundle(bundle, policy, identity)
        predicate, predicate_raw = _predicate_bytes(inner_root)
        saved_predicate = _safe_regular(metadata / "outer-predicate.json", "prepared outer predicate",
                                        MAX_PREDICATE_BYTES)
        if saved_predicate != predicate_raw:
            raise CandidateAuthenticationError("saved outer predicate differs from the exact protected-source predicate")
        summary = stage_candidate.verify_candidate(candidate, tag)
        prepared = _validate_prepared_metadata(metadata, identity, raw_manifest, tag, predicate_raw, summary)
        finalized_raw = _safe_regular(metadata / "outer-finalized.json", "outer finalized candidate metadata",
                                      1024 * 1024)
        finalized = verifier._strict_json(finalized_raw, "outer finalized candidate metadata")
        if finalized != summary:
            raise CandidateAuthenticationError("finalized metadata differs from the verified six-asset candidate")
        names = stage_candidate.asset_names(tag)
        subjects = {names[key] for key in ("payload", "sbom", "transport", "checksums")}
        gh_inputs = _parse_gh_values(gh_values, subjects)
        snapshots, gh_evidence = _verified_gh_bundle_snapshots(metadata, gh_inputs)
        report.update({"tag": tag, "candidate_name": candidate.name,
                       "inner_manifest_sha256": _sha256(raw_manifest),
                       "inner_verification": {"manifest_sha256": inner_verification["manifestSha256"],
                                              "source_sha": inner_verification["sourceSha"],
                                              "workflow_sha": inner_verification["workflowSha"],
                                              "workflow_runs": inner_verification["workflowRuns"]},
                       "prepared_metadata_sha256": _sha256(_canonical_json(prepared)),
                       "finalized_metadata_sha256": _sha256(finalized_raw),
                       "predicate_sha256": _sha256(predicate_raw),
                       "assets": summary["assets"], "gh_bundles": gh_evidence})
        asset_rows = _candidate_asset_rows(summary)
        artifact_bytes = (_tree_bytes(candidate, limit=MAX_CANDIDATE_PROOF_BYTES)
                          + _tree_bytes(metadata, limit=MAX_CANDIDATE_PROOF_BYTES))
        if artifact_bytes > MAX_CANDIDATE_PROOF_BYTES:
            raise CandidateAuthenticationError("candidate and proof artifact exceeds 96 MiB")

        inputs_manifest, input_materials = verifier._inputs_manifest(inner_root, policy)
        if _sha256(inputs_manifest) != policy["inputs_manifest_sha256"]:
            raise CandidateAuthenticationError("inner input manifest differs from the exact protected-source policy")
        deadline = time.monotonic() + verifier._TOTAL_SECONDS
        with tempfile.TemporaryDirectory(prefix="ami-rust-outer-verify-") as home_name:
            env = _command_env(Path(home_name))
            _verify_gh_attestations(candidate, tag, asset_rows, snapshots, policy, identity,
                                    predicate, input_materials, env, deadline,
                                    report["commands"], runner=runner)
            _verify_cosign(candidate, tag, policy, env, deadline, report["commands"], runner=runner)
            report["counterprobes"] = _counterprobes(
                candidate, tag, policy, snapshots[names["payload"]], work, env, deadline,
                report["commands"], runner=runner)
        report.update({"status": VERIFIED_STATUS,
                       "claim": "Outer GH and Cosign verification passed; R1 acceptance and publication remain separate gates."})
        final_bytes = (_tree_bytes(candidate, limit=MAX_CANDIDATE_PROOF_BYTES)
                       + _tree_bytes(metadata, limit=MAX_CANDIDATE_PROOF_BYTES))
        if final_bytes > MAX_CANDIDATE_PROOF_BYTES:
            raise CandidateAuthenticationError("candidate and proof artifact exceeds 96 MiB")
        _write_report(metadata, report, candidate)
        return report
    except Exception as error:
        report["status"] = FAILED_STATUS
        report["failure"] = {"type": type(error).__name__, "message": str(error)[:2000]}
        if identity is not None:
            report.update({"source_commit": identity["source_sha"], "workflow_commit": identity["workflow_sha"],
                           "run_id": identity["run_id"], "run_attempt": identity["run_attempt"],
                           "host_profile": HOST})
        try:
            _write_report(metadata, report, candidate)
        except Exception as report_error:
            raise CandidateAuthenticationError(
                "outer verification failed and its report could not be preserved: " + str(report_error)
            ) from error
        raise


def _cli() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("prepare", "verify"):
        child = commands.add_parser(name)
        child.add_argument("--bundle", type=Path, required=True)
        child.add_argument("--candidate", type=Path, required=True)
        child.add_argument("--work", type=Path, required=True)
        child.add_argument("--metadata", type=Path, required=True)
        child.add_argument("--python-bootstrap-root", type=Path, required=True)
        if name == "verify":
            child.add_argument("--gh", action="append", default=[], metavar="SUBJECT=PATH")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            result = prepare(args.bundle, args.candidate, args.work, args.metadata,
                             args.python_bootstrap_root)
        else:
            result = verify(args.candidate, args.bundle, args.work, args.metadata,
                            args.python_bootstrap_root, args.gh)
    except (OSError, RuntimeError, ValueError) as error:
        parser.exit(2, "candidate_auth: " + str(error) + "\n")
    sys.stdout.buffer.write(_canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
