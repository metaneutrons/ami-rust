#!/usr/bin/env python3
"""Compare original Linux SDK metadata under ordinary and observed builds.

This temporary internal probe authenticates and installs one original signed
SDK, then compares one ordinary native build with two strictly observed native
builds. It reports evidence only; it does not change a reference or accept RC1.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release"))

import ci_auth as auth
import ci_native
import ci_sdk
import ci_verify
import consumer_inputs
import verify_publisher


HOST = "linux-x86_64"
SOURCE = "fcfcd10ac08f302d450411650eb168bb0b6be78a"
RUN_ID = 39501724105
POLICY_SHA256 = "65669f0046e76ff4b20a068c6ccbd846db81708207a0ee15a93595e0b3f7c36b"
POLICY_BYTES = 1424
INPUTS_SHA256 = "97c2f44eef573fa06521bd6a629f466f6dc1840951aadcae43ca0afd0faa84c0"
LAUNCHER_SHA256 = "e05ffb53f07484b3ac68284bc09ab3841325f9df2c0fd7bf7314890fd5b50c45"
LAUNCHER_BYTES = 3880560
POLICY_FIELDS = {
    "schema", "repository", "workflow", "workflow_sha", "source_sha",
    "source_ref", "oidc_issuer", "cert_identity", "inputs_manifest_sha256",
    "allowed_host_profiles", "gh", "cosign", "gh_trusted_roots",
    "cosign_trusted_root",
}
COMPONENTS = ("rust", "cargo", "toolchain", "collector", "csdk", "vendor")
BUILD_NAMES = ("ordinary", "observed-a", "observed-b")
LABEL_RE = re.compile(r"[^A-Za-z0-9_.-]+")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _read_json(path: Path, maximum: int = 16 * 1024**2) -> dict:
    raw = auth.read(path, maximum)
    value = auth.parsed(raw)
    if not isinstance(value, dict):
        raise ValueError("JSON evidence must have an object root: " + path.name)
    return value


def _write_new(path: Path, value: object, mode: int = 0o600) -> None:
    ci_native.write(path, _json_bytes(value), mode)
    if path.is_symlink() or not path.is_file() or _read_json(path) != value:
        raise ValueError("new JSON evidence did not read back exactly: " + path.name)


def _existing_path(value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError(label + " must be a canonical absolute path without symlinks")
    return path


def _fresh_directory(value: str, label: str) -> Path:
    path = Path(value)
    if (not path.is_absolute() or path != Path(os.path.abspath(path))
            or path.is_symlink() or path.exists() or not path.parent.is_dir()
            or path.parent.resolve(strict=True) != path.parent):
        raise ValueError(label + " must be a fresh canonical absolute directory")
    path.mkdir(mode=0o700)
    if path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError(label + " resolved through an unexpected path")
    return path


def _regular_file(path: Path, label: str, *, expected_bytes: int | None = None,
                  expected_sha256: str | None = None) -> dict:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.resolve(strict=True) != path:
        raise ValueError(label + " must be a canonical regular file")
    digest = _sha256(path)
    if expected_bytes is not None and info.st_size != expected_bytes:
        raise ValueError(label + " differs from its pinned byte size")
    if expected_sha256 is not None and digest != expected_sha256:
        raise ValueError(label + " differs from its pinned SHA-256")
    return {"path": str(path), "bytes": info.st_size, "sha256": digest}


def _ensure_directory(path: Path, label: str) -> Path:
    if path.exists() or path.is_symlink():
        if path.is_symlink() or not path.is_dir() or path.resolve(strict=True) != path:
            raise ValueError(label + " is not a canonical directory")
        return path
    path.mkdir(mode=0o700, parents=True)
    if path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError(label + " resolved through an unexpected path")
    return path


def _copy_file(source: Path, destination: Path, label: str) -> dict:
    if source.is_symlink() or not source.is_file() or destination.exists() or destination.is_symlink():
        raise ValueError(label + " source or destination is not a fresh regular file")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    source_row = {"bytes": source.stat().st_size, "sha256": _sha256(source)}
    copied = {"bytes": destination.stat().st_size, "sha256": _sha256(destination)}
    if copied != source_row:
        raise ValueError(label + " failed byte-for-byte readback")
    return {"path": destination.name, **copied}


def _copy_tree(source: Path, destination: Path, label: str) -> dict:
    if source.is_symlink() or not source.is_dir() or destination.exists() or destination.is_symlink():
        raise ValueError(label + " source or destination is not a fresh real directory")
    for path in source.rglob("*"):
        info = path.lstat()
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise ValueError(label + " contains a symlink or special file")
    shutil.copytree(source, destination, symlinks=False, copy_function=shutil.copy2)
    source_inventory = ci_sdk.component_inventory(source)
    copied_inventory = ci_sdk.component_inventory(destination)
    if copied_inventory != source_inventory:
        raise ValueError(label + " tree copy differs from its complete file and symlink inventory")
    after = ci_sdk.directory_accounting(destination)[0]
    return {"path": destination.name, "regular_file_bytes": after,
            "inventory_sha256": auth.sha(auth.encoded(copied_inventory))}


def _output_limit(output: Path, label: str) -> None:
    size = ci_sdk.directory_accounting(output)[0]
    if size > ci_sdk.MAX_OUTPUT_BYTES:
        raise ValueError(label + " exceeded the 32 MiB diagnostic output ceiling")


def _read_log(work: Path, relative: str, label: str) -> tuple[Path, bytes]:
    rel = Path(relative)
    if rel.is_absolute() or any(part in ("", ".", "..") for part in rel.parts):
        raise ValueError(label + " log path is not a safe relative path")
    path = work.joinpath(*rel.parts)
    if path.is_symlink() or not path.is_file() or not path.resolve(strict=True).is_relative_to(work):
        raise ValueError(label + " log is missing or escaped the managed work root")
    return path, auth.read(path, ci_sdk.MAX_LOG_BYTES)


def _run_supervised(supervisor, command, *, label: str, cwd: Path,
                    timeout: int = ci_sdk.MAX_COMMAND_SECONDS) -> tuple[dict, bytes, bytes]:
    row = ci_native._supervised_run(supervisor, command, label=label, cwd=cwd, timeout=timeout)
    _, stdout = _read_log(supervisor.work, row["stdout_log"], label + " stdout")
    _, stderr = _read_log(supervisor.work, row["stderr_log"], label + " stderr")
    return row, stdout, stderr


def _run_cli_json(supervisor, cli: Path, args: list[str | Path], *, label: str,
                  cwd: Path) -> tuple[dict, dict, bytes, bytes]:
    _regular_file(cli, "original Linux consumer CLI", expected_bytes=LAUNCHER_BYTES,
                  expected_sha256=LAUNCHER_SHA256)
    if not os.access(cli, os.X_OK):
        raise ValueError("original Linux consumer CLI is not executable")
    command = [str(cli), *[str(arg) for arg in args]]
    row, stdout, stderr = _run_supervised(supervisor, command, label=label, cwd=cwd)
    value = auth.parsed(stdout)
    if not isinstance(value, dict):
        raise ValueError(label + " did not return a JSON object")
    return row, value, stdout, stderr


def _validate_original_policy(raw: bytes) -> dict:
    if len(raw) != POLICY_BYTES or auth.sha(raw) != POLICY_SHA256:
        raise ValueError("original consumer policy differs from the pinned artifact")
    policy = auth.parsed(raw)
    if not isinstance(policy, dict) or set(policy) != POLICY_FIELDS:
        raise ValueError("original consumer policy has an unexpected shape")
    if (policy.get("schema") != "ami-rust-publisher-trust-v2"
            or policy.get("repository") != auth.REPO or policy.get("workflow") != auth.WORKFLOW
            or policy.get("source_sha") != SOURCE or policy.get("workflow_sha") != SOURCE
            or policy.get("source_ref") != "refs/heads/main"
            or policy.get("oidc_issuer") != "https://token.actions.githubusercontent.com"
            or policy.get("cert_identity") != f"https://github.com/{auth.REPO}/{auth.WORKFLOW}@refs/heads/main"
            or policy.get("inputs_manifest_sha256") != INPUTS_SHA256
            or HOST not in policy.get("allowed_host_profiles", [])):
        raise ValueError("original policy source/workflow/input identity is not the requested publication")
    for key in ("gh", "cosign", "gh_trusted_roots", "cosign_trusted_root"):
        row = policy.get(key)
        if (not isinstance(row, dict) or set(row) != {"path", "sha256"}
                or not isinstance(row["path"], str) or not Path(row["path"]).is_absolute()
                or not isinstance(row["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])):
            raise ValueError("original policy verifier path or digest is malformed: " + key)
    return policy


def _remap_policy(original: dict, tools: dict, output: Path) -> tuple[Path, dict]:
    policy = copy.deepcopy(original)
    for name in ("gh", "cosign"):
        current = tools["tools"][name]
        if (policy[name]["sha256"] != current["sha256"]
                or Path(current["path"]).is_symlink() or not Path(current["path"]).is_file()):
            raise ValueError("bootstrapped verifier bytes differ from the original policy pin: " + name)
        policy[name]["path"] = current["path"]
    for key, name in (("gh_trusted_roots", "gh"), ("cosign_trusted_root", "cosign")):
        current = tools["roots"][name]
        if policy[key]["sha256"] != current["sha256"]:
            raise ValueError("bootstrapped trust-root bytes differ from the original policy pin: " + key)
        policy[key]["path"] = current["path"]
    for key in POLICY_FIELDS - {"gh", "cosign", "gh_trusted_roots", "cosign_trusted_root"}:
        if policy[key] != original[key]:
            raise ValueError("policy remapping changed a non-path identity field: " + key)
    for key in ("gh", "cosign", "gh_trusted_roots", "cosign_trusted_root"):
        if policy[key]["sha256"] != original[key]["sha256"]:
            raise ValueError("policy remapping changed a verifier or trust-root digest: " + key)
    policy_path = output / "original-policy-remapped.json"
    ci_native.write(policy_path, auth.encoded(policy), 0o600)
    if auth.parsed(auth.read(policy_path)) != policy:
        raise ValueError("remapped original policy failed readback")
    verify_publisher._policy(policy)
    return policy_path, policy


def _verified_report(verification: dict, policy_path: Path) -> dict:
    publisher = verification.get("publisher")
    report = publisher.get("report") if isinstance(publisher, dict) else None
    runs = report.get("workflowRuns") if isinstance(report, dict) else None
    if (verification.get("schema") != "ami-rust-release-verification-v1"
            or verification.get("status") != "verified"
            or publisher.get("external_policy_sha256") != _sha256(policy_path)
            or not isinstance(report, dict) or report.get("verified") is not True
            or report.get("sourceSha") != SOURCE or report.get("workflowSha") != SOURCE
            or report.get("repository") != auth.REPO or report.get("workflow") != auth.WORKFLOW
            or not isinstance(runs, list) or len(runs) != 1):
        raise ValueError("original CLI verification did not bind the requested signed publisher identity")
    run = runs[0]
    if (run.get("runId") != RUN_ID or run.get("hostProfile") != HOST
            or type(run.get("runAttempt")) is not int or run["runAttempt"] <= 0):
        raise ValueError("original CLI verification did not authenticate workflow run 39501724105")
    return report


def _copy_supervisor_logs(supervisor, output: Path) -> list[dict]:
    destination = _ensure_directory(output / "supervisor-logs", "supervisor log output")
    copied = []
    for index, row in enumerate(supervisor.commands):
        label = LABEL_RE.sub("-", str(row.get("label", "command"))).strip("-.") or "command"
        log_rows = {}
        for stream in ("stdout", "stderr"):
            source, raw = _read_log(supervisor.work, row[stream + "_log"], label + " " + stream)
            target = destination / f"{index:03d}-{label}.{stream}.raw"
            result = _copy_file(source, target, label + " " + stream)
            log_rows[stream] = {**result, "sha256": auth.sha(raw), "bytes": len(raw)}
        copied.append({"label": row.get("label"),
                       "exit_code": row.get("exit_code"), "stdout": log_rows["stdout"],
                       "stderr": log_rows["stderr"]})
        _output_limit(output, "supervisor log copies")
    return copied


def _copy_observer_evidence(source: Path, destination: Path, label: str) -> dict:
    copied = _copy_tree(source, destination, label)
    observed = _read_json(destination / "observation.json", 4 * 1024**2)
    if observed.get("status") != "PASS_EXPECTED_CONSUMER_RESULT_AND_ADAPTER_EVIDENCE":
        raise ValueError(label + " observation evidence failed readback")
    return {**copied, "observation_sha256": _sha256(destination / "observation.json"),
            "status": observed["status"]}


def _retain_native_command_logs(build_output: Path, destination: Path, label: str) -> dict:
    source = build_output / "commands"
    if source.is_symlink() or not source.is_dir() or destination.exists() or destination.is_symlink():
        raise ValueError(label + " Rust command log directory is missing or ambiguous")
    source_inventory = ci_sdk.component_inventory(source)
    if source_inventory["symlinks"]:
        raise ValueError(label + " Rust command log directory contains a symlink")
    names = {row["path"] for row in source_inventory["files"]}
    command_dirs = {name.rsplit("/", 1)[0] for name in names if "/" in name}
    if (not command_dirs or any(f"{directory}/stdout.log" not in names
                                or f"{directory}/stderr.log" not in names
                                for directory in command_dirs)):
        raise ValueError(label + " Rust command logs are incomplete")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.rename(source, destination)
    copied_inventory = ci_sdk.component_inventory(destination)
    if copied_inventory != source_inventory:
        raise ValueError(label + " retained Rust command logs differ from the build output")
    return {"path": destination.name, "inventory_sha256": auth.sha(auth.encoded(copied_inventory)),
            "regular_file_bytes": ci_sdk.directory_accounting(destination)[0],
            "files": source_inventory["files"]}


def _row_differences(left: dict, right: dict) -> list[dict]:
    return [{"artifact_id": name, "left": left.get(name), "right": right.get(name)}
            for name in sorted(set(left) | set(right)) if left.get(name) != right.get(name)]


def _build_one(name: str, cli: Path, xtask: Path, adapter: Path, supervisor,
               project: Path, lock_path: Path, policy_path: Path, closure_path: Path,
               output: Path, work: Path, static_roots: list[Path],
               *, observed: bool) -> dict:
    build_parent = _ensure_directory(work / "build-runs" / name, name + " build parent")
    derived_parent = _ensure_directory(build_parent / "derived", name + " derived parent")
    build_output = build_parent / "derived" / "build"
    if build_output.exists() or build_output.is_symlink():
        raise ValueError(name + " build output is not fresh")
    arguments: list[str | Path] = [
        "build", "--sdk-lock", lock_path, "--output-dir", build_output,
        "--", "build", "--manifest-path", project / "Cargo.toml",
        "--package", "ami-rust-dependencies", "--release", "--locked", "--offline",
    ]
    command = [str(cli), *[str(arg) for arg in arguments]]
    observer = None
    if observed:
        _regular_file(cli, "original Linux consumer CLI", expected_bytes=LAUNCHER_BYTES,
                      expected_sha256=LAUNCHER_SHA256)
        spec = ci_native._consumer_observation_spec(
            work, supervisor.python_root, cli, arguments, 0, policy_path, closure_path,
            [ci_native.ROOT, *static_roots])
        spec_dir = _ensure_directory(output / "observation-specs", "observation spec directory")
        spec_path = spec_dir / (name + ".json")
        ci_native.write(spec_path, auth.encoded(spec), 0o600)
        if auth.parsed(auth.read(spec_path)) != spec:
            raise ValueError(name + " observation spec failed readback")
        evidence_dir = _ensure_directory(work / "observer-evidence", name + " observer evidence parent")
        observed_path = evidence_dir / name
        wrapper = [str(xtask), "native-consumer-observe", "--spec", str(spec_path),
                   "--adapter", str(adapter), "--output", str(observed_path)]
        outer, stdout, stderr = _run_supervised(supervisor, wrapper, label="observe-" + name,
                                                 cwd=work)
        observation = _read_json(observed_path / "observation.json", 4 * 1024**2)
        if (observation.get("status") != "PASS_EXPECTED_CONSUMER_RESULT_AND_ADAPTER_EVIDENCE"
                or observation.get("expected_exit") != 0
                or observation.get("adapter_evidence", {}).get("child_exit_code") != 0
                or observation.get("command") != command):
            raise ValueError(name + " failed strict native observer admission")
        retained = _copy_observer_evidence(
            observed_path, output / "observations" / name, name + " observer evidence")
        observer = {"spec_path": spec_path.relative_to(output).as_posix(),
                    "spec_sha256": _sha256(spec_path), "wrapper_command": wrapper,
                    "observation": retained,
                    "adapter_evidence": observation["adapter_evidence"],
                    "consumer_command": observation["command"],
                    "stdout_bytes": len(stdout), "stdout_sha256": auth.sha(stdout),
                    "stderr_bytes": len(stderr), "stderr_sha256": auth.sha(stderr)}
        _output_limit(output, name + " observer evidence")
    else:
        _, result, stdout, stderr = _run_cli_json(
            supervisor, cli, arguments, label="build-ordinary", cwd=work)
        if (result.get("status") != "PASS"
                or result.get("native_executable") != str(build_output / "artifacts/AMIRUST")
                or result.get("receipt") != str(build_output / "build-receipt.json")):
            raise ValueError("ordinary native CLI build did not report PASS")
    receipt_path = build_output / "build-receipt.json"
    receipt = _read_json(receipt_path, 4 * 1024**2)
    if (receipt.get("status") != "PASS"
            or receipt.get("project_lock_sha256") != _sha256(lock_path)
            or receipt.get("sdk_manifest_sha256") != _sha256(project / "contract/sdk.json")):
        raise ValueError(name + " actual build receipt does not bind the selected lock and SDK")
    verified, native_file = ci_sdk._verify_native_receipt(
        build_output, None, supervisor, "metadata-probe-" + name)
    evidence = _ensure_directory(output / "builds" / name, name + " build evidence directory")
    receipt_copy = _copy_file(receipt_path, evidence / "build-receipt.json", name + " receipt")
    native_command_logs = _retain_native_command_logs(
        build_output, evidence / "native-commands", name + " Rust command logs")
    metadata = ci_sdk._copy_metadata_archives(
        build_output / "artifacts", verified["artifacts"], evidence)
    for row in metadata:
        _regular_file(output / "builds" / name / row["path"], name + " metadata archive",
                      expected_bytes=row["bytes"], expected_sha256=row["sha256"])
    native_row = {"bytes": native_file.stat().st_size, "sha256": _sha256(native_file)}
    _output_limit(output, name + " build evidence")
    return {
        "name": name, "execution": "strict-linux-observer" if observed else "ordinary-supervisor",
        "command": command, "project": str(project), "lock": str(lock_path),
        "lock_sha256": _sha256(lock_path), "stdout_bytes": len(stdout),
        "stdout_sha256": auth.sha(stdout), "stderr_bytes": len(stderr),
        "stderr_sha256": auth.sha(stderr), "observer": observer,
        "receipt": {**verified, "path": (evidence / "build-receipt.json").relative_to(output).as_posix(),
                    "sha256": receipt_copy["sha256"],
                    "canonical_artifacts": receipt["canonical_artifacts"]},
        "native_command_logs": native_command_logs,
        "native_executable": {**native_row, "retained": False, "path": None},
        "metadata_archives": metadata,
        "derived_parent": str(derived_parent),
        "_native_source_path": str(native_file),
    }


def run(args: argparse.Namespace) -> dict:
    if ci_native.current_host() != HOST:
        raise ValueError("the metadata probe is admitted only on Linux x86-64")
    source_root = ci_native.ROOT.resolve(strict=True)
    host_rust = _existing_path(args.host_rust, "host Rust root")
    python_root = _existing_path(args.python_bootstrap_root, "Python bootstrap root")
    bundle = _existing_path(args.bundle, "authenticated SDK bundle")
    original_policy_path = _existing_path(args.original_policy, "original consumer policy")
    launcher = _existing_path(args.launcher, "native host launcher")
    if not bundle.is_dir() or not original_policy_path.is_file() or not launcher.is_file():
        raise ValueError("bundle, original policy and launcher must be their expected filesystem types")
    if bundle == original_policy_path.parent or bundle in original_policy_path.parents:
        raise ValueError("policy and SDK bundle must be distinct, nonoverlapping artifact roots")
    _regular_file(launcher, "original Linux launcher", expected_bytes=LAUNCHER_BYTES,
                  expected_sha256=LAUNCHER_SHA256)
    if not os.access(launcher, os.X_OK) or launcher.stat().st_mode & 0o111 == 0:
        raise ValueError("original Linux launcher is not executable")
    original_policy = _validate_original_policy(auth.read(original_policy_path, 1024 * 1024))

    work = _fresh_directory(args.work, "work root")
    output = _fresh_directory(args.output, "output root")
    if work.parent != output.parent or work.parent != python_root.parent:
        raise ValueError("work, output and Python bootstrap must be siblings on one managed volume")
    managed = (source_root, work, output, python_root)
    if len(set(managed)) != len(managed) or any(ci_native._overlap(a, b)
                                                for i, a in enumerate(managed)
                                                for b in managed[i + 1:]):
        raise ValueError("source, work, output and Python roots must be distinct and nonoverlapping")
    static_roots = [("original-sdk-bundle", bundle),
                    ("original-consumer-artifact", original_policy_path.parent),
                    ("original-native-launcher", launcher.parent)]
    static_paths = [path.resolve(strict=True) for _, path in static_roots]
    if any(any(ci_native._overlap(path, root) for root in managed) for path in static_paths):
        raise ValueError("an original artifact root overlaps a managed root")
    if any(ci_native._overlap(a, b) for i, a in enumerate(static_paths)
           for b in static_paths[i + 1:]):
        raise ValueError("original bundle, policy and launcher roots overlap")

    input_path = ci_native.ROOT / "release/ci-sdk-inputs.json"
    resources_path = ci_native.ROOT / "release/ci-resources.json"
    reference_inputs, resources, _host_rows = ci_sdk.read_normative(
        input_path, resources_path, HOST)
    capacity = ci_sdk.validate_resource_policy(resources, work.parent)

    _built_cli, xtask, env, supervisor = ci_native.build_tools(
        work, host_rust, output, python_root, static_roots=static_roots)
    # Consumer commands must exercise the exact authenticated original CLI.
    cli = launcher
    cargo = host_rust / "toolchain" / "bin" / "cargo"
    ci_native._supervised_run(supervisor, [cargo, "build", "--release", "--locked", "--offline",
        "--manifest-path", ci_native.ROOT / "tools/consumer-enforcement-adapter/Cargo.toml",
        "--target-dir", work / "consumer-adapter-target"],
        label="build-consumer-enforcement-adapter", cwd=ci_native.ROOT)
    adapter = work / "consumer-adapter-target/release/consumer-enforcement-adapter"
    _regular_file(adapter, "consumer enforcement adapter")
    if not os.access(adapter, os.X_OK):
        raise ValueError("consumer enforcement adapter is not executable")

    verifier_work = work.parent / (work.name + "-verifier-work")
    verifier_output = work.parent / (work.name + "-verifier-metadata")
    live = [ci_sdk.directory_accounting(root) for root in (work, output)]
    extra_bytes = sum(row[0] for row in live)
    extra_bytes += sum(row["regular_file_bytes"] for row in supervisor.native_static_roots)
    extra_logs = sum(row[1] for row in live) + supervisor.native_static_log_bytes
    verifier_source_commit = ci_verify._source_commit()
    tool_receipt = ci_verify.bootstrap_tools(
        verifier_work, verifier_output, python_root, source_commit=verifier_source_commit,
        additional_input_bytes=extra_bytes, additional_log_bytes=extra_logs)
    tool_receipt_path = ci_verify._tools_receipt(verifier_output)
    if _read_json(tool_receipt_path, 256 * 1024) != tool_receipt:
        raise ValueError("pinned verifier bootstrap receipt failed exact readback")
    ci_native._add_static_roots(supervisor, [("verifier-work", verifier_work),
                                             ("verifier-metadata", verifier_output)])
    ci_native._check_limits(supervisor, "metadata probe verifier bootstrap")

    policy_path, remapped_policy = _remap_policy(original_policy, tool_receipt, output)
    native_reference_path = ci_native.ROOT / "release/native-reference.json"
    native_reference = ci_sdk.read_json(native_reference_path)
    ci_sdk.validate_native_reference(native_reference, reference_inputs,
                                     reference_inputs["native_reference"]["sha256"])
    expected_rows = ci_sdk._expected_native_rows(native_reference, HOST, "dependencies")
    computed_inputs = auth.input_manifest_for_sdk(ci_native.ROOT, ci_native.native_inputs()["sdk_version"])
    if (auth.sha(auth.encoded(computed_inputs)) != INPUTS_SHA256
            or remapped_policy["inputs_manifest_sha256"] != INPUTS_SHA256):
        raise ValueError("diagnostic source frozen publisher inputs differ from the original policy")

    _, verification, _, _ = _run_cli_json(
        supervisor, cli, ["verify", "--bundle", bundle, "--policy", policy_path],
        label="verify-original-sdk", cwd=work)
    verified_report = _verified_report(verification, policy_path)
    install_area = work / "native-v2"
    receipt_pin = work / "native-v2-receipt.sha256"
    _, install_result, _, _ = _run_cli_json(
        supervisor, cli, ["install", "--bundle", bundle, "--policy", policy_path,
                          "--prefix", install_area, "--receipt-pin", receipt_pin],
        label="install-original-sdk", cwd=work)
    receipt_path = install_area / "install-receipt.json"
    receipt_sha = _sha256(receipt_path)
    install_receipt = _read_json(receipt_path, 4 * 1024**2)
    if (install_result.get("schema") != "ami-rust-install-result-v1"
            or install_result.get("status") != "installed"
            or install_result.get("receipt_sha256") != receipt_sha
            or install_result.get("prefix") != str(install_area)
            or not receipt_pin.is_file() or receipt_pin.is_symlink()
            or receipt_pin.read_text(encoding="ascii").strip() != receipt_sha
            or install_receipt.get("schema") != "ami-rust-install-receipt-v3"
        or install_receipt.get("authentication", {}).get("external_policy_sha256") != _sha256(policy_path)):
        raise ValueError("authentic native installation receipt or external pin failed readback")
    installed_auth = install_receipt["authentication"].get("report", {})
    installed_runs = installed_auth.get("workflowRuns")
    if (installed_auth.get("sourceSha") != SOURCE or installed_auth.get("workflowSha") != SOURCE
            or not isinstance(installed_runs, list) or len(installed_runs) != 1
            or installed_runs[0].get("runId") != RUN_ID
            or installed_runs[0].get("hostProfile") != HOST):
        raise ValueError("actual install receipt lost the authenticated original publisher run")

    sdk_root = install_area / "sdk"
    manifest_path = sdk_root / "contract/sdk.json"
    manifest = ci_sdk.read_json(manifest_path, 16 * 1024**2)
    sdk_info = {"root": sdk_root, "manifest": manifest}
    sdk_info["component_info"] = ci_sdk._component_rows_from_sdk(sdk_info, HOST)
    provision_work = work / "consumer-provision"
    provision_work.mkdir(mode=0o700)
    provision = consumer_inputs.provision_inputs(
        bundle, provision_work, supervisor, HOST, sdk_info, reference_inputs,
        sdk=ci_sdk, auth=auth, extract_cargo=ci_verify._extract_flat_cargo)
    if set(provision["component_roots"]) != set(COMPONENTS):
        raise ValueError("verified consumer prerequisite closure does not include all six components")
    selection = {"schema": "ami-rust-selection-v2", "host": HOST,
                 "install_receipt_sha256": receipt_sha,
                 "components": {name: str(provision["component_roots"][name]) for name in COMPONENTS}}
    selection_path = work / "selection.json"
    ci_native.write(selection_path, auth.encoded(selection), 0o600)
    if auth.parsed(auth.read(selection_path)) != selection:
        raise ValueError("actual v2 component selection failed readback")

    closure = {
        "schema": "ami-rust-reviewed-consumer-inputs-v1",
        "source": {"source_sha": SOURCE, "workflow_sha": SOURCE},
        "publisher_inputs": computed_inputs,
        "candidate_manifest_sha256": _sha256(bundle / "release.json"),
        "scope": "Original authenticated SDK and tracked component identities for this diagnostic only.",
    }
    closure_path = output / "reviewed-consumer-inputs.json"
    ci_native.write(closure_path, auth.encoded(closure), 0o600)
    if auth.parsed(auth.read(closure_path)) != closure:
        raise ValueError("reviewed consumer input closure failed readback")

    installed_inventory = ci_sdk.component_inventory(sdk_root)
    projects: dict[str, Path] = {}
    locks: dict[str, Path] = {}
    lock_records = []
    project_root = work / "sdk-projects"
    project_root.mkdir(mode=0o700)
    for name in BUILD_NAMES:
        project = project_root / name / "sdk"
        project.parent.mkdir(mode=0o700)
        if project.exists() or project.is_symlink():
            raise ValueError(name + " SDK project copy destination is not fresh")
        shutil.copytree(sdk_root, project, symlinks=True, copy_function=shutil.copy2)
        project_inventory = ci_sdk.component_inventory(project)
        if project_inventory != installed_inventory:
            raise ValueError(name + " SDK project copy differs from installed SDK inventory")
        supervisor.check_limits("verified SDK project copy " + name)
        lock_path = work / "sdk-locks" / (name + ".json")
        lock_path.parent.mkdir(mode=0o700, exist_ok=True)
        _, locked, _, _ = _run_cli_json(
            supervisor, cli, ["lock", "--prefix", install_area, "--selection", selection_path,
                              "--project", project, "--output", lock_path],
            label="lock-" + name, cwd=work)
        if (locked.get("status") != "locked" or locked.get("output") != str(lock_path)
                or locked.get("receipt_sha256") != receipt_sha
                or locked.get("sdk_manifest_sha256") != _sha256(project / "contract/sdk.json")
                or lock_path.is_symlink() or not lock_path.is_file()):
            raise ValueError(name + " native direct lock did not bind the real installation")
        projects[name] = project
        locks[name] = lock_path
        lock_records.append({"name": name, "command": [str(cli), "lock", "--prefix", str(install_area),
            "--selection", str(selection_path), "--project", str(project), "--output", str(lock_path)],
            "lock_sha256": _sha256(lock_path), "result": locked,
            "project_inventory_sha256": auth.sha(auth.encoded(project_inventory))})
        supervisor.check_limits("direct lock " + name)

    readonly_roots = [Path(row["resolved_path"]) for row in supervisor.native_static_roots]
    builds = []
    for name in BUILD_NAMES:
        builds.append(_build_one(
            name, cli, xtask, adapter, supervisor, projects[name], locks[name],
            policy_path, closure_path, output, work,
            readonly_roots, observed=name != "ordinary"))
        ci_native._check_limits(supervisor, "completed " + name + " metadata build")

    copied_logs = _copy_supervisor_logs(supervisor, output)
    # Executables are useful for byte-level review, but only retain them after
    # all mandatory logs, receipts and raw metadata archives fit the output cap.
    for build in builds:
        source = Path(build.pop("_native_source_path"))
        native = build["native_executable"]
        if (ci_sdk.directory_accounting(output)[0] + native["bytes"] + 1024 * 1024
                <= ci_sdk.MAX_OUTPUT_BYTES):
            destination = output / "builds" / build["name"] / "AMIRUST"
            copied = _copy_file(source, destination, build["name"] + " exact AMIRUST")
            native.update({"retained": True, "path": str(destination.relative_to(output)),
                           "sha256": copied["sha256"], "bytes": copied["bytes"]})
        _output_limit(output, "optional AMIRUST copies")

    pairwise = []
    for left_index, left in enumerate(builds):
        for right in builds[left_index + 1:]:
            left_rows = left["receipt"]["canonical_artifacts"]
            right_rows = right["receipt"]["canonical_artifacts"]
            pairwise.append({"left": left["name"], "right": right["name"],
                             "differences": _row_differences(left_rows, right_rows)})
    reference_differences = {build["name"]: _row_differences(
        build["receipt"]["canonical_artifacts"], expected_rows) for build in builds}

    _output_limit(output, "all retained diagnostic evidence")
    _regular_file(original_policy_path, "original consumer policy",
                  expected_bytes=POLICY_BYTES, expected_sha256=POLICY_SHA256)
    _regular_file(launcher, "original Linux launcher", expected_bytes=LAUNCHER_BYTES,
                  expected_sha256=LAUNCHER_SHA256)
    source_identity = {"original_source_sha": SOURCE, "original_workflow_sha": SOURCE,
                       "original_run_id": RUN_ID,
                       "diagnostic_source_commit": verifier_source_commit}
    report = {
        "schema": "ami-rust-rc1-linux-metadata-probe-v1",
        "status": "DIAGNOSTIC_COMPLETE_NOT_RC1_ACCEPTANCE",
        "host": HOST,
        "source_identity": source_identity,
        "capacity_preflight": capacity,
        "claim": "Reproduces authentic original Linux SDK verification and install, then compares one ordinary supervised native build with two builds admitted by the existing strict Linux observer. This report is diagnostic evidence only.",
        "inputs": {"bundle": _regular_file(bundle / "release.json", "original SDK release manifest"),
                   "original_policy": _regular_file(original_policy_path, "original policy",
                       expected_bytes=POLICY_BYTES, expected_sha256=POLICY_SHA256),
                   "remapped_policy_sha256": _sha256(policy_path),
                   "launcher": _regular_file(launcher, "original launcher",
                       expected_bytes=LAUNCHER_BYTES, expected_sha256=LAUNCHER_SHA256),
                   "authenticated_publisher_report": verified_report},
        "verifier_tool_bootstrap": {"source_commit": tool_receipt["source_commit"],
                                    "metadata_receipt": str(tool_receipt_path),
                                    "receipt_sha256": _sha256(tool_receipt_path),
                                    "tools": tool_receipt["tools"], "roots": tool_receipt["roots"]},
        "installation": {"prefix": str(install_area), "sdk_manifest_path": str(manifest_path),
                         "sdk_manifest_sha256": _sha256(manifest_path),
                         "install_receipt_sha256": receipt_sha,
                         "component_inventory_sha256": auth.sha(auth.encoded(installed_inventory)),
                         "verified_component_roots": {name: str(provision["component_roots"][name])
                                                       for name in COMPONENTS},
                         "component_inventories": provision["component_inventories"]},
        "locks": lock_records,
        "builds": builds,
        "comparisons": {"pairwise_canonical_artifact_rows": pairwise,
                        "accepted_native_reference_dependencies": {
                            "reference_sha256": _sha256(native_reference_path),
                            "differences_by_build": reference_differences}},
        "supervisor_logs": copied_logs,
        "supervision": ci_native._supervision_summary(supervisor),
        "output_bytes_before_report": ci_sdk.directory_accounting(output)[0],
        "acceptance": {"reference_changed": False, "acceptance_claimed": False,
                       "differences_are_reported_without_gate_judgment": True},
    }
    report_path = output / "metadata-probe-report.json"
    _write_new(report_path, report)
    _output_limit(output, "final metadata probe report")
    report_readback = _read_json(report_path, 4 * 1024**2)
    if report_readback != report:
        raise ValueError("final metadata probe report failed full readback")
    ci_native._check_limits(supervisor, "final metadata diagnostic report")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-rust", required=True)
    parser.add_argument("--python-bootstrap-root", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--original-policy", required=True)
    parser.add_argument("--launcher", required=True)
    args = parser.parse_args()
    try:
        report = run(args)
    except Exception as error:
        print(f"metadata probe refused: {error}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1
    print(json.dumps({"status": report["status"], "report": str(Path(args.output) / "metadata-probe-report.json"),
                      "builds": len(report["builds"]),
                      "pairwise_difference_counts": [len(row["differences"])
                          for row in report["comparisons"]["pairwise_canonical_artifact_rows"]]},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
