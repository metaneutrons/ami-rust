#!/usr/bin/env python3
"""Temporary outer monitor for internal native Cargo development."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import resource
import struct
import subprocess
import sys
import time
import types


PROPOSAL_BASE_HEAD = "2bc4625d52576f232763f56d7e12f4b82b8ecbc8"
PROPOSAL_BASE_TREE = "0420172743be74f332addf14146af97dfef15570"
CI_CARGO_SHA256 = "3f431b9fbb2352890fbcbdbdd8bf6102b1d12cb076507cf6eb298a9e27e23d70"
RESOURCE_SHA256 = "b9a5fbfff842847c30b5f56ea4e1d3a368f4bda30689f0407ed9d33610571646"
MAX_RSS = 4 * 1024**3
MAX_WORKSPACE = 12 * 1024**3
MAX_LOGS = 16 * 1024**2
MAX_PHASE_SECONDS = 1200
MAX_STEP_SECONDS = 4500
CAMPAIGN_SECONDS = 5400
REVIEW_RESERVE_SECONDS = 300
PARENT_RSS_RESERVE = 512 * 1024**2
HELPER_RSS_REQUEST = 3758096384
EXPECTED_SCHEMA = "ami-rust-native-cargo-workflow-result-v1"
WRAPPER_SCHEMA = "ami-rust-native-cargo-supervision-result-v1"
INSPECTION_SCHEMA = "ami-rust-native-cargo-binary-inspection-v1"
EXPECTED_HELPER_LIMITS = {
    "seconds": MAX_PHASE_SECONDS,
    "rss_bytes": HELPER_RSS_REQUEST,
    "workspace_bytes": MAX_WORKSPACE,
    "log_bytes": MAX_LOGS,
}
EXPECTED_NEGATIVE_CONTROLS = {
    "actual-cli-child-exit-seven": 7,
    "expected-corrupted-overlay-receipt-rejection": 2,
    "expected-wrong-host-rejection": 2,
}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def campaign_timeout(start_epoch: int, now_epoch: int, *, campaign: int = CAMPAIGN_SECONDS,
                     reserve: int = REVIEW_RESERVE_SECONDS,
                     step_cap: int = MAX_STEP_SECONDS) -> int:
    if any(type(value) is not int for value in (start_epoch, now_epoch, campaign, reserve, step_cap)):
        raise ValueError("campaign clock values must be integers")
    remaining = campaign - (now_epoch - start_epoch) - reserve
    if remaining <= 0:
        raise ValueError("campaign has no time left outside the review reserve")
    return min(step_cap, remaining)


def native_identity_matches(system: str, machine: str, triple: str) -> bool:
    return (system, machine.lower(), triple) in {
        ("Linux", "x86_64", "x86_64-unknown-linux-gnu"),
        ("Linux", "aarch64", "aarch64-unknown-linux-gnu"),
        ("Darwin", "arm64", "aarch64-apple-darwin"),
        ("Darwin", "aarch64", "aarch64-apple-darwin"),
    }


def roots_are_disjoint(*roots: Path) -> bool:
    resolved = [path.resolve(strict=False) for path in roots]
    for index, left in enumerate(resolved):
        for right in resolved[index + 1:]:
            if left == right or left.is_relative_to(right) or right.is_relative_to(left):
                return False
    return True


def _gzip_size(path: Path) -> int:
    if path.stat().st_size < 4:
        raise ValueError("compressed log has no complete gzip size trailer: " + str(path))
    with path.open("rb") as stream:
        stream.seek(-4, os.SEEK_END)
        (size,) = struct.unpack("<I", stream.read(4))
    return size


def logical_log_bytes(*roots: Path) -> int:
    """Count raw logs and known compressed helper/setup logs once per stream."""
    streams: dict[Path, int] = {}
    for root in roots:
        for path in root.rglob("*"):
            try:
                mode = path.lstat().st_mode
            except FileNotFoundError:
                continue
            if path.is_symlink() or not path.is_file():
                continue
            name = path.name
            if name.endswith(".log"):
                key = path.with_name(name[:-4])
                try:
                    size = path.stat().st_size
                except FileNotFoundError:
                    # compress_streams may remove this raw file between lstat and stat.
                    # Its completed gzip stream will be counted on the next sample.
                    continue
            elif name.endswith(".raw.gz"):
                relative = path.relative_to(root)
                helper_stream = relative.parts[0] in {"command-records", "helper-cli"}
                producer_record = len(relative.parts) == 4 and relative.parts[:3] in {
                    ("producer", "provision", "record"),
                    ("producer", "build", "record"),
                }
                if (not (helper_stream or producer_record)
                        or name not in {"stdout.raw.gz", "stderr.raw.gz"}):
                    continue
                key = path.with_name(name[:-7])
                if path.with_name(name[:-7] + ".log").is_file():
                    # The uncompressed stream remains authoritative during compression.
                    continue
                size = _gzip_size(path)
            elif name.endswith(".output.gz"):
                relative = path.relative_to(root)
                if relative.parts[0] != "setup":
                    continue
                key = path.with_name(name[:-10])
                sidecar = path.with_name(name[:-3] + ".bytes")
                if not sidecar.is_file():
                    # During the gzip-to-counter transition, the raw .log remains authoritative.
                    if path.with_name(name[:-10] + ".log").is_file():
                        continue
                    raise ValueError("compressed setup log is missing its byte counter: " + str(path))
                raw_count = sidecar.read_text(encoding="ascii").strip()
                if not raw_count.isdecimal():
                    raise ValueError("compressed setup log has a malformed byte counter: " + str(sidecar))
                size = int(raw_count)
                trailer_size = _gzip_size(path)
                if size < 2**32 and trailer_size != size:
                    raise ValueError("setup log counter differs from gzip trailer: " + str(path))
            else:
                continue
            streams[key] = max(streams.get(key, 0), size)
    return sum(streams.values())


def negative_control_valid(label: str, record: dict) -> bool:
    expected_exit = EXPECTED_NEGATIVE_CONTROLS.get(label)
    return bool(
        expected_exit is not None
        and record.get("schema") == "ami-rust-native-command-qualification-record-v1"
        and record.get("passed") is False
        and record.get("capture_complete") is True
        and record.get("capture_error") is None
        and record.get("child_exit_code") == expected_exit
        and record.get("child_signal") is None
    )


def validate_helper_record(label: str, request_sha256: str, record: dict) -> int:
    if (not isinstance(record, dict)
            or record.get("schema") != "ami-rust-native-command-qualification-record-v1"
            or record.get("request_sha256") != request_sha256
            or record.get("limits") != EXPECTED_HELPER_LIMITS
            or record.get("capture_complete") is not True
            or record.get("capture_error") is not None
            or record.get("child_signal") is not None):
        raise ValueError("native helper record schema, capture, request, or limits are invalid")
    peak = record.get("aggregate_peak_rss_bytes")
    workspace = record.get("workspace_bytes_at_finish")
    logs = record.get("log_bytes_at_finish")
    if (type(peak) is not int or peak < 0 or peak > HELPER_RSS_REQUEST
            or type(workspace) is not int or workspace < 0 or workspace > MAX_WORKSPACE
            or type(logs) is not int or logs < 0 or logs > MAX_LOGS):
        raise ValueError("native helper resource totals are missing or exceed their limits")
    for stream_name in ("stdout", "stderr"):
        stream = record.get(stream_name)
        if (not isinstance(stream, dict) or type(stream.get("bytes")) is not int
                or stream["bytes"] < 0 or not isinstance(stream.get("sha256"), str)
                or len(stream["sha256"]) != 64):
            raise ValueError("native helper stream counters are malformed")
    if record.get("passed") is False:
        if not negative_control_valid(label, record):
            raise ValueError("native helper rejected an unexpected phase: " + label)
        if record.get("refusal") != f"child exited with status {EXPECTED_NEGATIVE_CONTROLS[label]}":
            raise ValueError("named negative control failed for a resource or capture reason")
    elif record.get("passed") is not True or record.get("child_exit_code") != 0 or record.get("refusal") is not None:
        raise ValueError("native helper positive phase did not pass with child exit zero")
    return peak


def validate_inner_result(path: Path, triple: str, head: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("inner typed result is missing or malformed") from error
    if (not isinstance(value, dict)
            or value.get("schema") != EXPECTED_SCHEMA
            or value.get("status") != "PREREQUISITE_ONLY"
            or value.get("exit_code") != 0
            or value.get("native_host") != triple
            or value.get("head") != head
            or value.get("source_head") != head):
        raise ValueError("inner typed result did not pass its schema, status, host, and source bindings")
    return value


def validate_binary_inspection(path: Path, triple: str, managed: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("native Cargo binary inspection is missing or malformed") from error
    expected = {
        "x86_64-unknown-linux-gnu": ("ELF", "x86_64"),
        "aarch64-unknown-linux-gnu": ("ELF", "aarch64"),
        "aarch64-apple-darwin": ("Mach-O", "arm64"),
    }.get(triple)
    if (expected is None or not isinstance(value, dict)
            or value.get("schema") != INSPECTION_SCHEMA
            or value.get("status") != "PASS"
            or value.get("host") != triple
            or (value.get("format"), value.get("architecture")) != expected):
        raise ValueError("native Cargo binary inspection format, architecture, or host is invalid")

    root = managed.resolve(strict=True)

    def check_record(field: str) -> Path:
        raw = value.get(field)
        if not isinstance(raw, str) or not Path(raw).is_absolute():
            raise ValueError("native Cargo inspection record path is missing: " + field)
        record = Path(raw).resolve(strict=True)
        if not record.is_file() or not record.is_relative_to(root):
            raise ValueError("native Cargo inspection record path escapes managed root: " + field)
        return record

    if expected[0] == "ELF":
        descriptions = {
            "x86_64": "Advanced Micro Devices X86-64",
            "aarch64": "AArch64",
        }
        if value.get("format_description") != descriptions[expected[1]]:
            raise ValueError("ELF inspection description does not match the native architecture")
        for field in ("header_record", "program_headers_record", "dynamic_dependencies_record"):
            check_record(field)
        interpreter = value.get("interpreter")
        runtime_record = value.get("runtime_dependencies_record")
        if interpreter is None:
            if runtime_record is not None:
                raise ValueError("static ELF inspection unexpectedly records an ldd result")
        else:
            allowed = {
                "/lib64/ld-linux-x86-64.so.2",
                "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                "/lib/ld-linux-aarch64.so.1",
                "/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1",
            }
            if interpreter not in allowed or not isinstance(runtime_record, str):
                raise ValueError("ELF runtime interpreter or ldd record is not admitted")
            check_record("runtime_dependencies_record")
    else:
        description = value.get("format_description")
        if (not isinstance(description, str)
                or "Mach-O 64-bit executable arm64" not in description
                or value.get("interpreter") is not None):
            raise ValueError("Mach-O inspection does not prove an arm64 executable")
        format_record = check_record("format_record")
        dependencies_record = check_record("dependencies_record")
        dependencies = value.get("system_dependencies")
        if (not isinstance(dependencies, list) or not dependencies
                or any(not isinstance(item, str) or not item.startswith((
                    "/System/Library/Frameworks/",
                    "/System/Library/PrivateFrameworks/",
                    "/usr/lib/",
                )) for item in dependencies)
                or dependencies != sorted(set(dependencies))):
            raise ValueError("Mach-O dependencies are empty, non-system, duplicated, or unsorted")

        def helper_stdout(record: Path) -> str:
            raw_log = record.parent / "stdout.raw.gz"
            try:
                with gzip.open(raw_log, "rb") as stream:
                    payload = stream.read(1024 * 1024 + 1)
            except (OSError, EOFError) as error:
                raise ValueError("Mach-O inspection helper stdout is missing or malformed") from error
            if len(payload) > 1024 * 1024:
                raise ValueError("Mach-O inspection helper stdout exceeds its bounded size")
            return payload.decode("utf-8", "replace")

        observed_description = helper_stdout(format_record).replace("\r", "").replace("\n", "")
        if observed_description != description:
            raise ValueError("Mach-O format description differs from the retained file output")
        dependency_lines = helper_stdout(dependencies_record).splitlines()
        observed_dependencies = [line.strip().split()[0] for line in dependency_lines[1:] if line.strip()]
        if (len(observed_dependencies) != len(set(observed_dependencies))
                or sorted(observed_dependencies) != dependencies):
            raise ValueError("Mach-O dependency list differs from the retained otool output")
    return value


def _load_supervisor(repo: Path):
    module_path = repo / "release/ci_cargo.py"
    if sha256(module_path) != CI_CARGO_SHA256:
        raise ValueError("temporary monitor source differs from its frozen digest")
    spec = importlib.util.spec_from_file_location("native_host_ci_cargo", module_path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load the existing temporary Cargo supervisor")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _own_hwm_bytes() -> int:
    # Linux reports KiB; Darwin reports bytes.
    raw = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    system = platform.system()
    if system == "Linux":
        return raw * 1024
    if system == "Darwin":
        return raw
    raise ValueError("unsupported native supervisor OS: " + system)


def _verify_inputs(repo: Path, managed: Path, outer_output: Path) -> tuple[str, str, str, Path]:
    env = os.environ
    required = ("RUNNER_TEMP", "GITHUB_WORKSPACE", "GITHUB_SHA", "GITHUB_REPOSITORY",
                "GITHUB_REF", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "NATIVE_HOST_TRIPLE",
                "NATIVE_EVENT_NAME", "NATIVE_REPOSITORY", "NATIVE_REF_NAME",
                "NATIVE_REF_PROTECTED", "NATIVE_RUN_ID", "NATIVE_RUN_ATTEMPT",
                "NATIVE_CAMPAIGN_START_EPOCH", "NATIVE_MANAGED_ROOT", "NATIVE_OUTER_OUTPUT")
    if any(not env.get(key) for key in required):
        raise ValueError("required protected workflow inputs are missing")
    triple = env["NATIVE_HOST_TRIPLE"]
    machine = platform.machine().lower()
    if not native_identity_matches(platform.system(), machine, triple):
        raise ValueError("runner architecture does not match the requested native host")
    if (env["NATIVE_EVENT_NAME"] != "workflow_dispatch"
            or env["NATIVE_REPOSITORY"] != "metaneutrons/ami-rust"
            or env["NATIVE_REF_NAME"] != "refs/heads/main"
            or env["NATIVE_REF_PROTECTED"] != "true"
            or env["GITHUB_REPOSITORY"] != env["NATIVE_REPOSITORY"]
            or env["GITHUB_REF"] != env["NATIVE_REF_NAME"]
            or env["GITHUB_RUN_ID"] != env["NATIVE_RUN_ID"]
            or env["GITHUB_RUN_ATTEMPT"] != env["NATIVE_RUN_ATTEMPT"]):
        raise ValueError("workflow is not the expected protected manual run")
    repo = repo.resolve(strict=True)
    managed = managed.resolve(strict=True)
    outer_output = outer_output.resolve(strict=True)
    runner_temp = Path(env["RUNNER_TEMP"]).resolve(strict=True)
    expected_repo = (Path(env["GITHUB_WORKSPACE"]) / "source").resolve(strict=True)
    if repo != expected_repo:
        raise ValueError("repo argument does not match the checked-out workflow source path")
    attempt_root = runner_temp / "ami-rust-native-cargo" / (env["GITHUB_RUN_ID"] + "-" + env["GITHUB_RUN_ATTEMPT"]) / triple
    if managed != attempt_root / "managed" or outer_output != attempt_root / "outer-output":
        raise ValueError("managed and outer output paths do not match the disjoint attempt roots")
    if not roots_are_disjoint(repo, managed, outer_output):
        raise ValueError("source, managed, and outer-output roots overlap")
    for path in (repo, managed, outer_output):
        if path.is_symlink():
            raise ValueError("a protected root is a symlink")
    if Path(env["NATIVE_MANAGED_ROOT"]).resolve(strict=True) != managed:
        raise ValueError("managed-root environment binding differs from the wrapper argument")
    if Path(env["NATIVE_OUTER_OUTPUT"]).resolve(strict=True) != outer_output:
        raise ValueError("outer-output environment binding differs from the wrapper argument")
    if (repo / ".git").is_dir() is False:
        raise ValueError("checked-out source has no Git metadata")
    head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    tree = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=all"], text=True)
    if head != env["GITHUB_SHA"] or dirty:
        raise ValueError("source checkout does not match the clean protected workflow SHA")
    if sha256(repo / "release/ci-resources.json") != RESOURCE_SHA256:
        raise ValueError("resource policy differs from the frozen budget")
    artifact = outer_output / "artifact"
    if not artifact.is_dir() or artifact.is_symlink():
        raise ValueError("outer output does not contain a fresh artifact directory")
    start = int(env["NATIVE_CAMPAIGN_START_EPOCH"])
    return triple, head, tree, artifact


def _supervised_env() -> dict[str, str]:
    keys = (
        "PATH", "HOME", "RUNNER_TEMP", "GITHUB_WORKSPACE", "GITHUB_SHA", "GITHUB_REPOSITORY",
        "GITHUB_REF", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "NATIVE_HOST_TRIPLE",
        "NATIVE_EVENT_NAME", "NATIVE_REPOSITORY", "NATIVE_REF_NAME", "NATIVE_REF_PROTECTED",
        "NATIVE_RUN_ID", "NATIVE_RUN_ATTEMPT", "NATIVE_CAMPAIGN_START_EPOCH",
        "NATIVE_MANAGED_ROOT", "NATIVE_OUTER_OUTPUT",
    )
    result = {key: os.environ[key] for key in keys if os.environ.get(key) is not None}
    result.setdefault("PATH", "/usr/bin:/bin")
    return result


def _native_phase_peak(managed: Path) -> int:
    peak = 0
    index_paths = sorted((managed / "phase-index").glob("*.json"))
    if not index_paths:
        raise ValueError("native phase index is missing or empty")
    seen_records = set()
    for index_path in index_paths:
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("native phase index is missing or malformed: " + str(index_path)) from error
        if (not isinstance(index, dict)
                or index.get("schema") != "ami-rust-native-cargo-phase-input-index-v1"
                or not isinstance(index.get("phase"), str)
                or not isinstance(index.get("request_sha256"), str)
                or len(index["request_sha256"]) != 64
                or not isinstance(index.get("record"), str)
                or index.get("limits") != EXPECTED_HELPER_LIMITS):
            raise ValueError("native phase index has invalid fields: " + str(index_path))
        record_path = Path(index["record"]).resolve(strict=True)
        if not record_path.is_relative_to(managed.resolve(strict=True)) or record_path in seen_records:
            raise ValueError("native phase index escapes or repeats a record path")
        seen_records.add(record_path)
        try:
            record = json.loads(record_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("native helper record is missing or malformed: " + str(record_path)) from error
        try:
            value = validate_helper_record(index["phase"], index["request_sha256"], record)
        except ValueError as error:
            raise ValueError(f"invalid native helper result {record_path}: {error}") from error
        peak = max(peak, value)
    record_paths = set((managed / "command-records").rglob("result.json"))
    if record_paths != seen_records:
        raise ValueError("native helper records and phase index entries do not match")
    return peak


def _retain_outer_logs(log_dir: Path, artifact: Path) -> None:
    paths = sorted(log_dir.iterdir())
    if (len(paths) != 2
            or any(path.is_symlink() or not path.is_file() or path.suffix != ".log" for path in paths)):
        raise ValueError("outer supervisor did not retain exactly two raw log streams")
    destination = artifact / "outer-logs"
    destination.mkdir(mode=0o700, exist_ok=False)
    for path in paths:
        os.replace(path, destination / path.name)
    log_dir.rmdir()


def run(repo: Path, managed: Path, outer_output: Path) -> int:
    started = time.monotonic()
    result_path = outer_output / "artifact/native-cargo-supervision-result.json"
    payload: dict = {
        "schema": WRAPPER_SCHEMA,
        "status": "FAILED",
        "claim": "temporary internal native Cargo prerequisite only",
        "limits": {
            "aggregate_rss_bytes": MAX_RSS,
            "managed_source_root_output_bytes": MAX_WORKSPACE,
            "aggregate_uncompressed_log_bytes": MAX_LOGS,
            "tool_phase_seconds": MAX_PHASE_SECONDS,
            "campaign_seconds": CAMPAIGN_SECONDS,
            "review_reserve_seconds": REVIEW_RESERVE_SECONDS,
            "native_helper_rss_request_bytes": HELPER_RSS_REQUEST,
            "python_bash_parent_reserve_bytes": PARENT_RSS_RESERVE,
        },
        "observation_boundaries": [
            "GitHub checkout and artifact upload are outside observation",
            "wrapper final-result serialization is outside observation",
            "no final no-Python proof is made",
        ],
    }
    full_peak = 0
    parent_peak = 0
    native_peak = 0
    try:
        triple, head, tree, artifact = _verify_inputs(repo, managed, outer_output)
        repo = repo.resolve(strict=True)
        managed = managed.resolve(strict=True)
        outer_output = outer_output.resolve(strict=True)
        start_epoch = int(os.environ["NATIVE_CAMPAIGN_START_EPOCH"])
        timeout = campaign_timeout(start_epoch, int(time.time()))
        module = _load_supervisor(repo)
        log_dir = managed / "outer-logs"
        log_dir.mkdir(mode=0o700, exist_ok=False)
        supervisor = module.Supervisor(managed, outer_output, _supervised_env(), log_dir)
        # Count the full pre-existing roots, including preflight and artifact data.
        supervisor.initial_work_bytes = 0
        supervisor.initial_output_bytes = 0
        supervisor.logs_bytes = types.MethodType(
            lambda self: logical_log_bytes(self.work, self.output), supervisor)
        original_rss_group = module.rss_group
        phase_marker = managed / "native-cargo-active-phase"

        def observe_rss(pid: int, rows=None) -> int:
            nonlocal full_peak, parent_peak
            rows = module.process_rows() if rows is None else rows
            descendant = original_rss_group(pid, rows)
            own = _own_hwm_bytes()
            combined = own + descendant
            full_peak = max(full_peak, combined)
            if phase_marker.exists():
                direct = sum(kib * 1024 for _, _, pgid, kib in rows if pgid == pid)
                phase_parent = own + direct
                parent_peak = max(parent_peak, phase_parent)
                if phase_parent > PARENT_RSS_RESERVE:
                    raise RuntimeError("active native phase exceeded the 512 MiB Python/Bash parent reserve")
            return combined

        module.rss_group = observe_rss
        try:
            supervisor.run(["bash", str(repo / "tools/qualify-native-cargo.sh")],
                           cwd=repo, label="native-cargo-producer", timeout=timeout)
        finally:
            module.rss_group = original_rss_group
            _retain_outer_logs(log_dir, artifact)
        native_peak = _native_phase_peak(managed)
        conservative_peak = max(full_peak, native_peak + parent_peak)
        if conservative_peak > MAX_RSS:
            raise ValueError("conservative aggregate RSS bound exceeds the unchanged 4 GiB ceiling")
        managed_peak = supervisor.peak_workspace
        logs_peak = logical_log_bytes(managed, outer_output)
        if managed_peak > MAX_WORKSPACE or logs_peak > MAX_LOGS:
            raise ValueError("final managed-root or aggregate log accounting exceeds its ceiling")
        inner_path = artifact / "native-cargo-result.json"
        inner = validate_inner_result(inner_path, triple, head)
        inspection_path = managed / "native-cargo-binary-inspection.json"
        validate_binary_inspection(inspection_path, triple, managed)
        payload.update({
            "status": "PREREQUISITE_ONLY",
            "repository": os.environ["GITHUB_REPOSITORY"],
            "ref": os.environ["GITHUB_REF"],
            "head": head,
            "source_tree": tree,
            "proposal_base": {"head": PROPOSAL_BASE_HEAD, "tree": PROPOSAL_BASE_TREE},
            "native_host": triple,
            "source_ci_cargo_sha256": sha256(repo / "release/ci_cargo.py"),
            "resource_policy_sha256": sha256(repo / "release/ci-resources.json"),
            "wrapper_sha256": sha256(Path(__file__).resolve()),
            "shell_producer_sha256": sha256(repo / "tools/qualify-native-cargo.sh"),
            "inner_result_sha256": sha256(inner_path),
            "binary_inspection_sha256": sha256(inspection_path),
            "observed": {
                "aggregate_rss_upper_bound_bytes": conservative_peak,
                "full_process_tree_plus_python_peak_bytes": full_peak,
                "native_phase_peak_bytes": native_peak,
                "python_bash_parent_peak_bytes": parent_peak,
                "managed_source_root_output_peak_bytes": managed_peak,
                "aggregate_uncompressed_log_bytes_at_finish": logs_peak,
                "tool_phase_limit_seconds": MAX_PHASE_SECONDS,
                "outer_phase_elapsed_seconds": round(time.monotonic() - started, 3),
                "outer_phase_timeout_seconds": timeout,
            },
            "inner_status": inner["status"],
        })
    except BaseException as error:
        payload["error"] = f"{type(error).__name__}: {str(error)[:500]}"
        payload["observed"] = {
            "aggregate_rss_upper_bound_bytes": max(full_peak, native_peak + parent_peak),
            "full_process_tree_plus_python_peak_bytes": full_peak,
            "native_phase_peak_bytes": native_peak,
            "python_bash_parent_peak_bytes": parent_peak,
            "outer_phase_elapsed_seconds": round(time.monotonic() - started, 3),
        }
    payload["elapsed_seconds"] = round(time.monotonic() - started, 3)
    temporary = result_path.with_suffix(".json.tmp")
    try:
        temporary.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, result_path)
    except OSError as error:
        print(f"could not serialize supervision result: {error}", file=sys.stderr)
        return 1
    if payload["status"] == "PREREQUISITE_ONLY":
        try:
            for _ in range(4):
                final_bytes = (module.directory_bytes(repo) + module.directory_bytes(managed)
                               + module.directory_bytes(outer_output))
                payload["observed"]["managed_source_root_output_bytes_after_serialization"] = final_bytes
                if final_bytes > MAX_WORKSPACE:
                    payload["status"] = "FAILED"
                    payload["error"] = "managed source/root/output bytes exceed the ceiling after wrapper result serialization"
                temporary.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
                os.replace(temporary, result_path)
                after_write = (module.directory_bytes(repo) + module.directory_bytes(managed)
                               + module.directory_bytes(outer_output))
                if after_write == final_bytes:
                    break
            else:
                payload["status"] = "FAILED"
                payload["error"] = "post-serialization workspace receipt did not stabilize"
                temporary.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
                os.replace(temporary, result_path)
        except BaseException as error:
            payload["status"] = "FAILED"
            payload["error"] = f"post-serialization workspace check failed: {type(error).__name__}: {str(error)[:400]}"
            try:
                temporary.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
                os.replace(temporary, result_path)
            except OSError as write_error:
                print(f"could not record post-serialization workspace failure: {write_error}", file=sys.stderr)
                return 1
    if payload["status"] != "PREREQUISITE_ONLY":
        print(payload.get("error", "supervision failed"), file=sys.stderr)
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--managed-root", type=Path, required=True)
    parser.add_argument("--outer-output", type=Path, required=True)
    args = parser.parse_args()
    try:
        return run(args.repo, args.managed_root, args.outer_output)
    except BaseException as error:
        print(f"wrapper input error: {type(error).__name__}: {str(error)[:500]}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
