#!/usr/bin/env python3
"""Bounded plan and direct compiler runner for the frozen Nouveau C sources.

The input compiler commands are parsed as data by :mod:`csdk_recipes`. This
module remaps only their declared source, build, include, sysroot, output, and
compiler operands. It does not invoke Ninja, a shell, or an archive tool.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import subprocess
import sys
import threading
import time
from typing import Any

_RECIPES_PATH = Path(__file__).resolve().with_name("csdk_recipes.py")
_RECIPES_SPEC = importlib.util.spec_from_file_location("_csdk_nouveau_recipes", _RECIPES_PATH)
if _RECIPES_SPEC is None or _RECIPES_SPEC.loader is None:  # pragma: no cover - filesystem failure
    raise ImportError("cannot load sibling csdk_recipes.py")
csdk_recipes = importlib.util.module_from_spec(_RECIPES_SPEC)
_RECIPES_SPEC.loader.exec_module(csdk_recipes)

_CI_CARGO_PATH = Path(__file__).resolve().with_name("ci_cargo.py")
_CI_CARGO_SPEC = importlib.util.spec_from_file_location("_csdk_nouveau_ci_cargo", _CI_CARGO_PATH)
if _CI_CARGO_SPEC is None or _CI_CARGO_SPEC.loader is None:  # pragma: no cover - filesystem failure
    raise ImportError("cannot load sibling ci_cargo.py")
ci_cargo = importlib.util.module_from_spec(_CI_CARGO_SPEC)
_CI_CARGO_SPEC.loader.exec_module(ci_cargo)


EXPECTED_OBJECTS = 825
ARCHIVE_OUTPUT = "SYS/Developer/lib/libdrm_nouveau.a"
ARCHIVE_RULE = "C_STATIC_LIBRARY_LINKER__hidd-nouveau-drm_Release"
COMPILER_RELATIVE = "bin/clang-11"
MAX_JOBS = 2
MAX_COMMAND_SECONDS = 1200
MAX_LOG_BYTES_PER_STREAM = 512 * 1024
PARENT_SUMMARY_RESERVE = 64 * 1024
MAX_AGGREGATE_SAVED_LOG_BYTES = 16 * 1024 * 1024 - PARENT_SUMMARY_RESERVE
FAILURE_LOG_RESERVE = MAX_JOBS * 2 * MAX_LOG_BYTES_PER_STREAM
MAX_REGULAR_SAVED_LOG_BYTES = MAX_AGGREGATE_SAVED_LOG_BYTES - FAILURE_LOG_RESERVE
MAX_TOTAL_WARNING_BYTES = MAX_AGGREGATE_SAVED_LOG_BYTES
MAX_RECIPE_BYTES = 80 * 1024 * 1024
SCHEMA = "ami-rust-nouveau-compile-plan-v1"
TRUNCATION_MARKER = b"\n[truncated: retained bounded output prefix; compile attempt failed]\n"


class NouveauError(ValueError):
    """Raised when a frozen compile input or output boundary is invalid."""


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _absolute_path(value: os.PathLike[str] | str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise NouveauError(label + " must be absolute")
    if ".." in path.parts:
        raise NouveauError(label + " must not contain parent traversal")
    return path


def _reject_symlink_components(path: Path, label: str) -> None:
    """Reject a symlink at every existing component, including dangling ones."""
    cursor = Path(path.anchor)
    for component in path.parts[1:]:
        cursor = cursor / component
        if cursor.is_symlink():
            raise NouveauError(label + " traverses a symlink: " + str(cursor))


def _require_directory(value: os.PathLike[str] | str, label: str) -> Path:
    path = _absolute_path(value, label)
    _reject_symlink_components(path, label)
    if not path.is_dir():
        raise NouveauError(label + " is not an existing directory: " + str(path))
    return path


def _require_regular_file(value: os.PathLike[str] | str, label: str) -> Path:
    path = _absolute_path(value, label)
    _reject_symlink_components(path, label)
    if not path.is_file():
        raise NouveauError(label + " is not a regular file: " + str(path))
    return path


def _intersects(left: Path, right: Path) -> bool:
    return left == right or left in right.parents or right in left.parents


def _require_disjoint(left: Path, right: Path, label: str) -> None:
    if _intersects(left, right):
        raise NouveauError(label + " paths overlap: " + str(left) + " and " + str(right))


def _safe_relative(value: str, label: str) -> PurePosixPath:
    if (not isinstance(value, str) or not value or "\\" in value or "\0" in value
            or ":" in value):
        raise NouveauError(label + " is not a portable relative path")
    path = PurePosixPath(value)
    if (path.is_absolute() or path.as_posix() != value
            or any(part in ("", ".", "..") for part in value.split("/"))):
        raise NouveauError(label + " is not normalized: " + value)
    return path


def _under(path: Path, root: Path, label: str) -> Path:
    try:
        return path.relative_to(root)
    except ValueError as exc:
        raise NouveauError(label + " escapes its declared root: " + str(path)) from exc


def _recipe_path(value: str, source_root: Path, build_root: Path, label: str) -> Path:
    """Map one declared ``AROS-NX`` recipe path to its concrete tree."""
    if value == csdk_recipes.BUILD_ROOT:
        return build_root
    if value.startswith(csdk_recipes.BUILD_PREFIX):
        relative = _safe_relative(value[len(csdk_recipes.BUILD_PREFIX):], label)
        return build_root.joinpath(*relative.parts)
    if value.startswith(csdk_recipes.SOURCE_PREFIX):
        relative = _safe_relative(value[len(csdk_recipes.SOURCE_PREFIX):], label)
        return source_root.joinpath(*relative.parts)
    raise NouveauError(label + " is outside the declared source/build prefixes: " + value)


def _output_path(value: str, build_root: Path, label: str) -> Path:
    relative = _safe_relative(value, label)
    return build_root.joinpath(*relative.parts)


def _archive_members(ninja_text: str) -> list[str]:
    matches = [edge for edge in csdk_recipes._ninja_edges(ninja_text)
               if ARCHIVE_OUTPUT in edge["outputs"]]
    if len(matches) != 1 or matches[0]["outputs"] != [ARCHIVE_OUTPUT]:
        raise NouveauError("Ninja must declare one unambiguous Nouveau DRM archive edge")
    dependencies = matches[0]["dependencies"]
    if not dependencies or dependencies[0] != ARCHIVE_RULE:
        raise NouveauError("Nouveau DRM archive edge uses an unexpected rule")
    tokens = dependencies[1:]
    boundary = next((i for i, token in enumerate(tokens) if token in ("|", "||")), len(tokens))
    members = tokens[:boundary]
    if len(members) != EXPECTED_OBJECTS or len(set(members)) != EXPECTED_OBJECTS:
        raise NouveauError("Nouveau DRM archive must list exactly 825 unique object members")
    if any(not member.startswith(csdk_recipes.NOUVEAU_OBJECT_PREFIX[len(csdk_recipes.BUILD_PREFIX):])
           or not member.endswith(".c.obj") for member in members):
        raise NouveauError("Nouveau DRM archive contains a non-Nouveau object member")
    for member in members:
        _safe_relative(member, "Nouveau DRM archive member")
    return members


_FROZEN_COMPILER = re.compile(
    r"\$\{CROSS_TOOLCHAIN_ROOT\}/v0\.1\.4/macos-aarch64/pc-x86_64/[0-9a-f]{64}/toolchain/bin/clang\Z"
)


def _map_path_operand(value: str, source_root: Path, build_root: Path, label: str) -> str:
    path = _recipe_path(value, source_root, build_root, label)
    if not path.is_absolute():  # roots are required to be absolute; this is defensive.
        raise NouveauError(label + " did not map to an absolute path")
    return str(path)


def _map_argv(raw_argv: list[str], record: dict, source_root: Path,
              build_root: Path, compiler: Path) -> tuple[list[str], Path, Path, list[Path]]:
    if not isinstance(raw_argv, list) or not raw_argv or any(not isinstance(x, str) for x in raw_argv):
        raise NouveauError("Nouveau compile record has an invalid argv")
    if not _FROZEN_COMPILER.fullmatch(raw_argv[0]):
        raise NouveauError("Nouveau compile record uses an unknown compiler placeholder")

    source_rel = _safe_relative(record.get("source"), "Nouveau source")
    if not str(source_rel).startswith("workbench/hidds/nouveau/") or source_rel.suffix != ".c":
        raise NouveauError("Nouveau compile source is outside its direct C source subtree")
    source = source_root.joinpath(*source_rel.parts)
    object_value = record.get("object")
    prefix = "build/pc-x86_64/"
    if not isinstance(object_value, str) or not object_value.startswith(prefix):
        raise NouveauError("Nouveau compile object is outside the declared build prefix")
    object_relative = _safe_relative(object_value[len(prefix):], "Nouveau object output")
    output = build_root.joinpath(*object_relative.parts)

    if raw_argv.count("-o") != 1 or raw_argv.count("-c") != 1:
        raise NouveauError("Nouveau compile argv must have exactly one -o and one -c")

    argv = list(raw_argv)
    argv[0] = str(compiler)
    output_seen = False
    source_seen = False
    include_paths: list[Path] = []
    index = 1
    while index < len(argv):
        token = argv[index]
        if token in ("-I", "-iquote"):
            if index + 1 >= len(argv):
                raise NouveauError("Nouveau compile argv has an incomplete " + token)
            value = argv[index + 1]
            mapped = _map_path_operand(value, source_root, build_root, token + " operand")
            mapped_path = Path(mapped)
            if not mapped_path.is_absolute():
                raise NouveauError("include path did not map to an absolute path")
            include_paths.append(mapped_path)
            argv[index + 1] = mapped
            index += 2
            continue
        if token.startswith("-iquote") and token != "-iquote":
            value = token[len("-iquote"):]
            mapped = _map_path_operand(value, source_root, build_root, "-iquote operand")
            include_paths.append(Path(mapped))
            argv[index] = "-iquote" + mapped
            index += 1
            continue
        if token.startswith("-I") and token != "-I":
            value = token[2:]
            mapped = _map_path_operand(value, source_root, build_root, "-I operand")
            include_paths.append(Path(mapped))
            argv[index] = "-I" + mapped
            index += 1
            continue
        if token == "--sysroot":
            if index + 1 >= len(argv):
                raise NouveauError("Nouveau compile argv has an incomplete --sysroot")
            mapped = _map_path_operand(argv[index + 1], source_root, build_root, "--sysroot operand")
            include_paths.append(Path(mapped))
            argv[index + 1] = mapped
            index += 2
            continue
        if token.startswith("--sysroot="):
            value = token[len("--sysroot="):]
            mapped = _map_path_operand(value, source_root, build_root, "--sysroot operand")
            include_paths.append(Path(mapped))
            argv[index] = "--sysroot=" + mapped
            index += 1
            continue
        if token == "-o":
            if index + 1 >= len(argv):
                raise NouveauError("Nouveau compile argv has an incomplete -o")
            mapped = _output_path(argv[index + 1], build_root, "Nouveau -o operand")
            if mapped != output:
                raise NouveauError("Nouveau -o operand differs from the compilation database object")
            argv[index + 1] = str(mapped)
            output_seen = True
            index += 2
            continue
        if token == "-c":
            if index + 1 >= len(argv):
                raise NouveauError("Nouveau compile argv has an incomplete -c")
            mapped = _map_path_operand(argv[index + 1], source_root, build_root, "Nouveau -c operand")
            if Path(mapped) != source:
                raise NouveauError("Nouveau -c operand differs from the compilation database source")
            argv[index + 1] = mapped
            source_seen = True
            index += 2
            continue

        # Unknown path spellings or historical CMake variables are never
        # passed through to the compiler, even when embedded in a flag.
        if (os.path.isabs(token) or re.match(r"^[A-Za-z]:[\\/]", token)
                or re.search(r"(?:^|[=,])/(?:[^,\s]+)?", token)
                or "$" in token or "AROS-NX/" in token or "CMakeFiles/" in token):
            raise NouveauError("Nouveau compile argv contains an unmapped path or placeholder: " + token)
        index += 1

    if not output_seen or not source_seen:
        raise NouveauError("Nouveau compile argv is missing its mapped source or output")
    argv.append("-ffile-prefix-map=" + str(source_root) + "=.")
    return argv, source, output, include_paths


def plan_nouveau(records: list[dict], ninja_text: str,
                 source_root: os.PathLike[str] | str,
                 build_root: os.PathLike[str] | str,
                 toolchain_root: os.PathLike[str] | str) -> dict:
    """Map the exact frozen 825-object archive recipe into a portable plan.

    ``records`` must be the parsed result of ``nouveau_compile_recipes``.
    Returned ``raw_argv`` vectors preserve the frozen token order independently
    from the concrete ``argv`` vectors that will be executed.
    """
    if not isinstance(records, list) or len(records) != EXPECTED_OBJECTS:
        raise NouveauError("Nouveau compile plan requires exactly 825 parsed records")
    if not isinstance(ninja_text, str):
        raise NouveauError("Ninja input must be text")
    source_root = _require_directory(source_root, "source root")
    build_root = _require_directory(build_root, "build root")
    toolchain_root = _require_directory(toolchain_root, "toolchain root")
    _require_disjoint(source_root, build_root, "source/build")
    _require_disjoint(source_root, toolchain_root, "source/toolchain")
    _require_disjoint(build_root, toolchain_root, "build/toolchain")

    archive_members = _archive_members(ninja_text)
    by_object: dict[str, dict] = {}
    by_source: set[str] = set()
    for row in records:
        if not isinstance(row, dict):
            raise NouveauError("Nouveau compile record must be an object")
        object_value = row.get("object")
        if not isinstance(object_value, str):
            raise NouveauError("Nouveau compile record is missing its object path")
        object_rel = _safe_relative(object_value, "Nouveau compile object")
        object_key = object_rel.as_posix()
        if object_key in by_object:
            raise NouveauError("duplicate Nouveau compile object: " + object_key)
        source_value = row.get("source")
        source_rel = _safe_relative(source_value, "Nouveau compile source")
        if source_rel.as_posix() in by_source:
            raise NouveauError("duplicate Nouveau compile source: " + source_rel.as_posix())
        by_source.add(source_rel.as_posix())
        by_object[object_key] = row

    if len(by_object) != EXPECTED_OBJECTS:
        raise NouveauError("Nouveau compile object set is incomplete")

    ordered_objects: list[Path] = []
    member_basenames: list[str] = []
    commands: list[dict] = []
    compiler = toolchain_root / COMPILER_RELATIVE
    for ninja_member in archive_members:
        object_value = "build/pc-x86_64/" + ninja_member
        row = by_object.get(object_value)
        if row is None:
            raise NouveauError("Ninja archive object is absent from the compile database: " + ninja_member)
        raw_argv = row.get("argv")
        argv, source, output, include_paths = _map_argv(
            raw_argv, row, source_root, build_root, compiler)
        _under(source, source_root, "Nouveau source")
        _under(output, build_root, "Nouveau object output")
        if _intersects(source, output):
            raise NouveauError("Nouveau object output overlaps a source file")
        ordered_objects.append(output)
        member_basename = PurePosixPath(ninja_member).name
        member_basenames.append(member_basename)
        commands.append({
            "source": str(source),
            "object": str(output),
            "member_basename": member_basename,
            "raw_argv": list(raw_argv),
            "argv": argv,
            "include_paths": [str(path) for path in include_paths],
        })

    ninja_set = set(archive_members)
    record_set = {
        object_key[len("build/pc-x86_64/"):]
        for object_key in by_object
        if object_key.startswith("build/pc-x86_64/")
    }
    if len(record_set) != EXPECTED_OBJECTS or record_set != ninja_set:
        raise NouveauError("Ninja archive object set differs from the 825 parsed compile records")
    if len(ordered_objects) != EXPECTED_OBJECTS or len(set(ordered_objects)) != EXPECTED_OBJECTS:
        raise NouveauError("mapped Nouveau object outputs are not 825 unique paths")

    # Validate all existing inputs, but never create a missing source/header
    # directory. A caller must materialize the exact header tree first.
    required_directories = {source_root, build_root, toolchain_root}
    required_directories.update(Path(item) for command in commands for item in command["include_paths"])
    for directory in sorted(required_directories, key=str):
        _reject_symlink_components(directory, "Nouveau input directory")
        if not directory.is_dir():
            raise NouveauError("Nouveau include or sysroot directory is missing: " + str(directory))
    for command in commands:
        source = Path(command["source"])
        _reject_symlink_components(source, "Nouveau source")
        if not source.is_file():
            raise NouveauError("Nouveau source file is missing: " + str(source))

    return {
        "schema": SCHEMA,
        "status": "PLANNED",
        "compiler": str(compiler),
        "toolchain_root": str(toolchain_root),
        "source_root": str(source_root),
        "build_root": str(build_root),
        "working_directory": str(build_root),
        "object_count": EXPECTED_OBJECTS,
        "archive_output": str(build_root / ARCHIVE_OUTPUT),
        "ordered_object_paths": [str(path) for path in ordered_objects],
        "member_basenames": member_basenames,
        "commands": commands,
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _validate_compiler(plan: dict, expected_sha256: str) -> Path:
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise NouveauError("expected compiler SHA-256 must be 64 lowercase hexadecimal characters")
    compiler = _require_regular_file(plan["compiler"], "pinned clang-11 compiler")
    if not os.access(compiler, os.X_OK):
        raise NouveauError("pinned clang-11 compiler is not executable")
    if _sha256_file(compiler) != expected_sha256:
        raise NouveauError("pinned clang-11 compiler byte SHA-256 differs")
    return compiler


def _safe_directory_creation(path: Path, root: Path) -> None:
    relative = _under(path, root, "Nouveau output directory")
    _reject_symlink_components(root, "build root")
    cursor = root
    for component in relative.parts:
        cursor = cursor / component
        if cursor.is_symlink():
            raise NouveauError("Nouveau output directory traverses a symlink: " + str(cursor))
        if cursor.exists():
            if not cursor.is_dir():
                raise NouveauError("Nouveau output parent is not a directory: " + str(cursor))
        else:
            cursor.mkdir()


def _prepare_outputs(plan: dict) -> None:
    build_root = Path(plan["build_root"])
    outputs = [Path(value) for value in plan["ordered_object_paths"]]
    if len(outputs) > EXPECTED_OBJECTS or len(outputs) != EXPECTED_OBJECTS or len(set(outputs)) != len(outputs):
        raise NouveauError("compile plan exceeds the 825 unique output-file bound")
    for output in outputs:
        _under(output, build_root, "Nouveau object output")
        _reject_symlink_components(output, "Nouveau object output")
        if output.exists() or output.is_symlink():
            raise NouveauError("Nouveau object output must be fresh: " + str(output))
    # Only object parent directories are created. No headers or include trees
    # are synthesized by this runner.
    for output in outputs:
        _safe_directory_creation(output.parent, build_root)
    for output in outputs:
        _reject_symlink_components(output.parent, "Nouveau object output")
        if output.exists() or output.is_symlink():
            raise NouveauError("Nouveau object output appeared before compilation: " + str(output))


class _PipeCapture:
    def __init__(self, stream, cap: int):
        self.stream = stream
        self.cap = cap
        self.data = bytearray()
        self.total = 0
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._drain, daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _drain(self) -> None:
        try:
            while True:
                chunk = self.stream.read(8192)
                if not chunk:
                    return
                self.total += len(chunk)
                if len(self.data) < self.cap:
                    self.data.extend(chunk[:self.cap - len(self.data)])
        except BaseException as exc:  # surfaced after join, never lost in a daemon thread
            self.error = exc

    def join(self, *, timeout_seconds: float = 3.0) -> None:
        self.thread.join(timeout=timeout_seconds)
        if self.thread.is_alive():
            try:
                self.stream.close()
            except OSError:
                pass
            self.thread.join(timeout=1.0)
        if self.thread.is_alive():
            raise NouveauError("compiler pipe reader did not stop within the bounded reap window")
        self.stream.close()

    @property
    def truncated(self) -> bool:
        return self.total > len(self.data)

    def bytes(self, *, failed: bool) -> bytes:
        if self.error is not None:
            raise NouveauError("failed to drain bounded compiler output") from self.error
        if not self.truncated:
            return bytes(self.data)
        if not failed:
            raise NouveauError("compiler output exceeded its per-stream capture limit")
        marker = TRUNCATION_MARKER + f"[captured {len(self.data)} of {self.total} bytes]\n".encode("ascii")
        return bytes(self.data[:self.cap - len(marker)]) + marker


def _new_log_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb"):
        pass


class _LogBudget:
    """Prospective byte accounting for per-object logs and the failure reserve."""

    def __init__(self) -> None:
        self.saved = 0

    def _write_pair(self, state: dict, stdout: bytes, stderr: bytes) -> None:
        pair_size = len(stdout) + len(stderr)
        if self.saved + pair_size > MAX_AGGREGATE_SAVED_LOG_BYTES:
            raise NouveauError("hard aggregate saved-log limit exceeded")
        for path_key, content in (("stdout_path", stdout), ("stderr_path", stderr)):
            with state[path_key].open("wb") as output:
                output.write(content)
        self.saved += pair_size
        state["logs_saved"] = True

    def save(self, state: dict, *, failed: bool) -> None:
        stdout = state["stdout"].bytes(failed=failed)
        stderr = state["stderr"].bytes(failed=failed)
        pair_size = len(stdout) + len(stderr)
        limit = MAX_AGGREGATE_SAVED_LOG_BYTES if failed else MAX_REGULAR_SAVED_LOG_BYTES
        if self.saved + pair_size > limit:
            raise NouveauError("aggregate saved-log limit exceeded")
        self._write_pair(state, stdout, stderr)

    def save_launch_failure(self, stdout_path: Path, stderr_path: Path, message: str) -> None:
        stdout = b""
        stderr = message.encode("utf-8", "replace")[:MAX_LOG_BYTES_PER_STREAM]
        if self.saved + len(stderr) > MAX_AGGREGATE_SAVED_LOG_BYTES:
            raise NouveauError("hard aggregate saved-log limit exceeded")
        with stdout_path.open("wb") as output:
            output.write(stdout)
        with stderr_path.open("wb") as output:
            output.write(stderr)
        self.saved += len(stderr)


def _finish_state(state: dict) -> None:
    failures = []
    for key in ("stdout", "stderr"):
        try:
            state[key].join()
        except BaseException as error:
            failures.append(type(error).__name__ + ": " + str(error)[:200])
    if failures:
        raise NouveauError("compiler pipe cleanup incomplete: " + "; ".join(failures))


def _stop_process_group(process: subprocess.Popen) -> dict:
    try:
        return ci_cargo.stop_group(process)
    except BaseException as error:
        # Keep bounded direct-child reaping even if the shared group observer
        # fails; the receipt remains incomplete because descendants were not
        # conclusively observed and stopped.
        signal_errors = []
        for signum in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, signum)
            except ProcessLookupError:
                pass
            except (OSError, PermissionError) as signal_error:
                signal_errors.append(
                    f"{signum}:{type(signal_error).__name__}:{str(signal_error)[:160]}")
        try:
            direct_reap = ci_cargo.reap_child_bounded(
                process, process_group_id=process.pid, wait_seconds=0.1,
                sigkill_wait_seconds=3.0)
        except BaseException as reap_error:
            direct_reap = {"schema": "ami-rust-direct-child-reap-v1",
                           "status": "incomplete_cleanup", "incomplete_cleanup": True,
                           "wait_attempt_count": 0, "return_code": process.returncode,
                           "error": type(reap_error).__name__ + ": " + str(reap_error)[:160]}
        return {"group_ids": [process.pid], "sigterm_group_ids": [],
                "sigkill_group_ids": [process.pid], "remaining_group_ids": [process.pid],
                "observer_errors": [type(error).__name__ + ": " + str(error)[:200],
                                    "fallback did not observe descendant groups"],
                "signal_errors": signal_errors, "direct_child_reap": direct_reap,
                "complete": False, "incomplete_cleanup": True,
                "status": "incomplete_cleanup"}


def _stop_processes(active: dict[int, dict]) -> list[dict]:
    receipts = []
    for index, state in active.items():
        process: subprocess.Popen = state["process"]
        receipt = _stop_process_group(process)
        state["cleanup"] = receipt
        receipts.append({"command_index": index, "receipt": receipt})
    return receipts


def _compile_commands_impl(plan: dict, work_dir: Path, jobs: int) -> dict:
    if jobs not in (1, MAX_JOBS):
        raise NouveauError("compile concurrency must be one or two jobs")
    if len(plan["commands"]) != EXPECTED_OBJECTS or len(plan["ordered_object_paths"]) != EXPECTED_OBJECTS:
        raise NouveauError("compile plan does not contain exactly 825 commands and outputs")

    logs_dir = work_dir / "nouveau-logs"
    _reject_symlink_components(logs_dir, "Nouveau log directory")
    if logs_dir.exists() or logs_dir.is_symlink():
        raise NouveauError("fresh Nouveau log directory required")
    source_root = Path(plan["source_root"])
    build_root = Path(plan["build_root"])
    toolchain_root = Path(plan["toolchain_root"])
    _require_disjoint(logs_dir, source_root, "logs/source")
    _require_disjoint(logs_dir, build_root, "logs/build")
    _require_disjoint(logs_dir, toolchain_root, "logs/toolchain")
    logs_dir.mkdir(parents=True)

    compiler = Path(plan["compiler"])
    active: dict[int, dict] = {}
    log_budget = _LogBudget()
    next_index = 0
    started = 0
    completed = 0
    observed_warning_bytes = 0
    cleanup_receipts = []
    failure: str | None = None
    failure_index: int | None = None

    def launch(index: int) -> None:
        nonlocal started
        command = plan["commands"][index]
        stem = f"{index:04d}"
        stdout_path = logs_dir / (stem + ".stdout.log")
        stderr_path = logs_dir / (stem + ".stderr.log")
        _new_log_file(stdout_path)
        _new_log_file(stderr_path)
        process: subprocess.Popen | None = None
        try:
            process = subprocess.Popen(
                command["argv"], cwd=plan["working_directory"], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
                process_group=0,
            )
            stdout_capture = _PipeCapture(process.stdout, MAX_LOG_BYTES_PER_STREAM)
            stderr_capture = _PipeCapture(process.stderr, MAX_LOG_BYTES_PER_STREAM)
            stdout_capture.start()
            stderr_capture.start()
            active[index] = {
                "process": process,
                "started_at": time.monotonic(),
                "stdout": stdout_capture,
                "stderr": stderr_capture,
                "stdout_path": stdout_path,
                "stderr_path": stderr_path,
                "logs_saved": False,
            }
            started += 1
        except OSError as exc:
            log_budget.save_launch_failure(stdout_path, stderr_path,
                                           "compiler launch failed: " + str(exc) + "\n")
            raise NouveauError("could not launch Nouveau compiler for " + command["source"] + ": " + str(exc)) from exc
        except BaseException:
            if process is not None:
                cleanup_receipt = _stop_process_group(process)
                if cleanup_receipt.get("incomplete_cleanup"):
                    raise NouveauError("compiler launch cleanup returned incomplete_cleanup")
            raise

    try:
        while next_index < EXPECTED_OBJECTS or active:
            while failure is None and next_index < EXPECTED_OBJECTS and len(active) < jobs:
                index = next_index
                next_index += 1
                try:
                    launch(index)
                except NouveauError as exc:
                    failure = str(exc)
                    failure_index = index
                    break

            if not active:
                break
            time.sleep(0.02)
            now = time.monotonic()
            expired_command = next((index for index, state in active.items()
                                    if now - state["started_at"] >= MAX_COMMAND_SECONDS), None)
            if expired_command is not None:
                failure = "compiler command exceeded per-command timeout of " + str(
                    MAX_COMMAND_SECONDS) + " seconds"
                failure_index = expired_command
            active_warning_bytes = sum(
                state["stdout"].total + state["stderr"].total for state in active.values()
            )
            overflow_stream = next((index for index, state in active.items()
                                    if state["stdout"].truncated or state["stderr"].truncated), None)
            if failure is None:
                if overflow_stream is not None:
                    failure = "compiler output exceeded the per-stream capture limit"
                    failure_index = overflow_stream
                elif observed_warning_bytes + active_warning_bytes > MAX_TOTAL_WARNING_BYTES:
                    failure = "total compiler warning-byte capture limit exceeded"
                    failure_index = next(iter(active))
            if failure is not None:
                cleanup_receipts.extend(_stop_processes(active))
                for state in active.values():
                    _finish_state(state)
                    observed_warning_bytes += state["stdout"].total + state["stderr"].total
                    if not state["logs_saved"]:
                        try:
                            log_budget.save(state, failed=True)
                        except NouveauError:
                            pass  # retain already-created empty log files at the hard bound
                active.clear()
                break
            finished = [index for index, state in active.items()
                        if state["process"].poll() is not None]
            for index in finished:
                state = active.pop(index)
                _finish_state(state)
                observed_warning_bytes += state["stdout"].total + state["stderr"].total
                if state["stdout"].truncated or state["stderr"].truncated:
                    if failure is None:
                        failure = "compiler output exceeded the per-stream capture limit"
                        failure_index = index
                    try:
                        log_budget.save(state, failed=True)
                    except NouveauError:
                        pass
                    break
                if observed_warning_bytes > MAX_TOTAL_WARNING_BYTES:
                    if failure is None:
                        failure = "total compiler warning-byte capture limit exceeded"
                        failure_index = index
                    try:
                        log_budget.save(state, failed=True)
                    except NouveauError:
                        pass
                    break
                return_code = state["process"].returncode
                if return_code != 0:
                    if failure is None:
                        failure = "compiler exited with status " + str(return_code)
                        failure_index = index
                    try:
                        log_budget.save(state, failed=True)
                    except NouveauError:
                        pass
                    break
                output_path = Path(plan["commands"][index]["object"])
                _reject_symlink_components(output_path, "Nouveau compiler output")
                if not output_path.is_file() or output_path.is_symlink():
                    if failure is None:
                        failure = "compiler returned success without a regular object: " + str(output_path)
                        failure_index = index
                    try:
                        log_budget.save(state, failed=True)
                    except NouveauError:
                        pass
                    break
                completed += 1
                try:
                    log_budget.save(state, failed=False)
                except NouveauError:
                    if failure is None:
                        failure = "aggregate saved-log limit exceeded"
                        failure_index = index
                    try:
                        log_budget.save(state, failed=True)
                    except NouveauError:
                        pass
                    break
            if failure is not None:
                cleanup_receipts.extend(_stop_processes(active))
                for state in active.values():
                    _finish_state(state)
                    observed_warning_bytes += state["stdout"].total + state["stderr"].total
                    if not state["logs_saved"]:
                        try:
                            log_budget.save(state, failed=True)
                        except NouveauError:
                            pass
                active.clear()
                break
    except BaseException as error:
        cleanup_receipts.extend(_stop_processes(active))
        if isinstance(error, CompileInterrupted):
            error.signal_state["process_group_cleanup"] = cleanup_receipts
            error.signal_state["incomplete_cleanup"] = any(
                row["receipt"].get("incomplete_cleanup") for row in cleanup_receipts)
        for index, state in active.items():
            try:
                _finish_state(state)
            except NouveauError as finish_error:
                cleanup_receipts.append({"command_index": index,
                    "receipt": {"status": "incomplete_cleanup", "incomplete_cleanup": True,
                                "error": str(finish_error)[:200]}})
            observed_warning_bytes += state["stdout"].total + state["stderr"].total
            if not state["logs_saved"]:
                try:
                    log_budget.save(state, failed=True)
                except NouveauError:
                    pass
        raise

    incomplete_cleanup = any(
        row["receipt"].get("incomplete_cleanup") for row in cleanup_receipts)
    if incomplete_cleanup:
        failure = failure or "compiler process-group cleanup returned incomplete_cleanup"

    return {
        "started": started,
        "completed": completed,
        "failed_index": failure_index,
        "failure": failure,
        "logs_directory": str(logs_dir),
        "warning_bytes_captured": observed_warning_bytes,
        "aggregate_saved_log_bytes": log_budget.saved,
        "aggregate_saved_log_limit": MAX_AGGREGATE_SAVED_LOG_BYTES,
        "per_command_timeout_seconds": MAX_COMMAND_SECONDS,
        "per_stream_capture_limit": MAX_LOG_BYTES_PER_STREAM,
        "total_warning_byte_limit": MAX_TOTAL_WARNING_BYTES,
        "process_group_cleanup": cleanup_receipts,
        "incomplete_cleanup": incomplete_cleanup,
    }


class CompileInterrupted(KeyboardInterrupt):
    def __init__(self, signal_state: dict[str, Any]):
        super().__init__("compiler run interrupted by SIGTERM")
        self.signal_state = signal_state


def _compile_commands(plan: dict, work_dir: Path, jobs: int) -> dict:
    """Run compiler groups with one idempotent SIGTERM cleanup request."""
    previous_sigterm = signal.getsignal(signal.SIGTERM)
    signal_state = {"received": 0, "cleanup_attempts": 0}

    def interrupt_compile(_signum, _frame):
        signal_state["received"] += 1
        if signal_state["cleanup_attempts"] == 0:
            signal_state["cleanup_attempts"] = 1
            raise CompileInterrupted(signal_state)

    signal.signal(signal.SIGTERM, interrupt_compile)
    try:
        return _compile_commands_impl(plan, work_dir, jobs)
    finally:
        signal.signal(signal.SIGTERM, previous_sigterm)


def _read_bounded_text(path: Path, label: str) -> str:
    file_path = _require_regular_file(path, label)
    size = file_path.stat().st_size
    if size > MAX_RECIPE_BYTES:
        raise NouveauError(label + " exceeds the bounded recipe input size")
    return file_path.read_text(encoding="utf-8")


def _write_plan_fresh(path: Path, value: dict) -> None:
    _reject_symlink_components(path, "compile plan output")
    if path.exists() or path.is_symlink():
        raise NouveauError("fresh compile plan output required: " + str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(_json_bytes(value))
        stream.flush()
        os.fsync(stream.fileno())


def _replace_plan(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + ".update")
    if temporary.exists() or temporary.is_symlink():
        raise NouveauError("compile plan update path already exists")
    with temporary.open("xb") as stream:
        stream.write(_json_bytes(value))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _cli_compile_plan(args: argparse.Namespace) -> int:
    work_dir = _require_directory(args.work_dir, "work directory")
    input_db = _require_regular_file(args.compile_commands, "frozen compilation database")
    input_ninja = _require_regular_file(args.ninja, "frozen Ninja file")
    db_text = _read_bounded_text(input_db, "frozen compilation database")
    ninja_text = _read_bounded_text(input_ninja, "frozen Ninja file")
    records = csdk_recipes.nouveau_compile_recipes(db_text)
    plan = plan_nouveau(records, ninja_text, args.source_root, args.build_root, args.toolchain_root)

    plan_path = work_dir / "nouveau-compile-plan.json"
    _require_disjoint(plan_path, Path(plan["source_root"]), "plan/source")
    _require_disjoint(plan_path, Path(plan["build_root"]), "plan/build")
    _require_disjoint(plan_path, Path(plan["toolchain_root"]), "plan/toolchain")
    logs_path = work_dir / "nouveau-logs"
    _require_disjoint(logs_path, Path(plan["source_root"]), "logs/source")
    _require_disjoint(logs_path, Path(plan["build_root"]), "logs/build")
    _require_disjoint(logs_path, Path(plan["toolchain_root"]), "logs/toolchain")
    _write_plan_fresh(plan_path, plan)
    try:
        _validate_compiler(plan, args.compiler_sha256)
        _prepare_outputs(plan)
        try:
            outcome = _compile_commands(plan, work_dir, args.jobs)
        except KeyboardInterrupt as exc:
            plan["status"] = "FAIL_COMPILE"
            plan["error"] = str(exc)
            state = getattr(exc, "signal_state", {})
            plan["compile"] = {
                "failure": str(exc),
                "interrupted": True,
                "sigterm_delivery_count": state.get("received", 0),
                "signal_cleanup_attempts": state.get("cleanup_attempts", 1),
                "process_group_cleanup": state.get("process_group_cleanup", []),
                "incomplete_cleanup": state.get("incomplete_cleanup", False),
                "cleanup_status": ("incomplete_cleanup" if state.get("incomplete_cleanup")
                                   else "complete"),
                "logs_directory": str(work_dir / "nouveau-logs"),
            }
            _replace_plan(plan_path, plan)
            print("csdk_nouveau: " + str(exc), file=sys.stderr)
            return 1
        plan["compile"] = outcome
        compiler = _require_regular_file(plan["compiler"], "pinned clang-11 compiler")
        compiler_sha_after = _sha256_file(compiler)
        outcome["compiler_sha256_after"] = compiler_sha_after
        if compiler_sha_after != args.compiler_sha256:
            raise NouveauError("pinned clang-11 compiler byte SHA-256 changed during compilation")
        if outcome["failure"] is not None:
            plan["status"] = "FAIL_COMPILE"
            _replace_plan(plan_path, plan)
            print(json.dumps({"plan": str(plan_path), **outcome}, sort_keys=True))
            return 1
        plan["status"] = "NOUVEAU_825_COMPILE_COMMANDS_COMPLETE"
        _replace_plan(plan_path, plan)
        print(json.dumps({"plan": str(plan_path), **outcome, "status": plan["status"]}, sort_keys=True))
        return 0
    except Exception as exc:
        plan["status"] = "FAIL_VALIDATION_OR_RUNNER"
        plan["error"] = str(exc)
        _replace_plan(plan_path, plan)
        print("csdk_nouveau: " + str(exc), file=sys.stderr)
        return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    compile_plan = subparsers.add_parser(
        "compile-plan", help="validate and compile the frozen 825-object Nouveau target")
    compile_plan.add_argument("--compile-commands", required=True, type=Path)
    compile_plan.add_argument("--ninja", required=True, type=Path)
    compile_plan.add_argument("--source-root", required=True, type=Path)
    compile_plan.add_argument("--build-root", required=True, type=Path)
    compile_plan.add_argument("--toolchain-root", required=True, type=Path)
    compile_plan.add_argument("--compiler-sha256", required=True)
    compile_plan.add_argument("--work-dir", required=True, type=Path)
    compile_plan.add_argument("--jobs", type=int, choices=(1, 2), default=2)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "compile-plan":
        try:
            return _cli_compile_plan(args)
        except (OSError, csdk_recipes.RecipeError, NouveauError, json.JSONDecodeError) as exc:
            print("csdk_nouveau: " + str(exc), file=sys.stderr)
            return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
