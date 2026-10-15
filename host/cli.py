#!/usr/bin/env python3
"""Project-locked entry point for the ami-rust native SDK.

Verification checks consistency with pins selected by the project lock; it does not
authenticate that lock as an independent release signature. Concurrent mutation of
other SDK or prerequisite files is outside the verifier's established guarantee.
"""
import sys

if not sys.flags.isolated or not sys.dont_write_bytecode:
    sys.stderr.write("ami-rust requires its pinned Python to start with -I -B\n")
    raise SystemExit(2)

import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import types
from pathlib import Path, PurePosixPath


VERSION = "0.1.0-dev"
PROJECT_LIMIT = 1024 * 1024
MANIFEST_LIMIT = 16 * 1024 * 1024
DRIVER_LIMIT = 2 * 1024 * 1024
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
DRIVER_PATH = "host/build.py"
CLI_PATH = "host/cli.py"
CONTRACTS_PATH = "host/contracts.py"


class Refusal(ValueError):
    pass


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_file(path, limit=None, label="file"):
    try:
        info = path.lstat()
    except OSError as error:
        raise Refusal(f"missing {label}: {path}") from error
    if not stat.S_ISREG(info.st_mode):
        raise Refusal(f"{label} must be a regular non-symlink file: {path}")
    if limit is not None and info.st_size > limit:
        raise Refusal(f"oversized {label}: {path}")
    return info


def _read_json(path, limit, label):
    _regular_file(path, limit, label)
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise Refusal(f"oversized {label}: {path}")
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise Refusal(f"duplicate JSON key in {label}: {key}")
                result[key] = value
            return result
        def reject_constant(value):
            raise Refusal(f"invalid JSON constant in {label}: {value}")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                           parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Refusal(f"invalid UTF-8 JSON in {label}: {error}") from error
    if not isinstance(value, dict):
        raise Refusal(f"{label} must contain a JSON object")
    return value, raw


def _required_object(value, key, label):
    result = value.get(key)
    if not isinstance(result, dict):
        raise Refusal(f"{label}.{key} must be an object")
    return result


def _portable_parts(value, label):
    if (not isinstance(value, str) or not value or "\\" in value or ":" in value
            or "\0" in value or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise Refusal(f"{label} must be a portable relative path")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts) or PurePosixPath(value).is_absolute():
        raise Refusal(f"unsafe {label}: {value}")
    return parts


def _under(root, relative, label):
    parts = _portable_parts(relative, label)
    path = root
    for index, part in enumerate(parts):
        path = path / part
        try:
            info = path.lstat()
        except OSError as error:
            raise Refusal(f"missing {label}: {relative}") from error
        if stat.S_ISLNK(info.st_mode):
            raise Refusal(f"symlink in {label}: {relative}")
        if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
            raise Refusal(f"non-directory parent in {label}: {relative}")
    return path


def _host_key():
    pair = (platform.system(), platform.machine().lower())
    result = {
        ("Darwin", "arm64"): "macos-aarch64",
        ("Linux", "x86_64"): "linux-x86_64",
    }.get(pair)
    if result is None:
        raise Refusal(f"unsupported host platform: {pair[0]}/{pair[1]}")
    return result


def _walk_host(root):
    host = root / "host"
    try:
        info = host.lstat()
    except OSError as error:
        raise Refusal("SDK host source directory is missing") from error
    if not stat.S_ISDIR(info.st_mode):
        raise Refusal("SDK host source path must be a real directory")
    actual = set()
    for directory, names, files in os.walk(host, followlinks=False):
        base = Path(directory)
        for name in list(names):
            child = base / name
            child_info = child.lstat()
            if stat.S_ISLNK(child_info.st_mode):
                raise Refusal(f"symlink in SDK host source tree: {child.relative_to(root)}")
            if not stat.S_ISDIR(child_info.st_mode):
                raise Refusal(f"non-directory in SDK host source tree: {child.relative_to(root)}")
            if name == "__pycache__":
                raise Refusal(f"Python bytecode cache in SDK host source tree: {child.relative_to(root)}")
        for name in files:
            child = base / name
            child_info = child.lstat()
            relative = child.relative_to(root).as_posix()
            if not stat.S_ISREG(child_info.st_mode):
                raise Refusal(f"non-regular or symlink in SDK host source tree: {relative}")
            if child.suffix.lower() in (".pyc", ".pyo"):
                raise Refusal(f"Python bytecode in SDK host source tree: {relative}")
            actual.add(relative)
    return actual


def _load_verified_contracts(path, expected_digest):
    module_name = "_ami_rust_project_locked_contracts"
    if module_name in sys.modules:
        raise Refusal("verified contracts module was already loaded")
    try:
        source = path.read_bytes()
    except OSError as error:
        raise Refusal(f"cannot read verified SDK contracts module: {error}") from error
    if hashlib.sha256(source).hexdigest() != expected_digest:
        raise Refusal("SDK contracts changed during verification")
    module = types.ModuleType(module_name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[module_name] = module
    try:
        code = compile(source, str(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except Exception:
        del sys.modules[module_name]
        raise
    return module


def verify_project_lock(lock_path):
    lock_path = Path(os.path.abspath(lock_path))
    project, project_raw = _read_json(lock_path, PROJECT_LIMIT, "project lock")
    project_digest = hashlib.sha256(project_raw).hexdigest()
    if project.get("schema") != "ami-rust-project-lock-v1":
        raise Refusal("missing or incompatible ami-rust project lock schema")
    sdk = _required_object(project, "sdk", "project lock")
    host = _required_object(project, "host", "project lock")
    if not isinstance(project.get("components"), dict):
        raise Refusal("project lock.components must be an object")

    root_value = sdk.get("root")
    if not isinstance(root_value, str) or not root_value or "\0" in root_value:
        raise Refusal("project lock.sdk.root must be a path string")
    root_input = Path(root_value)
    if not root_input.is_absolute():
        root_input = lock_path.parent / root_input
    try:
        if root_input.is_symlink():
            raise Refusal("SDK root must not be a symlink")
        root = root_input.resolve(strict=True)
    except OSError as error:
        raise Refusal(f"missing SDK root: {root_input}") from error
    if not root.is_dir():
        raise Refusal("SDK root must be a directory")

    manifest_name = sdk.get("manifest")
    manifest_digest = sdk.get("manifest_sha256")
    if not isinstance(manifest_digest, str) or not DIGEST.fullmatch(manifest_digest):
        raise Refusal("invalid project lock SDK manifest SHA-256")
    manifest_path = _under(root, manifest_name, "SDK manifest path")
    manifest, manifest_raw = _read_json(manifest_path, MANIFEST_LIMIT, "SDK manifest")
    if hashlib.sha256(manifest_raw).hexdigest() != manifest_digest:
        raise Refusal("SDK manifest identity mismatch")
    if manifest.get("schema") != "ami-rust-sdk-v1":
        raise Refusal("missing or incompatible ami-rust SDK manifest schema")
    if manifest.get("driver") != DRIVER_PATH:
        raise Refusal("SDK manifest driver must be host/build.py")
    if "development_only" in manifest and type(manifest["development_only"]) is not bool:
        raise Refusal("SDK manifest development_only must be a boolean")

    rows = manifest.get("files")
    if not isinstance(rows, list) or not rows:
        raise Refusal("SDK manifest.files must be a non-empty array")
    inventory = {}
    for row in rows:
        if not isinstance(row, dict):
            raise Refusal("SDK manifest file entries must be objects")
        name = row.get("path")
        _portable_parts(name, "SDK file path")
        if name in inventory:
            raise Refusal(f"duplicate SDK file inventory path: {name}")
        size = row.get("bytes")
        digest = row.get("sha256")
        if type(size) is not int or size < 0:
            raise Refusal(f"invalid SDK file byte length: {name}")
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise Refusal(f"invalid SDK file SHA-256: {name}")
        inventory[name] = (size, digest)

    for name in inventory:
        path = _under(root, name, "SDK file path")
        info = _regular_file(path, DRIVER_LIMIT if name == DRIVER_PATH else None,
                             label=f"SDK file {name}")
        expected_size, expected_digest = inventory[name]
        if info.st_size != expected_size or sha256_file(path) != expected_digest:
            raise Refusal(f"SDK file identity mismatch: {name}")

    for required in (DRIVER_PATH, CLI_PATH, CONTRACTS_PATH):
        if required not in inventory:
            raise Refusal(f"SDK inventory is missing required host source: {required}")
    host_files = {name for name in inventory if name.startswith("host/")}
    actual_host_files = _walk_host(root)
    if actual_host_files != host_files:
        extras = sorted(actual_host_files - host_files)
        missing = sorted(host_files - actual_host_files)
        raise Refusal(f"SDK host source inventory is incomplete: extra={extras[:3]} missing={missing[:3]}")

    cli_path = _under(root, CLI_PATH, "SDK CLI path")
    running_cli = Path(__file__).resolve(strict=True)
    if sha256_file(cli_path) != sha256_file(running_cli):
        raise Refusal("running ami-rust CLI does not match the SDK-inventoried host/cli.py")

    python_value = host.get("python")
    python_digest = host.get("python_sha256")
    if not isinstance(python_value, str) or not python_value or "\0" in python_value:
        raise Refusal("project lock host.python must be an absolute path")
    python_input = Path(python_value)
    if not python_input.is_absolute():
        raise Refusal("project lock host.python must be an absolute path")
    if not isinstance(python_digest, str) or not DIGEST.fullmatch(python_digest):
        raise Refusal("invalid project lock host Python SHA-256")
    try:
        python_path = python_input.resolve(strict=True)
        python_info = python_path.stat()
        running_python = Path(sys.executable).resolve(strict=True)
    except OSError as error:
        raise Refusal(f"selected or running Python is unavailable: {error}") from error
    if not stat.S_ISREG(python_info.st_mode) or not os.access(python_path, os.X_OK):
        raise Refusal("selected Python must resolve to an executable regular file")
    if sha256_file(python_path) != python_digest:
        raise Refusal("selected Python identity mismatch")
    if running_python != python_path:
        raise Refusal("ami-rust must run under the Python interpreter pinned by the project lock")

    current_host = _host_key()
    declared_host = host.get("platform")
    if declared_host is not None and declared_host != current_host:
        raise Refusal("project host platform does not match this machine")

    contracts_path = _under(root, CONTRACTS_PATH, "SDK contracts path")
    contracts = _load_verified_contracts(contracts_path, inventory[CONTRACTS_PATH][1])
    selected = contracts.select(lock_path)
    selected_lock, selected_project, selected_root, selected_manifest = selected[:4]
    if selected_lock != lock_path.absolute() or selected_root != root:
        raise Refusal("verified SDK selection changed while loading contracts")
    if sha256_file(lock_path) != project_digest:
        raise Refusal("project lock changed during verification")
    if selected_project.get("sdk", {}).get("manifest_sha256") != manifest_digest:
        raise Refusal("selected project lock differs from preflight identity")
    if selected_manifest.get("schema") != "ami-rust-sdk-v1":
        raise Refusal("selected SDK manifest changed while loading contracts")
    if sha256_file(manifest_path) != manifest_digest:
        raise Refusal("SDK manifest changed during verification")

    return {
        "lock_path": lock_path,
        "project": project,
        "root": root,
        "manifest": manifest,
        "manifest_path": manifest_path,
        "manifest_sha256": manifest_digest,
        "host": current_host,
        "python": python_path,
        "driver": _under(root, DRIVER_PATH, "SDK driver path"),
        "development_only": manifest.get("development_only", False),
    }


def _usage():
    return (
        "Usage:\n"
        "  ami-rust verify --sdk-lock FILE\n"
        "  ami-rust build --sdk-lock FILE --output-dir FRESH -- <Cargo build arguments>\n"
        "  ami-rust --version\n"
        "\n"
        "Runs only the host and build driver pinned by the explicit SDK lock.\n"
        "The CLI requires the pinned Python interpreter with -I -B.\n"
        "Verification checks project-selected pin consistency; it does not authenticate the lock as a release signature.\n"
        "Concurrent mutation of other SDK or prerequisite files is outside the verifier's established guarantee.\n"
        "A driver killed by signal N maps to exit status 128+N.\n"
    )


def _parse_options(command, arguments):
    if command == "build":
        try:
            divider = arguments.index("--")
        except ValueError as error:
            raise Refusal("build requires -- before the forwarded Cargo arguments") from error
        options = arguments[:divider]
        cargo_arguments = arguments[divider + 1:]
        if not cargo_arguments:
            raise Refusal("build requires Cargo arguments after --")
    else:
        if "--" in arguments:
            raise Refusal("verify does not accept forwarded arguments")
        options = arguments
        cargo_arguments = []

    values = {}
    index = 0
    while index < len(options):
        option = options[index]
        if option not in ("--sdk-lock", "--output-dir"):
            raise Refusal(f"unknown {command} option: {option}")
        if option in values:
            raise Refusal(f"duplicate {command} option: {option}")
        if index + 1 >= len(options) or options[index + 1] == "--" or options[index + 1].startswith("--"):
            raise Refusal(f"missing value for {option}")
        values[option] = options[index + 1]
        index += 2

    required = {"--sdk-lock"} if command == "verify" else {"--sdk-lock", "--output-dir"}
    missing = sorted(required - values.keys())
    if missing:
        raise Refusal(f"missing required option: {missing[0]}")
    return values, cargo_arguments


def _output_path(value):
    output = Path(os.path.abspath(value))
    if output.exists() or output.is_symlink():
        raise Refusal("output directory must be fresh")
    if not output.parent.is_dir():
        raise Refusal("output directory parent must already exist")
    return output


def _verify_command(lock_path):
    selected = verify_project_lock(lock_path)
    development = selected["development_only"]
    qualification = "development-only; not R1-qualified" if development else "not R1-qualified"
    claim = (f"{qualification}; checks consistency with project-selected pins only, not independent "
             "release authentication; concurrent mutation of other SDK or prerequisite files "
             "is outside the established guarantee")
    print(json.dumps({
        "status": "verified-development" if development else "verified",
        "development_only": development,
        "claim": claim,
        "host": selected["host"],
        "sdk_manifest_sha256": selected["manifest_sha256"],
    }, sort_keys=True, separators=(",", ":")))
    return 0


def _build_command(lock_path, output_value, cargo_arguments):
    selected = verify_project_lock(lock_path)
    output = _output_path(output_value)
    command = [
        str(selected["python"]), "-I", "-B", str(selected["driver"]),
        "--project-lock", str(selected["lock_path"]),
        "--output-dir", str(output), "--", *cargo_arguments,
    ]
    result = subprocess.run(command, check=False)
    if result.returncode < 0:
        signal_number = -result.returncode
        status = min(255, 128 + signal_number)
        print(f"ami-rust build driver terminated by signal {signal_number}; returning {status}", file=sys.stderr)
        return status
    return result.returncode


def main(arguments=None):
    if arguments is None:
        arguments = sys.argv[1:]
    if arguments in (["--help"], ["-h"]):
        print(_usage(), end="")
        return 0
    if arguments == ["--version"]:
        print(f"ami-rust {VERSION}")
        return 0
    if not arguments:
        sys.stderr.write(_usage())
        return 2

    command, *tail = arguments
    if command not in ("verify", "build"):
        sys.stderr.write(f"unknown command: {command}\n{_usage()}")
        return 2
    try:
        values, cargo_arguments = _parse_options(command, tail)
        lock_path = values["--sdk-lock"]
        if command == "verify":
            return _verify_command(lock_path)
        return _build_command(lock_path, values["--output-dir"], cargo_arguments)
    except (OSError, Refusal, ValueError, KeyError, TypeError, ImportError,
            AttributeError, subprocess.SubprocessError) as error:
        print(f"ami-rust {command} refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
