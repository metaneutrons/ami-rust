#!/usr/bin/env python3
"""Install and verify the pinned standalone Python used by hosted CI.

This creates a CI helper runtime only. It does not build or qualify the AROS
SDK. The archive and extracted runtime stay below a fresh --prefix.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import urllib.parse


SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parent.parent
SCHEMA = "ami-rust-ci-python-inputs-v1"
RECEIPT_SCHEMA = "ami-rust-ci-python-bootstrap-v1"
VERSION = "3.12.15"
HOST_TARGETS = {
    "macos-aarch64": "aarch64-apple-darwin",
    "linux-x86_64": "x86_64-unknown-linux-gnu",
}
REDIRECT_HOSTS = ("release-assets.githubusercontent.com", "objects.githubusercontent.com")
MAX_ARCHIVE_BYTES = 128 * 1024**2
MAX_EXPANDED_BYTES = 512 * 1024**2
MAX_MEMBERS = 100_000
MAX_PROBE_OUTPUT = 64 * 1024
PROBE_TIMEOUT_SECONDS = 30
CHUNK_BYTES = 64 * 1024


def load_cargo_helper():
    """Load the sibling helper explicitly; CI invokes this script with -I."""
    path = ROOT / "release" / "ci_cargo.py"
    spec = importlib.util.spec_from_file_location("_ami_rust_ci_cargo", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the pinned hosted CI resource helper")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ci_cargo = load_cargo_helper()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_digest(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _safe_relative_path(value) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ValueError("pinned Python executable path is invalid")
    path = PurePosixPath(value)
    if (path.is_absolute() or path.as_posix() != value
            or any(part in ("", ".", "..") for part in path.parts)
            or ":" in path.parts[0]):
        raise ValueError("pinned Python executable path is unsafe")
    return path


def _validate_archive_url(url: str, target: str) -> None:
    parsed = urllib.parse.urlparse(url)
    expected_name = f"cpython-{VERSION}+20261013-{target}-install_only.tar.gz"
    expected_path = f"/astral-sh/python-build-standalone/releases/download/20261013/{expected_name}"
    if (parsed.scheme != "https" or parsed.hostname != "github.com"
            or parsed.username is not None or parsed.password is not None or parsed.port is not None
            or parsed.query or parsed.fragment or urllib.parse.unquote(parsed.path) != expected_path):
        raise ValueError("Python archive URL is not the pinned GitHub release asset")


def validate_inputs(inputs: dict, normative: dict, host: str) -> dict:
    if inputs != normative:
        raise ValueError("Python input file differs from the tracked normative hosted CI pin")
    if not isinstance(inputs, dict) or inputs.get("schema") != SCHEMA or inputs.get("version") != VERSION:
        raise ValueError("unrecognized Python input schema or version")
    hosts = inputs.get("hosts")
    if not isinstance(hosts, dict) or set(hosts) != set(HOST_TARGETS):
        raise ValueError("Python pins must cover exactly the admitted hosted CI systems")
    if host not in HOST_TARGETS:
        raise ValueError("hosted Python bootstrap does not support this runner")
    record = hosts[host]
    expected_fields = {"url", "size_bytes", "sha256", "runtime_relative_path",
                       "runtime_sha256", "expanded_bytes", "member_count"}
    if not isinstance(record, dict) or not expected_fields <= set(record):
        raise ValueError("hosted Python pin is missing required fields")
    if record.get("host", host) != host or record.get("target_triple", HOST_TARGETS[host]) != HOST_TARGETS[host]:
        raise ValueError("hosted Python pin host/target identity is inconsistent")
    _validate_archive_url(record["url"], HOST_TARGETS[host])
    for key in ("size_bytes", "expanded_bytes", "member_count"):
        if type(record[key]) is not int or record[key] <= 0:
            raise ValueError("hosted Python archive size/member pins must be positive integers")
    if record["size_bytes"] > MAX_ARCHIVE_BYTES:
        raise ValueError("Python archive exceeds the admitted compressed size")
    if record["expanded_bytes"] > MAX_EXPANDED_BYTES:
        raise ValueError("Python archive exceeds the admitted expansion size")
    if record["member_count"] > MAX_MEMBERS:
        raise ValueError("Python archive exceeds the admitted member count")
    if "runtime_bytes" in record and (type(record["runtime_bytes"]) is not int
                                      or record["runtime_bytes"] <= 0
                                      or record["runtime_bytes"] > record["expanded_bytes"]):
        raise ValueError("pinned Python runtime byte count is invalid")
    if not _is_digest(record["sha256"]) or not _is_digest(record["runtime_sha256"]):
        raise ValueError("hosted Python archive/runtime SHA-256 pin is invalid")
    runtime_path = _safe_relative_path(record["runtime_relative_path"])
    if runtime_path.name != "python3.12":
        raise ValueError("pinned Python runtime path does not name python3.12")
    return record


def _read_normative_files(inputs_path: Path) -> tuple[dict, dict, str, str]:
    normative_path = ROOT / "release" / "ci-python-inputs.json"
    resources_path = ROOT / "release" / "ci-resources.json"
    if inputs_path.resolve(strict=True) != normative_path.resolve(strict=True):
        raise ValueError("--inputs must be release/ci-python-inputs.json")
    input_bytes = inputs_path.read_bytes()
    normative_bytes = normative_path.read_bytes()
    if input_bytes != normative_bytes:
        raise ValueError("Python input bytes differ from the tracked normative file")
    resources_bytes = resources_path.read_bytes()
    return (json.loads(input_bytes), json.loads(normative_bytes),
            hashlib.sha256(input_bytes).hexdigest(), hashlib.sha256(resources_bytes).hexdigest())


def _resource_policy() -> dict:
    policy = json.loads((ROOT / "release" / "ci-resources.json").read_text())
    if policy.get("schema") != "ami-rust-hosted-resources-v1":
        raise ValueError("unrecognized hosted CI resource policy")
    build = policy.get("build")
    if not isinstance(build, dict) or type(build.get("workspace_bytes")) is not int:
        raise ValueError("resource policy has no workspace ceiling")
    return policy


def _fresh_prefix(prefix: Path) -> Path:
    if not prefix.is_absolute():
        raise ValueError("--prefix must be an absolute path")
    prefix = prefix.absolute()
    if prefix.exists() or prefix.is_symlink():
        raise ValueError("Python bootstrap prefix must be fresh")
    if not prefix.parent.is_dir():
        raise ValueError("Python bootstrap prefix parent must already exist")
    return prefix


def _relative_runtime_file(runtime_root: Path, component_root: str, pinned_path: str) -> Path:
    relative = _safe_relative_path(pinned_path)
    if not relative.parts or relative.parts[0] != component_root:
        raise ValueError("pinned runtime path is outside the extracted archive component")
    current = runtime_root
    for index, part in enumerate(relative.parts):
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("pinned Python runtime path contains a symlink")
        if index + 1 == len(relative.parts):
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("pinned Python runtime is not a regular file")
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError("pinned Python runtime parent is not a directory")
    if not os.access(current, os.X_OK):
        raise ValueError("pinned Python runtime is not executable")
    return current


def _kill_probe(child: subprocess.Popen) -> None:
    try:
        ci_cargo.stop_group(child)
    except BaseException:
        # Make a second group-directed attempt if the shared helper itself
        # cannot complete its bounded stop procedure.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass


def bounded_process(command, *, timeout: int, max_output_bytes: int) -> dict:
    """Run one tiny probe with a deadline and a strict combined output cap."""
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
                             start_new_session=True)
    selector = selectors.DefaultSelector()
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    streams = {child.stdout: "stdout", child.stderr: "stderr"}
    for stream, name in streams.items():
        selector.register(stream, selectors.EVENT_READ, name)
    deadline = time.monotonic() + timeout
    try:
        while True:
            code = child.poll()
            if code is not None and not selector.get_map():
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("pinned Python introspection exceeded its time limit")
            events = selector.select(min(remaining, 0.1))
            for key, _ in events:
                used = len(captured["stdout"]) + len(captured["stderr"])
                if used == max_output_bytes:
                    block = os.read(key.fileobj.fileno(), 1)
                    if block:
                        raise ValueError("pinned Python introspection exceeded its output limit")
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                block = os.read(key.fileobj.fileno(), min(8192, max_output_bytes - used))
                if not block:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                name = key.data
                captured[name].extend(block)
                if len(captured["stdout"]) + len(captured["stderr"]) > max_output_bytes:
                    raise ValueError("pinned Python introspection exceeded its output limit")
        if ci_cargo.group_alive(child.pid):
            raise RuntimeError("pinned Python probe exited while its process group remained alive")
        return {"returncode": child.returncode,
                "stdout": bytes(captured["stdout"]), "stderr": bytes(captured["stderr"])}
    except BaseException:
        _kill_probe(child)
        raise
    finally:
        selector.close()
        for stream in streams:
            if not stream.closed:
                stream.close()


def inspect_runtime(executable: Path, expected_sha256: str, expected_bytes: int | None = None,
                    process_runner=bounded_process) -> dict:
    probe = (
        "import hashlib,json,pathlib,sys; "
        "p=pathlib.Path(sys.executable).resolve(strict=True); d=hashlib.sha256(); f=p.open('rb'); "
        "exec(\"for b in iter(lambda:f.read(1048576),b''):\\n d.update(b)\"); h=d.hexdigest(); "
        "print(json.dumps({'version':'.'.join(map(str,sys.version_info[:3])),"
        "'executable_sha256':h,'executable_bytes':p.stat().st_size},sort_keys=True))"
    )
    result = process_runner([str(executable), "-I", "-B", "-c", probe],
                            timeout=PROBE_TIMEOUT_SECONDS,
                            max_output_bytes=MAX_PROBE_OUTPUT)
    if result.get("returncode") != 0:
        raise RuntimeError("pinned Python introspection exited unsuccessfully")
    try:
        observed = json.loads(result.get("stdout", b"").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("pinned Python introspection returned invalid metadata") from error
    if (not isinstance(observed, dict) or observed.get("version") != VERSION
            or observed.get("executable_sha256") != expected_sha256
            or type(observed.get("executable_bytes")) is not int
            or observed["executable_bytes"] <= 0
            or (expected_bytes is not None and observed["executable_bytes"] != expected_bytes)):
        raise ValueError("pinned Python runtime version or resolved executable hash differs from its pin")
    return {"version": observed["version"], "sha256": observed["executable_sha256"],
            "bytes": observed["executable_bytes"]}


def _managed_workspace_bytes(prefix: Path) -> int:
    try:
        inside_repo = prefix.resolve().is_relative_to(ROOT.resolve())
    except OSError:
        inside_repo = False
    total = ci_cargo.directory_bytes(ROOT)
    if not inside_repo:
        total += ci_cargo.directory_bytes(prefix)
    return total


def _write_receipt(prefix: Path, receipt: dict) -> None:
    path = prefix / "bootstrap.json"
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    if len(encoded) > 64 * 1024:
        raise ValueError("Python bootstrap receipt exceeded its metadata limit")
    with path.open("xb") as stream:
        stream.write(encoded)


def provision(prefix: Path, inputs_path: Path, *, host_override: str | None = None,
              opener=None, process_runner=bounded_process) -> dict:
    prefix = _fresh_prefix(prefix)
    inputs, normative, inputs_sha, resources_sha = _read_normative_files(inputs_path)
    resources = _resource_policy()
    host, target = ci_cargo.host_identity()
    if host_override is not None:
        host = host_override
        target = HOST_TARGETS.get(host, "")
    pin = validate_inputs(inputs, normative, host)
    capacity = ci_cargo.check_capacity(host, prefix.parent, resources)
    prefix.mkdir()
    phase = "download"
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "claim": "Pinned CI Python runtime bootstrap only; not SDK or R1 qualification.",
        "status": "FAILED",
        "host": host,
        "target": target,
        "version": VERSION,
        "inputs_sha256": inputs_sha,
        "resources_sha256": resources_sha,
        "capacity": capacity,
        "relative_files": {"archive": "archive.tar.gz", "runtime_root": "runtime",
                           "bootstrap_receipt": "bootstrap.json"},
    }
    try:
        archive = prefix / "archive.tar.gz"
        download_args = {}
        if opener is not None:
            download_args["opener"] = opener
        archive_receipt = ci_cargo.download_verified(
            pin["url"], pin["size_bytes"], pin["sha256"], archive,
            expected_origin="github.com", redirect_hosts=REDIRECT_HOSTS, **download_args)
        if archive_receipt != {"bytes": pin["size_bytes"], "sha256": pin["sha256"]}:
            raise ValueError("download helper returned unexpected archive metadata")
        receipt["archive"] = {"path": "archive.tar.gz", **archive_receipt, "url": pin["url"]}
        receipt["archive_sha256"] = archive_receipt["sha256"]
        phase = "extract"
        runtime_root = prefix / "runtime"
        managed = _managed_workspace_bytes(prefix)
        workspace_limit = resources["build"]["workspace_bytes"]
        extraction = ci_cargo.safe_extract_tar(
            archive, runtime_root, expanded_limit=MAX_EXPANDED_BYTES,
            current_managed_bytes=managed, overall_limit=workspace_limit)
        if (extraction.get("member_count") != pin["member_count"]
                or extraction.get("expanded_bytes") != pin["expanded_bytes"]):
            raise ValueError("Python archive member count or expanded bytes differ from normative pin")
        receipt["extraction"] = extraction
        receipt["relative_files"]["runtime_root"] = "runtime"
        executable = _relative_runtime_file(runtime_root, extraction["component_root"],
                                            pin["runtime_relative_path"])
        executable_sha = sha256_file(executable)
        if executable_sha != pin["runtime_sha256"]:
            raise ValueError("pinned Python runtime executable SHA-256 differs from its normative pin")
        phase = "introspection"
        runtime = inspect_runtime(executable, pin["runtime_sha256"],
                                  pin.get("runtime_bytes"), process_runner)
        rel_executable = executable.relative_to(prefix).as_posix()
        receipt.update({
            "status": "READY_CI_RUNTIME_NOT_SDK_QUALIFICATION",
            "runtime_sha256": runtime["sha256"],
            "runtime": {"path": rel_executable, **runtime},
            "runtime_pin": {"sha256": pin["runtime_sha256"],
                            "relative_path": pin["runtime_relative_path"]},
            "relative_files": {"archive": "archive.tar.gz", "runtime_root": "runtime",
                               "runtime_executable": rel_executable,
                               "bootstrap_receipt": "bootstrap.json"},
            "observed_managed_prefix_bytes": ci_cargo.directory_bytes(prefix),
        })
        _write_receipt(prefix, receipt)
        return receipt
    except Exception as error:
        message = str(error)
        message = message.replace(str(prefix), "<prefix>").replace(str(inputs_path), "<inputs>")
        message = re.sub(r"(?<!\S)/(?:[^\s:]+)", "<absolute-path>", message)[:512]
        receipt.update({"failure": {"phase": phase, "type": type(error).__name__,
                                    "message": message},
                        "observed_managed_prefix_bytes": ci_cargo.directory_bytes(prefix)})
        _write_receipt(prefix, receipt)
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", required=True, type=Path)
    parser.add_argument("--inputs", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        receipt = provision(args.prefix, args.inputs)
    except Exception as error:
        print("ci-python: FAILED (" + type(error).__name__ + ")", file=sys.stderr)
        return 1
    print("ci-python: COMPLETE " + receipt["host"] + " Python " + receipt["version"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
