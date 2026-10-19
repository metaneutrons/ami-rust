#!/usr/bin/env python3
"""Pinned historical Python side of the explicit receipt lifecycle replay."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import platform
import stat
import subprocess
import sys
import tarfile
import traceback
from pathlib import Path

INSTALL_SHA256 = "0e77fa70bcaa69d08de3102e18c102a063b276c654242e676dd20fab6d74e984"
TEST_INSTALL_SHA256 = "379ba1ab0f3795dd880c17ec46705bf976da9b21bc9a57f7884c573e73bcd64c"
TARFILE_SHA256 = "f0891b6936a39e5a41bd857fc149191fbe30ca84e5958f203682e76e218ff2a4"
MAX_OUTPUT_BYTES = 1024 * 1024


class ReplayError(RuntimeError):
    pass


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ReplayError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_dir(path_text: str, label: str) -> Path:
    path = Path(path_text)
    need(path.is_absolute() and path.is_dir() and not path.is_symlink(),
         f"{label} must be a real absolute directory")
    need(path.resolve(strict=True) == path, f"{label} must already be canonical")
    return path


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    need(spec is not None and spec.loader is not None, f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def core_source_hashes(source: Path) -> dict[str, str]:
    core = source / "tooling/crates/core"
    selector = source / "tooling/macos-host-selection.rs"
    need(selector.is_file() and not selector.is_symlink(),
         "shared macOS host-selection source must be a regular file")
    paths = [core / "build.rs", core / "src/macos_process_snapshot.c", selector]
    paths.extend(sorted((core / "src").rglob("*.rs")))
    result = {}
    for path in paths:
        if not path.exists():
            continue
        need(path.is_file() and not path.is_symlink(), f"unexpected core source entry: {path}")
        result[path.relative_to(source).as_posix()] = sha(path.read_bytes())
    need(result, "current core source inventory is empty")
    return result


def check_runtime(source: Path, python: Path) -> dict:
    need(python.is_absolute() and python.is_file() and not python.is_symlink(),
         "pinned Python must be an absolute regular file")
    need(python.resolve(strict=True) == python and os.access(python, os.X_OK),
         "pinned Python must be canonical and executable")
    host = {("Darwin", "arm64"): "macos-aarch64", ("Linux", "x86_64"): "linux-x86_64"}.get(
        (platform.system(), platform.machine().lower()))
    need(host is not None, "this pair supports macOS arm64 and Linux x86-64")
    ci_raw = (source / "release/ci-python-inputs.json").read_bytes()
    ci = json.loads(ci_raw)
    need(ci.get("schema") == "ami-rust-ci-python-inputs-v1" and ci.get("version") == "3.12.15",
         "tracked Python pin schema/version changed")
    pin = ci["hosts"][host]
    need(pin["runtime_relative_path"] == "python/bin/python3.12", "tracked Python runtime path changed")
    python_raw = python.read_bytes()
    need(len(python_raw) == pin["runtime_bytes"] and sha(python_raw) == pin["runtime_sha256"],
         "Python executable differs from tracked host pin")
    need(Path(sys.executable).resolve(strict=True) == python,
         "helper is not running in the explicitly pinned Python")
    need(tuple(sys.version_info[:3]) == (3, 12, 15), "pinned Python version changed")
    python_root = python.parent.parent
    tarfile_path = Path(tarfile.__file__).resolve(strict=True)
    need(tarfile_path.relative_to(python_root).as_posix() == "lib/python3.12/tarfile.py",
         "tarfile module is outside pinned runtime")
    tarfile_sha = sha(tarfile_path.read_bytes())
    need(tarfile_sha == TARFILE_SHA256, "tarfile.py differs from the frozen historical input")
    return {
        "path": str(python),
        "host": host,
        "version": sys.version,
        "bytes": len(python_raw),
        "sha256": sha(python_raw),
        "ci_python_inputs_sha256": sha(ci_raw),
        "tarfile_path": str(tarfile_path),
        "tarfile_sha256": tarfile_sha,
    }


def tree_snapshot(root: Path):
    if not root.exists() and not root.is_symlink():
        return None
    rows = []
    pending = [(root, ".")]
    while pending:
        path, relative = pending.pop()
        info = path.lstat()
        base = {"path": relative, "mode": stat.S_IMODE(info.st_mode),
                "uid": info.st_uid, "gid": info.st_gid}
        if stat.S_ISDIR(info.st_mode):
            rows.append({**base, "kind": "directory"})
            children = sorted(os.scandir(path), key=lambda entry: entry.name, reverse=True)
            for child in children:
                child_path = Path(child.path)
                child_relative = child.name if relative == "." else f"{relative}/{child.name}"
                pending.append((child_path, child_relative))
        elif stat.S_ISREG(info.st_mode):
            raw = path.read_bytes()
            rows.append({**base, "kind": "file", "bytes": len(raw), "sha256": sha(raw)})
        elif stat.S_ISLNK(info.st_mode):
            rows.append({**base, "kind": "symlink", "target": os.readlink(path)})
        else:
            rows.append({**base, "kind": "special"})
    return sorted(rows, key=lambda row: row["path"])


def save_log(name: str, payload: dict, runs: Path, logs: list[str]) -> None:
    path = runs / f"{name}.json"
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    logs.append(str(path))


def rust_call(name: str, plan: dict, binary: Path, work: Path,
              runs: Path, logs: list[str]) -> dict:
    plan_path = runs / f"{name}.plan.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    child_env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(work / "home"),
        "TMPDIR": str(work / "tmp"),
        "LC_ALL": "C",
        "LANG": "C",
        "AMI_RUST_DIFFERENTIAL_SOURCE": os.environ["AMI_RUST_DIFFERENTIAL_SOURCE"],
        "AMI_RUST_RECEIPT_LIFECYCLE_PLAN": str(plan_path),
    }
    command = [str(binary), "--ignored", "--exact",
               "paired_historical_receipt_lifecycle_child", "--nocapture"]
    proc = subprocess.run(command, cwd=work, env=child_env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=False, timeout=60)
    need(len(proc.stdout) <= MAX_OUTPUT_BYTES and len(proc.stderr) <= MAX_OUTPUT_BYTES,
         f"{name}: Rust bridge raw output exceeded 1 MiB")
    result_path = plan_path.with_suffix(".result.json")
    try:
        result = json.loads(result_path.read_bytes())
    except Exception:
        result = None
    save_log(name + ".rust", {
        "command": command,
        "returncode": proc.returncode,
        "stdout": proc.stdout.decode("utf-8", "replace"),
        "stderr": proc.stderr.decode("utf-8", "replace"),
        "parsed": result,
    }, runs, logs)
    need(isinstance(result, dict), f"{name}: Rust bridge did not write a result")
    expected = int(result.get("exit_code", 2)) if result.get("status") == "refusal" else 0
    need(proc.returncode == expected,
         f"{name}: Rust exit {proc.returncode}, expected {expected}; result={result!r}")
    need(result.get("status") in ("ok", "refusal"), f"{name}: Rust bridge failed: {result!r}")
    return result


def python_call(name: str, proc, runs: Path, logs: list[str]) -> dict | None:
    try:
        payload = json.loads(proc.stdout) if proc.stdout.strip() else None
    except Exception:
        payload = None
    save_log(name + ".python", {
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "parsed": payload,
    }, runs, logs)
    return payload


def require_owned_safe_tree(snapshot, label: str) -> None:
    need(snapshot is not None, f"{label}: expected a filesystem tree")
    for row in snapshot:
        need(row["uid"] == os.getuid(), f"{label}: unexpected owner at {row['path']}")
        need(row["mode"] & 0o022 == 0, f"{label}: group/world-writable object at {row['path']}")


def make_rust_install_inputs(fixture, installer, case_root: Path) -> list[dict]:
    verified = installer.verify_bundle(str(fixture.bundle), str(fixture.trust_path))
    inputs = case_root / "rust-input-files"
    inputs.mkdir(mode=0o700)
    specs = []
    index = 0
    for name, contents in sorted(verified["sdk_files"].items()):
        mode = 0o755 if verified["sdk_modes"].get(name, 0o644) & 0o111 else 0o644
        path = inputs / f"{index:03d}.bin"
        index += 1
        path.write_bytes(contents)
        specs.append({"path": "sdk/" + name, "source": str(path), "mode": mode})
    for name, contents in sorted(verified["assets"].items()):
        path = inputs / f"{index:03d}.bin"
        index += 1
        path.write_bytes(contents)
        specs.append({"path": "payload/" + name, "source": str(path), "mode": 0o644})
    for name, contents in (("release.json", verified["manifest_raw"]),
                           ("release.json.sig", verified["signature"])):
        path = inputs / f"{index:03d}.bin"
        index += 1
        path.write_bytes(contents)
        specs.append({"path": "payload/" + name, "source": str(path), "mode": 0o644})
    return specs


def main() -> dict:
    allowed = {
        "PATH", "HOME", "TMPDIR", "LC_ALL", "LANG",
        "AMI_RUST_DIFFERENTIAL_SOURCE", "AMI_RUST_DIFFERENTIAL_WORK",
        "AMI_RUST_HISTORICAL_PYTHON", "AMI_RUST_DIFFERENTIAL_TEST_BINARY",
        "AMI_RUST_CARGO_MANIFEST_DIR",
    }
    injected = {"__CF_USER_TEXT_ENCODING"} if platform.system() == "Darwin" else set()
    need(allowed.issubset(os.environ) and set(os.environ) - allowed <= injected,
         "Python helper environment differs from its explicit allowlist")
    need(not any("TOKEN" in key.upper() for key in os.environ),
         "token-like environment variable present")
    need(os.environ["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin", "unexpected helper PATH")
    if "__CF_USER_TEXT_ENCODING" in os.environ:
        need(len(os.environ["__CF_USER_TEXT_ENCODING"].split(":")) == 3,
             "unexpected macOS environment injection")

    package = canonical_dir(os.environ["AMI_RUST_CARGO_MANIFEST_DIR"], "compiled core package root")
    source = canonical_dir(os.environ["AMI_RUST_DIFFERENTIAL_SOURCE"], "selected source root")
    need(source == (package / "../../..").resolve(strict=True),
         "selected source root differs from CARGO_MANIFEST_DIR")
    need(package == source / "tooling/crates/core", "CARGO_MANIFEST_DIR is not selected core package")
    work = canonical_dir(os.environ["AMI_RUST_DIFFERENTIAL_WORK"], "private output root")
    need({path.name for path in work.iterdir()} == {"home", "tmp"},
         "private output root is not fresh")
    binary = Path(os.environ["AMI_RUST_DIFFERENTIAL_TEST_BINARY"])
    need(binary.is_absolute() and binary.is_file() and not binary.is_symlink()
         and os.access(binary, os.X_OK), "Rust integration-test binary must be an absolute executable")
    python = Path(os.environ["AMI_RUST_HISTORICAL_PYTHON"])

    installer_path = source / "release/install.py"
    test_path = source / "release/test_install.py"
    need(sha(installer_path.read_bytes()) == INSTALL_SHA256,
         "frozen historical installer source changed")
    need(sha(test_path.read_bytes()) == TEST_INSTALL_SHA256,
         "frozen historical installer test source changed")
    runtime = check_runtime(source, python)
    core_before = core_source_hashes(source)
    test_source = package / "tests/historical_receipt_lifecycle.rs"
    helper_source = package / "tests/support/historical_receipt_lifecycle.py"
    test_hash_before = sha(test_source.read_bytes())
    helper_hash_before = sha(helper_source.read_bytes())
    logs: list[str] = []
    cases: list[dict] = []
    runs = work / "runs"
    runs.mkdir(mode=0o700)

    installer = load_module("ami_rust_historical_installer", installer_path)
    tests = load_module("ami_rust_historical_test_install", test_path)
    tests.InstallerFixture.setUpClass()
    fixture = tests.InstallerFixture("test_install_then_uninstall_removes_only_owned_tree")
    fixture.setUp()
    try:
        source_bundle_before = tree_snapshot(fixture.bundle)
        specs = make_rust_install_inputs(fixture, installer, fixture.case)

        def install_pair(label: str):
            py_home = fixture.case / f"{label}-python"
            rs_home = fixture.case / f"{label}-rust"
            py_home.mkdir(mode=0o700)
            rs_home.mkdir(mode=0o700)
            (py_home / "user-config.txt").write_bytes(b"preserve outside install\n")
            (rs_home / "user-config.txt").write_bytes(b"preserve outside install\n")
            py_prefix = py_home / "sdk-0.1.0-rc.3-local"
            rs_prefix = rs_home / "sdk-0.1.0-rc.3-local"
            py_pin = py_home / "receipt.sha256"
            rs_pin = rs_home / "receipt.sha256"

            py_proc = fixture._install(prefix=py_prefix, pin=py_pin, bundle=fixture.bundle)
            py_install = python_call(label + ".setup", py_proc, runs, logs)
            need(py_proc.returncode == 0 and py_install
                 and py_install.get("status") == "installed",
                 f"{label}: historical install failed: {py_proc.stderr!r}")
            receipt_raw = (py_prefix / "install-receipt.json").read_bytes()
            receipt = json.loads(receipt_raw)
            need(receipt.get("schema") == "ami-rust-install-receipt-v1",
                 f"{label}: expected historical v1 fixture, got {receipt.get('schema')!r}")
            receipt_source = fixture.case / f"{label}-receipt.bin"
            receipt_source.write_bytes(receipt_raw)
            rust_install = rust_call(label + ".setup", {
                "operation": "publish",
                "prefix": str(rs_prefix),
                "bundle": str(fixture.bundle),
                "receipt_source": str(receipt_source),
                "receipt_pin": str(rs_pin),
                "files": specs,
            }, binary, work, runs, logs)
            need(rust_install.get("status") == "ok",
                 f"{label}: Rust setup publication failed: {rust_install!r}")
            need(py_install["receipt_sha256"] == rust_install["receipt_sha256"],
                 f"{label}: published receipt digest differs")
            py_before = tree_snapshot(py_home)
            rs_before = tree_snapshot(rs_home)
            require_owned_safe_tree(py_before, label + " Python installation")
            require_owned_safe_tree(rs_before, label + " Rust installation")
            need(py_before == rs_before,
                 f"{label}: installed tree/owner/mode/pin state differs")
            return py_home, rs_home, py_prefix, rs_prefix, py_install["receipt_sha256"], py_before, rs_before

        # Positive: the same legacy v1 receipt is removed by Python's CLI and
        # the current linked core's receipt-aware uninstall API.
        py_home, rs_home, py_prefix, rs_prefix, digest, py_before, rs_before = install_pair("positive")
        py_proc = fixture._uninstall(prefix=py_prefix, receipt_sha256=digest)
        py_result = python_call("positive.uninstall", py_proc, runs, logs)
        need(py_proc.returncode == 0 and py_result
             and py_result.get("status") == "uninstalled",
             f"historical positive uninstall failed: {py_proc.stderr!r}")
        rust_result = rust_call("positive.uninstall", {
            "operation": "native-uninstall", "prefix": str(rs_prefix), "receipt_sha256": digest,
        }, binary, work, runs, logs)
        need(rust_result.get("status") == "ok", f"Rust semantic uninstall refused: {rust_result!r}")
        py_after = tree_snapshot(py_home)
        rs_after = tree_snapshot(rs_home)
        need(py_after == rs_after, "positive post-uninstall state differs")
        need((py_prefix.exists(), rs_prefix.exists()) == (False, False),
             "positive uninstall left an installation prefix")
        need((py_home / "receipt.sha256").read_text().strip() == digest
             and (rs_home / "receipt.sha256").read_text().strip() == digest,
             "positive uninstall did not retain the external receipt pin")
        need((py_home / "user-config.txt").read_bytes() == b"preserve outside install\n"
             and (rs_home / "user-config.txt").read_bytes() == b"preserve outside install\n",
             "positive uninstall changed adjacent user data")
        cases.append({
            "name": "positive-historical-v1-uninstall",
            "decision": "both accepted",
            "receipt_sha256": digest,
            "pre_state_python": py_before,
            "pre_state_rust": rs_before,
            "post_state_python": py_after,
            "post_state_rust": rs_after,
            "pin_retained": True,
            "adjacent_user_data_preserved": True,
        })

        # Counter-case: stale but syntactically valid pins must refuse without
        # changing any content, mode, UID/GID, or adjacent user data.
        py_home, rs_home, py_prefix, rs_prefix, digest, py_before, rs_before = install_pair("stale-pin")
        stale = "0" * 64
        need(stale != digest, "stale digest accidentally matches fixture receipt")
        py_proc = fixture._uninstall(prefix=py_prefix, receipt_sha256=stale)
        python_call("stale-pin.uninstall", py_proc, runs, logs)
        rust_result = rust_call("stale-pin.uninstall", {
            "operation": "native-uninstall", "prefix": str(rs_prefix), "receipt_sha256": stale,
        }, binary, work, runs, logs)
        need(py_proc.returncode == 2, f"historical stale-pin exit was {py_proc.returncode}, expected 2")
        need(rust_result.get("status") == "refusal" and rust_result.get("exit_code") == 2,
             f"Rust stale-pin decision differed: {rust_result!r}")
        py_after = tree_snapshot(py_home)
        rs_after = tree_snapshot(rs_home)
        need(py_before == rs_before == py_after == rs_after,
             "stale-pin refusal changed owned or adjacent filesystem state")
        cases.append({
            "name": "stale-external-receipt-pin",
            "decision": "both refused",
            "legacy_exit": py_proc.returncode,
            "rust_wrapper_exit": 2,
            "pre_state_python": py_before,
            "pre_state_rust": rs_before,
            "post_state_python": py_after,
            "post_state_rust": rs_after,
            "filesystem_unchanged": True,
        })

        core_after = core_source_hashes(source)
        test_hash_after = sha(test_source.read_bytes())
        helper_hash_after = sha(helper_source.read_bytes())
        need(core_before == core_after, "selected linked core sources changed during paired replay")
        need(test_hash_before == test_hash_after, "Rust test source changed during paired replay")
        need(helper_hash_before == helper_hash_after, "Python helper changed during paired replay")
        need(tree_snapshot(fixture.bundle) == source_bundle_before,
             "historical fixture bundle changed during replay")
        report = {
            "schema": "ami-rust-historical-receipt-lifecycle-pair-v1",
            "status": "pass",
            "scope": "Historical v1 receipt uninstall and stale external-pin refusal with full isolated tree/owner/mode/content snapshots.",
            "source_root": str(source),
            "core_package": str(package),
            "source_bindings": {
                "core_before": core_before,
                "core_after": core_after,
                "rust_test_sha256_before": test_hash_before,
                "rust_test_sha256_after": test_hash_after,
                "python_helper_sha256_before": helper_hash_before,
                "python_helper_sha256_after": helper_hash_after,
            },
            "historical_source_sha256": {
                "release/install.py": INSTALL_SHA256,
                "release/test_install.py": TEST_INSTALL_SHA256,
            },
            "python_runtime": check_runtime(source, python),
            "cases": cases,
            "case_count": len(cases),
            "ownership": "same-host UID/GID are recorded and compared; contents, object types and permission modes are compared; this does not exercise privileged cross-account mutation.",
            "limitations": [
                "The frozen historical fixture emits a receipt-v1. It does not model receipt-v3 fields.",
                "The historical Python validator accepts v1/v2 only and is not a semantic oracle for current v3 receipts.",
                "The Rust side calls native_install::uninstall from the selected linked core, not the installed CLI frontend.",
                "A v3 conclusion requires the signed current CLI install/uninstall path and stale-pin counter-case.",
            ],
            "logs": logs,
        }
        report_path = work / "report.json"
        report_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"status": "pass", "case_count": len(cases),
                          "cases": [case["name"] for case in cases]}, sort_keys=True))
        return report
    finally:
        fixture.tearDown()
        tests.InstallerFixture.tearDownClass()


if __name__ == "__main__":
    try:
        main()
    except BaseException as error:
        work_text = os.environ.get("AMI_RUST_DIFFERENTIAL_WORK")
        if work_text:
            work_path = Path(work_text)
            if work_path.is_dir():
                (work_path / "failure.json").write_text(json.dumps({
                    "status": "fail",
                    "error": f"{type(error).__name__}: {error}",
                    "traceback": traceback.format_exc(),
                }, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        print(f"receipt lifecycle replay failed: {type(error).__name__}: {error}", file=sys.stderr)
        raise
