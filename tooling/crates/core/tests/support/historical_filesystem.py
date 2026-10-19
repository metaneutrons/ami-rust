#!/usr/bin/env python3
"""Pinned historical Python side of the explicit inventory/TAR comparison."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import platform
import stat
import subprocess
import sys
import tarfile
from pathlib import Path

FIXTURE_DIGESTS_SHA256 = "3fa952f9167b2b54ec694b26f1271cfccd1949b5634cc041132957b623d548a0"
TARFILE_SHA256 = "f0891b6936a39e5a41bd857fc149191fbe30ca84e5958f203682e76e218ff2a4"
HISTORICAL_SOURCE_PINS = {
    "host/contracts.py": "6984a7aaa1fbd22ab01877ed4d8cbf88ba1c0dddf46bbc96ea53bedb46fe0176",
    "release/install.py": "0e77fa70bcaa69d08de3102e18c102a063b276c654242e676dd20fab6d74e984",
}
FUNCTION_PINS = {
    "host/contracts.py:measure_inventory": (98, 143, 2420, "d0a7722e9d4a48e16750783dc6cb416ce73f6ee3274282cfd3ed6873f9a5255f"),
    "release/install.py:_inventory": (178, 207, 1377, "31094c51065955ae84779e3bdcdf976be3024a9a9dc39eceb282aecb0199dab8"),
    "release/install.py:_verify_archive": (473, 514, 2286, "e634f1703ccd064d94861b1e6d2be667cd5ea387a41f721ea2326efc56e9d8eb"),
}
INVENTORY_NAMES = (
    "valid", "empty-directory", "link-chain", "file-change", "file-missing",
    "extra-file", "file-symlink", "directory-symlink", "link-mismatch",
    "escaping-link", "broken-link", "cyclic-link", "extra-symlink", "fifo",
)
MAX_OUTPUT_BYTES = 1024 * 1024


class ReplayError(RuntimeError):
    pass


def need(condition: bool, message: str) -> None:
    if not condition:
        raise ReplayError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_directory(value: str, label: str) -> Path:
    path = Path(value)
    need(path.is_absolute() and not path.is_symlink() and path.is_dir(), f"{label} must be an absolute real directory")
    need(path.resolve(strict=True) == path, f"{label} must already be canonical")
    return path


def file_identity(path: Path) -> dict:
    need(path.is_file() and not path.is_symlink(), f"fixture must be a regular file: {path}")
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": sha(raw)}


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    need(spec is not None and spec.loader is not None, f"cannot import historical source: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def core_source_hashes(source: Path) -> dict[str, str]:
    root = source / "tooling/crates/core/src"
    result = {}
    for path in sorted(root.rglob("*.rs")):
        need(path.is_file() and not path.is_symlink(), f"unexpected core source entry: {path}")
        result[path.relative_to(source).as_posix()] = sha(path.read_bytes())
    need(result, "core source tree is empty")
    return result


def verify_historical_functions(source: Path) -> dict:
    records = {}
    for relative, expected_sha in HISTORICAL_SOURCE_PINS.items():
        need(sha((source / relative).read_bytes()) == expected_sha,
             f"historical source/dependency bytes changed: {relative}")
    for key, (first, last, byte_count, expected_sha) in FUNCTION_PINS.items():
        relative, name = key.split(":", 1)
        path = source / relative
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        tree = ast.parse(text)
        functions = [node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name]
        need(len(functions) == 1, f"historical function missing or ambiguous: {key}")
        node = functions[0]
        need(node.lineno == first and node.end_lineno == last, f"historical function span changed: {key}")
        function_bytes = b"".join(raw.splitlines(keepends=True)[first - 1:last])
        need(len(function_bytes) == byte_count and sha(function_bytes) == expected_sha, f"historical function changed: {key}")
        records[key] = {"line_start": first, "line_end": last, "bytes": byte_count, "sha256": expected_sha}
    return records


def verify_runtime(source: Path, python: Path) -> dict:
    need(python.is_absolute() and not python.is_symlink() and python.is_file(), "pinned Python must be an absolute regular file")
    need(python.resolve(strict=True) == python and os.access(python, os.X_OK), "pinned Python must be canonical and executable")
    host = {("Darwin", "arm64"): "macos-aarch64", ("Linux", "x86_64"): "linux-x86_64"}.get(
        (platform.system(), platform.machine().lower())
    )
    need(host is not None, "historical filesystem replay supports only macOS arm64 and Linux x86_64")
    ci_raw = (source / "release/ci-python-inputs.json").read_bytes()
    ci = json.loads(ci_raw)
    need(ci.get("schema") == "ami-rust-ci-python-inputs-v1" and ci.get("version") == "3.12.15", "tracked Python runtime pin schema/version changed")
    pin = ci["hosts"][host]
    need(pin["runtime_relative_path"] == "python/bin/python3.12", "tracked Python runtime path changed")
    python_raw = python.read_bytes()
    need(len(python_raw) == pin["runtime_bytes"] and sha(python_raw) == pin["runtime_sha256"], "Python bytes differ from the tracked release pin")
    need(Path(sys.executable).resolve(strict=True) == python, "helper is not running under the explicitly pinned interpreter")
    need(tuple(sys.version_info[:3]) == (3, 12, 15), "pinned Python version is not 3.12.15")
    python_root = python.parent.parent
    tarfile_path = Path(tarfile.__file__).resolve(strict=True)
    need(tarfile_path.relative_to(python_root).as_posix() == "lib/python3.12/tarfile.py", "tarfile module is outside pinned runtime")
    tarfile_sha = sha(tarfile_path.read_bytes())
    need(tarfile_sha == TARFILE_SHA256, "pinned tarfile.py bytes changed")
    return {
        "path": str(python), "host": host, "version": sys.version,
        "bytes": len(python_raw), "sha256": sha(python_raw),
        "ci_python_inputs_sha256": sha(ci_raw), "tarfile_path": str(tarfile_path),
        "tarfile_sha256": tarfile_sha,
    }


def root_snapshot_sha(root: Path) -> str:
    rows = {}

    def walk(directory: Path, prefix: str = "") -> None:
        for entry in sorted(os.scandir(directory), key=lambda item: item.name):
            path = Path(entry.path)
            relative = f"{prefix}/{entry.name}" if prefix else entry.name
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                rows[relative] = {"type": "dir"}
                walk(path, relative)
            elif stat.S_ISREG(mode):
                raw = path.read_bytes()
                rows[relative] = {"type": "file", "bytes": len(raw), "sha256": sha(raw)}
            elif stat.S_ISLNK(mode):
                rows[relative] = {"type": "symlink", "target": os.readlink(path)}
            elif stat.S_ISFIFO(mode):
                rows[relative] = {"type": "fifo"}
            else:
                raise ReplayError(f"unsupported inventory fixture object: {path}")

    walk(root)
    encoded = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha(encoded)


def make_inventory_cases(root: Path, digest_manifest: dict) -> list[dict]:
    root.mkdir(mode=0o700)
    cases = []
    expected = digest_manifest["inventory_cases"]
    need(len(expected) == 14 and set(expected) == set(INVENTORY_NAMES), "inventory fixture case identity changed")
    for name in INVENTORY_NAMES:
        tree = root / f"{name} root with spaces"
        tree.mkdir(mode=0o700)
        (tree / "dir").mkdir()
        (tree / "dir/file").write_bytes(b"original")
        manifest = {"files": [{"path": "dir/file", "bytes": 8, "sha256": sha(b"original")}], "symlinks": []}
        if name == "empty-directory":
            (tree / "empty").mkdir()
        if name == "link-chain":
            (tree / "a").symlink_to("dir")
            (tree / "b").symlink_to("a/file")
            manifest["symlinks"] = [{"path": "a", "target": "dir"}, {"path": "b", "target": "a/file"}]
        if name == "file-change":
            (tree / "dir/file").write_bytes(b"changed!")
        if name == "file-missing":
            (tree / "dir/file").unlink()
        if name == "extra-file":
            (tree / "extra").write_bytes(b"extra")
        if name == "file-symlink":
            (tree / "dir/file").unlink()
            (tree / "dir/file").symlink_to("other")
            (tree / "dir/other").write_bytes(b"original")
        if name == "directory-symlink":
            (tree / "dir").rename(tree / "other")
            (tree / "dir").symlink_to("other")
        if name in {"link-mismatch", "escaping-link", "broken-link", "cyclic-link"}:
            target = {"link-mismatch": "dir/file", "escaping-link": "../outside", "broken-link": "missing", "cyclic-link": "a"}[name]
            (tree / "a").symlink_to(target)
            manifest["symlinks"] = [{"path": "a", "target": "different" if name == "link-mismatch" else target}]
        if name == "extra-symlink":
            (tree / "extra").symlink_to("dir/file")
        if name == "fifo":
            os.mkfifo(tree / "special")
        manifest_path = root / f"{name}.inventory.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        need(sha(manifest_path.read_bytes()) == expected[name]["inventory_sha256"], f"generated inventory manifest changed: {name}")
        need(root_snapshot_sha(tree) == expected[name]["root_sha256"], f"generated inventory tree changed: {name}")
        cases.append({"kind": "inventory", "case": name, "root": str(tree), "inventory": str(manifest_path)})
    return cases


def historical_python(case: dict, contracts, installer) -> dict:
    try:
        if case["kind"] == "inventory":
            manifest = json.loads(Path(case["inventory"]).read_bytes())
            count = contracts.measure_inventory(Path(case["root"]), manifest, complete=True)
            return {"decision": "accept", "exit_code": 0, "count": count, "report": None, "error": None}
        compressed = Path(case["archive"]).read_bytes()
        inventory = json.loads(Path(case["inventory"]).read_bytes())
        expected = installer._inventory(
            inventory, "SDK file", count_limit=1000,
            total_limit=16 * 1024 * 1024, file_limit=16 * 1024 * 1024,
        )
        found, modes = installer._verify_archive(compressed, expected)
        report = {
            name: {"bytes": len(data), "sha256": sha(data), "mode": 0o755 if modes[name] & 0o111 else 0o644}
            for name, data in found.items()
        }
        return {"decision": "accept", "exit_code": 0, "count": None, "report": report, "error": None}
    except Exception as error:
        return {"decision": "refuse", "exit_code": 2, "count": None, "report": None,
                "error": f"{type(error).__name__}: {error}"}


def run() -> None:
    allowed = {
        "PATH", "HOME", "TMPDIR", "LC_ALL", "LANG", "AMI_RUST_DIFFERENTIAL_SOURCE",
        "AMI_RUST_DIFFERENTIAL_WORK", "AMI_RUST_HISTORICAL_PYTHON",
        "AMI_RUST_DIFFERENTIAL_TEST_BINARY", "AMI_RUST_CARGO_MANIFEST_DIR",
    }
    injected = {"__CF_USER_TEXT_ENCODING"} if platform.system() == "Darwin" else set()
    need(allowed.issubset(os.environ) and set(os.environ) - allowed <= injected,
         "Python helper environment differs from the explicit allowlist")
    need(not any("TOKEN" in key.upper() for key in os.environ), "token-like environment variable present")
    need(os.environ["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin", "unexpected Python helper PATH")
    if "__CF_USER_TEXT_ENCODING" in os.environ:
        need(len(os.environ["__CF_USER_TEXT_ENCODING"].split(":")) == 3, "unexpected macOS environment injection")

    package = canonical_directory(os.environ["AMI_RUST_CARGO_MANIFEST_DIR"], "core package root")
    source = canonical_directory(os.environ["AMI_RUST_DIFFERENTIAL_SOURCE"], "selected source root")
    need(source == (package / "../../..").resolve(strict=True), "source root differs from compiled core checkout")
    work = canonical_directory(os.environ["AMI_RUST_DIFFERENTIAL_WORK"], "private output root")
    need({path.name for path in work.iterdir()} == {"home", "tmp"}, "private output root is not fresh")
    binary = Path(os.environ["AMI_RUST_DIFFERENTIAL_TEST_BINARY"])
    need(binary.is_absolute() and binary.is_file() and not binary.is_symlink() and os.access(binary, os.X_OK),
         "Rust integration-test binary must be an absolute executable")
    python = Path(os.environ["AMI_RUST_HISTORICAL_PYTHON"])

    fixture_manifest_path = package / "tests/fixtures/historical_filesystem/fixture-digests.json"
    fixture_raw = fixture_manifest_path.read_bytes()
    need(sha(fixture_raw) == FIXTURE_DIGESTS_SHA256, "fixture digest manifest changed")
    fixture_manifest = json.loads(fixture_raw)
    need(fixture_manifest.get("schema") == "ami-rust-historical-filesystem-fixture-digests-v1", "unknown fixture digest schema")
    need(len(fixture_manifest["inventory_cases"]) == 14 and len(fixture_manifest["archive_cases"]) == 36,
         "fixture case counts changed")
    expected_files = {"fixture-digests.json"}
    for name in fixture_manifest["archive_cases"]:
        expected_files.update({f"{name}.tar.xz", f"{name}.inventory.json"})
    fixture_root = fixture_manifest_path.parent
    need({path.name for path in fixture_root.iterdir()} == expected_files, "unexpected or missing TAR fixture file")
    archive_cases = []
    for name, pins in fixture_manifest["archive_cases"].items():
        archive = fixture_root / f"{name}.tar.xz"
        inventory = fixture_root / f"{name}.inventory.json"
        need(file_identity(archive)["sha256"] == pins["archive_sha256"], f"TAR fixture digest changed: {name}")
        need(file_identity(inventory)["sha256"] == pins["inventory_sha256"], f"TAR inventory digest changed: {name}")
        archive_cases.append({"kind": "archive", "case": name, "archive": str(archive), "inventory": str(inventory)})

    runtime = verify_runtime(source, python)
    functions = verify_historical_functions(source)
    source_hashes_before = core_source_hashes(source)
    test_source = package / "tests/historical_filesystem.rs"
    helper_source = package / "tests/support/historical_filesystem.py"
    test_hash_before = sha(test_source.read_bytes())
    helper_hash_before = sha(helper_source.read_bytes())

    runs = work / "runs"
    fixtures = work / "fixtures"
    runs.mkdir(mode=0o700)
    fixtures.mkdir(mode=0o700)
    inventory_cases = make_inventory_cases(fixtures / "inventory", fixture_manifest)
    cases = inventory_cases + archive_cases
    need(len(cases) == 50, "replay did not construct exactly 50 cases")
    contracts = load_module("ami_rust_historical_contracts", source / "host/contracts.py")
    installer = load_module("ami_rust_historical_installer", source / "release/install.py")

    paired = []
    for case in cases:
        row = dict(case)
        row["python"] = historical_python(case, contracts, installer)
        paired.append(row)
    plan = {"schema": "ami-rust-historical-filesystem-plan-v1", "cases": [
        {key: row[key] for key in ("kind", "case", "root", "inventory", "archive") if key in row}
        for row in paired
    ]}
    plan_path = runs / "case-plan.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    rust_result_path = runs / "rust-cases.json"
    rust_env = {
        "PATH": "/usr/bin:/bin", "HOME": str(work / "home"), "TMPDIR": str(work / "tmp"),
        "LC_ALL": "C", "LANG": "C", "AMI_RUST_DIFFERENTIAL_SOURCE": str(source),
        "AMI_RUST_FILESYSTEM_CASE_PLAN": str(plan_path),
        "AMI_RUST_FILESYSTEM_RUST_RESULT": str(rust_result_path),
    }
    command = [str(binary), "--ignored", "--exact", "filesystem_core_cases", "--nocapture"]
    child = subprocess.run(command, cwd=work, env=rust_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           check=False, timeout=120)
    need(len(child.stdout) <= MAX_OUTPUT_BYTES and len(child.stderr) <= MAX_OUTPUT_BYTES,
         "Rust replay child raw output exceeds 1 MiB")
    (runs / "rust-child.stdout.raw").write_bytes(child.stdout)
    (runs / "rust-child.stderr.raw").write_bytes(child.stderr)
    need(child.returncode == 0, f"Rust case child exited {child.returncode}")
    rust_raw = rust_result_path.read_bytes()
    need(len(rust_raw) <= 4 * 1024 * 1024, "Rust case report exceeds 4 MiB")
    rust_report = json.loads(rust_raw)
    need(rust_report.get("status") == "ok" and rust_report.get("case_count") == 50, "Rust report is incomplete")
    rust_rows = {(row["kind"], row["case"]): row for row in rust_report["cases"]}
    need(len(rust_rows) == 50, "Rust report case identities are not unique")

    python_accept = rust_accept = decision_equal = exit_equal = archive_report_equal = 0
    for case in paired:
        key = (case["kind"], case["case"])
        python_row = case["python"]
        rust_row = rust_rows.get(key)
        need(rust_row is not None, f"Rust result missing: {key}")
        need(python_row["decision"] == rust_row["decision"], f"Python/Rust decision differs: {key}")
        need(python_row["exit_code"] == rust_row["decision_exit_code"], f"Python/Rust exit code differs: {key}")
        decision_equal += 1
        exit_equal += 1
        if python_row["decision"] == "accept":
            python_accept += 1
            rust_accept += 1
            need(rust_row["semantic_report"] is not None, f"accepted Rust semantic report missing: {key}")
            if case["kind"] == "inventory":
                need(rust_row["semantic_report"]["files"] + rust_row["semantic_report"]["symlinks"] == python_row["count"],
                     f"accepted inventory count differs: {key}")
            else:
                need(rust_row["semantic_report"] == python_row["report"], f"accepted TAR report differs: {key}")
                archive_report_equal += 1
        else:
            need(rust_row["semantic_report"] is None, f"refused Rust case returned a semantic report: {key}")
        case["rust"] = rust_row
        case["decision_equal"] = True
        case["exit_equal"] = True
        case["full_report_equal"] = case["kind"] == "archive" and python_row["decision"] == "accept"

    need(python_accept == rust_accept == 17, "accepted decision total differs from reviewed replay")
    need(archive_report_equal == 14, "accepted publisher TAR report count differs from reviewed replay")
    source_hashes_after = core_source_hashes(source)
    test_hash_after = sha(test_source.read_bytes())
    helper_hash_after = sha(helper_source.read_bytes())
    need(source_hashes_before == source_hashes_after, "core source bytes changed during replay")
    need(test_hash_before == test_hash_after and helper_hash_before == helper_hash_after,
         "test or helper source changed during replay")

    report = {
        "schema": "ami-rust-historical-filesystem-replay-v1", "status": "pass",
        "scope": "Maintainer-only inventory and publisher TAR differential; not consumer command or no-Python acceptance.",
        "source_root": str(source), "python_runtime": runtime,
        "historical_functions": functions,
        "fixture_digest_manifest_sha256": sha(fixture_raw),
        "runtime_source_hashes": {"core_before": source_hashes_before, "core_after": source_hashes_after,
                                  "rust_test_sha256": test_hash_before, "python_helper_sha256": helper_hash_before},
        "rust_child_exit_code": child.returncode,
        "case_counts": {"inventory": len(inventory_cases), "archive": len(archive_cases), "total": len(cases)},
        "decision_counts": {"python_accept": python_accept, "rust_accept": rust_accept,
                            "decision_equal": decision_equal, "exit_equal": exit_equal,
                            "archive_full_report_equal": archive_report_equal},
        "cases": paired,
    }
    (work / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "pass", "case_counts": report["case_counts"], "decision_counts": report["decision_counts"]}, sort_keys=True))


def main() -> int:
    try:
        run()
        return 0
    except BaseException as error:
        print(f"historical filesystem replay failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
