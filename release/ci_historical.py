#!/usr/bin/env python3
"""Explicitly pair the pinned historical Python parsers with current core APIs.

This is maintainer qualification support. It does not invoke consumer commands,
verify cryptographic signatures, or claim RC1 acceptance.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

INSTALL_SHA256 = "0e77fa70bcaa69d08de3102e18c102a063b276c654242e676dd20fab6d74e984"
PUBLISHER_SHA256 = "446e3557d17bc8dfe1c145c948a37361b04e188ed5b9f15539e264d3e9221174"
EXPECTED_COUNTS = {
    "manifest": 41,
    "receipt": 14,
    "receipt-integer": 6,
    "publisher-claim": 70,
}
TOTAL_CASES = 131
MAX_RESULT_BYTES = 8 * 1024 * 1024
RUST_SOURCE_PATHS = [
    "tooling/crates/core/src/release_manifest.rs",
    "tooling/crates/core/src/receipts.rs",
    "tooling/crates/core/src/publisher_claims.rs",
    "tooling/crates/core/tests/historical_parser_differential.rs",
    "tooling/Cargo.lock",
]


class PinRefusal(RuntimeError):
    pass


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def file_identity(path: Path) -> dict:
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "sha256": sha256(raw)}


def host_profile() -> str:
    host = {
        ("Darwin", "arm64"): "macos-aarch64",
        ("Linux", "x86_64"): "linux-x86_64",
    }.get((platform.system(), platform.machine()))
    if host is None:
        raise PinRefusal("historical parser replay supports only macOS arm64 and Linux x86_64")
    return host


def canonical_directory(value: str | Path, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_dir():
        raise PinRefusal(f"{label} must be an absolute real directory")
    resolved = path.resolve(strict=True)
    if path != resolved:
        raise PinRefusal(f"{label} must already be canonical")
    return resolved


def canonical_executable(value: str | Path, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise PinRefusal(f"{label} must be an absolute regular executable")
    resolved = path.resolve(strict=True)
    if path != resolved or not os.access(path, os.X_OK):
        raise PinRefusal(f"{label} must be canonical and executable")
    return resolved


def verify_source_commit(source_root: Path, declared_commit: str) -> dict:
    """Bind the commit label to this exact, clean source checkout."""
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}

    def git(*arguments):
        result = subprocess.run(
            ["/usr/bin/git", "-C", str(source_root), *arguments], env=env,
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
        )
        return result.stdout.decode("utf-8").strip()

    if Path(git("rev-parse", "--show-toplevel")).resolve(strict=True) != source_root:
        raise PinRefusal("source is an archive or belongs to another Git checkout")
    if git("rev-parse", "HEAD") != declared_commit:
        raise PinRefusal("source checkout HEAD differs from the declared commit")
    if git("status", "--porcelain", "--untracked-files=all"):
        raise PinRefusal("source checkout has tracked or untracked changes")
    return {"commit": declared_commit, "tree": git("rev-parse", "HEAD^{tree}"),
            "clean_checkout_verified": True}


def runtime_pin(source_root: Path) -> tuple[dict, dict]:
    path = source_root / "release/ci-python-inputs.json"
    raw = path.read_bytes()
    inputs = json.loads(raw)
    if inputs.get("schema") != "ami-rust-ci-python-inputs-v1":
        raise PinRefusal("current CI Python input pin has an unknown schema")
    host = host_profile()
    runtime = inputs.get("hosts", {}).get(host)
    if not isinstance(runtime, dict):
        raise PinRefusal(f"CI Python input pin lacks host {host}")
    runtime = dict(runtime)
    runtime["version"] = inputs.get("version")
    if runtime.get("runtime_relative_path") != "python/bin/python3.12":
        raise PinRefusal("CI Python runtime path differs from the reviewed input")
    if not isinstance(runtime.get("runtime_bytes"), int) or not re.fullmatch(
        r"[0-9a-f]{64}", runtime.get("runtime_sha256", "")
    ):
        raise PinRefusal("CI Python runtime byte pin is malformed")
    return runtime, {"path": str(path), "bytes": len(raw), "sha256": sha256(raw)}


def verify_interpreter(source_root: Path, value: str | Path) -> dict:
    python = canonical_executable(value, "AMI_RUST_HISTORICAL_PYTHON")
    runtime, ci_identity = runtime_pin(source_root)
    raw = python.read_bytes()
    if len(raw) != runtime["runtime_bytes"] or sha256(raw) != runtime["runtime_sha256"]:
        raise PinRefusal("historical Python bytes differ from release/ci-python-inputs.json")
    return {
        "path": str(python),
        "host": host_profile(),
        "bytes": len(raw),
        "sha256": sha256(raw),
        "version": runtime_pin(source_root)[0].get("version", ""),
        "ci_python_inputs": ci_identity,
    }


def verify_python_sources(source_root: Path) -> dict:
    expected = {
        "release/install.py": INSTALL_SHA256,
        "release/verify_publisher.py": PUBLISHER_SHA256,
    }
    result = {}
    for relative, digest in expected.items():
        path = source_root / relative
        if path.is_symlink() or not path.is_file():
            raise PinRefusal(f"historical source is not a regular file: {relative}")
        identity = file_identity(path)
        if identity["sha256"] != digest:
            raise PinRefusal(f"historical source pin changed: {relative}")
        result[relative] = identity
    return result


def validate_production_lock(source_root: Path) -> dict:
    ref_path = source_root / "release/native-tooling-inputs.json"
    lock_path = source_root / "tooling/Cargo.lock"
    ref_raw = ref_path.read_bytes()
    reference = json.loads(ref_raw)
    lock_raw = lock_path.read_bytes()
    lock_pin = reference.get("cargo_lock", {})
    lock_identity = {"path": "tooling/Cargo.lock", "bytes": len(lock_raw), "sha256": sha256(lock_raw)}
    if lock_pin.get("path") != lock_identity["path"]:
        raise PinRefusal("native-tooling-inputs.json names a different Cargo lock")
    if lock_pin.get("bytes") != len(lock_raw) or lock_pin.get("sha256") != lock_identity["sha256"]:
        raise PinRefusal("Cargo.lock differs from the reviewed production lock pin")
    lock = tomllib.loads(lock_raw.decode("utf-8"))
    locked = sorted(
        (item["name"], item["version"], item["checksum"])
        for item in lock["package"]
        if item.get("source", "").startswith("registry+")
    )
    reviewed = sorted(
        (item["name"], item["version"], item["sha256"])
        for item in reference["registry_crates"]
    )
    if locked != reviewed or len(locked) != 29:
        raise PinRefusal("registry dependencies differ from the reviewed 29-package production lock")
    return {
        "cargo_lock": lock_identity,
        "native_tooling_inputs": {"path": str(ref_path), "bytes": len(ref_raw), "sha256": sha256(ref_raw)},
        "registry_package_count": len(locked),
    }


def rust_source_identities(source_root: Path) -> dict:
    return {relative: file_identity(source_root / relative) for relative in RUST_SOURCE_PATHS}


def verify_pinned_inputs(source_root: Path, python: str | Path) -> dict:
    source_root = canonical_directory(source_root, "source root")
    return {
        "source_root": str(source_root),
        "python_sources": verify_python_sources(source_root),
        "python_runtime": verify_interpreter(source_root, python),
        "production_lock": validate_production_lock(source_root),
    }


def guarded_child(source_root: Path, python: str | Path, runner):
    """Validate every Python pin before the supplied child-launch callback."""
    verify_pinned_inputs(source_root, python)
    return runner()


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load pinned historical module: {path.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def copy_fixture_tree(source: Path, destination: Path) -> dict:
    if source.is_symlink() or not source.is_dir() or destination.exists():
        raise RuntimeError(f"fixture copy roots must be a real source and fresh destination: {source}")
    rows = {}
    total_bytes = 0
    for directory, dirnames, filenames in os.walk(source, followlinks=False):
        directory_path = Path(directory)
        for name in list(dirnames):
            child = directory_path / name
            if child.is_symlink() or not child.is_dir():
                raise RuntimeError(f"fixture corpus contains a non-directory entry: {child}")
        for name in filenames:
            original = directory_path / name
            if original.is_symlink() or not original.is_file():
                raise RuntimeError(f"fixture corpus contains a non-regular file: {original}")
            relative = original.relative_to(source)
            raw = original.read_bytes()
            total_bytes += len(raw)
            if total_bytes > 32 * 1024 * 1024:
                raise RuntimeError("historical fixture copies exceed the 32 MiB input bound")
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            copied = target.read_bytes()
            if copied != raw:
                raise RuntimeError(f"fixture bytes changed while copying: {relative}")
            rows[relative.as_posix()] = {"bytes": len(raw), "sha256": sha256(raw)}
    return {"files": len(rows), "bytes": total_bytes, "tree_files": rows}


def assert_case_inputs(fixtures: Path) -> tuple[dict, dict]:
    definitions = [
        ("manifest", "release-manifests", "cases", "name", "input", "input_sha256"),
        ("receipt", "receipts", "cases", "case", "input", "input_sha256"),
        ("receipt-integer", "receipts/integers", "results", "case", "input", "input_sha256"),
        ("publisher-claim", "publisher-claims", "cases", "name", "file", "sha256"),
    ]
    oracle_identities = {}
    case_ids = set()
    counts = {}
    for corpus, directory, rows_key, name_key, file_key, digest_key in definitions:
        oracle_path = fixtures / directory / "oracle.json"
        raw = oracle_path.read_bytes()
        oracle = json.loads(raw)
        cases = oracle.get(rows_key)
        expected_count = EXPECTED_COUNTS[corpus]
        if not isinstance(cases, list) or len(cases) != expected_count:
            raise RuntimeError(f"{corpus} oracle must contain exactly {expected_count} cases")
        oracle_identities[corpus] = {"path": f"{directory}/oracle.json", "bytes": len(raw), "sha256": sha256(raw)}
        for case in cases:
            name = case.get(name_key)
            if not isinstance(name, str) or not name:
                raise RuntimeError(f"{corpus} oracle has an unnamed case")
            key = f"{corpus}:{name}"
            if key in case_ids:
                raise RuntimeError(f"duplicate corpus-scoped case identity: {key}")
            case_ids.add(key)
            rel = Path(directory) / case[file_key]
            if rel.is_absolute() or ".." in rel.parts:
                raise RuntimeError(f"unsafe fixture path in {key}")
            fixture = fixtures / rel
            input_raw = fixture.read_bytes()
            if sha256(input_raw) != case[digest_key]:
                raise RuntimeError(f"fixture digest differs from oracle: {key}")
        counts[corpus] = len(cases)
    if len(case_ids) != TOTAL_CASES or sum(counts.values()) != TOTAL_CASES:
        raise RuntimeError("fixture corpus is incomplete or has duplicate case identities")
    context_path = fixtures / "publisher-claims/context.json"
    context_raw = context_path.read_bytes()
    claim_oracle = json.loads((fixtures / "publisher-claims/oracle.json").read_bytes())
    if sha256(context_raw) != claim_oracle.get("context_sha256"):
        raise RuntimeError("publisher claims context differs from its frozen digest")
    oracle_identities["publisher-claims/context.json"] = {
        "path": "publisher-claims/context.json",
        "bytes": len(context_raw),
        "sha256": sha256(context_raw),
    }
    return counts, oracle_identities


def normalize_python_receipt(receipt: dict, inventory: dict) -> dict:
    typed_inventory = [
        {"path": path, "bytes": row[0], "sha256": row[1]}
        for path, row in sorted(inventory.items())
    ]
    authentication = receipt.get("authentication") or {}
    report = authentication.get("report") or {}
    workflow_runs = [
        {
            "run_id": str(row["runId"]),
            "run_attempt": str(row["runAttempt"]),
            "host_profile": row["hostProfile"],
        }
        for row in report.get("workflowRuns", [])
    ]
    return {
        "schema": receipt.get("schema"),
        "publisher": receipt.get("publisher"),
        "release_manifest_sha256": receipt.get("release_manifest_sha256"),
        "sdk_manifest_sha256": receipt.get("sdk_manifest_sha256"),
        "version": receipt.get("version"),
        "inventory": typed_inventory,
        "workflow_runs": workflow_runs,
    }


def historical_python_rows(fixtures: Path, work: Path, source_pins: dict) -> tuple[dict, dict]:
    historical_dir = work / "historical"
    historical_dir.mkdir()
    modules = {}
    for relative, name in [
        ("release/install.py", "historical_install"),
        ("release/verify_publisher.py", "historical_verify_publisher"),
    ]:
        raw = (Path(source_pins["source_root"]) / relative).read_bytes()
        dest = historical_dir / Path(relative).name
        dest.write_bytes(raw)
        if sha256(dest.read_bytes()) != source_pins["python_sources"][relative]["sha256"]:
            raise RuntimeError(f"private historical source copy changed: {relative}")
        modules[name] = load_module(name, dest)
    install = modules["historical_install"]
    publisher = modules["historical_verify_publisher"]
    rows = {}
    counts = {corpus: {"accept": 0, "refuse": 0} for corpus in EXPECTED_COUNTS}

    manifest_oracle = json.loads((fixtures / "release-manifests/oracle.json").read_bytes())
    for case in manifest_oracle["cases"]:
        key = f"manifest:{case['name']}"
        raw = (fixtures / "release-manifests" / case["input"]).read_bytes()
        error = None
        try:
            install._release_manifest(raw, production=case["production"])
            decision = "accept"
        except (ValueError, RecursionError) as exception:
            decision = "refuse"
            error = type(exception).__name__
        if (decision == "accept") != bool(case["historical_acceptance"]):
            raise RuntimeError(f"historical manifest result differs from oracle: {key}")
        counts["manifest"][decision] += 1
        rows[key] = {"corpus": "manifest", "name": case["name"], "decision": decision, "input_sha256": case["input_sha256"], "error_type": error}

    for corpus, subdir, rows_key in [
        ("receipt", "receipts", "cases"),
        ("receipt-integer", "receipts/integers", "results"),
    ]:
        oracle = json.loads((fixtures / subdir / "oracle.json").read_bytes())
        for case in oracle[rows_key]:
            name = case.get("case", case.get("name"))
            key = f"{corpus}:{name}"
            raw = (fixtures / subdir / case["input"]).read_bytes()
            error = None
            semantics = None
            try:
                receipt, inventory = install._validate_receipt(raw)
                decision = "accept"
                semantics = normalize_python_receipt(receipt, inventory)
            except (ValueError, RecursionError) as exception:
                decision = "refuse"
                error = type(exception).__name__
            expected = "accept" if case["decision"] == "accept" else "refuse"
            if decision != expected:
                raise RuntimeError(f"historical receipt result differs from oracle: {key}")
            if corpus == "receipt" and semantics is not None:
                for field in [
                    "schema", "publisher", "release_manifest_sha256",
                    "sdk_manifest_sha256", "version",
                ]:
                    if semantics[field] != case["receipt"][field]:
                        raise RuntimeError(f"historical receipt semantic mismatch for {key}: {field}")
                if semantics["inventory"] != case["typed_inventory"]:
                    raise RuntimeError(f"historical receipt inventory mismatch for {key}")
            counts[corpus][decision] += 1
            rows[key] = {
                "corpus": corpus,
                "name": name,
                "decision": decision,
                "input_sha256": case["input_sha256"],
                "common_receipt_semantics": semantics,
                "error_type": error,
            }

    context = json.loads((fixtures / "publisher-claims/context.json").read_bytes())
    oracle = json.loads((fixtures / "publisher-claims/oracle.json").read_bytes())
    if publisher._strict_json((fixtures / "publisher-claims/context.json").read_bytes(), "fixture context") != context:
        raise RuntimeError("historical claims context parsing was not stable")
    for case in oracle["cases"]:
        name = case["name"]
        key = f"publisher-claim:{name}"
        raw = (fixtures / "publisher-claims" / case["file"]).read_bytes()
        error = None
        try:
            statement = publisher._statement_result(raw, "fixture " + name)
            publisher._check_predicate(
                statement,
                policy=context["policy"],
                run=context["run"],
                host=context["host"],
                subject_paths=context["subject_paths"],
                manifest=context["manifest"],
                input_materials=context["input_materials"],
            )
            decision = "accept"
        except ValueError as exception:
            decision = "refuse"
            error = type(exception).__name__
        expected = case["expected"]
        if decision != expected or case["actual"] != expected:
            raise RuntimeError(f"historical publisher result differs from oracle: {key}")
        counts["publisher-claim"][decision] += 1
        rows[key] = {
            "corpus": "publisher-claim",
            "name": name,
            "decision": decision,
            "input_sha256": case["sha256"],
            "error_type": error,
        }

    if len(rows) != TOTAL_CASES or set(rows) != {
        f"{corpus}:{case[name_key]}"
        for corpus, directory, rows_key, name_key, *_ in [
            ("manifest", "release-manifests", "cases", "name"),
            ("receipt", "receipts", "cases", "case"),
            ("receipt-integer", "receipts/integers", "results", "case"),
            ("publisher-claim", "publisher-claims", "cases", "name"),
        ]
        for case in json.loads((fixtures / directory / "oracle.json").read_bytes())[rows_key]
    }:
        raise RuntimeError("historical Python replay did not execute every unique case")
    return rows, counts


def expect_preflight_refusal(source_root: Path, python: Path, child_counter: list[int], label: str) -> dict:
    try:
        guarded_child(source_root, python, lambda: child_counter.__setitem__(0, child_counter[0] + 1))
    except PinRefusal as exception:
        return {"label": label, "refused": True, "reason": str(exception)[:180]}
    raise RuntimeError(f"{label} was not refused before child execution")


def run_prechild_controls(source_root: Path, python: Path, work: Path) -> dict:
    controls = work / "prechild-controls"
    controls.mkdir()
    modified = controls / "changed-source"
    (modified / "release").mkdir(parents=True)
    for relative in [
        "release/install.py",
        "release/verify_publisher.py",
        "release/ci-python-inputs.json",
        "release/native-tooling-inputs.json",
    ]:
        shutil.copyfile(source_root / relative, modified / relative)
    with (modified / "release/install.py").open("ab") as stream:
        stream.write(b"\n# deliberately changed source pin control\n")
    fake_python = controls / "changed-python"
    fake_python.write_bytes(b"not the pinned Python runtime")
    fake_python.chmod(0o700)
    child_counter = [0]
    source_control = expect_preflight_refusal(modified, python, child_counter, "changed-source-pin")
    python_control = expect_preflight_refusal(source_root, fake_python.resolve(), child_counter, "interpreter-pin")
    if child_counter[0] != 0:
        raise RuntimeError("a child process started during a pin-refusal control")
    return {
        "source_pin_refused_before_child": source_control,
        "interpreter_pin_refused_before_child": python_control,
        "negative_control_child_count": child_counter[0],
    }


def validate_rust_toolchain(bin_dir: Path) -> dict:
    bin_dir = canonical_directory(bin_dir, "pinned Rust 1.98.1 bin directory")
    executables = {}
    for name in ("cargo", "rustc", "rustdoc"):
        executable = canonical_executable(bin_dir / name, f"pinned {name}")
        executables[name] = file_identity(executable)
    return {"bin_dir": str(bin_dir), "executables": executables}


def run_supervised_replay(
    source_root: Path,
    work: Path,
    supervised_output: Path,
    fixtures: Path,
    python: Path,
    rust_bin_dir: Path,
    cargo_home: Path,
    rust_result: Path,
    test_source: Path,
) -> dict:
    sys.path.insert(0, str(source_root / "release"))
    import ci_native as native

    python_root = python.parents[3]
    cargo = rust_bin_dir / "cargo"
    rustc = rust_bin_dir / "rustc"
    rustdoc = rust_bin_dir / "rustdoc"
    target = work / "target"
    home = work / "home"
    temp = work / "tmp"
    for directory in (work, supervised_output, home, temp):
        directory.mkdir(parents=True, exist_ok=True)
    if target.exists() or rust_result.exists():
        raise RuntimeError("supervised target and Rust result paths must be fresh")
    env = {
        "PATH": str(rust_bin_dir) + ":/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(home),
        "TMPDIR": str(temp),
        "LC_ALL": "C",
        "LANG": "C",
        "TZ": "UTC",
        "CARGO_HOME": str(cargo_home),
        "CARGO": str(cargo),
        "RUSTC": str(rustc),
        "RUSTDOC": str(rustdoc),
        "RUSTC_WRAPPER": "",
        "RUSTC_WORKSPACE_WRAPPER": "",
        "CARGO_BUILD_JOBS": "2",
        "CARGO_TARGET_DIR": str(target),
        "CARGO_NET_OFFLINE": "true",
        "AMI_RUST_HISTORICAL_PYTHON": str(python),
        "AMI_RUST_HISTORICAL_FIXTURE_ROOT": str(fixtures),
        "AMI_RUST_HISTORICAL_RUST_RESULT": str(rust_result),
    }
    cargo_home = canonical_directory(cargo_home, "existing Cargo cache home")
    rust_toolchain_root = rust_bin_dir.parent
    supervisor = native._make_supervisor(
        work,
        supervised_output,
        python_root,
        env,
        static_roots=[
            ("pinned-host-rust-1.98.1", rust_toolchain_root),
            ("existing-cargo-cache", cargo_home),
        ],
    )
    rustc_identity = native._supervised_text(
        supervisor, [rustc, "-Vv"], cwd=source_root, label="pinned-rustc-identity", timeout=60
    )
    if "rustc 1.98.1" not in rustc_identity or f"host: {host_target()}" not in rustc_identity:
        raise RuntimeError("host rustc identity differs from pinned Rust 1.98.1 for this host")
    cargo_identity = native._supervised_text(
        supervisor, [cargo, "--version"], cwd=source_root, label="pinned-cargo-identity", timeout=60
    ).strip()
    rustdoc_identity = native._supervised_text(
        supervisor, [rustdoc, "--version"], cwd=source_root, label="pinned-rustdoc-identity", timeout=60
    ).strip()
    if not cargo_identity.startswith("cargo 1.98.1") or not rustdoc_identity.startswith("rustdoc 1.98.1"):
        raise RuntimeError("cargo or rustdoc does not match the pinned Rust 1.98.1 toolchain")
    command = [
        cargo,
        "test",
        "--locked",
        "--offline",
        "--manifest-path",
        source_root / "tooling/Cargo.toml",
        "--package",
        "ami-rust-core",
        "--test",
        "historical_parser_differential",
        "--",
        "--ignored",
        "--exact",
        "historical_python_differential_corpus",
    ]
    native._supervised_run(
        supervisor,
        command,
        cwd=source_root / "tooling",
        label="historical-parser-current-rust-131-cases",
        timeout=1200,
    )
    rust_stdout = (work / "logs/historical-parser-current-rust-131-cases.stdout.log").read_text(
        encoding="utf-8", errors="replace"
    )
    if "test historical_python_differential_corpus ... ok" not in rust_stdout:
        raise RuntimeError("Cargo returned success without executing the explicit ignored test")
    if not re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", rust_stdout):
        raise RuntimeError("Cargo did not report exactly one executed historical differential test")
    if not rust_result.is_file():
        raise RuntimeError("the executed Rust test did not write its paired result")
    return {
        "rustc": rustc_identity.strip(),
        "cargo": cargo_identity,
        "rustdoc": rustdoc_identity,
        "test_stdout_sha256": sha256(rust_stdout.encode()),
        "supervision": native._supervision_summary(supervisor),
    }


def host_target() -> str:
    return {
        "macos-aarch64": "aarch64-apple-darwin",
        "linux-x86_64": "x86_64-unknown-linux-gnu",
    }[host_profile()]


def compare_rows(python_rows: dict, rust_result: dict, fixture_counts: dict) -> tuple[list[dict], dict, int]:
    if rust_result.get("schema") != "ami-rust-current-core-historical-parser-differential-v1":
        raise RuntimeError("Rust test result has an unknown schema")
    if rust_result.get("status") != "PASS_CURRENT_RUST_ORACLE_SIDE":
        raise RuntimeError("Rust test did not report successful corpus execution")
    if rust_result.get("counts", {}).get("total") != TOTAL_CASES:
        raise RuntimeError("Rust test result is missing cases")
    rust_rows = {}
    for row in rust_result.get("cases", []):
        key = f"{row['corpus']}:{row['name']}"
        if key in rust_rows:
            raise RuntimeError(f"duplicate Rust case result: {key}")
        rust_rows[key] = row
    if len(rust_rows) != TOTAL_CASES or set(rust_rows) != set(python_rows):
        raise RuntimeError("Python and Rust case inventories differ")
    output = []
    counts = {
        corpus: {
            "cases": fixture_counts[corpus],
            "historical_python_accept": 0,
            "historical_python_refuse": 0,
            "current_rust_accept": 0,
            "current_rust_refuse": 0,
        }
        for corpus in EXPECTED_COUNTS
    }
    manifest_differences = 0
    for key in sorted(python_rows):
        historical = python_rows[key]
        native = rust_rows[key]
        if historical["input_sha256"] != native["input_sha256"]:
            raise RuntimeError(f"input identity differs between implementations: {key}")
        corpus = historical["corpus"]
        python_decision = historical["decision"]
        rust_decision = native["current_rust_decision"]
        counts[corpus][f"historical_python_{python_decision}"] += 1
        counts[corpus][f"current_rust_{rust_decision}"] += 1
        intentional = native.get("intentional_difference")
        if corpus == "manifest":
            declared_python = native["historical_decision"]
            declared_native = native["declared_native_decision"]
            if python_decision != declared_python or rust_decision != declared_native:
                raise RuntimeError(f"manifest result differs from frozen declaration: {key}")
            if python_decision != rust_decision:
                manifest_differences += 1
                if not isinstance(intentional, str) or not intentional:
                    raise RuntimeError(f"manifest difference is not declared: {key}")
                outcome = "declared-manifest-difference"
            else:
                if intentional is not None:
                    raise RuntimeError(f"manifest has an unused difference note: {key}")
                outcome = "match"
        else:
            if python_decision != historical["decision"]:
                raise RuntimeError(f"historical Python decision mismatch for {key}")
            if python_decision != rust_decision:
                raise RuntimeError(f"unexpected Python/Rust decision mismatch for {key}")
            outcome = "match"
            if corpus in ("receipt", "receipt-integer") and python_decision == "accept":
                py_sem = historical.get("common_receipt_semantics")
                rust_sem = native.get("common_receipt_semantics")
                if py_sem != rust_sem:
                    raise RuntimeError(f"common accepted receipt semantics differ for {key}")
        output.append({
            "id": key,
            "corpus": corpus,
            "name": historical["name"],
            "input_sha256": historical["input_sha256"],
            "historical_python_decision": python_decision,
            "current_rust_decision": rust_decision,
            "outcome": outcome,
            "intentional_difference": intentional,
            "common_receipt_semantics_match": (
                historical.get("common_receipt_semantics") == native.get("common_receipt_semantics")
                if corpus in ("receipt", "receipt-integer") and python_decision == "accept"
                else None
            ),
        })
    if manifest_differences != 2:
        raise RuntimeError(f"expected exactly two declared manifest differences, found {manifest_differences}")
    for corpus, count in counts.items():
        if count["cases"] != EXPECTED_COUNTS[corpus]:
            raise RuntimeError(f"wrong case count for {corpus}")
        if not count["current_rust_accept"] or not count["current_rust_refuse"]:
            raise RuntimeError(f"{corpus} lacks a native positive or refusal control")
        if not count["historical_python_accept"] or not count["historical_python_refuse"]:
            raise RuntimeError(f"{corpus} lacks a historical positive or refusal control")
    return output, counts, manifest_differences


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output-dir", required=True, type=Path, help="fresh private result/work directory")
    parser.add_argument("--rust-bin-dir", required=True, type=Path, help="absolute pinned Rust 1.98.1 toolchain/bin")
    parser.add_argument("--cargo-home", required=True, type=Path, help="existing offline Cargo cache")
    parser.add_argument(
        "--test-source",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "tooling/crates/core/tests/historical_parser_differential.rs",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        raise PinRefusal("--source-commit must be a full lowercase Git object id")
    source_root = canonical_directory(args.source_root, "source root")
    python_value = os.environ.get("AMI_RUST_HISTORICAL_PYTHON")
    if not python_value:
        raise PinRefusal("AMI_RUST_HISTORICAL_PYTHON is required; no interpreter fallback is allowed")
    python = canonical_executable(python_value, "AMI_RUST_HISTORICAL_PYTHON")
    if Path(sys.executable).resolve(strict=True) != python:
        raise PinRefusal("the helper itself must run under AMI_RUST_HISTORICAL_PYTHON")
    source_pins = verify_pinned_inputs(source_root, python)
    checkout_identity = verify_source_commit(source_root, args.source_commit)
    if platform.python_version() != source_pins["python_runtime"]["version"]:
        raise PinRefusal("running Python version differs from the current host runtime pin")
    if getattr(sys, "get_int_max_str_digits", lambda: None)() != 4300:
        raise PinRefusal("Python integer parsing limit differs from the frozen historical oracle")
    rust_identity = validate_rust_toolchain(args.rust_bin_dir)
    test_source = args.test_source.resolve(strict=True)
    if not test_source.is_file():
        raise PinRefusal("portable Rust integration test source is missing")
    source_test = source_root / "tooling/crates/core/tests/historical_parser_differential.rs"
    if not source_test.is_file() or source_test.read_bytes() != test_source.read_bytes():
        raise PinRefusal("selected source root does not contain this exact portable integration test")
    if args.output_dir.exists() or args.output_dir.is_symlink():
        raise PinRefusal("output directory must be fresh; previous evidence is preserved")
    args.output_dir.mkdir(parents=True, mode=0o700)
    work = args.output_dir / "work"
    supervised_output = args.output_dir / "supervised-output"
    work.mkdir(mode=0o700)
    supervised_output.mkdir(mode=0o700)

    controls = run_prechild_controls(source_root, python, work)
    if controls["negative_control_child_count"] != 0:
        raise RuntimeError("pin refusal controls launched a child")

    fixture_source = source_root / "tooling/crates/core/tests/fixtures"
    fixture_copy = work / "fixtures"
    fixture_copy.mkdir(mode=0o700)
    fixture_tree = {}
    for relative in [
        "release-manifests",
        "receipts",
        "publisher-claims",
    ]:
        fixture_tree[relative] = copy_fixture_tree(fixture_source / relative, fixture_copy / relative)
    fixture_counts, oracle_identities = assert_case_inputs(fixture_copy)
    if fixture_counts != EXPECTED_COUNTS:
        raise RuntimeError("fixture counts differ from the required complete corpus")

    python_rows, python_counts = historical_python_rows(fixture_copy, work, source_pins)
    if len(python_rows) != TOTAL_CASES:
        raise RuntimeError("historical Python did not execute all 131 cases")
    rust_result_path = work / "current-rust-result.json"
    invocation_identity = {
        "schema": "ami-rust-portable-historical-parser-replay-v1",
        "status": "RUNNING",
        "source_commit": args.source_commit,
        "checkout_identity": checkout_identity,
        "source_root": str(source_root),
        "coordinator": file_identity(Path(__file__).resolve(strict=True)),
        "source_pins": source_pins,
        "rust_source": rust_source_identities(source_root),
        "rust_toolchain": rust_identity,
        "fixtures": {
            "counts": fixture_counts,
            "oracles": oracle_identities,
            "copied_trees": {
                key: {"files": value["files"], "bytes": value["bytes"]}
                for key, value in fixture_tree.items()
            },
        },
        "pre_child_pin_refusal_controls": controls,
        "historical_python_actual_counts": python_counts,
    }
    (args.output_dir / "result.json").write_text(json.dumps(invocation_identity, indent=2) + "\n")

    try:
        def rust_child():
            # Recheck immutable source and interpreter pins immediately before Cargo.
            verify_pinned_inputs(source_root, python)
            return run_supervised_replay(
                source_root,
                work,
                supervised_output,
                fixture_copy,
                python,
                rust_identity_path(args.rust_bin_dir),
                canonical_directory(args.cargo_home, "existing Cargo cache home"),
                rust_result_path,
                test_source,
            )

        rust_run = guarded_child(source_root, python, rust_child)
        if rust_result_path.stat().st_size > MAX_RESULT_BYTES:
            raise RuntimeError("current Rust result exceeds its byte bound")
        rust_result = json.loads(rust_result_path.read_bytes())
        paired_cases, paired_counts, manifest_differences = compare_rows(
            python_rows, rust_result, fixture_counts
        )
        # Bind all sources again after the Rust child has exited.
        final_source_pins = verify_pinned_inputs(source_root, python)
        if verify_source_commit(source_root, args.source_commit) != checkout_identity:
            raise RuntimeError("source checkout identity changed during replay")
        if source_pins != final_source_pins:
            raise RuntimeError("source or interpreter pins changed during replay")
        if invocation_identity["rust_source"] != rust_source_identities(source_root):
            raise RuntimeError("current Rust sources or lock changed during replay")
        if invocation_identity["coordinator"] != file_identity(Path(__file__).resolve(strict=True)):
            raise RuntimeError("portable replay coordinator changed during execution")
        result = {
            **invocation_identity,
            "status": "PASS_LOCAL_HISTORICAL_PYTHON_CURRENT_RUST_FUNCTION_REPLAY",
            "host": host_profile(),
            "python_runtime": {
                **source_pins["python_runtime"],
                "reported_version": platform.python_version(),
                "int_max_str_digits": sys.get_int_max_str_digits(),
            },
            "rust_run": rust_run,
            "current_rust_result_sha256": sha256(rust_result_path.read_bytes()),
            "paired_counts": paired_counts,
            "case_count": len(paired_cases),
            "unique_case_count": len({row["id"] for row in paired_cases}),
            "intentional_manifest_differences": manifest_differences,
            "cases": paired_cases,
            "claim": (
                "Explicit local function-level historical Python/current Rust parser comparison. "
                "Not consumer CLI lifecycle evidence, not both-host CI, and not RC1-A2 or RC1 acceptance."
            ),
        }
        encoded = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
        if len(encoded) > MAX_RESULT_BYTES:
            raise RuntimeError("durable paired result exceeds its 8 MiB bound")
        (args.output_dir / "result.json").write_bytes(encoded)
    except BaseException as exception:
        failure = {
            **invocation_identity,
            "status": "FAILED",
            "failure_type": type(exception).__name__,
            "failure": str(exception)[:800],
            "rust_result_path": str(rust_result_path),
        }
        (args.output_dir / "failure.json").write_text(json.dumps(failure, indent=2) + "\n")
        raise

    print(json.dumps({
        "status": result["status"],
        "case_count": result["case_count"],
        "paired_counts": result["paired_counts"],
        "intentional_manifest_differences": manifest_differences,
        "result": str(args.output_dir / "result.json"),
    }))


def rust_identity_path(value: Path) -> Path:
    return canonical_directory(value, "pinned Rust 1.98.1 bin directory")


if __name__ == "__main__":
    main()
