#!/usr/bin/env python3
"""Run bounded compile-only acceptance probes against an installed SDK."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile

SCRIPT = Path(__file__).resolve()
sys.path.insert(0, str(SCRIPT.parent))
import ci_sdk


SCHEMA = "ami-rust-compile-contract-probes-v1"
COMPONENTS = ("rust", "cargo", "toolchain", "collector", "csdk", "vendor")
FIXTURES = (
    ("positive-safe", ()),
    ("target-std", ("E0463", "std")),
    ("use-after-close", ("borrow of moved value", "file")),
    ("context-exit", ("lifetime may not live long enough",)),
    ("clone-file", ("Clone", "not satisfied")),
    ("send-file", ("E0277", "require_send", "Send")),
    ("sync-file", ("E0277", "require_sync", "Sync")),
    ("borrowed-callback-escape", ("lifetime may not live long enough",)),
)
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
MAX_JSON_BYTES = 32 * 1024**2


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _file_identity(path: Path) -> dict:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("expected a regular non-symlink file: " + str(path))
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    return {"path": str(path.resolve(strict=True)), "bytes": info.st_size, "sha256": digest}


def _read_json(path: Path, label: str) -> tuple[dict, bytes]:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_JSON_BYTES:
            raise ValueError("missing, linked or oversized " + label)
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError(label + " is oversized")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=ci_sdk.unique_json,
                       parse_constant=lambda token: (_ for _ in ()).throw(ValueError("invalid JSON constant")))
    if not isinstance(value, dict):
        raise ValueError(label + " must contain a JSON object")
    return value, raw


def _safe_child(root: Path, relative: str, label: str) -> Path:
    parts = relative.split("/") if isinstance(relative, str) else []
    if not parts or Path(relative).is_absolute() or "\\" in relative or any(
            part in ("", ".", "..") for part in parts):
        raise ValueError("unsafe " + label + " path")
    path = root
    for part in parts:
        path /= part
        if path.is_symlink():
            raise ValueError("symlink in " + label + " path: " + relative)
    return path


def _manifest_files(manifest: dict) -> dict:
    rows = manifest.get("files")
    if not isinstance(rows, list) or any(not isinstance(row, dict)
                                         or not isinstance(row.get("path"), str) for row in rows):
        raise ValueError("SDK manifest has no file inventory")
    result = {row["path"]: row for row in rows}
    if len(result) != len(rows):
        raise ValueError("duplicate SDK file inventory path")
    return result


def _verify_file_pin(path: Path, relative: str, inventory: dict) -> dict:
    pin = inventory.get(relative)
    identity = _file_identity(path)
    if not isinstance(pin, dict) or any(pin.get(key) != identity[key] for key in ("bytes", "sha256")):
        raise ValueError("installed SDK file differs from its manifest: " + relative)
    return identity


def _read_logs(supervisor, process: dict) -> tuple[bytes, bytes]:
    root = Path(supervisor.work).resolve(strict=True)
    names = [process.get(field) for field in ("stdout_log", "stderr_log")]
    paths = [Path(name) for name in names if isinstance(name, str)]
    if len(paths) != 2 or any(path.is_absolute() or ".." in path.parts or not path.parts for path in paths):
        raise RuntimeError("Supervisor returned an unsafe log path")
    paths = [root / path for path in paths]
    if any(path.is_symlink() or not path.resolve(strict=True).is_relative_to(root) for path in paths):
        raise RuntimeError("Supervisor log escaped its managed work root")
    return paths[0].read_bytes(), paths[1].read_bytes()


def _run(supervisor, command: list[str], *, cwd: Path, label: str,
         allow_nonzero: bool = False, timeout: int = 1200) -> dict:
    before = len(supervisor.commands)
    process = None
    try:
        process = supervisor.run(command, cwd=cwd, label=label, timeout=timeout)
    except RuntimeError:
        # Supervisor.run records the process row before raising for a nonzero
        # exit. Only compile fixtures may use that recorded status as evidence.
        rows = getattr(supervisor, "commands", ())
        if not allow_nonzero or len(rows) != before + 1:
            raise
        process = rows[-1]
        if process.get("label") != label:
            raise RuntimeError("Supervisor failed without recording the expected process row")
    if not isinstance(process, dict) or process.get("label") != label:
        raise RuntimeError("Supervisor returned no matching process row for " + label)
    stdout, stderr = _read_logs(supervisor, process)
    code, stop = process.get("exit_code"), process.get("stop_reason")
    if stop is not None:
        raise RuntimeError(label + " was stopped by the Supervisor: " + str(stop))
    if type(code) is not int:
        raise RuntimeError(label + " has no integer exit status")
    if not allow_nonzero and code != 0:
        raise RuntimeError(label + " failed with exit " + str(code))
    return {"command": [str(value) for value in command], "process": dict(process),
            "stdout": stdout.decode("utf-8", "replace"),
            "stderr": stderr.decode("utf-8", "replace"),
            "stdout_sha256": _sha(stdout), "stderr_sha256": _sha(stderr),
            "stdout_bytes": len(stdout), "stderr_bytes": len(stderr)}


def _json_result(row: dict, label: str) -> dict:
    try:
        result = json.loads(row["stdout"])
    except (json.JSONDecodeError, TypeError) as error:
        raise ValueError(label + " did not return one JSON object") from error
    if not isinstance(result, dict):
        raise ValueError(label + " returned a non-object JSON result")
    return result


def _private_consumer(path: Path) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise ValueError("consumer must be a real installed-consumer directory")
    info = path.lstat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("consumer must be a private directory owned by the current user")
    return path.resolve(strict=True)


def _real_directory(path: Path, label: str) -> Path:
    try:
        info = path.lstat()
    except OSError as error:
        raise ValueError(label + " is missing") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ValueError(label + " must be a real directory: " + str(path))
    return path.resolve(strict=True)


def _reject_ambient_cargo_config(path: Path) -> None:
    for directory in (path, *path.parents):
        for name in ("config", "config.toml"):
            candidate = directory / ".cargo" / name
            if candidate.exists() or candidate.is_symlink():
                raise ValueError("ambient Cargo configuration would affect the fixture check: "
                                 + str(candidate))


def _snapshot(*, host: str, bundle: Path, prefix: Path, sdk_root: Path, sdk: dict,
              selection_path: Path, receipt_pin: Path, target_spec: Path,
              python: Path, components: dict, cargo: Path, rustc: Path) -> dict:
    manifest_path = _safe_child(sdk_root, "contract/sdk.json", "installed SDK manifest")
    installed_manifest, installed_raw = _read_json(manifest_path, "installed SDK manifest")
    if _sha(installed_raw) != sdk["manifest_sha256"] or installed_manifest != sdk["manifest"]:
        raise ValueError("installed candidate SDK manifest differs from prepared SDK identity")
    inventory = _manifest_files(installed_manifest)
    sdk_files = {
        "manifest": _file_identity(manifest_path),
        "host_cli": _verify_file_pin(
            _safe_child(sdk_root, "host/cli.py", "installed SDK CLI"),
            "host/cli.py", inventory),
        "host_contracts": _verify_file_pin(
            _safe_child(sdk_root, "host/contracts.py", "installed SDK contracts"),
            "host/contracts.py", inventory),
        "target": _verify_file_pin(target_spec, "targets/x86_64-aros.json", inventory),
        "fixture_manifest": _verify_file_pin(
            _safe_child(sdk_root, "tests/compile-fail/Cargo.toml", "fixture manifest"),
            "tests/compile-fail/Cargo.toml", inventory),
        "fixture_lock": _verify_file_pin(
            _safe_child(sdk_root, "tests/compile-fail/Cargo.lock", "fixture lock"),
            "tests/compile-fail/Cargo.lock", inventory),
    }
    sdk_files["fixtures"] = {
        name: _verify_file_pin(
            _safe_child(sdk_root, "tests/compile-fail/fixtures/" + name.replace("-", "_") + ".rs",
                        "fixture source"),
            "tests/compile-fail/fixtures/" + name.replace("-", "_") + ".rs", inventory)
        for name, _ in FIXTURES
    }

    component_rows = {}
    profile = installed_manifest.get("profiles", {}).get(host)
    if not isinstance(profile, dict) or not isinstance(profile.get("components"), dict):
        raise ValueError("installed SDK has no component manifest references")
    for name in COMPONENTS:
        root, info = components[name], sdk["component_info"][name]
        reference = profile["components"].get(name, {})
        if (reference.get("manifest"), reference.get("sha256")) != (
                info.get("manifest_path"), info.get("manifest_sha256")):
            raise ValueError("prepared component identity differs from the installed SDK profile: " + name)
        manifest_path = _safe_child(sdk_root, reference["manifest"], name + " inventory manifest")
        manifest_value, manifest_raw = _read_json(manifest_path, name + " component manifest")
        if (_sha(manifest_raw) != reference["sha256"] or manifest_value != info["manifest"]):
            raise ValueError("installed component manifest differs from the prepared identity: " + name)
        actual = ci_sdk.verify_component(root, info["manifest"], name)
        component_rows[name] = {"root": str(root.resolve(strict=True)),
                                "manifest_path": info["manifest_path"],
                                "manifest_sha256": info["manifest_sha256"],
                                "manifest": info["manifest"],
                                "manifest_file": _verify_file_pin(manifest_path, reference["manifest"], inventory),
                                "inventory": actual}
    selection, selection_raw = _read_json(selection_path, "consumer selection")
    expected_selection = {name: str(components[name].resolve(strict=True)) for name in COMPONENTS}
    if selection.get("components") != expected_selection:
        raise ValueError("consumer selection differs from the actual selected component roots")
    if Path(selection.get("python", "")).resolve(strict=True) != python.resolve(strict=True):
        raise ValueError("consumer selection does not bind the selected Python")

    receipt_path = prefix / "install-receipt.json"
    receipt, receipt_raw = _read_json(receipt_path, "installed SDK receipt")
    pin_raw = receipt_pin.read_bytes()
    pin_value = pin_raw.decode("ascii").strip()
    if (not DIGEST.fullmatch(pin_value) or _sha(receipt_raw) != pin_value
            or receipt.get("sdk_manifest_sha256") != sdk["manifest_sha256"]):
        raise ValueError("installed SDK receipt differs from its external receipt pin")
    release_identity = _file_identity(bundle / "release.json")
    archive_identity = _file_identity(bundle / "sdk.tar.xz")
    payload_release = _file_identity(_safe_child(prefix, "payload/release.json", "installed release manifest"))
    payload_archive = _file_identity(_safe_child(prefix, "payload/sdk.tar.xz", "installed SDK archive"))
    if (receipt.get("release_manifest_sha256") != release_identity["sha256"]
            or payload_release["sha256"] != release_identity["sha256"]
            or payload_archive["sha256"] != archive_identity["sha256"]):
        raise ValueError("installed candidate receipt or payload differs from the authenticated bundle")
    authentication = receipt.get("authentication")
    auth_digest = _sha(json.dumps(authentication, sort_keys=True, separators=(",", ":")).encode()) \
        if authentication is not None else None

    return {
        "bundle": {"release_json": release_identity, "sdk_archive": archive_identity},
        "receipt": {"path": str(receipt_path), "sha256": _sha(receipt_raw),
                    "pin_path": str(receipt_pin), "pin_file_sha256": _sha(pin_raw),
                    "pin_value": pin_value, "release_manifest_sha256": receipt["release_manifest_sha256"],
                    "sdk_manifest_sha256": receipt["sdk_manifest_sha256"],
                    "authentication_sha256": auth_digest},
        "selection": {"path": str(selection_path), "sha256": _sha(selection_raw),
                      "python": str(python.resolve(strict=True)),
                      "components": expected_selection},
        "sdk_files": sdk_files,
        "components": component_rows,
        "tools": {"python": _file_identity(python), "rustc": _file_identity(rustc),
                  "cargo": _file_identity(cargo)},
        "profile": {**profile, "rust_commit": sdk["manifest"].get("rust_commit"),
                    "rust_llvm": sdk["manifest"].get("rust_llvm"),
                    "source_date_epoch": sdk["manifest"].get("source_date_epoch")},
    }


def _safe_remove_compile_cache(scratch: Path, consumer: Path, marker: bytes) -> dict:
    resolved_consumer = consumer.resolve(strict=True)
    root_info = scratch.lstat()
    if (stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode)
            or root_info.st_uid != os.getuid() or stat.S_IMODE(root_info.st_mode) & 0o077
            or scratch.resolve(strict=True).parent != resolved_consumer):
        raise RuntimeError("owned compile scratch root failed its cleanup safety check")
    marker_path = scratch / ".compile-probe-owner"
    if marker_path.is_symlink() or marker_path.read_bytes() != marker:
        raise RuntimeError("compile scratch ownership marker changed")
    workdir = scratch / "work"
    work_info = workdir.lstat()
    if stat.S_ISLNK(work_info.st_mode) or not stat.S_ISDIR(work_info.st_mode):
        raise RuntimeError("compile work root is not a real owned directory")
    cache = workdir / "target"
    info = cache.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError("compile cache is not a real owned directory")
    resolved_cache = cache.resolve(strict=True)
    if not resolved_cache.is_relative_to(scratch.resolve(strict=True)):
        raise RuntimeError("compile cache escaped the owned scratch root")
    size = sum(item.stat().st_size for item in cache.rglob("*")
               if item.is_file() and not item.is_symlink())
    shutil.rmtree(cache)
    return {"path": str(cache), "removed": not cache.exists(), "bytes_removed": size}


def qualify_compile_contract(*, supervisor, python, bundle, consumer, host, sdk, components) -> dict:
    """Qualify the eight installed-SDK compile fixtures under the shared supervisor."""
    if not isinstance(host, str) or host != ci_sdk.host_identity()[0]:
        raise ValueError("compile contract host does not match the executing supported host")
    if not isinstance(sdk, dict) or not isinstance(sdk.get("manifest"), dict):
        raise ValueError("prepared SDK identity is malformed")
    manifest_sha = sdk.get("manifest_sha256")
    if not isinstance(manifest_sha, str) or not DIGEST.fullmatch(manifest_sha):
        raise ValueError("prepared SDK manifest digest is malformed")
    if not isinstance(components, dict) or set(components) != set(COMPONENTS):
        raise ValueError("compile contract requires the exact six selected component roots")
    components = {name: Path(components[name]) for name in COMPONENTS}
    for name, root in components.items():
        if not root.is_absolute() or root.is_symlink() or not root.is_dir():
            raise ValueError("selected component root must be an absolute real directory: " + name)
    python, bundle = Path(python), Path(bundle)
    if not python.is_absolute() or not bundle.is_absolute():
        raise ValueError("selected Python and candidate bundle paths must be absolute")
    _real_directory(bundle, "candidate bundle")
    consumer = _private_consumer(Path(consumer))
    prefix = consumer / "sdk-0.1.0"
    sdk_root = prefix / "sdk"
    _real_directory(prefix, "installed SDK prefix")
    _real_directory(sdk_root, "installed SDK root")
    fixture_project = sdk_root / "tests/compile-fail"
    selection_path = consumer / "selection.json"
    receipt_pin = consumer / "receipt.sha256"
    lock_path = consumer / "compile-fixtures.lock.json"
    if lock_path.exists() or lock_path.is_symlink():
        raise ValueError("compile fixture project lock must be fresh")
    for path in (bundle / "install_publisher.py", bundle / "release.json", bundle / "sdk.tar.xz",
                 sdk_root / "host/cli.py", receipt_pin, selection_path):
        _file_identity(path)
    profile = sdk["manifest"].get("profiles", {}).get(host)
    if (not isinstance(profile, dict) or profile.get("rust_host") != ci_sdk.HOST_TARGETS[host]
            or profile.get("cargo_binary") != "bin/cargo"):
        raise ValueError("installed SDK has no admitted host/compiler profile")
    cargo = _safe_child(components["cargo"], profile["cargo_binary"], "selected Cargo")
    rustc = _safe_child(components["rust"], "bin/rustc", "selected rustc")
    rustdoc = _safe_child(components["rust"], "bin/rustdoc", "selected rustdoc")
    target_spec = _safe_child(sdk_root, "targets/x86_64-aros.json", "custom target")
    for executable in (python, cargo, rustc, rustdoc):
        info = executable.lstat()
        if not stat.S_ISREG(info.st_mode) or not os.access(executable, os.X_OK):
            raise ValueError("selected executable is missing, linked or non-executable: " + str(executable))
    rust_commit = sdk["manifest"].get("rust_commit")
    rust_llvm = sdk["manifest"].get("rust_llvm")
    source_epoch = sdk["manifest"].get("source_date_epoch")
    if (not isinstance(rust_commit, str) or not isinstance(rust_llvm, str)
            or type(source_epoch) is not int):
        raise ValueError("installed SDK compiler and reproducible-build identities are incomplete")

    # Capture and restore the caller's exact environment object even when a probe fails.
    original_env = supervisor.env
    try:
        before = _snapshot(host=host, bundle=bundle, prefix=prefix, sdk_root=sdk_root, sdk=sdk,
                           selection_path=selection_path, receipt_pin=receipt_pin,
                           target_spec=target_spec, python=python, components=components,
                           cargo=cargo, rustc=rustc)
        selection, _ = _read_json(selection_path, "consumer selection")
        if selection.get("python") != str(python.resolve(strict=True)):
            raise ValueError("consumer selection does not resolve to the supplied pinned Python")
        scratch = Path(tempfile.mkdtemp(prefix=".compile-contract-probes-", dir=consumer))
        os.chmod(scratch, 0o700)
        marker = ("ami-rust-compile-probes-v1\n" + str(scratch.resolve(strict=True)) + "\n").encode()
        (scratch / ".compile-probe-owner").write_bytes(marker)
        (scratch / ".compile-probe-owner").chmod(0o600)
        for name in ("home", "cargo-home", "tmp", "work", "logs"):
            path = scratch / name
            path.mkdir(mode=0o700)
        workdir = scratch / "work"
        target_dir = workdir / "target"
        cargo_home = scratch / "cargo-home"
        vendor = components["vendor"].resolve(strict=True)
        rust_root = components["rust"].resolve(strict=True)
        toolchain_root = components["toolchain"].resolve(strict=True)
        for name in ("home", "cargo-home", "tmp", "work"):
            _reject_ambient_cargo_config(scratch / name)

        remaps = [
            (sdk_root.resolve(strict=True), "/ami-rust"),
            (scratch.resolve(strict=True), "/build"),
            (vendor, "/vendor"),
            (rust_root, "/rust-toolchain"),
            (fixture_project.resolve(strict=True), "/project"),
        ]
        rustflags = ["-Copt-level=2", "-Cpanic=abort", "-Ccodegen-units=1",
                     "-Cembed-bitcode=no", "-Clto=off"] + [
                         "--remap-path-prefix=" + str(source) + "=" + destination
                         for source, destination in remaps]
        config = ("target-applies-to-host=false\n[source.crates-io]\nreplace-with=\"vendored\"\n"
                  "[source.vendored]\ndirectory=" + json.dumps(str(vendor)) +
                  "\n[build]\njobs=2\n[host." + profile["rust_host"] + "]\nrustflags=" +
                  json.dumps(["--remap-path-prefix=" + str(source) + "=" + destination
                              for source, destination in remaps]) + "\n")
        config_path = cargo_home / "config.toml"
        config_path.write_text(config, encoding="utf-8")
        config_path.chmod(0o600)
        env = {
            "HOME": str(scratch / "home"),
            "PATH": str(cargo.parent) + ":" + str(rustc.parent) + ":" +
                    str(toolchain_root / "bin") + ":/usr/bin:/bin",
            "CARGO": str(cargo), "CARGO_HOME": str(cargo_home),
            "CARGO_TARGET_DIR": str(target_dir), "RUSTC": str(rustc),
            "RUSTDOC": str(rustdoc), "TMPDIR": str(scratch / "tmp"),
            "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
            "CARGO_NET_OFFLINE": "true", "CARGO_ENCODED_RUSTFLAGS": "\x1f".join(rustflags),
            "LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": str(source_epoch),
            "RUSTC_WRAPPER": "", "RUSTC_WORKSPACE_WRAPPER": "",
        }
        supervisor.env = env

        lock_command = [str(python), "-I", "-B", str(bundle / "install_publisher.py"), "lock",
                        "--prefix", str(prefix), "--selection", str(selection_path),
                        "--project", str(fixture_project), "--output", str(lock_path)]
        lock_run = _run(supervisor, lock_command, cwd=consumer,
                        label="contract-probe-fixture-lock", timeout=120)
        lock_result = _json_result(lock_run, "fixture lock command")
        if (lock_result.get("status") != "locked" or lock_result.get("host") != host
                or lock_result.get("sdk_manifest_sha256") != manifest_sha
                or lock_result.get("receipt_sha256") != before["receipt"]["pin_value"]):
            raise ValueError("fixture project lock did not bind this installed candidate and selection")
        lock_identity = _file_identity(lock_path)
        project_lock, _ = _read_json(lock_path, "compile fixture project lock")
        if (project_lock.get("sdk", {}).get("manifest_sha256") != manifest_sha
                or project_lock.get("sdk", {}).get("root") != str(sdk_root.resolve(strict=True))
                or project_lock.get("host", {}).get("platform") != host
                or project_lock.get("host", {}).get("python") != str(python.resolve(strict=True))
                or project_lock.get("host", {}).get("python_sha256") != before["tools"]["python"]["sha256"]
                or project_lock.get("components") != before["selection"]["components"]
                or project_lock.get("cargo") != {
                    "manifest_sha256": before["sdk_files"]["fixture_manifest"]["sha256"],
                    "lock_sha256": before["sdk_files"]["fixture_lock"]["sha256"]}):
            raise ValueError("generated fixture lock differs from installed SDK and selected components")

        verify_command = [str(python), "-I", "-B", str(sdk_root / "host/cli.py"),
                          "verify", "--sdk-lock", str(lock_path)]
        verify_before = _run(supervisor, verify_command, cwd=consumer,
                             label="contract-probe-verify-before", timeout=120)
        verify_before_result = _json_result(verify_before, "pre-probe SDK CLI verify")
        if (verify_before_result.get("status") != "verified"
                or verify_before_result.get("host") != host
                or verify_before_result.get("sdk_manifest_sha256") != manifest_sha):
            raise ValueError("installed SDK CLI did not verify the generated fixture lock")

        compiler_run = _run(supervisor, [str(rustc), "-Vv"], cwd=workdir,
                            label="contract-probe-rustc-version", timeout=60)
        cargo_run = _run(supervisor, [str(cargo), "-Vv"], cwd=workdir,
                         label="contract-probe-cargo-version", timeout=60)
        compiler_vv = compiler_run["stdout"]
        if ("commit-hash: " + rust_commit not in compiler_vv
                or "LLVM version: " + rust_llvm not in compiler_vv
                or "host: " + profile["rust_host"] not in compiler_vv):
            raise ValueError("selected rustc -Vv differs from the installed SDK compiler profile")

        fixture_rows = []
        for name, required in FIXTURES:
            command = [str(cargo), "-Zhost-config", "-Ztarget-applies-to-host",
                       "-Zami-rust-reproducible-cross", "-Zbuild-std=core,alloc",
                       "-Zbuild-std-features=compiler-builtins-mem", "-Zjson-target-spec",
                       "check", "--manifest-path", str(fixture_project / "Cargo.toml"),
                       "--package", "m1-compile-fail-fixtures", "--target", str(target_spec),
                       "--release", "--locked", "--offline", "-j", "2",
                       "--message-format=human", "--bin", name]
            run = _run(supervisor, command, cwd=workdir, label="contract-probe-" + name,
                       allow_nonzero=name != "positive-safe", timeout=1200)
            output = run["stdout"] + run["stderr"]
            exit_code = run["process"]["exit_code"]
            if name == "positive-safe":
                accepted = exit_code == 0 and "m1-compile-fail-fixtures" in output \
                    and "error:" not in output.lower()
            else:
                accepted = exit_code != 0 and all(token.lower() in output.lower() for token in required)
            fixture_rows.append({
                "bin": name, "expected_diagnostics": list(required), "accepted": accepted,
                "command": run["command"], "process": run["process"],
                "stdout": run["stdout"], "stderr": run["stderr"],
                "stdout_sha256": run["stdout_sha256"], "stderr_sha256": run["stderr_sha256"],
                "stdout_bytes": run["stdout_bytes"], "stderr_bytes": run["stderr_bytes"],
            })
            if not accepted:
                raise ValueError("compile fixture did not meet its expected result: " + name)

        verify_after = _run(supervisor, verify_command, cwd=consumer,
                            label="contract-probe-verify-after", timeout=120)
        verify_after_result = _json_result(verify_after, "post-probe SDK CLI verify")
        if verify_after_result != verify_before_result:
            raise ValueError("installed SDK CLI verification identity changed during compile probes")
        after = _snapshot(host=host, bundle=bundle, prefix=prefix, sdk_root=sdk_root, sdk=sdk,
                          selection_path=selection_path, receipt_pin=receipt_pin,
                          target_spec=target_spec, python=python, components=components,
                          cargo=cargo, rustc=rustc)
        if after != before:
            raise ValueError("candidate, selection, compiler or fixture identity changed during probes")
        if _file_identity(lock_path) != lock_identity:
            raise ValueError("generated fixture project lock changed during compile probes")
        supervisor.check_limits("completed compile contract probes")
        cleanup = _safe_remove_compile_cache(scratch, consumer, marker)
        supervisor.check_limits("retired compile fixture cache")
        return {
            "schema": SCHEMA, "status": "PASS_COMPILE_CONTRACT_PROBES_ONLY", "host": host,
            "candidate": before, "project_lock": {**lock_identity, "result": lock_result,
                                                    "command": lock_run["command"],
                                                    "process": lock_run["process"],
                                                    "stdout_sha256": lock_run["stdout_sha256"],
                                                    "stderr_sha256": lock_run["stderr_sha256"]},
            "verify_before": {"result": verify_before_result, "command": verify_before["command"],
                              "process": verify_before["process"],
                              "stdout_sha256": verify_before["stdout_sha256"],
                              "stderr_sha256": verify_before["stderr_sha256"]},
            "compiler": {"rustc_vv": compiler_vv, "rustc_vv_sha256": compiler_run["stdout_sha256"],
                         "cargo_vv": cargo_run["stdout"], "cargo_vv_sha256": cargo_run["stdout_sha256"],
                         "rustc_process": compiler_run["process"], "cargo_process": cargo_run["process"],
                         "environment": env, "cargo_config": config,
                         "cargo_config_sha256": _sha(config.encode("utf-8"))},
            "fixtures": fixture_rows,
            "verify_after": {"result": verify_after_result, "command": verify_after["command"],
                             "process": verify_after["process"],
                             "stdout_sha256": verify_after["stdout_sha256"],
                             "stderr_sha256": verify_after["stderr_sha256"]},
            "candidate_after": after,
            "compile_cache_cleanup": cleanup,
            "scratch_root": str(scratch),
        }
    finally:
        supervisor.env = original_env
