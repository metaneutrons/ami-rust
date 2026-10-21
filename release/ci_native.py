#!/usr/bin/env python3
"""Transitional internal coordination for the Rust SDK-v2 producer.

The Rust xtask owns SDK/release composition. This helper reuses immutable
component archives and the existing protected signing workflow. It neither
publishes nor accepts RC1; retiring this internal Python is RC4 work.
"""
from __future__ import annotations

import argparse
import io
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import shutil
import stat
import sys
import tarfile
import tomllib
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "release"))
import ci_auth as auth
import ci_sdk

NATIVE_LIMIT = 64 * 1024**2
# Native qualification evidence is separate from the legacy 32 MiB SDK output.
# Keep 1 MiB of each 64 MiB reservation for cleanup and provider ZIP framing.
MAX_CONSUMER_OUTPUT_BYTES = 63 * 1024**2
HOST_TRIPLES = {"linux-x86_64": "x86_64-unknown-linux-gnu", "macos-aarch64": "aarch64-apple-darwin"}
PUBLISHED_V1_ARCHIVE_NAME = "ami-rust-0.1.0-packaging.2.tar.xz"
PUBLISHED_V1_ARCHIVE_PIN = {
    "url": "https://github.com/metaneutrons/ami-rust/releases/download/v0.1.0%2Bpackaging.2/"
    + PUBLISHED_V1_ARCHIVE_NAME,
    "bytes": 26_044_756,
    "sha256": "6567abfb4e36a2bf82816f51512343f4d1232c97c866e648fdf68ab4cf7f2448",
}
PUBLISHED_V1_ARCHIVE_ROOT = "ami-rust-0.1.0-2"
PUBLISHED_V1_PACKAGE_ROOT = "ami-rust-0.1.0-2/usr/libexec/ami-rust/0.1.0-2"
PUBLISHED_V1_XZ_MEMORY_LIMIT = 256 * 1024**2
PUBLISHED_V1_EXPANDED_LIMIT = 64 * 1024**2
PUBLISHED_V1_TAR_MEMBER_LIMIT = 1_000
PUBLISHED_V1_TAR_FILE_LIMIT = 32 * 1024**2
NATIVE_UPGRADE_SOURCE = "5135254310dba8d7ad2886332fb888b9518c159c"
NATIVE_UPGRADE_RUN = 39422283932
NATIVE_UPGRADE_HOST_PINS = {
    "linux-x86_64": {
        "pins_sha256": "5a4c5a335a778557dfcc44e05be78bd5543c5a042dc7cfcc51d9b10cace6301b",
        "authentication_sha256": "a89b0de38049c03b509d877ee0139c391805388ff2a62f4137f410e26109579f",
    },
    "macos-aarch64": {
        "pins_sha256": "69903abce2fe278b19ca5409debfb9bdd5a4fdc59239abe53a877e4336039a68",
        "authentication_sha256": "79ab31c84641d954ecc244f52c391efb9025631d4b77630a1485cc997f2ea9bb",
    },
}


def native_inputs():
    value = auth.parsed(auth.read(ROOT / "release/native-tooling-inputs.json"))
    lock_raw = auth.read(ROOT / "tooling/Cargo.lock")
    workspace = tomllib.loads(auth.read(ROOT / "tooling/Cargo.toml").decode())
    if workspace["workspace"]["package"]["version"] != value["cli_version"]:
        raise ValueError("native CLI version differs from the source workspace")
    lock = value["cargo_lock"]
    if (lock["path"] != "tooling/Cargo.lock" or len(lock_raw) != lock["bytes"]
            or auth.sha(lock_raw) != lock["sha256"]):
        raise ValueError("native Cargo lock differs from the producer pin")
    packages = tomllib.loads(lock_raw.decode())["package"]
    expected = sorted((p["name"], p["version"], p["checksum"]) for p in packages if "source" in p)
    observed = [(p["name"], p["version"], p["sha256"]) for p in value["registry_crates"]]
    if (observed != expected or len(expected) != 29
            or any(p["source"] != "registry+https://github.com/rust-lang/crates.io-index"
                   for p in packages if "source" in p)):
        raise ValueError("native archive selection differs from the reviewed Cargo lock")
    # Reuse the consumer-compatible validation before running any build.
    auth.input_manifest_for_sdk(ROOT, value["sdk_version"])
    return value


def current_host():
    host = {("Linux", "x86_64"): "linux-x86_64", ("Darwin", "arm64"): "macos-aarch64"}.get(
        (platform.system(), platform.machine()))
    if host is None:
        raise ValueError("unsupported native producer host")
    return host


def fresh(path):
    path = Path(path).absolute()
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise ValueError("fresh native producer directory required")
    if path == ROOT or ROOT in path.resolve().parents:
        raise ValueError("native producer work must be outside source")
    path.mkdir(mode=0o700)
    return path.resolve(strict=True)


def _python_root_for(work, explicit=None):
    if explicit is not None:
        return Path(explicit).absolute()
    return Path(work).absolute().parent / "ami-rust-python-bootstrap"


def write(path, raw, mode=0o644):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(raw)
    path.chmod(mode)


def _clean_child_env(env):
    """Keep subprocess environments explicit and remove registry credentials."""
    env = dict(env)
    env.pop("CARGO_REGISTRY_TOKEN", None)
    env.pop("CARGO_REGISTRIES_CRATES_IO_TOKEN", None)
    return env


def _overlap(left, right):
    return left == right or left in right.parents or right in left.parents


def _static_directory(path, label):
    path = Path(path).absolute()
    if path.is_symlink() or not path.is_dir():
        raise ValueError("native static input must be a real directory: " + label)
    path = path.resolve(strict=True)
    size, logs = ci_sdk.directory_accounting(path)
    return path, {"label": label, "path": path.name,
                  "regular_file_bytes": size, "log_bytes": logs}


def _add_static_roots(supervisor, roots):
    """Charge immutable external roots once; directory accounting never follows links."""
    rows = getattr(supervisor, "native_static_roots", [])
    paths = {Path(row["resolved_path"]) for row in rows}
    managed = [ROOT.resolve(strict=True), supervisor.work.resolve(strict=True),
               supervisor.output.resolve(strict=False), supervisor.python_root.resolve(strict=True)]
    for label, value in roots:
        path, row = _static_directory(value, label)
        if any(_overlap(path, root) for root in managed):
            raise ValueError("native static input overlaps a managed root: " + label)
        if any(_overlap(path, prior) for prior in paths):
            raise ValueError("native static input roots overlap: " + label)
        paths.add(path)
        row["resolved_path"] = str(path)
        rows.append(row)
        supervisor.checkout_bytes += row["regular_file_bytes"]
        supervisor.native_static_log_bytes = getattr(supervisor, "native_static_log_bytes", 0) + row["log_bytes"]
    supervisor.native_static_roots = rows
    if not hasattr(supervisor, "native_log_ceiling"):
        supervisor.native_log_ceiling = supervisor.limits["log_bytes"]
    supervisor.limits["log_bytes"] = supervisor.native_log_ceiling - supervisor.native_static_log_bytes
    if supervisor.limits["log_bytes"] < 0:
        raise RuntimeError("static native inputs already exceed the aggregate log ceiling")
    if not hasattr(supervisor, "native_peak_logs"):
        supervisor.native_peak_logs = 0
    return rows


def _make_supervisor(work, output, python_root, env, *, static_roots=()):
    work, output = Path(work).absolute(), Path(output).absolute()
    python_root = Path(python_root).absolute()
    if work.is_symlink() or output.is_symlink() or python_root.is_symlink():
        raise ValueError("native supervisor roots must not be symlinks")
    if not work.is_dir() or (output.exists() and not output.is_dir()):
        raise ValueError("native supervisor work and output roots must be directories")
    ci_sdk.verify_python_bootstrap(python_root, current_host())
    roots = [ROOT.resolve(strict=True), work.resolve(strict=True),
             output.resolve(strict=False), python_root.resolve(strict=True)]
    if len(set(roots)) != len(roots) or any(_overlap(a, b) for i, a in enumerate(roots) for b in roots[i + 1:]):
        raise ValueError("native supervisor managed roots must be distinct and nonoverlapping")
    if any(root == ROOT.resolve(strict=True) or ROOT.resolve(strict=True) in root.parents
           for root in roots[1:]):
        raise ValueError("native supervisor roots must remain outside the source checkout")
    supervisor = ci_sdk.Supervisor(work, output, python_root, _clean_child_env(env))
    supervisor.native_static_roots = []
    supervisor.native_static_log_bytes = 0
    supervisor.native_peak_logs = 0
    supervisor.native_log_ceiling = supervisor.limits["log_bytes"]
    _add_static_roots(supervisor, static_roots)
    _check_limits(supervisor, "initial native inputs")
    return supervisor


def _record_new_logs(supervisor, before):
    rows = supervisor.commands[before:]
    static_logs = getattr(supervisor, "native_static_log_bytes", 0)
    for row in rows:
        row["log_peak_observed_bytes"] += static_logs
        supervisor.native_peak_logs = max(supervisor.native_peak_logs,
                                          row["log_peak_observed_bytes"])
    return rows


def _supervised_run(supervisor, command, *, label, cwd=ROOT, timeout=1200, expected=0):
    before = len(supervisor.commands)
    try:
        row = supervisor.run([str(part) for part in command], cwd=Path(cwd), label=label, timeout=timeout)
    except RuntimeError:
        rows = _record_new_logs(supervisor, before)
        if (expected != 0 and len(rows) == 1 and rows[0].get("label") == label
                and rows[0].get("exit_code") == expected and rows[0].get("stop_reason") is None):
            return rows[0]
        raise
    rows = _record_new_logs(supervisor, before)
    if expected != 0:
        raise RuntimeError(f"supervisor returned without rejecting expected-failure command {label}")
    if row.get("exit_code") != expected:
        raise ValueError(f"native command {label} returned {row.get('exit_code')}, expected {expected}")
    return row


def _supervised_text(supervisor, command, *, label, cwd=ROOT, timeout=60):
    row = _supervised_run(supervisor, command, label=label, cwd=cwd, timeout=timeout)
    return (supervisor.work / row["stdout_log"]).read_text(errors="replace")


def _check_limits(supervisor, label):
    supervisor.check_limits(label)
    current_logs = supervisor.logs_bytes() + getattr(supervisor, "native_static_log_bytes", 0)
    supervisor.native_peak_logs = max(getattr(supervisor, "native_peak_logs", 0), current_logs)


def _supervision_summary(supervisor, auxiliary_commands=(), auxiliary_insert_at=None):
    commands = list(supervisor.commands)
    if auxiliary_commands:
        index = len(commands) if auxiliary_insert_at is None else auxiliary_insert_at
        commands[index:index] = list(auxiliary_commands)
    limits = {"rss_bytes": ci_sdk.MAX_RSS_BYTES,
              "workspace_bytes": ci_sdk.MAX_WORK_BYTES,
              "log_bytes": ci_sdk.MAX_LOG_BYTES,
              "seconds": ci_sdk.MAX_COMMAND_SECONDS}
    return {
        "schema": "ami-rust-native-supervision-v1",
        "limits": limits,
        "static_input_root_count": len(supervisor.native_static_roots),
        "static_input_roots": [{key: value for key, value in row.items() if key != "resolved_path"}
                                for row in supervisor.native_static_roots],
        "peak_rss_observed_bytes": max([0, supervisor.peak_rss] +
                                        [row.get("rss_peak_observed_bytes", 0) for row in commands]),
        "peak_workspace_observed_bytes": max([0, supervisor.peak_workspace] +
                                             [row.get("managed_peak_observed_bytes", 0) for row in commands]),
        "peak_log_observed_bytes": max([0, supervisor.native_peak_logs] +
                                       [row.get("log_peak_observed_bytes", 0) for row in commands]),
        "commands": commands,
    }


def build_tools(work, host_rust, output, python_root, *, static_roots=()):
    native_inputs()
    host_rust = Path(host_rust).absolute()
    if host_rust.is_symlink() or not host_rust.is_dir():
        raise ValueError("native host Rust root must be a real directory")
    toolchain = host_rust.resolve(strict=True) / "toolchain"
    rust = toolchain / "bin"
    for name in ("rustc", "cargo", "rustdoc"):
        if (rust / name).is_symlink() or not (rust / name).is_file():
            raise ValueError("pinned native host Rust executable is missing: " + name)
    for name in ("home", "cargo-home", "tmp"):
        (work / name).mkdir(mode=0o700)
    env = {"PATH": str(rust) + ":/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(work / "home"),
           "TMPDIR": str(work / "tmp"), "LC_ALL": "C", "CARGO_BUILD_JOBS": "2",
           "CARGO_HOME": str(work / "cargo-home"), "CLI_CARGO": str(rust / "cargo"),
           "RUSTC": str(rust / "rustc"), "RUSTDOC": str(rust / "rustdoc")}
    supervisor = _make_supervisor(work, output, python_root, env,
                                  static_roots=[("host-rust", host_rust), *static_roots])
    compiler = _supervised_text(supervisor, [str(rust / "rustc"), "-Vv"], cwd=ROOT,
                                label="native-rustc-identity", timeout=30)
    if ("commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985" not in compiler
            or "host: " + HOST_TRIPLES[current_host()] not in compiler):
        raise ValueError("native producer host compiler differs from the pinned bootstrap")
    _supervised_run(supervisor, [rust / "cargo", "fetch", "--locked", "--manifest-path", ROOT / "tooling/Cargo.toml"],
                    label="native-cargo-fetch")
    _supervised_run(supervisor, ["/bin/bash", ROOT / "tools/build-native-cli.sh", work / "target"],
                    label="native-build-cli")
    env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join([
        f"--remap-path-prefix={ROOT}=/ami-rust", f"--remap-path-prefix={work / 'cargo-home'}=/cargo"])
    if current_host() == "macos-aarch64":
        env["DYLD_LIBRARY_PATH"] = str(toolchain / "lib")
    supervisor.env = _clean_child_env(env)
    _supervised_run(supervisor, [rust / "cargo", "build", "--release", "--locked", "--offline", "--package",
                                 "ami-rust-xtask", "--manifest-path", ROOT / "tooling/Cargo.toml",
                                 "--target-dir", work / "target"], label="native-build-xtask")
    cli = work / "target/release/ami-rust"
    cli_identity_raw = _supervised_text(supervisor, [str(cli), "--version"], cwd=ROOT,
                                        label="native-cli-identity", timeout=60)
    write(work / "cli-identity.json", cli_identity_raw.encode())
    cli_identity = auth.parsed(auth.read(work / "cli-identity.json"))
    if cli_identity.get("schema") != "ami-rust-version-v1" or cli_identity.get("cli_version") != native_inputs()["cli_version"]:
        raise ValueError("built native CLI reports a different version")
    _check_limits(supervisor, "native build tools")
    return cli, work / "target/release/ami-rust-xtask", env, supervisor


def obtain_legacy(work, pin):
    """Read the hash-pinned immutable capsule; never execute its Python files."""
    with urllib.request.urlopen(pin["url"], timeout=120) as response:
        raw = response.read(pin["bytes"] + 1)
    if len(raw) != pin["bytes"] or auth.sha(raw) != pin["sha256"]:
        raise ValueError("immutable component capsule differs from its pin")
    plain = auth.bounded_xz(raw, NATIVE_LIMIT)
    members = {}
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:") as archive:
        for member in archive:
            path = member.name.rstrip("/") if member.isdir() else member.name
            auth.rel(path)
            if member.isdir():
                continue
            if (not member.isfile() or path in members or member.size > auth.FILE_LIMIT
                    or len(members) >= 512):
                raise ValueError("unsupported immutable capsule member")
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("immutable capsule member unreadable")
            members[path] = stream.read(member.size + 1)
            if len(members[path]) != member.size:
                raise ValueError("immutable capsule member truncated")
    if "release.json" not in members or sum(map(len, members.values())) > NATIVE_LIMIT:
        raise ValueError("immutable capsule has an unsupported layout")
    import public_transport
    public_transport._validate_path_set(list(members))
    root = work / "accepted-legacy"
    root.mkdir(mode=0o700)
    for name, raw in members.items():
        write(root / name, raw)
    return root


def _download_published_v1_archive(work, supervisor):
    """Download only the exact historical package archive into supervised work."""
    work = Path(work).resolve(strict=True)
    if work != Path(supervisor.work).resolve(strict=True):
        raise ValueError("published-v1 archive destination differs from supervised work")
    destination = work / PUBLISHED_V1_ARCHIVE_NAME
    if destination.exists() or destination.is_symlink():
        raise ValueError("published-v1 archive destination must be fresh")
    with urllib.request.urlopen(PUBLISHED_V1_ARCHIVE_PIN["url"], timeout=120) as response:
        raw = response.read(PUBLISHED_V1_ARCHIVE_PIN["bytes"] + 1)
    if (len(raw) != PUBLISHED_V1_ARCHIVE_PIN["bytes"]
            or auth.sha(raw) != PUBLISHED_V1_ARCHIVE_PIN["sha256"]):
        raise ValueError("published-v1 package archive differs from its exact release pin")
    write(destination, raw, 0o600)
    _check_limits(supervisor, "downloaded exact published-v1 package archive")
    return destination


def _extract_published_v1_archive(raw: bytes, destination: Path) -> tuple[Path, int, int, int]:
    """Validate the complete bounded tar before extracting any member."""
    if destination.exists() or destination.is_symlink():
        raise ValueError("published package extraction root must be fresh")
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ,
                                    memlimit=PUBLISHED_V1_XZ_MEMORY_LIMIT)
    plain = decoder.decompress(raw, max_length=PUBLISHED_V1_EXPANDED_LIMIT + 1)
    if (len(plain) > PUBLISHED_V1_EXPANDED_LIMIT or not decoder.eof
            or decoder.unused_data):
        raise ValueError("published package XZ stream exceeds its bounded profile")

    records = []
    names = {}
    total_files = 0
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:") as archive:
        for member in archive:
            if len(records) == PUBLISHED_V1_TAR_MEMBER_LIMIT:
                raise ValueError("published package tar exceeds its member bound")
            is_directory = member.type == tarfile.DIRTYPE
            is_regular = member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
            if not (is_directory or is_regular):
                raise ValueError("published package tar contains a link or special member")
            name = member.name[:-1] if is_directory and member.name.endswith("/") else member.name
            auth.rel(name)
            if name in names:
                raise ValueError("published package tar contains duplicate paths")
            mode = member.mode
            if mode < 0 or mode & ~0o7777 or mode & 0o7022:
                raise ValueError("published package tar contains an unsafe mode")
            if is_directory:
                if member.size != 0:
                    raise ValueError("published package directory has a payload")
            else:
                if not 0 <= member.size <= PUBLISHED_V1_TAR_FILE_LIMIT:
                    raise ValueError("published package file exceeds its member bound")
                total_files += member.size
                if total_files > PUBLISHED_V1_EXPANDED_LIMIT:
                    raise ValueError("published package files exceed their aggregate bound")
            if not (name == PUBLISHED_V1_ARCHIVE_ROOT
                    or name.startswith(PUBLISHED_V1_ARCHIVE_ROOT + "/")):
                raise ValueError("published package archive has an entry outside its exact top-level root")
            data = b""
            if is_regular:
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError("published package regular member has no data")
                data = stream.read(member.size + 1)
                if len(data) != member.size:
                    raise ValueError("published package member length differs from its header")
            names[name] = "directory" if is_directory else "file"
            records.append((name, is_directory, data, mode))

    if names.get(PUBLISHED_V1_ARCHIVE_ROOT) != "directory":
        raise ValueError("published package omits its exact archive top-level directory")
    if names.get(PUBLISHED_V1_PACKAGE_ROOT) != "directory":
        raise ValueError("published package omits the exact 0.1.0-2 package root")
    for required in ("pins.json", "cli.py"):
        if names.get(PUBLISHED_V1_PACKAGE_ROOT + "/" + required) != "file":
            raise ValueError("published package root omits a required regular file: " + required)
    for name in names:
        parts = name.split("/")
        for offset in range(1, len(parts)):
            if names.get("/".join(parts[:offset])) == "file":
                raise ValueError("published package file is an ancestor of another member")

    destination.mkdir(mode=0o700)
    directories = {name for name, is_directory, _, _ in records if is_directory}
    directories.update("/".join(name.split("/")[:offset])
                       for name, _, _, _ in records
                       for offset in range(1, len(name.split("/"))))
    directory_modes = {name: mode for name, is_directory, _, mode in records if is_directory}
    for name in sorted(directories, key=lambda path: (path.count("/"), path)):
        destination.joinpath(*PurePosixPath(name).parts).mkdir(mode=0o700)
    for name, is_directory, data, mode in records:
        if is_directory:
            continue
        target = destination.joinpath(*PurePosixPath(name).parts)
        with target.open("xb") as stream:
            stream.write(data)
        target.chmod(mode)
    for name, mode in sorted(directory_modes.items(), key=lambda row: row[0].count("/"), reverse=True):
        destination.joinpath(*PurePosixPath(name).parts).chmod(mode)
    package_root = destination.joinpath(*PUBLISHED_V1_PACKAGE_ROOT.split("/"))
    return package_root, len(records), total_files, len(plain)


def _prepare_published_legacy(work, output, supervisor, archive_source):
    """Run the actual published 0.1.0-2 setup/build as a separate oracle."""
    work = Path(work).resolve(strict=True)
    output = Path(output).absolute()
    if work != Path(supervisor.work).resolve(strict=True):
        raise ValueError("published-v1 setup work differs from its supervisor")
    if output.resolve(strict=False) != Path(supervisor.output).resolve(strict=False):
        raise ValueError("published-v1 setup output differs from its supervisor")
    area = fresh(work / "published-v1-rollback-setup")
    report_path = output / "published-v1-rollback-setup.json"
    archive_source = Path(archive_source).absolute()
    if archive_source.is_symlink():
        raise ValueError("published package archive source must not be a symlink")
    archive_source = archive_source.resolve(strict=True)
    archive_copy = area / PUBLISHED_V1_ARCHIVE_NAME
    package_tree = area / "package-tree"
    state_parent = area / "state-parent"
    project_parent = area / "project-parent"
    build_parent = area / "build-parent"
    home, tmp = area / "home", area / "tmp"
    for directory in (state_parent, project_parent, build_parent, home, tmp):
        directory.mkdir(mode=0o700)
    state = state_parent / "ami-rust-0.1.0-state"
    project = project_parent / "hello-aros"
    build = build_parent / "hello-aros-build"
    current_state = work / "native-state-write-area/derived/native-ready-state"
    operation_roots = (state, project, build)
    if (any(_overlap(path, current_state) for path in operation_roots)
            or any(_overlap(left, right) for index, left in enumerate(operation_roots)
                   for right in operation_roots[index + 1:])):
        raise ValueError("published-v1 state/project/build overlaps current native state")

    result = {
        "schema": "ami-rust-published-v1-rollback-setup-v1",
        "status": "RUNNING",
        "archive_pin": PUBLISHED_V1_ARCHIVE_PIN,
        "scope": "Historical published 0.1.0-2 setup/build oracle only; not new-consumer no-Python evidence, signed-new-SDK evidence, or RC1 acceptance.",
    }
    command_start = len(supervisor.commands)
    original_env = supervisor.env
    try:
        managed_roots = [ROOT.resolve(strict=True), work,
                         Path(supervisor.output).resolve(strict=False),
                         Path(supervisor.python_root).resolve(strict=True)]
        source_is_managed = any(root == archive_source or root in archive_source.parents
                                for root in managed_roots)
        if not source_is_managed:
            source_root = archive_source.parent.resolve(strict=True)
            if any(_overlap(source_root, root) for root in managed_roots):
                raise ValueError("external published archive parent overlaps a managed root")
            existing_roots = [Path(row["resolved_path"]) for row in supervisor.native_static_roots]
            covering = [root for root in existing_roots
                        if root == source_root or root in source_root.parents]
            overlapping = [root for root in existing_roots if _overlap(root, source_root)]
            if overlapping and not covering:
                raise ValueError("published archive source overlaps a partial static-input root")
            if not covering:
                _add_static_roots(supervisor, [("published-v1-package-archive", source_root)])
        archive_raw = auth.read(archive_source, cap=PUBLISHED_V1_ARCHIVE_PIN["bytes"])
        if (len(archive_raw) != PUBLISHED_V1_ARCHIVE_PIN["bytes"]
                or auth.sha(archive_raw) != PUBLISHED_V1_ARCHIVE_PIN["sha256"]):
            raise ValueError("retained published archive differs from its exact release pin")
        write(archive_copy, archive_raw, 0o600)
        package_root, member_count, package_file_bytes, expanded_bytes = _extract_published_v1_archive(
            archive_raw, package_tree)
        pins_path, cli = package_root / "pins.json", package_root / "cli.py"
        pins = auth.parsed(auth.read(pins_path))
        if (pins.get("sdk_version") != "0.1.0" or pins.get("package_version") != "0.1.0-2"
                or pins.get("source_commit") != "b4ebb9cce5decd01616b75acf451d0eba9995ee3"):
            raise ValueError("published package root differs from its historical version/source pins")
        _check_limits(supervisor, "validated published-v1 archive and package")

        python_inputs = auth.parsed(auth.read(ROOT / "release/ci-python-inputs.json"))
        python_pin = python_inputs["hosts"][current_host()]
        interpreter, python_bootstrap = ci_sdk.verify_python_bootstrap(
            Path(supervisor.python_root), current_host())
        python_relative = auth.rel(python_pin["runtime_relative_path"])
        expected_interpreter = Path(supervisor.python_root) / "runtime" / python_relative
        if interpreter.resolve(strict=True) != expected_interpreter.resolve(strict=True):
            raise ValueError("verified Python interpreter differs from the host runtime pin path")
        interpreter_raw = auth.read(interpreter, cap=python_pin["runtime_bytes"])
        if (len(interpreter_raw) != python_pin["runtime_bytes"]
                or auth.sha(interpreter_raw) != python_pin["runtime_sha256"]):
            raise ValueError("verified Python interpreter bytes differ from the host runtime pin")
        bootstrap_path = Path(supervisor.python_root) / "bootstrap.json"
        bootstrap_raw = auth.read(bootstrap_path, cap=64 * 1024)
        result.update({
            "archive": {"source": str(archive_source), "copy": str(archive_copy),
                        "bytes": len(archive_raw), "sha256": auth.sha(archive_raw)},
            "package_root": str(package_root),
            "package_version_pins": {key: pins[key] for key in
                                      ("sdk_version", "package_version", "source_commit")},
            "package_pins_sha256": auth.sha(auth.read(pins_path)),
            "historical_cli_sha256": auth.sha(auth.read(cli)),
            "package_tar": {"members": member_count, "regular_file_bytes": package_file_bytes,
                             "expanded_bytes": expanded_bytes,
                             "expanded_limit_bytes": PUBLISHED_V1_EXPANDED_LIMIT,
                             "decoder_memory_limit_bytes": PUBLISHED_V1_XZ_MEMORY_LIMIT},
            "interpreter": {"path": str(interpreter), "root": str(supervisor.python_root),
                            "host": current_host(), "bytes": len(interpreter_raw),
                            "sha256": auth.sha(interpreter_raw),
                            "pin_bytes": python_pin["runtime_bytes"],
                            "pin_sha256": python_pin["runtime_sha256"],
                            "bootstrap_sha256": auth.sha(bootstrap_raw),
                            "verified_bootstrap": python_bootstrap},
            "state": str(state), "project": str(project), "build": str(build),
            "home": str(home), "tmp": str(tmp),
            "package_tree": str(package_tree),
            "retained_root": str(state / "retained"),
            "retained_launcher": str(state / "retained/bin/ami-rust"),
        })

        supervisor.env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home),
                          "TMPDIR": str(tmp), "LC_ALL": "C"}
        commands = (
            ("published-v1-verify-package", ["verify-package"]),
            ("published-v1-prepare", ["prepare", "--state", state]),
            ("published-v1-new-project", ["new", "--state", state, "--project", project]),
            ("published-v1-build", ["build", "--state", state, "--project", project,
                                      "--output-dir", build]),
        )
        command_rows = []
        for label, arguments in commands:
            row = _supervised_run(supervisor, [interpreter, "-I", "-B", cli, *arguments],
                                  cwd=area, label=label, timeout=1200)
            _check_limits(supervisor, label)
            command_rows.append({key: row.get(key) for key in
                                 ("label", "exit_code", "stdout_log", "stderr_log")})

        ready_path = state / "ready.json"
        lock_path = project / "ami-rust.lock.json"
        executable = build / "artifacts/AMIRUST"
        ready_raw, lock_raw, executable_raw = (auth.read(ready_path), auth.read(lock_path),
                                                auth.read(executable))
        ready, lock = auth.parsed(ready_raw), auth.parsed(lock_raw)
        if (ready.get("schema") != "ami-rust-package-state-v1" or ready.get("status") != "READY"
                or ready.get("package_version") != "0.1.0-2"
                or lock.get("schema") != "ami-rust-project-lock-v1"):
            raise ValueError("published-v1 setup omitted its READY state or legacy project lock")
        result.update({
            "status": "PASS_ACTUAL_PUBLISHED_V1_SETUP_ORACLE_NOT_RC1_ACCEPTANCE",
            "ready_sha256": auth.sha(ready_raw),
            "legacy_lock_sha256": auth.sha(lock_raw),
            "native_executable": {"path": str(executable), "bytes": len(executable_raw),
                                  "sha256": auth.sha(executable_raw)},
            "commands": command_rows,
        })
        _check_limits(supervisor, "completed published-v1 setup oracle")
        return result
    except Exception as error:
        result.update(status="FAIL", error=repr(error))
        raise
    finally:
        supervisor.env = original_env
        result.setdefault("commands", [
            {key: row.get(key) for key in ("label", "exit_code", "stdout_log", "stderr_log")}
            for row in supervisor.commands[command_start:]
        ])
        write(report_path, auth.encoded(result), 0o600)


def producer(identity):
    return {"kind": "protected-github-actions", "repository": auth.REPO, "workflow": auth.WORKFLOW,
            **identity, "acceptance": "R1 acceptance and publication are separate gates"}


def host_build(work, output, host_rust, host, python_root=None):
    identity = auth.context(ROOT)
    if host != current_host():
        raise ValueError("producer host selection differs from the actual runner")
    config = native_inputs()
    python_root = _python_root_for(work, python_root)
    work = fresh(work)
    output = fresh(output)
    cli, xtask, env, supervisor = build_tools(work, host_rust, output, python_root)
    legacy = obtain_legacy(work, config["legacy_release"])
    _check_limits(supervisor, "native source capsule")
    draft = work / "sdk-draft"
    _supervised_run(supervisor, [xtask, "native-sdk", "--source-sdk", legacy / "sdk.tar.xz",
                                 "--source-commit", identity["source_sha"], "--version", config["sdk_version"],
                                 "--output", draft], label="native-compose-sdk")
    for name, source in (("ami-rust", cli), ("sdk.tar.xz", draft / "sdk.tar.xz"),
                         ("sdk-manifest.json", draft / "sdk-manifest.json")):
        write(output / name, auth.read(source), 0o755 if name == "ami-rust" else 0o644)
    _check_limits(supervisor, "native host output")
    report = {"schema": "ami-rust-native-host-producer-v1", "status": "UNSIGNED_HOST_OUTPUT",
              "host": host, "source": identity, "sdk_version": config["sdk_version"],
              "cli_version": config["cli_version"], "cargo_lock": config["cargo_lock"],
              "cli_identity": auth.parsed(auth.read(work / "cli-identity.json")),
              "supervision": _supervision_summary(supervisor),
              "files": [{"path": p.name, "bytes": p.stat().st_size, "sha256": auth.sha(auth.read(p))}
                        for p in sorted(output.iterdir())],
              "claim": "Native host output only; signatures, consumer qualification and release acceptance remain separate"}
    write(output / "native-host-producer.json", auth.encoded(report))
    _check_limits(supervisor, "native host producer receipt")
    report["supervision"] = _supervision_summary(supervisor)
    (output / "native-host-producer.json").write_bytes(auth.encoded(report))
    _check_limits(supervisor, "native host producer receipt")
    return report


def validate_host_payload(payload, host, identity, config):
    payload = Path(payload).absolute()
    if payload.is_symlink() or not payload.is_dir():
        raise ValueError("native host output root must be a real directory")
    payload = payload.resolve(strict=True)
    report = auth.parsed(auth.read(auth.below(payload, "native-host-producer.json")))
    if (report.get("schema") != "ami-rust-native-host-producer-v1"
            or report.get("status") != "UNSIGNED_HOST_OUTPUT" or report.get("source") != identity
            or report.get("host") != host or report.get("sdk_version") != config["sdk_version"]
            or report.get("cli_version") != config["cli_version"] or report.get("cargo_lock") != config["cargo_lock"]
            or report.get("cli_identity", {}).get("cli_version") != config["cli_version"]):
        raise ValueError("native host output selects a different source, run, host or lock")
    rows = report.get("files")
    if (not isinstance(rows, list) or len(rows) != 3
            or {r.get("path") for r in rows} != {"ami-rust", "sdk.tar.xz", "sdk-manifest.json"}):
        raise ValueError("native host output inventory is incomplete")
    for row in rows:
        raw = auth.read(auth.below(payload, row["path"]))
        if len(raw) != row["bytes"] or auth.sha(raw) != row["sha256"]:
            raise ValueError("native host output bytes differ from their build report")
    return payload


def _check_local_launcher(cli, payloads, host=None):
    host = current_host() if host is None else host
    if host not in payloads or auth.read(cli) != auth.read(payloads[host] / "ami-rust"):
        raise ValueError("native local CLI differs byte-for-byte from the selected host launcher")


def compose(work, output, host_rust, payloads, python_root=None, *, static_roots=()):
    identity = auth.context(ROOT)
    config = native_inputs()
    python_root = _python_root_for(work, python_root)
    work = fresh(work)
    output = Path(output).absolute()
    payloads = {host: validate_host_payload(payloads[host], host, identity, config) for host in auth.HOSTS}
    external_roots = [("native-host-" + host, payloads[host]) for host in auth.HOSTS]
    external_roots.extend(static_roots)
    cli, xtask, env, supervisor = build_tools(work, host_rust, output, python_root,
                                              static_roots=external_roots)
    _check_local_launcher(cli, payloads)
    if auth.read(payloads[auth.HOSTS[0]] / "sdk.tar.xz") != auth.read(payloads[auth.HOSTS[1]] / "sdk.tar.xz"):
        raise ValueError("native host SDK archives are not byte identical")
    legacy = obtain_legacy(work, config["legacy_release"])
    _check_limits(supervisor, "native release source capsule")
    producer_path = work / "declared-producer.json"
    write(producer_path, auth.encoded(producer(identity)))
    _supervised_run(supervisor, [xtask, "native-release", "--source-bundle", legacy,
                                 "--source-commit", identity["source_sha"], "--version", config["sdk_version"],
                                 "--linux-cli", payloads["linux-x86_64"] / "ami-rust",
                                 "--macos-cli", payloads["macos-aarch64"] / "ami-rust",
                                 "--producer-file", producer_path, "--native-notices", ROOT / "tooling/third-party",
                                 "--output", output],
                    label="native-compose-release")
    output = Path(output)
    if auth.read(output / "sdk.tar.xz") != auth.read(payloads[auth.HOSTS[0]] / "sdk.tar.xz"):
        raise ValueError("assembled SDK differs from both host producer outputs")
    write(output / ".auth/inputs.json", auth.encoded(auth.input_manifest_for_sdk(ROOT, config["sdk_version"])))
    if sum(p.stat().st_size for p in output.rglob("*") if p.is_file()) > NATIVE_LIMIT - 1024**2:
        raise ValueError("native candidate exceeds its prospective authentication profile")
    _check_limits(supervisor, "native assembled candidate")
    return {"schema": "ami-rust-native-publisher-candidate-v1", "status": "UNSIGNED_CANDIDATE",
            "source": identity, "manifest_sha256": auth.sha(auth.read(output / "release.json")),
            "supervision": _supervision_summary(supervisor)}


def audit(work, bundle, host_rust, payloads, python_root=None):
    work = Path(work)
    expected = work.parent / (work.name + "-expected")
    bundle = Path(bundle).absolute()
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("native signer candidate must be a real directory")
    bundle = bundle.resolve(strict=True)
    report = compose(work, expected, host_rust, payloads, python_root,
                     static_roots=[("signed-candidate", bundle)])
    required = {p.relative_to(expected).as_posix() for p in expected.rglob("*") if p.is_file()}
    observed = set()
    for path in bundle.rglob("*"):
        if stat.S_ISDIR(path.lstat().st_mode):
            continue
        name = path.relative_to(bundle).as_posix()
        if name not in required or auth.read(auth.below(bundle, name)) != auth.read(auth.below(expected, name)):
            raise ValueError("native signer candidate differs from independent composition: " + name)
        observed.add(name)
    if required != observed:
        raise ValueError("native signer candidate inventory is incomplete")
    digests = {name: auth.sha(auth.read(bundle / name)) for name in auth.SUBJECTS}
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with Path(github_output).open("a") as stream:
            for key, name in (("manifest", "release.json"), ("sdk", "sdk.tar.xz"), ("utility", "SHAUTIL")):
                stream.write(f"{key}={digests[name]}\n")
    return {"schema": "ami-rust-native-signer-audit-v1", "status": "PASS_UNSIGNED_CANDIDATE_ONLY",
            "source": report["source"], "subjects": digests,
            "supervision": report["supervision"]}


def verify_lifecycle(work, output, bundle, host_rust, python_root, outer, upgrade_outer, upgrade_bundle):
    """Real native verification/install/removal, with an independently built CLI.

    Internal Python coordinates this test. The Rust observer admits each
    consumer result only after its adapter evidence is complete and valid.
    Complete RC1 parity, migration and release acceptance remain separate gates.
    """
    import ci_verify
    identity = auth.context(ROOT)
    config = native_inputs()
    python_root = _python_root_for(work, python_root)
    work = fresh(work)
    output = fresh(output)
    bundle = Path(bundle).absolute()
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("native lifecycle candidate must be a real directory")
    bundle = bundle.resolve(strict=True)
    outer = Path(outer).absolute()
    if outer.is_symlink() or not outer.is_dir():
        raise ValueError("native outer candidate must be a real directory")
    outer = outer.resolve(strict=True)
    upgrade_outer = Path(upgrade_outer).absolute()
    upgrade_bundle = Path(upgrade_bundle).absolute()
    cli, xtask, env, supervisor = build_tools(work, host_rust, output, python_root,
        static_roots=[("signed-candidate", bundle), ("outer-candidate", outer),
                      ("upgrade-old-outer", upgrade_outer), ("upgrade-old-bundle", upgrade_bundle)])
    _supervised_run(supervisor, [Path(host_rust) / "toolchain/bin/cargo", "build", "--release", "--locked", "--offline",
        "--manifest-path", ROOT / "tools/consumer-enforcement-adapter/Cargo.toml",
        "--target-dir", work / "consumer-adapter-target"], label="native-build-consumer-adapter")
    adapter = work / "consumer-adapter-target/release/consumer-enforcement-adapter"
    verifier_work = work.parent / "ami-rust-native-verifier-work"
    verifier_metadata = work.parent / "ami-rust-native-verifier-metadata"
    bootstrap_insert_at = len(supervisor.commands)
    # These roots remain live but unchanged while the separate verifier
    # supervisor downloads and probes its tools. Its source/Python roots are
    # already counted there; charge each other root once, including live logs.
    live_samples = [ci_sdk.directory_accounting(root) for root in (work, output)]
    extra_bytes = sum(sample[0] for sample in live_samples)
    extra_bytes += sum(row["regular_file_bytes"] for row in supervisor.native_static_roots)
    extra_logs = sum(sample[1] for sample in live_samples) + supervisor.native_static_log_bytes
    tools = ci_verify.bootstrap_tools(verifier_work, verifier_metadata, python_root,
                                      additional_input_bytes=extra_bytes, additional_log_bytes=extra_logs)
    _add_static_roots(supervisor, [("verifier-work", verifier_work),
                                   ("verifier-metadata", verifier_metadata)])
    _check_limits(supervisor, "native verifier bootstrap")
    policy = {"schema": "ami-rust-publisher-trust-v2", "repository": auth.REPO, "workflow": auth.WORKFLOW,
              "workflow_sha": identity["workflow_sha"], "source_sha": identity["source_sha"],
              "source_ref": "refs/heads/main", "oidc_issuer": "https://token.actions.githubusercontent.com",
              "cert_identity": f"https://github.com/{auth.REPO}/{auth.WORKFLOW}@refs/heads/main",
              "inputs_manifest_sha256": auth.sha(auth.encoded(auth.input_manifest_for_sdk(ROOT, config["sdk_version"]))),
              "allowed_host_profiles": list(auth.HOSTS),
              **{name: {"path": tools["tools"][name]["path"], "sha256": tools["tools"][name]["sha256"]}
                 for name in ("gh", "cosign")},
              "gh_trusted_roots": tools["roots"]["gh"], "cosign_trusted_root": tools["roots"]["cosign"]}
    # Tool receipts may additionally describe roots' sizes. The public policy
    # deliberately admits only path and digest, as its Rust parser requires.
    for name in ("gh_trusted_roots", "cosign_trusted_root"):
        policy[name] = {key: policy[name][key] for key in ("path", "sha256")}
    policy_path = output / "native-publisher-policy.json"
    write(policy_path, auth.encoded(policy), 0o600)
    closure_path = output / "reviewed-consumer-inputs.json"
    write(closure_path, auth.encoded({"schema": "ami-rust-reviewed-consumer-inputs-v1", "source": identity,
        "publisher_inputs": auth.input_manifest_for_sdk(ROOT, config["sdk_version"]),
        "candidate_manifest_sha256": auth.sha(auth.read(bundle / "release.json")),
        "scope": "Reviewed source/component/vendor/package identities; each Rust observer additionally records exact runtime tools and phase policy."}), 0o600)
    for directory in (output / "observation-specs", output / "observations"):
        directory.mkdir(mode=0o700)
    commands = []

    def command(label, arguments, expected=0, *, executable=cli, disposable_refusal_state=None,
                additional_deny_exec=(), inert_python_roots=(), cold_runtime_reference=None,
                publisher_policy=None):
        stdout = output / (label + ".stdout.json")
        stderr = output / (label + ".stderr.log")
        spec = _consumer_observation_spec(work, python_root, executable, arguments, expected,
            policy_path if publisher_policy is None else publisher_policy, closure_path,
            [ROOT, *[row["resolved_path"] for row in supervisor.native_static_roots]],
            disposable_refusal_state=disposable_refusal_state,
            additional_deny_exec=additional_deny_exec, inert_python_roots=inert_python_roots,
            cold_runtime_reference=cold_runtime_reference)
        spec_path = output / "observation-specs" / (label + ".json")
        write(spec_path, auth.encoded(spec), 0o600)
        observed = output / "observations" / label
        record = _supervised_run(supervisor, [xtask, "native-consumer-observe", "--spec", spec_path,
            "--adapter", adapter, "--output", observed], cwd=work, label=label, timeout=1200)
        observation = auth.parsed(auth.read(observed / "observation.json"))
        if (observation.get("status") != "PASS_EXPECTED_CONSUMER_RESULT_AND_ADAPTER_EVIDENCE"
                or observation.get("expected_exit") != expected
                or observation.get("adapter_evidence", {}).get("child_exit_code") != expected):
            raise ValueError("native consumer result omitted complete admitted adapter evidence: " + label)
        shutil.copyfile(work / record["stdout_log"], stdout)
        shutil.copyfile(work / record["stderr_log"], stderr)
        commands.append({"label": label, "exit": expected, "expected_exit": expected,
                         "stdout_sha256": auth.sha(auth.read(stdout)),
                         "stderr_sha256": auth.sha(auth.read(stderr)),
                         "observation": observation,
                         "supervision_record": dict(record)})
        write(output / (label + ".result.json"), auth.encoded(commands[-1]))
        _check_limits(supervisor, "native lifecycle command " + label)
        return auth.read(stdout)

    command("01-real-native-verify", ["verify", "--bundle", bundle, "--policy", policy_path])
    for index, kind in enumerate(("gh", "cosign"), start=2):
        altered = work / ("altered-" + kind)
        shutil.copytree(bundle, altered)
        proof = altered / ".auth" / kind / "release.json.json"
        value = auth.parsed(auth.read(proof))
        row, key = ((value["dsseEnvelope"]["signatures"][0], "sig") if kind == "gh"
                    else (value["messageSignature"], "signature"))
        original = row[key]
        row[key] = ("A" if original[0] != "A" else "B") + original[1:]
        proof.write_bytes(auth.encoded(value))
        command(f"0{index}-altered-{kind}-signature", ["verify", "--bundle", altered, "--policy", policy_path], 2)
        diagnostic = (output / f"0{index}-altered-{kind}-signature.stderr.log").read_text()
        if "publisher verifier " not in diagnostic or f"/{kind} failed with" not in diagnostic:
            raise ValueError(f"altered {kind} signature did not reach the actual pinned verifier failure")
        shutil.rmtree(altered)
    altered = work / "altered-sdk"
    shutil.copytree(bundle, altered)
    with (altered / "sdk.tar.xz").open("ab") as stream:
        stream.write(b"isolated corruption counterprobe")
    command("04-altered-sdk", ["verify", "--bundle", altered, "--policy", policy_path], 2)
    shutil.rmtree(altered)
    install_area = work / "native-direct-install-area"
    install_area.mkdir(mode=0o700)
    prefix, pin = install_area / "native-install", install_area / "external-receipt.sha256"
    result = auth.parsed(command("05-native-install", ["install", "--bundle", bundle, "--policy", policy_path,
                                                        "--prefix", prefix, "--receipt-pin", pin]))
    receipt = result["receipt_sha256"]
    if (result["status"] != "installed" or auth.sha(auth.read(prefix / "install-receipt.json")) != receipt
            or pin.read_text().strip() != receipt):
        raise ValueError("native installation does not match its external receipt pin")
    installed_before = {p.relative_to(prefix).as_posix(): auth.sha(auth.read(p)) for p in prefix.rglob("*") if p.is_file()}
    command("06-occupied-install", ["install", "--bundle", bundle, "--policy", policy_path, "--prefix", prefix], 2)
    command("07-wrong-removal-pin", ["uninstall", "--prefix", prefix, "--receipt-sha256", "0" * 64], 2)
    installed_after = {p.relative_to(prefix).as_posix(): auth.sha(auth.read(p)) for p in prefix.rglob("*") if p.is_file()}
    if installed_before != installed_after:
        raise ValueError("refused native lifecycle operation changed installed user data")
    removed = auth.parsed(command("08-native-uninstall", ["uninstall", "--prefix", prefix, "--receipt-sha256", receipt]))
    if removed["status"] != "uninstalled" or prefix.exists() or pin.read_text().strip() != receipt:
        raise ValueError("native uninstall did not preserve the external pin and remove only its installation")
    package_lifecycle = _qualify_native_package(
        work, output, outer, bundle, cli, xtask, supervisor, policy_path, identity, config, command,
        upgrade_outer, upgrade_bundle)
    report = {"schema": "ami-rust-native-direct-lifecycle-v1", "status": "PASS_NATIVE_LIFECYCLE_NOT_RC1_ACCEPTANCE",
              "package_lifecycle": package_lifecycle,
              "native_matrix": package_lifecycle["native_matrix"],
              "source": identity, "host": current_host(), "commands": commands,
              "supervision": _supervision_summary(supervisor, tools.get("commands", []),
                                                   bootstrap_insert_at),
              "manifest_sha256": auth.sha(auth.read(bundle / "release.json")),
              "cli_sha256": auth.sha(auth.read(cli)), "receipt_sha256": receipt,
              "remaining_gates": ["complete both-host no-Python observation", "complete cold/warm and negative lifecycle matrix",
                                  "complete cross-host R1-A2 native output and raw-metadata comparison",
                                  "complete cross-host RC1-A4 migration, native upgrade and retained replay"],
              "claim": "Real inner/outer signatures, native direct and package preparation/build/removal/retained replay, plus the current-host two-root five-variant matrix; internal Python coordination is outside consumer scope. No-Python observation, cross-host R1-A2/A4 and RC1 acceptance remain open"}
    report_path = output / "native-direct-lifecycle.json"
    initial_report = auth.encoded(report)
    if ci_sdk.directory_bytes(output) + len(initial_report) > MAX_CONSUMER_OUTPUT_BYTES:
        raise ValueError("native lifecycle report would exceed the 64 MiB consumer artifact ceiling")
    write(report_path, initial_report)
    _check_limits(supervisor, "native direct lifecycle report")
    report["supervision"] = _supervision_summary(supervisor, tools.get("commands", []),
                                                  bootstrap_insert_at)
    final_report = auth.encoded(report)
    if (ci_sdk.directory_bytes(output) - report_path.stat().st_size + len(final_report)
            > MAX_CONSUMER_OUTPUT_BYTES):
        raise ValueError("native lifecycle report would exceed the 64 MiB consumer artifact ceiling")
    report_path.write_bytes(final_report)
    if ci_sdk.directory_bytes(output) > MAX_CONSUMER_OUTPUT_BYTES:
        raise ValueError("native lifecycle output exceeded the 64 MiB consumer artifact ceiling")
    _check_limits(supervisor, "native direct lifecycle report")
    return report


def _partition_inert_runtime_reads(readonly_roots, excluded_roots):
    """Keep ordinary sibling inputs readable without granting an inert runtime.

    Landlock cannot subtract a denied file from an allowed ancestor. Walk only
    the ancestors of explicit runtime exclusions, emitting literal directories
    and safe sibling grants. Listing/stat failures propagate; no rglob omission
    may silently turn an incomplete policy into a successful observation.
    """
    excluded = {Path(root).resolve(strict=True) for root in excluded_roots}
    trees, files, directories = set(), set(), set()

    def overlaps(left, right):
        return left == right or left in right.parents or right in left.parents

    def visit(path):
        canonical = path.resolve(strict=True)
        if any(canonical == root or root in canonical.parents for root in excluded):
            return
        info = canonical.lstat()
        if not any(canonical in root.parents for root in excluded):
            if stat.S_ISDIR(info.st_mode):
                trees.add(canonical)
            elif stat.S_ISREG(info.st_mode):
                files.add(canonical)
            else:
                raise ValueError("inert runtime partition encountered a nonregular input")
            return
        if not stat.S_ISDIR(info.st_mode) or path.is_symlink():
            raise ValueError("inert runtime partition ancestor must be a real directory")
        directories.add(canonical)
        with os.scandir(canonical) as entries:
            children = sorted((Path(entry.path) for entry in entries), key=lambda item: item.name)
        for child in children:
            visit(child)
        after = canonical.lstat()
        if (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("inert runtime partition ancestor changed during policy construction")

    for root in sorted({Path(path).resolve(strict=True) for path in readonly_roots}):
        if not root.is_dir():
            raise ValueError("consumer read-tree root must be an existing directory")
        visit(root)
    if any(overlaps(grant, denied) for grant in trees | files for denied in excluded):
        raise ValueError("inert runtime partition retained an overlapping data grant")
    return trees, files, directories


def _consumer_observation_spec(work, python_root, executable, arguments, expected,
                               policy_path, closure_path, readonly_roots, *, disposable_refusal_state=None,
                               additional_deny_exec=(), inert_python_roots=(), cold_runtime_reference=None):
    """Select each command's owned writes; Rust owns policy/runtime/report logic."""
    work = Path(work).resolve(strict=True)
    arguments = list(map(str, arguments))
    verb = arguments[0]
    phase = {"verify-package": "package-consistency", "native-package-verify": "package-authentication",
             "prepare": "prepare-refusal" if expected else "cold-prepare",
             "native-prepare-interruption": "cold-prepare",
             "new": "new-project", "migrate": "lock"}.get(verb, verb)
    if phase not in {"verify", "install", "uninstall", "package-consistency", "package-authentication",
                     "cold-prepare", "prepare-refusal", "check-inputs", "new-project", "lock", "build"}:
        raise ValueError("unsupported observed consumer command")

    def option(name):
        if name not in arguments:
            return None
        return Path(arguments[arguments.index(name) + 1]).absolute()

    writes = {work / "home", work / "tmp"}
    derived = None
    record = None
    state = option("--state")
    if state is not None and (state / "selection.json").is_file():
        record = state / "selection.json"
    for key in ("--selection", "--sdk-lock"):
        if option(key) is not None:
            record = option(key)
    legacy_python = None
    if verb == "migrate":
        record = option("--from-lock")
        if record is None and option("--project") is not None:
            candidate = option("--project") / "ami-rust.lock.json"
            if candidate.is_file():
                record = candidate
        if record is None or (option("--from-lock") is not None and option("--output") is None):
            raise ValueError("observed migration requires an explicit legacy lock and output or a conventional inspection lock")
        legacy = auth.parsed(auth.read(record))
        if legacy.get("schema") != "ami-rust-project-lock-v1":
            raise ValueError("observed migration requires the inert legacy v1 record")
        legacy_python = Path(legacy["host"]["python"]).resolve(strict=True)
        if not legacy_python.is_file():
            raise ValueError("legacy Python identity is not a regular file")
    if phase == "cold-prepare":
        if cold_runtime_reference is not None:
            if (record is not None or type(cold_runtime_reference) is not dict
                    or set(cold_runtime_reference) != {"path", "sha256"}):
                raise ValueError("cold runtime reference requires a fresh state and exact validated binding")
            record = Path(cold_runtime_reference["path"])
            if (record.is_symlink() or record.resolve(strict=True) != record or not record.is_file()
                    or auth.sha(auth.read(record)) != cold_runtime_reference["sha256"]):
                raise ValueError("validated cold runtime reference changed before observation")
        derived = {"role": "consumer-state-parent", "path": str(state.parent)}
        writes.add(state.parent.parent)
    elif phase == "build":
        target = option("--output-dir")
        derived = {"role": "consumer-build-parent", "path": str(target.parent)}
        writes.add(target.parent.parent)
    elif phase == "new-project":
        writes.add(option("--project").parent)
    elif phase == "lock" and option("--output") is not None:
        writes.add(option("--output").parent)
    elif phase == "package-authentication":
        writes.add(option("--work").parent)
    elif phase == "install" and not expected:
        writes.add(option("--prefix").parent)
        if option("--receipt-pin") is not None:
            writes.add(option("--receipt-pin").parent)
    elif phase == "uninstall" and not expected:
        writes.add(option("--prefix").parent)
    if disposable_refusal_state is not None:
        disposable = Path(disposable_refusal_state)
        if (phase != "prepare-refusal" or expected != 2 or state != disposable or record is not None
                or disposable == work or work not in disposable.parents
                or disposable.resolve(strict=True) != disposable):
            raise ValueError("disposable retry grant requires its exact existing partial private state")
        info = disposable.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("disposable retry state must be a private current-user directory")
        # Permit effects on this disposable partial state so an attempted write
        # cannot be hidden by a sandbox denial and mistaken for a refusal.
        writes.add(disposable)
    # Keep distinct native operation areas and remove duplicate/nested grants.
    writes = {root for root in writes if not any(root != other and other in root.parents for other in writes)}
    policy = auth.parsed(auth.read(policy_path))
    pin = auth.parsed(auth.read(ROOT / "release/ci-python-inputs.json"))["hosts"][current_host()]
    interpreter = Path(python_root) / "runtime" / pin["runtime_relative_path"]
    library_name = "libpython3.12.dylib" if current_host() == "macos-aarch64" else "libpython3.12.so.1.0"
    library = Path(python_root) / "runtime/python/lib" / library_name
    inert_roots = set()
    inert_interpreters, inert_libraries = set(), set()
    for root in map(Path, inert_python_roots):
        if root.is_symlink() or root.absolute() != root.resolve(strict=True) or not root.is_dir():
            raise ValueError("inert Python runtime must be a canonical real directory")
        old_interpreter = root / "bin/python3.12"
        old_library = root / "lib" / library_name
        for path in (old_interpreter, old_library):
            if path.is_symlink() or not path.is_file() or path.resolve(strict=True) != path:
                raise ValueError("inert Python interpreter/library must be canonical regular files")
        if any(root == writable or root in writable.parents or writable in root.parents
               for writable in writes):
            raise ValueError("consumer writes overlap an inert Python runtime")
        inert_roots.add(root)
        inert_interpreters.add(old_interpreter)
        inert_libraries.add(old_library)
    reads, read_files, read_directories = _partition_inert_runtime_reads(
        {work, *map(Path, readonly_roots)}, inert_roots)
    if legacy_python is not None:
        read_files.add(legacy_python)
    read_directories.add(Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True))
    denied_exec = {str(interpreter), *map(str, inert_interpreters),
                   *[str(Path(path).resolve(strict=True)) for path in additional_deny_exec]}
    if legacy_python is not None:
        denied_exec.add(str(legacy_python))
        if current_host() == "linux-x86_64":
            # The reviewed Rust CLI installs its irreversible process-wide
            # execve/execveat filter before rendering either migration form.
            # Linux cannot subtract deny-exec from this exact inert byte read.
            # Keep other interpreter/library denials and no derived execution.
            denied_exec.discard(str(legacy_python))
    bindings = [Path(closure_path), Path(policy_path)] + ([record] if record else [])
    return {"schema": "ami-rust-consumer-observation-spec-v1", "phase": phase,
            "command": [str(Path(executable).resolve(strict=True)), *arguments], "expected_exit": expected,
            "cwd": str(work), "home": str(work / "home"), "tmp": str(work / "tmp"),
            "read_trees": [{"role": "work", "path": str(root)} for root in sorted(reads)],
            "write_trees": [{"role": "work", "path": str(root)} for root in sorted(writes)],
            "read_files": [str(path) for path in sorted(read_files)],
            # The CLI checks account-home ownership independently of sandbox HOME.
            # Grant this directory literally, without reading its contents recursively.
            "read_directories": [str(path) for path in sorted(read_directories)],
            "executables": [policy[name]["path"] for name in ("gh", "cosign")]
                + ([str(option("--frontend").resolve(strict=True))]
                   if verb == "native-prepare-interruption" else []),
            "libraries": [], "deny_exec": sorted(denied_exec),
            "deny_library": sorted({str(library), *map(str, inert_libraries)}),
            # A dry-run only reads and validates the legacy inventories. Do not
            # run ldd on their executables before that validation has passed.
            "component_record": (str(record) if record and not (verb == "migrate" and "--dry-run" in arguments)
                                 else None), "derived": derived,
            "bindings": [{"path": str(path), "sha256": auth.sha(auth.read(path))} for path in bindings]}


def _validated_cold_runtime_reference(report, bundle, inspection, writes, inert_runtimes):
    """Admit an inventory-checked native reference, never the new cold state."""
    baseline = auth.parsed(auth.read(ROOT / "tooling/fixtures/accepted-r1-inputs.json"))["sdk_target"]
    if (current_host() != "linux-x86_64"
            or report.get("status") != "PASS_ACTUAL_PUBLISHED_V1_SETUP_ORACLE_NOT_RC1_ACCEPTANCE"
            or report.get("archive_pin") != PUBLISHED_V1_ARCHIVE_PIN
            or report.get("package_version_pins", {}).get("source_commit") != baseline["source_identity"]
            or inspection.get("status") != "migration-required" or inspection.get("host") != current_host()
            or inspection.get("migration_required") is not True):
        raise ValueError("cold runtime reference requires the actual validated published Linux setup")
    state, project = Path(report["state"]), Path(report["project"])
    record = project / "ami-rust.lock.json"
    if (record.is_symlink() or record.resolve(strict=True) != record
            or auth.sha(auth.read(record)) != report["legacy_lock_sha256"]
            or inspection.get("legacy_lock", {}).get("sha256") != report["legacy_lock_sha256"]
            or inspection.get("legacy_lock", {}).get("path") != str(record)
            or auth.sha(auth.read(state / "ready.json")) != report["ready_sha256"]):
        raise ValueError("cold runtime reference lost its exact published setup binding")
    for relative in ("release/ci-sdk-inputs.json", f"release/ci-cargo-producers/{current_host()}.json"):
        if auth.read(state / "source" / relative) != auth.read(ROOT / relative):
            raise ValueError("cold runtime reference native source pins differ from the candidate")
    compiler = inspection.get("compiler")
    if compiler != {key: baseline[key] for key in ("rust_commit", "rust_llvm", "source_date_epoch")}:
        raise ValueError("cold runtime reference compiler differs from the immutable native baseline")
    candidate = auth.parsed(auth.read(Path(bundle) / "release.json"))
    files = candidate["sdk_files"]
    current = {row["path"]: row["sha256"] for row in files}
    if len(current) != len(files):
        raise ValueError("candidate SDK inventory has duplicate paths")
    components = inspection.get("components", [])
    required = {"cargo", "collector", "csdk", "rust", "toolchain", "vendor"}
    if len(components) != 6 or {row["name"] for row in components} != required:
        raise ValueError("cold runtime reference omits the exact six native component inventories")
    recorded_components = auth.parsed(auth.read(record))["components"]
    if set(recorded_components) != required:
        raise ValueError("cold runtime reference lock omits native components")
    for row in components:
        manifest = f'host/profiles/{current_host()}/{row["name"]}.json'
        root = Path(row["root"])
        selected = Path(recorded_components[row["name"]])
        if not selected.is_absolute():
            selected = record.parent / selected
        if (row["manifest"] != manifest or current.get(manifest) != row["manifest_sha256"]
                or root.is_symlink() or root.resolve(strict=True) != root or not root.is_dir()
                or selected.resolve(strict=True) != root
                or state not in root.parents
                or any(_overlap(root, Path(path)) for path in (*writes, *inert_runtimes))):
            raise ValueError("cold runtime reference components differ, alias unsafe roots, or overlap consumer writes")
    if any(_overlap(record, Path(path)) for path in writes):
        raise ValueError("cold runtime reference binding overlaps consumer writes")
    return {"path": str(record), "sha256": report["legacy_lock_sha256"]}


def _publish_cold_root_diagnostics(work, output):
    diagnostics = Path(work) / "cold-root-diagnostics"
    output = Path(output)
    destination = output / "cold-root-diagnostics"
    if (diagnostics.is_symlink() or not diagnostics.is_dir()
            or output.is_symlink() or not output.is_dir()
            or destination.exists() or destination.is_symlink()):
        raise ValueError("cold-root diagnostics are not available at a fresh consumer destination")
    report = diagnostics / "report.json"
    raw = diagnostics / "raw"
    if (report.is_symlink() or not report.is_file() or raw.is_symlink() or not raw.is_dir()
            or report.stat().st_size > ci_sdk.MAX_COLD_ROOT_DIAGNOSTIC_REPORT_BYTES
            or ci_sdk.directory_bytes(raw) > ci_sdk.MAX_COLD_ROOT_DIAGNOSTIC_RAW_BYTES):
        raise ValueError("cold-root diagnostics exceed their bounded evidence profile")
    for path in diagnostics.rglob("*"):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError("cold-root diagnostics contain a nonregular entry")
    diagnostic_bytes = ci_sdk.directory_bytes(diagnostics)
    if ci_sdk.directory_bytes(output) + diagnostic_bytes > MAX_CONSUMER_OUTPUT_BYTES:
        raise ValueError("cold-root diagnostics would exceed the 64 MiB consumer artifact ceiling")
    inventory = ci_sdk.component_inventory(diagnostics)
    # Both roots share the runner filesystem. Rename the evidence so preserving
    # a failure does not duplicate up to 26 MiB of managed workspace.
    diagnostics.rename(destination)
    if (ci_sdk.component_inventory(destination) != inventory
            or ci_sdk.directory_bytes(output) > MAX_CONSUMER_OUTPUT_BYTES):
        raise ValueError("cold-root diagnostics changed or exceeded the consumer artifact ceiling")


def _preserve_matrix_metadata(artifacts, rows, work):
    """Keep only the three exact dependency archives until the matrix passes."""
    destination = Path(work) / "pending-native-metadata"
    if destination.exists() or destination.is_symlink():
        raise ValueError("native matrix metadata staging directory must be fresh")
    destination.mkdir(mode=0o700)
    retained = {}
    for crate in ci_sdk.METADATA_CRATES:
        names = [name for name in rows
                 if name.startswith("target/release/deps/")
                 and re.fullmatch("lib" + crate + r"-[0-9a-f]+\.rlib", Path(name).name)]
        if len(names) != 1:
            raise ValueError("expected exactly one raw metadata archive for " + crate)
        name = names[0]
        source = Path(artifacts).joinpath(*ci_sdk._safe_relative(name).parts)
        row = rows[name]
        if (source.is_symlink() or not source.is_file()
                or source.stat().st_size != row["bytes"] or ci_sdk.sha256(source) != row["sha256"]):
            raise ValueError("native matrix metadata archive differs from its canonical row: " + crate)
        target = destination.joinpath(*ci_sdk._safe_relative(name).parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if target.stat().st_size != row["bytes"] or ci_sdk.sha256(target) != row["sha256"]:
            raise ValueError("preserved native matrix metadata archive differs: " + crate)
        retained[name] = row
    return destination, retained


def _matrix_diagnostic_allowance(supervisor, output):
    # Reserve the complete structured mismatch report even when raw evidence
    # must be omitted. Moving it to output adds no second workspace copy.
    available = min(MAX_CONSUMER_OUTPUT_BYTES - ci_sdk.directory_bytes(output),
                    ci_sdk.MAX_WORK_BYTES - supervisor.managed_bytes())
    if available < ci_sdk.MAX_COLD_ROOT_DIAGNOSTIC_REPORT_BYTES:
        raise ValueError("insufficient managed headroom for the native matrix diagnostic report")
    return min(ci_sdk.MAX_COLD_ROOT_DIAGNOSTIC_RAW_BYTES,
               available - ci_sdk.MAX_COLD_ROOT_DIAGNOSTIC_REPORT_BYTES)


def _qualify_native_build_matrix(work, state, frontend, output, supervisor, config, command):
    """Build the frozen five-variant set in two private roots through the signed frontend."""
    work, state, output = Path(work).absolute(), Path(state).absolute(), Path(output).absolute()
    host = current_host()
    inputs_path = ROOT / "release/ci-sdk-inputs.json"
    inputs = ci_sdk.read_json(inputs_path)
    reference_pin = inputs["native_reference"]
    reference = ci_sdk.validate_native_reference(
        ci_sdk.read_json(ROOT / reference_pin["path"], 2 * 1024**2),
        inputs, reference_pin["sha256"])

    prefix = state / ("sdk-" + config["sdk_version"])
    selection = state / "selection.json"
    receipt_path = prefix / "install-receipt.json"
    sdk_source = prefix / "sdk"
    if (state.is_symlink() or not state.is_dir() or prefix.is_symlink() or not prefix.is_dir()
            or selection.is_symlink() or not selection.is_file()
            or receipt_path.is_symlink() or not receipt_path.is_file()
            or sdk_source.is_symlink() or not sdk_source.is_dir()):
        raise ValueError("native matrix requires the cold-prepared installed SDK and selection")
    selection_bytes = auth.read(selection)
    selection_value = auth.parsed(selection_bytes)
    install_receipt_sha256 = auth.sha(auth.read(receipt_path))
    if selection_value.get("install_receipt_sha256") != install_receipt_sha256:
        raise ValueError("native matrix selection differs from the installed SDK receipt")
    sdk_inventory = ci_sdk.component_inventory(sdk_source)
    if (not (sdk_source / "Cargo.toml").is_file()
            or (sdk_source / "Cargo.toml").is_symlink()
            or not (sdk_source / "Cargo.lock").is_file()
            or (sdk_source / "Cargo.lock").is_symlink()):
        raise ValueError("installed native SDK source workspace is incomplete")
    sdk_inventory_sha256 = auth.sha(auth.encoded(sdk_inventory))
    sdk_source_bytes = sum(row["bytes"] for row in sdk_inventory["files"])

    matrix_root = work / "native matrix with spaces"
    if matrix_root.exists() or matrix_root.is_symlink():
        raise ValueError("native matrix private root must be fresh")
    matrix_root.mkdir(mode=0o700)
    layouts = []
    for name in ("sdk-layout-a", "sdk-layout-b-with-spaces"):
        root = matrix_root / name
        root.mkdir(mode=0o700)
        project = root / "sdk"
        shutil.copytree(sdk_source, project, symlinks=True, copy_function=shutil.copy2)
        copied_inventory = ci_sdk.component_inventory(project)
        if copied_inventory != sdk_inventory:
            raise ValueError("native matrix SDK project copy differs from the verified installation")
        lock_path = root / "project-lock.json"
        lock_label = "17-matrix-lock-" + name
        lock_output = auth.parsed(command(lock_label, ["lock", "--prefix", prefix,
            "--selection", selection, "--project", project, "--output", lock_path], executable=frontend))
        if (lock_output.get("status") != "locked" or lock_output.get("output") != str(lock_path)
                or lock_output.get("receipt_sha256") != install_receipt_sha256
                or lock_output.get("sdk_manifest_sha256") != auth.sha(auth.read(project / "contract/sdk.json"))
                or lock_path.is_symlink() or not lock_path.is_file()):
            raise ValueError("native matrix direct lock did not bind the prepared SDK and project")
        layouts.append({"name": name, "root": root, "project": project,
                        "lock": lock_path, "lock_sha256": ci_sdk.sha256(lock_path),
                        "receipt_sha256": lock_output["receipt_sha256"],
                        "sdk_manifest_sha256": lock_output["sdk_manifest_sha256"]})
        _check_limits(supervisor, "created native matrix direct lock " + name)

    first_by_variant = {}
    build_records = []
    metadata_stage = None
    metadata_rows = None
    for layout in layouts:
        build_parent = layout["root"] / "build outputs"
        build_parent.mkdir(mode=0o700)
        for variant, (package, feature_args) in ci_sdk.VARIANTS.items():
            # Each command starts with its own empty derived-executable parent.
            # Reusing build_parent would include the preceding variant's tools.
            derived_parent = build_parent / (variant + "-derived")
            derived_parent.mkdir(mode=0o700)
            build_output = derived_parent / "build"
            label = f"{layout['name']}/{variant}"
            build_label = "19-matrix-build-" + layout["name"] + "-" + variant
            arguments = ["build", "--sdk-lock", layout["lock"], "--output-dir", build_output,
                         "--", "build", "--manifest-path", layout["project"] / "Cargo.toml",
                         "--package", package, "--release", "--locked", "--offline", *feature_args]
            build_output_value = auth.parsed(command(build_label, arguments, executable=frontend))
            if (build_output_value.get("status") != "PASS"
                    or build_output_value.get("native_executable") != str(build_output / "artifacts/AMIRUST")
                    or build_output_value.get("receipt") != str(build_output / "build-receipt.json")):
                raise ValueError("native matrix frontend build did not report PASS: " + label)
            build_receipt = ci_sdk.read_json(build_output / "build-receipt.json", 4 * 1024**2)
            if (build_receipt.get("project_lock_sha256") != layout["lock_sha256"]
                    or build_receipt.get("sdk_manifest_sha256") != layout["sdk_manifest_sha256"]):
                raise ValueError("native matrix build receipt differs from its selected project lock: " + label)
            expected_rows = ci_sdk._expected_native_rows(reference, host, variant)
            try:
                result, native_file = ci_sdk._verify_native_receipt(
                    build_output, expected_rows, supervisor, label)
            except ValueError as error:
                if "canonical outputs differ from the accepted host reference" not in str(error):
                    raise
                observed, observed_native = ci_sdk._verify_native_receipt(
                    build_output, None, supervisor, label + "/reference-diagnostic")
                if layout is layouts[0]:
                    diagnostic_first_layout = "accepted-host-reference"
                    diagnostic_first_rows = expected_rows
                    diagnostic_first_snapshot = {}
                    diagnostic_first_native = expected_rows["AMIRUST"]
                else:
                    first = first_by_variant[variant]
                    diagnostic_first_layout = layouts[0]["name"]
                    diagnostic_first_rows = first["artifacts"]
                    diagnostic_first_snapshot = first["snapshot"]
                    diagnostic_first_native = {
                        "bytes": first["bytes"], "sha256": first["sha256"]}
                ci_sdk._write_cold_root_diagnostics(
                    work, variant, diagnostic_first_layout, layout["name"],
                    diagnostic_first_rows, observed["artifacts"], diagnostic_first_snapshot,
                    build_output / "artifacts", diagnostic_first_native, {
                        "bytes": observed_native.stat().st_size,
                        "sha256": ci_sdk.sha256(observed_native)},
                    raw_limit_bytes=_matrix_diagnostic_allowance(supervisor, output))
                _publish_cold_root_diagnostics(work, output)
                raise

            native_row = {"bytes": native_file.stat().st_size, "sha256": ci_sdk.sha256(native_file)}
            if layout is layouts[0]:
                preserved = ci_sdk._preserve_native_payload(native_file, work, variant)
                snapshot = ci_sdk._preserve_canonical_snapshot(
                    build_output / "artifacts", result["artifacts"], work, variant,
                    supervisor.managed_bytes)
                first_by_variant[variant] = {
                    "path": preserved, "bytes": native_row["bytes"],
                    "sha256": native_row["sha256"], "artifacts": result["artifacts"],
                    "snapshot": snapshot}
                _check_limits(supervisor, "preserved first native matrix root " + variant)
            else:
                first = first_by_variant[variant]
                try:
                    ci_sdk._assert_cold_roots_match(
                        work, variant, layouts[0]["name"], layout["name"], first,
                        result["artifacts"], build_output / "artifacts", native_row,
                        diagnostic_raw_limit_bytes=_matrix_diagnostic_allowance(supervisor, output))
                except ValueError:
                    _publish_cold_root_diagnostics(work, output)
                    raise
                if variant == "dependencies":
                    metadata_stage, metadata_rows = _preserve_matrix_metadata(
                        build_output / "artifacts", result["artifacts"], work)
                    _check_limits(supervisor, "preserved native matrix metadata archives")
                snapshot_root = work / "cold-root-first" / variant
                if snapshot_root.exists():
                    shutil.rmtree(snapshot_root)
                if snapshot_root.exists() or snapshot_root.is_symlink():
                    raise RuntimeError("matched native matrix snapshot could not be retired")

            build_records.append({
                "identity": {"layout": layout["name"], "variant": variant,
                             "package": package, "feature_arguments": list(feature_args)},
                "command_label": build_label,
                "build_receipt_sha256": result["receipt_sha256"],
                "canonical_artifact_count": len(result["artifacts"]),
                "canonical_artifacts": result["artifacts"],
                "build_byproducts": result["build_byproducts"],
                "AMIRUST": native_row,
                "reference_match": result["artifacts"] == expected_rows})
            ci_sdk._retire_successful_build(build_output, work)
            _check_limits(supervisor, "retired successful native matrix build " + label)

    if (metadata_stage is None or metadata_rows is None
            or set(first_by_variant) != set(ci_sdk.VARIANTS)
            or len(build_records) != 2 * len(ci_sdk.VARIANTS)):
        raise RuntimeError("native matrix did not complete all five variants in both roots")
    if (auth.read(selection) != selection_bytes
            or auth.sha(auth.read(receipt_path)) != install_receipt_sha256):
        raise ValueError("native matrix changed the prepared selection or installed receipt")

    retained_native = [{"variant": variant, "path": "native/" + variant + ".AMIRUST",
                        "bytes": first_by_variant[variant]["bytes"],
                        "sha256": first_by_variant[variant]["sha256"]}
                       for variant in ci_sdk.VARIANTS]
    retained_metadata = [{"crate": crate, "path": "metadata/" + crate + ".rlib",
                          "canonical_path": name, **metadata_rows[name]}
                         for crate in ci_sdk.METADATA_CRATES
                         for name in metadata_rows
                         if name.startswith("target/release/deps/")
                         and re.fullmatch("lib" + crate + r"-[0-9a-f]+\.rlib", Path(name).name)]
    if (len(retained_native) != len(ci_sdk.VARIANTS)
            or len(retained_metadata) != len(ci_sdk.METADATA_CRATES)):
        raise ValueError("native matrix success payload inventory is incomplete")
    matrix = {
        "schema": "ami-rust-native-two-root-five-variant-matrix-v1",
        "status": "PASS_CURRENT_HOST_MATRIX_NOT_RC1_ACCEPTANCE",
        "host": host,
        "sdk_version": config["sdk_version"],
        "reference_sha256": reference_pin["sha256"],
        "root_count": len(layouts),
        "variant_count": len(ci_sdk.VARIANTS),
        "build_count": len(build_records),
        "canonical_artifact_count": sum(row["canonical_artifact_count"] for row in build_records),
        "canonical_artifact_count_by_layout": {
            layout["name"]: sum(row["canonical_artifact_count"] for row in build_records
                                if row["identity"]["layout"] == layout["name"])
            for layout in layouts},
        "layouts": [{"name": layout["name"],
                     "project": layout["project"].relative_to(work).as_posix(),
                     "lock_sha256": layout["lock_sha256"],
                     "receipt_sha256": layout["receipt_sha256"],
                     "sdk_manifest_sha256": layout["sdk_manifest_sha256"],
                     "sdk_source_file_count": len(sdk_inventory["files"]),
                     "sdk_source_symlink_count": len(sdk_inventory["symlinks"]),
                     "sdk_source_bytes": sdk_source_bytes,
                     "sdk_source_inventory_sha256": sdk_inventory_sha256}
                    for layout in layouts],
        "builds": build_records,
        "retained_native_payloads": retained_native,
        "retained_dependency_metadata": retained_metadata,
        "claim": "The five frozen native variants match the exact host reference in two fresh SDK project and build roots. This is current-host evidence only; cross-host R1-A2/A4, no-Python observation, and RC1 acceptance remain open.",
    }
    output_bytes = ci_sdk.directory_bytes(output)
    retained_bytes = sum(row["bytes"] for row in retained_native + retained_metadata)
    report_reserve = 2 * 1024**2
    if (output_bytes + retained_bytes + len(auth.encoded(matrix)) + report_reserve
            > MAX_CONSUMER_OUTPUT_BYTES):
        raise ValueError("native matrix outputs would exceed the 64 MiB consumer artifact ceiling")
    if ((output / "native").exists() or (output / "native").is_symlink()
            or (output / "metadata").exists() or (output / "metadata").is_symlink()):
        raise ValueError("native matrix output destinations must be fresh")
    published_native = [ci_sdk._copy_native_payload(
        first_by_variant[variant]["path"], output, variant) | {"variant": variant}
        for variant in ci_sdk.VARIANTS]
    published_metadata = ci_sdk._copy_metadata_archives(
        metadata_stage, metadata_rows, output)
    if published_native != retained_native or published_metadata != retained_metadata:
        raise ValueError("published native matrix outputs differ from their verified staging rows")
    if ci_sdk.directory_bytes(output) > MAX_CONSUMER_OUTPUT_BYTES:
        raise ValueError("native matrix outputs exceeded the 64 MiB consumer artifact ceiling")

    for layout in layouts:
        shutil.rmtree(layout["root"])
        if layout["root"].exists() or layout["root"].is_symlink():
            raise RuntimeError("successful native matrix project root could not be retired")
    if matrix_root.exists():
        matrix_root.rmdir()
    for temporary in (work / "pending-native", metadata_stage):
        if temporary.exists():
            shutil.rmtree(temporary)
        if temporary.exists() or temporary.is_symlink():
            raise RuntimeError("successful native matrix staging could not be retired")
    _check_limits(supervisor, "completed native two-root five-variant matrix")
    return matrix


def _retained_state_snapshot(root, *, entry_limit=100_000):
    root=Path(root)
    metadata,files,symlinks=[],[],[]
    def identity(info):
        return (info.st_uid,info.st_gid,info.st_mode,info.st_dev,info.st_ino,
                info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    def record(relative,info):
        if len(metadata)>=entry_limit:
            raise ValueError('retained-state snapshot exceeds its entry limit')
        metadata.append({'path':relative,'uid':info.st_uid,'gid':info.st_gid,'mode':info.st_mode,
                         'device':info.st_dev,'inode':info.st_ino,'mtime_ns':info.st_mtime_ns,'ctime_ns':info.st_ctime_ns})
    def walk(fd,relative,expected):
        before=os.fstat(fd)
        if not stat.S_ISDIR(before.st_mode) or identity(before)!=identity(expected):
            raise ValueError('retained directory changed before enumeration: '+relative)
        record(relative,before)
        # scandir errors propagate; Path.rglob silently skips unreadable subtrees.
        with os.scandir(fd) as entries:
            for entry in entries:
                name=entry.name
                child=name if relative=='.' else relative+'/'+name
                info=os.stat(name,dir_fd=fd,follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child_fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                    try:walk(child_fd,child,info)
                    finally:os.close(child_fd)
                elif stat.S_ISLNK(info.st_mode):
                    record(child,info)
                    target=os.readlink(name,dir_fd=fd)
                    if identity(os.stat(name,dir_fd=fd,follow_symlinks=False))!=identity(info):
                        raise ValueError('retained link changed during snapshot: '+child)
                    symlinks.append({'path':child,'target':target})
                elif stat.S_ISREG(info.st_mode):
                    record(child,info)
                    child_fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
                    with os.fdopen(child_fd,'rb') as stream:
                        if identity(os.fstat(stream.fileno()))!=identity(info):
                            raise ValueError('retained file changed before snapshot read: '+child)
                        digest=hashlib.sha256();size=0
                        for block in iter(lambda:stream.read(1024*1024),b''):
                            digest.update(block);size+=len(block)
                        if size!=info.st_size or identity(os.fstat(stream.fileno()))!=identity(info):
                            raise ValueError('retained file changed during snapshot read: '+child)
                    files.append({'path':child,'bytes':size,'sha256':digest.hexdigest()})
                else:
                    raise ValueError('unsupported file type in retained-state snapshot: '+child)
        if identity(os.fstat(fd))!=identity(before):
            raise ValueError('retained directory changed during snapshot: '+relative)
    expected=root.lstat()
    if not stat.S_ISDIR(expected.st_mode):
        raise ValueError('retained-state snapshot root must be a real directory')
    fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:walk(fd,'.',expected)
    finally:os.close(fd)
    key=lambda row:row['path']
    return {'inventory':{'files':sorted(files,key=key),'symlinks':sorted(symlinks,key=key)},'metadata':sorted(metadata,key=key)}


def _preservation_snapshot(roots):
    """Hash complete byte/link/metadata inventories without duplicating them in artifacts."""
    result = {}
    for label, root in sorted(roots.items()):
        # Six independently bounded component trees plus the state wrapper.
        snapshot = _retained_state_snapshot(root, entry_limit=7 * 100_000)
        result[label] = {"root": str(root), "sha256": auth.sha(auth.encoded(snapshot)),
                         "entries": len(snapshot["metadata"]),
                         "file_bytes": sum(row["bytes"] for row in snapshot["inventory"]["files"])}
    return result


def _retained_preservation_guards(work):
    """Populate only isolated qualification HOME and disposable unrelated data."""
    roots = {"global_cargo_config": work / "home/.cargo",
             "global_rustup_config": work / "home/.rustup",
             "unrelated_sdk": work / "unrelated-sdk",
             "user_data": work / "unrelated-user-data"}
    payloads = {"global_cargo_config": ("config.toml", b"[net]\noffline = true\n"),
                "global_rustup_config": ("settings.toml", b'version = "12"\n'),
                "unrelated_sdk": ("owner.txt", b"unrelated SDK, preserve all files and modes\n"),
                "user_data": ("notes.txt", b"unrelated user data, preserve all files and modes\n")}
    for label, root in roots.items():
        root.mkdir(mode=0o700)
        name, raw = payloads[label]
        write(root / name, raw, 0o600)
        (root / "empty-preservation-canary").mkdir(mode=0o700)
    return roots


def _published_v1_preservation_roots(legacy, guards):
    report = legacy["report"]
    return {
        "published_v1_state": Path(report["state"]),
        "published_v1_project": Path(report["project"]),
        "published_v1_build": Path(report["build"]),
        "published_v1_package_tree": Path(report["package_tree"]),
        "published_v1_home": Path(report["home"]),
        **({"published_v1_interrupted_prepare": Path(legacy["interruption"]["area"])}
           if "interruption" in legacy else {}),
        **guards,
    }


def _check_published_v1_preservation(legacy, guards, checkpoint):
    current = _preservation_snapshot(_published_v1_preservation_roots(legacy, guards))
    if current != legacy["baseline"]:
        raise ValueError("published 0.1.0 state/project/build/package/home or preservation guards changed during "
                         + checkpoint)
    archive = Path(legacy["report"]["archive"]["copy"])
    if auth.sha(auth.read(archive, cap=PUBLISHED_V1_ARCHIVE_PIN["bytes"])) != PUBLISHED_V1_ARCHIVE_PIN["sha256"]:
        raise ValueError("published 0.1.0 archive changed during " + checkpoint)
    legacy["checkpoints"].append({"name": checkpoint, "roots": current,
                                  "archive_sha256": PUBLISHED_V1_ARCHIVE_PIN["sha256"]})
    return current


def _set_active_package_root(active_root, expected_current, target):
    active_root, expected_current, target = map(Path, (active_root, expected_current, target))
    if (active_root.is_symlink() is False or not active_root.exists()
            or active_root.resolve(strict=True) != expected_current.resolve(strict=True)):
        raise ValueError("active CLI root does not resolve to the expected current package")
    if target.is_symlink() or not target.is_dir():
        raise ValueError("active CLI target must be a real package root")
    temporary = active_root.with_name(active_root.name + ".next")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("active CLI replacement link must be fresh")
    temporary.symlink_to(target.resolve(strict=True), target_is_directory=True)
    os.replace(temporary, active_root)
    if active_root.resolve(strict=True) != target.resolve(strict=True):
        raise ValueError("active CLI root did not resolve to the selected package")
    return active_root.resolve(strict=True)


def _published_v1_launcher_version(work, supervisor, active_root, label):
    launcher = Path(active_root) / "bin/ami-rust"
    if not launcher.is_file() or launcher.is_symlink():
        raise ValueError("published 0.1.0 retained launcher is missing or not a regular file")
    row = _supervised_run(supervisor, [launcher, "--version"], cwd=work,
                          label=label, timeout=60)
    raw = auth.read(Path(work) / row["stdout_log"], cap=4096)
    expected = b"ami-rust 0.1.0 (packaging 2)\n"
    if raw != expected:
        raise ValueError("published 0.1.0 retained launcher did not report its exact package identity")
    return {"launcher": str(launcher), "resolved_launcher": str(launcher.resolve(strict=True)),
            "stdout_sha256": auth.sha(raw), "version_output": raw.decode("ascii")}


def _validate_actual_published_v1_entry(report, legacy_state, legacy_project):
    old_lock = legacy_project / "ami-rust.lock.json"
    old_value = auth.parsed(auth.read(old_lock))
    old_ready = auth.parsed(auth.read(legacy_state / "ready.json"))
    old_sdk = old_value.get("sdk")
    if (old_value.get("schema") != "ami-rust-project-lock-v1"
            or type(old_sdk) is not dict or old_ready.get("schema") != "ami-rust-package-state-v1"
            or old_ready.get("status") != "READY" or old_ready.get("sdk_version") != "0.1.0"
            or old_ready.get("package_version") != "0.1.0-2"):
        raise ValueError("published setup report does not contain the actual pinned v1 project and state")
    old_sdk_root = Path(old_sdk.get("root", ""))
    expected_old_sdk = legacy_state / ("sdk-" + old_ready["sdk_version"]) / "sdk"
    if (old_sdk_root.resolve(strict=True) != expected_old_sdk.resolve(strict=True)
            or not old_sdk_root.is_dir() or old_sdk_root.is_symlink()):
        raise ValueError("published v1 project lock does not select its retained state SDK")
    manifest_relative = PurePosixPath(auth.rel(old_sdk["manifest"]))
    old_manifest = old_sdk_root.joinpath(*manifest_relative.parts)
    if auth.sha(auth.read(old_manifest)) != old_sdk.get("manifest_sha256"):
        raise ValueError("published v1 SDK manifest differs from its project lock")

    old_host = old_value.get("host")
    interpreter = report.get("interpreter")
    bootstrap = interpreter.get("verified_bootstrap") if type(interpreter) is dict else None
    relative_files = bootstrap.get("relative_files") if type(bootstrap) is dict else None
    runtime = bootstrap.get("runtime") if type(bootstrap) is dict else None
    runtime_pin = bootstrap.get("runtime_pin") if type(bootstrap) is dict else None
    runtime_relative = (relative_files.get("runtime_executable")
                        if type(relative_files) is dict else None)
    expected_runtime_relative = "runtime/python/bin/python3.12"
    expected_runtime_sha256 = interpreter.get("sha256") if type(interpreter) is dict else None
    expected_runtime_bytes = interpreter.get("bytes") if type(interpreter) is dict else None
    if (type(old_host) is not dict or type(interpreter) is not dict
            or runtime_relative != expected_runtime_relative
            or type(runtime) is not dict or runtime.get("path") != expected_runtime_relative
            or runtime.get("sha256") != expected_runtime_sha256
            or runtime.get("bytes") != expected_runtime_bytes
            or type(runtime_pin) is not dict
            or runtime_pin.get("relative_path") != "python/bin/python3.12"
            or runtime_pin.get("sha256") != expected_runtime_sha256
            or interpreter.get("pin_sha256") != expected_runtime_sha256
            or interpreter.get("pin_bytes") != expected_runtime_bytes
            or type(expected_runtime_sha256) is not str or len(expected_runtime_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_runtime_sha256)
            or type(expected_runtime_bytes) is not int or expected_runtime_bytes <= 0):
        raise ValueError("published setup report does not pin the retained v1 Python runtime layout")
    expected_old_python = (legacy_state / "ami-rust-python-bootstrap"
                           / Path(*PurePosixPath(auth.rel(runtime_relative)).parts))
    if old_host.get("python") != str(expected_old_python):
        raise ValueError("published v1 project lock does not select its retained state Python runtime")
    old_python = Path(old_host["python"])
    if old_python.is_symlink() or not old_python.is_file():
        raise ValueError("published v1 retained Python runtime is missing or not a regular file")
    if old_host.get("python_sha256") != expected_runtime_sha256:
        raise ValueError("published v1 retained Python runtime differs from its pinned setup report")
    old_python_raw = auth.read(old_python, cap=expected_runtime_bytes)
    if (len(old_python_raw) != expected_runtime_bytes
            or auth.sha(old_python_raw) != expected_runtime_sha256):
        raise ValueError("published v1 retained Python runtime differs from its pinned setup report")

    old_executable = Path(report["native_executable"]["path"])
    old_executable_raw = auth.read(old_executable)
    if (len(old_executable_raw) != report["native_executable"]["bytes"]
            or auth.sha(old_executable_raw) != report["native_executable"]["sha256"]):
        raise ValueError("published v1 native executable differs from its setup report")
    return {"old_lock": old_lock, "old_value": old_value, "old_ready": old_ready,
            "old_sdk": old_sdk, "old_sdk_root": old_sdk_root, "old_python": old_python,
            "old_executable_raw": old_executable_raw}


def _qualify_actual_published_v1_migration(work, output, state, project, frontend, supervisor,
                                            command, original_elf, guards, legacy):
    """Migrate and rebuild the real pinned 0.1.0 project with the native frontend."""
    report = legacy["report"]
    legacy_state, legacy_project = Path(report["state"]), Path(report["project"])
    entry = _validate_actual_published_v1_entry(report, legacy_state, legacy_project)
    old_lock, old_value, old_ready = entry["old_lock"], entry["old_value"], entry["old_ready"]
    old_sdk, old_sdk_root = entry["old_sdk"], entry["old_sdk_root"]
    old_python, old_executable_raw = entry["old_python"], entry["old_executable_raw"]

    legacy_before = _check_published_v1_preservation(legacy, guards, "before native migration")
    protected_inputs = {**_published_v1_preservation_roots(legacy, guards),
                        "native_ready_state": state, "native_project": project,
                        "native_first_build": Path(legacy["native_first_build"])}
    before = _preservation_snapshot(protected_inputs)
    command("20-published-v1-state-schema-refusal", ["check-inputs", "--state", legacy_state], 2,
            executable=frontend, additional_deny_exec=[old_python])
    refusal = auth.read(output / "20-published-v1-state-schema-refusal.stderr.log")
    expected_refusal = b"ami-rust: unsupported or missing schema; expected ami-rust-package-state-v2\n"
    if refusal != expected_refusal:
        raise ValueError("native frontend did not refuse the actual published v1 state at the v2 schema boundary")
    if _preservation_snapshot(_published_v1_preservation_roots(legacy, guards)) != legacy_before:
        raise ValueError("read-only native v1 state refusal changed published inputs or preservation guards")

    inspection = auth.parsed(command("20-published-v1-read-only-inspection",
        ["migrate", "--project", legacy_project, "--dry-run"], executable=frontend))
    if (inspection.get("legacy_lock", {}).get("sha256") != auth.sha(auth.read(old_lock))
            or inspection.get("legacy_python", {}).get("path") != str(old_python)
            or inspection.get("legacy_python", {}).get("sha256") != old_value["host"]["python_sha256"]
            or inspection.get("migration_required") is not True
            or _preservation_snapshot(protected_inputs) != before):
        raise ValueError("native read-only published-v1 inspection omitted its exact identities or changed protected inputs")
    prefix = state / ("sdk-" + auth.parsed(auth.read(state / "ready.json"))["sdk_version"])
    pin = auth.sha(auth.read(prefix / "install-receipt.json"))
    area = fresh(work / "published-v1-native-migration")
    migrated_parent = area / "output"
    migrated_parent.mkdir(mode=0o700)
    migrated = migrated_parent / "migrated-v2-lock.json"
    arguments = ["migrate", "--project", legacy_project, "--from-lock", old_lock,
                 "--install-prefix", prefix, "--receipt-sha256", pin, "--output", migrated]
    wrong = list(arguments)
    wrong[wrong.index("--receipt-sha256") + 1] = "0" * 64
    refused_before = _preservation_snapshot({"refused_output": migrated_parent})
    command("21-published-migration-wrong-receipt", wrong, 2, executable=frontend)
    if (_preservation_snapshot({"refused_output": migrated_parent}) != refused_before
            or migrated.exists() or migrated.is_symlink()
            or auth.read(output / "21-published-migration-wrong-receipt.stderr.log")
                != b"ami-rust: installed receipt differs from the external pin\n"):
        raise ValueError("refused published-v1 migration changed its output or missed the receipt refusal")
    result = auth.parsed(command("22-migrate-published-v1-project", arguments, executable=frontend))
    lock_bytes = auth.read(migrated)
    migrated_value = auth.parsed(lock_bytes)
    if (result.get("status") != "migrated"
            or result.get("legacy_lock_sha256") != auth.sha(auth.read(old_lock))
            or result.get("receipt_sha256") != pin
            or migrated_value.get("schema") != "ami-rust-project-lock-v2"):
        raise ValueError("native frontend did not migrate the exact published-v1 project into a separate v2 lock")
    occupied_before = _preservation_snapshot({"existing_output": migrated_parent})
    command("23-published-migration-occupied-output", arguments, 2, executable=frontend)
    if (_preservation_snapshot({"existing_output": migrated_parent}) != occupied_before
            or auth.read(migrated) != lock_bytes
            or auth.read(output / "23-published-migration-occupied-output.stderr.log")
                != b"ami-rust: output JSON path must be fresh\n"):
        raise ValueError("refused published-v1 migration changed the existing native lock")
    command("24-verify-published-migration-lock", ["verify", "--sdk-lock", migrated], executable=frontend)
    build_area = area / "build-area"
    build_area.mkdir(mode=0o700)
    build_parent = build_area / "derived"
    build_parent.mkdir(mode=0o700)
    build = build_parent / "build"
    built = auth.parsed(command("25-build-published-migrated-project", ["build", "--sdk-lock", migrated,
        "--output-dir", build, "--", "build", "--manifest-path", legacy_project / "Cargo.toml",
        "--package", "hello-aros", "--release", "--locked", "--offline"], executable=frontend))
    migrated_elf = auth.read(build / "artifacts/AMIRUST")
    if (built.get("status") != "PASS" or not (build / "build-receipt.json").is_file()
            or migrated_elf != old_executable_raw):
        raise ValueError("migrated published project did not reproduce its actual historical native executable")

    def project_material(root):
        rows = []
        total = 0
        for path in sorted(Path(root).rglob("*"), key=lambda item: item.as_posix()):
            if path.is_symlink():
                raise ValueError("published project material contains a symlink")
            if path.is_dir():
                continue
            relative = path.relative_to(root).as_posix()
            if relative == "ami-rust.lock.json":
                continue
            raw = auth.read(path, cap=16 * 1024**2)
            total += len(raw)
            if total > 64 * 1024**2 or len(rows) >= 10_000:
                raise ValueError("published project source material exceeds its comparison bound")
            rows.append({"path": relative, "bytes": len(raw), "sha256": auth.sha(raw)})
        return rows

    same_project_material = project_material(legacy_project) == project_material(project)
    if same_project_material and migrated_elf != original_elf:
        raise ValueError("identical published and native project material produced different migrated/native executables")
    after = _preservation_snapshot(protected_inputs)
    if before != after or _preservation_snapshot(_published_v1_preservation_roots(legacy, guards)) != legacy_before:
        raise ValueError("migration changed published or native inputs after its actual migrated build")
    _check_published_v1_preservation(legacy, guards, "native migration and migrated build")
    migration = {"schema": "ami-rust-published-v1-to-native-v2-transition-v1",
        "status": "PASS_ACTUAL_PUBLISHED_V1_MIGRATION_AND_EQUIVALENT_BUILD_NOT_RC1_ACCEPTANCE",
        "historical_setup_oracle": report["status"],
        "observed_consumer": "native Rust frontend only; historical Python was denied for v1 refusal and migration",
        "published_versions": report["package_version_pins"],
        "native_versions": {"cli_version": auth.parsed(auth.read(ROOT / "release/native-tooling-inputs.json"))["cli_version"],
                            "sdk_version": auth.parsed(auth.read(state / "ready.json"))["sdk_version"]},
        "legacy_state": str(legacy_state), "legacy_project": str(legacy_project),
        "legacy_lock_sha256": auth.sha(auth.read(old_lock)),
        "legacy_sdk_root": str(old_sdk_root), "legacy_sdk_manifest_sha256": old_sdk["manifest_sha256"],
        "legacy_python_path_denied": str(old_python), "v1_state_refusal_stderr_sha256": auth.sha(refusal),
        "inspection": inspection, "migration": result, "migrated_lock_sha256": auth.sha(lock_bytes),
        "migrated_build_sha256": auth.sha(migrated_elf),
        "published_build_sha256": report["native_executable"]["sha256"],
        "native_original_build_sha256": auth.sha(original_elf),
        "same_project_material_excluding_version_lock": same_project_material,
        "before": before, "after": after, "migrated_lock": str(migrated),
        "migrated_output_root": str(migrated_parent),
        "migration_area": str(area), "migrated_build_root": str(build),
        "scope": "Side-by-side published 0.1.0-2 to signed native 0.2 package migration/build evidence. This is not a package-manager or native-to-native upgrade and is not RC1 acceptance."}
    write(output / "native-public-migration.json", auth.encoded(migration))
    return migration


def _qualify_native_migration(work, output, state, project, frontend, xtask, supervisor, command, original_elf, guards, legacy=None):
    """Use published v1 inputs when supplied; keep the synthetic fallback for focused tests."""
    if legacy is not None:
        return _qualify_actual_published_v1_migration(work, output, state, project, frontend,
            supervisor, command, original_elf, guards, legacy)
    ready = auth.parsed(auth.read(state / "ready.json"))
    prefix = state / ("sdk-" + ready["sdk_version"])
    pin = auth.sha(auth.read(prefix / "install-receipt.json"))
    python_pin = auth.parsed(auth.read(ROOT / "release/ci-python-inputs.json"))["hosts"][current_host()]
    interpreter = supervisor.python_root / "runtime" / python_pin["runtime_relative_path"]
    original_protected = {"ready_state": state, "original_project": project, **guards}
    original_before = _preservation_snapshot(original_protected)
    area = work / "native-legacy-migration-fixture"
    generated = _supervised_run(supervisor, [xtask, "native-legacy-migration-fixture",
        "--install-prefix", prefix, "--selection", state / "selection.json", "--python", interpreter,
        "--project", project, "--output", area], cwd=work, label="20-compose-compatible-legacy-data")
    if _preservation_snapshot(original_protected) != original_before:
        raise ValueError("migration fixture generation changed existing inputs or retained data")
    fixture = auth.parsed(auth.read(work / generated["stdout_log"]))
    legacy_project, legacy_sdk = area / "project", area / "legacy-sdk"
    old_lock, migrated = legacy_project / "ami-rust.lock.json", area / "output/migrated-v2-lock.json"
    if (fixture.get("status") != "SYNTHETIC_BASELINE_COMPATIBLE_FIXTURE_NOT_HISTORICAL_EVIDENCE"
            or fixture.get("project") != str(legacy_project)
            or fixture.get("from_lock") != str(old_lock)
            or fixture.get("migration_output") != str(migrated)
            or fixture.get("receipt_pin", {}).get("sha256") != pin):
        raise ValueError("native migration fixture omitted its exact synthetic input identity")
    legacy_protected = {"legacy_project": legacy_project, "legacy_sdk": legacy_sdk}
    protected = {**original_protected, **legacy_protected}
    before = {**original_before, **_preservation_snapshot(legacy_protected)}
    arguments = ["migrate", "--project", legacy_project, "--from-lock", old_lock,
                 "--install-prefix", prefix, "--receipt-sha256", pin, "--output", migrated]
    wrong = list(arguments)
    wrong[wrong.index("--receipt-sha256") + 1] = "0" * 64
    refused_before = _preservation_snapshot({"refused_output": migrated.parent})
    command("21-migration-wrong-receipt", wrong, 2, executable=frontend)
    if (_preservation_snapshot({"refused_output": migrated.parent}) != refused_before
            or migrated.exists() or migrated.is_symlink()
            or auth.read(output / "21-migration-wrong-receipt.stderr.log")
                != b"ami-rust: installed receipt differs from the external pin\n"):
        raise ValueError("refused migration changed its output area or missed the receipt-pin refusal")
    result = auth.parsed(command("22-public-legacy-migration", arguments, executable=frontend))
    lock_bytes = auth.read(migrated)
    if (result.get("status") != "migrated" or result.get("legacy_lock_sha256") != auth.sha(auth.read(old_lock))
            or result.get("receipt_sha256") != pin
            or auth.parsed(lock_bytes).get("schema") != "ami-rust-project-lock-v2"):
        raise ValueError("public migration did not publish the selected separate native v2 lock")
    occupied_before = _preservation_snapshot({"existing_output": migrated.parent})
    command("23-migration-occupied-output", arguments, 2, executable=frontend)
    if (_preservation_snapshot({"existing_output": migrated.parent}) != occupied_before
            or auth.read(migrated) != lock_bytes
            or auth.read(output / "23-migration-occupied-output.stderr.log")
                != b"ami-rust: output JSON path must be fresh\n"):
        raise ValueError("refused migration changed the existing native lock")
    command("24-verify-migrated-lock", ["verify", "--sdk-lock", migrated], executable=frontend)
    build_area = work / "native-migration-build"
    build_area.mkdir(mode=0o700)
    build_parent = build_area / "derived"
    build_parent.mkdir(mode=0o700)
    build = build_parent / "build"
    built = auth.parsed(command("25-build-migrated-project", ["build", "--sdk-lock", migrated,
        "--output-dir", build, "--", "build", "--manifest-path", legacy_project / "Cargo.toml",
        "--package", "hello-aros", "--release", "--locked", "--offline"], executable=frontend))
    if (built.get("status") != "PASS" or not (build / "build-receipt.json").is_file()
            or auth.read(build / "artifacts/AMIRUST") != original_elf):
        raise ValueError("migrated project did not reproduce the original native executable")
    after = _preservation_snapshot(protected)
    if before != after:
        raise ValueError("migration or migrated build changed old inputs or the current ready installation")
    report = {"schema": "ami-rust-public-native-migration-effects-v1",
              "status": "PASS_PUBLIC_MIGRATION_AND_EQUIVALENT_BUILD",
              "fixture": fixture, "before": before, "after": after,
              "migrated_lock_sha256": auth.sha(lock_bytes), "native_executable_sha256": auth.sha(original_elf),
              "scope": "Actual public Rust commands under observation; legacy metadata is synthetic compatibility data against real installed baseline inputs. Historical release migration remains separate."}
    write(output / "native-public-migration.json", auth.encoded(report))
    return report


def _prepare_state_owner(state):
    """Measure the actual partial-state root, never infer ownership from a report."""
    info = Path(state).lstat()
    private = (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
               and stat.S_IMODE(info.st_mode) == 0o700 and os.getuid() != 0)
    if not private:
        raise ValueError("interrupted prepare state must be private and owned by the current user")
    return {"uid": info.st_uid, "mode": stat.S_IMODE(info.st_mode),
            "private_current_user": True}


def _unpublished_prepare_state(state):
    """Neither interrupted source fetch may publish an installation or READY."""
    forbidden = {"READY", "ready.json", "receipt.sha256", "selection.json",
                 "ami-rust-python-bootstrap"}
    entries = sorted(entry.name for entry in state.iterdir()
                     if entry.name in forbidden or entry.name.startswith("sdk-"))
    if entries:
        raise ValueError("interrupted source fetch published later-stage entries: " + repr(entries))
    return {"ready_absent": True, "installation_prefix_absent": True,
            "installation_receipt_absent": True, "selection_absent": True,
            "python_bootstrap_absent": True}


def _preserve_prepare_captures(driver, destination, names):
    """Keep fixed, bounded raw files even when a driver or its validation fails."""
    if not driver.exists() and not driver.is_symlink():
        return
    if not stat.S_ISDIR(driver.lstat().st_mode):
        raise ValueError("prepare capture root must be a real directory")
    destination.mkdir(mode=0o700)
    for name in names:
        source = driver / name
        if source.exists() or source.is_symlink():
            write(destination / name, auth.read(source, cap=16 * 1024**2), 0o600)


def _validate_historical_prepare_capture(driver, summary, interpreter, cli, state, published):
    report_path = driver / "preparation-capture.json"
    report = auth.parsed(auth.read(report_path))
    command, observation = report.get("command", {}), report.get("observation", {})
    capture, post = report.get("capture", {}), report.get("post_capture", {})
    expected_argv = ["-I", "-B", str(cli), "prepare", "--state", str(state)]
    if (summary.get("status") != "OBSERVED_FETCH_STAGE_SIGTERM"
            or summary.get("report") != str(report_path)
            or report.get("status") != "OBSERVED_FETCH_STAGE_SIGTERM"
            or command.get("program") != str(interpreter) or command.get("argv") != expected_argv
            or command.get("python_sha256") != published["interpreter"]["sha256"]
            or command.get("frontend_sha256") != published["historical_cli_sha256"]):
        raise ValueError("historical interruption omitted its exact checked command identities")
    if (observation.get("attempted") is not True or observation.get("signal_sent") is not True
            or observation.get("direct_child_raw_signal") != 15
            or observation.get("direct_child_exit_code") is not None
            or observation.get("shell_convention_status") != 143
            or observation.get("shell_was_invoked") is not False
            or observation.get("helper_interrupted") is not False
            or observation.get("helper_signal_error") is not None
            or any(observation.get(key) is not None for key in
                   ("signal_error", "scan_error", "later_stage"))):
        raise ValueError("historical interruption omitted the actual direct-child SIGTERM")
    marker = observation.get("fetch_head_at_signal", {})
    if (marker.get("path") != str(state / "source/.git/FETCH_HEAD")
            or marker.get("regular_file") is not True or marker.get("size_bytes") != 0
            or marker.get("uid") != os.getuid()
            or any(marker.get(key) is not True for key in
                   ("READY_absent", "ci_python_absent", "index_absent", "ready_json_absent"))
            or any(post.get(key) is not False for key in
                   ("READY_present", "ci_python_present", "git_index_present", "ready_json_present"))
            or post.get("later_stage_markers") != []):
        raise ValueError("historical interruption did not establish the pre-checkout fetch stage")
    accepted = capture.get("accepted_path")
    proper_path = (
        accepted == "DescendantRetainedPipe-cleaned-and-reaped"
        and capture.get("result") == "capture-error"
        and capture.get("cause") == "DescendantRetainedPipe"
    ) or (
        accepted == "CapturedProcess-raw-SIGTERM-reaped"
        and capture.get("result") == "captured-normal" and capture.get("cause") is None
    )
    if (not proper_path or capture.get("cleanup_error") is not None
            or capture.get("cleanup_outcome") != "accepted-path-with-no-reported-cleanup-error"):
        raise ValueError("historical interruption did not establish clean capture/reaping")
    for stream in ("stdout", "stderr"):
        raw = auth.read(driver / ("prepare." + stream + ".raw"), cap=16 * 1024**2)
        row = capture.get(stream, {})
        if (row.get("path") != "prepare." + stream + ".raw"
                or row.get("bytes") != len(raw) or row.get("sha256") != auth.sha(raw)):
            raise ValueError("historical prepare capture differs from its actual bytes")
    return report


def _qualify_historical_prepare_interruption(work, output, xtask, supervisor, published):
    """Transitional published-Python oracle, outside new-consumer observations."""
    area = fresh(work / "published-interrupted-prepare-area")
    parent, home, tmp = area / "state-parent", area / "home", area / "tmp"
    for directory in (parent, home, tmp):
        directory.mkdir(mode=0o700)
    state, driver = parent / "state", area / "driver-output"
    sibling = parent / "unrelated-user-data.bin"
    sentinel = b"preserve historical interrupted-prepare sibling\n"
    write(sibling, sentinel, 0o600)
    cli = Path(published["package_root"]) / "cli.py"
    # The published Python archive preserves a group-writable executable.
    # Harden an isolated, byte-identical copy; never alter historical inputs.
    runtime_source = Path(published["interpreter"]["root"]) / "runtime/python"
    interpreter_relative = Path(published["interpreter"]["path"]).relative_to(runtime_source)
    runtime = area / "python-runtime"
    shutil.copytree(runtime_source, runtime, symlinks=True)
    runtime.chmod(0o700)
    interpreter = runtime / interpreter_relative
    if not stat.S_ISREG(interpreter.lstat().st_mode):
        raise ValueError("historical probe interpreter must be a real regular file")
    interpreter.chmod(0o755)
    if auth.sha(auth.read(interpreter, cap=128 * 1024**2)) != published["interpreter"]["sha256"]:
        raise ValueError("private historical interpreter copy differs from the pinned bytes")
    report = {"schema": "ami-rust-historical-prepare-interruption-effects-v1", "status": "RUNNING",
              "host": current_host(), "area": str(area), "state": str(state),
              "runtime_root": str(runtime),
              "interpreter_copy": {"original": published["interpreter"]["path"],
                  "copy": str(interpreter), "sha256": published["interpreter"]["sha256"],
                  "original_mode": stat.S_IMODE(Path(published["interpreter"]["path"]).lstat().st_mode),
                  "copy_mode": stat.S_IMODE(interpreter.lstat().st_mode)},
              "scope": "Actual historical Python half only; not new-consumer no-Python or RC1 acceptance."}
    original_env = supervisor.env
    try:
        supervisor.env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home),
                          "TMPDIR": str(tmp), "LC_ALL": "C"}
        _supervised_run(supervisor, [interpreter, "-I", "-B", cli, "verify-package"],
                        label="09-published-prepare-original-verify", cwd=area)
        row = _supervised_run(supervisor, [xtask, "historical-prepare-interruption",
            "--python", interpreter, "--frontend", cli, "--state", state,
            "--home", home, "--tmp", tmp, "--cwd", area, "--output", driver],
            label="09-published-prepare-sigterm", cwd=area)
        summary = auth.parsed(auth.read(work / row["stdout_log"]))
        captured = _validate_historical_prepare_capture(driver, summary, interpreter, cli,
                                                        state, published)
        owner = _prepare_state_owner(state)
        unpublished = _unpublished_prepare_state(state)
        if (state / "prepare-failure.json").exists() or (state / "prepare-failure.json").is_symlink():
            raise ValueError("historical interrupted state unexpectedly contains a new failure receipt")
        retained_cli = state / "retained/libexec/ami-rust/0.1.0-2/cli.py"
        _supervised_run(supervisor, [interpreter, "-I", "-B", retained_cli, "verify-package"],
                        label="09-published-prepare-retained-verify", cwd=area)
        before = _retained_state_snapshot(state)
        sibling_before = _retained_state_snapshot(parent)
        retry = _supervised_run(supervisor, [interpreter, "-I", "-B", cli, "prepare", "--state", state],
                               label="09-published-prepare-retry-refusal", cwd=area, expected=2)
        refusal = auth.read(work / retry["stderr_log"])
        if refusal != (b"ami-rust: preparation requires a fresh state; "
                       b"failed states are retained for diagnosis\n"):
            raise ValueError("historical retry missed its real fresh-state refusal")
        after = _retained_state_snapshot(state)
        if (before != after or sibling_before != _retained_state_snapshot(parent)
                or auth.read(sibling) != sentinel):
            raise ValueError("historical prepare retry changed retained ownership, bytes or sibling data")
        report.update(status="PASS_ACTUAL_HISTORICAL_PREPARE_INTERRUPTION",
            driver=captured, state_owner=owner, retry_exit_code=retry["exit_code"],
            state_snapshot=before, state_snapshot_sha256=auth.sha(auth.encoded(before)),
            retry_state_snapshot_sha256=auth.sha(auth.encoded(after)),
            retained_package_consistent=True, unpublished=unpublished, failure_receipt=None,
            package=published["package_version_pins"],
            retry_refusal_sha256=auth.sha(refusal), unrelated_sibling_sha256=auth.sha(sentinel))
        _check_limits(supervisor, "completed actual historical prepare interruption")
        return report
    except Exception as error:
        report.update(status="FAIL", error=repr(error))
        raise
    finally:
        supervisor.env = original_env
        try:
            _preserve_prepare_captures(driver, output / "historical-prepare-interruption-captures",
                                      ("preparation-capture.json", "prepare.stdout.raw", "prepare.stderr.raw"))
        except Exception as error:
            report.update(status="FAIL", capture_preservation_error=repr(error))
            raise
        finally:
            write(output / "historical-prepare-interruption.json", auth.encoded(report), 0o600)


def _qualify_prepare_interruption(work, output, frontend, xtask, command):
    """Observe an actual public prepare SIGTERM, then verify retained effects."""
    area = work / "native-interrupted-prepare-area"
    area.mkdir(mode=0o700)
    parent = area / "derived"
    parent.mkdir(mode=0o700)
    state, driver = parent / "state", area / "driver-output"
    sibling = area / "unrelated-user-data.bin"
    sentinel = b"preserve interrupted-prepare sibling\n"
    write(sibling, sentinel)
    effects = {"schema": "ami-rust-public-prepare-interruption-effects-v1", "status": "RUNNING"}
    try:
        return _native_prepare_interruption_effects(work, output, frontend, xtask, command,
                                                   state, driver, sibling, sentinel, effects)
    except Exception as error:
        effects.update(status="FAIL", error=repr(error))
        raise
    finally:
        try:
            _preserve_prepare_captures(driver, output / "native-prepare-interruption-captures",
                                      ("report.json", "stdout.raw", "stderr.raw", "prepare-failure.json"))
        except Exception as error:
            effects.update(status="FAIL", capture_preservation_error=repr(error))
            raise
        finally:
            write(output / "native-prepare-interruption.json", auth.encoded(effects), 0o600)


def _native_prepare_interruption_effects(work, output, frontend, xtask, command,
                                       state, driver, sibling, sentinel, effects):
    result = auth.parsed(command("09-public-prepare-sigterm", ["native-prepare-interruption",
        "--frontend", frontend, "--state", state, "--home", work / "home",
        "--tmp", work / "tmp", "--output", driver], executable=xtask))
    report = auth.parsed(auth.read(driver / "report.json"))
    if (result.get("actual_child_exit_code") != 143 or result.get("helper_exit_code") != 0
            or report.get("status") != "OBSERVED_EXPECTED_PREPARE_INTERRUPTION"
            or report.get("capture", {}).get("actual_child_exit_code") != 143
            or report.get("capture", {}).get("actual_child_signal") is not None
            or report.get("capture", {}).get("error") is not None
            or report.get("launcher", {}).get("sha256") != auth.sha(auth.read(frontend))
            or report.get("signal", {}).get("sent") is not True
            or report.get("signal", {}).get("helper_interrupted") is not False
            or any(report.get("signal", {}).get(key) is not None
                   for key in ("error", "scan_error", "helper_signal_error"))):
        raise ValueError("public prepare interruption omitted its actual status or retained effects")
    owner, unpublished = _prepare_state_owner(state), _unpublished_prepare_state(state)
    failure_raw = auth.read(state / "prepare-failure.json")
    failure = auth.parsed(failure_raw)
    if (failure.get("schema") != "ami-rust-prepare-failure-v1"
            or failure.get("phase") != "source-checkout"
            or failure.get("ready") is not False or failure.get("state_retained") is not True):
        raise ValueError("native interruption omitted its valid pre-publication failure receipt")
    write(driver / "prepare-failure.json", failure_raw, 0o600)
    for stream in ("stdout", "stderr"):
        raw = auth.read(driver / (stream + ".raw"))
        row = report["capture"][stream]
        if len(raw) != row["bytes"] or auth.sha(raw) != row["sha256"]:
            raise ValueError("prepare interruption capture differs from its actual bytes")
    retained = state / "retained/bin/ami-rust"
    command("09-interrupted-retained-package-consistency", ["verify-package"], executable=retained)
    before = _retained_state_snapshot(state)
    area_before = _retained_state_snapshot(state.parent.parent)
    command("09-interrupted-state-retry-refusal", ["prepare", "--state", state], 2,
        executable=frontend, disposable_refusal_state=state)
    refusal = auth.read(output / "09-interrupted-state-retry-refusal.stderr.log")
    if refusal != b"ami-rust: state path must be fresh\n":
        raise ValueError("interrupted-state retry did not reach the native fresh-state refusal")
    after = _retained_state_snapshot(state)
    if (after != before or _retained_state_snapshot(state.parent.parent) != area_before
            or auth.read(sibling) != sentinel):
        raise ValueError("interrupted prepare retry changed retained ownership, bytes or sibling data")
    effects.update({"status": "PASS_ACTUAL_CLI_SIGTERM_RETAINED_STATE_AND_UNCHANGED_RETRY",
        "driver": report, "state_snapshot": before,
        "state_snapshot_sha256": auth.sha(auth.encoded(before)),
        "retry_state_snapshot_sha256": auth.sha(auth.encoded(after)),
        "state_owner": owner, "unpublished": unpublished,
        "failure_receipt": {"sha256": auth.sha(failure_raw), "record": failure},
        "retry_exit_code": 2, "retained_package_consistent": True,
        "retry_state_write_authority": "exact disposable partial state; no derived execution",
        "retry_refusal_sha256": auth.sha(refusal),
        "unrelated_sibling_sha256": auth.sha(sentinel),
        "scope": "Source-checkout interruption only; installation publication recovery is a separate case."})
    return effects


def _compare_prepare_interruptions(historical, native, identity, config):
    """Compare visible semantics; raw SIGTERM and handled exit 143 are distinct."""
    expected = ("PASS_ACTUAL_HISTORICAL_PREPARE_INTERRUPTION",
                "PASS_ACTUAL_CLI_SIGTERM_RETAINED_STATE_AND_UNCHANGED_RETRY")
    refusals = (b"ami-rust: preparation requires a fresh state; failed states are retained for diagnosis\n",
                b"ami-rust: state path must be fresh\n")
    for half, status, refusal in zip((historical, native), expected, refusals):
        owner = half.get("state_owner", {})
        unpublished = half.get("unpublished", {})
        if (half.get("status") != status or half.get("retry_exit_code") != 2
                or half.get("retained_package_consistent") is not True
                or owner != {"uid": os.getuid(), "mode": 0o700, "private_current_user": True}
                or unpublished != {"ready_absent": True, "installation_prefix_absent": True,
                                   "installation_receipt_absent": True, "selection_absent": True,
                                   "python_bootstrap_absent": True}
                or half.get("state_snapshot_sha256") != auth.sha(auth.encoded(half.get("state_snapshot")))
                or half.get("retry_state_snapshot_sha256") != half.get("state_snapshot_sha256")
                or half.get("retry_refusal_sha256") != auth.sha(refusal)):
            raise ValueError("prepare interruption pair lacks a validated half or preserved visible effects")
    old = historical["driver"]["observation"]
    new = native["driver"]["capture"]
    package = native["driver"]["package"]
    if (old.get("direct_child_raw_signal") != 15 or old.get("direct_child_exit_code") is not None
            or old.get("shell_convention_status") != 143 or old.get("shell_was_invoked") is not False
            or new.get("actual_child_exit_code") != 143 or new.get("actual_child_signal") is not None
            or historical.get("failure_receipt") is not None
            or not native.get("failure_receipt")
            or package.get("source_commit") != identity["source_sha"]
            or package.get("host") != current_host()
            or package.get("sdk_version") != config["sdk_version"]
            or package.get("cli_version") != config["cli_version"]):
        raise ValueError("prepare interruption pair lost its signal distinction or current package identity")
    return {"schema": "ami-rust-prepare-interruption-comparison-v1",
            "status": "PASS_ACTUAL_HOST_PREPARE_INTERRUPTION_SEMANTIC_PAIR",
            "host": current_host(), "native_package": package,
            "historical_package": historical["package"],
            "historical_effects_sha256": auth.sha(auth.encoded(historical)),
            "native_effects_sha256": auth.sha(auth.encoded(native)),
            "shared_effects": historical["unpublished"],
            "deliberate_differences": {
                "stage_witnesses": "Historical: empty FETCH_HEAD before checkout/bootstrap; Rust: active source-fetch command directory. Neither witness observes Git argv or its PID.",
                "termination": "Published Python: raw SIGTERM 15, no exit code; Rust: handled exit 143, no raw signal.",
                "diagnostics": "Both refuse retry with exit 2; each retains its version-specific diagnostic.",
                "failure_receipt": "Published Python writes no receipt; Rust retains a source-checkout failure receipt.",
                "source": "Each release uses its authentic source pin; the two source commits need not match."},
            "scope": "One host, actual CLI interruptions at separately witnessed pre-checkout source-fetch stages. Both-host protected SDK and complete RC1 acceptance remain separate."}


def _qualify_native_package(work, output, outer, bundle, cli, xtask, supervisor, policy_path, identity, config, command,
                            upgrade_outer, upgrade_bundle):
    """Exercise the actual packaged frontend and retained replay on signed inputs."""
    metadata = outer / "metadata"
    outer_report = auth.parsed(auth.read(metadata / "outer-verification.json"))
    if (outer_report.get("status") != "OUTER_CRYPTO_VERIFIED_NOT_R1_ACCEPTED"
            or outer_report.get("source_commit") != identity["source_sha"]
            or type(outer_report.get("run_id")) is not int
            or type(outer_report.get("run_attempt")) is not int
            or outer_report.get("run_id") != identity["run_id"]
            or outer_report.get("run_attempt") != identity["run_attempt"]):
        raise ValueError("outer producer receipt differs from the protected source/run")
    pins_path = metadata / ("native-package-inputs-" + current_host() + ".json")
    pins = auth.parsed(auth.read(pins_path))
    if (pins.get("source_commit") != identity["source_sha"]
            or type(pins.get("sdk_run_id")) is not int
            or type(pins.get("sdk_run_attempt")) is not int
            or pins.get("sdk_run_id") != identity["run_id"]
            or pins.get("sdk_run_attempt") != identity["run_attempt"]
            or pins.get("host") != current_host()
            or pins.get("cli_version") != config["cli_version"]
            or pins.get("sdk_version") != config["sdk_version"]):
        raise ValueError("native package inputs differ from source/run/host/version")
    notices = work / "native-package-notices"
    notices.mkdir(mode=0o700)
    for name in ("LICENSE-MIT", "LICENSE-APACHE"):
        write(notices / name, auth.read(ROOT / name))
    write(notices / "THIRD-PARTY-NOTICES.md", auth.read(ROOT / "tooling/third-party/THIRD-PARTY-NOTICES.md"))
    shutil.copytree(ROOT / "tooling/third-party/licenses", notices / "licenses")
    package = work / "native-package"
    _supervised_run(supervisor, [xtask, "native-package", "--pins", pins_path,
        "--proof-index", metadata / "native-package-proofs.json", "--launcher", cli,
        "--assets", outer / "candidate", "--proofs", metadata / "gh",
        "--notices", notices, "--output", package], label="native-consumer-compose-package")
    frontend = package / "bin/ami-rust"
    command("09-package-consistency", ["verify-package"], executable=frontend)
    authentication_area = work / "native-package-authentication-area"
    authentication_area.mkdir(mode=0o700)
    authentication = auth.parsed(command("09-package-publisher-authentication", ["native-package-verify", "--package", package,
        "--policy", policy_path, "--inputs", bundle / ".auth/inputs.json",
        "--work", authentication_area / "work"], executable=xtask))
    if authentication.get("status") != "OUTER_AND_INNER_AUTHENTICATED":
        raise ValueError("native package outer/inner authentication did not complete")

    # Preserve a genuine published 0.1.0 rollback population before any new
    # consumer prepare/interruption command. Its historical Python is setup
    # evidence only, including its separately observed interruption below.
    guards = _retained_preservation_guards(work)
    archive = _download_published_v1_archive(work, supervisor)
    legacy_report = _prepare_published_legacy(work, output, supervisor, archive)
    if legacy_report.get("status") != "PASS_ACTUAL_PUBLISHED_V1_SETUP_ORACLE_NOT_RC1_ACCEPTANCE":
        raise ValueError("published 0.1.0 rollback setup did not complete through its actual historical package")
    historical_interruption = _qualify_historical_prepare_interruption(
        work, output, xtask, supervisor, legacy_report)
    # Every new consumer command from this point shares the same excluded
    # historical runtime, including migrated-lock verification and builds.
    observed_command = command
    inert_runtimes = (Path(legacy_report["state"]) / "ami-rust-python-bootstrap/runtime/python",
                      Path(historical_interruption["runtime_root"]))
    cold_runtime_reference = None

    def command(label, arguments, expected=0, **options):
        return observed_command(label, arguments, expected,
                                inert_python_roots=inert_runtimes,
                                cold_runtime_reference=cold_runtime_reference, **options)

    legacy = {"report": legacy_report, "interruption": historical_interruption, "checkpoints": []}
    legacy_roots = _published_v1_preservation_roots(legacy, guards)
    legacy["baseline"] = _preservation_snapshot(legacy_roots)
    archive_copy = Path(legacy_report["archive"]["copy"])
    if auth.sha(auth.read(archive_copy, cap=PUBLISHED_V1_ARCHIVE_PIN["bytes"])) != PUBLISHED_V1_ARCHIVE_PIN["sha256"]:
        raise ValueError("published 0.1.0 rollback setup did not retain the exact package archive")
    legacy["checkpoints"].append({"name": "before-new-consumer-observations",
        "roots": legacy["baseline"], "archive_sha256": PUBLISHED_V1_ARCHIVE_PIN["sha256"]})

    active_root = work / "active-cli"
    old_root = Path(legacy_report["retained_root"])
    if active_root.exists() or active_root.is_symlink() or old_root.is_symlink() or not old_root.is_dir():
        raise ValueError("private active CLI selector or published retained root is not fresh and regular")
    selector_roots = {**legacy_roots, "native_package": package}
    selector_before = _preservation_snapshot(selector_roots)
    active_root.symlink_to(old_root.resolve(strict=True), target_is_directory=True)
    if active_root.resolve(strict=True) != old_root.resolve(strict=True):
        raise ValueError("initial active CLI root does not select the actual published retained launcher")
    if _preservation_snapshot(selector_roots) != selector_before:
        raise ValueError("initial active CLI selection changed published or native package inputs")
    old_version_before = _published_v1_launcher_version(
        work, supervisor, active_root, "published-v1-active-cli-version-before-native")
    _check_published_v1_preservation(legacy, guards, "published retained launcher identity check")

    state_write_area = work / "native-state-write-area"
    state_write_area.mkdir(mode=0o700)
    state_parent = state_write_area / "derived"
    state_parent.mkdir(mode=0o700)
    state = state_parent / "native-ready-state"
    if current_host() == "linux-x86_64":
        inspection = auth.parsed(command("09-cold-runtime-reference-inspection",
            ["migrate", "--project", legacy_report["project"], "--dry-run"], executable=frontend))
        cold_runtime_reference = _validated_cold_runtime_reference(legacy_report, bundle, inspection,
            (work / "home", work / "tmp", state_write_area), inert_runtimes)
        write(output / "native-cold-runtime-reference.json", auth.encoded({
            "schema": "ami-rust-cold-native-runtime-reference-v1", "binding": cold_runtime_reference,
            "compiler": inspection["compiler"], "components": inspection["components"],
            "candidate_manifest_sha256": auth.sha(auth.read(bundle / "release.json")),
            "claim": "Validated same native component inventories for bounded host runtime discovery only; new preparation remains cold and separate."}))
        _check_published_v1_preservation(legacy, guards, "validated cold runtime reference")
    prepared = auth.parsed(command("10-package-cold-prepare", ["prepare", "--state", state], executable=frontend))
    if prepared.get("status") != "READY":
        raise ValueError("native package preparation did not produce READY")
    ready = auth.read(state / "ready.json")
    command("11-package-warm-recheck", ["check-inputs", "--state", state], executable=frontend)
    command("12-occupied-state-refusal", ["prepare", "--state", state], 2, executable=frontend)
    if auth.read(state / "ready.json") != ready:
        raise ValueError("occupied-state preparation changed the accepted READY record")
    project_area = work / "native-project-write-area"
    project_area.mkdir(mode=0o700)
    project = project_area / "native-client-project"
    command("13-new-client-project", ["new", "--state", state, "--project", project], executable=frontend)
    first_write_area = work / "native-client-build"
    first_write_area.mkdir(mode=0o700)
    first_parent = first_write_area / "derived"
    first_parent.mkdir(mode=0o700)
    first = first_parent / "build"
    built = auth.parsed(command("14-package-offline-build", ["build", "--state", state,
        "--project", project, "--output-dir", first], executable=frontend))
    if built.get("status") != "PASS" or not (first / "build-receipt.json").is_file():
        raise ValueError("native packaged build omitted its PASS receipt")
    original_elf = auth.read(first / "artifacts/AMIRUST")
    _check_published_v1_preservation(legacy, guards, "native cold prepare and first project build")

    # Bind a private global selector to the new package, and use its resolved
    # canonical launcher for subsequent observed operations, including SIGTERM.
    selector_roots = {**legacy_roots, "native_package": package,
                      "native_ready_state": state, "native_project": project,
                      "native_first_build": first}
    selector_before_activation = _preservation_snapshot(selector_roots)
    selected_root = _set_active_package_root(active_root, old_root, package)
    frontend = (active_root / "bin/ami-rust").resolve(strict=True)
    if frontend != (package / "bin/ami-rust").resolve(strict=True):
        raise ValueError("active CLI root does not resolve to the exact native package launcher")
    selector_after_activation = _preservation_snapshot(selector_roots)
    if selector_before_activation != selector_after_activation:
        raise ValueError("native package activation changed old or new state, project, build, or preservation data")
    activation = [{"action": "initial-published-retained-root", "selector": str(active_root),
                   "resolved_root": str(old_root.resolve(strict=True)),
                   "launcher": old_version_before},
                  {"action": "activate-native-package", "selector": str(active_root),
                   "previous_root": str(old_root.resolve(strict=True)),
                   "selected_root": str(selected_root), "resolved_launcher": str(frontend),
                   "preservation_before": selector_before_activation,
                   "preservation_after": selector_after_activation}]

    interruption = _qualify_prepare_interruption(work, output, frontend, xtask, command)
    interruption_pair = _compare_prepare_interruptions(historical_interruption, interruption, identity, config)
    write(output / "prepare-interruption-comparison.json", auth.encoded(interruption_pair))
    _check_published_v1_preservation(legacy, guards, "new native prepare interruption and refusal")
    native_matrix = _qualify_native_build_matrix(
        work, state, frontend, output, supervisor, config, command)
    # A later retained-launcher failure must not discard the completed matrix.
    write(output / "native-build-matrix.json", auth.encoded(native_matrix))
    _check_limits(supervisor, "preserved completed native build matrix")
    _check_published_v1_preservation(legacy, guards, "native build matrix")
    legacy["native_first_build"] = str(first)
    migration = _qualify_native_migration(
        work, output, state, project, frontend, xtask, supervisor, command, original_elf, guards, legacy=legacy)
    _check_published_v1_preservation(legacy, guards, "native migration and migrated build")

    rollback_roots = {**selector_roots,
                      "native_migration_area": Path(migration["migration_area"])}
    selector_before_rollback = _preservation_snapshot(rollback_roots)
    rolled_back_root = _set_active_package_root(active_root, package, old_root)
    if rolled_back_root != old_root.resolve(strict=True):
        raise ValueError("active CLI rollback does not resolve to the published retained 0.1.0 root")
    selector_after_rollback = _preservation_snapshot(rollback_roots)
    if selector_before_rollback != selector_after_rollback:
        raise ValueError("active CLI rollback changed old or new state, project, build, migration, or package data")
    old_version_after = _published_v1_launcher_version(
        work, supervisor, active_root, "published-v1-active-cli-version-after-rollback")
    activation.append({"action": "rollback-to-published-retained-root", "selector": str(active_root),
                      "previous_root": str(package.resolve(strict=True)),
                      "selected_root": str(rolled_back_root),
                      "resolved_launcher": str(active_root / "bin/ami-rust"),
                      "launcher": old_version_after,
                      "preservation_before": selector_before_rollback,
                      "preservation_after": selector_after_rollback})
    _check_published_v1_preservation(legacy, guards, "active CLI rollback")

    marker = work / "unrelated-user-file.txt"
    write(marker, b"preserve across package removal\n")
    protected = {"ready_state_and_retained_tooling": state, "native_project": project,
                 "native_first_build": first, "native_migration_area": Path(migration["migration_area"]),
                 **legacy_roots}
    before_removal = _preservation_snapshot(protected)
    package_before_removal = _preservation_snapshot({"native_package": package})
    shutil.rmtree(package)
    if package.exists() or package.is_symlink() or active_root.resolve(strict=True) != old_root.resolve(strict=True):
        raise ValueError("native package removal changed the rolled-back selector or retained a package root")
    retained = state / "retained/bin/ami-rust"
    if not retained.is_file() or auth.read(state / "ready.json") != ready:
        raise ValueError("native package removal did not preserve retained tooling and state")
    command("15-retained-input-recheck", ["check-inputs", "--state", state], executable=retained)
    replay_write_area = work / "native-retained-build"
    replay_write_area.mkdir(mode=0o700)
    replay_parent = replay_write_area / "derived"
    replay_parent.mkdir(mode=0o700)
    replay = replay_parent / "build"
    repeated = auth.parsed(command("16-retained-offline-replay", ["build", "--state", state,
        "--project", project, "--output-dir", replay], executable=retained))
    if (repeated.get("status") != "PASS" or auth.read(replay / "artifacts/AMIRUST") != original_elf
            or auth.read(marker) != b"preserve across package removal\n"):
        raise ValueError("retained replay changed native output or unrelated user data")
    after_removal = _preservation_snapshot(protected)
    if after_removal != before_removal:
        raise ValueError("package removal or retained replay changed protected state/project/global config/SDK/user data")
    _check_published_v1_preservation(legacy, guards, "native package removal and retained replay")
    preservation = {"schema": "ami-rust-published-v1-native-retained-removal-preservation-v1",
                    "status": "PASS_COMPLETE_RETAINED_REMOVAL_PRESERVATION",
                    "before": before_removal, "after": after_removal,
                    "native_package_before_removal": package_before_removal,
                    "active_cli_transitions": activation,
                    "published_v1_preservation_checkpoints": legacy["checkpoints"],
                    "scope": "Side-by-side published 0.1.0-2 to native 0.2 package activation/rollback/removal and retained replay. This is not a package-manager or native-to-native upgrade."}
    write(output / "native-retained-removal-preservation.json", auth.encoded(preservation))
    transition = {"schema": "ami-rust-published-v1-native-package-transition-v1",
        "status": "PASS_SIDE_BY_SIDE_PUBLISHED_0_1_TO_NATIVE_0_2_TRANSITION_NOT_RC1_ACCEPTANCE",
        "historical_setup_oracle": legacy_report,
        "active_cli": {"selector": str(active_root), "transitions": activation,
                       "published_version_before_native": old_version_before,
                       "published_version_after_rollback": old_version_after,
                       "native_frontend": str(frontend),
                       "native_package_version": pins["package_version"],
                       "native_cli_version": pins["cli_version"]},
        "preservation_checkpoints": legacy["checkpoints"],
        "scope": "Private side-by-side published 0.1.0-2 to native 0.2 transition and removal. No package manager, native-to-native upgrade, or RC1 acceptance claim."}
    write(output / "native-published-v1-transition.json", auth.encoded(transition))
    upgrade = _qualify_native_upgrade(work, output, upgrade_outer, upgrade_bundle, outer, bundle,
        state, project, first, original_elf, xtask, cli, supervisor, policy_path, command,
        protected, notices, pins)
    _check_published_v1_preservation(legacy, guards, "native-to-native package upgrade")
    return {"status": "PASS_SIDE_BY_SIDE_PUBLISHED_V1_TO_NATIVE_PACKAGE_TRANSITION_AND_RETAINED_REPLAY",
        "native_upgrade": upgrade,
        "package_core_sha256": pins["core_sha256"], "authentication": authentication,
        "prepare_interruption": interruption,
        "historical_prepare_interruption": historical_interruption,
        "prepare_interruption_comparison": interruption_pair,
        "public_migration": migration,
        "published_v1_transition": transition,
        "native_executable_sha256": auth.sha(original_elf),
        "native_matrix": native_matrix,
        "retained_removal_preservation": preservation,
        "ready_sha256": auth.sha(ready),
        "removal": "private native 0.2 package root removed after selector rollback; both real old/new states, projects, builds and unrelated guards preserved",
        "limitation": "Historical Python created the published 0.1.0 state/project/build, ran its separate interrupted-prepare/retained-verification/retry oracle and two retained --version rollback controls. Those invocations are outside the observed new Rust consumer tree. New Rust operations use the runtime-excluding policy; Linux migration additionally installs the process-wide no-exec guard before reading the inert interpreter. Cargo offline mode was exercised; OS network denial and complete no-Python observation remain unqualified; the separate native_upgrade report covers actual native revision replacement; no package-manager transaction or RC1 acceptance is claimed"}


def _native_upgrade_inputs(outer, bundle, new_bundle, new_pins):
    """Bind the real earlier preview, not a synthetic relabelling of this SDK."""
    host = current_host()
    expected = NATIVE_UPGRADE_HOST_PINS[host]
    path = outer / "metadata" / f"native-package-inputs-{host}.json"
    raw = auth.read(path)
    if auth.sha(raw) != expected["pins_sha256"]:
        raise ValueError("native upgrade old package pins differ from the archived preview")
    old = auth.parsed(raw)
    if (old.get("source_commit") != NATIVE_UPGRADE_SOURCE
            or old.get("sdk_run_id") != NATIVE_UPGRADE_RUN or old.get("sdk_run_attempt") != 1
            or old.get("host") != host or old.get("package_version") != "0.2.0-1"
            or old.get("packaging_revision") != 1):
        raise ValueError("native upgrade old package identity differs from its pinned source/run")
    if (new_pins.get("sdk_version") != old["sdk_version"]
            or new_pins.get("cli_version") != old["cli_version"]
            or new_pins.get("host") != host or new_pins.get("package_version") != "0.2.0-2"
            or new_pins.get("packaging_revision") != 2
            or new_pins.get("source_commit") == old["source_commit"]
            or new_pins.get("manifest_sha256") == old["manifest_sha256"]):
        raise ValueError("native upgrade requires a distinct real revision-2 package and manifest")
    if auth.sha(auth.read(bundle / ".auth/authentication.json")) != expected["authentication_sha256"]:
        raise ValueError("native upgrade old host authentication differs from the original record")
    manifest_raw = auth.read(bundle / "release.json")
    manifest = auth.parsed(manifest_raw)
    if (auth.sha(manifest_raw) != old["manifest_sha256"]
            or manifest.get("producer", {}).get("source_sha") != NATIVE_UPGRADE_SOURCE
            or manifest.get("producer", {}).get("run_id") != NATIVE_UPGRADE_RUN
            or manifest.get("producer", {}).get("run_attempt") != 1):
        raise ValueError("native upgrade old inner manifest lost its source/run binding")
    # The generated SDK contract binds a different producer source identity.
    # Every other SDK member, including all target/component inputs, must be
    # identical before sharing the existing validated cold runtime reference.
    new_manifest = auth.parsed(auth.read(new_bundle / "release.json"))
    def baseline_rows(value):
        rows = value.get("sdk_files")
        if (not isinstance(rows, list) or len(rows) < 2
                or len({row["path"] for row in rows}) != len(rows)
                or sum(row["path"] == "contract/sdk.json" for row in rows) != 1):
            raise ValueError("native upgrade baseline/component inventory is incomplete or duplicated")
        return [row for row in rows if row["path"] != "contract/sdk.json"]
    if baseline_rows(manifest) != baseline_rows(new_manifest):
        raise ValueError("native upgrade baseline/component inventory changed")
    launcher_pin = manifest["host_launchers"][host]
    launcher = auth.below(bundle, launcher_pin["path"])
    launcher_raw = auth.read(launcher)
    if (len(launcher_raw) != launcher_pin["bytes"]
            or auth.sha(launcher_raw) != old["core_sha256"]
            or launcher_pin["sha256"] != old["core_sha256"]):
        raise ValueError("native upgrade old launcher differs from its manifest/package pins")
    return old, path, launcher


def _verified_retained_native_core(state, old_pins):
    """Verify the one supported retained launcher alias and read its pinned core."""
    state = Path(state)
    try:
        if not stat.S_ISDIR(state.lstat().st_mode):
            raise ValueError("retained native state must be a real directory")
    except OSError as error:
        raise ValueError("retained native state is missing or unsafe") from error

    version = old_pins.get("package_version")
    try:
        auth.rel(version)
    except (TypeError, ValueError) as error:
        raise ValueError("retained native package version is unsafe") from error
    if "/" in version:
        raise ValueError("retained native package version cannot select a nested path")

    alias_target = f"../libexec/ami-rust/{version}/bin/ami-rust"
    try:
        alias_parent = auth.below(state, "retained/bin")
        alias = alias_parent / "ami-rust"
        alias_before = alias.lstat()
    except (OSError, ValueError) as error:
        raise ValueError("retained native launcher alias is missing or unsafe") from error
    if not stat.S_ISLNK(alias_before.st_mode):
        raise ValueError("retained native launcher must be the expected relative alias")
    try:
        observed_target = os.readlink(alias)
        alias_after = alias.lstat()
    except OSError as error:
        raise ValueError("retained native launcher alias could not be inspected") from error
    if (observed_target != alias_target
            or (alias_before.st_dev, alias_before.st_ino, alias_before.st_mode)
            != (alias_after.st_dev, alias_after.st_ino, alias_after.st_mode)):
        raise ValueError("retained native launcher alias differs from its exact relative target")

    relative_core = f"retained/libexec/ami-rust/{version}/bin/ami-rust"
    try:
        core = auth.below(state, relative_core)
        core_info = core.lstat()
    except (OSError, ValueError) as error:
        raise ValueError("retained native package core is missing or has an unsafe path") from error
    if not stat.S_ISREG(core_info.st_mode):
        raise ValueError("retained native package core is not a regular file")
    try:
        raw = auth.read(core)
        resolved_alias = alias.resolve(strict=True)
        resolved_core = core.resolve(strict=True)
        resolved_alias.relative_to(state.resolve(strict=True))
    except (OSError, ValueError) as error:
        raise ValueError("retained native launcher does not resolve to its state package core") from error
    if resolved_alias != resolved_core:
        raise ValueError("retained native launcher does not resolve to its versioned package core")
    if auth.sha(raw) != old_pins.get("core_sha256"):
        raise ValueError("retained native package core differs from the authenticated old pin")
    return core, raw


def _qualify_native_upgrade(work, output, old_outer, old_bundle, new_outer, new_bundle,
                            new_state, new_project, new_first, new_elf, xtask, cli,
                            supervisor, policy_path, command, protected, notices, new_pins):
    """Actual native revision-1 -> revision-2 replacement and retained replay.

    This extends the existing internal test coordinator, not the consumer.
    Every public invocation uses the same Rust observer and enforcement adapter.
    Package-manager transactions remain a separate RC3 delivery gate.
    """
    old_pins, old_pins_path, old_launcher = _native_upgrade_inputs(
        old_outer, old_bundle, new_bundle, new_pins)
    policy = auth.parsed(auth.read(policy_path))
    policy.update(source_sha=NATIVE_UPGRADE_SOURCE, workflow_sha=NATIVE_UPGRADE_SOURCE,
                  inputs_manifest_sha256=auth.sha(auth.read(old_bundle / ".auth/inputs.json")))
    old_policy = output / "native-upgrade-old-publisher-policy.json"
    write(old_policy, auth.encoded(policy), 0o600)
    checkpoints = []

    def checkpoint(name, roots, expected):
        actual = _preservation_snapshot(roots)
        if actual != expected:
            raise ValueError("native upgrade changed protected state/project/config/SDK/data during " + name)
        checkpoints.append({"name": name, "roots": actual})

    original = _preservation_snapshot(protected)
    # This separately authenticates the original host-profiled inner proof.
    # The package verifier below additionally authenticates the outer capsule's
    # original common Linux inner proof, including on a macOS consumer.
    command("17-upgrade-old-inner-authentication", ["verify", "--bundle", old_bundle,
            "--policy", old_policy], executable=cli, publisher_policy=old_policy)
    old_notices = work / "native-upgrade-old-notices"
    old_notices.mkdir(mode=0o700)
    for name in ("LICENSE-MIT", "LICENSE-APACHE"):
        write(old_notices / name, auth.read(old_bundle / name))
    write(old_notices / "THIRD-PARTY-NOTICES.md",
          auth.read(old_bundle / "native-tooling/THIRD-PARTY-NOTICES.md"))
    shutil.copytree(old_bundle / "native-tooling/licenses", old_notices / "licenses")

    def compose(label, outer, pins_path, launcher, notice_root):
        root = work / ("native-upgrade-" + label + "-package")
        _supervised_run(supervisor, [xtask, "native-package", "--pins", pins_path,
            "--proof-index", outer / "metadata/native-package-proofs.json",
            "--launcher", launcher, "--assets", outer / "candidate",
            "--proofs", outer / "metadata/gh", "--notices", notice_root, "--output", root],
            label="native-upgrade-compose-" + label)
        return root

    old_package = compose("old", old_outer, old_pins_path, old_launcher, old_notices)
    new_package = compose("new", new_outer,
        new_outer / "metadata" / f"native-package-inputs-{current_host()}.json", cli, notices)
    for label, package, selected_policy, bundle in (
            ("old", old_package, old_policy, old_bundle),
            ("new", new_package, policy_path, new_bundle)):
        command("18-upgrade-" + label + "-consistency", ["verify-package"],
                executable=package / "bin/ami-rust", publisher_policy=selected_policy)
        area = work / ("native-upgrade-" + label + "-authentication-area")
        area.mkdir(mode=0o700)
        result = auth.parsed(command("18-upgrade-" + label + "-authentication",
            ["native-package-verify", "--package", package, "--policy", selected_policy,
             "--inputs", bundle / ".auth/inputs.json", "--work", area / "work"],
            executable=xtask, publisher_policy=selected_policy))
        if result.get("status") != "OUTER_AND_INNER_AUTHENTICATED":
            raise ValueError("native upgrade package authentication did not complete: " + label)

    area = work / "native-upgrade-old-state-area"
    area.mkdir(mode=0o700)
    parent = area / "derived"
    parent.mkdir(mode=0o700)
    state = parent / "state"
    prepared = auth.parsed(command("19-upgrade-old-cold-prepare", ["prepare", "--state", state],
                                  executable=old_package / "bin/ami-rust", publisher_policy=old_policy))
    if prepared.get("status") != "READY" or prepared.get("package_version") != old_pins["package_version"]:
        raise ValueError("native upgrade old package did not prepare its own real READY state")
    ready = auth.read(state / "ready.json")
    project_area = work / "native-upgrade-old-project-area"
    project_area.mkdir(mode=0o700)
    project = project_area / "project"
    command("20-upgrade-old-new-project", ["new", "--state", state, "--project", project],
            executable=old_package / "bin/ami-rust", publisher_policy=old_policy)

    def build(label, executable, selected_state, selected_project):
        area = work / label
        area.mkdir(mode=0o700)
        parent = area / "derived"
        parent.mkdir(mode=0o700)
        target = parent / "build"
        result = auth.parsed(command(label, ["build", "--state", selected_state,
            "--project", selected_project, "--output-dir", target], executable=executable))
        if result.get("status") != "PASS" or not (target / "build-receipt.json").is_file():
            raise ValueError("native upgrade build omitted its actual PASS receipt: " + label)
        elf = auth.read(target / "artifacts/AMIRUST")
        if elf != new_elf:
            raise ValueError("native upgrade build changed the pinned canonical executable: " + label)
        return target, elf

    first, old_elf = build("21-upgrade-old-offline-build", old_package / "bin/ami-rust", state, project)
    checkpoint("old-native-preparation-and-build", protected, original)
    preserved = {**protected, "upgrade_old_state": state,
                 "upgrade_old_project": project, "upgrade_old_build": first,
                 "upgrade_new_package": new_package}
    before = _preservation_snapshot(preserved)
    selector = work / "native-upgrade-active-cli"
    selector.symlink_to(old_package, target_is_directory=True)
    old_package_identity = _preservation_snapshot({"old_package": old_package})
    selected = _set_active_package_root(selector, old_package, new_package)
    frontend = (selector / "bin/ami-rust").resolve(strict=True)
    if selected != new_package or frontend != new_package / "bin/ami-rust":
        raise ValueError("native upgrade did not activate the actual new package")
    checkpoint("native-selector-replacement", preserved, before)
    refusal = "state is incomplete or belongs to another SDK/package; use its retained launcher"
    command("22-upgrade-new-refuses-old-state", ["check-inputs", "--state", state], 2,
            executable=frontend)
    if refusal not in (output / "22-upgrade-new-refuses-old-state.stderr.log").read_text():
        raise ValueError("native upgrade refusal did not identify the old retained owner")
    refusal_area = work / "native-upgrade-refused-build"
    refusal_area.mkdir(mode=0o700)
    refusal_parent = refusal_area / "derived"
    refusal_parent.mkdir(mode=0o700)
    command("23-upgrade-new-refuses-old-build", ["build", "--state", state,
            "--project", project, "--output-dir", refusal_parent / "build"], 2, executable=frontend)
    if (list(refusal_parent.iterdir()) or refusal not in
            (output / "23-upgrade-new-refuses-old-build.stderr.log").read_text()):
        raise ValueError("native upgrade incompatible build mutated output or hid its owner refusal")
    checkpoint("new-native-owner-refusals", preserved, before)
    shutil.rmtree(old_package)
    if old_package.exists() or old_package.is_symlink() or selector.resolve(strict=True) != new_package:
        raise ValueError("native upgrade did not remove only the replaced old package")
    retained = state / "retained/bin/ami-rust"
    retained_core, retained_core_raw = _verified_retained_native_core(state, old_pins)
    if auth.read(state / "ready.json") != ready:
        raise ValueError("native upgrade lost the exact old retained tooling/READY state")
    command("24-upgrade-old-retained-recheck", ["check-inputs", "--state", state], executable=retained)
    replay, replay_elf = build("25-upgrade-old-retained-offline-replay", retained, state, project)
    if replay_elf != old_elf:
        raise ValueError("native upgrade old retained replay changed its original executable")
    command("26-upgrade-new-current-recheck", ["check-inputs", "--state", new_state], executable=frontend)
    new_build, _ = build("27-upgrade-new-offline-build", frontend, new_state, new_project)
    checkpoint("removed-old-package-and-both-native-replays", preserved, before)
    # CI retires mutable work after the job. Preserve the original ownership
    # records, receipts and tiny executables so readback can inspect real bytes,
    # rather than relying only on paths or this coordinator's PASS string.
    evidence = {}
    for name, source in {
            "old-ready.json": state / "ready.json",
            "new-ready.json": new_state / "ready.json",
            "old-project-lock.json": project / "ami-rust.lock.json",
            "new-project-lock.json": new_project / "ami-rust.lock.json",
            "old-first-receipt.json": first / "build-receipt.json",
            "old-replay-receipt.json": replay / "build-receipt.json",
            "new-first-receipt.json": new_first / "build-receipt.json",
            "new-upgrade-receipt.json": new_build / "build-receipt.json",
            "old-first.AMIRUST": first / "artifacts/AMIRUST",
            "old-replay.AMIRUST": replay / "artifacts/AMIRUST",
            "new-first.AMIRUST": new_first / "artifacts/AMIRUST",
            "new-upgrade.AMIRUST": new_build / "artifacts/AMIRUST",
            "old-retained-core": retained_core,
    }.items():
        raw = retained_core_raw if name == "old-retained-core" else auth.read(source)
        destination = output / "native-upgrade-raw" / name
        write(destination, raw)
        evidence[name] = {"path": destination.relative_to(output).as_posix(),
                          "bytes": len(raw), "sha256": auth.sha(raw)}
    report = {"schema": "ami-rust-native-package-upgrade-v1",
        "status": "PASS_NATIVE_REVISION_UPGRADE_AND_OLD_RETAINED_OFFLINE_REPLAY_NOT_RC1_ACCEPTANCE",
        "host": current_host(), "old_pins": old_pins, "new_pins": new_pins,
        "old_original_host_authentication_sha256": NATIVE_UPGRADE_HOST_PINS[current_host()]["authentication_sha256"],
        "old_policy_sha256": auth.sha(auth.read(old_policy)),
        "selector": str(selector), "selected_new_package": str(selected),
        "removed_old_package": old_package_identity,
        "old_ready_sha256": auth.sha(ready), "old_retained_launcher_sha256": auth.sha(retained_core_raw),
        "old_first_build": str(first), "old_retained_replay": str(replay),
        "new_first_build": str(new_first), "new_upgrade_build": str(new_build),
        "canonical_executable_sha256": auth.sha(new_elf),
        "raw_evidence": evidence,
        "preservation_before": before, "preservation_after": _preservation_snapshot(preserved),
        "checkpoints": checkpoints,
        "scope": "Actual privately installed native 0.2.0-1 to distinct authenticated 0.2.0-2 package replacement/removal; observed old retained and new builds deny network and Python. No APT/Homebrew transaction, publication or complete RC1 acceptance claim."}
    write(output / "native-package-upgrade.json", auth.encoded(report))
    _check_limits(supervisor, "native-to-native upgrade report")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    host = subs.add_parser("host")
    host.add_argument("--host", choices=auth.HOSTS, required=True)
    host.add_argument("--output", type=Path, required=True)
    host.add_argument("--python-bootstrap-root", type=Path)
    for name in ("assemble", "audit"):
        sub = subs.add_parser(name)
        sub.add_argument("--linux", type=Path, required=True)
        sub.add_argument("--macos", type=Path, required=True)
        sub.add_argument("--output" if name == "assemble" else "--bundle", type=Path, required=True)
        sub.add_argument("--python-bootstrap-root", type=Path)
    verify = subs.add_parser("verify")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--outer", type=Path, required=True)
    verify.add_argument("--upgrade-outer", type=Path, required=True)
    verify.add_argument("--upgrade-bundle", type=Path, required=True)
    verify.add_argument("--output", type=Path, required=True)
    verify.add_argument("--python-bootstrap-root", type=Path, required=True)
    for sub in subs.choices.values():
        sub.add_argument("--work", type=Path, required=True)
        sub.add_argument("--host-rust", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "host":
        result = host_build(args.work, args.output, args.host_rust, args.host, args.python_bootstrap_root)
    elif args.command == "verify":
        result = verify_lifecycle(args.work, args.output, args.bundle, args.host_rust, args.python_bootstrap_root, args.outer,
                                  args.upgrade_outer, args.upgrade_bundle)
    else:
        payloads = {"linux-x86_64": args.linux, "macos-aarch64": args.macos}
        result = (compose(args.work, args.output, args.host_rust, payloads, args.python_bootstrap_root)
                  if args.command == "assemble" else
                  audit(args.work, args.bundle, args.host_rust, payloads, args.python_bootstrap_root))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
