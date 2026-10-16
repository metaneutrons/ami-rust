#!/usr/bin/env python3
"""Produce a pinned native AROS SDK candidate on a standard hosted runner.

The output contains the portable source SDK, this host's separately assembled
Cargo component, five native AMIRUST qualification artifacts, and bounded
receipts. It does not run an AROS guest or authorize SDK publication.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request

SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parent.parent
SCHEMA = "ami-rust-ci-sdk-inputs-v1"
RECEIPT_SCHEMA = "ami-rust-hosted-sdk-producer-v1"
REFERENCE_SCHEMA = "ami-rust-native-reference-v1"
HOST_TARGETS = {
    "macos-aarch64": "aarch64-apple-darwin",
    "linux-x86_64": "x86_64-unknown-linux-gnu",
}
LINKAGE_AUDIT_UTILITIES = {
    "macos-aarch64": ("otool", "-L"),
    "linux-x86_64": ("readelf", "-d"),
}
VARIANTS = {
    "minimal-noalloc": ("ami-rust-minimal", ("--no-default-features",)),
    "minimal-alloc": ("ami-rust-minimal", ("--features", "alloc")),
    "qualification": ("ami-rust-qualification", ()),
    "dependencies": ("ami-rust-dependencies", ()),
    "sha256sum": ("ami-rust-sha256sum", ()),
}
MAX_ARCHIVE_BYTES = 6 * 1024**3
MAX_OUTPUT_BYTES = 32 * 1024**2 - 64 * 1024
MAX_LOG_BYTES = 16 * 1024**2
MAX_RSS_BYTES = 4 * 1024**3
MAX_WORK_BYTES = 12 * 1024**3
MAX_COMMAND_SECONDS = 1200
MAX_CHANNEL_MANIFEST_BYTES = 4 * 1024**2
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
GIT_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
ARCHIVE_CHUNK = 1024 * 1024
REDIRECT_HOSTS = ("release-assets.githubusercontent.com", "objects.githubusercontent.com")


def load_helper(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load trusted SDK helper: " + relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ci_cargo = load_helper("_ami_rust_ci_cargo", "release/ci_cargo.py")
prepare_sdk = load_helper("_ami_rust_prepare_sdk", "release/prepare_sdk.py")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(ARCHIVE_CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def resolve_linkage_audit_utility(host: str) -> dict:
    """Resolve and fingerprint the host's native linkage reader before PATH is sanitized."""
    try:
        name, _ = LINKAGE_AUDIT_UTILITIES[host]
    except KeyError as error:
        raise ValueError("native Cargo linkage audit does not support host: " + host) from error
    found = shutil.which(name)
    if found is None:
        raise ValueError("native Cargo linkage audit utility is missing: " + name)
    path = Path(found).resolve(strict=True)
    info = path.stat()
    if (not stat.S_ISREG(info.st_mode) or (info.st_mode & 0o111) == 0
            or not os.access(path, os.X_OK)):
        raise ValueError("native Cargo linkage audit utility is not executable: " + name)
    return {"name": name, "path": str(path), "sha256": sha256(path)}


def audit_cargo_linkage(host: str, cargo_binary: Path, utility: dict,
                        supervisor: "Supervisor") -> dict:
    """Capture bounded native dynamic-linkage output for the packaged Cargo binary."""
    try:
        expected_name, option = LINKAGE_AUDIT_UTILITIES[host]
    except KeyError as error:
        raise ValueError("native Cargo linkage audit does not support host: " + host) from error
    if (not isinstance(utility, dict) or utility.get("name") != expected_name
            or not isinstance(utility.get("path"), str)
            or not Path(utility["path"]).is_absolute()
            or not _is_digest(utility.get("sha256"))):
        raise ValueError("native Cargo linkage audit utility identity is malformed")
    utility_path = Path(utility["path"])
    if (utility_path.is_symlink() or not utility_path.is_file()
            or (utility_path.stat().st_mode & 0o111) == 0
            or not os.access(utility_path, os.X_OK)
            or sha256(utility_path) != utility["sha256"]):
        raise ValueError("native Cargo linkage audit utility changed after resolution")
    if (cargo_binary.is_symlink() or not cargo_binary.is_file()
            or not os.access(cargo_binary, os.X_OK)):
        raise ValueError("packaged Cargo binary is missing or nonexecutable for linkage audit")

    binary_sha_before = sha256(cargo_binary)
    output = supervisor.run_text([str(utility_path), option, str(cargo_binary)],
                                 cwd=cargo_binary.parent.parent,
                                 label="cargo-linkage-evidence", timeout=60)
    if len(output.encode("utf-8")) > MAX_LOG_BYTES:
        raise ValueError("native Cargo linkage output exceeds the supervisor log bound")
    binary_sha_after = sha256(cargo_binary)
    utility_sha_after = sha256(utility_path)
    if binary_sha_before != binary_sha_after:
        raise ValueError("Cargo binary changed during native linkage audit")
    if utility_sha_after != utility["sha256"]:
        raise ValueError("native Cargo linkage audit utility changed during execution")
    return {
        "host": host,
        "binary_path": "bin/cargo",
        "binary_sha256_before": binary_sha_before,
        "binary_sha256_after": binary_sha_after,
        "utility": utility,
        "command_arguments": [option, str(cargo_binary)],
        "raw_output": output,
    }


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()


def unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def read_json(path: Path, limit: int = 64 * 1024**2) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError("missing, linked or oversized JSON: " + path.name)
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_json,
                       parse_constant=lambda token: (_ for _ in ()).throw(ValueError("invalid JSON constant")))
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object: " + path.name)
    return value


def host_identity() -> tuple[str, str]:
    system, machine = platform.system(), platform.machine().lower()
    host = {("Darwin", "arm64"): "macos-aarch64",
            ("Linux", "x86_64"): "linux-x86_64"}.get((system, machine))
    if host is None:
        raise ValueError("SDK producer supports only macOS ARM64 and Linux x86-64")
    return host, HOST_TARGETS[host]


def _safe_relative(value: object) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value or ":" in value:
        raise ValueError("manifest path is not a portable relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(part in ("", ".", "..") for part in value.split("/")):
        raise ValueError("unsafe relative path: " + value)
    return path


def _is_digest(value) -> bool:
    return isinstance(value, str) and DIGEST.fullmatch(value) is not None


def directory_bytes(root: Path) -> int:
    total = 0
    if not root.exists():
        return 0
    for path in root.rglob("*"):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
    return total


def physical_memory_bytes(host: str) -> int:
    if host == "macos-aarch64":
        return int(subprocess.check_output(["/usr/sbin/sysctl", "-n", "hw.memsize"], text=True).strip())
    return os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")


def validate_resource_schema(resources: dict) -> tuple[int, int]:
    capacity = resources.get("host_capacity")
    build = resources.get("build")
    if (resources.get("schema") != "ami-rust-hosted-resources-v1"
            or not isinstance(capacity, dict) or capacity.get("schema") != "ami-rust-host-capacity-v1"
            or not isinstance(build, dict)):
        raise ValueError("unrecognized hosted resource policy")
    expected_build = {"jobs": 2, "rss_bytes": MAX_RSS_BYTES, "seconds": MAX_COMMAND_SECONDS,
                      "workspace_bytes": MAX_WORK_BYTES, "log_bytes": MAX_LOG_BYTES}
    if build != expected_build:
        raise ValueError("SDK build ceilings differ from the admitted resource profile")
    ram_min = capacity.get("ram_minimum_bytes")
    disk_min = capacity.get("disk_free_minimum_bytes")
    if (type(ram_min) is not int or type(disk_min) is not int
            or ram_min < 6 * 1024**3 or disk_min < 24 * 1024**3):
        raise ValueError("host resource minima must be at least 6 GiB RAM and 24 GiB disk")
    return ram_min, disk_min


def validate_resource_policy(resources: dict, disk_path: Path) -> dict:
    ram_min, disk_min = validate_resource_schema(resources)
    host, _ = host_identity()
    ram = physical_memory_bytes(host)
    free = shutil.disk_usage(disk_path).free
    if ram < ram_min or free < disk_min:
        raise ValueError(f"host capacity refused: {ram} RAM bytes/{free} free bytes")
    return {"physical_ram_bytes": ram, "free_disk_bytes": free,
            "ram_minimum_bytes": ram_min, "disk_free_minimum_bytes": disk_min}


def validate_inputs(inputs: dict, normative: dict, host: str) -> dict:
    if inputs != normative:
        raise ValueError("SDK input pins differ from the tracked normative file")
    if inputs.get("schema") != SCHEMA:
        raise ValueError("unrecognized SDK input schema")
    if set(inputs.get("hosts", {})) != set(HOST_TARGETS) or host not in HOST_TARGETS:
        raise ValueError("SDK inputs must cover exactly both admitted standard hosts")
    if (inputs.get("rust_channel") != "nightly-2026-09-18"
            or not isinstance(inputs.get("rust_commit"), str)
            or GIT_COMMIT.fullmatch(inputs["rust_commit"]) is None):
        raise ValueError("pinned Rust nightly identity is incomplete")
    channel = inputs.get("channel_manifest")
    if (not isinstance(channel, dict) or channel.get("url") !=
            "https://static.rust-lang.org/dist/2026-09-18/channel-rust-nightly.toml"
            or not _is_digest(channel.get("sha256"))):
        raise ValueError("pinned Rust channel manifest identity is invalid")
    native = inputs.get("native_reference")
    if (not isinstance(native, dict) or native.get("path") != "release/native-reference.json"
            or not _is_digest(native.get("sha256"))
            or native.get("basis_source_record_sha256") != "64de65e5155238e72610485d1a81431bb53b1d5d81f7780807a1020217a86650"):
        raise ValueError("native reference input pin is incomplete or unrecognized")
    rows = inputs["hosts"][host]
    if set(rows) != {"rust", "toolchain", "collector"}:
        raise ValueError("host input component set is incomplete")
    rust = rows["rust"]
    if rust.get("kind") != "rust-installer" or rust.get("archive_order") != ["rustc", "rust-std", "rust-src", "cargo"]:
        raise ValueError("Rust installer component order differs from the reviewed pin")
    archives = rust.get("archives")
    expected_names = [f"rustc-nightly-{HOST_TARGETS[host]}.tar.xz",
                      f"rust-std-nightly-{HOST_TARGETS[host]}.tar.xz",
                      "rust-src-nightly.tar.xz",
                      f"cargo-nightly-{HOST_TARGETS[host]}.tar.xz"]
    if not isinstance(archives, list) or len(archives) != 4:
        raise ValueError("Rust component archive set must contain four entries")
    date = inputs["rust_channel"].removeprefix("nightly-")
    for row, component, filename in zip(archives, rust["archive_order"], expected_names, strict=True):
        parsed = urllib.parse.urlparse(row.get("url", ""))
        if (row.get("component") != component or parsed.scheme != "https"
                or parsed.hostname != "static.rust-lang.org"
                or parsed.path != f"/dist/{date}/{filename}"
                or type(row.get("bytes")) is not int or row["bytes"] <= 0
                or row["bytes"] > MAX_ARCHIVE_BYTES or not _is_digest(row.get("sha256"))):
            raise ValueError("Rust component URL/size/hash pin is invalid: " + component)
    expected_admin = ["lib/rustlib/install.log", "lib/rustlib/manifest-cargo",
                      "lib/rustlib/manifest-rust-src",
                      f"lib/rustlib/manifest-rust-std-{HOST_TARGETS[host]}",
                      "lib/rustlib/manifest-rustc"]
    if rust.get("remove_installer_administrative_files") != expected_admin:
        raise ValueError("Rust installer administrative cleanup set differs from the reviewed five files")

    for name, expected_root, kind in (("toolchain", "toolchain", "tar"),
                                      ("collector", None, "tar")):
        pin = rows[name]
        parsed = urllib.parse.urlparse(pin.get("url", ""))
        if (pin.get("kind") != kind or parsed.scheme != "https" or parsed.hostname != "github.com"
                or type(pin.get("bytes")) is not int or pin["bytes"] <= 0
                or pin["bytes"] > MAX_ARCHIVE_BYTES or not _is_digest(pin.get("sha256"))):
            raise ValueError("host tool archive pin is invalid: " + name)
        root = pin.get("archive_root")
        if not isinstance(root, str) or _safe_relative(root).as_posix() != root or "/" in root:
            raise ValueError("host tool archive root must be one portable directory name")
        if expected_root and root != expected_root:
            raise ValueError("cross toolchain archive root differs from its reviewed name")

    shared = inputs.get("shared")
    if not isinstance(shared, dict) or set(shared) != {"csdk", "vendor"}:
        raise ValueError("shared input component set is incomplete")
    for name, path, root in (("csdk", "release/inputs/csdk.tar.xz", "Developer"),
                             ("vendor", "release/inputs/vendor.tar.xz", "vendor")):
        pin = shared[name]
        if (pin.get("kind") != "repository-tar" or pin.get("path") != path
                or pin.get("archive_root") != root or type(pin.get("bytes")) is not int
                or pin["bytes"] <= 0 or not _is_digest(pin.get("sha256"))):
            raise ValueError("shared SDK input pin is malformed: " + name)
    portable = inputs.get("portable_csdk")
    if (not isinstance(portable, dict) or set(portable) != {"path", "bytes", "sha256"}
            or portable.get("path") != "release/portable-csdk/spec.json"
            or type(portable.get("bytes")) is not int or portable["bytes"] <= 0
            or not _is_digest(portable.get("sha256"))):
        raise ValueError("portable C-SDK derivation specification pin is malformed")
    return rows


def portable_csdk_spec(inputs: dict) -> dict:
    pin = inputs["portable_csdk"]
    path = ROOT / _safe_relative(pin["path"])
    if (path.is_symlink() or not path.is_file() or path.stat().st_size != pin["bytes"]
            or sha256(path) != pin["sha256"]):
        raise ValueError("portable C-SDK specification differs from its normative input pin")
    spec = read_json(path)
    prepare_sdk._validate_portable_csdk_spec(spec)
    if any(spec["original"]["archive"][key] != inputs["shared"]["csdk"][key]
           for key in ("path", "bytes", "sha256")):
        raise ValueError("portable C-SDK original archive differs from the frozen shared input")
    return spec


def portable_csdk_prerequisite(inputs: dict) -> dict:
    """The consumer installs the exact independently reproduced repository input."""
    pin = portable_csdk_spec(inputs)["candidate"]["archive"]
    return {key: pin[key] for key in ("path", "bytes", "sha256")} | {
        "kind": "repository-tar", "archive_root": "Developer"}


def csdk_host_tools() -> dict:
    """Resolve host build utilities before the SDK clears its ambient environment."""
    tools = {}
    for name in ("cc", "cmake", "pkg-config", "perl", "git"):
        found = shutil.which(name)
        if found is None:
            raise ValueError("portable C-SDK host utility is missing: " + name)
        path = Path(found).resolve(strict=True)
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError("portable C-SDK host utility is not executable: " + name)
        tools[name] = {"path": str(path), "sha256": sha256(path)}
    return tools


def produce_portable_csdk(inputs, toolchain, destination, work, output, python_path,
                          tools, supervisor):
    """Fresh derivation precedes provisioning; the golden archive is only a check."""
    spec = portable_csdk_spec(inputs)
    build_work, build_output = work / "portable-csdk-work", work / "portable-csdk-output"
    for row in tools.values():
        if sha256(Path(row["path"])) != row["sha256"]:
            raise ValueError("portable C-SDK host utility changed before generation")
    command = [str(python_path), "-I", "-B", str(ROOT / "release/csdk_producer.py"),
               "--work", str(build_work), "--output", str(build_output),
               "--toolchain", str(toolchain), "--native-compiler", tools["cc"]["path"],
               "--original-archive", str(ROOT / spec["original"]["archive"]["path"])]
    for name in ("cmake", "pkg-config", "perl", "git"):
        command.extend(["--" + name, tools[name]["path"]])
    process = supervisor.run(command, cwd=ROOT, label="derive-portable-csdk", timeout=1200)
    report_path = build_output / "csdk-producer.json"
    report = read_json(report_path, 4 * 1024**2)
    expected = spec["candidate"]["archive"]
    archive = build_output / expected["name"]
    if (report.get("schema") != "ami-rust-portable-csdk-producer-v1"
            or report.get("status") != "PRODUCED_CSDK_COMPONENT_CANDIDATE_NOT_R1_ACCEPTED"
            or report.get("host") != host_identity()[0]
            or report.get("spec_sha256") != inputs["portable_csdk"]["sha256"]
            or report.get("candidate_archive") != {
                "path": expected["name"], "bytes": expected["bytes"], "sha256": expected["sha256"]}
            or archive.stat().st_size != expected["bytes"] or sha256(archive) != expected["sha256"]):
        raise ValueError("fresh portable C-SDK producer or archive identity differs")
    golden = ROOT / expected["path"]
    if golden.stat().st_size != expected["bytes"] or sha256(golden) != expected["sha256"]:
        raise ValueError("repository C-SDK prerequisite differs from its reproduced identity")
    extraction = work / "archive-extraction/csdk-derived"
    root, receipt = _archive_member_root(archive, "Developer", current_managed=supervisor.managed_bytes(),
                                        extraction=extraction)
    os.replace(root, destination)
    shutil.rmtree(extraction)
    for row in tools.values():
        if sha256(Path(row["path"])) != row["sha256"]:
            raise ValueError("portable C-SDK host utility changed during generation")
    shutil.copyfile(report_path, output / "csdk-producer.json")
    return {"spec": inputs["portable_csdk"], "candidate_archive": expected,
            "producer_receipt_sha256": sha256(report_path), "process": process,
            "host_tools": tools, "extraction": receipt}


def download_channel_manifest(pin: dict, destination: Path, *,
                              opener=urllib.request.urlopen,
                              total_timeout: int = 120) -> dict:
    """Fetch the pinned Rust channel manifest with strict origin and size bounds."""
    parsed = urllib.parse.urlparse(pin.get("url", ""))
    if (parsed.scheme != "https" or parsed.hostname != "static.rust-lang.org"
            or not _is_digest(pin.get("sha256"))):
        raise ValueError("Rust channel manifest pin is malformed")
    if destination.exists() or destination.is_symlink():
        raise ValueError("Rust channel manifest destination must be fresh")
    partial = destination.with_name(destination.name + ".partial")
    if partial.exists() or partial.is_symlink():
        raise ValueError("Rust channel manifest partial destination already exists")
    request = urllib.request.Request(pin["url"], headers={"User-Agent": "ami-rust-hosted-sdk/1"})
    deadline = time.monotonic() + total_timeout
    digest = hashlib.sha256()
    received = 0
    try:
        with opener(request, timeout=30) as response:
            final = urllib.parse.urlparse(response.geturl())
            if final.scheme != "https" or final.hostname != "static.rust-lang.org":
                raise ValueError("Rust channel manifest redirected outside its pinned origin")
            declared = response.headers.get("Content-Length")
            if declared is not None and (not declared.isdecimal()
                                         or int(declared) > MAX_CHANNEL_MANIFEST_BYTES):
                raise ValueError("Rust channel manifest Content-Length exceeds its size bound")
            with partial.open("xb") as target:
                while True:
                    if time.monotonic() > deadline:
                        raise TimeoutError("Rust channel manifest download exceeded its time bound")
                    block = response.read(min(ARCHIVE_CHUNK, MAX_CHANNEL_MANIFEST_BYTES + 1 - received))
                    if not block:
                        break
                    received += len(block)
                    if received > MAX_CHANNEL_MANIFEST_BYTES:
                        raise ValueError("Rust channel manifest exceeds its size bound")
                    target.write(block)
                    digest.update(block)
                    if time.monotonic() > deadline:
                        raise TimeoutError("Rust channel manifest download exceeded its time bound")
        actual = digest.hexdigest()
        if not received or actual != pin["sha256"]:
            raise ValueError("Rust channel manifest bytes differ from the pinned digest")
        os.replace(partial, destination)
        return {"url": pin["url"], "path": destination.name,
                "bytes": received, "sha256": actual}
    except BaseException:
        try:
            partial.unlink()
        except FileNotFoundError:
            pass
        raise


def read_normative(inputs_path: Path, resources_path: Path, host: str):
    expected_inputs = ROOT / "release/ci-sdk-inputs.json"
    expected_resources = ROOT / "release/ci-resources.json"
    if inputs_path.resolve(strict=True) != expected_inputs.resolve(strict=True):
        raise ValueError("--inputs must be the tracked release/ci-sdk-inputs.json")
    if resources_path.resolve(strict=True) != expected_resources.resolve(strict=True):
        raise ValueError("--resources must be the tracked release/ci-resources.json")
    if inputs_path.read_bytes() != expected_inputs.read_bytes():
        raise ValueError("SDK inputs are not the normative tracked bytes")
    if resources_path.read_bytes() != expected_resources.read_bytes():
        raise ValueError("resource policy is not the normative tracked bytes")
    inputs, resources = read_json(expected_inputs), read_json(expected_resources)
    host_rows = validate_inputs(inputs, inputs, host)
    validate_resource_schema(resources)
    return inputs, resources, host_rows


def load_normative(inputs_path: Path, resources_path: Path, host: str):
    inputs, resources, host_rows = read_normative(inputs_path, resources_path, host)
    capacity = validate_resource_policy(resources, inputs_path.parent)
    return inputs, resources, host_rows, capacity


def verify_python_bootstrap(root: Path, host: str) -> tuple[Path, dict]:
    if root.is_symlink() or not root.is_dir() or root.name != "ami-rust-python-bootstrap":
        raise ValueError("pinned Python bootstrap root is missing or misnamed")
    manifest_path = ROOT / "release/ci-python-inputs.json"
    manifest = read_json(manifest_path, 1024 * 1024)
    if manifest.get("schema") != "ami-rust-ci-python-inputs-v1" or manifest.get("version") != "3.12.15":
        raise ValueError("unsupported pinned Python runtime manifest")
    record = manifest.get("hosts", {}).get(host)
    bootstrap = read_json(root / "bootstrap.json", 64 * 1024)
    if (not isinstance(record, dict)
            or bootstrap.get("schema") != "ami-rust-ci-python-bootstrap-v1"
            or bootstrap.get("status") != "READY_CI_RUNTIME_NOT_SDK_QUALIFICATION"
            or bootstrap.get("host") != host
            or bootstrap.get("archive_sha256") != record.get("sha256")
            or bootstrap.get("runtime_sha256") != record.get("runtime_sha256")):
        raise ValueError("pinned Python bootstrap receipt differs from this host's archive/runtime pins")
    relative = _safe_relative(record.get("runtime_relative_path"))
    executable = root / "runtime" / relative
    info = executable.lstat()
    if (not stat.S_ISREG(info.st_mode) or not os.access(executable, os.X_OK)
            or sha256(executable) != record["runtime_sha256"]
            or Path(sys.executable).resolve(strict=True) != executable.resolve(strict=True)):
        raise ValueError("running interpreter is not the executable from the pinned Python bootstrap")
    return executable, bootstrap


def component_inventory(root: Path) -> dict:
    """Return complete file/symlink rows in the SDK component manifest format."""
    files, symlinks = [], []
    root = root.resolve(strict=True)
    # Frozen component profiles use pathlib's hierarchical path ordering:
    # clang/ precedes clang-c/, although '-' precedes '/' in a flat string.
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).parts):
        relative = path.relative_to(root).as_posix()
        _safe_relative(relative)
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if stat.S_ISREG(info.st_mode):
            files.append({"path": relative, "bytes": info.st_size, "sha256": sha256(path)})
        elif stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            if not target or "\\" in target or PurePosixPath(target).is_absolute():
                raise ValueError("unsafe prerequisite component symlink: " + relative)
            resolved = (path.parent / target).resolve(strict=True)
            try:
                resolved.relative_to(root)
            except ValueError as error:
                raise ValueError("prerequisite component symlink escapes root: " + relative) from error
            symlinks.append({"path": relative, "target": target})
        else:
            raise ValueError("unsupported file type in prerequisite component: " + relative)
    return {"files": files, "symlinks": symlinks}


def verify_component(root: Path, manifest: dict, name: str) -> dict:
    if not isinstance(manifest, dict) or not {"files", "symlinks"} <= set(manifest):
        raise ValueError("component manifest is incomplete: " + name)
    expected = {"files": manifest["files"], "symlinks": manifest["symlinks"]}
    for row in expected["files"]:
        if (not isinstance(row, dict) or not _safe_relative(row.get("path"))
                or type(row.get("bytes")) is not int or row["bytes"] < 0
                or not _is_digest(row.get("sha256"))):
            raise ValueError("malformed file inventory row in " + name)
    for row in expected["symlinks"]:
        if (not isinstance(row, dict) or not _safe_relative(row.get("path"))
                or not isinstance(row.get("target"), str)):
            raise ValueError("malformed symlink inventory row in " + name)
    actual = component_inventory(root)
    if actual != expected:
        expected_names = {row["path"] for row in expected["files"] + expected["symlinks"]}
        actual_names = {row["path"] for row in actual["files"] + actual["symlinks"]}
        raise ValueError(f"complete {name} inventory mismatch: extra={len(actual_names-expected_names)} missing={len(expected_names-actual_names)}")
    serialized = b"".join(canonical_json(row) for row in actual["files"] + actual["symlinks"])
    return {"entry_count": len(actual["files"]) + len(actual["symlinks"]),
            "regular_file_bytes": sum(row["bytes"] for row in actual["files"]),
            "inventory_sha256": hashlib.sha256(serialized).hexdigest(),
            "license_inventory": ci_cargo.tree_inventory(root)["license_inventory"]}


class Supervisor:
    """Bound all helper descendants, work roots, output, and build logs."""
    def __init__(self, work: Path, output: Path, python_root: Path, env: dict[str, str],
                 *, rows_reader=ci_cargo.process_rows, limits: dict | None = None):
        self.work, self.output, self.python_root, self.env = work, output, python_root, env
        self.rows_reader = rows_reader
        self.limits = {"rss_bytes": MAX_RSS_BYTES, "workspace_bytes": MAX_WORK_BYTES,
                       "log_bytes": MAX_LOG_BYTES, "seconds": MAX_COMMAND_SECONDS}
        if limits:
            self.limits.update(limits)
        self.checkout_bytes = directory_bytes(ROOT)
        self.peak_rss = self.peak_workspace = self.peak_logs = 0
        self.commands = []
        self._seen_pids: set[int] = set()
        self._seen_groups: set[int] = set()

    def managed_bytes(self) -> int:
        return (self.checkout_bytes + directory_bytes(self.work) + directory_bytes(self.output)
                + directory_bytes(self.python_root))

    def logs_bytes(self) -> int:
        total = 0
        for root in (self.work, self.output, self.python_root):
            if not root.exists():
                continue
            for path in root.rglob("*.log"):
                try:
                    info = path.lstat()
                except FileNotFoundError:
                    continue
                if stat.S_ISREG(info.st_mode):
                    total += info.st_size
        return total

    def _sample_scope(self, pid: int, rows: list[tuple[int, int, int, int]]) -> list[tuple[int, int, int, int]]:
        """Remember visible descendants and groups, including reparented members."""
        connected = set(self._seen_pids) | {pid}
        groups = set(self._seen_groups) | {pid}
        while True:
            added = {child for child, parent, group, _ in rows
                     if parent in connected or group in groups} - connected
            new_groups = {group for child, _, group, _ in rows if child in connected | added} - groups
            if not added and not new_groups:
                break
            connected.update(added)
            groups.update(new_groups)
        if os.getpgrp() in groups:
            raise RuntimeError("managed subprocess scope entered the supervisor process group")
        self._seen_pids.update(connected)
        self._seen_groups.update(groups)
        return [row for row in rows if row[0] in connected]

    def _live_groups(self) -> set[int]:
        live = set()
        for group in self._seen_groups:
            try:
                os.killpg(group, 0)
                live.add(group)
            except ProcessLookupError:
                continue
            except PermissionError:
                live.add(group)
        return live

    def _kill_tree(self, child: subprocess.Popen, rows_reader=ci_cargo.process_rows) -> None:
        # Include currently visible descendants and every process group seen while
        # running; SDK host builds use nested groups, so killing only the wrapper
        # PGID could leave Cargo or clang behind.
        self._seen_groups.add(child.pid)
        observer_error = None
        try:
            rows = rows_reader()
            self._sample_scope(child.pid, rows)
        except BaseException as error:
            # Keep signaling every previously observed process group. The caller
            # still receives a failed run if cleanup cannot confirm termination.
            observer_error = error
        for group in self._seen_groups:
            try:
                os.killpg(group, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                rows = rows_reader()
                self._sample_scope(child.pid, rows)
            except BaseException as error:
                observer_error = observer_error or error
            active_groups = self._live_groups()
            if not active_groups:
                break
            try:
                if not observer_error:
                    # A fresh sample can reveal a nested process group spawned
                    # during shutdown; signal it before the next observation.
                    for group in self._seen_groups:
                        try:
                            os.killpg(group, signal.SIGTERM)
                        except (ProcessLookupError, PermissionError):
                            pass
            except BaseException as error:
                observer_error = observer_error or error
            time.sleep(0.05)
        for group in self._seen_groups:
            try:
                os.killpg(group, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=3)
        deadline = time.monotonic() + 3.0
        while self._live_groups():
            active_groups = self._live_groups()
            for group in active_groups:
                try:
                    os.killpg(group, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            try:
                rows = rows_reader()
                self._sample_scope(child.pid, rows)
            except BaseException as error:
                observer_error = observer_error or error
            if time.monotonic() >= deadline:
                raise RuntimeError("known managed process groups remained live after SIGKILL")
            time.sleep(0.05)
        if observer_error is not None:
            raise RuntimeError("process observer failed while stopping the managed group tree") from observer_error

    def run(self, command: list[str], *, cwd: Path, label: str, timeout: int = MAX_COMMAND_SECONDS) -> dict:
        if self.managed_bytes() > self.limits["workspace_bytes"]:
            raise RuntimeError("managed workspace ceiling exceeded before " + label)
        log_dir = self.work / "logs"
        log_dir.mkdir(exist_ok=True)
        stdout_path = log_dir / (label + ".stdout.log")
        stderr_path = log_dir / (label + ".stderr.log")
        start = time.monotonic()
        peak_rss = peak_workspace = peak_logs = 0
        reason = None
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            child = subprocess.Popen([str(part) for part in command], cwd=cwd, env=self.env,
                                     stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                     start_new_session=True)
            self._seen_pids.clear()
            self._seen_groups.clear()
            self._seen_groups.add(child.pid)
            try:
                while True:
                    code = child.poll()
                    rows = self.rows_reader()
                    descendants = self._sample_scope(child.pid, rows)
                    rss = sum(row[3] * 1024 for row in descendants)
                    peak_rss = max(peak_rss, rss)
                    now = time.monotonic()
                    if now - start > min(timeout, self.limits["seconds"]):
                        reason = "time ceiling"
                    workspace = self.managed_bytes()
                    logs = self.logs_bytes()
                    peak_workspace, peak_logs = max(peak_workspace, workspace), max(peak_logs, logs)
                    if rss > self.limits["rss_bytes"]:
                        reason = "aggregate descendant RSS ceiling"
                    elif workspace > self.limits["workspace_bytes"]:
                        reason = "checkout and managed workspace ceiling"
                    elif logs > self.limits["log_bytes"]:
                        reason = "aggregate log ceiling"
                    if reason:
                        break
                    # A successful wrapper must leave no process in a nested
                    # descendant group. Require the live set to empty after reap.
                    active_groups = {row[2] for row in rows} & self._seen_groups
                    if code is not None:
                        if active_groups:
                            reason = "leader exited while descendant processes remained"
                        break
                    time.sleep(0.1)
            except BaseException as error:
                reason = "monitor failure: " + type(error).__name__ + ": " + str(error)[:300]
            finally:
                try:
                    if reason or child.poll() is None:
                        self._kill_tree(child)
                    else:
                        child.wait(timeout=3)
                except BaseException as error:
                    self._kill_tree(child, self.rows_reader)
                    reason = reason or ("process-tree cleanup failure: " + type(error).__name__)
        peak_workspace = max(peak_workspace, self.managed_bytes())
        peak_logs = max(peak_logs, self.logs_bytes())
        peak_rss = max(peak_rss, 0)
        elapsed = time.monotonic() - start
        record = {"label": label, "exit_code": child.returncode, "stop_reason": reason,
                  "elapsed_seconds": round(elapsed, 3),
                  "rss_peak_observed_bytes": peak_rss,
                  "managed_peak_observed_bytes": peak_workspace,
                  "log_peak_observed_bytes": peak_logs,
                  "stdout_log": stdout_path.relative_to(self.work).as_posix(),
                  "stderr_log": stderr_path.relative_to(self.work).as_posix()}
        self.peak_rss = max(self.peak_rss, peak_rss)
        self.peak_workspace = max(self.peak_workspace, peak_workspace)
        self.peak_logs = max(self.peak_logs, peak_logs)
        self.commands.append(record)
        if reason or child.returncode:
            tail = stderr_path.read_bytes()[-2048:].decode("utf-8", "replace")
            raise RuntimeError(f"{label} failed: {reason or 'exit ' + str(child.returncode)}; {tail[-1000:]}")
        return record

    def run_text(self, command: list[str], *, cwd: Path, label: str, timeout: int = 60) -> str:
        row = self.run(command, cwd=cwd, label=label, timeout=timeout)
        return (self.work / row["stdout_log"]).read_text(errors="replace")

    def check_limits(self, label: str) -> None:
        workspace, logs = self.managed_bytes(), self.logs_bytes()
        self.peak_workspace, self.peak_logs = max(self.peak_workspace, workspace), max(self.peak_logs, logs)
        if workspace > self.limits["workspace_bytes"]:
            raise RuntimeError("managed workspace ceiling exceeded during " + label)
        if logs > self.limits["log_bytes"]:
            raise RuntimeError("aggregate log ceiling exceeded during " + label)


def validate_native_reference(reference: dict, inputs: dict, expected_sha: str) -> dict:
    if sha256(ROOT / "release/native-reference.json") != expected_sha:
        raise ValueError("native reference bytes differ from the normative SDK input pin")
    if reference.get("schema") != REFERENCE_SCHEMA:
        raise ValueError("unrecognized native reference schema")
    basis = reference.get("basis", {})
    if basis.get("source_record_sha256") != inputs["native_reference"]["basis_source_record_sha256"]:
        raise ValueError("native reference provenance differs from its tracked source record pin")
    if set(reference.get("hosts", {})) != set(HOST_TARGETS):
        raise ValueError("native reference must cover exactly both admitted hosts")
    for host, variants in reference["hosts"].items():
        if set(variants) != set(VARIANTS):
            raise ValueError("native reference does not cover exactly the five required variants")
        total_outputs = 0
        for variant, artifacts in variants.items():
            if not isinstance(artifacts, dict) or not artifacts:
                raise ValueError(f"native reference output map is empty: {host}/{variant}")
            total_outputs += len(artifacts)
            for name, row in artifacts.items():
                _safe_relative(name)
                if (not isinstance(row, dict) or type(row.get("bytes")) is not int
                        or row["bytes"] < 0 or not _is_digest(row.get("sha256"))):
                    raise ValueError("malformed native reference artifact row")
        if total_outputs != 104:
            raise ValueError(f"native reference must cover 104 outputs across its five variants: {host}")
    sha = reference["hosts"]["linux-x86_64"]["sha256sum"].get("AMIRUST")
    sha_mac = reference["hosts"]["macos-aarch64"]["sha256sum"].get("AMIRUST")
    expected_sha_artifact = {"bytes": 928144,
                             "sha256": "b9521e15361e26b22db49c1e8953a1d29940313a5214507d023c2d953ad4acd4"}
    if sha != expected_sha_artifact or sha_mac != expected_sha_artifact:
        raise ValueError("SHAUTIL reference artifact differs from the accepted native reference")
    return reference


def verify_frozen_cargo_report(path: Path, host: str, target: str) -> dict:
    report = read_json(path)
    artifact = report.get("custom_cargo_artifact", {})
    if (report.get("schema") != "ami-rust-hosted-custom-cargo-producer-v1"
            or report.get("status") != "PRODUCED_PREREQUISITE_ONLY_NOT_R1_QUALIFICATION"
            or report.get("host") != host or report.get("rust_target") != target
            or report.get("build_profile") != "release"
            or not isinstance(artifact, dict) or type(artifact.get("bytes")) is not int
            or artifact["bytes"] <= 0 or not _is_digest(artifact.get("sha256"))):
        raise ValueError("frozen Cargo producer receipt is malformed for " + host)
    return report


def preflight_cargo_producers(resources_path: Path) -> None:
    """Verify both pinned Cargo producer receipts before starting a Cargo build."""
    tracked_output = subprocess.run(
        ["/usr/bin/git", "-C", str(ROOT), "ls-files", "-z"],
        check=True, capture_output=True, timeout=30).stdout
    tracked = {item.decode("utf-8") for item in tracked_output.split(b"\0") if item}
    inputs, resources, inputs_sha, resources_sha = prepare_sdk.verify_expected_inputs(
        ROOT, tracked, resources_path)
    for host in HOST_TARGETS:
        relative = f"release/ci-cargo-producers/{host}.json"
        prepare_sdk.tracked_regular(ROOT, tracked, relative)
        prepare_sdk.canonical_producer(
            ROOT / relative, host, inputs, resources, inputs_sha, resources_sha, ROOT, tracked)


def _copy_tree(source: Path, destination: Path) -> None:
    if destination.exists() or destination.is_symlink():
        raise ValueError("component copy destination must be fresh")
    shutil.copytree(source, destination, symlinks=True, copy_function=shutil.copy2)


def _archive_member_root(archive: Path, expected_root: str, *, expanded_limit=MAX_ARCHIVE_BYTES,
                         current_managed: int = 0, extraction: Path | None = None) -> tuple[Path, dict]:
    extraction = extraction or archive.parent / (archive.name + ".extract")
    receipt = ci_cargo.safe_extract_tar(archive, extraction, expanded_limit=expanded_limit,
                                        current_managed_bytes=current_managed,
                                        overall_limit=MAX_WORK_BYTES)
    if receipt.get("component_root") != expected_root:
        shutil.rmtree(extraction)
        raise ValueError("archive root differs from its exact pin")
    root = extraction / expected_root
    if root.is_symlink() or not root.is_dir():
        raise ValueError("archive component root is missing or linked")
    return root, {**receipt, "archive_root": expected_root}


def _remove_exact_files(root: Path, paths: list[str]) -> list[dict]:
    removed = []
    for value in paths:
        relative = _safe_relative(value)
        path = root.joinpath(*relative.parts)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Rust installer admin path is not a regular file: " + value)
        removed.append({"path": value, "bytes": info.st_size, "sha256": sha256(path)})
        path.unlink()
    return removed


def _rust_archive_root(component: str, target: str) -> str:
    if component == "rust-src":
        return "rust-src-nightly"
    if component in {"rustc", "rust-std", "cargo"}:
        return f"{component}-nightly-{target}"
    raise ValueError("unrecognized pinned Rust component: " + component)


def _extract_sdk_archive(archive: Path, destination: Path, expected_sha: str,
                         expected_bytes: int, expected_members: int) -> dict:
    """Materialize the canonical 94-file source archive without generic tar extraction."""
    if sha256(archive) != expected_sha or archive.stat().st_size != expected_bytes:
        raise ValueError("prepared source SDK archive bytes/hash differ from producer receipt")
    if destination.exists() or destination.is_symlink():
        raise ValueError("prepared SDK extraction root must be fresh")
    with tarfile.open(archive, mode="r:xz") as bundle:
        members = bundle.getmembers()
        if len(members) != expected_members or len(members) != 94:
            raise ValueError("prepared SDK archive does not contain the exact 94-file source package")
        names = [member.name for member in members]
        if names != sorted(names) or len(names) != len(set(names)):
            raise ValueError("prepared SDK archive member ordering or uniqueness is invalid")
        destination.mkdir()
        created = []
        try:
            manifest_bytes = None
            for member in members:
                relative = _safe_relative(member.name)
                if (not member.isfile() or member.issym() or member.islnk()
                        or member.mode != 0o644 or member.uid != 0 or member.gid != 0
                        or member.uname or member.gname or member.mtime != prepare_sdk.EPOCH):
                    raise ValueError("prepared SDK archive contains a noncanonical member")
                target = destination.joinpath(*relative.parts)
                if not target.resolve().is_relative_to(destination.resolve()):
                    raise ValueError("prepared SDK member escapes the fresh source root")
                target.parent.mkdir(parents=True, exist_ok=True)
                source = bundle.extractfile(member)
                if source is None:
                    raise ValueError("prepared SDK archive member has no payload")
                digest = hashlib.sha256()
                remaining = member.size
                with source, target.open("xb") as output:
                    while remaining:
                        block = source.read(min(ARCHIVE_CHUNK, remaining))
                        if not block:
                            raise ValueError("short source SDK archive member")
                        output.write(block)
                        digest.update(block)
                        remaining -= len(block)
                    if source.read(1):
                        raise ValueError("long source SDK archive member")
                target.chmod(0o644)
                created.append(member.name)
                if member.name == "contract/sdk.json":
                    manifest_bytes = target.read_bytes()
            if manifest_bytes is None:
                raise ValueError("prepared source SDK archive has no contract/sdk.json")
            manifest = json.loads(manifest_bytes, object_pairs_hook=unique_json)
            if manifest.get("schema") != "ami-rust-sdk-v1" or manifest.get("qualification_only") is not False:
                raise ValueError("prepared SDK is not the requested production trust candidate")
            declared = manifest.get("files")
            if not isinstance(declared, list) or len(declared) != 93:
                raise ValueError("prepared SDK inventory must describe its exact 93 source files")
            rows = []
            for row in declared:
                name = _safe_relative(row.get("path")).as_posix()
                path = destination.joinpath(*PurePosixPath(name).parts)
                if not path.is_file() or path.is_symlink() or type(row.get("bytes")) is not int:
                    raise ValueError("prepared SDK manifest file is missing or malformed")
                if path.stat().st_size != row["bytes"] or sha256(path) != row.get("sha256"):
                    raise ValueError("prepared SDK source file differs from its complete manifest: " + name)
                rows.append(name)
            if set(rows) != set(created) - {"contract/sdk.json"}:
                raise ValueError("prepared SDK archive and internal file inventory differ")
            manifest_hash = hashlib.sha256(manifest_bytes).hexdigest()
            if any(not path.is_file() for path in (destination / "Cargo.toml", destination / "Cargo.lock")):
                raise ValueError("prepared SDK source is missing Cargo.toml/Cargo.lock")
            return {"root": destination, "manifest": manifest, "manifest_sha256": manifest_hash,
                    "member_count": len(members), "expanded_bytes": sum(m.size for m in members)}
        except BaseException:
            try:
                shutil.rmtree(destination)
            except OSError as cleanup_error:
                raise RuntimeError("source SDK extraction failed and its partial tree could not be retired") from cleanup_error
            raise


def _install_rust(host_rows: dict, inputs: dict, work: Path, components: Path,
                  supervisor: Supervisor) -> tuple[Path, list[dict], list[dict]]:
    rust_pin = host_rows["rust"]
    target = HOST_TARGETS[host_identity()[0]]
    rust_root = components / "rust"
    rust_root.mkdir()
    materials, extractions = [], []
    archives_dir = work / "downloaded-inputs"
    archives_dir.mkdir(exist_ok=True)
    for archive_pin in rust_pin["archives"]:
        name = archive_pin["component"]
        archive = archives_dir / (name + ".tar.xz")
        if supervisor.managed_bytes() + archive_pin["bytes"] > MAX_WORK_BYTES:
            raise ValueError("Rust archive download would exceed the managed workspace ceiling")
        download = ci_cargo.download_verified(archive_pin["url"], archive_pin["bytes"],
                                              archive_pin["sha256"], archive)
        download.update({"component": name, "url": archive_pin["url"],
                         "relative_path": archive.relative_to(work).as_posix()})
        extracted, receipt = _archive_member_root(
            archive, _rust_archive_root(name, target), current_managed=supervisor.managed_bytes(),
            extraction=work / "archive-extraction" / name)
        installer = extracted / "install.sh"
        if installer.is_symlink() or not installer.is_file() or not os.access(installer, os.X_OK):
            raise ValueError("Rust component installer is missing or nonexecutable: " + name)
        supervisor.run([str(installer), "--prefix=" + str(rust_root), "--disable-ldconfig"],
                       cwd=extracted, label="sdk-install-rust-" + name, timeout=300)
        materials.append(download)
        extractions.append({"component": name, "archive_member_count": receipt["member_count"],
                            "expanded_bytes": receipt["expanded_bytes"]})
        # The archive extraction is no longer needed after this component is installed.
        shutil.rmtree(work / "archive-extraction" / name)
        archive.unlink()
        supervisor.check_limits("Rust component install")
    removed = _remove_exact_files(rust_root, rust_pin["remove_installer_administrative_files"])
    return rust_root, materials, [{"components": extractions, "removed_administrative_files": removed}]


def _extract_pinned_component(pin: dict, label: str, work: Path, destination: Path,
                              supervisor: Supervisor,
                              selection_manifest: dict | None = None) -> tuple[Path, dict, dict]:
    archive = work / "downloaded-inputs" / (label + (".tar.gz" if pin["url"].endswith(".tar.gz") else ".tar.xz"))
    if supervisor.managed_bytes() + pin["bytes"] > MAX_WORK_BYTES:
        raise ValueError(label + " archive download would exceed the managed workspace ceiling")
    receipt = ci_cargo.download_verified(pin["url"], pin["bytes"], pin["sha256"], archive,
                                         expected_origin="github.com", redirect_hosts=REDIRECT_HOSTS)
    extraction_dir = work / "archive-extraction" / label
    extracted, extraction = _archive_member_root(archive, pin["archive_root"],
                                                  current_managed=supervisor.managed_bytes(),
                                                  extraction=extraction_dir)
    if selection_manifest is None:
        if destination.exists() or destination.is_symlink():
            raise ValueError("component destination is not fresh")
        os.replace(extracted, destination)
    else:
        _materialize_component_profile(extracted, destination, selection_manifest,
                                       current_managed=supervisor.managed_bytes())
        supervisor.check_limits("selected " + label + " component profile")
    shutil.rmtree(extraction_dir)
    archive.unlink()
    return destination, {"bytes": receipt["bytes"], "sha256": receipt["sha256"],
                         "url": pin["url"], "relative_path": archive.relative_to(work).as_posix()}, extraction


def _materialize_component_profile(source: Path, destination: Path, manifest: dict,
                                   *, current_managed: int = 0) -> dict:
    """Copy exactly the complete packaged component inventory from a verified tar."""
    if destination.exists() or destination.is_symlink():
        raise ValueError("selected component root must be fresh")
    if not isinstance(manifest, dict) or not {"files", "symlinks"} <= set(manifest):
        raise ValueError("selected component manifest is malformed")
    files, symlinks = manifest["files"], manifest["symlinks"]
    if not isinstance(files, list) or not isinstance(symlinks, list):
        raise ValueError("selected component inventory rows must be arrays")
    expanded = 0
    for row in files:
        if (not isinstance(row, dict) or not _safe_relative(row.get("path"))
                or type(row.get("bytes")) is not int or row["bytes"] < 0
                or not _is_digest(row.get("sha256"))):
            raise ValueError("selected component file row is malformed")
        expanded += row["bytes"]
    if current_managed + expanded > MAX_WORK_BYTES:
        raise ValueError("selected component copy would exceed managed workspace ceiling")
    destination.mkdir(parents=True)
    try:
        for row in files:
            relative = _safe_relative(row["path"])
            source_file = source.joinpath(*relative.parts)
            info = source_file.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_size != row["bytes"]
                    or sha256(source_file) != row["sha256"]):
                raise ValueError("verified archive file differs from its SDK component inventory: " + row["path"])
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, target)
        for row in symlinks:
            if (not isinstance(row, dict) or not _safe_relative(row.get("path"))
                    or not isinstance(row.get("target"), str)):
                raise ValueError("selected component symlink row is malformed")
            relative = _safe_relative(row["path"])
            source_link = source.joinpath(*relative.parts)
            info = source_link.lstat()
            target_text = os.readlink(source_link) if stat.S_ISLNK(info.st_mode) else None
            resolved = (source_link.parent / row["target"]).resolve(strict=True)
            if (target_text != row["target"] or "\\" in row["target"]
                    or PurePosixPath(row["target"]).is_absolute()
                    or not resolved.is_relative_to(source.resolve(strict=True))):
                raise ValueError("verified archive symlink differs from its SDK component inventory: " + row["path"])
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(row["target"])
        expected = {"files": files, "symlinks": symlinks}
        if component_inventory(destination) != expected:
            raise ValueError("selected component copy is incomplete")
    except BaseException:
        try:
            shutil.rmtree(destination)
        except OSError as cleanup_error:
            raise RuntimeError("selected component copy failed and could not be retired") from cleanup_error
        raise
    return component_inventory(destination)


def _extract_local_component(pin: dict, label: str, destination: Path,
                             supervisor: Supervisor) -> tuple[Path, dict]:
    archive = ROOT / pin["path"]
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size != pin["bytes"] or sha256(archive) != pin["sha256"]:
        raise ValueError("tracked shared SDK input differs from its exact pin: " + label)
    destination.parent.mkdir(parents=True, exist_ok=True)
    extraction_dir = supervisor.work / "archive-extraction" / label
    extracted, extraction = _archive_member_root(
        archive, pin["archive_root"], current_managed=supervisor.managed_bytes(),
        extraction=extraction_dir)
    os.replace(extracted, destination)
    shutil.rmtree(extraction_dir)
    supervisor.check_limits("shared " + label + " extraction")
    return destination, {"path": pin["path"], "bytes": pin["bytes"], "sha256": pin["sha256"],
                        "archive_member_count": extraction["member_count"],
                        "expanded_bytes": extraction["expanded_bytes"]}


def _copy_flat_sdk_archive(archive: Path, destination: Path) -> dict:
    if destination.exists() or destination.is_symlink():
        raise ValueError("source SDK archive destination must be fresh")
    shutil.copyfile(archive, destination)
    return {"path": destination.name, "bytes": destination.stat().st_size, "sha256": sha256(destination)}


def _component_rows_from_sdk(sdk: dict, host: str) -> dict:
    profile = sdk["manifest"].get("profiles", {}).get(host)
    if not isinstance(profile, dict) or profile.get("rust_host") != HOST_TARGETS[host]:
        raise ValueError("prepared SDK has no matching host component profile")
    component_pins = profile.get("components")
    if not isinstance(component_pins, dict) or set(component_pins) != {"rust", "cargo", "toolchain", "collector", "csdk", "vendor"}:
        raise ValueError("prepared SDK component profile is incomplete")
    result = {}
    for name, reference in component_pins.items():
        manifest_name = _safe_relative(reference.get("manifest")).as_posix()
        manifest_path = sdk["root"].joinpath(*PurePosixPath(manifest_name).parts)
        if not manifest_path.is_file() or manifest_path.is_symlink() or sha256(manifest_path) != reference.get("sha256"):
            raise ValueError("component manifest differs from host profile: " + name)
        manifest = read_json(manifest_path, 32 * 1024**2)
        if not {"files", "symlinks"} <= set(manifest):
            raise ValueError("component inventory manifest is malformed: " + name)
        result[name] = {"manifest_path": manifest_name, "manifest_sha256": reference["sha256"],
                        "manifest": manifest}
    return result


def require_cargo_match(actual: dict, frozen: dict) -> None:
    if (not isinstance(actual, dict) or not isinstance(frozen, dict)
            or type(actual.get("bytes")) is not int or actual["bytes"] <= 0
            or not _is_digest(actual.get("sha256"))
            or actual.get("bytes") != frozen.get("bytes")
            or actual.get("sha256") != frozen.get("sha256")):
        raise ValueError("fresh native Cargo differs from the frozen host producer receipt")


def _make_cargo_component(work: Path, cargo_output: Path, component_info: dict, host: str,
                          target: str, cargo_inputs: dict, resources: dict,
                          supervisor: Supervisor) -> tuple[Path, dict]:
    report_path = ROOT / "release/ci-cargo-producers" / (host + ".json")
    frozen = verify_frozen_cargo_report(report_path, host, target)
    local = read_json(cargo_output / "producer.json")
    if (local.get("status") != "PRODUCED_PREREQUISITE_ONLY_NOT_R1_QUALIFICATION"
            or local.get("host") != host or local.get("rust_target") != target):
        raise ValueError("current-host Cargo producer did not complete successfully")
    local_artifact = local["custom_cargo_artifact"]
    frozen_artifact = frozen["custom_cargo_artifact"]
    require_cargo_match(local_artifact, frozen_artifact)
    cargo_rel = _safe_relative(local_artifact.get("relative_path"))
    cargo_binary = work.joinpath(*cargo_rel.parts)
    if (not cargo_binary.is_file() or cargo_binary.is_symlink()
            or cargo_binary.stat().st_size != frozen_artifact["bytes"]
            or sha256(cargo_binary) != frozen_artifact["sha256"]):
        raise ValueError("fresh native Cargo artifact path/hash/size differs from frozen receipt")

    tracked_output = supervisor.run_text(["/usr/bin/git", "-C", str(ROOT), "ls-files", "-z"],
                                         cwd=work, label="sdk-source-tracked-files", timeout=30)
    tracked = {item for item in tracked_output.split("\0") if item}
    cargo_inputs_path = ROOT / "release/ci-bootstrap-inputs.json"
    cargo_inputs_bytes = cargo_inputs_path.read_bytes()
    source_inputs = read_json(cargo_inputs_path)
    resource_path = ROOT / "release/ci-resources.json"
    producer_bytes = prepare_sdk.canonical_producer(
        report_path, host, source_inputs, resources, hashlib.sha256(cargo_inputs_bytes).hexdigest(),
        sha256(resource_path), ROOT, tracked)
    component_root = work / "component-staging" / "cargo"
    component_root.mkdir(parents=True)
    binary_path = component_root / "bin" / "cargo"
    binary_path.parent.mkdir()
    shutil.copyfile(cargo_binary, binary_path)
    binary_path.chmod(0o755)
    (component_root / "producer.json").write_bytes(producer_bytes)
    manifest_row = component_info["cargo"]["manifest"]
    verify_component(component_root, manifest_row, "cargo")
    return component_root, {"host_receipt_path": report_path.relative_to(ROOT).as_posix(),
                            "frozen_producer_sha256": sha256(report_path),
                            "binary_bytes": binary_path.stat().st_size,
                            "binary_sha256": sha256(binary_path),
                            "producer_record_sha256": sha256(component_root / "producer.json"),
                            "version": local_artifact.get("version")}


def _canonical_cargo_archive(component_root: Path, destination: Path,
                             manifest: dict) -> dict:
    if destination.exists() or destination.is_symlink():
        raise ValueError("Cargo component archive destination must be fresh")
    rows = manifest.get("files")
    if not isinstance(rows, list) or {row.get("path") for row in rows} != {"bin/cargo", "producer.json"}:
        raise ValueError("Cargo component archive must contain exactly Cargo and its canonical producer record")
    with tarfile.open(destination, mode="w:xz", format=tarfile.USTAR_FORMAT) as bundle:
        for row in sorted(rows, key=lambda item: item["path"]):
            path = _safe_relative(row["path"])
            source = component_root.joinpath(*path.parts)
            if (source.is_symlink() or not source.is_file() or source.stat().st_size != row["bytes"]
                    or sha256(source) != row["sha256"]):
                raise ValueError("Cargo component file differs from packaged profile: " + row["path"])
            info = tarfile.TarInfo(path.as_posix())
            info.size = source.stat().st_size
            info.mode = 0o755 if path.as_posix() == "bin/cargo" else 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = prepare_sdk.EPOCH
            with source.open("rb") as stream:
                bundle.addfile(info, stream)
    with tarfile.open(destination, mode="r:xz") as bundle:
        members = bundle.getmembers()
        if [member.name for member in members] != ["bin/cargo", "producer.json"]:
            raise ValueError("Cargo component archive member order/content is invalid")
        for member in members:
            row = next(item for item in rows if item["path"] == member.name)
            payload = bundle.extractfile(member)
            if (not member.isfile() or member.uid != 0 or member.gid != 0
                    or member.mtime != prepare_sdk.EPOCH or payload is None
                    or member.size != row["bytes"]
                    or hashlib.sha256(payload.read()).hexdigest() != row["sha256"]):
                raise ValueError("Cargo component archive failed deterministic read-back")
    return {"path": destination.name, "bytes": destination.stat().st_size,
            "sha256": sha256(destination), "files": rows}


def _expected_native_rows(reference: dict, host: str, variant: str) -> dict:
    return reference["hosts"][host][variant]


def _project_lock(sdk_root: Path, components: dict[str, Path], host: str,
                  python_path: Path) -> dict:
    manifest_path = sdk_root / "contract/sdk.json"
    manifest = read_json(manifest_path, 16 * 1024**2)
    cargo_manifest = sdk_root / "Cargo.toml"
    cargo_lock = sdk_root / "Cargo.lock"
    if not cargo_manifest.is_file() or not cargo_lock.is_file():
        raise ValueError("prepared SDK workspace is missing locked Cargo inputs")
    return {"schema": "ami-rust-project-lock-v1",
            "sdk": {"root": str(sdk_root), "manifest": "contract/sdk.json",
                    "manifest_sha256": sha256(manifest_path)},
            "host": {"platform": host, "python": str(python_path.resolve(strict=True)),
                     "python_sha256": sha256(python_path)},
            "components": {name: str(root) for name, root in components.items()},
            "cargo": {"manifest_sha256": sha256(cargo_manifest),
                      "lock_sha256": sha256(cargo_lock)}}


def _prepare_layout(work: Path, host: str, sdk_source: Path, component_roots: dict[str, Path],
                    python_path: Path) -> list[dict]:
    layouts = []
    for layout_name in ("sdk-layout-a", "sdk-layout-b"):
        layout_root = work / layout_name
        layout_root.mkdir(exist_ok=True)
        sdk_root = layout_root / "sdk"
        if layout_name.endswith("a"):
            if sdk_source.resolve() == sdk_root.resolve():
                raise ValueError("first cold-root SDK must be copied from separate staging")
            _copy_tree(sdk_source, sdk_root)
        else:
            _copy_tree(work / "sdk-layout-a" / "sdk", sdk_root)
        component_dir = layout_root / "components"
        component_dir.mkdir(exist_ok=True)
        component_paths = {}
        for name in ("rust", "cargo", "toolchain", "collector", "csdk", "vendor"):
            destination = component_dir / name
            if layout_name.endswith("a"):
                source = component_roots[name]
                if source.resolve() == destination.resolve():
                    raise ValueError("first cold-root component must be copied from separate staging: " + name)
                _copy_tree(source, destination)
            else:
                _copy_tree(work / "sdk-layout-a" / "components" / name, destination)
            component_paths[name] = destination
        lock = _project_lock(sdk_root, component_paths, host, python_path)
        lock_path = layout_root / "project-lock.json"
        lock_path.write_bytes(canonical_json(lock))
        layouts.append({"name": layout_name, "root": layout_root, "sdk": sdk_root,
                        "components": component_paths, "lock": lock_path,
                        "lock_sha256": sha256(lock_path)})
    return layouts


def _copy_native_payload(source: Path, output: Path, variant: str) -> dict:
    native_dir = output / "native"
    native_dir.mkdir(exist_ok=True)
    destination = native_dir / (variant + ".AMIRUST")
    if destination.exists() or destination.is_symlink():
        raise ValueError("native output payload already exists")
    shutil.copyfile(source, destination)
    destination.chmod(0o755)
    return {"path": destination.relative_to(output).as_posix(),
            "bytes": destination.stat().st_size, "sha256": sha256(destination)}


def _preserve_native_payload(source: Path, work: Path, variant: str) -> Path:
    pending = work / "pending-native"
    pending.mkdir(exist_ok=True)
    destination = pending / (variant + ".AMIRUST")
    if destination.exists() or destination.is_symlink() or source.is_symlink() or not source.is_file():
        raise ValueError("native preservation source/destination is not a fresh regular file")
    shutil.copyfile(source, destination)
    destination.chmod(0o755)
    if destination.stat().st_size != source.stat().st_size or sha256(destination) != sha256(source):
        raise ValueError("preserved native build artifact differs from its source")
    return destination


def _validate_success_output(output: Path) -> int:
    allowed = {"producer.json", "sdk-producer.json", "csdk-producer.json", "sdk.tar.xz",
               "cargo-component.tar.xz"}
    allowed_native = {f"native/{name}.AMIRUST" for name in VARIANTS}
    observed = set()
    for path in output.rglob("*"):
        if path.is_dir() and not path.is_symlink():
            continue
        relative = path.relative_to(output).as_posix()
        if path.is_symlink() or not path.is_file() or relative not in allowed | allowed_native:
            raise ValueError("SDK output contains an unapproved or nonregular payload: " + relative)
        observed.add(relative)
    if observed != allowed | allowed_native:
        raise ValueError("SDK output is missing a required candidate payload")
    total = directory_bytes(output)
    if total > MAX_OUTPUT_BYTES:
        raise ValueError("host SDK artifact set exceeds the 32 MiB retention ceiling")
    return total


def _retire_successful_build(path: Path, work: Path) -> None:
    if path.is_symlink() or not path.is_dir() or not path.resolve().is_relative_to(work.resolve()):
        raise ValueError("native build output is not a managed regular directory")
    shutil.rmtree(path)
    if path.exists() or path.is_symlink():
        raise RuntimeError("successful native build output could not be retired")


def _verify_native_receipt(build_output: Path, reference_rows: dict,
                           supervisor: Supervisor, label: str) -> tuple[dict, Path]:
    receipt_path = build_output / "build-receipt.json"
    receipt = read_json(receipt_path, 4 * 1024**2)
    actual = receipt.get("canonical_artifacts")
    if not isinstance(actual, dict) or actual != reference_rows or len(actual) != len(reference_rows):
        raise ValueError("native canonical outputs differ from the accepted host reference: " + label)
    artifacts = build_output / "artifacts"
    observed = {}
    for name, row in actual.items():
        rel = _safe_relative(name)
        path = artifacts.joinpath(*rel.parts)
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_size != row["bytes"]
                or sha256(path) != row["sha256"]):
            raise ValueError("native output file differs from its canonical receipt: " + name)
        observed[name] = {"bytes": info.st_size, "sha256": row["sha256"]}
    actual_paths = {path.relative_to(artifacts).as_posix() for path in artifacts.rglob("*")
                    if path.is_file() or path.is_symlink()}
    if actual_paths != set(actual):
        raise ValueError("native artifact directory contains unrecorded or missing files")
    if receipt.get("host") != host_identity()[0]:
        raise ValueError("native build receipt identifies a different host")
    frontend = receipt.get("cargo_frontend", {})
    if not _is_digest(frontend.get("sha256")):
        raise ValueError("native build receipt omits its Cargo frontend identity")
    supervisor.check_limits("completed native build")
    return {"receipt_sha256": sha256(receipt_path), "artifacts": observed,
            "rss_peak_observed_bytes": max((row.get("rss_peak_observed_bytes", 0)
                                             for row in receipt.get("commands", [])), default=0),
            "elapsed_seconds": receipt.get("elapsed_seconds")}, artifacts / "AMIRUST"


def _native_command(layout: dict, variant: str, package: str, feature_args: tuple[str, ...],
                    python_path: Path, work: Path) -> tuple[list[str], Path]:
    build_parent = work / "build-results" / layout["name"]
    build_parent.mkdir(parents=True, exist_ok=True)
    build_output = build_parent / variant
    if build_output.exists() or build_output.is_symlink():
        raise ValueError("native build output must be fresh")
    command = [str(python_path), "-I", "-B", str(layout["sdk"] / "host/cli.py"),
               "build", "--sdk-lock", str(layout["lock"]),
               "--output-dir", str(build_output), "--", "build",
               "--manifest-path", str(layout["sdk"] / "Cargo.toml"),
               "--package", package, "--release", "--locked", "--offline", *feature_args]
    return command, build_output


def produce(args) -> dict:
    host, target = host_identity()
    linkage_audit_utility = resolve_linkage_audit_utility(host)
    host_csdk_tools = csdk_host_tools()
    if not args.work.is_absolute() or not args.output.is_absolute() or not args.python_bootstrap_root.is_absolute():
        raise ValueError("all managed roots must be absolute paths")
    if any(path.is_symlink() for path in (args.work, args.output, args.python_bootstrap_root)):
        raise ValueError("managed roots must not be symlinks")
    if args.work.exists() or args.output.exists():
        raise ValueError("SDK work and output directories must be fresh")
    if not args.work.parent.is_dir() or not args.output.parent.is_dir():
        raise ValueError("managed root parents must already exist")
    if (args.work.resolve().parent != args.output.resolve().parent
            or args.work.resolve().parent != args.python_bootstrap_root.resolve().parent):
        raise ValueError("work, output and pinned Python must be siblings on one managed volume")
    if args.python_bootstrap_root.name != "ami-rust-python-bootstrap":
        raise ValueError("pinned Python bootstrap root has the wrong managed name")
    if (args.work.resolve() == args.output.resolve()
            or args.work.resolve().is_relative_to(ROOT.resolve())
            or args.output.resolve().is_relative_to(ROOT.resolve())):
        raise ValueError("work and output must be fresh roots outside the source checkout")

    preflight_cargo_producers(args.resources)
    python_path, python_bootstrap = verify_python_bootstrap(args.python_bootstrap_root, host)
    env_root = args.work.resolve() / "sdk-task-env"
    env = {"HOME": str(env_root / "home"), "CARGO_HOME": str(env_root / "cargo-home"),
           "TMPDIR": str(env_root / "tmp"), "TMP": str(env_root / "tmp"),
           "TEMP": str(env_root / "tmp"),
           "PATH": str(python_path.parent) + ":/usr/bin:/bin:/usr/sbin:/sbin",
           "LC_ALL": "C", "TZ": "UTC", "GIT_TERMINAL_PROMPT": "0",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_OPTIONAL_LOCKS": "0", "CARGO_INCREMENTAL": "0",
           "SOURCE_DATE_EPOCH": "1791936000"}
    # Do not pass the workflow's ambient environment or credentials to helper
    # subprocesses. Each build receives only this controlled task environment.
    os.environ.clear()
    os.environ.update(env)
    inputs, resources, host_rows, capacity = load_normative(args.inputs, args.resources, host)
    native_reference_path = ROOT / inputs["native_reference"]["path"]
    reference = validate_native_reference(read_json(native_reference_path, 2 * 1024**2), inputs,
                                          inputs["native_reference"]["sha256"])
    cargo_inputs_path = args.cargo_inputs.resolve(strict=True)
    if (cargo_inputs_path != (ROOT / "release/ci-bootstrap-inputs.json").resolve(strict=True)
            or cargo_inputs_path.read_bytes() != (ROOT / "release/ci-bootstrap-inputs.json").read_bytes()):
        raise ValueError("--cargo-inputs must be the normative tracked Cargo bootstrap pins")
    cargo_inputs = read_json(cargo_inputs_path)
    if cargo_inputs.get("schema") != "ami-rust-ci-cargo-inputs-v1":
        raise ValueError("unrecognized hosted Cargo prerequisite inputs")
    resources_hash = sha256(args.resources)
    inputs_hash = sha256(args.inputs)
    capacity = validate_resource_policy(resources, args.work.parent)

    # This call creates --work and --output, provisions pinned Cargo under the
    # common managed work tree, and preserves its binary only below WORK.
    ci_cargo.produce(type("CargoArgs", (), {
        "work": args.work, "output": args.output, "inputs": cargo_inputs_path,
        "resources": args.resources.resolve(strict=True),
        "python_bootstrap_root": args.python_bootstrap_root})())
    cargo_report_path = args.output / "producer.json"
    local_cargo = read_json(cargo_report_path)
    if (local_cargo.get("status") != "PRODUCED_PREREQUISITE_ONLY_NOT_R1_QUALIFICATION"
            or local_cargo.get("host") != host or local_cargo.get("rust_target") != target):
        raise ValueError("pinned custom Cargo prerequisite did not complete for this host")
    frozen_cargo = verify_frozen_cargo_report(
        ROOT / "release/ci-cargo-producers" / (host + ".json"), host, target)
    require_cargo_match(local_cargo.get("custom_cargo_artifact"),
                        frozen_cargo.get("custom_cargo_artifact"))

    env_root.mkdir()
    for name in ("home", "cargo-home", "tmp"):
        (env_root / name).mkdir()
    supervisor = Supervisor(args.work, args.output, args.python_bootstrap_root, env)
    supervisor.peak_workspace = supervisor.managed_bytes()
    supervisor.peak_logs = supervisor.logs_bytes()
    supervisor.check_limits("post-Cargo preflight")
    channel_dir = args.work / "downloaded-inputs"
    channel_dir.mkdir(exist_ok=True)
    if supervisor.managed_bytes() + MAX_CHANNEL_MANIFEST_BYTES > MAX_WORK_BYTES:
        raise ValueError("Rust channel manifest download would exceed the managed workspace ceiling")
    channel_manifest_material = download_channel_manifest(
        inputs["channel_manifest"], channel_dir / "channel-rust-nightly.toml")
    channel_manifest_material["path"] = (channel_dir / "channel-rust-nightly.toml").relative_to(args.work).as_posix()
    supervisor.check_limits("pinned Rust channel manifest download")

    component_staging = args.work / "component-staging"
    component_staging.mkdir()
    components_root = component_staging
    prepared_root = args.work / "prepared-sdk"
    prepared_root.mkdir()
    producer_paths = {key: ROOT / "release/ci-cargo-producers" / (key + ".json")
                      for key in HOST_TARGETS}
    prepared_dir = prepared_root / "package"
    prepare_command = [str(python_path), "-I", "-B", str(ROOT / "release/prepare_sdk.py"),
                       "--source", str(ROOT), "--output", str(prepared_dir),
                       "--resources", str(args.resources.resolve(strict=True)),
                       "--production-candidate"]
    for profile in HOST_TARGETS:
        prepare_command.extend(["--cargo-producer", f"{profile}={producer_paths[profile]}"])
    prepared_output = supervisor.run_text(prepare_command, cwd=ROOT,
                                           label="prepare-source-sdk", timeout=300)
    prepared = json.loads(prepared_output, object_pairs_hook=unique_json)
    if (prepared.get("status") != "PREPARED_PRODUCTION_TRUST_CANDIDATE_NOT_R1_ACCEPTED"
            or prepared.get("qualification_only") is not False
            or prepared.get("cargo_binary_payload_included") is not False):
        raise ValueError("source SDK helper did not produce the non-qualification candidate package")
    supervisor.check_limits("prepared source SDK")
    sdk_archive = prepared_dir / prepared["archive"]
    sdk_info = _extract_sdk_archive(sdk_archive, prepared_root / "extracted",
                                    prepared["archive_sha256"], prepared["archive_bytes"],
                                    prepared["member_count"])
    source_tree_inventory = ci_cargo.tree_inventory(sdk_info["root"])
    component_info = _component_rows_from_sdk(sdk_info, host)

    rust_root, rust_archives, rust_extract_receipts = _install_rust(
        host_rows, inputs, args.work, components_root, supervisor)
    rust_version = supervisor.run_text([str(rust_root / "bin/rustc"), "-Vv"], cwd=args.work,
                                       label="sdk-rustc-version", timeout=30)
    if ("commit-hash: " + inputs["rust_commit"] not in rust_version
            or "LLVM version: " + inputs["rust_llvm"] not in rust_version
            or "host: " + target not in rust_version):
        raise ValueError("installed production Rust compiler commit/LLVM/host differs from pins")
    rust_inventory = verify_component(rust_root, component_info["rust"]["manifest"], "rust")

    downloaded_components = {}
    toolchain_pin = host_rows["toolchain"]
    toolchain_root, toolchain_material, toolchain_extract = _extract_pinned_component(
        toolchain_pin, "toolchain", args.work, components_root / "toolchain", supervisor)
    downloaded_components["toolchain"] = {**toolchain_material, "extraction": toolchain_extract}
    collector_pin = host_rows["collector"]
    collector_root, collector_material, collector_extract = _extract_pinned_component(
        collector_pin, "collector", args.work, components_root / "collector", supervisor,
        component_info["collector"]["manifest"])
    downloaded_components["collector"] = {**collector_material, "extraction": collector_extract}
    shared_materials = {}
    for name in ("vendor",):
        root, material = _extract_local_component(inputs["shared"][name], name,
                                                   components_root / name, supervisor)
        shared_materials[name] = material
    portable_csdk = produce_portable_csdk(inputs, toolchain_root, components_root / "csdk",
        args.work, args.output, python_path, host_csdk_tools, supervisor)
    shared_materials["csdk"] = {key: inputs["shared"]["csdk"][key] for key in ("path", "bytes", "sha256")}
    component_roots = {"rust": rust_root, "toolchain": toolchain_root,
                       "collector": collector_root, "csdk": components_root / "csdk",
                       "vendor": components_root / "vendor"}
    component_summaries = {"rust": rust_inventory}
    for name, root in (("toolchain", toolchain_root), ("collector", collector_root),
                       ("csdk", component_roots["csdk"]), ("vendor", component_roots["vendor"])):
        component_summaries[name] = verify_component(root, component_info[name]["manifest"], name)

    cargo_root, cargo_summary = _make_cargo_component(
        args.work, args.output, component_info, host, target, cargo_inputs, resources, supervisor)
    linkage_evidence = audit_cargo_linkage(
        host, cargo_root / "bin" / "cargo", linkage_audit_utility, supervisor)
    cargo_producer_record = read_json(cargo_root / "producer.json", 64 * 1024)
    component_roots["cargo"] = cargo_root
    component_summaries["cargo"] = verify_component(
        cargo_root, component_info["cargo"]["manifest"], "cargo")
    component_roots = {name: component_roots[name] for name in
                       ("rust", "cargo", "toolchain", "collector", "csdk", "vendor")}
    layouts = _prepare_layout(args.work, host, sdk_info["root"], component_roots, python_path)
    for layout in layouts:
        supervisor.run([str(python_path), "-I", "-B", str(layout["sdk"] / "host/cli.py"),
                        "verify", "--sdk-lock", str(layout["lock"])], cwd=args.work,
                       label="verify-" + layout["name"], timeout=60)

    cargo_archive = _canonical_cargo_archive(cargo_root, args.output / "cargo-component.tar.xz",
                                              component_info["cargo"]["manifest"])
    source_payload = _copy_flat_sdk_archive(sdk_archive, args.output / "sdk.tar.xz")
    build_records = []
    native_payloads = []
    by_variant = {}
    for layout in layouts:
        for variant, (package, feature_args) in VARIANTS.items():
            command, build_output = _native_command(layout, variant, package, feature_args,
                                                    python_path, args.work)
            run_record = supervisor.run(command, cwd=args.work,
                                         label=f"build-{layout['name']}-{variant}",
                                         timeout=MAX_COMMAND_SECONDS)
            result, native_file = _verify_native_receipt(
                build_output, _expected_native_rows(reference, host, variant), supervisor,
                layout["name"] + "/" + variant)
            native_hash = sha256(native_file)
            native_bytes = native_file.stat().st_size
            if layout["name"] == "sdk-layout-a":
                preserved = _preserve_native_payload(native_file, args.work, variant)
                by_variant[variant] = {"path": preserved, "sha256": native_hash,
                                       "bytes": native_bytes, "artifacts": result["artifacts"]}
            else:
                first = by_variant[variant]
                if (native_hash != first["sha256"] or native_bytes != first["bytes"]
                        or result["artifacts"] != first["artifacts"]):
                    raise ValueError("cold-root native outputs differ for " + variant)
                payload = _copy_native_payload(first["path"], args.output, variant)
                native_payloads.append({"variant": variant, **payload})
            build_records.append({"layout": layout["name"], "variant": variant,
                                  "package": package, "feature_arguments": list(feature_args),
                                  "process": run_record, "build_receipt_sha256": result["receipt_sha256"],
                                  "canonical_artifact_count": len(result["artifacts"]),
                                  "canonical_artifacts": result["artifacts"],
                                  "AMIRUST": {"bytes": native_bytes, "sha256": native_hash},
                                  "reference_match": True})
            _retire_successful_build(build_output, args.work)
            supervisor.check_limits("retired successful " + layout["name"] + "/" + variant)

    # Remove private construction roots only after both cold roots match every
    # accepted canonical output. A failure before here preserves evidence.
    for layout in layouts:
        if layout["root"].exists():
            shutil.rmtree(layout["root"])
        if layout["root"].exists():
            raise RuntimeError("consumed build root could not be retired")
    pending_native = args.work / "pending-native"
    if pending_native.exists():
        shutil.rmtree(pending_native)
    if pending_native.exists():
        raise RuntimeError("matched pending native artifacts could not be retired")
    for extra in (args.work / "archive-extraction", args.work / "downloaded-inputs",
                  component_staging, prepared_root, args.work / "portable-csdk-work",
                  args.work / "portable-csdk-output"):
        if extra.exists():
            shutil.rmtree(extra)
        if extra.exists():
            raise RuntimeError("verified input staging could not be retired")

    cargo_report_sha = sha256(cargo_report_path)
    producer_record = {
        "schema": RECEIPT_SCHEMA,
        "status": "PRODUCED_HOSTED_SDK_CANDIDATE_NOT_R1_ACCEPTED",
        "host": host, "rust_target": target,
        "claim": "Two cold native build roots matched the accepted canonical host outputs; no AROS guest, R1 acceptance, publisher verification, or release authorization.",
        "source": {"commit": prepared["source_commit"],
                   "sdk_manifest_sha256": sdk_info["manifest_sha256"],
                   "sdk_archive": source_payload,
                   "version": sdk_info["manifest"].get("version"),
                   "qualification_only": sdk_info["manifest"].get("qualification_only"),
                   "member_count": sdk_info["member_count"],
                   "inventory": source_tree_inventory},
        "inputs": {"sdk_inputs_sha256": inputs_hash, "cargo_inputs_sha256": sha256(cargo_inputs_path),
                   "resource_policy_sha256": resources_hash,
                   "native_reference_path": inputs["native_reference"]["path"],
                   "native_reference_sha256": inputs["native_reference"]["sha256"],
                   "native_reference_source_record_sha256": inputs["native_reference"]["basis_source_record_sha256"],
                   "python_bootstrap": {"archive_sha256": python_bootstrap["archive_sha256"],
                                         "runtime_sha256": python_bootstrap["runtime_sha256"]},
                   "rust_channel": inputs["rust_channel"], "rust_commit": inputs["rust_commit"],
                   "rust_llvm": inputs["rust_llvm"],
                   "channel_manifest": channel_manifest_material,
                   "rust_archives": rust_archives,
                   "rust_installer": rust_extract_receipts,
                   "toolchain": downloaded_components["toolchain"],
                   "collector": downloaded_components["collector"],
                   "shared": shared_materials,
                   "portable_csdk": portable_csdk,
                   "cargo_producer_receipt_sha256": cargo_report_sha},
        "components": component_summaries,
        "cargo_component": {**cargo_summary, "archive": cargo_archive,
                             "producer_report_path": cargo_summary["host_receipt_path"],
                             "producer_record": cargo_producer_record},
        "linkage_evidence": linkage_evidence,
        "native_reference": {"schema": REFERENCE_SCHEMA,
                             "source_record_sha256": reference["basis"]["source_record_sha256"],
                             "canonical_outputs_per_host": 104,
                             "canonical_outputs_by_variant": {name: len(reference["hosts"][host][name])
                                                               for name in VARIANTS},
                             "cold_roots_per_variant": 2,
                             "variants": list(VARIANTS)},
        "native_builds": build_records,
        "native_payloads": native_payloads,
        "budgets": {"jobs": 2, "rss_bytes": MAX_RSS_BYTES,
                    "command_seconds": MAX_COMMAND_SECONDS,
                    "workspace_bytes": MAX_WORK_BYTES, "log_bytes": MAX_LOG_BYTES,
                    "artifact_bytes": MAX_OUTPUT_BYTES},
        "capacity_preflight": capacity,
        "peaks": {"checkout_bytes": supervisor.checkout_bytes,
                  "managed_peak_bytes": supervisor.peak_workspace,
                  "rss_peak_observed_bytes": supervisor.peak_rss,
                  "log_peak_observed_bytes": supervisor.peak_logs,
                  "commands": supervisor.commands},
        "output_payloads": [source_payload, cargo_archive, *native_payloads],
    }
    receipt_path = args.output / "sdk-producer.json"
    receipt_path.write_bytes(canonical_json(producer_record))
    output_bytes = _validate_success_output(args.output)
    producer_record["output_bytes_observed"] = output_bytes
    receipt_path.write_bytes(canonical_json(producer_record))
    output_bytes = _validate_success_output(args.output)
    if output_bytes > MAX_OUTPUT_BYTES:
        raise ValueError("SDK host output exceeds its retention limit")
    supervisor.check_limits("completed SDK producer")
    return producer_record


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--cargo-inputs", type=Path, required=True)
    parser.add_argument("--resources", type=Path, required=True)
    parser.add_argument("--python-bootstrap-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        produce(args)
    except BaseException as error:
        try:
            if args.output.is_absolute() and args.output.is_dir() and not args.output.is_symlink():
                receipt_path = args.output / "sdk-producer.json"
                host, target = host_identity()
                error_text = str(error).replace(str(ROOT), "<checkout>")
                for managed in (args.work, args.output, args.python_bootstrap_root):
                    error_text = error_text.replace(str(managed), "<managed-path>")
                if receipt_path.is_file() and not receipt_path.is_symlink():
                    record = read_json(receipt_path, 8 * 1024**2)
                    record["status"] = "FAILED"
                    record["error_type"] = type(error).__name__
                    record["error"] = error_text.replace("\n", " ")[:2048]
                else:
                    record = {"schema": RECEIPT_SCHEMA, "status": "FAILED",
                              "host": host, "rust_target": target,
                              "error_type": type(error).__name__,
                              "error": error_text.replace("\n", " ")[:2048],
                              "claim": "Failed hosted SDK candidate attempt; no guest, R1 acceptance or publication claim."}
                receipt_path.write_bytes(canonical_json(record))
        except BaseException as receipt_error:
            print(f"ci_sdk: unable to write bounded failure receipt: {type(receipt_error).__name__}", file=sys.stderr)
        print(f"ci_sdk: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
