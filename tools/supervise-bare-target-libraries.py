#!/usr/bin/env python3
"""Run the internal bare-target library producer under the existing CI monitor."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import tomllib
import types

CI_CARGO_SHA = "589a8abc9fc4b0537b4b9646d441413f4eb005288bbc3ea0220f5218ffc18da2"
MONITOR_SHA = "8c809ff9ab2f22b17696931f0a5731a2154616f02c9a66232947f73f3b84e0d4"
RESOURCE_SHA = "b9a5fbfff842847c30b5f56ea4e1d3a368f4bda30689f0407ed9d33610571646"
H1_HELPER_SHA = "dfa41aa97181d7b2516e8f4b42b18793a2f35cdba969dd430be269adcf1754a3"
INPUTS_SHA = "d932be30b3f88ca6c77010d6f96e0449273970864250569b49cd6d391e37d1c2"
INPUT_BOOTSTRAP_SHA = "5733fb6599124b9d282a427b9c770d9d0b6fd57c369169be1f852f72c80896c6"
TOOLING_MANIFEST_SHA = "13ac0ca9ac4437c7ac77b066b5a044ea30f935ffef0446dad7146132eda12a3f"
TOOLING_LOCK_SHA = "9268b294c6d697a3914b735f775a0c2b0543e775de3f6bf10b2f964baf5de6cd"
TARGET_PIN_SHA = "33fdd3d97053370eb3db9e05ea75721dafcfc7f4b5f8c218acaab1911984c341"
TARGET_SPEC_SHA = "de7a0024aa94269641e3e6d480ce8cd334962bf7e02592b0652e19e56b5fba71"
TARGET_SPEC_PATH = "targets/x86_64-aros.json"
TARGET_ALIAS_PATH = "lib/rustlib/x86_64-aros/target.json"
TARGET_ALIAS_TARGET = "x86_64-aros.json"
BOOTSTRAP_RECORD_NAMES = {"excluded-installer-metadata.txt", "excluded-installer-state.txt",
                          "duplicate-identical-component-paths.txt"}
BOOTSTRAP_RECEIPT_MAX_BYTES = 1024 * 1024
XTASK_MODULE_SHA = "a2fd57fec83f1d32372b4aeac0a74445ad049a57875b26da371ed139ce48e0de"
XTASK_MAIN_SHA = "e88b12957bc6f16e4ba8743bdbaff873874ed24529fcd464e4a07ab47ffda842"
NATIVE_CARGO_COMMIT = "3efb1f477e99b42974b982d939fd100303cdf7db"
RUST_COMMIT = "330d317121e16b5db8e5adc63595910528ff2ee7"
LIMITS = {"rss_bytes": 4 * 1024**3, "workspace_bytes": 12 * 1024**3,
          "log_bytes": 16 * 1024**2, "command_seconds": 1200,
          "campaign_seconds": 5400, "review_reserve_seconds": 300}
SCHEMA = "ami-rust-bare-target-libraries-supervision-result-v1"
PRODUCER_SCHEMA = "ami-rust-bare-target-library-producer-v1"
PRODUCER_STATUS = "PRODUCED_BARE_TARGET_LIBRARIES_NOT_L1_OR_RC_QUALIFICATION"
BOOTSTRAP_SCHEMA = "ami-rust-bare-target-input-bootstrap-receipt-v1"
BOOTSTRAP_STATUS = "STAGED_INPUTS_ONLY_UNQUALIFIED"
INNER_COMMAND_LABELS = ("rustc-version", "rustc-sysroot", "cargo-version",
                        "rust-objcopy-version", "source-production")
INNER_LIMITS = {"seconds": 1200, "rss_bytes": 4 * 1024**3,
                "workspace_bytes": 12 * 1024**3, "log_bytes": 16 * 1024**2}
HOSTS = {
    "macos-aarch64": ("aarch64-apple-darwin", "Darwin", {"arm64", "aarch64"},
                      "tooling/crates/aros-native-build/pins/macos-aarch64/rust.json",
                      "9acf02ab3d4a22137b6c5f82294e35c518ff1ffdbad5a701d5f3cdb0910668ea",
                      "release/ci-bootstrap-inputs.json",
                      "5c3557a2696457d76562f8883efa2c7d2c4cfc583f4f5814a722907a1f639f81"),
    "linux-x86_64": ("x86_64-unknown-linux-gnu", "Linux", {"x86_64", "amd64"},
                     "tooling/crates/aros-native-build/pins/linux-x86_64/rust.json",
                     "7a88373f28d19d6d61494587240681999adfb2bec964b4c3d74fae9718f097e8",
                     "release/ci-bootstrap-inputs.json",
                     "5c3557a2696457d76562f8883efa2c7d2c4cfc583f4f5814a722907a1f639f81"),
    "linux-aarch64": ("aarch64-unknown-linux-gnu", "Linux", {"aarch64"},
                      "release/bare-target-libraries/linux-aarch64-rust.json",
                      "862be6c4c1d29c59fc774e2d38f046672fcd0aa0978a869be9af2752fb4f76ee",
                      "release/ci-bootstrap-linux-aarch64-inputs.json",
                      "60d8bab5bd3cc043e47b0cff2fc62e38285f2fa85be8fd5f7ce376a3623384d7"),
}
SYSTEM_PATH = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin"


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def require_file(repo: Path, relative: str, digest: str) -> Path:
    path = repo / relative
    if path.is_symlink() or not path.is_file() or sha(path) != digest:
        raise ValueError("pinned source input differs: " + relative)
    return path


def retain(source: Path, destination: Path, digest: str | None = None) -> dict:
    if source.is_symlink() or not source.is_file():
        raise ValueError("expected regular evidence file: " + str(source))
    actual = sha(source)
    if digest is not None and actual != digest:
        raise ValueError("evidence input hash mismatch: " + source.name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    if sha(destination) != actual:
        raise ValueError("copied evidence hash mismatch: " + destination.name)
    return {"path": destination.relative_to(destination.parents[1]).as_posix(),
            "bytes": destination.stat().st_size, "sha256": actual}


def import_monitor(repo: Path):
    path = require_file(repo, "tools/supervise-native-cargo.py", MONITOR_SHA)
    spec = importlib.util.spec_from_file_location("ami_rust_native_monitor", path)
    if spec is None or spec.loader is None:
        raise ValueError("cannot import the existing native-Cargo monitor helpers")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_checkout(args, artifact: Path) -> dict:
    env = os.environ
    host_key = env.get("BARE_HOST_KEY", "")
    host = HOSTS.get(host_key)
    if host is None:
        raise ValueError("unsupported host key")
    triple, system, machines, profile, profile_sha, h1_inputs, h1_sha = host
    if (env.get("BARE_HOST_TRIPLE") != triple or platform.system() != system
            or platform.machine().lower() not in machines):
        raise ValueError("selected host profile does not match the native runner")
    if (env.get("BARE_EVENT_NAME") != "workflow_dispatch"
            or env.get("BARE_REPOSITORY") != "metaneutrons/ami-rust"
            or env.get("BARE_REF_NAME") != "refs/heads/main"
            or env.get("BARE_REF_PROTECTED") != "true"
            or env.get("BARE_RUN_ID") != env.get("GITHUB_RUN_ID")
            or env.get("BARE_RUN_ATTEMPT") != env.get("GITHUB_RUN_ATTEMPT")):
        raise ValueError("run is not a protected manual main-branch invocation")
    mirrored = {"NATIVE_HOST_TRIPLE": triple, "NATIVE_EVENT_NAME": env.get("BARE_EVENT_NAME"),
                "NATIVE_REPOSITORY": env.get("BARE_REPOSITORY"), "NATIVE_REF_NAME": env.get("BARE_REF_NAME"),
                "NATIVE_REF_PROTECTED": env.get("BARE_REF_PROTECTED"),
                "NATIVE_RUN_ID": env.get("BARE_RUN_ID"), "NATIVE_RUN_ATTEMPT": env.get("BARE_RUN_ATTEMPT"),
                "NATIVE_CAMPAIGN_START_EPOCH": env.get("BARE_CAMPAIGN_START_EPOCH"),
                "NATIVE_MANAGED_ROOT": env.get("BARE_MANAGED_ROOT"),
                "NATIVE_OUTER_OUTPUT": env.get("BARE_OUTER_OUTPUT")}
    if any(not value or env.get(key) != value for key, value in mirrored.items()):
        raise ValueError("existing monitor environment bindings differ from the protected workflow inputs")
    for key in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_WORKSPACE", "RUNNER_TEMP"):
        if not env.get(key):
            raise ValueError("missing GitHub source/run binding: " + key)
    repo = args.repo.resolve(strict=True)
    if repo != (Path(env["GITHUB_WORKSPACE"]) / "source").resolve(strict=True):
        raise ValueError("driver repository path is not the checked-out source root")
    attempt = Path(env["RUNNER_TEMP"]) / "ami-rust-bare-target-libraries" / (env["GITHUB_RUN_ID"] + "-" + env["GITHUB_RUN_ATTEMPT"]) / host_key
    if (args.managed_root.resolve(strict=True) != (attempt / "managed").resolve(strict=True)
            or args.outer_output.resolve(strict=True) != (attempt / "outer-output").resolve(strict=True)):
        raise ValueError("managed/output directories are not this unique workflow attempt")
    if any(path.is_symlink() for path in (repo, args.managed_root, args.outer_output, artifact)):
        raise ValueError("source, work, output, and artifact roots must not be symbolic links")
    head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    tree = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=all"], text=True)
    if head != env["GITHUB_SHA"] or dirty or not (repo / ".git").is_dir():
        raise ValueError("source is not a clean exact GITHUB_SHA checkout")

    bound = {
        "release/ci_cargo.py": CI_CARGO_SHA,
        "release/ci-resources.json": RESOURCE_SHA,
        "tools/bootstrap-host-rust.sh": H1_HELPER_SHA,
        "tools/supervise-native-cargo.py": MONITOR_SHA,
        "tools/bootstrap-bare-target-inputs.sh": INPUT_BOOTSTRAP_SHA,
        "release/bare-target-libraries-inputs.json": INPUTS_SHA,
        "tooling/Cargo.toml": TOOLING_MANIFEST_SHA,
        "tooling/Cargo.lock": TOOLING_LOCK_SHA,
        "tooling/crates/aros-native-build/pins/target.json": TARGET_PIN_SHA,
        "targets/x86_64-aros.json": TARGET_SPEC_SHA,
        "tooling/crates/xtask/src/bare_target_producer.rs": XTASK_MODULE_SHA,
        "tooling/crates/xtask/src/main.rs": XTASK_MAIN_SHA,
        profile: profile_sha,
        h1_inputs: h1_sha,
    }
    source_files = {name: {"bytes": require_file(repo, name, digest).stat().st_size, "sha256": digest}
                    for name, digest in bound.items()}
    for name in (".cargo/config", ".cargo/config.toml", "tooling/.cargo/config", "tooling/.cargo/config.toml"):
        if (repo / name).exists() or (repo / name).is_symlink():
            raise ValueError("unexpected local Cargo config in checkout: " + name)
    manifest = json.loads((repo / "release/bare-target-libraries-inputs.json").read_text(encoding="utf-8"))
    if manifest.get("status") != "PROPOSAL_ONLY_INTERNAL_PRODUCER_INPUTS_NOT_ADMITTED":
        raise ValueError("bare-target manifest is not the frozen internal-only proposal")
    host_rows = [row for row in manifest.get("hosts", []) if row.get("host") == host_key]
    if len(host_rows) != 1 or host_rows[0].get("native_cargo", {}).get("artifact_id") is None:
        raise ValueError("manifest host/Cargo artifact row is missing or ambiguous")
    resources = json.loads((repo / "release/ci-resources.json").read_text(encoding="utf-8"))
    if resources.get("build") != {"jobs": 2, "rss_bytes": LIMITS["rss_bytes"],
                                  "seconds": LIMITS["command_seconds"],
                                  "workspace_bytes": LIMITS["workspace_bytes"],
                                  "log_bytes": LIMITS["log_bytes"]}:
        raise ValueError("tracked host-command budget differs from the shared Supervisor limits")
    start = int(env["BARE_CAMPAIGN_START_EPOCH"])
    return {"repo": repo, "head": head, "tree": tree, "host_key": host_key, "triple": triple,
            "profile": profile, "profile_sha": profile_sha, "h1_inputs": h1_inputs,
            "h1_sha": h1_sha, "start": start, "manifest": manifest, "host_row": host_rows[0],
            "source_files": source_files}


def remaining(start: int) -> int:
    value = LIMITS["campaign_seconds"] - (int(time.time()) - start) - LIMITS["review_reserve_seconds"]
    if value <= 0:
        raise RuntimeError("campaign review reserve prevents starting another command")
    return min(LIMITS["command_seconds"], value)


class Commands:
    def __init__(self, monitor, supervisor, artifact: Path, work: Path, start: int):
        self.monitor, self.supervisor, self.artifact, self.work, self.start = monitor, supervisor, artifact, work, start
        self.rows = []

    def run(self, label: str, argv: list[str], cwd: Path, *, token: str | None = None) -> dict:
        index = len(self.rows) + 1
        name = f"{index:02d}-{label}"
        requests = self.artifact / "outer-command-requests"
        results = self.artifact / "outer-command-results"
        requests.mkdir(exist_ok=True)
        results.mkdir(exist_ok=True)
        request_path = requests / f"{name}.json"
        result_path = results / f"{name}.json"
        timeout = remaining(self.start)
        request = {"schema": "ami-rust-bare-target-outer-command-request-v1", "label": label,
                   "argv": argv, "cwd": str(cwd), "timeout_seconds": timeout, "limits": LIMITS,
                   "environment": {key: value for key, value in self.supervisor.env.items() if key != "GH_TOKEN"},
                   "GH_TOKEN_present": bool(token)}
        write_json(request_path, request)
        before = len(self.supervisor.commands)
        error = None
        if token:
            self.supervisor.env["GH_TOKEN"] = token
        try:
            self.supervisor.run(argv, cwd=cwd, label=name, timeout=timeout)
        except BaseException as caught:
            error = f"{type(caught).__name__}: {str(caught)[:1000]}"
        finally:
            self.supervisor.env.pop("GH_TOKEN", None)
        row = self.supervisor.commands[before] if len(self.supervisor.commands) > before else None
        stdout_path = self.work / "command-logs" / f"{name}.stdout.log"
        stderr_path = self.work / "command-logs" / f"{name}.stderr.log"
        def stream(path):
            return ({"path": "outer-logs/" + path.name, "bytes": path.stat().st_size, "sha256": sha(path)}
                    if path.is_file() else {"path": "outer-logs/" + path.name, "present": False})
        result = {"schema": "ami-rust-bare-target-outer-command-result-v1", "label": label,
                  "status": "PASS" if row and row.get("exit_code") == 0 and not row.get("stop_reason") and not error else "FAILED",
                  "request": request_path.relative_to(self.artifact).as_posix(),
                  "request_sha256": sha(request_path), "supervisor": row,
                  "stdout": stream(stdout_path), "stderr": stream(stderr_path), "error": error}
        write_json(result_path, result)
        result["result"] = result_path.relative_to(self.artifact).as_posix()
        result["result_sha256"] = sha(result_path)
        self.rows.append(result)
        if result["status"] != "PASS":
            raise RuntimeError(error or "supervised command failed: " + label)
        return result


def copy_inputs(repo: Path, artifact: Path, host: dict) -> list[dict]:
    rows = []
    for relative, digest in [
        ("release/bare-target-libraries-inputs.json", INPUTS_SHA),
        (host["profile"], host["profile_sha"]),
        (host["h1_inputs"], host["h1_sha"]),
        ("tooling/Cargo.toml", TOOLING_MANIFEST_SHA),
        ("tooling/Cargo.lock", TOOLING_LOCK_SHA),
        ("tooling/crates/aros-native-build/pins/target.json", TARGET_PIN_SHA),
        ("targets/x86_64-aros.json", TARGET_SPEC_SHA),
    ]:
        destination = artifact / "input-provenance" / relative.replace("/", "__")
        row = retain(repo / relative, destination, digest)
        row["source_path"] = relative
        row["artifact_path"] = destination.relative_to(artifact).as_posix()
        rows.append(row)
    return rows


def validate_metadata(path: Path, lock_path: Path, repo: Path) -> dict:
    metadata = json.loads(path.read_text(encoding="utf-8"))
    if (type(metadata.get("version")) is not int or metadata.get("version") != 1
            or metadata.get("workspace_root") != str(repo / "tooling")):
        raise ValueError("offline tooling metadata has an unexpected workspace root")
    packages = metadata.get("packages")
    if not isinstance(packages, list) or any(not isinstance(row, dict) for row in packages):
        raise ValueError("offline tooling metadata has no packages array")
    registry = "registry+https://github.com/rust-lang/crates.io-index"
    local = {row.get("name") for row in packages if row.get("source") is None}
    if not {"ami-rust-core", "ami-rust-xtask", "aros-elf"} <= local:
        raise ValueError("offline metadata omits required local xtask packages")
    locked_data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    lock_rows = [row for row in locked_data.get("package", [])
                 if isinstance(row.get("source"), str) and row["source"].startswith("registry+")]
    locked_ids = {(row["name"], row["version"], row["source"]) for row in lock_rows}
    resolved_ids = {(row.get("name"), row.get("version"), row.get("source"))
                    for row in packages if row.get("source") == registry}
    if (len(locked_ids) != len(lock_rows) or len(resolved_ids) != sum(row.get("source") == registry for row in packages)
            or locked_ids != resolved_ids or any(row.get("source") not in (None, registry) for row in packages)):
        raise ValueError("resolved package name/version/source set differs from the locked crates.io closure")
    checksum_rows = []
    for row in lock_rows:
        checksum = row.get("checksum")
        if (not isinstance(checksum, str) or len(checksum) != 64
                or any(character not in "0123456789abcdef" for character in checksum)):
            raise ValueError("Cargo.lock registry package lacks a SHA-256 checksum")
        checksum_rows.append({"name": row["name"], "version": row["version"],
                              "source": row["source"], "checksum": checksum})
    checksum_rows.sort(key=lambda row: (row["name"], row["version"], row["source"]))
    checksum_identity = hashlib.sha256(json.dumps(checksum_rows, sort_keys=True, separators=(",", ":"))
                                       .encode("utf-8")).hexdigest()
    return {"bytes": path.stat().st_size, "sha256": sha(path), "metadata_version": metadata["version"],
            "registry_package_count": len(resolved_ids), "workspace_local_packages": sorted(local),
            "lock_registry_checksum_count": len(checksum_rows),
            "lock_registry_checksum_map_sha256": checksum_identity, "lock_sha256": sha(lock_path),
            "checksum_validation": "registry IDs matched Cargo.lock; Cargo fetch --locked ran in fresh private CARGO_HOME; Cargo metadata does not expose registry archive checksums"}


def _bound_existing_path(value: object, expected: Path, label: str) -> Path:
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise ValueError("A2 staging receipt has a non-absolute " + label + " path")
    supplied = Path(value)
    if supplied.is_symlink() or expected.is_symlink():
        raise ValueError("A2 staging receipt has a symbolic-link " + label + " path")
    try:
        actual_path = supplied.resolve(strict=True)
        expected_path = expected.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        raise ValueError("A2 staging receipt " + label + " path is unavailable") from error
    if actual_path != expected_path:
        raise ValueError("A2 staging receipt " + label + " path differs from the owned prefix")
    return actual_path


def validate_bootstrap_receipt(receipt: dict, prefix: Path, context: dict) -> None:
    """Bind the A2 receipt's identities and producer inputs to this exact owned prefix."""
    host_cargo = context["host_row"]["native_cargo"]
    member = host_cargo["member"]
    source_profile = receipt.get("source_profile")
    native_cargo = receipt.get("native_cargo")
    binary = native_cargo.get("binary") if isinstance(native_cargo, dict) else None
    target_spec = receipt.get("target_spec")
    target_alias = receipt.get("target_alias")
    if not all(isinstance(row, dict) for row in
               (source_profile, native_cargo, binary, target_spec, target_alias)):
        raise ValueError("A2 staging receipt omits a required identity or producer input object")
    if (receipt.get("schema") != BOOTSTRAP_SCHEMA or receipt.get("status") != BOOTSTRAP_STATUS
            or receipt.get("host") != context["host_key"]
            or receipt.get("manifest_sha256") != INPUTS_SHA
            or receipt.get("host_triple") != context["triple"]
            or source_profile.get("path") != context["profile"]
            or source_profile.get("sha256") != context["profile_sha"]
            or native_cargo.get("artifact_id") != host_cargo["artifact_id"]
            or binary.get("sha256") != member["sha256"]
            or binary.get("bytes") != member["bytes"]):
        raise ValueError("A2 staging receipt differs from the exact host input manifest")
    if (target_spec.get("path") != TARGET_SPEC_PATH
            or target_spec.get("sha256") != TARGET_SPEC_SHA
            or target_spec.get("staged_by_later_producer") is not True
            or target_alias.get("path") != TARGET_ALIAS_PATH
            or target_alias.get("target") != TARGET_ALIAS_TARGET
            or target_alias.get("materialized_by_later_producer") is not True):
        raise ValueError("A2 staging receipt differs from the exact producer target bindings")
    if prefix.is_symlink() or not prefix.is_dir():
        raise ValueError("A2 bootstrap prefix is not a physical directory")
    prefix = prefix.resolve(strict=True)
    source_sysroot = _bound_existing_path(receipt.get("source_sysroot"), prefix / "source-sysroot",
                                          "source sysroot")
    cargo_path = _bound_existing_path(binary.get("path"), prefix / "native-cargo/bin/cargo",
                                      "native Cargo")
    if not source_sysroot.is_dir() or not cargo_path.is_file() or not os.access(cargo_path, os.X_OK):
        raise ValueError("A2 staging receipt producer paths are not a directory and executable Cargo")
    return {"source_sysroot": source_sysroot, "native_cargo": cargo_path}


def retain_bootstrap_evidence(prefix: Path, artifact: Path) -> dict:
    """Copy only the receipt and small staging ledgers, including partial failure evidence."""
    if prefix.is_symlink():
        raise ValueError("A2 bootstrap prefix is a symbolic link")
    if not prefix.exists():
        return {"receipt": None, "records": []}
    if not prefix.is_dir():
        raise ValueError("A2 bootstrap prefix is not a directory")
    provenance = artifact / "input-provenance"
    if provenance.is_symlink() or not provenance.is_dir():
        raise ValueError("A2 input provenance destination is not a regular directory")
    result = {"receipt": None, "records": []}
    receipt = prefix / "bootstrap-inputs-receipt.json"
    if receipt.exists() or receipt.is_symlink():
        if receipt.is_symlink() or not receipt.is_file() or receipt.stat().st_size > BOOTSTRAP_RECEIPT_MAX_BYTES:
            raise ValueError("A2 bootstrap receipt is not a bounded regular file")
        destination = provenance / receipt.name
        source_sha = sha(receipt)
        if destination.exists() or destination.is_symlink():
            if destination.is_symlink() or not destination.is_file() or sha(destination) != source_sha:
                raise ValueError("retained A2 bootstrap receipt conflicts with its source")
        else:
            shutil.copyfile(receipt, destination)
        result["receipt"] = {"path": destination.relative_to(artifact).as_posix(),
                             "bytes": receipt.stat().st_size, "sha256": source_sha}

    records_root = prefix / "records"
    if records_root.exists() or records_root.is_symlink():
        if records_root.is_symlink() or not records_root.is_dir():
            raise ValueError("A2 bootstrap records root is not a regular directory")
        entries = sorted(records_root.iterdir())
        if len(entries) > 6:
            raise ValueError("A2 bootstrap records contain too many files")
        valid_entries = []
        for path in entries:
            allowed_members = (path.name == "rust-src-nightly.members.txt" or
                               (path.name.endswith(".members.txt") and
                                path.name.startswith(("rustc-nightly-", "rust-std-nightly-"))))
            if path.is_symlink() or not path.is_file() or not (allowed_members or path.name in BOOTSTRAP_RECORD_NAMES):
                raise ValueError("A2 bootstrap records contain an unexpected path or non-regular file")
            valid_entries.append(path)
        if sum(path.stat().st_size for path in valid_entries) > LIMITS["log_bytes"]:
            raise ValueError("A2 bootstrap record ledgers exceed the 16 MiB projection bound")
        destination_root = provenance / "bootstrap-records"
        if destination_root.exists() or destination_root.is_symlink():
            if destination_root.is_symlink() or not destination_root.is_dir():
                raise ValueError("retained A2 bootstrap records destination is not a directory")
            existing = {path.name: path for path in destination_root.iterdir()}
            if set(existing) != {path.name for path in valid_entries}:
                raise ValueError("retained A2 bootstrap records differ from their source inventory")
        else:
            destination_root.mkdir(mode=0o700)
            existing = {}
        for source in valid_entries:
            destination = destination_root / source.name
            if source.name in existing:
                if destination.is_symlink() or not destination.is_file() or sha(destination) != sha(source):
                    raise ValueError("retained A2 bootstrap record differs from its source")
            else:
                shutil.copyfile(source, destination)
                if sha(destination) != sha(source):
                    raise ValueError("copied A2 bootstrap record hash mismatch")
            result["records"].append({"path": destination.relative_to(artifact).as_posix(),
                                      "bytes": source.stat().st_size, "sha256": sha(source)})
    return result

def validate_inner_record(label: str, request_sha256: str, request: dict, record: dict) -> int:
    if (request.get("schema") != "ami-rust-native-command-qualification-request-v1"
            or request.get("limits") != INNER_LIMITS
            or record.get("schema") != "ami-rust-native-command-qualification-record-v1"
            or record.get("request_sha256") != request_sha256 or record.get("limits") != INNER_LIMITS
            or record.get("passed") is not True or record.get("refusal") is not None
            or record.get("capture_complete") is not True or record.get("capture_error") is not None
            or record.get("child_exit_code") != 0 or record.get("child_signal") is not None):
        raise ValueError("inner qualified command request/record does not match the pinned A4 contract: " + label)
    peak = record.get("aggregate_peak_rss_bytes")
    workspace = record.get("workspace_bytes_at_finish")
    logs = record.get("log_bytes_at_finish")
    if (type(peak) is not int or peak < 0 or peak > INNER_LIMITS["rss_bytes"]
            or type(workspace) is not int or workspace < 0 or workspace > INNER_LIMITS["workspace_bytes"]
            or type(logs) is not int or logs < 0 or logs > INNER_LIMITS["log_bytes"]):
        raise ValueError("inner qualified command resource totals are invalid: " + label)
    for stream_name in ("stdout", "stderr"):
        stream = record.get(stream_name)
        if (not isinstance(stream, dict) or type(stream.get("bytes")) is not int or stream["bytes"] < 0
                or not isinstance(stream.get("sha256"), str) or len(stream["sha256"]) != 64
                or any(character not in "0123456789abcdef" for character in stream["sha256"])):
            raise ValueError("inner qualified command stream metadata is invalid: " + label)
    return peak


def validate_producer(output: Path, receipt: dict, host_row: dict, profile_sha: str) -> dict:
    result_path = output / "producer.json"
    inventory_path = output / "component-inventory.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    if (result.get("schema") != PRODUCER_SCHEMA or result.get("status") != PRODUCER_STATUS
            or result.get("target") != "x86_64-aros" or result.get("rustc_commit") != RUST_COMMIT
            or result.get("input_profile_sha256") != profile_sha):
        raise ValueError("Rust producer receipt differs from pinned host/source/target inputs")
    cargo = result.get("native_cargo_override", {})
    pinned_cargo = receipt["native_cargo"]["binary"]
    manifest_cargo = host_row["native_cargo"]["member"]
    if (pinned_cargo.get("sha256") != manifest_cargo.get("sha256")
            or pinned_cargo.get("bytes") != manifest_cargo.get("bytes")
            or cargo.get("sha256") != pinned_cargo.get("sha256")
            or cargo.get("bytes") != pinned_cargo.get("bytes")):
        raise ValueError("producer native Cargo does not match the exact staged CI artifact")
    if sha(inventory_path) != result.get("scoped_component_inventory_sha256"):
        raise ValueError("complete producer component inventory digest mismatch")
    commands = result.get("qualification_commands")
    if (not isinstance(commands, list)
            or [row.get("label") if isinstance(row, dict) else None for row in commands] != list(INNER_COMMAND_LABELS)):
        raise ValueError("A4 requires five retained qualified commands, including rust-objcopy version")
    inner = []
    inner_peaks = []
    seen_paths = set()
    root = output.resolve(strict=True)
    for summary, label in zip(commands, INNER_COMMAND_LABELS, strict=True):
        if summary.get("passed") is not True or summary.get("child_exit_code") != 0:
            raise ValueError("producer contains a non-passing inner command summary")
        if not all(isinstance(summary.get(key), str) for key in
                   ("record_path", "request_path", "result_sha256", "request_sha256")):
            raise ValueError("inner command summary paths/digests are malformed")
        record_input = Path(summary["record_path"])
        request_input = Path(summary["request_path"])
        if record_input.is_symlink() or request_input.is_symlink():
            raise ValueError("inner command record/request must not be symbolic links")
        record_path = record_input.resolve(strict=True)
        request_path = request_input.resolve(strict=True)
        record_key = record_path.relative_to(root).as_posix() if record_path.is_relative_to(root) else ""
        request_key = request_path.relative_to(root).as_posix() if request_path.is_relative_to(root) else ""
        if (record_key != f"records/{label}/result.json" or request_key != f"requests/{label}.json"
                or record_key in seen_paths or request_key in seen_paths
                or record_key == request_key or not record_path.is_file() or not request_path.is_file()
                or sha(record_path) != summary["result_sha256"]
                or sha(request_path) != summary["request_sha256"]):
            raise ValueError("inner command record/request escapes output or differs from its digest")
        seen_paths.update((record_key, request_key))
        record = json.loads(record_path.read_text(encoding="utf-8"))
        request = json.loads(request_path.read_text(encoding="utf-8"))
        if not isinstance(request, dict) or not isinstance(record, dict):
            raise ValueError("inner command request/record is not a JSON object")
        resource_report = record.get("resource_report")
        if (not isinstance(resource_report, dict) or resource_report.get("incomplete_cleanup") is not False
                or resource_report.get("last_sample_complete") is not True
                or type(resource_report.get("sample_count")) is not int
                or resource_report["sample_count"] < 1):
            raise ValueError("inner command cleanup or resource sampling is incomplete")
        peak = validate_inner_record(label, summary["request_sha256"], request, record)
        for stream_name in ("stdout", "stderr"):
            stream = record[stream_name]
            digest = stream.get("sha256")
            if (type(stream.get("bytes")) is not int or stream["bytes"] < 0
                    or not isinstance(digest, str) or len(digest) != 64
                    or any(character not in "0123456789abcdef" for character in digest)):
                raise ValueError("inner command stream digest is malformed")
            log_path = record_path.parent / f"{stream_name}.log"
            if (log_path.is_symlink() or not log_path.is_file() or log_path.stat().st_size != stream["bytes"]
                    or sha(log_path) != digest):
                raise ValueError("inner command raw log differs from its recorded size/digest")
        inner_peaks.append(peak)
        inner.append({"label": summary["label"], "request_sha256": summary["request_sha256"],
                      "result_sha256": summary["result_sha256"], "child_exit_code": 0,
                      "aggregate_peak_rss_bytes": peak})
    libraries = result.get("libraries")
    expected = {"core", "alloc", "compiler_builtins"}
    if not isinstance(libraries, list) or len(libraries) != 3 or {row.get("crate") for row in libraries} != expected:
        raise ValueError("producer did not return exactly core, alloc, and compiler_builtins")
    for row in libraries:
        path = (output / "libraries" / row["path"]).resolve(strict=True)
        if not path.is_relative_to((output / "libraries").resolve(strict=True)):
            raise ValueError("producer library path escapes its output directory")
        if path.stat().st_size != row["bytes"] or sha(path) != row["sha256"]:
            raise ValueError("producer library bytes/hash differ from the receipt")
    return {"status": result["status"], "sha256": sha(result_path),
            "component_inventory_sha256": sha(inventory_path), "qualification_commands": inner,
            "inner_peak_rss_bytes": max(inner_peaks),
            "libraries": sorted([{"crate": row["crate"], "bytes": row["bytes"], "sha256": row["sha256"]}
                                 for row in libraries], key=lambda row: row["crate"])}


def retained_inner_resources(output: Path) -> tuple[list[dict], list[str]]:
    records_root = output / "records"
    rows = []
    errors = []
    if not records_root.exists():
        return rows, errors
    if records_root.is_symlink() or not records_root.is_dir():
        return rows, ["producer records root is not a regular directory"]
    label_order = {label: index for index, label in enumerate(INNER_COMMAND_LABELS)}
    paths = sorted(records_root.glob("*/result.json"),
                   key=lambda path: (label_order.get(path.parent.name, len(label_order)), path.parent.name))
    for path in paths:
        label = path.parent.name
        if path.is_symlink() or not path.is_file():
            errors.append(label + ": result is not a regular file")
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            peak = record.get("aggregate_peak_rss_bytes")
            if type(peak) is not int or peak < 0:
                errors.append(label + ": aggregate RSS is missing or invalid")
                peak_value = None
            else:
                peak_value = peak
            rows.append({"label": label, "path": path.relative_to(output).as_posix(),
                         "sha256": sha(path), "passed": record.get("passed"),
                         "aggregate_peak_rss_bytes": peak_value})
        except (OSError, UnicodeError, json.JSONDecodeError, AttributeError) as error:
            errors.append(label + ": " + type(error).__name__)
    return rows, errors


def run(args) -> int:
    artifact = args.outer_output / "artifact"
    payload = {"schema": SCHEMA, "status": "FAILED",
               "claim": "Internal bare-target libraries prerequisite only; not SDK, L1, RC4, or publication acceptance",
               "limits": LIMITS, "outer_commands": [],
               "observation_boundaries": ["host checkout, preflight, and artifact upload are outside the process monitor",
                                          "all eight maintainer commands use the existing Supervisor",
                                          "raw pinned Rust/Cargo staging and target profile inventory are owned by the frozen A2 helper and Rust producer"]}
    context = monitor = cargo_monitor = supervisor = commands = None
    work = args.managed_root
    logs = work / "command-logs"
    start_mono = time.monotonic()
    log_peak = 0
    current_stage = "checkout-guard"
    prefix = None
    bootstrap_projection = None
    bootstrap_projection_done = False
    outer_full_peak = 0
    producer_parent_peak = 0
    producer_parent_samples = 0
    parent_rss_reserve = 512 * 1024**2
    try:
        context = verify_checkout(args, artifact)
        monitor = import_monitor(context["repo"])
        cargo_monitor = monitor._load_supervisor(context["repo"])
        for name in ("home", "cargo-home", "rustup-home", "tmp", "gh-config", "command-logs"):
            path = work / name
            if path.exists() or path.is_symlink():
                raise ValueError("managed root is not fresh: " + name)
            path.mkdir(mode=0o700)
        for name in ("input-provenance", "bin", "outer-command-requests", "outer-command-results"):
            (artifact / name).mkdir(mode=0o700, exist_ok=False)
        provenance = copy_inputs(context["repo"], artifact, {
            "profile": context["profile"], "profile_sha": context["profile_sha"],
            "h1_inputs": context["h1_inputs"], "h1_sha": context["h1_sha"]})

        env = monitor._supervised_env()
        env.update({"HOME": str(work / "home"), "CARGO_HOME": str(work / "cargo-home"),
                    "RUSTUP_HOME": str(work / "rustup-home"), "TMPDIR": str(work / "tmp"),
                    "TMP": str(work / "tmp"), "TEMP": str(work / "tmp"), "PATH": SYSTEM_PATH,
                    "LC_ALL": "C", "TZ": "UTC", "GIT_TERMINAL_PROMPT": "0",
                    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                    "CARGO_NET_RETRY": "0", "CARGO_HTTP_TIMEOUT": "60", "CARGO_TERM_COLOR": "never",
                    "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0", "CARGO_NET_OFFLINE": "false"})
        supervisor = cargo_monitor.Supervisor(work, args.outer_output, env, logs)
        supervisor.initial_work_bytes = 0
        supervisor.initial_output_bytes = 0
        original_rss = cargo_monitor.rss_group
        original_own = monitor._own_hwm_bytes
        parent_rss_reserve = monitor.PARENT_RSS_RESERVE
        def observe(pid, rows=None):
            nonlocal outer_full_peak, producer_parent_peak, producer_parent_samples
            rows = cargo_monitor.process_rows() if rows is None else rows
            own_peak = original_own()
            full_peak = own_peak + original_rss(pid, rows)
            outer_full_peak = max(outer_full_peak, full_peak)
            if current_stage == "produce-bare-target-libraries":
                direct_root_rss = sum(kib * 1024 for _, _, pgid, kib in rows if pgid == pid)
                producer_parent = own_peak + direct_root_rss
                producer_parent_peak = max(producer_parent_peak, producer_parent)
                producer_parent_samples += 1
                if producer_parent > parent_rss_reserve:
                    raise RuntimeError("active A4 producer exceeded the 512 MiB Python/xtask parent reserve")
            return full_peak
        cargo_monitor.rss_group = observe
        def all_logs(self):
            nonlocal log_peak
            value = monitor.logical_log_bytes(self.work, self.output)
            log_peak = max(log_peak, value)
            return value
        supervisor.logs_bytes = types.MethodType(all_logs, supervisor)
        commands = Commands(cargo_monitor, supervisor, artifact, work, context["start"])
        repo = context["repo"]
        host_key = context["host_key"]
        triple = context["triple"]
        host_bin_root = work / "h1-host-rust/toolchain/bin"
        current_stage = "install-h1-host-rust"
        commands.run("bootstrap-host-rust", ["/bin/bash", str(repo / "tools/bootstrap-host-rust.sh"),
                      str(host_bin_root.parent.parent), triple], repo)
        cargo = host_bin_root / "cargo"
        rustc = host_bin_root / "rustc"
        rustdoc = host_bin_root / "rustdoc"
        if not all(path.is_file() and os.access(path, os.X_OK) for path in (cargo, rustc, rustdoc)):
            raise ValueError("pinned H1 setup did not stage host Cargo/rustc/rustdoc")
        h1 = json.loads((repo / context["h1_inputs"]).read_text(encoding="utf-8"))["rust"]
        supervisor.env.update({"PATH": str(host_bin_root) + ":" + SYSTEM_PATH,
                                "RUSTC": str(rustc), "RUSTDOC": str(rustdoc),
                                "CARGO_TARGET_DIR": str(work / "xtask-target")})
        current_stage = "record-h1-versions"
        commands.run("h1-rustc-version", [str(rustc), "-Vv"], repo)
        commands.run("h1-cargo-version", [str(cargo), "-Vv"], repo)
        rustc_text = (logs / "02-h1-rustc-version.stdout.log").read_text(encoding="utf-8", errors="replace")
        cargo_text = (logs / "03-h1-cargo-version.stdout.log").read_text(encoding="utf-8", errors="replace")
        if f"commit-hash: {h1['commit']}" not in rustc_text or "1.98.1" not in rustc_text:
            raise ValueError("rustc version does not match the selected H1 profile")
        if f"commit-hash: {h1['cargo_commit']}" not in cargo_text or "1.98.1" not in cargo_text:
            raise ValueError("Cargo version does not match the selected H1 profile")

        current_stage = "fetch-and-verify-locked-tooling"
        commands.run("cargo-fetch-tooling", [str(cargo), "fetch", "--locked", "--manifest-path",
                      str(repo / "tooling/Cargo.toml")], repo)
        supervisor.env["CARGO_NET_OFFLINE"] = "true"
        commands.run("cargo-metadata-tooling", [str(cargo), "metadata", "--format-version", "1",
                      "--locked", "--offline", "--manifest-path", str(repo / "tooling/Cargo.toml")], repo)
        metadata_path = logs / "05-cargo-metadata-tooling.stdout.log"
        metadata_copy = artifact / "input-provenance/tooling-cargo-metadata.json"
        shutil.copyfile(metadata_path, metadata_copy)
        metadata_identity = validate_metadata(metadata_copy, repo / "tooling/Cargo.lock", repo)
        current_stage = "build-protected-xtask"
        commands.run("cargo-build-xtask", [str(cargo), "build", "--locked", "--offline",
                      "--manifest-path", str(repo / "tooling/Cargo.toml"), "--package", "ami-rust-xtask",
                      "--bin", "ami-rust-xtask", "--release", "--target-dir", str(work / "xtask-target")], repo)
        binary = work / "xtask-target/release/ami-rust-xtask"
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError("protected source build did not produce ami-rust-xtask")
        kept_binary = artifact / "bin/ami-rust-xtask"
        shutil.copyfile(binary, kept_binary)
        kept_binary.chmod(0o755)
        if sha(binary) != sha(kept_binary):
            raise ValueError("retained xtask binary differs from the built file")
        header = kept_binary.read_bytes()[:20]
        if host_key == "macos-aarch64":
            if header[:4] != b"\xcf\xfa\xed\xfe" or int.from_bytes(header[4:8], "little") != 0x0100000C:
                raise ValueError("retained producer is not arm64 Mach-O")
            binary_format, architecture = "Mach-O 64-bit", "arm64"
        else:
            expected_machine = 62 if host_key == "linux-x86_64" else 183
            if header[:4] != b"\x7fELF" or header[4:6] != b"\x02\x01" or int.from_bytes(header[18:20], "little") != expected_machine:
                raise ValueError("retained producer is not an ELF64 binary for this host")
            binary_format, architecture = "ELF64 little-endian", triple.split("-", 1)[0]

        current_stage = "stage-exact-raw-inputs"
        token = os.environ.get("GH_TOKEN")
        if not token:
            raise ValueError("workflow GH_TOKEN is required for the frozen Cargo artifact")
        prefix = work / "bare-target-inputs"
        commands.run("bootstrap-bare-target-inputs", ["/bin/bash", str(repo / "tools/bootstrap-bare-target-inputs.sh"),
                      host_key, str(prefix)], repo, token=token)
        receipt_path = prefix / "bootstrap-inputs-receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        bootstrap_paths = validate_bootstrap_receipt(receipt, prefix, context)
        bootstrap_projection = retain_bootstrap_evidence(prefix, artifact)
        bootstrap_projection_done = True
        receipt_copy = artifact / "input-provenance/bootstrap-inputs-receipt.json"

        current_stage = "produce-bare-target-libraries"
        producer_work = work / "bare-target-producer-work"
        producer_output = artifact / "producer"
        commands.run("bare-target-libraries", [str(kept_binary), "bare-target-libraries", "--host", host_key,
                      "--rust-profile", str(repo / context["profile"]), "--host-rust", str(bootstrap_paths["source_sysroot"]),
                      "--native-cargo", str(bootstrap_paths["native_cargo"]), "--target-pin",
                      str(repo / "tooling/crates/aros-native-build/pins/target.json"), "--target-spec",
                      str(repo / "targets/x86_64-aros.json"), "--work", str(producer_work), "--output",
                      str(producer_output)], repo)
        producer = validate_producer(producer_output, receipt, context["host_row"], context["profile_sha"])
        artifact_files = cargo_monitor.tree_inventory(artifact)
        if artifact_files["regular_file_bytes"] > 127 * 1024**2:
            raise ValueError("retained artifact exceeds the 127 MiB payload cap")
        payload.update({"status": "PREREQUISITE_ONLY", "stage": "complete",
                        "repository": os.environ["GITHUB_REPOSITORY"], "ref": os.environ["GITHUB_REF"],
                        "source": {"head": context["head"], "tree": context["tree"],
                                   "files": context["source_files"]},
                        "host": {"key": host_key, "triple": triple}, "target": "x86_64-aros",
                        "host_profile": {"path": context["profile"], "sha256": context["profile_sha"]},
                        "native_cargo_artifact": context["host_row"]["native_cargo"],
                        "h1_inputs": {"path": context["h1_inputs"], "sha256": context["h1_sha"]},
                        "retained_inputs": provenance, "tooling_metadata": metadata_identity,
                        "xtask_binary": {"path": "bin/ami-rust-xtask", "bytes": kept_binary.stat().st_size,
                                         "sha256": sha(kept_binary), "source_main_sha256": XTASK_MAIN_SHA,
                                         "format": binary_format, "architecture": architecture,
                                         "producer_module_sha256": XTASK_MODULE_SHA,
                                         "h1_rustc_commit": h1["commit"], "h1_cargo_commit": h1["cargo_commit"]},
                        "bootstrap_receipt_sha256": sha(receipt_copy),
                        "bootstrap_evidence_projection": bootstrap_projection, "producer": producer,
                        "artifact_inventory": artifact_files,
                        "status_boundary": "PREREQUISITE_ONLY; temporary Python monitor remains; no SDK/L1/RC4/publication claim"})
    except BaseException as error:
        payload.update({"status": "FAILED", "stage": current_stage,
                        "error": f"{type(error).__name__}: {str(error)[:1200]}",
                        "source": ({"head": context["head"], "tree": context["tree"]} if context else None)})
    finally:
        if commands is not None:
            payload["outer_commands"] = commands.rows
        if prefix is not None and artifact.is_dir():
            try:
                if not bootstrap_projection_done:
                    bootstrap_projection = retain_bootstrap_evidence(prefix, artifact)
                    bootstrap_projection_done = True
                if bootstrap_projection is not None:
                    payload["bootstrap_evidence_projection"] = bootstrap_projection
            except BaseException as error:
                payload["status"] = "FAILED"
                payload["error"] = payload.get("error") or (
                    f"A2 partial evidence projection failed: {type(error).__name__}: {str(error)[:800]}")
        if supervisor is not None and monitor is not None:
            inner_rows, inner_errors = retained_inner_resources(artifact / "producer")
            inner_labels = [row["label"] for row in inner_rows]
            inner_complete = (inner_labels == list(INNER_COMMAND_LABELS) and not inner_errors
                              and all(row["passed"] is True for row in inner_rows))
            inner_peaks = [row["aggregate_peak_rss_bytes"] for row in inner_rows
                           if type(row["aggregate_peak_rss_bytes"]) is int]
            inner_peak = max(inner_peaks, default=0)
            outer_peak = max(supervisor.peak_rss, outer_full_peak)
            if payload.get("status") == "PREREQUISITE_ONLY" and (not inner_complete or producer_parent_samples == 0):
                payload["status"] = "FAILED"
                payload["error"] = payload.get("error") or "complete inner records/producer parent RSS samples are unavailable"
            payload["producer_inner_resource_records"] = inner_rows
            payload["observed"] = {
                "aggregate_rss_upper_bound_bytes": max(outer_peak, inner_peak + producer_parent_peak),
                "aggregate_rss_measurement_complete": inner_complete and producer_parent_samples > 0,
                "outer_supervisor_peak_rss_bytes": outer_peak,
                "producer_inner_peak_rss_bytes": inner_peak,
                "producer_parent_peak_rss_bytes": producer_parent_peak,
                "producer_parent_rss_reserve_bytes": parent_rss_reserve,
                "producer_parent_rss_samples": producer_parent_samples,
                "producer_inner_record_count": len(inner_rows),
                "producer_inner_record_errors": inner_errors,
                "workspace_peak_bytes": max(supervisor.peak_workspace,
                    cargo_monitor.directory_bytes(args.repo) + cargo_monitor.directory_bytes(work)
                    + cargo_monitor.directory_bytes(args.outer_output)),
                "aggregate_raw_log_peak_bytes": max(log_peak, monitor.logical_log_bytes(work, args.outer_output)),
                "command_elapsed_seconds": round(time.monotonic() - start_mono, 3),
                "campaign_elapsed_seconds": max(0, int(time.time()) - int(os.environ.get("BARE_CAMPAIGN_START_EPOCH", str(int(time.time()))))),
            }
            observed = payload["observed"]
            if (observed["aggregate_rss_upper_bound_bytes"] > LIMITS["rss_bytes"]
                    or observed["producer_parent_peak_rss_bytes"] > observed["producer_parent_rss_reserve_bytes"]
                    or observed["workspace_peak_bytes"] > LIMITS["workspace_bytes"]
                    or observed["aggregate_raw_log_peak_bytes"] > LIMITS["log_bytes"]
                    or observed["campaign_elapsed_seconds"] > LIMITS["campaign_seconds"] - LIMITS["review_reserve_seconds"]
                    or not observed["aggregate_rss_measurement_complete"]):
                payload["status"] = "FAILED"
                payload["error"] = payload.get("error") or "final resource accounting exceeded its bound or was incomplete"
        if logs.is_dir() and artifact.is_dir():
            try:
                outer_logs = artifact / "outer-logs"
                outer_logs.mkdir(exist_ok=True)
                for source in logs.iterdir():
                    if source.is_file() and not source.is_symlink():
                        shutil.move(str(source), outer_logs / source.name)
            except BaseException as error:
                payload["status"] = "FAILED"
                payload["error"] = payload.get("error") or f"could not retain outer logs: {type(error).__name__}"
        if artifact.is_dir():
            try:
                result_path = artifact / "bare-target-supervision-result.json"
                if cargo_monitor is None or not args.repo.exists():
                    write_json(result_path, payload)
                else:
                    for _ in range(5):
                        write_json(result_path, payload)
                        size_before = (cargo_monitor.directory_bytes(args.repo)
                                       + cargo_monitor.directory_bytes(work)
                                       + cargo_monitor.directory_bytes(args.outer_output))
                        payload.setdefault("observed", {})["workspace_bytes_after_result"] = size_before
                        if size_before > LIMITS["workspace_bytes"]:
                            payload["status"] = "FAILED"
                            payload["error"] = payload.get("error") or "serialized evidence exceeds workspace limit"
                        write_json(result_path, payload)
                        size_after = (cargo_monitor.directory_bytes(args.repo)
                                      + cargo_monitor.directory_bytes(work)
                                      + cargo_monitor.directory_bytes(args.outer_output))
                        if cargo_monitor.tree_inventory(artifact)["regular_file_bytes"] > 127 * 1024**2:
                            payload["status"] = "FAILED"
                            payload["error"] = payload.get("error") or "final artifact exceeds its 127 MiB payload cap"
                            write_json(result_path, payload)
                        if size_after == size_before:
                            break
                    else:
                        payload["status"] = "FAILED"
                        payload["error"] = payload.get("error") or "final workspace accounting did not stabilize"
                        write_json(result_path, payload)
            except BaseException as error:
                payload["status"] = "FAILED"
                payload["error"] = payload.get("error") or f"result serialization failed: {type(error).__name__}"
                try:
                    write_json(artifact / "bare-target-supervision-result.json", payload)
                except OSError:
                    pass
    return 0 if payload.get("status") == "PREREQUISITE_ONLY" else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--managed-root", type=Path, required=True)
    parser.add_argument("--outer-output", type=Path, required=True)
    args = parser.parse_args()
    try:
        return run(args)
    except BaseException as error:
        print(f"bare-target driver input error: {type(error).__name__}: {str(error)[:500]}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
