#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Bounded, source-only native Linux query of the pinned upstream Cargo graph.
# The existing SDK CI supervisor owns the process/resource boundary.
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo 'usage: rc0-cargo-source-closure.sh FRESH_WORK_ROOT EXISTING_OUTPUT_ROOT' >&2
  echo '       rc0-cargo-source-closure.sh --verify-lock CARGO_LOCK_COPY' >&2
  exit 2
fi

exec python3 -I -B - "$@" <<'PY'
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time
import tomllib


ROOT = Path.cwd().resolve(strict=True)
LOCK_SHA256 = "b4ccfa53ccf8d7360c0359c1533d801759629f9cdd486d9a0a88e512717058d9"
LOCK_BYTES = 136479
CARGO_COMMIT = "3efb1f477e99b42974b982d939fd100303cdf7db"
CARGO_REMOTE = "https://github.com/rust-lang/cargo.git"
PATCH_SHA256 = "1f22b7e2c6a7f4469cc6c2f4a84019d8d8ade558e78241d1e996d88a7f1de97f"
TARGET = "x86_64-unknown-linux-gnu"
EXPECTED_PACKAGES = 550
EXPECTED_REGISTRY_PACKAGES = 523
EXPECTED_WORKSPACE_PACKAGES = 27
MAX_CRATE_BYTES = 16 * 1024**2
MAX_CRATE_TOTAL_BYTES = 384 * 1024**2
MAX_OUTPUT_BYTES = 32 * 1024**2 - 64 * 1024
SYSTEM_PATH = "/usr/bin:/bin"
STARTED = time.monotonic()
DEADLINE = STARTED + 900
COMMANDS: list[dict] = []


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def remaining_seconds() -> int:
    remaining = int(DEADLINE - time.monotonic())
    if remaining <= 0:
        raise TimeoutError("15-minute source-closure ceiling reached")
    return remaining


def run(label: str, argv: list[str], *, cwd: Path, env: dict[str, str],
        stdout_path: Path | None = None, stderr_path: Path | None = None,
        input_bytes: bytes | None = None, timeout: int = 300,
        expected: str = "zero") -> dict:
    stdout_path = stdout_path or (OUTPUT / "commands" / (label + ".stdout.log"))
    stderr_path = stderr_path or (OUTPUT / "commands" / (label + ".stderr.log"))
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    row = {
        "label": label,
        "argv": [str(part) for part in argv],
        "cwd": str(cwd),
        "environment": dict(sorted(env.items())),
        "stdin_sha256": hashlib.sha256(input_bytes).hexdigest() if input_bytes is not None else None,
        "expected_status": expected,
        "status": "RUNNING",
    }
    try:
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            completed = subprocess.run(
                argv, cwd=cwd, env=env, input=input_bytes,
                stdin=subprocess.DEVNULL if input_bytes is None else None,
                stdout=stdout, stderr=stderr, timeout=min(timeout, remaining_seconds()),
                check=False,
            )
        code = completed.returncode
        accepted = (code == 0) if expected == "zero" else (code != 0)
        row.update({
            "exit_code": code,
            "accepted": accepted,
            "stdout": {"path": str(stdout_path.relative_to(OUTPUT)),
                       "bytes": stdout_path.stat().st_size, "sha256": sha256(stdout_path)},
            "stderr": {"path": str(stderr_path.relative_to(OUTPUT)),
                       "bytes": stderr_path.stat().st_size, "sha256": sha256(stderr_path)},
        })
        if not accepted:
            row["status"] = "UNEXPECTED_EXIT_STATUS"
        else:
            row["status"] = "EXPECTED_NONZERO" if expected == "nonzero" else "SUCCESS"
    except BaseException as error:
        row.update({"status": "EXCEPTION", "error": type(error).__name__ + ": " + str(error)[:1000]})
        if stdout_path.exists():
            row["stdout"] = {"path": str(stdout_path.relative_to(OUTPUT)),
                             "bytes": stdout_path.stat().st_size, "sha256": sha256(stdout_path)}
        if stderr_path.exists():
            row["stderr"] = {"path": str(stderr_path.relative_to(OUTPUT)),
                             "bytes": stderr_path.stat().st_size, "sha256": sha256(stderr_path)}
    row["elapsed_seconds"] = round(time.monotonic() - started, 3)
    COMMANDS.append(row)
    write_json(OUTPUT / "commands.json", COMMANDS)
    if row["status"] not in ("SUCCESS", "EXPECTED_NONZERO"):
        raise RuntimeError(label + " failed: " + row.get("error", "unexpected exit " + str(row.get("exit_code"))))
    return row


def output_text(row: dict) -> str:
    return (OUTPUT / row["stdout"]["path"]).read_text(encoding="utf-8", errors="replace")


def check_linux_host() -> dict:
    if platform.system() != "Linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        raise RuntimeError("source closure query requires native Linux x86-64")
    os_release = Path("/etc/os-release").read_text(encoding="utf-8")
    if not re.search(r"(?m)^ID=ubuntu$", os_release) or not re.search(r'(?m)^VERSION_ID="24\.04"$', os_release):
        raise RuntimeError("source closure query requires the standard Ubuntu 24.04 hosted image")
    return {"system": platform.system(), "machine": platform.machine(),
            "platform": platform.platform(), "os_release_sha256": hashlib.sha256(os_release.encode()).hexdigest(),
            "os_release": os_release}


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("expected JSON object: " + str(path))
    return value


def verify_pins() -> tuple[dict, dict, dict]:
    inputs_path = ROOT / "release/ci-bootstrap-inputs.json"
    source_path = ROOT / "host/cargo-repro/source.json"
    patch_path = ROOT / "host/cargo-repro/cargo-metadata.patch"
    inputs = read_json(inputs_path)
    source_pin = read_json(source_path)
    custom = inputs.get("custom_cargo", {})
    lock = custom.get("cargo_lock", {})
    targets = custom.get("patch_targets", [])
    expected_targets = [
        {"path": "src/compiler/build_runner/compilation_files.rs",
         "upstream_sha256": "275e1ff7e6512bbbb3b30a7f0ceb9c7d455745e6aafce0484cb73d8fe31e0e67",
         "patched_sha256": "b572e74e742cca08765540aa9f611b1877defc08d146cff52fcd9b0c039106db"},
        {"path": "src/workspace/features.rs",
         "upstream_sha256": "2747b5598654963df7d9270b07fc7dbd80a700cf219b26db71b0d2291ea74638",
         "patched_sha256": "0db8ba62877729fdee23ee8ae26f11a7b79fdd8bf086845a53c5f097eb1eacc3"},
    ]
    if (custom.get("upstream") != CARGO_REMOTE or custom.get("commit") != CARGO_COMMIT
            or custom.get("patch_path") != "host/cargo-repro/cargo-metadata.patch"
            or custom.get("patch_sha256") != PATCH_SHA256 or targets != expected_targets
            or lock.get("path") != "Cargo.lock" or lock.get("bytes") != LOCK_BYTES
            or lock.get("sha256") != LOCK_SHA256 or lock.get("packages") != EXPECTED_PACKAGES
            or lock.get("registry_packages") != EXPECTED_REGISTRY_PACKAGES
            or lock.get("workspace_path_packages") != EXPECTED_WORKSPACE_PACKAGES
            or lock.get("git_packages") != 0):
        raise ValueError("Cargo source, patch or lock inputs differ from the reviewed public pins")
    if (source_pin.get("upstream", "").removesuffix(".git") != CARGO_REMOTE.removesuffix(".git")
            or source_pin.get("commit") != CARGO_COMMIT
            or source_pin.get("patch_sha256") != PATCH_SHA256
            or source_pin.get("path") != expected_targets[0]["path"]
            or source_pin.get("original_sha256") != expected_targets[0]["upstream_sha256"]
            or source_pin.get("patched_sha256") != expected_targets[0]["patched_sha256"]
            or source_pin.get("additional_files") != [
                {"path": expected_targets[1]["path"],
                 "original_sha256": expected_targets[1]["upstream_sha256"],
                 "patched_sha256": expected_targets[1]["patched_sha256"]}]
            or sha256(patch_path) != PATCH_SHA256):
        raise ValueError("Cargo source patch bytes or target identities differ from source.json")
    return inputs, source_pin, {"path": str(patch_path.relative_to(ROOT)), "sha256": sha256(patch_path),
                                "targets": expected_targets,
                                "inputs_json_sha256": sha256(inputs_path),
                                "source_json_sha256": sha256(source_path)}


def verify_lock(lock_path: Path) -> dict:
    data = lock_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != LOCK_BYTES or digest != LOCK_SHA256:
        raise ValueError("Cargo.lock does not match the pinned bytes and SHA-256")
    parsed = tomllib.loads(data.decode("utf-8"))
    packages = parsed.get("package", [])
    registry = [row for row in packages if str(row.get("source", "")).startswith("registry+")]
    workspace = [row for row in packages if not row.get("source")]
    git = [row for row in packages if str(row.get("source", "")).startswith("git+")]
    if (len(packages) != EXPECTED_PACKAGES or len(registry) != EXPECTED_REGISTRY_PACKAGES
            or len(workspace) != EXPECTED_WORKSPACE_PACKAGES or git):
        raise ValueError("Cargo.lock package classes differ from the public source inventory")
    if any(not re.fullmatch(r"[0-9a-f]{64}", str(row.get("checksum", ""))) for row in registry):
        raise ValueError("registry package lacks a Cargo.lock SHA-256 checksum")
    return {"bytes": len(data), "sha256": digest, "packages": len(packages),
            "registry_packages": len(registry), "workspace_path_packages": len(workspace),
            "git_packages": len(git),
            "registry": sorted(registry, key=lambda row: (row["name"], row["version"]))}


def tool_inventory(env: dict[str, str]) -> dict:
    requested = {
        "git": ["--version"], "cc": ["--version"], "ar": ["--version"],
        "perl": ["-v"], "make": ["--version"], "pkg-config": ["--version"],
        "patch": ["--version"], "curl": ["--version"], "jq": ["--version"],
        "tar": ["--version"], "shasum": ["--version"],
    }
    rows = {}
    for name, tail in requested.items():
        found = shutil.which(name, path=SYSTEM_PATH)
        if found is None:
            rows[name] = {"status": "MISSING"}
            if name in {"git", "cc", "ar", "perl", "make", "pkg-config", "patch", "curl", "jq", "tar", "shasum"}:
                raise RuntimeError("required Ubuntu host utility is missing: " + name)
            continue
        resolved = Path(found).resolve(strict=True)
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise RuntimeError("host utility is not a regular executable: " + name)
        version_row = run("tool-version-" + name, [str(resolved), *tail], cwd=ROOT, env=env,
                          stdout_path=OUTPUT / "tools" / (name + ".version.txt"),
                          stderr_path=OUTPUT / "tools" / (name + ".version.stderr.log"), timeout=15)
        version = output_text(version_row)
        rows[name] = {"status": "RECORDED", "requested_path": found,
                      "resolved_path": str(resolved), "sha256": sha256(resolved),
                      "version_argv": [str(resolved), *tail], "version_output": version[:8192],
                      "version_output_truncated": len(version) > 8192}
    return rows


def parse_native_graph(tree_path: Path, metadata_path: Path, source: Path) -> dict:
    tree_text = tree_path.read_text(encoding="utf-8")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    # --format-version selects Cargo's JSON `version` field, not a field named
    # after the command-line option. Check the actual retained native output.
    if (type(metadata.get("version")) is not int or metadata["version"] != 1
            or not isinstance(metadata.get("packages"), list) or not metadata["packages"]):
        raise ValueError("cargo metadata output is not format version 1")
    package_map: dict[tuple[str, str], list[dict]] = {}
    for package in metadata["packages"]:
        package_map.setdefault((package["name"], package["version"]), []).append(package)
    tree_re = re.compile(r"^([^ ]+) v([^ ]+)(?: \(([^)]*)\))?(?: (.*))?$")
    selected: dict[tuple[str, str], dict] = {}
    for number, line in enumerate(tree_text.splitlines(), 1):
        match = tree_re.fullmatch(line.strip().removesuffix(" (*)"))
        if match is None:
            raise ValueError(f"unparsed cargo tree feature row {number}: {line[:200]}")
        key = (match.group(1), match.group(2))
        item = selected.setdefault(key, {"features": set(), "manifest_dir": None})
        manifest_dir = match.group(3)
        if manifest_dir == "proc-macro" or (manifest_dir and not manifest_dir.startswith("/")):
            manifest_dir = None
        if manifest_dir:
            if item["manifest_dir"] not in (None, manifest_dir):
                raise ValueError("one Cargo package identity has conflicting source paths in the tree")
            item["manifest_dir"] = manifest_dir
        features = (match.group(4) or "").strip()
        if features:
            item["features"].update(feature for feature in features.split(",") if feature)

    resolution = metadata.get("resolve")
    if (not isinstance(resolution, dict) or not isinstance(resolution.get("nodes"), list)
            or not resolution["nodes"]):
        raise ValueError("cargo metadata has no resolved package nodes")
    node_ids = {row.get("id") for row in resolution["nodes"]}
    if not selected:
        raise ValueError("cargo tree selected no packages")
    selected_rows = []
    for (name, version), selected_row in sorted(selected.items()):
        candidates = package_map.get((name, version), [])
        if len(candidates) > 1 and selected_row["manifest_dir"]:
            # Both paths are Cargo output data. Do not require the ephemeral
            # runner filesystem to still exist when reviewing retained output.
            source_dir = os.path.normpath(selected_row["manifest_dir"])
            candidates = [candidate for candidate in candidates
                          if Path(candidate["manifest_path"]).is_absolute()
                          and os.path.normpath(str(Path(candidate["manifest_path"]).parent)) == source_dir]
        elif len(candidates) > 1:
            registry_candidates = [candidate for candidate in candidates if candidate.get("source")]
            if len(registry_candidates) == 1:
                candidates = registry_candidates
        if len(candidates) != 1:
            raise ValueError("cargo metadata does not uniquely identify selected package: " + repr((name, version)))
        package = candidates[0]
        if package["id"] not in node_ids:
            raise ValueError("cargo metadata resolution omits a package in the native cargo-tree graph")
        selected_rows.append({"name": name, "version": version, "package_id": package["id"],
                              "source": package.get("source"),
                              "features": sorted(selected_row["features"])})
    identity_source_rows = [
        {"name": row["name"], "version": row["version"], "source": row["source"]}
        for row in selected_rows
    ]
    identity_source_bytes = json.dumps(identity_source_rows, sort_keys=True,
                                       separators=(",", ":")).encode("utf-8")
    graph = {
        "schema": "ami-rust-native-cargo-graph-v1",
        "claim": "locked Linux normal/build dependency graph with all-static; source metadata only",
        "target": TARGET,
        "selected_package_count": len(selected_rows),
        "selected_identity_source_set_sha256": hashlib.sha256(identity_source_bytes).hexdigest(),
        "cargo_tree_line_count": len(tree_text.splitlines()),
        "metadata_package_record_count": len(metadata["packages"]),
        "metadata_resolve_node_count": len(node_ids),
        "metadata_root": metadata.get("resolve", {}).get("root"),
        "packages": selected_rows,
    }
    return graph


def probe_native_graph_refusals(tree_path: Path, metadata_path: Path, work: Path, source: Path) -> list[dict]:
    """Exercise this parser with altered copies of actual native Cargo output."""
    original = json.loads(metadata_path.read_text(encoding="utf-8"))
    controls = work / "graph-parser-controls"
    controls.mkdir()
    rows = []
    for label in ("missing-version", "wrong-version", "string-version", "boolean-version",
                  "missing-packages", "empty-packages", "missing-resolve", "empty-nodes",
                  "ambiguous-package", "empty-tree", "unknown-tree-package"):
        altered = json.loads(json.dumps(original))
        tree = tree_path
        if label == "missing-version":
            del altered["version"]
        elif label == "wrong-version":
            altered["version"] = 2
        elif label == "string-version":
            altered["version"] = "1"
        elif label == "boolean-version":
            altered["version"] = True
        elif label == "missing-packages":
            del altered["packages"]
        elif label == "empty-packages":
            altered["packages"] = []
        elif label == "missing-resolve":
            del altered["resolve"]
        elif label == "empty-nodes":
            altered["resolve"]["nodes"] = []
        elif label == "ambiguous-package":
            # Cargo itself is necessarily selected; a repeated identical row
            # must not be resolved by accepting the first directory/list entry.
            cargo_rows = [row for row in altered["packages"] if row["name"] == "cargo"]
            if len(cargo_rows) != 1:
                raise ValueError("control requires one Cargo package record")
            altered["packages"].append(cargo_rows[0])
        else:
            tree = controls / (label + ".txt")
            tree.write_text("" if label == "empty-tree" else "not-in-the-lock v0.0.0\n", encoding="utf-8")
        metadata = controls / (label + ".json")
        write_json(metadata, altered)
        try:
            parse_native_graph(tree, metadata, source)
        except ValueError as error:
            rows.append({"case": label, "status": "EXPECTED_REFUSAL", "error": str(error)})
        else:
            raise ValueError("native graph parser accepted altered control: " + label)
    return rows


def validate_fetched_registry_inputs(lock_info: dict, cargo_home: Path) -> dict:
    expected = {(row["name"], row["version"]): row["checksum"] for row in lock_info["registry"]}
    archive_paths = list(cargo_home.glob("registry/cache/*/*.crate"))
    archive_rows = {}
    total_bytes = 0
    maximum_bytes = 0
    for archive in archive_paths:
        match = next((key for key in expected if archive.name == f"{key[0]}-{key[1]}.crate"), None)
        if match is None or match in archive_rows:
            raise ValueError("isolated Cargo cache contains an unexpected or duplicate archive: " + archive.name)
        size = archive.stat().st_size
        if size > MAX_CRATE_BYTES:
            raise ValueError("locked crate archive exceeds the 16 MiB individual fetch bound")
        total_bytes += size
        maximum_bytes = max(maximum_bytes, size)
        digest = sha256(archive)
        if digest != expected[match]:
            raise ValueError("registry archive checksum differs from Cargo.lock: " + archive.name)
        archive_rows[match] = {"archive": archive.name, "bytes": size, "sha256": digest}
    if not archive_rows:
        raise ValueError("locked registry fetch produced no cached crate archives")
    if total_bytes > MAX_CRATE_TOTAL_BYTES:
        raise ValueError("registry archive aggregate exceeds the 384 MiB bounded-fetch ceiling")
    package_rows = [{"name": key[0], "version": key[1], "lock_checksum": expected[key],
                     **archive_rows[key]} for key in sorted(archive_rows)]
    inputs = {"schema": "ami-rust-cargo-registry-source-inputs-v1",
              "lock_sha256": LOCK_SHA256,
              "fetched_registry_archive_count": len(package_rows),
              "archive_bytes_total": total_bytes, "archive_bytes_max": maximum_bytes,
              "per_archive_limit_bytes": MAX_CRATE_BYTES,
              "aggregate_limit_bytes": MAX_CRATE_TOTAL_BYTES,
              "packages": package_rows}
    write_json(OUTPUT / "registry-source-inputs.json", inputs)
    return {"fetched_registry_archive_count": len(package_rows), "archive_bytes_total": total_bytes,
            "archive_bytes_max": maximum_bytes,
            "registry_source_inputs_sha256": sha256(OUTPUT / "registry-source-inputs.json")}


def output_bytes(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*")
               if path.is_file() and not path.is_symlink())


def main() -> int:
    global ROOT, OUTPUT
    ROOT = Path.cwd().resolve(strict=True)
    if len(sys.argv) == 3 and sys.argv[1] == "--verify-lock":
        lock_path = Path(sys.argv[2]).resolve(strict=True)
        try:
            lock_info = verify_lock(lock_path)
        except (OSError, ValueError, tomllib.TOMLDecodeError) as error:
            print("LOCK_REFUSED: " + str(error), file=sys.stderr)
            return 2
        print(json.dumps({key: value for key, value in lock_info.items() if key != "registry"},
                         sort_keys=True))
        return 0
    if len(sys.argv) != 3:
        raise SystemExit("expected fresh work path and existing output path")
    work = Path(sys.argv[1])
    OUTPUT = Path(sys.argv[2])
    if not work.is_absolute() or not OUTPUT.is_absolute() or work.exists() or not OUTPUT.is_dir():
        raise SystemExit("work must be a fresh absolute path and output an existing absolute directory")
    if any(OUTPUT.iterdir()):
        raise SystemExit("output directory must be fresh")
    host = check_linux_host()
    work.mkdir(parents=True)
    for name in ("home", "tmp", "cargo-home", "commands"):
        (work / name).mkdir(parents=True, exist_ok=True)
    base_env = {
        "HOME": str(work / "home"),
        "TMPDIR": str(work / "tmp"),
        "CARGO_HOME": str(work / "cargo-home"),
        "PATH": SYSTEM_PATH,
        "LC_ALL": "C",
        "TZ": "UTC",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    leaked = sorted(key for key in os.environ
                    if key.startswith("CARGO_") or key in {
                        "RUSTFLAGS", "RUSTC", "RUSTDOC", "RUSTC_WRAPPER",
                        "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP", "RUSTDOCFLAGS"})
    if leaked:
        raise RuntimeError("ambient Rust/Cargo override was present in source-closure driver: " + ", ".join(leaked))

    receipt = {
        "schema": "ami-rust-native-cargo-source-closure-v1",
        "status": "FAIL",
        "claim": "native Linux source graph and input inventory only; no package compilation, build.rs execution, or runtime observation",
        "host": host,
        "target": TARGET,
        "source_identity": None,
        "phase": "preflight",
        "commands": COMMANDS,
        "started_unix": time.time(),
        "limits": {"seconds": 900, "workspace_bytes": 12 * 1024**3,
                   "rss_bytes": 4 * 1024**3, "log_bytes": 16 * 1024**2,
                   "individual_crate_archive_bytes": MAX_CRATE_BYTES,
                   "aggregate_crate_archive_bytes": MAX_CRATE_TOTAL_BYTES,
                   "retained_output_bytes": MAX_OUTPUT_BYTES},
        "internal_python_orchestration": True,
        "python_executable": sys.executable,
    }
    result_path = OUTPUT / "query-result.json"
    try:
        inputs, source_pin, patch_info = verify_pins()
        receipt["source_identity"] = {
            "upstream": CARGO_REMOTE, "commit": CARGO_COMMIT,
            "cargo_lock": {"bytes": LOCK_BYTES, "sha256": LOCK_SHA256,
                           "packages": EXPECTED_PACKAGES,
                           "registry_packages": EXPECTED_REGISTRY_PACKAGES,
                           "workspace_path_packages": EXPECTED_WORKSPACE_PACKAGES,
                           "git_packages": 0},
            "patch": patch_info,
            "bootstrap_inputs_sha256": sha256(ROOT / "release/ci-bootstrap-inputs.json"),
            "resource_policy_sha256": sha256(ROOT / "release/ci-resources.json"),
            "bootstrap_helper_sha256": sha256(ROOT / "tools/bootstrap-host-rust.sh"),
        }

        receipt["phase"] = "host-tool-identities"
        tools = tool_inventory(base_env)
        receipt["host_tools"] = tools

        source = work / "cargo-source"
        source.mkdir()
        receipt["phase"] = "fetch-pinned-cargo-source"
        git = str(Path(shutil.which("git", path=SYSTEM_PATH)).resolve(strict=True))
        run("git-init", [git, "-C", str(source), "init", "--quiet"], cwd=ROOT, env=base_env)
        run("git-add-origin", [git, "-C", str(source), "remote", "add", "origin", CARGO_REMOTE],
            cwd=ROOT, env=base_env)
        run("git-fetch-pinned-commit", [git, "-C", str(source), "fetch", "--no-tags", "--depth=1",
                                         "origin", CARGO_COMMIT], cwd=ROOT, env=base_env, timeout=300)
        run("git-checkout-pinned-commit", [git, "-C", str(source), "checkout", "--detach", "FETCH_HEAD"],
            cwd=ROOT, env=base_env)
        head = output_text(run("git-source-head", [git, "-C", str(source), "rev-parse", "HEAD"],
                               cwd=ROOT, env=base_env, timeout=30)).strip()
        upstream_tree = output_text(run("git-source-tree", [git, "-C", str(source), "rev-parse", "HEAD^{tree}"],
                                         cwd=ROOT, env=base_env, timeout=30)).strip()
        if head != CARGO_COMMIT:
            raise ValueError("fetched Cargo source HEAD does not equal the exact pinned commit")
        lock_info = verify_lock(source / "Cargo.lock")
        receipt["source_identity"].update({"fetched_head": head, "upstream_git_tree": upstream_tree,
                                           "verified_lock": {key: value for key, value in lock_info.items()
                                                             if key != "registry"}})

        receipt["phase"] = "lock-verifier-counterprobe"
        lock_probe_root = work / "lock-verifier-counterprobe"
        lock_probe_root.mkdir()
        good_lock = lock_probe_root / "Cargo.lock.good"
        bad_lock = lock_probe_root / "Cargo.lock.bad"
        lock_bytes = (source / "Cargo.lock").read_bytes()
        good_lock.write_bytes(lock_bytes)
        bad_lock.write_bytes(lock_bytes + b"\n")
        bash = str(Path(shutil.which("bash", path=SYSTEM_PATH)).resolve(strict=True))
        verifier = ROOT / "tools/rc0-cargo-source-closure.sh"
        good_probe = run("verify-good-lock-copy",
                         [bash, str(verifier), "--verify-lock", str(good_lock)],
                         cwd=ROOT, env=base_env, timeout=15)
        bad_probe = run("verify-bad-lock-copy",
                        [bash, str(verifier), "--verify-lock", str(bad_lock)],
                        cwd=ROOT, env=base_env, expected="nonzero", timeout=15)
        bad_refusal = (OUTPUT / bad_probe["stderr"]["path"]).read_text(encoding="utf-8", errors="replace").strip()
        expected_refusal = "LOCK_REFUSED: Cargo.lock does not match the pinned bytes and SHA-256"
        if bad_probe["exit_code"] != 2 or bad_refusal != expected_refusal:
            raise ValueError("wrong-lock copy did not receive the exact pinned-lock refusal")
        receipt["lock_verifier_counterprobe"] = {
            "status": "PASS_SAME_VERIFY_LOCK_GATE",
            "good_copy_exit_code": good_probe["exit_code"],
            "bad_copy_exit_code": bad_probe["exit_code"],
            "bad_copy_stderr": bad_refusal,
            "isolated_copies_only": True,
            "verifier_mode_has_no_network_or_write_behavior": True,
        }

        receipt["phase"] = "apply-and-verify-source-patch"
        for row in patch_info["targets"]:
            target_path = source / row["path"]
            if sha256(target_path) != row["upstream_sha256"]:
                raise ValueError("upstream Cargo patch target has unexpected preimage: " + row["path"])
        patch = ROOT / patch_info["path"]
        patch_bin = str(Path(shutil.which("patch", path=SYSTEM_PATH)).resolve(strict=True))
        run("apply-cargo-source-patch", [patch_bin, "-p1", "--batch", "--forward"],
            cwd=source, env=base_env, input_bytes=patch.read_bytes(), timeout=30)
        for row in patch_info["targets"]:
            if sha256(source / row["path"]) != row["patched_sha256"]:
                raise ValueError("patched Cargo source target hash differs: " + row["path"])
        changed = output_text(run("git-patched-paths", [git, "-C", str(source), "diff", "--name-only"],
                                  cwd=ROOT, env=base_env, timeout=30)).splitlines()
        if changed != sorted(row["path"] for row in patch_info["targets"]):
            raise ValueError("applied Cargo patch changed an unexpected source path")
        diff_row = run("git-patched-diff", [git, "-C", str(source), "diff", "--binary"],
                       cwd=ROOT, env=base_env, stdout_path=OUTPUT / "cargo-source.patch.diff",
                       stderr_path=OUTPUT / "cargo-source.patch.stderr.log", timeout=30)
        receipt["source_identity"].update({"patched_source_diff_sha256": diff_row["stdout"]["sha256"],
                                           "patched_targets": [
                                               {"path": row["path"], "sha256": row["patched_sha256"]}
                                               for row in patch_info["targets"]]})
        if verify_lock(source / "Cargo.lock") != lock_info:
            raise ValueError("Cargo source patch altered Cargo.lock")

        receipt["phase"] = "bootstrap-pinned-host-rust"
        bootstrap_env = dict(base_env)
        bash = str(Path(shutil.which("bash", path=SYSTEM_PATH)).resolve(strict=True))
        host_prefix = work / "host-rust"
        bootstrap = run("bootstrap-host-rust-1.98.1",
                        [bash, str(ROOT / "tools/bootstrap-host-rust.sh"), str(host_prefix), TARGET],
                        cwd=ROOT, env=bootstrap_env, timeout=300)
        host_bin = host_prefix / "toolchain" / "bin"
        cargo = host_bin / "cargo"
        rustc = host_bin / "rustc"
        rustdoc = host_bin / "rustdoc"
        if not all(path.is_file() and os.access(path, os.X_OK) for path in (cargo, rustc, rustdoc)):
            raise ValueError("pinned host Rust bootstrap did not install cargo/rustc/rustdoc")
        cargo_env = dict(base_env)
        cargo_env["PATH"] = str(host_bin) + ":" + SYSTEM_PATH
        cargo_env["RUSTC"] = str(rustc)
        cargo_env["RUSTDOC"] = str(rustdoc)
        cargo_version = run("pinned-cargo-version", [str(cargo), "-Vv"], cwd=ROOT, env=cargo_env,
                            stdout_path=OUTPUT / "pinned-cargo-version.txt",
                            stderr_path=OUTPUT / "pinned-cargo-version.stderr.log", timeout=30)
        rustc_version = run("pinned-rustc-version", [str(rustc), "-Vv"], cwd=ROOT, env=cargo_env,
                            stdout_path=OUTPUT / "pinned-rustc-version.txt",
                            stderr_path=OUTPUT / "pinned-rustc-version.stderr.log", timeout=30)
        cargo_version_text, rustc_version_text = output_text(cargo_version), output_text(rustc_version)
        if ("release: 1.98.1" not in rustc_version_text
                or "commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985" not in rustc_version_text
                or "cargo 1.98.1" not in cargo_version_text
                or "commit-hash: 797e8a9bca276c1c9f9f738d2a20f484fa4eea9d" not in cargo_version_text
                or "host: " + TARGET not in cargo_version_text):
            raise ValueError("bootstrap host Rust/Cargo binary identity differs from the existing pin")
        rust_pin = inputs["rust"]["components"][TARGET]
        bootstrap_archives = []
        for component in ("rustc", "rust-std", "cargo"):
            row = rust_pin[component]
            archive = host_prefix / "downloads" / Path(row["url"]).name
            if (archive.stat().st_size != row["http_content_length"]
                    or sha256(archive) != row["sha256"]):
                raise ValueError("host Rust bootstrap archive differs from the existing pin: " + component)
            bootstrap_archives.append({"component": component, "bytes": archive.stat().st_size,
                                       "sha256": sha256(archive), "url": row["url"]})
        receipt["host_rust"] = {"rustc_sha256": sha256(rustc), "cargo_sha256": sha256(cargo),
                                "rustdoc_sha256": sha256(rustdoc),
                                "rustc_version": rustc_version_text.strip(),
                                "cargo_version": cargo_version_text.strip(),
                                "bootstrap_command": bootstrap["argv"],
                                "bootstrap_helper_sha256": sha256(ROOT / "tools/bootstrap-host-rust.sh"),
                                "archives": bootstrap_archives}

        receipt["phase"] = "fetch-and-verify-locked-registry-inputs"
        fetch_env = dict(cargo_env)
        fetch_env["CARGO_NET_OFFLINE"] = "false"
        fetch_command = [str(cargo), "fetch", "--locked", "--manifest-path", str(source / "Cargo.toml"),
                         "--target", TARGET]
        fetch = run("cargo-fetch-locked-native-target", fetch_command,
                    cwd=source, env=fetch_env, timeout=420)
        registry_result = validate_fetched_registry_inputs(lock_info, work / "cargo-home")
        receipt["registry_inputs"] = {**registry_result,
                                      "fetch_command": fetch["argv"],
                                      "fetch_status": fetch["status"],
                                      "isolated_cargo_home": "work/cargo-home",
                                      "fetch_phase_preceded_all_queries": True}

        receipt["phase"] = "offline-linux-metadata-query"
        query_env = dict(cargo_env)
        query_env["CARGO_NET_OFFLINE"] = "true"
        query_env["CARGO_TERM_COLOR"] = "never"
        tree_path = OUTPUT / "linux-tree-features.stdout.txt"
        tree_command = [str(cargo), "tree", "--locked", "--offline",
                        "--manifest-path", str(source / "Cargo.toml"),
                        "--package", "cargo", "--features", "all-static",
                        "-e", "normal,build", "--target", TARGET,
                        "--color", "never", "--prefix", "none", "--format", "{p} {f}"]
        tree = run("cargo-tree-linux-normal-build-all-static", tree_command,
                   cwd=source, env=query_env, stdout_path=tree_path,
                   stderr_path=OUTPUT / "linux-tree-features.stderr.log", timeout=180)
        if tree["stdout"]["bytes"] == 0:
            raise ValueError("Cargo tree query succeeded with empty output")
        metadata_path = OUTPUT / "cargo-metadata-linux.json"
        metadata_command = [str(cargo), "metadata", "--locked", "--offline",
                            "--manifest-path", str(source / "Cargo.toml"),
                            "--format-version", "1", "--filter-platform", TARGET,
                            "--features", "all-static"]
        metadata_run = run("cargo-metadata-linux-filter-platform-all-static", metadata_command,
                           cwd=source, env=query_env, stdout_path=metadata_path,
                           stderr_path=OUTPUT / "cargo-metadata-linux.stderr.log", timeout=180)
        graph = parse_native_graph(tree_path, metadata_path, source)
        receipt["graph_parser_counterprobes"] = probe_native_graph_refusals(tree_path, metadata_path, work, source)
        write_json(OUTPUT / "locked-linux-cargo-graph.json", graph)
        graph_info = {key: graph[key] for key in (
            "selected_package_count", "cargo_tree_line_count", "metadata_package_record_count",
            "metadata_resolve_node_count", "selected_identity_source_set_sha256")}
        graph_info["locked_graph_sha256"] = sha256(OUTPUT / "locked-linux-cargo-graph.json")
        receipt["queries"] = {
            "cargo_tree": {"command": tree["argv"], "exit_code": tree["exit_code"],
                           "stdout": tree["stdout"], "stderr": tree["stderr"],
                           "status": "PASS_SOURCE_GRAPH_ONLY"},
            "cargo_metadata": {"command": metadata_run["argv"], "exit_code": metadata_run["exit_code"],
                               "stdout": metadata_run["stdout"], "stderr": metadata_run["stderr"],
                               "status": "PASS_SOURCE_GRAPH_ONLY"},
            "selected_graph": graph_info,
        }
        receipt["phase"] = "complete"
        receipt["commands"] = COMMANDS
        receipt["status"] = "PASS_NATIVE_LINUX_SOURCE_GRAPH_ONLY"
        receipt["elapsed_seconds"] = round(time.monotonic() - STARTED, 3)
        retained = output_bytes(OUTPUT)
        if retained > MAX_OUTPUT_BYTES:
            raise ValueError("retained source-closure metadata exceeds the 32 MiB evidence bound")
        receipt["retained_output_bytes_before_result"] = retained
    except BaseException as error:
        receipt["status"] = "FAIL"
        receipt["error"] = type(error).__name__ + ": " + str(error)[:2000]
        receipt["commands"] = COMMANDS
        receipt["elapsed_seconds"] = round(time.monotonic() - STARTED, 3)
    finally:
        write_json(result_path, receipt)
    return 0 if receipt["status"] == "PASS_NATIVE_LINUX_SOURCE_GRAPH_ONLY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
PY
