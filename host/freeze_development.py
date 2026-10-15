#!/usr/bin/env python3
"""Freeze a development-only portable SDK selection; never an R1 acceptance."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from contracts import (
    CARGO_METADATA_MODE,
    COMPONENT_NAMES,
    executable_file,
    host_key,
    require_component_keys,
    require_separate_component_roots,
    sha256,
)


def inventory(root):
    files, symlinks = [], []
    for path in sorted(root.rglob("*")):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            symlinks.append({"path": name, "target": str(path.readlink())})
        elif path.is_file():
            files.append({"path": name, "bytes": path.stat().st_size, "sha256": sha256(path)})
    return {"files": files, "symlinks": symlinks}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", required=True, type=Path)
    parser.add_argument("--sdk-root", required=True, type=Path)
    parser.add_argument("--manifest-output", required=True, type=Path)
    parser.add_argument("--project-lock-output", required=True, type=Path)
    args = parser.parse_args()
    root = args.sdk_root.resolve(strict=True)
    selection = json.loads(args.selection.read_text())
    if not isinstance(selection, dict):
        raise ValueError("development selection must be an object")
    require_component_keys(selection.get("components"), "development selection")
    cargo_binary = selection.get("cargo_binary")
    cargo_metadata_mode = selection.get("cargo_metadata_mode")
    if cargo_metadata_mode != CARGO_METADATA_MODE:
        raise ValueError("missing or unsupported SDK Cargo metadata mode")
    key = host_key()
    component_roots = {
        name: Path(selection["components"][name]).resolve(strict=True)
        for name in COMPONENT_NAMES
    }
    require_separate_component_roots(component_roots)
    if not isinstance(cargo_binary, str):
        raise ValueError("missing or invalid SDK Cargo binary path")
    executable_file(component_roots["cargo"], cargo_binary, "SDK Cargo binary")
    profile_dir = root / "host/profiles" / key
    profile_dir.mkdir(parents=True, exist_ok=True)
    components = {}
    for name in COMPONENT_NAMES:
        component = component_roots[name]
        out = profile_dir / (name + ".json")
        out.write_text(json.dumps(inventory(component), indent=2) + "\n")
        components[name] = {"manifest": out.relative_to(root).as_posix(), "sha256": sha256(out)}
    files = []
    names = set()
    for directory in ("crates", "native", "targets", "tests", "examples"):
        for path in (root / directory).rglob("*"):
            if path.is_file() and "__pycache__" not in path.parts:
                names.add(path.relative_to(root).as_posix())
    for path in (root / "host").rglob("*"):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
            names.add(path.relative_to(root).as_posix())
    names.update(["Cargo.toml", "Cargo.lock", "host/build.py", "host/contracts.py", "host/compact_sections.py", "host/elf_audit.py"])
    # AMI_SDK_TESTING consumes this header through the diagnostic binding.
    # It is a declared qualification input even though release builds do not.
    names.add("scripts/measurement/m1_measurement.h")
    for name in sorted(names):
        path = root / name
        if path.is_symlink():
            raise ValueError("SDK source symlinks are not supported")
        files.append({"path": name, "bytes": path.stat().st_size, "sha256": sha256(path)})
    budgets = json.loads((root / "inputs/budgets.json").read_text())
    previous = json.loads(args.manifest_output.read_text()) if args.manifest_output.is_file() else {}
    profiles = previous.get("profiles", {})
    profiles[key] = {
        "rust_host": {"macos-aarch64": "aarch64-apple-darwin", "linux-x86_64": "x86_64-unknown-linux-gnu"}[key],
        "collector_binary": selection["collector_binary"],
        "cargo_binary": cargo_binary,
        "cargo_metadata_mode": cargo_metadata_mode,
        "components": components,
    }
    manifest = {"schema": "ami-rust-sdk-v1", "version": "0.1.0-dev.20261015", "development_only": True, "source_identity": "working tree; not release-qualified", "driver": "host/build.py", "source_date_epoch": 1791936000, "rust_commit": "dc3f85158a955a87a6e4363af1fbe9cf2d063cce", "rust_llvm": "22.1.8", "profiles": profiles, "budgets": budgets, "files": files}
    args.manifest_output.write_text(json.dumps(manifest, indent=2) + "\n")
    python = Path(selection["python"]).resolve(strict=True)
    lock = {"schema": "ami-rust-project-lock-v1", "sdk": {"root": str(root), "manifest": args.manifest_output.resolve().relative_to(root).as_posix(), "manifest_sha256": sha256(args.manifest_output)}, "host": {"platform": key, "python": str(python), "python_sha256": sha256(python)}, "components": selection["components"], "cargo": {"manifest_sha256": sha256(root / "Cargo.toml"), "lock_sha256": sha256(root / "Cargo.lock")}}
    args.project_lock_output.write_text(json.dumps(lock, indent=2)+"\n")
    print(json.dumps({"claim": "development selection only", "host": key, "sdk_files": len(files), "manifest_sha256": sha256(args.manifest_output)}, indent=2))


if __name__ == "__main__":
    main()
