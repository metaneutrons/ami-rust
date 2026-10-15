"""Portable, offline SDK selection. Project locks never select global state."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat

DIGEST = re.compile(r"[0-9a-f]{64}")
COMPONENT_NAMES = ("rust", "cargo", "toolchain", "collector", "csdk", "vendor")
CARGO_METADATA_MODE = "ami-rust-reproducible-cross-v1"


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_json(path: Path, limit: int = 16 * 1024 * 1024):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        raise ValueError(f"missing, linked or oversized manifest: {path}")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=unique)


def portable_parts(text: str):
    if not isinstance(text, str) or not text or any(char in text for char in ("\\", ":", "\0")):
        raise ValueError("manifest path must be a portable relative path")
    parts = text.split("/")
    if any(part in ("", ".", "..") for part in parts) or Path(text).is_absolute():
        raise ValueError(f"unsafe manifest path: {text}")
    return parts


def relative(root: Path, text: str) -> Path:
    path = root
    for part in portable_parts(text):
        path = path / part
        if path.is_symlink():
            raise ValueError(f"symlink in manifest file path: {text}")
    return path


def executable_file(root: Path, text: object, label: str) -> Path:
    if not isinstance(text, str) or not text:
        raise ValueError(f"missing or invalid {label} path")
    try:
        path = relative(root, text)
    except ValueError as exc:
        raise ValueError(f"unsafe {label} path: {text}") from exc
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise ValueError(f"missing or invalid {label}: {text}") from exc
    if not stat.S_ISREG(mode):
        raise ValueError(f"missing or invalid {label}: {text}")
    execute_bits = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
    if not mode & execute_bits or not os.access(path, os.X_OK):
        raise ValueError(f"{label} is not executable: {text}")
    return path


def require_component_keys(value: object, owner: str) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"{owner} components must be an object")
    keys = set(value)
    expected = set(COMPONENT_NAMES)
    missing = sorted(expected - keys)
    extra = sorted(keys - expected)
    if missing or extra:
        raise ValueError(
            f"{owner} component keys mismatch: "
            f"missing={','.join(missing) or '-'} extra={','.join(extra) or '-'}"
        )


def require_separate_component_roots(components: dict[str, Path]) -> None:
    names = list(components)
    for index, left_name in enumerate(names):
        left = components[left_name]
        for right_name in names[index + 1:]:
            right = components[right_name]
            if left == right or left in right.parents or right in left.parents:
                raise ValueError(
                    f"overlapping SDK component roots: {left_name} and {right_name}"
                )


def measure_inventory(root: Path, manifest: dict, *, complete: bool = False):
    seen = set()
    for row in manifest["files"]:
        name = row["path"]
        if name in seen or not isinstance(row["sha256"], str) or not DIGEST.fullmatch(row["sha256"]):
            raise ValueError("duplicate file or invalid digest in inventory")
        seen.add(name)
        path = relative(root, name)
        if type(row["bytes"]) is not int or row["bytes"] < 0 or not path.is_file():
            raise ValueError(f"missing or invalid component: {name}")
        if path.stat().st_size != row["bytes"] or sha256(path) != row["sha256"]:
            raise ValueError(f"component identity mismatch: {name}")
    for row in manifest.get("symlinks", []):
        name = row["path"]
        if name in seen:
            raise ValueError("duplicate file/symlink identity")
        seen.add(name)
        portable_parts(name)
        leaf = Path(name)
        parent = relative(root, str(leaf.parent)) if str(leaf.parent) != "." else root
        if leaf.name in ("", ".", "..") or leaf.is_absolute():
            raise ValueError("unsafe symlink path")
        path = parent / leaf.name
        if not path.is_symlink() or os.readlink(path) != row["target"]:
            raise ValueError(f"component symlink mismatch: {name}")
        # Every target must remain within this component and eventually resolve.
        try:
            path.resolve(strict=True).relative_to(root.resolve(strict=True))
        except (OSError, RuntimeError, ValueError) as exc:
            raise ValueError(f"escaping/broken component symlink: {name}") from exc
    if complete:
        actual = set()
        for directory, dirs, files in os.walk(root, followlinks=False):
            base = Path(directory)
            for name in list(dirs):
                if (base / name).is_symlink():
                    actual.add((base / name).relative_to(root).as_posix())
                    dirs.remove(name)
            for name in files:
                path = base / name
                if not path.is_symlink() and not stat.S_ISREG(path.stat().st_mode):
                    raise ValueError("nonregular prerequisite file")
                actual.add(path.relative_to(root).as_posix())
        if actual != seen:
            raise ValueError(f"incomplete prerequisite inventory: extra={len(actual-seen)} missing={len(seen-actual)}")
    return len(seen)


def host_key():
    system = platform.system()
    machine = platform.machine().lower()
    key = {("Darwin", "arm64"): "macos-aarch64", ("Linux", "x86_64"): "linux-x86_64"}.get((system, machine))
    if key is None:
        raise ValueError(f"unsupported build host: {system}/{machine}")
    return key


def select(project_lock: Path):
    project_lock = project_lock.absolute()
    project = read_json(project_lock, 1024 * 1024)
    if project.get("schema") != "ami-rust-project-lock-v1":
        raise ValueError("missing/incompatible ami-rust project lock schema")
    sdk = project["sdk"]
    root = Path(sdk["root"])
    if not root.is_absolute():
        root = project_lock.parent / root
    root = root.resolve(strict=True)
    manifest_path = relative(root, sdk["manifest"])
    if not DIGEST.fullmatch(sdk["manifest_sha256"]) or sha256(manifest_path) != sdk["manifest_sha256"]:
        raise ValueError("SDK manifest identity mismatch")
    manifest = read_json(manifest_path)
    if manifest.get("schema") != "ami-rust-sdk-v1":
        raise ValueError("incompatible SDK manifest schema")
    measure_inventory(root, manifest)
    current_host = host_key()
    if project["host"]["platform"] != current_host:
        raise ValueError("project host profile does not match this host")
    profile = manifest["profiles"][current_host]
    require_component_keys(profile.get("components"), "SDK profile")
    require_component_keys(project.get("components"), "project lock")
    if profile.get("cargo_metadata_mode") != CARGO_METADATA_MODE:
        raise ValueError("missing or unsupported SDK Cargo metadata mode")
    python = Path(project["host"]["python"])
    if not python.is_absolute() or sha256(python.resolve(strict=True)) != project["host"]["python_sha256"]:
        raise ValueError("selected Python identity mismatch")
    components = {}
    counts = {}
    profile_components = profile["components"]
    project_components = project["components"]
    for name in COMPONENT_NAMES:
        expected = profile_components[name]
        component_root = Path(project_components[name])
        if not component_root.is_absolute():
            component_root = project_lock.parent / component_root
        component_root = component_root.resolve(strict=True)
        require_separate_component_roots({**components, name: component_root})
        input_manifest = relative(root, expected["manifest"])
        if sha256(input_manifest) != expected["sha256"]:
            raise ValueError(f"prerequisite manifest identity mismatch: {name}")
        inventory = read_json(input_manifest)
        counts[name] = measure_inventory(component_root, inventory, complete=True)
        components[name] = component_root
    if not isinstance(profile.get("cargo_binary"), str):
        raise ValueError("missing or invalid SDK Cargo binary path")
    executable_file(components["cargo"], profile["cargo_binary"], "SDK Cargo binary")
    return project_lock, project, root, manifest, profile, components, counts
