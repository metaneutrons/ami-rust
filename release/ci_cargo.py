#!/usr/bin/env python3
"""Produce a pinned host Cargo prerequisite under the hosted CI budgets.

This workflow creates a host tool only.  It does not build an AROS SDK or
establish R1 qualification.  All downloads, checkouts, caches, vendors, and
build products stay under the fresh --work directory; --output holds JSON
metadata only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import posixpath
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
ARCHIVE_CHUNK = 1024 * 1024
MAX_EXPANDED_ARCHIVE = 6 * 1024**3
MAX_LOG_BYTES = 16 * 1024**2
MAX_RSS_BYTES = 4 * 1024**3
MAX_WORK_BYTES = 12 * 1024**3
SUPERVISOR_STOP_GRACE_SECONDS = 15
PROCESS_ROWS_TIMEOUT_SECONDS = 2.0
PRODUCER_SCHEMA = "ami-rust-hosted-custom-cargo-producer-v1"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(ARCHIVE_CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_sha256(value) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def host_identity() -> tuple[str, str]:
    system, machine = platform.system(), platform.machine().lower()
    if system == "Darwin" and machine in ("arm64", "aarch64"):
        return "macos-aarch64", "aarch64-apple-darwin"
    if system == "Linux" and machine in ("x86_64", "amd64"):
        return "linux-x86_64", "x86_64-unknown-linux-gnu"
    raise ValueError("hosted Cargo producer supports only Darwin arm64 and Linux x86_64")


def physical_memory_bytes(host: str) -> int:
    if host == "macos-aarch64":
        return int(subprocess.check_output(["/usr/sbin/sysctl", "-n", "hw.memsize"], text=True).strip())
    return os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE")


def check_capacity(host: str, disk_path: Path, resources: dict) -> dict:
    capacity = resources.get("host_capacity")
    if not isinstance(capacity, dict) or capacity.get("schema") != "ami-rust-host-capacity-v1":
        raise ValueError("resource policy has no admitted host capacity profile")
    # Resource policy uses the names established by release/ci-resources.json.
    ram_floor = capacity.get("ram_minimum_bytes")
    disk_floor = capacity.get("disk_free_minimum_bytes")
    if (type(ram_floor) is not int or type(disk_floor) is not int
            or ram_floor < 6 * 1024**3 or disk_floor < 24 * 1024**3):
        raise ValueError("host capacity minima must be at least 6 GiB RAM and 24 GiB disk")
    ram = physical_memory_bytes(host)
    free = shutil.disk_usage(disk_path).free
    if ram < ram_floor or free < disk_floor:
        raise ValueError(f"host capacity refused: {ram} RAM bytes/{free} free bytes")
    return {"physical_ram_bytes": ram, "free_disk_bytes": free,
            "ram_minimum_bytes": ram_floor, "disk_free_minimum_bytes": disk_floor}


def validate_pins(inputs: dict, resources: dict) -> tuple[str, str]:
    normative_inputs = json.loads((ROOT / "release/ci-bootstrap-inputs.json").read_text())
    normative_resources = json.loads((ROOT / "release/ci-resources.json").read_text())
    if inputs != normative_inputs or resources != normative_resources:
        raise ValueError("input files differ from the tracked normative hosted CI pins")
    if inputs.get("schema") != "ami-rust-ci-cargo-inputs-v1":
        raise ValueError("unrecognized Cargo bootstrap input schema")
    rust = inputs.get("rust")
    if (not isinstance(rust, dict) or rust.get("release") != "1.98.1"
            or len(rust.get("commit", "")) != 40
            or len(rust.get("cargo_commit", "")) != 40 or not rust.get("manifest")):
        raise ValueError("Rust bootstrap release/commit pins are incomplete")
    expected_targets = {"aarch64-apple-darwin", "x86_64-unknown-linux-gnu"}
    if set(rust.get("components", {})) != expected_targets:
        raise ValueError("Rust component pins do not cover exactly the admitted hosts")
    for target in expected_targets:
        component_set = rust["components"][target]
        if set(component_set) != {"rustc", "rust-std", "cargo", "total_archive_bytes"}:
            raise ValueError("Rust component set is incomplete")
        archive_sum = 0
        for name in ("rustc", "rust-std", "cargo"):
            component = component_set[name]
            expected_name = f"{name}-{rust['release']}-{target}.tar.xz"
            parsed = urllib.parse.urlparse(component.get("url", ""))
            if (parsed.scheme != "https" or parsed.hostname != "static.rust-lang.org"
                    or parsed.path.rsplit("/", 1)[-1] != expected_name
                    or type(component.get("http_content_length")) is not int
                    or len(component.get("sha256", "")) != 64):
                raise ValueError("Rust archive input is not an exact HTTPS/hash/size pin")
            archive_sum += component["http_content_length"]
        if component_set["total_archive_bytes"] != archive_sum:
            raise ValueError("Rust archive total does not match component sizes")
    manifest = rust["manifest"]
    if (manifest.get("url") != "https://static.rust-lang.org/dist/channel-rust-1.98.1.toml"
            or len(manifest.get("sha256", "")) != 64
            or type(manifest.get("bytes")) is not int or manifest["bytes"] > 1024 * 1024):
        raise ValueError("Rust channel manifest pin is invalid")

    source_pin = json.loads((ROOT / "host/cargo-repro/source.json").read_text())
    custom = inputs.get("custom_cargo", {})
    target_pins = [{"path": source_pin["path"], "upstream_sha256": source_pin["original_sha256"],
                    "patched_sha256": source_pin["patched_sha256"]}]
    target_pins += [{"path": row["path"], "upstream_sha256": row["original_sha256"],
                     "patched_sha256": row["patched_sha256"]}
                    for row in source_pin.get("additional_files", [])]
    if (custom.get("upstream", "").removesuffix(".git") != source_pin["upstream"].removesuffix(".git")
            or custom.get("commit") != source_pin["commit"]
            or custom.get("patch_path") != "host/cargo-repro/cargo-metadata.patch"
            or custom.get("patch_sha256") != source_pin["patch_sha256"]
            or custom.get("patch_targets") != target_pins):
        raise ValueError("normative Cargo source/patch inputs differ from tracked source pins")
    overlay = inputs.get("openssl_overlay", {})
    if (overlay.get("recipe_sha256") != sha256(ROOT / "host/cargo-repro/openssl-overlay.json")
            or overlay.get("patch_sha256") != sha256(ROOT / "host/cargo-repro/openssl-paths.patch")):
        raise ValueError("normative OpenSSL overlay hashes differ from the tracked recipe")
    if resources.get("schema") != "ami-rust-hosted-resources-v1":
        raise ValueError("unrecognized resource policy schema")
    helper_pins = inputs.get("producer_helpers")
    if not isinstance(helper_pins, dict):
        raise ValueError("CI inputs do not pin the producer helper sources")
    expected_helper_fields = {"producer_path", "producer_sha256", "overlay_helper_sha256",
                              "host_supervisor_path", "host_supervisor_sha256"}
    if not expected_helper_fields <= set(helper_pins):
        raise ValueError("CI producer helper pins are incomplete")
    if (helper_pins["producer_path"] != "host/cargo-repro/produce.py"
            or helper_pins["host_supervisor_path"] != "host/build.py"):
        raise ValueError("CI producer helper paths differ from the supported implementation")
    helper_paths = {"producer_path": ROOT / "host/cargo-repro/produce.py",
                    "overlay_helper_sha256": ROOT / "host/cargo-repro/prepare-overlay.py",
                    "host_supervisor_path": ROOT / "host/build.py"}
    expected_hashes = {"producer_path": "producer_sha256",
                       "overlay_helper_sha256": "overlay_helper_sha256",
                       "host_supervisor_path": "host_supervisor_sha256"}
    for path_key, path in helper_paths.items():
        hash_key = expected_hashes[path_key]
        if sha256(path) != helper_pins[hash_key]:
            raise ValueError("producer helper differs from CI pin: " + path_key)
    build = resources.get("build")
    expected = {"jobs": 2, "rss_bytes": MAX_RSS_BYTES, "seconds": 1200,
                "workspace_bytes": MAX_WORK_BYTES, "log_bytes": MAX_LOG_BYTES}
    if build != expected:
        raise ValueError("resource policy does not match the admitted Cargo producer ceilings")
    runtime_pin = inputs.get("python_runtime_manifest")
    if runtime_pin is not None:
        runtime_path = ROOT / "release/ci-python-inputs.json"
        bootstrap_path = ROOT / "release/ci_python.py"
        if (runtime_pin.get("path") != "release/ci-python-inputs.json"
                or sha256(runtime_path) != runtime_pin.get("sha256")
                or helper_pins.get("python_bootstrap_path") != "release/ci_python.py"
                or sha256(bootstrap_path) != helper_pins.get("python_bootstrap_sha256")):
            raise ValueError("portable Python manifest/helper differs from the normative pins")
        runtime_inputs = json.loads(runtime_path.read_text())
        if (runtime_inputs.get("schema") != "ami-rust-ci-python-inputs-v1"
                or set(runtime_inputs.get("hosts", {})) != {"macos-aarch64", "linux-x86_64"}):
            raise ValueError("portable Python inputs do not cover the admitted hosts")
        for profile, row in runtime_inputs["hosts"].items():
            if inputs["python"][profile]["sha256"] != row["runtime_sha256"]:
                raise ValueError("Python runtime executable pin disagrees with the pinned archive")
    host, target = host_identity()
    python_pin = inputs.get("python", {}).get(host, {}).get("sha256", "")
    if len(python_pin) != 64:
        raise ValueError("no pinned Python receipt for this hosted runner")
    return host, target


def download_verified(url: str, expected_bytes: int, expected_sha256: str,
                      destination: Path, opener=urllib.request.urlopen,
                      total_timeout: int = 300,
                      expected_origin: str = "static.rust-lang.org",
                      redirect_hosts: tuple[str, ...] = ()) -> dict:
    """Stream one pinned HTTPS object to a fresh file, validating size and hash."""
    parsed = urllib.parse.urlparse(url)
    if expected_origin not in {"static.rust-lang.org", "github.com"}:
        raise ValueError("unrecognised pinned input origin")
    permitted_cdn = {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}
    if (any(host not in permitted_cdn for host in redirect_hosts)
            or (expected_origin == "static.rust-lang.org" and redirect_hosts)):
        raise ValueError("unrecognised pinned input redirect policy")
    if parsed.scheme != "https" or parsed.hostname != expected_origin:
        raise ValueError("component URL must use its pinned HTTPS origin")
    if type(expected_bytes) is not int or expected_bytes <= 0:
        raise ValueError("invalid pinned download size")
    if len(expected_sha256) != 64:
        raise ValueError("invalid pinned download digest")
    destination = destination.absolute()
    partial = destination.with_name(destination.name + ".partial")
    if destination.exists() or partial.exists():
        raise ValueError("download destination must be fresh")
    digest = hashlib.sha256()
    received = 0
    deadline = time.monotonic() + total_timeout
    request = urllib.request.Request(url, headers={"User-Agent": "ami-rust-hosted-cargo/1"})
    try:
        with opener(request, timeout=30) as response:
            final = urllib.parse.urlparse(response.geturl())
            if final.scheme != "https" or final.hostname not in {expected_origin, *redirect_hosts}:
                raise ValueError("download redirected outside the pinned HTTPS origins")
            content_length = response.headers.get("Content-Length")
            if content_length is not None and int(content_length) != expected_bytes:
                raise ValueError("download Content-Length differs from the pinned size")
            with partial.open("xb") as target:
                while True:
                    if time.monotonic() > deadline:
                        raise TimeoutError("download exceeded its total time budget")
                    block = response.read(ARCHIVE_CHUNK)
                    if not block:
                        break
                    received += len(block)
                    if received > expected_bytes:
                        raise ValueError("download exceeds pinned byte size")
                    target.write(block)
                    digest.update(block)
                    if time.monotonic() > deadline:
                        raise TimeoutError("download exceeded its total time budget")
        if received != expected_bytes:
            raise ValueError("download byte count differs from the pinned size")
        actual = digest.hexdigest()
        if actual != expected_sha256:
            raise ValueError("download SHA-256 differs from the pinned digest")
        os.replace(partial, destination)
        return {"bytes": received, "sha256": actual}
    except BaseException:
        try:
            partial.unlink()
        except FileNotFoundError:
            pass
        raise


def _member_path(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("archive contains an unsafe member path")
    if ":" in path.parts[0] or "\\" in name:
        raise ValueError("archive contains a non-portable member path")
    return path


def safe_extract_tar(archive: Path, destination: Path,
                     expanded_limit: int = MAX_EXPANDED_ARCHIVE,
                     current_managed_bytes: int = 0,
                     overall_limit: int = MAX_WORK_BYTES) -> dict:
    """Extract a verified tar without traversal, link pivots, devices, or overwrite."""
    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError("archive extraction directory must be fresh")
    created = False
    try:
        with tarfile.open(archive, mode="r:*") as bundle:
            members = bundle.getmembers()
            by_name = {}
            expanded = 0
            roots = set()
            for member in members:
                path = _member_path(member.name.rstrip("/"))
                name = path.as_posix()
                if name in by_name:
                    raise ValueError("archive contains duplicate member names")
                if len(path.parts) < 1:
                    raise ValueError("archive member has no component root")
                roots.add(path.parts[0])
                if member.isdir():
                    pass
                elif member.isfile():
                    if member.size < 0:
                        raise ValueError("archive member has negative size")
                    expanded += member.size
                elif member.issym():
                    target = member.linkname
                    if not target or posixpath.isabs(target) or "\\" in target:
                        raise ValueError("archive symlink target is unsafe")
                    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
                    if resolved == ".." or resolved.startswith("../") or not resolved.startswith(path.parts[0] + "/"):
                        raise ValueError("archive symlink escapes component root")
                elif member.islnk():
                    target_path = _member_path(member.linkname)
                    if target_path.parts[0] != path.parts[0]:
                        raise ValueError("archive hard link escapes component root")
                else:
                    raise ValueError("archive contains a special or unsupported member")
                by_name[name] = (member, path)
            if len(roots) != 1 or expanded > expanded_limit:
                raise ValueError("archive component layout or expanded size is invalid")
            if current_managed_bytes + expanded > overall_limit:
                raise ValueError("archive expansion would exceed managed workspace ceiling")
            for name, (member, path) in by_name.items():
                for parent in path.parents:
                    if parent == PurePosixPath("."):
                        continue
                    ancestor = by_name.get(parent.as_posix())
                    if ancestor and (ancestor[0].issym() or ancestor[0].islnk() or ancestor[0].isfile()):
                        raise ValueError("archive member descends through a non-directory")
            # Make directories first, then regular files, then safe hard/symbolic links.
            destination.mkdir(parents=True)
            created = True
            dirs = sorted((row for row in by_name.values() if row[0].isdir()),
                          key=lambda row: len(row[1].parts))
            for member, path in dirs:
                target = destination.joinpath(*path.parts)
                target.mkdir(parents=True, exist_ok=True)
            for name, (member, path) in by_name.items():
                if not member.isfile():
                    continue
                target = destination.joinpath(*path.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                source = bundle.extractfile(member)
                if source is None:
                    raise ValueError("archive regular file has no payload")
                remaining = member.size
                with source, target.open("xb") as output:
                    while remaining:
                        block = source.read(min(ARCHIVE_CHUNK, remaining))
                        if not block:
                            raise ValueError("archive payload ended before its declared size")
                        output.write(block)
                        remaining -= len(block)
                    if source.read(1):
                        raise ValueError("archive payload exceeds its declared size")
                target.chmod(member.mode & 0o777)
            for name, (member, path) in by_name.items():
                target = destination.joinpath(*path.parts)
                if member.islnk():
                    link = _member_path(member.linkname)
                    source = destination.joinpath(*link.parts)
                    if not source.is_file() or source.is_symlink():
                        raise ValueError("archive hard link target is not a regular file")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    os.link(source, target)
                elif member.issym():
                    target.parent.mkdir(parents=True, exist_ok=True)
                    os.symlink(member.linkname, target)
            for member, path in reversed(dirs):
                target = destination.joinpath(*path.parts)
                target.chmod(member.mode & 0o777)
        return {"component_root": next(iter(roots)), "member_count": len(members),
                "expanded_bytes": expanded}
    except BaseException as error:
        if created and destination.exists():
            try:
                shutil.rmtree(destination)
            except OSError as cleanup_error:
                raise RuntimeError("archive extraction failed and partial output could not be removed") from cleanup_error
        raise


def tree_inventory(root: Path, *, exclude_git: bool = False) -> dict:
    """Hash every entry deterministically without retaining an oversized listing."""
    digest = hashlib.sha256()
    count = total = symlinks = 0
    license_digest = hashlib.sha256()
    license_count = license_bytes = 0
    license_names = ("license", "licence", "copying", "notice", "copyright", "patents")
    paths = []
    for path in root.rglob("*"):
        if exclude_git and (".git" in path.relative_to(root).parts):
            continue
        paths.append(path)
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        row = {"path": relative, "mode": info.st_mode & 0o777}
        if stat.S_ISREG(info.st_mode):
            file_hash = sha256(path)
            row.update({"type": "file", "bytes": info.st_size, "sha256": file_hash})
            total += info.st_size
        elif stat.S_ISLNK(info.st_mode):
            row.update({"type": "symlink", "target": os.readlink(path)})
            symlinks += 1
        else:
            raise ValueError("inventory contains unsupported filesystem entry: " + relative)
        encoded = json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        digest.update(encoded)
        count += 1
        lower = PurePosixPath(relative).name.casefold()
        if any(lower.startswith(prefix) for prefix in license_names) or "/license/" in ("/" + relative.casefold() + "/"):
            license_digest.update(encoded)
            license_count += 1
            license_bytes += info.st_size if stat.S_ISREG(info.st_mode) else len(row["target"].encode())
    return {"entry_count": count, "regular_file_bytes": total, "symlink_count": symlinks,
            "inventory_sha256": digest.hexdigest(),
            "license_inventory": {"entry_count": license_count, "bytes": license_bytes,
                                  "inventory_sha256": license_digest.hexdigest()}}


def process_rows(*, timeout: float = PROCESS_ROWS_TIMEOUT_SECONDS):
    if timeout <= 0 or timeout > 5:
        raise ValueError("process table observer timeout exceeds the bounded policy")
    output = subprocess.check_output(["/bin/ps", "-axo", "pid=,ppid=,pgid=,rss="],
                                     text=True, timeout=timeout)
    return [tuple(map(int, line.split())) for line in output.splitlines()
            if len(line.split()) == 4]


def rss_group(pid: int, rows=None) -> int:
    rows = process_rows() if rows is None else rows
    ids = {pid}
    while True:
        extra = {child for child, parent, group, _ in rows
                 if parent in ids or group == pid} - ids
        if not extra:
            return sum(kib * 1024 for child, _, _, kib in rows if child in ids)
        ids |= extra


def group_alive(pid: int, rows=None) -> bool:
    rows = process_rows() if rows is None else rows
    return any(group == pid for _, _, group, _ in rows)


def descendant_process_groups(root_pid: int, rows=None) -> list[int]:
    """Return process groups below root_pid, excluding the root's own group."""
    rows = process_rows() if rows is None else rows
    root_row = next((row for row in rows if row[0] == root_pid), None)
    if root_row is None:
        return []
    root_group = root_row[2]
    children = {}
    for pid, parent, group, rss in rows:
        children.setdefault(parent, set()).add(pid)
    descendants = {root_pid}
    pending = [root_pid]
    while pending:
        parent = pending.pop()
        for child in children.get(parent, ()):
            if child not in descendants:
                descendants.add(child)
                pending.append(child)
    return sorted({group for pid, parent, group, rss in rows
                   if pid in descendants and group != root_group})


def _groups_alive(group_ids, rows_reader):
    groups = set(group_ids)
    if not groups:
        return [], None
    try:
        rows = rows_reader()
    except (OSError, subprocess.SubprocessError, ValueError, TypeError) as error:
        return sorted(groups), type(error).__name__ + ": " + str(error)[:300]
    return sorted({group for _, _, group, _ in rows if group in groups}), None


def _signal_groups(group_ids, signum):
    sent = []
    errors = []
    for group in sorted(set(group_ids)):
        try:
            os.killpg(group, signum)
            sent.append(group)
        except ProcessLookupError:
            pass
        except (OSError, PermissionError) as error:
            errors.append(f"{group}:{type(error).__name__}:{str(error)[:160]}")
    return sent, errors


def stop_process_groups(group_ids, rows_reader=None, *, grace_seconds: float = 3.0) -> dict:
    """Terminate only already-observed process groups, then verify they are gone."""
    if rows_reader is None:
        rows_reader = process_rows
    return _terminate_process_groups(group_ids, rows_reader, grace_seconds)


def _terminate_process_groups(group_ids, rows_reader, grace_seconds, *, reap=None):
    groups = sorted({int(group) for group in group_ids if type(group) is int and group > 1})
    result = {"group_ids": groups, "sigterm_group_ids": [], "sigkill_group_ids": [],
              "remaining_group_ids": [], "observer_errors": [], "signal_errors": [],
              "complete": True, "incomplete_cleanup": False, "status": "complete"}
    if not groups:
        return result
    alive, error = _groups_alive(groups, rows_reader)
    if error:
        result["observer_errors"].append(error)
        alive = groups
    result["sigterm_group_ids"], errors = _signal_groups(alive, signal.SIGTERM)
    result["signal_errors"].extend(errors)
    deadline = time.monotonic() + max(0.0, grace_seconds)
    while time.monotonic() < deadline:
        if reap is not None:
            reap()
        alive, error = _groups_alive(groups, rows_reader)
        if error:
            if error not in result["observer_errors"]:
                result["observer_errors"].append(error)
            alive = groups
            break
        if not alive:
            break
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    if reap is not None:
        reap()
    alive, error = _groups_alive(groups, rows_reader)
    if error:
        if error not in result["observer_errors"]:
            result["observer_errors"].append(error)
        alive = groups
    if alive:
        result["sigkill_group_ids"], errors = _signal_groups(alive, signal.SIGKILL)
        result["signal_errors"].extend(errors)
        deadline = time.monotonic() + max(0.25, grace_seconds)
        while time.monotonic() < deadline:
            if reap is not None:
                reap()
            alive, error = _groups_alive(groups, rows_reader)
            if error:
                if error not in result["observer_errors"]:
                    result["observer_errors"].append(error)
                alive = groups
                break
            if not alive:
                break
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    if reap is not None:
        reap()
    alive, error = _groups_alive(groups, rows_reader)
    if error:
        if error not in result["observer_errors"]:
            result["observer_errors"].append(error)
        alive = groups
    result["remaining_group_ids"] = alive
    result["complete"] = not alive and not result["observer_errors"] and not result["signal_errors"]
    result["incomplete_cleanup"] = not result["complete"]
    result["status"] = "complete" if result["complete"] else "incomplete_cleanup"
    return result


def reap_child_bounded(child: subprocess.Popen, *, process_group_id: int | None = None,
                       wait_seconds: float = 3.0,
                       sigkill_wait_seconds: float = 3.0) -> dict:
    """Reap a direct child with two finite waits and an explicit failure receipt."""
    if (wait_seconds < 0 or sigkill_wait_seconds < 0
            or wait_seconds > 10 or sigkill_wait_seconds > 10
            or (process_group_id is not None
                and (type(process_group_id) is not int or process_group_id <= 1))):
        raise ValueError("direct-child reap input is outside the bounded policy")
    result = {"schema": "ami-rust-direct-child-reap-v1", "status": "complete",
              "incomplete_cleanup": False, "wait_attempt_count": 0,
              "initial_wait_timeout_seconds": wait_seconds,
              "post_sigkill_wait_timeout_seconds": sigkill_wait_seconds,
              "sigkill_attempted": False, "signal_errors": [],
              "process_group_id": process_group_id,
              "initial_wait_timed_out": False, "post_sigkill_wait_timed_out": False,
              "return_code": None}
    try:
        result["wait_attempt_count"] += 1
        child.wait(timeout=wait_seconds)
    except subprocess.TimeoutExpired:
        result["initial_wait_timed_out"] = True
        result["sigkill_attempted"] = True
        if process_group_id is not None:
            try:
                os.killpg(process_group_id, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except (OSError, PermissionError) as error:
                result["signal_errors"].append(
                    f"killpg:{type(error).__name__}:{str(error)[:160]}")
        try:
            child.kill()
        except ProcessLookupError:
            pass
        except (OSError, PermissionError) as error:
            result["signal_errors"].append(
                f"kill:{type(error).__name__}:{str(error)[:160]}")
        try:
            result["wait_attempt_count"] += 1
            child.wait(timeout=sigkill_wait_seconds)
        except subprocess.TimeoutExpired:
            result["post_sigkill_wait_timed_out"] = True
        except BaseException as error:
            result["signal_errors"].append(
                f"wait:{type(error).__name__}:{str(error)[:160]}")
    except BaseException as error:
        result["signal_errors"].append(
            f"wait:{type(error).__name__}:{str(error)[:160]}")
    result["return_code"] = child.returncode
    result["incomplete_cleanup"] = bool(
        result["post_sigkill_wait_timed_out"] or result["signal_errors"]
        or child.returncode is None)
    result["status"] = "incomplete_cleanup" if result["incomplete_cleanup"] else "complete"
    return result


def stop_group(child: subprocess.Popen, rows_reader=None, *, grace_seconds: float = 3,
               descendant_groups=()) -> dict:
    """Stop observed groups, then perform bounded direct-child reaping."""
    if rows_reader is None:
        rows_reader = process_rows
    groups = sorted(({child.pid} | set(descendant_groups)) - {0, 1})
    result = _terminate_process_groups(groups, rows_reader, grace_seconds, reap=child.poll)
    direct_reap = reap_child_bounded(child, process_group_id=child.pid)
    result["direct_child_reap"] = direct_reap
    if direct_reap["sigkill_attempted"]:
        result["sigkill_group_ids"] = sorted(
            set(result["sigkill_group_ids"]) | {child.pid})
    result["complete"] = bool(result["complete"] and direct_reap["status"] == "complete")
    result["incomplete_cleanup"] = not result["complete"]
    result["status"] = "complete" if result["complete"] else "incomplete_cleanup"
    return result




class Supervisor:
    def __init__(self, work: Path, output: Path, env: dict[str, str], log_dir: Path,
                 extra_roots: tuple[Path, ...] = ()):
        self.work, self.output, self.env, self.log_dir = work, output, env, log_dir
        self.extra_roots = extra_roots
        self.checkout_bytes = directory_bytes(ROOT)
        self.work_under_checkout = work.resolve().is_relative_to(ROOT.resolve())
        self.output_under_checkout = output.resolve().is_relative_to(ROOT.resolve())
        self.initial_work_bytes = directory_bytes(work)
        self.initial_output_bytes = directory_bytes(output)
        self.peak_rss = 0
        self.peak_workspace = self.managed_bytes()
        self.commands = []

    def managed_bytes(self):
        work_bytes = directory_bytes(self.work)
        output_bytes = directory_bytes(self.output)
        total = self.checkout_bytes
        total += work_bytes - self.initial_work_bytes if self.work_under_checkout else work_bytes
        total += output_bytes - self.initial_output_bytes if self.output_under_checkout else output_bytes
        total += sum(directory_bytes(path) for path in self.extra_roots)
        return total

    def logs_bytes(self):
        total = 0
        for path in self.work.rglob("*.log"):
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISREG(info.st_mode):
                total += info.st_size
        return total

    def run(self, command, *, cwd: Path, label: str, timeout: int = 1200,
            stdin_bytes: bytes | None = None, rss_guard=None,
            cleanup_descendant_groups: bool = False) -> dict:
        stdout_path = self.log_dir / (label + ".stdout.log")
        stderr_path = self.log_dir / (label + ".stderr.log")
        if self.managed_bytes() > MAX_WORK_BYTES:
            raise RuntimeError("managed workspace ceiling exceeded before " + label)
        if rss_guard is not None and not rss_guard(0):
            raise RuntimeError("external RSS guard exceeded before " + label)
        start = time.monotonic()
        peak_rss = peak_size = 0
        reason = None
        descendant_groups = set()
        cleanup_result = None
        cleanup_error = None
        cleanup_census_errors = []
        direct_child_reap = None
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            child = subprocess.Popen(command, cwd=cwd, env=self.env, stdout=stdout, stderr=stderr,
                                     stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
                                     start_new_session=True)
            try:
                if stdin_bytes is not None:
                    child.stdin.write(stdin_bytes)
                    child.stdin.close()
                next_size = 0.0
                while child.poll() is None:
                    rows = process_rows()
                    peak_rss = max(peak_rss, rss_group(child.pid, rows))
                    if cleanup_descendant_groups:
                        descendant_groups.update(descendant_process_groups(child.pid, rows))
                    now = time.monotonic()
                    if now >= next_size:
                        peak_size = max(peak_size, self.managed_bytes())
                        next_size = now + 0.5
                    if now - start > timeout:
                        reason = reason or "timeout"
                    if rss_guard is not None and not rss_guard(peak_rss):
                        reason = reason or "external RSS guard"
                    if peak_rss > MAX_RSS_BYTES:
                        reason = reason or "aggregate RSS ceiling"
                    if peak_size > MAX_WORK_BYTES:
                        reason = reason or "managed workspace ceiling"
                    if self.logs_bytes() > MAX_LOG_BYTES:
                        reason = reason or "aggregate log ceiling"
                    if reason:
                        break
                    time.sleep(0.1)
            except BaseException as error:
                reason = "monitor failure: " + type(error).__name__ + ": " + str(error)[:300]
            finally:
                descendants_alive = False
                if cleanup_descendant_groups:
                    try:
                        rows = process_rows()
                        descendant_groups.update(descendant_process_groups(child.pid, rows))
                        descendants_alive = any(group in descendant_groups
                                                for _, _, group, _ in rows)
                    except (OSError, subprocess.SubprocessError, ValueError, TypeError) as error:
                        message = (type(error).__name__ + ": " + str(error)[:200])
                        cleanup_census_errors.append(message)
                        reason = reason or ("monitor failure during descendant cleanup census: "
                                            + message)
                        descendants_alive = bool(descendant_groups)
                try:
                    root_group_alive = group_alive(child.pid)
                except (OSError, subprocess.SubprocessError, ValueError, TypeError) as error:
                    reason = reason or ("monitor failure checking process group: "
                                        + type(error).__name__ + ": " + str(error)[:200])
                    root_group_alive = True
                if reason or root_group_alive or descendants_alive:
                    reason = reason or "leader exited while a supervised process group remained alive"
                    try:
                        cleanup_result = stop_group(
                            child, grace_seconds=SUPERVISOR_STOP_GRACE_SECONDS,
                            descendant_groups=descendant_groups if cleanup_descendant_groups else ())
                        direct_child_reap = cleanup_result.get("direct_child_reap")
                    except BaseException as error:
                        cleanup_error = type(error).__name__ + ": " + str(error)[:300]
                        signal_errors = []
                        try:
                            os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        except (OSError, PermissionError) as signal_error:
                            signal_errors.append(
                                f"killpg:{type(signal_error).__name__}:{str(signal_error)[:160]}")
                        try:
                            child.kill()
                        except ProcessLookupError:
                            pass
                        except (OSError, PermissionError) as signal_error:
                            signal_errors.append(
                                f"kill:{type(signal_error).__name__}:{str(signal_error)[:160]}")
                        direct_child_reap = reap_child_bounded(child)
                        cleanup_result = {
                            "group_ids": sorted({child.pid} | descendant_groups),
                            "sigterm_group_ids": [], "sigkill_group_ids": [child.pid],
                            "remaining_group_ids": sorted(descendant_groups),
                            "observer_errors": list(cleanup_census_errors),
                            "signal_errors": signal_errors,
                            "direct_child_reap": direct_child_reap,
                            "complete": False, "incomplete_cleanup": True,
                            "status": "incomplete_cleanup", "cleanup_error": cleanup_error}
                else:
                    direct_child_reap = reap_child_bounded(child)
                    if direct_child_reap["status"] != "complete":
                        reason = reason or "incomplete_cleanup: direct child reap failed"
                        cleanup_result = stop_group(
                            child, grace_seconds=SUPERVISOR_STOP_GRACE_SECONDS,
                            descendant_groups=descendant_groups if cleanup_descendant_groups else ())
                        direct_child_reap = cleanup_result.get("direct_child_reap", direct_child_reap)
        if self.logs_bytes() > MAX_LOG_BYTES:
            reason = reason or "aggregate log ceiling"
        if rss_guard is not None and not rss_guard(peak_rss):
            reason = reason or "external RSS guard"
        peak_size = max(peak_size, self.managed_bytes())
        if peak_size > MAX_WORK_BYTES:
            reason = reason or "managed workspace ceiling"
        if cleanup_census_errors:
            cleanup_result = cleanup_result or {
                "group_ids": sorted({child.pid} | descendant_groups),
                "sigterm_group_ids": [], "sigkill_group_ids": [],
                "remaining_group_ids": sorted(descendant_groups),
                "observer_errors": [], "signal_errors": [],
                "complete": False, "incomplete_cleanup": True,
                "status": "incomplete_cleanup"}
            cleanup_result["observer_errors"] = sorted(
                set(cleanup_result.get("observer_errors", [])) | set(cleanup_census_errors))
            cleanup_result["complete"] = False
            cleanup_result["incomplete_cleanup"] = True
            cleanup_result["status"] = "incomplete_cleanup"
        if cleanup_result and cleanup_result.get("incomplete_cleanup"):
            reason = reason or "incomplete_cleanup"
        elapsed = time.monotonic() - start
        row = {"label": label, "exit_code": child.returncode, "stop_reason": reason,
               "elapsed_seconds": round(elapsed, 3), "rss_peak_observed_bytes": peak_rss,
               "managed_peak_observed_bytes": max(peak_size, self.managed_bytes()),
               "stdout_log": stdout_path.relative_to(self.work).as_posix(),
               "stderr_log": stderr_path.relative_to(self.work).as_posix(),
               "direct_child_reap": direct_child_reap,
               "cleanup_status": (cleanup_result or {}).get("status", "complete"),
               "incomplete_cleanup": bool((cleanup_result or {}).get("incomplete_cleanup", False))}
        if cleanup_descendant_groups:
            row["tracked_descendant_process_group_ids"] = sorted(descendant_groups)
            row["descendant_process_group_cleanup"] = cleanup_result or {
                "group_ids": [], "sigterm_group_ids": [], "sigkill_group_ids": [],
                "remaining_group_ids": [], "observer_errors": list(cleanup_census_errors),
                "signal_errors": [], "direct_child_reap": direct_child_reap,
                "complete": not bool(cleanup_error or cleanup_census_errors),
                "incomplete_cleanup": bool(cleanup_error or cleanup_census_errors),
                "status": "incomplete_cleanup" if cleanup_error or cleanup_census_errors else "complete"}
            if cleanup_error:
                row["descendant_process_group_cleanup"]["cleanup_error"] = cleanup_error
        self.peak_rss = max(self.peak_rss, peak_rss)
        self.peak_workspace = max(self.peak_workspace, row["managed_peak_observed_bytes"])
        self.commands.append(row)
        if reason or child.returncode:
            stderr_tail = stderr_path.read_bytes()[-4096:].decode("utf-8", "replace")
            suffix = ("; cleanup " + cleanup_error) if cleanup_error else ""
            raise RuntimeError(f"{label} failed: {reason or 'exit ' + str(child.returncode)}; "
                               + stderr_tail[-1000:] + suffix)
        if cleanup_error:
            raise RuntimeError(f"{label} cleanup failed: " + cleanup_error)
        return row

    def run_text(self, command, *, cwd: Path, label: str, timeout: int = 60) -> str:
        row = self.run(command, cwd=cwd, label=label, timeout=timeout)
        return (self.work / row["stdout_log"]).read_text(errors="replace")


def directory_bytes(root: Path) -> int:
    total = 0
    for path in root.rglob("*"):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
    return total


def safe_run_env(work: Path, rust_bin: Path) -> dict[str, str]:
    private_home = work / "home"
    cargo_home = work / "cargo-home"
    tmp = work / "tmp"
    for path in (private_home, cargo_home, tmp):
        path.mkdir()
    env = {"HOME": str(private_home), "CARGO_HOME": str(cargo_home),
           "TMPDIR": str(tmp), "TMP": str(tmp), "TEMP": str(tmp),
           "PATH": str(rust_bin) + ":/usr/bin:/bin:/usr/sbin:/sbin",
           "LC_ALL": "C", "TZ": "UTC", "GIT_TERMINAL_PROMPT": "0",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
           "GIT_OPTIONAL_LOCKS": "0", "CARGO_INCREMENTAL": "0"}
    return env


def _verified_component_rows(inputs: dict, target: str):
    components = inputs["rust"]["components"][target]
    names = ("rustc", "rust-std", "cargo")
    rows = []
    for name in names:
        entry = components[name]
        url = entry["url"]
        expected = f"{name}-1.98.1-{target}.tar.xz"
        if urllib.parse.urlparse(url).path.rsplit("/", 1)[-1] != expected:
            raise ValueError("Rust component URL does not match its pinned release/host name")
        rows.append((name, entry["http_content_length"], entry["sha256"], url))
    return rows


def cargo_custom_source(inputs: dict, work: Path, supervisor: Supervisor, repo: Path,
                        resources: Path) -> tuple[Path, dict]:
    pin = inputs["custom_cargo"]
    source = work / "cargo-source"
    source.mkdir()
    git = "/usr/bin/git"
    supervisor.run([git, "init", "--quiet", str(source)], cwd=work, label="git-init", timeout=60)
    supervisor.run([git, "-C", str(source), "remote", "add", "origin", pin["upstream"]],
                   cwd=work, label="git-remote", timeout=30)
    supervisor.run([git, "-C", str(source), "fetch", "--quiet", "--depth=1", "origin", pin["commit"]],
                   cwd=work, label="git-fetch", timeout=180)
    supervisor.run([git, "-C", str(source), "checkout", "--quiet", "--detach", "FETCH_HEAD"],
                   cwd=work, label="git-checkout", timeout=60)
    head = supervisor.run_text([git, "-C", str(source), "rev-parse", "HEAD"],
                               cwd=work, label="git-verify-head", timeout=30).strip()
    if head != pin["commit"]:
        raise ValueError("fetched Cargo source commit differs from the pin")
    lock = source / pin["cargo_lock"]["path"]
    if sha256(lock) != pin["cargo_lock"]["sha256"] or lock.stat().st_size != pin["cargo_lock"]["bytes"]:
        raise ValueError("Cargo.lock differs from the pinned source lock")
    patch_path = repo / pin["patch_path"]
    if sha256(patch_path) != pin["patch_sha256"]:
        raise ValueError("Cargo custom patch differs from its pin")
    patch_rows = []
    for target in pin["patch_targets"]:
        file = source / target["path"]
        if sha256(file) != target["upstream_sha256"]:
            raise ValueError("Cargo patch target differs from its upstream pin: " + target["path"])
        patch_rows.append({"path": target["path"], "upstream_sha256": target["upstream_sha256"],
                           "patched_sha256": target["patched_sha256"]})
    supervisor.run(["/usr/bin/patch", "-p1", "--batch", "--forward", "-i", str(patch_path)],
                   cwd=source, label="apply-cargo-patch", timeout=30)
    changed = supervisor.run_text([git, "-C", str(source), "diff", "--name-only"],
                                  cwd=work, label="git-verify-patch", timeout=30).splitlines()
    if sorted(changed) != sorted(row["path"] for row in pin["patch_targets"]):
        raise ValueError("Cargo patch changed an unexpected source path")
    for target in pin["patch_targets"]:
        if sha256(source / target["path"]) != target["patched_sha256"]:
            raise ValueError("Cargo patch output differs from its pinned digest: " + target["path"])
    inventory = tree_inventory(source, exclude_git=True)
    return source, {"upstream": pin["upstream"], "commit": head,
                    "cargo_lock_sha256": sha256(lock), "patch_sha256": sha256(patch_path),
                    "patch_targets": patch_rows, "inventory": inventory}


def write_json(path: Path, record: dict) -> None:
    path.write_text(json.dumps(record, sort_keys=True, indent=2, ensure_ascii=False) + "\n")


def validate_output_metadata(output: Path) -> dict:
    """Require exactly one bounded, parseable producer metadata object."""
    entries = list(output.iterdir())
    if (len(entries) != 1 or entries[0].name != "producer.json"
            or entries[0].is_symlink() or not entries[0].is_file()
            or directory_bytes(output) > 32 * 1024**2):
        raise ValueError("producer output must contain only producer.json under 32 MiB")
    record = json.loads(entries[0].read_text())
    if (not isinstance(record, dict) or record.get("schema") != PRODUCER_SCHEMA
            or record.get("status") not in {
                "PRODUCED_PREREQUISITE_ONLY_NOT_R1_QUALIFICATION", "FAILED"}):
        raise ValueError("producer output JSON has an invalid schema or status")
    return record


def produce(args) -> dict:
    if not args.work.is_absolute() or not args.output.is_absolute():
        raise ValueError("--work and --output must be absolute paths")
    if args.work.is_symlink() or args.output.is_symlink():
        raise ValueError("--work and --output must not be symlinks")
    work, output = args.work.resolve(), args.output.resolve()
    inputs_path, resources_path = args.inputs.resolve(strict=True), args.resources.resolve(strict=True)
    if work.exists() or output.exists() or work.is_symlink() or output.is_symlink():
        raise ValueError("--work and --output must be fresh paths")
    if not work.parent.is_dir() or not output.parent.is_dir():
        raise ValueError("--work and --output parent directories must already exist")
    if work == output or work in output.parents or output in work.parents:
        raise ValueError("--work and --output must not overlap")
    if not inputs_path.is_file() or not resources_path.is_file():
        raise ValueError("input pins and resource policy must be regular files")
    inputs = json.loads(inputs_path.read_text())
    resources = json.loads(resources_path.read_text())
    host, rust_target = validate_pins(inputs, resources)
    python_bootstrap = None
    extra_roots = ()
    runtime_pin = inputs.get("python_runtime_manifest")
    if runtime_pin is not None:
        manifest_path = ROOT / "release/ci-python-inputs.json"
        if (runtime_pin.get("path") != "release/ci-python-inputs.json"
                or sha256(manifest_path) != runtime_pin.get("sha256")):
            raise ValueError("portable Python manifest differs from its normative pin")
        bootstrap_root = args.python_bootstrap_root
        if (bootstrap_root is None or not bootstrap_root.is_absolute()
                or bootstrap_root.is_symlink() or not bootstrap_root.is_dir()
                or bootstrap_root.parent.resolve() != work.parent.resolve()
                or bootstrap_root.name != "ami-rust-python-bootstrap"):
            raise ValueError("portable Python bootstrap must be the managed sibling runtime prefix")
        bootstrap_root = bootstrap_root.resolve(strict=True)
        python_bootstrap = json.loads((bootstrap_root / "bootstrap.json").read_text())
        runtime_inputs = json.loads(manifest_path.read_text())
        selected_python = runtime_inputs["hosts"][host]
        if (python_bootstrap.get("status") != "READY_CI_RUNTIME_NOT_SDK_QUALIFICATION"
                or python_bootstrap.get("host") != host
                or python_bootstrap.get("archive_sha256") != selected_python["sha256"]
                or python_bootstrap.get("runtime_sha256") != selected_python["runtime_sha256"]
                or Path(sys.executable).resolve(strict=True) !=
                   (bootstrap_root / "runtime" / selected_python["runtime_relative_path"]).resolve(strict=True)):
            raise ValueError("portable Python runtime receipt or executable is not the admitted input")
        extra_roots = (bootstrap_root,)
    elif args.python_bootstrap_root is not None:
        raise ValueError("unselected portable Python prefix")
    capacity = {"work": check_capacity(host, work.parent, resources),
                "output": check_capacity(host, output.parent, resources)}
    python_path = Path(sys.executable).resolve(strict=True)
    python_digest = sha256(python_path)
    python_pin = inputs["python"][host]["sha256"]
    if python_digest != python_pin:
        raise ValueError("active Python interpreter differs from the pinned hosted receipt")

    work.mkdir()
    output.mkdir()
    log_dir = work / "logs"
    log_dir.mkdir()
    download_dir = work / "rust-archives"
    download_dir.mkdir()
    extracted = work / "rust-components"
    extracted.mkdir()
    bootstrap_prefix = work / "bootstrap"
    bootstrap_prefix.mkdir()
    env = safe_run_env(work, work / "bootstrap/bin")
    supervisor = Supervisor(work, output, env, log_dir, extra_roots=extra_roots)
    stage = "preflight"
    start = time.monotonic()
    materials = []
    try:
        stage = "download-and-verify-rust"
        for name, size, digest, url in _verified_component_rows(inputs, rust_target):
            if supervisor.managed_bytes() + size > MAX_WORK_BYTES:
                raise ValueError("Rust download would exceed managed workspace ceiling")
            archive = download_dir / (name + ".tar.xz")
            receipt = download_verified(url, size, digest, archive)
            receipt.update({"component": name, "url": url,
                            "relative_file": archive.relative_to(work).as_posix()})
            materials.append(receipt)
            extract_root = extracted / name
            extraction = safe_extract_tar(archive, extract_root,
                                          current_managed_bytes=supervisor.managed_bytes())
            receipt["archive_member_count"] = extraction["member_count"]
            receipt["expanded_bytes"] = extraction["expanded_bytes"]
            component = extract_root / extraction["component_root"]
            supervisor.run([str(component / "install.sh"), "--prefix=" + str(bootstrap_prefix),
                            "--disable-ldconfig"], cwd=component,
                           label="install-rust-" + name, timeout=180)
        stage = "verify-rust-bootstrap"
        rust_bin = bootstrap_prefix / "bin"
        env["PATH"] = str(rust_bin) + ":/usr/bin:/bin:/usr/sbin:/sbin"
        env["RUSTC"] = str(rust_bin / "rustc")
        env["RUSTDOC"] = str(rust_bin / "rustdoc")
        compiler = supervisor.run_text([str(rust_bin / "rustc"), "-Vv"], cwd=work,
                                        label="rustc-version", timeout=30)
        if ("release: " + inputs["rust"]["release"] + "\n") not in compiler or (
                "commit-hash: " + inputs["rust"]["commit"]) not in compiler:
            raise ValueError("installed Rust compiler version/commit differs from its pin")
        bootstrap_cargo_version = supervisor.run_text([str(rust_bin / "cargo"), "-Vv"],
                                                       cwd=work, label="bootstrap-cargo-version", timeout=30)
        if ("cargo 1.98.1" not in bootstrap_cargo_version
                or "commit-hash: " + inputs["rust"]["cargo_commit"] not in bootstrap_cargo_version
                or "host: " + rust_target not in bootstrap_cargo_version):
            raise ValueError("installed bootstrap Cargo version/commit differs from its pin")
        bootstrap_inventory = tree_inventory(bootstrap_prefix)
        stage = "fetch-and-patch-cargo-source"
        source, source_record = cargo_custom_source(inputs, work, supervisor, ROOT, resources_path)
        vendor = work / "vendor-upstream"
        provision_work = work / "provision-work"
        provision_record = work / "records/provision"
        build_work = work / "build-work"
        build_record = work / "records/build"
        (work / "records").mkdir()
        common = [sys.executable, "-I", "-B", str(ROOT / "host/cargo-repro/produce.py"),
                  "--source", str(source), "--host-rust", str(bootstrap_prefix),
                  "--resource-policy", str(resources_path), "--share-supervisor-group"]
        stage = "provision-vendor"
        supervisor.run(common + ["provision", "--work", str(provision_work), "--record", str(provision_record),
                                 "--vendor", str(vendor)],
                       cwd=source, label="cargo-vendor", timeout=600)
        upstream_inventory = tree_inventory(vendor)
        overlay = work / "vendor-overlay"
        overlay_receipt = work / "vendor-overlay-receipt.json"
        stage = "prepare-vendor-overlay"
        supervisor.run([sys.executable, "-I", "-B", str(ROOT / "host/cargo-repro/prepare-overlay.py"),
                        "--source-vendor", str(vendor), "--output-vendor", str(overlay),
                        "--receipt", str(overlay_receipt)], cwd=source,
                       label="cargo-vendor-overlay", timeout=600)
        overlay_inventory = tree_inventory(overlay)
        stage = "build-custom-cargo"
        supervisor.run(common + ["build", "--work", str(build_work), "--record", str(build_record),
                                 "--vendor", str(overlay), "--vendor-overlay-receipt", str(overlay_receipt),
                                 "--profile", "release"], cwd=source,
                       label="cargo-build", timeout=1200)
        build_result = json.loads((build_record / "result.json").read_text())
        artifact = build_result.get("artifact")
        cargo_path = build_work / "target/release/cargo"
        if not isinstance(artifact, dict) or not cargo_path.is_file():
            raise ValueError("producer did not report the release Cargo artifact")
        if artifact.get("sha256") != sha256(cargo_path) or artifact.get("bytes") != cargo_path.stat().st_size:
            raise ValueError("Cargo artifact bytes/hash differ from producer result")
        version = supervisor.run_text([str(cargo_path), "-Vv"], cwd=work,
                                       label="built-cargo-version", timeout=30)
        if "commit-hash: " + inputs["custom_cargo"]["commit"] not in version:
            raise ValueError("built Cargo version identity does not report the pinned source commit")
        source_after = tree_inventory(source, exclude_git=True)
        if source_after != source_record["inventory"]:
            raise ValueError("Cargo source tree changed during producer build")
        if tree_inventory(vendor) != upstream_inventory:
            raise ValueError("vendor overlay helper changed the upstream vendor tree")
        overlay_receipt_record = json.loads(overlay_receipt.read_text())
        helper_pins = inputs["producer_helpers"]
        helper_actual = {"produce.py": sha256(ROOT / "host/cargo-repro/produce.py"),
                         "prepare-overlay.py": sha256(ROOT / "host/cargo-repro/prepare-overlay.py"),
                         "build.py": sha256(ROOT / "host/build.py"),
                         "ci_cargo.py": sha256(SCRIPT)}
        record = {
            "schema": "ami-rust-hosted-custom-cargo-producer-v1",
            "status": "PRODUCED_PREREQUISITE_ONLY_NOT_R1_QUALIFICATION",
            "host": host, "rust_target": rust_target,
            "claim": "Pinned host Cargo prerequisite producer; no SDK, guest, or R1 qualification.",
            "input_materials": {
                "inputs_sha256": sha256(inputs_path), "resource_policy_sha256": sha256(resources_path),
                "python": {"executable_basename": python_path.name, "sha256": python_digest,
                           "pinned_sha256": python_pin, "version": platform.python_version()},
                "python_runtime": python_bootstrap,
                "rust_archives": materials,
                "rust_channel_manifest": inputs["rust"]["manifest"],
                "rust_release": inputs["rust"]["release"], "rust_commit": inputs["rust"]["commit"],
                "installed_rustc_version": compiler.strip(),
                "installed_bootstrap_cargo_version": bootstrap_cargo_version.strip(),
                "bootstrap_cargo_commit": inputs["rust"]["cargo_commit"],
                "bootstrap_inventory": bootstrap_inventory,
                "cargo_upstream": source_record,
                "cargo_patch": {"path": inputs["custom_cargo"]["patch_path"],
                                "sha256": inputs["custom_cargo"]["patch_sha256"],
                                "targets": source_record["patch_targets"]},
                "openssl_overlay_recipe_sha256": inputs["openssl_overlay"]["recipe_sha256"],
                "openssl_overlay_patch_sha256": inputs["openssl_overlay"]["patch_sha256"],
                "producer_helpers": {"ci_input_pins": helper_pins,
                                     "actual_sha256": helper_actual,
                                     "driver_sha256": sha256(SCRIPT)},
            },
            "source_inventory": source_record["inventory"],
            "vendor": {"upstream_inventory": upstream_inventory,
                       "overlay_inventory": overlay_inventory,
                       "overlay_receipt_sha256": sha256(overlay_receipt),
                       "overlay_identity": {key: value for key, value in overlay_receipt_record.items()
                                            if key not in ("files", "source_vendor", "output_vendor")}},
            "custom_cargo_artifact": {"relative_path": cargo_path.relative_to(work).as_posix(),
                                      "bytes": cargo_path.stat().st_size, "sha256": sha256(cargo_path),
                                      "version": version.strip()},
            "capacity_preflight": capacity,
            "budgets": resources["build"], "build_profile": "release",
            "peaks": {"rss_observed_bytes": supervisor.peak_rss,
                      "work_plus_output_observed_bytes": max(supervisor.peak_workspace,
                                                             supervisor.managed_bytes()),
                      "checkout_initial_bytes": supervisor.checkout_bytes,
                      "elapsed_seconds": round(time.monotonic() - start, 3),
                      "commands": supervisor.commands},
            "relative_files": [
                {"role": "Cargo checkout", "path": source.relative_to(work).as_posix()},
                {"role": "Rust bootstrap", "path": bootstrap_prefix.relative_to(work).as_posix()},
                {"role": "Cargo vendor", "path": vendor.relative_to(work).as_posix()},
                {"role": "patched vendor", "path": overlay.relative_to(work).as_posix()},
                {"role": "built Cargo", "path": cargo_path.relative_to(work).as_posix()},
                {"role": "producer metadata", "path": "producer.json"},
            ],
        }
        write_json(output / "producer.json", record)
        return validate_output_metadata(output)
    except BaseException as error:
        error_text = str(error).replace(str(ROOT), "<checkout>")
        for path_arg in (work, output):
            error_text = error_text.replace(str(path_arg), "<managed-path>")
        failure = {"schema": "ami-rust-hosted-custom-cargo-producer-v1",
                   "status": "FAILED", "stage": stage,
                   "error": (type(error).__name__ + ": " + error_text.replace("\n", " "))[:2048],
                   "host": host, "rust_target": rust_target,
                   "capacity_preflight": capacity,
                   "peaks": {"rss_observed_bytes": supervisor.peak_rss,
                             "work_plus_output_observed_bytes": max(supervisor.peak_workspace,
                                                                    supervisor.managed_bytes()),
                             "checkout_initial_bytes": supervisor.checkout_bytes,
                             "elapsed_seconds": round(time.monotonic() - start, 3),
                             "commands": supervisor.commands},
                   "claim": "Failed prerequisite producer attempt; this is not R1 qualification."}
        write_json(output / "producer.json", failure)
        validate_output_metadata(output)
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--resources", type=Path, required=True)
    parser.add_argument("--python-bootstrap-root", type=Path)
    args = parser.parse_args(argv)
    try:
        produce(args)
    except BaseException as error:
        output = args.output
        if (output.is_absolute() and not output.exists() and not output.is_symlink()
                and output.parent.is_dir()):
            output.mkdir()
            message = str(error).replace(str(ROOT), "<checkout>")
            for path_arg in (args.work, args.output):
                if path_arg.is_absolute():
                    message = message.replace(str(path_arg), "<managed-path>")
            failure_host, failure_target = host_identity()
            observed_python = Path(sys.executable).resolve(strict=True)
            write_json(output / "producer.json", {
                "schema": "ami-rust-hosted-custom-cargo-producer-v1",
                "status": "FAILED", "stage": "preflight",
                "host": failure_host, "rust_target": failure_target,
                "error_type": type(error).__name__,
                "error": message.replace("\n", " ")[:1024],
                "python_observed": {"executable_basename": observed_python.name,
                                    "sha256": sha256(observed_python),
                                    "version": platform.python_version()},
                "managed_work_tree_exists_at_failure": args.work.exists(),
                "claim": "Failed prerequisite producer attempt; this is not R1 qualification."})
            validate_output_metadata(output)
        print(f"ci_cargo: {type(error).__name__}: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
