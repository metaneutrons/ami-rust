#!/usr/bin/env python3
"""Record bounded disk-space and filesystem observations for a public client."""

from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import stat
import threading
from typing import Any, Callable


SCHEMA = "ami-rust-resource-observations-v1"
MAX_RECEIPT_BYTES = 4 * 1024 * 1024
RECEIPT_NAMES = ("consumer-preparation.json", "tool-bootstrap.json")


class MeasureError(ValueError):
    """Raised when a measurement input cannot be inventoried safely."""


def _read_receipt(path: Path) -> bytes:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise MeasureError(f"cannot open receipt {path.name}") from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_RECEIPT_BYTES:
            raise MeasureError(f"receipt {path.name} is linked, non-regular or oversized")
        content = bytearray()
        while len(content) <= MAX_RECEIPT_BYTES:
            chunk = os.read(fd, min(65536, MAX_RECEIPT_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        if len(content) != info.st_size or len(content) > MAX_RECEIPT_BYTES:
            raise MeasureError(f"receipt {path.name} changed or exceeded its byte bound")
        return bytes(content)
    finally:
        os.close(fd)


def _parse_receipt(raw: bytes) -> dict[str, Any]:
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise MeasureError(f"consumer preparation receipt has duplicate key {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise MeasureError(f"consumer preparation receipt has invalid constant {value}")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                           parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise MeasureError("consumer preparation receipt is not valid bounded JSON") from error
    if type(value) is not dict or value.get("schema") != "ami-rust-consumer-preparation-v1":
        raise MeasureError("consumer preparation receipt has an unsupported schema")

    capacity = value.get("capacity")
    if type(capacity) is not dict or not capacity:
        raise MeasureError("consumer preparation receipt has no capacity measurements")
    for field, item in capacity.items():
        if type(item) is not int or item < 0:
            raise MeasureError(f"consumer preparation capacity field {field} is invalid")

    commands = value.get("commands")
    if type(commands) is not list or len(commands) > 256:
        raise MeasureError("consumer preparation receipt has invalid command observations")
    for command in commands:
        if type(command) is not dict or type(command.get("label")) is not str:
            raise MeasureError("consumer preparation receipt has a malformed command observation")
        elapsed = command.get("elapsed_seconds")
        if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0:
            raise MeasureError("consumer preparation receipt has invalid command timing")
        for field in ("rss_peak_observed_bytes", "managed_peak_observed_bytes"):
            item = command.get(field)
            if type(item) is not int or item < 0:
                raise MeasureError(f"consumer preparation receipt has invalid {field}")

    components = value.get("components")
    if type(components) is not dict or not components:
        raise MeasureError("consumer preparation receipt has no component inventories")
    component_bytes: dict[str, int] = {}
    for name, component in components.items():
        if (type(name) is not str or type(component) is not dict
                or type(component.get("regular_file_bytes")) is not int
                or component["regular_file_bytes"] < 0):
            raise MeasureError("consumer preparation receipt has a malformed component inventory")
        component_bytes[name] = component["regular_file_bytes"]

    source_policy = value.get("source_policy")
    if (type(source_policy) is not dict or not source_policy
            or any(type(item) is not str or len(item) != 40
                   or any(char not in "0123456789abcdef" for char in item)
                   for item in source_policy.values())):
        raise MeasureError("consumer preparation receipt has invalid source identity pins")
    pin_fields = ("selection_sha256", "sdk_manifest_sha256", "release_manifest_sha256", "policy_sha256")
    selection_pins: dict[str, str] = {}
    for field in pin_fields:
        item = value.get(field)
        if (type(item) is not str or len(item) != 64
                or any(char not in "0123456789abcdef" for char in item)):
            raise MeasureError(f"consumer preparation receipt has invalid {field}")
        selection_pins[field] = item

    return {
        "schema": value["schema"],
        "status": value.get("status"),
        "capacity": capacity,
        "commands": commands,
        "components": {name: {"regular_file_bytes": size}
                       for name, size in sorted(component_bytes.items())},
        "source_identity": source_policy,
        "selection_pins": selection_pins,
        "selection_path": value.get("selection_path"),
        "policy_path": value.get("policy_path"),
        "host": value.get("host"),
        "receipt_bytes": len(raw),
        "receipt_sha256": hashlib.sha256(raw).hexdigest(),
        "scope": "original_sdk_supervisor",
        "scope_note": "Original SDK preparation supervisor measurements; not whole-machine measurements.",
    }


def _inventory(paths: list[Path]) -> dict[str, Any]:
    logical_bytes = 0
    allocated_bytes = 0
    regular_files: set[tuple[int, int]] = set()
    regular_count = 0
    symlink_count = 0
    directory_count = 0
    other_count = 0
    exists = False
    stack: list[Path] = []
    for root in paths:
        try:
            info = root.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise MeasureError(f"cannot inspect measurement root {root}") from error
        if not stat.S_ISDIR(info.st_mode):
            raise MeasureError(f"measurement root is not a real directory: {root}")
        exists = True
        stack.append(root)

    while stack:
        directory = stack.pop()
        directory_count += 1
        try:
            with os.scandir(directory) as iterator:
                entries = list(iterator)
        except OSError as error:
            raise MeasureError(f"cannot read measurement directory {directory}") from error
        for entry in entries:
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as error:
                raise MeasureError(f"cannot stat measurement entry {entry.name}") from error
            if stat.S_ISLNK(info.st_mode):
                symlink_count += 1
            elif stat.S_ISDIR(info.st_mode):
                stack.append(Path(entry.path))
            elif stat.S_ISREG(info.st_mode):
                inode = (info.st_dev, info.st_ino)
                if inode not in regular_files:
                    regular_files.add(inode)
                    regular_count += 1
                    logical_bytes += info.st_size
                    allocated_bytes += getattr(info, "st_blocks", 0) * 512
            else:
                other_count += 1

    return {
        "paths": [str(path) for path in paths],
        "exists": exists,
        "regular_file_count": regular_count,
        "regular_file_bytes": logical_bytes,
        "allocated_file_bytes": allocated_bytes,
        "symlink_count": symlink_count,
        "directory_count": directory_count,
        "other_entry_count": other_count,
        "inode_deduplication": "unique (device,inode) within each scope",
        "symlinks_followed": False,
    }


def _sdk_roots(state: Path) -> list[Path]:
    try:
        with os.scandir(state) as entries:
            roots = []
            for entry in entries:
                if not entry.name.startswith("sdk-"):
                    continue
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    roots.append(Path(entry.path))
            return sorted(roots)
    except FileNotFoundError:
        return []
    except OSError as error:
        raise MeasureError("cannot locate installed SDK state") from error


def capture(state: Path, project: Path, buildroot: Path) -> dict[str, Any]:
    """Inventory bounded consumer roots and preserve the original SDK receipt."""
    state, project, buildroot = (Path(os.path.abspath(path)) for path in (state, project, buildroot))
    scopes = {
        "retained_snapshot": [state / "retained"],
        "source": [state / "source"],
        "python_bootstrap": [state / "ami-rust-python-bootstrap"],
        "preparation": [state / "preparation", state / "preparation-output"],
        "installed_sdk": _sdk_roots(state),
        "whole_sdk_state": [state],
        "project": [project],
        "build_outputs": [buildroot],
    }
    receipt_raw = _read_receipt(state / "preparation-output" / "consumer-preparation.json")
    receipt = _parse_receipt(receipt_raw)
    return {
        "schema": SCHEMA,
        "scopes": {name: _inventory(paths) for name, paths in scopes.items()},
        "original_sdk_supervisor": receipt,
    }


def copy_original_receipts(state: Path, destination: Path) -> dict[str, Any]:
    """Copy the two bounded original-SDK receipts without replacing existing files."""
    state = Path(os.path.abspath(state))
    destination = Path(os.path.abspath(destination))
    try:
        destination.mkdir(parents=True, exist_ok=True)
        if not stat.S_ISDIR(destination.lstat().st_mode):
            raise MeasureError("receipt destination is not a real directory")
    except OSError as error:
        raise MeasureError("cannot create receipt destination") from error

    rows = []
    for name in RECEIPT_NAMES:
        raw = _read_receipt(state / "preparation-output" / name)
        target = destination / name
        try:
            with target.open("xb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
        except OSError as error:
            raise MeasureError(f"cannot save original receipt {name}") from error
        rows.append({"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
    return {"scope": "original_sdk_supervisor_receipts", "files": rows}


class DiskSampler:
    """Sample free space on one observed volume and report the observed delta."""

    def __init__(self, root: Path, interval: float = 1.0,
                 disk_usage: Callable[[str | os.PathLike[str]], Any] = shutil.disk_usage) -> None:
        if type(interval) not in (int, float) or not math.isfinite(interval) or interval <= 0:
            raise ValueError("sampling interval must be finite and positive")
        self.root = Path(os.path.abspath(root))
        self.interval = float(interval)
        self.disk_usage = disk_usage
        self._stop = threading.Event()
        self._first = threading.Event()
        self._lock = threading.Lock()
        self._start_free: int | None = None
        self._minimum_free: int | None = None
        self._sample_count = 0
        self._error: str | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> "DiskSampler":
        if self._thread is not None:
            raise RuntimeError("disk sampler can only be started once")
        self._thread = threading.Thread(target=self._sample, name="ami-rust-disk-sampler", daemon=True)
        self._thread.start()
        self._first.wait(timeout=2.0)
        if not self._first.is_set():
            with self._lock:
                self._error = self._error or "initial disk sample did not complete within 2 seconds"
            self._stop.set()
        return self

    def _sample(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    free = int(self.disk_usage(self.root).free)
                    if free < 0:
                        raise ValueError("disk usage returned a negative free-space value")
                    with self._lock:
                        if self._start_free is None:
                            self._start_free = free
                        self._minimum_free = free if self._minimum_free is None else min(self._minimum_free, free)
                        self._sample_count += 1
                except Exception as error:
                    with self._lock:
                        self._error = f"{type(error).__name__}: {error}"
                    return
                finally:
                    self._first.set()
                if self._stop.wait(self.interval):
                    return
        finally:
            self._first.set()

    def stop(self) -> dict[str, Any]:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=2.0)
        with self._lock:
            start = self._start_free
            minimum = self._minimum_free
            error = self._error
            count = self._sample_count
        stopped = thread is None or not thread.is_alive()
        if not stopped:
            error = error or "sampling thread did not stop within 2 seconds"
        return {
            "scope": "observed_volume_free_space_delta",
            "root": str(self.root),
            "sampling_interval_seconds": self.interval,
            "sample_count": count,
            "start_free_bytes": start,
            "minimum_free_bytes": minimum,
            "peak_free_delta_bytes": (max(0, start - minimum)
                                      if start is not None and minimum is not None else None),
            "sampling_error": error,
            "thread_stopped": stopped,
        }
