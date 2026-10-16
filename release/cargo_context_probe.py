#!/usr/bin/env python3
"""Compare two independently produced pinned host Cargo binaries.

Run with the selected pinned Python runtime.  Example:
  python release/cargo_context_probe.py --temporary /abs/run/managed \
    --output /abs/run/managed/evidence --inputs release/ci-bootstrap-inputs.json \
    --resources release/ci-resources.json \
    --python-bootstrap-root /abs/run/managed/ami-rust-python-bootstrap

This is a diagnostic comparison only; it does not accept a Cargo release or
establish R1 qualification.  `--cleanup` retires only work roots recorded by
an interrupted invocation and leaves its output evidence intact.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import stat
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from release import ci_cargo

WORK_NAMES = ("ami-rust-cargo-work", "ami-rust-sdk-work")
BOOTSTRAP_NAME = "ami-rust-python-bootstrap"
OWNER_NAME = ".cargo-context-probe-owner.json"
OUTPUT_LIMIT = 32 * 1024**2
WORK_LIMIT = 12 * 1024**3
RECORD_LIMIT = 64 * 1024
APPENDIX_RESERVE = 7 * 1024**2 + RECORD_LIMIT
TEXT_LIMIT = 16 * 1024
SCHEMA = "ami-rust-cargo-context-probe-v1"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def tree_bytes(root: Path) -> int:
    total = 0
    for path in root.rglob("*"):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("managed output contains a symlink")
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
        elif not stat.S_ISDIR(info.st_mode):
            raise ValueError("managed output contains a non-regular entry")
    return total


def write_json(path: Path, value: dict) -> None:
    data = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode()
    if len(data) > RECORD_LIMIT:
        raise ValueError("probe record exceeds its bounded size")
    partial = path.with_name(path.name + ".partial")
    with partial.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(partial, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def sync_file_and_parent(path: Path) -> None:
    with path.open("rb") as stream:
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _canonical_existing(path: Path, label: str) -> Path:
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError(label + " must be an absolute canonical path")
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError(label + " path contains a symlink")
    return path


def _canonical_new(path: Path, label: str) -> Path:
    if (not path.is_absolute() or path.resolve(strict=False) != path
            or not path.parent.is_dir() or path.exists() or path.is_symlink()):
        raise ValueError(label + " must be a fresh absolute canonical path")
    _canonical_existing(path.parent, label + " parent")
    return path


def validate_paths(args) -> tuple[Path, Path, Path]:
    temporary = _canonical_existing(args.temporary, "--temporary")
    if not temporary.is_dir():
        raise ValueError("--temporary must be an existing directory")
    output = _canonical_new(args.output, "--output")
    if output.parent != temporary or output.name in (*WORK_NAMES, BOOTSTRAP_NAME, OWNER_NAME):
        raise ValueError("--output must be a fresh sibling of the managed work roots")
    bootstrap = temporary / BOOTSTRAP_NAME
    if args.python_bootstrap_root != bootstrap:
        raise ValueError("--python-bootstrap-root must be the selected fixed sibling bootstrap")
    for name in WORK_NAMES:
        root = temporary / name
        if root.exists() or root.is_symlink():
            raise ValueError("managed work root must be fresh: " + name)
    if (temporary / OWNER_NAME).exists() or (temporary / OWNER_NAME).is_symlink():
        raise ValueError("temporary parent already has a probe ownership record")
    return temporary, output, bootstrap


def validate_inputs(args, temporary: Path, output: Path, bootstrap: Path):
    _canonical_existing(bootstrap, "Python bootstrap")
    if not bootstrap.is_dir():
        raise ValueError("Python bootstrap must be a directory")
    result = []
    for path, label in ((args.inputs, "inputs"), (args.resources, "resources")):
        if path.is_symlink():
            raise ValueError(label + " must not be a symlink")
        resolved = path.resolve(strict=True)
        if not resolved.is_file() or resolved.is_relative_to(temporary):
            raise ValueError(label + " must be a regular file outside managed temporary storage")
        result.append(resolved)
    return tuple(result)


def _command(argv: list[str], env: dict[str, str]) -> dict:
    result = subprocess.run(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=30, check=False)
    def text(data):
        return data[:TEXT_LIMIT].decode("utf-8", "replace")
    return {"argv": argv, "returncode": result.returncode,
            "stdout": text(result.stdout), "stdout_bytes": len(result.stdout),
            "stdout_truncated": len(result.stdout) > TEXT_LIMIT,
            "stderr": text(result.stderr), "stderr_bytes": len(result.stderr),
            "stderr_truncated": len(result.stderr) > TEXT_LIMIT}


def capture_host_toolchain(output: Path) -> dict:
    home = output / ".host-probe-home"
    home.mkdir()
    env = {"HOME": str(home), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
           "TMPDIR": str(home), "LC_ALL": "C", "TZ": "UTC"}
    commands = []

    def run(argv):
        row = _command(argv, env)
        commands.append(row)
        if row["returncode"] != 0:
            raise RuntimeError("host tool identity command failed: " + " ".join(argv))
        return row["stdout"].strip()

    system = platform.system()
    if system == "Darwin":
        clang = run(["/usr/bin/xcrun", "--find", "clang"])
        linker = run(["/usr/bin/xcrun", "--find", "ld"])
        sdk = run(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"])
        sdk_version = run(["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-version"])
        run([clang, "--version"])
        run([linker, "-v"])
        run(["/usr/bin/xcodebuild", "-version"])
        identity = {"clang_path": clang, "linker_path": linker,
                    "sdk_path": sdk, "sdk_version": sdk_version}
    elif system == "Linux":
        clang = shutil.which("cc", path=env["PATH"])
        linker = shutil.which("ld", path=env["PATH"])
        if not clang or not linker:
            raise RuntimeError("host cc or ld was not found in the sanitized PATH")
        run([clang, "--version"])
        run([clang, "-print-prog-name=ld"])
        run([linker, "--version"])
        identity = {"cc_path": clang, "linker_path": linker}
    else:
        raise RuntimeError("unsupported host for toolchain identity")
    return {"schema": "ami-rust-cargo-context-host-tools-v1",
            "host": platform.platform(), "system": system,
            "machine": platform.machine(), "identity": identity,
            "commands": commands,
            "environment_policy": "fixed HOME, PATH, TMPDIR, LC_ALL and TZ only"}


def _diagnostic_files(work: Path) -> list[tuple[str, Path]]:
    rows = []
    for directory in ("logs", "records"):
        root = work / directory
        if not root.exists():
            continue
        if root.is_symlink() or not root.is_dir():
            raise ValueError("producer diagnostics root is not a real directory")
        for path in sorted(root.rglob("*")):
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("producer diagnostics contain a non-regular file")
            rows.append((path.relative_to(work).as_posix(), path))
    return rows


def _add_canonical(tar: tarfile.TarFile, name: str, path: Path, mode: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = path.stat().st_size
    info.mode, info.uid, info.gid, info.mtime = mode, 0, 0, 0
    info.uname = info.gname = ""
    with path.open("rb") as stream:
        tar.addfile(info, stream)


def _verify_archive(path: Path, expected: list[tuple[str, Path, int, str, int]]) -> None:
    with tarfile.open(path, "r:xz") as archive:
        members = archive.getmembers()
        if len(members) != len(expected):
            raise ValueError("compressed snapshot member count changed")
        for member, (name, _, size, digest, mode) in zip(members, expected):
            if (member.name != name or not member.isfile() or member.size != size
                    or member.mode != mode or member.uid != 0 or member.gid != 0
                    or member.mtime != 0):
                raise ValueError("compressed snapshot metadata changed")
            actual = hashlib.sha256()
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("compressed snapshot member is unreadable")
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                actual.update(block)
            if actual.hexdigest() != digest:
                raise ValueError("compressed snapshot contents changed")


def _write_archive(path: Path, rows: list[tuple[str, Path]]) -> dict:
    if path.exists() or path.is_symlink():
        raise ValueError("snapshot destination is not fresh")
    partial = path.with_name(path.name + ".partial")
    if partial.exists() or partial.is_symlink():
        raise ValueError("snapshot partial destination is not fresh")
    expected = [(name, source, source.stat().st_size, sha256(source),
                 stat.S_IMODE(source.stat().st_mode)) for name, source in rows]
    try:
        with tarfile.open(partial, mode="w:xz", format=tarfile.USTAR_FORMAT, preset=6) as archive:
            for name, source, _, _, mode in expected:
                _add_canonical(archive, name, source, mode)
        with partial.open("rb") as stream:
            os.fsync(stream.fileno())
        _verify_archive(partial, expected)
        os.replace(partial, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except BaseException:
        if partial.exists() and not partial.is_symlink():
            partial.unlink()
        raise
    return {"path": path.name, "bytes": path.stat().st_size,
            "sha256": sha256(path),
            "members": [{"path": name, "bytes": size, "sha256": digest, "mode": mode}
                        for name, _, size, digest, mode in expected]}


def _producer_report(phase: Path, returned) -> dict:
    record = ci_cargo.validate_output_metadata(phase)
    if not isinstance(returned, dict) or returned != record:
        raise ValueError("returned producer report differs from its preserved raw report")
    return record


def _producer_build_rss_limit(report: dict) -> int:
    budgets = report.get("budgets")
    rss_limit = budgets.get("rss_bytes") if isinstance(budgets, dict) else None
    if type(rss_limit) is not int or rss_limit <= 0:
        raise ValueError("producer report lacks a valid selected build RSS limit")
    return rss_limit


def _artifact(work: Path, report: dict) -> Path:
    artifact = report.get("custom_cargo_artifact")
    expected = work / "build-work/target/release/cargo"
    if (not isinstance(artifact, dict) or artifact.get("relative_path") != "build-work/target/release/cargo"
            or expected.is_symlink() or not expected.is_file()):
        raise ValueError("producer report does not identify the expected regular Cargo binary")
    info = expected.stat()
    if artifact.get("bytes") != info.st_size or artifact.get("sha256") != sha256(expected):
        raise ValueError("raw Cargo binary differs from its producer report hash or size")
    result_path = work / "records/build/result.json"
    result = json.loads(result_path.read_text())
    built = result.get("artifact")
    if (not isinstance(built, dict) or built.get("bytes") != info.st_size
            or built.get("sha256") != artifact["sha256"]):
        raise ValueError("Cargo binary differs from the source build result hash or size")
    return expected


def _archive_equal(first: Path, second: Path) -> bool:
    with tarfile.open(first, "r:xz") as left, tarfile.open(second, "r:xz") as right:
        a, b = left.extractfile("cargo"), right.extractfile("cargo")
        if a is None or b is None:
            raise ValueError("Cargo snapshot is missing its binary member")
        while True:
            x, y = a.read(1024 * 1024), b.read(1024 * 1024)
            if x != y:
                return False
            if not x:
                return True


def _owner_record(temporary: Path, output: Path) -> dict:
    return {"schema": SCHEMA, "temporary": str(temporary), "output": str(output),
            "work_names": list(WORK_NAMES), "pid": os.getpid()}


def cleanup(args) -> int:
    temporary = _canonical_existing(args.temporary, "--temporary")
    output = args.output
    if (not output.is_absolute() or output.resolve(strict=False) != output
            or output.parent != temporary or output.name in (*WORK_NAMES, BOOTSTRAP_NAME, OWNER_NAME)):
        raise ValueError("cleanup output must be the recorded canonical sibling path")
    marker = temporary / OWNER_NAME
    if marker.is_symlink() or not marker.is_file() or marker.stat().st_size > 4096:
        raise ValueError("no valid probe ownership record is available for cleanup")
    owner = json.loads(marker.read_text())
    if (owner.get("schema") != SCHEMA or owner.get("temporary") != str(temporary)
            or owner.get("output") != str(output) or owner.get("work_names") != list(WORK_NAMES)):
        raise ValueError("probe ownership record does not match these cleanup paths")
    cleanup_path = output / "cleanup.json"
    if output.exists() and (output.is_symlink() or not output.is_dir()):
        raise ValueError("cleanup output is not a real directory")
    if output.is_dir() and (cleanup_path.exists() or cleanup_path.is_symlink()):
        raise ValueError("cleanup record path is not fresh")
    pid = owner.get("pid")
    if type(pid) is int and pid != os.getpid():
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            pass
        else:
            raise ValueError("recorded probe process may still be active")
    removed = []
    for name in WORK_NAMES:
        root = temporary / name
        if root.is_symlink():
            raise ValueError("refusing to clean a linked work root")
        if root.exists():
            if not root.is_dir():
                raise ValueError("refusing to clean a non-directory work root")
            shutil.rmtree(root)
            removed.append(name)
    marker.unlink()
    if output.is_dir() and not output.is_symlink():
        write_json(cleanup_path, {"schema": SCHEMA, "status": "OWN_WORK_ROOTS_RETIRED",
                                  "removed_work_roots": removed,
                                  "preserved_output_bytes": tree_bytes(output)})
    return 0


def run_probe(args) -> int:
    temporary, output, bootstrap = validate_paths(args)
    output.mkdir()
    outcome = {"schema": SCHEMA, "status": "RUNNING_DIAGNOSTIC_ONLY",
               "claim": "Cargo byte comparison only; no release acceptance or R1 qualification.",
               "host": platform.platform(), "phases": [], "started_unix_seconds": int(time.time()),
               "output_limit_bytes": OUTPUT_LIMIT, "appendix_reserve_bytes": APPENDIX_RESERVE}
    write_json(output / "outcome.json", outcome)
    marker = temporary / OWNER_NAME
    try:
        with marker.open("xb") as stream:
            stream.write((json.dumps(_owner_record(temporary, output), sort_keys=True) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        inputs, resources = validate_inputs(args, temporary, output, bootstrap)
        try:
            toolchain = capture_host_toolchain(output)
        finally:
            home = output / ".host-probe-home"
            if home.is_symlink():
                home.unlink()
            elif home.is_dir():
                shutil.rmtree(home)
        write_json(output / "host-toolchain.json", toolchain)
        retained = tree_bytes(output)
        peak_bound = 0
        driver_rss_limit = None
        archives = []
        for index, name in enumerate(WORK_NAMES):
            work = temporary / name
            phase = output / ("cargo" if index == 0 else "sdk")
            producer_args = argparse.Namespace(work=work, output=phase,
                inputs=inputs, resources=resources,
                python_bootstrap_root=bootstrap)
            try:
                returned = ci_cargo.produce(producer_args)
                report = _producer_report(phase, returned)
                if report.get("status") != "PRODUCED_PREREQUISITE_ONLY_NOT_R1_QUALIFICATION":
                    raise ValueError("producer report is not a successful prerequisite result")
                phase_rss_limit = _producer_build_rss_limit(report)
                if driver_rss_limit is not None and phase_rss_limit != driver_rss_limit:
                    raise ValueError("producer build RSS limit changed between phases")
                driver_rss_limit = phase_rss_limit
                binary = _artifact(work, report)
                cargo_archive = _write_archive(phase / "cargo.tar.xz", [("cargo", binary)])
                diagnostics = _write_archive(phase / "diagnostics.tar.xz", _diagnostic_files(work))
                phase_peak = report.get("peaks", {}).get("work_plus_output_observed_bytes")
                if type(phase_peak) is not int or phase_peak < 0:
                    raise ValueError("producer report lacks a valid recorded work peak")
                phase_bound = retained + phase_peak + tree_bytes(phase)
                peak_bound = max(peak_bound, phase_bound)
                if peak_bound > WORK_LIMIT:
                    raise ValueError("combined recorded work-peak bound exceeds 12 GiB")
                if tree_bytes(output) + APPENDIX_RESERVE > OUTPUT_LIMIT:
                    for snapshot in (phase / "cargo.tar.xz", phase / "diagnostics.tar.xz"):
                        if snapshot.exists() and not snapshot.is_symlink():
                            snapshot.unlink()
                    raise ValueError("probe output plus reserved source/licence appendix exceeds 32 MiB")
                sync_file_and_parent(phase / "producer.json")
                outcome["phases"].append({"name": name, "status": "SNAPSHOT_VERIFIED",
                    "producer_report_sha256": sha256(phase / "producer.json"),
                    "cargo_snapshot": cargo_archive, "diagnostics_snapshot": diagnostics,
                    "producer_work_peak_bytes": phase_peak,
                    "combined_work_peak_bound_bytes": phase_bound})
                archives.append(phase / "cargo.tar.xz")
                shutil.rmtree(work)
                retained = tree_bytes(output)
                write_json(output / "outcome.json", outcome)
            except BaseException as error:
                # A failed producer still has useful bounded command/build evidence.
                if phase.is_dir() and (work / "logs").is_dir() and not (phase / "diagnostics.tar.xz").exists():
                    try:
                        _write_archive(phase / "diagnostics.tar.xz", _diagnostic_files(work))
                        if tree_bytes(output) + APPENDIX_RESERVE > OUTPUT_LIMIT:
                            (phase / "diagnostics.tar.xz").unlink()
                    except BaseException:
                        pass
                producer_path = phase / "producer.json"
                failed_bound = None
                if producer_path.is_file() and not producer_path.is_symlink():
                    try:
                        failed_report = json.loads(producer_path.read_text())
                        recorded = failed_report.get("peaks", {}).get("work_plus_output_observed_bytes")
                        if type(recorded) is int and recorded >= 0:
                            failed_bound = retained + recorded + (tree_bytes(phase) if phase.is_dir() else 0)
                            peak_bound = max(peak_bound, failed_bound)
                    except (OSError, ValueError, TypeError):
                        pass
                detail = {"name": name, "status": "FAILED_EVIDENCE_RETAINED",
                          "error": (type(error).__name__ + ": " + str(error))[:2048],
                          "work_root_retained": work.exists(),
                          "producer_report_sha256": sha256(producer_path) if producer_path.is_file() else None,
                          "combined_work_peak_bound_bytes": failed_bound}
                outcome["phases"].append(detail)
                outcome["status"] = "FAILED_EVIDENCE_RETAINED"
                outcome["combined_work_peak_bound_bytes"] = peak_bound
                outcome["cleanup_command"] = "--cleanup with the same --temporary and --output"
                write_json(output / "outcome.json", outcome)
                return 1

        outcome["combined_work_peak_bound_bytes"] = peak_bound
        outcome["driver_peak_rss_bytes"] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform == "darwin" else 1024)
        outcome["driver_peak_rss_limit_bytes"] = driver_rss_limit
        if outcome["driver_peak_rss_bytes"] > driver_rss_limit:
            raise ValueError("driver peak RSS exceeded selected build.rss_bytes resource policy")
        equal = _archive_equal(archives[0], archives[1])
        outcome["status"] = ("MATCH_NOT_RELEASE_ACCEPTED" if equal else
                             "MISMATCH_RETAINED_NOT_RELEASE_ACCEPTED")
        outcome["raw_cargo_bytes_equal"] = equal
        if not any((temporary / name).exists() for name in WORK_NAMES):
            marker.unlink()
        write_json(output / "outcome.json", outcome)
        return 0 if equal else 1
    except BaseException as error:
        outcome["status"] = "FAILED_EVIDENCE_RETAINED"
        outcome["error"] = (type(error).__name__ + ": " + str(error))[:2048]
        outcome["combined_work_peak_bound_bytes"] = peak_bound if "peak_bound" in locals() else 0
        outcome["cleanup_command"] = "--cleanup with the same --temporary and --output"
        write_json(output / "outcome.json", outcome)
        return 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--temporary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inputs", type=Path)
    parser.add_argument("--resources", type=Path)
    parser.add_argument("--python-bootstrap-root", type=Path)
    parser.add_argument("--cleanup", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.cleanup:
            return cleanup(args)
        if args.inputs is None or args.resources is None or args.python_bootstrap_root is None:
            raise ValueError("--inputs, --resources and --python-bootstrap-root are required")
        return run_probe(args)
    except BaseException as error:
        print(f"cargo_context_probe: {type(error).__name__}: {str(error)[:2048]}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
