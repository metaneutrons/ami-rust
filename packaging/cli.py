#!/usr/bin/env python3
"""Package-manager adapter over the unchanged, source-pinned SDK entry points."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import subprocess
import sys

PACKAGE = Path(__file__).resolve().parent


def read_json(path: Path) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key: " + key)
            result[key] = value
        return result
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024**2:
        raise ValueError("missing, linked or oversized metadata: " + str(path))
    value = json.loads(path.read_text(), object_pairs_hook=pairs,
                       parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    if not isinstance(value, dict):
        raise ValueError("metadata must be an object")
    return value


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else _digest(stream)


def _digest(stream) -> str:
    value = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        value.update(block)
    return value.hexdigest()


def verify_package(root: Path = PACKAGE) -> dict:
    pins = read_json(root / "pins.json")
    inventory = read_json(root / "inventory.json")
    if (pins.get("schema") != "ami-rust-package-inputs-v1"
            or inventory.get("schema") != "ami-rust-package-inventory-v1"
            or inventory.get("sdk_version") != pins.get("sdk_version")
            or inventory.get("package_version") != pins.get("package_version")):
        raise ValueError("package identity differs from its inventory")
    rows = {}
    for row in inventory.get("files", []):
        name = row.get("path")
        if (not isinstance(name, str) or "\\" in name or ":" in name
                or any(part in ("", ".", "..") for part in name.split("/"))
                or name in rows or name == "inventory.json"):
            raise ValueError("unsafe or repeated package inventory path")
        path = root / name
        if (path.resolve(strict=True) != path or not stat.S_ISREG(path.lstat().st_mode)
                or path.stat().st_size != row.get("bytes")
                or stat.S_IMODE(path.stat().st_mode) != row.get("mode")
                or digest(path) != row.get("sha256")):
            raise ValueError("package file failed inventory verification: " + name)
        rows[name] = row
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("linked package file or directory")
        if path.is_file() and path != root / "inventory.json":
            actual.add(path.relative_to(root).as_posix())
    if actual != set(rows):
        raise ValueError("package contains missing or unexpected files")
    required = {"cli.py", "worker.py", "pins.json", "proofs.json", "LICENSE-MIT", "LICENSE-APACHE"}
    if not required <= set(rows):
        raise ValueError("incomplete package control files")
    for row in pins["assets"]:
        expected = rows.get("assets/" + row["path"])
        if expected is None or any(expected[key] != row[key] for key in ("bytes", "sha256")):
            raise ValueError("package SDK asset differs from the qualified release")
    return pins


def host_key() -> str:
    pair = platform.system(), platform.machine().lower()
    if pair == ("Darwin", "arm64") and platform.mac_ver()[0].split(".")[0] == "26":
        return "macos-aarch64"
    if pair == ("Linux", "x86_64"):
        release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines()
                       if "=" in line and not line.startswith("#"))
        if release.get("ID", "").strip('"') == "ubuntu" and release.get("VERSION_ID", "").strip('"') == "24.04":
            return "linux-x86_64"
    raise ValueError("supported hosts: macOS 26 Apple Silicon or Ubuntu 24.04 x86-64")


def environment() -> dict:
    result = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(Path.home()),
              "LANG": "C", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
              "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"}
    if "TMPDIR" in os.environ:
        result["TMPDIR"] = os.environ["TMPDIR"]
    return result


def run(arguments, *, cwd=None, timeout=1200):
    subprocess.run([str(value) for value in arguments], cwd=cwd, env=environment(),
                   check=True, timeout=timeout)


def state_path(value: str, *, fresh=False) -> Path:
    path = Path(value)
    if not path.is_absolute() or Path(os.path.abspath(path)) != path or path.resolve() != path:
        raise ValueError("state requires a normalized absolute path without symlink components")
    if os.getuid() == 0:
        raise ValueError("prepare and project commands run as a regular user, never as root")
    if fresh:
        if path.exists() or path.is_symlink():
            raise ValueError("preparation requires a fresh state; failed states are retained for diagnosis")
        if not path.parent.is_dir():
            raise ValueError("state parent must already exist")
    else:
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("state must be a private directory owned by the current user")
    retained = path / "retained/libexec/ami-rust"
    if (path == PACKAGE or PACKAGE in path.parents
            or (path in PACKAGE.parents and (fresh or not PACKAGE.is_relative_to(retained)))):
        raise ValueError("state and installed package must be disjoint")
    return path


def prepare(value: str, pins: dict) -> None:
    host = host_key()
    state = state_path(value, fresh=True)
    state.mkdir(mode=0o700)
    # Keep a versioned adapter and the authenticated raw inputs for locked old
    # projects even when their package-manager installation is removed/upgraded.
    retained = state / "retained" / "libexec" / "ami-rust" / pins["package_version"]
    shutil.copytree(PACKAGE, retained)
    (state / "retained" / "bin").mkdir(parents=True)
    executable = state / "retained" / "bin" / "ami-rust"
    executable.write_text("#!/bin/sh\nexec " + _quote(sys.executable) + " -I -B "
                          + _quote(str(retained / "cli.py")) + ' "$@"\n')
    executable.chmod(0o700)
    source = state / "source"
    run(["/usr/bin/git", "-c", "init.defaultBranch=main", "init", "--template=", source])
    run(["/usr/bin/git", "-C", source, "remote", "add", "origin",
         "https://github.com/" + pins["repository"] + ".git"])
    run(["/usr/bin/git", "-C", source, "-c", "core.hooksPath=/dev/null", "fetch", "--depth=1",
         "origin", pins["source_commit"]])
    run(["/usr/bin/git", "-C", source, "-c", "core.hooksPath=/dev/null", "checkout", "--detach", pins["source_commit"]])
    head = subprocess.check_output(["/usr/bin/git", "-C", str(source), "rev-parse", "HEAD"],
                                   env=environment(), text=True).strip()
    if head != pins["source_commit"]:
        raise ValueError("downloaded source differs from the package's exact publisher pin")
    run([sys.executable, "-I", "-B", source / "release/ci_python.py", "--prefix", state / "ami-rust-python-bootstrap",
         "--inputs", source / "release/ci-python-inputs.json"])
    python = state / "ami-rust-python-bootstrap/runtime/python/bin/python3.12"
    run([python, "-I", "-B", retained / "worker.py", "--state", state], timeout=2400)
    ready = read_json(state / "ready.json")
    if ready.get("host") != host or ready.get("source_commit") != pins["source_commit"]:
        raise ValueError("prepared state differs from the selected host/publisher")
    # This interpreter belongs to the retained state, so package-manager Python
    # upgrades/cleanup do not invalidate a previously prepared SDK launcher.
    executable.write_text("#!/bin/sh\nexec " + _quote(str(python)) + " -I -B "
                          + _quote(str(retained / "cli.py")) + ' "$@"\n')
    print(json.dumps({"status": "PREPARED", "sdk_version": pins["sdk_version"],
                      "state": str(state), "retained_launcher": str(executable)}))


def _quote(value: str) -> str:
    import shlex
    return shlex.quote(value)


def ready_state(value: str, pins: dict) -> tuple[Path, Path]:
    state = state_path(value)
    ready = read_json(state / "ready.json")
    if (ready.get("schema") != "ami-rust-package-state-v1" or ready.get("status") != "READY"
            or ready.get("host") != host_key() or ready.get("source_commit") != pins["source_commit"]
            or ready.get("manifest_sha256") != pins["manifest_sha256"]
            or ready.get("sdk_version") != pins["sdk_version"]):
        raise ValueError("state is incomplete or belongs to another SDK; use its retained launcher")
    return state, state / "ami-rust-python-bootstrap/runtime/python/bin/python3.12"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="store_true")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("verify-package")
    prep = sub.add_parser("prepare", help="explicitly fetch and verify pinned prerequisites into a fresh private state")
    prep.add_argument("--state", required=True)
    for name in ("new", "build", "check-inputs"):
        command = sub.add_parser(name)
        command.add_argument("--state", required=True)
        if name in ("new", "build"):
            command.add_argument("--project", required=True)
        if name == "build":
            command.add_argument("--output-dir", required=True)
            command.add_argument("--package", default="hello-aros")
            command.add_argument("cargo_args", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if not sys.flags.isolated or not sys.dont_write_bytecode:
        raise ValueError("start the package launcher with Python -I -B")
    pins = verify_package()
    if args.version:
        print("ami-rust " + pins["sdk_version"] + " (packaging " + str(pins["packaging_revision"]) + ")")
    elif args.command == "verify-package":
        print(json.dumps({"status": "VERIFIED_PACKAGE", "sdk_version": pins["sdk_version"],
                          "package_version": pins["package_version"]}))
    elif args.command == "prepare":
        prepare(args.state, pins)
    elif args.command:
        state, python = ready_state(args.state, pins)
        prefix = state / ("sdk-" + pins["sdk_version"])
        bundle = state / "ami-rust-public-authenticated-bundle"
        if args.command == "new":
            project = Path(args.project)
            if not project.is_absolute():
                raise ValueError("project requires an explicit absolute path")
            run([python, "-I", "-B", bundle / "new_project.py", "--sdk", prefix / "sdk",
                 "--output", project, "--receipt-sha256", (state / "receipt.sha256").read_text().strip()])
            run([python, "-I", "-B", bundle / "install_publisher.py", "lock", "--prefix", prefix,
                 "--selection", state / "selection.json", "--project", project,
                 "--output", project / "ami-rust.lock.json"])
        elif args.command == "build":
            project = Path(args.project)
            forwarded = args.cargo_args[1:] if args.cargo_args[:1] == ["--"] else args.cargo_args
            run([python, "-I", "-B", prefix / "sdk/host/cli.py", "build", "--sdk-lock",
                 project / "ami-rust.lock.json", "--output-dir", args.output_dir, "--", "build",
                 "--manifest-path", project / "Cargo.toml", "--package", args.package,
                 "--release", "--locked", "--offline", *forwarded])
        else:
            run([python, "-I", "-B", state / "source/release/ci_verify.py", "check-inputs",
                 "--bundle", bundle, "--work", state / "preparation", "--output", state / "preparation-output",
                 "--python-bootstrap-root", state / "ami-rust-python-bootstrap", "--source-commit", pins["source_commit"],
                 "--workflow-commit", pins["source_commit"], "--selection", state / "selection.json"])
    else:
        parser.print_help()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as error:
        sys.stderr.write("ami-rust: child command failed\n")
        raise SystemExit(error.returncode if error.returncode >= 0 else min(255, 128 - error.returncode))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        sys.stderr.write("ami-rust: " + str(error) + "\n")
        raise SystemExit(2)
