#!/usr/bin/env python3
"""Exercise the installed package, retained state, and one local upgrade path."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import signal
import stat
import subprocess
import sys
import tarfile
import time
import uuid
from urllib.parse import quote


PACKAGE_DIR = Path(__file__).resolve().parent
QUALIFY = PACKAGE_DIR / "qualify.py"
README = PACKAGE_DIR / "README.md"
SDK_VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
HOMEBREW_VERSION_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:_(?:[1-9][0-9]*))?\Z"
)
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
EXECUTION_CUTOFF_SECONDS = 85 * 60
CAMPAIGN_LIMIT_SECONDS = 90 * 60
MAX_REPORT_BYTES = 4 * 1024 * 1024
MAX_PACKAGE_BYTES = 512 * 1024 * 1024
MAX_COMMAND_LOG_BYTES = 16 * 1024 * 1024


class LifecycleError(RuntimeError):
    """The package lifecycle could not satisfy its bounded contract."""


class CommandFailure(LifecycleError):
    """A required external command failed; its bounded logs remain in evidence."""


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""


@dataclass(frozen=True)
class PackageSet:
    directory: Path
    pins: dict
    archive: Path
    deb: Path
    formula: Path
    files: dict[str, dict[str, object]]


@dataclass(frozen=True)
class BrewInstallation:
    versions: tuple[str, ...]
    linked_keg: str | None = None


def _json_object(raw: bytes, label: str) -> dict:
    def unique_pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise LifecycleError(f"{label} has a duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value):
        raise LifecycleError(f"{label} has an invalid JSON constant: {value}")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs,
                           parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise LifecycleError(f"{label} is not bounded UTF-8 JSON") from error
    if type(value) is not dict:
        raise LifecycleError(f"{label} must be a JSON object")
    return value


def _read_regular(path: Path, label: str, maximum: int = MAX_REPORT_BYTES) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise LifecycleError(f"cannot open {label}: {error}") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise LifecycleError(f"{label} must be a bounded regular file")
        chunks = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum or len(data) != info.st_size:
            raise LifecycleError(f"{label} changed or exceeds its byte bound")
        return data
    finally:
        os.close(descriptor)


def sha256_file(path: Path) -> str:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise LifecycleError(f"cannot hash {path.name}: {error}") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PACKAGE_BYTES:
            raise LifecycleError(f"{path.name} is not a bounded regular file")
        digest = hashlib.sha256()
        size = 0
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            size += len(block)
            if size > MAX_PACKAGE_BYTES:
                raise LifecycleError(f"{path.name} exceeds the package size bound")
            digest.update(block)
        if size != info.st_size:
            raise LifecycleError(f"{path.name} changed while it was hashed")
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def file_inventory(directory: Path) -> dict[str, dict[str, object]]:
    """Return exact file metadata, refusing links, directories and special files."""
    if directory.is_symlink() or not directory.is_dir():
        raise LifecycleError("packages directory must be a real directory")
    result = {}
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise LifecycleError(f"packages/{path.name} must be a regular, non-linked file")
        if info.st_size > MAX_PACKAGE_BYTES:
            raise LifecycleError(f"packages/{path.name} exceeds the package size bound")
        result[path.name] = {"bytes": info.st_size, "sha256": sha256_file(path)}
    return result


def _valid_digest_row(row, label: str) -> tuple[str, int, str]:
    if type(row) is not dict or set(row) - {"path", "bytes", "sha256"}:
        raise LifecycleError(f"{label} row is malformed")
    name = row.get("path")
    size = row.get("bytes")
    digest = row.get("sha256")
    if (type(name) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}", name)
            or type(size) is not int or not 1 <= size <= MAX_PACKAGE_BYTES
            or type(digest) is not str or SHA256_RE.fullmatch(digest) is None):
        raise LifecycleError(f"{label} row has invalid file metadata")
    return name, size, digest


def load_package_set(directory: str | os.PathLike[str], pins_path: Path | None = None) -> PackageSet:
    """Validate the exact build/metadata output before any package-manager action."""
    package_dir = Path(directory)
    if not package_dir.is_absolute() or Path(os.path.abspath(package_dir)) != package_dir:
        raise LifecycleError("packages directory must be an absolute normalized path")
    if package_dir.resolve() != package_dir or package_dir.is_symlink() or not package_dir.is_dir():
        raise LifecycleError("packages directory must be a real directory without symlink components")
    pins_file = pins_path or PACKAGE_DIR / "pins.json"
    pins = _json_object(_read_regular(pins_file, "packaging/pins.json"), "packaging/pins.json")
    sdk = pins.get("sdk_version")
    revision = pins.get("packaging_revision")
    package_version = pins.get("package_version")
    tag = pins.get("packaging_tag")
    if (pins.get("schema") != "ami-rust-package-inputs-v1" or type(sdk) is not str
            or SDK_VERSION_RE.fullmatch(sdk) is None or type(revision) is not int or revision < 1
            or package_version != f"{sdk}-{revision}"
            or tag != f"v{sdk}+packaging.{revision}"):
        raise LifecycleError("packaging pins do not identify a stable ami-rust package")

    archive_name = f"ami-rust-{sdk}-packaging.{revision}.tar.xz"
    deb_name = f"ami-rust_{package_version}_amd64.deb"
    build_path = package_dir / "packaging-report.json"
    metadata_path = package_dir / "metadata-report.json"
    build = _json_object(_read_regular(build_path, "packaging-report.json"), "packaging-report.json")
    metadata = _json_object(_read_regular(metadata_path, "metadata-report.json"), "metadata-report.json")
    if (build.get("schema") != "ami-rust-packaging-report-v1"
            or build.get("sdk_version") != sdk or build.get("package_version") != package_version
            or build.get("packaging_tag") != tag):
        raise LifecycleError("packaging report identity differs from pins")
    build_outputs = build.get("outputs")
    if type(build_outputs) is not dict or set(build_outputs) != {archive_name, deb_name}:
        raise LifecycleError("packaging report must identify only the pinned archive and Debian package")

    expected: dict[str, dict[str, object]] = {}
    for name, row in build_outputs.items():
        if type(name) is not str or name not in {archive_name, deb_name} or type(row) is not dict:
            raise LifecycleError("packaging report contains an unexpected output")
        size, digest = row.get("bytes"), row.get("sha256")
        if (type(size) is not int or not 1 <= size <= MAX_PACKAGE_BYTES
                or type(digest) is not str or SHA256_RE.fullmatch(digest) is None):
            raise LifecycleError(f"packaging report metadata is invalid for {name}")
        actual = package_dir / name
        if not actual.is_file() or actual.is_symlink() or actual.stat().st_size != size or sha256_file(actual) != digest:
            raise LifecycleError(f"package output differs from packaging report: {name}")
        expected[name] = {"bytes": size, "sha256": digest}

    identity = metadata.get("sdk")
    if (metadata.get("schema") != "ami-rust-packaging-metadata-report-v1"
            or type(identity) is not dict or identity.get("version") != sdk
            or identity.get("package_version") != package_version
            or identity.get("packaging_revision") != revision or identity.get("packaging_tag") != tag):
        raise LifecycleError("metadata report identity differs from pins")
    generated = metadata.get("generated_files")
    payloads = metadata.get("payloads")
    formula_name = "ami-rust.rb"
    sbom_archive = archive_name + ".spdx.json"
    sbom_deb = deb_name + ".spdx.json"
    if (type(payloads) is not dict or set(payloads) != {archive_name, deb_name}
            or type(generated) is not dict or set(generated) != {formula_name, sbom_archive, sbom_deb}):
        raise LifecycleError("metadata report must identify the formula and both package SPDX files")
    for name, row in generated.items():
        file_name, size, digest = _valid_digest_row(row, "generated metadata")
        if file_name != name:
            raise LifecycleError("metadata report path differs from its key")
        path = package_dir / name
        if not path.is_file() or path.is_symlink() or path.stat().st_size != size or sha256_file(path) != digest:
            raise LifecycleError(f"generated metadata differs from report: {name}")
        expected[name] = {"bytes": size, "sha256": digest}
    for payload_name, sbom_name in ((archive_name, sbom_archive), (deb_name, sbom_deb)):
        payload = payloads.get(payload_name)
        if (type(payload) is not dict or payload.get("bytes") != expected[payload_name]["bytes"]
                or payload.get("sha256") != expected[payload_name]["sha256"]
                or type(payload.get("spdx")) is not dict
                or payload["spdx"].get("path") != sbom_name
                or payload["spdx"].get("sha256") != expected[sbom_name]["sha256"]
                or payload["spdx"].get("bytes") != expected[sbom_name]["bytes"]):
            raise LifecycleError(f"metadata payload report is inconsistent for {payload_name}")
    expected.update({"packaging-report.json": {"bytes": build_path.stat().st_size,
                                                "sha256": hashlib.sha256(_read_regular(build_path, "packaging-report.json")).hexdigest()},
                     "metadata-report.json": {"bytes": metadata_path.stat().st_size,
                                              "sha256": hashlib.sha256(_read_regular(metadata_path, "metadata-report.json")).hexdigest()}})
    actual_inventory = file_inventory(package_dir)
    if set(actual_inventory) != set(expected):
        missing, extra = sorted(set(expected) - set(actual_inventory)), sorted(set(actual_inventory) - set(expected))
        raise LifecycleError(f"packages directory differs from exact output inventory (missing={missing}, extra={extra})")
    if actual_inventory != expected:
        raise LifecycleError("packages directory bytes differ from the exact reported output inventory")

    formula_raw = _read_regular(package_dir / formula_name, formula_name, 1024 * 1024)
    try:
        formula = formula_raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise LifecycleError("Homebrew formula is not UTF-8") from error
    expected_url = (f"https://github.com/{pins['repository']}/releases/download/"
                    f"{quote(tag, safe='')}/{quote(archive_name, safe='')}")
    if (formula.count(f'url "{expected_url}"') != 1
            or formula.count(f'version "{sdk}"') != 1
            or formula.count(f'sha256 "{expected[archive_name]["sha256"]}"') != 1
            or formula.count(f"  revision {revision}\n") != 1):
        raise LifecycleError("Homebrew formula does not match the final public package asset and revision")

    deb = package_dir / deb_name
    members = parse_ar(_read_regular(deb, deb_name, MAX_PACKAGE_BYTES))
    if set(members) != {"debian-binary", "control.tar.gz", "data.tar.xz"} or members["debian-binary"] != b"2.0\n":
        raise LifecycleError("Debian package does not have the expected exact ar members")
    control = deb_control(members["control.tar.gz"])
    if (control.count(b"Package: ami-rust\n") != 1
            or control.count(f"Version: {package_version}\n".encode()) != 1
            or control.count(b"Architecture: amd64\n") != 1):
        raise LifecycleError("Debian package control identity differs from pins")

    return PackageSet(package_dir, pins, package_dir / archive_name, deb,
                      package_dir / formula_name, actual_inventory)


def parse_ar(data: bytes) -> dict[str, bytes]:
    if not data.startswith(b"!<arch>\n"):
        raise LifecycleError("Debian package has an invalid ar signature")
    position, result = 8, {}
    while position < len(data):
        if position + 60 > len(data):
            raise LifecycleError("Debian package has a truncated ar header")
        header = data[position:position + 60]
        if header[58:60] != b"`\n":
            raise LifecycleError("Debian package has an invalid ar header")
        try:
            name = header[:16].decode("ascii").strip().rstrip("/")
            size = int(header[48:58].decode("ascii").strip())
        except (UnicodeDecodeError, ValueError) as error:
            raise LifecycleError("Debian package has malformed ar metadata") from error
        position += 60
        end = position + size
        if not name or name in result or size < 0 or end > len(data):
            raise LifecycleError("Debian package has a repeated member or invalid length")
        result[name] = data[position:end]
        position = end + size % 2
    if position != len(data):
        raise LifecycleError("Debian package has trailing ar bytes")
    return result


def deb_control(control_tar: bytes) -> bytes:
    try:
        with tarfile.open(fileobj=io.BytesIO(control_tar), mode="r:gz") as archive:
            members = archive.getmembers()
            if (len(members) != 1 or members[0].name != "control" or not members[0].isfile()
                    or members[0].size > 1024 * 1024):
                raise LifecycleError("Debian control archive must contain one bounded regular control file")
            stream = archive.extractfile(members[0])
            if stream is None:
                raise LifecycleError("cannot read Debian control archive")
            with stream:
                raw = stream.read(1024 * 1024 + 1)
    except (OSError, EOFError, tarfile.TarError) as error:
        raise LifecycleError("Debian control archive is invalid") from error
    if len(raw) > 1024 * 1024:
        raise LifecycleError("Debian control file exceeds its byte bound")
    return raw


def _ar_member(name: str, data: bytes) -> bytes:
    encoded = (name + "/").encode("ascii")
    if len(encoded) > 16 or not re.fullmatch(r"[A-Za-z0-9._+-]+", name):
        raise LifecycleError("Debian fixture has an invalid ar member name")
    header = (encoded.ljust(16, b" ") + b"0".ljust(12, b" ") + b"0".ljust(6, b" ")
              + b"0".ljust(6, b" ") + b"100644".ljust(8, b" ")
              + str(len(data)).encode("ascii").ljust(10, b" ") + b"`\n")
    return header + data + (b"\n" if len(data) % 2 else b"")


def _control_tar(control: bytes) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
            info = tarfile.TarInfo("control")
            info.type = tarfile.REGTYPE
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            info.size = len(control)
            archive.addfile(info, io.BytesIO(control))
    return output.getvalue()


def make_debian_upgrade_fixture(package: PackageSet, destination: Path) -> dict[str, object]:
    """Create an unsigned local lower-revision .deb without touching final assets."""
    pins = package.pins
    source_members = parse_ar(_read_regular(package.deb, package.deb.name, MAX_PACKAGE_BYTES))
    current_control = deb_control(source_members["control.tar.gz"])
    current_version = pins["package_version"]
    fixture_revision = pins["packaging_revision"] - 1
    fixture_version = f"{pins['sdk_version']}-{fixture_revision}"
    old_line = f"Version: {current_version}\n".encode("ascii")
    if current_control.count(old_line) != 1:
        raise LifecycleError("final Debian control version is not the single pinned version")
    fixture_control = current_control.replace(old_line, f"Version: {fixture_version}\n".encode("ascii"), 1)
    fixture_control_tar = _control_tar(fixture_control)
    data_member = source_members["data.tar.xz"]
    fixture_raw = (b"!<arch>\n" + _ar_member("debian-binary", source_members["debian-binary"])
                   + _ar_member("control.tar.gz", fixture_control_tar)
                   + _ar_member("data.tar.xz", data_member))
    fixture_members = parse_ar(fixture_raw)
    if fixture_members["data.tar.xz"] != data_member:
        raise LifecycleError("Debian upgrade fixture changed the final package data payload")
    verified_control = deb_control(fixture_members["control.tar.gz"])
    if (verified_control.count(f"Version: {fixture_version}\n".encode("ascii")) != 1
            or verified_control.replace(f"Version: {fixture_version}\n".encode("ascii"), old_line, 1) != current_control):
        raise LifecycleError("Debian upgrade fixture differs from final control only by its revision")
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    fixture = destination / f"ami-rust_{fixture_version}_amd64.deb"
    with fixture.open("xb") as stream:
        stream.write(fixture_raw)
    return {"kind": "local-unsigned-upgrade-fixture", "version": fixture_version,
            "revision": fixture_revision, "path": str(fixture),
            "sha256": hashlib.sha256(fixture_raw).hexdigest(),
            "data_sha256": hashlib.sha256(data_member).hexdigest(),
            "final_data_sha256": hashlib.sha256(data_member).hexdigest(),
            "source_final_deb_sha256": sha256_file(package.deb)}


def make_homebrew_upgrade_fixture(package: PackageSet, destination: Path) -> dict[str, object]:
    """Return revision-zero formula bytes derived from, but not written over, final formula."""
    raw = _read_regular(package.formula, package.formula.name, 1024 * 1024)
    revision = package.pins["packaging_revision"]
    revision_line = f"  revision {revision}\n".encode("ascii")
    if raw.count(revision_line) != 1:
        raise LifecycleError("final Homebrew formula does not contain one pinned revision")
    fixture_raw = raw.replace(revision_line, b"", 1)
    if b"  revision " in fixture_raw:
        raise LifecycleError("revision-zero Homebrew fixture still declares a formula revision")
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    fixture = destination / "ami-rust.rb"
    with fixture.open("xb") as stream:
        stream.write(fixture_raw)
    if _read_regular(package.formula, package.formula.name, 1024 * 1024) != raw:
        raise LifecycleError("final Homebrew formula changed while making its upgrade fixture")
    return {"kind": "local-unsigned-upgrade-fixture", "version": package.pins["sdk_version"],
            "revision": 0, "path": str(fixture),
            "sha256": hashlib.sha256(fixture_raw).hexdigest(),
            "final_formula_sha256": hashlib.sha256(raw).hexdigest(),
            "identity": "same SDK version and public URL; Homebrew formula revision 0"}


def detect_host(system: str | None = None, machine: str | None = None,
                version: str | None = None, os_release: dict[str, str] | None = None) -> str:
    system = platform.system() if system is None else system
    machine = platform.machine() if machine is None else machine
    if system == "Darwin" and machine.lower() == "arm64":
        version = platform.mac_ver()[0] if version is None else version
        if version.split(".", 1)[0] == "26":
            return "macos-26-arm64"
    if system == "Linux" and machine.lower() in {"x86_64", "amd64"}:
        if os_release is None:
            fields = {}
            try:
                for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
                    if "=" in line and not line.startswith("#"):
                        key, value = line.split("=", 1)
                        fields[key] = value.strip().strip('"')
            except OSError as error:
                raise LifecycleError("cannot identify Linux distribution") from error
            os_release = fields
        if os_release.get("ID") == "ubuntu" and os_release.get("VERSION_ID") == "24.04":
            return "ubuntu-24.04-x86_64"
    raise LifecycleError("supported hosts: macOS 26 Apple Silicon or Ubuntu 24.04 x86-64")


def _safe_environment() -> dict[str, str]:
    env = {}
    for key, value in os.environ.items():
        upper = key.upper()
        if any(marker in upper for marker in ("TOKEN", "SECRET", "PRIVATE_KEY", "PASSWORD", "CREDENTIAL", "AUTH")):
            continue
        if key in {"PATH", "HOME", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "SHELL", "USER", "LOGNAME"} or upper.startswith("HOMEBREW_"):
            env[key] = value
    env.setdefault("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
    env.setdefault("LANG", "C")
    env.setdefault("LC_ALL", "C")
    return env


class SubprocessRunner:
    """Log commands to the retained evidence root and kill their process group on budget expiry."""
    def __init__(self, evidence_dir: Path, monotonic=time.monotonic):
        self.evidence_dir = evidence_dir
        self.monotonic = monotonic
        self.command_dir = evidence_dir / "commands"
        self.command_dir.mkdir(mode=0o700)
        self.sequence = 0

    def run(self, label: str, argv, *, timeout: float, cwd: Path | None = None) -> CommandResult:
        if not re.fullmatch(r"[a-z0-9-]+", label):
            raise LifecycleError("command label is not a plain identifier")
        if timeout <= 0:
            raise TimeoutError("whole-host lifecycle budget is exhausted")
        self.sequence += 1
        stem = f"{self.sequence:03d}-{label}"
        stdout_path, stderr_path = self.command_dir / (stem + ".stdout.log"), self.command_dir / (stem + ".stderr.log")
        argv_text = [str(value) for value in argv]
        started = self.monotonic()
        exit_code = None
        error_text = None
        try:
            with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
                process = subprocess.Popen(argv_text, cwd=cwd, env=_safe_environment(), stdin=subprocess.DEVNULL,
                                           stdout=stdout, stderr=stderr, start_new_session=True)
                deadline = started + timeout
                while process.poll() is None:
                    remaining = deadline - self.monotonic()
                    if remaining <= 0:
                        error_text = "whole-host lifecycle command timed out"
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                        exit_code = 124
                        break
                    if (stdout_path.stat().st_size > MAX_COMMAND_LOG_BYTES
                            or stderr_path.stat().st_size > MAX_COMMAND_LOG_BYTES):
                        error_text = "command output exceeded the 16 MiB evidence bound"
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait()
                        exit_code = 125
                        break
                    time.sleep(min(0.2, remaining))
                if exit_code is None:
                    exit_code = process.returncode
        except OSError as error:
            error_text = str(error)
            exit_code = 126
        stdout_raw = stdout_path.read_bytes() if stdout_path.exists() else b""
        stderr_raw = stderr_path.read_bytes() if stderr_path.exists() else b""
        row = {"label": label, "argv": argv_text, "exit_code": exit_code,
               "elapsed_seconds": max(0.0, self.monotonic() - started),
               "stdout_bytes": len(stdout_raw), "stderr_bytes": len(stderr_raw)}
        if error_text:
            row["error"] = error_text
        with (self.command_dir / (stem + ".json")).open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(row, indent=2) + "\n")
        return CommandResult(int(exit_code), stdout_raw, stderr_raw)


class Lifecycle:
    def __init__(self, packages_dir: str | os.PathLike[str], root: str | os.PathLike[str], *,
                 runner=None, host_profile: str | None = None, budget_seconds: int = CAMPAIGN_LIMIT_SECONDS,
                 monotonic=time.monotonic, tap_suffix: str | None = None):
        self.packages_dir = Path(packages_dir)
        self.root = Path(root)
        self.runner = runner
        self.host_profile = host_profile
        self.budget_seconds = budget_seconds
        self.monotonic = monotonic
        self.tap_suffix = tap_suffix or uuid.uuid4().hex[:12]
        if type(budget_seconds) is not int or not 1 <= budget_seconds <= CAMPAIGN_LIMIT_SECONDS:
            raise ValueError("campaign budget must be from 1 through 5400 seconds")
        self.execution_cutoff_seconds = min(EXECUTION_CUTOFF_SECONDS, budget_seconds)
        self.evidence_dir = self.root / "evidence"
        self.package: PackageSet | None = None
        self.started: float | None = None
        self.profile: str | None = None
        self.owned_package = False
        self.owned_brew_versions: set[str] = set()
        self.owned_tap = False
        self.tap_name: str | None = None
        self.tap_repository: Path | None = None
        self.brew_prefix: Path | None = None
        self.retained_launcher: Path | None = None
        self.phase_rows: list[dict[str, object]] = []
        self.final_inventory: dict[str, dict[str, object]] | None = None

    def _remaining(self) -> float:
        if self.started is None:
            raise LifecycleError("lifecycle clock has not started")
        return self.budget_seconds - (self.monotonic() - self.started)

    def _write_json(self, path: Path, value: dict) -> None:
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, path)

    def _record_phase(self, name: str, status: str, **details) -> None:
        row = {"phase": name, "status": status, **details}
        self.phase_rows.append(row)
        self._write_json(self.evidence_dir / (name + ".json"), row)

    def _phase(self, name: str, action):
        self._record_phase(name, "RUNNING", started_elapsed_seconds=self.budget_seconds - self._remaining())
        try:
            result = action()
        except Exception as error:
            self._record_phase(name, "FAIL", error=f"{type(error).__name__}: {error}",
                               elapsed_seconds=self.budget_seconds - self._remaining())
            raise
        self._record_phase(name, "PASS", elapsed_seconds=self.budget_seconds - self._remaining())
        return result

    def _command(self, label: str, argv, *, allowed: tuple[int, ...] = (0,), cwd: Path | None = None) -> CommandResult:
        remaining = self._remaining()
        elapsed = self.budget_seconds - remaining
        cleanup = (label.startswith("cleanup-") or label.endswith("-cleanup") or label == "brew-untap-owned")
        if not cleanup:
            remaining = min(remaining, self.execution_cutoff_seconds - elapsed)
        if remaining <= 0:
            boundary = "whole-host cleanup deadline" if cleanup else "85-minute execution cutoff"
            raise TimeoutError(f"package lifecycle {boundary} reached")
        if self.runner is None:
            raise LifecycleError("command runner is unavailable")
        result = self.runner.run(label, [str(value) for value in argv], timeout=remaining, cwd=cwd)
        if not isinstance(result, CommandResult):
            result = CommandResult(int(result.returncode), result.stdout or b"", result.stderr or b"")
        if result.returncode not in allowed:
            message = result.stderr.decode("utf-8", "replace").strip()
            raise CommandFailure(f"{label} failed with exit {result.returncode}" + (f": {message[:500]}" if message else ""))
        if len(result.stdout) + len(result.stderr) > 2 * MAX_COMMAND_LOG_BYTES:
            raise LifecycleError(f"{label} returned oversized evidence")
        return result

    def _prepare_root(self) -> None:
        if not self.root.is_absolute() or Path(os.path.abspath(self.root)) != self.root:
            raise LifecycleError("lifecycle root must be an absolute normalized path")
        if self.root.resolve() != self.root or self.root.exists() or self.root.is_symlink():
            raise LifecycleError("lifecycle root must be fresh and have no symlink components")
        if not self.root.parent.is_dir() or self.root.parent.resolve() != self.root.parent:
            raise LifecycleError("lifecycle root parent must be an existing real directory")
        if self.packages_dir == self.root or self.packages_dir in self.root.parents or self.root in self.packages_dir.parents:
            raise LifecycleError("lifecycle root and immutable package output must be disjoint")
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)
        self.evidence_dir.mkdir(mode=0o700)
        self.started = self.monotonic()
        if self.runner is None:
            self.runner = SubprocessRunner(self.evidence_dir, monotonic=self.monotonic)

    def _preflight(self) -> None:
        if os.getuid() == 0:
            raise LifecycleError("package lifecycle must run as a normal user, never as root")
        self.profile = self.host_profile or detect_host()
        if self.profile not in {"ubuntu-24.04-x86_64", "macos-26-arm64"}:
            raise LifecycleError("supported hosts: macOS 26 Apple Silicon or Ubuntu 24.04 x86-64")
        self.package = load_package_set(self.packages_dir)
        expected_host = {"ubuntu-24.04-x86_64": ("apt", "linux-x86_64"),
                         "macos-26-arm64": ("homebrew", "macos-aarch64")}[self.profile]
        hosts = self.package.pins.get("hosts")
        if type(hosts) is not dict or hosts.get(expected_host[0]) != expected_host[1]:
            raise LifecycleError("package pins do not qualify this package manager on the current host")
        self.final_inventory = dict(self.package.files)
        if self.profile == "ubuntu-24.04-x86_64":
            result = self._command("initial-installed-query", ["dpkg-query", "-W", "-f=${db:Status-Status}\t${Version}\n", "ami-rust"], allowed=(0, 1))
            if result.returncode == 0:
                raise LifecycleError("ami-rust already has a dpkg record; refusing to adopt or remove it")
            if Path("/usr/bin/ami-rust").exists() or Path("/usr/bin/ami-rust").is_symlink():
                raise LifecycleError("/usr/bin/ami-rust exists outside this campaign; refusing collision")
        else:
            result = self._command("brew-prefix", ["brew", "--prefix"])
            prefix_text = result.stdout.decode("utf-8", "strict").strip()
            prefix = Path(prefix_text)
            if not prefix.is_absolute() or not prefix_text or not prefix.is_dir() or prefix.is_symlink():
                raise LifecycleError("brew --prefix did not return an absolute prefix")
            self.brew_prefix = prefix
            installed = self._brew_installed("initial-installed-query")
            if installed is not None:
                raise LifecycleError("ami-rust is already installed by Homebrew; refusing to adopt or remove it")
            executable = prefix / "bin/ami-rust"
            if executable.exists() or executable.is_symlink():
                raise LifecycleError(f"{executable} exists outside this campaign; refusing collision")
            self.tap_name = f"local/ami-rust-lifecycle-{self.tap_suffix}"
            taps = self._command("brew-tap-list", ["brew", "tap"])
            if self.tap_name in taps.stdout.decode("utf-8", "replace").splitlines():
                raise LifecycleError("generated temporary tap name already exists; refusing collision")

    def _brew_installed(self, label: str, *, inspect_linked_keg: bool = False) -> BrewInstallation | None:
        result = self._command(label, ["brew", "list", "--versions", "ami-rust"], allowed=(0, 1))
        if result.returncode == 1:
            if result.stdout.strip():
                raise LifecycleError("Homebrew reports no ami-rust package but returned version data")
            return None
        lines = result.stdout.decode("utf-8", "strict").splitlines()
        if len(lines) != 1:
            raise LifecycleError("Homebrew reports ami-rust installed without a version")
        fields = lines[0].split()
        if len(fields) < 2 or fields[0] != "ami-rust":
            raise LifecycleError("Homebrew installed-package query returned an unexpected identity")
        versions = tuple(fields[1:])
        if (len(set(versions)) != len(versions)
                or any(HOMEBREW_VERSION_RE.fullmatch(version) is None for version in versions)):
            raise LifecycleError("Homebrew installed-package query returned duplicate or unsafe versions")
        if not inspect_linked_keg:
            return BrewInstallation(versions)

        formula = self._brew_formula_reference()
        info_result = self._command(label + "-info", ["brew", "info", "--json=v2", formula])
        info = _json_object(info_result.stdout, label + " Homebrew formula info")
        formulae = info.get("formulae")
        if type(formulae) is not list or len(formulae) != 1 or type(formulae[0]) is not dict:
            raise LifecycleError("Homebrew formula info is absent or ambiguous")
        record = formulae[0]
        if record.get("name") != "ami-rust" or record.get("full_name") != formula:
            raise LifecycleError("Homebrew formula info resolved to an unrelated identity")
        installed = record.get("installed")
        if type(installed) is not list or not installed:
            raise LifecycleError("Homebrew formula info omitted its installed keg inventory")
        info_versions = []
        for row in installed:
            if type(row) is not dict or type(row.get("version")) is not str:
                raise LifecycleError("Homebrew formula info has a malformed installed keg")
            info_versions.append(row["version"])
        if (len(set(info_versions)) != len(info_versions)
                or set(info_versions) != set(versions)):
            raise LifecycleError("Homebrew formula info disagrees with the installed keg inventory")
        linked_keg = record.get("linked_keg")
        if (linked_keg is not None and type(linked_keg) is not str
                or linked_keg is not None and linked_keg not in versions):
            raise LifecycleError("Homebrew linked keg does not match its installed inventory")
        return BrewInstallation(versions, linked_keg)

    def _apt_installed(self, label: str) -> tuple[str, str] | None:
        result = self._command(label, ["dpkg-query", "-W", "-f=${db:Status-Status}\t${Version}\n", "ami-rust"], allowed=(0, 1))
        if result.returncode == 1:
            return None
        fields = result.stdout.decode("utf-8", "strict").strip().split("\t")
        if len(fields) != 2:
            raise LifecycleError("dpkg installed-package query returned an unexpected identity")
        return fields[0], fields[1]

    def _assert_installed_version(self, label: str, expected: str) -> None:
        if self.profile == "ubuntu-24.04-x86_64":
            installed = self._apt_installed(label)
            if installed != ("installed", expected):
                raise LifecycleError(f"dpkg package state is {installed!r}; expected installed {expected}")
        else:
            installed = self._brew_installed(label, inspect_linked_keg=True)
            brew_version = expected.replace("-", "_")
            if installed is None or installed.linked_keg != brew_version:
                active = None if installed is None else installed.linked_keg
                raise LifecycleError(f"Homebrew active keg is {active!r}; expected {brew_version}")
            if not installed.versions or not set(installed.versions) <= self.owned_brew_versions:
                raise LifecycleError(
                    f"Homebrew keg inventory is {sorted(installed.versions)!r}; "
                    f"expected a nonempty subset of campaign-owned {sorted(self.owned_brew_versions)!r}"
                )

    def _apt_install(self, label: str, package_file: Path, version: str) -> None:
        self.owned_package = True
        self._command(label, ["sudo", "dpkg", "-i", package_file])
        self._assert_installed_version(label + "-verify", version)

    def _apt_remove(self, label: str) -> None:
        if self._apt_installed(label + "-query") is not None:
            self._command(label, ["sudo", "dpkg", "-r", "ami-rust"])
        if self._apt_installed(label + "-verify-removed") is not None:
            raise LifecycleError("dpkg still reports ami-rust after package removal")
        self.owned_package = False

    def _brew_setup_tap(self) -> None:
        assert self.tap_name is not None and self.package is not None
        self.owned_tap = True
        self._command("brew-tap-new", ["brew", "tap-new", "--no-git", self.tap_name])
        result = self._command("brew-tap-repository", ["brew", "--repository", self.tap_name])
        repo_text = result.stdout.decode("utf-8", "strict").strip()
        repo = Path(repo_text)
        if not repo.is_absolute() or not repo_text or repo.is_symlink() or not repo.is_dir():
            raise LifecycleError("Homebrew temporary tap repository is not a real absolute directory")
        formula_dir = repo / "Formula"
        if not formula_dir.exists():
            formula_dir.mkdir(mode=0o755)
        if formula_dir.is_symlink() or not formula_dir.is_dir():
            raise LifecycleError("Homebrew temporary tap Formula directory is unsafe")
        final_formula = formula_dir / "ami-rust.rb"
        if final_formula.exists() or final_formula.is_symlink():
            raise LifecycleError("Homebrew temporary tap unexpectedly already contains ami-rust.rb")
        final_formula.write_bytes(_read_regular(self.package.formula, self.package.formula.name, 1024 * 1024))
        if _read_regular(final_formula, "temporary final formula", 1024 * 1024) != _read_regular(self.package.formula, self.package.formula.name, 1024 * 1024):
            raise LifecycleError("temporary tap formula differs from the exact generated final formula")
        self.tap_repository = repo

    def _brew_formula_reference(self) -> str:
        if self.tap_name is None:
            raise LifecycleError("Homebrew temporary tap is not initialized")
        return self.tap_name + "/ami-rust"

    def _brew_install(self, label: str, version: str) -> None:
        self.owned_package = True
        self.owned_brew_versions.add(version.replace("-", "_"))
        self._command(label, ["brew", "install", self._brew_formula_reference()])
        self._assert_installed_version(label + "-verify", version)

    def _brew_remove(self, label: str) -> None:
        installed = self._brew_installed(label + "-query", inspect_linked_keg=True)
        if installed is not None:
            if not self.owned_brew_versions or not set(installed.versions) <= self.owned_brew_versions:
                raise LifecycleError("Homebrew contains versions not owned by this campaign; refusing removal")
            self._command(label, ["brew", "uninstall", "--force", self._brew_formula_reference()])
        if self._brew_installed(label + "-verify-removed") is not None:
            raise LifecycleError("Homebrew still reports ami-rust after package removal")
        self.owned_package = False
        self.owned_brew_versions.clear()

    def _qualify(self, mode: str, label: str, executable: Path, phase: str | None = None) -> None:
        if self.package is None:
            raise LifecycleError("package outputs were not validated")
        argv = [sys.executable, "-I", "-B", QUALIFY, mode, "--executable", executable,
                "--root", self.root / "qualification"]
        if mode == "exercise":
            argv.extend(["--readme", README])
        else:
            if phase is None:
                raise LifecycleError("qualification replay requires a phase name")
            argv.extend(["--phase", phase])
        self._command(label, argv)
        if mode == "exercise":
            launcher = (self.root / "qualification" / "user-home"
                        / f"ami-rust-{self.package.pins['sdk_version']}-state"
                        / "retained/bin/ami-rust")
            try:
                info = launcher.lstat()
            except OSError as error:
                raise LifecycleError("qualification did not preserve its retained launcher") from error
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or not info.st_mode & stat.S_IXUSR or stat.S_IMODE(info.st_mode) & 0o077
                    or launcher.resolve() != launcher):
                raise LifecycleError("retained launcher is not a regular user-owned executable")
            persistent = _json_object(_read_regular(self.root / "qualification/persistent.json",
                                                    "qualification persistent state"),
                                      "qualification persistent state")
            expected_state = (self.root / "qualification/user-home"
                              / f"ami-rust-{self.package.pins['sdk_version']}-state")
            if Path(persistent.get("state", "")) != expected_state:
                raise LifecycleError("qualification persistent state points outside its fresh campaign root")
            state_info = expected_state.lstat()
            if (not stat.S_ISDIR(state_info.st_mode) or state_info.st_uid != os.getuid()
                    or stat.S_IMODE(state_info.st_mode) & 0o077 or expected_state.resolve() != expected_state):
                raise LifecycleError("prepared SDK state must remain a private user-owned directory")
            ready = _json_object(_read_regular(expected_state / "ready.json", "prepared state receipt"),
                                 "prepared state receipt")
            expected_host = self.package.pins["hosts"]["apt" if self.profile == "ubuntu-24.04-x86_64" else "homebrew"]
            if (ready.get("status") != "READY" or ready.get("sdk_version") != self.package.pins["sdk_version"]
                    or ready.get("source_commit") != self.package.pins["source_commit"]
                    or ready.get("host") != expected_host):
                raise LifecycleError("prepared state receipt differs from the pinned host or SDK")
            self.retained_launcher = launcher

    def _verify_unchanged(self) -> None:
        if self.package is None or self.final_inventory is None:
            raise LifecycleError("package inventory was not captured")
        if file_inventory(self.package.directory) != self.final_inventory:
            raise LifecycleError("lifecycle changed the immutable final package output directory")

    def _setup_and_initial_install(self) -> None:
        assert self.package is not None
        if self.profile == "ubuntu-24.04-x86_64":
            self._apt_install("install-final-initial", self.package.deb, self.package.pins["package_version"])
        else:
            self._brew_setup_tap()
            self._brew_install("install-final-initial", self.package.pins["sdk_version"]
                               + "-" + str(self.package.pins["packaging_revision"]))

    def _remove_current(self) -> None:
        if self.profile == "ubuntu-24.04-x86_64":
            self._apt_remove("uninstall-current")
        else:
            self._brew_remove("uninstall-current")

    def _reinstall_final(self) -> None:
        assert self.package is not None
        if self.profile == "ubuntu-24.04-x86_64":
            self._apt_install("reinstall-final", self.package.deb, self.package.pins["package_version"])
        else:
            self._brew_install("reinstall-final", self.package.pins["sdk_version"]
                               + "-" + str(self.package.pins["packaging_revision"]))

    def _upgrade_test(self) -> dict[str, object]:
        assert self.package is not None
        fixture_dir = self.root / "upgrade-fixture"
        self._remove_current()
        if self.profile == "ubuntu-24.04-x86_64":
            fixture = make_debian_upgrade_fixture(self.package, fixture_dir)
            self._write_json(self.evidence_dir / "upgrade-fixture.json", fixture)
            self._apt_install("install-lower-revision-fixture", Path(str(fixture["path"])), str(fixture["version"]))
            self._apt_install("upgrade-to-final", self.package.deb, self.package.pins["package_version"])
        else:
            fixture = make_homebrew_upgrade_fixture(self.package, fixture_dir)
            self._write_json(self.evidence_dir / "upgrade-fixture.json", fixture)
            assert self.tap_repository is not None
            formula_path = self.tap_repository / "Formula/ami-rust.rb"
            fixture_raw = _read_regular(Path(str(fixture["path"])), "revision-zero Homebrew fixture", 1024 * 1024)
            formula_path.write_bytes(fixture_raw)
            self._brew_install("install-lower-revision-fixture", self.package.pins["sdk_version"])
            final_raw = _read_regular(self.package.formula, self.package.formula.name, 1024 * 1024)
            formula_path.write_bytes(final_raw)
            if _read_regular(formula_path, "restored final tap formula", 1024 * 1024) != final_raw:
                raise LifecycleError("temporary tap was not restored to the exact final formula")
            self.owned_package = True
            self.owned_brew_versions.add(
                self.package.pins["sdk_version"] + "_" + str(self.package.pins["packaging_revision"])
            )
            self._command("upgrade-to-final", ["brew", "upgrade", self._brew_formula_reference()])
            self._assert_installed_version("upgrade-to-final-verify", self.package.pins["sdk_version"]
                                           + "-" + str(self.package.pins["packaging_revision"]))
        self._verify_unchanged()
        return fixture

    def _cleanup(self) -> None:
        if self.owned_package:
            if self.profile == "ubuntu-24.04-x86_64":
                self._apt_remove("cleanup-owned-package")
            elif self.profile == "macos-26-arm64":
                self._brew_remove("cleanup-owned-package")
        if self.owned_tap:
            if self.owned_package:
                raise LifecycleError("cannot remove the campaign tap while its package remains installed")
            assert self.tap_name is not None
            taps = self._command("brew-tap-list-cleanup", ["brew", "tap"])
            if self.tap_name in taps.stdout.decode("utf-8", "replace").splitlines():
                self._command("brew-untap-owned", ["brew", "untap", self.tap_name])
            self.owned_tap = False

    def run(self) -> dict[str, object]:
        self._prepare_root()
        try:
            self._phase("preflight", self._preflight)
            self._phase("install-final-initial", self._setup_and_initial_install)
            assert self.package is not None
            executable = (Path("/usr/bin/ami-rust") if self.profile == "ubuntu-24.04-x86_64"
                          else self.brew_prefix / "bin/ami-rust")
            self._phase("exercise-installed-final", lambda: self._qualify("exercise", "qualify-exercise", executable))
            self._phase("uninstall-final", self._remove_current)
            if self.retained_launcher is None:
                raise LifecycleError("exercise phase did not retain the prepared SDK launcher")
            self._phase("replay-retained-after-uninstall",
                        lambda: self._qualify("replay", "qualify-replay-retained", self.retained_launcher, "retained-after-uninstall"))
            self._phase("reinstall-final", self._reinstall_final)
            self._phase("replay-current-after-reinstall",
                        lambda: self._qualify("replay", "qualify-replay-current", executable, "current-after-reinstall"))
            fixture = self._phase("lower-revision-upgrade", self._upgrade_test)
            self._phase("replay-current-after-upgrade",
                        lambda: self._qualify("replay", "qualify-replay-upgraded", executable, "current-after-upgrade"))
            self._phase("verify-final-output-unchanged", self._verify_unchanged)
            self._phase("cleanup-owned-installation", self._cleanup)
            result = {"schema": "ami-rust-package-manager-lifecycle-v1", "status": "PASS",
                      "host_profile": self.profile, "sdk_version": self.package.pins["sdk_version"],
                      "package_version": self.package.pins["package_version"],
                      "package_output_inventory": self.final_inventory,
                      "upgrade_fixture": fixture, "phases": self.phase_rows,
                      "elapsed_seconds": self.budget_seconds - self._remaining(),
                      "execution_cutoff_seconds": self.execution_cutoff_seconds,
                      "whole_host_budget_seconds": self.budget_seconds,
                      "states_and_evidence_retained": True,
                      "installed_package_removed": True,
                      "temporary_tap_removed": not self.owned_tap}
            self._write_json(self.evidence_dir / "result.json", result)
            return result
        except Exception as error:
            self._record_overall_failure(error)
            try:
                self._phase("cleanup-owned-installation", self._cleanup)
            except Exception as cleanup_error:
                self._record_overall_failure(error, cleanup_error=cleanup_error)
                raise LifecycleError(f"{error}; cleanup also failed: {cleanup_error}") from error
            self._record_overall_failure(error)
            raise

    def _record_overall_failure(self, error: Exception, cleanup_error: Exception | None = None) -> None:
        report = {"schema": "ami-rust-package-manager-lifecycle-v1", "status": "FAIL",
                  "host_profile": self.profile, "error": f"{type(error).__name__}: {error}",
                  "cleanup_error": (f"{type(cleanup_error).__name__}: {cleanup_error}" if cleanup_error else None),
                  "phases": self.phase_rows, "whole_host_budget_seconds": self.budget_seconds,
                  "execution_cutoff_seconds": self.execution_cutoff_seconds,
                  "elapsed_seconds": (self.budget_seconds - self._remaining() if self.started is not None else None),
                  "states_and_evidence_retained": True,
                  "owned_package_may_remain": self.owned_package, "owned_tap_may_remain": self.owned_tap}
        self._write_json(self.evidence_dir / "result.json", report)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packages-dir", required=True, type=Path,
                        help="exact output directory from packaging/build.py plus packaging/metadata.py")
    parser.add_argument("--root", required=True, type=Path,
                        help="fresh private directory for retained user state and lifecycle evidence")
    parser.add_argument("--budget-seconds", type=int, default=CAMPAIGN_LIMIT_SECONDS)
    args = parser.parse_args(argv)
    if not 1 <= args.budget_seconds <= CAMPAIGN_LIMIT_SECONDS:
        parser.error("--budget-seconds must be from 1 through 5400")
    try:
        result = Lifecycle(args.packages_dir, args.root, budget_seconds=args.budget_seconds).run()
    except (LifecycleError, OSError, TimeoutError, subprocess.SubprocessError) as error:
        print(f"ami-rust lifecycle: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"status": result["status"], "host_profile": result["host_profile"],
                      "evidence": str(args.root / "evidence/result.json")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
