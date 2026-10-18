#!/usr/bin/env python3
"""Execute the documented public channel instructions on a fresh client."""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import shutil
import subprocess
import sys
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def load_pins() -> dict:
    value = json.loads((HERE / "pins.json").read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError("packaging pins are not a JSON object")
    version, revision = value.get("sdk_version"), value.get("packaging_revision")
    if (type(version) is not str or VERSION_RE.fullmatch(version) is None
            or type(revision) is not int or revision < 1
            or value.get("package_version") != f"{version}-{revision}"):
        raise ValueError("packaging pins do not identify a stable package version")
    return value


def _candidate_deb(packages_dir: Path, pins: dict) -> Path:
    """Bind the downgrade fixture source to the exact sealed candidate DEB."""
    filename = f"ami-rust_{pins['package_version']}_amd64.deb"
    deb = packages_dir / filename
    info = deb.lstat()
    if not deb.is_file() or deb.is_symlink() or info.st_nlink != 1:
        raise ValueError("authenticated candidate Debian package is not a regular file")
    candidate_path = packages_dir / "candidate.json"
    candidate_info = candidate_path.lstat()
    if not candidate_path.is_file() or candidate_path.is_symlink() or candidate_info.st_size > 2 * 1024**2:
        raise ValueError("authenticated candidate inventory is not a bounded regular file")
    candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    if type(candidate) is not dict or candidate.get("schema") != "ami-rust-package-candidate-v1":
        raise ValueError("authenticated candidate inventory has an unsupported schema")
    original = candidate.get("original_sdk")
    if type(original) is not dict or original.get("version") != pins["sdk_version"]:
        raise ValueError("authenticated candidate SDK identity differs from packaging pins")
    rows = [row for row in candidate.get("assets", [])
            if type(row) is dict and row.get("path") == filename]
    digest = hashlib.sha256(deb.read_bytes()).hexdigest()
    if (len(rows) != 1 or set(rows[0]) != {"path", "bytes", "sha256"}
            or type(rows[0]["bytes"]) is not int or rows[0]["bytes"] != info.st_size
            or type(rows[0]["sha256"]) is not str or SHA256_RE.fullmatch(rows[0]["sha256"]) is None
            or rows[0]["sha256"] != digest):
        raise ValueError("candidate Debian package differs from its authenticated inventory")
    return deb


def make_apt_upgrade_fixture(packages_dir: Path, root: Path, pins: dict) -> dict:
    """Make the lower revision with the producer lifecycle's verified helper."""
    deb = _candidate_deb(packages_dir, pins)
    spec = importlib.util.spec_from_file_location("ami_rust_public_lifecycle", HERE / "lifecycle.py")
    if spec is None or spec.loader is None:
        raise ValueError("cannot load the package lifecycle fixture builder")
    lifecycle = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = lifecycle
    spec.loader.exec_module(lifecycle)
    fixture = lifecycle.make_debian_upgrade_fixture(
        SimpleNamespace(pins=pins, deb=deb), root / "upgrade-fixture"
    )
    return fixture


def _require_apt_version(run, expected: str, label: str) -> None:
    output = run(label, ["dpkg-query", "-W", "-f=${db:Status-Status}\\t${Version}\\n", "ami-rust"])
    try:
        lines = output.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("dpkg package query returned non-UTF-8 output") from error
    if len(lines) != 1:
        raise ValueError("dpkg package query returned an unexpected number of records")
    fields = lines[0].split("\t")
    if len(fields) != 2 or fields[0] != "installed" or fields[1] != expected:
        raise ValueError(f"dpkg package state is {lines[0]!r}; expected installed {expected}")


def upgrade_public_apt(packages_dir: Path, root: Path, pins: dict, executable: Path, run) -> dict:
    """Upgrade the installed lower revision through the signed public APT source."""
    fixture = make_apt_upgrade_fixture(packages_dir, root, pins)
    lower_version = fixture.get("version")
    if type(lower_version) is not str or fixture.get("revision") != pins["packaging_revision"] - 1:
        raise ValueError("lower-revision Debian fixture does not match pinned packaging revision")
    run("install-lower-revision-fixture", ["sudo", "apt-get", "install", "--yes",
        "--allow-downgrades", fixture["path"]])
    _require_apt_version(run, lower_version, "verify-lower-revision")
    run("upgrade-from-public-archive", ["sudo", "apt-get", "install", "--yes",
        "--only-upgrade", f"ami-rust={pins['package_version']}"])
    _require_apt_version(run, pins["package_version"], "verify-public-archive-upgrade")
    run("verify-upgraded-public-package", [executable, "verify-package"])
    run("replay-public-apt-upgrade", [sys.executable, "-I", "-B", HERE / "qualify.py", "replay",
        "--root", root / "consumer", "--executable", executable, "--phase", "public-apt-upgrade"])
    return fixture


def instruction_blocks(channel: str, document: Path) -> list[str]:
    snippets = re.findall(r"```sh\n(.*?)\n```", document.read_text(encoding="utf-8"), re.S)
    expected = 2 if channel == "apt" else 1
    if len(snippets) != expected:
        raise ValueError(f"{channel} instructions must have exactly {expected} executable blocks")
    return snippets


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--channel", choices=("apt", "homebrew"), required=True)
    parser.add_argument("--packages-dir", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    root.mkdir(mode=0o700)
    started = time.time()
    rows = []
    measurement_spec = importlib.util.spec_from_file_location("ami_rust_public_measure", HERE / "measure.py")
    measurement = importlib.util.module_from_spec(measurement_spec)
    measurement_spec.loader.exec_module(measurement)
    sampler = measurement.DiskSampler(root).start()
    measurements = {"schema": measurement.SCHEMA, "status": "INCOMPLETE"}
    consumer_environment = {key: value for key, value in os.environ.items()
        if key in {"HOME", "PATH", "TMPDIR", "LANG", "LC_ALL", "USER", "LOGNAME"}
        or (key.startswith("HOMEBREW_") and not any(word in key for word in ("TOKEN", "SECRET", "KEY")))}

    def run(label, argv, *, environment=None):
        remaining = started + 5100 - time.time()
        if remaining <= 0:
            raise TimeoutError("public client execution cutoff reached")
        stdout_path = root / (label + ".stdout.log")
        stderr_path = root / (label + ".stderr.log")
        with stdout_path.open("x") as out, stderr_path.open("x") as err:
            command_started = time.time()
            process = subprocess.Popen([str(value) for value in argv], stdout=out, stderr=err,
                                       env=consumer_environment if environment is None else environment,
                                       start_new_session=True)
            try:
                code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                code = 124
        rows.append({"label": label, "exit_code": code,
                     "elapsed_seconds": time.time() - command_started})
        if code:
            raise RuntimeError(label + " failed; see retained command logs")
        return stdout_path.read_bytes()

    (root / "clock.json").write_text(json.dumps({"start_unix": started,
        "execution_cutoff_seconds": 5100, "campaign_limit_seconds": 5400,
        "scope": "Fresh public channel client; original SDK/native baseline unchanged"}, indent=2) + "\n")
    status = "FAIL_PUBLIC_CHANNEL_CONSUMER"
    failure = None
    try:
        if shutil.which("ami-rust") is not None:
            raise ValueError("fresh public consumer refuses an existing ami-rust launcher")
        if args.channel == "apt":
            run("signed-public-archive", [sys.executable, "-I", "-B", HERE / "verify_apt.py",
                "--packages-dir", args.packages_dir, "--root", root / "archive-verification"])
        else:
            spec = importlib.util.spec_from_file_location("ami_rust_public_stage", HERE / "stage.py")
            stage = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(stage)
            record = stage.api("repos/metaneutrons/homebrew-tap/contents/Formula/ami-rust.rb?ref=main")
            actual = base64.b64decode(record["content"], validate=False)
            if actual != (args.packages_dir / "ami-rust.rb").read_bytes():
                raise ValueError("public Homebrew formula differs from attested release bytes")
            (root / "published-formula.rb").write_bytes(actual)
        document = HERE / ("INSTALL-APT.md" if args.channel == "apt" else "INSTALL-HOMEBREW.md")
        snippets = instruction_blocks(args.channel, document)
        script = root / "verbatim-installation.sh"
        script.write_text(snippets[0] + "\n")
        run("verbatim-public-install", ["/bin/bash", "-e", "-o", "pipefail", script])
        executable = Path(shutil.which("ami-rust") or "")
        if not executable.is_absolute():
            raise ValueError("channel installation did not provide ami-rust")
        run("consumer", [sys.executable, "-I", "-B", HERE / "qualify.py", "exercise",
            "--root", root / "consumer", "--executable", executable, "--readme", HERE / "README.md"])
        pins = load_pins()
        if args.channel == "apt":
            fixture = upgrade_public_apt(args.packages_dir, root, pins, executable, run)
            (root / "apt-upgrade-fixture.json").write_text(json.dumps(fixture, indent=2) + "\n")
        removal = (["sudo", "apt-get", "remove", "--yes", "ami-rust"] if args.channel == "apt"
                   else ["brew", "uninstall", "ami-rust"])
        run("remove-public-package", removal)
        retained = root / "consumer/user-home/ami-rust-0.1.0-state/retained/bin/ami-rust"
        persistent = json.loads((root / "consumer/persistent.json").read_text())
        retained_blocks = re.findall(r"```sh\n(.*?)\n```", (HERE / "README.md").read_text(), re.S)
        if len(retained_blocks) != 2:
            raise ValueError("package instructions must contain the initial and retained command blocks")
        retained_script = root / "verbatim-retained-commands.sh"
        retained_script.write_text(retained_blocks[1] + "\n")
        retained_environment = {**consumer_environment, "STATE": persistent["state"],
                                "PROJECT": persistent["project"], "HOME": str(root / "consumer/user-home")}
        run("verbatim-retained-commands", ["/bin/bash", "-e", "-o", "pipefail", retained_script],
            environment=retained_environment)
        native = root / "consumer/user-home/hello-aros-rebuild/artifacts/AMIRUST"
        if hashlib.sha256(native.read_bytes()).hexdigest() != persistent["hello_native_sha256"]:
            raise ValueError("documented retained-state recipe changed the native output")
        run("retained-project-after-removal", [sys.executable, "-I", "-B", HERE / "qualify.py", "replay",
            "--root", root / "consumer", "--executable", retained, "--phase", "public-removal"])
        persistent = json.loads((root / "consumer/persistent.json").read_text())
        state = Path(persistent["state"])
        measurements.update(measurement.capture(state, Path(persistent["project"]),
            root / "consumer/user-home/hello-aros-rebuild"))
        measurements["original_receipts"] = measurement.copy_original_receipts(
            state, root / "original-sdk-receipts")
        measurements["volume"] = sampler.stop()
        if measurements["volume"]["sampling_error"] or not measurements["volume"]["sample_count"]:
            raise ValueError("public client disk-space observations are incomplete")
        if args.channel == "apt":
            cleanup_script = root / "verbatim-apt-cleanup.sh"
            cleanup_script.write_text(snippets[1] + "\n")
            run("verbatim-public-apt-archive-cleanup",
                ["/bin/bash", "-e", "-o", "pipefail", cleanup_script])
        measurements["status"] = "PASS_RESOURCE_OBSERVATIONS"
        if time.time() - started > 5400:
            raise TimeoutError("public client campaign exceeded its closure window")
        status = "PASS_PUBLIC_CHANNEL_CONSUMER"
    except Exception as error:
        failure = str(error)
        raise
    finally:
        measurements.setdefault("volume", sampler.stop())
        (root / "resource-measurements.json").write_text(json.dumps(measurements, indent=2) + "\n")
        (root / "result.json").write_text(json.dumps({"status": status, "channel": args.channel,
            "commands": rows, "elapsed_seconds": time.time() - started, "error": failure,
            "budget_exception": False}, indent=2) + "\n")


if __name__ == "__main__":
    main()
