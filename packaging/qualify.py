#!/usr/bin/env python3
"""Execute delivered package commands and preserve bounded lifecycle evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, data):
    with Path(path).open("x") as stream:
        stream.write(json.dumps(data, indent=2) + "\n")


def project_inventory(root):
    return {path.relative_to(root).as_posix(): {"bytes": path.stat().st_size, "sha256": sha(path)}
            for path in sorted(root.rglob("*")) if path.is_file()}


class Campaign:
    def __init__(self, root, executable, phase):
        self.root = root.resolve()
        self.executable = executable.absolute()
        self.phase = phase
        if not re.fullmatch("[a-z0-9-]+", phase):
            raise ValueError("phase must be a plain identifier")
        self.output = self.root / ("evidence-" + phase)
        self.output.mkdir(mode=0o700)
        self.start = time.time()
        self.rows = []
        self.env = dict(os.environ)
        for name in ("GH_TOKEN", "GITHUB_TOKEN", "HOMEBREW_APP_PRIVATE_KEY", "ARCHIVE_DISPATCH_PRIVATE_KEY",
                     "CARGO_HOME", "RUSTUP_HOME", "RUSTC", "RUSTDOC", "CARGO_TARGET_DIR"):
            self.env.pop(name, None)
        self.home = self.root / "user-home"
        self.env.update({"HOME": str(self.home), "PATH": str(self.executable.parent) + ":/usr/bin:/bin:/usr/sbin:/sbin"})
        save(self.output / "clock.json", {"start_unix": self.start, "test_cutoff_seconds": 5100,
             "campaign_limit_seconds": 5400, "phase": phase, "clock_reset": False,
             "scope": "This named package lifecycle phase; no new SDK/Rust implementation or native runtime claim."})

    def run(self, label, argv):
        remaining = self.start + 5100 - time.time()
        if remaining <= 0:
            raise TimeoutError("package lifecycle execution cutoff reached")
        started = time.time()
        stdout = self.output / (label + ".stdout.log")
        stderr = self.output / (label + ".stderr.log")
        with stdout.open("x") as out, stderr.open("x") as err:
            process = subprocess.Popen([str(value) for value in argv], env=self.env,
                cwd=self.root, stdout=out, stderr=err, start_new_session=True)
            try:
                code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                code = 124
        row = {"label": label, "argv": [str(value) for value in argv], "exit_code": code,
               "elapsed_seconds": time.time() - started,
               "stdout_bytes": stdout.stat().st_size, "stderr_bytes": stderr.stat().st_size}
        self.rows.append(row)
        save(self.output / (label + ".json"), row)
        if code:
            raise RuntimeError(label + " failed with exit " + str(code) + "; see retained logs")
        if stdout.stat().st_size + stderr.stat().st_size > 16 * 1024**2:
            raise ValueError("lifecycle command exceeded the existing 16 MiB log profile")

    def finish(self, status, **fields):
        elapsed = time.time() - self.start
        if elapsed > 5400 and status.startswith("PASS"):
            raise TimeoutError("campaign closure exceeded its prospective 90-minute window")
        report = {"schema": "ami-rust-package-consumer-evidence-v1", "status": status,
                  "phase": self.phase, "commands": self.rows, "elapsed_seconds": elapsed,
                  "budget_exception": False, "sdk_version": "0.1.0", **fields}
        save(self.output / "result.json", report)
        print(json.dumps({"status": status, "phase": self.phase, "elapsed_seconds": elapsed}))


def exercise(root, executable, readme):
    campaign = Campaign(root, executable, "initial")
    try:
        campaign.home.mkdir(mode=0o700)
        rustup = campaign.home / ".rustup"
        rustup.mkdir()
        marker = rustup / "settings.toml"
        marker.write_text('version = "12"\ndefault_toolchain = "stable"\nprofile = "default"\n')
        marker_sha = sha(marker)
        snippet = re.findall(r"```sh\n(.*?)\n```", readme.read_text(), re.S)[0]
        script = campaign.output / "installed-instructions.sh"
        script.write_text(snippet + "\n")
        campaign.run("verbatim-instructions", ["/bin/bash", "-e", script])
        state = campaign.home / "ami-rust-0.1.0-state"
        project = campaign.home / "hello-aros"
        native = campaign.home / "hello-aros-build/artifacts/AMIRUST"
        ready = json.loads((state / "ready.json").read_text())
        if ready.get("status") != "READY":
            raise ValueError("state was not ready after delivered instructions")
        python = state / "ami-rust-python-bootstrap/runtime/python/bin/python3.12"
        prefix = state / "sdk-0.1.0"
        bundle = state / "ami-rust-public-authenticated-bundle"
        campaign.run("reference-lock", [python, "-I", "-B", bundle / "install_publisher.py", "lock",
            "--prefix", prefix, "--selection", state / "selection.json", "--project", prefix / "sdk",
            "--output", campaign.root / "reference.lock.json"])
        campaign.run("reference-build", [python, "-I", "-B", prefix / "sdk/host/cli.py", "build",
            "--sdk-lock", campaign.root / "reference.lock.json", "--output-dir", campaign.root / "reference-build",
            "--", "build", "--manifest-path", prefix / "sdk/Cargo.toml", "--package", "ami-rust-sha256sum",
            "--release", "--locked", "--offline"])
        reference = campaign.root / "reference-build/artifacts/AMIRUST"
        expected = "85a2171d918423eb56b1a65757b72597e8902dad72f3a924fe277d253b7db162"
        if reference.stat().st_size != 928208 or sha(reference) != expected:
            raise ValueError("rebuilt native reference differs from the accepted R1 executable")
        campaign.run("retained-inputs", [executable, "check-inputs", "--state", state])
        if sha(marker) != marker_sha:
            raise ValueError("global Rust settings changed")
        persistent = {"state": str(state), "project": str(project), "project_inventory": project_inventory(project),
                      "hello_native_sha256": sha(native), "reference_native_sha256": sha(reference),
                      "rustup_settings_sha256": marker_sha, "snippet_sha256": sha(script), "ready": ready}
        save(campaign.root / "persistent.json", persistent)
        campaign.finish("PASS_PACKAGE_CONSUMER_EXERCISE_NOT_CHANNEL_PUBLICATION", **persistent)
    except Exception as error:
        campaign.finish("FAIL_PACKAGE_CONSUMER_EXERCISE", error=str(error))
        raise


def replay(root, executable, phase):
    campaign = Campaign(root, executable, phase)
    try:
        persistent = json.loads((campaign.root / "persistent.json").read_text())
        state = Path(persistent["state"])
        project = Path(persistent["project"])
        campaign.run("package-verification", [executable, "verify-package"])
        campaign.run("offline-rebuild", [executable, "build", "--state", state, "--project", project,
                     "--output-dir", campaign.root / ("build-" + phase)])
        native = campaign.root / ("build-" + phase) / "artifacts/AMIRUST"
        if sha(native) != persistent["hello_native_sha256"]:
            raise ValueError("package lifecycle changed the native output")
        if project_inventory(project) != persistent["project_inventory"]:
            raise ValueError("package lifecycle modified project or lock files")
        if sha(campaign.home / ".rustup/settings.toml") != persistent["rustup_settings_sha256"]:
            raise ValueError("package lifecycle changed global Rust settings")
        campaign.run("retained-inputs", [executable, "check-inputs", "--state", state])
        campaign.finish("PASS_PACKAGE_LIFECYCLE_REPLAY_NOT_CHANNEL_PUBLICATION",
                        native_sha256=sha(native), project_preserved=True, global_rust_preserved=True)
    except Exception as error:
        campaign.finish("FAIL_PACKAGE_LIFECYCLE_REPLAY", error=str(error))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("exercise", "replay"))
    parser.add_argument("--executable", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--phase", default="reinstall")
    parser.add_argument("--readme", default=Path(__file__).with_name("README.md"), type=Path)
    args = parser.parse_args()
    if args.mode == "exercise":
        args.root.mkdir(mode=0o700)
        exercise(args.root, args.executable, args.readme)
    else:
        replay(args.root, args.executable, args.phase)


if __name__ == "__main__":
    main()
