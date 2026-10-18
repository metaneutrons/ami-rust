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

HERE = Path(__file__).resolve().parent


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
        with (root / (label + ".stdout.log")).open("x") as out, (root / (label + ".stderr.log")).open("x") as err:
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
        snippets = re.findall(r"```sh\n(.*?)\n```", document.read_text(), re.S)
        if len(snippets) != 1:
            raise ValueError("public channel instructions must have exactly one executable block")
        script = root / "verbatim-installation.sh"
        script.write_text(snippets[0] + "\n")
        run("verbatim-public-install", ["/bin/bash", "-e", "-o", "pipefail", script])
        executable = Path(shutil.which("ami-rust") or "")
        if not executable.is_absolute():
            raise ValueError("channel installation did not provide ami-rust")
        run("consumer", [sys.executable, "-I", "-B", HERE / "qualify.py", "exercise",
            "--root", root / "consumer", "--executable", executable, "--readme", HERE / "README.md"])
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
