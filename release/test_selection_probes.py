"""Synthetic tests for bounded selection-probe control flow and diagnostics."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


SCRIPT = Path(__file__).resolve().with_name("selection_probes.py")
SPEC = importlib.util.spec_from_file_location("_test_selection_probes", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load selection probe module")
probes = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probes
SPEC.loader.exec_module(probes)

HOST = {("Darwin", "arm64"): "macos-aarch64",
        ("Linux", "x86_64"): "linux-x86_64"}[(platform.system(), platform.machine().lower())]


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def json_bytes(value) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


class LocalSupervisor:
    """Small real subprocess runner for trusted fixture CLI calls."""

    def __init__(self, root: Path):
        self.work = root / "supervisor-work"
        self.output = root / "supervisor-output"
        self.python_root = root / "python-root"
        self.work.mkdir(parents=True)
        self.output.mkdir(parents=True)
        self.python_root.mkdir(parents=True)
        self.env = dict(os.environ)
        self.limits = {"workspace_bytes": 128 * 1024**2}
        self.commands = []

    def managed_bytes(self):
        return sum(path.stat().st_size for root in (self.work, self.output, self.python_root)
                   for path in root.rglob("*") if path.is_file() and not path.is_symlink())

    def check_limits(self, _label):
        if self.managed_bytes() > self.limits["workspace_bytes"]:
            raise RuntimeError("fixture workspace limit")

    def run(self, command, *, cwd, label, timeout=300):
        log_dir = self.work / "logs"
        log_dir.mkdir(exist_ok=True)
        stdout_name, stderr_name = f"{label}.stdout.log", f"{label}.stderr.log"
        start = time.monotonic()
        result = subprocess.run(command, cwd=cwd, env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, check=False)
        (log_dir / stdout_name).write_bytes(result.stdout)
        (log_dir / stderr_name).write_bytes(result.stderr)
        row = {"label": label, "exit_code": result.returncode, "stop_reason": None,
               "elapsed_seconds": time.monotonic() - start,
               "stdout_log": "logs/" + stdout_name, "stderr_log": "logs/" + stderr_name}
        self.commands.append(row)
        if result.returncode:
            raise RuntimeError(label + " failed")
        return row


class Fixture:
    def __init__(self, root: Path):
        self.root = root
        self.work = root / "work"
        self.consumer = self.work / "consumers/absolute-a"
        self.sdk_root = self.consumer / "sdk-0.1.0/sdk"
        self.components = {name: self.work / "component-staging" / name
                           for name in probes.COMPONENTS}
        self.python = Path(sys.executable).resolve(strict=True)
        self.host = HOST
        self.consumer.mkdir(parents=True)
        (self.sdk_root / "host").mkdir(parents=True)
        (self.sdk_root / "contract").mkdir()
        for name in ("cli.py", "contracts.py", "build.py"):
            shutil.copyfile(SCRIPT.parents[1] / "host" / name, self.sdk_root / "host" / name)

        self.component_info = {}
        component_pins = {}
        component_manifest_paths = []
        files = ["host/cli.py", "host/contracts.py", "host/build.py"]
        for name in probes.COMPONENTS:
            root_path = self.components[name]
            if name == "rust":
                members = {"bin/rustc": (b"fixture rustc\n", 0o755),
                           "bin/rustdoc": (b"fixture rustdoc\n", 0o755)}
            elif name == "cargo":
                members = {"bin/cargo": (b"fixture cargo\n", 0o755)}
            elif name == "toolchain":
                members = {"bin/ld.lld": (b"fixture linker\n", 0o755)}
            elif name == "collector":
                members = {"bin/aros-collect": (b"fixture collector\n", 0o755)}
            elif name == "csdk":
                members = {"include/aros.h": (b"fixture header\n", 0o644)}
            else:
                members = {"registry/index/fixture": (b"fixture vendor\n", 0o644)}
            inventory_files = []
            for relative, (raw, mode) in members.items():
                path = root_path / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
                path.chmod(mode)
                inventory_files.append({"path": relative, "bytes": len(raw), "sha256": digest(raw)})
            component_manifest = {"files": inventory_files, "symlinks": []}
            manifest_relative = f"component-manifests/{name}.json"
            manifest_path = self.sdk_root / manifest_relative
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            raw_manifest = json_bytes(component_manifest)
            manifest_path.write_bytes(raw_manifest)
            files.append(manifest_relative)
            component_manifest_paths.append(manifest_relative)
            component_pins[name] = {"manifest": manifest_relative,
                                    "sha256": digest(raw_manifest)}
            self.component_info[name] = {"manifest_path": manifest_relative,
                                         "manifest_sha256": digest(raw_manifest),
                                         "manifest": component_manifest}

        (self.sdk_root / "Cargo.toml").write_text('[package]\nname="fixture"\n')
        (self.sdk_root / "Cargo.lock").write_text("version = 3\n")
        files.extend(("Cargo.toml", "Cargo.lock"))
        for relative in files:
            path = self.sdk_root / relative
            raw = path.read_bytes()
            self_file_rows = getattr(self, "file_rows", [])
            self_file_rows.append({"path": relative, "bytes": len(raw), "sha256": digest(raw)})
            self.file_rows = self_file_rows
        cargo_binary = self.components["cargo"] / "bin/cargo"
        manifest = {
            "schema": "ami-rust-sdk-v1", "version": "0.1.0",
            "qualification_only": False, "driver": "host/build.py",
            "files": self.file_rows,
            "profiles": {HOST: {"cargo_metadata_mode": "ami-rust-reproducible-cross-v1",
                                 "cargo_binary": "bin/cargo", "rust_host": "fixture-host",
                                 "components": component_pins}},
        }
        manifest_raw = json_bytes(manifest)
        self.manifest_path = self.sdk_root / "contract/sdk.json"
        self.manifest_path.write_bytes(manifest_raw)
        self.manifest = manifest
        self.manifest_sha = digest(manifest_raw)
        self.sdk = {"root": self.sdk_root, "manifest": manifest,
                    "manifest_sha256": self.manifest_sha,
                    "component_info": self.component_info}

        cargo_toml = self.sdk_root / "Cargo.toml"
        cargo_lock = self.sdk_root / "Cargo.lock"
        project_lock = {
            "schema": "ami-rust-project-lock-v1",
            "sdk": {"root": str(self.sdk_root), "manifest": "contract/sdk.json",
                    "manifest_sha256": self.manifest_sha},
            "host": {"platform": HOST, "python": str(self.python),
                     "python_sha256": digest(self.python.read_bytes())},
            "components": {name: str(path) for name, path in self.components.items()},
            "cargo": {"manifest_sha256": digest(cargo_toml.read_bytes()),
                      "lock_sha256": digest(cargo_lock.read_bytes())},
        }
        self.lock = self.consumer / "utility.lock.json"
        self.lock.write_bytes(json_bytes(project_lock))
        self.selection = self.consumer / "selection.json"
        self.selection.write_bytes(json_bytes({
            "python": str(self.python),
            "components": {name: str(path) for name, path in self.components.items()},
        }))
        receipt = {"schema": "ami-rust-install-receipt-v2",
                   "release_manifest_sha256": digest(b"fixture release manifest"),
                   "sdk_manifest_sha256": self.manifest_sha, "version": "0.1.0"}
        receipt_raw = json_bytes(receipt)
        (self.sdk_root.parent / "install-receipt.json").write_bytes(receipt_raw)
        (self.consumer / "receipt.sha256").write_text(digest(receipt_raw) + "\n")


class SelectionProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="selection-probe-tests-")
        self.root = Path(self.temp.name).resolve()
        self.fixture = Fixture(self.root)
        self.supervisor = LocalSupervisor(self.root)
        self.probe_root = self.fixture.consumer / ".probe-scratch"
        self.probe_root.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def test_real_cli_accepts_full_fixture_then_refuses_each_isolated_mutation(self):
        fixture = self.fixture
        sdk_sha = fixture.manifest_sha
        cli = fixture.sdk_root / "host/cli.py"
        state_before, _, _, _ = probes._check_preexisting_state(
            fixture.consumer, fixture.sdk, fixture.components, fixture.python, fixture.host)
        before = probes._run_verify(self.supervisor, fixture.python, cli, fixture.lock,
                                    host=fixture.host, sdk_sha=sdk_sha,
                                    label="fixture-positive-verify", cwd=fixture.consumer)
        self.assertEqual(before["result"]["status"], "verified")
        lock, _ = probes._strict_json(fixture.lock)
        rows = probes._run_selection_refusals(
            self.supervisor, fixture.python, cli, fixture.consumer, fixture.sdk_root,
            fixture.lock, lock, fixture.components, fixture.host, self.probe_root)
        self.assertEqual({row["case"] for row in rows}, {
            "missing-lock", "incompatible-schema", "wrong-host", "wrong-sdk-manifest",
            "changed-cargo-lock", "changed-rustc", "changed-linker", "target-override"})
        by_case = {row["case"]: row for row in rows}
        for case in ("changed-cargo-lock", "changed-rustc", "changed-linker"):
            self.assertEqual(by_case[case]["full_copy_readback"]["result"]["status"], "verified")
            self.assertTrue(by_case[case]["accepted_output_absent"])
            self.assertIn("identity mismatch", by_case[case]["stderr"])
        after = probes._run_verify(self.supervisor, fixture.python, cli, fixture.lock,
                                   host=fixture.host, sdk_sha=sdk_sha,
                                   label="fixture-positive-verify-after", cwd=fixture.consumer)
        self.assertEqual(after["result"]["sdk_manifest_sha256"], sdk_sha)
        self.assertTrue(fixture.lock.is_file())
        self.assertEqual(json.loads(fixture.lock.read_text())["components"],
                         {name: str(path) for name, path in fixture.components.items()})
        self.assertFalse((fixture.sdk_root / "Cargo.lock").read_bytes().endswith(b"selection-probe-mutation\n"))
        state_after, _, _, _ = probes._check_preexisting_state(
            fixture.consumer, fixture.sdk, fixture.components, fixture.python, fixture.host)
        self.assertEqual(state_before, state_after)
        self.assertEqual(list(self.probe_root.iterdir()), [])

    def test_supervisor_success_cannot_be_counted_as_expected_negative(self):
        supervisor = LocalSupervisor(self.root / "zero-case")
        output = self.root / "zero-output"
        output.parent.mkdir(exist_ok=True)

        def return_success(command, *, cwd, label, timeout):
            log_dir = supervisor.work / "logs"
            log_dir.mkdir(exist_ok=True)
            (log_dir / "zero.stdout.log").write_bytes(b"{}");
            (log_dir / "zero.stderr.log").write_bytes(b"expected diagnostic")
            row = {"label": label, "exit_code": 0, "stop_reason": None,
                   "stdout_log": "logs/zero.stdout.log", "stderr_log": "logs/zero.stderr.log"}
            supervisor.commands.append(row)
            return row

        supervisor.run = return_success
        with self.assertRaisesRegex(ValueError, "returned normally"):
            probes._expect_refusal(supervisor, ["fixture"], cwd=self.root,
                                   label="runtime-zero", diagnostics=("expected diagnostic",),
                                   absent=(output,))
        self.assertFalse(output.exists())

    def test_stopped_or_wrong_diagnostic_negative_is_not_accepted(self):
        for row, stderr, expected in (
                ({"exit_code": 2, "stop_reason": "time ceiling"}, b"expected", "stopped"),
                ({"exit_code": 2, "stop_reason": None}, b"different refusal", "wrong diagnostic")):
            with self.subTest(expected=expected):
                supervisor = LocalSupervisor(self.root / ("negative-" + expected.replace(" ", "-")))
                label = "probe-" + expected.replace(" ", "-")

                def return_failed(_command, *, cwd, label=label, timeout):
                    log_dir = supervisor.work / "logs"
                    log_dir.mkdir(exist_ok=True)
                    (log_dir / "out.log").write_bytes(b"")
                    (log_dir / "err.log").write_bytes(stderr)
                    process = {"label": label, "stdout_log": "logs/out.log",
                               "stderr_log": "logs/err.log", **row}
                    supervisor.commands.append(process)
                    raise RuntimeError("expected supervisor failure")

                supervisor.run = return_failed
                with self.assertRaisesRegex(ValueError, expected):
                    probes._expect_refusal(supervisor, ["fixture"], cwd=self.root,
                                           label=label, diagnostics=("expected",),
                                           absent=(self.root / "absent-output",))

    def test_sentinel_hashes_detect_mutation(self):
        root = self.root / "sentinels"
        root.mkdir()
        before = probes._sentinels(root)
        after = {str(path): {"sha256": probes._file_sha(path), "bytes": path.stat().st_size}
                 for path in (root / "home/.cargo/config.toml", root / "cargo-home/config.toml",
                              root / "rustup-home/settings.toml")}
        self.assertEqual(before, after)
        changed = root / "cargo-home/config.toml"
        changed.write_bytes(b"changed\n")
        after[str(changed)] = {"sha256": probes._file_sha(changed), "bytes": changed.stat().st_size}
        self.assertNotEqual(before, after)


if __name__ == "__main__":
    unittest.main()
