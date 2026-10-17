#!/usr/bin/env python3
"""Synthetic control-flow tests; all SDK and command-driver inputs are fakes."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().with_name("contract_probes.py")
SPEC = importlib.util.spec_from_file_location("_test_contract_probes", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load compile contract probe helper")
probes = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probes)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def put(path: Path, raw: bytes, executable: bool = False) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    if executable:
        path.chmod(0o755)
    return raw


class FakeSupervisor:
    """An explicit fake process boundary. It never invokes SDK or Cargo code."""
    def __init__(self, work: Path, scenario: str = "pass"):
        self.work = work
        self.env = {"CALLER_SENTINEL": "preserve-this-environment"}
        self.commands = []
        self.scenario = scenario

    def run(self, command, *, cwd, label, timeout=1200):
        self.work.joinpath("logs").mkdir(exist_ok=True)
        stdout_path = self.work / "logs" / (label + ".stdout.log")
        stderr_path = self.work / "logs" / (label + ".stderr.log")
        code, stop, stdout, stderr = 0, None, "", ""
        if label == "contract-probe-fixture-lock":
            args = list(command)
            lock_path = Path(args[args.index("--output") + 1])
            prefix = Path(args[args.index("--prefix") + 1])
            selection_path = Path(args[args.index("--selection") + 1])
            project = Path(args[args.index("--project") + 1])
            selection = json.loads(selection_path.read_text())
            manifest_raw = (prefix / "sdk/contract/sdk.json").read_bytes()
            receipt_raw = (prefix / "install-receipt.json").read_bytes()
            python_path = Path(selection["python"])
            lock = {
                "schema": "ami-rust-project-lock-v1",
                "sdk": {"root": str(prefix / "sdk"), "manifest": "contract/sdk.json",
                        "manifest_sha256": sha(manifest_raw)},
                "host": {"platform": self.host, "python": str(python_path),
                         "python_sha256": sha(python_path.read_bytes())},
                "components": selection["components"],
                "cargo": {"manifest_sha256": sha((project / "Cargo.toml").read_bytes()),
                          "lock_sha256": sha((project / "Cargo.lock").read_bytes())},
            }
            lock_path.write_text(json.dumps(lock, sort_keys=True, indent=2) + "\n")
            stdout = json.dumps({"status": "locked", "host": self.host,
                                 "sdk_manifest_sha256": sha(manifest_raw),
                                 "receipt_sha256": sha(receipt_raw)})
        elif label.startswith("contract-probe-verify-"):
            lock_path = Path(command[-1])
            lock = json.loads(lock_path.read_text())
            stdout = json.dumps({"status": "verified", "host": self.host,
                                 "sdk_manifest_sha256": lock["sdk"]["manifest_sha256"],
                                 "development_only": False})
        elif label == "contract-probe-rustc-version":
            stdout = ("rustc 1.99.0\ncommit-hash: " + self.rust_commit +
                      "\nLLVM version: " + self.rust_llvm + "\nhost: " + self.rust_host + "\n")
        elif label == "contract-probe-cargo-version":
            stdout = "cargo 1.99.0\nrelease: 1.99.0\n"
        elif label.startswith("contract-probe-"):
            name = label.removeprefix("contract-probe-")
            target = Path(self.env["CARGO_TARGET_DIR"])
            target.mkdir(parents=True, exist_ok=True)
            put(target / "fake-cache", b"cache")
            if name == "positive-safe":
                stdout = "Checking m1-compile-fail-fixtures v0.1.0\nFinished dev\n"
                if self.scenario == "positive-fail":
                    code, stderr = 1, "synthetic positive fixture failure\n"
            elif name == "target-std":
                if self.scenario == "negative-unexpected-pass":
                    stdout = "Checking m1-compile-fail-fixtures v0.1.0\n"
                elif self.scenario == "negative-wrong-diagnostic":
                    code, stderr = 1, "error: unrelated fixture diagnostic\n"
                elif self.scenario == "negative-stop":
                    code, stop, stderr = 1, "time ceiling", "synthetic stopped command\n"
                else:
                    code, stderr = 1, "error[E0463]: can't find crate for `std`\n"
                if self.scenario == "input-mutation":
                    project = Path(command[command.index("--manifest-path") + 1]).parent
                    put(project / "fixtures/target_std.rs", b"changed during the check\n")
            else:
                expected = dict(probes.FIXTURES)[name]
                code = 1
                stderr = "error: " + " ".join(expected) + "\n"
        else:
            raise AssertionError("unexpected fake command label: " + label)

        stdout_path.write_text(stdout)
        stderr_path.write_text(stderr)
        row = {"label": label, "exit_code": code, "stop_reason": stop,
               "elapsed_seconds": 0.01, "rss_peak_observed_bytes": 1,
               "managed_peak_observed_bytes": 2, "log_peak_observed_bytes": 3,
               "stdout_log": "logs/" + stdout_path.name,
               "stderr_log": "logs/" + stderr_path.name}
        self.commands.append(row)
        if stop or code:
            raise RuntimeError("synthetic Supervisor failure")
        return row

    def check_limits(self, label):
        self.last_check = label


class CompileContractProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="contract-probes-test-")
        self.root = Path(self.temp.name).resolve()
        self.bundle = self.root / "candidate-bundle"
        self.consumer = self.root / "consumer"
        self.consumer.mkdir(mode=0o700)
        self.prefix = self.consumer / "sdk-0.1.0"
        self.sdk_root = self.prefix / "sdk"
        self.host = probes.ci_sdk.host_identity()[0]
        self.host_target = probes.ci_sdk.HOST_TARGETS[self.host]
        self.rust_commit = "1" * 40
        self.rust_llvm = "23.1.1"
        self.python = put(self.root / "python3", b"synthetic selected Python", executable=True)
        self.python_path = self.root / "python3"
        self.components = {}
        component_info = {}
        for name in probes.COMPONENTS:
            component = self.root / "components" / name
            component.mkdir(parents=True)
            if name == "rust":
                put(component / "bin/rustc", b"synthetic selected rustc", executable=True)
                put(component / "bin/rustdoc", b"synthetic selected rustdoc", executable=True)
            elif name == "cargo":
                put(component / "bin/cargo", b"synthetic selected cargo", executable=True)
            else:
                put(component / "inventory-item", ("synthetic " + name).encode())
            self.components[name] = component
            manifest = probes.ci_sdk.component_inventory(component)
            component_info[name] = {
                "manifest_path": "components/" + name + ".json",
                "manifest_sha256": sha(json.dumps(manifest, sort_keys=True).encode()),
                "manifest": manifest,
            }

        files = []
        sdk_files = {}
        payloads = {
            "host/cli.py": b"# fake SDK CLI\n",
            "host/contracts.py": b"# fake SDK contracts\n",
            "targets/x86_64-aros.json": b'{"llvm-target":"i386-unknown-none"}\n',
            "tests/compile-fail/Cargo.toml": b'[package]\nname="m1-compile-fail-fixtures"\n',
            "tests/compile-fail/Cargo.lock": b"version = 4\n",
        }
        fixture_files = {
            "positive_safe.rs": b"// safe fixture\n",
            "target_std.rs": b"extern crate std;\n",
            "use_after_close.rs": b"// use after close\n",
            "context_exit.rs": b"// context lifetime\n",
            "clone_file.rs": b"// Clone bound\n",
            "send_file.rs": b"// Send bound\n",
            "sync_file.rs": b"// Sync bound\n",
            "borrowed_callback_escape.rs": b"// borrowed callback\n",
        }
        for name, raw in fixture_files.items():
            payloads["tests/compile-fail/fixtures/" + name] = raw
        for relative, raw in payloads.items():
            path = self.sdk_root / relative
            put(path, raw)
            row = {"path": relative, "bytes": len(raw), "sha256": sha(raw)}
            files.append(row)
            sdk_files[relative] = row
        profile_components = {}
        for name, info in component_info.items():
            relative = "host/profiles/" + self.host + "/" + name + ".json"
            raw = (json.dumps(info["manifest"], sort_keys=True, indent=2) + "\n").encode()
            put(self.sdk_root / relative, raw)
            info["manifest_path"] = relative
            info["manifest_sha256"] = sha(raw)
            profile_components[name] = {"manifest": relative, "sha256": info["manifest_sha256"]}
            files.append({"path": relative, "bytes": len(raw), "sha256": sha(raw)})
        put(self.bundle / "install_publisher.py", b"# fake candidate installer\n")
        self.rust_commit = self.rust_commit
        manifest = {
            "schema": "ami-rust-sdk-v1", "version": "0.1.0", "source_identity": "a" * 40,
            "rust_commit": self.rust_commit, "rust_llvm": self.rust_llvm,
            "source_date_epoch": 1791936000, "files": files,
            "profiles": {self.host: {"rust_host": self.host_target, "cargo_binary": "bin/cargo",
                                      "components": profile_components}},
        }
        manifest_raw = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
        self.manifest_sha = sha(put(self.sdk_root / "contract/sdk.json", manifest_raw))
        self.sdk = {"root": self.sdk_root, "manifest": manifest,
                    "manifest_sha256": self.manifest_sha, "component_info": component_info}
        self.bundle.mkdir(parents=True, exist_ok=True)
        release_raw = b'{"candidate":"synthetic"}\n'
        archive_raw = b"synthetic SDK archive bytes\n"
        put(self.bundle / "release.json", release_raw)
        put(self.bundle / "sdk.tar.xz", archive_raw)
        put(self.prefix / "payload/release.json", release_raw)
        put(self.prefix / "payload/sdk.tar.xz", archive_raw)
        receipt = {
            "schema": "ami-rust-install-receipt-v2",
            "publisher": "metaneutrons.ami-rust.github",
            "release_manifest_sha256": sha(release_raw),
            "sdk_manifest_sha256": self.manifest_sha,
            "version": "0.1.0", "inventory": [], "authentication": {"report": {"synthetic": True}},
        }
        receipt_raw = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
        put(self.prefix / "install-receipt.json", receipt_raw)
        put(self.consumer / "receipt.sha256", (sha(receipt_raw) + "\n").encode())
        selection = {"python": str(self.python_path.resolve()),
                     "components": {name: str(path.resolve()) for name, path in self.components.items()}}
        put(self.consumer / "selection.json", (json.dumps(selection, sort_keys=True) + "\n").encode())
        self.work = self.root / "supervisor-work"
        self.work.mkdir()
        self.supervisor = FakeSupervisor(self.work)
        self.supervisor.host = self.host
        self.supervisor.rust_commit = self.rust_commit
        self.supervisor.rust_llvm = self.rust_llvm
        self.supervisor.rust_host = self.host_target

    def tearDown(self):
        self.temp.cleanup()

    def qualify(self):
        return probes.qualify_compile_contract(
            supervisor=self.supervisor, python=self.python_path, bundle=self.bundle,
            consumer=self.consumer, host=self.host, sdk=self.sdk, components=self.components)

    def test_standalone_compile_fail_manifest_has_explicit_license_and_loads_in_cargo(self):
        cargo = shutil.which("cargo")
        if cargo is None:
            self.skipTest("Cargo is required to check the real standalone fixture manifest")
        source_root = Path(__file__).resolve().parents[1]
        manifest = source_root / "tests/compile-fail/Cargo.toml"
        self.assertIn('license = "MIT OR Apache-2.0"', manifest.read_text())
        fixture_raw = manifest.read_bytes()
        sdk_contract = json.loads((source_root / "contract/sdk.json").read_text())
        fixture_rows = [row for row in sdk_contract["files"]
                        if row.get("path") == "tests/compile-fail/Cargo.toml"]
        self.assertEqual(len(fixture_rows), 1)
        self.assertEqual(fixture_rows[0]["bytes"], len(fixture_raw))
        self.assertEqual(fixture_rows[0]["sha256"], sha(fixture_raw))
        outer = json.loads((source_root / "release/bundle-files.json").read_text())
        self.assertEqual(len(outer["files"]), 102)
        quickstart_rows = [row for row in outer["files"] if row.get("path") == "QUICKSTART.md"]
        quickstart = (source_root / "release/bundle-assets/QUICKSTART.md").read_bytes()
        self.assertEqual(len(quickstart_rows), 1)
        self.assertEqual(quickstart_rows[0]["bytes"], len(quickstart))
        self.assertEqual(quickstart_rows[0]["sha256"], sha(quickstart))
        self.assertEqual(quickstart, (source_root / "docs/quickstart.md").read_bytes())
        env = dict(os.environ)
        env.update({"CARGO_NET_OFFLINE": "true", "CARGO_TERM_COLOR": "never"})
        result = subprocess.run(
            [cargo, "metadata", "--no-deps", "--format-version", "1", "--locked",
             "--manifest-path", str(manifest)], cwd=source_root, env=env,
            text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        metadata = json.loads(result.stdout)
        package = next(item for item in metadata["packages"]
                       if item["name"] == "m1-compile-fail-fixtures")
        self.assertEqual(package["license"], "MIT OR Apache-2.0")

    def test_valid_eight_case_pass_binds_flags_and_restores_environment(self):
        environment = self.supervisor.env
        report = self.qualify()
        self.assertEqual(report["status"], "PASS_COMPILE_CONTRACT_PROBES_ONLY")
        self.assertEqual([row["bin"] for row in report["fixtures"]],
                         [name for name, _ in probes.FIXTURES])
        self.assertTrue(all(row["accepted"] for row in report["fixtures"]))
        self.assertIs(self.supervisor.env, environment)
        self.assertIn("--locked", report["fixtures"][0]["command"])
        self.assertIn("--offline", report["fixtures"][0]["command"])
        self.assertIn("-Zbuild-std=core,alloc", report["fixtures"][0]["command"])
        self.assertEqual(report["fixtures"][0]["command"][-2:], ["--bin", "positive-safe"])
        self.assertEqual(report["fixtures"][0]["command"], [
            str(self.components["cargo"] / "bin/cargo"), "-Zhost-config",
            "-Ztarget-applies-to-host", "-Zami-rust-reproducible-cross",
            "-Zbuild-std=core,alloc", "-Zbuild-std-features=compiler-builtins-mem",
            "-Zjson-target-spec", "check", "--manifest-path",
            str(self.sdk_root / "tests/compile-fail/Cargo.toml"), "--package",
            "m1-compile-fail-fixtures", "--target",
            str(self.sdk_root / "targets/x86_64-aros.json"), "--release", "--locked",
            "--offline", "-j", "2", "--message-format=human", "--bin", "positive-safe",
        ])
        env = report["compiler"]["environment"]
        self.assertEqual(set(env), {
            "HOME", "PATH", "CARGO", "CARGO_HOME", "CARGO_TARGET_DIR", "RUSTC", "RUSTDOC",
            "TMPDIR", "CARGO_BUILD_JOBS", "CARGO_INCREMENTAL", "CARGO_NET_OFFLINE",
            "CARGO_ENCODED_RUSTFLAGS", "LC_ALL", "TZ", "SOURCE_DATE_EPOCH",
            "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
        })
        self.assertEqual(env["PATH"].split(":")[:3], [
            str(self.components["cargo"] / "bin"), str(self.components["rust"] / "bin"),
            str(self.components["toolchain"] / "bin"),
        ])
        self.assertEqual(env["CARGO"], str(self.components["cargo"] / "bin/cargo"))
        self.assertEqual(env["RUSTC"], str(self.components["rust"] / "bin/rustc"))
        expected_remaps = [
            "--remap-path-prefix=" + str(self.sdk_root) + "=/ami-rust",
            "--remap-path-prefix=" + str(Path(report["scratch_root"]).resolve()) + "=/build",
            "--remap-path-prefix=" + str(self.components["vendor"].resolve()) + "=/vendor",
            "--remap-path-prefix=" + str(self.components["rust"].resolve()) + "=/rust-toolchain",
            "--remap-path-prefix=" + str(self.sdk_root / "tests/compile-fail") + "=/project",
        ]
        self.assertEqual(env["CARGO_ENCODED_RUSTFLAGS"].split("\x1f"), [
            "-Copt-level=2", "-Cpanic=abort", "-Ccodegen-units=1",
            "-Cembed-bitcode=no", "-Clto=off", *expected_remaps,
        ])
        self.assertEqual(report["compiler"]["cargo_config_sha256"],
                         sha(report["compiler"]["cargo_config"].encode()))
        self.assertEqual(report["candidate"]["sdk_files"]["fixture_lock"]["sha256"],
                         report["candidate_after"]["sdk_files"]["fixture_lock"]["sha256"])
        self.assertTrue(report["compile_cache_cleanup"]["removed"])
        self.assertFalse((Path(report["scratch_root"]) / "work/target").exists())
        self.assertTrue((Path(report["scratch_root"]) / ".compile-probe-owner").is_file())
        self.assertTrue((self.consumer / "receipt.sha256").is_file())
        self.assertTrue((self.consumer / "compile-fixtures.lock.json").is_file())

    def test_positive_fixture_failure_refuses(self):
        self.supervisor.scenario = "positive-fail"
        with self.assertRaises(RuntimeError):
            self.qualify()

    def test_negative_unexpected_success_refuses(self):
        self.supervisor.scenario = "negative-unexpected-pass"
        with self.assertRaisesRegex(ValueError, "target-std"):
            self.qualify()

    def test_negative_wrong_diagnostic_refuses(self):
        self.supervisor.scenario = "negative-wrong-diagnostic"
        with self.assertRaisesRegex(ValueError, "target-std"):
            self.qualify()

    def test_supervisor_stop_is_not_an_accepted_negative(self):
        self.supervisor.scenario = "negative-stop"
        with self.assertRaisesRegex(RuntimeError, "stopped by the Supervisor"):
            self.qualify()

    def test_selected_root_mutation_refuses_before_any_command(self):
        selection_path = self.consumer / "selection.json"
        selection = json.loads(selection_path.read_text())
        selection["components"]["vendor"] = str(self.root / "other-vendor")
        selection_path.write_text(json.dumps(selection))
        with self.assertRaisesRegex(ValueError, "actual selected component roots"):
            self.qualify()
        self.assertEqual(self.supervisor.commands, [])

    def test_candidate_input_mutation_during_probe_refuses(self):
        self.supervisor.scenario = "input-mutation"
        with self.assertRaisesRegex(ValueError, "installed SDK file differs from its manifest"):
            self.qualify()

    def test_cleanup_refuses_symlink_cache_without_touching_target(self):
        scratch = self.consumer / ".owned-scratch"
        scratch.mkdir(mode=0o700)
        work = scratch / "work"
        work.mkdir(mode=0o700)
        marker = b"owned scratch\n"
        put(scratch / ".compile-probe-owner", marker)
        external = self.root / "external-cache"
        external.mkdir()
        put(external / "keep", b"preserve")
        os.symlink(external, work / "target")
        with self.assertRaisesRegex(RuntimeError, "not a real owned directory"):
            probes._safe_remove_compile_cache(scratch, self.consumer, marker)
        self.assertEqual((external / "keep").read_bytes(), b"preserve")


if __name__ == "__main__":
    unittest.main()
