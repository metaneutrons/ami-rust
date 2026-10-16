#!/usr/bin/env python3
"""Synthetic, no-network fixtures for the hosted SDK producer safeguards."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "release/ci_sdk.py"
spec = importlib.util.spec_from_file_location("_test_ci_sdk", SCRIPT)
ci_sdk = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(ci_sdk)


class HostedSdkProducerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = Path(tempfile.mkdtemp(prefix="ami-rust-ci-sdk-test-"))
        self.work = self.temporary / "work"
        self.output = self.temporary / "output"
        self.python_root = self.temporary / "ami-rust-python-bootstrap"
        for path in (self.work, self.output, self.python_root):
            path.mkdir()

    def tearDown(self):
        shutil.rmtree(self.temporary)

    def test_reading_normative_inputs_does_not_admit_the_source_volume_for_work(self):
        with patch.object(ci_sdk, "validate_resource_policy", side_effect=AssertionError("no disk admission while reading")):
            inputs, resources, host = ci_sdk.read_normative(
                ROOT / "release/ci-sdk-inputs.json", ROOT / "release/ci-resources.json", "macos-aarch64")
        self.assertEqual(inputs["schema"], "ami-rust-ci-sdk-inputs-v1")
        self.assertEqual(ci_sdk.validate_resource_schema(resources), (6 * 1024**3, 24 * 1024**3))
        self.assertIn("rust", host)
        changed = copy.deepcopy(resources)
        changed["build"]["workspace_bytes"] += 1
        with self.assertRaisesRegex(ValueError, "ceilings differ"):
            ci_sdk.validate_resource_schema(changed)

    def test_changed_normative_input_is_rejected(self):
        path = ROOT / "release/ci-sdk-inputs.json"
        inputs = ci_sdk.read_json(path)
        host, _ = ci_sdk.host_identity()
        altered = copy.deepcopy(inputs)
        altered["hosts"][host]["collector"]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            ci_sdk.validate_inputs(altered, inputs, host)

    def test_consumer_csdk_prerequisite_is_the_separately_pinned_derived_archive(self):
        inputs = ci_sdk.read_json(ROOT / "release/ci-sdk-inputs.json")
        pin = ci_sdk.portable_csdk_prerequisite(inputs)
        self.assertEqual(pin["path"], "release/inputs/portable-csdk.tar.xz")
        self.assertNotEqual(pin["sha256"], inputs["shared"]["csdk"]["sha256"])
        self.assertEqual(pin["archive_root"], "Developer")
        changed = copy.deepcopy(inputs)
        changed["portable_csdk"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "normative input pin"):
            ci_sdk.portable_csdk_prerequisite(changed)

    def test_derived_csdk_spec_cannot_replace_the_original_baseline_identity(self):
        inputs = ci_sdk.read_json(ROOT / "release/ci-sdk-inputs.json")
        spec = ci_sdk.portable_csdk_spec(inputs)
        spec["original"]["archive"]["sha256"] = "a" * 64
        path = self.temporary / inputs["portable_csdk"]["path"]
        path.parent.mkdir(parents=True)
        path.write_bytes(ci_sdk.canonical_json(spec))
        inputs["portable_csdk"].update(bytes=path.stat().st_size, sha256=ci_sdk.sha256(path))
        with patch.object(ci_sdk, "ROOT", self.temporary):
            with self.assertRaisesRegex(ValueError, "frozen shared input"):
                ci_sdk.portable_csdk_prerequisite(inputs)

    def test_component_inventory_uses_frozen_hierarchical_path_order(self):
        component = self.work / "component"
        for name in ("include/clang/a.h", "include/clang-c/b.h"):
            target = component / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(name.encode())
        files = [{"path": name, "bytes": len(name.encode()),
                  "sha256": hashlib.sha256(name.encode()).hexdigest()}
                 for name in ("include/clang/a.h", "include/clang-c/b.h")]
        profile = {"files": files, "symlinks": []}
        self.assertEqual(ci_sdk.component_inventory(component), profile)
        ci_sdk.verify_component(component, profile, "fixture")
        with self.assertRaises(ValueError):
            ci_sdk.verify_component(component, {"files": files + files, "symlinks": []}, "fixture")
        (component / "include/clang/a.h").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            ci_sdk.verify_component(component, profile, "fixture")

    def test_both_tracked_host_pin_sets_validate_git_commit_format(self):
        inputs = ci_sdk.read_json(ROOT / "release/ci-sdk-inputs.json")
        for host in ci_sdk.HOST_TARGETS:
            ci_sdk.validate_inputs(inputs, inputs, host)
        altered = copy.deepcopy(inputs)
        altered["rust_commit"] = "0" * 64
        with self.assertRaises(ValueError):
            ci_sdk.validate_inputs(altered, inputs, "macos-aarch64")

    def test_channel_manifest_download_is_bounded_and_hash_pinned(self):
        payload = b"[pkg.rustc]\nversion = 'fixture'\n"

        class Response(io.BytesIO):
            headers = {"Content-Length": str(len(payload))}

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.close()

            def geturl(self):
                return "https://static.rust-lang.org/dist/fixture/channel.toml"

        def opener(request, timeout):
            self.assertEqual(timeout, 30)
            self.assertEqual(request.full_url, "https://static.rust-lang.org/dist/fixture/channel.toml")
            return Response(payload)

        pin = {"url": "https://static.rust-lang.org/dist/fixture/channel.toml",
               "sha256": hashlib.sha256(payload).hexdigest()}
        destination = self.work / "channel.toml"
        row = ci_sdk.download_channel_manifest(pin, destination, opener=opener)
        self.assertEqual(destination.read_bytes(), payload)
        self.assertEqual(row["sha256"], pin["sha256"])
        bad = dict(pin, sha256="0" * 64)
        with self.assertRaises(ValueError):
            ci_sdk.download_channel_manifest(bad, self.work / "bad-channel.toml", opener=opener)
        self.assertFalse((self.work / "bad-channel.toml").exists())
        self.assertFalse((self.work / "bad-channel.toml.partial").exists())

    def test_rust_src_uses_universal_archive_root(self):
        self.assertEqual(ci_sdk._rust_archive_root("rust-src", "aarch64-apple-darwin"),
                         "rust-src-nightly")
        self.assertEqual(ci_sdk._rust_archive_root("rustc", "x86_64-unknown-linux-gnu"),
                         "rustc-nightly-x86_64-unknown-linux-gnu")
        with self.assertRaises(ValueError):
            ci_sdk._rust_archive_root("unknown", "aarch64-apple-darwin")

    def test_collector_profile_selects_exact_files_from_verified_asset_tree(self):
        source = self.work / "verified-collector-asset"
        (source / "bin").mkdir(parents=True)
        (source / "bin/aros-collect").write_bytes(b"collector")
        (source / "bin/other-tool").write_bytes(b"verified but not packaged")
        chosen = source / "bin/aros-collect"
        manifest = {"files": [{"path": "bin/aros-collect", "bytes": chosen.stat().st_size,
                               "sha256": ci_sdk.sha256(chosen)}], "symlinks": []}
        destination = self.work / "profiled-collector"
        ci_sdk._materialize_component_profile(source, destination, manifest,
                                               current_managed=ci_sdk.directory_bytes(self.work))
        self.assertEqual(ci_sdk.component_inventory(destination), manifest)
        self.assertFalse((destination / "bin/other-tool").exists())
        altered = copy.deepcopy(manifest)
        altered["files"][0]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            ci_sdk._materialize_component_profile(source, self.work / "bad-collector", altered)
        self.assertFalse((self.work / "bad-collector").exists())

    def test_pinned_native_reference_and_sha_util_are_checked(self):
        inputs = ci_sdk.read_json(ROOT / "release/ci-sdk-inputs.json")
        reference = ci_sdk.read_json(ROOT / "release/native-reference.json")
        valid = ci_sdk.validate_native_reference(reference, inputs,
                                                  inputs["native_reference"]["sha256"])
        self.assertEqual(sum(len(rows) for rows in valid["hosts"]["linux-x86_64"].values()), 104)
        with self.assertRaises(ValueError):
            ci_sdk.validate_native_reference(reference, inputs, "0" * 64)

    def test_unsafe_tar_path_is_rejected_before_extraction(self):
        archive = self.temporary / "unsafe.tar"
        with tarfile.open(archive, "w") as bundle:
            item = tarfile.TarInfo("root/../../escape")
            item.size = 1
            bundle.addfile(item, io.BytesIO(b"x"))
        destination = self.temporary / "unsafe-extract"
        with self.assertRaises(ValueError):
            ci_sdk.ci_cargo.safe_extract_tar(archive, destination)
        self.assertFalse(destination.exists())
        self.assertFalse((self.temporary / "escape").exists())

    def test_safe_component_tar_extracts_exact_root(self):
        archive = self.temporary / "component.tar"
        with tarfile.open(archive, "w") as bundle:
            directory = tarfile.TarInfo("root/")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            bundle.addfile(directory)
            subdir = tarfile.TarInfo("root/bin/")
            subdir.type = tarfile.DIRTYPE
            subdir.mode = 0o755
            bundle.addfile(subdir)
            file = tarfile.TarInfo("root/bin/tool")
            payload = b"fixture"
            file.size = len(payload)
            file.mode = 0o755
            bundle.addfile(file, io.BytesIO(payload))
        destination = self.temporary / "safe-extract"
        receipt = ci_sdk.ci_cargo.safe_extract_tar(archive, destination)
        self.assertEqual(receipt["component_root"], "root")
        self.assertEqual((destination / "root/bin/tool").read_bytes(), b"fixture")

    def test_workspace_limit_refuses_growth(self):
        supervisor = ci_sdk.Supervisor(self.work, self.output, self.python_root,
                                       {"PATH": "/usr/bin:/bin"})
        baseline = supervisor.managed_bytes()
        supervisor.limits["workspace_bytes"] = baseline - 1
        with self.assertRaises(RuntimeError):
            supervisor.check_limits("fixture")

    def test_native_cargo_must_match_frozen_bytes_and_hash(self):
        accepted = {"bytes": 99, "sha256": hashlib.sha256(b"cargo").hexdigest()}
        ci_sdk.require_cargo_match(dict(accepted), dict(accepted))
        altered = dict(accepted, sha256="0" * 64)
        with self.assertRaises(ValueError):
            ci_sdk.require_cargo_match(altered, accepted)
        with self.assertRaises(ValueError):
            ci_sdk.require_cargo_match(dict(accepted, bytes=100), accepted)

    def test_native_linkage_audit_selects_host_utility_and_records_bounded_evidence(self):
        class RecordingSupervisor:
            def __init__(self):
                self.call = None

            def run_text(self, command, *, cwd, label, timeout):
                self.call = (command, cwd, label, timeout)
                return "dynamic linkage fixture\n"

        cargo_binary = self.work / "cargo-component" / "bin" / "cargo"
        cargo_binary.parent.mkdir(parents=True)
        cargo_binary.write_bytes(b"verified cargo fixture")
        cargo_binary.chmod(0o755)
        for host, (name, option) in ci_sdk.LINKAGE_AUDIT_UTILITIES.items():
            with self.subTest(host=host):
                utility_path = self.work / (name + "-fixture")
                utility_path.write_bytes((name + " fixture").encode())
                utility_path.chmod(0o755)
                with patch.object(ci_sdk.shutil, "which", return_value=str(utility_path)) as which:
                    utility = ci_sdk.resolve_linkage_audit_utility(host)
                which.assert_called_once_with(name)
                supervisor = RecordingSupervisor()
                evidence = ci_sdk.audit_cargo_linkage(host, cargo_binary, utility, supervisor)
                expected_command = [str(utility_path.resolve()), option, str(cargo_binary)]
                self.assertEqual(supervisor.call,
                                 (expected_command, cargo_binary.parent.parent,
                                  "cargo-linkage-evidence", 60))
                self.assertEqual(evidence["host"], host)
                self.assertEqual(evidence["utility"], {
                    "name": name, "path": str(utility_path.resolve()),
                    "sha256": ci_sdk.sha256(utility_path)})
                self.assertEqual(evidence["binary_sha256_before"], ci_sdk.sha256(cargo_binary))
                self.assertEqual(evidence["binary_sha256_after"], ci_sdk.sha256(cargo_binary))
                self.assertEqual(evidence["raw_output"], "dynamic linkage fixture\n")

    def test_native_linkage_audit_requires_utility_presence_and_execute_permission(self):
        with patch.object(ci_sdk.shutil, "which", return_value=None) as which:
            with self.assertRaisesRegex(ValueError, "utility is missing: otool"):
                ci_sdk.resolve_linkage_audit_utility("macos-aarch64")
        which.assert_called_once_with("otool")

        utility_path = self.work / "readelf-fixture"
        utility_path.write_bytes(b"not executable")
        utility_path.chmod(0o644)
        with patch.object(ci_sdk.shutil, "which", return_value=str(utility_path)) as which:
            with self.assertRaisesRegex(ValueError, "utility is not executable: readelf"):
                ci_sdk.resolve_linkage_audit_utility("linux-x86_64")
        which.assert_called_once_with("readelf")

    def test_native_linkage_audit_rejects_binary_mutation_during_measurement(self):
        cargo_binary = self.work / "cargo-component" / "bin" / "cargo"
        cargo_binary.parent.mkdir(parents=True)
        cargo_binary.write_bytes(b"verified cargo fixture")
        cargo_binary.chmod(0o755)
        utility_path = self.work / "readelf-fixture"
        utility_path.write_bytes(b"readelf fixture")
        utility_path.chmod(0o755)
        utility = {"name": "readelf", "path": str(utility_path.resolve()),
                   "sha256": ci_sdk.sha256(utility_path)}

        class MutatingSupervisor:
            def run_text(self, command, *, cwd, label, timeout):
                cargo_binary.write_bytes(b"mutated during measurement")
                return "dynamic linkage fixture\n"

        with self.assertRaisesRegex(ValueError, "Cargo binary changed during native linkage audit"):
            ci_sdk.audit_cargo_linkage("linux-x86_64", cargo_binary, utility, MutatingSupervisor())

    def test_successful_output_retirement_removes_only_managed_build_tree(self):
        build = self.work / "build"
        build.mkdir()
        (build / "marker").write_text("fixture")
        ci_sdk._retire_successful_build(build, self.work)
        self.assertFalse(build.exists())
        outside = self.temporary / "outside"
        outside.mkdir()
        with self.assertRaises(ValueError):
            ci_sdk._retire_successful_build(outside, self.work)
        linked = self.work / "linked-build"
        linked.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            ci_sdk._retire_successful_build(linked, self.work)

    def test_root_a_artifact_survives_retirement_until_root_b_match(self):
        build = self.work / "build-results/sdk-layout-a/qualification"
        artifact = build / "artifacts/AMIRUST"
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(b"native fixture")
        preserved = ci_sdk._preserve_native_payload(artifact, self.work, "qualification")
        before = ci_sdk.sha256(artifact)
        ci_sdk._retire_successful_build(build, self.work)
        self.assertFalse(build.exists())
        self.assertEqual(ci_sdk.sha256(preserved), before)
        payload = ci_sdk._copy_native_payload(preserved, self.output, "qualification")
        self.assertEqual(payload["sha256"], before)

    def test_cold_roots_copy_from_separate_staging_and_each_other(self):
        sdk_source = self.work / "sdk-staging"
        (sdk_source / "contract").mkdir(parents=True)
        (sdk_source / "contract/sdk.json").write_text("{}\n")
        (sdk_source / "Cargo.toml").write_text("[workspace]\n")
        (sdk_source / "Cargo.lock").write_text("# fixture\n")
        component_roots = {}
        for name in ("rust", "cargo", "toolchain", "collector", "csdk", "vendor"):
            root = self.work / "component-staging" / name
            root.mkdir(parents=True)
            (root / "identity").write_text(name)
            component_roots[name] = root
        layouts = ci_sdk._prepare_layout(self.work, "macos-aarch64", sdk_source,
                                         component_roots, Path(sys.executable).resolve())
        self.assertNotEqual(layouts[0]["sdk"].resolve(), sdk_source.resolve())
        self.assertEqual((layouts[0]["sdk"] / "contract/sdk.json").read_text(), "{}\n")
        self.assertEqual((layouts[1]["components"]["collector"] / "identity").read_text(),
                         "collector")
        self.assertNotEqual(layouts[0]["components"]["collector"].resolve(),
                            component_roots["collector"].resolve())
        self.assertNotEqual(layouts[1]["components"]["collector"].resolve(),
                            layouts[0]["components"]["collector"].resolve())

    def _nested_child_command(self, body: str) -> list[str]:
        child_code = "import time; time.sleep(30)"
        child = json.dumps([sys.executable, "-I", "-B", "-c", child_code])
        marker = json.dumps(str(self.work / "nested.pid"))
        code = ("import json, pathlib, subprocess, time; "
                f"p=subprocess.Popen({child}, start_new_session=True); "
                f"pathlib.Path({marker}).write_text(str(p.pid)); " + body)
        return [sys.executable, "-I", "-B", "-c", code]

    def _assert_group_stopped(self, pid: int):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                os.killpg(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.05)
        self.fail("nested process group remained after bounded supervisor cleanup")

    def test_nested_new_group_is_killed_after_leader_exit(self):
        supervisor = ci_sdk.Supervisor(self.work, self.output, self.python_root,
                                       {"PATH": "/usr/bin:/bin"})
        with self.assertRaises(RuntimeError):
            supervisor.run(self._nested_child_command("time.sleep(0.4)"),
                           cwd=self.work, label="nested-exit", timeout=5)
        pid = int((self.work / "nested.pid").read_text())
        self._assert_group_stopped(pid)

    def test_monitor_error_resamples_and_kills_nested_group(self):
        calls = 0

        def fail_once():
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("synthetic process observer failure")
            return ci_sdk.ci_cargo.process_rows()

        supervisor = ci_sdk.Supervisor(self.work, self.output, self.python_root,
                                       {"PATH": "/usr/bin:/bin"}, rows_reader=fail_once)
        with self.assertRaises(RuntimeError):
            supervisor.run(self._nested_child_command("time.sleep(5)"),
                           cwd=self.work, label="monitor-failure", timeout=5)
        pid = int((self.work / "nested.pid").read_text())
        self._assert_group_stopped(pid)

    def test_workspace_limit_kills_wrapper_and_nested_group(self):
        supervisor = ci_sdk.Supervisor(self.work, self.output, self.python_root,
                                       {"PATH": "/usr/bin:/bin"})
        supervisor.limits["workspace_bytes"] = supervisor.managed_bytes() + 2048
        code = "import pathlib,time; pathlib.Path('trigger.bin').write_bytes(b'x'*65536); time.sleep(5)"
        with self.assertRaises(RuntimeError):
            supervisor.run(self._nested_child_command(code), cwd=self.work,
                           label="workspace-limit", timeout=5)
        pid = int((self.work / "nested.pid").read_text())
        self._assert_group_stopped(pid)

    def test_cargo_component_archive_is_exact_and_deterministic(self):
        component = self.work / "component"
        (component / "bin").mkdir(parents=True)
        (component / "bin/cargo").write_bytes(b"cargo fixture")
        (component / "bin/cargo").chmod(0o755)
        (component / "producer.json").write_bytes(b"{}\n")
        rows = []
        for name in ("bin/cargo", "producer.json"):
            path = component / name
            rows.append({"path": name, "bytes": path.stat().st_size,
                         "sha256": ci_sdk.sha256(path)})
        manifest = {"files": rows, "symlinks": []}
        first = self.output / "cargo-a.tar.xz"
        second = self.output / "cargo-b.tar.xz"
        ci_sdk._canonical_cargo_archive(component, first, manifest)
        ci_sdk._canonical_cargo_archive(component, second, manifest)
        self.assertEqual(ci_sdk.sha256(first), ci_sdk.sha256(second))
        with tarfile.open(first, "r:xz") as bundle:
            self.assertEqual([m.name for m in bundle.getmembers()], ["bin/cargo", "producer.json"])


if __name__ == "__main__":
    unittest.main()
