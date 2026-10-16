#!/usr/bin/env python3
"""Offline fixtures for the hosted consumer's six prerequisite inputs."""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import shutil
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent


def load_helper(name: str, relative: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ci_sdk = load_helper("_test_consumer_inputs_ci_sdk", "release/ci_sdk.py")
consumer_inputs = load_helper("_test_consumer_inputs", "release/consumer_inputs.py")


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class FakeSdk:
    """Filesystem providers stand in for bounded downloads and extraction."""

    HOST_TARGETS = ci_sdk.HOST_TARGETS
    sha256 = staticmethod(ci_sdk.sha256)
    verify_component = staticmethod(ci_sdk.verify_component)

    def __init__(self, component_info, *, corrupt=None):
        self.component_info = component_info
        self.corrupt = corrupt
        self.calls = []

    def _write_component(self, name, root):
        manifest = self.component_info[name]["manifest"]
        root.mkdir(parents=True)
        for row in manifest["files"]:
            path = root / row["path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            if self.corrupt == name:
                path.write_bytes(b"corrupted fixture component")
            else:
                path.write_bytes(self.component_info[name]["contents"][row["path"]])

    def _install_rust(self, host_rows, inputs, work, components, supervisor):
        self.calls.append("install-rust")
        root = components / "rust"
        self._write_component("rust", root)
        return root, [{"component": "rustc", "sha256": "a" * 64}], [
            {"components": [{"component": "rustc", "expanded_bytes": 10}]}]

    def _extract_pinned_component(self, pin, label, work, destination, supervisor,
                                  selection_manifest=None):
        self.calls.append("pinned-" + label)
        self._write_component(label, destination)
        return destination, {"url": "https://github.com/example/" + label}, {
            "archive_member_count": 1, "expanded_bytes": 10}

    def portable_csdk_prerequisite(self, inputs):
        self.calls.append("derive-csdk")
        return {"source": "derived-csdk"}

    def _extract_local_component(self, pin, label, destination, supervisor):
        self.calls.append("local-" + label)
        self._write_component(label, destination)
        return destination, {"path": pin["source"], "archive_member_count": 1,
                             "expanded_bytes": 10}


class FakeAuth:
    def __init__(self, expected_archive):
        self.expected_archive = expected_archive
        self.calls = []

    def cargo_matches(self, raw, manifest):
        self.calls.append((raw, manifest))
        if raw != self.expected_archive:
            raise ValueError("Cargo archive differs from the fixture pin")


class FakeSupervisor:
    def __init__(self, reference_inputs):
        self.reference_inputs = reference_inputs
        self.text_calls = []
        self.limit_checks = []

    def run_text(self, command, *, cwd, label, timeout):
        self.text_calls.append((command, cwd, label, timeout))
        return ("rustc fixture\ncommit-hash: " + self.reference_inputs["rust_commit"] +
                "\nLLVM version: " + self.reference_inputs["rust_llvm"] +
                "\nhost: " + ci_sdk.HOST_TARGETS["linux-x86_64"] + "\n")

    def check_limits(self, label):
        self.limit_checks.append(label)


def make_component_info():
    components = {}
    for name in ("rust", "cargo", "toolchain", "collector", "csdk", "vendor"):
        if name == "cargo":
            contents = {"bin/cargo": b"fixture cargo binary",
                        "producer.json": b"fixture cargo receipt"}
        else:
            relative = "bin/rustc" if name == "rust" else "payload/" + name
            contents = {relative: ("fixture " + name).encode()}
        files = [{"path": path, "bytes": len(raw), "sha256": digest(raw)}
                 for path, raw in contents.items()]
        components[name] = {"manifest": {"files": files, "symlinks": []},
                            "contents": contents}
    return components


def make_reference_inputs():
    host = "linux-x86_64"
    return {
        "hosts": {host: {"rust": {"pin": "rust"},
                         "toolchain": {"pin": "toolchain"},
                         "collector": {"pin": "collector"}}},
        "rust_commit": "1" * 40,
        "rust_llvm": "fixture-llvm",
        "shared": {"csdk": {"source": "original-csdk"},
                   "vendor": {"source": "pinned-vendor"}},
    }


class ConsumerInputProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = Path(tempfile.mkdtemp(prefix="ami-rust-consumer-inputs-test-"))
        self.work = self.temporary / "work"
        self.bundle = self.temporary / "bundle"
        self.work.mkdir()
        self.bundle.mkdir()
        self.host = "linux-x86_64"
        self.reference_inputs = make_reference_inputs()
        self.component_info = make_component_info()
        self.sdk_info = {"manifest": {"profiles": {self.host: {}}},
                         "component_info": self.component_info}
        self.cargo_archive = b"candidate cargo archive fixture"
        (self.bundle / f"cargo-{self.host}.tar.xz").write_bytes(self.cargo_archive)
        self.sdk = FakeSdk(self.component_info)
        self.auth = FakeAuth(self.cargo_archive)
        self.supervisor = FakeSupervisor(self.reference_inputs)
        self.extract_calls = []

    def tearDown(self):
        shutil.rmtree(self.temporary)

    def extract_cargo(self, archive, root, manifest):
        self.extract_calls.append((archive, root, manifest))
        self.sdk._write_component("cargo", root)
        return ci_sdk.verify_component(root, manifest, "cargo")

    def provision(self):
        return consumer_inputs.provision_inputs(
            self.bundle, self.work, self.supervisor, self.host, self.sdk_info,
            self.reference_inputs, sdk=self.sdk, auth=self.auth,
            extract_cargo=self.extract_cargo)

    def test_returns_exact_six_roots_and_full_inventories_in_order(self):
        report = self.provision()
        expected = ("rust", "cargo", "toolchain", "collector", "csdk", "vendor")

        self.assertEqual(tuple(report["component_roots"]), expected)
        self.assertEqual(tuple(report["component_inventories"]), expected)
        self.assertEqual(set(report["component_roots"]), set(expected))
        for name in expected:
            self.assertEqual(report["component_inventories"][name]["entry_count"],
                             len(self.component_info[name]["manifest"]["files"]))
            self.assertTrue(report["component_roots"][name].is_dir())
        self.assertEqual(report["rust_archives"][0]["component"], "rustc")
        self.assertEqual(report["rust_installer"][0]["components"][0]["component"], "rustc")
        self.assertIn("pin", report["toolchain"])
        self.assertIn("extraction", report["collector"])
        self.assertEqual(report["shared"]["csdk"]["path"], "derived-csdk")
        self.assertEqual(report["shared"]["vendor"]["path"], "pinned-vendor")
        self.assertEqual(report["cargo_inventory"], report["component_inventories"]["cargo"])
        self.assertEqual(report["cargo_archive_sha256"], digest(self.cargo_archive))
        self.assertEqual(self.sdk.calls, ["install-rust", "pinned-toolchain", "pinned-collector",
                                          "derive-csdk", "local-csdk", "local-vendor"])
        self.assertEqual(len(self.auth.calls), 1)
        self.assertEqual(len(self.extract_calls), 1)
        self.assertEqual(self.supervisor.limit_checks,
                         ["all six verified consumer prerequisites"])

    def test_existing_component_staging_fails_before_provider_calls(self):
        (self.work / "component-staging").mkdir()

        with self.assertRaises(FileExistsError):
            self.provision()

        self.assertEqual(self.sdk.calls, [])
        self.assertEqual(self.auth.calls, [])
        self.assertEqual(self.extract_calls, [])
        self.assertEqual(self.supervisor.text_calls, [])

    def test_corrupted_component_fails_inventory_without_success_report(self):
        self.sdk.corrupt = "collector"
        report = None

        with self.assertRaisesRegex(ValueError, "complete collector inventory mismatch"):
            report = self.provision()

        self.assertIsNone(report)
        self.assertEqual(self.supervisor.limit_checks, [])


if __name__ == "__main__":
    unittest.main()
