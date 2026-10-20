"""Focused offline tests for the protected native outer coordinator."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("ci_native_outer.py")
SPEC = importlib.util.spec_from_file_location("ami_rust_ci_native_outer_test_target", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ci_native_outer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ci_native_outer
SPEC.loader.exec_module(ci_native_outer)

auth = ci_native_outer.auth


class NativeOuterCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="native-outer-coordinator-test-")
        self.root = Path(self.temp.name).resolve()
        self.version = "0.2.0"
        self.config = {"sdk_version": self.version, "cli_version": "0.2.0-dev"}
        self.identity = {"source_sha": "1" * 40, "workflow_sha": "1" * 40,
                         "run_id": 42, "run_attempt": 3}

    def tearDown(self):
        self.temp.cleanup()

    def _assets(self):
        names = ci_native_outer._asset_names(self.version)
        return {name: ("fixture:" + name).encode() for name in names.values()}

    def _proof_values(self):
        values = []
        for index, subject in enumerate(ci_native_outer._proof_subjects(self.version)):
            path = self.root / f"proof-{index}.json"
            path.write_text('{"fixture":true}\n', encoding="utf-8")
            values.append(f"{subject}={path}")
        return values

    def test_proof_mapping_requires_exact_subject_set_once(self):
        values = self._proof_values()
        parsed = ci_native_outer._proof_mapping(values, self.version)
        self.assertEqual(set(parsed), set(ci_native_outer._proof_subjects(self.version)))
        self.assertEqual(ci_native_outer._proof_filename("SHA256SUMS"), "SHA256SUMS.json")
        with self.assertRaisesRegex(ValueError, "exactly four"):
            ci_native_outer._proof_mapping(values[:-1], self.version)
        with self.assertRaisesRegex(ValueError, "once"):
            ci_native_outer._proof_mapping(values + [values[0]], self.version)
        with self.assertRaisesRegex(ValueError, "exact outer subject"):
            ci_native_outer._proof_mapping(values + ["release.json=" + str(self.root)], self.version)

    def test_candidate_inventory_binds_all_six_bytes_and_rejects_extra_files(self):
        candidate = self.root / "candidate"
        candidate.mkdir()
        assets = self._assets()
        for name, raw in assets.items():
            (candidate / name).write_bytes(raw)
        rows = ci_native_outer._candidate_rows(candidate, set(assets))
        self.assertEqual([row["path"] for row in rows], sorted(assets))
        for row in rows:
            self.assertEqual(row["sha256"], auth.sha(assets[row["path"]]))
        (candidate / "unexpected").write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            ci_native_outer._candidate_rows(candidate, set(assets))

    def test_native_package_inputs_pin_six_assets_four_proofs_and_each_host_launcher(self):
        assets = self._assets()
        rows = [{"path": name, "bytes": len(raw), "sha256": auth.sha(raw)}
                for name, raw in sorted(assets.items())]
        proof_rows = {subject: {"bytes": 17, "sha256": str(index + 1) * 64}
                      for index, subject in enumerate(ci_native_outer._proof_subjects(self.version))}
        manifest_raw = b'{"native":"manifest"}\n'
        manifest = {"assets": []}
        launcher_rows = {
            ci_native_outer.LINUX: {"path": "bin/ami-rust-linux", "bytes": 5,
                                    "sha256": auth.sha(b"linux")},
            ci_native_outer.MACOS: {"path": "bin/ami-rust-macos", "bytes": 5,
                                    "sha256": auth.sha(b"macos")},
        }
        maintainer = "Maintainer <maintainer@example.invalid>"
        for host in ci_native_outer.HOSTS:
            pins = ci_native_outer._package_inputs(
                self.identity, "2" * 40, manifest_raw, manifest, self.config, rows,
                proof_rows, launcher_rows, host, maintainer)
            self.assertEqual(pins["schema"], "ami-rust-package-inputs-v2")
            self.assertEqual(pins["host"], host)
            self.assertEqual(pins["source_tree"], "2" * 40)
            self.assertEqual(pins["package_version"], "0.2.0-2")
            self.assertEqual(pins["packaging_revision"], 2)
            self.assertEqual(pins["cli_version"], self.config["cli_version"])
            self.assertEqual(pins["sdk_version"], self.config["sdk_version"])
            self.assertEqual(pins["assets"], rows)
            self.assertEqual(set(pins["publisher_proofs"]),
                             set(ci_native_outer._proof_subjects(self.version)))
            self.assertEqual(pins["launchers"]["ami-rust"]["sha256"], launcher_rows[host]["sha256"])
            self.assertEqual(pins["launchers"]["cargo-ami"]["sha256"], launcher_rows[host]["sha256"])
            self.assertEqual(pins["maintainer"], maintainer)
        with self.assertRaisesRegex(ValueError, "six finalized"):
            ci_native_outer._package_inputs(
                self.identity, "2" * 40, manifest_raw, manifest, self.config, rows[:-1],
                proof_rows, launcher_rows, ci_native_outer.LINUX, maintainer)

    def test_bundle_launcher_hashes_are_checked_against_manifest_and_bytes(self):
        bundle = self.root / "bundle"
        bundle.mkdir()
        config = self.config
        inputs = {"schema": "fixture", "materials": []}
        identity = self.identity
        launchers = {ci_native_outer.LINUX: b"linux-launcher",
                     ci_native_outer.MACOS: b"macos-launcher"}
        paths = {ci_native_outer.LINUX: "bin/ami-rust-linux",
                 ci_native_outer.MACOS: "bin/ami-rust-macos"}
        (bundle / ".auth").mkdir()
        (bundle / ".auth/inputs.json").write_bytes(auth.encoded(inputs))
        host_rows = {}
        assets = []
        for host in ci_native_outer.HOSTS:
            raw = launchers[host]
            name = paths[host]
            destination = bundle / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
            pin = {"path": name, "bytes": len(raw), "sha256": auth.sha(raw)}
            host_rows[host] = pin
            assets.append(pin)
        manifest = {
            "schema": "ami-rust-release-v2", "qualification_only": False,
            "version": config["sdk_version"], "assets": assets, "host_launchers": host_rows,
            "producer": {"kind": "protected-github-actions", "repository": auth.REPO,
                         "workflow": auth.WORKFLOW, "source_sha": identity["source_sha"],
                         "workflow_sha": identity["workflow_sha"], "run_id": identity["run_id"],
                         "run_attempt": identity["run_attempt"],
                         "acceptance": "R1 acceptance and publication are separate gates"},
        }
        (bundle / "release.json").write_bytes(auth.encoded(manifest))
        with patch.object(auth, "input_manifest_for_sdk", return_value=inputs):
            checked, raw, checked_launchers, digest = ci_native_outer._bundle_identity(
                bundle, identity, config)
            self.assertEqual(checked, manifest)
            self.assertEqual(raw, auth.encoded(manifest))
            self.assertEqual(checked_launchers, launchers)
            self.assertEqual(len(digest), 64)
            (bundle / paths[ci_native_outer.MACOS]).write_bytes(b"tampered-launcher")
            with self.assertRaisesRegex(ValueError, "differs from its manifest pin"):
                ci_native_outer._bundle_identity(bundle, identity, config)

    def test_prepare_requires_exact_local_linux_launcher_bytes(self):
        cli = self.root / "ami-rust"
        launchers = {ci_native_outer.LINUX: b"independently-built-linux-cli",
                     ci_native_outer.MACOS: b"macos-cli"}
        cli.write_bytes(launchers[ci_native_outer.LINUX])
        ci_native_outer._check_local_linux_launcher(cli, launchers)

        cli.write_bytes(b"different-linux-cli")
        with self.assertRaisesRegex(ValueError, "byte-for-byte"):
            ci_native_outer._check_local_linux_launcher(cli, launchers)

    def test_source_policy_uses_native_sdk_input_manifest_and_pinned_verifier_paths(self):
        materials = {"schema": "ami-rust-publisher-inputs-v2", "materials": []}
        tools = {
            "tools": {name: {"path": f"/tmp/verifier/tools/{name}", "sha256": str(i) * 64}
                      for name, i in (("gh", 1), ("cosign", 2))},
            "roots": {"gh": {"path": "/tmp/verifier/gh-root", "sha256": "3" * 64},
                      "cosign": {"path": "/tmp/verifier/cosign-root", "sha256": "4" * 64}},
        }
        with patch.object(auth, "input_manifest_for_sdk", return_value=materials):
            policy = ci_native_outer._native_policy(self.identity, tools, self.config)
        self.assertEqual(policy["inputs_manifest_sha256"], auth.sha(auth.encoded(materials)))
        self.assertEqual(policy["gh"]["path"], tools["tools"]["gh"]["path"])
        self.assertEqual(policy["cosign_trusted_root"]["sha256"], "4" * 64)
        self.assertEqual(policy["source_sha"], self.identity["source_sha"])

    def test_prepare_refuses_before_creating_paths_without_protected_context(self):
        work = self.root / "work"
        output = self.root / "output"
        with patch.object(auth, "context", side_effect=ValueError("protected context required")):
            with self.assertRaisesRegex(ValueError, "protected context required"):
                ci_native_outer.prepare(self.root / "missing-bundle", work, output,
                                        self.root / "missing-host-rust",
                                        self.root / "ami-rust-python-bootstrap")
        self.assertFalse(work.exists())
        self.assertFalse(output.exists())

    def test_child_environment_removes_registry_tokens(self):
        env = ci_native_outer._source_env({"PATH": "/usr/bin", "CARGO_REGISTRY_TOKEN": "hidden",
                                           "CARGO_REGISTRIES_CRATES_IO_TOKEN": "hidden"})
        self.assertNotIn("CARGO_REGISTRY_TOKEN", env)
        self.assertNotIn("CARGO_REGISTRIES_CRATES_IO_TOKEN", env)
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")

    def test_resume_state_keeps_python_receipt_but_never_serializes_live_objects(self):
        work = self.root / "work"
        work.mkdir(mode=0o700)
        state = {"schema": "ami-rust-native-outer-state-v1", "phase": "prepared",
                 "python_bootstrap_receipt": {"host": ci_native_outer.LINUX},
                 "supervision": {"commands": []}, "supervisor": object(),
                 "manifest_raw": b"not JSON serializable"}
        ci_native_outer._save_state(work, state)
        saved = ci_native_outer._load_state(work)
        self.assertEqual(saved["python_bootstrap_receipt"], {"host": ci_native_outer.LINUX})
        self.assertNotIn("supervisor", saved)
        self.assertNotIn("manifest_raw", saved)


if __name__ == "__main__":
    unittest.main()
