#!/usr/bin/env python3
"""Synthetic, no-network fixtures for the hosted SDK producer safeguards."""
from __future__ import annotations

import ast
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
PENDING_CARGO_PRODUCERS = ROOT / "release/ci-cargo-producers-pending.json"
PENDING_CARGO_SCHEMA = "ami-rust-cargo-prerequisite-pending-v1"
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

    def _native_build_fixture(self, name="reference-proposal"):
        build = self.work / name
        artifacts = build / "artifacts"
        artifacts.mkdir(parents=True)
        (artifacts / "AMIRUST").write_bytes(b"fresh native fixture")
        rows = {"AMIRUST": {"bytes": 20, "sha256": ci_sdk.sha256(artifacts / "AMIRUST")}}
        byproduct_bytes = {
            "AMIRUST.map": b"link map with private build paths\n",
            "AMIRUST.unstripped": b"unstripped native image",
            "AMIRUST.stripped": b"stripped native image",
        }
        for name, data in byproduct_bytes.items():
            (artifacts / name).write_bytes(data)
        host, _ = ci_sdk.host_identity()
        (build / "build-receipt.json").write_bytes(ci_sdk.canonical_json({
            "status": "PASS", "canonical_artifacts": rows, "host": host,
            "cargo_frontend": {"sha256": "a" * 64}, "commands": []}))
        return build, artifacts, rows, byproduct_bytes

    def _cargo_work_retirement_fixture(self):
        for relative in ci_sdk.CARGO_WORK_RETIRE_PATHS:
            root = self.work / relative
            root.mkdir()
            (root / "marker").write_bytes((relative + " fixture\n").encode())

        cargo_root = self.work / "component-staging" / "cargo"
        binary = cargo_root / "bin" / "cargo"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"verified Cargo fixture\n")
        binary.chmod(0o755)
        (cargo_root / "producer.json").write_bytes(b'{"fixture":true}\n')
        cargo_manifest = ci_sdk.component_inventory(cargo_root)

        report_bytes = b'{"status":"fixture Cargo success"}\n'
        (self.output / "producer.json").write_bytes(report_bytes)
        retained = {
            self.work / "rust-archives/input.tar.xz": b"pinned input archive",
            self.work / "logs/cargo.stdout.log": b"retained Cargo log",
            self.work / "records/build.json": b"retained build record",
            self.work / "vendor-overlay-receipt.json": b"retained overlay receipt",
            self.work / "prepared-sdk/extracted/Cargo.toml": b"new SDK source data",
        }
        for path, payload in retained.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)

        supervisor = ci_sdk.Supervisor(
            self.work, self.output, self.python_root, {"PATH": "/usr/bin:/bin"})
        return {
            "cargo_root": cargo_root,
            "cargo_manifest": cargo_manifest,
            "binary_sha256": ci_sdk.sha256(binary),
            "report_bytes": report_bytes,
            "report_sha256": hashlib.sha256(report_bytes).hexdigest(),
            "retained": retained,
            "supervisor": supervisor,
        }

    def _assert_pending_cargo_marker(self, marker, current):
        expected_keys = {
            "schema", "status", "inputs_sha256", "resource_policy_sha256",
            "host_supervisor_sha256", "reports", "reason",
        }
        self.assertIsInstance(marker, dict)
        self.assertEqual(set(marker), expected_keys)
        self.assertEqual(marker["schema"], PENDING_CARGO_SCHEMA)
        self.assertEqual(marker["status"], "PENDING_PROTECTED_TWO_HOST_RUN")
        self.assertIsInstance(marker["reason"], str)
        self.assertTrue(marker["reason"].strip())
        self.assertEqual(marker["inputs_sha256"], current["inputs_sha256"])
        self.assertEqual(marker["resource_policy_sha256"], current["resource_policy_sha256"])
        self.assertEqual(marker["host_supervisor_sha256"], current["host_supervisor_sha256"])
        for name in ("inputs_sha256", "resource_policy_sha256", "host_supervisor_sha256"):
            self.assertTrue(ci_sdk._is_digest(marker[name]), name)

        self.assertIsInstance(marker["reports"], dict)
        self.assertIsInstance(current["reports"], dict)
        self.assertEqual(set(marker["reports"]), set(ci_sdk.HOST_TARGETS))
        self.assertEqual(set(current["reports"]), set(ci_sdk.HOST_TARGETS))
        for host in ci_sdk.HOST_TARGETS:
            expected = marker["reports"][host]
            observed = current["reports"][host]
            self.assertIsInstance(expected, dict)
            self.assertIsInstance(observed, dict)
            self.assertEqual(set(expected), {
                "sha256", "previous_inputs_sha256", "previous_host_supervisor_sha256",
            })
            self.assertEqual(expected["sha256"], observed["sha256"])
            self.assertEqual(expected["previous_inputs_sha256"],
                             observed["previous_inputs_sha256"])
            self.assertEqual(expected["previous_host_supervisor_sha256"],
                             observed["previous_host_supervisor_sha256"])
            for name in ("sha256", "previous_inputs_sha256",
                         "previous_host_supervisor_sha256"):
                self.assertTrue(ci_sdk._is_digest(expected[name]), f"{host} {name}")
            self.assertEqual(observed["previous_pinned_host_supervisor_sha256"],
                             expected["previous_host_supervisor_sha256"])
            self.assertEqual(observed["resource_policy_sha256"],
                             current["resource_policy_sha256"])
            self.assertNotEqual(expected["previous_inputs_sha256"],
                                current["inputs_sha256"], "old report inputs must be stale")
            # The input digest proves staleness. A Cargo recipe change can
            # leave the shared host supervisor unchanged; its old identity
            # must still match the exact retained report and previous pin.

    def _pending_cargo_fixture(self):
        current = {
            "inputs_sha256": hashlib.sha256(b"new inputs").hexdigest(),
            "resource_policy_sha256": hashlib.sha256(b"current resources").hexdigest(),
            "host_supervisor_sha256": hashlib.sha256(b"new helper").hexdigest(),
            "reports": {},
        }
        reports = {}
        for host in ci_sdk.HOST_TARGETS:
            old_inputs = hashlib.sha256(("old inputs " + host).encode()).hexdigest()
            old_helper = hashlib.sha256(("old helper " + host).encode()).hexdigest()
            reports[host] = {
                "sha256": hashlib.sha256(("raw report " + host).encode()).hexdigest(),
                "previous_inputs_sha256": old_inputs,
                "previous_host_supervisor_sha256": old_helper,
            }
            current["reports"][host] = {
                **reports[host],
                "previous_pinned_host_supervisor_sha256": old_helper,
                "resource_policy_sha256": current["resource_policy_sha256"],
            }
        marker = {
            "schema": PENDING_CARGO_SCHEMA,
            "status": "PENDING_PROTECTED_TWO_HOST_RUN",
            "inputs_sha256": current["inputs_sha256"],
            "resource_policy_sha256": current["resource_policy_sha256"],
            "host_supervisor_sha256": current["host_supervisor_sha256"],
            "reports": reports,
            "reason": "Updated helper pins require fresh protected two-host reports.",
        }
        return marker, current

    def test_reference_proposal_and_default_verify_canonical_files_and_byproducts(self):
        build, artifacts, rows, byproduct_bytes = self._native_build_fixture()

        class Limits:
            def check_limits(self, label):
                self.checked = label

        limits = Limits()
        proposal, native = ci_sdk._verify_native_receipt(build, None, limits, "proposal")
        self.assertEqual(proposal["artifacts"], rows)
        self.assertEqual(native, artifacts / "AMIRUST")
        expected_byproducts = {
            name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in byproduct_bytes.items()
        }
        self.assertEqual(proposal["build_byproducts"], expected_byproducts)
        default, _ = ci_sdk._verify_native_receipt(build, rows, limits, "production")
        self.assertEqual(default["artifacts"], rows)
        self.assertEqual(default["build_byproducts"], expected_byproducts)
        accepted = copy.deepcopy(rows)
        accepted["AMIRUST"]["sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "accepted host reference"):
            ci_sdk._verify_native_receipt(build, accepted, limits, "production")
        (artifacts / "AMIRUST").write_bytes(b"changed native file!")
        with self.assertRaisesRegex(ValueError, "differs from its canonical receipt"):
            ci_sdk._verify_native_receipt(build, None, limits, "corrupt proposal")

    def test_native_receipt_rejects_unknown_extra_artifact(self):
        build, artifacts, _, _ = self._native_build_fixture("unknown-extra")
        extra = artifacts / "target/release/deps/libunknown-abc123.rlib"
        extra.parent.mkdir(parents=True)
        extra.write_bytes(b"unrecorded library")
        with self.assertRaisesRegex(ValueError, "extra=.*libunknown-abc123\\.rlib"):
            ci_sdk._verify_native_receipt(build, None, object(), "unknown extra")

    def test_native_receipt_requires_each_build_byproduct(self):
        build, artifacts, _, _ = self._native_build_fixture("missing-byproduct")
        (artifacts / "AMIRUST.map").unlink()
        with self.assertRaisesRegex(ValueError, "missing=.*AMIRUST\\.map"):
            ci_sdk._verify_native_receipt(build, None, object(), "missing byproduct")

    def test_native_receipt_rejects_linked_build_byproduct(self):
        build, artifacts, _, _ = self._native_build_fixture("linked-byproduct")
        (artifacts / "AMIRUST.map").unlink()
        (artifacts / "AMIRUST.map").symlink_to(artifacts / "AMIRUST")
        with self.assertRaisesRegex(ValueError, "inventory mismatch") as raised:
            ci_sdk._verify_native_receipt(build, None, object(), "linked byproduct")
        self.assertIn("extra=['AMIRUST.map']", str(raised.exception))
        self.assertIn("missing=['AMIRUST.map']", str(raised.exception))

    def test_native_receipt_requires_pass_status(self):
        build, _, _, _ = self._native_build_fixture("nonpass")
        receipt_path = build / "build-receipt.json"
        receipt = ci_sdk.read_json(receipt_path)
        receipt["status"] = "FAILED"
        receipt_path.write_bytes(ci_sdk.canonical_json(receipt))
        with self.assertRaisesRegex(ValueError, "status is not PASS"):
            ci_sdk._verify_native_receipt(build, None, object(), "non-PASS receipt")

    def test_raw_metadata_retention_preserves_exact_canonical_archives(self):
        artifacts = self.work / "artifacts"
        rows = {}
        for crate in ci_sdk.METADATA_CRATES:
            name = "target/release/deps/lib" + crate + "-abc123.rlib"
            source = artifacts / name
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(b"!<arch>\n" + crate.encode())
            rows[name] = {"bytes": source.stat().st_size, "sha256": ci_sdk.sha256(source)}
        retained = ci_sdk._copy_metadata_archives(artifacts, rows, self.output)
        self.assertEqual({row["crate"] for row in retained}, set(ci_sdk.METADATA_CRATES))
        for row in retained:
            self.assertEqual((self.output / row["path"]).read_bytes(),
                             (artifacts / row["canonical_path"]).read_bytes())
        missing_output = self.work / "missing-output"
        missing_output.mkdir()
        with self.assertRaisesRegex(ValueError, "exactly one raw metadata archive"):
            ci_sdk._copy_metadata_archives(artifacts, {}, missing_output)
        changed_output = self.work / "changed-output"
        changed_output.mkdir()
        (artifacts / next(iter(rows))).write_bytes(b"altered archive")
        with self.assertRaisesRegex(ValueError, "differs from its canonical output"):
            ci_sdk._copy_metadata_archives(artifacts, rows, changed_output)

    def test_cold_root_match_stays_strict_and_retains_changed_rlib_bytes(self):
        first_artifacts = self.work / "cold-first-artifacts"
        second_artifacts = self.work / "cold-second-artifacts"
        member = "target/release/deps/libsample-abc123.rlib"
        first_rlib = b"first exact rlib contents"
        second_rlib = b"second exact rlib contents"
        for root, rlib in ((first_artifacts, first_rlib), (second_artifacts, second_rlib)):
            (root / "target/release/deps").mkdir(parents=True)
            (root / "AMIRUST").write_bytes(b"same native image")
            (root / member).write_bytes(rlib)

        def rows(root):
            return {name: {"bytes": (root / name).stat().st_size,
                           "sha256": ci_sdk.sha256(root / name)}
                    for name in ("AMIRUST", member)}

        first_rows = rows(first_artifacts)
        snapshot = ci_sdk._preserve_canonical_snapshot(
            first_artifacts, first_rows, self.work, "dependencies",
            lambda: ci_sdk.MAX_WORK_BYTES - sum(row["bytes"] for row in first_rows.values()))
        first = {"bytes": first_rows["AMIRUST"]["bytes"],
                 "sha256": first_rows["AMIRUST"]["sha256"],
                 "artifacts": first_rows, "snapshot": snapshot}
        with self.assertRaisesRegex(ValueError, "cold-root native outputs differ for dependencies"):
            ci_sdk._assert_cold_roots_match(
                self.work, "dependencies", "sdk-layout-a", "sdk-layout-b", first,
                rows(second_artifacts), second_artifacts,
                {"bytes": first["bytes"], "sha256": first["sha256"]})

        diagnostic_root = self.work / "cold-root-diagnostics"
        report = ci_sdk.read_json(diagnostic_root / "report.json", 2 * 1024**2)
        self.assertEqual(report["status"], "COLD_ROOT_NATIVE_MISMATCH")
        self.assertEqual(report["host_artifact_retention_limit_bytes"], 32 * 1024**2)
        self.assertEqual(report["first_canonical_artifacts"], first_rows)
        self.assertEqual(report["second_canonical_artifacts"], rows(second_artifacts))
        self.assertEqual([row["member"] for row in report["differing_members"]], [member])
        mismatch = report["differing_members"][0]
        self.assertEqual((diagnostic_root / mismatch["first"]["path"]).read_bytes(), first_rlib)
        self.assertEqual((diagnostic_root / mismatch["second"]["path"]).read_bytes(), second_rlib)

    def test_unknown_diagnostic_retention_profile_refuses_before_writing(self):
        for limit in (True, 0, 32 * 1024**2 + 1, 96 * 1024**2):
            with self.subTest(limit=limit), self.assertRaisesRegex(ValueError, "host retention profile"):
                ci_sdk._write_cold_root_diagnostics(
                    self.work, "fixture", "first", "second", {}, {}, {}, self.work, {}, {},
                    host_artifact_retention_limit_bytes=limit)
            self.assertFalse((self.work / "cold-root-diagnostics").exists())

    def test_identical_cold_roots_pass_without_diagnostic_payload(self):
        artifacts = self.work / "identical-cold-artifacts"
        (artifacts / "target/release/deps").mkdir(parents=True)
        (artifacts / "AMIRUST").write_bytes(b"same native image")
        member = "target/release/deps/libsample-abc123.rlib"
        (artifacts / member).write_bytes(b"same rlib")
        rows = {name: {"bytes": (artifacts / name).stat().st_size,
                       "sha256": ci_sdk.sha256(artifacts / name)}
                for name in ("AMIRUST", member)}
        snapshot = ci_sdk._preserve_canonical_snapshot(
            artifacts, rows, self.work, "dependencies",
            lambda: ci_sdk.MAX_WORK_BYTES - sum(row["bytes"] for row in rows.values()))
        first = {"bytes": rows["AMIRUST"]["bytes"], "sha256": rows["AMIRUST"]["sha256"],
                 "artifacts": rows, "snapshot": snapshot}
        ci_sdk._assert_cold_roots_match(
            self.work, "dependencies", "sdk-layout-a", "sdk-layout-b", first, rows,
            artifacts, {"bytes": first["bytes"], "sha256": first["sha256"]})
        self.assertFalse((self.work / "cold-root-diagnostics").exists())

    def test_cold_root_raw_cap_preserves_maps_and_omission_reasons(self):
        first_artifacts = self.work / "capped-first-artifacts"
        second_artifacts = self.work / "capped-second-artifacts"
        member = "target/release/deps/libsample-abc123.rlib"
        for root, value in ((first_artifacts, b"first"), (second_artifacts, b"second")):
            (root / "target/release/deps").mkdir(parents=True)
            (root / "AMIRUST").write_bytes(b"same native")
            (root / member).write_bytes(value)
        rows = lambda root: {
            name: {"bytes": (root / name).stat().st_size, "sha256": ci_sdk.sha256(root / name)}
            for name in ("AMIRUST", member)}
        first_rows = rows(first_artifacts)
        snapshot = ci_sdk._preserve_canonical_snapshot(
            first_artifacts, first_rows, self.work, "dependencies",
            lambda: ci_sdk.MAX_WORK_BYTES - sum(row["bytes"] for row in first_rows.values()))
        first = {"bytes": first_rows["AMIRUST"]["bytes"],
                 "sha256": first_rows["AMIRUST"]["sha256"],
                 "artifacts": first_rows, "snapshot": snapshot}
        with patch.object(ci_sdk, "MAX_COLD_ROOT_DIAGNOSTIC_RAW_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "cold-root native outputs differ"):
                ci_sdk._assert_cold_roots_match(
                    self.work, "dependencies", "sdk-layout-a", "sdk-layout-b", first,
                    rows(second_artifacts), second_artifacts,
                    {"bytes": first["bytes"], "sha256": first["sha256"]})
        report = ci_sdk.read_json(self.work / "cold-root-diagnostics/report.json")
        self.assertEqual(report["first_canonical_artifacts"], first_rows)
        self.assertEqual(report["raw_retained_bytes"], 0)
        self.assertEqual(report["raw_omitted_bytes"], len(b"first") + len(b"second"))
        for side in ("first", "second"):
            self.assertFalse(report["differing_members"][0][side]["retained"])
            self.assertIn("ceiling", report["differing_members"][0][side]["omitted_reason"])

    def test_cold_root_snapshot_admission_uses_aggregate_managed_bytes(self):
        artifacts = self.work / "aggregate-admission-artifacts"
        artifacts.mkdir()
        (artifacts / "AMIRUST").write_bytes(b"native")
        rows = {"AMIRUST": {"bytes": 6, "sha256": ci_sdk.sha256(artifacts / "AMIRUST")}}
        snapshot_bytes = rows["AMIRUST"]["bytes"]
        self.assertLessEqual(ci_sdk.directory_bytes(self.work) + snapshot_bytes,
                             ci_sdk.MAX_WORK_BYTES)
        positive = ci_sdk._preserve_canonical_snapshot(
            artifacts, rows, self.work, "fits",
            lambda: ci_sdk.MAX_WORK_BYTES - snapshot_bytes)
        self.assertIn("AMIRUST", positive)
        self.assertTrue((self.work / "cold-root-first/fits").is_dir())
        aggregate = ci_sdk.MAX_WORK_BYTES - snapshot_bytes + 1
        with self.assertRaisesRegex(ValueError, "managed workspace ceiling"):
            ci_sdk._preserve_canonical_snapshot(
                artifacts, rows, self.work, "dependencies", lambda: aggregate)
        self.assertFalse((self.work / "cold-root-first/dependencies").exists())
        with self.assertRaisesRegex(ValueError, "aggregate managed-byte reader"):
            ci_sdk._preserve_canonical_snapshot(
                artifacts, rows, self.work, "dependencies", 100)

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

    def test_distribution_sbom_identifies_the_selected_cargo_reports_and_artifacts(self):
        sbom = ci_sdk.read_json(ROOT / "release/bundle-assets/sbom.spdx.json", 2 * 1024**2)
        identifiers = {
            "linux-x86_64": "SPDXRef-HostCargoArtifact-Linux-x86-64",
            "macos-aarch64": "SPDXRef-HostCargoArtifact-macOS-aarch64",
        }
        for host, identifier in identifiers.items():
            with self.subTest(host=host):
                path = ROOT / "release/ci-cargo-producers" / (host + ".json")
                artifact = ci_sdk.read_json(path)["custom_cargo_artifact"]
                rows = [row for row in sbom["packages"] if row["SPDXID"] == identifier]
                self.assertEqual(len(rows), 1)
                row = rows[0]
                self.assertEqual(row["checksums"], [
                    {"algorithm": "SHA256", "checksumValue": artifact["sha256"]}])
                self.assertIn(f"Exact size {artifact['bytes']} bytes.", row["sourceInfo"])
                self.assertIn(f"{path.relative_to(ROOT)} SHA-256 {ci_sdk.sha256(path)} ",
                              row["sourceInfo"])

    def test_retired_cli_supervisor_pin_refuses_current_source(self):
        with self.assertRaisesRegex(ValueError, "host/build.py differs from its normative producer pin"):
            ci_sdk.preflight_cargo_producers(ROOT / "release/ci-resources.json")

    def _current_pending_cargo_state(self):
        resources_path = ROOT / "release/ci-resources.json"
        listing = subprocess.run(["/usr/bin/git", "-C", str(ROOT), "ls-files", "-z"],
                                 check=True, capture_output=True, timeout=30).stdout
        tracked = {item.decode("utf-8") for item in listing.split(b"\0") if item}
        inputs, resources, inputs_sha, resources_sha = ci_sdk.prepare_sdk.verify_expected_inputs(
            ROOT, tracked, resources_path)
        reports = {}
        for host in ci_sdk.HOST_TARGETS:
            relative = "release/ci-cargo-producers/" + host + ".json"
            ci_sdk.prepare_sdk.tracked_regular(ROOT, tracked, relative)
            path = ROOT / relative
            report = ci_sdk.read_json(path)
            material = report["input_materials"]
            helpers = material["producer_helpers"]
            reports[host] = {
                "sha256": ci_sdk.sha256(path),
                "previous_inputs_sha256": material["inputs_sha256"],
                "previous_host_supervisor_sha256": helpers["actual_sha256"]["build.py"],
                "previous_pinned_host_supervisor_sha256":
                    helpers["ci_input_pins"]["host_supervisor_sha256"],
                "resource_policy_sha256": material["resource_policy_sha256"],
            }
        return {
            "inputs_sha256": inputs_sha,
            "resource_policy_sha256": resources_sha,
            "host_supervisor_sha256": inputs["producer_helpers"]["host_supervisor_sha256"],
            "reports": reports,
            "verified_inputs": (inputs, resources, tracked, inputs_sha, resources_sha),
        }

    def test_pending_cargo_marker_binds_current_pins_and_stale_reports(self):
        marker, current = self._pending_cargo_fixture()
        self._assert_pending_cargo_marker(marker, current)

    def test_pending_cargo_marker_allows_unchanged_shared_supervisor(self):
        marker, current = self._pending_cargo_fixture()
        for host in ci_sdk.HOST_TARGETS:
            supervisor = current["host_supervisor_sha256"]
            marker["reports"][host]["previous_host_supervisor_sha256"] = supervisor
            current["reports"][host]["previous_host_supervisor_sha256"] = supervisor
            current["reports"][host]["previous_pinned_host_supervisor_sha256"] = supervisor
        self._assert_pending_cargo_marker(marker, current)

    def test_pending_cargo_marker_rejects_mismatched_bindings_and_nonstale_reports(self):
        cases = (
            ("input pin", lambda marker, current:
             marker.update(inputs_sha256="0" * 64)),
            ("resource pin", lambda marker, current:
             marker.update(resource_policy_sha256="0" * 64)),
            ("helper pin", lambda marker, current:
             marker.update(host_supervisor_sha256="0" * 64)),
            ("report hash", lambda marker, current:
             marker["reports"][next(iter(ci_sdk.HOST_TARGETS))].update(sha256="0" * 64)),
            ("missing host report", lambda marker, current:
             marker["reports"].pop(next(iter(ci_sdk.HOST_TARGETS)))),
            ("unexpected marker field", lambda marker, current:
             marker.update(unexpected=True)),
            ("old inputs", lambda marker, current:
             marker["reports"][next(iter(ci_sdk.HOST_TARGETS))].update(
                 previous_inputs_sha256=current["inputs_sha256"])),
            ("old helper", lambda marker, current:
             marker["reports"][next(iter(ci_sdk.HOST_TARGETS))].update(
                 previous_host_supervisor_sha256=current["host_supervisor_sha256"])),
            ("prior helper pin", lambda marker, current:
             current["reports"][next(iter(ci_sdk.HOST_TARGETS))].update(
                 previous_pinned_host_supervisor_sha256="0" * 64)),
            ("prior resource policy", lambda marker, current:
             current["reports"][next(iter(ci_sdk.HOST_TARGETS))].update(
                 resource_policy_sha256="0" * 64)),
            ("malformed schema", lambda marker, current:
             marker.update(schema="ami-rust-cargo-prerequisite-pending-v0")),
            ("empty reason", lambda marker, current: marker.update(reason="  ")),
        )
        for label, alter in cases:
            marker, current = self._pending_cargo_fixture()
            alter(marker, current)
            with self.subTest(binding=label), self.assertRaises(AssertionError):
                self._assert_pending_cargo_marker(marker, current)

    def test_pinned_cargo_reports_reject_stale_policy_digests(self):
        resources_path = ROOT / "release/ci-resources.json"
        listing = subprocess.run(["/usr/bin/git", "-C", str(ROOT), "ls-files", "-z"],
                                 check=True, capture_output=True, timeout=30).stdout
        tracked = {item.decode("utf-8") for item in listing.split(b"\0") if item}
        # Test report policy validation independently of source admission. The
        # retired CLI supervisor cannot pass current-source admission above.
        inputs_path = ROOT / "release/ci-sdk-inputs.json"
        inputs = ci_sdk.read_json(inputs_path)
        resources = ci_sdk.read_json(resources_path)
        inputs_sha, resources_sha = ci_sdk.sha256(inputs_path), ci_sdk.sha256(resources_path)
        for host in ci_sdk.HOST_TARGETS:
            with self.subTest(host=host):
                report = ci_sdk.read_json(ROOT / "release/ci-cargo-producers" / (host + ".json"))
                report["input_materials"]["resource_policy_sha256"] = "0" * 64
                fixture = self.temporary / (host + ".json")
                fixture.write_bytes(ci_sdk.canonical_json(report))
                with self.assertRaisesRegex(ValueError, "input/resource policy digests"):
                    ci_sdk.prepare_sdk.canonical_producer(
                        fixture, host, inputs, resources, inputs_sha, resources_sha, ROOT, tracked)

    def test_stale_resource_policy_stops_before_native_cargo_producer(self):
        stale_resources = self.temporary / "stale-ci-resources.json"
        stale = ci_sdk.read_json(ROOT / "release/ci-resources.json")
        stale["build"]["jobs"] += 1
        stale_resources.write_bytes(ci_sdk.canonical_json(stale))
        managed = self.temporary / "early-produce"
        managed.mkdir()
        args = type("Args", (), {
            "work": managed / "work", "output": managed / "output",
            "python_bootstrap_root": managed / "ami-rust-python-bootstrap",
            "resources": stale_resources,
            "inputs": ROOT / "release/ci-sdk-inputs.json",
            "cargo_inputs": ROOT / "release/ci-bootstrap-inputs.json"})()
        host = "linux-x86_64"
        with (patch.object(ci_sdk, "host_identity", return_value=(host, ci_sdk.HOST_TARGETS[host])),
              patch.object(ci_sdk, "resolve_linkage_audit_utility", return_value={}),
              patch.object(ci_sdk, "csdk_host_tools", return_value={}),
              patch.object(ci_sdk, "verify_python_bootstrap",
                           side_effect=AssertionError("stale pins must fail before bootstrap validation")),
              patch.object(ci_sdk.ci_cargo, "produce") as cargo_produce):
            with self.assertRaisesRegex(ValueError, "resources bytes differ"):
                ci_sdk.produce(args)
            cargo_produce.assert_not_called()

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
        source_record = ci_sdk.read_json(ROOT / "release/candidate-r4/reference-artifacts.json")
        self.assertEqual(valid["basis"]["source_record_sha256"],
                         "8916ae5fd5d9403f1b0592555f0c26e474893a913a4fe925b66d8c4fd1aa2250")
        self.assertEqual(valid["basis"]["source_record_path"],
                         "release/candidate-r4/reference-artifacts.json")
        self.assertEqual(valid["basis"]["native_qualification_path"],
                         "release/candidate-r4/qualification.json")
        self.assertEqual(valid["basis"]["native_qualification_sha256"],
                         "c5e559f592c7300b502ebf976ecd5b65c9191a130dbc2f7b5c9ed68a7045982c")
        self.assertEqual(ci_sdk.sha256(ROOT / valid["basis"]["source_record_path"]),
                         valid["basis"]["source_record_sha256"])
        self.assertEqual(ci_sdk.sha256(ROOT / valid["basis"]["native_qualification_path"]),
                         valid["basis"]["native_qualification_sha256"])
        self.assertEqual(valid["hosts"], source_record)
        expected_sha_util = {"bytes": 928208,
                             "sha256": "85a2171d918423eb56b1a65757b72597e8902dad72f3a924fe277d253b7db162"}
        for host in ("linux-x86_64", "macos-aarch64"):
            self.assertEqual(valid["hosts"][host]["sha256sum"]["AMIRUST"], expected_sha_util)
            self.assertEqual(sum(len(rows) for rows in valid["hosts"][host].values()), 104)
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

    def test_rust_installs_use_distinct_sdk_logs_and_preserve_cargo_logs(self):
        names = ["rustc", "rust-std", "rust-src", "cargo"]
        log_dir = self.work / "logs"
        log_dir.mkdir()
        cargo_logs = {}
        for name in names:
            for stream in ("stdout", "stderr"):
                path = log_dir / f"install-rust-{name}.{stream}.log"
                path.write_bytes(f"cargo-stage {name} {stream} sentinel\n".encode())
                cargo_logs[path] = path.read_bytes()

        def fake_download(url, byte_count, digest, destination):
            destination.write_bytes(b"fixture archive")
            return {"bytes": byte_count, "sha256": digest}

        def fake_archive_member_root(archive, expected_root, *, current_managed, extraction):
            extracted = extraction / expected_root
            extracted.mkdir(parents=True)
            installer = extracted / "install.sh"
            name = archive.stem.removesuffix(".tar")
            installer.write_text(
                "#!/bin/sh\nprintf 'installed " + name + "\\n'\n"
                "printf 'stderr " + name + "\\n' >&2\n",
                encoding="utf-8")
            installer.chmod(0o755)
            return extracted, {"member_count": 1, "expanded_bytes": installer.stat().st_size}

        rust_pin = {
            "archives": [{"component": name, "bytes": 1,
                          "sha256": hashlib.sha256(name.encode()).hexdigest(),
                          "url": "https://fixture.invalid/" + name}
                         for name in names],
            "remove_installer_administrative_files": [],
        }
        components = self.work / "components"
        components.mkdir()
        supervisor = ci_sdk.Supervisor(self.work, self.output, self.python_root,
                                       {"PATH": "/usr/bin:/bin"})
        with (patch.object(ci_sdk, "host_identity",
                           return_value=("linux-x86_64", ci_sdk.HOST_TARGETS["linux-x86_64"])),
              patch.object(ci_sdk.ci_cargo, "download_verified", side_effect=fake_download),
              patch.object(ci_sdk, "_archive_member_root", side_effect=fake_archive_member_root),
              patch.object(ci_sdk, "_remove_exact_files", return_value=[])):
            rust_root, materials, receipts = ci_sdk._install_rust(
                {"rust": rust_pin}, {}, self.work, components, supervisor)

        self.assertEqual(rust_root, components / "rust")
        self.assertEqual([row["component"] for row in materials], names)
        self.assertEqual([row["component"] for row in receipts[0]["components"]], names)
        self.assertEqual([row["label"] for row in supervisor.commands],
                         ["sdk-install-rust-" + name for name in names])
        for name in names:
            row = next(row for row in supervisor.commands if row["label"].endswith(name))
            self.assertEqual(row["exit_code"], 0)
            self.assertIn("installed " + name,
                          (self.work / row["stdout_log"]).read_text())
            self.assertIn("stderr " + name,
                          (self.work / row["stderr_log"]).read_text())
        self.assertEqual({path: path.read_bytes() for path in cargo_logs}, cargo_logs)

    def test_native_cargo_must_match_frozen_bytes_and_hash(self):
        accepted = {"bytes": 99, "sha256": hashlib.sha256(b"cargo").hexdigest()}
        ci_sdk.require_cargo_match(dict(accepted), dict(accepted))
        altered = dict(accepted, sha256="0" * 64)
        with self.assertRaises(ValueError):
            ci_sdk.require_cargo_match(altered, accepted)
        with self.assertRaises(ValueError):
            ci_sdk.require_cargo_match(dict(accepted, bytes=100), accepted)

    def test_early_cargo_retirement_prunes_exact_roots_and_preserves_inputs(self):
        fixture = self._cargo_work_retirement_fixture()
        supervisor = fixture["supervisor"]
        managed_before = supervisor.managed_bytes()
        logs_before = supervisor.logs_bytes()
        supervisor.peak_workspace = managed_before + 1
        supervisor.peak_logs = logs_before + 1
        supervisor.peak_rss = 123456
        prior_commands = list(supervisor.commands)

        retirement, cargo_inventory = ci_sdk._retire_cargo_worktrees(
            self.work, self.output, fixture["cargo_root"], fixture["cargo_manifest"],
            fixture["report_bytes"], fixture["report_sha256"], supervisor)

        self.assertEqual(tuple(row["path"] for row in retirement["work_paths"]),
                         ci_sdk.CARGO_WORK_RETIRE_PATHS)
        self.assertTrue(all(row["status"] == "removed" for row in retirement["work_paths"]))
        self.assertTrue(all(not (self.work / relative).exists()
                            for relative in ci_sdk.CARGO_WORK_RETIRE_PATHS))
        self.assertEqual(ci_sdk.sha256(fixture["cargo_root"] / "bin/cargo"),
                         fixture["binary_sha256"])
        self.assertEqual(cargo_inventory["inventory_sha256"],
                         retirement["cargo_component"]["manifest_inventory_sha256"])
        self.assertEqual((self.output / "producer.json").read_bytes(), fixture["report_bytes"])
        self.assertEqual(ci_sdk.sha256(self.output / "producer.json"), fixture["report_sha256"])
        for path, payload in fixture["retained"].items():
            self.assertEqual(path.read_bytes(), payload, str(path.relative_to(self.temporary)))
        self.assertLess(retirement["accounting"]["managed_bytes_after"],
                        retirement["accounting"]["managed_bytes_before"])
        self.assertEqual(supervisor.peak_workspace, managed_before + 1)
        self.assertEqual(supervisor.peak_logs, logs_before + 1)
        self.assertEqual(supervisor.peak_rss, 123456)
        self.assertEqual(supervisor.commands, prior_commands)
        digest_payload = {key: value for key, value in retirement.items()
                          if key != "summary_sha256"}
        self.assertEqual(retirement["summary_sha256"],
                         hashlib.sha256(ci_sdk.canonical_json(digest_payload)).hexdigest())
        for row in retirement["work_paths"]:
            self.assertFalse(row["path"].startswith("/"))

    def test_early_cargo_retirement_rejects_altered_staged_binary_before_deletion(self):
        fixture = self._cargo_work_retirement_fixture()
        binary = fixture["cargo_root"] / "bin/cargo"
        binary.write_bytes(b"altered staged Cargo fixture\n")
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            ci_sdk._retire_cargo_worktrees(
                self.work, self.output, fixture["cargo_root"], fixture["cargo_manifest"],
                fixture["report_bytes"], fixture["report_sha256"], fixture["supervisor"])
        self.assertTrue(all((self.work / relative).is_dir()
                            for relative in ci_sdk.CARGO_WORK_RETIRE_PATHS))

    def test_early_cargo_retirement_preflights_all_roots_before_deletion(self):
        fixture = self._cargo_work_retirement_fixture()
        outside = self.temporary / "outside"
        outside.mkdir()
        marker = outside / "marker"
        marker.write_bytes(b"outside sentinel")
        last_root = self.work / ci_sdk.CARGO_WORK_RETIRE_PATHS[-1]
        shutil.rmtree(last_root)
        last_root.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "linked or not a directory"):
            ci_sdk._retire_cargo_worktrees(
                self.work, self.output, fixture["cargo_root"], fixture["cargo_manifest"],
                fixture["report_bytes"], fixture["report_sha256"], fixture["supervisor"])
        self.assertTrue((self.work / ci_sdk.CARGO_WORK_RETIRE_PATHS[0]).is_dir())
        self.assertEqual(marker.read_bytes(), b"outside sentinel")

    def test_early_cargo_retirement_rejects_nondirectory_before_deletion(self):
        fixture = self._cargo_work_retirement_fixture()
        last_root = self.work / ci_sdk.CARGO_WORK_RETIRE_PATHS[-1]
        shutil.rmtree(last_root)
        last_root.write_bytes(b"not a directory")
        with self.assertRaisesRegex(ValueError, "linked or not a directory"):
            ci_sdk._retire_cargo_worktrees(
                self.work, self.output, fixture["cargo_root"], fixture["cargo_manifest"],
                fixture["report_bytes"], fixture["report_sha256"], fixture["supervisor"])
        self.assertTrue((self.work / ci_sdk.CARGO_WORK_RETIRE_PATHS[0]).is_dir())

    def test_early_cargo_retirement_rejects_escaping_allowlist_before_deletion(self):
        fixture = self._cargo_work_retirement_fixture()
        outside = self.temporary / "outside"
        outside.mkdir()
        marker = outside / "marker"
        marker.write_bytes(b"outside sentinel")
        with patch.object(ci_sdk, "CARGO_WORK_RETIRE_PATHS",
                          ci_sdk.CARGO_WORK_RETIRE_PATHS + ("../outside",)):
            with self.assertRaisesRegex(ValueError, "unsafe relative path"):
                ci_sdk._retire_cargo_worktrees(
                    self.work, self.output, fixture["cargo_root"], fixture["cargo_manifest"],
                    fixture["report_bytes"], fixture["report_sha256"], fixture["supervisor"])
        self.assertTrue((self.work / ci_sdk.CARGO_WORK_RETIRE_PATHS[0]).is_dir())
        self.assertEqual(marker.read_bytes(), b"outside sentinel")

    def test_early_cargo_retirement_cannot_claim_a_failed_removal(self):
        fixture = self._cargo_work_retirement_fixture()
        root = (self.work / ci_sdk.CARGO_WORK_RETIRE_PATHS[0]).resolve()
        real_rmtree = shutil.rmtree

        def leave_first_root(path, *args, **kwargs):
            if Path(path) == root:
                return
            return real_rmtree(path, *args, **kwargs)

        with patch.object(ci_sdk.shutil, "rmtree", side_effect=leave_first_root):
            with self.assertRaisesRegex(RuntimeError, "remains after retirement"):
                ci_sdk._retire_cargo_worktrees(
                    self.work, self.output, fixture["cargo_root"], fixture["cargo_manifest"],
                    fixture["report_bytes"], fixture["report_sha256"], fixture["supervisor"])
        self.assertTrue(root.is_dir())
        self.assertTrue(all((self.work / relative).exists()
                            for relative in ci_sdk.CARGO_WORK_RETIRE_PATHS))

    def test_produce_stages_and_retires_cargo_before_rust_and_csdk(self):
        tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
        produce = next(node for node in tree.body
                       if isinstance(node, ast.FunctionDef) and node.name == "produce")
        calls = {}
        for node in ast.walk(produce):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                calls.setdefault(node.func.id, []).append(node.lineno)
        ordered = ["_component_rows_from_sdk", "_make_cargo_component",
                   "audit_cargo_linkage", "_retire_cargo_worktrees",
                   "_install_rust", "produce_portable_csdk"]
        self.assertTrue(all(name in calls for name in ordered))
        line_numbers = [min(calls[name]) for name in ordered]
        self.assertEqual(line_numbers, sorted(line_numbers))
        evidence_assignments = []
        for node in ast.walk(produce):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if (isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Name)
                    and target.value.id == "retirement_evidence"
                    and isinstance(target.slice, ast.Constant)
                    and target.slice.value == "cargo_work_retirement"):
                evidence_assignments.append(node.lineno)
        self.assertEqual(len(evidence_assignments), 1)
        self.assertLess(min(calls["_retire_cargo_worktrees"]), evidence_assignments[0])
        self.assertLess(evidence_assignments[0], min(calls["produce_portable_csdk"]))

    def _main_argv(self):
        return [
            "--work", str((self.temporary / "main-work").resolve()),
            "--output", str(self.output.resolve()),
            "--inputs", str((self.temporary / "inputs.json").resolve()),
            "--cargo-inputs", str((self.temporary / "cargo-inputs.json").resolve()),
            "--resources", str((self.temporary / "resources.json").resolve()),
            "--python-bootstrap-root", str((self.temporary / "python-bootstrap").resolve()),
        ]

    def test_main_failure_receipt_preserves_verified_cargo_retirement(self):
        fixture = self._cargo_work_retirement_fixture()
        retirement, _ = ci_sdk._retire_cargo_worktrees(
            self.work, self.output, fixture["cargo_root"], fixture["cargo_manifest"],
            fixture["report_bytes"], fixture["report_sha256"], fixture["supervisor"])

        def fail_during_csdk(args, *, retirement_evidence):
            retirement_evidence["cargo_work_retirement"] = retirement
            raise RuntimeError("simulated portable C-SDK timeout")

        with patch.object(ci_sdk, "produce", side_effect=fail_during_csdk):
            self.assertEqual(ci_sdk.main(self._main_argv()), 1)

        record = ci_sdk.read_json(self.output / "sdk-producer.json")
        self.assertEqual(record["status"], "FAILED")
        self.assertEqual(record["cargo_work_retirement"], retirement)
        self.assertEqual(record["cargo_work_retirement"]["summary_sha256"],
                         retirement["summary_sha256"])
        self.assertEqual(record["claim"],
                         "Failed hosted SDK candidate attempt; no guest, R1 acceptance or publication claim.")

    def test_main_pre_retirement_failure_does_not_claim_retirement(self):
        stale_record = {
            "schema": ci_sdk.RECEIPT_SCHEMA, "status": "PRODUCED",
            "cargo_work_retirement": {"status": "stale prior retirement"},
        }
        (self.output / "sdk-producer.json").write_bytes(ci_sdk.canonical_json(stale_record))

        def fail_before_retirement(args, *, retirement_evidence):
            raise RuntimeError("simulated pre-retirement failure")

        with patch.object(ci_sdk, "produce", side_effect=fail_before_retirement):
            self.assertEqual(ci_sdk.main(self._main_argv()), 1)

        record = ci_sdk.read_json(self.output / "sdk-producer.json")
        self.assertEqual(record["status"], "FAILED")
        self.assertNotIn("cargo_work_retirement", record)

    def test_main_success_receipt_is_unchanged_by_retirement_evidence_channel(self):
        success_bytes = b'{"schema":"fixture","status":"SUCCESS"}\n'
        observed_evidence = {}

        def succeed(args, *, retirement_evidence):
            observed_evidence.update(retirement_evidence)
            (args.output / "sdk-producer.json").write_bytes(success_bytes)
            return {"status": "SUCCESS"}

        with patch.object(ci_sdk, "produce", side_effect=succeed):
            self.assertEqual(ci_sdk.main(self._main_argv()), 0)

        self.assertEqual(observed_evidence, {})
        self.assertEqual((self.output / "sdk-producer.json").read_bytes(), success_bytes)

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
