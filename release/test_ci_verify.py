"""Synthetic bounded fixtures for hosted consumer verification.

These tests exercise routing and fail-closed control flow only. They do not
fabricate or claim GH attestation, Cosign, Fulcio, or publisher signatures.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import stat
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock
import zipfile

SCRIPT = Path(__file__).resolve().with_name("ci_verify.py")
SPEC = importlib.util.spec_from_file_location("_test_ci_verify", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load adjacent ci_verify.py fixture target")
ci_verify = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ci_verify
SPEC.loader.exec_module(ci_verify)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def write_json(path: Path, value: object) -> bytes:
    raw = ci_verify.canonical_json(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    return raw


class HostedConsumerVerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ci-verify-fixture-")
        self.root = Path(self.temp.name).resolve()
        self.work = self.root / "work"
        self.work.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def _exercise_complete_install_recipe(self, corrupt=None):
        """Exercise the real two-root coordinator through project lock and uninstall."""
        host = "linux-x86_64"
        sdk_digest = "d" * 64
        components = {name: self.work / "components" / name for name in
                      ("rust", "cargo", "toolchain", "collector", "csdk", "vendor")}
        for path in components.values():
            path.mkdir(parents=True)
        first = self.work / "consumers" / "absolute-a"
        first.mkdir(parents=True)
        python = self.root / "python"
        python.write_bytes(b"fixture interpreter")
        write_json(first / "selection.json", {
            "python": str(python.resolve()),
            "components": {name: str(path.resolve()) for name, path in components.items()}})
        bundle = self.work / "candidate"
        write_json(bundle / "release.json", {"fixture": "authenticated elsewhere"})
        output = self.root / "output"
        output.mkdir()
        commands = ["recipe-" + str(i) for i in range(12)]
        variant_order = ("sha256sum", "minimal-noalloc", "minimal-alloc", "qualification", "dependencies")
        build_names = ("utility-build", "minimal-noalloc-build", "minimal-alloc-build",
                       "qualification-build", "dependencies-build")
        payloads = {name: ("native-" + name).encode() for name in variant_order}
        archive_payloads = {crate: ("raw-archive-" + crate).encode()
                            for crate in ci_verify.ci_sdk.METADATA_CRATES}
        archive_names = {crate: "target/release/deps/lib" + crate + "-" + sha(raw)[:16] + ".rlib"
                         for crate, raw in archive_payloads.items()}
        canonical_by_variant = {
            name: {"AMIRUST": {"bytes": len(raw), "sha256": sha(raw)}}
            for name, raw in payloads.items()}
        canonical_by_variant["dependencies"].update({
            archive_names[crate]: {"bytes": len(raw), "sha256": sha(raw)}
            for crate, raw in archive_payloads.items()})
        reference = {"hosts": {host: canonical_by_variant}}
        sdk = {"manifest_sha256": sdk_digest,
               "manifest": {"version": "0.1.0", "source_identity": "4" * 40},
               "component_info": {name: {"manifest": {"fixture": name}} for name in components}}
        supervisor = SimpleNamespace(work=self.work, env={}, check_limits=lambda label: None)
        self.recipe_calls = []
        self.probe_calls = []

        def compile_companion(**kwargs):
            self.assertEqual(kwargs["consumer"], first)
            self.assertEqual(kwargs["components"], components)
            self.assertEqual(set(self.recipe_calls), {(root, i)
                for root in ("absolute-a", "absolute-b") for i in range(11)})
            self.assertTrue((first / "sdk-0.1.0").is_dir())
            self.probe_calls.append("compile")
            if corrupt == "compile-probe":
                raise ValueError("synthetic compile companion failure")
            return {"status": "PASS_COMPILE_CONTRACT_PROBES_ONLY", "host": host,
                    "candidate": {"sdk_files": {"manifest": {"sha256": sdk_digest}}},
                    "fixture_only": True}

        def selection_companion(**kwargs):
            self.assertEqual(self.probe_calls, ["compile"])
            self.assertEqual(kwargs["consumer"], first)
            self.assertTrue((first / "sdk-0.1.0").is_dir())
            self.probe_calls.append("selection")
            return {"status": "PASS_SELECTION_CONTRACT_PROBES_ONLY", "host": host,
                    "candidate": {"sdk_manifest_sha256":
                        "f" * 64 if corrupt == "selection-probe-binding" else sdk_digest},
                    "fixture_only": True}

        def execute(supervisor, env, consumer, line, label):
            index = commands.index(line)
            self.recipe_calls.append((consumer.name, index))
            receipt = ("a" if consumer.name == "absolute-a" else "b") * 64
            result = {"host": host, "sdk_manifest_sha256": sdk_digest, "receipt_sha256": receipt}
            if index == 0:
                result.update(status="verified", qualification_only=False)
            elif index == 1:
                (consumer / "sdk-0.1.0").mkdir()
                (consumer / "receipt.sha256").write_text(receipt + "\n")
                result.update(status="installed", version="0.1.0", qualification_only=False,
                              release_manifest_sha256=sha((bundle / "release.json").read_bytes()))
                if corrupt == "missing-install-host":
                    result.pop("host")
                elif corrupt == "wrong-install-host":
                    result["host"] = "macos-aarch64"
            elif index in (2, 9):
                result["status"] = "locked"
                if index == 9 and corrupt == "receipt":
                    result["receipt_sha256"] = "f" * 64
            elif index == 8:
                project = consumer / "hello-aros"
                project.mkdir()
                (project / "Cargo.toml").write_text('[package]\nname="hello-aros"\n')
                result.update(package="hello-aros", project=str(project))
                if corrupt == "manifest":
                    result["sdk_manifest_sha256"] = "e" * 64
            elif index == 11:
                shutil.rmtree(consumer / "sdk-0.1.0")
                result.update(status="uninstalled", version="0.1.0")
            else:
                build_name = build_names[index - 3] if index < 8 else "hello-build"
                variant = variant_order[index - 3] if index < 8 else None
                raw = payloads[variant] if variant is not None else b"hello-native"
                target = consumer / build_name / "artifacts"
                target.mkdir(parents=True)
                (target / "AMIRUST").write_bytes(raw)
                if variant == "dependencies":
                    for crate, archive_raw in archive_payloads.items():
                        if corrupt == "metadata-data" and consumer.name == "absolute-b" and crate == "serde":
                            archive_raw = b"changed-second-root-serde"
                        archive_path = target.joinpath(*Path(archive_names[crate]).parts)
                        archive_path.parent.mkdir(parents=True, exist_ok=True)
                        archive_path.write_bytes(archive_raw)
            return {"exit_code": 0}, json.dumps(result), ""

        def receipt(path, host, expected, supervisor, label, *, output=None,
                    failure_binding=None):
            artifact = path / "artifacts/AMIRUST"
            raw = artifact.read_bytes()
            canonical = expected or {"AMIRUST": {"bytes": len(raw), "sha256": sha(raw)}}
            if corrupt == "second-receipt" and path.name == "dependencies-build" and path.parent.name == "absolute-b":
                canonical = {**canonical, "AMIRUST": {"bytes": len(raw), "sha256": "f" * 64}}
            return {"receipt_sha256": "c" * 64, "AMIRUST_path": str(artifact),
                    "canonical_artifacts": canonical, "reference_match": expected is not None}

        with mock.patch.object(ci_verify, "_run_recipe_line", side_effect=execute), \
                mock.patch.object(ci_verify, "_build_receipt", side_effect=receipt), \
                mock.patch.object(ci_verify, "_copy_components_to_consumers",
                                  return_value=[components, components]), \
                mock.patch.object(ci_verify.ci_sdk, "verify_component", return_value={"fixture": "unchanged"}), \
                mock.patch.object(ci_verify.contract_probes, "qualify_compile_contract", side_effect=compile_companion), \
                mock.patch.object(ci_verify.selection_probes, "qualify_selection_contract", side_effect=selection_companion):
            return ci_verify._install_and_run_recipe(
                bundle, self.work, output, python, supervisor, host, sdk, components, reference, commands)

    def test_compile_companion_failure_stops_before_uninstall(self):
        with self.assertRaisesRegex(ValueError, "synthetic compile companion failure"):
            self._exercise_complete_install_recipe(corrupt="compile-probe")
        self.assertFalse(any(index == 11 for _, index in self.recipe_calls))
        self.assertEqual(self.probe_calls, ["compile"])
        self.assertTrue((self.work / "consumers/absolute-a/sdk-0.1.0").is_dir())

    def test_selection_companion_wrong_candidate_stops_before_uninstall(self):
        with self.assertRaisesRegex(ValueError, "selection contract probes did not bind"):
            self._exercise_complete_install_recipe(corrupt="selection-probe-binding")
        self.assertFalse(any(index == 11 for _, index in self.recipe_calls))
        self.assertEqual(self.probe_calls, ["compile", "selection"])
        self.assertTrue((self.work / "consumers/absolute-a/sdk-0.1.0").is_dir())

    def test_complete_recipe_passes_project_context_and_keeps_receipts_per_root(self):
        result = self._exercise_complete_install_recipe()
        self.assertEqual(set(self.recipe_calls), {(root, i) for root in ("absolute-a", "absolute-b")
                                                 for i in range(12)})
        self.assertEqual(len(self.recipe_calls), 24)
        self.assertEqual(self.probe_calls, ["compile", "selection"])
        self.assertEqual(result["final_contract_probes"]["root"], "absolute-a")
        self.assertTrue(result["final_contract_probes"]["compile"]["fixture_only"])
        self.assertFalse(result["final_contract_probes"]["r1_acceptance"])
        self.assertEqual(len(result["retained_native"]), 5)
        self.assertEqual(len(result["retained_metadata"]), 6)
        expected_paths = {f"metadata/{root}/{crate}.rlib"
                          for root in ("absolute-a", "absolute-b")
                          for crate in ci_verify.ci_sdk.METADATA_CRATES}
        self.assertEqual({row["path"] for row in result["retained_metadata"]}, expected_paths)
        self.assertEqual(len({(self.root / "output" / row["path"]).stat().st_ino
                              for row in result["retained_metadata"]}), 6)
        for root in ("absolute-a", "absolute-b"):
            dependency = next(row for row in result["commands"][root]
                              if row["recipe_index"] == 7)
            canonical = dependency["canonical_artifacts"]
            canonical_digest = sha(ci_verify.canonical_json(canonical))
            for retained in (row for row in result["retained_metadata"] if row["root"] == root):
                self.assertEqual(retained["build_receipt_sha256"],
                                 dependency["build_receipt_sha256"])
                self.assertEqual(retained["canonical_artifacts_sha256"], canonical_digest)
                self.assertEqual(retained["canonical_artifact"],
                                 canonical[retained["canonical_path"]])
        for row in result["retained_metadata"]:
            retained = self.root / "output" / row["path"]
            self.assertEqual(retained.stat().st_size, row["bytes"])
            self.assertEqual(sha(retained.read_bytes()), row["sha256"])
            self.assertEqual(row["canonical_artifact"],
                             {"bytes": row["bytes"], "sha256": row["sha256"]})
            self.assertEqual(row["host"], "linux-x86_64")
            self.assertEqual(row["source_sdk_identity"], "4" * 40)
            self.assertEqual(row["sdk_manifest_sha256"], "d" * 64)
            self.assertEqual(row["build_receipt_sha256"], "c" * 64)
            self.assertTrue(row["reference_match"])
        for root, digest in (("absolute-a", "a" * 64), ("absolute-b", "b" * 64)):
            lock = next(row for row in result["commands"][root] if row["recipe_index"] == 9)
            self.assertEqual(lock["result"]["receipt_sha256"], digest)
            self.assertTrue(result["uninstall"][root]["selected_prefix_absent"])

    def test_complete_recipe_rejects_install_result_for_another_host(self):
        with self.assertRaisesRegex(ValueError,
                                   "production installation result differs from the authenticated candidate"):
            self._exercise_complete_install_recipe(corrupt="wrong-install-host")
        self.assertIn(("absolute-a", 1), self.recipe_calls)
        self.assertNotIn(("absolute-a", 2), self.recipe_calls)
        self.assertFalse(any(index >= 3 for _root, index in self.recipe_calls))

    def test_complete_recipe_rejects_install_result_without_host(self):
        with self.assertRaisesRegex(ValueError,
                                   "production installation result differs from the authenticated candidate"):
            self._exercise_complete_install_recipe(corrupt="missing-install-host")
        self.assertIn(("absolute-a", 1), self.recipe_calls)
        self.assertNotIn(("absolute-a", 2), self.recipe_calls)
        self.assertFalse(any(index >= 3 for _root, index in self.recipe_calls))

    def test_complete_recipe_rejects_new_project_from_different_sdk(self):
        with self.assertRaisesRegex(ValueError, "unexpected package"):
            self._exercise_complete_install_recipe(corrupt="manifest")
        self.assertNotIn(("absolute-a", 9), self.recipe_calls)

    def test_complete_recipe_rejects_new_project_lock_with_wrong_install_receipt(self):
        with self.assertRaisesRegex(ValueError, "does not bind the installed SDK and receipt"):
            self._exercise_complete_install_recipe(corrupt="receipt")
        self.assertNotIn(("absolute-a", 10), self.recipe_calls)

    def test_complete_recipe_rejects_changed_second_root_metadata_archive(self):
        with self.assertRaisesRegex(ValueError, "raw metadata archive differs from its canonical output:.*serde"):
            self._exercise_complete_install_recipe(corrupt="metadata-data")

    def test_complete_recipe_rejects_second_root_receipt_with_wrong_linked_input(self):
        with self.assertRaisesRegex(ValueError, "independently verified reference.*absolute-b/dependencies"):
            self._exercise_complete_install_recipe(corrupt="second-receipt")

    def test_metadata_archive_retention_rejects_ambiguous_missing_and_changed_inputs(self):
        for case, message in (("ambiguous", "exactly one"),
                              ("missing", "is missing"),
                              ("changed", "differs from its canonical output"),
                              ("linked", "differs from its canonical output")):
            with self.subTest(case=case):
                artifacts = self.work / ("artifacts-" + case)
                artifacts.mkdir()
                rows = {}
                for crate in ci_verify.ci_sdk.METADATA_CRATES:
                    raw = ("archive-" + crate).encode()
                    member = f"target/release/deps/lib{crate}-{sha(raw)[:16]}.rlib"
                    rows[member] = {"bytes": len(raw), "sha256": sha(raw)}
                    if not (case == "missing" and crate == "ed25519_dalek"):
                        path = artifacts.joinpath(*Path(member).parts)
                        path.parent.mkdir(parents=True, exist_ok=True)
                        if case == "linked" and crate == "serde":
                            target = path.with_name("serde-target.rlib")
                            target.write_bytes(raw)
                            path.symlink_to(target.name)
                        else:
                            path.write_bytes(b"changed" if case == "changed" and crate == "serde" else raw)
                if case == "ambiguous":
                    raw = b"second-serde-archive"
                    member = f"target/release/deps/libserde-{sha(raw)[:16]}.rlib"
                    rows[member] = {"bytes": len(raw), "sha256": sha(raw)}
                    path = artifacts.joinpath(*Path(member).parts)
                    path.write_bytes(raw)
                output = self.root / ("output-" + case)
                output.mkdir()
                with self.assertRaisesRegex(ValueError, message):
                    ci_verify._copy_consumer_metadata_archives(artifacts, rows, output, "absolute-a")

    def test_client_source_identity_uses_explicit_clean_publisher_checkout_without_ci(self):
        source, workflow = "1" * 40, "1" * 40
        with mock.patch.object(ci_verify, "_assert_source_clean") as clean, \
                mock.patch.object(ci_verify.subprocess, "check_output", return_value=
                                  "https://github.com/metaneutrons/ami-rust.git\n"), \
                mock.patch.object(ci_verify.ci_auth, "context", side_effect=AssertionError("not CI")):
            identity = ci_verify.consumer_source_identity(source, workflow)
        self.assertEqual(identity, {"source_sha": source, "workflow_sha": workflow})
        clean.assert_called_once_with(source)

    def test_client_source_rejects_missing_commit_wrong_origin_and_dirty_checkout(self):
        with mock.patch.object(ci_verify, "_assert_source_clean") as clean:
            for invalid in (None, "main", "1" * 39, "../candidate"):
                with self.assertRaisesRegex(ValueError, "exact trusted Git commits"):
                    ci_verify.consumer_source_identity(invalid)
            with self.assertRaisesRegex(ValueError, "must equal"):
                ci_verify.consumer_source_identity("1" * 40, "2" * 40)
            clean.assert_not_called()
        with mock.patch.object(ci_verify, "_assert_source_clean"), \
                mock.patch.object(ci_verify.subprocess, "check_output", return_value=
                                  "https://github.com/untrusted/ami-rust.git\n"):
            with self.assertRaisesRegex(ValueError, "designated publisher"):
                ci_verify.consumer_source_identity("1" * 40)
        with mock.patch.object(ci_verify, "_assert_source_clean", side_effect=ValueError("dirty source")):
            with self.assertRaisesRegex(ValueError, "dirty source"):
                ci_verify.consumer_source_identity("1" * 40)

    def test_ci_policy_still_requires_real_protected_context(self):
        with mock.patch.object(ci_verify.ci_auth, "context", side_effect=ValueError("protected context missing")):
            with self.assertRaisesRegex(ValueError, "protected context missing"):
                ci_verify._policy_from_source("1" * 40, {}, {}, self.work)

    def test_common_policy_binds_explicit_source_workflow_and_pinned_tools(self):
        (self.work / "trust").mkdir()
        roots = {name: {"path": str(self.root / (name + "-root")), "sha256": "3" * 64}
                 for name in ("gh", "cosign")}
        material = {"schema": "ami-rust-publisher-inputs-v1", "materials": []}
        pins = {name: {"binary_sha256": "4" * 64} for name in ("gh", "cosign")}
        identity = {"source_sha": "1" * 40, "workflow_sha": "2" * 40}
        with mock.patch.object(ci_verify, "_assert_source_clean") as clean, \
                mock.patch.object(ci_verify.ci_auth, "input_manifest", return_value=material), \
                mock.patch.object(ci_verify, "validate_tool_manifest", return_value=pins), \
                mock.patch.object(ci_verify.ci_auth, "context", side_effect=AssertionError("not CI")):
            path, policy = ci_verify._write_source_policy(identity, roots, self.work)
            self.assertEqual(ci_verify._write_source_policy(identity, roots, self.work, reuse=True), (path, policy))
            path.write_bytes(path.read_bytes().replace(b'"source_sha"', b'"tampered_x"'))
            with self.assertRaisesRegex(ValueError, "must be fresh"):
                ci_verify._write_source_policy(identity, roots, self.work, reuse=True)
            path.write_bytes(ci_verify.canonical_json(policy))
        self.assertEqual(clean.call_count, 3)
        self.assertEqual(policy["source_sha"], identity["source_sha"])
        self.assertEqual(policy["workflow_sha"], identity["workflow_sha"])
        self.assertEqual(policy["inputs_manifest_sha256"], sha(ci_verify.ci_auth.encoded(material)))
        self.assertEqual(policy["gh"]["sha256"], pins["gh"]["binary_sha256"])
        self.assertEqual(json.loads(path.read_text()), policy)
        with self.assertRaisesRegex(ValueError, "exact source and workflow commits"):
            ci_verify._write_source_policy({"source_sha": "main"}, roots, self.work)

    def _client_route(self, verified=True):
        bundle = self._candidate(self.root / "client-bundle")
        cargo = "cargo-macos-aarch64.tar.xz"
        (bundle / cargo).write_bytes(b"cargo fixture")
        with tarfile.open(bundle / "sdk.tar.xz", "w:xz"):
            pass
        release = json.loads((bundle / "release.json").read_text())
        release["assets"].append({"path": cargo, "bytes": 13, "sha256": sha(b"cargo fixture")})
        write_json(bundle / "release.json", release)
        output = self.root / "client-output"
        output.mkdir()
        write_json(output / "tool-bootstrap.json", {})
        bootstrap = self.root / "ami-rust-python-bootstrap"
        bootstrap.mkdir()
        python = bootstrap / "python"
        python.write_bytes(b"pinned python fixture")
        (self.work / "trust").mkdir()
        policy_path = self.work / "trust/publisher-policy.json"
        policy_path.write_bytes(b"external policy fixture")
        source = "1" * 40
        roots = {name: self.work / "component-staging" / name
                 for name in ("rust", "cargo", "toolchain", "collector", "csdk", "vendor")}
        profile = {"files": [{"path": "item", "bytes": 4, "sha256": sha(b"data")}], "symlinks": []}
        info = {name: {"manifest": profile} for name in roots}
        events = []

        def verify(*args, **kwargs):
            events.append("verify")
            return {}, json.dumps({"status": "verified" if verified else "refused", "host": "macos-aarch64",
                                   "qualification_only": False,
                                   "release_manifest_sha256": sha((bundle / "release.json").read_bytes())}), ""

        def extract(archive, destination, *args):
            events.append("extract")
            destination.mkdir(parents=True)
            return {"root": destination, "manifest": {"source_identity": source},
                    "manifest_sha256": "2" * 64}

        def provision(*args, **kwargs):
            events.append("provision")
            for root in roots.values():
                root.mkdir(parents=True)
                (root / "item").write_bytes(b"data")
            return {"component_roots": roots,
                    "component_inventories": {name: ci_verify.ci_sdk.verify_component(root, profile, name)
                                              for name, root in roots.items()}}

        supervisor = SimpleNamespace(commands=[], checkout_bytes=0, check_limits=lambda label: None)
        stack = ExitStack()
        for obj, name, value in (
            (ci_verify, "consumer_source_identity", {"source_sha": source, "workflow_sha": source}),
            (ci_verify, "_managed_roots", None), (ci_verify, "host_identity", "macos-aarch64"),
            (ci_verify.ci_sdk, "verify_python_bootstrap", (python, {})),
            (ci_verify, "_verify_tool_receipt", {"roots": {}}),
            (ci_verify, "_write_source_policy", (policy_path, {})),
            (ci_verify.ci_sdk, "Supervisor", supervisor),
            (ci_verify.ci_sdk, "read_normative", ({}, {}, {})),
            (ci_verify, "_recheck_capacity", {}),
            (ci_verify.ci_sdk, "validate_resource_policy", {}),
            (ci_verify, "_validate_trusted_consumer_assets", None),
            (ci_verify.ci_sdk, "_component_rows_from_sdk", info),
            (ci_verify, "_assert_source_clean", None),
        ):
            stack.enter_context(mock.patch.object(obj, name, return_value=value))
        stack.enter_context(mock.patch.object(ci_verify, "_run_supervised", side_effect=verify))
        stack.enter_context(mock.patch.object(ci_verify.ci_sdk, "_extract_sdk_archive", side_effect=extract))
        provider = stack.enter_context(mock.patch.object(ci_verify.consumer_inputs, "provision_inputs", side_effect=provision))
        return stack, bundle, output, bootstrap, source, roots, events, provider

    def test_preparation_refuses_bad_verification_before_sdk_extraction_or_provisioning(self):
        stack, bundle, output, bootstrap, source, roots, events, provider = self._client_route(verified=False)
        with stack:
            with self.assertRaisesRegex(ValueError, "unexpected result"):
                ci_verify.prepare_consumer_inputs(bundle, self.work, output, bootstrap, source,
                                                 None, self.root / "selection.json")
        self.assertEqual(events, ["verify"])
        provider.assert_not_called()
        self.assertFalse((self.work / "component-staging").exists())
        self.assertFalse((self.root / "selection.json").exists())

    def test_prepared_inputs_recheck_all_six_roots_without_replacement_or_receipt_change(self):
        stack, bundle, output, bootstrap, source, roots, events, provider = self._client_route()
        selection = self.root / "selection.json"
        with stack:
            result = ci_verify.prepare_consumer_inputs(bundle, self.work, output, bootstrap, source, None, selection)
            self.assertEqual(result["status"], "PREPARED_VERIFIED_INPUTS_NOT_INSTALLED")
            self.assertEqual(events, ["verify", "extract", "provision"])
            before = (selection.read_bytes(), (output / "consumer-preparation.json").read_bytes())
            checked = ci_verify.prepare_consumer_inputs(bundle, self.work, output, bootstrap, source,
                                                        None, selection, check_only=True)
            self.assertEqual(checked["status"], "VERIFIED_RETAINED_INPUTS")
            self.assertEqual(set(checked["components"]), set(roots))
            self.assertEqual(before, (selection.read_bytes(), (output / "consumer-preparation.json").read_bytes()))
            self.assertEqual(provider.call_count, 1)
            (roots["csdk"] / "item").write_bytes(b"bad!")
            with self.assertRaises(ValueError):
                ci_verify.prepare_consumer_inputs(bundle, self.work, output, bootstrap, source,
                                                  None, selection, check_only=True)
            self.assertEqual((roots["csdk"] / "item").read_bytes(), b"bad!")
            self.assertEqual(provider.call_count, 1)

    def test_preparation_rejects_selection_inside_the_candidate_before_verification(self):
        stack, bundle, output, bootstrap, source, roots, events, provider = self._client_route()
        with stack:
            with self.assertRaisesRegex(ValueError, "outside source, bundle"):
                ci_verify.prepare_consumer_inputs(bundle, self.work, output, bootstrap, source,
                                                  None, bundle / "selection.json")
        self.assertEqual(events, [])
        provider.assert_not_called()

    def test_preparation_rejects_selection_receipt_collision_before_verification(self):
        stack, bundle, output, bootstrap, source, roots, events, provider = self._client_route()
        with stack:
            with self.assertRaisesRegex(ValueError, "outside source, bundle"):
                ci_verify.prepare_consumer_inputs(bundle, self.work, output, bootstrap, source,
                                                  None, output / "consumer-preparation.json")
        self.assertEqual(events, [])
        provider.assert_not_called()

    def test_preparation_rejects_existing_receipt_before_provisioning(self):
        stack, bundle, output, bootstrap, source, roots, events, provider = self._client_route()
        receipt = output / "consumer-preparation.json"
        receipt.write_bytes(b"prior receipt")
        with stack:
            with self.assertRaisesRegex(ValueError, "receipt must be fresh"):
                ci_verify.prepare_consumer_inputs(bundle, self.work, output, bootstrap, source,
                                                  None, self.root / "selection.json")
        self.assertEqual(receipt.read_bytes(), b"prior receipt")
        self.assertEqual(events, [])
        provider.assert_not_called()

    def test_consumer_roots_are_fresh_and_reject_an_external_parent_link(self):
        first = ci_verify._create_consumer_roots(self.work)
        self.assertEqual(first.resolve().parent.parent, self.work)
        with self.assertRaises(FileExistsError):
            ci_verify._create_consumer_roots(self.work)
        work = self.root / "linked-work"
        work.mkdir()
        external = self.root / "unrelated-external"
        external.mkdir()
        marker = external / "marker"
        marker.write_bytes(b"unrelated")
        (work / "consumers").symlink_to(external, target_is_directory=True)
        with self.assertRaises(FileExistsError):
            ci_verify._create_consumer_roots(work)
        self.assertEqual([path.name for path in external.iterdir()], ["marker"])
        self.assertEqual(marker.read_bytes(), b"unrelated")

    def test_retained_check_needs_only_bounded_scratch_but_keeps_ram_and_policy_limits(self):
        resources = ci_verify.strict_json(ci_verify.ROOT / "release/ci-resources.json")
        scratch = ci_verify.MAX_ARCHIVE_EXPANDED + ci_verify.ci_sdk.MAX_LOG_BYTES + ci_verify.MAX_OUTPUT_BYTES
        with mock.patch.object(ci_verify.ci_sdk, "physical_memory_bytes", return_value=6 * 1024**3), \
                mock.patch.object(ci_verify.shutil, "disk_usage", return_value=SimpleNamespace(free=scratch)):
            result = ci_verify._recheck_capacity(resources, self.root)
            self.assertEqual(result["scratch_required_bytes"], 560 * 1024**2)
            self.assertFalse(result["cold_provisioning_admitted"])
        with mock.patch.object(ci_verify.ci_sdk, "physical_memory_bytes", return_value=6 * 1024**3), \
                mock.patch.object(ci_verify.shutil, "disk_usage", return_value=SimpleNamespace(free=scratch - 1)):
            with self.assertRaisesRegex(ValueError, "insufficient"):
                ci_verify._recheck_capacity(resources, self.root)
        with mock.patch.object(ci_verify.ci_sdk, "physical_memory_bytes", return_value=6 * 1024**3 - 1), \
                mock.patch.object(ci_verify.shutil, "disk_usage", return_value=SimpleNamespace(free=scratch)):
            with self.assertRaisesRegex(ValueError, "insufficient"):
                ci_verify._recheck_capacity(resources, self.root)
        changed = json.loads(json.dumps(resources))
        changed["build"]["seconds"] += 1
        with self.assertRaisesRegex(ValueError, "ceilings differ"):
            ci_verify._recheck_capacity(changed, self.root)

    def test_local_bootstrap_does_not_write_ambient_github_output(self):
        output = self.root / "tool-output"
        output.mkdir()
        bootstrap = self.root / "ami-rust-python-bootstrap"
        bootstrap.mkdir()
        python = bootstrap / "python"
        python.write_bytes(b"python fixture")
        export = self.root / "ambient-github-output"
        export.write_bytes(b"unrelated file\n")
        source = "1" * 40
        pins = {name: {"url": "https://github.com/pinned/" + name + ".tar.gz",
                       "bytes": 1, "sha256": sha(b"g"), "binary_bytes": 1,
                       "binary_sha256": sha(b"g"), "version": "fixture"}
                for name in ("gh", "cosign")}
        def download(url, size, digest, destination, **kwargs):
            destination.write_bytes(b"g")
            return {"sha256": digest}
        def extract(archive, host, pin, destination):
            destination.write_bytes(b"g")
            destination.chmod(0o700)
            return {"sha256": sha(b"g")}
        supervisor = SimpleNamespace(commands=[], checkout_bytes=0, limits={"log_bytes": ci_verify.ci_sdk.MAX_LOG_BYTES},
                                     managed_bytes=lambda: 0, check_limits=lambda label: None)
        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(ci_verify.os.environ, {"GITHUB_OUTPUT": str(export)}))
            for obj, name, value in (
                (ci_verify, "_managed_roots", None),
                (ci_verify, "consumer_source_identity", {"source_sha": source, "workflow_sha": source}),
                (ci_verify, "host_identity", "macos-aarch64"),
                (ci_verify.ci_sdk, "verify_python_bootstrap", (python, {})),
                (ci_verify, "validate_tool_manifest", pins),
                (ci_verify, "_trust_paths", {}),
                (ci_verify, "_tool_env", {}),
                (ci_verify.ci_sdk, "Supervisor", supervisor),
            ):
                stack.enter_context(mock.patch.object(obj, name, return_value=value))
            stack.enter_context(mock.patch.object(ci_verify.ci_cargo, "download_verified", side_effect=download))
            stack.enter_context(mock.patch.object(ci_verify, "_write_archive_member", side_effect=extract))
            stack.enter_context(mock.patch.object(ci_verify, "_version_text", side_effect=
                                                  ("gh version 2.102.0", "v3.1.3")))
            result = ci_verify.bootstrap_tools(self.work, output, bootstrap, source_commit=source,
                                               additional_input_bytes=1024**3, additional_log_bytes=123)
        self.assertEqual(supervisor.checkout_bytes, 1024**3)
        self.assertEqual(supervisor.limits["log_bytes"], ci_verify.ci_sdk.MAX_LOG_BYTES - 123)
        self.assertEqual(result["status"], "PINNED_VERIFIER_TOOLS_READY")
        self.assertEqual(export.read_bytes(), b"unrelated file\n")

    def test_verifier_bootstrap_refuses_invalid_external_charges_before_mutation(self):
        for kwargs in ({"additional_input_bytes": -1},
                       {"additional_input_bytes": ci_verify.ci_sdk.MAX_WORK_BYTES + 1},
                       {"additional_log_bytes": ci_verify.ci_sdk.MAX_LOG_BYTES + 1},
                       {"additional_log_bytes": True}):
            with self.subTest(kwargs=kwargs), mock.patch.object(ci_verify, "_managed_roots") as roots:
                with self.assertRaisesRegex(ValueError, "invalid external"):
                    ci_verify.bootstrap_tools(self.work, self.root / "unused-output",
                                               self.root / "unused-python", **kwargs)
                roots.assert_not_called()

    def test_preparation_recipe_matches_delivered_commands_and_rejects_an_edit(self):
        bundle = self.root / "recipe"
        bundle.mkdir()
        original = (ci_verify.ROOT / "release/bundle-assets/QUICKSTART.md").read_text()
        path = bundle / "QUICKSTART.md"
        path.write_text(original)
        self.assertEqual(ci_verify._preparation_commands(bundle), ci_verify.PREPARATION_COMMANDS)
        path.write_text(original.replace("check-inputs --bundle", "prepare-inputs --bundle"))
        with self.assertRaisesRegex(ValueError, "preparation and recheck"):
            ci_verify._preparation_commands(bundle)

    def test_tracked_tool_pins_route_to_both_supported_hosts(self):
        manifest = ci_verify.strict_json(ci_verify.ROOT / "release/ci-auth-tools.json")
        mac = ci_verify.validate_tool_manifest(manifest, "macos-aarch64")
        linux = ci_verify.validate_tool_manifest(manifest, "linux-x86_64")
        self.assertEqual(mac["gh"]["archive_member"], "gh_2.102.0_macOS_arm64/bin/gh")
        self.assertEqual(linux["gh"]["archive_member"], "gh_2.102.0_linux_amd64/bin/gh")
        self.assertEqual(mac["cosign"]["url"].rsplit("/", 1)[-1], "cosign-darwin-arm64")
        self.assertEqual(linux["cosign"]["url"].rsplit("/", 1)[-1], "cosign-linux-amd64")
        self.assertNotEqual(mac["gh"]["binary_sha256"], linux["gh"]["binary_sha256"])

    def test_tool_manifest_rejects_cross_host_or_root_substitution(self):
        manifest = ci_verify.strict_json(ci_verify.ROOT / "release/ci-auth-tools.json")
        broken = json.loads(json.dumps(manifest))
        broken["hosts"]["macos-aarch64"]["gh"]["archive_member"] = "gh_2.102.0_linux_amd64/bin/gh"
        with self.assertRaisesRegex(ValueError, "archive member"):
            ci_verify.validate_tool_manifest(broken, "macos-aarch64")
        broken = json.loads(json.dumps(manifest))
        broken["roots"]["cosign"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "trust root"):
            ci_verify.validate_tool_manifest(broken, "linux-x86_64")

    def test_linux_gh_extractor_reads_only_the_pinned_regular_member(self):
        payload = b"synthetic-gh-executable"
        pin = {"archive_member": "gh_2.102.0_linux_amd64/bin/gh",
               "binary_bytes": len(payload), "binary_sha256": sha(payload)}
        archive = self.work / "gh.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            for name in ("gh_2.102.0_linux_amd64/", "gh_2.102.0_linux_amd64/bin/"):
                info = tarfile.TarInfo(name)
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            info = tarfile.TarInfo(pin["archive_member"])
            info.size = len(payload)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(payload))
        target = self.work / "tools/gh"
        result = ci_verify._write_archive_member(archive, "linux-x86_64", pin, target)
        self.assertEqual(target.read_bytes(), payload)
        self.assertTrue(target.stat().st_mode & stat.S_IXUSR)
        self.assertEqual(result["sha256"], pin["binary_sha256"])

    def test_macos_gh_extractor_rejects_linked_archive_member(self):
        payload = b"synthetic-gh-executable"
        pin = {"archive_member": "gh_2.102.0_macOS_arm64/bin/gh",
               "binary_bytes": len(payload), "binary_sha256": sha(payload)}
        archive = self.work / "gh.zip"
        with zipfile.ZipFile(archive, "w") as bundle:
            info = zipfile.ZipInfo(pin["archive_member"])
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            bundle.writestr(info, "../outside")
        target = self.work / "tools/gh"
        with self.assertRaisesRegex(ValueError, "link or special"):
            ci_verify._write_archive_member(archive, "macos-aarch64", pin, target)
        self.assertFalse(target.exists())

    def _candidate(self, root: Path) -> Path:
        root.mkdir()
        payloads = {
            "sdk.tar.xz": b"sdk-fixture",
            "SHAUTIL": b"shautil-fixture",
            "install.py": b"fixture installer",
            "install_publisher.py": b"fixture publisher installer",
            "verify_publisher.py": b"fixture verifier",
            "new_project.py": b"fixture project helper",
            "QUICKSTART.md": b"# Fixture\n",
            ".auth/inputs.json": b"{}\n",
            ".auth/authentication.json": b"{}\n",
        }
        manifest = {"version": "0.1.0", "assets": [
            {"path": name, "bytes": len(payloads[name]), "sha256": sha(payloads[name])}
            for name in ("sdk.tar.xz", "SHAUTIL")], "qualification_only": False}
        payloads["release.json"] = ci_verify.canonical_json(manifest)
        for name, raw in payloads.items():
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        return root

    def test_all_five_tamper_probes_fail_before_any_install(self):
        bundle = self._candidate(self.root / "candidate")
        policy = write_json(self.work / "trust/policy.json", {"source_sha": "a" * 40})
        install_prefix = self.work / "consumers/absolute-a/sdk-0.1.0"
        calls = []

        def synthetic_verifier(candidate, policy_path, label):
            calls.append(label)
            sdk = candidate / "sdk.tar.xz"
            shautil = candidate / "SHAUTIL"
            accepted = (sdk.is_file() and shautil.is_file()
                        and sdk.read_bytes() == b"sdk-fixture"
                        and shautil.read_bytes() == b"shautil-fixture"
                        and json.loads((candidate / "release.json").read_text())["version"] == "0.1.0"
                        and json.loads(policy_path.read_text())["source_sha"] == "a" * 40)
            return {"accepted": accepted, "exit_code": 0 if accepted else 2,
                    "stop_reason": None, "stderr_sha256": sha(b"synthetic rejection")}

        rows = ci_verify.run_negative_probes(bundle, self.work / "trust/policy.json", self.work,
                                             install_prefix, synthetic_verifier)
        self.assertEqual([row["case"] for row in rows], [
            "mutated-sdk", "mutated-shautil", "missing-asset", "manifest-mismatch", "wrong-source-policy"])
        self.assertEqual(calls, ["negative-" + row["case"] for row in rows])
        self.assertFalse(install_prefix.exists())
        self.assertTrue(all(row["status"] == "REJECTED_BEFORE_INSTALL" for row in rows))

    def test_negative_probes_refuse_to_start_after_install_exists(self):
        bundle = self._candidate(self.root / "candidate")
        policy = write_json(self.work / "trust/policy.json", {"source_sha": "a" * 40})
        prefix = self.work / "consumers/installed"
        prefix.mkdir(parents=True)
        called = []
        with self.assertRaisesRegex(ValueError, "precede every installation"):
            ci_verify.run_negative_probes(bundle, policy, self.work, prefix,
                                          lambda *args: called.append(args))
        self.assertEqual(called, [])

    def test_signed_quickstart_must_be_the_exact_twelve_command_recipe(self):
        bundle = self.root / "bundle"
        bundle.mkdir()
        text = "# Recipe\n\n```sh\n" + "\n".join(ci_verify.EXPECTED_RECIPE) + "\n```\n"
        (bundle / "QUICKSTART.md").write_text(text)
        commands, digest = ci_verify._recipe_commands(bundle)
        self.assertEqual(tuple(commands), ci_verify.EXPECTED_RECIPE)
        self.assertEqual(digest, sha(text.encode()))
        (bundle / "QUICKSTART.md").write_text(text.replace("--offline", "--locked", 1))
        with self.assertRaisesRegex(ValueError, "exact reviewed 12-command"):
            ci_verify._recipe_commands(bundle)

    def test_shipped_quickstarts_match_all_producer_package_and_feature_selections(self):
        docs = ci_verify.ROOT / "docs/quickstart.md"
        signed_asset = ci_verify.ROOT / "release/bundle-assets/QUICKSTART.md"
        docs_raw = docs.read_bytes()
        self.assertTrue(docs_raw.endswith(signed_asset.read_bytes()))
        for name, raw in (("docs", docs_raw), ("signed-asset", signed_asset.read_bytes())):
            bundle = self.root / name
            bundle.mkdir()
            (bundle / "QUICKSTART.md").write_bytes(raw)
            commands, digest = ci_verify._recipe_commands(bundle)
            self.assertEqual(tuple(commands), ci_verify.EXPECTED_RECIPE)
            self.assertEqual(digest, sha(raw))
            ci_verify._validate_recipe_build_contract(commands)

    def test_recipe_feature_contract_rejects_noalloc_default_feature_drift(self):
        commands = list(ci_verify.EXPECTED_RECIPE)
        commands[4] = commands[4].replace(" --no-default-features", "")
        with self.assertRaisesRegex(ValueError, "minimal-noalloc"):
            ci_verify._validate_recipe_build_contract(commands)

    def test_recipe_feature_contract_rejects_package_and_alloc_feature_drift(self):
        package_changed = list(ci_verify.EXPECTED_RECIPE)
        package_changed[6] = package_changed[6].replace(
            "--package ami-rust-qualification", "--package ami-rust-dependencies")
        with self.assertRaisesRegex(ValueError, "qualification"):
            ci_verify._validate_recipe_build_contract(package_changed)

        alloc_changed = list(ci_verify.EXPECTED_RECIPE)
        alloc_changed[5] = alloc_changed[5].replace("--features alloc", "--features other")
        with self.assertRaisesRegex(ValueError, "minimal-alloc"):
            ci_verify._validate_recipe_build_contract(alloc_changed)

    def test_native_reference_mismatch_retains_bound_receipt_maps_and_diff(self):
        host = "linux-x86_64"
        build = self.work / "consumers/absolute-a/minimal-noalloc-build"
        build.mkdir(parents=True)
        output = self.root / "failure-output"
        output.mkdir()
        expected = {
            "AMIRUST": {"bytes": 10, "sha256": "a" * 64},
            "target/release/deps/libexpected-1.rlib": {"bytes": 20, "sha256": "b" * 64},
        }
        actual = {
            "AMIRUST": {"bytes": 11, "sha256": "c" * 64},
            "target/release/deps/libactual-2.rlib": {"bytes": 21, "sha256": "d" * 64},
        }
        receipt_path = build / "build-receipt.json"
        write_json(receipt_path, {"status": "PASS", "host": host,
                                  "sdk_manifest_sha256": "e" * 64,
                                  "forwarded_cargo_arguments": ["--no-default-features"],
                                  "canonical_artifacts": actual, "commands": []})
        supervisor = SimpleNamespace(work=self.work, check_limits=lambda _label: None)
        process = {"label": "consumer-absolute-a-minimal-noalloc-build",
                   "exit_code": 0, "stop_reason": None, "stdout_log": "logs/build.out"}
        binding = {
            "source_identity": "1" * 40,
            "sdk_manifest_sha256": "e" * 64,
            "candidate_release_manifest_sha256": "f" * 64,
            "variant": "minimal-noalloc", "consumer_root": "absolute-a",
            "recipe_index": 4, "signed_command": ci_verify.EXPECTED_RECIPE[4],
            "process": process,
        }
        with self.assertRaisesRegex(ValueError, "native canonical outputs differ"):
            ci_verify._build_receipt(build, host, expected, supervisor,
                                     "absolute-a/minimal-noalloc", output=output,
                                     failure_binding=binding)

        diagnostic_path = output / "native-canonical-mismatch.json"
        diagnostic = json.loads(diagnostic_path.read_text())
        self.assertEqual(diagnostic["status"], "FAILED_NATIVE_CANONICAL_REFERENCE_MISMATCH")
        self.assertEqual(diagnostic["binding"]["host"], host)
        self.assertEqual(diagnostic["binding"]["source_identity"], "1" * 40)
        self.assertEqual(diagnostic["binding"]["sdk_manifest_sha256"], "e" * 64)
        self.assertEqual(diagnostic["binding"]["variant"], "minimal-noalloc")
        self.assertEqual(diagnostic["binding"]["signed_command"], ci_verify.EXPECTED_RECIPE[4])
        self.assertEqual(diagnostic["binding"]["process"], process)
        self.assertEqual(diagnostic["build_receipt"]["sha256"], sha(receipt_path.read_bytes()))
        self.assertEqual(diagnostic["build_receipt"]["receipt"]["canonical_artifacts"], actual)
        self.assertEqual(diagnostic["expected_canonical_artifacts"], expected)
        self.assertEqual(diagnostic["actual_canonical_artifacts"], actual)
        self.assertEqual(diagnostic["diff"], {
            "missing_from_actual": ["target/release/deps/libexpected-1.rlib"],
            "unexpected_in_actual": ["target/release/deps/libactual-2.rlib"],
            "changed_rows": ["AMIRUST"],
        })
        self.assertFalse(diagnostic["claims"]["r1_accepted"])
        self.assertLessEqual(ci_verify.ci_sdk.directory_bytes(output)
                             + ci_verify.FAILURE_RECEIPT_RESERVE_BYTES,
                             ci_verify.MAX_OUTPUT_BYTES)
        self.assertEqual(stat.S_IMODE(diagnostic_path.stat().st_mode), 0o600)

    def test_native_mismatch_diagnostic_refuses_existing_link_and_output_overflow(self):
        output = self.root / "bounded-output"
        output.mkdir()
        external = self.root / "external-diagnostic-target"
        external.write_bytes(b"keep this file")
        diagnostic_path = output / "native-canonical-mismatch.json"
        diagnostic_path.symlink_to(external)
        receipt_path = self.work / "build-receipt.json"
        write_json(receipt_path, {"status": "PASS", "host": "linux-x86_64"})
        supervisor = SimpleNamespace(work=self.work)
        binding = {
            "source_identity": "1" * 40, "sdk_manifest_sha256": "e" * 64,
            "candidate_release_manifest_sha256": "f" * 64,
            "variant": "minimal-noalloc", "consumer_root": "absolute-a",
            "recipe_index": 4, "signed_command": ci_verify.EXPECTED_RECIPE[4],
            "process": {"label": "fixture"},
        }
        with self.assertRaisesRegex(ValueError, "already exists"):
            ci_verify._write_native_canonical_mismatch(
                output, receipt_path, {"status": "PASS"}, {"AMIRUST": {}}, {},
                "linux-x86_64", binding, supervisor)
        self.assertEqual(external.read_bytes(), b"keep this file")
        diagnostic_path.unlink()

        with mock.patch.object(ci_verify, "MAX_OUTPUT_BYTES", 2048), \
                mock.patch.object(ci_verify, "FAILURE_RECEIPT_RESERVE_BYTES", 128):
            with self.assertRaisesRegex(ValueError, "remaining 32 MiB output limit"):
                ci_verify._write_native_canonical_mismatch(
                    output, receipt_path, {"status": "PASS"},
                    {"x" * 4096: {"bytes": 1, "sha256": "a" * 64}}, {},
                    "linux-x86_64", binding, supervisor)
        self.assertFalse(diagnostic_path.exists())

    def test_failure_receipt_fits_exact_remaining_output_budget(self):
        output = self.root / "failure-receipt-output"
        output.mkdir()
        prior = output / "retained-evidence.bin"
        prior.write_bytes(b"preserve this evidence")
        error = ValueError("synthetic consumer failure")
        expected = {
            "schema": ci_verify.RESULT_SCHEMA, "status": "FAILED",
            "failed_stage": "fixture-stage", "error_type": "ValueError",
            "error": "synthetic consumer failure",
            "claims": {"publisher_release_acceptance": False, "r1_accepted": False,
                       "signed": False, "published": False},
            "preserved_work": True,
        }
        raw = ci_verify.canonical_json(expected)
        with mock.patch.object(ci_verify, "MAX_OUTPUT_BYTES",
                               len(prior.read_bytes()) + len(raw)):
            result = ci_verify._write_failure(output, error, "fixture-stage")
        receipt = output / "consumer-qualification.json"
        self.assertEqual(result, expected)
        self.assertEqual(receipt.read_bytes(), raw)
        self.assertEqual(prior.read_bytes(), b"preserve this evidence")
        self.assertEqual(ci_verify.ci_sdk.directory_bytes(output),
                         len(prior.read_bytes()) + len(raw))
        self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)

    def test_failure_receipt_refuses_one_byte_output_overflow_without_deleting_evidence(self):
        output = self.root / "failure-receipt-overflow"
        output.mkdir()
        prior = output / "retained-evidence.bin"
        prior_bytes = b"preserve this evidence"
        prior.write_bytes(prior_bytes)
        error = ValueError("synthetic consumer failure")
        expected = {
            "schema": ci_verify.RESULT_SCHEMA, "status": "FAILED",
            "failed_stage": "fixture-stage", "error_type": "ValueError",
            "error": "synthetic consumer failure",
            "claims": {"publisher_release_acceptance": False, "r1_accepted": False,
                       "signed": False, "published": False},
            "preserved_work": True,
        }
        raw = ci_verify.canonical_json(expected)
        stderr = io.StringIO()
        with mock.patch.object(ci_verify, "MAX_OUTPUT_BYTES",
                               len(prior_bytes) + len(raw) - 1), \
                mock.patch("sys.stderr", stderr):
            result = ci_verify._write_failure(output, error, "fixture-stage")
        self.assertIsNone(result)
        self.assertIn("would exceed the 32 MiB output limit", stderr.getvalue())
        self.assertEqual(prior.read_bytes(), prior_bytes)
        self.assertFalse((output / "consumer-qualification.json").exists())
        self.assertEqual(ci_verify.ci_sdk.directory_bytes(output), len(prior_bytes))

    def test_positive_verifier_report_binds_exact_protected_consumer_assets(self):
        wanted = {"install.py", "install_publisher.py", "verify_publisher.py",
                  "new_project.py", "QUICKSTART.md"}
        trusted_source = self.root / "trusted-source"
        static_rows = []
        source_payloads = {}
        for name in sorted(wanted):
            relative = "fixture-assets/" + name
            raw = ("synthetic trusted source: " + name + "\n").encode()
            source_payloads[name] = raw
            target = trusted_source / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            static_rows.append({"path": name, "source": relative, "bytes": len(raw),
                                "sha256": sha(raw)})
        write_json(trusted_source / "release/bundle-files.json",
                   {"schema": "ami-rust-bundle-files-v1", "files": static_rows})
        pins = {row["path"]: row for row in static_rows}
        bundle = self.root / "authenticated-candidate"
        bundle.mkdir()
        asset_rows = []
        for name in sorted(wanted):
            pin = pins[name]
            target = bundle / name
            target.write_bytes(source_payloads[name])
            asset_rows.append({"path": name, "bytes": pin["bytes"], "sha256": pin["sha256"]})
        policy = {"repository": "metaneutrons/ami-rust",
                  "workflow": ".github/workflows/sdk-qualify.yml",
                  "workflow_sha": "b" * 40, "source_sha": "a" * 40}
        producer = {"kind": "protected-github-actions", "repository": policy["repository"],
                    "workflow": policy["workflow"], "source_sha": policy["source_sha"],
                    "workflow_sha": policy["workflow_sha"], "run_id": 39089771746,
                    "run_attempt": 1,
                    "acceptance": "R1 acceptance and publication are separate gates"}
        manifest = {"schema": "ami-rust-release-v1", "version": "0.1.0",
                    "qualification_only": False, "assets": asset_rows,
                    "producer": producer}
        subjects = sorted(("release.json", "sdk.tar.xz", "SHAUTIL"))
        auth = {"schema": "ami-rust-publisher-verification-v2", "verified": True,
                "repository": policy["repository"], "workflow": policy["workflow"],
                "workflowSha": policy["workflow_sha"], "sourceSha": policy["source_sha"],
                "sourceRef": "refs/heads/main", "attestedSubjects": subjects,
                "cosignSubjects": subjects,
                "manifestBoundAssets": sorted(wanted | set(subjects)),
                "workflowRuns": [{"runId": producer["run_id"],
                                  "runAttempt": producer["run_attempt"],
                                  "hostProfile": "linux-x86_64"}]}
        result = {"status": "verified", "version": "0.1.0", "host": "linux-x86_64",
                  "authentication": auth}

        def bind_manifest():
            write_json(bundle / "release.json", manifest)
            manifest_sha = ci_verify.sha256(bundle / "release.json")
            result["release_manifest_sha256"] = manifest_sha
            auth["manifestSha256"] = manifest_sha

        def verify(expected_workflow_runs=None):
            ci_verify._validate_trusted_consumer_assets(
                bundle, result, policy, trusted_source,
                expected_workflow_runs=expected_workflow_runs)

        bind_manifest()
        verify()
        # Publisher and consumer are separate identities. A Linux publisher
        # run remains valid for a macOS consumer because its exact run tuple is
        # bound by both the signed release producer and verifier report.
        result["host"] = "macos-aarch64"
        verify()
        publisher_run = auth["workflowRuns"][0]
        verify(expected_workflow_runs=[publisher_run])
        for expected in (
                [{"runId": 1, "runAttempt": 1, "hostProfile": "linux-x86_64"}],
                [{"runId": producer["run_id"], "runAttempt": 2,
                  "hostProfile": "linux-x86_64"}],
                [{"runId": producer["run_id"], "runAttempt": 1,
                  "hostProfile": "macos-aarch64"}],
                [{"runId": True, "runAttempt": 1, "hostProfile": "linux-x86_64"}],
                [{"runId": producer["run_id"], "runAttempt": 1,
                  "hostProfile": "unknown-host"}],
        ):
            with self.subTest(expected_workflow_runs=expected):
                with self.assertRaisesRegex(ValueError, "authentication report differs"):
                    verify(expected_workflow_runs=expected)

        # Authentication must match the publisher run embedded in the
        # authenticated candidate, independent of consumer host.
        original_auth_row = auth["workflowRuns"][0]
        for row in (
                {"runId": producer["run_id"] + 1, "runAttempt": 1,
                 "hostProfile": "linux-x86_64"},
                {"runId": producer["run_id"], "runAttempt": 2,
                 "hostProfile": "linux-x86_64"},
                {"runId": producer["run_id"], "runAttempt": 1,
                 "hostProfile": "unknown-host"},
                {"runId": producer["run_id"], "runAttempt": 1,
                 "hostProfile": "linux-x86_64", "extra": True},
        ):
            with self.subTest(authenticated_workflow_run=row):
                auth["workflowRuns"] = [row]
                with self.assertRaisesRegex(ValueError, "authentication report differs"):
                    verify()
        auth["workflowRuns"] = [original_auth_row]

        # Reject any noncanonical or mismatched protected producer identity;
        # refresh manifest digests so each probe reaches this identity check.
        base_producer = dict(producer)
        changes = (
            {"kind": "local-unpublished-candidate"},
            {"repository": "attacker/repo"},
            {"workflow": ".github/workflows/other.yml"},
            {"source_sha": "c" * 40},
            {"workflow_sha": "d" * 40},
            {"run_id": producer["run_id"] + 1},
            {"run_attempt": 2},
            {"run_id": True},
            {"extra": "not canonical"},
        )
        for change in changes:
            with self.subTest(producer_change=change):
                producer.clear()
                producer.update(base_producer)
                producer.update(change)
                bind_manifest()
                with self.assertRaisesRegex(ValueError, "authentication report differs"):
                    verify()
        producer.clear()
        producer.update(base_producer)
        bind_manifest()
        result["host"] = "linux-x86_64"
        verify()
        (bundle / "new_project.py").write_bytes(b"changed after authentication")
        with self.assertRaisesRegex(ValueError, "differs from protected source pin"):
            verify()

    def test_cargo_extractor_verifies_exact_profile_and_archive_metadata(self):
        files = {"bin/cargo": b"cargo-binary", "producer.json": b'{"schema":"fixture"}\n'}
        profile = {"files": [{"path": name, "bytes": len(raw), "sha256": sha(raw)}
                             for name, raw in sorted(files.items())], "symlinks": []}
        archive = self.work / "cargo.tar.xz"
        with tarfile.open(archive, "w:xz", format=tarfile.USTAR_FORMAT) as tar:
            for name, raw in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.size = len(raw)
                info.mode = 0o755 if name == "bin/cargo" else 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 1791936000
                tar.addfile(info, io.BytesIO(raw))
        result = ci_verify._extract_flat_cargo(archive, self.work / "cargo-root", profile)
        self.assertEqual(result["entry_count"], 2)
        self.assertEqual((self.work / "cargo-root/bin/cargo").read_bytes(), files["bin/cargo"])

    def test_cargo_extractor_rejects_noncanonical_permissions(self):
        files = {"bin/cargo": b"cargo-binary", "producer.json": b'{"schema":"fixture"}\n'}
        profile = {"files": [{"path": name, "bytes": len(raw), "sha256": sha(raw)}
                             for name, raw in sorted(files.items())], "symlinks": []}
        archive = self.work / "cargo-noncanonical.tar.xz"
        with tarfile.open(archive, "w:xz", format=tarfile.USTAR_FORMAT) as tar:
            for name, raw in sorted(files.items()):
                info = tarfile.TarInfo(name)
                info.size = len(raw)
                info.mode = 0o700 if name == "bin/cargo" else 0o644
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = 1791936000
                tar.addfile(info, io.BytesIO(raw))
        with self.assertRaisesRegex(ValueError, "noncanonical metadata"):
            ci_verify._extract_flat_cargo(archive, self.work / "cargo-rejected", profile)
        self.assertFalse((self.work / "cargo-rejected").exists())


if __name__ == "__main__":
    unittest.main()
