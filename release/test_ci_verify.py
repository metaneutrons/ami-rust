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
        reference = {"hosts": {host: {name: {"AMIRUST": {"bytes": len(raw), "sha256": sha(raw)}}
                                     for name, raw in payloads.items()}}}
        sdk = {"manifest_sha256": sdk_digest, "manifest": {"version": "0.1.0"},
               "component_info": {name: {"manifest": {"fixture": name}} for name in components}}
        supervisor = SimpleNamespace(work=self.work, env={}, check_limits=lambda label: None)
        self.recipe_calls = []

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
                raw = payloads[variant_order[index - 3]] if index < 8 else b"hello-native"
                target = consumer / build_name / "artifacts"
                target.mkdir(parents=True)
                (target / "AMIRUST").write_bytes(raw)
            return {"exit_code": 0}, json.dumps(result), ""

        def receipt(path, host, expected, supervisor, label):
            artifact = path / "artifacts/AMIRUST"
            raw = artifact.read_bytes()
            return {"receipt_sha256": "c" * 64, "AMIRUST_path": str(artifact),
                    "canonical_artifacts": expected or {"AMIRUST": {"bytes": len(raw), "sha256": sha(raw)}}}

        with mock.patch.object(ci_verify, "_run_recipe_line", side_effect=execute), \
                mock.patch.object(ci_verify, "_build_receipt", side_effect=receipt), \
                mock.patch.object(ci_verify, "_copy_components_to_consumers",
                                  return_value=[components, components]), \
                mock.patch.object(ci_verify.ci_sdk, "verify_component", return_value={"fixture": "unchanged"}):
            return ci_verify._install_and_run_recipe(
                bundle, self.work, output, python, supervisor, host, sdk, components, reference, commands)

    def test_complete_recipe_passes_project_context_and_keeps_receipts_per_root(self):
        result = self._exercise_complete_install_recipe()
        self.assertEqual(set(self.recipe_calls), {(root, i) for root in ("absolute-a", "absolute-b")
                                                 for i in range(12)})
        self.assertEqual(len(self.recipe_calls), 24)
        self.assertEqual(len(result["retained_native"]), 5)
        for root, digest in (("absolute-a", "a" * 64), ("absolute-b", "b" * 64)):
            lock = next(row for row in result["commands"][root] if row["recipe_index"] == 9)
            self.assertEqual(lock["result"]["receipt_sha256"], digest)
            self.assertTrue(result["uninstall"][root]["selected_prefix_absent"])

    def test_complete_recipe_rejects_new_project_from_different_sdk(self):
        with self.assertRaisesRegex(ValueError, "unexpected package"):
            self._exercise_complete_install_recipe(corrupt="manifest")
        self.assertNotIn(("absolute-a", 9), self.recipe_calls)

    def test_complete_recipe_rejects_new_project_lock_with_wrong_install_receipt(self):
        with self.assertRaisesRegex(ValueError, "does not bind the installed SDK and receipt"):
            self._exercise_complete_install_recipe(corrupt="receipt")
        self.assertNotIn(("absolute-a", 10), self.recipe_calls)

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
        supervisor = SimpleNamespace(commands=[], checkout_bytes=0, managed_bytes=lambda: 0, check_limits=lambda label: None)
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
            result = ci_verify.bootstrap_tools(self.work, output, bootstrap, source_commit=source)
        self.assertEqual(result["status"], "PINNED_VERIFIER_TOOLS_READY")
        self.assertEqual(export.read_bytes(), b"unrelated file\n")

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
        manifest = {"version": "0.1.0", "assets": asset_rows}
        write_json(bundle / "release.json", manifest)
        manifest_sha = ci_verify.sha256(bundle / "release.json")
        policy = {"workflow_sha": "b" * 40, "source_sha": "a" * 40}
        subjects = sorted(("release.json", "sdk.tar.xz", "SHAUTIL"))
        auth = {"schema": "ami-rust-publisher-verification-v2", "verified": True,
                "repository": "metaneutrons/ami-rust", "workflow": ".github/workflows/sdk-qualify.yml",
                "workflowSha": policy["workflow_sha"], "sourceSha": policy["source_sha"],
                "sourceRef": "refs/heads/main", "manifestSha256": manifest_sha,
                "attestedSubjects": subjects, "cosignSubjects": subjects,
                "manifestBoundAssets": sorted(wanted | set(subjects)),
                "workflowRuns": [{"hostProfile": "linux-x86_64"}]}
        result = {"status": "verified", "release_manifest_sha256": manifest_sha,
                  "version": "0.1.0", "host": "linux-x86_64", "authentication": auth}
        ci_verify._validate_trusted_consumer_assets(bundle, result, policy, trusted_source)
        for host in ci_verify.HOSTS:
            result["host"] = host
            auth["workflowRuns"] = [{"hostProfile": host}]
            ci_verify._validate_trusted_consumer_assets(bundle, result, policy, trusted_source)
            other = next(h for h in ci_verify.HOSTS if h != host)
            auth["workflowRuns"] = [{"hostProfile": other}]
            with self.assertRaisesRegex(ValueError, "authentication report differs"):
                ci_verify._validate_trusted_consumer_assets(bundle, result, policy, trusted_source)
        auth["workflowRuns"] = [{"hostProfile": host} for host in ci_verify.HOSTS]
        with self.assertRaisesRegex(ValueError, "authentication report differs"):
            ci_verify._validate_trusted_consumer_assets(bundle, result, policy, trusted_source)
        auth["workflowRuns"] = [{"hostProfile": result["host"]}]
        (bundle / "new_project.py").write_bytes(b"changed after authentication")
        with self.assertRaisesRegex(ValueError, "differs from protected source pin"):
            ci_verify._validate_trusted_consumer_assets(bundle, result, policy, trusted_source)

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
