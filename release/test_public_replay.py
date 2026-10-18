"""Offline orchestration fixtures for the public consumer replay driver."""
from __future__ import annotations

import ast
from contextlib import redirect_stderr
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("public_replay.py")
SPEC = importlib.util.spec_from_file_location("r1_public_replay_fixture_target", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
public_replay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(public_replay)
WORKFLOW = SCRIPT.parents[1] / ".github" / "workflows" / "public-replay.yml"


def _load_actual_ci_verify():
    path = SCRIPT.with_name("ci_verify.py")
    spec = importlib.util.spec_from_file_location("r1_public_replay_actual_ci_verify", path)
    if spec is None or spec.loader is None:
        raise AssertionError("actual pinned ci_verify.py could not be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _public_candidate_download_workflow_tree() -> ast.Module:
    """Parse the workflow's six-asset download block without executing network I/O."""
    lines = WORKFLOW.read_text(encoding="utf-8").splitlines()
    blocks = []
    for index, line in enumerate(lines):
        if "-I -B - <<'PYCODE'" not in line:
            continue
        indentation = len(line) - len(line.lstrip())
        end = next((position for position in range(index + 1, len(lines))
                    if lines[position] == " " * indentation + "PYCODE"), None)
        if end is None:
            raise AssertionError("workflow Python heredoc has no terminator")
        body = []
        for body_line in lines[index + 1:end]:
            if body_line.strip():
                if not body_line.startswith(" " * indentation):
                    raise AssertionError("workflow Python block escapes its YAML run body")
                body.append(body_line[indentation:])
            else:
                body.append("")
        blocks.append("\n".join(body) + "\n")

    for block in blocks:
        tree = ast.parse(block, filename=str(WORKFLOW))
        if any(isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == "names"
                       for target in node.targets)
               and isinstance(node.value, ast.Call)
               and isinstance(node.value.func, ast.Attribute)
               and node.value.func.attr == "asset_names"
               for node in tree.body):
            return tree
    raise AssertionError("public download Python block is missing stage.asset_names(tag)")


class FakeSupervisor:
    def __init__(self, work, output, python_root, env):
        self.work = work
        self.output = output
        self.python_root = python_root
        self.env = env
        self.checkout_bytes = 17
        self.peak_workspace = 23
        self.peak_rss = 29
        self.peak_logs = 31
        self.commands = []
        self.labels = []

    def check_limits(self, label):
        self.labels.append(label)


class FakeSDK:
    MAX_WORK_BYTES = 12 * 1024**3
    MAX_RSS_BYTES = 4 * 1024**3
    MAX_LOG_BYTES = 16 * 1024**2
    MAX_COMMAND_SECONDS = 1200

    def __init__(self, owner):
        self.owner = owner
        self.Supervisor = FakeSupervisor

    def verify_python_bootstrap(self, root, host):
        return Path("/pinned/python"), {
            "archive_sha256": "1" * 64,
            "runtime_sha256": "2" * 64,
        }

    def read_normative(self, inputs, resources, host):
        self.owner.events.append(("read_normative", host))
        return ({"native_reference": {"sha256": "3" * 64}}, {"fake": True}, {})

    def validate_resource_policy(self, resources, disk_path):
        self.owner.events.append(("capacity", str(disk_path)))
        return {"free_disk_bytes": 24 * 1024**3}

    def validate_native_reference(self, reference, inputs, expected_sha):
        return {"hosts": {"macos-aarch64": {}}}

    def read_json(self, path, maximum=None):
        return {"source_identity": self.owner.commit, "version": "0.1.0"}

    def _component_rows_from_sdk(self, sdk, host):
        return {name: {"manifest": {"files": [], "symlinks": []}}
                for name in self.owner.component_names}

    def verify_component(self, root, manifest, name):
        return {"name": name, "entry_count": 1, "inventory_sha256": name + "0" * 56}

    def directory_bytes(self, root):
        total = 0
        for path in Path(root).rglob("*"):
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if path.is_file() and not path.is_symlink():
                total += info.st_size
        return total


class FakeTrustedHelpers:
    HOSTS = ("macos-aarch64", "linux-x86_64")
    component_names = ("rust", "cargo", "toolchain", "collector", "csdk", "vendor")

    def __init__(self, source, commit, bundle_digest, *, candidate_version="0.1.0",
                 source_mismatch=False,
                 preparation_mismatch=False, recheck_mismatch=False):
        self.ROOT = Path(source)
        self.commit = commit
        self.bundle_digest = bundle_digest
        self.candidate_version = candidate_version
        self.source_mismatch = source_mismatch
        self.preparation_mismatch = preparation_mismatch
        self.recheck_mismatch = recheck_mismatch
        self.events = []
        self.ci_auth = types.SimpleNamespace(REPO="metaneutrons/ami-rust")
        self.ci_sdk = FakeSDK(self)
        self.MAX_OUTPUT_BYTES = 32 * 1024**2
        self.EXPECTED_PREPARE = "trusted prepare command supplied by signed QUICKSTART"
        self.EXPECTED_CHECK = "trusted check command supplied by signed QUICKSTART"
        self.EXPECTED_RECIPE = [f"signed recipe line {index}" for index in range(12)]
        self.tool_bytes = {"gh": b"pinned-gh", "cosign": b"pinned-cosign"}
        self.tool_pins = {
            "host": "macos-aarch64",
            **{name: {"bytes": 1, "binary_sha256": hashlib.sha256(data).hexdigest()}
               for name, data in self.tool_bytes.items()},
            "roots": {
                "gh": {"path": "release/trust/github-trusted-root.jsonl",
                       "bytes": 1, "sha256": "a" * 64},
                "cosign": {"path": "release/trust/sigstore-trusted-root.json",
                            "bytes": 1, "sha256": "b" * 64},
            },
        }
        self.preparation = None
        self.policy = {"inputs_manifest_sha256": "4" * 64}
        self.policy_sha = "5" * 64
        self.MAX_BUNDLE_BYTES = 32 * 1024**2
        self.expected_workflow_runs = None

    @staticmethod
    def canonical_json(value):
        return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()

    @staticmethod
    def sha256(path):
        return public_replay.sha256(Path(path))

    def consumer_source_identity(self, source_commit, workflow_commit=None):
        self.events.append(("source_identity", source_commit, workflow_commit))
        if self.source_mismatch:
            return {"source_sha": "f" * 40, "workflow_sha": "f" * 40}
        return {"source_sha": source_commit, "workflow_sha": workflow_commit or source_commit}

    def _candidate_inventory(self, bundle):
        self.events.append(("candidate_inventory", str(bundle)))
        path = Path(bundle) / "release.json"
        return [("release.json", path)], path.stat().st_size

    def _managed_roots(self, work, output, python_root):
        self.events.append(("managed_roots",))
        for path in (Path(work), Path(output)):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)

    def host_identity(self):
        return "macos-aarch64"

    def strict_json(self, path, maximum=1024 * 1024):
        path = Path(path)
        if path.name == "ci-auth-tools.json":
            return {"fake": "tool manifest"}
        if path.name == "release.json":
            self.events.append(("manifest_parse", str(path)))
            rows = [{"path": name, "bytes": 1, "sha256": "a" * 64}
                    for name in ("sdk.tar.xz", "SHAUTIL", "cargo-macos-aarch64.tar.xz",
                                 "install.py", "install_publisher.py", "verify_publisher.py",
                                 "new_project.py", "QUICKSTART.md")]
            return {"assets": rows, "qualification_only": False,
                    "version": self.candidate_version}
        raise AssertionError("unexpected JSON input: " + str(path))

    def validate_tool_manifest(self, manifest, host):
        return self.tool_pins

    def bootstrap_tools(self, work, output, python_root, *, source_commit, additional_input_bytes):
        self.events.append(("bootstrap_tools", source_commit, additional_input_bytes))
        work, output = Path(work), Path(output)
        (work / "tools").mkdir()
        (work / "trust").mkdir()
        for name, data in self.tool_bytes.items():
            path = work / "tools" / name
            path.write_bytes(data)
            path.chmod(0o700)
        (output / "tool-bootstrap.json").write_text("{}\n")

    def _verify_tool_receipt(self, work, output, host, manifest):
        self.events.append(("verify_tool_receipt",))
        return {
            "roots": {"gh": {"path": "gh-root"}, "cosign": {"path": "cosign-root"}},
            "tools": {name: {"sha256": self.tool_pins[name]["binary_sha256"]}
                      for name in self.tool_bytes},
        }

    def _write_source_policy(self, identity, roots, work):
        self.events.append(("write_source_policy", dict(identity)))
        path = Path(work) / "trust" / "publisher-policy.json"
        path.write_text("{}\n")
        return path, self.policy

    def _tool_env(self, work, python):
        return {"PATH": "/pinned/tools", "LANG": "C"}

    def _version_text(self, supervisor, path, arguments, label):
        self.events.append(("version", path.name, label))
        return "gh version 2.102.0" if path.name == "gh" else "cosign v3.1.3"

    def _copy_candidate(self, source, destination):
        self.events.append(("copy_candidate", str(source)))
        shutil.copytree(source, destination)
        total = sum(p.stat().st_size for p in Path(destination).rglob("*") if p.is_file())
        return {"file_count": 1, "bytes": total, "inventory_sha256": "6" * 64}

    def _run_supervised(self, supervisor, python, script, argv, *, cwd, label, timeout=300):
        self.events.append(("protected_verify", str(script), tuple(argv)))
        verified = {
            "status": "verified", "host": "macos-aarch64", "qualification_only": False,
            "release_manifest_sha256": self.bundle_digest, "version": self.candidate_version,
            "authentication": {"verified": True, "repository": self.ci_auth.REPO},
        }
        row = {"label": label, "exit_code": 0, "stop_reason": None}
        return row, json.dumps(verified), ""

    def _parse_command_result(self, stdout, expected_status, label):
        value = json.loads(stdout)
        if value.get("status") != expected_status:
            raise ValueError("unexpected fake command status: " + label)
        return value

    def _validate_trusted_consumer_assets(self, bundle, verified, policy, *, trusted_source,
                                          expected_workflow_runs=None):
        if Path(trusted_source) != self.ROOT:
            raise AssertionError("trusted consumer assets must come from the selected source checkout")
        self.expected_workflow_runs = expected_workflow_runs
        self.events.append(("validate_trusted_assets", str(trusted_source)))

    def run_negative_probes(self, bundle, policy_path, work, install_prefix, callback):
        self.events.append(("negative_probes",))
        return [{"accepted": False, "exit_code": 1}]

    def _preparation_commands(self, bundle):
        self.events.append(("preparation_commands",))
        return self.EXPECTED_PREPARE, self.EXPECTED_CHECK

    def _recipe_commands(self, bundle):
        self.events.append(("recipe_commands",))
        return list(self.EXPECTED_RECIPE), "7" * 64

    def _create_consumer_roots(self, work):
        root = Path(work) / "consumers"
        root.mkdir(mode=0o700)
        first = root / "absolute-a"
        first.mkdir(mode=0o700)
        return first

    def _run_recipe_line(self, supervisor, env, cwd, line, label):
        self.events.append(("recipe_line", line, label))
        if line == self.EXPECTED_PREPARE:
            sdk_manifest = Path(env["PREP"]) / "verified-source-sdk" / "contract" / "sdk.json"
            sdk_manifest.parent.mkdir(mode=0o700, parents=True)
            sdk_manifest.write_text('{"source_identity":"' + env["SOURCE_COMMIT"] + '"}\n')
            for name in self.component_names:
                (Path(env["PREP"]) / "component-staging" / name).mkdir(mode=0o700, parents=True)
            (Path(env["PREP_OUTPUT"]) / "consumer-preparation.json").write_text("{}\n")
            source_policy = {"source_sha": env["SOURCE_COMMIT"],
                             "workflow_sha": env["WORKFLOW_COMMIT"]}
            if self.preparation_mismatch:
                source_policy["source_sha"] = "f" * 40
            self.preparation = {
                "status": "PREPARED_VERIFIED_INPUTS_NOT_INSTALLED",
                "source_policy": source_policy,
                "release_manifest_sha256": self.bundle_digest,
                "sdk_manifest_sha256": self.sha256(sdk_manifest),
                "selection_sha256": "8" * 64,
                "policy_sha256": self.policy_sha,
                "provisioning": {"fixture": "controlled"},
            }
            return {}, json.dumps(self.preparation), ""
        if line == self.EXPECTED_CHECK:
            components = {name: self.ci_sdk.verify_component(
                Path(env["PREP"]) / "component-staging" / name, {}, name)
                for name in self.component_names}
            if self.recheck_mismatch:
                components["rust"] = {"name": "altered"}
            result = {
                "status": "VERIFIED_RETAINED_INPUTS",
                "components": components,
                "selection_sha256": self.preparation["selection_sha256"],
                "policy_sha256": self.preparation["policy_sha256"],
            }
            return {}, json.dumps(result), ""
        raise AssertionError("driver attempted to reconstruct or execute recipe lines itself")

    def _install_and_run_recipe(self, bundle, work, output, python, supervisor,
                                host, sdk, components, reference, commands):
        self.events.append(("install_and_run_recipe", tuple(commands)))
        if commands != self.EXPECTED_RECIPE:
            raise AssertionError("driver did not pass through trusted recipe commands")
        if Path(bundle) != Path(work) / "candidate":
            raise AssertionError("recipe did not use the authenticated private candidate snapshot")
        native = [{"path": "native/variant-" + str(index) + ".AMIRUST",
                   "bytes": 1, "sha256": str(index) * 64} for index in range(5)]
        output_native = Path(output) / "native"
        output_native.mkdir(mode=0o700)
        for index in range(5):
            (output_native / ("variant-" + str(index) + ".AMIRUST")).write_bytes(b"x")
        retained_metadata = []
        for root_name in ("absolute-a", "absolute-b"):
            metadata_root = Path(output) / "metadata" / root_name
            metadata_root.mkdir(mode=0o700, parents=True)
            for crate in ("serde", "curve25519_dalek", "ed25519_dalek"):
                path = metadata_root / (crate + ".rlib")
                raw = (root_name + ":" + crate).encode()
                path.write_bytes(raw)
                digest = hashlib.sha256(raw).hexdigest()
                retained_metadata.append({
                    "crate": crate, "path": path.relative_to(output).as_posix(),
                    "canonical_path": "target/release/deps/lib" + crate + "-" + digest[:16] + ".rlib",
                    "bytes": len(raw), "sha256": digest, "root": root_name,
                    "host": "macos-aarch64", "source_sdk_identity": self.commit,
                    "sdk_manifest_sha256": "d" * 64, "build_receipt_sha256": "e" * 64,
                    "canonical_artifacts_sha256": "f" * 64,
                    "canonical_artifact": {"bytes": len(raw), "sha256": digest},
                    "reference_match": True,
                })
        inventories = {name: self.ci_sdk.verify_component(components[name], {}, name)
                       for name in self.component_names}
        return {
            "commands": {"absolute-a": [], "absolute-b": []},
            "uninstall": {"absolute-a": {"selected_prefix_absent": True},
                          "absolute-b": {"selected_prefix_absent": True}},
            "prerequisite_inventories_after_uninstall": {
                "absolute-a": inventories, "absolute-b": inventories},
            "unrelated_sibling_marker_sha256": "9" * 64,
            "retained_native": native,
            "retained_metadata": retained_metadata,
            "final_contract_probes": {"fixture_only": True, "r1_acceptance": False},
        }

    def _assert_source_clean(self, source_commit):
        self.events.append(("assert_source_clean", source_commit))


class OuterPublisherWorkflowBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="public-replay-outer-workflow-binding-")
        self.output = Path(self.temp.name).resolve() / "output"
        self.output.mkdir(mode=0o700)
        self.source = "a" * 40
        self.row = {"runId": 12345, "runAttempt": 1, "hostProfile": "linux-x86_64"}
        self.receipt = {
            "status": "PUBLIC_CANDIDATE_AUTHENTICATED_AND_UNPACKED_NOT_INSTALLED_NOT_R1_ACCEPTED",
            "authenticated": True, "unpacked": True, "installed": False, "r1_accepted": False,
            "source_commit": self.source, "workflow_commit": self.source,
            "inner_verification": {"verified": True, "manifest_sha256": "b" * 64,
                                   "source_sha": self.source, "workflow_sha": self.source,
                                   "workflow_runs": [self.row]},
        }
        self.path = self.output / public_replay.OUTER_RECEIPT_NAME
        self.write_receipt()

    def tearDown(self):
        self.temp.cleanup()

    def write_receipt(self):
        raw = public_replay._canonical_json(self.receipt)
        self.path.write_bytes(raw)
        self.summary = {"status": self.receipt["status"], "authenticated": True,
                        "unpacked": True, "receipt_path": public_replay.OUTER_RECEIPT_NAME,
                        "receipt_sha256": hashlib.sha256(raw).hexdigest()}

    def runs(self):
        return public_replay._publisher_workflow_runs_from_outer_receipt(
            self.output, self.summary, self.source, ("macos-aarch64", "linux-x86_64"))

    def test_retained_receipt_supplies_hash_bound_linux_publisher_run(self):
        self.assertEqual(self.runs(), [self.row])

    def test_outer_receipt_hash_and_source_context_are_required(self):
        self.path.write_bytes(self.path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "differs from its verified digest"):
            self.runs()
        self.write_receipt()
        self.receipt["inner_verification"]["workflow_sha"] = "f" * 40
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "does not bind the selected publisher source"):
            self.runs()

    def test_non_singleton_or_malformed_publisher_run_is_rejected(self):
        self.receipt["inner_verification"]["workflow_runs"] = [self.row, self.row]
        self.write_receipt()
        with self.assertRaisesRegex(ValueError, "exactly one workflow run"):
            self.runs()
        malformed = ([{"runId": True, "runAttempt": 1, "hostProfile": "linux-x86_64"}],
                     [{"runId": 12345, "runAttempt": 0, "hostProfile": "linux-x86_64"}],
                     [{"runId": 12345, "runAttempt": 1, "hostProfile": "unknown-host"}],
                     [{"runId": 12345, "runAttempt": 1,
                       "hostProfile": "linux-x86_64", "extra": True}])
        for rows in malformed:
            with self.subTest(rows=rows):
                self.receipt["inner_verification"]["workflow_runs"] = rows
                self.write_receipt()
                with self.assertRaisesRegex(ValueError, "workflow run identity is malformed"):
                    self.runs()


class PublicReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "selected-source"
        (self.source / "release").mkdir(parents=True)
        for name in ("install_publisher.py", "ci-auth-tools.json", "ci-sdk-inputs.json",
                     "ci-resources.json", "native-reference.json"):
            (self.source / "release" / name).write_text("fixture\n")
        self.bundle = self.root / "public-bundle"
        self.bundle.mkdir()
        self.manifest_bytes = b"externally selected release manifest fixture\n"
        (self.bundle / "release.json").write_bytes(self.manifest_bytes)
        self.bundle_digest = hashlib.sha256(self.manifest_bytes).hexdigest()
        self.commit = "a" * 40
        self.work = self.root / "work"
        self.output = self.root / "output"
        self.python_root = self.root / "ami-rust-python-bootstrap"
        self.python_root.mkdir()
        self.helpers = FakeTrustedHelpers(self.source, self.commit, self.bundle_digest)

    def tearDown(self):
        self.temp.cleanup()

    def replay(self, helpers=None, *, digest=None, release_tag="v0.1.0",
               tag_verifier=None):
        verifier = tag_verifier or mock.Mock(return_value=self.commit)
        with mock.patch.object(public_replay, "_verify_release_tag_target", verifier):
            return public_replay.replay_public_candidate(
                source=self.source, source_commit=self.commit, bundle=self.bundle,
                manifest_sha256=digest or self.bundle_digest, release_tag=release_tag,
                work=self.work,
                output=self.output, python_bootstrap_root=self.python_root,
                helpers=helpers or self.helpers,
            )

    def make_git_source(self, name, origin="https://github.com/metaneutrons/ami-rust.git"):
        source = self.root / name
        (source / "release").mkdir(parents=True)
        marker = self.root / (name + "-import-marker.txt")
        source_script = source / "release" / "ci_verify.py"
        source_script.write_text(
            "from pathlib import Path\n"
            "ROOT = Path(__file__).resolve().parents[1]\n"
            "Path(" + repr(str(marker)) + ").write_text('imported\\n')\n"
        )
        command = ["/usr/bin/git", "-C", str(source)]
        subprocess.run([*command, "init", "--quiet"], check=True, stdout=subprocess.PIPE)
        subprocess.run([*command, "config", "user.name", "Replay Fixture"], check=True)
        subprocess.run([*command, "config", "user.email", "replay-fixture@example.invalid"], check=True)
        subprocess.run([*command, "remote", "add", "origin", origin], check=True)
        subprocess.run([*command, "add", "release/ci_verify.py"], check=True)
        subprocess.run([*command, "commit", "--quiet", "-m", "fixture source"], check=True,
                       stdout=subprocess.PIPE)
        revision = subprocess.run([*command, "rev-parse", "HEAD"], check=True,
                                  stdout=subprocess.PIPE, text=True).stdout.strip()
        return source, revision, marker, source_script

    def test_wrong_external_source_is_rejected_before_installer_side_effects(self):
        helpers = FakeTrustedHelpers(self.source, self.commit, self.bundle_digest,
                                     source_mismatch=True)
        with self.assertRaisesRegex(ValueError, "externally selected source commit"):
            self.replay(helpers)
        self.assertFalse(any(event[0] in {"bootstrap_tools", "write_source_policy", "protected_verify"}
                             for event in helpers.events))
        self.assertFalse(self.work.exists())
        self.assertFalse(self.output.exists())

    def test_wrong_external_manifest_hash_is_rejected_before_installer_side_effects(self):
        with self.assertRaisesRegex(ValueError, "externally supplied manifest"):
            self.replay(digest="b" * 64)
        self.assertFalse(any(event[0] in {"bootstrap_tools", "write_source_policy", "protected_verify"}
                             for event in self.helpers.events))
        self.assertFalse(self.work.exists())
        self.assertFalse(self.output.exists())

    def test_matching_release_tag_runs_public_flow_and_is_recorded(self):
        tag_verifier = mock.Mock(return_value=self.commit)
        report = self.replay(tag_verifier=tag_verifier)
        tag_verifier.assert_called_once_with(self.source, "v0.1.0", self.commit)
        event_names = [event[0] for event in self.helpers.events]
        self.assertLess(event_names.index("source_identity"), event_names.index("bootstrap_tools"))
        self.assertLess(event_names.index("source_identity"), event_names.index("candidate_inventory"))
        self.assertLess(event_names.index("bootstrap_tools"), event_names.index("write_source_policy"))
        self.assertLess(event_names.index("protected_verify"), event_names.index("preparation_commands"))
        trusted_assets_call = next(event for event in self.helpers.events
                                   if event[0] == "validate_trusted_assets")
        self.assertEqual(trusted_assets_call[1], str(self.source))
        self.assertLess(event_names.index("recipe_line"), event_names.index("install_and_run_recipe"))
        self.assertEqual(event_names.count("recipe_line"), 2)
        self.assertEqual(self.helpers.events[1][0], "candidate_inventory")
        bootstrap_call = next(event for event in self.helpers.events if event[0] == "bootstrap_tools")
        self.assertEqual(bootstrap_call[2], len(self.manifest_bytes))
        install_call = next(event for event in self.helpers.events if event[0] == "install_and_run_recipe")
        self.assertEqual(install_call[1], tuple(self.helpers.EXPECTED_RECIPE))
        self.assertEqual(report["status"], public_replay.RESULT_STATUS)
        self.assertEqual(report["release_tag"], "v0.1.0")
        self.assertEqual(report["release_tag_target_commit"], self.commit)
        self.assertEqual(report["candidate"]["release_manifest_sha256"], self.bundle_digest)
        self.assertEqual(report["candidate"]["version"], "0.1.0")
        self.assertEqual(report["claims"]["r1_accepted"], False)
        self.assertEqual(report["claims"]["aros_guest_run"], False)
        self.assertEqual(len(report["retained_metadata"]), 6)
        self.assertTrue(report["final_contract_probes"]["fixture_only"])
        self.assertFalse(report["final_contract_probes"]["r1_acceptance"])
        self.assertEqual({row["root"] for row in report["retained_metadata"]},
                         {"absolute-a", "absolute-b"})
        self.assertEqual({row["path"] for row in report["retained_metadata"]},
                         {f"metadata/{root}/{crate}.rlib"
                          for root in ("absolute-a", "absolute-b")
                          for crate in ("serde", "curve25519_dalek", "ed25519_dalek")})
        self.assertTrue((self.output / public_replay.RESULT_NAME).is_file())

    def test_prerelease_tag_compares_authenticated_manifest_release_core(self):
        report = self.replay(release_tag="v0.1.0-rc.2+build.7")
        self.assertEqual(report["release_tag"], "v0.1.0-rc.2+build.7")
        self.assertEqual(report["candidate"]["version"], "0.1.0")

    def test_release_core_accepts_stable_prerelease_and_build_metadata(self):
        for tag, expected in (
            ("v1.2.3", "1.2.3"),
            ("v1.2.3-rc.4", "1.2.3"),
            ("v1.2.3+ci.5", "1.2.3"),
            ("v1.2.3-rc.4+ci.5", "1.2.3"),
        ):
            with self.subTest(tag=tag):
                self.assertEqual(public_replay.release_core(tag), expected)

    def test_release_core_rejects_malformed_semver_tags(self):
        for tag in ("1.2.3", "v01.2.3", "v1.2.3-01", "v1.2.3-"):
            with self.subTest(tag=tag):
                with self.assertRaisesRegex(ValueError, "canonical v-prefixed SemVer"):
                    public_replay.release_core(tag)

    def test_transport_workflow_uses_shared_six_asset_names_and_external_pin(self):
        tree = _public_candidate_download_workflow_tree()
        self.assertIn("inventory_sha", ast.unparse(tree))
        url_calls = [node for node in ast.walk(tree)
                     if isinstance(node, ast.Call)
                     and isinstance(node.func, ast.Name) and node.func.id == "download"]
        self.assertEqual(len(url_calls), 1)
        self.assertIn("quote(name", ast.unparse(url_calls[0]))

    def test_prerelease_tag_with_wrong_manifest_core_stops_before_preparation(self):
        helpers = FakeTrustedHelpers(self.source, self.commit, self.bundle_digest,
                                     candidate_version="0.1.1")
        with self.assertRaisesRegex(ValueError, "authenticated release manifest version"):
            self.replay(helpers, release_tag="v0.1.0-rc.2")

        event_names = [event[0] for event in helpers.events]
        self.assertLess(event_names.index("protected_verify"), event_names.index("manifest_parse"))
        self.assertTrue((self.output / public_replay.FAILURE_NAME).is_file())
        failure = json.loads((self.output / public_replay.FAILURE_NAME).read_text())
        self.assertEqual(failure["release_tag"], "v0.1.0-rc.2")
        self.assertEqual(failure["release_tag_target_commit"], self.commit)
        self.assertFalse(any(name in event_names for name in (
            "negative_probes", "preparation_commands", "recipe_line",
            "install_and_run_recipe")))
        self.assertFalse((self.output / public_replay.RESULT_NAME).exists())

    def test_tag_binding_failure_stops_before_bundle_access_and_records_phase(self):
        self.output.mkdir(mode=0o700)
        tag_verifier = mock.Mock(side_effect=ValueError(
            "selected release tag target differs from the external source commit"))
        with self.assertRaisesRegex(ValueError, "release tag target differs"):
            self.replay(tag_verifier=tag_verifier)

        tag_verifier.assert_called_once_with(self.source, "v0.1.0", self.commit)
        self.assertEqual([event[0] for event in self.helpers.events], ["source_identity"])
        failure = json.loads((self.output / public_replay.FAILURE_NAME).read_text())
        self.assertEqual(failure["phase"], "release-tag-source-binding")
        self.assertNotIn("release_tag_target_commit", failure)
        self.assertFalse(self.work.exists())

    def test_lightweight_and_annotated_release_tags_peel_to_the_pinned_commit(self):
        for name, tag, annotated in (
            ("lightweight-tag-source", "v1.2.3", False),
            ("annotated-tag-source", "v2.3.4-rc.1", True),
        ):
            with self.subTest(tag=tag):
                source, revision, _, _ = self.make_git_source(name)
                arguments = (["tag", "-a", tag, "-m", "isolated fixture tag"]
                             if annotated else ["tag", tag])
                subprocess.run(["/usr/bin/git", "-C", str(source), *arguments],
                               check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertEqual(
                    public_replay._verify_release_tag_target(source, tag, revision), revision)

    def test_missing_release_tag_is_rejected(self):
        source, revision, _, _ = self.make_git_source("missing-tag-source")
        with self.assertRaisesRegex(ValueError, "release tag Git verification failed"):
            public_replay._verify_release_tag_target(source, "v1.2.3", revision)

    def test_release_tag_pointing_at_another_commit_is_rejected(self):
        source, first_revision, _, script = self.make_git_source("wrong-tag-target-source")
        subprocess.run(["/usr/bin/git", "-C", str(source), "tag", "v1.2.3", first_revision],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        script.write_text(script.read_text(encoding="utf-8") + "# second fixture commit\n",
                          encoding="utf-8")
        subprocess.run(["/usr/bin/git", "-C", str(source), "add", "release/ci_verify.py"],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["/usr/bin/git", "-C", str(source), "commit", "--quiet", "-m",
                        "second fixture source"], check=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
        second_revision = subprocess.run(
            ["/usr/bin/git", "-C", str(source), "rev-parse", "HEAD"], check=True,
            stdout=subprocess.PIPE, text=True).stdout.strip()
        self.assertNotEqual(first_revision, second_revision)
        with self.assertRaisesRegex(ValueError, "tag target differs"):
            public_replay._verify_release_tag_target(source, "v1.2.3", second_revision)

    def test_release_tag_binding_rejects_head_different_from_external_source(self):
        source, first_revision, _, script = self.make_git_source("wrong-head-source")
        subprocess.run(["/usr/bin/git", "-C", str(source), "tag", "-a", "v1.2.3",
                        "-m", "isolated fixture tag", first_revision], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        script.write_text(script.read_text(encoding="utf-8") + "# second fixture commit\n",
                          encoding="utf-8")
        subprocess.run(["/usr/bin/git", "-C", str(source), "add", "release/ci_verify.py"],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["/usr/bin/git", "-C", str(source), "commit", "--quiet", "-m",
                        "second fixture source"], check=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
        with self.assertRaisesRegex(ValueError, "HEAD differs from the external source commit"):
            public_replay._verify_release_tag_target(source, "v1.2.3", first_revision)

    def test_malformed_release_tag_is_rejected_before_source_or_bundle_access(self):
        for release_tag in ("0.1.0", "v01.2.3", "v1.2.3-01"):
            with self.subTest(release_tag=release_tag):
                with self.assertRaisesRegex(ValueError, "v-prefixed SemVer"):
                    self.replay(release_tag=release_tag)
        self.assertEqual(self.helpers.events, [])
        self.assertFalse(self.work.exists())
        self.assertFalse(self.output.exists())

    def test_cli_parses_required_release_tag(self):
        parser = public_replay._parser()
        required_args = [
            "--source", str(self.source), "--source-commit", self.commit,
            "--candidate-assets", str(self.bundle), "--transport-sha256", "c" * 64,
            "--manifest-sha256", self.bundle_digest,
            "--work", str(self.work),
            "--output", str(self.output),
            "--python-bootstrap-root", str(self.python_root),
        ]
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as missing_tag:
                parser.parse_args(required_args)
        self.assertEqual(missing_tag.exception.code, 2)
        args = parser.parse_args([*required_args, "--release-tag", "v0.1.0"])
        self.assertEqual(args.release_tag, "v0.1.0")

    def test_preparation_identity_mismatch_stops_before_recipe_installation(self):
        helpers = FakeTrustedHelpers(self.source, self.commit, self.bundle_digest,
                                     preparation_mismatch=True)
        with self.assertRaisesRegex(ValueError, "documented preparation differs"):
            self.replay(helpers)
        self.assertFalse(any(event[0] == "install_and_run_recipe" for event in helpers.events))
        self.assertFalse((self.output / public_replay.RESULT_NAME).exists())
        self.assertTrue((self.output / public_replay.FAILURE_NAME).is_file())

    def test_post_uninstall_recheck_mismatch_fails_without_pass_receipt(self):
        helpers = FakeTrustedHelpers(self.source, self.commit, self.bundle_digest,
                                     recheck_mismatch=True)
        with self.assertRaisesRegex(ValueError, "post-uninstall input recheck"):
            self.replay(helpers)
        event_names = [event[0] for event in helpers.events]
        self.assertIn("install_and_run_recipe", event_names)
        self.assertEqual(event_names.count("recipe_line"), 2)
        self.assertFalse((self.output / public_replay.RESULT_NAME).exists())
        failure = json.loads((self.output / public_replay.FAILURE_NAME).read_text())
        self.assertEqual(failure["status"], "FAIL_PUBLIC_CONSUMER_REPLAY_NOT_R1_ACCEPTANCE")
        self.assertNotIn("environment", failure)
        self.assertNotIn("env", failure)

    def test_dirty_source_is_rejected_before_modified_helper_import(self):
        source, revision, marker, script = self.make_git_source("dirty-source")
        script.write_text(script.read_text() + "# dirty modification\n")
        with self.assertRaisesRegex(ValueError, "tracked, untracked, or submodule modifications"):
            public_replay._load_selected_trusted_helpers(source, revision)
        self.assertFalse(marker.exists())

    def test_wrong_source_commit_is_rejected_before_helper_import(self):
        source, revision, marker, _ = self.make_git_source("wrong-commit-source")
        wrong_revision = "f" * 40 if revision != "f" * 40 else "e" * 40
        with self.assertRaisesRegex(ValueError, "HEAD differs from the external source commit"):
            public_replay._load_selected_trusted_helpers(source, wrong_revision)
        self.assertFalse(marker.exists())

    def test_wrong_source_origin_is_rejected_before_helper_import(self):
        source, revision, marker, _ = self.make_git_source(
            "wrong-origin-source", origin="https://example.invalid/untrusted/ami-rust.git")
        with self.assertRaisesRegex(ValueError, "origin is not the approved publisher repository"):
            public_replay._load_selected_trusted_helpers(source, revision)
        self.assertFalse(marker.exists())

    def test_clean_approved_source_loader_imports_tiny_root_module(self):
        source, revision, marker, _ = self.make_git_source("approved-source")
        module = public_replay._load_selected_trusted_helpers(source, revision)
        self.assertEqual(Path(module.ROOT), source)
        self.assertEqual(marker.read_text(), "imported\n")


class PublicGitHubProofDownloadIsolationTests(unittest.TestCase):
    """Exercise pinned-GH output placement with a local fake CLI, never the network."""

    NAMES = {
        "payload": "ami-rust-0.1.0-release.tar.xz",
        "sbom": "ami-rust-0.1.0-release.tar.xz.spdx.json",
        "transport": "ami-rust-0.1.0-transport.json",
        "checksums": "SHA256SUMS",
        "payload_signature": "ami-rust-0.1.0-release.tar.xz.sigstore.json",
        "transport_signature": "ami-rust-0.1.0-transport.json.sigstore.json",
    }

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="public-gh-proof-output-")
        self.root = Path(self.temp.name).resolve()
        self.candidate = self.root / "candidate"
        self.candidate.mkdir(mode=0o700)
        for index, name in enumerate(self.NAMES.values()):
            (self.candidate / name).write_bytes(("asset-fixture-" + str(index)).encode())
        self.work = self.root / "work"
        self.work.mkdir(mode=0o700)
        self.bin = self.root / "bin"
        self.bin.mkdir(mode=0o700)
        self.observations = self.root / "invocations.jsonl"

    def tearDown(self):
        self.temp.cleanup()

    def make_fake_gh(self, mode="normal"):
        executable = self.bin / "gh"
        script = f'''#!{sys.executable}
import hashlib, json, os, pathlib, sys
mode = {mode!r}
asset = pathlib.Path(sys.argv[3])
home = pathlib.Path(os.environ["HOME"])
config = pathlib.Path(os.environ["GH_CONFIG_DIR"])
cache = pathlib.Path(os.environ["XDG_CACHE_HOME"])
cwd = pathlib.Path.cwd()
(home / ".local" / "share" / "gh").mkdir(parents=True)
(home / ".local" / "share" / "gh" / "runtime-state").write_text("fixture\\n")
(config / "hosts.yml").write_text("github.com:\\n")
(cache / "gh").mkdir()
(cache / "gh" / "entry").write_text("fixture\\n")
observation = {{"cwd": str(cwd), "home": str(home), "config": str(config),
               "cache": str(cache), "token_present": bool(os.environ.get("GH_TOKEN"))}}
with open({str(self.observations)!r}, "a", encoding="utf-8") as stream:
    stream.write(json.dumps(observation, sort_keys=True) + "\\n")
digest = hashlib.sha256(asset.read_bytes()).hexdigest()
name = "sha256:" + digest + ".jsonl"
if mode == "wrong-digest":
    name = "sha256:" + ("0" * 64) + ".jsonl"
raw = (json.dumps({{"fixture": True}}) + "\\n").encode()
target = cwd / name
if mode == "symlink":
    source = home / "proof.jsonl"
    source.write_bytes(raw)
    target.symlink_to(source)
else:
    target.write_bytes(raw)
if mode == "extra-output":
    (cwd / "extra.bin").write_bytes(b"unexpected")
'''
        executable.write_text(script, encoding="utf-8")
        executable.chmod(0o700)
        return executable

    def run_download(self, mode="normal"):
        executable = self.make_fake_gh(mode)
        stage_candidate = types.SimpleNamespace(asset_names=lambda _tag: self.NAMES)
        return public_replay._download_public_gh_proofs(
            self.candidate, "v0.1.0", executable, self.work, stage_candidate,
            "fictional-retrieval-token")

    def test_realistic_cli_side_files_stay_outside_exact_download_directory(self):
        result = self.run_download()
        self.assertEqual(set(result), {self.NAMES[key] for key in
                                      ("payload", "sbom", "transport", "checksums")})
        self.assertEqual(len(self.observations.read_text().splitlines()), 4)
        for line in self.observations.read_text().splitlines():
            row = json.loads(line)
            cwd = Path(row["cwd"])
            for key in ("home", "config", "cache"):
                runtime_path = Path(row[key])
                self.assertFalse(runtime_path.is_relative_to(cwd))
                self.assertTrue(runtime_path.is_dir())
            self.assertTrue(row["token_present"])
            self.assertEqual(len(list(cwd.iterdir())), 1)
            output = next(cwd.iterdir())
            self.assertRegex(output.name, r"^sha256:[0-9a-f]{64}\.jsonl$")
            self.assertTrue(output.is_file())
        self.assertNotIn(b"fictional-retrieval-token",
                         b"".join(path.read_bytes() for path in self.work.rglob("*")
                                  if path.is_file() and not path.is_symlink()))

    def test_unexpected_second_download_output_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "exactly one JSONL file"):
            self.run_download("extra-output")

    def test_wrong_subject_digest_filename_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unexpected name or size"):
            self.run_download("wrong-digest")

    def test_symlinked_subject_proof_output_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unexpected name or size"):
            self.run_download("symlink")


class PinnedToolArchiveBudgetTests(unittest.TestCase):
    """Use the actual tracked manifest validator shape without downloading tools."""

    @classmethod
    def setUpClass(cls):
        cls.actual_ci_verify = _load_actual_ci_verify()
        cls.tool_manifest = json.loads(SCRIPT.with_name("ci-auth-tools.json").read_text())

    def test_real_validator_rows_are_summed_without_host_or_trust_roots(self):
        for host in ("linux-x86_64", "macos-aarch64"):
            with self.subTest(host=host):
                tool_pins = self.actual_ci_verify.validate_tool_manifest(
                    self.tool_manifest, host)
                self.assertEqual(set(tool_pins), {"host", "gh", "cosign", "roots"})
                self.assertIsInstance(tool_pins["host"], str)
                self.assertEqual(set(tool_pins["roots"]), {"gh", "cosign"})
                # This is the former outer-mode expression; the actual validator
                # shape proves why it raised the reported TypeError.
                with self.assertRaisesRegex(TypeError, "string indices must be integers"):
                    sum(row["bytes"] for row in tool_pins.values())
                expected = (self.tool_manifest["hosts"][host]["gh"]["bytes"]
                            + self.tool_manifest["hosts"][host]["cosign"]["bytes"])
                self.assertEqual(public_replay._pinned_tool_archive_bytes(tool_pins), expected)

    def test_malformed_or_missing_tool_archive_pin_is_rejected(self):
        valid = self.actual_ci_verify.validate_tool_manifest(
            self.tool_manifest, "linux-x86_64")
        for name, bad_row in (("missing-gh", None),
                              ("string-cosign", "not-a-tool-row"),
                              ("boolean-size", {"bytes": True}),
                              ("zero-size", {"bytes": 0})):
            with self.subTest(counterprobe=name):
                changed = dict(valid)
                if name == "missing-gh":
                    changed.pop("gh")
                else:
                    changed["cosign"] = bad_row
                with self.assertRaises(ValueError):
                    public_replay._pinned_tool_archive_bytes(changed)


class PublicReplayOuterIntegrationTests(unittest.TestCase):
    """Synthetic replay wiring checks; they do not claim real cryptographic acceptance."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="public-replay-outer-test-")
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "selected-publisher-source"
        (self.source / "release").mkdir(parents=True)
        for name in ("install_publisher.py", "ci-auth-tools.json", "ci-sdk-inputs.json",
                     "ci-resources.json", "native-reference.json"):
            (self.source / "release" / name).write_text("external source fixture\n")
        self.commit = "a" * 40
        self.controls_commit = "b" * 40
        self.controls = self.root / "frozen-controls"
        self._create_frozen_controls()
        self.candidate_assets = self.root / "candidate-assets"
        self.candidate_assets.mkdir(mode=0o700)
        self.names = {
            "payload": "ami-rust-0.1.0-release.tar.xz",
            "sbom": "ami-rust-0.1.0-release.tar.xz.spdx.json",
            "payload_signature": "ami-rust-0.1.0-release.tar.xz.sigstore.json",
            "transport": "ami-rust-0.1.0-transport.json",
            "transport_signature": "ami-rust-0.1.0-transport.json.sigstore.json",
            "checksums": "SHA256SUMS",
        }
        for index, name in enumerate(self.names.values()):
            (self.candidate_assets / name).write_bytes(("candidate-" + str(index)).encode())
        self.manifest_bytes = b"authenticated public release manifest fixture\n"
        self.manifest_sha256 = hashlib.sha256(self.manifest_bytes).hexdigest()
        self.transport_sha256 = "c" * 64
        self.work = self.root / "work"
        self.output = self.root / "output"
        self.python_root = self.root / "python-bootstrap"
        self.python_root.mkdir(mode=0o700)
        self.helpers = FakeTrustedHelpers(self.source, self.commit, self.manifest_sha256)
        self.inputs_bytes = b'{"schema":"fixture-inputs","materials":[]}\n'
        self.helpers.ci_auth.input_manifest = lambda _source: []
        self.helpers.ci_auth.encoded = lambda _materials: self.inputs_bytes
        self.helpers.policy["inputs_manifest_sha256"] = hashlib.sha256(self.inputs_bytes).hexdigest()
        original_strict_json = self.helpers.strict_json

        def integration_strict_json(path, maximum=None):
            if Path(path).name == "ci-auth-tools.json":
                return {"roots": {"gh": {"bytes": 1}, "cosign": {"bytes": 1}}}
            return original_strict_json(path, maximum)

        self.helpers.strict_json = integration_strict_json
        self.gh_bundles = self._make_gh_inputs()
        self.auth_calls = []

        class Stage:
            @staticmethod
            def asset_names(tag):
                if tag != "v0.1.0":
                    raise AssertionError("verifier received an unexpected release tag")
                return self.names

            @staticmethod
            def _outer_limits(_names):
                return {name: 1024 * 1024 for name in self.names.values()}

        self.fake_public_candidate = types.SimpleNamespace(
            stage_candidate=Stage,
            RECEIPT_STATUS=(
                "PUBLIC_CANDIDATE_AUTHENTICATED_AND_UNPACKED_NOT_INSTALLED_NOT_R1_ACCEPTED"
            ),
            verify_and_unpack=self._fake_verify_and_unpack,
        )

    def tearDown(self):
        self.temp.cleanup()

    def _create_frozen_controls(self):
        rows = {}
        for relative in public_replay.PUBLIC_REPLAY_CONTROL_PATHS:
            path = self.controls / relative
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            raw = ("frozen control:" + relative + "\n").encode()
            path.write_bytes(raw)
            path.chmod(0o600)
            rows[relative] = {
                "source_path": relative,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        record = {
            "schema": "ami-rust-public-replay-control-source-v1",
            "workflow_source_commit": self.controls_commit,
            "workflow_run_id": "123",
            "workflow_run_attempt": "1",
            "controls": rows,
        }
        (self.controls / "control-source.json").write_bytes(public_replay._canonical_json(record))
        (self.controls / "control-source.json").chmod(0o600)

    def _make_gh_inputs(self):
        root = self.root / "gh-inputs"
        root.mkdir(mode=0o700)
        result = {}
        for key in ("payload", "sbom", "transport", "checksums"):
            subject = self.names[key]
            path = root / (key + ".json")
            path.write_bytes(public_replay._canonical_json({"fixture_subject": subject}))
            result[subject] = [path]
        return result

    def _fake_verify_and_unpack(self, candidate, tag, source_commit, transport_sha256,
                                manifest_sha256, policy, trusted_inputs_root, gh_bundles,
                                destination, work, runner=None):
        self.auth_calls.append({
            "candidate": Path(candidate), "tag": tag, "source_commit": source_commit,
            "transport_sha256": transport_sha256, "manifest_sha256": manifest_sha256,
            "policy": policy, "trusted_inputs_root": Path(trusted_inputs_root),
            "gh_bundles": gh_bundles, "destination": Path(destination),
            "work": Path(work), "runner": runner,
        })
        expected_subjects = {self.names[key] for key in ("payload", "sbom", "transport", "checksums")}
        if set(gh_bundles) != expected_subjects or any(not gh_bundles[name] for name in expected_subjects):
            raise ValueError("synthetic missing GH proof")
        for subject in expected_subjects:
            proof = gh_bundles[subject][0]
            expected = public_replay._canonical_json({"fixture_subject": subject})
            if Path(proof).read_bytes() != expected:
                raise ValueError("synthetic wrong GH proof")
        self.assertFalse(Path(destination).exists(), "bundle was unpacked before crypto completed")
        self.helpers.events.append(("outer_crypto_complete",))
        evidence = Path(work) / "public-candidate-fixture"
        evidence.mkdir(mode=0o700)
        proof_root = evidence / "gh"
        proof_root.mkdir(mode=0o700)
        selected = {}
        for subject in sorted(expected_subjects):
            source_proof = Path(gh_bundles[subject][0])
            raw = source_proof.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            (proof_root / (digest + ".json")).write_bytes(raw)
            selected[subject] = [{"sha256": digest, "statement_sha256": "d" * 64}]
        Path(destination).mkdir(mode=0o700)
        (Path(destination) / "release.json").write_bytes(self.manifest_bytes)
        self.helpers.events.append(("safe_unpack",))
        receipt = {
            "schema": "ami-rust-public-candidate-authentication-v1",
            "status": self.fake_public_candidate.RECEIPT_STATUS,
            "authenticated": True,
            "unpacked": True,
            "installed": False,
            "r1_accepted": False,
            "source_commit": source_commit,
            "workflow_commit": source_commit,
            "transport_sha256": transport_sha256,
            "manifest_sha256": manifest_sha256,
            "candidate_assets": [{"path": name} for name in sorted(self.names.values())],
            "selected_gh_proofs": selected,
            "cosign_proofs": {
                self.names["payload"]: {"bundle_sha256": "e" * 64},
                self.names["transport"]: {"bundle_sha256": "f" * 64},
            },
            "evidence_directory": str(evidence),
            "destination": str(destination),
            "run_id": 123,
            "run_attempt": 1,
            "inner_verification": {
                "verified": True,
                "manifest_sha256": "d" * 64,
                "source_sha": source_commit,
                "workflow_sha": source_commit,
                "workflow_runs": [{"runId": 123, "runAttempt": 1,
                                   "hostProfile": "linux-x86_64"}],
            },
            "receipt_path": str(evidence / "receipt.json"),
        }
        (evidence / "receipt.json").write_bytes(public_replay._canonical_json(receipt))
        return receipt

    def replay(self, *, gh_bundles=None):
        with mock.patch.object(public_replay, "_verify_release_tag_target",
                               return_value=self.commit), \
                mock.patch.object(public_replay, "_load_public_candidate",
                                  return_value=self.fake_public_candidate):
            return public_replay.replay_public_candidate(
                source=self.source,
                source_commit=self.commit,
                candidate_assets=self.candidate_assets,
                transport_sha256=self.transport_sha256,
                manifest_sha256=self.manifest_sha256,
                release_tag="v0.1.0",
                work=self.work,
                output=self.output,
                python_bootstrap_root=self.python_root,
                controls_root=self.controls,
                gh_bundles=self.gh_bundles if gh_bundles is None else gh_bundles,
                helpers=self.helpers,
            )

    def test_production_path_authenticates_then_unpacks_before_consumer_install(self):
        with mock.patch.dict(os.environ, {
            "GH_TOKEN": "retrieve-only-token",
            "GITHUB_TOKEN": "ambient-token",
        }, clear=False):
            report = self.replay()
            self.assertNotIn("GH_TOKEN", os.environ)
            self.assertNotIn("GITHUB_TOKEN", os.environ)

        self.assertEqual(len(self.auth_calls), 1)
        call = self.auth_calls[0]
        self.assertEqual(call["tag"], "v0.1.0")
        self.assertEqual(call["source_commit"], self.commit)
        self.assertEqual(call["transport_sha256"], self.transport_sha256)
        self.assertEqual(call["manifest_sha256"], self.manifest_sha256)
        self.assertTrue((call["trusted_inputs_root"] / ".auth" / "inputs.json").is_file())
        self.assertEqual(call["work"].parent, self.work)
        self.assertTrue(call["work"].is_relative_to(self.work))
        self.assertEqual(call["destination"].parent, self.work.parent)
        self.assertNotEqual(call["destination"], self.work)

        event_names = [event[0] for event in self.helpers.events]
        self.assertLess(event_names.index("outer_crypto_complete"), event_names.index("safe_unpack"))
        self.assertLess(event_names.index("safe_unpack"), event_names.index("protected_verify"))
        self.assertLess(event_names.index("protected_verify"), event_names.index("install_and_run_recipe"))
        self.assertTrue(report["claims"]["public_transport_verified_by_harness"])
        self.assertEqual(report["source_policy"]["source_sha"], self.commit)
        self.assertEqual(report["source_policy"]["workflow_sha"], self.commit)
        self.assertEqual(report["host"], "macos-aarch64")
        self.assertEqual(self.helpers.expected_workflow_runs,
                         [{"runId": 123, "runAttempt": 1, "hostProfile": "linux-x86_64"}])
        retained_outer = json.loads((self.output / public_replay.OUTER_RECEIPT_NAME).read_text())
        self.assertEqual(retained_outer["inner_verification"]["workflow_runs"],
                         [{"runId": 123, "runAttempt": 1, "hostProfile": "linux-x86_64"}])
        self.assertNotEqual(self.controls_commit, self.commit)
        self.assertEqual(report["workflow_control_sources"]["workflow_source_commit"],
                         self.controls_commit)
        self.assertTrue((self.output / public_replay.OUTER_RECEIPT_NAME).is_file())
        self.assertFalse((self.output / "candidate-assets").exists())
        self.assertFalse((self.output / self.names["payload"]).exists())
        retained = report["public_candidate_authentication"]["selected_proofs"]
        self.assertEqual(len(retained), 4)
        for row in retained:
            path = self.output / row["path"]
            self.assertEqual(path.stat().st_size, row["bytes"])
            self.assertEqual(public_replay.sha256(path), row["sha256"])

    def test_missing_or_wrong_proof_fails_before_unpack_and_never_claims_verification(self):
        cases = ("missing", "wrong")
        for label in cases:
            with self.subTest(proof=label):
                self.work = self.root / ("work-" + label)
                self.output = self.root / ("output-" + label)
                proofs = {subject: list(paths) for subject, paths in self.gh_bundles.items()}
                if label == "missing":
                    proofs.pop(next(iter(proofs)))
                else:
                    wrong = self.root / "wrong-proof.json"
                    wrong.write_text("{\"fixture_subject\":\"wrong\"}\n", encoding="utf-8")
                    proofs[next(iter(proofs))] = [wrong]
                with self.assertRaisesRegex(ValueError, "synthetic (missing|wrong) GH proof"):
                    self.replay(gh_bundles=proofs)
                self.assertFalse((self.work.parent / "ami-rust-public-authenticated-bundle").exists())
                self.assertFalse((self.output / public_replay.RESULT_NAME).exists())
                failure = json.loads((self.output / public_replay.FAILURE_NAME).read_text())
                self.assertFalse(failure["claims"]["public_transport_verified_by_harness"])
                event_names = [event[0] for event in self.helpers.events]
                self.assertNotIn("safe_unpack", event_names)
                self.assertNotIn("install_and_run_recipe", event_names)


if __name__ == "__main__":
    unittest.main()
