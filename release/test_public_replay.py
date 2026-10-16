"""Offline orchestration fixtures for the public consumer replay driver."""
from __future__ import annotations

import ast
from contextlib import redirect_stderr
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import types
import unittest
import urllib.parse
from unittest import mock


SCRIPT = Path(__file__).with_name("public_replay.py")
SPEC = importlib.util.spec_from_file_location("r1_public_replay_fixture_target", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
public_replay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(public_replay)
WORKFLOW = SCRIPT.parents[1] / ".github" / "workflows" / "public-replay.yml"


def _public_transport_workflow_tree() -> ast.Module:
    """Parse the transport step's embedded Python control block."""
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
               and any(isinstance(target, ast.Name) and target.id == "expected_archive_name"
                       for target in node.targets)
               for node in tree.body):
            return tree
    raise AssertionError("public transport Python block is missing expected_archive_name")


def _workflow_assignment(tree: ast.Module, name: str) -> ast.Assign:
    matches = [node for node in tree.body
               if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == name
                       for target in node.targets)]
    if len(matches) != 1:
        raise AssertionError(f"expected one workflow assignment to {name}")
    return matches[0]


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
        self.tool_pins = {name: {"binary_sha256": hashlib.sha256(data).hexdigest()}
                          for name, data in self.tool_bytes.items()}
        self.preparation = None
        self.policy = {"inputs_manifest_sha256": "4" * 64}
        self.policy_sha = "5" * 64

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

    def _validate_trusted_consumer_assets(self, bundle, verified, policy):
        self.events.append(("validate_trusted_assets",))

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
        }

    def _assert_source_clean(self, source_commit):
        self.events.append(("assert_source_clean", source_commit))


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

    def test_transport_workflow_uses_shared_core_for_filenames_and_full_tag_urls(self):
        tree = _public_transport_workflow_tree()
        controls = Path("/frozen-controls")
        loads = []

        def load_control(name, path):
            loads.append((name, path))
            return public_replay

        namespace = {"controls": controls, "load": load_control, "urllib": urllib}

        def execute(name):
            statement = _workflow_assignment(tree, name)
            exec(compile(ast.Module(body=[statement], type_ignores=[]),
                         str(WORKFLOW), "exec"), namespace)

        execute("replay_control")
        self.assertEqual(loads, [("_ami_rust_public_replay_control",
                                  controls / "public_replay.py")])

        base = "https://github.com/metaneutrons/ami-rust/releases/download/"
        for tag, core in (("v1.2.3", "1.2.3"),
                          ("v1.2.3-rc.4+ci.5", "1.2.3")):
            with self.subTest(tag=tag):
                namespace["tag"] = tag
                for name in ("version", "archive_path", "encoded_tag", "encoded_version",
                             "expected_archive_name", "inventory_url", "archive_url"):
                    execute(name)
                encoded_tag = urllib.parse.quote(tag, safe="v.-")
                encoded_core = urllib.parse.quote(core, safe=".-")
                archive_name = "ami-rust-" + core + "-release.tar.xz"
                self.assertEqual(namespace["version"], core)
                self.assertEqual(namespace["archive_path"].name, archive_name)
                self.assertEqual(namespace["expected_archive_name"], archive_name)
                self.assertEqual(
                    namespace["inventory_url"],
                    base + encoded_tag + "/ami-rust-" + encoded_core + "-transport.json")
                self.assertEqual(
                    namespace["archive_url"],
                    base + encoded_tag + "/" + urllib.parse.quote(archive_name, safe=".-"))

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
            "--bundle", str(self.bundle), "--manifest-sha256", self.bundle_digest,
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


if __name__ == "__main__":
    unittest.main()
