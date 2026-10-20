"""Synthetic binding and lifecycle tests for native package revision upgrades.

These fixtures contain inert bytes and a fake command observer. They exercise
the Python coordinator's decisions; they are not runtime or release evidence.
"""
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_auth as auth
import ci_native as native


class NativeUpgradeFixtures(unittest.TestCase):
    host = "linux-x86_64"
    old_launcher = b"synthetic old launcher bytes\n"
    new_launcher = b"synthetic new launcher bytes\n"
    sdk_files = [
        {"path": "contract/sdk.json", "bytes": 48, "sha256": "c" * 64},
        {"path": "sdk/target/lib/libexec.a", "bytes": 9, "sha256": "a" * 64},
    ]

    def fixture(self, *, old_changes=None, old_producer_changes=None,
                new_changes=None, new_sdk_files=None, same_cli=False):
        root = Path(tempfile.mkdtemp(prefix="ami-rust-native-upgrade-fixture-")).resolve()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        host = self.host
        old_outer, old_bundle = root / "old-outer", root / "old-bundle"
        new_outer, new_bundle = root / "new-outer", root / "new-bundle"
        for path in (old_outer / "metadata", old_bundle / ".auth",
                     new_outer / "metadata", new_bundle):
            path.mkdir(parents=True)

        old_launcher = old_bundle / "host/ami-rust"
        old_launcher.parent.mkdir()
        old_launcher.write_bytes(self.old_launcher)
        auth_bytes = b"synthetic original host authentication\n"
        (old_bundle / ".auth/authentication.json").write_bytes(auth_bytes)
        (old_bundle / ".auth/inputs.json").write_bytes(b"synthetic input manifest\n")

        old_manifest = {
            "producer": {"source_sha": native.NATIVE_UPGRADE_SOURCE,
                         "run_id": native.NATIVE_UPGRADE_RUN, "run_attempt": 1},
            "sdk_files": list(self.sdk_files),
            "host_launchers": {host: {"path": "host/ami-rust", "bytes": len(self.old_launcher),
                                      "sha256": auth.sha(self.old_launcher)}},
        }
        if old_producer_changes:
            old_manifest["producer"].update(old_producer_changes)
        old_manifest_raw = auth.encoded(old_manifest)
        (old_bundle / "release.json").write_bytes(old_manifest_raw)

        old_pins = {
            "source_commit": native.NATIVE_UPGRADE_SOURCE,
            "sdk_run_id": native.NATIVE_UPGRADE_RUN,
            "sdk_run_attempt": 1,
            "host": host,
            "package_version": "0.2.0-1",
            "packaging_revision": 1,
            "sdk_version": "0.2.0",
            "cli_version": "0.2.0",
            "manifest_sha256": auth.sha(old_manifest_raw),
            "core_sha256": auth.sha(self.old_launcher),
        }
        if old_changes:
            old_pins.update(old_changes)
        old_pins_raw = auth.encoded(old_pins)
        old_pins_path = old_outer / "metadata" / f"native-package-inputs-{host}.json"
        old_pins_path.write_bytes(old_pins_raw)
        (old_outer / "metadata/native-package-proofs.json").write_bytes(b"synthetic proof index\n")

        new_launcher_bytes = self.old_launcher if same_cli else self.new_launcher
        current_sdk_files = [
            {"path": "contract/sdk.json", "bytes": 48, "sha256": "d" * 64},
            self.sdk_files[1],
        ]
        new_manifest = {
            "producer": {"source_sha": "b" * 40, "run_id": native.NATIVE_UPGRADE_RUN + 1,
                         "run_attempt": 1},
            "sdk_files": list(current_sdk_files if new_sdk_files is None else new_sdk_files),
            "host_launchers": {host: {"path": "host/ami-rust", "bytes": len(new_launcher_bytes),
                                      "sha256": auth.sha(new_launcher_bytes)}},
        }
        new_manifest_raw = auth.encoded(new_manifest)
        (new_bundle / "release.json").write_bytes(new_manifest_raw)
        new_pins = {
            "source_commit": "b" * 40,
            "host": host,
            "package_version": "0.2.0-2",
            "packaging_revision": 2,
            "sdk_version": old_pins["sdk_version"],
            "cli_version": old_pins["cli_version"],
            "manifest_sha256": auth.sha(new_manifest_raw),
            "core_sha256": auth.sha(new_launcher_bytes),
        }
        if new_changes:
            new_pins.update(new_changes)
        new_pins_path = new_outer / "metadata" / f"native-package-inputs-{host}.json"
        new_pins_path.write_bytes(auth.encoded(new_pins))
        (new_outer / "metadata/native-package-proofs.json").write_bytes(b"synthetic proof index\n")

        # The old bundle's legal/tooling inputs are inert local fixture files.
        for name in ("LICENSE-MIT", "LICENSE-APACHE", "native-tooling/THIRD-PARTY-NOTICES.md",
                     "native-tooling/licenses/LICENSE-MIT"):
            path = old_bundle / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic notice fixture\n")

        fixture = {
            "root": root, "host": host, "old_outer": old_outer, "old_bundle": old_bundle,
            "new_outer": new_outer, "new_bundle": new_bundle,
            "old_pins": old_pins, "new_pins": new_pins,
            "old_pins_path": old_pins_path, "old_launcher": old_launcher,
            "old_launcher_bytes": self.old_launcher, "new_launcher_bytes": new_launcher_bytes,
            "auth_bytes": auth_bytes,
        }
        fixture["host_pins"] = {host: {
            "pins_sha256": auth.sha(old_pins_raw),
            "authentication_sha256": auth.sha(auth_bytes),
        }}
        return fixture

    def invoke_inputs(self, fixture):
        with patch.object(native, "current_host", return_value=fixture["host"]), \
                patch.object(native, "NATIVE_UPGRADE_HOST_PINS", fixture["host_pins"]):
            return native._native_upgrade_inputs(fixture["old_outer"], fixture["old_bundle"],
                                                 fixture["new_bundle"], fixture["new_pins"])


class NativeUpgradeInputBindingTests(NativeUpgradeFixtures):
    def test_exact_pins_authentication_source_run_versions_baseline_and_launcher_bind(self):
        fixture = self.fixture(same_cli=True)
        old, pins_path, launcher = self.invoke_inputs(fixture)
        self.assertEqual(old, fixture["old_pins"])
        self.assertEqual(pins_path, fixture["old_pins_path"])
        self.assertEqual(launcher.read_bytes(), fixture["old_launcher_bytes"])
        self.assertEqual(fixture["new_pins"]["core_sha256"], old["core_sha256"])
        self.assertNotEqual(fixture["new_pins"]["manifest_sha256"], old["manifest_sha256"])

    def test_old_pin_file_must_match_archived_digest(self):
        fixture = self.fixture()
        fixture["old_pins_path"].write_bytes(b"tampered synthetic pin file\n")
        with self.assertRaisesRegex(ValueError, "archived preview"):
            self.invoke_inputs(fixture)

    def test_original_host_authentication_is_pinned(self):
        fixture = self.fixture()
        (fixture["old_bundle"] / ".auth/authentication.json").write_bytes(b"different fixture auth\n")
        with self.assertRaisesRegex(ValueError, "original record"):
            self.invoke_inputs(fixture)

    def test_old_source_run_host_and_revision_identity_are_exact(self):
        cases = (("source_commit", "c" * 40), ("sdk_run_id", native.NATIVE_UPGRADE_RUN + 1),
                 ("sdk_run_attempt", 2), ("host", "macos-aarch64"),
                 ("package_version", "0.2.0-9"), ("packaging_revision", 9))
        for key, value in cases:
            with self.subTest(key=key):
                fixture = self.fixture(old_changes={key: value})
                with self.assertRaisesRegex(ValueError, "source/run"):
                    self.invoke_inputs(fixture)

    def test_revision_two_versions_source_and_manifest_must_differ_correctly(self):
        cases = (("sdk_version", "0.3.0"), ("cli_version", "0.3.0"),
                 ("host", "macos-aarch64"), ("package_version", "0.2.0-1"),
                 ("packaging_revision", 1), ("source_commit", native.NATIVE_UPGRADE_SOURCE))
        for key, value in cases:
            with self.subTest(key=key):
                fixture = self.fixture(new_changes={key: value})
                with self.assertRaisesRegex(ValueError, "revision-2 package and manifest"):
                    self.invoke_inputs(fixture)
        fixture = self.fixture()
        fixture["new_pins"]["manifest_sha256"] = fixture["old_pins"]["manifest_sha256"]
        with self.assertRaisesRegex(ValueError, "revision-2 package and manifest"):
            self.invoke_inputs(fixture)

    def test_old_inner_manifest_source_and_run_are_bound(self):
        for changes in ({"source_sha": "c" * 40}, {"run_id": native.NATIVE_UPGRADE_RUN + 1},
                        {"run_attempt": 2}):
            with self.subTest(changes=changes):
                fixture = self.fixture(old_producer_changes=changes)
                with self.assertRaisesRegex(ValueError, "source/run binding"):
                    self.invoke_inputs(fixture)

    def test_new_bundle_must_keep_the_same_nonempty_sdk_baseline(self):
        fixture = self.fixture(new_sdk_files=[
            {"path": "contract/sdk.json", "bytes": 48, "sha256": "d" * 64},
            {"path": "sdk/target/lib/libexec.a", "bytes": 10, "sha256": "f" * 64},
        ])
        with self.assertRaisesRegex(ValueError, "baseline/component inventory"):
            self.invoke_inputs(fixture)

    def test_baseline_inventory_rejects_duplicate_or_missing_sdk_contract_rows(self):
        for rows in (
                [*self.sdk_files, self.sdk_files[1]],
                [self.sdk_files[1], {"path": "sdk/other", "bytes": 1, "sha256": "f" * 64}]):
            with self.subTest(rows=rows), self.assertRaisesRegex(
                    ValueError, "baseline/component inventory is incomplete or duplicated"):
                self.invoke_inputs(self.fixture(new_sdk_files=rows))

    def test_old_launcher_bytes_must_match_manifest_and_package_pin(self):
        fixture = self.fixture()
        fixture["old_launcher"].write_bytes(b"changed synthetic launcher\n")
        with self.assertRaisesRegex(ValueError, "launcher differs"):
            self.invoke_inputs(fixture)


class SyntheticUpgradeSupervisor:
    """Fake observer: emits fixture files and never launches the named command."""

    def __init__(self, work, output):
        self.work, self.output = work, output
        self.commands = []
        self.native_static_log_bytes = 0
        self.native_peak_logs = 0
        self.peak_rss = self.peak_workspace = 0

    def run(self, command, *, cwd, label, timeout):
        if label.startswith("native-upgrade-compose-"):
            output = Path(command[command.index("--output") + 1])
            launcher = Path(command[command.index("--launcher") + 1])
            (output / "bin").mkdir(parents=True)
            shutil.copyfile(launcher, output / "bin/ami-rust")
        stdout = self.work / f"{label}.stdout"
        stderr = self.work / f"{label}.stderr"
        stdout.write_bytes(b"")
        stderr.write_bytes(b"")
        row = {"label": label, "exit_code": 0, "stop_reason": None,
               "stdout_log": stdout.name, "stderr_log": stderr.name,
               "log_peak_observed_bytes": 0, "rss_peak_observed_bytes": 0,
               "managed_peak_observed_bytes": 0}
        self.commands.append(row)
        return row

    def check_limits(self, label):
        self.checked = label

    def logs_bytes(self):
        return 0


class NativeUpgradeStateMachineTests(NativeUpgradeFixtures):
    def run_upgrade(self, *, mutation=None, wrong_owner_diagnostic=False,
                    create_refused_output=False, changed_replay=False):
        fixture = self.fixture(same_cli=True)
        root = fixture["root"]
        work, output = root / "work", root / "output"
        work.mkdir()
        output.mkdir()
        new_state, new_project, new_first = root / "new-state", root / "new-project", root / "new-build"
        for path in (new_state, new_project, new_first / "artifacts"):
            path.mkdir(parents=True)
        (new_state / "ready.json").write_bytes(b"synthetic current READY\n")
        (new_project / "project.toml").write_bytes(b"synthetic current project\n")
        (new_project / "ami-rust.lock.json").write_bytes(b"synthetic current project lock\n")
        canonical_elf = b"synthetic canonical AMIRUST ELF bytes\n"
        (new_first / "artifacts/AMIRUST").write_bytes(canonical_elf)
        (new_first / "build-receipt.json").write_bytes(b"synthetic build receipt\n")

        protected = {}
        for label, relative, payload in (
                ("global_cargo_config", "home/.cargo/config.toml", b"synthetic config\n"),
                ("unrelated_sdk", "unrelated-sdk/owner.txt", b"synthetic SDK guard\n"),
                ("user_data", "user-data/notes.txt", b"synthetic user data\n")):
            file = root / relative
            file.parent.mkdir(parents=True)
            file.write_bytes(payload)
            protected[label] = file.parent

        policy_path = root / "publisher-policy.json"
        policy_path.write_bytes(auth.encoded({"schema": "synthetic policy"}))
        cli = root / "new-cli-fixture"
        cli.write_bytes(fixture["new_launcher_bytes"])
        notices = root / "new-notices"
        notices.mkdir()
        supervisor = SyntheticUpgradeSupervisor(work, output)
        effects = {"state": None, "project": None}

        def observed(label, arguments, expected=0, *, executable, publisher_policy=None):
            args = [str(part) for part in arguments]
            diagnostic = ""
            result = {}
            if label == "18-upgrade-old-authentication" or label == "18-upgrade-new-authentication":
                result = {"status": "OUTER_AND_INNER_AUTHENTICATED"}
            elif label == "19-upgrade-old-cold-prepare":
                state = Path(args[args.index("--state") + 1])
                effects["state"] = state
                version = fixture["old_pins"]["package_version"]
                core = state / "retained/libexec/ami-rust" / version / "bin/ami-rust"
                core.parent.mkdir(parents=True)
                shutil.copyfile(executable, core)
                alias = state / "retained/bin/ami-rust"
                alias.parent.mkdir(parents=True)
                alias.symlink_to(f"../libexec/ami-rust/{version}/bin/ami-rust")
                (state / "ready.json").write_bytes(b"synthetic old READY state\n")
                result = {"status": "READY", "package_version": fixture["old_pins"]["package_version"]}
            elif label == "20-upgrade-old-new-project":
                project = Path(args[args.index("--project") + 1])
                effects["project"] = project
                project.mkdir()
                (project / "project.toml").write_bytes(b"synthetic old project\n")
                (project / "ami-rust.lock.json").write_bytes(b"synthetic old project lock\n")
            elif label in ("21-upgrade-old-offline-build", "25-upgrade-old-retained-offline-replay",
                           "27-upgrade-new-offline-build"):
                target = Path(args[args.index("--output-dir") + 1])
                target.mkdir(parents=True)
                (target / "artifacts").mkdir()
                elf = canonical_elf
                if changed_replay and label == "25-upgrade-old-retained-offline-replay":
                    elf = b"changed synthetic replay ELF\n"
                (target / "artifacts/AMIRUST").write_bytes(elf)
                (target / "build-receipt.json").write_bytes(b"synthetic PASS receipt\n")
                result = {"status": "PASS"}
            elif label == "22-upgrade-new-refuses-old-state":
                diagnostic = ("state is incomplete or belongs to another SDK/package; use its retained launcher\n"
                              if not wrong_owner_diagnostic else "state is invalid\n")
                if mutation == "state":
                    (effects["state"] / "ready.json").write_bytes(b"mutated state\n")
                elif mutation == "project":
                    (effects["project"] / "project.toml").write_bytes(b"mutated project\n")
                elif mutation == "config":
                    (protected["global_cargo_config"] / "config.toml").write_bytes(b"mutated config\n")
            elif label == "23-upgrade-new-refuses-old-build":
                diagnostic = "state is incomplete or belongs to another SDK/package; use its retained launcher\n"
                if create_refused_output:
                    target = Path(args[args.index("--output-dir") + 1])
                    target.mkdir()
                    (target / "unexpected-output").write_bytes(b"fixture mutation\n")

            stdout_path = output / f"{label}.stdout.json"
            stderr_path = output / f"{label}.stderr.log"
            stdout_path.write_bytes(auth.encoded(result) if result else b"{}\n")
            stderr_path.write_text(diagnostic)
            return auth.encoded(result) if result else b"{}\n"

        with patch.object(native, "current_host", return_value=fixture["host"]), \
                patch.object(native, "NATIVE_UPGRADE_HOST_PINS", fixture["host_pins"]):
            report = native._qualify_native_upgrade(
                work, output, fixture["old_outer"], fixture["old_bundle"], fixture["new_outer"],
                fixture["new_bundle"], new_state, new_project, new_first, canonical_elf,
                root / "xtask-fixture", cli, supervisor, policy_path,
                observed, protected, notices, fixture["new_pins"])
        return report, fixture, canonical_elf, new_state, new_project, protected

    def test_actual_coordinator_replaces_selector_removes_old_root_and_preserves_retained_replay(self):
        report, fixture, elf, new_state, new_project, _ = self.run_upgrade()
        selector = fixture["root"] / "work/native-upgrade-active-cli"
        new_package = fixture["root"] / "work/native-upgrade-new-package"
        old_package = fixture["root"] / "work/native-upgrade-old-package"
        old_state = fixture["root"] / "work/native-upgrade-old-state-area/derived/state"
        old_project = fixture["root"] / "work/native-upgrade-old-project-area/project"
        self.assertEqual(report["status"],
                         "PASS_NATIVE_REVISION_UPGRADE_AND_OLD_RETAINED_OFFLINE_REPLAY_NOT_RC1_ACCEPTANCE")
        self.assertTrue(selector.is_symlink())
        self.assertEqual(selector.resolve(), new_package.resolve())
        self.assertEqual(Path(report["selected_new_package"]).resolve(), new_package.resolve())
        self.assertEqual((new_package / "bin/ami-rust").read_bytes(), fixture["new_launcher_bytes"])
        self.assertFalse(old_package.exists())
        self.assertEqual((old_state / "ready.json").read_bytes(), b"synthetic old READY state\n")
        self.assertEqual(auth.sha((old_state / "retained/bin/ami-rust").read_bytes()),
                         fixture["old_pins"]["core_sha256"])
        self.assertEqual((fixture["root"] / "work/21-upgrade-old-offline-build/derived/build"
                          / "artifacts/AMIRUST").read_bytes(), elf)
        self.assertEqual((fixture["root"] / "work/25-upgrade-old-retained-offline-replay/derived/build"
                          / "artifacts/AMIRUST").read_bytes(), elf)
        self.assertEqual((fixture["root"] / "work/27-upgrade-new-offline-build/derived/build"
                          / "artifacts/AMIRUST").read_bytes(), elf)
        self.assertEqual(report["preservation_before"], report["preservation_after"])
        self.assertEqual(report["canonical_executable_sha256"], auth.sha(elf))

        work = fixture["root"] / "work"
        output = fixture["root"] / "output"
        old_first = work / "21-upgrade-old-offline-build/derived/build"
        old_replay = work / "25-upgrade-old-retained-offline-replay/derived/build"
        new_first = fixture["root"] / "new-build"
        new_upgrade = work / "27-upgrade-new-offline-build/derived/build"
        sources = {
            "old-ready.json": old_state / "ready.json",
            "new-ready.json": new_state / "ready.json",
            "old-project-lock.json": old_project / "ami-rust.lock.json",
            "new-project-lock.json": new_project / "ami-rust.lock.json",
            "old-first-receipt.json": old_first / "build-receipt.json",
            "old-replay-receipt.json": old_replay / "build-receipt.json",
            "new-first-receipt.json": new_first / "build-receipt.json",
            "new-upgrade-receipt.json": new_upgrade / "build-receipt.json",
            "old-first.AMIRUST": old_first / "artifacts/AMIRUST",
            "old-replay.AMIRUST": old_replay / "artifacts/AMIRUST",
            "new-first.AMIRUST": new_first / "artifacts/AMIRUST",
            "new-upgrade.AMIRUST": new_upgrade / "artifacts/AMIRUST",
            "old-retained-core": old_state / "retained/libexec/ami-rust"
                                 / fixture["old_pins"]["package_version"] / "bin/ami-rust",
        }
        self.assertEqual(set(report["raw_evidence"]), set(sources))
        self.assertEqual(len(report["raw_evidence"]), 13)
        for name, source in sources.items():
            with self.subTest(raw_evidence=name):
                indexed = report["raw_evidence"][name]
                retained = output / indexed["path"]
                source_bytes = source.read_bytes()
                self.assertEqual(indexed["path"], f"native-upgrade-raw/{name}")
                self.assertEqual(retained.read_bytes(), source_bytes)
                self.assertEqual(indexed["bytes"], len(source_bytes))
                self.assertEqual(indexed["sha256"], auth.sha(source_bytes))

    def test_coordinator_detects_old_state_project_and_global_config_mutations(self):
        for mutation in ("state", "project", "config"):
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                    ValueError, "changed protected state/project/config/SDK/data during new-native-owner-refusals"):
                self.run_upgrade(mutation=mutation)

    def test_coordinator_requires_the_old_owner_refusal_diagnostic(self):
        with self.assertRaisesRegex(ValueError, "refusal did not identify the old retained owner"):
            self.run_upgrade(wrong_owner_diagnostic=True)

    def test_coordinator_rejects_output_created_by_an_incompatible_refused_build(self):
        with self.assertRaisesRegex(ValueError, "incompatible build mutated output or hid its owner refusal"):
            self.run_upgrade(create_refused_output=True)

    def test_coordinator_rejects_changed_retained_replay_elf(self):
        with self.assertRaisesRegex(ValueError, "changed the pinned canonical executable: 25-upgrade"):
            self.run_upgrade(changed_replay=True)


if __name__ == "__main__":
    unittest.main()
