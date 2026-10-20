"""Native producer controls; synthetic fixtures are not publisher evidence."""
import io
import json
import lzma
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import ANY, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ci_auth as auth
import ci_native as native
import ci_sdk


class NativeProducerTests(unittest.TestCase):
    def test_actual_native_lock_and_archive_selection_agree(self):
        # This fixture checks the real committed lock/registry selection.
        # Full source/material parity is exercised separately against the
        # actual source checkout; the installer CI uses a sparse checkout.
        with patch.object(auth, "input_manifest_for_sdk", return_value={}):
            value = native.native_inputs()
        self.assertEqual(value["sdk_version"], "0.2.0")
        self.assertEqual(len(value["registry_crates"]), 29)
        changed = json.loads(json.dumps(value))
        changed["registry_crates"][0]["sha256"] = "f" * 64
        original = auth.read

        def read(path, *args):
            if Path(path).name == "native-tooling-inputs.json":
                return auth.encoded(changed)
            return original(path, *args)

        with patch.object(auth, "read", side_effect=read):
            with self.assertRaisesRegex(ValueError, "reviewed Cargo lock"):
                native.native_inputs()

    def test_host_payload_is_bound_to_source_host_lock_and_actual_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            identity = {"source_sha": "a" * 40, "workflow_sha": "a" * 40, "run_id": 1, "run_attempt": 1}
            config = {"sdk_version": "0.2.0", "cli_version": "0.2.0-dev", "cargo_lock": {"fixture": True}}
            files = {"ami-rust": b"inert host fixture", "sdk.tar.xz": b"inert SDK", "sdk-manifest.json": b"{}\n"}
            for name, raw in files.items():
                (root / name).write_bytes(raw)
            report = {"schema": "ami-rust-native-host-producer-v1", "status": "UNSIGNED_HOST_OUTPUT",
                      "source": identity, "host": "linux-x86_64", **config,
                      "cli_identity": {"schema": "ami-rust-version-v1", "cli_version": "0.2.0-dev"},
                      "files": [{"path": k, "bytes": len(v), "sha256": auth.sha(v)} for k, v in sorted(files.items())]}
            (root / "native-host-producer.json").write_bytes(auth.encoded(report))
            self.assertEqual(native.validate_host_payload(root, "linux-x86_64", identity, config), root)
            for host, changed_identity in (("macos-aarch64", identity),
                                           ("linux-x86_64", {**identity, "source_sha": "b" * 40})):
                with self.assertRaisesRegex(ValueError, "different source"):
                    native.validate_host_payload(root, host, changed_identity, config)
            (root / "ami-rust").write_bytes(b"altered fixture")
            with self.assertRaisesRegex(ValueError, "bytes differ"):
                native.validate_host_payload(root, "linux-x86_64", identity, config)

    def test_capsule_hash_and_paths_are_checked_before_writing_members(self):
        import lzma
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory).resolve()

            def capsule(name):
                out = io.BytesIO()
                with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                    for path in ("release.json", name):
                        raw = b"{}\n"
                        row = tarfile.TarInfo(path)
                        row.size = len(raw)
                        archive.addfile(row, io.BytesIO(raw))
                return lzma.compress(out.getvalue())

            raw = capsule("sdk.tar.xz")
            pin = {"url": "https://example.invalid/fixture", "bytes": len(raw), "sha256": auth.sha(raw)}
            with patch.object(native.urllib.request, "urlopen", return_value=io.BytesIO(raw)):
                result = native.obtain_legacy(work, pin)
                self.assertEqual((result / "sdk.tar.xz").read_bytes(), b"{}\n")
            bad_hash_work = work / "bad-hash"
            bad_hash_work.mkdir()
            with patch.object(native.urllib.request, "urlopen", return_value=io.BytesIO(raw)):
                with self.assertRaisesRegex(ValueError, "differs from its pin"):
                    native.obtain_legacy(bad_hash_work, {**pin, "sha256": "0" * 64})
            self.assertEqual(list(bad_hash_work.iterdir()), [])
            bad_path_work = work / "bad-path"
            bad_path_work.mkdir()
            evil = capsule("../escaped")
            with patch.object(native.urllib.request, "urlopen", return_value=io.BytesIO(evil)):
                with self.assertRaisesRegex(ValueError, "unsafe relative"):
                    native.obtain_legacy(bad_path_work, {**pin, "bytes": len(evil), "sha256": auth.sha(evil)})
            self.assertEqual(list(bad_path_work.iterdir()), [])
            self.assertFalse((work / "escaped").exists())

    def test_unprotected_context_cannot_start_host_production(self):
        with patch.dict(native.os.environ, {"GITHUB_ACTIONS": "false"}, clear=True), \
                patch.object(native, "fresh") as create:
            with self.assertRaisesRegex(ValueError, "protected hosted"):
                native.host_build(Path("/unused-work"), Path("/unused-output"), Path("/unused-rust"), "linux-x86_64")
            create.assert_not_called()


class NativeSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temporary = Path(tempfile.mkdtemp(prefix="ami-rust-native-supervisor-test-")).resolve()
        self.work = self.temporary / "work"
        self.output = self.temporary / "output"
        self.python_root = self.temporary / "ami-rust-python-bootstrap"
        for path in (self.work, self.output, self.python_root):
            path.mkdir()

    def tearDown(self):
        shutil.rmtree(self.temporary)

    def test_static_roots_are_charged_without_following_child_symlinks(self):
        static = self.temporary / "host-rust"
        static.mkdir()
        (static / "toolchain.bin").write_bytes(b"pinned")
        target = self.temporary / "outside.bin"
        target.write_bytes(b"not charged through a symlink")
        (static / "outside-link").symlink_to(target)

        class RecordingSupervisor:
            def __init__(self, work, output, python_root, env):
                self.work, self.output, self.python_root = work, output, python_root
                self.env = env
                self.checkout_bytes = ci_sdk.directory_bytes(native.ROOT)
                self.limits = {"rss_bytes": ci_sdk.MAX_RSS_BYTES,
                               "workspace_bytes": ci_sdk.MAX_WORK_BYTES,
                               "log_bytes": ci_sdk.MAX_LOG_BYTES,
                               "seconds": ci_sdk.MAX_COMMAND_SECONDS}
                self.commands = []
                self.peak_rss = self.peak_workspace = self.peak_logs = 0

            def logs_bytes(self):
                return sum(ci_sdk.directory_accounting(root)[1]
                           for root in (self.work, self.output, self.python_root))

            def check_limits(self, label):
                self.checked = label

        with patch.object(native.ci_sdk, "verify_python_bootstrap", return_value=(Path(sys.executable), {})), \
                patch.object(native.ci_sdk, "Supervisor", RecordingSupervisor):
            supervisor = native._make_supervisor(
                self.work, self.output, self.python_root,
                {"PATH": "/usr/bin:/bin", "CARGO_REGISTRY_TOKEN": "test-token"},
                static_roots=[("host-rust", static)])

        self.assertEqual(supervisor.checkout_bytes - ci_sdk.directory_bytes(native.ROOT), len(b"pinned"))
        self.assertEqual(supervisor.native_static_roots[0]["regular_file_bytes"], len(b"pinned"))
        self.assertNotIn("CARGO_REGISTRY_TOKEN", supervisor.env)
        self.assertEqual(supervisor.native_static_roots[0]["label"], "host-rust")

    def test_static_roots_must_not_overlap_managed_roots(self):
        nested = self.work / "external"
        nested.mkdir()

        with patch.object(native.ci_sdk, "verify_python_bootstrap", return_value=(Path(sys.executable), {})):
            with self.assertRaisesRegex(ValueError, "overlaps a managed root"):
                native._make_supervisor(self.work, self.output, self.python_root, {"PATH": "/usr/bin:/bin"},
                                        static_roots=[("nested", nested)])

    def test_expected_exit_requires_one_matching_clean_supervisor_record(self):
        class FakeSupervisor:
            def __init__(self, record):
                self.commands = []
                self.record = record
                self.native_static_log_bytes = 0
                self.native_peak_logs = 0

            def run(self, command, *, cwd, label, timeout):
                row = {"label": self.record.get("label", label),
                       "exit_code": self.record.get("exit_code", 2),
                       "stop_reason": self.record.get("stop_reason"),
                       "log_peak_observed_bytes": 0}
                self.commands.append(row)
                if row["exit_code"]:
                    raise RuntimeError("expected command failure")
                return row

        accepted = FakeSupervisor({})
        record = native._supervised_run(accepted, ["native-test"], label="expected-error", expected=2)
        self.assertEqual(record["label"], "expected-error")
        self.assertEqual(record["exit_code"], 2)
        self.assertIsNone(record["stop_reason"])

        for case in ({"stop_reason": "time ceiling"}, {"label": "other-command"},
                     {"exit_code": 3}):
            with self.subTest(case=case):
                with self.assertRaisesRegex(RuntimeError, "expected command failure"):
                    native._supervised_run(FakeSupervisor(case), ["native-test"],
                                           label="expected-error", expected=2)

        class ReturningSupervisor(FakeSupervisor):
            def run(self, command, *, cwd, label, timeout):
                row = {"label": label, "exit_code": 2, "stop_reason": None,
                       "log_peak_observed_bytes": 0}
                self.commands.append(row)
                return row

        with self.assertRaisesRegex(RuntimeError, "returned without rejecting"):
            native._supervised_run(ReturningSupervisor({}), ["native-test"],
                                   label="expected-error", expected=2)


class NativeMatrixTests(unittest.TestCase):
    def setUp(self):
        self.temporary = Path(tempfile.mkdtemp(prefix="ami-rust-native-matrix-test-")).resolve()
        self.work = self.temporary / "work"
        self.output = self.temporary / "output"
        self.state = self.work / "native-ready-state"
        self.prefix = self.state / "sdk-0.2.0"
        self.sdk = self.prefix / "sdk"
        for path in (self.work, self.output, self.state, self.sdk / "contract"):
            path.mkdir(parents=True, exist_ok=True)
        (self.sdk / "Cargo.toml").write_text("[workspace]\n")
        (self.sdk / "Cargo.lock").write_text("version = 4\n")
        (self.sdk / "contract/sdk.json").write_text("{}\n")
        receipt = b"verified installation fixture\n"
        (self.prefix / "install-receipt.json").write_bytes(receipt)
        self.selection_bytes = auth.encoded({"install_receipt_sha256": auth.sha(receipt)})
        (self.state / "selection.json").write_bytes(self.selection_bytes)
        self.frontend = self.work / "signed-ami-rust"
        self.frontend.write_bytes(b"inert signed frontend fixture")
        self.rows = self._reference_rows()

    def tearDown(self):
        shutil.rmtree(self.temporary)

    def _artifact_bytes(self, variant):
        result = {"AMIRUST": ("native fixture for " + variant).encode()}
        if variant == "dependencies":
            for crate in ci_sdk.METADATA_CRATES:
                result["target/release/deps/lib" + crate + "-abc123.rlib"] = b"!<arch>\n" + crate.encode()
        return result

    def _reference_rows(self):
        rows = {}
        for variant in ci_sdk.VARIANTS:
            rows[variant] = {
                name: {"bytes": len(raw), "sha256": auth.sha(raw)}
                for name, raw in self._artifact_bytes(variant).items()}
        return rows

    def _fixture_supervisor(self):
        class Limits:
            native_static_log_bytes = 0
            native_peak_logs = 0

            def check_limits(self, label):
                self.checked = label

            def logs_bytes(self):
                return 0

            def managed_bytes(self):
                return ci_sdk.directory_bytes(self.work) + ci_sdk.directory_bytes(self.output)

        limits = Limits()
        limits.work, limits.output = self.work, self.output
        return limits

    def _command(self, *, mismatching=None, wrong_receipt=False):
        invocations = []
        host = native.current_host()
        by_package = {package: variant for variant, (package, _) in ci_sdk.VARIANTS.items()
                      if package != "ami-rust-minimal"}

        def command(label, arguments, expected=0, *, executable):
            invocations.append((label, list(arguments), executable))
            self.assertEqual(executable, self.frontend)
            if arguments[0] == "lock":
                lock_path = Path(arguments[arguments.index("--output") + 1])
                project = Path(arguments[arguments.index("--project") + 1])
                lock_path.write_bytes(b"native project lock fixture\n")
                return auth.encoded({"status": "locked", "output": str(lock_path),
                    "receipt_sha256": auth.sha(auth.read(self.prefix / "install-receipt.json")),
                    "sdk_manifest_sha256": auth.sha(auth.read(project / "contract/sdk.json"))})
            self.assertEqual(arguments[0], "build")
            self.assertFalse((self.output / "native").exists(), "native outputs published before all builds pass")
            self.assertFalse((self.output / "metadata").exists(), "metadata published before all builds pass")
            output = Path(arguments[arguments.index("--output-dir") + 1])
            self.assertTrue(output.parent.is_dir())
            self.assertEqual(output.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(list(output.parent.iterdir()), [],
                             "derived executable parent contains an earlier build")
            package = arguments[arguments.index("--package") + 1]
            cargo_args = arguments[arguments.index("--") + 1:]
            if package == "ami-rust-minimal":
                variant = ("minimal-noalloc" if "--no-default-features" in cargo_args
                           else "minimal-alloc")
            else:
                variant = by_package[package]
            project = Path(cargo_args[cargo_args.index("--manifest-path") + 1]).parent
            layout = project.parent.name
            self.assertEqual(Path(arguments[arguments.index("--sdk-lock") + 1]),
                             project.parent / "project-lock.json")
            self.assertEqual(list(map(str, cargo_args)), [
                "build", "--manifest-path", str(project / "Cargo.toml"),
                "--package", package, "--release", "--locked", "--offline",
                *ci_sdk.VARIANTS[variant][1]])
            artifact_data = self._artifact_bytes(variant)
            if mismatching == (layout, variant):
                artifact_data = dict(artifact_data)
                artifact_data["AMIRUST"] += b" changed-root-bytes"
            artifacts = output / "artifacts"
            rows = {}
            for name, raw in artifact_data.items():
                destination = artifacts / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(raw)
                rows[name] = {"bytes": len(raw), "sha256": auth.sha(raw)}
            byproducts = {}
            for name in ci_sdk.NATIVE_BUILD_BYPRODUCTS:
                raw = ("fixture:" + name).encode()
                (artifacts / name).write_bytes(raw)
                byproducts[name] = raw
            (output / "build-receipt.json").write_bytes(auth.encoded({
                "status": "PASS", "host": host, "canonical_artifacts": rows,
                "project_lock_sha256": ("f" * 64 if wrong_receipt else auth.sha(auth.read(project.parent / "project-lock.json"))),
                "sdk_manifest_sha256": auth.sha(auth.read(project / "contract/sdk.json")),
                "cargo_frontend": {"sha256": "a" * 64}, "commands": [],
                "elapsed_seconds": 0}))
            return auth.encoded({"status": "PASS", "native_executable": str(artifacts / "AMIRUST"),
                                 "receipt": str(output / "build-receipt.json")})

        return command, invocations

    def test_two_root_matrix_runs_all_frozen_variants_and_publishes_after_success(self):
        command, invocations = self._command()
        reference = {"hosts": {native.current_host(): self.rows}}
        with patch.object(native.ci_sdk, "validate_native_reference", return_value=reference):
            matrix = native._qualify_native_build_matrix(
                self.work, self.state, self.frontend, self.output, self._fixture_supervisor(),
                {"sdk_version": "0.2.0"}, command)

        self.assertEqual(matrix["status"], "PASS_CURRENT_HOST_MATRIX_NOT_RC1_ACCEPTANCE")
        self.assertEqual(matrix["root_count"], 2)
        self.assertEqual(matrix["build_count"], 10)
        self.assertEqual(len(matrix["builds"]), 10)
        self.assertEqual(len({row["command_label"] for row in matrix["builds"]}), 10)
        self.assertEqual(len([row for row in invocations if row[1][0] == "lock"]), 2)
        build_calls = [row for row in invocations if row[1][0] == "build"]
        self.assertEqual(len(build_calls), 10)
        self.assertEqual(len({row[0] for row in invocations}), 12)
        self.assertTrue(all(row[2] == self.frontend for row in invocations))
        self.assertEqual([row["identity"]["variant"] for row in matrix["builds"]],
                         list(ci_sdk.VARIANTS) * 2)
        self.assertIn(" ", str(self.work / "native matrix with spaces/sdk-layout-b-with-spaces/sdk"))
        self.assertEqual(len(matrix["retained_native_payloads"]), 5)
        self.assertEqual(len(matrix["retained_dependency_metadata"]), 3)
        for row in matrix["retained_native_payloads"]:
            self.assertEqual((self.output / row["path"]).read_bytes(),
                             ("native fixture for " + row["variant"]).encode())
        for row in matrix["retained_dependency_metadata"]:
            self.assertEqual((self.output / row["path"]).read_bytes(),
                             b"!<arch>\n" + row["crate"].encode())
        self.assertEqual(auth.read(self.state / "selection.json"), self.selection_bytes)
        self.assertFalse((self.work / "native matrix with spaces").exists())
        self.assertFalse((self.work / "pending-native").exists())
        self.assertFalse((self.work / "pending-native-metadata").exists())

    def test_reference_mismatch_copies_bounded_diagnostics_before_failing(self):
        command, _ = self._command(mismatching=("sdk-layout-b-with-spaces", "qualification"))
        reference = {"hosts": {native.current_host(): self.rows}}
        with patch.object(native.ci_sdk, "validate_native_reference", return_value=reference):
            with self.assertRaisesRegex(ValueError, "accepted host reference"):
                native._qualify_native_build_matrix(
                    self.work, self.state, self.frontend, self.output, self._fixture_supervisor(),
                    {"sdk_version": "0.2.0"}, command)

        diagnostics = self.output / "cold-root-diagnostics"
        report = auth.parsed(auth.read(diagnostics / "report.json"))
        self.assertEqual(report["status"], "COLD_ROOT_NATIVE_MISMATCH")
        self.assertEqual(report["variant"], "qualification")
        self.assertEqual(report["first_layout"], "sdk-layout-a")
        self.assertEqual(report["second_layout"], "sdk-layout-b-with-spaces")
        self.assertGreater(report["raw_retained_bytes"], 0)
        self.assertFalse((self.output / "native").exists())
        self.assertFalse((self.output / "metadata").exists())
        self.assertFalse((self.work / "cold-root-diagnostics").exists())

    def test_equal_artifacts_with_a_receipt_for_another_lock_are_refused(self):
        command, _ = self._command(wrong_receipt=True)
        reference = {"hosts": {native.current_host(): self.rows}}
        with patch.object(native.ci_sdk, "validate_native_reference", return_value=reference):
            with self.assertRaisesRegex(ValueError, "selected project lock"):
                native._qualify_native_build_matrix(
                    self.work, self.state, self.frontend, self.output, self._fixture_supervisor(),
                    {"sdk_version": "0.2.0"}, command)
        self.assertFalse((self.output / "native").exists())
        self.assertFalse((self.output / "metadata").exists())

    def test_mismatch_keeps_structured_evidence_when_raw_retention_has_no_headroom(self):
        with (self.output / "previous-command.stdout.json").open("wb") as stream:
            stream.truncate(ci_sdk.MAX_OUTPUT_BYTES - ci_sdk.MAX_COLD_ROOT_DIAGNOSTIC_REPORT_BYTES)
        command, _ = self._command(mismatching=("sdk-layout-b-with-spaces", "qualification"))
        reference = {"hosts": {native.current_host(): self.rows}}
        with patch.object(native.ci_sdk, "validate_native_reference", return_value=reference):
            with self.assertRaisesRegex(ValueError, "accepted host reference"):
                native._qualify_native_build_matrix(
                    self.work, self.state, self.frontend, self.output, self._fixture_supervisor(),
                    {"sdk_version": "0.2.0"}, command)
        report = auth.parsed(auth.read(self.output / "cold-root-diagnostics/report.json"))
        self.assertEqual(report["raw_retention_limit_bytes"], 0)
        self.assertEqual(report["raw_retained_bytes"], 0)
        self.assertGreater(report["raw_omitted_bytes"], 0)
        self.assertLessEqual(ci_sdk.directory_bytes(self.output), ci_sdk.MAX_OUTPUT_BYTES)
        self.assertFalse((self.work / "cold-root-diagnostics").exists())

    def test_signed_package_lifecycle_runs_matrix_before_removal_and_keeps_replay(self):
        self._run_signed_package_lifecycle_matrix_case()

    def test_linux_signed_package_lifecycle_inspects_cold_runtime_before_matrix(self):
        self._run_signed_package_lifecycle_matrix_case(fixture_host="linux-x86_64")

    def test_completed_matrix_report_survives_later_retained_replay_failure(self):
        self._run_signed_package_lifecycle_matrix_case(fail_replay=True)

    def test_linux_completed_matrix_report_survives_retained_replay_refusal(self):
        self._run_signed_package_lifecycle_matrix_case(fail_replay=True, fixture_host="linux-x86_64")

    def test_retained_removal_refuses_changed_global_configuration(self):
        self._run_signed_package_lifecycle_matrix_case(mutate_replay=True)

    def test_linux_retained_removal_refuses_changed_global_configuration(self):
        self._run_signed_package_lifecycle_matrix_case(mutate_replay=True, fixture_host="linux-x86_64")

    def test_failed_published_setup_never_runs_new_consumer_commands(self):
        self._run_signed_package_lifecycle_matrix_case(fail_setup=True)

    def test_failed_historical_interruption_stops_before_new_consumer_observations(self):
        self._run_signed_package_lifecycle_matrix_case(fail_historical_interruption=True)

    def _run_signed_package_lifecycle_matrix_case(self, *, fail_replay=False, mutate_replay=False,
                                                  fail_setup=False, fail_historical_interruption=False,
                                                  fixture_host=None):
        (self.work / "home").mkdir(mode=0o700)
        outer = self.work / "outer"
        metadata = outer / "metadata"
        metadata.mkdir(parents=True)
        # Explicit Linux fixture cases exercise the new read-only reference step
        # even when this suite runs on macOS. Default cases retain native-host coverage.
        host = fixture_host or native.current_host()
        baseline = auth.parsed(auth.read(native.ROOT / "tooling/fixtures/accepted-r1-inputs.json"))["sdk_target"]
        bundle = self.work / "bundle"
        bundle.mkdir(mode=0o700)
        cold_component_rows = []
        cold_reference_binding = None
        identity = {"source_sha": "a" * 40, "run_id": 42, "run_attempt": 2}
        config = {"sdk_version": "0.2.0", "cli_version": "0.2.0-dev"}
        pins = {"source_commit": identity["source_sha"], "sdk_run_id": 42,
                "sdk_run_attempt": 2, "host": host, **config,
                "package_version": "0.2.0-1", "core_sha256": "b" * 64}
        (metadata / ("native-package-inputs-" + host + ".json")).write_bytes(auth.encoded(pins))
        (metadata / "outer-verification.json").write_bytes(auth.encoded({
            "status": "OUTER_CRYPTO_VERIFIED_NOT_R1_ACCEPTED", "source_commit": identity["source_sha"],
            "run_id": 42, "run_attempt": 2}))
        package = self.work / "native-package"
        matrix_calls = []
        commands = []
        observed_command_options = []
        prepared_state = None
        legacy_report = {}
        interruption_order = []
        dummy_archive = b"inert published archive fixture; not an archive authenticity claim\n"
        archive_input = self.work / "published-v1-archive-input.xz"
        archive_input.write_bytes(dummy_archive)
        archive_pin = {"bytes": len(dummy_archive), "sha256": auth.sha(dummy_archive)}

        def compose(*args, **kwargs):
            (package / "bin").mkdir(parents=True)
            (package / "bin/ami-rust").write_bytes(b"inert frontend fixture")

        def command(label, arguments, expected=0, *, executable, **options):
            nonlocal prepared_state
            commands.append(label)
            observed_command_options.append((label, options))
            if legacy_report:
                expected_inert_root = (Path(legacy_report["state"])
                                       / "ami-rust-python-bootstrap/runtime/python")
                self.assertEqual(options.get("inert_python_roots"), (expected_inert_root,
                    self.work / "inert-interrupted-published-state/python-runtime"),
                                 "every post-setup consumer command must exclude the retained v1 runtime")
            else:
                self.assertNotIn("inert_python_roots", options)
            if arguments[0] == "native-package-verify":
                self.assertEqual(label, "09-package-publisher-authentication")
                self.assertEqual(executable, self.work / "xtask")
                return auth.encoded({"status": "OUTER_AND_INNER_AUTHENTICATED"})
            if label == "09-cold-runtime-reference-inspection":
                self.assertEqual(arguments, ["migrate", "--project", legacy_report["project"], "--dry-run"])
                self.assertEqual(executable, package / "bin/ami-rust")
                self.assertEqual(commands, ["09-package-consistency", "09-package-publisher-authentication",
                                            "09-cold-runtime-reference-inspection"])
                self.assertEqual(interruption_order, ["historical"])
                self.assertEqual(matrix_calls, [], "cold reference inspection must precede the native matrix")
                self.assertIsNone(options.get("cold_runtime_reference"))
                return auth.encoded(cold_inspection())
            if cold_reference_binding is not None:
                self.assertEqual(options.get("cold_runtime_reference"), cold_reference_binding,
                                 "validated cold lock binding must reach later consumer observations")
            if label == "16-retained-offline-replay" and fail_replay:
                self.assertFalse(package.exists())
                self.assertEqual(auth.parsed(auth.read(self.output / "native-build-matrix.json")),
                                 {"build_count": 10, "fixture": True})
                raise ValueError("isolated retained replay refusal")
            if arguments[0] == "prepare":
                if expected:
                    return b""
                prepared_state = Path(arguments[arguments.index("--state") + 1])
                self.assertEqual(list(prepared_state.parent.iterdir()), [])
                self.assertEqual(prepared_state.parent.stat().st_mode & 0o777, 0o700)
                prepared_state.mkdir(mode=0o700)
                (prepared_state / "ready.json").write_bytes(b"ready fixture\n")
                retained = prepared_state / "retained/bin/ami-rust"
                retained.parent.mkdir(parents=True)
                retained.write_bytes(b"inert retained fixture")
                return auth.encoded({"status": "READY"})
            if arguments[0] == "new":
                Path(arguments[arguments.index("--project") + 1]).mkdir()
            if arguments[0] == "build":
                build = Path(arguments[arguments.index("--output-dir") + 1])
                (build / "artifacts").mkdir(parents=True)
                (build / "artifacts/AMIRUST").write_bytes(b"native replay fixture")
                (build / "build-receipt.json").write_bytes(b"receipt fixture")
                if executable == prepared_state / "retained/bin/ami-rust":
                    self.assertFalse(package.exists())
                    self.assertEqual(len(matrix_calls), 1)
                    if mutate_replay:
                        (self.work / "home/.cargo/config.toml").chmod(0o644)
                return auth.encoded({"status": "PASS"})
            return b""

        def matrix(work, state, frontend, output, supervisor, selected, callback):
            self.assertEqual((work, state, output), (self.work, prepared_state, self.output))
            self.assertEqual(frontend, package / "bin/ami-rust")
            self.assertTrue(frontend.is_file(), "matrix must run before package removal")
            self.assertEqual(selected, config)
            self.assertIsNot(callback, command)
            callback("matrix-inert-runtime-exclusion-probe", ["verify-package"], executable=frontend)
            self.assertEqual(observed_command_options[-1][1].get("inert_python_roots"),
                             (Path(legacy_report["state"])
                              / "ami-rust-python-bootstrap/runtime/python",
                              self.work / "inert-interrupted-published-state/python-runtime"))
            self.assertIn("14-package-offline-build", commands)
            matrix_calls.append(True)
            return {"build_count": 10, "fixture": True}

        def download_published_archive(work, supervisor):
            self.assertEqual(work, self.work)
            self.assertEqual(Path(supervisor.work), self.work)
            return archive_input

        def prepare_published_legacy(work, output, supervisor, archive_source):
            self.assertEqual((work, output), (self.work, self.output))
            self.assertEqual(Path(supervisor.work), self.work)
            self.assertEqual(Path(archive_source), archive_input)
            area = self.work / "inert-published-v1-setup"
            state = area / "state-parent/ami-rust-0.1.0-state"
            project = area / "project-parent/hello-aros"
            build = area / "build-parent/hello-aros-build"
            package_tree = area / "package-tree"
            home = area / "home"
            archive_copy = area / "ami-rust-0.1.0-packaging.2.tar.xz"
            for directory in (state, project, build, package_tree, home):
                directory.mkdir(mode=0o700, parents=True)
            archive_copy.write_bytes(Path(archive_source).read_bytes())

            ready = {"schema": "ami-rust-package-state-v1", "status": "READY",
                     "sdk_version": "0.1.0", "package_version": "0.1.0-2"}
            (state / "ready.json").write_bytes(auth.encoded(ready))
            retained_root = state / "retained"
            retained_launcher = retained_root / "bin/ami-rust"
            retained_launcher.parent.mkdir(parents=True)
            retained_launcher.write_bytes(b"inert retained v1 launcher identity\n")

            runtime_root = state / "ami-rust-python-bootstrap/runtime/python"
            (runtime_root / "bin").mkdir(parents=True)
            (runtime_root / "lib").mkdir()
            runtime_bytes = b"inert retained v1 Python identity; never executed\n"
            retained_python = runtime_root / "bin/python3.12"
            retained_python.write_bytes(runtime_bytes)
            library_name = ("libpython3.12.dylib" if host == "macos-aarch64"
                            else "libpython3.12.so.1.0")
            (runtime_root / "lib" / library_name).write_bytes(b"inert retained runtime library identity\n")

            sdk_root = state / "sdk-0.1.0/sdk"
            sdk_manifest = sdk_root / "contract/sdk.json"
            sdk_manifest.parent.mkdir(parents=True)
            sdk_manifest_bytes = b'{"fixture":"published-v1"}\n'
            sdk_manifest.write_bytes(sdk_manifest_bytes)
            project_manifest = project / "Cargo.toml"
            project_manifest.write_bytes(b"# inert published project fixture\n")
            project_lock = project / "Cargo.lock"
            project_lock.write_bytes(b"version = 4\n")
            component_roots = {}
            for name in ("rust", "cargo", "toolchain", "collector", "csdk", "vendor"):
                component_root = state / "native-reference-components" / name
                component_root.mkdir(mode=0o700, parents=True)
                component_roots[name] = str(component_root)
                manifest = f"host/profiles/{host}/{name}.json"
                manifest_path = bundle / manifest
                manifest_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                profile_bytes = auth.encoded({"fixture": "linux-cold-runtime-reference",
                                              "host": host, "component": name})
                manifest_path.write_bytes(profile_bytes)
                cold_component_rows.append({"name": name, "root": str(component_root),
                                            "manifest": manifest,
                                            "manifest_sha256": auth.sha(profile_bytes)})
            (bundle / "release.json").write_bytes(auth.encoded({
                "schema": "ami-rust-release-v2", "version": "0.2.0",
                "sdk_files": [{"path": row["manifest"], "sha256": row["manifest_sha256"]}
                              for row in cold_component_rows]}))
            lock = {"schema": "ami-rust-project-lock-v1",
                    "sdk": {"root": str(sdk_root), "manifest": "contract/sdk.json",
                            "manifest_sha256": auth.sha(sdk_manifest_bytes)},
                    "host": {"platform": host, "python": str(retained_python),
                            "python_sha256": auth.sha(runtime_bytes)},
                    "components": component_roots,
                    "cargo": {"manifest_sha256": auth.sha(project_manifest.read_bytes()),
                              "lock_sha256": auth.sha(project_lock.read_bytes())}}
            lock_path = project / "ami-rust.lock.json"
            lock_path.write_bytes(auth.encoded(lock))
            old_executable = build / "artifacts/AMIRUST"
            old_executable.parent.mkdir()
            old_executable.write_bytes(b"inert published v1 executable fixture\n")
            package_root = package_tree / "ami-rust-0.1.0-2/usr/libexec/ami-rust/0.1.0-2"
            package_root.mkdir(mode=0o700, parents=True)
            (package_root / "fixture.txt").write_bytes(b"inert extracted package fixture\n")
            (home / "fixture.txt").write_bytes(b"inert published home fixture\n")

            coordinator_python_root = self.work / "coordinator-python-bootstrap"
            coordinator_python = coordinator_python_root / "runtime/python/bin/python3.12"
            coordinator_python.parent.mkdir(mode=0o700, parents=True)
            coordinator_python.write_bytes(runtime_bytes)
            runtime_relative = "runtime/python/bin/python3.12"
            verified_bootstrap = {
                "schema": "ami-rust-ci-python-bootstrap-v1", "status": "READY_CI_RUNTIME_NOT_SDK_QUALIFICATION",
                "host": host, "version": "3.12.15",
                "target": "x86_64-unknown-linux-gnu" if host == "linux-x86_64" else "aarch64-apple-darwin",
                "relative_files": {"runtime_executable": runtime_relative, "runtime_root": "runtime"},
                "runtime": {"path": runtime_relative, "bytes": len(runtime_bytes),
                            "sha256": auth.sha(runtime_bytes), "version": "3.12.15"},
                "runtime_pin": {"relative_path": "python/bin/python3.12",
                                "sha256": auth.sha(runtime_bytes)},
                "runtime_sha256": auth.sha(runtime_bytes)}
            legacy_report.update({
                "schema": "ami-rust-published-v1-rollback-setup-v1",
                "status": "PASS_ACTUAL_PUBLISHED_V1_SETUP_ORACLE_NOT_RC1_ACCEPTANCE",
                "archive": {"source": str(archive_source), "copy": str(archive_copy),
                            "bytes": len(dummy_archive), "sha256": auth.sha(dummy_archive)},
                "archive_pin": {"bytes": len(dummy_archive), "sha256": auth.sha(dummy_archive)},
                "package_root": str(package_root),
                "package_version_pins": {"sdk_version": "0.1.0", "package_version": "0.1.0-2",
                                          "source_commit": "b4ebb9cce5decd01616b75acf451d0eba9995ee3"},
                "package_pins_sha256": "c" * 64,
                "historical_cli_sha256": auth.sha(b"inert published v1 launcher identity\n"),
                "package_tar": {"members": 1, "regular_file_bytes": 35,
                                "expanded_bytes": 35, "expanded_limit_bytes": 64 * 1024**2,
                                "decoder_memory_limit_bytes": 256 * 1024**2},
                "interpreter": {"path": str(coordinator_python),
                                "root": str(coordinator_python_root), "host": host,
                                "bytes": len(runtime_bytes), "sha256": auth.sha(runtime_bytes),
                                "pin_bytes": len(runtime_bytes), "pin_sha256": auth.sha(runtime_bytes),
                                "bootstrap_sha256": "d" * 64,
                                "verified_bootstrap": verified_bootstrap},
                "state": str(state), "project": str(project), "build": str(build),
                "home": str(home), "tmp": str(area / "tmp"), "package_tree": str(package_tree),
                "retained_root": str(retained_root), "retained_launcher": str(retained_launcher),
                "ready_sha256": auth.sha(auth.encoded(ready)),
                "legacy_lock_sha256": auth.sha(auth.encoded(lock)),
                "native_executable": {"path": str(old_executable),
                                      "bytes": old_executable.stat().st_size,
                                      "sha256": auth.sha(old_executable.read_bytes())},
                "commands": []})
            (area / "tmp").mkdir(mode=0o700)
            if fail_setup:
                legacy_report["status"] = "FAIL_INERT_SETUP_FIXTURE"
            return legacy_report

        def cold_inspection():
            project = Path(legacy_report["project"])
            state = Path(legacy_report["state"])
            lock = project / "ami-rust.lock.json"
            sdk_root = state / "sdk-0.1.0/sdk"
            python = state / "ami-rust-python-bootstrap/runtime/python/bin/python3.12"
            return {
                "status": "migration-required", "project": str(project),
                "legacy_lock": {"path": str(lock), "schema": "ami-rust-project-lock-v1",
                                "sha256": legacy_report["legacy_lock_sha256"]},
                "legacy_sdk": {"root": str(sdk_root), "version": "0.1.0",
                               "manifest": "contract/sdk.json",
                               "manifest_sha256": auth.sha(auth.read(sdk_root / "contract/sdk.json"))},
                "legacy_python": {"path": str(python),
                                  "sha256": legacy_report["interpreter"]["sha256"]},
                "compiler": {key: baseline[key] for key in ("rust_commit", "rust_llvm", "source_date_epoch")},
                "host": host,
                "cargo": {"manifest_sha256": auth.sha(auth.read(project / "Cargo.toml")),
                          "lock_sha256": auth.sha(auth.read(project / "Cargo.lock"))},
                "components": cold_component_rows,
                "selection_missing": False,
                "selection_source": "components embedded in ami-rust-project-lock-v1",
                "migration_required": True,
                "claim": "synthetic lifecycle-order fixture; not migration or SDK evidence",
            }

        def validate_cold_runtime_reference(report, candidate_bundle, inspection, writes, inert_runtimes):
            nonlocal cold_reference_binding
            self.assertIs(report, legacy_report)
            self.assertEqual(candidate_bundle, bundle)
            self.assertEqual(inspection, cold_inspection())
            self.assertEqual(tuple(writes), (self.work / "home", self.work / "tmp",
                                             self.work / "native-state-write-area"))
            self.assertEqual(tuple(inert_runtimes), (
                Path(legacy_report["state"]) / "ami-rust-python-bootstrap/runtime/python",
                self.work / "inert-interrupted-published-state/python-runtime"))
            self.assertEqual(len(cold_component_rows), 6)
            cold_reference_binding = {"path": str(Path(legacy_report["project"]) / "ami-rust.lock.json"),
                                      "sha256": legacy_report["legacy_lock_sha256"]}
            return cold_reference_binding

        def migration(*args, **kwargs):
            self.assertEqual(len(matrix_calls), 1)
            self.assertEqual(kwargs.get("legacy", {}).get("report"), legacy_report)
            area = self.work / "native-published-v1-migration"
            area.mkdir(mode=0o700)
            for name in ("project", "legacy-sdk", "output"):
                (area / name).mkdir(mode=0o700)
            (area / "fixture.txt").write_bytes(b"inert v1 migration preservation root\n")
            return {"status": "SYNTHETIC_ORDER_FIXTURE_NO_MIGRATION_EVIDENCE",
                    "migration_area": str(area)}

        def historical_interruption(work, output, xtask, supervisor, published):
            self.assertIs(published, legacy_report)
            self.assertEqual(commands, ["09-package-consistency", "09-package-publisher-authentication"])
            interruption_order.append("historical")
            if fail_historical_interruption:
                raise ValueError("isolated historical interruption failure")
            area = work / "inert-interrupted-published-state"
            area.mkdir(mode=0o700)
            (area / "sentinel").write_bytes(b"inert interrupted state fixture\n")
            (area / "python-runtime").mkdir(mode=0o700)
            return {"status": "SYNTHETIC_ORDER_FIXTURE_NO_SIGTERM_EVIDENCE", "area": str(area),
                    "runtime_root": str(area / "python-runtime")}

        def native_interruption(work, output, frontend, xtask, callback):
            self.assertEqual(interruption_order, ["historical"])
            interruption_order.append("native")
            callback("interruption-inert-runtime-exclusion-probe", ["verify-package"], executable=frontend)
            return {"status": "SYNTHETIC_ORDER_FIXTURE_NO_SIGTERM_EVIDENCE"}

        # Composition is a stub in this lifecycle-order fixture. Supply inert
        # notice data locally so the test also works in the narrow installer
        # CI checkout; actual legal bytes are checked by package production.
        fixture_source = self.temporary / "source-fixture"
        licenses = fixture_source / "tooling/third-party/licenses"
        licenses.mkdir(parents=True)
        for name in ("LICENSE-MIT", "LICENSE-APACHE"):
            (fixture_source / name).write_bytes(b"inert notice fixture\n")
        (licenses.parent / "THIRD-PARTY-NOTICES.md").write_bytes(b"inert third-party notice fixture\n")
        with patch.object(native, "current_host", return_value=host), \
                patch.object(native, "ROOT", fixture_source), \
                patch.object(native, "PUBLISHED_V1_ARCHIVE_PIN", archive_pin), \
                patch.object(native, "_download_published_v1_archive",
                             side_effect=download_published_archive) as archive_probe, \
                patch.object(native, "_prepare_published_legacy",
                             side_effect=prepare_published_legacy) as setup_probe, \
                patch.object(native, "_published_v1_launcher_version", return_value={
                    "version_output": "ami-rust 0.1.0 (packaging 2)\n"}), \
                patch.object(native, "_supervised_run", side_effect=compose), \
                patch.object(native, "_qualify_native_build_matrix", side_effect=matrix), \
                patch.object(native, "_qualify_native_migration", side_effect=migration) as migration_probe, \
                patch.object(native, "_qualify_native_upgrade", return_value={"fixture": True}), \
                patch.object(native, "_qualify_historical_prepare_interruption",
                             side_effect=historical_interruption) as historical_probe, \
                patch.object(native, "_compare_prepare_interruptions", return_value={
                    "status": "SYNTHETIC_ORDER_FIXTURE_NOT_A_COMPARISON"}) as pair_probe, \
                patch.object(native, "_qualify_prepare_interruption",
                             side_effect=native_interruption) as interruption_probe, \
                patch.object(native, "_validated_cold_runtime_reference",
                             side_effect=validate_cold_runtime_reference) as cold_reference_probe:
            if fail_setup:
                with self.assertRaisesRegex(ValueError, "published 0.1.0 rollback setup did not complete"):
                    native._qualify_native_package(
                        self.work, self.output, outer, self.work / "bundle", self.frontend,
                        self.work / "xtask", self._fixture_supervisor(), self.work / "policy.json",
                        identity, config, command, None, None)
            elif fail_historical_interruption:
                with self.assertRaisesRegex(ValueError, "isolated historical interruption failure"):
                    native._qualify_native_package(
                        self.work, self.output, outer, self.work / "bundle", self.frontend,
                        self.work / "xtask", self._fixture_supervisor(), self.work / "policy.json",
                        identity, config, command, None, None)
            elif fail_replay:
                with self.assertRaisesRegex(ValueError, "isolated retained replay refusal"):
                    native._qualify_native_package(
                        self.work, self.output, outer, self.work / "bundle", self.frontend,
                        self.work / "xtask", self._fixture_supervisor(), self.work / "policy.json",
                        identity, config, command, None, None)
            elif mutate_replay:
                with self.assertRaisesRegex(ValueError, "changed protected state/project/global config"):
                    native._qualify_native_package(
                        self.work, self.output, outer, self.work / "bundle", self.frontend,
                        self.work / "xtask", self._fixture_supervisor(), self.work / "policy.json",
                        identity, config, command, None, None)
            else:
                report = native._qualify_native_package(
                    self.work, self.output, outer, self.work / "bundle", self.frontend,
                    self.work / "xtask", self._fixture_supervisor(), self.work / "policy.json",
                    identity, config, command, None, None)
                self.assertEqual(report["native_matrix"], {"build_count": 10, "fixture": True})
                preservation = report["retained_removal_preservation"]
                self.assertEqual(preservation["before"], preservation["after"])
                self.assertEqual(set(preservation["before"]), {
                    "ready_state_and_retained_tooling", "native_project", "native_first_build",
                    "native_migration_area", "published_v1_state", "published_v1_project",
                    "published_v1_build", "published_v1_package_tree", "published_v1_home",
                    "published_v1_interrupted_prepare",
                    "global_cargo_config", "global_rustup_config", "unrelated_sdk", "user_data"})
        if fail_setup or fail_historical_interruption:
            self.assertFalse((self.output / "native-build-matrix.json").exists())
            self.assertFalse((self.output / "native-cold-runtime-reference.json").exists())
            cold_reference_probe.assert_not_called()
        else:
            self.assertEqual(auth.parsed(auth.read(self.output / "native-build-matrix.json")),
                             {"build_count": 10, "fixture": True})
            if host == "linux-x86_64":
                self.assertEqual(commands[:4], ["09-package-consistency",
                                                "09-package-publisher-authentication",
                                                "09-cold-runtime-reference-inspection",
                                                "10-package-cold-prepare"])
                cold_reference_probe.assert_called_once()
                reference = auth.parsed(auth.read(self.output / "native-cold-runtime-reference.json"))
                self.assertEqual(reference["schema"], "ami-rust-cold-native-runtime-reference-v1")
                self.assertEqual(reference["binding"], cold_reference_binding)
                self.assertEqual(reference["compiler"], cold_inspection()["compiler"])
                self.assertEqual(reference["components"], cold_component_rows)
                self.assertEqual(reference["candidate_manifest_sha256"],
                                 auth.sha(auth.read(bundle / "release.json")))
            else:
                self.assertFalse((self.output / "native-cold-runtime-reference.json").exists())
                cold_reference_probe.assert_not_called()
        archive_probe.assert_called_once_with(self.work, ANY)
        setup_probe.assert_called_once_with(self.work, self.output, ANY, archive_input)
        if fail_setup or fail_historical_interruption:
            self.assertEqual(commands, ["09-package-consistency", "09-package-publisher-authentication"])
            interruption_probe.assert_not_called()
            migration_probe.assert_not_called()
            pair_probe.assert_not_called()
            if fail_setup:
                historical_probe.assert_not_called()
            else:
                historical_probe.assert_called_once()
            self.assertTrue(package.exists())
        else:
            self.assertEqual(interruption_order, ["historical", "native"])
            historical_probe.assert_called_once()
            pair_probe.assert_called_once()
            interruption_probe.assert_called_once()
            migration_probe.assert_called_once()
            self.assertEqual(commands[-2:], ["15-retained-input-recheck", "16-retained-offline-replay"])
            self.assertFalse(package.exists())


class PrepareInterruptionPairTests(unittest.TestCase):
    """Synthetic adapter controls; no child execution or SDK acceptance claim."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ami-rust-interruption-controls-")
        self.root = Path(self.temporary.name).resolve()
        self.identity = {"source_sha": "a" * 40}
        self.config = {"sdk_version": "0.2.0", "cli_version": "0.2.0-dev"}

    def tearDown(self):
        self.temporary.cleanup()

    def run_pair(self, name, *, historical_change=None, native_change=None, retry_mutation=False):
        area = self.root / name
        area.mkdir(mode=0o700)
        work, output = area / "work", area / "output"
        work.mkdir(mode=0o700)
        output.mkdir(mode=0o700)
        cli = area / "cli.py"
        runtime_root = area / "bootstrap/runtime/python"
        (runtime_root / "bin").mkdir(parents=True)
        python = runtime_root / "bin/python3.12"
        cli.write_bytes(b"inert historical CLI fixture")
        python.write_bytes(b"inert interpreter fixture")
        published = {"package_root": str(area), "historical_cli_sha256": auth.sha(cli.read_bytes()),
                     "interpreter": {"path": str(python), "root": str(area / "bootstrap"),
                                     "sha256": auth.sha(python.read_bytes())},
                     "package_version_pins": {"source_commit": "b" * 40, "sdk_version": "0.1.0"}}
        supervisor = SimpleNamespace(work=work, output=output, env={"sentinel": "restore me"})
        original_env = supervisor.env

        def supervise(_supervisor, argv, *, label, cwd, expected=0):
            stdout, stderr = output / (label + ".stdout"), output / (label + ".stderr")
            payload = b""
            refusal = b""
            if label == "09-published-prepare-sigterm":
                state = Path(argv[argv.index("--state") + 1])
                driver = Path(argv[argv.index("--output") + 1])
                state.mkdir(mode=0o700)
                retained = state / "retained/libexec/ami-rust/0.1.0-2/cli.py"
                retained.parent.mkdir(parents=True)
                retained.write_bytes(cli.read_bytes())
                driver.mkdir(mode=0o700)
                for stream in ("stdout", "stderr"):
                    (driver / ("prepare." + stream + ".raw")).write_bytes(b"")
                observation = {"attempted": True, "signal_sent": True, "direct_child_raw_signal": 15,
                    "direct_child_exit_code": None, "shell_convention_status": 143,
                    "shell_was_invoked": False, "helper_interrupted": False,
                    "fetch_head_at_signal": {"path": str(state / "source/.git/FETCH_HEAD"),
                        "regular_file": True, "size_bytes": 0, "uid": os.getuid(),
                        "READY_absent": True, "ci_python_absent": True,
                        "index_absent": True, "ready_json_absent": True}}
                report = {"status": "OBSERVED_FETCH_STAGE_SIGTERM", "observation": observation,
                    "command": {"program": str(argv[argv.index("--python") + 1]),
                        "argv": ["-I", "-B", str(cli), "prepare", "--state", str(state)],
                        "python_sha256": published["interpreter"]["sha256"],
                        "frontend_sha256": published["historical_cli_sha256"]},
                    "post_capture": {"READY_present": False, "ci_python_present": False,
                        "git_index_present": False, "ready_json_present": False, "later_stage_markers": []},
                    "capture": {"accepted_path": "DescendantRetainedPipe-cleaned-and-reaped",
                        "result": "capture-error", "cause": "DescendantRetainedPipe", "cleanup_error": None,
                        "cleanup_outcome": "accepted-path-with-no-reported-cleanup-error",
                        **{stream: {"path": "prepare." + stream + ".raw", "bytes": 0,
                                    "sha256": auth.sha(b"")} for stream in ("stdout", "stderr")}}}
                if historical_change:
                    historical_change(report, state)
                (driver / "preparation-capture.json").write_bytes(auth.encoded(report))
                payload = auth.encoded({"status": "OBSERVED_FETCH_STAGE_SIGTERM",
                                        "report": str(driver / "preparation-capture.json")})
            elif label == "09-published-prepare-retry-refusal":
                refusal = (b"ami-rust: preparation requires a fresh state; "
                           b"failed states are retained for diagnosis\n")
            stdout.write_bytes(payload)
            stderr.write_bytes(refusal)
            return {"stdout_log": str(stdout.relative_to(work.parent)),
                    "stderr_log": str(stderr.relative_to(work.parent)), "exit_code": expected}

        # The real supervisor stores log paths relative to work. Keep this
        # fixture's log files there as well, rather than imitating execution.
        def supervised(*args, **kwargs):
            row = supervise(*args, **kwargs)
            for key in ("stdout_log", "stderr_log"):
                row[key] = os.path.relpath(area / row[key], work)
            return row

        frontend = area / "ami-rust"
        frontend.write_bytes(b"inert new CLI fixture")

        def command(label, arguments, expected=0, **options):
            if label == "09-public-prepare-sigterm":
                state = Path(arguments[arguments.index("--state") + 1])
                driver = Path(arguments[arguments.index("--output") + 1])
                state.mkdir(mode=0o700)
                (state / "retained/bin").mkdir(parents=True)
                (state / "retained/bin/ami-rust").write_bytes(frontend.read_bytes())
                failure = {"schema": "ami-rust-prepare-failure-v1", "phase": "source-checkout",
                           "ready": False, "state_retained": True}
                (state / "prepare-failure.json").write_bytes(auth.encoded(failure))
                driver.mkdir(mode=0o700)
                for stream in ("stdout", "stderr"):
                    (driver / (stream + ".raw")).write_bytes(b"")
                report = {"status": "OBSERVED_EXPECTED_PREPARE_INTERRUPTION",
                    "launcher": {"sha256": auth.sha(frontend.read_bytes())},
                    "signal": {"sent": True, "helper_interrupted": False},
                    "package": {"source_commit": self.identity["source_sha"],
                                "host": native.current_host(), **self.config},
                    "capture": {"actual_child_exit_code": 143, "actual_child_signal": None,
                                "error": None, **{stream: {"bytes": 0, "sha256": auth.sha(b"")}
                                                  for stream in ("stdout", "stderr")}}}
                if native_change:
                    native_change(report, state)
                (driver / "report.json").write_bytes(auth.encoded(report))
                return auth.encoded({"actual_child_exit_code": 143, "helper_exit_code": 0})
            if label == "09-interrupted-state-retry-refusal":
                (output / (label + ".stderr.log")).write_bytes(b"ami-rust: state path must be fresh\n")
                if retry_mutation:
                    state = Path(arguments[arguments.index("--state") + 1])
                    (state / "retained/bin/ami-rust").chmod(0o777)
            return b""

        with patch.object(native, "_supervised_run", side_effect=supervised), \
                patch.object(native, "_check_limits"):
            try:
                old = native._qualify_historical_prepare_interruption(
                    work, output, area / "xtask", supervisor, published)
                new = native._qualify_prepare_interruption(work, output, frontend, area / "xtask", command)
                return old, new, native._compare_prepare_interruptions(old, new, self.identity, self.config)
            finally:
                self.assertIs(supervisor.env, original_env)

    def test_pair_preserves_deliberate_signal_and_receipt_differences(self):
        old, new, paired = self.run_pair("positive")
        self.assertEqual(paired["status"], "PASS_ACTUAL_HOST_PREPARE_INTERRUPTION_SEMANTIC_PAIR")
        self.assertIsNone(old["failure_receipt"])
        self.assertEqual(new["failure_receipt"]["record"]["phase"], "source-checkout")
        raw_receipt = auth.read(self.root / "positive/output/native-prepare-interruption-captures/prepare-failure.json")
        self.assertEqual(auth.parsed(raw_receipt), new["failure_receipt"]["record"])
        self.assertEqual(auth.sha(raw_receipt), new["failure_receipt"]["sha256"])
        self.assertNotEqual(paired["historical_package"]["source_commit"],
                            paired["native_package"]["source_commit"])
        for index, value in enumerate(({}, {**old, "retry_exit_code": 0},
                                       {**old, "retry_state_snapshot_sha256": "0" * 64})):
            with self.subTest(index=index), self.assertRaises(ValueError):
                native._compare_prepare_interruptions(value, new, self.identity, self.config)

    def test_historical_invalid_capture_cannot_form_a_pair_and_keeps_raw_evidence(self):
        changes = [lambda report, state: report["capture"].update(cleanup_error="EPERM"),
                   lambda report, state: report["observation"].update(direct_child_raw_signal=None),
                   lambda report, state: report["observation"].update(helper_interrupted=True),
                   lambda report, state: report["observation"]["fetch_head_at_signal"].update(size_bytes=1),
                   lambda report, state: report["command"].update(frontend_sha256="0" * 64),
                   lambda report, state: report["capture"]["stdout"].update(sha256="0" * 64)]
        for index, change in enumerate(changes):
            name = "bad-old-" + str(index)
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.run_pair(name, historical_change=change)
            output = self.root / name / "output"
            self.assertEqual(auth.parsed(auth.read(output / "historical-prepare-interruption.json"))["status"], "FAIL")
            self.assertTrue((output / "historical-prepare-interruption-captures/prepare.stdout.raw").is_file())

    def test_native_invalid_effects_and_changed_retry_cannot_form_a_pair(self):
        changes = [lambda report, state: report["capture"].update(actual_child_signal=15),
                   lambda report, state: report["capture"].update(error="cleanup failed"),
                   lambda report, state: (state / "sdk-0.2.0").mkdir(),
                   lambda report, state: (state / "ready.json").symlink_to("missing-ready"),
                   lambda report, state: (state / "receipt.sha256").write_bytes(b"premature"),
                   lambda report, state: (state / "prepare-failure.json").write_bytes(auth.encoded({"ready": True}))]
        for index, change in enumerate(changes):
            name = "bad-new-" + str(index)
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.run_pair(name, native_change=change)
            output = self.root / name / "output"
            self.assertEqual(auth.parsed(auth.read(output / "native-prepare-interruption.json"))["status"], "FAIL")
            self.assertTrue((output / "native-prepare-interruption-captures/stderr.raw").is_file())
        with self.assertRaisesRegex(ValueError, "changed retained ownership"):
            self.run_pair("changed-retry", retry_mutation=True)


class NativeColdRuntimeReferenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ami-rust cold reference ")
        self.root = Path(self.temporary.name).resolve()
        self.state, self.project, self.bundle = (self.root / name for name in ("old-state", "old-project", "bundle"))
        for path in (self.state, self.project, self.bundle):
            path.mkdir(mode=0o700)
        self.host = patch.object(native, "current_host", return_value="linux-x86_64")
        self.host.start()
        self.addCleanup(self.host.stop)
        self.addCleanup(self.temporary.cleanup)
        self.baseline = auth.parsed(auth.read(native.ROOT / "tooling/fixtures/accepted-r1-inputs.json"))["sdk_target"]
        self.components = []
        for name in ("cargo", "collector", "csdk", "rust", "toolchain", "vendor"):
            root = self.state / name
            root.mkdir(mode=0o700)
            self.components.append({"name": name, "root": str(root),
                "manifest": f"host/profiles/linux-x86_64/{name}.json", "manifest_sha256": auth.sha(name.encode())})
        self.lock = self.project / "ami-rust.lock.json"
        self.lock.write_bytes(auth.encoded({"components": {r["name"]: r["root"] for r in self.components}}))
        (self.state / "ready.json").write_bytes(b'{"fixture":"validated by native dry-run in production"}\n')
        self.report = {"status": "PASS_ACTUAL_PUBLISHED_V1_SETUP_ORACLE_NOT_RC1_ACCEPTANCE",
            "archive_pin": native.PUBLISHED_V1_ARCHIVE_PIN,
            "package_version_pins": {"source_commit": self.baseline["source_identity"]},
            "state": str(self.state), "project": str(self.project),
            "legacy_lock_sha256": auth.sha(auth.read(self.lock)),
            "ready_sha256": auth.sha(auth.read(self.state / "ready.json"))}
        self.inspection = {"status": "migration-required", "host": "linux-x86_64", "migration_required": True,
            "legacy_lock": {"path": str(self.lock), "sha256": self.report["legacy_lock_sha256"]},
            "compiler": {key: self.baseline[key] for key in ("rust_commit", "rust_llvm", "source_date_epoch")},
            "components": self.components}
        self.manifest = {"sdk_files": [{"path": r["manifest"], "sha256": r["manifest_sha256"]}
                                      for r in self.components]}
        self.write_manifest()
        for relative in ("release/ci-sdk-inputs.json", "release/ci-cargo-producers/linux-x86_64.json"):
            path = self.state / "source" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(auth.read(native.ROOT / relative))
        self.writes = (self.root / "new-state-area",)
        self.inert = (self.state / "ami-rust-python-bootstrap/runtime/python",)

    def write_manifest(self):
        (self.bundle / "release.json").write_bytes(auth.encoded(self.manifest))

    def validate(self):
        return native._validated_cold_runtime_reference(self.report, self.bundle, self.inspection,
                                                       self.writes, self.inert)

    def test_same_current_candidate_inventories_admit_only_the_bound_read_only_lock(self):
        self.assertEqual(self.validate(), {"path": str(self.lock), "sha256": self.report["legacy_lock_sha256"]})
        self.assertFalse(self.writes[0].exists())

    def test_changed_compiler_or_current_candidate_manifest_refuses(self):
        self.inspection["compiler"]["rust_commit"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "compiler differs"):
            self.validate()
        self.inspection["compiler"]["rust_commit"] = self.baseline["rust_commit"]
        self.manifest["sdk_files"][0]["sha256"] = "0" * 64
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "components differ"):
            self.validate()

    def test_changed_lock_ready_and_source_pins_refuse_before_discovery(self):
        for path in (self.lock, self.state / "ready.json",
                     self.state / "source/release/ci-sdk-inputs.json"):
            original = path.read_bytes()
            with self.subTest(path=path):
                path.write_bytes(original + b"\n")
                with self.assertRaisesRegex(ValueError, "binding|source pins"):
                    self.validate()
                path.write_bytes(original)

    def test_incomplete_duplicate_and_overlapping_component_references_refuse(self):
        original = self.inspection["components"]
        for rows in (original[:-1], [original[0], *original[1:-1], original[0]]):
            self.inspection["components"] = rows
            with self.assertRaisesRegex(ValueError, "exact six"):
                self.validate()
        self.inspection["components"] = original
        self.writes = (self.state / "rust",)
        with self.assertRaisesRegex(ValueError, "overlap"):
            self.validate()
        self.writes = (self.root / "new-state-area",)
        self.inert = (self.state / "rust",)
        with self.assertRaisesRegex(ValueError, "overlap"):
            self.validate()

    def test_wrong_host_source_and_duplicate_candidate_paths_refuse(self):
        self.inspection["host"] = "macos-aarch64"
        with self.assertRaisesRegex(ValueError, "published Linux"):
            self.validate()
        self.inspection["host"] = "linux-x86_64"
        self.report["package_version_pins"]["source_commit"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "published Linux"):
            self.validate()
        self.report["package_version_pins"]["source_commit"] = self.baseline["source_identity"]
        self.manifest["sdk_files"].append(self.manifest["sdk_files"][0])
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, "duplicate paths"):
            self.validate()


class NativeObservationSpecTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ami-rust-observed phase ")
        self.root = Path(self.temporary.name).resolve()
        self.work = self.root / "work"
        self.work.mkdir(mode=0o700)
        for name in ("home", "tmp"):
            (self.work / name).mkdir(mode=0o700)
        self.cli = self.work / "cli"
        self.cli.write_bytes(b"inert frontend, no runtime claim\n")
        self.policy = self.root / "policy.json"
        self.policy.write_bytes(auth.encoded({name: {"path": "/usr/bin/true"} for name in ("gh", "cosign")}))
        self.closure = self.root / "reviewed-inputs.json"
        self.closure.write_bytes(b'{"fixture":true}\n')
        self.area = self.work / "state-area"
        self.area.mkdir(mode=0o700)
        self.derived = self.area / "derived"
        self.derived.mkdir(mode=0o700)
        self.state = self.derived / "state"

    def tearDown(self):
        self.temporary.cleanup()

    def spec(self, arguments, expected=0, **kwargs):
        return native._consumer_observation_spec(self.work, self.root / "python", self.cli,
            arguments, expected, self.policy, self.closure, [], **kwargs)

    def ready(self):
        self.state.mkdir(mode=0o700)
        (self.state / "selection.json").write_bytes(b'{"components":{}}\n')

    def test_cold_state_has_one_private_derived_parent_and_explicit_bindings(self):
        spec = self.spec(["prepare", "--state", self.state])
        self.assertEqual(spec["phase"], "cold-prepare")
        self.assertEqual(spec["derived"], {"role": "consumer-state-parent", "path": str(self.derived)})
        self.assertIsNone(spec["component_record"])
        self.assertIn(str(self.area), [row["path"] for row in spec["write_trees"]])
        self.assertEqual(spec["bindings"][0]["sha256"], auth.sha(auth.read(self.closure)))

    def test_account_home_is_only_a_literal_directory_read(self):
        lock = self.work / "lock.json"
        lock.write_bytes(b'{"components":{}}\n')
        spec = self.spec(["verify", "--sdk-lock", lock])
        account_home = str(Path(native.pwd.getpwuid(native.os.getuid()).pw_dir).resolve(strict=True))
        self.assertEqual(spec["read_directories"], [account_home])
        self.assertNotIn(account_home, [row["path"] for row in spec["read_trees"]])
        self.assertNotIn(account_home, [row["path"] for row in spec["write_trees"]])

    def test_cold_runtime_reference_is_bound_without_changing_the_fresh_state(self):
        record = self.work / "validated-old-lock.json"
        record.write_bytes(b'{"components":{}}\n')
        reference = {"path": str(record), "sha256": auth.sha(record.read_bytes())}
        spec = self.spec(["prepare", "--state", self.state], cold_runtime_reference=reference)
        self.assertEqual(spec["component_record"], str(record))
        self.assertIn(reference, spec["bindings"])
        self.assertEqual(spec["command"][-1], str(self.state))
        self.assertFalse(self.state.exists())
        self.assertNotIn(str(record.parent), [row["path"] for row in spec["write_trees"]])
        record.write_bytes(b"changed after validation")
        with self.assertRaisesRegex(ValueError, "reference changed"):
            self.spec(["prepare", "--state", self.state], cold_runtime_reference=reference)

    def test_denied_interpreter_uses_the_actual_bootstrap_runtime_layout(self):
        spec = self.spec(["verify-package"])
        self.assertEqual(spec["deny_exec"],
                         [str(self.root / "python/runtime/python/bin/python3.12")])
        self.assertTrue(spec["deny_library"][0].startswith(str(self.root / "python/runtime/python/lib")))

    def test_ready_checks_and_expected_prepare_refusals_never_write_state(self):
        self.ready()
        for arguments, expected, phase in ((["check-inputs", "--state", self.state], 0, "check-inputs"),
                (["prepare", "--state", self.state], 2, "prepare-refusal")):
            spec = self.spec(arguments, expected)
            self.assertEqual(spec["phase"], phase)
            self.assertIsNone(spec["derived"])
            self.assertEqual(spec["component_record"], str(self.state / "selection.json"))
            self.assertEqual({row["path"] for row in spec["write_trees"]},
                             {str(self.work / "home"), str(self.work / "tmp")})

    def test_build_writes_its_own_area_and_binds_the_actual_project_lock(self):
        self.ready()
        area = self.work / "build-area"
        parent = area / "derived"
        parent.mkdir(mode=0o700, parents=True)
        lock = self.work / "project-lock.json"
        lock.write_bytes(b'{"components":{}}\n')
        spec = self.spec(["build", "--sdk-lock", lock, "--output-dir", parent / "build"])
        self.assertEqual(spec["derived"], {"role": "consumer-build-parent", "path": str(parent)})
        self.assertEqual(spec["component_record"], str(lock))
        self.assertIn(str(area), [row["path"] for row in spec["write_trees"]])
        self.assertNotIn(str(self.work), [row["path"] for row in spec["write_trees"]])

    def test_package_authentication_uses_the_same_observed_command_surface(self):
        spec = self.spec(["native-package-verify", "--work", self.work / "auth-work"])
        self.assertEqual(spec["phase"], "package-authentication")
        self.assertEqual(spec["write_trees"], [{"role": "work", "path": str(self.work)}])
        self.assertEqual(spec["expected_exit"], 0)

    def test_interruption_driver_binds_only_its_actual_frontend_and_fresh_state_parent(self):
        spec = self.spec(["native-prepare-interruption", "--frontend", self.cli,
            "--state", self.state, "--home", self.work / "home", "--tmp", self.work / "tmp",
            "--output", self.area / "driver"])
        self.assertEqual(spec["phase"], "cold-prepare")
        self.assertEqual(spec["derived"]["path"], str(self.derived))
        self.assertIn(str(self.cli), spec["executables"])
        self.assertNotIn(str(self.cli.parent), spec["executables"])
        self.assertNotIn(str(self.work), [row["path"] for row in spec["write_trees"]])

    def test_retained_snapshot_detects_mode_and_empty_directory_changes(self):
        self.ready()
        selected = self.state / "selection.json"
        selected.chmod(0o644)
        before = native._retained_state_snapshot(self.state)
        self.assertEqual(before, native._retained_state_snapshot(self.state))
        selected.chmod(0o600)
        self.assertNotEqual(before, native._retained_state_snapshot(self.state))
        selected.chmod(0o644)
        before = native._retained_state_snapshot(self.state)
        (self.state / "empty").mkdir()
        self.assertNotEqual(before, native._retained_state_snapshot(self.state))

    def test_migration_binds_legacy_lock_and_reads_interpreter_without_execution(self):
        legacy = self.work / "legacy"
        legacy.mkdir(mode=0o700)
        interpreter = legacy / "python"
        interpreter.write_bytes(b"inert interpreter identity, never executed\n")
        lock = legacy / "old-lock.json"
        lock.write_bytes(auth.encoded({"schema": "ami-rust-project-lock-v1",
                                      "host": {"python": str(interpreter)}}))
        destination = self.work / "migration-output"
        destination.mkdir(mode=0o700)
        args = ["migrate", "--project", legacy, "--from-lock", lock,
                "--output", destination / "native-lock.json"]
        spec = self.spec(args)
        self.assertEqual(spec["phase"], "lock")
        self.assertEqual(spec["component_record"], str(lock))
        self.assertIn({"path": str(lock), "sha256": auth.sha(lock.read_bytes())}, spec["bindings"])
        self.assertEqual(spec["read_files"], [str(interpreter)])
        if native.current_host() == "linux-x86_64":
            self.assertNotIn(str(interpreter), spec["deny_exec"])
        else:
            self.assertIn(str(interpreter), spec["deny_exec"])
        self.assertNotIn(str(interpreter), spec["executables"])
        self.assertIn(str(destination), [row["path"] for row in spec["write_trees"]])
        self.assertNotIn(str(legacy), [row["path"] for row in spec["write_trees"]])
        lock.write_bytes(auth.encoded({"schema": "ami-rust-project-lock-v2"}))
        with self.assertRaisesRegex(ValueError, "inert legacy v1"):
            self.spec(args)
        with self.assertRaisesRegex(ValueError, "explicit legacy lock and output"):
            self.spec(["migrate", "--project", legacy])

    def test_migration_inspection_binds_conventional_lock_without_output_writes(self):
        project = self.work / "inspection-project"
        project.mkdir(mode=0o700)
        interpreter = project / "python"
        interpreter.write_bytes(b"inert identity")
        lock = project / "ami-rust.lock.json"
        lock.write_bytes(auth.encoded({"schema": "ami-rust-project-lock-v1",
                                      "host": {"python": str(interpreter)}}))
        result = self.spec(["migrate", "--project", project, "--dry-run"])
        self.assertIsNone(result["component_record"])
        self.assertIn({"path": str(lock), "sha256": auth.sha(lock.read_bytes())}, result["bindings"])
        self.assertEqual({row["path"] for row in result["write_trees"]},
                         {str(self.work / "home"), str(self.work / "tmp")})
        self.assertIsNone(result["derived"])
        self.assertIn(str(interpreter), result["read_files"])

    def test_preservation_snapshot_detects_same_bytes_replaced_output(self):
        root = self.work / "existing-output"
        root.mkdir(mode=0o700)
        target = root / "lock.json"
        target.write_bytes(b"same accepted lock bytes\n")
        before = native._preservation_snapshot({"output": root})
        replacement = root / "replacement.json"
        replacement.write_bytes(target.read_bytes())
        replacement.replace(target)
        self.assertEqual(target.read_bytes(), b"same accepted lock bytes\n")
        self.assertNotEqual(before, native._preservation_snapshot({"output": root}))

    def test_disposable_retry_can_write_only_its_partial_state_to_expose_mutations(self):
        self.state.mkdir(mode=0o700)
        args = ["prepare", "--state", self.state]
        spec = self.spec(args, 2, disposable_refusal_state=self.state)
        self.assertIn(str(self.state), [row["path"] for row in spec["write_trees"]])
        self.assertNotIn(str(self.derived), [row["path"] for row in spec["write_trees"]])
        self.assertIsNone(spec["derived"])
        (self.state / "selection.json").write_bytes(b"{}")
        with self.assertRaisesRegex(ValueError, "disposable retry grant"):
            self.spec(args, 2, disposable_refusal_state=self.state)

    def test_unknown_observer_phase_is_refused(self):
        with self.assertRaisesRegex(ValueError, "unsupported observed consumer command"):
            self.spec(["unsupported-command"])

    def test_links_are_data_and_external_targets_are_never_in_the_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary).resolve();root=base/'preserved';root.mkdir()
            external=base/'external';external.mkdir();target=external/'private';target.write_bytes(b'outside-one')
            (root/'absolute').symlink_to(target)
            (root/'dangling').symlink_to(base/'missing')
            (root/'directory').symlink_to(external,target_is_directory=True)
            before=native._retained_state_snapshot(root)
            self.assertEqual(before,native._retained_state_snapshot(root))
            self.assertEqual(before['inventory']['files'],[])
            self.assertEqual({row['target'] for row in before['inventory']['symlinks']},{str(target),str(base/'missing'),str(external)})
            self.assertEqual(len(before['metadata']),4)
            target.write_bytes(b'outside-two');self.assertEqual(before,native._retained_state_snapshot(root))
            (root/'absolute').unlink();(root/'absolute').symlink_to(base/'different')
            self.assertNotEqual(before,native._retained_state_snapshot(root))
    def test_file_bytes_metadata_and_empty_directories_are_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();p=root/'file';p.write_bytes(b'one')
            before=native._retained_state_snapshot(root);p.write_bytes(b'two')
            self.assertNotEqual(before,native._retained_state_snapshot(root))
            before=native._retained_state_snapshot(root);(root/'empty').mkdir()
            self.assertNotEqual(before,native._retained_state_snapshot(root))
            with self.assertRaisesRegex(ValueError,'entry limit'):native._retained_state_snapshot(root,entry_limit=1)

    def test_unreadable_subtree_refuses_instead_of_omitting_writable_known_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();directory=root/'opaque';directory.mkdir()
            child=directory/'known';child.write_bytes(b'old')
            directory.chmod(0o300)
            try:
                with self.assertRaises(PermissionError):native._retained_state_snapshot(root)
                child.write_bytes(b'new')
                with self.assertRaises(PermissionError):native._retained_state_snapshot(root)
            finally:directory.chmod(0o700)
    def test_root_symlink_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();(root/'actual').mkdir();(root/'alias').symlink_to(root/'actual',target_is_directory=True)
            with self.assertRaisesRegex(ValueError,'root must be a real directory'):native._retained_state_snapshot(root/'alias')



class NativeMigrationPreservationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ami-rust-migration-preservation-")
        self.root = Path(self.temporary.name).resolve()
        self.work, self.output = self.root / "work", self.root / "output"
        self.state, self.project = self.work / "state", self.work / "project"
        self.prefix = self.state / "sdk-fixture"
        for directory in (self.work, self.output, self.state, self.project, self.prefix):
            directory.mkdir(mode=0o700)
        (self.state / "ready.json").write_bytes(auth.encoded({"sdk_version": "fixture"}))
        self.receipt = b"inert receipt, no authentication claim\n"
        (self.prefix / "install-receipt.json").write_bytes(self.receipt)
        self.manifest = self.project / "Cargo.toml"
        self.manifest.write_bytes(b"# inert preserved project\n")
        self.manifest.chmod(0o600)
        self.supervisor = SimpleNamespace(python_root=self.work / "inert-python")
        self.area = self.work / "native-legacy-migration-fixture"

    def tearDown(self):
        self.temporary.cleanup()

    def generate(self, *_args, **_kwargs):
        for directory in (self.area, self.area / "project", self.area / "legacy-sdk", self.area / "output"):
            directory.mkdir(mode=0o700)
        fixture = {"status": "SYNTHETIC_BASELINE_COMPATIBLE_FIXTURE_NOT_HISTORICAL_EVIDENCE",
                   "project": str(self.area / "project"),
                   "from_lock": str(self.area / "project/ami-rust.lock.json"),
                   "migration_output": str(self.area / "output/migrated-v2-lock.json"),
                   "receipt_pin": {"sha256": auth.sha(self.receipt)}}
        (self.work / "fixture.stdout.json").write_bytes(auth.encoded(fixture))
        return {"stdout_log": "fixture.stdout.json"}

    def qualify(self, generator, command):
        with patch.object(native, "_supervised_run", side_effect=generator):
            return native._qualify_native_migration(self.work, self.output, self.state, self.project,
                self.work / "inert-cli", self.work / "inert-xtask", self.supervisor, command,
                b"inert reference", {})

    def test_fixture_generation_cannot_change_original_project_before_baseline(self):
        def generator(*args, **kwargs):
            result = self.generate(*args, **kwargs)
            self.manifest.chmod(0o644)
            return result
        with self.assertRaisesRegex(ValueError, "fixture generation changed existing inputs"):
            self.qualify(generator, lambda *_args, **_kwargs: self.fail("public command ran after mutation"))

    def test_wrong_receipt_cannot_leave_neighboring_temporary_output(self):
        def command(label, _args, expected, **_kwargs):
            self.assertEqual((label, expected), ("21-migration-wrong-receipt", 2))
            (self.output / (label + ".stderr.log")).write_bytes(
                b"ami-rust: installed receipt differs from the external pin\n")
            (self.area / "output/leftover-temporary-file").write_bytes(b"unexpected write\n")
        with self.assertRaisesRegex(ValueError, "refused migration changed its output area"):
            self.qualify(self.generate, command)
        self.assertFalse((self.area / "output/migrated-v2-lock.json").exists())

    def test_wrong_receipt_requires_the_actual_receipt_pin_refusal(self):
        def command(label, _args, expected, **_kwargs):
            self.assertEqual((label, expected), ("21-migration-wrong-receipt", 2))
            (self.output / (label + ".stderr.log")).write_bytes(b"unrelated setup refusal\n")
        with self.assertRaisesRegex(ValueError, "missed the receipt-pin refusal"):
            self.qualify(self.generate, command)


class NativeSupervisorAdditionalTests(unittest.TestCase):
    def setUp(self):
        self.temporary = Path(tempfile.mkdtemp(prefix="ami-rust-native-supervisor-test-")).resolve()
        self.work = self.temporary / "work"
        self.output = self.temporary / "output"
        self.python_root = self.temporary / "ami-rust-python-bootstrap"
        for path in (self.work, self.output, self.python_root):
            path.mkdir()

    def tearDown(self):
        shutil.rmtree(self.temporary)

    def test_existing_supervisor_records_stdout_stderr_and_expected_failure(self):
        env = native._clean_child_env({"PATH": "/usr/bin:/bin", "CARGO_REGISTRY_TOKEN": "test-token",
                                       "CARGO_REGISTRIES_CRATES_IO_TOKEN": "test-token-2"})
        with patch.object(native.ci_sdk, "verify_python_bootstrap", return_value=(Path(sys.executable), {})):
            supervisor = native._make_supervisor(self.work, self.output, self.python_root, env)
        text = native._supervised_text(
            supervisor,
            [sys.executable, "-c", "import os; print('token=' + str('CARGO_REGISTRY_TOKEN' in os.environ))"],
            label="native-test-clean-env", timeout=10)
        self.assertEqual(text, "token=False\n")

        row = native._supervised_run(
            supervisor,
            [sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr); raise SystemExit(2)"],
            label="native-test-expected-exit", timeout=10, expected=2)
        self.assertEqual(row["exit_code"], 2)
        self.assertIsNone(row["stop_reason"])
        stdout = self.work / row["stdout_log"]
        stderr = self.work / row["stderr_log"]
        self.assertEqual(stdout.read_text(), "out\n")
        self.assertEqual(stderr.read_text(), "err\n")

    def test_local_launcher_comparison_is_exact(self):
        local = self.temporary / "local-cli"
        remote = self.temporary / "payload-cli"
        local.write_bytes(b"native launcher bytes")
        remote.write_bytes(b"native launcher bytes")
        payloads = {"linux-x86_64": self.temporary}
        (self.temporary / "ami-rust").write_bytes(remote.read_bytes())
        native._check_local_launcher(local, payloads, "linux-x86_64")

        (self.temporary / "ami-rust").write_bytes(b"same behavior, different bytes")
        with self.assertRaisesRegex(ValueError, "byte-for-byte"):
            native._check_local_launcher(local, payloads, "linux-x86_64")


class InertRuntimePartitionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="inert runtime partition ")
        self.root = Path(self.temporary.name).resolve()
        self.work = self.root / "work"
        self.work.mkdir(mode=0o700)
        for name in ("home", "tmp"):
            (self.work / name).mkdir(mode=0o700)
        self.runtime = self.work / "old-state/bootstrap/runtime/python"
        for name in ("bin", "lib"):
            (self.runtime / name).mkdir(mode=0o700, parents=True)
        self.interpreter = self.runtime / "bin/python3.12"
        self.library = self.runtime / ("lib/libpython3.12.dylib" if native.current_host() == "macos-aarch64" else "lib/libpython3.12.so.1.0")
        self.interpreter.write_bytes(b"inert identity")
        self.library.write_bytes(b"inert library")
        (self.work / "old-state/ready.json").write_bytes(b"{}")
        self.sibling = self.work / "old-state/sdk"
        self.sibling.mkdir()
        (self.sibling / "manifest.json").write_bytes(b"{}")
        self.cli = self.work / "cli"
        self.cli.write_bytes(b"native placeholder")
        self.policy = self.root / "policy.json"
        self.policy.write_bytes(native.auth.encoded({name: {"path": "/usr/bin/true"} for name in ("gh", "cosign")}))
        self.closure = self.root / "closure.json"
        self.closure.write_bytes(b"{}")

    def tearDown(self):
        self.temporary.cleanup()

    def spec(self, args, **kwargs):
        return native._consumer_observation_spec(self.work, self.root / "coordinator-python", self.cli,
            args, 0, self.policy, self.closure, [], inert_python_roots=[self.runtime], **kwargs)

    def test_sibling_data_is_granted_but_runtime_data_is_not(self):
        trees, files, directories = native._partition_inert_runtime_reads([self.work], [self.runtime])
        self.assertIn(self.sibling, trees)
        self.assertIn(self.work / "old-state/ready.json", files)
        self.assertIn(self.work / "old-state", directories)
        self.assertFalse(any(grant == self.runtime or grant in self.runtime.parents or self.runtime in grant.parents
                             for grant in trees | files))
        self.assertNotIn(self.library, files)
        self.assertNotIn(self.interpreter, files)

    def test_every_phase_excludes_library_and_exact_interpreter_exec(self):
        for args in (["verify-package"], ["check-inputs", "--state", self.work / "old-state"]):
            result = self.spec(args)
            self.assertIn(str(self.library), result["deny_library"])
            self.assertIn(str(self.interpreter), result["deny_exec"])
            self.assertNotIn(str(self.work), [row["path"] for row in result["read_trees"]])
            self.assertIn(str(self.work), result["read_directories"])

    def test_migration_keeps_only_exact_inert_interpreter_data(self):
        lock = self.work / "old-state/old-lock.json"
        lock.write_bytes(native.auth.encoded({"schema": "ami-rust-project-lock-v1", "host": {"python": str(self.interpreter)}}))
        parent = self.work / "migration-output"
        parent.mkdir()
        result = self.spec(["migrate", "--from-lock", lock, "--output", parent / "new-lock.json"])
        self.assertIn(str(self.interpreter), result["read_files"])
        self.assertNotIn(str(self.library), result["read_files"])
        if native.current_host() == "linux-x86_64":
            self.assertNotIn(str(self.interpreter), result["deny_exec"])
        else:
            self.assertIn(str(self.interpreter), result["deny_exec"])
        self.assertIsNone(result["derived"])

    def test_write_ancestor_of_runtime_fails_before_consumer(self):
        with self.assertRaisesRegex(ValueError, "writes overlap"):
            self.spec(["native-package-verify", "--work", self.work / "authentication"])

    def test_alias_into_excluded_runtime_never_grants_data(self):
        (self.work / "runtime-alias").symlink_to(self.runtime, target_is_directory=True)
        trees, files, _ = native._partition_inert_runtime_reads([self.work], [self.runtime])
        self.assertNotIn(self.runtime, trees)
        self.assertNotIn(self.interpreter, files)

    def test_unlistable_partition_ancestor_propagates(self):
        real_scandir = os.scandir
        def failing(path):
            if Path(path) == self.work / "old-state":
                raise PermissionError("intentional unreadable partition")
            return real_scandir(path)
        with patch.object(native.os, "scandir", side_effect=failing):
            with self.assertRaisesRegex(PermissionError, "intentional unreadable"):
                native._partition_inert_runtime_reads([self.work], [self.runtime])

    def test_missing_or_aliased_runtime_is_rejected(self):
        (self.runtime / "bin/python3.12").unlink()
        with self.assertRaisesRegex(ValueError, "canonical regular"):
            self.spec(["verify-package"])



class PublishedMigrationEntryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="published entry fixture ")
        self.root = Path(self.temporary.name).resolve()
        self.state, self.project = self.root / "state", self.root / "project"
        self.project.mkdir()
        self.sdk = self.state / "sdk-0.1.0/sdk"
        self.sdk.mkdir(parents=True)
        (self.sdk / "manifest.json").write_bytes(b"inert SDK manifest fixture")
        self.python = self.state / "ami-rust-python-bootstrap/runtime/python/bin/python3.12"
        self.python.parent.mkdir(parents=True)
        self.python.write_bytes(b"inert interpreter identity")
        self.runtime_hash = auth.sha(self.python.read_bytes())
        self.runtime_size = self.python.stat().st_size
        self.executable = self.root / "native-executable"
        self.executable.write_bytes(b"inert native output identity")
        (self.state / "ready.json").write_bytes(auth.encoded({"schema": "ami-rust-package-state-v1",
            "status": "READY", "sdk_version": "0.1.0", "package_version": "0.1.0-2"}))
        relative = "runtime/python/bin/python3.12"
        self.report = {"interpreter": {"path": str(self.root / "different-coordinator-python"),
            "sha256": self.runtime_hash, "bytes": self.runtime_size,
            "pin_sha256": self.runtime_hash, "pin_bytes": self.runtime_size,
            "verified_bootstrap": {"relative_files": {"runtime_executable": relative},
                "runtime": {"path": relative, "sha256": self.runtime_hash, "bytes": self.runtime_size},
                "runtime_pin": {"relative_path": "python/bin/python3.12", "sha256": self.runtime_hash}}},
            "native_executable": {"path": str(self.executable), "bytes": self.executable.stat().st_size,
                                  "sha256": auth.sha(self.executable.read_bytes())}}
        self.lock = {"schema": "ami-rust-project-lock-v1", "sdk": {"root": str(self.sdk),
            "manifest": "manifest.json", "manifest_sha256": auth.sha((self.sdk / "manifest.json").read_bytes())},
            "host": {"python": str(self.python), "python_sha256": self.runtime_hash}}

    def tearDown(self):
        self.temporary.cleanup()

    def validate(self):
        (self.project / "ami-rust.lock.json").write_bytes(auth.encoded(self.lock))
        return native._validate_actual_published_v1_entry(self.report, self.state, self.project)

    def test_real_retained_layout_can_differ_from_coordinator_interpreter(self):
        self.assertEqual(self.validate()["old_python"], self.python)

    def test_wrong_interpreter_path_and_digest_are_refused(self):
        self.lock["host"]["python"] = self.report["interpreter"]["path"]
        with self.assertRaisesRegex(ValueError, "retained state Python runtime"):
            self.validate()
        self.lock["host"]["python"] = str(self.python)
        self.lock["host"]["python_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "pinned setup report"):
            self.validate()

    def test_changed_runtime_bytes_are_refused(self):
        self.python.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "pinned setup report"):
            self.validate()

    def test_changed_manifest_is_refused(self):
        self.lock["sdk"]["manifest_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "SDK manifest differs"):
            self.validate()


class PublishedArchiveTests(unittest.TestCase):
    def archive(self, *, invalid=None):
        rows = [(native.PUBLISHED_V1_ARCHIVE_ROOT, tarfile.DIRTYPE, 0o755),
                (native.PUBLISHED_V1_PACKAGE_ROOT, tarfile.DIRTYPE, 0o755),
                (native.PUBLISHED_V1_PACKAGE_ROOT + "/pins.json", tarfile.REGTYPE, 0o644),
                (native.PUBLISHED_V1_PACKAGE_ROOT + "/cli.py", tarfile.REGTYPE, 0o644),
                (native.PUBLISHED_V1_ARCHIVE_ROOT + "/usr/bin/ami-rust", tarfile.REGTYPE, 0o755)]
        if invalid == "path": rows.append(("../escape", tarfile.REGTYPE, 0o644))
        if invalid == "link": rows.append((native.PUBLISHED_V1_ARCHIVE_ROOT + "/link", tarfile.SYMTYPE, 0o644))
        if invalid == "duplicate": rows.append(rows[-1])
        if invalid == "mode": rows.append((native.PUBLISHED_V1_ARCHIVE_ROOT + "/writable", tarfile.REGTYPE, 0o777))
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, kind, mode in rows:
                member = tarfile.TarInfo(name)
                member.type, member.mode, member.size = kind, mode, 0
                if kind == tarfile.SYMTYPE: member.linkname = "/outside"
                archive.addfile(member, io.BytesIO(b""))
        raw = lzma.compress(stream.getvalue())
        return raw + (b"trailing" if invalid == "trailing" else b"")

    def test_complete_layout_including_external_wrapper_is_admitted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "package"
            package, count, _, _ = native._extract_published_v1_archive(self.archive(), root)
            self.assertEqual(package, root / native.PUBLISHED_V1_PACKAGE_ROOT)
            self.assertEqual(count, 5)
            self.assertTrue((root / native.PUBLISHED_V1_ARCHIVE_ROOT / "usr/bin/ami-rust").is_file())
            with self.assertRaisesRegex(ValueError, "must be fresh"):
                native._extract_published_v1_archive(self.archive(), root)

    def test_unsafe_archive_refuses_before_any_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            for kind in ("path", "link", "duplicate", "mode", "trailing"):
                with self.subTest(kind=kind):
                    output = Path(temporary).resolve() / kind
                    with self.assertRaises(ValueError):
                        native._extract_published_v1_archive(self.archive(invalid=kind), output)
                    self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
