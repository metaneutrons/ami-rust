"""Native producer controls; synthetic fixtures are not publisher evidence."""
import io
import json
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

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

    def test_completed_matrix_report_survives_later_retained_replay_failure(self):
        self._run_signed_package_lifecycle_matrix_case(fail_replay=True)

    def _run_signed_package_lifecycle_matrix_case(self, *, fail_replay=False):
        outer = self.work / "outer"
        metadata = outer / "metadata"
        metadata.mkdir(parents=True)
        host = native.current_host()
        identity = {"source_sha": "a" * 40, "run_id": 42, "run_attempt": 2}
        config = {"sdk_version": "0.2.0", "cli_version": "0.2.0-dev"}
        pins = {"source_commit": identity["source_sha"], "sdk_run_id": 42,
                "sdk_run_attempt": 2, "host": host, **config, "core_sha256": "b" * 64}
        (metadata / ("native-package-inputs-" + host + ".json")).write_bytes(auth.encoded(pins))
        (metadata / "outer-verification.json").write_bytes(auth.encoded({
            "status": "OUTER_CRYPTO_VERIFIED_NOT_R1_ACCEPTED", "source_commit": identity["source_sha"],
            "run_id": 42, "run_attempt": 2}))
        package = self.work / "native-package"
        matrix_calls = []
        commands = []
        prepared_state = None

        def compose(*args, **kwargs):
            (package / "bin").mkdir(parents=True)
            (package / "bin/ami-rust").write_bytes(b"inert frontend fixture")

        def command(label, arguments, expected=0, *, executable):
            nonlocal prepared_state
            commands.append(label)
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
                return auth.encoded({"status": "PASS"})
            return b""

        def matrix(work, state, frontend, output, supervisor, selected, callback):
            self.assertEqual((work, state, output), (self.work, prepared_state, self.output))
            self.assertEqual(frontend, package / "bin/ami-rust")
            self.assertTrue(frontend.is_file(), "matrix must run before package removal")
            self.assertEqual(selected, config)
            self.assertIs(callback, command)
            self.assertIn("14-package-offline-build", commands)
            matrix_calls.append(True)
            return {"build_count": 10, "fixture": True}

        # Composition is a stub in this lifecycle-order fixture. Supply inert
        # notice data locally so the test also works in the narrow installer
        # CI checkout; actual legal bytes are checked by package production.
        fixture_source = self.temporary / "source-fixture"
        licenses = fixture_source / "tooling/third-party/licenses"
        licenses.mkdir(parents=True)
        for name in ("LICENSE-MIT", "LICENSE-APACHE"):
            (fixture_source / name).write_bytes(b"inert notice fixture\n")
        (licenses.parent / "THIRD-PARTY-NOTICES.md").write_bytes(b"inert third-party notice fixture\n")
        with patch.object(native, "ROOT", fixture_source), \
                patch.object(native, "_supervised_run", side_effect=compose), \
                patch.object(native, "_supervised_text", return_value='{"status":"OUTER_AND_INNER_AUTHENTICATED"}'), \
                patch.object(native, "_qualify_native_build_matrix", side_effect=matrix):
            if fail_replay:
                with self.assertRaisesRegex(ValueError, "isolated retained replay refusal"):
                    native._qualify_native_package(
                        self.work, self.output, outer, self.work / "bundle", self.frontend,
                        self.work / "xtask", self._fixture_supervisor(), self.work / "policy.json",
                        identity, config, command)
            else:
                report = native._qualify_native_package(
                    self.work, self.output, outer, self.work / "bundle", self.frontend,
                    self.work / "xtask", self._fixture_supervisor(), self.work / "policy.json",
                    identity, config, command)
                self.assertEqual(report["native_matrix"], {"build_count": 10, "fixture": True})
        self.assertEqual(auth.parsed(auth.read(self.output / "native-build-matrix.json")),
                         {"build_count": 10, "fixture": True})
        self.assertEqual(commands[-2:], ["15-retained-input-recheck", "16-retained-offline-replay"])
        self.assertFalse(package.exists())


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


if __name__ == "__main__":
    unittest.main()
