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
