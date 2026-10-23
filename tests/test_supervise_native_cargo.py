from __future__ import annotations

import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "tools/supervise-native-cargo.py"
SPEC = importlib.util.spec_from_file_location("supervise_native_cargo", SOURCE)
assert SPEC is not None and SPEC.loader is not None
MONITOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MONITOR)


def gzip_file(path: Path, payload: bytes) -> None:
    path.write_bytes(gzip.compress(payload, mtime=0))


class SupervisorPureControls(unittest.TestCase):
    def test_recipe_defaults_to_v2_and_preserves_explicit_selection(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(MONITOR._supervised_env()["NATIVE_CARGO_RECIPE"], "three-host-v2")
        for name in ("three-host-v2", "three-host-v3"):
            with patch.dict(os.environ, {"NATIVE_CARGO_RECIPE": name}, clear=True):
                self.assertEqual(MONITOR.native_recipe(), name)
                self.assertEqual(MONITOR._supervised_env()["NATIVE_CARGO_RECIPE"], name)
        for name in ("", "../../../unreviewed", "three-host-v4"):
            with patch.dict(os.environ, {"NATIVE_CARGO_RECIPE": name}, clear=True):
                with self.assertRaises(ValueError):
                    MONITOR._supervised_env()

    def test_ci_cargo_pin_matches_current_shared_monitor_source(self):
        shared_monitor = ROOT / "release/ci_cargo.py"
        self.assertEqual(MONITOR.sha256(shared_monitor), MONITOR.CI_CARGO_SHA256)

    def test_native_identity_keeps_linux_hosts_and_admits_only_arm64_macos(self):
        self.assertTrue(MONITOR.native_identity_matches(
            "Linux", "x86_64", "x86_64-unknown-linux-gnu"))
        self.assertTrue(MONITOR.native_identity_matches(
            "Linux", "aarch64", "aarch64-unknown-linux-gnu"))
        self.assertTrue(MONITOR.native_identity_matches(
            "Darwin", "arm64", "aarch64-apple-darwin"))
        self.assertTrue(MONITOR.native_identity_matches(
            "Darwin", "aarch64", "aarch64-apple-darwin"))
        self.assertFalse(MONITOR.native_identity_matches(
            "Darwin", "x86_64", "aarch64-apple-darwin"))
        self.assertFalse(MONITOR.native_identity_matches(
            "Linux", "arm64", "aarch64-apple-darwin"))

    def test_ru_maxrss_is_normalized_for_linux_and_darwin(self):
        with patch.object(MONITOR.resource, "getrusage",
                          return_value=SimpleNamespace(ru_maxrss=1234)), \
                patch.object(MONITOR.platform, "system", return_value="Linux"):
            self.assertEqual(MONITOR._own_hwm_bytes(), 1234 * 1024)
        with patch.object(MONITOR.resource, "getrusage",
                          return_value=SimpleNamespace(ru_maxrss=1234)), \
                patch.object(MONITOR.platform, "system", return_value="Darwin"):
            self.assertEqual(MONITOR._own_hwm_bytes(), 1234)

    def test_binary_inspection_accepts_matching_elf_and_macho_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = root / "command-records"
            records.mkdir()
            paths = []
            for name in ("header", "program", "dynamic"):
                record_dir = records / name
                record_dir.mkdir()
                record = record_dir / "result.json"
                record.write_text("{}", encoding="utf-8")
                paths.append(str(record))
            inspection_path = root / "native-cargo-binary-inspection.json"
            inspection_path.write_text(json.dumps({
                "schema": MONITOR.INSPECTION_SCHEMA,
                "status": "PASS",
                "host": "x86_64-unknown-linux-gnu",
                "format": "ELF",
                "architecture": "x86_64",
                "format_description": "Advanced Micro Devices X86-64",
                "interpreter": None,
                "header_record": paths[0],
                "program_headers_record": paths[1],
                "dynamic_dependencies_record": paths[2],
                "runtime_dependencies_record": None,
            }), encoding="utf-8")
            self.assertEqual(MONITOR.validate_binary_inspection(
                inspection_path, "x86_64-unknown-linux-gnu", root)["format"], "ELF")

            format_dir = records / "format"
            dependencies_dir = records / "dependencies"
            format_dir.mkdir()
            dependencies_dir.mkdir()
            format_record = format_dir / "result.json"
            dependencies_record = dependencies_dir / "result.json"
            format_record.write_text("{}", encoding="utf-8")
            dependencies_record.write_text("{}", encoding="utf-8")
            description = b"cargo: Mach-O 64-bit executable arm64\n"
            dependency_output = (
                b"cargo:\n"
                b"\t/System/Library/Frameworks/Security.framework/Versions/A/Security (compatibility version 1.0.0, current version 1.0.0)\n"
                b"\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1.0.0)\n"
            )
            gzip_file(format_dir / "stdout.raw.gz", description)
            gzip_file(dependencies_dir / "stdout.raw.gz", dependency_output)
            dependencies = [
                "/System/Library/Frameworks/Security.framework/Versions/A/Security",
                "/usr/lib/libSystem.B.dylib",
            ]
            inspection_path.write_text(json.dumps({
                "schema": MONITOR.INSPECTION_SCHEMA,
                "status": "PASS",
                "host": "aarch64-apple-darwin",
                "format": "Mach-O",
                "architecture": "arm64",
                "format_description": description.decode().strip(),
                "interpreter": None,
                "format_record": str(format_record),
                "dependencies_record": str(dependencies_record),
                "system_dependencies": dependencies,
            }), encoding="utf-8")
            self.assertEqual(MONITOR.validate_binary_inspection(
                inspection_path, "aarch64-apple-darwin", root)["architecture"], "arm64")

    def test_binary_inspection_rejects_false_macho_or_non_system_dependency(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = root / "command-records"
            records.mkdir()
            format_dir = records / "format"
            dependencies_dir = records / "dependencies"
            format_dir.mkdir()
            dependencies_dir.mkdir()
            format_record = format_dir / "result.json"
            dependencies_record = dependencies_dir / "result.json"
            format_record.write_text("{}", encoding="utf-8")
            dependencies_record.write_text("{}", encoding="utf-8")
            gzip_file(format_dir / "stdout.raw.gz", b"cargo: Mach-O 64-bit executable arm64\n")
            gzip_file(dependencies_dir / "stdout.raw.gz", b"cargo:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1.0.0)\n")
            inspection_path = root / "native-cargo-binary-inspection.json"
            value = {
                "schema": MONITOR.INSPECTION_SCHEMA,
                "status": "PASS",
                "host": "aarch64-apple-darwin",
                "format": "Mach-O",
                "architecture": "arm64",
                "format_description": "cargo: Mach-O 64-bit executable x86_64",
                "interpreter": None,
                "format_record": str(format_record),
                "dependencies_record": str(dependencies_record),
                "system_dependencies": ["/usr/lib/libSystem.B.dylib"],
            }
            inspection_path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                MONITOR.validate_binary_inspection(
                    inspection_path, "aarch64-apple-darwin", root)
            value["format_description"] = "cargo: Mach-O 64-bit executable arm64"
            value["system_dependencies"] = ["@rpath/libunexpected.dylib"]
            inspection_path.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                MONITOR.validate_binary_inspection(
                    inspection_path, "aarch64-apple-darwin", root)

    def test_campaign_clock_preserves_review_reserve_and_step_cap(self):
        self.assertEqual(MONITOR.campaign_timeout(1000, 1000), 4500)
        self.assertEqual(MONITOR.campaign_timeout(1000, 2000), 4100)
        with self.assertRaises(ValueError):
            MONITOR.campaign_timeout(1000, 6100)
        with self.assertRaises(ValueError):
            MONITOR.campaign_timeout(True, 1000)

    def test_root_overlap_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, managed, output = (root / name for name in ("source", "managed", "output"))
            for path in (source, managed, output):
                path.mkdir()
            self.assertTrue(MONITOR.roots_are_disjoint(source, managed, output))
            self.assertFalse(MONITOR.roots_are_disjoint(source, managed, managed / "nested"))
            self.assertFalse(MONITOR.roots_are_disjoint(source, managed, managed))

    def test_raw_and_compressed_log_aliases_count_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helper = root / "command-records/001"
            setup = root / "setup"
            helper.mkdir(parents=True)
            setup.mkdir()
            producer = root / "producer/provision/record"
            producer.mkdir(parents=True)
            (helper / "stdout.log").write_bytes(b"captured-stream")
            gzip_file(helper / "stdout.raw.gz", b"captured-stream")
            (producer / "stdout.log").write_bytes(b"producer-output")
            gzip_file(producer / "stdout.raw.gz", b"producer-output")
            gzip_file(setup / "tooling.output.gz", b"setup-output")
            (setup / "tooling.output.bytes").write_text("12\n", encoding="ascii")
            (root / "vendor.gz").write_bytes(b"not a counted output stream")
            upstream = root / "upstream-cargo"
            upstream.mkdir()
            (upstream / "vendor.raw.gz").write_bytes(b"never inspect arbitrary vendor gzip")
            unexpected = root / "producer/unexpected/record"
            unexpected.mkdir(parents=True)
            (unexpected / "stdout.raw.gz").write_bytes(b"not a known producer log")
            expected = len(b"captured-stream") + len(b"producer-output") + 12
            self.assertEqual(MONITOR.logical_log_bytes(root), expected)
            (helper / "stdout.log").unlink()
            (producer / "stdout.log").unlink()
            self.assertEqual(MONITOR.logical_log_bytes(root), expected)

    def test_raw_log_disappearing_during_compression_is_skipped_for_this_sample(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            log = root / "producer/build/record/stderr.log"
            log.parent.mkdir(parents=True)
            log.write_bytes(b"being-compressed")
            original_stat = Path.stat
            original_is_file = Path.is_file

            def file_predicate_before_unlink(path, *args, **kwargs):
                if path == log:
                    return True
                return original_is_file(path, *args, **kwargs)

            def disappear_on_size_stat(path, *args, **kwargs):
                if path == log and kwargs.get("follow_symlinks", True):
                    raise FileNotFoundError(path)
                return original_stat(path, *args, **kwargs)

            # Python versions implement is_file/lstat differently. Inject the
            # unlink after the file predicate, at the explicit size read.
            with patch.object(Path, "is_file", file_predicate_before_unlink), \
                    patch.object(Path, "stat", disappear_on_size_stat):
                self.assertEqual(MONITOR.logical_log_bytes(root), 0)

    def test_malformed_or_uncounted_compressed_logs_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helper = root / "command-records/001"
            helper.mkdir(parents=True)
            (helper / "stdout.raw.gz").write_bytes(b"bad")
            with self.assertRaises(ValueError):
                MONITOR.logical_log_bytes(root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            setup = root / "setup"
            setup.mkdir()
            gzip_file(setup / "phase.output.gz", b"setup")
            with self.assertRaises(ValueError):
                MONITOR.logical_log_bytes(root)

    def test_negative_records_are_allowed_only_for_named_controls(self):
        record = {
            "schema": "ami-rust-native-command-qualification-record-v1",
            "passed": False,
            "capture_complete": True,
            "capture_error": None,
            "child_exit_code": 7,
            "child_signal": None,
        }
        self.assertTrue(MONITOR.negative_control_valid("actual-cli-child-exit-seven", record))
        self.assertFalse(MONITOR.negative_control_valid("unexpected-phase", record))
        record["capture_complete"] = False
        self.assertFalse(MONITOR.negative_control_valid("actual-cli-child-exit-seven", record))

    def test_negative_control_budget_failure_is_not_accepted(self):
        request_sha = hashlib.sha256(b"request").hexdigest()
        record = {
            "schema": "ami-rust-native-command-qualification-record-v1",
            "request_sha256": request_sha,
            "limits": dict(MONITOR.EXPECTED_HELPER_LIMITS),
            "passed": False,
            "refusal": "child exited with status 7",
            "capture_complete": True,
            "capture_error": None,
            "child_exit_code": 7,
            "child_signal": None,
            "aggregate_peak_rss_bytes": 100,
            "workspace_bytes_at_finish": 200,
            "log_bytes_at_finish": 300,
            "stdout": {"bytes": 10, "sha256": "a" * 64},
            "stderr": {"bytes": 20, "sha256": "b" * 64},
        }
        self.assertEqual(MONITOR.validate_helper_record(
            "actual-cli-child-exit-seven", request_sha, record), 100)
        record["aggregate_peak_rss_bytes"] = MONITOR.HELPER_RSS_REQUEST + 1
        with self.assertRaises(ValueError):
            MONITOR.validate_helper_record("actual-cli-child-exit-seven", request_sha, record)

    def test_missing_and_malformed_inner_results_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "result.json"
            with self.assertRaises(ValueError):
                MONITOR.validate_inner_result(path, "x86_64-unknown-linux-gnu", "head")
            path.write_text("{broken", encoding="utf-8")
            with self.assertRaises(ValueError):
                MONITOR.validate_inner_result(path, "x86_64-unknown-linux-gnu", "head")
            path.write_text(json.dumps({"schema": MONITOR.EXPECTED_SCHEMA, "status": "FAILED"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                MONITOR.validate_inner_result(path, "x86_64-unknown-linux-gnu", "head")

    def test_missing_and_malformed_native_records_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "phase-index").mkdir()
            (root / "command-records").mkdir()
            index = {
                "schema": "ami-rust-native-cargo-phase-input-index-v1",
                "phase": "probe",
                "request_sha256": hashlib.sha256(b"request").hexdigest(),
                "record": str(root / "command-records/missing/result.json"),
                "limits": dict(MONITOR.EXPECTED_HELPER_LIMITS),
            }
            (root / "phase-index/001-probe.json").write_text(json.dumps(index), encoding="utf-8")
            with self.assertRaises((OSError, ValueError)):
                MONITOR._native_phase_peak(root)
            (root / "phase-index/001-probe.json").write_text("not json", encoding="utf-8")
            with self.assertRaises(ValueError):
                MONITOR._native_phase_peak(root)


if __name__ == "__main__":
    unittest.main()
