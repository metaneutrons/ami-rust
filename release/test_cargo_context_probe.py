"""Synthetic tests for the bounded host Cargo context comparison."""
import hashlib
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from release import cargo_context_probe as probe


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.owner = tempfile.TemporaryDirectory(prefix="cargo-context-probe-")
        self.addCleanup(self.owner.cleanup)
        self.base = Path(self.owner.name).resolve()
        self.temporary = self.base / "managed"
        self.temporary.mkdir()
        (self.temporary / probe.BOOTSTRAP_NAME).mkdir()
        self.output = self.temporary / "evidence"
        self.inputs = self.base / "inputs.json"
        self.resources = self.base / "resources.json"
        self.inputs.write_text("{}\n")
        policy_path = Path(probe.ci_cargo.__file__).resolve().parent / "ci-resources.json"
        self.resource_policy = json.loads(policy_path.read_text())
        self.resources.write_text(json.dumps(self.resource_policy, sort_keys=True) + "\n")
        self.calls = 0

    def argv(self):
        return ["--temporary", str(self.temporary), "--output", str(self.output),
                "--inputs", str(self.inputs), "--resources", str(self.resources),
                "--python-bootstrap-root", str(self.temporary / probe.BOOTSTRAP_NAME)]

    @staticmethod
    def _write_json(path, row):
        path.write_text(json.dumps(row, sort_keys=True) + "\n")

    def producer(self, payloads=(b"same-cargo", b"same-cargo"), fail_second=False,
                 bad_hash=False):
        def produce(args):
            self.calls += 1
            index = self.calls - 1
            args.work.mkdir()
            args.output.mkdir()
            logs = args.work / "logs"
            build = args.work / "records/build"
            logs.mkdir()
            build.mkdir(parents=True)
            (logs / "cargo-build.stdout.log").write_text("synthetic build diagnostic\n")
            (build / "inputs.json").write_text('{"command":["cargo","build"]}\n')
            (build / "stdout.log").write_text("synthetic compiler output\n")
            (build / "stderr.log").write_text("")
            binary = args.work / "build-work/target/release/cargo"
            binary.parent.mkdir(parents=True)
            data = payloads[min(index, len(payloads) - 1)]
            binary.write_bytes(data)
            binary.chmod(0o755)
            digest = hashlib.sha256(data).hexdigest()
            self._write_json(build / "result.json", {
                "artifact": {"path": str(binary), "bytes": len(data), "sha256": digest}})
            if fail_second and index == 1:
                record = {"schema": probe.ci_cargo.PRODUCER_SCHEMA, "status": "FAILED",
                          "stage": "synthetic", "error": "synthetic second-run failure"}
                self._write_json(args.output / "producer.json", record)
                raise RuntimeError("synthetic second-run failure")
            record = {"schema": probe.ci_cargo.PRODUCER_SCHEMA,
                      "status": "PRODUCED_PREREQUISITE_ONLY_NOT_R1_QUALIFICATION",
                      "budgets": json.loads(args.resources.read_text())["build"],
                      "custom_cargo_artifact": {
                          "relative_path": "build-work/target/release/cargo",
                          "bytes": len(data), "sha256": "0" * 64 if bad_hash else digest},
                      "peaks": {"work_plus_output_observed_bytes": 4096}}
            self._write_json(args.output / "producer.json", record)
            return record
        return produce

    def run_with(self, producer, peak_rss_bytes=64 * 1024**2):
        raw_peak_rss = peak_rss_bytes if sys.platform == "darwin" else peak_rss_bytes // 1024
        with mock.patch.object(probe, "capture_host_toolchain", return_value={"schema": "test"}), \
             mock.patch.object(probe.ci_cargo, "produce", side_effect=producer), \
             mock.patch.object(probe.resource, "getrusage", return_value=mock.Mock(ru_maxrss=raw_peak_rss)):
            return probe.main(self.argv())

    def test_equal_binaries_are_preserved_and_match_is_not_acceptance(self):
        measured_peak = 296_517_632
        self.assertEqual(self.run_with(self.producer(), peak_rss_bytes=measured_peak), 0)
        outcome = json.loads((self.output / "outcome.json").read_text())
        self.assertEqual(outcome["status"], "MATCH_NOT_RELEASE_ACCEPTED")
        self.assertEqual(outcome["driver_peak_rss_bytes"], measured_peak)
        self.assertEqual(outcome["driver_peak_rss_limit_bytes"],
                         self.resource_policy["build"]["rss_bytes"])
        for phase in ("cargo", "sdk"):
            folder = self.output / phase
            self.assertTrue((folder / "producer.json").is_file())
            self.assertTrue((folder / "cargo.tar.xz").is_file())
            self.assertTrue((folder / "diagnostics.tar.xz").is_file())
            with tarfile.open(folder / "cargo.tar.xz", "r:xz") as archive:
                member = archive.getmember("cargo")
                self.assertEqual(member.mode, 0o755)
                self.assertEqual(archive.extractfile(member).read(), b"same-cargo")
        self.assertFalse((self.temporary / probe.WORK_NAMES[0]).exists())
        self.assertFalse((self.temporary / probe.WORK_NAMES[1]).exists())

    def test_driver_peak_above_selected_policy_is_retained(self):
        limit = self.resource_policy["build"]["rss_bytes"]
        measured_peak = limit + 1024
        self.assertEqual(self.run_with(self.producer(), peak_rss_bytes=measured_peak), 1)
        outcome = json.loads((self.output / "outcome.json").read_text())
        self.assertEqual(outcome["status"], "FAILED_EVIDENCE_RETAINED")
        self.assertEqual(outcome["driver_peak_rss_bytes"], measured_peak)
        self.assertEqual(outcome["driver_peak_rss_limit_bytes"], limit)
        self.assertIn("driver peak RSS exceeded", outcome["error"])
        self.assertTrue((self.output / "cargo/cargo.tar.xz").is_file())
        self.assertTrue((self.output / "sdk/cargo.tar.xz").is_file())

    def test_different_binaries_are_retained_before_nonzero_rejection(self):
        self.assertEqual(self.run_with(self.producer((b"cargo-one", b"cargo-two"))), 1)
        outcome = json.loads((self.output / "outcome.json").read_text())
        self.assertEqual(outcome["status"], "MISMATCH_RETAINED_NOT_RELEASE_ACCEPTED")
        self.assertTrue((self.output / "cargo/cargo.tar.xz").is_file())
        self.assertTrue((self.output / "sdk/cargo.tar.xz").is_file())
        self.assertTrue((self.output / "cargo/producer.json").is_file())
        self.assertTrue((self.output / "sdk/producer.json").is_file())
        with tarfile.open(self.output / "cargo/cargo.tar.xz", "r:xz") as archive:
            self.assertEqual(archive.extractfile("cargo").read(), b"cargo-one")
        with tarfile.open(self.output / "sdk/cargo.tar.xz", "r:xz") as archive:
            self.assertEqual(archive.extractfile("cargo").read(), b"cargo-two")

    def test_tampered_producer_hash_is_rejected_and_work_is_retained(self):
        self.assertEqual(self.run_with(self.producer(bad_hash=True)), 1)
        outcome = json.loads((self.output / "outcome.json").read_text())
        self.assertEqual(outcome["status"], "FAILED_EVIDENCE_RETAINED")
        self.assertIn("report hash or size", outcome["phases"][0]["error"])
        self.assertTrue((self.output / "cargo/producer.json").is_file())
        self.assertTrue((self.temporary / probe.WORK_NAMES[0]).is_dir())
        self.assertFalse((self.output / "cargo/cargo.tar.xz").exists())

    def test_missing_input_gets_a_bounded_failure_record(self):
        argv = self.argv()
        argv[argv.index("--inputs") + 1] = str(self.base / "missing-inputs.json")
        with mock.patch.object(probe, "capture_host_toolchain") as capture:
            self.assertEqual(probe.main(argv), 1)
        capture.assert_not_called()
        outcome = json.loads((self.output / "outcome.json").read_text())
        self.assertEqual(outcome["status"], "FAILED_EVIDENCE_RETAINED")
        self.assertLess((self.output / "outcome.json").stat().st_size, probe.RECORD_LIMIT)
        self.assertTrue((self.temporary / probe.OWNER_NAME).is_file())

    def test_overlapping_output_path_is_rejected_without_writes(self):
        overlapping = self.temporary / probe.WORK_NAMES[0]
        argv = self.argv()
        argv[argv.index("--output") + 1] = str(overlapping)
        with mock.patch.object(probe, "capture_host_toolchain") as capture:
            self.assertEqual(probe.main(argv), 1)
        capture.assert_not_called()
        self.assertFalse(overlapping.exists())

    def test_symlinked_managed_parent_is_rejected(self):
        linked = self.base / "managed-link"
        linked.symlink_to(self.temporary, target_is_directory=True)
        argv = self.argv()
        argv[argv.index("--temporary") + 1] = str(linked)
        argv[argv.index("--output") + 1] = str(linked / "evidence")
        self.assertEqual(probe.main(argv), 1)
        self.assertFalse(self.output.exists())

    def test_cleanup_after_second_failure_keeps_first_evidence(self):
        self.assertEqual(self.run_with(self.producer(fail_second=True)), 1)
        self.assertTrue((self.output / "cargo/cargo.tar.xz").is_file())
        self.assertTrue((self.output / "sdk/producer.json").is_file())
        self.assertTrue((self.output / "sdk/diagnostics.tar.xz").is_file())
        self.assertTrue((self.temporary / probe.WORK_NAMES[1]).is_dir())
        self.assertEqual(probe.main(["--temporary", str(self.temporary), "--output",
                                     str(self.output), "--cleanup"]), 0)
        self.assertFalse((self.temporary / probe.WORK_NAMES[1]).exists())
        self.assertTrue((self.output / "cargo/cargo.tar.xz").is_file())
        self.assertTrue((self.output / "cargo/producer.json").is_file())
        self.assertTrue((self.output / "sdk/producer.json").is_file())
        self.assertTrue((self.output / "sdk/diagnostics.tar.xz").is_file())


if __name__ == "__main__":
    unittest.main()
