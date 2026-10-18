#!/usr/bin/env python3
"""Offline fixtures for resource and receipt observations."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from types import SimpleNamespace


_MEASURE_PATH = Path(__file__).with_name("measure.py")
_SPEC = importlib.util.spec_from_file_location("ami_rust_measure_test", _MEASURE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
measure = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(measure)


def receipt() -> dict:
    return {
        "schema": "ami-rust-consumer-preparation-v1",
        "status": "PREPARED_VERIFIED_INPUTS_NOT_INSTALLED",
        "capacity": {
            "disk_free_minimum_bytes": 10,
            "free_disk_bytes": 100,
            "physical_ram_bytes": 200,
            "ram_minimum_bytes": 20,
        },
        "commands": [{
            "label": "prepare", "elapsed_seconds": 1.25,
            "rss_peak_observed_bytes": 300, "managed_peak_observed_bytes": 400,
            "exit_code": 0,
        }],
        "components": {"rust": {"regular_file_bytes": 500, "entry_count": 2}},
        "source_policy": {"source_sha": "a" * 40, "workflow_sha": "b" * 40},
        "selection_sha256": "c" * 64,
        "sdk_manifest_sha256": "d" * 64,
        "release_manifest_sha256": "e" * 64,
        "policy_sha256": "f" * 64,
        "selection_path": "/state/selection.json",
        "policy_path": "/state/preparation/trust/publisher-policy.json",
        "host": "linux-x86_64",
    }


class MeasureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.project = self.root / "project"
        self.buildroot = self.root / "build"
        for path in (self.state, self.project, self.buildroot):
            path.mkdir()
        for name in ("retained", "source", "ami-rust-python-bootstrap", "preparation",
                     "preparation-output", "sdk-0.1.0"):
            (self.state / name).mkdir()
        (self.state / "preparation-output" / "consumer-preparation.json").write_text(
            json.dumps(receipt()) + "\n", encoding="utf-8")
        (self.state / "preparation-output" / "tool-bootstrap.json").write_text(
            json.dumps({"schema": "fixture-tool-bootstrap"}) + "\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_capture_counts_scoped_regular_files_without_following_links(self) -> None:
        source = self.state / "source"
        first = source / "source.bin"
        first.write_bytes(b"abc")
        (source / "hardlink.bin").hardlink_to(first)
        (source / "linked.bin").symlink_to(first)
        (self.state / "retained" / "launcher").write_bytes(b"retain")
        (self.state / "ami-rust-python-bootstrap" / "python").write_bytes(b"py")
        (self.state / "preparation" / "cache").write_bytes(b"cache")
        (self.state / "sdk-0.1.0" / "sdk").write_bytes(b"sdk")
        (self.project / "input.rs").write_bytes(b"source")
        (self.buildroot / "AMIRUST").write_bytes(b"binary")

        result = measure.capture(self.state, self.project, self.buildroot)
        self.assertEqual(result["schema"], "ami-rust-resource-observations-v1")
        source_scope = result["scopes"]["source"]
        self.assertEqual(source_scope["regular_file_count"], 1)
        self.assertEqual(source_scope["regular_file_bytes"], 3)
        self.assertEqual(source_scope["symlink_count"], 1)
        self.assertFalse(source_scope["symlinks_followed"])
        self.assertGreaterEqual(source_scope["allocated_file_bytes"], 0)
        self.assertEqual(result["scopes"]["retained_snapshot"]["regular_file_bytes"], 6)
        self.assertEqual(result["scopes"]["python_bootstrap"]["regular_file_bytes"], 2)
        self.assertEqual(result["scopes"]["installed_sdk"]["regular_file_bytes"], 3)
        self.assertEqual(result["scopes"]["project"]["regular_file_bytes"], 6)
        self.assertEqual(result["scopes"]["build_outputs"]["regular_file_bytes"], 6)
        self.assertEqual(result["scopes"]["whole_sdk_state"]["regular_file_count"], 7)

        original = result["original_sdk_supervisor"]
        self.assertEqual(original["scope"], "original_sdk_supervisor")
        self.assertIn("not whole-machine", original["scope_note"])
        self.assertEqual(original["capacity"]["physical_ram_bytes"], 200)
        self.assertEqual(original["commands"][0]["rss_peak_observed_bytes"], 300)
        self.assertEqual(original["commands"][0]["managed_peak_observed_bytes"], 400)
        self.assertEqual(original["components"]["rust"]["regular_file_bytes"], 500)
        self.assertEqual(original["source_identity"]["source_sha"], "a" * 40)
        self.assertEqual(original["selection_pins"]["selection_sha256"], "c" * 64)

    def test_copy_original_receipts_preserves_bytes_and_hashes(self) -> None:
        destination = self.root / "copied-receipts"
        result = measure.copy_original_receipts(self.state, destination)
        self.assertEqual(result["scope"], "original_sdk_supervisor_receipts")
        self.assertEqual({row["path"] for row in result["files"]},
                         {"consumer-preparation.json", "tool-bootstrap.json"})
        for row in result["files"]:
            original = self.state / "preparation-output" / row["path"]
            copied = destination / row["path"]
            self.assertEqual(copied.read_bytes(), original.read_bytes())
            self.assertEqual(row["bytes"], copied.stat().st_size)
            self.assertEqual(row["sha256"], hashlib.sha256(copied.read_bytes()).hexdigest())
        with self.assertRaises(measure.MeasureError):
            measure.copy_original_receipts(self.state, destination)

    def test_bad_original_receipt_fails_capture(self) -> None:
        receipt_path = self.state / "preparation-output" / "consumer-preparation.json"
        receipt_path.write_text('{"schema":"ami-rust-consumer-preparation-v1",'
                                '"schema":"duplicate"}', encoding="utf-8")
        with self.assertRaises(measure.MeasureError):
            measure.capture(self.state, self.project, self.buildroot)

        receipt_path.write_text(json.dumps(receipt() | {
            "commands": [{"label": "bad", "elapsed_seconds": -1,
                          "rss_peak_observed_bytes": 0, "managed_peak_observed_bytes": 0}]
        }), encoding="utf-8")
        with self.assertRaises(measure.MeasureError):
            measure.capture(self.state, self.project, self.buildroot)

    def test_disk_sampler_reports_observed_volume_free_delta(self) -> None:
        samples = [1000, 700, 850]
        lock = threading.Lock()
        reached = threading.Event()
        calls = 0

        def fake_disk_usage(_root):
            nonlocal calls
            with lock:
                index = min(calls, len(samples) - 1)
                calls += 1
                if calls >= len(samples):
                    reached.set()
                return SimpleNamespace(free=samples[index])

        sampler = measure.DiskSampler(self.root, interval=0.001,
                                      disk_usage=fake_disk_usage).start()
        self.assertTrue(reached.wait(1.0), "sampler did not observe all fixture values")
        record = sampler.stop()
        self.assertEqual(record["scope"], "observed_volume_free_space_delta")
        self.assertEqual(record["sampling_interval_seconds"], 0.001)
        self.assertEqual(record["start_free_bytes"], 1000)
        self.assertEqual(record["minimum_free_bytes"], 700)
        self.assertEqual(record["peak_free_delta_bytes"], 300)
        self.assertEqual(record["sample_count"], 3)
        self.assertIsNone(record["sampling_error"])
        self.assertTrue(record["thread_stopped"])

    def test_disk_sampler_retains_sampling_error(self) -> None:
        reached = threading.Event()
        calls = 0

        def failing_disk_usage(_root):
            nonlocal calls
            calls += 1
            if calls == 1:
                return SimpleNamespace(free=500)
            reached.set()
            raise OSError("fixture disk failure")

        sampler = measure.DiskSampler(self.root, interval=0.001,
                                      disk_usage=failing_disk_usage).start()
        self.assertTrue(reached.wait(1.0))
        record = sampler.stop()
        self.assertEqual(record["start_free_bytes"], 500)
        self.assertEqual(record["minimum_free_bytes"], 500)
        self.assertEqual(record["peak_free_delta_bytes"], 0)
        self.assertIn("fixture disk failure", record["sampling_error"])
        self.assertTrue(record["thread_stopped"])


if __name__ == "__main__":
    unittest.main()
