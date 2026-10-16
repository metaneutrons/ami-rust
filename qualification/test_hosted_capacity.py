"""Boundary and regression checks for local free-space admission."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("local_capacity", Path(__file__).with_name("hosted_capacity.py"))
capacity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(capacity)


class LocalCapacityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "source"
        self.backups = self.root / "AROS-M0-Backups"
        (self.source / "release").mkdir(parents=True)
        self.backups.mkdir()
        self.minimum = 32 * 1024**3
        self.policy = {"schema": "ami-rust-local-storage-v2", "mode": "free-space-headroom",
                       "minimum_free_bytes": self.minimum, "per_file_quotas": False,
                       "fixed_archive_quota_bytes": None, "preserve_existing_evidence": True}
        self.write_policy()
        self.roots = patch.multiple(capacity, ROOT=self.source, BACKUPS=self.backups)
        self.roots.start()
        self.addCleanup(self.roots.stop)
        self.addCleanup(self.temp.cleanup)

    def write_policy(self):
        (self.source / "release/ci-resources.json").write_text(json.dumps({"local_storage": self.policy}))

    def test_operation_admission_keeps_headroom_and_checks_a_shared_volume_once(self):
        peak = 2 * 1024**3
        calls = []
        def usage(path):
            calls.append(path)
            return SimpleNamespace(free=self.minimum + peak)
        result = capacity.check(reserve=peak, disk_usage=usage)
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["volumes"][0]["free_after_planned_peak_bytes"], self.minimum)
        with self.assertRaisesRegex(RuntimeError, "insufficient free disk"):
            capacity.check(reserve=peak, disk_usage=lambda path: SimpleNamespace(free=self.minimum + peak - 1))

    def test_two_megabyte_source_copy_is_not_subject_to_a_one_megabyte_quota(self):
        source = self.source / "licence.txt"
        original = b"x" * (2 * 1024**2)
        source.write_bytes(original)
        with patch.object(capacity.shutil, "disk_usage", return_value=SimpleNamespace(free=100 * 1024**3)):
            capacity.reserve_file(source, 1024**2)
            result = capacity.check()
            capacity.release_file(source)
        self.assertFalse(result["per_file_quotas"])
        self.assertIsNone(result["fixed_archive_quota_bytes"])
        self.assertEqual(source.read_bytes(), original)
        self.assertFalse((self.source / "qualification/r1-hosted/active-budget").exists())

    def test_invalid_peak_and_reintroduced_small_quotas_fail_closed(self):
        for peak in (-1, True, 1.5):
            with self.assertRaises(ValueError):
                capacity.check(reserve=peak)
        self.policy["per_file_quotas"] = True
        self.write_policy()
        with self.assertRaisesRegex(ValueError, "invalid local free-space policy"):
            capacity.check()

    def test_separate_storage_volumes_are_both_checked(self):
        class Volume:
            def __init__(self, path, device):
                self.path, self.device = path, device
            def __truediv__(self, name):
                return self.path / name
            def stat(self):
                return SimpleNamespace(st_dev=self.device)
            def is_dir(self):
                return True
            def __str__(self):
                return str(self.path)
        source, backups = Volume(self.source, 1), Volume(self.backups, 2)
        with patch.multiple(capacity, ROOT=source, BACKUPS=backups):
            with self.assertRaisesRegex(RuntimeError, "insufficient"):
                capacity.check(disk_usage=lambda path: SimpleNamespace(
                    free=self.minimum if path is source else self.minimum - 1))

    def test_missing_optional_backup_directory_does_not_block_an_edit_session(self):
        self.backups.rmdir()
        result = capacity.check(disk_usage=lambda path: SimpleNamespace(free=self.minimum))
        self.assertEqual(len(result["volumes"]), 1)


if __name__ == "__main__":
    unittest.main()
