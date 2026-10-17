#!/usr/bin/env python3
"""Differential fixtures for the hosted SDK supervisor's byte accounting."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "release/ci_sdk.py"
spec = importlib.util.spec_from_file_location("_test_sdk_storage_accounting", SCRIPT)
assert spec and spec.loader
ci_sdk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci_sdk)


def old_directory_bytes(root: Path) -> int:
    """Literal two-pass implementation retained as the differential oracle."""
    total = 0
    if not root.exists():
        return 0
    for path in root.rglob("*"):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
    return total


def old_logs_bytes(root: Path) -> int:
    total = 0
    if not root.exists():
        return 0
    for path in root.rglob("*.log"):
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISREG(info.st_mode):
            total += info.st_size
    return total


class StorageAccountingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = Path(tempfile.mkdtemp(prefix="ami-rust-storage-accounting-"))
        self.work = self.temporary / "work"
        self.output = self.temporary / "output"
        self.python_root = self.temporary / "python"
        for root in (self.work, self.output, self.python_root):
            root.mkdir()

    def tearDown(self):
        shutil.rmtree(self.temporary)

    def _supervisor(self, work=None, output=None, python_root=None):
        supervisor = ci_sdk.Supervisor(
            work or self.work, output or self.output, python_root or self.python_root,
            {"PATH": "/usr/bin:/bin"})
        # Keep the checkout contribution explicit and stable in these fixtures.
        supervisor.checkout_bytes = 37
        return supervisor

    def _old_sample(self, supervisor):
        roots = (supervisor.work, supervisor.output, supervisor.python_root)
        return (supervisor.checkout_bytes + sum(old_directory_bytes(root) for root in roots),
                sum(old_logs_bytes(root) for root in roots))

    def test_combined_sample_matches_two_pass_oracle_with_names_and_links(self):
        (self.work / "nested folder" / ".hidden").mkdir(parents=True)
        (self.output / "Unicode 雪").mkdir()
        (self.python_root / "nested").mkdir()
        (self.work / "space name.bin").write_bytes(b"abcde")
        (self.work / "nested folder" / ".hidden" / "雪 space.log").write_bytes(b"hidden-log")
        (self.output / "Unicode 雪" / "empty.log").write_bytes(b"")
        (self.output / "UPPER.LOG").write_bytes(b"not a lowercase log suffix")
        (self.python_root / "nested" / "build output.log").write_bytes(b"log-bytes")

        outside = self.temporary / "outside directory"
        outside.mkdir()
        (outside / "must-not-count.log").write_bytes(b"outside")
        (self.work / "linked directory").symlink_to(outside, target_is_directory=True)
        (self.output / "linked-file.log").symlink_to(self.work / "space name.bin")
        (self.python_root / "dangling.log").symlink_to(self.temporary / "missing target")

        supervisor = self._supervisor()
        expected = self._old_sample(supervisor)
        self.assertEqual(supervisor.accounting_sample(), expected)
        self.assertEqual(supervisor.managed_bytes(), expected[0])
        self.assertEqual(supervisor.logs_bytes(), expected[1])
        self.assertEqual(ci_sdk.directory_accounting(self.work),
                         (old_directory_bytes(self.work), old_logs_bytes(self.work)))

    def test_empty_and_missing_roots_match_old_behavior(self):
        empty = self.temporary / "empty"
        empty.mkdir()
        missing = self.temporary / "missing"
        self.assertEqual(ci_sdk.directory_accounting(empty),
                         (old_directory_bytes(empty), old_logs_bytes(empty)))
        self.assertEqual(ci_sdk.directory_accounting(missing), (0, 0))
        self.assertEqual((old_directory_bytes(missing), old_logs_bytes(missing)), (0, 0))

    def test_overlapping_roots_keep_duplicate_accounting(self):
        work = self.temporary / "overlap"
        output = work / "nested output"
        python_root = output / "python root"
        python_root.mkdir(parents=True)
        (work / "root.log").write_bytes(b"root")
        (output / "output.log").write_bytes(b"out")
        (python_root / "python.log").write_bytes(b"py")
        supervisor = self._supervisor(work, output, python_root)

        expected = self._old_sample(supervisor)
        observed = supervisor.accounting_sample()
        self.assertEqual(observed, expected)
        # The nested output and Python files are included through each root,
        # matching the former independent per-root sums.
        self.assertEqual(observed[0], 37 + sum(old_directory_bytes(root)
                                               for root in (work, output, python_root)))
        self.assertEqual(observed[1], sum(old_logs_bytes(root)
                                          for root in (work, output, python_root)))

    def test_growth_and_removal_are_visible_between_samples(self):
        supervisor = self._supervisor()
        baseline = supervisor.accounting_sample()
        path = self.work / "dynamic.log"
        path.write_bytes(b"abc")
        grown = supervisor.accounting_sample()
        self.assertEqual(grown, self._old_sample(supervisor))
        self.assertEqual(grown[0] - baseline[0], 3)
        self.assertEqual(grown[1] - baseline[1], 3)

        path.write_bytes(b"abcdefgh")
        extended = supervisor.accounting_sample()
        self.assertEqual(extended, self._old_sample(supervisor))
        self.assertEqual(extended[0] - baseline[0], 8)
        self.assertEqual(extended[1] - baseline[1], 8)

        path.unlink()
        removed = supervisor.accounting_sample()
        self.assertEqual(removed, baseline)
        self.assertEqual(removed, self._old_sample(supervisor))

    def test_workspace_and_log_ceilings_use_one_combined_sample(self):
        (self.work / "ordinary.bin").write_bytes(b"1234")
        (self.output / "known.log").write_bytes(b"abc")
        supervisor = self._supervisor()
        supervisor.checkout_bytes = 0
        total, logs = supervisor.accounting_sample()
        self.assertEqual((total, logs), (7, 3))

        supervisor.limits["workspace_bytes"] = total - 1
        supervisor.limits["log_bytes"] = logs + 10
        with self.assertRaisesRegex(RuntimeError, "workspace ceiling"):
            supervisor.check_limits("non-log ceiling fixture")

        supervisor.limits["workspace_bytes"] = total
        supervisor.limits["log_bytes"] = logs - 1
        with self.assertRaisesRegex(RuntimeError, "log ceiling"):
            supervisor.check_limits("log ceiling fixture")

        supervisor.limits["log_bytes"] = logs
        with patch.object(supervisor, "accounting_sample",
                          wraps=supervisor.accounting_sample) as sample:
            supervisor.check_limits("exact ceiling fixture")
        sample.assert_called_once_with()

    def test_scan_errors_fail_closed(self):
        for error in (PermissionError("denied fixture"), OSError(5, "I/O fixture")):
            with self.subTest(error=type(error).__name__):
                with patch.object(ci_sdk.os, "scandir", side_effect=error):
                    with self.assertRaises(type(error)):
                        ci_sdk.directory_accounting(self.work)

    def test_vanished_child_is_skipped_and_symlink_replacement_fails_closed(self):
        real_open = os.open
        disappearing = self.work / "vanishing child"
        disappearing.mkdir()
        (disappearing / "payload.bin").write_bytes(b"must not be counted after removal")
        vanished_open = []

        def remove_child_before_open(path, flags, *args, **kwargs):
            if path == disappearing.name and kwargs.get("dir_fd") is not None:
                vanished_open.append(path)
                (disappearing / "payload.bin").unlink()
                disappearing.rmdir()
            return real_open(path, flags, *args, **kwargs)

        with patch.object(ci_sdk.os, "open", side_effect=remove_child_before_open):
            self.assertEqual(ci_sdk.directory_accounting(self.work), (0, 0))
        self.assertEqual(vanished_open, [disappearing.name])
        self.assertFalse(disappearing.exists())

        replaced = self.work / "replaced child"
        replaced.mkdir()
        (replaced / "payload.bin").write_bytes(b"must not be counted through link")
        outside = self.temporary / "outside target"
        outside.mkdir()
        (outside / "target.log").write_bytes(b"must never be followed")
        replaced_open = []

        def replace_child_with_symlink(path, flags, *args, **kwargs):
            if path == replaced.name and kwargs.get("dir_fd") is not None:
                replaced_open.append(path)
                (replaced / "payload.bin").unlink()
                replaced.rmdir()
                replaced.symlink_to(outside, target_is_directory=True)
            return real_open(path, flags, *args, **kwargs)

        with patch.object(ci_sdk.os, "open", side_effect=replace_child_with_symlink):
            with self.assertRaises(OSError):
                ci_sdk.directory_accounting(self.work)
        self.assertEqual(replaced_open, [replaced.name])
        self.assertTrue(replaced.is_symlink())
        self.assertTrue((outside / "target.log").is_file())

    def test_child_scandir_error_closes_root_and_child_descriptors(self):
        child = self.work / "inaccessible child"
        child.mkdir()
        (child / "payload.bin").write_bytes(b"fixture")

        real_open, real_close, real_scandir = os.open, os.close, os.scandir
        opened = []
        closed = []
        child_fds = set()

        def tracked_open(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            opened.append(fd)
            if kwargs.get("dir_fd") is not None:
                child_fds.add(fd)
            return fd

        def deny_child_scan(path):
            if isinstance(path, int) and path in child_fds:
                raise PermissionError("injected child scandir denial")
            return real_scandir(path)

        def tracked_close(fd):
            result = real_close(fd)
            closed.append(fd)
            return result

        with patch.object(ci_sdk.os, "open", side_effect=tracked_open), \
                patch.object(ci_sdk.os, "scandir", side_effect=deny_child_scan), \
                patch.object(ci_sdk.os, "close", side_effect=tracked_close):
            with self.assertRaisesRegex(PermissionError, "child scandir denial"):
                ci_sdk.directory_accounting(self.work)
            self.assertEqual(len(opened), 2)
            self.assertEqual(len(set(opened)), 2)
            self.assertCountEqual(closed, opened)
            for fd in opened:
                with self.assertRaises(OSError):
                    os.fstat(fd)


if __name__ == "__main__":
    unittest.main()
