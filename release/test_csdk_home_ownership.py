#!/usr/bin/env python3
"""Focused HOME/TMP handoff regression using the real Supervisor and inner CLI."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT / "tools/supervise-portable-csdk-linux-aarch64.py"
CI_CARGO = ROOT / "release/ci_cargo.py"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load test dependency: " + str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class HomeOwnershipHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.driver = load_module(DRIVER, "csdk_home_handoff_driver_fixture")
        cls.ci_cargo = load_module(CI_CARGO, "csdk_home_handoff_ci_cargo_fixture")
        # Keep the existing Supervisor's measured checkout small and explicit.
        cls.ci_cargo.ROOT = ROOT

    def run_inner(self, missing_tmp: bool = False, bad_home_mode: bool = False):
        with tempfile.TemporaryDirectory(prefix="csdk-home-handoff-") as temporary:
            run = Path(temporary)
            repo = run / "source"
            (repo / "release").mkdir(parents=True)
            # The first frozen source pin matches; the next absent pin stops
            # before host checks, downloads, or compiler use.
            (repo / "release/ci_cargo.py").write_bytes(CI_CARGO.read_bytes())
            managed = run / "managed"
            managed.mkdir(mode=0o700)
            output = run / "output"
            (output / "artifact").mkdir(parents=True)
            runtime = self.driver.create_outer_runtime_directories(managed)
            before = {name: (path.stat().st_dev, path.stat().st_ino, path.stat().st_mode)
                      for name, path in runtime.items()}
            if missing_tmp:
                runtime["tmp"].rmdir()
            if bad_home_mode:
                runtime["home"].chmod(0o755)
            logs = managed / "observer-logs"
            logs.mkdir(mode=0o700)
            env = {
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "HOME": str(runtime["home"]),
                "TMPDIR": str(runtime["tmp"]),
                "TMP": str(runtime["tmp"]),
                "TEMP": str(runtime["tmp"]),
                "GITHUB_SHA": "0" * 40,
                "GITHUB_RUN_ID": "1",
                "GITHUB_RUN_ATTEMPT": "1",
                "CSDK_CAMPAIGN_START_EPOCH": str(int(time.time())),
                "CSDK_POLICY_SHA256": "0" * 64,
                "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_OPTIONAL_LOCKS": "0",
            }
            supervisor = self.ci_cargo.Supervisor(managed, output, env, logs)
            command = [sys.executable, "-I", "-B", str(DRIVER), "--inner",
                       "--repo", str(repo), "--managed-root", str(managed),
                       "--outer-output", str(output)]
            try:
                supervisor.run(command, cwd=repo, label="home-handoff", timeout=20,
                               cleanup_descendant_groups=True)
                self.fail("expected the incomplete pinned-source fixture to fail")
            except RuntimeError as error:
                self.assertIn("home-handoff failed: exit 1", str(error))
                self.assertEqual(len(supervisor.commands), 1)
                row = supervisor.commands[0]
            receipt = json.loads((output / "artifact/inner-result.json").read_text())
            stderr = (logs / "home-handoff.stderr.log").read_text()
            self.assertEqual(row["exit_code"], 1)
            self.assertIsNone(row["stop_reason"])
            self.assertFalse(row["incomplete_cleanup"])
            self.assertEqual(receipt["status"], "FAILED")
            self.assertFalse(receipt["sdk_l1_rc4_or_release_acceptance"])
            self.assertNotIn("FileExistsError", stderr)
            if missing_tmp:
                self.assertIn("outer runtime directory is missing: tmp", stderr)
            elif bad_home_mode:
                self.assertIn("outer runtime directory is not a private owned directory: home",
                              stderr)
            else:
                self.assertIn("expected a regular file:", stderr)
                self.assertIn("release/ci-resources.json", stderr)
                after = {name: (path.stat().st_dev, path.stat().st_ino, path.stat().st_mode)
                         for name, path in runtime.items()}
                self.assertEqual(before, after)
            return row, receipt, stderr

    def test_outer_created_directories_are_reused_by_inner_process(self):
        row, receipt, stderr = self.run_inner()
        self.assertEqual(receipt["stage"], "exception")
        self.assertIn("portable C-SDK candidate producer failed", stderr)

    def test_inner_refuses_missing_outer_directory_before_pinned_source_work(self):
        _, receipt, stderr = self.run_inner(missing_tmp=True)
        self.assertIn("outer runtime directory is missing: tmp", receipt["failure"])
        self.assertNotIn("expected a regular file", stderr)

    def test_inner_refuses_nonprivate_runtime_directory(self):
        _, receipt, stderr = self.run_inner(bad_home_mode=True)
        self.assertIn("not a private owned directory: home", receipt["failure"])
        self.assertNotIn("expected a regular file", stderr)

    def test_inner_refuses_symlinked_runtime_directory(self):
        with tempfile.TemporaryDirectory(prefix="csdk-home-symlink-") as temporary:
            root = Path(temporary)
            managed = root / "managed"
            managed.mkdir()
            target = root / "target"
            target.mkdir(mode=0o700)
            (managed / "home").symlink_to(target, target_is_directory=True)
            (managed / "tmp").mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError, "private owned directory: home"):
                self.driver.require_outer_runtime_directories(managed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
