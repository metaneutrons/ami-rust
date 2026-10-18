#!/usr/bin/env python3
"""Tests for bounded package lifecycle qualification and replay."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


_QUALIFY_PATH = Path(__file__).with_name("qualify.py")
_SPEC = importlib.util.spec_from_file_location("ami_rust_qualify", _QUALIFY_PATH)
assert _SPEC is not None and _SPEC.loader is not None
qualify = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(qualify)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _create_fake_replay(root: Path, mutation: str = "none") -> tuple[Path, bytes]:
    root.mkdir(parents=True)
    home = root / "user-home"
    settings = home / ".rustup" / "settings.toml"
    settings.parent.mkdir(parents=True)
    settings.write_text('version = "12"\ndefault_toolchain = "stable"\n', encoding="utf-8")
    project = root / "hello-aros"
    project.mkdir()
    (project / "Cargo.toml").write_text('[package]\nname = "fixture"\nversion = "0.1.0"\n', encoding="utf-8")
    (project / "Cargo.lock").write_text('version = 4\n\n[[package]]\nname = "fixture"\nversion = "0.1.0"\n', encoding="utf-8")
    state = root / "ami-rust-0.1.0-state"
    state.mkdir()
    native = b"fixture-native-output-v1\n"

    script = f"""#!{sys.executable}
import sys
from pathlib import Path

mutation = {mutation!r}
arguments = sys.argv[1:]
command = arguments[0] if arguments else ""
if command == "verify-package":
    print("verified fixture package")
elif command == "check-inputs":
    print("checked fixture inputs")
elif command == "build":
    output = Path(arguments[arguments.index("--output-dir") + 1])
    output.mkdir(parents=True)
    artifacts = output / "artifacts"
    artifacts.mkdir()
    content = b"fixture-native-output-drift\\n" if mutation == "native" else b"fixture-native-output-v1\\n"
    (artifacts / "AMIRUST").write_bytes(content)
    project = Path(arguments[arguments.index("--project") + 1])
    if mutation == "project":
        (project / "Cargo.toml").write_text("changed project\\n")
    if mutation == "settings":
        settings = Path.home() / ".rustup/settings.toml"
        settings.write_text("changed global Rust settings\\n")
else:
    raise SystemExit("unexpected fixture command: " + command)
"""
    executable = root / "fake-ami-rust"
    executable.write_text(script, encoding="utf-8")
    executable.chmod(0o755)
    persistent = {
        "state": str(state),
        "project": str(project),
        "project_inventory": qualify.project_inventory(project),
        "hello_native_sha256": _digest(native),
        "reference_native_sha256": _digest(b"fixture-reference-native\n"),
        "rustup_settings_sha256": qualify.sha(settings),
    }
    (root / "persistent.json").write_text(json.dumps(persistent, indent=2) + "\n", encoding="utf-8")
    return executable, native


class CampaignTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_run_records_success_and_failure_logs(self) -> None:
        success = qualify.Campaign(self.root, Path(sys.executable), "success")
        success.run(
            "harmless-child",
            [sys.executable, "-I", "-B", "-c", "import sys; print('out'); print('err', file=sys.stderr)"],
        )
        row = json.loads((success.output / "harmless-child.json").read_text(encoding="utf-8"))
        self.assertEqual(row["exit_code"], 0)
        self.assertEqual((success.output / "harmless-child.stdout.log").read_text(encoding="utf-8"), "out\n")
        self.assertEqual((success.output / "harmless-child.stderr.log").read_text(encoding="utf-8"), "err\n")

        failure = qualify.Campaign(self.root, Path(sys.executable), "failure")
        with self.assertRaisesRegex(RuntimeError, "failed with exit 7"):
            failure.run(
                "failing-child",
                [sys.executable, "-I", "-B", "-c", "import sys; print('failure-out'); print('failure-err', file=sys.stderr); sys.exit(7)"],
            )
        failed_row = json.loads((failure.output / "failing-child.json").read_text(encoding="utf-8"))
        self.assertEqual(failed_row["exit_code"], 7)
        self.assertIn("failure-out", (failure.output / "failing-child.stdout.log").read_text(encoding="utf-8"))
        self.assertIn("failure-err", (failure.output / "failing-child.stderr.log").read_text(encoding="utf-8"))

    def test_expired_cutoff_refuses_to_start_child(self) -> None:
        campaign = qualify.Campaign(self.root, Path(sys.executable), "expired")
        marker = self.root / "child-started"
        child = [sys.executable, "-I", "-B", "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        with mock.patch.object(qualify.time, "time", return_value=campaign.start + 5100):
            with self.assertRaisesRegex(TimeoutError, "execution cutoff"):
                campaign.run("must-not-run", child)
        self.assertFalse(marker.exists())
        self.assertFalse((campaign.output / "must-not-run.stdout.log").exists())
        self.assertEqual(campaign.rows, [])

    def test_timeout_kills_process_group_and_retains_exit_124_evidence(self) -> None:
        campaign = qualify.Campaign(self.root, Path(sys.executable), "timeout")

        class TimedOutChild:
            pid = 4312

            def __init__(self) -> None:
                self.wait_count = 0

            def wait(self, timeout=None):
                self.wait_count += 1
                if self.wait_count == 1:
                    raise subprocess.TimeoutExpired(["fixture-child"], timeout)
                return -signal.SIGKILL

        child = TimedOutChild()
        with mock.patch.object(qualify.subprocess, "Popen", return_value=child):
            with mock.patch.object(qualify.os, "killpg") as killpg:
                with self.assertRaisesRegex(RuntimeError, "failed with exit 124"):
                    campaign.run("timed-child", ["fixture-child"])
        killpg.assert_called_once_with(child.pid, signal.SIGKILL)
        self.assertEqual(child.wait_count, 2)
        row = json.loads((campaign.output / "timed-child.json").read_text(encoding="utf-8"))
        self.assertEqual(row["exit_code"], 124)
        self.assertTrue((campaign.output / "timed-child.stdout.log").is_file())
        self.assertTrue((campaign.output / "timed-child.stderr.log").is_file())


class ReplayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_fixture_replay_passes_and_preserves_project_and_settings(self) -> None:
        root = self.root / "passing"
        executable, _native = _create_fake_replay(root)
        with contextlib.redirect_stdout(io.StringIO()):
            qualify.replay(root, executable, "fixture-pass")
        result = json.loads((root / "evidence-fixture-pass/result.json").read_text(encoding="utf-8"))
        self.assertEqual(result["status"], "PASS_PACKAGE_LIFECYCLE_REPLAY_NOT_CHANNEL_PUBLICATION")
        self.assertTrue(result["project_preserved"])
        self.assertTrue(result["global_rust_preserved"])
        self.assertEqual(result["native_sha256"], _digest(b"fixture-native-output-v1\n"))

    def test_native_project_or_settings_drift_records_failure_never_pass(self) -> None:
        for mutation in ("native", "project", "settings"):
            with self.subTest(mutation=mutation):
                root = self.root / mutation
                executable, _native = _create_fake_replay(root, mutation)
                with contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises((RuntimeError, ValueError)):
                        qualify.replay(root, executable, "fixture-" + mutation)
                result = json.loads(
                    (root / ("evidence-fixture-" + mutation) / "result.json").read_text(encoding="utf-8")
                )
                self.assertTrue(result["status"].startswith("FAIL_"))
                self.assertFalse(result["status"].startswith("PASS"))
                self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
