"""Focused UNIT_FIXTURE tests for C-SDK timeout cleanup across process groups."""
from __future__ import annotations

import importlib.util
import contextlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


RELEASE = Path(__file__).resolve().parent
DRIVER_PATH = RELEASE.parent / "tools/supervise-portable-csdk-linux-aarch64.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError("cannot load fixture target " + str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


driver = load_module("csdk_supervision_driver_fixture", DRIVER_PATH)
ci_cargo = load_module("csdk_supervision_ci_cargo_fixture", RELEASE / "ci_cargo.py")
producer = load_module("csdk_supervision_producer_fixture", RELEASE / "csdk_producer.py")


COMPILER_SOURCE = """#!PYTHON
import json, os, signal, subprocess, sys, time
from pathlib import Path
pid_file = Path(os.environ["CSDK_FIXTURE_PIDS"])
ready = Path(os.environ["CSDK_FIXTURE_DESCENDANT_READY"])
marker = Path(os.environ["CSDK_FIXTURE_MARKER"])
cleanup_ready = Path(os.environ["CSDK_FIXTURE_CLEANUP_READY"])
descendant_code = '''import os, signal, sys, time
from pathlib import Path
ready, marker = Path(sys.argv[1]), Path(sys.argv[2])
def stopped(_signum, _frame):
    marker.write_text("descendant stopped")
    raise SystemExit(143)
signal.signal(signal.SIGTERM, stopped)
ready.write_text(str(os.getpid()))
while True: time.sleep(1)
'''
child = subprocess.Popen([sys.executable, "-c", descendant_code, str(ready), str(marker)],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, process_group=0)
deadline = time.monotonic() + 5
while not ready.exists() and time.monotonic() < deadline: time.sleep(0.01)
if not ready.exists(): raise SystemExit("fixture descendant did not start")
def stopped(_signum, _frame):
    cleanup_ready.write_text("compiler cleanup started")
    time.sleep(0.15)
    try: os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError: pass
    try: child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        child.kill()
        try: child.wait(timeout=3)
        except subprocess.TimeoutExpired: pass
    raise SystemExit(143)
signal.signal(signal.SIGTERM, stopped)
pid_file.write_text(json.dumps({"clang_pid": os.getpid(), "clang_pgid": os.getpgid(0),
                                "descendant_pid": child.pid, "descendant_pgid": os.getpgid(child.pid)}))
while True: time.sleep(1)
""".replace("PYTHON", sys.executable)


FIXTURE_SOURCE = """import importlib.util, json, os, sys
from pathlib import Path
source, root = Path(sys.argv[1]), Path(sys.argv[2]).resolve()
spec = importlib.util.spec_from_file_location("fixture_csdk_producer", source)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module.nouveau.EXPECTED_OBJECTS = 1
source_root, build_root, toolchain_root = root / "source", root / "build", root / "toolchain"
for path in (source_root, build_root, toolchain_root): path.mkdir(parents=True, exist_ok=True)
worker_pid_file = root / "worker-pid.json"
worker_pid_file.write_text(json.dumps({"pid": os.getpid(), "ppid": os.getppid(),
                                      "pgid": os.getpgrp()}))
def alive(pid):
    try: os.kill(pid, 0)
    except ProcessLookupError: return False
    return True
def fixture_rows():
    worker = json.loads(worker_pid_file.read_text())
    worker_pid = worker["pid"]
    rows = []
    if alive(worker_pid): rows.append((worker_pid, os.getppid(), worker["pgid"], 2048))
    pid_file = Path(os.environ["CSDK_FIXTURE_PIDS"])
    if pid_file.is_file():
        values = json.loads(pid_file.read_text())
        if alive(values["clang_pid"]):
            rows.append((values["clang_pid"], worker_pid, values["clang_pgid"], 2048))
        if alive(values["descendant_pid"]):
            rows.append((values["descendant_pid"], values["clang_pid"],
                         values["descendant_pgid"], 2048))
    return rows
if sys.platform == "darwin":
    module.nouveau.ci_cargo.process_rows = fixture_rows
compiler = root / "clang-fixture.py"
compiler.write_text(COMPILER_SOURCE)
compiler.chmod(0o755)
work = root / "compile-work"
work.mkdir()
object_path, plan_path = build_root / "fixture.o", root / "nouveau-plan.json"
plan = {"commands": [{"argv": [str(compiler)], "source": "fixture.c", "object": str(object_path)}],
        "ordered_object_paths": [str(object_path)], "working_directory": str(root),
        "compiler": str(compiler),
        "source_root": str(source_root), "build_root": str(build_root),
        "toolchain_root": str(toolchain_root)}
module.nouveau._prepare_outputs(plan)
module.nouveau._write_plan_fresh(plan_path, plan)
try:
    module.compile_nouveau(plan, work, plan_path, jobs=1)
except RuntimeError as error:
    result = {"schema": "UNIT_FIXTURE-csdk-inner-v1", "status": "FAILED",
              "failure": str(error), "candidate_accepted": False}
    (root / "inner-result.json").write_text(json.dumps(result, sort_keys=True) + "\\n")
    print("fixture producer interrupted and recorded failure", file=sys.stderr)
    raise SystemExit(1)
raise SystemExit("fixture compile unexpectedly completed")
"""


def write_fixture(root: Path) -> tuple[Path, Path, dict[str, str]]:
    fixture = root / "compile-fixture.py"
    fixture.write_text(FIXTURE_SOURCE.replace("COMPILER_SOURCE", repr(COMPILER_SOURCE)))
    fixture.chmod(0o600)
    state = root / "state"
    state.mkdir()
    env = dict(os.environ)
    env.update({
        "CSDK_FIXTURE_PIDS": str(state / "clang-pids.json"),
        "CSDK_FIXTURE_DESCENDANT_READY": str(state / "descendant-ready"),
        "CSDK_FIXTURE_MARKER": str(state / "descendant-stopped"),
        "CSDK_FIXTURE_CLEANUP_READY": str(state / "compiler-cleanup-ready"),
        "CSDK_FIXTURE_STUBBORN_PID": str(state / "stubborn-pid"),
    })
    return fixture, state, env


def command_for(fixture: Path, state: Path) -> list[str]:
    return [sys.executable, "-B", str(fixture), str(RELEASE / "csdk_producer.py"),
            str(state.parent)]


def assert_dead(test: unittest.TestCase, pid: int) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.02)
    test.fail("process remained alive after process-group cleanup: " + str(pid))


STUBBORN_SOURCE = """import os, signal, sys, time
from pathlib import Path
record = Path(sys.argv[1])
signal.signal(signal.SIGTERM, signal.SIG_IGN)
record.write_text(str(os.getpid()) + "," + str(os.getpgid(0)))
while True: time.sleep(1)
"""


FALLBACK_WORKER_SOURCE = """import json, os, signal, subprocess, sys, time
from pathlib import Path
root = Path(sys.argv[1])
signal.signal(signal.SIGTERM, signal.SIG_IGN)
worker = {"pid": os.getpid(), "ppid": os.getppid(), "pgid": os.getpgid(0)}
(root / "worker-pid.json").write_text(json.dumps(worker))
env = os.environ.copy()
compiler = subprocess.Popen([sys.executable, "-c", COMPILER_SOURCE], env=env,
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, process_group=0)
stubborn_file = Path(env["CSDK_FIXTURE_STUBBORN_PID"])
stubborn = subprocess.Popen([sys.executable, "-c", STUBBORN_SOURCE, str(stubborn_file)],
                            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, process_group=0)
deadline = time.monotonic() + 5
while (not Path(env["CSDK_FIXTURE_PIDS"]).is_file() or not stubborn_file.is_file()):
    if time.monotonic() >= deadline: raise SystemExit("fallback children did not start")
    time.sleep(0.01)
compiler_row = json.loads(Path(env["CSDK_FIXTURE_PIDS"]).read_text())
stubborn_pid, stubborn_pgid = map(int, stubborn_file.read_text().split(","))
rows = {"worker": worker,
        "clang": {"pid": compiler_row["clang_pid"], "ppid": os.getpid(),
                  "pgid": compiler_row["clang_pgid"]},
        "descendant": {"pid": compiler_row["descendant_pid"],
                       "ppid": compiler_row["clang_pid"],
                       "pgid": compiler_row["descendant_pgid"]},
        "stubborn": {"pid": stubborn_pid, "ppid": os.getpid(), "pgid": stubborn_pgid}}
(root / "fallback-pids.json").write_text(json.dumps(rows, sort_keys=True))
while True:
    compiler.poll()
    stubborn.poll()
    time.sleep(0.01)
"""


def fallback_command(root: Path) -> list[str]:
    script = root / "fallback-worker.py"
    source = FALLBACK_WORKER_SOURCE.replace("COMPILER_SOURCE", repr(COMPILER_SOURCE))
    source = source.replace("STUBBORN_SOURCE", repr(STUBBORN_SOURCE))
    script.write_text(source)
    return [sys.executable, "-B", str(script), str(root)]


def fixture_process_rows(root: Path):
    rows = []
    worker_path = root / "worker-pid.json"
    if not worker_path.is_file():
        return rows
    fallback_path = root / "fallback-pids.json"
    if fallback_path.is_file():
        values = json.loads(fallback_path.read_text())
        records = [values[key] for key in ("worker", "clang", "descendant", "stubborn")]
    else:
        worker = json.loads(worker_path.read_text())
        records = [worker]
        compiler_path = root / "state" / "clang-pids.json"
        if compiler_path.is_file():
            values = json.loads(compiler_path.read_text())
            records.extend([
                {"pid": values["clang_pid"], "ppid": worker["pid"],
                 "pgid": values["clang_pgid"]},
                {"pid": values["descendant_pid"], "ppid": values["clang_pid"],
                 "pgid": values["descendant_pgid"]},
            ])
    for row in records:
        try:
            os.kill(row["pid"], 0)
        except ProcessLookupError:
            continue
        rows.append((row["pid"], row["ppid"], row["pgid"], 2048))
    return rows


def duplicate_sigterm_after_cleanup_starts(root: Path):
    sent = threading.Event()
    errors = []

    def signal_twice():
        marker = root / "state" / "compiler-cleanup-ready"
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not marker.is_file():
            time.sleep(0.01)
        try:
            worker = json.loads((root / "worker-pid.json").read_text())
            os.kill(worker["pid"], signal.SIGTERM)
            sent.set()
        except BaseException as error:
            errors.append(type(error).__name__ + ": " + str(error))

    thread = threading.Thread(target=signal_twice, daemon=True)
    thread.start()
    return sent, thread, errors


def signal_driver_twice_around_cleanup(root: Path):
    sent = threading.Event()
    errors = []
    driver_pid = os.getpid()

    def signal_twice():
        clang_pids = root / "state" / "clang-pids.json"
        cleanup_ready = root / "state" / "compiler-cleanup-ready"
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not clang_pids.is_file():
            time.sleep(0.01)
        try:
            os.kill(driver_pid, signal.SIGTERM)
            while time.monotonic() < deadline and not cleanup_ready.is_file():
                time.sleep(0.01)
            os.kill(driver_pid, signal.SIGTERM)
            sent.set()
        except BaseException as error:
            errors.append(type(error).__name__ + ": " + str(error))

    thread = threading.Thread(target=signal_twice, daemon=True)
    thread.start()
    return sent, thread, errors


def process_rows_fixture_context(root: Path):
    if sys.platform == "darwin":
        return mock.patch.object(ci_cargo, "process_rows",
                                 side_effect=lambda: fixture_process_rows(root))
    return contextlib.nullcontext()


class ProducerTimeoutTests(unittest.TestCase):
    def assert_fixture_stopped(self, root: Path, state: Path,
                               expected_signals: int = 2) -> None:
        values = json.loads((state / "clang-pids.json").read_text())
        worker = json.loads((root / "worker-pid.json").read_text())
        self.assertEqual(values["clang_pid"], values["clang_pgid"])
        self.assertEqual(values["descendant_pid"], values["descendant_pgid"])
        self.assertNotEqual(values["descendant_pgid"], values["clang_pgid"])
        self.assertNotEqual(values["clang_pgid"], worker["pgid"])
        self.assertTrue((state / "descendant-stopped").is_file())
        for pid in (worker["pid"], values["clang_pid"], values["descendant_pid"]):
            assert_dead(self, pid)
        self.assertEqual(json.loads((root / "inner-result.json").read_text())["status"], "FAILED")
        self.assertFalse((root / "csdk-output" / "csdk-producer.json").exists())
        plan = json.loads((root / "nouveau-plan.json").read_text())
        self.assertEqual(plan["status"], "FAIL_COMPILE")
        self.assertTrue(plan["compile"]["interrupted"])
        self.assertEqual(plan["compile"]["sigterm_delivery_count"], expected_signals)
        self.assertEqual(plan["compile"]["signal_cleanup_attempts"], 1)
        self.assertEqual(plan["compile"]["cleanup_status"], "complete")
        self.assertFalse(plan["compile"]["incomplete_cleanup"])
        self.assertTrue(plan["compile"]["process_group_cleanup"])
        logs = Path(plan["compile"]["logs_directory"])
        self.assertTrue((logs / "0000.stdout.log").is_file())
        self.assertTrue((logs / "0000.stderr.log").is_file())
        self.assertLessEqual(sum(p.stat().st_size for p in logs.iterdir() if p.is_file()),
                             producer.nouveau.MAX_AGGREGATE_SAVED_LOG_BYTES)

    def test_campaign_producer_deadline_signals_and_reaps_clang_group(self):
        with tempfile.TemporaryDirectory(prefix="csdk-producer-timeout-") as temp:
            root = Path(temp)
            fixture, state, env = write_fixture(root)
            stdout_path, stderr_path = root / "producer.stdout.log", root / "producer.stderr.log"
            timeout_record = root / "producer-timeout.json"
            sent, thread, errors = duplicate_sigterm_after_cleanup_starts(root)
            with process_rows_fixture_context(root):
                with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
                    with self.assertRaisesRegex(TimeoutError, "producer deadline failed"):
                        driver.run_child_with_deadline(
                            command_for(fixture, state), cwd=root, env=env,
                            stdout=stdout, stderr=stderr, timeout=1.0,
                            label="UNIT_FIXTURE producer deadline", timeout_record=timeout_record,
                            ci_cargo_module=ci_cargo)
            thread.join(timeout=1)
            self.assertTrue(sent.is_set(), errors)
            self.assertFalse(errors)
            record = json.loads(timeout_record.read_text())
            self.assertEqual(record["status"], "FAILED")
            self.assertFalse(record["candidate_accepted"])
            self.assertEqual(record["termination_reason"], "producer_deadline")
            self.assertFalse(record["direct_child_sigkill_fallback"])
            self.assertEqual(record["cleanup_attempts"], 1)
            self.assertEqual(record["driver_sigterm_delivery_count"], 0)
            self.assertEqual(record["child_exit_code"], 1)
            self.assertEqual(record["stdout"]["path"], str(stdout_path))
            self.assertEqual(record["stderr"]["path"], str(stderr_path))
            self.assertIn("fixture producer interrupted", stderr_path.read_text())
            self.assert_fixture_stopped(root, state)

    def test_outer_signal_cleanup_is_idempotent_and_receipted(self):
        with tempfile.TemporaryDirectory(prefix="csdk-outer-signal-") as temp:
            root = Path(temp)
            fixture, state, env = write_fixture(root)
            stdout_path, stderr_path = root / "producer.stdout.log", root / "producer.stderr.log"
            timeout_record = root / "producer-signal.json"
            sent, thread, errors = signal_driver_twice_around_cleanup(root)
            with process_rows_fixture_context(root):
                with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
                    with self.assertRaisesRegex(TimeoutError, "outer signal fixture failed"):
                        driver.run_child_with_deadline(
                            command_for(fixture, state), cwd=root, env=env,
                            stdout=stdout, stderr=stderr, timeout=10.0,
                            label="UNIT_FIXTURE outer signal fixture",
                            timeout_record=timeout_record, ci_cargo_module=ci_cargo)
            thread.join(timeout=1)
            self.assertTrue(sent.is_set(), errors)
            self.assertFalse(errors)
            record = json.loads(timeout_record.read_text())
            self.assertEqual(record["termination_reason"], "outer_supervisor_sigterm")
            self.assertEqual(record["driver_sigterm_delivery_count"], 2)
            self.assertEqual(record["cleanup_attempts"], 1)
            self.assertFalse(record["candidate_accepted"])
            self.assertTrue(record["cleanup_complete"], record)
            self.assertEqual(record["cleanup_status"], "complete")
            self.assertEqual(record["descendant_process_group_cleanup"]["status"], "complete")
            self.assertEqual(record["direct_child_reap"]["status"], "complete")
            self.assert_fixture_stopped(root, state, expected_signals=1)

    def test_producer_deadline_sigkill_fallback_stops_observed_groups(self):
        with tempfile.TemporaryDirectory(prefix="csdk-producer-fallback-") as temp:
            root = Path(temp)
            _fixture, state, env = write_fixture(root)
            stdout_path, stderr_path = root / "producer.stdout.log", root / "producer.stderr.log"
            timeout_record = root / "producer-timeout.json"
            command = fallback_command(root)
            with process_rows_fixture_context(root):
                with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
                    with self.assertRaisesRegex(TimeoutError, "SIGKILL fallback failed: producer deadline"):
                        driver.run_child_with_deadline(
                            command, cwd=root, env=env, stdout=stdout, stderr=stderr,
                            timeout=1.5, label="UNIT_FIXTURE producer SIGKILL fallback",
                            timeout_record=timeout_record, ci_cargo_module=ci_cargo,
                            shutdown_grace_seconds=0.25)
            record = json.loads(timeout_record.read_text())
            self.assertEqual(record["status"], "FAILED")
            self.assertFalse(record["candidate_accepted"])
            self.assertTrue(record["direct_child_sigkill_fallback"])
            self.assertEqual(record["cleanup_attempts"], 1)
            cleanup = record["descendant_process_group_cleanup"]
            self.assertTrue(cleanup["complete"], cleanup)
            pids = json.loads((root / "fallback-pids.json").read_text())
            tracked = record["descendant_process_group_cleanup"]["group_ids"]
            self.assertIn(pids["clang"]["pgid"], tracked)
            self.assertIn(pids["descendant"]["pgid"], tracked)
            self.assertIn(pids["stubborn"]["pgid"], tracked)
            self.assertIn(pids["stubborn"]["pgid"], cleanup["sigkill_group_ids"])
            for key in ("worker", "clang", "descendant", "stubborn"):
                assert_dead(self, pids[key]["pid"])
            self.assertEqual(record["stdout"]["path"], str(stdout_path))
            self.assertEqual(record["stderr"]["path"], str(stderr_path))
            self.assertFalse((root / "csdk-output" / "csdk-producer.json").exists())

    def test_outer_supervisor_deadline_signals_and_reaps_clang_group(self):
        with tempfile.TemporaryDirectory(prefix="csdk-outer-timeout-") as temp:
            root = Path(temp)
            fixture, state, env = write_fixture(root)
            work, output = root / "supervisor-work", root / "supervisor-output"
            logs = work / "observer-logs"
            for path in (work, output, logs): path.mkdir(parents=True, exist_ok=True)
            supervisor = ci_cargo.Supervisor(work, output, env, logs)
            sent, thread, errors = duplicate_sigterm_after_cleanup_starts(root)
            with process_rows_fixture_context(root):
                with self.assertRaisesRegex(RuntimeError, "outer-deadline-fixture failed: timeout"):
                    supervisor.run(command_for(fixture, state), cwd=root,
                                   label="outer-deadline-fixture", timeout=1.0,
                                   cleanup_descendant_groups=True)
            thread.join(timeout=1)
            self.assertTrue(sent.is_set(), errors)
            self.assertFalse(errors)
            self.assertEqual(len(supervisor.commands), 1)
            self.assertEqual(supervisor.commands[0]["stop_reason"], "timeout")
            self.assertEqual(supervisor.commands[0]["exit_code"], 1)
            self.assertTrue(supervisor.commands[0]["descendant_process_group_cleanup"]["complete"])
            self.assertEqual(supervisor.commands[0]["cleanup_status"], "complete")
            self.assertEqual(supervisor.commands[0]["direct_child_reap"]["status"], "complete")
            self.assertTrue((logs / "outer-deadline-fixture.stderr.log").is_file())
            self.assertIn("fixture producer interrupted",
                          (logs / "outer-deadline-fixture.stderr.log").read_text())
            self.assert_fixture_stopped(root, state)

    def test_outer_supervisor_deadline_sigkill_fallback_stops_observed_groups(self):
        with tempfile.TemporaryDirectory(prefix="csdk-outer-fallback-") as temp:
            root = Path(temp)
            _fixture, state, env = write_fixture(root)
            work, output = root / "supervisor-work", root / "supervisor-output"
            logs = work / "observer-logs"
            for path in (work, output, logs): path.mkdir(parents=True, exist_ok=True)
            supervisor = ci_cargo.Supervisor(work, output, env, logs)
            with process_rows_fixture_context(root):
                with self.assertRaisesRegex(RuntimeError, "outer-fallback-fixture failed: timeout"):
                    supervisor.run(fallback_command(root), cwd=root,
                                   label="outer-fallback-fixture", timeout=1.5,
                                   cleanup_descendant_groups=True)
            self.assertEqual(len(supervisor.commands), 1)
            row = supervisor.commands[0]
            self.assertEqual(row["stop_reason"], "timeout")
            self.assertTrue(row["descendant_process_group_cleanup"]["complete"], row)
            self.assertEqual(row["cleanup_status"], "complete")
            self.assertEqual(row["direct_child_reap"]["status"], "complete")
            cleanup = row["descendant_process_group_cleanup"]
            pids = json.loads((root / "fallback-pids.json").read_text())
            self.assertIn(pids["clang"]["pgid"], row["tracked_descendant_process_group_ids"])
            self.assertIn(pids["descendant"]["pgid"], row["tracked_descendant_process_group_ids"])
            self.assertIn(pids["stubborn"]["pgid"], row["tracked_descendant_process_group_ids"])
            self.assertIn(pids["stubborn"]["pgid"], cleanup["sigkill_group_ids"])
            for key in ("worker", "clang", "descendant", "stubborn"):
                assert_dead(self, pids[key]["pid"])
            self.assertTrue((logs / "outer-fallback-fixture.stdout.log").is_file())
            self.assertTrue((logs / "outer-fallback-fixture.stderr.log").is_file())
            self.assertFalse((output / "csdk-producer.json").exists())


class BoundedCleanupTests(unittest.TestCase):
    def test_nested_deadline_policy_preserves_window_and_cleanup_margins(self):
        driver.validate_nested_deadline_policy(
            ci_cargo.PROCESS_ROWS_TIMEOUT_SECONDS, ci_cargo.SUPERVISOR_STOP_GRACE_SECONDS)
        self.assertEqual(driver.PRODUCER_WINDOW_SECONDS, 4400)
        self.assertEqual(driver.INNER_PRODUCER_WORK_SECONDS, 4250)
        self.assertEqual(driver.INNER_PRODUCER_CLEANUP_RESERVE_SECONDS, 150)
        self.assertEqual(driver.OUTER_PRODUCER_DEADLINE_SECONDS, 4340)
        self.assertEqual(driver.OUTER_CLEANUP_RESERVE_SECONDS, 60)
        self.assertEqual(driver.OUTER_PRODUCER_DEADLINE_SECONDS
                         - driver.INNER_PRODUCER_WORK_SECONDS, 90)
        with self.assertRaisesRegex(ValueError, "observer timeout"):
            driver.validate_nested_deadline_policy(
                ci_cargo.PROCESS_ROWS_TIMEOUT_SECONDS + 1,
                ci_cargo.SUPERVISOR_STOP_GRACE_SECONDS)

    def test_direct_child_reap_has_finite_waits_and_typed_incomplete_receipt(self):
        class NeverReapedChild:
            pid = 987654321
            returncode = None

            def __init__(self):
                self.wait_timeouts = []
                self.killed = False

            def wait(self, timeout=None):
                self.wait_timeouts.append(timeout)
                if timeout is None:
                    raise AssertionError("unbounded wait was attempted")
                raise subprocess.TimeoutExpired(["fixture-child"], timeout)

            def kill(self):
                self.killed = True

        child = NeverReapedChild()
        receipt = ci_cargo.reap_child_bounded(
            child, wait_seconds=0.01, sigkill_wait_seconds=0.02)
        self.assertEqual(child.wait_timeouts, [0.01, 0.02])
        self.assertTrue(child.killed)
        self.assertEqual(receipt["wait_attempt_count"], 2)
        self.assertTrue(receipt["initial_wait_timed_out"])
        self.assertTrue(receipt["post_sigkill_wait_timed_out"])
        self.assertTrue(receipt["incomplete_cleanup"])
        self.assertEqual(receipt["status"], "incomplete_cleanup")

    def test_transient_descendant_census_error_survives_successful_recensus(self):
        with tempfile.TemporaryDirectory(prefix="csdk-census-error-") as temp:
            root = Path(temp)
            work, output = root / "work", root / "output"
            logs = work / "observer-logs"
            for path in (work, output, logs):
                path.mkdir(parents=True, exist_ok=True)
            original_reader = ci_cargo.process_rows
            calls = 0

            def fail_once_during_final_census():
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("fixture transient final-census failure")
                return original_reader()

            supervisor = ci_cargo.Supervisor(work, output, dict(os.environ), logs)
            with mock.patch.object(ci_cargo, "process_rows",
                                   side_effect=fail_once_during_final_census):
                with self.assertRaisesRegex(RuntimeError, "timeout"):
                    supervisor.run(
                        [sys.executable, "-B", "-c", "import time; time.sleep(4)"],
                        cwd=work, label="cleanup-census-fixture", timeout=0,
                        cleanup_descendant_groups=True)
            self.assertEqual(len(supervisor.commands), 1)
            row = supervisor.commands[0]
            cleanup = row["descendant_process_group_cleanup"]
            self.assertIn("OSError: fixture transient final-census failure",
                          cleanup["observer_errors"])
            self.assertFalse(cleanup["complete"])
            self.assertTrue(cleanup["incomplete_cleanup"])
            self.assertEqual(cleanup["status"], "incomplete_cleanup")
            self.assertEqual(row["cleanup_status"], "incomplete_cleanup")


COMPOSED_COMPILER_SOURCE = r'''import json, os, signal, subprocess, sys, time
from pathlib import Path
root, receipt, output = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
child_code = "import os,signal,sys,time; from pathlib import Path; signal.signal(signal.SIGTERM,signal.SIG_IGN); Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(3600)"
child_pid_path = root / "stubborn-descendant.pid"
child = subprocess.Popen([sys.executable, "-B", "-c", child_code, str(child_pid_path)],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, process_group=0)
output.parent.mkdir(parents=True, exist_ok=True)
output.write_bytes(b"fixture object")
receipt.write_text(json.dumps({"compiler_pid": os.getpid(),
                               "compiler_pgid": os.getpgid(0),
                               "descendant_pid": child.pid,
                               "descendant_pgid": os.getpgid(child.pid),
                               "session_id": os.getsid(0)}, sort_keys=True))
signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True: time.sleep(1)
'''

COMPOSED_PRODUCER_SOURCE = r'''import importlib.util, json, os, sys
from pathlib import Path
producer_path, root = Path(sys.argv[1]), Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("composed_fixture_csdk_producer", producer_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
module.nouveau.EXPECTED_OBJECTS = 1
module.nouveau.ci_cargo.SUPERVISOR_STOP_GRACE_SECONDS = 0.25
(root / "producer-process.json").write_text(json.dumps({
    "pid": os.getpid(), "pgid": os.getpgrp(), "session_id": os.getsid(0)}, sort_keys=True))
source_root, build_root, toolchain_root = root / "source", root / "build", root / "toolchain"
for path in (source_root, build_root, toolchain_root): path.mkdir(parents=True, exist_ok=True)
source = source_root / "fixture.c"
source.write_text("int fixture(void) { return 0; }\n")
compiler = root / "stubborn-compiler.py"
compiler.write_text(COMPILER_SOURCE)
compiler.chmod(0o700)
object_path = build_root / "fixture.o"
plan_path = root / "nouveau-plan.json"
work_dir = root / "producer-work"
work_dir.mkdir()
plan = {"commands": [{"argv": [sys.executable, "-B", str(compiler), str(root),
                                  str(root / "process-tree.json"), str(object_path)],
                      "source": str(source), "object": str(object_path), "include_paths": []}],
        "ordered_object_paths": [str(object_path)], "working_directory": str(build_root),
        "compiler": str(compiler), "source_root": str(source_root),
        "build_root": str(build_root), "toolchain_root": str(toolchain_root)}
module.nouveau._prepare_outputs(plan)
module.nouveau._write_plan_fresh(plan_path, plan)
try:
    module.compile_nouveau(plan, work_dir, plan_path, jobs=1)
except RuntimeError as error:
    (root / "inner-result.json").write_text(json.dumps({"status": "FAILED",
        "candidate_accepted": False, "failure": str(error)}, sort_keys=True))
    raise SystemExit(1)
raise SystemExit("fixture compiler unexpectedly completed")
'''

COMPOSED_WRAPPER_SOURCE = r'''import importlib.util, os, subprocess, sys
from pathlib import Path
driver_path, ci_path, producer_path, fixture_path, root = map(Path, sys.argv[1:6])
inner_timeout = float(sys.argv[6])
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
driver = load("composed_fixture_driver", driver_path)
ci = load("composed_fixture_ci_cargo", ci_path)
ci.SUPERVISOR_STOP_GRACE_SECONDS = 0.25
(root / "wrapper-process.json").write_text(__import__("json").dumps({
    "pid": os.getpid(), "pgid": os.getpgrp(), "session_id": os.getsid(0)}, sort_keys=True))
command = [sys.executable, "-B", str(fixture_path), str(producer_path), str(root)]
with (root / "nested-producer.stdout.log").open("xb") as stdout, \
     (root / "nested-producer.stderr.log").open("xb") as stderr:
    try:
        rc = driver.run_child_with_deadline(
            command, cwd=root, env=os.environ.copy(), stdout=stdout, stderr=stderr,
            timeout=inner_timeout, label="UNIT_FIXTURE composed producer deadline",
            timeout_record=root / "inner-timeout.json", ci_cargo_module=ci,
            shutdown_grace_seconds=0.25)
    except TimeoutError:
        raise SystemExit(1)
raise SystemExit(rc)
'''

class ComposedProcessTreeTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform.startswith("linux"),
                         "Linux CI must exercise the real unmocked ps process observer")
    def run_composed_case(self, *, inner_timeout: float, outer_timeout: float,
                          expected_reason: str) -> None:
        with tempfile.TemporaryDirectory(prefix="csdk-composed-deadline-") as temp:
            root = Path(temp)
            work, output = root / "work", root / "output"
            logs = work / "observer-logs"
            for path in (work, output, logs):
                path.mkdir(parents=True, exist_ok=True)
            producer_fixture = work / "producer-fixture.py"
            producer_fixture.write_text(
                COMPOSED_PRODUCER_SOURCE.replace("COMPILER_SOURCE", repr(COMPOSED_COMPILER_SOURCE)))
            wrapper_fixture = work / "wrapper-fixture.py"
            wrapper_fixture.write_text(COMPOSED_WRAPPER_SOURCE)
            env = dict(os.environ)
            env.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1"})
            command = [sys.executable, "-B", str(wrapper_fixture), str(DRIVER_PATH),
                       str(RELEASE / "ci_cargo.py"), str(RELEASE / "csdk_producer.py"),
                       str(producer_fixture), str(work), str(inner_timeout)]
            supervisor = ci_cargo.Supervisor(work, output, env, logs)
            with mock.patch.object(ci_cargo, "SUPERVISOR_STOP_GRACE_SECONDS", 0.25):
                with self.assertRaises(RuntimeError):
                    supervisor.run(command, cwd=work, label="composed-deadline-fixture",
                                   timeout=outer_timeout, cleanup_descendant_groups=True)
            self.assertEqual(len(supervisor.commands), 1)
            row = supervisor.commands[0]
            self.assertEqual(row["cleanup_status"], "complete", row)
            self.assertTrue(row["descendant_process_group_cleanup"]["complete"], row)
            if expected_reason == "outer_supervisor_sigterm":
                self.assertEqual(row["stop_reason"], "timeout")
            else:
                self.assertIsNone(row["stop_reason"])
            timeout_path = work / "inner-timeout.json"
            self.assertTrue(timeout_path.is_file(), "wrapper must retain its nested cleanup receipt")
            receipt = json.loads(timeout_path.read_text())
            self.assertEqual(receipt["termination_reason"], expected_reason)
            self.assertTrue(receipt["cleanup_complete"], receipt)
            self.assertFalse(receipt["candidate_accepted"])
            topology = json.loads((work / "process-tree.json").read_text())
            wrapper = json.loads((work / "wrapper-process.json").read_text())
            producer = json.loads((work / "producer-process.json").read_text())
            stubborn_pid = int((work / "stubborn-descendant.pid").read_text())
            self.assertEqual(producer["pgid"], wrapper["pgid"])
            self.assertEqual(producer["session_id"], wrapper["session_id"])
            self.assertEqual(topology["session_id"], wrapper["session_id"])
            self.assertNotEqual(topology["compiler_pgid"], topology["descendant_pgid"])
            self.assertIn(topology["compiler_pgid"], row["tracked_descendant_process_group_ids"])
            self.assertIn(topology["descendant_pgid"], row["tracked_descendant_process_group_ids"])
            if expected_reason == "producer_deadline":
                cleanup = receipt["descendant_process_group_cleanup"]
                self.assertIn(topology["descendant_pgid"], cleanup["sigkill_group_ids"])
            for pid in (topology["compiler_pid"], topology["descendant_pid"], stubborn_pid):
                assert_dead(self, pid)
            self.assertFalse((work / "csdk-output" / "csdk-producer.json").exists())

    def test_real_linux_outer_wrapper_producer_compiler_deadlines(self):
        # First exercise the wrapper's work cutoff; then let the outer backup
        # cutoff interrupt the same production session/process-group topology.
        self.run_composed_case(inner_timeout=3.0, outer_timeout=8.0,
                               expected_reason="producer_deadline")
        self.run_composed_case(inner_timeout=8.0, outer_timeout=4.0,
                               expected_reason="outer_supervisor_sigterm")


if __name__ == "__main__":
    unittest.main()
