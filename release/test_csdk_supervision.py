"""Focused UNIT_FIXTURE tests for C-SDK timeout cleanup across process groups."""
from __future__ import annotations

import importlib.util
import hashlib
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
# Six-second cold-start control plus five-second descendant startup, with
# bounded import/exec headroom. This is fixture setup, not a producer deadline.
FIXTURE_STARTUP_TIMEOUT_SECONDS = 20.0


COMPILER_SOURCE = """#!PYTHON
import json, os, signal, subprocess, sys, time
from pathlib import Path
time.sleep(float(os.environ.get("CSDK_FIXTURE_STARTUP_DELAY", "0")))
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
pid_file_tmp = pid_file.with_name(pid_file.name + ".tmp")
pid_file_tmp.write_text(json.dumps({"clang_pid": os.getpid(), "clang_pgid": os.getpgid(0),
                                    "descendant_pid": child.pid, "descendant_pgid": os.getpgid(child.pid)}))
os.replace(pid_file_tmp, pid_file)
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
worker_pid_tmp = worker_pid_file.with_name(worker_pid_file.name + ".tmp")
worker_pid_tmp.write_text(json.dumps({"pid": os.getpid(), "ppid": os.getppid(),
                                      "pgid": os.getpgrp()}))
os.replace(worker_pid_tmp, worker_pid_file)
def alive(pid, expected_group):
    # Darwin kill(pid, 0) also succeeds for an unreaped zombie, whose old
    # process group can already reject killpg with EPERM.
    try: actual_group = os.getpgid(pid)
    except ProcessLookupError: return False
    if actual_group != expected_group:
        raise RuntimeError("fixture process group identity changed")
    return True
def fixture_rows():
    worker = json.loads(worker_pid_file.read_text())
    worker_pid = worker["pid"]
    rows = []
    if alive(worker_pid, worker["pgid"]): rows.append((worker_pid, os.getppid(), worker["pgid"], 2048))
    pid_file = Path(os.environ["CSDK_FIXTURE_PIDS"])
    if pid_file.is_file():
        values = json.loads(pid_file.read_text())
        if alive(values["clang_pid"], values["clang_pgid"]):
            rows.append((values["clang_pid"], worker_pid, values["clang_pgid"], 2048))
        if alive(values["descendant_pid"], values["descendant_pgid"]):
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


def write_fixture(root: Path, *, startup_delay: float = 0) -> tuple[Path, Path, dict[str, str]]:
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
        "CSDK_FIXTURE_STARTUP_DELAY": str(startup_delay),
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
worker_path = root / "worker-pid.json"
worker_tmp = worker_path.with_name(worker_path.name + ".tmp")
worker_tmp.write_text(json.dumps(worker))
os.replace(worker_tmp, worker_path)
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
fallback_path = root / "fallback-pids.json"
fallback_tmp = fallback_path.with_name(fallback_path.name + ".tmp")
fallback_tmp.write_text(json.dumps(rows, sort_keys=True))
os.replace(fallback_tmp, fallback_path)
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
            actual_group = os.getpgid(row["pid"])
        except ProcessLookupError:
            continue
        if actual_group != row["pgid"]:
            raise RuntimeError("fixture process group identity changed")
        rows.append((row["pid"], row["ppid"], actual_group, 2048))
    return rows


def duplicate_sigterm_after_cleanup_starts(root: Path):
    sent = threading.Event()
    errors = []

    def signal_twice():
        marker = root / "state" / "compiler-cleanup-ready"
        deadline = time.monotonic() + FIXTURE_STARTUP_TIMEOUT_SECONDS + 5
        while time.monotonic() < deadline and not marker.is_file():
            time.sleep(0.01)
        try:
            if not marker.is_file():
                raise TimeoutError("fixture compiler cleanup did not start")
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
        provisional_receipt = root / "producer-signal.json"
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not clang_pids.is_file():
            time.sleep(0.01)
        try:
            os.kill(driver_pid, signal.SIGTERM)
            while time.monotonic() < deadline and not provisional_receipt.is_file():
                time.sleep(0.01)
            if provisional_receipt.is_file():
                provisional = json.loads(provisional_receipt.read_text())
                if (provisional.get("receipt_phase") != "cleanup_in_progress"
                        or provisional.get("status") != "FAILED"
                        or provisional.get("candidate_accepted") is not False
                        or provisional.get("cleanup_complete") is not False):
                    raise AssertionError("provisional receipt was not visibly incomplete")
            os.kill(driver_pid, signal.SIGTERM)
            sent.set()
        except BaseException as error:
            errors.append(type(error).__name__ + ": " + str(error))

    thread = threading.Thread(target=signal_twice, daemon=True)
    thread.start()
    return sent, thread, errors


def wait_fixture_ready(path: Path, *, timeout: float = FIXTURE_STARTUP_TIMEOUT_SECONDS):
    deadline = time.monotonic() + timeout
    while not path.is_file():
        if time.monotonic() >= deadline:
            root = path.parent.parent if path.parent.name == "state" else path.parent
            names = ("worker-pid.json", "state/descendant-ready", "state/clang-pids.json",
                     "fallback-pids.json", "inner-result.json", "nouveau-plan.json",
                     "compile-work/nouveau-logs/0000.stderr.log")
            diagnostics = {"awaited": str(path.relative_to(root)),
                           "startup_timeout_seconds": timeout,
                           "present": {name: (root / name).is_file() for name in names}}
            remaining_bytes = 1024
            for name in names:
                try:
                    with (root / name).open("rb") as stream:
                        captured = stream.read(remaining_bytes)
                except OSError:
                    continue
                remaining_bytes -= len(captured)
                diagnostics[name] = captured.decode("utf-8", errors="replace")
                if not remaining_bytes:
                    break
            print("fixture startup diagnostics: "
                  + json.dumps(diagnostics, sort_keys=True)[:2048],
                  file=sys.stderr, flush=True)
            raise TimeoutError("fixture process tree did not become ready")
        time.sleep(0.01)


def process_rows_fixture_context(root: Path, *, fallback: bool = False):
    original_reader = ci_cargo.process_rows
    first_census = True
    startup_failed = False

    def rows(**kwargs):
        nonlocal first_census, startup_failed
        if first_census:
            first_census = False
            # These tests exercise shutdown of a complete process tree. The
            # first census has a separate bounded fixture-startup handshake,
            # so the short timeout cannot fire before signal handlers exist.
            ready = root / ("fallback-pids.json" if fallback else "state/clang-pids.json")
            try:
                wait_fixture_ready(ready)
            except TimeoutError:
                startup_failed = True
                raise
        # Missing journals cannot prove a partial tree is complete. Preserve
        # the initial monitor failure and use the native census for cleanup.
        if startup_failed:
            return original_reader(**kwargs)
        if sys.platform == "darwin":
            return fixture_process_rows(root)
        return original_reader(**kwargs)

    return mock.patch.object(ci_cargo, "process_rows", side_effect=rows)


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
            thread.join(timeout=FIXTURE_STARTUP_TIMEOUT_SECONDS + 6)
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
            self.assertEqual(record["sigterm_grace_seconds"],
                             driver.OUTER_SIGNAL_PRODUCER_SETTLE_SECONDS)
            self.assertEqual(record["configured_sigterm_grace_seconds"],
                             driver.PRODUCER_SHUTDOWN_GRACE_SECONDS)
            self.assertEqual(record["outer_signal_cleanup_deadline_seconds"],
                             driver.OUTER_SIGNAL_RECEIPT_DEADLINE_SECONDS)
            self.assertEqual(record["outer_signal_operation_deadline_seconds"]
                             + record["outer_signal_finalization_reserve_seconds"],
                             driver.OUTER_SIGNAL_RECEIPT_DEADLINE_SECONDS)
            self.assertEqual(record["minimum_outer_escalation_margin_seconds"], 3.0)
            self.assertEqual(record["receipt_phase"], "final")
            self.assertEqual(record["driver_sigterm_delivery_count"], 2)
            self.assertEqual(record["cleanup_attempts"], 1)
            self.assertFalse(record["candidate_accepted"])
            self.assertTrue(record["cleanup_complete"], record)
            self.assertEqual(record["cleanup_status"], "complete")
            self.assertEqual(record["descendant_process_group_cleanup"]["status"], "complete")
            self.assertEqual(record["direct_child_reap"]["status"], "complete")
            self.assert_fixture_stopped(root, state, expected_signals=1)

    def test_outer_signal_slow_observer_times_out_with_fail_closed_receipt(self):
        with tempfile.TemporaryDirectory(prefix="csdk-outer-slow-observer-") as temp:
            root = Path(temp)
            ready = root / "child-ready"
            stdout_path, stderr_path = root / "producer.stdout.log", root / "producer.stderr.log"
            timeout_record = root / "producer-signal.json"
            observer_mode = threading.Event()
            sent = threading.Event()
            errors = []
            calls = []
            original_reader = ci_cargo.process_rows

            def child_command():
                source = root / "slow-observer-child.py"
                source.write_text(
                    "import pathlib,time; pathlib.Path(" + repr(str(ready))
                    + ").write_text('ready'); time.sleep(30)\n")
                return [sys.executable, "-B", str(source)]

            def signal_driver():
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and not ready.is_file():
                    time.sleep(0.01)
                try:
                    os.kill(os.getpid(), signal.SIGTERM)
                    observer_mode.set()
                    sent.set()
                except BaseException as error:
                    errors.append(type(error).__name__ + ": " + str(error))

            def slow_rows(*, timeout=ci_cargo.PROCESS_ROWS_TIMEOUT_SECONDS):
                calls.append(timeout)
                if observer_mode.is_set():
                    # Model a timed-out ps call at its requested bound, with a
                    # small deterministic process-launch overrun.
                    time.sleep(timeout + 0.02)
                    raise subprocess.TimeoutExpired(["/bin/ps"], timeout)
                return original_reader(timeout=timeout)

            thread = threading.Thread(target=signal_driver, daemon=True)
            thread.start()
            started = time.monotonic()
            with mock.patch.object(ci_cargo, "process_rows", side_effect=slow_rows):
                with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
                    with self.assertRaisesRegex(TimeoutError, "outer signal slow observer failed"):
                        driver.run_child_with_deadline(
                            child_command(), cwd=root, env=dict(os.environ),
                            stdout=stdout, stderr=stderr, timeout=10.0,
                            label="UNIT_FIXTURE outer signal slow observer",
                            timeout_record=timeout_record, ci_cargo_module=ci_cargo)
            elapsed = time.monotonic() - started
            thread.join(timeout=1)
            self.assertTrue(sent.is_set(), errors)
            self.assertFalse(errors)
            self.assertTrue(timeout_record.is_file())
            record = json.loads(timeout_record.read_text())
            self.assertEqual(record["receipt_phase"], "final")
            self.assertLessEqual(elapsed, driver.OUTER_SIGNAL_RECEIPT_DEADLINE_SECONDS + 0.5)
            self.assertGreaterEqual(record["descendant_process_group_cleanup"]["process_table_calls"], 1)
            self.assertLessEqual(record["descendant_process_group_cleanup"]["process_table_calls"], 2)
            self.assertFalse(record["cleanup_complete"], record)
            self.assertEqual(record["cleanup_status"], "incomplete_cleanup")
            self.assertTrue(record["descendant_process_group_cleanup"]["observer_errors"])
            self.assertTrue(record["direct_child_reap"]["status"] == "complete")
            self.assertTrue(all(0 < timeout <= driver.OUTER_SIGNAL_OBSERVER_TIMEOUT_SECONDS
                                for timeout in calls if timeout < 2))

    def test_producer_deadline_sigkill_fallback_stops_observed_groups(self):
        with tempfile.TemporaryDirectory(prefix="csdk-producer-fallback-") as temp:
            root = Path(temp)
            _fixture, state, env = write_fixture(root)
            stdout_path, stderr_path = root / "producer.stdout.log", root / "producer.stderr.log"
            timeout_record = root / "producer-timeout.json"
            command = fallback_command(root)
            with process_rows_fixture_context(root, fallback=True):
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
        self.check_outer_supervisor_deadline()

    def test_outer_supervisor_deadline_with_slow_fixture_startup(self):
        self.check_outer_supervisor_deadline(startup_delay=6.0)

    def check_outer_supervisor_deadline(self, *, startup_delay: float = 0):
        with tempfile.TemporaryDirectory(prefix="csdk-outer-timeout-") as temp:
            root = Path(temp)
            fixture, state, env = write_fixture(root, startup_delay=startup_delay)
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
            thread.join(timeout=FIXTURE_STARTUP_TIMEOUT_SECONDS + 6)
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
            with process_rows_fixture_context(root, fallback=True):
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


class FixtureObserverTests(unittest.TestCase):
    def test_missing_readiness_still_discovers_and_stops_separate_group(self):
        with tempfile.TemporaryDirectory(prefix="csdk-fixture-partial-tree-") as temp:
            root = Path(temp)
            ready = root / "unrecorded-child-pid"
            child_source = (
                "import os,signal,time; from pathlib import Path; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"Path({str(ready)!r}).write_text(str(os.getpid())); "
                "time.sleep(30)")
            parent_source = (
                "import subprocess,sys,time; "
                f"subprocess.Popen([sys.executable,'-c',{child_source!r}], process_group=0); "
                "time.sleep(30)")
            logs = root / "logs"
            logs.mkdir()
            supervisor = ci_cargo.Supervisor(root, root / "output", dict(os.environ), logs)
            original_wait = wait_fixture_ready

            def withhold_journal(_path):
                original_wait(ready)
                raise TimeoutError("synthetic missing fixture journal")

            try:
                with mock.patch.dict(globals(), {"wait_fixture_ready": withhold_journal}):
                    with process_rows_fixture_context(root):
                        with self.assertRaisesRegex(RuntimeError, "monitor failure"):
                            supervisor.run([sys.executable, "-c", parent_source], cwd=root,
                                           label="partial-tree", timeout=10,
                                           cleanup_descendant_groups=True)
                child_pid = int(ready.read_text())
                row = supervisor.commands[0]
                self.assertIn(child_pid, row["tracked_descendant_process_group_ids"])
                self.assertIn(child_pid, row["descendant_process_group_cleanup"]["sigkill_group_ids"])
                assert_dead(self, child_pid)
                self.assertFalse((root / "output/csdk-producer.json").exists())
            finally:
                # A regression must not leave its deliberately stubborn child
                # running even when the discovery assertion fails.
                if ready.is_file():
                    pid = int(ready.read_text())
                    try:
                        if os.getpgid(pid) != pid:
                            raise RuntimeError("fixture child group identity changed")
                        os.killpg(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_group_census_uses_current_membership_and_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="csdk-fixture-census-") as temp:
            root = Path(temp)
            (root / "worker-pid.json").write_text(json.dumps(
                {"pid": 12345, "ppid": 12344, "pgid": 12345}))
            with mock.patch.object(os, "getpgid", return_value=12345):
                self.assertEqual(fixture_process_rows(root), [(12345, 12344, 12345, 2048)])
            # A zombie may still pass kill(pid, 0), but is no longer a member
            # of a signalable process group on Darwin.
            with mock.patch.object(os, "kill", return_value=None), \
                    mock.patch.object(os, "getpgid", side_effect=ProcessLookupError):
                self.assertEqual(fixture_process_rows(root), [])
            with mock.patch.object(os, "getpgid", side_effect=PermissionError):
                with self.assertRaises(PermissionError):
                    fixture_process_rows(root)
            with mock.patch.object(os, "getpgid", return_value=54321):
                with self.assertRaisesRegex(RuntimeError, "identity changed"):
                    fixture_process_rows(root)

    def test_missing_fixture_readiness_is_a_bounded_failure(self):
        with tempfile.TemporaryDirectory(prefix="csdk-fixture-not-ready-") as temp:
            with self.assertRaisesRegex(TimeoutError, "did not become ready"):
                wait_fixture_ready(Path(temp) / "missing", timeout=0.01)


class BoundedCleanupTests(unittest.TestCase):
    def test_nested_deadline_policy_preserves_window_and_cleanup_margins(self):
        driver.validate_nested_deadline_policy(
            ci_cargo.PROCESS_ROWS_TIMEOUT_SECONDS, ci_cargo.SUPERVISOR_STOP_GRACE_SECONDS)
        self.assertEqual(driver.PRODUCER_WINDOW_SECONDS, 4400)
        self.assertEqual(driver.INNER_PRODUCER_WORK_SECONDS, 4250)
        self.assertEqual(driver.INNER_PRODUCER_CLEANUP_RESERVE_SECONDS, 150)
        self.assertEqual(driver.OUTER_PRODUCER_DEADLINE_SECONDS, 4340)
        self.assertEqual(driver.OUTER_CLEANUP_RESERVE_SECONDS, 60)
        self.assertEqual(driver.OUTER_SIGNAL_OPERATION_DEADLINE_SECONDS
                         + driver.OUTER_SIGNAL_FINALIZATION_RESERVE_SECONDS,
                         driver.OUTER_SIGNAL_RECEIPT_DEADLINE_SECONDS)
        self.assertEqual(driver.OUTER_SIGNAL_RECEIPT_DEADLINE_SECONDS
                         + ci_cargo.PROCESS_ROWS_TIMEOUT_SECONDS + 3,
                         ci_cargo.SUPERVISOR_STOP_GRACE_SECONDS)
        self.assertLess(driver.OUTER_CLEANUP_MINIMUM_SECONDS,
                        driver.OUTER_CLEANUP_RESERVE_SECONDS)
        self.assertEqual(driver.OUTER_PRODUCER_DEADLINE_SECONDS
                         - driver.INNER_PRODUCER_WORK_SECONDS, 90)
        with self.assertRaisesRegex(ValueError, "observer timeout"):
            driver.validate_nested_deadline_policy(
                ci_cargo.PROCESS_ROWS_TIMEOUT_SECONDS + 1,
                ci_cargo.SUPERVISOR_STOP_GRACE_SECONDS)

    def test_outer_signal_walks_all_live_groups_and_stops_at_absolute_deadline(self):
        class FakeClock:
            def __init__(self):
                self.now = 100.0
                self.reads_until_deadline = None

            def monotonic(self):
                if self.reads_until_deadline is not None:
                    if self.reads_until_deadline == 0:
                        self.now = 100.0 + driver.OUTER_SIGNAL_OPERATION_DEADLINE_SECONDS
                    else:
                        self.reads_until_deadline -= 1
                return self.now

        class FakeProcess:
            pid = 12345

            def __init__(self):
                self._returncode = 0

            @property
            def returncode(self):
                return self._returncode

            @returncode.setter
            def returncode(self, value):
                self._returncode = value

            def poll(self):
                return self.returncode

        class FakeObserver:
            def __init__(self, process, groups, orphan_group, helper_group, foreign_group, *,
                         include_foreign=False, fail_initial=False,
                         fail_descendant_initial=False, fail_session_group=None):
                self.process = process
                self.groups = list(groups)
                self.orphan_group = orphan_group
                self.helper_group = helper_group
                self.foreign_group = foreign_group
                self.include_foreign = include_foreign
                self.alive = set(groups) | {orphan_group, helper_group}
                self.fail_initial = fail_initial
                self.fail_descendant_initial = fail_descendant_initial
                self.fail_session_group = fail_session_group
                self.pid_groups = {group + 1000: group for group in groups}
                self.pid_groups[orphan_group + 2000] = orphan_group
                self.pid_groups[helper_group + 3000] = helper_group
                self.pid_groups[foreign_group + 60000] = foreign_group
                self.sessions = {pid: 12345 for pid, group in self.pid_groups.items()
                                 if group not in {helper_group, foreign_group}}
                self.sessions[helper_group + 3000] = 7777
                self.sessions[foreign_group + 60000] = 9999
                self.calls = 0
                self.descendant_calls = 0

            def process_rows(self, *, timeout):
                self.calls += 1
                if self.fail_initial and self.calls == 1:
                    raise subprocess.TimeoutExpired(["fixture-ps"], timeout)
                rows = [(self.process.pid, 1, 99, 1)] + [
                    (group + 1000, self.process.pid, group, 1)
                    for group in self.groups if group in self.alive]
                if self.orphan_group in self.alive:
                    rows.append((self.orphan_group + 2000, 76500, self.orphan_group, 1))
                if self.helper_group in self.alive:
                    rows.append((self.helper_group + 3000, self.process.pid,
                                 self.helper_group, 1))
                if self.include_foreign:
                    rows.append((self.foreign_group + 60000, 76500,
                                 self.foreign_group, 1))
                return rows

            def descendant_process_groups(self, root_pid, rows):
                self.descendant_calls += 1
                if self.fail_descendant_initial and self.descendant_calls == 1:
                    raise RuntimeError("fixture descendant census failed")
                return sorted({row[2] for row in rows
                               if row[0] != root_pid and row[1] == root_pid})

            def get_session_id(self, pid):
                if pid == 0:
                    return 12345
                if (self.fail_session_group is not None
                        and self.pid_groups.get(pid) == self.fail_session_group):
                    raise PermissionError("fixture session identity is unavailable")
                if pid not in self.sessions:
                    raise ProcessLookupError(pid)
                return self.sessions[pid]

            @staticmethod
            def reap_child_bounded(process, *, wait_seconds, sigkill_wait_seconds):
                return {"status": "complete", "incomplete_cleanup": False,
                        "sigkill_attempted": False, "wait_attempt_count": 0}

        groups = list(range(501, 508))
        orphan_group = 508
        fresh_other_session_helper_group = 509
        previously_seen_unrelated_group = 999
        owned_groups = groups + [orphan_group, fresh_other_session_helper_group]

        def exercise(*, expire_after=None, expire_phase="during_signal", fail_initial=False,
                     fail_descendant_initial=False, fail_session_group=None,
                     include_foreign=False):
            clock = FakeClock()
            process = FakeProcess()
            observer = FakeObserver(
                process, groups, orphan_group, fresh_other_session_helper_group,
                previously_seen_unrelated_group, include_foreign=include_foreign,
                fail_initial=fail_initial, fail_descendant_initial=fail_descendant_initial,
                fail_session_group=fail_session_group)
            sent = []

            def signal_group(group, signum):
                self.assertEqual(signum, signal.SIGKILL)
                sent.append(group)
                observer.alive.discard(group)
                if expire_after is not None and len(sent) == expire_after:
                    if expire_phase == "between_checks":
                        # The after-kill check sees time before cutoff; the
                        # next group's pre-kill check sees the expired cutoff.
                        clock.reads_until_deadline = 1
                    else:
                        clock.now = 100.0 + driver.OUTER_SIGNAL_OPERATION_DEADLINE_SECONDS

            with mock.patch.object(driver, "time", clock):
                result = driver._outer_signal_cleanup(
                    process, set(owned_groups) | ({previously_seen_unrelated_group}
                                                   if include_foreign else set()), observer,
                    received_at=100.0,
                    signal_group=signal_group, get_session_id=observer.get_session_id)
            return result, sent

        completed, sent = exercise()
        self.assertEqual(sent, owned_groups)
        self.assertEqual(completed["sigkill_group_ids"], owned_groups)
        self.assertNotIn(previously_seen_unrelated_group, completed["sigkill_group_ids"])
        self.assertEqual(completed["unsignaled_group_ids"], [])
        self.assertNotIn(previously_seen_unrelated_group, completed["remaining_group_ids"])
        self.assertTrue(completed["signal_census_complete"])
        self.assertFalse(completed["signal_deadline_exhausted"])
        self.assertTrue(completed["complete"], completed)

        expired, sent = exercise(expire_after=2, expire_phase="between_checks")
        self.assertEqual(sent, owned_groups[:2])
        self.assertEqual(expired["sigkill_group_ids"], owned_groups[:2])
        self.assertEqual(expired["unsignaled_group_ids"], owned_groups[2:])
        self.assertTrue(expired["signal_deadline_exhausted"])
        self.assertFalse(expired["complete"])
        self.assertEqual(expired["status"], "incomplete_cleanup")

        expired_during_signal, sent = exercise(expire_after=2)
        self.assertEqual(sent, owned_groups[:2])
        self.assertEqual(expired_during_signal["unsignaled_group_ids"], owned_groups[2:])
        self.assertTrue(expired_during_signal["signal_deadline_exhausted"])
        self.assertFalse(expired_during_signal["complete"])

        failed_census, sent = exercise(fail_initial=True)
        self.assertEqual(sent, [])
        self.assertFalse(failed_census["signal_census_complete"])
        self.assertEqual(failed_census["sigkill_group_ids"], [])
        self.assertFalse(failed_census["complete"])
        self.assertTrue(any("initial-census" in error
                            for error in failed_census["observer_errors"]))

        failed_descendant_census, sent = exercise(fail_descendant_initial=True)
        self.assertEqual(sent, [])
        self.assertFalse(failed_descendant_census["signal_census_complete"])
        self.assertEqual(failed_descendant_census["sigkill_group_ids"], [])
        self.assertFalse(failed_descendant_census["complete"])
        self.assertTrue(any("RuntimeError: fixture descendant census failed" in error
                            for error in failed_descendant_census["observer_errors"]))

        foreign_reuse, sent = exercise(include_foreign=True)
        self.assertNotIn(previously_seen_unrelated_group, sent)
        self.assertIn(previously_seen_unrelated_group,
                      foreign_reuse["foreign_session_group_ids"])
        self.assertIn(previously_seen_unrelated_group,
                      foreign_reuse["ambiguous_session_group_ids"])
        self.assertIn(previously_seen_unrelated_group, foreign_reuse["unsignaled_group_ids"])
        self.assertFalse(foreign_reuse["complete"])

        unresolved, sent = exercise(fail_session_group=orphan_group)
        self.assertNotIn(orphan_group, sent)
        self.assertIn(orphan_group, unresolved["unverified_session_group_ids"])
        self.assertIn(orphan_group, unresolved["unsignaled_group_ids"])
        self.assertFalse(unresolved["complete"])

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

    def test_expired_receipt_promotion_keeps_incomplete_provisional(self):
        with tempfile.TemporaryDirectory(prefix="csdk-expired-receipt-") as temp:
            receipt_path = Path(temp) / "timeout.json"
            provisional = {
                "status": "FAILED", "receipt_phase": "cleanup_in_progress",
                "cleanup_complete": False, "candidate_accepted": False,
            }
            driver.write_json_fresh_atomic(receipt_path, provisional)
            timely, promoted = driver.replace_json_before_deadline(
                receipt_path, {"status": "complete", "cleanup_complete": True},
                deadline=time.monotonic() - 1.0)
            self.assertFalse(timely)
            self.assertFalse(promoted)
            self.assertEqual(json.loads(receipt_path.read_text()), provisional)
            self.assertFalse(receipt_path.with_name("timeout.json.finalizing").exists())

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
(root / "wrapper-process.json").write_text(__import__("json").dumps({
    "pid": os.getpid(), "pgid": os.getpgrp(), "session_id": os.getsid(0)}, sort_keys=True))
command = [sys.executable, "-B", str(fixture_path), str(producer_path), str(root)]
with (root / "nested-producer.stdout.log").open("xb") as stdout, \
     (root / "nested-producer.stderr.log").open("xb") as stderr:
    try:
        rc = driver.run_child_with_deadline(
            command, cwd=root, env=os.environ.copy(), stdout=stdout, stderr=stderr,
            timeout=inner_timeout, label="UNIT_FIXTURE composed producer deadline",
            timeout_record=root / "inner-timeout.json", ci_cargo_module=ci)
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
            self.assertEqual(ci_cargo.SUPERVISOR_STOP_GRACE_SECONDS,
                             driver.PRODUCER_SHUTDOWN_GRACE_SECONDS,
                             "composed fixtures must retain the production 15s shared grace")
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
            expected_cleanup_grace = (
                driver.OUTER_SIGNAL_PRODUCER_SETTLE_SECONDS
                if expected_reason == "outer_supervisor_sigterm"
                else driver.PRODUCER_SHUTDOWN_GRACE_SECONDS)
            self.assertEqual(receipt["sigterm_grace_seconds"], expected_cleanup_grace)
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
            cleanup = receipt["descendant_process_group_cleanup"]
            self.assertIn(topology["descendant_pgid"], cleanup["sigkill_group_ids"])
            for pid in (topology["compiler_pid"], topology["descendant_pid"], stubborn_pid):
                assert_dead(self, pid)
            self.assertFalse((work / "csdk-output" / "csdk-producer.json").exists())
            case_name = ("outer-backup" if expected_reason == "outer_supervisor_sigterm"
                         else "producer-deadline")
            print("UNIT_FIXTURE_COMPOSED " + json.dumps({
                "schema": "ami-rust-csdk-composed-cleanup-fixture-v1",
                "case": case_name,
                "observer_platform": sys.platform,
                "termination_reason": receipt["termination_reason"],
                "cleanup_complete": receipt["cleanup_complete"],
                "inner_receipt_sha256": hashlib.sha256(timeout_path.read_bytes()).hexdigest(),
            }, sort_keys=True), flush=True)

    def test_real_linux_outer_wrapper_producer_compiler_deadlines(self):
        # First exercise the wrapper's work cutoff; then let the outer backup
        # cutoff interrupt the same production session/process-group topology.
        self.run_composed_case(inner_timeout=3.0, outer_timeout=45.0,
                               expected_reason="producer_deadline")
        self.run_composed_case(inner_timeout=8.0, outer_timeout=4.0,
                               expected_reason="outer_supervisor_sigterm")


if __name__ == "__main__":
    unittest.main()
