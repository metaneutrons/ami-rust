"""Offline synthetic tests for the hosted Cargo producer's guardrails."""
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import runpy
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from release import ci_cargo


class FakeResponse:
    def __init__(self, body, url, length=None):
        self.body = io.BytesIO(body)
        self.headers = {"Content-Length": str(len(body) if length is None else length)}
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, count=-1):
        return self.body.read(count)

    def geturl(self):
        return self.url


def tar_xz(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:xz") as archive:
        for name, kind, payload in entries:
            member = tarfile.TarInfo(name)
            if kind == "file":
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            elif kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = payload
                archive.addfile(member)
            elif kind == "dir":
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
    return output.getvalue()


class DownloadTests(unittest.TestCase):
    def test_verified_stream_is_written_only_after_exact_digest(self):
        body = b"synthetic pinned archive"
        url = "https://static.rust-lang.org/dist/test.tar.xz"
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "archive.tar.xz"
            receipt = ci_cargo.download_verified(
                url, len(body), hashlib.sha256(body).hexdigest(), target,
                opener=lambda request, timeout: FakeResponse(body, url))
            self.assertEqual(receipt["sha256"], hashlib.sha256(body).hexdigest())
            self.assertEqual(target.read_bytes(), body)
            bad = Path(temp) / "bad.tar.xz"
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                ci_cargo.download_verified(
                    url, len(body), "0" * 64, bad,
                    opener=lambda request, timeout: FakeResponse(body, url))
            self.assertFalse(bad.exists())
            self.assertFalse(Path(str(bad) + ".partial").exists())

    def test_download_refuses_origin_redirect_and_size_mismatch(self):
        body = b"archive"
        url = "https://static.rust-lang.org/dist/test.tar.xz"
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "archive"
            digest = hashlib.sha256(body).hexdigest()
            with self.assertRaisesRegex(ValueError, "redirected"):
                ci_cargo.download_verified(
                    url, len(body), digest, target,
                    opener=lambda request, timeout: FakeResponse(body, "https://elsewhere.invalid/file"))
            with self.assertRaisesRegex(ValueError, "byte count"):
                ci_cargo.download_verified(
                    url, len(body) + 1, digest, target,
                    opener=lambda request, timeout: FakeResponse(body, url, len(body) + 1))


class ArchiveTests(unittest.TestCase):
    def test_extracts_regular_files_and_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "good.tar.xz"
            archive.write_bytes(tar_xz([("rustc-test/bin/rustc", "file", b"binary")]))
            out = root / "out"
            receipt = ci_cargo.safe_extract_tar(archive, out)
            self.assertEqual(receipt["component_root"], "rustc-test")
            self.assertEqual((out / "rustc-test/bin/rustc").read_bytes(), b"binary")
            bad_archive = root / "bad.tar.xz"
            bad_archive.write_bytes(tar_xz([("rustc-test/../../outside", "file", b"bad")]))
            bad_out = root / "bad-out"
            with self.assertRaisesRegex(ValueError, "unsafe member path"):
                ci_cargo.safe_extract_tar(bad_archive, bad_out)
            self.assertFalse((root / "outside").exists())
            self.assertFalse(bad_out.exists())

    def test_rejects_symlink_pivot_and_expanded_size_over_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            escaping = root / "escape.tar.xz"
            escaping.write_bytes(tar_xz([("cargo-test/link", "symlink", "../../outside")]))
            with self.assertRaisesRegex(ValueError, "symlink escapes"):
                ci_cargo.safe_extract_tar(escaping, root / "escape-out")
            oversized = root / "oversized.tar.xz"
            oversized.write_bytes(tar_xz([("cargo-test/file", "file", b"12345")]))
            with self.assertRaisesRegex(ValueError, "expanded size"):
                ci_cargo.safe_extract_tar(oversized, root / "oversized-out", expanded_limit=4)

    def test_extraction_preflights_total_managed_workspace(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "archive.tar.xz"
            archive.write_bytes(tar_xz([("cargo-test/file", "file", b"12345")]))
            output = root / "out"
            with self.assertRaisesRegex(ValueError, "managed workspace ceiling"):
                ci_cargo.safe_extract_tar(archive, output, current_managed_bytes=96,
                                          overall_limit=100)
            self.assertFalse(output.exists())


class PreflightFailureTests(unittest.TestCase):
    def test_failed_admission_preserves_host_python_and_no_work_observation(self):
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            work, output = base / "work", base / "output"
            with mock.patch.object(ci_cargo, "produce", side_effect=ValueError("pinned Python refusal")):
                with contextlib.redirect_stderr(io.StringIO()):
                    code = ci_cargo.main(["--work", str(work), "--output", str(output),
                                          "--inputs", str(base / "inputs.json"),
                                          "--resources", str(base / "resources.json")])
            self.assertEqual(code, 1)
            record = json.loads((output / "producer.json").read_text())
            self.assertEqual(record["host"], ci_cargo.host_identity()[0])
            self.assertEqual(record["rust_target"], ci_cargo.host_identity()[1])
            self.assertEqual(record["python_observed"]["sha256"],
                             ci_cargo.sha256(Path(sys.executable).resolve(strict=True)))
            self.assertFalse(record["managed_work_tree_exists_at_failure"])
            self.assertFalse(work.exists())
            self.assertEqual(record["status"], "FAILED")


class ResourceTests(unittest.TestCase):
    def test_portable_runtime_counts_before_process_admission(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            work, output, bootstrap = root / "work", root / "output", root / "bootstrap"
            logs = work / "logs"
            logs.mkdir(parents=True)
            output.mkdir()
            bootstrap.mkdir()
            base = ci_cargo.Supervisor(work, output, os.environ.copy(), logs).managed_bytes()
            (bootstrap / "runtime.bin").write_bytes(b"x" * 2048)
            supervisor = ci_cargo.Supervisor(work, output, os.environ.copy(), logs,
                                             extra_roots=(bootstrap,))
            self.assertEqual(supervisor.managed_bytes(), base + 2048)
            with mock.patch.object(ci_cargo, "MAX_WORK_BYTES", base + 2047):
                with mock.patch.object(ci_cargo.subprocess, "Popen") as spawn:
                    with self.assertRaisesRegex(RuntimeError, "workspace ceiling"):
                        supervisor.run([sys.executable, "-c", "pass"], cwd=root, label="runtime-budget")
                    spawn.assert_not_called()

    def test_capacity_threshold_is_fail_closed(self):
        policy = {"host_capacity": {"schema": "ami-rust-host-capacity-v1",
                                    "ram_minimum_bytes": 6 * 1024**3,
                                    "disk_free_minimum_bytes": 24 * 1024**3}}
        with mock.patch.object(ci_cargo, "physical_memory_bytes", return_value=8 * 1024**3), \
             mock.patch.object(ci_cargo.shutil, "disk_usage", return_value=mock.Mock(free=25 * 1024**3)):
            passed = ci_cargo.check_capacity("linux-x86_64", Path("/tmp"), policy)
            self.assertEqual(passed["physical_ram_bytes"], 8 * 1024**3)
        with mock.patch.object(ci_cargo, "physical_memory_bytes", return_value=5 * 1024**3), \
             mock.patch.object(ci_cargo.shutil, "disk_usage", return_value=mock.Mock(free=25 * 1024**3)):
            with self.assertRaisesRegex(ValueError, "capacity refused"):
                ci_cargo.check_capacity("linux-x86_64", Path("/tmp"), policy)


class OutputMetadataTests(unittest.TestCase):
    def test_requires_single_parseable_producer_schema_object(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp)
            (output / "producer.json").write_text(
                '{"schema":"ami-rust-hosted-custom-cargo-producer-v1",'
                '"status":"FAILED"}\n')
            self.assertEqual(ci_cargo.validate_output_metadata(output)["status"], "FAILED")
            (output / "producer.json").write_text("[]\n")
            with self.assertRaisesRegex(ValueError, "invalid schema"):
                ci_cargo.validate_output_metadata(output)
            (output / "producer.json").write_text(
                '{"schema":"ami-rust-hosted-custom-cargo-producer-v1",'
                '"status":"FAILED"}\n')
            (output / "unexpected.bin").write_bytes(b"no")
            with self.assertRaisesRegex(ValueError, "only producer.json"):
                ci_cargo.validate_output_metadata(output)


class SupervisorTests(unittest.TestCase):
    def _supervisor(self, root):
        work = root / "work"
        output = root / "output"
        logs = work / "logs"
        logs.mkdir(parents=True)
        output.mkdir()
        return ci_cargo.Supervisor(work, output, os.environ.copy(), logs)

    def test_rss_counter_probe_stops_process(self):
        with tempfile.TemporaryDirectory() as temp:
            supervisor = self._supervisor(Path(temp))
            command = [sys.executable, "-c", "import time; time.sleep(20)"]
            with mock.patch.object(ci_cargo, "rss_group", return_value=ci_cargo.MAX_RSS_BYTES + 1):
                with self.assertRaisesRegex(RuntimeError, "aggregate RSS ceiling"):
                    supervisor.run(command, cwd=Path(temp), label="rss-probe", timeout=5)
            self.assertEqual(supervisor.commands[0]["stop_reason"], "aggregate RSS ceiling")
            self.assertIsNotNone(supervisor.commands[0]["exit_code"])

    def test_build_child_keeps_standalone_session_isolation_by_default(self):
        producer_path = Path(__file__).resolve().parent.parent / "host/cargo-repro/produce.py"
        producer = runpy.run_path(str(producer_path))
        with tempfile.TemporaryDirectory() as temp:
            child = producer["spawn_build_child"](
                [sys.executable, "-c", "import time; time.sleep(0.1)"], cwd=Path(temp),
                env=os.environ.copy(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                self.assertEqual(os.getpgid(child.pid), child.pid)
                self.assertEqual(child.wait(timeout=3), 0)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()

    def test_kills_descendant_when_leader_exits(self):
        if sys.platform == "win32":
            self.skipTest("hosted producer targets Darwin/Linux process groups")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            supervisor = self._supervisor(root)
            pidfile = root / "child.pid"
            child_code = "import time; time.sleep(20)"
            leader_code = ("import subprocess,sys; p=subprocess.Popen([sys.executable,'-c',"
                           + repr(child_code) + "]); open(sys.argv[1],'w').write(str(p.pid))")
            with self.assertRaisesRegex(RuntimeError, "leader exited"):
                supervisor.run([sys.executable, "-c", leader_code, str(pidfile)],
                               cwd=root, label="orphan-probe", timeout=5)
            child_pid = int(pidfile.read_text())
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                try:
                    os.kill(child_pid, 0)
                    status = subprocess.check_output(
                        ["/bin/ps", "-p", str(child_pid), "-o", "stat="], text=True).strip()
                    if not status or status.startswith("Z"):
                        break
                except (OSError, subprocess.CalledProcessError):
                    break
                time.sleep(0.05)
            else:
                with self.assertRaises(ProcessLookupError):
                    os.kill(child_pid, 0)

    def test_outer_supervisor_accepts_completed_shared_group(self):
        producer_path = Path(__file__).resolve().parent.parent / "host/cargo-repro/produce.py"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            supervisor = self._supervisor(root)
            wrapper = (
                "import runpy,sys,pathlib,os,subprocess;"
                "module=runpy.run_path(sys.argv[1]);"
                "assert module['supervisor_group_is_private']();"
                "child=module['spawn_build_child']([sys.executable,'-c','pass'],"
                "cwd=pathlib.Path.cwd(),env=os.environ.copy(),stdout=subprocess.DEVNULL,"
                "stderr=subprocess.DEVNULL,share_supervisor_group=True);"
                "assert os.getpgid(child.pid)==os.getpgrp();"
                "assert child.wait(timeout=3)==0"
            )
            result = supervisor.run([sys.executable, "-I", "-B", "-c", wrapper, str(producer_path)],
                                    cwd=root, label="nested-completion", timeout=5)
            self.assertEqual(result["exit_code"], 0)
            self.assertIsNone(result["stop_reason"])

    def test_outer_supervisor_kills_nested_producer_and_shared_cargo_group(self):
        if sys.platform == "win32":
            self.skipTest("hosted producer targets Darwin/Linux process groups")
        producer_path = Path(__file__).resolve().parent.parent / "host/cargo-repro/produce.py"
        producer = runpy.run_path(str(producer_path))
        self.assertTrue(callable(producer["spawn_build_child"]))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            supervisor = self._supervisor(root)
            pidfile = root / "nested-pids"
            child_code = "import time; time.sleep(30)"
            wrapper_code = (
                "import importlib.util,os,pathlib,subprocess,sys,time;"
                "spec=importlib.util.spec_from_file_location('producer',sys.argv[1]);"
                "module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);"
                "assert module.supervisor_group_is_private();"
                "cargo=module.spawn_build_child([sys.executable,'-c'," + repr(child_code) + "],"
                "cwd=pathlib.Path.cwd(),env=os.environ.copy(),stdout=subprocess.DEVNULL,"
                "stderr=subprocess.DEVNULL,share_supervisor_group=True);"
                "pathlib.Path(sys.argv[2]).write_text(' '.join(map(str,[os.getpid(),"
                "os.getpgrp(),cargo.pid,os.getpgid(cargo.pid)])));"
                "time.sleep(30)"
            )
            command = [sys.executable, "-c", wrapper_code, str(producer_path), str(pidfile)]

            def rss_probe(_pid):
                return (ci_cargo.MAX_RSS_BYTES + 1) if pidfile.exists() else 0

            pids = []
            try:
                with mock.patch.object(ci_cargo, "rss_group", side_effect=rss_probe):
                    with self.assertRaisesRegex(RuntimeError, "aggregate RSS ceiling"):
                        supervisor.run(command, cwd=root, label="nested-rss-probe", timeout=5)
                pids = [int(value) for value in pidfile.read_text().split()]
                wrapper_pid, wrapper_pgid, cargo_pid, cargo_pgid = pids
                self.assertEqual(wrapper_pid, wrapper_pgid)
                self.assertEqual(cargo_pgid, wrapper_pgid)

                def running(pid):
                    try:
                        status = subprocess.check_output(
                            ["/bin/ps", "-p", str(pid), "-o", "stat="], text=True).strip()
                    except subprocess.CalledProcessError:
                        return False
                    return bool(status and not status.startswith("Z"))

                deadline = time.monotonic() + 2
                while time.monotonic() < deadline and any(running(pid) for pid in pids[::2]):
                    time.sleep(0.05)
                self.assertFalse(running(wrapper_pid), "producer wrapper remained alive")
                self.assertFalse(running(cargo_pid), "Cargo-like descendant escaped outer group kill")
            finally:
                for pid in (pids[2], pids[0]) if len(pids) == 4 else ():
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except OSError:
                        pass


if __name__ == "__main__":
    unittest.main()
