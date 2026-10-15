"""Offline tests for the pinned hosted-CI Python bootstrap."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock


RELEASE = Path(__file__).resolve().parent


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load test module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ci_python = load_module("_test_ami_rust_ci_python", RELEASE / "ci_python.py")


class FakeResponse:
    def __init__(self, body: bytes, url: str):
        self.body = io.BytesIO(body)
        self.headers = {"Content-Length": str(len(body))}
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self, count=-1):
        return self.body.read(count)

    def geturl(self):
        return self.url


def tar_gz(entries) -> bytes:
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:gz") as archive:
        for name, kind, payload in entries:
            member = tarfile.TarInfo(name)
            if kind == "dir":
                member.type = tarfile.DIRTYPE
                member.mode = 0o755
                archive.addfile(member)
            elif kind == "file":
                member.size = len(payload)
                member.mode = 0o755
                archive.addfile(member, io.BytesIO(payload))
            elif kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = payload
                archive.addfile(member)
            else:
                raise AssertionError(kind)
    return result.getvalue()


class Fixture:
    def __init__(self, root: Path, *, archive: bytes | None = None,
                 member_count: int = 3, expanded_bytes: int | None = None,
                 runtime_sha: str | None = None):
        self.repo = root / "repo"
        (self.repo / "release").mkdir(parents=True)
        self.host = "macos-aarch64"
        self.target = "aarch64-apple-darwin"
        self.runtime = b"synthetic Python executable; never executed by these tests"
        self.runtime_sha = runtime_sha or hashlib.sha256(self.runtime).hexdigest()
        self.archive = archive or tar_gz([
            ("python", "dir", b""),
            ("python/bin", "dir", b""),
            ("python/bin/python3.12", "file", self.runtime),
        ])
        self.url = ("https://github.com/astral-sh/python-build-standalone/releases/download/"
                    "20261013/cpython-3.12.15%2B20261013-aarch64-apple-darwin-install_only.tar.gz")
        self.inputs = {
            "schema": "ami-rust-ci-python-inputs-v1",
            "version": "3.12.15",
            "qualification_claimed": False,
            "hosts": {
                self.host: {
                    "host": self.host,
                    "target_triple": self.target,
                    "url": self.url,
                    "asset_name": "cpython-3.12.15+20261013-aarch64-apple-darwin-install_only.tar.gz",
                    "size_bytes": len(self.archive),
                    "sha256": hashlib.sha256(self.archive).hexdigest(),
                    "runtime_relative_path": "python/bin/python3.12",
                    "runtime_sha256": self.runtime_sha,
                    "runtime_bytes": len(self.runtime),
                    "expanded_bytes": len(self.runtime) if expanded_bytes is None else expanded_bytes,
                    "member_count": member_count,
                },
                "linux-x86_64": {
                    "host": "linux-x86_64",
                    "target_triple": "x86_64-unknown-linux-gnu",
                    "url": ("https://github.com/astral-sh/python-build-standalone/releases/download/"
                            "20261013/cpython-3.12.15%2B20261013-x86_64-unknown-linux-gnu-install_only.tar.gz"),
                    "asset_name": "cpython-3.12.15+20261013-x86_64-unknown-linux-gnu-install_only.tar.gz",
                    "size_bytes": 1,
                    "sha256": "0" * 64,
                    "runtime_relative_path": "python/bin/python3.12",
                    "runtime_sha256": "1" * 64,
                    "runtime_bytes": 1,
                    "expanded_bytes": 1,
                    "member_count": 1,
                },
            },
        }
        self.inputs_path = self.repo / "release" / "ci-python-inputs.json"
        self.inputs_path.write_text(json.dumps(self.inputs, sort_keys=True, indent=2) + "\n")
        self.resources = {
            "schema": "ami-rust-hosted-resources-v1",
            "host_capacity": {"schema": "ami-rust-host-capacity-v1",
                              "ram_minimum_bytes": 6 * 1024**3,
                              "disk_free_minimum_bytes": 24 * 1024**3},
            "build": {"workspace_bytes": 12 * 1024**3},
        }
        (self.repo / "release" / "ci-resources.json").write_text(
            json.dumps(self.resources, sort_keys=True, indent=2) + "\n")
        self.previous_root = ci_python.ROOT
        ci_python.ROOT = self.repo

    def close(self):
        ci_python.ROOT = self.previous_root

    def opener(self, body: bytes | None = None):
        payload = self.archive if body is None else body
        url = "https://release-assets.githubusercontent.com/assets/synthetic"
        return lambda request, timeout: FakeResponse(payload, url)

    def process_runner(self, executable_hash: str | None = None):
        digest = self.runtime_sha if executable_hash is None else executable_hash
        def run(command, *, timeout, max_output_bytes):
            self.asserted_command = command
            assert command[1:4] == ["-I", "-B", "-c"]
            compile(command[4], "<pinned-python-introspection-probe>", "exec")
            assert timeout == 30 and max_output_bytes == 64 * 1024
            output = json.dumps({"version": "3.12.15", "executable_sha256": digest,
                                 "executable_bytes": len(self.runtime)}).encode()
            return {"returncode": 0, "stdout": output, "stderr": b""}
        return run


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixture = Fixture(self.root)
        self.capacity_patch = mock.patch.object(
            ci_python.ci_cargo, "check_capacity",
            return_value={"physical_ram_bytes": 8 * 1024**3,
                          "free_disk_bytes": 32 * 1024**3,
                          "ram_minimum_bytes": 6 * 1024**3,
                          "disk_free_minimum_bytes": 24 * 1024**3})
        self.capacity_patch.start()

    def tearDown(self):
        self.capacity_patch.stop()
        self.fixture.close()
        self.temp.cleanup()

    def provision(self, *, archive_body=None, prefix_name="python-bootstrap", **kwargs):
        prefix = self.root / prefix_name
        return ci_python.provision(
            prefix, self.fixture.inputs_path, host_override=self.fixture.host,
            opener=self.fixture.opener(archive_body), **kwargs)

    def test_verified_fake_download_extracts_and_records_runtime(self):
        prefix = self.root / "python-bootstrap"
        receipt = self.provision(process_runner=self.fixture.process_runner())
        self.assertEqual(receipt["status"], "READY_CI_RUNTIME_NOT_SDK_QUALIFICATION")
        self.assertEqual(receipt["host"], self.fixture.host)
        self.assertEqual(receipt["archive_sha256"], self.fixture.inputs["hosts"][self.fixture.host]["sha256"])
        self.assertEqual(receipt["runtime_sha256"], self.fixture.runtime_sha)
        self.assertEqual(receipt["extraction"], {"component_root": "python", "member_count": 3,
                                                  "expanded_bytes": len(self.fixture.runtime)})
        self.assertEqual((prefix / "archive.tar.gz").read_bytes(), self.fixture.archive)
        self.assertEqual((prefix / "runtime/python/bin/python3.12").read_bytes(), self.fixture.runtime)
        stored = json.loads((prefix / "bootstrap.json").read_text())
        self.assertEqual(stored, receipt)
        self.assertNotIn(str(self.root), json.dumps(receipt))
        self.assertIn("-I", self.fixture.asserted_command)
        self.assertIn("-B", self.fixture.asserted_command)

    def test_corrupt_archive_hash_is_rejected_and_failure_receipt_written(self):
        prefix = self.root / "corrupt"
        bad = bytearray(self.fixture.archive)
        bad[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            self.provision(archive_body=bytes(bad), prefix_name="corrupt")
        receipt = json.loads((prefix / "bootstrap.json").read_text())
        self.assertEqual(receipt["status"], "FAILED")
        self.assertEqual(receipt["failure"]["phase"], "download")
        self.assertFalse((prefix / "archive.tar.gz").exists())

    def test_safe_extractor_rejects_path_traversal(self):
        body = tar_gz([("python/../../escape", "file", b"bad")])
        self.fixture.archive = body
        record = self.fixture.inputs["hosts"][self.fixture.host]
        record["size_bytes"] = len(body)
        record["sha256"] = hashlib.sha256(body).hexdigest()
        record["expanded_bytes"] = 3
        record["runtime_bytes"] = 1
        record["member_count"] = 1
        self.fixture.inputs_path.write_text(json.dumps(self.fixture.inputs, sort_keys=True, indent=2) + "\n")
        prefix = self.root / "unsafe"
        with self.assertRaisesRegex(ValueError, "unsafe member path"):
            self.provision(prefix_name="unsafe")
        self.assertFalse((self.root / "escape").exists())
        receipt = json.loads((prefix / "bootstrap.json").read_text())
        self.assertEqual(receipt["failure"]["phase"], "extract")

    def test_runtime_sha_mismatch_prevents_interpreter_probe(self):
        record = self.fixture.inputs["hosts"][self.fixture.host]
        record["runtime_sha256"] = "0" * 64
        self.fixture.inputs_path.write_text(json.dumps(self.fixture.inputs, sort_keys=True, indent=2) + "\n")
        probe = mock.Mock(side_effect=AssertionError("runtime must not be executed"))
        with self.assertRaisesRegex(ValueError, "runtime executable SHA-256"):
            self.provision(prefix_name="bad-runtime", process_runner=probe)
        self.assertEqual(probe.call_count, 0)
        receipt = json.loads((self.root / "bad-runtime" / "bootstrap.json").read_text())
        self.assertEqual(receipt["failure"]["phase"], "extract")

    def test_exact_member_and_expanded_pins_are_required(self):
        record = self.fixture.inputs["hosts"][self.fixture.host]
        record["member_count"] = 4
        self.fixture.inputs_path.write_text(json.dumps(self.fixture.inputs, sort_keys=True, indent=2) + "\n")
        probe = mock.Mock(side_effect=AssertionError("mismatched archive must not be executed"))
        with self.assertRaisesRegex(ValueError, "member count or expanded bytes"):
            self.provision(prefix_name="bad-count", process_runner=probe)
        self.assertEqual(probe.call_count, 0)

    def test_existing_prefix_is_refused_without_download(self):
        prefix = self.root / "existing"
        prefix.mkdir()
        opener = mock.Mock(side_effect=AssertionError("must not download"))
        with self.assertRaisesRegex(ValueError, "prefix must be fresh"):
            ci_python.provision(prefix, self.fixture.inputs_path,
                                host_override=self.fixture.host, opener=opener)
        opener.assert_not_called()

    def test_runtime_path_traversal_is_rejected_by_pin_validation(self):
        record = self.fixture.inputs["hosts"][self.fixture.host]
        record["runtime_relative_path"] = "python/../outside"
        self.fixture.inputs_path.write_text(json.dumps(self.fixture.inputs, sort_keys=True, indent=2) + "\n")
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.provision(prefix_name="bad-path")
        self.assertFalse((self.root / "bad-path").exists())


if __name__ == "__main__":
    unittest.main()
