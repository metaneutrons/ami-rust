#!/usr/bin/env python3
"""Offline tests for public APT upgrade and cleanup instructions."""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("ami_rust_public_consumer_tests", HERE / "public_consumer.py")
assert SPEC is not None and SPEC.loader is not None
public_consumer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(public_consumer)

LIFECYCLE_SPEC = importlib.util.spec_from_file_location("ami_rust_public_consumer_lifecycle", HERE / "lifecycle.py")
assert LIFECYCLE_SPEC is not None and LIFECYCLE_SPEC.loader is not None
lifecycle = importlib.util.module_from_spec(LIFECYCLE_SPEC)
import sys
sys.modules[LIFECYCLE_SPEC.name] = lifecycle
LIFECYCLE_SPEC.loader.exec_module(lifecycle)


def tar_member(name: str, raw: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:xz", format=tarfile.USTAR_FORMAT) as archive:
        info = tarfile.TarInfo(name)
        info.mode = 0o644
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = 1
        info.size = len(raw)
        archive.addfile(info, io.BytesIO(raw))
    return output.getvalue()


def control_tar(raw: bytes) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=1) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
            info = tarfile.TarInfo("control")
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 1
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return output.getvalue()


def ar_member(name: str, raw: bytes) -> bytes:
    header = ((name + "/").encode().ljust(16, b" ") + b"0".ljust(12, b" ")
              + b"0".ljust(6, b" ") + b"0".ljust(6, b" ")
              + b"100644".ljust(8, b" ") + str(len(raw)).encode().ljust(10, b" ") + b"`\n")
    return header + raw + (b"\n" if len(raw) % 2 else b"")


class AptFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.packages = root / "candidate"
        self.packages.mkdir()
        self.pins = {"sdk_version": "0.1.0", "packaging_revision": 2,
                     "package_version": "0.1.0-2"}
        filename = "ami-rust_0.1.0-2_amd64.deb"
        control = ("Package: ami-rust\nVersion: 0.1.0-2\nArchitecture: amd64\n"
                   "Maintainer: test\nDescription: fixture\n").encode()
        self.data = tar_member("usr/bin/ami-rust", b"fixture launcher\n")
        package = (b"!<arch>\n" + ar_member("debian-binary", b"2.0\n")
                   + ar_member("control.tar.gz", control_tar(control))
                   + ar_member("data.tar.xz", self.data))
        self.deb = self.packages / filename
        self.deb.write_bytes(package)
        candidate = {"schema": "ami-rust-package-candidate-v1",
                     "original_sdk": {"version": self.pins["sdk_version"]},
                     "assets": [{"path": filename, "bytes": len(package),
                                 "sha256": hashlib.sha256(package).hexdigest()}]}
        (self.packages / "candidate.json").write_text(json.dumps(candidate), encoding="utf-8")


class FakeRunner:
    def __init__(self, lower_version: str = "0.1.0-1") -> None:
        self.lower_version = lower_version
        self.calls: list[tuple[str, list[str]]] = []

    def __call__(self, label, argv):
        arguments = [str(value) for value in argv]
        self.calls.append((label, arguments))
        if label == "verify-lower-revision":
            return f"installed\t{self.lower_version}\n".encode()
        if label == "verify-public-archive-upgrade":
            return b"installed\t0.1.0-2\n"
        return b""


class PublicConsumerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.fixture = AptFixture(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_lower_revision_uses_exact_candidate_and_preserves_final_deb(self) -> None:
        original = self.fixture.deb.read_bytes()
        result = public_consumer.make_apt_upgrade_fixture(
            self.fixture.packages, self.root, self.fixture.pins
        )
        lower = Path(result["path"])
        members = lifecycle.parse_ar(lower.read_bytes())
        final_members = lifecycle.parse_ar(original)
        final_control = lifecycle.deb_control(final_members["control.tar.gz"])
        lower_control = lifecycle.deb_control(members["control.tar.gz"])
        self.assertEqual(result["kind"], "local-unsigned-upgrade-fixture")
        self.assertEqual(result["version"], "0.1.0-1")
        self.assertEqual(result["revision"], 1)
        self.assertEqual(members["data.tar.xz"], self.fixture.data)
        self.assertEqual(members["data.tar.xz"], final_members["data.tar.xz"])
        self.assertEqual(lower_control.replace(b"Version: 0.1.0-1\n", b"Version: 0.1.0-2\n", 1),
                         final_control)
        self.assertEqual(self.fixture.deb.read_bytes(), original)
        self.assertEqual(result["source_final_deb_sha256"], hashlib.sha256(original).hexdigest())

    def test_public_upgrade_uses_lower_local_deb_then_explicit_archive_version(self) -> None:
        runner = FakeRunner()
        executable = Path("/usr/bin/ami-rust")
        fixture = public_consumer.upgrade_public_apt(
            self.fixture.packages, self.root, self.fixture.pins, executable, runner
        )
        labels = [label for label, _argv in runner.calls]
        self.assertEqual(labels, ["install-lower-revision-fixture", "verify-lower-revision",
                                  "upgrade-from-public-archive", "verify-public-archive-upgrade",
                                  "verify-upgraded-public-package", "replay-public-apt-upgrade"])
        commands = dict(runner.calls)
        self.assertEqual(commands["install-lower-revision-fixture"], [
            "sudo", "apt-get", "install", "--yes", "--allow-downgrades", fixture["path"]])
        self.assertEqual(commands["upgrade-from-public-archive"], [
            "sudo", "apt-get", "install", "--yes", "--only-upgrade", "ami-rust=0.1.0-2"])
        self.assertEqual(commands["verify-lower-revision"][:3], [
            "dpkg-query", "-W", "-f=${db:Status-Status}\\t${Version}\\n"])
        self.assertEqual(commands["verify-public-archive-upgrade"][:3], [
            "dpkg-query", "-W", "-f=${db:Status-Status}\\t${Version}\\n"])
        replay = commands["replay-public-apt-upgrade"]
        self.assertEqual(replay[replay.index("--phase") + 1], "public-apt-upgrade")

    def test_wrong_lower_version_stops_before_public_archive_upgrade(self) -> None:
        runner = FakeRunner(lower_version="0.1.0-0")
        with self.assertRaisesRegex(ValueError, "expected installed 0.1.0-1"):
            public_consumer.upgrade_public_apt(
                self.fixture.packages, self.root, self.fixture.pins,
                Path("/usr/bin/ami-rust"), runner
            )
        self.assertNotIn("upgrade-from-public-archive", [label for label, _argv in runner.calls])

    def test_candidate_deb_bytes_must_match_candidate_inventory(self) -> None:
        self.fixture.deb.write_bytes(b"changed candidate package\n")
        with self.assertRaisesRegex(ValueError, "differs from its authenticated inventory"):
            public_consumer.make_apt_upgrade_fixture(
                self.fixture.packages, self.root, self.fixture.pins
            )
        self.assertFalse((self.root / "upgrade-fixture").exists())

    def test_apt_has_install_and_cleanup_blocks_while_homebrew_has_one(self) -> None:
        apt_doc = self.root / "apt.md"
        apt_doc.write_text("```sh\ninstall\n```\n\n```sh\ncleanup\n```\n", encoding="utf-8")
        brew_doc = self.root / "brew.md"
        brew_doc.write_text("```sh\ninstall\n```\n", encoding="utf-8")
        self.assertEqual(public_consumer.instruction_blocks("apt", apt_doc), ["install", "cleanup"])
        self.assertEqual(public_consumer.instruction_blocks("homebrew", brew_doc), ["install"])
        with self.assertRaisesRegex(ValueError, "exactly 2 executable blocks"):
            public_consumer.instruction_blocks("apt", brew_doc)


if __name__ == "__main__":
    unittest.main()
