#!/usr/bin/env python3
"""Offline fixtures for package candidate inventory sealing and verification."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


_CANDIDATE_PATH = Path(__file__).with_name("candidate.py")
_SPEC = importlib.util.spec_from_file_location("ami_rust_candidate_test", _CANDIDATE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
candidate = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(candidate)


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True)
        self.pins_path = root / "pins.json"
        self.directory = root / "candidate"
        self.directory.mkdir()
        self.pins = {
            "schema": "ami-rust-package-inputs-v1",
            "sdk_version": "0.1.0",
            "packaging_revision": 1,
            "package_version": "0.1.0-1",
            "packaging_tag": "v0.1.0+packaging.1",
            "sdk_tag": "v0.1.0",
            "repository": "metaneutrons/ami-rust",
            "source_commit": "a" * 40,
            "source_tree": "b" * 40,
            "sdk_run_id": 1001,
            "sdk_run_attempt": 2,
            "manifest_sha256": "c" * 64,
            "transport_sha256": "d" * 64,
        }
        self.pins_path.write_text(json.dumps(self.pins, sort_keys=True) + "\n", encoding="utf-8")
        self.source_commit = "e" * 40
        self.source_tree = "f" * 40
        self.run_id = 2002
        self.run_attempt = 3
        self.epoch = 1_800_000_000
        for name in candidate.asset_names(self.pins):
            self.directory.joinpath(name).write_bytes(("fixture:" + name + "\n").encode())

    def seal(self) -> dict:
        return candidate.seal(
            self.pins_path, self.directory, self.source_commit, self.source_tree,
            self.run_id, self.run_attempt, self.epoch,
        )

    def verify(self, **overrides) -> dict:
        values = {
            "source_commit": self.source_commit,
            "source_tree": self.source_tree,
            "run_id": self.run_id,
            "run_attempt": self.run_attempt,
            "epoch": self.epoch,
        }
        values.update(overrides)
        return candidate.verify(self.pins_path, self.directory, **values)


class CandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def fixture(self, name: str = "fixture") -> Fixture:
        return Fixture(self.root / name)

    def test_seal_and_verify_exact_twelve_file_inventory(self) -> None:
        fixture = self.fixture()
        record = fixture.seal()
        self.assertEqual(record["schema"], "ami-rust-package-candidate-v1")
        self.assertEqual(record["source_commit"], fixture.source_commit)
        self.assertEqual(record["source_tree"], fixture.source_tree)
        self.assertEqual(record["run_id"], fixture.run_id)
        self.assertEqual(record["run_attempt"], fixture.run_attempt)
        self.assertEqual(record["original_sdk"]["source_commit"], fixture.pins["source_commit"])
        self.assertNotEqual(record["source_commit"], record["original_sdk"]["source_commit"])
        self.assertEqual({row["path"] for row in record["assets"]}, set(candidate.asset_names(fixture.pins)))
        names = {path.name for path in fixture.directory.iterdir()}
        self.assertEqual(len(names), 12)
        self.assertEqual(names, set(candidate.asset_names(fixture.pins)) | {"candidate.json", "SHA256SUMS"})
        sums = (fixture.directory / "SHA256SUMS").read_bytes().decode("ascii").splitlines()
        self.assertEqual(len(sums), 11)
        self.assertTrue(any(line.endswith("  candidate.json") for line in sums))
        self.assertEqual(fixture.verify(), record)

    def test_cli_seals_and_verifies_with_isolated_python(self) -> None:
        fixture = self.fixture("cli")
        args = [
            "--pins", str(fixture.pins_path), "--directory", str(fixture.directory),
            "--source-commit", fixture.source_commit, "--source-tree", fixture.source_tree,
            "--run-id", str(fixture.run_id), "--run-attempt", str(fixture.run_attempt),
        ]
        seal = subprocess.run(
            [sys.executable, "-I", "-B", str(_CANDIDATE_PATH), "seal", *args,
             "--epoch", str(fixture.epoch)], capture_output=True, text=True,
        )
        self.assertEqual(seal.returncode, 0, seal.stderr)
        self.assertEqual(json.loads(seal.stdout)["status"], "SEALED_OFFLINE_INVENTORY_ONLY")
        verify = subprocess.run(
            [sys.executable, "-I", "-B", str(_CANDIDATE_PATH), "verify", *args,
             "--epoch", str(fixture.epoch)], capture_output=True, text=True,
        )
        self.assertEqual(verify.returncode, 0, verify.stderr)
        self.assertEqual(json.loads(verify.stdout)["status"], "VERIFIED_OFFLINE_INVENTORY_ONLY")

    def test_changed_or_truncated_asset_fails_verification(self) -> None:
        for name, content in (("changed", b"changed bytes\n"), ("truncated", b"x")):
            with self.subTest(name=name):
                fixture = self.fixture(name)
                fixture.seal()
                payload = next(
                    fixture.directory / asset for asset in candidate.asset_names(fixture.pins)
                    if asset.endswith((".tar.xz", ".deb"))
                )
                payload.write_bytes(content)
                with self.assertRaises(candidate.CandidateError):
                    fixture.verify()

    def test_missing_extra_and_linked_files_fail(self) -> None:
        fixture = self.fixture()
        fixture.seal()
        (fixture.directory / "ami-rust.rb").unlink()
        with self.assertRaises(candidate.CandidateError):
            fixture.verify()

        fixture = self.fixture("extra")
        fixture.seal()
        (fixture.directory / "unexpected.txt").write_text("extra\n", encoding="utf-8")
        with self.assertRaises(candidate.CandidateError):
            fixture.verify()

        fixture = self.fixture("symlink")
        fixture.seal()
        target = fixture.directory / "ami-rust.rb"
        saved = fixture.directory / "saved-formula"
        target.rename(saved)
        target.symlink_to(saved)
        with self.assertRaises(candidate.CandidateError):
            fixture.verify()

    def test_identity_and_checksum_mutations_fail(self) -> None:
        fixture = self.fixture()
        fixture.seal()
        for identity in (
            {"source_commit": "9" * 40},
            {"source_tree": "8" * 40},
            {"run_id": fixture.run_id + 1},
            {"run_attempt": fixture.run_attempt + 1},
            {"epoch": fixture.epoch + 1},
        ):
            with self.subTest(identity=identity):
                with self.assertRaises(candidate.CandidateError):
                    fixture.verify(**identity)

        fixture = self.fixture("checksums")
        fixture.seal()
        sums = fixture.directory / "SHA256SUMS"
        sums.write_bytes(sums.read_bytes().replace(b"  ami-rust.rb\n", b"  ami-rust.rbX\n"))
        with self.assertRaises(candidate.CandidateError):
            fixture.verify()

    def test_duplicate_candidate_json_key_and_oversized_asset_fail(self) -> None:
        fixture = self.fixture()
        fixture.seal()
        (fixture.directory / "candidate.json").write_text(
            '{"schema":"ami-rust-package-candidate-v1","schema":"duplicate"}\n',
            encoding="utf-8",
        )
        with self.assertRaises(candidate.CandidateError):
            fixture.verify()

        fixture = self.fixture("oversized")
        with mock.patch.object(candidate, "MAX_METADATA_BYTES", 1):
            with self.assertRaises(candidate.CandidateError):
                fixture.seal()


if __name__ == "__main__":
    unittest.main(verbosity=2)
