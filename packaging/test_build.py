#!/usr/bin/env python3
"""Focused tests for the deterministic packaging builder."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


_BUILD_PATH = Path(__file__).with_name("build.py")
_SPEC = importlib.util.spec_from_file_location("ami_rust_package_build", _BUILD_PATH)
assert _SPEC is not None and _SPEC.loader is not None
build_module = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(build_module)


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.source = root / "source"
        self.assets = root / "assets"
        self.proofs = root / "proofs"
        self.index = root / "proof-index.json"
        self.source.joinpath("packaging").mkdir(parents=True)
        self.assets.mkdir()
        self.proofs.mkdir()
        shutil.copyfile(Path(__file__).with_name("cli.py"), self.source / "packaging" / "cli.py")
        shutil.copyfile(Path(__file__).with_name("worker.py"), self.source / "packaging" / "worker.py")
        self.source.joinpath("packaging", "README.md").write_text("Package docs.\n", encoding="utf-8")
        self.source.joinpath("LICENSE-MIT").write_text("MIT test notice\n", encoding="utf-8")
        self.source.joinpath("LICENSE-APACHE").write_text("Apache test notice\n", encoding="utf-8")
        asset_data = {
            "SHA256SUMS": b"sum  payload\n",
            "ami-rust-0.1.0-release.tar.xz": b"release payload\n",
            "ami-rust-0.1.0-release.tar.xz.sigstore.json": b'{"signature":"release"}\n',
            "ami-rust-0.1.0-release.tar.xz.spdx.json": b'{"spdxVersion":"SPDX-2.3"}\n',
            "ami-rust-0.1.0-transport.json": b'{"schema":"transport"}\n',
            "ami-rust-0.1.0-transport.json.sigstore.json": b'{"signature":"transport"}\n',
        }
        pins = {
            "schema": "ami-rust-package-inputs-v1",
            "sdk_version": "0.1.0",
            "packaging_revision": 1,
            "package_version": "0.1.0-1",
            "packaging_tag": "v0.1.0+packaging.1",
            "maintainer": "Fabian Schmieder <fabian@example.invalid>",
            "assets": [],
        }
        for name, data in asset_data.items():
            self.assets.joinpath(name).write_bytes(data)
            pins["assets"].append(
                {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            )
        self.source.joinpath("packaging", "pins.json").write_text(
            json.dumps(pins, indent=2) + "\n", encoding="utf-8"
        )
        proof_subjects = {}
        for index, subject in enumerate(
            [
                "SHA256SUMS",
                "ami-rust-0.1.0-release.tar.xz",
                "ami-rust-0.1.0-release.tar.xz.spdx.json",
                "ami-rust-0.1.0-transport.json",
            ]
        ):
            name = f"proof-{index}.sigstore.json"
            data = json.dumps({"subject": subject, "proof": "fixture"}, sort_keys=True).encode() + b"\n"
            self.proofs.joinpath(name).write_bytes(data)
            proof_subjects[subject] = [
                {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            ]
        self.index.write_text(json.dumps({"subjects": proof_subjects}, indent=2) + "\n", encoding="utf-8")

    def pin_publisher_proofs(self) -> None:
        pins_path = self.source / "packaging/pins.json"
        pins = json.loads(pins_path.read_text(encoding="utf-8"))
        index = json.loads(self.index.read_text(encoding="utf-8"))
        pins["publisher_proofs"] = {
            subject: [{"bytes": row["bytes"], "sha256": row["sha256"]} for row in rows]
            for subject, rows in index["subjects"].items()
        }
        pins_path.write_text(json.dumps(pins, indent=2) + "\n", encoding="utf-8")

    def build(self, output: Path):
        return build_module.build(self.source, self.assets, self.proofs, self.index, output, 1_800_000_000)


class BuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def fixture(self) -> Fixture:
        return Fixture(self.root / "fixture")

    def test_two_builds_are_byte_identical_and_packages_read_back(self) -> None:
        fixture = self.fixture()
        first = self.root / "first"
        second = self.root / "second"
        report_a = fixture.build(first)
        report_b = fixture.build(second)
        self.assertEqual(report_a, report_b)
        files_a = {path.name: path.read_bytes() for path in first.iterdir()}
        files_b = {path.name: path.read_bytes() for path in second.iterdir()}
        self.assertEqual(files_a, files_b)
        self.assertEqual(
            set(files_a),
            {
                "ami-rust-0.1.0-packaging.1.tar.xz",
                "ami-rust_0.1.0-1_amd64.deb",
                "packaging-report.json",
            },
        )
        self.assertEqual(report_a["schema"], "ami-rust-packaging-report-v1")
        with tarfile.open(first / "ami-rust-0.1.0-packaging.1.tar.xz", "r:xz") as archive:
            names = archive.getnames()
        tops = {name.split("/", 1)[0] for name in names}
        self.assertEqual(tops, {"ami-rust-0.1.0-1"})
        self.assertIn("ami-rust-0.1.0-1/usr/bin/ami-rust", names)
        self.assertIn(
            "ami-rust-0.1.0-1/usr/libexec/ami-rust/0.1.0-1/inventory.json", names
        )
        self.assertIn("ami-rust-0.1.0-1/usr/share/doc/ami-rust/README.md", names)
        extracted = self.root / "extracted"
        with tarfile.open(first / "ami-rust-0.1.0-packaging.1.tar.xz", "r:xz") as archive:
            for member in archive.getmembers():
                destination = extracted.joinpath(*member.name.rstrip("/").split("/"))
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                    destination.chmod(member.mode)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                self.assertIsNotNone(stream)
                destination.write_bytes(stream.read())
                destination.chmod(member.mode)
        packaged_cli = extracted / "ami-rust-0.1.0-1/usr/libexec/ami-rust/0.1.0-1/cli.py"
        verify = subprocess.run(
            [sys.executable, "-I", "-B", str(packaged_cli), "verify-package"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(verify.returncode, 0, verify.stderr)
        self.assertEqual(json.loads(verify.stdout)["status"], "VERIFIED_PACKAGE")
        dpkg_deb = shutil.which("dpkg-deb")
        if dpkg_deb:
            package = first / "ami-rust_0.1.0-1_amd64.deb"
            info = subprocess.run([dpkg_deb, "--info", str(package)], capture_output=True, text=True)
            contents = subprocess.run([dpkg_deb, "--contents", str(package)], capture_output=True, text=True)
            self.assertEqual(info.returncode, 0, info.stderr)
            self.assertEqual(contents.returncode, 0, contents.stderr)
            self.assertIn("Depends: python3 (>= 3.10), git, ca-certificates", info.stdout)
            self.assertIn("usr/bin/ami-rust", contents.stdout)

    def test_same_proof_can_attest_multiple_subjects(self) -> None:
        fixture = self.fixture()
        index = json.loads(fixture.index.read_text(encoding="utf-8"))
        subjects = index["subjects"]
        sums_proof = subjects["SHA256SUMS"][0]
        release_subject = "ami-rust-0.1.0-release.tar.xz"
        subjects[release_subject] = [dict(sums_proof)]
        fixture.proofs.joinpath("proof-1.sigstore.json").unlink()
        fixture.index.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
        fixture.pin_publisher_proofs()

        output = self.root / "shared-proof-output"
        fixture.build(output)
        archive_path = output / "ami-rust-0.1.0-packaging.1.tar.xz"
        with tarfile.open(archive_path, "r:xz") as archive:
            names = archive.getnames()
            packaged_index = archive.extractfile(
                "ami-rust-0.1.0-1/usr/libexec/ami-rust/0.1.0-1/proofs.json"
            )
            self.assertIsNotNone(packaged_index)
            packaged_subjects = json.loads(packaged_index.read())["subjects"]
        self.assertEqual(packaged_subjects["SHA256SUMS"], packaged_subjects[release_subject])
        self.assertEqual(
            sum(
                name.startswith("ami-rust-0.1.0-1/usr/libexec/ami-rust/0.1.0-1/proofs/")
                for name in names
            ),
            3,
        )

    def test_pinned_proof_digests_accept_the_matching_index(self) -> None:
        fixture = self.fixture()
        fixture.pin_publisher_proofs()

        report = fixture.build(self.root / "pinned-proof-output")
        self.assertEqual(report["schema"], "ami-rust-packaging-report-v1")

    def test_self_consistent_substituted_proof_is_rejected_by_source_pins(self) -> None:
        fixture = self.fixture()
        fixture.pin_publisher_proofs()
        index = json.loads(fixture.index.read_text(encoding="utf-8"))
        subject = "SHA256SUMS"
        row = index["subjects"][subject][0]
        replacement = json.dumps(
            {"subject": subject, "proof": "well-formed but not source-pinned"}, sort_keys=True
        ).encode() + b"\n"
        fixture.proofs.joinpath(row["path"]).write_bytes(replacement)
        row["bytes"] = len(replacement)
        row["sha256"] = hashlib.sha256(replacement).hexdigest()
        fixture.index.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")

        output = self.root / "substituted-proof-output"
        with self.assertRaisesRegex(build_module.BuildError, "differ from pins.json"):
            fixture.build(output)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".substituted-proof-output.stage-*")), [])

    def test_bad_inputs_are_rejected_without_publishing_outputs(self) -> None:
        cases = (
            "altered asset",
            "missing proof",
            "unsafe proof path",
            "symlink asset",
            "extra proof",
            "duplicate proof in subject",
            "conflicting proof alias",
        )
        for case in cases:
            with self.subTest(case=case):
                case_root = self.root / case.replace(" ", "-")
                fixture = Fixture(case_root / "fixture")
                if case == "altered asset":
                    fixture.assets.joinpath("SHA256SUMS").write_bytes(b"changed\n")
                elif case == "missing proof":
                    fixture.proofs.joinpath("proof-0.sigstore.json").unlink()
                elif case == "unsafe proof path":
                    index = json.loads(fixture.index.read_text(encoding="utf-8"))
                    index["subjects"]["SHA256SUMS"][0]["path"] = "../outside.json"
                    fixture.index.write_text(json.dumps(index), encoding="utf-8")
                elif case == "symlink asset":
                    target = fixture.assets.joinpath("SHA256SUMS")
                    target.unlink()
                    target.symlink_to(fixture.assets / "ami-rust-0.1.0-transport.json")
                elif case == "extra proof":
                    fixture.proofs.joinpath("extra.json").write_text("{}\n", encoding="utf-8")
                elif case == "duplicate proof in subject":
                    index = json.loads(fixture.index.read_text(encoding="utf-8"))
                    rows = index["subjects"]["SHA256SUMS"]
                    rows.append(dict(rows[0]))
                    fixture.index.write_text(json.dumps(index), encoding="utf-8")
                elif case == "conflicting proof alias":
                    index = json.loads(fixture.index.read_text(encoding="utf-8"))
                    index["subjects"]["ami-rust-0.1.0-release.tar.xz"][0].update(
                        {"path": "proof-0.sigstore.json", "sha256": "0" * 64}
                    )
                    fixture.index.write_text(json.dumps(index), encoding="utf-8")
                output = case_root / "published"
                with self.assertRaises(build_module.BuildError):
                    fixture.build(output)
                self.assertFalse(output.exists())
                self.assertEqual(list(case_root.glob(".published.stage-*")), [])

    def test_existing_output_is_not_overwritten(self) -> None:
        fixture = self.fixture()
        output = self.root / "already-there"
        output.mkdir()
        marker = output / "keep.txt"
        marker.write_text("unchanged", encoding="utf-8")
        with self.assertRaises(build_module.BuildError):
            fixture.build(output)
        self.assertEqual(marker.read_text(encoding="utf-8"), "unchanged")


if __name__ == "__main__":
    unittest.main()
