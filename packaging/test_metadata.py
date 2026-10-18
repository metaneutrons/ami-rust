#!/usr/bin/env python3
"""Offline tests for deterministic package-manager and SPDX metadata."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


_PACKAGE_DIR = Path(__file__).resolve().parent
_BUILD_SPEC = importlib.util.spec_from_file_location(
    "ami_rust_package_build_for_metadata", _PACKAGE_DIR / "build.py"
)
assert _BUILD_SPEC is not None and _BUILD_SPEC.loader is not None
build_module = importlib.util.module_from_spec(_BUILD_SPEC)
_BUILD_SPEC.loader.exec_module(build_module)

_METADATA_SPEC = importlib.util.spec_from_file_location(
    "ami_rust_package_metadata", _PACKAGE_DIR / "metadata.py"
)
assert _METADATA_SPEC is not None and _METADATA_SPEC.loader is not None
metadata_module = importlib.util.module_from_spec(_METADATA_SPEC)
_METADATA_SPEC.loader.exec_module(metadata_module)


def _json_bytes(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


class Fixture:
    def __init__(
        self,
        root: Path,
        *,
        malformed_original_spdx: bool = False,
        sdk_version: str = "0.1.0",
        packaging_revision: int = 1,
    ) -> None:
        self.root = root
        self.sdk_version = sdk_version
        self.packaging_revision = packaging_revision
        self.package_version = f"{sdk_version}-{packaging_revision}"
        self.sdk_tag = f"v{sdk_version}"
        self.packaging_tag = f"v{sdk_version}+packaging.{packaging_revision}"
        self.sdk_release_archive = f"ami-rust-{sdk_version}-release.tar.xz"
        self.sdk_sbom = self.sdk_release_archive + ".spdx.json"
        self.transport_name = f"ami-rust-{sdk_version}-transport.json"
        self.archive_name = f"ami-rust-{sdk_version}-packaging.{packaging_revision}.tar.xz"
        self.deb_name = f"ami-rust_{self.package_version}_amd64.deb"
        self.root.mkdir(parents=True)
        self.source = root / "source"
        self.assets = root / "assets"
        self.proofs = root / "proofs"
        self.proof_index = root / "proof-index.json"
        self.source_packaging = self.source / "packaging"
        self.source_packaging.mkdir(parents=True)
        self.assets.mkdir()
        self.proofs.mkdir()
        shutil.copyfile(_PACKAGE_DIR / "cli.py", self.source_packaging / "cli.py")
        shutil.copyfile(_PACKAGE_DIR / "worker.py", self.source_packaging / "worker.py")
        (self.source / "LICENSE-MIT").write_text("MIT fixture notice\n", encoding="utf-8")
        (self.source / "LICENSE-APACHE").write_text("Apache fixture notice\n", encoding="utf-8")
        (self.source_packaging / "README.md").write_text("Adapter fixture.\n", encoding="utf-8")

        self.original_namespace = (
            "https://spdx.org/spdxdocs/ami-rust-sdk-original-fixture/" + sdk_version
        )
        original_spdx = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "ami-rust-sdk-original-fixture",
            "documentNamespace": self.original_namespace,
            "creationInfo": {"creators": ["Tool: fixture-1"], "created": "2026-01-01T00:00:00Z"},
            "packages": [
                {
                    "name": "aros-component-fixture",
                    "SPDXID": "SPDXRef-Package-AROSFixture",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "LicenseRef-Custom-AROS",
                    "copyrightText": "NOASSERTION",
                }
            ],
            "hasExtractedLicensingInfos": [
                {"licenseId": "LicenseRef-Custom-AROS", "extractedText": "Custom AROS fixture terms."},
                {"licenseId": "LicenseRef-libgit", "extractedText": "Custom libgit fixture terms."},
            ],
        }
        if malformed_original_spdx:
            original_spdx.pop("documentNamespace")
        original_spdx_raw = _json_bytes(original_spdx)
        self.asset_data = {
            "SHA256SUMS": b"fixture checksums\n",
            self.sdk_release_archive: b"small synthetic SDK payload archive\n",
            self.sdk_release_archive + ".sigstore.json": b'{"signature":"fixture-release"}\n',
            self.sdk_sbom: original_spdx_raw,
            self.transport_name: b'{"schema":"fixture-transport"}\n',
            self.transport_name + ".sigstore.json": b'{"signature":"fixture-transport"}\n',
        }
        self.pins = {
            "schema": "ami-rust-package-inputs-v1",
            "sdk_version": sdk_version,
            "sdk_tag": self.sdk_tag,
            "packaging_revision": packaging_revision,
            "package_version": self.package_version,
            "packaging_tag": self.packaging_tag,
            "repository": "metaneutrons/ami-rust",
            "source_commit": "b4ebb9cce5decd01616b75acf451d0eba9995ee3",
            "source_tree": "c5d9eed6b057ddadd17356801f8b3897e3e430dc",
            "sdk_run_id": 39121017959,
            "sdk_run_attempt": 1,
            "manifest_sha256": "a" * 64,
            "transport_sha256": hashlib.sha256(self.asset_data[self.transport_name]).hexdigest(),
            "maintainer": "Fabian Schmieder <436979+metaneutrons@users.noreply.github.com>",
            "hosts": {"apt": "linux-x86_64", "homebrew": "macos-aarch64"},
            "assets": [],
        }
        for name, data in self.asset_data.items():
            self.assets.joinpath(name).write_bytes(data)
            self.pins["assets"].append(
                {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            )
        self.source_packaging.joinpath("pins.json").write_text(
            json.dumps(self.pins, indent=2) + "\n", encoding="utf-8"
        )

        proof_subjects = {}
        subject_assets = (
            "SHA256SUMS",
            self.sdk_release_archive,
            self.sdk_sbom,
            self.transport_name,
        )
        for index, subject in enumerate(subject_assets):
            name = f"fixture-proof-{index}.json"
            proof = _json_bytes({"subject": subject, "proof": "synthetic"})
            self.proofs.joinpath(name).write_bytes(proof)
            proof_subjects[subject] = [
                {"path": name, "bytes": len(proof), "sha256": hashlib.sha256(proof).hexdigest()}
            ]
        self.proof_index.write_text(
            json.dumps({"subjects": proof_subjects}, indent=2) + "\n", encoding="utf-8"
        )
        self.epoch = 1_800_000_000

    def build(self, output: Path) -> dict:
        return build_module.build(
            self.source, self.assets, self.proofs, self.proof_index, output, self.epoch
        )

    def make(self, output: Path) -> dict:
        self.build(output)
        return metadata_module.generate(self.source, output, self.epoch)


class MetadataTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def fixture(self, name: str = "fixture", **kwargs) -> Fixture:
        return Fixture(self.root / name, **kwargs)

    def test_generation_is_deterministic_and_binds_formula_and_sboms(self) -> None:
        fixture = self.fixture()
        first_dir = self.root / "first"
        second_dir = self.root / "second"
        first_build = fixture.build(first_dir)
        first_report = metadata_module.generate(fixture.source, first_dir, fixture.epoch)
        second_build = fixture.build(second_dir)
        second_report = metadata_module.generate(fixture.source, second_dir, fixture.epoch)

        self.assertEqual(first_build, second_build)
        self.assertEqual(first_report, second_report)
        generated_names = set(first_report["generated_files"])
        self.assertEqual(
            generated_names,
            {
                "ami-rust.rb",
                fixture.archive_name + ".spdx.json",
                fixture.deb_name + ".spdx.json",
            },
        )
        self.assertEqual(
            {name: (first_dir / name).read_bytes() for name in generated_names},
            {name: (second_dir / name).read_bytes() for name in generated_names},
        )
        self.assertEqual(
            {path.name for path in first_dir.iterdir()},
            generated_names | {
                fixture.archive_name,
                fixture.deb_name,
                "packaging-report.json",
                "metadata-report.json",
            },
        )
        saved_report = json.loads((first_dir / "metadata-report.json").read_text(encoding="utf-8"))
        self.assertEqual(saved_report, first_report)
        self.assertEqual(first_report["source"]["commit"], fixture.pins["source_commit"])
        self.assertEqual(first_report["sdk"]["packaging_tag"], fixture.packaging_tag)
        self.assertEqual(
            first_report["original_sdk_sbom"]["sha256"],
            hashlib.sha256(fixture.asset_data[fixture.sdk_sbom]).hexdigest(),
        )

        archive_name = fixture.archive_name
        formula = (first_dir / "ami-rust.rb").read_text(encoding="utf-8")
        self.assertIn('class AmiRust < Formula', formula)
        self.assertIn('homepage "https://github.com/metaneutrons/ami-rust"', formula)
        self.assertIn(
            'url "https://github.com/metaneutrons/ami-rust/releases/download/'
            f'{fixture.packaging_tag.replace("+", "%2B")}/' + archive_name + '"', formula
        )
        self.assertIn(f'sha256 "{first_build["outputs"][archive_name]["sha256"]}"', formula)
        self.assertIn(f'version "{fixture.sdk_version}"', formula)
        self.assertIn(f"revision {fixture.packaging_revision}", formula)
        self.assertIn('license :cannot_represent', formula)
        self.assertIn('depends_on "python@3.14"', formula)
        self.assertIn('depends_on "git"', formula)
        self.assertIn("depends_on arch: :arm64", formula)
        self.assertIn("depends_on macos: :tahoe", formula)
        self.assertIn('prefix.install Dir["usr/*"]', formula)
        self.assertIn('formula_opt_bin("python@3.14")/"python3.14"', formula)
        self.assertIn('inreplace bin/"ami-rust", "#!/usr/bin/python3", "#!#{python}"', formula)
        self.assertIn("6 GiB of RAM", formula)
        self.assertIn("24 GiB of free disk", formula)
        self.assertIn("global compiler defaults unchanged", formula)
        self.assertIn('test do', formula)
        self.assertIn(
            'assert_equal(\n      "ami-rust '
            f'{fixture.sdk_version} (packaging {fixture.packaging_revision})"',
            formula,
        )
        self.assertIn('JSON.parse(shell_output("#{bin}/ami-rust verify-package"))', formula)
        self.assertIn('livecheck do\n    skip "This packaging release requires explicit qualification."\n  end', formula)
        self.assertLess(formula.index(f'version "{fixture.sdk_version}"'), formula.index('sha256 '))
        self.assertLess(formula.index('livecheck do'), formula.index('depends_on arch: :arm64'))
        self.assertIn('the declaration below describes the composite.', formula)
        self.assertEqual(formula.count("  url "), 1)
        self.assertNotIn("bottle do", formula)

        expected_external = {
            "externalDocumentId": "DocumentRef-OriginalSDK",
            "spdxDocument": fixture.original_namespace,
            "checksum": {
                "algorithm": "SHA256",
                "checksumValue": first_report["original_sdk_sbom"]["sha256"],
            },
        }
        for payload_name, payload in first_report["payloads"].items():
            spdx_path = first_dir / payload["spdx"]["path"]
            spdx = json.loads(spdx_path.read_text(encoding="utf-8"))
            self.assertEqual(spdx["spdxVersion"], "SPDX-2.3")
            self.assertEqual(spdx["creationInfo"]["created"], "2027-01-15T08:00:00Z")
            self.assertEqual(spdx["externalDocumentRefs"], [expected_external])
            packages = {package["name"]: package for package in spdx["packages"]}
            self.assertEqual(packages["ami-rust"]["licenseDeclared"], "NOASSERTION")
            self.assertEqual(packages["ami-rust-package-adapter"]["licenseDeclared"],
                             "MIT OR Apache-2.0")
            self.assertEqual(packages["ami-rust-sdk"]["licenseDeclared"], "NOASSERTION")
            self.assertEqual(
                packages["ami-rust"]["checksums"],
                [{"algorithm": "SHA256", "checksumValue": payload["sha256"]}],
            )
            self.assertIn(
                f"Exact downloaded payload file size: {payload['bytes']} bytes.",
                packages["ami-rust"]["packageComment"],
            )
            self.assertIn(
                {
                    "spdxElementId": packages["ami-rust-sdk"]["SPDXID"],
                    "relationshipType": "DESCRIBED_BY",
                    "relatedSpdxElement": "DocumentRef-OriginalSDK:SPDXRef-DOCUMENT",
                },
                spdx["relationships"],
            )
            self.assertNotIn("LicenseRef-Custom-AROS", spdx_path.read_text(encoding="utf-8"))
            self.assertIn(payload_name, first_report["payloads"])

        archive_path = first_dir / archive_name
        with tarfile.open(archive_path, mode="r:xz") as archive:
            libexec_prefix = (
                f"ami-rust-{fixture.package_version}/usr/libexec/ami-rust/"
                f"{fixture.package_version}/"
            )
            destination = self.root / "installed-package"
            destination.mkdir()
            for member in archive.getmembers():
                if member.isfile() and member.name.startswith(libexec_prefix):
                    relative = member.name[len(libexec_prefix):]
                    target = destination.joinpath(*relative.split("/"))
                    target.parent.mkdir(parents=True, exist_ok=True)
                    stream = archive.extractfile(member)
                    self.assertIsNotNone(stream)
                    target.write_bytes(stream.read())
        cli = destination / "cli.py"
        version = subprocess.run(
            [sys.executable, "-I", "-B", str(cli), "--version"],
            check=True, capture_output=True, text=True,
        )
        verify = subprocess.run(
            [sys.executable, "-I", "-B", str(cli), "verify-package"],
            check=True, capture_output=True, text=True,
        )
        self.assertEqual(
            version.stdout.strip(),
            f"ami-rust {fixture.sdk_version} (packaging {fixture.packaging_revision})",
        )
        self.assertEqual(
            json.loads(verify.stdout),
            {
                "status": "VERIFIED_PACKAGE",
                "sdk_version": fixture.sdk_version,
                "package_version": fixture.package_version,
            },
        )

    def test_malformed_or_mismatched_build_payloads_are_rejected_before_writes(self) -> None:
        cases = ("archive-digest", "deb-digest", "report-json", "report-pin")
        for case in cases:
            with self.subTest(case=case):
                fixture = self.fixture(case)
                output = self.root / ("build-" + case)
                fixture.build(output)
                archive_name = fixture.archive_name
                deb_name = fixture.deb_name
                if case == "archive-digest":
                    with (output / archive_name).open("r+b") as stream:
                        stream.seek(0)
                        byte = stream.read(1)
                        stream.seek(0)
                        stream.write(bytes([byte[0] ^ 1]))
                elif case == "deb-digest":
                    with (output / deb_name).open("r+b") as stream:
                        stream.seek(0)
                        byte = stream.read(1)
                        stream.seek(0)
                        stream.write(bytes([byte[0] ^ 1]))
                else:
                    report_path = output / "packaging-report.json"
                    report = json.loads(report_path.read_text(encoding="utf-8"))
                    if case == "report-json":
                        report_path.write_text('{"schema":"x","schema":"y"}\n', encoding="utf-8")
                    else:
                        report["outputs"][archive_name]["sha256"] = "0" * 64
                        report_path.write_text(json.dumps(report) + "\n", encoding="utf-8")
                with self.assertRaises(metadata_module.MetadataError):
                    metadata_module.generate(fixture.source, output, fixture.epoch)
                self.assertFalse((output / "ami-rust.rb").exists())
                self.assertFalse((output / (archive_name + ".spdx.json")).exists())
                self.assertFalse((output / (deb_name + ".spdx.json")).exists())
                self.assertTrue((output / "packaging-report.json").exists())

    def test_coherent_new_pin_version_changes_all_generated_names_and_links(self) -> None:
        fixture = self.fixture("new-version", sdk_version="0.1.1", packaging_revision=2)
        output = self.root / "new-version-build"
        report = fixture.make(output)
        formula = (output / "ami-rust.rb").read_text(encoding="utf-8")
        report_text = (output / "metadata-report.json").read_text(encoding="utf-8")

        self.assertEqual(
            set(report["generated_files"]),
            {
                "ami-rust.rb",
                fixture.archive_name + ".spdx.json",
                fixture.deb_name + ".spdx.json",
            },
        )
        self.assertEqual(
            set(report["payloads"]), {fixture.archive_name, fixture.deb_name}
        )
        self.assertEqual(
            report["original_sdk_sbom"]["path"], "assets/" + fixture.sdk_sbom
        )
        self.assertEqual(
            report["original_sdk_sbom"]["sha256"],
            hashlib.sha256(fixture.asset_data[fixture.sdk_sbom]).hexdigest(),
        )
        self.assertIn(
            'url "https://github.com/metaneutrons/ami-rust/releases/download/'
            f'{fixture.packaging_tag.replace("+", "%2B")}/{fixture.archive_name}"',
            formula,
        )
        self.assertIn('version "0.1.1"', formula)
        self.assertIn("revision 2", formula)
        self.assertIn('assert_equal(\n      "ami-rust 0.1.1 (packaging 2)"', formula)
        self.assertNotIn("0.1.0", formula)
        self.assertNotIn("0.1.0", report_text)

        archive_sbom = json.loads(
            (output / report["payloads"][fixture.archive_name]["spdx"]["path"])
            .read_text(encoding="utf-8")
        )
        packages = {package["name"]: package for package in archive_sbom["packages"]}
        self.assertEqual(packages["ami-rust-sdk"]["versionInfo"], "0.1.1")
        self.assertEqual(packages["ami-rust-sdk"]["packageFileName"], fixture.sdk_release_archive)
        self.assertIn("/v0.1.1/" + fixture.sdk_release_archive,
                      packages["ami-rust-sdk"]["downloadLocation"])
        self.assertEqual(packages["ami-rust-package-adapter"]["versionInfo"], "0.1.1-2")
        self.assertEqual(
            archive_sbom["externalDocumentRefs"][0]["checksum"]["checksumValue"],
            report["original_sdk_sbom"]["sha256"],
        )

    def test_invalid_original_spdx_identity_is_rejected_without_rewriting_it(self) -> None:
        fixture = self.fixture(malformed_original_spdx=True)
        output = self.root / "bad-original-spdx"
        fixture.build(output)
        raw_original = fixture.asset_data[fixture.sdk_sbom]
        with self.assertRaises(metadata_module.MetadataError):
            metadata_module.generate(fixture.source, output, fixture.epoch)
        self.assertFalse((output / "ami-rust.rb").exists())
        self.assertFalse((output / "metadata-report.json").exists())
        self.assertEqual(
            fixture.assets.joinpath(fixture.sdk_sbom).read_bytes(),
            raw_original,
        )


if __name__ == "__main__":
    unittest.main()
