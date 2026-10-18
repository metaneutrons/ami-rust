#!/usr/bin/env python3
"""Focused offline tests for bounded SDK input retrieval."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace


_FETCH_PATH = Path(__file__).with_name("fetch.py")
_SPEC = importlib.util.spec_from_file_location("ami_rust_package_fetch", _FETCH_PATH)
assert _SPEC is not None and _SPEC.loader is not None
fetch_module = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(fetch_module)


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True)
        self.output = root / "fetched"
        self.asset_data = {
            "SHA256SUMS": b"checksums fixture\n",
            "ami-rust-0.1.0-release.tar.xz": b"SDK archive fixture\n",
            "ami-rust-0.1.0-release.tar.xz.sigstore.json": b'{"signature":"archive"}\n',
            "ami-rust-0.1.0-release.tar.xz.spdx.json": b'{"spdxVersion":"SPDX-2.3"}\n',
            "ami-rust-0.1.0-transport.json": b'{"schema":"transport"}\n',
            "ami-rust-0.1.0-transport.json.sigstore.json": b'{"signature":"transport"}\n',
        }
        self.pins = {
            "schema": "ami-rust-package-inputs-v1",
            "repository": "metaneutrons/ami-rust",
            "sdk_version": "0.1.0",
            "sdk_tag": "v0.1.0",
            "packaging_revision": 1,
            "package_version": "0.1.0-1",
            "packaging_tag": "v0.1.0+packaging.1",
            "source_commit": "b4ebb9cce5decd01616b75acf451d0eba9995ee3",
            "source_tree": "c5d9eed6b057ddadd17356801f8b3897e3e430dc",
            "sdk_run_id": 39121017959,
            "sdk_run_attempt": 1,
            "manifest_sha256": "a" * 64,
            "transport_sha256": hashlib.sha256(self.asset_data["ami-rust-0.1.0-transport.json"]).hexdigest(),
            "assets": [],
        }
        for name, data in self.asset_data.items():
            self.pins["assets"].append(
                {"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            )
        subjects = (
            "SHA256SUMS",
            "ami-rust-0.1.0-release.tar.xz",
            "ami-rust-0.1.0-release.tar.xz.spdx.json",
            "ami-rust-0.1.0-transport.json",
        )
        self.pins["publisher_proofs"] = {}
        for subject in subjects:
            asset_digest = hashlib.sha256(self.asset_data[subject]).hexdigest()
            proof = self._proof_for(subject, asset_digest)
            self.pins["publisher_proofs"][subject] = [{
                "bytes": len(proof), "sha256": hashlib.sha256(proof).hexdigest(),
            }]
        self.urls: list[str] = []
        self.commands: list[list[str]] = []
        self.download_dirs: list[Path] = []
        self.missing_asset: str | None = None
        self.changed_asset: str | None = None
        self.oversized_asset: str | None = None
        self.proof_mode = "valid"
        self.duplicate_first_proof = False
        self.shared_proof: bytes | None = None
        self.asset_requests = 0

    def opener(self, url: str, *, timeout: int):
        self.assertions(timeout == 60, "asset retrieval timeout must be bounded")
        self.urls.append(url)
        name = url.rsplit("/", 1)[-1]
        from urllib.parse import unquote
        name = unquote(name)
        if name == self.missing_asset:
            raise OSError("fixture has no response for this asset")
        data = self.asset_data[name]
        if name == self.changed_asset:
            data = bytes([data[0] ^ 1]) + data[1:]
        if name == self.oversized_asset:
            data += b"x"
        self.asset_requests += 1
        return io.BytesIO(data)

    @staticmethod
    def assertions(condition: bool, message: str) -> None:
        if not condition:
            raise AssertionError(message)

    def _proof_for(self, subject: str, digest: str, *, extra: bool = False) -> bytes:
        value = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": subject, "digest": {"sha256": digest}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {"fixture": True, **({"extra": True} if extra else {})},
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def runner(self, command, *, cwd, stdin, stdout, stderr, timeout, check):
        command = [str(value) for value in command]
        self.commands.append(command)
        directory = Path(cwd)
        self.download_dirs.append(directory)
        self.assertions(not list(directory.iterdir()), "each GH retrieval needs a fresh directory")
        self.assertions(stdin == subprocess.DEVNULL, "GH retrieval must not inherit stdin")
        self.assertions(stdout == subprocess.DEVNULL and stderr == subprocess.DEVNULL,
                         "GH retrieval output must stay out of logs")
        self.assertions(timeout == 300 and check is False, "GH retrieval must be bounded")
        asset = Path(command[3])
        digest = hashlib.sha256(asset.read_bytes()).hexdigest()
        if self.proof_mode == "duplicate-key":
            raw = b'{"same":1,"same":2}'
        elif self.proof_mode == "constant":
            raw = b'{"value":NaN}'
        elif self.proof_mode == "non-object":
            raw = b"[]"
        elif self.proof_mode == "invalid":
            raw = b"not-json"
        elif self.proof_mode == "blank-line":
            raw = b"{}\n\n{}"
        elif self.proof_mode == "too-many-lines":
            raw = b"{}\n" * 9
        elif self.proof_mode == "oversized-line":
            raw = b'{"x":"' + b"a" * (2 * 1024 * 1024) + b'"}'
        elif self.proof_mode == "extra-only":
            raw = self._proof_for(asset.name, digest, extra=True)
        else:
            raw = self.shared_proof or self._proof_for(asset.name, digest)
            if self.proof_mode == "extra-valid":
                raw += b"\n" + self._proof_for(asset.name, digest, extra=True)
            if self.duplicate_first_proof and asset.name == "SHA256SUMS":
                raw += b"\n" + raw

        if self.proof_mode == "unexpected-name":
            filename = "unexpected.jsonl"
        else:
            filename = "sha256:" + digest + ".jsonl"
        (directory / filename).write_bytes(raw)
        if self.proof_mode == "multiple-files":
            (directory / "another.jsonl").write_text("{}\n", encoding="utf-8")
        return SimpleNamespace(returncode=0)

    def fetch(self):
        return fetch_module.fetch(self.pins, self.output, opener=self.opener, runner=self.runner)


class FetchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def fixture(self) -> Fixture:
        return Fixture(self.root / "fixture")

    def test_fetches_exact_assets_and_deduplicates_raw_proof_lines(self) -> None:
        fixture = self.fixture()
        fixture.duplicate_first_proof = True
        report = fixture.fetch()

        self.assertEqual(len(fixture.urls), 6)
        self.assertEqual(
            set(fixture.urls),
            {
                "https://github.com/metaneutrons/ami-rust/releases/download/v0.1.0/"
                + name
                for name in fixture.asset_data
            },
        )
        self.assertEqual(len(fixture.commands), 4)
        self.assertEqual(len(set(fixture.download_dirs)), 4)
        self.assertEqual(
            fixture.commands[0],
            [
                "gh", "attestation", "download", str(fixture.output / "assets" / "SHA256SUMS"),
                "--repo", "metaneutrons/ami-rust", "--hostname", "github.com",
                "--predicate-type", "https://slsa.dev/provenance/v1", "--limit", "8",
            ],
        )
        self.assertEqual(
            {path.name for path in fixture.output.iterdir()},
            {"assets", "proofs", "proofs.json", "fetch-report.json"},
        )
        self.assertEqual({path.name for path in (fixture.output / "assets").iterdir()},
                         set(fixture.asset_data))
        proof_index = json.loads((fixture.output / "proofs.json").read_text(encoding="utf-8"))
        expected_subjects = {
            "SHA256SUMS",
            "ami-rust-0.1.0-release.tar.xz",
            "ami-rust-0.1.0-release.tar.xz.spdx.json",
            "ami-rust-0.1.0-transport.json",
        }
        self.assertEqual(set(proof_index), {"subjects"})
        self.assertEqual(set(proof_index["subjects"]), expected_subjects)
        self.assertEqual(len(proof_index["subjects"]["SHA256SUMS"]), 1)
        proof_files = list((fixture.output / "proofs").iterdir())
        self.assertEqual(len(proof_files), 4)
        self.assertTrue(all(path.name == hashlib.sha256(path.read_bytes()).hexdigest() + ".json"
                            for path in proof_files))
        self.assertEqual(report["pins"], fixture.pins)
        self.assertEqual(report["source"]["sdk_tag"], "v0.1.0")
        self.assertEqual(report["proof_line_count"], 5)
        self.assertEqual(report["proof_unique_count"], 4)
        self.assertEqual(report["proof_ignored_count"], 0)
        self.assertEqual(report["proof_counts"]["SHA256SUMS"], 1)
        self.assertNotIn("authenticated", report)
        saved_report = json.loads((fixture.output / "fetch-report.json").read_text(encoding="utf-8"))
        self.assertEqual(saved_report, report)
        for row in report["assets"]:
            self.assertEqual(row["pinned_bytes"], row["actual_bytes"])
            self.assertEqual(row["pinned_sha256"], row["actual_sha256"])

    def test_extra_well_formed_proofs_do_not_change_selected_proof_inputs(self) -> None:
        baseline = self.fixture()
        baseline.fetch()
        baseline_index = (baseline.output / "proofs.json").read_bytes()
        baseline_files = {path.name: path.read_bytes()
                          for path in (baseline.output / "proofs").iterdir()}

        extra = Fixture(self.root / "fixture-extra")
        extra.proof_mode = "extra-valid"
        report = extra.fetch()
        extra_files = {path.name: path.read_bytes() for path in (extra.output / "proofs").iterdir()}

        self.assertEqual((extra.output / "proofs.json").read_bytes(), baseline_index)
        self.assertEqual(extra_files, baseline_files)
        self.assertEqual(report["proof_ignored_count"], 4)
        self.assertEqual(report["proof_line_count"], 8)

    def test_one_pinned_multi_subject_proof_is_shared_across_subjects(self) -> None:
        fixture = self.fixture()
        subjects = sorted(fixture.pins["publisher_proofs"])
        value = {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{
                "name": subject,
                "digest": {"sha256": hashlib.sha256(fixture.asset_data[subject]).hexdigest()},
            } for subject in subjects],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {"fixture": True, "shared": True},
        }
        shared = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        pin = {"bytes": len(shared), "sha256": hashlib.sha256(shared).hexdigest()}
        fixture.shared_proof = shared
        fixture.pins["publisher_proofs"] = {subject: [dict(pin)] for subject in subjects}

        report = fixture.fetch()
        index = json.loads((fixture.output / "proofs.json").read_text(encoding="utf-8"))
        self.assertEqual(report["proof_unique_count"], 1)
        self.assertEqual(len(list((fixture.output / "proofs").iterdir())), 1)
        self.assertEqual({row["path"] for rows in index["subjects"].values() for row in rows},
                         {pin["sha256"] + ".json"})
        self.assertTrue(all(len(rows) == 1 for rows in index["subjects"].values()))

    def test_missing_or_changed_pinned_proof_is_rejected(self) -> None:
        missing = self.fixture()
        missing.proof_mode = "extra-only"
        with self.assertRaisesRegex(fetch_module.FetchError, "pinned GH attestation proof"):
            missing.fetch()
        self.assertTrue((missing.output / ".gh-downloads").is_dir())
        self.assertFalse((missing.output / "proofs.json").exists())

        changed = Fixture(self.root / "fixture-changed-pin")
        changed.pins["publisher_proofs"]["SHA256SUMS"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(fetch_module.FetchError, "pinned GH attestation proof"):
            changed.fetch()
        self.assertFalse((changed.output / "proofs.json").exists())

    def test_publisher_proof_pin_schema_is_exact_bounded_and_unique(self) -> None:
        cases = ("missing-subject", "bad-length", "duplicate-row")
        for case in cases:
            with self.subTest(case=case):
                fixture = Fixture(self.root / ("publisher-pin-" + case))
                publisher_proofs = fixture.pins["publisher_proofs"]
                if case == "missing-subject":
                    del publisher_proofs["SHA256SUMS"]
                elif case == "bad-length":
                    publisher_proofs["SHA256SUMS"][0]["bytes"] = 0
                else:
                    publisher_proofs["SHA256SUMS"].append(
                        dict(publisher_proofs["SHA256SUMS"][0])
                    )
                with self.assertRaises(fetch_module.FetchError):
                    fixture.fetch()
                self.assertFalse(fixture.output.exists())
                self.assertEqual(fixture.urls, [])

    def test_existing_output_is_rejected_without_overwriting(self) -> None:
        fixture = self.fixture()
        fixture.output.mkdir(parents=True)
        marker = fixture.output / "keep.txt"
        marker.write_text("unchanged", encoding="utf-8")
        with self.assertRaises(fetch_module.FetchError):
            fixture.fetch()
        self.assertEqual(marker.read_text(encoding="utf-8"), "unchanged")
        self.assertEqual(fixture.urls, [])

    def test_invalid_asset_downloads_fail_and_remain_for_inspection(self) -> None:
        cases = ("altered", "missing", "oversized")
        for case in cases:
            with self.subTest(case=case):
                fixture = Fixture(self.root / ("fixture-" + case))
                if case == "altered":
                    fixture.changed_asset = "SHA256SUMS"
                elif case == "missing":
                    fixture.missing_asset = "SHA256SUMS"
                else:
                    fixture.oversized_asset = "SHA256SUMS"
                with self.assertRaises(fetch_module.FetchError):
                    fixture.fetch()
                self.assertTrue(fixture.output.is_dir())
                self.assertFalse((fixture.output / "proofs.json").exists())
                self.assertFalse((fixture.output / "fetch-report.json").exists())
                self.assertEqual(fixture.commands, [])
                partial = fixture.output / "assets" / "SHA256SUMS"
                if case == "missing":
                    self.assertFalse(partial.exists())
                else:
                    self.assertTrue(partial.is_file())
                    self.assertLessEqual(partial.stat().st_size,
                                         fixture.pins["assets"][0]["bytes"])

    def test_malformed_or_ambiguous_attestations_fail_before_packaging(self) -> None:
        cases = (
            "duplicate-key", "constant", "non-object", "invalid", "blank-line",
            "too-many-lines", "oversized-line", "unexpected-name", "multiple-files",
        )
        for case in cases:
            with self.subTest(case=case):
                fixture = Fixture(self.root / ("proof-" + case))
                fixture.proof_mode = case
                with self.assertRaises(fetch_module.FetchError):
                    fixture.fetch()
                self.assertEqual(len(fixture.urls), 6)
                self.assertEqual(len(fixture.commands), 1)
                self.assertTrue(fixture.output.is_dir())
                self.assertFalse((fixture.output / "proofs.json").exists())
                self.assertFalse((fixture.output / "fetch-report.json").exists())
                self.assertTrue((fixture.output / ".gh-downloads").is_dir())

    def test_pins_must_cover_the_exact_release_assets(self) -> None:
        fixture = self.fixture()
        fixture.pins["assets"].pop()
        with self.assertRaises(fetch_module.FetchError):
            fixture.fetch()
        self.assertFalse(fixture.output.exists())
        self.assertEqual(fixture.urls, [])


if __name__ == "__main__":
    unittest.main()
