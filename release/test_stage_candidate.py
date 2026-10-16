#!/usr/bin/env python3
"""Offline fixtures for public SDK release candidate staging."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("stage_candidate.py")
SPEC = importlib.util.spec_from_file_location("r1_stage_candidate_fixture_target", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
stage_candidate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stage_candidate)


class StageCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="stage-candidate-test-")
        self.root = Path(self.temp.name).resolve()
        self.bundle = self.root / "authenticated-bundle"
        self.bundle.mkdir()
        self.version = "1.2.3"
        self.source_commit = "a" * 40
        self.payloads = {
            "sdk.tar.xz": b"synthetic sdk archive\x00\xff",
            "sbom.spdx.json": b'{"spdxVersion":"SPDX-2.3","packages":[]}\n',
        }
        for name, data in self.payloads.items():
            (self.bundle / name).write_bytes(data)
        auth = self.bundle / ".auth"
        auth.mkdir()
        (auth / "inputs.json").write_bytes(b'{"schema":"ami-rust-auth-inputs-v1"}\n')
        (auth / "authentication.json").write_bytes(b'{"verified":true}\n')
        self._write_manifest()
        self.output = self.root / "prepared-candidate"

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def _digest(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def _json(value: object) -> bytes:
        return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")

    def _write_manifest(self, *, version=None, source_commit=None, qualification_only=False):
        manifest = {
            "schema": "ami-rust-release-v1",
            "version": version or self.version,
            "qualification_only": qualification_only,
            "sdk_archive": "sdk.tar.xz",
            "assets": [
                {"path": name, "bytes": len(data), "sha256": self._digest(data)}
                for name, data in sorted(self.payloads.items())
            ],
            "producer": {
                "kind": "protected-github-actions",
                "repository": "metaneutrons/ami-rust",
                "workflow": "release/sdk-qualify.yml",
                "source_sha": source_commit or self.source_commit,
                "workflow_sha": source_commit or self.source_commit,
                "acceptance": "R1 acceptance and publication are separate gates",
            },
        }
        (self.bundle / "release.json").write_bytes(self._json(manifest))

    def _add_signatures(self):
        names = stage_candidate.asset_names("v1.2.3")
        (self.output / names["payload_signature"]).write_bytes(self._json({"bundle": "payload"}))
        (self.output / names["transport_signature"]).write_bytes(self._json({"bundle": "transport"}))

    def _prepare(self, tag="v1.2.3-rc.1+build.4"):
        self.output = self.root / "prepared-candidate"
        return stage_candidate.prepare(tag, self.bundle, self.output)

    def test_prepare_finalize_and_full_payload_round_trip(self):
        tag = "v1.2.3-rc.1+build.4"
        names = stage_candidate.asset_names(tag)
        prepared = self._prepare(tag)
        self.assertEqual(names["payload"], "ami-rust-1.2.3-release.tar.xz")
        self.assertEqual(names["transport"], "ami-rust-1.2.3-transport.json")
        self.assertEqual(names["sbom"], names["payload"] + ".spdx.json")
        self.assertEqual(names["payload_signature"], names["payload"] + ".sigstore.json")
        self.assertEqual(names["transport_signature"], names["transport"] + ".sigstore.json")
        self.assertEqual(set(path.name for path in self.output.iterdir()), {
            names["payload"], names["sbom"], names["transport"]})
        self.assertEqual(prepared["version"], self.version)
        self.assertEqual(prepared["source_commit"], self.source_commit)
        self.assertEqual(prepared["release_json_sha256"], self._digest((self.bundle / "release.json").read_bytes()))
        self.assertNotIn("status", prepared)

        record = json.loads((self.output / names["transport"]).read_bytes())
        self.assertEqual(set(record), {"archive", "files"})
        self.assertEqual(record["archive"]["name"], names["payload"])
        readback = self.root / "full-round-trip"
        receipt = stage_candidate._TRANSPORT.unpack_bundle(
            self.output / names["payload"], record, readback)
        self.assertEqual(receipt, record)
        original = dict(stage_candidate._TRANSPORT._scan_bundle(self.bundle))
        unpacked = dict(stage_candidate._TRANSPORT._scan_bundle(readback))
        self.assertEqual(unpacked, original)

        self._add_signatures()
        result = stage_candidate.finalize(self.output, tag)
        self.assertEqual(set(path.name for path in self.output.iterdir()), set(names.values()))
        checksum_names = sorted(name for key, name in names.items() if key != "checksums")
        expected_checksums = "".join(
            self._digest((self.output / name).read_bytes()) + "  " + name + "\n"
            for name in checksum_names
        ).encode("ascii")
        self.assertEqual((self.output / names["checksums"]).read_bytes(), expected_checksums)
        before_verify = {path.name: path.read_bytes() for path in self.output.iterdir()}
        verified = stage_candidate.verify_candidate(self.output, tag)
        after_verify = {path.name: path.read_bytes() for path in self.output.iterdir()}
        self.assertEqual(after_verify, before_verify)
        self.assertEqual(result, verified)
        self.assertEqual(verified["source_commit"], self.source_commit)
        self.assertEqual(verified["release_json_sha256"], prepared["release_json_sha256"])
        self.assertEqual([row["path"] for row in verified["assets"]], sorted(names.values()))

        copied = self.root / "copied-candidate"
        shutil.copytree(self.output, copied)
        self.assertEqual(stage_candidate.verify_candidate(copied, tag), verified)

    def test_bundle_sbom_must_match_its_manifest_hash(self):
        self._prepare()
        self.output = self.root / "modified-output"
        self.payloads["sbom.spdx.json"] = b'{"spdxVersion":"SPDX-2.3","packages":["changed"]}\n'
        (self.bundle / "sbom.spdx.json").write_bytes(self.payloads["sbom.spdx.json"])
        with self.assertRaisesRegex(ValueError, "asset pins differ"):
            stage_candidate.prepare("v1.2.3", self.bundle, self.output)
        self.assertFalse(self.output.exists())

    def test_missing_declared_asset_and_wrong_release_core_are_rejected(self):
        (self.bundle / "sbom.spdx.json").unlink()
        with self.assertRaises(ValueError):
            stage_candidate.prepare("v1.2.3", self.bundle, self.output)
        self.assertFalse(self.output.exists())

        (self.bundle / "sbom.spdx.json").write_bytes(self.payloads["sbom.spdx.json"])
        wrong_output = self.root / "wrong-version"
        with self.assertRaisesRegex(ValueError, "selected production release core"):
            stage_candidate.prepare("v1.2.4-rc.2", self.bundle, wrong_output)
        self.assertFalse(wrong_output.exists())

    def test_rejects_qualification_only_and_noncanonical_source_commit(self):
        self._write_manifest(qualification_only=True)
        with self.assertRaisesRegex(ValueError, "production release core"):
            stage_candidate.prepare("v1.2.3", self.bundle, self.output)

        self._write_manifest(source_commit="A" * 40)
        with self.assertRaisesRegex(ValueError, "canonical lowercase"):
            stage_candidate.prepare("v1.2.3", self.bundle, self.output)
        self.assertFalse(self.output.exists())

    def test_output_must_be_fresh_and_outside_bundle(self):
        existing = self.root / "already-there"
        existing.mkdir()
        marker = existing / "keep.txt"
        marker.write_bytes(b"preserve")
        with self.assertRaisesRegex(ValueError, "must be fresh"):
            stage_candidate.prepare("v1.2.3", self.bundle, existing)
        self.assertEqual(marker.read_bytes(), b"preserve")

        nested = self.bundle / "candidate-output"
        with self.assertRaisesRegex(ValueError, "outside and separate"):
            stage_candidate.prepare("v1.2.3", self.bundle, nested)
        self.assertFalse(nested.exists())

    def test_destination_created_at_install_time_is_never_overwritten(self):
        raced_output = self.root / "raced-output"
        marker = raced_output / "existing.txt"
        original_mkdir = Path.mkdir
        injected = False

        def create_destination_before_mkdir(path, *args, **kwargs):
            nonlocal injected
            if path == raced_output and not injected:
                injected = True
                original_mkdir(path, mode=0o700)
                marker.write_bytes(b"preserve this directory")
            return original_mkdir(path, *args, **kwargs)

        with patch.object(Path, "mkdir", create_destination_before_mkdir):
            with self.assertRaisesRegex(ValueError, "remain fresh"):
                stage_candidate.prepare("v1.2.3", self.bundle, raced_output)
        self.assertTrue(injected)
        self.assertEqual(marker.read_bytes(), b"preserve this directory")
        self.assertEqual({path.name for path in raced_output.iterdir()}, {"existing.txt"})

    def test_finalize_rejects_missing_extra_and_modified_prepared_files(self):
        self._prepare()
        with self.assertRaisesRegex(ValueError, "wrong file set"):
            stage_candidate.finalize(self.output, "v1.2.3")

        self._add_signatures()
        (self.output / "unexpected.txt").write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "wrong file set"):
            stage_candidate.finalize(self.output, "v1.2.3")
        (self.output / "unexpected.txt").unlink()

        names = stage_candidate.asset_names("v1.2.3")
        (self.output / names["sbom"]).write_bytes(b"modified SBOM")
        with self.assertRaisesRegex(ValueError, "copied SBOM differs"):
            stage_candidate.finalize(self.output, "v1.2.3")

    def test_outer_asset_scan_uses_per_file_limits_not_inner_bundle_total(self):
        self._prepare("v1.2.3")
        names = stage_candidate.asset_names("v1.2.3")
        expected = {names[key] for key in ("payload", "sbom", "transport")}
        original_sbom = (self.output / names["sbom"]).read_bytes()
        small_inner_limit = 64
        self.assertLessEqual(len(original_sbom), small_inner_limit)
        outer_total = sum(path.stat().st_size for path in self.output.iterdir())
        self.assertGreater(outer_total, small_inner_limit)

        with patch.object(stage_candidate._TRANSPORT, "MAX_TOTAL_BYTES", small_inner_limit):
            scanned = stage_candidate._scan_candidate_files(self.output, expected, names)
            self.assertGreater(sum(map(len, scanned.values())), small_inner_limit)
            too_large_sbom = b"x" * (small_inner_limit + 1)
            (self.output / names["sbom"]).write_bytes(too_large_sbom)
            try:
                with self.assertRaisesRegex(ValueError, "raw byte limit"):
                    stage_candidate._scan_candidate_files(self.output, expected, names)
            finally:
                (self.output / names["sbom"]).write_bytes(original_sbom)

    def test_finalize_rejects_non_json_or_linked_signature_assets(self):
        self._prepare()
        names = stage_candidate.asset_names("v1.2.3")
        (self.output / names["payload_signature"]).write_bytes(b"not json")
        (self.output / names["transport_signature"]).write_bytes(b"{}\n")
        with self.assertRaisesRegex(ValueError, "valid UTF-8 JSON"):
            stage_candidate.finalize(self.output, "v1.2.3")
        (self.output / names["payload_signature"]).unlink()

        external = self.root / "external-signature.json"
        external.write_bytes(b'{"bundle":"payload"}\n')
        os.link(external, self.output / names["payload_signature"])
        with self.assertRaisesRegex(ValueError, "linked"):
            stage_candidate.finalize(self.output, "v1.2.3")

    def test_verify_rejects_tampered_checksum_and_extra_or_linked_members(self):
        self._prepare("v1.2.3")
        self._add_signatures()
        stage_candidate.finalize(self.output, "v1.2.3")
        names = stage_candidate.asset_names("v1.2.3")

        checksum = self.output / names["checksums"]
        original = checksum.read_bytes()
        checksum.write_bytes(original + b"extra\n")
        with self.assertRaisesRegex(ValueError, "does not match"):
            stage_candidate.verify_candidate(self.output, "v1.2.3")
        checksum.write_bytes(original)

        extra = self.output / "extra.txt"
        extra.write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "wrong file set"):
            stage_candidate.verify_candidate(self.output, "v1.2.3")
        extra.unlink()

        linked = self.root / "linked-checksum"
        linked.write_bytes(original)
        checksum.unlink()
        os.link(linked, checksum)
        with self.assertRaisesRegex(ValueError, "linked"):
            stage_candidate.verify_candidate(self.output, "v1.2.3")

    def test_bundle_symlink_is_rejected_by_canonical_transport_scanner(self):
        (self.bundle / "linked.json").symlink_to(self.bundle / "release.json")
        with self.assertRaisesRegex(ValueError, "symlink or non-regular"):
            stage_candidate.prepare("v1.2.3", self.bundle, self.output)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
