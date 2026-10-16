#!/usr/bin/env python3
"""Regression tests for the published Cargo notice source capsule index."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tarfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
CAPSULE = ROOT / "release/cargo-notices/payload-v3"
ARCHIVE = CAPSULE / "cargo-notices-corresponding-source-v3.tar.xz"
INVENTORY = CAPSULE / "inventory.json"
BUNDLE_FILES = ROOT / "release/bundle-files.json"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_archive(archive_path: Path) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    with tarfile.open(archive_path, "r:xz") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                raise AssertionError(f"non-regular archive member: {member.name}")
            if member.name in members:
                raise AssertionError(f"duplicate archive member: {member.name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise AssertionError(f"cannot read archive member: {member.name}")
            members[member.name] = stream.read()
    return members


def validate_inventory(index: dict[str, object], members: dict[str, bytes]) -> None:
    rows = index.get("files")
    if not isinstance(rows, list):
        raise AssertionError("inventory files must be a list")
    paths = [row.get("path") for row in rows if isinstance(row, dict)]
    if len(paths) != len(rows):
        raise AssertionError("inventory file rows must be objects")
    if "inventory.json" in paths:
        raise AssertionError("inventory.json must be excluded from its own files list")
    if len(paths) != len(set(paths)):
        raise AssertionError("inventory contains duplicate paths")
    if set(members) != set(paths) | {"inventory.json"}:
        raise AssertionError("archive member set differs from inventory files plus inventory.json")

    expanded_bytes = sum(row.get("bytes", -1) for row in rows)
    if index.get("expanded_bytes_before_inventory") != expanded_bytes:
        raise AssertionError("expanded_bytes_before_inventory differs from listed member bytes")

    for row in rows:
        path = row["path"]
        data = members[path]
        if row.get("bytes") != len(data):
            raise AssertionError(f"byte count mismatch for {path}")
        if row.get("sha256") != sha256(data):
            raise AssertionError(f"SHA-256 mismatch for {path}")


class CargoNoticeInventoryTests(unittest.TestCase):
    def setUp(self):
        self.members = read_archive(ARCHIVE)
        self.external_inventory_bytes = INVENTORY.read_bytes()
        self.index = json.loads(self.external_inventory_bytes)

    def test_actual_archive_matches_external_inventory_and_bundle_manifest(self):
        self.assertEqual(self.members["inventory.json"], self.external_inventory_bytes)
        validate_inventory(self.index, self.members)
        self.assertEqual(len(self.index["files"]), 2671)
        self.assertEqual(len(self.members), 2672)
        self.assertEqual(self.index["expanded_bytes_before_inventory"], 16772015)
        self.assertTrue(any(
            "excluded from its own files list" in item and "release/bundle-files.json" in item
            for item in self.index["limitations"]
        ))

        manifest = json.loads(BUNDLE_FILES.read_text(encoding="utf-8"))
        expected = {
            "cargo-notices-corresponding-source.tar.xz": ARCHIVE,
            "cargo-source-inventory.json": INVENTORY,
        }
        for path, source in expected.items():
            with self.subTest(path=path):
                rows = [row for row in manifest["files"] if row["path"] == path]
                data = source.read_bytes()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["bytes"], len(data))
                self.assertEqual(rows[0]["sha256"], sha256(data))

    def test_counterprobes_reject_stale_self_entry_missing_member_and_changed_bytes(self):
        stale_self_entry = copy.deepcopy(self.index)
        stale_self_entry["files"].append({
            "bytes": 821751,
            "path": "inventory.json",
            "sha256": "08992f320827cdbd60bda452c80b853d9e4519417745538faa7910e1777ab6d1",
        })
        with self.assertRaisesRegex(AssertionError, "excluded from its own files list"):
            validate_inventory(stale_self_entry, self.members)

        missing_member = copy.deepcopy(self.index)
        missing_member["files"] = missing_member["files"][1:]
        with self.assertRaisesRegex(AssertionError, "member set differs"):
            validate_inventory(missing_member, self.members)

        changed_bytes = self.members.copy()
        path = self.index["files"][0]["path"]
        original = changed_bytes[path]
        changed_bytes[path] = bytes([original[0] ^ 1]) + original[1:]
        with self.assertRaisesRegex(AssertionError, "SHA-256 mismatch"):
            validate_inventory(self.index, changed_bytes)


if __name__ == "__main__":
    unittest.main(verbosity=2)
