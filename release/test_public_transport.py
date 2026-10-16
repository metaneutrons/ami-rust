#!/usr/bin/env python3
"""Focused fixtures for deterministic candidate transport and safe readback."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import lzma
import os
from pathlib import Path
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("public_transport.py")
SPEC = importlib.util.spec_from_file_location("r1_public_transport_fixture_target", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
public_transport = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(public_transport)


class PublicTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="public-transport-test-")
        self.root = Path(self.temp.name).resolve()
        self.bundle = self.root / "candidate"
        self.bundle.mkdir()
        (self.bundle / ".auth").write_bytes(b"authenticated candidate bytes\x00\xff")
        notices = self.bundle / "notices"
        notices.mkdir()
        (notices / "LICENSE.txt").write_bytes(b"first notice\r\nsecond notice\r\n")
        (self.bundle / "release.json").write_bytes(b'{"version":"0.1.0"}\n')
        self.archive = self.root / "candidate.tar.xz"

    def tearDown(self):
        self.temp.cleanup()

    def _pack(self):
        return public_transport.pack_bundle(self.bundle, self.archive)

    def _make_tar(self, rows, *, mtime=public_transport.TAR_MTIME):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT,
                          encoding="ascii", errors="strict") as archive:
            for name, data, member_type, linkname in rows:
                info = tarfile.TarInfo(name)
                info.type = member_type
                info.mode = 0o644
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = mtime
                info.linkname = linkname
                info.size = len(data) if member_type == tarfile.REGTYPE else 0
                info.devmajor = 0
                info.devminor = 0
                info.pax_headers = {}
                archive.addfile(info, io.BytesIO(data) if info.size else None)
        return output.getvalue()

    def _repin_archive(self, original_record, data):
        self.archive.write_bytes(data)
        record = dict(original_record)
        record["archive"]["bytes"] = len(data)
        record["archive"]["sha256"] = hashlib.sha256(data).hexdigest()
        return record

    def _assert_rejected_without_output(self, record, *, archive_data=None):
        if archive_data is not None:
            record = self._repin_archive(record, archive_data)
        before = self.archive.read_bytes()
        destination = self.root / "readback"
        with self.assertRaises(ValueError):
            public_transport.unpack_bundle(self.archive, record, destination)
        self.assertFalse(destination.exists())
        self.assertEqual(self.archive.read_bytes(), before)
        self.assertEqual(list(self.root.glob(".readback.stage-*")), [])

    def test_round_trip_preserves_hidden_and_crlf_files_and_repacks_stably(self):
        record = self._pack()
        self.assertEqual([row["path"] for row in record["files"]],
                         [".auth", "notices/LICENSE.txt", "release.json"])
        self.assertEqual(record["archive"]["bytes"], self.archive.stat().st_size)
        self.assertEqual(record["archive"]["sha256"], hashlib.sha256(self.archive.read_bytes()).hexdigest())

        destination = self.root / "readback"
        receipt = public_transport.unpack_bundle(self.archive, record, destination)
        self.assertEqual(receipt, record)
        for relative in (".auth", "notices/LICENSE.txt", "release.json"):
            self.assertEqual((destination / relative).read_bytes(), (self.bundle / relative).read_bytes())
        self.assertIn(b"\r\n", (destination / "notices/LICENSE.txt").read_bytes())

        second_archive = self.root / "repacked.tar.xz"
        second_record = public_transport.pack_bundle(destination, second_archive)
        self.assertEqual(second_record["files"], record["files"])
        self.assertEqual(second_record["archive"]["bytes"], record["archive"]["bytes"])
        self.assertEqual(second_record["archive"]["sha256"], record["archive"]["sha256"])
        self.assertEqual(second_archive.read_bytes(), self.archive.read_bytes())

    def test_changed_archive_pin_is_rejected_before_readback(self):
        record = self._pack()
        original = self.archive.read_bytes()
        self.archive.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        changed = self.archive.read_bytes()
        destination = self.root / "readback"
        with self.assertRaises(ValueError):
            public_transport.unpack_bundle(self.archive, record, destination)
        self.assertFalse(destination.exists())
        self.assertEqual(self.archive.read_bytes(), changed)

    def test_changed_member_pin_is_rejected(self):
        record = self._pack()
        changed_digest = {**record, "files": [dict(row) for row in record["files"]]}
        changed_digest["files"][1]["sha256"] = "0" * 64
        self._assert_rejected_without_output(changed_digest)
        changed_size = {**record, "files": [dict(row) for row in record["files"]]}
        changed_size["files"][1]["bytes"] += 1
        self._assert_rejected_without_output(changed_size)

    def test_duplicate_member_is_rejected(self):
        record = self._pack()
        data = self._make_tar([
            (".auth", b"one", tarfile.REGTYPE, ""),
            (".auth", b"two", tarfile.REGTYPE, ""),
        ])
        self._assert_rejected_without_output(record, archive_data=lzma.compress(data, format=lzma.FORMAT_XZ))

    def test_traversal_member_is_rejected(self):
        record = self._pack()
        data = self._make_tar([("../escape", b"outside", tarfile.REGTYPE, "")])
        self._assert_rejected_without_output(record, archive_data=lzma.compress(data, format=lzma.FORMAT_XZ))
        self.assertFalse((self.root.parent / "escape").exists())

    def test_link_member_is_rejected(self):
        record = self._pack()
        data = self._make_tar([(".auth", b"", tarfile.SYMTYPE, "../outside")])
        self._assert_rejected_without_output(record, archive_data=lzma.compress(data, format=lzma.FORMAT_XZ))

    def test_extra_and_missing_members_are_rejected(self):
        record = self._pack()
        extra = self._make_tar([
            (".auth", b"x", tarfile.REGTYPE, ""),
            ("extra", b"x", tarfile.REGTYPE, ""),
        ])
        self._assert_rejected_without_output(record, archive_data=lzma.compress(extra, format=lzma.FORMAT_XZ))
        missing = self._make_tar([(".auth", b"x", tarfile.REGTYPE, "")])
        self._assert_rejected_without_output(record, archive_data=lzma.compress(missing, format=lzma.FORMAT_XZ))

    def test_noncanonical_tar_metadata_is_rejected(self):
        record = self._pack()
        data = self._make_tar(
            [(".auth", b"authenticated candidate bytes\x00\xff", tarfile.REGTYPE, "")],
            mtime=public_transport.TAR_MTIME + 1,
        )
        self._assert_rejected_without_output(record, archive_data=lzma.compress(data, format=lzma.FORMAT_XZ))

    def test_trailing_and_concatenated_xz_streams_are_rejected(self):
        record = self._pack()
        valid_tar = self._make_tar([
            (".auth", b"authenticated candidate bytes\x00\xff", tarfile.REGTYPE, ""),
            ("notices/LICENSE.txt", b"first notice\r\nsecond notice\r\n", tarfile.REGTYPE, ""),
            ("release.json", b'{"version":"0.1.0"}\n', tarfile.REGTYPE, ""),
        ])
        stream = lzma.compress(valid_tar, format=lzma.FORMAT_XZ)
        self._assert_rejected_without_output(record, archive_data=stream + b"trailing")
        self._assert_rejected_without_output(record, archive_data=stream + lzma.compress(b"", format=lzma.FORMAT_XZ))

    def test_pack_refuses_symlink_and_hardlinked_files(self):
        symlink_bundle = self.root / "symlink-bundle"
        symlink_bundle.mkdir()
        (symlink_bundle / "external").symlink_to(self.bundle / ".auth")
        with self.assertRaises(ValueError):
            public_transport.pack_bundle(symlink_bundle, self.root / "symlink.tar.xz")
        self.assertFalse((self.root / "symlink.tar.xz").exists())

        linked_bundle = self.root / "linked-bundle"
        linked_bundle.mkdir()
        external = self.root / "outside.txt"
        external.write_bytes(b"linked")
        os.link(external, linked_bundle / "candidate.txt")
        with self.assertRaises(ValueError):
            public_transport.pack_bundle(linked_bundle, self.root / "linked.tar.xz")
        self.assertFalse((self.root / "linked.tar.xz").exists())

    def test_pack_keeps_the_existing_file_and_raw_byte_limits(self):
        many = self.root / "many"
        many.mkdir()
        for index in range(public_transport.MAX_FILES + 1):
            (many / f"f{index:03}.txt").touch()
        with self.assertRaises(ValueError):
            public_transport.pack_bundle(many, self.root / "many.tar.xz")
        self.assertFalse((self.root / "many.tar.xz").exists())

        oversized = self.root / "oversized"
        oversized.mkdir()
        with (oversized / "large.bin").open("wb") as stream:
            stream.truncate(public_transport.MAX_TOTAL_BYTES + 1)
        with self.assertRaises(ValueError):
            public_transport.pack_bundle(oversized, self.root / "oversized.tar.xz")
        self.assertFalse((self.root / "oversized.tar.xz").exists())


if __name__ == "__main__":
    unittest.main()
