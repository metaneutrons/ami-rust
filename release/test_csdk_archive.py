"""Synthetic positive and corruption probes for native GNU archive readback."""
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location("ar_test", Path(__file__).with_name("csdk_archive.py"))
ar = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ar)


def entry(name, data):
    header = (
        f"{name:<16}{0:<12}{0:<6}{0:<6}{0o644:<8o}{len(data):<10}`\n"
    ).encode("ascii")
    if len(header) != 60:
        raise ValueError("synthetic archive member header is not 60 bytes")
    return header + data + (b"\n" if len(data) & 1 else b"")


def elf_object(machine=62, extra=b""):
    elf = bytearray(64)
    elf[:7] = b"\x7fELF\x02\x01\x01"
    elf[16:18] = (1).to_bytes(2, "little")
    elf[18:20] = machine.to_bytes(2, "little")
    elf[20:24] = (1).to_bytes(4, "little")
    elf[52:54] = (64).to_bytes(2, "little")
    return bytes(elf) + extra


def archive(members=None, symbols=None, index_payload_factory=None):
    if members is None:
        members = [("unit.o", elf_object())]
    if symbols is None:
        symbols = [("foo", 0)]

    long_names = bytearray()
    encoded_names = []
    for name, _ in members:
        encoded = name.encode("ascii")
        if len(encoded) > 15:
            encoded_names.append(f"/{len(long_names)}")
            long_names.extend(encoded + b"/\n")
        else:
            encoded_names.append(name + "/")

    if index_payload_factory is None:
        def index_payload_factory(offsets):
            return (
                len(symbols).to_bytes(4, "big")
                + b"".join(offsets[ordinal].to_bytes(4, "big") for _, ordinal in symbols)
                + b"".join(name.encode("ascii") + b"\0" for name, _ in symbols)
            )

    placeholder = index_payload_factory([0] * len(members))
    index_size = len(entry("/", placeholder))
    table_data = bytes(long_names)
    table_member = entry("//", table_data) if table_data else b""
    member_offsets = []
    position = len(b"!<arch>\n") + index_size + len(table_member)
    for name, data in zip(encoded_names, (data for _, data in members)):
        member_offsets.append(position)
        position += len(entry(name, data))
    index_payload = index_payload_factory(member_offsets)
    if len(entry("/", index_payload)) != index_size:
        raise ValueError("synthetic symbol-index size changed after offset calculation")

    raw = b"!<arch>\n" + entry("/", index_payload) + table_member
    for name, (_, data) in zip(encoded_names, members):
        raw += entry(name, data)
    return raw, member_offsets


class ArchiveTests(unittest.TestCase):
    def test_long_names_duplicate_basenames_and_exact_member_ordinals(self):
        members = [
            ("very_long_gnu_archive_member_name.o", elf_object()),
            ("duplicate.o", elf_object(extra=b"\0")),
            ("duplicate.o", elf_object()),
        ]
        symbols = [("long_member_symbol", 0), ("first_duplicate_symbol", 1), ("second_duplicate_symbol", 2)]
        raw, offsets = archive(members, symbols)

        parsed = ar.read_archive(raw)

        self.assertEqual([member["name"] for member in parsed["members"]], [name for name, _ in members])
        self.assertEqual([member["header_offset"] for member in parsed["members"]], offsets)
        self.assertEqual(
            parsed["symbols"],
            [
                {"name": "long_member_symbol", "member": 0},
                {"name": "first_duplicate_symbol", "member": 1},
                {"name": "second_duplicate_symbol", "member": 2},
            ],
        )
        self.assertEqual(parsed["members"][1]["bytes"], 65)
        self.assertEqual(raw[offsets[1] + 60 + 65:offsets[1] + 60 + 66], b"\n")
        self.assertEqual(parsed["members"][1]["data"], members[1][1])

    def test_truncated_members_foreign_machine_and_bad_odd_padding_fail(self):
        members = [("odd.o", elf_object(extra=b"\0")), ("unit.o", elf_object())]
        raw, offsets = archive(members, [("foo", 0)])
        bad_padding = bytearray(raw)
        bad_padding[offsets[0] + 60 + len(members[0][1])] = 0
        for candidate in (raw[:-1], archive([("unit.o", elf_object(machine=183))])[0], b"!<thin>\n", bytes(bad_padding)):
            with self.subTest(candidate_prefix=candidate[:8]):
                with self.assertRaises(ValueError):
                    ar.read_archive(candidate)

    def test_malformed_symbol_indices_fail(self):
        members = [("unit.o", elf_object())]
        malformed_factories = [
            lambda offsets: (1).to_bytes(4, "big") + (offsets[0] + 1).to_bytes(4, "big") + b"foo\0",
            lambda offsets: (2).to_bytes(4, "big") + offsets[0].to_bytes(4, "big"),
            lambda offsets: (1).to_bytes(4, "big") + offsets[0].to_bytes(4, "big") + b"foo\0extra\0",
            lambda offsets: (1).to_bytes(4, "big") + offsets[0].to_bytes(4, "big") + b"foo",
        ]
        for factory in malformed_factories:
            raw, _ = archive(members, [], factory)
            with self.subTest(index_size=len(raw)):
                with self.assertRaises(ValueError):
                    ar.read_archive(raw)


if __name__ == "__main__":
    unittest.main()
