"""Read bounded GNU archives without changing their members or indices."""
from __future__ import annotations

import hashlib


MAX_ARCHIVE_BYTES = 16 * 1024**2
MAX_SYMBOLS = 1_000_000
AR_MAGIC = b"!<arch>\n"


def _decode_ascii(value: bytes, description: str) -> str:
    try:
        return value.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError(f"non-ASCII {description}") from error


def _elf64_x86_64_relocatable(data: bytes) -> bool:
    return (
        len(data) >= 64
        and data[:7] == b"\x7fELF\x02\x01\x01"
        and int.from_bytes(data[16:18], "little") == 1  # ET_REL
        and int.from_bytes(data[18:20], "little") == 62  # EM_X86_64
        and int.from_bytes(data[20:24], "little") == 1  # EV_CURRENT
        and int.from_bytes(data[52:54], "little") == 64  # ELF64 header size
    )


def _resolve_long_name(table: bytes, reference: str) -> str:
    offset_text = reference[1:]
    if not offset_text.isdigit():
        raise ValueError("unsupported GNU archive member name encoding")
    offset = int(offset_text)
    if offset >= len(table) or (offset and table[offset - 1:offset] != b"\n"):
        raise ValueError("GNU long-name reference is not at an entry boundary")
    end = table.find(b"/\n", offset)
    if end < 0:
        raise ValueError("unterminated GNU long archive member name")
    return _decode_ascii(table[offset:end], "GNU long archive member name")


def _symbol_names(payload: bytes, count: int) -> list[str]:
    cursor = 4 + count * 4
    end = len(payload)
    names = []
    for _ in range(count):
        terminator = payload.find(b"\0", cursor)
        if terminator < 0:
            raise ValueError("unterminated GNU archive symbol-index name")
        raw_name = payload[cursor:terminator]
        if not raw_name:
            raise ValueError("empty GNU archive symbol-index name")
        try:
            names.append(raw_name.decode("utf-8"))
        except UnicodeDecodeError as error:
            raise ValueError("invalid UTF-8 GNU archive symbol-index name") from error
        cursor = terminator + 1
    if any(payload[cursor:end]):
        raise ValueError("unexpected data after GNU archive symbol-index names")
    return names


def read_archive(raw: bytes) -> dict:
    """Parse a regular GNU ar archive of ELF64 x86-64 relocatable objects.

    Symbol-index offsets are resolved against member-header offsets and the
    returned member number is the object's ordinal in archive order. Duplicate
    member names therefore remain distinct and unambiguous.
    """
    if not isinstance(raw, bytes) or len(raw) > MAX_ARCHIVE_BYTES or not raw.startswith(AR_MAGIC):
        raise ValueError("expected a bounded complete GNU archive")

    entries = []
    long_name_table = None
    symbol_payload = None
    position = len(AR_MAGIC)

    while position < len(raw):
        header_offset = position
        header = raw[position:position + 60]
        if len(header) != 60 or header[58:60] != b"`\n":
            raise ValueError("invalid GNU archive member header")
        try:
            size_text = header[48:58].strip(b" ")
            if not size_text or any(byte < ord("0") or byte > ord("9") for byte in size_text):
                raise ValueError("non-decimal GNU archive member size")
            stored_size = int(size_text)
            stored_name = header[:16].decode("ascii").rstrip(" ")
        except (ValueError, UnicodeDecodeError) as error:
            raise ValueError("invalid GNU archive member size or name") from error
        if stored_size < 0:
            raise ValueError("negative GNU archive member size")

        data_offset = position + 60
        data_end = data_offset + stored_size
        if data_end > len(raw):
            raise ValueError("truncated GNU archive member")
        data = raw[data_offset:data_end]
        position = data_end
        if stored_size & 1:
            if raw[position:position + 1] != b"\n":
                raise ValueError("invalid GNU archive member padding")
            position += 1

        if stored_name == "//":
            if long_name_table is not None:
                raise ValueError("duplicate GNU archive long-name table")
            long_name_table = data
        elif stored_name == "/":
            if symbol_payload is not None:
                raise ValueError("duplicate GNU archive symbol index")
            symbol_payload = data
        elif stored_name.startswith("/"):
            if long_name_table is None:
                raise ValueError("GNU archive member references a missing long-name table")
            member_name = _resolve_long_name(long_name_table, stored_name)
            entries.append((member_name, header_offset, data))
        else:
            if not stored_name.endswith("/"):
                raise ValueError("unsupported GNU archive member name encoding")
            entries.append((stored_name[:-1], header_offset, data))

    if position != len(raw) or symbol_payload is None or len(symbol_payload) < 4:
        raise ValueError("incomplete GNU archive or missing symbol index")

    count = int.from_bytes(symbol_payload[:4], "big")
    offsets_end = 4 + count * 4
    if count > MAX_SYMBOLS or offsets_end > len(symbol_payload):
        raise ValueError("invalid GNU archive symbol-index count")
    symbol_offsets = [
        int.from_bytes(symbol_payload[4 + 4 * index:8 + 4 * index], "big")
        for index in range(count)
    ]
    symbol_names = _symbol_names(symbol_payload, count)

    members = []
    ordinal_by_header_offset = {}
    for name, header_offset, data in entries:
        if not name or any(character in name for character in ("/", "\\", "\0")) or name in (".", ".."):
            raise ValueError("unsafe GNU archive member name")
        if not _elf64_x86_64_relocatable(data):
            raise ValueError("archive member is not an ELF64 x86-64 relocatable object")
        ordinal_by_header_offset[header_offset] = len(members)
        members.append({
            "name": name,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "data": data,
            "header_offset": header_offset,
        })

    symbols = []
    for name, header_offset in zip(symbol_names, symbol_offsets):
        if header_offset not in ordinal_by_header_offset:
            raise ValueError("GNU archive symbol index refers outside its object headers")
        symbols.append({"name": name, "member": ordinal_by_header_offset[header_offset]})

    return {
        "members": members,
        "symbols": symbols,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
    }
