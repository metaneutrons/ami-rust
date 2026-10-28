//! Bounded readback for regular GNU `ar` archives containing ELF objects.
//!
//! The parser retains the original archive and borrows member payloads from it.
//! It validates the GNU symbol index against exact object-header offsets and
//! never rewrites archive bytes or metadata.

use std::collections::HashMap;

use crate::{Refusal, Result, digest::sha256_bytes};

pub const MAX_ARCHIVE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SYMBOLS: usize = 1_000_000;

const AR_MAGIC: &[u8; 8] = b"!<arch>\n";
const HEADER_BYTES: usize = 60;

/// One ordinary object member in archive order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveMember<'a> {
    /// Decoded ASCII archive member name.
    pub name: String,
    /// Length of the unmodified object payload.
    pub bytes: usize,
    /// Lowercase SHA-256 of the unmodified object payload.
    pub sha256: String,
    /// Borrowed object payload from the original archive.
    pub data: &'a [u8],
    /// Byte offset of this member's 60-byte archive header.
    pub header_offset: usize,
}

/// One symbol-index row, bound to an object member ordinal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveSymbol {
    /// UTF-8 symbol name as stored in the GNU index.
    pub name: String,
    /// Zero-based ordinal among ordinary object members.
    pub member: usize,
}

/// Validated archive identity and its borrowed object and symbol rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Archive<'a> {
    pub members: Vec<ArchiveMember<'a>>,
    pub symbols: Vec<ArchiveSymbol>,
    /// Lowercase SHA-256 of every original archive byte.
    pub sha256: String,
    /// Exact original archive length.
    pub bytes: usize,
    /// The original archive bytes, unchanged.
    pub raw_bytes: &'a [u8],
}

struct PendingMember<'a> {
    name: String,
    header_offset: usize,
    data: &'a [u8],
}

/// Parse a complete, bounded GNU archive of ELF64 little-endian x86-64
/// relocatable objects. Index offsets are resolved to exact object-header
/// positions, so duplicate basenames remain distinct members.
pub fn read_archive(raw: &[u8]) -> Result<Archive<'_>> {
    if raw.len() > MAX_ARCHIVE_BYTES || !raw.starts_with(AR_MAGIC) {
        return Err(Refusal::new("expected a bounded complete GNU archive"));
    }

    let mut position = AR_MAGIC.len();
    let mut members = Vec::new();
    let mut long_name_table: Option<&[u8]> = None;
    let mut symbol_payload: Option<&[u8]> = None;

    while position < raw.len() {
        let header_offset = position;
        let header_end = position
            .checked_add(HEADER_BYTES)
            .ok_or_else(|| Refusal::new("GNU archive member header offset overflow"))?;
        let header = raw
            .get(position..header_end)
            .ok_or_else(|| Refusal::new("invalid GNU archive member header"))?;
        if header.get(58..60) != Some(b"`\n".as_slice()) {
            return Err(Refusal::new("invalid GNU archive member header"));
        }

        let size_field = header
            .get(48..58)
            .ok_or_else(|| Refusal::new("invalid GNU archive member size"))?;
        let size_start = size_field
            .iter()
            .position(|byte| *byte != b' ')
            .unwrap_or(size_field.len());
        if size_start == size_field.len() {
            return Err(Refusal::new("non-decimal GNU archive member size"));
        }
        let size_end = size_field
            .iter()
            .rposition(|byte| *byte != b' ')
            .ok_or_else(|| Refusal::new("non-decimal GNU archive member size"))?;
        let size_text = size_field
            .get(size_start..=size_end)
            .ok_or_else(|| Refusal::new("non-decimal GNU archive member size"))?;
        let mut stored_size = 0_usize;
        for byte in size_text {
            if !byte.is_ascii_digit() {
                return Err(Refusal::new("non-decimal GNU archive member size"));
            }
            stored_size = stored_size
                .checked_mul(10)
                .and_then(|size| size.checked_add(usize::from(*byte - b'0')))
                .ok_or_else(|| Refusal::new("GNU archive member size overflow"))?;
        }

        let name_field = header
            .get(..16)
            .ok_or_else(|| Refusal::new("invalid GNU archive member name"))?;
        let mut name_end = name_field.len();
        while name_end > 0 && name_field.get(name_end - 1) == Some(&b' ') {
            name_end -= 1;
        }
        let stored_name_bytes = name_field
            .get(..name_end)
            .ok_or_else(|| Refusal::new("invalid GNU archive member name"))?;
        if !stored_name_bytes.is_ascii() {
            return Err(Refusal::new("non-ASCII GNU archive member name"));
        }
        let stored_name = std::str::from_utf8(stored_name_bytes)
            .map_err(|_| Refusal::new("non-ASCII GNU archive member name"))?;

        let data_start = header_end;
        let data_end = data_start
            .checked_add(stored_size)
            .ok_or_else(|| Refusal::new("GNU archive member end offset overflow"))?;
        let data = raw
            .get(data_start..data_end)
            .ok_or_else(|| Refusal::new("truncated GNU archive member"))?;
        let next_position = if stored_size & 1 == 1 {
            let padded_end = data_end
                .checked_add(1)
                .ok_or_else(|| Refusal::new("GNU archive padding offset overflow"))?;
            if raw.get(data_end..padded_end) != Some(b"\n".as_slice()) {
                return Err(Refusal::new("invalid GNU archive member padding"));
            }
            padded_end
        } else {
            data_end
        };

        if stored_name == "//" {
            if long_name_table.is_some() {
                return Err(Refusal::new("duplicate GNU archive long-name table"));
            }
            long_name_table = Some(data);
        } else if stored_name == "/" {
            if symbol_payload.is_some() {
                return Err(Refusal::new("duplicate GNU archive symbol index"));
            }
            symbol_payload = Some(data);
        } else if stored_name.starts_with('/') {
            let table = long_name_table.ok_or_else(|| {
                Refusal::new("GNU archive member references a missing long-name table")
            })?;
            let name = resolve_long_name(table, stored_name)?;
            members.push(PendingMember {
                name,
                header_offset,
                data,
            });
        } else {
            let name = stored_name
                .strip_suffix('/')
                .ok_or_else(|| Refusal::new("unsupported GNU archive member name encoding"))?;
            members.push(PendingMember {
                name: name.to_owned(),
                header_offset,
                data,
            });
        }

        position = next_position;
    }

    let symbol_payload = symbol_payload
        .ok_or_else(|| Refusal::new("incomplete GNU archive or missing symbol index"))?;
    if position != raw.len() || symbol_payload.len() < 4 {
        return Err(Refusal::new(
            "incomplete GNU archive or missing symbol index",
        ));
    }
    let count_bytes = symbol_payload
        .get(..4)
        .ok_or_else(|| Refusal::new("invalid GNU archive symbol-index count"))?;
    let symbol_count_u32 = u32::from_be_bytes([
        count_bytes[0],
        count_bytes[1],
        count_bytes[2],
        count_bytes[3],
    ]);
    let symbol_count = usize::try_from(symbol_count_u32)
        .map_err(|_| Refusal::new("invalid GNU archive symbol-index count"))?;
    let offsets_bytes = symbol_count
        .checked_mul(4)
        .ok_or_else(|| Refusal::new("invalid GNU archive symbol-index count"))?;
    let offsets_end = 4_usize
        .checked_add(offsets_bytes)
        .ok_or_else(|| Refusal::new("invalid GNU archive symbol-index count"))?;
    if symbol_count > MAX_SYMBOLS || offsets_end > symbol_payload.len() {
        return Err(Refusal::new("invalid GNU archive symbol-index count"));
    }

    let symbol_names = parse_symbol_names(symbol_payload, symbol_count, offsets_end)?;
    let mut symbol_offsets = Vec::with_capacity(symbol_count);
    for index in 0..symbol_count {
        let field_start = 4_usize
            .checked_add(
                index
                    .checked_mul(4)
                    .ok_or_else(|| Refusal::new("GNU archive symbol-index offset overflow"))?,
            )
            .ok_or_else(|| Refusal::new("GNU archive symbol-index offset overflow"))?;
        let field_end = field_start
            .checked_add(4)
            .ok_or_else(|| Refusal::new("GNU archive symbol-index offset overflow"))?;
        let field = symbol_payload
            .get(field_start..field_end)
            .ok_or_else(|| Refusal::new("invalid GNU archive symbol-index count"))?;
        let offset_u32 = u32::from_be_bytes([field[0], field[1], field[2], field[3]]);
        symbol_offsets.push(
            usize::try_from(offset_u32)
                .map_err(|_| Refusal::new("invalid GNU archive symbol-index offset"))?,
        );
    }

    let mut ordinal_by_header_offset = HashMap::with_capacity(members.len());
    let mut parsed_members = Vec::with_capacity(members.len());
    for pending in members {
        if !is_safe_member_name(&pending.name) {
            return Err(Refusal::new("unsafe GNU archive member name"));
        }
        if !is_elf64_x86_64_relocatable(pending.data) {
            return Err(Refusal::new(
                "archive member is not an ELF64 x86-64 relocatable object",
            ));
        }
        let ordinal = parsed_members.len();
        ordinal_by_header_offset.insert(pending.header_offset, ordinal);
        parsed_members.push(ArchiveMember {
            name: pending.name,
            bytes: pending.data.len(),
            sha256: sha256_bytes(pending.data),
            data: pending.data,
            header_offset: pending.header_offset,
        });
    }

    let mut symbols = Vec::with_capacity(symbol_count);
    for (name, header_offset) in symbol_names.into_iter().zip(symbol_offsets) {
        let member = ordinal_by_header_offset
            .get(&header_offset)
            .copied()
            .ok_or_else(|| {
                Refusal::new("GNU archive symbol index refers outside its object headers")
            })?;
        symbols.push(ArchiveSymbol { name, member });
    }

    Ok(Archive {
        members: parsed_members,
        symbols,
        sha256: sha256_bytes(raw),
        bytes: raw.len(),
        raw_bytes: raw,
    })
}

fn resolve_long_name(table: &[u8], reference: &str) -> Result<String> {
    let offset_text = reference
        .strip_prefix('/')
        .ok_or_else(|| Refusal::new("unsupported GNU archive member name encoding"))?;
    if offset_text.is_empty() || !offset_text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Refusal::new("unsupported GNU archive member name encoding"));
    }
    let mut offset = 0_usize;
    for byte in offset_text.bytes() {
        offset = offset
            .checked_mul(10)
            .and_then(|value| value.checked_add(usize::from(byte - b'0')))
            .ok_or_else(|| Refusal::new("GNU long-name reference offset overflow"))?;
    }
    if offset >= table.len() || (offset > 0 && table.get(offset - 1) != Some(&b'\n')) {
        return Err(Refusal::new(
            "GNU long-name reference is not at an entry boundary",
        ));
    }
    let tail = table
        .get(offset..)
        .ok_or_else(|| Refusal::new("GNU long-name reference is outside its table"))?;
    let terminator = tail
        .windows(2)
        .position(|window| window == b"/\n")
        .ok_or_else(|| Refusal::new("unterminated GNU long archive member name"))?;
    let name = tail
        .get(..terminator)
        .ok_or_else(|| Refusal::new("unterminated GNU long archive member name"))?;
    if !name.is_ascii() {
        return Err(Refusal::new("non-ASCII GNU long archive member name"));
    }
    String::from_utf8(name.to_vec())
        .map_err(|_| Refusal::new("non-ASCII GNU long archive member name"))
}

fn parse_symbol_names(payload: &[u8], count: usize, mut cursor: usize) -> Result<Vec<String>> {
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        let tail = payload
            .get(cursor..)
            .ok_or_else(|| Refusal::new("unterminated GNU archive symbol-index name"))?;
        let terminator = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| Refusal::new("unterminated GNU archive symbol-index name"))?;
        if terminator == 0 {
            return Err(Refusal::new("empty GNU archive symbol-index name"));
        }
        let end = cursor
            .checked_add(terminator)
            .ok_or_else(|| Refusal::new("GNU archive symbol-index name offset overflow"))?;
        let raw_name = payload
            .get(cursor..end)
            .ok_or_else(|| Refusal::new("unterminated GNU archive symbol-index name"))?;
        let name = String::from_utf8(raw_name.to_vec())
            .map_err(|_| Refusal::new("invalid UTF-8 GNU archive symbol-index name"))?;
        names.push(name);
        cursor = end
            .checked_add(1)
            .ok_or_else(|| Refusal::new("GNU archive symbol-index name offset overflow"))?;
    }
    let padding = payload
        .get(cursor..)
        .ok_or_else(|| Refusal::new("unexpected data after GNU archive symbol-index names"))?;
    if padding.iter().any(|byte| *byte != 0) {
        return Err(Refusal::new(
            "unexpected data after GNU archive symbol-index names",
        ));
    }
    Ok(names)
}

fn is_safe_member_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name
            .chars()
            .any(|character| matches!(character, '/' | '\\' | '\0'))
}

fn is_elf64_x86_64_relocatable(data: &[u8]) -> bool {
    data.len() >= 64
        && data.get(..7) == Some(b"\x7fELF\x02\x01\x01".as_slice())
        && read_u16_le(data, 16) == Some(1) // ET_REL
        && read_u16_le(data, 18) == Some(62) // EM_X86_64
        && read_u32_le(data, 20) == Some(1) // EV_CURRENT
        && read_u16_le(data, 52) == Some(64) // ELF64 header size
}

fn read_u16_le(data: &[u8], start: usize) -> Option<u16> {
    let field = data.get(start..start.checked_add(2)?)?;
    Some(u16::from_le_bytes([*field.first()?, *field.get(1)?]))
}

fn read_u32_le(data: &[u8], start: usize) -> Option<u32> {
    let field = data.get(start..start.checked_add(4)?)?;
    Some(u32::from_le_bytes([
        *field.first()?,
        *field.get(1)?,
        *field.get(2)?,
        *field.get(3)?,
    ]))
}

#[cfg(test)]
mod tests {
    use super::{Archive, MAX_ARCHIVE_BYTES, MAX_SYMBOLS, read_archive};
    use crate::digest::sha256_bytes;

    const MAGIC: &[u8; 8] = b"!<arch>\n";

    fn entry(name: &str, data: &[u8]) -> Vec<u8> {
        let mode = format!("{:o}", 0o644);
        let header = format!(
            "{name:<16}{:<12}{:<6}{:<6}{mode:<8}{:<10}`\n",
            0,
            0,
            0,
            data.len()
        );
        assert_eq!(header.len(), 60);
        let mut result = header.into_bytes();
        result.extend_from_slice(data);
        if data.len() & 1 == 1 {
            result.push(b'\n');
        }
        result
    }

    fn elf_object(machine: u16, extra: &[u8]) -> Vec<u8> {
        let mut elf = vec![0_u8; 64];
        elf[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        elf[16..18].copy_from_slice(&1_u16.to_le_bytes());
        elf[18..20].copy_from_slice(&machine.to_le_bytes());
        elf[20..24].copy_from_slice(&1_u32.to_le_bytes());
        elf[52..54].copy_from_slice(&64_u16.to_le_bytes());
        elf.extend_from_slice(extra);
        elf
    }

    fn build_archive_with_index(
        members: &[(&str, Vec<u8>)],
        index_factory: impl Fn(&[usize]) -> Vec<u8>,
    ) -> (Vec<u8>, Vec<usize>) {
        let mut long_names = Vec::new();
        let mut encoded_names = Vec::with_capacity(members.len());
        for (name, _) in members {
            if name.len() > 15 {
                encoded_names.push(format!("/{}", long_names.len()));
                long_names.extend_from_slice(name.as_bytes());
                long_names.extend_from_slice(b"/\n");
            } else {
                encoded_names.push(format!("{name}/"));
            }
        }

        let placeholders = vec![0; members.len()];
        let placeholder = index_factory(&placeholders);
        let index_entry = entry("/", &placeholder);
        let table_entry = if long_names.is_empty() {
            Vec::new()
        } else {
            entry("//", &long_names)
        };
        let mut offsets = Vec::with_capacity(members.len());
        let mut position = MAGIC.len() + index_entry.len() + table_entry.len();
        for (encoded_name, (_, data)) in encoded_names.iter().zip(members.iter()) {
            offsets.push(position);
            position += entry(encoded_name, data).len();
        }

        let index_payload = index_factory(&offsets);
        assert_eq!(index_payload.len(), placeholder.len());
        let mut raw = MAGIC.to_vec();
        raw.extend_from_slice(&entry("/", &index_payload));
        raw.extend_from_slice(&table_entry);
        for (encoded_name, (_, data)) in encoded_names.iter().zip(members.iter()) {
            raw.extend_from_slice(&entry(encoded_name, data));
        }
        (raw, offsets)
    }

    fn archive(members: &[(&str, Vec<u8>)], symbols: &[(&str, usize)]) -> (Vec<u8>, Vec<usize>) {
        build_archive_with_index(members, |offsets| {
            let mut payload = u32::try_from(symbols.len()).unwrap().to_be_bytes().to_vec();
            for (_, ordinal) in symbols {
                let offset = u32::try_from(offsets[*ordinal]).unwrap();
                payload.extend_from_slice(&offset.to_be_bytes());
            }
            for (name, _) in symbols {
                payload.extend_from_slice(name.as_bytes());
                payload.push(0);
            }
            payload
        })
    }

    fn parse(raw: &[u8]) -> crate::Result<Archive<'_>> {
        read_archive(raw)
    }

    #[test]
    fn resolves_long_names_duplicate_basenames_and_exact_member_ordinals() {
        let objects = [
            elf_object(62, &[]),
            elf_object(62, &[0]),
            elf_object(62, &[]),
        ];
        let names = [
            "very_long_gnu_archive_member_name.o",
            "duplicate.o",
            "duplicate.o",
        ];
        let symbols = [
            ("long_member_symbol", 0),
            ("first_duplicate_symbol", 1),
            ("second_duplicate_symbol", 2),
        ];
        let member_specs = names
            .iter()
            .copied()
            .zip(objects.iter().cloned())
            .collect::<Vec<_>>();
        let (raw, offsets) = archive(&member_specs, &symbols);

        let parsed = parse(&raw).unwrap();
        assert_eq!(parsed.raw_bytes, raw);
        assert_eq!(parsed.bytes, raw.len());
        assert_eq!(parsed.sha256, sha256_bytes(&raw));
        assert_eq!(
            parsed
                .members
                .iter()
                .map(|member| member.name.as_str())
                .collect::<Vec<_>>(),
            names
        );
        assert_eq!(
            parsed
                .members
                .iter()
                .map(|member| member.header_offset)
                .collect::<Vec<_>>(),
            offsets
        );
        assert_eq!(parsed.members[1].bytes, 65);
        assert_eq!(parsed.members[1].data, objects[1]);
        assert_eq!(parsed.members[1].sha256, sha256_bytes(&objects[1]));
        assert_eq!(
            parsed
                .symbols
                .iter()
                .map(|symbol| (symbol.name.as_str(), symbol.member))
                .collect::<Vec<_>>(),
            vec![
                ("long_member_symbol", 0),
                ("first_duplicate_symbol", 1),
                ("second_duplicate_symbol", 2),
            ]
        );
        assert_eq!(
            raw.get(offsets[1] + 60 + 65..offsets[1] + 60 + 66),
            Some(b"\n".as_slice())
        );
    }

    #[test]
    fn rejects_truncation_foreign_machine_bad_padding_and_thin_archives() {
        let objects = [elf_object(62, &[0]), elf_object(62, &[])];
        let (raw, offsets) = archive(
            &[
                ("odd.o", objects[0].clone()),
                ("unit.o", objects[1].clone()),
            ],
            &[("foo", 0)],
        );
        let mut bad_padding = raw.clone();
        let padding_offset = offsets[0] + 60 + objects[0].len();
        bad_padding[padding_offset] = 0;
        let (foreign, _) = archive(&[("unit.o", elf_object(183, &[]))], &[("foo", 0)]);
        for candidate in [
            raw[..raw.len() - 1].to_vec(),
            foreign,
            b"!<thin>\n".to_vec(),
            bad_padding,
        ] {
            assert!(parse(&candidate).is_err());
        }
    }

    #[test]
    fn rejects_bad_header_trailer_and_malformed_size() {
        let (valid, _) = archive(&[("unit.o", elf_object(62, &[]))], &[]);
        let mut bad_trailer = valid.clone();
        let last_header = bad_trailer.len() - 64 - 60;
        bad_trailer[last_header + 58] = b'!';
        assert!(parse(&bad_trailer).is_err());

        let mut bad_size_header = entry("unit.o/", &[]);
        bad_size_header[48..58].copy_from_slice(b"not-a-size");
        let mut malformed_size = MAGIC.to_vec();
        malformed_size.extend_from_slice(&entry("/", &0_u32.to_be_bytes()));
        malformed_size.extend_from_slice(&bad_size_header);
        assert!(parse(&malformed_size).is_err());
    }

    #[test]
    fn rejects_malformed_symbol_indices_and_nonzero_index_padding() {
        let members = [("unit.o", elf_object(62, &[]))];
        type IndexFactory = fn(&[usize]) -> Vec<u8>;
        let malformed: [IndexFactory; 4] = [
            |offsets: &[usize]| {
                let mut payload = 1_u32.to_be_bytes().to_vec();
                payload.extend_from_slice(&u32::try_from(offsets[0] + 1).unwrap().to_be_bytes());
                payload.extend_from_slice(b"foo\0");
                payload
            },
            |offsets: &[usize]| {
                let mut payload = 2_u32.to_be_bytes().to_vec();
                payload.extend_from_slice(&u32::try_from(offsets[0]).unwrap().to_be_bytes());
                payload.extend_from_slice(&u32::try_from(offsets[0]).unwrap().to_be_bytes());
                payload.extend_from_slice(b"foo\0");
                payload
            },
            |offsets: &[usize]| {
                let mut payload = 1_u32.to_be_bytes().to_vec();
                payload.extend_from_slice(&u32::try_from(offsets[0]).unwrap().to_be_bytes());
                payload.extend_from_slice(b"foo\0extra\0");
                payload
            },
            |offsets: &[usize]| {
                let mut payload = 1_u32.to_be_bytes().to_vec();
                payload.extend_from_slice(&u32::try_from(offsets[0]).unwrap().to_be_bytes());
                payload.extend_from_slice(b"foo");
                payload
            },
        ];
        for make_index in malformed {
            let (candidate, _) = build_archive_with_index(&members, make_index);
            assert!(parse(&candidate).is_err());
        }

        let (zero_padded, _) = build_archive_with_index(&members, |offsets| {
            let mut payload = 1_u32.to_be_bytes().to_vec();
            payload.extend_from_slice(&u32::try_from(offsets[0]).unwrap().to_be_bytes());
            payload.extend_from_slice(b"foo\0\0\0");
            payload
        });
        assert!(parse(&zero_padded).is_ok());
    }

    #[test]
    fn rejects_missing_or_duplicate_indices_and_long_name_tables() {
        let object = elf_object(62, &[]);

        let mut missing_index = MAGIC.to_vec();
        missing_index.extend_from_slice(&entry("unit.o/", &object));
        assert!(parse(&missing_index).is_err());

        let mut duplicate_index = MAGIC.to_vec();
        duplicate_index.extend_from_slice(&entry("/", &0_u32.to_be_bytes()));
        duplicate_index.extend_from_slice(&entry("/", &0_u32.to_be_bytes()));
        assert!(parse(&duplicate_index).is_err());

        let mut duplicate_table = MAGIC.to_vec();
        duplicate_table.extend_from_slice(&entry("/", &0_u32.to_be_bytes()));
        duplicate_table.extend_from_slice(&entry("//", b"one.o/\n"));
        duplicate_table.extend_from_slice(&entry("//", b"two.o/\n"));
        assert!(parse(&duplicate_table).is_err());

        let mut missing_table = MAGIC.to_vec();
        missing_table.extend_from_slice(&entry("/", &0_u32.to_be_bytes()));
        missing_table.extend_from_slice(&entry("/0", &object));
        assert!(parse(&missing_table).is_err());
    }

    #[test]
    fn rejects_nonboundary_empty_and_unsafe_long_names() {
        let object = elf_object(62, &[]);
        let mut nonboundary = MAGIC.to_vec();
        nonboundary.extend_from_slice(&entry("/", &0_u32.to_be_bytes()));
        nonboundary.extend_from_slice(&entry("//", b"foobar/\n"));
        nonboundary.extend_from_slice(&entry("/1", &object));
        assert!(parse(&nonboundary).is_err());

        for table in [
            b"/\n".as_slice(),
            b"../unit.o/\n".as_slice(),
            b"./\n".as_slice(),
        ] {
            let mut unsafe_name = MAGIC.to_vec();
            unsafe_name.extend_from_slice(&entry("/", &0_u32.to_be_bytes()));
            unsafe_name.extend_from_slice(&entry("//", table));
            unsafe_name.extend_from_slice(&entry("/0", &object));
            assert!(parse(&unsafe_name).is_err());
        }

        let mut empty_direct = MAGIC.to_vec();
        empty_direct.extend_from_slice(&entry("/", &0_u32.to_be_bytes()));
        empty_direct.extend_from_slice(&entry(" ", &object));
        assert!(parse(&empty_direct).is_err());
    }

    #[test]
    fn accepts_zero_symbol_index_and_utf8_symbol_names() {
        let zero_symbols = archive(&[("unit.o", elf_object(62, &[]))], &[]).0;
        let parsed = parse(&zero_symbols).unwrap();
        assert!(parsed.symbols.is_empty());

        let utf8_symbol = "symbol_λ";
        let utf8_archive =
            build_archive_with_index(&[("unit.o", elf_object(62, &[]))], |offsets| {
                let mut payload = 1_u32.to_be_bytes().to_vec();
                payload.extend_from_slice(&u32::try_from(offsets[0]).unwrap().to_be_bytes());
                payload.extend_from_slice(utf8_symbol.as_bytes());
                payload.push(0);
                payload
            })
            .0;
        assert_eq!(parse(&utf8_archive).unwrap().symbols[0].name, utf8_symbol);
    }

    #[test]
    fn rejects_archive_size_over_limit_and_symbol_count_over_limit() {
        let mut oversized = vec![0_u8; MAX_ARCHIVE_BYTES + 1];
        oversized[..MAGIC.len()].copy_from_slice(MAGIC);
        assert!(parse(&oversized).is_err());

        let count = u32::try_from(MAX_SYMBOLS + 1).unwrap();
        let mut payload = vec![0_u8; 4 + (MAX_SYMBOLS + 1) * 4];
        payload[..4].copy_from_slice(&count.to_be_bytes());
        let mut archive = MAGIC.to_vec();
        archive.extend_from_slice(&entry("/", &payload));
        assert!(parse(&archive).is_err());
    }

    #[test]
    fn rejects_empty_and_invalid_utf8_symbol_names() {
        for name in [b"\0".as_slice(), b"\xff\0".as_slice()] {
            let candidate =
                build_archive_with_index(&[("unit.o", elf_object(62, &[]))], |offsets| {
                    let mut payload = 1_u32.to_be_bytes().to_vec();
                    payload.extend_from_slice(&u32::try_from(offsets[0]).unwrap().to_be_bytes());
                    payload.extend_from_slice(name);
                    payload
                })
                .0;
            assert!(parse(&candidate).is_err());
        }
    }
}
