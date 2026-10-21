//! Pure section-name compaction for the accepted AROS ELF finalization recipe.
//!
//! Only section-name strings and section-table offsets are rewritten. Every
//! other file-backed section payload is compared byte-for-byte before return.
//! Full native ELF validation remains the responsibility of `elf::audit`.

use crate::{Refusal, Result};
use std::{ops::Range, str};

const ELF_HEADER_SIZE: usize = 64;
const SECTION_HEADER_SIZE: usize = 64;
const SHT_NOBITS: u32 = 8;

#[derive(Debug, serde::Serialize)]
pub struct SectionRename {
    pub section: usize,
    pub from: String,
    pub to: String,
}

#[derive(Debug, serde::Serialize)]
pub struct CompactionReport {
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub saved_metadata_bytes: usize,
    pub sections_renamed: usize,
    pub all_other_section_payloads_preserved: bool,
    pub renames: Vec<SectionRename>,
}

pub struct CompactedElf {
    pub bytes: Vec<u8>,
    pub report: CompactionReport,
}

/// Apply the fixed Rust-local section-name shortening used by the frozen
/// native build recipe. The input is borrowed and never changed.
pub fn compact_elf_sections(bytes: &[u8]) -> Result<Vec<u8>> {
    compact_elf_sections_with_report(bytes).map(|result| result.bytes)
}

pub fn compact_elf_sections_with_report(bytes: &[u8]) -> Result<CompactedElf> {
    const EXPECTED_IDENTITY: [u8; 9] = [0x7f, b'E', b'L', b'F', 2, 1, 1, 0x0f, 1];
    if bytes.get(..EXPECTED_IDENTITY.len()) != Some(EXPECTED_IDENTITY.as_slice()) {
        return Err(Refusal::new("wrong ELF identity/ABI marker"));
    }
    if bytes.len() < ELF_HEADER_SIZE {
        return Err(Refusal::new("truncated ELF header"));
    }
    if read_u16(bytes, 16, "ELF object type")? != 1 || read_u16(bytes, 18, "ELF machine")? != 62 {
        return Err(Refusal::new("expected native ET_REL/x86-64 ELF"));
    }
    if read_u16(bytes, 56, "program header count")? != 0 {
        return Err(Refusal::new("unexpected program header"));
    }
    if read_u16(bytes, 58, "section header entry size")? as usize != SECTION_HEADER_SIZE {
        return Err(Refusal::new("invalid section header entry size"));
    }

    let section_offset = read_u64(bytes, 40, "section header offset")?;
    let section_count = usize::from(read_u16(bytes, 60, "section count")?);
    let string_index = usize::from(read_u16(bytes, 62, "section name table index")?);
    if section_count == 0 || section_count == usize::from(u16::MAX) || string_index >= section_count
    {
        return Err(Refusal::new("invalid section table"));
    }
    let section_table_size = section_count
        .checked_mul(SECTION_HEADER_SIZE)
        .ok_or_else(|| Refusal::new("section table size overflow"))?;
    let section_table = checked_range(
        section_offset,
        u64::try_from(section_table_size)
            .map_err(|_| Refusal::new("section table size does not fit ELF offset"))?,
        bytes.len(),
        "truncated section table",
    )?;

    let mut headers = Vec::new();
    headers
        .try_reserve_exact(section_count)
        .map_err(|_| Refusal::new("could not allocate section header index"))?;
    for index in 0..section_count {
        let entry_offset = section_table
            .start
            .checked_add(
                index
                    .checked_mul(SECTION_HEADER_SIZE)
                    .ok_or_else(|| Refusal::new("section header offset overflow"))?,
            )
            .ok_or_else(|| Refusal::new("section header offset overflow"))?;
        let entry_end = entry_offset
            .checked_add(SECTION_HEADER_SIZE)
            .ok_or_else(|| Refusal::new("section header range overflow"))?;
        let raw: [u8; SECTION_HEADER_SIZE] = bytes
            .get(entry_offset..entry_end)
            .ok_or_else(|| Refusal::new("truncated section header"))?
            .try_into()
            .map_err(|_| Refusal::new("truncated section header"))?;
        headers.push(raw);
    }

    let old_string_offset = read_u64(&headers[string_index], 24, "string table offset")?;
    let old_string_size = read_u64(&headers[string_index], 32, "string table size")?;
    let old_string_range = checked_range(
        old_string_offset,
        old_string_size,
        bytes.len(),
        "truncated section names",
    )?;
    if section_table.start < old_string_range.end {
        return Err(Refusal::new("unsupported section table layout"));
    }
    let names = bytes
        .get(old_string_range.clone())
        .ok_or_else(|| Refusal::new("truncated section names"))?;

    // Match the frozen Python transform: each section header receives its own
    // string-table entry, including duplicate names that formerly shared one.
    let mut compacted_names = Vec::new();
    compacted_names
        .try_reserve(1)
        .map_err(|_| Refusal::new("could not allocate section name table"))?;
    compacted_names.push(0);
    let mut renames = Vec::new();
    for (index, header) in headers.iter_mut().enumerate() {
        let name_offset = read_u32(header, 0, "section name offset")?;
        let name = section_name(names, name_offset)?;
        let shorten = should_shorten(name);
        let shortened;
        let label = if shorten {
            shortened = format!(".r{index}");
            renames.push(SectionRename {
                section: index,
                from: name.to_owned(),
                to: shortened.clone(),
            });
            shortened.as_str()
        } else {
            name
        };
        let replacement_offset = if label.is_empty() {
            0
        } else {
            let replacement_offset = u32::try_from(compacted_names.len())
                .map_err(|_| Refusal::new("section name table offset overflow"))?;
            let additional = label
                .len()
                .checked_add(1)
                .ok_or_else(|| Refusal::new("section name table size overflow"))?;
            let prospective_size = compacted_names
                .len()
                .checked_add(additional)
                .ok_or_else(|| Refusal::new("section name table size overflow"))?;
            if prospective_size
                > usize::try_from(old_string_size)
                    .map_err(|_| Refusal::new("section name table size does not fit host"))?
            {
                return Err(Refusal::new("section-name expansion"));
            }
            compacted_names
                .try_reserve(additional)
                .map_err(|_| Refusal::new("could not allocate compacted section names"))?;
            compacted_names.extend_from_slice(label.as_bytes());
            compacted_names.push(0);
            replacement_offset
        };
        header[..4].copy_from_slice(&replacement_offset.to_le_bytes());
    }

    let old_string_size = usize::try_from(old_string_size)
        .map_err(|_| Refusal::new("section name table size does not fit host"))?;
    let padding = old_string_size
        .checked_sub(compacted_names.len())
        .ok_or_else(|| Refusal::new("section-name expansion"))?
        % 8;
    compacted_names
        .try_reserve(padding)
        .map_err(|_| Refusal::new("could not allocate compacted section names"))?;
    let padded_name_size = compacted_names
        .len()
        .checked_add(padding)
        .ok_or_else(|| Refusal::new("section name table size overflow"))?;
    compacted_names.resize(padded_name_size, 0);
    let delta = old_string_size
        .checked_sub(padded_name_size)
        .ok_or_else(|| Refusal::new("section-name expansion"))?;
    if delta % 8 != 0 {
        return Err(Refusal::new("section table alignment changed"));
    }
    let new_section_offset = section_table
        .start
        .checked_sub(delta)
        .ok_or_else(|| Refusal::new("section table offset underflow"))?;

    let new_file_size = bytes
        .len()
        .checked_sub(delta)
        .ok_or_else(|| Refusal::new("compacted ELF size underflow"))?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(new_file_size)
        .map_err(|_| Refusal::new("could not allocate compacted ELF"))?;
    result.extend_from_slice(&bytes[..old_string_range.start]);
    result.extend_from_slice(&compacted_names);
    result.extend_from_slice(&bytes[old_string_range.end..]);
    if result.len() != new_file_size {
        return Err(Refusal::new("compacted ELF size mismatch"));
    }
    write_u64(
        &mut result,
        40,
        u64::try_from(new_section_offset)
            .map_err(|_| Refusal::new("compacted section table offset overflow"))?,
    )?;

    for (index, header) in headers.iter_mut().enumerate() {
        let original_offset = read_u64(header, 24, "section file offset")?;
        let size = read_u64(header, 32, "section size")?;
        let kind = read_u32(header, 4, "section type")?;
        let new_offset = if index != string_index
            && original_offset
                >= u64::try_from(old_string_range.end)
                    .map_err(|_| Refusal::new("section offset does not fit ELF field"))?
        {
            original_offset
                .checked_sub(
                    u64::try_from(delta)
                        .map_err(|_| Refusal::new("section offset delta overflow"))?,
                )
                .ok_or_else(|| Refusal::new("section offset underflow"))?
        } else {
            original_offset
        };
        if index == string_index {
            write_u64(
                header,
                32,
                u64::try_from(compacted_names.len() - padding)
                    .map_err(|_| Refusal::new("compacted name table size overflow"))?,
            )?;
        }
        write_u64(header, 24, new_offset)?;
        let alignment = read_u64(header, 48, "section alignment")?;
        if alignment > 1 && new_offset % alignment != 0 {
            return Err(Refusal::new("section alignment changed"));
        }

        // SHT_NOBITS has no file payload. For every other section except the
        // rewritten name table, require bounded source and output ranges and
        // prove the transform preserved its payload exactly.
        if index != string_index && kind != SHT_NOBITS {
            let source = checked_range(original_offset, size, bytes.len(), "bad original payload")?;
            let destination =
                checked_range(new_offset, size, result.len(), "bad compacted payload")?;
            if bytes.get(source) != result.get(destination) {
                return Err(Refusal::new("section payload changed"));
            }
        }

        let header_offset = new_section_offset
            .checked_add(
                index
                    .checked_mul(SECTION_HEADER_SIZE)
                    .ok_or_else(|| Refusal::new("section header offset overflow"))?,
            )
            .ok_or_else(|| Refusal::new("section header offset overflow"))?;
        let header_end = header_offset
            .checked_add(SECTION_HEADER_SIZE)
            .ok_or_else(|| Refusal::new("section header range overflow"))?;
        let target = result
            .get_mut(header_offset..header_end)
            .ok_or_else(|| Refusal::new("compacted section table is truncated"))?;
        target.copy_from_slice(header);
    }
    Ok(CompactedElf {
        report: CompactionReport {
            input_bytes: bytes.len(),
            output_bytes: result.len(),
            saved_metadata_bytes: delta,
            sections_renamed: renames.len(),
            all_other_section_payloads_preserved: true,
            renames,
        },
        bytes: result,
    })
}

fn should_shorten(name: &str) -> bool {
    const RUST_SYMBOL_PREFIXES: [&str; 8] = [
        ".ltext.",
        ".lrodata.",
        ".ldata.",
        ".lbss.",
        ".rela.ltext.",
        ".rela.lrodata.",
        ".rela.ldata.",
        ".rela.lbss.",
    ];
    (name.contains("._R")
        && RUST_SYMBOL_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix)))
        || name.starts_with(".lrodata..Lanon.")
        || name.starts_with(".rela.lrodata..Lanon.")
}

fn section_name(names: &[u8], offset: u32) -> Result<&str> {
    let offset = usize::try_from(offset)
        .map_err(|_| Refusal::new("section name offset does not fit host"))?;
    let tail = names
        .get(offset..)
        .ok_or_else(|| Refusal::new("bad section name offset"))?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(tail.len());
    str::from_utf8(&tail[..end]).map_err(|_| Refusal::new("non-UTF8 section name"))
}

fn checked_range(offset: u64, size: u64, length: usize, message: &str) -> Result<Range<usize>> {
    let start = usize::try_from(offset).map_err(|_| Refusal::new(message.to_owned()))?;
    let size = usize::try_from(size).map_err(|_| Refusal::new(message.to_owned()))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| Refusal::new(message.to_owned()))?;
    if end > length {
        return Err(Refusal::new(message.to_owned()));
    }
    Ok(start..end)
}

fn read_u16(bytes: &[u8], offset: usize, message: &str) -> Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| Refusal::new(message.to_owned()))?;
    let bytes: [u8; 2] = bytes
        .get(offset..end)
        .ok_or_else(|| Refusal::new(message.to_owned()))?
        .try_into()
        .map_err(|_| Refusal::new(message.to_owned()))?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(bytes: &[u8], offset: usize, message: &str) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| Refusal::new(message.to_owned()))?;
    let bytes: [u8; 4] = bytes
        .get(offset..end)
        .ok_or_else(|| Refusal::new(message.to_owned()))?
        .try_into()
        .map_err(|_| Refusal::new(message.to_owned()))?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(bytes: &[u8], offset: usize, message: &str) -> Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| Refusal::new(message.to_owned()))?;
    let bytes: [u8; 8] = bytes
        .get(offset..end)
        .ok_or_else(|| Refusal::new(message.to_owned()))?
        .try_into()
        .map_err(|_| Refusal::new(message.to_owned()))?;
    Ok(u64::from_le_bytes(bytes))
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) -> Result<()> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| Refusal::new("ELF header write offset overflow"))?;
    let output = bytes
        .get_mut(offset..end)
        .ok_or_else(|| Refusal::new("truncated ELF header write"))?;
    output.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, fs, path::PathBuf};

    fn fixture(section_names: &[&str]) -> Vec<u8> {
        let count = section_names.len() + 2;
        let mut names = vec![0];
        let mut offsets = Vec::with_capacity(section_names.len() + 1);
        offsets.push(0_u32);
        for name in section_names.iter().copied().chain([".shstrtab"]) {
            offsets.push(u32::try_from(names.len()).unwrap());
            names.extend_from_slice(name.as_bytes());
            names.push(0);
        }
        names.resize((names.len() + 7) & !7, 0);
        let data_offset = ELF_HEADER_SIZE;
        let data_size = section_names.len() * 8;
        let string_offset = data_offset + data_size;
        let section_offset = string_offset + names.len();
        let mut bytes = vec![0_u8; section_offset + count * SECTION_HEADER_SIZE];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4..9].copy_from_slice(&[2, 1, 1, 0x0f, 1]);
        bytes[16..18].copy_from_slice(&1_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62_u16.to_le_bytes());
        bytes[40..48].copy_from_slice(&(section_offset as u64).to_le_bytes());
        bytes[56..58].copy_from_slice(&0_u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&(SECTION_HEADER_SIZE as u16).to_le_bytes());
        bytes[60..62].copy_from_slice(&(count as u16).to_le_bytes());
        bytes[62..64].copy_from_slice(&((count - 1) as u16).to_le_bytes());
        for index in 0..data_size {
            bytes[data_offset + index] = u8::try_from(index).unwrap().wrapping_add(0x41);
        }
        bytes[string_offset..section_offset].copy_from_slice(&names);

        // Section zero remains SHT_NULL. Each named payload is file-backed and
        // adjacent so payload preservation and offset translation are visible.
        for (index, _name) in section_names.iter().enumerate() {
            let header_start = section_offset + (index + 1) * SECTION_HEADER_SIZE;
            let header = &mut bytes[header_start..header_start + SECTION_HEADER_SIZE];
            header[..4].copy_from_slice(&offsets[index + 1].to_le_bytes());
            header[4..8].copy_from_slice(&1_u32.to_le_bytes()); // SHT_PROGBITS
            let flags = if index == 0 { 6_u64 } else { 2_u64 };
            header[8..16].copy_from_slice(&flags.to_le_bytes());
            let offset = data_offset + index * 8;
            header[24..32].copy_from_slice(&(offset as u64).to_le_bytes());
            header[32..40].copy_from_slice(&8_u64.to_le_bytes());
            header[48..56].copy_from_slice(&8_u64.to_le_bytes());
        }
        let header_start = section_offset + (count - 1) * SECTION_HEADER_SIZE;
        let header = &mut bytes[header_start..header_start + SECTION_HEADER_SIZE];
        header[..4].copy_from_slice(&offsets[count - 1].to_le_bytes());
        header[4..8].copy_from_slice(&3_u32.to_le_bytes()); // SHT_STRTAB
        header[24..32].copy_from_slice(&(string_offset as u64).to_le_bytes());
        header[32..40].copy_from_slice(&(names.len() as u64).to_le_bytes());
        header[48..56].copy_from_slice(&1_u64.to_le_bytes());
        bytes
    }

    fn section_header(bytes: &[u8], index: usize) -> &[u8] {
        let section_offset = read_u64(bytes, 40, "section offset").unwrap() as usize;
        let start = section_offset + index * SECTION_HEADER_SIZE;
        &bytes[start..start + SECTION_HEADER_SIZE]
    }

    fn section_name_at(bytes: &[u8], index: usize) -> String {
        let string_index = usize::from(read_u16(bytes, 62, "string index").unwrap());
        let names_header = section_header(bytes, string_index);
        let offset = read_u64(names_header, 24, "name offset").unwrap() as usize;
        let size = read_u64(names_header, 32, "name size").unwrap() as usize;
        let names = &bytes[offset..offset + size];
        let name_offset =
            read_u32(section_header(bytes, index), 0, "name offset").unwrap() as usize;
        String::from_utf8(
            names[name_offset..]
                .split(|byte| *byte == 0)
                .next()
                .unwrap()
                .to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn shortens_only_frozen_private_section_families_and_preserves_payloads() {
        let names = [
            ".ltext._Rprivate_symbol_path_that_is_long",
            ".lrodata..Lanon.private_constant_name",
            ".rela.ltext._Rprivate_relocation_name",
            ".text.unrelated._Rname",
        ];
        let original = fixture(&names);
        let result = compact_elf_sections_with_report(&original).unwrap();
        assert_eq!(result.report.sections_renamed, 3);
        assert_eq!(result.report.renames[0].section, 1);
        assert_eq!(result.report.renames[0].from, names[0]);
        assert_eq!(result.report.renames[0].to, ".r1");
        assert_eq!(
            result.report.input_bytes - result.report.output_bytes,
            result.report.saved_metadata_bytes
        );
        assert!(result.report.all_other_section_payloads_preserved);
        let compacted = result.bytes;
        assert_eq!(section_name_at(&compacted, 1), ".r1");
        assert_eq!(section_name_at(&compacted, 2), ".r2");
        assert_eq!(section_name_at(&compacted, 3), ".r3");
        assert_eq!(section_name_at(&compacted, 4), names[3]);
        for index in 1..=names.len() {
            let old = section_header(&original, index);
            let new = section_header(&compacted, index);
            let old_offset = read_u64(old, 24, "old payload offset").unwrap() as usize;
            let old_size = read_u64(old, 32, "old payload size").unwrap() as usize;
            let new_offset = read_u64(new, 24, "new payload offset").unwrap() as usize;
            let new_size = read_u64(new, 32, "new payload size").unwrap() as usize;
            assert_eq!(old_size, new_size);
            assert_eq!(
                original[old_offset..old_offset + old_size],
                compacted[new_offset..new_offset + new_size]
            );
        }
        assert_eq!(compact_elf_sections(&compacted).unwrap(), compacted);
    }

    #[test]
    fn refuses_bad_headers_tables_names_and_expansion() {
        let good = fixture(&[".ltext._Rlong_private_name"]);
        let mut malformed = good.clone();
        malformed[0] = 0;
        assert!(compact_elf_sections(&malformed).is_err());

        let mut malformed = good.clone();
        malformed[8] = 0; // Wrong AROS ABI identity marker.
        assert!(compact_elf_sections(&malformed).is_err());

        let mut malformed = good.clone();
        malformed[56..58].copy_from_slice(&1_u16.to_le_bytes());
        assert!(compact_elf_sections(&malformed).is_err());

        let mut malformed = good.clone();
        malformed[62..64].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(compact_elf_sections(&malformed).is_err());

        let mut malformed = good.clone();
        malformed[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(compact_elf_sections(&malformed).is_err());

        let mut malformed = good.clone();
        let string_index = usize::from(read_u16(&good, 62, "string index").unwrap());
        let header_start = read_u64(&good, 40, "section offset").unwrap() as usize
            + string_index * SECTION_HEADER_SIZE;
        malformed[header_start + 24..header_start + 32].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(compact_elf_sections(&malformed).is_err());

        let mut malformed = good.clone();
        let first_section_header = read_u64(&good, 40, "section offset").unwrap() as usize + 64;
        malformed[first_section_header..first_section_header + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(compact_elf_sections(&malformed).is_err());

        let mut malformed = good.clone();
        malformed[first_section_header + 24..first_section_header + 32]
            .copy_from_slice(&(u64::MAX - 7).to_le_bytes());
        assert!(compact_elf_sections(&malformed).is_err());

        let mut malformed = good.clone();
        let names_header = header_start;
        let names_offset =
            read_u64(&good[names_header..names_header + 64], 24, "names offset").unwrap() as usize;
        malformed[names_offset + 1] = 0xff;
        assert!(compact_elf_sections(&malformed).is_err());

        let repeated_name = "one repeated but intentionally long ordinary section name";
        let mut shared_names = fixture(&[repeated_name, repeated_name, repeated_name]);
        let section_offset = read_u64(&shared_names, 40, "section offset").unwrap() as usize;
        let string_index = usize::from(read_u16(&shared_names, 62, "string index").unwrap());
        let names_header = section_offset + string_index * SECTION_HEADER_SIZE;
        let names_offset = read_u64(
            &shared_names[names_header..names_header + SECTION_HEADER_SIZE],
            24,
            "names offset",
        )
        .unwrap() as usize;
        let short_table_size = 1 + repeated_name.len() + 1 + ".shstrtab".len() + 1;
        let mut short_table = Vec::with_capacity(short_table_size);
        short_table.push(0);
        short_table.extend_from_slice(repeated_name.as_bytes());
        short_table.push(0);
        let shstrtab_name_offset = u32::try_from(short_table.len()).unwrap();
        short_table.extend_from_slice(b".shstrtab\0");
        assert_eq!(short_table.len(), short_table_size);
        shared_names[names_offset..names_offset + short_table.len()].copy_from_slice(&short_table);
        shared_names[names_header + 32..names_header + 40]
            .copy_from_slice(&(short_table.len() as u64).to_le_bytes());
        for index in 1..=3 {
            let header = section_offset + index * SECTION_HEADER_SIZE;
            shared_names[header..header + 4].copy_from_slice(&1_u32.to_le_bytes());
        }
        shared_names[names_header..names_header + 4]
            .copy_from_slice(&shstrtab_name_offset.to_le_bytes());
        assert!(compact_elf_sections(&shared_names).is_err());
    }

    #[test]
    #[ignore = "requires a retained read-only R1 ELF artifact"]
    fn retained_r1_elf_is_already_compact_and_idempotent() {
        let path = env::var_os("AMI_R1_RETAINED_ELF")
            .map(PathBuf::from)
            .expect("set AMI_R1_RETAINED_ELF to a retained read-only R1 artifact");
        let original = fs::read(path).expect("read retained R1 ELF");
        assert_eq!(compact_elf_sections(&original).unwrap(), original);
    }
}
