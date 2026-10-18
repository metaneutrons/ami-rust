//! Read-only auditor for AROS-native x86_64 ELF relocatable objects.
//!
//! The reference thresholds in the returned report are measurements only. They
//! intentionally do not reject a valid object that exceeds those thresholds.
//! Malformed-input handling is stricter than the Python reference for gABI-
//! forbidden multiple symbol tables and overlapping file-backed sections;
//! these checks do not change valid-object reports. Refusal reports for
//! malformed strong-symbol tables use fixed-size, first-error diagnostics.

use crate::{Refusal, Result};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    hash::{Hash, Hasher},
    ops::Range,
    rc::Rc,
};

const ELF_HEADER_SIZE: usize = 64;
const SECTION_HEADER_SIZE: usize = 64;
const SYMBOL_SIZE: usize = 24;
const RELA_SIZE: usize = 24;
const SHT_NULL: u32 = 0;
const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHT_NOBITS: u32 = 8;
const SHF_WRITE: u64 = 1;
const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;
const STARTUP_SYMBOL: &str = "__startup_entry";
const ALLOWED_RELOCATIONS: [u32; 8] = [0, 1, 2, 4, 10, 11, 24, 25];

#[derive(Clone, Debug)]
struct Section {
    name_offset: u32,
    kind: u32,
    flags: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    alignment: u64,
    entry_size: u64,
}

#[derive(Clone, Debug, Debug)]
struct RawName<'a>(&'a [u8]);

impl RawName<'_> {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn lossy_chars(&self) -> impl Iterator<Item = char> + '_ {
        self.0.utf8_chunks().flat_map(|chunk| {
            let replacement_count = if chunk.invalid().is_empty() { 0 } else { 1 };
            chunk
                .valid()
                .chars()
                .chain(std::iter::once('\u{fffd}').take(replacement_count))
        })
    }

    fn equals_str(&self, value: &str) -> bool {
        self.lossy_chars().eq(value.chars())
    }

    fn lossy_string(&self) -> String {
        String::from_utf8_lossy(self.0).into_owned()
    }
}

impl PartialEq for RawName<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.lossy_chars().eq(other.lossy_chars())
    }
}

impl Eq for RawName<'_> {}

impl Hash for RawName<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut length = 0_usize;
        for character in self.lossy_chars() {
            character.hash(state);
            length += 1;
        }
        length.hash(state);
    }
}

#[derive(Clone, Debug)]
struct Symbol<'a> {
    name: Rc<RawName<'a>>,
    info: u8,
    other: u8,
    section: u16,
    value: u64,
    size: u64,
}

impl Symbol<'_> {
    fn report(&self) -> Value {
        json!({
            "name": self.name.lossy_string(),
            "info": self.info,
            "other": self.other,
            "section": self.section,
            "value": self.value,
            "size": self.size,
        })
    }
}

/// Audit an in-memory ELF object and return the legacy report shape.
///
/// `variant` selects only the reference-test thresholds (`core` or the legacy
/// default/dependency thresholds). `path` is reported verbatim and is not read.
pub fn audit(bytes: &[u8], variant: &str, path: &str) -> Result<Value> {
    let expected_identity = [0x7f, b'E', b'L', b'F', 2, 1, 1, 0x0f, 1];
    if bytes.get(..expected_identity.len()) != Some(expected_identity.as_slice()) {
        return Err(Refusal::new("wrong ELF identity/ABI marker"));
    }
    if bytes.len() < ELF_HEADER_SIZE {
        return Err(Refusal::new("truncated ELF header"));
    }

    let object_type = read_u16(bytes, 16, "ELF object type")?;
    let machine = read_u16(bytes, 18, "ELF machine")?;
    if (object_type, machine) != (1, 62) {
        return Err(Refusal::new("wrong native ET_REL/x86_64"));
    }

    let section_offset = read_u64(bytes, 40, "section header offset")?;
    let section_entry_size = read_u16(bytes, 58, "section header entry size")?;
    let section_count = read_u16(bytes, 60, "section count")?;
    let string_section_index = read_u16(bytes, 62, "section name table index")?;
    if section_entry_size != SECTION_HEADER_SIZE as u16
        || section_count == 0
        || section_count == u16::MAX
        || string_section_index >= section_count
    {
        return Err(Refusal::new("bad section header bounds"));
    }
    let table_size = u64::from(section_count)
        .checked_mul(u64::from(section_entry_size))
        .ok_or_else(|| Refusal::new("section header table size overflow"))?;
    let table_range = checked_range(
        section_offset,
        table_size,
        bytes.len(),
        "bad section header bounds",
    )?;

    let mut sections = Vec::with_capacity(usize::from(section_count));
    for index in 0..usize::from(section_count) {
        let entry_offset = table_range
            .start
            .checked_add(
                index
                    .checked_mul(SECTION_HEADER_SIZE)
                    .ok_or_else(|| Refusal::new("section header entry offset overflow"))?,
            )
            .ok_or_else(|| Refusal::new("section header entry offset overflow"))?;
        sections.push(Section {
            name_offset: read_u32(bytes, entry_offset, "section name offset")?,
            kind: read_u32(bytes, entry_offset + 4, "section type")?,
            flags: read_u64(bytes, entry_offset + 8, "section flags")?,
            offset: read_u64(bytes, entry_offset + 24, "section file offset")?,
            size: read_u64(bytes, entry_offset + 32, "section size")?,
            link: read_u32(bytes, entry_offset + 40, "section link")?,
            info: read_u32(bytes, entry_offset + 44, "section info")?,
            alignment: read_u64(bytes, entry_offset + 48, "section alignment")?,
            entry_size: read_u64(bytes, entry_offset + 56, "section entry size")?,
        });
    }

    // The ELF gABI permits at most one symbol table per object and requires
    // section contents not to overlap. Check these structural constraints
    // before decoding any strings or allocating symbol-table records.
    if sections
        .iter()
        .filter(|section| section.kind == SHT_SYMTAB)
        .count()
        > 1
    {
        return Err(Refusal::new("multiple symbol tables are not supported"));
    }
    let mut file_ranges = Vec::new();
    for (index, section) in sections.iter().enumerate() {
        if section.kind == SHT_NOBITS {
            continue;
        }
        let range = checked_range(
            section.offset,
            section.size,
            bytes.len(),
            "bad section data range",
        )?;
        if section.kind != SHT_NULL && section.size != 0 {
            file_ranges.push((range, index));
        }
    }
    file_ranges.sort_by_key(|(range, index)| (range.start, range.end, *index));
    for pair in file_ranges.windows(2) {
        if pair[0].0.end > pair[1].0.start {
            return Err(Refusal::new("overlapping file-backed sections"));
        }
    }

    let string_section = &sections[usize::from(string_section_index)];
    // The legacy auditor bounds-checks the raw section-name table range even
    // when its section header incorrectly declares SHT_NOBITS.
    let names_range = checked_range(
        string_section.offset,
        string_section.size,
        bytes.len(),
        "bad section name table bounds",
    )?;
    let names = bytes
        .get(names_range)
        .ok_or_else(|| Refusal::new("bad section name table bounds"))?;
    // Validate every file-backed section, as the Python reference does before
    // considering allocation flags or section types.
    for section in &sections {
        let _ = section_data(bytes, section)?;
    }
    let mut section_name_cache = HashMap::new();
    let section_names: Vec<Rc<RawName<'_>>> = sections
        .iter()
        .map(|section| cached_name(names, section.name_offset, &mut section_name_cache))
        .collect::<Result<_>>()?;
    drop(section_name_cache);

    let allocated: Vec<(usize, &Section)> = sections
        .iter()
        .enumerate()
        .filter(|(_, section)| section.flags & SHF_ALLOC != 0 && section.size != 0)
        .collect();
    let (first_allocated_index, first_allocated) = allocated
        .first()
        .copied()
        .ok_or_else(|| Refusal::new("no allocated section"))?;
    if first_allocated.flags & SHF_EXECINSTR == 0 {
        return Err(Refusal::new("first allocated hunk is not executable"));
    }

    let mut symbol_tables: Vec<Option<Vec<Symbol<'_>>>> = vec![None; usize::from(section_count)];
    let mut strong_definitions = HashSet::new();
    let mut symbol_name_cache = HashMap::new();
    for (index, section) in sections.iter().enumerate() {
        if section.kind != SHT_SYMTAB {
            continue;
        }
        if section.entry_size != SYMBOL_SIZE as u64
            || section.link >= u32::from(section_count)
            || section.size % SYMBOL_SIZE as u64 != 0
        {
            return Err(Refusal::new("invalid symbols"));
        }
        let link = usize::try_from(section.link)
            .map_err(|_| Refusal::new("symbol string table index does not fit host"))?;
        let strings = section_data(bytes, &sections[link])?;
        let count = usize::try_from(section.size / SYMBOL_SIZE as u64)
            .map_err(|_| Refusal::new("symbol count does not fit host address space"))?;
        let base = usize::try_from(section.offset)
            .map_err(|_| Refusal::new("symbol table offset does not fit host address space"))?;
        let mut symbols = Vec::with_capacity(count);
        for item in 0..count {
            let relative = item
                .checked_mul(SYMBOL_SIZE)
                .ok_or_else(|| Refusal::new("symbol offset overflow"))?;
            let offset = base
                .checked_add(relative)
                .ok_or_else(|| Refusal::new("symbol offset overflow"))?;
            let name_offset = read_u32(bytes, offset, "symbol name offset")?;
            let info = read_u8(bytes, offset + 4, "symbol info")?;
            let other = read_u8(bytes, offset + 5, "symbol visibility")?;
            let symbol_section = read_u16(bytes, offset + 6, "symbol section")?;
            let value = read_u64(bytes, offset + 8, "symbol value")?;
            let size = read_u64(bytes, offset + 16, "symbol size")?;
            let name = cached_name(strings, name_offset, &mut symbol_name_cache)?;
            let symbol = Symbol {
                name,
                info,
                other,
                section: symbol_section,
                value,
                size,
            };
            if symbol.section == 0 && symbol.info >> 4 == 1 && !symbol.name.is_empty() {
                // Stop at the first unresolved strong symbol to keep refusal
                // diagnostics bounded even for a large malformed symbol table.
                return Err(Refusal::new("unresolved strong symbol"));
            }
            if symbol.section != 0
                && symbol.info >> 4 == 1
                && !symbol.name.is_empty()
                && !strong_definitions.insert(symbol.name.clone())
            {
                return Err(Refusal::new("duplicate strong definition"));
            }
            symbols.push(symbol);
        }
        symbol_tables[index] = Some(symbols);
    }
    drop(symbol_name_cache);
    let entries: Vec<&Symbol> = symbol_tables
        .iter()
        .flatten()
        .flat_map(|symbols| symbols.iter())
        .filter(|symbol| symbol.name.equals_str(STARTUP_SYMBOL))
        .collect();
    if entries.len() != 1
        || usize::from(entries[0].section) != first_allocated_index
        || entries[0].value != 0
    {
        return Err(Refusal::new("startup must enter first text at 0"));
    }
    let entry = entries[0];

    let mut relocations = Vec::new();
    let mut relocation_types: BTreeMap<String, u64> = BTreeMap::new();
    for section in &sections {
        if section.kind != SHT_RELA {
            continue;
        }
        let link = usize::try_from(section.link)
            .map_err(|_| Refusal::new("RELA symbol table index does not fit host"))?;
        if section.entry_size != RELA_SIZE as u64
            || section.size % RELA_SIZE as u64 != 0
            || symbol_tables.get(link).and_then(Option::as_ref).is_none()
            || section.info >= u32::from(section_count)
        {
            return Err(Refusal::new("invalid RELA table"));
        }
        let target_index = usize::try_from(section.info)
            .map_err(|_| Refusal::new("RELA target index does not fit host"))?;
        let target = &sections[target_index];
        if target.flags & SHF_ALLOC == 0 {
            continue;
        }
        let symbols = symbol_tables[link]
            .as_ref()
            .ok_or_else(|| Refusal::new("invalid RELA symbol table"))?;
        let count = usize::try_from(section.size / RELA_SIZE as u64)
            .map_err(|_| Refusal::new("RELA count does not fit host address space"))?;
        let base = usize::try_from(section.offset)
            .map_err(|_| Refusal::new("RELA offset does not fit host address space"))?;
        for item in 0..count {
            let relative = item
                .checked_mul(RELA_SIZE)
                .ok_or_else(|| Refusal::new("RELA offset overflow"))?;
            let offset = base
                .checked_add(relative)
                .ok_or_else(|| Refusal::new("RELA offset overflow"))?;
            let destination = read_u64(bytes, offset, "relocation destination")?;
            let info = read_u64(bytes, offset + 8, "relocation info")?;
            let addend = read_i64(bytes, offset + 16, "relocation addend")?;
            let relocation_type = info as u32;
            let symbol_index = usize::try_from(info >> 32)
                .map_err(|_| Refusal::new("relocation symbol index does not fit host"))?;
            if !ALLOWED_RELOCATIONS.contains(&relocation_type) {
                return Err(Refusal::new(format!(
                    "unsupported AROS relocation: {relocation_type}"
                )));
            }
            let symbol = symbols
                .get(symbol_index)
                .ok_or_else(|| Refusal::new("invalid relocation symbol"))?;
            let width = match relocation_type {
                2 | 4 | 10 | 11 => 4_u64,
                0 => 0,
                _ => 8,
            };
            if destination
                .checked_add(width)
                .is_none_or(|end| end > target.size)
            {
                return Err(Refusal::new("relocation out of bounds"));
            }
            let target_name = section_names
                .get(target_index)
                .ok_or_else(|| Refusal::new("invalid relocation target section"))?;
            relocations.push(json!({
                "target_section": target_name.lossy_string(),
                "offset": destination,
                "type": relocation_type,
                "addend": addend,
                "symbol_section": symbol.section,
                "symbol_value": symbol.value,
                "symbol_name": symbol.name.lossy_string(),
            }));
            let key = relocation_type.to_string();
            let count = relocation_types.entry(key).or_default();
            *count = count
                .checked_add(1)
                .ok_or_else(|| Refusal::new("relocation count overflow"))?;
        }
    }

    let mut allocated_sections = Vec::with_capacity(allocated.len());
    let mut code_ro_bytes = 0_u64;
    let mut writable_bss_bytes = 0_u64;
    for (index, section) in allocated {
        let section_bytes = section_data(bytes, section)?;
        if section.flags & SHF_WRITE == 0 {
            code_ro_bytes = code_ro_bytes
                .checked_add(section.size)
                .ok_or_else(|| Refusal::new("read-only allocated size overflow"))?;
        } else {
            writable_bss_bytes = writable_bss_bytes
                .checked_add(section.size)
                .ok_or_else(|| Refusal::new("writable allocated size overflow"))?;
        }
        allocated_sections.push(json!({
            "index": index,
            "name": section_names[index].lossy_string(),
            "type": section.kind,
            "flags": section.flags,
            "size": section.size,
            "align": section.alignment,
            "sha256": crate::digest::sha256_bytes(section_bytes),
        }));
    }
    let allocated_static_bytes = code_ro_bytes
        .checked_add(writable_bss_bytes)
        .ok_or_else(|| Refusal::new("allocated static size overflow"))?;
    let static_owned_estimate_bytes = allocated_static_bytes
        .checked_add(131_072)
        .ok_or_else(|| Refusal::new("static owned size overflow"))?;
    let maximum_file_bytes = if variant == "core" {
        1_048_576_u64
    } else {
        4_194_304_u64
    };
    let maximum_code_ro_bytes = if variant == "core" {
        524_288_u64
    } else {
        2_097_152_u64
    };
    let file_bytes = u64::try_from(bytes.len())
        .map_err(|_| Refusal::new("file size does not fit report integer"))?;
    let observations = [
        ("file", file_bytes <= maximum_file_bytes),
        ("code_ro", code_ro_bytes <= maximum_code_ro_bytes),
        ("static_owned", static_owned_estimate_bytes <= 33_554_432),
    ];
    let reference_observations: BTreeMap<&str, &str> = observations
        .iter()
        .map(|(name, within)| {
            (
                *name,
                if *within {
                    "within-reference-threshold"
                } else {
                    "above-reference-threshold"
                },
            )
        })
        .collect();
    let within_reference_limits = observations.iter().all(|(_, within)| *within);

    Ok(json!({
        "path": path,
        "sha256": crate::digest::sha256_bytes(bytes),
        "file_bytes": file_bytes,
        "variant": variant,
        "code_ro_bytes": code_ro_bytes,
        "writable_bss_bytes": writable_bss_bytes,
        "allocated_static_bytes": allocated_static_bytes,
        "static_owned_estimate_bytes": static_owned_estimate_bytes,
        "allocated_sections": allocated_sections,
        "entry": entry.report(),
        "relocation_types": relocation_types,
        "relocations": relocations,
        "strong_undefined": Vec::<String>::new(),
        "limits": {
            "file": maximum_file_bytes,
            "code_ro": maximum_code_ro_bytes,
            "static_owned": 33_554_432_u64,
        },
        "limits_are_product_constraints": false,
        "limits_scope": "reference-test-thresholds",
        "reference_status": {
            "within_reference_limits": within_reference_limits,
            "observations": reference_observations,
        },
        "result": "PASS",
    }))
}

fn read_u8(bytes: &[u8], offset: usize, description: &str) -> Result<u8> {
    bytes
        .get(offset)
        .copied()
        .ok_or_else(|| Refusal::new(format!("truncated {description}")))
}

fn read_u16(bytes: &[u8], offset: usize, description: &str) -> Result<u16> {
    let raw = read_array::<2>(bytes, offset, description)?;
    Ok(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize, description: &str) -> Result<u32> {
    let raw = read_array::<4>(bytes, offset, description)?;
    Ok(u32::from_le_bytes(raw))
}

fn read_u64(bytes: &[u8], offset: usize, description: &str) -> Result<u64> {
    let raw = read_array::<8>(bytes, offset, description)?;
    Ok(u64::from_le_bytes(raw))
}

fn read_i64(bytes: &[u8], offset: usize, description: &str) -> Result<i64> {
    let raw = read_array::<8>(bytes, offset, description)?;
    Ok(i64::from_le_bytes(raw))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize, description: &str) -> Result<[u8; N]> {
    let end = offset
        .checked_add(N)
        .ok_or_else(|| Refusal::new(format!("{description} offset overflow")))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| Refusal::new(format!("truncated {description}")))?;
    slice
        .try_into()
        .map_err(|_| Refusal::new(format!("truncated {description}")))
}

fn checked_range(offset: u64, size: u64, total: usize, description: &str) -> Result<Range<usize>> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| Refusal::new(description))?;
    let start = usize::try_from(offset).map_err(|_| Refusal::new(description))?;
    let end = usize::try_from(end).map_err(|_| Refusal::new(description))?;
    if end > total || start > end {
        return Err(Refusal::new(description));
    }
    Ok(start..end)
}

fn section_data<'a>(bytes: &'a [u8], section: &Section) -> Result<&'a [u8]> {
    if section.kind == SHT_NOBITS {
        return Ok(&[]);
    }
    let range = checked_range(
        section.offset,
        section.size,
        bytes.len(),
        "bad section data range",
    )?;
    bytes
        .get(range)
        .ok_or_else(|| Refusal::new("bad section data range"))
}

fn cached_name<'a>(
    strings: &'a [u8],
    offset: u32,
    cache: &mut HashMap<u32, Rc<RawName<'a>>>,
) -> Result<Rc<RawName<'a>>> {
    if let Some(name) = cache.get(&offset) {
        return Ok(Rc::clone(name));
    }
    let string_offset = usize::try_from(offset)
        .map_err(|_| Refusal::new("string offset does not fit host address space"))?;
    // Names retain raw borrowed bytes even when invalid UTF-8. Repeated
    // references to one offset share the RawName allocation. Distinct offsets
    // into overlapping suffixes may still repeat scans; host input/work
    // budgets remain the caller's responsibility.
    let bytes = strings.get(string_offset..).unwrap_or(&[]);
    let name = Rc::new(RawName(
        bytes.split(|byte| *byte == 0).next().unwrap_or(&[]),
    ));
    cache.insert(offset, Rc::clone(&name));
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::{RawName, audit, cached_name};
    use serde_json::Value;
    use std::{
        collections::{HashMap, hash_map::DefaultHasher},
        hash::{Hash, Hasher},
        rc::Rc,
    };

    struct Fixture {
        bytes: Vec<u8>,
        symbol_table_offset: usize,
        rela_offset: Option<usize>,
        section_headers_offset: usize,
        section_names_offset: usize,
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "Fixture mirrors one fixed ELF section-header layout"
    )]
    fn append_section_header(
        output: &mut Vec<u8>,
        name: u32,
        kind: u32,
        flags: u64,
        offset: u64,
        size: u64,
        link: u32,
        info: u32,
        alignment: u64,
        entry_size: u64,
    ) {
        output.extend_from_slice(&name.to_le_bytes());
        output.extend_from_slice(&kind.to_le_bytes());
        output.extend_from_slice(&flags.to_le_bytes());
        output.extend_from_slice(&0_u64.to_le_bytes());
        output.extend_from_slice(&offset.to_le_bytes());
        output.extend_from_slice(&size.to_le_bytes());
        output.extend_from_slice(&link.to_le_bytes());
        output.extend_from_slice(&info.to_le_bytes());
        output.extend_from_slice(&alignment.to_le_bytes());
        output.extend_from_slice(&entry_size.to_le_bytes());
    }

    fn name_offset(table: &[u8], value: &[u8]) -> u32 {
        table
            .windows(value.len())
            .position(|window| window == value)
            .expect("fixture section name") as u32
    }

    fn fixture(
        text_size: usize,
        bss_size: u64,
        machine: u16,
        relocation_type: Option<u32>,
        duplicate_startup: bool,
    ) -> Fixture {
        let mut bytes = vec![0_u8; 64];
        let text_offset = bytes.len();
        bytes.resize(text_offset + text_size, 0x5a);
        let strings = b"\0__startup_entry\0";
        let strings_offset = bytes.len();
        bytes.extend_from_slice(strings);

        let symbol_table_offset = bytes.len();
        bytes.extend_from_slice(&[0_u8; 24]);
        // st_name=1, STB_GLOBAL|STT_NOTYPE, default visibility, .text, value=0.
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&0x10_u8.to_le_bytes());
        bytes.extend_from_slice(&0_u8.to_le_bytes());
        bytes.extend_from_slice(&1_u16.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        if duplicate_startup {
            bytes.extend_from_slice(&1_u32.to_le_bytes());
            bytes.extend_from_slice(&0x10_u8.to_le_bytes());
            bytes.extend_from_slice(&0_u8.to_le_bytes());
            bytes.extend_from_slice(&1_u16.to_le_bytes());
            bytes.extend_from_slice(&0_u64.to_le_bytes());
            bytes.extend_from_slice(&0_u64.to_le_bytes());
        }
        let symbol_table_size = bytes.len() - symbol_table_offset;

        let rela_offset = relocation_type.map(|kind| {
            let offset = bytes.len();
            bytes.extend_from_slice(&0_u64.to_le_bytes());
            let info = (1_u64 << 32) | u64::from(kind);
            bytes.extend_from_slice(&info.to_le_bytes());
            bytes.extend_from_slice(&0_i64.to_le_bytes());
            offset
        });

        let section_names = b"\0.text\0.bss\0.strtab\0.symtab\0.rela.text\0.shstrtab\0";
        let section_names_offset = bytes.len();
        bytes.extend_from_slice(section_names);
        let section_headers_offset = bytes.len();
        let section_count = if relocation_type.is_some() {
            7_u16
        } else {
            6_u16
        };
        let text_name = name_offset(section_names, b".text");
        let bss_name = name_offset(section_names, b".bss");
        let strings_name = name_offset(section_names, b".strtab");
        let symbols_name = name_offset(section_names, b".symtab");
        let rela_name = name_offset(section_names, b".rela.text");
        let shstr_name = name_offset(section_names, b".shstrtab");

        append_section_header(&mut bytes, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        append_section_header(
            &mut bytes,
            text_name,
            1,
            0x6,
            text_offset as u64,
            text_size as u64,
            0,
            0,
            16,
            0,
        );
        append_section_header(&mut bytes, bss_name, 8, 0x3, 0, bss_size, 0, 0, 8, 0);
        append_section_header(
            &mut bytes,
            strings_name,
            3,
            0,
            strings_offset as u64,
            strings.len() as u64,
            0,
            0,
            1,
            0,
        );
        append_section_header(
            &mut bytes,
            symbols_name,
            2,
            0,
            symbol_table_offset as u64,
            symbol_table_size as u64,
            3,
            1,
            8,
            24,
        );
        if let Some(offset) = rela_offset {
            append_section_header(&mut bytes, rela_name, 4, 0, offset as u64, 24, 4, 1, 8, 24);
        }
        append_section_header(
            &mut bytes,
            shstr_name,
            3,
            0,
            section_names_offset as u64,
            section_names.len() as u64,
            0,
            0,
            1,
            0,
        );

        bytes[..16].copy_from_slice(&[
            0x7f, b'E', b'L', b'F', 2, 1, 1, 0x0f, 1, 0, 0, 0, 0, 0, 0, 0,
        ]);
        bytes[16..18].copy_from_slice(&1_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[40..48].copy_from_slice(&(section_headers_offset as u64).to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&section_count.to_le_bytes());
        bytes[62..64].copy_from_slice(&(section_count - 1).to_le_bytes());

        Fixture {
            bytes,
            symbol_table_offset,
            rela_offset,
            section_headers_offset,
            section_names_offset,
        }
    }

    fn report(bytes: &[u8], variant: &str) -> Value {
        audit(bytes, variant, "fixture.o").expect("valid fixture should pass")
    }

    #[test]
    fn reports_native_object_and_reference_measurements() {
        let fixture = fixture(128, 1024, 62, Some(2), false);
        let report = report(&fixture.bytes, "core");
        assert_eq!(report["path"], "fixture.o");
        assert_eq!(report["file_bytes"], fixture.bytes.len());
        assert_eq!(report["code_ro_bytes"], 128);
        assert_eq!(report["writable_bss_bytes"], 1024);
        assert_eq!(report["allocated_static_bytes"], 1152);
        assert_eq!(report["static_owned_estimate_bytes"], 132_224);
        assert_eq!(report["limits"]["file"], 1_048_576);
        assert_eq!(report["limits"]["code_ro"], 524_288);
        assert_eq!(report["limits_are_product_constraints"], false);
        assert_eq!(report["limits_scope"], "reference-test-thresholds");
        assert_eq!(report["reference_status"]["within_reference_limits"], true);
        assert_eq!(report["relocation_types"]["2"], 1);
        assert_eq!(report["relocations"][0]["target_section"], ".text");
        assert_eq!(report["entry"]["name"], "__startup_entry");
        assert_eq!(report["result"], "PASS");
    }

    #[test]
    fn caches_repeated_long_names_and_preserves_lossy_utf8_reporting() {
        let long_name = "long-section-or-symbol-name-".repeat(128);
        let mut strings = vec![0_u8];
        strings.extend_from_slice(long_name.as_bytes());
        strings.push(0);
        let lossy_offset = u32::try_from(strings.len()).expect("fixture string offset fits u32");
        strings.extend_from_slice(b"bad\xffname\0");

        let mut section_cache = HashMap::new();
        let section_name = cached_name(&strings, 1, &mut section_cache).unwrap();
        let repeated_section_name = cached_name(&strings, 1, &mut section_cache).unwrap();
        assert!(Rc::ptr_eq(&section_name, &repeated_section_name));
        assert_eq!(section_name.0.as_ptr(), strings[1..].as_ptr());

        let mut symbol_cache = HashMap::new();
        let symbol_name = cached_name(&strings, 1, &mut symbol_cache).unwrap();
        let repeated_symbol_name = cached_name(&strings, 1, &mut symbol_cache).unwrap();
        assert!(Rc::ptr_eq(&symbol_name, &repeated_symbol_name));

        let lossy_name = cached_name(&strings, lossy_offset, &mut symbol_cache).unwrap();
        let repeated_lossy_name = cached_name(&strings, lossy_offset, &mut symbol_cache).unwrap();
        assert!(Rc::ptr_eq(&lossy_name, &repeated_lossy_name));
        assert_eq!(lossy_name.lossy_string(), "bad\u{fffd}name");
        assert_eq!(
            lossy_name.0.as_ptr(),
            strings[lossy_offset as usize..].as_ptr()
        );

        let invalid_bytes = vec![0xff; 4096];
        let mut invalid_cache = HashMap::new();
        for offset in 0..1024_usize {
            let offset_u32 = u32::try_from(offset).expect("small fixture offset fits u32");
            let name = cached_name(&invalid_bytes, offset_u32, &mut invalid_cache).unwrap();
            assert_eq!(name.0.as_ptr(), invalid_bytes[offset..].as_ptr());
        }

        let first_invalid = RawName(b"bad\xff");
        let second_invalid = RawName(b"bad\xfe");
        assert_eq!(first_invalid, second_invalid);
        let mut first_hash = DefaultHasher::new();
        first_invalid.hash(&mut first_hash);
        let mut second_hash = DefaultHasher::new();
        second_invalid.hash(&mut second_hash);
        assert_eq!(first_hash.finish(), second_hash.finish());

        let mut lossy_report_fixture = fixture(128, 1024, 62, None, false);
        lossy_report_fixture.bytes[lossy_report_fixture.section_names_offset + 1] = 0xff;
        let report = report(&lossy_report_fixture.bytes, "core");
        assert_eq!(report["allocated_sections"][0]["name"], "\u{fffd}text");
    }

    #[test]
    fn accepts_objects_above_reference_thresholds_including_large_bss() {
        let fixture = fixture(4 * 1024 * 1024 + 1, 33 * 1024 * 1024, 62, None, false);
        for variant in ["core", "deps"] {
            let report = report(&fixture.bytes, variant);
            assert_eq!(report["result"], "PASS");
            assert_eq!(report["reference_status"]["within_reference_limits"], false);
            assert_eq!(
                report["reference_status"]["observations"]["static_owned"],
                "above-reference-threshold"
            );
        }
    }

    #[test]
    fn refuses_wrong_abi_and_machine() {
        let mut wrong_abi = fixture(128, 1024, 62, None, false);
        wrong_abi.bytes[7] = 0;
        assert!(audit(&wrong_abi.bytes, "core", "fixture.o").is_err());

        let wrong_machine = fixture(128, 1024, 3, None, false);
        assert!(audit(&wrong_machine.bytes, "core", "fixture.o").is_err());
    }

    #[test]
    fn refuses_section_table_and_section_data_out_of_bounds() {
        let mut bad_table = fixture(128, 1024, 62, None, false);
        bad_table.bytes[40..48].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(audit(&bad_table.bytes, "core", "fixture.o").is_err());

        let mut bad_section = fixture(128, 1024, 62, None, false);
        let text_offset_field = bad_section.section_headers_offset + 64 + 24;
        bad_section.bytes[text_offset_field..text_offset_field + 8]
            .copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(audit(&bad_section.bytes, "core", "fixture.o").is_err());
    }

    #[test]
    fn refuses_overlapping_rela_and_data_sections() {
        let mut overlap = fixture(128, 1024, 62, Some(2), false);
        let rela_offset_field = overlap.section_headers_offset + 5 * 64 + 24;
        overlap.bytes[rela_offset_field..rela_offset_field + 8]
            .copy_from_slice(&64_u64.to_le_bytes());
        let error = audit(&overlap.bytes, "core", "fixture.o").expect_err("overlap must refuse");
        assert_eq!(error.to_string(), "overlapping file-backed sections");
    }

    #[test]
    fn refuses_overlapping_nonnull_section_at_index_zero() {
        let mut overlap = fixture(128, 1024, 62, None, false);
        let null_header = overlap.section_headers_offset;
        overlap.bytes[null_header + 4..null_header + 8].copy_from_slice(&1_u32.to_le_bytes());
        overlap.bytes[null_header + 24..null_header + 32].copy_from_slice(&64_u64.to_le_bytes());
        overlap.bytes[null_header + 32..null_header + 40].copy_from_slice(&1_u64.to_le_bytes());
        let error = audit(&overlap.bytes, "core", "fixture.o")
            .expect_err("non-NULL section zero overlap must refuse");
        assert_eq!(error.to_string(), "overlapping file-backed sections");
    }

    #[test]
    fn refuses_many_aliased_large_symbol_tables_before_symbol_parsing() {
        const ALIASED_TABLES: usize = 1_000;
        const TABLE_BYTES: usize = 2 * 1024 * 1024;

        let mut fixture = fixture(128, 1024, 62, None, false);
        let old_headers_offset = fixture.section_headers_offset;
        let mut headers = fixture.bytes[old_headers_offset..].to_vec();
        fixture.bytes.truncate(old_headers_offset);

        let large_table_offset = fixture.bytes.len();
        fixture.bytes.resize(large_table_offset + TABLE_BYTES, 0);
        let new_headers_offset = fixture.bytes.len();
        let symtab_header_start = 4 * 64;
        let symtab_header_end = symtab_header_start + 64;
        headers[symtab_header_start + 24..symtab_header_start + 32]
            .copy_from_slice(&(large_table_offset as u64).to_le_bytes());
        headers[symtab_header_start + 32..symtab_header_start + 40]
            .copy_from_slice(&(TABLE_BYTES as u64).to_le_bytes());
        let aliased_symtab_header = headers[symtab_header_start..symtab_header_end].to_vec();
        for _ in 0..ALIASED_TABLES {
            headers.extend_from_slice(&aliased_symtab_header);
        }
        fixture.bytes.extend_from_slice(&headers);

        let section_count = 6_u16 + ALIASED_TABLES as u16;
        fixture.bytes[40..48].copy_from_slice(&(new_headers_offset as u64).to_le_bytes());
        fixture.bytes[60..62].copy_from_slice(&section_count.to_le_bytes());
        let error = audit(&fixture.bytes, "core", "fixture.o")
            .expect_err("aliased symbol tables must be refused before parsing");
        assert_eq!(
            error.to_string(),
            "multiple symbol tables are not supported"
        );
    }

    #[test]
    fn refuses_out_of_bounds_nobits_section_name_table() {
        let mut bad_names = fixture(128, 1024, 62, None, false);
        let string_table_header = bad_names.section_headers_offset + 5 * 64;
        bad_names.bytes[string_table_header + 4..string_table_header + 8]
            .copy_from_slice(&8_u32.to_le_bytes());
        bad_names.bytes[string_table_header + 24..string_table_header + 32]
            .copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(audit(&bad_names.bytes, "core", "fixture.o").is_err());
    }

    #[test]
    fn requires_startup_in_first_executable_section_at_zero() {
        let mut non_executable = fixture(128, 1024, 62, None, false);
        let text_flags = non_executable.section_headers_offset + 64 + 8;
        non_executable.bytes[text_flags..text_flags + 8].copy_from_slice(&0x2_u64.to_le_bytes());
        assert!(audit(&non_executable.bytes, "core", "fixture.o").is_err());

        let mut wrong_section = fixture(128, 1024, 62, None, false);
        let symbol_section = wrong_section.symbol_table_offset + 24 + 6;
        wrong_section.bytes[symbol_section..symbol_section + 2]
            .copy_from_slice(&2_u16.to_le_bytes());
        assert!(audit(&wrong_section.bytes, "core", "fixture.o").is_err());

        let mut wrong_value = fixture(128, 1024, 62, None, false);
        let symbol_value = wrong_value.symbol_table_offset + 24 + 8;
        wrong_value.bytes[symbol_value..symbol_value + 8].copy_from_slice(&1_u64.to_le_bytes());
        assert!(audit(&wrong_value.bytes, "core", "fixture.o").is_err());
    }

    #[test]
    fn refuses_unsupported_and_out_of_bounds_relocations() {
        let unsupported = fixture(128, 1024, 62, Some(255), false);
        assert!(audit(&unsupported.bytes, "core", "fixture.o").is_err());

        let mut out_of_bounds = fixture(128, 1024, 62, Some(2), false);
        let rela_offset = out_of_bounds.rela_offset.expect("fixture has RELA");
        out_of_bounds.bytes[rela_offset..rela_offset + 8].copy_from_slice(&127_u64.to_le_bytes());
        assert!(audit(&out_of_bounds.bytes, "core", "fixture.o").is_err());
    }

    #[test]
    fn refuses_duplicate_and_unresolved_strong_symbols() {
        let duplicate = fixture(128, 1024, 62, None, true);
        assert!(audit(&duplicate.bytes, "core", "fixture.o").is_err());

        let mut unresolved = fixture(128, 1024, 62, None, false);
        let symbol_section = unresolved.symbol_table_offset + 24 + 6;
        unresolved.bytes[symbol_section..symbol_section + 2].copy_from_slice(&0_u16.to_le_bytes());
        assert!(audit(&unresolved.bytes, "core", "fixture.o").is_err());
    }

    #[test]
    fn refuses_malformed_symbol_and_rela_table_metadata() {
        let mut bad_symbols = fixture(128, 1024, 62, None, false);
        let symbol_link_field = bad_symbols.section_headers_offset + 4 * 64 + 40;
        bad_symbols.bytes[symbol_link_field..symbol_link_field + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(audit(&bad_symbols.bytes, "core", "fixture.o").is_err());

        let mut bad_rela = fixture(128, 1024, 62, Some(2), false);
        let rela_header = bad_rela.section_headers_offset + 5 * 64;
        bad_rela.bytes[rela_header + 40..rela_header + 44].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(audit(&bad_rela.bytes, "core", "fixture.o").is_err());
    }
}
