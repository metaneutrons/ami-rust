//! Cross-host comparison for the three source-built AROS target libraries.
//!
//! The accepted R1 rule preserves every compiler output byte. Native archive
//! records and symbol indices must be identical. Only `lib.rmeta`, Cargo's
//! receipt-bound 16-hex disambiguator in archive member names, and the matching
//! `.rmeta-link`/GNU-long-name references may differ between producer hosts.

use ami_rust_core::{
    Refusal, Result,
    digest::{is_sha256_digest, sha256_bytes, sha256_file},
};
use lzma_rust2::XzReader;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    path::PathBuf,
};

const MAX_RLIB_BYTES: usize = 512 * 1024 * 1024;
const AR_HEADER_BYTES: usize = 60;

#[derive(Clone)]
pub(super) struct TargetRlib {
    pub(super) path: String,
    pub(super) bytes: u64,
    pub(super) sha256: String,
}

pub(super) struct HostTargetRlibs {
    pub(super) host: String,
    pub(super) direct_archive: PathBuf,
    pub(super) archive_bytes: u64,
    pub(super) archive_sha256: String,
    pub(super) libraries: Vec<TargetRlib>,
}

struct LoadedRlib {
    identity: TargetRlib,
    crate_name: String,
    disambiguator: String,
    raw: Vec<u8>,
}

#[derive(Clone)]
struct ArRecord<'a> {
    name: String,
    raw: &'a [u8],
    payload: &'a [u8],
}

pub(super) fn compare(hosts: Vec<HostTargetRlibs>) -> Result<Value> {
    if hosts.len() != 3 {
        return Err(Refusal::new(
            "target-library qualification requires exactly three hosts",
        ));
    }
    let mut loaded = Vec::new();
    for host in hosts {
        let archive_metadata = std::fs::symlink_metadata(&host.direct_archive)?;
        if !archive_metadata.file_type().is_file()
            || host.archive_bytes == 0
            || !is_sha256_digest(&host.archive_sha256)
            || sha256_file(&host.direct_archive)? != host.archive_sha256
            || archive_metadata.len() != host.archive_bytes
        {
            return Err(Refusal::new(format!(
                "{} direct archive differs from its producer inventory",
                host.host
            )));
        }
        let extracted = read_direct_archive(&host)?;
        let mut libraries = BTreeMap::new();
        for identity in host.libraries {
            let (crate_name, disambiguator) = library_filename(&identity.path)?;
            if identity.bytes == 0
                || identity.bytes > MAX_RLIB_BYTES as u64
                || !is_sha256_digest(&identity.sha256)
            {
                return Err(Refusal::new(format!(
                    "{} target-library identity is malformed",
                    host.host
                )));
            }
            let raw = extracted.get(&identity.path).cloned().ok_or_else(|| {
                Refusal::new(format!(
                    "{} direct archive lacks an inventoried target library",
                    host.host
                ))
            })?;
            if libraries
                .insert(
                    crate_name.clone(),
                    LoadedRlib {
                        identity,
                        crate_name,
                        disambiguator,
                        raw,
                    },
                )
                .is_some()
            {
                return Err(Refusal::new(format!(
                    "{} target libraries duplicate one crate",
                    host.host
                )));
            }
        }
        if libraries.keys().map(String::as_str).collect::<Vec<_>>()
            != ["alloc", "compiler_builtins", "core"]
        {
            return Err(Refusal::new(format!(
                "{} target libraries do not contain the exact three required crates",
                host.host
            )));
        }
        loaded.push((host.host, libraries));
    }

    let baseline = &loaded[0];
    let mut comparisons = Vec::new();
    for candidate in &loaded[1..] {
        for crate_name in ["alloc", "compiler_builtins", "core"] {
            comparisons.push(compare_rlib(
                &baseline.0,
                &baseline.1[crate_name],
                &candidate.0,
                &candidate.1[crate_name],
            )?);
        }
    }
    Ok(json!({
        "rule": "R1-A2_SEPARATE_HOST_METADATA_QUALIFICATION",
        "hosts": loaded.iter().map(|(host, _)| host).collect::<Vec<_>>(),
        "libraries_per_host": 3,
        "pairwise_comparisons": comparisons,
        "native_object_and_symbol_index_records_equal": true,
        "allowed_host_metadata": [
            "lib.rmeta",
            "Cargo-bound archive member disambiguators",
            "matching GNU long-name and .rmeta-link disambiguator references"
        ],
        "compiler_outputs_mutated": false,
    }))
}

fn read_direct_archive(host: &HostTargetRlibs) -> Result<BTreeMap<String, Vec<u8>>> {
    let expected = host
        .libraries
        .iter()
        .map(|identity| identity.path.clone())
        .collect::<BTreeSet<_>>();
    if expected.len() != host.libraries.len() {
        return Err(Refusal::new(format!(
            "{} target-library inventory contains duplicate paths",
            host.host
        )));
    }
    let decoder = XzReader::new_mem_limit(File::open(&host.direct_archive)?, false, 64 * 1024);
    let mut archive = tar::Archive::new(decoder);
    let mut found = BTreeMap::new();
    for entry in archive
        .entries()
        .map_err(|error| Refusal::new(format!("could not read direct archive: {error}")))?
    {
        let entry = entry.map_err(|error| {
            Refusal::new(format!("could not read direct archive member: {error}"))
        })?;
        let path = entry
            .path()
            .map_err(|error| Refusal::new(format!("invalid direct archive path: {error}")))?;
        let path = path
            .to_str()
            .ok_or_else(|| Refusal::new("direct archive path is not UTF-8"))?;
        let entry_type = entry.header().entry_type();
        let normalized_path = if entry_type.is_dir() {
            path.strip_suffix('/').unwrap_or(path)
        } else {
            path
        };
        if normalized_path.is_empty()
            || normalized_path.starts_with('/')
            || normalized_path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(Refusal::new(
                "direct archive path is not safe and normalized",
            ));
        }
        if entry_type.is_dir() {
            continue;
        }
        if !entry_type.is_file() {
            return Err(Refusal::new(
                "direct archive contains a non-file, non-directory member",
            ));
        }
        let Some(relative) = expected
            .iter()
            .find(|relative| path.ends_with(&format!("/{relative}")))
        else {
            continue;
        };
        let identity = host
            .libraries
            .iter()
            .find(|identity| &identity.path == relative)
            .expect("expected set came from identities");
        let declared_size = entry.header().size().map_err(|error| {
            Refusal::new(format!("invalid direct archive member size: {error}"))
        })?;
        if declared_size != identity.bytes || declared_size > MAX_RLIB_BYTES as u64 {
            return Err(Refusal::new(format!(
                "{} direct archive target-library size differs from its inventory",
                host.host
            )));
        }
        let capacity = usize::try_from(declared_size)
            .map_err(|_| Refusal::new("target-library size exceeds host address space"))?;
        let mut raw = Vec::with_capacity(capacity);
        entry
            .take(declared_size.saturating_add(1))
            .read_to_end(&mut raw)?;
        if raw.len() as u64 != identity.bytes || sha256_bytes(&raw) != identity.sha256 {
            return Err(Refusal::new(format!(
                "{} direct archive target library differs from its inventory",
                host.host
            )));
        }
        if found.insert(relative.clone(), raw).is_some() {
            return Err(Refusal::new(format!(
                "{} direct archive duplicates a target library",
                host.host
            )));
        }
    }
    if found.len() != expected.len() {
        return Err(Refusal::new(format!(
            "{} direct archive does not contain the exact target-library set",
            host.host
        )));
    }
    Ok(found)
}

fn compare_rlib(
    baseline_host: &str,
    baseline: &LoadedRlib,
    candidate_host: &str,
    candidate: &LoadedRlib,
) -> Result<Value> {
    if baseline.crate_name != candidate.crate_name {
        return Err(Refusal::new("target-library crate identities differ"));
    }
    if baseline.raw == candidate.raw {
        return Ok(json!({
            "crate": baseline.crate_name,
            "baseline_host": baseline_host,
            "candidate_host": candidate_host,
            "raw_archive_equal": true,
            "baseline": identity_json(&baseline.identity),
            "candidate": identity_json(&candidate.identity),
            "allowed_metadata_records_differ": [],
        }));
    }
    if baseline.disambiguator == candidate.disambiguator {
        return Err(Refusal::new(format!(
            "{} target archive differs without a different Cargo disambiguator",
            baseline.crate_name
        )));
    }
    let baseline_records = parse_ar(&baseline.raw)?;
    let candidate_records = parse_ar(&candidate.raw)?;
    if baseline_records.len() != candidate_records.len() {
        return Err(Refusal::new(format!(
            "{} target archive member multiplicity differs",
            baseline.crate_name
        )));
    }

    let mut name_mappings = Vec::new();
    for (left, right) in baseline_records.iter().zip(&candidate_records) {
        if left.name == right.name {
            continue;
        }
        let prefix_left = format!("{}-{}", baseline.crate_name, baseline.disambiguator);
        let prefix_right = format!("{}-{}", candidate.crate_name, candidate.disambiguator);
        let suffix_left = left.name.strip_prefix(&prefix_left);
        let suffix_right = right.name.strip_prefix(&prefix_right);
        if suffix_left.is_none()
            || suffix_left != suffix_right
            || !valid_codegen_suffix(suffix_left.expect("checked"), &baseline.crate_name)
            || left.raw != right.raw
        {
            return Err(Refusal::new(format!(
                "{} native archive member name or bytes differ outside the Cargo disambiguator",
                baseline.crate_name
            )));
        }
        name_mappings.push((left.name.clone(), right.name.clone()));
    }

    let mut lib_rmeta = 0_u64;
    let mut filename_metadata = Vec::new();
    let mut native_records = 0_u64;
    for (left, right) in baseline_records.iter().zip(&candidate_records) {
        if left.name != right.name {
            native_records += 1;
            continue;
        }
        if left.name == "lib.rmeta" {
            lib_rmeta += 1;
            continue;
        }
        if matches!(
            left.name.as_str(),
            "@gnu-long-name-table" | "lib.rmeta-link"
        ) && left.raw != right.raw
        {
            compare_filename_metadata(
                left,
                right,
                &name_mappings,
                &baseline.crate_name,
                &baseline.disambiguator,
                &candidate.disambiguator,
            )?;
            filename_metadata.push(left.name.clone());
            continue;
        }
        if left.raw != right.raw {
            return Err(Refusal::new(format!(
                "{} non-metadata archive record differs: {}",
                baseline.crate_name, left.name
            )));
        }
        native_records += 1;
    }
    if lib_rmeta != 1 {
        return Err(Refusal::new(format!(
            "{} target archive does not contain exactly one lib.rmeta",
            baseline.crate_name
        )));
    }
    Ok(json!({
        "crate": baseline.crate_name,
        "baseline_host": baseline_host,
        "candidate_host": candidate_host,
        "raw_archive_equal": false,
        "baseline": identity_json(&baseline.identity),
        "candidate": identity_json(&candidate.identity),
        "cargo_disambiguators": {
            "baseline": baseline.disambiguator,
            "candidate": candidate.disambiguator,
        },
        "receipt_bound_member_name_mappings": name_mappings.len(),
        "equal_native_and_index_records": native_records,
        "allowed_metadata_records_differ": {
            "lib.rmeta": true,
            "filename_references": filename_metadata,
        },
    }))
}

fn parse_ar(raw: &[u8]) -> Result<Vec<ArRecord<'_>>> {
    if !raw.starts_with(b"!<arch>\n") {
        return Err(Refusal::new("target library is not a Unix ar archive"));
    }
    let mut cursor = 8_usize;
    let mut pending = Vec::new();
    let mut long_names = None;
    while cursor < raw.len() {
        let header_end = cursor
            .checked_add(AR_HEADER_BYTES)
            .ok_or_else(|| Refusal::new("ar header offset overflow"))?;
        let header = raw
            .get(cursor..header_end)
            .ok_or_else(|| Refusal::new("truncated ar member header"))?;
        if header.get(58..60) != Some(b"`\n".as_slice()) {
            return Err(Refusal::new("invalid ar member header"));
        }
        let name_field = std::str::from_utf8(
            header
                .get(..16)
                .ok_or_else(|| Refusal::new("invalid ar member name"))?,
        )
        .map_err(|_| Refusal::new("non-ASCII ar member name"))?
        .trim_end();
        let size_text = std::str::from_utf8(
            header
                .get(48..58)
                .ok_or_else(|| Refusal::new("invalid ar member size"))?,
        )
        .map_err(|_| Refusal::new("non-ASCII ar member size"))?
        .trim();
        let size = size_text
            .parse::<usize>()
            .map_err(|_| Refusal::new("non-decimal ar member size"))?;
        let payload_end = header_end
            .checked_add(size)
            .ok_or_else(|| Refusal::new("ar member size overflow"))?;
        let record_end = payload_end
            .checked_add(size & 1)
            .ok_or_else(|| Refusal::new("ar padding offset overflow"))?;
        let payload = raw
            .get(header_end..payload_end)
            .ok_or_else(|| Refusal::new("truncated ar member payload"))?;
        let record = raw
            .get(cursor..record_end)
            .ok_or_else(|| Refusal::new("truncated ar member record"))?;
        if size & 1 == 1 && raw.get(payload_end) != Some(&b'\n') {
            return Err(Refusal::new("invalid ar member padding"));
        }
        if name_field == "//" {
            if long_names.replace(payload).is_some() {
                return Err(Refusal::new("duplicate GNU ar long-name table"));
            }
        }
        pending.push((name_field.to_owned(), record, payload));
        cursor = record_end;
    }
    if cursor != raw.len() {
        return Err(Refusal::new("ar archive has trailing bytes"));
    }
    let mut records = Vec::new();
    for (name_field, record, payload) in pending {
        let name = match name_field.as_str() {
            "/" => "@symbol-index32".to_owned(),
            "/SYM64/" => "@symbol-index64".to_owned(),
            "//" => "@gnu-long-name-table".to_owned(),
            value if value.starts_with('/') => {
                let offset = value[1..]
                    .parse::<usize>()
                    .map_err(|_| Refusal::new("invalid GNU long-name reference"))?;
                resolve_long_name(
                    long_names.ok_or_else(|| Refusal::new("missing GNU long-name table"))?,
                    offset,
                )?
            }
            value => value
                .strip_suffix('/')
                .ok_or_else(|| Refusal::new("unsupported ar member name encoding"))?
                .to_owned(),
        };
        records.push(ArRecord {
            name,
            raw: record,
            payload,
        });
    }
    Ok(records)
}

fn resolve_long_name(table: &[u8], offset: usize) -> Result<String> {
    if offset >= table.len() || (offset > 0 && table.get(offset - 1) != Some(&b'\n')) {
        return Err(Refusal::new(
            "GNU long-name reference is not at an entry boundary",
        ));
    }
    let tail = &table[offset..];
    let end = tail
        .windows(2)
        .position(|window| window == b"/\n")
        .ok_or_else(|| Refusal::new("unterminated GNU long name"))?;
    std::str::from_utf8(&tail[..end])
        .map(str::to_owned)
        .map_err(|_| Refusal::new("GNU long name is not UTF-8"))
}

fn compare_filename_metadata(
    left: &ArRecord<'_>,
    right: &ArRecord<'_>,
    mappings: &[(String, String)],
    crate_name: &str,
    left_hash: &str,
    right_hash: &str,
) -> Result<()> {
    if mappings.is_empty() || left.raw.len() != right.raw.len() {
        return Err(Refusal::new(format!(
            "{crate_name} filename metadata lacks one unambiguous Cargo mapping"
        )));
    }
    let (section_start, section_len) = if left.name == "lib.rmeta-link" {
        let left_section = rmeta_link_section(left.payload)?;
        let right_section = rmeta_link_section(right.payload)?;
        if left_section != right_section {
            return Err(Refusal::new(format!(
                "{crate_name} rmeta-link section layout differs"
            )));
        }
        left_section
    } else {
        (0, left.payload.len())
    };
    let mut masked_left = left.raw.to_vec();
    let mut masked_right = right.raw.to_vec();
    for (left_name, right_name) in mappings {
        let suffix = if left.name == "@gnu-long-name-table" {
            b"/\n".as_slice()
        } else {
            b"".as_slice()
        };
        let mut left_needle = left_name.as_bytes().to_vec();
        left_needle.extend_from_slice(suffix);
        let mut right_needle = right_name.as_bytes().to_vec();
        right_needle.extend_from_slice(suffix);
        let left_offset = unique_offset(
            &left.payload[section_start..section_start + section_len],
            &left_needle,
        )?;
        let right_offset = unique_offset(
            &right.payload[section_start..section_start + section_len],
            &right_needle,
        )?;
        if left_offset != right_offset {
            return Err(Refusal::new(format!(
                "{crate_name} filename metadata moved between hosts"
            )));
        }
        let hash_offset = AR_HEADER_BYTES + section_start + left_offset + crate_name.len() + 1;
        let end = hash_offset + 16;
        if masked_left.get(hash_offset..end) != Some(left_hash.as_bytes())
            || masked_right.get(hash_offset..end) != Some(right_hash.as_bytes())
        {
            return Err(Refusal::new(format!(
                "{crate_name} filename metadata is not bound to the compiler artifact disambiguator"
            )));
        }
        masked_left[hash_offset..end].fill(0);
        masked_right[hash_offset..end].fill(0);
    }
    if masked_left != masked_right {
        return Err(Refusal::new(format!(
            "{crate_name} filename metadata differs outside approved disambiguators"
        )));
    }
    Ok(())
}

fn rmeta_link_section(payload: &[u8]) -> Result<(usize, usize)> {
    if payload.len() < 64 || payload.get(..7) != Some(b"\x7fELF\x02\x01\x01".as_slice()) {
        return Err(Refusal::new("rmeta-link member is not ELF64 little-endian"));
    }
    if read_u16(payload, 16)? != 1
        || read_u16(payload, 18)? != 62
        || read_u16(payload, 52)? != 64
        || read_u16(payload, 56)? != 0
        || read_u16(payload, 58)? != 64
    {
        return Err(Refusal::new(
            "rmeta-link ELF header differs from the pinned format",
        ));
    }
    let section_offset = usize::try_from(read_u64(payload, 40)?)
        .map_err(|_| Refusal::new("rmeta-link section offset exceeds host"))?;
    let section_count = usize::from(read_u16(payload, 60)?);
    let string_index = usize::from(read_u16(payload, 62)?);
    if section_count == 0 || string_index >= section_count {
        return Err(Refusal::new("rmeta-link section table is invalid"));
    }
    let table_end = section_offset
        .checked_add(section_count * 64)
        .ok_or_else(|| Refusal::new("rmeta-link section table overflow"))?;
    if table_end > payload.len() {
        return Err(Refusal::new("rmeta-link section table is truncated"));
    }
    let strings = section(payload, section_offset, string_index)?;
    if strings.kind != 3 || strings.offset + strings.bytes > payload.len() {
        return Err(Refusal::new("rmeta-link section-name table is invalid"));
    }
    let names = &payload[strings.offset..strings.offset + strings.bytes];
    let mut found = None;
    for index in 0..section_count {
        let row = section(payload, section_offset, index)?;
        let name = nul_string(names, row.name_offset)?;
        if name == b".rmeta-link" {
            if found.is_some()
                || row.kind != 1
                || row.flags & 0x8000_0000 == 0
                || row.flags & 2 != 0
                || row.offset + row.bytes > payload.len()
            {
                return Err(Refusal::new("rmeta-link filename section is invalid"));
            }
            found = Some((row.offset, row.bytes));
        }
    }
    found.ok_or_else(|| Refusal::new("rmeta-link filename section is missing"))
}

struct ElfSection {
    name_offset: usize,
    kind: u32,
    flags: u64,
    offset: usize,
    bytes: usize,
}

fn section(payload: &[u8], table: usize, index: usize) -> Result<ElfSection> {
    let start = table
        .checked_add(index * 64)
        .ok_or_else(|| Refusal::new("ELF section offset overflow"))?;
    Ok(ElfSection {
        name_offset: usize::try_from(read_u32(payload, start)?)
            .map_err(|_| Refusal::new("ELF section name offset exceeds host"))?,
        kind: read_u32(payload, start + 4)?,
        flags: read_u64(payload, start + 8)?,
        offset: usize::try_from(read_u64(payload, start + 24)?)
            .map_err(|_| Refusal::new("ELF section offset exceeds host"))?,
        bytes: usize::try_from(read_u64(payload, start + 32)?)
            .map_err(|_| Refusal::new("ELF section size exceeds host"))?,
    })
}

fn read_u16(raw: &[u8], offset: usize) -> Result<u16> {
    let field = raw
        .get(offset..offset + 2)
        .ok_or_else(|| Refusal::new("truncated ELF u16 field"))?;
    Ok(u16::from_le_bytes([field[0], field[1]]))
}

fn read_u32(raw: &[u8], offset: usize) -> Result<u32> {
    let field = raw
        .get(offset..offset + 4)
        .ok_or_else(|| Refusal::new("truncated ELF u32 field"))?;
    Ok(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

fn read_u64(raw: &[u8], offset: usize) -> Result<u64> {
    let field = raw
        .get(offset..offset + 8)
        .ok_or_else(|| Refusal::new("truncated ELF u64 field"))?;
    Ok(u64::from_le_bytes([
        field[0], field[1], field[2], field[3], field[4], field[5], field[6], field[7],
    ]))
}

fn nul_string(raw: &[u8], offset: usize) -> Result<&[u8]> {
    let tail = raw
        .get(offset..)
        .ok_or_else(|| Refusal::new("ELF section name is out of bounds"))?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| Refusal::new("ELF section name is unterminated"))?;
    Ok(&tail[..end])
}

fn unique_offset(haystack: &[u8], needle: &[u8]) -> Result<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return Err(Refusal::new("filename metadata reference is absent"));
    }
    let mut matches = haystack
        .windows(needle.len())
        .enumerate()
        .filter(|(_, candidate)| *candidate == needle)
        .map(|(offset, _)| offset);
    let first = matches
        .next()
        .ok_or_else(|| Refusal::new("filename metadata reference is absent"))?;
    if matches.next().is_some() {
        return Err(Refusal::new("filename metadata reference is ambiguous"));
    }
    Ok(first)
}

fn valid_codegen_suffix(suffix: &str, crate_name: &str) -> bool {
    let Some(rest) = suffix.strip_prefix(&format!(".{crate_name}.")) else {
        return false;
    };
    let Some((unit, tail)) = rest.split_once("-cgu.") else {
        return false;
    };
    !unit.is_empty()
        && unit.len() <= 16
        && unit.bytes().all(|byte| byte.is_ascii_hexdigit())
        && tail.ends_with(".rcgu.o")
        && tail[..tail.len() - ".rcgu.o".len()]
            .bytes()
            .all(|byte| byte.is_ascii_digit())
}

fn library_filename(path: &str) -> Result<(String, String)> {
    let leaf = path
        .strip_prefix("lib/rustlib/x86_64-aros/lib/lib")
        .and_then(|value| value.strip_suffix(".rlib"))
        .ok_or_else(|| Refusal::new("target-library path has an unexpected layout"))?;
    if leaf.contains('/') || leaf.contains('\\') {
        return Err(Refusal::new("target-library path is not one library leaf"));
    }
    let (crate_name, disambiguator) = leaf
        .rsplit_once('-')
        .ok_or_else(|| Refusal::new("target-library filename lacks a disambiguator"))?;
    if !matches!(crate_name, "alloc" | "compiler_builtins" | "core")
        || disambiguator.len() != 16
        || !disambiguator
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Refusal::new("target-library filename is malformed"));
    }
    Ok((crate_name.to_owned(), disambiguator.to_owned()))
}

fn identity_json(identity: &TargetRlib) -> Value {
    json!({
        "path": identity.path,
        "bytes": identity.bytes,
        "sha256": identity.sha256,
    })
}
