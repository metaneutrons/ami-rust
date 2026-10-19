//! Bounded extraction of the native-v2 public transport capsule.
//!
//! This is a transport-integrity layer, not publisher authentication. The
//! caller must authenticate the record and compressed archive before treating
//! the returned directory as trusted input. Native transport permits a 64 MiB
//! archive and file-byte total; the historical public-candidate transport
//! remains a separate 32 MiB profile.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::{File, Metadata},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::fs::MetadataExt,
};

use serde_json::Value;

use crate::{
    Refusal, Result,
    compression::{DecodeLimits, copy_xz},
    digest::{is_sha256_digest, sha256_bytes},
    directory::Directory,
    json::{JsonProfile, parse_json_value},
    publisher_files::{BundleMeasurement, scan_native_bundle_exact},
    publisher_tar::validate_portable_path,
};

pub const MAX_NATIVE_TRANSPORT_FILES: usize = 512;
pub const MAX_NATIVE_TRANSPORT_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_NATIVE_TRANSPORT_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_NATIVE_TRANSPORT_XZ_MEMORY_KIB: u32 = 128 * 1024;
const TAR_BLOCK_BYTES: usize = 512;
const TAR_RECORD_BYTES: usize = 10 * 1024;
const TAR_MTIME: u64 = 1_791_936_000;
const STAGE_ENTRY_LIMIT: usize = 16_384;

/// The archive identity declared by a native transport record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeTransportArchive {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}

/// One complete regular-file row in a native transport inventory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeTransportFile {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

/// Structurally checked native-v2 transport record. Parsing checks shape,
/// bounds, paths, and digests; it does not establish trust or authenticate the
/// record's source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeTransportRecord {
    pub archive: NativeTransportArchive,
    pub files: Vec<NativeTransportFile>,
}

/// Result of validating and publishing the exact inventory named by a record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeTransportReceipt {
    pub archive: NativeTransportArchive,
    pub files: Vec<NativeTransportFile>,
    pub measurement: BundleMeasurement,
}

/// Parse a native transport record, rejecting duplicate keys and unknown
/// fields. Callers must authenticate these bytes independently.
pub fn parse_native_transport_record(raw: &[u8]) -> Result<NativeTransportRecord> {
    let value = parse_json_value(raw, JsonProfile::ReleaseManifestAndInstallReceipt)?;
    let mut canonical = serde_json::to_vec_pretty(&value).map_err(|error| {
        Refusal::new(format!(
            "could not canonicalize native transport record: {error}"
        ))
    })?;
    canonical.push(b'\n');
    if raw != canonical {
        return Err(Refusal::new(
            "native transport record is not canonical sorted-key JSON",
        ));
    }
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new("native transport record must be an object"))?;
    if !exact_fields(object, &["archive", "files"]) {
        return Err(Refusal::new(
            "native transport record has unknown or missing fields",
        ));
    }
    let archive_value = object
        .get("archive")
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new("native transport archive must be an object"))?;
    if !exact_fields(archive_value, &["name", "bytes", "sha256"]) {
        return Err(Refusal::new(
            "native transport archive has unknown or missing fields",
        ));
    }
    let archive_name = required_string(archive_value.get("name"), "archive name")?;
    validate_single_component(&archive_name, "archive name")?;
    let archive_bytes = required_u64(archive_value.get("bytes"), "archive byte count")?;
    if archive_bytes == 0 || archive_bytes > MAX_NATIVE_TRANSPORT_ARCHIVE_BYTES as u64 {
        return Err(Refusal::new(
            "native transport archive size is outside its 64 MiB profile",
        ));
    }
    let archive_sha256 = required_digest(archive_value.get("sha256"), "archive SHA-256")?;

    let rows = object
        .get("files")
        .and_then(Value::as_array)
        .filter(|rows| rows.len() <= MAX_NATIVE_TRANSPORT_FILES)
        .ok_or_else(|| {
            Refusal::new("native transport files must be an array of at most 512 rows")
        })?;
    let mut files = Vec::new();
    files
        .try_reserve_exact(rows.len())
        .map_err(|_| Refusal::new("could not allocate native transport inventory"))?;
    let mut total_bytes = 0_u64;
    let mut previous_path: Option<String> = None;
    for row in rows {
        let row = row
            .as_object()
            .ok_or_else(|| Refusal::new("native transport file row must be an object"))?;
        if !exact_fields(row, &["path", "bytes", "sha256"]) {
            return Err(Refusal::new(
                "native transport file row has unknown or missing fields",
            ));
        }
        let path = required_string(row.get("path"), "file path")?;
        let canonical = validate_portable_path(path.as_bytes())?;
        if canonical != path {
            return Err(Refusal::new("native transport path is not canonical"));
        }
        if previous_path
            .as_ref()
            .is_some_and(|previous| previous >= &path)
        {
            return Err(Refusal::new(
                "native transport inventory must be sorted and unique",
            ));
        }
        previous_path = Some(path.clone());
        let bytes = required_u64(row.get("bytes"), "file byte count")?;
        total_bytes = total_bytes
            .checked_add(bytes)
            .filter(|total| *total <= MAX_NATIVE_TRANSPORT_BYTES)
            .ok_or_else(|| Refusal::new("native transport files exceed the 64 MiB total"))?;
        let sha256 = required_digest(row.get("sha256"), "file SHA-256")?;
        files.push(NativeTransportFile {
            path,
            bytes,
            sha256,
        });
    }
    validate_file_path_set(&files)?;

    Ok(NativeTransportRecord {
        archive: NativeTransportArchive {
            name: archive_name,
            bytes: archive_bytes,
            sha256: archive_sha256,
        },
        files,
    })
}

/// Verify a caller-authenticated native transport archive and publish its
/// complete inventory below `parent/destination_name` using exclusive staging.
/// The explicit archive name binds the open descriptor to the record's name;
/// a `File` alone has no portable basename to compare. This function does not
/// authenticate the transport record or make a same-UID snapshot guarantee.
/// The caller must have opened the archive through its own no-follow file
/// validation; this function verifies its descriptor type, link count, size,
/// metadata stability, and content digest.
pub fn unpack_native_transport(
    mut archive: File,
    archive_name: &str,
    parent: &Directory,
    destination_name: &str,
    record: &NativeTransportRecord,
    mut cancelled: impl FnMut() -> bool,
) -> Result<NativeTransportReceipt> {
    validate_single_component(archive_name, "actual archive name")?;
    validate_single_component(destination_name, "transport destination")?;
    if archive_name != record.archive.name {
        return Err(Refusal::new(
            "native transport archive name differs from the authenticated record",
        ));
    }
    validate_record_again(record)?;
    check_cancelled(&mut cancelled)?;

    let compressed = read_pinned_archive(&mut archive, record, &mut cancelled)?;
    check_cancelled(&mut cancelled)?;
    let mut decoded = Vec::new();
    let decoded_limit = decoded_tar_limit(record)?;
    decoded
        .try_reserve_exact(decoded_limit)
        .map_err(|_| Refusal::new("could not reserve bounded native transport TAR buffer"))?;
    copy_xz(
        &compressed,
        &mut decoded,
        DecodeLimits {
            max_compressed_bytes: MAX_NATIVE_TRANSPORT_ARCHIVE_BYTES,
            max_decoded_bytes: decoded_limit,
            max_xz_memory_kib: MAX_NATIVE_TRANSPORT_XZ_MEMORY_KIB,
        },
    )?;
    drop(compressed);
    check_cancelled(&mut cancelled)?;

    let verified = verify_canonical_tar(&decoded, record, &mut cancelled)?;
    check_cancelled(&mut cancelled)?;
    publish_verified_files(
        parent,
        destination_name,
        record,
        &decoded,
        &verified,
        &mut cancelled,
    )
}

#[derive(Clone, Debug)]
struct VerifiedRange {
    path: String,
    range: std::ops::Range<usize>,
}

fn verify_canonical_tar(
    archive: &[u8],
    record: &NativeTransportRecord,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<VerifiedRange>> {
    let maximum = decoded_tar_limit(record)?;
    if archive.len() > maximum {
        return Err(Refusal::new(
            "decoded native transport exceeds its bounded TAR profile",
        ));
    }
    let mut position = 0_usize;
    let mut verified = Vec::new();
    verified
        .try_reserve_exact(record.files.len())
        .map_err(|_| Refusal::new("could not allocate verified transport ranges"))?;
    for row in &record.files {
        check_cancelled(cancelled)?;
        let header_end = position
            .checked_add(TAR_BLOCK_BYTES)
            .ok_or_else(|| Refusal::new("native transport TAR offset overflow"))?;
        let header = archive
            .get(position..header_end)
            .ok_or_else(|| Refusal::new("truncated native transport TAR header"))?;
        let expected_header = canonical_header(&row.path, row.bytes)?;
        if header != expected_header {
            return Err(Refusal::new(format!(
                "native transport TAR header is noncanonical for {}",
                row.path
            )));
        }
        let size = usize::try_from(row.bytes)
            .map_err(|_| Refusal::new("native transport file size does not fit this host"))?;
        let data_start = header_end;
        let data_end = data_start
            .checked_add(size)
            .ok_or_else(|| Refusal::new("native transport file range overflow"))?;
        let padded_end = padded_data_end(data_start, size)?;
        let contents = archive
            .get(data_start..data_end)
            .ok_or_else(|| Refusal::new("truncated native transport file data"))?;
        let padding = archive
            .get(data_end..padded_end)
            .ok_or_else(|| Refusal::new("truncated native transport file padding"))?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(Refusal::new(
                "native transport TAR has nonzero file padding",
            ));
        }
        if sha256_bytes(contents) != row.sha256 {
            return Err(Refusal::new(format!(
                "native transport file digest differs for {}",
                row.path
            )));
        }
        verified.push(VerifiedRange {
            path: row.path.clone(),
            range: data_start..data_end,
        });
        position = padded_end;
    }

    let trailer_end = position
        .checked_add(TAR_BLOCK_BYTES * 2)
        .ok_or_else(|| Refusal::new("native transport TAR trailer offset overflow"))?;
    let rounded = trailer_end
        .checked_add(TAR_RECORD_BYTES - 1)
        .ok_or_else(|| Refusal::new("native transport TAR record padding overflow"))?
        / TAR_RECORD_BYTES
        * TAR_RECORD_BYTES;
    if archive.len() != rounded
        || archive
            .get(position..)
            .is_none_or(|trailer| trailer.iter().any(|byte| *byte != 0))
    {
        return Err(Refusal::new(
            "native transport TAR has a noncanonical end marker or trailing data",
        ));
    }
    Ok(verified)
}

fn canonical_header(path: &str, size: u64) -> Result<[u8; TAR_BLOCK_BYTES]> {
    let (prefix, name) = split_ustar_path(path)?;
    let mut header = [0_u8; TAR_BLOCK_BYTES];
    header[..name.len()].copy_from_slice(name.as_bytes());
    write_octal_field(&mut header[100..108], 0o644)?;
    write_octal_field(&mut header[108..116], 0)?;
    write_octal_field(&mut header[116..124], 0)?;
    write_octal_field(&mut header[124..136], size)?;
    write_octal_field(&mut header[136..148], TAR_MTIME)?;
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());

    header[148..156].fill(b' ');
    let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
    let checksum = format!("{checksum:06o}\0 ");
    if checksum.len() != 8 {
        return Err(Refusal::new(
            "native transport TAR header checksum is not representable",
        ));
    }
    header[148..156].copy_from_slice(checksum.as_bytes());
    Ok(header)
}

fn write_octal_field(field: &mut [u8], value: u64) -> Result<()> {
    if field.is_empty() {
        return Err(Refusal::new("empty native TAR numeric field"));
    }
    let digits = field.len() - 1;
    let text = format!("{value:0digits$o}\0");
    if text.len() != field.len() {
        return Err(Refusal::new(
            "native transport TAR numeric field exceeds USTAR range",
        ));
    }
    field.copy_from_slice(text.as_bytes());
    Ok(())
}

fn split_ustar_path(path: &str) -> Result<(&str, &str)> {
    if path.len() <= 100 {
        return Ok(("", path));
    }
    for (index, byte) in path.bytes().enumerate().rev() {
        if byte == b'/' {
            let prefix = &path[..index];
            let name = &path[index + 1..];
            if !prefix.is_empty() && prefix.len() <= 155 && !name.is_empty() && name.len() <= 100 {
                return Ok((prefix, name));
            }
        }
    }
    Err(Refusal::new(
        "native transport path cannot be represented as canonical USTAR",
    ))
}

fn padded_data_end(start: usize, size: usize) -> Result<usize> {
    let padded_size = size
        .checked_add(TAR_BLOCK_BYTES - 1)
        .ok_or_else(|| Refusal::new("native transport TAR padding overflow"))?
        / TAR_BLOCK_BYTES
        * TAR_BLOCK_BYTES;
    start
        .checked_add(padded_size)
        .ok_or_else(|| Refusal::new("native transport TAR range overflow"))
}

fn decoded_tar_limit(record: &NativeTransportRecord) -> Result<usize> {
    let mut payload_bytes = 0_u64;
    let mut tar_bytes = 2 * TAR_BLOCK_BYTES;
    for row in &record.files {
        payload_bytes = payload_bytes
            .checked_add(row.bytes)
            .filter(|value| *value <= MAX_NATIVE_TRANSPORT_BYTES)
            .ok_or_else(|| Refusal::new("native transport files exceed the 64 MiB total"))?;
        let bytes = usize::try_from(row.bytes)
            .map_err(|_| Refusal::new("native transport member does not fit this host"))?;
        let padded = bytes
            .checked_add(TAR_BLOCK_BYTES - 1)
            .map(|n| n / TAR_BLOCK_BYTES * TAR_BLOCK_BYTES)
            .ok_or_else(|| Refusal::new("native transport member padding overflow"))?;
        tar_bytes = tar_bytes
            .checked_add(TAR_BLOCK_BYTES)
            .and_then(|n| n.checked_add(padded))
            .ok_or_else(|| Refusal::new("native transport TAR length overflow"))?;
    }
    // Account for each header AND each file's independent block padding, then
    // the two end blocks and Python's complete 10 KiB record padding.
    tar_bytes
        .checked_add(TAR_RECORD_BYTES - 1)
        .map(|n| n / TAR_RECORD_BYTES * TAR_RECORD_BYTES)
        .ok_or_else(|| Refusal::new("native transport final record padding overflow"))
}

fn read_pinned_archive(
    file: &mut File,
    record: &NativeTransportRecord,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<Vec<u8>> {
    let before = file.metadata().map_err(|error| {
        Refusal::new(format!(
            "could not inspect native transport archive: {error}"
        ))
    })?;
    if !before.is_file()
        || before.nlink() != 1
        || before.len() != record.archive.bytes
        || before.len() > MAX_NATIVE_TRANSPORT_ARCHIVE_BYTES as u64
    {
        return Err(Refusal::new(
            "native transport archive descriptor differs from its size profile",
        ));
    }
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        Refusal::new(format!(
            "could not rewind native transport archive: {error}"
        ))
    })?;
    let capacity = usize::try_from(record.archive.bytes)
        .map_err(|_| Refusal::new("native transport archive size does not fit this host"))?;
    let mut contents = Vec::new();
    contents
        .try_reserve_exact(capacity)
        .map_err(|_| Refusal::new("could not reserve bounded native transport archive buffer"))?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        check_cancelled(cancelled)?;
        let count = file.read(&mut buffer).map_err(|error| {
            Refusal::new(format!("could not read native transport archive: {error}"))
        })?;
        if count == 0 {
            break;
        }
        if contents.len().saturating_add(count) > capacity {
            return Err(Refusal::new(
                "native transport archive grew beyond its authenticated size",
            ));
        }
        contents.extend_from_slice(&buffer[..count]);
    }
    let after = file.metadata().map_err(|error| {
        Refusal::new(format!(
            "could not recheck native transport archive: {error}"
        ))
    })?;
    if !same_file_state(&before, &after)
        || contents.len() != capacity
        || sha256_bytes(&contents) != record.archive.sha256
    {
        return Err(Refusal::new(
            "native transport archive bytes, digest, or identity differ from the record",
        ));
    }
    Ok(contents)
}

fn same_file_state(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.nlink() == after.nlink()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn publish_verified_files(
    parent: &Directory,
    destination_name: &str,
    record: &NativeTransportRecord,
    decoded: &[u8],
    verified: &[VerifiedRange],
    cancelled: &mut impl FnMut() -> bool,
) -> Result<NativeTransportReceipt> {
    let stage_name = unique_stage_name()?;
    let mut created = false;
    let root = match parent.mkdir_new_tracked(&stage_name, 0o700, || created = true) {
        Ok(root) => root,
        Err(error) => {
            if created {
                let cleanup = parent.remove_tree(&stage_name, STAGE_ENTRY_LIMIT);
                return Err(combine_cleanup(error, cleanup));
            }
            return Err(error);
        }
    };
    let mut stage = OwnedStage {
        parent,
        name: stage_name,
        root,
        active: true,
    };

    let result = (|| {
        let (expected_files, expected_dirs) = expected_paths(record)?;
        for directory in &expected_dirs {
            check_cancelled(cancelled)?;
            let (parent_path, leaf) = split_parent(directory);
            stage
                .root
                .relative_directory(parent_path)?
                .mkdir_new(OsStr::new(leaf), 0o700)?;
        }
        for row in verified {
            check_cancelled(cancelled)?;
            let (parent_path, leaf) = split_parent(&row.path);
            let mut output = stage
                .root
                .relative_directory(parent_path)?
                .create_new_file(OsStr::new(leaf), 0o644)?;
            output
                .write_all(&decoded[row.range.clone()])
                .map_err(|error| {
                    Refusal::new(format!("could not write staged transport file: {error}"))
                })?;
            output.sync_all().map_err(|error| {
                Refusal::new(format!("could not sync staged transport file: {error}"))
            })?;
        }
        let measurement = scan_native_bundle_exact(&stage.root, &expected_files, &expected_dirs)?;
        if measurement.total_file_bytes != record.files.iter().map(|row| row.bytes).sum::<u64>() {
            return Err(Refusal::new(
                "staged native transport byte total differs from its inventory",
            ));
        }
        check_cancelled(cancelled)?;
        stage
            .parent
            .rename_no_replace(&stage.name, stage.parent, OsStr::new(destination_name))?;
        stage.name = OsString::from(destination_name);
        stage.root.sync_best_effort();
        stage.parent.sync_best_effort();

        let published = stage.parent.child(OsStr::new(destination_name))?;
        if !same_directory_identity(&stage.root, &published)? {
            return Err(Refusal::new(
                "published native transport directory changed before final verification",
            ));
        }
        let final_measurement =
            scan_native_bundle_exact(&published, &expected_files, &expected_dirs)?;
        if final_measurement != measurement {
            return Err(Refusal::new(
                "published native transport inventory changed after atomic rename",
            ));
        }
        check_cancelled(cancelled)?;
        stage.active = false;
        Ok(NativeTransportReceipt {
            archive: record.archive.clone(),
            files: record.files.clone(),
            measurement: final_measurement,
        })
    })();

    match result {
        Ok(receipt) => Ok(receipt),
        Err(error) => Err(stage.cleanup(error)),
    }
}

struct OwnedStage<'a> {
    parent: &'a Directory,
    name: OsString,
    root: Directory,
    active: bool,
}

impl OwnedStage<'_> {
    fn cleanup(&mut self, cause: Refusal) -> Refusal {
        if !self.active {
            return cause;
        }
        match self.parent.child(&self.name) {
            Ok(current) if same_directory_identity(&self.root, &current).unwrap_or(false) => {
                match self.parent.remove_tree(&self.name, STAGE_ENTRY_LIMIT) {
                    Ok(()) => {
                        self.active = false;
                        cause
                    }
                    Err(error) => Refusal::new(format!(
                        "{cause}; verified transport staging tree remains at {}: {error}",
                        self.name.to_string_lossy()
                    )),
                }
            }
            Ok(_) => Refusal::new(format!(
                "{cause}; transport staging entry changed and was preserved: {}",
                self.name.to_string_lossy()
            )),
            Err(error) => Refusal::new(format!(
                "{cause}; transport staging entry could not be re-opened and was preserved: {error}"
            )),
        }
    }
}

impl Drop for OwnedStage<'_> {
    fn drop(&mut self) {
        if self.active {
            let _ = self.cleanup(Refusal::new("native transport staging was abandoned"));
        }
    }
}

fn same_directory_identity(left: &Directory, right: &Directory) -> Result<bool> {
    let left = left.metadata()?;
    let right = right.metadata()?;
    Ok(left.dev() == right.dev() && left.ino() == right.ino())
}

fn expected_paths(record: &NativeTransportRecord) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    for row in &record.files {
        if !files.insert(row.path.clone()) {
            return Err(Refusal::new(
                "native transport inventory repeats a file path",
            ));
        }
        let parts: Vec<_> = row.path.split('/').collect();
        let mut parent = String::new();
        for component in &parts[..parts.len() - 1] {
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(component);
            directories.insert(parent.clone());
        }
    }
    if files.iter().any(|file| directories.contains(file)) {
        return Err(Refusal::new(
            "native transport file path is an ancestor of another file",
        ));
    }
    Ok((files, directories))
}

fn validate_file_path_set(files: &[NativeTransportFile]) -> Result<()> {
    let mut folded: BTreeMap<String, String> = BTreeMap::new();
    let mut folded_files = BTreeSet::new();
    for row in files {
        let parts: Vec<_> = row.path.split('/').collect();
        let mut parent = String::new();
        for (index, component) in parts.iter().enumerate() {
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(component);
            let key = parent.to_ascii_lowercase();
            if folded
                .insert(key.clone(), parent.clone())
                .is_some_and(|previous| previous != parent)
            {
                return Err(Refusal::new(
                    "native transport inventory contains a case-colliding path component",
                ));
            }
            if index == parts.len() - 1 {
                folded_files.insert(key);
            }
        }
    }
    for row in files {
        let parts: Vec<_> = row.path.split('/').collect();
        let mut parent = String::new();
        for component in &parts[..parts.len() - 1] {
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(component);
            if folded_files.contains(&parent.to_ascii_lowercase()) {
                return Err(Refusal::new(
                    "native transport file path conflicts with an ancestor file",
                ));
            }
        }
    }
    Ok(())
}

fn validate_record_again(record: &NativeTransportRecord) -> Result<()> {
    validate_single_component(&record.archive.name, "archive name")?;
    if record.archive.bytes == 0
        || record.archive.bytes > MAX_NATIVE_TRANSPORT_ARCHIVE_BYTES as u64
        || !is_sha256_digest(&record.archive.sha256)
        || record.files.len() > MAX_NATIVE_TRANSPORT_FILES
    {
        return Err(Refusal::new(
            "invalid native transport record bounds or digest",
        ));
    }
    let mut total = 0_u64;
    let mut previous: Option<&str> = None;
    for row in &record.files {
        let canonical = validate_portable_path(row.path.as_bytes())?;
        if canonical != row.path || !is_sha256_digest(&row.sha256) {
            return Err(Refusal::new("invalid native transport path or file digest"));
        }
        if previous.is_some_and(|path| path >= row.path.as_str()) {
            return Err(Refusal::new(
                "native transport inventory must be sorted and unique",
            ));
        }
        previous = Some(&row.path);
        total = total
            .checked_add(row.bytes)
            .filter(|value| *value <= MAX_NATIVE_TRANSPORT_BYTES)
            .ok_or_else(|| Refusal::new("native transport files exceed the 64 MiB total"))?;
    }
    validate_file_path_set(&record.files)
}

fn validate_single_component(value: &str, label: &str) -> Result<()> {
    let canonical = validate_portable_path(value.as_bytes())?;
    if canonical != value || value.contains('/') || value.len() > 100 {
        return Err(Refusal::new(format!(
            "{label} must be one portable filename"
        )));
    }
    Ok(())
}

fn required_string(value: Option<&Value>, label: &str) -> Result<String> {
    value
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| Refusal::new(format!("native transport {label} must be a string")))
}

fn required_u64(value: Option<&Value>, label: &str) -> Result<u64> {
    value.and_then(Value::as_u64).ok_or_else(|| {
        Refusal::new(format!(
            "native transport {label} must be an unsigned integer"
        ))
    })
}

fn required_digest(value: Option<&Value>, label: &str) -> Result<String> {
    let digest = required_string(value, label)?;
    if !is_sha256_digest(&digest) {
        return Err(Refusal::new(format!("native transport {label} is invalid")));
    }
    Ok(digest)
}

fn exact_fields(object: &serde_json::Map<String, Value>, fields: &[&str]) -> bool {
    object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
}

fn split_parent(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn check_cancelled(cancelled: &mut impl FnMut() -> bool) -> Result<()> {
    if cancelled() {
        return Err(Refusal::new("native transport processing cancelled"));
    }
    Ok(())
}

#[allow(unsafe_code)]
fn unique_stage_name() -> Result<OsString> {
    let mut random = [0_u8; 12];
    // SAFETY: getentropy receives a live 12-byte output buffer, below its
    // documented 256-byte limit. macOS and Linux provide this POSIX API.
    if unsafe { libc::getentropy(random.as_mut_ptr().cast(), random.len()) } != 0 {
        return Err(Refusal::new(format!(
            "could not generate native transport staging name: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut name = OsString::from(".ami-rust-transport-");
    for byte in random {
        name.push(format!("{byte:02x}"));
    }
    Ok(name)
}

fn combine_cleanup(cause: Refusal, cleanup: Result<()>) -> Refusal {
    match cleanup {
        Ok(()) => cause,
        Err(error) => Refusal::new(format!(
            "{cause}; partially created transport stage could not be cleaned: {error}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File},
        io::Write,
        os::unix::fs::{DirBuilderExt, MetadataExt},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use lzma_rust2::{XzOptions, XzWriter};
    use serde_json::{Value, json};
    use tar::{Builder, EntryType, Header};

    use crate::{digest::sha256_bytes, directory::Directory};

    use super::{
        MAX_NATIVE_TRANSPORT_BYTES, NativeTransportFile, NativeTransportRecord,
        parse_native_transport_record, unpack_native_transport,
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "ami-native-transport-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(fs::canonicalize(path).unwrap())
        }

        fn archive(&self, bytes: &[u8]) -> (File, String) {
            let path = self.0.join("release.tar.xz");
            fs::write(&path, bytes).unwrap();
            (File::open(path).unwrap(), "release.tar.xz".to_owned())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn canonical_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        builder.mode(tar::HeaderMode::Deterministic);
        for (path, contents) in files {
            let mut header = Header::new_ustar();
            header.set_entry_type(EntryType::Regular);
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(1_791_936_000);
            header.set_cksum();
            builder.append_data(&mut header, *path, *contents).unwrap();
        }
        let mut archive = builder.into_inner().unwrap();
        let mut position = 0;
        for (_, contents) in files {
            python_checksum(&mut archive[position..position + 512]);
            position += 512 + contents.len().div_ceil(512) * 512;
        }
        archive.resize(archive.len().div_ceil(10 * 1024) * (10 * 1024), 0);
        archive
    }

    fn python_checksum(header: &mut [u8]) {
        header[148..156].fill(b' ');
        let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
        // CPython tarfile writes six octal digits, NUL, and the original final
        // space from its initial checksum field. tar-rs uses a different valid
        // octal representation, so normalize only these test fixture headers.
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    }

    fn xz(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = XzWriter::new(Vec::new(), XzOptions::with_preset(1)).unwrap();
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn fixture_record(
        archive_name: &str,
        compressed: &[u8],
        files: &[(&str, &[u8])],
    ) -> NativeTransportRecord {
        NativeTransportRecord {
            archive: super::NativeTransportArchive {
                name: archive_name.to_owned(),
                bytes: compressed.len() as u64,
                sha256: sha256_bytes(compressed),
            },
            files: files
                .iter()
                .map(|(path, bytes)| NativeTransportFile {
                    path: (*path).to_owned(),
                    bytes: bytes.len() as u64,
                    sha256: sha256_bytes(bytes),
                })
                .collect(),
        }
    }

    fn record_json(record: &NativeTransportRecord) -> Vec<u8> {
        let value = json!({
            "archive": {"name":record.archive.name,"bytes":record.archive.bytes,"sha256":record.archive.sha256},
            "files":record.files.iter().map(|file| json!({"path":file.path,"bytes":file.bytes,"sha256":file.sha256})).collect::<Vec<Value>>(),
        });
        canonical_json(&value)
    }

    fn canonical_json(value: &Value) -> Vec<u8> {
        let mut raw = serde_json::to_vec_pretty(&value).unwrap();
        raw.push(b'\n');
        raw
    }

    #[test]
    fn parses_closed_record_and_refuses_duplicate_unknown_and_bad_path_fields() {
        let compressed = xz(&canonical_tar(&[("bin/tool", b"tool")]));
        let record = fixture_record("release.tar.xz", &compressed, &[("bin/tool", b"tool")]);
        assert_eq!(
            parse_native_transport_record(&record_json(&record)).unwrap(),
            record
        );
        let mut noncanonical = record_json(&record);
        noncanonical.insert(0, b' ');
        assert!(parse_native_transport_record(&noncanonical).is_err());

        let duplicate = br#"{"archive":{},"archive":{},"files":[]}"#;
        assert!(parse_native_transport_record(duplicate).is_err());

        let digest = "0".repeat(64);
        let unknown_field = json!({
            "archive":{"name":"release.tar.xz","bytes":1,"sha256":digest.clone(),"extra":1},
            "files":[]
        });
        assert!(parse_native_transport_record(&canonical_json(&unknown_field)).is_err());

        let invalid_path = json!({
            "archive":{"name":"release.tar.xz","bytes":1,"sha256":digest.clone()},
            "files":[{"path":"../x","bytes":0,"sha256":digest.clone()}]
        });
        assert!(parse_native_transport_record(&canonical_json(&invalid_path)).is_err());

        let too_long_name = json!({
            "archive":{"name":format!("{}.tar.xz", "x".repeat(96)),"bytes":1,"sha256":digest},
            "files":[]
        });
        assert!(parse_native_transport_record(&canonical_json(&too_long_name)).is_err());
    }

    #[test]
    fn validates_and_publishes_exact_ustar_inventory() {
        let files = [
            ("bin/tool", b"program".as_slice()),
            ("share/read-me.txt", b"data".as_slice()),
        ];
        let raw = canonical_tar(&files);
        let expected_header = super::canonical_header("bin/tool", files[0].1.len() as u64).unwrap();
        assert_eq!(&raw[..512], &expected_header);
        let compressed = xz(&raw);
        let record = fixture_record("release.tar.xz", &compressed, &files);
        let fixture = Fixture::new();
        let parent = Directory::open(&fixture.0).unwrap();
        let (archive, name) = fixture.archive(&compressed);
        let receipt =
            unpack_native_transport(archive, &name, &parent, "unpacked", &record, || false)
                .unwrap();
        assert_eq!(receipt.archive, record.archive);
        assert_eq!(receipt.files, record.files);
        assert_eq!(
            fs::read(fixture.0.join("unpacked/bin/tool")).unwrap(),
            b"program"
        );
        assert_eq!(
            fs::read(fixture.0.join("unpacked/share/read-me.txt")).unwrap(),
            b"data"
        );
        assert_eq!(
            fs::metadata(fixture.0.join("unpacked/bin/tool"))
                .unwrap()
                .mode()
                & 0o777,
            0o644
        );
        assert_eq!(
            fs::metadata(fixture.0.join("unpacked")).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(fixture.0.join("unpacked/bin")).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 2);
    }

    #[test]
    fn refuses_archive_name_size_digest_and_cancel_before_staging() {
        let files = [("file", b"payload".as_slice())];
        let compressed = xz(&canonical_tar(&files));
        let record = fixture_record("release.tar.xz", &compressed, &files);
        let fixture = Fixture::new();
        let parent = Directory::open(&fixture.0).unwrap();
        let (archive, _name) = fixture.archive(&compressed);
        assert!(
            unpack_native_transport(archive, "wrong.tar.xz", &parent, "out", &record, || false)
                .is_err()
        );
        assert!(!fixture.0.join("out").exists());

        let (archive, name) = fixture.archive(&compressed);
        let mut wrong_size = record.clone();
        wrong_size.archive.bytes += 1;
        assert!(
            unpack_native_transport(archive, &name, &parent, "out", &wrong_size, || false).is_err()
        );
        assert!(!fixture.0.join("out").exists());

        let (archive, name) = fixture.archive(&compressed);
        let mut wrong_digest = record.clone();
        wrong_digest.archive.sha256 = "0".repeat(64);
        assert!(
            unpack_native_transport(archive, &name, &parent, "out", &wrong_digest, || false)
                .is_err()
        );
        assert!(!fixture.0.join("out").exists());

        let (archive, name) = fixture.archive(&compressed);
        assert!(unpack_native_transport(archive, &name, &parent, "out", &record, || true).is_err());
        assert!(!fixture.0.join("out").exists());
    }

    #[test]
    fn preserves_existing_destination_and_refuses_a_wrong_file_digest() {
        let files = [("bin/tool", b"payload".as_slice())];
        let compressed = xz(&canonical_tar(&files));
        let record = fixture_record("release.tar.xz", &compressed, &files);
        let fixture = Fixture::new();
        let parent = Directory::open(&fixture.0).unwrap();

        let mut wrong_file_pin = record.clone();
        wrong_file_pin.files[0].sha256 = "0".repeat(64);
        let (archive, name) = fixture.archive(&compressed);
        assert!(
            unpack_native_transport(
                archive,
                &name,
                &parent,
                "wrong-file-pin",
                &wrong_file_pin,
                || false,
            )
            .is_err()
        );
        assert!(!fixture.0.join("wrong-file-pin").exists());

        let destination = fixture.0.join("already-present");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("keep.txt"), b"keep").unwrap();
        let (archive, name) = fixture.archive(&compressed);
        assert!(
            unpack_native_transport(archive, &name, &parent, "already-present", &record, || {
                false
            })
            .is_err()
        );
        assert_eq!(fs::read(destination.join("keep.txt")).unwrap(), b"keep");
        assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 2);
    }

    #[test]
    fn refuses_noncanonical_header_and_xz_suffixes() {
        let files = [("file", b"payload".as_slice())];
        let mut raw_tar = canonical_tar(&files);
        raw_tar[136] ^= 1;
        fix_checksum(&mut raw_tar[..512]);
        let compressed = xz(&raw_tar);
        let record = fixture_record("release.tar.xz", &compressed, &files);
        let fixture = Fixture::new();
        let parent = Directory::open(&fixture.0).unwrap();
        let (archive, name) = fixture.archive(&compressed);
        assert!(
            unpack_native_transport(archive, &name, &parent, "bad-header", &record, || false)
                .is_err()
        );

        let mut with_suffix = xz(&canonical_tar(&files));
        with_suffix.push(0);
        let record = fixture_record("release.tar.xz", &with_suffix, &files);
        let (archive, name) = fixture.archive(&with_suffix);
        assert!(
            unpack_native_transport(archive, &name, &parent, "bad-suffix", &record, || false)
                .is_err()
        );

        let mut concatenated = xz(&canonical_tar(&files));
        concatenated.extend_from_slice(&xz(b""));
        let record = fixture_record("release.tar.xz", &concatenated, &files);
        let (archive, name) = fixture.archive(&concatenated);
        assert!(
            unpack_native_transport(archive, &name, &parent, "bad-concat", &record, || false)
                .is_err()
        );
    }

    #[test]
    fn refuses_inventory_order_collisions_and_ancestor_paths() {
        let zero = "0".repeat(64);
        for paths in [
            vec!["b", "a"],
            vec!["A", "a"],
            vec!["a", "a/b"],
            vec!["A/file", "a/other"],
            vec!["A", "a/b"],
        ] {
            let value = json!({
                "archive":{"name":"x.tar.xz","bytes":1,"sha256":zero.clone()},
                "files":paths.iter().map(|path| json!({"path":path,"bytes":0,"sha256":zero.clone()})).collect::<Vec<Value>>()
            });
            assert!(parse_native_transport_record(&canonical_json(&value)).is_err());
        }
    }

    #[test]
    fn enforces_the_64_mib_inventory_total_without_allocating_payloads() {
        let zero = "0".repeat(64);
        let value = json!({
            "archive":{"name":"x.tar.xz","bytes":1,"sha256":zero.clone()},
            "files":[
                {"path":"a","bytes":MAX_NATIVE_TRANSPORT_BYTES,"sha256":zero.clone()},
                {"path":"b","bytes":1,"sha256":zero}
            ]
        });
        assert!(parse_native_transport_record(&canonical_json(&value)).is_err());
    }

    #[test]
    fn enforces_the_declared_decoded_profile_limit() {
        let maximum = super::decoded_tar_limit(&NativeTransportRecord {
            archive: super::NativeTransportArchive {
                name: "release.tar.xz".to_owned(),
                bytes: 1,
                sha256: "0".repeat(64),
            },
            files: vec![NativeTransportFile {
                path: "one".to_owned(),
                bytes: MAX_NATIVE_TRANSPORT_BYTES,
                sha256: "0".repeat(64),
            }],
        })
        .unwrap();
        assert_eq!(
            maximum,
            (64_usize * 1024 * 1024 + 512 + 1024).div_ceil(10 * 1024) * (10 * 1024)
        );
    }

    #[test]
    fn independent_file_padding_is_included_at_the_full_member_count() {
        let names = (0..512).map(|i| format!("file-{i:04}")).collect::<Vec<_>>();
        let files = names
            .iter()
            .map(|name| (name.as_str(), b"x".as_slice()))
            .collect::<Vec<_>>();
        let raw = canonical_tar(&files);
        let compressed = xz(&raw);
        let record = fixture_record("release.tar.xz", &compressed, &files);
        assert_eq!(super::decoded_tar_limit(&record).unwrap(), raw.len());
        assert!(raw.len() > 512 + 512 * 512 + 20 * 1024);
        let fixture = Fixture::new();
        let parent = Directory::open(&fixture.0).unwrap();
        let (archive, name) = fixture.archive(&compressed);
        let receipt =
            unpack_native_transport(archive, &name, &parent, "all-files", &record, || false)
                .unwrap();
        assert_eq!(receipt.files.len(), 512);
    }

    fn fix_checksum(header: &mut [u8]) {
        header[148..156].fill(b' ');
        let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    }
}
