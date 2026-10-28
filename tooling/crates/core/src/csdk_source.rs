//! Bounded materialization of the pinned corresponding-source C-SDK capsule.
//!
//! The caller supplies authenticated identities and owns the cancellation and
//! resource callback. This module verifies the inputs before creating output,
//! validates every capsule member while streaming, and writes only the selected
//! source, generated, and recipe inputs. The original libaom archive is scanned
//! separately and only its uniquely pinned generator file is added to the tree.

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("C-SDK source materialization is supported on macOS and Linux only");

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    rc::Rc,
};

use flate2::read::MultiGzDecoder;
use lzma_rust2::XzReader;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tar::Archive;

use crate::{
    Refusal, Result,
    digest::encode_hex,
    directory::Directory,
    files::{open_regular_nofollow, validate_relative_inventory_path},
    json::{JsonProfile, parse_json_value},
};

const MANIFEST_MAX_BYTES: u64 = JsonProfile::SdkComponentManifest.max_bytes() as u64;
const CAPSULE_MAX_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DECODED_TAR_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SELECTED_BYTES: u64 = 352 * 1024 * 1024;
const MAX_REGULAR_MEMBER_BYTES: u64 = 96 * 1024 * 1024;
const MAX_MEMBERS: usize = 100_000;
const MAX_PATH_BYTES: usize = 4096;
const MAX_PATH_COMPONENTS: usize = 128;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const XZ_MEMORY_LIMIT_KIB: u32 = 64 * 1024;
const CAPSULE_SCHEMA: &str = "ami-rust-csdk-corresponding-source-capsule-v1";
const LIBAOM_ARCHIVE_PATH: &str = "vendor/libaom/original/libaom-3.12.1.tar.gz";
const LIBAOM_ROOT: &str = "libaom-3.12.1/";

type CheckFn<'a> = Rc<RefCell<dyn FnMut(&str) -> Result<()> + 'a>>;
type CallbackFailure = Rc<RefCell<Option<Refusal>>>;

/// An exact byte length and SHA-256 identity supplied by the authenticated caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CsdkSourceFilePin {
    pub bytes: u64,
    pub sha256: [u8; 32],
}

/// Inputs and output location for one corresponding-source materialization.
///
/// `nested_generator_path` is the recipe-relative suffix below the pinned
/// libaom source root, for example `build/cmake/pkg_config.cmake`.
pub struct CsdkSourceMaterializationRequest {
    pub capsule: PathBuf,
    pub manifest: PathBuf,
    pub destination: PathBuf,
    pub capsule_pin: CsdkSourceFilePin,
    pub manifest_pin: CsdkSourceFilePin,
    pub nested_archive_sha256: [u8; 32],
    pub nested_generator_path: String,
    pub nested_generator_sha256: [u8; 32],
}

/// Typed roots for the extracted SDK sources. The JSON receipt carries only
/// relative paths; these paths remain native `PathBuf` values for the caller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CsdkSourceRoots {
    pub destination: PathBuf,
    pub aros_nx: PathBuf,
    pub aros_tools: PathBuf,
    pub libaom: PathBuf,
}

/// Materialization summary and typed source roots.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CsdkSourceMaterializationReceipt {
    pub receipt_value: Value,
    pub roots: CsdkSourceRoots,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InventoryKind {
    Directory,
    File,
}

#[derive(Clone, Debug)]
struct InventoryEntry {
    kind: InventoryKind,
    bytes: u64,
    mode: u32,
    sha256: Option<[u8; 32]>,
}

struct Inventory {
    rows: BTreeMap<String, InventoryEntry>,
    selected_bytes: u64,
}

/// Verify both pinned inputs before creating the destination, then stream and
/// validate the full capsule and nested libaom source archive.
///
/// Any failure after the private destination root is created leaves that root
/// in place and includes its location in the refusal for explicit recovery.
pub fn materialize_csdk_source(
    request: CsdkSourceMaterializationRequest,
    cancellation_check: impl FnMut(&str) -> Result<()>,
) -> Result<CsdkSourceMaterializationReceipt> {
    let checker: CheckFn<'_> = Rc::new(RefCell::new(cancellation_check));
    let callback_failure: CallbackFailure = Rc::new(RefCell::new(None));
    validate_request_paths(&request)?;
    checkpoint(&checker, "before opening C-SDK source inputs")?;

    let mut capsule = open_regular_nofollow(&request.capsule)?;
    let mut manifest = open_regular_nofollow(&request.manifest)?;
    validate_file_length(&capsule, request.capsule_pin.bytes, "source capsule")?;
    validate_file_length(&manifest, request.manifest_pin.bytes, "source manifest")?;

    let manifest_bytes = read_pinned_file(
        &mut manifest,
        request.manifest_pin,
        MANIFEST_MAX_BYTES,
        &checker,
        "reading source manifest",
    )?;
    let inventory = parse_inventory(&manifest_bytes, &request)?;
    hash_pinned_file(
        &mut capsule,
        request.capsule_pin,
        &checker,
        "prehashing source capsule",
    )?;
    capsule.seek(SeekFrom::Start(0))?;

    let (destination_parent_path, destination_name) =
        destination_parent_and_name(&request.destination)?;
    let destination_parent = Directory::open(&destination_parent_path)?;
    let mut root_owned = false;
    let root = match destination_parent.mkdir_new_tracked(&destination_name, 0o700, || {
        root_owned = true;
    }) {
        Ok(root) => root,
        Err(error) if root_owned => {
            return Err(recovery_refusal(error, &request.destination));
        }
        Err(error) => return Err(error),
    };

    let result = materialize_into_root(
        capsule,
        &root,
        &request,
        &inventory,
        &checker,
        &callback_failure,
    );

    match result {
        Ok(receipt) => Ok(receipt),
        Err(error) => Err(recovery_refusal(error, &request.destination)),
    }
}

fn materialize_into_root(
    capsule: File,
    root: &Directory,
    request: &CsdkSourceMaterializationRequest,
    inventory: &Inventory,
    checker: &CheckFn<'_>,
    callback_failure: &CallbackFailure,
) -> Result<CsdkSourceMaterializationReceipt> {
    let mut seen = BTreeSet::new();
    let mut created_directories = BTreeSet::new();
    let mut copied_bytes = 0_u64;
    let input = HashingInput::new(
        capsule,
        request.capsule_pin,
        Rc::clone(checker),
        Rc::clone(callback_failure),
        "decoding source capsule",
    );
    let xz = XzReader::new_mem_limit(input, true, XZ_MEMORY_LIMIT_KIB);
    let decoded = BoundedDecodedReader::new(xz, MAX_DECODED_TAR_BYTES);
    let mut archive = Archive::new(decoded);
    let mut entries = archive.entries().map_err(|error| {
        callback_or_io(
            callback_failure,
            "could not begin source capsule TAR",
            error,
        )
    })?;

    loop {
        checkpoint(checker, "before source capsule member")?;
        let Some(next_entry) = entries.next() else {
            break;
        };
        let mut entry = next_entry.map_err(|error| {
            callback_or_io(callback_failure, "could not read source capsule TAR", error)
        })?;
        if seen.len() == MAX_MEMBERS {
            return Err(Refusal::new(
                "source capsule exceeds the member-count bound",
            ));
        }

        let entry_type = entry.header().entry_type();
        let is_directory = entry_type.is_dir();
        let path = normalized_tar_path(entry.path_bytes().as_ref(), is_directory)?;
        let row = inventory
            .rows
            .get(&path)
            .ok_or_else(|| Refusal::new("source capsule contains an unknown member"))?;
        if !seen.insert(path.clone()) {
            return Err(Refusal::new("source capsule contains a duplicate member"));
        }

        if is_directory {
            if row.kind != InventoryKind::Directory || entry.size() != row.bytes || row.bytes != 0 {
                return Err(Refusal::new(
                    "source capsule directory differs from its inventory",
                ));
            }
            continue;
        }
        if !entry_type.is_file() || row.kind != InventoryKind::File || entry.size() != row.bytes {
            return Err(Refusal::new("source capsule member type or size differs"));
        }
        if entry.size() > MAX_REGULAR_MEMBER_BYTES {
            return Err(Refusal::new(
                "source capsule member exceeds the per-file bound",
            ));
        }

        let selected = is_selected(&path);
        let mut output = if selected {
            let (parent_path, basename) = split_relative_parent(&path)?;
            let parent = create_output_parent(root, parent_path, &mut created_directories)?;
            Some(parent.create_new_file(basename, row.mode & 0o777)?)
        } else {
            None
        };
        let mut hasher = Sha256::new();
        let mut member_bytes = 0_u64;
        let mut buffer = [0_u8; COPY_BUFFER_BYTES];
        loop {
            checkpoint(checker, "copying source capsule member")?;
            let remaining = row.bytes.saturating_sub(member_bytes);
            let read_limit = buffer
                .len()
                .min(usize::try_from(remaining).unwrap_or(usize::MAX));
            if read_limit == 0 {
                let mut extra = [0_u8; 1];
                match entry.read(&mut extra) {
                    Ok(0) => break,
                    Ok(_) => {
                        return Err(Refusal::new(
                            "source capsule member exceeds its declared size",
                        ));
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        return Err(callback_or_io(
                            callback_failure,
                            "could not finish source capsule member",
                            error,
                        ));
                    }
                }
            }
            match entry.read(&mut buffer[..read_limit]) {
                Ok(0) => {
                    return Err(Refusal::new(
                        "source capsule member is shorter than declared",
                    ));
                }
                Ok(read) => {
                    member_bytes = member_bytes
                        .checked_add(read as u64)
                        .ok_or_else(|| Refusal::new("source capsule member byte count overflow"))?;
                    hasher.update(&buffer[..read]);
                    if let Some(output) = output.as_mut() {
                        output.write_all(&buffer[..read])?;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(callback_or_io(
                        callback_failure,
                        "could not read source capsule member",
                        error,
                    ));
                }
            }
        }

        let digest: [u8; 32] = hasher.finalize().into();
        if Some(digest) != row.sha256 {
            return Err(Refusal::new(format!(
                "source capsule member hash differs: {path}"
            )));
        }
        if let Some(mut output) = output {
            output.flush()?;
            copied_bytes = copied_bytes
                .checked_add(member_bytes)
                .ok_or_else(|| Refusal::new("selected source byte count overflow"))?;
        }
    }

    let mut decoded = archive.into_inner();
    drain_zero_padding(
        &mut decoded,
        checker,
        callback_failure,
        "source capsule TAR",
    )?;
    let xz = decoded.into_inner();
    let mut compressed = xz.into_inner();
    drain_input(
        &mut compressed,
        checker,
        callback_failure,
        "finishing source capsule input",
    )?;
    let (_capsule, compressed_bytes, compressed_sha256) = compressed.finish();
    if compressed_bytes != request.capsule_pin.bytes
        || compressed_sha256 != request.capsule_pin.sha256
    {
        return Err(Refusal::new("source capsule changed while it was decoded"));
    }
    if seen.len() != inventory.rows.len() {
        return Err(Refusal::new("source capsule inventory is incomplete"));
    }
    if copied_bytes != inventory.selected_bytes {
        return Err(Refusal::new(
            "selected source materialization byte count differs",
        ));
    }

    checkpoint(checker, "before nested libaom source extraction")?;
    extract_libaom_generator(
        root,
        request,
        inventory,
        &mut created_directories,
        checker,
        callback_failure,
    )?;
    if let Some(error) = callback_failure.borrow_mut().take() {
        return Err(error);
    }

    let capsule_sha = encode_hex(&request.capsule_pin.sha256);
    let receipt_value = json!({
        "status": "PASS_SOURCE_MATERIALIZATION_ONLY",
        "all_capsule_members_verified": seen.len(),
        "selected_regular_bytes": copied_bytes,
        "source_capsule_sha256": capsule_sha,
        "roots": {
            "AROS-NX": "sources/AROS-NX",
            "aros-tools": "sources/aros-tools",
            "libaom": "sources/libaom"
        }
    });
    Ok(CsdkSourceMaterializationReceipt {
        receipt_value,
        roots: CsdkSourceRoots {
            destination: request.destination.clone(),
            aros_nx: request.destination.join("sources/AROS-NX"),
            aros_tools: request.destination.join("sources/aros-tools"),
            libaom: request.destination.join("sources/libaom"),
        },
    })
}

fn extract_libaom_generator(
    root: &Directory,
    request: &CsdkSourceMaterializationRequest,
    inventory: &Inventory,
    created_directories: &mut BTreeSet<String>,
    checker: &CheckFn<'_>,
    callback_failure: &CallbackFailure,
) -> Result<()> {
    validate_generator_suffix(&request.nested_generator_path)?;
    let suffix = &request.nested_generator_path;
    let archive_member = format!("{LIBAOM_ROOT}{suffix}");
    let nested_row = inventory
        .rows
        .get(LIBAOM_ARCHIVE_PATH)
        .ok_or_else(|| Refusal::new("pinned original libaom archive is absent from inventory"))?;
    if nested_row.kind != InventoryKind::File
        || nested_row.sha256 != Some(request.nested_archive_sha256)
        || nested_row.bytes > MAX_REGULAR_MEMBER_BYTES
    {
        return Err(Refusal::new(
            "nested libaom archive pin differs from its inventory row",
        ));
    }

    let nested_parent = root.relative_directory("vendor/libaom/original")?;
    let mut nested_file = nested_parent.regular(std::ffi::OsStr::new("libaom-3.12.1.tar.gz"))?;
    validate_file_length(&nested_file, nested_row.bytes, "nested libaom archive")?;
    let (nested_bytes, nested_sha256) = hash_file(
        &mut nested_file,
        checker,
        "prehashing nested libaom archive",
    )?;
    if nested_bytes != nested_row.bytes || nested_sha256 != request.nested_archive_sha256 {
        return Err(Refusal::new("nested libaom archive differs from its pin"));
    }
    nested_file.seek(SeekFrom::Start(0))?;

    let nested_input = HashingInput::new(
        nested_file,
        CsdkSourceFilePin {
            bytes: nested_row.bytes,
            sha256: request.nested_archive_sha256,
        },
        Rc::clone(checker),
        Rc::clone(callback_failure),
        "scanning nested libaom archive",
    );
    let gzip = MultiGzDecoder::new(nested_input);
    let decoded = BoundedDecodedReader::new(gzip, MAX_DECODED_TAR_BYTES);
    let mut archive = Archive::new(decoded);
    let mut entries = archive.entries().map_err(|error| {
        callback_or_io(callback_failure, "could not begin nested libaom TAR", error)
    })?;
    let mut target_seen = false;
    let output_path = format!("sources/libaom/{suffix}");
    let (output_parent_path, output_basename) = split_relative_parent(&output_path)?;
    let mut target_output: Option<File> = None;
    let mut target_hasher = Sha256::new();
    let mut target_bytes = 0_u64;
    let mut target_expected_bytes = None;
    let mut nested_members = 0_usize;

    loop {
        checkpoint(checker, "before nested libaom TAR member")?;
        let Some(next_entry) = entries.next() else {
            break;
        };
        let mut entry = next_entry.map_err(|error| {
            callback_or_io(callback_failure, "could not read nested libaom TAR", error)
        })?;
        if nested_members == MAX_MEMBERS {
            return Err(Refusal::new(
                "nested libaom TAR exceeds the member-count bound",
            ));
        }
        nested_members += 1;
        let path = normalized_tar_path(
            entry.path_bytes().as_ref(),
            entry.header().entry_type().is_dir(),
        )?;
        let is_target = path == archive_member;
        if !is_target {
            continue;
        }
        if target_seen {
            return Err(Refusal::new("nested libaom generator source is duplicated"));
        }
        target_seen = true;
        if !entry.header().entry_type().is_file() || entry.size() > MAX_REGULAR_MEMBER_BYTES {
            return Err(Refusal::new(
                "nested libaom generator source is not a bounded regular file",
            ));
        }
        target_expected_bytes = Some(entry.size());
        let output_parent = create_output_parent(root, output_parent_path, created_directories)?;
        target_output = Some(output_parent.create_new_file(output_basename, 0o644)?);
        let mut buffer = [0_u8; COPY_BUFFER_BYTES];
        loop {
            checkpoint(checker, "copying nested libaom generator source")?;
            match entry.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    target_bytes = target_bytes
                        .checked_add(read as u64)
                        .ok_or_else(|| Refusal::new("nested generator byte count overflow"))?;
                    if target_bytes > MAX_REGULAR_MEMBER_BYTES {
                        return Err(Refusal::new(
                            "nested generator source exceeds the per-file bound",
                        ));
                    }
                    target_hasher.update(&buffer[..read]);
                    target_output
                        .as_mut()
                        .expect("target output exists after opening")
                        .write_all(&buffer[..read])?;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(callback_or_io(
                        callback_failure,
                        "could not copy nested generator source",
                        error,
                    ));
                }
            }
        }
    }

    let mut decoded = archive.into_inner();
    drain_zero_padding(&mut decoded, checker, callback_failure, "nested libaom TAR")?;
    let gzip = decoded.into_inner();
    let mut compressed = gzip.into_inner();
    drain_input(
        &mut compressed,
        checker,
        callback_failure,
        "finishing nested libaom archive",
    )?;
    let (_archive, archive_bytes, archive_sha256) = compressed.finish();
    if archive_bytes != nested_row.bytes || archive_sha256 != request.nested_archive_sha256 {
        return Err(Refusal::new(
            "nested libaom archive changed while it was scanned",
        ));
    }
    if !target_seen {
        return Err(Refusal::new("nested libaom generator source is absent"));
    }
    if target_expected_bytes != Some(target_bytes) {
        return Err(Refusal::new(
            "nested libaom generator source is shorter than declared",
        ));
    }
    let target_sha256: [u8; 32] = target_hasher.finalize().into();
    if target_sha256 != request.nested_generator_sha256 {
        return Err(Refusal::new(
            "nested libaom generator source differs from its pin",
        ));
    }
    if let Some(mut output) = target_output {
        output.flush()?;
    }
    Ok(())
}

fn parse_inventory(raw: &[u8], request: &CsdkSourceMaterializationRequest) -> Result<Inventory> {
    let value = parse_json_value(raw, JsonProfile::SdkComponentManifest)?;
    let root = value
        .as_object()
        .ok_or_else(|| Refusal::new("source capsule manifest root must be an object"))?;
    let allowed_root_fields = [
        "capsule",
        "capsule_member_count",
        "determinism",
        "elapsed_seconds",
        "inventory",
        "limitations",
        "output_plus_scratch_limit_bytes",
        "preflight_base_estimate_bytes",
        "preflight_safety_margin_bytes",
        "preflight_uncompressed_bytes",
        "readback",
        "readback_report",
        "regular_member_bytes",
        "schema",
        "sdk_input",
        "source_authorities",
        "status",
        "vendor_sources",
    ];
    reject_unknown_fields(root, &allowed_root_fields, "source capsule manifest")?;
    if string_field(root, "schema")? != CAPSULE_SCHEMA {
        return Err(Refusal::new("source capsule manifest schema differs"));
    }

    let capsule = object_field(root, "capsule")?;
    reject_unknown_fields(
        capsule,
        &["bytes", "path", "sha256"],
        "source capsule identity",
    )?;
    if unsigned_field(capsule, "bytes")? != request.capsule_pin.bytes
        || string_field(capsule, "sha256")? != encode_hex(&request.capsule_pin.sha256)
        || string_field(capsule, "path")? != "csdk-corresponding-source.tar.xz"
    {
        return Err(Refusal::new(
            "source capsule manifest has a different capsule identity",
        ));
    }

    let raw_rows = root
        .get("inventory")
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::new("source capsule inventory must be an array"))?;
    let declared_count = usize_field(root, "capsule_member_count")?;
    if raw_rows.len() != declared_count || declared_count > MAX_MEMBERS {
        return Err(Refusal::new(
            "source capsule inventory member count differs or exceeds its bound",
        ));
    }
    let mut rows = BTreeMap::new();
    let mut selected_bytes = 0_u64;
    let mut regular_file_bytes = 0_u64;
    for raw_row in raw_rows {
        let row = raw_row
            .as_object()
            .ok_or_else(|| Refusal::new("source capsule inventory row must be an object"))?;
        let path = string_field(row, "path")?.to_owned();
        validate_inventory_path(&path)?;
        let origin = string_field(row, "origin")?;
        let _ = origin;
        let bytes = unsigned_field(row, "bytes")?;
        let mode = u32::try_from(unsigned_field(row, "mode")?)
            .map_err(|_| Refusal::new("source capsule inventory mode is not representable"))?;
        let (kind, sha256) = match string_field(row, "type")? {
            "directory" => {
                reject_unknown_fields(
                    row,
                    &["bytes", "mode", "origin", "path", "type"],
                    "source capsule directory row",
                )?;
                if bytes != 0 {
                    return Err(Refusal::new(
                        "source capsule directory row has nonzero bytes",
                    ));
                }
                (InventoryKind::Directory, None)
            }
            "file" => {
                reject_unknown_fields(
                    row,
                    &[
                        "bytes", "git_oid", "mode", "origin", "path", "sha256", "type",
                    ],
                    "source capsule file row",
                )?;
                if bytes > MAX_REGULAR_MEMBER_BYTES {
                    return Err(Refusal::new(
                        "source capsule inventory file exceeds the per-file bound",
                    ));
                }
                // The pinned capsule records upstream Git provenance for tracked
                // source files. Content integrity is still checked with SHA-256.
                if let Some(oid) = row.get("git_oid") {
                    let oid = oid.as_str().ok_or_else(|| {
                        Refusal::new("source capsule Git object identity must be a string")
                    })?;
                    if oid.len() != 40
                        || !oid
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    {
                        return Err(Refusal::new(
                            "source capsule Git object identity is invalid",
                        ));
                    }
                }
                let sha256 = parse_sha256(string_field(row, "sha256")?)?;
                regular_file_bytes = regular_file_bytes
                    .checked_add(bytes)
                    .ok_or_else(|| Refusal::new("source capsule regular byte total overflow"))?;
                if is_selected(&path) {
                    selected_bytes = selected_bytes
                        .checked_add(bytes)
                        .ok_or_else(|| Refusal::new("selected source byte total overflow"))?;
                }
                (InventoryKind::File, Some(sha256))
            }
            _ => {
                return Err(Refusal::new(
                    "source capsule inventory has an unknown member type",
                ));
            }
        };
        if rows
            .insert(
                path,
                InventoryEntry {
                    kind,
                    bytes,
                    mode,
                    sha256,
                },
            )
            .is_some()
        {
            return Err(Refusal::new(
                "source capsule inventory contains duplicate paths",
            ));
        }
    }
    if unsigned_field(root, "regular_member_bytes")? != regular_file_bytes {
        return Err(Refusal::new(
            "source capsule regular-file byte total differs",
        ));
    }
    if let Some(readback) = root.get("readback").and_then(Value::as_object)
        && (readback.get("member_count").and_then(Value::as_u64) != Some(declared_count as u64)
            || readback.get("regular_file_bytes").and_then(Value::as_u64)
                != Some(regular_file_bytes))
    {
        return Err(Refusal::new(
            "source capsule readback counts differ from its inventory",
        ));
    }
    if selected_bytes > MAX_SELECTED_BYTES {
        return Err(Refusal::new(
            "selected C-SDK source inputs exceed their bound",
        ));
    }
    let nested = rows
        .get(LIBAOM_ARCHIVE_PATH)
        .ok_or_else(|| Refusal::new("pinned original libaom archive is absent from inventory"))?;
    if nested.kind != InventoryKind::File || nested.sha256 != Some(request.nested_archive_sha256) {
        return Err(Refusal::new(
            "nested libaom archive differs from its explicit pin",
        ));
    }
    Ok(Inventory {
        rows,
        selected_bytes,
    })
}

fn validate_request_paths(request: &CsdkSourceMaterializationRequest) -> Result<()> {
    if request.capsule_pin.bytes == 0 || request.capsule_pin.bytes > CAPSULE_MAX_BYTES {
        return Err(Refusal::new(
            "source capsule compressed length is outside its format bound",
        ));
    }
    if request.manifest_pin.bytes == 0 || request.manifest_pin.bytes > MANIFEST_MAX_BYTES {
        return Err(Refusal::new(
            "source manifest length is outside its JSON profile",
        ));
    }
    let capsule = lexical_absolute(&request.capsule, "source capsule")?;
    let manifest = lexical_absolute(&request.manifest, "source manifest")?;
    let destination = lexical_absolute(&request.destination, "source destination")?;
    if paths_intersect(&capsule, &manifest)
        || paths_intersect(&capsule, &destination)
        || paths_intersect(&manifest, &destination)
    {
        return Err(Refusal::new(
            "source capsule, manifest, and destination paths overlap",
        ));
    }
    validate_generator_suffix(&request.nested_generator_path)?;
    Ok(())
}

fn lexical_absolute(path: &Path, label: &str) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(Refusal::new(format!("{label} must be absolute")));
    }
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => result.push("/"),
            Component::Normal(name) => result.push(name),
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(Refusal::new(format!(
                    "{label} contains unsupported traversal"
                )));
            }
        }
    }
    if !result.is_absolute() {
        return Err(Refusal::new(format!("{label} must be absolute")));
    }
    Ok(result)
}

fn paths_intersect(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn destination_parent_and_name(path: &Path) -> Result<(PathBuf, std::ffi::OsString)> {
    let normalized = lexical_absolute(path, "source destination")?;
    let name = normalized
        .file_name()
        .ok_or_else(|| Refusal::new("source destination must name a fresh directory"))?;
    if name.is_empty() || name == "." || name == ".." {
        return Err(Refusal::new(
            "source destination must name a fresh directory",
        ));
    }
    let parent = normalized
        .parent()
        .ok_or_else(|| Refusal::new("source destination parent is missing"))?;
    Ok((parent.to_path_buf(), name.to_os_string()))
}

fn validate_file_length(file: &File, expected: u64, label: &str) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not inspect {label}: {error}")))?;
    if !metadata.file_type().is_file() || metadata.len() != expected {
        return Err(Refusal::new(format!(
            "{label} type or byte length differs from its pin"
        )));
    }
    Ok(())
}

fn read_pinned_file(
    file: &mut File,
    pin: CsdkSourceFilePin,
    maximum_bytes: u64,
    checker: &CheckFn<'_>,
    label: &str,
) -> Result<Vec<u8>> {
    if pin.bytes > maximum_bytes {
        return Err(Refusal::new(format!("{label} exceeds its byte bound")));
    }
    file.seek(SeekFrom::Start(0))?;
    let capacity = usize::try_from(pin.bytes)
        .map_err(|_| Refusal::new("pinned input length is not representable"))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|error| {
        Refusal::new(format!(
            "could not allocate bounded manifest buffer: {error}"
        ))
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    while bytes.len() < capacity {
        checkpoint(checker, label)?;
        let read_limit = buffer.len().min(capacity - bytes.len());
        match file.read(&mut buffer[..read_limit]) {
            Ok(0) => {
                return Err(Refusal::new(
                    "pinned input ended before its declared length",
                ));
            }
            Ok(read) => {
                hasher.update(&buffer[..read]);
                bytes.extend_from_slice(&buffer[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Refusal::new(format!("could not read {label}: {error}"))),
        }
    }
    let mut extra = [0_u8; 1];
    checkpoint(checker, label)?;
    if file.read(&mut extra)? != 0 {
        return Err(Refusal::new("pinned input exceeds its declared length"));
    }
    let sha256: [u8; 32] = hasher.finalize().into();
    if sha256 != pin.sha256 {
        return Err(Refusal::new(format!(
            "{label} SHA-256 differs from its pin"
        )));
    }
    Ok(bytes)
}

fn hash_pinned_file(
    file: &mut File,
    pin: CsdkSourceFilePin,
    checker: &CheckFn<'_>,
    label: &str,
) -> Result<()> {
    let (bytes, sha256) = hash_file(file, checker, label)?;
    if bytes != pin.bytes || sha256 != pin.sha256 {
        return Err(Refusal::new(format!("{label} differs from its pin")));
    }
    Ok(())
}

fn hash_file(file: &mut File, checker: &CheckFn<'_>, label: &str) -> Result<(u64, [u8; 32])> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        checkpoint(checker, label)?;
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                bytes = bytes
                    .checked_add(read as u64)
                    .ok_or_else(|| Refusal::new("pinned input byte count overflow"))?;
                hasher.update(&buffer[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Refusal::new(format!("could not hash {label}: {error}"))),
        }
    }
    let sha256: [u8; 32] = hasher.finalize().into();
    Ok((bytes, sha256))
}

struct HashingInput<'a> {
    inner: File,
    expected: CsdkSourceFilePin,
    bytes: u64,
    hasher: Sha256,
    checker: CheckFn<'a>,
    callback_failure: CallbackFailure,
    label: &'static str,
}

impl<'a> HashingInput<'a> {
    fn new(
        inner: File,
        expected: CsdkSourceFilePin,
        checker: CheckFn<'a>,
        callback_failure: CallbackFailure,
        label: &'static str,
    ) -> Self {
        Self {
            inner,
            expected,
            bytes: 0,
            hasher: Sha256::new(),
            checker,
            callback_failure,
            label,
        }
    }

    fn finish(self) -> (File, u64, [u8; 32]) {
        let sha256: [u8; 32] = self.hasher.finalize().into();
        (self.inner, self.bytes, sha256)
    }
}

impl Read for HashingInput<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.callback_failure.borrow().is_some() {
            return Err(io::Error::other("resource callback previously refused"));
        }
        if let Err(error) = checkpoint(&self.checker, self.label) {
            *self.callback_failure.borrow_mut() = Some(error);
            return Err(io::Error::other("cancellation callback refused"));
        }
        if self.bytes == self.expected.bytes {
            let mut probe = [0_u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pinned input exceeds its byte length",
                )),
            };
        }
        let remaining = self.expected.bytes - self.bytes;
        let read_limit = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let read = self.inner.read(&mut buffer[..read_limit])?;
        self.bytes = self.bytes.checked_add(read as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "pinned byte count overflow")
        })?;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

struct BoundedDecodedReader<R> {
    inner: R,
    maximum: u64,
    bytes: u64,
}

impl<R> BoundedDecodedReader<R> {
    fn new(inner: R, maximum: u64) -> Self {
        Self {
            inner,
            maximum,
            bytes: 0,
        }
    }

    fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for BoundedDecodedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.bytes == self.maximum {
            let mut probe = [0_u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "decoded TAR exceeds its byte bound",
                )),
            };
        }
        let remaining = self.maximum - self.bytes;
        let read_limit = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let read = self.inner.read(&mut buffer[..read_limit])?;
        self.bytes = self.bytes.checked_add(read as u64).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "decoded TAR byte count overflow",
            )
        })?;
        Ok(read)
    }
}

fn drain_input<R: Read>(
    reader: &mut R,
    checker: &CheckFn<'_>,
    callback_failure: &CallbackFailure,
    label: &str,
) -> Result<()> {
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        checkpoint(checker, label)?;
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(callback_or_io(
                    callback_failure,
                    &format!("could not drain {label}"),
                    error,
                ));
            }
        }
    }
}

fn drain_zero_padding<R: Read>(
    reader: &mut R,
    checker: &CheckFn<'_>,
    callback_failure: &CallbackFailure,
    label: &str,
) -> Result<()> {
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        checkpoint(checker, "draining complete decoded TAR stream")?;
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => {
                if !buffer[..read].iter().all(|byte| *byte == 0) {
                    return Err(Refusal::new(format!(
                        "nonzero data follows the {label} end marker"
                    )));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(callback_or_io(
                    callback_failure,
                    "could not drain decoded TAR",
                    error,
                ));
            }
        }
    }
}

fn create_output_parent(
    root: &Directory,
    relative_parent: &str,
    created: &mut BTreeSet<String>,
) -> Result<Directory> {
    if relative_parent.is_empty() {
        return root.relative_directory("");
    }
    validate_inventory_path(relative_parent)?;
    let mut current = root.relative_directory("")?;
    let mut prefix = String::new();
    let components: Vec<&str> = relative_parent.split('/').collect();
    if components.len() > MAX_PATH_COMPONENTS {
        return Err(Refusal::new(
            "selected output path exceeds the component bound",
        ));
    }
    for component in components {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(component);
        current = if created.contains(&prefix) {
            current.child(std::ffi::OsStr::new(component))?
        } else {
            let child = current.mkdir_new(std::ffi::OsStr::new(component), 0o700)?;
            created.insert(prefix.clone());
            child
        };
    }
    Ok(current)
}

fn normalized_tar_path(raw: &[u8], is_directory: bool) -> Result<String> {
    let raw =
        std::str::from_utf8(raw).map_err(|_| Refusal::new("TAR member path is not valid UTF-8"))?;
    let path = if is_directory && raw.ends_with('/') {
        if raw.ends_with("//") {
            return Err(Refusal::new("TAR directory path is not normalized"));
        }
        &raw[..raw.len() - 1]
    } else {
        raw
    };
    validate_inventory_path(path)?;
    Ok(path.to_owned())
}

fn validate_inventory_path(path: &str) -> Result<()> {
    validate_relative_inventory_path(path)?;
    if path.len() > MAX_PATH_BYTES || path.split('/').count() > MAX_PATH_COMPONENTS {
        return Err(Refusal::new("source capsule path exceeds its format bound"));
    }
    Ok(())
}

fn split_relative_parent(path: &str) -> Result<(&str, &std::ffi::OsStr)> {
    validate_inventory_path(path)?;
    let path = Path::new(path);
    let basename = path
        .file_name()
        .ok_or_else(|| Refusal::new("source output path has no basename"))?;
    let parent = path
        .parent()
        .and_then(Path::to_str)
        .filter(|parent| *parent != ".")
        .unwrap_or("");
    Ok((parent, basename))
}

fn validate_generator_suffix(path: &str) -> Result<()> {
    validate_inventory_path(path)?;
    if path.starts_with("sources/") || path.starts_with("libaom-3.12.1/") {
        return Err(Refusal::new(
            "nested generator path must be relative to the libaom source root",
        ));
    }
    Ok(())
}

fn is_selected(path: &str) -> bool {
    path.starts_with("sources/")
        || path.starts_with("generated/")
        || path.starts_with("recipes/")
        || path == LIBAOM_ARCHIVE_PATH
}

fn parse_sha256(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Refusal::new(
            "source capsule SHA-256 must be lowercase hexadecimal",
        ));
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| Refusal::new("source capsule SHA-256 is malformed"))?;
    }
    Ok(digest)
}

fn reject_unknown_fields(object: &Map<String, Value>, allowed: &[&str], label: &str) -> Result<()> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(Refusal::new(format!("{label} contains an unknown field")));
    }
    Ok(())
}

fn object_field<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Map<String, Value>> {
    object.get(key).and_then(Value::as_object).ok_or_else(|| {
        Refusal::new(format!(
            "source capsule manifest field {key} must be an object"
        ))
    })
}

fn string_field<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    object.get(key).and_then(Value::as_str).ok_or_else(|| {
        Refusal::new(format!(
            "source capsule manifest field {key} must be a string"
        ))
    })
}

fn unsigned_field(object: &Map<String, Value>, key: &str) -> Result<u64> {
    object.get(key).and_then(Value::as_u64).ok_or_else(|| {
        Refusal::new(format!(
            "source capsule manifest field {key} must be unsigned"
        ))
    })
}

fn usize_field(object: &Map<String, Value>, key: &str) -> Result<usize> {
    usize::try_from(unsigned_field(object, key)?).map_err(|_| {
        Refusal::new(format!(
            "source capsule manifest field {key} is not representable"
        ))
    })
}

fn checkpoint(checker: &CheckFn<'_>, label: &str) -> Result<()> {
    (checker.borrow_mut())(label)
}

fn callback_or_io(callback_failure: &CallbackFailure, context: &str, error: io::Error) -> Refusal {
    callback_failure
        .borrow_mut()
        .take()
        .unwrap_or_else(|| Refusal::new(format!("{context}: {error}")))
}

fn recovery_refusal(error: Refusal, destination: &Path) -> Refusal {
    Refusal::new(format!(
        "{error}; partial private source tree retained at {} for caller recovery",
        destination.display()
    ))
}

#[cfg(test)]
mod tests;
