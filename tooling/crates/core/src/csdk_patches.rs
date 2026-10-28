//! Apply the pinned, ordered portable C-SDK source patch series.
//!
//! The caller authenticates the series pin and owns process supervision,
//! cancellation, aggregate resource accounting, and recovery of staging after a
//! failed or partial patch. This module validates all declared inputs before
//! the first process is started and retains no success receipt on failure.
//! Descriptor-relative access rejects symlink path components, but does not
//! freeze bytes against a concurrent writer outside the owner model.

use std::{
    collections::BTreeSet,
    ffi::{OsStr, OsString},
    fs::File,
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
    time::Duration,
};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    Refusal, Result,
    csdk_source::{CsdkSourceFilePin, CsdkSourceRoots},
    digest::{encode_hex, is_sha256_digest},
    directory::Directory,
    files::validate_relative_inventory_path,
    json::{JsonProfile, parse_json_value},
};

const SERIES_NAME: &str = "series.json";
const PATCH_MAX_BYTES: u64 = JsonProfile::ReleaseManifestAndInstallReceipt.max_bytes() as u64;
const SOURCE_MAX_BYTES: u64 = 96 * 1024 * 1024;
const IO_BUFFER_BYTES: usize = 64 * 1024;
const PATCH_SCHEMA: &str = "ami-rust-portable-csdk-patches-v1";

struct PatchRow {
    component: String,
    path: String,
    patch: String,
    before_sha256: String,
    after_sha256: String,
    patch_sha256: String,
}

struct SourceRoot {
    component: &'static str,
    path: PathBuf,
    directory: Directory,
    identity: DirectoryIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    mode: u32,
}

#[derive(Clone, Copy)]
struct InputIdentity {
    source_parent: DirectoryIdentity,
    source_file: FileIdentity,
    patch_parent: DirectoryIdentity,
    patch_file: FileIdentity,
}

struct PatchSeries {
    rows: Vec<PatchRow>,
    file_identity: FileIdentity,
}

struct PatchInvocation<'a> {
    patch_directory: &'a Path,
    patch_root: &'a Directory,
    patch_root_identity: DirectoryIdentity,
    series: &'a PatchSeries,
    series_pin: CsdkSourceFilePin,
}

struct PatchExecution<'a, Run, Checkpoint> {
    run: &'a mut Run,
    checkpoint: &'a mut Checkpoint,
    runner_invoked: &'a mut bool,
}

/// Apply the authenticated series in declared order under the caller's process
/// supervisor. Partial changes are left in the owned staging tree for recovery.
pub fn apply_csdk_source_patches(
    roots: &CsdkSourceRoots,
    patch_directory: &Path,
    series_pin: CsdkSourceFilePin,
    mut run: impl FnMut(&[OsString], &Path, &str, Duration) -> Result<()>,
    mut checkpoint: impl FnMut(&str) -> Result<()>,
) -> Result<Vec<Value>> {
    validate_absolute_path(&roots.destination, "C-SDK source destination")?;
    validate_absolute_path(patch_directory, "C-SDK patch directory")?;
    let expected_roots = [
        roots.destination.join("sources/AROS-NX"),
        roots.destination.join("sources/aros-tools"),
        roots.destination.join("sources/libaom"),
    ];
    if roots.aros_nx != expected_roots[0]
        || roots.aros_tools != expected_roots[1]
        || roots.libaom != expected_roots[2]
    {
        return Err(Refusal::new(
            "C-SDK source roots do not match destination/sources component layout",
        ));
    }

    checkpoint("before opening C-SDK patch inputs")?;
    let destination = Directory::open(&roots.destination)?;
    let sources = destination.relative_directory("sources")?;
    let source_roots = [
        open_source_root("AROS-NX", &roots.aros_nx, &sources)?,
        open_source_root("aros-tools", &roots.aros_tools, &sources)?,
        open_source_root("libaom", &roots.libaom, &sources)?,
    ];
    let patch_root = Directory::open(patch_directory)?;
    let patch_root_identity = directory_identity(&patch_root)?;
    let series = read_patch_series(&patch_root, series_pin, &mut checkpoint)?;

    let mut targets = BTreeSet::new();
    for row in &series.rows {
        if !targets.insert((row.component.as_str(), row.path.as_str())) {
            return Err(Refusal::new(format!(
                "patch series contains an ambiguous duplicate target: {}/{}",
                row.component, row.path
            )));
        }
    }

    // Verify every declared preimage and patch before any external process can
    // mutate staging. The captured identities are checked again around each run.
    let mut input_identities = Vec::with_capacity(series.rows.len());
    for (index, row) in series.rows.iter().enumerate() {
        checkpoint("prechecking declared C-SDK source patch")
            .map_err(|error| row_context(error, index, row, false))?;
        let source = source_root(&source_roots, &row.component)
            .ok_or_else(|| Refusal::new("unsupported C-SDK patch component"))?;
        let source_snapshot = source_snapshot(source, &row.path, &mut checkpoint)
            .map_err(|error| row_context(error, index, row, false))?;
        if source_snapshot.sha256 != row.before_sha256 {
            return Err(row_context(
                Refusal::new("source preimage hash differs from the patch series"),
                index,
                row,
                false,
            ));
        }
        let patch_snapshot = patch_snapshot(&patch_root, row, &mut checkpoint)
            .map_err(|error| row_context(error, index, row, false))?;
        input_identities.push(InputIdentity {
            source_parent: source_snapshot.parent,
            source_file: source_snapshot.file,
            patch_parent: patch_snapshot.parent,
            patch_file: patch_snapshot.file,
        });
    }

    let mut receipts = Vec::with_capacity(series.rows.len());
    let invocation = PatchInvocation {
        patch_directory,
        patch_root: &patch_root,
        patch_root_identity,
        series: &series,
        series_pin,
    };
    for (index, (row, identities)) in series.rows.iter().zip(&input_identities).enumerate() {
        let partial = !receipts.is_empty();
        let checkpoint_label = if partial {
            "between C-SDK source patch mutations"
        } else {
            "before first C-SDK source patch mutation"
        };
        checkpoint(checkpoint_label).map_err(|error| row_context(error, index, row, partial))?;
        let source = source_root(&source_roots, &row.component)
            .ok_or_else(|| Refusal::new("unsupported C-SDK patch component"))?;
        let mut runner_invoked = false;
        let result = {
            let mut execution = PatchExecution {
                run: &mut run,
                checkpoint: &mut checkpoint,
                runner_invoked: &mut runner_invoked,
            };
            apply_one_patch(source, &invocation, row, *identities, index, &mut execution)
        };
        match result {
            Ok(receipt) => receipts.push(receipt),
            Err(error) => {
                return Err(row_context(error, index, row, partial || runner_invoked));
            }
        }
    }
    Ok(receipts)
}

fn open_source_root(
    component: &'static str,
    path: &Path,
    sources: &Directory,
) -> Result<SourceRoot> {
    let directory = sources.child(OsStr::new(component))?;
    Ok(SourceRoot {
        component,
        path: path.to_path_buf(),
        identity: directory_identity(&directory)?,
        directory,
    })
}

fn source_root<'a>(roots: &'a [SourceRoot; 3], component: &str) -> Option<&'a SourceRoot> {
    roots.iter().find(|root| root.component == component)
}

fn read_patch_series(
    patch_root: &Directory,
    pin: CsdkSourceFilePin,
    checkpoint: &mut impl FnMut(&str) -> Result<()>,
) -> Result<PatchSeries> {
    let (_parent, mut file, parent_identity, file_identity) =
        open_relative_file(patch_root, SERIES_NAME)?;
    if parent_identity != directory_identity(patch_root)? {
        return Err(Refusal::new(
            "patch series parent directory identity differs",
        ));
    }
    let bytes = read_bounded(
        &mut file,
        PATCH_MAX_BYTES,
        Some(pin.bytes),
        checkpoint,
        "reading pinned C-SDK patch series",
    )?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if digest != pin.sha256 {
        return Err(Refusal::new(
            "C-SDK patch series bytes differ from their pin",
        ));
    }
    let value = parse_json_value(&bytes, JsonProfile::ReleaseManifestAndInstallReceipt)?;
    Ok(PatchSeries {
        rows: parse_rows(&value)?,
        file_identity,
    })
}

fn parse_rows(value: &Value) -> Result<Vec<PatchRow>> {
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new("C-SDK patch series must be an object"))?;
    if object.get("schema").and_then(Value::as_str) != Some(PATCH_SCHEMA) {
        return Err(Refusal::new("unrecognized C-SDK patch series schema"));
    }
    let rows = object
        .get("patches")
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::new("C-SDK patch series must contain a patches array"))?;
    rows.iter().map(parse_row).collect()
}

fn parse_row(value: &Value) -> Result<PatchRow> {
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new("C-SDK patch series row must be an object"))?;
    let required = |field: &'static str| -> Result<String> {
        object
            .get(field)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| Refusal::new(format!("C-SDK patch row {field} must be a string")))
    };
    let component = required("component")?;
    if !matches!(component.as_str(), "AROS-NX" | "aros-tools" | "libaom") {
        return Err(Refusal::new("unsupported C-SDK patch component"));
    }
    let path = required("path")?;
    let patch = required("patch")?;
    validate_relative_inventory_path(&path)?;
    validate_relative_inventory_path(&patch)?;
    let before_sha256 = required_digest(&required("before_sha256")?, "before_sha256")?;
    let after_sha256 = required_digest(&required("after_sha256")?, "after_sha256")?;
    let patch_sha256 = required_digest(&required("patch_sha256")?, "patch_sha256")?;
    Ok(PatchRow {
        component,
        path,
        patch,
        before_sha256,
        after_sha256,
        patch_sha256,
    })
}

fn required_digest(value: &str, field: &str) -> Result<String> {
    if !is_sha256_digest(value) {
        return Err(Refusal::new(format!(
            "C-SDK patch row {field} must be lowercase SHA-256"
        )));
    }
    Ok(value.to_owned())
}

struct FileSnapshot {
    parent: DirectoryIdentity,
    file: FileIdentity,
    sha256: String,
}

fn source_snapshot(
    source: &SourceRoot,
    path: &str,
    checkpoint: &mut impl FnMut(&str) -> Result<()>,
) -> Result<FileSnapshot> {
    let (_parent, mut file, parent_identity, file_identity) =
        open_relative_file(&source.directory, path)?;
    let sha256 = hash_file(
        &mut file,
        SOURCE_MAX_BYTES,
        checkpoint,
        "hashing C-SDK source file",
    )?;
    Ok(FileSnapshot {
        parent: parent_identity,
        file: file_identity,
        sha256,
    })
}

fn patch_snapshot(
    patch_root: &Directory,
    row: &PatchRow,
    checkpoint: &mut impl FnMut(&str) -> Result<()>,
) -> Result<FileSnapshot> {
    let (_parent, mut file, parent_identity, file_identity) =
        open_relative_file(patch_root, &row.patch)?;
    let bytes = read_bounded(
        &mut file,
        PATCH_MAX_BYTES,
        None,
        checkpoint,
        "reading C-SDK patch text",
    )?;
    if crate::digest::sha256_bytes(&bytes) != row.patch_sha256 {
        return Err(Refusal::new(
            "source patch bytes differ from the series pin",
        ));
    }
    validate_patch_headers(&bytes, &row.path)?;
    Ok(FileSnapshot {
        parent: parent_identity,
        file: file_identity,
        sha256: row.patch_sha256.clone(),
    })
}

fn validate_patch_headers(bytes: &[u8], source_path: &str) -> Result<()> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| Refusal::new(format!("source patch is not UTF-8 text: {error}")))?;
    if text.as_bytes().contains(&0) {
        return Err(Refusal::new("source patch contains a NUL byte"));
    }
    let headers: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("--- ") || line.starts_with("+++ "))
        .collect();
    let expected_before = format!("--- a/{source_path}");
    let expected_after = format!("+++ b/{source_path}");
    if headers.len() != 2 || headers[0] != expected_before || headers[1] != expected_after {
        return Err(Refusal::new(
            "source patch must contain exactly its declared before and after file headers",
        ));
    }
    Ok(())
}

fn apply_one_patch<Run, Checkpoint>(
    source: &SourceRoot,
    invocation: &PatchInvocation<'_>,
    row: &PatchRow,
    expected: InputIdentity,
    index: usize,
    execution: &mut PatchExecution<'_, Run, Checkpoint>,
) -> Result<Value>
where
    Run: FnMut(&[OsString], &Path, &str, Duration) -> Result<()>,
    Checkpoint: FnMut(&str) -> Result<()>,
{
    ensure_directory_identity(&source.path, source.identity)?;
    ensure_directory_identity(invocation.patch_directory, invocation.patch_root_identity)?;
    verify_series_path(
        invocation.patch_root,
        invocation.series_pin,
        invocation.series.file_identity,
        execution.checkpoint,
    )?;

    let before = source_snapshot(source, &row.path, execution.checkpoint)?;
    if before.parent != expected.source_parent
        || before.file != expected.source_file
        || before.sha256 != row.before_sha256
    {
        return Err(Refusal::new(
            "source preimage path, identity, or hash changed before patch execution",
        ));
    }
    let patch = patch_snapshot(invocation.patch_root, row, execution.checkpoint)?;
    if patch.parent != expected.patch_parent || patch.file != expected.patch_file {
        return Err(Refusal::new(
            "source patch path identity changed before patch execution",
        ));
    }

    let patch_path = invocation.patch_directory.join(&row.patch);
    let arguments = [
        OsString::from("/usr/bin/patch"),
        OsString::from("--batch"),
        OsString::from("--forward"),
        OsString::from("--fuzz=0"),
        OsString::from("-p1"),
        OsString::from("-i"),
        patch_path.as_os_str().to_owned(),
    ];
    let label = format!("patch-{index}-{}", row.component);
    *execution.runner_invoked = true;
    (execution.run)(&arguments, &source.path, &label, Duration::from_secs(30))?;

    (execution.checkpoint)("after C-SDK source patch process")?;
    ensure_directory_identity(&source.path, source.identity)?;
    ensure_directory_identity(invocation.patch_directory, invocation.patch_root_identity)?;
    verify_series_path(
        invocation.patch_root,
        invocation.series_pin,
        invocation.series.file_identity,
        execution.checkpoint,
    )?;
    let after = source_snapshot(source, &row.path, execution.checkpoint)?;
    if after.parent != expected.source_parent || after.sha256 != row.after_sha256 {
        return Err(Refusal::new(
            "patched source path identity or after-image hash differs from the series",
        ));
    }
    let patch_after = patch_snapshot(invocation.patch_root, row, execution.checkpoint)?;
    if patch_after.parent != expected.patch_parent
        || patch_after.file != expected.patch_file
        || patch_after.sha256 != row.patch_sha256
    {
        return Err(Refusal::new(
            "source patch file identity or hash changed during patch execution",
        ));
    }

    Ok(serde_json::json!({
        "component": row.component,
        "path": row.path,
        "before_sha256": row.before_sha256,
        "after_sha256": row.after_sha256,
        "patch_sha256": row.patch_sha256,
    }))
}

fn verify_series_path(
    patch_root: &Directory,
    pin: CsdkSourceFilePin,
    expected_file: FileIdentity,
    checkpoint: &mut impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    let (_parent, mut file, parent_identity, file_identity) =
        open_relative_file(patch_root, SERIES_NAME)?;
    if parent_identity != directory_identity(patch_root)? || file_identity != expected_file {
        return Err(Refusal::new("pinned patch series path identity changed"));
    }
    let bytes = read_bounded(
        &mut file,
        PATCH_MAX_BYTES,
        Some(pin.bytes),
        checkpoint,
        "rechecking pinned C-SDK patch series",
    )?;
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if digest != pin.sha256 {
        return Err(Refusal::new("C-SDK patch series bytes changed"));
    }
    Ok(())
}

fn open_relative_file(
    root: &Directory,
    path: &str,
) -> Result<(Directory, File, DirectoryIdentity, FileIdentity)> {
    validate_relative_inventory_path(path)?;
    let (parent_path, basename) = match path.rsplit_once('/') {
        Some((parent, basename)) => (parent, basename),
        None => ("", path),
    };
    let parent = root.relative_directory(parent_path)?;
    let parent_identity = directory_identity(&parent)?;
    let file = parent.regular(OsStr::new(basename))?;
    let file_identity = file_identity(&file)?;
    Ok((parent, file, parent_identity, file_identity))
}

fn read_bounded(
    file: &mut File,
    maximum: u64,
    expected_length: Option<u64>,
    checkpoint: &mut impl FnMut(&str) -> Result<()>,
    label: &str,
) -> Result<Vec<u8>> {
    let initial_length = file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not inspect bounded input: {error}")))?
        .len();
    if initial_length > maximum {
        return Err(Refusal::new("bounded input exceeds its format size"));
    }
    if expected_length.is_some_and(|length| length != initial_length) {
        return Err(Refusal::new("bounded input length differs from its pin"));
    }
    let initial_capacity = usize::try_from(initial_length)
        .map_err(|_| Refusal::new("bounded input length cannot fit in memory"))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(initial_capacity).map_err(|error| {
        Refusal::new(format!("could not allocate bounded input buffer: {error}"))
    })?;
    let over_limit = maximum
        .checked_add(1)
        .ok_or_else(|| Refusal::new("bounded input limit cannot be incremented"))?;
    let mut buffer = [0_u8; IO_BUFFER_BYTES];
    loop {
        checkpoint(label)?;
        let remaining = over_limit.saturating_sub(bytes.len() as u64);
        let read_limit = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        if read_limit == 0 {
            return Err(Refusal::new("bounded input exceeds its format size"));
        }
        match file.read(&mut buffer[..read_limit]) {
            Ok(0) => break,
            Ok(read) => {
                bytes.try_reserve(read).map_err(|error| {
                    Refusal::new(format!("could not grow bounded input buffer: {error}"))
                })?;
                bytes.extend_from_slice(&buffer[..read]);
                if bytes.len() as u64 > maximum {
                    return Err(Refusal::new("bounded input exceeds its format size"));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not read bounded input: {error}"
                )));
            }
        }
    }
    if expected_length.is_some_and(|length| length != bytes.len() as u64) {
        return Err(Refusal::new("bounded input length changed while reading"));
    }
    let final_length = file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not recheck bounded input: {error}")))?
        .len();
    if final_length != bytes.len() as u64 {
        return Err(Refusal::new("bounded input changed while reading"));
    }
    Ok(bytes)
}

fn hash_file(
    file: &mut File,
    maximum: u64,
    checkpoint: &mut impl FnMut(&str) -> Result<()>,
    label: &str,
) -> Result<String> {
    let initial_length = file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not inspect source file: {error}")))?
        .len();
    if initial_length > maximum {
        return Err(Refusal::new("source file exceeds the per-file read bound"));
    }
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; IO_BUFFER_BYTES];
    loop {
        checkpoint(label)?;
        let remaining = maximum.saturating_sub(total);
        let read_limit = buffer
            .len()
            .min(usize::try_from(remaining.saturating_add(1)).unwrap_or(usize::MAX));
        if read_limit == 0 {
            return Err(Refusal::new("source file exceeds the per-file read bound"));
        }
        match file.read(&mut buffer[..read_limit]) {
            Ok(0) => break,
            Ok(read) => {
                total = total
                    .checked_add(read as u64)
                    .ok_or_else(|| Refusal::new("source file byte count overflow"))?;
                if total > maximum {
                    return Err(Refusal::new("source file exceeds the per-file read bound"));
                }
                hasher.update(&buffer[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Refusal::new(format!("could not hash source file: {error}"))),
        }
    }
    let final_length = file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not recheck source file: {error}")))?
        .len();
    if total != initial_length || final_length != initial_length {
        return Err(Refusal::new("source file changed while it was hashed"));
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(encode_hex(&digest))
}

fn directory_identity(directory: &Directory) -> Result<DirectoryIdentity> {
    let metadata = directory.metadata()?;
    Ok(DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
    })
}

fn file_identity(file: &File) -> Result<FileIdentity> {
    let metadata = file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not inspect regular file: {error}")))?;
    if !metadata.file_type().is_file() {
        return Err(Refusal::new("opened patch input is not a regular file"));
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
    })
}

fn ensure_directory_identity(path: &Path, expected: DirectoryIdentity) -> Result<()> {
    let opened = Directory::open(path)?;
    if directory_identity(&opened)? != expected {
        return Err(Refusal::new(
            "C-SDK patch root path identity changed during patch application",
        ));
    }
    Ok(())
}

fn validate_absolute_path(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute() {
        return Err(Refusal::new(format!("{label} must be absolute")));
    }
    let mut has_root = false;
    let mut normal_components = 0_usize;
    for component in path.components() {
        match component {
            Component::RootDir => has_root = true,
            Component::Normal(_) => normal_components += 1,
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(Refusal::new(format!(
                    "{label} contains a non-canonical or traversing component"
                )));
            }
        }
    }
    if !has_root || normal_components == 0 {
        return Err(Refusal::new(format!(
            "{label} is not a usable absolute path"
        )));
    }
    Ok(())
}

fn row_context(error: Refusal, index: usize, row: &PatchRow, partial: bool) -> Refusal {
    let status = if partial {
        "the owned staging may contain partial patch changes and was left for recovery"
    } else {
        "no patch process was invoked for this row"
    };
    Refusal::new(format!(
        "C-SDK patch row {index} ({}:{}): {error}; {status}",
        row.component, row.path
    ))
    .with_exit_code(error.exit_code())
}

#[cfg(test)]
mod tests;
