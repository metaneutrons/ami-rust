//! Authenticated staging of the original portable C-SDK archive.
//!
//! This is producer staging only. A successful receipt describes a verified
//! tree suitable for the producer's later work; it does not install or accept
//! a public component. The shared component extractor authenticates the pinned
//! XZ archive on both passes, and the shared inventory verifier checks the
//! complete regular-file profile before the tree is returned.

use crate::{
    Refusal, Result,
    component_archive::{
        ArchiveFormat, ArchiveLimits, ComponentArchiveSpec, extract_component_archive,
    },
    csdk_source::CsdkSourceFilePin,
    digest::{encode_hex, is_sha256_digest},
    directory::Directory,
    files::{open_regular_nofollow, validate_relative_inventory_path},
    inventory::{FileIdentity, InventoryLimits, verify_complete_directory_checked},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

const CSDK_ROOT: &str = "Developer";
const ARCHIVE_TREE: &str = "archive";

/// Inputs for extraction of an authenticated original C-SDK archive.
pub struct CsdkStagingRequest {
    /// Absolute archive path, opened without following links.
    pub archive: PathBuf,
    /// Caller-authenticated compressed archive length and SHA-256.
    pub archive_pin: CsdkSourceFilePin,
    /// Historical regular-file profile relative to `Developer`; mode is omitted.
    pub profile: Vec<FileIdentity>,
    /// Fresh absolute leaf directory, below an existing parent, for private archive staging.
    pub destination: PathBuf,
    /// Caller-selected extraction resource bounds.
    pub limits: ArchiveLimits,
}

/// Verified original staging tree. File modes are the extracted original
/// permission bits masked to `0o777`, matching the historical producer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CsdkStagingReceipt {
    /// Extracted `Developer` directory, still inside producer staging.
    pub developer: PathBuf,
    /// Original permission bits keyed by path relative to `Developer`.
    pub modes: BTreeMap<String, u32>,
    /// Sum of verified regular-file payload bytes.
    pub file_bytes: u64,
    /// Number of verified regular files.
    pub files: usize,
}

/// Extract and verify the original C-SDK into a fresh, retained staging
/// container. Any error after the container is created names its path and
/// leaves it in place for diagnosis; failed output is never returned as a
/// receipt.
pub fn stage_original_csdk(
    request: CsdkStagingRequest,
    mut checkpoint: impl FnMut(&str) -> Result<()>,
) -> Result<CsdkStagingReceipt> {
    validate_absolute_no_parent(&request.archive, "original C-SDK archive")?;
    validate_absolute_no_parent(&request.destination, "original C-SDK destination")?;
    validate_profile(
        &request.profile,
        request.limits.max_members,
        &mut checkpoint,
    )?;
    let inventory_limits = inventory_limits(request.limits)?;
    checkpoint("opening original C-SDK archive")?;

    let archive = open_regular_nofollow(&request.archive)?;
    let destination_name = request
        .destination
        .file_name()
        .filter(|name| *name != OsStr::new(".") && *name != OsStr::new(".."))
        .ok_or_else(|| Refusal::new("original C-SDK destination must name a leaf directory"))?;
    let destination_parent_path = request
        .destination
        .parent()
        .ok_or_else(|| Refusal::new("original C-SDK destination must have an existing parent"))?;
    if !destination_parent_path.is_absolute() {
        return Err(Refusal::new(
            "original C-SDK destination parent must be absolute",
        ));
    }
    let destination_parent = Directory::open(destination_parent_path)?;
    let destination_parent_canonical =
        fs::canonicalize(destination_parent_path).map_err(|error| {
            Refusal::new(format!(
                "could not resolve C-SDK destination parent: {error}"
            ))
        })?;
    let canonical_parent = Directory::open(&destination_parent_canonical)?;
    let retained_parent_metadata = destination_parent.metadata()?;
    let canonical_parent_metadata = canonical_parent.metadata()?;
    if retained_parent_metadata.dev() != canonical_parent_metadata.dev()
        || retained_parent_metadata.ino() != canonical_parent_metadata.ino()
    {
        return Err(Refusal::new(
            "original C-SDK destination parent changed while it was opened",
        ));
    }
    let destination_path = destination_parent_canonical.join(destination_name);
    reject_source_destination_overlap(&request.archive, &destination_path, &archive)?;

    checkpoint("creating original C-SDK staging container")?;
    let mut destination_created = false;
    let destination_root =
        match destination_parent
            .mkdir_new_tracked(destination_name, 0o700, || destination_created = true)
        {
            Ok(root) => root,
            Err(error) if destination_created => {
                return Err(retained_failure(
                    &destination_path,
                    format!("could not open the newly created staging container: {error}"),
                ));
            }
            Err(error) => return Err(error),
        };

    let archive_sha256 = encode_hex(&request.archive_pin.sha256);
    let archive_receipt = extract_component_archive(
        archive,
        &destination_root,
        ComponentArchiveSpec {
            destination_name: OsStr::new(ARCHIVE_TREE),
            compressed_bytes: request.archive_pin.bytes,
            compressed_sha256: &archive_sha256,
            format: ArchiveFormat::TarXz,
            limits: request.limits,
        },
        || checkpoint("authenticating and extracting original C-SDK archive"),
    )
    .map_err(|failure| {
        let detail = match failure.recovery_entry {
            Some(entry) => format!(
                "{}; extractor recovery entry remains at {}",
                failure.reason,
                destination_path.join(entry).display()
            ),
            None => failure.reason.to_string(),
        };
        retained_failure(
            &destination_path,
            format!("original C-SDK archive extraction failed: {detail}"),
        )
    })?;

    if archive_receipt.component_root != CSDK_ROOT {
        return Err(retained_failure(
            &destination_path,
            format!(
                "original C-SDK archive root is {:?}, expected {CSDK_ROOT}",
                archive_receipt.component_root
            ),
        ));
    }
    let developer = destination_root
        .relative_directory(&format!("{ARCHIVE_TREE}/{CSDK_ROOT}"))
        .map_err(|error| {
            retained_failure(
                &destination_path,
                format!("could not open extracted Developer directory: {error}"),
            )
        })?;
    let measured = verify_complete_directory_checked(
        &developer,
        &request.profile,
        &[],
        inventory_limits,
        || checkpoint("verifying original C-SDK file profile"),
    )
    .map_err(|error| {
        retained_failure(
            &destination_path,
            format!("original C-SDK profile verification failed: {error}"),
        )
    })?;

    let mut modes = BTreeMap::new();
    for identity in &request.profile {
        checkpoint("capturing original C-SDK file permissions").map_err(|error| {
            retained_failure(
                &destination_path,
                format!("could not finish original C-SDK mode capture: {error}"),
            )
        })?;
        let (parent_path, leaf) = identity
            .path
            .rsplit_once('/')
            .unwrap_or(("", &identity.path));
        let parent = developer.relative_directory(parent_path).map_err(|error| {
            retained_failure(
                &destination_path,
                format!("could not resolve original C-SDK profile path: {error}"),
            )
        })?;
        let file = parent.regular(OsStr::new(leaf)).map_err(|error| {
            retained_failure(
                &destination_path,
                format!("could not reopen verified C-SDK profile file: {error}"),
            )
        })?;
        let metadata = file.metadata().map_err(|error| {
            retained_failure(
                &destination_path,
                format!("could not inspect original C-SDK file mode: {error}"),
            )
        })?;
        if metadata.nlink() != 1 {
            return Err(retained_failure(
                &destination_path,
                "original C-SDK profile contains a hard-linked file".to_owned(),
            ));
        }
        let mode = metadata.permissions().mode();
        if mode & 0o7000 != 0 {
            return Err(retained_failure(
                &destination_path,
                "extracted C-SDK file unexpectedly has special permission bits".to_owned(),
            ));
        }
        modes.insert(identity.path.clone(), mode & 0o777);
    }
    checkpoint("finishing original C-SDK staging").map_err(|error| {
        retained_failure(
            &destination_path,
            format!("original C-SDK staging was cancelled before receipt: {error}"),
        )
    })?;
    let developer_path = destination_path.join(ARCHIVE_TREE).join(CSDK_ROOT);
    for (path, expected, label) in [
        (
            destination_parent_canonical.as_path(),
            &destination_parent,
            "original C-SDK destination parent",
        ),
        (
            destination_path.as_path(),
            &destination_root,
            "original C-SDK staging container",
        ),
        (
            developer_path.as_path(),
            &developer,
            "extracted Developer directory",
        ),
    ] {
        ensure_directory_matches(path, expected, label).map_err(|error| {
            Refusal::new(format!(
                "{error}; retained unaccepted C-SDK staging no longer matches its path (expected {})",
                destination_path.display()
            ))
        })?;
    }

    Ok(CsdkStagingReceipt {
        developer: developer_path,
        modes,
        file_bytes: measured.file_bytes,
        files: measured.files,
    })
}

fn validate_profile(
    profile: &[FileIdentity],
    maximum_files: usize,
    checkpoint: &mut impl FnMut(&str) -> Result<()>,
) -> Result<()> {
    if maximum_files == 0 || profile.len() > maximum_files {
        return Err(Refusal::new(
            "original C-SDK profile exceeds the supplied archive member bound",
        ));
    }
    let mut paths = BTreeSet::new();
    for identity in profile {
        checkpoint("validating original C-SDK file profile")?;
        validate_relative_inventory_path(&identity.path)?;
        if identity.mode.is_some() || !is_sha256_digest(&identity.sha256) {
            return Err(Refusal::new(
                "original C-SDK profile must omit modes and use lowercase SHA-256 digests",
            ));
        }
        if !paths.insert(identity.path.as_str()) {
            return Err(Refusal::new(
                "original C-SDK profile contains a duplicate file path",
            ));
        }
    }
    for path in &paths {
        checkpoint("checking original C-SDK profile paths")?;
        for (offset, _) in path.match_indices('/') {
            if paths.contains(&path[..offset]) {
                return Err(Refusal::new(
                    "original C-SDK profile file is also a directory ancestor",
                ));
            }
        }
    }
    Ok(())
}

fn inventory_limits(limits: ArchiveLimits) -> Result<InventoryLimits> {
    // Every visible tree entry is named by at least one logical member path;
    // each such path has at most max_path_components components.
    let max_tree_entries = limits
        .max_members
        .checked_mul(limits.max_path_components)
        .ok_or_else(|| Refusal::new("original C-SDK inventory bound overflow"))?;
    Ok(InventoryLimits {
        max_tree_entries,
        max_link_resolution_steps: limits.max_members,
    })
}

fn validate_absolute_no_parent(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(Refusal::new(format!(
            "{label} path must be absolute and contain no parent traversal"
        )));
    }
    Ok(())
}

fn reject_source_destination_overlap(
    archive_path: &Path,
    destination_path: &Path,
    archive: &fs::File,
) -> Result<()> {
    let canonical_archive = fs::canonicalize(archive_path).map_err(|error| {
        Refusal::new(format!("could not resolve original C-SDK archive: {error}"))
    })?;
    let path_metadata = fs::metadata(&canonical_archive).map_err(|error| {
        Refusal::new(format!("could not inspect original C-SDK archive: {error}"))
    })?;
    let opened_metadata = archive.metadata().map_err(|error| {
        Refusal::new(format!("could not inspect opened C-SDK archive: {error}"))
    })?;
    if path_metadata.dev() != opened_metadata.dev() || path_metadata.ino() != opened_metadata.ino()
    {
        return Err(Refusal::new(
            "original C-SDK archive path changed while it was opened",
        ));
    }
    if paths_overlap(&canonical_archive, destination_path) {
        return Err(Refusal::new(
            "original C-SDK archive and staging destination must not contain one another",
        ));
    }
    Ok(())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn ensure_directory_matches(path: &Path, expected: &Directory, label: &str) -> Result<()> {
    let observed = Directory::open(path)
        .map_err(|error| Refusal::new(format!("{label} path cannot be reopened: {error}")))?;
    let expected_metadata = expected.metadata()?;
    let observed_metadata = observed.metadata()?;
    if expected_metadata.dev() != observed_metadata.dev()
        || expected_metadata.ino() != observed_metadata.ino()
    {
        return Err(Refusal::new(format!(
            "{label} path no longer identifies the retained directory"
        )));
    }
    Ok(())
}

fn retained_failure(destination: &Path, detail: String) -> Refusal {
    Refusal::new(format!(
        "{detail}; unaccepted original C-SDK staging container retained at {}",
        destination.display()
    ))
}

#[cfg(test)]
mod tests;
