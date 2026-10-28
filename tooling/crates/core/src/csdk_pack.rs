//! Canonical, bounded C-SDK TAR.XZ and TAR production from an authenticated staging tree.
//!
//! The caller authenticates the profile and mode map and supervises aggregate
//! resources. This module verifies the complete input before creating output,
//! streams each pinned regular file into a USTAR/XZ writer, and returns only
//! identities observed from the completed derivation.

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("C-SDK archive production is supported on macOS and Linux only");

use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::{self, File, Metadata},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    rc::Rc,
};

use lzma_rust2::{XzOptions, XzWriter};
use sha2::{Digest, Sha256};
use tar::{Builder, EntryType, Header};

use crate::{
    Refusal, Result,
    csdk_source::CsdkSourceFilePin,
    digest::{encode_hex, is_sha256_digest},
    directory::Directory,
    files::{open_regular_nofollow, validate_relative_inventory_path},
    inventory::{FileIdentity, InventoryLimits, verify_complete_directory_checked},
};

const CSDK_ROOT_PREFIX: &str = "Developer/";
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const USTAR_PATH_BYTES: usize = 100;
const TAR_RECORD_BYTES: u64 = 10_240;
const OUTPUT_MODE: u32 = 0o600;

type CheckFn<'a> = Rc<RefCell<dyn FnMut(&str) -> Result<()> + 'a>>;
type CallbackFailure = Rc<RefCell<Option<Refusal>>>;

/// Caller-selected limits for one canonical C-SDK archive derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CsdkPackLimits {
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_payload_bytes: u64,
    pub max_tar_bytes: u64,
    pub max_archive_bytes: u64,
}

/// Inputs for producing one fresh C-SDK TAR.XZ or TAR archive.
///
/// profile must be authenticated by the caller and omit modes. modes maps
/// those same profile paths to their original permission bits. destination
/// names the fresh archive file.
pub struct CsdkPackRequest {
    pub developer: PathBuf,
    pub destination: PathBuf,
    pub profile: Vec<FileIdentity>,
    pub modes: BTreeMap<String, u32>,
    pub limits: CsdkPackLimits,
}

/// Observed identities and counts for a newly produced archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CsdkPackReceipt {
    pub archive: CsdkSourceFilePin,
    pub decoded_tar: CsdkSourceFilePin,
    pub files: usize,
    pub file_bytes: u64,
}

/// Produce a deterministic USTAR TAR.XZ from the exact authenticated profile.
///
/// The destination is created with exclusive, descriptor-relative creation.
/// Any failure after creation retains the incomplete or unaccepted output and
/// names its exact path in the refusal.
pub fn pack_csdk(
    request: CsdkPackRequest,
    check: impl FnMut(&str) -> Result<()>,
) -> Result<CsdkPackReceipt> {
    pack_csdk_with_format(request, PackFormat::Xz, check)
}

/// Produce a deterministic USTAR TAR from the exact authenticated profile.
///
/// The destination is created and verified with the same ownership, profile,
/// mode, size, and readback checks as [`pack_csdk`]. For this raw format,
/// `archive` and `decoded_tar` in the receipt identify the same bytes.
pub fn pack_csdk_tar(
    request: CsdkPackRequest,
    check: impl FnMut(&str) -> Result<()>,
) -> Result<CsdkPackReceipt> {
    pack_csdk_with_format(request, PackFormat::Tar, check)
}

#[derive(Clone, Copy)]
enum PackFormat {
    Xz,
    Tar,
}

fn pack_csdk_with_format(
    mut request: CsdkPackRequest,
    format: PackFormat,
    check: impl FnMut(&str) -> Result<()>,
) -> Result<CsdkPackReceipt> {
    let checker: CheckFn<'_> = Rc::new(RefCell::new(check));
    let callback_failure: CallbackFailure = Rc::new(RefCell::new(None));

    validate_absolute_path(&request.developer, "C-SDK Developer directory")?;
    validate_absolute_path(&request.destination, "C-SDK archive destination")?;
    request
        .profile
        .sort_by(|left, right| left.path.cmp(&right.path));
    let payload_bytes = validate_profile_and_modes(&request, &checker)?;

    checkpoint(&checker, "opening C-SDK source and archive parent")?;
    let developer = Directory::open(&request.developer)?;
    let developer_path =
        canonical_directory_path(&request.developer, &developer, "C-SDK Developer directory")?;
    let (destination_parent_path, destination_name) =
        destination_parent_and_name(&request.destination)?;
    let destination_parent = Directory::open(destination_parent_path)?;
    let destination_parent_canonical = canonical_directory_path(
        destination_parent_path,
        &destination_parent,
        "C-SDK archive destination parent",
    )?;
    let destination_path = destination_parent_canonical.join(destination_name);
    reject_source_destination_overlap(&developer_path, &destination_path)?;

    let inventory_limits = inventory_limits(request.limits)?;
    verify_complete_directory_checked(&developer, &request.profile, &[], inventory_limits, || {
        checkpoint(&checker, "verifying complete C-SDK file profile")
    })?;
    verify_modes_and_links(&developer, &request.profile, &request.modes, || {
        checkpoint(&checker, "checking original C-SDK file mode and links")
    })?;

    checkpoint(&checker, "creating fresh C-SDK archive")?;
    let mut output_created = false;
    let output_paths = PackOutputPaths {
        developer_path: &developer_path,
        destination_parent: &destination_parent,
        destination_parent_path,
        destination_parent_canonical: &destination_parent_canonical,
        destination_name,
        destination_path: &destination_path,
    };
    let result = produce_and_verify(
        &request,
        &developer,
        &output_paths,
        payload_bytes,
        &checker,
        &callback_failure,
        &mut output_created,
        format,
    );
    result.map_err(|error| {
        if output_created {
            retained_failure(error, &destination_path)
        } else {
            error
        }
    })
}

fn validate_profile_and_modes(request: &CsdkPackRequest, checker: &CheckFn<'_>) -> Result<u64> {
    if request.profile.len() > request.limits.max_files {
        return Err(Refusal::new(
            "C-SDK profile exceeds the supplied file-count bound",
        ));
    }
    if request.modes.len() != request.profile.len() {
        return Err(Refusal::new(
            "C-SDK mode map does not cover exactly the authenticated profile",
        ));
    }

    let mut seen = BTreeSet::new();
    let mut total_bytes = 0_u64;
    for identity in &request.profile {
        checkpoint(checker, "validating C-SDK profile")?;
        validate_relative_inventory_path(&identity.path)?;
        if identity.path.is_empty()
            || !identity.path.as_bytes().is_ascii()
            || !is_sha256_digest(&identity.sha256)
            || identity.mode.is_some()
        {
            return Err(Refusal::new(
                "C-SDK profile paths must be ASCII and profile rows must omit modes",
            ));
        }
        let full_path_bytes = CSDK_ROOT_PREFIX
            .len()
            .checked_add(identity.path.len())
            .ok_or_else(|| Refusal::new("C-SDK USTAR path length overflow"))?;
        if full_path_bytes > USTAR_PATH_BYTES {
            return Err(Refusal::new(format!(
                "C-SDK USTAR path exceeds 100 bytes: {}",
                identity.path
            )));
        }
        if !seen.insert(identity.path.as_str()) {
            return Err(Refusal::new("C-SDK profile contains a duplicate file path"));
        }
        if identity.bytes > request.limits.max_file_bytes {
            return Err(Refusal::new(
                "C-SDK profile file exceeds the supplied per-file bound",
            ));
        }
        total_bytes = total_bytes
            .checked_add(identity.bytes)
            .ok_or_else(|| Refusal::new("C-SDK profile payload total overflow"))?;
        if total_bytes > request.limits.max_payload_bytes {
            return Err(Refusal::new(
                "C-SDK profile exceeds the supplied payload-byte bound",
            ));
        }
        let mode = request
            .modes
            .get(&identity.path)
            .ok_or_else(|| Refusal::new("C-SDK mode map is missing a profile path"))?;
        if mode & !0o777 != 0 {
            return Err(Refusal::new(
                "C-SDK mode map contains unsupported permission bits",
            ));
        }
    }
    if request
        .modes
        .keys()
        .any(|path| !seen.contains(path.as_str()))
    {
        return Err(Refusal::new(
            "C-SDK mode map contains a path outside the authenticated profile",
        ));
    }
    Ok(total_bytes)
}

fn inventory_limits(limits: CsdkPackLimits) -> Result<InventoryLimits> {
    // A USTAR path is at most 100 bytes; each visible file or directory
    // consumes at least one path byte, so this bounds all profile-derived
    // tree entries. Extra empty directories remain subject to this same bound.
    let max_tree_entries = limits
        .max_files
        .checked_mul(USTAR_PATH_BYTES)
        .ok_or_else(|| Refusal::new("C-SDK tree-entry bound overflow"))?;
    Ok(InventoryLimits {
        max_tree_entries,
        max_link_resolution_steps: 0,
    })
}

fn verify_modes_and_links(
    developer: &Directory,
    profile: &[FileIdentity],
    modes: &BTreeMap<String, u32>,
    mut check_file: impl FnMut() -> Result<()>,
) -> Result<()> {
    for identity in profile {
        check_file()?;
        let file = open_profile_file(developer, &identity.path)?;
        let metadata = file.metadata().map_err(|error| {
            Refusal::new(format!("could not inspect original C-SDK file: {error}"))
        })?;
        let expected_mode = modes
            .get(&identity.path)
            .ok_or_else(|| Refusal::new("C-SDK mode map is missing a profile path"))?;
        if metadata.nlink() != 1 {
            return Err(Refusal::new(
                "C-SDK input contains a hard-linked regular file",
            ));
        }
        if metadata.len() != identity.bytes
            || metadata.permissions().mode() & 0o777 != *expected_mode
            || metadata.permissions().mode() & 0o7000 != 0
        {
            return Err(Refusal::new(
                "C-SDK file size or original permission mode differs from its profile",
            ));
        }
    }
    Ok(())
}

struct PackOutputPaths<'a> {
    developer_path: &'a Path,
    destination_parent: &'a Directory,
    destination_parent_path: &'a Path,
    destination_parent_canonical: &'a Path,
    destination_name: &'a OsStr,
    destination_path: &'a Path,
}

#[allow(clippy::too_many_arguments)]
fn produce_and_verify(
    request: &CsdkPackRequest,
    developer: &Directory,
    paths: &PackOutputPaths<'_>,
    payload_bytes: u64,
    checker: &CheckFn<'_>,
    callback_failure: &CallbackFailure,
    output_created: &mut bool,
    format: PackFormat,
) -> Result<CsdkPackReceipt> {
    let output = paths.destination_parent.create_new_file_tracked(
        paths.destination_name,
        OUTPUT_MODE,
        || *output_created = true,
    )?;
    let initial_output_metadata = output
        .metadata()
        .map_err(|error| Refusal::new(format!("could not inspect new C-SDK archive: {error}")))?;
    if !initial_output_metadata.file_type().is_file() || initial_output_metadata.nlink() != 1 {
        return Err(Refusal::new(
            "new C-SDK archive is not a singly linked regular file",
        ));
    }
    let output_identity = file_identity(&initial_output_metadata);

    let (mut output, archive_bytes, archive_sha256, tar_bytes, tar_sha256) = match format {
        PackFormat::Xz => {
            let compressed = HashingBoundedWriter::new(
                output,
                request.limits.max_archive_bytes,
                checker.clone(),
                Rc::clone(callback_failure),
                "writing compressed C-SDK archive",
            );
            let xz = XzWriter::new(compressed, XzOptions::with_preset(6)).map_err(|error| {
                callback_or_io(callback_failure, "could not create C-SDK XZ stream", error)
            })?;
            let mut raw = HashingBoundedWriter::new(
                xz,
                request.limits.max_tar_bytes,
                checker.clone(),
                Rc::clone(callback_failure),
                "writing decoded C-SDK TAR",
            );
            write_profile_tar(request, developer, &mut raw, checker, callback_failure)?;
            pad_tar(&mut raw, callback_failure)?;

            let (xz, tar_bytes, tar_sha256) = raw.into_parts();
            let compressed = xz.finish().map_err(|error| {
                callback_or_io(callback_failure, "could not finish C-SDK XZ stream", error)
            })?;
            let (output, archive_bytes, archive_sha256) = compressed.into_parts();
            (output, archive_bytes, archive_sha256, tar_bytes, tar_sha256)
        }
        PackFormat::Tar => {
            let mut raw = HashingBoundedWriter::new(
                output,
                request
                    .limits
                    .max_archive_bytes
                    .min(request.limits.max_tar_bytes),
                checker.clone(),
                Rc::clone(callback_failure),
                "writing raw C-SDK TAR archive",
            );
            write_profile_tar(request, developer, &mut raw, checker, callback_failure)?;
            pad_tar(&mut raw, callback_failure)?;
            let (output, tar_bytes, tar_sha256) = raw.into_parts();
            (output, tar_bytes, tar_sha256, tar_bytes, tar_sha256)
        }
    };
    output.flush().map_err(|error| {
        callback_or_io(callback_failure, "could not flush C-SDK archive", error)
    })?;
    output
        .sync_all()
        .map_err(|error| callback_or_io(callback_failure, "could not sync C-SDK archive", error))?;

    let archive_metadata = output.metadata().map_err(|error| {
        Refusal::new(format!(
            "could not inspect completed C-SDK archive: {error}"
        ))
    })?;
    if !archive_metadata.file_type().is_file()
        || archive_metadata.nlink() != 1
        || archive_metadata.len() != archive_bytes
        || file_identity(&archive_metadata) != output_identity
    {
        return Err(Refusal::new(
            "completed C-SDK archive descriptor changed during production",
        ));
    }

    // Run the last caller callback before any final pathname checks. A callback
    // can have effects, so no callback may run after the identities below have
    // been checked and before the receipt is returned.
    checkpoint(checker, "final C-SDK identity checkpoint")?;
    verify_complete_directory_checked(
        developer,
        &request.profile,
        &[],
        inventory_limits(request.limits)?,
        || Ok(()),
    )?;
    verify_modes_and_links(developer, &request.profile, &request.modes, || Ok(()))?;

    ensure_directory_matches(paths.developer_path, developer, "C-SDK Developer directory")?;
    ensure_directory_matches(&request.developer, developer, "C-SDK Developer directory")?;
    ensure_directory_matches(
        paths.destination_parent_canonical,
        paths.destination_parent,
        "C-SDK archive destination parent",
    )?;
    ensure_directory_matches(
        paths.destination_parent_path,
        paths.destination_parent,
        "C-SDK archive destination parent",
    )?;

    let mut path_file = open_regular_nofollow(paths.destination_path)?;
    let path_metadata = path_file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not inspect C-SDK archive path: {error}")))?;
    if file_identity(&path_metadata) != output_identity
        || path_metadata.nlink() != 1
        || path_metadata.len() != archive_bytes
    {
        return Err(Refusal::new(
            "C-SDK archive pathname no longer identifies the newly produced file",
        ));
    }
    // A caller callback can rewrite the same inode without changing its size.
    // Bind the receipt to bytes read back after the last callback, as well as
    // to the bytes observed during writes. This is a quiescent-file check,
    // not a snapshot against a hostile concurrent writer.
    let mut observed_bytes = 0_u64;
    let mut observed_digest = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        let amount = path_file.read(&mut buffer)?;
        if amount == 0 {
            break;
        }
        observed_bytes = observed_bytes
            .checked_add(amount as u64)
            .ok_or_else(|| Refusal::new("C-SDK output readback length overflow"))?;
        if observed_bytes > archive_bytes {
            return Err(Refusal::new("C-SDK archive bytes changed after production"));
        }
        observed_digest.update(&buffer[..amount]);
    }
    let observed_digest: [u8; 32] = observed_digest.finalize().into();
    if observed_bytes != archive_bytes || observed_digest != archive_sha256 {
        return Err(Refusal::new("C-SDK archive bytes changed after production"));
    }
    // Retain the opened pathname descriptor through receipt construction.
    let _retained_path_file = path_file;

    Ok(CsdkPackReceipt {
        archive: CsdkSourceFilePin {
            bytes: archive_bytes,
            sha256: archive_sha256,
        },
        decoded_tar: CsdkSourceFilePin {
            bytes: tar_bytes,
            sha256: tar_sha256,
        },
        files: request.profile.len(),
        file_bytes: payload_bytes,
    })
}

fn write_profile_tar<W: Write>(
    request: &CsdkPackRequest,
    developer: &Directory,
    raw: &mut HashingBoundedWriter<'_, W>,
    checker: &CheckFn<'_>,
    callback_failure: &CallbackFailure,
) -> Result<()> {
    let mut builder = Builder::new(raw);
    for identity in &request.profile {
        checkpoint(checker, "adding C-SDK profile file to TAR")?;
        let file = open_profile_file(developer, &identity.path)?;
        let metadata = file.metadata().map_err(|error| {
            Refusal::new(format!(
                "could not inspect opened C-SDK profile file: {error}"
            ))
        })?;
        if metadata.nlink() != 1
            || metadata.len() != identity.bytes
            || metadata.permissions().mode() & 0o777
                != *request
                    .modes
                    .get(&identity.path)
                    .ok_or_else(|| Refusal::new("C-SDK mode map is incomplete"))?
            || metadata.permissions().mode() & 0o7000 != 0
        {
            return Err(Refusal::new(
                "opened C-SDK file differs from its verified size, links, or mode",
            ));
        }

        let mut header = Header::new_ustar();
        header.set_size(identity.bytes);
        header.set_mode(request.modes[&identity.path]);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_username("")?;
        header.set_groupname("")?;
        header.set_entry_type(EntryType::Regular);

        let full_path = format!("{CSDK_ROOT_PREFIX}{}", identity.path);
        header.set_path(&full_path)?;
        header.set_cksum();
        // Python tarfile's canonical field is six octal digits, NUL,
        // then space. tar::Header's default is seven digits then NUL.
        // Format the structured header before appending it; never patch
        // a completed archive or allow append_data to reset the field.
        let checksum = format!("{:06o}\0 ", header.cksum()?);
        if checksum.len() != 8 {
            return Err(Refusal::new(
                "C-SDK TAR checksum field is not representable",
            ));
        }
        header.as_mut_bytes()[148..156].copy_from_slice(checksum.as_bytes());
        let mut payload = ProfileReader::new(
            file,
            identity.bytes,
            checker.clone(),
            Rc::clone(callback_failure),
            &identity.path,
        );
        if let Err(error) = builder.append(&header, &mut payload) {
            return Err(callback_or_io(
                callback_failure,
                &format!("could not append C-SDK profile file {}", identity.path),
                error,
            ));
        }
        if payload.read_extra_byte().map_err(|error| {
            callback_or_io(
                callback_failure,
                &format!(
                    "could not finish reading C-SDK profile file {}",
                    identity.path
                ),
                error,
            )
        })? {
            return Err(Refusal::new(format!(
                "C-SDK profile file grew while it was being archived: {}",
                identity.path
            )));
        }
        payload.verify(identity)?;
        checkpoint(checker, "finished adding C-SDK profile file to TAR")?;
    }
    builder.finish().map_err(|error| {
        callback_or_io(
            callback_failure,
            "could not finish C-SDK TAR entries",
            error,
        )
    })?;
    Ok(())
}

fn pad_tar<W: Write>(
    raw: &mut HashingBoundedWriter<'_, W>,
    callback_failure: &CallbackFailure,
) -> Result<()> {
    // Builder::finish writes two end blocks. Historical output then pads the
    // complete stream to a 10,240-byte record; that padding can itself add
    // further zero blocks, including a third one when the offset requires it.
    let remainder = raw.bytes_written() % TAR_RECORD_BYTES;
    if remainder != 0 {
        let padding = TAR_RECORD_BYTES - remainder;
        write_zeroes(raw, padding).map_err(|error| {
            callback_or_io(callback_failure, "could not record-pad C-SDK TAR", error)
        })?;
    }
    Ok(())
}

struct HashingBoundedWriter<'a, W> {
    inner: W,
    maximum: u64,
    bytes: u64,
    digest: Sha256,
    checker: CheckFn<'a>,
    callback_failure: CallbackFailure,
    checkpoint_label: &'static str,
}

impl<'a, W> HashingBoundedWriter<'a, W> {
    fn new(
        inner: W,
        maximum: u64,
        checker: CheckFn<'a>,
        callback_failure: CallbackFailure,
        checkpoint_label: &'static str,
    ) -> Self {
        Self {
            inner,
            maximum,
            bytes: 0,
            digest: Sha256::new(),
            checker,
            callback_failure,
            checkpoint_label,
        }
    }

    fn bytes_written(&self) -> u64 {
        self.bytes
    }

    fn into_parts(self) -> (W, u64, [u8; 32]) {
        (self.inner, self.bytes, self.digest.finalize().into())
    }
}

impl<W: Write> Write for HashingBoundedWriter<'_, W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        checkpoint_io(&self.checker, &self.callback_failure, self.checkpoint_label)?;
        let remaining = self.maximum.saturating_sub(self.bytes);
        if remaining == 0 {
            return Err(io::Error::other("C-SDK archive byte limit reached"));
        }
        let allowed = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| io::Error::other("C-SDK output write size is not representable"))?;
        let written = self.inner.write(&buffer[..allowed])?;
        let written_u64 = u64::try_from(written)
            .map_err(|_| io::Error::other("C-SDK output byte count is not representable"))?;
        self.bytes = self
            .bytes
            .checked_add(written_u64)
            .ok_or_else(|| io::Error::other("C-SDK output byte count overflow"))?;
        self.digest.update(&buffer[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        checkpoint_io(&self.checker, &self.callback_failure, self.checkpoint_label)?;
        self.inner.flush()
    }
}

struct ProfileReader<'a, R> {
    inner: R,
    expected_bytes: u64,
    bytes: u64,
    digest: Sha256,
    checker: CheckFn<'a>,
    callback_failure: CallbackFailure,
    checkpoint_label: String,
}

impl<'a, R> ProfileReader<'a, R> {
    fn new(
        inner: R,
        expected_bytes: u64,
        checker: CheckFn<'a>,
        callback_failure: CallbackFailure,
        profile_path: &str,
    ) -> Self {
        Self {
            inner,
            expected_bytes,
            bytes: 0,
            digest: Sha256::new(),
            checker,
            callback_failure,
            checkpoint_label: format!("reading C-SDK profile file {profile_path}"),
        }
    }

    fn read_extra_byte(&mut self) -> io::Result<bool>
    where
        R: Read,
    {
        checkpoint_io(
            &self.checker,
            &self.callback_failure,
            &self.checkpoint_label,
        )?;
        let mut extra = [0_u8; 1];
        Ok(self.inner.read(&mut extra)? != 0)
    }

    fn verify(&self, identity: &FileIdentity) -> Result<()> {
        if self.bytes != self.expected_bytes {
            return Err(Refusal::new(format!(
                "streamed C-SDK file length differs from its profile: {}",
                identity.path
            )));
        }
        let digest: [u8; 32] = self.digest.clone().finalize().into();
        if encode_hex(&digest) != identity.sha256 {
            return Err(Refusal::new(format!(
                "streamed C-SDK file digest differs from its profile: {}",
                identity.path
            )));
        }
        Ok(())
    }
}

impl<R: Read> Read for ProfileReader<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() || self.bytes == self.expected_bytes {
            return Ok(0);
        }
        checkpoint_io(
            &self.checker,
            &self.callback_failure,
            &self.checkpoint_label,
        )?;
        let remaining = self.expected_bytes - self.bytes;
        let allowed = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| io::Error::other("C-SDK input read size is not representable"))?;
        let read = self.inner.read(&mut buffer[..allowed])?;
        let read_u64 = u64::try_from(read)
            .map_err(|_| io::Error::other("C-SDK input byte count is not representable"))?;
        self.bytes = self
            .bytes
            .checked_add(read_u64)
            .ok_or_else(|| io::Error::other("C-SDK input byte count overflow"))?;
        self.digest.update(&buffer[..read]);
        Ok(read)
    }
}

fn checkpoint(checker: &CheckFn<'_>, label: &str) -> Result<()> {
    (checker.borrow_mut())(label)
}

fn checkpoint_io(
    checker: &CheckFn<'_>,
    callback_failure: &CallbackFailure,
    label: &str,
) -> io::Result<()> {
    if let Err(error) = checkpoint(checker, label) {
        *callback_failure.borrow_mut() = Some(error);
        return Err(io::Error::other("C-SDK operation was cancelled"));
    }
    Ok(())
}

fn callback_or_io(callback_failure: &CallbackFailure, context: &str, error: io::Error) -> Refusal {
    callback_failure
        .borrow_mut()
        .take()
        .unwrap_or_else(|| Refusal::new(format!("{context}: {error}")))
}

fn open_profile_file(developer: &Directory, profile_path: &str) -> Result<File> {
    let (parent_path, leaf) = profile_path.rsplit_once('/').unwrap_or(("", profile_path));
    developer
        .relative_directory(parent_path)?
        .regular(OsStr::new(leaf))
}

fn validate_absolute_path(path: &Path, label: &str) -> Result<()> {
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

fn destination_parent_and_name(destination: &Path) -> Result<(&Path, &OsStr)> {
    let name = destination
        .file_name()
        .filter(|name| *name != OsStr::new(".") && *name != OsStr::new(".."))
        .ok_or_else(|| Refusal::new("C-SDK archive destination must name a file"))?;
    let parent = destination
        .parent()
        .ok_or_else(|| Refusal::new("C-SDK archive destination must have a parent"))?;
    if !parent.is_absolute() {
        return Err(Refusal::new(
            "C-SDK archive destination parent must be absolute",
        ));
    }
    Ok((parent, name))
}

fn canonical_directory_path(path: &Path, expected: &Directory, label: &str) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| Refusal::new(format!("could not resolve {label}: {error}")))?;
    ensure_directory_matches(&canonical, expected, label)?;
    Ok(canonical)
}

fn ensure_directory_matches(path: &Path, expected: &Directory, label: &str) -> Result<()> {
    let observed = Directory::open(path)
        .map_err(|error| Refusal::new(format!("{label} path cannot be reopened: {error}")))?;
    if directory_identity(&observed.metadata()?) != directory_identity(&expected.metadata()?) {
        return Err(Refusal::new(format!(
            "{label} path no longer identifies the retained directory"
        )));
    }
    Ok(())
}

fn reject_source_destination_overlap(developer: &Path, destination: &Path) -> Result<()> {
    if developer == destination
        || developer.starts_with(destination)
        || destination.starts_with(developer)
    {
        return Err(Refusal::new(
            "C-SDK source directory and archive destination overlap",
        ));
    }
    Ok(())
}

fn directory_identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn file_identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn retained_failure(error: Refusal, destination: &Path) -> Refusal {
    Refusal::new(format!(
        "{error}; unaccepted C-SDK archive retained at {}",
        destination.display()
    ))
}

fn write_zeroes(writer: &mut impl Write, mut bytes: u64) -> io::Result<()> {
    static ZEROES: [u8; COPY_BUFFER_BYTES] = [0; COPY_BUFFER_BYTES];
    while bytes != 0 {
        let amount = usize::try_from(bytes.min(ZEROES.len() as u64))
            .map_err(|_| io::Error::other("C-SDK TAR padding is not representable"))?;
        writer.write_all(&ZEROES[..amount])?;
        bytes -= amount as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
