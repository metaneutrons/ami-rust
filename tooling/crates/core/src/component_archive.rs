//! Bounded, authenticated extraction of one pinned component TAR.
//!
//! Compressed input is decoded to an unpublished temporary TAR and hashed
//! before its member graph is accepted. Extraction then streams the same
//! compressed input a second time into a private staging tree; both compressed
//! and decoded stream identities must match the validated first pass before an
//! exclusive rename publishes the tree. No external archive utility runs.
//!
//! The caller owns the archive descriptor and supplies the authenticated
//! digest, format, resource limits and cancellation check. Output names are
//! descriptor-relative. This module is supported on macOS and Linux. Like the
//! surrounding filesystem layer, it does not promise a snapshot against a
//! concurrent writer running as the same user.

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("component archive extraction is supported only on macOS and Linux");

use std::{
    collections::BTreeMap,
    error::Error,
    ffi::{CString, OsStr, OsString},
    fmt,
    fs::{File, Permissions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
};

use flate2::read::MultiGzDecoder;
use lzma_rust2::XzReader;
use sha2::{Digest, Sha256};
use tar::{Archive, Entry, EntryType};

use crate::{Refusal, Result, directory::Directory};

const COPY_BUFFER_BYTES: usize = 64 * 1024;
const TAR_BLOCK_BYTES: u64 = 512;
const INDEX_ENTRY_OVERHEAD: usize = 256;
const DIRECTORY_INDEX_OVERHEAD: usize = 96;
const TEMP_TAR_NAME: &str = "decoded.tar";

/// Compression used by a pinned component archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveFormat {
    /// Uncompressed TAR.
    Tar,
    /// Gzip-compressed TAR. Concatenated gzip members are accepted.
    TarGzip,
    /// XZ-compressed TAR. Concatenated XZ streams are accepted.
    TarXz,
}

/// Caller-supplied resource and workspace bounds for one extraction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArchiveLimits {
    /// Maximum authenticated compressed input size.
    pub max_compressed_bytes: u64,
    /// Maximum complete decoded TAR stream, including TAR metadata and padding.
    pub max_decoded_tar_bytes: u64,
    /// Maximum total regular-file payload bytes in the component tree.
    pub max_expanded_bytes: u64,
    /// Maximum payload size of one regular file.
    pub max_file_bytes: u64,
    /// Maximum logical TAR members. Extension records do not count as members.
    pub max_members: usize,
    /// Maximum accounted memory for the validated member/path index.
    pub max_index_bytes: usize,
    /// Maximum normalized member path length in UTF-8 bytes.
    pub max_path_bytes: usize,
    /// Maximum normalized member path component count.
    pub max_path_components: usize,
    /// Maximum single GNU/PAX extension record body.
    pub max_extension_bytes: usize,
    /// Managed workspace bytes already present, including the compressed archive.
    pub current_workspace_bytes: u64,
    /// Maximum managed workspace bytes during this extraction.
    pub max_workspace_bytes: u64,
    /// XZ decoder per-block memory limit in KiB. Must be nonzero for `TarXz`.
    pub xz_memory_limit_kib: u32,
}

/// Exact compressed archive identity and extraction destination.
pub struct ComponentArchiveSpec<'a> {
    /// Fresh leaf name to publish below the retained destination parent.
    pub destination_name: &'a OsStr,
    /// Pinned compressed byte count.
    pub compressed_bytes: u64,
    /// Pinned lowercase SHA-256 of the complete compressed input.
    pub compressed_sha256: &'a str,
    /// Pinned archive compression format.
    pub format: ArchiveFormat,
    /// Per-call resource and workspace bounds.
    pub limits: ArchiveLimits,
}

/// Summary matching the component-root/member-count/expanded-byte fields used
/// by the prior preparation pipeline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentArchiveReceipt {
    pub component_root: String,
    pub member_count: usize,
    pub expanded_bytes: u64,
}

/// Failure details include the staging entry only when cleanup failed and the
/// partial tree remains for explicit recovery.
#[derive(Debug)]
pub struct ComponentArchiveFailure {
    pub reason: Refusal,
    pub recovery_entry: Option<OsString>,
}

impl fmt::Display for ComponentArchiveFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, formatter)
    }
}

impl Error for ComponentArchiveFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.reason)
    }
}

pub type ComponentArchiveResult<T> = std::result::Result<T, ComponentArchiveFailure>;

/// Authenticate, preflight, stream-extract and atomically publish one pinned
/// component archive below `destination_parent`.
///
/// The input must be a securely opened regular-file descriptor. The function
/// verifies its exact metadata length and SHA-256 while decoding into a private
/// temporary TAR, preflights the complete graph, then re-decodes and re-hashes
/// before publication. On failure it removes its private staging tree; if that
/// cleanup fails, `recovery_entry` names the retained partial tree relative to
/// the supplied parent descriptor. Existing destination entries are never
/// replaced.
pub fn extract_component_archive(
    mut archive: File,
    destination_parent: &Directory,
    spec: ComponentArchiveSpec<'_>,
    mut cancellation_check: impl FnMut() -> Result<()>,
) -> ComponentArchiveResult<ComponentArchiveReceipt> {
    validate_request(&archive, &spec).map_err(failure)?;
    let stage_name = random_stage_name().map_err(failure)?;
    let cleanup_bound = cleanup_entry_bound(&spec.limits).map_err(failure)?;
    let stage = create_stage(destination_parent, &stage_name, cleanup_bound)?;

    let result = (|| -> Result<ComponentArchiveReceipt> {
        cancellation_check()?;
        let mut decoded_tar = stage.create_new_file(OsStr::new(TEMP_TAR_NAME), 0o600)?;
        let (source, decoded_identity) =
            decode_to_temp_tar(archive, &mut decoded_tar, &spec, &mut cancellation_check)?;
        decoded_tar.flush()?;
        drop(decoded_tar);

        cancellation_check()?;
        let preflight_tar = stage.regular(OsStr::new(TEMP_TAR_NAME))?;
        let plan = preflight_tar_stream(
            preflight_tar,
            decoded_identity,
            &spec.limits,
            &mut cancellation_check,
        )?;
        stage.unlink_entry(OsStr::new(TEMP_TAR_NAME))?;

        cancellation_check()?;
        archive = source;
        archive.seek(SeekFrom::Start(0))?;
        let directory_handles = create_planned_directories(&stage, &plan, &mut cancellation_check)?;
        let observed = extract_second_pass(
            archive,
            &directory_handles,
            &plan,
            &spec,
            &mut cancellation_check,
        )?;
        if observed != decoded_identity {
            return Err(Refusal::new(
                "component archive changed between validation and extraction passes",
            ));
        }

        apply_directory_modes(&directory_handles, &plan, &mut cancellation_check)?;
        stage.set_mode_exact(0o755)?;
        cancellation_check()?;
        destination_parent.rename_no_replace(
            &stage_name,
            destination_parent,
            spec.destination_name,
        )?;
        destination_parent.sync_best_effort();
        Ok(ComponentArchiveReceipt {
            component_root: plan.component_root,
            member_count: plan.members.len(),
            expanded_bytes: plan.expanded_bytes,
        })
    })();

    match result {
        Ok(receipt) => Ok(receipt),
        Err(reason) => Err(cleanup_failure(
            destination_parent,
            &stage_name,
            cleanup_bound,
            reason,
        )),
    }
}

fn validate_request(archive: &File, spec: &ComponentArchiveSpec<'_>) -> Result<()> {
    if !crate::digest::is_sha256_digest(spec.compressed_sha256) {
        return Err(Refusal::new("component archive SHA-256 pin is malformed"));
    }
    let limits = spec.limits;
    if spec.compressed_bytes == 0
        || spec.compressed_bytes > limits.max_compressed_bytes
        || limits.max_decoded_tar_bytes == 0
        || limits.max_expanded_bytes == 0
        || limits.max_file_bytes == 0
        || limits.max_members == 0
        || limits.max_index_bytes == 0
        || limits.max_path_bytes == 0
        || limits.max_path_components == 0
        || limits.max_extension_bytes == 0
        || limits.max_workspace_bytes == 0
        || limits.current_workspace_bytes > limits.max_workspace_bytes
        || (spec.format == ArchiveFormat::TarXz && limits.xz_memory_limit_kib == 0)
    {
        return Err(Refusal::new(
            "component archive resource limits are invalid",
        ));
    }
    if archive.metadata()?.len() != spec.compressed_bytes {
        return Err(Refusal::new(
            "component archive compressed length differs from its pin",
        ));
    }
    if !archive.metadata()?.file_type().is_file() {
        return Err(Refusal::new(
            "component archive input is not a regular file",
        ));
    }
    let destination = spec.destination_name.as_bytes();
    if destination.is_empty()
        || destination == b"."
        || destination == b".."
        || destination.contains(&b'/')
        || destination.contains(&0)
    {
        return Err(Refusal::new(
            "component destination must be one ordinary leaf name",
        ));
    }
    cleanup_entry_bound(&limits)?;
    Ok(())
}

fn cleanup_entry_bound(limits: &ArchiveLimits) -> Result<usize> {
    limits
        .max_path_components
        .checked_add(1)
        .and_then(|per_member| limits.max_members.checked_mul(per_member))
        .and_then(|entries| entries.checked_add(2))
        .ok_or_else(|| Refusal::new("component cleanup entry bound overflow"))
}

fn failure(reason: Refusal) -> ComponentArchiveFailure {
    ComponentArchiveFailure {
        reason,
        recovery_entry: None,
    }
}

fn cleanup_failure(
    parent: &Directory,
    stage_name: &OsStr,
    maximum_entries: usize,
    reason: Refusal,
) -> ComponentArchiveFailure {
    match parent.remove_tree(stage_name, maximum_entries) {
        Ok(()) => ComponentArchiveFailure {
            reason,
            recovery_entry: None,
        },
        Err(cleanup) => ComponentArchiveFailure {
            reason: Refusal::new(format!(
                "{reason}; partial component tree remains at {} because cleanup failed: {cleanup}",
                stage_name.to_string_lossy()
            )),
            recovery_entry: Some(stage_name.to_os_string()),
        },
    }
}

fn create_stage(
    parent: &Directory,
    stage_name: &OsStr,
    cleanup_bound: usize,
) -> ComponentArchiveResult<Directory> {
    create_stage_with(parent, stage_name, cleanup_bound, |parent, name, owned| {
        parent.mkdir_new_tracked(name, 0o700, || *owned = true)
    })
}

fn create_stage_with(
    parent: &Directory,
    stage_name: &OsStr,
    cleanup_bound: usize,
    create: impl FnOnce(&Directory, &OsStr, &mut bool) -> Result<Directory>,
) -> ComponentArchiveResult<Directory> {
    let mut stage_owned = false;
    match create(parent, stage_name, &mut stage_owned) {
        Ok(stage) => Ok(stage),
        Err(reason) if stage_owned => {
            Err(cleanup_failure(parent, stage_name, cleanup_bound, reason))
        }
        Err(reason) => Err(failure(reason)),
    }
}

fn random_stage_name() -> Result<OsString> {
    let mut nonce = [0_u8; 12];
    #[allow(
        unsafe_code,
        reason = "getentropy fills this fixed 12-byte buffer on macOS and Linux."
    )]
    // SAFETY: the buffer is writable and 12 bytes, below getentropy's limit.
    let result = unsafe { libc::getentropy(nonce.as_mut_ptr().cast(), nonce.len()) };
    if result != 0 {
        return Err(Refusal::new(format!(
            "could not allocate a private component staging name: {}",
            io::Error::last_os_error()
        )));
    }
    let mut name = format!(".ami-rust-component-{}-", std::process::id());
    for byte in nonce {
        use fmt::Write as _;
        write!(name, "{byte:02x}").expect("formatting into String cannot fail");
    }
    Ok(OsString::from(name))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StreamIdentity {
    bytes: u64,
    sha256: [u8; 32],
}

struct HashingReader<R> {
    inner: R,
    expected_bytes: u64,
    bytes: u64,
    hasher: Sha256,
}

impl<R: Read> HashingReader<R> {
    fn new(inner: R, expected_bytes: u64) -> Self {
        Self {
            inner,
            expected_bytes,
            bytes: 0,
            hasher: Sha256::new(),
        }
    }

    fn finish(self) -> (R, StreamIdentity) {
        let digest: [u8; 32] = self.hasher.finalize().into();
        (
            self.inner,
            StreamIdentity {
                bytes: self.bytes,
                sha256: digest,
            },
        )
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.bytes == self.expected_bytes {
            let mut probe = [0_u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "compressed input exceeds its exact byte pin",
                )),
            };
        }
        let remaining = self.expected_bytes - self.bytes;
        let request = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let read = self.inner.read(&mut buffer[..request])?;
        self.bytes = self.bytes.checked_add(read as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "input byte count overflow")
        })?;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

struct DecodedReader<R> {
    inner: R,
    limit: u64,
    bytes: u64,
    hasher: Sha256,
}

impl<R: Read> DecodedReader<R> {
    fn new(inner: R, limit: u64) -> Self {
        Self {
            inner,
            limit,
            bytes: 0,
            hasher: Sha256::new(),
        }
    }

    fn finish(self) -> (R, StreamIdentity) {
        let digest: [u8; 32] = self.hasher.finalize().into();
        (
            self.inner,
            StreamIdentity {
                bytes: self.bytes,
                sha256: digest,
            },
        )
    }
}

impl<R: Read> Read for DecodedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.bytes == self.limit {
            let mut probe = [0_u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "decoded TAR exceeds its configured byte limit",
                )),
            };
        }
        let remaining = self.limit - self.bytes;
        let request = buffer
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let read = self.inner.read(&mut buffer[..request])?;
        self.bytes = self.bytes.checked_add(read as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "decoded byte count overflow")
        })?;
        self.hasher.update(&buffer[..read]);
        Ok(read)
    }
}

enum Decoder<R: Read> {
    Raw(R),
    Gzip(MultiGzDecoder<R>),
    Xz(Box<XzReader<R>>),
}

impl<R: Read> Decoder<R> {
    fn new(reader: R, format: ArchiveFormat, xz_memory_limit_kib: u32) -> Self {
        match format {
            ArchiveFormat::Tar => Self::Raw(reader),
            ArchiveFormat::TarGzip => Self::Gzip(MultiGzDecoder::new(reader)),
            ArchiveFormat::TarXz => Self::Xz(Box::new(XzReader::new_mem_limit(
                reader,
                true,
                xz_memory_limit_kib,
            ))),
        }
    }

    fn into_inner(self) -> R {
        match self {
            Self::Raw(reader) => reader,
            Self::Gzip(decoder) => decoder.into_inner(),
            Self::Xz(decoder) => decoder.into_inner(),
        }
    }
}

impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Raw(reader) => reader.read(buffer),
            Self::Gzip(decoder) => decoder.read(buffer),
            Self::Xz(decoder) => decoder.read(buffer),
        }
    }
}

fn decode_to_temp_tar(
    mut archive: File,
    output: &mut File,
    spec: &ComponentArchiveSpec<'_>,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<(File, StreamIdentity)> {
    archive.seek(SeekFrom::Start(0))?;
    let input = HashingReader::new(archive, spec.compressed_bytes);
    let mut decoder = Decoder::new(input, spec.format, spec.limits.xz_memory_limit_kib);
    let mut digest = Sha256::new();
    let mut decoded_bytes = 0_u64;
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        cancellation_check()?;
        let read = match decoder.read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "component archive decoding failed: {error}"
                )));
            }
        };
        if read == 0 {
            break;
        }
        decoded_bytes = checked_workspace_growth(
            decoded_bytes,
            read as u64,
            spec.limits.max_decoded_tar_bytes,
            spec.limits.current_workspace_bytes,
            spec.limits.max_workspace_bytes,
        )?;
        output.write_all(&buffer[..read])?;
        digest.update(&buffer[..read]);
    }
    let input = drain_compressed_input(decoder.into_inner(), cancellation_check)?;
    verify_compressed_identity(input.1, spec)?;
    Ok((
        input.0,
        StreamIdentity {
            bytes: decoded_bytes,
            sha256: digest.finalize().into(),
        },
    ))
}

fn checked_workspace_growth(
    current_output: u64,
    additional: u64,
    output_limit: u64,
    current_workspace: u64,
    workspace_limit: u64,
) -> Result<u64> {
    let next = current_output
        .checked_add(additional)
        .filter(|next| *next <= output_limit)
        .ok_or_else(|| {
            Refusal::new("component archive decoded or expanded bytes exceed their limit")
        })?;
    current_workspace
        .checked_add(next)
        .filter(|total| *total <= workspace_limit)
        .ok_or_else(|| {
            Refusal::new("component extraction exceeds the managed workspace ceiling")
        })?;
    Ok(next)
}

fn drain_compressed_input<R: Read>(
    mut reader: HashingReader<R>,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<(R, StreamIdentity)> {
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        cancellation_check()?;
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not finish reading component archive bytes: {error}"
                )));
            }
        }
    }
    let (source, identity) = reader.finish();
    Ok((source, identity))
}

fn verify_compressed_identity(
    identity: StreamIdentity,
    spec: &ComponentArchiveSpec<'_>,
) -> Result<()> {
    if identity.bytes != spec.compressed_bytes
        || encode_sha256(&identity.sha256) != spec.compressed_sha256
    {
        return Err(Refusal::new(
            "component archive compressed bytes differ from their authenticated pin",
        ));
    }
    Ok(())
}

fn encode_sha256(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 15)]));
    }
    output
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemberKind {
    Directory,
    File,
    Symlink,
    HardLink,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ArchiveMember {
    path: String,
    kind: MemberKind,
    size: u64,
    mode: u32,
    link_target: Option<String>,
}

#[derive(Default)]
struct PaxFields {
    path: Option<Vec<u8>>,
    linkpath: Option<Vec<u8>>,
    size: Option<u64>,
}

impl PaxFields {
    fn merge(&mut self, other: Self) {
        if other.path.is_some() {
            self.path = other.path;
        }
        if other.linkpath.is_some() {
            self.linkpath = other.linkpath;
        }
        if other.size.is_some() {
            self.size = other.size;
        }
    }
}

#[derive(Default)]
struct ExtensionState {
    global: PaxFields,
    local: PaxFields,
    gnu_name: Option<Vec<u8>>,
    gnu_link: Option<Vec<u8>>,
}

struct ParsedMember {
    member: ArchiveMember,
    raw_size: u64,
}

fn parse_raw_record<R: Read>(
    entry: &mut Entry<'_, R>,
    extensions: &mut ExtensionState,
    limits: &ArchiveLimits,
) -> Result<Option<ParsedMember>> {
    let entry_type = entry.header().entry_type();
    let raw_size = entry.size();
    match entry_type {
        EntryType::GNULongName => {
            let body = read_extension_body(entry, raw_size, limits.max_extension_bytes)?;
            if extensions.gnu_name.is_none() {
                extensions.gnu_name = Some(trim_gnu_extension(body)?);
            }
            return Ok(None);
        }
        EntryType::GNULongLink => {
            let body = read_extension_body(entry, raw_size, limits.max_extension_bytes)?;
            if extensions.gnu_link.is_none() {
                extensions.gnu_link = Some(trim_gnu_extension(body)?);
            }
            return Ok(None);
        }
        EntryType::XHeader => {
            let body = read_extension_body(entry, raw_size, limits.max_extension_bytes)?;
            let fields = parse_pax_fields(&body, limits.max_path_bytes)?;
            extensions.local.merge(fields);
            return Ok(None);
        }
        EntryType::XGlobalHeader => {
            let body = read_extension_body(entry, raw_size, limits.max_extension_bytes)?;
            let fields = parse_pax_fields(&body, limits.max_path_bytes)?;
            if fields.size.is_some() {
                return Err(Refusal::new(
                    "global PAX size override is unsupported for pinned components",
                ));
            }
            extensions.global.merge(fields);
            return Ok(None);
        }
        _ => {}
    }

    let raw_path = entry.path_bytes();
    let path_bytes = extensions
        .local
        .path
        .as_deref()
        .or(extensions.global.path.as_deref())
        .or(extensions.gnu_name.as_deref())
        .unwrap_or(raw_path.as_ref());
    let path = normalize_member_path(path_bytes, limits)?;
    let raw_link = entry.link_name_bytes();
    let link_bytes = extensions
        .local
        .linkpath
        .as_deref()
        .or(extensions.global.linkpath.as_deref())
        .or(extensions.gnu_link.as_deref())
        .or(raw_link.as_deref());
    let mode = entry
        .header()
        .mode()
        .map_err(|error| Refusal::new(format!("invalid component TAR mode: {error}")))?
        & 0o777;
    let kind = match entry_type {
        EntryType::Directory => MemberKind::Directory,
        EntryType::Regular | EntryType::Continuous => MemberKind::File,
        EntryType::Symlink => MemberKind::Symlink,
        EntryType::Link => MemberKind::HardLink,
        _ => {
            return Err(Refusal::new(format!(
                "component TAR contains unsupported member type {entry_type:?}"
            )));
        }
    };
    let size = match extensions.local.size.take() {
        Some(size) if size == raw_size => size,
        Some(_) => {
            return Err(Refusal::new(
                "PAX member size differs from its bounded TAR header size",
            ));
        }
        None => raw_size,
    };
    let link_target = match kind {
        MemberKind::Symlink => {
            let target =
                link_bytes.ok_or_else(|| Refusal::new("component symlink has no target"))?;
            let target = std::str::from_utf8(target)
                .map_err(|_| Refusal::new("component symlink target is not UTF-8"))?;
            validate_symlink_target(&path, target, limits)?;
            Some(target.to_owned())
        }
        MemberKind::HardLink => {
            let target =
                link_bytes.ok_or_else(|| Refusal::new("component hard link has no target"))?;
            Some(normalize_member_path(target, limits)?)
        }
        MemberKind::Directory | MemberKind::File => None,
    };
    extensions.local = PaxFields::default();
    extensions.gnu_name = None;
    extensions.gnu_link = None;
    Ok(Some(ParsedMember {
        member: ArchiveMember {
            path,
            kind,
            size,
            mode,
            link_target,
        },
        raw_size,
    }))
}

fn read_extension_body<R: Read>(
    entry: &mut Entry<'_, R>,
    size: u64,
    limit: usize,
) -> Result<Vec<u8>> {
    let size = usize::try_from(size)
        .map_err(|_| Refusal::new("component TAR extension size is not representable"))?;
    if size > limit {
        return Err(Refusal::new(
            "component TAR extension body exceeds its configured limit",
        ));
    }
    let mut body = Vec::new();
    body.try_reserve_exact(size)
        .map_err(|_| Refusal::new("could not allocate bounded TAR extension body"))?;
    body.resize(size, 0);
    entry
        .read_exact(&mut body)
        .map_err(|error| Refusal::new(format!("truncated component TAR extension: {error}")))?;
    Ok(body)
}

fn trim_gnu_extension(mut body: Vec<u8>) -> Result<Vec<u8>> {
    while body.last() == Some(&0) {
        body.pop();
    }
    if body.contains(&0) {
        return Err(Refusal::new("GNU TAR extension contains an embedded NUL"));
    }
    Ok(body)
}

fn parse_pax_fields(body: &[u8], max_path_bytes: usize) -> Result<PaxFields> {
    let mut fields = PaxFields::default();
    let mut offset = 0_usize;
    while offset < body.len() {
        let space = body[offset..]
            .iter()
            .position(|byte| *byte == b' ')
            .and_then(|relative| offset.checked_add(relative))
            .ok_or_else(|| Refusal::new("malformed PAX record length"))?;
        let length = usize::try_from(parse_decimal(&body[offset..space])?)
            .map_err(|_| Refusal::new("PAX record length is not representable"))?;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= body.len() && *end > space + 2)
            .ok_or_else(|| Refusal::new("PAX record length exceeds its extension body"))?;
        if body[end - 1] != b'\n' {
            return Err(Refusal::new("PAX record lacks its terminating newline"));
        }
        let assignment = &body[space + 1..end - 1];
        let equal = assignment
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(|| Refusal::new("malformed PAX key/value record"))?;
        let key = &assignment[..equal];
        let value = &assignment[equal + 1..];
        match key {
            b"path" => {
                if value.len() > max_path_bytes {
                    return Err(Refusal::new("PAX path exceeds its configured limit"));
                }
                fields.path = Some(value.to_vec());
            }
            b"linkpath" => {
                if value.len() > max_path_bytes {
                    return Err(Refusal::new("PAX link target exceeds its configured limit"));
                }
                fields.linkpath = Some(value.to_vec());
            }
            b"size" => fields.size = Some(parse_decimal(value)?),
            _ if key.starts_with(b"GNU.sparse.") => {
                return Err(Refusal::new("sparse PAX component members are unsupported"));
            }
            _ => {}
        }
        offset = end;
    }
    Ok(fields)
}

fn parse_decimal(bytes: &[u8]) -> Result<u64> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(Refusal::new("PAX integer is not an unsigned decimal"));
    }
    bytes.iter().try_fold(0_u64, |value, digit| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(*digit - b'0')))
            .ok_or_else(|| Refusal::new("PAX integer overflow"))
    })
}

fn normalize_member_path(raw: &[u8], limits: &ArchiveLimits) -> Result<String> {
    if raw.len() > limits.max_path_bytes || raw.is_empty() || raw[0] == b'/' {
        return Err(Refusal::new(
            "component TAR member path is absolute or oversized",
        ));
    }
    if raw.contains(&b'\\') || raw.contains(&0) {
        return Err(Refusal::new("component TAR member path is not portable"));
    }
    let mut parts = Vec::new();
    for part in raw.split(|byte| *byte == b'/') {
        if part.is_empty() || part == b"." {
            continue;
        }
        if part == b".." {
            return Err(Refusal::new(
                "component TAR member path contains parent traversal",
            ));
        }
        parts.push(
            std::str::from_utf8(part)
                .map_err(|_| Refusal::new("component TAR member path is not UTF-8"))?,
        );
        if parts.len() > limits.max_path_components {
            return Err(Refusal::new("component TAR member path is too deep"));
        }
    }
    let first = parts
        .first()
        .ok_or_else(|| Refusal::new("component TAR member has no path components"))?;
    if first.contains(':') {
        return Err(Refusal::new("component TAR member root contains a colon"));
    }
    let normalized = parts.join("/");
    crate::files::validate_relative_inventory_path(&normalized)?;
    if normalized.len() > limits.max_path_bytes {
        return Err(Refusal::new(
            "normalized component path exceeds its configured limit",
        ));
    }
    Ok(normalized)
}

fn validate_symlink_target(path: &str, target: &str, limits: &ArchiveLimits) -> Result<()> {
    if target.is_empty() || target.len() > limits.max_path_bytes || target.starts_with('/') {
        return Err(Refusal::new(
            "component symlink target is absolute or oversized",
        ));
    }
    if target.contains('\\') || target.contains('\0') {
        return Err(Refusal::new("component symlink target is not portable"));
    }
    let root = path
        .split('/')
        .next()
        .ok_or_else(|| Refusal::new("component symlink has no component root"))?;
    let mut resolved: Vec<&str> = path.split('/').collect();
    resolved.pop();
    for part in target.split('/') {
        match part {
            "" | "." => {}
            ".." if resolved.len() > 1 => {
                resolved.pop();
            }
            ".." => return Err(Refusal::new("component symlink escapes its root")),
            ordinary => {
                resolved.push(ordinary);
                if resolved.len() > limits.max_path_components {
                    return Err(Refusal::new("component symlink target is too deep"));
                }
            }
        }
    }
    if resolved.first().copied() != Some(root) || resolved.len() == 1 {
        return Err(Refusal::new("component symlink escapes its root"));
    }
    Ok(())
}

struct ArchivePlan {
    component_root: String,
    members: Vec<ArchiveMember>,
    member_indices: BTreeMap<String, usize>,
    directories: BTreeMap<String, u32>,
    expanded_bytes: u64,
    index_bytes: usize,
}

fn preflight_tar_stream(
    file: File,
    decoded_identity: StreamIdentity,
    limits: &ArchiveLimits,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<ArchivePlan> {
    if decoded_identity.bytes == 0 {
        return Err(Refusal::new("component archive decoded to an empty TAR"));
    }
    if decoded_identity.bytes > limits.max_decoded_tar_bytes {
        return Err(Refusal::new("component TAR exceeds its decoded byte limit"));
    }
    let archive_len = file.metadata()?.len();
    if archive_len != decoded_identity.bytes {
        return Err(Refusal::new("temporary component TAR length changed"));
    }
    let mut plan = ArchivePlan {
        component_root: String::new(),
        members: Vec::new(),
        member_indices: BTreeMap::new(),
        directories: BTreeMap::new(),
        expanded_bytes: 0,
        index_bytes: 0,
    };
    let mut case_paths = BTreeMap::<String, String>::new();
    let mut extensions = ExtensionState::default();
    let mut archive = Archive::new(file);
    let mut entries = archive
        .entries()
        .map_err(|error| Refusal::new(format!("could not read component TAR: {error}")))?
        .raw(true);

    for result in entries.by_ref() {
        cancellation_check()?;
        let mut entry = result
            .map_err(|error| Refusal::new(format!("invalid component TAR entry: {error}")))?;
        check_tar_member_range(entry.raw_file_position(), entry.size(), archive_len)?;
        if let Some(parsed) = parse_raw_record(&mut entry, &mut extensions, limits)? {
            drain_exact(&mut entry, parsed.raw_size, cancellation_check)?;
            record_member(parsed.member, &mut plan, &mut case_paths, limits)?;
        }
    }
    let _file = archive.into_inner();
    if extensions.local.path.is_some()
        || extensions.local.linkpath.is_some()
        || extensions.local.size.is_some()
        || extensions.gnu_name.is_some()
        || extensions.gnu_link.is_some()
    {
        return Err(Refusal::new(
            "component TAR ends with an unattached GNU/PAX extension",
        ));
    }
    finish_plan(plan, limits)
}

fn check_tar_member_range(data_offset: u64, size: u64, archive_len: u64) -> Result<()> {
    let padded = size
        .checked_add(TAR_BLOCK_BYTES - 1)
        .map(|size| size / TAR_BLOCK_BYTES * TAR_BLOCK_BYTES)
        .ok_or_else(|| Refusal::new("component TAR member size overflow"))?;
    data_offset
        .checked_add(padded)
        .filter(|end| *end <= archive_len)
        .ok_or_else(|| Refusal::new("component TAR member exceeds decoded archive bounds"))?;
    Ok(())
}

fn drain_exact<R: Read>(
    input: &mut R,
    mut remaining: u64,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    while remaining > 0 {
        cancellation_check()?;
        let request = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = match input.read(&mut buffer[..request]) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not read component TAR payload: {error}"
                )));
            }
        };
        if read == 0 {
            return Err(Refusal::new(
                "component TAR payload is shorter than declared",
            ));
        }
        remaining -= read as u64;
    }
    Ok(())
}

fn record_member(
    member: ArchiveMember,
    plan: &mut ArchivePlan,
    case_paths: &mut BTreeMap<String, String>,
    limits: &ArchiveLimits,
) -> Result<()> {
    if plan.members.len() >= limits.max_members {
        return Err(Refusal::new("component TAR exceeds its member-count limit"));
    }
    if let Some(root) = member.path.split('/').next() {
        if plan.component_root.is_empty() {
            plan.component_root = root.to_owned();
        } else if plan.component_root != root {
            return Err(Refusal::new("component TAR contains more than one root"));
        }
    }
    if plan.member_indices.contains_key(&member.path) {
        return Err(Refusal::new(
            "component TAR contains duplicate member names",
        ));
    }
    charge_index(
        &mut plan.index_bytes,
        member
            .path
            .len()
            .checked_add(member.link_target.as_ref().map_or(0, String::len))
            .and_then(|length| length.checked_add(INDEX_ENTRY_OVERHEAD))
            .ok_or_else(|| Refusal::new("component member index size overflow"))?,
        limits.max_index_bytes,
    )?;
    check_case_path(
        &member.path,
        case_paths,
        &mut plan.index_bytes,
        limits.max_index_bytes,
    )?;
    let index = plan.members.len();
    plan.member_indices.insert(member.path.clone(), index);

    let components: Vec<_> = member.path.split('/').collect();
    let mut prefix = String::new();
    for (position, component) in components.iter().enumerate() {
        if position > 0 {
            prefix.push('/');
        }
        prefix.push_str(component);
        if position + 1 < components.len() {
            if !plan.directories.contains_key(&prefix) {
                charge_index(
                    &mut plan.index_bytes,
                    prefix
                        .len()
                        .checked_add(DIRECTORY_INDEX_OVERHEAD)
                        .ok_or_else(|| Refusal::new("component directory index size overflow"))?,
                    limits.max_index_bytes,
                )?;
                plan.directories.insert(prefix.clone(), 0o755);
            }
        } else if member.kind == MemberKind::Directory {
            plan.directories.insert(prefix.clone(), member.mode);
        }
    }

    if member.kind == MemberKind::File {
        if member.size > limits.max_file_bytes {
            return Err(Refusal::new(
                "component file exceeds its individual size limit",
            ));
        }
        plan.expanded_bytes = plan
            .expanded_bytes
            .checked_add(member.size)
            .filter(|total| *total <= limits.max_expanded_bytes)
            .ok_or_else(|| Refusal::new("component archive exceeds its expanded size limit"))?;
    }
    plan.members.push(member);
    Ok(())
}

fn charge_index(current: &mut usize, additional: usize, maximum: usize) -> Result<()> {
    *current = current
        .checked_add(additional)
        .filter(|total| *total <= maximum)
        .ok_or_else(|| Refusal::new("component member index exceeds its memory profile"))?;
    Ok(())
}

fn check_case_path(
    path: &str,
    case_paths: &mut BTreeMap<String, String>,
    index_bytes: &mut usize,
    index_limit: usize,
) -> Result<()> {
    let mut prefix = String::new();
    for (position, component) in path.split('/').enumerate() {
        if position > 0 {
            prefix.push('/');
        }
        prefix.push_str(component);
        let folded = prefix.to_lowercase();
        match case_paths.get(&folded) {
            Some(previous) if previous != &prefix => {
                return Err(Refusal::new("component TAR contains case-colliding paths"));
            }
            Some(_) => {}
            None => {
                charge_index(
                    index_bytes,
                    folded
                        .len()
                        .checked_add(prefix.len())
                        .and_then(|size| size.checked_add(DIRECTORY_INDEX_OVERHEAD))
                        .ok_or_else(|| Refusal::new("component case index size overflow"))?,
                    index_limit,
                )?;
                case_paths.insert(folded, prefix.clone());
            }
        }
    }
    Ok(())
}

fn finish_plan(plan: ArchivePlan, limits: &ArchiveLimits) -> Result<ArchivePlan> {
    if plan.members.is_empty() || plan.component_root.is_empty() {
        return Err(Refusal::new("component TAR has no logical members"));
    }
    if !plan.directories.contains_key(&plan.component_root) {
        return Err(Refusal::new("component TAR root is not a directory"));
    }
    if limits
        .current_workspace_bytes
        .checked_add(plan.expanded_bytes)
        .filter(|total| *total <= limits.max_workspace_bytes)
        .is_none()
    {
        return Err(Refusal::new(
            "component extraction exceeds the managed workspace ceiling",
        ));
    }

    for member in &plan.members {
        let mut parent = String::new();
        let components: Vec<_> = member.path.split('/').collect();
        for component in &components[..components.len().saturating_sub(1)] {
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(component);
            if plan
                .member_indices
                .get(&parent)
                .is_some_and(|index| plan.members[*index].kind != MemberKind::Directory)
            {
                return Err(Refusal::new(
                    "component TAR member descends through a non-directory",
                ));
            }
        }
        if member.kind == MemberKind::HardLink {
            let target = member
                .link_target
                .as_ref()
                .expect("hardlink target validated during member parsing");
            if target.split('/').next() != Some(plan.component_root.as_str()) {
                return Err(Refusal::new("component hard link escapes its root"));
            }
        }
    }

    // Python safe_extract_tar creates all regular files first, then processes
    // links in original order. Mirror the hard-link availability rule so
    // forward links to not-yet-created hard links are rejected in preflight.
    for (member_index, member) in plan.members.iter().enumerate() {
        if member.kind == MemberKind::HardLink {
            let target = member
                .link_target
                .as_ref()
                .expect("hardlink target validated during member parsing");
            let target_index = plan.member_indices.get(target).copied();
            let target_is_available =
                target_index.is_some_and(|target_index| match plan.members[target_index].kind {
                    MemberKind::File => true,
                    MemberKind::HardLink => target_index < member_index,
                    MemberKind::Directory | MemberKind::Symlink => false,
                });
            if !target_is_available {
                return Err(Refusal::new(
                    "component hard link target is not an earlier regular file or hard link",
                ));
            }
        }
    }
    Ok(plan)
}

fn create_planned_directories(
    root: &Directory,
    plan: &ArchivePlan,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<BTreeMap<String, Directory>> {
    let mut paths: Vec<_> = plan.directories.iter().collect();
    paths.sort_by(|(left, _), (right, _)| {
        left.matches('/')
            .count()
            .cmp(&right.matches('/').count())
            .then_with(|| left.cmp(right))
    });
    let mut opened = BTreeMap::new();
    for (path, _) in paths {
        cancellation_check()?;
        let (parent_path, leaf) = path.rsplit_once('/').unwrap_or(("", path));
        let parent = if parent_path.is_empty() {
            root
        } else {
            opened
                .get(parent_path)
                .ok_or_else(|| Refusal::new("component directory plan is not parent-first"))?
        };
        let child = parent.mkdir_new(OsStr::new(leaf), 0o700)?;
        opened.insert(path.clone(), child);
    }
    Ok(opened)
}

fn extract_second_pass(
    source: File,
    directories: &BTreeMap<String, Directory>,
    plan: &ArchivePlan,
    spec: &ComponentArchiveSpec<'_>,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<StreamIdentity> {
    let compressed = HashingReader::new(source, spec.compressed_bytes);
    let decoder = Decoder::new(compressed, spec.format, spec.limits.xz_memory_limit_kib);
    let decoded = DecodedReader::new(decoder, spec.limits.max_decoded_tar_bytes);
    let mut archive = Archive::new(decoded);
    let mut entries = archive
        .entries()
        .map_err(|error| Refusal::new(format!("could not read extraction TAR: {error}")))?
        .raw(true);
    let mut extensions = ExtensionState::default();
    let mut member_index = 0_usize;
    let mut written_bytes = 0_u64;

    for result in entries.by_ref() {
        cancellation_check()?;
        let mut entry = result
            .map_err(|error| Refusal::new(format!("invalid extraction TAR entry: {error}")))?;
        let Some(parsed) = parse_raw_record(&mut entry, &mut extensions, &spec.limits)? else {
            continue;
        };
        let expected = plan
            .members
            .get(member_index)
            .ok_or_else(|| Refusal::new("extraction TAR has additional logical members"))?;
        if &parsed.member != expected {
            return Err(Refusal::new(
                "component TAR member graph changed between validation and extraction",
            ));
        }
        member_index += 1;
        match parsed.member.kind {
            MemberKind::File => {
                let (parent_path, leaf) = split_path(&parsed.member.path);
                let parent = directories
                    .get(parent_path)
                    .ok_or_else(|| Refusal::new("component file parent is not a directory"))?;
                let mut output = parent.create_new_file(OsStr::new(leaf), 0o600)?;
                written_bytes = copy_file_payload(
                    &mut entry,
                    &mut output,
                    parsed.raw_size,
                    written_bytes,
                    &spec.limits,
                    cancellation_check,
                )?;
                output.flush()?;
                output.set_permissions(Permissions::from_mode(parsed.member.mode))?;
            }
            _ => drain_exact(&mut entry, parsed.raw_size, cancellation_check)?,
        }
    }
    if member_index != plan.members.len() {
        return Err(Refusal::new(
            "extraction TAR omits validated logical members",
        ));
    }
    materialize_links(directories, plan, cancellation_check)?;

    let mut decoded = archive.into_inner();
    drain_decoded_reader(&mut decoded, cancellation_check)?;
    let (decoder, decoded_identity) = decoded.finish();
    let (compressed_reader, compressed_identity) =
        drain_compressed_input(decoder.into_inner(), cancellation_check)?;
    drop(compressed_reader);
    verify_compressed_identity(compressed_identity, spec)?;
    Ok(decoded_identity)
}

fn copy_file_payload<R: Read>(
    input: &mut R,
    output: &mut File,
    mut remaining: u64,
    mut written_total: u64,
    limits: &ArchiveLimits,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<u64> {
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    while remaining > 0 {
        cancellation_check()?;
        let request = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = match input.read(&mut buffer[..request]) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not read component file payload: {error}"
                )));
            }
        };
        if read == 0 {
            return Err(Refusal::new(
                "component file payload is shorter than declared",
            ));
        }
        written_total = checked_workspace_growth(
            written_total,
            read as u64,
            limits.max_expanded_bytes,
            limits.current_workspace_bytes,
            limits.max_workspace_bytes,
        )?;
        output.write_all(&buffer[..read])?;
        remaining -= read as u64;
    }
    Ok(written_total)
}

fn drain_decoded_reader<R: Read>(
    reader: &mut DecodedReader<R>,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        cancellation_check()?;
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not finish decoding component TAR: {error}"
                )));
            }
        }
    }
}

fn materialize_links(
    directories: &BTreeMap<String, Directory>,
    plan: &ArchivePlan,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    for member in &plan.members {
        cancellation_check()?;
        if !matches!(member.kind, MemberKind::Symlink | MemberKind::HardLink) {
            continue;
        }
        let (parent_path, leaf) = split_path(&member.path);
        let parent = directories
            .get(parent_path)
            .ok_or_else(|| Refusal::new("component link parent is not a directory"))?;
        let target = member
            .link_target
            .as_deref()
            .ok_or_else(|| Refusal::new("component link has no target"))?;
        match member.kind {
            MemberKind::Symlink => create_symlink(parent, leaf, target)?,
            MemberKind::HardLink => {
                let (source_parent_path, source_leaf) = split_path(target);
                let source_parent = directories
                    .get(source_parent_path)
                    .ok_or_else(|| Refusal::new("component hard-link parent is not a directory"))?;
                let expected = source_parent.classify_entry(OsStr::new(source_leaf))?;
                if expected.entry_type() != crate::directory::EntryType::RegularFile {
                    return Err(Refusal::new(
                        "component hard-link target is not an existing regular file",
                    ));
                }
                let _source =
                    source_parent.open_regular_matching(OsStr::new(source_leaf), expected)?;
                create_hard_link(source_parent, source_leaf, parent, leaf)?;
            }
            MemberKind::Directory | MemberKind::File => {}
        }
    }
    Ok(())
}

fn apply_directory_modes(
    directories: &BTreeMap<String, Directory>,
    plan: &ArchivePlan,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let mut paths: Vec<_> = plan.directories.iter().collect();
    paths.sort_by(|(left, _), (right, _)| {
        right
            .matches('/')
            .count()
            .cmp(&left.matches('/').count())
            .then_with(|| left.cmp(right))
    });
    for (path, mode) in paths {
        cancellation_check()?;
        directories
            .get(path)
            .ok_or_else(|| Refusal::new("component directory handle is missing"))?
            .set_mode_exact(*mode as libc::mode_t)?;
    }
    Ok(())
}

fn create_symlink(parent: &Directory, leaf: &str, target: &str) -> Result<()> {
    let leaf = CString::new(leaf.as_bytes())
        .map_err(|_| Refusal::new("component symlink name contains NUL"))?;
    let target = CString::new(target.as_bytes())
        .map_err(|_| Refusal::new("component symlink target contains NUL"))?;
    #[allow(
        unsafe_code,
        reason = "symlinkat is anchored to a retained parent and a validated relative target."
    )]
    // SAFETY: parent is live; both paths are NUL-terminated and contain no slash in the leaf.
    let result = unsafe { libc::symlinkat(target.as_ptr(), parent.raw_fd(), leaf.as_ptr()) };
    if result != 0 {
        return Err(Refusal::new(format!(
            "could not create component symlink: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn create_hard_link(
    source_parent: &Directory,
    source_leaf: &str,
    destination_parent: &Directory,
    destination_leaf: &str,
) -> Result<()> {
    let source = CString::new(source_leaf.as_bytes())
        .map_err(|_| Refusal::new("component hard-link source contains NUL"))?;
    let destination = CString::new(destination_leaf.as_bytes())
        .map_err(|_| Refusal::new("component hard-link name contains NUL"))?;
    #[allow(
        unsafe_code,
        reason = "linkat uses retained parent descriptors and validated leaves."
    )]
    // SAFETY: both parents are live and both names are validated single components.
    let result = unsafe {
        libc::linkat(
            source_parent.raw_fd(),
            source.as_ptr(),
            destination_parent.raw_fd(),
            destination.as_ptr(),
            0,
        )
    };
    if result != 0 {
        return Err(Refusal::new(format!(
            "could not create component hard link: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn split_path(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

#[cfg(test)]
mod tests {
    use super::{
        ArchiveFormat, ArchiveLimits, ComponentArchiveSpec, create_stage_with,
        extract_component_archive,
    };
    use crate::{digest::sha256_bytes, directory::Directory};
    use flate2::{Compression, write::GzEncoder};
    use lzma_rust2::{XzOptions, XzWriter};
    use std::{
        ffi::{CString, OsStr, OsString},
        fs::{self, File},
        io::{Cursor, Write},
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    use tar::{Builder, EntryType, Header};

    static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let base = std::env::current_dir().expect("current directory");
            for _ in 0..100 {
                let number = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
                let path = base.join(format!(
                    ".ami-rust-component-archive-test-{}-{number}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
                        return Self(path);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("could not create archive fixture: {error}"),
                }
            }
            panic!("could not allocate a unique archive fixture");
        }

        fn root(&self) -> Directory {
            Directory::open(&self.0).expect("open fixture root")
        }

        fn archive_file(&self, name: &str, bytes: &[u8]) -> File {
            let path = self.0.join(name);
            fs::write(&path, bytes).expect("write archive fixture");
            File::open(path).expect("open archive fixture")
        }

        fn extract(
            &self,
            name: &str,
            bytes: &[u8],
            format: ArchiveFormat,
        ) -> super::ComponentArchiveResult<super::ComponentArchiveReceipt> {
            let archive = self.archive_file("input.archive", bytes);
            let expected = u64::try_from(bytes.len()).unwrap();
            extract_component_archive(
                archive,
                &self.root(),
                ComponentArchiveSpec {
                    destination_name: std::ffi::OsStr::new(name),
                    compressed_bytes: expected,
                    compressed_sha256: &sha256_bytes(bytes),
                    format,
                    limits: limits(expected),
                },
                || Ok(()),
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove archive fixture");
        }
    }

    fn limits(compressed: u64) -> ArchiveLimits {
        ArchiveLimits {
            max_compressed_bytes: compressed.max(1),
            max_decoded_tar_bytes: 8 * 1024 * 1024,
            max_expanded_bytes: 4 * 1024 * 1024,
            max_file_bytes: 2 * 1024 * 1024,
            max_members: 100,
            max_index_bytes: 1024 * 1024,
            max_path_bytes: 1024,
            max_path_components: 32,
            max_extension_bytes: 64 * 1024,
            current_workspace_bytes: 0,
            max_workspace_bytes: 16 * 1024 * 1024,
            xz_memory_limit_kib: 64 * 1024,
        }
    }

    #[test]
    fn stage_creation_cleans_only_owned_entries_and_preserves_recovery_name() {
        let fixture = Fixture::new();
        let parent = fixture.root();
        let cleanup_bound = 4;

        let cleaned_name = OsStr::new("injected-stage-failure");
        let cleaned = create_stage_with(
            &parent,
            cleaned_name,
            cleanup_bound,
            |parent, name, owned| {
                let stage = parent.mkdir_new_tracked(name, 0o700, || *owned = true)?;
                drop(stage);
                Err(crate::Refusal::new("injected post-mkdir failure"))
            },
        );
        let Err(cleaned) = cleaned else {
            panic!("injected stage failure unexpectedly succeeded");
        };
        assert_eq!(cleaned.recovery_entry, None);
        assert!(
            cleaned
                .reason
                .to_string()
                .contains("injected post-mkdir failure")
        );
        assert!(!fixture.0.join(cleaned_name).exists());

        let occupied_name = OsStr::new("preexisting-stage-collision");
        fs::create_dir(fixture.0.join(occupied_name)).unwrap();
        fs::write(fixture.0.join(occupied_name).join("marker"), b"preserve").unwrap();
        let occupied = create_stage_with(
            &parent,
            occupied_name,
            cleanup_bound,
            |parent, name, owned| parent.mkdir_new_tracked(name, 0o700, || *owned = true),
        );
        let Err(occupied) = occupied else {
            panic!("preexisting stage collision unexpectedly succeeded");
        };
        assert_eq!(occupied.recovery_entry, None);
        assert_eq!(
            fs::read(fixture.0.join(occupied_name).join("marker")).unwrap(),
            b"preserve"
        );

        let retained_name = OsStr::new("stage-with-recovery-entry");
        let retained = create_stage_with(
            &parent,
            retained_name,
            cleanup_bound,
            |parent, name, owned| {
                let stage = parent.mkdir_new_tracked(name, 0o700, || *owned = true)?;
                let fifo_name = CString::new("cleanup-blocker").unwrap();
                #[allow(
                    unsafe_code,
                    reason = "The test creates a FIFO to force deterministic bounded-cleanup refusal."
                )]
                // SAFETY: stage is a live descriptor and fifo_name is NUL-terminated.
                let fifo_result =
                    unsafe { libc::mkfifoat(stage.raw_fd(), fifo_name.as_ptr(), 0o600) };
                if fifo_result != 0 {
                    return Err(crate::Refusal::new(format!(
                        "could not create cleanup test FIFO: {}",
                        std::io::Error::last_os_error()
                    )));
                }
                drop(stage);
                Err(crate::Refusal::new("injected post-mkdir cleanup failure"))
            },
        );
        let Err(retained) = retained else {
            panic!("injected recovery-stage failure unexpectedly succeeded");
        };
        assert_eq!(retained.recovery_entry, Some(OsString::from(retained_name)));
        assert!(retained.reason.to_string().contains("cleanup failed"));
        assert!(
            fixture
                .0
                .join(retained_name)
                .join("cleanup-blocker")
                .exists()
        );

        fs::remove_file(fixture.0.join(retained_name).join("cleanup-blocker")).unwrap();
        parent.remove_tree(retained_name, cleanup_bound).unwrap();
        assert!(!fixture.0.join(retained_name).exists());
    }

    fn append_record(builder: &mut Builder<Vec<u8>>, path: &str, kind: EntryType, body: &[u8]) {
        let mut header = Header::new_gnu();
        header.set_mode(0o755);
        header.set_size(body.len() as u64);
        header.set_entry_type(kind);
        if matches!(kind, EntryType::Link | EntryType::Symlink) {
            header
                .set_link_name("component/file")
                .expect("set link target");
        }
        builder
            .append_data(&mut header, path, Cursor::new(body))
            .expect("append TAR fixture record");
    }

    fn regular_tar() -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        append_record(&mut builder, "component/", EntryType::Directory, b"");
        let mut file = Header::new_gnu();
        file.set_mode(0o755);
        file.set_size(7);
        file.set_entry_type(EntryType::Regular);
        builder
            .append_data(&mut file, "component/bin/tool", Cursor::new(b"payload"))
            .unwrap();
        builder.into_inner().unwrap()
    }

    fn pax_record(key: &str, value: &str) -> Vec<u8> {
        let tail = format!(" {key}={value}\n");
        let mut length = tail.len() + 1;
        loop {
            let next = tail.len() + length.to_string().len();
            if next == length {
                let mut record = length.to_string().into_bytes();
                record.extend_from_slice(tail.as_bytes());
                return record;
            }
            length = next;
        }
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn xz(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = XzWriter::new(Vec::new(), XzOptions::with_preset(1)).unwrap();
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn extracts_pinned_regular_gzip_and_xz_archives_with_modes_and_receipts() {
        let fixture = Fixture::new();
        let plain = regular_tar();
        let receipt = fixture
            .extract("plain", &plain, ArchiveFormat::Tar)
            .unwrap();
        assert_eq!(receipt.component_root, "component");
        assert_eq!(receipt.member_count, 2);
        assert_eq!(receipt.expanded_bytes, 7);
        let tool = fixture.0.join("plain/component/bin/tool");
        assert_eq!(fs::read(&tool).unwrap(), b"payload");
        assert_eq!(
            fs::metadata(tool).unwrap().permissions().mode() & 0o777,
            0o755
        );

        let compressed = gzip(&plain);
        let receipt = fixture
            .extract("gzip", &compressed, ArchiveFormat::TarGzip)
            .unwrap();
        assert_eq!(receipt.component_root, "component");
        assert_eq!(
            fs::read(fixture.0.join("gzip/component/bin/tool")).unwrap(),
            b"payload"
        );

        let compressed = xz(&plain);
        let receipt = fixture
            .extract("xz", &compressed, ArchiveFormat::TarXz)
            .unwrap();
        assert_eq!(receipt.component_root, "component");
        assert_eq!(
            fs::read(fixture.0.join("xz/component/bin/tool")).unwrap(),
            b"payload"
        );
    }

    #[test]
    fn applies_bounded_pax_path_overrides() {
        let fixture = Fixture::new();
        let path = format!("component/{}", "long-name-".repeat(12));
        let extension = pax_record("path", &path);
        let mut builder = Builder::new(Vec::new());
        append_record(
            &mut builder,
            "PaxHeaders.0/component",
            EntryType::XHeader,
            &extension,
        );
        append_record(&mut builder, "component/short", EntryType::Regular, b"data");
        let archive = builder.into_inner().unwrap();
        fixture
            .extract("pax", &archive, ArchiveFormat::Tar)
            .unwrap();
        assert_eq!(fs::read(fixture.0.join("pax").join(path)).unwrap(), b"data");
    }

    #[test]
    fn creates_safe_relative_symlinks_and_hard_links_after_regular_files() {
        let fixture = Fixture::new();
        let mut builder = Builder::new(Vec::new());
        append_record(&mut builder, "component", EntryType::Directory, b"");
        let mut hard = Header::new_gnu();
        hard.set_size(0);
        hard.set_mode(0o644);
        hard.set_entry_type(EntryType::Link);
        hard.set_link_name("component/file").unwrap();
        builder
            .append_data(&mut hard, "component/hard", Cursor::new([]))
            .unwrap();
        let mut file = Header::new_gnu();
        file.set_size(4);
        file.set_mode(0o644);
        builder
            .append_data(&mut file, "component/file", Cursor::new(b"data"))
            .unwrap();
        let mut symbolic = Header::new_gnu();
        symbolic.set_size(0);
        symbolic.set_mode(0o777);
        symbolic.set_entry_type(EntryType::Symlink);
        symbolic.set_link_name("file").unwrap();
        builder
            .append_data(&mut symbolic, "component/alias", Cursor::new([]))
            .unwrap();
        let tar = builder.into_inner().unwrap();
        fixture.extract("links", &tar, ArchiveFormat::Tar).unwrap();

        let root = fixture.0.join("links/component");
        assert_eq!(fs::read(root.join("hard")).unwrap(), b"data");
        assert_eq!(
            fs::metadata(root.join("file")).unwrap().ino(),
            fs::metadata(root.join("hard")).unwrap().ino()
        );
        assert_eq!(
            fs::read_link(root.join("alias")).unwrap(),
            PathBuf::from("file")
        );
    }

    #[test]
    fn rejects_traversal_link_pivots_case_aliases_and_duplicate_members_before_publish() {
        let fixture = Fixture::new();
        let mut traversal = Builder::new(Vec::new());
        let mut bad = Header::new_gnu();
        bad.set_size(1);
        bad.set_mode(0o644);
        bad.set_entry_type(EntryType::Regular);
        // Bypass the writer's own safe-path guard for this isolated input.
        // The reader must encounter the malformed member and reject it.
        let name = b"component/../escape";
        bad.as_mut_bytes()[..100].fill(0);
        bad.as_mut_bytes()[..name.len()].copy_from_slice(name);
        bad.set_cksum();
        traversal.append(&bad, Cursor::new(b"x")).unwrap();
        let traversal = traversal.into_inner().unwrap();
        assert!(
            fixture
                .extract("traversal", &traversal, ArchiveFormat::Tar)
                .is_err()
        );
        assert!(!fixture.0.join("traversal").exists());
        assert!(!fixture.0.join("escape").exists());

        let mut pivot = Builder::new(Vec::new());
        append_record(&mut pivot, "component", EntryType::Directory, b"");
        let mut symbolic = Header::new_gnu();
        symbolic.set_size(0);
        symbolic.set_entry_type(EntryType::Symlink);
        symbolic.set_link_name("file").unwrap();
        pivot
            .append_data(&mut symbolic, "component/pivot", Cursor::new([]))
            .unwrap();
        append_record(
            &mut pivot,
            "component/pivot/child",
            EntryType::Regular,
            b"x",
        );
        let pivot = pivot.into_inner().unwrap();
        assert!(
            fixture
                .extract("symlink-pivot", &pivot, ArchiveFormat::Tar)
                .is_err()
        );
        assert!(!fixture.0.join("symlink-pivot").exists());

        let mut escaping_link = Builder::new(Vec::new());
        append_record(&mut escaping_link, "component", EntryType::Directory, b"");
        let mut symbolic = Header::new_gnu();
        symbolic.set_size(0);
        symbolic.set_entry_type(EntryType::Symlink);
        symbolic.set_link_name("../../outside").unwrap();
        escaping_link
            .append_data(&mut symbolic, "component/escape", Cursor::new([]))
            .unwrap();
        let escaping_link = escaping_link.into_inner().unwrap();
        assert!(
            fixture
                .extract("symlink-escape", &escaping_link, ArchiveFormat::Tar)
                .is_err()
        );
        assert!(!fixture.0.join("symlink-escape").exists());

        for rows in [
            vec![
                ("component/Name", EntryType::Regular),
                ("component/name", EntryType::Regular),
            ],
            vec![
                ("component/file", EntryType::Regular),
                ("component/file/child", EntryType::Regular),
            ],
        ] {
            let mut builder = Builder::new(Vec::new());
            for (path, kind) in rows {
                append_record(&mut builder, path, kind, b"x");
            }
            let bytes = builder.into_inner().unwrap();
            assert!(
                fixture
                    .extract("bad-graph", &bytes, ArchiveFormat::Tar)
                    .is_err()
            );
        }

        let mut duplicate = Builder::new(Vec::new());
        append_record(&mut duplicate, "component/file", EntryType::Regular, b"a");
        append_record(&mut duplicate, "component/file", EntryType::Regular, b"b");
        assert!(
            fixture
                .extract(
                    "duplicate",
                    &duplicate.into_inner().unwrap(),
                    ArchiveFormat::Tar
                )
                .is_err()
        );
    }

    #[test]
    fn rejects_digest_size_expansion_cancellation_and_existing_destination_without_damage() {
        let fixture = Fixture::new();
        let tar = regular_tar();
        let archive = fixture.archive_file("wrong-digest", &tar);
        let wrong_digest = "0".repeat(64);
        assert!(
            extract_component_archive(
                archive,
                &fixture.root(),
                ComponentArchiveSpec {
                    destination_name: std::ffi::OsStr::new("wrong-digest-out"),
                    compressed_bytes: tar.len() as u64,
                    compressed_sha256: &wrong_digest,
                    format: ArchiveFormat::Tar,
                    limits: limits(tar.len() as u64),
                },
                || Ok(()),
            )
            .is_err()
        );
        assert!(!fixture.0.join("wrong-digest-out").exists());

        let mut small = limits(tar.len() as u64);
        small.max_expanded_bytes = 3;
        let archive = fixture.archive_file("over-expansion", &tar);
        let digest = sha256_bytes(&tar);
        assert!(
            extract_component_archive(
                archive,
                &fixture.root(),
                ComponentArchiveSpec {
                    destination_name: std::ffi::OsStr::new("over-expansion-out"),
                    compressed_bytes: tar.len() as u64,
                    compressed_sha256: &digest,
                    format: ArchiveFormat::Tar,
                    limits: small,
                },
                || Ok(()),
            )
            .is_err()
        );

        let archive = fixture.archive_file("cancelled", &tar);
        let digest = sha256_bytes(&tar);
        let result = extract_component_archive(
            archive,
            &fixture.root(),
            ComponentArchiveSpec {
                destination_name: std::ffi::OsStr::new("cancelled-out"),
                compressed_bytes: tar.len() as u64,
                compressed_sha256: &digest,
                format: ArchiveFormat::Tar,
                limits: limits(tar.len() as u64),
            },
            || Err(crate::Refusal::new("cancelled fixture")),
        );
        assert!(result.is_err());
        assert!(!fixture.0.join("cancelled-out").exists());

        fs::create_dir(fixture.0.join("occupied")).unwrap();
        fs::write(fixture.0.join("occupied/marker"), b"keep").unwrap();
        let archive = fixture.archive_file("occupied-input", &tar);
        let digest = sha256_bytes(&tar);
        assert!(
            extract_component_archive(
                archive,
                &fixture.root(),
                ComponentArchiveSpec {
                    destination_name: std::ffi::OsStr::new("occupied"),
                    compressed_bytes: tar.len() as u64,
                    compressed_sha256: &digest,
                    format: ArchiveFormat::Tar,
                    limits: limits(tar.len() as u64),
                },
                || Ok(()),
            )
            .is_err()
        );
        assert_eq!(
            fs::read(fixture.0.join("occupied/marker")).unwrap(),
            b"keep"
        );
    }
}
