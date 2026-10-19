//! Authenticated extraction for the pinned flat Cargo component archive.
//!
//! Unlike ordinary toolchain component archives, Cargo has exactly two flat
//! members. This module authenticates and validates both members before it
//! creates a staging tree, then publishes that complete tree with an exclusive
//! rename. Input and output lookups remain descriptor-relative. It supports
//! macOS and Linux and does not claim a snapshot against a same-user writer.

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("flat Cargo archive extraction is supported only on macOS and Linux");

use std::{
    collections::BTreeMap,
    error::Error,
    ffi::{OsStr, OsString},
    fmt,
    fs::{File, Permissions},
    io::{self, Read, Seek, SeekFrom, Write},
    ops::Range,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
};

use sha2::{Digest, Sha256};
use tar::{Archive, EntryType};

use crate::{
    Refusal, Result,
    compression::{DecodeLimits, copy_xz},
    digest::{encode_hex, is_sha256_digest},
    directory::Directory,
    inventory::{
        FileIdentity, InventoryLimits, LinkIdentity, Measurement, verify_complete_directory_checked,
    },
};

const MAX_COMPRESSED_BYTES: u64 = 16 * 1024 * 1024;
const MAX_DECODED_TAR_BYTES: usize = 256 * 1024 * 1024;
const MAX_EXPANDED_BYTES: u64 = 256 * 1024 * 1024;
const XZ_MEMORY_LIMIT_KIB: u32 = 64 * 1024;
const EXPECTED_MTIME: u64 = 1_791_936_000;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const MEMBERS: [&str; 2] = ["bin/cargo", "producer.json"];
const CLEANUP_ENTRY_BOUND: usize = 4;

/// Authenticated flat Cargo archive identity and requested destination.
pub struct CargoArchiveSpec<'a> {
    pub destination_name: &'a OsStr,
    pub compressed_bytes: u64,
    pub compressed_sha256: &'a str,
    pub files: &'a [FileIdentity],
    /// The pinned Cargo inventory must not contain symlinks.
    pub links: &'a [LinkIdentity],
}

/// Measurements of the authenticated archive and published Cargo component.
#[derive(Debug, Eq, PartialEq)]
pub struct CargoArchiveReceipt {
    pub measurement: Measurement,
    pub compressed_bytes: u64,
    pub decoded_tar_bytes: usize,
    pub expanded_bytes: u64,
}

/// A failed extraction names the staging directory only when cleanup failed.
#[derive(Debug)]
pub struct CargoArchiveFailure {
    pub reason: Refusal,
    pub recovery_entry: Option<OsString>,
}

impl fmt::Display for CargoArchiveFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, formatter)
    }
}

impl Error for CargoArchiveFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.reason)
    }
}

pub type CargoArchiveResult<T> = std::result::Result<T, CargoArchiveFailure>;

/// Verify and extract a canonical two-member Cargo archive beneath a retained
/// destination parent. The supplied descriptor must already refer to a
/// securely opened regular file. No output is created until compressed bytes,
/// the complete XZ stream, both TAR headers, both payload hashes, and the exact
/// member order have passed validation. Existing destinations are never
/// replaced. Failed cleanup is reported through `recovery_entry`.
pub fn extract_flat_cargo_archive(
    mut archive: File,
    destination_parent: &Directory,
    spec: CargoArchiveSpec<'_>,
    mut cancellation_check: impl FnMut() -> Result<()>,
) -> CargoArchiveResult<CargoArchiveReceipt> {
    let expected = validate_request(&archive, &spec).map_err(failure)?;
    let compressed = read_authenticated_archive(
        &mut archive,
        spec.compressed_bytes,
        spec.compressed_sha256,
        &mut cancellation_check,
    )
    .map_err(failure)?;

    let decoded = decode_archive(&compressed, &mut cancellation_check).map_err(failure)?;
    let members =
        preflight_archive(&decoded, &expected, &mut cancellation_check).map_err(failure)?;
    cancellation_check().map_err(failure)?;

    let stage_name = random_stage_name().map_err(failure)?;
    let stage = create_stage(destination_parent, &stage_name)?;
    let result = (|| -> Result<CargoArchiveReceipt> {
        cancellation_check()?;
        let bin = stage.mkdir_new(OsStr::new("bin"), 0o755)?;
        for member in &members {
            cancellation_check()?;
            let contents = decoded
                .get(member.payload.clone())
                .ok_or_else(|| Refusal::new("validated Cargo member range disappeared"))?;
            let (parent, name, mode) = match member.path {
                "bin/cargo" => (&bin, OsStr::new("cargo"), 0o755),
                "producer.json" => (&stage, OsStr::new("producer.json"), 0o644),
                _ => return Err(Refusal::new("unexpected validated Cargo member path")),
            };
            write_new_file(parent, name, mode, contents, &mut cancellation_check)?;
        }

        let output_rows = exact_output_rows(spec.files)?;
        let measurement = verify_complete_directory_checked(
            &stage,
            &output_rows,
            &[],
            InventoryLimits {
                max_tree_entries: 3,
                max_link_resolution_steps: 1,
            },
            &mut cancellation_check,
        )?;
        if measurement.files != 2
            || measurement.symlinks != 0
            || measurement.directories != 1
            || measurement.file_bytes != expected.expanded_bytes
        {
            return Err(Refusal::new(
                "published Cargo staging tree differs from its exact two-file inventory",
            ));
        }

        stage.set_mode_exact(0o755)?;
        cancellation_check()?;
        destination_parent.rename_no_replace(
            &stage_name,
            destination_parent,
            spec.destination_name,
        )?;
        destination_parent.sync_best_effort();
        Ok(CargoArchiveReceipt {
            measurement,
            compressed_bytes: spec.compressed_bytes,
            decoded_tar_bytes: decoded.len(),
            expanded_bytes: expected.expanded_bytes,
        })
    })();

    match result {
        Ok(receipt) => Ok(receipt),
        Err(reason) => Err(cleanup_failure(destination_parent, &stage_name, reason)),
    }
}

struct ExpectedFiles<'a> {
    rows: BTreeMap<&'a str, &'a FileIdentity>,
    expanded_bytes: u64,
}

fn validate_request<'a>(
    archive: &File,
    spec: &'a CargoArchiveSpec<'a>,
) -> Result<ExpectedFiles<'a>> {
    if !is_sha256_digest(spec.compressed_sha256) {
        return Err(Refusal::new("Cargo archive SHA-256 pin is malformed"));
    }
    if spec.compressed_bytes == 0 || spec.compressed_bytes > MAX_COMPRESSED_BYTES {
        return Err(Refusal::new(
            "Cargo archive compressed length is outside its fixed bound",
        ));
    }
    let metadata = archive.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() != spec.compressed_bytes {
        return Err(Refusal::new(
            "Cargo archive input is not a regular file of its pinned length",
        ));
    }
    if !ordinary_name(spec.destination_name) {
        return Err(Refusal::new(
            "Cargo destination must be one ordinary entry name",
        ));
    }
    if !spec.links.is_empty() || spec.files.len() != MEMBERS.len() {
        return Err(Refusal::new(
            "Cargo inventory must contain exactly two files and no symlinks",
        ));
    }

    let mut rows = BTreeMap::new();
    let mut expanded_bytes = 0_u64;
    for file in spec.files {
        if !MEMBERS.contains(&file.path.as_str())
            || !is_sha256_digest(&file.sha256)
            || file.mode.is_some()
        {
            return Err(Refusal::new("Cargo inventory row is malformed"));
        }
        expanded_bytes = expanded_bytes
            .checked_add(file.bytes)
            .ok_or_else(|| Refusal::new("Cargo inventory byte total overflow"))?;
        if rows.insert(file.path.as_str(), file).is_some() {
            return Err(Refusal::new("Cargo inventory has duplicate file paths"));
        }
    }
    if MEMBERS.iter().any(|path| !rows.contains_key(path)) {
        return Err(Refusal::new(
            "Cargo inventory must contain bin/cargo and producer.json",
        ));
    }
    if expanded_bytes > MAX_EXPANDED_BYTES {
        return Err(Refusal::new(
            "Cargo inventory exceeds the expanded-byte bound",
        ));
    }
    Ok(ExpectedFiles {
        rows,
        expanded_bytes,
    })
}

fn ordinary_name(name: &OsStr) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes != b"."
        && bytes != b".."
        && !bytes.contains(&b'/')
        && !bytes.contains(&0)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileState {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    length: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl From<&std::fs::Metadata> for FileState {
    fn from(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            length: metadata.len(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

fn read_authenticated_archive(
    archive: &mut File,
    expected_bytes: u64,
    expected_sha256: &str,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    let before = archive.metadata()?;
    if !before.file_type().is_file() || before.len() != expected_bytes {
        return Err(Refusal::new(
            "Cargo archive descriptor changed before reading",
        ));
    }
    let before = FileState::from(&before);
    let capacity = usize::try_from(expected_bytes)
        .map_err(|_| Refusal::new("Cargo archive length is not representable"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| Refusal::new("could not allocate bounded Cargo archive input"))?;
    archive.seek(SeekFrom::Start(0))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    let mut total = 0_u64;
    loop {
        cancellation_check()?;
        let count = match archive.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not read Cargo archive: {error}"
                )));
            }
        };
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| Refusal::new("Cargo archive byte count overflow"))?;
        if total > expected_bytes {
            return Err(Refusal::new("Cargo archive grew beyond its pinned length"));
        }
        digest.update(&buffer[..count]);
        bytes.extend_from_slice(&buffer[..count]);
    }
    if total != expected_bytes {
        return Err(Refusal::new("Cargo archive ended before its pinned length"));
    }
    let observed: [u8; 32] = digest.finalize().into();
    if encode_hex(&observed) != expected_sha256 {
        return Err(Refusal::new("Cargo archive SHA-256 differs from its pin"));
    }
    let after = archive.metadata()?;
    if FileState::from(&after) != before {
        return Err(Refusal::new(
            "Cargo archive metadata changed while its bytes were read",
        ));
    }
    Ok(bytes)
}

struct DecodedBuffer<'a, F> {
    bytes: Vec<u8>,
    cancellation_check: &'a mut F,
}

impl<F> Write for DecodedBuffer<'_, F>
where
    F: FnMut() -> Result<()>,
{
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        (self.cancellation_check)().map_err(|error| io::Error::other(error.to_string()))?;
        let new_length = self
            .bytes
            .len()
            .checked_add(input.len())
            .ok_or_else(|| io::Error::other("decoded Cargo TAR length overflow"))?;
        if new_length > MAX_DECODED_TAR_BYTES {
            return Err(io::Error::other(
                "decoded Cargo TAR exceeds its fixed bound",
            ));
        }
        self.bytes
            .try_reserve(input.len())
            .map_err(|_| io::Error::other("could not allocate bounded decoded Cargo TAR"))?;
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        (self.cancellation_check)().map_err(|error| io::Error::other(error.to_string()))
    }
}

fn decode_archive(
    compressed: &[u8],
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    cancellation_check()?;
    let mut output = DecodedBuffer {
        bytes: Vec::new(),
        cancellation_check,
    };
    let decoded = copy_xz(
        compressed,
        &mut output,
        DecodeLimits {
            max_compressed_bytes: usize::try_from(MAX_COMPRESSED_BYTES)
                .expect("fixed Cargo compressed limit fits usize"),
            max_decoded_bytes: MAX_DECODED_TAR_BYTES,
            max_xz_memory_kib: XZ_MEMORY_LIMIT_KIB,
        },
    )?;
    if decoded != output.bytes.len() {
        return Err(Refusal::new(
            "Cargo XZ decoder byte count differs from its bounded sink",
        ));
    }
    Ok(output.bytes)
}

#[derive(Clone, Debug)]
struct CargoMember {
    path: &'static str,
    payload: Range<usize>,
}

fn preflight_archive(
    decoded: &[u8],
    expected: &ExpectedFiles<'_>,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<Vec<CargoMember>> {
    let mut archive = Archive::new(io::Cursor::new(decoded));
    let entries = archive
        .entries()
        .map_err(|error| Refusal::new(format!("could not read Cargo TAR entries: {error}")))?;
    let mut entries = entries.raw(true);
    let mut members = Vec::new();
    members
        .try_reserve_exact(MEMBERS.len())
        .map_err(|_| Refusal::new("could not allocate Cargo member index"))?;

    for path in MEMBERS {
        cancellation_check()?;
        let entry = entries
            .next()
            .ok_or_else(|| Refusal::new("Cargo TAR is missing a required member"))?
            .map_err(|error| Refusal::new(format!("invalid Cargo TAR header: {error}")))?;
        let header = entry.header();
        if header.entry_type() != EntryType::Regular {
            return Err(Refusal::new(
                "Cargo TAR members must be regular files without extension records",
            ));
        }
        let raw_header = header.as_bytes();
        if raw_header[..100].contains(&b'\\') || raw_header[345..500].contains(&b'\\') {
            return Err(Refusal::new(
                "Cargo TAR member path contains a noncanonical backslash",
            ));
        }
        if header.path_bytes().as_ref() != path.as_bytes() {
            return Err(Refusal::new(
                "Cargo TAR member names or order differ from the pinned flat layout",
            ));
        }
        if header.mode().map_err(tar_error("Cargo TAR mode"))?
            != if path == "bin/cargo" { 0o755 } else { 0o644 }
            || header.uid().map_err(tar_error("Cargo TAR uid"))? != 0
            || header.gid().map_err(tar_error("Cargo TAR gid"))? != 0
            || header.mtime().map_err(tar_error("Cargo TAR mtime"))? != EXPECTED_MTIME
        {
            return Err(Refusal::new(
                "Cargo TAR mode, ownership, or timestamp is noncanonical",
            ));
        }
        let username = header
            .username()
            .map_err(|error| Refusal::new(format!("invalid Cargo TAR uname: {error}")))?
            .unwrap_or("");
        let groupname = header
            .groupname()
            .map_err(|error| Refusal::new(format!("invalid Cargo TAR gname: {error}")))?
            .unwrap_or("");
        if !username.is_empty() || !groupname.is_empty() {
            return Err(Refusal::new("Cargo TAR uname and gname must be empty"));
        }

        let row = expected
            .rows
            .get(path)
            .ok_or_else(|| Refusal::new("Cargo TAR member has no inventory row"))?;
        if entry.size() != row.bytes {
            return Err(Refusal::new(
                "Cargo TAR member size differs from its authenticated inventory",
            ));
        }
        let start = usize::try_from(entry.raw_file_position())
            .map_err(|_| Refusal::new("Cargo TAR member offset is not representable"))?;
        let size = usize::try_from(entry.size())
            .map_err(|_| Refusal::new("Cargo TAR member size is not representable"))?;
        let end = start
            .checked_add(size)
            .ok_or_else(|| Refusal::new("Cargo TAR member range overflow"))?;
        let payload = decoded
            .get(start..end)
            .ok_or_else(|| Refusal::new("Cargo TAR member data is truncated"))?;
        if sha256_payload(payload, cancellation_check)? != row.sha256 {
            return Err(Refusal::new(
                "Cargo TAR member SHA-256 differs from its authenticated inventory",
            ));
        }
        members.push(CargoMember {
            path,
            payload: start..end,
        });
        drop(entry);
    }
    if let Some(extra) = entries.next() {
        extra
            .map_err(|error| Refusal::new(format!("invalid trailing Cargo TAR entry: {error}")))?;
        return Err(Refusal::new("Cargo TAR contains an extra member"));
    }
    Ok(members)
}

fn tar_error(context: &'static str) -> impl FnOnce(io::Error) -> Refusal {
    move |error| Refusal::new(format!("could not read {context}: {error}"))
}

fn sha256_payload(
    bytes: &[u8],
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<String> {
    let mut digest = Sha256::new();
    for chunk in bytes.chunks(COPY_BUFFER_BYTES) {
        cancellation_check()?;
        digest.update(chunk);
    }
    let value: [u8; 32] = digest.finalize().into();
    Ok(encode_hex(&value))
}

fn exact_output_rows(files: &[FileIdentity]) -> Result<Vec<FileIdentity>> {
    let mut rows = Vec::new();
    rows.try_reserve_exact(files.len())
        .map_err(|_| Refusal::new("could not allocate Cargo output inventory"))?;
    for file in files {
        let mut file = file.clone();
        file.mode = Some(if file.path == "bin/cargo" {
            0o755
        } else {
            0o644
        });
        rows.push(file);
    }
    Ok(rows)
}

fn write_new_file(
    parent: &Directory,
    name: &OsStr,
    mode: u32,
    contents: &[u8],
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let mut file = parent.create_new_file(name, 0o600)?;
    for chunk in contents.chunks(COPY_BUFFER_BYTES) {
        cancellation_check()?;
        file.write_all(chunk)
            .map_err(|error| Refusal::new(format!("could not write Cargo member: {error}")))?;
    }
    file.flush()
        .map_err(|error| Refusal::new(format!("could not flush Cargo member: {error}")))?;
    file.set_permissions(Permissions::from_mode(mode))
        .map_err(|error| Refusal::new(format!("could not set Cargo member mode: {error}")))?;
    Ok(())
}

fn create_stage(parent: &Directory, name: &OsStr) -> CargoArchiveResult<Directory> {
    let mut owned = false;
    match parent.mkdir_new_tracked(name, 0o700, || owned = true) {
        Ok(directory) => Ok(directory),
        Err(reason) if owned => Err(cleanup_failure(parent, name, reason)),
        Err(reason) => Err(failure(reason)),
    }
}

fn cleanup_failure(parent: &Directory, stage_name: &OsStr, reason: Refusal) -> CargoArchiveFailure {
    match parent.remove_tree(stage_name, CLEANUP_ENTRY_BOUND) {
        Ok(()) => CargoArchiveFailure {
            reason,
            recovery_entry: None,
        },
        Err(cleanup) => CargoArchiveFailure {
            reason: Refusal::new(format!(
                "{reason}; partial Cargo tree remains at {} because cleanup failed: {cleanup}",
                stage_name.to_string_lossy()
            )),
            recovery_entry: Some(stage_name.to_os_string()),
        },
    }
}

fn failure(reason: Refusal) -> CargoArchiveFailure {
    CargoArchiveFailure {
        reason,
        recovery_entry: None,
    }
}

#[allow(
    unsafe_code,
    reason = "getentropy fills this fixed 12-byte buffer on macOS and Linux."
)]
fn random_stage_name() -> Result<OsString> {
    let mut nonce = [0_u8; 12];
    // SAFETY: the writable buffer is 12 bytes, below getentropy's platform limit.
    let result = unsafe { libc::getentropy(nonce.as_mut_ptr().cast(), nonce.len()) };
    if result != 0 {
        return Err(Refusal::new(format!(
            "could not allocate a private Cargo staging name: {}",
            io::Error::last_os_error()
        )));
    }
    let mut name = format!(".ami-rust-cargo-{}-", std::process::id());
    for byte in nonce {
        use fmt::Write as _;
        write!(name, "{byte:02x}").expect("formatting into String cannot fail");
    }
    Ok(OsString::from(name))
}

#[cfg(test)]
mod tests {
    use super::{CargoArchiveSpec, extract_flat_cargo_archive};
    use crate::{
        Refusal,
        digest::sha256_bytes,
        directory::Directory,
        inventory::{FileIdentity, LinkIdentity},
    };
    use lzma_rust2::{XzOptions, XzWriter};
    use std::{
        ffi::OsStr,
        fs::{self, File},
        io::Write,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    use tar::{Builder, EntryType, Header};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    const CARGO_BYTES: &[u8] = b"synthetic cargo executable\0\xff";
    const PRODUCER_BYTES: &[u8] = b"{\"schema\":\"test\"}\n";

    #[derive(Clone)]
    struct Member<'a> {
        path: &'a str,
        bytes: &'a [u8],
        mode: u32,
        uid: u64,
        gid: u64,
        mtime: u64,
        username: Option<&'a str>,
        groupname: Option<&'a str>,
        entry_type: EntryType,
        link_name: Option<&'a str>,
    }

    impl<'a> Member<'a> {
        fn regular(path: &'a str, bytes: &'a [u8], mode: u32) -> Self {
            Self {
                path,
                bytes,
                mode,
                uid: 0,
                gid: 0,
                mtime: 1_791_936_000,
                username: None,
                groupname: None,
                entry_type: EntryType::Regular,
                link_name: None,
            }
        }
    }

    struct TempTree(PathBuf);

    impl TempTree {
        fn new() -> Self {
            let base = std::env::current_dir().expect("current directory");
            for _ in 0..100 {
                let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
                let path = base.join(format!(
                    ".ami-rust-cargo-archive-test-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("could not create Cargo archive test tree: {error}"),
                }
            }
            panic!("could not allocate a unique Cargo archive test tree");
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }

        fn destination(&self) -> Directory {
            Directory::open(self.path()).expect("open test destination parent")
        }

        fn archive(&self, bytes: &[u8]) -> (File, Vec<u8>) {
            let path = self.path().join("input.tar.xz");
            let mut file = File::create(&path).expect("create test archive");
            file.write_all(bytes).expect("write test archive");
            drop(file);
            (File::open(path).expect("open test archive"), bytes.to_vec())
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove Cargo archive test tree");
        }
    }

    fn rows() -> Vec<FileIdentity> {
        vec![
            FileIdentity {
                path: "bin/cargo".into(),
                bytes: CARGO_BYTES.len() as u64,
                sha256: sha256_bytes(CARGO_BYTES),
                mode: None,
            },
            FileIdentity {
                path: "producer.json".into(),
                bytes: PRODUCER_BYTES.len() as u64,
                sha256: sha256_bytes(PRODUCER_BYTES),
                mode: None,
            },
        ]
    }

    fn archive(members: &[Member<'_>]) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        for member in members {
            let mut header = Header::new_ustar();
            if member
                .path
                .as_bytes()
                .split(|byte| *byte == b'/')
                .any(|part| part == b"..")
            {
                // Exercise a validly checksummed hostile path. The TAR writer
                // correctly refuses traversal paths, so this fixture writes
                // the raw name field directly and checksums the header below.
                let path = member.path.as_bytes();
                assert!(path.len() <= 100);
                header.as_mut_bytes()[..100].fill(0);
                header.as_mut_bytes()[..path.len()].copy_from_slice(path);
            } else {
                header.set_path(member.path).expect("set test member path");
            }
            header.set_size(member.bytes.len() as u64);
            header.set_mode(member.mode);
            header.set_uid(member.uid);
            header.set_gid(member.gid);
            header.set_mtime(member.mtime);
            header
                .set_username(member.username.unwrap_or(""))
                .expect("set test uname");
            header
                .set_groupname(member.groupname.unwrap_or(""))
                .expect("set test gname");
            header.set_entry_type(member.entry_type);
            if let Some(link_name) = member.link_name {
                header.set_link_name(link_name).expect("set test link name");
            }
            header.set_cksum();
            builder
                .append(&header, member.bytes)
                .expect("append test member");
        }
        builder.finish().expect("finish test tar");
        builder.into_inner().expect("extract test tar bytes")
    }

    fn xz(bytes: &[u8]) -> Vec<u8> {
        let mut writer =
            XzWriter::new(Vec::new(), XzOptions::with_preset(1)).expect("create test XZ encoder");
        writer.write_all(bytes).expect("write test XZ input");
        writer.finish().expect("finish test XZ stream")
    }

    fn canonical_archive() -> Vec<u8> {
        xz(&archive(&[
            Member::regular("bin/cargo", CARGO_BYTES, 0o755),
            Member::regular("producer.json", PRODUCER_BYTES, 0o644),
        ]))
    }

    fn extract(
        tree: &TempTree,
        compressed: &[u8],
        files: &[FileIdentity],
        links: &[LinkIdentity],
        cancel: impl FnMut() -> crate::Result<()>,
    ) -> super::CargoArchiveResult<super::CargoArchiveReceipt> {
        let (archive, source_bytes) = tree.archive(compressed);
        extract_flat_cargo_archive(
            archive,
            &tree.destination(),
            CargoArchiveSpec {
                destination_name: OsStr::new("cargo-component"),
                compressed_bytes: source_bytes.len() as u64,
                compressed_sha256: &sha256_bytes(&source_bytes),
                files,
                links,
            },
            cancel,
        )
    }

    #[test]
    fn extracts_exact_two_members_and_publishes_verified_tree() {
        let tree = TempTree::new();
        let bytes = canonical_archive();
        let receipt = extract(&tree, &bytes, &rows(), &[], || Ok(())).unwrap();
        assert_eq!(receipt.measurement.files, 2);
        assert_eq!(receipt.measurement.symlinks, 0);
        assert_eq!(receipt.measurement.directories, 1);
        assert_eq!(
            fs::read(tree.path().join("cargo-component/bin/cargo")).unwrap(),
            CARGO_BYTES
        );
        assert_eq!(
            fs::read(tree.path().join("cargo-component/producer.json")).unwrap(),
            PRODUCER_BYTES
        );
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(
                &fs::metadata(tree.path().join("cargo-component/bin/cargo"))
                    .unwrap()
                    .permissions()
            ) & 0o777,
            0o755
        );
    }

    #[test]
    fn refuses_compressed_identity_and_inventory_mismatches_before_output() {
        let tree = TempTree::new();
        let compressed = canonical_archive();
        let (archive, source_bytes) = tree.archive(&compressed);
        let bad_sha = sha256_bytes(b"different archive");
        let error = extract_flat_cargo_archive(
            archive,
            &tree.destination(),
            CargoArchiveSpec {
                destination_name: OsStr::new("cargo-component"),
                compressed_bytes: source_bytes.len() as u64,
                compressed_sha256: &bad_sha,
                files: &rows(),
                links: &[],
            },
            || Ok(()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("SHA-256"));
        assert!(!tree.path().join("cargo-component").exists());

        let mut wrong_rows = rows();
        wrong_rows[0].sha256 = sha256_bytes(b"wrong cargo");
        let error = extract(&tree, &compressed, &wrong_rows, &[], || Ok(())).unwrap_err();
        assert!(error.to_string().contains("SHA-256"));
        assert!(!tree.path().join("cargo-component").exists());

        let mut mode_rows = rows();
        mode_rows[0].mode = Some(0o755);
        let error = extract(&tree, &compressed, &mode_rows, &[], || Ok(())).unwrap_err();
        assert!(error.to_string().contains("inventory row"));
        assert!(!tree.path().join("cargo-component").exists());
    }

    #[test]
    fn refuses_noncanonical_header_metadata_and_member_order() {
        let cases = [
            vec![
                Member {
                    mode: 0o644,
                    ..Member::regular("bin/cargo", CARGO_BYTES, 0o755)
                },
                Member::regular("producer.json", PRODUCER_BYTES, 0o644),
            ],
            vec![
                Member {
                    uid: 1,
                    ..Member::regular("bin/cargo", CARGO_BYTES, 0o755)
                },
                Member::regular("producer.json", PRODUCER_BYTES, 0o644),
            ],
            vec![
                Member {
                    gid: 1,
                    ..Member::regular("bin/cargo", CARGO_BYTES, 0o755)
                },
                Member::regular("producer.json", PRODUCER_BYTES, 0o644),
            ],
            vec![
                Member {
                    mtime: 1,
                    ..Member::regular("bin/cargo", CARGO_BYTES, 0o755)
                },
                Member::regular("producer.json", PRODUCER_BYTES, 0o644),
            ],
            vec![
                Member {
                    username: Some("root"),
                    ..Member::regular("bin/cargo", CARGO_BYTES, 0o755)
                },
                Member::regular("producer.json", PRODUCER_BYTES, 0o644),
            ],
            vec![
                Member {
                    groupname: Some("wheel"),
                    ..Member::regular("bin/cargo", CARGO_BYTES, 0o755)
                },
                Member::regular("producer.json", PRODUCER_BYTES, 0o644),
            ],
            vec![
                Member::regular("producer.json", PRODUCER_BYTES, 0o644),
                Member::regular("bin/cargo", CARGO_BYTES, 0o755),
            ],
        ];
        for members in cases {
            let tree = TempTree::new();
            let compressed = xz(&archive(&members));
            let error = extract(&tree, &compressed, &rows(), &[], || Ok(())).unwrap_err();
            assert!(!error.to_string().is_empty());
            assert!(!tree.path().join("cargo-component").exists());
        }
    }

    #[test]
    fn refuses_extra_link_and_traversal_members() {
        let extra = xz(&archive(&[
            Member::regular("bin/cargo", CARGO_BYTES, 0o755),
            Member::regular("producer.json", PRODUCER_BYTES, 0o644),
            Member::regular("extra", b"extra", 0o644),
        ]));
        let linked = xz(&archive(&[
            Member {
                entry_type: EntryType::symlink(),
                link_name: Some("cargo"),
                ..Member::regular("bin/cargo", b"", 0o777)
            },
            Member::regular("producer.json", PRODUCER_BYTES, 0o644),
        ]));
        let pax = xz(&archive(&[
            Member {
                path: "PaxHeaders.0/bin/cargo",
                bytes: b"30 mtime=1791936000\n",
                entry_type: EntryType::new(b'x'),
                ..Member::regular("PaxHeaders.0/bin/cargo", b"", 0o644)
            },
            Member::regular("bin/cargo", CARGO_BYTES, 0o755),
            Member::regular("producer.json", PRODUCER_BYTES, 0o644),
        ]));
        let traversal = xz(&archive(&[
            Member::regular("../bin/cargo", CARGO_BYTES, 0o755),
            Member::regular("producer.json", PRODUCER_BYTES, 0o644),
        ]));
        for compressed in [extra, linked, traversal, pax] {
            let tree = TempTree::new();
            let error = extract(&tree, &compressed, &rows(), &[], || Ok(())).unwrap_err();
            assert!(!error.to_string().is_empty());
            assert!(!tree.path().join("cargo-component").exists());
        }
    }

    #[test]
    fn refuses_size_link_inventory_and_cancelled_publication_without_changes() {
        let tree = TempTree::new();
        let compressed = xz(&archive(&[
            Member::regular("bin/cargo", b"short", 0o755),
            Member::regular("producer.json", PRODUCER_BYTES, 0o644),
        ]));
        let error = extract(&tree, &compressed, &rows(), &[], || Ok(())).unwrap_err();
        assert!(error.to_string().contains("size"));

        let compressed = canonical_archive();
        let symlink_rows = vec![LinkIdentity {
            path: "bin/cargo".into(),
            target: "other".into(),
        }];
        let error = extract(&tree, &compressed, &rows(), &symlink_rows, || Ok(())).unwrap_err();
        assert!(error.to_string().contains("no symlinks"));

        fs::create_dir(tree.path().join("cargo-component")).unwrap();
        fs::write(tree.path().join("cargo-component/sentinel"), b"preserve").unwrap();
        let error = extract(&tree, &compressed, &rows(), &[], || Ok(())).unwrap_err();
        assert!(!error.to_string().is_empty());
        assert_eq!(
            fs::read(tree.path().join("cargo-component/sentinel")).unwrap(),
            b"preserve"
        );
        fs::remove_dir_all(tree.path().join("cargo-component")).unwrap();

        let mut saw_owned_stage = false;
        let error = extract(&tree, &compressed, &rows(), &[], || {
            let entries = fs::read_dir(tree.path())
                .map_err(|error| Refusal::new(format!("enumerate fixture: {error}")))?;
            for entry in entries {
                let entry =
                    entry.map_err(|error| Refusal::new(format!("read fixture: {error}")))?;
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".ami-rust-cargo-")
                {
                    saw_owned_stage = true;
                    return Err(Refusal::new("cancelled after staging directory creation"));
                }
            }
            Ok(())
        })
        .unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        assert!(saw_owned_stage);
        assert_eq!(fs::read_dir(tree.path()).unwrap().count(), 1);
        assert!(!tree.path().join("cargo-component").exists());
    }
}
