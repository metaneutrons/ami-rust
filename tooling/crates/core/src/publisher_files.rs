//! Descriptor-anchored read-only access to publisher bundle files.
//!
//! These helpers validate a bounded file tree and read bounded regular files.
//! They do not authenticate the tree or provide a snapshot against another
//! process that can mutate entries or file contents during access. The caller
//! must rely on a trusted, stable bundle tree; descriptor-relative checks catch
//! ordinary replacement between classification and open but are not an atomic
//! defense against a malicious same-owner writer.

use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs::{File, Metadata},
    io::{self, Read},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
};

use crate::{
    Refusal, Result,
    directory::{Directory, EntryType},
};

const MAX_BUNDLE_FILES: usize = 512;
pub(crate) const LEGACY_BUNDLE_BYTE_LIMIT: u64 = 32 * 1024 * 1024;
pub(crate) const NATIVE_BUNDLE_BYTE_LIMIT: u64 = 64 * 1024 * 1024;
const MAX_PATH_COMPONENTS: usize = 24;
const READ_BUFFER_BYTES: usize = 16 * 1024;

/// Exact file paths and byte count measured during a bounded tree scan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleMeasurement {
    pub files: BTreeSet<String>,
    pub total_file_bytes: u64,
}

/// Read one portable bundle file without following any path component.
///
/// The entry is classified without following links before open, then the
/// opened descriptor is checked against that identity. Its size, mode, owner,
/// mtime, and ctime must also remain stable across the read. These checks do
/// not close the race against a malicious same-owner writer that changes the
/// entry after classification.
pub fn read_bundle_file(root: &Directory, relative: &str, limit: usize) -> Result<Vec<u8>> {
    let path = validate_path(relative.as_bytes())?;
    if path != relative {
        return Err(Refusal::new("bundle path is not canonical"));
    }
    let (parent_path, leaf) = match relative.rsplit_once('/') {
        Some((parent, leaf)) => (parent, leaf),
        None => ("", relative),
    };
    let parent = root.relative_directory(parent_path)?;
    let leaf = OsStr::new(leaf);
    let identity = parent.classify_entry(leaf)?;
    if identity.entry_type() != EntryType::RegularFile {
        return Err(Refusal::new("bundle entry is not a regular file"));
    }
    let file = parent.open_regular_matching(leaf, identity)?;
    read_open_regular(file, limit)
}

/// Read an already descriptor-validated regular file, with ordinary change
/// detection. External protected files use this after ownership validation.
pub(crate) fn read_open_regular(mut file: File, limit: usize) -> Result<Vec<u8>> {
    let before = metadata(&file)?;
    if !before.file_type().is_file() {
        return Err(Refusal::new("bundle entry is not a regular file"));
    }
    let initial_length = usize::try_from(before.len())
        .map_err(|_| Refusal::new("bundle file length cannot fit in memory"))?;
    if initial_length > limit {
        return Err(Refusal::new("bundle file exceeds its byte limit"));
    }

    let contents = read_file_contents(&mut file, limit, initial_length)?;
    let after = metadata(&file)?;
    if !same_file_state(&before, &after) {
        return Err(Refusal::new("bundle file changed while it was being read"));
    }
    Ok(contents)
}

/// Measure a legacy publisher bundle under its fixed 32 MiB aggregate limit
/// and require exactly the authenticated file and directory paths. Entries are
/// classified without following links before opening, then checked against the
/// opened descriptor. File contents are not re-read here, and concurrent tree
/// changes are not a snapshot guarantee.
pub fn scan_bundle_exact(
    root: &Directory,
    expected_files: &BTreeSet<String>,
    allowed_directories: &BTreeSet<String>,
) -> Result<BundleMeasurement> {
    scan_bundle_exact_with_limit(
        root,
        expected_files,
        allowed_directories,
        LEGACY_BUNDLE_BYTE_LIMIT,
    )
}

/// Measure a native-v2 publisher bundle under its bounded 64 MiB aggregate
/// profile. Legacy inspection callers keep the public 32 MiB scan.
pub(crate) fn scan_native_bundle_exact(
    root: &Directory,
    expected_files: &BTreeSet<String>,
    allowed_directories: &BTreeSet<String>,
) -> Result<BundleMeasurement> {
    scan_bundle_exact_with_limit(
        root,
        expected_files,
        allowed_directories,
        NATIVE_BUNDLE_BYTE_LIMIT,
    )
}

fn scan_bundle_exact_with_limit(
    root: &Directory,
    expected_files: &BTreeSet<String>,
    allowed_directories: &BTreeSet<String>,
    byte_limit: u64,
) -> Result<BundleMeasurement> {
    let expected_directories = validate_expected_paths(expected_files)?;
    if &expected_directories != allowed_directories {
        return Err(Refusal::new(
            "allowed bundle directories do not match expected file ancestors",
        ));
    }
    let entry_limit = expected_files
        .len()
        .checked_add(allowed_directories.len())
        .ok_or_else(|| Refusal::new("bundle entry bound overflow"))?;
    let mut state = ScanState {
        expected_files,
        allowed_directories,
        entry_limit,
        byte_limit,
        entries_seen: 0,
        files: BTreeSet::new(),
        directories: BTreeSet::new(),
        total_file_bytes: 0,
    };
    scan_directory(root, "", 0, &mut state)?;
    if &state.files != expected_files {
        return Err(Refusal::new(
            "bundle file set differs from the expected set",
        ));
    }
    if &state.directories != allowed_directories {
        return Err(Refusal::new(
            "bundle directory set differs from the allowed set",
        ));
    }
    Ok(BundleMeasurement {
        files: state.files,
        total_file_bytes: state.total_file_bytes,
    })
}

struct ScanState<'a> {
    expected_files: &'a BTreeSet<String>,
    allowed_directories: &'a BTreeSet<String>,
    entry_limit: usize,
    byte_limit: u64,
    entries_seen: usize,
    files: BTreeSet<String>,
    directories: BTreeSet<String>,
    total_file_bytes: u64,
}

fn scan_directory(
    directory: &Directory,
    prefix: &str,
    depth: usize,
    state: &mut ScanState<'_>,
) -> Result<()> {
    let remaining = state
        .entry_limit
        .checked_sub(state.entries_seen)
        .ok_or_else(|| Refusal::new("bundle entry count exceeded its bound"))?;
    let names = directory.names(remaining)?;
    state.entries_seen = state
        .entries_seen
        .checked_add(names.len())
        .ok_or_else(|| Refusal::new("bundle entry count overflow"))?;

    for name in names {
        let path = joined_path(prefix, &name)?;
        let canonical = validate_path(path.as_bytes())?;
        if canonical != path {
            return Err(Refusal::new("bundle entry path is not canonical"));
        }

        let identity = directory.classify_entry(&name)?;
        match identity.entry_type() {
            EntryType::Directory => {
                if depth >= MAX_PATH_COMPONENTS || !state.allowed_directories.contains(&path) {
                    return Err(Refusal::new(format!(
                        "bundle contains an extra or over-nested directory: {path}"
                    )));
                }
                let child = directory.open_child_matching(&name, identity)?;
                state.directories.insert(path.clone());
                scan_directory(&child, &path, depth + 1, state)?;
            }
            EntryType::RegularFile => {
                if !state.expected_files.contains(&path) {
                    return Err(Refusal::new(format!(
                        "bundle contains an extra file: {path}"
                    )));
                }
                if !state.files.insert(path.clone()) {
                    return Err(Refusal::new(format!(
                        "bundle contains a duplicate file: {path}"
                    )));
                }
                let file = directory.open_regular_matching(&name, identity)?;
                let file_metadata = metadata(&file)?;
                state.total_file_bytes = state
                    .total_file_bytes
                    .checked_add(file_metadata.len())
                    .ok_or_else(|| Refusal::new("bundle file byte count overflow"))?;
                if state.total_file_bytes > state.byte_limit {
                    return Err(Refusal::new(format!(
                        "bundle files exceed the {}-byte limit",
                        state.byte_limit
                    )));
                }
                if depth + 1 > MAX_PATH_COMPONENTS {
                    return Err(Refusal::new(format!(
                        "bundle file path is too deeply nested: {path}"
                    )));
                }
            }
            EntryType::Symlink => {
                return Err(Refusal::new(format!("bundle symlink is forbidden: {path}")));
            }
            EntryType::Other => {
                return Err(Refusal::new(format!(
                    "bundle entry is not a regular file or directory: {path}"
                )));
            }
        }
    }
    Ok(())
}

fn validate_expected_paths(expected_files: &BTreeSet<String>) -> Result<BTreeSet<String>> {
    if expected_files.len() > MAX_BUNDLE_FILES {
        return Err(Refusal::new(format!(
            "bundle has more than {MAX_BUNDLE_FILES} expected files"
        )));
    }
    let mut directories = BTreeSet::new();
    for path in expected_files {
        let canonical = validate_path(path.as_bytes())?;
        if canonical != *path {
            return Err(Refusal::new("expected bundle path is not canonical"));
        }
        let mut parent = String::new();
        let mut components = path.split('/').peekable();
        while let Some(component) = components.next() {
            if components.peek().is_none() {
                break;
            }
            if !parent.is_empty() {
                parent.push('/');
            }
            parent.push_str(component);
            if expected_files.contains(&parent) {
                return Err(Refusal::new(
                    "expected bundle file conflicts with a directory path",
                ));
            }
            directories.insert(parent.clone());
        }
    }
    if directories.len() > MAX_BUNDLE_FILES * (MAX_PATH_COMPONENTS - 1) {
        return Err(Refusal::new(
            "expected bundle directory count exceeds its bound",
        ));
    }
    Ok(directories)
}

fn validate_path(bytes: &[u8]) -> Result<String> {
    if bytes.is_empty()
        || bytes.len() > 240
        || bytes[0] == b'/'
        || bytes.contains(&b'\\')
        || bytes.contains(&b':')
        || !bytes.iter().all(|byte| (0x20..0x7f).contains(byte))
    {
        return Err(Refusal::new("bundle path is not a portable relative path"));
    }
    let path =
        std::str::from_utf8(bytes).map_err(|_| Refusal::new("bundle path is not valid ASCII"))?;
    let components: Vec<&str> = path.split('/').collect();
    if components.len() > MAX_PATH_COMPONENTS {
        return Err(Refusal::new("bundle path has too many components"));
    }
    if components.iter().any(|component| {
        component.is_empty()
            || *component == "."
            || *component == ".."
            || component.len() > 120
            || component.ends_with('.')
            || !component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
    }) {
        return Err(Refusal::new("bundle path has a nonportable component"));
    }
    Ok(path.to_owned())
}

fn joined_path(prefix: &str, name: &OsStr) -> Result<String> {
    let mut bytes = Vec::with_capacity(prefix.len() + usize::from(!prefix.is_empty()) + name.len());
    if !prefix.is_empty() {
        bytes.extend_from_slice(prefix.as_bytes());
        bytes.push(b'/');
    }
    bytes.extend_from_slice(name.as_bytes());
    validate_path(&bytes)
}

fn metadata(file: &File) -> Result<Metadata> {
    file.metadata()
        .map_err(|error| Refusal::new(format!("could not inspect bundle file: {error}")))
}

fn same_file_state(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn read_file_contents(
    reader: &mut impl Read,
    limit: usize,
    initial_length: usize,
) -> Result<Vec<u8>> {
    if initial_length > limit {
        return Err(Refusal::new("bundle file exceeds its byte limit"));
    }
    let read_bound = limit
        .checked_add(1)
        .ok_or_else(|| Refusal::new("bundle file limit cannot be incremented safely"))?;
    let mut contents = Vec::new();
    contents
        .try_reserve_exact(initial_length)
        .map_err(|error| Refusal::new(format!("could not allocate bundle file: {error}")))?;
    let mut buffer = [0_u8; READ_BUFFER_BYTES];
    loop {
        let remaining = read_bound - contents.len();
        let amount = buffer.len().min(remaining);
        match reader.read(&mut buffer[..amount]) {
            Ok(0) => {
                if contents.len() != initial_length {
                    return Err(Refusal::new("bundle file length changed while being read"));
                }
                return Ok(contents);
            }
            Ok(read) => {
                if contents.len() + read > limit {
                    return Err(Refusal::new("bundle file exceeds its byte limit"));
                }
                contents.try_reserve(read).map_err(|error| {
                    Refusal::new(format!("could not grow bundle file buffer: {error}"))
                })?;
                contents.extend_from_slice(&buffer[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Refusal::new(format!("could not read bundle file: {error}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BundleMeasurement, LEGACY_BUNDLE_BYTE_LIMIT, NATIVE_BUNDLE_BYTE_LIMIT, read_bundle_file,
        read_file_contents, scan_bundle_exact, scan_native_bundle_exact,
    };
    use crate::directory::Directory;
    use std::{
        collections::BTreeSet,
        fs::{self, File},
        io::{self, Cursor},
        os::unix::ffi::OsStrExt,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::current_dir()
                .expect("current directory")
                .join(format!(
                    ".ami-publisher-files-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            fs::create_dir(&path).expect("create fixture directory");
            Self(path)
        }

        fn root(&self) -> Directory {
            Directory::open(&self.0).expect("open fixture directory")
        }

        fn write(&self, path: &str, bytes: &[u8]) {
            let target = self.0.join(path);
            fs::create_dir_all(target.parent().expect("parent path")).expect("create parents");
            fs::write(target, bytes).expect("write fixture file");
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove fixture directory");
        }
    }

    fn paths(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn reads_empty_and_exact_limit_files() {
        let fixture = Fixture::new();
        fixture.write("empty", b"");
        fixture.write("nested/exact", b"1234");
        let root = fixture.root();
        assert_eq!(read_bundle_file(&root, "empty", 0).unwrap(), b"");
        assert_eq!(read_bundle_file(&root, "nested/exact", 4).unwrap(), b"1234");
        assert!(read_bundle_file(&root, "nested/exact", 3).is_err());
    }

    #[test]
    fn scan_accepts_the_complete_nested_file_and_directory_set() {
        let fixture = Fixture::new();
        fixture.write("root.bin", b"abc");
        fixture.write("nested/child.bin", b"12345");
        fixture.write("nested/deeper/empty", b"");
        let root = fixture.root();
        assert_eq!(
            scan_bundle_exact(
                &root,
                &paths(&["root.bin", "nested/child.bin", "nested/deeper/empty"]),
                &paths(&["nested", "nested/deeper"]),
            )
            .unwrap(),
            BundleMeasurement {
                files: paths(&["root.bin", "nested/child.bin", "nested/deeper/empty"]),
                total_file_bytes: 8,
            }
        );
    }

    #[test]
    fn scan_accepts_an_empty_tree_only_with_empty_expected_sets() {
        let fixture = Fixture::new();
        let root = fixture.root();
        assert_eq!(
            scan_bundle_exact(&root, &paths(&[]), &paths(&[])).unwrap(),
            BundleMeasurement {
                files: paths(&[]),
                total_file_bytes: 0,
            }
        );
    }

    #[test]
    fn scan_refuses_extra_missing_and_empty_extra_directory_entries() {
        let extra_file = Fixture::new();
        extra_file.write("extra", b"x");
        assert!(scan_bundle_exact(&extra_file.root(), &paths(&["wanted"]), &paths(&[])).is_err());

        let missing_file = Fixture::new();
        assert!(
            scan_bundle_exact(&missing_file.root(), &paths(&["missing"]), &paths(&[])).is_err()
        );

        let empty_directory = Fixture::new();
        fs::create_dir(empty_directory.0.join("empty")).unwrap();
        assert!(
            scan_bundle_exact(&empty_directory.root(), &paths(&["wanted"]), &paths(&[])).is_err()
        );
    }

    #[test]
    fn scan_and_read_refuse_symlinks_and_unsafe_leaf_names() {
        let leaf_link = Fixture::new();
        leaf_link.write("target", b"data");
        fs::create_dir(leaf_link.0.join("bundle")).unwrap();
        std::os::unix::fs::symlink("../target", leaf_link.0.join("bundle/requested")).unwrap();
        let root = Directory::open(&leaf_link.0.join("bundle")).unwrap();
        assert!(read_bundle_file(&root, "requested", 4).is_err());
        assert!(scan_bundle_exact(&root, &paths(&["requested"]), &paths(&[])).is_err());

        let ancestor_link = Fixture::new();
        ancestor_link.write("outside/file", b"data");
        fs::create_dir(ancestor_link.0.join("bundle")).unwrap();
        std::os::unix::fs::symlink("../outside", ancestor_link.0.join("bundle/alias")).unwrap();
        let root = Directory::open(&ancestor_link.0.join("bundle")).unwrap();
        assert!(read_bundle_file(&root, "alias/file", 4).is_err());
        assert!(scan_bundle_exact(&root, &paths(&["alias/file"]), &paths(&["alias"])).is_err());

        let unsafe_name = Fixture::new();
        unsafe_name.write("bad\\name", b"data");
        let unsafe_root = unsafe_name.root();
        assert!(read_bundle_file(&unsafe_root, "bad\\name", 4).is_err());
        assert!(scan_bundle_exact(&unsafe_root, &paths(&["wanted"]), &paths(&[])).is_err());
    }

    #[test]
    fn scan_refuses_fifo_without_blocking_and_enforces_combined_byte_limit() {
        let fifo = Fixture::new();
        create_fifo(&fifo.0.join("pipe"));
        assert!(scan_bundle_exact(&fifo.root(), &paths(&["pipe"]), &paths(&[])).is_err());

        let exact_limit = Fixture::new();
        let file = File::create(exact_limit.0.join("large")).unwrap();
        file.set_len(LEGACY_BUNDLE_BYTE_LIMIT).unwrap();
        assert_eq!(
            scan_bundle_exact(&exact_limit.root(), &paths(&["large"]), &paths(&[]))
                .unwrap()
                .total_file_bytes,
            LEGACY_BUNDLE_BYTE_LIMIT
        );

        let oversized = Fixture::new();
        let file = File::create(oversized.0.join("large")).unwrap();
        file.set_len(LEGACY_BUNDLE_BYTE_LIMIT + 1).unwrap();
        assert!(scan_bundle_exact(&oversized.root(), &paths(&["large"]), &paths(&[])).is_err());
    }

    #[test]
    fn native_bundle_scan_has_exact_64_mib_aggregate_boundary() {
        let at_limit = Fixture::new();
        let file = File::create(at_limit.0.join("large")).unwrap();
        file.set_len(NATIVE_BUNDLE_BYTE_LIMIT).unwrap();
        assert_eq!(
            scan_native_bundle_exact(&at_limit.root(), &paths(&["large"]), &paths(&[]))
                .unwrap()
                .total_file_bytes,
            NATIVE_BUNDLE_BYTE_LIMIT
        );
        assert!(
            scan_bundle_exact(&at_limit.root(), &paths(&["large"]), &paths(&[])).is_err(),
            "the public legacy scanner must retain its 32 MiB profile"
        );

        let over_limit = Fixture::new();
        let file = File::create(over_limit.0.join("large")).unwrap();
        file.set_len(NATIVE_BUNDLE_BYTE_LIMIT + 1).unwrap();
        assert!(
            scan_native_bundle_exact(&over_limit.root(), &paths(&["large"]), &paths(&[])).is_err()
        );
    }

    #[test]
    fn retained_root_survives_rename_during_access() {
        let fixture = Fixture::new();
        let bundle = fixture.0.join("bundle");
        fs::create_dir(&bundle).unwrap();
        fs::write(bundle.join("file"), b"kept").unwrap();
        let root = Directory::open(&bundle).unwrap();
        fs::rename(&bundle, fixture.0.join("renamed")).unwrap();
        assert_eq!(read_bundle_file(&root, "file", 4).unwrap(), b"kept");
        assert_eq!(
            scan_bundle_exact(&root, &paths(&["file"]), &paths(&[]))
                .unwrap()
                .total_file_bytes,
            4
        );
    }

    #[test]
    fn bounded_reader_refuses_growth_even_when_still_under_the_limit() {
        let mut reader = Cursor::new(b"four".as_slice());
        assert!(read_file_contents(&mut reader, 8, 3).is_err());
        let mut at_limit = Cursor::new(b"four".as_slice());
        assert_eq!(read_file_contents(&mut at_limit, 4, 4).unwrap(), b"four");
    }

    #[allow(unsafe_code)]
    fn create_fifo(path: &Path) {
        use std::ffi::CString;
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: path is a valid NUL-terminated path and mode is ordinary permissions.
        let result = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
        assert_eq!(result, 0, "create FIFO: {}", io::Error::last_os_error());
    }

    #[test]
    fn scan_preserves_the_historical_path_profile_for_reserved_device_names() {
        let fixture = Fixture::new();
        fixture.write("CON.json", b"x");
        let root = fixture.root();
        assert_eq!(read_bundle_file(&root, "CON.json", 1).unwrap(), b"x");
        assert_eq!(
            scan_bundle_exact(&root, &paths(&["CON.json"]), &paths(&[]))
                .unwrap()
                .files,
            paths(&["CON.json"])
        );
    }
}
