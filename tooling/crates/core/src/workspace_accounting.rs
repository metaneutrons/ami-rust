//! Descriptor-anchored regular-file and log-byte accounting.
//!
//! The scanner does not follow symlinks or open symlinks/special entries. It
//! samples regular-file sizes using one no-follow stat and counts hard links
//! once per directory entry, as the historical Python walker does.
//! Caller-selected entry and work bounds are required. The caller must validate
//! that the supplied root is the intended filesystem boundary. A present tree
//! is not an atomic snapshot against a concurrent same-UID writer; child
//! directory identity is checked after opening, while regular-file sizes come
//! from a single stat sample.

#![deny(unsafe_code)]

use crate::directory::Directory;

use std::{
    ffi::{CStr, CString, OsString},
    fmt,
    fs::File,
    io,
    os::{
        fd::{FromRawFd, IntoRawFd},
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::MetadataExt,
        },
    },
    path::Path,
};

const DIRECTORY_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScanLimits {
    /// Maximum non-dot directory entries processed over the whole walk.
    pub max_entries: u64,
    /// Maximum work units: one for opening the root, one for each entry's
    /// no-follow classification, and one more for opening a directory entry.
    pub max_work_units: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Accounting {
    pub regular_file_bytes: u64,
    pub log_file_bytes: u64,
    pub entries_seen: u64,
    pub work_units: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanError(String);

impl fmt::Display for ScanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ScanError {}

fn refusal(message: impl Into<String>) -> ScanError {
    ScanError(message.into())
}

fn io_refusal(context: &str) -> ScanError {
    refusal(format!("{context}: {}", io::Error::last_os_error()))
}

fn io_error(context: &str, error: io::Error) -> ScanError {
    refusal(format!("{context}: {error}"))
}

fn charge_work(
    accounting: &mut Accounting,
    limits: ScanLimits,
    units: u64,
) -> Result<(), ScanError> {
    let next = accounting
        .work_units
        .checked_add(units)
        .ok_or_else(|| refusal("directory accounting work counter overflow"))?;
    if next > limits.max_work_units {
        return Err(refusal("directory accounting work bound exceeded"));
    }
    accounting.work_units = next;
    Ok(())
}

fn charge_entry(accounting: &mut Accounting, limits: ScanLimits) -> Result<(), ScanError> {
    let next = accounting
        .entries_seen
        .checked_add(1)
        .ok_or_else(|| refusal("directory accounting entry counter overflow"))?;
    if next > limits.max_entries {
        return Err(refusal("directory accounting entry bound exceeded"));
    }
    accounting.entries_seen = next;
    Ok(())
}

fn add_bytes(current: u64, amount: u64) -> Result<u64, ScanError> {
    current
        .checked_add(amount)
        .ok_or_else(|| refusal("directory accounting byte sum overflow"))
}

fn is_log_name(name: &[u8]) -> bool {
    name.ends_with(b".log")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryKind {
    Regular,
    Directory,
    Symlink,
    Other,
}

#[derive(Clone, Copy, Debug)]
struct EntrySnapshot {
    device: u64,
    inode: u64,
    mode: u32,
    size: i64,
    kind: EntryKind,
}

impl EntrySnapshot {
    #[allow(clippy::unnecessary_cast)]
    fn from_stat(metadata: &libc::stat) -> Self {
        let mode = metadata.st_mode as u32;
        let kind = match mode & libc::S_IFMT as u32 {
            value if value == libc::S_IFREG as u32 => EntryKind::Regular,
            value if value == libc::S_IFDIR as u32 => EntryKind::Directory,
            value if value == libc::S_IFLNK as u32 => EntryKind::Symlink,
            _ => EntryKind::Other,
        };
        Self {
            device: metadata.st_dev as u64,
            inode: metadata.st_ino as u64,
            mode,
            size: metadata.st_size as i64,
            kind,
        }
    }
}

/// Scan one root using no-follow descriptor-relative operations.
///
/// Missing root paths return zero, matching the historical helper. Any other
/// root-open failure is visible. ENOENT for an entry that vanishes after
/// enumeration or a classified child directory removed before open is skipped
/// as in Python; other errors remain visible. Regular-file sizes are one
/// `fstatat` sample and can change before the next walk.
pub fn scan(root: &Path, limits: ScanLimits) -> Result<Accounting, ScanError> {
    validate_root_spelling(root)?;
    let Some(root_file) = open_root(root)
        .map_err(|error| io_error("could not open no-follow accounting root", error))?
    else {
        return Ok(Accounting::default());
    };
    scan_owned_root(root_file, limits)
}

/// Sample the exact directory already retained by the caller. Opening `.`
/// relative to that descriptor creates an independent enumeration cursor for
/// every sample; a duplicated descriptor would share the previous cursor.
/// The caller separately verifies that its required namespace still names this
/// directory. No pathname is reopened to choose the sampling boundary here.
pub fn scan_directory(root: &Directory, limits: ScanLimits) -> Result<Accounting, ScanError> {
    let root_file = open_directory_at(root.raw_fd(), c".")
        .map_err(|error| io_error("could not open anchored accounting cursor", error))?;
    scan_owned_root(root_file, limits)
}

fn scan_owned_root(root_file: File, limits: ScanLimits) -> Result<Accounting, ScanError> {
    let mut accounting = Accounting::default();
    let root_metadata = root_file
        .metadata()
        .map_err(|error| io_error("could not inspect accounting root", error))?;
    if !root_metadata.is_dir() {
        return Err(refusal("accounting root is not a directory"));
    }
    charge_work(&mut accounting, limits, 1)?;
    let root_fd = root_file.into_raw_fd();
    let root_stream = DirStream::from_owned_fd(root_fd)
        .map_err(|error| io_error("could not enumerate accounting root", error))?;
    let mut stack = vec![root_stream];

    while !stack.is_empty() {
        let next_name = stack
            .last_mut()
            .expect("nonempty directory stack")
            .next_name()
            .map_err(|error| io_error("could not read directory entry", error))?;
        let Some(name) = next_name else {
            stack.pop();
            continue;
        };
        let name_bytes = name.as_bytes();
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }

        charge_entry(&mut accounting, limits)?;
        charge_work(&mut accounting, limits, 1)?;
        let entry = CString::new(name_bytes)
            .map_err(|_| refusal("directory entry unexpectedly contains NUL"))?;
        let parent_fd = stack
            .last()
            .expect("current directory stream exists")
            .fd()?;
        let observed = match stat_at_if_present(parent_fd, &entry)
            .map_err(|error| io_error("could not classify no-follow directory entry", error))?
        {
            Some(observed) => observed,
            None => continue,
        };
        let snapshot = EntrySnapshot::from_stat(&observed);

        match snapshot.kind {
            EntryKind::Regular => {
                let bytes = u64::try_from(snapshot.size)
                    .map_err(|_| refusal("regular file has a negative sampled size"))?;
                accounting.regular_file_bytes = add_bytes(accounting.regular_file_bytes, bytes)?;
                if is_log_name(name_bytes) {
                    accounting.log_file_bytes = add_bytes(accounting.log_file_bytes, bytes)?;
                }
            }
            EntryKind::Directory => {
                charge_work(&mut accounting, limits, 1)?;
                let child = match open_directory_at_if_present(parent_fd, &entry)
                    .map_err(|error| io_error("could not open classified child directory", error))?
                {
                    Some(child) => child,
                    None => continue,
                };
                let metadata = child
                    .metadata()
                    .map_err(|error| io_error("could not inspect opened child directory", error))?;
                if !snapshot.matches_directory_metadata(&metadata) {
                    return Err(refusal(
                        "directory entry identity changed during accounting",
                    ));
                }
                let child_fd = child.into_raw_fd();
                let stream = DirStream::from_owned_fd(child_fd)
                    .map_err(|error| io_error("could not enumerate child directory", error))?;
                stack.push(stream);
            }
            // Ignore symlinks and special entries from their initial no-follow
            // classification, matching the historical one-stat sample.
            EntryKind::Symlink | EntryKind::Other => {}
        }
    }
    Ok(accounting)
}

fn validate_root_spelling(root: &Path) -> Result<(), ScanError> {
    let raw = root.as_os_str().as_bytes();
    if raw != b"/"
        && matches!(
            raw.rsplit(|byte| *byte == b'/').next(),
            Some(b"" | b"." | b"..")
        )
    {
        return Err(refusal(
            "accounting root must end in a named leaf, not a slash, dot or parent alias",
        ));
    }
    Ok(())
}

impl EntrySnapshot {
    fn matches_directory_metadata(self, metadata: &std::fs::Metadata) -> bool {
        self.device == metadata.dev()
            && self.inode == metadata.ino()
            && self.mode == metadata.mode()
            && self.kind == EntryKind::Directory
    }
}

#[allow(unsafe_code)]
fn stat_at(parent_fd: libc::c_int, name: &CStr) -> io::Result<libc::stat> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent_fd is a live directory descriptor, name is a live C
    // string, and successful fstatat initializes the entire stat structure.
    let result = unsafe {
        libc::fstatat(
            parent_fd,
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatat initialized the full structure.
    Ok(unsafe { metadata.assume_init() })
}

fn stat_at_if_present(parent_fd: libc::c_int, name: &CStr) -> io::Result<Option<libc::stat>> {
    match stat_at(parent_fd, name) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[allow(unsafe_code)]
fn open_root(root: &Path) -> io::Result<Option<File>> {
    let path = CString::new(root.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "root path contains NUL"))?;
    // SAFETY: path remains live through open and flags require no mode.
    let descriptor = unsafe { libc::open(path.as_ptr(), DIRECTORY_FLAGS) };
    if descriptor < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error);
    }
    // SAFETY: descriptor is fresh and transferred to this File.
    Ok(Some(unsafe { File::from_raw_fd(descriptor) }))
}

fn open_directory_at(parent_fd: libc::c_int, name: &CStr) -> io::Result<File> {
    open_file_at(parent_fd, name, DIRECTORY_FLAGS)
}

fn open_directory_at_if_present(parent_fd: libc::c_int, name: &CStr) -> io::Result<Option<File>> {
    match open_directory_at(parent_fd, name) {
        Ok(directory) => Ok(Some(directory)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[allow(unsafe_code)]
fn open_file_at(parent_fd: libc::c_int, name: &CStr, flags: libc::c_int) -> io::Result<File> {
    // SAFETY: parent_fd and name remain valid; flags require no mode argument.
    let descriptor = unsafe { libc::openat(parent_fd, name.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: descriptor is fresh and transferred to exactly one File.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

struct DirStream(*mut libc::DIR);

impl DirStream {
    #[allow(unsafe_code)]
    fn from_owned_fd(descriptor: libc::c_int) -> io::Result<Self> {
        // SAFETY: descriptor is an owned open directory descriptor. On
        // success, fdopendir transfers it to the returned DIR stream.
        let stream = unsafe { libc::fdopendir(descriptor) };
        if stream.is_null() {
            let error = io::Error::last_os_error();
            // SAFETY: failed fdopendir did not take ownership of descriptor.
            unsafe {
                libc::close(descriptor);
            }
            return Err(error);
        }
        Ok(Self(stream))
    }

    #[allow(unsafe_code)]
    fn fd(&self) -> Result<libc::c_int, ScanError> {
        // SAFETY: self owns a live DIR stream until Drop.
        let descriptor = unsafe { libc::dirfd(self.0) };
        if descriptor < 0 {
            Err(io_refusal("could not access live directory descriptor"))
        } else {
            Ok(descriptor)
        }
    }

    #[allow(unsafe_code)]
    fn next_name(&mut self) -> io::Result<Option<OsString>> {
        // SAFETY: errno is thread-local and available on the supported hosts.
        unsafe {
            *errno_pointer() = 0;
        }
        // SAFETY: self owns a live DIR; copy d_name before the next readdir.
        let entry = unsafe { libc::readdir(self.0) };
        if entry.is_null() {
            // SAFETY: errno is thread-local and valid for this platform.
            if unsafe { *errno_pointer() } != 0 {
                return Err(io::Error::last_os_error());
            }
            return Ok(None);
        }
        // SAFETY: readdir returns a live dirent with a NUL-terminated d_name.
        let bytes = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        Ok(Some(OsString::from_vec(bytes.to_vec())))
    }
}

impl Drop for DirStream {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: this object exclusively owns a successful fdopendir stream.
        unsafe {
            libc::closedir(self.0);
        }
    }
}

#[allow(unsafe_code)]
unsafe fn errno_pointer() -> *mut libc::c_int {
    #[cfg(target_os = "linux")]
    // SAFETY: libc exposes this thread's errno location.
    unsafe {
        libc::__errno_location()
    }
    #[cfg(target_os = "macos")]
    // SAFETY: libc exposes this thread's errno location.
    unsafe {
        libc::__error()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs::{self, OpenOptions, Permissions},
        io::Write,
        os::fd::AsRawFd,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

    struct Tree(PathBuf);

    impl Tree {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "rc1 observer accounting fixture {} {}",
                std::process::id(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).expect("create private accounting fixture");
            fs::set_permissions(&root, Permissions::from_mode(0o700)).unwrap();
            Self(root)
        }
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove accounting fixture");
        }
    }

    fn limits(entries: u64, work: u64) -> ScanLimits {
        ScanLimits {
            max_entries: entries,
            max_work_units: work,
        }
    }

    #[test]
    fn counts_regular_and_exact_log_suffixes_per_path_with_nested_spaces_and_hardlinks() {
        let tree = Tree::new();
        fs::create_dir(tree.0.join("nested dir")).unwrap();
        fs::write(tree.0.join("root.log"), b"abc").unwrap();
        fs::write(tree.0.join("plain"), b"12").unwrap();
        fs::write(tree.0.join("nested dir/inside.log"), b"12345").unwrap();
        fs::write(tree.0.join("nested dir/upper.LOG"), b"xxxx").unwrap();
        fs::hard_link(tree.0.join("root.log"), tree.0.join("nested dir/alias.log")).unwrap();

        let result = scan(&tree.0, limits(16, 32)).unwrap();
        assert_eq!(result.regular_file_bytes, 17);
        assert_eq!(result.log_file_bytes, 11);
        assert_eq!(result.entries_seen, 6);
        assert!(result.work_units <= 32);
    }

    #[test]
    fn symlinks_and_special_entries_contribute_zero_without_opening_targets() {
        let tree = Tree::new();
        let outside_tree = Tree::new();
        let outside = outside_tree.0.join("outside directory");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret.log"), b"outside bytes ignored").unwrap();
        symlink(outside.join("secret.log"), tree.0.join("external.log")).unwrap();
        symlink(&outside, tree.0.join("external directory")).unwrap();
        fs::write(tree.0.join("real.log"), b"inside").unwrap();
        create_fifo(&tree.0.join("pipe.log"));

        let result = scan(&tree.0, limits(16, 32)).unwrap();
        assert_eq!(result.regular_file_bytes, 6);
        assert_eq!(result.log_file_bytes, 6);
        assert_eq!(result.entries_seen, 4);
    }

    #[test]
    fn log_suffix_match_is_byte_preserving() {
        assert!(is_log_name(b"raw\xff.log"));
        assert!(is_log_name(b"nested path/file.log"));
        assert!(!is_log_name(b"file.LOG"));
    }

    #[test]
    fn missing_initial_root_is_zero_but_a_root_symlink_refuses() {
        let tree = Tree::new();
        let missing = tree.0.join("missing");
        assert_eq!(scan(&missing, limits(0, 0)).unwrap(), Accounting::default());

        let target = tree.0.join("target");
        fs::create_dir(&target).unwrap();
        let link = tree.0.join("root link");
        symlink(&target, &link).unwrap();
        assert!(scan(&link, limits(8, 16)).is_err());
        fs::write(target.join("outside.log"), b"must never be counted").unwrap();
        for suffix in ["/", "/.", "/.."] {
            let mut spelling = link.as_os_str().to_os_string();
            spelling.push(suffix);
            let error = scan(Path::new(&spelling), limits(8, 16))
                .expect_err("a root alias must not bypass the final no-follow leaf");
            assert!(error.to_string().contains("named leaf"));
        }
        assert!(validate_root_spelling(Path::new("/")).is_ok());
    }

    #[test]
    fn skips_only_enoent_for_entry_stat_and_child_directory_open() {
        let tree = Tree::new();
        let root = open_root(&tree.0).unwrap().unwrap();
        assert!(
            stat_at_if_present(root.as_raw_fd(), c"gone.log")
                .unwrap()
                .is_none()
        );

        let child = tree.0.join("vanishing directory");
        fs::create_dir(&child).unwrap();
        let classified = stat_at(root.as_raw_fd(), c"vanishing directory").unwrap();
        assert_eq!(
            EntrySnapshot::from_stat(&classified).kind,
            EntryKind::Directory
        );
        fs::remove_dir(&child).unwrap();
        assert!(
            open_directory_at_if_present(root.as_raw_fd(), c"vanishing directory")
                .unwrap()
                .is_none()
        );

        // EBADF is not ENOENT and must remain visible through both helpers.
        assert!(stat_at_if_present(-1, c"gone").is_err());
        assert!(open_directory_at_if_present(-1, c"gone").is_err());
    }

    #[test]
    fn caller_entry_and_work_bounds_refuse_excess_work() {
        let tree = Tree::new();
        fs::write(tree.0.join("one"), b"x").unwrap();
        assert!(scan(&tree.0, limits(0, 16)).is_err());
        assert!(scan(&tree.0, limits(1, 1)).is_err());
        // Root stream setup and one no-follow stat fit; regular files are
        // counted from that stat sample and require no second open unit.
        let result = scan(&tree.0, limits(1, 2)).unwrap();
        assert_eq!(result.regular_file_bytes, 1);
        assert_eq!(result.work_units, 2);
    }

    #[test]
    fn counts_regular_files_without_read_permission() {
        let tree = Tree::new();
        let unreadable = tree.0.join("unreadable.log");
        fs::write(&unreadable, b"no read required").unwrap();
        fs::set_permissions(&unreadable, Permissions::from_mode(0o000)).unwrap();

        let result = scan(&tree.0, limits(4, 8)).unwrap();
        assert_eq!(result.regular_file_bytes, 16);
        assert_eq!(result.log_file_bytes, 16);
    }

    #[test]
    fn later_sampling_observes_a_regular_log_file_growing() {
        let tree = Tree::new();
        let log = tree.0.join("application.log");
        fs::write(&log, b"a").unwrap();
        let first = scan(&tree.0, limits(4, 8)).unwrap();
        assert_eq!(first.regular_file_bytes, 1);
        assert_eq!(first.log_file_bytes, 1);

        let mut appended = OpenOptions::new().append(true).open(&log).unwrap();
        appended.write_all(b"bc").unwrap();
        drop(appended);

        let second = scan(&tree.0, limits(4, 8)).unwrap();
        assert_eq!(second.regular_file_bytes, 3);
        assert_eq!(second.log_file_bytes, 3);
    }

    #[test]
    fn retained_directory_samples_repeat_with_independent_cursors_after_path_replacement() {
        let tree = Tree::new();
        let root = tree.0.join("sample root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("build.log"), b"abc").unwrap();
        let directory = Directory::open(&fs::canonicalize(&root).unwrap()).unwrap();
        assert_eq!(
            scan_directory(&directory, limits(4, 8))
                .unwrap()
                .log_file_bytes,
            3
        );
        assert_eq!(
            scan_directory(&directory, limits(4, 8))
                .unwrap()
                .log_file_bytes,
            3
        );

        let moved = tree.0.join("retained root");
        fs::rename(&root, &moved).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(root.join("replacement.log"), b"unrelated replacement bytes").unwrap();
        fs::write(moved.join("build.log"), b"abcde").unwrap();
        let sample = scan_directory(&directory, limits(4, 8)).unwrap();
        assert_eq!(sample.regular_file_bytes, 5);
        assert_eq!(sample.log_file_bytes, 5);
        // Namespace validation belongs to the observer; the sampler must not
        // silently switch from the retained handle to the replacement path.
        assert_ne!(
            directory.metadata().unwrap().ino(),
            fs::metadata(&root).unwrap().ino()
        );
    }

    #[test]
    fn byte_accumulation_checks_u64_overflow() {
        assert!(add_bytes(u64::MAX, 1).is_err());
        assert_eq!(add_bytes(7, 9).unwrap(), 16);
    }

    #[allow(unsafe_code)]
    fn create_fifo(path: &Path) {
        let encoded = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: the path is a live NUL-terminated name in a private fixture.
        assert_eq!(unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) }, 0);
    }
}
