//! Descriptor-anchored, read-only directory access for inventory verification.
//!
//! Directory descriptors survive pathname replacement. They do not freeze
//! concurrent changes by another writer to the same directory or inode.

use crate::{Refusal, Result};
use std::{
    ffi::{CStr, CString, OsStr, OsString},
    fs::{File, Metadata},
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::MetadataExt,
        },
    },
    path::{Component, Path},
};

const FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;

fn error(context: &str) -> Refusal {
    Refusal::new(format!("{context}: {}", io::Error::last_os_error()))
}

fn name(value: &OsStr) -> Result<CString> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(Refusal::new("expected one ordinary directory entry name"));
    }
    CString::new(bytes).map_err(|_| Refusal::new("directory entry name contains NUL"))
}

#[derive(Debug)]
pub struct Directory(File);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EntryType {
    Directory,
    RegularFile,
    Symlink,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EntryIdentity {
    entry_type: EntryType,
    device: u64,
    inode: u64,
    mode: u32,
}

impl EntryIdentity {
    pub(crate) fn entry_type(self) -> EntryType {
        self.entry_type
    }

    pub(crate) fn matches_metadata(self, metadata: &Metadata) -> bool {
        self.device == metadata.dev()
            && self.inode == metadata.ino()
            && self.mode == metadata.mode()
            && self.entry_type == EntryType::from_mode(metadata.mode())
    }
}

impl EntryType {
    #[allow(
        clippy::unnecessary_cast,
        reason = "POSIX mode field widths differ between macOS and Linux."
    )]
    fn from_mode(mode: u32) -> Self {
        match mode & libc::S_IFMT as u32 {
            value if value == libc::S_IFDIR as u32 => Self::Directory,
            value if value == libc::S_IFREG as u32 => Self::RegularFile,
            value if value == libc::S_IFLNK as u32 => Self::Symlink,
            _ => Self::Other,
        }
    }
}

impl Directory {
    pub(crate) fn raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }

    /// Open each ancestor without following symlinks. Parent traversal refuses.
    #[allow(unsafe_code)]
    pub fn open(path: &Path) -> Result<Self> {
        let anchor = if path.is_absolute() { c"/" } else { c"." };
        // SAFETY: anchor is static and flags do not require a mode argument.
        let fd = unsafe { libc::open(anchor.as_ptr(), FLAGS) };
        if fd < 0 {
            return Err(error("could not open directory anchor"));
        }
        // SAFETY: fd is fresh and transferred to exactly one owning File.
        let mut current = Self(unsafe { File::from_raw_fd(fd) });
        for part in path.components() {
            match part {
                Component::RootDir | Component::CurDir => {}
                Component::Normal(part) => current = current.child(part)?,
                _ => return Err(Refusal::new("directory path contains parent traversal")),
            }
        }
        Ok(current)
    }

    pub fn metadata(&self) -> Result<Metadata> {
        self.0
            .metadata()
            .map_err(|e| Refusal::new(format!("could not inspect directory: {e}")))
    }

    /// Classify one entry without following a symlink or opening its target.
    #[allow(unsafe_code)]
    #[allow(
        clippy::unnecessary_cast,
        reason = "POSIX stat field widths differ between macOS and Linux."
    )]
    pub(crate) fn classify_entry(&self, entry: &OsStr) -> Result<EntryIdentity> {
        let entry = name(entry)?;
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: the parent descriptor and basename are valid; successful
        // fstatat initializes the struct, and AT_SYMLINK_NOFOLLOW classifies a
        // symlink itself without opening or following its target.
        let result = unsafe {
            libc::fstatat(
                self.0.as_raw_fd(),
                entry.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            return Err(error("could not classify anchored directory entry"));
        }
        // SAFETY: successful fstatat initialized the complete stat structure.
        let metadata = unsafe { metadata.assume_init() };
        let mode = metadata.st_mode as u32;
        Ok(EntryIdentity {
            entry_type: EntryType::from_mode(mode),
            device: metadata.st_dev as u64,
            inode: metadata.st_ino as u64,
            mode,
        })
    }

    /// Open a previously classified directory and verify that the descriptor
    /// still refers to that exact entry identity.
    pub(crate) fn open_child_matching(
        &self,
        entry: &OsStr,
        expected: EntryIdentity,
    ) -> Result<Self> {
        if expected.entry_type != EntryType::Directory {
            return Err(Refusal::new("classified bundle entry is not a directory"));
        }
        let child = self.child(entry)?;
        if !expected.matches_metadata(&child.metadata()?) {
            return Err(Refusal::new(
                "bundle directory changed after no-follow classification",
            ));
        }
        Ok(child)
    }

    /// Open a previously classified regular file and verify the descriptor's
    /// identity before any caller reads its contents.
    pub(crate) fn open_regular_matching(
        &self,
        entry: &OsStr,
        expected: EntryIdentity,
    ) -> Result<File> {
        if expected.entry_type != EntryType::RegularFile {
            return Err(Refusal::new(
                "classified bundle entry is not a regular file",
            ));
        }
        let file = self.regular(entry)?;
        let metadata = file.metadata().map_err(|error| {
            Refusal::new(format!("could not inspect opened bundle entry: {error}"))
        })?;
        if !expected.matches_metadata(&metadata) {
            return Err(Refusal::new(
                "bundle file changed after no-follow classification",
            ));
        }
        Ok(file)
    }

    pub fn child(&self, entry: &OsStr) -> Result<Self> {
        self.open_entry(entry, FLAGS).map(Self)
    }

    /// Resolve a portable relative directory from this retained root handle.
    pub fn relative_directory(&self, path: &str) -> Result<Self> {
        let mut current = Self(
            self.0
                .try_clone()
                .map_err(|e| Refusal::new(format!("could not retain directory handle: {e}")))?,
        );
        if path.is_empty() {
            return Ok(current);
        }
        crate::files::validate_relative_inventory_path(path)?;
        for component in path.split('/') {
            current = current.child(OsStr::new(component))?;
        }
        Ok(current)
    }

    pub fn regular(&self, entry: &OsStr) -> Result<File> {
        let expected = self.classify_entry(entry)?;
        if expected.entry_type() != EntryType::RegularFile {
            return Err(Refusal::new("inventory entry is not a regular file"));
        }
        let file = self.open_entry(
            entry,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )?;
        let metadata = file
            .metadata()
            .map_err(|e| Refusal::new(format!("could not inspect entry: {e}")))?;
        if !expected.matches_metadata(&metadata) {
            return Err(Refusal::new(
                "regular file changed after no-follow classification",
            ));
        }
        Ok(file)
    }

    #[allow(unsafe_code)]
    fn open_entry(&self, entry: &OsStr, flags: libc::c_int) -> Result<File> {
        let entry = name(entry)?;
        // SAFETY: parent owns a live descriptor; entry is NUL terminated.
        let fd = unsafe { libc::openat(self.0.as_raw_fd(), entry.as_ptr(), flags) };
        if fd < 0 {
            return Err(error("could not open anchored directory entry"));
        }
        // SAFETY: fd is fresh and owned by the returned File only.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    /// Read a link without following it. The caller supplies a target-byte bound.
    #[allow(unsafe_code)]
    pub fn link_target(&self, entry: &OsStr, maximum: usize) -> Result<OsString> {
        let entry = name(entry)?;
        let size = maximum
            .checked_add(1)
            .ok_or_else(|| Refusal::new("link target bound overflow"))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| Refusal::new("could not allocate link target buffer"))?;
        bytes.resize(size, 0);
        // SAFETY: buffer has size writable bytes, and both descriptor and name
        // remain live throughout readlinkat. No C string terminator is assumed.
        let count = unsafe {
            libc::readlinkat(
                self.0.as_raw_fd(),
                entry.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if count < 0 {
            return Err(error("could not read anchored symlink"));
        }
        let count =
            usize::try_from(count).map_err(|_| Refusal::new("link length is not representable"))?;
        if count > maximum {
            return Err(Refusal::new("symlink target exceeds expected bound"));
        }
        bytes.truncate(count);
        Ok(OsString::from_vec(bytes))
    }

    /// Enumerate byte-preserving entry names with a fresh directory stream.
    /// The limit bounds allocation before another entry name is retained.
    #[allow(unsafe_code)]
    pub fn names(&self, maximum: usize) -> Result<Vec<OsString>> {
        // Opening '.' produces an independent directory offset; dup would share
        // an offset and make a second enumeration spuriously appear empty.
        // SAFETY: parent descriptor and static C string are valid.
        let fd = unsafe { libc::openat(self.0.as_raw_fd(), c".".as_ptr(), FLAGS) };
        if fd < 0 {
            return Err(error("could not open directory enumeration"));
        }
        // SAFETY: fd is a live directory descriptor. On success fdopendir owns it.
        let pointer = unsafe { libc::fdopendir(fd) };
        if pointer.is_null() {
            let refusal = error("could not begin directory enumeration");
            // SAFETY: fdopendir failed and did not take descriptor ownership.
            unsafe {
                libc::close(fd);
            }
            return Err(refusal);
        }
        struct Stream(*mut libc::DIR);
        impl Drop for Stream {
            fn drop(&mut self) {
                // SAFETY: this guard exclusively owns a successful fdopendir.
                unsafe {
                    libc::closedir(self.0);
                }
            }
        }
        let stream = Stream(pointer);
        let mut result = Vec::new();
        loop {
            // SAFETY: errno is thread local. Clear it to distinguish EOF/error.
            unsafe {
                *errno_pointer() = 0;
            }
            // SAFETY: stream owns a live DIR; each name is copied before the
            // next readdir invalidates the returned pointer.
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                // SAFETY: thread-local errno is valid for this platform.
                if unsafe { *errno_pointer() } != 0 {
                    return Err(error("could not enumerate directory"));
                }
                break;
            }
            // SAFETY: a successful readdir supplies a NUL-terminated d_name.
            let entry = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if entry == b"." || entry == b".." {
                continue;
            }
            if result.len() == maximum {
                return Err(Refusal::new(
                    "directory entry count exceeds inventory bound",
                ));
            }
            result.push(OsString::from_vec(entry.to_vec()));
        }
        result.sort();
        Ok(result)
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
        fs,
        os::unix::fs::symlink,
        sync::atomic::{AtomicU64, Ordering},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::current_dir().unwrap().join(format!(
                ".ami-directory-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn enumeration_repeats_and_bounds_before_retaining_extra_names() {
        let fixture = Fixture::new();
        fs::write(fixture.0.join("file"), b"content").unwrap();
        let directory = Directory::open(&fixture.0).unwrap();
        assert_eq!(directory.names(1).unwrap(), vec![OsString::from("file")]);
        assert_eq!(directory.names(1).unwrap(), vec![OsString::from("file")]);
        assert!(directory.names(0).is_err());
    }

    #[test]
    fn refuses_linked_ancestors_and_leaf_and_reads_exact_link_bytes() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.0.join("real")).unwrap();
        fs::write(fixture.0.join("real/file"), b"content").unwrap();
        symlink("real", fixture.0.join("alias")).unwrap();
        let directory = Directory::open(&fixture.0).unwrap();
        assert!(Directory::open(&fixture.0.join("alias")).is_err());
        assert!(directory.child(OsStr::new("alias")).is_err());
        assert!(directory.regular(OsStr::new("alias")).is_err());
        assert_eq!(
            directory.link_target(OsStr::new("alias"), 4).unwrap(),
            OsString::from("real")
        );
        assert!(directory.link_target(OsStr::new("alias"), 3).is_err());
        assert!(directory.child(OsStr::new("..")).is_err());
        assert!(directory.regular(OsStr::new("real/file")).is_err());
    }

    #[test]
    fn nofollow_classification_and_open_identity_check_cover_entry_kinds() {
        let fixture = Fixture::new();
        fs::create_dir(fixture.0.join("directory")).unwrap();
        fs::write(fixture.0.join("file"), b"original").unwrap();
        symlink("file", fixture.0.join("link")).unwrap();
        let directory = Directory::open(&fixture.0).unwrap();

        let directory_identity = directory.classify_entry(OsStr::new("directory")).unwrap();
        let file_identity = directory.classify_entry(OsStr::new("file")).unwrap();
        let link_identity = directory.classify_entry(OsStr::new("link")).unwrap();
        assert_eq!(directory_identity.entry_type(), EntryType::Directory);
        assert_eq!(file_identity.entry_type(), EntryType::RegularFile);
        assert_eq!(link_identity.entry_type(), EntryType::Symlink);
        assert!(file_identity.matches_metadata(&fs::metadata(fixture.0.join("file")).unwrap()));
        assert!(
            directory
                .open_regular_matching(OsStr::new("directory"), file_identity)
                .is_err()
        );

        // Keep the classified inode alive under another name so the replacement
        // cannot reuse its inode number before the descriptor check.
        fs::rename(fixture.0.join("file"), fixture.0.join("moved-file")).unwrap();
        fs::write(fixture.0.join("file"), b"replacement").unwrap();
        assert!(
            directory
                .open_regular_matching(OsStr::new("file"), file_identity)
                .is_err()
        );
        assert!(
            directory
                .open_child_matching(OsStr::new("link"), directory_identity)
                .is_err()
        );
    }

    #[test]
    fn nofollow_classification_rejects_device_nodes_without_opening_them() {
        let dev = Directory::open(Path::new("/dev")).unwrap();
        let null_identity = dev.classify_entry(OsStr::new("null")).unwrap();
        assert_eq!(null_identity.entry_type(), EntryType::Other);
        assert!(
            dev.open_regular_matching(OsStr::new("null"), null_identity)
                .is_err()
        );
    }

    #[test]
    fn retained_handle_is_not_redirected_by_path_replacement() {
        let fixture = Fixture::new();
        let original = fixture.0.join("original");
        fs::create_dir(&original).unwrap();
        fs::write(original.join("old"), b"original").unwrap();
        let directory = Directory::open(&original).unwrap();
        fs::rename(&original, fixture.0.join("moved")).unwrap();
        fs::create_dir(&original).unwrap();
        fs::write(original.join("decoy"), b"replacement").unwrap();
        assert_eq!(directory.names(1).unwrap(), vec![OsString::from("old")]);
        assert!(directory.regular(OsStr::new("decoy")).is_err());
    }
}
