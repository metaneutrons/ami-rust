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
        unix::ffi::{OsStrExt, OsStringExt},
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
        let file = self.open_entry(
            entry,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )?;
        if !file
            .metadata()
            .map_err(|e| Refusal::new(format!("could not inspect entry: {e}")))?
            .is_file()
        {
            return Err(Refusal::new("inventory entry is not a regular file"));
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
