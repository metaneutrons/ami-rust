//! Descriptor-relative filesystem mutations for transaction-owned trees.
//!
//! These operations anchor each lookup to an already-open parent directory.
//! They do not provide a snapshot against concurrent mutation by another
//! process with access to the same directory.

use crate::{Refusal, Result, directory::Directory};
use std::{
    ffi::{CString, OsStr, OsString},
    fs::File,
    io,
    mem::MaybeUninit,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::{OsStrExt, OsStringExt},
    },
};

const DIRECTORY_FLAGS: libc::c_int =
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

fn mode(value: u32) -> Result<libc::mode_t> {
    if value & !0o777 != 0 {
        return Err(Refusal::new("file mode contains unsupported bits"));
    }
    Ok(value as libc::mode_t)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EntryKind {
    Directory,
    RegularFile,
    Symlink,
    Other,
}

impl Directory {
    /// Create a fresh directory entry without opening or changing it. This
    /// narrow operation lets a transaction mark ownership immediately after
    /// `mkdirat`, before doing fallible descriptor work.
    pub(crate) fn create_directory_entry(&self, entry: &OsStr, permissions: u32) -> Result<()> {
        let permissions = mode(permissions)?;
        self.mkdirat_new(entry, permissions)
    }

    #[allow(unsafe_code)]
    fn mkdirat_new(&self, entry: &OsStr, permissions: libc::mode_t) -> Result<()> {
        let entry_name = name(entry)?;
        // SAFETY: the parent descriptor is live and the entry is one NUL-terminated name.
        let result = unsafe { libc::mkdirat(self.raw_fd(), entry_name.as_ptr(), permissions) };
        if result != 0 {
            return Err(error("could not create fresh directory"));
        }
        Ok(())
    }

    /// Create and open a fresh child directory, then set its exact permission
    /// bits. If opening or chmod fails after `mkdirat`, the new name remains
    /// caller-owned and can be cleaned through this parent handle.
    pub(crate) fn mkdir_new(&self, entry: &OsStr, permissions: u32) -> Result<Self> {
        self.mkdir_new_tracked(entry, permissions, || {})
    }

    /// As `mkdir_new`, calling `on_created` immediately after successful
    /// `mkdirat` and before opening the child or setting its exact mode.
    pub(crate) fn mkdir_new_tracked(
        &self,
        entry: &OsStr,
        permissions: u32,
        on_created: impl FnOnce(),
    ) -> Result<Self> {
        let permissions = mode(permissions)?;
        self.create_directory_entry(entry, permissions as u32)?;
        on_created();
        // A restrictive umask can leave the new directory mode 000, which
        // cannot be opened with O_RDONLY. Temporarily grant only owner access
        // through the fresh basename, without following a substituted link;
        // the returned descriptor is then set to the requested exact mode.
        self.set_entry_mode_exact_nofollow(entry, 0o700)?;
        let child = self.child(entry)?;
        child.set_mode_exact(permissions)?;
        Ok(child)
    }

    /// Set a fresh entry's mode without following a symlink.
    ///
    /// This is intended for an exclusively created basename below a retained,
    /// transaction-owned parent. It does not defend against a concurrent
    /// same-UID writer replacing that basename with a different non-symlink.
    #[allow(unsafe_code)]
    pub(crate) fn set_entry_mode_exact_nofollow(
        &self,
        entry: &OsStr,
        permissions: u32,
    ) -> Result<()> {
        let permissions = mode(permissions)?;
        let entry_name = name(entry)?;
        // SAFETY: the parent descriptor is live and the basename is valid.
        // AT_SYMLINK_NOFOLLOW prevents a substituted symlink target from being
        // changed; the subsequent directory open also refuses a symlink.
        let result = unsafe {
            libc::fchmodat(
                self.raw_fd(),
                entry_name.as_ptr(),
                permissions,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            return Err(error("could not set entry mode without following links"));
        }
        Ok(())
    }

    /// Create a fresh regular file without following a link and set exact
    /// permission bits. If chmod fails, the created entry remains caller-owned.
    pub(crate) fn create_new_file(&self, entry: &OsStr, permissions: u32) -> Result<File> {
        self.create_new_file_tracked(entry, permissions, || {})
    }

    /// As `create_new_file`, calling `on_created` after the fresh descriptor is
    /// owned by a `File` and before setting its exact permission bits.
    #[allow(unsafe_code)]
    pub(crate) fn create_new_file_tracked(
        &self,
        entry: &OsStr,
        permissions: u32,
        on_created: impl FnOnce(),
    ) -> Result<File> {
        let permissions = mode(permissions)?;
        let entry_name = name(entry)?;
        let flags =
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // C variadic arguments promote macOS's 16-bit mode_t to unsigned int.
        #[cfg(target_os = "macos")]
        let mode_argument = permissions as libc::c_uint;
        #[cfg(target_os = "linux")]
        let mode_argument = permissions;
        // SAFETY: the parent descriptor is live and the entry is one NUL-terminated name.
        let fd = unsafe { libc::openat(self.raw_fd(), entry_name.as_ptr(), flags, mode_argument) };
        if fd < 0 {
            return Err(error("could not create fresh file"));
        }
        // SAFETY: openat returned a fresh descriptor transferred to this File.
        let file = unsafe { File::from_raw_fd(fd) };
        on_created();
        // SAFETY: file owns a live descriptor and permissions contains only mode bits.
        let result = unsafe { libc::fchmod(file.as_raw_fd(), permissions) };
        if result != 0 {
            return Err(error("could not set exact file mode"));
        }
        Ok(file)
    }

    /// Atomically rename a regular file or directory into a sibling name
    /// without replacing any existing destination. Unsupported platforms or
    /// kernel/filesystem operations fail closed.
    pub(crate) fn rename_no_replace(
        &self,
        source: &OsStr,
        destination_parent: &Self,
        destination: &OsStr,
    ) -> Result<()> {
        require_same_directory(self, destination_parent)?;
        self.rename_exclusive(source, destination_parent, destination)
    }

    /// Move a staged directory between retained parents on one filesystem.
    /// Existing destinations are never replaced; there is no copy fallback.
    /// Callers own both private parents and recheck the component inventory
    /// before exposing its published location to a consumer.
    pub(crate) fn move_directory_no_replace(
        &self,
        source: &OsStr,
        destination_parent: &Self,
        destination: &OsStr,
    ) -> Result<()> {
        use std::os::unix::fs::MetadataExt;

        if self.metadata()?.dev() != destination_parent.metadata()?.dev() {
            return Err(Refusal::new(
                "exclusive directory move requires one shared filesystem",
            ));
        }
        if self.entry_kind(source)? != EntryKind::Directory {
            return Err(Refusal::new(
                "exclusive directory move source must be a directory",
            ));
        }
        self.rename_exclusive(source, destination_parent, destination)
    }

    #[allow(unsafe_code)]
    fn rename_exclusive(
        &self,
        source: &OsStr,
        destination_parent: &Self,
        destination: &OsStr,
    ) -> Result<()> {
        let source_name = name(source)?;
        let destination_name = name(destination)?;
        match self.entry_kind(source)? {
            EntryKind::Directory | EntryKind::RegularFile => {}
            EntryKind::Symlink | EntryKind::Other => {
                return Err(Refusal::new(
                    "exclusive rename source must be a regular file or directory",
                ));
            }
        }

        #[cfg(target_os = "linux")]
        // SAFETY: both live descriptors and NUL-terminated basenames remain valid.
        let result = unsafe {
            libc::renameat2(
                self.raw_fd(),
                source_name.as_ptr(),
                destination_parent.raw_fd(),
                destination_name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };

        #[cfg(target_os = "macos")]
        // SAFETY: both live descriptors and NUL-terminated basenames remain valid.
        let result = unsafe {
            libc::renameatx_np(
                self.raw_fd(),
                source_name.as_ptr(),
                destination_parent.raw_fd(),
                destination_name.as_ptr(),
                libc::RENAME_EXCL,
            )
        };

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        let result: libc::c_int = {
            let _ = (source_name, destination_name);
            return Err(Refusal::new(
                "exclusive atomic rename is supported only on macOS and Linux",
            ));
        };

        if result != 0 {
            return Err(error("exclusive atomic rename failed"));
        }
        Ok(())
    }

    /// Unlink a regular file or symlink entry without following it.
    #[allow(unsafe_code)]
    pub(crate) fn unlink_entry(&self, entry: &OsStr) -> Result<()> {
        let entry_name = name(entry)?;
        match self.entry_kind(entry)? {
            EntryKind::RegularFile | EntryKind::Symlink => {}
            EntryKind::Directory => {
                return Err(Refusal::new("refusing to unlink a directory as a file"));
            }
            EntryKind::Other => return Err(Refusal::new("refusing to unlink a special file")),
        }
        // SAFETY: the parent descriptor is live; unlinkat removes the named
        // entry itself and does not follow a symlink in that entry.
        let result = unsafe { libc::unlinkat(self.raw_fd(), entry_name.as_ptr(), 0) };
        if result != 0 {
            return Err(error("could not unlink directory entry"));
        }
        Ok(())
    }

    /// Remove an empty child directory without following a link.
    #[allow(unsafe_code)]
    pub(crate) fn remove_empty_directory(&self, entry: &OsStr) -> Result<()> {
        let entry_name = name(entry)?;
        if self.entry_kind(entry)? != EntryKind::Directory {
            return Err(Refusal::new("expected a real directory entry"));
        }
        // SAFETY: the parent descriptor is live; AT_REMOVEDIR removes only an
        // empty directory and cannot traverse a symlink.
        let result =
            unsafe { libc::unlinkat(self.raw_fd(), entry_name.as_ptr(), libc::AT_REMOVEDIR) };
        if result != 0 {
            return Err(error("could not remove empty directory"));
        }
        Ok(())
    }

    /// Best-effort directory fsync, matching the installer’s existing
    /// durability policy. Returns false when the host filesystem refuses it.
    #[allow(unsafe_code)]
    pub(crate) fn sync_best_effort(&self) -> bool {
        // SAFETY: self owns a live directory descriptor.
        unsafe { libc::fsync(self.raw_fd()) == 0 }
    }

    /// Remove a tree below this descriptor without following symlinks.
    /// `maximum_entries` includes the root entry. An error may leave a partial
    /// tree; the caller retains ownership of that tree and its recovery name.
    pub(crate) fn remove_tree(&self, entry: &OsStr, maximum_entries: usize) -> Result<()> {
        if maximum_entries == 0 {
            return Err(Refusal::new("recursive removal exceeds entry bound"));
        }
        // Charge the caller-supplied root before retaining it in a frame.
        let mut remaining = maximum_entries - 1;
        let root_name = owned_name(entry)?;
        match self.entry_kind(entry)? {
            EntryKind::RegularFile | EntryKind::Symlink => self.unlink_entry(entry),
            EntryKind::Directory => {
                let root = self.child(entry)?;
                let entries = read_names_bounded(&root, &mut remaining)?;
                let mut stack = Vec::new();
                stack
                    .try_reserve_exact(1)
                    .map_err(|_| Refusal::new("could not allocate recursive-removal stack"))?;
                stack.push(RemovalFrame {
                    directory: root,
                    name_in_parent: root_name,
                    entries,
                    next_entry: 0,
                });

                loop {
                    let action = {
                        let frame = stack.last_mut().expect("removal stack is nonempty");
                        if frame.next_entry == frame.entries.len() {
                            RemovalAction::Complete
                        } else {
                            let name = std::mem::take(&mut frame.entries[frame.next_entry]);
                            frame.next_entry += 1;
                            match frame.directory.entry_kind(&name)? {
                                EntryKind::RegularFile | EntryKind::Symlink => {
                                    frame.directory.unlink_entry(&name)?;
                                    RemovalAction::Continue
                                }
                                EntryKind::Directory => {
                                    let child = frame.directory.child(&name)?;
                                    let entries = read_names_bounded(&child, &mut remaining)?;
                                    RemovalAction::Descend(RemovalFrame {
                                        directory: child,
                                        name_in_parent: name,
                                        entries,
                                        next_entry: 0,
                                    })
                                }
                                EntryKind::Other => {
                                    return Err(Refusal::new(
                                        "recursive removal refuses a special filesystem entry",
                                    ));
                                }
                            }
                        }
                    };

                    match action {
                        RemovalAction::Continue => {}
                        RemovalAction::Descend(frame) => {
                            stack.try_reserve(1).map_err(|_| {
                                Refusal::new("could not grow recursive-removal stack")
                            })?;
                            stack.push(frame);
                        }
                        RemovalAction::Complete => {
                            let completed = stack.pop().expect("removal stack is nonempty");
                            if let Some(parent) = stack.last() {
                                parent
                                    .directory
                                    .remove_empty_directory(&completed.name_in_parent)?;
                            } else {
                                self.remove_empty_directory(&completed.name_in_parent)?;
                                return Ok(());
                            }
                        }
                    }
                }
            }
            EntryKind::Other => Err(Refusal::new(
                "recursive removal refuses a special filesystem entry",
            )),
        }
    }

    #[allow(unsafe_code)]
    pub(crate) fn set_mode_exact(&self, permissions: libc::mode_t) -> Result<()> {
        // SAFETY: self owns a live directory descriptor and permissions is mode-only.
        let result = unsafe { libc::fchmod(self.raw_fd(), permissions) };
        if result != 0 {
            return Err(error("could not set exact directory mode"));
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    fn entry_kind(&self, entry: &OsStr) -> Result<EntryKind> {
        let entry_name = name(entry)?;
        let mut metadata = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: parent descriptor and basename are valid; fstatat initializes
        // the struct on success and AT_SYMLINK_NOFOLLOW observes links themselves.
        let result = unsafe {
            libc::fstatat(
                self.raw_fd(),
                entry_name.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result != 0 {
            return Err(error("could not inspect directory entry"));
        }
        // SAFETY: successful fstatat initialized the complete stat structure.
        let file_type = unsafe { metadata.assume_init() }.st_mode & libc::S_IFMT;
        match file_type {
            libc::S_IFDIR => Ok(EntryKind::Directory),
            libc::S_IFREG => Ok(EntryKind::RegularFile),
            libc::S_IFLNK => Ok(EntryKind::Symlink),
            _ => Ok(EntryKind::Other),
        }
    }
}

struct RemovalFrame {
    directory: Directory,
    name_in_parent: OsString,
    entries: Vec<OsString>,
    next_entry: usize,
}

enum RemovalAction {
    Continue,
    Descend(RemovalFrame),
    Complete,
}

fn owned_name(value: &OsStr) -> Result<OsString> {
    let bytes = value.as_bytes();
    let mut copy = Vec::new();
    copy.try_reserve_exact(bytes.len())
        .map_err(|_| Refusal::new("could not allocate directory entry name"))?;
    copy.extend_from_slice(bytes);
    Ok(OsString::from_vec(copy))
}

#[allow(unsafe_code)]
fn read_names_bounded(directory: &Directory, remaining: &mut usize) -> Result<Vec<OsString>> {
    // Opening '.' creates an independent stream offset for this frame.
    // SAFETY: the directory descriptor and static C string are valid.
    let fd = unsafe { libc::openat(directory.raw_fd(), c".".as_ptr(), DIRECTORY_FLAGS) };
    if fd < 0 {
        return Err(error("could not open directory enumeration"));
    }
    // SAFETY: fd is a live directory descriptor. A successful fdopendir owns it.
    let pointer = unsafe { libc::fdopendir(fd) };
    if pointer.is_null() {
        let refusal = error("could not begin directory enumeration");
        // SAFETY: fdopendir failed and did not take ownership of fd.
        unsafe {
            libc::close(fd);
        }
        return Err(refusal);
    }
    let stream = DirectoryStream(pointer);
    let mut names = Vec::new();
    loop {
        // SAFETY: errno is thread-local and this clears it before readdir.
        unsafe {
            *errno_pointer() = 0;
        }
        // SAFETY: stream owns a live DIR until its Drop implementation runs.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            // SAFETY: errno_pointer returns this thread's errno location.
            if unsafe { *errno_pointer() } != 0 {
                return Err(error("could not enumerate directory"));
            }
            break;
        }
        // SAFETY: readdir returns a NUL-terminated d_name valid until next call.
        let bytes = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if *remaining == 0 {
            return Err(Refusal::new("recursive removal exceeds entry bound"));
        }
        // Charge each entry before allocating or retaining its copied name.
        *remaining -= 1;
        names
            .try_reserve(1)
            .map_err(|_| Refusal::new("could not allocate directory entry list"))?;
        let mut copy = Vec::new();
        copy.try_reserve_exact(bytes.len())
            .map_err(|_| Refusal::new("could not allocate directory entry name"))?;
        copy.extend_from_slice(bytes);
        names.push(OsString::from_vec(copy));
    }
    names.sort();
    Ok(names)
}

struct DirectoryStream(*mut libc::DIR);

#[allow(unsafe_code)]
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: this guard exclusively owns a successful fdopendir result.
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

fn require_same_directory(left: &Directory, right: &Directory) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let left_metadata = left.metadata()?;
    let right_metadata = right.metadata()?;
    if left_metadata.dev() != right_metadata.dev() || left_metadata.ino() != right_metadata.ino() {
        return Err(Refusal::new(
            "exclusive atomic rename requires one shared parent directory",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Write,
        os::unix::fs::{MetadataExt, symlink},
        process::Command,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(std::path::PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::current_dir().unwrap().join(format!(
                ".ami-mutations-{}-{}",
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
    fn exclusive_creation_sets_exact_modes_and_rejects_existing_entries() {
        let fixture = Fixture::new();
        let root = Directory::open(&fixture.0).unwrap();
        let stage = root.mkdir_new(OsStr::new("stage"), 0o700).unwrap();
        assert_eq!(stage.metadata().unwrap().mode() & 0o777, 0o700);
        assert!(root.mkdir_new(OsStr::new("stage"), 0o755).is_err());
        assert!(root.mkdir_new(OsStr::new("../escape"), 0o700).is_err());

        let mut receipt = stage.create_new_file(OsStr::new("receipt"), 0o600).unwrap();
        receipt.write_all(b"owned").unwrap();
        assert_eq!(receipt.metadata().unwrap().mode() & 0o777, 0o600);
        assert!(stage.create_new_file(OsStr::new("receipt"), 0o644).is_err());
        assert!(stage.create_new_file(OsStr::new("."), 0o600).is_err());
    }

    #[test]
    #[allow(unsafe_code)]
    fn restrictive_umask_isolated_child_process() {
        const CHILD_ENV: &str = "AMI_MUTATIONS_RESTRICTIVE_UMASK_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            let fixture = Fixture::new();
            let root = Directory::open(&fixture.0).unwrap();
            // Keep the umask change out of the parent test process, where it
            // could race unrelated tests that create files or directories.
            // SAFETY: this is a dedicated subprocess used only by this test.
            unsafe {
                libc::umask(0o777);
            }
            let stage = root.mkdir_new(OsStr::new("stage"), 0o700).unwrap();
            assert_eq!(stage.metadata().unwrap().mode() & 0o777, 0o700);

            // Even a requested mode without owner access remains openable
            // through the temporary private 0700 mode, then is set exactly.
            let zero_mode = root.mkdir_new(OsStr::new("zero-mode"), 0).unwrap();
            assert_eq!(zero_mode.metadata().unwrap().mode() & 0o777, 0);
            zero_mode.set_mode_exact(0o700).unwrap();
            return;
        }

        let executable = std::env::current_exe().unwrap();
        let status = Command::new(executable)
            .arg("--exact")
            .arg("mutations::tests::restrictive_umask_isolated_child_process")
            .arg("--nocapture")
            .env(CHILD_ENV, "1")
            .status()
            .unwrap();
        assert!(status.success(), "restrictive-umask child failed: {status}");
    }

    #[test]
    fn tracked_creation_marks_owned_entries_before_followup_descriptor_work() {
        let fixture = Fixture::new();
        let root = Directory::open(&fixture.0).unwrap();
        let mut directory_created = false;
        let mut original_mode = None;
        let result = root.mkdir_new_tracked(OsStr::new("stage"), 0o700, || {
            directory_created = true;
            original_mode = Some(fs::metadata(fixture.0.join("stage")).unwrap().mode() & 0o777);
            fs::rename(fixture.0.join("stage"), fixture.0.join("moved-stage")).unwrap();
            symlink("moved-stage", fixture.0.join("stage")).unwrap();
        });
        assert!(directory_created);
        assert!(result.is_err());
        assert!(fixture.0.join("moved-stage").is_dir());
        assert!(fixture.0.join("stage").is_symlink());
        assert_eq!(
            fs::metadata(fixture.0.join("moved-stage")).unwrap().mode() & 0o777,
            original_mode.unwrap()
        );

        let mut file_created = false;
        let file = root
            .create_new_file_tracked(OsStr::new("tracked-file"), 0o600, || {
                file_created = true;
                assert!(fixture.0.join("tracked-file").is_file());
            })
            .unwrap();
        assert!(file_created);
        drop(file);

        let mut called_on_collision = false;
        assert!(
            root.create_new_file_tracked(OsStr::new("tracked-file"), 0o600, || {
                called_on_collision = true;
            })
            .is_err()
        );
        assert!(!called_on_collision);
    }

    #[test]
    fn no_replace_rename_publishes_once_and_preserves_collisions() {
        let fixture = Fixture::new();
        let root = Directory::open(&fixture.0).unwrap();
        fs::write(fixture.0.join("occupied-file"), b"keep-file").unwrap();
        fs::create_dir(fixture.0.join("occupied-dir")).unwrap();
        fs::write(fixture.0.join("outside"), b"keep-target").unwrap();
        symlink("outside", fixture.0.join("occupied-link")).unwrap();

        let mut source_file = root
            .create_new_file(OsStr::new("source-file"), 0o600)
            .unwrap();
        source_file.write_all(b"source").unwrap();
        drop(source_file);
        assert!(
            root.rename_no_replace(
                OsStr::new("source-file"),
                &root,
                OsStr::new("occupied-file")
            )
            .is_err()
        );
        assert_eq!(
            fs::read(fixture.0.join("occupied-file")).unwrap(),
            b"keep-file"
        );
        assert_eq!(fs::read(fixture.0.join("source-file")).unwrap(), b"source");

        let stage = root.mkdir_new(OsStr::new("stage"), 0o700).unwrap();
        let mut marker = stage.create_new_file(OsStr::new("marker"), 0o600).unwrap();
        marker.write_all(b"whole-tree").unwrap();
        drop(marker);
        assert!(
            root.rename_no_replace(OsStr::new("stage"), &root, OsStr::new("occupied-dir"))
                .is_err()
        );
        assert_eq!(
            fs::read(fixture.0.join("stage/marker")).unwrap(),
            b"whole-tree"
        );
        root.rename_no_replace(OsStr::new("stage"), &root, OsStr::new("published"))
            .unwrap();
        assert_eq!(
            fs::read(fixture.0.join("published/marker")).unwrap(),
            b"whole-tree"
        );

        let mut another = root.create_new_file(OsStr::new("another"), 0o600).unwrap();
        another.write_all(b"source-two").unwrap();
        drop(another);
        assert!(
            root.rename_no_replace(OsStr::new("another"), &root, OsStr::new("occupied-link"))
                .is_err()
        );
        assert_eq!(fs::read(fixture.0.join("outside")).unwrap(), b"keep-target");
        assert!(fixture.0.join("occupied-link").is_symlink());

        symlink("outside", fixture.0.join("source-link")).unwrap();
        assert!(
            root.rename_no_replace(OsStr::new("source-link"), &root, OsStr::new("link-moved"))
                .is_err()
        );
        assert!(fixture.0.join("source-link").is_symlink());

        let other_parent_path = fixture.0.join("other-parent");
        fs::create_dir(&other_parent_path).unwrap();
        let other_parent = Directory::open(&other_parent_path).unwrap();
        assert!(
            root.rename_no_replace(
                OsStr::new("another"),
                &other_parent,
                OsStr::new("cross-dir")
            )
            .is_err()
        );
    }

    #[test]
    fn component_directory_move_uses_distinct_retained_parents_without_replacement() {
        let fixture = Fixture::new();
        let root = Directory::open(&fixture.0).unwrap();
        let extraction = root
            .mkdir_new(OsStr::new("archive-extraction"), 0o700)
            .unwrap();
        let staging = root
            .mkdir_new(OsStr::new("component-staging"), 0o700)
            .unwrap();
        let component = extraction
            .mkdir_new(OsStr::new("archive-root"), 0o700)
            .unwrap();
        component
            .create_new_file(OsStr::new("manifest"), 0o600)
            .unwrap()
            .write_all(b"verified component bytes")
            .unwrap();
        // This is the cold-provisioning failure: sibling-only publication must
        // continue to refuse different parents for transaction/receipt callers.
        assert!(
            extraction
                .rename_no_replace(
                    OsStr::new("archive-root"),
                    &staging,
                    OsStr::new("toolchain")
                )
                .is_err()
        );

        staging
            .create_new_file(OsStr::new("occupied-file"), 0o600)
            .unwrap()
            .write_all(b"keep file")
            .unwrap();
        staging
            .mkdir_new(OsStr::new("occupied-dir"), 0o700)
            .unwrap();
        symlink(
            "occupied-file",
            fixture.0.join("component-staging/occupied-link"),
        )
        .unwrap();
        for destination in ["occupied-file", "occupied-dir", "occupied-link"] {
            assert!(
                extraction
                    .move_directory_no_replace(
                        OsStr::new("archive-root"),
                        &staging,
                        OsStr::new(destination)
                    )
                    .is_err()
            );
            assert_eq!(
                fs::read(fixture.0.join("archive-extraction/archive-root/manifest")).unwrap(),
                b"verified component bytes"
            );
        }
        assert_eq!(
            fs::read(fixture.0.join("component-staging/occupied-file")).unwrap(),
            b"keep file"
        );
        assert!(
            fixture
                .0
                .join("component-staging/occupied-link")
                .is_symlink()
        );

        // The live descriptors remain the authority after both names move.
        fs::rename(
            fixture.0.join("archive-extraction"),
            fixture.0.join("extraction-renamed"),
        )
        .unwrap();
        fs::rename(
            fixture.0.join("component-staging"),
            fixture.0.join("staging-renamed"),
        )
        .unwrap();
        extraction
            .move_directory_no_replace(
                OsStr::new("archive-root"),
                &staging,
                OsStr::new("toolchain"),
            )
            .unwrap();
        assert!(!fixture.0.join("extraction-renamed/archive-root").exists());
        assert_eq!(
            fs::read(fixture.0.join("staging-renamed/toolchain/manifest")).unwrap(),
            b"verified component bytes"
        );
        assert_eq!(
            component
                .regular(OsStr::new("manifest"))
                .unwrap()
                .metadata()
                .unwrap()
                .len(),
            24
        );

        extraction
            .create_new_file(OsStr::new("not-a-directory"), 0o600)
            .unwrap();
        symlink(
            "../staging-renamed/toolchain",
            fixture.0.join("extraction-renamed/linked-source"),
        )
        .unwrap();
        for source in [
            "not-a-directory",
            "linked-source",
            "../staging-renamed/toolchain",
        ] {
            assert!(
                extraction
                    .move_directory_no_replace(
                        OsStr::new(source),
                        &staging,
                        OsStr::new("must-not-exist")
                    )
                    .is_err()
            );
            assert!(!fixture.0.join("staging-renamed/must-not-exist").exists());
        }
    }

    #[test]
    fn bounded_tree_removal_unlinks_links_without_following_them() {
        let fixture = Fixture::new();
        let root = Directory::open(&fixture.0).unwrap();
        let outside = fixture.0.join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("keep"), b"outside").unwrap();
        fs::write(fixture.0.join("sibling"), b"sibling").unwrap();
        fs::create_dir_all(fixture.0.join("owned/nested")).unwrap();
        fs::write(fixture.0.join("owned/nested/file"), b"inside").unwrap();
        symlink(&outside, fixture.0.join("owned/outside-link")).unwrap();

        root.remove_tree(OsStr::new("owned"), 8).unwrap();
        assert!(!fixture.0.join("owned").exists());
        assert_eq!(fs::read(outside.join("keep")).unwrap(), b"outside");
        assert_eq!(fs::read(fixture.0.join("sibling")).unwrap(), b"sibling");

        fs::create_dir(fixture.0.join("bounded")).unwrap();
        fs::write(fixture.0.join("bounded/file"), b"retained-on-refusal").unwrap();
        assert!(root.remove_tree(OsStr::new("bounded"), 1).is_err());
        assert_eq!(
            fs::read(fixture.0.join("bounded/file")).unwrap(),
            b"retained-on-refusal"
        );
    }

    #[test]
    fn deep_tree_removal_uses_heap_frames_not_call_stack_recursion() {
        let fixture = Fixture::new();
        let root = Directory::open(&fixture.0).unwrap();
        let mut current = root.mkdir_new(OsStr::new("deep"), 0o700).unwrap();
        const DEPTH: usize = 2048;
        for _ in 0..DEPTH {
            current = current.mkdir_new(OsStr::new("d"), 0o700).unwrap();
        }
        drop(current);
        drop(root);

        let root = Directory::open(&fixture.0).unwrap();
        let result = std::thread::Builder::new()
            .stack_size(64 * 1024)
            .spawn(move || root.remove_tree(OsStr::new("deep"), DEPTH + 1))
            .unwrap()
            .join()
            .unwrap();
        match result {
            Ok(()) => assert!(!fixture.0.join("deep").exists()),
            Err(error) => {
                assert!(
                    error.to_string().contains("open files"),
                    "unexpected deep-removal failure: {error}"
                );
                assert!(fixture.0.join("deep").exists());
            }
        }
    }

    #[test]
    fn retained_parent_descriptor_survives_path_replacement() {
        let fixture = Fixture::new();
        let parent_path = fixture.0.join("parent");
        let moved_path = fixture.0.join("moved-parent");
        fs::create_dir(&parent_path).unwrap();
        let parent = Directory::open(&parent_path).unwrap();
        fs::rename(&parent_path, &moved_path).unwrap();
        fs::create_dir(&parent_path).unwrap();

        let mut file = parent
            .create_new_file(OsStr::new("anchored"), 0o600)
            .unwrap();
        file.write_all(b"original-parent").unwrap();
        drop(file);
        assert_eq!(
            fs::read(moved_path.join("anchored")).unwrap(),
            b"original-parent"
        );
        assert!(!parent_path.join("anchored").exists());

        let mut staged = parent.create_new_file(OsStr::new("stage"), 0o600).unwrap();
        staged.write_all(b"rename-anchor").unwrap();
        drop(staged);
        parent
            .rename_no_replace(OsStr::new("stage"), &parent, OsStr::new("published"))
            .unwrap();
        assert_eq!(
            fs::read(moved_path.join("published")).unwrap(),
            b"rename-anchor"
        );
        assert!(!parent_path.join("published").exists());
    }
}
