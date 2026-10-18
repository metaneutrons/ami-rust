//! Host file access that rejects symlinks in every path component.
//!
//! Relative paths are resolved from an already-open handle to the current
//! working directory. Descriptor-relative traversal prevents later pathname
//! substitution from redirecting an opened component. It does not snapshot a
//! regular file's bytes: another process with write access can still mutate the
//! same file while it is being read.

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("host file access is supported on macOS and Linux only");

use crate::{Refusal, Result};
use std::{
    ffi::CString,
    fs::File,
    io::{self, Read},
    os::{fd::AsRawFd, fd::FromRawFd, unix::ffi::OsStrExt},
    path::{Component, Path},
};

const DIRECTORY_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
const REGULAR_FILE_FLAGS: libc::c_int =
    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;

fn io_refusal(context: &str, error: io::Error) -> Refusal {
    Refusal::new(format!("{context}: {error}"))
}

// Narrow allowance: this POSIX `open` is required to create the anchored path
// descriptor, and its descriptor ownership is checked and locally documented.
#[allow(unsafe_code)]
fn open_directory_anchor(path: &str) -> Result<File> {
    let path = CString::new(path).expect("static directory anchor contains no NUL");
    // SAFETY: `path` is a valid NUL-terminated string and the returned file
    // descriptor is checked before ownership is transferred to `File`.
    let fd = unsafe { libc::open(path.as_ptr(), DIRECTORY_FLAGS) };
    if fd < 0 {
        return Err(io_refusal(
            "could not open the path traversal anchor",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: `fd` is a fresh descriptor returned by `open` and is now owned
    // exclusively by this `File`.
    Ok(unsafe { File::from_raw_fd(fd) })
}

// Narrow allowance: this POSIX `openat` walks one descriptor-relative component
// at a time with `O_NOFOLLOW`; its descriptor ownership is locally documented.
#[allow(unsafe_code)]
fn openat_component(parent: &File, name: &CString, flags: libc::c_int) -> Result<File> {
    // SAFETY: `parent` owns a live directory descriptor, `name` is
    // NUL-terminated, and `openat` returns a fresh descriptor on success.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(io_refusal(
            "could not open a path component without following links",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: `fd` is a fresh descriptor returned by `openat` and is now owned
    // exclusively by this `File`.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Open a regular file while refusing symlinks in the final path and ancestors.
///
/// Absolute paths start from an open handle to `/`. Relative paths start from
/// an open handle to the current working directory. Parent traversal is
/// rejected. The final open is nonblocking so FIFOs cannot stall the caller;
/// `fstat` via `File::metadata` then accepts regular files only.
pub fn open_regular_nofollow(path: &Path) -> Result<File> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                let name = CString::new(name.as_bytes())
                    .map_err(|_| Refusal::new("path component contains a NUL byte"))?;
                components.push(name);
            }
            Component::ParentDir => {
                return Err(Refusal::new(
                    "parent traversal is not allowed in a file path",
                ));
            }
            Component::Prefix(_) => {
                return Err(Refusal::new("platform path prefixes are not supported"));
            }
        }
    }

    let Some((final_name, ancestors)) = components.split_last() else {
        return Err(Refusal::new("file path must name a regular file"));
    };

    let mut current = open_directory_anchor(if path.is_absolute() { "/" } else { "." })?;
    for name in ancestors {
        current = openat_component(&current, name, DIRECTORY_FLAGS)?;
    }

    let file = openat_component(&current, final_name, REGULAR_FILE_FLAGS)?;
    let metadata = file
        .metadata()
        .map_err(|error| io_refusal("could not inspect the opened file", error))?;
    if !metadata.file_type().is_file() {
        return Err(Refusal::new("input is not a regular file"));
    }
    Ok(file)
}

/// Read a regular file, accepting exactly `limit` bytes and refusing byte `limit + 1`.
pub fn read_regular_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let limit_u64 = u64::try_from(limit)
        .map_err(|_| Refusal::new("file size limit cannot be represented as a file length"))?;

    let mut file = open_regular_nofollow(path)?;
    let initial_length = file
        .metadata()
        .map_err(|error| io_refusal("could not inspect the opened file", error))?
        .len();
    if initial_length > limit_u64 {
        return Err(Refusal::new("regular file exceeds its byte limit"));
    }

    let initial_capacity = usize::try_from(initial_length)
        .map_err(|_| Refusal::new("file length cannot be represented in memory"))?;
    read_bounded(&mut file, limit, initial_capacity)
}

fn read_bounded(reader: &mut impl Read, limit: usize, initial_capacity: usize) -> Result<Vec<u8>> {
    let over_limit = limit
        .checked_add(1)
        .ok_or_else(|| Refusal::new("file size limit cannot be incremented safely"))?;
    if initial_capacity > limit {
        return Err(Refusal::new("initial file length exceeds its byte limit"));
    }

    let mut contents = Vec::new();
    contents
        .try_reserve_exact(initial_capacity)
        .map_err(|error| {
            Refusal::new(format!("could not allocate bounded file buffer: {error}"))
        })?;

    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let remaining = over_limit - contents.len();
        let read_limit = buffer.len().min(remaining);
        match reader.read(&mut buffer[..read_limit]) {
            Ok(0) => return Ok(contents),
            Ok(read) => {
                contents.try_reserve(read).map_err(|error| {
                    Refusal::new(format!("could not grow bounded file buffer: {error}"))
                })?;
                contents.extend_from_slice(&buffer[..read]);
                if contents.len() > limit {
                    return Err(Refusal::new("regular file exceeds its byte limit"));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io_refusal("could not read the opened file", error)),
        }
    }
}

/// Validate a portable relative path used in a component inventory.
pub fn validate_relative_inventory_path(path: &str) -> Result<()> {
    let bytes = path.as_bytes();
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || bytes.iter().any(|byte| *byte <= 0x1f || *byte == 0x7f)
        || path
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(Refusal::new(
            "component path is not a portable relative path",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        open_regular_nofollow, read_bounded, read_regular_bounded, validate_relative_inventory_path,
    };
    use std::{
        ffi::CString,
        fs,
        io::Cursor,
        os::unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::symlink,
        },
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, Instant},
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let cwd = std::env::current_dir().expect("current directory");
            for _ in 0..100 {
                let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
                let path = cwd.join(format!(
                    ".ami-rust-files-test-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("could not create test directory: {error}"),
                }
            }
            panic!("could not allocate a unique test directory");
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove test directory");
        }
    }

    #[test]
    fn reads_binary_regular_file_at_exact_limit_and_from_relative_path() {
        let temporary = TempDir::new();
        let file = temporary.path().join("input.bin");
        let contents: &[u8] = &[0_u8, 0xff, b'a', b'\n'];
        fs::write(&file, contents).expect("write fixture");
        let relative = file
            .strip_prefix(std::env::current_dir().expect("current directory"))
            .expect("fixture is below current directory");

        assert_eq!(
            read_regular_bounded(relative, contents.len())
                .unwrap()
                .as_slice(),
            contents
        );
    }

    #[test]
    fn rejects_a_file_one_byte_over_the_limit() {
        let temporary = TempDir::new();
        let file = temporary.path().join("input");
        fs::write(&file, b"four").expect("write fixture");

        assert!(read_regular_bounded(&file, 3).is_err());
    }

    #[test]
    fn bounded_reader_checks_streamed_bytes_after_a_zero_length_observation() {
        let exact: &[u8] = b"streamed";
        assert_eq!(
            read_bounded(&mut Cursor::new(exact), exact.len(), 0)
                .unwrap()
                .as_slice(),
            exact
        );
        assert!(read_bounded(&mut Cursor::new(b"streamed!"), exact.len(), 0).is_err());
    }

    #[test]
    fn reads_a_non_utf8_filename_without_lossy_conversion() {
        let temporary = TempDir::new();
        let name = std::ffi::OsString::from_vec(vec![b'i', b'n', b'p', b'u', b't', 0xff]);
        let file = temporary.path().join(name);
        fs::write(&file, b"binary-name").expect("write non-UTF-8 fixture");

        assert_eq!(
            read_regular_bounded(&file, 11).unwrap().as_slice(),
            &b"binary-name"[..]
        );
    }

    #[test]
    fn opener_rejects_parent_traversal_and_nul_components() {
        assert!(open_regular_nofollow(Path::new("../outside")).is_err());
        assert!(open_regular_nofollow(Path::new("nested/../outside")).is_err());
        assert!(open_regular_nofollow(Path::new("bad\0name")).is_err());
    }

    #[test]
    fn rejects_final_and_ancestor_symlinks() {
        let temporary = TempDir::new();
        let target = temporary.path().join("target");
        fs::create_dir(&target).expect("create target directory");
        fs::write(target.join("input"), b"safe").expect("write target file");
        let final_link = temporary.path().join("final-link");
        symlink(target.join("input"), &final_link).expect("create final symlink");
        let ancestor_link = temporary.path().join("ancestor-link");
        symlink(&target, &ancestor_link).expect("create ancestor symlink");

        assert!(open_regular_nofollow(&final_link).is_err());
        assert!(open_regular_nofollow(&ancestor_link.join("input")).is_err());
    }

    #[test]
    // Narrow allowance: `mkfifo` creates the test-only nonblocking-I/O fixture.
    #[allow(unsafe_code)]
    fn refuses_fifo_without_blocking() {
        let temporary = TempDir::new();
        let fifo = temporary.path().join("pipe");
        let encoded = CString::new(fifo.as_os_str().as_bytes()).expect("FIFO path has no NUL");
        // SAFETY: `encoded` is a valid NUL-terminated path and the mode is valid.
        let result = unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) };
        assert_eq!(
            result,
            0,
            "create FIFO: {}",
            std::io::Error::last_os_error()
        );

        let started = Instant::now();
        assert!(open_regular_nofollow(&fifo).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn rejects_nonportable_inventory_paths() {
        for invalid in [
            "",
            "/absolute/path",
            ".",
            "..",
            "a/./b",
            "a/../b",
            "a//b",
            "a/",
            "a\\b",
            "a:b",
            "a\0b",
            "a\nb",
            "a\u{7f}b",
        ] {
            assert!(
                validate_relative_inventory_path(invalid).is_err(),
                "unexpectedly accepted {invalid:?}"
            );
        }
        assert!(validate_relative_inventory_path("cargo/bin/cargo").is_ok());
        assert!(validate_relative_inventory_path("licenses/ü.txt").is_ok());
    }

    #[test]
    fn temporary_inputs_are_cleaned_up() {
        let path;
        {
            let temporary = TempDir::new();
            path = temporary.path().to_path_buf();
            fs::write(path.join("input"), b"temporary").expect("write fixture");
            assert_eq!(
                read_regular_bounded(&path.join("input"), 9).unwrap(),
                b"temporary"
            );
        }
        assert!(!path.exists());
    }
}
