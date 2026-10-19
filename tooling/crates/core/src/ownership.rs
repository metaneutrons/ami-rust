//! Read-only validation of fresh host paths and private package state.
//!
//! Validated targets retain an open descriptor for their existing parent
//! directory. The caller remains responsible for using an exclusive,
//! descriptor-relative create or rename when it later publishes data.

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("host path ownership checks are supported on macOS and Linux only");

use crate::{Refusal, Result, directory::Directory};
use std::{
    ffi::{CStr, CString, OsStr, OsString},
    fs::{self, File, Metadata},
    io,
    mem::MaybeUninit,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::MetadataExt,
    },
    path::{Component, Path, PathBuf},
};

/// A path that did not exist when validated, paired with its opened parent.
#[derive(Debug)]
pub struct FreshTarget {
    path: PathBuf,
    parent: Directory,
    name: OsString,
}

impl FreshTarget {
    /// Canonical absolute destination path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Open parent directory retained during validation.
    pub fn parent(&self) -> &Directory {
        &self.parent
    }

    /// Final path component, preserved as native filesystem bytes.
    pub fn name(&self) -> &OsStr {
        &self.name
    }
}

/// An existing installation prefix validated for read-only inspection or
/// uninstall. Both the parent and target directory handles are retained. This
/// validates path ownership only; it does not authenticate installed contents.
#[derive(Debug)]
pub struct ExistingTarget {
    path: PathBuf,
    parent: Directory,
    root: Directory,
    name: OsString,
}

impl ExistingTarget {
    /// Canonical absolute installation path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Retained parent directory handle.
    pub fn parent(&self) -> &Directory {
        &self.parent
    }

    /// Retained handle to the existing installation directory.
    pub fn root(&self) -> &Directory {
        &self.root
    }

    /// Final path component, preserved as native filesystem bytes.
    pub fn name(&self) -> &OsStr {
        &self.name
    }
}

/// Validate a fresh installation prefix using the historical installer rules.
/// The prefix must be normalized and absolute, outside `/`, the current user's
/// home and the current directory's ancestor chain, and its existing parent
/// must be a secure current-user-owned directory.
pub fn install_target(path: &Path) -> Result<FreshTarget> {
    let (path, parent, _) = validate_install_target_path(path)?;
    fresh_target(&path, parent, "installation prefix")
}

/// Validate an existing installation prefix for read-only inspection or
/// uninstall. The prefix uses the same path guards as install_target; its leaf
/// must be a real current-user-owned directory that is not group/world writable.
pub fn existing_install_target(path: &Path) -> Result<ExistingTarget> {
    let (path, parent, name) = validate_install_target_path(path)?;
    let root = parent.child(&name).map_err(|error| {
        Refusal::new(format!(
            "installation prefix must be a real directory without symlinks: {error}"
        ))
    })?;
    validate_directory_metadata(
        &root.metadata()?,
        current_uid(),
        true,
        "installation prefix",
    )?;
    Ok(ExistingTarget {
        path,
        parent,
        root,
        name,
    })
}

fn validate_install_target_path(path: &Path) -> Result<(PathBuf, Directory, OsString)> {
    validate_normalized_absolute(path, "installation prefix")?;
    if path == Path::new("/") || path == home_directory()?.as_path() {
        return Err(Refusal::new(
            "installation prefix may not be root or the home directory",
        ));
    }
    let cwd = std::env::current_dir()
        .map_err(|error| io_refusal("could not inspect the current directory", error))?;
    if path == cwd || cwd.starts_with(path) {
        return Err(Refusal::new(
            "installation prefix may not replace the current working directory or an ancestor",
        ));
    }
    let parent_path = path
        .parent()
        .ok_or_else(|| Refusal::new("invalid installation prefix"))?;
    let parent = secure_user_directory(parent_path, "installation parent")?;
    let name = target_name(path, "installation prefix")?;
    Ok((path.to_path_buf(), parent, name))
}

/// Validate a fresh external receipt-pin file. Its path is normalized like
/// Python `os.path.abspath`, and it must be disjoint from both the installation
/// prefix and the verified release bundle.
pub fn receipt_pin(path: &Path, prefix: &Path, bundle: &Path) -> Result<FreshTarget> {
    if path.as_os_str().is_empty() {
        return Err(Refusal::new("receipt pin path is required"));
    }
    let path = absolute_normalized(path)?;
    let prefix = install_target(prefix)?.path;
    let _bundle_directory = open_directory_chain(bundle, AncestorPolicy::Unrestricted)?;
    if path == Path::new("/") || path == home_directory()?.as_path() {
        return Err(Refusal::new(
            "receipt pin must be a fresh file outside the installation prefix",
        ));
    }
    if paths_overlap(&path, &prefix) || paths_overlap(&path, bundle) {
        return Err(Refusal::new(
            "receipt pin must be a fresh file outside the installation prefix and release bundle",
        ));
    }
    let parent_path = path
        .parent()
        .ok_or_else(|| Refusal::new("invalid receipt pin path"))?;
    let parent = secure_user_directory(parent_path, "receipt pin parent")?;
    fresh_target(&path, parent, "receipt pin path")
}

/// Validate a fresh output file using the historical CLI policy: relative
/// inputs are made absolute, the parent must be a secure user directory, and
/// any existing leaf (including a symlink) is refused.
pub fn fresh_output(path: &Path) -> Result<FreshTarget> {
    if path.as_os_str().is_empty() {
        return Err(Refusal::new("output JSON path is required"));
    }
    let path = absolute_normalized(path)?;
    let parent_path = path
        .parent()
        .ok_or_else(|| Refusal::new("invalid output JSON path"))?;
    let parent = secure_user_directory(parent_path, "output parent")?;
    fresh_target(&path, parent, "output JSON path")
}

/// Validate a fresh package state directory. Preparation must run as a
/// non-root user; its parent must already exist and contain no symlink
/// components. The parent permission policy follows `packaging/cli.py`.
pub fn fresh_private_state(path: &Path) -> Result<FreshTarget> {
    require_non_root(current_uid())?;
    validate_normalized_absolute(path, "state")?;
    let parent_path = path
        .parent()
        .ok_or_else(|| Refusal::new("state path must name a directory"))?;
    let parent = open_directory_chain(parent_path, AncestorPolicy::Unrestricted)?;
    fresh_target(path, parent, "state")
}

/// Open and validate an existing private package state directory. The state
/// must be a real current-user-owned directory with no group/world permissions.
pub fn existing_private_state(path: &Path) -> Result<Directory> {
    require_non_root(current_uid())?;
    validate_normalized_absolute(path, "state")?;
    let state = open_directory_chain(path, AncestorPolicy::Unrestricted)?;
    let metadata = state.metadata()?;
    if metadata.uid() != current_uid() || metadata.mode() & 0o077 != 0 {
        return Err(Refusal::new(
            "state must be a private directory owned by the current user",
        ));
    }
    Ok(state)
}

/// Refuse state/package overlap while preserving the retained-launcher
/// exception from `packaging/cli.py` for existing states only.
pub fn validate_state_package_separation(state: &Path, package: &Path, fresh: bool) -> Result<()> {
    validate_normalized_absolute(state, "state")?;
    validate_normalized_absolute(package, "installed package")?;
    let retained = state.join("retained/libexec/ami-rust");
    let package_inside_retained = package.starts_with(&retained);
    if state == package
        || state.starts_with(package)
        || (package.starts_with(state) && (fresh || !package_inside_retained))
    {
        return Err(Refusal::new("state and installed package must be disjoint"));
    }
    Ok(())
}

/// Refuse equal or ancestor/descendant paths. Inputs must already be absolute
/// and normalized; this helper does not touch either path.
pub fn require_disjoint(left: &Path, right: &Path, message: &str) -> Result<()> {
    validate_normalized_absolute(left, "path")?;
    validate_normalized_absolute(right, "protected path")?;
    if paths_overlap(left, right) {
        return Err(Refusal::new(message.to_owned()));
    }
    Ok(())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left == right || left.starts_with(right) || right.starts_with(left)
}

fn fresh_target(path: &Path, parent: Directory, label: &str) -> Result<FreshTarget> {
    let name = target_name(path, label)?;
    if entry_exists_at(&parent, &name)? {
        let reason = match label {
            "installation prefix" => "installation prefix must be fresh",
            "receipt pin path" => "receipt pin path must be fresh",
            "output JSON path" => "output JSON path must be fresh",
            _ => "state path must be fresh",
        };
        return Err(Refusal::new(reason));
    }
    Ok(FreshTarget {
        path: path.to_path_buf(),
        parent,
        name,
    })
}

fn target_name(path: &Path, label: &str) -> Result<OsString> {
    path.file_name()
        .filter(|name| !name.is_empty() && *name != OsStr::new(".") && *name != OsStr::new(".."))
        .map(OsStr::to_os_string)
        .ok_or_else(|| Refusal::new(format!("invalid {label}")))
}

fn secure_user_directory(path: &Path, label: &str) -> Result<Directory> {
    if !path.is_absolute() {
        return Err(Refusal::new(format!("{label} must be absolute")));
    }
    open_directory_chain(path, AncestorPolicy::SecureUserLeaf(label))
}

#[derive(Clone, Copy)]
enum AncestorPolicy<'a> {
    Unrestricted,
    SecureUserLeaf(&'a str),
    ProtectedInputAncestors(&'a str),
}

/// Open an external trust input with the historical protected-input ownership
/// rules. Every ancestor is retained/opened without symlinks. A root-owned
/// sticky ancestor is permitted; the regular file itself must be root/current
/// user owned and not group/world writable. Executables must preserve identity.
pub fn protected_regular_file(path: &Path, executable: bool) -> Result<File> {
    validate_normalized_absolute(path, "external trust input")?;
    let parent_path = path
        .parent()
        .ok_or_else(|| Refusal::new("missing trust-input parent"))?;
    let parent = open_directory_chain(
        parent_path,
        AncestorPolicy::ProtectedInputAncestors("external trust input"),
    )?;
    let entry = target_name(path, "external trust input")?;
    let file = parent.regular(&entry)?;
    let metadata = file
        .metadata()
        .map_err(|error| io_refusal("could not inspect trust input", error))?;
    if ![0, current_uid()].contains(&metadata.uid()) || metadata.mode() & 0o022 != 0 {
        return Err(Refusal::new(
            "unsafe ownership/write permissions for external trust input",
        ));
    }
    if executable {
        if metadata.mode() & 0o111 == 0 || metadata.mode() & 0o6000 != 0 {
            return Err(Refusal::new(
                "external verifier must be executable without set-ID bits",
            ));
        }
        can_execute_entry(&parent, &entry)?;
    }
    Ok(file)
}

/// Secure root/current-owner chain, also permitting root-owned sticky
/// directories. Used for a verifier HOME parent before exclusive creation.
pub(crate) fn protected_directory(path: &Path) -> Result<Directory> {
    open_directory_chain(
        path,
        AncestorPolicy::ProtectedInputAncestors("protected directory"),
    )
}

#[allow(
    unsafe_code,
    reason = "Descriptor-relative access check preserves actual caller ACL/permission semantics."
)]
fn can_execute_entry(parent: &Directory, entry: &OsStr) -> Result<()> {
    let name =
        CString::new(entry.as_bytes()).map_err(|_| Refusal::new("trust input contains NUL"))?;
    // SAFETY: parent owns an open directory fd; name is a live NUL-terminated
    // entry. No file is opened/executed or permission changed by faccessat.
    if unsafe { libc::faccessat(parent.raw_fd(), name.as_ptr(), libc::X_OK, 0) } != 0 {
        return Err(io_refusal(
            "external verifier is not executable",
            io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn open_directory_chain(path: &Path, policy: AncestorPolicy<'_>) -> Result<Directory> {
    validate_normalized_absolute(path, "directory")?;
    let canonical =
        fs::canonicalize(path).map_err(|error| io_refusal("could not resolve directory", error))?;
    if !same_os_path(&canonical, path) {
        return Err(Refusal::new("directory must have no symlink components"));
    }

    let uid = current_uid();
    let mut current = Directory::open(Path::new("/"))?;
    let components = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_os_string()),
            Component::RootDir => None,
            _ => None,
        })
        .peekable();
    let mut component_index = 0usize;
    let total_components = components.clone().count();
    let root_metadata = current.metadata()?;
    if let AncestorPolicy::SecureUserLeaf(label) | AncestorPolicy::ProtectedInputAncestors(label) =
        policy
    {
        validate_directory_metadata(
            &root_metadata,
            uid,
            total_components == 0 && matches!(policy, AncestorPolicy::SecureUserLeaf(_)),
            label,
        )?;
    }

    for component in components {
        let child = current.child(&component).map_err(|error| {
            Refusal::new(format!(
                "directory has a missing, unsafe, or non-directory ancestor: {error}"
            ))
        })?;
        component_index += 1;
        let metadata = child.metadata()?;
        if let AncestorPolicy::SecureUserLeaf(label)
        | AncestorPolicy::ProtectedInputAncestors(label) = policy
        {
            validate_directory_metadata(
                &metadata,
                uid,
                component_index == total_components
                    && matches!(policy, AncestorPolicy::SecureUserLeaf(_)),
                label,
            )?;
        }
        current = child;
    }
    Ok(current)
}

fn validate_directory_metadata(
    metadata: &Metadata,
    uid: u32,
    is_leaf: bool,
    label: &str,
) -> Result<()> {
    if !metadata.file_type().is_dir() {
        return Err(Refusal::new(format!(
            "{label} ancestor must be a real directory"
        )));
    }
    let owner = metadata.uid();
    if owner != 0 && owner != uid {
        return Err(Refusal::new(format!(
            "{label} ancestor has an unexpected owner"
        )));
    }
    let mode = metadata.mode();
    if is_leaf {
        if owner != uid {
            return Err(Refusal::new(format!(
                "{label} must be owned by the current user"
            )));
        }
        if mode & 0o022 != 0 {
            return Err(Refusal::new(format!(
                "{label} must not be group/world writable"
            )));
        }
        return Ok(());
    }
    let root_sticky = owner == 0 && mode & 0o1000 != 0;
    if mode & 0o022 != 0 && !root_sticky {
        return Err(Refusal::new(format!(
            "{label} ancestor is group/world writable"
        )));
    }
    Ok(())
}

fn validate_normalized_absolute(path: &Path, label: &str) -> Result<()> {
    if !path.is_absolute() || !same_os_path(path, &lexically_normalized(path)) {
        return Err(Refusal::new(format!(
            "{label} must be a normalized absolute path"
        )));
    }
    if path.as_os_str().as_bytes().contains(&0) {
        return Err(Refusal::new(format!("{label} contains a NUL byte")));
    }
    Ok(())
}

fn absolute_normalized(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| io_refusal("could not inspect the current directory", error))?
            .join(path)
    };
    if absolute.as_os_str().as_bytes().contains(&0) {
        return Err(Refusal::new("path contains a NUL byte"));
    }
    let normalized = lexically_normalized(&absolute);
    validate_normalized_absolute(&normalized, "path")?;
    Ok(normalized)
}

fn lexically_normalized(path: &Path) -> PathBuf {
    let mut result = PathBuf::from("/");
    let mut components: Vec<OsString> = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => components.push(name.to_os_string()),
            Component::ParentDir => {
                components.pop();
            }
            Component::Prefix(_) => {}
        }
    }
    for component in components {
        result.push(component);
    }
    result
}

fn same_os_path(left: &Path, right: &Path) -> bool {
    left.as_os_str().as_bytes() == right.as_os_str().as_bytes()
}

fn require_non_root(uid: u32) -> Result<()> {
    if uid == 0 {
        return Err(Refusal::new(
            "prepare and project commands run as a regular user, never as root",
        ));
    }
    Ok(())
}

#[allow(unsafe_code)]
fn current_uid() -> u32 {
    // SAFETY: `getuid` takes no pointers and only reads the process credentials.
    unsafe { libc::getuid() }
}

#[allow(unsafe_code)]
fn home_directory() -> Result<PathBuf> {
    let uid: libc::uid_t = current_uid();
    // SAFETY: `sysconf` takes no pointers. A nonpositive result means the
    // platform has no suggested buffer size, so the retry loop starts small.
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut size = usize::try_from(suggested)
        .ok()
        .filter(|size| *size > 0)
        .unwrap_or(1024);
    loop {
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(size).map_err(|error| {
            Refusal::new(format!("could not allocate account lookup buffer: {error}"))
        })?;
        buffer.resize(size, 0);
        let mut record = MaybeUninit::<libc::passwd>::zeroed();
        let mut found = std::ptr::null_mut();
        // SAFETY: all output pointers refer to initialized writable storage;
        // the buffer length is accurate, and the record is read only when the
        // call returns success with a non-null result pointer.
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                record.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut found,
            )
        };
        if status == libc::ERANGE {
            size = size
                .checked_mul(2)
                .ok_or_else(|| Refusal::new("account lookup buffer size overflow"))?;
            continue;
        }
        if status != 0 {
            return Err(io_refusal(
                "could not find the current user's home directory",
                io::Error::from_raw_os_error(status),
            ));
        }
        if found.is_null() {
            return Err(Refusal::new(
                "could not find the current user's home directory",
            ));
        }
        // SAFETY: `found` is non-null on successful `getpwuid_r`, and its
        // `pw_dir` pointer points into the live `buffer` allocation.
        let record = unsafe { record.assume_init() };
        if record.pw_dir.is_null() {
            return Err(Refusal::new(
                "could not find the current user's home directory",
            ));
        }
        // SAFETY: libc provided a NUL-terminated `pw_dir` on successful lookup.
        let bytes = unsafe { CStr::from_ptr(record.pw_dir) }.to_bytes();
        let home = PathBuf::from(OsString::from_vec(bytes.to_vec()));
        let resolved = fs::canonicalize(&home)
            .map_err(|error| io_refusal("could not resolve the current user's home", error))?;
        return Ok(resolved);
    }
}

#[allow(unsafe_code)]
fn entry_exists_at(parent: &Directory, name: &OsStr) -> Result<bool> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| Refusal::new("target name contains a NUL byte"))?;
    let mut status = MaybeUninit::<libc::stat>::zeroed();
    // SAFETY: the parent descriptor is live, `name` is NUL-terminated, and
    // `status` points to writable storage. AT_SYMLINK_NOFOLLOW inspects the
    // leaf itself, including symlinks, without traversing it.
    let result = unsafe {
        libc::fstatat(
            parent.raw_fd(),
            name.as_ptr(),
            status.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        // SAFETY: successful `fstatat` initialized the `stat` record.
        let _ = unsafe { status.assume_init() };
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        Ok(false)
    } else {
        Err(io_refusal("could not inspect fresh target path", error))
    }
}

fn io_refusal(context: &str, error: io::Error) -> Refusal {
    Refusal::new(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::{
        existing_install_target, existing_private_state, fresh_output, fresh_private_state,
        home_directory, install_target, protected_regular_file, receipt_pin, require_disjoint,
        require_non_root, validate_state_package_separation,
    };
    use std::{
        ffi::{OsStr, OsString},
        fs,
        os::unix::{
            ffi::OsStringExt,
            fs::{MetadataExt, PermissionsExt, symlink},
        },
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let root = fs::canonicalize(std::env::temp_dir()).expect("canonical temp directory");
            for _ in 0..100 {
                let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
                let path = root.join(format!(
                    ".ami-rust-ownership-test-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create temporary directory: {error}"),
                }
            }
            panic!("could not reserve unique temporary directory");
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn assert_refused<T>(result: crate::Result<T>) {
        assert!(result.is_err());
    }

    #[test]
    fn external_trust_inputs_require_secure_regular_paths_and_executable_access() {
        let temp = TempDir::new();
        let file = temp.0.join("trust");
        fs::write(&file, b"pinned data").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(protected_regular_file(&file, false).is_ok());
        assert_refused(protected_regular_file(&file, true));
        fs::set_permissions(&file, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(protected_regular_file(&file, true).is_ok());
        for mode in [0o622, 0o4700, 0o2700] {
            fs::set_permissions(&file, fs::Permissions::from_mode(mode)).unwrap();
            assert_refused(protected_regular_file(&file, true));
        }
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let linked = temp.0.join("linked");
        symlink(&file, &linked).unwrap();
        assert_refused(protected_regular_file(&linked, false));
        let parent_link = temp.0.join("parent-link");
        symlink(&temp.0, &parent_link).unwrap();
        assert_refused(protected_regular_file(&parent_link.join("trust"), false));
        fs::set_permissions(&temp.0, fs::Permissions::from_mode(0o777)).unwrap();
        assert_refused(protected_regular_file(&file, false));
        fs::set_permissions(&temp.0, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(protected_regular_file(&file, false).is_ok());
    }

    #[test]
    fn accepts_fresh_prefix_and_rejects_occupied_leaf_kinds() {
        let temp = TempDir::new();
        let _valid = install_target(&temp.0.join("new-prefix")).unwrap();

        let regular = temp.0.join("regular");
        fs::write(&regular, b"occupied").unwrap();
        assert_refused(install_target(&regular));

        let directory = temp.0.join("directory");
        fs::create_dir(&directory).unwrap();
        assert_refused(install_target(&directory));

        let link = temp.0.join("link");
        symlink(&regular, &link).unwrap();
        assert_refused(install_target(&link));
    }

    #[test]
    fn rejects_symlink_ancestors_and_insecure_parent_modes() {
        let temp = TempDir::new();
        let real = temp.0.join("real");
        fs::create_dir(&real).unwrap();
        let link = temp.0.join("link");
        symlink(&real, &link).unwrap();
        assert_refused(install_target(&link.join("prefix")));

        let original = fs::metadata(&temp.0).unwrap().permissions();
        let mut open = original.clone();
        use std::os::unix::fs::PermissionsExt;
        open.set_mode(0o777);
        fs::set_permissions(&temp.0, open).unwrap();
        assert_refused(install_target(&temp.0.join("unsafe-prefix")));
        fs::set_permissions(&temp.0, original).unwrap();
    }

    #[test]
    fn install_target_rejects_root_home_and_current_directory_ancestor() {
        assert_refused(install_target(Path::new("/")));
        let home = home_directory().unwrap();
        assert_refused(install_target(&home));
        let cwd = std::env::current_dir().unwrap();
        assert_refused(install_target(&cwd));
    }

    #[test]
    fn existing_install_target_retains_root_and_parent_and_checks_modes() {
        let temp = TempDir::new();
        let installed = temp.0.join("installed");
        fs::create_dir(&installed).unwrap();
        let target = existing_install_target(&installed).unwrap();
        assert_eq!(target.path(), installed);
        assert_eq!(target.name(), OsStr::new("installed"));
        assert!(target.parent().metadata().unwrap().is_dir());
        assert!(target.root().metadata().unwrap().is_dir());

        let unsafe_prefix = temp.0.join("unsafe");
        fs::create_dir(&unsafe_prefix).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&unsafe_prefix, fs::Permissions::from_mode(0o775)).unwrap();
        assert_refused(existing_install_target(&unsafe_prefix));

        let regular = temp.0.join("regular");
        fs::write(&regular, b"file").unwrap();
        assert_refused(existing_install_target(&regular));

        let alias = temp.0.join("alias");
        symlink(&installed, &alias).unwrap();
        assert_refused(existing_install_target(&alias));

        assert_refused(existing_install_target(&temp.0.join("missing")));
    }

    #[test]
    fn validates_external_receipt_pin_disjointness_and_freshness() {
        let temp = TempDir::new();
        let prefix = temp.0.join("prefix");
        let bundle = temp.0.join("bundle");
        fs::create_dir(&bundle).unwrap();

        let outside = temp.0.join("receipt.sha256");
        assert!(receipt_pin(&outside, &prefix, &bundle).is_ok());
        assert_refused(receipt_pin(&prefix.join("pin"), &prefix, &bundle));
        assert_refused(receipt_pin(&temp.0, &prefix, &bundle));
        assert_refused(receipt_pin(&bundle.join("pin"), &prefix, &bundle));

        fs::write(&outside, b"occupied").unwrap();
        assert_refused(receipt_pin(&outside, &prefix, &bundle));
    }

    #[test]
    fn fresh_output_absolutizes_relative_path_and_refuses_existing_entries() {
        let temp = TempDir::new();
        let relative = PathBuf::from(format!(
            ".ami-rust-ownership-relative-{}.json",
            std::process::id()
        ));
        let validated = fresh_output(&relative).unwrap();
        assert!(validated.path().is_absolute());

        let occupied = temp.0.join("existing-output.json");
        fs::write(&occupied, b"existing").unwrap();
        assert_refused(fresh_output(&occupied));
        assert_refused(fresh_output(&temp.0));
        let nul_path = PathBuf::from(OsString::from_vec(b"relative\0bad".to_vec()));
        assert_refused(fresh_output(&nul_path));
    }

    #[test]
    fn private_state_requires_nonroot_current_user_and_private_mode() {
        assert_refused(require_non_root(0));
        if super::current_uid() == 0 {
            // This host is intentionally root; state APIs must refuse here.
            assert_refused(fresh_private_state(Path::new("/tmp/fresh-state")));
            assert_refused(existing_private_state(Path::new("/tmp")));
            return;
        }

        let temp = TempDir::new();
        let fresh = temp.0.join("fresh-state");
        let validated = fresh_private_state(&fresh).unwrap();
        assert_eq!(validated.path(), fresh);

        let existing = temp.0.join("private-state");
        fs::create_dir(&existing).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&existing, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(existing_private_state(&existing).is_ok());
        assert_refused(fresh_private_state(&existing));

        fs::set_permissions(&existing, fs::Permissions::from_mode(0o755)).unwrap();
        assert_refused(existing_private_state(&existing));
    }

    #[test]
    fn preserves_state_package_retention_exception_and_checks_overlap() {
        let state = Path::new("/tmp/state");
        let package = state.join("retained/libexec/ami-rust/v1");
        assert!(validate_state_package_separation(state, &package, false).is_ok());
        assert_refused(validate_state_package_separation(state, &package, true));
        assert_refused(validate_state_package_separation(
            state,
            &state.join("package"),
            false,
        ));
        assert_refused(require_disjoint(
            Path::new("/tmp/tree/output"),
            Path::new("/tmp/tree"),
            "must be disjoint",
        ));
    }

    #[test]
    fn retains_native_bytes_in_fresh_target_names() {
        let temp = TempDir::new();
        let name = OsString::from_vec(vec![b'n', b'a', b'm', b'e', 0xff]);
        let target_path = temp.0.join(&name);
        let target = fresh_output(&target_path).unwrap();
        assert_eq!(target.name(), name.as_os_str());
        assert_eq!(target.path(), target_path);
        assert!(target.parent().metadata().unwrap().is_dir());
    }

    #[test]
    fn open_parent_handle_remains_available_for_race_safe_publication() {
        let temp = TempDir::new();
        let target = install_target(&temp.0.join("new-prefix")).unwrap();
        let metadata = target.parent().metadata().unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.uid(), super::current_uid());
    }
}
