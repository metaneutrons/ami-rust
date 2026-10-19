//! Filesystem and process-ownership checks for the selected macOS developer tools.
//!
//! The caller obtains the selected developer directory through its already-bounded
//! host-selection interface and passes that exact path to [`resolve_selected`].
//! This module performs no environment lookup, subprocess invocation, network
//! access, or fallback search.

use std::os::unix::fs::MetadataExt;
use std::{
    collections::BTreeMap,
    error::Error,
    fmt, fs,
    path::{Component, Path, PathBuf},
};

const ROOT_UID: u32 = 0;
const GROUP_OR_OTHER_WRITE: u32 = 0o022;
const EXECUTE_BITS: u32 = 0o111;
const READ_BITS: u32 = 0o444;

#[allow(
    unsafe_code,
    reason = "POSIX geteuid exposes the effective owner without a subprocess or environment lookup."
)]
unsafe extern "C" {
    fn geteuid() -> u32;
}

#[allow(
    unsafe_code,
    reason = "The no-argument POSIX geteuid call only reads process ownership."
)]
fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments, reads only the calling process's
    // effective POSIX user ID, and cannot fail.
    unsafe { geteuid() }
}

/// The only supported selected developer-directory layouts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeveloperLayout {
    /// `Xcode.app/Contents/Developer` and its default toolchain/platform SDK.
    Xcode,
    /// `/Library/Developer/CommandLineTools` and its SDK.
    CommandLineTools,
}

impl DeveloperLayout {
    /// Stable, machine-readable layout name for receipts and diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Xcode => "xcode",
            Self::CommandLineTools => "command-line-tools",
        }
    }
}

/// Expected kind of a selected filesystem object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryKind {
    Directory,
    RegularFile,
}

/// Identity of a symbolic link at a requested path, when that path is a link.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinkIdentity {
    /// Exact link text as returned by `read_link` (may be relative).
    pub target_text: PathBuf,
    pub uid: u32,
    pub gid: u32,
    /// Link mode as reported by the host; POSIX symlink mode is not used as a
    /// write-permission check because macOS reports links as mode 0777.
    pub mode: u32,
    pub bytes: u64,
    pub device: u64,
    pub inode: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
}

/// Canonical path and stable filesystem metadata for one selected input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PathIdentity {
    /// Path supplied by the caller or derived from the selected developer root.
    pub requested_path: PathBuf,
    /// Canonical target path after resolving all links and `..` components.
    pub canonical_path: PathBuf,
    /// Identity of the final requested-path symlink, if it is a symlink.
    pub requested_link: Option<LinkIdentity>,
    pub kind: EntryKind,
    pub bytes: u64,
    pub uid: u32,
    pub gid: u32,
    /// Permission and special bits (`mode & 07777`), excluding file-type bits.
    pub mode: u32,
    pub device: u64,
    pub inode: u64,
    pub modified_seconds: i64,
    pub modified_nanoseconds: i64,
}

/// Selected compiler, linker and SDK metadata rooted in one explicit developer directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostSelection {
    pub layout: DeveloperLayout,
    /// Canonical selected Xcode.app or Command Line Tools installation root.
    pub installation_root: PathIdentity,
    pub developer_directory: PathIdentity,
    pub clang: PathIdentity,
    pub linker: PathIdentity,
    pub sdk: PathIdentity,
    pub sdk_settings_json: PathIdentity,
    pub sdk_settings_plist: PathIdentity,
    /// Root- or current-user-owned, non-group/world-writable canonical
    /// directories from the selected installation root through each selected
    /// path, sorted and deduplicated.
    pub guarded_directories: Vec<PathIdentity>,
}

/// Failure category for host-tool selection or a later identity recheck.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectionErrorKind {
    InvalidInput,
    UnsupportedLayout,
    AmbiguousLayout,
    MissingPath,
    UnsafeOwnership,
    WritablePath,
    WrongType,
    NotExecutable,
    NotReadable,
    EmptyMetadata,
    EscapesInstallationRoot,
    Changed,
}

/// Useful path-qualified error from selection or identity rechecking.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectionError {
    pub kind: SelectionErrorKind,
    pub path: Option<PathBuf>,
    pub details: String,
}

impl SelectionError {
    fn new(kind: SelectionErrorKind, path: Option<&Path>, details: impl Into<String>) -> Self {
        Self {
            kind,
            path: path.map(Path::to_path_buf),
            details: details.into(),
        }
    }

    fn at(kind: SelectionErrorKind, path: &Path, details: impl Into<String>) -> Self {
        Self::new(kind, Some(path), details)
    }
}

impl fmt::Display for SelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(path) = &self.path {
            write!(formatter, "{}: {}", path.display(), self.details)
        } else {
            formatter.write_str(&self.details)
        }
    }
}

impl Error for SelectionError {}

/// Resolve one explicit `/usr/bin/xcode-select -p` result without fallback.
///
/// The caller owns the bounded selector invocation. This function requires an
/// absolute path and accepts only Xcode's `Contents/Developer` directory or
/// the Command Line Tools root. Selected objects and canonical directories
/// from the selected installation root through those objects must be
/// owned by root or the current effective user and not group/world writable.
/// Compiler/linker files must be regular executable files; both SDK settings
/// files must be nonempty regular readable files. Directories above the
/// selected installation are outside this check.
pub fn resolve_selected(developer_directory: &Path) -> Result<HostSelection, SelectionError> {
    validate_absolute_path(developer_directory)?;
    let developer = inspect_entry(developer_directory, EntryKind::Directory, false, false)?;
    let canonical_developer = &developer.canonical_path;
    let layout = classify_layout(canonical_developer)?;
    let installation_path = match layout {
        DeveloperLayout::Xcode => canonical_developer
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| {
                SelectionError::at(
                    SelectionErrorKind::UnsupportedLayout,
                    canonical_developer,
                    "selected Xcode developer directory has no Xcode.app installation root",
                )
            })?
            .to_path_buf(),
        DeveloperLayout::CommandLineTools => canonical_developer.clone(),
    };
    let installation_root = inspect_entry(&installation_path, EntryKind::Directory, false, false)?;

    let (clang_path, linker_path, sdk_path) = match layout {
        DeveloperLayout::Xcode => (
            canonical_developer.join("Toolchains/XcodeDefault.xctoolchain/usr/bin/clang"),
            canonical_developer.join("Toolchains/XcodeDefault.xctoolchain/usr/bin/ld"),
            canonical_developer.join("Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"),
        ),
        DeveloperLayout::CommandLineTools => (
            canonical_developer.join("usr/bin/clang"),
            canonical_developer.join("usr/bin/ld"),
            canonical_developer.join("SDKs/MacOSX.sdk"),
        ),
    };

    let clang = inspect_entry(&clang_path, EntryKind::RegularFile, true, false)?;
    let linker = inspect_entry(&linker_path, EntryKind::RegularFile, true, false)?;
    let sdk = inspect_entry(&sdk_path, EntryKind::Directory, false, false)?;
    let sdk_settings_json = inspect_entry(
        &sdk.canonical_path.join("SDKSettings.json"),
        EntryKind::RegularFile,
        false,
        true,
    )?;
    let sdk_settings_plist = inspect_entry(
        &sdk.canonical_path.join("SDKSettings.plist"),
        EntryKind::RegularFile,
        false,
        true,
    )?;

    let mut directories = BTreeMap::new();
    collect_guarded_directories(
        &installation_root,
        &installation_root.canonical_path,
        &mut directories,
    )?;
    for identity in [
        &developer,
        &clang,
        &linker,
        &sdk,
        &sdk_settings_json,
        &sdk_settings_plist,
    ] {
        collect_guarded_directories(
            identity,
            &installation_root.canonical_path,
            &mut directories,
        )?;
    }

    Ok(HostSelection {
        layout,
        installation_root,
        developer_directory: developer,
        clang,
        linker,
        sdk,
        sdk_settings_json,
        sdk_settings_plist,
        guarded_directories: directories.into_values().collect(),
    })
}

impl HostSelection {
    /// Re-resolve the original selected directory and reject any identity change.
    pub fn recheck(&self) -> Result<(), SelectionError> {
        let current = resolve_selected(&self.developer_directory.requested_path)?;
        if current == *self {
            Ok(())
        } else {
            Err(SelectionError::at(
                SelectionErrorKind::Changed,
                &self.developer_directory.requested_path,
                "selected macOS host-tool identities changed after selection",
            ))
        }
    }
}

fn validate_absolute_path(path: &Path) -> Result<(), SelectionError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(SelectionError::at(
            SelectionErrorKind::InvalidInput,
            path,
            "selected developer directory must be an absolute normalized path",
        ));
    }
    Ok(())
}

fn classify_layout(path: &Path) -> Result<DeveloperLayout, SelectionError> {
    let xcode = path.ends_with(Path::new("Contents/Developer"));
    let command_line_tools = path.ends_with(Path::new("Library/Developer/CommandLineTools"));
    match choose_layout(xcode, command_line_tools) {
        Ok(layout) => Ok(layout),
        Err(kind) => Err(SelectionError::at(
            kind,
            path,
            match kind {
                SelectionErrorKind::AmbiguousLayout => {
                    "selected developer directory matches multiple supported layouts"
                }
                _ => {
                    "selected developer directory is not a supported Xcode or Command Line Tools root"
                }
            },
        )),
    }
}

fn require_within_installation(
    path: &Path,
    installation_root: &Path,
) -> Result<(), SelectionError> {
    if path.starts_with(installation_root) {
        Ok(())
    } else {
        Err(SelectionError::at(
            SelectionErrorKind::EscapesInstallationRoot,
            path,
            format!(
                "canonical selected path is outside installation root {}",
                installation_root.display()
            ),
        ))
    }
}

fn choose_layout(
    xcode: bool,
    command_line_tools: bool,
) -> Result<DeveloperLayout, SelectionErrorKind> {
    match (xcode, command_line_tools) {
        (true, false) => Ok(DeveloperLayout::Xcode),
        (false, true) => Ok(DeveloperLayout::CommandLineTools),
        (true, true) => Err(SelectionErrorKind::AmbiguousLayout),
        (false, false) => Err(SelectionErrorKind::UnsupportedLayout),
    }
}

fn inspect_entry(
    requested_path: &Path,
    expected_kind: EntryKind,
    executable: bool,
    nonempty: bool,
) -> Result<PathIdentity, SelectionError> {
    let requested_meta = fs::symlink_metadata(requested_path).map_err(|error| {
        SelectionError::at(
            SelectionErrorKind::MissingPath,
            requested_path,
            format!("cannot inspect selected path: {error}"),
        )
    })?;
    let requested_link = if requested_meta.file_type().is_symlink() {
        let target_text = fs::read_link(requested_path).map_err(|error| {
            SelectionError::at(
                SelectionErrorKind::MissingPath,
                requested_path,
                format!("cannot read selected symlink: {error}"),
            )
        })?;
        validate_owner(requested_path, requested_meta.uid(), effective_uid())?;
        Some(LinkIdentity {
            target_text,
            uid: requested_meta.uid(),
            gid: requested_meta.gid(),
            mode: requested_meta.mode() & 0o7777,
            bytes: requested_meta.len(),
            device: requested_meta.dev(),
            inode: requested_meta.ino(),
            modified_seconds: requested_meta.mtime(),
            modified_nanoseconds: requested_meta.mtime_nsec(),
        })
    } else {
        None
    };

    let canonical_path = fs::canonicalize(requested_path).map_err(|error| {
        SelectionError::at(
            SelectionErrorKind::MissingPath,
            requested_path,
            format!("cannot resolve selected path: {error}"),
        )
    })?;
    if !canonical_path.is_absolute() {
        return Err(SelectionError::at(
            SelectionErrorKind::InvalidInput,
            requested_path,
            "canonical selected path is not absolute",
        ));
    }
    let metadata = fs::symlink_metadata(&canonical_path).map_err(|error| {
        SelectionError::at(
            SelectionErrorKind::MissingPath,
            &canonical_path,
            format!("cannot inspect canonical selected path: {error}"),
        )
    })?;
    let actual_kind = if metadata.file_type().is_dir() {
        EntryKind::Directory
    } else if metadata.file_type().is_file() {
        EntryKind::RegularFile
    } else {
        return Err(SelectionError::at(
            SelectionErrorKind::WrongType,
            &canonical_path,
            "selected path is neither a directory nor a regular file",
        ));
    };
    validate_attributes(
        &canonical_path,
        expected_kind,
        metadata.uid(),
        effective_uid(),
        metadata.mode() & 0o7777,
        executable,
        nonempty,
    )?;
    if nonempty && metadata.len() == 0 {
        return Err(SelectionError::at(
            SelectionErrorKind::EmptyMetadata,
            &canonical_path,
            "SDK settings metadata is empty",
        ));
    }
    if actual_kind != expected_kind {
        return Err(SelectionError::at(
            SelectionErrorKind::WrongType,
            &canonical_path,
            format!("expected {expected_kind:?}, found {actual_kind:?}"),
        ));
    }

    Ok(PathIdentity {
        requested_path: requested_path.to_path_buf(),
        canonical_path,
        requested_link,
        kind: actual_kind,
        bytes: metadata.len(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: metadata.mode() & 0o7777,
        device: metadata.dev(),
        inode: metadata.ino(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "Pure metadata policy compares actual/effective ownership, kind, permissions and required capabilities explicitly."
)]
fn validate_attributes(
    path: &Path,
    kind: EntryKind,
    uid: u32,
    current_uid: u32,
    mode: u32,
    executable: bool,
    nonempty: bool,
) -> Result<(), SelectionError> {
    validate_owner(path, uid, current_uid)?;
    if kind == EntryKind::Directory && mode & GROUP_OR_OTHER_WRITE != 0 {
        return Err(SelectionError::at(
            SelectionErrorKind::WritablePath,
            path,
            "selected directory is group- or other-writable",
        ));
    }
    if kind == EntryKind::RegularFile && mode & GROUP_OR_OTHER_WRITE != 0 {
        return Err(SelectionError::at(
            SelectionErrorKind::WritablePath,
            path,
            "selected file is group- or other-writable",
        ));
    }
    if executable && kind != EntryKind::RegularFile {
        return Err(SelectionError::at(
            SelectionErrorKind::WrongType,
            path,
            "an executable selection must be a regular file",
        ));
    }
    if executable && mode & EXECUTE_BITS == 0 {
        return Err(SelectionError::at(
            SelectionErrorKind::NotExecutable,
            path,
            "selected compiler or linker has no execute bit",
        ));
    }
    if nonempty && kind != EntryKind::RegularFile {
        return Err(SelectionError::at(
            SelectionErrorKind::WrongType,
            path,
            "SDK metadata must be a regular file",
        ));
    }
    if nonempty && mode & READ_BITS == 0 {
        return Err(SelectionError::at(
            SelectionErrorKind::NotReadable,
            path,
            "SDK metadata has no read permission bit",
        ));
    }
    Ok(())
}

fn validate_owner(path: &Path, uid: u32, current_uid: u32) -> Result<(), SelectionError> {
    if uid != ROOT_UID && uid != current_uid {
        return Err(SelectionError::at(
            SelectionErrorKind::UnsafeOwnership,
            path,
            format!(
                "selected path must be owned by root (uid {ROOT_UID}) or the current effective user (uid {current_uid}), found uid {uid}"
            ),
        ));
    }
    Ok(())
}

fn collect_guarded_directories(
    identity: &PathIdentity,
    installation_root: &Path,
    directories: &mut BTreeMap<PathBuf, PathIdentity>,
) -> Result<(), SelectionError> {
    require_within_installation(&identity.canonical_path, installation_root)?;
    let mut directory = match identity.kind {
        EntryKind::Directory => identity.canonical_path.as_path(),
        EntryKind::RegularFile => identity.canonical_path.parent().ok_or_else(|| {
            SelectionError::at(
                SelectionErrorKind::InvalidInput,
                &identity.canonical_path,
                "selected file has no parent directory",
            )
        })?,
    };
    let mut chain = Vec::new();
    loop {
        require_within_installation(directory, installation_root)?;
        chain.push(directory.to_path_buf());
        if directory == installation_root {
            break;
        }
        match directory.parent() {
            Some(parent) => directory = parent,
            None => {
                return Err(SelectionError::at(
                    SelectionErrorKind::EscapesInstallationRoot,
                    directory,
                    "selected path ancestry ended before the installation root",
                ));
            }
        }
    }
    chain.reverse();
    for path in chain {
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            SelectionError::at(
                SelectionErrorKind::MissingPath,
                &path,
                format!("cannot inspect selected directory ancestor: {error}"),
            )
        })?;
        if !metadata.file_type().is_dir() {
            return Err(SelectionError::at(
                SelectionErrorKind::WrongType,
                &path,
                "canonical selected path ancestor is not a real directory",
            ));
        }
        validate_attributes(
            &path,
            EntryKind::Directory,
            metadata.uid(),
            effective_uid(),
            metadata.mode() & 0o7777,
            false,
            false,
        )?;
        directories
            .entry(path.clone())
            .or_insert_with(|| PathIdentity {
                requested_path: path.clone(),
                canonical_path: path,
                requested_link: None,
                kind: EntryKind::Directory,
                bytes: metadata.len(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: metadata.mode() & 0o7777,
                device: metadata.dev(),
                inode: metadata.ino(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
            });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DeveloperLayout, EntryKind, SelectionErrorKind, choose_layout, require_within_installation,
        validate_attributes,
    };
    use std::path::Path;

    #[test]
    fn classifies_only_the_two_selected_developer_root_shapes() {
        assert_eq!(choose_layout(true, false), Ok(DeveloperLayout::Xcode));
        assert_eq!(
            choose_layout(false, true),
            Ok(DeveloperLayout::CommandLineTools)
        );
        assert_eq!(
            choose_layout(false, false),
            Err(SelectionErrorKind::UnsupportedLayout)
        );
        assert_eq!(
            choose_layout(true, true),
            Err(SelectionErrorKind::AmbiguousLayout)
        );
        assert!(
            Path::new("/Applications/Xcode.app/Contents/Developer")
                .ends_with(Path::new("Contents/Developer"))
        );
        assert!(
            Path::new("/Library/Developer/CommandLineTools")
                .ends_with(Path::new("Library/Developer/CommandLineTools"))
        );
    }

    #[test]
    fn production_attributes_accept_root_owned_private_files_and_directories() {
        assert!(
            validate_attributes(
                Path::new("/selected/compiler"),
                EntryKind::RegularFile,
                0,
                501,
                0o755,
                true,
                false,
            )
            .is_ok()
        );
        assert!(
            validate_attributes(
                Path::new("/selected/sdk"),
                EntryKind::Directory,
                0,
                501,
                0o755,
                false,
                false,
            )
            .is_ok()
        );
        assert!(
            validate_attributes(
                Path::new("/selected/SDKSettings.json"),
                EntryKind::RegularFile,
                0,
                501,
                0o644,
                false,
                true,
            )
            .is_ok()
        );
    }

    #[test]
    fn production_attributes_accept_current_user_and_reject_other_users_and_writable_modes() {
        assert!(
            validate_attributes(
                Path::new("/selected/compiler"),
                EntryKind::RegularFile,
                501,
                501,
                0o755,
                true,
                false,
            )
            .is_ok()
        );
        assert!(
            validate_attributes(
                Path::new("/selected/sdk"),
                EntryKind::Directory,
                501,
                501,
                0o755,
                false,
                false,
            )
            .is_ok()
        );
        assert_eq!(
            validate_attributes(
                Path::new("/selected/compiler"),
                EntryKind::RegularFile,
                502,
                501,
                0o755,
                true,
                false,
            )
            .unwrap_err()
            .kind,
            SelectionErrorKind::UnsafeOwnership
        );
        assert_eq!(
            validate_attributes(
                Path::new("/selected/compiler"),
                EntryKind::RegularFile,
                501,
                501,
                0o775,
                true,
                false,
            )
            .unwrap_err()
            .kind,
            SelectionErrorKind::WritablePath
        );
    }

    #[test]
    fn production_attributes_reject_wrong_owner_writable_paths_and_nonexecutables() {
        assert_eq!(
            validate_attributes(
                Path::new("/selected/compiler"),
                EntryKind::RegularFile,
                502,
                501,
                0o755,
                true,
                false,
            )
            .unwrap_err()
            .kind,
            SelectionErrorKind::UnsafeOwnership
        );
        assert_eq!(
            validate_attributes(
                Path::new("/selected/compiler"),
                EntryKind::RegularFile,
                0,
                501,
                0o775,
                true,
                false,
            )
            .unwrap_err()
            .kind,
            SelectionErrorKind::WritablePath
        );
        assert_eq!(
            validate_attributes(
                Path::new("/selected/compiler"),
                EntryKind::RegularFile,
                0,
                501,
                0o644,
                true,
                false,
            )
            .unwrap_err()
            .kind,
            SelectionErrorKind::NotExecutable
        );
        assert_eq!(
            validate_attributes(
                Path::new("/selected/SDKSettings.json"),
                EntryKind::RegularFile,
                0,
                501,
                0o200,
                false,
                true,
            )
            .unwrap_err()
            .kind,
            SelectionErrorKind::NotReadable
        );
    }

    #[test]
    fn selected_paths_must_remain_inside_the_selected_installation() {
        let root = Path::new("/Applications/Xcode.app");
        assert!(
            require_within_installation(
                Path::new("/Applications/Xcode.app/Contents/Developer"),
                root,
            )
            .is_ok()
        );
        assert_eq!(
            require_within_installation(
                Path::new("/Applications/Other.app/Contents/Developer"),
                root
            )
            .unwrap_err()
            .kind,
            SelectionErrorKind::EscapesInstallationRoot
        );
    }
}
