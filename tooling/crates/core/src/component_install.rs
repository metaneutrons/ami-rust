//! Materialize one authenticated component profile from a larger extracted
//! source tree.
//!
//! Only paths present in the caller-authenticated component inventory are
//! copied. Files are streamed into fresh inodes, checked against their declared
//! size and digest, and assigned the source file's ordinary permission bits.
//! Inventoried symlinks are reproduced only after their source target matches
//! the authenticated row. The completed subset is verified through its retained
//! staging descriptor and published with an exclusive rename. This does not
//! provide a snapshot against a concurrent writer running as the same user.

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("component profile installation is supported only on macOS and Linux");

use crate::{
    Refusal, Result,
    digest::{encode_hex, is_sha256_digest},
    directory::Directory,
    files::validate_relative_inventory_path,
    inventory::{
        FileIdentity, InventoryLimits, LinkIdentity, Measurement, verify_complete_directory_checked,
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    ffi::{CString, OsStr, OsString},
    fmt,
    fs::{Metadata, Permissions},
    io::{self, Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt},
    },
};

const COPY_BUFFER_BYTES: usize = 64 * 1024;
const DEFAULT_DIRECTORY_MODE: u32 = 0o755;
const PRIVATE_STAGE_MODE: u32 = 0o700;

/// Bounded host work for one selected component profile. The entry count
/// includes inventory leaves and all implicit parent directories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ComponentInstallLimits {
    pub max_tree_entries: usize,
    pub max_path_bytes: usize,
    pub max_path_components: usize,
    pub max_file_bytes: u64,
    pub max_expanded_bytes: u64,
    pub current_workspace_bytes: u64,
    pub max_workspace_bytes: u64,
    pub max_link_target_bytes: usize,
    pub max_link_resolution_steps: usize,
}

/// Authenticated output selection and caller-owned resource bounds.
pub struct ComponentInstallSpec<'a> {
    /// Fresh leaf to publish below `destination_parent`.
    pub destination_name: &'a OsStr,
    pub files: &'a [FileIdentity],
    pub symlinks: &'a [LinkIdentity],
    pub limits: ComponentInstallLimits,
}

/// Complete installed subset measurement.
#[derive(Debug, Eq, PartialEq)]
pub struct ComponentInstallReceipt {
    pub measurement: Measurement,
}

/// Failure preserves the cause and identifies staging data requiring recovery
/// if best-effort cleanup could not remove it.
#[derive(Debug)]
pub struct ComponentInstallFailure {
    pub reason: Refusal,
    pub recovery_entry: Option<OsString>,
}

impl fmt::Display for ComponentInstallFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.reason, formatter)
    }
}

impl Error for ComponentInstallFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.reason)
    }
}

pub type ComponentInstallResult<T> = std::result::Result<T, ComponentInstallFailure>;

/// Copy an authenticated component subset from `source` into a fresh sibling
/// root below `destination_parent`, then publish that root without replacement.
///
/// `source` is normally the root selected from a verified component archive;
/// it may contain other files that are intentionally not part of this profile.
/// Input rows must already be authenticated by the caller. This function
/// verifies their source bytes and link targets, but makes no signature or
/// publisher-authentication claim. Cancellation is checked between entries,
/// during streaming copies, during final verification, and before publication.
pub fn install_component_profile(
    source: &Directory,
    destination_parent: &Directory,
    spec: ComponentInstallSpec<'_>,
    mut cancellation_check: impl FnMut() -> Result<()>,
) -> ComponentInstallResult<ComponentInstallReceipt> {
    let plan = validate_spec(&spec).map_err(failure)?;
    let cleanup_bound = plan
        .tree_entries
        .checked_add(1)
        .ok_or_else(|| failure(Refusal::new("component cleanup entry bound overflow")))?;
    let stage_name = random_stage_name().map_err(failure)?;

    let mut stage_created = false;
    let stage = match destination_parent
        .mkdir_new_tracked(&stage_name, PRIVATE_STAGE_MODE, || stage_created = true)
    {
        Ok(stage) => stage,
        Err(reason) if stage_created => {
            return Err(cleanup_failure(
                destination_parent,
                &stage_name,
                cleanup_bound,
                reason,
            ));
        }
        Err(reason) => return Err(failure(reason)),
    };

    let result = (|| -> Result<ComponentInstallReceipt> {
        cancellation_check()?;
        let directories = create_output_directories(&stage, &plan, &mut cancellation_check)?;

        for file in spec.files {
            cancellation_check()?;
            copy_one_file(
                source,
                &stage,
                &directories,
                file,
                &spec.limits,
                &mut cancellation_check,
            )?;
        }

        for link in spec.symlinks {
            cancellation_check()?;
            materialize_one_link(source, &stage, &directories, link, &spec.limits)?;
        }

        cancellation_check()?;
        let measurement = verify_complete_directory_checked(
            &stage,
            spec.files,
            spec.symlinks,
            InventoryLimits {
                max_tree_entries: spec.limits.max_tree_entries,
                max_link_resolution_steps: spec.limits.max_link_resolution_steps,
            },
            &mut cancellation_check,
        )?;
        cancellation_check()?;
        stage.set_mode_exact(DEFAULT_DIRECTORY_MODE as libc::mode_t)?;
        cancellation_check()?;
        destination_parent.rename_no_replace(
            &stage_name,
            destination_parent,
            spec.destination_name,
        )?;
        destination_parent.sync_best_effort();

        Ok(ComponentInstallReceipt { measurement })
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

struct InstallPlan {
    directories: BTreeSet<String>,
    tree_entries: usize,
}

fn validate_spec(spec: &ComponentInstallSpec<'_>) -> Result<InstallPlan> {
    let limits = spec.limits;
    if limits.max_tree_entries == 0
        || limits.max_path_bytes == 0
        || limits.max_path_components == 0
        || limits.max_expanded_bytes == 0
        || limits.max_workspace_bytes == 0
        || limits.max_link_target_bytes == 0
        || limits.max_link_resolution_steps == 0
        || limits.current_workspace_bytes > limits.max_workspace_bytes
    {
        return Err(Refusal::new("component installation limits are invalid"));
    }
    validate_destination_name(spec.destination_name)?;

    let row_count = spec
        .files
        .len()
        .checked_add(spec.symlinks.len())
        .ok_or_else(|| Refusal::new("component inventory count overflow"))?;
    if row_count > limits.max_tree_entries {
        return Err(Refusal::new("component inventory exceeds its entry bound"));
    }

    let mut leaves = BTreeSet::<String>::new();
    let mut portable_case_paths = BTreeMap::<String, String>::new();
    let mut directories = BTreeSet::<String>::new();
    let mut expanded_bytes = 0_u64;
    for file in spec.files {
        validate_inventory_path(&file.path, limits)?;
        record_case_path(&file.path, &mut portable_case_paths)?;
        if !is_sha256_digest(&file.sha256)
            || file.mode.is_some_and(|mode| mode & !0o7777 != 0)
            || file.bytes > limits.max_file_bytes
        {
            return Err(Refusal::new(
                "component file inventory row is invalid or over limit",
            ));
        }
        expanded_bytes = expanded_bytes
            .checked_add(file.bytes)
            .ok_or_else(|| Refusal::new("component expanded byte count overflow"))?;
        if !leaves.insert(file.path.clone()) {
            return Err(Refusal::new(
                "component inventory contains duplicate or conflicting paths",
            ));
        }
        add_parent_directories(&file.path, &mut directories);
    }
    for link in spec.symlinks {
        validate_inventory_path(&link.path, limits)?;
        record_case_path(&link.path, &mut portable_case_paths)?;
        validate_link_target(&link.target, limits.max_link_target_bytes)?;
        if !leaves.insert(link.path.clone()) {
            return Err(Refusal::new(
                "component inventory contains duplicate or conflicting paths",
            ));
        }
        add_parent_directories(&link.path, &mut directories);
    }

    for path in &leaves {
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
            if leaves.contains(&parent) {
                return Err(Refusal::new(
                    "component inventory leaf is a directory ancestor",
                ));
            }
        }
    }

    let tree_entries = row_count
        .checked_add(directories.len())
        .ok_or_else(|| Refusal::new("component tree entry count overflow"))?;
    if tree_entries > limits.max_tree_entries {
        return Err(Refusal::new("component tree exceeds its entry bound"));
    }
    if expanded_bytes > limits.max_expanded_bytes
        || limits
            .current_workspace_bytes
            .checked_add(expanded_bytes)
            .is_none_or(|total| total > limits.max_workspace_bytes)
    {
        return Err(Refusal::new("component profile exceeds its byte budget"));
    }
    Ok(InstallPlan {
        directories,
        tree_entries,
    })
}

fn validate_inventory_path(path: &str, limits: ComponentInstallLimits) -> Result<()> {
    validate_relative_inventory_path(path)?;
    if path.len() > limits.max_path_bytes || path.split('/').count() > limits.max_path_components {
        return Err(Refusal::new("component inventory path exceeds its bound"));
    }
    Ok(())
}

pub(crate) fn validate_link_target(target: &str, maximum: usize) -> Result<()> {
    if target.is_empty()
        || target.len() > maximum
        || target.starts_with('/')
        || target.contains(['\\', ':'])
        || target.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
    {
        return Err(Refusal::new(
            "component symlink target is unsafe or over limit",
        ));
    }
    Ok(())
}

fn record_case_path(path: &str, index: &mut BTreeMap<String, String>) -> Result<()> {
    let mut prefix = String::new();
    for component in path.split('/') {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(component);
        let folded = prefix.to_lowercase();
        if index
            .get(&folded)
            .is_some_and(|previous| previous != &prefix)
        {
            return Err(Refusal::new(
                "component inventory contains case-colliding paths",
            ));
        }
        index.entry(folded).or_insert_with(|| prefix.clone());
    }
    Ok(())
}

fn validate_destination_name(name: &OsStr) -> Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.contains(&0)
    {
        return Err(Refusal::new(
            "component destination must be one ordinary leaf name",
        ));
    }
    Ok(())
}

fn add_parent_directories(path: &str, directories: &mut BTreeSet<String>) {
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
        directories.insert(parent.clone());
    }
}

fn create_output_directories(
    stage: &Directory,
    plan: &InstallPlan,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<BTreeMap<String, Directory>> {
    let mut paths: Vec<_> = plan.directories.iter().collect();
    paths.sort_by(|left, right| {
        left.matches('/')
            .count()
            .cmp(&right.matches('/').count())
            .then_with(|| left.cmp(right))
    });
    let mut output = BTreeMap::new();
    for path in paths {
        cancellation_check()?;
        let (parent, leaf) = path.rsplit_once('/').unwrap_or(("", path));
        let parent_directory = if parent.is_empty() {
            stage
        } else {
            output
                .get(parent)
                .ok_or_else(|| Refusal::new("component parent directory was not created"))?
        };
        let directory = parent_directory.mkdir_new(OsStr::new(leaf), DEFAULT_DIRECTORY_MODE)?;
        output.insert(path.clone(), directory);
    }
    Ok(output)
}

fn destination_directory<'a>(
    stage: &'a Directory,
    directories: &'a BTreeMap<String, Directory>,
    parent_path: &str,
) -> Result<&'a Directory> {
    if parent_path.is_empty() {
        Ok(stage)
    } else {
        directories
            .get(parent_path)
            .ok_or_else(|| Refusal::new("component destination parent is missing"))
    }
}

fn copy_one_file(
    source: &Directory,
    stage: &Directory,
    directories: &BTreeMap<String, Directory>,
    expected: &FileIdentity,
    limits: &ComponentInstallLimits,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let (parent_path, leaf) = expected
        .path
        .rsplit_once('/')
        .unwrap_or(("", &expected.path));
    let source_parent = source.relative_directory(parent_path)?;
    let mut input = source_parent.regular(OsStr::new(leaf))?;
    let before = input.metadata()?;
    if !before.file_type().is_file() || before.len() != expected.bytes {
        return Err(Refusal::new(
            "component source file size or type differs from inventory",
        ));
    }
    let source_mode = before.mode() & 0o7777;
    if expected.mode.is_some_and(|mode| mode != source_mode) {
        return Err(Refusal::new(
            "component source file mode differs from inventory",
        ));
    }

    let parent = destination_directory(stage, directories, parent_path)?;
    let mut output = parent.create_new_file(OsStr::new(leaf), 0o600)?;
    let read_bound = expected
        .bytes
        .checked_add(1)
        .ok_or_else(|| Refusal::new("component file size cannot be bounded"))?;
    let mut bytes = 0_u64;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    loop {
        cancellation_check()?;
        let remaining = read_bound
            .checked_sub(bytes)
            .ok_or_else(|| Refusal::new("component file byte count overflow"))?;
        let amount = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| Refusal::new("component file read size is not representable"))?;
        match input.read(&mut buffer[..amount]) {
            Ok(0) => break,
            Ok(count) => {
                bytes = bytes
                    .checked_add(count as u64)
                    .ok_or_else(|| Refusal::new("component file byte count overflow"))?;
                if bytes > expected.bytes {
                    return Err(Refusal::new(
                        "component source file grew beyond inventory size",
                    ));
                }
                digest.update(&buffer[..count]);
                output.write_all(&buffer[..count])?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not copy component file: {error}"
                )));
            }
        }
    }
    if bytes != expected.bytes || encode_hex(&digest.finalize().into()) != expected.sha256 {
        return Err(Refusal::new(
            "component source file bytes differ from inventory",
        ));
    }
    output.flush()?;
    output.set_permissions(Permissions::from_mode(source_mode))?;
    let after = input.metadata()?;
    if !same_file_state(&before, &after) {
        return Err(Refusal::new(
            "component source file changed while it was copied",
        ));
    }
    if bytes > limits.max_file_bytes {
        return Err(Refusal::new("component source file exceeds its byte limit"));
    }
    Ok(())
}

fn same_file_state(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn materialize_one_link(
    source: &Directory,
    stage: &Directory,
    directories: &BTreeMap<String, Directory>,
    expected: &LinkIdentity,
    limits: &ComponentInstallLimits,
) -> Result<()> {
    let (parent_path, leaf) = expected
        .path
        .rsplit_once('/')
        .unwrap_or(("", &expected.path));
    let source_parent = source.relative_directory(parent_path)?;
    let source_target =
        source_parent.link_target(OsStr::new(leaf), limits.max_link_target_bytes)?;
    if source_target.as_bytes() != expected.target.as_bytes() {
        return Err(Refusal::new(
            "component source symlink target differs from inventory",
        ));
    }
    let parent = destination_directory(stage, directories, parent_path)?;
    create_symlink(parent, leaf, &expected.target)
}

pub(crate) fn create_symlink(parent: &Directory, leaf: &str, target: &str) -> Result<()> {
    let leaf = CString::new(leaf.as_bytes())
        .map_err(|_| Refusal::new("component symlink path contains NUL"))?;
    let target = CString::new(target.as_bytes())
        .map_err(|_| Refusal::new("component symlink target contains NUL"))?;
    #[allow(
        unsafe_code,
        reason = "symlinkat is anchored to a retained parent and validated inventory paths."
    )]
    // SAFETY: parent owns a live directory descriptor; leaf is one NUL-free
    // basename and target has already passed the portable relative-link check.
    let result = unsafe { libc::symlinkat(target.as_ptr(), parent.raw_fd(), leaf.as_ptr()) };
    if result != 0 {
        return Err(Refusal::new(format!(
            "could not materialize component symlink: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

pub(crate) fn random_stage_name() -> Result<OsString> {
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
    let mut name = format!(".ami-rust-profile-{}-", std::process::id());
    use fmt::Write as _;
    for byte in nonce {
        write!(name, "{byte:02x}").expect("formatting into String cannot fail");
    }
    Ok(OsString::from(name))
}

fn failure(reason: Refusal) -> ComponentInstallFailure {
    ComponentInstallFailure {
        reason,
        recovery_entry: None,
    }
}

fn cleanup_failure(
    parent: &Directory,
    stage_name: &OsStr,
    maximum_entries: usize,
    reason: Refusal,
) -> ComponentInstallFailure {
    match parent.remove_tree(stage_name, maximum_entries) {
        Ok(()) => ComponentInstallFailure {
            reason,
            recovery_entry: None,
        },
        Err(cleanup) => ComponentInstallFailure {
            reason: Refusal::new(format!(
                "{reason}; partial component profile remains at {} because cleanup failed: {cleanup}",
                stage_name.to_string_lossy()
            )),
            recovery_entry: Some(stage_name.to_os_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::sha256_bytes;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::current_dir()
                .expect("current directory")
                .join(format!(
                    ".ami-rust-component-install-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            fs::create_dir(&path).expect("create component fixture");
            fs::create_dir(path.join("source")).expect("create source root");
            fs::create_dir(path.join("destinations")).expect("create destination parent");
            Self(path)
        }

        fn source(&self) -> Directory {
            Directory::open(&self.0.join("source")).expect("open source root")
        }

        fn destinations(&self) -> Directory {
            Directory::open(&self.0.join("destinations")).expect("open destination parent")
        }

        fn write_source(&self, relative: &str, bytes: &[u8], mode: u32) {
            let path = self.0.join("source").join(relative);
            fs::create_dir_all(path.parent().expect("source parent"))
                .expect("create source parents");
            fs::write(&path, bytes).expect("write source file");
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                .expect("set source file mode");
        }

        fn install(
            &self,
            destination: &str,
            files: &[FileIdentity],
            symlinks: &[LinkIdentity],
            limits: ComponentInstallLimits,
            cancellation_check: impl FnMut() -> Result<()>,
        ) -> ComponentInstallResult<ComponentInstallReceipt> {
            install_component_profile(
                &self.source(),
                &self.destinations(),
                ComponentInstallSpec {
                    destination_name: OsStr::new(destination),
                    files,
                    symlinks,
                    limits,
                },
                cancellation_check,
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove component fixture");
        }
    }

    fn limits() -> ComponentInstallLimits {
        ComponentInstallLimits {
            max_tree_entries: 64,
            max_path_bytes: 256,
            max_path_components: 16,
            max_file_bytes: 1024 * 1024,
            max_expanded_bytes: 4 * 1024 * 1024,
            current_workspace_bytes: 0,
            max_workspace_bytes: 8 * 1024 * 1024,
            max_link_target_bytes: 256,
            max_link_resolution_steps: 256,
        }
    }

    fn file(path: &str, bytes: &[u8]) -> FileIdentity {
        FileIdentity {
            path: path.to_owned(),
            bytes: bytes.len() as u64,
            sha256: sha256_bytes(bytes),
            mode: None,
        }
    }

    fn link(path: &str, target: &str) -> LinkIdentity {
        LinkIdentity {
            path: path.to_owned(),
            target: target.to_owned(),
        }
    }

    #[test]
    fn materializes_only_selected_files_with_source_modes_and_inventoried_links() {
        let fixture = Fixture::new();
        let binary = b"selected collector bytes\0";
        fixture.write_source("bin/aros-collect", binary, 0o751);
        fixture.write_source("bin/unused-helper", b"not selected", 0o755);
        fixture.write_source("share/readme", b"also not selected", 0o644);
        symlink("aros-collect", fixture.0.join("source/bin/collector")).unwrap();

        let files = [file("bin/aros-collect", binary)];
        let links = [link("bin/collector", "aros-collect")];
        let receipt = fixture
            .install("collector", &files, &links, limits(), || Ok(()))
            .unwrap();
        assert_eq!(receipt.measurement.files, 1);
        assert_eq!(receipt.measurement.symlinks, 1);
        assert_eq!(receipt.measurement.file_bytes, binary.len() as u64);

        let output = fixture.0.join("destinations/collector");
        assert_eq!(fs::read(output.join("bin/aros-collect")).unwrap(), binary);
        assert_eq!(
            fs::read_link(output.join("bin/collector")).unwrap(),
            std::path::Path::new("aros-collect")
        );
        assert_eq!(
            fs::metadata(output.join("bin/aros-collect"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o751
        );
        let names = fs::read_dir(output.join("bin"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            names,
            BTreeSet::from([OsString::from("aros-collect"), OsString::from("collector")])
        );
        assert!(!output.join("share").exists());
    }

    #[test]
    fn refuses_changed_sources_and_cleans_unpublished_stage() {
        let fixture = Fixture::new();
        fixture.write_source("bin/tool", b"original", 0o755);
        fs::write(fixture.0.join("source/bin/tool"), b"changed!").unwrap();
        let expected = [file("bin/tool", b"original")];
        let error = fixture
            .install("tool-root", &expected, &[], limits(), || Ok(()))
            .unwrap_err();
        assert!(error.to_string().contains("bytes differ from inventory"));
        assert!(error.recovery_entry.is_none());
        assert!(!fixture.0.join("destinations/tool-root").exists());
        assert_eq!(
            fs::read_dir(fixture.0.join("destinations"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn destination_collision_preserves_existing_tree_and_cleans_stage() {
        let fixture = Fixture::new();
        fixture.write_source("bin/tool", b"selected", 0o755);
        let existing = fixture.0.join("destinations/tool-root");
        fs::create_dir(&existing).unwrap();
        fs::write(existing.join("keep"), b"preexisting").unwrap();
        let expected = [file("bin/tool", b"selected")];
        let error = fixture
            .install("tool-root", &expected, &[], limits(), || Ok(()))
            .unwrap_err();
        assert!(error.recovery_entry.is_none());
        assert_eq!(fs::read(existing.join("keep")).unwrap(), b"preexisting");
        assert_eq!(
            fs::read_dir(fixture.0.join("destinations"))
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn cancellation_removes_private_stage_without_publishing() {
        let fixture = Fixture::new();
        fixture.write_source("bin/tool", b"selected", 0o755);
        let expected = [file("bin/tool", b"selected")];
        let error = fixture
            .install("tool-root", &expected, &[], limits(), || {
                Err(Refusal::new("cancelled fixture"))
            })
            .unwrap_err();
        assert!(error.to_string().contains("cancelled fixture"));
        assert!(error.recovery_entry.is_none());
        assert!(!fixture.0.join("destinations/tool-root").exists());
        assert_eq!(
            fs::read_dir(fixture.0.join("destinations"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn rejects_duplicate_unsafe_ancestor_and_case_colliding_paths_before_copy() {
        let fixture = Fixture::new();
        fixture.write_source("tool", b"one", 0o644);
        let duplicate = [file("tool", b"one"), file("tool", b"one")];
        assert!(
            fixture
                .install("duplicate", &duplicate, &[], limits(), || Ok(()))
                .is_err()
        );

        let traversal = [file("../tool", b"one")];
        assert!(
            fixture
                .install("traversal", &traversal, &[], limits(), || Ok(()))
                .is_err()
        );

        let ancestor = [file("tool", b"one"), file("tool/child", b"two")];
        assert!(
            fixture
                .install("ancestor", &ancestor, &[], limits(), || Ok(()))
                .is_err()
        );

        let case_alias = [file("Tool", b"one"), file("tool", b"one")];
        assert!(
            fixture
                .install("case-alias", &case_alias, &[], limits(), || Ok(()))
                .is_err()
        );
        assert!(
            fs::read_dir(fixture.0.join("destinations"))
                .unwrap()
                .count()
                == 0
        );
    }

    #[test]
    fn rejects_unsafe_or_unselected_symlink_targets_without_publication() {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.0.join("source/bin")).unwrap();
        fs::write(fixture.0.join("source/outside"), b"outside").unwrap();
        symlink("../../outside", fixture.0.join("source/bin/escape")).unwrap();
        let links = [link("bin/escape", "../../outside")];
        let error = fixture
            .install("selected", &[], &links, limits(), || Ok(()))
            .unwrap_err();
        assert!(error.recovery_entry.is_none());
        assert!(!fixture.0.join("destinations/selected").exists());
        assert_eq!(
            fs::read_dir(fixture.0.join("destinations"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn declared_mode_and_expansion_limits_are_enforced() {
        let fixture = Fixture::new();
        fixture.write_source("bin/tool", b"payload", 0o751);
        let mut wrong_mode = file("bin/tool", b"payload");
        wrong_mode.mode = Some(0o755);
        assert!(
            fixture
                .install("wrong-mode", &[wrong_mode], &[], limits(), || Ok(()))
                .is_err()
        );

        let mut over_limit = limits();
        over_limit.max_expanded_bytes = 6;
        assert!(
            fixture
                .install(
                    "over-limit",
                    &[file("bin/tool", b"payload")],
                    &[],
                    over_limit,
                    || Ok(())
                )
                .is_err()
        );
        assert_eq!(
            fs::read_dir(fixture.0.join("destinations"))
                .unwrap()
                .count(),
            0
        );
    }
}
