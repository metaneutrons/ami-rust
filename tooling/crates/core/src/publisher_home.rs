//! Private temporary home directories for pinned publisher-verifier tools.
//!
//! The home and `gh` configuration directory are created with exact `0700`
//! modes below a canonical system temporary directory. Cleanup is anchored to
//! a retained parent descriptor and bounded to 16,384 entries. The directory
//! is private against other UIDs; concurrent mutation by another process
//! running as the same UID is outside this helper's protection.

#[cfg(test)]
use crate::process_spawn::FixtureCommandExt;

use crate::{Refusal, Result, directory::Directory};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::{OsStr, OsString},
    fs,
    io::Write,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const CLEANUP_ENTRY_LIMIT: usize = 16_384;
const HOME_PREFIX: &str = ".ami-rust-publisher-home-";
const GH_DIRECTORY: &str = "gh";

/// A private HOME directory with a dedicated `gh` directory.
///
/// `finish` reports cleanup failure to the caller. If it is not called, or if
/// stack unwinding drops this value, `Drop` makes a best-effort bounded cleanup
/// attempt. A cleanup failure during `Drop` cannot be reported and may leave a
/// private directory behind; callers that need an error must call `finish`.
pub(crate) struct PublisherHome {
    parent: Directory,
    entry: OsString,
    path: PathBuf,
    // Retain the directory descriptor for the lifetime of HOME. Pathname
    // replacement by another process with the same UID remains out of scope.
    _root: Directory,
    cleaned: bool,
}

impl PublisherHome {
    /// Create a new private HOME and its private `gh` subdirectory.
    pub(crate) fn new() -> Result<Self> {
        let temp_path = fs::canonicalize(env::temp_dir()).map_err(|error| {
            Refusal::new(format!(
                "could not resolve the system temporary directory: {error}"
            ))
        })?;
        if !temp_path.is_absolute() {
            return Err(Refusal::new(
                "canonical system temporary directory must be absolute",
            ));
        }

        let parent = crate::ownership::protected_directory(&temp_path).map_err(|error| {
            Refusal::new(format!(
                "system temporary directory is not a real descriptor-openable directory: {error}"
            ))
        })?;
        validate_temp_parent(&parent)?;

        let entry = unique_entry_name()?;
        let path = temp_path.join(&entry);
        let mut home_created = false;
        let root = match parent.mkdir_new_tracked(&entry, 0o700, || home_created = true) {
            Ok(root) => root,
            Err(error) if home_created => {
                return Err(cleanup_partial(
                    &parent,
                    &entry,
                    &path,
                    "HOME creation",
                    error,
                ));
            }
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not create private publisher HOME at {}: {error}",
                    path.display()
                )));
            }
        };

        let mut gh_created = false;
        if let Err(error) = root.mkdir_new_tracked(OsStr::new(GH_DIRECTORY), 0o700, || {
            gh_created = true;
        }) {
            let detail = if gh_created {
                "gh directory was created before its descriptor or mode setup failed"
            } else {
                "gh directory creation failed before ownership was recorded"
            };
            return Err(cleanup_partial(&parent, &entry, &path, detail, error));
        }

        Ok(Self {
            parent,
            entry,
            path,
            _root: root,
            cleaned: false,
        })
    }

    /// Canonical absolute path to the private HOME directory.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Stage verified input bytes below the private HOME for path-based tools.
    /// Exact modes and exclusive descriptor-relative creation protect against
    /// other UIDs even when the source bundle permits other-user writes.
    pub(crate) fn stage_bundle(&self, files: &BTreeMap<String, Vec<u8>>) -> Result<PathBuf> {
        let root = self._root.mkdir_new(OsStr::new("bundle"), 0o700)?;
        let mut directories = BTreeSet::new();
        for (path, bytes) in files {
            crate::publisher_metadata::validate_bundle_relative_path(path)?;
            let mut parent = String::new();
            let components: Vec<_> = path.split('/').collect();
            for component in &components[..components.len() - 1] {
                let base = root.relative_directory(&parent)?;
                if !parent.is_empty() {
                    parent.push('/');
                }
                parent.push_str(component);
                if directories.insert(parent.clone()) {
                    base.mkdir_new(OsStr::new(component), 0o700)?;
                }
            }
            let (parent, leaf) = path.rsplit_once('/').unwrap_or(("", path));
            let mut file = root
                .relative_directory(parent)?
                .create_new_file(OsStr::new(leaf), 0o600)?;
            file.write_all(bytes).map_err(|error| {
                Refusal::new(format!("could not stage publisher bytes: {error}"))
            })?;
        }
        Ok(self.path.join("bundle"))
    }

    /// Remove the temporary tree and report any bounded-cleanup failure.
    pub(crate) fn finish(mut self) -> Result<()> {
        match self.parent.remove_tree(&self.entry, CLEANUP_ENTRY_LIMIT) {
            Ok(()) => {
                self.cleaned = true;
                Ok(())
            }
            Err(error) => Err(Refusal::new(format!(
                "could not clean private publisher HOME at {}: {error}",
                self.path.display()
            ))),
        }
    }
}

impl Drop for PublisherHome {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.parent.remove_tree(&self.entry, CLEANUP_ENTRY_LIMIT);
        }
    }
}

fn validate_temp_parent(parent: &Directory) -> Result<()> {
    let metadata = parent
        .metadata()
        .map_err(|error| Refusal::new(format!("could not inspect temporary parent: {error}")))?;
    if !metadata.is_dir() {
        return Err(Refusal::new(
            "canonical system temporary path is not a directory",
        ));
    }

    let mode = metadata.mode() & 0o7777;
    let uid = metadata.uid();
    let current_uid = current_uid();
    if uid == current_uid && mode & 0o022 == 0 {
        return Ok(());
    }
    // Standard shared system temporary directories such as /tmp are safe for
    // exclusive random names when root-owned and sticky: other UIDs cannot
    // unlink an entry owned by this process. The actual HOME is mode 0700.
    if uid == 0 && mode & 0o1000 != 0 {
        return Ok(());
    }
    Err(Refusal::new(
        "system temporary parent must be private to this user or root-owned and sticky",
    ))
}

fn cleanup_partial(
    parent: &Directory,
    entry: &OsStr,
    path: &Path,
    phase: &str,
    cause: Refusal,
) -> Refusal {
    match parent.remove_tree(entry, CLEANUP_ENTRY_LIMIT) {
        Ok(()) => Refusal::new(format!("{phase} failed: {cause}")),
        Err(cleanup) => Refusal::new(format!(
            "{phase} failed: {cause}; private HOME retained at {} because cleanup failed: {cleanup}",
            path.display()
        )),
    }
}

fn unique_entry_name() -> Result<OsString> {
    let mut name = OsString::from(HOME_PREFIX);
    for byte in random_bytes()? {
        name.push(format!("{byte:02x}"));
    }
    Ok(name)
}

#[allow(unsafe_code)]
fn random_bytes() -> Result<[u8; 12]> {
    let mut bytes = [0_u8; 12];
    // SAFETY: getentropy receives a writable 12-byte buffer, below its
    // documented 256-byte maximum on both supported hosts.
    if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
        return Err(Refusal::new(format!(
            "could not generate private publisher HOME name: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(bytes)
}

#[allow(unsafe_code)]
fn current_uid() -> u32 {
    // SAFETY: getuid has no pointer arguments and returns this process's real UID.
    unsafe { libc::getuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        ffi::CString,
        fs,
        os::unix::{ffi::OsStrExt, fs::PermissionsExt},
        process::Command,
    };

    fn permission_mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn creates_private_home_and_gh_subdirectory_then_finishes() {
        let home = PublisherHome::new().unwrap();
        let path = home.path().to_owned();
        assert!(path.is_absolute());
        assert_eq!(permission_mode(&path), 0o700);
        assert_eq!(permission_mode(&path.join(GH_DIRECTORY)), 0o700);
        home.finish().unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn drop_makes_a_best_effort_cleanup() {
        let home = PublisherHome::new().unwrap();
        let path = home.path().to_owned();
        drop(home);
        assert!(!path.exists());
    }

    #[test]
    fn stages_exact_private_bytes_without_aliasing_the_source() {
        let home = PublisherHome::new().unwrap();
        let files = BTreeMap::from([
            ("release.json".to_owned(), b"original".to_vec()),
            (".auth/gh/CON.json".to_owned(), b"{}".to_vec()),
        ]);
        let staged = home.stage_bundle(&files).unwrap();
        assert_eq!(permission_mode(&staged), 0o700);
        assert_eq!(permission_mode(&staged.join(".auth/gh")), 0o700);
        assert_eq!(permission_mode(&staged.join("release.json")), 0o600);
        assert_eq!(fs::read(staged.join("release.json")).unwrap(), b"original");
        fs::write(staged.join("release.json"), b"changed").unwrap();
        assert_eq!(files["release.json"], b"original");
        assert!(home.stage_bundle(&files).is_err());
        home.finish().unwrap();

        let home = PublisherHome::new().unwrap();
        assert!(
            home.stage_bundle(&BTreeMap::from([("../escape".to_owned(), vec![])]))
                .is_err()
        );
        home.finish().unwrap();
    }

    #[test]
    #[allow(unsafe_code)]
    fn finish_reports_bounded_cleanup_error_and_names_retained_home() {
        let home = PublisherHome::new().unwrap();
        let path = home.path().to_owned();
        let special_path = path.join(GH_DIRECTORY).join("cleanup-blocker.fifo");
        let c_path = CString::new(special_path.as_os_str().as_bytes()).unwrap();
        // SAFETY: the owned fixture path is a live NUL-terminated string. A
        // FIFO supplies a special-file countercontrol without socket path limits.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);

        let error = home.finish().unwrap_err();
        assert!(error.to_string().contains(&path.display().to_string()));
        assert!(path.exists());

        fs::remove_file(&special_path).unwrap();
        let parent = Directory::open(path.parent().unwrap()).unwrap();
        parent
            .remove_tree(path.file_name().unwrap(), CLEANUP_ENTRY_LIMIT)
            .unwrap();
        assert!(!path.exists());
    }

    #[test]
    #[allow(unsafe_code)]
    fn exact_home_modes_survive_restrictive_umask_in_isolated_child() {
        const CHILD_MARKER: &str = "AMI_RUST_PUBLISHER_HOME_UMASK_CHILD";
        if env::var_os(CHILD_MARKER).as_deref() == Some(OsStr::new("1")) {
            // SAFETY: this branch runs only in a dedicated child test process,
            // so changing its process-global umask cannot affect other tests.
            unsafe {
                libc::umask(0o777);
            }
            let home = PublisherHome::new().unwrap();
            let path = home.path().to_owned();
            assert_eq!(permission_mode(&path), 0o700);
            assert_eq!(permission_mode(&path.join(GH_DIRECTORY)), 0o700);
            home.finish().unwrap();
            assert!(!path.exists());
            return;
        }

        let executable = std::env::current_exe().unwrap();
        let output = Command::new(executable)
            .args([
                "--exact",
                "publisher_home::tests::exact_home_modes_survive_restrictive_umask_in_isolated_child",
            ])
            .env(CHILD_MARKER, "1")
            .env_remove("CARGO_REGISTRY_TOKEN")
            .output_guarded()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated umask test failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
