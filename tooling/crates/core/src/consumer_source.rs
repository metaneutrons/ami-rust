//! Exact package-pinned source checkout using native Git and isolated config.
//! Source Python files are inert data; no source helper is imported or run.
use crate::{
    Refusal, Result, consumer_session::ConsumerSession, directory::Directory,
    package_records::NativePackagePins,
};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    time::Duration,
};

#[cfg(target_os = "macos")]
use crate::{digest::encode_hex, ownership};
#[cfg(target_os = "macos")]
use std::{
    ffi::OsStr,
    io::{Read, Write},
    os::unix::fs::MetadataExt,
};

#[cfg(target_os = "macos")]
const XCODE_SELECT: &str = "/usr/bin/xcode-select";

pub fn checkout_package_source(
    session: &mut ConsumerSession<'_>,
    pins: &NativePackagePins,
) -> Result<PathBuf> {
    if pins.repository != "metaneutrons/ami-rust"
        || !git_identity(&pins.source_commit)
        || !git_identity(&pins.source_tree)
    {
        return Err(Refusal::new("invalid pinned consumer source identity"));
    }
    session.recheck_root()?;
    let source = session.path().join("source");
    match std::fs::symlink_metadata(&source) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => return Err(Refusal::new("consumer source checkout must be fresh")),
    }
    let git = SourceGit::select(session)?;
    let init = vec![
        "-c".into(),
        "init.defaultBranch=main".into(),
        "-c".into(),
        "core.hooksPath=/dev/null".into(),
        "init".into(),
        "--template=".into(),
        source.clone().into_os_string(),
    ];
    git.run(session, "source-init", init, Duration::from_secs(30))?;
    let mut fetch = git_args(&source);
    fetch.extend([
        "fetch".into(),
        "--depth=1".into(),
        "--no-tags".into(),
        "https://github.com/metaneutrons/ami-rust.git".into(),
        pins.source_commit.clone().into(),
    ]);
    git.run(session, "source-fetch", fetch, Duration::from_secs(300))?;
    let mut checkout = git_args(&source);
    checkout.extend([
        "checkout".into(),
        "--detach".into(),
        pins.source_commit.clone().into(),
    ]);
    git.run(
        session,
        "source-checkout",
        checkout,
        Duration::from_secs(60),
    )?;
    for (expression, expected, label) in [
        ("HEAD", pins.source_commit.as_str(), "source-commit"),
        ("HEAD^{tree}", pins.source_tree.as_str(), "source-tree"),
    ] {
        let mut args = git_args(&source);
        args.extend(["rev-parse".into(), "--verify".into(), expression.into()]);
        let actual = git.run(session, label, args, Duration::from_secs(30))?;
        if actual.stdout != format!("{expected}\n").as_bytes() {
            return Err(Refusal::new(
                "consumer source differs from package-pinned Git identity",
            ));
        }
    }
    Directory::open(&source)?;
    session.recheck_root()?;
    Ok(source)
}

struct SourceGit {
    #[cfg(not(target_os = "macos"))]
    path: PathBuf,
    #[cfg(target_os = "macos")]
    selected: SelectedMacosGit,
}

impl SourceGit {
    fn select(session: &mut ConsumerSession<'_>) -> Result<Self> {
        #[cfg(target_os = "macos")]
        {
            let selected = SelectedMacosGit::select(session)?;
            write_selected_git_report(session, &selected)?;
            Ok(Self { selected })
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = session;
            Ok(Self {
                path: PathBuf::from("/usr/bin/git"),
            })
        }
    }

    fn run(
        &self,
        session: &mut ConsumerSession<'_>,
        label: &str,
        args: Vec<OsString>,
        timeout: Duration,
    ) -> Result<crate::consumer_session::ConsumerOutput> {
        #[cfg(target_os = "macos")]
        {
            self.selected.recheck(session)?;
            let command = session.run_selected_macos_git(label, &self.selected, args, timeout);
            let identity = self.selected.recheck(session);
            match (command, identity) {
                (Ok(output), Ok(())) => Ok(output),
                (Err(error), Ok(())) => Err(error),
                (_, Err(error)) => Err(error),
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            session.run(label, &self.path, args, timeout)
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ProtectedExecutableIdentity {
    path: PathBuf,
    sha256: String,
    bytes: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    device: u64,
    inode: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(target_os = "macos")]
pub(crate) struct SelectedMacosGit {
    selection: crate::macos_host_selection::HostSelection,
    selector: ProtectedExecutableIdentity,
    git: ProtectedExecutableIdentity,
    git_directories: Vec<GitDirectoryIdentity>,
}

#[cfg(target_os = "macos")]
impl SelectedMacosGit {
    fn select(session: &mut ConsumerSession<'_>) -> Result<Self> {
        let selector = protected_executable_identity(Path::new(XCODE_SELECT))?;
        let selected_developer = selected_developer_directory(session, "source-git-select")?;
        if protected_executable_identity(Path::new(XCODE_SELECT))? != selector {
            return Err(Refusal::new(
                "macOS selector changed while selecting consumer Git",
            ));
        }
        let selection = crate::macos_host_selection::resolve_selected(&selected_developer)
            .map_err(|error| Refusal::new(format!("macOS host-tool selection failed: {error}")))?;
        let requested_git = selection
            .developer_directory
            .canonical_path
            .join("usr/bin/git");
        let canonical_git = std::fs::canonicalize(&requested_git).map_err(|error| {
            Refusal::new(format!(
                "selected macOS developer Git is unavailable: {error}"
            ))
        })?;
        if canonical_git != requested_git {
            return Err(Refusal::new(
                "selected macOS developer Git must be the canonical usr/bin/git file",
            ));
        }
        let git = protected_executable_identity(&canonical_git)?;
        let git_directories =
            git_directory_identities(&selection.installation_root.canonical_path, &canonical_git)?;
        let selected = Self {
            selection,
            selector,
            git,
            git_directories,
        };
        session.recheck_root()?;
        Ok(selected)
    }

    fn recheck(&self, session: &mut ConsumerSession<'_>) -> Result<()> {
        session.recheck_root()?;
        if protected_executable_identity(Path::new(XCODE_SELECT))? != self.selector {
            return Err(Refusal::new(
                "macOS selector identity changed during consumer source checkout",
            ));
        }
        let selected_developer = selected_developer_directory(session, "source-git-recheck")?;
        if selected_developer != self.selection.developer_directory.requested_path
            || protected_executable_identity(Path::new(XCODE_SELECT))? != self.selector
        {
            return Err(Refusal::new(
                "selected macOS developer directory or selector changed during consumer source checkout",
            ));
        }
        self.checked_program()?;
        session.recheck_root()
    }

    /// Only this privately constructed selection can authorize the special
    /// installation-root ancestor policy in ConsumerSession.
    pub(crate) fn checked_program(&self) -> Result<&Path> {
        self.selection
            .recheck()
            .map_err(|error| Refusal::new(format!("macOS host-tool recheck failed: {error}")))?;
        if protected_executable_identity(Path::new(XCODE_SELECT))? != self.selector
            || protected_executable_identity(&self.git.path)? != self.git
            || git_directory_identities(
                &self.selection.installation_root.canonical_path,
                &self.git.path,
            )? != self.git_directories
        {
            return Err(Refusal::new(
                "selected macOS developer Git identity changed during consumer source checkout",
            ));
        }
        Ok(&self.git.path)
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Eq, PartialEq)]
struct GitDirectoryIdentity {
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

#[cfg(target_os = "macos")]
fn git_directory_identities(installation: &Path, git: &Path) -> Result<Vec<GitDirectoryIdentity>> {
    let parent = git
        .parent()
        .ok_or_else(|| Refusal::new("selected Git has no parent"))?;
    let relative = parent
        .strip_prefix(installation)
        .map_err(|_| Refusal::new("selected Git escapes the developer installation"))?;
    let mut path = installation.to_path_buf();
    let mut paths = vec![path.clone()];
    for component in relative.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err(Refusal::new("selected Git parent has invalid components"));
        }
        path.push(component);
        paths.push(path.clone());
    }
    paths
        .into_iter()
        .map(|path| {
            let directory = Directory::open(&path)?;
            let metadata = directory.metadata()?;
            if ![0, ownership::current_uid()].contains(&metadata.uid())
                || metadata.mode() & 0o022 != 0
            {
                return Err(Refusal::new(
                    "selected Git directory has unsafe owner or mode",
                ));
            }
            Ok(GitDirectoryIdentity {
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
                uid: metadata.uid(),
                gid: metadata.gid(),
                mode: metadata.mode() & 0o7777,
            })
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn selected_developer_directory(session: &mut ConsumerSession<'_>, label: &str) -> Result<PathBuf> {
    let output = session.run(
        label,
        Path::new(XCODE_SELECT),
        vec![OsString::from("-p")],
        Duration::from_secs(30),
    )?;
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| Refusal::new("macOS selector output is not UTF-8"))?;
    let path = text.strip_suffix('\n').unwrap_or(text);
    if path.is_empty() || path.contains(['\n', '\r', '\0']) || !Path::new(path).is_absolute() {
        return Err(Refusal::new(
            "macOS selector did not return one absolute developer directory",
        ));
    }
    Ok(PathBuf::from(path))
}

#[cfg(target_os = "macos")]
fn protected_executable_identity(path: &Path) -> Result<ProtectedExecutableIdentity> {
    use sha2::{Digest, Sha256};

    if !path.is_absolute() || std::fs::canonicalize(path)? != path {
        return Err(Refusal::new(
            "selected macOS executable path must be canonical",
        ));
    }
    // The selector is an OS path; Git's parent chain is guarded from the
    // selected installation root by git_directory_identities. Do not apply the external
    // publisher-input ancestor policy to /Applications, which macOS may make
    // admin-group writable even when Xcode and its tools are protected.
    let mut file = crate::files::open_regular_nofollow(path)?;
    let before = file.metadata()?;
    if (before.uid() != 0 && before.uid() != ownership::current_uid())
        || before.mode() & 0o022 != 0
        || before.mode() & 0o6000 != 0
        || before.mode() & 0o111 == 0
    {
        return Err(Refusal::new(
            "selected macOS executable has unsafe owner or mode",
        ));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => digest.update(&buffer[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not hash selected macOS executable: {error}"
                )));
            }
        }
    }
    let after = file.metadata()?;
    if !same_executable_state(&before, &after) {
        return Err(Refusal::new(
            "selected macOS executable changed while its identity was read",
        ));
    }
    let digest: [u8; 32] = digest.finalize().into();
    Ok(ProtectedExecutableIdentity {
        path: path.to_path_buf(),
        sha256: encode_hex(&digest),
        bytes: after.len(),
        uid: after.uid(),
        gid: after.gid(),
        mode: after.mode() & 0o7777,
        device: after.dev(),
        inode: after.ino(),
        modified_seconds: after.mtime(),
        modified_nanoseconds: after.mtime_nsec(),
        changed_seconds: after.ctime(),
        changed_nanoseconds: after.ctime_nsec(),
    })
}

#[cfg(target_os = "macos")]
fn same_executable_state(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.mode() == after.mode()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(target_os = "macos")]
fn write_selected_git_report(
    session: &ConsumerSession<'_>,
    selected: &SelectedMacosGit,
) -> Result<()> {
    let report = serde_json::json!({
        "schema": "ami-rust-consumer-selected-os-git-v1",
        "selector": executable_report(&selected.selector)?,
        "developer_directory": {
            "requested_path": selected.selection.developer_directory.requested_path.to_str()
                .ok_or_else(|| Refusal::new("selected developer path is not UTF-8"))?,
            "canonical_path": selected.selection.developer_directory.canonical_path.to_str()
                .ok_or_else(|| Refusal::new("canonical developer path is not UTF-8"))?,
            "layout": selected.selection.layout.as_str(),
        },
        "git": executable_report(&selected.git)?,
        "scope": "package-pinned consumer source checkout",
    });
    let root = Directory::open(session.path())?;
    let mut file = root.create_new_file(OsStr::new("source-git-identity.json"), 0o600)?;
    file.write_all(&serde_json::to_vec_pretty(&report).map_err(|error| {
        Refusal::new(format!(
            "could not serialize selected Git identity: {error}"
        ))
    })?)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn executable_report(identity: &ProtectedExecutableIdentity) -> Result<serde_json::Value> {
    Ok(serde_json::json!({
        "canonical_path": identity.path.to_str()
            .ok_or_else(|| Refusal::new("selected executable path is not UTF-8"))?,
        "sha256": identity.sha256,
        "bytes": identity.bytes,
        "uid": identity.uid,
        "gid": identity.gid,
        "mode": identity.mode,
        "device": identity.device,
        "inode": identity.inode,
        "modified_seconds": identity.modified_seconds,
        "modified_nanoseconds": identity.modified_nanoseconds,
        "changed_seconds": identity.changed_seconds,
        "changed_nanoseconds": identity.changed_nanoseconds,
    }))
}

fn git_identity(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn git_args(source: &Path) -> Vec<OsString> {
    vec![
        "-C".into(),
        source.as_os_str().into(),
        "-c".into(),
        "core.hooksPath=/dev/null".into(),
        "-c".into(),
        "core.fsmonitor=false".into(),
        "-c".into(),
        "submodule.recurse=false".into(),
        "-c".into(),
        "protocol.file.allow=never".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    fn private_test_root(label: &str) -> PathBuf {
        use std::os::unix::fs::DirBuilderExt;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("ami-rust-{label}-{}-{nonce}", std::process::id()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        std::fs::canonicalize(path).unwrap()
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn selected_git_runs_in_an_isolated_native_session() {
        use crate::process_capture::{CaptureLimits, CommandSpec, capture};
        let current = std::env::current_exe().unwrap();
        let command = CommandSpec::new(
            current.as_os_str(),
            [
                "--exact",
                "consumer_source::tests::actual_selected_git_session_probe",
                "--ignored",
                "--nocapture",
            ]
            .map(OsString::from),
            std::env::current_dir().unwrap(),
            ["HOME", "TMPDIR", "PATH"]
                .into_iter()
                .filter_map(|name| std::env::var_os(name).map(|value| (name.into(), value)))
                .collect(),
        );
        let output = capture(
            &command,
            CaptureLimits {
                timeout: Duration::from_secs(120),
                stdout_bytes: 1024 * 1024,
                stderr_bytes: 1024 * 1024,
                termination_grace: Duration::from_secs(2),
            },
            || false,
        )
        .unwrap();
        assert_eq!(
            output.exit_code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("ACTUAL_SELECTED_GIT_SESSION_PASS")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "isolated by selected_git_runs_in_an_isolated_native_session"]
    fn actual_selected_git_session_probe() {
        let root = private_test_root("selected-git");
        let signals = crate::signals::SigtermGuard::acquire().unwrap();
        let mut session = ConsumerSession::new(&root, &signals).unwrap();
        let git = SourceGit::select(&mut session).unwrap();
        assert_ne!(git.selected.git.path, Path::new("/usr/bin/git"));
        assert_eq!(
            git.selected.git.path,
            git.selected
                .selection
                .developer_directory
                .canonical_path
                .join("usr/bin/git")
        );
        let output = git
            .run(
                &mut session,
                "actual-git-version",
                vec!["--version".into()],
                Duration::from_secs(30),
            )
            .unwrap();
        assert!(output.stdout.starts_with(b"git version "));
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("source-git-identity.json")).unwrap())
                .unwrap();
        assert_eq!(report["git"]["sha256"], git.selected.git.sha256);
        assert_eq!(
            report["git"]["canonical_path"],
            git.selected.git.path.to_str().unwrap()
        );
        drop(session);
        signals.finish().unwrap();
        std::fs::remove_dir_all(root).unwrap();
        println!("ACTUAL_SELECTED_GIT_SESSION_PASS");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn selected_executable_identity_detects_changes_and_refuses_writable_inputs() {
        use std::os::unix::fs::PermissionsExt;
        let root = private_test_root("git-identity");
        let path = root.join("tool");
        std::fs::copy("/usr/bin/true", &path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let first = protected_executable_identity(&path).unwrap();
        std::fs::write(&path, b"isolated changed identity fixture; never executed").unwrap();
        assert_ne!(first, protected_executable_identity(&path).unwrap());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o722)).unwrap();
        assert!(protected_executable_identity(&path).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn git_parent_chain_rejects_writable_and_symlink_directories() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = private_test_root("git-directories");
        let bin = root.join("usr/bin");
        std::fs::create_dir_all(&bin).unwrap();
        let git = bin.join("git");
        let identities = git_directory_identities(&root, &git).unwrap();
        assert_eq!(identities.len(), 3);
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(git_directory_identities(&root, &git).is_err());
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(&bin, root.join("real-bin")).unwrap();
        symlink(root.join("real-bin"), &bin).unwrap();
        assert!(git_directory_identities(&root, &git).is_err());
        assert!(git_directory_identities(&root, Path::new("/usr/bin/git")).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exact_git_identity_and_disabled_optional_execution_are_explicit() {
        assert!(git_identity(&"a".repeat(40)));
        assert!(!git_identity("main"));
        assert!(!git_identity(&"a".repeat(39)));
        assert!(!git_identity(&"A".repeat(40)));
        let args = git_args(Path::new("/tmp/source with spaces"));
        assert!(args.contains(&OsString::from("core.hooksPath=/dev/null")));
        assert!(args.contains(&OsString::from("core.fsmonitor=false")));
        assert!(args.contains(&OsString::from("submodule.recurse=false")));
    }
}
