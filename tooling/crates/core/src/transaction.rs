//! Filesystem publication for already-authenticated installation inputs.
//!
//! This layer enforces path ownership, exclusive creation, complete staged
//! inventories and pre/post-publication failure semantics. It does not parse or
//! authenticate release policy, signatures or receipt semantics. The consumer
//! must do that before calling it; it is not a public CLI capability by itself.

use crate::{
    Refusal, Result,
    digest::sha256_bytes,
    directory::Directory,
    files::validate_relative_inventory_path,
    inventory::{FileIdentity, InventoryLimits, verify_complete_directory},
    ownership::{self, FreshTarget},
    signals::SigtermGuard,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

const RECEIPT: &str = "install-receipt.json";
const MAX_RECEIPT: usize = 4 * 1024 * 1024;
const MAX_INSTALLED_BYTES: usize = 64 * 1024 * 1024;
const MAX_FILES: usize = 2002;

/// One immutable, previously authenticated file to place below sdk/ or payload/.
/// SDK archive modes must already be normalized to 0755 or 0644 by its parser.
pub struct InstallFile<'a> {
    pub path: &'a str,
    pub contents: &'a [u8],
    pub mode: u32,
}

#[derive(Debug)]
pub struct PublishedInstall {
    pub prefix: PathBuf,
    pub receipt_sha256: String,
    pub receipt_pin: Option<PathBuf>,
}

/// A post-publication failure retains the installation. A pre-publication
/// cleanup failure names the retained owned staging tree for recovery.
#[derive(Debug)]
pub struct InstallFailure {
    pub reason: Refusal,
    pub published: Option<PublishedInstall>,
    pub recovery: Option<Box<RecoveryLocation>>,
}

/// Recovery names are descriptor-relative. If the parent pathname was moved,
/// no valid current path is asserted; the last-known parent and inode identity
/// let the caller explain that the owned tree is under a detached parent.
#[derive(Debug)]
pub struct RecoveryLocation {
    pub entry_name: OsString,
    pub last_known_parent: PathBuf,
    pub parent_identity: Option<(u64, u64)>,
    pub verified_path: Option<PathBuf>,
}

impl RecoveryLocation {
    fn observe(parent: &Directory, last_known_parent: &Path, entry: &OsStr) -> Self {
        let retained = parent.metadata().ok();
        let parent_identity = retained
            .as_ref()
            .map(|metadata| (metadata.dev(), metadata.ino()));
        let verified_path = if recheck_directory_identity(parent, last_known_parent).is_ok() {
            Some(last_known_parent.join(entry))
        } else {
            None
        };
        Self {
            entry_name: entry.to_os_string(),
            last_known_parent: last_known_parent.to_owned(),
            parent_identity,
            verified_path,
        }
    }
}

impl InstallFailure {
    pub fn exit_code(&self) -> i32 {
        if self.published.is_some() { 1 } else { 2 }
    }
}

impl From<Refusal> for InstallFailure {
    fn from(reason: Refusal) -> Self {
        Self {
            reason,
            published: None,
            recovery: None,
        }
    }
}

struct Layout {
    directories: BTreeSet<String>,
    files: Vec<FileIdentity>,
    cleanup_entries: usize,
}

impl Layout {
    fn inspect(files: &[InstallFile<'_>], receipt: &[u8]) -> Result<Self> {
        if files.len() > MAX_FILES || receipt.len() > MAX_RECEIPT {
            return Err(Refusal::new(
                "installation exceeds the frozen file/receipt profile",
            ));
        }
        let mut paths = BTreeSet::new();
        let mut folded = BTreeMap::new();
        let mut directories = BTreeSet::from(["sdk".to_owned(), "payload".to_owned()]);
        let mut identities = Vec::new();
        let mut total = receipt.len();
        for file in files {
            crate::publisher_tar::validate_portable_path(file.path.as_bytes())?;
            for (offset, _) in file
                .path
                .match_indices('/')
                .chain(std::iter::once((file.path.len(), "/")))
            {
                let path = &file.path[..offset];
                if folded
                    .insert(path.to_ascii_lowercase(), path)
                    .is_some_and(|previous| previous != path)
                {
                    return Err(Refusal::new("case-colliding installed paths"));
                }
            }
            if !(file.path.starts_with("sdk/") || file.path.starts_with("payload/"))
                || !matches!(file.mode, 0o644 | 0o755)
                || (file.path.starts_with("payload/") && file.mode != 0o644)
            {
                return Err(Refusal::new(
                    "invalid installed file namespace or normalized mode",
                ));
            }
            if !paths.insert(file.path) {
                return Err(Refusal::new("duplicate installed file"));
            }
            total = total
                .checked_add(file.contents.len())
                .filter(|total| *total <= MAX_INSTALLED_BYTES)
                .ok_or_else(|| Refusal::new("installation exceeds the frozen byte profile"))?;
            for (offset, _) in file.path.match_indices('/') {
                directories.insert(file.path[..offset].to_owned());
            }
            identities.push(FileIdentity {
                path: file.path.to_owned(),
                bytes: file.contents.len() as u64,
                sha256: sha256_bytes(file.contents),
                mode: Some(file.mode),
            });
        }
        if paths.iter().any(|path| directories.contains(*path)) {
            return Err(Refusal::new(
                "installed file conflicts with a directory ancestor",
            ));
        }
        identities.push(FileIdentity {
            path: RECEIPT.into(),
            bytes: receipt.len() as u64,
            sha256: sha256_bytes(receipt),
            mode: Some(0o600),
        });
        // The bound derives from this exact layout, including its root. It is
        // a host cleanup work bound, not an AROS executable/allocation quota.
        let cleanup_entries = directories
            .len()
            .checked_add(identities.len())
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| Refusal::new("installation entry count overflow"))?;
        Ok(Self {
            directories,
            files: identities,
            cleanup_entries,
        })
    }
}

/// Publish immutable authenticated bytes and an optional external receipt pin.
/// Receipt semantic/authentication binding is deliberately an upstream step.
pub fn publish_install(
    prefix: &Path,
    bundle: &Path,
    receipt_pin: Option<&Path>,
    files: &[InstallFile<'_>],
    receipt: &[u8],
) -> std::result::Result<PublishedInstall, InstallFailure> {
    publish_with_hook(prefix, bundle, receipt_pin, files, receipt, |_, _| Ok(()))
}

#[derive(Clone, Copy)]
enum Boundary {
    Staged,
    Written,
    BeforePublish,
    Published,
    Pinned,
}

fn publish_with_hook(
    prefix: &Path,
    bundle: &Path,
    receipt_pin: Option<&Path>,
    files: &[InstallFile<'_>],
    receipt: &[u8],
    mut hook: impl FnMut(Boundary, &Path) -> Result<()>,
) -> std::result::Result<PublishedInstall, InstallFailure> {
    let layout = Layout::inspect(files, receipt)?;
    let target = ownership::install_target(prefix)?;
    ownership::require_disjoint(
        prefix,
        bundle,
        "installation prefix must be outside the release bundle",
    )?;
    Directory::open(bundle)?;
    let pin = receipt_pin
        .map(|pin| ownership::receipt_pin(pin, prefix, bundle))
        .transpose()?;
    let mut stage = Stage::new(target, layout.cleanup_entries)?;
    let signals = SigtermGuard::acquire()?;
    let mut pin_published = false;
    let result = (|| -> Result<()> {
        signals.check()?;
        stage.create(&signals)?;
        hook(Boundary::Staged, &stage.path())?;
        signals.check()?;
        let root = stage
            .directory
            .as_ref()
            .expect("created staging descriptor");
        for path in &layout.directories {
            signals.check()?;
            let (parent, name) = split_relative(path);
            root.relative_directory(parent)?
                .mkdir_new(OsStr::new(name), 0o755)?;
        }
        for file in files {
            signals.check()?;
            write_tree_file(root, file.path, file.contents, file.mode)?;
        }
        write_tree_file(root, RECEIPT, receipt, 0o600)?;
        hook(Boundary::Written, &stage.path())?;
        signals.check()?;
        verify_exact_tree(root, &layout.files, &layout.directories)?;
        for path in layout.directories.iter().rev() {
            signals.check()?;
            root.relative_directory(path)?.sync_best_effort();
        }
        root.sync_best_effort();
        hook(Boundary::BeforePublish, &stage.path())?;
        signals.check()?;
        recheck_parent(&stage.target)?;
        signals.with_blocked(|| {
            stage.target.parent().rename_no_replace(
                &stage.name,
                stage.target.parent(),
                stage.target.name(),
            )?;
            // Set this before restoring the mask, including restoration errors.
            stage.published = true;
            Ok(())
        })?;
        stage.target.parent().sync_best_effort();
        hook(Boundary::Published, stage.target.path())?;
        signals.check()?;
        if let Some(pin) = &pin {
            write_pin(pin, &sha256_bytes(receipt), &signals, &mut pin_published)?;
        }
        hook(Boundary::Pinned, stage.target.path())?;
        signals.check()
    })();
    // Always restore before returning; a restoration error after publication
    // is a partial-result failure, never a reason to remove the SDK.
    let result = match (result, signals.finish()) {
        (Err(first), Err(restore)) => Err(Refusal::new(format!("{first}; {restore}"))),
        (Err(error), _) | (_, Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    };
    let published = || PublishedInstall {
        prefix: stage.target.path().to_owned(),
        receipt_sha256: sha256_bytes(receipt),
        receipt_pin: if pin_published {
            pin.as_ref().map(|pin| pin.path().to_owned())
        } else {
            None
        },
    };
    match result {
        Ok(()) => Ok(published()),
        Err(reason) if stage.published => Err(InstallFailure {
            reason,
            published: Some(published()),
            recovery: None,
        }),
        Err(reason) => {
            let recovery = stage
                .abort()
                .err()
                .map(|cleanup| (Box::new(stage.recovery()), cleanup));
            let (reason, recovery) = match recovery {
                Some((path, cleanup)) => (
                    Refusal::new(format!("{reason}; staging cleanup failed: {cleanup}")),
                    Some(path),
                ),
                None => (reason, None),
            };
            Err(InstallFailure {
                reason,
                published: None,
                recovery,
            })
        }
    }
}

struct Stage {
    target: FreshTarget,
    name: OsString,
    directory: Option<Directory>,
    owned: bool,
    published: bool,
    cleanup_entries: usize,
}

impl Stage {
    fn new(target: FreshTarget, cleanup_entries: usize) -> Result<Self> {
        let name = hidden_name(target.name(), ".stage-")?;
        Ok(Self {
            target,
            name,
            directory: None,
            owned: false,
            published: false,
            cleanup_entries,
        })
    }

    fn path(&self) -> PathBuf {
        self.target
            .path()
            .parent()
            .expect("validated target parent")
            .join(&self.name)
    }

    fn create(&mut self, signals: &SigtermGuard) -> Result<()> {
        signals.with_blocked(|| {
            self.target
                .parent()
                .create_directory_entry(&self.name, 0o700)?;
            self.owned = true;
            Ok(())
        })?;
        signals.check()?;
        self.target
            .parent()
            .set_entry_mode_exact_nofollow(&self.name, 0o700)?;
        self.directory = Some(self.target.parent().child(&self.name)?);
        Ok(())
    }

    fn abort(&mut self) -> Result<()> {
        if !self.owned || self.published {
            return Ok(());
        }
        // An explicit cleanup attempt owns reporting. Do not retry it in Drop
        // and silently change the recovery tree after reporting its location.
        self.owned = false;
        self.target
            .parent()
            .remove_tree(&self.name, self.cleanup_entries)
    }

    fn recovery(&self) -> RecoveryLocation {
        RecoveryLocation::observe(
            self.target.parent(),
            self.target.path().parent().expect("validated parent"),
            &self.name,
        )
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        let _ = self.abort();
    }
}

fn split_relative(path: &str) -> (&str, &str) {
    path.rsplit_once('/').unwrap_or(("", path))
}

fn write_tree_file(root: &Directory, path: &str, bytes: &[u8], mode: u32) -> Result<()> {
    validate_relative_inventory_path(path)?;
    let (parent, name) = split_relative(path);
    let parent = root.relative_directory(parent)?;
    let mut file = parent.create_new_file(OsStr::new(name), mode)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn recheck_parent(target: &FreshTarget) -> Result<()> {
    let path = target.path().parent().expect("validated target parent");
    recheck_directory_identity(target.parent(), path)
}

fn verify_exact_tree(
    root: &Directory,
    files: &[FileIdentity],
    directories: &BTreeSet<String>,
) -> Result<()> {
    let measurement = verify_complete_directory(
        root,
        files,
        &[],
        InventoryLimits {
            max_tree_entries: files.len() + directories.len(),
            max_link_resolution_steps: 0,
        },
    )?;
    if measurement.directories != directories.len() {
        return Err(Refusal::new(
            "installation directory set differs from its exact layout",
        ));
    }
    for path in directories {
        root.relative_directory(path)?;
    }
    for expected in files {
        let (parent, name) = split_relative(&expected.path);
        let metadata = root
            .relative_directory(parent)?
            .regular(OsStr::new(name))?
            .metadata()?;
        if metadata.uid() != current_uid() || metadata.mode() & 0o022 != 0 {
            return Err(Refusal::new("installed file is not safely user-owned"));
        }
    }
    Ok(())
}

#[derive(Debug)]
pub struct RemovalFailure {
    pub reason: Refusal,
    /// After a failed rollback or partial deletion this is the owned hidden
    /// tree to inspect. It is never restored after deletion has begun.
    pub recovery: Option<Box<RecoveryLocation>>,
}

impl From<Refusal> for RemovalFailure {
    fn from(reason: Refusal) -> Self {
        Self {
            reason,
            recovery: None,
        }
    }
}

/// Remove an exact inventory already extracted from the externally pinned,
/// semantically validated receipt. This function also checks the raw receipt
/// pin and actual filesystem twice. It does not authenticate receipt semantics.
pub fn remove_verified_installation(
    prefix: &Path,
    files: &[FileIdentity],
    receipt_digest: &str,
) -> std::result::Result<(), RemovalFailure> {
    remove_with_hook(prefix, files, receipt_digest, |_, _| Ok(()))
}

#[derive(Clone, Copy)]
enum RemovalBoundary {
    Verified,
    Moved,
    BeforeDelete,
}

fn remove_with_hook(
    prefix: &Path,
    files: &[FileIdentity],
    receipt_digest: &str,
    mut hook: impl FnMut(RemovalBoundary, &Path) -> Result<()>,
) -> std::result::Result<(), RemovalFailure> {
    let target = ownership::existing_install_target(prefix)?;
    let (identities, directories) = removal_layout(target.root(), files, receipt_digest)?;
    let verify = |root: &Directory| -> Result<()> {
        read_pinned_receipt(root, receipt_digest)?;
        verify_exact_tree(root, &identities, &directories)
    };
    verify(target.root())?;
    hook(RemovalBoundary::Verified, target.path())?;
    recheck_directory_identity(
        target.parent(),
        target.path().parent().expect("validated parent"),
    )?;
    let name = hidden_name(target.name(), ".remove-")?;
    let tombstone = target
        .path()
        .parent()
        .expect("validated parent")
        .join(&name);
    target
        .parent()
        .rename_no_replace(target.name(), target.parent(), &name)?;
    target.parent().sync_best_effort();
    let recheck = (|| -> Result<()> {
        hook(RemovalBoundary::Moved, &tombstone)?;
        // Reopen the moved entry through the retained parent, rather than
        // trusting a pathname or the old root handle after the atomic move.
        let moved = target.parent().child(&name)?;
        let original = target.root().metadata()?;
        let observed = moved.metadata()?;
        if observed.dev() != original.dev() || observed.ino() != original.ino() {
            return Err(Refusal::new("moved installation identity changed"));
        }
        verify(&moved)
    })();
    if let Err(reason) = recheck {
        return match target
            .parent()
            .rename_no_replace(&name, target.parent(), target.name())
        {
            Ok(()) => {
                target.parent().sync_best_effort();
                Err(RemovalFailure {
                    reason,
                    recovery: None,
                })
            }
            Err(rollback) => Err(RemovalFailure {
                reason: Refusal::new(format!("{reason}; exclusive rollback failed: {rollback}")),
                recovery: Some(Box::new(RecoveryLocation::observe(
                    target.parent(),
                    target.path().parent().expect("validated parent"),
                    &name,
                ))),
            }),
        };
    }
    // From this point the root name must never be restored: cleanup may have
    // removed some children already. Recovery always names the tombstone.
    let deletion = hook(RemovalBoundary::BeforeDelete, &tombstone).and_then(|()| {
        target
            .parent()
            .remove_tree(&name, identities.len() + directories.len() + 1)
    });
    if let Err(reason) = deletion {
        return Err(RemovalFailure {
            reason,
            recovery: Some(Box::new(RecoveryLocation::observe(
                target.parent(),
                target.path().parent().expect("validated parent"),
                &name,
            ))),
        });
    }
    target.parent().sync_best_effort();
    Ok(())
}

fn removal_layout(
    root: &Directory,
    files: &[FileIdentity],
    digest: &str,
) -> Result<(Vec<FileIdentity>, BTreeSet<String>)> {
    if files.len() > MAX_FILES {
        return Err(Refusal::new(
            "installed inventory exceeds frozen file count",
        ));
    }
    let receipt = read_pinned_receipt(root, digest)?;
    let mut total = receipt.len() as u64;
    let mut paths = BTreeSet::new();
    let mut folded = BTreeSet::new();
    let mut directories = BTreeSet::new();
    for file in files {
        crate::publisher_tar::validate_portable_path(file.path.as_bytes())?;
        if !(file.path.starts_with("sdk/") || file.path.starts_with("payload/"))
            || !paths.insert(file.path.as_str())
            || !folded.insert(file.path.to_ascii_lowercase())
        {
            return Err(Refusal::new(
                "invalid installed inventory namespace or duplicate path",
            ));
        }
        total = total
            .checked_add(file.bytes)
            .filter(|total| *total <= MAX_INSTALLED_BYTES as u64)
            .ok_or_else(|| Refusal::new("installed inventory exceeds frozen byte profile"))?;
        for (offset, _) in file.path.match_indices('/') {
            directories.insert(file.path[..offset].to_owned());
        }
    }
    let mut identities = files.to_vec();
    identities.push(FileIdentity {
        path: RECEIPT.into(),
        bytes: receipt.len() as u64,
        sha256: digest.into(),
        mode: None,
    });
    Ok((identities, directories))
}

fn read_pinned_receipt(root: &Directory, digest: &str) -> Result<Vec<u8>> {
    if !crate::digest::is_sha256_digest(digest) {
        return Err(Refusal::new("invalid external receipt pin"));
    }
    let file = root.regular(OsStr::new(RECEIPT))?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_RECEIPT as u64
        || metadata.mode() & 0o022 != 0
        || metadata.uid() != current_uid()
    {
        return Err(Refusal::new(
            "installation receipt must be bounded and safely user-owned",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECEIPT as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RECEIPT || sha256_bytes(&bytes) != digest {
        return Err(Refusal::new(
            "installation receipt does not match the external receipt pin",
        ));
    }
    Ok(bytes)
}

#[allow(unsafe_code)]
fn current_uid() -> u32 {
    // SAFETY: getuid takes no pointers and reads only process credentials.
    unsafe { libc::getuid() }
}

fn recheck_directory_identity(retained: &Directory, path: &Path) -> Result<()> {
    let observed = Directory::open(path)?.metadata()?;
    let retained = retained.metadata()?;
    if observed.dev() != retained.dev() || observed.ino() != retained.ino() {
        return Err(Refusal::new(
            "publication parent pathname changed after validation",
        ));
    }
    Ok(())
}

fn write_pin(
    target: &FreshTarget,
    digest: &str,
    signals: &SigtermGuard,
    published: &mut bool,
) -> Result<()> {
    let temporary = hidden_name(target.name(), ".ami-rust-")?;
    let mut created = false;
    let result = (|| -> Result<()> {
        signals.check()?;
        let mut file = signals.with_blocked(|| {
            target
                .parent()
                .create_new_file_tracked(&temporary, 0o600, || created = true)
        })?;
        signals.check()?;
        file.write_all(digest.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        recheck_parent(target)?;
        signals.check()?;
        signals.with_blocked(|| {
            target
                .parent()
                .rename_no_replace(&temporary, target.parent(), target.name())?;
            *published = true;
            Ok(())
        })?;
        target.parent().sync_best_effort();
        Ok(())
    })();
    if created
        && !*published
        && let Err(cleanup) = target.parent().unlink_entry(&temporary)
    {
        let first = result.err().map_or_else(
            || "receipt pin write failed".to_owned(),
            |error| error.to_string(),
        );
        return Err(Refusal::new(format!(
            "{first}; receipt pin temporary retained at {}: {cleanup}",
            target
                .path()
                .parent()
                .expect("validated parent")
                .join(&temporary)
                .display()
        )));
    }
    result
}

fn hidden_name(base: &OsStr, separator: &str) -> Result<OsString> {
    let mut value = OsString::from(".");
    value.push(base);
    value.push(separator);
    let random = random_bytes()?;
    for byte in random {
        value.push(format!("{byte:02x}"));
    }
    Ok(value)
}

#[allow(unsafe_code)]
fn random_bytes() -> Result<[u8; 12]> {
    let mut bytes = [0_u8; 12];
    // SAFETY: getentropy receives a live writable 12-byte buffer, below its
    // documented 256-byte maximum. Both supported hosts provide this API.
    if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
        return Err(Refusal::new(format!(
            "could not generate transaction name: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        process::Command,
    };

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let path = std::env::current_dir()
                .unwrap()
                .join(hidden_name(OsStr::new("transaction-test"), "-").unwrap());
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            fs::create_dir(path.join("bundle")).unwrap();
            fs::write(path.join("bundle/keep"), b"immutable bundle").unwrap();
            Self(path)
        }
        fn prefix(&self) -> PathBuf {
            self.0.join("installed sdk")
        }
        fn bundle(&self) -> PathBuf {
            self.0.join("bundle")
        }
        fn pin(&self) -> PathBuf {
            self.0.join("receipt.pin")
        }
        fn assert_no_stage(&self) {
            assert!(fs::read_dir(&self.0).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".stage-")
            }));
            assert_eq!(
                fs::read(self.bundle().join("keep")).unwrap(),
                b"immutable bundle"
            );
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn files() -> [InstallFile<'static>; 2] {
        [
            InstallFile {
                path: "sdk/bin/tool",
                contents: b"native tool",
                mode: 0o755,
            },
            InstallFile {
                path: "payload/release.json",
                contents: b"{}\n",
                mode: 0o644,
            },
        ]
    }
    const RECEIPT_BYTES: &[u8] = b"{\"fixture\":true}\n";

    #[test]
    fn filesystem_transactions_and_real_sigterm_are_isolated_in_a_child() {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "transaction::tests::transaction_child_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env("AMI_RUST_TRANSACTION_CHILD", "run")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "transaction child failed\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "executed by the parent test in an isolated process"]
    fn transaction_child_fixture() {
        assert_eq!(
            std::env::var("AMI_RUST_TRANSACTION_CHILD").as_deref(),
            Ok("run")
        );
        success_and_exclusive_rerun();
        prepublication_refusals_preserve_other_data();
        tampered_stage_refuses_and_cleanup_recovery_is_explicit();
        parent_path_replacement_refuses_through_retained_handle();
        failed_cleanup_under_a_moved_parent_does_not_report_a_decoy_path();
        postpublication_pin_collision_retains_installation();
        signal_boundaries_preserve_the_correct_tree();
        uninstall_preserves_pin_and_rejects_changes_before_move();
        uninstall_recheck_rolls_back_exclusively_and_retains_partial_deletion();
    }

    fn success_and_exclusive_rerun() {
        let fixture = Fixture::new();
        let result = publish_install(
            &fixture.prefix(),
            &fixture.bundle(),
            Some(&fixture.pin()),
            &files(),
            RECEIPT_BYTES,
        )
        .unwrap();
        assert_eq!(result.prefix, fixture.prefix());
        assert_eq!(result.receipt_sha256, sha256_bytes(RECEIPT_BYTES));
        assert_eq!(result.receipt_pin, Some(fixture.pin()));
        assert_eq!(
            fs::read(fixture.pin()).unwrap(),
            format!("{}\n", result.receipt_sha256).as_bytes()
        );
        for (path, mode) in [
            ("", 0o700),
            ("sdk", 0o755),
            ("sdk/bin", 0o755),
            ("sdk/bin/tool", 0o755),
            ("payload/release.json", 0o644),
            (RECEIPT, 0o600),
        ] {
            assert_eq!(
                fs::metadata(fixture.prefix().join(path))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                mode
            );
        }
        assert_eq!(
            fs::metadata(fixture.pin()).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        let failure = publish_install(
            &fixture.prefix(),
            &fixture.bundle(),
            None,
            &files(),
            RECEIPT_BYTES,
        )
        .unwrap_err();
        assert_eq!(failure.exit_code(), 2);
        assert_eq!(
            fs::read(fixture.prefix().join("sdk/bin/tool")).unwrap(),
            b"native tool"
        );
        fixture.assert_no_stage();
    }

    fn prepublication_refusals_preserve_other_data() {
        for boundary in [Boundary::Staged, Boundary::BeforePublish] {
            let fixture = Fixture::new();
            let failure = publish_with_hook(
                &fixture.prefix(),
                &fixture.bundle(),
                None,
                &files(),
                RECEIPT_BYTES,
                |point, _| {
                    if std::mem::discriminant(&point) == std::mem::discriminant(&boundary) {
                        return Err(Refusal::new("injected prepublication refusal"));
                    }
                    Ok(())
                },
            )
            .unwrap_err();
            assert_eq!(failure.exit_code(), 2);
            assert!(failure.recovery.is_none());
            assert!(!fixture.prefix().exists());
            fixture.assert_no_stage();
        }
        let fixture = Fixture::new();
        let failure = publish_with_hook(
            &fixture.prefix(),
            &fixture.bundle(),
            None,
            &files(),
            RECEIPT_BYTES,
            |point, _| {
                if matches!(point, Boundary::BeforePublish) {
                    fs::write(fixture.prefix(), b"unrelated destination").unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(failure.exit_code(), 2);
        assert!(failure.recovery.is_none());
        assert_eq!(
            fs::read(fixture.prefix()).unwrap(),
            b"unrelated destination"
        );
        fixture.assert_no_stage();
        for path in [
            "sdk/../escape",
            "sdk/CON",
            "sdk/non-ascii-ü",
            "payload/trailing.",
        ] {
            let bad = [InstallFile {
                path,
                contents: b"bad",
                mode: 0o644,
            }];
            assert!(
                publish_install(
                    &fixture.0.join("fresh"),
                    &fixture.bundle(),
                    None,
                    &bad,
                    RECEIPT_BYTES
                )
                .is_err()
            );
        }
        let collision = [
            InstallFile {
                path: "sdk/Tool",
                contents: b"a",
                mode: 0o644,
            },
            InstallFile {
                path: "sdk/tool/child",
                contents: b"b",
                mode: 0o644,
            },
        ];
        assert!(Layout::inspect(&collision, RECEIPT_BYTES).is_err());
    }

    fn tampered_stage_refuses_and_cleanup_recovery_is_explicit() {
        let fixture = Fixture::new();
        let failure = publish_with_hook(
            &fixture.prefix(),
            &fixture.bundle(),
            None,
            &files(),
            RECEIPT_BYTES,
            |point, stage| {
                if matches!(point, Boundary::Written) {
                    fs::write(stage.join("sdk/bin/tool"), b"changed").unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(failure.reason.to_string().contains("inventory"));
        assert!(failure.recovery.is_none());
        fixture.assert_no_stage();
        let failure = publish_with_hook(
            &fixture.prefix(),
            &fixture.bundle(),
            None,
            &files(),
            RECEIPT_BYTES,
            |point, stage| {
                if matches!(point, Boundary::Written) {
                    fs::write(stage.join("extra"), b"unexpected").unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(failure.exit_code(), 2);
        let recovery = failure
            .recovery
            .expect("bounded cleanup reports its owned recovery tree");
        assert!(recovery.verified_path.unwrap().exists());
        assert!(!fixture.prefix().exists());
        assert_eq!(
            fs::read(fixture.bundle().join("keep")).unwrap(),
            b"immutable bundle"
        );
    }

    fn parent_path_replacement_refuses_through_retained_handle() {
        let fixture = Fixture::new();
        let parent = fixture.0.join("parent");
        fs::create_dir(&parent).unwrap();
        let prefix = parent.join("installed");
        let moved = fixture.0.join("moved");
        let failure = publish_with_hook(
            &prefix,
            &fixture.bundle(),
            None,
            &files(),
            RECEIPT_BYTES,
            |point, _| {
                if matches!(point, Boundary::BeforePublish) {
                    fs::rename(&parent, &moved).unwrap();
                    fs::create_dir(&parent).unwrap();
                    fs::write(parent.join("keep"), b"decoy parent").unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert!(
            failure
                .reason
                .to_string()
                .contains("parent pathname changed")
        );
        assert!(failure.recovery.is_none());
        assert_eq!(fs::read(parent.join("keep")).unwrap(), b"decoy parent");
        assert_eq!(fs::read_dir(moved).unwrap().count(), 0);
    }

    fn failed_cleanup_under_a_moved_parent_does_not_report_a_decoy_path() {
        let fixture = Fixture::new();
        let parent = fixture.0.join("parent");
        fs::create_dir(&parent).unwrap();
        let prefix = parent.join("installed");
        let moved = fixture.0.join("moved");
        let failure = publish_with_hook(
            &prefix,
            &fixture.bundle(),
            None,
            &files(),
            RECEIPT_BYTES,
            |point, stage| {
                if matches!(point, Boundary::BeforePublish) {
                    // More entries than this exact immutable layout admits make
                    // cleanup fail within its work bound after the parent moves.
                    for number in 0..20 {
                        fs::write(stage.join(format!("extra-{number}")), b"extra").unwrap();
                    }
                    fs::rename(&parent, &moved).unwrap();
                    fs::create_dir(&parent).unwrap();
                    fs::write(parent.join("keep"), b"decoy parent").unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
        let recovery = failure
            .recovery
            .expect("owned staging retained after cleanup refusal");
        assert!(recovery.verified_path.is_none());
        assert_eq!(recovery.last_known_parent, parent);
        let moved_metadata = fs::metadata(&moved).unwrap();
        assert_eq!(
            recovery.parent_identity,
            Some((moved_metadata.dev(), moved_metadata.ino()))
        );
        assert!(moved.join(recovery.entry_name).exists());
        assert_eq!(fs::read(parent.join("keep")).unwrap(), b"decoy parent");
    }

    fn postpublication_pin_collision_retains_installation() {
        let fixture = Fixture::new();
        let failure = publish_with_hook(
            &fixture.prefix(),
            &fixture.bundle(),
            Some(&fixture.pin()),
            &files(),
            RECEIPT_BYTES,
            |point, _| {
                if matches!(point, Boundary::Published) {
                    symlink("bundle/keep", fixture.pin()).unwrap();
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(failure.exit_code(), 1);
        let installed = failure.published.unwrap();
        assert_eq!(installed.receipt_sha256, sha256_bytes(RECEIPT_BYTES));
        assert!(installed.receipt_pin.is_none());
        assert_eq!(
            fs::read_link(fixture.pin()).unwrap(),
            PathBuf::from("bundle/keep")
        );
        assert_eq!(
            fs::read(fixture.prefix().join(RECEIPT)).unwrap(),
            RECEIPT_BYTES
        );
        assert!(fs::read_dir(&fixture.0).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".ami-rust-")
        }));
        fixture.assert_no_stage();
    }

    #[allow(unsafe_code)]
    fn signal_boundaries_preserve_the_correct_tree() {
        for boundary in [
            Boundary::Staged,
            Boundary::BeforePublish,
            Boundary::Published,
            Boundary::Pinned,
        ] {
            let fixture = Fixture::new();
            let failure = publish_with_hook(
                &fixture.prefix(),
                &fixture.bundle(),
                Some(&fixture.pin()),
                &files(),
                RECEIPT_BYTES,
                |point, _| {
                    if std::mem::discriminant(&point) == std::mem::discriminant(&boundary) {
                        // SAFETY: this isolated child targets its current live thread.
                        assert_eq!(
                            unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGTERM) },
                            0
                        );
                    }
                    Ok(())
                },
            )
            .unwrap_err();
            let published = matches!(boundary, Boundary::Published | Boundary::Pinned);
            assert_eq!(failure.exit_code(), if published { 1 } else { 2 });
            assert_eq!(fixture.prefix().exists(), published);
            assert_eq!(fixture.pin().exists(), matches!(boundary, Boundary::Pinned));
            assert_eq!(
                failure
                    .published
                    .as_ref()
                    .and_then(|installed| installed.receipt_pin.as_ref())
                    .is_some(),
                matches!(boundary, Boundary::Pinned)
            );
            assert!(failure.recovery.is_none());
            fixture.assert_no_stage();
        }
    }

    fn installed_fixture() -> (Fixture, Vec<FileIdentity>, String) {
        let fixture = Fixture::new();
        let installed = publish_install(
            &fixture.prefix(),
            &fixture.bundle(),
            Some(&fixture.pin()),
            &files(),
            RECEIPT_BYTES,
        )
        .unwrap();
        let identities = Layout::inspect(&files(), RECEIPT_BYTES)
            .unwrap()
            .files
            .into_iter()
            .filter(|file| file.path != RECEIPT)
            .collect();
        (fixture, identities, installed.receipt_sha256)
    }

    fn uninstall_preserves_pin_and_rejects_changes_before_move() {
        let (fixture, identities, digest) = installed_fixture();
        assert!(
            remove_verified_installation(&fixture.prefix(), &identities, &"0".repeat(64)).is_err()
        );
        assert!(fixture.prefix().exists());
        fs::create_dir(fixture.prefix().join("extra-empty")).unwrap();
        assert!(remove_verified_installation(&fixture.prefix(), &identities, &digest).is_err());
        assert!(fixture.prefix().exists());
        fs::remove_dir(fixture.prefix().join("extra-empty")).unwrap();
        fs::write(fixture.prefix().join("sdk/bin/tool"), b"modified").unwrap();
        assert!(remove_verified_installation(&fixture.prefix(), &identities, &digest).is_err());
        assert_eq!(
            fs::read(fixture.prefix().join("sdk/bin/tool")).unwrap(),
            b"modified"
        );
        fs::write(fixture.prefix().join("sdk/bin/tool"), b"native tool").unwrap();
        remove_verified_installation(&fixture.prefix(), &identities, &digest).unwrap();
        assert!(!fixture.prefix().exists());
        assert_eq!(
            fs::read(fixture.pin()).unwrap(),
            format!("{digest}\n").as_bytes()
        );
        fixture.assert_no_stage();
    }

    fn uninstall_recheck_rolls_back_exclusively_and_retains_partial_deletion() {
        let (fixture, identities, digest) = installed_fixture();
        let failure = remove_with_hook(&fixture.prefix(), &identities, &digest, |point, path| {
            if matches!(point, RemovalBoundary::Moved) {
                fs::write(path.join("sdk/bin/tool"), b"changed after move").unwrap();
            }
            Ok(())
        })
        .unwrap_err();
        assert!(failure.recovery.is_none());
        assert_eq!(
            fs::read(fixture.prefix().join("sdk/bin/tool")).unwrap(),
            b"changed after move"
        );
        assert!(!fs::read_dir(&fixture.0).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".remove-")
        }));

        let (fixture, identities, digest) = installed_fixture();
        let failure = remove_with_hook(&fixture.prefix(), &identities, &digest, |point, path| {
            if matches!(point, RemovalBoundary::Moved) {
                fs::write(path.join("sdk/bin/tool"), b"changed after move").unwrap();
                fs::write(fixture.prefix(), b"new unrelated occupant").unwrap();
            }
            Ok(())
        })
        .unwrap_err();
        assert!(failure.reason.to_string().contains("rollback failed"));
        let recovery = failure.recovery.unwrap().verified_path.unwrap();
        assert_eq!(
            fs::read(fixture.prefix()).unwrap(),
            b"new unrelated occupant"
        );
        assert_eq!(
            fs::read(recovery.join("sdk/bin/tool")).unwrap(),
            b"changed after move"
        );

        let (fixture, identities, digest) = installed_fixture();
        let failure = remove_with_hook(&fixture.prefix(), &identities, &digest, |point, path| {
            if matches!(point, RemovalBoundary::BeforeDelete) {
                fs::remove_file(path.join("sdk/bin/tool")).unwrap();
                return Err(Refusal::new("injected interruption after one deletion"));
            }
            Ok(())
        })
        .unwrap_err();
        assert!(!fixture.prefix().exists());
        let recovery = failure.recovery.unwrap().verified_path.unwrap();
        assert!(!recovery.join("sdk/bin/tool").exists());
        assert_eq!(fs::read(recovery.join(RECEIPT)).unwrap(), RECEIPT_BYTES);
        fixture.assert_no_stage();
    }
}
