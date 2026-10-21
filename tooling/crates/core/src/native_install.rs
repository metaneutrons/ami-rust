//! Authenticated native installation and externally pinned removal.
//!
//! Installation consumes retained publisher/SDK bytes. Removal authenticates
//! its authority through the explicitly supplied receipt digest, then checks
//! manifest/archive/inventory bindings before invoking the transaction engine.
//! Historical receipts are removal inputs only; their drivers never execute.

#[cfg(test)]
use crate::process_spawn::FixtureCommandExt;
pub use crate::transaction::{InstallFailure, PublishedInstall, RemovalFailure};

use crate::{
    Refusal, Result,
    compression::{DecodeLimits, copy_xz},
    digest::{is_sha256_digest, sha256_bytes},
    directory::{Directory, EntryType},
    host_platform::supported_host,
    inventory::FileIdentity,
    json::JsonProfile,
    ownership,
    package::check_native_header,
    publisher::{VerifiedPublisherBundle, verify_publisher_bundle},
    publisher_files::read_open_regular,
    publisher_tar::{ExpectedFile, MAX_DECODED_TAR_BYTES, verify_publisher_sdk_tar},
    receipts::{Authentication, ReceiptKind, parse_install_receipt},
    records::Host,
    release_manifest::{
        NativeReleaseManifest, ReleaseFile, parse_native_release_manifest, parse_release_manifest,
    },
    sdk::VerifiedSdkV2Payload,
    signals::SigtermGuard,
    transaction::{self, InstallFile},
};
use serde::Serialize;
use std::{collections::BTreeMap, ffi::OsStr, path::Path};

/// A completely checked installation whose removal authority is externally
/// pinned. This is local retained-state authority, not fresh publisher proof.
/// Historical installations never produce this native-driver capability.
pub struct CheckedNativeInstallation {
    target: ownership::ExistingTarget,
    files: BTreeMap<String, FileIdentity>,
    receipt: crate::receipts::InstallReceipt,
    receipt_digest: String,
}

impl CheckedNativeInstallation {
    pub fn open(prefix: &Path, receipt_digest: &str) -> Result<Self> {
        let files = installed_inventory(prefix, receipt_digest)?;
        let target = transaction::inspect_verified_installation(prefix, &files, receipt_digest)?;
        let raw = read_relative(target.root(), "install-receipt.json", 4 * 1024 * 1024)?;
        if sha256_bytes(&raw) != receipt_digest {
            return Err(Refusal::new("retained installation receipt changed"));
        }
        let receipt = parse_install_receipt(&raw)?;
        if receipt.kind != ReceiptKind::NativeV3 {
            return Err(Refusal::new(
                "historical executable-driver contract requires explicit migration",
            ));
        }
        Ok(Self {
            target,
            files: files
                .into_iter()
                .map(|file| (file.path.clone(), file))
                .collect(),
            receipt,
            receipt_digest: receipt_digest.to_owned(),
        })
    }

    pub fn path(&self) -> &Path {
        self.target.path()
    }

    pub fn receipt(&self) -> &crate::receipts::InstallReceipt {
        &self.receipt
    }

    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }

    pub fn file_identities(&self) -> impl Iterator<Item = &FileIdentity> {
        self.files.values()
    }

    /// Read an inventory-bound file through the retained root. The actual
    /// descriptor's owner, mode, size and digest must still match. Recheck the
    /// complete installation before executing a longer consumer operation.
    pub fn read_file(&self, relative: &str) -> Result<Vec<u8>> {
        use std::os::unix::fs::MetadataExt;
        let expected = self.files.get(relative).ok_or_else(|| {
            Refusal::new("file is absent from the retained installation inventory")
        })?;
        let (parent, leaf) = relative.rsplit_once('/').unwrap_or(("", relative));
        let directory = self.target.root().relative_directory(parent)?;
        let identity = directory.classify_entry(OsStr::new(leaf))?;
        if identity.entry_type() != EntryType::RegularFile {
            return Err(Refusal::new("retained installation file changed type"));
        }
        let file = directory.open_regular_matching(OsStr::new(leaf), identity)?;
        let metadata = file.metadata()?;
        if metadata.uid() != self.target.root().metadata()?.uid()
            || Some(metadata.mode() & 0o7777) != expected.mode
        {
            return Err(Refusal::new(
                "retained installation file owner or mode changed",
            ));
        }
        let bytes = read_open_regular(
            file,
            usize::try_from(expected.bytes)
                .map_err(|_| Refusal::new("retained file size is not representable"))?,
        )?;
        if bytes.len() as u64 != expected.bytes || sha256_bytes(&bytes) != expected.sha256 {
            return Err(Refusal::new("retained installation file bytes changed"));
        }
        Ok(bytes)
    }

    pub fn recheck(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let checked = Self::open(self.path(), &self.receipt_digest)?;
        let before = self.target.root().metadata()?;
        let after = checked.target.root().metadata()?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(Refusal::new("retained installation root identity changed"));
        }
        Ok(())
    }
}

struct OwnedFile {
    path: String,
    contents: Vec<u8>,
    mode: u32,
}

struct InstallPlan {
    files: Vec<OwnedFile>,
    receipt: Vec<u8>,
    selected_cli: String,
}

#[derive(Serialize)]
struct ReceiptRow<'a> {
    path: &'a str,
    bytes: u64,
    sha256: String,
}

#[derive(Serialize)]
struct NativeReceipt<'a> {
    schema: &'static str,
    publisher: &'static str,
    release_manifest_sha256: String,
    sdk_manifest_sha256: &'a str,
    version: &'a str,
    inventory: Vec<ReceiptRow<'a>>,
    authentication: &'a Authentication,
    host: Host,
    cli_sha256: &'a str,
    core_sha256: &'a str,
}

/// Authenticate first, then publish the exact retained native payload under a
/// single signal guard. Post-publication errors retain the resulting identity.
pub fn install(
    bundle: &Path,
    policy: &Path,
    prefix: &Path,
    receipt_pin: Option<&Path>,
) -> std::result::Result<PublishedInstall, InstallFailure> {
    // Refuse unsafe/existing destinations before paying for cryptography.
    ownership::install_target(prefix)?;
    ownership::require_disjoint(prefix, bundle, "installation must be outside the bundle")?;
    if let Some(pin) = receipt_pin {
        ownership::receipt_pin(pin, prefix, bundle)?;
    }
    let signals = SigtermGuard::acquire()?;
    let result = (|| {
        signals.check()?;
        let host = supported_host()?;
        let verified = verify_publisher_bundle(bundle, policy, || signals.requested())?;
        signals.check()?;
        install_verified_guarded(&verified, bundle, prefix, receipt_pin, host, &signals)
    })();
    match (result, signals.finish()) {
        (Ok(published), Ok(())) => Ok(published),
        (Ok(published), Err(reason)) => Err(InstallFailure {
            reason,
            published: Some(published),
            recovery: None,
        }),
        (Err(mut failure), Err(restore)) => {
            failure.reason = Refusal::new(format!("{}; {restore}", failure.reason));
            Err(failure)
        }
        (Err(failure), Ok(())) => Err(failure),
    }
}

/// Internal composition under the caller's existing operation signal guard.
/// The unforgeable publisher capability still selects all installed bytes.
pub(crate) fn install_verified_guarded(
    verified: &VerifiedPublisherBundle,
    bundle: &Path,
    prefix: &Path,
    receipt_pin: Option<&Path>,
    host: Host,
    signals: &SigtermGuard,
) -> std::result::Result<PublishedInstall, InstallFailure> {
    ownership::install_target(prefix)?;
    ownership::require_disjoint(prefix, bundle, "installation must be outside the bundle")?;
    if let Some(pin) = receipt_pin {
        ownership::receipt_pin(pin, prefix, bundle)?;
    }
    host.ensure_current()?;
    signals.check()?;
    let sdk = VerifiedSdkV2Payload::from_verified_bundle(verified)?;
    let plan = assemble_install(verified, &sdk, host)?;
    signals.check()?;
    let files = plan
        .files
        .iter()
        .map(|file| InstallFile {
            path: &file.path,
            contents: &file.contents,
            mode: file.mode,
        })
        .collect::<Vec<_>>();
    transaction::publish_native_install_guarded(
        prefix,
        bundle,
        receipt_pin,
        &files,
        &plan.receipt,
        &plan.selected_cli,
        signals,
    )
}

struct InstallSources<'a> {
    manifest: &'a NativeReleaseManifest,
    raw_manifest: &'a [u8],
    assets: &'a BTreeMap<String, Vec<u8>>,
    signature: &'a [u8],
    authentication: &'a Authentication,
}

fn assemble_install(
    bundle: &VerifiedPublisherBundle,
    sdk: &VerifiedSdkV2Payload,
    host: Host,
) -> Result<InstallPlan> {
    assemble_sources(
        InstallSources {
            manifest: bundle.manifest(),
            raw_manifest: bundle.raw_manifest(),
            assets: bundle.assets(),
            signature: bundle.release_signature(),
            authentication: bundle.authentication(),
        },
        sdk,
        host,
    )
}

// Pure composition, private to this module. Tests of this helper do not
// authenticate a publisher; production reaches it only through the capability.
fn assemble_sources(
    source: InstallSources<'_>,
    sdk: &VerifiedSdkV2Payload,
    host: Host,
) -> Result<InstallPlan> {
    let manifest = source.manifest;
    if sdk.summary().sdk_manifest_sha256 != manifest.sdk_manifest_sha256.as_str()
        || sdk.summary().version != manifest.version
    {
        return Err(Refusal::new(
            "native SDK capability belongs to a different release",
        ));
    }
    let launcher = manifest.host_launchers.for_host(host);
    let selected_cli = format!("payload/{}", launcher.path);
    let launcher_bytes = source
        .assets
        .get(&launcher.path)
        .ok_or_else(|| Refusal::new("authenticated host launcher is missing"))?;
    if launcher.bytes != launcher_bytes.len() as u64
        || launcher.sha256.as_str() != sha256_bytes(launcher_bytes)
    {
        return Err(Refusal::new("selected host launcher identity differs"));
    }
    check_native_header(launcher_bytes, host)?;
    let mut files = Vec::new();
    for file in sdk.files() {
        files.push(OwnedFile {
            path: format!("sdk/{}", file.path()),
            contents: file.contents().to_vec(),
            mode: file.mode(),
        });
    }
    for (path, contents) in source.assets {
        files.push(OwnedFile {
            path: format!("payload/{path}"),
            contents: contents.clone(),
            mode: if *path == launcher.path { 0o755 } else { 0o644 },
        });
    }
    files.push(OwnedFile {
        path: "payload/release.json".into(),
        contents: source.raw_manifest.to_vec(),
        mode: 0o644,
    });
    files.push(OwnedFile {
        path: "payload/release.json.sig".into(),
        contents: source.signature.to_vec(),
        mode: 0o644,
    });
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let inventory = files
        .iter()
        .map(|file| ReceiptRow {
            path: &file.path,
            bytes: file.contents.len() as u64,
            sha256: sha256_bytes(&file.contents),
        })
        .collect();
    // Serialize directly, preserving exact workflow-counter decimal lexemes.
    let mut receipt = serde_json::to_vec_pretty(&NativeReceipt {
        schema: "ami-rust-install-receipt-v3",
        publisher: "metaneutrons.ami-rust.github",
        release_manifest_sha256: sha256_bytes(source.raw_manifest),
        sdk_manifest_sha256: manifest.sdk_manifest_sha256.as_str(),
        version: &manifest.version,
        inventory,
        authentication: source.authentication,
        host,
        cli_sha256: launcher.sha256.as_str(),
        core_sha256: launcher.sha256.as_str(),
    })
    .map_err(|error| Refusal::new(format!("could not encode native receipt: {error}")))?;
    receipt.push(b'\n');
    parse_install_receipt(&receipt)?;
    Ok(InstallPlan {
        files,
        receipt,
        selected_cli,
    })
}

/// Remove a completely matched installation using an external receipt digest.
/// No archive driver, verifier subprocess or historical interpreter executes.
pub fn uninstall(prefix: &Path, receipt_sha256: &str) -> std::result::Result<(), RemovalFailure> {
    let files = installed_inventory(prefix, receipt_sha256)?;
    transaction::remove_verified_installation(prefix, &files, receipt_sha256)
}

fn installed_inventory(prefix: &Path, receipt_sha256: &str) -> Result<Vec<FileIdentity>> {
    if !is_sha256_digest(receipt_sha256) {
        return Err(Refusal::new(
            "receipt digest must be 64 lowercase hex characters",
        ));
    }
    let target = ownership::existing_install_target(prefix)?;
    let root = target.root();
    let receipt_raw = read_relative(
        root,
        "install-receipt.json",
        JsonProfile::ReleaseManifestAndInstallReceipt.max_bytes(),
    )?;
    if sha256_bytes(&receipt_raw) != receipt_sha256 {
        return Err(Refusal::new(
            "installed receipt differs from the external pin",
        ));
    }
    let receipt = parse_install_receipt(&receipt_raw)?;
    let raw_manifest = read_relative(root, "payload/release.json", 4 * 1024 * 1024)?;
    if sha256_bytes(&raw_manifest) != receipt.release_manifest_sha256.as_str() {
        return Err(Refusal::new(
            "installed release manifest differs from the receipt",
        ));
    }
    let (version, sdk_digest, assets, sdk_files, native_launcher) = match receipt.kind {
        ReceiptKind::NativeV3 => {
            let manifest = parse_native_release_manifest(&raw_manifest, true)?;
            let native = receipt
                .native
                .as_ref()
                .ok_or_else(|| Refusal::new("missing native identity"))?;
            native.host.ensure_current()?;
            let launcher = manifest.host_launchers.for_host(native.host);
            if launcher.sha256 != native.cli_sha256 || native.cli_sha256 != native.core_sha256 {
                return Err(Refusal::new("installed host CLI differs from its receipt"));
            }
            let selected = format!("payload/{}", launcher.path);
            let contents = read_relative(root, &selected, 16 * 1024 * 1024)?;
            check_native_header(&contents, native.host)?;
            (
                manifest.version,
                manifest.sdk_manifest_sha256,
                manifest.assets,
                manifest.sdk_files,
                Some(selected),
            )
        }
        kind => {
            let manifest =
                parse_release_manifest(&raw_manifest, kind == ReceiptKind::HistoricalProductionV2)?;
            (
                manifest.version,
                manifest.sdk_manifest_sha256,
                manifest.assets,
                manifest.sdk_files,
                None,
            )
        }
    };
    if version != receipt.version || sdk_digest != receipt.sdk_manifest_sha256 {
        return Err(Refusal::new(
            "installed SDK identity differs from the receipt",
        ));
    }
    let mut expected = BTreeMap::new();
    for row in &assets {
        let path = format!("payload/{}", row.path);
        let mode = if native_launcher.as_ref() == Some(&path) {
            0o755
        } else {
            0o644
        };
        insert_expected(&mut expected, path, row, mode)?;
    }
    let archive = read_relative(root, "payload/sdk.tar.xz", 16 * 1024 * 1024)?;
    let archive_row = assets
        .iter()
        .find(|row| row.path == "sdk.tar.xz")
        .ok_or_else(|| Refusal::new("installed archive is not bound to the manifest"))?;
    if archive.len() as u64 != archive_row.bytes
        || sha256_bytes(&archive) != archive_row.sha256.as_str()
    {
        return Err(Refusal::new("installed archive identity differs"));
    }
    let mut decoded = Vec::new();
    copy_xz(
        &archive,
        &mut decoded,
        DecodeLimits {
            max_compressed_bytes: 16 * 1024 * 1024,
            max_decoded_bytes: MAX_DECODED_TAR_BYTES,
            max_xz_memory_kib: 64 * 1024,
        },
    )?;
    let rows = sdk_files
        .iter()
        .map(|row| ExpectedFile {
            path: &row.path,
            size: row.bytes as usize,
            sha256: row.sha256.as_str(),
        })
        .collect::<Vec<_>>();
    let members = verify_publisher_sdk_tar(&decoded, &rows)?;
    for member in members {
        let row = sdk_files
            .iter()
            .find(|row| row.path == member.path)
            .ok_or_else(|| Refusal::new("unexpected installed SDK member"))?;
        insert_expected(
            &mut expected,
            format!("sdk/{}", member.path),
            row,
            member.mode,
        )?;
    }
    for (path, raw) in [
        ("payload/release.json", raw_manifest),
        (
            "payload/release.json.sig",
            read_relative(root, "payload/release.json.sig", 16 * 1024 * 1024)?,
        ),
    ] {
        if expected
            .insert(
                path.to_owned(),
                FileIdentity {
                    path: path.into(),
                    bytes: raw.len() as u64,
                    sha256: sha256_bytes(&raw),
                    mode: Some(0o644),
                },
            )
            .is_some()
        {
            return Err(Refusal::new(
                "installed manifest/proof conflicts with an asset path",
            ));
        }
    }
    if expected.len() != receipt.inventory.len() {
        return Err(Refusal::new(
            "receipt inventory does not exactly cover the release",
        ));
    }
    for row in &receipt.inventory {
        let file = expected
            .get(&row.path)
            .ok_or_else(|| Refusal::new("receipt names an unexpected installed file"))?;
        if file.bytes != row.bytes || file.sha256 != row.sha256.as_str() {
            return Err(Refusal::new(
                "receipt file identity differs from the release",
            ));
        }
    }
    Ok(expected.into_values().collect())
}

fn insert_expected(
    files: &mut BTreeMap<String, FileIdentity>,
    path: String,
    row: &ReleaseFile,
    mode: u32,
) -> Result<()> {
    if files
        .insert(
            path.clone(),
            FileIdentity {
                path,
                bytes: row.bytes,
                sha256: row.sha256.as_str().to_owned(),
                mode: Some(mode),
            },
        )
        .is_some()
    {
        return Err(Refusal::new("duplicate installed identity"));
    }
    Ok(())
}

fn read_relative(root: &Directory, relative: &str, maximum: usize) -> Result<Vec<u8>> {
    let (parent, leaf) = relative.rsplit_once('/').unwrap_or(("", relative));
    let directory = root.relative_directory(parent)?;
    let identity = directory.classify_entry(OsStr::new(leaf))?;
    if identity.entry_type() != EntryType::RegularFile {
        return Err(Refusal::new("installed entry must be a regular file"));
    }
    read_open_regular(
        directory.open_regular_matching(OsStr::new(leaf), identity)?,
        maximum,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipts::{POLICY_EVIDENCE, VERIFICATION_MODE};
    use serde_json::{Value, json};
    use std::{
        fs,
        os::unix::fs::DirBuilderExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn native_installation_and_pinned_removal_are_isolated_in_a_child() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_install::tests::native_install_child_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env_clear()
            .env("HOME", std::env::var_os("HOME").unwrap())
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("AMI_NATIVE_INSTALL_FIXTURE", "1")
            .output_guarded()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "run by the parent with isolated process-wide signal state"]
    fn native_install_child_fixture() {
        assert_eq!(
            std::env::var("AMI_NATIVE_INSTALL_FIXTURE").as_deref(),
            Ok("1")
        );
        pinned_synthetic_native_installation_removes_exactly_its_owned_tree();
        additional_user_file_refuses_uninstall_without_moving_or_deleting_data();
        changed_sdk_bytes_or_stale_receipt_pin_cannot_authorize_removal();
        malformed_external_policy_cannot_create_an_installation_or_pin();
        retained_component_selection_checks_all_six_roots_and_rechecks_changes();
    }

    struct TestRoot(PathBuf);
    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "ami-native-install-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(fs::canonicalize(path).unwrap())
        }
    }
    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    // These are header-admission fixtures, not executable compiler programs or
    // signature evidence. No test constructs a production publisher capability.
    fn header(host: Host) -> Vec<u8> {
        let mut raw = vec![0; 128];
        match host {
            Host::MacosAarch64 => {
                raw[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
                raw[4..8].copy_from_slice(&0x0100_000c_u32.to_le_bytes());
                raw[12..16].copy_from_slice(&2_u32.to_le_bytes());
            }
            Host::LinuxX86_64 => {
                raw[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
                raw[16..18].copy_from_slice(&2_u16.to_le_bytes());
                raw[18..20].copy_from_slice(&62_u16.to_le_bytes());
                raw[20..24].copy_from_slice(&1_u32.to_le_bytes());
                raw[24..32].copy_from_slice(&0x400078_u64.to_le_bytes());
                raw[32..40].copy_from_slice(&64_u64.to_le_bytes());
                raw[52..54].copy_from_slice(&64_u16.to_le_bytes());
                raw[54..56].copy_from_slice(&56_u16.to_le_bytes());
                raw[56..58].copy_from_slice(&1_u16.to_le_bytes());
                raw[64..68].copy_from_slice(&1_u32.to_le_bytes());
                raw[68..72].copy_from_slice(&5_u32.to_le_bytes());
                raw[80..88].copy_from_slice(&0x400000_u64.to_le_bytes());
                raw[96..104].copy_from_slice(&128_u64.to_le_bytes());
                raw[104..112].copy_from_slice(&128_u64.to_le_bytes());
            }
        }
        raw
    }

    fn rows(files: &[ReleaseFile]) -> Value {
        Value::Array(
            files
                .iter()
                .map(|row| json!({"path":row.path,"bytes":row.bytes,"sha256":row.sha256.as_str()}))
                .collect(),
        )
    }

    fn synthetic_plan() -> InstallPlan {
        let (sdk, mut manifest, mut assets) =
            crate::sdk::test_payload_with_manifest_and_assets().unwrap();
        let mut launchers = serde_json::Map::new();
        for (host, key) in [
            (Host::LinuxX86_64, "linux-x86_64"),
            (Host::MacosAarch64, "macos-aarch64"),
        ] {
            let launcher = manifest.host_launchers.for_host(host);
            let path = launcher.path.clone();
            let data = header(host);
            let digest = sha256_bytes(&data);
            let row = manifest
                .assets
                .iter_mut()
                .find(|row| row.path == path)
                .unwrap();
            row.bytes = data.len() as u64;
            row.sha256 = serde_json::from_value(json!(digest)).unwrap();
            launchers.insert(
                key.into(),
                json!({"path":path,"bytes":data.len(),"sha256":digest}),
            );
            assets.insert(path, data);
        }
        let utility = b"inert utility fixture".to_vec();
        let utility_row: Value =
            json!({"path":"SHAUTIL","bytes":utility.len(),"sha256":sha256_bytes(&utility)});
        let mut asset_rows = rows(&manifest.assets).as_array().unwrap().clone();
        asset_rows.push(utility_row);
        assets.insert("SHAUTIL".into(), utility);
        let raw = serde_json::to_vec(&json!({
            "schema":"ami-rust-release-v2", "version":manifest.version,
            "qualification_only":false, "sdk_archive":manifest.sdk_archive,
            "sdk_manifest_sha256":manifest.sdk_manifest_sha256.as_str(),
            "assets":asset_rows, "sdk_files":rows(&manifest.sdk_files),
            "producer":{"source_sha":"a".repeat(40)}, "host_launchers":launchers,
        }))
        .unwrap();
        let manifest = parse_native_release_manifest(&raw, true).unwrap();
        let subjects = ["SHAUTIL", "release.json", "sdk.tar.xz"];
        let authentication: Authentication = serde_json::from_value(json!({
            "external_policy_sha256":"b".repeat(64),
            "report":{
                "schema":"ami-rust-publisher-verification-v2", "verified":true,
                "repository":"metaneutrons/ami-rust", "workflow":".github/workflows/sdk-qualify.yml",
                "workflowSha":"a".repeat(40), "sourceSha":"a".repeat(40), "sourceRef":"refs/heads/main",
                "manifestSha256":sha256_bytes(&raw),
                "workflowRuns":[{"runId":1,"runAttempt":1,"hostProfile":Host::current().unwrap()}],
                "attestedSubjects":subjects, "cosignSubjects":subjects,
                "manifestBoundAssets":assets.keys().collect::<Vec<_>>(),
                "publisherPolicyEvidence":POLICY_EVIDENCE,
                "verificationMode":VERIFICATION_MODE, "elapsedSeconds":0.001,
            }
        })).unwrap();
        assemble_sources(
            InstallSources {
                manifest: &manifest,
                raw_manifest: &raw,
                assets: &assets,
                signature: b"inert retained Cosign fixture",
                authentication: &authentication,
            },
            &sdk,
            Host::current().unwrap(),
        )
        .unwrap()
    }

    fn publish_fixture(root: &TestRoot) -> PublishedInstall {
        let plan = synthetic_plan();
        let bundle = root.0.join("bundle");
        fs::create_dir(&bundle).unwrap();
        let files = plan
            .files
            .iter()
            .map(|file| InstallFile {
                path: &file.path,
                contents: &file.contents,
                mode: file.mode,
            })
            .collect::<Vec<_>>();
        let guard = SigtermGuard::acquire().unwrap();
        let published = transaction::publish_native_install_guarded(
            &root.0.join("installed"),
            &bundle,
            Some(&root.0.join("receipt.sha256")),
            &files,
            &plan.receipt,
            &plan.selected_cli,
            &guard,
        )
        .unwrap();
        guard.finish().unwrap();
        published
    }

    fn pinned_synthetic_native_installation_removes_exactly_its_owned_tree() {
        let root = TestRoot::new();
        let unrelated = root.0.join("global-rust-config");
        fs::write(&unrelated, b"user configuration").unwrap();
        let installed = publish_fixture(&root);
        let receipt = read_relative(
            &Directory::open(&installed.prefix).unwrap(),
            "install-receipt.json",
            4 * 1024 * 1024,
        )
        .unwrap();
        assert_eq!(
            parse_install_receipt(&receipt).unwrap().kind,
            ReceiptKind::NativeV3
        );
        assert_eq!(
            fs::read_to_string(root.0.join("receipt.sha256")).unwrap(),
            format!("{}\n", installed.receipt_sha256)
        );
        let retained =
            CheckedNativeInstallation::open(&installed.prefix, &installed.receipt_sha256).unwrap();
        assert_eq!(retained.receipt_digest(), installed.receipt_sha256);
        assert_eq!(retained.receipt().kind, ReceiptKind::NativeV3);
        assert!(
            !retained
                .read_file("sdk/contract/sdk.json")
                .unwrap()
                .is_empty()
        );
        assert!(retained.read_file("sdk/not-listed").is_err());
        retained.recheck().unwrap();
        uninstall(&installed.prefix, &installed.receipt_sha256).unwrap();
        assert!(!installed.prefix.exists());
        assert!(retained.recheck().is_err());
        assert_eq!(fs::read(unrelated).unwrap(), b"user configuration");
        assert!(root.0.join("receipt.sha256").is_file());
    }

    fn additional_user_file_refuses_uninstall_without_moving_or_deleting_data() {
        let root = TestRoot::new();
        let installed = publish_fixture(&root);
        let user_file = installed.prefix.join("user-notes.txt");
        fs::write(&user_file, b"keep my notes").unwrap();
        assert!(
            CheckedNativeInstallation::open(&installed.prefix, &installed.receipt_sha256).is_err()
        );
        assert!(uninstall(&installed.prefix, &installed.receipt_sha256).is_err());
        assert_eq!(fs::read(user_file).unwrap(), b"keep my notes");
        assert!(installed.prefix.join("sdk/contract/sdk.json").is_file());
    }

    fn changed_sdk_bytes_or_stale_receipt_pin_cannot_authorize_removal() {
        let root = TestRoot::new();
        let installed = publish_fixture(&root);
        let retained =
            CheckedNativeInstallation::open(&installed.prefix, &installed.receipt_sha256).unwrap();
        assert!(uninstall(&installed.prefix, &"0".repeat(64)).is_err());
        assert!(CheckedNativeInstallation::open(&installed.prefix, &"0".repeat(64)).is_err());
        fs::write(installed.prefix.join("sdk/README.md"), b"user-edited SDK").unwrap();
        assert!(retained.read_file("sdk/README.md").is_err());
        assert!(retained.recheck().is_err());
        assert!(uninstall(&installed.prefix, &installed.receipt_sha256).is_err());
        assert_eq!(
            fs::read(installed.prefix.join("sdk/README.md")).unwrap(),
            b"user-edited SDK"
        );
        assert!(installed.prefix.join("install-receipt.json").is_file());
    }

    fn malformed_external_policy_cannot_create_an_installation_or_pin() {
        let root = TestRoot::new();
        let bundle = root.0.join("bundle");
        fs::create_dir(&bundle).unwrap();
        let policy = root.0.join("policy.json");
        fs::write(&policy, b"{}").unwrap();
        let prefix = root.0.join("installed");
        let pin = root.0.join("receipt.sha256");
        let error = install(&bundle, &policy, &prefix, Some(&pin)).unwrap_err();
        assert!(error.published.is_none());
        assert!(!prefix.exists());
        assert!(!pin.exists());
        assert_eq!(fs::read(policy).unwrap(), b"{}");
    }

    fn retained_component_selection_checks_all_six_roots_and_rechecks_changes() {
        use std::os::unix::fs::PermissionsExt;
        let root = TestRoot::new();
        let installed = publish_fixture(&root);
        let installation =
            CheckedNativeInstallation::open(&installed.prefix, &installed.receipt_sha256).unwrap();
        let mut roots = serde_json::Map::new();
        for name in ["rust", "cargo", "toolchain", "collector", "csdk", "vendor"] {
            let component = root.0.join(format!("component-{name}"));
            fs::create_dir_all(component.join("bin")).unwrap();
            let tool = component.join("bin/tool");
            fs::write(&tool, b"synthetic component\n").unwrap();
            fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
            std::os::unix::fs::symlink("tool", component.join("bin/alias")).unwrap();
            roots.insert(name.into(), json!(component));
        }
        let mut raw_selection = json!({
            "schema":"ami-rust-selection-v2", "host":Host::current().unwrap(),
            "install_receipt_sha256":installed.receipt_sha256,
            "components":roots,
        });
        let selection =
            crate::records::parse_selection(&serde_json::to_vec(&raw_selection).unwrap()).unwrap();
        let selected = crate::selected_inputs::verify_selection(&installation, &selection).unwrap();
        for name in ["rust", "cargo", "toolchain", "collector", "csdk", "vendor"] {
            let component = selected.component(name).unwrap();
            assert_eq!(component.measurement().files, 1);
            assert_eq!(
                component.executable("bin/tool").unwrap(),
                component.path().join("bin/tool")
            );
            assert_eq!(
                component.executable("bin/alias").unwrap(),
                component.path().join("bin/alias")
            );
            assert!(component.executable("bin/unlisted").is_err());
        }
        selected.recheck().unwrap();
        let tool = root.0.join("component-rust/bin/tool");
        fs::write(&tool, b"changed").unwrap();
        assert!(selected.recheck().is_err());
        fs::write(&tool, b"synthetic component\n").unwrap();
        selected.recheck().unwrap();
        fs::write(root.0.join("component-vendor/extra"), b"user data").unwrap();
        assert!(crate::selected_inputs::verify_selection(&installation, &selection).is_err());
        assert_eq!(
            fs::read(root.0.join("component-vendor/extra")).unwrap(),
            b"user data"
        );
        raw_selection["install_receipt_sha256"] = json!("0".repeat(64));
        let stale =
            crate::records::parse_selection(&serde_json::to_vec(&raw_selection).unwrap()).unwrap();
        assert!(crate::selected_inputs::verify_selection(&installation, &stale).is_err());
        assert!(installed.prefix.is_dir());
    }
}
