//! Offline publisher authentication using separately pinned GH and Cosign.
//!
//! Success binds the retained in-memory manifest/assets to all six successful
//! verifier calls and the external policy. This is a trusted-owner filesystem
//! model: descriptor reads and pre/post rechecks detect ordinary changes, not
//! an adversarial same-user writer. Tools reopen absolute paths. Process-group
//! capture and resource sampling are not process containment. Current visible
//! RSS, private HOME bytes and aggregate logs use the host reference profile;
//! sampling cannot prove the absence of unsampled or escaped processes.

use crate::{
    Refusal, Result,
    digest::sha256_bytes,
    directory::Directory,
    json::{JsonProfile, parse_json_value},
    ownership::protected_regular_file,
    process_capture::{CaptureLimits, CommandSpec},
    publisher_claims::{PublisherClaimContext, check_github_output},
    publisher_files::{
        BundleMeasurement, LEGACY_BUNDLE_BYTE_LIMIT, NATIVE_BUNDLE_BYTE_LIMIT, read_bundle_file,
        read_open_regular, scan_bundle_exact, scan_native_bundle_exact,
    },
    publisher_home::PublisherHome,
    publisher_metadata::{AuthenticationMetadata, parse_authentication_metadata},
    publisher_policy::{
        PinnedPolicyFile, PublisherPolicy, parse_inputs_manifest, parse_publisher_policy,
    },
    receipts::{Authentication, POLICY_EVIDENCE, PublisherReport, VERIFICATION_MODE, WorkflowRun},
    release_manifest::{
        NativeReleaseManifest, ReleaseFile, ReleaseManifest, parse_native_release_manifest,
        parse_release_manifest,
    },
    resource_capture::{ResourceLimits, ResourceReport, SampleLimits, capture_with_resources},
    workspace_accounting::ScanLimits,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsString,
    fs::{self, Metadata},
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::Path,
    time::{Duration, Instant},
};

const TOOL_MAX_BYTES: u64 = 512 * 1024 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(300);
const SUBJECTS: [&str; 3] = ["SHAUTIL", "release.json", "sdk.tar.xz"];
type BundleScanner =
    fn(&Directory, &BTreeSet<String>, &BTreeSet<String>) -> Result<BundleMeasurement>;

/// Select the schema explicitly. Legacy inspection never activates a Python
/// driver or grants permission to install it through a native consumer path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReleaseFlavor {
    LegacyInspection,
    Native,
}

#[derive(Debug)]
enum ParsedManifest {
    Legacy(ReleaseManifest),
    Native(NativeReleaseManifest),
}

impl ParsedManifest {
    fn assets(&self) -> &[ReleaseFile] {
        match self {
            Self::Legacy(m) => &m.assets,
            Self::Native(m) => &m.assets,
        }
    }
    fn qualification_only(&self) -> bool {
        match self {
            Self::Legacy(m) => m.qualification_only,
            Self::Native(m) => m.qualification_only,
        }
    }
}

/// Constructible only by successful verification. Downstream installation uses
/// these retained bytes rather than reopening a mutable bundle after success.
#[derive(Debug)]
pub struct VerifiedPublisherBundle {
    manifest: NativeReleaseManifest,
    raw_manifest: Vec<u8>,
    assets: BTreeMap<String, Vec<u8>>,
    authentication: Authentication,
    release_signature: Vec<u8>,
    resource_reports: Vec<ResourceReport>,
}

impl VerifiedPublisherBundle {
    pub fn manifest(&self) -> &NativeReleaseManifest {
        &self.manifest
    }
    pub fn raw_manifest(&self) -> &[u8] {
        &self.raw_manifest
    }
    pub fn assets(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.assets
    }
    pub fn authentication(&self) -> &Authentication {
        &self.authentication
    }
    /// Authenticated Cosign proof retained with the exact verified manifest.
    pub fn release_signature(&self) -> &[u8] {
        &self.release_signature
    }
    /// One sampled resource report for each successful pinned verifier call.
    pub fn resource_reports(&self) -> &[ResourceReport] {
        &self.resource_reports
    }
}

/// Historical signature evidence only. This type deliberately exposes no
/// installation payload or native release authorization.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyPublisherInspection {
    schema: String,
    signatures_verified: bool,
    native_installation_authorized: bool,
    external_policy_sha256: crate::records::Sha256,
    release_manifest_sha256: crate::records::Sha256,
    repository: String,
    workflow: String,
    workflow_sha: String,
    source_sha: String,
    source_ref: String,
    workflow_runs: Vec<WorkflowRun>,
    attested_subjects: Vec<String>,
    cosign_subjects: Vec<String>,
    verification_mode: String,
    elapsed_seconds: serde_json::Number,
}

struct CheckedBundle {
    manifest: ParsedManifest,
    raw_manifest: Vec<u8>,
    assets: BTreeMap<String, Vec<u8>>,
    authentication: Authentication,
    release_signature: Vec<u8>,
    resource_reports: Vec<ResourceReport>,
}

struct Observation<'a, C> {
    started: Instant,
    cancelled: &'a mut C,
    resource_reports: Vec<ResourceReport>,
}
impl<C: FnMut() -> bool> Observation<'_, C> {
    fn check(&mut self) -> Result<()> {
        if (self.cancelled)() {
            return Err(Refusal::new("publisher verification cancelled"));
        }
        if self.started.elapsed() >= TOTAL_TIMEOUT {
            return Err(Refusal::new("publisher verification deadline expired"));
        }
        Ok(())
    }
}

/// Authenticate one production bundle. No shell, interpreter, user config or
/// inherited credentials are passed to the pinned verifier processes. The
/// 300-second cooperative deadline includes admission and rechecks; kernel I/O,
/// process creation, cleanup and reaping are not hard real-time guarantees.
pub fn verify_publisher_bundle(
    bundle: &Path,
    policy_path: &Path,
    cancelled: impl FnMut() -> bool,
) -> Result<VerifiedPublisherBundle> {
    let checked = check_publisher_bundle(bundle, policy_path, ReleaseFlavor::Native, cancelled)?;
    let ParsedManifest::Native(manifest) = checked.manifest else {
        return Err(Refusal::new(
            "native authentication cannot authorize a legacy release",
        ));
    };
    Ok(VerifiedPublisherBundle {
        manifest,
        raw_manifest: checked.raw_manifest,
        assets: checked.assets,
        authentication: checked.authentication,
        release_signature: checked.release_signature,
        resource_reports: checked.resource_reports,
    })
}

/// Inspect historical production signatures for compatibility evidence. This
/// does not admit release-v1 into the native production installer contract.
pub fn inspect_legacy_publisher_bundle(
    bundle: &Path,
    policy_path: &Path,
    cancelled: impl FnMut() -> bool,
) -> Result<LegacyPublisherInspection> {
    let checked = check_publisher_bundle(
        bundle,
        policy_path,
        ReleaseFlavor::LegacyInspection,
        cancelled,
    )?;
    let authentication = checked.authentication;
    let report = authentication.report;
    Ok(LegacyPublisherInspection {
        schema: "ami-rust-legacy-publisher-inspection-v1".to_owned(),
        signatures_verified: report.verified,
        native_installation_authorized: false,
        external_policy_sha256: authentication.external_policy_sha256,
        release_manifest_sha256: report.manifest_sha256,
        repository: report.repository,
        workflow: report.workflow,
        workflow_sha: report.workflow_sha,
        source_sha: report.source_sha,
        source_ref: report.source_ref,
        workflow_runs: report.workflow_runs,
        attested_subjects: report.attested_subjects,
        cosign_subjects: report.cosign_subjects,
        verification_mode: report.verification_mode,
        elapsed_seconds: report.elapsed_seconds,
    })
}

fn check_publisher_bundle(
    bundle: &Path,
    policy_path: &Path,
    flavor: ReleaseFlavor,
    mut cancelled: impl FnMut() -> bool,
) -> Result<CheckedBundle> {
    let mut observer = Observation {
        started: Instant::now(),
        cancelled: &mut cancelled,
        resource_reports: Vec::new(),
    };
    observer.check()?;
    let root = bundle_directory(bundle)?;
    if policy_path.starts_with(bundle) {
        return Err(Refusal::new(
            "publisher policy must be external to the bundle",
        ));
    }
    let policy_raw = read_protected(
        policy_path,
        JsonProfile::PublisherPolicyAndAuthenticationMetadata,
    )?;
    let policy = parse_publisher_policy(&policy_raw)?;
    for (pin, executable) in pins(&policy) {
        if Path::new(&pin.path).starts_with(bundle) {
            return Err(Refusal::new(
                "publisher tools and trust roots must be external to the bundle",
            ));
        }
        check_pin(pin, executable, &mut observer)?;
    }
    check_trusted_roots(&policy)?;
    let raw_manifest = read_bundle_file(
        &root,
        "release.json",
        JsonProfile::ReleaseManifestAndInstallReceipt.max_bytes(),
    )?;
    let manifest = match flavor {
        ReleaseFlavor::LegacyInspection => {
            ParsedManifest::Legacy(parse_release_manifest(&raw_manifest, true)?)
        }
        ReleaseFlavor::Native => {
            ParsedManifest::Native(parse_native_release_manifest(&raw_manifest, true)?)
        }
    };
    if manifest.qualification_only() {
        return Err(Refusal::new(
            "publisher verification requires a production release",
        ));
    }
    let manifest_sha256 = sha256_bytes(&raw_manifest);
    let metadata_raw = read_bundle_file(
        &root,
        ".auth/authentication.json",
        JsonProfile::PublisherPolicyAndAuthenticationMetadata.max_bytes(),
    )?;
    let metadata =
        parse_authentication_metadata(&metadata_raw, &manifest_sha256, manifest.assets(), &policy)?;
    let scan_exact: BundleScanner = match flavor {
        ReleaseFlavor::LegacyInspection => scan_bundle_exact,
        ReleaseFlavor::Native => scan_native_bundle_exact,
    };
    scan_exact(
        &root,
        &metadata.expected_files,
        &metadata.allowed_directories,
    )?;
    let inputs_raw = read_bundle_file(
        &root,
        ".auth/inputs.json",
        JsonProfile::PublisherPolicyAndAuthenticationMetadata.max_bytes(),
    )?;
    if sha256_bytes(&inputs_raw) != policy.inputs_manifest_sha256.as_str() {
        return Err(Refusal::new(
            "inputs manifest digest does not match trusted policy",
        ));
    }
    let inputs = parse_inputs_manifest(&inputs_raw)?;
    let mut retained = BTreeMap::from([
        ("release.json".to_owned(), raw_manifest),
        (".auth/authentication.json".to_owned(), metadata_raw),
        (".auth/inputs.json".to_owned(), inputs_raw),
    ]);
    for asset in manifest.assets() {
        observer.check()?;
        let raw = read_bundle_file(&root, &asset.path, 16 * 1024 * 1024)?;
        if raw.len() as u64 != asset.bytes || sha256_bytes(&raw) != asset.sha256.as_str() {
            return Err(Refusal::new(format!(
                "manifest asset bytes differ: {}",
                asset.path
            )));
        }
        retained.insert(asset.path.clone(), raw);
    }
    for (paths, profile) in [
        (&metadata.gh_bundles, JsonProfile::GithubAttestationBundle),
        (&metadata.cosign_bundles, JsonProfile::CosignBundle),
    ] {
        for path in paths.values() {
            let raw = read_bundle_file(&root, path, profile.max_bytes())?;
            require_json_object(&raw, profile, "signature bundle")?;
            retained.insert(path.clone(), raw);
        }
    }
    if retained
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        != metadata.expected_files
    {
        return Err(Refusal::new("retained publisher file set mismatch"));
    }
    let retained_bytes = retained
        .values()
        .try_fold(0_u64, |total, bytes| total.checked_add(bytes.len() as u64))
        .ok_or_else(|| Refusal::new("retained publisher byte count overflow"))?;
    check_retained_byte_limit(retained_bytes, flavor)?;
    let home = PublisherHome::new()?;
    let result = (|| {
        // Verifiers reopen these private files, never the untrusted original
        // paths. Retained bytes and the staged copy have the same identities.
        let staged_path = home.stage_bundle(&retained)?;
        let staged_root = Directory::open(&staged_path)?;
        for subject in SUBJECTS {
            recheck_subject(
                &staged_root,
                subject,
                &metadata.gh_bundles[subject],
                &retained,
            )?;
            check_pin(&policy.gh, true, &mut observer)?;
            check_pin(&policy.gh_trusted_roots, false, &mut observer)?;
            let output = run_verifier(
                &policy.gh,
                gh_arguments(&staged_path, subject, &metadata, &policy),
                &home,
                &mut observer,
            )?;
            let digest = sha256_bytes(&retained[subject]);
            check_github_output(
                &output,
                PublisherClaimContext {
                    policy: &policy,
                    run_id: &metadata.declared_run.run_id,
                    run_attempt: &metadata.declared_run.run_attempt,
                    host: metadata.declared_run.host_profile,
                    subject,
                    subject_sha256: &digest,
                    materials: &inputs.materials,
                },
            )?;
        }
        for subject in ["release.json", "sdk.tar.xz", "SHAUTIL"] {
            recheck_subject(
                &staged_root,
                subject,
                &metadata.cosign_bundles[subject],
                &retained,
            )?;
            check_pin(&policy.cosign, true, &mut observer)?;
            check_pin(&policy.cosign_trusted_root, false, &mut observer)?;
            run_verifier(
                &policy.cosign,
                cosign_arguments(&staged_path, subject, &metadata, &policy),
                &home,
                &mut observer,
            )?;
        }
        observer.check()?;
        scan_exact(
            &staged_root,
            &metadata.expected_files,
            &metadata.allowed_directories,
        )?;
        for (path, raw) in &retained {
            observer.check()?;
            if read_bundle_file(&staged_root, path, raw.len())? != *raw {
                return Err(Refusal::new("private staged publisher bytes changed"));
            }
        }
        let reopened = bundle_directory(bundle)?;
        if !same_inode(&root.metadata()?, &reopened.metadata()?) {
            return Err(Refusal::new(
                "publisher bundle root changed during verification",
            ));
        }
        scan_exact(
            &root,
            &metadata.expected_files,
            &metadata.allowed_directories,
        )?;
        for (path, raw) in &retained {
            observer.check()?;
            if read_bundle_file(&root, path, raw.len())? != *raw {
                return Err(Refusal::new(format!(
                    "publisher file changed during verification: {path}"
                )));
            }
        }
        if read_protected(
            policy_path,
            JsonProfile::PublisherPolicyAndAuthenticationMetadata,
        )? != policy_raw
        {
            return Err(Refusal::new(
                "external publisher policy changed during verification",
            ));
        }
        for (pin, executable) in pins(&policy) {
            check_pin(pin, executable, &mut observer)?;
        }
        observer.check()
    })();
    // Keep known resource evidence when a genuine verifier rejects a
    // signature, claim checks fail, or later filesystem/cleanup checks fail.
    let resource_summary = completed_resource_summary(&observer.resource_reports);
    let result = result.map_err(|error| Refusal::new(format!("{error}; {resource_summary}")));
    let cleanup = home
        .finish()
        .map_err(|error| Refusal::new(format!("{error}; {resource_summary}")));
    match (result, cleanup) {
        (Err(error), Err(cleanup)) => {
            return Err(Refusal::new(format!(
                "{error}; verifier home cleanup also failed: {cleanup}"
            )));
        }
        (Err(error), _) | (_, Err(error)) => return Err(error),
        (Ok(()), Ok(())) => {}
    }
    observer.check()?;
    let release_signature = retained
        .remove(&metadata.cosign_bundles["release.json"])
        .ok_or_else(|| Refusal::new("missing retained authenticated manifest signature"))?;
    let raw_manifest = retained
        .remove("release.json")
        .ok_or_else(|| Refusal::new("missing retained manifest"))?;
    let mut assets = BTreeMap::new();
    for asset in manifest.assets() {
        let raw = retained
            .remove(&asset.path)
            .ok_or_else(|| Refusal::new("missing retained asset"))?;
        assets.insert(asset.path.clone(), raw);
    }
    let subjects: Vec<_> = SUBJECTS.into_iter().map(str::to_owned).collect();
    let report = PublisherReport {
        schema: "ami-rust-publisher-verification-v2".to_owned(),
        verified: true,
        repository: policy.repository,
        workflow: policy.workflow,
        workflow_sha: policy.workflow_sha,
        source_sha: policy.source_sha,
        source_ref: policy.source_ref,
        manifest_sha256: parse_digest(&manifest_sha256)?,
        workflow_runs: vec![WorkflowRun {
            run_id: metadata.declared_run.run_id,
            run_attempt: metadata.declared_run.run_attempt,
            host_profile: metadata.declared_run.host_profile,
        }],
        attested_subjects: subjects.clone(),
        manifest_bound_assets: assets.keys().cloned().collect(),
        cosign_subjects: subjects,
        publisher_policy_evidence: POLICY_EVIDENCE.to_owned(),
        verification_mode: VERIFICATION_MODE.to_owned(),
        elapsed_seconds: serde_json::Number::from_f64(
            (observer.started.elapsed().as_secs_f64() * 1000.0).round() / 1000.0,
        )
        .ok_or_else(|| Refusal::new("unrepresentable verification duration"))?,
    };
    Ok(CheckedBundle {
        manifest,
        raw_manifest,
        assets,
        release_signature,
        resource_reports: observer.resource_reports,
        authentication: Authentication {
            report,
            external_policy_sha256: parse_digest(&sha256_bytes(&policy_raw))?,
        },
    })
}

fn check_retained_byte_limit(total: u64, flavor: ReleaseFlavor) -> Result<()> {
    let limit = match flavor {
        ReleaseFlavor::LegacyInspection => LEGACY_BUNDLE_BYTE_LIMIT,
        ReleaseFlavor::Native => NATIVE_BUNDLE_BYTE_LIMIT,
    };
    if total > limit {
        return Err(Refusal::new(format!(
            "retained publisher files exceed the {limit}-byte bundle profile"
        )));
    }
    Ok(())
}

fn completed_resource_summary(reports: &[ResourceReport]) -> String {
    let peak = |value: fn(&ResourceReport) -> u64| reports.iter().map(value).max().unwrap_or(0);
    format!(
        "completed verifier captures={}; sampled peaks: RSS={} workspace={} logs={} bytes; incomplete samples={}",
        reports.len(),
        peak(|r| r.peak_visible_rss_bytes),
        peak(|r| r.peak_workspace_bytes),
        peak(|r| r.peak_log_bytes),
        reports.iter().filter(|r| !r.last_sample_complete).count(),
    )
}

fn parse_digest(value: &str) -> Result<crate::records::Sha256> {
    serde_json::from_value(serde_json::Value::String(value.to_owned()))
        .map_err(|error| Refusal::new(error.to_string()))
}

fn bundle_directory(path: &Path) -> Result<Directory> {
    if !path.is_absolute()
        || fs::canonicalize(path)
            .map_err(|e| Refusal::new(format!("could not resolve publisher bundle: {e}")))?
            .as_os_str()
            != path.as_os_str()
    {
        return Err(Refusal::new(
            "publisher bundle must be a canonical absolute directory without symlinks",
        ));
    }
    Directory::open(path)
}

fn pins(policy: &PublisherPolicy) -> [(&PinnedPolicyFile, bool); 4] {
    [
        (&policy.gh, true),
        (&policy.cosign, true),
        (&policy.gh_trusted_roots, false),
        (&policy.cosign_trusted_root, false),
    ]
}

fn read_protected(path: &Path, profile: JsonProfile) -> Result<Vec<u8>> {
    read_open_regular(protected_regular_file(path, false)?, profile.max_bytes())
}

fn same_inode(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev() && before.ino() == after.ino()
}
fn same_state(before: &Metadata, after: &Metadata) -> bool {
    same_inode(before, after)
        && before.len() == after.len()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn check_pin<C: FnMut() -> bool>(
    pin: &PinnedPolicyFile,
    executable: bool,
    observer: &mut Observation<'_, C>,
) -> Result<()> {
    observer.check()?;
    let mut file = protected_regular_file(Path::new(&pin.path), executable)?;
    let before = file.metadata().map_err(|e| Refusal::new(e.to_string()))?;
    let limit = if executable {
        TOOL_MAX_BYTES
    } else {
        JsonProfile::TrustedRoot.max_bytes() as u64
    };
    if before.len() > limit {
        return Err(Refusal::new("pinned trust input exceeds its byte profile"));
    }
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        observer.check()?;
        let read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Refusal::new(format!("could not hash trust input: {e}"))),
        };
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| Refusal::new("trust input length overflow"))?;
        if total > limit {
            return Err(Refusal::new("growing trust input exceeds its byte profile"));
        }
        digest.update(&buffer[..read]);
    }
    let after = file.metadata().map_err(|e| Refusal::new(e.to_string()))?;
    let actual: [u8; 32] = digest.finalize().into();
    if total != before.len()
        || !same_state(&before, &after)
        || crate::digest::encode_hex(&actual) != pin.sha256.as_str()
    {
        return Err(Refusal::new(format!(
            "pinned trust input changed or digest mismatch: {}",
            pin.path
        )));
    }
    Ok(())
}

fn require_json_object(raw: &[u8], profile: JsonProfile, label: &str) -> Result<()> {
    if !parse_json_value(raw, profile)?.is_object() {
        return Err(Refusal::new(format!("{label} must be a JSON object")));
    }
    Ok(())
}

fn check_trusted_roots(policy: &PublisherPolicy) -> Result<()> {
    let raw = read_protected(
        Path::new(&policy.gh_trusted_roots.path),
        JsonProfile::TrustedRoot,
    )?;
    let text = std::str::from_utf8(&raw)
        .map_err(|e| Refusal::new(format!("invalid GitHub root UTF-8: {e}")))?;
    let mut count = 0;
    // Historical bytes.splitlines accepts CR, LF and CRLF; blank-line
    // stripping is ASCII-only. Unicode whitespace is not an empty JSON line.
    for line in text.split(['\r', '\n']).filter(|line| {
        !line
            .trim_matches(|c: char| c.is_ascii_whitespace())
            .is_empty()
    }) {
        require_json_object(
            line.as_bytes(),
            JsonProfile::TrustedRoot,
            "GitHub trusted root line",
        )?;
        count += 1;
    }
    if count == 0 {
        return Err(Refusal::new("GitHub trusted roots file is empty"));
    }
    require_json_object(
        &read_protected(
            Path::new(&policy.cosign_trusted_root.path),
            JsonProfile::TrustedRoot,
        )?,
        JsonProfile::TrustedRoot,
        "Sigstore trusted root",
    )
}

fn recheck_subject(
    root: &Directory,
    subject: &str,
    proof: &str,
    retained: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    for path in [subject, proof] {
        let raw = &retained[path];
        if read_bundle_file(root, path, raw.len())? != *raw {
            return Err(Refusal::new(format!(
                "publisher subject/proof changed: {path}"
            )));
        }
    }
    Ok(())
}

fn verifier_environment(home: &Path) -> BTreeMap<OsString, OsString> {
    let mut env = BTreeMap::from([
        ("PATH".into(), "/bin:/usr/bin".into()),
        ("LC_ALL".into(), "C".into()),
        ("LANG".into(), "C".into()),
        ("GH_PROMPT_DISABLED".into(), "1".into()),
        ("NO_COLOR".into(), "1".into()),
        ("COSIGN_EXPERIMENTAL".into(), "0".into()),
    ]);
    env.insert("HOME".into(), home.as_os_str().to_owned());
    env.insert("GH_CONFIG_DIR".into(), home.join("gh").into_os_string());
    env
}

fn run_verifier<C: FnMut() -> bool>(
    pin: &PinnedPolicyFile,
    args: Vec<OsString>,
    home: &PublisherHome,
    observer: &mut Observation<'_, C>,
) -> Result<Vec<u8>> {
    observer.check()?;
    let timeout = TOTAL_TIMEOUT
        .saturating_sub(observer.started.elapsed())
        .min(COMMAND_TIMEOUT);
    let spec = CommandSpec::new(
        &pin.path,
        args,
        home.path(),
        verifier_environment(home.path()),
    );
    let captured = capture_with_resources(
        &spec,
        CaptureLimits {
            timeout,
            stdout_bytes: 4 * 1024 * 1024,
            stderr_bytes: 64 * 1024,
            termination_grace: Duration::from_secs(2),
        },
        ResourceLimits {
            max_visible_rss_bytes: 4 * 1024 * 1024 * 1024,
            max_workspace_bytes: 12 * 1024 * 1024 * 1024,
            max_log_bytes: 16 * 1024 * 1024,
        },
        SampleLimits {
            max_ps_bytes: 2 * 1024 * 1024,
            max_ps_rows: 32_768,
            max_history_entries: 131_072,
            max_roots: 1,
            scan: ScanLimits { max_entries: 100_000, max_work_units: 200_001 },
        },
        &[home.path().to_path_buf()],
        &mut *observer.cancelled,
    )
    .map_err(|error| {
        let report = error.report();
        Refusal::new(format!(
            "publisher verifier failed: {error}; sampled peaks: RSS={} workspace={} logs={} bytes; last sample complete={}; observed escaped group count={}",
            report.peak_visible_rss_bytes, report.peak_workspace_bytes,
            report.peak_log_bytes, report.last_sample_complete,
            report.current_escaped_process_groups.len(),
        ))
    })?;
    observer.resource_reports.push(captured.report);
    let output = captured.process;
    if !output.status.success() {
        return Err(Refusal::new(format!(
            "publisher verifier {} failed with {}",
            Path::new(&pin.path).display(),
            output.status
        )));
    }
    observer.check()?;
    Ok(output.stdout)
}

fn gh_arguments(
    bundle: &Path,
    subject: &str,
    metadata: &AuthenticationMetadata,
    policy: &PublisherPolicy,
) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "attestation".into(),
        "verify".into(),
        bundle.join(subject).into_os_string(),
    ];
    for (flag, value) in [
        ("--repo", policy.repository.as_str()),
        ("--bundle", ""),
        ("--custom-trusted-root", &policy.gh_trusted_roots.path),
        ("--signer-digest", &policy.workflow_sha),
        ("--source-digest", &policy.source_sha),
        ("--source-ref", &policy.source_ref),
    ] {
        args.push(flag.into());
        args.push(if flag == "--bundle" {
            bundle.join(&metadata.gh_bundles[subject]).into_os_string()
        } else {
            value.into()
        });
    }
    args.extend([
        "--deny-self-hosted-runners".into(),
        "--predicate-type".into(),
        "https://slsa.dev/provenance/v1".into(),
        "--cert-identity".into(),
        policy.cert_identity.clone().into(),
        "--cert-oidc-issuer".into(),
        policy.oidc_issuer.clone().into(),
        "--format=json".into(),
    ]);
    args
}

fn cosign_arguments(
    bundle: &Path,
    subject: &str,
    metadata: &AuthenticationMetadata,
    policy: &PublisherPolicy,
) -> Vec<OsString> {
    let mut args = vec![
        "verify-blob".into(),
        bundle.join(subject).into_os_string(),
        "--bundle".into(),
        bundle
            .join(&metadata.cosign_bundles[subject])
            .into_os_string(),
    ];
    for (flag, value) in [
        ("--trusted-root", policy.cosign_trusted_root.path.as_str()),
        ("--certificate-identity", &policy.cert_identity),
        ("--certificate-oidc-issuer", &policy.oidc_issuer),
        (
            "--certificate-github-workflow-repository",
            &policy.repository,
        ),
        ("--certificate-github-workflow-ref", &policy.source_ref),
        ("--certificate-github-workflow-sha", &policy.workflow_sha),
        ("--certificate-github-workflow-trigger", "workflow_dispatch"),
    ] {
        args.push(flag.into());
        args.push(value.into());
    }
    args
}

#[cfg(test)]
#[path = "publisher_tests.rs"]
mod tests;
