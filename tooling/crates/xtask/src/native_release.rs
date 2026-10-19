//! Compose an unsigned native release-v2 candidate from retained legacy
//! assets, a native SDK-v2 draft, and one launcher for each supported host.
//!
//! This validates declared source identities and byte inventories only. It
//! does not authenticate a producer, qualify a release, sign, or publish.

use std::collections::{BTreeMap, BTreeSet};

use ami_rust_core::{
    Refusal, Result,
    compression::{DecodeLimits, copy_xz},
    digest::{is_sha256_digest, sha256_bytes},
    json::{JsonProfile, parse_json_value},
    package::check_native_header,
    publisher_tar::{
        ExpectedFile, MAX_DECODED_TAR_BYTES, MAX_FILE_BYTES, verify_publisher_sdk_tar,
    },
    records::Host,
    release_manifest::{
        NativeReleaseManifest, ReleaseManifest, parse_native_release_manifest,
        parse_release_manifest,
    },
};
use serde_json::{Map, Value};

use crate::sdk::NativeSdkDraft;

const ACCEPTED_BASELINE: &[u8] = include_bytes!("../../../fixtures/accepted-r1-inputs.json");
const BASELINE_SCHEMA: &str = "ami-rust-accepted-r1-inputs-v1";
const LEGACY_VERSION: &str = "0.1.0";
const SDK_SCHEMA: &str = "ami-rust-sdk-v2";
const SDK_DRIVER: &str = "ami-rust-native-compatibility-v1";
const RELEASE_SCHEMA: &str = "ami-rust-release-v2";
const SDK_ARCHIVE: &str = "sdk.tar.xz";
const SDK_MANIFEST: &str = "contract/sdk.json";
const SOURCE_SHA_LENGTH: usize = 40;
const MAX_XZ_BYTES: usize = 16 * 1024 * 1024;
const MAX_RELEASE_ASSET_BYTES: usize = 64 * 1024 * 1024;
const MAX_RELEASE_ASSETS: usize = 512;
const XZ_MEMORY_LIMIT_KIB: u32 = 64 * 1024;
const WORKFLOW: &str = ".github/workflows/sdk-qualify.yml";
const REPOSITORY: &str = "metaneutrons/ami-rust";
const PRODUCER_KIND: &str = "protected-github-actions";
const PRODUCER_ACCEPTANCE: &str = "R1 acceptance and publication are separate gates";
const LINUX_LAUNCHER: &str = "bin/ami-rust-linux";
const MACOS_LAUNCHER: &str = "bin/ami-rust-macos";
const HOST_LAUNCHERS: [(&str, &str, Host); 2] = [
    ("linux-x86_64", LINUX_LAUNCHER, Host::LinuxX86_64),
    ("macos-aarch64", MACOS_LAUNCHER, Host::MacosAarch64),
];

// These are the original fixed legal and corresponding-source assets that
// remain applicable to the native release. Every `licences/*` member in the
// accepted legacy manifest is added separately from this list.
const REQUIRED_LEGAL_ASSETS: [&str; 9] = [
    "LICENSE-APACHE",
    "LICENSE-MIT",
    "LICENSE.md",
    "THIRD_PARTY_NOTICES.md",
    "aros-corresponding-sources.tar.xz",
    "aros-source-inventory.json",
    "cargo-notices-corresponding-source.tar.xz",
    "cargo-source-inventory.json",
    "sbom.spdx.json",
];
const REQUIRED_UNCHANGED_ASSETS: [&str; 3] = [
    "SHAUTIL",
    "cargo-linux-x86_64.tar.xz",
    "cargo-macos-aarch64.tar.xz",
];

/// Unsigned release-v2 bytes and their complete asset map.
///
/// `qualification_only` is false because this is the production-shaped
/// manifest consumed by the native publisher. The draft itself is unsigned
/// and does not establish publisher authentication, qualification, R1
/// acceptance, or publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeReleaseDraft {
    pub manifest: Vec<u8>,
    pub assets: BTreeMap<String, Vec<u8>>,
    pub manifest_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileIdentity {
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AcceptedLegacyBaseline {
    version: String,
    release_manifest: FileIdentity,
    sdk_archive: FileIdentity,
    sdk_manifest: FileIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DeclaredProducer {
    source_sha: String,
    value: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SdkIdentity {
    version: String,
    source_identity: String,
}

/// Compose an unsigned native release-v2 candidate from accepted release-v1
/// bytes and the current native producer outputs.
///
/// `legacy_assets` contains exactly the preservation assets selected by this
/// module; it excludes the old `sdk.tar.xz`, which is replaced by `sdk`.
/// Launcher keys are the fixed host names `linux-x86_64` and `macos-aarch64`.
/// `producer_identity` is a declared protected-workflow identity, not
/// evidence that any corresponding GitHub workflow or signature is trusted.
pub fn assemble_native_release_v2(
    legacy_release_manifest: &[u8],
    legacy_assets: &BTreeMap<String, Vec<u8>>,
    sdk: &NativeSdkDraft,
    host_launchers: &BTreeMap<String, Vec<u8>>,
    producer_identity: &Value,
) -> Result<NativeReleaseDraft> {
    let baseline = load_accepted_legacy_baseline()?;
    assemble_with_baseline(
        legacy_release_manifest,
        legacy_assets,
        sdk,
        host_launchers,
        producer_identity,
        &baseline,
    )
}

/// Return the exact retained-asset selection from the immutable release.
/// Reading this list does not authorize execution of its historical drivers.
pub fn legacy_preservation_paths(raw: &[u8]) -> Result<Vec<String>> {
    verify_legacy_release_manifest(raw, &load_accepted_legacy_baseline()?)?;
    let release = parse_release_manifest(raw, true)?;
    Ok(preservation_paths(&release)?.into_iter().collect())
}

fn load_accepted_legacy_baseline() -> Result<AcceptedLegacyBaseline> {
    let value = parse_json_value(ACCEPTED_BASELINE, JsonProfile::SdkComponentManifest)?;
    if string_field(&value, "schema")? != BASELINE_SCHEMA {
        return Err(Refusal::new(
            "compiled accepted R1 baseline schema is unsupported",
        ));
    }
    let accepted_release = field(&value, "accepted_release")?;
    let version = string_field(accepted_release, "version")?.to_owned();
    if version != LEGACY_VERSION {
        return Err(Refusal::new(
            "compiled accepted release baseline is not the immutable 0.1.0 release",
        ));
    }

    let release_manifest = identity_field(
        field(accepted_release, "release_manifest")?,
        "release manifest",
    )?;
    let sdk_archive_value = field(accepted_release, "sdk_archive")?;
    if string_field(sdk_archive_value, "archive_asset_path")? != SDK_ARCHIVE {
        return Err(Refusal::new(
            "compiled accepted SDK archive path is unsupported",
        ));
    }
    let sdk_archive = identity_field(sdk_archive_value, "SDK archive")?;

    let sdk_manifest_value = field(accepted_release, "sdk_manifest")?;
    if string_field(sdk_manifest_value, "archive_path")? != SDK_MANIFEST {
        return Err(Refusal::new(
            "compiled accepted SDK manifest path is unsupported",
        ));
    }
    let sdk_manifest = identity_field(sdk_manifest_value, "SDK manifest")?;

    Ok(AcceptedLegacyBaseline {
        version,
        release_manifest,
        sdk_archive,
        sdk_manifest,
    })
}

fn identity_field(value: &Value, label: &str) -> Result<FileIdentity> {
    let bytes = number_field(value, "bytes")?;
    let sha256 = string_field(value, "sha256")?.to_owned();
    if !is_sha256_digest(&sha256) || bytes > MAX_FILE_BYTES as u64 {
        return Err(Refusal::new(format!(
            "compiled accepted {label} identity is invalid"
        )));
    }
    Ok(FileIdentity { bytes, sha256 })
}

fn assemble_with_baseline(
    legacy_release_manifest: &[u8],
    legacy_assets: &BTreeMap<String, Vec<u8>>,
    sdk: &NativeSdkDraft,
    host_launchers: &BTreeMap<String, Vec<u8>>,
    producer_identity: &Value,
    baseline: &AcceptedLegacyBaseline,
) -> Result<NativeReleaseDraft> {
    verify_legacy_release_manifest(legacy_release_manifest, baseline)?;
    let release = parse_release_manifest(legacy_release_manifest, true)?;
    let producer = validate_producer_identity(producer_identity)?;
    let sdk_identity = verify_sdk_draft(sdk, &producer.source_sha)?;
    if sdk_identity.version == LEGACY_VERSION {
        return Err(Refusal::new(
            "native release cannot reuse the immutable legacy 0.1.0 version",
        ));
    }

    let selected_legacy = verify_selected_legacy_assets(&release, legacy_assets)?;
    let launchers = verify_host_launchers(host_launchers)?;

    let mut assets = selected_legacy;
    insert_asset(&mut assets, SDK_ARCHIVE, sdk.archive.clone())?;
    for (path, contents) in launchers.values() {
        insert_asset(&mut assets, path, contents.clone())?;
    }
    check_release_asset_bounds(&assets)?;

    let mut sdk_files = Vec::with_capacity(sdk.files.len());
    for (path, contents) in &sdk.files {
        sdk_files.push(serde_json::json!({
            "path": path,
            "bytes": contents.len(),
            "sha256": sha256_bytes(contents),
        }));
    }
    let asset_rows = assets
        .iter()
        .map(|(path, contents)| {
            serde_json::json!({
                "path": path,
                "bytes": contents.len(),
                "sha256": sha256_bytes(contents),
            })
        })
        .collect::<Vec<_>>();

    let mut host_launchers_manifest = Map::new();
    for (host, path, _) in HOST_LAUNCHERS {
        let contents = &launchers
            .get(host)
            .ok_or_else(|| Refusal::new(format!("native launcher is missing for {host}")))?
            .1;
        host_launchers_manifest.insert(
            host.to_owned(),
            serde_json::json!({
                "path": path,
                "bytes": contents.len(),
                "sha256": sha256_bytes(contents),
            }),
        );
    }

    let manifest_value = serde_json::json!({
        "schema": RELEASE_SCHEMA,
        "version": sdk_identity.version.clone(),
        "qualification_only": false,
        "sdk_archive": SDK_ARCHIVE,
        "sdk_manifest_sha256": sdk.manifest_sha256.clone(),
        "assets": asset_rows,
        "sdk_files": sdk_files,
        "producer": producer.value.clone(),
        "host_launchers": Value::Object(host_launchers_manifest),
    });
    let manifest = canonical_json(&manifest_value)?;
    let parsed = parse_native_release_manifest(&manifest, true)?;
    verify_composed_release(&parsed, &assets, &sdk_identity, sdk)?;

    Ok(NativeReleaseDraft {
        manifest_sha256: sha256_bytes(&manifest),
        manifest,
        assets,
    })
}

fn verify_legacy_release_manifest(raw: &[u8], baseline: &AcceptedLegacyBaseline) -> Result<()> {
    if raw.len() as u64 != baseline.release_manifest.bytes
        || sha256_bytes(raw) != baseline.release_manifest.sha256
    {
        return Err(Refusal::new(
            "legacy release manifest differs from the accepted R1 identity",
        ));
    }
    let release = parse_release_manifest(raw, true)?;
    if release.version != baseline.version
        || release.version != LEGACY_VERSION
        || release.qualification_only
        || release.sdk_archive != SDK_ARCHIVE
        || release.sdk_manifest_sha256.as_str() != baseline.sdk_manifest.sha256
    {
        return Err(Refusal::new(
            "legacy release manifest differs from the accepted release profile",
        ));
    }
    let sdk_archive = release
        .assets
        .iter()
        .find(|asset| asset.path == SDK_ARCHIVE)
        .ok_or_else(|| Refusal::new("accepted legacy manifest omits sdk.tar.xz"))?;
    if sdk_archive.bytes != baseline.sdk_archive.bytes
        || sdk_archive.sha256.as_str() != baseline.sdk_archive.sha256
    {
        return Err(Refusal::new(
            "legacy SDK archive identity differs from the accepted R1 pin",
        ));
    }
    let sdk_manifest = release
        .sdk_files
        .iter()
        .find(|file| file.path == SDK_MANIFEST)
        .ok_or_else(|| Refusal::new("accepted legacy manifest omits contract/sdk.json"))?;
    if sdk_manifest.bytes != baseline.sdk_manifest.bytes
        || sdk_manifest.sha256.as_str() != baseline.sdk_manifest.sha256
    {
        return Err(Refusal::new(
            "legacy SDK manifest identity differs from the accepted R1 pin",
        ));
    }
    Ok(())
}

fn validate_producer_identity(value: &Value) -> Result<DeclaredProducer> {
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new("native release producer identity must be an object"))?;
    let expected = BTreeSet::from([
        "kind",
        "repository",
        "workflow",
        "source_sha",
        "workflow_sha",
        "run_id",
        "run_attempt",
        "acceptance",
    ]);
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(Refusal::new(
            "native release producer identity has missing or unknown fields",
        ));
    }
    if string_field(value, "kind")? != PRODUCER_KIND
        || string_field(value, "repository")? != REPOSITORY
        || string_field(value, "workflow")? != WORKFLOW
        || string_field(value, "acceptance")? != PRODUCER_ACCEPTANCE
    {
        return Err(Refusal::new(
            "native release producer identity is outside the protected workflow profile",
        ));
    }
    let source_sha = string_field(value, "source_sha")?.to_owned();
    let workflow_sha = string_field(value, "workflow_sha")?;
    if !is_git_identity(&source_sha) || workflow_sha != source_sha {
        return Err(Refusal::new(
            "native release source and workflow identities are invalid or incoherent",
        ));
    }
    if number_field(value, "run_id")? == 0 || number_field(value, "run_attempt")? == 0 {
        return Err(Refusal::new(
            "native release run ID and attempt must be positive integers",
        ));
    }
    Ok(DeclaredProducer {
        source_sha,
        value: value.clone(),
    })
}

fn verify_sdk_draft(sdk: &NativeSdkDraft, source_sha: &str) -> Result<SdkIdentity> {
    if sdk.archive.is_empty() || sdk.archive.len() > MAX_XZ_BYTES {
        return Err(Refusal::new(
            "native SDK archive is empty or exceeds the 16 MiB compressed limit",
        ));
    }
    let manifest_file = sdk
        .files
        .get(SDK_MANIFEST)
        .ok_or_else(|| Refusal::new("native SDK draft omits contract/sdk.json"))?;
    if manifest_file != &sdk.manifest
        || sha256_bytes(&sdk.manifest) != sdk.manifest_sha256
        || canonical_json(&parse_json_value(
            &sdk.manifest,
            JsonProfile::SdkComponentManifest,
        )?)? != sdk.manifest
    {
        return Err(Refusal::new(
            "native SDK draft manifest bytes or digest are inconsistent",
        ));
    }
    let value = parse_json_value(&sdk.manifest, JsonProfile::SdkComponentManifest)?;
    if string_field(&value, "schema")? != SDK_SCHEMA
        || string_field(&value, "driver")? != SDK_DRIVER
        || string_field(&value, "target")? != "x86_64-aros"
        || bool_field(&value, "qualification_only")?
    {
        return Err(Refusal::new(
            "native SDK draft does not use the production SDK-v2 profile",
        ));
    }
    let version = string_field(&value, "version")?.to_owned();
    if version == LEGACY_VERSION {
        return Err(Refusal::new(
            "native SDK draft cannot reuse the immutable legacy 0.1.0 version",
        ));
    }
    let source_identity = string_field(&value, "source_identity")?.to_owned();
    if !is_git_identity(&source_identity) || source_identity != source_sha {
        return Err(Refusal::new(
            "native SDK source_identity differs from the declared producer source",
        ));
    }

    verify_sdk_manifest_inventory(&value, &sdk.files)?;
    let mut decoded = Vec::new();
    copy_xz(
        &sdk.archive,
        &mut decoded,
        DecodeLimits {
            max_compressed_bytes: MAX_XZ_BYTES,
            max_decoded_bytes: MAX_DECODED_TAR_BYTES,
            max_xz_memory_kib: XZ_MEMORY_LIMIT_KIB,
        },
    )?;
    let mut digests = BTreeMap::new();
    for (path, contents) in &sdk.files {
        if contents.len() > MAX_FILE_BYTES {
            return Err(Refusal::new(format!(
                "native SDK file exceeds the publisher file limit: {path}"
            )));
        }
        digests.insert(path.as_str(), sha256_bytes(contents));
    }
    let expected = sdk
        .files
        .iter()
        .map(|(path, contents)| ExpectedFile {
            path,
            size: contents.len(),
            sha256: digests.get(path.as_str()).expect("SDK digest exists"),
        })
        .collect::<Vec<_>>();
    verify_publisher_sdk_tar(&decoded, &expected)?;
    Ok(SdkIdentity {
        version,
        source_identity,
    })
}

fn verify_sdk_manifest_inventory(
    manifest: &Value,
    sdk_files: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    let rows = field(manifest, "files")?
        .as_array()
        .ok_or_else(|| Refusal::new("native SDK manifest files must be an array"))?;
    let mut declared = BTreeMap::new();
    let mut previous_path: Option<&str> = None;
    for row in rows {
        let object = row
            .as_object()
            .ok_or_else(|| Refusal::new("native SDK file row must be an object"))?;
        require_exact_fields(object, &["path", "bytes", "sha256"], "native SDK file row")?;
        let path = string_field(row, "path")?;
        if path == SDK_MANIFEST
            || previous_path.is_some_and(|previous| previous >= path)
            || path.is_empty()
            || path.starts_with('/')
            || path.contains('\\')
            || path
                .split('/')
                .any(|component| component.is_empty() || component == "." || component == "..")
        {
            return Err(Refusal::new(
                "native SDK manifest file paths must be sorted, relative, and non-self-referential",
            ));
        }
        previous_path = Some(path);
        let bytes = number_field(row, "bytes")?;
        let sha256 = string_field(row, "sha256")?;
        if !is_sha256_digest(sha256) {
            return Err(Refusal::new(format!(
                "native SDK manifest has an invalid file digest: {path}"
            )));
        }
        let contents = sdk_files
            .get(path)
            .ok_or_else(|| Refusal::new(format!("native SDK files omit {path}")))?;
        if contents.len() as u64 != bytes || sha256_bytes(contents) != sha256 {
            return Err(Refusal::new(format!(
                "native SDK file differs from its manifest identity: {path}"
            )));
        }
        declared.insert(path.to_owned(), (bytes, sha256.to_owned()));
    }
    let archive_paths = sdk_files
        .keys()
        .filter(|path| path.as_str() != SDK_MANIFEST)
        .cloned()
        .collect::<BTreeSet<_>>();
    if archive_paths != declared.keys().cloned().collect::<BTreeSet<_>>() {
        return Err(Refusal::new(
            "native SDK manifest inventory differs from its file map",
        ));
    }
    Ok(())
}

fn verify_selected_legacy_assets(
    release: &ReleaseManifest,
    selected: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let release_assets = release
        .assets
        .iter()
        .map(|asset| (asset.path.as_str(), asset))
        .collect::<BTreeMap<_, _>>();
    let required = preservation_paths(release)?;
    let actual = selected.keys().cloned().collect::<BTreeSet<_>>();
    if actual != required {
        return Err(Refusal::new(
            "selected legacy asset set differs from the fixed native preservation profile",
        ));
    }

    let mut preserved = BTreeMap::new();
    for path in required {
        let contents = selected
            .get(&path)
            .ok_or_else(|| Refusal::new(format!("selected legacy asset is missing: {path}")))?;
        let identity = release_assets
            .get(path.as_str())
            .ok_or_else(|| Refusal::new(format!("legacy release manifest omits {path}")))?;
        if contents.len() as u64 != identity.bytes
            || sha256_bytes(contents) != identity.sha256.as_str()
        {
            return Err(Refusal::new(format!(
                "selected legacy asset differs from its accepted release identity: {path}"
            )));
        }
        preserved.insert(path, contents.clone());
    }
    Ok(preserved)
}

fn preservation_paths(release: &ReleaseManifest) -> Result<BTreeSet<String>> {
    let mut required = REQUIRED_LEGAL_ASSETS
        .into_iter()
        .chain(REQUIRED_UNCHANGED_ASSETS)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    for asset in &release.assets {
        if asset.path.starts_with("licences/") {
            required.insert(asset.path.clone());
        }
    }
    if !required.iter().any(|path| path.starts_with("licences/")) {
        return Err(Refusal::new(
            "accepted legacy release has no pinned third-party license texts",
        ));
    }
    for path in &required {
        if !release.assets.iter().any(|asset| asset.path == *path) {
            return Err(Refusal::new(format!(
                "accepted legacy release omits required preservation asset {path}"
            )));
        }
    }
    Ok(required)
}

fn verify_host_launchers(
    launchers: &BTreeMap<String, Vec<u8>>,
) -> Result<BTreeMap<String, (String, Vec<u8>)>> {
    let expected_hosts = HOST_LAUNCHERS
        .iter()
        .map(|(host, _, _)| (*host).to_owned())
        .collect::<BTreeSet<_>>();
    if launchers.keys().cloned().collect::<BTreeSet<_>>() != expected_hosts {
        return Err(Refusal::new(
            "native release requires exactly one launcher for each supported host",
        ));
    }
    let mut verified = BTreeMap::new();
    for (host, path, platform) in HOST_LAUNCHERS {
        let contents = launchers
            .get(host)
            .ok_or_else(|| Refusal::new(format!("native launcher is missing for {host}")))?;
        if contents.is_empty() || contents.len() > MAX_FILE_BYTES {
            return Err(Refusal::new(format!(
                "native launcher is empty or exceeds the 16 MiB file limit: {host}"
            )));
        }
        check_native_header(contents, platform)?;
        verified.insert(host.to_owned(), (path.to_owned(), contents.clone()));
    }
    Ok(verified)
}

fn verify_composed_release(
    release: &NativeReleaseManifest,
    assets: &BTreeMap<String, Vec<u8>>,
    sdk_identity: &SdkIdentity,
    sdk: &NativeSdkDraft,
) -> Result<()> {
    if release.version != sdk_identity.version
        || release.qualification_only
        || release.sdk_archive != SDK_ARCHIVE
        || release.sdk_manifest_sha256.as_str() != sdk.manifest_sha256
        || release.assets.len() != assets.len()
        || release.sdk_files.len() != sdk.files.len()
    {
        return Err(Refusal::new(
            "composed native release manifest does not match the candidate bytes",
        ));
    }
    for row in &release.assets {
        let contents = assets.get(&row.path).ok_or_else(|| {
            Refusal::new(format!("native release asset is missing: {}", row.path))
        })?;
        if contents.len() as u64 != row.bytes || sha256_bytes(contents) != row.sha256.as_str() {
            return Err(Refusal::new(format!(
                "native release asset identity differs from its bytes: {}",
                row.path
            )));
        }
    }
    for row in &release.sdk_files {
        let contents = sdk.files.get(&row.path).ok_or_else(|| {
            Refusal::new(format!("native release SDK inventory omits {}", row.path))
        })?;
        if contents.len() as u64 != row.bytes || sha256_bytes(contents) != row.sha256.as_str() {
            return Err(Refusal::new(format!(
                "native release SDK identity differs from its bytes: {}",
                row.path
            )));
        }
    }
    Ok(())
}

fn insert_asset(
    assets: &mut BTreeMap<String, Vec<u8>>,
    path: &str,
    contents: Vec<u8>,
) -> Result<()> {
    if assets.insert(path.to_owned(), contents).is_some() {
        return Err(Refusal::new(format!(
            "native release asset path is repeated: {path}"
        )));
    }
    Ok(())
}

fn check_release_asset_bounds(assets: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    if assets.len() > MAX_RELEASE_ASSETS {
        return Err(Refusal::new("native release exceeds the asset count limit"));
    }
    let total = assets.values().try_fold(0_usize, |total, contents| {
        if contents.len() > MAX_FILE_BYTES {
            return Err(Refusal::new(
                "native release asset exceeds the 16 MiB per-file limit",
            ));
        }
        total
            .checked_add(contents.len())
            .ok_or_else(|| Refusal::new("native release asset total overflow"))
    })?;
    if total > MAX_RELEASE_ASSET_BYTES {
        return Err(Refusal::new(
            "native release assets exceed the 64 MiB total limit",
        ));
    }
    Ok(())
}

fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    write_canonical_json(value, &mut output)?;
    output.push(b'\n');
    Ok(output)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_writer(output, value)
                .map_err(|error| Refusal::new(format!("could not encode JSON value: {error}")))?;
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(object) => {
            output.push(b'{');
            let mut entries = object.iter().collect::<Vec<_>>();
            entries.sort_unstable_by_key(|(key, _)| *key);
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)
                    .map_err(|error| Refusal::new(format!("could not encode JSON key: {error}")))?;
                output.push(b':');
                write_canonical_json(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn require_exact_fields(object: &Map<String, Value>, fields: &[&str], label: &str) -> Result<()> {
    let expected = fields.iter().copied().collect::<BTreeSet<_>>();
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(Refusal::new(format!(
            "{label} has missing or unknown fields"
        )));
    }
    Ok(())
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value
        .as_object()
        .and_then(|object| object.get(name))
        .ok_or_else(|| Refusal::new(format!("native release input is missing {name}")))
}

fn string_field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    field(value, name)?
        .as_str()
        .ok_or_else(|| Refusal::new(format!("native release input {name} must be a string")))
}

fn number_field(value: &Value, name: &str) -> Result<u64> {
    field(value, name)?.as_u64().ok_or_else(|| {
        Refusal::new(format!(
            "native release input {name} must be an unsigned integer"
        ))
    })
}

fn bool_field(value: &Value, name: &str) -> Result<bool> {
    field(value, name)?
        .as_bool()
        .ok_or_else(|| Refusal::new(format!("native release input {name} must be a boolean")))
}

fn is_git_identity(value: &str) -> bool {
    value.len() == SOURCE_SHA_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{
        ACCEPTED_BASELINE, AcceptedLegacyBaseline, FileIdentity, LEGACY_VERSION, LINUX_LAUNCHER,
        MACOS_LAUNCHER, NativeReleaseDraft, REQUIRED_LEGAL_ASSETS, REQUIRED_UNCHANGED_ASSETS,
        SDK_ARCHIVE, SDK_DRIVER, SDK_MANIFEST, SDK_SCHEMA, assemble_with_baseline, canonical_json,
        verify_legacy_release_manifest,
    };
    use crate::sdk::NativeSdkDraft;
    use ami_rust_core::{
        digest::sha256_bytes,
        json::{JsonProfile, parse_json_value},
        release_manifest::parse_native_release_manifest,
    };
    use lzma_rust2::{XzOptions, XzWriter};
    use serde_json::{Map, Value, json};
    use std::{collections::BTreeMap, io::Write};
    use tar::{Builder, Header};

    const SOURCE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

    struct Fixture {
        legacy_manifest: Vec<u8>,
        legacy_assets: BTreeMap<String, Vec<u8>>,
        sdk: NativeSdkDraft,
        launchers: BTreeMap<String, Vec<u8>>,
        producer: Value,
        baseline: AcceptedLegacyBaseline,
    }

    fn fixture() -> Fixture {
        let mut legacy_assets = BTreeMap::new();
        for path in REQUIRED_LEGAL_ASSETS
            .into_iter()
            .chain(REQUIRED_UNCHANGED_ASSETS)
            .chain(["licences/000-fixture-license.txt"])
        {
            legacy_assets.insert(
                path.to_owned(),
                format!("original bytes for {path}\n").into_bytes(),
            );
        }
        let legacy_sdk_archive = b"original legacy SDK archive".to_vec();
        let legacy_sdk_manifest = b"original SDK manifest bytes".to_vec();
        let mut old_assets = legacy_assets
            .iter()
            .map(|(path, contents)| {
                json!({"path":path,"bytes":contents.len(),"sha256":sha256_bytes(contents)})
            })
            .collect::<Vec<_>>();
        old_assets.push(json!({
            "path":SDK_ARCHIVE,"bytes":legacy_sdk_archive.len(),"sha256":sha256_bytes(&legacy_sdk_archive)
        }));
        old_assets.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
        let old_value = json!({
            "schema":"ami-rust-release-v1",
            "version":LEGACY_VERSION,
            "qualification_only":false,
            "sdk_archive":SDK_ARCHIVE,
            "sdk_manifest_sha256":sha256_bytes(&legacy_sdk_manifest),
            "assets":old_assets,
            "sdk_files":[{"path":SDK_MANIFEST,"bytes":legacy_sdk_manifest.len(),"sha256":sha256_bytes(&legacy_sdk_manifest)}],
            "producer":{"fixture":true},
            "host_interpreters":{
                "linux-x86_64":{"sha256":"1".repeat(64)},
                "macos-aarch64":{"sha256":"2".repeat(64)}
            }
        });
        let legacy_manifest = canonical_json(&old_value).expect("encode old release fixture");
        let baseline = AcceptedLegacyBaseline {
            version: LEGACY_VERSION.to_owned(),
            release_manifest: FileIdentity {
                bytes: legacy_manifest.len() as u64,
                sha256: sha256_bytes(&legacy_manifest),
            },
            sdk_archive: FileIdentity {
                bytes: legacy_sdk_archive.len() as u64,
                sha256: sha256_bytes(&legacy_sdk_archive),
            },
            sdk_manifest: FileIdentity {
                bytes: legacy_sdk_manifest.len() as u64,
                sha256: sha256_bytes(&legacy_sdk_manifest),
            },
        };
        let sdk = sdk_fixture(SOURCE_SHA, "0.2.0");
        let launchers = BTreeMap::from([
            ("linux-x86_64".to_owned(), linux_header()),
            ("macos-aarch64".to_owned(), macos_header()),
        ]);
        let producer = json!({
            "kind":"protected-github-actions",
            "repository":"metaneutrons/ami-rust",
            "workflow":".github/workflows/sdk-qualify.yml",
            "source_sha":SOURCE_SHA,
            "workflow_sha":SOURCE_SHA,
            "run_id":123456789,
            "run_attempt":2,
            "acceptance":"R1 acceptance and publication are separate gates"
        });
        Fixture {
            legacy_manifest,
            legacy_assets,
            sdk,
            launchers,
            producer,
            baseline,
        }
    }

    fn sdk_fixture(source_sha: &str, version: &str) -> NativeSdkDraft {
        let mut files = BTreeMap::new();
        files.insert("README.md".to_owned(), b"Native SDK fixture\n".to_vec());
        let mut profiles = Map::new();
        for (host, triple) in [
            ("linux-x86_64", "x86_64-unknown-linux-gnu"),
            ("macos-aarch64", "aarch64-apple-darwin"),
        ] {
            let mut components = Map::new();
            for component in ["rust", "cargo", "toolchain", "collector", "csdk", "vendor"] {
                let path = format!("host/profiles/{host}/{component}.json");
                let contents = format!("{{\"component\":\"{component}\"}}\n").into_bytes();
                let digest = sha256_bytes(&contents);
                files.insert(path.clone(), contents);
                components.insert(
                    component.to_owned(),
                    json!({"manifest":path,"sha256":digest}),
                );
            }
            profiles.insert(
                host.to_owned(),
                json!({
                    "rust_host":triple,
                    "cargo_metadata_mode":"ami-rust-reproducible-cross-v1",
                    "cargo_binary":"bin/cargo",
                    "collector_binary":"bin/aros-collect",
                    "components":Value::Object(components)
                }),
            );
        }
        let rows = files
            .iter()
            .map(|(path, contents)| {
                json!({"path":path,"bytes":contents.len(),"sha256":sha256_bytes(contents)})
            })
            .collect::<Vec<_>>();
        let manifest_value = json!({
            "schema":SDK_SCHEMA,
            "version":version,
            "qualification_only":false,
            "driver":SDK_DRIVER,
            "target":"x86_64-aros",
            "files":rows,
            "profiles":Value::Object(profiles),
            "rust_commit":"330d317121e16b5db8e5adc63595910528ff2ee7",
            "rust_llvm":"23.1.1",
            "source_date_epoch":1791936000,
            "source_identity":source_sha,
            "build":{"jobs":2,"rss_bytes":4294967296_u64,"seconds":1200,"workspace_bytes":12884901888_u64,"log_bytes":16777216},
            "host_capacity":{"schema":"ami-rust-host-capacity-v1","ram_minimum_bytes":6442450944_u64,"disk_free_minimum_bytes":25769803776_u64},
            "application_memory_policy":"ami-rust-application-memory-policy-v1"
        });
        let manifest = canonical_json(&manifest_value).expect("encode SDK fixture manifest");
        files.insert(SDK_MANIFEST.to_owned(), manifest.clone());

        let mut builder = Builder::new(Vec::new());
        for (path, contents) in &files {
            let mut header = Header::new_gnu();
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(1_791_936_000);
            header.set_size(contents.len() as u64);
            header.set_cksum();
            builder
                .append_data(&mut header, path, contents.as_slice())
                .expect("append SDK fixture member");
        }
        let tar = builder.into_inner().expect("finish SDK fixture TAR");
        let mut encoder = XzWriter::new(Vec::new(), XzOptions::with_preset(6))
            .expect("initialize SDK fixture XZ");
        encoder.write_all(&tar).expect("encode SDK fixture XZ");
        let archive = encoder.finish().expect("finish SDK fixture XZ");
        NativeSdkDraft {
            manifest_sha256: sha256_bytes(&manifest),
            manifest,
            archive,
            files,
        }
    }

    fn linux_header() -> Vec<u8> {
        let mut bytes = vec![0_u8; 120];
        bytes[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        bytes[7] = 0;
        put_u16(&mut bytes, 16, 2);
        put_u16(&mut bytes, 18, 62);
        put_u32(&mut bytes, 20, 1);
        put_u64(&mut bytes, 24, 0x400000);
        put_u64(&mut bytes, 32, 64);
        put_u16(&mut bytes, 52, 64);
        put_u16(&mut bytes, 54, 56);
        put_u16(&mut bytes, 56, 1);
        put_u32(&mut bytes, 64, 1);
        put_u32(&mut bytes, 68, 1);
        put_u64(&mut bytes, 72, 120);
        put_u64(&mut bytes, 80, 0x400000);
        put_u64(&mut bytes, 96, 0);
        put_u64(&mut bytes, 104, 1);
        bytes
    }

    fn macos_header() -> Vec<u8> {
        let mut bytes = vec![0_u8; 64];
        bytes[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        put_u32(&mut bytes, 4, 0x0100_000c);
        put_u32(&mut bytes, 12, 2);
        bytes
    }

    fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn compose(fixture: &Fixture) -> NativeReleaseDraft {
        assemble_with_baseline(
            &fixture.legacy_manifest,
            &fixture.legacy_assets,
            &fixture.sdk,
            &fixture.launchers,
            &fixture.producer,
            &fixture.baseline,
        )
        .expect("compose native release fixture")
    }

    #[test]
    fn compiled_release_baseline_pins_immutable_legacy_inputs() {
        let value = parse_json_value(ACCEPTED_BASELINE, JsonProfile::SdkComponentManifest)
            .expect("parse accepted R1 inputs");
        let accepted = &value["accepted_release"];
        assert_eq!(accepted["version"], LEGACY_VERSION);
        assert_eq!(accepted["release_manifest"]["bytes"], 33_761);
        assert_eq!(
            accepted["release_manifest"]["sha256"],
            "cd9adcf44264c86eb0bdea35bb16c02529c8ae5b051d4a9dd3aa6007f0972b65"
        );
        assert_eq!(
            accepted["sdk_archive"]["sha256"],
            "087f69659f1d0d5136b2c07789488c23dd52ca7b38b21579183620a5fbc61dd4"
        );
        assert_eq!(accepted["sdk_manifest"]["archive_path"], SDK_MANIFEST);
    }

    #[test]
    fn composes_deterministic_unsigned_release_and_preserves_selected_assets() {
        let fixture = fixture();
        let first = compose(&fixture);
        let second = compose(&fixture);
        assert_eq!(first, second);
        assert_eq!(first.manifest_sha256, sha256_bytes(&first.manifest));
        for (path, bytes) in &fixture.legacy_assets {
            assert_eq!(first.assets.get(path), Some(bytes));
        }
        assert_eq!(first.assets.get(SDK_ARCHIVE), Some(&fixture.sdk.archive));
        assert_eq!(
            first.assets.get(LINUX_LAUNCHER),
            fixture.launchers.get("linux-x86_64")
        );
        assert_eq!(
            first.assets.get(MACOS_LAUNCHER),
            fixture.launchers.get("macos-aarch64")
        );

        let manifest = parse_native_release_manifest(&first.manifest, true)
            .expect("parse generated release-v2");
        assert_eq!(manifest.version, "0.2.0");
        assert!(!manifest.qualification_only);
        assert_eq!(manifest.assets.len(), first.assets.len());
        assert_eq!(manifest.host_launchers.linux_x86_64.path, LINUX_LAUNCHER);
        assert_eq!(manifest.host_launchers.macos_aarch64.path, MACOS_LAUNCHER);
        let value = parse_json_value(
            &first.manifest,
            JsonProfile::ReleaseManifestAndInstallReceipt,
        )
        .expect("parse release JSON");
        assert!(value.get("host_interpreters").is_none());
    }

    #[test]
    fn rejects_changed_original_inputs_and_missing_or_wrong_host_launchers() {
        let fixture = fixture();

        let mut changed_manifest = fixture.legacy_manifest.clone();
        changed_manifest.push(b' ');
        assert!(verify_legacy_release_manifest(&changed_manifest, &fixture.baseline).is_err());

        let mut changed_assets = fixture.legacy_assets.clone();
        changed_assets.insert("LICENSE-APACHE".to_owned(), b"changed legal text".to_vec());
        assert!(
            assemble_with_baseline(
                &fixture.legacy_manifest,
                &changed_assets,
                &fixture.sdk,
                &fixture.launchers,
                &fixture.producer,
                &fixture.baseline,
            )
            .is_err()
        );

        let mut missing_host = fixture.launchers.clone();
        missing_host.remove("macos-aarch64");
        assert!(
            assemble_with_baseline(
                &fixture.legacy_manifest,
                &fixture.legacy_assets,
                &fixture.sdk,
                &missing_host,
                &fixture.producer,
                &fixture.baseline,
            )
            .is_err()
        );

        let mut wrong_host = fixture.launchers.clone();
        wrong_host.insert("linux-x86_64".to_owned(), macos_header());
        assert!(
            assemble_with_baseline(
                &fixture.legacy_manifest,
                &fixture.legacy_assets,
                &fixture.sdk,
                &wrong_host,
                &fixture.producer,
                &fixture.baseline,
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_sdk_manifest_archive_and_source_mismatches() {
        let fixture = fixture();
        let mut changed_files = fixture.sdk.clone();
        changed_files
            .files
            .insert("README.md".to_owned(), b"changed after archive\n".to_vec());
        assert!(
            assemble_with_baseline(
                &fixture.legacy_manifest,
                &fixture.legacy_assets,
                &changed_files,
                &fixture.launchers,
                &fixture.producer,
                &fixture.baseline,
            )
            .is_err()
        );

        let mut changed_archive = fixture.sdk.clone();
        changed_archive.archive[0] ^= 0xff;
        assert!(
            assemble_with_baseline(
                &fixture.legacy_manifest,
                &fixture.legacy_assets,
                &changed_archive,
                &fixture.launchers,
                &fixture.producer,
                &fixture.baseline,
            )
            .is_err()
        );

        let mut wrong_source = fixture.producer.clone();
        wrong_source["source_sha"] = json!("f".repeat(40));
        wrong_source["workflow_sha"] = json!("f".repeat(40));
        assert!(
            assemble_with_baseline(
                &fixture.legacy_manifest,
                &fixture.legacy_assets,
                &fixture.sdk,
                &fixture.launchers,
                &wrong_source,
                &fixture.baseline,
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_the_legacy_version_and_noncoherent_producer_identity() {
        let mut fixture = fixture();
        fixture.sdk = sdk_fixture(SOURCE_SHA, LEGACY_VERSION);
        assert!(
            assemble_with_baseline(
                &fixture.legacy_manifest,
                &fixture.legacy_assets,
                &fixture.sdk,
                &fixture.launchers,
                &fixture.producer,
                &fixture.baseline,
            )
            .is_err()
        );

        let mut wrong_workflow = fixture.producer.clone();
        wrong_workflow["workflow_sha"] = json!("f".repeat(40));
        assert!(
            assemble_with_baseline(
                &fixture.legacy_manifest,
                &fixture.legacy_assets,
                &sdk_fixture(SOURCE_SHA, "0.2.0"),
                &fixture.launchers,
                &wrong_workflow,
                &fixture.baseline,
            )
            .is_err()
        );
    }
}
