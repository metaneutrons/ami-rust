//! Pure parsing and relationship checks for the native public-package records.
//!
//! These types contain untrusted claims. Parsing does not inspect files, verify
//! publisher signatures, or authorize installation or publication.

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::value::RawValue;
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Refusal, Result,
    digest::is_sha256_digest,
    inventory::FileIdentity,
    json::{JsonProfile, parse_json_value},
    publisher_tar::validate_portable_path,
    records::{Host, Sha256},
    workflow_counter::PositiveCounter,
};

const INPUTS_SCHEMA: &str = "ami-rust-package-inputs-v2";
const INVENTORY_SCHEMA: &str = "ami-rust-package-inventory-v2";
const PROOFS_SCHEMA: &str = "ami-rust-package-proofs-v2";
const REPOSITORY: &str = "metaneutrons/ami-rust";
const PACKAGE_JSON_LIMIT: usize = 2 * 1024 * 1024;
const ASSET_BYTES_LIMIT: u64 = 128 * 1024 * 1024;
const ASSET_TOTAL_BYTES_LIMIT: u64 = 256 * 1024 * 1024;
const INVENTORY_TOTAL_BYTES_LIMIT: u64 = 512 * 1024 * 1024;
const PROOF_BYTES_LIMIT: u64 = 16 * 1024 * 1024;
const PROOFS_TOTAL_BYTES_LIMIT: u64 = 64 * 1024 * 1024;
const PROOF_COUNT_LIMIT: usize = 64;

/// A path, byte count, and digest claimed by a native package record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AssetPin {
    pub path: String,
    pub bytes: u64,
    pub sha256: Sha256,
}

/// One proof-file identity pinned for an authenticated asset subject.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProofIdentity {
    pub bytes: u64,
    pub sha256: Sha256,
}

/// Structurally validated native package inputs. The values remain claims
/// until callers independently verify their corresponding files and proofs.
#[derive(Clone, Debug, Serialize)]
pub struct NativePackagePins {
    pub cli_version: String,
    pub sdk_version: String,
    pub packaging_revision: u32,
    pub package_version: String,
    pub packaging_tag: String,
    pub sdk_tag: String,
    pub repository: String,
    pub source_commit: String,
    pub source_tree: String,
    pub sdk_run_id: PositiveCounter,
    pub sdk_run_attempt: PositiveCounter,
    pub manifest_sha256: Sha256,
    pub transport_sha256: Sha256,
    pub assets: Vec<AssetPin>,
    pub hosts: BTreeMap<String, Host>,
    pub maintainer: String,
    pub publisher_proofs: BTreeMap<String, Vec<ProofIdentity>>,
    pub host: Host,
    pub launchers: BTreeMap<String, AssetPin>,
    pub core_sha256: Sha256,
}

/// Structurally validated package file inventory. Ownership, file identity,
/// and role-specific permissions are checked by the filesystem caller.
#[derive(Clone, Debug)]
pub struct NativePackageInventory {
    pub cli_version: String,
    pub sdk_version: String,
    pub package_version: String,
    pub host: Host,
    pub files: Vec<FileIdentity>,
}

#[derive(Deserialize)]
struct CounterEnvelope<'a> {
    #[serde(borrow)]
    sdk_run_id: &'a RawValue,
    #[serde(borrow)]
    sdk_run_attempt: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativePackagePinsWire {
    schema: String,
    cli_version: String,
    sdk_version: String,
    packaging_revision: u32,
    package_version: String,
    packaging_tag: String,
    sdk_tag: String,
    repository: String,
    source_commit: String,
    source_tree: String,
    sdk_run_id: u64,
    sdk_run_attempt: u64,
    manifest_sha256: Sha256,
    transport_sha256: Sha256,
    assets: Vec<AssetPinWire>,
    hosts: BTreeMap<String, Host>,
    maintainer: String,
    publisher_proofs: BTreeMap<String, Vec<ProofIdentityWire>>,
    host: Host,
    launchers: BTreeMap<String, AssetPinWire>,
    core_sha256: Sha256,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetPinWire {
    path: String,
    bytes: u64,
    sha256: Sha256,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofIdentityWire {
    bytes: u64,
    sha256: Sha256,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativePackageInventoryWire {
    schema: String,
    cli_version: String,
    sdk_version: String,
    package_version: String,
    host: Host,
    files: Vec<InventoryFileWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryFileWire {
    path: String,
    bytes: u64,
    sha256: String,
    mode: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativePackageProofsWire {
    schema: String,
    subjects: BTreeMap<String, Vec<PackageProofWire>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageProofWire {
    path: String,
    bytes: u64,
    sha256: Sha256,
}

/// Parse native inputs while preserving exact positive workflow counters up to
/// Python's historical 4,300-digit JSON-integer boundary. A bounded borrowed
/// prepass locates the counter tokens; the strict duplicate/depth/schema pass
/// then runs over a temporary copy with only over-u64 counter lexemes replaced.
pub fn parse_native_package_pins(raw: &[u8]) -> Result<NativePackagePins> {
    let profile = package_profile();
    crate::json::check_raw_value_prepass(raw, profile)?;

    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    deserializer.disable_recursion_limit();
    let counters = CounterEnvelope::deserialize(&mut deserializer)
        .map_err(|error| Refusal::new(format!("invalid package workflow counters: {error}")))?;
    deserializer
        .end()
        .map_err(|error| Refusal::new(format!("invalid package workflow counters: {error}")))?;

    let (validation_copy, exact_counters) = crate::workflow_counter::validation_copy(
        raw,
        &[counters.sdk_run_id, counters.sdk_run_attempt],
    )?;
    let mut exact_counters = exact_counters.into_iter();
    let sdk_run_id = exact_counters
        .next()
        .ok_or_else(|| Refusal::new("package SDK run ID is missing"))?;
    let sdk_run_attempt = exact_counters
        .next()
        .ok_or_else(|| Refusal::new("package SDK run attempt is missing"))?;
    if exact_counters.next().is_some() {
        return Err(Refusal::new("unexpected package SDK workflow counter"));
    }

    let value = parse_json_value(&validation_copy, profile)?;
    let wire: NativePackagePinsWire = deserialize_schema(value, INPUTS_SCHEMA)?;
    let _schema = wire.schema;
    // The typed copy's small numeric values are only structural placeholders;
    // reading them here makes explicit that they are not the returned claims.
    let _counter_placeholders = (wire.sdk_run_id, wire.sdk_run_attempt);
    if wire.packaging_revision == 0 {
        return Err(Refusal::new("packaging revision must be positive"));
    }
    validate_version_tuple(
        &wire.cli_version,
        &wire.sdk_version,
        wire.packaging_revision,
        &wire.package_version,
        &wire.packaging_tag,
        &wire.sdk_tag,
    )?;
    if wire.repository != REPOSITORY {
        return Err(Refusal::new("package repository identity mismatch"));
    }
    validate_commit(&wire.source_commit, "source commit")?;
    validate_commit(&wire.source_tree, "source tree")?;
    if wire.maintainer.is_empty()
        || wire.maintainer.trim() != wire.maintainer
        || wire
            .maintainer
            .chars()
            .any(|character| matches!(character, '\r' | '\n' | '\0'))
    {
        return Err(Refusal::new(
            "maintainer must be trimmed nonempty single-line text",
        ));
    }
    validate_hosts(&wire.hosts)?;
    validate_asset_pins(&wire.assets, &wire.sdk_version, &wire.transport_sha256)?;
    validate_launcher_pins(&wire.launchers, &wire.core_sha256)?;
    let expected_subjects = proof_subjects(&wire.sdk_version);
    let publisher_proofs = wire
        .publisher_proofs
        .into_iter()
        .map(|(subject, rows)| (subject, rows.into_iter().map(ProofIdentity::from).collect()))
        .collect::<BTreeMap<_, Vec<_>>>();
    validate_pinned_proof_identities(&publisher_proofs, &expected_subjects)?;

    Ok(NativePackagePins {
        cli_version: wire.cli_version,
        sdk_version: wire.sdk_version,
        packaging_revision: wire.packaging_revision,
        package_version: wire.package_version,
        packaging_tag: wire.packaging_tag,
        sdk_tag: wire.sdk_tag,
        repository: wire.repository,
        source_commit: wire.source_commit,
        source_tree: wire.source_tree,
        sdk_run_id,
        sdk_run_attempt,
        manifest_sha256: wire.manifest_sha256,
        transport_sha256: wire.transport_sha256,
        assets: wire.assets.into_iter().map(AssetPin::from).collect(),
        hosts: wire.hosts,
        maintainer: wire.maintainer,
        publisher_proofs,
        host: wire.host,
        launchers: wire
            .launchers
            .into_iter()
            .map(|(name, pin)| (name, pin.into()))
            .collect(),
        core_sha256: wire.core_sha256,
    })
}

/// Parse a native package inventory, requiring a mode on every row and
/// rejecting portable-path aliases before the filesystem layer sees it.
pub fn parse_native_package_inventory(raw: &[u8]) -> Result<NativePackageInventory> {
    let mut wire: NativePackageInventoryWire =
        decode_document(raw, INVENTORY_SCHEMA, package_profile())?;
    let _schema = wire.schema;
    if !valid_cli_version(&wire.cli_version)
        || !valid_sdk_version(&wire.sdk_version)
        || !valid_package_version(&wire.sdk_version, &wire.package_version)
    {
        return Err(Refusal::new(
            "package inventory version identity is invalid",
        ));
    }
    if wire.files.is_empty() {
        return Err(Refusal::new("package inventory file list is empty"));
    }
    let mut total = 0_u64;
    let mut paths = Vec::with_capacity(wire.files.len());
    for file in &wire.files {
        validate_portable_file_path(&file.path, "package inventory")?;
        if file.path.eq_ignore_ascii_case("inventory.json") {
            return Err(Refusal::new("package inventory must not list itself"));
        }
        if file.bytes > ASSET_BYTES_LIMIT {
            return Err(Refusal::new("package inventory file exceeds 128 MiB"));
        }
        if !is_sha256_digest(&file.sha256) || file.mode & !0o7777 != 0 {
            return Err(Refusal::new("package inventory digest or mode is invalid"));
        }
        total = total
            .checked_add(file.bytes)
            .ok_or_else(|| Refusal::new("package inventory byte total overflow"))?;
        if total > INVENTORY_TOTAL_BYTES_LIMIT {
            return Err(Refusal::new("package inventory exceeds 512 MiB"));
        }
        paths.push(file.path.as_str());
    }
    validate_path_set(paths, "package inventory")?;

    Ok(NativePackageInventory {
        cli_version: wire.cli_version,
        sdk_version: wire.sdk_version,
        package_version: wire.package_version,
        host: wire.host,
        files: wire
            .files
            .drain(..)
            .map(|file| FileIdentity {
                path: file.path,
                bytes: file.bytes,
                sha256: file.sha256,
                mode: Some(file.mode),
            })
            .collect(),
    })
}

/// Parse proof snapshots and bind their distinct file identities to the
/// per-subject digests already pinned by native inputs.
pub fn parse_native_package_proofs(
    raw: &[u8],
    pins: &NativePackagePins,
) -> Result<BTreeMap<String, AssetPin>> {
    let wire: NativePackageProofsWire = decode_document(raw, PROOFS_SCHEMA, package_profile())?;
    let _schema = wire.schema;
    let expected_subjects = proof_subjects(&pins.sdk_version);
    validate_pinned_proof_identities(&pins.publisher_proofs, &expected_subjects)?;
    if wire.subjects.keys().cloned().collect::<BTreeSet<_>>() != expected_subjects {
        return Err(Refusal::new(
            "package proofs do not cover the exact pinned subjects",
        ));
    }

    let mut all_paths = BTreeMap::<String, ProofIdentity>::new();
    let mut folded_paths = BTreeMap::<String, String>::new();
    let mut digest_bytes = BTreeMap::<String, u64>::new();
    let mut total_distinct_bytes = 0_u64;
    for (subject, rows) in wire.subjects {
        if !(1..=PROOF_COUNT_LIMIT).contains(&rows.len()) {
            return Err(Refusal::new(
                "each package subject requires 1 to 64 proof files",
            ));
        }
        let mut subject_paths = BTreeSet::new();
        let mut subject_folded = BTreeSet::new();
        let mut subject_digests = BTreeSet::new();
        let mut identities = BTreeSet::new();
        for row in rows {
            validate_flat_proof_path(&row.path)?;
            if row.bytes == 0 || row.bytes > PROOF_BYTES_LIMIT {
                return Err(Refusal::new(
                    "package proof size must be between 1 and 16 MiB",
                ));
            }
            if !subject_paths.insert(row.path.clone())
                || !subject_folded.insert(row.path.to_ascii_lowercase())
                || !subject_digests.insert(row.sha256.as_str().to_owned())
            {
                return Err(Refusal::new(
                    "package subject repeats a proof path or digest",
                ));
            }
            let identity = ProofIdentity {
                bytes: row.bytes,
                sha256: row.sha256,
            };
            if !identities.insert(identity_key(&identity)) {
                return Err(Refusal::new("package subject repeats a proof identity"));
            }
            if pins.publisher_proofs[&subject]
                .iter()
                .all(|expected| identity_key(expected) != identity_key(&identity))
            {
                return Err(Refusal::new(format!(
                    "package proof identity is not pinned for subject {subject}"
                )));
            }
            let digest = identity.sha256.as_str().to_owned();
            if digest_bytes
                .insert(digest, identity.bytes)
                .is_some_and(|previous| previous != identity.bytes)
            {
                return Err(Refusal::new(
                    "one proof digest has conflicting byte lengths",
                ));
            }
            let folded = row.path.to_ascii_lowercase();
            if folded_paths
                .get(&folded)
                .is_some_and(|previous| previous != &row.path)
            {
                return Err(Refusal::new(
                    "package proofs contain case-folded path aliases",
                ));
            }
            folded_paths.insert(folded, row.path.clone());
            if let Some(previous) = all_paths.get(&row.path) {
                if previous != &identity {
                    return Err(Refusal::new(
                        "cross-subject proof path has conflicting identity",
                    ));
                }
            } else {
                total_distinct_bytes = total_distinct_bytes
                    .checked_add(identity.bytes)
                    .ok_or_else(|| Refusal::new("package proof byte total overflow"))?;
                if total_distinct_bytes > PROOFS_TOTAL_BYTES_LIMIT {
                    return Err(Refusal::new("distinct package proofs exceed 64 MiB"));
                }
                all_paths.insert(row.path, identity);
            }
        }
        let pinned = pins.publisher_proofs[&subject]
            .iter()
            .map(identity_key)
            .collect::<BTreeSet<_>>();
        if identities != pinned {
            return Err(Refusal::new(format!(
                "package proof identity set differs from pins for subject {subject}"
            )));
        }
    }

    Ok(all_paths
        .into_iter()
        .map(|(path, identity)| {
            (
                path.clone(),
                AssetPin {
                    path,
                    bytes: identity.bytes,
                    sha256: identity.sha256,
                },
            )
        })
        .collect())
}

fn package_profile() -> JsonProfile {
    JsonProfile::PackageMetadataStateSelection
}

fn decode_document<T: DeserializeOwned>(
    raw: &[u8],
    schema: &str,
    profile: JsonProfile,
) -> Result<T> {
    if raw.len() > PACKAGE_JSON_LIMIT {
        return Err(Refusal::new("package JSON exceeds 2 MiB"));
    }
    let value = parse_json_value(raw, profile)?;
    deserialize_schema(value, schema)
}

fn deserialize_schema<T: DeserializeOwned>(value: serde_json::Value, schema: &str) -> Result<T> {
    let actual = value
        .as_object()
        .and_then(|object| object.get("schema"))
        .and_then(serde_json::Value::as_str);
    if actual != Some(schema) {
        return Err(Refusal::new(format!(
            "unsupported or missing schema; expected {schema}"
        )));
    }
    T::deserialize(value).map_err(|error| Refusal::new(format!("invalid {schema}: {error}")))
}

fn validate_version_tuple(
    cli_version: &str,
    sdk_version: &str,
    revision: u32,
    package_version: &str,
    packaging_tag: &str,
    sdk_tag: &str,
) -> Result<()> {
    if !valid_cli_version(cli_version)
        || !valid_sdk_version(sdk_version)
        || !valid_package_version(sdk_version, package_version)
        || package_version != format!("{sdk_version}-{revision}")
        || packaging_tag != format!("v{sdk_version}+packaging.{revision}")
        || sdk_tag != format!("v{sdk_version}")
    {
        return Err(Refusal::new(
            "package version or tag identity is inconsistent",
        ));
    }
    Ok(())
}

fn valid_cli_version(value: &str) -> bool {
    let (core, prerelease) = match value.split_once('-') {
        Some((core, prerelease)) => (core, Some(prerelease)),
        None => (value, None),
    };
    if !valid_numeric_core(core) {
        return false;
    }
    let Some(prerelease) = prerelease else {
        return true;
    };
    if prerelease.is_empty() {
        return false;
    }
    prerelease.split('.').all(|identifier| {
        !identifier.is_empty()
            && identifier
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && !(identifier.len() > 1
                && identifier.starts_with('0')
                && identifier.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

fn valid_sdk_version(value: &str) -> bool {
    valid_numeric_core(value)
}

fn valid_numeric_core(value: &str) -> bool {
    let mut parts = value.split('.');
    let components = [parts.next(), parts.next(), parts.next()];
    if parts.next().is_some() {
        return false;
    }
    components.into_iter().all(|part| {
        part.is_some_and(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && !(part.len() > 1 && part.starts_with('0'))
        })
    })
}

fn valid_package_version(sdk_version: &str, package_version: &str) -> bool {
    let Some(revision) = package_version.strip_prefix(&format!("{sdk_version}-")) else {
        return false;
    };
    !revision.is_empty()
        && !revision.starts_with('0')
        && revision.bytes().all(|byte| byte.is_ascii_digit())
        && revision.parse::<u32>().is_ok_and(|revision| revision > 0)
}

fn validate_commit(value: &str, label: &str) -> Result<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Refusal::new(format!(
            "{label} must contain 40 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn validate_hosts(hosts: &BTreeMap<String, Host>) -> Result<()> {
    let expected = BTreeMap::from([
        ("apt".to_owned(), Host::LinuxX86_64),
        ("homebrew".to_owned(), Host::MacosAarch64),
    ]);
    if hosts != &expected {
        return Err(Refusal::new(
            "package host matrix must bind apt and Homebrew hosts",
        ));
    }
    Ok(())
}

fn asset_names(sdk_version: &str) -> BTreeSet<String> {
    let payload = format!("ami-rust-{sdk_version}-release.tar.xz");
    let transport = format!("ami-rust-{sdk_version}-transport.json");
    BTreeSet::from([
        "SHA256SUMS".to_owned(),
        payload.clone(),
        format!("{payload}.sigstore.json"),
        format!("{payload}.spdx.json"),
        transport.clone(),
        format!("{transport}.sigstore.json"),
    ])
}

fn proof_subjects(sdk_version: &str) -> BTreeSet<String> {
    let payload = format!("ami-rust-{sdk_version}-release.tar.xz");
    let transport = format!("ami-rust-{sdk_version}-transport.json");
    BTreeSet::from([
        "SHA256SUMS".to_owned(),
        payload.clone(),
        format!("{payload}.spdx.json"),
        transport,
    ])
}

fn validate_asset_pins(
    assets: &[AssetPinWire],
    sdk_version: &str,
    transport: &Sha256,
) -> Result<()> {
    if assets.len() != 6 {
        return Err(Refusal::new(
            "native package inputs require exactly six assets",
        ));
    }
    let mut total = 0_u64;
    for asset in assets {
        validate_portable_file_path(&asset.path, "package asset")?;
        if asset.bytes > ASSET_BYTES_LIMIT {
            return Err(Refusal::new("package asset exceeds 128 MiB"));
        }
        total = total
            .checked_add(asset.bytes)
            .ok_or_else(|| Refusal::new("package asset byte total overflow"))?;
    }
    if total > ASSET_TOTAL_BYTES_LIMIT {
        return Err(Refusal::new("package assets exceed 256 MiB"));
    }
    validate_path_set(
        assets.iter().map(|asset| asset.path.as_str()),
        "package assets",
    )?;
    let actual = assets
        .iter()
        .map(|asset| asset.path.clone())
        .collect::<BTreeSet<_>>();
    if actual != asset_names(sdk_version) {
        return Err(Refusal::new(
            "package assets do not match the exact release filenames",
        ));
    }
    let transport_name = format!("ami-rust-{sdk_version}-transport.json");
    let transport_asset = assets
        .iter()
        .find(|asset| asset.path == transport_name)
        .ok_or_else(|| Refusal::new("package transport asset is missing"))?;
    if &transport_asset.sha256 != transport {
        return Err(Refusal::new("transport digest differs from its asset pin"));
    }
    Ok(())
}

fn validate_launcher_pins(
    launchers: &BTreeMap<String, AssetPinWire>,
    core_sha256: &Sha256,
) -> Result<()> {
    let required = ["ami-rust", "cargo-ami"];
    if launchers.len() != required.len()
        || required.iter().any(|name| !launchers.contains_key(*name))
    {
        return Err(Refusal::new(
            "package launchers must contain ami-rust and cargo-ami",
        ));
    }
    let mut shared: Option<(&u64, &Sha256)> = None;
    for name in required {
        let launcher = &launchers[name];
        let expected_path = format!("bin/{name}");
        if launcher.path != expected_path
            || launcher.bytes == 0
            || launcher.bytes > ASSET_BYTES_LIMIT
            || &launcher.sha256 != core_sha256
        {
            return Err(Refusal::new(format!(
                "invalid package launcher pin: {name}"
            )));
        }
        if let Some((bytes, digest)) = shared {
            if launcher.bytes != *bytes || &launcher.sha256 != digest {
                return Err(Refusal::new(
                    "package launchers do not share identical bytes",
                ));
            }
        } else {
            shared = Some((&launcher.bytes, &launcher.sha256));
        }
    }
    Ok(())
}

fn validate_pinned_proof_identities(
    proofs: &BTreeMap<String, Vec<ProofIdentity>>,
    expected_subjects: &BTreeSet<String>,
) -> Result<()> {
    if proofs.keys().cloned().collect::<BTreeSet<_>>() != *expected_subjects {
        return Err(Refusal::new(
            "publisher proof pins do not cover exact asset subjects",
        ));
    }
    for (subject, rows) in proofs {
        if !(1..=PROOF_COUNT_LIMIT).contains(&rows.len()) {
            return Err(Refusal::new(
                "each publisher subject requires 1 to 64 proof pins",
            ));
        }
        let mut identities = BTreeSet::new();
        for row in rows {
            if row.bytes == 0 || row.bytes > PROOF_BYTES_LIMIT {
                return Err(Refusal::new(
                    "publisher proof pin size must be between 1 and 16 MiB",
                ));
            }
            if !identities.insert(identity_key(row)) {
                return Err(Refusal::new(format!(
                    "publisher proof pins repeat an identity for {subject}"
                )));
            }
        }
    }
    Ok(())
}

fn identity_key(identity: &ProofIdentity) -> (u64, String) {
    (identity.bytes, identity.sha256.as_str().to_owned())
}

fn validate_portable_file_path(path: &str, label: &str) -> Result<()> {
    let normalized = validate_portable_path(path.as_bytes())
        .map_err(|error| Refusal::new(format!("invalid {label} path: {error}")))?;
    if normalized != path {
        return Err(Refusal::new(format!("invalid {label} path")));
    }
    Ok(())
}

fn validate_flat_proof_path(path: &str) -> Result<()> {
    validate_portable_file_path(path, "proof")?;
    if path.contains('/') {
        return Err(Refusal::new(
            "package proof path must be one portable filename",
        ));
    }
    Ok(())
}

fn validate_path_set<'a>(paths: impl IntoIterator<Item = &'a str>, label: &str) -> Result<()> {
    let mut exact = BTreeSet::new();
    let mut folded = BTreeSet::new();
    let mut directory_spellings = BTreeMap::<String, String>::new();
    let mut path_rows = Vec::new();
    for path in paths {
        if !exact.insert(path.to_owned()) || !folded.insert(path.to_ascii_lowercase()) {
            return Err(Refusal::new(format!(
                "{label} contain duplicate or case-colliding paths"
            )));
        }
        let mut exact_prefix = String::new();
        for component in path.split('/') {
            if !exact_prefix.is_empty() {
                exact_prefix.push('/');
            }
            exact_prefix.push_str(component);
            let folded_prefix = exact_prefix.to_ascii_lowercase();
            if directory_spellings
                .get(&folded_prefix)
                .is_some_and(|previous| previous != &exact_prefix)
            {
                return Err(Refusal::new(format!(
                    "{label} contain case-folded directory aliases"
                )));
            }
            directory_spellings.insert(folded_prefix, exact_prefix.clone());
        }
        path_rows.push(path.to_owned());
    }
    for path in &path_rows {
        for (offset, _) in path.match_indices('/') {
            if folded.contains(&path[..offset].to_ascii_lowercase()) {
                return Err(Refusal::new(format!(
                    "{label} contain a file/directory ancestor conflict"
                )));
            }
        }
    }
    Ok(())
}

impl From<AssetPinWire> for AssetPin {
    fn from(value: AssetPinWire) -> Self {
        Self {
            path: value.path,
            bytes: value.bytes,
            sha256: value.sha256,
        }
    }
}

impl From<ProofIdentityWire> for ProofIdentity {
    fn from(value: ProofIdentityWire) -> Self {
        Self {
            bytes: value.bytes,
            sha256: value.sha256,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Map, Value, json};

    fn valid_inputs_value() -> Value {
        let sdk_version = "1.2.3";
        let payload = format!("ami-rust-{sdk_version}-release.tar.xz");
        let transport = format!("ami-rust-{sdk_version}-transport.json");
        let names = [
            "SHA256SUMS".to_owned(),
            payload.clone(),
            format!("{payload}.sigstore.json"),
            format!("{payload}.spdx.json"),
            transport.clone(),
            format!("{transport}.sigstore.json"),
        ];
        let assets = names
            .iter()
            .enumerate()
            .map(|(index, path)| {
                json!({
                    "path": path,
                    "bytes": 100 + index as u64,
                    "sha256": format!("{:064x}", index + 1),
                })
            })
            .collect::<Vec<_>>();
        let transport_sha256 = format!("{:064x}", 5);

        let mut publisher_proofs = BTreeMap::<String, Value>::new();
        for (index, subject) in proof_subjects(sdk_version).into_iter().enumerate() {
            publisher_proofs.insert(
                subject,
                json!([{
                    "bytes": 32,
                    "sha256": format!("{:064x}", index + 16),
                }]),
            );
        }
        let hosts = BTreeMap::from([
            ("apt".to_owned(), json!("linux-x86_64")),
            ("homebrew".to_owned(), json!("macos-aarch64")),
        ]);
        let launchers = BTreeMap::from([
            (
                "ami-rust".to_owned(),
                json!({
                    "path": "bin/ami-rust",
                    "bytes": 4096,
                    "sha256": "f".repeat(64),
                }),
            ),
            (
                "cargo-ami".to_owned(),
                json!({
                    "path": "bin/cargo-ami",
                    "bytes": 4096,
                    "sha256": "f".repeat(64),
                }),
            ),
        ]);
        json!({
            "schema": INPUTS_SCHEMA,
            "cli_version": "0.3.0-rc.2",
            "sdk_version": sdk_version,
            "packaging_revision": 4,
            "package_version": "1.2.3-4",
            "packaging_tag": "v1.2.3+packaging.4",
            "sdk_tag": "v1.2.3",
            "repository": REPOSITORY,
            "source_commit": "a".repeat(40),
            "source_tree": "b".repeat(40),
            "sdk_run_id": 7,
            "sdk_run_attempt": 2,
            "manifest_sha256": "c".repeat(64),
            "transport_sha256": transport_sha256,
            "assets": assets,
            "hosts": hosts,
            "maintainer": "Fabian Schmieder",
            "publisher_proofs": publisher_proofs,
            "host": "linux-x86_64",
            "launchers": launchers,
            "core_sha256": "f".repeat(64),
        })
    }

    fn valid_inputs_raw() -> Vec<u8> {
        serde_json::to_vec(&valid_inputs_value()).unwrap()
    }

    fn valid_proofs_value(pins: &NativePackagePins) -> Value {
        let mut subjects = Map::new();
        for (index, (subject, identities)) in pins.publisher_proofs.iter().enumerate() {
            let rows = identities
                .iter()
                .enumerate()
                .map(|(row, identity)| {
                    json!({
                        "path": format!("proof-{index}-{row}.json"),
                        "bytes": identity.bytes,
                        "sha256": identity.sha256.as_str(),
                    })
                })
                .collect::<Vec<_>>();
            subjects.insert(subject.clone(), json!(rows));
        }
        json!({"schema": PROOFS_SCHEMA, "subjects": subjects})
    }

    fn valid_inventory_value() -> Value {
        json!({
            "schema": INVENTORY_SCHEMA,
            "cli_version": "0.3.0-rc.2",
            "sdk_version": "1.2.3",
            "package_version": "1.2.3-4",
            "host": "macos-aarch64",
            "files": [{
                "path": "bin/ami-rust",
                "bytes": 4096,
                "sha256": "a".repeat(64),
                "mode": 493,
            }],
        })
    }

    fn replace_number(raw: &mut String, field: &str, replacement: &str) {
        let key = format!("\"{field}\":");
        let value_start = raw.find(&key).unwrap() + key.len();
        let value_end = value_start
            + raw[value_start..]
                .bytes()
                .take_while(u8::is_ascii_digit)
                .count();
        raw.replace_range(value_start..value_end, replacement);
    }

    #[test]
    fn parses_native_pins_and_binds_version_hosts_assets_and_static_launchers() {
        let pins = parse_native_package_pins(&valid_inputs_raw()).unwrap();
        assert_eq!(pins.cli_version, "0.3.0-rc.2");
        assert_eq!(pins.sdk_version, "1.2.3");
        assert_eq!(pins.sdk_run_id.as_decimal(), "7");
        assert_eq!(pins.sdk_run_attempt.as_decimal(), "2");
        assert_eq!(pins.assets.len(), 6);
        assert_eq!(pins.launchers.len(), 2);
        assert_eq!(pins.hosts["apt"], Host::LinuxX86_64);
        assert_eq!(pins.hosts["homebrew"], Host::MacosAarch64);
    }

    #[test]
    fn rejects_inconsistent_version_host_launcher_asset_and_repository_claims() {
        let mut cases = Vec::new();
        let mut value = valid_inputs_value();
        value["sdk_tag"] = json!("v1.2.4");
        cases.push(value);
        let mut value = valid_inputs_value();
        value["hosts"]["apt"] = json!("macos-aarch64");
        cases.push(value);
        let mut value = valid_inputs_value();
        value["launchers"]["cargo-ami"]["sha256"] = json!("e".repeat(64));
        cases.push(value);
        let mut value = valid_inputs_value();
        value["assets"][0]["path"] = json!("EXTRA");
        cases.push(value);
        let mut value = valid_inputs_value();
        value["repository"] = json!("example.invalid/ami-rust");
        cases.push(value);
        for value in cases {
            assert!(parse_native_package_pins(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }

    #[test]
    fn preserves_4300_digit_exact_sdk_counters_and_rejects_4301() {
        let mut raw = String::from_utf8(valid_inputs_raw()).unwrap();
        replace_number(&mut raw, "sdk_run_id", &"9".repeat(4_300));
        let pins = parse_native_package_pins(raw.as_bytes()).unwrap();
        assert_eq!(pins.sdk_run_id.as_decimal(), "9".repeat(4_300));

        let mut raw = String::from_utf8(valid_inputs_raw()).unwrap();
        replace_number(&mut raw, "sdk_run_attempt", &"8".repeat(4_301));
        assert!(parse_native_package_pins(raw.as_bytes()).is_err());

        let mut raw = String::from_utf8(valid_inputs_raw()).unwrap();
        replace_number(&mut raw, "sdk_run_id", "1.0");
        assert!(parse_native_package_pins(raw.as_bytes()).is_err());
    }

    #[test]
    fn rejects_duplicate_and_unknown_native_input_fields() {
        let valid = String::from_utf8(valid_inputs_raw()).unwrap();
        let duplicate = valid.replacen('{', "{\"cli_version\":\"0.3.0-rc.2\",", 1);
        assert!(parse_native_package_pins(duplicate.as_bytes()).is_err());
        let unknown = valid.replacen("{", "{\"extra\":true,", 1);
        assert!(parse_native_package_pins(unknown.as_bytes()).is_err());
        let mut trailing = valid.into_bytes();
        trailing.extend_from_slice(b" false");
        assert!(parse_native_package_pins(&trailing).is_err());
    }

    #[test]
    fn accepts_asset_and_launcher_limits_then_refuses_one_byte_over() {
        let mut value = valid_inputs_value();
        for (index, asset) in value["assets"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .enumerate()
        {
            asset["bytes"] = json!(if index < 2 { ASSET_BYTES_LIMIT } else { 0 });
        }
        assert!(parse_native_package_pins(&serde_json::to_vec(&value).unwrap()).is_ok());
        value["assets"][0]["bytes"] = json!(ASSET_BYTES_LIMIT + 1);
        assert!(parse_native_package_pins(&serde_json::to_vec(&value).unwrap()).is_err());

        let mut value = valid_inputs_value();
        value["launchers"]["ami-rust"]["bytes"] = json!(ASSET_BYTES_LIMIT);
        value["launchers"]["cargo-ami"]["bytes"] = json!(ASSET_BYTES_LIMIT);
        assert!(parse_native_package_pins(&serde_json::to_vec(&value).unwrap()).is_ok());
        value["launchers"]["ami-rust"]["bytes"] = json!(ASSET_BYTES_LIMIT + 1);
        assert!(parse_native_package_pins(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn accepts_exact_two_mib_input_document_and_refuses_one_byte_more() {
        let mut value = valid_inputs_value();
        let initial = serde_json::to_vec(&value).unwrap().len();
        let padding = PACKAGE_JSON_LIMIT - initial;
        value["maintainer"] = json!("m".repeat("Fabian Schmieder".len() + padding));
        let raw = serde_json::to_vec(&value).unwrap();
        assert_eq!(raw.len(), PACKAGE_JSON_LIMIT);
        assert!(parse_native_package_pins(&raw).is_ok());
        let mut oversized = raw;
        oversized.insert(oversized.len() - 1, b' ');
        assert!(parse_native_package_pins(&oversized).is_err());
    }

    #[test]
    fn parses_proof_rows_and_enforces_exact_identity_sets_and_shared_path_identity() {
        let pins_raw = valid_inputs_raw();
        let pins = parse_native_package_pins(&pins_raw).unwrap();
        let proof_raw = serde_json::to_vec(&valid_proofs_value(&pins)).unwrap();
        let parsed = parse_native_package_proofs(&proof_raw, &pins).unwrap();
        assert_eq!(parsed.len(), 4);

        let mut shared_pins_value = valid_inputs_value();
        for proof_rows in shared_pins_value["publisher_proofs"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            proof_rows[0]["bytes"] = json!(9);
            proof_rows[0]["sha256"] = json!("d".repeat(64));
        }
        let shared_pins =
            parse_native_package_pins(&serde_json::to_vec(&shared_pins_value).unwrap()).unwrap();
        let mut shared_proofs = valid_proofs_value(&shared_pins);
        for rows in shared_proofs["subjects"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            rows[0]["path"] = json!("same-proof.json");
        }
        let shared =
            parse_native_package_proofs(&serde_json::to_vec(&shared_proofs).unwrap(), &shared_pins)
                .unwrap();
        assert_eq!(shared.len(), 1);
        let mut case_alias_proofs = shared_proofs.clone();
        case_alias_proofs["subjects"]
            .as_object_mut()
            .unwrap()
            .values_mut()
            .nth(1)
            .unwrap()[0]["path"] = json!("SAME-proof.json");
        assert!(
            parse_native_package_proofs(
                &serde_json::to_vec(&case_alias_proofs).unwrap(),
                &shared_pins,
            )
            .is_err()
        );

        let mut conflicting_pins_value = shared_pins_value;
        let conflicting_keys = conflicting_pins_value["publisher_proofs"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let conflicting_subject = &conflicting_keys[1];
        conflicting_pins_value["publisher_proofs"][conflicting_subject][0]["bytes"] = json!(10);
        conflicting_pins_value["publisher_proofs"][conflicting_subject][0]["sha256"] =
            json!("e".repeat(64));
        let conflicting_pins =
            parse_native_package_pins(&serde_json::to_vec(&conflicting_pins_value).unwrap())
                .unwrap();
        let mut conflicting_proofs = valid_proofs_value(&conflicting_pins);
        for rows in conflicting_proofs["subjects"]
            .as_object_mut()
            .unwrap()
            .values_mut()
        {
            rows[0]["path"] = json!("same-proof.json");
        }
        assert!(
            parse_native_package_proofs(
                &serde_json::to_vec(&conflicting_proofs).unwrap(),
                &conflicting_pins,
            )
            .is_err()
        );
    }

    #[test]
    fn proof_size_count_alias_and_digest_conflicts_are_refused() {
        let mut pins_value = valid_inputs_value();
        let first_subject = pins_value["publisher_proofs"]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        pins_value["publisher_proofs"][&first_subject][0]["bytes"] = json!(PROOF_BYTES_LIMIT);
        let pins = parse_native_package_pins(&serde_json::to_vec(&pins_value).unwrap()).unwrap();
        let mut proofs = valid_proofs_value(&pins);
        proofs["subjects"][&first_subject][0]["bytes"] = json!(PROOF_BYTES_LIMIT);
        assert!(parse_native_package_proofs(&serde_json::to_vec(&proofs).unwrap(), &pins).is_ok());
        proofs["subjects"][&first_subject][0]["bytes"] = json!(PROOF_BYTES_LIMIT + 1);
        assert!(parse_native_package_proofs(&serde_json::to_vec(&proofs).unwrap(), &pins).is_err());

        let pins = parse_native_package_pins(&valid_inputs_raw()).unwrap();
        let mut proofs = valid_proofs_value(&pins);
        let first_subject = proofs["subjects"]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        let first = proofs["subjects"][&first_subject][0].clone();
        proofs["subjects"][&first_subject]
            .as_array_mut()
            .unwrap()
            .push(first);
        assert!(parse_native_package_proofs(&serde_json::to_vec(&proofs).unwrap(), &pins).is_err());
    }

    #[test]
    fn proof_count_and_distinct_path_byte_limits_accept_exact_boundaries() {
        let mut pins_value = valid_inputs_value();
        let subjects = pins_value["publisher_proofs"].as_object_mut().unwrap();
        let keys = subjects.keys().cloned().collect::<Vec<_>>();
        for (subject_index, subject) in keys.iter().enumerate() {
            let rows = subjects.get_mut(subject).unwrap().as_array_mut().unwrap();
            rows[0]["bytes"] = json!(PROOF_BYTES_LIMIT);
            rows[0]["sha256"] = json!(format!("{:064x}", subject_index + 50));
        }
        let pins = parse_native_package_pins(&serde_json::to_vec(&pins_value).unwrap()).unwrap();
        let proofs = valid_proofs_value(&pins);
        assert_eq!(
            parse_native_package_proofs(&serde_json::to_vec(&proofs).unwrap(), &pins)
                .unwrap()
                .len(),
            4
        );

        // Isolate the 64-row boundary from the independent total-byte bound
        // already exercised above: adding rows to a full 64 MiB set must fail.
        for subject in &keys {
            pins_value["publisher_proofs"][subject][0]["bytes"] = json!(1);
        }
        let first_subject = keys[0].clone();
        let more_rows = pins_value["publisher_proofs"][&first_subject]
            .as_array_mut()
            .unwrap();
        for index in 1..PROOF_COUNT_LIMIT {
            more_rows.push(json!({
                "bytes": 1,
                "sha256": format!("{:064x}", index + 100),
            }));
        }
        let pins = parse_native_package_pins(&serde_json::to_vec(&pins_value).unwrap()).unwrap();
        let proofs = valid_proofs_value(&pins);
        assert!(parse_native_package_proofs(&serde_json::to_vec(&proofs).unwrap(), &pins).is_ok());

        pins_value["publisher_proofs"][&first_subject]
            .as_array_mut()
            .unwrap()
            .push(json!({"bytes": 1, "sha256": "e".repeat(64)}));
        assert!(parse_native_package_pins(&serde_json::to_vec(&pins_value).unwrap()).is_err());
    }

    #[test]
    fn distinct_proof_paths_may_total_exactly_64_mib_but_not_one_byte_more() {
        let mut pins_value = valid_inputs_value();
        let subjects = pins_value["publisher_proofs"].as_object_mut().unwrap();
        let keys = subjects.keys().cloned().collect::<Vec<_>>();
        for (index, subject) in keys.iter().enumerate() {
            let row = &mut subjects.get_mut(subject).unwrap()[0];
            row["bytes"] = json!(PROOF_BYTES_LIMIT);
            row["sha256"] = json!(format!("{:064x}", index + 20));
        }
        let pins = parse_native_package_pins(&serde_json::to_vec(&pins_value).unwrap()).unwrap();
        let proofs = valid_proofs_value(&pins);
        assert!(parse_native_package_proofs(&serde_json::to_vec(&proofs).unwrap(), &pins).is_ok());

        let extra = json!({"bytes": 1, "sha256": "e".repeat(64)});
        pins_value["publisher_proofs"][&keys[0]]
            .as_array_mut()
            .unwrap()
            .push(extra);
        let pins = parse_native_package_pins(&serde_json::to_vec(&pins_value).unwrap()).unwrap();
        let proofs = valid_proofs_value(&pins);
        assert!(parse_native_package_proofs(&serde_json::to_vec(&proofs).unwrap(), &pins).is_err());
    }

    #[test]
    fn rejects_proof_subject_set_mismatch_and_conflicting_digest_lengths() {
        let pins = parse_native_package_pins(&valid_inputs_raw()).unwrap();
        let mut proofs = valid_proofs_value(&pins);
        let subjects = proofs["subjects"].as_object_mut().unwrap();
        let keys = subjects.keys().cloned().collect::<Vec<_>>();
        let second = keys[1].clone();
        subjects.remove(&second);
        subjects.insert("unexpected-subject".to_owned(), json!([]));
        assert!(parse_native_package_proofs(&serde_json::to_vec(&proofs).unwrap(), &pins).is_err());

        let mut conflicting_pins_value = valid_inputs_value();
        let conflicting_subjects = conflicting_pins_value["publisher_proofs"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        conflicting_pins_value["publisher_proofs"][&conflicting_subjects[0]][0]["sha256"] =
            json!("a".repeat(64));
        conflicting_pins_value["publisher_proofs"][&conflicting_subjects[0]][0]["bytes"] =
            json!(500);
        conflicting_pins_value["publisher_proofs"][&conflicting_subjects[1]][0]["sha256"] =
            json!("a".repeat(64));
        conflicting_pins_value["publisher_proofs"][&conflicting_subjects[1]][0]["bytes"] =
            json!(999);
        let conflicting_pins =
            parse_native_package_pins(&serde_json::to_vec(&conflicting_pins_value).unwrap())
                .unwrap();
        let mut conflicting_proofs = valid_proofs_value(&conflicting_pins);
        let subjects = conflicting_proofs["subjects"].as_object_mut().unwrap();
        let first = &conflicting_subjects[0];
        let second = &conflicting_subjects[1];
        subjects.get_mut(first).unwrap()[0]["sha256"] = json!("a".repeat(64));
        subjects.get_mut(first).unwrap()[0]["bytes"] = json!(500);
        subjects.get_mut(second).unwrap()[0]["sha256"] = json!("a".repeat(64));
        subjects.get_mut(second).unwrap()[0]["bytes"] = json!(999);
        assert!(
            parse_native_package_proofs(
                &serde_json::to_vec(&conflicting_proofs).unwrap(),
                &conflicting_pins,
            )
            .is_err()
        );
    }

    #[test]
    fn parses_mode_required_inventory_and_enforces_portable_paths_and_512_mib_bound() {
        let inventory =
            parse_native_package_inventory(&serde_json::to_vec(&valid_inventory_value()).unwrap())
                .unwrap();
        assert_eq!(inventory.files.len(), 1);
        assert_eq!(inventory.files[0].mode, Some(0o755));

        let mut value = valid_inventory_value();
        value["files"][0]["bytes"] = json!(ASSET_BYTES_LIMIT);
        let additional = ["bin/cargo-ami", "include/header.h", "share/data.bin"];
        for path in additional {
            value["files"].as_array_mut().unwrap().push(json!({
                "path": path,
                "bytes": ASSET_BYTES_LIMIT,
                "sha256": "b".repeat(64),
                "mode": 420,
            }));
        }
        assert!(parse_native_package_inventory(&serde_json::to_vec(&value).unwrap()).is_ok());
        value["files"][3]["bytes"] = json!(ASSET_BYTES_LIMIT + 1);
        assert!(parse_native_package_inventory(&serde_json::to_vec(&value).unwrap()).is_err());

        let mut missing_mode = valid_inventory_value();
        missing_mode["files"][0]
            .as_object_mut()
            .unwrap()
            .remove("mode");
        assert!(
            parse_native_package_inventory(&serde_json::to_vec(&missing_mode).unwrap()).is_err()
        );

        for paths in [
            vec!["bin/tool", "BIN/other"],
            vec!["bin", "bin/tool"],
            vec!["inventory.json"],
            vec!["../escape"],
        ] {
            let mut bad = valid_inventory_value();
            bad["files"] = json!(
                paths
                    .into_iter()
                    .map(|path| json!({"path":path,"bytes":1,"sha256":"c".repeat(64),"mode":420}))
                    .collect::<Vec<_>>()
            );
            assert!(parse_native_package_inventory(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
    }

    #[test]
    fn schema_and_semver_controls_are_closed() {
        assert!(valid_cli_version("1.2.3"));
        assert!(valid_cli_version("1.2.3-rc.1"));
        assert!(!valid_cli_version("01.2.3"));
        assert!(!valid_cli_version("1.2.3-01"));
        assert!(!valid_cli_version("1.2.3+build"));
        assert!(!valid_sdk_version("1.2"));
        assert!(!valid_sdk_version("1.2.3-alpha"));

        let mut invalid_schema = valid_inventory_value();
        invalid_schema["schema"] = json!("ami-rust-package-inventory-v1");
        assert!(
            parse_native_package_inventory(&serde_json::to_vec(&invalid_schema).unwrap()).is_err()
        );
    }
}
