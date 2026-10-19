//! Draft an unsigned native SDK-v2 archive from retained legacy SDK members.
//!
//! The accepted R1 baseline is compiled into this tool. Target source files and
//! host component manifests are copied byte-for-byte only when their sizes and
//! SHA-256 digests match that baseline. This module does not authenticate the
//! producer, qualify a release, or publish the returned draft.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

use ami_rust_core::{
    Refusal, Result,
    digest::{is_sha256_digest, sha256_bytes},
    json::{JsonProfile, parse_json_value},
    publisher_tar::{
        ExpectedFile, MAX_DECODED_TAR_BYTES, MAX_FILE_BYTES, verify_publisher_sdk_tar,
    },
};
use lzma_rust2::{XzOptions, XzWriter};
use serde_json::{Map, Value};

const ACCEPTED_BASELINE: &[u8] = include_bytes!("../../../fixtures/accepted-r1-inputs.json");
const BASELINE_SCHEMA: &str = "ami-rust-accepted-r1-inputs-v1";
const BASELINE_VERSION: &str = "0.1.0";
const SDK_SCHEMA: &str = "ami-rust-sdk-v2";
const SDK_DRIVER: &str = "ami-rust-native-compatibility-v1";
const SDK_MANIFEST_PATH: &str = "contract/sdk.json";
const README_PATH: &str = "README.md";
const LEGAL_NOTICE_PATHS: [&str; 4] = [
    "LICENSE-APACHE",
    "LICENSE-MIT",
    "LICENSE.md",
    "THIRD_PARTY_NOTICES.md",
];
const BUILD_PROFILE: [(&str, u64); 5] = [
    ("jobs", 2),
    ("rss_bytes", 4 * 1024 * 1024 * 1024),
    ("seconds", 1_200),
    ("workspace_bytes", 12 * 1024 * 1024 * 1024),
    ("log_bytes", 16 * 1024 * 1024),
];
const HOST_CAPACITY: [(&str, u64); 2] = [
    ("ram_minimum_bytes", 6 * 1024 * 1024 * 1024),
    ("disk_free_minimum_bytes", 24 * 1024 * 1024 * 1024),
];
const HOSTS: [(&str, &str); 2] = [
    ("linux-x86_64", "x86_64-unknown-linux-gnu"),
    ("macos-aarch64", "aarch64-apple-darwin"),
];
const COMPONENTS: [&str; 6] = ["rust", "cargo", "toolchain", "collector", "csdk", "vendor"];
const EXPECTED_TARGET_INPUTS: usize = 56;
const EXPECTED_COMPONENT_MANIFESTS: usize = HOSTS.len() * COMPONENTS.len();
const TAR_BLOCK_BYTES: usize = 512;
const TAR_RECORD_BYTES: usize = 10_240;
const XZ_COMPRESSED_LIMIT: usize = 16 * 1024 * 1024;
const XZ_PRESET: u32 = 6;

/// An unsigned, locally assembled native SDK-v2 draft.
///
/// `archive` is a canonical flat USTAR archive compressed as one XZ stream.
/// Its `contract/sdk.json` manifest omits its own inventory row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeSdkDraft {
    pub manifest: Vec<u8>,
    pub archive: Vec<u8>,
    pub files: BTreeMap<String, Vec<u8>>,
    pub manifest_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileIdentity {
    path: String,
    bytes: usize,
    sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AcceptedBaseline {
    rust_commit: String,
    rust_llvm: String,
    source_date_epoch: u64,
    target_inputs: BTreeMap<String, FileIdentity>,
    component_manifests: BTreeMap<String, FileIdentity>,
}

/// Assemble a native SDK-v2 draft from bytes retained from the legacy SDK.
///
/// `source_identity` is syntax-checked only; trusted workflow code must bind it
/// to the protected producer source before using this draft in a release.
pub fn assemble_native_sdk(
    source_members: &BTreeMap<String, Vec<u8>>,
    source_identity: &str,
    version: &str,
) -> Result<NativeSdkDraft> {
    validate_source_identity(source_identity)?;
    validate_version(version)?;
    let baseline = load_accepted_baseline()?;
    assemble_with_baseline(source_members, source_identity, version, &baseline)
}

fn load_accepted_baseline() -> Result<AcceptedBaseline> {
    let value = parse_json_value(ACCEPTED_BASELINE, JsonProfile::SdkComponentManifest)?;
    if string_field(&value, "schema")? != BASELINE_SCHEMA {
        return Err(Refusal::new(
            "compiled accepted R1 baseline schema is unsupported",
        ));
    }

    let sdk_target = field(&value, "sdk_target")?;
    let rust_commit = string_field(sdk_target, "rust_commit")?.to_owned();
    let rust_llvm = string_field(sdk_target, "rust_llvm")?.to_owned();
    let source_date_epoch = number_field(sdk_target, "source_date_epoch")?;
    if !is_git_identity(&rust_commit) || rust_llvm.is_empty() || source_date_epoch == 0 {
        return Err(Refusal::new(
            "compiled accepted R1 baseline has invalid SDK target metadata",
        ));
    }

    let target_catalog = field(&value, "sdk_target_inputs")?;
    if number_field(target_catalog, "file_count")? != EXPECTED_TARGET_INPUTS as u64 {
        return Err(Refusal::new(
            "compiled accepted R1 target inventory has an unexpected file count",
        ));
    }
    let target_inputs = parse_identity_rows(
        field(target_catalog, "files")?,
        "accepted R1 target input",
        Some(EXPECTED_TARGET_INPUTS),
    )?;
    if target_inputs.keys().any(|path| !is_target_input_path(path)) {
        return Err(Refusal::new(
            "compiled accepted R1 target inventory contains a non-target path",
        ));
    }

    let component_manifests = parse_identity_rows(
        field(&value, "component_manifests")?,
        "accepted R1 component manifest",
        Some(EXPECTED_COMPONENT_MANIFESTS),
    )?;
    let expected_component_paths = component_manifest_paths();
    if component_manifests.keys().cloned().collect::<BTreeSet<_>>() != expected_component_paths {
        return Err(Refusal::new(
            "compiled accepted R1 component inventory does not contain the fixed twelve profiles",
        ));
    }

    Ok(AcceptedBaseline {
        rust_commit,
        rust_llvm,
        source_date_epoch,
        target_inputs,
        component_manifests,
    })
}

fn parse_identity_rows(
    value: &Value,
    label: &str,
    expected_count: Option<usize>,
) -> Result<BTreeMap<String, FileIdentity>> {
    let rows = value
        .as_array()
        .ok_or_else(|| Refusal::new(format!("{label} inventory must be an array")))?;
    if let Some(expected_count) = expected_count
        && rows.len() != expected_count
    {
        return Err(Refusal::new(format!(
            "{label} inventory must contain exactly {expected_count} rows"
        )));
    }
    let mut result = BTreeMap::new();
    let mut folded = BTreeSet::new();
    for row in rows {
        let path = string_field(row, "path")?.to_owned();
        let bytes = usize::try_from(number_field(row, "bytes")?)
            .map_err(|_| Refusal::new(format!("{label} size is not representable: {path}")))?;
        let sha256 = string_field(row, "sha256")?.to_owned();
        if path.is_empty()
            || path.starts_with('/')
            || path.contains('\\')
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || bytes > MAX_FILE_BYTES
            || !is_sha256_digest(&sha256)
            || !folded.insert(path.to_ascii_lowercase())
        {
            return Err(Refusal::new(format!("invalid {label} identity: {path}")));
        }
        let identity = FileIdentity {
            path: path.clone(),
            bytes,
            sha256,
        };
        if result.insert(path.clone(), identity).is_some() {
            return Err(Refusal::new(format!("duplicate {label} path: {path}")));
        }
    }
    Ok(result)
}

fn assemble_with_baseline(
    source_members: &BTreeMap<String, Vec<u8>>,
    source_identity: &str,
    version: &str,
    baseline: &AcceptedBaseline,
) -> Result<NativeSdkDraft> {
    validate_source_identity(source_identity)?;
    validate_version(version)?;
    validate_baseline_shape(baseline)?;

    let actual_target_paths = source_members
        .keys()
        .filter(|path| is_target_input_path(path))
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_target_paths = baseline
        .target_inputs
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if actual_target_paths != expected_target_paths {
        return Err(Refusal::new(
            "legacy SDK target input path set differs from the accepted R1 baseline",
        ));
    }

    let mut files = BTreeMap::new();
    for identity in baseline
        .target_inputs
        .values()
        .chain(baseline.component_manifests.values())
    {
        let contents = source_members
            .get(&identity.path)
            .ok_or_else(|| Refusal::new(format!("legacy SDK is missing {}", identity.path)))?;
        verify_identity(identity, contents)?;
        if files
            .insert(identity.path.clone(), contents.clone())
            .is_some()
        {
            return Err(Refusal::new(format!(
                "accepted SDK input path is repeated: {}",
                identity.path
            )));
        }
    }

    for path in LEGAL_NOTICE_PATHS {
        let contents = source_members.get(path).ok_or_else(|| {
            Refusal::new(format!(
                "legacy SDK is missing required legal notice {path}"
            ))
        })?;
        if contents.is_empty() || contents.len() > MAX_FILE_BYTES {
            return Err(Refusal::new(format!(
                "legacy SDK legal notice is empty or exceeds the publisher file limit: {path}"
            )));
        }
        files.insert(path.to_owned(), contents.clone());
    }

    files.insert(README_PATH.to_owned(), readme_bytes());
    let manifest = make_manifest(&files, source_identity, version, baseline)?;
    if manifest.len() > MAX_FILE_BYTES {
        return Err(Refusal::new(
            "generated SDK manifest exceeds the publisher file limit",
        ));
    }
    files.insert(SDK_MANIFEST_PATH.to_owned(), manifest.clone());

    let tar = build_canonical_ustar(&files, baseline.source_date_epoch)?;
    verify_tar_inventory(&tar, &files)?;
    let archive = compress_xz(&tar)?;
    if archive.len() > XZ_COMPRESSED_LIMIT {
        return Err(Refusal::new(
            "generated SDK XZ archive exceeds the native SDK compressed-size limit",
        ));
    }

    Ok(NativeSdkDraft {
        manifest_sha256: sha256_bytes(&manifest),
        manifest,
        archive,
        files,
    })
}

fn validate_baseline_shape(baseline: &AcceptedBaseline) -> Result<()> {
    if !is_git_identity(&baseline.rust_commit)
        || baseline.rust_llvm.is_empty()
        || baseline.source_date_epoch == 0
        || baseline.target_inputs.is_empty()
        || baseline.component_manifests.len() != EXPECTED_COMPONENT_MANIFESTS
        || baseline
            .target_inputs
            .keys()
            .any(|path| !is_target_input_path(path))
        || baseline
            .component_manifests
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != component_manifest_paths()
    {
        return Err(Refusal::new("accepted R1 baseline inventory is malformed"));
    }
    Ok(())
}

fn verify_identity(identity: &FileIdentity, contents: &[u8]) -> Result<()> {
    if contents.len() != identity.bytes || sha256_bytes(contents) != identity.sha256 {
        return Err(Refusal::new(format!(
            "legacy SDK input differs from accepted R1 identity: {}",
            identity.path
        )));
    }
    Ok(())
}

fn make_manifest(
    files: &BTreeMap<String, Vec<u8>>,
    source_identity: &str,
    version: &str,
    baseline: &AcceptedBaseline,
) -> Result<Vec<u8>> {
    let mut rows = Vec::with_capacity(files.len());
    for (path, contents) in files {
        if path == SDK_MANIFEST_PATH {
            continue;
        }
        rows.push(serde_json::json!({
            "path": path,
            "bytes": contents.len(),
            "sha256": sha256_bytes(contents),
        }));
    }

    let mut profiles = Map::new();
    for (host, triple) in HOSTS {
        let mut components = Map::new();
        for component in COMPONENTS {
            let path = format!("host/profiles/{host}/{component}.json");
            let contents = files
                .get(&path)
                .ok_or_else(|| Refusal::new(format!("accepted SDK is missing {path}")))?;
            components.insert(
                component.to_owned(),
                serde_json::json!({
                    "manifest": path,
                    "sha256": sha256_bytes(contents),
                }),
            );
        }
        profiles.insert(
            host.to_owned(),
            serde_json::json!({
                "rust_host": triple,
                "cargo_metadata_mode": "ami-rust-reproducible-cross-v1",
                "cargo_binary": "bin/cargo",
                "collector_binary": "bin/aros-collect",
                "components": Value::Object(components),
            }),
        );
    }

    let mut build = Map::new();
    for (name, value) in BUILD_PROFILE {
        build.insert(name.to_owned(), Value::from(value));
    }
    let mut host_capacity = Map::new();
    for (name, value) in HOST_CAPACITY {
        host_capacity.insert(name.to_owned(), Value::from(value));
    }
    host_capacity.insert(
        "schema".to_owned(),
        Value::String("ami-rust-host-capacity-v1".to_owned()),
    );

    let manifest = serde_json::json!({
        "schema": SDK_SCHEMA,
        "version": version,
        "qualification_only": false,
        "driver": SDK_DRIVER,
        "target": "x86_64-aros",
        "files": rows,
        "profiles": Value::Object(profiles),
        "rust_commit": baseline.rust_commit,
        "rust_llvm": baseline.rust_llvm,
        "source_date_epoch": baseline.source_date_epoch,
        "source_identity": source_identity,
        "build": Value::Object(build),
        "host_capacity": Value::Object(host_capacity),
        "application_memory_policy": "ami-rust-application-memory-policy-v1",
    });
    let mut bytes = Vec::new();
    write_canonical_json(&manifest, &mut bytes)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            serde_json::to_writer(output, value).map_err(|error| {
                Refusal::new(format!("could not serialize SDK manifest: {error}"))
            })?;
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
            entries.sort_unstable_by_key(|(left, _)| *left);
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key).map_err(|error| {
                    Refusal::new(format!("could not serialize SDK manifest key: {error}"))
                })?;
                output.push(b':');
                write_canonical_json(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn build_canonical_ustar(files: &BTreeMap<String, Vec<u8>>, mtime: u64) -> Result<Vec<u8>> {
    let mut archive = Vec::new();
    for (path, contents) in files {
        if path.len() > 100 || path.is_empty() || contents.len() > MAX_FILE_BYTES {
            return Err(Refusal::new(format!(
                "SDK TAR path or member size is outside the publisher profile: {path}"
            )));
        }
        let mut header = [0_u8; TAR_BLOCK_BYTES];
        header[..path.len()].copy_from_slice(path.as_bytes());
        write_octal_field(&mut header, 100..108, 0o644)?;
        write_octal_field(&mut header, 108..116, 0)?;
        write_octal_field(&mut header, 116..124, 0)?;
        write_octal_field(&mut header, 124..136, contents.len() as u64)?;
        write_octal_field(&mut header, 136..148, mtime)?;
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
        let checksum_field = format!("{checksum:06o}\0 ");
        if checksum_field.len() != 8 {
            return Err(Refusal::new("SDK TAR header checksum is not representable"));
        }
        header[148..156].copy_from_slice(checksum_field.as_bytes());
        archive.extend_from_slice(&header);
        archive.extend_from_slice(contents);
        let content_padding =
            (TAR_BLOCK_BYTES - contents.len() % TAR_BLOCK_BYTES) % TAR_BLOCK_BYTES;
        archive.resize(
            archive
                .len()
                .checked_add(content_padding)
                .ok_or_else(|| Refusal::new("SDK TAR size overflow"))?,
            0,
        );
        if archive.len() > MAX_DECODED_TAR_BYTES {
            return Err(Refusal::new(
                "generated SDK TAR exceeds the native SDK decoded-size limit",
            ));
        }
    }

    let trailer_end = archive
        .len()
        .checked_add(2 * TAR_BLOCK_BYTES)
        .ok_or_else(|| Refusal::new("SDK TAR size overflow"))?;
    let record_end = trailer_end
        .checked_add(TAR_RECORD_BYTES - 1)
        .ok_or_else(|| Refusal::new("SDK TAR size overflow"))?
        / TAR_RECORD_BYTES
        * TAR_RECORD_BYTES;
    if record_end > MAX_DECODED_TAR_BYTES {
        return Err(Refusal::new(
            "generated SDK TAR exceeds the native SDK decoded-size limit",
        ));
    }
    archive.resize(record_end, 0);
    Ok(archive)
}

fn write_octal_field(
    header: &mut [u8; TAR_BLOCK_BYTES],
    range: std::ops::Range<usize>,
    value: u64,
) -> Result<()> {
    let width = range.len() - 1;
    let text = format!("{value:0width$o}");
    if text.len() > width {
        return Err(Refusal::new(
            "SDK TAR numeric header field is not representable",
        ));
    }
    header[range.start..range.start + width].copy_from_slice(text.as_bytes());
    header[range.end - 1] = 0;
    Ok(())
}

fn verify_tar_inventory(tar: &[u8], files: &BTreeMap<String, Vec<u8>>) -> Result<()> {
    let digests = files
        .values()
        .map(|contents| sha256_bytes(contents))
        .collect::<Vec<_>>();
    let expected = files
        .iter()
        .zip(&digests)
        .map(|((path, contents), sha256)| ExpectedFile {
            path,
            size: contents.len(),
            sha256,
        })
        .collect::<Vec<_>>();
    verify_publisher_sdk_tar(tar, &expected)?;
    Ok(())
}

fn compress_xz(tar: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = XzWriter::new(Vec::new(), XzOptions::with_preset(XZ_PRESET))
        .map_err(|error| Refusal::new(format!("could not initialize SDK XZ encoder: {error}")))?;
    encoder
        .write_all(tar)
        .map_err(|error| Refusal::new(format!("could not encode SDK XZ archive: {error}")))?;
    encoder
        .finish()
        .map_err(|error| Refusal::new(format!("could not finish SDK XZ archive: {error}")))
}

fn readme_bytes() -> Vec<u8> {
    b"# ami-rust native SDK\n\nThis archive contains accepted target inputs and host component profile manifests.\n\nNative CLI preparation and build documentation is maintained separately.\nThis SDK does not include a Python driver.\n".to_vec()
}

fn validate_source_identity(value: &str) -> Result<()> {
    if !is_git_identity(value) {
        return Err(Refusal::new(
            "SDK source_identity must be exactly 40 lowercase hexadecimal digits",
        ));
    }
    Ok(())
}

fn is_git_identity(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_version(version: &str) -> Result<()> {
    let bytes = version.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 64
        || !bytes[0].is_ascii_alphanumeric()
        || bytes[1..].iter().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'+' | b'_' | b'-'))
        })
        || version == BASELINE_VERSION
    {
        return Err(Refusal::new(
            "SDK version must use the native release version syntax and must differ from 0.1.0",
        ));
    }
    Ok(())
}

fn is_target_input_path(path: &str) -> bool {
    matches!(path, "Cargo.toml" | "Cargo.lock")
        || ["native/", "targets/", "crates/", "examples/", "tests/"]
            .iter()
            .any(|prefix| path.starts_with(prefix))
}

fn component_manifest_paths() -> BTreeSet<String> {
    HOSTS
        .iter()
        .flat_map(|(host, _)| {
            COMPONENTS
                .iter()
                .map(move |component| format!("host/profiles/{host}/{component}.json"))
        })
        .collect()
}

fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value> {
    value
        .as_object()
        .and_then(|object| object.get(name))
        .ok_or_else(|| Refusal::new(format!("accepted R1 baseline is missing {name}")))
}

fn string_field<'a>(value: &'a Value, name: &str) -> Result<&'a str> {
    field(value, name)?
        .as_str()
        .ok_or_else(|| Refusal::new(format!("accepted R1 baseline {name} must be a string")))
}

fn number_field(value: &Value, name: &str) -> Result<u64> {
    field(value, name)?.as_u64().ok_or_else(|| {
        Refusal::new(format!(
            "accepted R1 baseline {name} must be an unsigned integer"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ACCEPTED_BASELINE, AcceptedBaseline, COMPONENTS, FileIdentity, HOSTS, LEGAL_NOTICE_PATHS,
        NativeSdkDraft, assemble_with_baseline, component_manifest_paths, load_accepted_baseline,
    };
    use ami_rust_core::{
        compression::{DecodeLimits, copy_xz},
        digest::sha256_bytes,
        json::{JsonProfile, parse_json_value},
        publisher_tar::{ExpectedFile, MAX_DECODED_TAR_BYTES, verify_publisher_sdk_tar},
    };
    use serde_json::Value;
    use std::collections::BTreeMap;

    const SOURCE_IDENTITY: &str = "0123456789abcdef0123456789abcdef01234567";

    fn tiny_baseline(source_members: &BTreeMap<String, Vec<u8>>) -> AcceptedBaseline {
        let target_paths = ["Cargo.toml", "Cargo.lock"];
        let target_inputs = target_paths
            .into_iter()
            .map(|path| identity_for(path, source_members))
            .map(|identity| (identity.path.clone(), identity))
            .collect();
        let component_manifests = component_manifest_paths()
            .into_iter()
            .map(|path| identity_for(&path, source_members))
            .map(|identity| (identity.path.clone(), identity))
            .collect();
        AcceptedBaseline {
            rust_commit: "330d317121e16b5db8e5adc63595910528ff2ee7".to_owned(),
            rust_llvm: "23.1.1".to_owned(),
            source_date_epoch: 1_791_936_000,
            target_inputs,
            component_manifests,
        }
    }

    fn input_members() -> BTreeMap<String, Vec<u8>> {
        let mut members = BTreeMap::new();
        members.insert("Cargo.toml".to_owned(), b"[workspace]\n".to_vec());
        members.insert("Cargo.lock".to_owned(), b"version = 4\n".to_vec());
        for (host_index, (host, _)) in HOSTS.iter().enumerate() {
            for (component_index, component) in COMPONENTS.iter().enumerate() {
                members.insert(
                    format!("host/profiles/{host}/{component}.json"),
                    format!("profile {host_index}:{component_index}\n").into_bytes(),
                );
            }
        }
        for path in LEGAL_NOTICE_PATHS {
            members.insert(
                path.to_owned(),
                format!("original notice: {path}\n").into_bytes(),
            );
        }
        // Other legacy SDK members are intentionally excluded from the draft.
        members.insert("docs/legacy.md".to_owned(), b"legacy\n".to_vec());
        members
    }

    fn identity_for(path: &str, members: &BTreeMap<String, Vec<u8>>) -> FileIdentity {
        let bytes = members.get(path).expect("fixture input member");
        FileIdentity {
            path: path.to_owned(),
            bytes: bytes.len(),
            sha256: sha256_bytes(bytes),
        }
    }

    fn draft() -> (NativeSdkDraft, BTreeMap<String, Vec<u8>>) {
        let inputs = input_members();
        let baseline = tiny_baseline(&inputs);
        let draft = assemble_with_baseline(&inputs, SOURCE_IDENTITY, "0.2.0", &baseline)
            .expect("assemble native SDK fixture");
        (draft, inputs)
    }

    fn verify_archive(draft: &NativeSdkDraft) -> Vec<u8> {
        let mut tar = Vec::new();
        copy_xz(
            &draft.archive,
            &mut tar,
            DecodeLimits {
                max_compressed_bytes: 16 * 1024 * 1024,
                max_decoded_bytes: MAX_DECODED_TAR_BYTES,
                max_xz_memory_kib: 64 * 1024,
            },
        )
        .expect("decode generated XZ archive");
        let digests = draft
            .files
            .values()
            .map(|contents| sha256_bytes(contents))
            .collect::<Vec<_>>();
        let expected = draft
            .files
            .iter()
            .zip(&digests)
            .map(|((path, contents), sha256)| ExpectedFile {
                path,
                size: contents.len(),
                sha256,
            })
            .collect::<Vec<_>>();
        let verified = verify_publisher_sdk_tar(&tar, &expected).expect("verify generated TAR");
        assert_eq!(verified.len(), draft.files.len());
        assert_canonical_headers(&tar, draft);
        for member in verified {
            assert_eq!(draft.files.get(&member.path).unwrap(), member.contents);
            assert_eq!(member.mode, 0o644);
        }
        tar
    }

    fn assert_canonical_headers(tar: &[u8], draft: &NativeSdkDraft) {
        let mut position = 0;
        let mut paths = Vec::new();
        while position + 512 <= tar.len() {
            let header = &tar[position..position + 512];
            if header.iter().all(|byte| *byte == 0) {
                break;
            }
            assert_eq!(&header[100..108], b"0000644\0");
            assert_eq!(&header[108..116], b"0000000\0");
            assert_eq!(&header[116..124], b"0000000\0");
            assert_eq!(octal(&header[136..148]), 1_791_936_000);
            assert_eq!(header[156], b'0');
            assert_eq!(&header[257..263], b"ustar\0");
            assert_eq!(&header[263..265], b"00");
            assert!(header[157..257].iter().all(|byte| *byte == 0));
            assert!(header[265..329].iter().all(|byte| *byte == 0));
            assert!(header[345..500].iter().all(|byte| *byte == 0));
            assert_eq!(header[154], 0);
            assert_eq!(header[155], b' ');
            let encoded_checksum = octal(&header[148..154]);
            let checksum = header
                .iter()
                .enumerate()
                .map(|(index, byte)| {
                    if (148..156).contains(&index) {
                        u64::from(b' ')
                    } else {
                        u64::from(*byte)
                    }
                })
                .sum::<u64>();
            assert_eq!(encoded_checksum, checksum);

            let name_end = header[..100]
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(100);
            paths.push(std::str::from_utf8(&header[..name_end]).unwrap().to_owned());
            let size = usize::try_from(octal(&header[124..136])).unwrap();
            position += 512 + size.div_ceil(512) * 512;
        }
        assert_eq!(paths, draft.files.keys().cloned().collect::<Vec<_>>());
        assert_eq!(tar.len() % 10_240, 0);
        assert!(tar[position..].iter().all(|byte| *byte == 0));
    }

    fn octal(field: &[u8]) -> u64 {
        let end = field
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(field.len());
        u64::from_str_radix(std::str::from_utf8(&field[..end]).unwrap(), 8).unwrap()
    }

    #[test]
    fn compiled_baseline_has_the_fixed_target_and_profile_inventories() {
        let baseline = load_accepted_baseline().expect("load compiled baseline");
        assert_eq!(baseline.target_inputs.len(), 56);
        assert_eq!(baseline.component_manifests.len(), 12);
        assert_eq!(
            baseline.rust_commit,
            "330d317121e16b5db8e5adc63595910528ff2ee7"
        );
        assert_eq!(baseline.rust_llvm, "23.1.1");
        assert_eq!(baseline.source_date_epoch, 1_791_936_000);
        assert!(ACCEPTED_BASELINE.starts_with(b"{"));
    }

    #[test]
    fn draft_is_deterministic_and_preserves_only_accepted_input_bytes() {
        let (first, inputs) = draft();
        let second =
            assemble_with_baseline(&inputs, SOURCE_IDENTITY, "0.2.0", &tiny_baseline(&inputs))
                .expect("assemble same SDK twice");
        assert_eq!(first, second);
        assert_eq!(first.manifest_sha256, sha256_bytes(&first.manifest));
        assert_eq!(
            first.files.get("Cargo.toml").unwrap(),
            inputs.get("Cargo.toml").unwrap()
        );
        assert_eq!(
            first.files.get("Cargo.lock").unwrap(),
            inputs.get("Cargo.lock").unwrap()
        );
        assert!(!first.files.contains_key("docs/legacy.md"));
        assert_eq!(first.files.len(), 20);
        for path in LEGAL_NOTICE_PATHS {
            assert_eq!(first.files.get(path).unwrap(), inputs.get(path).unwrap());
        }
        assert!(first.files.contains_key("README.md"));
        assert!(first.files.contains_key("contract/sdk.json"));
        assert!(
            first.files["README.md"]
                .windows(6)
                .any(|part| part == b"Python")
        );
        let value = parse_json_value(&first.manifest, JsonProfile::SdkComponentManifest)
            .expect("parse generated SDK-v2 JSON");
        assert_eq!(value["schema"], "ami-rust-sdk-v2");
        assert_eq!(value["version"], "0.2.0");
        assert!(!value["qualification_only"].as_bool().unwrap());
        assert_eq!(value["source_identity"], SOURCE_IDENTITY);
        assert_eq!(
            value["rust_commit"],
            "330d317121e16b5db8e5adc63595910528ff2ee7"
        );
        assert_eq!(value["rust_llvm"], "23.1.1");
        assert_eq!(value["source_date_epoch"], 1_791_936_000);
        assert_eq!(value["profiles"].as_object().unwrap().len(), 2);
        assert!(first.manifest.ends_with(b"\n"));
        assert_eq!(verify_archive(&first).len() % 10_240, 0);
    }

    #[test]
    fn rejects_unsafe_version_source_identity_and_changed_baseline_inputs() {
        let inputs = input_members();
        let baseline = tiny_baseline(&inputs);
        for version in ["0.1.0", "../0.2.0", "0.2.0\n", ""] {
            assert!(assemble_with_baseline(&inputs, SOURCE_IDENTITY, version, &baseline).is_err());
        }
        for identity in [
            "ABCDEF0123456789abcdef0123456789abcdef01",
            "../0123456789abcdef0123456789abcdef01234567",
            "short",
        ] {
            assert!(assemble_with_baseline(&inputs, identity, "0.2.0", &baseline).is_err());
        }

        let mut changed = inputs.clone();
        changed.insert(
            "Cargo.toml".to_owned(),
            b"[workspace]\nchanged = true\n".to_vec(),
        );
        assert!(assemble_with_baseline(&changed, SOURCE_IDENTITY, "0.2.0", &baseline).is_err());

        let mut changed_profile = inputs.clone();
        changed_profile.insert(
            "host/profiles/linux-x86_64/rust.json".to_owned(),
            b"changed profile\n".to_vec(),
        );
        assert!(
            assemble_with_baseline(&changed_profile, SOURCE_IDENTITY, "0.2.0", &baseline).is_err()
        );

        let mut missing_notice = inputs.clone();
        missing_notice.remove(LEGAL_NOTICE_PATHS[0]);
        assert!(
            assemble_with_baseline(&missing_notice, SOURCE_IDENTITY, "0.2.0", &baseline).is_err()
        );

        let mut extra = inputs;
        extra.insert("crates/unaccepted.rs".to_owned(), b"unexpected\n".to_vec());
        assert!(assemble_with_baseline(&extra, SOURCE_IDENTITY, "0.2.0", &baseline).is_err());
    }

    #[test]
    fn canonical_manifest_and_archive_agree_on_the_complete_file_inventory() {
        let (draft, _) = draft();
        let reparsed = parse_json_value(&draft.manifest, JsonProfile::SdkComponentManifest)
            .expect("parse generated manifest");
        assert_eq!(canonical_json(&reparsed), draft.manifest);
        let manifest_value: Value = reparsed;
        let rows = manifest_value["files"].as_array().expect("files array");
        assert_eq!(rows.len(), draft.files.len() - 1);
        assert!(rows.iter().all(|row| row["path"] != "contract/sdk.json"));
        let tar = verify_archive(&draft);
        assert!(tar.len() <= MAX_DECODED_TAR_BYTES);
    }

    fn canonical_json(value: &Value) -> Vec<u8> {
        let mut bytes = Vec::new();
        super::write_canonical_json(value, &mut bytes).unwrap();
        bytes.push(b'\n');
        bytes
    }
}
