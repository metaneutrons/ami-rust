//! Composition of authenticated SDK-v2 archives for the native consumer.
//!
//! The entry point accepts only a `VerifiedPublisherBundle`, whose constructor
//! belongs to the publisher verifier. The private helper over parsed release
//! fields and byte maps exists for unit fixtures; its success is not
//! authentication. This module does not install or activate a build, and it
//! does not compare component pins to the accepted R1 baseline.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    Refusal, Result,
    compression::{DecodeLimits, copy_xz},
    digest::sha256_bytes,
    json::{JsonProfile, parse_json_value},
    publisher::VerifiedPublisherBundle,
    publisher_tar::{
        ExpectedFile, MAX_DECODED_TAR_BYTES, MAX_FILE_BYTES, MAX_MEMBERS, verify_publisher_sdk_tar,
    },
    release_manifest::{NativeReleaseManifest, ReleaseFile},
};
use serde_json::Value;

const SDK_SCHEMA: &str = "ami-rust-sdk-v2";
const SDK_DRIVER: &str = "ami-rust-native-compatibility-v1";
const SDK_ARCHIVE: &str = "sdk.tar.xz";
const SDK_MANIFEST_PATH: &str = "contract/sdk.json";
const MAX_XZ_COMPRESSED_BYTES: usize = 16 * 1024 * 1024;
const XZ_MEMORY_LIMIT_KIB: u32 = 64 * 1024;
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
const CARGO_METADATA_MODE: &str = "ami-rust-reproducible-cross-v1";

/// Summary of a structurally valid SDK-v2 archive bound to an authenticated
/// release. This says nothing about installation, R1 acceptance, or build
/// qualification.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct VerifiedSdkV2Summary {
    pub version: String,
    pub qualification_only: bool,
    pub sdk_manifest_sha256: String,
    pub archive_files: usize,
    pub component_manifest_files: usize,
}

/// Compose inner SDK-v2 only from retained bytes produced by successful native
/// publisher verification. This function does not reopen bundle paths.
pub fn compose_verified_sdk_v2(bundle: &VerifiedPublisherBundle) -> Result<VerifiedSdkV2Summary> {
    compose_retained_parts(bundle.manifest(), bundle.assets())
}

/// Private pure helper for fixtures. Inputs passed here are untrusted unless
/// the caller has independently obtained them from `VerifiedPublisherBundle`.
fn compose_retained_parts(
    release: &NativeReleaseManifest,
    assets: &BTreeMap<String, Vec<u8>>,
) -> Result<VerifiedSdkV2Summary> {
    if release.qualification_only {
        return Err(Refusal::new(
            "native SDK production composition refuses qualification-only releases",
        ));
    }
    if release.sdk_archive != SDK_ARCHIVE {
        return Err(Refusal::new(
            "native release SDK archive name is unsupported",
        ));
    }
    let archive_asset = release
        .assets
        .iter()
        .find(|asset| asset.path == SDK_ARCHIVE)
        .ok_or_else(|| Refusal::new("native release asset inventory is missing sdk.tar.xz"))?;
    let archive_bytes = assets
        .get(SDK_ARCHIVE)
        .ok_or_else(|| Refusal::new("verified release did not retain sdk.tar.xz bytes"))?;
    if u64::try_from(archive_bytes.len()).ok() != Some(archive_asset.bytes)
        || sha256_bytes(archive_bytes) != archive_asset.sha256.as_str()
    {
        return Err(Refusal::new(
            "retained SDK archive bytes differ from the release asset identity",
        ));
    }

    let mut decoded = Vec::new();
    copy_xz(
        archive_bytes,
        &mut decoded,
        DecodeLimits {
            max_compressed_bytes: MAX_XZ_COMPRESSED_BYTES,
            max_decoded_bytes: MAX_DECODED_TAR_BYTES,
            max_xz_memory_kib: XZ_MEMORY_LIMIT_KIB,
        },
    )?;

    let expected_outer = release_files_as_expected(&release.sdk_files)?;
    let archive_files = verify_publisher_sdk_tar(&decoded, &expected_outer)?;
    let sdk_manifest_file = archive_files
        .iter()
        .find(|file| file.path == SDK_MANIFEST_PATH)
        .ok_or_else(|| Refusal::new("SDK archive is missing contract/sdk.json"))?;
    let sdk_manifest_raw = sdk_manifest_file.contents;
    if sha256_bytes(sdk_manifest_raw) != release.sdk_manifest_sha256.as_str() {
        return Err(Refusal::new(
            "inner SDK manifest digest differs from release-v2",
        ));
    }
    let outer_manifest_row = release
        .sdk_files
        .iter()
        .find(|file| file.path == SDK_MANIFEST_PATH)
        .ok_or_else(|| Refusal::new("release sdk_files does not pin contract/sdk.json"))?;
    if u64::try_from(sdk_manifest_raw.len()).ok() != Some(outer_manifest_row.bytes)
        || sha256_bytes(sdk_manifest_raw) != outer_manifest_row.sha256.as_str()
    {
        return Err(Refusal::new(
            "inner SDK manifest differs from its outer inventory row",
        ));
    }

    let parsed = parse_sdk_v2(
        sdk_manifest_raw,
        &release.version,
        release.qualification_only,
    )?;
    compare_inner_inventory(&parsed.files, &release.sdk_files)?;
    check_component_manifest_rows(&parsed, &release.sdk_files)?;

    Ok(VerifiedSdkV2Summary {
        version: parsed.version,
        qualification_only: parsed.qualification_only,
        sdk_manifest_sha256: release.sdk_manifest_sha256.as_str().to_owned(),
        archive_files: archive_files.len(),
        component_manifest_files: COMPONENTS.len() * HOSTS.len(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SdkFileRow {
    path: String,
    bytes: u64,
    sha256: String,
}

type ComponentManifestRows = BTreeMap<String, (String, String)>;
type HostProfiles = BTreeMap<String, ComponentManifestRows>;

#[derive(Debug)]
struct ParsedSdkV2 {
    version: String,
    qualification_only: bool,
    files: Vec<SdkFileRow>,
    profiles: HostProfiles,
}

fn parse_sdk_v2(
    raw: &[u8],
    release_version: &str,
    release_qualification_only: bool,
) -> Result<ParsedSdkV2> {
    let value = parse_json_value(raw, JsonProfile::SdkComponentManifest)?;
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new("SDK-v2 manifest must be an object"))?;
    let required = [
        "schema",
        "version",
        "qualification_only",
        "driver",
        "target",
        "files",
        "profiles",
        "rust_commit",
        "rust_llvm",
        "source_date_epoch",
        "source_identity",
        "build",
        "host_capacity",
        "application_memory_policy",
    ];
    exact_keys(object, &required, &["extensions"], "SDK-v2 manifest")?;

    if get_string(object, "schema")? != SDK_SCHEMA {
        return Err(Refusal::new("unsupported SDK manifest schema"));
    }
    if get_string(object, "driver")? != SDK_DRIVER {
        return Err(Refusal::new("unsupported SDK-v2 driver recipe"));
    }
    if get_string(object, "target")? != "x86_64-aros" {
        return Err(Refusal::new("SDK-v2 target must be x86_64-aros"));
    }
    if get_string(object, "application_memory_policy")? != "ami-rust-application-memory-policy-v1" {
        return Err(Refusal::new("unsupported SDK application memory policy"));
    }
    let version = get_string(object, "version")?.to_owned();
    if version != release_version {
        return Err(Refusal::new("SDK-v2 version differs from release-v2"));
    }
    let qualification_only = object
        .get("qualification_only")
        .and_then(Value::as_bool)
        .ok_or_else(|| Refusal::new("SDK-v2 qualification_only must be a boolean"))?;
    if qualification_only != release_qualification_only || qualification_only {
        return Err(Refusal::new(
            "SDK-v2 qualification status must match a production release",
        ));
    }
    let rust_commit = get_string(object, "rust_commit")?;
    let source_identity = get_string(object, "source_identity")?;
    if !is_hex_identity(rust_commit) || !is_hex_identity(source_identity) {
        return Err(Refusal::new(
            "SDK-v2 source and compiler identities must be 40 lowercase hex digits",
        ));
    }
    if get_string(object, "rust_llvm")?.is_empty() {
        return Err(Refusal::new("SDK-v2 rust_llvm must be a non-empty string"));
    }
    let _source_date_epoch = get_counter(object, "source_date_epoch")?;
    check_fixed_counter_object(
        object.get("build"),
        &BUILD_PROFILE,
        None,
        "SDK-v2 build profile",
    )?;
    check_fixed_counter_object(
        object.get("host_capacity"),
        &HOST_CAPACITY,
        Some(("schema", "ami-rust-host-capacity-v1")),
        "SDK-v2 host capacity",
    )?;

    let files = parse_file_rows(object.get("files"))?;
    let profiles = parse_profiles(object.get("profiles"))?;
    Ok(ParsedSdkV2 {
        version,
        qualification_only,
        files,
        profiles,
    })
}

fn parse_file_rows(value: Option<&Value>) -> Result<Vec<SdkFileRow>> {
    let rows = value
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::new("SDK-v2 files must be an array"))?;
    if rows.is_empty() || rows.len() >= MAX_MEMBERS {
        return Err(Refusal::new(
            "SDK-v2 files must have 1 to 999 non-self entries",
        ));
    }
    let mut output = Vec::with_capacity(rows.len());
    let mut exact = BTreeSet::new();
    let mut folded = BTreeSet::new();
    for row in rows {
        let object = row
            .as_object()
            .ok_or_else(|| Refusal::new("SDK-v2 file rows must be objects"))?;
        exact_keys(object, &["path", "bytes", "sha256"], &[], "SDK-v2 file row")?;
        let path = get_string(object, "path")?.to_owned();
        if path == SDK_MANIFEST_PATH {
            return Err(Refusal::new(
                "SDK-v2 files must omit the self-referential contract/sdk.json row",
            ));
        }
        let bytes = get_counter(object, "bytes")?;
        if bytes > MAX_FILE_BYTES as u64 {
            return Err(Refusal::new(format!(
                "SDK-v2 file exceeds publisher TAR file limit: {path}"
            )));
        }
        let sha256 = get_string(object, "sha256")?.to_owned();
        if !is_sha256(&sha256) {
            return Err(Refusal::new(format!(
                "SDK-v2 file has invalid SHA-256: {path}"
            )));
        }
        if !exact.insert(path.clone()) || !folded.insert(path.to_ascii_lowercase()) {
            return Err(Refusal::new(format!(
                "SDK-v2 files contain duplicate or case-colliding path: {path}"
            )));
        }
        output.push(SdkFileRow {
            path,
            bytes,
            sha256,
        });
    }
    Ok(output)
}

fn parse_profiles(value: Option<&Value>) -> Result<HostProfiles> {
    let profiles = value
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new("SDK-v2 profiles must be an object"))?;
    let expected_hosts = HOSTS.iter().map(|(host, _)| *host).collect::<BTreeSet<_>>();
    if profiles.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected_hosts {
        return Err(Refusal::new(
            "SDK-v2 profiles must contain exactly macos-aarch64 and linux-x86_64",
        ));
    }
    let mut result = BTreeMap::new();
    for (host, triple) in HOSTS {
        let profile = profiles
            .get(host)
            .and_then(Value::as_object)
            .ok_or_else(|| Refusal::new(format!("SDK-v2 profile {host} must be an object")))?;
        exact_keys(
            profile,
            &[
                "rust_host",
                "cargo_metadata_mode",
                "cargo_binary",
                "collector_binary",
                "components",
            ],
            &[],
            "SDK-v2 host profile",
        )?;
        if get_string(profile, "rust_host")? != triple {
            return Err(Refusal::new(format!(
                "SDK-v2 {host} Rust host triple differs from the supported profile"
            )));
        }
        if get_string(profile, "cargo_metadata_mode")? != CARGO_METADATA_MODE {
            return Err(Refusal::new(format!(
                "SDK-v2 {host} Cargo metadata mode is unsupported"
            )));
        }
        if get_string(profile, "cargo_binary")? != "bin/cargo"
            || get_string(profile, "collector_binary")? != "bin/aros-collect"
        {
            return Err(Refusal::new(format!(
                "SDK-v2 {host} executable paths are not the fixed native recipe paths"
            )));
        }
        let components = profile
            .get("components")
            .and_then(Value::as_object)
            .ok_or_else(|| Refusal::new(format!("SDK-v2 {host} components must be an object")))?;
        let expected_components = COMPONENTS.iter().copied().collect::<BTreeSet<_>>();
        if components
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != expected_components
        {
            return Err(Refusal::new(format!(
                "SDK-v2 {host} must contain exactly six component identities"
            )));
        }
        let mut component_files = BTreeMap::new();
        for component in COMPONENTS {
            let row = components
                .get(component)
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    Refusal::new(format!("SDK-v2 {host}.{component} must be an object"))
                })?;
            exact_keys(row, &["manifest", "sha256"], &[], "SDK-v2 component row")?;
            let path = get_string(row, "manifest")?.to_owned();
            let expected_path = format!("host/profiles/{host}/{component}.json");
            if path != expected_path {
                return Err(Refusal::new(format!(
                    "SDK-v2 {host}.{component} manifest path differs from the fixed profile path"
                )));
            }
            let digest = get_string(row, "sha256")?.to_owned();
            if !is_sha256(&digest) {
                return Err(Refusal::new(format!(
                    "SDK-v2 {host}.{component} manifest SHA-256 is invalid"
                )));
            }
            component_files.insert(component.to_owned(), (path, digest));
        }
        result.insert(host.to_owned(), component_files);
    }
    Ok(result)
}

fn compare_inner_inventory(inner: &[SdkFileRow], outer: &[ReleaseFile]) -> Result<()> {
    let mut outer_map = BTreeMap::new();
    for row in outer {
        if row.path == SDK_MANIFEST_PATH {
            continue;
        }
        if outer_map
            .insert(row.path.as_str(), (row.bytes, row.sha256.as_str()))
            .is_some()
        {
            return Err(Refusal::new(
                "outer SDK file inventory contains a duplicate path",
            ));
        }
    }
    if inner.len() != outer_map.len() {
        return Err(Refusal::new(
            "inner SDK file inventory does not exactly cover non-self archive members",
        ));
    }
    for row in inner {
        if outer_map.get(row.path.as_str()) != Some(&(row.bytes, row.sha256.as_str())) {
            return Err(Refusal::new(format!(
                "inner SDK file row differs from authenticated archive inventory: {}",
                row.path
            )));
        }
    }
    Ok(())
}

fn check_component_manifest_rows(parsed: &ParsedSdkV2, outer: &[ReleaseFile]) -> Result<()> {
    let rows = parsed
        .files
        .iter()
        .map(|row| (row.path.as_str(), row.sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    for (host, components) in &parsed.profiles {
        for (component, (path, digest)) in components {
            if rows.get(path.as_str()).copied() != Some(digest.as_str()) {
                return Err(Refusal::new(format!(
                    "SDK-v2 {host}.{component} manifest does not bind to its files inventory row"
                )));
            }
            if !outer
                .iter()
                .any(|row| row.path == *path && row.sha256.as_str() == digest)
            {
                return Err(Refusal::new(format!(
                    "SDK-v2 {host}.{component} manifest is absent from the authenticated archive inventory"
                )));
            }
        }
    }
    Ok(())
}

fn release_files_as_expected(files: &[ReleaseFile]) -> Result<Vec<ExpectedFile<'_>>> {
    files
        .iter()
        .map(|file| {
            let size = usize::try_from(file.bytes).map_err(|_| {
                Refusal::new(format!(
                    "SDK archive member size is not representable: {}",
                    file.path
                ))
            })?;
            Ok(ExpectedFile {
                path: &file.path,
                size,
                sha256: file.sha256.as_str(),
            })
        })
        .collect()
}

fn check_fixed_counter_object(
    value: Option<&Value>,
    expected: &[(&str, u64)],
    schema: Option<(&str, &str)>,
    label: &str,
) -> Result<()> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new(format!("{label} must be an object")))?;
    let mut required = expected
        .iter()
        .map(|(key, _)| *key)
        .collect::<BTreeSet<_>>();
    if let Some((schema_key, _)) = schema {
        required.insert(schema_key);
    }
    let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if keys != required {
        return Err(Refusal::new(format!(
            "{label} has missing or unknown fields"
        )));
    }
    if let Some((key, value)) = schema
        && get_string(object, key)? != value
    {
        return Err(Refusal::new(format!("{label} schema is unsupported")));
    }
    for (key, expected_value) in expected {
        if get_counter(object, key)? != *expected_value {
            return Err(Refusal::new(format!(
                "{label} field {key} differs from admitted host profile"
            )));
        }
    }
    Ok(())
}

fn exact_keys(
    object: &serde_json::Map<String, Value>,
    required: &[&str],
    optional: &[&str],
    label: &str,
) -> Result<()> {
    let keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let required_set = required.iter().copied().collect::<BTreeSet<_>>();
    let allowed = required
        .iter()
        .chain(optional)
        .copied()
        .collect::<BTreeSet<_>>();
    if !required_set.is_subset(&keys) || !keys.is_subset(&allowed) {
        return Err(Refusal::new(format!(
            "{label} has missing or unknown fields"
        )));
    }
    Ok(())
}

fn get_string<'a>(object: &'a serde_json::Map<String, Value>, key: &str) -> Result<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new(format!("{key} must be a string")))
}

fn get_counter(object: &serde_json::Map<String, Value>, key: &str) -> Result<u64> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| Refusal::new(format!("{key} must be a nonnegative integer")))
}

fn is_hex_identity(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, io::Write};

    use lzma_rust2::{XzOptions, XzWriter};
    use serde_json::{Value, json};
    use tar::{Builder, Header};

    use crate::{
        digest::sha256_bytes,
        release_manifest::{NativeReleaseManifest, parse_native_release_manifest},
    };

    use super::{
        BUILD_PROFILE, HOST_CAPACITY, SDK_DRIVER, SDK_MANIFEST_PATH, VerifiedSdkV2Summary,
        compose_retained_parts, parse_sdk_v2,
    };

    const VERSION: &str = "1.2.3";

    struct Fixture {
        release: NativeReleaseManifest,
        assets: BTreeMap<String, Vec<u8>>,
        sdk_value: Value,
        archive_uncompressed: Vec<u8>,
    }

    impl Fixture {
        fn valid() -> Self {
            let mut data = BTreeMap::<String, Vec<u8>>::new();
            data.insert("README.md".to_owned(), b"candidate SDK\n".to_vec());
            let mut profiles = serde_json::Map::new();
            for (host, triple) in [
                ("linux-x86_64", "x86_64-unknown-linux-gnu"),
                ("macos-aarch64", "aarch64-apple-darwin"),
            ] {
                let mut components = serde_json::Map::new();
                for name in ["rust", "cargo", "toolchain", "collector", "csdk", "vendor"] {
                    let path = format!("host/profiles/{host}/{name}.json");
                    let contents = format!("{{\"component\":\"{name}\"}}\n").into_bytes();
                    let digest = sha256_bytes(&contents);
                    data.insert(path.clone(), contents);
                    components.insert(name.to_owned(), json!({"manifest":path,"sha256":digest}));
                }
                profiles.insert(
                    host.to_owned(),
                    json!({
                        "rust_host":triple,
                        "cargo_metadata_mode":"ami-rust-reproducible-cross-v1",
                        "cargo_binary":"bin/cargo",
                        "collector_binary":"bin/aros-collect",
                        "components":Value::Object(components),
                    }),
                );
            }
            let mut rows = data
                .iter()
                .map(|(path, bytes)| {
                    json!({
                        "path":path,"bytes":bytes.len(),"sha256":sha256_bytes(bytes)
                    })
                })
                .collect::<Vec<_>>();
            rows.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
            let sdk_value = json!({
                "schema":"ami-rust-sdk-v2",
                "version":VERSION,
                "qualification_only":false,
                "driver":SDK_DRIVER,
                "target":"x86_64-aros",
                "files":rows,
                "profiles":Value::Object(profiles),
                "rust_commit":"330d317121e16b5db8e5adc63595910528ff2ee7",
                "rust_llvm":"23.1.1",
                "source_date_epoch":1791936000u64,
                "source_identity":"82edf967fe4a84cde43680108873a44ce8c71b4f",
                "build":counter_json(&BUILD_PROFILE),
                "host_capacity":host_capacity_json(),
                "application_memory_policy":"ami-rust-application-memory-policy-v1",
            });
            let sdk_raw = serde_json::to_vec(&sdk_value).unwrap();
            data.insert(SDK_MANIFEST_PATH.to_owned(), sdk_raw.clone());
            let tar_bytes = make_tar(&data);
            let xz_bytes = make_xz(&tar_bytes);
            let sdk_files = data
                .iter()
                .map(|(path, bytes)| {
                    json!({
                        "path":path,"bytes":bytes.len(),"sha256":sha256_bytes(bytes)
                    })
                })
                .collect::<Vec<_>>();
            let sdk_manifest_sha = sha256_bytes(&sdk_raw);
            let assets = vec![
                json!({"path":"sdk.tar.xz","bytes":xz_bytes.len(),"sha256":sha256_bytes(&xz_bytes)}),
                json!({"path":"bin/ami-rust-linux","bytes":4,"sha256":"c".repeat(64)}),
                json!({"path":"bin/ami-rust-macos","bytes":5,"sha256":"d".repeat(64)}),
            ];
            let outer = json!({
                "schema":"ami-rust-release-v2",
                "version":VERSION,
                "qualification_only":false,
                "sdk_archive":"sdk.tar.xz",
                "sdk_manifest_sha256":sdk_manifest_sha,
                "assets":assets,
                "sdk_files":sdk_files,
                "producer":{"source_sha":"82edf967fe4a84cde43680108873a44ce8c71b4f"},
                "host_launchers":{
                    "linux-x86_64":{"path":"bin/ami-rust-linux","bytes":4,"sha256":"c".repeat(64)},
                    "macos-aarch64":{"path":"bin/ami-rust-macos","bytes":5,"sha256":"d".repeat(64)}
                }
            });
            let outer_raw = serde_json::to_vec(&outer).unwrap();
            let release = parse_native_release_manifest(&outer_raw, true).unwrap();
            let assets = BTreeMap::from([("sdk.tar.xz".to_owned(), xz_bytes)]);
            Self {
                release,
                assets,
                sdk_value,
                archive_uncompressed: tar_bytes,
            }
        }

        fn rebind(&mut self) {
            // Recreate source files from component profile rows, then rebind the SDK inventory
            // and rebuild the archive plus outer release manifest.
            let files = self.profile_members();
            let mut rows = files
                .iter()
                .map(|(path, bytes)| {
                    json!({"path":path,"bytes":bytes.len(),"sha256":sha256_bytes(bytes)})
                })
                .collect::<Vec<_>>();
            rows.sort_by(|left, right| left["path"].as_str().cmp(&right["path"].as_str()));
            self.sdk_value["files"] = Value::Array(rows);
            self.rebind_archive(files);
        }

        fn profile_members(&self) -> BTreeMap<String, Vec<u8>> {
            let mut files = BTreeMap::new();
            files.insert("README.md".to_owned(), b"candidate SDK\n".to_vec());
            let profiles = self.sdk_value["profiles"].as_object().unwrap();
            for profile in profiles.values() {
                for component in profile["components"].as_object().unwrap().values() {
                    let path = component["manifest"].as_str().unwrap().to_owned();
                    let component_name = path
                        .rsplit('/')
                        .next()
                        .unwrap()
                        .trim_end_matches(".json")
                        .to_owned();
                    files.insert(
                        path,
                        format!("{{\"component\":\"{component_name}\"}}\n").into_bytes(),
                    );
                }
            }
            files
        }

        fn rebind_archive(&mut self, mut tar_members: BTreeMap<String, Vec<u8>>) {
            let sdk_raw = serde_json::to_vec(&self.sdk_value).unwrap();
            tar_members.insert(SDK_MANIFEST_PATH.to_owned(), sdk_raw.clone());
            self.archive_uncompressed = make_tar(&tar_members);
            let xz_bytes = make_xz(&self.archive_uncompressed);
            let sdk_files = tar_members
                .iter()
                .map(|(path, bytes)| {
                    json!({
                        "path":path,"bytes":bytes.len(),"sha256":sha256_bytes(bytes)
                    })
                })
                .collect::<Vec<_>>();
            let sdk_manifest_sha = sha256_bytes(&sdk_raw);
            let outer = json!({
                "schema":"ami-rust-release-v2","version":self.release.version,
                "qualification_only":self.release.qualification_only,"sdk_archive":"sdk.tar.xz",
                "sdk_manifest_sha256":sdk_manifest_sha,"assets":[
                    {"path":"sdk.tar.xz","bytes":xz_bytes.len(),"sha256":sha256_bytes(&xz_bytes)},
                    {"path":"bin/ami-rust-linux","bytes":4,"sha256":"c".repeat(64)},
                    {"path":"bin/ami-rust-macos","bytes":5,"sha256":"d".repeat(64)}
                ],"sdk_files":sdk_files,
                "producer":{"source_sha":"82edf967fe4a84cde43680108873a44ce8c71b4f"},
                "host_launchers":{
                    "linux-x86_64":{"path":"bin/ami-rust-linux","bytes":4,"sha256":"c".repeat(64)},
                    "macos-aarch64":{"path":"bin/ami-rust-macos","bytes":5,"sha256":"d".repeat(64)}
                }
            });
            self.release =
                parse_native_release_manifest(&serde_json::to_vec(&outer).unwrap(), true).unwrap();
            self.assets.insert("sdk.tar.xz".to_owned(), xz_bytes);
        }

        fn set_release_qualification(&mut self, qualification_only: bool) {
            let xz_bytes = self.assets.get("sdk.tar.xz").unwrap().clone();
            let sdk_files = self
                .release
                .sdk_files
                .iter()
                .map(|row| {
                    json!({
                        "path":row.path,"bytes":row.bytes,"sha256":row.sha256.as_str()
                    })
                })
                .collect::<Vec<_>>();
            let outer = json!({
                "schema":"ami-rust-release-v2",
                "version":self.release.version,
                "qualification_only":qualification_only,
                "sdk_archive":"sdk.tar.xz",
                "sdk_manifest_sha256":self.release.sdk_manifest_sha256.as_str(),
                "assets":[
                    {"path":"sdk.tar.xz","bytes":xz_bytes.len(),"sha256":sha256_bytes(&xz_bytes)},
                    {"path":"bin/ami-rust-linux","bytes":4,"sha256":"c".repeat(64)},
                    {"path":"bin/ami-rust-macos","bytes":5,"sha256":"d".repeat(64)}
                ],
                "sdk_files":sdk_files,
                "producer":{"source_sha":"82edf967fe4a84cde43680108873a44ce8c71b4f"},
                "host_launchers":{
                    "linux-x86_64":{"path":"bin/ami-rust-linux","bytes":4,"sha256":"c".repeat(64)},
                    "macos-aarch64":{"path":"bin/ami-rust-macos","bytes":5,"sha256":"d".repeat(64)}
                }
            });
            self.release =
                parse_native_release_manifest(&serde_json::to_vec(&outer).unwrap(), true).unwrap();
        }

        fn rebind_with_archive_only(&mut self) {
            let xz_bytes = self.assets.get("sdk.tar.xz").unwrap().clone();
            let sdk_files = self
                .release
                .sdk_files
                .iter()
                .map(|row| {
                    json!({
                        "path":row.path,"bytes":row.bytes,"sha256":row.sha256.as_str()
                    })
                })
                .collect::<Vec<_>>();
            let outer = json!({
                "schema":"ami-rust-release-v2",
                "version":self.release.version,
                "qualification_only":self.release.qualification_only,
                "sdk_archive":"sdk.tar.xz",
                "sdk_manifest_sha256":self.release.sdk_manifest_sha256.as_str(),
                "assets":[
                    {"path":"sdk.tar.xz","bytes":xz_bytes.len(),"sha256":sha256_bytes(&xz_bytes)},
                    {"path":"bin/ami-rust-linux","bytes":4,"sha256":"c".repeat(64)},
                    {"path":"bin/ami-rust-macos","bytes":5,"sha256":"d".repeat(64)}
                ],
                "sdk_files":sdk_files,
                "producer":{"source_sha":"82edf967fe4a84cde43680108873a44ce8c71b4f"},
                "host_launchers":{
                    "linux-x86_64":{"path":"bin/ami-rust-linux","bytes":4,"sha256":"c".repeat(64)},
                    "macos-aarch64":{"path":"bin/ami-rust-macos","bytes":5,"sha256":"d".repeat(64)}
                }
            });
            self.release =
                parse_native_release_manifest(&serde_json::to_vec(&outer).unwrap(), true).unwrap();
        }
    }

    fn counter_json(rows: &[(&str, u64)]) -> Value {
        let mut object = serde_json::Map::new();
        for (key, value) in rows {
            object.insert((*key).to_owned(), json!(value));
        }
        Value::Object(object)
    }

    fn host_capacity_json() -> Value {
        let mut value = counter_json(&HOST_CAPACITY);
        value
            .as_object_mut()
            .unwrap()
            .insert("schema".to_owned(), json!("ami-rust-host-capacity-v1"));
        value
    }

    fn make_tar(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        for (path, contents) in files {
            let mut header = Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(1791936000);
            header.set_cksum();
            builder
                .append_data(&mut header, path, contents.as_slice())
                .unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn make_tar_with_unsafe_member(files: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        for (path, contents) in files {
            let mut header = Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(1791936000);
            header.set_cksum();
            builder
                .append_data(&mut header, path, contents.as_slice())
                .unwrap();
        }
        let contents = b"outside\n";
        let mut header = Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(1791936000);
        let header_bytes = header.as_mut_bytes();
        header_bytes[..100].fill(0);
        header_bytes[..9].copy_from_slice(b"../escape");
        header.set_cksum();
        builder.append(&header, contents.as_slice()).unwrap();
        builder.into_inner().unwrap()
    }

    fn make_xz(tar_bytes: &[u8]) -> Vec<u8> {
        let mut encoder = XzWriter::new(Vec::new(), XzOptions::with_preset(1)).unwrap();
        encoder.write_all(tar_bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn compose(fixture: &Fixture) -> crate::Result<VerifiedSdkV2Summary> {
        compose_retained_parts(&fixture.release, &fixture.assets)
    }

    #[test]
    fn composes_valid_sdk_v2_from_retained_release_parts() {
        let fixture = Fixture::valid();
        let result = compose(&fixture).unwrap();
        assert_eq!(result.version, VERSION);
        assert!(!result.qualification_only);
        assert_eq!(result.archive_files, 14);
        assert_eq!(result.component_manifest_files, 12);
    }

    #[test]
    fn refuses_legacy_schema_driver_and_unknown_decision_keys() {
        let fixture = Fixture::valid();
        for (key, value) in [
            ("schema", json!("ami-rust-sdk-v1")),
            ("driver", json!("host/build.py")),
        ] {
            let mut raw = fixture.sdk_value.clone();
            raw[key] = value;
            assert!(
                parse_sdk_v2(&serde_json::to_vec(&raw).unwrap(), VERSION, false).is_err(),
                "{key}"
            );
        }
        let mut raw = fixture.sdk_value.clone();
        raw["arbitrary_command"] = json!(["/tmp/run-me"]);
        assert!(parse_sdk_v2(&serde_json::to_vec(&raw).unwrap(), VERSION, false).is_err());
    }

    #[test]
    fn refuses_release_version_and_qualification_mismatches() {
        let fixture = Fixture::valid();
        let raw = serde_json::to_vec(&fixture.sdk_value).unwrap();
        assert!(parse_sdk_v2(&raw, "9.9.9", false).is_err());
        let mut qualification = fixture.sdk_value.clone();
        qualification["qualification_only"] = json!(true);
        assert!(
            parse_sdk_v2(&serde_json::to_vec(&qualification).unwrap(), VERSION, false).is_err()
        );
        assert!(compose_retained_parts(&fixture.release, &fixture.assets).is_ok());

        let mut qualified_release = Fixture::valid();
        qualified_release.set_release_qualification(true);
        assert!(compose(&qualified_release).is_err());
    }

    #[test]
    fn strict_json_parser_rejects_duplicate_keys_and_noninteger_profile_counters() {
        let fixture = Fixture::valid();
        let raw = serde_json::to_vec(&fixture.sdk_value).unwrap();
        let dup = String::from_utf8(raw).unwrap().replacen(
            "\"driver\":",
            "\"driver\":\"ami-rust-native-compatibility-v1\",\"driver\":",
            1,
        );
        assert!(parse_sdk_v2(dup.as_bytes(), VERSION, false).is_err());
        for bad in [json!(2.0), json!(true), json!(-1), json!(3)] {
            let mut value = fixture.sdk_value.clone();
            value["build"]["jobs"] = bad;
            assert!(parse_sdk_v2(&serde_json::to_vec(&value).unwrap(), VERSION, false).is_err());
        }
    }

    #[test]
    fn refuses_profile_host_mode_and_component_identity_mismatches() {
        let fixture = Fixture::valid();
        let cases = [
            ("rust_host", json!("aarch64-unknown-linux-gnu")),
            ("cargo_metadata_mode", json!("different-mode")),
            ("cargo_binary", json!("bin/unreviewed-cargo")),
        ];
        for (key, value) in cases {
            let mut raw = fixture.sdk_value.clone();
            raw["profiles"]["linux-x86_64"][key] = value;
            assert!(
                parse_sdk_v2(&serde_json::to_vec(&raw).unwrap(), VERSION, false).is_err(),
                "{key}"
            );
        }
        let mut raw = fixture.sdk_value.clone();
        raw["profiles"]["linux-x86_64"]["components"]["cargo"]["sha256"] = json!("0".repeat(64));
        let mut changed = Fixture {
            sdk_value: raw,
            ..fixture
        };
        changed.rebind();
        assert!(compose(&changed).is_err());
    }

    #[test]
    fn component_manifests_must_use_their_unique_host_and_role_paths() {
        let fixture = Fixture::valid();
        for (label, path) in [
            ("wrong host", "host/profiles/macos-aarch64/cargo.json"),
            (
                "wrong component",
                "host/profiles/linux-x86_64/toolchain.json",
            ),
            ("reused path", "host/profiles/linux-x86_64/rust.json"),
        ] {
            let mut changed = Fixture {
                sdk_value: fixture.sdk_value.clone(),
                ..Fixture::valid()
            };
            changed.sdk_value["profiles"]["linux-x86_64"]["components"]["cargo"]["manifest"] =
                json!(path);
            changed.rebind();
            assert!(compose(&changed).is_err(), "{label}");
        }
    }

    #[test]
    fn refuses_inner_inventory_missing_extra_duplicate_and_self_rows() {
        let fixture = Fixture::valid();
        for mutation in ["missing", "extra", "duplicate", "self"] {
            let mut changed = Fixture {
                sdk_value: fixture.sdk_value.clone(),
                ..Fixture::valid()
            };
            let rows = changed.sdk_value["files"].as_array_mut().unwrap();
            match mutation {
                "missing" => {
                    rows.pop();
                }
                "extra" => {
                    rows.push(json!({"path":"extra.bin","bytes":1,"sha256":sha256_bytes(b"x")}))
                }
                "duplicate" => rows.push(rows[0].clone()),
                "self" => rows
                    .push(json!({"path":SDK_MANIFEST_PATH,"bytes":1,"sha256":sha256_bytes(b"x")})),
                _ => unreachable!(),
            }
            let members = changed.profile_members();
            changed.rebind_archive(members);
            assert!(compose(&changed).is_err(), "{mutation}");
        }
    }

    #[test]
    fn refuses_manifest_self_digest_and_outer_inventory_mismatch() {
        let fixture = Fixture::valid();
        let sdk_files = fixture
            .release
            .sdk_files
            .iter()
            .map(|row| {
                json!({
                    "path":row.path,"bytes":row.bytes,"sha256":row.sha256.as_str()
                })
            })
            .collect::<Vec<_>>();
        let xz_bytes = fixture.assets.get("sdk.tar.xz").unwrap();
        let broken_self_pin = json!({
            "schema":"ami-rust-release-v2","version":fixture.release.version,
            "qualification_only":false,"sdk_archive":"sdk.tar.xz",
            "sdk_manifest_sha256":"0".repeat(64),
            "assets":[
                {"path":"sdk.tar.xz","bytes":xz_bytes.len(),"sha256":sha256_bytes(xz_bytes)},
                {"path":"bin/ami-rust-linux","bytes":4,"sha256":"c".repeat(64)},
                {"path":"bin/ami-rust-macos","bytes":5,"sha256":"d".repeat(64)}
            ],"sdk_files":sdk_files,
            "producer":{"source_sha":"82edf967fe4a84cde43680108873a44ce8c71b4f"},
            "host_launchers":{
                "linux-x86_64":{"path":"bin/ami-rust-linux","bytes":4,"sha256":"c".repeat(64)},
                "macos-aarch64":{"path":"bin/ami-rust-macos","bytes":5,"sha256":"d".repeat(64)}
            }
        });
        assert!(
            parse_native_release_manifest(&serde_json::to_vec(&broken_self_pin).unwrap(), true)
                .is_err()
        );

        let mut bad_manifest = Fixture::valid();
        let mut members = BTreeMap::new();
        members.insert(SDK_MANIFEST_PATH.to_owned(), b"{}".to_vec());
        bad_manifest.archive_uncompressed = make_tar(&members);
        bad_manifest.assets.insert(
            "sdk.tar.xz".to_owned(),
            make_xz(&bad_manifest.archive_uncompressed),
        );
        bad_manifest.rebind_with_archive_only();
        assert!(compose(&bad_manifest).is_err());
    }

    #[test]
    fn complete_composition_refuses_raw_unsafe_tar_member_paths() {
        let mut fixture = Fixture::valid();
        let mut members = fixture.profile_members();
        members.insert(
            SDK_MANIFEST_PATH.to_owned(),
            serde_json::to_vec(&fixture.sdk_value).unwrap(),
        );
        fixture.archive_uncompressed = make_tar_with_unsafe_member(&members);
        fixture.assets.insert(
            "sdk.tar.xz".to_owned(),
            make_xz(&fixture.archive_uncompressed),
        );
        fixture.rebind_with_archive_only();
        assert!(compose(&fixture).is_err());
    }

    #[test]
    fn complete_composition_refuses_raw_unsafe_inner_inventory_paths() {
        let mut fixture = Fixture::valid();
        let readme_row = fixture.sdk_value["files"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|row| row["path"] == "README.md")
            .unwrap();
        readme_row["path"] = json!("../escape");

        let members = fixture.profile_members();
        fixture.rebind_archive(members);
        assert!(compose(&fixture).is_err());
    }

    #[test]
    fn refuses_tar_and_xz_corruption() {
        let mut bad_xz = Fixture::valid();
        bad_xz
            .assets
            .insert("sdk.tar.xz".to_owned(), b"not xz".to_vec());
        bad_xz.rebind_with_archive_only();
        assert!(compose(&bad_xz).is_err());

        let mut trailing_xz = Fixture::valid();
        let mut trailing_bytes = trailing_xz.assets.get("sdk.tar.xz").unwrap().clone();
        trailing_bytes.push(0);
        trailing_xz
            .assets
            .insert("sdk.tar.xz".to_owned(), trailing_bytes);
        trailing_xz.rebind_with_archive_only();
        assert!(compose(&trailing_xz).is_err());

        let mut bad_tar = Fixture::valid();
        let corrupt_tar = b"not a tar archive";
        bad_tar
            .assets
            .insert("sdk.tar.xz".to_owned(), make_xz(corrupt_tar));
        // Update the outer asset identity so the corruption reaches TAR verification.
        bad_tar.rebind_with_archive_only();
        assert!(compose(&bad_tar).is_err());
    }
}
