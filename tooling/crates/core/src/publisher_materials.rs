//! Source-derived SLSA material manifest for the hosted SDK publisher.
//!
//! This reproduces `release/ci_auth.py::input_manifest` without invoking that
//! helper or any producer runtime. Every repository file used as a local pin
//! is opened descriptor-relatively without following symlinks, then measured
//! and hashed from the opened regular-file descriptor. Metadata checks detect
//! ordinary concurrent changes; they are not a snapshot against a same-owner
//! writer.

use crate::{
    Refusal, Result,
    digest::{encode_hex, is_sha256_digest},
    directory::{Directory, EntryType},
    json::{JsonProfile, parse_json_value},
};
use serde::Deserialize;
use serde_json::{Map, Value, value::RawValue};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs::{File, Metadata},
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::Path,
};

const REPOSITORY: &str = "metaneutrons/ami-rust";
const INPUT_FILE_LIMIT: u64 = 16 * 1024 * 1024;
const SOURCE_CAPSULE_LIMIT: u64 = 104 * 1024 * 1024;
const PORTABLE_CSDK_SPEC_PATH: &str = "release/portable-csdk/spec.json";
const ORIGINAL_CSDK_ARCHIVE_PATH: &str = "release/inputs/csdk.tar.xz";
const CANDIDATE_CSDK_ARCHIVE_PATH: &str = "release/inputs/portable-csdk.tar.xz";
const CANDIDATE_CSDK_ARCHIVE_NAME: &str = "csdk-component.tar.xz";
const HOSTS: [&str; 2] = ["linux-x86_64", "macos-aarch64"];

#[derive(Clone, Debug, Eq, PartialEq)]
struct MaterialDigest {
    algorithm: String,
    digest: String,
}

#[derive(Clone, Debug)]
struct FilePin {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Deserialize)]
struct RawPatchSeries<'a> {
    #[serde(borrow)]
    patches: Vec<RawPatch<'a>>,
}

#[derive(Deserialize)]
struct RawPatch<'a> {
    #[serde(borrow)]
    patch: &'a str,
    #[serde(borrow)]
    patch_sha256: &'a str,
    #[serde(borrow)]
    bytes: Option<&'a RawValue>,
}

/// Build the exact sorted, pretty-printed `ami-rust-publisher-inputs-v1`
/// material manifest from a detached source checkout.
///
/// Cancellation is checked between inputs and during every streamed file
/// read. This function verifies source-local byte and digest relationships; it
/// does not authenticate a publisher, execute a source helper, or run Python.
pub fn publisher_input_manifest(
    source: &Path,
    mut cancellation_check: impl FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    cancellation_check()?;
    let root = Directory::open(source)?;

    let sdk_inputs_raw = read_source_file(
        &root,
        "release/ci-sdk-inputs.json",
        INPUT_FILE_LIMIT,
        &mut cancellation_check,
    )?;
    let bootstrap_raw = read_source_file(
        &root,
        "release/ci-bootstrap-inputs.json",
        INPUT_FILE_LIMIT,
        &mut cancellation_check,
    )?;
    let python_raw = read_source_file(
        &root,
        "release/ci-python-inputs.json",
        INPUT_FILE_LIMIT,
        &mut cancellation_check,
    )?;
    let auth_tools_raw = read_source_file(
        &root,
        "release/ci-auth-tools.json",
        INPUT_FILE_LIMIT,
        &mut cancellation_check,
    )?;
    let sdk_inputs = parse_json_value(&sdk_inputs_raw, JsonProfile::SdkComponentManifest)?;
    let bootstrap = parse_json_value(&bootstrap_raw, JsonProfile::SdkComponentManifest)?;
    let python = parse_json_value(&python_raw, JsonProfile::SdkComponentManifest)?;
    let auth_tools = parse_json_value(&auth_tools_raw, JsonProfile::SdkComponentManifest)?;

    let mut materials = BTreeMap::new();
    cancellation_check()?;
    let channel = required_field(object(&sdk_inputs, "SDK inputs")?, "channel_manifest")?;
    add_url_material(&mut materials, channel, "channel manifest")?;

    let sdk_hosts = required_field(object(&sdk_inputs, "SDK inputs")?, "hosts")?;
    let python_hosts = required_field(object(&python, "Python inputs")?, "hosts")?;
    for host in HOSTS {
        cancellation_check()?;
        let host_inputs = required_field(object(sdk_hosts, "SDK hosts")?, host)?;
        let rust = required_field(object(host_inputs, "host SDK inputs")?, "rust")?;
        for archive in array(
            required_field(object(rust, "host Rust inputs")?, "archives")?,
            "host Rust archives",
        )? {
            cancellation_check()?;
            add_url_material(&mut materials, archive, "Rust archive")?;
        }
        for component in ["toolchain", "collector"] {
            cancellation_check()?;
            add_url_material(
                &mut materials,
                required_field(object(host_inputs, "host SDK inputs")?, component)?,
                "host component",
            )?;
        }
        add_url_material(
            &mut materials,
            required_field(object(python_hosts, "Python hosts")?, host)?,
            "Python runtime",
        )?;
    }

    let bootstrap_rust = required_field(object(&bootstrap, "bootstrap inputs")?, "rust")?;
    let bootstrap_components = required_field(
        object(bootstrap_rust, "bootstrap Rust inputs")?,
        "components",
    )?;
    for target in object(bootstrap_components, "bootstrap Rust targets")?.values() {
        cancellation_check()?;
        for component in ["rustc", "rust-std", "cargo"] {
            cancellation_check()?;
            add_url_material(
                &mut materials,
                required_field(object(target, "bootstrap Rust target")?, component)?,
                "bootstrap Rust component",
            )?;
        }
    }
    let custom_cargo = required_field(object(&bootstrap, "bootstrap inputs")?, "custom_cargo")?;
    let custom_cargo = object(custom_cargo, "custom Cargo identity")?;
    let cargo_upstream = string_field(custom_cargo, "upstream", "custom Cargo upstream")?;
    let cargo_commit = string_field(custom_cargo, "commit", "custom Cargo commit")?;
    add_material(
        &mut materials,
        format!("{cargo_upstream}@{cargo_commit}"),
        "gitCommit",
        cargo_commit,
    )?;

    let shared = required_field(object(&sdk_inputs, "SDK inputs")?, "shared")?;
    for row in object(shared, "shared SDK inputs")?.values() {
        cancellation_check()?;
        let row = object(row, "shared SDK input")?;
        let path = string_field(row, "path", "shared input path")?;
        let bytes = unsigned_field(row, "bytes", "shared input byte count")?;
        let sha256 = string_field(row, "sha256", "shared input digest")?;
        verify_source_file(
            &root,
            path,
            bytes,
            sha256,
            INPUT_FILE_LIMIT,
            &mut cancellation_check,
        )?;
        add_repository_material(&mut materials, path, sha256)?;
    }

    load_portable_csdk(&root, &sdk_inputs, &mut materials, &mut cancellation_check)?;

    const FIXED_MATERIALS: [&str; 11] = [
        "release/ci-sdk-inputs.json",
        "release/ci-bootstrap-inputs.json",
        "release/ci-python-inputs.json",
        "release/ci-resources.json",
        "release/native-reference.json",
        "release/bundle-files.json",
        "release/ci-auth-tools.json",
        "release/patches/portable-csdk/series.json",
        "release/csdk-source/manifest.json",
        "host/cargo-repro/cargo-metadata.patch",
        "host/cargo-repro/openssl-paths.patch",
    ];
    for path in FIXED_MATERIALS {
        cancellation_check()?;
        let known_bytes = match path {
            "release/ci-sdk-inputs.json" => Some(sdk_inputs_raw.as_slice()),
            "release/ci-bootstrap-inputs.json" => Some(bootstrap_raw.as_slice()),
            "release/ci-python-inputs.json" => Some(python_raw.as_slice()),
            "release/ci-auth-tools.json" => Some(auth_tools_raw.as_slice()),
            _ => None,
        };
        let sha256 = match known_bytes {
            Some(bytes) => sha256_bytes(bytes),
            None => hash_source_file(&root, path, INPUT_FILE_LIMIT, &mut cancellation_check)?.1,
        };
        add_repository_material(&mut materials, path, &sha256)?;
    }

    let tools = object(&auth_tools, "authentication tools")?;
    let tool_hosts = required_field(tools, "hosts")?;
    for host in HOSTS {
        cancellation_check()?;
        let host_tools = required_field(object(tool_hosts, "authentication tool hosts")?, host)?;
        for component in ["gh", "cosign"] {
            cancellation_check()?;
            add_url_material(
                &mut materials,
                required_field(object(host_tools, "host authentication tools")?, component)?,
                "authentication tool",
            )?;
        }
    }
    let roots = required_field(tools, "roots")?;
    for pin_value in object(roots, "authentication trust roots")?.values() {
        cancellation_check()?;
        let pin = object(pin_value, "authentication trust root pin")?;
        let path = string_field(pin, "path", "trust root path")?;
        let bytes = unsigned_field(pin, "bytes", "trust root byte count")?;
        let sha256 = string_field(pin, "sha256", "trust root digest")?;
        verify_source_file(
            &root,
            path,
            bytes,
            sha256,
            INPUT_FILE_LIMIT,
            &mut cancellation_check,
        )?;
        add_repository_material(&mut materials, path, sha256)?;
    }

    cancellation_check()?;
    Ok(encode_manifest(&materials))
}

/// Select the material closure for the requested SDK generation. Historical
/// SDKs retain their original byte-exact closure; native generations also bind
/// the Rust tooling sources, locked crate archives and accepted input capsule.
pub fn publisher_input_manifest_for_sdk(
    source: &Path,
    sdk_version: &str,
    mut cancellation_check: impl FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    let legacy = publisher_input_manifest(source, &mut cancellation_check)?;
    if sdk_version == "0.1.0" {
        return Ok(legacy);
    }
    let parsed = crate::publisher_policy::parse_inputs_manifest(&legacy)?;
    let mut materials = BTreeMap::new();
    for material in parsed.materials {
        use crate::publisher_policy::PinnedMaterialDigest;
        match material.digest {
            PinnedMaterialDigest::Sha256 { sha256 } => {
                add_material(&mut materials, material.uri, "sha256", sha256.as_str())?;
            }
            PinnedMaterialDigest::GitCommit { git_commit } => {
                add_material(&mut materials, material.uri, "gitCommit", &git_commit)?;
            }
        }
    }
    let root = Directory::open(source)?;
    append_native_materials(&root, sdk_version, &mut materials, &mut cancellation_check)?;
    Ok(encode_manifest(&materials))
}

fn append_native_materials(
    root: &Directory,
    sdk_version: &str,
    materials: &mut BTreeMap<String, MaterialDigest>,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    const CONFIG: &str = "release/native-tooling-inputs.json";
    let raw = read_source_file(root, CONFIG, INPUT_FILE_LIMIT, cancellation_check)?;
    let value = parse_json_value(&raw, JsonProfile::SdkComponentManifest)?;
    let config = object(&value, "native tooling inputs")?;
    require_exact_fields(
        config,
        &[
            "schema",
            "sdk_version",
            "cli_version",
            "legacy_release",
            "cargo_lock",
            "registry_crates",
            "source_files",
        ],
        "native tooling inputs",
    )?;
    if string_field(config, "schema", "native inputs schema")?
        != "ami-rust-native-tooling-inputs-v1"
        || string_field(config, "sdk_version", "native SDK version")? != sdk_version
        || sdk_version == "0.1.0"
    {
        return Err(Refusal::new(
            "native tooling inputs select a different SDK generation",
        ));
    }
    let cli_version = string_field(config, "cli_version", "native CLI version")?;
    if cli_version.split('-').next() != Some(sdk_version) {
        return Err(Refusal::new("native CLI and SDK version cores differ"));
    }
    let lock = file_pin(required_field(config, "cargo_lock")?, "native Cargo lock")?;
    if lock.path != "tooling/Cargo.lock" {
        return Err(Refusal::new("native producer must pin tooling/Cargo.lock"));
    }
    verify_source_file(
        root,
        &lock.path,
        lock.bytes,
        &lock.sha256,
        INPUT_FILE_LIMIT,
        cancellation_check,
    )?;
    let baseline_raw = read_source_file(
        root,
        "tooling/fixtures/accepted-r1-inputs.json",
        INPUT_FILE_LIMIT,
        cancellation_check,
    )?;
    let baseline = parse_json_value(&baseline_raw, JsonProfile::SdkComponentManifest)?;
    let accepted_archive =
        &baseline["accepted_release"]["public_provenance"]["public_release_archive_asset"];
    let capsule = required_field(config, "legacy_release")?;
    let capsule_object = object(capsule, "accepted input capsule")?;
    require_exact_fields(
        capsule_object,
        &["url", "bytes", "sha256"],
        "accepted input capsule",
    )?;
    if capsule["bytes"] != accepted_archive["bytes"]
        || capsule["sha256"] != accepted_archive["sha256"]
        || capsule["url"].as_str()
            != Some(
                "https://github.com/metaneutrons/ami-rust/releases/download/v0.1.0/ami-rust-0.1.0-release.tar.xz",
            )
    {
        return Err(Refusal::new(
            "native producer input capsule differs from the accepted baseline",
        ));
    }
    add_url_material(materials, capsule, "accepted input capsule")?;
    let sources = array(
        required_field(config, "source_files")?,
        "native source files",
    )?;
    if sources.is_empty() || sources.len() > 1_000 {
        return Err(Refusal::new(
            "invalid native producer source inventory length",
        ));
    }
    let mut previous = None;
    for path in sources {
        cancellation_check()?;
        let path = path
            .as_str()
            .ok_or_else(|| Refusal::new("native source path must be a string"))?;
        validate_source_path(path)?;
        if !(path.starts_with("tooling/")
            || matches!(
                path,
                "tools/bootstrap-host-rust.sh" | "tools/build-native-cli.sh"
            ))
            || previous.is_some_and(|previous: &str| previous >= path)
        {
            return Err(Refusal::new(
                "native source inventory has unsupported or unordered paths",
            ));
        }
        previous = Some(path);
        let (_, digest) = hash_source_file(root, path, INPUT_FILE_LIMIT, cancellation_check)?;
        add_repository_material(materials, path, &digest)?;
    }
    for required in [
        "tooling/Cargo.lock",
        "tooling/Cargo.toml",
        "tooling/crates/core/build.rs",
        "tooling/crates/core/src/macos_process_snapshot.c",
        "tooling/crates/core/src/macos_process_snapshot.rs",
        "tooling/crates/xtask/src/native_release.rs",
        "tooling/macos-host-selection.rs",
        "tooling/fixtures/accepted-r1-inputs.json",
        "tooling/fixtures/accepted-r1-support-inputs.json",
        "tools/bootstrap-host-rust.sh",
        "tools/build-native-cli.sh",
    ] {
        if !sources.iter().any(|path| path.as_str() == Some(required)) {
            return Err(Refusal::new(
                "native producer source inventory omits a required input",
            ));
        }
    }
    let crates = array(
        required_field(config, "registry_crates")?,
        "native registry crates",
    )?;
    if crates.len() != 29 {
        return Err(Refusal::new(
            "native producer registry set differs from the reviewed 29-crate selection",
        ));
    }
    let mut previous = None;
    for row in crates {
        cancellation_check()?;
        let record = object(row, "native crate input")?;
        require_exact_fields(
            record,
            &["name", "version", "url", "sha256"],
            "native crate input",
        )?;
        let name = string_field(record, "name", "native crate name")?;
        let version = string_field(record, "version", "native crate version")?;
        if name.is_empty()
            || version.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || !version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
            || previous.is_some_and(|previous| previous >= (name, version))
            || string_field(record, "url", "native crate URL")?
                != format!("https://static.crates.io/crates/{name}/{name}-{version}.crate")
        {
            return Err(Refusal::new(
                "invalid or unordered native registry crate identity",
            ));
        }
        previous = Some((name, version));
        add_url_material(materials, row, "native crate input")?;
    }
    add_repository_material(materials, CONFIG, &sha256_bytes(&raw))?;
    cancellation_check()
}

fn load_portable_csdk(
    root: &Directory,
    inputs: &Value,
    materials: &mut BTreeMap<String, MaterialDigest>,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    cancellation_check()?;
    let pin_value = required_field(object(inputs, "SDK inputs")?, "portable_csdk")?;
    let specification_pin = file_pin(pin_value, "portable C-SDK specification pin")?;
    if specification_pin.path != PORTABLE_CSDK_SPEC_PATH {
        return Err(Refusal::new(
            "SDK inputs do not pin the normative portable C-SDK specification",
        ));
    }
    let specification_raw = read_pinned_source_file(
        root,
        &specification_pin,
        INPUT_FILE_LIMIT,
        "portable C-SDK specification",
        cancellation_check,
    )?;
    let specification = parse_json_value(&specification_raw, JsonProfile::SdkComponentManifest)?;
    validate_portable_csdk_spec(&specification)?;

    let spec_object = object(&specification, "portable C-SDK specification")?;
    let original = object(
        required_field(spec_object, "original")?,
        "original C-SDK identity",
    )?;
    let candidate = object(
        required_field(spec_object, "candidate")?,
        "candidate C-SDK identity",
    )?;
    let original_archive = file_pin(
        required_field(original, "archive")?,
        "original C-SDK archive pin",
    )?;
    let shared_csdk = required_field(
        object(
            required_field(object(inputs, "SDK inputs")?, "shared")?,
            "shared SDK inputs",
        )?,
        "csdk",
    )?;
    let shared_csdk = object(shared_csdk, "shared C-SDK archive pin")?;
    if string_field(shared_csdk, "path", "shared C-SDK path")? != original_archive.path
        || unsigned_field(shared_csdk, "bytes", "shared C-SDK byte count")?
            != original_archive.bytes
        || string_field(shared_csdk, "sha256", "shared C-SDK digest")? != original_archive.sha256
    {
        return Err(Refusal::new(
            "portable C-SDK original archive differs from the shared SDK input pin",
        ));
    }

    let original_profile = file_pin(
        required_field(original, "profile")?,
        "original portable C-SDK profile pin",
    )?;
    let candidate_profile = file_pin(
        required_field(candidate, "profile")?,
        "candidate portable C-SDK profile pin",
    )?;
    let candidate_archive = candidate_archive_pin(required_field(candidate, "archive")?)?;
    let patch_series = file_pin(
        required_field(spec_object, "patch_series")?,
        "portable C-SDK patch-series pin",
    )?;
    let source_capsule = file_pin(
        required_field(spec_object, "source_capsule")?,
        "portable C-SDK source-capsule pin",
    )?;
    let source_manifest = file_pin(
        required_field(spec_object, "source_manifest")?,
        "portable C-SDK source-manifest pin",
    )?;

    verify_pinned_source_file(
        root,
        &original_profile,
        INPUT_FILE_LIMIT,
        "original C-SDK profile",
        cancellation_check,
    )?;
    verify_pinned_source_file(
        root,
        &candidate_profile,
        INPUT_FILE_LIMIT,
        "candidate C-SDK profile",
        cancellation_check,
    )?;
    verify_pinned_source_file(
        root,
        &original_archive,
        INPUT_FILE_LIMIT,
        "original C-SDK archive",
        cancellation_check,
    )?;
    verify_pinned_source_file(
        root,
        &candidate_archive,
        INPUT_FILE_LIMIT,
        "candidate C-SDK archive",
        cancellation_check,
    )?;

    let toolchains = object(
        required_field(spec_object, "toolchains")?,
        "C-SDK toolchains",
    )?;
    for host in HOSTS {
        cancellation_check()?;
        let components = object(required_field(toolchains, host)?, "C-SDK toolchain profile")?;
        let profile = file_pin(
            required_field(components, "profile")?,
            "C-SDK toolchain profile pin",
        )?;
        verify_pinned_source_file(
            root,
            &profile,
            INPUT_FILE_LIMIT,
            "C-SDK toolchain profile",
            cancellation_check,
        )?;
    }

    let series_raw = read_pinned_source_file(
        root,
        &patch_series,
        INPUT_FILE_LIMIT,
        "portable C-SDK patch series",
        cancellation_check,
    )?;
    let source_manifest_raw = read_pinned_source_file(
        root,
        &source_manifest,
        INPUT_FILE_LIMIT,
        "portable C-SDK source manifest",
        cancellation_check,
    )?;
    verify_pinned_source_file(
        root,
        &source_capsule,
        SOURCE_CAPSULE_LIMIT,
        "portable C-SDK corresponding-source capsule",
        cancellation_check,
    )?;
    let series = parse_json_value(&series_raw, JsonProfile::SdkComponentManifest)?;
    let source_manifest_value =
        parse_json_value(&source_manifest_raw, JsonProfile::SdkComponentManifest)?;
    let capsule = required_field(
        object(&source_manifest_value, "portable C-SDK source manifest")?,
        "capsule",
    )?;
    let capsule = object(capsule, "portable C-SDK source-manifest capsule")?;
    let capsule_relative = validate_source_path(string_field(
        capsule,
        "path",
        "portable C-SDK source-manifest capsule path",
    )?)?;
    let capsule_path = format!("release/csdk-source/{capsule_relative}");
    let series_object = object(&series, "portable C-SDK patch series")?;
    if capsule_path != source_capsule.path
        || unsigned_field(capsule, "bytes", "source-manifest capsule byte count")?
            != source_capsule.bytes
        || string_field(capsule, "sha256", "source-manifest capsule digest")?
            != source_capsule.sha256
        || string_field(
            series_object,
            "original_source_capsule_sha256",
            "patch-series source-capsule digest",
        )? != source_capsule.sha256
    {
        return Err(Refusal::new(
            "portable C-SDK capsule, source manifest and patch-series pins disagree",
        ));
    }

    let patch_rows = array(
        required_field(series_object, "patches")?,
        "portable C-SDK patch rows",
    )?;
    let raw_patch_rows = raw_patch_series(&series_raw)?;
    if raw_patch_rows.len() != patch_rows.len() {
        return Err(Refusal::new(
            "portable C-SDK patch rows changed during parsing",
        ));
    }
    for (patch_value, raw_patch) in patch_rows.iter().zip(raw_patch_rows) {
        cancellation_check()?;
        let patch = object(patch_value, "portable C-SDK patch row")?;
        let patch_leaf =
            validate_source_path(string_field(patch, "patch", "portable C-SDK patch path")?)?;
        let patch_path = format!("release/patches/portable-csdk/{patch_leaf}");
        let patch_sha = string_field(patch, "patch_sha256", "portable C-SDK patch digest")?;
        if raw_patch.patch != patch_leaf || raw_patch.patch_sha256 != patch_sha {
            return Err(Refusal::new(
                "portable C-SDK patch rows changed during parsing",
            ));
        }
        let patch_bytes = positive_integer_token(raw_patch.bytes);
        if let Some(bytes) = patch_bytes {
            verify_source_file(
                root,
                &patch_path,
                bytes,
                patch_sha,
                INPUT_FILE_LIMIT,
                cancellation_check,
            )?;
        } else {
            let (_, observed_sha) =
                hash_source_file(root, &patch_path, INPUT_FILE_LIMIT, cancellation_check)?;
            if observed_sha != patch_sha {
                return Err(Refusal::new(
                    "portable C-SDK patch differs from its source digest",
                ));
            }
        }
        add_repository_material(materials, &patch_path, patch_sha)?;
    }

    for pin in [
        &specification_pin,
        &original_profile,
        &candidate_profile,
        &original_archive,
        &candidate_archive,
        &patch_series,
        &source_capsule,
        &source_manifest,
    ] {
        cancellation_check()?;
        add_repository_material(materials, &pin.path, &pin.sha256)?;
    }
    for host in HOSTS {
        cancellation_check()?;
        let components = object(required_field(toolchains, host)?, "C-SDK toolchain profile")?;
        let profile = file_pin(
            required_field(components, "profile")?,
            "C-SDK toolchain profile pin",
        )?;
        add_repository_material(materials, &profile.path, &profile.sha256)?;
    }
    Ok(())
}

fn validate_portable_csdk_spec(value: &Value) -> Result<()> {
    let spec = object(value, "portable C-SDK specification")?;
    require_exact_fields(
        spec,
        &[
            "schema",
            "status",
            "original",
            "candidate",
            "nouveau",
            "patch_series",
            "required_counts",
            "source_capsule",
            "source_manifest",
            "toolchains",
        ],
        "portable C-SDK specification",
    )?;
    if string_field(spec, "schema", "portable C-SDK schema")? != "ami-rust-portable-csdk-v1"
        || string_field(spec, "status", "portable C-SDK status")?
            != "PINNED_CANDIDATE_TWO_HOST_QUALIFICATION_REQUIRED"
    {
        return Err(Refusal::new("unsupported portable C-SDK specification"));
    }

    let original = object(required_field(spec, "original")?, "original C-SDK identity")?;
    let candidate = object(
        required_field(spec, "candidate")?,
        "candidate C-SDK identity",
    )?;
    require_exact_fields(original, &["profile", "archive"], "original C-SDK identity")?;
    require_exact_fields(
        candidate,
        &["profile", "archive"],
        "candidate C-SDK identity",
    )?;
    let original_profile = file_pin(
        required_field(original, "profile")?,
        "original C-SDK profile pin",
    )?;
    let candidate_profile = file_pin(
        required_field(candidate, "profile")?,
        "candidate C-SDK profile pin",
    )?;
    let original_archive = file_pin(
        required_field(original, "archive")?,
        "original C-SDK archive pin",
    )?;
    if original_archive.path != ORIGINAL_CSDK_ARCHIVE_PATH
        || original_profile.path != "release/portable-csdk/original-profile.json"
        || candidate_profile.path != "release/portable-csdk/profile.json"
    {
        return Err(Refusal::new(
            "portable C-SDK original or candidate path is not normative",
        ));
    }
    let candidate_archive = candidate_archive_pin(required_field(candidate, "archive")?)?;
    if candidate_archive.path != CANDIDATE_CSDK_ARCHIVE_PATH
        || candidate_archive_name(candidate, "archive")? != CANDIDATE_CSDK_ARCHIVE_NAME
    {
        return Err(Refusal::new(
            "portable C-SDK candidate archive differs from its repository prerequisite",
        ));
    }

    let patch_series = file_pin(
        required_field(spec, "patch_series")?,
        "portable C-SDK patch-series pin",
    )?;
    let source_capsule = file_pin(
        required_field(spec, "source_capsule")?,
        "portable C-SDK source-capsule pin",
    )?;
    let source_manifest = file_pin(
        required_field(spec, "source_manifest")?,
        "portable C-SDK source-manifest pin",
    )?;
    if patch_series.path != "release/patches/portable-csdk/series.json"
        || source_capsule.path != "release/csdk-source/csdk-corresponding-source.tar.xz"
        || source_manifest.path != "release/csdk-source/manifest.json"
    {
        return Err(Refusal::new(
            "portable C-SDK source material path is not normative",
        ));
    }

    let counts = object(
        required_field(spec, "required_counts")?,
        "C-SDK change counts",
    )?;
    require_exact_fields(
        counts,
        &["changed_files", "public_headers", "regular_files"],
        "C-SDK change counts",
    )?;
    if unsigned_field(counts, "changed_files", "changed file count")? != 532
        || unsigned_field(counts, "public_headers", "public header count")? != 530
        || unsigned_field(counts, "regular_files", "regular file count")? != 2835
    {
        return Err(Refusal::new(
            "portable C-SDK change counts differ from the reviewed values",
        ));
    }

    validate_nouveau(required_field(spec, "nouveau")?)?;
    let toolchains = object(required_field(spec, "toolchains")?, "C-SDK toolchains")?;
    if toolchains.len() != HOSTS.len() || HOSTS.iter().any(|host| !toolchains.contains_key(*host)) {
        return Err(Refusal::new(
            "portable C-SDK toolchain profiles are incomplete",
        ));
    }
    for host in HOSTS {
        let components = object(required_field(toolchains, host)?, "C-SDK toolchain profile")?;
        require_exact_fields(
            components,
            &["compiler", "profile"],
            "C-SDK toolchain identity",
        )?;
        let compiler = object(
            required_field(components, "compiler")?,
            "C-SDK compiler pin",
        )?;
        require_exact_fields(compiler, &["path", "bytes", "sha256"], "C-SDK compiler pin")?;
        if string_field(compiler, "path", "C-SDK compiler path")? != "bin/clang-11"
            || unsigned_field(compiler, "bytes", "C-SDK compiler byte count")? == 0
            || !is_sha256_digest(string_field(compiler, "sha256", "C-SDK compiler digest")?)
        {
            return Err(Refusal::new("malformed portable C-SDK compiler pin"));
        }
        let profile = file_pin(
            required_field(components, "profile")?,
            "C-SDK toolchain profile pin",
        )?;
        let expected_path = format!("release/portable-csdk/toolchains/{host}.json");
        if profile.path != expected_path {
            return Err(Refusal::new(
                "portable C-SDK toolchain profile path is not normative",
            ));
        }
    }
    Ok(())
}

fn validate_nouveau(value: &Value) -> Result<()> {
    let nouveau = object(value, "portable C-SDK nouveau identity")?;
    require_exact_fields(
        nouveau,
        &[
            "archive_path",
            "derived_bytes",
            "derived_sha256",
            "historical_source_prefix",
            "objects",
            "original_bytes",
            "original_sha256",
            "path_changed_members",
            "symbols",
            "unchanged_members",
        ],
        "portable C-SDK nouveau identity",
    )?;
    validate_source_path(string_field(
        nouveau,
        "archive_path",
        "nouveau archive path",
    )?)?;
    for key in ["derived_sha256", "original_sha256"] {
        if !is_sha256_digest(string_field(nouveau, key, "nouveau digest")?) {
            return Err(Refusal::new("malformed portable C-SDK nouveau digest"));
        }
    }
    let _ = string_field(
        nouveau,
        "historical_source_prefix",
        "historical nouveau source prefix",
    )?;
    for key in [
        "derived_bytes",
        "objects",
        "original_bytes",
        "path_changed_members",
        "symbols",
        "unchanged_members",
    ] {
        unsigned_field(nouveau, key, "nouveau measurement")?;
    }
    Ok(())
}

fn candidate_archive_name<'a>(candidate: &'a Map<String, Value>, key: &str) -> Result<&'a str> {
    let archive = required_field(candidate, key)?;
    string_field(
        object(archive, "candidate C-SDK archive pin")?,
        "name",
        "candidate archive name",
    )
}

fn candidate_archive_pin(value: &Value) -> Result<FilePin> {
    let object = object(value, "candidate C-SDK archive pin")?;
    require_exact_fields(
        object,
        &["path", "name", "bytes", "sha256"],
        "candidate C-SDK archive pin",
    )?;
    let name = string_field(object, "name", "candidate C-SDK archive name")?;
    validate_source_path(name)?;
    Ok(FilePin {
        path: validate_source_path(string_field(
            object,
            "path",
            "candidate C-SDK archive path",
        )?)?
        .to_owned(),
        bytes: positive_unsigned_field(object, "bytes", "candidate archive byte count")?,
        sha256: checked_digest(string_field(object, "sha256", "candidate archive digest")?)?,
    })
}

fn file_pin(value: &Value, label: &str) -> Result<FilePin> {
    let object = object(value, label)?;
    require_exact_fields(object, &["path", "bytes", "sha256"], label)?;
    Ok(FilePin {
        path: validate_source_path(string_field(object, "path", "pinned source path")?)?.to_owned(),
        bytes: positive_unsigned_field(object, "bytes", "pinned source byte count")?,
        sha256: checked_digest(string_field(object, "sha256", "pinned source digest")?)?,
    })
}

fn verify_pinned_source_file(
    root: &Directory,
    pin: &FilePin,
    maximum_bytes: u64,
    label: &str,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let (bytes, digest) = hash_source_file(root, &pin.path, maximum_bytes, cancellation_check)?;
    if bytes != pin.bytes || digest != pin.sha256 {
        return Err(Refusal::new(format!("{label} differs from its source pin")));
    }
    Ok(())
}

fn read_pinned_source_file(
    root: &Directory,
    pin: &FilePin,
    maximum_bytes: u64,
    label: &str,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    let bytes = read_source_file(root, &pin.path, maximum_bytes, cancellation_check)?;
    if bytes.len() as u64 != pin.bytes || sha256_bytes(&bytes) != pin.sha256 {
        return Err(Refusal::new(format!("{label} differs from its source pin")));
    }
    Ok(bytes)
}

fn verify_source_file(
    root: &Directory,
    path: &str,
    expected_bytes: u64,
    expected_sha256: &str,
    maximum_bytes: u64,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    let (actual_bytes, actual_sha256) =
        hash_source_file(root, path, maximum_bytes, cancellation_check)?;
    if actual_bytes != expected_bytes || actual_sha256 != expected_sha256 {
        return Err(Refusal::new("repository input differs from its source pin"));
    }
    Ok(())
}

fn hash_source_file(
    root: &Directory,
    path: &str,
    maximum_bytes: u64,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<(u64, String)> {
    let mut file = open_source_regular(root, path)?;
    let before = file_state(&file)?;
    if before.length > maximum_bytes {
        return Err(Refusal::new(
            "repository input exceeds its source byte limit",
        ));
    }
    let read_bound = before
        .length
        .checked_add(1)
        .ok_or_else(|| Refusal::new("repository input length overflow"))?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        cancellation_check()?;
        let remaining = read_bound.saturating_sub(total);
        let amount = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| Refusal::new("repository input read length is not representable"))?;
        if amount == 0 {
            return Err(Refusal::new("repository input grew while hashing"));
        }
        let count = match file.read(&mut buffer[..amount]) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not hash repository input: {error}"
                )));
            }
        };
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| Refusal::new("repository input byte count overflow"))?;
        if total > before.length {
            return Err(Refusal::new("repository input grew while hashing"));
        }
        digest.update(&buffer[..count]);
    }
    let after = file_state(&file)?;
    if total != before.length || before != after {
        return Err(Refusal::new("repository input changed while hashing"));
    }
    let digest: [u8; 32] = digest.finalize().into();
    Ok((total, encode_hex(&digest)))
}

fn read_source_file(
    root: &Directory,
    path: &str,
    maximum_bytes: u64,
    cancellation_check: &mut impl FnMut() -> Result<()>,
) -> Result<Vec<u8>> {
    let mut file = open_source_regular(root, path)?;
    let before = file_state(&file)?;
    if before.length > maximum_bytes {
        return Err(Refusal::new(
            "repository input exceeds its source byte limit",
        ));
    }
    let initial_capacity = usize::try_from(before.length)
        .map_err(|_| Refusal::new("repository input length is not representable"))?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(initial_capacity)
        .map_err(|error| {
            Refusal::new(format!(
                "could not allocate repository input buffer: {error}"
            ))
        })?;
    let read_bound = before
        .length
        .checked_add(1)
        .ok_or_else(|| Refusal::new("repository input length overflow"))?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        cancellation_check()?;
        let remaining = read_bound.saturating_sub(output.len() as u64);
        let amount = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| Refusal::new("repository input read length is not representable"))?;
        if amount == 0 {
            return Err(Refusal::new("repository input grew while reading"));
        }
        let count = match file.read(&mut buffer[..amount]) {
            Ok(0) => break,
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Refusal::new(format!(
                    "could not read repository input: {error}"
                )));
            }
        };
        let new_length = output
            .len()
            .checked_add(count)
            .ok_or_else(|| Refusal::new("repository input byte count overflow"))?;
        if new_length as u64 > before.length {
            return Err(Refusal::new("repository input grew while reading"));
        }
        output.try_reserve(count).map_err(|error| {
            Refusal::new(format!("could not grow repository input buffer: {error}"))
        })?;
        output.extend_from_slice(&buffer[..count]);
    }
    let after = file_state(&file)?;
    if output.len() as u64 != before.length || before != after {
        return Err(Refusal::new("repository input changed while reading"));
    }
    Ok(output)
}

fn open_source_regular(root: &Directory, path: &str) -> Result<File> {
    let path = validate_source_path(path)?;
    let (parent_path, leaf) = match path.rsplit_once('/') {
        Some((parent, leaf)) => (parent, leaf),
        None => ("", path),
    };
    let parent = root.relative_directory(parent_path)?;
    let leaf = OsStr::new(leaf);
    let identity = parent.classify_entry(leaf)?;
    if identity.entry_type() != EntryType::RegularFile {
        return Err(Refusal::new("repository input is not a regular file"));
    }
    parent.open_regular_matching(leaf, identity)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileState {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    length: u64,
    mtime_seconds: i64,
    mtime_nanoseconds: i64,
    ctime_seconds: i64,
    ctime_nanoseconds: i64,
}

fn file_state(file: &File) -> Result<FileState> {
    let metadata = file
        .metadata()
        .map_err(|error| Refusal::new(format!("could not inspect repository input: {error}")))?;
    if !metadata.file_type().is_file() {
        return Err(Refusal::new("repository input is not a regular file"));
    }
    Ok(state_from_metadata(&metadata))
}

fn state_from_metadata(metadata: &Metadata) -> FileState {
    FileState {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        length: metadata.len(),
        mtime_seconds: metadata.mtime(),
        mtime_nanoseconds: metadata.mtime_nsec(),
        ctime_seconds: metadata.ctime(),
        ctime_nanoseconds: metadata.ctime_nsec(),
    }
}

fn add_url_material(
    materials: &mut BTreeMap<String, MaterialDigest>,
    value: &Value,
    label: &str,
) -> Result<()> {
    let row = object(value, label)?;
    add_material(
        materials,
        string_field(row, "url", "publisher input URL")?.to_owned(),
        "sha256",
        string_field(row, "sha256", "publisher input SHA-256")?,
    )
}

fn add_repository_material(
    materials: &mut BTreeMap<String, MaterialDigest>,
    path: &str,
    digest: &str,
) -> Result<()> {
    validate_source_path(path)?;
    add_material(
        materials,
        format!("git+https://github.com/{REPOSITORY}#{path}"),
        "sha256",
        digest,
    )
}

fn add_material(
    materials: &mut BTreeMap<String, MaterialDigest>,
    uri: String,
    algorithm: &str,
    digest: &str,
) -> Result<()> {
    match algorithm {
        "sha256" if is_sha256_digest(digest) => {}
        "gitCommit" if is_lower_hex_40(digest) => {}
        _ => return Err(Refusal::new("invalid publisher input material digest")),
    }
    let identity = MaterialDigest {
        algorithm: algorithm.to_owned(),
        digest: digest.to_owned(),
    };
    if let Some(previous) = materials.get(&uri) {
        if previous != &identity {
            return Err(Refusal::new("conflicting publisher material identity"));
        }
    } else {
        materials.insert(uri, identity);
    }
    Ok(())
}

fn encode_manifest(materials: &BTreeMap<String, MaterialDigest>) -> Vec<u8> {
    let mut output = String::new();
    output.push_str("{\n  \"materials\": [");
    if !materials.is_empty() {
        output.push('\n');
        for (index, (uri, material)) in materials.iter().enumerate() {
            output.push_str("    {\n      \"digest\": {\n        ");
            write_json_string(&mut output, &material.algorithm);
            output.push_str(": ");
            write_json_string(&mut output, &material.digest);
            output.push_str("\n      },\n      \"uri\": ");
            write_json_string(&mut output, uri);
            output.push_str("\n    }");
            if index + 1 != materials.len() {
                output.push(',');
            }
            output.push('\n');
        }
        output.push_str("  ");
    }
    output.push_str("],\n  \"schema\": \"ami-rust-publisher-inputs-v1\"\n}\n");
    output.into_bytes()
}

fn write_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\t' => output.push_str("\\t"),
            '\n' => output.push_str("\\n"),
            '\u{000c}' => output.push_str("\\f"),
            '\r' => output.push_str("\\r"),
            character if (' '..='~').contains(&character) => output.push(character),
            character if u32::from(character) <= 0xffff => {
                use std::fmt::Write as _;
                write!(output, "\\u{:04x}", u32::from(character))
                    .expect("writing JSON into String cannot fail");
            }
            character => {
                let scalar = u32::from(character) - 0x1_0000;
                let high = 0xd800 + (scalar >> 10);
                let low = 0xdc00 + (scalar & 0x3ff);
                use std::fmt::Write as _;
                write!(output, "\\u{high:04x}\\u{low:04x}")
                    .expect("writing JSON into String cannot fail");
            }
        }
    }
    output.push('"');
}

fn validate_source_path(path: &str) -> Result<&str> {
    let bytes = path.as_bytes();
    if path.is_empty()
        || bytes.len() > 240
        || bytes.iter().any(|byte| *byte < 0x20 || *byte >= 0x7f)
        || path.contains(['\\', ':'])
    {
        return Err(Refusal::new("unsafe portable C-SDK source path"));
    }
    let components: Vec<&str> = path.split('/').collect();
    if components.len() > 24
        || components.iter().any(|component| {
            component.is_empty()
                || component.len() > 120
                || *component == "."
                || *component == ".."
                || component.ends_with('.')
                || !component.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-')
                })
                || is_reserved_component(component)
        })
    {
        return Err(Refusal::new("nonportable publisher source path"));
    }
    Ok(path)
}

fn is_reserved_component(component: &str) -> bool {
    let base = component.split('.').next().unwrap_or(component);
    let upper = base.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ["COM", "LPT"].iter().any(|prefix| {
            upper.strip_prefix(prefix).is_some_and(|suffix| {
                suffix.len() == 1 && suffix.as_bytes()[0].is_ascii_digit() && suffix != "0"
            })
        })
}

fn is_lower_hex_40(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn checked_digest(value: &str) -> Result<String> {
    if !is_sha256_digest(value) {
        return Err(Refusal::new("invalid portable C-SDK source digest"));
    }
    Ok(value.to_owned())
}

fn object<'a>(value: &'a Value, label: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| Refusal::new(format!("{label} must be a JSON object")))
}

fn array<'a>(value: &'a Value, label: &str) -> Result<&'a [Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| Refusal::new(format!("{label} must be a JSON array")))
}

fn required_field<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Value> {
    object
        .get(key)
        .ok_or_else(|| Refusal::new(format!("publisher source metadata omits {key}")))
}

fn string_field<'a>(object: &'a Map<String, Value>, key: &str, label: &str) -> Result<&'a str> {
    required_field(object, key)?
        .as_str()
        .ok_or_else(|| Refusal::new(format!("{label} must be a string")))
}

fn unsigned_field(object: &Map<String, Value>, key: &str, label: &str) -> Result<u64> {
    required_field(object, key)?
        .as_u64()
        .ok_or_else(|| Refusal::new(format!("{label} must be a nonnegative integer")))
}

fn positive_unsigned_field(object: &Map<String, Value>, key: &str, label: &str) -> Result<u64> {
    let value = unsigned_field(object, key, label)?;
    if value == 0 {
        return Err(Refusal::new(format!("{label} must be positive")));
    }
    Ok(value)
}

fn raw_patch_series(raw: &[u8]) -> Result<Vec<RawPatch<'_>>> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    deserializer.disable_recursion_limit();
    let series = RawPatchSeries::deserialize(&mut deserializer)
        .map_err(|error| Refusal::new(format!("invalid portable C-SDK patch series: {error}")))?;
    deserializer
        .end()
        .map_err(|error| Refusal::new(format!("invalid portable C-SDK patch series: {error}")))?;
    Ok(series.patches)
}

fn positive_integer_token(value: Option<&RawValue>) -> Option<u64> {
    let token = value?.get();
    if token.is_empty() || !token.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let value = token.parse::<u64>().unwrap_or(u64::MAX);
    (value > 0).then_some(value)
}

fn require_exact_fields(object: &Map<String, Value>, expected: &[&str], label: &str) -> Result<()> {
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(Refusal::new(format!(
            "{label} has unknown or missing fields"
        )));
    }
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    encode_hex(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn native_materials_bind_the_locked_sources_and_refuse_changed_lock_or_capsule() {
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        let native = parse_json_value(
            &std::fs::read(source.join("release/native-tooling-inputs.json")).unwrap(),
            JsonProfile::SdkComponentManifest,
        )
        .unwrap();
        let root = Directory::open(&source).unwrap();
        let mut materials = BTreeMap::new();
        append_native_materials(&root, "0.2.0", &mut materials, &mut || Ok(())).unwrap();
        assert!(materials.contains_key(
            "git+https://github.com/metaneutrons/ami-rust#tooling/crates/cli/src/main.rs"
        ));
        assert!(materials.contains_key(native["legacy_release"]["url"].as_str().unwrap()));
        let mut cancelled = || Err(Refusal::new("cancelled native materials"));
        assert!(
            append_native_materials(&root, "0.2.0", &mut BTreeMap::new(), &mut cancelled).is_err()
        );
        assert!(
            append_native_materials(&root, "0.3.0", &mut BTreeMap::new(), &mut || Ok(())).is_err()
        );

        let temporary = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("ami-native-materials-{}", std::process::id()));
        std::fs::create_dir(&temporary).unwrap();
        {
            for path in native["source_files"].as_array().unwrap() {
                let path = path.as_str().unwrap();
                let target = temporary.join(path);
                std::fs::create_dir_all(target.parent().unwrap()).unwrap();
                std::fs::copy(source.join(path), target).unwrap();
            }
            let config_path = temporary.join("release/native-tooling-inputs.json");
            std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
            std::fs::write(&config_path, serde_json::to_vec(&native).unwrap()).unwrap();
            let root = Directory::open(&temporary).unwrap();
            append_native_materials(&root, "0.2.0", &mut BTreeMap::new(), &mut || Ok(())).unwrap();

            let selector_path = "tooling/macos-host-selection.rs";
            let mut missing_selector = native.clone();
            missing_selector["source_files"]
                .as_array_mut()
                .unwrap()
                .retain(|path| path.as_str() != Some(selector_path));
            std::fs::write(&config_path, serde_json::to_vec(&missing_selector).unwrap()).unwrap();
            assert!(
                append_native_materials(&root, "0.2.0", &mut BTreeMap::new(), &mut || Ok(()))
                    .unwrap_err()
                    .to_string()
                    .contains("omits a required input")
            );
            std::fs::write(&config_path, serde_json::to_vec(&native).unwrap()).unwrap();

            std::fs::write(temporary.join("tooling/Cargo.lock"), b"changed lock").unwrap();
            assert!(
                append_native_materials(&root, "0.2.0", &mut BTreeMap::new(), &mut || Ok(()))
                    .unwrap_err()
                    .to_string()
                    .contains("source pin")
            );
            std::fs::copy(
                source.join("tooling/Cargo.lock"),
                temporary.join("tooling/Cargo.lock"),
            )
            .unwrap();
            let mut bad = native.clone();
            bad["legacy_release"]["sha256"] = Value::String("f".repeat(64));
            std::fs::write(&config_path, serde_json::to_vec(&bad).unwrap()).unwrap();
            assert!(
                append_native_materials(&root, "0.2.0", &mut BTreeMap::new(), &mut || Ok(()))
                    .is_err()
            );
        }
        std::fs::remove_dir_all(temporary).unwrap();
    }

    #[test]
    fn source_path_rules_reject_windows_aliases_and_nonportable_bytes() {
        for path in [
            "",
            "/absolute/path",
            "a/../b",
            "a\\b",
            "release/CON.json",
            "release/com1.txt",
            "release/name.",
            "release/ü.json",
            "release/line\nbreak",
        ] {
            assert!(validate_source_path(path).is_err(), "{path:?}");
        }
        assert!(validate_source_path("release/portable-csdk/spec.json").is_ok());
    }

    #[test]
    fn digest_identity_conflicts_are_rejected() {
        let mut materials = BTreeMap::new();
        add_material(
            &mut materials,
            "https://example.invalid/input".to_owned(),
            "sha256",
            &"a".repeat(64),
        )
        .unwrap();
        assert!(
            add_material(
                &mut materials,
                "https://example.invalid/input".to_owned(),
                "sha256",
                &"b".repeat(64),
            )
            .is_err()
        );
    }

    #[test]
    #[ignore = "requires AMI_RUST_PUBLISHER_INPUTS_REFERENCE with the exact accepted manifest"]
    fn publisher_material_manifest_matches_opt_in_retained_reference() {
        let reference = std::env::var_os("AMI_RUST_PUBLISHER_INPUTS_REFERENCE")
            .expect("retained reference is required");
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        let actual = publisher_input_manifest(&source, || Ok(())).unwrap();
        let expected = std::fs::read(Path::new(&reference)).unwrap();
        assert_eq!(
            actual, expected,
            "source-derived publisher material bytes differ"
        );
    }

    #[test]
    #[ignore = "requires AMI_RUST_NATIVE_INPUTS_REFERENCE from the transitional producer"]
    fn native_material_manifest_matches_opt_in_transitional_producer() {
        let reference = std::env::var_os("AMI_RUST_NATIVE_INPUTS_REFERENCE")
            .expect("native reference is required");
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .unwrap();
        let actual = publisher_input_manifest_for_sdk(&source, "0.2.0", || Ok(())).unwrap();
        assert_eq!(
            sha256_bytes(&actual),
            sha256_bytes(&std::fs::read(reference).unwrap())
        );
        assert_eq!(
            publisher_input_manifest_for_sdk(&source, "0.1.0", || Ok(())).unwrap(),
            publisher_input_manifest(&source, || Ok(())).unwrap()
        );
    }
}
