//! One offline Rust producer for the RP1 toolchain contract.
//!
//! Acquisition is deliberately outside this command. Every selected remote
//! input must already exist below the acquired-input directory under its
//! contract role. The command verifies all bytes before creating work or
//! output, builds the AROS target libraries and repository linker, composes the
//! portable SDK, emits rust-installer components and publishes one inventory.

use crate::{bare_target_producer, native_prefix_compose};
use ami_rust_core::{
    Refusal, Result,
    component_archive::{
        ArchiveFormat, ArchiveLimits, ComponentArchiveSpec, extract_component_archive,
    },
    digest::{sha256_bytes, sha256_file},
    directory::Directory,
    files::read_regular_bounded,
    json::{JsonProfile, parse_json_value},
    production_contract::{ProductionInput, ProductionPlan, production_plan},
    toolchain_package::{
        NativePackageRequest, RustupPackageRequest, package_native_formats,
        package_rustup_components,
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const REQUEST_SCHEMA: &str = "ami-rust-toolchain-producer-request-v1";
const RESULT_SCHEMA: &str = "ami-rust-toolchain-producer-result-v1";
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const CAMPAIGN_SECONDS: u64 = 5_400;
const WORKSPACE_BYTES: u64 = 20 * 1024 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerRequest {
    schema: String,
    repository_root: PathBuf,
    contract: PathBuf,
    acquired_inputs: PathBuf,
    work: PathBuf,
    output: PathBuf,
    version: String,
}

struct Extracted {
    outer: PathBuf,
}

pub(super) fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    if arguments.next().as_deref() != Some(OsStr::new("--request")) {
        return Err(usage());
    }
    let request_path = PathBuf::from(arguments.next().ok_or_else(usage)?);
    if arguments.next().is_some() {
        return Err(usage());
    }
    let raw = read_regular_bounded(&request_path, MAX_REQUEST_BYTES)?;
    let value = parse_json_value(&raw, JsonProfile::ProductionContract)?;
    let request: ProducerRequest = serde_json::from_value(value)
        .map_err(|error| Refusal::new(format!("invalid toolchain producer request: {error}")))?;
    if request.schema != REQUEST_SCHEMA {
        return Err(Refusal::new(
            "toolchain producer request schema is unsupported",
        ));
    }
    produce(request)
}

fn produce(request: ProducerRequest) -> Result<()> {
    let started = Instant::now();
    let repository = existing_absolute_directory(&request.repository_root, "repository root")?;
    let acquired = existing_absolute_directory(&request.acquired_inputs, "acquired input root")?;
    let work = fresh_absolute_path(&request.work, "producer work")?;
    let output = fresh_absolute_path(&request.output, "producer output")?;
    require_disjoint(&repository, &work)?;
    require_disjoint(&repository, &output)?;
    require_disjoint(&acquired, &work)?;
    require_disjoint(&acquired, &output)?;
    require_disjoint(&work, &output)?;
    let host_key = current_host()?;
    let plan = production_plan(&repository, &request.contract, host_key, &request.version)?;

    // This is the transaction boundary: authenticate every selected remote
    // byte before either caller-owned destination can be created.
    let acquired_inputs = authenticate_acquired_inputs(&plan, &acquired)?;
    check_deadline(started)?;

    fs::create_dir(&work)?;
    fs::set_permissions(&work, fs::Permissions::from_mode(0o700))?;
    for name in ["extracted", "source-rust", "cargo-component", "linker"] {
        create_private_dir(&work.join(name))?;
    }

    let extracted_root = work.join("extracted");
    let rustc = extract_input(
        remote(&plan, &acquired_inputs, &format!("rustc-{host_key}"))?,
        &extracted_root,
        "rustc",
    )?;
    let host_std = extract_input(
        remote(
            &plan,
            &acquired_inputs,
            &format!("host-rust-std-{host_key}"),
        )?,
        &extracted_root,
        "host-rust-std",
    )?;
    let rust_src = extract_input(
        remote(&plan, &acquired_inputs, "rust-src")?,
        &extracted_root,
        "rust-src",
    )?;
    let upstream_cargo = extract_input(
        remote(
            &plan,
            &acquired_inputs,
            &format!("upstream-cargo-{host_key}"),
        )?,
        &extracted_root,
        "upstream-cargo",
    )?;
    let source_rust = work.join("source-rust");
    merge_component_payload(&rustc.outer.join("rustc"), &source_rust)?;
    merge_component_payload(
        &host_std
            .outer
            .join(format!("rust-std-{}", plan.host.rust_triple)),
        &source_rust,
    )?;
    merge_component_payload(&rust_src.outer.join("rust-src"), &source_rust)?;
    merge_component_payload(&upstream_cargo.outer.join("cargo"), &source_rust)?;
    materialize_rust_installer_state(&source_rust, &upstream_cargo.outer, &plan.host.rust_triple)?;

    let cargo_payload = component_payload(&upstream_cargo.outer, "cargo")?;
    let cargo_binary = cargo_payload.join("bin/cargo");
    let cargo_profile = materialize_cargo_component(
        &cargo_binary,
        &work.join("cargo-component"),
        &repository,
        &plan,
    )?;

    let mut bare_targets = Vec::new();
    for target in ["x86_64-unknown-aros-abi1", "x86_64-unknown-aros-abi11"] {
        let bare_output = work.join(format!("bare-output-{target}"));
        bare_target_producer::produce(bare_target_producer::BareTargetRequest {
            host: host_key.to_owned(),
            rust_profile: repository.join(bare_target_producer::profile_relative_path(host_key)?),
            host_rust: source_rust.clone(),
            native_cargo: work.join("cargo-component/bin/cargo"),
            target_pin: repository.join(format!(
                "tooling/crates/aros-native-build/pins/{target}.json"
            )),
            target_spec: repository.join(format!("targets/{target}.json")),
            work: work.join(format!("bare-work-{target}")),
            output: bare_output.clone(),
        })?;
        check_deadline(started)?;
        let profile = source_built_target_profile(&bare_output, target, host_key)?;
        bare_targets.push((target, bare_output, profile));
    }

    // The bare-target producer retains its established 512-MiB parent-process
    // reservation. Extract larger inputs only after that bounded phase so an
    // embedded typed call does not inherit unrelated decompression high-water.
    let llvm = extract_input(
        remote(
            &plan,
            &acquired_inputs,
            &format!("native-link-tools-{host_key}"),
        )?,
        &extracted_root,
        "native-link-tools",
    )?;
    let collector = extract_input(
        remote(&plan, &acquired_inputs, &format!("collector-{host_key}"))?,
        &extracted_root,
        "collector",
    )?;
    let csdk = extract_input(
        local(&plan, "portable-csdk-archive", &repository)?,
        &extracted_root,
        "portable-csdk",
    )?;
    let abi11_csdk = extract_input(
        local(&plan, "abi11-portable-csdk-archive", &repository)?,
        &extracted_root,
        "abi11-portable-csdk",
    )?;
    let abi11_profile_raw = read_regular_bounded(
        &repository.join("release/abi11-csdk/profile.json"),
        JsonProfile::PackageMetadataStateSelection.max_bytes(),
    )?;
    let abi11_profile = std::str::from_utf8(&abi11_profile_raw)
        .map_err(|_| Refusal::new("ABI11 C SDK profile is not UTF-8"))?
        .to_owned();
    let producer_vendor = extract_input(
        local(&plan, "producer-vendor-archive", &repository)?,
        &extracted_root,
        "producer-vendor",
    )?;

    let linker = build_linker(&repository, &work, &plan, &producer_vendor.outer, started)?;
    let output_parent = fs::canonicalize(
        output
            .parent()
            .ok_or_else(|| Refusal::new("producer output has no parent"))?,
    )?;
    let output_leaf = output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Refusal::new("producer output leaf must be UTF-8"))?;
    let stage = output_parent.join(format!(".{output_leaf}.stage-{}", std::process::id()));
    if stage.exists() {
        return Err(Refusal::new("producer transaction stage is occupied"));
    }
    create_private_dir(&stage)?;
    let transaction = (|| -> Result<Value> {
        let sdk_parent = stage.join("stage").join(host_key);
        fs::create_dir_all(&sdk_parent)?;
        let sdk = sdk_parent.join("sdk");
        let llvm_root = component_payload(&llvm.outer, "toolchain")?;
        let csdk_root = component_payload(&csdk.outer, "Developer")?;
        let abi11_csdk_root = component_payload(&abi11_csdk.outer, "Developer")?;
        let collector_root = component_payload(
            &collector.outer,
            &format!("aros-tools-v0.3.19-{}", plan.host.rust_triple),
        )?;
        let target_profiles = bare_targets
            .iter()
            .map(
                |(name, output, profile)| native_prefix_compose::TargetProfileInput {
                    name,
                    libraries_root: output.join("libraries"),
                    profile,
                },
            )
            .collect::<Vec<_>>();
        let composition = native_prefix_compose::compose_candidate_with_target_profiles(
            host_key,
            &plan.host.rust_triple,
            &repository,
            &sdk,
            [
                source_rust.clone(),
                work.join("cargo-component"),
                llvm_root,
                csdk_root,
                collector_root,
            ],
            native_prefix_compose::LinkerIdentity {
                root: linker.root,
                bytes: linker.bytes,
                sha256: linker.sha256,
                build_request_sha256: linker.request_sha256,
                build_record_sha256: linker.record_sha256,
            },
            Some(&cargo_profile),
            &target_profiles,
            Some(native_prefix_compose::AdditionalCsdkInput {
                root: abi11_csdk_root,
                profile: &abi11_profile,
            }),
        )?;
        if !composition.receipt.symlinks.is_empty() {
            return Err(Refusal::new(
                "portable SDK composition unexpectedly retained symlinks",
            ));
        }
        let artifacts_parent = stage.join("artifacts");
        create_private_dir(&artifacts_parent)?;
        let rustup_temp = stage.join(".rustup-components");
        let rustup = package_rustup_components(
            RustupPackageRequest {
                prefix: &sdk,
                output: &rustup_temp,
                host_key,
                rust_host_triple: &plan.host.rust_triple,
                version: &request.version,
                epoch: plan.release_epoch,
                files: &composition.receipt.files,
            },
            || check_deadline(started),
        )?;
        for artifact in &rustup.artifacts {
            fs::rename(
                rustup_temp.join(&artifact.path),
                artifacts_parent.join(&artifact.path),
            )?;
        }
        fs::remove_dir(rustup_temp)?;

        let native_temp = stage.join(".native-packages");
        let native = package_native_formats(
            NativePackageRequest {
                prefix: &sdk,
                output: &native_temp,
                host_key,
                version: &request.version,
                epoch: plan.release_epoch,
                files: &composition.receipt.files,
            },
            || check_deadline(started),
        )?;
        for artifact in &native.artifacts {
            fs::rename(
                native_temp.join(&artifact.path),
                artifacts_parent.join(&artifact.path),
            )?;
        }
        fs::remove_dir(native_temp)?;
        let release_artifacts = native.artifacts;

        let declared = plan
            .outputs
            .iter()
            .map(|row| {
                let artifact = rustup
                    .artifacts
                    .iter()
                    .chain(release_artifacts.iter())
                    .find(|artifact| artifact.role == row.role);
                json!({
                    "role": row.role,
                    "kind": row.kind,
                    "path": row.path,
                    "consumers": row.consumers,
                    "materialized": artifact.is_some()
                        || row.role == "host-sdk-tree"
                        || row.role == "aros-abi1-target-sysroot"
                        || row.role == "aros-abi11-target-sysroot"
                        || row.role == "abi1-csdk-sysroot"
                        || row.role == "abi11-csdk-sysroot"
                        || row.role == "host-file-inventory",
                    "identity": artifact,
                })
            })
            .collect::<Vec<_>>();
        let inventory_path = plan
            .outputs
            .iter()
            .find(|row| row.role == "host-file-inventory")
            .ok_or_else(|| Refusal::new("production contract lacks host inventory output"))?;
        let inventory = json!({
            "schema": RESULT_SCHEMA,
            "status": "RP2_OFFLINE_UNSIGNED_TOOLCHAIN_PRODUCED",
            "version": request.version,
            "host": plan.host,
            "targets": &plan.target_triples,
            "production_contract_sha256": plan.manifest_sha256,
            "release_epoch": plan.release_epoch,
            "sdk": {
                "files": composition.receipt.files,
                "file_count": composition.receipt.measurement.files,
                "file_bytes": composition.receipt.measurement.file_bytes,
                "directories": composition.receipt.measurement.directories,
                "portable_view_policy_sha256": composition.receipt.portable_view_policy_sha256,
            },
            "rustup": rustup,
            "artifacts": release_artifacts,
            "declared_outputs": declared,
            "publication_authorized": false,
            "claim": "Offline unsigned producer output. Signing, publication, aggregate channel metadata and channel handoff remain RP3."
        });
        let path = stage.join(&inventory_path.path);
        fs::create_dir_all(path.parent().expect("inventory parent"))?;
        write_json_new(&path, &inventory)?;
        let summary = json!({
            "schema": "ami-rust-toolchain-producer-summary-v1",
            "status": "RP2_OFFLINE_UNSIGNED_TOOLCHAIN_PRODUCED",
            "version": request.version,
            "host": plan.host.key,
            "targets": &plan.target_triples,
            "inventory": {
                "path": inventory_path.path,
                "bytes": fs::symlink_metadata(&path)?.len(),
                "sha256": sha256_file(&path)?,
            },
            "artifacts": rustup.artifacts.iter().chain(release_artifacts.iter()).collect::<Vec<_>>(),
            "publication_authorized": false,
        });
        check_deadline(started)?;
        Ok(summary)
    })();
    match transaction {
        Ok(inventory) => {
            if directory_bytes(&work)? + directory_bytes(&stage)? > WORKSPACE_BYTES {
                let _ = fs::remove_dir_all(&stage);
                return Err(Refusal::new(
                    "toolchain producer exceeded its 20-GiB workspace bound",
                ));
            }
            fs::rename(&stage, &output)?;
            println!("{inventory}");
            Ok(())
        }
        Err(error) => {
            let _ = fs::remove_dir_all(&stage);
            Err(error)
        }
    }
}

fn source_built_target_profile(bare_output: &Path, target: &str, host_key: &str) -> Result<String> {
    if !matches!(
        target,
        "x86_64-unknown-aros-abi1" | "x86_64-unknown-aros-abi11"
    ) {
        return Err(Refusal::new("source-built target is not admitted"));
    }
    let expected = std::collections::BTreeSet::from([
        "alloc".to_owned(),
        "compiler_builtins".to_owned(),
        "core".to_owned(),
    ]);

    let report_raw = read_regular_bounded(
        &bare_output.join("producer.json"),
        JsonProfile::PackageMetadataStateSelection.max_bytes(),
    )?;
    let report = parse_json_value(&report_raw, JsonProfile::PackageMetadataStateSelection)?;
    if report.get("schema").and_then(Value::as_str)
        != Some("ami-rust-bare-target-library-producer-v1")
        || report.get("status").and_then(Value::as_str)
            != Some("PRODUCED_BARE_TARGET_LIBRARIES_NOT_L1_OR_RC_QUALIFICATION")
        || report.get("host").and_then(Value::as_str) != Some(host_key)
        || report.get("target").and_then(Value::as_str) != Some(target)
        || report.get("rustc_commit").and_then(Value::as_str)
            != Some("330d317121e16b5db8e5adc63595910528ff2ee7")
    {
        return Err(Refusal::new(
            "source-built target-library receipt has the wrong host, target, or compiler identity",
        ));
    }
    let libraries = report
        .get("libraries")
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::new("source-built target-library receipt lacks libraries"))?;
    if libraries.len() != expected.len() * 2 {
        return Err(Refusal::new(
            "source-built target-library receipt must contain exactly three rlib/rmeta pairs",
        ));
    }
    let library_root = bare_output.join("libraries");
    let mut seen = std::collections::BTreeSet::new();
    let mut files = Vec::new();
    for row in libraries {
        let crate_name = row
            .get("crate")
            .and_then(Value::as_str)
            .ok_or_else(|| Refusal::new("source-built target-library crate is missing"))?;
        let path = row
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| Refusal::new("source-built target-library path is missing"))?;
        let (filename_crate, kind) = target_library_artifact(path)?;
        if filename_crate != crate_name
            || !expected.contains(crate_name)
            || row.get("kind").and_then(Value::as_str) != Some(kind)
            || !seen.insert((crate_name.to_owned(), kind.to_owned()))
        {
            return Err(Refusal::new(
                "source-built target-library identities are missing, duplicated, or malformed",
            ));
        }
        let bytes = row
            .get("bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| Refusal::new("source-built target-library byte count is missing"))?;
        let sha256 = row
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| Refusal::new("source-built target-library digest is missing"))?;
        let library = library_root.join(path);
        verify_identity(&library, bytes, sha256, crate_name)?;
        files.push(json!({
            "path": path,
            "bytes": bytes,
            "sha256": sha256,
        }));
    }
    let expected_artifacts = expected
        .iter()
        .flat_map(|crate_name| {
            ["rlib", "rmeta"].map(|kind| (crate_name.to_owned(), kind.to_owned()))
        })
        .collect();
    if seen != expected_artifacts {
        return Err(Refusal::new(
            "source-built target-library receipt does not cover the required crates",
        ));
    }
    files.sort_by(|left, right| {
        left.get("path")
            .and_then(Value::as_str)
            .cmp(&right.get("path").and_then(Value::as_str))
    });
    serde_json::to_string(&json!({
        "schema": "aros-target-library-candidate-v1",
        "target": target,
        "rustc_commit": "330d317121e16b5db8e5adc63595910528ff2ee7",
        "origin": "Exact source-built output selected by the authenticated bare-target producer receipt",
        "files": files,
        "symlinks": [],
    }))
    .map_err(|error| Refusal::new(format!("could not serialize target-library profile: {error}")))
}

fn target_library_artifact(path: &str) -> Result<(String, &'static str)> {
    if path.contains('/') || path.contains('\\') {
        return Err(Refusal::new("target-library path is not one regular leaf"));
    }
    let (path, kind) = if let Some(path) = path.strip_suffix(".rlib") {
        (path, "rlib")
    } else if let Some(path) = path.strip_suffix(".rmeta") {
        (path, "rmeta")
    } else {
        return Err(Refusal::new(
            "target-library path is neither an rlib nor an rmeta leaf",
        ));
    };
    let stem = path
        .strip_prefix("lib")
        .ok_or_else(|| Refusal::new("target-library filename is malformed"))?;
    let (crate_name, disambiguator) = stem
        .rsplit_once('-')
        .ok_or_else(|| Refusal::new("target-library filename lacks a disambiguator"))?;
    if !matches!(crate_name, "core" | "alloc" | "compiler_builtins")
        || disambiguator.len() != 16
        || !disambiguator
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Refusal::new(
            "target-library filename has an unapproved crate or disambiguator",
        ));
    }
    Ok((crate_name.to_owned(), kind))
}

fn authenticate_acquired_inputs(
    plan: &ProductionPlan,
    root: &Path,
) -> Result<BTreeMap<String, PathBuf>> {
    let mut result = BTreeMap::new();
    for input in plan.inputs.iter().filter(|input| input.url.is_some()) {
        let path = root.join(&input.role);
        verify_identity(&path, input.bytes, &input.sha256, &input.role)?;
        result.insert(input.role.clone(), path);
    }
    Ok(result)
}

fn remote<'a>(
    plan: &'a ProductionPlan,
    acquired: &'a BTreeMap<String, PathBuf>,
    role: &str,
) -> Result<(&'a ProductionInput, PathBuf)> {
    let input = plan
        .inputs
        .iter()
        .find(|input| input.role == role && input.url.is_some())
        .ok_or_else(|| Refusal::new(format!("production contract lacks remote input {role}")))?;
    let path = acquired
        .get(role)
        .cloned()
        .ok_or_else(|| Refusal::new(format!("acquired input is absent: {role}")))?;
    Ok((input, path))
}

fn local<'a>(
    plan: &'a ProductionPlan,
    role: &str,
    repository: &Path,
) -> Result<(&'a ProductionInput, PathBuf)> {
    let input = plan
        .inputs
        .iter()
        .find(|input| input.role == role)
        .ok_or_else(|| Refusal::new(format!("production contract lacks local input {role}")))?;
    let relative = input
        .repository_path
        .as_ref()
        .ok_or_else(|| Refusal::new(format!("production input is not repository-owned: {role}")))?;
    Ok((input, repository.join(relative)))
}

fn extract_input(
    input: (&ProductionInput, PathBuf),
    destination: &Path,
    leaf: &str,
) -> Result<Extracted> {
    let (input, path) = input;
    let format = match input.archive_format.as_deref() {
        Some("tar.xz") => ArchiveFormat::TarXz,
        Some("tar.gz") => ArchiveFormat::TarGzip,
        _ => {
            return Err(Refusal::new(format!(
                "input {} is not an admitted archive",
                input.role
            )));
        }
    };
    let parent = Directory::open(destination)?;
    let receipt = extract_component_archive(
        File::open(path)?,
        &parent,
        ComponentArchiveSpec {
            destination_name: OsStr::new(leaf),
            compressed_bytes: input.bytes,
            compressed_sha256: &input.sha256,
            format,
            limits: ArchiveLimits {
                max_compressed_bytes: 512 * 1024 * 1024,
                max_decoded_tar_bytes: 12 * 1024 * 1024 * 1024,
                max_expanded_bytes: 12 * 1024 * 1024 * 1024,
                max_file_bytes: 4 * 1024 * 1024 * 1024,
                max_members: 250_000,
                max_index_bytes: 256 * 1024 * 1024,
                max_path_bytes: 4_096,
                max_path_components: 128,
                max_extension_bytes: 1024 * 1024,
                current_workspace_bytes: 0,
                max_workspace_bytes: WORKSPACE_BYTES,
                xz_memory_limit_kib: 512 * 1024,
            },
        },
        || Ok(()),
    )
    .map_err(|failure| Refusal::new(format!("{} extraction failed: {failure}", input.role)))?;
    Ok(Extracted {
        outer: destination.join(leaf).join(receipt.component_root),
    })
}

fn component_payload(outer: &Path, declared_root: &str) -> Result<PathBuf> {
    if outer.file_name().and_then(|name| name.to_str()) == Some(declared_root) {
        return Ok(outer.to_path_buf());
    }
    let nested = outer.join(declared_root);
    if nested.is_dir() && !nested.is_symlink() {
        Ok(nested)
    } else {
        Err(Refusal::new(format!(
            "archive lacks declared payload root {declared_root}"
        )))
    }
}

fn merge_component_payload(source: &Path, destination: &Path) -> Result<()> {
    if !source.is_dir() || source.is_symlink() {
        return Err(Refusal::new(
            "Rust component payload is not a real directory",
        ));
    }
    merge_directory(source, destination, true)
}

fn merge_directory(source: &Path, destination: &Path, component_root: bool) -> Result<()> {
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if component_root && entry.file_name() == OsStr::new("manifest.in") {
            continue;
        }
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_dir() {
            if !destination_path.exists() {
                fs::create_dir(&destination_path)?;
                fs::set_permissions(
                    &destination_path,
                    fs::Permissions::from_mode(metadata.permissions().mode() & 0o777),
                )?;
            } else if !destination_path.is_dir() || destination_path.is_symlink() {
                return Err(Refusal::new(
                    "Rust components contain a path-kind collision",
                ));
            }
            merge_directory(&source_path, &destination_path, false)?;
        } else if metadata.file_type().is_file() {
            if destination_path.exists() {
                if fs::symlink_metadata(&destination_path)?
                    .file_type()
                    .is_file()
                    && sha256_file(&source_path)? == sha256_file(&destination_path)?
                {
                    continue;
                }
                return Err(Refusal::new(
                    "Rust components contain conflicting file bytes",
                ));
            }
            fs::copy(&source_path, &destination_path)?;
            fs::set_permissions(
                &destination_path,
                fs::Permissions::from_mode(metadata.permissions().mode() & 0o777),
            )?;
        } else if metadata.file_type().is_symlink() {
            let target = fs::read_link(&source_path)?;
            if destination_path.exists() || fs::symlink_metadata(&destination_path).is_ok() {
                if fs::symlink_metadata(&destination_path)?
                    .file_type()
                    .is_symlink()
                    && fs::read_link(&destination_path)? == target
                {
                    continue;
                }
                return Err(Refusal::new("Rust components contain conflicting symlinks"));
            }
            symlink(target, destination_path)?;
        } else {
            return Err(Refusal::new("Rust component contains a special file"));
        }
    }
    Ok(())
}

fn materialize_rust_installer_state(
    rust: &Path,
    upstream_cargo: &Path,
    rust_host_triple: &str,
) -> Result<()> {
    let rustlib = rust.join("lib/rustlib");
    let components = format!("rustc\nrust-std-{rust_host_triple}\nrust-src\ncargo\n");
    write_new(&rustlib.join("components"), components.as_bytes(), 0o644)?;
    let version = read_regular_bounded(&upstream_cargo.join("rust-installer-version"), 16)?;
    if version != b"3\n" {
        return Err(Refusal::new(
            "upstream Cargo has an unsupported rust-installer version",
        ));
    }
    write_new(&rustlib.join("rust-installer-version"), &version, 0o644)?;
    let uninstall = read_regular_bounded(&upstream_cargo.join("install.sh"), 128 * 1024)?;
    write_new(&rustlib.join("uninstall.sh"), &uninstall, 0o755)
}

fn materialize_cargo_component(
    binary: &Path,
    destination: &Path,
    repository: &Path,
    plan: &ProductionPlan,
) -> Result<String> {
    let metadata = fs::symlink_metadata(binary)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 {
        return Err(Refusal::new(
            "official Cargo component lacks a regular executable",
        ));
    }
    fs::create_dir(destination.join("bin"))?;
    fs::copy(binary, destination.join("bin/cargo"))?;
    fs::set_permissions(
        destination.join("bin/cargo"),
        fs::Permissions::from_mode(0o755),
    )?;
    let mut files = vec![json!({
        "path": "bin/cargo",
        "bytes": metadata.len(),
        "sha256": sha256_file(binary)?,
        "mode": 493,
    })];
    let notice_root = destination.join("share/doc/ami-rust");
    fs::create_dir_all(&notice_root)?;
    for (role, name) in [
        ("project-license-apache", "LICENSE-APACHE"),
        ("project-license-mit", "LICENSE-MIT"),
        ("project-license-summary", "LICENSE.md"),
        ("project-third-party-notices", "THIRD_PARTY_NOTICES.md"),
        ("aros-apl-license", "APL-1.1.txt"),
        ("csdk-source-availability", "SOURCE-AVAILABILITY.md"),
        ("csdk-portability-changes", "CSDK-CHANGES.md"),
        ("abi11-csdk-notes", "ABI11-CSDK.md"),
        ("sdk-api", "SDK-API.md"),
        ("license-review", "licence-review.json"),
    ] {
        let (input, source) = local(plan, role, repository)?;
        let target = notice_root.join(name);
        fs::copy(&source, &target)?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644))?;
        files.push(json!({
            "path": format!("share/doc/ami-rust/{name}"),
            "bytes": input.bytes,
            "sha256": input.sha256,
            "mode": 420,
        }));
    }
    files.sort_by(|left, right| {
        left.get("path")
            .and_then(Value::as_str)
            .cmp(&right.get("path").and_then(Value::as_str))
    });
    let profile = json!({
        "schema": "ami-rust-official-cargo-component-v1",
        "origin": "official Cargo component from the pinned Rust distribution plus contract-pinned ami-rust and AROS notices",
        "files": files,
        "symlinks": [],
    });
    serde_json::to_string(&profile)
        .map_err(|error| Refusal::new(format!("could not encode Cargo profile: {error}")))
}

struct LinkerBuild {
    root: PathBuf,
    bytes: u64,
    sha256: String,
    request_sha256: String,
    record_sha256: String,
}

fn build_linker(
    repository: &Path,
    work: &Path,
    plan: &ProductionPlan,
    vendor_outer: &Path,
    started: Instant,
) -> Result<LinkerBuild> {
    let vendor = component_payload(vendor_outer, "vendor")?;
    let cargo_home = work.join("linker-cargo-home");
    let home = work.join("linker-home");
    let temporary = work.join("linker-tmp");
    let target = work.join("linker-target");
    create_private_dir(&cargo_home)?;
    create_private_dir(&home)?;
    create_private_dir(&temporary)?;
    create_private_dir(&target)?;
    let vendor_text = serde_json::to_string(
        vendor
            .to_str()
            .ok_or_else(|| Refusal::new("producer vendor path must be UTF-8"))?,
    )
    .map_err(|error| Refusal::new(error.to_string()))?;
    write_new(
        &cargo_home.join("config.toml"),
        format!(
            "[source.crates-io]\nreplace-with=\"ami-rust-vendor\"\n[source.ami-rust-vendor]\ndirectory={vendor_text}\n"
        )
        .as_bytes(),
        0o600,
    )?;
    let request = json!({
        "schema":"ami-rust-rp2-linker-build-request-v1",
        "host":plan.host.key,
        "target":plan.host.rust_triple,
        "manifest":"tooling/Cargo.toml",
        "package":"aros-native-build",
        "binary":"aros-link",
        "offline":true,
    });
    let request_path = work.join("linker/build-request.json");
    write_json_new(&request_path, &request)?;
    let request_sha256 = sha256_file(&request_path)?;
    let rust = work.join("source-rust");
    let cargo = rust.join("bin/cargo");
    let mut command = Command::new(&cargo);
    command
        .args([
            "build",
            "--release",
            "--locked",
            "--offline",
            "--manifest-path",
        ])
        .arg(repository.join("tooling/Cargo.toml"))
        .args([
            "--package",
            "aros-native-build",
            "--bin",
            "aros-link",
            "--target",
        ])
        .arg(&plan.host.rust_triple)
        .arg("--target-dir")
        .arg(&target)
        .current_dir(repository)
        .env_clear()
        .env(
            "PATH",
            format!(
                "{}:/usr/bin:/bin:/usr/sbin:/sbin",
                rust.join("bin").display()
            ),
        )
        .env("HOME", &home)
        .env("TMPDIR", &temporary)
        .env("CARGO_HOME", &cargo_home)
        .env("CARGO_BUILD_JOBS", "2")
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_NET_OFFLINE", "true")
        .env("RUSTC", rust.join("bin/rustc"))
        .env("RUSTDOC", rust.join("bin/rustdoc"))
        .env("SOURCE_DATE_EPOCH", plan.release_epoch.to_string())
        .env(
            "CARGO_ENCODED_RUSTFLAGS",
            [
                format!(
                    "--remap-path-prefix={}=/ami-rust-source",
                    repository.display()
                ),
                format!("--remap-path-prefix={}=/ami-rust-work", work.display()),
            ]
            .join("\u{1f}"),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let result = command.output().map_err(|error| {
        Refusal::new(format!(
            "could not start source-built aros-link child with {}: {error}",
            cargo.display()
        ))
    })?;
    write_new(&work.join("linker/stdout.log"), &result.stdout, 0o600)?;
    write_new(&work.join("linker/stderr.log"), &result.stderr, 0o600)?;
    let record = json!({
        "schema":"ami-rust-rp2-linker-build-result-v1",
        "request_sha256":request_sha256,
        "passed":result.status.success(),
        "child_exit_code":result.status.code(),
        "stdout_sha256":sha256_bytes(&result.stdout),
        "stderr_sha256":sha256_bytes(&result.stderr),
    });
    let record_path = work.join("linker/build-result.json");
    write_json_new(&record_path, &record)?;
    let record_sha256 = sha256_file(&record_path)?;
    if !result.status.success() {
        return Err(Refusal::new("source-built aros-link child build failed"));
    }
    check_deadline(started)?;
    let built = target
        .join(&plan.host.rust_triple)
        .join("release/aros-link");
    let bytes = fs::symlink_metadata(&built)?.len();
    let sha256 = sha256_file(&built)?;
    fs::copy(&built, work.join("linker/aros-link"))?;
    fs::set_permissions(
        work.join("linker/aros-link"),
        fs::Permissions::from_mode(0o755),
    )?;
    Ok(LinkerBuild {
        root: work.join("linker"),
        bytes,
        sha256,
        request_sha256,
        record_sha256,
    })
}

fn verify_identity(path: &Path, bytes: u64, sha256: &str, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() != bytes || sha256_file(path)? != sha256 {
        return Err(Refusal::new(format!(
            "{label} differs from the RP1 identity"
        )));
    }
    Ok(())
}

fn existing_absolute_directory(path: &Path, label: &str) -> Result<PathBuf> {
    if !path.is_absolute() || path.is_symlink() {
        return Err(Refusal::new(format!(
            "{label} must be an absolute real directory"
        )));
    }
    let canonical = fs::canonicalize(path)?;
    if !canonical.is_dir() {
        return Err(Refusal::new(format!("{label} is not a directory")));
    }
    Ok(canonical)
}

fn fresh_absolute_path(path: &Path, label: &str) -> Result<PathBuf> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path.exists()
        || path.symlink_metadata().is_ok()
    {
        return Err(Refusal::new(format!(
            "{label} must be an absent absolute path"
        )));
    }
    let parent = fs::canonicalize(path.parent().expect("fresh path parent"))?;
    Ok(parent.join(path.file_name().expect("fresh path leaf")))
}

fn require_disjoint(left: &Path, right: &Path) -> Result<()> {
    if left.starts_with(right) || right.starts_with(left) {
        return Err(Refusal::new("toolchain producer roots must be disjoint"));
    }
    Ok(())
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(path)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_json_new(path: &Path, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| Refusal::new(format!("could not encode producer JSON: {error}")))?;
    bytes.push(b'\n');
    write_new(path, &bytes, 0o600)
}

fn current_host() -> Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("macos-aarch64"),
        ("linux", "x86_64") => Ok("linux-x86_64"),
        ("linux", "aarch64") => Ok("linux-aarch64"),
        _ => Err(Refusal::new(
            "running host is outside the RP1 production matrix",
        )),
    }
}

fn check_deadline(started: Instant) -> Result<()> {
    if started.elapsed() > Duration::from_secs(CAMPAIGN_SECONDS) {
        Err(Refusal::new(
            "toolchain producer exceeded its 90-minute campaign budget",
        ))
    } else {
        Ok(())
    }
}

fn directory_bytes(root: &Path) -> Result<u64> {
    let mut pending = vec![root.to_path_buf()];
    let mut total = 0_u64;
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_dir() {
                pending.push(entry.path());
            } else if metadata.file_type().is_file() {
                total = total
                    .checked_add(metadata.len())
                    .ok_or_else(|| Refusal::new("workspace byte accounting overflow"))?;
            }
        }
    }
    Ok(total)
}

fn usage() -> Refusal {
    Refusal::new("usage: ami-rust-xtask toolchain-producer --request FILE")
}
