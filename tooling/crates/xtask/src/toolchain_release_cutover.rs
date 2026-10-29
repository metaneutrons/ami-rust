//! RP3's small Rust release coordinator.
//!
//! Workflows own runner setup, immutable downloads, permissions and mutation
//! ordering.  This command owns the shared byte identities and refuses to
//! publish anything itself.

use crate::target_rlib_compare::{self, HostTargetRlibs, TargetRlib};
use ami_rust_core::{
    Refusal, Result,
    digest::{is_sha256_digest, sha256_bytes, sha256_file},
    files::read_regular_bounded,
    json::{JsonProfile, parse_json_value},
    production_contract::{production_plan, verify_production_contract},
    toolchain_release::{
        Artifact, ReleaseHost, RustupComponents, RustupManifestHost, RustupManifestRequest,
        render_rustup_manifest,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Command,
};

const CHECK_SCHEMA: &str = "ami-rust-rp3-cutover-check-v1";
const REQUEST_SCHEMA: &str = "ami-rust-rp3-release-request-v1";
const INVENTORY_SCHEMA: &str = "ami-rust-rp3-publication-inventory-v1";
const HANDOFF_SCHEMA: &str = "ami-rust-m7-distribution-handoff-v1";
const FINAL_SCHEMA: &str = "ami-rust-rp3-final-readback-v1";
const PRODUCER_SCHEMA: &str = "ami-rust-toolchain-producer-result-v1";
const PRODUCER_STATUS: &str = "RP2_OFFLINE_UNSIGNED_TOOLCHAIN_PRODUCED";
const MAX_JSON: usize = 16 * 1024 * 1024;
const WORKFLOWS: [(&str, &str); 3] = [
    ("toolchain-pr-check.yml", "toolchain-release-cutover check"),
    ("toolchain-qualify.yml", "toolchain-producer"),
    (
        "toolchain-release.yml",
        "toolchain-release-cutover finalize",
    ),
];
const QUALIFICATION_OBSERVATION_BOUNDARY: (&str, &str) = (
    "toolchain-qualify.yml",
    "PASS_EXACT_DUAL_ABI_CARGO_BUILD_ON_THREE_HOSTS",
);
const HOSTS: [&str; 3] = ["macos-aarch64", "linux-x86_64", "linux-aarch64"];
const TARGETS: [&str; 2] = ["x86_64-unknown-aros-abi1", "x86_64-unknown-aros-abi11"];
const COMPONENTS: [(&str, &str); 3] = [
    ("rustup-rustc-component", "rustc"),
    ("rustup-cargo-component", "cargo"),
    ("rustup-rust-std-component", "rust-std"),
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseRequest {
    schema: String,
    source_root: PathBuf,
    contract: PathBuf,
    version: String,
    rust_version: String,
    cargo_version: String,
    source_commit: String,
    source_tree: String,
    qualification_run_id: u64,
    qualification_run_attempt: u64,
    host_outputs: BTreeMap<String, PathBuf>,
    source_capsule_output: PathBuf,
    catalog_root: Option<PathBuf>,
    catalog_commit: Option<String>,
    output: PathBuf,
}

#[derive(Deserialize)]
struct ProducerInventory {
    schema: String,
    status: String,
    version: String,
    host: ProducerHost,
    targets: Vec<String>,
    production_contract_sha256: String,
    release_epoch: u64,
    sdk: ProducerSdk,
    rustup: ProducerRustup,
    artifacts: Vec<ProducerArtifact>,
    publication_authorized: bool,
}

#[derive(Deserialize)]
struct ProducerSdk {
    files: Vec<ProducerSdkFile>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
struct ProducerSdkFile {
    path: String,
    bytes: u64,
    sha256: String,
    #[serde(default)]
    mode: Option<u32>,
}

#[derive(Deserialize)]
struct ProducerHost {
    key: String,
}

#[derive(Deserialize)]
struct ProducerRustup {
    artifacts: Vec<ProducerArtifact>,
}

#[derive(Clone, Deserialize)]
struct ProducerArtifact {
    role: String,
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Clone)]
struct FileIdentity {
    name: String,
    bytes: u64,
    sha256: String,
}

pub(super) fn run(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    match arguments.next().as_deref() {
        Some(value) if value == OsStr::new("check") => check(arguments),
        Some(value) if value == OsStr::new("assemble") => assemble(arguments),
        Some(value) if value == OsStr::new("prepare-qualification") => {
            prepare_qualification(arguments)
        }
        Some(value) if value == OsStr::new("bind-catalog") => bind_catalog(arguments),
        Some(value) if value == OsStr::new("finalize") => finalize(arguments),
        Some(value) if value == OsStr::new("recover-public") => recover_public(arguments),
        Some(value) if value == OsStr::new("verify-readback") => verify_readback(arguments),
        _ => Err(usage()),
    }
}

fn bind_catalog(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let mut options = options(
        &mut arguments,
        &["--assembly-root", "--catalog-root", "--catalog-commit"],
    )?;
    let root = existing_directory(take_path(&mut options, "--assembly-root")?, "assembly root")?;
    let catalog = existing_directory(take_path(&mut options, "--catalog-root")?, "catalog root")?;
    let catalog_commit = take_string(&mut options, "--catalog-commit")?;
    require_git_id(&catalog_commit, "catalog commit")?;
    if git_identity(&catalog, "HEAD")? != catalog_commit {
        return Err(Refusal::new(
            "catalog checkout differs from the selected commit",
        ));
    }
    let mut result = read_object(&root.join("assembly-result.json"))?;
    if result.get("schema").and_then(Value::as_str) != Some("ami-rust-rp3-assembly-result-v1")
        || !result.get("catalog_commit").is_some_and(Value::is_null)
        || result.get("status").and_then(Value::as_str) != Some("CATALOG_READY_FOR_REVIEW")
    {
        return Err(Refusal::new(
            "assembly is not an unbound reviewed-catalog candidate",
        ));
    }
    let version = result
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new("assembly result lacks a version"))?
        .to_owned();
    let distribution = root.join("distribution/rustup").join(&version).join("dist");
    let selected = catalog
        .join("distribution/rustup")
        .join(&version)
        .join("dist");
    let names = [
        format!("channel-rust-{version}.toml"),
        format!("channel-rust-{version}.toml.sha256"),
    ];
    let mut catalogs = Vec::new();
    for name in names {
        let expected = read_regular_bounded(&distribution.join(&name), 1024 * 1024)?;
        let actual = read_regular_bounded(&selected.join(&name), 1024 * 1024)?;
        if actual != expected {
            return Err(Refusal::new(
                "selected catalog bytes differ from the exact candidate",
            ));
        }
        catalogs.push(json!({
            "path":format!("distribution/rustup/{version}/dist/{name}"),
            "bytes":actual.len(),
            "sha256":sha256_bytes(&actual),
        }));
    }
    let candidate = existing_directory(root.join("candidate"), "candidate directory")?;
    let binding = json!({
        "schema":"ami-rust-rp3-catalog-binding-v1",
        "status":"EXACT_RUSTUP_CATALOG_COMMIT_BOUND",
        "version":version,
        "catalog_commit":catalog_commit,
        "files":catalogs,
    });
    let identity = write_json_candidate(&candidate, "catalog-binding.json", &binding)?;

    let mut plan = read_object(&root.join("signature-plan.json"))?;
    if plan.get("schema").and_then(Value::as_str) != Some("ami-rust-rp3-signature-plan-v1")
        || plan.get("status").and_then(Value::as_str) != Some("READY_FOR_PROTECTED_SIGNATURES")
    {
        return Err(Refusal::new("unsupported RP3 signature plan"));
    }
    let names = plan
        .get_mut("signature_subjects")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| Refusal::new("signature plan lacks subjects"))?;
    names.push(Value::String(identity.name.clone()));
    names.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
    let subject_count = {
        let subjects = plan
            .get_mut("subjects")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| Refusal::new("signature plan lacks subject identities"))?;
        subjects.push(identity_json(&identity));
        subjects.sort_by(|left, right| {
            left.get("name")
                .and_then(Value::as_str)
                .cmp(&right.get("name").and_then(Value::as_str))
        });
        subjects.len()
    };
    plan.insert("subject_count".to_owned(), json!(subject_count));
    replace_json(&root.join("signature-plan.json"), &Value::Object(plan))?;

    result.insert("status".to_owned(), json!("READY_FOR_PROTECTED_SIGNATURES"));
    result.insert("catalog_commit".to_owned(), json!(catalog_commit));
    result.insert("raw_subject_count".to_owned(), json!(subject_count));
    replace_json(&root.join("assembly-result.json"), &Value::Object(result))?;
    println!(
        "{}",
        json!({"status":"EXACT_RUSTUP_CATALOG_COMMIT_BOUND","catalog_commit":catalog_commit})
    );
    Ok(())
}

fn check(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let mut options = options(
        &mut arguments,
        &["--source-root", "--contract", "--version", "--output"],
    )?;
    let source = existing_directory(take_path(&mut options, "--source-root")?, "source root")?;
    let contract = take_path(&mut options, "--contract")?;
    let version = take_string(&mut options, "--version")?;
    let output = fresh_file_path(take_path(&mut options, "--output")?)?;
    let summary = verify_production_contract(&source, &contract)?;
    for host in HOSTS {
        let _ = production_plan(&source, &contract, host, &version)?;
    }
    let workflow_root = source.join(".github/workflows");
    for (name, command) in WORKFLOWS {
        let raw = read_regular_bounded(&workflow_root.join(name), 256 * 1024)?;
        let text =
            std::str::from_utf8(&raw).map_err(|_| Refusal::new("RP3 workflow must be UTF-8"))?;
        if !text.contains(command) {
            return Err(Refusal::new(format!(
                "RP3 workflow lacks its Rust entry point: {name}"
            )));
        }
    }
    let (qualification_name, qualification_boundary) = QUALIFICATION_OBSERVATION_BOUNDARY;
    let qualification_raw =
        read_regular_bounded(&workflow_root.join(qualification_name), 256 * 1024)?;
    let qualification = std::str::from_utf8(&qualification_raw)
        .map_err(|_| Refusal::new("qualification workflow must be UTF-8"))?;
    if !qualification.contains(qualification_boundary) {
        return Err(Refusal::new(
            "qualification workflow lacks the exact Cargo-build boundary",
        ));
    }
    let release = read_regular_bounded(&workflow_root.join("toolchain-release.yml"), 256 * 1024)?;
    let release = std::str::from_utf8(&release)
        .map_err(|_| Refusal::new("RP3 release workflow must be UTF-8"))?;
    if !release.contains("toolchain-release-cutover recover-public") {
        return Err(Refusal::new(
            "RP3 release workflow lacks its non-mutating public recovery entry point",
        ));
    }
    for retired in [
        "toolchain-capsule-producer.yml",
        "toolchain-crate-producer.yml",
        "toolchain-documented-producer.yml",
        "toolchain-homebrew.yml",
        "toolchain-publish.yml",
        "toolchain-sdk-producer.yml",
    ] {
        if workflow_root.join(retired).exists() {
            return Err(Refusal::new(format!(
                "retired toolchain workflow remains active: {retired}"
            )));
        }
    }
    write_json_new(
        &output,
        &json!({
            "schema": CHECK_SCHEMA,
            "status": "RP3_RUST_ENTRY_POINTS_READY",
            "version": version,
            "contract": summary,
            "entry_points": ["pull-request", "three-host-qualification", "protected-release"],
            "publication_authorized": false,
            "claim": "Cheap structural and contract check only; no SDK was built, signed or published."
        }),
    )?;
    println!(
        "{}",
        json!({"status":"RP3_RUST_ENTRY_POINTS_READY","output":output})
    );
    Ok(())
}

fn assemble(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    if arguments.next().as_deref() != Some(OsStr::new("--request")) {
        return Err(usage());
    }
    let request_path = PathBuf::from(arguments.next().ok_or_else(usage)?);
    if arguments.next().is_some() {
        return Err(usage());
    }
    let raw = read_regular_bounded(&request_path, 128 * 1024)?;
    let request: ReleaseRequest =
        serde_json::from_value(parse_json_value(&raw, JsonProfile::ProductionContract)?)
            .map_err(|error| Refusal::new(format!("invalid RP3 release request: {error}")))?;
    if request.schema != REQUEST_SCHEMA
        || request.qualification_run_id == 0
        || request.qualification_run_attempt == 0
        || request
            .host_outputs
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != HOSTS.into_iter().collect()
        || request.catalog_root.is_some() != request.catalog_commit.is_some()
    {
        return Err(Refusal::new("RP3 release request has an unsupported shape"));
    }
    require_git_id(&request.source_commit, "source commit")?;
    require_git_id(&request.source_tree, "source tree")?;
    if let Some(commit) = &request.catalog_commit {
        require_git_id(commit, "catalog commit")?;
    }
    let source = existing_directory(request.source_root, "source root")?;
    let source_head = git_identity(&source, "HEAD")?;
    let source_tree = git_identity(&source, "HEAD^{tree}")?;
    let source_epoch = git_commit_epoch(&source, "HEAD")?;
    if source_head != request.source_commit || source_tree != request.source_tree {
        return Err(Refusal::new(
            "release request source identity differs from its checkout",
        ));
    }
    let plans = HOSTS
        .into_iter()
        .map(|host| production_plan(&source, &request.contract, host, &request.version))
        .collect::<Result<Vec<_>>>()?;
    let contract_sha = plans[0].manifest_sha256.clone();
    let epoch = plans[0].release_epoch;
    if plans
        .iter()
        .any(|plan| plan.manifest_sha256 != contract_sha || plan.release_epoch != epoch)
    {
        return Err(Refusal::new(
            "host production plans do not share one contract identity",
        ));
    }
    let source_capsule = verified_source_capsule(
        &request.source_capsule_output,
        &request.version,
        &request.source_commit,
        &request.source_tree,
        source_epoch,
    )?;

    let output = fresh_directory_path(request.output)?;
    let stage = sibling_stage(&output)?;
    fs::create_dir(&stage)?;
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))?;
    let candidate = stage.join("candidate");
    let distribution = stage
        .join("distribution/rustup")
        .join(&request.version)
        .join("dist");
    fs::create_dir(&candidate)?;
    fs::create_dir_all(&distribution)?;

    let result = (|| -> Result<()> {
        let mut rustup_hosts = Vec::new();
        let mut producer_rows = Vec::new();
        let mut raw_assets = Vec::new();
        raw_assets.push(copy_verified(
            &source_capsule.path,
            &candidate.join(&source_capsule.identity.name),
            source_capsule.identity.bytes,
            &source_capsule.identity.sha256,
        )?);
        let mut channel_assets = BTreeMap::<String, FileIdentity>::new();
        let mut invariant_target_payload: Option<Vec<ProducerSdkFile>> = None;
        let mut host_target_rlibs = Vec::new();
        let mut target_metadata_rows = Vec::new();
        for host in HOSTS {
            let root = existing_directory(request.host_outputs[host].clone(), "producer output")?;
            let inventory_name = format!("ami-rust-{}-{host}.inventory.json", request.version);
            let inventory_path = root.join("artifacts").join(&inventory_name);
            let inventory_raw = read_regular_bounded(&inventory_path, MAX_JSON)?;
            let inventory: ProducerInventory = serde_json::from_value(parse_json_value(
                &inventory_raw,
                JsonProfile::SdkComponentManifest,
            )?)
            .map_err(|error| Refusal::new(format!("invalid producer inventory: {error}")))?;
            if inventory.schema != PRODUCER_SCHEMA
                || inventory.status != PRODUCER_STATUS
                || inventory.version != request.version
                || inventory.host.key != host
                || inventory.targets != TARGETS
                || inventory.production_contract_sha256 != contract_sha
                || inventory.release_epoch != epoch
                || inventory.publication_authorized
            {
                return Err(Refusal::new(format!(
                    "producer inventory differs from RP3 selection: {host}"
                )));
            }
            let mut host_target_payload = inventory
                .sdk
                .files
                .iter()
                .filter(|row| {
                    TARGETS
                        .iter()
                        .any(|target| row.path.starts_with(&format!("lib/rustlib/{target}/")))
                })
                .cloned()
                .collect::<Vec<_>>();
            host_target_payload.sort();
            if host_target_payload.is_empty()
                || host_target_payload
                    .iter()
                    .any(|row| row.bytes == 0 || !is_sha256_digest(&row.sha256))
            {
                return Err(Refusal::new(format!(
                    "producer inventory lacks a valid AROS target payload: {host}"
                )));
            }
            let mut host_rlibs = Vec::new();
            let mut host_metadata = Vec::new();
            let mut host_invariant_payload = Vec::new();
            for row in host_target_payload {
                if row.path.ends_with(".rlib") {
                    if row.mode.is_some_and(|mode| mode != 0o644) {
                        return Err(Refusal::new(format!(
                            "producer target library has an unexpected mode: {host}"
                        )));
                    }
                    host_rlibs.push(TargetRlib {
                        path: row.path,
                        bytes: row.bytes,
                        sha256: row.sha256,
                    });
                } else if row.path.ends_with(".rmeta") {
                    if row.mode.is_some_and(|mode| mode != 0o644) {
                        return Err(Refusal::new(format!(
                            "producer target metadata has an unexpected mode: {host}"
                        )));
                    }
                    host_metadata.push(row);
                } else {
                    host_invariant_payload.push(row);
                }
            }
            host_metadata.sort();
            if host_rlibs.len() != 6 || host_metadata.len() != 6 {
                return Err(Refusal::new(format!(
                    "producer target payload lacks the dual-ABI rlib/rmeta set: {host}"
                )));
            }
            target_metadata_rows.push(json!({
                "host": host,
                "artifacts": host_metadata,
                "compiler_outputs_mutated": false,
            }));
            host_invariant_payload.sort();
            if let Some(expected) = &invariant_target_payload {
                if expected != &host_invariant_payload {
                    return Err(Refusal::new(format!(
                        "invariant AROS target payload differs between producer hosts: {host}"
                    )));
                }
            } else {
                invariant_target_payload = Some(host_invariant_payload);
            }
            let direct_archives = inventory
                .artifacts
                .iter()
                .filter(|artifact| artifact.role == "direct-archive")
                .collect::<Vec<_>>();
            if direct_archives.len() != 1 {
                return Err(Refusal::new(format!(
                    "producer inventory must contain exactly one direct archive: {host}"
                )));
            }
            let direct_archive = direct_archives[0];
            host_target_rlibs.push(HostTargetRlibs {
                host: host.to_owned(),
                direct_archive: root.join("artifacts").join(&direct_archive.path),
                archive_bytes: direct_archive.bytes,
                archive_sha256: direct_archive.sha256.clone(),
                libraries: host_rlibs,
            });
            let inventory_identity = copy_verified(
                &inventory_path,
                &candidate.join(&inventory_name),
                inventory_raw.len() as u64,
                &sha256_bytes(&inventory_raw),
            )?;
            raw_assets.push(inventory_identity.clone());
            let mut components = BTreeMap::new();
            for artifact in inventory.rustup.artifacts {
                if !COMPONENTS.iter().any(|(role, _)| *role == artifact.role)
                    || components
                        .insert(artifact.role.clone(), artifact.clone())
                        .is_some()
                {
                    return Err(Refusal::new(
                        "producer inventory has an invalid Rustup component set",
                    ));
                }
                let identity = copy_verified(
                    &root.join("artifacts").join(&artifact.path),
                    &candidate.join(&artifact.path),
                    artifact.bytes,
                    &artifact.sha256,
                )?;
                raw_assets.push(identity);
            }
            if components.len() != COMPONENTS.len() {
                return Err(Refusal::new("producer inventory omits a Rustup component"));
            }
            let required_native = BTreeSet::from(["direct-archive", "release-notices"]);
            if inventory
                .artifacts
                .iter()
                .map(|row| row.role.as_str())
                .collect::<BTreeSet<_>>()
                != required_native
            {
                return Err(Refusal::new(format!(
                    "producer inventory has an invalid native package set: {host}"
                )));
            }
            for artifact in inventory.artifacts {
                require_native_artifact_name(&artifact, host, &request.version)?;
                let source = root.join("artifacts").join(&artifact.path);
                if let Some(existing) = channel_assets.get(&artifact.path) {
                    verify_file(&source, existing.bytes, &existing.sha256)?;
                    if artifact.bytes != existing.bytes || artifact.sha256 != existing.sha256 {
                        return Err(Refusal::new(
                            "common native package differs between producer hosts",
                        ));
                    }
                    continue;
                }
                let identity = copy_verified(
                    &source,
                    &candidate.join(&artifact.path),
                    artifact.bytes,
                    &artifact.sha256,
                )?;
                channel_assets.insert(artifact.path, identity.clone());
                raw_assets.push(identity);
            }
            rustup_hosts.push(RustupManifestHost {
                host: release_host(host)?,
                components: RustupComponents {
                    rustc: release_artifact(
                        components
                            .remove("rustup-rustc-component")
                            .expect("checked"),
                    )?,
                    cargo: release_artifact(
                        components
                            .remove("rustup-cargo-component")
                            .expect("checked"),
                    )?,
                    rust_std: release_artifact(
                        components
                            .remove("rustup-rust-std-component")
                            .expect("checked"),
                    )?,
                },
            });
            producer_rows.push(json!({
                "host": host,
                "inventory": identity_json(&inventory_identity),
            }));
        }
        let target_library_comparison = target_rlib_compare::compare(host_target_rlibs)?;
        let release_tag = format!("v{}", request.version);
        let rendered = render_rustup_manifest(&RustupManifestRequest {
            version: request.version.clone(),
            epoch,
            rust_version: request.rust_version.clone(),
            cargo_version: request.cargo_version.clone(),
            release_tag: release_tag.clone(),
            hosts: rustup_hosts,
        })?;
        let manifest_identity = write_candidate_file(
            &candidate,
            &rendered.manifest_name,
            rendered.manifest.as_bytes(),
        )?;
        let checksum_identity = write_candidate_file(
            &candidate,
            &rendered.checksum_name,
            rendered.checksum.as_bytes(),
        )?;
        write_new(
            &distribution.join(&rendered.manifest_name),
            rendered.manifest.as_bytes(),
        )?;
        write_new(
            &distribution.join(&rendered.checksum_name),
            rendered.checksum.as_bytes(),
        )?;
        raw_assets.extend([manifest_identity, checksum_identity]);

        raw_assets.sort_by(|left, right| left.name.cmp(&right.name));
        require_unique_names(&raw_assets)?;
        let sbom =
            render_release_sbom(&request.version, &request.source_commit, epoch, &raw_assets)?;
        raw_assets.push(write_json_candidate(
            &candidate,
            &format!("ami-rust-{}.spdx.json", request.version),
            &sbom,
        )?);

        if let (Some(catalog_root), Some(catalog_commit)) =
            (&request.catalog_root, &request.catalog_commit)
        {
            let catalog = existing_directory(catalog_root.clone(), "catalog root")?;
            if git_identity(&catalog, "HEAD")? != *catalog_commit {
                return Err(Refusal::new(
                    "catalog checkout differs from the selected commit",
                ));
            }
            let selected = catalog
                .join("distribution/rustup")
                .join(&request.version)
                .join("dist");
            for (name, expected) in [
                (&rendered.manifest_name, rendered.manifest.as_bytes()),
                (&rendered.checksum_name, rendered.checksum.as_bytes()),
            ] {
                if read_regular_bounded(&selected.join(name), 1024 * 1024)? != expected {
                    return Err(Refusal::new(
                        "selected catalog bytes differ from the exact producer inventory",
                    ));
                }
            }
        }

        raw_assets.sort_by(|left, right| left.name.cmp(&right.name));
        require_unique_names(&raw_assets)?;
        let direct_archives = ["macos-aarch64", "linux-x86_64", "linux-aarch64"]
            .iter()
            .map(|host| {
                identity_json(
                    &channel_assets[&format!("ami-rust-{}-{host}.tar.xz", request.version)],
                )
            })
            .collect::<Vec<_>>();
        let handoff = json!({
            "schema": HANDOFF_SCHEMA,
            "status": "EXACT_RELEASE_ASSET_IDENTITIES_FOR_DIRECT_AND_RUSTUP",
            "version": request.version,
            "release_tag": release_tag,
            "qualification": {"run_id":request.qualification_run_id,"run_attempt":request.qualification_run_attempt},
            "assets": raw_assets.iter().map(identity_json).collect::<Vec<_>>(),
            "direct": {
                "archives": direct_archives
            },
            "rustup": {
                "manifest":rendered.manifest_name,
                "checksum":rendered.checksum_name,
                "component_count":9,
            },
            "deferred_channels": ["apt", "homebrew", "aur", "crates.io"],
            "claim": "The 0.1 candidate prepares only authenticated direct archives and rustup distribution metadata. No asset is published by assembly."
        });
        let handoff_identity = write_json_candidate(&candidate, "channel-handoff.json", &handoff)?;
        raw_assets.push(handoff_identity);
        raw_assets.sort_by(|left, right| left.name.cmp(&right.name));

        let publication = json!({
            "schema": INVENTORY_SCHEMA,
            "status": if request.catalog_commit.is_some() {"READY_FOR_PROTECTED_SIGNING"} else {"CATALOG_READY_FOR_REVIEW"},
            "version": request.version,
            "release_tag": format!("v{}", request.version),
            "targets": TARGETS,
            "source": {"commit":request.source_commit,"tree":request.source_tree,"epoch":epoch},
            "production_contract_sha256": contract_sha,
            "qualification": {"run_id":request.qualification_run_id,"run_attempt":request.qualification_run_attempt},
            "catalog_commit": request.catalog_commit,
            "producer_inventories": producer_rows,
            "three_host_target_payload": {
                "comparison": "R1-A2 native records exact; Cargo-bound filenames and matching metadata references separately qualified",
                "invariant_file_count": invariant_target_payload.as_ref().expect("three hosts checked").len(),
                "invariant_files": invariant_target_payload.expect("three hosts checked"),
                "target_libraries": target_library_comparison,
                "host_metadata": target_metadata_rows,
                "host_metadata_mutated": false
            },
            "assets": raw_assets.iter().map(identity_json).collect::<Vec<_>>(),
            "publication_authorized": false,
            "claim": "Exact RP2 producer outputs assembled for RP3. Only the protected workflow may sign, attest, stage, read back and promote these bytes."
        });
        let publication_identity =
            write_json_candidate(&candidate, "publication-inventory.json", &publication)?;
        raw_assets.push(publication_identity);
        raw_assets.sort_by(|left, right| left.name.cmp(&right.name));
        let signature_plan = json!({
            "schema":"ami-rust-rp3-signature-plan-v1",
            "status":"READY_FOR_PROTECTED_SIGNATURES",
            "subject_count":raw_assets.len(),
            "signature_subjects":raw_assets.iter().map(|row| row.name.clone()).collect::<Vec<_>>(),
            "subjects":raw_assets.iter().map(identity_json).collect::<Vec<_>>()
        });
        write_json_new(&stage.join("signature-plan.json"), &signature_plan)?;
        write_json_new(
            &stage.join("assembly-result.json"),
            &json!({
                "schema":"ami-rust-rp3-assembly-result-v1",
                "status":if request.catalog_commit.is_some() {"READY_FOR_PROTECTED_SIGNATURES"} else {"CATALOG_READY_FOR_REVIEW"},
                "version":request.version,
                "release_tag":format!("v{}",request.version),
                "raw_subject_count":raw_assets.len(),
                "catalog_commit":request.catalog_commit,
                "publication_authorized":false
            }),
        )?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&stage);
        return Err(error);
    }
    fs::rename(&stage, &output)?;
    println!(
        "{}",
        json!({"status":"RP3_RELEASE_ASSEMBLED","output":output})
    );
    Ok(())
}

fn prepare_qualification(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let mut options = options(&mut arguments, &["--assembly-root", "--host", "--output"])?;
    let root = existing_directory(take_path(&mut options, "--assembly-root")?, "assembly root")?;
    let host = take_string(&mut options, "--host")?;
    let _ = release_host(&host)?;
    let output = fresh_directory_path(take_path(&mut options, "--output")?)?;
    let result = read_object(&root.join("assembly-result.json"))?;
    if result.get("schema").and_then(Value::as_str) != Some("ami-rust-rp3-assembly-result-v1")
        || result.get("status").and_then(Value::as_str) != Some("CATALOG_READY_FOR_REVIEW")
        || result
            .get("publication_authorized")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err(Refusal::new(
            "qualification requires one unsigned exact RP3 assembly",
        ));
    }
    let version = result
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new("assembly result lacks a version"))?;
    let candidate = existing_directory(root.join("candidate"), "candidate directory")?;
    let manifest_name = format!("channel-rust-{version}.toml");
    let production_manifest = read_regular_bounded(&candidate.join(&manifest_name), 1024 * 1024)?;
    let production_manifest = String::from_utf8(production_manifest)
        .map_err(|_| Refusal::new("rustup manifest must be UTF-8"))?;
    let public_prefix =
        format!("https://github.com/metaneutrons/ami-rust/releases/download/v{version}/");
    if production_manifest.matches(&public_prefix).count() != 9 {
        return Err(Refusal::new(
            "production rustup manifest does not declare nine exact component URLs",
        ));
    }
    let candidate_text = candidate
        .to_str()
        .ok_or_else(|| Refusal::new("candidate path must be UTF-8"))?;
    if candidate_text
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'"' | b'\\' | b'#' | b'?'))
    {
        return Err(Refusal::new(
            "candidate path cannot be represented as a local rustup URL",
        ));
    }
    let local_prefix = format!("file://{candidate_text}/");
    let qualification_manifest = production_manifest.replace(&public_prefix, &local_prefix);
    let stage = sibling_stage(&output)?;
    fs::create_dir(&stage)?;
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))?;
    let transaction = (|| -> Result<()> {
        let dist = stage.join("dist");
        fs::create_dir(&dist)?;
        write_new(
            &dist.join(&manifest_name),
            qualification_manifest.as_bytes(),
        )?;
        let checksum_name = format!("{manifest_name}.sha256");
        let checksum = format!(
            "{}  {manifest_name}\n",
            sha256_bytes(qualification_manifest.as_bytes())
        );
        write_new(&dist.join(&checksum_name), checksum.as_bytes())?;
        write_json_new(
            &stage.join("qualification-catalog.json"),
            &json!({
                "schema":"ami-rust-rp4-local-rustup-catalog-v1",
                "status":"READY_FOR_UNMODIFIED_RUSTUP_QUALIFICATION",
                "version":version,
                "host":host,
                "production_manifest_sha256":sha256_bytes(production_manifest.as_bytes()),
                "qualification_manifest_sha256":sha256_bytes(qualification_manifest.as_bytes()),
                "component_url_replacements":9,
                "component_bytes_mutated":false,
                "publication_authorized":false
            }),
        )?;
        Ok(())
    })();
    if let Err(error) = transaction {
        let _ = fs::remove_dir_all(&stage);
        return Err(error);
    }
    fs::rename(stage, &output)?;
    println!(
        "{}",
        json!({"status":"RP4_LOCAL_RUSTUP_CATALOG_READY","host":host,"output":output})
    );
    Ok(())
}

fn finalize(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let root = one_directory_option(&mut arguments, "--assembly-root")?;
    let candidate = existing_directory(root.join("candidate"), "candidate directory")?;
    let plan = read_object(&root.join("signature-plan.json"))?;
    if plan.get("schema").and_then(Value::as_str) != Some("ami-rust-rp3-signature-plan-v1")
        || plan.get("status").and_then(Value::as_str) != Some("READY_FOR_PROTECTED_SIGNATURES")
    {
        return Err(Refusal::new("unsupported RP3 signature plan"));
    }
    let subjects = plan
        .get("subjects")
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::new("RP3 signature plan lacks subject identities"))?;
    let mut identities = Vec::new();
    for subject in subjects {
        let row = parse_identity(subject)?;
        verify_file(&candidate.join(&row.name), row.bytes, &row.sha256)?;
        identities.push(row.clone());
        let signature_name = format!("{}.sigstore.json", row.name);
        let signature_path = candidate.join(&signature_name);
        let metadata = regular_metadata(&signature_path)?;
        if metadata.len() == 0 || metadata.len() > 4 * 1024 * 1024 {
            return Err(Refusal::new("signature bundle has an invalid size"));
        }
        identities.push(FileIdentity {
            name: signature_name,
            bytes: metadata.len(),
            sha256: sha256_file(&signature_path)?,
        });
    }
    identities.sort_by(|left, right| left.name.cmp(&right.name));
    require_unique_names(&identities)?;
    let mut checksums = Vec::new();
    for row in &identities {
        checksums.extend_from_slice(format!("{}  {}\n", row.sha256, row.name).as_bytes());
    }
    let sums = write_candidate_file(&candidate, "SHA256SUMS", &checksums)?;
    identities.push(sums);
    identities.sort_by(|left, right| left.name.cmp(&right.name));
    let final_result = json!({
        "schema": FINAL_SCHEMA,
        "status":"READY_FOR_ATTESTED_DRAFT_UPLOAD",
        "files":identities.iter().map(identity_json).collect::<Vec<_>>(),
        "file_count":identities.len(),
        "total_bytes":identities.iter().try_fold(0_u64, |sum,row| sum.checked_add(row.bytes).ok_or_else(|| Refusal::new("candidate byte total overflow")))?,
        "claim":"Exact signed bytes only; the protected workflow still must attest, upload, publicly read back and promote them."
    });
    write_json_new(&root.join("final-readback.json"), &final_result)?;
    let mut attestation = Vec::new();
    for row in &identities {
        attestation.extend_from_slice(format!("{}  {}\n", row.sha256, row.name).as_bytes());
    }
    write_new(&root.join("attestation-subjects.sha256"), &attestation)?;
    println!(
        "{}",
        json!({"status":"READY_FOR_ATTESTED_DRAFT_UPLOAD","file_count":identities.len()})
    );
    Ok(())
}

fn recover_public(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let mut options = options(&mut arguments, &["--assembly-root", "--download"])?;
    let root = existing_directory(take_path(&mut options, "--assembly-root")?, "assembly root")?;
    let download = existing_directory(take_path(&mut options, "--download")?, "public download")?;
    let plan = read_object(&root.join("signature-plan.json"))?;
    if plan.get("schema").and_then(Value::as_str) != Some("ami-rust-rp3-signature-plan-v1")
        || plan.get("status").and_then(Value::as_str) != Some("READY_FOR_PROTECTED_SIGNATURES")
    {
        return Err(Refusal::new("unsupported RP3 signature plan"));
    }
    let subjects = plan
        .get("subjects")
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::new("RP3 signature plan lacks subject identities"))?;
    let mut identities = Vec::new();
    for subject in subjects {
        let row = parse_identity(subject)?;
        verify_file(&download.join(&row.name), row.bytes, &row.sha256)?;
        identities.push(row.clone());
        let signature_name = format!("{}.sigstore.json", row.name);
        let signature_path = download.join(&signature_name);
        let metadata = regular_metadata(&signature_path)?;
        if metadata.len() == 0 || metadata.len() > 4 * 1024 * 1024 {
            return Err(Refusal::new("public signature bundle has an invalid size"));
        }
        let raw = read_regular_bounded(&signature_path, 4 * 1024 * 1024)?;
        let _ = parse_json_value(&raw, JsonProfile::ProductionContract)?;
        identities.push(FileIdentity {
            name: signature_name,
            bytes: metadata.len(),
            sha256: sha256_bytes(&raw),
        });
    }
    identities.sort_by(|left, right| left.name.cmp(&right.name));
    require_unique_names(&identities)?;
    let mut checksums = Vec::new();
    for row in &identities {
        checksums.extend_from_slice(format!("{}  {}\n", row.sha256, row.name).as_bytes());
    }
    let actual_checksums = read_regular_bounded(&download.join("SHA256SUMS"), MAX_JSON)?;
    if actual_checksums != checksums {
        return Err(Refusal::new(
            "public SHA256SUMS differs from the exact recovered candidate",
        ));
    }
    identities.push(FileIdentity {
        name: "SHA256SUMS".to_owned(),
        bytes: actual_checksums.len() as u64,
        sha256: sha256_bytes(&actual_checksums),
    });
    identities.sort_by(|left, right| left.name.cmp(&right.name));
    let expected_names = identities
        .iter()
        .map(|row| row.name.clone())
        .collect::<BTreeSet<_>>();
    if directory_file_names(&download)? != expected_names {
        return Err(Refusal::new(
            "public recovery download contains a different release asset set",
        ));
    }
    let final_result = json!({
        "schema": FINAL_SCHEMA,
        "status":"RECOVERED_EXACT_PUBLIC_RELEASE",
        "files":identities.iter().map(identity_json).collect::<Vec<_>>(),
        "file_count":identities.len(),
        "total_bytes":identities.iter().try_fold(0_u64, |sum,row| sum.checked_add(row.bytes).ok_or_else(|| Refusal::new("candidate byte total overflow")))?,
        "claim":"Existing public bytes exactly match the bound raw subjects and checksum closure; recovery may read back, verify and promote but cannot replace them."
    });
    write_json_new(&root.join("final-readback.json"), &final_result)?;
    println!(
        "{}",
        json!({"status":"RECOVERED_EXACT_PUBLIC_RELEASE","file_count":identities.len()})
    );
    Ok(())
}

fn verify_readback(mut arguments: impl Iterator<Item = OsString>) -> Result<()> {
    let mut options = options(&mut arguments, &["--assembly-root", "--download"])?;
    let root = existing_directory(take_path(&mut options, "--assembly-root")?, "assembly root")?;
    let download = existing_directory(take_path(&mut options, "--download")?, "public download")?;
    let final_result = read_object(&root.join("final-readback.json"))?;
    let status = final_result.get("status").and_then(Value::as_str);
    if final_result.get("schema").and_then(Value::as_str) != Some(FINAL_SCHEMA)
        || !matches!(
            status,
            Some("READY_FOR_ATTESTED_DRAFT_UPLOAD" | "RECOVERED_EXACT_PUBLIC_RELEASE")
        )
    {
        return Err(Refusal::new("unsupported final readback record"));
    }
    let rows = final_result
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::new("final readback lacks files"))?;
    let expected = rows
        .iter()
        .map(parse_identity)
        .collect::<Result<Vec<_>>>()?;
    let actual_names = directory_file_names(&download)?;
    let expected_names = expected
        .iter()
        .map(|row| row.name.clone())
        .collect::<BTreeSet<_>>();
    if actual_names != expected_names {
        return Err(Refusal::new(
            "public release download set differs from the final candidate",
        ));
    }
    for row in &expected {
        verify_file(&download.join(&row.name), row.bytes, &row.sha256)?;
    }
    println!(
        "{}",
        json!({
            "schema":"ami-rust-rp3-public-readback-v1",
            "status":"EVERY_PUBLISHED_BYTE_MATCHES_BEFORE_PROMOTION",
            "file_count":expected.len()
        })
    );
    Ok(())
}

fn require_native_artifact_name(
    artifact: &ProducerArtifact,
    host: &str,
    version: &str,
) -> Result<()> {
    let expected = match artifact.role.as_str() {
        "direct-archive" => format!("ami-rust-{version}-{host}.tar.xz"),
        "release-notices" => format!("ami-rust-{version}-notices.tar.xz"),
        _ => return Err(Refusal::new("unsupported native producer artifact role")),
    };
    if artifact.path != expected {
        return Err(Refusal::new(format!(
            "native producer artifact name differs for {}",
            artifact.role
        )));
    }
    Ok(())
}

struct VerifiedSourceCapsule {
    path: PathBuf,
    identity: FileIdentity,
}

fn verified_source_capsule(
    root: &Path,
    version: &str,
    source_commit: &str,
    source_tree: &str,
    epoch: u64,
) -> Result<VerifiedSourceCapsule> {
    let root = existing_directory(root.to_path_buf(), "source capsule output")?;
    let result = read_object(&root.join("result.json"))?;
    if result.get("schema").and_then(Value::as_str)
        != Some("ami-rust-toolchain-capsule-result-v1")
        || result.get("status").and_then(Value::as_str)
            != Some("COMPLETED_LOCAL_UNSIGNED_CANDIDATE_ONLY")
        || result.get("version").and_then(Value::as_str) != Some(version)
    {
        return Err(Refusal::new(
            "source capsule result has an unsupported identity",
        ));
    }
    let source = result
        .get("source")
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new("source capsule result lacks a source identity"))?;
    if source.get("commit").and_then(Value::as_str) != Some(source_commit)
        || source.get("tree").and_then(Value::as_str) != Some(source_tree)
        || source.get("epoch").and_then(Value::as_u64) != Some(epoch)
    {
        return Err(Refusal::new(
            "source capsule was not produced from the selected release source",
        ));
    }
    let expected_source = format!("ami-rust-{version}-sources.tar.xz");
    let expected_vendor = format!("ami-rust-{version}-vendor.tar.xz");
    let artifacts = result
        .get("artifacts")
        .and_then(Value::as_array)
        .ok_or_else(|| Refusal::new("source capsule result lacks artifacts"))?;
    if artifacts.len() != 2 {
        return Err(Refusal::new(
            "source capsule result must contain exactly source and vendor archives",
        ));
    }
    let mut names = BTreeSet::new();
    let mut selected = None;
    for artifact in artifacts {
        let name = artifact
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| Refusal::new("source capsule artifact lacks a name"))?;
        let bytes = artifact
            .get("bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| Refusal::new("source capsule artifact lacks a byte count"))?;
        let sha256 = artifact
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| Refusal::new("source capsule artifact lacks a digest"))?;
        if bytes == 0
            || !is_sha256_digest(sha256)
            || !names.insert(name.to_owned())
            || (name != expected_source && name != expected_vendor)
        {
            return Err(Refusal::new(
                "source capsule artifact set or identity is invalid",
            ));
        }
        let path = root.join(name);
        verify_file(&path, bytes, sha256)?;
        if name == expected_source {
            selected = Some(VerifiedSourceCapsule {
                path,
                identity: FileIdentity {
                    name: name.to_owned(),
                    bytes,
                    sha256: sha256.to_owned(),
                },
            });
        }
    }
    if names != BTreeSet::from([expected_source, expected_vendor]) {
        return Err(Refusal::new(
            "source capsule result omits a required archive",
        ));
    }
    selected.ok_or_else(|| Refusal::new("source capsule archive is absent"))
}

fn render_release_sbom(
    version: &str,
    source_commit: &str,
    epoch: u64,
    assets: &[FileIdentity],
) -> Result<Value> {
    let created = unix_timestamp(epoch)?;
    let files = assets
        .iter()
        .enumerate()
        .map(|(index, row)| {
            json!({
                "SPDXID":format!("SPDXRef-File-{}",index + 1),
                "fileName":row.name,
                "checksums":[{"algorithm":"SHA256","checksumValue":row.sha256}],
                "licenseConcluded":"NOASSERTION",
                "licenseInfoInFiles":["NOASSERTION"],
                "copyrightText":"NOASSERTION",
            })
        })
        .collect::<Vec<_>>();
    let relationships = files
        .iter()
        .map(|row| {
            json!({
                "spdxElementId":"SPDXRef-Package-ami-rust",
                "relationshipType":"CONTAINS",
                "relatedSpdxElement":row["SPDXID"],
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "spdxVersion":"SPDX-2.3",
        "dataLicense":"CC0-1.0",
        "SPDXID":"SPDXRef-DOCUMENT",
        "name":format!("ami-rust-{version}"),
        "documentNamespace":format!("https://github.com/metaneutrons/ami-rust/releases/download/v{version}/ami-rust-{version}.spdx.json#{source_commit}"),
        "creationInfo":{"created":created,"creators":["Tool: ami-rust-xtask"]},
        "packages":[{
            "SPDXID":"SPDXRef-Package-ami-rust",
            "name":"ami-rust",
            "versionInfo":version,
            "downloadLocation":format!("https://github.com/metaneutrons/ami-rust/releases/tag/v{version}"),
            "filesAnalyzed":true,
            "licenseConcluded":"NOASSERTION",
            "licenseDeclared":"NOASSERTION",
            "copyrightText":"NOASSERTION",
        }],
        "files":files,
        "relationships":relationships,
    }))
}

fn unix_timestamp(seconds: u64) -> Result<String> {
    let days = i64::try_from(seconds / 86_400)
        .map_err(|_| Refusal::new("release epoch is outside the supported date range"))?;
    let seconds = seconds % 86_400;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    if !(0..=9_999).contains(&year) {
        return Err(Refusal::new(
            "release epoch is outside the supported date range",
        ));
    }
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        seconds / 3_600,
        (seconds % 3_600) / 60,
        seconds % 60,
    ))
}

fn release_artifact(row: ProducerArtifact) -> Result<Artifact> {
    serde_json::from_value(json!({"name":row.path,"bytes":row.bytes,"sha256":row.sha256}))
        .map_err(|error| Refusal::new(format!("invalid Rustup artifact identity: {error}")))
}

fn release_host(host: &str) -> Result<ReleaseHost> {
    match host {
        "macos-aarch64" => Ok(ReleaseHost::MacosAarch64),
        "linux-x86_64" => Ok(ReleaseHost::LinuxX86_64),
        "linux-aarch64" => Ok(ReleaseHost::LinuxAarch64),
        _ => Err(Refusal::new("unsupported release host")),
    }
}

fn options(
    arguments: &mut impl Iterator<Item = OsString>,
    admitted: &[&str],
) -> Result<BTreeMap<OsString, OsString>> {
    let mut result = BTreeMap::new();
    while let Some(key) = arguments.next() {
        if !admitted.iter().any(|candidate| key == *candidate) {
            return Err(usage());
        }
        let value = arguments.next().ok_or_else(usage)?;
        if result.insert(key, value).is_some() {
            return Err(usage());
        }
    }
    Ok(result)
}

fn take_path(options: &mut BTreeMap<OsString, OsString>, name: &str) -> Result<PathBuf> {
    options
        .remove(OsStr::new(name))
        .map(PathBuf::from)
        .ok_or_else(usage)
}

fn take_string(options: &mut BTreeMap<OsString, OsString>, name: &str) -> Result<String> {
    options
        .remove(OsStr::new(name))
        .and_then(|value| value.into_string().ok())
        .ok_or_else(usage)
}

fn one_directory_option(
    arguments: &mut impl Iterator<Item = OsString>,
    name: &str,
) -> Result<PathBuf> {
    if arguments.next().as_deref() != Some(OsStr::new(name)) {
        return Err(usage());
    }
    let path = PathBuf::from(arguments.next().ok_or_else(usage)?);
    if arguments.next().is_some() {
        return Err(usage());
    }
    existing_directory(path, "assembly root")
}

fn existing_directory(path: PathBuf, label: &str) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(Refusal::new(format!("{label} must be absolute")));
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| Refusal::new(format!("could not inspect {label}: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(Refusal::new(format!("{label} must be a real directory")));
    }
    fs::canonicalize(path).map_err(Into::into)
}

fn fresh_file_path(path: PathBuf) -> Result<PathBuf> {
    fresh_path(path, "output file")
}

fn fresh_directory_path(path: PathBuf) -> Result<PathBuf> {
    fresh_path(path, "output directory")
}

fn fresh_path(path: PathBuf, label: &str) -> Result<PathBuf> {
    if !path.is_absolute() || path.file_name().is_none() || fs::symlink_metadata(&path).is_ok() {
        return Err(Refusal::new(format!(
            "{label} must be a fresh absolute path"
        )));
    }
    let parent = fs::canonicalize(
        path.parent()
            .ok_or_else(|| Refusal::new(format!("{label} has no parent")))?,
    )?;
    Ok(parent.join(path.file_name().expect("checked")))
}

fn sibling_stage(output: &Path) -> Result<PathBuf> {
    let name = output
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| Refusal::new("output name must be UTF-8"))?;
    let stage = output.with_file_name(format!(".{name}.stage-{}", std::process::id()));
    if fs::symlink_metadata(&stage).is_ok() {
        return Err(Refusal::new("release assembly stage is occupied"));
    }
    Ok(stage)
}

fn copy_verified(
    source: &Path,
    destination: &Path,
    bytes: u64,
    digest: &str,
) -> Result<FileIdentity> {
    if !is_sha256_digest(digest) {
        return Err(Refusal::new("selected asset has an invalid digest"));
    }
    verify_file(source, bytes, digest)?;
    let mut input = File::open(source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)?;
    std::io::copy(&mut input, &mut output)?;
    output.sync_all()?;
    verify_file(destination, bytes, digest)?;
    Ok(FileIdentity {
        name: destination
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| Refusal::new("asset name must be UTF-8"))?
            .to_owned(),
        bytes,
        sha256: digest.to_owned(),
    })
}

fn verify_file(path: &Path, bytes: u64, digest: &str) -> Result<()> {
    let metadata = regular_metadata(path)?;
    if metadata.len() != bytes || sha256_file(path)? != digest {
        return Err(Refusal::new(format!(
            "file identity differs: {}",
            path.display()
        )));
    }
    Ok(())
}

fn regular_metadata(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
        return Err(Refusal::new(format!(
            "required input is not one regular file: {}",
            path.display()
        )));
    }
    Ok(metadata)
}

fn write_candidate_file(root: &Path, name: &str, bytes: &[u8]) -> Result<FileIdentity> {
    safe_name(name)?;
    write_new(&root.join(name), bytes)?;
    Ok(FileIdentity {
        name: name.to_owned(),
        bytes: bytes.len() as u64,
        sha256: sha256_bytes(bytes),
    })
}

fn write_json_candidate(root: &Path, name: &str, value: &Value) -> Result<FileIdentity> {
    let bytes = canonical_json(value)?;
    write_candidate_file(root, name, &bytes)
}

fn write_json_new(path: &Path, value: &Value) -> Result<()> {
    write_new(path, &canonical_json(value)?)
}

fn replace_json(path: &Path, value: &Value) -> Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    write_new(&temporary, &canonical_json(value)?)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn canonical_json(value: &Value) -> Result<Vec<u8>> {
    let mut raw = serde_json::to_vec(value)
        .map_err(|error| Refusal::new(format!("could not encode RP3 JSON: {error}")))?;
    raw.push(b'\n');
    Ok(raw)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
    output.write_all(bytes)?;
    output.sync_all()?;
    Ok(())
}

fn identity_json(row: &FileIdentity) -> Value {
    json!({"name":row.name,"bytes":row.bytes,"sha256":row.sha256})
}

fn parse_identity(value: &Value) -> Result<FileIdentity> {
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new("file identity must be an object"))?;
    if object.len() != 3 {
        return Err(Refusal::new("file identity has unknown fields"));
    }
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new("file identity lacks name"))?;
    let bytes = object
        .get("bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| Refusal::new("file identity lacks bytes"))?;
    let sha256 = object
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new("file identity lacks digest"))?;
    safe_name(name)?;
    if bytes == 0 || !is_sha256_digest(sha256) {
        return Err(Refusal::new("file identity has invalid size or digest"));
    }
    Ok(FileIdentity {
        name: name.to_owned(),
        bytes,
        sha256: sha256.to_owned(),
    })
}

fn require_unique_names(rows: &[FileIdentity]) -> Result<()> {
    if rows
        .iter()
        .map(|row| row.name.as_str())
        .collect::<BTreeSet<_>>()
        .len()
        != rows.len()
    {
        return Err(Refusal::new("release asset names collide"));
    }
    Ok(())
}

fn safe_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.starts_with('.')
        || name.ends_with('.')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
    {
        return Err(Refusal::new("unsafe release asset name"));
    }
    Ok(())
}

fn read_object(path: &Path) -> Result<serde_json::Map<String, Value>> {
    parse_json_value(
        &read_regular_bounded(path, MAX_JSON)?,
        JsonProfile::ProductionContract,
    )?
    .as_object()
    .cloned()
    .ok_or_else(|| Refusal::new("RP3 record must be an object"))
}

fn directory_file_names(root: &Path) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| Refusal::new("public asset name must be UTF-8"))?;
        safe_name(&name)?;
        let _ = regular_metadata(&entry.path())?;
        names.insert(name);
    }
    Ok(names)
}

fn git_identity(root: &Path, revision: &str) -> Result<String> {
    let output = Command::new("git")
        .args(["-C"])
        .arg(root)
        .args(["rev-parse", revision])
        .output()?;
    if !output.status.success() {
        return Err(Refusal::new("could not resolve selected Git identity"));
    }
    let value =
        String::from_utf8(output.stdout).map_err(|_| Refusal::new("Git identity is not UTF-8"))?;
    let value = value.trim();
    require_git_id(value, "Git identity")?;
    Ok(value.to_owned())
}

fn git_commit_epoch(root: &Path, revision: &str) -> Result<u64> {
    let output = Command::new("git")
        .args(["-C"])
        .arg(root)
        .args(["show", "-s", "--format=%ct", revision])
        .output()?;
    if !output.status.success() {
        return Err(Refusal::new(
            "could not resolve selected Git commit timestamp",
        ));
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|_| Refusal::new("Git commit timestamp is not UTF-8"))?;
    let epoch = value
        .trim()
        .parse::<u64>()
        .map_err(|_| Refusal::new("Git commit timestamp is invalid"))?;
    if epoch == 0 {
        return Err(Refusal::new("Git commit timestamp must be positive"));
    }
    Ok(epoch)
}

fn require_git_id(value: &str, label: &str) -> Result<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Refusal::new(format!(
            "{label} must be a full lowercase Git object ID"
        )));
    }
    Ok(())
}

fn usage() -> Refusal {
    Refusal::new(
        "usage: ami-rust-xtask toolchain-release-cutover {check --source-root DIR --contract FILE --version VERSION --output FILE|assemble --request FILE|prepare-qualification --assembly-root DIR --host HOST --output DIR|bind-catalog --assembly-root DIR --catalog-root DIR --catalog-commit COMMIT|finalize --assembly-root DIR|recover-public --assembly-root DIR --download DIR|verify-readback --assembly-root DIR --download DIR}",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn source_capsule_must_match_the_selected_source_and_bytes() {
        let root = std::env::temp_dir().join(format!(
            "ami-rust-source-capsule-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let version = "0.1.0";
        let commit = "0123456789abcdef0123456789abcdef01234567";
        let tree = "89abcdef0123456789abcdef0123456789abcdef";
        let epoch = 1_793_095_486;
        let source_name = format!("ami-rust-{version}-sources.tar.xz");
        let vendor_name = format!("ami-rust-{version}-vendor.tar.xz");
        let source_bytes = b"source capsule";
        let vendor_bytes = b"vendor capsule";
        fs::write(root.join(&source_name), source_bytes).unwrap();
        fs::write(root.join(&vendor_name), vendor_bytes).unwrap();
        let result = json!({
            "schema":"ami-rust-toolchain-capsule-result-v1",
            "status":"COMPLETED_LOCAL_UNSIGNED_CANDIDATE_ONLY",
            "version":version,
            "source":{"commit":commit,"tree":tree,"epoch":epoch},
            "artifacts":[
                {"name":source_name,"bytes":source_bytes.len(),"sha256":sha256_bytes(source_bytes)},
                {"name":vendor_name,"bytes":vendor_bytes.len(),"sha256":sha256_bytes(vendor_bytes)}
            ]
        });
        fs::write(root.join("result.json"), serde_json::to_vec(&result).unwrap()).unwrap();

        let selected =
            verified_source_capsule(&root, version, commit, tree, epoch).expect("valid capsule");
        assert_eq!(selected.identity.name, source_name);

        fs::write(root.join(&source_name), b"corrupted capsule").unwrap();
        assert!(verified_source_capsule(&root, version, commit, tree, epoch).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
