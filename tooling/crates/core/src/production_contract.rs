//! RP1's single production input and output contract.
//!
//! This reader performs no acquisition and writes no output. It validates the
//! complete declarative contract, checks every repository-owned input, and
//! admits the portable C-SDK archive against its exact member inventory.

use crate::{
    Refusal, Result,
    digest::{is_sha256_digest, sha256_file},
    json::{JsonProfile, read_json},
};
use lzma_rust2::XzReader;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
};
use tar::Archive;

const SCHEMA: &str = "ami-rust-production-contract-v1";
const STATUS: &str = "RP1_FROZEN_INPUT_AND_OUTPUT_CONTRACT_NOT_PRODUCED";
const HOSTS: [(&str, &str, Option<&str>); 3] = [
    ("linux-aarch64", "aarch64-unknown-linux-gnu", Some("arm64")),
    ("linux-x86_64", "x86_64-unknown-linux-gnu", Some("amd64")),
    ("macos-aarch64", "aarch64-apple-darwin", None),
];
const REQUIRED_INPUTS: &[&str] = &[
    "cargo-openssl-overlay",
    "cargo-openssl-path-patch",
    "cargo-reproducibility-patch",
    "cargo-source-contract",
    "csdk-corresponding-source",
    "csdk-source-inventory",
    "next-genmodule-patch-series",
    "portable-csdk-archive",
    "portable-csdk-member-inventory",
    "portable-csdk-patch-series",
    "producer-vendor-archive",
    "producer-vendor-inventory",
    "published-source-closure",
    "rust-channel-manifest",
    "rust-src",
    "target-library-contract",
    "target-specification",
    "target-vendor-archive",
];
const REQUIRED_OUTPUTS: &[&str] = &[
    "aros-target-sysroot",
    "artifact-signature",
    "build-provenance",
    "debian-package",
    "debian-package-input",
    "direct-archive",
    "homebrew-formula",
    "homebrew-formula-input",
    "host-file-inventory",
    "host-sdk-tree",
    "portable-csdk-sysroot",
    "release-checksums",
    "release-inventory",
    "release-notices",
    "release-sbom",
    "release-sources",
    "rustup-cargo-component",
    "rustup-channel-checksum",
    "rustup-channel-manifest",
    "rustup-rust-std-component",
    "rustup-rustc-component",
];
const REQUIRED_LICENSES: &[&str] = &[
    "aros-sdk",
    "paired-cargo",
    "producer-vendor",
    "project",
    "project-mit",
    "rust-distribution",
    "target-vendor",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionContract {
    schema: String,
    status: String,
    release_epoch: u64,
    product: Product,
    target: Target,
    toolchain: Toolchain,
    hosts: Vec<Host>,
    inputs: Vec<Input>,
    licenses: Vec<License>,
    outputs: Vec<Output>,
    rules: Rules,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Product {
    name: String,
    version_parameter: String,
    publication_authorized: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    triple: String,
    abi: String,
    baseline: String,
    spec_role: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Toolchain {
    rust_channel: String,
    rust_commit: String,
    rust_llvm: String,
    cargo_version: String,
    cargo_commit: String,
    cargo_patch_required: bool,
    cargo_source_build_in_active_producer: bool,
    cargo_delivery: String,
    rustc_source_build_in_active_producer: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Host {
    key: String,
    rust_triple: String,
    artifact_suffix: String,
    debian_arch: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    role: String,
    hosts: Vec<String>,
    source: Source,
    bytes: u64,
    sha256: String,
    license_ref: String,
    #[serde(default)]
    required_for: Vec<String>,
    archive: Option<ArchiveContract>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    path: Option<String>,
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArchiveContract {
    format: String,
    root: String,
    member_inventory: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct License {
    id: String,
    path: String,
    bytes: u64,
    sha256: String,
    declaration: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Output {
    role: String,
    kind: String,
    path: String,
    hosts: Vec<String>,
    consumers: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Rules {
    network_authority: String,
    local_paths: String,
    versioning: String,
    single_inventory: String,
    absolute_paths_in_outputs: bool,
    second_rust_bootstrap: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberInventory {
    files: Vec<Member>,
    #[serde(default)]
    symlinks: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Member {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Serialize)]
pub struct ProductionContractSummary {
    pub schema: &'static str,
    pub status: &'static str,
    pub manifest_sha256: String,
    pub release_epoch: u64,
    pub hosts: Vec<String>,
    pub inputs: usize,
    pub outputs: usize,
    pub portable_csdk_members: usize,
    pub decision: &'static str,
}

/// One admitted host and its upstream Rust triple.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProductionHost {
    pub key: String,
    pub rust_triple: String,
    pub debian_arch: Option<String>,
}

/// One authenticated producer input selected from the frozen RP1 contract.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProductionInput {
    pub role: String,
    pub repository_path: Option<PathBuf>,
    pub url: Option<String>,
    pub bytes: u64,
    pub sha256: String,
    pub archive_format: Option<String>,
    pub archive_root: Option<String>,
}

/// One output declaration with all contract templates resolved.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProductionOutput {
    pub role: String,
    pub kind: String,
    pub path: String,
    pub consumers: Vec<String>,
}

/// Typed execution view of the verified RP1 contract for one native host.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProductionPlan {
    pub manifest_sha256: String,
    pub release_epoch: u64,
    pub host: ProductionHost,
    pub target_triple: String,
    pub inputs: Vec<ProductionInput>,
    pub outputs: Vec<ProductionOutput>,
}

/// Verify the repository-owned contract without acquiring inputs or writing
/// production output. `manifest_relative` must be a repository-relative path.
pub fn verify_production_contract(
    repository_root: &Path,
    manifest_relative: &Path,
) -> Result<ProductionContractSummary> {
    let manifest_text = manifest_relative
        .to_str()
        .ok_or_else(|| Refusal::new("production contract path must be UTF-8"))?;
    safe_relative(manifest_text, false, "production contract path")?;
    let manifest_path = repository_root.join(manifest_relative);
    let manifest_sha256 = sha256_file(&manifest_path)?;
    let contract: ProductionContract = read_json(&manifest_path, JsonProfile::ProductionContract)?;
    let portable_csdk_members = verify_contract(repository_root, &contract)?;
    let mut hosts = contract
        .hosts
        .iter()
        .map(|host| host.key.clone())
        .collect::<Vec<_>>();
    hosts.sort();
    Ok(ProductionContractSummary {
        schema: SCHEMA,
        status: "VERIFIED_RP1_PRODUCTION_CONTRACT",
        manifest_sha256,
        release_epoch: contract.release_epoch,
        hosts,
        inputs: contract.inputs.len(),
        outputs: contract.outputs.len(),
        portable_csdk_members,
        decision: "contract verification only; production, signing and publication remain disabled",
    })
}

/// Verify the complete frozen contract and select the closed execution view for
/// `host_key`. Repository inputs retain repository-relative paths. Remote inputs
/// are declarations only; callers must acquire and authenticate their bytes
/// before invoking production.
pub fn production_plan(
    repository_root: &Path,
    manifest_relative: &Path,
    host_key: &str,
    version: &str,
) -> Result<ProductionPlan> {
    let manifest_text = manifest_relative
        .to_str()
        .ok_or_else(|| Refusal::new("production contract path must be UTF-8"))?;
    safe_relative(manifest_text, false, "production contract path")?;
    validate_version(version)?;
    let manifest_path = repository_root.join(manifest_relative);
    let manifest_sha256 = sha256_file(&manifest_path)?;
    let contract: ProductionContract = read_json(&manifest_path, JsonProfile::ProductionContract)?;
    verify_contract(repository_root, &contract)?;
    let host = contract
        .hosts
        .iter()
        .find(|host| host.key == host_key)
        .ok_or_else(|| Refusal::new("production host is not declared by the RP1 contract"))?;
    let selected = ProductionHost {
        key: host.key.clone(),
        rust_triple: host.rust_triple.clone(),
        debian_arch: host.debian_arch.clone(),
    };
    let inputs = contract
        .inputs
        .iter()
        .filter(|input| input.hosts.iter().any(|candidate| candidate == host_key))
        .map(|input| ProductionInput {
            role: input.role.clone(),
            repository_path: input.source.path.as_ref().map(PathBuf::from),
            url: input.source.url.clone(),
            bytes: input.bytes,
            sha256: input.sha256.clone(),
            archive_format: input.archive.as_ref().map(|archive| archive.format.clone()),
            archive_root: input.archive.as_ref().map(|archive| archive.root.clone()),
        })
        .collect::<Vec<_>>();
    let outputs = contract
        .outputs
        .iter()
        .filter(|output| {
            output.hosts.is_empty() || output.hosts.iter().any(|host| host == host_key)
        })
        .map(|output| {
            let path = resolve_output_path(
                &output.path,
                version,
                host_key,
                &host.artifact_suffix,
                host.debian_arch.as_deref(),
            )?;
            Ok(ProductionOutput {
                role: output.role.clone(),
                kind: output.kind.clone(),
                path,
                consumers: output.consumers.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(ProductionPlan {
        manifest_sha256,
        release_epoch: contract.release_epoch,
        host: selected,
        target_triple: contract.target.triple,
        inputs,
        outputs,
    })
}

fn validate_version(version: &str) -> Result<()> {
    let mut count = 0_usize;
    for part in version.split('.') {
        count += 1;
        if part.is_empty()
            || (part.len() > 1 && part.starts_with('0'))
            || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(Refusal::new(
                "production version must be a numeric x.y.z version",
            ));
        }
    }
    if count != 3 {
        return Err(Refusal::new(
            "production version must be a numeric x.y.z version",
        ));
    }
    Ok(())
}

fn resolve_output_path(
    template: &str,
    version: &str,
    host: &str,
    artifact: &str,
    debian_arch: Option<&str>,
) -> Result<String> {
    let mut path = template
        .replace("{version}", version)
        .replace("{host}", host)
        .replace("{artifact}", artifact);
    if path.contains("{debian_arch}") {
        let architecture = debian_arch.ok_or_else(|| {
            Refusal::new("host-independent output unexpectedly requires a Debian architecture")
        })?;
        path = path.replace("{debian_arch}", architecture);
    }
    if path.contains('{') || path.contains('}') {
        return Err(Refusal::new(
            "production output retained an unresolved template",
        ));
    }
    safe_relative(&path, false, "resolved production output path")?;
    Ok(path)
}

fn verify_contract(repository_root: &Path, contract: &ProductionContract) -> Result<usize> {
    if contract.schema != SCHEMA || contract.status != STATUS || contract.release_epoch == 0 {
        return Err(Refusal::new(
            "production contract identity is not the frozen RP1 schema",
        ));
    }
    if contract.product.name != "ami-rust"
        || contract.product.version_parameter != "version"
        || contract.product.publication_authorized
    {
        return Err(Refusal::new(
            "production contract product boundary is invalid",
        ));
    }
    if contract.target.triple != "x86_64-aros"
        || contract.target.abi != "AROS ABI-v1"
        || contract.target.baseline.is_empty()
        || contract.target.spec_role != "target-specification"
    {
        return Err(Refusal::new(
            "production contract target boundary is invalid",
        ));
    }
    verify_toolchain(&contract.toolchain)?;
    let known_hosts = verify_hosts(&contract.hosts)?;
    let license_ids = verify_licenses(repository_root, &contract.licenses)?;
    let paths = verify_inputs(
        repository_root,
        &contract.inputs,
        &known_hosts,
        &license_ids,
    )?;
    verify_outputs(&contract.outputs, &known_hosts)?;
    verify_rules(&contract.rules)?;

    let portable = contract
        .inputs
        .iter()
        .find(|input| input.role == "portable-csdk-archive")
        .ok_or_else(|| Refusal::new("production contract omits portable C-SDK archive"))?;
    let archive = portable
        .archive
        .as_ref()
        .ok_or_else(|| Refusal::new("portable C-SDK archive contract is absent"))?;
    if archive.format != "tar.xz" {
        return Err(Refusal::new("portable C-SDK archive format is not tar.xz"));
    }
    let archive_path = portable
        .source
        .path
        .as_ref()
        .ok_or_else(|| Refusal::new("portable C-SDK must be a repository input"))?;
    let inventory_path = archive
        .member_inventory
        .as_ref()
        .ok_or_else(|| Refusal::new("portable C-SDK member inventory is absent"))?;
    if !paths.contains(inventory_path) {
        return Err(Refusal::new(
            "portable C-SDK member inventory is not a declared input",
        ));
    }
    verify_member_inventory(
        &repository_root.join(archive_path),
        &repository_root.join(inventory_path),
        &archive.root,
    )
}

fn verify_toolchain(toolchain: &Toolchain) -> Result<()> {
    if toolchain.rust_channel != "nightly-2026-09-18"
        || !git_identity(&toolchain.rust_commit)
        || toolchain.rust_llvm != "23.1.1"
        || toolchain.cargo_version.is_empty()
        || !git_identity(&toolchain.cargo_commit)
        || !toolchain.cargo_patch_required
        || toolchain.cargo_source_build_in_active_producer
        || toolchain.rustc_source_build_in_active_producer
        || !toolchain.cargo_delivery.contains("authenticated prebuilt")
    {
        return Err(Refusal::new(
            "production toolchain selection is incomplete or inconsistent",
        ));
    }
    Ok(())
}

fn verify_hosts(hosts: &[Host]) -> Result<BTreeSet<String>> {
    let expected = HOSTS
        .iter()
        .map(|(key, triple, arch)| {
            (
                (*key).to_owned(),
                ((*triple).to_owned(), arch.map(str::to_owned)),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut actual = BTreeMap::new();
    for host in hosts {
        if host.artifact_suffix != host.key
            || actual
                .insert(
                    host.key.clone(),
                    (host.rust_triple.clone(), host.debian_arch.clone()),
                )
                .is_some()
        {
            return Err(Refusal::new(
                "production contract has a duplicate or mismatched host",
            ));
        }
    }
    if actual != expected {
        return Err(Refusal::new(
            "production contract host matrix differs from RP1",
        ));
    }
    Ok(actual.into_keys().collect())
}

fn verify_licenses(repository_root: &Path, rows: &[License]) -> Result<BTreeSet<String>> {
    let mut ids = BTreeSet::new();
    for row in rows {
        if row.id.is_empty() || !ids.insert(row.id.clone()) || row.declaration.is_empty() {
            return Err(Refusal::new(
                "production contract licence record is invalid",
            ));
        }
        verify_local_file(
            repository_root,
            &row.path,
            row.bytes,
            &row.sha256,
            "licence record",
        )?;
    }
    for id in REQUIRED_LICENSES {
        if !ids.contains(*id) {
            return Err(Refusal::new(format!(
                "production contract omits required licence record {id}"
            )));
        }
    }
    Ok(ids)
}

fn verify_inputs(
    repository_root: &Path,
    inputs: &[Input],
    known_hosts: &BTreeSet<String>,
    license_ids: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    let mut roles = BTreeSet::new();
    let mut local_paths = BTreeSet::new();
    for input in inputs {
        if input.role.is_empty()
            || !roles.insert(input.role.clone())
            || input.bytes == 0
            || !is_sha256_digest(&input.sha256)
        {
            return Err(Refusal::new("production input role or identity is invalid"));
        }
        verify_host_scope(&input.hosts, known_hosts, "production input")?;
        if !license_ids.contains(&input.license_ref) {
            return Err(Refusal::new(
                "production input references an unknown licence record",
            ));
        }
        let location_count =
            input.source.path.is_some() as usize + input.source.url.is_some() as usize;
        if location_count != 1 {
            return Err(Refusal::new(
                "production input must have exactly one path or URL",
            ));
        }
        if let Some(path) = &input.source.path {
            verify_local_file(
                repository_root,
                path,
                input.bytes,
                &input.sha256,
                "production input",
            )?;
            if !local_paths.insert(path.clone()) {
                return Err(Refusal::new(
                    "production input path is declared more than once",
                ));
            }
        }
        if let Some(url) = &input.source.url
            && (!url.starts_with("https://") || url.bytes().any(|byte| byte.is_ascii_whitespace()))
        {
            return Err(Refusal::new("production input URL is not an HTTPS URL"));
        }
        let mut purposes = BTreeSet::new();
        if input
            .required_for
            .iter()
            .any(|purpose| purpose.is_empty() || !purposes.insert(purpose))
        {
            return Err(Refusal::new("production input purpose list is invalid"));
        }
        if let Some(archive) = &input.archive {
            if !["tar.xz", "tar.gz"].contains(&archive.format.as_str()) {
                return Err(Refusal::new(
                    "production input archive format is unsupported",
                ));
            }
            safe_relative(&archive.root, false, "archive root")?;
            if archive.root.contains('/') {
                return Err(Refusal::new(
                    "production input archive root must be one directory",
                ));
            }
            if let Some(path) = &archive.member_inventory {
                safe_relative(path, false, "archive member inventory")?;
            }
        }
    }
    for role in REQUIRED_INPUTS {
        if !roles.contains(*role) {
            return Err(Refusal::new(format!(
                "production contract omits required input role {role}"
            )));
        }
    }
    for host in known_hosts {
        for prefix in [
            "rustc",
            "host-rust-std",
            "upstream-cargo",
            "paired-cargo",
            "native-link-tools",
            "collector",
        ] {
            let role = format!("{prefix}-{host}");
            if !roles.contains(&role) {
                return Err(Refusal::new(format!(
                    "production contract omits host input role {role}"
                )));
            }
        }
    }
    Ok(local_paths)
}

fn verify_outputs(outputs: &[Output], known_hosts: &BTreeSet<String>) -> Result<()> {
    let mut roles = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for output in outputs {
        if output.role.is_empty()
            || output.kind.is_empty()
            || !roles.insert(output.role.clone())
            || !paths.insert(output.path.clone())
            || output.consumers.is_empty()
        {
            return Err(Refusal::new(
                "production output inventory has a duplicate or empty field",
            ));
        }
        safe_relative(&output.path, true, "production output path")?;
        verify_host_scope_allow_global(&output.hosts, known_hosts, "production output")?;
        let mut consumers = BTreeSet::new();
        if output
            .consumers
            .iter()
            .any(|consumer| consumer.is_empty() || !consumers.insert(consumer))
        {
            return Err(Refusal::new("production output consumer list is invalid"));
        }
    }
    for role in REQUIRED_OUTPUTS {
        if !roles.contains(*role) {
            return Err(Refusal::new(format!(
                "production contract omits required output role {role}"
            )));
        }
    }
    Ok(())
}

fn verify_rules(rules: &Rules) -> Result<()> {
    if rules.network_authority != "acquisition only; Rust producer is offline"
        || rules.local_paths != "repository-relative UTF-8 paths only"
        || !rules
            .versioning
            .contains("same-channel mutation prohibited")
        || !rules
            .single_inventory
            .contains("channel-specific reconstruction is prohibited")
        || rules.absolute_paths_in_outputs
        || rules.second_rust_bootstrap
    {
        return Err(Refusal::new(
            "production contract execution rules are invalid",
        ));
    }
    Ok(())
}

fn verify_local_file(
    repository_root: &Path,
    relative: &str,
    expected_bytes: u64,
    expected_sha256: &str,
    label: &str,
) -> Result<()> {
    safe_relative(relative, false, label)?;
    if !is_sha256_digest(expected_sha256) {
        return Err(Refusal::new(format!("{label} SHA-256 is malformed")));
    }
    let path = repository_root.join(relative);
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_file() || metadata.len() != expected_bytes {
        return Err(Refusal::new(format!(
            "{label} size or type differs from its contract"
        )));
    }
    if sha256_file(&path)? != expected_sha256 {
        return Err(Refusal::new(format!(
            "{label} digest differs from its contract"
        )));
    }
    Ok(())
}

fn verify_host_scope(hosts: &[String], known: &BTreeSet<String>, label: &str) -> Result<()> {
    if hosts.is_empty() {
        return Err(Refusal::new(format!("{label} host scope is empty")));
    }
    verify_host_scope_allow_global(hosts, known, label)
}

fn verify_host_scope_allow_global(
    hosts: &[String],
    known: &BTreeSet<String>,
    label: &str,
) -> Result<()> {
    let mut actual = BTreeSet::new();
    if hosts
        .iter()
        .any(|host| !known.contains(host) || !actual.insert(host))
    {
        return Err(Refusal::new(format!("{label} host scope is invalid")));
    }
    Ok(())
}

fn safe_relative(value: &str, templates: bool, label: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('/')
        || value.contains('\\')
        || value.contains('\0')
        || value.contains(':')
    {
        return Err(Refusal::new(format!("{label} is not a safe relative path")));
    }
    for component in value.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(Refusal::new(format!("{label} is not a safe relative path")));
        }
        if !templates && (component.contains('{') || component.contains('}')) {
            return Err(Refusal::new(format!(
                "{label} unexpectedly contains a template"
            )));
        }
    }
    if templates {
        let mut rest = value;
        loop {
            if let Some(end) = rest.find('}')
                && rest.find('{').is_none_or(|start| end < start)
            {
                return Err(Refusal::new(format!(
                    "{label} has an unmatched template terminator"
                )));
            }
            let Some(start) = rest.find('{') else {
                break;
            };
            let after = &rest[start + 1..];
            let end = after
                .find('}')
                .ok_or_else(|| Refusal::new(format!("{label} has an incomplete template")))?;
            if !["artifact", "debian_arch", "host", "version"].contains(&&after[..end]) {
                return Err(Refusal::new(format!("{label} has an unknown template")));
            }
            rest = &after[end + 1..];
        }
    }
    Ok(())
}

fn git_identity(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn verify_member_inventory(
    archive_path: &Path,
    inventory_path: &Path,
    root: &str,
) -> Result<usize> {
    let inventory: MemberInventory = read_json(inventory_path, JsonProfile::SdkComponentManifest)?;
    if !inventory.symlinks.is_empty() || inventory.files.is_empty() {
        return Err(Refusal::new(
            "portable C-SDK inventory must contain only regular files",
        ));
    }
    let mut expected = BTreeMap::new();
    for member in inventory.files {
        safe_relative(&member.path, false, "portable C-SDK inventory member")?;
        if member.bytes == 0
            || !is_sha256_digest(&member.sha256)
            || expected
                .insert(member.path, (member.bytes, member.sha256))
                .is_some()
        {
            return Err(Refusal::new(
                "portable C-SDK inventory has an invalid or duplicate member",
            ));
        }
    }
    let expected_count = expected.len();
    let input = File::open(archive_path)?;
    let decoder = XzReader::new_mem_limit(input, true, 64 * 1024);
    let mut archive = Archive::new(decoder);
    for entry in archive
        .entries()
        .map_err(|error| Refusal::new(format!("could not read portable C-SDK archive: {error}")))?
    {
        let mut entry = entry.map_err(|error| {
            Refusal::new(format!("could not read portable C-SDK member: {error}"))
        })?;
        if !entry.header().entry_type().is_file() {
            return Err(Refusal::new(
                "portable C-SDK archive has an undeclared non-file member",
            ));
        }
        let raw = entry.path_bytes();
        let path = std::str::from_utf8(raw.as_ref())
            .map_err(|_| Refusal::new("portable C-SDK member path is not UTF-8"))?;
        safe_relative(path, false, "portable C-SDK archive member")?;
        let prefix = format!("{root}/");
        let relative = path
            .strip_prefix(&prefix)
            .ok_or_else(|| Refusal::new("portable C-SDK member escapes its declared root"))?;
        safe_relative(relative, false, "portable C-SDK archive member")?;
        let (bytes, sha256) = expected
            .remove(relative)
            .ok_or_else(|| Refusal::new("portable C-SDK archive contains an undeclared member"))?;
        let mut count = 0_u64;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = match entry.read(&mut buffer) {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            if read == 0 {
                break;
            }
            count = count
                .checked_add(read as u64)
                .ok_or_else(|| Refusal::new("portable C-SDK member size overflow"))?;
            if count > bytes {
                return Err(Refusal::new(
                    "portable C-SDK member exceeds its declared size",
                ));
            }
            digest.update(&buffer[..read]);
        }
        let actual: [u8; 32] = digest.finalize().into();
        if count != bytes || crate::digest::encode_hex(&actual) != sha256 {
            return Err(Refusal::new(
                "portable C-SDK member differs from its inventory",
            ));
        }
    }
    if !expected.is_empty() {
        return Err(Refusal::new(
            "portable C-SDK archive omits declared members",
        ));
    }
    Ok(expected_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::sha256_bytes;
    use lzma_rust2::{XzOptions, XzWriter};
    use std::{
        fs,
        io::Write,
        sync::atomic::{AtomicU64, Ordering},
    };
    use tar::{Builder, Header};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn repository_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()
            .expect("repository root must resolve")
    }

    #[test]
    #[ignore = "requires the complete RP1 repository input closure"]
    fn accepts_the_real_rp1_contract() {
        let summary = verify_production_contract(
            &repository_root(),
            Path::new("release/rust-production-contract.json"),
        )
        .expect("real RP1 contract must pass");
        assert_eq!(
            summary.manifest_sha256,
            "69fd8e053552bf76c78f794f6f25d17179ba2d4855343662965b41301326396c"
        );
        assert_eq!(summary.inputs, 36);
        assert_eq!(summary.outputs, 21);
        assert_eq!(summary.portable_csdk_members, 2835);
        assert_eq!(summary.hosts.len(), 3);
    }

    #[test]
    #[ignore = "requires the complete RP1 repository input closure"]
    fn refuses_one_altered_repository_digest() {
        let root = repository_root();
        let mut contract: ProductionContract = read_json(
            &root.join("release/rust-production-contract.json"),
            JsonProfile::ProductionContract,
        )
        .unwrap();
        contract
            .inputs
            .iter_mut()
            .find(|input| input.role == "target-specification")
            .unwrap()
            .sha256 = "0".repeat(64);
        assert!(verify_contract(&root, &contract).is_err());
    }

    #[test]
    fn refuses_an_undeclared_member_and_an_escaping_path() {
        let root = std::env::temp_dir().join(format!(
            "ami-rust-rp1-contract-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let good = b"declared\n";
        let inventory = serde_json::json!({
            "files":[{"path":"good.txt","bytes":good.len(),"sha256":sha256_bytes(good)}],
            "symlinks":[]
        });
        fs::write(
            root.join("inventory.json"),
            serde_json::to_vec(&inventory).unwrap(),
        )
        .unwrap();

        let undeclared = xz_tar(
            &[
                ("Developer/good.txt", good),
                ("Developer/extra.txt", b"extra\n"),
            ],
            false,
        );
        fs::write(root.join("undeclared.tar.xz"), undeclared).unwrap();
        assert!(
            verify_member_inventory(
                &root.join("undeclared.tar.xz"),
                &root.join("inventory.json"),
                "Developer"
            )
            .is_err()
        );

        let escaping = xz_tar(&[("Developer/good.txt", good)], true);
        fs::write(root.join("escaping.tar.xz"), escaping).unwrap();
        assert!(
            verify_member_inventory(
                &root.join("escaping.tar.xz"),
                &root.join("inventory.json"),
                "Developer"
            )
            .is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn xz_tar(members: &[(&str, &[u8])], escape: bool) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        for (path, contents) in members {
            let mut header = Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(1793095486);
            header.set_cksum();
            builder.append_data(&mut header, path, *contents).unwrap();
        }
        if escape {
            let contents = b"escape\n";
            let mut header = Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(1793095486);
            let bytes = header.as_mut_bytes();
            bytes[..100].fill(0);
            bytes[..9].copy_from_slice(b"../escape");
            header.set_cksum();
            builder.append(&header, contents.as_slice()).unwrap();
        }
        let tar = builder.into_inner().unwrap();
        let mut encoder = XzWriter::new(Vec::new(), XzOptions::with_preset(1)).unwrap();
        encoder.write_all(&tar).unwrap();
        encoder.finish().unwrap()
    }
}
