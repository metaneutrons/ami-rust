//! Read-only inspection and side-by-side migration of historical project locks.
//!
//! A legacy lock binds a Python-based SDK identity. It is parsed as inert data;
//! no path from that record is executed. Migration is admitted only when its
//! target compiler and all six local component inventories match the immutable
//! initial baseline and a separately receipt-pinned native installation.

use crate::{
    Refusal, Result,
    baseline::InitialBaseline,
    digest::{is_sha256_digest, sha256_bytes},
    directory::{Directory, EntryType},
    files::validate_relative_inventory_path,
    inventory::{FileIdentity, InventoryLimits, LinkIdentity, verify_complete_directory_checked},
    json::{JsonProfile, parse_json_value},
    native_install::CheckedNativeInstallation,
    native_project::ProjectLockResult,
    ownership,
    records::{Host, SelectionV2, parse_selection},
    selected_inputs::verify_selection,
    signals::SigtermGuard,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, Metadata},
    io::{self, Read},
    os::unix::fs::MetadataExt,
    path::{Component, Path, PathBuf},
};

const LEGACY_LOCK_SCHEMA: &str = "ami-rust-project-lock-v1";
const LEGACY_SDK_SCHEMA: &str = "ami-rust-sdk-v1";
const LEGACY_BINDING_SCHEMA: &str = "ami-rust-project-sdk-binding-v1";
const LEGACY_CARGO_METADATA_MODE: &str = "ami-rust-reproducible-cross-v1";
const COMPONENT_NAMES: [&str; 6] = ["rust", "cargo", "toolchain", "collector", "csdk", "vendor"];
const INVENTORY_LIMITS: InventoryLimits = InventoryLimits {
    max_tree_entries: 100_000,
    max_link_resolution_steps: 100_000,
};

/// Result of validating an old project lock without changing the filesystem.
#[derive(Clone, Debug, Serialize)]
pub struct MigrationReport {
    pub status: &'static str,
    pub project: String,
    pub legacy_lock: LegacyLockIdentity,
    pub legacy_sdk: LegacySdkIdentity,
    pub legacy_python: LegacyPythonIdentity,
    pub compiler: CompilerIdentity,
    pub host: Host,
    pub cargo: CargoIdentity,
    pub components: Vec<ComponentIdentity>,
    /// Legacy project locks embed all six roots. There is no sidecar selection
    /// file to locate or migrate for this supported record version.
    pub selection_missing: bool,
    pub selection_source: &'static str,
    pub migration_required: bool,
    pub claim: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct LegacyLockIdentity {
    pub path: String,
    pub schema: &'static str,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct LegacySdkIdentity {
    pub root: String,
    pub version: String,
    pub manifest: String,
    pub manifest_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompilerIdentity {
    pub rust_commit: String,
    pub rust_llvm: String,
    pub source_date_epoch: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CargoIdentity {
    pub manifest_sha256: String,
    pub lock_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct LegacyPythonIdentity {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ComponentIdentity {
    pub name: String,
    pub root: String,
    pub manifest: String,
    pub manifest_sha256: String,
}

/// Result of creating a separate native v2 project lock.
#[derive(Clone, Debug, Serialize)]
pub struct MigrationWriteResult {
    pub status: &'static str,
    pub output: String,
    pub legacy_lock_sha256: String,
    pub legacy_sdk: LegacySdkIdentity,
    pub legacy_python: LegacyPythonIdentity,
    pub sdk_version: String,
    pub sdk_manifest_sha256: String,
    pub receipt_sha256: String,
    pub compiler: CompilerIdentity,
    pub host: Host,
    pub cargo: CargoIdentity,
    pub claim: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyProjectLockV1 {
    #[serde(rename = "schema")]
    _schema: String,
    sdk: LegacyLockSdk,
    host: LegacyLockHost,
    components: LegacyProjectComponents,
    cargo: LegacyCargoIdentity,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyProjectSdkBindingV1 {
    schema: String,
    version: String,
    sdk_manifest_sha256: crate::records::Sha256,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyLockSdk {
    root: PathBuf,
    manifest: String,
    manifest_sha256: crate::records::Sha256,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyLockHost {
    platform: Host,
    python: PathBuf,
    python_sha256: crate::records::Sha256,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyProjectComponents {
    rust: PathBuf,
    cargo: PathBuf,
    toolchain: PathBuf,
    collector: PathBuf,
    csdk: PathBuf,
    vendor: PathBuf,
}

impl LegacyProjectComponents {
    fn entries(&self) -> [(&'static str, &Path); 6] {
        [
            ("rust", &self.rust),
            ("cargo", &self.cargo),
            ("toolchain", &self.toolchain),
            ("collector", &self.collector),
            ("csdk", &self.csdk),
            ("vendor", &self.vendor),
        ]
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyCargoIdentity {
    manifest_sha256: crate::records::Sha256,
    lock_sha256: crate::records::Sha256,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacySdkManifestV1 {
    #[serde(rename = "schema")]
    _schema: String,
    version: String,
    rust_commit: String,
    rust_llvm: String,
    source_date_epoch: u64,
    files: Vec<FileIdentity>,
    #[serde(default)]
    symlinks: Vec<LinkIdentity>,
    profiles: BTreeMap<String, LegacySdkProfile>,
    // These fields existed in historical host SDK records. They are accepted
    // as descriptive metadata and are never used as authorization or commands.
    #[serde(default)]
    source_identity: Option<String>,
    #[serde(default)]
    qualification_only: Option<bool>,
    #[serde(default)]
    development_only: Option<bool>,
    #[serde(default)]
    driver: Option<String>,
    #[serde(default)]
    budgets: Option<Map<String, Value>>,
    #[serde(default)]
    packaging: Option<Map<String, Value>>,
    #[serde(default)]
    runtime_memory_policy: Option<Map<String, Value>>,
    #[serde(default)]
    host_capacity: Option<Map<String, Value>>,
    #[serde(default)]
    hosted_cargo: Option<Map<String, Value>>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacySdkProfile {
    cargo_binary: String,
    cargo_metadata_mode: String,
    components: BTreeMap<String, LegacyComponentManifestRef>,
    #[serde(default)]
    rust_host: Option<String>,
    #[serde(default)]
    collector_binary: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyComponentManifestRef {
    manifest: String,
    sha256: crate::records::Sha256,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyComponentInventory {
    files: Vec<FileIdentity>,
    #[serde(default)]
    symlinks: Vec<LinkIdentity>,
    // Retained opaque producer metadata is inert and is already bound by the
    // manifest digest in the old SDK profile.
    #[serde(default, rename = "producer_identity_spec")]
    _producer_identity_spec: Option<Map<String, Value>>,
}

struct ValidatedLegacyProject {
    project: PathBuf,
    lock_path: PathBuf,
    lock_sha256: String,
    sdk: LegacySdkIdentity,
    python: LegacyPythonIdentity,
    compiler: CompilerIdentity,
    host: Host,
    cargo: CargoIdentity,
    component_roots: BTreeMap<String, PathBuf>,
    component_manifests: BTreeMap<String, (String, String)>,
    binding: Option<Vec<u8>>,
}

/// Inspect the conventional `ami-rust.lock.json` in a project directory.
///
/// All old identities are read as data. In particular, the recorded Python
/// executable is hashed but never launched.
pub fn dry_run(project: &Path, signals: &SigtermGuard) -> Result<MigrationReport> {
    let project_path = absolute_lexical(project, &std::env::current_dir()?)?;
    let lock_path = project_path.join("ami-rust.lock.json");
    let legacy = validate_legacy_project(&project_path, &lock_path, signals)?;
    Ok(report(&legacy))
}

/// Validate a legacy v1 lock and write a separate native v2 lock.
///
/// `receipt_sha256` is the digest supplied from outside the new installation.
/// This establishes local pin consistency only; it does not recreate fresh
/// publisher authentication or R1 qualification.
pub fn migrate(
    project: &Path,
    from_lock: &Path,
    install_prefix: &Path,
    receipt_sha256: &str,
    output: &Path,
    signals: &SigtermGuard,
) -> Result<MigrationWriteResult> {
    signals.check()?;
    if !is_sha256_digest(receipt_sha256) {
        return Err(Refusal::new(
            "native installation receipt pin must be 64 lowercase SHA-256 hex characters",
        ));
    }

    let project_path = absolute_lexical(project, &std::env::current_dir()?)?;
    let old_lock_path = absolute_lexical(from_lock, &std::env::current_dir()?)?;
    let legacy = validate_legacy_project(&project_path, &old_lock_path, signals)?;
    let installation = CheckedNativeInstallation::open(install_prefix, receipt_sha256)?;
    let host = Host::current()?;
    let recipe = InitialBaseline::load()?.admit_initial_sdk(&installation, host)?;

    if legacy.compiler.rust_commit != recipe.rust_commit
        || legacy.compiler.rust_llvm != recipe.rust_llvm
        || legacy.compiler.source_date_epoch != recipe.source_date_epoch
    {
        return Err(Refusal::new(
            "legacy project compiler or source epoch differs from the immutable native baseline; migration is unsupported",
        ));
    }
    for name in COMPONENT_NAMES {
        let old = legacy
            .component_manifests
            .get(name)
            .ok_or_else(|| Refusal::new("legacy SDK omits a component inventory"))?;
        let current = recipe
            .component_manifests
            .get(name)
            .ok_or_else(|| Refusal::new("native SDK omits a component inventory"))?;
        if old != current {
            return Err(Refusal::new(format!(
                "legacy {name} component inventory differs from the immutable native baseline; migration is unsupported"
            )));
        }
    }

    let selection = selection_from_legacy(&legacy, &installation, host)?;
    // lock_project repeats the installation, baseline, selection, Cargo and
    // output checks immediately before its exclusive atomic publication.
    let output_target = ownership::fresh_output(output)?;
    for protected in legacy
        .component_roots
        .values()
        .map(PathBuf::as_path)
        .chain(std::iter::once(Path::new(&legacy.sdk.root)))
    {
        ownership::require_disjoint(
            output_target.path(),
            protected,
            "migration output overlaps a legacy SDK or selected component",
        )?;
    }

    // Revalidate all legacy pins immediately before invoking the shared writer.
    // The existing lock writer independently rechecks Cargo and native inputs.
    let final_legacy = validate_legacy_project(&project_path, &old_lock_path, signals)?;
    if legacy.lock_sha256 != final_legacy.lock_sha256
        || legacy.cargo.manifest_sha256 != final_legacy.cargo.manifest_sha256
        || legacy.cargo.lock_sha256 != final_legacy.cargo.lock_sha256
        || legacy.sdk.manifest_sha256 != final_legacy.sdk.manifest_sha256
        || legacy.component_manifests != final_legacy.component_manifests
        || legacy.binding != final_legacy.binding
    {
        return Err(Refusal::new(
            "legacy project inputs changed during migration validation",
        ));
    }
    signals.check()?;
    let written = crate::native_project::lock_project_for_migration(
        &installation,
        &selection,
        &project_path,
        output,
        legacy.binding.as_deref(),
        signals,
    )?;
    Ok(write_result(legacy, written, &installation, recipe.version))
}

fn report(legacy: &ValidatedLegacyProject) -> MigrationReport {
    MigrationReport {
        status: "migration-required",
        project: path_text(&legacy.project)
            .unwrap_or_else(|_| legacy.project.display().to_string()),
        legacy_lock: LegacyLockIdentity {
            path: path_text(&legacy.lock_path)
                .unwrap_or_else(|_| legacy.lock_path.display().to_string()),
            schema: LEGACY_LOCK_SCHEMA,
            sha256: legacy.lock_sha256.clone(),
        },
        legacy_sdk: legacy.sdk.clone(),
        legacy_python: legacy.python.clone(),
        compiler: legacy.compiler.clone(),
        host: legacy.host,
        cargo: legacy.cargo.clone(),
        components: COMPONENT_NAMES
            .iter()
            .filter_map(|name| {
                let root = legacy.component_roots.get(*name)?;
                let (manifest, manifest_sha256) = legacy.component_manifests.get(*name)?;
                Some(ComponentIdentity {
                    name: (*name).to_owned(),
                    root: root.display().to_string(),
                    manifest: manifest.clone(),
                    manifest_sha256: manifest_sha256.clone(),
                })
            })
            .collect(),
        selection_missing: false,
        selection_source: "components embedded in ami-rust-project-lock-v1",
        migration_required: true,
        claim: "legacy project identities are internally consistent; Python-bound legacy CLI identity remains and publisher trust/R1 qualification are not established",
    }
}

fn write_result(
    legacy: ValidatedLegacyProject,
    written: ProjectLockResult,
    installation: &CheckedNativeInstallation,
    sdk_version: String,
) -> MigrationWriteResult {
    MigrationWriteResult {
        status: "migrated",
        output: written.output,
        legacy_lock_sha256: legacy.lock_sha256,
        legacy_sdk: legacy.sdk,
        legacy_python: legacy.python,
        sdk_version,
        sdk_manifest_sha256: written.sdk_manifest_sha256,
        receipt_sha256: installation.receipt_digest().to_owned(),
        compiler: legacy.compiler,
        host: written.host,
        cargo: legacy.cargo,
        claim: "new project lock pins the externally receipt-checked native SDK, immutable compiler baseline, identical local component inventories and current Cargo files; this does not independently reauthenticate publisher trust or establish R1 qualification",
    }
}

fn validate_legacy_project(
    project: &Path,
    lock_path: &Path,
    signals: &SigtermGuard,
) -> Result<ValidatedLegacyProject> {
    signals.check()?;
    let project = canonical_directory(project, &std::env::current_dir()?, "project directory")?;
    let project_root = ownership::protected_directory(&project)?;
    let project_uid = project_root.metadata()?.uid();
    let lock_path = absolute_lexical(lock_path, &std::env::current_dir()?)?;
    let lock_parent_path = lock_path
        .parent()
        .ok_or_else(|| Refusal::new("legacy lock has no parent directory"))?;
    let lock_parent = canonical_directory(
        lock_parent_path,
        &std::env::current_dir()?,
        "legacy lock parent",
    )?;
    let lock_parent_dir = ownership::protected_directory(&lock_parent)?;
    let lock_uid = lock_parent_dir.metadata()?.uid();
    let lock_leaf = lock_path
        .file_name()
        .ok_or_else(|| Refusal::new("legacy lock path must name a file"))?;
    let lock_bytes = read_regular_at(
        &lock_parent_dir,
        lock_leaf,
        JsonProfile::ProjectLock.max_bytes(),
        Some(lock_uid),
        signals,
    )?;
    let lock_sha256 = sha256_bytes(&lock_bytes);
    let lock = parse_legacy_lock(&lock_bytes)?;
    let host = Host::current()?;
    if lock.host.platform != host {
        return Err(Refusal::new(
            "legacy project lock host does not match this host",
        ));
    }

    let sdk_root = canonical_directory(&lock.sdk.root, &lock_parent, "legacy SDK root")?;
    let sdk_directory = ownership::protected_directory(&sdk_root)?;
    let sdk_uid = sdk_directory.metadata()?.uid();
    validate_relative_inventory_path(&lock.sdk.manifest)?;
    let sdk_manifest_raw = read_relative_regular(
        &sdk_root,
        &sdk_directory,
        &lock.sdk.manifest,
        JsonProfile::SdkComponentManifest.max_bytes(),
        Some(sdk_uid),
        signals,
    )?;
    let legacy_sdk_manifest_sha256 = sha256_bytes(&sdk_manifest_raw);
    if legacy_sdk_manifest_sha256 != lock.sdk.manifest_sha256.as_str() {
        return Err(Refusal::new("legacy SDK manifest identity mismatch"));
    }
    let manifest = parse_legacy_sdk_manifest(&sdk_manifest_raw)?;
    let profile = manifest
        .profiles
        .get(host_name(host))
        .ok_or_else(|| Refusal::new("legacy SDK omits the current host profile"))?;
    if profile.cargo_metadata_mode != LEGACY_CARGO_METADATA_MODE {
        return Err(Refusal::new(
            "legacy SDK uses an unsupported Cargo metadata mode",
        ));
    }
    if profile
        .rust_host
        .as_deref()
        .is_some_and(|target| target != target_name(host))
    {
        return Err(Refusal::new(
            "legacy SDK host profile targets a different Rust host",
        ));
    }
    if profile
        .components
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != COMPONENT_NAMES.into_iter().collect::<BTreeSet<_>>()
    {
        return Err(Refusal::new(
            "legacy SDK profile must bind exactly the six supported components",
        ));
    }
    validate_relative_inventory_path(&profile.cargo_binary)?;
    if let Some(path) = &profile.collector_binary {
        validate_relative_inventory_path(path)?;
    }

    let binding = read_legacy_binding(
        &project,
        &project_root,
        project_uid,
        &manifest,
        &lock.sdk,
        signals,
    )?;

    // Include the manifest itself when validating the old SDK tree. Historical
    // SDK manifests omit their own digest from their file list by construction.
    let mut sdk_files = manifest.files.clone();
    if sdk_files.iter().any(|row| row.path == lock.sdk.manifest) {
        return Err(Refusal::new(
            "legacy SDK inventory has a self-referential manifest entry",
        ));
    }
    sdk_files.push(FileIdentity {
        path: lock.sdk.manifest.clone(),
        bytes: sdk_manifest_raw.len() as u64,
        sha256: legacy_sdk_manifest_sha256.clone(),
        mode: None,
    });
    verify_complete_directory_checked(
        &sdk_directory,
        &sdk_files,
        &manifest.symlinks,
        INVENTORY_LIMITS,
        || signals.check(),
    )?;

    let mut component_roots = BTreeMap::<String, PathBuf>::new();
    let mut root_handles = BTreeMap::<String, (PathBuf, Directory)>::new();
    for (name, root_value) in lock.components.entries() {
        let root = canonical_directory(root_value, &lock_parent, "legacy component root")?;
        let directory = ownership::protected_directory(&root)?;
        ownership::require_disjoint(&root, &sdk_root, "legacy component root overlaps the SDK")?;
        for prior in component_roots.values() {
            let prior: &PathBuf = prior;
            ownership::require_disjoint(&root, prior, "legacy component roots overlap")?;
            let prior_directory = root_handles
                .values()
                .find_map(|(path, dir): &(PathBuf, Directory)| (path == prior).then_some(dir))
                .ok_or_else(|| Refusal::new("legacy component root identity is missing"))?;
            let before = prior_directory.metadata()?;
            let after = directory.metadata()?;
            if before.dev() == after.dev() && before.ino() == after.ino() {
                return Err(Refusal::new(
                    "legacy component roots alias the same directory",
                ));
            }
        }

        let manifest_ref = profile
            .components
            .get(name)
            .ok_or_else(|| Refusal::new("legacy SDK omits a component manifest"))?;
        validate_relative_inventory_path(&manifest_ref.manifest)?;
        let inventory_raw = read_relative_regular(
            &sdk_root,
            &sdk_directory,
            &manifest_ref.manifest,
            JsonProfile::SdkComponentManifest.max_bytes(),
            Some(sdk_uid),
            signals,
        )?;
        if sha256_bytes(&inventory_raw) != manifest_ref.sha256.as_str() {
            return Err(Refusal::new(format!(
                "legacy {name} component manifest identity mismatch"
            )));
        }
        let inventory = parse_component_inventory(&inventory_raw)?;
        verify_complete_directory_checked(
            &directory,
            &inventory.files,
            &inventory.symlinks,
            INVENTORY_LIMITS,
            || signals.check(),
        )?;

        component_roots.insert(name.to_owned(), root.clone());
        root_handles.insert(name.to_owned(), (root, directory));
    }

    let cargo_binary = component_roots
        .get("cargo")
        .ok_or_else(|| Refusal::new("legacy Cargo component root is missing"))?
        .join(&profile.cargo_binary);
    let _cargo_executable = ownership::protected_regular_file(&cargo_binary, true)?;
    let python_path = canonical_file(&lock.host.python, "legacy Python identity")?;
    let (_, python_sha256) =
        hash_protected_file(&python_path, true, None, signals, "legacy Python identity")?;
    if python_sha256 != lock.host.python_sha256.as_str() {
        return Err(Refusal::new("legacy Python identity changed"));
    }
    let python = LegacyPythonIdentity {
        path: path_text(&python_path)?,
        sha256: python_sha256,
    };

    let cargo_manifest = project.join("Cargo.toml");
    let cargo_lock = project.join("Cargo.lock");
    let (manifest_bytes, cargo_manifest_sha256) = hash_protected_file(
        &cargo_manifest,
        false,
        Some(project_uid),
        signals,
        "project Cargo.toml",
    )?;
    let (lock_bytes, cargo_lock_sha256) = hash_protected_file(
        &cargo_lock,
        false,
        Some(project_uid),
        signals,
        "project Cargo.lock",
    )?;
    if cargo_manifest_sha256 != lock.cargo.manifest_sha256.as_str()
        || cargo_lock_sha256 != lock.cargo.lock_sha256.as_str()
    {
        return Err(Refusal::new(
            "project Cargo.toml or Cargo.lock identity differs from the legacy lock",
        ));
    }
    // Keep lengths checked while streaming, even though only the hashes enter
    // the report. These values also make a replaced/growing file detectable.
    let _ = (manifest_bytes, lock_bytes);

    let component_manifests = profile
        .components
        .iter()
        .map(|(name, row)| {
            (
                name.clone(),
                (row.manifest.clone(), row.sha256.as_str().to_owned()),
            )
        })
        .collect();
    let sdk_version = manifest.version.clone();
    let compiler = CompilerIdentity {
        rust_commit: manifest.rust_commit.clone(),
        rust_llvm: manifest.rust_llvm.clone(),
        source_date_epoch: manifest.source_date_epoch,
    };

    signals.check()?;
    Ok(ValidatedLegacyProject {
        project: project.clone(),
        lock_path,
        lock_sha256,
        sdk: LegacySdkIdentity {
            root: path_text(&sdk_root)?,
            version: sdk_version,
            manifest: lock.sdk.manifest,
            manifest_sha256: legacy_sdk_manifest_sha256,
        },
        python,
        compiler,
        host,
        cargo: CargoIdentity {
            manifest_sha256: cargo_manifest_sha256,
            lock_sha256: cargo_lock_sha256,
        },
        component_roots,
        component_manifests,
        binding,
    })
}

fn parse_legacy_lock(raw: &[u8]) -> Result<LegacyProjectLockV1> {
    let value = parse_json_value(raw, JsonProfile::ProjectLock)?;
    let schema = value
        .as_object()
        .and_then(|object| object.get("schema"))
        .and_then(Value::as_str);
    if schema != Some(LEGACY_LOCK_SCHEMA) {
        return Err(Refusal::new(
            "unsupported, missing, or future project lock schema; expected ami-rust-project-lock-v1",
        ));
    }
    let lock: LegacyProjectLockV1 = serde::Deserialize::deserialize(value)
        .map_err(|error| Refusal::new(format!("invalid legacy project lock: {error}")))?;
    Ok(lock)
}

fn parse_legacy_sdk_manifest(raw: &[u8]) -> Result<LegacySdkManifestV1> {
    let value = parse_json_value(raw, JsonProfile::SdkComponentManifest)?;
    let schema = value
        .as_object()
        .and_then(|object| object.get("schema"))
        .and_then(Value::as_str);
    if schema != Some(LEGACY_SDK_SCHEMA) {
        return Err(Refusal::new(
            "unsupported legacy SDK schema; expected ami-rust-sdk-v1",
        ));
    }
    let manifest: LegacySdkManifestV1 = serde::Deserialize::deserialize(value)
        .map_err(|error| Refusal::new(format!("invalid legacy SDK manifest: {error}")))?;
    if manifest.version.is_empty()
        || manifest.version.chars().any(char::is_control)
        || !valid_git_identity(&manifest.rust_commit)
        || manifest.rust_llvm.is_empty()
        || manifest.rust_llvm.chars().any(char::is_control)
        || manifest.files.is_empty()
    {
        return Err(Refusal::new(
            "legacy SDK omits a supported version or compiler identity",
        ));
    }
    // Historical development manifests used descriptive source identities
    // such as "working tree; not release-qualified". This field is inert and
    // does not participate in migration admission.
    for profile_name in manifest.profiles.keys() {
        if !matches!(profile_name.as_str(), "linux-x86_64" | "macos-aarch64") {
            return Err(Refusal::new(
                "legacy SDK contains an unsupported host profile",
            ));
        }
    }
    Ok(manifest)
}

fn read_legacy_binding(
    project: &Path,
    project_root: &Directory,
    project_uid: u32,
    manifest: &LegacySdkManifestV1,
    lock_sdk: &LegacyLockSdk,
    signals: &SigtermGuard,
) -> Result<Option<Vec<u8>>> {
    let binding_leaf = std::ffi::OsStr::new("ami-rust-sdk.json");
    let binding_path = project.join(binding_leaf);
    let exists = match fs::symlink_metadata(&binding_path) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(Refusal::new(format!(
                "could not inspect legacy project binding: {error}"
            )));
        }
    };
    if !exists {
        return Ok(None);
    }
    let raw = read_regular_at(project_root, binding_leaf, 4096, Some(project_uid), signals)?;
    let value = parse_json_value(&raw, JsonProfile::SdkComponentManifest)?;
    let binding: LegacyProjectSdkBindingV1 = serde::Deserialize::deserialize(value)
        .map_err(|error| Refusal::new(format!("invalid legacy project SDK binding: {error}")))?;
    if binding.schema != LEGACY_BINDING_SCHEMA
        || binding.version != manifest.version
        || binding.sdk_manifest_sha256 != lock_sdk.manifest_sha256
    {
        return Err(Refusal::new(
            "legacy project SDK binding differs from the selected legacy SDK",
        ));
    }
    Ok(Some(raw))
}

fn parse_component_inventory(raw: &[u8]) -> Result<LegacyComponentInventory> {
    let value = parse_json_value(raw, JsonProfile::SdkComponentManifest)?;
    serde::Deserialize::deserialize(value)
        .map_err(|error| Refusal::new(format!("invalid legacy component inventory: {error}")))
}

fn selection_from_legacy(
    legacy: &ValidatedLegacyProject,
    installation: &CheckedNativeInstallation,
    host: Host,
) -> Result<SelectionV2> {
    let path = |name: &str| -> Result<&str> {
        legacy
            .component_roots
            .get(name)
            .and_then(|path| path.to_str())
            .ok_or_else(|| Refusal::new("legacy component root is not UTF-8"))
    };
    let value = json!({
        "schema": "ami-rust-selection-v2",
        "host": host_name(host),
        "install_receipt_sha256": installation.receipt_digest(),
        "components": {
            "rust": path("rust")?,
            "cargo": path("cargo")?,
            "toolchain": path("toolchain")?,
            "collector": path("collector")?,
            "csdk": path("csdk")?,
            "vendor": path("vendor")?
        }
    });
    let raw = serde_json::to_vec(&value)
        .map_err(|error| Refusal::new(format!("could not encode migration selection: {error}")))?;
    let selection = parse_selection(&raw)?;
    // A second check here makes incompatibility with the target SDK explicit
    // before the shared lock writer is entered.
    let selected = verify_selection(installation, &selection)?;
    selected.recheck()?;
    Ok(selection)
}

fn read_regular_at(
    root: &Directory,
    leaf: &std::ffi::OsStr,
    limit: usize,
    expected_uid: Option<u32>,
    signals: &SigtermGuard,
) -> Result<Vec<u8>> {
    let identity = root.classify_entry(leaf)?;
    if identity.entry_type() != EntryType::RegularFile {
        return Err(Refusal::new("expected a regular file without symlinks"));
    }
    let file = root.open_regular_matching(leaf, identity)?;
    read_bounded_file(file, limit, expected_uid, signals, "legacy input")
}

fn read_relative_regular(
    root_path: &Path,
    root: &Directory,
    relative: &str,
    limit: usize,
    expected_uid: Option<u32>,
    signals: &SigtermGuard,
) -> Result<Vec<u8>> {
    validate_relative_inventory_path(relative)?;
    let (parent_relative, leaf) = relative.rsplit_once('/').unwrap_or(("", relative));
    let parent = root.relative_directory(parent_relative)?;
    let identity = parent.classify_entry(std::ffi::OsStr::new(leaf))?;
    if identity.entry_type() != EntryType::RegularFile {
        return Err(Refusal::new("legacy manifest path is not a regular file"));
    }
    let file = parent.open_regular_matching(std::ffi::OsStr::new(leaf), identity)?;
    let full_path = root_path.join(relative);
    let before = file.metadata()?;
    let protected = ownership::protected_regular_file(&full_path, false)?;
    let protected_metadata = protected.metadata()?;
    if before.dev() != protected_metadata.dev() || before.ino() != protected_metadata.ino() {
        return Err(Refusal::new(
            "legacy manifest file changed during path validation",
        ));
    }
    read_bounded_file(file, limit, expected_uid, signals, "legacy manifest")
}

fn read_bounded_file(
    mut file: File,
    limit: usize,
    expected_uid: Option<u32>,
    signals: &SigtermGuard,
    label: &str,
) -> Result<Vec<u8>> {
    let before = file.metadata()?;
    if !before.file_type().is_file() {
        return Err(Refusal::new(format!("{label} is not a regular file")));
    }
    if expected_uid.is_some_and(|uid| before.uid() != uid)
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
    {
        return Err(Refusal::new(format!(
            "{label} has unsafe ownership or permissions"
        )));
    }
    let initial = usize::try_from(before.len())
        .map_err(|_| Refusal::new(format!("{label} length is not representable")))?;
    if initial > limit {
        return Err(Refusal::new(format!("{label} exceeds its size limit")));
    }
    let read_bound = limit
        .checked_add(1)
        .ok_or_else(|| Refusal::new("legacy input size limit overflow"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(initial)
        .map_err(|error| Refusal::new(format!("could not allocate {label}: {error}")))?;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        signals.check()?;
        let amount = (read_bound - bytes.len()).min(buffer.len());
        let count = match file.read(&mut buffer[..amount]) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Refusal::new(format!("could not read {label}: {error}"))),
        };
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() > limit {
            return Err(Refusal::new(format!("{label} grew beyond its size limit")));
        }
    }
    let after = file.metadata()?;
    if !same_file_state(&before, &after) || bytes.len() != initial {
        return Err(Refusal::new(format!("{label} changed while being read")));
    }
    signals.check()?;
    Ok(bytes)
}

fn hash_protected_file(
    path: &Path,
    executable: bool,
    expected_uid: Option<u32>,
    signals: &SigtermGuard,
    label: &str,
) -> Result<(u64, String)> {
    signals.check()?;
    let mut file = ownership::protected_regular_file(path, executable)?;
    let before = file.metadata()?;
    if expected_uid.is_some_and(|uid| before.uid() != uid)
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
    {
        return Err(Refusal::new(format!(
            "{label} has unexpected ownership or permissions"
        )));
    }
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        signals.check()?;
        let count = match file.read(&mut buffer) {
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Refusal::new(format!("could not hash {label}: {error}"))),
        };
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| Refusal::new(format!("{label} byte count overflow")))?;
        digest.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    if !same_file_state(&before, &after) || total != before.len() {
        return Err(Refusal::new(format!("{label} changed while being hashed")));
    }
    let digest: [u8; 32] = digest.finalize().into();
    signals.check()?;
    Ok((total, crate::digest::encode_hex(&digest)))
}

fn canonical_directory(path: &Path, base: &Path, label: &str) -> Result<PathBuf> {
    let absolute = absolute_lexical(path, base)?;
    let canonical = fs::canonicalize(&absolute)
        .map_err(|error| Refusal::new(format!("cannot resolve {label}: {error}")))?;
    if canonical != absolute {
        return Err(Refusal::new(format!(
            "{label} contains a symlink or path alias"
        )));
    }
    let directory = ownership::protected_directory(&absolute)?;
    if !directory.metadata()?.is_dir() {
        return Err(Refusal::new(format!("{label} is not a real directory")));
    }
    Ok(absolute)
}

fn canonical_file(path: &Path, label: &str) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(Refusal::new(format!("{label} path must be absolute")));
    }
    let normalized = absolute_lexical(path, Path::new("/"))?;
    if normalized != path {
        return Err(Refusal::new(format!("{label} path is not normalized")));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| Refusal::new(format!("cannot resolve {label}: {error}")))?;
    if canonical.as_path() != path {
        return Err(Refusal::new(format!(
            "{label} contains a symlink or path alias"
        )));
    }
    Ok(path.to_path_buf())
}

fn absolute_lexical(path: &Path, base: &Path) -> Result<PathBuf> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let mut normalized = PathBuf::new();
    for part in joined.components() {
        match part {
            Component::RootDir => normalized.push("/"),
            Component::CurDir => {}
            Component::Normal(name) => normalized.push(name),
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(Refusal::new("path traverses above the filesystem root"));
                }
            }
            Component::Prefix(_) => {
                return Err(Refusal::new("platform path prefixes are unsupported"));
            }
        }
    }
    if !normalized.is_absolute() {
        return Err(Refusal::new("path must resolve to an absolute path"));
    }
    Ok(normalized)
}

fn same_file_state(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.nlink() == after.nlink()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn valid_git_identity(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn host_name(host: Host) -> &'static str {
    match host {
        Host::LinuxX86_64 => "linux-x86_64",
        Host::MacosAarch64 => "macos-aarch64",
    }
}

fn target_name(host: Host) -> &'static str {
    match host {
        Host::LinuxX86_64 => "x86_64-unknown-linux-gnu",
        Host::MacosAarch64 => "aarch64-apple-darwin",
    }
}

fn path_text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Refusal::new("migration path is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
    const CHILD_MODE: &str = "AMI_NATIVE_MIGRATE_FIXTURE";

    #[test]
    fn legacy_migration_checks_run_in_an_isolated_signal_process() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_migrate::tests::migration_child_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env_clear()
            .env("HOME", std::env::var_os("HOME").unwrap())
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env(CHILD_MODE, "1")
            .output()
            .expect("spawn isolated legacy migration tests");
        assert!(
            output.status.success(),
            "legacy migration child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "run by the parent test with isolated process-wide signal state"]
    fn migration_child_fixture() {
        assert_eq!(std::env::var(CHILD_MODE).as_deref(), Ok("1"));
        dry_run_validates_legacy_lock_and_reports_embedded_selection();
        dry_run_refuses_changed_cargo_inputs_and_future_lock_schema();
        dry_run_refuses_linked_cargo_file();
        dry_run_refuses_changed_legacy_binding();
    }

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let root = fs::canonicalize(std::env::temp_dir()).expect("temporary directory");
            for _ in 0..100 {
                let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
                let path = root.join(format!(
                    ".ami-rust-migrate-test-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => {
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                            .expect("private fixture root");
                        return Self(path);
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("could not create migration fixture: {error}"),
                }
            }
            panic!("could not reserve migration fixture directory")
        }

        fn build(&self) -> PathBuf {
            let project = self.0.join("project");
            let sdk = self.0.join("sdk");
            fs::create_dir(&project).expect("project directory");
            fs::create_dir_all(sdk.join("contract")).expect("SDK contract directory");
            fs::create_dir_all(
                sdk.join("host/profiles")
                    .join(host_name(Host::current().unwrap())),
            )
            .expect("SDK profile directory");

            let mut profile_components = Map::new();
            let mut sdk_files = Vec::new();
            for name in COMPONENT_NAMES {
                let component = self.0.join(format!("component-{name}"));
                fs::create_dir(&component).expect("component root");
                let relative = if name == "cargo" {
                    "bin/cargo"
                } else {
                    "identity"
                };
                let file = component.join(relative);
                fs::create_dir_all(file.parent().unwrap()).expect("component file parent");
                fs::write(&file, format!("{name} inventory fixture\n")).expect("component file");
                if name == "cargo" {
                    fs::set_permissions(&file, fs::Permissions::from_mode(0o755))
                        .expect("Cargo executable mode");
                }
                let bytes = fs::read(&file).expect("component file bytes");
                let inventory = json!({
                    "files": [{"path": relative, "bytes": bytes.len(), "sha256": sha256_bytes(&bytes)}],
                    "symlinks": [],
                    "producer_identity_spec": {"historical": "inert metadata"}
                });
                let inventory_path = format!(
                    "host/profiles/{}/{name}.json",
                    host_name(Host::current().unwrap())
                );
                let inventory_bytes = serde_json::to_vec_pretty(&inventory).unwrap();
                fs::write(sdk.join(&inventory_path), &inventory_bytes).expect("component manifest");
                sdk_files.push(json!({
                    "path": inventory_path,
                    "bytes": inventory_bytes.len(),
                    "sha256": sha256_bytes(&inventory_bytes)
                }));
                profile_components.insert(
                    name.to_owned(),
                    json!({"manifest": inventory_path, "sha256": sha256_bytes(&inventory_bytes)}),
                );
                // Keep component paths stable in this fixture without running
                // any executable from them.
                let _ = component;
            }

            let marker = b"historical SDK marker\n";
            fs::write(sdk.join("sdk.catalog"), marker).expect("SDK marker");
            sdk_files.push(json!({
                "path": "sdk.catalog",
                "bytes": marker.len(),
                "sha256": sha256_bytes(marker)
            }));
            let host = Host::current().unwrap();
            let manifest = json!({
                "schema": LEGACY_SDK_SCHEMA,
                "version": "0.1.0",
                "source_identity": "working tree; not release-qualified",
                "rust_commit": "a".repeat(40),
                "rust_llvm": "23.1.1",
                "source_date_epoch": 1791936000u64,
                "qualification_only": true,
                "development_only": true,
                "driver": "host/build.py",
                "budgets": {"build_rss_bytes": 123456789},
                "packaging": {"rust_provisioning": "metadata only"},
                "runtime_memory_policy": {"schema": "ami-rust-runtime-memory-policy-v1"},
                "host_capacity": {"schema": "ami-rust-host-capacity-v1"},
                "hosted_cargo": {"status": "producer metadata only"},
                "files": sdk_files,
                "profiles": {
                    host_name(host): {
                        "rust_host": target_name(host),
                        "cargo_binary": "bin/cargo",
                        "cargo_metadata_mode": LEGACY_CARGO_METADATA_MODE,
                        "collector_binary": "bin/aros-collect",
                        "components": profile_components
                    }
                }
            });
            let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
            fs::write(sdk.join("contract/sdk.json"), &manifest_bytes).expect("SDK manifest");

            let cargo_manifest = b"[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n";
            let cargo_lock = b"version = 4\n";
            fs::write(project.join("Cargo.toml"), cargo_manifest).expect("Cargo.toml");
            fs::write(project.join("Cargo.lock"), cargo_lock).expect("Cargo.lock");
            let python = std::env::current_exe().expect("test executable");
            let components = COMPONENT_NAMES
                .into_iter()
                .map(|name| {
                    (
                        name.to_owned(),
                        self.0
                            .join(format!("component-{name}"))
                            .to_str()
                            .unwrap()
                            .to_owned()
                            .into(),
                    )
                })
                .collect::<serde_json::Map<String, Value>>();
            let lock = json!({
                "schema": LEGACY_LOCK_SCHEMA,
                "sdk": {
                    "root": sdk.to_str().unwrap(),
                    "manifest": "contract/sdk.json",
                    "manifest_sha256": sha256_bytes(&manifest_bytes)
                },
                "host": {
                    "platform": host_name(host),
                    "python": python.to_str().unwrap(),
                    "python_sha256": crate::digest::sha256_file(&python).unwrap()
                },
                "components": components,
                "cargo": {
                    "manifest_sha256": sha256_bytes(cargo_manifest),
                    "lock_sha256": sha256_bytes(cargo_lock)
                }
            });
            fs::write(
                project.join("ami-rust.lock.json"),
                serde_json::to_vec_pretty(&lock).unwrap(),
            )
            .expect("legacy lock");
            let binding = json!({
                "schema": LEGACY_BINDING_SCHEMA,
                "version": "0.1.0",
                "sdk_manifest_sha256": sha256_bytes(&manifest_bytes)
            });
            fs::write(
                project.join("ami-rust-sdk.json"),
                serde_json::to_vec_pretty(&binding).unwrap(),
            )
            .expect("legacy SDK binding");
            project
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn dry_run_validates_legacy_lock_and_reports_embedded_selection() {
        let fixture = Fixture::new();
        let project = fixture.build();
        let signals = SigtermGuard::acquire().expect("signal guard");
        let report = dry_run(&project, &signals).expect("valid migration dry-run");
        assert_eq!(report.status, "migration-required");
        assert!(report.migration_required);
        assert!(!report.selection_missing);
        assert_eq!(report.legacy_lock.schema, LEGACY_LOCK_SCHEMA);
        assert_eq!(report.legacy_sdk.version, "0.1.0");
        assert_eq!(report.compiler.rust_commit, "a".repeat(40));
        assert_eq!(
            report.cargo.manifest_sha256,
            sha256_bytes(b"[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n")
        );
        signals.finish().expect("restore signal handler");
    }

    fn dry_run_refuses_changed_cargo_inputs_and_future_lock_schema() {
        let fixture = Fixture::new();
        let project = fixture.build();
        let signals = SigtermGuard::acquire().expect("signal guard");
        fs::write(project.join("Cargo.toml"), b"changed\n").expect("change Cargo.toml");
        assert!(dry_run(&project, &signals).is_err());

        let lock_path = project.join("ami-rust.lock.json");
        let mut lock: Value = serde_json::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
        lock["schema"] = Value::String("ami-rust-project-lock-v2".into());
        fs::write(&lock_path, serde_json::to_vec(&lock).unwrap()).expect("future lock");
        assert!(dry_run(&project, &signals).is_err());
        signals.finish().expect("restore signal handler");
    }

    fn dry_run_refuses_linked_cargo_file() {
        let fixture = Fixture::new();
        let project = fixture.build();
        let cargo = project.join("Cargo.lock");
        let saved = project.join("Cargo.lock.saved");
        fs::rename(&cargo, &saved).expect("move Cargo.lock");
        symlink(&saved, &cargo).expect("linked Cargo.lock");
        let signals = SigtermGuard::acquire().expect("signal guard");
        assert!(dry_run(&project, &signals).is_err());
        signals.finish().expect("restore signal handler");
    }

    fn dry_run_refuses_changed_legacy_binding() {
        let fixture = Fixture::new();
        let project = fixture.build();
        let binding_path = project.join("ami-rust-sdk.json");
        let mut binding: Value = serde_json::from_slice(&fs::read(&binding_path).unwrap()).unwrap();
        binding["version"] = Value::String("0.2.0".into());
        fs::write(&binding_path, serde_json::to_vec(&binding).unwrap()).unwrap();
        let signals = SigtermGuard::acquire().expect("signal guard");
        assert!(dry_run(&project, &signals).is_err());
        signals.finish().expect("restore signal handler");
    }
}
