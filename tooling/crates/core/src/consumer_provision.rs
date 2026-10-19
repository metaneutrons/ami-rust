//! Native provisioning of the six consumer components from admitted pins.
//!
//! This module is orchestration only. The caller has already authenticated the
//! package and source checkout; this code admits the unchanged initial SDK,
//! rechecks the source-level acquisition pins against the compiled baseline,
//! materializes components in the private consumer session, and verifies all
//! six component inventories before returning their roots. It never executes
//! Python or source helpers and never writes consumer readiness state.

use crate::{
    Refusal, Result,
    acquisition::{
        AcquisitionObservationConfig, CurlExecutablePin, DownloadLimits, DownloadPin, HttpsOrigin,
        acquire_pinned_download,
    },
    baseline::InitialBaseline,
    cargo_archive::{CargoArchiveSpec, extract_flat_cargo_archive},
    component_archive::{
        ArchiveFormat, ArchiveLimits, ComponentArchiveSpec, extract_component_archive,
    },
    component_install::{ComponentInstallLimits, ComponentInstallSpec, install_component_profile},
    consumer_session::ConsumerSession,
    digest::{is_sha256_digest, sha256_bytes},
    directory::{Directory, EntryType},
    files::validate_relative_inventory_path,
    inventory::{
        FileIdentity, InventoryLimits, LinkIdentity, Measurement, verify_complete_directory_checked,
    },
    json::{JsonProfile, parse_json, parse_json_value},
    native_install::CheckedNativeInstallation,
    ownership::{self, FreshTarget},
    process_capture::CommandSpec,
    records::{ComponentRoots, Host},
    signals::SigtermGuard,
    workspace_accounting::{self, ScanLimits},
};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::File,
    io::Write,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Duration,
};

const COMPONENT_NAMES: [&str; 6] = ["rust", "cargo", "toolchain", "collector", "csdk", "vendor"];
const RUST_COMPONENTS: [&str; 4] = ["rustc", "rust-std", "rust-src", "cargo"];
const RUST_ADMIN_FILES_PREFIX: [&str; 3] = [
    "lib/rustlib/install.log",
    "lib/rustlib/manifest-cargo",
    "lib/rustlib/manifest-rust-src",
];
const WORKSPACE_LIMIT: u64 = 12 * 1024 * 1024 * 1024;
const EXPANDED_ARCHIVE_LIMIT: u64 = 6 * 1024 * 1024 * 1024;
const ARCHIVE_MEMBER_LIMIT: usize = 100_000;
const ARCHIVE_INDEX_LIMIT: usize = 1024 * 1024 * 1024;
const ARCHIVE_PATH_LIMIT: usize = 4096;
const ARCHIVE_PATH_COMPONENT_LIMIT: usize = 256;
const ARCHIVE_EXTENSION_LIMIT: usize = 16 * 1024 * 1024;
const XZ_MEMORY_LIMIT_KIB: u32 = 256 * 1024;
const TREE_SCAN_LIMITS: ScanLimits = ScanLimits {
    max_entries: 100_000,
    max_work_units: 200_001,
};
const INVENTORY_LIMITS: InventoryLimits = InventoryLimits {
    max_tree_entries: 100_000,
    max_link_resolution_steps: 100_000,
};
const DOWNLOAD_TOTAL_TIMEOUT: Duration = Duration::from_secs(300);
const DOWNLOAD_HOP_TIMEOUT: Duration = Duration::from_secs(30);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(300);

/// Six verified roots ready for a selection record. Measurements describe the
/// inventories actually checked at the end of provisioning; they do not make
/// new publisher-authentication claims.
#[derive(Debug)]
pub struct ProvisionedComponents {
    pub roots: ComponentRoots,
    pub measurements: BTreeMap<String, Measurement>,
}

struct ComponentInventory {
    files: Vec<FileIdentity>,
    symlinks: Vec<LinkIdentity>,
}

#[derive(Debug, Deserialize)]
struct ComponentInventoryWire {
    files: Vec<ComponentFileWire>,
    symlinks: Vec<ComponentLinkWire>,
}

#[derive(Debug, Deserialize)]
struct ComponentFileWire {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct ComponentLinkWire {
    path: String,
    target: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RemoteArchivePin {
    url: String,
    bytes: u64,
    sha256: String,
    archive_root: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RustInstallPlan {
    archives: Vec<(String, RemoteArchivePin)>,
    administrative_files: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeHostPlan {
    rust: RustInstallPlan,
    toolchain: RemoteArchivePin,
    collector: RemoteArchivePin,
    vendor_path: String,
    vendor_bytes: u64,
    vendor_sha256: String,
    csdk_path: String,
    csdk_bytes: u64,
    csdk_sha256: String,
    csdk_root: String,
}

struct ExtractedComponent {
    container: Directory,
    archive: Directory,
    root_name: OsString,
    root_path: PathBuf,
    root: Directory,
}

/// Provision the six consumer components under the retained private session.
///
/// `source_checkout` must be the exact `session.path()/source` tree already
/// fetched and checked against the authenticated package pin. `signals` must
/// be the same operation guard used to create `session`. The returned roots
/// are not a READY state and must still be bound into a consumer selection by
/// the caller.
pub fn provision_native_consumer_components(
    installation: &CheckedNativeInstallation,
    baseline: &InitialBaseline,
    host: Host,
    source_checkout: &Path,
    session: &mut ConsumerSession<'_>,
    curl: &CurlExecutablePin,
    signals: &SigtermGuard,
) -> Result<ProvisionedComponents> {
    signals.check()?;
    host.ensure_current()?;
    session.recheck_root()?;

    // This is deliberately before any provisioning writes. The recipe binds
    // component manifest names/digests to the accepted target bytes.
    let recipe = baseline.admit_initial_sdk(installation, host)?;
    installation.recheck()?;
    let expected_source = session.path().join("source");
    if source_checkout != expected_source || !source_checkout.is_absolute() {
        return Err(Refusal::new(
            "consumer provisioning requires the exact retained session source checkout",
        ));
    }
    ownership::require_disjoint(
        source_checkout,
        &installation.path().join("sdk"),
        "consumer source and installed SDK must be disjoint",
    )?;
    let source = Directory::open(source_checkout)?;

    let runtime = baseline.runtime_acquisition();
    let inputs = read_and_validate_ci_inputs(&source, runtime)?;
    let plan = runtime_host_plan(&inputs, runtime, host)?;
    validate_portable_csdk_spec(&source, &inputs, runtime, &plan)?;
    let inventories = read_component_inventories(installation, &recipe)?;
    validate_component_names(&inventories)?;
    validate_collector_profile(&inventories["collector"], host)?;
    validate_cargo_profile(&inventories["cargo"])?;
    installation.recheck()?;
    signals.check()?;

    let state = ownership::existing_private_state(session.path())?;
    let work = state.mkdir_new(OsStr::new("provision-work"), 0o700)?;
    let work_path = session.path().join("provision-work");
    let downloads = work.mkdir_new(OsStr::new("downloaded-inputs"), 0o700)?;
    let extractions = work.mkdir_new(OsStr::new("archive-extraction"), 0o700)?;
    let component_stage = work.mkdir_new(OsStr::new("component-staging"), 0o700)?;
    let component_stage_path = work_path.join("component-staging");
    let rust_root = component_stage.mkdir_new(OsStr::new("rust"), 0o755)?;
    let rust_root_path = component_stage_path.join("rust");
    check_workspace(session, signals)?;

    provision_rust(
        &plan.rust,
        &downloads,
        &extractions,
        &work_path,
        &component_stage,
        &component_stage_path,
        &rust_root,
        &rust_root_path,
        session,
        curl,
        signals,
    )?;
    verify_rust_identity(&rust_root_path, host, runtime, session, signals)?;

    provision_toolchain(
        &plan.toolchain,
        &downloads,
        &extractions,
        &component_stage,
        &component_stage_path,
        &work_path,
        session,
        curl,
        signals,
    )?;
    provision_collector(
        &plan.collector,
        &inventories["collector"],
        &downloads,
        &extractions,
        &component_stage,
        &component_stage_path,
        &work_path,
        session,
        curl,
        signals,
    )?;
    provision_local_component(
        &source,
        &plan.csdk_path,
        plan.csdk_bytes,
        &plan.csdk_sha256,
        &plan.csdk_root,
        "csdk",
        &extractions,
        &component_stage,
        &component_stage_path,
        &work_path,
        session,
        signals,
    )?;
    provision_local_component(
        &source,
        &plan.vendor_path,
        plan.vendor_bytes,
        &plan.vendor_sha256,
        "vendor",
        "vendor",
        &extractions,
        &component_stage,
        &component_stage_path,
        &work_path,
        session,
        signals,
    )?;
    provision_cargo(
        installation,
        runtime,
        host,
        &inventories["cargo"],
        &downloads,
        &component_stage,
        &component_stage_path,
        session,
        signals,
    )?;

    let roots = ComponentRoots {
        rust: rust_root_path,
        cargo: component_stage_path.join("cargo"),
        toolchain: component_stage_path.join("toolchain"),
        collector: component_stage_path.join("collector"),
        csdk: component_stage_path.join("csdk"),
        vendor: component_stage_path.join("vendor"),
    };
    let measurements = verify_six_components(
        &roots,
        &component_stage,
        &component_stage_path,
        &source,
        source_checkout,
        installation.path(),
        &inventories,
        session,
        signals,
    )?;
    check_workspace(session, signals)?;
    installation.recheck()?;
    session.recheck_root()?;

    Ok(ProvisionedComponents {
        roots,
        measurements,
    })
}

fn read_and_validate_ci_inputs(source: &Directory, runtime: &Value) -> Result<Value> {
    let accepted = field(runtime, "accepted_source")?;
    let path = string(accepted, "path")?;
    if path != "release/ci-sdk-inputs.json" {
        return Err(Refusal::new("compiled CI input source path changed"));
    }
    let bytes = counter(accepted, "bytes")?;
    let digest = string(accepted, "sha256")?;
    let raw = read_source_file(source, path, bytes, digest, 1024 * 1024)?;
    let inputs = parse_json_value(&raw, JsonProfile::SdkComponentManifest)?;
    if string(&inputs, "schema")? != "ami-rust-ci-sdk-inputs-v1" {
        return Err(Refusal::new("unsupported checked CI input schema"));
    }
    let rust = field(runtime, "rust")?;
    for (source_key, runtime_key) in [
        ("rust_channel", "channel"),
        ("rust_commit", "commit"),
        ("rust_llvm", "llvm"),
    ] {
        if string(&inputs, source_key)? != string(rust, runtime_key)? {
            return Err(Refusal::new(format!(
                "checked CI input {source_key} differs from compiled baseline"
            )));
        }
    }
    if field(&inputs, "channel_manifest")? != field(rust, "channel_manifest")? {
        return Err(Refusal::new(
            "checked Rust channel manifest pin differs from compiled baseline",
        ));
    }
    Ok(inputs)
}

fn runtime_host_plan(inputs: &Value, runtime: &Value, host: Host) -> Result<RuntimeHostPlan> {
    let key = host_key(host);
    let runtime_rust = field(runtime, "rust")?;
    let source_host = field(field(inputs, "hosts")?, key)?;
    let pinned_host = field(field(runtime_rust, "hosts")?, key)?;
    if source_host != pinned_host {
        return Err(Refusal::new(
            "source host acquisition rows differ from the compiled baseline",
        ));
    }
    exact_keys(
        source_host,
        &["rust", "toolchain", "collector"],
        "host acquisition",
    )?;

    let rust_row = field(source_host, "rust")?;
    if string(rust_row, "kind")? != "rust-installer" {
        return Err(Refusal::new(
            "Rust host pin is not an installer archive profile",
        ));
    }
    let archive_order = string_array(field(rust_row, "archive_order")?)?;
    if archive_order.as_slice() != RUST_COMPONENTS.as_slice() {
        return Err(Refusal::new(
            "Rust installer component order differs from accepted profile",
        ));
    }
    let archive_rows = array(field(rust_row, "archives")?)?;
    if archive_rows.len() != RUST_COMPONENTS.len() {
        return Err(Refusal::new("Rust installer archive set is incomplete"));
    }
    let target = rust_target(host);
    let mut rust_archives = Vec::with_capacity(RUST_COMPONENTS.len());
    for (component, row) in RUST_COMPONENTS.iter().zip(archive_rows) {
        if string(row, "component")? != *component {
            return Err(Refusal::new("Rust installer archive order is inconsistent"));
        }
        let archive_root = rust_archive_root(component, target);
        rust_archives.push((
            (*component).to_owned(),
            remote_pin(row, None, &archive_root)?,
        ));
    }
    let admin = string_array(field(rust_row, "remove_installer_administrative_files")?)?;
    let expected_admin = expected_rust_admin_paths(target);
    if admin.as_slice()
        != expected_admin
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
    {
        return Err(Refusal::new(
            "Rust installer administrative-file removal list differs from accepted profile",
        ));
    }

    let toolchain_row = field(source_host, "toolchain")?;
    let collector_row = field(source_host, "collector")?;
    for (label, row) in [("toolchain", toolchain_row), ("collector", collector_row)] {
        if string(row, "kind")? != "tar" {
            return Err(Refusal::new(format!("{label} is not a pinned TAR profile")));
        }
    }
    let toolchain = remote_pin(toolchain_row, Some("toolchain"), "toolchain")?;
    let collector_root = string(collector_row, "archive_root")?;
    validate_archive_root(collector_root)?;
    let collector = remote_pin(collector_row, Some(collector_root), collector_root)?;

    let source_shared = field(inputs, "shared")?;
    let baseline_shared = field(runtime, "shared_archives")?;
    let source_vendor = field(source_shared, "vendor")?;
    let pinned_vendor = field(baseline_shared, "vendor")?;
    if source_vendor != pinned_vendor
        || string(source_vendor, "kind")? != "repository-tar"
        || string(source_vendor, "path")? != "release/inputs/vendor.tar.xz"
        || string(source_vendor, "archive_root")? != "vendor"
    {
        return Err(Refusal::new(
            "source vendor archive pin differs from compiled baseline",
        ));
    }

    let portable = field(baseline_shared, "portable_csdk")?;
    let spec_pin = field(portable, "spec")?;
    let source_spec = field(inputs, "portable_csdk")?;
    for key in ["path", "bytes", "sha256"] {
        if field(source_spec, key)? != field(spec_pin, key)? {
            return Err(Refusal::new(
                "source portable CSDK specification pin differs from compiled baseline",
            ));
        }
    }
    let csdk_archive = field(portable, "archive")?;
    if string(csdk_archive, "name")? != "csdk-component.tar.xz" {
        return Err(Refusal::new("portable CSDK candidate archive name changed"));
    }
    let csdk_path = string(csdk_archive, "path")?.to_owned();
    validate_relative_inventory_path(&csdk_path)?;
    let vendor_path = string(source_vendor, "path")?.to_owned();
    validate_relative_inventory_path(&vendor_path)?;

    Ok(RuntimeHostPlan {
        rust: RustInstallPlan {
            archives: rust_archives,
            administrative_files: admin.into_iter().map(str::to_owned).collect(),
        },
        toolchain,
        collector,
        vendor_path,
        vendor_bytes: counter(source_vendor, "bytes")?,
        vendor_sha256: string(source_vendor, "sha256")?.to_owned(),
        csdk_path,
        csdk_bytes: counter(csdk_archive, "bytes")?,
        csdk_sha256: string(csdk_archive, "sha256")?.to_owned(),
        csdk_root: "Developer".to_owned(),
    })
}

fn validate_portable_csdk_spec(
    source: &Directory,
    inputs: &Value,
    runtime: &Value,
    plan: &RuntimeHostPlan,
) -> Result<()> {
    let runtime_portable = field(field(runtime, "shared_archives")?, "portable_csdk")?;
    let spec_pin = field(runtime_portable, "spec")?;
    let spec_path = string(spec_pin, "path")?;
    let spec_raw = read_source_file(
        source,
        spec_path,
        counter(spec_pin, "bytes")?,
        string(spec_pin, "sha256")?,
        4 * 1024 * 1024,
    )?;
    let spec = parse_json_value(&spec_raw, JsonProfile::SdkComponentManifest)?;
    if string(&spec, "schema")? != "ami-rust-portable-csdk-v1"
        || string(&spec, "status")? != "PINNED_CANDIDATE_TWO_HOST_QUALIFICATION_REQUIRED"
    {
        return Err(Refusal::new(
            "portable CSDK spec is not the accepted candidate",
        ));
    }
    let candidate = field(&spec, "candidate")?;
    let archive = field(candidate, "archive")?;
    let profile = field(candidate, "profile")?;
    let source_original = field(field(inputs, "shared")?, "csdk")?;
    let spec_original = field(field(&spec, "original")?, "archive")?;
    if string(source_original, "kind")? != "repository-tar"
        || string(source_original, "path")? != "release/inputs/csdk.tar.xz"
        || string(source_original, "archive_root")? != "Developer"
    {
        return Err(Refusal::new("original CSDK source pin changed"));
    }
    for key in ["path", "bytes", "sha256"] {
        if field(source_original, key)? != field(spec_original, key)? {
            return Err(Refusal::new(
                "portable CSDK original archive differs from source input pin",
            ));
        }
    }
    let pinned_archive = field(runtime_portable, "archive")?;
    let pinned_profile = field(runtime_portable, "profile")?;
    for key in ["name", "path", "bytes", "sha256"] {
        if field(archive, key)? != field(pinned_archive, key)? {
            return Err(Refusal::new(
                "portable CSDK candidate archive differs from compiled baseline",
            ));
        }
    }
    for key in ["path", "bytes", "sha256"] {
        if field(profile, key)? != field(pinned_profile, key)? {
            return Err(Refusal::new(
                "portable CSDK candidate profile differs from compiled baseline",
            ));
        }
    }
    if string(archive, "path")? != plan.csdk_path
        || counter(archive, "bytes")? != plan.csdk_bytes
        || string(archive, "sha256")? != plan.csdk_sha256
    {
        return Err(Refusal::new("selected portable CSDK archive pin changed"));
    }
    let profile_raw = read_source_file(
        source,
        string(profile, "path")?,
        counter(profile, "bytes")?,
        string(profile, "sha256")?,
        4 * 1024 * 1024,
    )?;
    let source_spec = field(inputs, "portable_csdk")?;
    for key in ["path", "bytes", "sha256"] {
        if field(source_spec, key)? != field(spec_pin, key)? {
            return Err(Refusal::new(
                "source portable CSDK spec pointer differs from compiled baseline",
            ));
        }
    }
    // The inventory is supplied by the admitted SDK recipe. Reading and
    // hashing this selected source profile keeps the candidate's own pin live
    // without treating it as an authentication authority.
    if profile_raw.len() as u64 != counter(profile, "bytes")?
        || sha256_bytes(&profile_raw) != string(profile, "sha256")?
    {
        return Err(Refusal::new("portable CSDK profile differs from its pin"));
    }
    Ok(())
}

fn read_component_inventories(
    installation: &CheckedNativeInstallation,
    recipe: &crate::sdk::InstalledSdkRecipe,
) -> Result<BTreeMap<String, ComponentInventory>> {
    let mut inventories = BTreeMap::new();
    for name in COMPONENT_NAMES {
        let (path, expected_digest) = recipe
            .component_manifests
            .get(name)
            .ok_or_else(|| Refusal::new(format!("admitted SDK omits {name} inventory")))?;
        validate_relative_inventory_path(path)?;
        let raw = installation.read_file(&format!("sdk/{path}"))?;
        if raw.len() > JsonProfile::SdkComponentManifest.max_bytes()
            || sha256_bytes(&raw).as_str() != expected_digest
        {
            return Err(Refusal::new(format!(
                "retained SDK {name} inventory differs from its admitted digest"
            )));
        }
        let inventory = parse_component_inventory(&raw)?;
        validate_inventory_rows(&inventory, name)?;
        inventories.insert(name.to_owned(), inventory);
    }
    if inventories.len() != COMPONENT_NAMES.len() {
        return Err(Refusal::new(
            "admitted SDK component inventory set is not exact",
        ));
    }
    Ok(inventories)
}

fn validate_inventory_rows(inventory: &ComponentInventory, name: &str) -> Result<()> {
    let count = inventory
        .files
        .len()
        .checked_add(inventory.symlinks.len())
        .ok_or_else(|| Refusal::new("SDK component inventory count overflow"))?;
    if count == 0 || count > ARCHIVE_MEMBER_LIMIT {
        return Err(Refusal::new(format!(
            "SDK {name} inventory has an unsupported row count"
        )));
    }
    Ok(())
}

fn parse_component_inventory(raw: &[u8]) -> Result<ComponentInventory> {
    // The existing SDK consumer reads only these two arrays and deliberately
    // tolerates ancillary root/row fields (Cargo inventories include a
    // producer_identity_spec). Duplicate JSON keys and size/depth limits are
    // still rejected by the shared parser.
    let wire: ComponentInventoryWire = parse_json(raw, JsonProfile::SdkComponentManifest)?;
    Ok(ComponentInventory {
        files: wire
            .files
            .into_iter()
            .map(|row| FileIdentity {
                path: row.path,
                bytes: row.bytes,
                sha256: row.sha256,
                // The historical consumer inventory binds file bytes and
                // paths, while selected materialization preserves source
                // permission bits separately.
                mode: None,
            })
            .collect(),
        symlinks: wire
            .symlinks
            .into_iter()
            .map(|row| LinkIdentity {
                path: row.path,
                target: row.target,
            })
            .collect(),
    })
}

fn validate_component_names(inventories: &BTreeMap<String, ComponentInventory>) -> Result<()> {
    let actual: BTreeSet<&str> = inventories.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = COMPONENT_NAMES.into_iter().collect();
    if actual != expected {
        return Err(Refusal::new("SDK component inventory names are not exact"));
    }
    Ok(())
}

fn validate_collector_profile(inventory: &ComponentInventory, host: Host) -> Result<()> {
    let expected_files = match host {
        Host::MacosAarch64 => 1,
        Host::LinuxX86_64 => 10,
    };
    if inventory.files.len() != expected_files {
        return Err(Refusal::new(format!(
            "collector inventory has {} files; accepted {} profile requires {expected_files}",
            inventory.files.len(),
            host_key(host)
        )));
    }
    Ok(())
}

fn validate_cargo_profile(inventory: &ComponentInventory) -> Result<()> {
    let paths: BTreeSet<&str> = inventory
        .files
        .iter()
        .map(|row| row.path.as_str())
        .collect();
    if paths != BTreeSet::from(["bin/cargo", "producer.json"])
        || inventory.files.len() != 2
        || !inventory.symlinks.is_empty()
    {
        return Err(Refusal::new(
            "Cargo inventory must contain only bin/cargo and producer.json",
        ));
    }
    Ok(())
}

// Keep retained source/destination descriptors and their paths explicit at this boundary.
#[allow(clippy::too_many_arguments)]
fn provision_rust(
    plan: &RustInstallPlan,
    downloads: &Directory,
    extractions: &Directory,
    work_path: &Path,
    component_stage: &Directory,
    component_stage_path: &Path,
    rust_root: &Directory,
    rust_root_path: &Path,
    session: &mut ConsumerSession<'_>,
    curl: &CurlExecutablePin,
    signals: &SigtermGuard,
) -> Result<()> {
    if plan.archives.len() != RUST_COMPONENTS.len() {
        return Err(Refusal::new(
            "Rust installer plan must contain four archives",
        ));
    }
    for (component, pin) in &plan.archives {
        signals.check()?;
        let download_name = format!("{component}.tar.xz");
        acquire_remote_archive(
            pin,
            &download_name,
            downloads,
            &work_path.join("downloaded-inputs"),
            session,
            curl,
            signals,
        )?;
        let container_name = format!("rust-{component}");
        let root_name = pin
            .archive_root
            .as_deref()
            .ok_or_else(|| Refusal::new("Rust archive pin omits its expected root"))?;
        let archive = downloads.regular(OsStr::new(&download_name))?;
        let extracted = extract_archive(
            archive,
            extractions,
            &work_path.join("archive-extraction"),
            &container_name,
            root_name,
            pin.bytes,
            &pin.sha256,
            ArchiveFormat::TarXz,
            signals,
            session,
        )?;
        let installer = extracted.root_path().join("install.sh");
        let install_file = extracted.root.regular(OsStr::new("install.sh"))?;
        if install_file.metadata()?.mode() & 0o111 == 0 {
            return Err(Refusal::new(format!(
                "pinned Rust {component} installer is not executable"
            )));
        }
        drop(install_file);
        let mut args = Vec::with_capacity(2);
        let mut prefix_arg = OsString::from("--prefix=");
        prefix_arg.push(rust_root_path.as_os_str());
        args.push(prefix_arg);
        args.push(OsString::from("--disable-ldconfig"));
        let spec = CommandSpec::new(
            installer.as_os_str(),
            args,
            extracted.root_path(),
            session.environment(),
        );
        session.run_spec(&format!("rust-install-{component}"), spec, INSTALL_TIMEOUT)?;
        check_workspace(session, signals)?;
        drop(extracted.root);
        drop(extracted.archive);
        drop(extracted.container);
        retire_extraction(
            extractions,
            &work_path.join("archive-extraction"),
            &container_name,
        )?;
        retire_download(
            downloads,
            &work_path.join("downloaded-inputs"),
            &download_name,
        )?;
        check_workspace(session, signals)?;
    }
    remove_rust_admin_files(rust_root, &plan.administrative_files)?;
    component_stage.sync_best_effort();
    if rust_root_path != component_stage_path.join("rust") {
        return Err(Refusal::new(
            "Rust component destination changed during installation",
        ));
    }
    check_workspace(session, signals).map(|_| ())
}

fn remove_rust_admin_files(root: &Directory, paths: &[String]) -> Result<()> {
    if paths.len() != 5 {
        return Err(Refusal::new(
            "Rust administrative removal list must contain exactly five entries",
        ));
    }
    let mut seen = BTreeSet::new();
    for path in paths {
        validate_relative_inventory_path(path)?;
        if !seen.insert(path.as_str()) {
            return Err(Refusal::new("duplicate Rust installer administrative path"));
        }
        let (parent_path, leaf) = path.rsplit_once('/').unwrap_or(("", path.as_str()));
        let parent = root.relative_directory(parent_path)?;
        let name = OsStr::new(leaf);
        let identity = parent.classify_entry(name)?;
        if identity.entry_type() != EntryType::RegularFile {
            return Err(Refusal::new(format!(
                "Rust installer administrative entry is not a regular file: {path}"
            )));
        }
        drop(parent.open_regular_matching(name, identity)?);
        parent.unlink_entry(name)?;
    }
    Ok(())
}

fn verify_rust_identity(
    rust_root: &Path,
    host: Host,
    runtime: &Value,
    session: &mut ConsumerSession<'_>,
    signals: &SigtermGuard,
) -> Result<()> {
    let rustc = rust_root.join("bin/rustc");
    let args = vec![OsString::from("-Vv")];
    let spec = CommandSpec::new(
        rustc.as_os_str(),
        args,
        session.path(),
        session.environment(),
    );
    let output = session.run_spec(
        "verify-consumer-rust-identity",
        spec,
        Duration::from_secs(30),
    )?;
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|_| Refusal::new("installed rustc -Vv output is not UTF-8"))?;
    let rust = field(runtime, "rust")?;
    for expected in [
        format!("commit-hash: {}", string(rust, "commit")?),
        format!("LLVM version: {}", string(rust, "llvm")?),
        format!("host: {}", rust_target(host)),
    ] {
        if !stdout.lines().any(|line| line == expected) {
            return Err(Refusal::new(format!(
                "installed Rust identity omits expected {expected}"
            )));
        }
    }
    check_workspace(session, signals).map(|_| ())
}

// Keep retained source/destination descriptors and their paths explicit at this boundary.
#[allow(clippy::too_many_arguments)]
fn provision_toolchain(
    pin: &RemoteArchivePin,
    downloads: &Directory,
    extractions: &Directory,
    component_stage: &Directory,
    component_stage_path: &Path,
    work_path: &Path,
    session: &mut ConsumerSession<'_>,
    curl: &CurlExecutablePin,
    signals: &SigtermGuard,
) -> Result<()> {
    provision_remote_whole_component(
        pin,
        "toolchain",
        downloads,
        extractions,
        component_stage,
        component_stage_path,
        work_path,
        session,
        curl,
        signals,
    )
}

// Keep retained source/destination descriptors and their paths explicit at this boundary.
#[allow(clippy::too_many_arguments)]
fn provision_remote_whole_component(
    pin: &RemoteArchivePin,
    label: &str,
    downloads: &Directory,
    extractions: &Directory,
    component_stage: &Directory,
    component_stage_path: &Path,
    work_path: &Path,
    session: &mut ConsumerSession<'_>,
    curl: &CurlExecutablePin,
    signals: &SigtermGuard,
) -> Result<()> {
    let format = archive_format(&pin.url)?;
    let suffix = archive_suffix(format);
    let download_name = format!("{label}{suffix}");
    acquire_remote_archive(
        pin,
        &download_name,
        downloads,
        &work_path.join("downloaded-inputs"),
        session,
        curl,
        signals,
    )?;
    let root_name = pin
        .archive_root
        .as_deref()
        .ok_or_else(|| Refusal::new(format!("{label} pin omits its archive root")))?;
    let container_name = label.to_owned();
    let archive = downloads.regular(OsStr::new(&download_name))?;
    let extracted = extract_archive(
        archive,
        extractions,
        &work_path.join("archive-extraction"),
        &container_name,
        root_name,
        pin.bytes,
        &pin.sha256,
        format,
        signals,
        session,
    )?;
    extracted.archive.rename_no_replace(
        &extracted.root_name,
        component_stage,
        OsStr::new(label),
    )?;
    drop(extracted.root);
    drop(extracted.archive);
    drop(extracted.container);
    retire_extraction(
        extractions,
        &work_path.join("archive-extraction"),
        &container_name,
    )?;
    retire_download(
        downloads,
        &work_path.join("downloaded-inputs"),
        &download_name,
    )?;
    if !component_stage_path.join(label).is_absolute() {
        return Err(Refusal::new("component destination path is not absolute"));
    }
    check_workspace(session, signals).map(|_| ())
}

// Keep retained source/destination descriptors and their paths explicit at this boundary.
#[allow(clippy::too_many_arguments)]
fn provision_collector(
    pin: &RemoteArchivePin,
    inventory: &ComponentInventory,
    downloads: &Directory,
    extractions: &Directory,
    component_stage: &Directory,
    component_stage_path: &Path,
    work_path: &Path,
    session: &mut ConsumerSession<'_>,
    curl: &CurlExecutablePin,
    signals: &SigtermGuard,
) -> Result<()> {
    let format = archive_format(&pin.url)?;
    let download_name = format!("collector{}", archive_suffix(format));
    acquire_remote_archive(
        pin,
        &download_name,
        downloads,
        &work_path.join("downloaded-inputs"),
        session,
        curl,
        signals,
    )?;
    let archive = downloads.regular(OsStr::new(&download_name))?;
    let root_name = pin
        .archive_root
        .as_deref()
        .ok_or_else(|| Refusal::new("collector pin omits its archive root"))?;
    let container_name = "collector";
    let extracted = extract_archive(
        archive,
        extractions,
        &work_path.join("archive-extraction"),
        container_name,
        root_name,
        pin.bytes,
        &pin.sha256,
        format,
        signals,
        session,
    )?;
    let workspace = check_workspace(session, signals)?;
    let spec = ComponentInstallSpec {
        destination_name: OsStr::new("collector"),
        files: &inventory.files,
        symlinks: &inventory.symlinks,
        limits: component_install_limits(workspace),
    };
    install_component_profile(&extracted.root, component_stage, spec, || signals.check()).map_err(
        |error| component_install_error("collector profile", component_stage_path, error),
    )?;
    check_workspace(session, signals)?;
    drop(extracted.root);
    drop(extracted.archive);
    drop(extracted.container);
    retire_extraction(
        extractions,
        &work_path.join("archive-extraction"),
        container_name,
    )?;
    retire_download(
        downloads,
        &work_path.join("downloaded-inputs"),
        &download_name,
    )?;
    if !component_stage_path.join("collector").is_absolute() {
        return Err(Refusal::new("collector output path is not absolute"));
    }
    check_workspace(session, signals).map(|_| ())
}

#[allow(
    clippy::too_many_arguments,
    reason = "One pinned local component is extracted into a caller-owned root."
)]
fn provision_local_component(
    source: &Directory,
    source_path: &str,
    expected_bytes: u64,
    expected_sha256: &str,
    expected_root: &str,
    label: &str,
    extractions: &Directory,
    component_stage: &Directory,
    component_stage_path: &Path,
    work_path: &Path,
    session: &mut ConsumerSession<'_>,
    signals: &SigtermGuard,
) -> Result<()> {
    validate_relative_inventory_path(source_path)?;
    let archive = open_source_file(source, source_path)?;
    let format = archive_format(source_path)?;
    let container_name = label.to_owned();
    let extracted = extract_archive(
        archive,
        extractions,
        &work_path.join("archive-extraction"),
        &container_name,
        expected_root,
        expected_bytes,
        expected_sha256,
        format,
        signals,
        session,
    )?;
    extracted.archive.rename_no_replace(
        &extracted.root_name,
        component_stage,
        OsStr::new(label),
    )?;
    drop(extracted.root);
    drop(extracted.archive);
    drop(extracted.container);
    retire_extraction(
        extractions,
        &work_path.join("archive-extraction"),
        &container_name,
    )?;
    if !component_stage_path.join(label).is_absolute() {
        return Err(Refusal::new(format!("{label} output path is not absolute")));
    }
    check_workspace(session, signals).map(|_| ())
}

// Keep retained source/destination descriptors and their paths explicit at this boundary.
#[allow(clippy::too_many_arguments)]
fn provision_cargo(
    installation: &CheckedNativeInstallation,
    runtime: &Value,
    host: Host,
    inventory: &ComponentInventory,
    downloads: &Directory,
    component_stage: &Directory,
    component_stage_path: &Path,
    session: &mut ConsumerSession<'_>,
    signals: &SigtermGuard,
) -> Result<()> {
    let asset = cargo_asset(runtime, host)?;
    let path = string(asset, "path")?;
    if path != format!("cargo-{}.tar.xz", host_key(host)) {
        return Err(Refusal::new("compiled Cargo payload asset path changed"));
    }
    let expected_bytes = counter(asset, "bytes")?;
    let expected_sha = string(asset, "sha256")?;
    let raw = installation.read_file(&format!("payload/{path}"))?;
    if raw.len() as u64 != expected_bytes || sha256_bytes(&raw) != expected_sha {
        return Err(Refusal::new(
            "retained Cargo payload differs from compiled pin",
        ));
    }
    let current = check_workspace(session, signals)?;
    check_projected_workspace(current, expected_bytes)?;
    let filename = OsString::from(path);
    let mut archive = downloads.create_new_file(&filename, 0o600)?;
    archive.write_all(&raw)?;
    archive.sync_all()?;
    drop(archive);
    check_workspace(session, signals)?;
    let archive = downloads.regular(&filename)?;
    let spec = CargoArchiveSpec {
        destination_name: OsStr::new("cargo"),
        compressed_bytes: expected_bytes,
        compressed_sha256: expected_sha,
        files: &inventory.files,
        links: &inventory.symlinks,
    };
    extract_flat_cargo_archive(archive, component_stage, spec, || signals.check()).map_err(
        |error| cargo_archive_error("Cargo payload", &component_stage_path.join("cargo"), error),
    )?;
    check_workspace(session, signals)?;
    retire_download(
        downloads,
        &session.path().join("provision-work/downloaded-inputs"),
        path,
    )?;
    if !component_stage_path.join("cargo").is_absolute() {
        return Err(Refusal::new("Cargo output path is not absolute"));
    }
    check_workspace(session, signals).map(|_| ())
}

fn cargo_asset(runtime: &Value, host: Host) -> Result<&Value> {
    let assets = array(field(
        field(runtime, "authenticated_bundle_cargo_assets")?,
        "assets",
    )?)?;
    let expected = format!("cargo-{}.tar.xz", host_key(host));
    assets
        .iter()
        .find(|asset| asset.get("path").and_then(Value::as_str) == Some(expected.as_str()))
        .ok_or_else(|| Refusal::new("compiled initial baseline omits host Cargo payload"))
}

fn acquire_remote_archive(
    pin: &RemoteArchivePin,
    filename: &str,
    downloads: &Directory,
    downloads_path: &Path,
    session: &ConsumerSession<'_>,
    curl: &CurlExecutablePin,
    signals: &SigtermGuard,
) -> Result<()> {
    signals.check()?;
    let current = check_workspace(session, signals)?;
    check_projected_workspace(current, pin.bytes)?;
    let (origin, redirects) = url_origin(&pin.url)?;
    let download_pin = DownloadPin::new(
        pin.url.clone(),
        pin.bytes,
        pin.sha256.clone(),
        origin,
        redirects.iter().copied(),
    )?;
    let path = downloads_path.join(filename);
    let destination: FreshTarget = ownership::fresh_output(&path)?;
    let observation = AcquisitionObservationConfig {
        resource_limits: crate::resource_capture::ResourceLimits {
            max_visible_rss_bytes: 4 * 1024 * 1024 * 1024,
            max_workspace_bytes: WORKSPACE_LIMIT,
            max_log_bytes: 16 * 1024 * 1024,
        },
        sample_limits: crate::resource_capture::SampleLimits {
            max_ps_bytes: 2 * 1024 * 1024,
            max_ps_rows: 32_768,
            max_history_entries: 131_072,
            max_roots: 1,
            scan: TREE_SCAN_LIMITS,
        },
        required_roots: vec![session.path().to_path_buf()],
    };
    let result = acquire_pinned_download(
        &download_pin,
        curl,
        &destination,
        DownloadLimits {
            max_bytes: pin.bytes,
            total_timeout: DOWNLOAD_TOTAL_TIMEOUT,
            per_hop_timeout: DOWNLOAD_HOP_TIMEOUT,
            termination_grace: Duration::from_secs(2),
            max_redirects: 5,
            max_header_bytes: 64 * 1024,
            max_stderr_bytes: 64 * 1024,
        },
        &observation,
        || signals.requested(),
    )?;
    if result.bytes != pin.bytes || result.sha256 != pin.sha256 {
        return Err(Refusal::new("download result differs from its exact pin"));
    }
    let file = downloads.regular(OsStr::new(filename))?;
    if file.metadata()?.len() != pin.bytes {
        return Err(Refusal::new(
            "downloaded archive size changed after publication",
        ));
    }
    drop(file);
    check_workspace(session, signals)?;
    Ok(())
}

// Keep retained source/destination descriptors and their paths explicit at this boundary.
#[allow(clippy::too_many_arguments)]
fn extract_archive(
    archive: File,
    extraction_parent: &Directory,
    extraction_parent_path: &Path,
    container_name: &str,
    expected_root: &str,
    compressed_bytes: u64,
    compressed_sha256: &str,
    format: ArchiveFormat,
    signals: &SigtermGuard,
    session: &ConsumerSession<'_>,
) -> Result<ExtractedComponent> {
    validate_archive_root(expected_root)?;
    let container_os = OsStr::new(container_name);
    extraction_parent.mkdir_new(container_os, 0o700)?;
    let container = extraction_parent.child(container_os)?;
    let current = check_workspace(session, signals)?;
    let receipt = extract_component_archive(
        archive,
        &container,
        ComponentArchiveSpec {
            destination_name: OsStr::new("archive"),
            compressed_bytes,
            compressed_sha256,
            format,
            limits: archive_limits(current, compressed_bytes),
        },
        || signals.check(),
    )
    .map_err(|error| {
        component_archive_error(
            container_name,
            &extraction_parent_path.join(container_name),
            error,
        )
    })?;
    if receipt.component_root != expected_root {
        return Err(Refusal::new(format!(
            "{container_name} archive root {:?} differs from pinned root {:?}; retained extraction: {}",
            receipt.component_root,
            expected_root,
            extraction_parent_path
                .join(container_name)
                .join("archive")
                .display()
        )));
    }
    let root_name = OsString::from(expected_root);
    let archive_root = container.child(OsStr::new("archive"))?;
    let root = archive_root.child(OsStr::new(expected_root))?;
    let root_path = extraction_parent_path
        .join(container_name)
        .join("archive")
        .join(expected_root);
    check_workspace(session, signals)?;
    Ok(ExtractedComponent {
        container,
        archive: archive_root,
        root_name,
        root_path,
        root,
    })
}

impl ExtractedComponent {
    fn root_path(&self) -> PathBuf {
        self.root_path.clone()
    }
}

fn retire_extraction(parent: &Directory, parent_path: &Path, name: &str) -> Result<()> {
    parent
        .remove_tree(OsStr::new(name), ARCHIVE_MEMBER_LIMIT.saturating_add(1))
        .map_err(|error| {
            Refusal::new(format!(
                "could not fully retire private extraction {}: {error}",
                parent_path.join(name).display()
            ))
        })
}

fn retire_download(parent: &Directory, parent_path: &Path, name: &str) -> Result<()> {
    parent.unlink_entry(OsStr::new(name)).map_err(|error| {
        Refusal::new(format!(
            "could not retire private downloaded archive {}: {error}",
            parent_path.join(name).display()
        ))
    })
}

// Keep retained source/destination descriptors and their paths explicit at this boundary.
#[allow(clippy::too_many_arguments)]
fn verify_six_components(
    roots: &ComponentRoots,
    component_stage: &Directory,
    component_stage_path: &Path,
    _source: &Directory,
    source_path: &Path,
    installation_path: &Path,
    inventories: &BTreeMap<String, ComponentInventory>,
    session: &ConsumerSession<'_>,
    signals: &SigtermGuard,
) -> Result<BTreeMap<String, Measurement>> {
    let entries = roots.entries();
    if entries.len() != COMPONENT_NAMES.len() {
        return Err(Refusal::new("consumer component root set is incomplete"));
    }
    let mut seen_paths = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut measurements = BTreeMap::new();
    for (name, path) in entries {
        let expected_path = component_stage_path.join(name);
        if path != expected_path.as_path()
            || !path.is_absolute()
            || !seen_paths.insert(path.to_path_buf())
        {
            return Err(Refusal::new(format!(
                "consumer {name} root is not a distinct component-staging child"
            )));
        }
        ownership::require_disjoint(path, source_path, "component root overlaps source checkout")?;
        ownership::require_disjoint(
            path,
            installation_path,
            "component root overlaps the retained SDK installation",
        )?;
        let retained = component_stage.child(OsStr::new(name))?;
        let metadata = retained.metadata()?;
        if !metadata.is_dir() || !identities.insert((metadata.dev(), metadata.ino())) {
            return Err(Refusal::new(
                "consumer component roots are not six distinct directories",
            ));
        }
        let source_metadata = _source.metadata()?;
        if !source_metadata.is_dir() {
            return Err(Refusal::new("retained source checkout changed type"));
        }
        let reopened_root = Directory::open(path)?;
        let reopened_metadata = reopened_root.metadata()?;
        if reopened_metadata.dev() != metadata.dev() || reopened_metadata.ino() != metadata.ino() {
            return Err(Refusal::new(format!(
                "consumer {name} root pathname changed after staging"
            )));
        }
        let inventory = inventories
            .get(name)
            .ok_or_else(|| Refusal::new(format!("admitted SDK omits {name} inventory")))?;
        let measurement = verify_complete_directory_checked(
            &retained,
            &inventory.files,
            &inventory.symlinks,
            INVENTORY_LIMITS,
            || signals.check(),
        )?;
        measurements.insert(name.to_owned(), measurement);
        check_workspace(session, signals)?;
    }
    if measurements.len() != COMPONENT_NAMES.len() {
        return Err(Refusal::new(
            "consumer component verification is incomplete",
        ));
    }
    Ok(measurements)
}

fn component_install_limits(current_workspace_bytes: u64) -> ComponentInstallLimits {
    ComponentInstallLimits {
        max_tree_entries: ARCHIVE_MEMBER_LIMIT,
        max_path_bytes: ARCHIVE_PATH_LIMIT,
        max_path_components: ARCHIVE_PATH_COMPONENT_LIMIT,
        max_file_bytes: EXPANDED_ARCHIVE_LIMIT,
        max_expanded_bytes: EXPANDED_ARCHIVE_LIMIT,
        current_workspace_bytes,
        max_workspace_bytes: WORKSPACE_LIMIT,
        max_link_target_bytes: ARCHIVE_PATH_LIMIT,
        max_link_resolution_steps: ARCHIVE_MEMBER_LIMIT,
    }
}

fn archive_limits(current_workspace_bytes: u64, compressed_bytes: u64) -> ArchiveLimits {
    ArchiveLimits {
        max_compressed_bytes: compressed_bytes,
        max_decoded_tar_bytes: WORKSPACE_LIMIT,
        max_expanded_bytes: EXPANDED_ARCHIVE_LIMIT,
        max_file_bytes: EXPANDED_ARCHIVE_LIMIT,
        max_members: ARCHIVE_MEMBER_LIMIT,
        max_index_bytes: ARCHIVE_INDEX_LIMIT,
        max_path_bytes: ARCHIVE_PATH_LIMIT,
        max_path_components: ARCHIVE_PATH_COMPONENT_LIMIT,
        max_extension_bytes: ARCHIVE_EXTENSION_LIMIT,
        current_workspace_bytes,
        max_workspace_bytes: WORKSPACE_LIMIT,
        xz_memory_limit_kib: XZ_MEMORY_LIMIT_KIB,
    }
}

fn check_workspace(session: &ConsumerSession<'_>, signals: &SigtermGuard) -> Result<u64> {
    signals.check()?;
    session.recheck_root()?;
    let root = ownership::existing_private_state(session.path())?;
    let accounting = workspace_accounting::scan_directory(&root, TREE_SCAN_LIMITS)
        .map_err(|error| Refusal::new(format!("consumer workspace scan failed: {error}")))?;
    if accounting.regular_file_bytes > WORKSPACE_LIMIT {
        return Err(Refusal::new(format!(
            "consumer managed workspace exceeds the accepted 12 GiB ceiling: {} bytes",
            accounting.regular_file_bytes
        )));
    }
    signals.check()?;
    session.recheck_root()?;
    Ok(accounting.regular_file_bytes)
}

fn check_projected_workspace(current: u64, additional: u64) -> Result<()> {
    if current
        .checked_add(additional)
        .is_none_or(|projected| projected > WORKSPACE_LIMIT)
    {
        return Err(Refusal::new(
            "consumer provisioning would exceed the accepted 12 GiB workspace ceiling",
        ));
    }
    Ok(())
}

fn read_source_file(
    source: &Directory,
    relative: &str,
    expected_bytes: u64,
    expected_sha256: &str,
    read_limit: usize,
) -> Result<Vec<u8>> {
    validate_relative_inventory_path(relative)?;
    if !is_sha256_digest(expected_sha256) {
        return Err(Refusal::new(
            "source file pin has a malformed SHA-256 digest",
        ));
    }
    let file = open_source_file(source, relative)?;
    if file.metadata()?.len() != expected_bytes {
        return Err(Refusal::new(format!(
            "source file size differs from its pin: {relative}"
        )));
    }
    let bytes = crate::publisher_files::read_open_regular(file, read_limit)?;
    if bytes.len() as u64 != expected_bytes || sha256_bytes(&bytes) != expected_sha256 {
        return Err(Refusal::new(format!(
            "source file bytes differ from their pin: {relative}"
        )));
    }
    Ok(bytes)
}

fn open_source_file(source: &Directory, relative: &str) -> Result<File> {
    validate_relative_inventory_path(relative)?;
    let (parent, leaf) = relative.rsplit_once('/').unwrap_or(("", relative));
    source.relative_directory(parent)?.regular(OsStr::new(leaf))
}

fn remote_pin(
    row: &Value,
    required_root: Option<&str>,
    archive_root: &str,
) -> Result<RemoteArchivePin> {
    let url = string(row, "url")?.to_owned();
    archive_format(&url)?;
    let bytes = counter(row, "bytes")?;
    if bytes == 0 || bytes > EXPANDED_ARCHIVE_LIMIT {
        return Err(Refusal::new(
            "remote archive exceeds accepted source byte bound",
        ));
    }
    let sha256 = string(row, "sha256")?.to_owned();
    if !is_sha256_digest(&sha256) {
        return Err(Refusal::new("remote archive has malformed SHA-256 digest"));
    }
    if let Some(expected) = required_root
        && string(row, "archive_root")? != expected
    {
        return Err(Refusal::new(
            "remote archive root differs from accepted profile",
        ));
    }
    validate_archive_root(archive_root)?;
    Ok(RemoteArchivePin {
        url,
        bytes,
        sha256,
        archive_root: Some(archive_root.to_owned()),
    })
}

fn url_origin(url: &str) -> Result<(HttpsOrigin, &'static [HttpsOrigin])> {
    if url.starts_with("https://static.rust-lang.org/") {
        Ok((HttpsOrigin::StaticRustLang, &[]))
    } else if url.starts_with("https://github.com/") {
        Ok((
            HttpsOrigin::Github,
            &[HttpsOrigin::GithubReleaseAssets, HttpsOrigin::GithubObjects],
        ))
    } else {
        Err(Refusal::new(
            "archive URL is outside accepted HTTPS origins",
        ))
    }
}

fn archive_format(url_or_path: &str) -> Result<ArchiveFormat> {
    if url_or_path.ends_with(".tar.gz") {
        Ok(ArchiveFormat::TarGzip)
    } else if url_or_path.ends_with(".tar.xz") {
        Ok(ArchiveFormat::TarXz)
    } else {
        Err(Refusal::new(
            "accepted component archive must end in .tar.gz or .tar.xz",
        ))
    }
}

fn validate_archive_root(root: &str) -> Result<()> {
    validate_relative_inventory_path(root)?;
    if root.contains('/') || root.contains('\\') {
        return Err(Refusal::new(
            "component archive root must be one portable path component",
        ));
    }
    Ok(())
}

fn archive_suffix(format: ArchiveFormat) -> &'static str {
    match format {
        ArchiveFormat::Tar => ".tar",
        ArchiveFormat::TarGzip => ".tar.gz",
        ArchiveFormat::TarXz => ".tar.xz",
    }
}

fn rust_archive_root(component: &str, target: &str) -> String {
    if component == "rust-src" {
        "rust-src-nightly".to_owned()
    } else {
        format!("{component}-nightly-{target}")
    }
}

fn expected_rust_admin_paths(target: &str) -> Vec<String> {
    let mut paths: Vec<String> = RUST_ADMIN_FILES_PREFIX
        .iter()
        .map(|path| (*path).to_owned())
        .collect();
    paths.push(format!("lib/rustlib/manifest-rust-std-{target}"));
    paths.push("lib/rustlib/manifest-rustc".to_owned());
    paths
}

fn rust_target(host: Host) -> &'static str {
    match host {
        Host::LinuxX86_64 => "x86_64-unknown-linux-gnu",
        Host::MacosAarch64 => "aarch64-apple-darwin",
    }
}

fn host_key(host: Host) -> &'static str {
    match host {
        Host::LinuxX86_64 => "linux-x86_64",
        Host::MacosAarch64 => "macos-aarch64",
    }
}

fn exact_keys(value: &Value, expected: &[&str], label: &str) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new(format!("{label} must be an object")))?;
    let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = expected.iter().copied().collect();
    if actual != expected {
        return Err(Refusal::new(format!("{label} has an unexpected field set")));
    }
    Ok(())
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| Refusal::new(format!("checked source pin omits {key}")))
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    field(value, key)?
        .as_str()
        .ok_or_else(|| Refusal::new(format!("checked source pin field {key} is not a string")))
}

fn counter(value: &Value, key: &str) -> Result<u64> {
    field(value, key)?
        .as_u64()
        .ok_or_else(|| Refusal::new(format!("checked source pin field {key} is not a counter")))
}

fn array(value: &Value) -> Result<&[Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| Refusal::new("checked source pin field is not an array"))
}

fn string_array(value: &Value) -> Result<Vec<&str>> {
    array(value)?
        .iter()
        .map(|row| {
            row.as_str()
                .ok_or_else(|| Refusal::new("checked source pin array contains a non-string"))
        })
        .collect()
}

fn component_archive_error(
    label: &str,
    container_path: &Path,
    error: crate::component_archive::ComponentArchiveFailure,
) -> Refusal {
    match error.recovery_entry {
        Some(entry) => Refusal::new(format!(
            "{label} extraction failed: {}; retained recovery entry: {}",
            error.reason,
            container_path.join(entry).display()
        )),
        None => Refusal::new(format!("{label} extraction failed: {}", error.reason)),
    }
}

fn component_install_error(
    label: &str,
    parent_path: &Path,
    error: crate::component_install::ComponentInstallFailure,
) -> Refusal {
    match error.recovery_entry {
        Some(entry) => Refusal::new(format!(
            "{label} failed: {}; retained recovery entry: {}",
            error.reason,
            parent_path.join(entry).display()
        )),
        None => Refusal::new(format!("{label} failed: {}", error.reason)),
    }
}

fn cargo_archive_error(
    label: &str,
    destination_path: &Path,
    error: crate::cargo_archive::CargoArchiveFailure,
) -> Refusal {
    match error.recovery_entry {
        Some(entry) => Refusal::new(format!(
            "{label} extraction failed: {}; retained recovery entry: {}",
            error.reason,
            destination_path
                .parent()
                .unwrap_or(destination_path)
                .join(entry)
                .display()
        )),
        None => Refusal::new(format!("{label} extraction failed: {}", error.reason)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_component_order_roots_and_admin_paths_match_both_accepted_targets() {
        for (host, target) in [
            (Host::LinuxX86_64, "x86_64-unknown-linux-gnu"),
            (Host::MacosAarch64, "aarch64-apple-darwin"),
        ] {
            assert_eq!(
                host_key(host),
                match host {
                    Host::LinuxX86_64 => "linux-x86_64",
                    Host::MacosAarch64 => "macos-aarch64",
                }
            );
            assert_eq!(RUST_COMPONENTS, ["rustc", "rust-std", "rust-src", "cargo"]);
            assert_eq!(rust_archive_root("rust-src", target), "rust-src-nightly");
            assert_eq!(
                rust_archive_root("rustc", target),
                format!("rustc-nightly-{target}")
            );
            let admin = expected_rust_admin_paths(target);
            assert_eq!(admin.len(), 5);
            assert!(admin.contains(&format!("lib/rustlib/manifest-rust-std-{target}")));
        }
    }

    #[test]
    fn collector_profiles_keep_exact_platform_file_counts() {
        let file = |path: &str| FileIdentity {
            path: path.to_owned(),
            bytes: 1,
            sha256: "a".repeat(64),
            mode: None,
        };
        let linux = ComponentInventory {
            files: (0..10)
                .map(|index| file(&format!("bin/tool-{index}")))
                .collect(),
            symlinks: Vec::new(),
        };
        let mac = ComponentInventory {
            files: vec![file("bin/aros-collect")],
            symlinks: Vec::new(),
        };
        assert!(validate_collector_profile(&linux, Host::LinuxX86_64).is_ok());
        assert!(validate_collector_profile(&mac, Host::MacosAarch64).is_ok());
        assert!(validate_collector_profile(&mac, Host::LinuxX86_64).is_err());
    }

    #[test]
    fn cargo_inventory_has_only_the_two_pinned_flat_members() {
        let inventory = ComponentInventory {
            files: vec![
                FileIdentity {
                    path: "bin/cargo".to_owned(),
                    bytes: 1,
                    sha256: "a".repeat(64),
                    mode: Some(0o755),
                },
                FileIdentity {
                    path: "producer.json".to_owned(),
                    bytes: 2,
                    sha256: "b".repeat(64),
                    mode: Some(0o644),
                },
            ],
            symlinks: Vec::new(),
        };
        assert!(validate_cargo_profile(&inventory).is_ok());
        let mut extra = inventory;
        extra.files.push(FileIdentity {
            path: "bin/rustc".to_owned(),
            bytes: 1,
            sha256: "c".repeat(64),
            mode: None,
        });
        assert!(validate_cargo_profile(&extra).is_err());
    }

    #[test]
    fn accepted_host_plan_refuses_source_rows_that_differ_from_compiled_pins() {
        let baseline = InitialBaseline::load().unwrap();
        let runtime = baseline.runtime_acquisition();
        let source = parse_json_value(
            include_bytes!("../../../../release/ci-sdk-inputs.json"),
            JsonProfile::SdkComponentManifest,
        )
        .unwrap();
        let plan = runtime_host_plan(&source, runtime, Host::LinuxX86_64).unwrap();
        assert_eq!(plan.rust.archives.len(), 4);
        assert_eq!(plan.csdk_root, "Developer");
        let mut changed = source;
        changed["hosts"]["linux-x86_64"]["collector"]["sha256"] = Value::String("0".repeat(64));
        assert!(runtime_host_plan(&changed, runtime, Host::LinuxX86_64).is_err());
    }
}
