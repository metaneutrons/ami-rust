//! Build a private, explicitly synthetic v1 project fixture against a real
//! currently installed native baseline. This does not represent old release
//! bytes and does not establish historical migration acceptance.

use ami_rust_core::{
    Refusal, Result,
    baseline::InitialBaseline,
    digest::{is_sha256_digest, sha256_bytes},
    directory::Directory,
    files::{read_regular_bounded, validate_relative_inventory_path},
    host_platform,
    json::{JsonProfile, parse_json_value},
    native_install::CheckedNativeInstallation,
    ownership,
    ready_state::installed_prefix,
    records::{StateStatus, parse_package_state, parse_selection},
    selected_inputs::verify_selection,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

const OPTIONS: [&str; 5] = [
    "--install-prefix",
    "--selection",
    "--python",
    "--project",
    "--output",
];
const PYTHON_BYTES_MAX: usize = 64 * 1024 * 1024;
const PROJECT_TEXT_MAX: usize = 4 * 1024 * 1024;
const COMPONENT_MANIFEST_TOTAL_MAX: usize = 8 * 1024 * 1024;
const SDK_SOURCE_FILE_LIMIT: usize = 1_000;
const SDK_SOURCE_BYTE_LIMIT: u64 = 8 * 1024 * 1024;
const SDK_SOURCE_ENTRY_LIMIT: usize = 100_000;
const COMPONENTS: [&str; 6] = ["rust", "cargo", "toolchain", "collector", "csdk", "vendor"];

/// Create synthetic legacy metadata and a conventional v1 lock in `--output`.
/// Component roots, SDK recipe identities and the receipt come from a checked,
/// ready native state. No interpreter, compiler, cargo command or driver runs.
pub fn run(mut args: impl Iterator<Item = OsString>) -> Result<()> {
    let mut options = BTreeMap::new();
    while let Some(key) = args.next() {
        if !OPTIONS.iter().any(|allowed| key == *allowed) {
            return Err(Refusal::new("unknown legacy-migration-fixture option"));
        }
        let value = args
            .next()
            .ok_or_else(|| Refusal::new("legacy-migration-fixture option requires a value"))?;
        if options.insert(key, value).is_some() {
            return Err(Refusal::new(
                "legacy-migration-fixture options may occur only once",
            ));
        }
    }
    let install_prefix = PathBuf::from(take(&mut options, "--install-prefix")?);
    let selection_path = PathBuf::from(take(&mut options, "--selection")?);
    let python_arg = PathBuf::from(take(&mut options, "--python")?);
    let current_project = PathBuf::from(take(&mut options, "--project")?);
    let area = PathBuf::from(take(&mut options, "--output")?);
    if !options.is_empty() {
        return Err(Refusal::new("unexpected legacy-migration-fixture options"));
    }

    let host = host_platform::supported_host()?;
    let install_prefix = canonical_directory(&install_prefix, "install prefix")?;
    let state_root = canonical_directory(
        install_prefix
            .parent()
            .ok_or_else(|| Refusal::new("install prefix has no state parent"))?,
        "ready state",
    )?;
    ownership::existing_private_state(&state_root)?;
    let selection_path = canonical_file(&selection_path, "selection")?;
    if selection_path != state_root.join("selection.json") {
        return Err(Refusal::new(
            "selection must be the current ready state's selection.json",
        ));
    }
    let ready_bytes = read_regular_bounded(
        &state_root.join("ready.json"),
        JsonProfile::PackageMetadataStateSelection.max_bytes(),
    )?;
    let ready = parse_package_state(&ready_bytes)?;
    if ready.status != StateStatus::Ready
        || ready.host != host
        || installed_prefix(&state_root, &ready.sdk_version)? != install_prefix
    {
        return Err(Refusal::new(
            "install prefix is not the current host's ready SDK installation",
        ));
    }

    let selection_bytes = read_regular_bounded(
        &selection_path,
        JsonProfile::PackageMetadataStateSelection.max_bytes(),
    )?;
    let selection = parse_selection(&selection_bytes)?;
    if selection.host != host
        || selection.install_receipt_sha256.as_str() != ready.install_receipt_sha256.as_str()
    {
        return Err(Refusal::new(
            "selection does not match the ready state's host and receipt",
        ));
    }
    let pin_path = state_root.join("receipt.sha256");
    let pin_bytes = read_regular_bounded(&pin_path, 128)?;
    let pin_digest = parse_receipt_pin(&pin_bytes)?;
    if pin_digest != selection.install_receipt_sha256.as_str() {
        return Err(Refusal::new(
            "external receipt pin differs from ready selection",
        ));
    }
    let installation = CheckedNativeInstallation::open(&install_prefix, pin_digest)?;
    if installation.receipt().version != ready.sdk_version
        || installation.receipt().release_manifest_sha256 != ready.manifest_sha256
    {
        return Err(Refusal::new(
            "ready state differs from the externally pinned installation",
        ));
    }
    let recipe = InitialBaseline::load()?.admit_initial_sdk(&installation, host)?;
    let selected = verify_selection(&installation, &selection)?;
    selected.recheck()?;

    let current_project = canonical_directory(&current_project, "current project")?;
    let project_owner = ownership::existing_private_state(&current_project)?
        .metadata()?
        .uid();
    let cargo_toml = read_text(&current_project.join("Cargo.toml"), "Cargo.toml")?;
    let cargo_lock = read_text(&current_project.join("Cargo.lock"), "Cargo.lock")?;
    let lib_rs = read_text(&current_project.join("src/lib.rs"), "src/lib.rs")?;

    let python = canonical_file(&python_arg, "coordinator Python")?;
    // The pinned historical interpreter is inert data and has mode 0775.
    // Match the migration reader's data policy without relaxing executable
    // trust checks or changing the preserved bootstrap input.
    let python_parent = Directory::open(
        python
            .parent()
            .ok_or_else(|| Refusal::new("coordinator Python has no parent"))?,
    )?;
    let mut python_file = python_parent.regular(
        python
            .file_name()
            .ok_or_else(|| Refusal::new("coordinator Python has no filename"))?,
    )?;
    let python_metadata = python_file.metadata()?;
    if ![0, project_owner].contains(&python_metadata.uid())
        || python_metadata.mode() & 0o6002 != 0
        || python_metadata.nlink() != 1
        || python_metadata.len() > PYTHON_BYTES_MAX as u64
    {
        return Err(Refusal::new(
            "coordinator Python identity exceeds its bounded regular-file profile",
        ));
    }
    let mut python_bytes = Vec::new();
    (&mut python_file)
        .take(PYTHON_BYTES_MAX as u64 + 1)
        .read_to_end(&mut python_bytes)?;
    let python_after = python_file.metadata()?;
    if python_bytes.len() > PYTHON_BYTES_MAX
        || python_after.len() != python_metadata.len()
        || python_after.mtime() != python_metadata.mtime()
        || python_after.mtime_nsec() != python_metadata.mtime_nsec()
        || python_after.ctime() != python_metadata.ctime()
        || python_after.ctime_nsec() != python_metadata.ctime_nsec()
    {
        return Err(Refusal::new("inert Python identity changed while reading"));
    }
    let python_sha256 = sha256_bytes(&python_bytes);

    let _fresh_area = ownership::fresh_private_state(&area)?;
    ownership::require_disjoint(&area, &state_root, "fixture output overlaps ready state")?;
    ownership::require_disjoint(
        &area,
        &current_project,
        "fixture output overlaps current project",
    )?;
    ownership::require_disjoint(
        &area,
        &install_prefix,
        "fixture output overlaps installed SDK",
    )?;
    ownership::require_disjoint(&area, &python, "fixture output overlaps coordinator Python")?;
    for (_, root) in selection.components.entries() {
        ownership::require_disjoint(&area, root, "fixture output overlaps selected components")?;
    }
    let area_text = path_text(&area)?;

    create_private_dir(&area)?;
    let report = build_fixture(
        &area,
        &selection_path,
        &current_project,
        &cargo_toml,
        &cargo_lock,
        &lib_rs,
        &selection,
        &selected,
        &installation,
        &recipe,
        host,
        &python,
        &python_sha256,
        &ready_bytes,
        &selection_bytes,
        &pin_path,
        pin_digest,
    );
    let report = report.map_err(|error| {
        Refusal::new(format!("{error}; partial fixture retained at {area_text}"))
    })?;
    println!(
        "{}",
        serde_json::to_string(&report)
            .map_err(|error| Refusal::new(format!("could not encode fixture result: {error}")))?
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_fixture(
    area: &Path,
    selection_path: &Path,
    current_project: &Path,
    cargo_toml: &[u8],
    cargo_lock: &[u8],
    lib_rs: &[u8],
    selection: &ami_rust_core::records::SelectionV2,
    selected: &ami_rust_core::selected_inputs::SelectedInputs,
    installation: &CheckedNativeInstallation,
    recipe: &ami_rust_core::sdk::InstalledSdkRecipe,
    host: ami_rust_core::records::Host,
    python: &Path,
    python_sha256: &str,
    ready_bytes: &[u8],
    selection_bytes: &[u8],
    pin_path: &Path,
    pin_digest: &str,
) -> Result<Value> {
    let project = area.join("project");
    let sdk = area.join("legacy-sdk");
    create_private_dir(&project)?;
    create_private_dir(&project.join("src"))?;
    create_private_dir(&sdk)?;
    create_private_dir(&sdk.join("contract"))?;
    create_private_dir(&sdk.join("host"))?;
    create_private_dir(&sdk.join("host/profiles"))?;
    let profile_root = sdk.join("host/profiles").join(host_name(host));
    create_private_dir(&profile_root)?;

    write_private_new(&project.join("Cargo.toml"), cargo_toml)?;
    write_private_new(&project.join("Cargo.lock"), cargo_lock)?;
    write_private_new(&project.join("src/lib.rs"), lib_rs)?;
    let (sdk_source_files, sdk_source_bytes) = copy_sdk_source_tree(
        &current_project.join("sdk-source"),
        &project.join("sdk-source"),
    )?;

    let sdk_manifest_raw = installation.read_file("sdk/contract/sdk.json")?;
    let sdk_manifest = parse_json_value(&sdk_manifest_raw, JsonProfile::SdkComponentManifest)?;
    let profile = sdk_manifest
        .get("profiles")
        .and_then(|profiles| profiles.get(host_name(host)))
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new("installed SDK omits the current profile"))?;
    let cargo_binary = text_field(profile, "cargo_binary")?;
    let cargo_metadata_mode = text_field(profile, "cargo_metadata_mode")?;
    let rust_host = text_field(profile, "rust_host")?;
    let collector_binary = text_field(profile, "collector_binary")?;
    validate_relative_inventory_path(cargo_binary)?;
    validate_relative_inventory_path(collector_binary)?;
    if cargo_metadata_mode != "ami-rust-reproducible-cross-v1" {
        return Err(Refusal::new(
            "installed SDK Cargo metadata mode is not supported by legacy migration",
        ));
    }

    let mut component_rows = serde_json::Map::new();
    let mut sdk_files = Vec::new();
    let mut component_roots = serde_json::Map::new();
    let mut copied_bytes = 0_usize;
    for name in COMPONENTS {
        let (manifest_path, expected_digest) = recipe
            .component_manifests
            .get(name)
            .ok_or_else(|| Refusal::new(format!("installed SDK omits {name} inventory")))?;
        let expected_path = format!("host/profiles/{}/{name}.json", host_name(host));
        if manifest_path != &expected_path {
            return Err(Refusal::new(format!(
                "installed {name} inventory path differs from the current profile"
            )));
        }
        validate_relative_inventory_path(manifest_path)?;
        let raw = installation.read_file(&format!("sdk/{manifest_path}"))?;
        if sha256_bytes(&raw).as_str() != expected_digest.as_str() {
            return Err(Refusal::new(format!(
                "installed {name} inventory changed before fixture construction"
            )));
        }
        copied_bytes = copied_bytes
            .checked_add(raw.len())
            .filter(|total| *total <= COMPONENT_MANIFEST_TOTAL_MAX)
            .ok_or_else(|| Refusal::new("component inventory fixture exceeds its byte limit"))?;
        let destination = sdk.join(manifest_path);
        write_private_new(&destination, &raw)?;
        sdk_files.push(json!({
            "path": manifest_path,
            "bytes": raw.len(),
            "sha256": expected_digest
        }));
        component_rows.insert(
            name.to_owned(),
            json!({"manifest": manifest_path, "sha256": expected_digest}),
        );
        let root = selection
            .components
            .entries()
            .into_iter()
            .find_map(|(selected_name, root)| (selected_name == name).then_some(root))
            .ok_or_else(|| Refusal::new("selection omits a required component root"))?;
        component_roots.insert(name.to_owned(), json!(path_text(root)?));
    }

    let sdk_version = "0.1.0-synthetic-compatible";
    let legacy_sdk = json!({
        "schema": "ami-rust-sdk-v1",
        "version": sdk_version,
        "rust_commit": recipe.rust_commit,
        "rust_llvm": recipe.rust_llvm,
        "source_date_epoch": recipe.source_date_epoch,
        "files": sdk_files,
        "profiles": {
            host_name(host): {
                "rust_host": rust_host,
                "cargo_binary": cargo_binary,
                "collector_binary": collector_binary,
                "cargo_metadata_mode": cargo_metadata_mode,
                "components": component_rows
            }
        }
    });
    let legacy_sdk_raw = serde_json::to_vec_pretty(&legacy_sdk).map_err(|error| {
        Refusal::new(format!("could not encode synthetic SDK manifest: {error}"))
    })?;
    let legacy_sdk_sha256 = sha256_bytes(&legacy_sdk_raw);
    write_private_new(&sdk.join("contract/sdk.json"), &legacy_sdk_raw)?;

    let lock = json!({
        "schema": "ami-rust-project-lock-v1",
        "sdk": {
            "root": path_text(&sdk)?,
            "manifest": "contract/sdk.json",
            "manifest_sha256": legacy_sdk_sha256
        },
        "host": {
            "platform": host_name(host),
            "python": path_text(python)?,
            "python_sha256": python_sha256
        },
        "components": component_roots,
        "cargo": {
            "manifest_sha256": sha256_bytes(cargo_toml),
            "lock_sha256": sha256_bytes(cargo_lock)
        }
    });
    let lock_raw = serde_json::to_vec_pretty(&lock).map_err(|error| {
        Refusal::new(format!("could not encode synthetic legacy lock: {error}"))
    })?;
    let from_lock = project.join("ami-rust.lock.json");
    write_private_new(&from_lock, &lock_raw)?;

    // Keep the new lock's writable parent disjoint from every old input bound
    // by the consumer observer.
    let migration_parent = area.join("output");
    create_private_dir(&migration_parent)?;
    let migration_output = migration_parent.join("migrated-v2-lock.json");
    let report_path = area.join("fixture-report.json");
    installation.recheck()?;
    selected.recheck()?;
    let report = json!({
        "schema": "ami-rust-legacy-migration-fixture-v1",
        "status": "SYNTHETIC_BASELINE_COMPATIBLE_FIXTURE_NOT_HISTORICAL_EVIDENCE",
        "project": path_text(&project)?,
        "from_lock": path_text(&from_lock)?,
        "legacy_sdk": path_text(&sdk)?,
        "migration_output": path_text(&migration_output)?,
        "install_prefix": path_text(installation.path())?,
        "receipt_pin": {"path": path_text(pin_path)?, "sha256": pin_digest},
        "selection": {
            "path": path_text(selection_path)?,
            "sha256": sha256_bytes(selection_bytes),
            "component_roots_are_reused_read_only": true
        },
        "ready_state_sha256": sha256_bytes(ready_bytes),
        "legacy_python": {
            "path": path_text(python)?,
            "sha256": python_sha256,
            "executed": false
        },
        "compiler": {
            "rust_commit": recipe.rust_commit,
            "rust_llvm": recipe.rust_llvm,
            "source_date_epoch": recipe.source_date_epoch
        },
        "legacy_sdk_manifest_sha256": legacy_sdk_sha256,
        "component_inventory_bytes": copied_bytes,
        "copied_current_project_files": ["Cargo.toml", "Cargo.lock", "src/lib.rs", "sdk-source/"],
        "sdk_source_copy": {
            "source": path_text(&current_project.join("sdk-source"))?,
            "files": sdk_source_files,
            "bytes": sdk_source_bytes,
            "file_limit": SDK_SOURCE_FILE_LIMIT,
            "byte_limit": SDK_SOURCE_BYTE_LIMIT,
            "entry_limit": SDK_SOURCE_ENTRY_LIMIT
        },
        "excluded_current_v2_files": ["ami-rust.lock.json", "ami-rust-sdk.json"],
        "scope": "Current native installation, receipt, baseline and selected component trees are checked real inputs; v1 SDK/lock metadata is synthetic compatibility data, not a historical release fixture."
    });
    let report_raw = serde_json::to_vec_pretty(&report)
        .map_err(|error| Refusal::new(format!("could not encode fixture report: {error}")))?;
    write_private_new(&report_path, &report_raw)?;
    Ok(report)
}

fn copy_sdk_source_tree(source: &Path, destination: &Path) -> Result<(usize, u64)> {
    let root = Directory::open(source)?;
    if root.metadata()?.mode() & 0o7777 != 0o755 {
        return Err(Refusal::new(
            "current sdk-source root mode is not normalized",
        ));
    }
    create_source_dir(destination, 0o755)?;
    drop(root);
    let mut pending = vec![PathBuf::new()];
    let mut entries = 1_usize;
    let mut files = 0_usize;
    let mut total_bytes = 0_u64;
    let mut has_public_crate_manifest = false;

    while let Some(relative_parent) = pending.pop() {
        let directory = Directory::open(&source.join(&relative_parent))?;
        let names = directory.names(SDK_SOURCE_ENTRY_LIMIT.saturating_sub(entries))?;
        entries = entries
            .checked_add(names.len())
            .filter(|count| *count <= SDK_SOURCE_ENTRY_LIMIT)
            .ok_or_else(|| Refusal::new("sdk-source tree exceeds its entry bound"))?;
        for name in names {
            if name.to_str().is_none() {
                return Err(Refusal::new("sdk-source path is not UTF-8"));
            }
            let relative = relative_parent.join(&name);
            let relative_text = relative
                .to_str()
                .ok_or_else(|| Refusal::new("sdk-source path is not UTF-8"))?;
            validate_relative_inventory_path(relative_text)?;
            let output = destination.join(&relative);

            if let Ok(child) = directory.child(&name) {
                if child.metadata()?.mode() & 0o7777 != 0o755 {
                    return Err(Refusal::new("sdk-source directory mode is not normalized"));
                }
                create_source_dir(&output, 0o755)?;
                drop(child);
                pending.push(relative);
                continue;
            }

            let mut file = directory.regular(&name)?;
            let metadata = file.metadata()?;
            let mode = metadata.mode() & 0o7777;
            if metadata.nlink() != 1 || !matches!(mode, 0o644 | 0o755) {
                return Err(Refusal::new(
                    "sdk-source file link count or mode is not normalized",
                ));
            }
            files = files
                .checked_add(1)
                .filter(|count| *count <= SDK_SOURCE_FILE_LIMIT)
                .ok_or_else(|| Refusal::new("sdk-source tree exceeds its 1000-file bound"))?;
            let remaining = SDK_SOURCE_BYTE_LIMIT
                .checked_sub(total_bytes)
                .ok_or_else(|| Refusal::new("sdk-source byte bound overflow"))?;
            if metadata.len() > remaining {
                return Err(Refusal::new("sdk-source tree exceeds its 8 MiB byte bound"));
            }
            let bytes = read_open_bounded(&mut file, remaining)?;
            if bytes.len() as u64 != metadata.len() {
                return Err(Refusal::new("sdk-source file changed while being copied"));
            }
            total_bytes = total_bytes
                .checked_add(bytes.len() as u64)
                .filter(|count| *count <= SDK_SOURCE_BYTE_LIMIT)
                .ok_or_else(|| Refusal::new("sdk-source tree exceeds its 8 MiB byte bound"))?;
            if relative_text == "crates/public/amiga-os/Cargo.toml" {
                has_public_crate_manifest = true;
            }
            write_source_file_new(&output, &bytes, mode)?;
        }
    }
    if files == 0 || !has_public_crate_manifest {
        return Err(Refusal::new(
            "sdk-source tree omits the public amiga-os Cargo package",
        ));
    }
    Ok((files, total_bytes))
}

fn read_open_bounded(file: &mut fs::File, limit: u64) -> Result<Vec<u8>> {
    let limit = usize::try_from(limit)
        .map_err(|_| Refusal::new("sdk-source byte bound is not representable"))?;
    let initial = usize::try_from(file.metadata()?.len())
        .map_err(|_| Refusal::new("sdk-source file length is not representable"))?;
    if initial > limit {
        return Err(Refusal::new(
            "sdk-source file exceeds its remaining byte bound",
        ));
    }
    let read_limit = limit
        .checked_add(1)
        .ok_or_else(|| Refusal::new("sdk-source read bound overflow"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(initial)
        .map_err(|_| Refusal::new("could not allocate bounded sdk-source buffer"))?;
    file.take(read_limit as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(Refusal::new(
            "sdk-source file exceeds its remaining byte bound",
        ));
    }
    Ok(bytes)
}

fn create_source_dir(path: &Path, mode: u32) -> Result<()> {
    fs::DirBuilder::new().mode(mode).create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn write_source_file_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .open(path)?;
    file.write_all(bytes)?;
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    Ok(())
}

fn take(options: &mut BTreeMap<OsString, OsString>, name: &str) -> Result<OsString> {
    options
        .remove(OsStr::new(name))
        .ok_or_else(|| Refusal::new(format!("missing {name}")))
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf> {
    if !path.is_absolute() || fs::canonicalize(path)? != path {
        return Err(Refusal::new(format!(
            "{label} must be canonical and absolute"
        )));
    }
    if !fs::metadata(path)?.is_dir() {
        return Err(Refusal::new(format!("{label} is not a directory")));
    }
    Ok(path.to_path_buf())
}

fn canonical_file(path: &Path, label: &str) -> Result<PathBuf> {
    if !path.is_absolute() || fs::canonicalize(path)? != path || !fs::metadata(path)?.is_file() {
        return Err(Refusal::new(format!(
            "{label} must be a canonical regular file"
        )));
    }
    Ok(path.to_path_buf())
}

fn read_text(path: &Path, label: &str) -> Result<Vec<u8>> {
    let raw = read_regular_bounded(path, PROJECT_TEXT_MAX)?;
    if raw.is_empty() || std::str::from_utf8(&raw).is_err() {
        return Err(Refusal::new(format!("{label} must be nonempty UTF-8 text")));
    }
    Ok(raw)
}

fn parse_receipt_pin(raw: &[u8]) -> Result<&str> {
    let value = raw.strip_suffix(b"\n").unwrap_or(raw);
    let digest = std::str::from_utf8(value)
        .map_err(|_| Refusal::new("external receipt pin is not UTF-8"))?;
    if !is_sha256_digest(digest) {
        return Err(Refusal::new(
            "external receipt pin is not one SHA-256 digest",
        ));
    }
    Ok(digest)
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn path_text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Refusal::new("fixture path is not UTF-8"))
}

fn host_name(host: ami_rust_core::records::Host) -> &'static str {
    match host {
        ami_rust_core::records::Host::LinuxX86_64 => "linux-x86_64",
        ami_rust_core::records::Host::MacosAarch64 => "macos-aarch64",
    }
}

fn text_field<'a>(object: &'a serde_json::Map<String, Value>, key: &str) -> Result<&'a str> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new(format!("installed SDK profile omits {key}")))
}
