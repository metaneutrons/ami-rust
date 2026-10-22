//! Pinned maintainer preparation and verification for the Cargo OpenSSL vendor
//! overlay. The upstream vendor tree is read-only input; successful output is a
//! prerequisite overlay receipt, not SDK or release acceptance.

use crate::{
    Refusal, Result,
    digest::{is_sha256_digest, sha256_bytes, sha256_file},
    directory::{Directory, EntryType},
    files::{open_regular_nofollow, read_regular_bounded, validate_relative_inventory_path},
    json::{JsonProfile, parse_json_value},
    process_capture::{CaptureLimits, CommandSpec, capture},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const PIN_SHA256: &str = "15fbc9da969b32968884c24bf47f2d8b61b8f7d46ac73947faade43569569077";
const PATCH_SHA256: &str = "67f92b277d2cb9508ca3d6d041ebf9feb0ddbf05e97a9419960f313344cd6de8";
const PIN_SCHEMA: &str = "ami-rust-cargo-vendor-overlay-v1";
const RECEIPT_SCHEMA: &str = "ami-rust-cargo-vendor-overlay-receipt-v2";
const CLAIM: &str = "offline prerequisite overlay provisioning, not SDK/R1 acceptance";
const PACKAGE_NAME: &str = "openssl-src";
const PACKAGE_VERSION: &str = "300.6.1+3.6.3";
const PACKAGE_CHECKSUM: &str = "46eb8fb9fb3b61ce1c0f8a026c4c1a0714d3a9e138e7fbde78753ce2babc3846";
const SOURCE_PATH: &str = "openssl-src-300.6.1+3.6.3/src/lib.rs";
const SOURCE_SHA256: &str = "c0f7ee0384ee12835abc6197122dc60ac75e33a3906dfe90bc378e62df56839d";
const PATCHED_SHA256: &str = "992641416caf72adc67e9196ee4e452f5ba284e8586050c9d2ed8bb1d287c1a5";
const PATCH_REPO_PATH: &str = "host/cargo-repro/openssl-paths.patch";
const MAX_TREE_ENTRIES: usize = 100_000;
const MAX_PATCH_BYTES: usize = 16 * 1024 * 1024;
const MAX_CAPTURE_STREAM_BYTES: usize = 8 * 1024 * 1024;
const MAX_TOTAL_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
const MAX_WORKSPACE_BYTES: u64 = 12 * 1024 * 1024 * 1024;
const MAX_ELAPSED: Duration = Duration::from_secs(1_200);
const PATCH_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    path: String,
    bytes: u64,
    mode: u32,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DirectoryIdentity {
    path: String,
    mode: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct VendorInventory {
    root_mode: u32,
    directories: Vec<DirectoryIdentity>,
    files: Vec<FileIdentity>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OverlayReceipt {
    schema: String,
    claim: String,
    overlay_pin_sha256: String,
    patch_sha256: String,
    source_vendor: String,
    output_vendor: String,
    changed_files: Vec<String>,
    original_inventory_sha256: String,
    original_vendor_recheck: String,
    elapsed_seconds: f64,
    source_plus_output_bytes: u64,
    patch_stdout: String,
    patch_stderr: String,
    original_directories: Vec<DirectoryIdentity>,
    directories: Vec<DirectoryIdentity>,
    original_files: Vec<FileIdentity>,
    files: Vec<FileIdentity>,
    original_root_mode: u32,
    root_mode: u32,
}

#[derive(Clone, Debug)]
struct OverlayPlan {
    pin_sha256: String,
    patch_sha256: String,
    patch_path: PathBuf,
    package_checksum: String,
    source_path: String,
    source_sha256: String,
    patched_sha256: String,
}

#[derive(Debug)]
struct PatchOutput {
    stdout: String,
    stderr: String,
}

/// Prepare a fresh, disjoint vendor copy using the exact checked-in OpenSSL
/// overlay recipe and patch.
pub fn prepare_overlay(
    source_vendor: &Path,
    output_vendor: &Path,
    receipt: &Path,
    recipe: &Path,
) -> Result<Value> {
    let plan = load_pinned_plan(recipe)?;
    prepare_with_plan(source_vendor, output_vendor, receipt, &plan, run_patch)
}

/// Verify a prepared vendor tree and its typed receipt against the pinned
/// recipe identity.
pub fn verify_overlay(vendor: &Path, receipt: &Path, recipe: &Path) -> Result<Value> {
    let plan = load_pinned_plan(recipe)?;
    verify_with_plan(vendor, receipt, &plan)
}

fn load_pinned_plan(recipe: &Path) -> Result<OverlayPlan> {
    let (recipe, _recipe_directory) = canonical_directory(recipe, "overlay recipe")?;
    let pin_path = recipe.join("openssl-overlay.json");
    let pin_raw = read_regular_bounded(&pin_path, JsonProfile::SdkComponentManifest.max_bytes())?;
    let pin_sha256 = sha256_bytes(&pin_raw);
    if pin_sha256 != PIN_SHA256 {
        return Err(Refusal::new("vendor overlay recipe identity mismatch"));
    }
    let pin = parse_json_value(&pin_raw, JsonProfile::SdkComponentManifest)?;
    validate_pinned_json(&pin)?;

    let patch_path = recipe.join("openssl-paths.patch");
    let patch = read_regular_bounded(&patch_path, MAX_PATCH_BYTES)?;
    let patch_sha256 = sha256_bytes(&patch);
    if patch_sha256 != PATCH_SHA256 {
        return Err(Refusal::new("vendor overlay patch identity mismatch"));
    }

    Ok(OverlayPlan {
        pin_sha256,
        patch_sha256,
        patch_path,
        package_checksum: PACKAGE_CHECKSUM.to_owned(),
        source_path: SOURCE_PATH.to_owned(),
        source_sha256: SOURCE_SHA256.to_owned(),
        patched_sha256: PATCHED_SHA256.to_owned(),
    })
}

fn validate_pinned_json(pin: &Value) -> Result<()> {
    if pin.get("schema").and_then(Value::as_str) != Some(PIN_SCHEMA)
        || pin.get("patch_file").and_then(Value::as_str) != Some(PATCH_REPO_PATH)
        || pin.get("patch_sha256").and_then(Value::as_str) != Some(PATCH_SHA256)
        || pin.get("source_path_in_vendor").and_then(Value::as_str) != Some(SOURCE_PATH)
        || pin.get("source_sha256").and_then(Value::as_str) != Some(SOURCE_SHA256)
        || pin.get("patched_sha256").and_then(Value::as_str) != Some(PATCHED_SHA256)
    {
        return Err(Refusal::new(
            "vendor overlay recipe has unexpected pinned inputs",
        ));
    }
    let package = pin
        .get("package")
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new("vendor overlay package pin is missing"))?;
    if package.get("name").and_then(Value::as_str) != Some(PACKAGE_NAME)
        || package.get("version").and_then(Value::as_str) != Some(PACKAGE_VERSION)
        || package.get("cargo_lock_checksum").and_then(Value::as_str) != Some(PACKAGE_CHECKSUM)
    {
        return Err(Refusal::new("vendor overlay package pin mismatch"));
    }
    Ok(())
}

fn prepare_with_plan(
    source_vendor: &Path,
    output_vendor: &Path,
    receipt_path: &Path,
    plan: &OverlayPlan,
    patcher: impl FnOnce(&Path, &Path) -> Result<PatchOutput>,
) -> Result<Value> {
    let (source, source_directory) = canonical_directory(source_vendor, "source vendor")?;
    let output = fresh_path(output_vendor, "output vendor")?;
    let receipt = fresh_path(receipt_path, "overlay receipt")?;
    if paths_overlap(&source, &output)
        || paths_overlap(&source, &receipt)
        || paths_overlap(&output, &receipt)
    {
        return Err(Refusal::new(
            "overlay source, output, and receipt paths must be disjoint",
        ));
    }
    let _ = path_text(&source)?;
    let _ = path_text(&output)?;

    let patch_identity = sha256_file(&plan.patch_path)?;
    if patch_identity != plan.patch_sha256 {
        return Err(Refusal::new("vendor overlay patch identity mismatch"));
    }
    let started = Instant::now();
    let before = inventory_from_directory(&source, &source_directory)?;
    let source_bytes = file_bytes(&before.files)?;
    let estimated_workspace = source_bytes
        .checked_mul(2)
        .ok_or_else(|| Refusal::new("overlay workspace byte total overflow"))?;
    if estimated_workspace > MAX_WORKSPACE_BYTES {
        return Err(Refusal::new("overlay provisioning workspace budget"));
    }
    validate_upstream_vendor(&source, &before, plan)?;

    fs::create_dir(&output)?;
    fs::set_permissions(&output, fs::Permissions::from_mode(0o700))?;
    copy_vendor(&source, &output, &before)?;

    let patched_path = output.join(&plan.source_path);
    let checksum_path = checksum_path(&plan.source_path)?;
    set_file_mode(
        &patched_path,
        source_file(&before, &plan.source_path)?.mode | 0o200,
    )?;
    set_file_mode(
        &output.join(&checksum_path),
        source_file(&before, &checksum_path)?.mode | 0o200,
    )?;
    let applied = patcher(&output, &plan.patch_path)?;
    if sha256_file(&patched_path)? != plan.patched_sha256 {
        return Err(Refusal::new("patched source identity mismatch"));
    }
    if sha256_file(&plan.patch_path)? != plan.patch_sha256 {
        return Err(Refusal::new(
            "vendor overlay patch changed during application",
        ));
    }
    validate_checksum_file(
        &output.join(&checksum_path),
        &plan.package_checksum,
        &plan.source_sha256,
    )?;

    let mut checksum = read_json_file(&output.join(&checksum_path))?;
    let files = checksum
        .get_mut("files")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| Refusal::new("Cargo checksum record has no files object"))?;
    files.insert(
        "src/lib.rs".to_owned(),
        Value::String(plan.patched_sha256.clone()),
    );
    let checksum_bytes = serde_json::to_vec(&checksum)
        .map_err(|_| Refusal::new("could not encode Cargo checksum record"))?;
    fs::write(output.join(&checksum_path), checksum_bytes)?;
    set_file_mode(
        &output.join(&checksum_path),
        source_file(&before, &checksum_path)?.mode,
    )?;
    set_file_mode(&patched_path, source_file(&before, &plan.source_path)?.mode)?;

    let mut after = inventory(&output)?;
    if directory_paths(&after.directories) != directory_paths(&before.directories) {
        return Err(Refusal::new("overlay changed vendor directory membership"));
    }
    let changed = changed_files(&before.files, &after.files)?;
    let mut expected_changed = vec![plan.source_path.clone(), checksum_path.clone()];
    expected_changed.sort();
    if changed != expected_changed {
        return Err(Refusal::new(
            "overlay changed undeclared files or vendor membership",
        ));
    }
    if source_file(&after, &plan.source_path)?.sha256 != plan.patched_sha256
        || source_file(&after, &plan.source_path)?.mode
            != source_file(&before, &plan.source_path)?.mode
    {
        return Err(Refusal::new("patched source identity or mode mismatch"));
    }
    validate_checksum_file(
        &output.join(&checksum_path),
        &plan.package_checksum,
        &plan.patched_sha256,
    )?;

    restore_directory_modes(&output, &before)?;
    let restored = inventory(&output)?;
    if restored.files != after.files
        || restored.directories != before.directories
        || restored.root_mode != before.root_mode
    {
        return Err(Refusal::new(
            "overlay directory mode restoration or output identity mismatch",
        ));
    }
    after = restored;
    let source_after = inventory_from_directory(&source, &source_directory)?;
    if source_after != before {
        return Err(Refusal::new("overlay changed the upstream vendor tree"));
    }
    let elapsed = started.elapsed();
    if elapsed > MAX_ELAPSED {
        return Err(Refusal::new("overlay provisioning time budget"));
    }
    let total_bytes = source_bytes
        .checked_add(file_bytes(&after.files)?)
        .ok_or_else(|| Refusal::new("overlay workspace byte total overflow"))?;
    if total_bytes > MAX_WORKSPACE_BYTES {
        return Err(Refusal::new("overlay provisioning workspace budget"));
    }

    let record = OverlayReceipt {
        schema: RECEIPT_SCHEMA.to_owned(),
        claim: CLAIM.to_owned(),
        overlay_pin_sha256: plan.pin_sha256.clone(),
        patch_sha256: plan.patch_sha256.clone(),
        source_vendor: path_text(&source)?,
        output_vendor: path_text(&output)?,
        changed_files: changed,
        original_inventory_sha256: inventory_digest(&before)?,
        original_vendor_recheck: "PASS".to_owned(),
        elapsed_seconds: elapsed.as_secs_f64(),
        source_plus_output_bytes: total_bytes,
        patch_stdout: applied.stdout,
        patch_stderr: applied.stderr,
        original_directories: before.directories,
        directories: after.directories,
        original_files: before.files,
        files: after.files,
        original_root_mode: before.root_mode,
        root_mode: after.root_mode,
    };
    validate_receipt_shape(&record, plan)?;
    let raw = serde_json::to_vec(&record)
        .map_err(|_| Refusal::new("could not encode vendor overlay receipt"))?;
    if raw.len() > JsonProfile::CargoVendorOverlayReceipt.max_bytes() {
        return Err(Refusal::new(
            "vendor overlay receipt exceeds its JSON bound",
        ));
    }
    write_new_receipt(&receipt, &raw)?;
    Ok(receipt_summary(&record, &raw))
}

fn run_patch(output: &Path, patch_path: &Path) -> Result<PatchOutput> {
    let environment = BTreeMap::from([
        (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        (OsString::from("LC_ALL"), OsString::from("C")),
        (OsString::from("LANG"), OsString::from("C")),
        (OsString::from("TZ"), OsString::from("UTC")),
    ]);
    let spec = CommandSpec::new(
        "/usr/bin/patch",
        [
            OsString::from("-p1"),
            OsString::from("--batch"),
            OsString::from("-i"),
            patch_path.as_os_str().to_owned(),
        ],
        output,
        environment,
    );
    let captured = capture(
        &spec,
        CaptureLimits {
            timeout: PATCH_TIMEOUT,
            stdout_bytes: MAX_CAPTURE_STREAM_BYTES,
            stderr_bytes: MAX_CAPTURE_STREAM_BYTES,
            termination_grace: Duration::from_secs(2),
        },
        || false,
    )
    .map_err(|error| Refusal::new(format!("pinned overlay patch command failed: {error}")))?;
    if !captured.status.success() {
        return Err(Refusal::new(format!(
            "pinned overlay patch command exited with {}",
            captured
                .exit_code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "a signal".to_owned())
        )));
    }
    if captured.stdout.len() + captured.stderr.len() > MAX_TOTAL_CAPTURE_BYTES {
        return Err(Refusal::new("overlay patch output exceeds the log bound"));
    }
    let stdout = String::from_utf8(captured.stdout)
        .map_err(|_| Refusal::new("overlay patch stdout is not UTF-8"))?;
    let stderr = String::from_utf8(captured.stderr)
        .map_err(|_| Refusal::new("overlay patch stderr is not UTF-8"))?;
    Ok(PatchOutput { stdout, stderr })
}

fn verify_with_plan(vendor: &Path, receipt_path: &Path, plan: &OverlayPlan) -> Result<Value> {
    let (vendor, _vendor_directory) = canonical_directory(vendor, "overlay vendor")?;
    let receipt = existing_file_path(receipt_path, "overlay receipt")?;
    if paths_overlap(&vendor, &receipt) {
        return Err(Refusal::new(
            "overlay receipt must be outside the vendor tree",
        ));
    }
    let raw = read_regular_bounded(&receipt, JsonProfile::CargoVendorOverlayReceipt.max_bytes())?;
    let record: OverlayReceipt =
        crate::json::parse_json(&raw, JsonProfile::CargoVendorOverlayReceipt)?;
    validate_receipt_shape(&record, plan)?;
    let current = inventory(&vendor)?;
    if current.files != record.files
        || current.directories != record.directories
        || current.root_mode != record.root_mode
    {
        return Err(Refusal::new("vendor overlay inventory mismatch"));
    }
    if source_file(&current, &plan.source_path)?.sha256 != plan.patched_sha256 {
        return Err(Refusal::new("patched source identity mismatch"));
    }
    let checksum_path = checksum_path(&plan.source_path)?;
    validate_checksum_file(
        &vendor.join(checksum_path),
        &plan.package_checksum,
        &plan.patched_sha256,
    )?;
    Ok(serde_json::json!({
        "receipt_sha256": sha256_bytes(&raw),
        "pin_sha256": plan.pin_sha256,
        "patch_sha256": plan.patch_sha256,
        "inventory_files": record.files.len(),
        "inventory_directories": record.directories.len(),
    }))
}

fn validate_receipt_shape(record: &OverlayReceipt, plan: &OverlayPlan) -> Result<()> {
    if record.schema != RECEIPT_SCHEMA
        || record.claim != CLAIM
        || record.overlay_pin_sha256 != plan.pin_sha256
        || record.patch_sha256 != plan.patch_sha256
        || record.original_vendor_recheck != "PASS"
        || !record.elapsed_seconds.is_finite()
        || record.elapsed_seconds < 0.0
        || record.elapsed_seconds > MAX_ELAPSED.as_secs_f64()
        || record.patch_stdout.len() + record.patch_stderr.len() > MAX_TOTAL_CAPTURE_BYTES
        || !is_sha256_digest(&record.original_inventory_sha256)
    {
        return Err(Refusal::new("vendor overlay receipt identity mismatch"));
    }
    let original = VendorInventory {
        root_mode: record.original_root_mode,
        directories: record.original_directories.clone(),
        files: record.original_files.clone(),
    };
    let final_inventory = VendorInventory {
        root_mode: record.root_mode,
        directories: record.directories.clone(),
        files: record.files.clone(),
    };
    validate_inventory_shape(&original)?;
    validate_inventory_shape(&final_inventory)?;
    if inventory_digest(&original)? != record.original_inventory_sha256 {
        return Err(Refusal::new(
            "vendor overlay original inventory identity mismatch",
        ));
    }
    if original.root_mode != final_inventory.root_mode
        || original.directories != final_inventory.directories
    {
        return Err(Refusal::new(
            "vendor overlay changed directory membership or modes",
        ));
    }
    let checksum_path = checksum_path(&plan.source_path)?;
    if source_file(&original, &checksum_path)?.mode
        != source_file(&final_inventory, &checksum_path)?.mode
    {
        return Err(Refusal::new("vendor overlay checksum mode mismatch"));
    }
    let mut expected_changed = vec![plan.source_path.clone(), checksum_path];
    expected_changed.sort();
    let actual_changed = changed_files(&original.files, &final_inventory.files)?;
    if actual_changed != expected_changed || record.changed_files != expected_changed {
        return Err(Refusal::new("vendor overlay changed undeclared files"));
    }
    if source_file(&original, &plan.source_path)?.sha256 != plan.source_sha256
        || source_file(&final_inventory, &plan.source_path)?.sha256 != plan.patched_sha256
        || source_file(&original, &plan.source_path)?.mode
            != source_file(&final_inventory, &plan.source_path)?.mode
    {
        return Err(Refusal::new("vendor overlay source identity mismatch"));
    }
    let expected_bytes = file_bytes(&original.files)?
        .checked_add(file_bytes(&final_inventory.files)?)
        .ok_or_else(|| Refusal::new("overlay workspace byte total overflow"))?;
    if record.source_plus_output_bytes != expected_bytes || expected_bytes > MAX_WORKSPACE_BYTES {
        return Err(Refusal::new("vendor overlay workspace identity mismatch"));
    }
    Ok(())
}

fn validate_inventory_shape(inventory: &VendorInventory) -> Result<()> {
    if inventory.root_mode & !0o7777 != 0
        || inventory.files.len() + inventory.directories.len() > MAX_TREE_ENTRIES
    {
        return Err(Refusal::new("vendor overlay inventory exceeds its bounds"));
    }
    let mut previous = None::<&str>;
    let mut seen = BTreeSet::new();
    for directory in &inventory.directories {
        validate_relative_inventory_path(&directory.path)?;
        if directory.mode & !0o7777 != 0
            || previous.is_some_and(|value| value >= directory.path.as_str())
            || !seen.insert(directory.path.as_str())
        {
            return Err(Refusal::new(
                "vendor overlay directory inventory is invalid",
            ));
        }
        previous = Some(&directory.path);
    }
    previous = None;
    for file in &inventory.files {
        validate_relative_inventory_path(&file.path)?;
        if file.mode & !0o7777 != 0
            || !is_sha256_digest(&file.sha256)
            || previous.is_some_and(|value| value >= file.path.as_str())
            || !seen.insert(file.path.as_str())
        {
            return Err(Refusal::new("vendor overlay file inventory is invalid"));
        }
        previous = Some(&file.path);
    }
    Ok(())
}

fn validate_upstream_vendor(
    source: &Path,
    inventory: &VendorInventory,
    plan: &OverlayPlan,
) -> Result<()> {
    if source_file(inventory, &plan.source_path)?.sha256 != plan.source_sha256 {
        return Err(Refusal::new("upstream vendor/patch identity mismatch"));
    }
    let checksum = checksum_path(&plan.source_path)?;
    validate_checksum_file(
        &source.join(checksum),
        &plan.package_checksum,
        &plan.source_sha256,
    )
}

fn validate_checksum_file(
    path: &Path,
    package_checksum: &str,
    source_checksum: &str,
) -> Result<()> {
    let checksum = read_json_file(path)?;
    let package = checksum
        .get("package")
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new("Cargo checksum record has no package identity"))?;
    let files = checksum
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new("Cargo checksum record has no files object"))?;
    if package != package_checksum
        || files.get("src/lib.rs").and_then(Value::as_str) != Some(source_checksum)
    {
        return Err(Refusal::new("upstream vendor/patch identity mismatch"));
    }
    Ok(())
}

fn read_json_file(path: &Path) -> Result<Value> {
    let raw = read_regular_bounded(path, JsonProfile::SdkComponentManifest.max_bytes())?;
    parse_json_value(&raw, JsonProfile::SdkComponentManifest)
}

fn inventory(path: &Path) -> Result<VendorInventory> {
    let directory = Directory::open(path)?;
    inventory_from_directory(path, &directory)
}

fn inventory_from_directory(path: &Path, root: &Directory) -> Result<VendorInventory> {
    let root_mode = root.metadata()?.mode() & 0o7777;
    let mut directories = Vec::new();
    let mut files = Vec::new();
    let mut entries = 0_usize;
    let mut pending = vec![String::new()];
    while let Some(prefix) = pending.pop() {
        let directory = root.relative_directory(&prefix)?;
        let names = directory.names(MAX_TREE_ENTRIES.saturating_sub(entries))?;
        for name in names {
            entries = entries
                .checked_add(1)
                .ok_or_else(|| Refusal::new("vendor tree entry count overflow"))?;
            if entries > MAX_TREE_ENTRIES {
                return Err(Refusal::new("vendor tree exceeds traversal bound"));
            }
            let name = name
                .to_str()
                .ok_or_else(|| Refusal::new("vendor path is not UTF-8"))?;
            let relative = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            validate_relative_inventory_path(&relative)?;
            let identity = directory.classify_entry(OsStr::new(name))?;
            match identity.entry_type() {
                EntryType::Directory => {
                    let child = directory.open_child_matching(OsStr::new(name), identity)?;
                    directories.push(DirectoryIdentity {
                        path: relative.clone(),
                        mode: child.metadata()?.mode() & 0o7777,
                    });
                    pending.push(relative);
                }
                EntryType::RegularFile => {
                    let file = directory.open_regular_matching(OsStr::new(name), identity)?;
                    let metadata = file.metadata()?;
                    let absolute = path.join(&relative);
                    files.push(FileIdentity {
                        path: relative,
                        bytes: metadata.len(),
                        mode: metadata.mode() & 0o7777,
                        sha256: sha256_file(&absolute)?,
                    });
                }
                EntryType::Symlink | EntryType::Other => {
                    return Err(Refusal::new(
                        "vendor contains a symlink or non-regular entry",
                    ));
                }
            }
        }
    }
    directories.sort_by(|left, right| left.path.cmp(&right.path));
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(VendorInventory {
        root_mode,
        directories,
        files,
    })
}

fn copy_vendor(source: &Path, output: &Path, inventory: &VendorInventory) -> Result<()> {
    for directory in &inventory.directories {
        fs::create_dir(output.join(&directory.path))?;
        set_file_mode(&output.join(&directory.path), 0o700)?;
    }
    for row in &inventory.files {
        let source_path = source.join(&row.path);
        let output_path = output.join(&row.path);
        let mut input = open_regular_nofollow(&source_path)?;
        let mut target = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output_path)?;
        std::io::copy(&mut input, &mut target)?;
        // As in the historical copy, close and verify every file. The receipt
        // is synced separately; this helper makes no power-loss atomicity claim.
        drop(target);
        set_file_mode(&output_path, row.mode)?;
    }
    Ok(())
}

fn restore_directory_modes(output: &Path, original: &VendorInventory) -> Result<()> {
    for directory in original.directories.iter().rev() {
        set_file_mode(&output.join(&directory.path), directory.mode)?;
    }
    set_file_mode(output, original.root_mode)?;
    Ok(())
}

fn changed_files(before: &[FileIdentity], after: &[FileIdentity]) -> Result<Vec<String>> {
    let old = before
        .iter()
        .map(|row| (row.path.as_str(), row))
        .collect::<BTreeMap<_, _>>();
    let new = after
        .iter()
        .map(|row| (row.path.as_str(), row))
        .collect::<BTreeMap<_, _>>();
    if old.keys().ne(new.keys()) {
        return Err(Refusal::new("overlay changed vendor file membership"));
    }
    Ok(old
        .iter()
        .filter(|&(path, original)| *new.get(path).expect("key sets were compared") != *original)
        .map(|(path, _)| (*path).to_owned())
        .collect())
}

fn directory_paths(directories: &[DirectoryIdentity]) -> Vec<&str> {
    directories
        .iter()
        .map(|directory| directory.path.as_str())
        .collect()
}

fn source_file<'a>(inventory: &'a VendorInventory, path: &str) -> Result<&'a FileIdentity> {
    inventory
        .files
        .binary_search_by(|row| row.path.as_str().cmp(path))
        .ok()
        .map(|index| &inventory.files[index])
        .ok_or_else(|| Refusal::new("vendor overlay inventory omits a declared file"))
}

fn checksum_path(source_path: &str) -> Result<String> {
    let (package_root, _) = source_path
        .split_once('/')
        .ok_or_else(|| Refusal::new("pinned source path has no package root"))?;
    Ok(format!("{package_root}/.cargo-checksum.json"))
}

fn file_bytes(files: &[FileIdentity]) -> Result<u64> {
    files.iter().try_fold(0_u64, |total, file| {
        total
            .checked_add(file.bytes)
            .ok_or_else(|| Refusal::new("vendor file byte total overflow"))
    })
}

fn inventory_digest(inventory: &VendorInventory) -> Result<String> {
    let raw = serde_json::to_vec(inventory)
        .map_err(|_| Refusal::new("could not encode vendor inventory identity"))?;
    Ok(sha256_bytes(&raw))
}

fn canonical_directory(path: &Path, label: &str) -> Result<(PathBuf, Directory)> {
    // Resolve ordinary caller aliases before anchoring the selected tree.
    // Entries inside that tree still use descriptor-based no-follow access.
    let before = fs::metadata(path)
        .map_err(|error| Refusal::new(format!("could not inspect {label}: {error}")))?;
    let canonical = fs::canonicalize(path)
        .map_err(|error| Refusal::new(format!("could not resolve {label}: {error}")))?;
    let opened = Directory::open(&canonical)
        .map_err(|error| Refusal::new(format!("could not retain {label}: {error}")))?;
    let after = opened.metadata()?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(Refusal::new(format!(
            "{label} changed during path resolution"
        )));
    }
    Ok((canonical, opened))
}

fn fresh_path(path: &Path, label: &str) -> Result<PathBuf> {
    let (parent, _directory) = canonical_directory(parent_or_current(path), label)?;
    let leaf = path
        .file_name()
        .filter(|value| *value != OsStr::new(".") && *value != OsStr::new(".."))
        .ok_or_else(|| Refusal::new(format!("{label} path must name a fresh entry")))?;
    let full = parent.join(leaf);
    match fs::symlink_metadata(&full) {
        Ok(_) => return Err(Refusal::new(format!("{label} path must be fresh"))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(Refusal::new(format!(
                "could not inspect {label} path: {error}"
            )));
        }
    }
    Ok(full)
}

fn existing_file_path(path: &Path, label: &str) -> Result<PathBuf> {
    let (parent, _directory) = canonical_directory(parent_or_current(path), label)?;
    let leaf = path
        .file_name()
        .ok_or_else(|| Refusal::new(format!("{label} path must name a file")))?;
    let full = parent.join(leaf);
    open_regular_nofollow(&full)
        .map_err(|error| Refusal::new(format!("could not open {label}: {error}")))?;
    Ok(full)
}

fn parent_or_current(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn path_text(path: &Path) -> Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| Refusal::new("overlay path is not UTF-8"))
}

fn set_file_mode(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn write_new_receipt(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut created = false;
    let result = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        created = true;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    if result.is_err() && created {
        let _ = fs::remove_file(path);
    }
    result
}

fn receipt_summary(record: &OverlayReceipt, raw: &[u8]) -> Value {
    serde_json::json!({
        "schema": record.schema,
        "claim": record.claim,
        "overlay_pin_sha256": record.overlay_pin_sha256,
        "patch_sha256": record.patch_sha256,
        "source_vendor": record.source_vendor,
        "output_vendor": record.output_vendor,
        "changed_files": record.changed_files,
        "original_inventory_sha256": record.original_inventory_sha256,
        "original_vendor_recheck": record.original_vendor_recheck,
        "elapsed_seconds": record.elapsed_seconds,
        "source_plus_output_bytes": record.source_plus_output_bytes,
        "patch_stdout": record.patch_stdout,
        "patch_stderr": record.patch_stderr,
        "inventory_files": record.files.len(),
        "receipt_sha256": sha256_bytes(raw),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT: AtomicU64 = AtomicU64::new(0);
    const ORIGINAL: &[u8] = b"source before overlay\n";
    const PATCHED: &[u8] = b"source after overlay\n";
    const CHECKSUM: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const TEST_PIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let path = std::env::current_dir()
                .expect("current directory")
                .join(format!(
                    ".ami-cargo-overlay-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            fs::create_dir(&path).expect("create fixture root");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove fixture tree");
        }
    }

    fn fixture_plan(root: &Path) -> OverlayPlan {
        let patch_path = root.join("test.patch");
        fs::write(&patch_path, b"injected patch identity").expect("write injected patch");
        OverlayPlan {
            pin_sha256: TEST_PIN.to_owned(),
            patch_sha256: sha256_file(&patch_path).unwrap(),
            patch_path,
            package_checksum: CHECKSUM.to_owned(),
            source_path: "openssl-src-300.6.1+3.6.3/src/lib.rs".to_owned(),
            source_sha256: sha256_bytes(ORIGINAL),
            patched_sha256: sha256_bytes(PATCHED),
        }
    }

    fn source_tree(root: &Path, current_source: &[u8], current_package: &str) -> PathBuf {
        let source = root.join("vendor");
        let package = source.join("openssl-src-300.6.1+3.6.3");
        fs::create_dir_all(package.join("src")).expect("create vendor package");
        fs::write(package.join("src/lib.rs"), current_source).expect("write source fixture");
        fs::write(
            package.join(".cargo-checksum.json"),
            serde_json::to_vec(&serde_json::json!({
                "files": {"src/lib.rs": sha256_bytes(current_source)},
                "package": current_package
            }))
            .unwrap(),
        )
        .expect("write checksum fixture");
        source
    }

    fn fake_patch(output: &Path, _patch: &Path) -> Result<PatchOutput> {
        fs::write(output.join("openssl-src-300.6.1+3.6.3/src/lib.rs"), PATCHED)?;
        Ok(PatchOutput {
            stdout: "patch applied\n".to_owned(),
            stderr: String::new(),
        })
    }

    fn prepare_fixture(
        root: &Path,
        plan: &OverlayPlan,
        patcher: impl FnOnce(&Path, &Path) -> Result<PatchOutput>,
    ) -> Result<Value> {
        let source = root.join("vendor");
        let output = root.join("overlay");
        let receipt = root.join("overlay.json");
        prepare_with_plan(&source, &output, &receipt, plan, patcher)
    }

    #[test]
    fn injected_copy_patch_and_verify_fixture_preserves_modes_and_receipt_evidence() {
        let fixture = Fixture::new();
        let source = source_tree(fixture.path(), ORIGINAL, CHECKSUM);
        fs::create_dir_all(source.join("extra/empty")).unwrap();
        fs::write(source.join("extra/notice"), b"preserve me").unwrap();
        fs::set_permissions(
            source.join("extra/notice"),
            fs::Permissions::from_mode(0o640),
        )
        .unwrap();
        let plan = fixture_plan(fixture.path());
        let summary = prepare_fixture(fixture.path(), &plan, fake_patch).unwrap();
        let output = fixture.path().join("overlay");
        let receipt = fixture.path().join("overlay.json");
        let verified = verify_with_plan(&output, &receipt, &plan).unwrap();
        assert_eq!(summary["changed_files"].as_array().unwrap().len(), 2);
        assert_eq!(verified["inventory_files"], 3);
        assert_eq!(fs::read(output.join(&plan.source_path)).unwrap(), PATCHED);
        assert_eq!(
            fs::read(output.join("extra/notice")).unwrap(),
            b"preserve me"
        );
        assert_eq!(
            fs::metadata(output.join("extra/notice")).unwrap().mode() & 0o7777,
            0o640
        );
        let raw = fs::read(receipt).unwrap();
        let record: OverlayReceipt =
            crate::json::parse_json(&raw, JsonProfile::CargoVendorOverlayReceipt).unwrap();
        assert_eq!(record.patch_stdout, "patch applied\n");
        assert_eq!(record.original_files.len(), record.files.len());
        assert_eq!(fs::read(source.join(&plan.source_path)).unwrap(), ORIGINAL);
    }

    #[test]
    fn refuses_invalid_source_and_package_checksum_before_creating_output() {
        let fixture = Fixture::new();
        source_tree(fixture.path(), b"wrong source", CHECKSUM);
        let plan = fixture_plan(fixture.path());
        assert!(prepare_fixture(fixture.path(), &plan, fake_patch).is_err());
        assert!(!fixture.path().join("overlay").exists());
        assert!(!fixture.path().join("overlay.json").exists());

        let second = Fixture::new();
        source_tree(second.path(), ORIGINAL, "wrong package checksum");
        let plan = fixture_plan(second.path());
        assert!(prepare_fixture(second.path(), &plan, fake_patch).is_err());
        assert!(!second.path().join("overlay").exists());
    }

    #[test]
    fn refuses_a_patch_digest_mismatch_before_copying() {
        let fixture = Fixture::new();
        source_tree(fixture.path(), ORIGINAL, CHECKSUM);
        let mut plan = fixture_plan(fixture.path());
        plan.patch_sha256 = sha256_bytes(b"different patch");
        assert!(prepare_fixture(fixture.path(), &plan, fake_patch).is_err());
        assert!(!fixture.path().join("overlay").exists());
    }

    #[test]
    fn rejects_extra_mutation_and_keeps_failed_output_without_receipt() {
        let fixture = Fixture::new();
        source_tree(fixture.path(), ORIGINAL, CHECKSUM);
        let plan = fixture_plan(fixture.path());
        let result = prepare_fixture(fixture.path(), &plan, |output, patch| {
            fake_patch(output, patch)?;
            fs::write(output.join("unexpected"), b"extra")?;
            Ok(PatchOutput {
                stdout: String::new(),
                stderr: String::new(),
            })
        });
        assert!(result.is_err());
        assert!(fixture.path().join("overlay").exists());
        assert!(!fixture.path().join("overlay.json").exists());
    }

    #[test]
    fn refuses_overlapping_paths_and_occupied_output_or_receipt() {
        let fixture = Fixture::new();
        let source = source_tree(fixture.path(), ORIGINAL, CHECKSUM);
        let plan = fixture_plan(fixture.path());
        assert!(
            prepare_with_plan(
                &source,
                &source.join("nested-overlay"),
                &fixture.path().join("receipt.json"),
                &plan,
                fake_patch,
            )
            .is_err()
        );
        fs::create_dir(fixture.path().join("overlay")).unwrap();
        assert!(prepare_fixture(fixture.path(), &plan, fake_patch).is_err());
        fs::remove_dir(fixture.path().join("overlay")).unwrap();
        fs::write(fixture.path().join("overlay.json"), b"occupied").unwrap();
        assert!(prepare_fixture(fixture.path(), &plan, fake_patch).is_err());
        assert!(!fixture.path().join("overlay").exists());
    }

    #[test]
    fn rejects_symlink_in_vendor_inventory() {
        let fixture = Fixture::new();
        let source = source_tree(fixture.path(), ORIGINAL, CHECKSUM);
        symlink(
            "openssl-src-300.6.1+3.6.3/src/lib.rs",
            source.join("linked-file"),
        )
        .unwrap();
        let plan = fixture_plan(fixture.path());
        assert!(prepare_fixture(fixture.path(), &plan, fake_patch).is_err());
        assert!(!fixture.path().join("overlay").exists());
    }

    #[test]
    fn verifier_rejects_mutation_and_receipt_inside_vendor_tree() {
        let fixture = Fixture::new();
        source_tree(fixture.path(), ORIGINAL, CHECKSUM);
        let plan = fixture_plan(fixture.path());
        prepare_fixture(fixture.path(), &plan, fake_patch).unwrap();
        let output = fixture.path().join("overlay");
        let receipt = fixture.path().join("overlay.json");
        fs::write(output.join("extra"), b"mutated").unwrap();
        assert!(verify_with_plan(&output, &receipt, &plan).is_err());
        assert!(verify_with_plan(&output, &output.join("receipt.json"), &plan).is_err());
    }

    #[test]
    fn source_output_receipt_and_recipe_accept_ordinary_path_aliases() {
        let fixture = Fixture::new();
        let plan = fixture_plan(fixture.path());
        let source = source_tree(fixture.path(), ORIGINAL, CHECKSUM);
        let alias = fixture.path().join("caller alias with spaces");
        symlink(fixture.path(), &alias).unwrap();
        let output = alias.join("output");
        let receipt = alias.join("receipt.json");
        prepare_with_plan(
            &alias.join(source.file_name().unwrap()),
            &output,
            &receipt,
            &plan,
            fake_patch,
        )
        .unwrap();
        verify_with_plan(&output, &receipt, &plan).unwrap();
        let recipe = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../host/cargo-repro");
        let recipe_alias = fixture.path().join("recipe alias");
        symlink(&recipe, &recipe_alias).unwrap();
        assert_eq!(
            load_pinned_plan(&recipe_alias).unwrap().pin_sha256,
            PIN_SHA256
        );
        fs::remove_file(alias).unwrap();
    }

    #[test]
    fn verifier_accepts_an_identical_overlay_after_relocation() {
        let fixture = Fixture::new();
        source_tree(fixture.path(), ORIGINAL, CHECKSUM);
        let plan = fixture_plan(fixture.path());
        prepare_fixture(fixture.path(), &plan, fake_patch).unwrap();
        let relocated = fixture.path().join("relocated-overlay");
        fs::rename(fixture.path().join("overlay"), &relocated).unwrap();
        assert!(verify_with_plan(&relocated, &fixture.path().join("overlay.json"), &plan).is_ok());
    }

    #[test]
    fn patch_failure_preserves_diagnostics_and_never_writes_a_success_receipt() {
        let fixture = Fixture::new();
        source_tree(fixture.path(), ORIGINAL, CHECKSUM);
        let plan = fixture_plan(fixture.path());
        let result = prepare_fixture(fixture.path(), &plan, |output, _patch| {
            fs::write(output.join("partial"), b"diagnostic")?;
            Err(Refusal::new("simulated patch failure"))
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read(fixture.path().join("overlay/partial")).unwrap(),
            b"diagnostic"
        );
        assert!(!fixture.path().join("overlay.json").exists());
    }

    #[test]
    #[ignore = "native-command positive fixture for the supervised maintainer run"]
    fn native_command_positive_fixture_uses_the_real_patch_executable() {
        let fixture = Fixture::new();
        let output = fixture.path().join("vendor");
        fs::create_dir_all(output.join("crate/src")).unwrap();
        fs::write(output.join("crate/src/lib.rs"), b"before\n").unwrap();
        let patch = fixture.path().join("native.patch");
        fs::write(
            &patch,
            b"--- a/crate/src/lib.rs\n+++ b/crate/src/lib.rs\n@@ -1 +1 @@\n-before\n+after\n",
        )
        .unwrap();
        run_patch(&output, &patch).unwrap();
        assert_eq!(
            fs::read(output.join("crate/src/lib.rs")).unwrap(),
            b"after\n"
        );
    }
}
