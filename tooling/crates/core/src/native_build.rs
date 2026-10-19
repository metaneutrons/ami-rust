//! Supervised orchestration for the pinned native consumer build.
//!
//! Command recipes live in [`native_recipe`]. This module checks the explicit
//! project inputs, creates a fresh private output, supervises every external
//! tool, finalizes the ELF in process, and writes a PASS receipt only after the
//! immutable inputs have been checked again.

use crate::{
    Refusal, Result,
    compact::{CompactionReport, compact_elf_sections_with_report},
    consumer_session::{ConsumerOutput, ConsumerSession},
    digest::{sha256_bytes, sha256_file},
    directory::Directory,
    elf, files,
    json::{JsonProfile, parse_json_value},
    native_project::{CheckedProject, verify_project_lock},
    native_recipe::{
        CargoBuildOptions, NativeBuildRecipe, NativeRecipePaths, remove_registry_credentials,
    },
    ownership,
    process_capture::CommandSpec,
    records::Host,
    selected_inputs::SelectedInputs,
    signals::SigtermGuard,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::{CString, OsStr, OsString},
    fs::{self, File},
    io::{Read, Write},
    os::unix::{ffi::OsStrExt, io::AsRawFd},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const BUILD_SECONDS: u64 = 1_200;
const MINIMUM_RAM_BYTES: u64 = 6 * 1024 * 1024 * 1024;
const MINIMUM_FREE_DISK_BYTES: u64 = 24 * 1024 * 1024 * 1024;
const CARGO_METADATA_MODE: &str = "ami-rust-reproducible-cross-v1";
const COMPONENTS: [&str; 6] = ["rust", "cargo", "toolchain", "collector", "csdk", "vendor"];
const COMMAND_ARTIFACT_EXTENSIONS: [&str; 3] = ["o", "a", "rlib"];

/// Result of a completed or child-failed build campaign.
///
/// Preflight, supervision, monitoring, cancellation, compaction, and audit
/// failures remain `Err`; a child that completed with a nonzero status returns
/// that historical CLI status and leaves the output tree available for review.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildResult {
    pub exit_code: u8,
    pub native_executable: Option<PathBuf>,
    pub receipt: Option<PathBuf>,
}

impl BuildResult {
    fn failed(exit_code: u8) -> Self {
        Self {
            exit_code,
            native_executable: None,
            receipt: None,
        }
    }
}

struct CargoOutputSummary {
    static_archives: Vec<PathBuf>,
    verbose_build_script_lines: usize,
}

struct ObservedCommand {
    output: Option<ConsumerOutput>,
    failure_exit_code: Option<u8>,
}

struct HostCapacity {
    policy: Value,
    physical_ram_bytes: u64,
    free_disk_bytes: u64,
}

struct CargoFiles {
    manifest: PathBuf,
    lock: PathBuf,
    manifest_sha256: String,
    lock_sha256: String,
}

/// Run the frozen Rust/C/link/strip build recipe for a checked project.
///
/// `options.manifest_path` is the explicit Cargo manifest. Its adjacent
/// `Cargo.lock` is verified against the project lock, independently of where
/// that project lock itself is stored.
pub fn run_build(
    checked: &CheckedProject,
    mut options: CargoBuildOptions,
    output: &Path,
    signals: &SigtermGuard,
) -> Result<BuildResult> {
    signals.check()?;
    checked.lock.host.platform.ensure_current()?;

    let output_path = normalize_output_directory(output)?;
    let cargo_files = verify_cargo_files(checked, &mut options)?;
    let project_root = cargo_files
        .manifest
        .parent()
        .ok_or_else(|| Refusal::new("Cargo manifest has no project directory"))?
        .to_path_buf();
    let project_lock_digest = sha256_file(&checked.lock_path)?;
    recheck_checked_project(checked, &project_lock_digest)?;
    let selected = select_tools(&checked.selected_inputs)?;
    let cargo_sha256 = hash_selected_alias(
        &selected.cargo,
        checked.selected_inputs.component("cargo")?.path(),
    )?;

    let sdk = read_sdk_build_policy(checked)?;
    let capacity = measure_host_capacity(
        output_path
            .parent()
            .ok_or_else(|| Refusal::new("build output has no parent directory"))?,
        sdk.capacity_policy,
    )?;
    if capacity.physical_ram_bytes < capacity.policy["ram_minimum_bytes"].as_u64().unwrap_or(0)
        || capacity.free_disk_bytes
            < capacity.policy["disk_free_minimum_bytes"]
                .as_u64()
                .unwrap_or(0)
    {
        return Err(Refusal::new(
            "host capacity is below the installed SDK policy",
        ));
    }

    require_output_disjoint(&output_path, checked, &project_root)?;
    reject_ambient_cargo_config(&output_path.join("work"))?;
    validate_receipt_strings(&options, &output_path)?;
    signals.check()?;

    let fresh = ownership::fresh_build_output(&output_path)?;
    let root = fresh.parent().mkdir_new(fresh.name(), 0o700)?;
    let build_lock = root.create_new_file(OsStr::new("build.lock"), 0o600)?;
    lock_build_directory(&build_lock)?;

    let _work = root.mkdir_new(OsStr::new("work"), 0o700)?;
    let cargo_home = root.mkdir_new(OsStr::new("cargo-home"), 0o700)?;
    let bin = root.mkdir_new(OsStr::new("bin"), 0o700)?;
    let artifacts = root.mkdir_new(OsStr::new("artifacts"), 0o700)?;
    let mut session = ConsumerSession::new_build(&output_path, signals)?;

    install_build_tool_aliases(&bin, &output_path, &selected)?;

    let recipe = NativeBuildRecipe::new(
        NativeRecipePaths {
            source_root: checked.installation.path().join("sdk"),
            output_root: output_path.clone(),
            work_dir: output_path.join("work"),
            rust_root: checked
                .selected_inputs
                .component("rust")?
                .path()
                .to_path_buf(),
            cargo_program: selected.cargo.clone(),
            toolchain_root: checked
                .selected_inputs
                .component("toolchain")?
                .path()
                .to_path_buf(),
            sdk_root: checked
                .selected_inputs
                .component("csdk")?
                .path()
                .to_path_buf(),
            vendor_root: checked
                .selected_inputs
                .component("vendor")?
                .path()
                .to_path_buf(),
        },
        checked.lock.host.platform,
        checked.selected_inputs.recipe.source_date_epoch,
    );
    let cargo_config = recipe.cargo_config_toml(&options)?;
    write_new_file(&cargo_home, "config.toml", cargo_config.as_bytes(), 0o600)?;

    let campaign_start = Instant::now();
    let probe_environment = remove_registry_credentials(session.environment());
    let rustc_probe = CommandSpec::new(
        selected.rustc.as_os_str().to_os_string(),
        vec![OsString::from("-Vv")],
        work_path(&output_path),
        probe_environment.clone(),
    );
    let rustc_result = run_observed(
        &mut session,
        campaign_start,
        "Rustc-version",
        rustc_probe,
        &mut Vec::new(),
        false,
    )?;
    if let Some(code) = rustc_result.failure_exit_code {
        return Ok(BuildResult::failed(code));
    }
    let rustc_output = rustc_result
        .output
        .ok_or_else(|| Refusal::new("rustc probe returned no captured output"))?;
    let compiler_verbose = utf8_output(&rustc_output.stdout, "rustc -Vv output")?;
    verify_rustc_identity(
        &compiler_verbose,
        &checked.selected_inputs.recipe.rust_commit,
        &checked.selected_inputs.recipe.rust_llvm,
        checked.lock.host.platform,
    )?;

    let cargo_probe = CommandSpec::new(
        selected.cargo.as_os_str().to_os_string(),
        vec![OsString::from("-Vv")],
        work_path(&output_path),
        probe_environment,
    );
    let cargo_result = run_observed(
        &mut session,
        campaign_start,
        "Cargo-version",
        cargo_probe,
        &mut Vec::new(),
        false,
    )?;
    if let Some(code) = cargo_result.failure_exit_code {
        return Ok(BuildResult::failed(code));
    }
    let cargo_probe_output = cargo_result
        .output
        .ok_or_else(|| Refusal::new("Cargo probe returned no captured output"))?;
    let cargo_version = utf8_output(&cargo_probe_output.stdout, "cargo -Vv output")?;

    let mut command_records = Vec::new();
    for command in recipe.c_compile_commands(&options)? {
        let observed = run_observed(
            &mut session,
            campaign_start,
            command.label,
            command.spec,
            &mut command_records,
            true,
        )?;
        if let Some(code) = observed.failure_exit_code {
            return Ok(BuildResult::failed(code));
        }
    }

    let startup = run_observed(
        &mut session,
        campaign_start,
        "Startup",
        recipe.startup_spec(&options)?,
        &mut command_records,
        true,
    )?;
    if let Some(code) = startup.failure_exit_code {
        return Ok(BuildResult::failed(code));
    }

    let cargo_build = run_observed(
        &mut session,
        campaign_start,
        "Rust",
        recipe.cargo_spec(&options)?,
        &mut command_records,
        true,
    )?;
    if let Some(code) = cargo_build.failure_exit_code {
        return Ok(BuildResult::failed(code));
    }
    let cargo_build_output = cargo_build
        .output
        .ok_or_else(|| Refusal::new("Cargo build returned no captured output"))?;
    let cargo_output = parse_cargo_output(&cargo_build_output.stdout)?;
    let archive = single_static_archive(&cargo_output)?;
    let archive_path = validate_static_archive(&output_path, &archive)?;
    copy_new_file(&archive_path, &artifacts, "application.a", 0o600)?;

    let link = run_observed(
        &mut session,
        campaign_start,
        "Link",
        recipe.collector_spec(&options)?,
        &mut command_records,
        true,
    )?;
    if let Some(code) = link.failure_exit_code {
        return Ok(BuildResult::failed(code));
    }

    let strip = run_observed(
        &mut session,
        campaign_start,
        "Strip",
        recipe.strip_spec(&options)?,
        &mut command_records,
        true,
    )?;
    if let Some(code) = strip.failure_exit_code {
        return Ok(BuildResult::failed(code));
    }

    ensure_campaign_time(campaign_start)?;
    let stripped_path = output_path.join("artifacts/AMIRUST.stripped");
    let executable_path = output_path.join("artifacts/AMIRUST");
    let stripped = read_regular_file(&stripped_path)?;
    let compacted = compact_elf_sections_with_report(&stripped)?;
    write_new_file(&artifacts, "AMIRUST", &compacted.bytes, 0o600)?;
    let compact_receipt = compaction_receipt(&stripped_path, &executable_path, &compacted.report)?;
    write_new_file(
        &root,
        "metadata-compaction.json",
        &pretty_json_line(&compact_receipt)?,
        0o600,
    )?;

    let executable_text = path_text(&executable_path)?;
    let audit = elf::audit(
        &compacted.bytes,
        if options.package == OsStr::new("ami-rust-dependencies") {
            "deps"
        } else {
            "core"
        },
        &executable_text,
    )?;
    write_new_file(&root, "elf-audit.json", &pretty_json_line(&audit)?, 0o600)?;

    ensure_campaign_time(campaign_start)?;
    recheck_checked_project(checked, &project_lock_digest)?;
    let cargo_files_after = verify_cargo_files(checked, &mut options)?;
    if cargo_files_after.manifest_sha256 != cargo_files.manifest_sha256
        || cargo_files_after.lock_sha256 != cargo_files.lock_sha256
        || cargo_files_after.manifest != cargo_files.manifest
        || cargo_files_after.lock != cargo_files.lock
    {
        return Err(Refusal::new(
            "project Cargo files changed during native build",
        ));
    }

    let generated = collect_target_artifacts(&output_path)?;
    let mut canonical_artifacts = BTreeMap::<String, Value>::new();
    for name in [
        "entry.o",
        "sdk.o",
        "layout.o",
        "startup.o",
        "application.a",
        "AMIRUST",
    ]
    .into_iter()
    .chain(options.is_testing_package().then_some("bind.o"))
    {
        let path = output_path.join("artifacts").join(name);
        canonical_artifacts.insert(name.to_owned(), artifact_identity(&path)?);
    }
    for (source, relative) in generated {
        ensure_campaign_time(campaign_start)?;
        let destination_relative = PathBuf::from("target").join(&relative);
        let destination_text = path_text(&destination_relative)?;
        let destination = output_path.join("artifacts").join(&destination_relative);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        refuse_existing(&destination)?;
        fs::rename(&source, &destination)?;
        canonical_artifacts.insert(destination_text, artifact_identity(&destination)?);
    }

    let cargo_sha256_after = hash_selected_alias(
        &selected.cargo,
        checked.selected_inputs.component("cargo")?.path(),
    )?;
    if cargo_sha256 != cargo_sha256_after {
        return Err(Refusal::new(
            "selected Cargo executable changed during build",
        ));
    }

    // Cargo target outputs have been moved into the canonical artifact tree;
    // retiring the private scratch tree happens before the PASS receipt.
    fs::remove_dir_all(output_path.join("work"))?;
    session.recheck_root()?;
    recheck_checked_project(checked, &project_lock_digest)?;
    ensure_campaign_time(campaign_start)?;
    let final_cargo_files = verify_cargo_files(checked, &mut options)?;
    if final_cargo_files.manifest_sha256 != cargo_files.manifest_sha256
        || final_cargo_files.lock_sha256 != cargo_files.lock_sha256
    {
        return Err(Refusal::new(
            "project Cargo files changed during native build",
        ));
    }

    let receipt = json!({
        "schema": "ami-rust-native-build-receipt-v1",
        "status": "PASS",
        "claim": "native build only; runtime and release qualification require separate evidence",
        "host": host_key(checked.lock.host.platform),
        // This is the stable Rust host profile. The former Python backend used
        // platform.platform(), a descriptive string that varies by interpreter.
        "platform": host_key(checked.lock.host.platform),
        "host_ram_bytes": capacity.physical_ram_bytes,
        "source_date_epoch": checked.selected_inputs.recipe.source_date_epoch,
        "project_lock_sha256": project_lock_digest,
        "sdk_manifest_sha256": checked.lock.sdk.manifest_sha256.as_str(),
        "prerequisite_inventory_counts": prerequisite_counts(&checked.selected_inputs)?,
        "compiler_verbose": compiler_verbose,
        "forwarded_cargo_arguments": options.forwarded_arguments.iter().map(|arg| os_text(arg.as_os_str())).collect::<Result<Vec<_>>>()?,
        "verbose_build_script_lines": cargo_output.verbose_build_script_lines,
        "deterministic_rust_flags": deterministic_rust_flags(&recipe, &options)?,
        "canonical_artifacts": canonical_artifacts,
        "elapsed_seconds": campaign_start.elapsed().as_secs_f64(),
        "commands": command_records,
        "cargo_frontend": {
            "path": path_text(&selected.cargo)?,
            "sha256": cargo_sha256,
            "metadata_mode": sdk.cargo_metadata_mode,
            "version": cargo_version,
        },
        "host_capacity": {
            "policy": capacity.policy,
            "physical_ram_bytes": capacity.physical_ram_bytes,
            "free_disk_bytes_before_build": capacity.free_disk_bytes,
        },
    });
    signals.check()?;
    write_build_receipt(&root, &pretty_json_line(&receipt)?, signals)?;

    Ok(BuildResult {
        exit_code: 0,
        native_executable: Some(executable_path),
        receipt: Some(output_path.join("build-receipt.json")),
    })
}

struct SelectedTools {
    rustc: PathBuf,
    cargo: PathBuf,
    collector: PathBuf,
    auxiliary_tool_links: Vec<(String, PathBuf)>,
}

fn select_tools(inputs: &SelectedInputs) -> Result<SelectedTools> {
    let rust = inputs.component("rust")?;
    let cargo = inputs.component("cargo")?;
    let toolchain = inputs.component("toolchain")?;
    let collector = inputs.component("collector")?;
    let mut auxiliary_tool_links = Vec::new();
    for name in ["llvm-objdump", "llvm-nm", "llvm-ar", "llvm-strip", "ld.lld"] {
        auxiliary_tool_links.push((
            name.to_owned(),
            toolchain.executable(&format!("bin/{name}"))?,
        ));
    }
    // The shared recipe resolves these fixed names from the verified
    // toolchain root. Select them here first so each fixed path is inventory-
    // bound before the recipe is constructed.
    let _clang = toolchain.executable("bin/clang")?;
    let _objcopy = toolchain.executable("bin/llvm-objcopy")?;
    Ok(SelectedTools {
        rustc: rust.executable("bin/rustc")?,
        cargo: cargo.executable("bin/cargo")?,
        collector: collector.executable("bin/aros-collect")?,
        auxiliary_tool_links,
    })
}

fn install_build_tool_aliases(bin: &Directory, output: &Path, tools: &SelectedTools) -> Result<()> {
    use std::os::unix::fs::symlink;

    for (name, source) in &tools.auxiliary_tool_links {
        let alias = output.join("bin").join(name);
        symlink(source, alias)?;
    }
    copy_new_file(&tools.collector, bin, "aros-collect", 0o755)?;
    symlink("aros-collect", output.join("bin/collect-aros"))?;
    Ok(())
}

fn verify_cargo_files(
    checked: &CheckedProject,
    options: &mut CargoBuildOptions,
) -> Result<CargoFiles> {
    let manifest = fs::canonicalize(&options.manifest_path)
        .map_err(|error| Refusal::new(format!("cannot resolve Cargo manifest: {error}")))?;
    if !fs::metadata(&manifest)?.is_file() {
        return Err(Refusal::new(
            "explicit Cargo manifest is not a regular file",
        ));
    }
    let manifest_parent = manifest
        .parent()
        .ok_or_else(|| Refusal::new("Cargo manifest has no parent directory"))?;
    let lock = manifest_parent.join("Cargo.lock");
    let manifest_sha256 = sha256_file(&manifest)?;
    let lock_sha256 = sha256_file(&lock)?;
    if manifest_sha256 != checked.lock.cargo.manifest_sha256.as_str()
        || lock_sha256 != checked.lock.cargo.lock_sha256.as_str()
    {
        return Err(Refusal::new(
            "project Cargo manifest/lock identity mismatch",
        ));
    }
    options.manifest_path = manifest.clone();
    Ok(CargoFiles {
        manifest,
        lock,
        manifest_sha256,
        lock_sha256,
    })
}

fn recheck_checked_project(checked: &CheckedProject, expected_lock_sha256: &str) -> Result<()> {
    checked.installation.recheck()?;
    checked.selected_inputs.recheck()?;
    if sha256_file(&checked.lock_path)? != expected_lock_sha256 {
        return Err(Refusal::new("native project lock changed during build"));
    }
    let current = verify_project_lock(&checked.lock_path)?;
    if serde_json::to_value(&current.lock).map_err(json_refusal)?
        != serde_json::to_value(&checked.lock).map_err(json_refusal)?
        || current.installation.receipt_digest() != checked.installation.receipt_digest()
        || current.installation.path() != checked.installation.path()
        || current.selected_inputs.host != checked.selected_inputs.host
    {
        return Err(Refusal::new(
            "native project selection changed during build",
        ));
    }
    for name in COMPONENTS {
        if current.selected_inputs.component(name)?.path()
            != checked.selected_inputs.component(name)?.path()
        {
            return Err(Refusal::new(
                "native project component selection changed during build",
            ));
        }
    }
    Ok(())
}

fn require_output_disjoint(
    output: &Path,
    checked: &CheckedProject,
    project_root: &Path,
) -> Result<()> {
    ownership::require_disjoint(
        output,
        checked.installation.path(),
        "build output must be outside the installed SDK",
    )?;
    ownership::require_disjoint(
        output,
        project_root,
        "build output must be outside the Cargo project",
    )?;
    for name in COMPONENTS {
        ownership::require_disjoint(
            output,
            checked.selected_inputs.component(name)?.path(),
            "build output must be outside selected component roots",
        )?;
    }
    Ok(())
}

fn reject_ambient_cargo_config(work: &Path) -> Result<()> {
    for parent in work.ancestors() {
        for name in ["config", "config.toml"] {
            let candidate = parent.join(".cargo").join(name);
            match fs::symlink_metadata(&candidate) {
                Ok(_) => {
                    return Err(Refusal::new(format!(
                        "ambient Cargo configuration would affect the locked build: {}; use an output directory outside its ancestry",
                        candidate.display()
                    )));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(Refusal::new(format!(
                        "could not inspect Cargo configuration path {}: {error}",
                        candidate.display()
                    )));
                }
            }
        }
    }
    Ok(())
}

fn read_sdk_build_policy(checked: &CheckedProject) -> Result<SdkBuildPolicy> {
    let bytes = checked.installation.read_file("sdk/contract/sdk.json")?;
    if sha256_bytes(&bytes) != checked.lock.sdk.manifest_sha256.as_str() {
        return Err(Refusal::new("installed SDK manifest identity mismatch"));
    }
    let value = parse_json_value(&bytes, JsonProfile::SdkComponentManifest)?;
    let object = value
        .as_object()
        .ok_or_else(|| Refusal::new("installed SDK manifest must be an object"))?;
    let capacity_policy = object
        .get("host_capacity")
        .filter(|policy| policy.is_object())
        .cloned()
        .ok_or_else(|| Refusal::new("installed SDK host capacity policy is missing"))?;
    let capacity_object = capacity_policy.as_object().expect("checked above");
    if capacity_object.get("schema").and_then(Value::as_str) != Some("ami-rust-host-capacity-v1") {
        return Err(Refusal::new(
            "unsupported installed SDK host capacity schema",
        ));
    }
    let ram_floor = capacity_object
        .get("ram_minimum_bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| Refusal::new("invalid installed SDK RAM floor"))?;
    let disk_floor = capacity_object
        .get("disk_free_minimum_bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| Refusal::new("invalid installed SDK disk floor"))?;
    if ram_floor < MINIMUM_RAM_BYTES || disk_floor < MINIMUM_FREE_DISK_BYTES {
        return Err(Refusal::new(
            "installed SDK capacity policy is below its admitted floor",
        ));
    }

    let host = host_key(checked.lock.host.platform);
    let profile = object
        .get("profiles")
        .and_then(Value::as_object)
        .and_then(|profiles| profiles.get(host))
        .and_then(Value::as_object)
        .ok_or_else(|| Refusal::new("installed SDK omits the current host profile"))?;
    let cargo_metadata_mode = profile
        .get("cargo_metadata_mode")
        .and_then(Value::as_str)
        .ok_or_else(|| Refusal::new("installed SDK Cargo metadata mode is missing"))?;
    if cargo_metadata_mode != CARGO_METADATA_MODE {
        return Err(Refusal::new(
            "installed SDK Cargo metadata mode is unsupported",
        ));
    }
    Ok(SdkBuildPolicy {
        capacity_policy,
        cargo_metadata_mode: cargo_metadata_mode.to_owned(),
    })
}

struct SdkBuildPolicy {
    capacity_policy: Value,
    cargo_metadata_mode: String,
}

fn measure_host_capacity(parent: &Path, policy: Value) -> Result<HostCapacity> {
    let (physical_ram_bytes, free_disk_bytes) = host_capacity(parent)?;
    Ok(HostCapacity {
        policy,
        physical_ram_bytes,
        free_disk_bytes,
    })
}

#[allow(
    unsafe_code,
    reason = "POSIX sysconf/statvfs read host capacity without mutation."
)]
#[allow(
    clippy::unnecessary_cast,
    reason = "statvfs field widths vary between the two supported Unix hosts."
)]
fn host_capacity(parent: &Path) -> Result<(u64, u64)> {
    use std::mem::MaybeUninit;

    // SAFETY: sysconf takes no pointers and returns the host's physical page
    // count and page size. Nonpositive values are rejected below.
    let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
    // SAFETY: same as above, for the system page size.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let physical_ram = u64::try_from(pages)
        .ok()
        .and_then(|pages| u64::try_from(page_size).ok().map(|size| (pages, size)))
        .filter(|(pages, size)| *pages != 0 && *size != 0)
        .and_then(|(pages, size)| pages.checked_mul(size))
        .ok_or_else(|| Refusal::new("could not determine physical host RAM"))?;

    let parent_c = CString::new(parent.as_os_str().as_bytes())
        .map_err(|_| Refusal::new("build output parent contains NUL"))?;
    let mut stats = MaybeUninit::<libc::statvfs>::zeroed();
    // SAFETY: parent_c is NUL-terminated and stats points to writable storage;
    // a successful statvfs initializes the complete result structure.
    if unsafe { libc::statvfs(parent_c.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return Err(Refusal::new(format!(
            "could not measure free build workspace: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: successful statvfs initialized the complete structure.
    let stats = unsafe { stats.assume_init() };
    let unit = if stats.f_frsize != 0 {
        stats.f_frsize as u64
    } else {
        stats.f_bsize as u64
    };
    let free_disk = (stats.f_bavail as u64)
        .checked_mul(unit)
        .ok_or_else(|| Refusal::new("free build workspace size overflow"))?;
    Ok((physical_ram, free_disk))
}

fn run_observed(
    session: &mut ConsumerSession<'_>,
    campaign_start: Instant,
    label: &str,
    spec: CommandSpec,
    records: &mut Vec<Value>,
    include_record: bool,
) -> Result<ObservedCommand> {
    ensure_campaign_time(campaign_start)?;
    let timeout = Duration::from_secs(BUILD_SECONDS)
        .checked_sub(campaign_start.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| Refusal::new("native build timeout expired").with_exit_code(1))?;
    let command = if include_record {
        Some(command_as_text(&spec)?)
    } else {
        None
    };
    let started = Instant::now();
    let output = match session.run_spec_retaining_exit(label, spec, timeout) {
        Ok(output) => output,
        Err(error) => {
            if let Some(exit_code) = session.last_failure_exit_code() {
                return Ok(ObservedCommand {
                    output: None,
                    failure_exit_code: Some(exit_code),
                });
            }
            return Err(error);
        }
    };
    let elapsed = started.elapsed().as_secs_f64();
    let failure_exit_code = child_failure_code(&output);
    if let Some(command) = command {
        records.push(json!({
            "command": command,
            "exit_code": python_exit_code(&output),
            "stop_reason": Value::Null,
            "elapsed_seconds": elapsed,
            "rss_peak_observed_bytes": output.resources.peak_visible_rss_bytes,
            "workspace_peak_observed_bytes": output.resources.peak_workspace_bytes,
        }));
    }
    Ok(ObservedCommand {
        output: Some(output),
        failure_exit_code,
    })
}

fn child_failure_code(output: &ConsumerOutput) -> Option<u8> {
    match (output.exit_code, output.signal) {
        (Some(0), None) => None,
        (Some(code), None) if (1..256).contains(&code) => Some(code as u8),
        _ => Some(130),
    }
}

fn python_exit_code(output: &ConsumerOutput) -> Option<i32> {
    match (output.exit_code, output.signal) {
        (Some(code), None) => Some(code),
        (None, Some(signal)) => Some(-signal),
        _ => None,
    }
}

fn command_as_text(spec: &CommandSpec) -> Result<Vec<String>> {
    let mut result = Vec::with_capacity(spec.args.len() + 1);
    result.push(os_text(spec.program.as_os_str())?);
    result.extend(
        spec.args
            .iter()
            .map(|argument| os_text(argument.as_os_str()))
            .collect::<Result<Vec<_>>>()?,
    );
    Ok(result)
}

fn parse_cargo_output(stdout: &[u8]) -> Result<CargoOutputSummary> {
    let text = std::str::from_utf8(stdout)
        .map_err(|error| Refusal::new(format!("Cargo output is not UTF-8: {error}")))?;
    let mut static_archives = Vec::new();
    let mut verbose_build_script_lines = 0_usize;
    for line in text.lines() {
        if line.starts_with('[') && line.contains("] ") {
            verbose_build_script_lines = verbose_build_script_lines
                .checked_add(1)
                .ok_or_else(|| Refusal::new("Cargo build-script line count overflow"))?;
            continue;
        }
        let message = parse_json_value(line.as_bytes(), JsonProfile::SdkComponentManifest)
            .map_err(|error| Refusal::new(format!("invalid Cargo JSON message: {error}")))?;
        if message.get("reason").and_then(Value::as_str) != Some("compiler-artifact") {
            continue;
        }
        let target = message
            .get("target")
            .and_then(Value::as_object)
            .ok_or_else(|| Refusal::new("Cargo compiler-artifact omits target"))?;
        let kinds = target
            .get("kind")
            .and_then(Value::as_array)
            .ok_or_else(|| Refusal::new("Cargo compiler-artifact target omits kinds"))?;
        let is_staticlib = kinds.iter().any(|kind| kind.as_str() == Some("staticlib"));
        if !is_staticlib {
            continue;
        }
        let filenames = message
            .get("filenames")
            .and_then(Value::as_array)
            .ok_or_else(|| Refusal::new("Cargo staticlib artifact omits filenames"))?;
        for filename in filenames {
            let filename = filename
                .as_str()
                .ok_or_else(|| Refusal::new("Cargo artifact filename is not a string"))?;
            if filename.ends_with(".a") {
                static_archives.push(PathBuf::from(filename));
            }
        }
    }
    Ok(CargoOutputSummary {
        static_archives,
        verbose_build_script_lines,
    })
}

fn single_static_archive(summary: &CargoOutputSummary) -> Result<PathBuf> {
    if summary.static_archives.len() != 1 {
        return Err(Refusal::new(
            "Cargo must report exactly one application static library",
        ));
    }
    Ok(summary.static_archives[0].clone())
}

fn validate_static_archive(output: &Path, reported: &Path) -> Result<PathBuf> {
    let work = output.join("work");
    let target_root = work.join("target");
    let target_metadata = fs::symlink_metadata(&target_root)?;
    if !target_metadata.is_dir() || target_metadata.file_type().is_symlink() {
        return Err(Refusal::new(
            "Cargo target directory is not a real directory",
        ));
    }
    let path = if reported.is_absolute() {
        reported.to_path_buf()
    } else {
        work.join(reported)
    };
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Refusal::new("invalid Cargo artifact path"));
    }
    let target_real = fs::canonicalize(&target_root)?;
    let artifact_real = fs::canonicalize(&path)?;
    if !artifact_real.starts_with(&target_real) {
        return Err(Refusal::new("Cargo artifact escaped its target directory"));
    }
    Ok(path)
}

fn collect_target_artifacts(output: &Path) -> Result<Vec<(PathBuf, PathBuf)>> {
    let target_root = output.join("work/target/x86_64-aros");
    let metadata = match fs::symlink_metadata(&target_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Refusal::new("Cargo target root is not a real directory"));
    }
    let mut candidates = Vec::new();
    walk_target_artifacts(&target_root, &target_root, &mut candidates)?;
    candidates.sort_by(|left, right| left.1.cmp(&right.1));
    Ok(candidates)
}

fn walk_target_artifacts(
    root: &Path,
    directory: &Path,
    output: &mut Vec<(PathBuf, PathBuf)>,
) -> Result<()> {
    let mut children = fs::read_dir(directory)?.collect::<std::result::Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.path());
    for child in children {
        let path = child.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            walk_target_artifacts(root, &path, output)?;
            continue;
        }
        let has_output_extension = path
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|extension| COMMAND_ARTIFACT_EXTENSIONS.contains(&extension));
        if !has_output_extension {
            continue;
        }
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(Refusal::new("invalid generated target library/object"));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| Refusal::new("generated target artifact escaped target root"))?
            .to_path_buf();
        output.push((path, relative));
    }
    Ok(())
}

fn compaction_receipt(input: &Path, output: &Path, report: &CompactionReport) -> Result<Value> {
    Ok(json!({
        "input": path_text(input)?,
        "output": path_text(output)?,
        "input_bytes": report.input_bytes,
        "output_bytes": report.output_bytes,
        "saved_metadata_bytes": report.saved_metadata_bytes,
        "sections_renamed": report.sections_renamed,
        "all_other_section_payloads_preserved": report.all_other_section_payloads_preserved,
        "renames": report.renames,
    }))
}

fn prerequisite_counts(inputs: &SelectedInputs) -> Result<BTreeMap<String, usize>> {
    COMPONENTS
        .into_iter()
        .map(|name| {
            let measurement = inputs.component(name)?.measurement();
            let count = measurement
                .files
                .checked_add(measurement.symlinks)
                .ok_or_else(|| Refusal::new("prerequisite inventory count overflow"))?;
            Ok((name.to_owned(), count))
        })
        .collect()
}

fn deterministic_rust_flags(
    recipe: &NativeBuildRecipe,
    options: &CargoBuildOptions,
) -> Result<Vec<String>> {
    let environment = recipe.cargo_environment(options)?;
    let encoded = environment
        .get(OsStr::new("CARGO_ENCODED_RUSTFLAGS"))
        .ok_or_else(|| Refusal::new("native Cargo recipe omitted deterministic Rust flags"))?;
    encoded
        .as_os_str()
        .as_bytes()
        .split(|byte| *byte == 0x1f)
        .map(|flag| {
            String::from_utf8(flag.to_vec())
                .map_err(|error| Refusal::new(format!("Rust flag is not UTF-8: {error}")))
        })
        .collect()
}

fn verify_rustc_identity(verbose: &str, commit: &str, llvm: &str, host: Host) -> Result<()> {
    let expected = [
        format!("commit-hash: {commit}"),
        format!("LLVM version: {llvm}"),
        format!("host: {}", host.rust_host_triple_for_build()),
    ];
    if !expected
        .iter()
        .all(|expected| verbose.lines().any(|line| line == expected))
    {
        return Err(Refusal::new(
            "selected Rust compiler/LLVM/host identity mismatch",
        ));
    }
    Ok(())
}

fn normalize_output_directory(output: &Path) -> Result<PathBuf> {
    if output.as_os_str().is_empty() {
        return Err(Refusal::new("build output directory is required"));
    }
    let absolute = if output.is_absolute() {
        output.to_path_buf()
    } else {
        std::env::current_dir()?.join(output)
    };
    let leaf = absolute
        .file_name()
        .filter(|name| !name.is_empty() && *name != OsStr::new(".") && *name != OsStr::new(".."))
        .ok_or_else(|| Refusal::new("build output path must name a fresh directory"))?;
    let parent = absolute
        .parent()
        .ok_or_else(|| Refusal::new("build output path has no parent"))?;
    let parent = fs::canonicalize(parent)
        .map_err(|error| Refusal::new(format!("build output parent must exist: {error}")))?;
    Ok(parent.join(leaf))
}

fn validate_receipt_strings(options: &CargoBuildOptions, output: &Path) -> Result<()> {
    path_text(output)?;
    for argument in &options.forwarded_arguments {
        os_text(argument.as_os_str())?;
    }
    path_text(&options.manifest_path)?;
    Ok(())
}

fn work_path(output: &Path) -> PathBuf {
    output.join("work")
}

fn ensure_campaign_time(started: Instant) -> Result<()> {
    if started.elapsed() >= Duration::from_secs(BUILD_SECONDS) {
        return Err(Refusal::new("native build timeout expired").with_exit_code(1));
    }
    Ok(())
}

fn lock_build_directory(file: &File) -> Result<()> {
    #[allow(
        unsafe_code,
        reason = "flock protects a fresh output directory from concurrent builds."
    )]
    {
        // SAFETY: file owns a live descriptor; flock only changes its advisory
        // lock state and does not retain the pointer.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Refusal::new(format!(
                "could not lock native build output: {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

fn write_new_file(directory: &Directory, name: &str, bytes: &[u8], mode: u32) -> Result<()> {
    let mut file = directory.create_new_file(OsStr::new(name), mode)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_build_receipt(directory: &Directory, bytes: &[u8], signals: &SigtermGuard) -> Result<()> {
    write_build_receipt_with_sync(directory, bytes, signals, File::sync_all)
}

fn write_build_receipt_with_sync(
    directory: &Directory,
    bytes: &[u8],
    signals: &SigtermGuard,
    sync_file: impl FnOnce(&File) -> std::io::Result<()>,
) -> Result<()> {
    let temporary = random_build_receipt_name()?;
    let mut created = false;
    let mut published = false;
    let result = (|| {
        signals.check()?;
        let mut file = signals.with_blocked(|| {
            directory.create_new_file_tracked(&temporary, 0o600, || created = true)
        })?;
        signals.check()?;
        file.write_all(bytes)?;
        sync_file(&file).map_err(|error| {
            Refusal::new(format!("could not sync native build receipt: {error}"))
        })?;
        signals.check()?;
        signals.with_blocked(|| {
            directory.rename_no_replace(&temporary, directory, OsStr::new("build-receipt.json"))?;
            published = true;
            Ok(())
        })?;
        directory.sync_best_effort();
        signals.check().map_err(|error| {
            Refusal::new(format!(
                "build receipt was published but SIGTERM requested a stop: {error}"
            ))
        })?;
        Ok(())
    })();

    if created
        && !published
        && let Err(cleanup) = directory.unlink_entry(&temporary)
    {
        return Err(Refusal::new(format!(
            "{}; build receipt staging file {} could not be removed: {cleanup}",
            result.as_ref().err().map_or_else(
                || "build receipt was not published".to_owned(),
                ToString::to_string
            ),
            temporary.to_string_lossy()
        )));
    }
    match result {
        Ok(()) if published => Ok(()),
        Ok(()) => Err(Refusal::new("build receipt was not published")),
        Err(error) if published => Err(Refusal::new(format!(
            "build receipt was published but a later operation failed: {error}"
        ))),
        Err(error) => Err(error),
    }
}

#[allow(
    unsafe_code,
    reason = "getentropy supplies a private exclusive receipt staging basename."
)]
fn random_build_receipt_name() -> Result<OsString> {
    let mut bytes = [0_u8; 12];
    // SAFETY: getentropy writes to this initialized 12-byte buffer, within its
    // documented maximum. macOS and Linux provide this API.
    if unsafe { libc::getentropy(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
        return Err(Refusal::new(format!(
            "could not generate a private build receipt staging name: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut name = OsString::from(".ami-rust-build-receipt-");
    for byte in bytes {
        name.push(format!("{byte:02x}"));
    }
    Ok(name)
}

fn copy_new_file(source: &Path, directory: &Directory, name: &str, mode: u32) -> Result<()> {
    let mut source_file = File::open(source)?;
    if !source_file.metadata()?.is_file() {
        return Err(Refusal::new("selected copy source is not a regular file"));
    }
    let mut destination = directory.create_new_file(OsStr::new(name), mode)?;
    std::io::copy(&mut source_file, &mut destination)?;
    destination.sync_all()?;
    Ok(())
}

fn read_regular_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Refusal::new("native build artifact is not a regular file"));
    }
    let mut file = files::open_regular_nofollow(path)?;
    let capacity = usize::try_from(file.metadata()?.len())
        .map_err(|_| Refusal::new("native build artifact length is not representable"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|error| Refusal::new(format!("could not allocate ELF buffer: {error}")))?;
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn artifact_identity(path: &Path) -> Result<Value> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Refusal::new("canonical artifact is not a regular file"));
    }
    Ok(json!({
        "bytes": metadata.len(),
        "sha256": sha256_file(path)?,
    }))
}

fn hash_selected_alias(path: &Path, root: &Path) -> Result<String> {
    let resolved = fs::canonicalize(path)?;
    if !resolved.starts_with(root) {
        return Err(Refusal::new(
            "selected executable alias escaped its component",
        ));
    }
    sha256_file(&resolved)
}

fn refuse_existing(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(Refusal::new("native artifact destination already exists")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn pretty_json_line(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(json_refusal)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn json_refusal(error: serde_json::Error) -> Refusal {
    Refusal::new(format!("cannot serialize native build receipt: {error}"))
}

fn utf8_output(bytes: &[u8], label: &str) -> Result<String> {
    String::from_utf8(bytes.to_vec())
        .map_err(|error| Refusal::new(format!("{label} is not UTF-8: {error}")))
}

fn os_text(value: &OsStr) -> Result<String> {
    String::from_utf8(value.as_bytes().to_vec())
        .map_err(|error| Refusal::new(format!("native receipt value is not UTF-8: {error}")))
}

fn path_text(path: &Path) -> Result<String> {
    os_text(path.as_os_str())
}

fn host_key(host: Host) -> &'static str {
    match host {
        Host::LinuxX86_64 => "linux-x86_64",
        Host::MacosAarch64 => "macos-aarch64",
    }
}

trait HostBuildTriple {
    fn rust_host_triple_for_build(self) -> &'static str;
}

impl HostBuildTriple for Host {
    fn rust_host_triple_for_build(self) -> &'static str {
        match self {
            Host::LinuxX86_64 => "x86_64-unknown-linux-gnu",
            Host::MacosAarch64 => "aarch64-apple-darwin",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource_capture::ResourceReport;
    use std::os::unix::fs::PermissionsExt;

    const RECEIPT_CHILD_MODE: &str = "AMI_NATIVE_BUILD_RECEIPT_FIXTURE";

    fn cargo_artifact_message(kind: &str, filename: &str) -> String {
        json!({
            "reason": "compiler-artifact",
            "target": {"kind": [kind]},
            "filenames": [filename],
        })
        .to_string()
    }

    #[test]
    fn real_host_capacity_is_measurable_and_missing_volume_refuses() {
        let (ram, available_disk) = host_capacity(&std::env::temp_dir()).unwrap();
        assert!(ram > 0 && available_disk > 0);
        assert!(host_capacity(Path::new("/ami-rust-nonexistent-capacity-control/absent")).is_err());
    }

    #[test]
    fn build_receipt_publication_controls_run_with_isolated_signal_state() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_build::tests::build_receipt_child_fixture",
                "--ignored",
                "--nocapture",
            ])
            .env_clear()
            .env("HOME", std::env::var_os("HOME").unwrap())
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env(RECEIPT_CHILD_MODE, "1")
            .output()
            .expect("spawn isolated build receipt test");
        assert!(
            output.status.success(),
            "build receipt child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "run by the parent test with isolated process-wide signal state"]
    fn build_receipt_child_fixture() {
        assert_eq!(std::env::var(RECEIPT_CHILD_MODE).as_deref(), Ok("1"));
        let path = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                ".ami-rust-build-receipt-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        std::fs::create_dir(&path).expect("create receipt fixture");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .expect("make receipt fixture private");
        let directory = Directory::open(&path).expect("open receipt fixture");
        let signals = SigtermGuard::acquire().expect("install isolated signal guard");
        let receipt = b"{\"schema\":\"ami-rust-native-build-receipt-v1\",\"status\":\"PASS\"}\n";
        let final_path = path.join("build-receipt.json");

        write_build_receipt_with_sync(&directory, receipt, &signals, File::sync_all)
            .expect("publish synced build receipt");
        assert_eq!(std::fs::read(&final_path).unwrap(), receipt);
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 1);
        std::fs::remove_file(&final_path).expect("remove positive control receipt");

        let failed = write_build_receipt_with_sync(&directory, receipt, &signals, |_| {
            Err(std::io::Error::other("injected sync failure after write"))
        });
        assert!(failed.is_err());
        assert!(!final_path.exists(), "failed sync published a PASS receipt");
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);

        let existing = b"existing receipt";
        std::fs::write(&final_path, existing).expect("create collision control");
        assert!(
            write_build_receipt_with_sync(&directory, receipt, &signals, File::sync_all).is_err()
        );
        assert_eq!(std::fs::read(&final_path).unwrap(), existing);
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 1);

        drop(directory);
        signals.finish().expect("restore signal handler");
        std::fs::remove_dir_all(path).expect("remove receipt fixture");
    }

    #[test]
    fn cargo_output_selects_only_staticlib_archives_and_counts_verbose_lines() {
        let stdout = format!(
            "[ami-rust 0.1.0] build script output\n{}\n{}\n",
            cargo_artifact_message("lib", "/work/target/libhelper.rlib"),
            cargo_artifact_message("staticlib", "/work/target/libapp.a"),
        );
        let parsed = parse_cargo_output(stdout.as_bytes()).unwrap();
        assert_eq!(parsed.verbose_build_script_lines, 1);
        assert_eq!(
            parsed.static_archives,
            [PathBuf::from("/work/target/libapp.a")]
        );
        assert_eq!(
            single_static_archive(&parsed).unwrap(),
            PathBuf::from("/work/target/libapp.a")
        );
    }

    #[test]
    fn cargo_output_rejects_ambiguous_or_absent_application_archives() {
        let two = format!(
            "{}\n{}\n",
            cargo_artifact_message("staticlib", "/work/target/one.a"),
            cargo_artifact_message("staticlib", "/work/target/two.a"),
        );
        assert!(single_static_archive(&parse_cargo_output(two.as_bytes()).unwrap()).is_err());
        let none = cargo_artifact_message("lib", "/work/target/libapp.rlib");
        assert!(single_static_archive(&parse_cargo_output(none.as_bytes()).unwrap()).is_err());
        assert!(parse_cargo_output(b"not-json\n").is_err());
    }

    #[test]
    fn child_exit_status_preserves_ordinary_codes_and_maps_signals_to_130() {
        let mut output = ConsumerOutput {
            stdout: Vec::new(),
            stderr: Vec::new(),
            resources: ResourceReport::default(),
            exit_code: Some(37),
            signal: None,
        };
        assert_eq!(child_failure_code(&output), Some(37));
        assert_eq!(python_exit_code(&output), Some(37));
        output.exit_code = None;
        output.signal = Some(9);
        assert_eq!(child_failure_code(&output), Some(130));
        assert_eq!(python_exit_code(&output), Some(-9));
        output.exit_code = Some(0);
        output.signal = None;
        assert_eq!(child_failure_code(&output), None);
    }

    #[test]
    fn rustc_identity_requires_exact_pinned_lines() {
        let valid = "commit-hash: abc\nLLVM version: 11.0.0\nhost: aarch64-apple-darwin\n";
        assert!(verify_rustc_identity(valid, "abc", "11.0.0", Host::MacosAarch64).is_ok());
        assert!(
            verify_rustc_identity(
                "commit-hash: abc-extra\nLLVM version: 11.0.0\nhost: aarch64-apple-darwin\n",
                "abc",
                "11.0.0",
                Host::MacosAarch64,
            )
            .is_err()
        );
    }
}
